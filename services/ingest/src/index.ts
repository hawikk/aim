import { Pool } from "pg";
import { loadConfig } from "./config";
import {
  HttpDeviceMappingRegistrar,
  HttpIdentityResolver,
  mintIdentityServiceJwt,
} from "./identity";
import { runMigrations } from "./migrate";
import { S3BatchArchive } from "./object-store";
import { PostgresSink } from "./pg-sink";
import { loadRetentionConfig, RetentionPurger } from "./retention";
import { PostgresDeviceStore } from "./device-store";
import { PostgresEnrollTokenStore } from "./enroll-token-store";
import { buildServer } from "./server";
import { PostgresVendorAdminStore, pollVendorAdminOnce } from "./vendor-admin";

async function main(): Promise<void> {
  const config = loadConfig();

  const pool = new Pool({ connectionString: config.databaseUrl });
  const applied = await runMigrations(pool, config.migrationsDir);

  const sink = new PostgresSink(pool);
  const deviceStore = new PostgresDeviceStore(pool);
  const enrollTokenStore = new PostgresEnrollTokenStore(pool);
  const resolver = config.identityResolveUrl
    ? new HttpIdentityResolver(config.identityResolveUrl)
    : undefined;
  // enroll-time device_mappings registration. Needs both the resolve
  // URL (identity-sync base) and a shared HS256 secret to pass the gate.
  const deviceMappingRegistrar =
    config.identityResolveUrl && config.identitySyncJwtHs256Secret
      ? new HttpDeviceMappingRegistrar(config.identityResolveUrl, () =>
          mintIdentityServiceJwt(config.identitySyncJwtHs256Secret as string),
        )
      : undefined;
  const archive = config.objectStore ? new S3BatchArchive(config.objectStore) : undefined;
  const vendorAdminStore = new PostgresVendorAdminStore(pool);
  const app = await buildServer({
    sink,
    tokens: config.ingestTokens,
    sharedTokenMode: config.sharedTokenMode,
    enrollTokens: config.enrollTokens,
    enrollTokenStore,
    deviceStore,
    resolver,
    deviceMappingRegistrar,
    archive,
    otelHostSalt: config.otelHostSalt,
    admission: config.admission,
    attestation: config.attestation,
    vendorAdminStore,
    logger: true,
  });
  if (applied.length > 0) {
    app.log.info({ migrations: applied }, "database migrations applied");
  }
  app.log.info(
    {
      identityResolution: config.identityResolveUrl ? config.identityResolveUrl : "disabled",
      enrollTimeDeviceMapping: deviceMappingRegistrar ? "enabled" : "disabled",
    },
    "identity enrichment configured",
  );
  app.log.info(
    {
      eventAuth: "device_token (DB) primary; INGEST_TOKENS shared path gated by mode",
      sharedTokenMode: config.sharedTokenMode,
      sharedTokenCount: config.ingestTokens.length,
    },
    "event auth configured (— survives INGEST_TOKENS rotation)",
  );
  app.log.info(
    {
      enrollTokenStore: "db-backed (dashboard-minted tokens)",
      legacyEnvTokens: config.enrollTokens.length > 0 ? "enabled (deprecated)" : "disabled (ENROLL_TOKENS unset)",
    },
    "collector enrollment configured",
  );
  app.log.info(
    {
      archival: config.objectStore
        ? `${config.objectStore.endpoint}/${config.objectStore.bucket}`
        : "disabled (OBJECT_STORE_ENDPOINT/BUCKET unset)",
    },
    "raw-batch archival configured",
  );

  app.log.info(
    {
      mode: config.admission.mode,
      maxInflight: config.admission.maxInflight,
      retryAfterSeconds: config.admission.retryAfterSeconds,
    },
    "ingest admission control configured",
  );

  app.log.info(
    {
      mode: config.attestation.mode,
      publicKeyCount: config.attestation.publicKeys.size,
    },
    "collector build attestation configured",
  );

  app.log.info(
    {
      otelReceiver: "enabled",
      otelMetrics: "enabled (/v1/metrics — Claude Code)",
      otelHostSalt: config.otelHostSalt ? "env (OTEL_HOST_SALT)" : "dev default — set OTEL_HOST_SALT in prod",
    },
    "OTLP GenAI + Claude Code metrics receiver configured",
  );

  app.log.info(
    {
      copilot: config.vendorAdmin.copilotToken ? "configured" : "dark (COPILOT_METRICS_TOKEN unset)",
      cursor: config.vendorAdmin.cursorApiKey ? "configured" : "dark (CURSOR_ADMIN_API_KEY unset)",
      pollIntervalSeconds: config.vendorAdmin.pollIntervalSeconds,
    },
    "vendor admin poller configured (— missing tokens degrade, do not fail ingest)",
  );

  // Retention enforcement. Fail-closed: an invalid config disables
  // the purge and lifecycle wiring but leaves ingest serving — a bad window
  // must never delete data or take the ingest path down.
  const retention = loadRetentionConfig();
  let purgeTimer: NodeJS.Timeout | undefined;
  if (!retention.ok) {
    app.log.error({ error: retention.error }, "retention config invalid — purge DISABLED");
  } else {
    const { config: rc } = retention;
    app.log.info(
      { windows: rc.windows, dryRun: rc.dryRun, batchSize: rc.batchSize, intervalHours: rc.intervalMs / 3_600_000 },
      "retention enforcement configured",
    );

    // Object-store expiry: declare the raw-batch lifecycle so the store ages
    // out event-class objects itself. Fail-open — a lifecycle error is logged,
    // never fatal (Postgres retention still runs).
    if (archive) {
      archive
        .applyRetentionPolicy(rc.windows.events)
        .then(() =>
          app.log.info({ days: rc.windows.events }, "object-store retention lifecycle applied"),
        )
        .catch((err) =>
          app.log.error({ err }, "object-store retention lifecycle NOT applied — will retry next boot"),
        );
    }

    // Postgres purge on an interval. Each run is guarded: a purge error is
    // logged and retried next tick, never crashing the server. unref() so the
    // timer never keeps the process alive on its own.
    if (rc.intervalMs > 0) {
      const purger = new RetentionPurger(pool, rc);
      const runPurge = async () => {
        try {
          const summary = await purger.purge();
          app.log.info({ event: "retention.purge", ...summary }, "retention purge complete");
        } catch (err) {
          app.log.error({ err }, "retention purge failed — retry next interval");
        }
      };
      void runPurge();
      purgeTimer = setInterval(() => void runPurge(), rc.intervalMs);
      purgeTimer.unref();
    }
  }

  let vendorTimer: NodeJS.Timeout | undefined;
  const runVendorPoll = async () => {
    try {
      const results = await pollVendorAdminOnce(config.vendorAdmin, {
        store: vendorAdminStore,
        log: (msg, fields) => app.log.info(fields ?? {}, msg),
      });
      app.log.info(
        { results: results.map((r) => ({ feed: r.feed, status: r.status, rows: r.rows })) },
        "vendor admin poll complete",
      );
    } catch (err) {
      app.log.error({ err }, "vendor admin poll failed — ingest stays up");
    }
  };
  if (config.vendorAdmin.pollIntervalSeconds > 0) {
    void runVendorPoll();
    vendorTimer = setInterval(() => void runVendorPoll(), config.vendorAdmin.pollIntervalSeconds * 1000);
    vendorTimer.unref();
  }

  const shutdown = async (signal: string) => {
    if (purgeTimer) clearInterval(purgeTimer);
    if (vendorTimer) clearInterval(vendorTimer);
    app.log.info({ signal }, "shutting down");
    await app.close();
    await sink.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  await app.listen({ port: config.port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.error("fatal startup error", err);
  process.exit(1);
});

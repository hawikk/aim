import { createHash } from "node:crypto";
import type { EventSink, EnrichedEvent, RejectedRecord } from "./sink";
import type { PoolLike } from "./migrate";

const INSERT_EVENT = `
  INSERT INTO events (
    event_id, ts, source, tool, tool_raw, tool_version, provider, model,
    session_id, tokens_in, tokens_out, cost_estimate_usd,
    host_ref, user_ref, repo_ref, match_flags, payload,
    user_pseudonym, team, event_type, tool_calls,
    service_name, duration_ms, status,
    traffic_class, bytes_up, bytes_down, http_status, principal_kind
  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)
  ON CONFLICT (event_id) DO NOTHING
`;

const INSERT_REJECTED = `
  INSERT INTO rejected_events (batch_index, error, payload_hash, payload_keys)
  VALUES ($1, $2, $3, $4)
`;

/**
 * Direct-to-Postgres event sink (v0). Idempotent on event_id via
 * ON CONFLICT DO NOTHING, so retries and duplicate deliveries are safe.
 */
export class PostgresSink implements EventSink {
  constructor(private readonly pool: PoolLike) {}

  async insert(events: EnrichedEvent[]): Promise<number> {
    let inserted = 0;
    for (const e of events) {
      // payload holds the canonical validated event; enrichment lives in
      // dedicated columns, not inside the raw contract payload.
      const { user_pseudonym, team, principal_kind, ...canonical } = e;
      const result = await this.pool.query(INSERT_EVENT, [
        e.event_id,
        e.ts,
        e.source,
        e.tool,
        e.tool_raw ?? null,
        e.tool_version ?? null,
        e.provider ?? null,
        e.model ?? null,
        e.session_id,
        e.tokens_in ?? null,
        e.tokens_out ?? null,
        e.cost_estimate_usd ?? null,
        e.host_ref,
        e.user_ref ?? null,
        e.repo_ref ?? null,
        JSON.stringify(e.match_flags),
        JSON.stringify(canonical),
        user_pseudonym,
        team,
        e.event_type ?? "usage",
        e.tool_calls ? JSON.stringify(e.tool_calls) : null,
        e.service_name ?? null,
        e.duration_ms ?? null,
        e.status ?? null,
        e.traffic_class ?? null,
        e.bytes_up ?? null,
        e.bytes_down ?? null,
        e.http_status ?? null,
        principal_kind,
      ]);
      inserted += result.rowCount ?? 0;
    }
    return inserted;
  }

  /**
   * Audit rejected events WITHOUT storing the payload: an invalid event may
   * contain arbitrary content. We persist the validation error, a SHA-256
   * hash (for correlation with the sender), and the top-level key names.
   */
  async insertRejected(records: RejectedRecord[]): Promise<void> {
    for (const r of records) {
      const serialized = safeSerialize(r.payload);
      const hash = createHash("sha256").update(serialized).digest("hex");
      const keys =
        r.payload !== null && typeof r.payload === "object" && !Array.isArray(r.payload)
          ? Object.keys(r.payload)
          : [];
      await this.pool.query(INSERT_REJECTED, [r.batchIndex, r.error, hash, JSON.stringify(keys)]);
    }
  }

  async ping(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

function safeSerialize(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { newDb } from "pg-mem";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { loadConfig } from "../src/config";
import { includeFileForPgMem, runMigrations, type PoolLike } from "../src/migrate";
import { archiveKey, toArchiveNdjson, type BatchArchive } from "../src/object-store";
import { PostgresSink } from "../src/pg-sink";
import { validateEvent, type UsageEventV1 } from "../src/schema";
import { buildServer } from "../src/server";

const TOKEN = "test-collector-token";
const hex64 = (s: string) => createHash("sha256").update(s).digest("hex");

/** Marker content: must never appear in anything the platform writes. */
const CANARY = "ARCHIVE-CONTENT-CANARY-do-not-store";

function makeEvent(overrides: Partial<UsageEventV1> = {}): UsageEventV1 {
  return {
    schema_version: "1.0",
    event_id: randomUUID(),
    ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    host_ref: hex64(`host-${randomUUID()}`),
    user_ref: hex64(`user-${randomUUID()}`),
    tool: "claude_code",
    tool_version: "1.0.0",
    model: "claude-opus-4",
    provider: "anthropic",
    session_id: randomUUID(),
    tokens_in: 500,
    tokens_out: 120,
    repo_ref: hex64("repo-example"),
    match_flags: [],
    source: "endpoint",
    ...overrides,
  };
}

/** In-memory archive capturing every put for assertions. */
class FakeArchive implements BatchArchive {
  puts: { key: string; body: string }[] = [];
  fail = false;

  async put(key: string, body: string): Promise<void> {
    if (this.fail) {
      throw new Error("object store unavailable");
    }
    this.puts.push({ key, body });
  }
}

describe("raw-batch archival (AIM-83)", () => {
  let pool: PoolLike;
  let archive: FakeArchive;
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    const db = newDb();
    // pg-mem ships no gen_random_uuid(); migration 008 uses it.
    db.public.registerFunction({ name: "gen_random_uuid", returns: "uuid" as never, implementation: () => crypto.randomUUID() });
    pool = new (db.adapters.createPg().Pool)() as unknown as PoolLike;
    await runMigrations(pool, join(__dirname, "..", "migrations"), { includeFile: includeFileForPgMem });
    archive = new FakeArchive();
    app = await buildServer({ sink: new PostgresSink(pool), tokens: [TOKEN], archive });
  });

  afterAll(async () => {
    await app.close();
  });

  function post(events: unknown[], token: string | null = TOKEN) {
    return app.inject({
      method: "POST",
      url: "/v1/events",
      headers: token ? { authorization: `Bearer ${token}` } : {},
      payload: { events },
    });
  }

  test("validated batch is archived as NDJSON keyed by date/batch-id; rejects become stubs", async () => {
    const good = makeEvent();
    const bad = { event_id: "not-a-uuid" };
    archive.puts = [];

    const res = await post([good, bad]);
    expect(res.statusCode).toBe(200);
    expect(archive.puts).toHaveLength(1);

    const { key, body } = archive.puts[0]!;
    expect(key).toMatch(/^raw\/\d{4}\/\d{2}\/\d{2}\/[0-9a-f-]{36}\.ndjson$/);

    const lines = body.trimEnd().split("\n").map((l: string) => JSON.parse(l));
    const meta = lines[0]._batch_meta;
    expect(meta.batch_id).toBe(key.split("/").pop()?.replace(/\.ndjson$/, ""));
    expect(meta.event_count).toBe(2);
    expect(meta.rejected_count).toBe(1);
    expect(new Date(meta.received_at).toString()).not.toBe("Invalid Date");

    // Schema-valid events are archived verbatim, in batch order.
    expect(lines[1]).toEqual(JSON.parse(JSON.stringify(good)));

    // The event schema validation rejected keeps its line — so batch order
    // and line count still describe what the collector sent — but only as a
    // fingerprint. The payload itself is never written.
    expect(lines[2]._rejected).toMatchObject({ batch_index: 1, payload_keys: ["event_id"] });
    expect(lines[2]._rejected.payload_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(lines[2]).not.toHaveProperty("event_id");
    expect(body).not.toContain("not-a-uuid");

    // Replayability: dropping the meta line and the stubs leaves exactly the
    // events that re-validate.
    const replayable = lines
      .slice(1)
      .filter((l: Record<string, unknown>) => !("_rejected" in l));
    expect(replayable).toHaveLength(1);
    expect(validateEvent(replayable[0]).valid).toBe(true);
  });

  test("content-bearing event is never archived, only fingerprinted", async () => {
    archive.puts = [];
    // A buggy or malicious collector that puts prompt text on the wire.
    // additionalProperties:false rejects it, and the archive is written after
    // validation — so object storage never sees it. Archiving before
    // validation (the pre-fix order) landed this verbatim in the bucket.
    const leaky = { ...makeEvent(), prompt_text: CANARY, code_snippet: CANARY };

    const res = await post([leaky]);
    expect(res.statusCode).toBe(200);
    expect(res.json().accepted).toBe(0);
    expect(res.json().rejected).toHaveLength(1);

    expect(archive.puts).toHaveLength(1);
    const { body } = archive.puts[0]!;
    expect(body).not.toContain(CANARY);

    const lines = body.trimEnd().split("\n").map((l: string) => JSON.parse(l));
    expect(lines[0]._batch_meta.rejected_count).toBe(1);
    // Key names survive for audit — the AIM-650 posture is "we can prove what
    // shape arrived", not "we keep it".
    expect(lines[1]._rejected.payload_keys).toContain("prompt_text");
    expect(lines[1]._rejected.payload_keys).toContain("code_snippet");

    // The stub joins to its rejected_events row on payload_hash.
    const dlq = await pool.query(
      "SELECT payload_keys FROM rejected_events WHERE payload_hash = $1",
      [lines[1]._rejected.payload_hash],
    );
    expect(dlq.rows).toHaveLength(1);
  });

  test("unknown keys on the collector envelope never reach the archive meta", async () => {
    archive.puts = [];
    const res = await app.inject({
      method: "POST",
      url: "/v1/events",
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: {
        events: [makeEvent()],
        // parseCollectorIdentity allowlists device_id/os_user/build and
        // ignores everything else, so the parsed identity — not the raw wire
        // envelope — is what gets archived.
        collector: { device_id: randomUUID(), os_user: "alice", prompt_text: CANARY },
      },
    });
    expect(res.statusCode).toBe(200);

    const { body } = archive.puts[0]!;
    expect(body).not.toContain(CANARY);
    const meta = JSON.parse(body.split("\n")[0]!)._batch_meta;
    expect(Object.keys(meta.collector).sort()).toEqual(["device_id", "os_user"]);
  });

  test("archive failure is fail-open: batch still stored, error counted", async () => {
    archive.fail = true;
    const event = makeEvent();

    const res = await post([event]);
    expect(res.statusCode).toBe(200);
    expect(res.json().accepted).toBe(1);

    const stored = await pool.query("SELECT event_id FROM events WHERE event_id = $1", [
      event.event_id,
    ]);
    expect(stored.rows).toHaveLength(1);

    const metrics = await app.inject({ method: "GET", url: "/metrics" });
    expect(metrics.body).toContain("ingest_archive_errors_total 1");
    archive.fail = false;
  });

  test("unauthorized and malformed batches are never archived", async () => {
    archive.puts = [];
    expect((await post([makeEvent()], "wrong-token")).statusCode).toBe(401);
    expect((await post([])).statusCode).toBe(400);
    expect(archive.puts).toHaveLength(0);
  });

  test("collector identity is preserved in the meta line", async () => {
    archive.puts = [];
    const res = await app.inject({
      method: "POST",
      url: "/v1/events",
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: {
        events: [makeEvent()],
        collector: { device_id: randomUUID(), os_user: "alice" },
      },
    });
    expect(res.statusCode).toBe(200);
    const meta = JSON.parse(archive.puts[0]!.body.split("\n")[0]!)._batch_meta;
    expect(meta.collector.os_user).toBe("alice");
  });
});

describe("archive key + NDJSON helpers", () => {
  test("archiveKey partitions by UTC date", () => {
    const at = new Date("2026-07-22T13:00:00Z");
    expect(archiveKey("abc", at)).toBe("raw/2026/07/22/abc.ndjson");
  });

  const meta = {
    batch_id: "b1",
    received_at: "2026-07-22T13:00:00.000Z",
    collector: null,
    event_count: 2,
    rejected_count: 1,
  };

  test("toArchiveNdjson writes valid events verbatim and rejects as fingerprints", () => {
    const event = makeEvent();
    const body = toArchiveNdjson(meta, [
      { kind: "accepted", event },
      {
        kind: "rejected",
        rejected: {
          batchIndex: 1,
          error: "(root): unexpected property 'prompt_text'",
          payload: { prompt_text: CANARY },
        },
      },
    ]);

    const lines = body.trimEnd().split("\n");
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[0]!)._batch_meta.batch_id).toBe("b1");
    expect(JSON.parse(lines[1]!)).toEqual(JSON.parse(JSON.stringify(event)));
    expect(body).not.toContain(CANARY);
    expect(JSON.parse(lines[2]!)._rejected).toEqual({
      batch_index: 1,
      error: "(root): unexpected property 'prompt_text'",
      payload_hash: hex64(JSON.stringify({ prompt_text: CANARY })),
      payload_keys: ["prompt_text"],
    });
  });

  test("embedded newlines keep the one-JSON-value-per-line invariant", () => {
    const body = toArchiveNdjson({ ...meta, event_count: 1 }, [
      {
        kind: "rejected",
        rejected: { batchIndex: 0, error: "first\nsecond", payload: { a: "x\ny" } },
      },
    ]);
    expect(body.trimEnd().split("\n")).toHaveLength(2);
  });
});

describe("object store config (AIM-83)", () => {
  const base = { DATABASE_URL: "postgres://x", INGEST_TOKENS: "t" };

  test("disabled when endpoint and bucket are both unset", () => {
    expect(loadConfig(base).objectStore).toBeUndefined();
  });

  test("enabled with credentials, region defaults to us-east-1", () => {
    const cfg = loadConfig({
      ...base,
      OBJECT_STORE_ENDPOINT: "http://minio:9000",
      OBJECT_STORE_BUCKET: "b",
      OBJECT_STORE_ACCESS_KEY: "k",
      OBJECT_STORE_SECRET_KEY: "s",
    });
    expect(cfg.objectStore).toEqual({
      endpoint: "http://minio:9000",
      bucket: "b",
      region: "us-east-1",
      accessKey: "k",
      secretKey: "s",
    });
  });

  test("endpoint without bucket (or vice versa) fails fast", () => {
    expect(() => loadConfig({ ...base, OBJECT_STORE_ENDPOINT: "http://x" })).toThrow(
      /must be set together/,
    );
    expect(() => loadConfig({ ...base, OBJECT_STORE_BUCKET: "b" })).toThrow(/must be set together/);
  });

  test("missing credentials fail fast when archival is enabled", () => {
    expect(() =>
      loadConfig({
        ...base,
        OBJECT_STORE_ENDPOINT: "http://x",
        OBJECT_STORE_BUCKET: "b",
      }),
    ).toThrow(/OBJECT_STORE_ACCESS_KEY/);
  });
});

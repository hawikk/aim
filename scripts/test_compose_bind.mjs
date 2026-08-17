#!/usr/bin/env node
/**
 * AIM-184: the compose stacks must not publish anything on 0.0.0.0 by default.
 *
 * A `ports:` entry written "5432:5432" has no interface, so Docker binds it to
 * every address the host has — and because publishing is done with DNAT rules
 * inserted ahead of the INPUT chain, a host firewall does not stop it. Running
 * this repo's compose is the documented way to run AIM locally, so that shape
 * hands the telemetry database to anyone on the same network.
 *
 * This asserts on the *rendered* config (`docker compose config --format json`),
 * not on the source text: it reads back the host_ip Docker will actually bind,
 * which is what a substring grep for "0.0.0.0" would miss. A mapping with no
 * interface renders host_ip "" — an empty host_ip means 0.0.0.0, and this
 * treats it as such.
 *
 * Run: node --test scripts/test_compose_bind.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Interfaces that expose a port beyond the local machine. */
const WILDCARD = new Set(['', '0.0.0.0', '::', '[::]', '*']);

/** Services whose ports carry data at rest, not an authenticated API. */
const DATASTORES = new Set(['postgres', 'minio', 'redis-bus']);

const COMPOSE_FILES = ['docker-compose.yml', 'infra/docker-compose.yml'];

/**
 * Render one compose file with a scrubbed environment.
 *
 * env -i equivalent: a developer's exported POSTGRES_PORT or a repo-root .env
 * must not be able to change what this test sees, in either direction — the
 * point is the behaviour a fresh clone gets. --env-file /dev/null suppresses
 * the implicit ./.env load. `--profile '*'` renders profile-gated services too,
 * so one added behind a profile is still covered.
 *
 * `overrides` are the variables under test; the two `:?`-required values below
 * only exist so infra/docker-compose.yml renders at all.
 */
function renderPorts(file, overrides = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    POSTGRES_PASSWORD: 'test-only',
    INGEST_TOKENS: 'test-only',
    ...overrides,
  };
  let out;
  try {
    out = execFileSync(
      'docker',
      ['compose', '--env-file', '/dev/null', '--profile', '*', '-f', file, 'config', '--format', 'json'],
      { cwd: REPO, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch (err) {
    // Loud, never skipped: a green run that rendered nothing would be the same
    // silent pass this test exists to prevent.
    throw new Error(
      `docker compose config failed for ${file} — this test needs the docker CLI.\n` +
        `${err.stderr || err.message}`,
    );
  }
  const parsed = JSON.parse(out);
  const rows = [];
  for (const [service, spec] of Object.entries(parsed.services ?? {})) {
    for (const port of spec.ports ?? []) {
      rows.push({ service, hostIp: port.host_ip ?? '', published: String(port.published ?? '') });
    }
  }
  return rows;
}

for (const file of COMPOSE_FILES) {
  test(`${file}: no published port binds a wildcard interface by default`, () => {
    const rows = renderPorts(file);
    // Guard against a rename or a config that renders no ports at all: an
    // empty result would satisfy every assertion below without proving one.
    assert.ok(rows.length > 0, `${file} rendered no published ports — nothing was checked`);
    const exposed = rows.filter((r) => WILDCARD.has(r.hostIp));
    assert.deepEqual(
      exposed,
      [],
      `${file} publishes on a wildcard interface: ` +
        `${exposed.map((r) => `${r.service} -> ${r.hostIp || '(no interface)'}:${r.published}`).join(', ')}. ` +
        'Prefix the mapping with ${AIM_BIND_ADDR:-127.0.0.1} (or ${AIM_DATASTORE_BIND_ADDR:-127.0.0.1}).',
    );
  });

  test(`${file}: an empty bind address falls back to loopback, not 0.0.0.0`, () => {
    // `${VAR-default}` would render ":5432:5432" here, which Compose reads as
    // an empty host_ip — i.e. wide open. `${VAR:-default}` is load-bearing.
    const rows = renderPorts(file, { AIM_BIND_ADDR: '', AIM_DATASTORE_BIND_ADDR: '' });
    assert.ok(rows.length > 0, `${file} rendered no published ports`);
    for (const row of rows) {
      assert.equal(row.hostIp, '127.0.0.1', `${file}: ${row.service}:${row.published} with an empty bind address`);
    }
  });

  test(`${file}: widening the app surfaces does not widen the datastores`, () => {
    // The pilot case: an operator publishes ingest for collectors on other
    // machines. That must not also publish Postgres/MinIO — the two knobs are
    // separate for this reason, and this is the test that keeps them separate.
    const rows = renderPorts(file, { AIM_BIND_ADDR: '0.0.0.0' });
    const stores = rows.filter((r) => DATASTORES.has(r.service));
    if (file === 'docker-compose.yml') {
      assert.ok(stores.length > 0, 'expected postgres/minio to be rendered');
    }
    for (const row of stores) {
      assert.equal(
        row.hostIp,
        '127.0.0.1',
        `${file}: datastore ${row.service}:${row.published} followed AIM_BIND_ADDR — it must use AIM_DATASTORE_BIND_ADDR`,
      );
    }
  });

  test(`${file}: the bind address is actually wired through`, () => {
    // Without this, every assertion above would still pass if the ports were
    // hardcoded to 127.0.0.1 and the variables were dead.
    const rows = renderPorts(file, { AIM_BIND_ADDR: '10.1.2.3', AIM_DATASTORE_BIND_ADDR: '10.4.5.6' });
    const seen = new Set(rows.map((r) => r.hostIp));
    assert.ok(seen.has('10.1.2.3'), `${file}: AIM_BIND_ADDR had no effect (rendered ${[...seen].join(', ')})`);
    if (file === 'docker-compose.yml') {
      assert.ok(
        seen.has('10.4.5.6'),
        `${file}: AIM_DATASTORE_BIND_ADDR had no effect (rendered ${[...seen].join(', ')})`,
      );
    }
  });
}

#!/usr/bin/env node
/**
 * pilot pull overrides must (1) clear `build:` on the pilot image
 * set, (2) pin `image:` from AIM_*_IMAGE, and (3) leave contributor
 * `docker compose up --build` intact when the pull override is not used.
 *
 * Run: node --test scripts/test_compose_pull.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { statSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const PILOT_BUILD_SERVICES = ['ingest', 'api', 'guardrail', 'identity-sync'];
const PILOT_GATED = ['gatehouse', 'sentinel', 'hygiene-cron', 'shadow-ai'];

function render(files, overrides = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    POSTGRES_PASSWORD: 'test-only',
    INGEST_TOKENS: 'test-only',
    AIM_INGEST_IMAGE: 'ghcr.io/hawikk/aim-ingest@sha256:' + 'a'.repeat(64),
    AIM_API_IMAGE: 'ghcr.io/hawikk/aim-api@sha256:' + 'b'.repeat(64),
    AIM_GUARDRAIL_IMAGE: 'ghcr.io/hawikk/aim-guardrail@sha256:' + 'c'.repeat(64),
    AIM_IDENTITY_SYNC_IMAGE:
      'ghcr.io/hawikk/aim-identity-sync@sha256:' + 'd'.repeat(64),
    AIM_IMAGE_TAG: 'main-deadbeef',
    ...overrides,
  };
  const args = ['compose', '--env-file', '/dev/null'];
  for (const f of files) {
    args.push('-f', f);
  }
  args.push('config', '--format', 'json');
  const out = execFileSync('docker', args, {
    cwd: REPO,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return JSON.parse(out);
}

test('base compose still has build: for pilot app services (contributor path)', () => {
  const cfg = render(['docker-compose.yml']);
  for (const name of PILOT_BUILD_SERVICES) {
    const svc = cfg.services[name];
    assert.ok(svc, `missing service ${name}`);
    assert.ok(svc.build, `${name} should keep build: without pull override`);
  }
});

test('pilot.yml gates non-pilot pillars behind profiles', () => {
  const cfg = render([
    'docker-compose.yml',
    'deploy/compose/docker-compose.pilot.yml',
  ]);
  for (const name of PILOT_BUILD_SERVICES) {
    assert.ok(cfg.services[name], `pilot service missing: ${name}`);
    const profiles = cfg.services[name].profiles || [];
    assert.equal(profiles.length, 0, `${name} must not be profile-gated`);
  }
  for (const name of PILOT_GATED) {
    const svc = cfg.services[name];
    if (svc) {
      const profiles = svc.profiles || [];
      assert.ok(
        profiles.length > 0,
        `${name} should be profile-gated when present in config`,
      );
    }
  }
});

test('pull.yml clears build and pins digest images for pilot set', () => {
  const cfg = render([
    'docker-compose.yml',
    'deploy/compose/docker-compose.pilot.yml',
    'deploy/compose/docker-compose.pull.yml',
  ]);
  for (const name of PILOT_BUILD_SERVICES) {
    const svc = cfg.services[name];
    assert.ok(svc, `missing ${name}`);
    assert.equal(
      svc.build,
      undefined,
      `${name} build: must be reset by pull override`,
    );
    assert.ok(svc.image, `${name} must have image:`);
    assert.match(
      svc.image,
      /@sha256:[a-f0-9]{64}$/,
      `${name} image should be digest-pinned in this test`,
    );
  }
  // Dashboard is the api service image.
  assert.match(cfg.services.api.image, /aim-api@sha256:/);
});

test('install-pilot.sh is executable and documents modes', () => {
  const script = path.join(REPO, 'scripts/install-pilot.sh');
  const st = statSync(script);
  assert.ok((st.mode & 0o111) !== 0, 'install-pilot.sh must be executable');
  const body = readFileSync(script, 'utf8');
  for (const flag of ['--pull', '--build', '--prefer-pull']) {
    assert.ok(body.includes(flag), `missing flag ${flag}`);
  }
});

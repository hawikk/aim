#!/usr/bin/env node
// Thin wrapper — Playwright lives under apps/web.
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, '..', 'apps', 'web', 'scripts', 'capture-readme-screenshots.mjs');
const r = spawnSync(process.execPath, [script, ...process.argv.slice(2)], {
  stdio: 'inherit',
  cwd: join(here, '..', 'apps', 'web'),
  env: process.env,
});
process.exit(r.status ?? 1);

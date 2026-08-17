#!/usr/bin/env node
/**
 * Headless screenshots of dashboard views.
 *
 * Why this exists: UI PRs require pixel evidence, and the agent environment
 * previously had no browser. The decision was "add a headless browser as a
 * devDependency" rather than shipping CSS changes on jsdom dumps alone.
 *
 * Supply-chain posture (same discipline as Chart.js, different layer):
 *  - `playwright` is a *devDependency only*. It never ships in the static UI
 *    bundle, is never loaded from a CDN, and is never a runtime import path
 *    for operator-facing code.
 *  - Pin exact version in package.json (no caret). Browsers are installed
 *    separately via `npx playwright install chromium` — not at `npm ci` —
 *    so CI unit tests stay free of a 170MB binary download on every run.
 *  - The fixture server + DOM fixtures are the same ones the test floor uses;
 *    screenshots are of the real public/ modules against the same data.
 *
 * Usage:
 *   cd apps/web
 *   npm ci
 *   npx playwright install chromium   # once per machine / CI image
 *   npm run screenshot
 *   npm run screenshot -- --views rules,onboarding --themes dark,light
 *   npm run screenshot -- --out /tmp/aim-shots --views overview,security,findings,inbox
 *
 * Exit 2 if Chromium is not installed (so a missing browser is loud, not a
 * silent empty directory).
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { startFixtureServer } from '../test/helpers/fixture-server.js';

const here = dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT = join(here, '..', 'test', 'screenshots');
const DEFAULT_VIEWS = ['rules', 'onboarding', 'overview', 'security', 'findings', 'inbox'];
const DEFAULT_THEMES = ['dark', 'light'];
const VIEWPORT = { width: 1440, height: 900 };

function parseArgs(argv) {
  const out = {
    out: DEFAULT_OUT,
    views: DEFAULT_VIEWS,
    themes: DEFAULT_THEMES,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') out.out = resolve(argv[++i]);
    else if (a === '--views') out.views = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--themes') out.themes = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--help' || a === '-h') {
      console.log(`Usage: node scripts/screenshot.mjs [--out DIR] [--views a,b] [--themes dark,light]`);
      process.exit(0);
    }
  }
  for (const t of out.themes) {
    if (t !== 'dark' && t !== 'light') {
      console.error(`unknown theme "${t}" (want dark|light)`);
      process.exit(1);
    }
  }
  return out;
}

/** Wait until the named view is the active panel (module fetches may lag). */
async function waitForView(page, view, timeoutMs = 15000) {
  await page.waitForFunction(
    (v) => {
      const panel = document.querySelector(`#view-${v}`);
      if (!panel || !panel.classList.contains('active')) return false;
      // Module views set aria-busy while the first fetch is in flight.
      const busy = panel.querySelector('[aria-busy="true"]');
      return !busy;
    },
    view,
    { timeout: timeoutMs },
  );
}

async function applyTheme(page, theme) {
  // Match public/lib/theme.js: dark is attribute-less, light sets data-theme.
  await page.evaluate((t) => {
    try {
      localStorage.setItem('aim.theme', t);
    } catch { /* storage blocked: still set the attribute for this capture */ }
    if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    // Prefer the real runtime path when the module has loaded.
    window.dispatchEvent(new CustomEvent('aim:themechange', { detail: { theme: t } }));
  }, theme);
  // One paint after the attribute flip so CSS variables recompute.
  await page.waitForTimeout(50);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  await mkdir(opts.out, { recursive: true });

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (err) {
    console.error('Chromium is not available to Playwright.');
    console.error('Install it once with:  npx playwright install chromium');
    console.error(String(err?.message || err));
    process.exit(2);
  }

  const server = await startFixtureServer({ mode: 'populated' });
  const page = await browser.newPage({ viewport: VIEWPORT, deviceScaleFactor: 1 });
  const written = [];

  try {
    for (const theme of opts.themes) {
      for (const view of opts.views) {
        // Seed theme before first paint so the inline pre-paint script in
        // index.html picks it up (avoids a flash-then-capture of the wrong theme).
        await page.addInitScript((t) => {
          try { localStorage.setItem('aim.theme', t); } catch { /* ignore */ }
        }, theme);

        await page.goto(`${server.origin}/#/${view}`, { waitUntil: 'networkidle' });
        await applyTheme(page, theme);
        // Hash navigation on a cold load: modules register async after /api/me
        // and their own capability fetches. Re-assert the target once the tab
        // exists (module tabs are injected, not in index.html).
        await page.waitForFunction(
          (v) => !!document.querySelector(`#tab-${v}`) || !!document.querySelector(`#view-${v}`),
          view,
          { timeout: 15000 },
        );
        // Drive the tab so module views that lost the landing race reclaim the panel.
        await page.evaluate((v) => {
          const tab = document.querySelector(`#tab-${v}`);
          if (tab) tab.click();
        }, view);
        await waitForView(page, view);

        const file = join(opts.out, `${view}-${theme}.png`);
        await page.screenshot({ path: file, fullPage: false });
        written.push(file);
        console.log(`wrote ${file}`);
      }
    }

    const manifest = {
      generatedAt: new Date().toISOString(),
      viewport: VIEWPORT,
      views: opts.views,
      themes: opts.themes,
      files: written.map((p) => p.replace(/\\/g, '/')),
      note: 'Fixture-backed captures of apps/web/public against test/helpers/fixtures.js. Not production telemetry.',
    };
    const manifestPath = join(opts.out, 'manifest.json');
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`wrote ${manifestPath}`);
    console.log(`\n${written.length} screenshot(s) in ${opts.out}`);
  } finally {
    await page.close().catch(() => {});
    await browser.close().catch(() => {});
    await server.close().catch(() => {});
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

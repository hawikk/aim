#!/usr/bin/env node
/**
 * Capture README hero screenshots from a LIVE aim-api dashboard.
 *
 * Default: http://127.0.0.1:8181 (aim-local personal/standalone — no SSO).
 * Viewport 1440×900 @ deviceScaleFactor 2 → 2880×1800 PNGs (matches legacy assets).
 *
 * Usage:
 *   node scripts/capture-readme-screenshots.mjs
 *   AIM_BASE=http://127.0.0.1:8181 node scripts/capture-readme-screenshots.mjs --out docs/screenshots
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..', '..', '..');  // apps/web/scripts → repo root
const DEFAULT_OUT = join(ROOT, 'docs', 'screenshots');
const DEFAULT_BASE = process.env.AIM_BASE || 'http://127.0.0.1:8181';

// Hero set + chrome reference shots used by README.
const SHOTS = [
  { name: 'overview', hash: '#/overview', waitMs: 2500 },
  { name: 'security', hash: '#/security', waitMs: 2500 },
  { name: 'activity', hash: '#/activity', waitMs: 2500 },
  { name: 'fleet', hash: '#/fleet', waitMs: 2500 },
  // Sidebar chrome reference (README theme-dark / theme-light)
  { name: 'theme-dark', hash: '#/overview', theme: 'dark', waitMs: 2000 },
  { name: 'theme-light', hash: '#/overview', theme: 'light', waitMs: 2000 },
];

const VIEWPORT = { width: 1440, height: 900 };
const SCALE = 2;

function parseArgs(argv) {
  let out = DEFAULT_OUT;
  let base = DEFAULT_BASE;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') out = resolve(argv[++i]);
    else if (argv[i] === '--base') base = argv[++i];
  }
  return { out, base };
}

async function setTheme(page, theme) {
  await page.evaluate((t) => {
    try {
      localStorage.setItem('aim.theme', t);
    } catch { /* ignore */ }
    if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    window.dispatchEvent(new CustomEvent('aim:themechange', { detail: { theme: t } }));
  }, theme);
  await page.waitForTimeout(80);
}

async function dismissNoise(page) {
  // Close any toast / cookie banners if present (best-effort).
  await page.evaluate(() => {
    for (const sel of [
      '[data-dismiss]',
      'button[aria-label="Dismiss"]',
      'button[aria-label="Close"]',
      '.toast button',
    ]) {
      document.querySelectorAll(sel).forEach((el) => {
        try { el.click(); } catch { /* ignore */ }
      });
    }
  });
}

async function waitForDashboard(page) {
  // /api/me must succeed (personal mode or session).
  await page.waitForFunction(
    () => {
      const tabs = document.querySelector('#tabs') || document.querySelector('nav');
      const body = document.body;
      if (!tabs || !body) return false;
      // Avoid blank auth-redirect shells.
      const text = body.innerText || '';
      if (/sign in|unauthenticated|login/i.test(text) && text.length < 400) return false;
      return true;
    },
    { timeout: 20000 },
  );
}

async function activateView(page, hash) {
  const view = hash.replace(/^#\//, '').split(/[/?]/)[0];
  await page.evaluate((h) => {
    location.hash = h;
  }, hash);
  await page.waitForTimeout(200);
  // Click tab if present (module views / capability-gated tabs).
  await page.evaluate((v) => {
    const tab = document.querySelector(`#tab-${v}`) || document.querySelector(`[data-view="${v}"]`);
    if (tab) tab.click();
    // Expand parent nav group if collapsed.
    const group = tab?.closest('.nav-group-wrap');
    if (group && group.getAttribute('data-collapsed') === 'true') {
      const toggle = group.querySelector('[data-nav-toggle]');
      if (toggle) toggle.click();
    }
  }, view);
  // Wait for active panel when view shell exists.
  await page.waitForFunction(
    (v) => {
      const panel = document.querySelector(`#view-${v}`);
      if (!panel) return true; // some routes paint differently
      if (!panel.classList.contains('active') && panel.getAttribute('hidden') != null) return false;
      const busy = panel.querySelector('[aria-busy="true"]');
      return !busy;
    },
    view,
    { timeout: 20000 },
  ).catch(() => {});
}

async function main() {
  const { out, base } = parseArgs(process.argv.slice(2));
  await mkdir(out, { recursive: true });

  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--disable-dev-shm-usage', '--no-sandbox'],
    });
  } catch (err) {
    console.error('Chromium unavailable. Run: cd apps/web && npx playwright install chromium');
    console.error(String(err?.message || err));
    process.exit(2);
  }

  const context = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: SCALE,
    colorScheme: 'dark',
  });
  const page = await context.newPage();
  const written = [];
  const stamp = new Date().toISOString();

  try {
    // Warm session (personal mode issues identity on first hit).
    await page.goto(`${base}/`, { waitUntil: 'networkidle', timeout: 60000 });
    await waitForDashboard(page);
    await dismissNoise(page);

    for (const shot of SHOTS) {
      const theme = shot.theme || 'dark';
      await page.addInitScript((t) => {
        try { localStorage.setItem('aim.theme', t); } catch { /* ignore */ }
      }, theme);

      await setTheme(page, theme);
      await activateView(page, shot.hash);
      // Extra settle for charts / table paints
      await page.waitForTimeout(shot.waitMs || 2000);
      await dismissNoise(page);

      // Hide cursor-ish focus rings for cleaner marketing shots.
      await page.evaluate(() => {
        if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      });

      const dest = join(out, `${shot.name}.png`);
      await page.screenshot({
        path: dest,
        fullPage: false,
        type: 'png',
        animations: 'disabled',
      });
      written.push(dest);
      console.log(`wrote ${dest}`);
    }

    const manifest = {
      generatedAt: stamp,
      base,
      viewport: VIEWPORT,
      deviceScaleFactor: SCALE,
      pixelSize: { width: VIEWPORT.width * SCALE, height: VIEWPORT.height * SCALE },
      files: written,
      note: 'Live aim-api captures for README heroes. Prefer aim-local personal mode (no SSO).',
    };
    const man = join(out, 'readme-screenshots-manifest.json');
    await writeFile(man, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`wrote ${man}`);
    console.log(`\n${written.length} screenshot(s) → ${out}`);
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

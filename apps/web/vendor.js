// Copies Chart.js from node_modules into public/vendor so the dashboard has no
// runtime CDN dependency (no third-party requests from a security tool's UI).
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// chart.js exports map exposes neither dist/* nor package.json; use the direct
// node_modules path (this script only runs at install time inside apps/web).
const src = join(here, 'node_modules', 'chart.js', 'dist', 'chart.umd.js');
const destDir = join(here, 'public', 'vendor');
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, 'chart.umd.js'));
console.log(`vendored ${src} -> public/vendor/chart.umd.js`);

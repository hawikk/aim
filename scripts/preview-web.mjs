// Local preview server for the dashboard redesign (AIM-151).
// Serves apps/web/public from the working tree and proxies /api + /auth to a
// running api service, so the new UI can be reviewed against REAL collector
// telemetry instead of a seed fixture. Dev-only; never shipped in an image.
//
//   node scripts/preview-web.mjs [--port 8099] [--upstream http://localhost:8085]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) args.set(process.argv[i].replace(/^--/, ''), process.argv[i + 1]);
const PORT = Number(args.get('port') ?? 8099);
const UPSTREAM = args.get('upstream') ?? 'http://localhost:8085';
const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'apps', 'web', 'public');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
};

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/auth')) {
    try {
      const up = await fetch(UPSTREAM + req.url, {
        method: req.method,
        headers: { ...req.headers, host: new URL(UPSTREAM).host },
        redirect: 'manual',
      });
      res.writeHead(up.status, Object.fromEntries(up.headers));
      res.end(Buffer.from(await up.arrayBuffer()));
    } catch (err) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ detail: `upstream ${UPSTREAM} unreachable: ${err.message}` }));
    }
    return;
  }
  // Static, path-traversal safe.
  const rel = normalize(url.pathname === '/' ? '/index.html' : url.pathname).replace(/^(\.\.[/\\])+/, '');
  try {
    let body = await readFile(join(ROOT, rel));
    // ?activate=<view> forces a tab for headless screenshots. Modules like
    // onboarding legitimately claim the initial landing on a first-run stack,
    // which otherwise makes it impossible to capture the other views.
    const activate = url.searchParams.get('activate');
    if (rel.endsWith('index.html') && /^[a-z-]+$/.test(activate ?? '')) {
      // Modules activate asynchronously once their own fetches settle, and
      // under --virtual-time-budget timers fire long before real network I/O
      // completes — so a fixed delay always loses the race. Re-click the target
      // whenever something else holds the main area; this settles as soon as
      // the last module has had its say.
      // Note: drive the range via the control, not via the hash — the range
      // buttons are the only way to get a days filter onto a module view.
      const range = url.searchParams.get('range');
      const rangeJs = /^\d+$/.test(range ?? '')
        ? `const r=document.querySelector('#range button[data-days="${range}"]');if(r&&!r.classList.contains('active'))r.click();`
        : '';
      // Since AIM-152 a re-click actually re-renders even when the hash already
      // matches, so clicking is enough to reclaim the view — this no longer has
      // to forge .active classes behind the router's back. Settle the view
      // FIRST and only then touch the range, or the range click leaves the
      // router with nothing to re-render.
      body = Buffer.from(String(body).replace('</body>',
        `<script>setInterval(()=>{`
        + `const b=document.querySelector('#tab-${activate}');`
        + `const v=document.querySelector('#view-${activate}');`
        + `if(!b||!v)return;`
        + `if(!v.classList.contains('active')){b.click();return;}`
        + `${rangeJs}},50)</script></body>`));
    }
    res.writeHead(200, { 'content-type': TYPES[extname(rel)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(PORT, () => console.log(`preview: http://localhost:${PORT} (api -> ${UPSTREAM})`));

/* Widget data loaders for the custom dashboards builder (AIM-1162 split).
 * Each catalog entry has a `source` key; multiple widgets sharing a source
 * (e.g. four overview KPIs) resolve once per canvas paint via dctx.dataCache. */
import { api } from '../lib/api.js';
import { dctx } from './state.js';

/** Mirror the topbar range without coupling to app.js state. The hash query
 * is the source of truth for shareable range; default 30 when absent. */
export function currentDays() {
  try {
    const raw = String(location.hash || '').replace(/^#\/?/, '');
    const q = new URLSearchParams(raw.split('?')[1] || '');
    const days = Number(q.get('days'));
    return [7, 30, 90].includes(days) ? days : 30;
  } catch {
    return 30;
  }
}

export async function loadSource(source, days) {
  const key = `${source}:${days}`;
  if (dctx.dataCache.has(key)) return dctx.dataCache.get(key);
  const caps = dctx.caps || {};
  const promise = (async () => {
    switch (source) {
      case 'overview':
        return api(`/api/overview?days=${days}`);
      case 'tools': {
        const list = await api(`/api/tools?days=${days}`);
        return Array.isArray(list) ? list : (list?.tools ?? []);
      }
      case 'unapproved': {
        const d = await api(`/api/unapproved?days=${days}`);
        return Array.isArray(d) ? d : (d?.unapproved ?? d?.tools ?? []);
      }
      case 'flags':
        return api(`/api/flags?days=${days}`);
      case 'teams': {
        const d = await api(`/api/teams?days=${days}`);
        return Array.isArray(d) ? d : (d?.teams ?? []);
      }
      case 'findingsCritical': {
        if (!caps.findingsConsole) return { total: null, gated: true };
        return api('/api/findings?status=new,acknowledged&severity=critical&limit=1');
      }
      case 'findingsOpen': {
        if (!caps.findingsConsole) return { findings: [], gated: true };
        const [crit, high] = await Promise.all([
          api('/api/findings?status=new,acknowledged&severity=critical&limit=25'),
          api('/api/findings?status=new,acknowledged&severity=high&limit=25'),
        ]);
        return {
          findings: [...(crit?.findings ?? []), ...(high?.findings ?? [])],
        };
      }
      default:
        throw new Error(`Unknown widget source ${source}`);
    }
  })().catch((err) => {
    dctx.dataCache.delete(key);
    throw err;
  });
  dctx.dataCache.set(key, promise);
  return promise;
}

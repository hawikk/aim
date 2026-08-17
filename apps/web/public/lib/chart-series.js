/* Pure trend-series builders.
 * Kept free of DOM / Chart.js so unit tests and views share one vocabulary. */

export const ACCENT = '--accent';
export const GOOD = '--good';
export const BAD = '--bad';
export const WARN = '--warn';
export const PALETTE = [ACCENT, GOOD, WARN, BAD, '--muted', '--sev-high'];

/**
 * Detection-volume series from /api/flags trend rows.
 * Primary series is total hits/day; top-N detectors as secondary lines.
 *
 * @param {Array<{day: string, detector: string, hits: number}>} trend
 * @param {{ topN?: number, labelDay?: (day: string) => string }} [opts]
 * @returns {{ labels: string[], series: Array<{label: string, data: number[], token?: string}> }}
 */
export function detectionVolumeSeries(trend, opts = {}) {
  const topN = opts.topN ?? 4;
  const labelDay = opts.labelDay ?? ((d) => d);
  const rows = Array.isArray(trend) ? trend : [];
  if (rows.length === 0) return { labels: [], series: [] };

  const dayKeys = [...new Set(rows.map((t) => t.day))].sort();
  const labels = dayKeys.map(labelDay);
  const byDet = new Map();
  const totals = dayKeys.map(() => 0);
  for (const t of rows) {
    const di = dayKeys.indexOf(t.day);
    if (di < 0) continue;
    const hits = Number(t.hits) || 0;
    totals[di] += hits;
    if (!byDet.has(t.detector)) byDet.set(t.detector, dayKeys.map(() => 0));
    byDet.get(t.detector)[di] += hits;
  }
  const ranked = [...byDet.entries()]
    .map(([det, data]) => ({ det, data, sum: data.reduce((a, b) => a + b, 0) }))
    .sort((a, b) => b.sum - a.sum);
  const series = [
    { label: 'All detections', data: totals, token: ACCENT },
    ...ranked.slice(0, topN).map((r, i) => ({
      label: r.det,
      data: r.data,
      token: PALETTE[(i + 1) % PALETTE.length],
    })),
  ];
  return { labels, series };
}

/**
 * Enforce-block series from /api/enforcement trend rows.
 * blocked = hard deny, would_block = shadow, confirmed = break-glass override.
 *
 * @param {Array<{day: string, blocked?: number, would_block?: number, confirmed?: number}>} trend
 * @param {{ labelDay?: (day: string) => string }} [opts]
 */
export function enforcementBlocksSeries(trend, opts = {}) {
  const labelDay = opts.labelDay ?? ((d) => d);
  const rows = Array.isArray(trend) ? trend : [];
  if (rows.length === 0) return { labels: [], series: [] };
  const sorted = [...rows].sort((a, b) => String(a.day).localeCompare(String(b.day)));
  const labels = sorted.map((r) => labelDay(r.day));
  const series = [
    { label: 'Blocked', data: sorted.map((r) => Number(r.blocked) || 0), token: BAD },
    { label: 'Would-block (shadow)', data: sorted.map((r) => Number(r.would_block) || 0), token: WARN },
    { label: 'Override', data: sorted.map((r) => Number(r.confirmed) || 0), token: ACCENT },
  ];
  return { labels, series };
}

/**
 * Fleet coverage series from optional /api/fleet.trend rows.
 * Prefers healthyPct; otherwise healthy/deployed.
 *
 * @param {Array<{day: string, healthyPct?: number, healthy?: number, deployed?: number, coverageGaps?: number}>} trend
 * @param {{ labelDay?: (day: string) => string }} [opts]
 */
export function fleetCoverageSeries(trend, opts = {}) {
  const labelDay = opts.labelDay ?? ((d) => d);
  const rows = Array.isArray(trend) ? trend : [];
  if (rows.length === 0) return { labels: [], series: [] };
  const sorted = [...rows].sort((a, b) => String(a.day).localeCompare(String(b.day)));
  const labels = sorted.map((r) => labelDay(r.day));
  const pct = sorted.map((r) => {
    if (r.healthyPct != null && Number.isFinite(Number(r.healthyPct))) {
      return Math.max(0, Math.min(100, Number(r.healthyPct)));
    }
    const deployed = Number(r.deployed) || 0;
    const healthy = Number(r.healthy) || 0;
    return deployed > 0 ? Math.round((healthy / deployed) * 1000) / 10 : 0;
  });
  const gaps = sorted.map((r) => Number(r.coverageGaps) || 0);
  const series = [
    { label: 'Healthy %', data: pct, token: GOOD },
    { label: 'Coverage gaps', data: gaps, token: BAD },
  ];
  return { labels, series };
}

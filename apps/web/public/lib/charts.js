/* Chart.js helpers pure-moved from app.js (AIM-527), with AIM-514 token retheme.
 * AIM-588: pure series builders live in chart-series.js (DOM-free for unit tests). */
import { $ } from './dom.js';
import { fmtInt } from './format.js';
import { emptyState } from './components.js';
import { initThemeToggle, THEME_EVENT } from './theme.js';
import { severityColors } from './severity.js';
import {
  ACCENT as SERIES_ACCENT,
  GOOD as SERIES_GOOD,
  BAD as SERIES_BAD,
  WARN,
  detectionVolumeSeries,
  enforcementBlocksSeries,
  fleetCoverageSeries,
} from './chart-series.js';

export { detectionVolumeSeries, enforcementBlocksSeries, fleetCoverageSeries, WARN };

export const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/* AIM-514: a chart color is a TOKEN NAME here, never a hex captured at import. */
export const ACCENT = SERIES_ACCENT || '--accent';
export const GOOD = SERIES_GOOD || '--good';
export const BAD = SERIES_BAD || '--bad';
/* AIM-151: one accent + semantic set + two neutrals. */
/* AIM-524: slot 6 was --sev-high, so a sixth series impersonated a high badge.
 * Status colours are reserved; categorical series must not sit on --sev-*. */
export const PALETTE = [ACCENT, GOOD, '--warn', BAD, '--muted', '--accent-solid'];

function applyChartDefaults() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = cssVar('--muted');
  Chart.defaults.font.size = 12;
  Chart.defaults.font.family = cssVar('--mono');
  Chart.defaults.borderColor = cssVar('--chart-grid');
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.boxHeight = 10;
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.pointStyle = 'circle';
  Chart.defaults.plugins.tooltip.backgroundColor = cssVar('--chart-tooltip-bg');
  Chart.defaults.plugins.tooltip.borderColor = cssVar('--chart-tooltip-border');
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleColor = cssVar('--chart-tooltip-title');
  Chart.defaults.plugins.tooltip.bodyColor = cssVar('--chart-tooltip-body');
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 4;
  /* Fixed short duration. Avoid layout thrash on repaint (AIM-588). */
  Chart.defaults.animation.duration = 150;
}
applyChartDefaults();

export const charts = {};
/* chart instance -> re-resolve token colors. WeakMap so destroyed charts drop out (AIM-514). */
const recolorers = new WeakMap();

const tint = (hex) => (hex?.startsWith('#') && hex.length === 7 ? `${hex}1a` : hex);
const seriesToken = (ds, i) => ds.token || PALETTE[i % PALETTE.length];

export function lineChart(id, labels, datasets, summary, opts = {}) {
  charts[id]?.destroy();
  const canvas = $(id);
  if (!canvas) return;
  const paint = (ds, i, count) => {
    const color = cssVar(seriesToken(ds, i));
    return {
      borderColor: color,
      pointHoverBackgroundColor: color,
      fill: count === 1,
      backgroundColor: tint(color),
    };
  };
  const yScale = {
    beginAtZero: true,
    grid: { color: cssVar('--chart-grid') },
    border: { display: false },
  };
  if (opts.yMax != null) yScale.max = opts.yMax;
  if (opts.suggestedMax != null) yScale.suggestedMax = opts.suggestedMax;
  const chart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: datasets.map((ds, i) => ({
        borderWidth: 1.5,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.25,
        ...ds,
        token: seriesToken(ds, i),
        ...paint(ds, i, datasets.length),
      })),
    },
    options: {
      responsive: true,
      /* Fixed parent .chart-box height — never let Chart.js resize the layout. */
      maintainAspectRatio: false,
      animation: { duration: 150 },
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 12 } },
        y: yScale,
      },
    },
  });
  charts[id] = chart;
  recolorers.set(chart, () => {
    const count = chart.data.datasets.length;
    chart.data.datasets.forEach((ds, i) => Object.assign(ds, paint(ds, i, count)));
    chart.options.scales.y.grid.color = cssVar('--chart-grid');
  });
  setChartState(id, false, null, summary);
}

export function barChart(id, labels, data, label, summary, opts = {}) {
  charts[id]?.destroy();
  const canvas = $(id);
  const severityBands = opts.severityBands ?? null;
  const fill = severityBands
    ? severityColors(severityBands)
    : cssVar(ACCENT);
  if (!canvas) return;
  const chart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label,
        data,
        token: severityBands ? null : ACCENT,
        severityBands,
        backgroundColor: fill,
        borderColor: fill,
        borderWidth: 0,
        borderRadius: 2,
        maxBarThickness: 42,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: cssVar('--chart-grid') }, border: { display: false } },
      },
    },
  });
  charts[id] = chart;
  recolorers.set(chart, () => {
    const [ds] = chart.data.datasets;
    if (ds.severityBands) {
      const colors = severityColors(ds.severityBands);
      ds.backgroundColor = colors;
      ds.borderColor = colors;
    } else {
      ds.backgroundColor = cssVar(ds.token || ACCENT);
      ds.borderColor = ds.backgroundColor;
    }
    chart.options.scales.y.grid.color = cssVar('--chart-grid');
  });
  setChartState(id, false, null, summary);
}

/* Re-resolve every token-derived color and repaint in place (AIM-514). */
function rethemeCharts() {
  applyChartDefaults();
  for (const chart of Object.values(charts)) {
    if (!chart) continue;
    recolorers.get(chart)?.();
    chart.update();
  }
}
/**
 * Wire theme toggle + chart re-coloring. Must run from the cache-busted app.js
 * bootstrap on every harness mount (AIM-551 / AIM-527): `public/lib/*` modules
 * are deliberately shared across mounts, so a top-level call here only fires
 * once and leaves later mounts with a dead toggle (theme.test.js).
 */
export function initCharts() {
  window.addEventListener(THEME_EVENT, rethemeCharts);
  initThemeToggle();
}

export function setChartState(id, isEmpty, empty, summary) {
  const canvas = $(id);
  if (!canvas) return;
  const box = canvas.closest('.chart-box') ?? canvas.parentElement;
  box.querySelector('.empty-state')?.remove();
  if (isEmpty) {
    charts[id]?.destroy();
    delete charts[id];
    canvas.hidden = true;
    canvas.removeAttribute('aria-label');
    box.insertAdjacentHTML('beforeend', emptyState(empty));
  } else {
    canvas.hidden = false;
    if (summary) canvas.setAttribute('aria-label', summary);
  }
}

export function chartSummary(kind, labels, series) {
  const totals = series.map((s) => `${s.label}: total ${fmtInt(s.data.reduce((a, b) => a + b, 0))}`);
  return `${kind} chart over ${labels.length} day(s). ${totals.join('; ')}.`;
}

/* Underscore aliases for AIM-527 private import names used by views/*.js. */
export {
  ACCENT as _ACCENT,
  GOOD as _GOOD,
  PALETTE as _PALETTE,
  cssVar as _cssVar,
  lineChart as _lineChart,
  barChart as _barChart,
  charts as _charts,
  setChartState as _setChartState,
  chartSummary as _chartSummary,
};

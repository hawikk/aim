/* Security view charts (split): severity mix, flags trend,
 * detection volume + enforce blocks. Pure renderers — the
 * orchestrator fetches and passes payloads in. */
import { fmtInt, fmtDay } from '../../lib/format.js';
import { EMPTY } from '../../lib/components.js';
import { lineChart, setChartState, chartSummary, PALETTE, barChart, detectionVolumeSeries, enforcementBlocksSeries } from '../../lib/charts.js';
import { SEVERITY_BANDS, severityBand } from '../../lib/ui.js';

/* "Where is the risk concentrated?" — detector matches banded by severity.
 * Bars coloured from the same --sev-* tokens the pills read. */
export function renderSecSeverityMix(detectors) {
  const byBand = new Map();
  for (const d of detectors ?? []) {
    const band = severityBand(d.severity);
    byBand.set(band, (byBand.get(band) ?? 0) + (d.hits ?? 0));
  }
  const bands = SEVERITY_BANDS.filter((b) => byBand.get(b) > 0);
  if (bands.length === 0) {
    setChartState('#flags-severity', true, {
      needsEvents: true,
      title: 'No detectors triggered',
      body: 'Nothing matched a guardrail detector in this range, so there is no severity mix to show.',
    });
    return;
  }
  const counts = bands.map((b) => byBand.get(b));
  const total = counts.reduce((a, b) => a + b, 0);
  barChart(
    '#flags-severity',
    bands,
    counts,
    'Matches',
    `Bar chart of ${fmtInt(total)} detector matches by severity. `
      + bands.map((b, i) => `${b}: ${fmtInt(counts[i])}`).join('; ') + '.',
    { severityBands: bands },
  );
}

/** Per-detector matches over the window, one line per detector. */
export function renderFlagsTrendChart(flags) {
  if (flags.detectors.length === 0) {
    setChartState('#flags-trend', true, EMPTY.flagsTrend);
    return;
  }
  const days = [...new Set(flags.trend.map((t) => fmtDay(t.day)))];
  const detectors = [...new Set(flags.trend.map((t) => t.detector))];
  const flagSeries = detectors.map((det, i) => ({
    label: det,
    data: days.map((d) => flags.trend.find((t) => fmtDay(t.day) === d && t.detector === det)?.hits ?? 0),
    token: PALETTE[i % PALETTE.length],
  }));
  lineChart('#flags-trend', days, flagSeries, chartSummary('Line', days, flagSeries));
}

/**: detection volume chart from /api/flags.trend. */
export function renderDetectionVolumeChart(flags) {
  const trend = flags?.trend ?? [];
  if (trend.length === 0) {
    setChartState('#flags-trend', true, EMPTY.flagsTrend);
    return;
  }
  const { labels, series } = detectionVolumeSeries(trend, { labelDay: fmtDay, topN: 4 });
  lineChart('#flags-trend', labels, series, chartSummary('Detection volume', labels, series));
}

/**
 * enforce blocks from GET /api/enforcement?days=N.
 * Soft-fail when the endpoint is absent (404/network) so Security still loads;
 * empty state is honest about missing history rather than inventing zeros.
 */
export function renderEnforceBlocksChart(enforcement) {
  const trend = enforcement?.trend ?? [];
  if (!enforcement || trend.length === 0) {
    setChartState('#blocks-trend', true, EMPTY.blocksTrend);
    return;
  }
  const { labels, series } = enforcementBlocksSeries(trend, { labelDay: fmtDay });
  lineChart('#blocks-trend', labels, series, chartSummary('Enforce blocks', labels, series));
}

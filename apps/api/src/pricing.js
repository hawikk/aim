// Rough public list prices, USD per 1M tokens [input, output]. Cost estimates only —
// actual contracts may differ. Unknown models fall back to DEFAULT.
//
// Kept in sync with the personal-mode price table in
// collectors/claude-code/aim_collector/store.py — test/pricing.test.js fails
// the build when the two drift apart.
//
// Lookup is longest-prefix + boundary-aware (see resolvePrice), so versioned
// API ids like claude-sonnet-4-6 and vendor paths like kimi-code/k3 resolve
// without requiring every date-stamped SKU to be hand-listed. Cache-hit rates
// are applied only when a collector sets cost_estimate_usd (schema has no
// tokens_cached column) — otherwise full tokens_in is billed at the uncached
// input rate (overstates agentic tools with high prompt-cache hit rates).
export const PRICE_PER_MTOK = {
  // Anthropic — docs.anthropic.com/en/docs/about-claude/pricing (2026-08).
  // API model ids use hyphens (claude-opus-4-8), not dots.
  // Columns modeled: base input / output. Cache read ≈ 0.1× input (collector).
  'claude-fable-5': [10, 50],
  'claude-mythos-5': [10, 50],
  'claude-opus-5': [5, 25],
  'claude-opus-4-8': [5, 25],
  'claude-opus-4-7': [5, 25],
  'claude-opus-4-6': [5, 25],
  'claude-opus-4-5': [5, 25],
  'claude-opus-4-1': [15, 75],
  'claude-opus-4': [15, 75], // retired baseline; do not use for 4.5+
  'claude-sonnet-5': [2, 10], // intro through 2026-08-31; $3/$15 thereafter
  'claude-sonnet-4-6': [3, 15],
  'claude-sonnet-4-5': [3, 15],
  'claude-sonnet-4': [3, 15],
  'claude-haiku-4-5': [1, 5],
  'claude-haiku-3-5': [0.8, 4],
  'claude-3-7-sonnet': [3, 15],
  'claude-3-5-sonnet': [3, 15],
  'claude-3-5-haiku': [0.8, 4],
  'claude-3-opus': [15, 75],
  'claude-3-haiku': [0.25, 1.25],

  // OpenAI
  'gpt-4o-mini': [0.15, 0.6],
  'gpt-4o': [2.5, 10],
  'gpt-4.1-mini': [0.4, 1.6],
  'gpt-4.1': [2, 8],
  'gpt-4-turbo': [10, 30],
  'o4-mini': [1.1, 4.4],
  'o3': [2, 8],
  'o1': [15, 60],

  // Cursor / other IDE proxies (estimates)
  'cursor-auto': [3, 15],
  'swe-1': [3, 15],
  'codeium-chat': [1, 3],

  // xAI public short-context list prices (docs.x.ai/developers/pricing, 2026-08).
  'grok-4.5': [2, 6],
  'grok-4.3': [1.25, 2.5],
  'grok-4.20': [1.25, 2.5],
  'grok-build-0.1': [1, 2],
  'grok-3': [3, 15],
  'grok-code-fast-1': [0.2, 1.5],

  // Moonshot / Kimi — platform.moonshot.ai + OpenRouter list (2026-08).
  // Wire aliases often look like kimi-code/k3 or kimi-code/kimi-for-coding.
  'kimi-code/k3': [3, 15],
  'kimi-k3': [3, 15],
  'kimi-code/kimi-for-coding': [0.73, 3.5],
  'kimi-for-coding': [0.73, 3.5],
  'kimi-k2.7-code': [0.73, 3.5],
  'kimi-k2.6': [0.59, 2.48],
  'kimi-k2.5': [0.57, 2.85],
  'kimi-k2-thinking': [0.6, 2.5],
  'kimi-k2': [0.57, 2.3],
  'kimi-k2-0905': [0.6, 2.5],
  'moonshot-v1': [1, 3], // legacy

  // Google Gemini — ai.google.dev/gemini-api/docs/pricing (2026-08).
  // Text paid tier, prompts ≤200k where a long-context band exists.
  'gemini-3.1-pro': [2, 12],
  'gemini-3-pro': [2, 12],
  'gemini-3.6-flash': [1.5, 7.5],
  'gemini-3.5-flash-lite': [0.3, 2.5],
  'gemini-3.5-flash': [1.5, 9],
  'gemini-3.1-flash-lite': [0.25, 1.5],
  'gemini-3-flash': [0.5, 3],
  'gemini-2.5-pro': [1.25, 10],
  'gemini-2.5-flash-lite': [0.1, 0.4],
  'gemini-2.5-flash': [0.3, 2.5],
  'gemini-1.5-pro': [1.25, 5],
  'gemini-1.5-flash': [0.075, 0.3],
};
export const DEFAULT = [5, 20];

/** Escape a model key for safe inclusion in a SQL string literal. */
function sqlQuote(model) {
  return `'${String(model).replace(/'/g, "''")}'`;
}

/**
 * Boundary-aware model match candidates for one price-table key.
 * Matches exact id, versioned suffix (key-…), path forms (vendor/key),
 * without letting `gpt-4` swallow `gpt-4o`.
 */
function modelMatchesKey(model, key) {
  if (!model || !key) return false;
  const name = String(model).trim().toLowerCase();
  const k = String(key).trim().toLowerCase();
  if (!name || !k) return false;
  if (name === k) return true;
  if (name.startsWith(`${k}-`) || name.startsWith(`${k}/`)) return true;
  if (name.endsWith(`/${k}`) || name.includes(`/${k}-`) || name.includes(`/${k}/`)) return true;
  // Bare basename after vendor path: kimi-code/k3 vs key k3 only when key
  // itself has no slash (avoid over-matching short keys against unrelated paths).
  if (!k.includes('/')) {
    const base = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name;
    if (base === k || base.startsWith(`${k}-`)) return true;
  }
  return false;
}

/**
 * Resolve [input, output] USD/1M for a model id. Longest matching table key
 * wins so claude-opus-4-8 ($5/$25) beats claude-opus-4 ($15/$75).
 */
export function resolvePrice(model) {
  if (model == null || model === '') return DEFAULT;
  const name = String(model).trim();
  if (!name) return DEFAULT;
  // Exact hit first (O(1) common path).
  if (Object.prototype.hasOwnProperty.call(PRICE_PER_MTOK, name)) {
    return PRICE_PER_MTOK[name];
  }
  const lower = name.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(PRICE_PER_MTOK, lower)) {
    return PRICE_PER_MTOK[lower];
  }
  let bestKey = null;
  for (const key of Object.keys(PRICE_PER_MTOK)) {
    if (!modelMatchesKey(lower, key)) continue;
    if (bestKey == null || key.length > bestKey.length) bestKey = key;
  }
  return bestKey ? PRICE_PER_MTOK[bestKey] : DEFAULT;
}

export function costFor(model, tokensInput, tokensOutput) {
  const [pin, pout] = resolvePrice(model);
  return (tokensInput * pin + tokensOutput * pout) / 1_000_000;
}

// SQL expression computing USD cost per events row, mirroring costFor() above.
// Used in aggregate queries so Postgres does the math. Generated from
// PRICE_PER_MTOK, so it cannot drift from the table.
// Canonical events (AIM-18/AIM-34) may carry a collector-computed cost_estimate_usd;
// when present it wins, otherwise we estimate from tokens + list prices above.
//
// WHEN clauses are longest-key-first so more specific SKUs win. Each key matches
// exact id, `key-%` version suffix, and `%/key` vendor-path forms.
const sortedKeys = Object.keys(PRICE_PER_MTOK).sort((a, b) => b.length - a.length);

function sqlWhenForKey(modelKey, price) {
  const k = sqlQuote(modelKey);
  const lit = String(modelKey).replace(/'/g, "''");
  // Path-safe patterns. Short keys without '/' also match basename after '/'.
  const patterns = [
    `model = ${k}`,
    `model LIKE '${lit}-%'`,
    `model LIKE '${lit}/%'`,
  ];
  if (!lit.includes('/')) {
    patterns.push(`model LIKE '%/${lit}'`);
    patterns.push(`model LIKE '%/${lit}-%'`);
  }
  return `WHEN ${patterns.join(' OR ')} THEN ${price}`;
}

const pinCases = sortedKeys.map((m) => sqlWhenForKey(m, PRICE_PER_MTOK[m][0])).join(' ');
const poutCases = sortedKeys.map((m) => sqlWhenForKey(m, PRICE_PER_MTOK[m][1])).join(' ');
export const COST_SQL = `COALESCE(cost_estimate_usd, (
  COALESCE(tokens_in, 0)  * (CASE ${pinCases} ELSE ${DEFAULT[0]} END) +
  COALESCE(tokens_out, 0) * (CASE ${poutCases} ELSE ${DEFAULT[1]} END)
) / 1000000.0)`;

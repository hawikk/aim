# matcher-ruleset — canonical endpoint secret/PII ruleset (AIM-91)

`matchers.py` here is the **single source of truth** for the local secret/PII
detectors that run inside every endpoint collector (claude-code, cursor,
kilo-code, kimi-code). The collectors ship as standalone endpoint packages,
so each carries a verbatim vendored copy.

## Workflow

1. Edit `matchers.py` in this directory — never the collector copies.
2. Run `python3 scripts/sync_matcher_ruleset.py` to update the copies.
3. Update `collectors/matcher-fixtures/evasion.json` expectations and
   regenerate `docs/security/detector-evasion-capability.md` with
   `python3 scripts/matcher_evasion_report.py`.
4. CI enforces sync (`sync_matcher_ruleset.py --check`) and fixture/doc
   consistency (`matcher_evasion_report.py --check`, plus the per-collector
   `tests/test_matcher_evasion.py` suites).

## What the ruleset does

- Four detection passes per scan: raw text, Unicode-normalized text
  (NFKC + confusable/quote folding + `[at]`/`[dot]` folding), a
  whitespace-deleted pass restricted to token-style detectors, and a
  bounded base64 decode-and-rescan.
- Three detector categories (name prefix): `secret:*` (credential material),
  `pii:*` (personal data), and `injection:*` (AIM-96 — prompt-injection /
  jailbreak phrasings in EN/DE/FR/ES: instruction override, persona and
  system-prompt override, prompt extraction, jailbreak personas,
  chat-template delimiter injection).
- Validated detectors keep precision high: Luhn for credit cards, MOD-97
  for IBAN, structural checks for US SSN, ES DNI/NIE check letter, FR NIR
  mod-97 key, DE Steuer-ID ISO 7064 Mod 11,10, JWT header-decode
  validation, and repeated-char placeholder suppression for API tokens.
- Output is detector names only — matched content never leaves the endpoint.

Detector changes are security-relevant behavior changes: they need
CEO/Security sign-off (see the AIM-91 thread for the ratified proposal).

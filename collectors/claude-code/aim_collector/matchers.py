"""Local secret/PII/injection pattern matchers — unified ruleset for ALL collectors.

CANONICAL SOURCE. The copies under each collector package
(`collectors/*/*_collector/matchers.py`) are generated from this file by
`scripts/sync_matcher_ruleset.py`. Edit HERE, re-run the sync script, and
keep `collectors/matcher-fixtures/evasion.json` +
`docs/security/detector-evasion-capability.md` in sync.

These run ON THE ENDPOINT against content that never leaves the machine
(hook prompt text, tool inputs, local task/wire logs). Output is a set of
flag strings only — matched content is discarded immediately.
`scan_text_matches`/`scan_obj_matches` additionally expose the
occurrences IN-PROCESS so the event builder can compute redacted secret
fingerprints; `Match.matched` is fingerprinted and discarded on the spot,
never logged, spooled, or emitted. The one exception is `redact_text`:
same detectors, but it rewrites the matched spans in place to
`[REDACTED:<detector>]` markers for the endpoint inline-redaction guardrail
— still nothing but flag names leaves the machine.

Keep patterns high-precision: false positives cost trust, false negatives
are documented in docs/security/detector-evasion-capability.md (generated
from the evasion fixtures, enforced in CI).

Detection passes (union of flags), per scan:
  1. raw text
  2. normalized text — NFKC, Unicode-confusable folding (dashes, quotes,
     Cyrillic lookalikes), quote/backtick equivalence, [at]/[dot] and
     (at)/(dot) folding, ASCII \\uXXXX escape fold, invisible-char strip
  3. whitespace-deleted text — closes split/insertion evasion; restricted
     to prefix-anchored/token detectors (`squash=True`) so prose cannot
     be welded into fake context-dependent matches
  4. base64 decode-and-rescan — bounded blob extraction (incl. MIME-style
     line-joined blobs), decoded payloads re-scanned with pass 1 and at
     most one extra base64 depth (depth-2 max)
  5. targeted hex decode-and-rescan — even-length hex runs that UTF-8-decode
     cleanly are re-scanned plain (catches hex-wrapped AKIA-class tokens
     without generic binary-hash FPs)

Validated detectors (credit card/Luhn, IBAN/MOD-97, SSN structure, ES DNI/NIE
check letter, FR NIR key, DE Steuer-ID check digit, JWT header decode, token
placeholder suppression) pair a candidate regex with a validator function
to keep precision high.

Detector categories (name prefix):
  secret:    credential material — severity high downstream
  pii:       personal data — severity medium downstream
  injection: prompt-injection / jailbreak phrasings — severity
             medium downstream. These are PROSE patterns: inherently more
             FP-prone than token detectors because engineers legitimately
             discuss injection attacks with their coding assistants. They
             are tuned tight (imperative constructions, qualified nouns),
             cover EN/DE/FR/ES, and their FP rate is pinned by fixtures.
"""

import base64
import binascii
import re
import unicodedata
from typing import Callable, NamedTuple

# ---------------------------------------------------------------------------
# Normalization (pass 2/3)
# ---------------------------------------------------------------------------

# Unicode lookalikes that NFKC does not fold (Cyrillic confusables, dash and
# quote variants). All quote-like characters fold to '"' so quote/backtick
# equivalence falls out of the same pass.
_CONFUSABLES = {
    "‑": "-",  # U+2011 non-breaking hyphen
    "‐": "-",  # U+2010 hyphen
    "‒": "-",  # U+2012 figure dash
    "–": "-",  # U+2013 en dash
    "—": "-",  # U+2014 em dash
    "―": "-",  # U+2015 horizontal bar
    "−": "-",  # U+2212 minus sign
    "'": '"',  # single quote equivalence
    "`": '"',  # backtick equivalence
    "´": '"',  # U+00B4 acute accent
    "‘": '"',  # U+2018
    "’": '"',  # U+2019
    "“": '"',  # U+201C
    "”": '"',  # U+201D
    "′": '"',  # U+2032 prime
    "″": '"',  # U+2033 double prime
    # Cyrillic lookalikes (lowercase)
    "а": "a",  # U+0430
    "е": "e",  # U+0435
    "о": "o",  # U+043E
    "р": "p",  # U+0440
    "с": "c",  # U+0441
    "х": "x",  # U+0445
    "у": "y",  # U+0443
    "і": "i",  # U+0456
    "ј": "j",  # U+0458
    "ѕ": "s",  # U+0455
    # Cyrillic lookalikes (uppercase) — / R-2026-08-09
    # Lowercase-only folding left capital U+0410 (А) etc. as residual misses.
    "А": "A",  # U+0410
    "Е": "E",  # U+0415
    "О": "O",  # U+041E
    "Р": "P",  # U+0420
    "С": "C",  # U+0421
    "Х": "X",  # U+0425
    "У": "Y",  # U+0423
    "І": "I",  # U+0406
    "Ј": "J",  # U+0408
    "Ѕ": "S",  # U+0405
    "В": "B",  # U+0412
    "К": "K",  # U+041A
    "М": "M",  # U+041C
    "Т": "T",  # U+0422
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# Bracketed [at]/[dot] and parenthesized (at)/(dot).
# Bare " at " / " dot " remain intentionally unfolded — too FP-prone in prose.
_AT_DOT_FOLD = re.compile(r"\s*[\[(](?:at|dot)[\])]\s*", re.IGNORECASE)

# JSON/JS-style \\uXXXX escapes of printable ASCII (F-match-6 class).
# Only ASCII is folded so raw-log lines like "\\u0041KIA..." collapse to the
# real token shape; non-ASCII escapes are left alone.
_UNICODE_ESCAPE_ASCII = re.compile(r"\\u00([2-7][0-9a-fA-F])")

# Invisible / format characters adversaries insert into token bodies to split
# contiguous regex matches (F-match-4). Stripped in the normalize
# pass only — raw pass still catches clean tokens; squashed pass already drops
# true whitespace. These characters never appear in real credential material.
_INVISIBLE_CHARS = re.compile(
    # base set + purple-team expansion (invisible math format chars)
    "[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]"
    # ZWSP ZWNJ ZWJ WJ FA IT IS IP BOM soft-hyphen
)


def _normalize(text: str) -> str:
    """Compatibility fold: NFKC + confusable/quote + invisible + at/dot + \\uXXXX."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_CONFUSABLE_TABLE)
    text = _INVISIBLE_CHARS.sub("", text)

    def _at_dot(m: re.Match) -> str:
        inner = m.group(0).strip("[]() \t").lower()
        return "@" if inner == "at" else "."

    text = _AT_DOT_FOLD.sub(_at_dot, text)

    def _u_esc(m: re.Match) -> str:
        return chr(int(m.group(1), 16))

    return _UNICODE_ESCAPE_ASCII.sub(_u_esc, text)


def _squash(text: str) -> str:
    """Delete all whitespace — closes newline-split / space-insertion evasion."""
    return "".join(text.split())


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


class _Rule(NamedTuple):
    name: str
    pattern: re.Pattern
    # Safe to run against the whitespace-deleted variant. Only true for
    # prefix-anchored / structural token detectors; context-dependent
    # patterns would weld prose into false positives.
    squash: bool


class _ValidatedRule(NamedTuple):
    name: str
    candidate: re.Pattern
    validate: Callable[[re.Match], bool]
    squash: bool


def _is_placeholder(body: str) -> bool:
    """True for docs-style repeated-char placeholder bodies (`xxxx…`, `abab…`)."""
    return len(set(body.lower())) <= 2


def _token_ok(m: re.Match) -> bool:
    return not _is_placeholder(m.group(1))


# AWS publishes a handful of documentation credentials that are cryptographically
# dead and appear constantly in engineer→assistant paste (SDK samples, blogs,
# Stack Overflow). Live pilot FP audit: these dominate organic
# "secret" noise and are allowlisted by gitleaks/trufflehog. Exact denylist
# only — other format-valid dead keys (canaries, corpus positives) still fire.
_AWS_DOCS_ACCESS_KEYS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
})
_AWS_DOCS_SECRET_BODIES = frozenset({
    # Canonical AWS docs secret-key body (40 base64-ish chars).
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})


def _aws_access_key_ok(m: re.Match) -> bool:
    """Reject the exact AWS documentation access-key id."""
    return m.group(0).upper() not in _AWS_DOCS_ACCESS_KEYS


def _aws_secret_key_ok(m: re.Match) -> bool:
    """Reject the exact AWS documentation secret-key body."""
    body_m = re.search(r"[0-9a-zA-Z/+]{40}", m.group(0))
    if not body_m:
        return True
    return body_m.group(0) not in _AWS_DOCS_SECRET_BODIES


_RULES: list[_Rule] = [
    _Rule("secret:gcp-service-account", re.compile(r'"private_key"\s*:\s*"-----BEGIN'), False),
    _Rule("secret:private-key-block", re.compile(
        r"-{2,}\s*BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY\s*-{2,}",
        re.IGNORECASE), True),
    # ap[i1]_k[e3]y covers common leetspeak label evasion.
    _Rule("secret:generic-api-key-assignment", re.compile(
        r"\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|ap[i1][_-]?k[e3]y)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?",
        re.IGNORECASE), True),
    _Rule("pii:email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), True),
    # --- prompt-injection / jailbreak phrasings -------------------
    # Prose patterns: squash=False everywhere in this group (whitespace
    # deletion would weld prose into false matches). All case-insensitive;
    # Unicode-confusable evasion is handled by the normalization pass.
    # Imperative override of prior instructions — EN/DE/FR/ES.
    _Rule("injection:ignore-instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+)*"
        r"(?:previous|prior|above|earlier|preceding|initial|original|existing)\s+"
        r"(?:instructions?|directives?|guidelines?|rules?|prompts?|constraints|programming)\b"
        r"|\bignorier(?:e|en|t|st)?\s+(?:alle\s+|jede\s+|deine\s+|die\s+|sämtliche\s+)*"
        r"(?:vorherigen?|bisherigen?|obigen?|vorangegangenen|ursprünglichen)\s+"
        r"(?:Anweisungen|Instruktionen|Regeln|Richtlinien|Vorgaben)\b"
        r"|\bignor(?:e|ez|er)\s+(?:toutes?\s+|les\s+|tes\s+|vos\s+)*"
        r"(?:instructions?|directives?|consignes|règles)\s+"
        r"(?:précédentes?|antérieures?|ci-dessus|initiales?|d'origine)\b"
        r"|\bignor(?:a|e|ar|en)\s+(?:todas?\s+|las\s+|tus\s+|sus\s+)*"
        r"(?:instrucciones|directrices|reglas|consignas)\s+"
        r"(?:anteriores|previas|iniciales|originales|de\s+arriba)\b",
        re.IGNORECASE), False),
    # Persona / context override ("you are now …", "from now on you …").
    # Bare "act as" is deliberately excluded — legitimate role-prompting is
    # constant in coding assistants and would drown analysts.
    _Rule("injection:system-prompt-override", re.compile(
        r"\byou\s+are\s+now\b"
        r"|\bfrom\s+now\s+on[,\s]+you\b"
        r"|\byour\s+new\s+(?:instructions?|directives?|rules?|system\s+prompt|identity|persona)\b"
        r"|\bnew\s+system\s+(?:prompt|instructions?)\b"
        r"|\bdu\s+bist\s+jetzt\b"
        r"|\b(?:ab\s+jetzt|von\s+jetzt\s+an)\s+(?:bist\s+du|gilt|gelten)\b"
        r"|\btu\s+es\s+maintenant\b"
        r"|\b(?:désormais|à\s+partir\s+de\s+maintenant)[,\s]+tu\b"
        r"|\bahora\s+eres\b"
        r"|\ba\s+partir\s+de\s+ahora[,\s]+(?:eres|serás)\b",
        re.IGNORECASE), False),
    # System-prompt extraction probes. Nouns must be qualified (system /
    # initial / original / hidden) — bare "show your instructions" is too
    # common in legitimate task prompts.
    _Rule("injection:prompt-extraction", re.compile(
        r"\b(?:reveal|show|print|display|repeat|leak|output|share|give|tell)\b[^\n.?!]{0,25}"
        r"\byour\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|"
        r"hidden\s+instructions?|full\s+prompt|secret\s+prompt|system\s+instructions?|"
        r"guidelines|directives)\b"
        r"|\brepeat\s+(?:the\s+)?(?:words?|text|everything|content)\s+above\b"
        r"|\bwhat\s+(?:are|were)\s+your\s+(?:original|initial|system|hidden)\s+instructions\b"
        r"|\b(?:zeig|nenn|gib|wiederhol)(?:e|en)?\b[^\n.?!]{0,25}"
        r"\bdeinen?\s+(?:Systemprompt|System-Prompt|ursprünglichen\s+Anweisungen|"
        r"versteckten\s+Anweisungen|Systemanweisungen)\b"
        r"|\bwas\s+(?:sind|waren)\s+deine\s+(?:ursprünglichen\s+|versteckten\s+)?Anweisungen\b"
        r"|\b(?:montre|affiche|révèle|donne|répète)(?:-moi)?\b[^\n.?!]{0,25}"
        r"\b(?:ton|ta|tes)\s+(?:prompt\s+système|instructions?\s+(?:initiales?|originales?|"
        r"cachées?|système))\b"
        r"|\b(?:muestra|revela|repite|enseña|dime)(?:me)?\b[^\n.?!]{0,25}"
        r"\btu[s]?\s+(?:prompt\s+(?:del\s+)?sistema|instrucciones\s+(?:iniciales|originales|"
        r"ocultas|del\s+sistema))\b",
        re.IGNORECASE), False),
    # Jailbreak personas / safety-bypass phrasings. Bare "jailbreak" and bare
    # "developer mode" are excluded (defensive-security discussion, Android
    # docs); "DAN" the acronym is excluded (collides with the name Dan).
    _Rule("injection:jailbreak-persona", re.compile(
        r"\bdo\s+anything\s+now\b"
        r"|\b(?:dan|jailbreak|evil|god|unrestricted|uncensored)\s+mode\b"
        r"|\bdeveloper\s+mode\s+(?:enabled|activated)\b"
        r"|\b(?:no|without|ignore)\s+(?:any\s+)?(?:ethical|moral|safety|content)\s+"
        r"(?:guidelines?|restrictions?|filters?|limits?|boundaries)\b"
        r"|\bpretend\s+(?:to\s+be|you\s+are|you\s+have)\s+(?:an?\s+)?"
        r"(?:unrestricted|uncensored|unfiltered)\b"
        r"|\bbypass\s+(?:your\s+|the\s+)?(?:safety|content|ethical)\s+"
        r"(?:filters?|guidelines?|restrictions?|controls?)\b",
        re.IGNORECASE), False),
    # Chat-template delimiter injection — structural tokens, high precision.
    _Rule("injection:delimiter-override", re.compile(
        r"<<\s*SYS\s*>>"
        r"|\[\s*/?\s*INST\s*\]"
        r"|<\|im_(?:start|end)\|>"
        r"|<\|(?:system|user|assistant)\|>"
        r"|###\s*(?:System|Instruction|Human|Assistant)\s*:"), True),
]

# Token detectors with placeholder suppression (group 1 = token body).
_TOKEN_RULES: list[_ValidatedRule] = [
    # Real keys are uppercase; a fully-lowercased AKIA copy is a known lossy
    # evasion we still catch. "asia" is deliberately not case-folded — it is
    # an English word and would FP in the whitespace-deleted pass.
    # exact AWS docs access-key id is denylisted (organic paste noise).
    _ValidatedRule(
        "secret:aws-access-key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bakia[0-9a-z]{16}\b"),
        _aws_access_key_ok,
        True,
    ),
    # Requires an assignment-ish separator ([:=]) so the whitespace-deleted
    # pass cannot weld prose mentioning "aws" into a 40-char run. No trailing
    # \b after "aws": it must match inside names like aws_secret.
    # exact AWS docs secret-key body is denylisted.
    _ValidatedRule(
        "secret:aws-secret-key",
        re.compile(
            r"\baws.{0,20}?(?:[:=]|%3[Dd])\s*['\"]?[0-9a-zA-Z/+]{40}['\"]?",
            re.IGNORECASE,
        ),
        _aws_secret_key_ok,
        True,
    ),
    # GitHub tokens have a fixed shape: a typed prefix + a base62 body of known
    # length. Classic tokens (ghp/gho/ghu/ghs/ghr) carry exactly 36 base62 chars
    # (no underscores); fine-grained github_pat_ tokens carry an 82-char body
    # that may contain underscores. Pinning the exact length + charset rejects
    # documentation placeholders such as `ghp_your_github_token` and
    # `ghp_your_new_github_token` (the sole secret firing in the
    # dogfood backtest was one such placeholder) while still matching real
    # leaked tokens; placeholder suppression stays as a same-char backstop.
    _ValidatedRule("secret:github-token", re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_([A-Za-z0-9]{36})\b", re.IGNORECASE), _token_ok, True),
    _ValidatedRule("secret:github-token", re.compile(
        r"\bgithub_pat_([A-Za-z0-9_]{82})\b", re.IGNORECASE), _token_ok, True),
    _ValidatedRule("secret:gitlab-token", re.compile(
        r"\bglpat-([A-Za-z0-9_\-]{20,})\b", re.IGNORECASE), _token_ok, True),
    _ValidatedRule("secret:slack-token", re.compile(
        r"\bxox[baprs]-?([A-Za-z0-9\-]{10,})\b", re.IGNORECASE), _token_ok, True),
    _ValidatedRule("secret:openai-key", re.compile(
        r"\bsk-([A-Za-z0-9_\-]{20,})\b", re.IGNORECASE), _token_ok, True),
    _ValidatedRule("secret:anthropic-key", re.compile(
        r"\bsk-ant-([A-Za-z0-9_\-]{20,})\b", re.IGNORECASE), _token_ok, True),
    # --- additional token types, all placeholder-suppressed --------
    _ValidatedRule("secret:google-api-key", re.compile(
        r"\bAIza([0-9A-Za-z_\-]{35})\b"), _token_ok, True),
    # Live + restricted keys only: pk_ is publishable by design, sk_test is
    # not a live credential.
    _ValidatedRule("secret:stripe-key", re.compile(
        r"\b(?:sk|rk)_live_([0-9a-zA-Z]{16,})\b"), _token_ok, True),
    _ValidatedRule("secret:npm-token", re.compile(
        r"\bnpm_([A-Za-z0-9]{36})\b"), _token_ok, True),
    # PyPI upload tokens are macaroons; the prefix is constant.
    _ValidatedRule("secret:pypi-token", re.compile(
        r"\bpypi-AgEIcHlwaS5vcmc([A-Za-z0-9_\-]{40,})\b"), _token_ok, True),
]


def _sg_ok(m: re.Match) -> bool:
    """SendGrid key: both segments must be non-placeholder."""
    return not _is_placeholder(m.group(1)) and not _is_placeholder(m.group(2))


_SENDGRID_RULE = _ValidatedRule("secret:sendgrid-key", re.compile(
    r"\bSG\.([A-Za-z0-9_\-]{22})\.([A-Za-z0-9_\-]{43})\b"), _sg_ok, True)

_SLACK_WEBHOOK_RULE = _ValidatedRule("secret:slack-webhook", re.compile(
    r"https?://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/([A-Za-z0-9]{20,})",
    re.IGNORECASE), _token_ok, False)


# --- JWT: candidate + header-decode validation --------------------

_JWT_CANDIDATE = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]{8,})\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b")


def _jwt_ok(m: re.Match) -> bool:
    """Header segment must base64url-decode to a JSON object naming an alg —
    rejects random eyJ-prefixed tokens and placeholder JWTs."""
    seg = m.group(1)
    if _is_placeholder(seg):
        return False
    try:
        padded = seg + "=" * (-len(seg) % 4)
        header = base64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return '"alg"' in header and header.lstrip().startswith("{")


# --- credit cards: candidate + Luhn checksum --------------------------------

_CC_CANDIDATE = re.compile(r"\b(?:\d[ .-]?){13,16}\b")


def _luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cc_ok(m: re.Match) -> bool:
    return _luhn_ok(re.sub(r"[ .-]", "", m.group(0)))


# --- US SSN: candidate + structural validity --------------------------------

# Dot separators allowed; 3-2-4 + structural checks keep FP guards green.
_SSN_CANDIDATE = re.compile(r"\b(\d{3})[ .\-]?(\d{2})[ .\-]?(\d{4})\b")


def _ssn_ok(m: re.Match) -> bool:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


# --- IBAN: candidate + MOD-97 checksum (ISO 13616) --------------------------

_IBAN_CANDIDATE = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b", re.IGNORECASE)


def _iban_ok(m: re.Match) -> bool:
    iban = m.group(1).upper()
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(digits) % 97 == 1


# --- ES DNI/NIE: candidate + check letter --------------------------

_ES_DNI_CANDIDATE = re.compile(r"\b(\d{8}|[XYZ]\d{7})[ -]?([A-Z])\b", re.IGNORECASE)
_ES_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def _es_dni_ok(m: re.Match) -> bool:
    body, letter = m.group(1).upper(), m.group(2).upper()
    # NIE: leading X/Y/Z stands for 0/1/2.
    body = {"X": "0", "Y": "1", "Z": "2"}.get(body[0], body[0]) + body[1:]
    if not body.isdigit():
        return False
    return _ES_DNI_LETTERS[int(body) % 23] == letter


# --- FR NIR (INSEE): candidate + mod-97 key ------------------------

_FR_NIR_CANDIDATE = re.compile(
    r"\b([1278])\s?(\d{2})\s?(\d{2})\s?(\d{2}|2[AB])\s?(\d{3})\s?(\d{3})\s?(\d{2})\b",
    re.IGNORECASE)


def _fr_nir_ok(m: re.Match) -> bool:
    sex, year, month, dept, commune, order, key = (m.group(i) for i in range(1, 8))
    month_i = int(month)
    # 01-12 normal; 20-42 and 91-99 are special registers — reject others.
    if not (1 <= month_i <= 12 or 20 <= month_i <= 42 or 91 <= month_i <= 99):
        return False
    # Corsica 2A/2B counts as 19/18 for the key computation.
    dept = dept.upper().replace("2A", "19").replace("2B", "18")
    n = int(sex + year + month + dept + commune + order)
    return 97 - (n % 97) == int(key)


# --- DE Steuer-ID (IdNr): candidate + ISO 7064 Mod 11,10 -----------

_DE_STEUERID_CANDIDATE = re.compile(r"\b(\d{11})\b")


def _de_steuerid_ok(m: re.Match) -> bool:
    digits = m.group(1)
    if digits[0] == "0":  # IdNr never starts with 0
        return False
    product = 10
    for ch in digits[:10]:
        s = (int(ch) + product) % 10
        if s == 0:
            s = 10
        product = (2 * s) % 11
    check = 11 - product
    if check == 10:
        check = 0
    return check == int(digits[10])


# --- IT codice fiscale: structural candidate + month/day checks ----
# The check-character table (odd/even position values) is not reproduced —
# structure + month-letter + day-range keeps precision acceptable; documented
# as structure-only in the capability statement.

_IT_CF_CANDIDATE = re.compile(
    r"\b[A-Z]{6}\d{2}([A-Z])(\d{2})[A-Z]\d{3}[A-Z]\b", re.IGNORECASE)
_IT_CF_MONTHS = set("ABCDEHLMPRST")


def _it_cf_ok(m: re.Match) -> bool:
    if m.group(1).upper() not in _IT_CF_MONTHS:
        return False
    day = int(m.group(2))
    return 1 <= day <= 31 or 41 <= day <= 71  # 41-71 = female day encoding


_VALIDATED_RULES: list[_ValidatedRule] = _TOKEN_RULES + [
    _SENDGRID_RULE,
    _SLACK_WEBHOOK_RULE,
    _ValidatedRule("secret:jwt", _JWT_CANDIDATE, _jwt_ok, True),
    _ValidatedRule("pii:credit-card", _CC_CANDIDATE, _cc_ok, True),
    _ValidatedRule("pii:us-ssn", _SSN_CANDIDATE, _ssn_ok, True),
    _ValidatedRule("pii:iban", _IBAN_CANDIDATE, _iban_ok, True),
    _ValidatedRule("pii:es-dni-nie", _ES_DNI_CANDIDATE, _es_dni_ok, True),
    _ValidatedRule("pii:fr-nir", _FR_NIR_CANDIDATE, _fr_nir_ok, True),
    _ValidatedRule("pii:de-steuerid", _DE_STEUERID_CANDIDATE, _de_steuerid_ok, True),
    _ValidatedRule("pii:it-codice-fiscale", _IT_CF_CANDIDATE, _it_cf_ok, True),
]

# --- base64 decode-and-rescan -----------------------------------------------

_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_B64_LINE = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")
_B64_MAX_BLOBS = 64
# Depth-1 was the original bound (CPU/DoS). permits one nested decode
# so base64-of-base64 secret wrappers are caught; depth >2 still evades by design.
_B64_MAX_DEPTH = 2

# --- targeted hex decode-and-rescan (F-match-1 class) -------------
# Even-length hex runs of ≥24 chars (12+ decoded bytes). Only UTF-8-clean
# decodes are re-scanned — commit hashes / random digests almost always fail
# strict UTF-8 or fail to match any token pattern, so this stays precision-safe.
_HEX_CANDIDATE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24,}(?![0-9a-fA-F])")
_HEX_MAX_BLOBS = 32

# Bound the amount of content we scan per payload; scanning is cheap but
# pathological tool inputs (multi-MB file writes) should not stall hooks.
_SCAN_LIMIT = 256 * 1024


def rule_names() -> list[str]:
    """All detector names this ruleset can emit, sorted and de-duplicated
    (a detector may be split across more than one candidate rule, e.g. the
    classic vs. fine-grained GitHub token shapes)."""
    return sorted({r.name for r in _RULES} | {r.name for r in _VALIDATED_RULES})


class Match(NamedTuple):
    """One detector occurrence, IN-PROCESS ONLY.

    `matched` is the raw matched text. The collector's event builder turns it
    into a redacted fingerprint (keyed, truncated HMAC) and discards it; it
    must never be logged, spooled, or emitted — same rule as the scanned
    payload itself."""
    detector: str
    matched: str
    offset: int    # char offset of the match within the scanned surface
    surface: str   # scan pass: raw | normalized | squashed | base64 | hex


def _scan_plain_matches(text: str, squash: bool, surface: str) -> list[Match]:
    out: list[Match] = []
    for r in _RULES:
        if squash and not r.squash:
            continue
        out.extend(Match(r.name, m.group(0), m.start(), surface)
                   for m in r.pattern.finditer(text))
    for r in _VALIDATED_RULES:
        if squash and not r.squash:
            continue
        out.extend(Match(r.name, m.group(0), m.start(), surface)
                   for m in r.candidate.finditer(text) if r.validate(m))
    return out


def _mime_join_b64(text: str) -> str:
    """Join consecutive pure-base64 lines (MIME-style short wraps) into blobs.

    / F-match-3: blob extraction requires a contiguous ≥24-char run;
    MIME wraps of 16-char lines otherwise decode as garbage per fragment.
    Non-base64 lines break the join so prose is never welded across paragraphs.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    buf: list[str] = []

    def flush() -> None:
        if buf:
            out.append("".join(buf))
            buf.clear()

    for line in lines:
        body = line.strip()
        if body and _B64_LINE.match(body) and " " not in body and "\t" not in body:
            buf.append(body)
        else:
            flush()
            out.append(line)
    flush()
    return "".join(out)


def _scan_base64_matches(text: str, depth: int = 1) -> list[Match]:
    out: list[Match] = []
    # Contiguous blobs on the raw surface, plus MIME-joined short-line surface.
    surfaces = [text]
    joined = _mime_join_b64(text)
    if joined != text:
        surfaces.append(joined)
    seen_blobs: set[str] = set()
    for surface in surfaces:
        for m in list(_B64_CANDIDATE.finditer(surface))[:_B64_MAX_BLOBS]:
            blob = m.group(0)
            if blob in seen_blobs or len(blob) % 4:
                continue
            seen_blobs.add(blob)
            try:
                decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="strict")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if len(decoded) < 12:
                continue
            out.extend(_scan_plain_matches(decoded, squash=False, surface="base64"))
            if depth < _B64_MAX_DEPTH:
                out.extend(_scan_base64_matches(decoded, depth=depth + 1))
    return out


def _scan_hex_matches(text: str) -> list[Match]:
    """Decode even-length hex runs and re-scan plain."""
    out: list[Match] = []
    for m in list(_HEX_CANDIDATE.finditer(text))[:_HEX_MAX_BLOBS]:
        blob = m.group(0)
        if len(blob) % 2:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(decoded) < 12:
            continue
        # Reject decodes that are mostly control/non-printable — digests that
        # happen to be valid UTF-8 still rarely look like credentials, but this
        # keeps the pass tight.
        if sum(1 for ch in decoded if ch.isprintable()) < len(decoded) * 0.9:
            continue
        out.extend(_scan_plain_matches(decoded, squash=False, surface="hex"))
    return out


def scan_text_matches(text: "str | None") -> list[Match]:
    """Return every detector occurrence in text, across all scan passes.

    Same passes as scan_text; use scan_text when only detector names are
    needed (e.g. the endpoint enforcement decision path). Never raises."""
    if not text:
        return []
    text = text[:_SCAN_LIMIT]
    normalized = _normalize(text)
    matches = _scan_plain_matches(text, squash=False, surface="raw")
    if normalized != text:
        matches += _scan_plain_matches(normalized, squash=False, surface="normalized")
    squashed = _squash(normalized)
    if squashed != normalized:
        matches += _scan_plain_matches(squashed, squash=True, surface="squashed")
    matches += _scan_base64_matches(text)
    if normalized != text:
        matches += _scan_base64_matches(normalized)
    matches += _scan_hex_matches(text)
    if normalized != text:
        matches += _scan_hex_matches(normalized)
    return matches

def scan_text(text: "str | None") -> list[str]:
    """Return sorted flag names for patterns present in text. Never raises."""
    return sorted({m.detector for m in scan_text_matches(text)})


def scan_obj_matches(obj) -> list[Match]:
    """Serialize an arbitrary hook payload field and scan it for occurrences."""
    if obj is None:
        return []
    try:
        import json
        return scan_text_matches(json.dumps(obj, default=str))
    except Exception:
        return []


def scan_obj(obj) -> list[str]:
    """Serialize an arbitrary hook payload field and scan it (names only)."""
    return sorted({m.detector for m in scan_obj_matches(obj)})


# ---------------------------------------------------------------------------
# Inline redaction
# ---------------------------------------------------------------------------
#
# scan_text is multi-pass (raw / normalized / squashed / base64-rescan), but
# only the RAW pass produces spans that exist verbatim in the input — a match
# found only after NFKC folding, whitespace deletion, or base64 decoding has
# no offset in the original text and therefore cannot be redacted. redact_text
# deliberately covers raw-pass matches only; callers must re-scan the redacted
# output and treat any residual flag as "not redactable" (the enforce layer
# falls back to blocking — see enforce.decide_redact_tool_input).
#
# The replacement marker carries the detector name and nothing else: no
# matched substring, no hash of it, no offset table. Redaction is
# reversible-by-no-one because there is nothing left to reverse.


class Redaction(NamedTuple):
    text: str              # redacted text (identical to input when nothing fired)
    detectors: list[str]   # sorted detector names whose spans were replaced


#: Detector-name prefixes redact_text covers by default: the high-precision
#: secret rules that passed the enforce gate. PII/injection detectors
#: are deliberately NOT defaulted in — structured PII can be opted in by the
#: caller; prose (injection) patterns are NEVER redactable (rewriting a
#: sentence is not redaction, it is silent content mutation) and are excluded
#: even when a caller passes an injection: prefix.
REDACT_PREFIXES_DEFAULT = ("secret:",)

#: Inputs longer than the scan limit are not redacted at all (returned
#: unchanged with no detectors) — silently redacting only a prefix of the
#: content would leak the tail. The enforce layer treats "no detectors" on
#: oversize input via its normal residual/fallback path.
def redact_text(text: "str | None",
                prefixes: "tuple[str, ...]" = REDACT_PREFIXES_DEFAULT) -> Redaction:
    """Replace raw-pass matches of the eligible detectors with
    ``[REDACTED:<detector>]`` markers. Never raises.

    Returns the (possibly unchanged) text plus the sorted detector names that
    fired. Overlapping spans from different detectors are merged into one
    marker listing all of them (``+``-joined)."""
    if not text or len(text) > _SCAN_LIMIT:
        return Redaction(text or "", [])
    eligible = tuple(p for p in prefixes if not p.startswith("injection:"))
    if not eligible:
        return Redaction(text, [])
    spans: list[tuple[int, int, str]] = []
    for r in _RULES:
        if r.name.startswith(eligible):
            spans += [(m.start(), m.end(), r.name) for m in r.pattern.finditer(text)]
    for r in _VALIDATED_RULES:
        if r.name.startswith(eligible):
            spans += [(m.start(), m.end(), r.name) for m in r.candidate.finditer(text)
                      if r.validate(m)]
    if not spans:
        return Redaction(text, [])
    # Merge overlapping spans, unioning their detector names.
    spans.sort()
    merged: list[list] = []
    for start, end, name in spans:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            merged[-1][2].add(name)
        else:
            merged.append([start, end, {name}])
    out = []
    pos = 0
    detectors: set[str] = set()
    for start, end, names in merged:
        out.append(text[pos:start])
        dets = sorted(names)
        detectors.update(dets)
        out.append("[REDACTED:" + "+".join(dets) + "]")
        pos = end
    out.append(text[pos:])
    return Redaction("".join(out), sorted(detectors))

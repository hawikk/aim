#!/usr/bin/env bash
# — one-shot device enroll (install CLI + aim join + doctor + status).
#
# Served by the dashboard as a public static asset:
#   curl -fsSL http://<aim-host>:8081/enroll.sh | bash -s -- \
#     --url http://<aim-host>:8080 --token <enrollment-secret>
#
# Or offline-ish (local wheel already present):
#   AIM_WHEEL=/path/to/aimonitoring_security-*.whl bash enroll.sh \
#     --url http://…:8080 --token <enrollment-secret>
#
# Security:
#   * Never prints the enrollment token (or device token).
#   * Prefer pipx install of aimonitoring-security (never the AimStack package).
#   * Python 3.11+ is required (clear failure otherwise).
#   * Exits non-zero if join/doctor fails or token_file is missing.
#
# Do not enable `set -x` — that would leak argv secrets into the shell history
# and logs. The token is still briefly visible to local `ps` while `aim join`
# runs (CLI argv); keep that window short and avoid shared terminals.
set -euo pipefail

PKG_NAME="aimonitoring-security"
MIN_PY_MAJOR=3
MIN_PY_MINOR=11

INGEST_URL="${AIM_INGEST_URL:-${AIM_INGEST_PUBLIC_URL:-}}"
TOKEN="${AIM_ENROLL_TOKEN:-}"
RING=""
CA_BUNDLE=""
RESOLVE_ENTRIES=()
SKIP_INSTALL=0
ASSUME_YES=0

usage() {
  cat <<'EOF'
usage: enroll.sh --url <ingest-url> --token <enroll-token> [options]

One-shot device enroll for AI Monitoring:
  1. Preflight Python 3.11+
  2. Install/ensure aimonitoring-security (pipx preferred; AIM_WHEEL offline)
  3. aim join <url> --token …
  4. aim doctor --fix
  5. aim status
  6. Verify token_file → device_token (fail closed if missing)

Options:
  --url, --ingest-url URL   Fleet ingest base URL (http://host:8080)
  --token, --enroll-token T Enrollment secret (also AIM_ENROLL_TOKEN)
  --ring RING               Optional rollout ring label
  --ca-bundle, --ca-cert P  PEM trust bundle for private ingest CA
  --resolve HOST:PORT:IP Split-horizon dial (repeatable)
  --skip-install            Assume `aim` is already on PATH
  -y, --yes                 Non-interactive (reserved; default is non-interactive)
  -h, --help                Show this help

Env:
  AIM_WHEEL                 Path to a local wheel (offline / air-gap install)
  AIM_INGEST_URL            Default for --url
  AIM_ENROLL_TOKEN          Default for --token (prefer flag; never log this)
  AIM_PIP_FALLBACK=1        Allow `python3 -m pip install --user` if pipx missing

Exit codes:
  0  enrolled, doctor green, token_file present
  1  runtime failure (install/join/doctor/token_file)
  2  bad usage / preflight (Python too old, missing args)
EOF
}

log()  { printf '→ %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
usage_die() { printf 'error: %s\n' "$*" >&2; usage >&2; exit 2; }

# Redact accidental token echoes if a subshell dumps argv (best-effort).
redact() {
  local s="$1"
  if [[ -n "${TOKEN:-}" && "$s" == *"$TOKEN"* ]]; then
    s="${s//"$TOKEN"/[REDACTED]}"
  fi
  printf '%s' "$s"
}

have() { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --url|--ingest-url)
      [[ $# -ge 2 ]] || usage_die "$1 requires a value"
      INGEST_URL="$2"; shift 2 ;;
    --url=*|--ingest-url=*)
      INGEST_URL="${1#*=}"; shift ;;
    --token|--enroll-token)
      [[ $# -ge 2 ]] || usage_die "$1 requires a value"
      TOKEN="$2"; shift 2 ;;
    --token=*|--enroll-token=*)
      TOKEN="${1#*=}"; shift ;;
    --ring)
      [[ $# -ge 2 ]] || usage_die "$1 requires a value"
      RING="$2"; shift 2 ;;
    --ring=*) RING="${1#*=}"; shift ;;
    --ca-bundle|--ca-cert)
      [[ $# -ge 2 ]] || usage_die "$1 requires a value"
      CA_BUNDLE="$2"; shift 2 ;;
    --ca-bundle=*|--ca-cert=*)
      CA_BUNDLE="${1#*=}"; shift ;;
    --resolve)
      [[ $# -ge 2 ]] || usage_die "$1 requires a value"
      RESOLVE_ENTRIES+=("$2"); shift 2 ;;
    --resolve=*)
      RESOLVE_ENTRIES+=("${1#*=}"); shift ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    --)
      shift
      # Convenience: aim-enroll <url> <token>
      if [[ $# -ge 1 && -z "$INGEST_URL" ]]; then INGEST_URL="$1"; shift; fi
      if [[ $# -ge 1 && -z "$TOKEN" ]]; then TOKEN="$1"; shift; fi
      break ;;
    -*)
      usage_die "unknown option: $1" ;;
    *)
      # Positional form: enroll.sh <url> <token>
      if [[ -z "$INGEST_URL" ]]; then
        INGEST_URL="$1"
      elif [[ -z "$TOKEN" ]]; then
        TOKEN="$1"
      else
        usage_die "unexpected argument: $1"
      fi
      shift ;;
  esac
done

# Silence unused (reserved for future interactive prompts).
: "${ASSUME_YES}"

[[ -n "$INGEST_URL" ]] || usage_die "--url <ingest-url> is required (or AIM_INGEST_URL)"
[[ -n "$TOKEN" ]] || usage_die "--token <enroll-token> is required (or AIM_ENROLL_TOKEN)"

# ---------------------------------------------------------------------------
# Preflight: Python 3.11+
# ---------------------------------------------------------------------------
pick_python() {
  local c
  for c in python3.13 python3.12 python3.11 python3; do
    if have "$c"; then
      if "$c" -c "import sys; raise SystemExit(0 if sys.version_info >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)" 2>/dev/null; then
        printf '%s' "$c"
        return 0
      fi
    fi
  done
  return 1
}

log "preflight: Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+"
PY="$(pick_python || true)"
if [[ -z "${PY}" ]]; then
  if have python3; then
    ver="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo unknown)"
    printf 'error: Python %s.%s+ is required for aimonitoring-security; found python3 %s\n' \
      "$MIN_PY_MAJOR" "$MIN_PY_MINOR" "$ver" >&2
  else
    printf 'error: Python %s.%s+ is required but no python3 was found on PATH\n' \
      "$MIN_PY_MAJOR" "$MIN_PY_MINOR" >&2
  fi
  printf 'hint: install Python 3.11+ (python.org, brew, apt/dnf, or your org package), then re-run.\n' >&2
  exit 2
fi
log "using $($PY -c 'import sys; print("Python %d.%d.%d" % sys.version_info[:3])') ($PY)"

# ---------------------------------------------------------------------------
# Install / ensure aimonitoring-security
# ---------------------------------------------------------------------------
aim_on_path() {
  have aim && aim --version >/dev/null 2>&1
}

install_with_pipx() {
  local target="$1"
  log "install via pipx: ${target}"
  # --force refreshes an older pin so doctor/token_file fixes land.
  pipx install --force "$target"
}

install_with_pip_user() {
  local target="$1"
  warn "pipx not found; falling back to: $PY -m pip install --user $target"
  warn "prefer: python3 -m pip install --user pipx && pipx ensurepath  (then re-open shell)"
  "$PY" -m pip install --user --upgrade "$target"
  # User base scripts may not be on PATH yet.
  local user_base
  user_base="$("$PY" -m site --user-base 2>/dev/null || true)"
  if [[ -n "$user_base" && -d "$user_base/bin" ]]; then
    export PATH="$user_base/bin:$PATH"
  fi
}

ensure_cli() {
  if [[ "$SKIP_INSTALL" -eq 1 ]]; then
    aim_on_path || die "--skip-install set but 'aim' is not on PATH"
    log "skip install: $(aim --version 2>/dev/null || echo aim present)"
    return 0
  fi

  if [[ -n "${AIM_WHEEL:-}" ]]; then
    [[ -f "$AIM_WHEEL" ]] || die "AIM_WHEEL is set but not a file: $AIM_WHEEL"
    log "offline wheel: $AIM_WHEEL"
    if have pipx; then
      install_with_pipx "$AIM_WHEEL"
    elif [[ "${AIM_PIP_FALLBACK:-}" == "1" ]] || ! have pipx; then
      install_with_pip_user "$AIM_WHEEL"
    fi
  elif aim_on_path; then
    log "aim already installed: $(aim --version 2>/dev/null || true)"
  else
    log "install public package: $PKG_NAME"
    if have pipx; then
      install_with_pipx "$PKG_NAME"
    else
      if [[ "${AIM_PIP_FALLBACK:-0}" != "1" ]]; then
        warn "pipx is preferred but not installed."
        warn "Install pipx, or re-run with AIM_PIP_FALLBACK=1 to use pip --user."
        warn "  macOS:  brew install pipx && pipx ensurepath"
        warn "  Debian: python3 -m pip install --user pipx && pipx ensurepath"
      fi
      install_with_pip_user "$PKG_NAME"
    fi
  fi

  aim_on_path || die "install finished but 'aim' is still not on PATH (open a new shell or run: pipx ensurepath)"
  log "cli: $(aim --version 2>/dev/null || echo ok)"
}

ensure_cli

# ---------------------------------------------------------------------------
# Join + doctor + status
# ---------------------------------------------------------------------------
JOIN_ARGS=("$INGEST_URL" --token "$TOKEN")
[[ -n "$RING" ]] && JOIN_ARGS+=(--ring "$RING")
[[ -n "$CA_BUNDLE" ]] && JOIN_ARGS+=(--ca-bundle "$CA_BUNDLE")
for r in "${RESOLVE_ENTRIES[@]+"${RESOLVE_ENTRIES[@]}"}"; do
  JOIN_ARGS+=(--resolve "$r")
done

log "aim join → $INGEST_URL"
# Intentionally do not print JOIN_ARGS (contains token).
if ! aim join "${JOIN_ARGS[@]}"; then
  die "aim join failed — device not enrolled (token never logged)"
fi

log "aim doctor --fix"
if ! aim doctor --fix; then
  die "aim doctor --fix reported unhealthy findings — fix above, then re-run enroll"
fi

log "aim status"
if ! aim status; then
  die "aim status reported a problem after join"
fi

# ---------------------------------------------------------------------------
# Fail closed on missing token_file (silent flush failure)
# ---------------------------------------------------------------------------
verify_token_file() {
  local state="${AIM_STATE_DIR:-$HOME/.aim-collector}"
  local cfg="$state/config.json"
  local tok="$state/device_token"
  if [[ ! -f "$tok" ]]; then
    die "device_token missing at $tok — enrollment incomplete"
  fi
  if [[ ! -f "$cfg" ]]; then
    die "config.json missing at $cfg — cannot verify token_file"
  fi
  # Parse without printing secrets. Use python for portable JSON.
  if ! "$PY" - "$cfg" "$tok" <<'PY'
import json, sys
from pathlib import Path
cfg_path, tok_path = Path(sys.argv[1]), Path(sys.argv[2])
try:
    cfg = json.loads(cfg_path.read_text())
except Exception as e:
    print(f"config.json unreadable: {e}", file=sys.stderr)
    sys.exit(1)
tf = str(cfg.get("token_file") or "").strip()
if not tf:
    print("config.json token_file is missing — events will not flush", file=sys.stderr)
    sys.exit(1)
if Path(tf).expanduser().resolve() != tok_path.expanduser().resolve():
    print(
        f"config.json token_file does not point at device_token "
        f"(got {tf!r}, expected {str(tok_path)!r})",
        file=sys.stderr,
    )
    sys.exit(1)
sys.exit(0)
PY
  then
    die "token_file verification failed — events cannot flush"
  fi
  log "token_file OK → $tok"
}

verify_token_file

log "enroll complete — device should appear in Fleet within one heartbeat (~5 min)"
log "next: use an AI coding tool briefly, then check Activity on the dashboard"
exit 0

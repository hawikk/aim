#!/usr/bin/env bash
# — shared device-enroll one-liner printer.
#
# Sourced or executed by install-pilot (control-plane bootstrap) after the
# stack is healthy, so operators get a copy-paste command for engineer laptops
# without inventing a second contract.
#
# Usage:
#   ./scripts/print-device-enroll-oneliner.sh
#   ./scripts/print-device-enroll-oneliner.sh --host 100.64.0.10
#   AIM_HOST=aim.internal ./scripts/print-device-enroll-oneliner.sh
#   # install-pilot mint path (token shown once to the operator TTY only):
#   source scripts/print-device-enroll-oneliner.sh
#   print_device_enroll_oneliner --host "$host" --token "$secret"
#   # bare command string only (for scripts that wrap it):
#   device_enroll_command --host "$host" --token "$secret"
#
# Without --token / AIM_ENROLL_TOKEN the printer uses the <enrollment-secret>
# placeholder (docs / manual path). Never write the raw token to a log file.
set -euo pipefail

# Resolve dashboard + ingest base URLs from host/env.
# Prints nothing; sets _AIM_ENROLL_DASH_URL and _AIM_ENROLL_INGEST_URL.
_device_enroll_urls() {
  local host="${1:-${AIM_HOST:-${AIM_BIND_HOST:-127.0.0.1}}}"
  local dash_port="${DASHBOARD_PORT:-8081}"
  local ingest_port="${API_PORT:-${INGEST_PORT:-8080}}"
  local dash_url="${AIM_BASE_URL:-http://${host}:${dash_port}}"
  local ingest_url="${AIM_INGEST_PUBLIC_URL:-${AIM_INGEST_URL:-http://${host}:${ingest_port}}}"
  _AIM_ENROLL_DASH_URL="${dash_url%/}"
  _AIM_ENROLL_INGEST_URL="${ingest_url%/}"
}

# Parse optional --host / --token flags into HOST_OUT / TOKEN_OUT (by-name via globals).
_device_enroll_parse_args() {
  _AIM_ENROLL_HOST="${AIM_HOST:-${AIM_BIND_HOST:-${AIM_PUBLIC_HOST:-}}}"
  _AIM_ENROLL_TOKEN="${AIM_ENROLL_TOKEN:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) _AIM_ENROLL_HOST="$2"; shift 2 ;;
      --host=*) _AIM_ENROLL_HOST="${1#*=}"; shift ;;
      --token) _AIM_ENROLL_TOKEN="$2"; shift 2 ;;
      --token=*) _AIM_ENROLL_TOKEN="${1#*=}"; shift ;;
      -h|--help) return 2 ;;
      *)
        # Positional host for back-compat: print_device_enroll_oneliner <host>
        if [[ -z "${_AIM_ENROLL_HOST}" && "$1" != -* ]]; then
          _AIM_ENROLL_HOST="$1"
          shift
        else
          printf 'unknown arg: %s\n' "$1" >&2
          return 2
        fi
        ;;
    esac
  done
  # Default host when nothing provided.
  if [[ -z "${_AIM_ENROLL_HOST}" ]]; then
    _AIM_ENROLL_HOST="127.0.0.1"
  fi
}

# Single curl|bash command line (no commentary). Prefer this from install-pilot
# after minting so the operator gets one copy-paste line with the real secret.
device_enroll_command() {
  _device_enroll_parse_args "$@" || return $?
  _device_enroll_urls "$_AIM_ENROLL_HOST"
  local tok="${_AIM_ENROLL_TOKEN:-<enrollment-secret>}"
  printf 'curl -fsSL %s/enroll.sh | bash -s -- --url %s --token %s\n' \
    "$_AIM_ENROLL_DASH_URL" "$_AIM_ENROLL_INGEST_URL" "$tok"
}

print_device_enroll_oneliner() {
  _device_enroll_parse_args "$@" || {
    sed -n '2,25p' "${BASH_SOURCE[0]}" 2>/dev/null || true
    return 2
  }
  _device_enroll_urls "$_AIM_ENROLL_HOST"
  local tok="${_AIM_ENROLL_TOKEN:-<enrollment-secret>}"
  local cmd
  cmd="$(device_enroll_command --host "$_AIM_ENROLL_HOST" --token "$tok")"

  cat <<EOF
# Device enroll (engineer laptop / workstation)
# 1) Mint a scoped token in the dashboard Onboarding view (or API), unless
#    install-pilot already substituted one below.
# 2) Run on the device (Python 3.11+, pipx preferred):

${cmd}

# Offline wheel (air-gap / private mirror):
#   AIM_WHEEL=/path/to/aimonitoring_security-*.whl bash enroll.sh \\
#     --url ${_AIM_ENROLL_INGEST_URL} --token ${tok}
#
# Never paste the raw token into chat, tickets, or shared logs.
# enroll.sh never logs the token; fail-closed if token_file is missing.
EOF
}

# When executed (not sourced), print once.
if [[ "${BASH_SOURCE[0]##*/}" == "${0##*/}" ]]; then
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,25p' "$0"
    exit 0
  fi
  # --command-only: emit just the curl line (install-pilot / scripts).
  if [[ "${1:-}" == "--command-only" ]]; then
    shift
    device_enroll_command "$@"
    exit $?
  fi
  print_device_enroll_oneliner "$@"
fi

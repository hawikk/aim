#!/usr/bin/env bash
# AIM-454 / AIM-521: loud availability check for the aim-ci PR security runner pool.
#
# Why this exists:
#   When zero runners with the `aim-ci` label are online, every PR gate
#   (ci.yml, merge-audit, policy-guardrail, auto-merge, isolation-proof)
#   queues forever. A check that itself runs on `aim-ci` would queue too —
#   silence is the failure mode. This script must run off-path:
#     - local timer / cron on the ops host (preferred; not a queued job)
#     - GitHub Actions job on the `aim-ops` label (never aim-ci)
#     - health-report timer that exits non-zero and writes an alert file
#
# Exit codes (must stay distinct so operators do not confuse "cannot see"
# with "nothing is there"):
#   0  — at least MIN_ONLINE aim-ci runners are online
#   1  — usage / non-auth API / parse error (cannot determine status → fail closed)
#   2  — zero aim-ci runners online (blast-radius alert / blackout)
#   3  — fewer than MIN_ONLINE online (degraded / single-host risk)
#   4  — auth failure listing runners (401/403) — observability gap, NOT capacity
#
# Auth note (AIM-521):
#   Listing self-hosted runners is an admin-class API. Actions' GITHUB_TOKEN
#   cannot call it (no administration permission on job tokens). Prefer a
#   dedicated PAT (AIM_CI_RUNNER_LIST_TOKEN / GH_TOKEN) or host `gh auth`.
#   If a token 401/403s and `gh` is available, fall back to `gh` so a
#   mis-injected GITHUB_TOKEN does not mask real capacity forever.
#
# Env:
#   GH_REPO                 owner/repo (default: hawikk/aim)
#   MIN_ONLINE              required online aim-ci count (default: 1)
#   ALERT_FILE              path to write JSON alert on failure (optional)
#   AIM_CI_LABEL            label to require (default: aim-ci)
#   GH_TOKEN/GITHUB_TOKEN   optional; otherwise uses `gh auth`
set -euo pipefail

REPO="${GH_REPO:-hawikk/aim}"
MIN_ONLINE="${MIN_ONLINE:-1}"
ALERT_FILE="${ALERT_FILE:-}"
LABEL="${AIM_CI_LABEL:-aim-ci}"

err() { printf '[aim-ci-availability] ERROR: %s\n' "$*" >&2; }
warn() { printf '[aim-ci-availability] WARN: %s\n' "$*" >&2; }

# Write a pre-Python alert when the runner list itself is unreachable so the
# workflow step summary can still distinguish auth/API from capacity.
write_preflight_alert() {
  local code="$1" state="$2" message="$3"
  [ -n "${ALERT_FILE}" ] || return 0
  local parent generated
  parent="$(dirname "${ALERT_FILE}")"
  if [ -n "${parent}" ] && [ "${parent}" != "." ]; then
    mkdir -p "${parent}"
  fi
  generated="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  python3 - "$ALERT_FILE" "$code" "$state" "$message" "$REPO" "$LABEL" "$MIN_ONLINE" "$generated" <<'PY'
import json, sys
path, code, state, message, repo, label, min_online, generated = sys.argv[1:9]
payload = {
    "generatedAt": generated or None,
    "repo": repo,
    "label": label,
    "state": state,
    "exitCode": int(code),
    "message": message,
    "online": None,
    "total": None,
    "busy": None,
    "minOnline": int(min_online),
    "runners": [],
    "source": "check_aim_ci_availability.sh",
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
PY
}

# Prints body on stdout. Returns:
#   0 success
#   4 auth failure (401/403)
#   1 other failure
# Does not exit — caller decides whether to fall back.
curl_list_runners() {
  local token="$1"
  local tmp http_code body
  tmp="$(mktemp)"
  http_code="$(
    curl -sS -o "${tmp}" -w "%{http_code}" \
      -H "Authorization: Bearer ${token}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "User-Agent: aim-ci-availability" \
      "https://api.github.com/repos/${REPO}/actions/runners?per_page=100" \
      || true
  )"
  body="$(cat "${tmp}" 2>/dev/null || true)"
  rm -f "${tmp}"

  case "${http_code}" in
    200)
      printf '%s' "${body}"
      return 0
      ;;
    401|403)
      err "AUTH: token list runners for ${REPO} returned HTTP ${http_code} (GITHUB_TOKEN cannot list self-hosted runners; need PAT Administration:Read or host gh auth)"
      return 4
      ;;
    ""|000)
      err "API: failed to list runners for ${REPO} via curl (no HTTP status — network/DNS/TLS)"
      return 1
      ;;
    *)
      err "API: failed to list runners for ${REPO} via curl (HTTP ${http_code})"
      return 1
      ;;
  esac
}

# Prints body on stdout. Returns 0/1/4 same as curl_list_runners.
gh_list_runners() {
  local tmp body
  tmp="$(mktemp)"
  if ! env -u FORCE_COLOR -u CLICOLOR_FORCE -u GH_TOKEN -u GITHUB_TOKEN \
      NO_COLOR=1 CLICOLOR=0 GH_PAGER=cat \
      gh api "repos/${REPO}/actions/runners?per_page=100" >"${tmp}" 2>"${tmp}.err"; then
    body="$(cat "${tmp}.err" "${tmp}" 2>/dev/null || true)"
    rm -f "${tmp}" "${tmp}.err"
    if printf '%s' "${body}" | grep -Eqi 'HTTP[[:space:]]*(401|403)|"status"[[:space:]]*:[[:space:]]*(401|403)|Unauthorized|Forbidden|Resource not accessible by integration|Bad credentials'; then
      err "AUTH: gh api failed to list runners for ${REPO} (auth/permission denied)"
      return 4
    fi
    err "API: failed to list runners for ${REPO} via gh"
    return 1
  fi
  body="$(cat "${tmp}")"
  rm -f "${tmp}" "${tmp}.err"
  printf '%s' "${body}"
  return 0
}

fail_auth() {
  local detail="$1"
  err "AUTH: ${detail}. Capacity is UNOBSERVABLE — this is NOT a blackout. Set AIM_CI_RUNNER_LIST_TOKEN (PAT Administration:Read / classic repo) or ensure host gh auth can list runners."
  write_preflight_alert 4 auth_error \
    "auth failure listing runners for ${REPO}; capacity unobservable (not a blackout)"
  exit 4
}

fail_api() {
  local detail="$1"
  err "API: ${detail}"
  write_preflight_alert 1 api_error \
    "API failure listing runners for ${REPO}: ${detail}"
  exit 1
}

raw=""
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
token_rc=0

if [ -n "${token}" ]; then
  set +e
  raw="$(curl_list_runners "${token}")"
  token_rc=$?
  set -e
  if [ "${token_rc}" -eq 0 ]; then
    :
  elif [ "${token_rc}" -eq 4 ] && command -v gh >/dev/null 2>&1; then
    # Common GHA footgun: job injects GITHUB_TOKEN which always 403s here.
    # Fall back to host gh auth so the probe still sees real capacity.
    warn "token cannot list runners (HTTP 401/403); falling back to host gh auth"
    set +e
    raw="$(gh_list_runners)"
    token_rc=$?
    set -e
    if [ "${token_rc}" -eq 0 ]; then
      :
    elif [ "${token_rc}" -eq 4 ]; then
      fail_auth "token and host gh both denied listing runners for ${REPO}"
    else
      fail_api "token auth-failed and host gh API error for ${REPO}"
    fi
  elif [ "${token_rc}" -eq 4 ]; then
    fail_auth "token denied listing runners for ${REPO} and gh is not available for fallback"
  else
    fail_api "curl list runners failed for ${REPO}"
  fi
elif command -v gh >/dev/null 2>&1; then
  set +e
  raw="$(gh_list_runners)"
  token_rc=$?
  set -e
  if [ "${token_rc}" -eq 4 ]; then
    fail_auth "host gh denied listing runners for ${REPO}"
  elif [ "${token_rc}" -ne 0 ]; then
    fail_api "host gh list runners failed for ${REPO}"
  fi
else
  err "usage: need GH_TOKEN/GITHUB_TOKEN or gh in PATH"
  write_preflight_alert 1 usage_error "need GH_TOKEN/GITHUB_TOKEN or gh in PATH"
  exit 1
fi

# JSON is passed as argv[4] so a heredoc program source cannot steal stdin.
export AIM_CI_AVAIL_ALERT="$ALERT_FILE"
exec python3 - "$REPO" "$LABEL" "$MIN_ONLINE" "$raw" <<'PY'
import json, os, sys, datetime

repo, label, min_online_s, raw = sys.argv[1:5]
min_online = int(min_online_s)
alert_file = os.environ.get("AIM_CI_AVAIL_ALERT") or ""

try:
    body = json.loads(raw)
except json.JSONDecodeError:
    print("[aim-ci-availability] ERROR: runner list JSON parse failed", file=sys.stderr)
    sys.exit(1)

# Auth/API error payloads sometimes still parse as JSON without a runners list.
if isinstance(body, dict) and "message" in body and "runners" not in body:
    msg = body.get("message") or "unknown API error"
    print(
        f"[aim-ci-availability] ERROR: GitHub API message without runners list: {msg}",
        file=sys.stderr,
    )
    low = str(msg).lower()
    if any(s in low for s in ("bad credentials", "must have", "not accessible", "forbidden", "unauthorized")):
        sys.exit(4)
    sys.exit(1)

runners = body.get("runners") or []
aim = []
for r in runners:
    labels = [
        (l.get("name") if isinstance(l, dict) else str(l))
        for l in (r.get("labels") or [])
    ]
    if label not in labels:
        continue
    aim.append({
        "name": r.get("name") or "?",
        "status": (r.get("status") or "unknown").lower(),
        "busy": bool(r.get("busy")),
        "labels": labels,
    })

online = [r for r in aim if r["status"] == "online"]
online_n = len(online)
total_n = len(aim)
busy_n = sum(1 for r in online if r["busy"])
generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
detail = ", ".join(
    f"{r['name']}={r['status']}{' busy' if r['busy'] else ''}" for r in aim
) or "(none registered)"


def write_alert(code: int, message: str, state: str) -> None:
    if not alert_file:
        return
    payload = {
        "generatedAt": generated,
        "repo": repo,
        "label": label,
        "state": state,
        "exitCode": code,
        "message": message,
        "online": online_n,
        "total": total_n,
        "busy": busy_n,
        "minOnline": min_online,
        "runners": aim,
        "source": "check_aim_ci_availability.sh",
    }
    parent = os.path.dirname(alert_file)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(alert_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


print(
    f"[aim-ci-availability] repo={repo} label={label} "
    f"online={online_n}/{total_n} busy={busy_n} min={min_online}"
)
print(f"[aim-ci-availability] runners: {detail}")

if online_n == 0:
    msg = (
        f"ALERT: zero '{label}' runners online for {repo}. "
        f"All PR security gates will queue indefinitely. Registered: {detail}"
    )
    print(f"[aim-ci-availability] {msg}", file=sys.stderr)
    print(f"::error title=aim-ci capacity blackout::{msg}")
    write_alert(2, msg, "blackout")
    sys.exit(2)

if online_n < min_online:
    msg = (
        f"ALERT: only {online_n}/{min_online} required '{label}' runners online "
        f"for {repo} (single-host risk). {detail}"
    )
    print(f"[aim-ci-availability] {msg}", file=sys.stderr)
    print(f"::error title=aim-ci capacity degraded::{msg}")
    write_alert(3, msg, "degraded")
    sys.exit(3)

print(f"[aim-ci-availability] OK: {online_n} '{label}' runner(s) online for {repo}")
if alert_file and os.path.isfile(alert_file):
    try:
        os.remove(alert_file)
    except OSError:
        pass
sys.exit(0)
PY

#!/usr/bin/env bash
# auto-heal aim-ci-gce when it holds an orphaned job lease.
#
# Detects the failure mode: runner reports busy=true while the repo
# has zero *jobs* in_progress for this runner for longer than ORPHAN_THRESHOLD_SEC.
# GitHub then stops dispatching and the queue piles up until a service restart.
#
# Important: do NOT rely only on runs?status=in_progress. GitHub often keeps a
# multi-job workflow_run status as "queued" while individual jobs are already
# in_progress on the runner (observed live during). We also scan recent
# queued runs' jobs for status=in_progress assigned to RUNNER_NAME.
#
# Install path: deploy/runner/install-runner.sh (or install-watchdog.sh).
# Timer: every ~5 minutes via aim-ci-runner-watchdog.timer.
#
# Env (see /etc/aim/runner-watchdog.env):
#   GH_REPO                 owner/repo (required), e.g. hawikk/aim
#   RUNNER_NAME             runner name (default: aim-ci-gce)
#   RUNNER_SERVICE          systemd unit (default derived from GH_REPO + RUNNER_NAME)
#   ORPHAN_THRESHOLD_SEC    seconds busy+empty before restart (default: 600)
#   COOLDOWN_SEC            min seconds between restarts (default: 1800)
#   STATE_FILE              durable state path (default: /var/lib/aim/runner-watchdog-state.json)
#   LOG_FILE                append-only human log (default: /var/lib/aim/runner-watchdog.log)
#   ALERT_WEBHOOK_URL       optional POST JSON alert target
#   DRY_RUN                 if 1/true, never restart (log what would happen)
#   GH_TOKEN / GITHUB_TOKEN API token with actions:read (or repo). Prefer GH_TOKEN.
#
# Non-goal: do not retarget jobs to aim-local-hawik / aim-ops (D-C2 isolation).
set -euo pipefail

log() { printf '[aim-ci-watchdog] %s\n' "$*"; }
warn() { printf '[aim-ci-watchdog] WARN: %s\n' "$*" >&2; }
err() { printf '[aim-ci-watchdog] ERROR: %s\n' "$*" >&2; }

GH_REPO="${GH_REPO:-hawikk/aim}"
RUNNER_NAME="${RUNNER_NAME:-aim-ci-gce}"
ORPHAN_THRESHOLD_SEC="${ORPHAN_THRESHOLD_SEC:-600}"
COOLDOWN_SEC="${COOLDOWN_SEC:-1800}"
STATE_FILE="${STATE_FILE:-/var/lib/aim/runner-watchdog-state.json}"
LOG_FILE="${LOG_FILE:-/var/lib/aim/runner-watchdog.log}"
DRY_RUN="${DRY_RUN:-0}"
ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"

if [ -z "${RUNNER_SERVICE:-}" ]; then
  RUNNER_SERVICE="actions.runner.$(echo "$GH_REPO" | tr '/' '-').${RUNNER_NAME}.service"
fi

now_epoch() { date -u +%s; }
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

append_log() {
  local line="$1"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  printf '%s %s\n' "$(now_iso)" "$line" >>"$LOG_FILE" 2>/dev/null || true
  log "$line"
}

if ! command -v python3 >/dev/null 2>&1; then
  err "python3 required"
  exit 2
fi

# --- GitHub API helpers ----------------------------------------------------
api_json() {
  local path="$1"
  if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    curl -fsSL \
      -H "Authorization: Bearer ${token}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "User-Agent: aim-ci-runner-watchdog" \
      "https://api.github.com/${path}"
  elif command -v gh >/dev/null 2>&1; then
    env -u FORCE_COLOR -u CLICOLOR_FORCE NO_COLOR=1 CLICOLOR=0 \
      gh api "$path"
  else
    err "no GH_TOKEN/GITHUB_TOKEN and gh not installed; cannot query GitHub"
    return 2
  fi
}

# --- Durable state ---------------------------------------------------------
read_state() {
  python3 - "$STATE_FILE" <<'PY'
import json, os, sys
path = sys.argv[1]
empty = {
    "orphan_since_epoch": None,
    "orphan_since_iso": None,
    "last_restart_epoch": None,
    "last_restart_iso": None,
    "last_result": "init",
    "last_check_iso": None,
    "restart_count": 0,
}
data = dict(empty)
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            data.update(loaded)
    except (OSError, json.JSONDecodeError):
        pass
print(json.dumps(data))
PY
}

update_state() {
  # Mutate state with key=value pairs.
  # Special values: null, __now_epoch__, __now_iso__, __inc__
  python3 - "$STATE_FILE" "$@" <<'PY'
import json, os, sys
from datetime import datetime, timezone

path = sys.argv[1]
pairs = sys.argv[2:]
empty = {
    "orphan_since_epoch": None,
    "orphan_since_iso": None,
    "last_restart_epoch": None,
    "last_restart_iso": None,
    "last_result": "init",
    "last_check_iso": None,
    "restart_count": 0,
}
data = dict(empty)
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            data.update(loaded)
    except (OSError, json.JSONDecodeError):
        pass

now = datetime.now(timezone.utc)
data["last_check_iso"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

for p in pairs:
    if "=" not in p:
        continue
    k, v = p.split("=", 1)
    if v == "null":
        data[k] = None
    elif v == "__now_epoch__":
        data[k] = int(now.timestamp())
    elif v == "__now_iso__":
        data[k] = data["last_check_iso"]
    elif v == "__inc__":
        data[k] = int(data.get(k) or 0) + 1
    elif v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
        data[k] = int(v)
    elif v in ("true", "false"):
        data[k] = v == "true"
    else:
        data[k] = v

os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
print(json.dumps(data))
PY
}

clear_orphan() {
  update_state orphan_since_epoch=null orphan_since_iso=null last_result="$1" >/dev/null
}

post_alert() {
  local summary="$1"
  local detail="$2"
  append_log "ALERT: $summary — $detail"
  if [ -n "$ALERT_WEBHOOK_URL" ]; then
    local payload
    payload="$(python3 -c 'import json,sys; print(json.dumps({"text":sys.argv[1],"summary":sys.argv[2],"detail":sys.argv[3],"runner":sys.argv[4],"repo":sys.argv[5],"source":"aim-ci-runner-watchdog"}))' \
      "$summary" "$summary" "$detail" "$RUNNER_NAME" "$GH_REPO")"
    curl -fsSL -X POST \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 \
      || warn "alert webhook POST failed"
  fi
  logger -t aim-ci-runner-watchdog -p daemon.warning \
    "ORPHAN_RESTART runner=${RUNNER_NAME} repo=${GH_REPO} service=${RUNNER_SERVICE} ${detail}" \
    2>/dev/null || true
}

parse_runner() {
  # Args: runners_json_file
  # stdout: shell assignments runner_found= busy= runner_status=
  local runners_file="$1"
  python3 - "$RUNNER_NAME" "$runners_file" <<'PY'
import json, sys
runner_name, runners_path = sys.argv[1], sys.argv[2]
with open(runners_path, encoding="utf-8") as f:
    runners_body = json.load(f)
match = None
for r in runners_body.get("runners") or []:
    if r.get("name") == runner_name:
        match = r
        break
if match is None:
    print("runner_found=0")
    print("busy=0")
    print("runner_status=missing")
else:
    print("runner_found=1")
    print("busy=%d" % (1 if match.get("busy") else 0))
    status = match.get("status") or "unknown"
    status = "".join(c if c.isalnum() or c in "-_" else "_" for c in status)
    print("runner_status=%s" % status)
PY
}

# Count active jobs for this runner. GitHub can leave workflow_run.status as
# "queued" while a job is already in_progress — so we scan both in_progress
# and queued runs' job lists.
count_active_jobs_for_runner() {
  local out_file="$1"
  python3 - "$GH_REPO" "$RUNNER_NAME" "$out_file" <<'PY'
import json, os, sys, urllib.error, urllib.request

repo, runner_name, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""

def api(path: str):
    url = f"https://api.github.com/{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aim-ci-runner-watchdog",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        raise SystemExit(f"api_error {e.code} {path}: {body}")
    except Exception as e:
        raise SystemExit(f"api_error {path}: {e}")

# Prefer token path; if no token, fall back to gh CLI via subprocess for runs only.
use_gh = not token
if use_gh:
    import subprocess
    def api(path: str):
        env = os.environ.copy()
        env.pop("FORCE_COLOR", None)
        env.pop("CLICOLOR_FORCE", None)
        env["NO_COLOR"] = "1"
        env["CLICOLOR"] = "0"
        p = subprocess.run(
            ["gh", "api", path],
            capture_output=True, text=True, env=env, timeout=60,
        )
        if p.returncode != 0:
            raise SystemExit(f"api_error gh {path}: {p.stderr[:200]}")
        return json.loads(p.stdout or "{}")

in_progress_runs = api(f"repos/{repo}/actions/runs?status=in_progress&per_page=20")
queued_runs = api(f"repos/{repo}/actions/runs?status=queued&per_page=20")
run_ids = []
for body in (in_progress_runs, queued_runs):
    for r in body.get("workflow_runs") or []:
        rid = r.get("id")
        if rid is not None:
            run_ids.append(int(rid))

# de-dupe preserving order
seen = set()
uniq = []
for rid in run_ids:
    if rid not in seen:
        seen.add(rid)
        uniq.append(rid)

active = []
for rid in uniq:
    jobs_body = api(f"repos/{repo}/actions/runs/{rid}/jobs?per_page=100")
    for j in jobs_body.get("jobs") or []:
        if j.get("status") != "in_progress":
            continue
        jrunner = j.get("runner_name") or ""
        # Count jobs on this runner, or unassigned-but-running (shouldn't happen).
        if jrunner == runner_name or jrunner == "":
            active.append({
                "run_id": rid,
                "job_id": j.get("id"),
                "name": j.get("name"),
                "runner_name": jrunner,
                "started_at": j.get("started_at"),
            })

# Prefer only exact runner match for "healthy busy"; empty runner_name jobs are
# still a signal that *something* is running service-side.
exact = [a for a in active if a.get("runner_name") == runner_name]
any_active = active
result = {
    "in_progress_runs": int(in_progress_runs.get("total_count") or 0),
    "queued_runs_scanned": len(queued_runs.get("workflow_runs") or []),
    "active_jobs_on_runner": len(exact),
    "active_jobs_any": len(any_active),
    "sample": (exact or any_active)[:3],
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
print(f"in_progress_runs={result['in_progress_runs']}")
print(f"active_jobs_on_runner={result['active_jobs_on_runner']}")
print(f"active_jobs_any={result['active_jobs_any']}")
PY
}

# --- Main check ------------------------------------------------------------
main() {
  local busy runner_status runner_found
  local in_progress_runs active_jobs_on_runner active_jobs_any
  local state orphan_since last_restart age since_restart
  local epoch tmpdir runners_file jobs_summary

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  runners_file="${tmpdir}/runners.json"
  jobs_summary="${tmpdir}/jobs_summary.json"

  if ! api_json "repos/${GH_REPO}/actions/runners?per_page=100" >"$runners_file"; then
    err "failed to list runners for ${GH_REPO}"
    update_state last_result=api_error_runners >/dev/null || true
    exit 1
  fi

  # shellcheck disable=SC2046
  eval "$(parse_runner "$runners_file")"

  epoch="$(now_epoch)"

  if [ "${runner_found:-0}" != "1" ]; then
    append_log "check runner=${RUNNER_NAME} found=0"
    clear_orphan "runner_missing"
    exit 0
  fi

  if [ "${runner_status:-}" != "online" ]; then
    append_log "check runner=${RUNNER_NAME} status=${runner_status}"
    clear_orphan "runner_${runner_status}"
    exit 0
  fi

  # Healthy idle
  if [ "${busy:-0}" = "0" ]; then
    append_log "check runner=${RUNNER_NAME} status=online busy=0 → healthy_idle"
    clear_orphan "healthy_idle"
    exit 0
  fi

  # busy=true: confirm whether any job is actually in_progress for this runner.
  # Export token for the python helper (may already be in env).
  if ! eval "$(count_active_jobs_for_runner "$jobs_summary")"; then
    err "failed to enumerate active jobs for ${GH_REPO}"
    update_state last_result=api_error_jobs >/dev/null || true
    exit 1
  fi

  append_log "check runner=${RUNNER_NAME} busy=1 in_progress_runs=${in_progress_runs:-0} active_jobs_on_runner=${active_jobs_on_runner:-0} active_jobs_any=${active_jobs_any:-0}"

  # Healthy busy: job-level or run-level in_progress
  if [ "${active_jobs_on_runner:-0}" -gt 0 ] || [ "${in_progress_runs:-0}" -gt 0 ]; then
    clear_orphan "healthy_busy"
    exit 0
  fi

  # Orphan candidate: busy=true && no active jobs on this runner && no in_progress runs
  state="$(read_state)"
  orphan_since="$(python3 -c 'import json,sys; v=json.loads(sys.argv[1]).get("orphan_since_epoch"); print("" if v is None else v)' "$state")"
  last_restart="$(python3 -c 'import json,sys; v=json.loads(sys.argv[1]).get("last_restart_epoch"); print("" if v is None else v)' "$state")"

  if [ -z "$orphan_since" ]; then
    update_state \
      orphan_since_epoch=__now_epoch__ \
      orphan_since_iso=__now_iso__ \
      last_result=orphan_detected \
      >/dev/null
    append_log "orphan candidate started (busy=true, no active jobs); threshold=${ORPHAN_THRESHOLD_SEC}s"
    exit 0
  fi

  age=$((epoch - orphan_since))
  if [ "$age" -lt "$ORPHAN_THRESHOLD_SEC" ]; then
    update_state last_result=orphan_waiting >/dev/null
    append_log "orphan waiting age=${age}s threshold=${ORPHAN_THRESHOLD_SEC}s"
    exit 0
  fi

  # Cooldown: avoid thrash if restart does not clear the condition.
  if [ -n "$last_restart" ]; then
    since_restart=$((epoch - last_restart))
    if [ "$since_restart" -lt "$COOLDOWN_SEC" ]; then
      update_state last_result=cooldown >/dev/null
      append_log "orphan confirmed age=${age}s but cooldown active (${since_restart}s < ${COOLDOWN_SEC}s); not restarting"
      exit 0
    fi
  fi

  # Act
  if [ "$DRY_RUN" = "1" ] || [ "$DRY_RUN" = "true" ]; then
    post_alert "DRY_RUN would restart ${RUNNER_SERVICE}" \
      "orphan_age_sec=${age} busy=true active_jobs_on_runner=0 in_progress_runs=0"
    update_state last_result=dry_run_restart >/dev/null
    exit 0
  fi

  if [ "$(id -u)" -ne 0 ]; then
    err "restart requires root (systemctl restart ${RUNNER_SERVICE})"
    update_state last_result=need_root >/dev/null
    exit 1
  fi

  append_log "restarting ${RUNNER_SERVICE} (orphan_age_sec=${age})"
  if systemctl restart "$RUNNER_SERVICE"; then
    post_alert "restarted ${RUNNER_NAME} after orphaned job lease" \
      "orphan_age_sec=${age} service=${RUNNER_SERVICE} repo=${GH_REPO} active_jobs=0"
    update_state \
      orphan_since_epoch=null \
      orphan_since_iso=null \
      last_restart_epoch=__now_epoch__ \
      last_restart_iso=__now_iso__ \
      last_result=restarted \
      restart_count=__inc__ \
      >/dev/null
    sleep 2
    if systemctl is-active --quiet "$RUNNER_SERVICE"; then
      append_log "service active after restart"
    else
      warn "service not active after restart"
      update_state last_result=restarted_but_inactive >/dev/null || true
      exit 1
    fi
    exit 0
  fi

  err "systemctl restart ${RUNNER_SERVICE} failed"
  post_alert "FAILED to restart ${RUNNER_NAME}" \
    "orphan_age_sec=${age} service=${RUNNER_SERVICE}"
  update_state last_result=restart_failed >/dev/null || true
  exit 1
}

main "$@"

#!/usr/bin/env bash
# AIM-297: write a CI runner health snapshot for the D2 status screen.
#
# Output (default /var/lib/aim/ci-runner-status.json) is consumed by
# GET /api/system/status via AIM_CI_RUNNER_STATUS_FILE.
#
# Env:
#   AIM_CI_RUNNER_REPOS        comma/space list of owner/repo (required)
#   AIM_CI_RUNNER_STATUS_FILE  output path (default /var/lib/aim/ci-runner-status.json)
#   GH_TOKEN / GITHUB_TOKEN    optional; otherwise uses `gh auth`
set -euo pipefail

REPOS="${AIM_CI_RUNNER_REPOS:-}"
OUT="${AIM_CI_RUNNER_STATUS_FILE:-/var/lib/aim/ci-runner-status.json}"
[ -n "$REPOS" ] || { echo "AIM_CI_RUNNER_REPOS required" >&2; exit 2; }

api_json() {
  local path="$1"
  # `gh` may colorize even with --jq when FORCE_COLOR is set in agent envs.
  # Strip ANSI, or prefer curl with a token when available.
  if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    curl -fsSL -H "Authorization: Bearer ${token}" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "User-Agent: aim-ci-runner-health" \
      "https://api.github.com/${path}" 2>/dev/null || echo '{}'
  elif command -v gh >/dev/null 2>&1; then
    env -u FORCE_COLOR -u CLICOLOR_FORCE NO_COLOR=1 CLICOLOR=0 \
      gh api "$path" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || echo '{}'
  else
    echo '{}'
  fi
}

REPOS="${REPOS//,/ }"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
repo_list=()

for repo in $REPOS; do
  [ -n "$repo" ] || continue
  safe="${repo//\//_}"
  api_json "repos/${repo}/actions/runners?per_page=100" > "${tmpdir}/${safe}.runners.json"
  api_json "repos/${repo}/actions/runs?status=queued&per_page=100" > "${tmpdir}/${safe}.queued.json"
  echo "$repo" > "${tmpdir}/${safe}.repo"
  repo_list+=("$safe")
done

generated="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$(dirname "$OUT")"
python3 - "$OUT" "$generated" "$tmpdir" "${repo_list[@]}" <<'PY'
import json, os, sys
out, generated, tmpdir = sys.argv[1], sys.argv[2], sys.argv[3]
safes = sys.argv[4:]
runners = []
queued_total = 0
for safe in safes:
    repo = open(os.path.join(tmpdir, f"{safe}.repo"), encoding="utf-8").read().strip()
    with open(os.path.join(tmpdir, f"{safe}.runners.json"), encoding="utf-8") as f:
        try:
            body = json.load(f)
        except json.JSONDecodeError:
            body = {}
    with open(os.path.join(tmpdir, f"{safe}.queued.json"), encoding="utf-8") as f:
        try:
            qbody = json.load(f)
        except json.JSONDecodeError:
            qbody = {}
    for r in body.get("runners") or []:
        labels = [
            (l.get("name") if isinstance(l, dict) else l)
            for l in (r.get("labels") or [])
        ]
        # AIM-454: PR capacity tile counts only aim-ci. Including aim-ops
        # made a blackout look healthy while gates still queued forever.
        if "aim-ci" not in labels:
            continue
        if "aim-isolated" in labels:
            isolation = "hard"
        elif "aim-local-soft" in labels:
            isolation = "soft"
        else:
            isolation = "unknown"
        runners.append({
            "name": r.get("name"),
            "status": r.get("status"),
            "busy": bool(r.get("busy")),
            "labels": labels,
            "isolation": isolation,
            "repo": repo,
        })
    queued_total += int(qbody.get("total_count") or 0)

online_n = sum(1 for r in runners if str(r.get("status") or "").lower() == "online")
payload = {
    "generatedAt": generated,
    "source": "health-report.sh",
    "queuedJobs": queued_total,
    "runners": runners,
    "online": online_n,
    "total": len(runners),
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
# AIM-454: loud blackout signal next to the status file (not a queued job).
alert_path = out + ".blackout"
if online_n == 0:
    alert = {
        "generatedAt": generated,
        "state": "blackout",
        "message": "zero aim-ci runners online; PR security gates will queue indefinitely",
        "queuedJobs": queued_total,
        "runners": runners,
        "source": "health-report.sh",
    }
    with open(alert_path, "w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)
        f.write("\n")
elif os.path.isfile(alert_path):
    try:
        os.remove(alert_path)
    except OSError:
        pass
print(out)
print(json.dumps({
    "online": online_n,
    "total": len(runners),
    "queuedJobs": queued_total,
    "blackout": online_n == 0,
}))
# Exit non-zero on blackout so systemd OnFailure / timers notice.
if online_n == 0:
    raise SystemExit(2)
PY

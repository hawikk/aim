#!/usr/bin/env python3
"""execute .github/workflows/ci.yml on this host, because Actions is off.

GitHub Actions is disabled at the repo level on all three hawikk repos for the
Actions blackout, so no PR gets checks and auto-merge.yml never fires. This is
the replacement verification path: same workflow file, same commands, run here.

The design constraint that shapes everything below: a local runner must never
report a job green that it did not actually verify. `secret scan` in ci.yml has
zero `run:` steps -- it is entirely gitleaks/gitleaks-action@v2 -- so the naive
"execute the run: steps" runner scans nothing and prints a pass. Three rules
prevent that class of lie:

  1. Every `uses:` in the workflow must be classified in .github/ci-local.json.
     An unclassified action is a hard config error: no attestation is produced.
  2. A job in which nothing verifying actually executed can never be `pass`.
     It is `degraded`, with the reason recorded.
  3. Anything the runner cannot faithfully reproduce -- a missing tool, an
     expression it does not understand, an unavailable service -- degrades the
     job. Degradation of a required check is a non-zero exit.

Usage:
  scripts/ci_local.py                      run every job, write ci-local-attestation.json
  scripts/ci_local.py --job static --job test
  scripts/ci_local.py --list
  scripts/ci_local.py --self-test          prove the three rules above are load-bearing
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not a CI verdict
    sys.exit("ci_local: PyYAML is required (pip install pyyaml)")

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
ACTION_MAP = REPO / ".github" / "ci-local.json"
REQUIRED_CHECKS = REPO / ".github" / "required-checks.json"
ATTESTATION = REPO / "ci-local-attestation.json"

PASS, FAIL, DEGRADED, SKIPPED = "pass", "fail", "degraded", "skipped"

# Step kinds that perform no verification. A job made only of these ran nothing.
INERT_KINDS = {"harness", "artifact", "skipped"}


class ConfigError(Exception):
    """The runner cannot trust itself -- refuse to emit a verdict."""


# --------------------------------------------------------------------------
# expressions
# --------------------------------------------------------------------------


class Expressions:
    """A deliberately small ${{ }} evaluator.

    Anything outside this whitelist returns unresolved, which degrades the job
    rather than guessing. Guessing wrong on an `if:` silently skips a check.
    """

    def __init__(self, event: str, env: dict, ref: str, base_ref: str, workflow: str):
        self.event = event
        self.env = env
        self.ref = ref
        self.base_ref = base_ref
        self.workflow = workflow
        self.step_outputs: dict[str, dict[str, str]] = {}
        self.job_failed = False

    def _atom(self, expr: str):
        """Return (value, resolved)."""
        e = expr.strip()
        if e == "!cancelled()" or e == "always()":
            return True, True
        if e == "cancelled()":
            return False, True
        if e == "success()":
            return not self.job_failed, True
        if e == "failure()":
            return self.job_failed, True

        m = re.fullmatch(r"github\.event_name\s*==\s*'([^']*)'", e)
        if m:
            return self.event == m.group(1), True
        m = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)\s*==\s*'([^']*)'", e)
        if m:
            got = self.step_outputs.get(m.group(1), {}).get(m.group(2), "")
            return got == m.group(3), True
        m = re.fullmatch(r"env\.(\w+)\s*==\s*'([^']*)'", e)
        if m:
            return self.env.get(m.group(1), "") == m.group(2), True
        return None, False

    def condition(self, expr) -> tuple[bool, bool]:
        if isinstance(expr, bool):
            return expr, True
        e = str(expr).strip()
        if e.startswith("${{") and e.endswith("}}"):
            e = e[3:-2].strip()
        result = True
        for part in re.split(r"&&", e):
            value, ok = self._atom(part)
            if not ok:
                return False, False
            result = result and bool(value)
        return result, True

    def interpolate(self, text: str) -> tuple[str, bool]:
        """Substitute ${{ }} in a string. Returns (text, fully_resolved)."""
        resolved = True

        def sub(match):
            nonlocal resolved
            inner = match.group(1).strip()
            m = re.fullmatch(r"env\.(\w+)", inner)
            if m:
                return self.env.get(m.group(1), "")
            if inner == "github.ref":
                return self.ref
            if inner == "github.base_ref":
                return self.base_ref
            if inner == "github.workflow":
                return self.workflow
            if inner == "github.event_name":
                return self.event
            m = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", inner)
            if m:
                return self.step_outputs.get(m.group(1), {}).get(m.group(2), "")
            if inner.startswith("secrets."):
                # A secret has no local value. Pretending it is empty would let a
                # step "pass" while authenticating as nobody.
                resolved = False
                return ""
            resolved = False
            return ""

        return re.sub(r"\$\{\{([^}]*)\}\}", sub, text), resolved


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------


@dataclass
class StepResult:
    name: str
    kind: str
    verdict: str
    reason: str = ""
    duration_s: float = 0.0


@dataclass
class JobResult:
    id: str
    name: str
    verdict: str = PASS
    steps: list[StepResult] = field(default_factory=list)
    degraded_reasons: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def degrade(self, reason: str):
        if self.verdict != FAIL:
            self.verdict = DEGRADED
        if reason not in self.degraded_reasons:
            self.degraded_reasons.append(reason)


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------


class Runner:
    def __init__(self, workflow_path: Path, action_map: dict, event="pull_request",
                 verbose=True, cwd: Path | None = None):
        self.workflow_path = workflow_path
        self.wf = yaml.safe_load(workflow_path.read_text())
        self.actions = action_map["actions"]
        self.event = event
        self.verbose = verbose
        self.cwd = cwd or REPO
        self.notes: list[str] = []
        self._docker: bool | None = None
        self._job_bin: str = ""
        self._tempdirs: list[str] = []
        self._runner_temp: str = tempfile.gettempdir()
        self._full_history: bool | None = None
        self._validate_action_coverage()

    # -- preflight ---------------------------------------------------------

    def _validate_action_coverage(self):
        """Rule 1: every `uses:` must be classified, or we emit nothing at all."""
        unmapped = set()
        for job in self.wf.get("jobs", {}).values():
            for step in job.get("steps", []):
                if "uses" in step:
                    name = str(step["uses"]).split("@")[0]
                    if name not in self.actions:
                        unmapped.add(step["uses"])
        if unmapped:
            raise ConfigError(
                "unclassified action(s) in %s: %s\n"
                "Add them to %s before trusting a local run -- an unknown action "
                "may be the only thing verifying something."
                % (self.workflow_path.name, ", ".join(sorted(unmapped)),
                   ACTION_MAP.relative_to(REPO))
            )

    def has_docker(self) -> bool:
        if self._docker is None:
            self._docker = shutil.which("docker") is not None and subprocess.run(
                ["docker", "info"], capture_output=True).returncode == 0
        return self._docker

    def has_full_history(self) -> bool:
        if self._full_history is None:
            out = subprocess.run(["git", "rev-parse", "--is-shallow-repository"],
                                 cwd=self.cwd, capture_output=True, text=True)
            self._full_history = out.stdout.strip() == "false"
        return self._full_history

    def _requirements_met(self, spec: dict) -> str | None:
        for req, want in (spec or {}).items():
            if req == "docker" and want and not self.has_docker():
                return "docker is unavailable on this host"
            if req in ("git_full_history", "fetch-depth-0") and not self.has_full_history():
                return "shallow clone: history-dependent scanning would under-report"
        return None

    # -- services ----------------------------------------------------------

    def _start_services(self, job: dict, result: JobResult) -> list[str]:
        services = job.get("services") or {}
        if not services:
            return []
        if not self.has_docker():
            result.degrade("service containers required but docker is unavailable")
            return []
        started = []
        for name, spec in services.items():
            # A CI runner is a clean host; this one is not. If something already
            # holds the port, docker fails with a wall of networking text that
            # says nothing about the actual conflict.
            for port in spec.get("ports", []):
                host_port = int(str(port).split(":")[0])
                probe = socket.socket()
                conflict = probe.connect_ex(("127.0.0.1", host_port)) == 0
                probe.close()
                if conflict:
                    result.degrade(
                        f"service {name} needs host port {host_port}, which is "
                        "already in use (this host runs a live stack). Stop the "
                        f"listener on {host_port} to verify this job locally.")
            if result.verdict == DEGRADED:
                return started
            cmd = ["docker", "run", "-d", "--rm"]
            for port in spec.get("ports", []):
                cmd += ["-p", str(port)]
            if spec.get("options"):
                cmd += shlex.split(spec["options"])
            cmd.append(spec["image"])
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                result.degrade(f"could not start service {name}: {proc.stderr.strip()[:200]}")
                continue
            cid = proc.stdout.strip()
            started.append(cid)
            self._await_health(cid, name, spec, result)
        return started

    def _await_health(self, cid: str, name: str, spec: dict, result: JobResult):
        if "--health-cmd" not in (spec.get("options") or ""):
            time.sleep(1)
            return
        for _ in range(30):
            out = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", cid],
                capture_output=True, text=True)
            if out.stdout.strip() == "healthy":
                return
            time.sleep(1)
        result.degrade(f"service {name} never became healthy")

    @staticmethod
    def _stop_services(ids: list[str]):
        for cid in ids:
            subprocess.run(["docker", "kill", cid], capture_output=True)

    # -- steps -------------------------------------------------------------

    def _new_job_python(self, result: JobResult) -> str:
        """Give each job the writable, isolated interpreter Actions gives it.

        Two host gaps read as code failures if left alone, and both would make
        the local gate permanently red for reasons that have nothing to do with
        the diff:

          * actions/setup-python puts a `python` on PATH; Debian ships only
            `python3`, so steps calling `python` die with "command not found".
          * this host's system Python is PEP 668 externally-managed, so every
            `pip install` in ci.yml fails outright. The Actions interpreter is
            not externally-managed.

        A per-JOB venv fixes both and is the faithful choice rather than the
        convenient one: each Actions job starts from a clean interpreter, so
        reusing one venv across jobs could let job A's install satisfy a
        dependency job B forgot to declare -- hiding exactly the kind of bug
        this gate exists to catch.
        """
        venv = tempfile.mkdtemp(prefix=f"ci-local-{result.id}-")
        self._runner_temp = tempfile.mkdtemp(prefix=f"ci-local-tmp-{result.id}-")
        self._tempdirs.append(self._runner_temp)
        proc = subprocess.run([sys.executable, "-m", "venv", "--system-site-packages",
                               os.path.join(venv, "v")], capture_output=True, text=True)
        if proc.returncode != 0:
            result.degrade("could not create a job venv; python steps run against "
                           "the host interpreter and may fail for host reasons")
            return ""
        self._tempdirs.append(venv)
        return os.path.join(venv, "v", "bin")

    def _run_shell(self, script: str, env: dict, workdir: Path, step_id: str | None,
                   expr: Expressions) -> tuple[int, str]:
        out_file = Path(tempfile.mkstemp(prefix="ghout")[1])
        env_file = Path(tempfile.mkstemp(prefix="ghenv")[1])
        # The standard runner variables. These are not cosmetic: ci.yml builds
        # paths like "$RUNNER_TEMP/v", and an unset RUNNER_TEMP expands that to
        # the absolute path /v, so the aim-package job died on "Permission
        # denied: '/v'" -- a host gap masquerading as a packaging failure.
        run_env = {**os.environ, **env,
                   "PATH": ((self._job_bin + os.pathsep) if self._job_bin else "")
                           + os.environ.get("PATH", ""),
                   "GITHUB_OUTPUT": str(out_file), "GITHUB_ENV": str(env_file),
                   "RUNNER_TEMP": self._runner_temp, "RUNNER_OS": "Linux",
                   "RUNNER_ARCH": "X64", "GITHUB_WORKSPACE": str(self.cwd),
                   "GITHUB_EVENT_NAME": self.event,
                   "GITHUB_REPOSITORY": "hawikk/aim",
                   "CI": "true", "AIM_CI_LOCAL": "1"}
        # Always capture: in verbose mode the output was streamed and then lost,
        # so a failing step left an EMPTY `reason` in the attestation -- evidence
        # that exists only in a terminal someone already closed.
        proc = subprocess.run(["bash", "-eo", "pipefail", "-c", script],
                              cwd=workdir, env=run_env,
                              capture_output=True, text=True)
        if self.verbose:
            sys.stdout.write((proc.stdout or "") + (proc.stderr or ""))
            sys.stdout.flush()
        for line in out_file.read_text().splitlines():
            if "=" in line and step_id:
                k, v = line.split("=", 1)
                expr.step_outputs.setdefault(step_id, {})[k] = v
        for line in env_file.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                expr.env[k] = v
        out_file.unlink(missing_ok=True)
        env_file.unlink(missing_ok=True)
        tail = ((proc.stdout or "") + (proc.stderr or "")).strip()[-800:]
        return proc.returncode, tail

    def _gitleaks_command(self, result: JobResult) -> str | None:
        """Scan exactly the commits the action would scan -- or refuse to pass.

        gitleaks-action on pull_request scans the PR's commits. Scanning the whole
        tree locally instead surfaces 30 deliberate corpus fixtures plus 2 known
        false positives, i.e. permanent red. Scanning nothing is the opposite
        failure and is worse: it looks green. So an empty range degrades.
        """
        base = None
        for candidate in ("origin/main", "main"):
            probe = subprocess.run(["git", "merge-base", candidate, "HEAD"],
                                   cwd=self.cwd, capture_output=True, text=True)
            if probe.returncode == 0:
                base = probe.stdout.strip()
                break
        if not base:
            result.degrade("secret scan: no main branch to diff against, so the "
                           "PR commit range is unknown")
            return None

        count = subprocess.run(["git", "rev-list", "--count", f"{base}..HEAD"],
                               cwd=self.cwd, capture_output=True, text=True).stdout.strip()
        if count in ("", "0"):
            result.degrade("secret scan: 0 commits in %s..HEAD -- nothing was "
                           "scanned, so this is not a clean result" % base[:8])
            return None

        self.notes.append(f"secret scan covered {count} commit(s) in {base[:8]}..HEAD "
                          "(same scope as gitleaks-action on a PR)")
        if git("status", "--porcelain", cwd=self.cwd):
            self.notes.append("WARNING: uncommitted changes were NOT secret-scanned; "
                              "commit before trusting the secret scan verdict")
        return ('docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.28.0 detect '
                '--source=/repo --config=/repo/.gitleaks.toml --redact --no-banner '
                f'--exit-code 1 --log-opts="{base}..HEAD"')

    def _docker_build_command(self, with_: dict) -> str:
        parts = ["docker", "build"]
        if with_.get("file"):
            parts += ["-f", str(with_["file"])]
        for tag in str(with_.get("tags", "")).splitlines():
            if tag.strip():
                parts += ["-t", tag.strip()]
        for arg in str(with_.get("build-args", "")).splitlines():
            if arg.strip():
                parts += ["--build-arg", arg.strip()]
        parts.append(str(with_.get("context", ".")))
        return " ".join(shlex.quote(p) if " " in p else p for p in parts)

    def _run_action(self, step: dict, result: JobResult, expr: Expressions,
                    env: dict, workdir: Path) -> StepResult:
        ref = str(step["uses"])
        spec = self.actions[ref.split("@")[0]]
        kind = spec["kind"]
        label = step.get("name") or ref

        requires = dict(spec.get("requires") or {})
        if "fetch-depth-0" in requires and str((step.get("with") or {}).get("fetch-depth", "")) != "0":
            requires.pop("fetch-depth-0")
        unmet = self._requirements_met(requires)
        if unmet:
            result.degrade(f"{ref}: {unmet}")
            return StepResult(label, kind, DEGRADED, unmet)

        if kind in ("harness", "artifact"):
            return StepResult(label, kind, SKIPPED, spec.get("reason", ""))

        if kind == "unsupported":
            result.degrade(f"{ref}: not reproducible locally")
            return StepResult(label, kind, DEGRADED, spec.get("reason", ""))

        if kind == "toolchain":
            proc = subprocess.run(["bash", "-c", spec["verify"]],
                                  cwd=workdir, capture_output=True, text=True)
            if proc.returncode != 0:
                reason = f"{ref}: tool missing locally ({spec['verify']!r} failed)"
                result.degrade(reason)
                return StepResult(label, kind, DEGRADED, reason)
            got = (proc.stdout or proc.stderr).strip().splitlines()[0]
            want_key = spec.get("version_from")
            want = str((step.get("with") or {}).get(want_key, "")) if want_key else ""
            want, _ = expr.interpolate(want)
            note = f"local {got}"
            if want and want.split(".")[0] not in got:
                note = f"version drift: workflow pins {want}, host has {got}"
                result.degrade(f"{ref}: {note}")
                return StepResult(label, kind, DEGRADED, note)
            return StepResult(label, kind, PASS, note)

        if kind == "replacement":
            command = spec["local"]
            if command == "__docker_build__":
                command = self._docker_build_command(step.get("with") or {})
            elif command == "__gitleaks__":
                command = self._gitleaks_command(result)
                if command is None:
                    return StepResult(label, kind, DEGRADED, result.degraded_reasons[-1])
            command, ok = expr.interpolate(command)
            if not ok:
                result.degrade(f"{ref}: local command needs an unavailable value")
                return StepResult(label, kind, DEGRADED, "unresolved expression")
            started = time.time()
            code, tail = self._run_shell(command, env, workdir, step.get("id"), expr)
            sr = StepResult(label, kind, PASS if code == 0 else FAIL,
                            "" if code == 0 else tail, round(time.time() - started, 1))
            if code != 0:
                result.verdict = FAIL
            return sr

        raise ConfigError(f"unknown kind {kind!r} for {ref}")

    # -- jobs --------------------------------------------------------------

    def run_job(self, job_id: str) -> JobResult:
        job = self.wf["jobs"][job_id]
        result = JobResult(job_id, job.get("name", job_id))
        started = time.time()
        top_env = {k: str(v) for k, v in (self.wf.get("env") or {}).items()}
        expr = Expressions(self.event, dict(top_env), "refs/heads/local", "main",
                           self.wf.get("name", "ci"))

        if self.verbose:
            print(f"\n=== {result.name} [{job_id}]", flush=True)

        self._job_bin = self._new_job_python(result)
        services = self._start_services(job, result)
        try:
            for step in job.get("steps", []):
                label = step.get("name") or step.get("uses", "step")
                if "if" in step:
                    ok, resolved = expr.condition(step["if"])
                    if not resolved:
                        reason = f"unevaluatable condition {step['if']!r}"
                        result.degrade(f"{label}: {reason}")
                        result.steps.append(StepResult(label, "run", DEGRADED, reason))
                        continue
                    if not ok:
                        result.steps.append(StepResult(label, "run", SKIPPED, "if: false"))
                        continue

                if "uses" in step:
                    sr = self._run_action(step, result, expr, dict(expr.env), self.cwd)
                    result.steps.append(sr)
                    if self.verbose:
                        print(f"  [{sr.verdict:8}] {sr.name}", flush=True)
                    continue

                step_env = dict(expr.env)
                unresolved = False
                for k, v in (step.get("env") or {}).items():
                    value, ok = expr.interpolate(str(v))
                    step_env[k] = value
                    unresolved = unresolved or not ok
                script, ok = expr.interpolate(step["run"])
                if not ok or unresolved:
                    reason = "step needs a secret or unsupported context value"
                    result.degrade(f"{label}: {reason}")
                    result.steps.append(StepResult(label, "run", DEGRADED, reason))
                    continue

                workdir = self.cwd / step.get("working-directory", ".")
                if self.verbose:
                    print(f"  --> {label}", flush=True)
                t0 = time.time()
                code, tail = self._run_shell(script, step_env, workdir, step.get("id"), expr)
                sr = StepResult(label, "run", PASS if code == 0 else FAIL,
                                "" if code == 0 else tail, round(time.time() - t0, 1))
                result.steps.append(sr)
                if code != 0:
                    result.verdict = FAIL
                    expr.job_failed = True
                    if self.verbose:
                        print(f"  [FAIL] {label}", flush=True)
        finally:
            self._stop_services(services)

        # Rule 2: a job that verified nothing is not a passing job.
        if result.verdict == PASS:
            did_work = any(s.verdict in (PASS, FAIL) and s.kind not in INERT_KINDS
                           for s in result.steps)
            if not did_work:
                result.degrade("no verifying step executed locally -- this job "
                               "proves nothing here")
        result.duration_s = round(time.time() - started, 1)
        return result


# --------------------------------------------------------------------------
# attestation
# --------------------------------------------------------------------------


def git(*args, cwd=REPO) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True).stdout.strip()


def build_attestation(results: list[JobResult], event: str, notes: list[str]) -> dict:
    required = []
    if REQUIRED_CHECKS.exists():
        blob = json.loads(re.sub(r'"_comment":\s*\[[^\]]*\],', "",
                                 REQUIRED_CHECKS.read_text(), count=1))
        required = blob.get("always", [])

    by_name = {r.name: r for r in results}
    covered, not_covered = [], []
    for check in required:
        r = by_name.get(check)
        if r is None:
            not_covered.append({"check": check, "why": "job not run in this invocation"})
        elif r.verdict == PASS:
            covered.append(check)
        else:
            not_covered.append({"check": check, "why": f"{r.verdict}: "
                                + "; ".join(r.degraded_reasons) if r.degraded_reasons
                                else r.verdict})

    if any(r.verdict == FAIL for r in results):
        verdict = FAIL
    elif not_covered or any(r.verdict == DEGRADED for r in results):
        verdict = DEGRADED
    else:
        verdict = PASS

    return {
        "schema": "aim.ci-local.attestation/v1",
        "_comment": "Produced by scripts/ci_local.py during the Actions "
                    "blackout. This is NOT a GitHub check run. `degraded` means "
                    "some required verification did not happen here -- read "
                    "required_checks.not_covered before merging on it.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": f"{socket.gethostname()} ({platform.platform()})",
        "workflow": str(WORKFLOW.relative_to(REPO)),
        "event": event,
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "tree_dirty": bool(git("status", "--porcelain")),
        "verdict": verdict,
        "required_checks": {"covered": covered, "not_covered": not_covered},
        "jobs": [
            {
                "id": r.id, "name": r.name, "verdict": r.verdict,
                "duration_s": r.duration_s, "degraded_reasons": r.degraded_reasons,
                "steps": [
                    {"name": s.name, "kind": s.kind, "verdict": s.verdict,
                     "reason": s.reason, "duration_s": s.duration_s}
                    for s in r.steps
                ],
            }
            for r in results
        ],
        "notes": notes,
    }


def print_summary(att: dict):
    print("\n" + "=" * 68)
    print(f"local CI verdict: {att['verdict'].upper()}   commit {att['commit'][:8]}"
          + ("  (DIRTY TREE)" if att["tree_dirty"] else ""))
    print("=" * 68)
    for job in att["jobs"]:
        print(f"  {job['verdict']:9} {job['name']}  ({job['duration_s']}s)")
        for reason in job["degraded_reasons"]:
            print(f"            - {reason}")
    nc = att["required_checks"]["not_covered"]
    if nc:
        print(f"\n  {len(nc)} required check(s) NOT verified locally:")
        for item in nc:
            print(f"    - {item['check']}: {item['why']}")
    print()


# --------------------------------------------------------------------------
# self-test: prove the three rules are load-bearing
# --------------------------------------------------------------------------


def self_test() -> int:
    """Mutate the inputs and assert the runner's guarantees actually bite."""
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if not cond else ""))

    tmp = Path(tempfile.mkdtemp(prefix="ci-local-selftest"))
    subprocess.run(["git", "init", "-q", str(tmp)], check=True)
    subprocess.run(["git", "-C", str(tmp), "commit", "-q", "--allow-empty", "-m", "x"],
                   check=True, capture_output=True)
    real_map = json.loads(ACTION_MAP.read_text())

    def write(name, jobs, env=None):
        path = tmp / name
        path.write_text(yaml.dump({"name": "t", "on": {}, "env": env or {}, "jobs": jobs}))
        return path

    # Rule 1: an unclassified action must be a hard refusal, not a green run.
    wf = write("unmapped.yml", {"j": {"name": "j", "steps": [{"uses": "evil/action@v1"}]}})
    try:
        Runner(wf, real_map, verbose=False, cwd=tmp)
        check("rule 1: unclassified action refuses to run", False, "no ConfigError raised")
    except ConfigError as exc:
        check("rule 1: unclassified action refuses to run", "evil/action@v1" in str(exc))

    # Rule 2 (the gitleaks case): a job whose only steps are inert cannot pass.
    # This is the mutation test -- reclassifying a real scanner as an artifact
    # upload is exactly the mistake that would fake a green `secret scan`.
    muted = json.loads(json.dumps(real_map))
    muted["actions"]["gitleaks/gitleaks-action"] = {"kind": "artifact", "reason": "mutated"}
    wf = write("inert.yml", {"gitleaks": {"name": "secret scan", "steps": [
        {"uses": "actions/checkout@v4"},
        {"uses": "gitleaks/gitleaks-action@v2"},
    ]}})
    res = Runner(wf, muted, verbose=False, cwd=tmp).run_job("gitleaks")
    check("rule 2: job that verified nothing is not 'pass'", res.verdict == DEGRADED,
          f"got {res.verdict}")

    # ...and with the real classification it is NOT inert (it would really scan).
    wf2 = write("real.yml", {"gitleaks": {"name": "secret scan", "steps": [
        {"uses": "gitleaks/gitleaks-action@v2"},
    ]}})
    runner = Runner(wf2, real_map, verbose=False, cwd=tmp)
    spec = runner.actions["gitleaks/gitleaks-action"]
    check("rule 2: real map classifies the scanner as verifying work",
          spec["kind"] == "replacement" and "gitleaks" in spec["local"])

    # Rule 2, zero-target form: an empty scan range must not read as clean.
    # Narrowing the secret scan to the PR's commits (to avoid permanent red on
    # pre-existing fixtures) creates exactly this risk, so it is pinned here.
    subprocess.run(["git", "-C", str(tmp), "branch", "-f", "main", "HEAD"],
                   check=True, capture_output=True)
    wf = write("empty-range.yml", {"gitleaks": {"name": "secret scan", "steps": [
        {"uses": "gitleaks/gitleaks-action@v2"}]}})
    res = Runner(wf, real_map, verbose=False, cwd=tmp).run_job("gitleaks")
    check("rule 2: secret scan with 0 commits in range degrades, not passes",
          res.verdict == DEGRADED and any("0 commits" in r for r in res.degraded_reasons),
          f"got {res.verdict}: {res.degraded_reasons}")

    # Rule 3a: a failing command fails the job.
    wf = write("fail.yml", {"j": {"name": "j", "steps": [{"name": "boom", "run": "exit 7"}]}})
    res = Runner(wf, real_map, verbose=False, cwd=tmp).run_job("j")
    check("rule 3: failing run step fails the job", res.verdict == FAIL, f"got {res.verdict}")

    # Rule 3b: an expression the evaluator does not understand degrades, never skips silently.
    wf = write("expr.yml", {"j": {"name": "j", "steps": [
        {"name": "mystery", "if": "${{ github.actor == 'nobody' }}", "run": "true"}]}})
    res = Runner(wf, real_map, verbose=False, cwd=tmp).run_job("j")
    check("rule 3: unknown if: expression degrades the job", res.verdict == DEGRADED,
          f"got {res.verdict}")

    # Rule 3c: a step needing a secret cannot report pass.
    wf = write("secret.yml", {"j": {"name": "j", "steps": [
        {"name": "needs token", "env": {"T": "${{ secrets.GITHUB_TOKEN }}"}, "run": "true"}]}})
    res = Runner(wf, real_map, verbose=False, cwd=tmp).run_job("j")
    check("rule 3: step requiring a secret degrades the job", res.verdict == DEGRADED,
          f"got {res.verdict}")

    # A genuinely passing job still passes -- the guard is not just "always red".
    wf = write("ok.yml", {"j": {"name": "j", "steps": [{"name": "real work", "run": "true"}]}})
    res = Runner(wf, real_map, verbose=False, cwd=tmp).run_job("j")
    check("control: a real passing step yields 'pass'", res.verdict == PASS, f"got {res.verdict}")

    # Attestation must surface uncovered required checks rather than hiding them.
    att = build_attestation([JobResult("x", "unit tests", DEGRADED,
                                       degraded_reasons=["docker missing"])],
                            "pull_request", [])
    check("attestation: degraded required check is reported not_covered",
          att["verdict"] == DEGRADED and any(
              c["check"] == "unit tests" for c in att["required_checks"]["not_covered"]))

    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nself-test: {len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--job", action="append", dest="jobs", help="run only these job ids")
    ap.add_argument("--list", action="store_true", help="list jobs and exit")
    ap.add_argument("--event", default="pull_request", choices=["pull_request", "push"])
    ap.add_argument("--attestation", type=Path, default=ATTESTATION)
    ap.add_argument("--allow-degraded", action="store_true",
                    help="exit 0 even if required checks were not verified locally")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    try:
        runner = Runner(WORKFLOW, json.loads(ACTION_MAP.read_text()),
                        event=args.event, verbose=not args.quiet)
    except ConfigError as exc:
        print(f"ci_local: REFUSING TO RUN\n{exc}", file=sys.stderr)
        return 3

    if args.list:
        for jid, job in runner.wf["jobs"].items():
            print(f"{jid:16} {job.get('name', '')}")
        return 0

    job_ids = args.jobs or list(runner.wf["jobs"])
    unknown = [j for j in job_ids if j not in runner.wf["jobs"]]
    if unknown:
        print(f"ci_local: no such job(s): {', '.join(unknown)}", file=sys.stderr)
        return 3

    results = [runner.run_job(jid) for jid in job_ids]
    notes = list(runner.notes)
    if args.jobs:
        notes.append("PARTIAL RUN: only " + ", ".join(args.jobs))
    if not runner.has_docker():
        notes.append("docker unavailable on this host; container-dependent checks degraded")

    att = build_attestation(results, args.event, notes)
    args.attestation.write_text(json.dumps(att, indent=2) + "\n")
    print_summary(att)
    print(f"attestation: {args.attestation}")

    if att["verdict"] == FAIL:
        return 1
    if att["verdict"] == DEGRADED and not args.allow_degraded:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

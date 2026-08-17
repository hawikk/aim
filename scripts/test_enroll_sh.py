#!/usr/bin/env python3
"""AIM-1124 — static + behavioural checks for apps/web/public/enroll.sh.

No live network, no real pipx install. Covers:
  * script is served-path static (exists, executable bit optional, shebang)
  * --help works under bash
  * Python preflight fails closed on too-old interpreter (via mock PATH)
  * usage fails closed when --token / --url missing
  * script never echoes a provided token on happy or failure paths
  * print-device-enroll-oneliner emits the curl | bash contract

Run:
  python3 scripts/test_enroll_sh.py
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENROLL = ROOT / "apps" / "web" / "public" / "enroll.sh"
ONELINER = ROOT / "scripts" / "print-device-enroll-oneliner.sh"

SECRET = "deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef"


def run(argv, *, env=None, timeout=15):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        env=env or os.environ.copy(),
        timeout=timeout,
        check=False,
    )


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def test_enroll_script_exists_and_is_bash():
    assert_true(ENROLL.is_file(), f"missing {ENROLL}")
    text = ENROLL.read_text(encoding="utf-8")
    assert_true(text.startswith("#!/usr/bin/env bash"), "shebang must be bash")
    assert_true("aimonitoring-security" in text, "must install correct package name")
    assert_true('PKG_NAME="aimonitoring-security"' in text, "package constant must be correct")
    assert_true("token_file" in text, "must verify token_file")
    assert_true("AIM_WHEEL" in text, "must support offline AIM_WHEEL")
    assert_true("3.11" in text or "MIN_PY_MINOR=11" in text, "must require Python 3.11+")
    # Never echo the raw token variable on purpose.
    assert_true('echo "$TOKEN"' not in text, "must not echo $TOKEN")
    assert_true("printf '%s\\n' \"$TOKEN\"" not in text, "must not printf $TOKEN")


def test_help_exits_zero():
    r = run(["bash", str(ENROLL), "--help"])
    assert_true(r.returncode == 0, f"--help rc={r.returncode}: {r.stderr}")
    assert_true("usage:" in r.stdout.lower() or "One-shot" in r.stdout, r.stdout)


def test_missing_args_fail_usage():
    r = run(["bash", str(ENROLL)])
    assert_true(r.returncode == 2, f"expected usage exit 2, got {r.returncode}: {r.stderr}")
    assert_true(SECRET not in r.stdout + r.stderr, "token must not appear when absent")

    r = run(["bash", str(ENROLL), "--url", "http://127.0.0.1:8080"])
    assert_true(r.returncode == 2, f"missing token should be 2, got {r.returncode}")
    assert_true("token" in (r.stderr + r.stdout).lower(), r.stderr)


def test_token_never_logged_on_preflight_failure():
    """Force a fake python3 that reports 3.9 so preflight fails; token must not leak."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        fake_py = td_path / "python3"
        fake_py.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"$1\" == \"-c\" ]]; then\n"
            "  # Simulate old interpreter for version checks.\n"
            "  case \"$2\" in\n"
            "    *version_info*) exit 1 ;;\n"
            "    *sys.version_info*) echo '3.9.18' ;;\n"
            "    *) exit 0 ;;\n"
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            "echo '3.9.18'\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_py.chmod(fake_py.stat().st_mode | stat.S_IEXEC)
        # Isolate PATH so real python3.11+ on the host cannot pass preflight.
        # Keep only common shell builtins locations + our fake python3.
        env = os.environ.copy()
        env["PATH"] = f"{td}:/usr/bin:/bin"
        env.pop("AIM_WHEEL", None)
        # Hide versioned interpreters that may still exist under /usr/bin.
        for name in ("python3.11", "python3.12", "python3.13", "python3.14"):
            p = td_path / name
            if not p.exists():
                p.symlink_to(fake_py)
        r = run(
            [
                "bash",
                str(ENROLL),
                "--url",
                "http://127.0.0.1:8080",
                "--token",
                SECRET,
            ],
            env=env,
        )
        out = r.stdout + r.stderr
        assert_true(r.returncode == 2, f"expected preflight fail 2, got {r.returncode}: {out}")
        assert_true(SECRET not in out, f"token leaked in output:\n{out}")
        assert_true("3.11" in out or "Python" in out, out)


def test_oneliner_contract():
    assert_true(ONELINER.is_file(), f"missing {ONELINER}")
    r = run(["bash", str(ONELINER), "--host", "aim.example"])
    assert_true(r.returncode == 0, r.stderr)
    text = r.stdout
    assert_true("curl -fsSL" in text, text)
    assert_true("http://aim.example:8081/enroll.sh" in text, text)
    assert_true("--url http://aim.example:8080" in text, text)
    assert_true("--token" in text, text)
    assert_true(SECRET not in text, "oneliner must not embed a real secret")
    assert_true("<enrollment-secret>" in text, text)

    # install-pilot mint path: optional --token substitutes the real secret
    # (operator TTY only — never for shared logs).
    r2 = run(
        [
            "bash",
            str(ONELINER),
            "--command-only",
            "--host",
            "aim.example",
            "--token",
            SECRET,
        ]
    )
    assert_true(r2.returncode == 0, r2.stderr)
    line = r2.stdout.strip()
    assert_true(line.startswith("curl -fsSL"), line)
    assert_true(f"--token {SECRET}" in line, line)
    assert_true("enroll.sh" in line, line)


def test_install_pilot_prints_enroll_oneliner():
    """install-pilot must source the shared printer and prefer enroll.sh."""
    pilot = ROOT / "scripts" / "install-pilot.sh"
    assert_true(pilot.is_file(), f"missing {pilot} (install-pilot integration)")
    text = pilot.read_text(encoding="utf-8")
    assert_true("print-device-enroll-oneliner.sh" in text, "must source shared oneliner")
    assert_true("device_enroll_command" in text, "must call device_enroll_command")
    assert_true("enroll.sh" in text, "must mention enroll.sh in printed path")
    # Must not prefer bare aim join as the primary one-liner label.
    assert_true(
        "One-liner (preferred — Python 3.11+, pipx; install + join + doctor)" in text
        or "enroll_cmd" in text,
        "mint path should prefer enroll one-shot",
    )


def main() -> int:
    tests = [
        test_enroll_script_exists_and_is_bash,
        test_help_exits_zero,
        test_missing_args_fail_usage,
        test_token_never_logged_on_preflight_failure,
        test_oneliner_contract,
        test_install_pilot_prints_enroll_oneliner,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"ok  {t.__name__}")
        except Exception as e:  # noqa: BLE001 — report each test
            failed += 1
            print(f"FAIL {t.__name__}: {e}", file=sys.stderr)
    if failed:
        print(f"{failed} test(s) failed", file=sys.stderr)
        return 1
    print(f"all {len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

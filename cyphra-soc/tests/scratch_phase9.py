"""scratch_phase9 — socctl/ CLI surface.

    python tests/scratch_phase9.py

The CLI is a thin wrapper over the platform's modules. The tests
verify:

* ``main`` parses arguments and dispatches to the registered
  subcommand.
* Each shipped subcommand prints to stdout and returns an integer
  exit code.
* Subcommands accept their declared arguments.
* An unknown command returns a non-zero exit code.
"""

import argparse
import io
import sys
from contextlib import redirect_stdout

sys.path.insert(0, ".")

import socctl  # noqa: F401 — imports register every subcommand
from socctl import commands  # noqa: F401
from socctl.cli import Command, command, list_commands, main

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── dispatcher ─────────────────────────────────────────────────────────────


def test_registered_commands() -> None:
    print("\n[cli] the dispatcher has every shipped subcommand registered")
    expected = {
        "readiness", "metrics", "cases", "crises",
        "hunts", "regression", "coverage", "intel",
    }
    actual = set(list_commands())
    check(
        "every shipped subcommand is registered",
        actual == expected,
        f"missing={expected - actual} extra={actual - expected}",
    )


def test_main_dispatches() -> None:
    print("\n[cli] main() parses and dispatches each subcommand")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["intel"])
    check(
        "intel returns 0 and prints the indicator count",
        rc == 0 and "indicators loaded:" in buf.getvalue(),
        f"rc={rc} stdout={buf.getvalue()!r}",
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["hunts"])
    check(
        "hunts returns 0 and lists the registered library",
        rc == 0 and "registered hunts:" in buf.getvalue(),
        f"rc={rc} stdout={buf.getvalue()!r}",
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["metrics"])
    check(
        "metrics returns 0 and prints the snapshot",
        rc == 0 and "mttd_seconds:" in buf.getvalue(),
        f"rc={rc} stdout={buf.getvalue()!r}",
    )


def test_unknown_command_returns_nonzero() -> None:
    print("\n[cli] an unknown command returns a non-zero exit code")
    buf = io.StringIO()
    sys.stderr = buf  # argparse writes help to stderr on error
    try:
        rc = main(["not_a_subcommand"])
    finally:
        sys.stderr = sys.__stderr__
    check(
        "an unknown command returns 2",
        rc == 2,
        f"rc={rc}",
    )


def test_regression_command_runs() -> None:
    print("\n[cli] the regression subcommand runs the harness")
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        baseline = Path(tmp) / "baseline.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["regression", "--baseline", str(baseline)])
        check(
            "regression returns 0 on a passing run and prints the verdict",
            rc == 0 and "passed:" in buf.getvalue(),
            f"rc={rc} stdout={buf.getvalue()!r}",
        )


def test_regression_reset_flag() -> None:
    print("\n[cli] the regression subcommand supports --reset")
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        baseline = Path(tmp) / "baseline.json"
        baseline.write_text("{}", encoding="utf-8")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["regression", "--baseline", str(baseline), "--reset"])
        check(
            "--reset clears the baseline file",
            not baseline.exists(),
            f"rc={rc} exists={baseline.exists()}",
        )


def test_cases_command() -> None:
    print("\n[cli] the cases subcommand handles an empty store")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["cases"])
    check(
        "cases returns 0 and reports no cases on an empty store",
        rc == 0 and "no cases in the store" in buf.getvalue(),
        f"rc={rc} stdout={buf.getvalue()!r}",
    )


def test_crises_command() -> None:
    print("\n[cli] the crises subcommand handles an empty board")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["crises"])
    check(
        "crises returns 0 and reports no active crises",
        rc == 0 and "no active crises" in buf.getvalue(),
        f"rc={rc} stdout={buf.getvalue()!r}",
    )


def test_coverage_command() -> None:
    print("\n[cli] the coverage subcommand prints the matrix")
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["coverage"])
    check(
        "coverage returns 0 and prints at least one function",
        rc == 0 and "function" in buf.getvalue()
        and "scenarios" in buf.getvalue(),
        f"rc={rc}",
    )


# ── decorator ─────────────────────────────────────────────────────────────


def test_decorator_registers_command() -> None:
    print("\n[cli] the @command decorator registers a runner")

    @command(name="phase9_temp_test", help="a temporary test command")
    def _runner(args: argparse.Namespace) -> int:
        print("hello from temp")
        return 0

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["phase9_temp_test"])
    check(
        "the decorator-registered command runs and prints",
        rc == 0 and "hello from temp" in buf.getvalue(),
        f"rc={rc}",
    )
    # Clean up: the registry is module-level state.
    from socctl.cli import _REGISTRY
    _REGISTRY.pop("phase9_temp_test", None)


# ── entry ──────────────────────────────────────────────────────────────────


def main_test() -> int:
    test_registered_commands()
    test_main_dispatches()
    test_unknown_command_returns_nonzero()
    test_regression_command_runs()
    test_regression_reset_flag()
    test_cases_command()
    test_crises_command()
    test_coverage_command()
    test_decorator_registers_command()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main_test())

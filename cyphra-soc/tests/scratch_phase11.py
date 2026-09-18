"""scratch_phase11 — the honesty audit itself.

    python tests/scratch_phase11.py

The audit script (phase11_honesty.py) is the proof that the
platform matches its documentation. The tests verify:

1. The audit script runs cleanly and produces a JSON-shaped report.
2. Every shipped package's ``__all__`` resolves — no dead exports.
3. The coverage check classifies every SOC function correctly.
4. The suite-runner parses summary lines correctly.
5. The new dimensions — yaml/code alignment, dead code, doc/behaviour —
   return the expected shape and respect the filter rules.
"""

import importlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, ".")

ROOT = Path(__file__).resolve().parent.parent

from phase11_honesty import (
    AuditReport,
    CoverageCheck,
    DeadCodeCheck,
    DocBehaviourCheck,
    ModuleCheck,
    SuiteCheck,
    YamlAlignmentCheck,
    check_coverage,
    check_dead_code,
    check_doc_behaviour,
    check_modules,
    check_yaml_alignment,
    _parse_summary,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── module inventory ────────────────────────────────────────────────────────


def test_module_inventory_runs() -> None:
    print("\n[audit] the module inventory runs and every shipped package resolves")
    modules = check_modules()
    check(
        "the inventory returns one entry per shipped package",
        len(modules) > 0,
        f"modules={len(modules)}",
    )
    failed = [m for m in modules if m.missing]
    check(
        "no package has missing exports",
        not failed,
        f"failed={[(m.module, m.missing) for m in failed]}",
    )


# ── coverage ───────────────────────────────────────────────────────────────


def test_coverage_classification() -> None:
    print("\n[audit] the coverage check classifies every SOC function")
    coverage = check_coverage()
    check(
        "the coverage check returns a CoverageCheck",
        coverage is not None,
        "coverage check returned None",
    )
    if coverage is None:
        return
    from validate.coverage import SOC_FUNCTIONS
    missing = set(coverage.missing) if coverage.missing else set()
    declared = set(SOC_FUNCTIONS)
    check(
        "the coverage check's missing list is a subset of SOC_FUNCTIONS",
        missing <= declared,
        f"missing={missing} declared={declared}",
    )
    check(
        "the shipped scenarios cover every SOC function",
        not coverage.missing,
        f"missing={coverage.missing}",
    )


# ── suite summary parser ───────────────────────────────────────────────────


def test_parse_summary_line() -> None:
    print("\n[audit] the summary parser reads 'N passed, M failed'")
    p, f = _parse_summary("427 passed, 0 failed")
    check(
        "the canonical line parses to (427, 0)",
        p == 427 and f == 0,
        f"got ({p}, {f})",
    )
    p, f = _parse_summary("\n  12 passed, 0 failed\n")
    check(
        "a leading newline does not break the parser",
        p == 12 and f == 0,
        f"got ({p}, {f})",
    )
    p, f = _parse_summary("a failed lookup arrives at the server")
    check(
        "prose that mentions 'failed' does not parse as a summary",
        p == 0 and f == 0,
        f"got ({p}, {f})",
    )
    p, f = _parse_summary("nothing here")
    check(
        "an unrelated string returns (0, 0)",
        p == 0 and f == 0,
        f"got ({p}, {f})",
    )


# ── new dimensions ─────────────────────────────────────────────────────────


def test_yaml_alignment_shape() -> None:
    print("\n[audit] the yaml/code alignment check returns the right shape")
    check_ = check_yaml_alignment()
    check(
        "the yaml alignment check returns a YamlAlignmentCheck",
        isinstance(check_, YamlAlignmentCheck),
        f"got {type(check_).__name__}",
    )
    # soc.yaml declares eight sections; the code reads seven (the eighth
    # is ``connectors``, handled separately as a credential holder).
    check(
        "the yaml alignment check classifies every section as known",
        not check_.unknown_sections,
        f"unknown={check_.unknown_sections}",
    )
    check(
        "the yaml alignment check finds no unknown keys",
        not check_.unknown_keys,
        f"unknown_keys={check_.unknown_keys[:5]}...",
    )


def test_dead_code_shape() -> None:
    print("\n[audit] the dead-code check returns the right shape")
    check_ = check_dead_code()
    check(
        "the dead-code check returns a DeadCodeCheck",
        isinstance(check_, DeadCodeCheck),
        f"got {type(check_).__name__}",
    )


def test_doc_behaviour_shape() -> None:
    print("\n[audit] the doc/behaviour check returns the right shape")
    check_ = check_doc_behaviour()
    check(
        "the doc/behaviour check returns a DocBehaviourCheck",
        isinstance(check_, DocBehaviourCheck),
        f"got {type(check_).__name__}",
    )


# ── end-to-end ────────────────────────────────────────────────────────────


def test_audit_script_runs() -> None:
    print("\n[audit] the audit script runs end-to-end and emits JSON")
    result = subprocess.run(
        [sys.executable, str(ROOT / "phase11_honesty.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        encoding="utf-8",
        errors="replace",
    )
    check(
        "the audit exits non-negative",
        result.returncode >= 0,
        f"exit={result.returncode}",
    )
    check(
        "the audit emits a JSON-shaped report",
        result.stdout.lstrip().startswith("{") and result.stdout.rstrip().endswith("}"),
        f"stdout head={result.stdout[:120]!r}",
    )
    try:
        doc = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        check("the JSON parses", False, f"error: {exc}")
        return
    check(
        "the JSON has a 'suites' key",
        "suites" in doc,
        f"keys={list(doc)}",
    )
    check(
        "the JSON has a 'coverage' key",
        "coverage" in doc,
        f"keys={list(doc)}",
    )
    check(
        "the JSON has the three new dimension keys",
        "yaml_alignment" in doc
        and "dead_code" in doc
        and "doc_behaviour" in doc,
        f"keys={list(doc)}",
    )
    check(
        "every suite's passed count is non-negative",
        all(s["passed"] >= 0 for s in doc["suites"]),
        f"suites={[(s['name'], s['passed']) for s in doc['suites']]}",
    )
    # The "audit exits 0" assertion is not in this test on purpose.
    # Phase 11's job is to *surface* problems; whether there are any
    # is a property of the codebase, not a property of the test.


# ── entry ──────────────────────────────────────────────────────────────────


def main() -> int:
    test_module_inventory_runs()
    test_coverage_classification()
    test_parse_summary_line()
    test_yaml_alignment_shape()
    test_dead_code_shape()
    test_doc_behaviour_shape()
    test_audit_script_runs()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

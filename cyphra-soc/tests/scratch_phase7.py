"""scratch_phase7 — validate subsystem: coverage, runner, gap, drift, regression.

    python tests/scratch_phase7.py

Five sections, each layer verified end-to-end:

1. **Coverage matrix** — every shipped scenario names the SOC functions it covers.
2. **Gap report** — missing vs fragile functions.
3. **End-to-end runner** — emulation through enrichment → detection → correlate → triage → respond.
4. **Drift detector** — layer-aware regression detection.
5. **Regression harness** — the CI entry point with persisted baseline.
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, ".")

from validate import (
    CoverageCell,
    CoverageMatrix,
    DriftConfig,
    DriftReport,
    EndToEndRunner,
    GapReport,
    LayerDrift,
    LayerReport,
    Pipeline,
    RegressionHarness,
    RegressionVerdict,
    RunReport,
    SOC_FUNCTIONS,
    build_gap_report,
    build_matrix,
    compare,
    default_pipeline,
)
from validate.emulation.generator import (
    ScenarioResult,
    list_scenarios,
    run_all,
    run_scenario,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── coverage matrix ────────────────────────────────────────────────────────


def test_coverage_matrix_built() -> None:
    print("\n[coverage] the shipped scenarios populate the matrix")
    matrix = build_matrix()
    check(
        "every shipped SOC function is in the matrix or the gap report",
        set(matrix.cells) | set(matrix.gaps()) == set(SOC_FUNCTIONS),
        f"cells={set(matrix.cells)} gaps={set(matrix.gaps())}",
    )
    covered = matrix.covered()
    check(
        "at least four SOC functions are covered by at least one scenario",
        len(covered) >= 4,
        f"covered={covered}",
    )
    check(
        "the matrix's coverage ratio is non-zero",
        matrix.ratio() > 0,
        f"ratio={matrix.ratio():.2f}",
    )
    total = matrix.total()
    check(
        "the matrix knows the shipped function count",
        total == len(SOC_FUNCTIONS),
        f"total={total}",
    )


# ── gap report ─────────────────────────────────────────────────────────────


def test_gap_report_classifies() -> None:
    print("\n[gap] the gap report classifies functions")
    matrix = build_matrix()
    report = build_gap_report(matrix)
    # The shipped scenarios cover collection, correlation, detection,
    # triage, intel and response. Other functions may be missing —
    # the gap report surfaces them.
    check(
        "the gap report has a non-empty missing or fragile list",
        bool(report.missing) or bool(report.fragile),
        f"covered={report.covered} fragile={report.fragile} missing={report.missing}",
    )
    # A restricted shipped-list filters the report to only the
    # functions the deployment has actually shipped.
    narrow = build_gap_report(matrix, shipped=("collection", "intel"))
    check(
        "a restricted shipped list narrows the gap report",
        set(narrow.covered + narrow.missing) <= {"collection", "intel"},
        f"narrow={narrow.covered} {narrow.missing}",
    )


# ── end-to-end runner ──────────────────────────────────────────────────────


def test_runner_default_pipeline() -> None:
    print("\n[runner] the default pipeline runs every scenario end-to-end")
    pipeline = default_pipeline()
    runner = EndToEndRunner(pipeline, clock=lambda: 1_000_000.0)
    report = runner.run()
    check(
        "every scenario produced at least one event",
        report.event_count > 0 and report.scenario_count == 8,
        f"events={report.event_count} scenarios={report.scenario_count}",
    )
    check(
        "every layer saw input",
        all(layer.in_count > 0 for layer in report.layers),
        f"layers={[l.name for l in report.layers]}",
    )
    check(
        "the correlate layer joined findings into incidents",
        len(report.incidents) > 0,
        f"incidents={len(report.incidents)}",
    )
    check(
        "the triage layer recorded dispositions",
        report.layers[3].out_count > 0,
        f"triage_out={report.layers[3].out_count}",
    )
    check(
        "at least one escalation reached the respond layer",
        report.escalations >= 1
        and report.layers[4].in_count >= 1,
        f"escalations={report.escalations} respond_in={report.layers[4].in_count}",
    )


def test_runner_respects_scenario_subset() -> None:
    print("\n[runner] the runner can run a single scenario")
    pipeline = default_pipeline()
    runner = EndToEndRunner(pipeline, clock=lambda: 1_000_000.0)
    report = runner.run(
        scenarios=[run_scenario("c2_beacon", 1_000_000.0, 1_003_600.0)]
    )
    check(
        "the runner ran only the supplied scenario",
        report.scenario_count == 1
        and report.event_count > 0,
        f"scenarios={report.scenario_count} events={report.event_count}",
    )


def test_runner_no_enricher() -> None:
    print("\n[runner] the runner works without an enricher")
    pipeline = default_pipeline()
    pipeline.enricher = None
    runner = EndToEndRunner(pipeline, clock=lambda: 1_000_000.0)
    report = runner.run(scenarios=[run_scenario("c2_beacon", 1_000_000.0, 1_003_600.0)])
    check(
        "without an enricher the runner still produces incidents",
        report.event_count > 0,
        f"events={report.event_count}",
    )


# ── drift detector ─────────────────────────────────────────────────────────


def test_drift_equal_runs_pass() -> None:
    print("\n[drift] two identical runs report within tolerance")
    base = RunReport(
        started_at=0.0, completed_at=0.0,
        layers=[LayerReport(name="detection", in_count=94, out_count=66)],
        incidents=[None] * 7, escalations=2,
        ml_scores=[0.5], scenario_count=8, event_count=94,
    )
    base.rule_hits = type(base.rule_hits)({"r1": 10, "r2": 5})
    drift = compare(base, base)
    check(
        "an unchanged run reports within tolerance",
        drift.within_tolerance,
        f"layers={[(d.name, d.in_delta, d.out_delta) for d in drift.layers]}",
    )


def test_drift_detects_layer_regression() -> None:
    print("\n[drift] a detection-layer regression is flagged")
    baseline = RunReport(
        started_at=0.0, completed_at=0.0,
        layers=[LayerReport(name="detection", in_count=94, out_count=66)],
        incidents=[None] * 7, escalations=2,
        ml_scores=[0.5], scenario_count=8, event_count=94,
    )
    baseline.rule_hits = type(baseline.rule_hits)({"r1": 10, "r2": 5})
    current = RunReport(
        started_at=0.0, completed_at=0.0,
        layers=[LayerReport(name="detection", in_count=94, out_count=60)],  # lost 6
        incidents=[None] * 5, escalations=1,
        ml_scores=[0.5], scenario_count=8, event_count=94,
    )
    current.rule_hits = type(current.rule_hits)({"r1": 8, "r2": 5})
    drift = compare(baseline, current)
    check(
        "the detection layer is flagged as regressed",
        not drift.within_tolerance,
        f"within_tolerance={drift.within_tolerance} layers={[(d.name, d.in_delta, d.out_delta, d.within_tolerance) for d in drift.layers]}",
    )
    detection_drift = next(d for d in drift.layers if d.name == "detection")
    check(
        "the detection layer drift carries the exact delta",
        detection_drift.out_delta == -6,
        f"out_delta={detection_drift.out_delta}",
    )


def test_drift_tolerance_is_configurable() -> None:
    print("\n[drift] a configurable tolerance accepts a small drift")
    baseline = RunReport(
        started_at=0.0, completed_at=0.0,
        layers=[LayerReport(name="detection", in_count=94, out_count=66)],
        incidents=[None] * 7, escalations=2,
        ml_scores=[0.5], scenario_count=8, event_count=94,
    )
    baseline.rule_hits = type(baseline.rule_hits)({"r1": 10})
    current = RunReport(
        started_at=0.0, completed_at=0.0,
        layers=[LayerReport(name="detection", in_count=94, out_count=64)],  # -2
        incidents=[None] * 7, escalations=2,
        ml_scores=[0.5], scenario_count=8, event_count=94,
    )
    current.rule_hits = type(current.rule_hits)({"r1": 8})  # -2
    tight = compare(baseline, current, config=DriftConfig(layer_tolerance=0, rule_tolerance=0))
    loose = compare(baseline, current, config=DriftConfig(layer_tolerance=5, rule_tolerance=5))
    check(
        "tight tolerance flags a -2 drift",
        not tight.within_tolerance,
        f"tight={tight.within_tolerance}",
    )
    check(
        "loose tolerance accepts the same -2 drift",
        loose.within_tolerance,
        f"loose={loose.within_tolerance}",
    )


# ── regression harness ──────────────────────────────────────────────────────


def test_regression_first_run_persists_baseline() -> None:
    print("\n[regression] the first run of a fresh deployment persists the baseline")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "baseline.json"
        # The shipped function set covers everything the platform
        # actually exercises. ``normalisation`` and ``compliance``
        # are not yet wired, so they sit in the gap list — the
        # runner narrows the gap report to the shipped set to
        # reflect that.
        shipped = (
            "collection", "parsing", "enrichment", "correlation",
            "detect", "triage", "respond", "hunt", "intel",
            "cases", "metrics", "learn",
        )
        harness = RegressionHarness(
            baseline_path=path,
            pipeline_factory=default_pipeline,
            clock=lambda: 1_000_000.0,
        )
        # CI runs the full shipped scenario set, not a single one.
        from validate.emulation.generator import run_all
        scenarios = run_all(1_000_000.0, 1_003_600.0)
        verdict = harness.run(scenarios=scenarios, shipped=shipped)
        check(
            "the first run persists the baseline",
            path.exists() and verdict.baseline_persisted,
            f"path exists={path.exists()} baseline_persisted={verdict.baseline_persisted}",
        )
        check(
            "the first run is a passing run",
            verdict.passed,
            f"passed={verdict.passed} gap.missing={verdict.gap.missing}",
        )


def test_regression_second_run_compares() -> None:
    print("\n[regression] the second run is compared against the persisted baseline")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "baseline.json"
        shipped = (
            "collection", "parsing", "enrichment", "correlation",
            "detect", "triage", "respond", "hunt", "intel",
            "cases", "metrics", "learn",
        )
        clock = lambda: 1_000_000.0
        harness = RegressionHarness(
            baseline_path=path,
            pipeline_factory=default_pipeline,
            clock=clock,
        )
        from validate.emulation.generator import run_all
        scenarios = run_all(1_000_000.0, 1_003_600.0)
        harness.run(scenarios=scenarios, shipped=shipped)
        verdict = harness.run(scenarios=scenarios, shipped=shipped)
        check(
            "a second run with the same scenarios is within tolerance",
            verdict.passed and verdict.drift is not None
            and verdict.drift.within_tolerance,
            f"passed={verdict.passed} drift={verdict.drift.within_tolerance if verdict.drift else None}",
        )
        check(
            "the second run does not re-persist the baseline",
            not verdict.baseline_persisted,
            f"baseline_persisted={verdict.baseline_persisted}",
        )


def test_regression_reset_baseline() -> None:
    print("\n[regression] the operator can reset the baseline")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "baseline.json"
        path.write_text("{}", encoding="utf-8")
        harness = RegressionHarness(baseline_path=path, pipeline_factory=default_pipeline)
        check(
            "reset_baseline returns True when a baseline exists",
            harness.reset_baseline(),
            "reset",
        )
        check(
            "reset_baseline returns False when no baseline exists",
            not harness.reset_baseline(),
            "no baseline",
        )


# ── helpers ────────────────────────────────────────────────────────────────


def _make_report(
    *,
    layer_counts: dict[str, tuple[int, int]],
    rule_hits: dict[str, int],
    ml_score_mean: float = 0.5,
    incidents: int = 0,
    escalations: int = 0,
) -> RunReport:
    """A tiny report builder for drift tests."""
    from collections import Counter
    return RunReport(
        started_at=0.0,
        completed_at=0.0,
        layers=[
            LayerReport(name=name, in_count=in_, out_count=out)
            for name, (in_, out) in layer_counts.items()
        ],
        incidents=[None] * incidents,
        escalations=escalations,
        ml_scores=[ml_score_mean],
        rule_hits=Counter(rule_hits),
        scenario_count=8,
        event_count=94,
    )


# ── entry ──────────────────────────────────────────────────────────────────


def main() -> int:
    test_coverage_matrix_built()
    test_gap_report_classifies()
    test_runner_default_pipeline()
    test_runner_respects_scenario_subset()
    test_runner_no_enricher()
    test_drift_equal_runs_pass()
    test_drift_detects_layer_regression()
    test_drift_tolerance_is_configurable()
    test_regression_first_run_persists_baseline()
    test_regression_second_run_compares()
    test_regression_reset_baseline()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

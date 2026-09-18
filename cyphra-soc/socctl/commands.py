"""socctl subcommands — the operator's view of every layer.

Each subcommand is a registered :func:`socctl.cli.command` callable
that prints to ``stdout`` and returns an integer exit code. The
functions are *thin*: they import the platform's modules and format
their output. The output is plain text — pipeable, greppable, and
stable across releases.

Adding a subcommand:

1. Decorate a function with ``@command(name="...", help="...", setup=...)``.
2. The function receives the parsed ``argparse.Namespace`` and
   returns an integer exit code.
3. The subcommand is automatically registered with the top-level
   parser on import.

The shipped subcommands cover every platform layer: readiness,
metrics, cases, crises, hunts, regression, coverage, intel.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from socctl.cli import command


def _print(text: str) -> None:
    """Write to stdout without buffering surprises."""
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def _load_config() -> Any:
    """Load the platform config. Failures print and exit non-zero."""
    try:
        from core.config import load
        return load()
    except Exception as exc:  # noqa: BLE001
        _print(f"socctl: failed to load config: {exc!r}")
        raise SystemExit(2)


# ── readiness ───────────────────────────────────────────────────────────────


@command(
    name="readiness",
    help="Print the platform readiness report — every credential and grant.",
    setup=lambda p: p.add_argument(
        "--json", action="store_true",
        help="also print the full report as JSON",
    ),
)
def _readiness(args: argparse.Namespace) -> int:
    config = _load_config()
    creds = config.credentials()
    configured = [c for c in creds if c.configured]
    unset = [c for c in creds if not c.configured]
    _print(f"credentials: {len(creds)} total, {len(configured)} configured, {len(unset)} unset")
    if unset:
        _print("\nawaiting credentials:")
        for c in unset:
            _print(f"  - {c.name:<48} (${c.env_var})")
    if args.json:
        _print("\n" + json.dumps(
            {
                "credentials": {
                    "configured": [c.name for c in configured],
                    "unset": [c.name for c in unset],
                },
                "config_path": str(config.config_path) if config.config_path else None,
            },
            indent=2,
        ))
    return 0


# ── metrics ────────────────────────────────────────────────────────────────


@command(
    name="metrics",
    help="Print the metrics tracker snapshot.",
)
def _metrics(args: argparse.Namespace) -> int:
    from metrics import MetricsTracker

    tracker = MetricsTracker()
    report = tracker.sample()
    _print(f"alert_volume:        {report.alert_volume}")
    _print(f"incident_count:     {report.incident_count}")
    _print(f"mttd_seconds:        {report.mttd_seconds:.3f}")
    _print(f"mttr_seconds:        {report.mttr_seconds:.3f}")
    _print(f"false_positive_rate: {report.false_positive_rate:.3f}")
    _print(f"true_positive_rate:  {report.true_positive_rate:.3f}")
    _print(f"escalation_rate:     {report.escalation_rate:.3f}")
    if report.verdict_counts:
        _print("\nverdict_counts:")
        for label, count in sorted(report.verdict_counts.items()):
            _print(f"  - {label}: {count}")
    return 0


# ── cases ─────────────────────────────────────────────────────────────────


@command(
    name="cases",
    help="List every case in the case store.",
    setup=lambda p: p.add_argument(
        "--all", action="store_true",
        help="include closed and archived cases",
    ),
)
def _cases(args: argparse.Namespace) -> int:
    from cases import CaseStore, STATUS_NAMES

    store = CaseStore()
    cases = store.list_open() if not args.all else (
        store.list_open()
        + store.list_by_status(5)
        + store.list_by_status(6)
    )
    if not cases:
        _print("no cases in the store")
        return 0
    _print(f"{'uid':<16}  {'status':<22}  {'severity':<10}  title")
    for case in cases:
        _print(
            f"{case.uid:<16}  "
            f"{STATUS_NAMES.get(case.status, '?'):<22}  "
            f"{case.severity_id:<10}  "
            f"{case.title[:60]}"
        )
    return 0


# ── crises ────────────────────────────────────────────────────────────────


@command(
    name="crises",
    help="List every active crisis.",
    setup=lambda p: p.add_argument(
        "--all", action="store_true",
        help="include contained and closed crises",
    ),
)
def _crises(args: argparse.Namespace) -> int:
    from cases import CaseStore
    from crisis import CRISIS_STATUS_NAMES, CrisisManager
    from respond import PlaybookDispatcher

    manager = CrisisManager(CaseStore(), PlaybookDispatcher())
    crises = manager.list_active() if not args.all else manager.list_all()
    if not crises:
        _print("no active crises")
        return 0
    _print(f"{'uid':<16}  {'status':<12}  name")
    for crisis in crises:
        _print(
            f"{crisis.uid:<16}  "
            f"{CRISIS_STATUS_NAMES.get(crisis.status, '?'):<12}  "
            f"{crisis.name}"
        )
    return 0


# ── hunts ─────────────────────────────────────────────────────────────────


@command(
    name="hunts",
    help="List the hunt library and the runner's stats.",
    setup=lambda p: p.add_argument(
        "--run", action="store_true",
        help="also run each hunt against an empty stream",
    ),
)
def _hunts(args: argparse.Namespace) -> int:
    from hunt import HuntRunner, default_hunt_library

    runner = HuntRunner()
    for hunt in default_hunt_library():
        runner.add(hunt)
    lib = runner.list_hunts()
    _print(f"registered hunts: {len(lib)}")
    for hunt_name in lib:
        hunt = runner.get(hunt_name)
        if hunt is None:
            continue
        _print(
            f"  - {hunt.name:<40}  window={hunt.window:<6}  "
            f"predicates={len(hunt.predicates)}"
        )
    if args.run:
        for hunt_name in lib:
            hunt = runner.get(hunt_name)
            if hunt is None:
                continue
            result = runner.run(hunt, [])
            _print(f"\n{hunt.name}: hits={result.hit_count}")
    return 0


# ── regression ────────────────────────────────────────────────────────────


@command(
    name="regression",
    help="Run the regression harness; print the verdict and persist the baseline.",
    setup=lambda p: (
        p.add_argument(
            "--baseline", default="baseline.json",
            help="path to the persisted baseline (default: baseline.json)",
        ),
        p.add_argument(
            "--reset", action="store_true",
            help="reset the persisted baseline after the run",
        ),
    ),
)
def _regression(args: argparse.Namespace) -> int:
    from validate import RegressionHarness, default_pipeline
    from validate.emulation.generator import run_all

    baseline_path = Path(args.baseline).expanduser()
    harness = RegressionHarness(
        baseline_path=baseline_path,
        pipeline_factory=default_pipeline,
    )
    verdict = harness.run(
        scenarios=run_all(0.0, 3600.0),
        shipped=("collection", "parsing", "enrichment", "correlation",
                 "detect", "triage", "respond", "hunt", "intel",
                 "cases", "metrics", "learn"),
    )
    _print(f"passed:              {verdict.passed}")
    _print(f"events:               {verdict.run.event_count}")
    _print(f"incidents:            {len(verdict.run.incidents)}")
    _print(f"escalations:          {verdict.run.escalations}")
    if verdict.drift is not None:
        _print(f"drift.within_tolerance: {verdict.drift.within_tolerance}")
    if verdict.gap.missing:
        _print("missing functions:")
        for fn in verdict.gap.missing:
            _print(f"  - {fn}")
    if args.reset:
        harness.reset_baseline()
        _print("baseline reset")
    return 0 if verdict.passed else 1


# ── coverage ─────────────────────────────────────────────────────────────


@command(
    name="coverage",
    help="Print the coverage matrix — every SOC function and the scenarios covering it.",
)
def _coverage(args: argparse.Namespace) -> int:
    from validate import build_gap_report, build_matrix

    matrix = build_matrix()
    _print(f"{'function':<22}  {'count':<6}  scenarios")
    for function in sorted(matrix.cells):
        cell = matrix.cells[function]
        _print(
            f"{function:<22}  {cell.scenario_count:<6}  "
            f"{', '.join(cell.scenario_names)}"
        )
    gap = build_gap_report(matrix)
    if gap.missing:
        _print("\nmissing functions:")
        for fn in gap.missing:
            _print(f"  - {fn}")
    return 0


# ── intel ─────────────────────────────────────────────────────────────────


@command(
    name="intel",
    help="Print intel-store stats: indicator counts and source breakdown.",
)
def _intel(args: argparse.Namespace) -> int:
    from intel import IntelStore

    store = IntelStore()
    _print(f"indicators loaded: {len(store)}")
    sources = store.sources()
    if sources:
        _print("\nby source:")
        for source, count in sorted(sources.items()):
            _print(f"  - {source}: {count}")
    return 0

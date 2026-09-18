"""socctl subcommands — the operator's view of every layer.

Each subcommand is a registered :func:`socctl.cli.command` callable
that prints to ``stdout`` and returns an integer exit code. Every
subcommand accepts a ``--json`` flag that emits machine-readable
JSON instead of the formatted text output — the SOC backend
shells out to these subcommands and parses the JSON.

The functions are *thin*: they import the platform's modules and
format their output. The output is plain text — pipeable,
greppable, and stable across releases.

Adding a subcommand:

1. Decorate a function with ``@command(name="...", help="...", setup=...)``.
2. The function receives the parsed ``argparse.Namespace`` and
   returns an integer exit code.
3. Build a ``payload`` dict (always) and a ``text`` string (always),
   then call :func:`_emit(args, text, payload)` to write whichever
   shape ``args.json`` requested.

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


def _emit(args: argparse.Namespace, text: str, payload: dict[str, Any]) -> None:
    """Either print the human-readable text or the machine JSON.

    A single helper so every subcommand gets consistent JSON output
    without each one carrying its own ``if args.json`` branch.
    """
    if getattr(args, "json", False):
        _print(json.dumps(payload, default=str))
    else:
        _print(text)


def _load_config() -> Any:
    """Load the platform config. Failures print and exit non-zero."""
    try:
        from core.config import load
        return load()
    except Exception as exc:  # noqa: BLE001
        _print(f"socctl: failed to load config: {exc!r}")
        raise SystemExit(2)


def _json_flag(p: argparse.ArgumentParser) -> None:
    """Add the standard ``--json`` flag to a subcommand."""
    p.add_argument(
        "--json", dest="json", action="store_true",
        help="emit machine-readable JSON instead of formatted text",
    )


# ── readiness ───────────────────────────────────────────────────────────────


@command(
    name="readiness",
    help="Print the platform readiness report — every credential and grant.",
    setup=_json_flag,
)
def _readiness(args: argparse.Namespace) -> int:
    config = _load_config()
    creds = config.credentials()
    configured = [c for c in creds if c.configured]
    unset = [c for c in creds if not c.configured]
    text = (
        f"credentials: {len(creds)} total, {len(configured)} configured, "
        f"{len(unset)} unset\n"
    )
    if unset:
        text += "\nawaiting credentials:\n"
        for c in unset:
            text += f"  - {c.name:<48} (${c.env_var})\n"
    payload = {
        "total": len(creds),
        "configured": [c.name for c in configured],
        "unset": [
            {"name": c.name, "env_var": c.env_var, "purpose": c.purpose}
            for c in unset
        ],
        "config_path": str(config.config_path) if config.config_path else None,
    }
    _emit(args, text, payload)
    return 0


# ── metrics ────────────────────────────────────────────────────────────────


@command(
    name="metrics",
    help="Print the metrics tracker snapshot.",
    setup=_json_flag,
)
def _metrics(args: argparse.Namespace) -> int:
    from metrics import MetricsTracker

    tracker = MetricsTracker()
    report = tracker.sample()
    text = (
        f"alert_volume:        {report.alert_volume}\n"
        f"incident_count:     {report.incident_count}\n"
        f"mttd_seconds:        {report.mttd_seconds:.3f}\n"
        f"mttr_seconds:        {report.mttr_seconds:.3f}\n"
        f"false_positive_rate: {report.false_positive_rate:.3f}\n"
        f"true_positive_rate:  {report.true_positive_rate:.3f}\n"
        f"escalation_rate:     {report.escalation_rate:.3f}\n"
    )
    if report.verdict_counts:
        text += "\nverdict_counts:\n"
        for label, count in sorted(report.verdict_counts.items()):
            text += f"  - {label}: {count}\n"
    payload = {
        "alert_volume": report.alert_volume,
        "incident_count": report.incident_count,
        "mttd_seconds": report.mttd_seconds,
        "mttr_seconds": report.mttr_seconds,
        "false_positive_rate": report.false_positive_rate,
        "true_positive_rate": report.true_positive_rate,
        "escalation_rate": report.escalation_rate,
        "verdict_counts": dict(report.verdict_counts),
    }
    _emit(args, text, payload)
    return 0


# ── cases ─────────────────────────────────────────────────────────────────


@command(
    name="cases",
    help="List every case in the case store.",
    setup=lambda p: (
        p.add_argument(
            "--all", action="store_true",
            help="include closed and archived cases",
        ),
        _json_flag(p),
    ),
)
def _cases(args: argparse.Namespace) -> int:
    from cases import CaseStore, STATUS_NAMES

    store = CaseStore()
    if args.all:
        cases = (
            list(store.list_open())
            + list(store.list_by_status(5))
            + list(store.list_by_status(6))
        )
    else:
        cases = list(store.list_open())

    if not cases:
        _emit(args, "no cases in the store", {"cases": []})
        return 0

    text = f"{'uid':<16}  {'status':<22}  {'severity':<10}  title\n"
    for case in cases:
        text += (
            f"{case.uid:<16}  "
            f"{STATUS_NAMES.get(case.status, '?'):<22}  "
            f"{case.severity_id:<10}  "
            f"{case.title[:60]}\n"
        )
    payload = {
        "cases": [
            {
                "uid": case.uid,
                "status": STATUS_NAMES.get(case.status, "?"),
                "status_id": case.status,
                "severity_id": case.severity_id,
                "title": case.title,
                "summary": case.summary,
                "attack_ids": list(case.attack_ids),
                "actor_keys": list(case.actor_keys),
                "target_keys": list(case.target_keys),
                "source_incident_uid": case.source_incident_uid,
                "opened_at": case.opened_at,
                "updated_at": case.updated_at,
            }
            for case in cases
        ]
    }
    _emit(args, text, payload)
    return 0


# ── crises ────────────────────────────────────────────────────────────────


@command(
    name="crises",
    help="List every active crisis.",
    setup=lambda p: (
        p.add_argument(
            "--all", action="store_true",
            help="include contained and closed crises",
        ),
        _json_flag(p),
    ),
)
def _crises(args: argparse.Namespace) -> int:
    from cases import CaseStore
    from crisis import CRISIS_STATUS_NAMES, CrisisManager
    from respond import PlaybookDispatcher

    manager = CrisisManager(CaseStore(), PlaybookDispatcher())
    crises = list(manager.list_active() if not args.all else manager.list_all())
    if not crises:
        _emit(args, "no active crises", {"crises": []})
        return 0

    text = f"{'uid':<16}  {'status':<12}  name\n"
    for crisis in crises:
        text += (
            f"{crisis.uid:<16}  "
            f"{CRISIS_STATUS_NAMES.get(crisis.status, '?'):<12}  "
            f"{crisis.name}\n"
        )
    payload = {
        "crises": [
            {
                "uid": crisis.uid,
                "status": CRISIS_STATUS_NAMES.get(crisis.status, "?"),
                "status_id": crisis.status,
                "name": crisis.name,
                "description": crisis.description,
                "case_uids": list(crisis.case_uids),
                "opened_at": crisis.opened_at,
                "playbook_ids": list(crisis.playbook_ids),
            }
            for crisis in crises
        ]
    }
    _emit(args, text, payload)
    return 0


# ── hunts ─────────────────────────────────────────────────────────────────


@command(
    name="hunts",
    help="List the hunt library and the runner's stats.",
    setup=lambda p: (
        p.add_argument(
            "--run", action="store_true",
            help="also run each hunt against an empty stream",
        ),
        _json_flag(p),
    ),
)
def _hunts(args: argparse.Namespace) -> int:
    from hunt import HuntRunner, default_hunt_library

    runner = HuntRunner()
    for hunt in default_hunt_library():
        runner.add(hunt)
    lib = list(runner.list_hunts())
    results_payload = []
    text = f"registered hunts: {len(lib)}\n"
    for hunt_name in lib:
        hunt = runner.get(hunt_name)
        if hunt is None:
            continue
        text += (
            f"  - {hunt.name:<40}  window={hunt.window:<6}  "
            f"predicates={len(hunt.predicates)}\n"
        )
        if args.run:
            result = runner.run(hunt, [])
            text += f"\n{hunt.name}: hits={result.hit_count}\n"
            results_payload.append({
                "name": hunt.name,
                "hit_count": result.hit_count,
                "ran": True,
            })
    payload = {
        "registered": [
            {
                "name": hunt.name,
                "window": hunt.window,
                "predicate_count": len(hunt.predicates),
            }
            for hunt_name in lib
            for hunt in [runner.get(hunt_name)]
            if hunt is not None
        ],
        "runs": results_payload,
    }
    _emit(args, text, payload)
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
        _json_flag(p),
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
    text = (
        f"passed:              {verdict.passed}\n"
        f"events:               {verdict.run.event_count}\n"
        f"incidents:            {len(verdict.run.incidents)}\n"
        f"escalations:          {verdict.run.escalations}\n"
    )
    if verdict.drift is not None:
        text += f"drift.within_tolerance: {verdict.drift.within_tolerance}\n"
    if verdict.gap.missing:
        text += "\nmissing functions:\n"
        for fn in verdict.gap.missing:
            text += f"  - {fn}\n"
    if args.reset:
        harness.reset_baseline()
        text += "baseline reset\n"
    payload = {
        "passed": verdict.passed,
        "events": verdict.run.event_count,
        "incidents": len(verdict.run.incidents),
        "escalations": verdict.run.escalations,
        "drift_within_tolerance": (
            verdict.drift.within_tolerance if verdict.drift is not None else None
        ),
        "missing_functions": list(verdict.gap.missing),
        "baseline_reset": args.reset,
    }
    _emit(args, text, payload)
    return 0 if verdict.passed else 1


# ── coverage ─────────────────────────────────────────────────────────────


@command(
    name="coverage",
    help="Print the coverage matrix — every SOC function and the scenarios covering it.",
    setup=_json_flag,
)
def _coverage(args: argparse.Namespace) -> int:
    from validate import build_gap_report, build_matrix

    matrix = build_matrix()
    rows = []
    for function in sorted(matrix.cells):
        cell = matrix.cells[function]
        rows.append({
            "function": function,
            "count": cell.scenario_count,
            "scenarios": list(cell.scenario_names),
        })
    text = f"{'function':<22}  {'count':<6}  scenarios\n"
    for row in rows:
        text += (
            f"{row['function']:<22}  {row['count']:<6}  "
            f"{', '.join(row['scenarios'])}\n"
        )
    gap = build_gap_report(matrix)
    if gap.missing:
        text += "\nmissing functions:\n"
        for fn in gap.missing:
            text += f"  - {fn}\n"
    payload = {
        "rows": rows,
        "missing": list(gap.missing),
        "fragile": list(gap.fragile),
    }
    _emit(args, text, payload)
    return 0


# ── intel ─────────────────────────────────────────────────────────────────


@command(
    name="intel",
    help="Print intel-store stats: indicator counts and source breakdown.",
    setup=_json_flag,
)
def _intel(args: argparse.Namespace) -> int:
    from intel import IntelStore

    store = IntelStore()
    sources = dict(store.sources())
    text = f"indicators loaded: {len(store)}\n"
    if sources:
        text += "\nby source:\n"
        for source, count in sorted(sources.items()):
            text += f"  - {source}: {count}\n"
    payload = {
        "indicators_loaded": len(store),
        "by_source": sources,
    }
    _emit(args, text, payload)
    return 0

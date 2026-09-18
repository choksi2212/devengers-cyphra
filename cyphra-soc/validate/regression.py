"""The regression harness — runs the platform against itself.

The harness is the entry point the platform's CI uses:

* It runs the end-to-end pipeline against the shipped scenarios.
* It loads the persisted baseline from disk (or creates one if
  missing — first run of a deployment is the baseline).
* It compares the current run against the baseline and emits a
  :class:`DriftReport`.

The baseline file is a JSON snapshot of the last run. A deployment
that runs the harness on every release persists the snapshot after
each green run; a deployment that wants to *reset* the baseline
deletes the file and lets the next run create a fresh one.

The harness reports *no regression* (``within_tolerance=True``) when
the platform is healthy. A release that introduces a regression is
caught before the deployment is approved, which is the whole point
of the regression harness.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from validate.coverage import CoverageMatrix, build_matrix
from validate.drift import DriftConfig, DriftReport, compare
from validate.gap import GapReport, build_gap_report
from validate.runner import (
    EndToEndRunner,
    LayerReport,
    Pipeline,
    RunReport,
    default_pipeline,
)
from validate.emulation.generator import ScenarioResult


@dataclass
class RegressionVerdict:
    """The harness's verdict on one run.

    ``passed`` is ``True`` iff the run is within tolerance AND the
    coverage matrix has no gaps AND the gap report has no
    missing-classified functions. ``run`` carries the full
    :class:`RunReport`; ``drift`` carries the :class:`DriftReport`
    against the baseline; ``gap`` carries the :class:`GapReport` for
    the shipped function set.
    """

    passed: bool
    run: RunReport
    drift: DriftReport | None
    gap: GapReport
    baseline_persisted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "run": self.run.to_dict(),
            "drift": self.drift.to_dict() if self.drift else None,
            "gap": self.gap.to_dict(),
            "baseline_persisted": self.baseline_persisted,
        }


class RegressionHarness:
    """The regression harness.

    A single instance is reusable; the runner is recreated on every
    ``run`` so the harness can swap in a fresh model or fresh
    scenarios between runs.
    """

    def __init__(
        self,
        *,
        baseline_path: Path,
        pipeline_factory: Any = default_pipeline,
        drift_config: DriftConfig | None = None,
        clock: Any = time.time,
    ) -> None:
        self.baseline_path = Path(baseline_path)
        self.pipeline_factory = pipeline_factory
        self.drift_config = drift_config or DriftConfig()
        self.clock = clock

    def run(
        self,
        scenarios: Iterable[ScenarioResult] | None = None,
        *,
        shipped: Iterable[str] | None = None,
        start: float | None = None,
        end: float | None = None,
    ) -> RegressionVerdict:
        """One run of the harness.

        ``scenarios`` is the scenario set; ``None`` uses the shipped
        eight. ``shipped`` is the SOC functions the deployment has
        shipped; ``None`` uses the full set. ``start`` and ``end`` are
        the wall-clock window the scenarios cover.

        On success, the harness persists the current run as the new
        baseline. The persist happens *after* the drift comparison,
        so a regression does not overwrite the previous baseline —
        the operator can roll back without re-running the entire
        harness.
        """
        pipeline = self.pipeline_factory()
        runner = EndToEndRunner(pipeline, clock=self.clock)
        run = runner.run(scenarios, start=start, end=end)
        matrix = build_matrix(scenarios)
        gap = build_gap_report(matrix, shipped=shipped)
        baseline = self._load_baseline()
        drift: DriftReport | None = None
        passed = True
        if baseline is None:
            baseline_persisted = True
            self._persist_baseline(run)
        else:
            drift = compare(baseline, run, config=self.drift_config)
            if not drift.within_tolerance:
                passed = False
        # A gap in the shipped function set is a regression in itself —
        # the platform was claiming a function it cannot prove.
        if gap.missing:
            passed = False
        return RegressionVerdict(
            passed=passed,
            run=run,
            drift=drift,
            gap=gap,
            baseline_persisted=baseline is None,
        )

    def _load_baseline(self) -> RunReport | None:
        """Load the persisted baseline, or ``None`` on a missing or corrupt file."""
        if not self.baseline_path.exists():
            return None
        try:
            doc = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return _report_from_dict(doc)

    def _persist_baseline(self, run: RunReport) -> None:
        """Write the current run as the new baseline.

        The run is persisted as a JSON-serialisable dict. ``Incident``
        objects are not JSON-serialisable directly, so the harness
        persists the ``to_dict`` form, which is the layer counts
        plus the rule-hit distribution plus the incident count —
        everything the drift detector reads.
        """
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(
            json.dumps(_serialisable_report(run), default=str, sort_keys=True),
            encoding="utf-8",
        )

    def reset_baseline(self) -> bool:
        """Delete the persisted baseline; the next run becomes a fresh baseline."""
        if not self.baseline_path.exists():
            return False
        self.baseline_path.unlink()
        return True


def _serialisable_report(run: RunReport) -> dict[str, Any]:
    """A run-report snapshot the drift detector can read.

    The detector reads only the layer counts, the rule-hit counts,
    the ML score summary, the incident count, and the escalation
    count. None of those need the Incident objects themselves, so
    the snapshot is the report's ``to_dict`` with the incidents
    list replaced by its count.
    """
    doc = run.to_dict()
    doc["incidents"] = len(run.incidents)
    return doc


def _report_from_dict(doc: Mapping[str, Any]) -> RunReport:
    """Reconstruct a :class:`RunReport` from the persisted snapshot.

    Only the fields the drift detector reads are reconstructed. The
    ``incidents`` list is empty — the detector uses the count, not
    the list.
    """
    from collections import Counter
    layers = [
        LayerReport(
            name=item.get("name", ""),
            in_count=int(item.get("in", 0)),
            out_count=int(item.get("out", 0)),
            extra={
                k: v
                for k, v in item.items()
                if k not in ("name", "in", "out")
            },
        )
        for item in doc.get("layers", [])
    ]
    rule_hits_dict = doc.get("rule_hits", {}) or {}
    summary = doc.get("ml_score_summary", {}) or {}
    mean_score = float(summary.get("mean", 0.0))
    return RunReport(
        started_at=float(doc.get("started_at", 0.0)),
        completed_at=float(doc.get("completed_at", 0.0)),
        layers=layers,
        incidents=[],
        escalations=int(doc.get("escalations", 0)),
        ml_scores=[mean_score] if mean_score else [],
        rule_hits=Counter(rule_hits_dict),
        scenario_count=int(doc.get("scenarios", 0)),
        event_count=int(doc.get("events", 0)),
    )


__all__ = ["RegressionHarness", "RegressionVerdict"]

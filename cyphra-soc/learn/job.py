"""Periodic retrain job — runs :mod:`learn.retrain` on a schedule.

The job is the platform's *automatic* counterpart to
:func:`learn.retrain.retrain_with_verdicts`. The retrain function
takes a list of verdicts and a payload map and produces a new
model. The job runs the same pipeline, but reads verdicts from the
:class:`VerdictStore` and payloads from a supplier the deployment
configures (typically the lake's audit-chain replay).

A deployment triggers the job on a schedule:

* Every ``N`` verdicts (the default).
* Every ``T`` seconds (a wall-clock cadence).
* On demand — the operator calls :meth:`RetrainJob.run_once` after
  a major change.

The job is *atomic* on the model swap: the old model serves traffic
until the new model is fully trained and evaluated, then a single
pointer is updated. A retrain that fails leaves the old model in
place.

The job's report — the same :class:`learn.retrain.RetrainReport`
the retrain function returns — is what the operator's dashboard
shows. The headline numbers (before/after precision and recall)
must be read; a "model improved" report with a recall drop is a
regression that needs more verdicts, not a successful retrain.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from learn.features import extract_features
from learn.label_audit import audit
from learn.model import Model
from learn.retrain import RetrainReport, retrain_with_verdicts
from learn.training_set import TrainingSet, from_verdicts
from learn.verdict import Verdict
from learn.verdict_store import VerdictStore


@dataclass
class RetrainJobStats:
    """The job's self-reported counters."""

    runs: int = 0
    successes: int = 0
    failures: int = 0
    last_run_at: float = 0.0
    last_report: RetrainReport | None = None
    last_error: str = ""


@dataclass
class RetrainJobConfig:
    """The job's runtime configuration."""

    min_verdicts: int = 10
    cooldown_seconds: float = 3600.0


class RetrainJob:
    """The periodic retrain job.

    A single instance owns one :class:`learn.model.Model` — the
    "current" model — and a :class:`VerdictStore` — the verdicts the
    retrain reads from. The model is swapped atomically when a
    retrain succeeds.

    ``payload_supplier`` is a callable the deployment injects to
    fetch the OCSF payloads the verdicts reference. A real
    deployment reads from the lake; the test path passes a static
    dict.
    """

    def __init__(
        self,
        *,
        current_model: Model,
        verdict_store: VerdictStore,
        payload_supplier: Callable[[Sequence[str]], dict[str, Mapping[str, Any]]],
        config: RetrainJobConfig | None = None,
        clock: Any = time.time,
    ) -> None:
        self.current_model = current_model
        self.verdict_store = verdict_store
        self.payload_supplier = payload_supplier
        self.config = config or RetrainJobConfig()
        self.clock = clock
        self.stats = RetrainJobStats()
        self._last_run_completed_at = 0.0

    @property
    def model(self) -> Model:
        """The current model — the one the detector uses."""
        return self.current_model

    def should_run(self) -> bool:
        """Whether a retrain should run *now*.

        Two gates: the verdict count has to be above the minimum,
        and the cooldown since the last run has to be elapsed.
        """
        verdict_count = self.verdict_store.count()
        if verdict_count < self.config.min_verdicts:
            return False
        if self.clock() - self._last_run_completed_at < self.config.cooldown_seconds:
            return False
        return True

    def run_once(self, *, split_ratio: float = 0.8) -> RetrainJobStats:
        """Run the retrain pipeline once.

        Reads every verdict from the store, asks the payload
        supplier for the original payloads, builds the training
        set, runs :func:`learn.retrain.retrain_with_verdicts`. On
        success the new model replaces the current one
        atomically.
        """
        verdicts = self.verdict_store.all()
        if not verdicts:
            self.stats.last_error = "no verdicts available"
            self.stats.runs += 1
            return self.stats
        alert_uids = list({v.alert_uid for v in verdicts})
        payloads = dict(self.payload_supplier(alert_uids))
        try:
            new_model, report = retrain_with_verdicts(
                self.current_model,
                verdicts,
                payloads,
                split_ratio=split_ratio,
            )
        except Exception as exc:  # noqa: BLE001
            self.stats.failures += 1
            self.stats.runs += 1
            self.stats.last_run_at = self.clock()
            self.stats.last_error = repr(exc)
            return self.stats
        self.stats.runs += 1
        self.stats.last_run_at = self.clock()
        self.stats.last_report = report
        if report.audit.total == 0:
            self.stats.last_error = "retrain had no verdicts"
            return self.stats
        # Atomic model swap — only if the retrain succeeded.
        self.current_model = new_model
        self._last_run_completed_at = self.clock()
        self.stats.successes += 1
        return self.stats

    def run_if_due(self, *, split_ratio: float = 0.8) -> RetrainJobStats:
        """Run a retrain only if :meth:`should_run` is ``True``."""
        if not self.should_run():
            return self.stats
        return self.run_once(split_ratio=split_ratio)


__all__ = [
    "RetrainJob",
    "RetrainJobConfig",
    "RetrainJobStats",
]

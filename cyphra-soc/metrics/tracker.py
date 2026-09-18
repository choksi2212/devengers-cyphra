"""Operational metrics — the SOC's numbers.

Five metrics are worth their own counters; the rest can be derived
from them.

* **mean_time_to_detect** (MTTD) — the wall-clock time between an
  event's ``time`` and the incident it joins. A fast MTTD means the
  correlate engine is keeping up with the data; a slow one means a
  connector or detection rule is dropping events.
* **mean_time_to_respond** (MTTR) — the wall-clock time between an
  incident's ``window_end`` and the analyst's first disposition. A
  fast MTTR means the queue is staffed; a slow one means triage is
  backlogged.
* **false_positive_rate** — the fraction of dispositions that are
  false alarms or benign. A high rate means detection rules or the
  ML model are noisy.
* **alert_volume** — the number of findings the platform emitted
  over the window.
* **escalation_rate** — the fraction of dispositions that
  escalated. A high rate means most alerts are real; a low rate
  means the platform pages too often.

The tracker is in-memory. A production deployment persists every
metric observation to VedDB so dashboards can read historical data;
the in-memory tracker is sufficient for the test path and for
real-time dashboards whose window is "the last hour".
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import Incident
from triage import Disposition, DispositionRecord, TriageQueue


@dataclass
class MetricSample:
    """One (label, value, at) tuple."""

    label: str
    value: float
    at: float


@dataclass
class MetricsReport:
    """The current view of the SOC's operational metrics."""

    alert_volume: int = 0
    incident_count: int = 0
    mttd_seconds: float = 0.0
    mttr_seconds: float = 0.0
    false_positive_rate: float = 0.0
    true_positive_rate: float = 0.0
    escalation_rate: float = 0.0
    verdict_counts: dict[str, int] = field(default_factory=dict)
    sampled_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_volume": self.alert_volume,
            "incident_count": self.incident_count,
            "mttd_seconds": self.mttd_seconds,
            "mttr_seconds": self.mttr_seconds,
            "false_positive_rate": self.false_positive_rate,
            "true_positive_rate": self.true_positive_rate,
            "escalation_rate": self.escalation_rate,
            "verdict_counts": dict(self.verdict_counts),
            "sampled_at": self.sampled_at,
        }


class MetricsTracker:
    """The in-memory metrics tracker.

    A single instance is reusable; the test path constructs one per
    test, the production path has one for the lifetime of the
    platform.
    """

    def __init__(self, *, clock: Any = time.time) -> None:
        self.clock = clock
        self._mttd_samples: list[float] = []
        self._mttr_samples: list[float] = []
        self._verdict_counts: dict[int, int] = {}
        self._escalation_count = 0
        self._disposition_count = 0
        self._alert_count = 0
        self._incident_count = 0

    def observe_finding(self, *, event_time: float, detected_at: float | None = None) -> None:
        """Record one finding's detection latency."""
        self._alert_count += 1
        if detected_at is None:
            detected_at = self.clock()
        delta = detected_at - event_time
        if delta >= 0:
            self._mttd_samples.append(delta)

    def observe_incident(self, incident: Incident) -> None:
        """Record one incident's appearance."""
        self._incident_count += 1

    def observe_disposition(
        self,
        record: DispositionRecord,
        *,
        incident_window_end: float,
    ) -> None:
        """Record one disposition's latency."""
        self._disposition_count += 1
        self._verdict_counts[record.disposition_id] = (
            self._verdict_counts.get(record.disposition_id, 0) + 1
        )
        if record.disposition_id in (
            int(Disposition.ESCALATE),
            int(Disposition.TRUE_POSITIVE),
        ):
            self._escalation_count += 1
        delta = record.created_at - incident_window_end
        if delta >= 0:
            self._mttr_samples.append(delta)

    def sample(self) -> MetricsReport:
        """A point-in-time snapshot of the metrics."""
        false_positive = self._verdict_counts.get(int(Disposition.FALSE_POSITIVE), 0)
        benign = self._verdict_counts.get(int(Disposition.BENIGN), 0)
        true_positive = self._verdict_counts.get(int(Disposition.TRUE_POSITIVE), 0)
        total = self._disposition_count
        report = MetricsReport(
            alert_volume=self._alert_count,
            incident_count=self._incident_count,
            mttd_seconds=_mean(self._mttd_samples),
            mttr_seconds=_mean(self._mttr_samples),
            false_positive_rate=(false_positive + benign) / total if total else 0.0,
            true_positive_rate=true_positive / total if total else 0.0,
            escalation_rate=self._escalation_count / total if total else 0.0,
            sampled_at=self.clock(),
        )
        from triage.disposition import DISPOSITION_NAMES
        report.verdict_counts = {
            DISPOSITION_NAMES[k]: v
            for k, v in self._verdict_counts.items()
        }
        return report

    def reset(self) -> None:
        """Clear all counters. Used by the test path."""
        self._mttd_samples.clear()
        self._mttr_samples.clear()
        self._verdict_counts.clear()
        self._escalation_count = 0
        self._disposition_count = 0
        self._alert_count = 0
        self._incident_count = 0


def _mean(samples: Sequence[float]) -> float:
    """The arithmetic mean, or 0.0 on an empty sample."""
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


__all__ = ["MetricsReport", "MetricsTracker", "MetricSample"]

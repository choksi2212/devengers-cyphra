"""The detection engine — every detector that turns events into findings.

The engine is the dispatcher. It owns:

* A **rule registry** — named rule sets that match a single event against
  a declarative predicate and emit a 2004 finding when they fire.
* A **statistical detector** — rate-based rules that need a rolling
  window of events to make a decision.
* A **behavioural detector** — sequence rules that look at a stream of
  events from a single source and emit a finding when a *pattern* is
  matched, regardless of which single events participated.
* An **ML detector** — the platform's :class:`learn.Model` scoring each
  event and emitting a finding when the score exceeds the model's
  threshold. This is the detector that the retrain pipeline (Phase 2a)
  tunes.

The engine runs every detector against every event. An event that fires
five rules produces five findings. A *correlated* event — one that is
part of a longer pattern — fires the behavioural detector and may also
fire the rule that matches the individual event. The findings are then
handed to the correlate engine (Phase 3) which groups them by incident.

Findings are OCSF 2004 DetectionFinding objects. ``finding_info`` carries
the rule's ``info`` block, ``attack`` carries the technique the rule is
about (if any), and ``verdict_id`` is left at :attr:`OcsfVerdict.UNKNOWN`
until an analyst reaches it.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from core.schema.ocsf import ClassUid, Severity, Verdict as OcsfVerdict
from detect.finding import Finding
from detect.rules.signature import RuleMatch, RuleSet

logger = logging.getLogger(__name__)


@dataclass
class DetectionReport:
    """The engine's output for one event.

    ``findings`` is the list of :class:`Finding` objects the detectors
    emitted for this event. ``matched_rules`` is the rule IDs that fired
    (without the rest of the metadata), used for audit logs.
    """

    event_time: float
    event_class_uid: int
    findings: list[Finding] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    ml_score: float | None = None
    duration_ms: float = 0.0


@dataclass
class EngineStats:
    """Counts the engine exposes via ``stats()``."""

    events_seen: int = 0
    findings_emitted: int = 0
    rule_matches: int = 0
    ml_scored: int = 0
    behaviour_fires: int = 0
    last_error: str = ""


class DetectionEngine:
    """The platform's detection dispatcher.

    A single instance is intended to live the lifetime of the platform.
    Detectors register on construction; ``detect(event)`` is the only
    public surface for incoming events. ``stats()`` is the operator's
    health check.
    """

    def __init__(
        self,
        rule_set: RuleSet,
        *,
        ml_scorer: Any = None,
        behaviour_state: Any = None,
        clock: Any = time.time,
    ) -> None:
        self.rule_set = rule_set
        self.ml_scorer = ml_scorer
        self.behaviour_state = behaviour_state
        self.clock = clock
        self.stats = EngineStats()

    def detect(self, event: Mapping[str, Any]) -> DetectionReport:
        """One event in, one report out.

        The engine runs every detector against the event. An event with no
        detector match returns a report with no findings — that is normal,
        the engine is not a noise source. The correlate engine is the
        place where "many small events become one big event".
        """
        started = self.clock()
        report = DetectionReport(
            event_time=float(event.get("time", started)),
            event_class_uid=int(event.get("class_uid", 0)),
        )
        try:
            # Signature / rule-based.
            rule_findings = self._apply_rules(event)
            report.findings.extend(rule_findings)
            report.matched_rules.extend(f.rule_id for f in rule_findings)
            self.stats.rule_matches += len(rule_findings)

            # Behavioural — pattern detection over the running state.
            if self.behaviour_state is not None:
                behaviour = self.behaviour_state.observe(event)
                for f in behaviour:
                    report.findings.append(f)
                    report.matched_rules.append(f.rule_id)
                    self.stats.behaviour_fires += 1

            # ML scoring — the model reads the event's feature vector and
            # emits a finding when the score exceeds its threshold. The
            # finding's confidence is the model's probability.
            if self.ml_scorer is not None:
                score = self.ml_scorer.score_event(event)
                report.ml_score = score
                self.stats.ml_scored += 1
                if score >= getattr(self.ml_scorer, "threshold", 0.5):
                    f = self._ml_finding(event, score)
                    report.findings.append(f)
                    report.matched_rules.append(f.rule_id)
        except Exception as exc:  # noqa: BLE001
            self.stats.last_error = repr(exc)
            logger.exception("detection engine failed on event")
        self.stats.events_seen += 1
        self.stats.findings_emitted += len(report.findings)
        report.duration_ms = (self.clock() - started) * 1000.0
        return report

    # ── helpers ────────────────────────────────────────────────────────────

    def _apply_rules(self, event: Mapping[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for match in self.rule_set.match(event):
            findings.append(self._rule_finding(event, match))
        return findings

    def _rule_finding(
        self, event: Mapping[str, Any], match: RuleMatch
    ) -> Finding:
        rule = match.rule
        return Finding(
            alert_uid=str(event.get("metadata_uid") or ""),
            alert_time=float(event.get("time", 0.0)),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=int(rule.severity),
            confidence=match.confidence,
            attack=rule.attack,
            description=rule.description,
            metadata={
                "matched_paths": list(match.paths),
                "rationale": match.rationale,
            },
        )

    def _ml_finding(self, event: Mapping[str, Any], score: float) -> Finding:
        return Finding(
            alert_uid=str(event.get("metadata_uid") or ""),
            alert_time=float(event.get("time", 0.0)),
            rule_id="ml.scoring",
            rule_name="ML detector",
            severity=int(
                Severity.HIGH if score >= 0.9 else
                Severity.MEDIUM if score >= 0.7 else
                Severity.LOW
            ),
            confidence=float(score),
            attack="",
            description=(
                f"ML model scored {score:.3f} for event class_uid="
                f"{event.get('class_uid')!r}"
            ),
            metadata={"model_score": float(score)},
        )

    def to_ocsf(self, report: DetectionReport) -> list[dict[str, Any]]:
        """The findings as OCSF 2004 DetectionFinding records.

        The correlate engine consumes these. Every record carries the
        minimum fields a 2004 requires: ``class_uid``, ``time``,
        ``metadata_uid``, ``finding_info``, ``severity_id``.
        """
        out: list[dict[str, Any]] = []
        for finding in report.findings:
            out.append({
                "class_uid": int(ClassUid.DETECTION_FINDING),
                "time": finding.alert_time,
                "severity_id": finding.severity,
                "metadata_uid": finding.finding_uuid or f"finding-{finding.alert_uid}-{finding.rule_id}",
                "metadata_product_name": "Cyphra SOC Detection Engine",
                "metadata_product_vendor_name": "Cyphra SOC",
                "metadata_version": "1.9.0",
                "finding_info": [{
                    "name": finding.rule_name,
                    "uid": finding.rule_id,
                    "desc": finding.description,
                    "confidence": int(round(finding.confidence * 100)),
                }],
                "verdict_id": int(OcsfVerdict.UNKNOWN),
                "activity_name": finding.rule_name,
                "activity_id": 1,
                "metadata_labels": [],
                "unmapped": {
                    "rule_id": finding.rule_id,
                    "rationale": finding.metadata.get("rationale", ""),
                    "matched_paths": finding.metadata.get("matched_paths", []),
                },
            } | ({"attacks": [{"technique_id": finding.attack}]} if finding.attack else {}))
        return out

    def stats_dict(self) -> dict[str, Any]:
        """A serialisable stats dict for the operator's health dashboard."""
        return {
            "events_seen": self.stats.events_seen,
            "findings_emitted": self.stats.findings_emitted,
            "rule_matches": self.stats.rule_matches,
            "ml_scored": self.stats.ml_scored,
            "behaviour_fires": self.stats.behaviour_fires,
            "last_error": self.stats.last_error,
        }


__all__ = [
    "DetectionEngine",
    "DetectionReport",
    "EngineStats",
    "Finding",
]

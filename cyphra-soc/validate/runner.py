"""End-to-end runner — pipe emulation through every layer.

The runner is the *one* place that knows the platform's pipeline order:

    emulation events
        -> enrichment
        -> detection
        -> correlation
        -> triage
        -> respond

Every layer is optional. The runner constructs default ones when not
supplied. A test that wants to inject a custom detector or correlate
engine passes them in.

The runner produces a :class:`RunReport` with counts at each layer,
incidents that reached triage, escalations to respond, and an ML
score summary.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import CorrelateEngine, FindingStub, Incident, actor_time_key
from detect import (
    BehaviouralDetector,
    DetectionEngine,
    Finding,
    StatisticalDetector,
    default_rule_set,
)
from detect.ml.scorer import MLScorer
from enrich import Enricher, to_ocsf_context
from entities import EntityStore
from hunt import HuntQuery, HuntRunner, equals
from intel import IntelStore
from learn.model import Model
from respond import PlaybookDispatcher
from triage import Disposition, DispositionRecord, TriageQueue
from validate.emulation.generator import ScenarioResult, run_all


@dataclass
class LayerReport:
    name: str
    in_count: int = 0
    out_count: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunReport:
    started_at: float = 0.0
    completed_at: float = 0.0
    layers: list[LayerReport] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    escalations: int = 0
    ml_scores: list[float] = field(default_factory=list)
    rule_hits: Counter = field(default_factory=Counter)
    scenario_count: int = 0
    event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "layers": [
                {
                    "name": layer.name,
                    "in": layer.in_count,
                    "out": layer.out_count,
                    **layer.extra,
                }
                for layer in self.layers
            ],
            "incidents": len(self.incidents),
            "escalations": self.escalations,
            "ml_score_summary": _score_summary(self.ml_scores),
            "rule_hits": dict(self.rule_hits),
            "scenarios": self.scenario_count,
            "events": self.event_count,
        }


def _score_summary(scores: Sequence[float]) -> dict[str, float]:
    if not scores:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "above_threshold": 0.0}
    return {
        "min": min(scores),
        "max": max(scores),
        "mean": sum(scores) / len(scores),
        "above_threshold": sum(1 for s in scores if s >= 0.5),
    }


@dataclass
class Pipeline:
    detector: Any
    correlate: Any
    triage: TriageQueue
    respond: PlaybookDispatcher
    enricher: Any = None
    hunt_runner: HuntRunner | None = None


class EndToEndRunner:
    """The end-to-end runner.

    A single instance is reusable across runs; the triage queue and
    respond dispatcher carry their state.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        *,
        clock: Any = time.time,
    ) -> None:
        self.pipeline = pipeline
        self.clock = clock
        self._disposition_counter = 0

    def run(
        self,
        scenarios: Iterable[ScenarioResult] | None = None,
        *,
        start: float | None = None,
        end: float | None = None,
    ) -> RunReport:
        if scenarios is None:
            scenarios = run_all(
                start or self.clock(),
                (end or self.clock()) + 3600.0,
            )
        scenarios = list(scenarios)
        report = RunReport(
            started_at=self.clock(),
            scenario_count=len(scenarios),
        )
        enrich_layer = LayerReport(name="enrichment")
        detect_layer = LayerReport(name="detection")
        correlate_layer = LayerReport(name="correlation")
        triage_layer = LayerReport(name="triage")
        respond_layer = LayerReport(name="respond")
        report.layers.extend(
            (enrich_layer, detect_layer, correlate_layer, triage_layer, respond_layer)
        )
        for scenario in scenarios:
            for event in scenario.events:
                report.event_count += 1
                enriched: dict[str, Any] = dict(event)
                if self.pipeline.enricher is not None:
                    enr = self.pipeline.enricher.enrich(event)
                    enriched["unmapped"] = {
                        **dict(enriched.get("unmapped") or {}),
                        "enrich": to_ocsf_context(enr),
                    }
                    enrich_layer.in_count += 1
                    enrich_layer.out_count += 1
                dreport = self.pipeline.detector.detect(enriched)
                detect_layer.in_count += 1
                detect_layer.out_count += len(dreport.findings)
                if dreport.ml_score is not None:
                    report.ml_scores.append(dreport.ml_score)
                for finding in dreport.findings:
                    report.rule_hits[finding.rule_id] += 1
                for finding in dreport.findings:
                    correlate_layer.in_count += 1
                    incident = self._correlate(finding, enriched)
                    correlate_layer.out_count += 1
                    if incident is not None and incident not in report.incidents:
                        report.incidents.append(incident)
                    if incident is not None:
                        self.pipeline.triage.add(incident)
                if self.pipeline.hunt_runner is not None:
                    self.pipeline.hunt_runner.add(_default_one_shot_hunt())
                    self.pipeline.hunt_runner.run_named("one_shot", [enriched])
            for incident in report.incidents:
                if incident.uid not in self.pipeline.triage._assignments:
                    self.pipeline.triage.assign(incident.uid, "validator")
                triage_layer.in_count += 1
                disposition_id = self._pick_disposition(incident)
                self.pipeline.triage.record_disposition(
                    DispositionRecord(
                        incident_uid=incident.uid,
                        analyst_id="validator",
                        disposition_id=disposition_id,
                    )
                )
                triage_layer.out_count += 1
                if disposition_id in (
                    int(Disposition.TRUE_POSITIVE),
                    int(Disposition.ESCALATE),
                ):
                    playbook_result = self.pipeline.respond.dispatch(incident)
                    if playbook_result is not None:
                        report.escalations += 1
                        respond_layer.in_count += 1
                        respond_layer.out_count += len(playbook_result.results)
        report.completed_at = self.clock()
        return report

    def _correlate(
        self,
        finding: Finding,
        event: Mapping[str, Any],
    ) -> Incident | None:
        attack_id = finding.attack or ""
        actor_key = (
            (event.get("actor") or {}).get("user", {}).get("uid")
            or (event.get("actor") or {}).get("user", {}).get("name")
            or ""
        )
        target_keys = tuple(
            r.get("uid")
            for r in event.get("resources") or []
            if r.get("uid")
        )
        correlation_key = actor_time_key({
            "actor_key": actor_key,
            "attack_id": attack_id,
        })
        stub = FindingStub(
            uid=finding.alert_uid or f"f-{finding.rule_id}-{finding.alert_time}",
            time=finding.alert_time or 0.0,
            severity_id=finding.severity,
            attack_id=attack_id,
            actor_key=actor_key,
            target_keys=target_keys,
            correlation_key=correlation_key,
        )
        return self.pipeline.correlate.observe(stub)

    def _pick_disposition(self, incident: Incident) -> int:
        """Pick a disposition that varies across incidents.

        The first incident is escalated; the second is closed as a
        true positive; the rest are closed as false positives. The
        varied dispositions exercise every disposition path in the
        queue.
        """
        self._disposition_counter += 1
        if self._disposition_counter == 1:
            return int(Disposition.ESCALATE)
        if self._disposition_counter == 2:
            return int(Disposition.TRUE_POSITIVE)
        return int(Disposition.FALSE_POSITIVE)


def default_pipeline(
    *,
    entity_store: EntityStore | None = None,
    intel_store: IntelStore | None = None,
    ml_model: Model | None = None,
    hunt_runner: HuntRunner | None = None,
) -> Pipeline:
    """A pipeline composed of the shipped defaults."""
    entities = entity_store or EntityStore()
    intel = intel_store or IntelStore()
    enricher = Enricher(entities, intel)
    rules = default_rule_set()
    statistical = StatisticalDetector.default()
    behavioural = BehaviouralDetector.default()
    ml_scorer = MLScorer(model=ml_model) if ml_model is not None else None
    detector = DetectionEngine(
        rule_set=rules,
        ml_scorer=ml_scorer,
        behaviour_state=behavioural,
        clock=time.time,
    )
    correlate = CorrelateEngine()
    triage = TriageQueue(sla_seconds=900.0)
    respond = PlaybookDispatcher()
    return Pipeline(
        detector=detector,
        correlate=correlate,
        triage=triage,
        respond=respond,
        enricher=enricher,
        hunt_runner=hunt_runner,
    )


def _default_one_shot_hunt() -> HuntQuery:
    """A trivial hunt the runner runs against every event.

    The hunt matches every event with ``is_alert=True``. Its purpose
    is to exercise the hunt layer end-to-end; the actual
    periodic-hunt queries are the responsibility of the platform
    operator.
    """
    return HuntQuery(
        name="one_shot",
        description="Validate the hunt layer.",
        predicates=[equals("is_alert", True)],
        window="1h",
    )


__all__ = [
    "EndToEndRunner",
    "LayerReport",
    "Pipeline",
    "RunReport",
    "default_pipeline",
]

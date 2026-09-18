"""Drift detector — compare two end-to-end runs and report deltas.

The regression harness runs the end-to-end pipeline on every release.
The first run establishes the *baseline*; subsequent runs are
compared against it. A drift is a layer-level counter that moved
beyond a tolerance — the operator sees the exact number that
changed and where.

The detector is *layer-aware* — the correlate layer's "incidents
created" is the same number in two healthy runs, but a regression
in the detection layer would drop the correlate layer's "incidents
in" without changing its "incidents created". A detector that
compared totals would miss the regression; a detector that compares
layer-by-layer sees it.

The detector is also *rule-aware* — the rule-hit counts are a more
sensitive signal than the layer totals. A rule that stops firing
because of a connector regression would not move the layer totals
much (the next rule would catch the events) but the rule-hit
distribution would shift.

The detector's tolerances are configurable. The default is *zero*
for counts that should be deterministic (rule hits, layer totals),
and *5 %* for counts that have natural variance (ML scores, hunt
sample counts).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from validate.runner import RunReport


@dataclass
class LayerDrift:
    """The drift on one layer.

    ``name`` is the layer's name. ``in_delta`` and ``out_delta`` are
    the changes in in_count and out_count. ``within_tolerance`` is
    ``True`` if the deltas are within the layer's tolerance.
    """

    name: str
    in_delta: int = 0
    out_delta: int = 0
    within_tolerance: bool = True


@dataclass
class RuleDrift:
    """The drift on one rule's hit count.

    ``rule_id`` is the rule's id. ``baseline`` and ``current`` are
    the hit counts in the two runs. ``within_tolerance`` is
    ``True`` if the delta is small.
    """

    rule_id: str
    baseline: int
    current: int
    within_tolerance: bool


@dataclass
class DriftReport:
    """The full drift between two :class:`RunReport` outputs.

    ``within_tolerance`` is ``True`` iff every layer and every rule
    is within tolerance — i.e. no regression detected. ``layers``
    and ``rules`` carry the per-element drift so the operator can
    see where the regression came from when ``within_tolerance`` is
    ``False``.
    """

    within_tolerance: bool
    layers: list[LayerDrift] = field(default_factory=list)
    rules: list[RuleDrift] = field(default_factory=list)
    ml_score_mean_delta: float = 0.0
    incident_delta: int = 0
    escalation_delta: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "within_tolerance": self.within_tolerance,
            "layers": [
                {
                    "name": layer.name,
                    "in_delta": layer.in_delta,
                    "out_delta": layer.out_delta,
                    "within_tolerance": layer.within_tolerance,
                }
                for layer in self.layers
            ],
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "baseline": rule.baseline,
                    "current": rule.current,
                    "within_tolerance": rule.within_tolerance,
                }
                for rule in self.rules
            ],
            "ml_score_mean_delta": self.ml_score_mean_delta,
            "incident_delta": self.incident_delta,
            "escalation_delta": self.escalation_delta,
        }


@dataclass
class DriftConfig:
    """The detector's tolerances.

    ``layer_tolerance`` is the absolute number of in/out events the
    layer may shift without being flagged. ``rule_tolerance`` is
    the absolute number of rule hits per rule that may shift. The
    defaults are zero — a regression is a regression — but a noisy
    deployment raises them.
    """

    layer_tolerance: int = 0
    rule_tolerance: int = 0
    ml_score_tolerance: float = 0.05


def compare(
    baseline: RunReport,
    current: RunReport,
    *,
    config: DriftConfig | None = None,
) -> DriftReport:
    """Compare two runs and report the drift.

    The two runs should be the result of the *same* scenario set —
    the drift is "what changed between the two runs", not "what
    changed in the scenarios".
    """
    config = config or DriftConfig()
    baseline_layers = {layer.name: layer for layer in baseline.layers}
    current_layers = {layer.name: layer for layer in current.layers}
    layer_names = set(baseline_layers) | set(current_layers)
    layer_drifts: list[LayerDrift] = []
    overall_within = True
    for name in sorted(layer_names):
        bl = baseline_layers.get(name)
        cu = current_layers.get(name)
        in_delta = (cu.in_count if cu else 0) - (bl.in_count if bl else 0)
        out_delta = (cu.out_count if cu else 0) - (bl.out_count if bl else 0)
        within = (
            abs(in_delta) <= config.layer_tolerance
            and abs(out_delta) <= config.layer_tolerance
        )
        if not within:
            overall_within = False
        layer_drifts.append(LayerDrift(
            name=name,
            in_delta=in_delta,
            out_delta=out_delta,
            within_tolerance=within,
        ))
    rule_names = set(baseline.rule_hits) | set(current.rule_hits)
    rule_drifts: list[RuleDrift] = []
    for name in sorted(rule_names):
        b = baseline.rule_hits.get(name, 0)
        c = current.rule_hits.get(name, 0)
        within = abs(c - b) <= config.rule_tolerance
        if not within:
            overall_within = False
        rule_drifts.append(RuleDrift(
            rule_id=name,
            baseline=b,
            current=c,
            within_tolerance=within,
        ))
    base_score = baseline.to_dict()["ml_score_summary"]["mean"]
    cur_score = current.to_dict()["ml_score_summary"]["mean"]
    score_delta = cur_score - base_score
    if abs(score_delta) > config.ml_score_tolerance:
        overall_within = False
    incident_delta = len(current.incidents) - len(baseline.incidents)
    escalation_delta = current.escalations - baseline.escalations
    return DriftReport(
        within_tolerance=overall_within,
        layers=layer_drifts,
        rules=rule_drifts,
        ml_score_mean_delta=score_delta,
        incident_delta=incident_delta,
        escalation_delta=escalation_delta,
    )


__all__ = [
    "DriftConfig",
    "DriftReport",
    "LayerDrift",
    "RuleDrift",
    "compare",
]

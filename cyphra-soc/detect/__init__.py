"""The detection engine — rules, statistics, behaviour, ML.

Four detector kinds cover the spectrum of what a SOC has to detect:

* :mod:`detect.rules.signature` — declarative predicates over single
  events. The fast, cheap, easy-to-audit layer.
* :mod:`detect.rules.statistical` — rolling-window rate rules over
  per-actor or per-IP counters.
* :mod:`detect.rules.sequence` — multi-step patterns that fire on the
  chain, not the individual events.
* :mod:`detect.ml.scorer` — the platform's :class:`learn.model.Model`
  applied to every event.

The :class:`detect.engine.DetectionEngine` is the dispatcher; it owns
the four kinds and emits one :class:`Finding` per match. Findings are
shaped to OCSF 2004 DetectionFinding; the correlate engine consumes
them.
"""

from detect.engine import (
    DetectionEngine,
    DetectionReport,
    EngineStats,
    Finding,
)
from detect.ml.scorer import MLScorer
from detect.rules.sequence import (
    BehaviouralDetector,
    SequencePattern,
)
from detect.rules.signature import (
    FieldCondition,
    OPERATIONS,
    Rule,
    RuleMatch,
    RuleSet,
    all_of,
    any_of,
    default_rule_set,
    field_contains,
    field_equals,
    field_exists,
    field_in,
    field_not_exists,
    field_regex,
)
from detect.rules.statistical import (
    BurstRule,
    RateRule,
    StatisticalDetector,
)

__all__ = [
    "BehaviouralDetector",
    "BurstRule",
    "DetectionEngine",
    "DetectionReport",
    "EngineStats",
    "FieldCondition",
    "Finding",
    "MLScorer",
    "OPERATIONS",
    "RateRule",
    "Rule",
    "RuleMatch",
    "RuleSet",
    "SequencePattern",
    "StatisticalDetector",
    "all_of",
    "any_of",
    "default_rule_set",
    "field_contains",
    "field_equals",
    "field_exists",
    "field_in",
    "field_not_exists",
    "field_regex",
]

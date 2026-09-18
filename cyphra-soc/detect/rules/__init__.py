"""Detection rules — signature, statistical, sequence.

Each sub-module ships with a ``default_*`` factory that returns the rule
pack the platform starts with; a deployment extends the pack rather than
replacing it.
"""

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
    "FieldCondition",
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

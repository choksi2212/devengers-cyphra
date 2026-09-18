"""Analyst verdict capture — the human-in-the-loop anchor of the label fix.

Every alert that reaches the SOC console is a *claim*: the platform says this
event is suspicious. The claim is a hypothesis until an analyst confirms or
denies it. Without that confirmation the platform's confidence is a *self-
report*: an algorithm judging its own output, not a measure of truth.

Verdicts are aligned with OCSF's :class:`core.schema.ocsf.Verdict` enum so a
verdict captured here can be placed on the finding's ``verdict_id`` field
without translation. Two of OCSF's members are deliberately not used as
training labels — :attr:`OcsfVerdict.SUSPICIOUS` and
:attr:`OcsfVerdict.INSUFFICIENT_DATA` — because both are "I don't know"
rather than a conclusion, and a model trained on non-conclusions cannot
learn the decision boundary.

A verdict is *irrevocable*. An analyst who changes their mind can issue a
new verdict on the same alert (the latest one wins) but the old one stays
in the audit trail. This is the property that lets Phase 2a's "report
honestly" be honest: a model retrained on analyst verdicts cannot quietly
walk back a label that contradicts its predictions.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from core.schema.ocsf import Verdict as OcsfVerdict

#: Re-export OCSF's verdict enum under a name that reads in the analyst's
#: vocabulary — ``VerdictLabel.TRUE_POSITIVE`` is the *state* an alert is in,
#: whereas ``OcsfVerdict.TRUE_POSITIVE`` is the field on a 2004/2005 finding.
VerdictLabel = OcsfVerdict


#: Human-readable names for the analyst UI. The OCSF BENIGN / INSUFFICIENT_DATA
#: members are surfaced under names that read as workflow states.
VERDICT_NAMES: Mapping[int, str] = {
    int(OcsfVerdict.UNKNOWN): "unknown",
    int(OcsfVerdict.FALSE_POSITIVE): "false_positive",
    int(OcsfVerdict.TRUE_POSITIVE): "true_positive",
    int(OcsfVerdict.DISREGARD): "disregard",
    int(OcsfVerdict.SUSPICIOUS): "suspicious",
    int(OcsfVerdict.BENIGN): "benign",
    int(OcsfVerdict.TEST): "test",
    int(OcsfVerdict.INSUFFICIENT_DATA): "needs_review",
    int(OcsfVerdict.SECURITY_RISK): "security_risk",
    int(OcsfVerdict.MANAGED_EXTERNALLY): "managed_externally",
    int(OcsfVerdict.DUPLICATE): "duplicate",
    int(OcsfVerdict.OTHER): "other",
}


@dataclass
class Verdict:
    """One analyst's verdict on one alert.

    ``alert_uid`` is the alert's :attr:`metadata_uid`. ``analyst_id`` is the
    operator's handle (no PII); ``verdict_id`` is the enum value;
    ``reason`` is a free-text note that lands in the audit trail;
    ``created_at`` is the monotonic clock time at capture.
    """

    alert_uid: str
    analyst_id: str
    verdict_id: int
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    verdict_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))


def is_conclusive(verdict_id: int) -> bool:
    """``True`` when the verdict trains models. ``needs_review`` does not.

    ``OcsfVerdict.BENIGN`` is conclusive for the binary model because a
    benign event is still a non-threat — the alert fired, nothing
    followed. ``OcsfVerdict.SUSPICIOUS`` and
    ``OcsfVerdict.INSUFFICIENT_DATA`` are not conclusive because "I don't
    know" is not a label.
    """
    return verdict_id in (
        int(OcsfVerdict.TRUE_POSITIVE),
        int(OcsfVerdict.FALSE_POSITIVE),
        int(OcsfVerdict.BENIGN),
    )


def label_for_training(verdict_id: int) -> int:
    """Map a verdict to the binary label used by the model.

    ``TRUE_POSITIVE`` → 1 (the alert was right), ``FALSE_POSITIVE`` and
    ``BENIGN`` → 0 (the alert was wrong). The distinction between
    ``FALSE_POSITIVE`` and ``BENIGN`` matters for the audit report ("of N
    false alarms, how many were benign?") but not for the model's threshold.
    """
    if verdict_id == int(OcsfVerdict.TRUE_POSITIVE):
        return 1
    if verdict_id in (int(OcsfVerdict.FALSE_POSITIVE), int(OcsfVerdict.BENIGN)):
        return 0
    raise ValueError(
        f"verdict {verdict_id} ({VERDICT_NAMES.get(verdict_id, '?')}) is not "
        "conclusive; it cannot be used as a training label"
    )


def from_name(name: str) -> int:
    """Parse a verdict label name back into its enum value."""
    upper = name.strip().lower().replace("-", "_")
    for k, v in VERDICT_NAMES.items():
        if v == upper:
            return k
    raise ValueError(f"unknown verdict label {name!r}")


__all__ = [
    "VERDICT_NAMES",
    "Verdict",
    "VerdictLabel",
    "from_name",
    "is_conclusive",
    "label_for_training",
]

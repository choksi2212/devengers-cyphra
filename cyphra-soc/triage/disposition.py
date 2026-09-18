"""Analyst dispositions — the verdict on an incident.

A disposition is what an analyst *does* with an incident: close it as a
true positive, dismiss it as a false alarm, mark it as benign, hand it
off for a deeper review, or escalate it to respond. The disposition
flows back to the correlate layer, the metrics module and the audit
chain.

Every disposition is *irrevocable*. An analyst who changes their mind
issues a new disposition; the latest wins. The audit trail in the
underlying :class:`TriageQueue` keeps every historical disposition so
the operator can see the back-and-forth, and the metrics module can
report "time-to-first-disposition" without losing data on late
re-dispositions.

The disposition value space is the analyst's working vocabulary, not
the OCSF enum. The two are *aligned* — every disposition maps to one
OCSF value — but the analyst UI exposes the friendly name and the
correlate layer reads the OCSF value.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from core.schema.ocsf import Verdict as OcsfVerdict


class Disposition(enum.IntEnum):
    """The disposition an analyst can set on an incident.

    Aligned with OCSF's :class:`Verdict` enum where it makes sense
    (``TRUE_POSITIVE`` and ``FALSE_POSITIVE`` are the same value);
    extended with workflow states (escalate, request_more_info) that
    are not on the OCSF enum because they are triage-only actions.
    """

    UNKNOWN = int(OcsfVerdict.UNKNOWN)
    FALSE_POSITIVE = int(OcsfVerdict.FALSE_POSITIVE)
    TRUE_POSITIVE = int(OcsfVerdict.TRUE_POSITIVE)
    BENIGN = int(OcsfVerdict.BENIGN)
    SUSPICIOUS = int(OcsfVerdict.SUSPICIOUS)
    INSUFFICIENT_DATA = int(OcsfVerdict.INSUFFICIENT_DATA)
    # Workflow-only dispositions, off the OCSF enum. Values chosen to be
    # far above the OCSF enum so a future OCSF member cannot collide.
    ESCALATE = 100
    REQUEST_MORE_INFO = 101


DISPOSITION_NAMES: Mapping[int, str] = {
    int(OcsfVerdict.UNKNOWN): "unknown",
    int(OcsfVerdict.FALSE_POSITIVE): "false_positive",
    int(OcsfVerdict.TRUE_POSITIVE): "true_positive",
    int(OcsfVerdict.BENIGN): "benign",
    int(OcsfVerdict.SUSPICIOUS): "suspicious",
    int(OcsfVerdict.INSUFFICIENT_DATA): "needs_more_info",
    int(Disposition.ESCALATE): "escalate",
    int(Disposition.REQUEST_MORE_INFO): "request_more_info",
}


#: Dispositions that *close* the incident — the analyst has decided
#: and the queue should not page on it again.
CLOSING_DISPOSITIONS: frozenset[int] = frozenset({
    int(Disposition.FALSE_POSITIVE),
    int(Disposition.TRUE_POSITIVE),
    int(Disposition.BENIGN),
})


#: Dispositions that *escalate* — the queue hands the incident to the
#: respond layer for containment.
ESCALATING_DISPOSITIONS: frozenset[int] = frozenset({
    int(Disposition.ESCALATE),
    int(Disposition.TRUE_POSITIVE),
})


@dataclass
class DispositionRecord:
    """One analyst's disposition on one incident.

    ``incident_uid`` is the correlate layer's incident id.
    ``analyst_id`` is the operator's handle (no PII).
    ``disposition_id`` is the :class:`Disposition` value.
    ``rationale`` is the analyst's free-text note; the metrics module
    aggregates it for review.
    """

    incident_uid: str
    analyst_id: str
    disposition_id: int
    rationale: str = ""
    created_at: float = field(default_factory=time.time)
    record_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))


def from_name(name: str) -> int:
    """Parse a disposition name back into its enum value."""
    upper = name.strip().lower().replace("-", "_").replace(" ", "_")
    for k, v in DISPOSITION_NAMES.items():
        if v == upper:
            return k
    raise ValueError(f"unknown disposition {name!r}")


def to_ocsf_verdict(disposition_id: int) -> int:
    """Map a triage disposition to the OCSF verdict value for the lake.

    Workflow-only dispositions (escalate, request_more_info) have no
    direct OCSF counterpart — the verdict stays at UNKNOWN and the
    disposition lands in the incident's ``unmapped`` block.
    """
    if disposition_id in CLOSING_DISPOSITIONS:
        return int(disposition_id)
    return int(OcsfVerdict.UNKNOWN)


__all__ = [
    "CLOSING_DISPOSITIONS",
    "DISPOSITION_NAMES",
    "ESCALATING_DISPOSITIONS",
    "Disposition",
    "DispositionRecord",
    "from_name",
    "to_ocsf_verdict",
]

"""The case — the long-lived record of an investigation.

A correlate engine incident lives for as long as the events it groups
together. A *case* lives longer: from the moment the incident opens,
through the triage, through the response, through the postmortem, to
the day the case is closed and archived. A case is what the SOC
console renders; an incident is what the correlate engine emits.

The case carries:

* The incident's identity (``source_incident_uid``).
* The case's own state — ``Open``, ``Under Investigation``,
  ``Contained``, ``Postmortem``, ``Closed``, ``Archived``.
* The timeline — every transition is timestamped so the postmortem
  can read "the case was open for 47 minutes before disposition".
* The actors — the case owner, the responders, the analysts who
  touched the disposition.
* The postmortem — a free-form report written when the case closes,
  with timeline events, root cause, lessons learned.

Cases are append-only on transitions. A case's state moves forward
through the state machine; the audit chain records every move.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping


class CaseStatus(enum.IntEnum):
    """The state a case moves through.

    Aligned with OCSF's :class:`FindingStatus` enum: 1 New, 2 In
    Progress, 4 Resolved, 5 Archived, 6 Deleted. 3 Suppressed and
    99 Other are reserved by OCSF but not used here — a case is
    either open, contained, in postmortem, closed or archived.
    """

    NEW = 1
    UNDER_INVESTIGATION = 2
    CONTAINED = 3
    POSTMORTEM = 4
    CLOSED = 5
    ARCHIVED = 6


STATUS_NAMES: Mapping[int, str] = {
    int(CaseStatus.NEW): "new",
    int(CaseStatus.UNDER_INVESTIGATION): "under_investigation",
    int(CaseStatus.CONTAINED): "contained",
    int(CaseStatus.POSTMORTEM): "postmortem",
    int(CaseStatus.CLOSED): "closed",
    int(CaseStatus.ARCHIVED): "archived",
}


#: Allowed status transitions. ``NEW`` is the entry point;
#: ``ARCHIVED`` is the terminal state. A case moves forward.
_ALLOWED: Mapping[int, frozenset[int]] = {
    int(CaseStatus.NEW): frozenset({
        int(CaseStatus.UNDER_INVESTIGATION),
        int(CaseStatus.CLOSED),
    }),
    int(CaseStatus.UNDER_INVESTIGATION): frozenset({
        int(CaseStatus.CONTAINED),
        int(CaseStatus.POSTMORTEM),
        int(CaseStatus.CLOSED),
    }),
    int(CaseStatus.CONTAINED): frozenset({
        int(CaseStatus.POSTMORTEM),
        int(CaseStatus.CLOSED),
    }),
    int(CaseStatus.POSTMORTEM): frozenset({
        int(CaseStatus.CLOSED),
    }),
    int(CaseStatus.CLOSED): frozenset({
        int(CaseStatus.ARCHIVED),
    }),
    int(CaseStatus.ARCHIVED): frozenset(),
}


@dataclass
class TimelineEvent:
    """One entry on the case's timeline."""

    at: float
    actor_id: str
    kind: str  # "status_change" | "disposition" | "action" | "note"
    description: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Case:
    """One case in the platform.

    ``uid`` is the platform's canonical id. ``source_incident_uid``
    is the correlate engine's incident the case wraps. ``owner_id``
    is the analyst or responder who owns the case; ``status`` is the
    current state. ``timeline`` is every event the case has
    accumulated, oldest first.

    ``title`` and ``summary`` are surfaced in the SOC console and
    the postmortem. ``root_cause`` and ``lessons_learned`` are filled
    by the analyst when the case enters ``POSTMORTEM``.
    """

    uid: str
    source_incident_uid: str
    title: str
    summary: str
    owner_id: str = ""
    status: int = int(CaseStatus.NEW)
    severity_id: int = 4
    attack_ids: list[str] = field(default_factory=list)
    actor_keys: list[str] = field(default_factory=list)
    target_keys: list[str] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    root_cause: str = ""
    lessons_learned: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: float = 0.0


def transition(case: Case, *, to: int, actor_id: str, note: str = "") -> Case:
    """Move a case to a new status.

    Raises ``ValueError`` if the transition is not allowed. The
    transition is recorded on the timeline so the postmortem can read
    it.
    """
    if to not in _ALLOWED.get(case.status, frozenset()):
        raise ValueError(
            f"cannot move case {case.uid} from {STATUS_NAMES[case.status]!r} "
            f"to {STATUS_NAMES.get(to, '?')!r}"
        )
    from_status = STATUS_NAMES[case.status]
    case.status = to
    case.updated_at = time.time()
    if to == int(CaseStatus.CLOSED):
        case.closed_at = case.updated_at
    case.timeline.append(TimelineEvent(
        at=case.updated_at,
        actor_id=actor_id,
        kind="status_change",
        description=f"{from_status} -> {STATUS_NAMES[to]}",
        details={"from": from_status, "to": STATUS_NAMES[to], "note": note},
    ))
    return case


def record(case: Case, *, actor_id: str, kind: str, description: str, **details: Any) -> TimelineEvent:
    """Append a timeline event without changing the case's status."""
    event = TimelineEvent(
        at=time.time(),
        actor_id=actor_id,
        kind=kind,
        description=description,
        details=dict(details),
    )
    case.timeline.append(event)
    case.updated_at = event.at
    return event


def new_case_uid() -> str:
    return f"c-{uuid.uuid4().hex[:12]}"


__all__ = [
    "Case",
    "CaseStatus",
    "STATUS_NAMES",
    "TimelineEvent",
    "new_case_uid",
    "record",
    "transition",
]

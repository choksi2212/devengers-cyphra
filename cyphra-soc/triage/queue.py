"""The triage queue — every open incident, with analyst state.

The queue is the analyst UI's data model. It carries:

* Every incident the correlate engine has emitted, keyed by incident uid.
* An *assignment* per incident — which analyst owns it.
* The latest disposition per incident.
* A history of every disposition ever recorded, for audit.
* An SLA deadline per incident, and a list of breached SLAs.

The queue is *append-only on dispositions* — the latest disposition
wins, but the historical record is preserved. The metrics module reads
the history to compute time-to-first-disposition and similar.

The queue is in-memory by default. A real deployment persists it to
VedDB so a restart does not lose state; the ``TriageQueue`` here is the
in-memory shape that the VedDB-backed store implements.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import Incident
from triage.disposition import (
    CLOSING_DISPOSITIONS,
    ESCALATING_DISPOSITIONS,
    Disposition,
    DispositionRecord,
)


@dataclass
class Assignment:
    """Which analyst owns an incident.

    ``incident_uid`` is the correlate id. ``analyst_id`` is the
    operator's handle. ``assigned_at`` is the monotonic clock; the
    queue's "open for N seconds" metric reads it.
    """

    incident_uid: str
    analyst_id: str
    assigned_at: float = field(default_factory=time.time)


@dataclass
class QueueStats:
    """The queue's self-reported counters."""

    incidents_added: int = 0
    incidents_closed: int = 0
    dispositions_recorded: int = 0
    escalations: int = 0
    sla_breaches: int = 0
    last_error: str = ""


class TriageQueue:
    """The triage queue's in-memory implementation.

    Three indexes:

    * ``_incidents`` — incident_uid → incident.
    * ``_dispositions`` — incident_uid → all dispositions, newest last.
    * ``_assignments`` — incident_uid → assignment.
    """

    def __init__(
        self,
        *,
        sla_seconds: float = 900.0,
        clock: Any = time.time,
    ) -> None:
        self.sla_seconds = float(sla_seconds)
        self.clock = clock
        self._incidents: dict[str, Incident] = {}
        self._dispositions: dict[str, list[DispositionRecord]] = {}
        self._assignments: dict[str, Assignment] = {}
        self.stats = QueueStats()

    # ── incident intake ────────────────────────────────────────────────────

    def add(self, incident: Incident) -> Incident:
        """Register an incident from the correlate engine."""
        existing = self._incidents.get(incident.uid)
        if existing is None:
            self._incidents[incident.uid] = incident
            self.stats.incidents_added += 1
            return incident
        # An incident with the same uid is the *same* incident — the
        # correlate engine re-emitted it on a new finding. The queue
        # updates its in-memory copy from the correlate engine's
        # current state.
        existing.window_start = min(existing.window_start, incident.window_start)
        existing.window_end = max(existing.window_end, incident.window_end)
        existing.severity_id = max(existing.severity_id, incident.severity_id)
        existing.attack_ids = list(
            dict.fromkeys(list(existing.attack_ids) + list(incident.attack_ids))
        )
        for k in incident.actor_keys:
            if k not in existing.actor_keys:
                existing.actor_keys.append(k)
        for k in incident.target_keys:
            if k not in existing.target_keys:
                existing.target_keys.append(k)
        for uid in incident.finding_uids:
            if uid not in existing.finding_uids:
                existing.finding_uids.append(uid)
        existing.updated_at = self.clock()
        return existing

    def close(self, incident_uid: str) -> Incident | None:
        """Mark an incident as resolved and remove it from the open queue."""
        incident = self._incidents.pop(incident_uid, None)
        if incident is not None:
            incident.status_id = 4
            self.stats.incidents_closed += 1
        return incident

    # ── assignment ────────────────────────────────────────────────────────

    def assign(self, incident_uid: str, analyst_id: str) -> Assignment | None:
        """Assign an analyst to an incident.

        Returns the new :class:`Assignment`, or ``None`` if the
        incident is unknown. Reassignment replaces the previous
        assignment without keeping history — the audit chain captures
        the reassignment as an event, the queue does not.
        """
        if incident_uid not in self._incidents:
            return None
        assignment = Assignment(
            incident_uid=incident_uid,
            analyst_id=analyst_id,
            assigned_at=self.clock(),
        )
        self._assignments[incident_uid] = assignment
        return assignment

    def unassigned_incidents(self) -> list[Incident]:
        return [
            incident
            for uid, incident in self._incidents.items()
            if uid not in self._assignments
        ]

    # ── dispositions ───────────────────────────────────────────────────────

    def record_disposition(self, record: DispositionRecord) -> Incident | None:
        """Record an analyst's disposition on an incident.

        Returns the affected incident, or ``None`` if unknown. The
        latest disposition wins; closing dispositions also remove the
        incident from the open queue and the queue's escalating
        dispositions call into the respond layer.
        """
        incident = self._incidents.get(record.incident_uid)
        if incident is None:
            return None
        record.created_at = record.created_at or self.clock()
        history = self._dispositions.setdefault(record.incident_uid, [])
        history.append(record)
        self.stats.dispositions_recorded += 1
        # Reflect the latest disposition on the incident.
        from triage.disposition import to_ocsf_verdict
        incident.status_id = to_ocsf_verdict(record.disposition_id)
        # Closing dispositions remove the incident from the open queue.
        if record.disposition_id in CLOSING_DISPOSITIONS:
            self.close(record.incident_uid)
        if record.disposition_id in ESCALATING_DISPOSITIONS:
            self.stats.escalations += 1
        return incident

    def disposition_history(self, incident_uid: str) -> list[DispositionRecord]:
        """Every disposition ever recorded on an incident, oldest first."""
        return list(self._dispositions.get(incident_uid, []))

    def latest_disposition(self, incident_uid: str) -> DispositionRecord | None:
        """The most recent disposition on an incident, or ``None``."""
        history = self._dispositions.get(incident_uid)
        return history[-1] if history else None

    # ── reads ──────────────────────────────────────────────────────────────

    def get(self, incident_uid: str) -> Incident | None:
        return self._incidents.get(incident_uid)

    def open_incidents(self) -> list[Incident]:
        return list(self._incidents.values())

    def sla_breached(self, *, now: float | None = None) -> list[Incident]:
        """Every open incident whose deadline has passed.

        "SLA" here means *time to first disposition* — an incident with
        no disposition that has been in the queue longer than
        ``sla_seconds`` is breached. The metrics module surfaces
        ``sla_breaches``; the queue also increments the counter.
        """
        moment = now if now is not None else self.clock()
        breached: list[Incident] = []
        for uid, incident in self._incidents.items():
            history = self._dispositions.get(uid, [])
            if history:
                continue
            age = moment - incident.created_at
            if age > self.sla_seconds:
                breached.append(incident)
                self.stats.sla_breaches += 1
        return breached

    def stats_dict(self) -> dict[str, Any]:
        return {
            "incidents_added": self.stats.incidents_added,
            "incidents_closed": self.stats.incidents_closed,
            "open_count": len(self._incidents),
            "dispositions_recorded": self.stats.dispositions_recorded,
            "escalations": self.stats.escalations,
            "sla_breaches": self.stats.sla_breaches,
            "last_error": self.stats.last_error,
        }


__all__ = ["Assignment", "QueueStats", "TriageQueue"]

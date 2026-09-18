"""The case store — every case the platform has produced.

The store indexes cases by ``uid`` and by ``source_incident_uid``.
A case opened from an incident has the same source-incident id
forever; the correlate engine may re-emit the incident on a new
finding, but the case carries the original. The store's
:func:`get_for_incident` returns the existing case rather than
opening a new one — a duplicate case for the same incident is a bug,
not a feature.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from cases.case import Case, CaseStatus, STATUS_NAMES


@dataclass
class CaseStats:
    """The store's self-reported counters."""

    cases_opened: int = 0
    cases_closed: int = 0
    transitions: int = 0
    last_error: str = ""


class CaseStore:
    """The in-memory case store.

    In production, the store is backed by VedDB so a restart does
    not lose state. The in-memory shape is sufficient for the test
    path and for the platform's per-process case view.
    """

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._by_incident: dict[str, str] = {}
        self.stats = CaseStats()

    def open_case(
        self,
        *,
        source_incident_uid: str,
        title: str,
        summary: str,
        severity_id: int,
        attack_ids: Iterable[str] = (),
        actor_keys: Iterable[str] = (),
        target_keys: Iterable[str] = (),
        owner_id: str = "",
    ) -> Case:
        """Open a new case from an incident.

        If the store already has a case for this incident, the
        existing case is returned with the new context merged in —
        the correlate engine re-emitting an incident does not open
        a duplicate case.
        """
        existing_uid = self._by_incident.get(source_incident_uid)
        if existing_uid is not None:
            existing = self._cases.get(existing_uid)
            if existing is not None:
                self._merge_incident(
                    existing,
                    severity_id=severity_id,
                    attack_ids=attack_ids,
                    actor_keys=actor_keys,
                    target_keys=target_keys,
                )
                return existing
        case = Case(
            uid=self._allocate_uid(),
            source_incident_uid=source_incident_uid,
            title=title,
            summary=summary,
            severity_id=severity_id,
            attack_ids=list(dict.fromkeys(list(attack_ids))),
            actor_keys=list(dict.fromkeys(list(actor_keys))),
            target_keys=list(dict.fromkeys(list(target_keys))),
            owner_id=owner_id,
        )
        self._cases[case.uid] = case
        self._by_incident[source_incident_uid] = case.uid
        self.stats.cases_opened += 1
        return case

    def get(self, uid: str) -> Case | None:
        return self._cases.get(uid)

    def get_for_incident(self, source_incident_uid: str) -> Case | None:
        uid = self._by_incident.get(source_incident_uid)
        return self._cases.get(uid) if uid else None

    def list_open(self) -> list[Case]:
        """Every case not in a terminal state."""
        return [
            case for case in self._cases.values()
            if case.status < int(CaseStatus.CLOSED)
        ]

    def list_by_owner(self, owner_id: str) -> list[Case]:
        return [case for case in self._cases.values() if case.owner_id == owner_id]

    def list_by_status(self, status: int) -> list[Case]:
        return [case for case in self._cases.values() if case.status == status]

    def transition(
        self,
        case_uid: str,
        *,
        to: int,
        actor_id: str,
        note: str = "",
    ) -> Case | None:
        """Move a case to a new status.

        Returns the case on success, ``None`` if the case is unknown.
        Delegates the state-machine check to :func:`cases.case.transition`.
        """
        from cases.case import transition as case_transition
        case = self._cases.get(case_uid)
        if case is None:
            return None
        case_transition(case, to=to, actor_id=actor_id, note=note)
        self.stats.transitions += 1
        if to == int(CaseStatus.CLOSED):
            self.stats.cases_closed += 1
        return case

    def stats_dict(self) -> dict[str, Any]:
        return {
            "cases_opened": self.stats.cases_opened,
            "cases_closed": self.stats.cases_closed,
            "transitions": self.stats.transitions,
            "open_count": len(self.list_open()),
            "total": len(self._cases),
            "last_error": self.stats.last_error,
        }

    def _allocate_uid(self) -> str:
        from cases.case import new_case_uid
        return new_case_uid()

    def _merge_incident(
        self,
        case: Case,
        *,
        severity_id: int,
        attack_ids: Iterable[str],
        actor_keys: Iterable[str],
        target_keys: Iterable[str],
    ) -> None:
        """Merge a re-emitted incident's context into the existing case."""
        case.severity_id = max(case.severity_id, severity_id)
        for attack in attack_ids:
            if attack not in case.attack_ids:
                case.attack_ids.append(attack)
        for actor in actor_keys:
            if actor not in case.actor_keys:
                case.actor_keys.append(actor)
        for target in target_keys:
            if target not in case.target_keys:
                case.target_keys.append(target)


__all__ = ["CaseStats", "CaseStore"]

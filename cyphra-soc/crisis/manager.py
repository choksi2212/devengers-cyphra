"""Crisis mode — multi-case emergency coordination.

A *crisis* is the platform's response to an event that exceeds a
single case: a multi-cloud ransomware outbreak, a coordinated
campaign against three subsidiaries, an active exploit in
production. The crisis mode has its own state — the SOC console
goes red, paging escalates, and the playbook dispatcher routes
every incident through the crisis playbook library.

A crisis carries:

* A ``name`` and a ``description`` — the human-readable incident.
* An ``actor_id`` — the crisis commander (the analyst running the
  response).
* A list of ``case_uids`` — the cases folded into the crisis.
* A list of ``playbook_ids`` — the playbooks the crisis will run.
* A ``status`` — ``Active``, ``Contained``, ``Closed``.

A crisis is *declarative*: opening a crisis does not call the
playbooks. The operator (or an automated bridge) calls
:meth:`CrisisManager.activate` to run every playbook across every
case in the crisis. A crisis is closed by the commander; closing a
crisis does not close the cases — those follow their own state
machines.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import Incident
from cases import Case, CaseStatus, CaseStore
from respond import ActionResult, Playbook, PlaybookDispatcher, PlaybookResult


class CrisisStatus(enum.IntEnum):
    """The state of a crisis."""

    ACTIVE = 1
    CONTAINED = 2
    CLOSED = 3


CRISIS_STATUS_NAMES: Mapping[int, str] = {
    int(CrisisStatus.ACTIVE): "active",
    int(CrisisStatus.CONTAINED): "contained",
    int(CrisisStatus.CLOSED): "closed",
}


@dataclass
class Crisis:
    """One crisis in the platform."""

    uid: str
    name: str
    description: str
    actor_id: str
    case_uids: list[str] = field(default_factory=list)
    playbook_ids: list[str] = field(default_factory=list)
    status: int = int(CrisisStatus.ACTIVE)
    playbook_results: list[PlaybookResult] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: float = 0.0


@dataclass
class CrisisStats:
    """The manager's self-reported counters."""

    crises_opened: int = 0
    crises_closed: int = 0
    playbooks_run: int = 0
    actions_applied: int = 0
    last_error: str = ""


class CrisisManager:
    """The crisis dispatcher.

    A single instance is reusable; the case store and playbook
    dispatcher carry their state across crises.
    """

    def __init__(
        self,
        case_store: CaseStore,
        playbook_dispatcher: PlaybookDispatcher,
    ) -> None:
        self.case_store = case_store
        self.playbook_dispatcher = playbook_dispatcher
        self._crises: dict[str, Crisis] = {}
        self.stats = CrisisStats()

    def open(
        self,
        *,
        name: str,
        description: str,
        actor_id: str,
        case_uids: Iterable[str] = (),
        playbook_ids: Iterable[str] = (),
    ) -> Crisis:
        """Open a new crisis."""
        crisis = Crisis(
            uid=self._allocate_uid(),
            name=name,
            description=description,
            actor_id=actor_id,
            case_uids=list(case_uids),
            playbook_ids=list(playbook_ids),
        )
        self._crises[crisis.uid] = crisis
        self.stats.crises_opened += 1
        return crisis

    def get(self, uid: str) -> Crisis | None:
        return self._crises.get(uid)

    def activate(self, crisis_uid: str) -> Crisis | None:
        """Run every playbook in the crisis across every case.

        Cases are read from the store; the playbook dispatcher
        produces the actions. The crisis's playbook_results list
        collects every result so the postmortem can read what the
        crisis did.
        """
        crisis = self._crises.get(crisis_uid)
        if crisis is None:
            return None
        for case_uid in crisis.case_uids:
            case = self.case_store.get(case_uid)
            if case is None:
                continue
            incident = self._synthesize_incident(case)
            for playbook_id in crisis.playbook_ids:
                playbook = self._resolve_playbook(playbook_id)
                if playbook is None:
                    continue
                result = playbook.run(incident, self.playbook_dispatcher.actions)
                crisis.playbook_results.append(result)
                self.stats.playbooks_run += 1
                for action_result in result.results:
                    self.stats.actions_applied += 1
        crisis.updated_at = time.time()
        return crisis

    def contain(self, crisis_uid: str) -> Crisis | None:
        """Mark a crisis as contained."""
        crisis = self._crises.get(crisis_uid)
        if crisis is None:
            return None
        if crisis.status != int(CrisisStatus.ACTIVE):
            return None
        crisis.status = int(CrisisStatus.CONTAINED)
        crisis.updated_at = time.time()
        return crisis

    def close(self, crisis_uid: str) -> Crisis | None:
        """Mark a crisis as closed."""
        crisis = self._crises.get(crisis_uid)
        if crisis is None:
            return None
        crisis.status = int(CrisisStatus.CLOSED)
        crisis.closed_at = time.time()
        crisis.updated_at = crisis.closed_at
        self.stats.crises_closed += 1
        return crisis

    def list_active(self) -> list[Crisis]:
        return [
            crisis for crisis in self._crises.values()
            if crisis.status == int(CrisisStatus.ACTIVE)
        ]

    def list_all(self) -> list[Crisis]:
        return list(self._crises.values())

    def stats_dict(self) -> dict[str, Any]:
        return {
            "crises_opened": self.stats.crises_opened,
            "crises_closed": self.stats.crises_closed,
            "playbooks_run": self.stats.playbooks_run,
            "actions_applied": self.stats.actions_applied,
            "active": len(self.list_active()),
            "total": len(self._crises),
            "last_error": self.stats.last_error,
        }

    def _allocate_uid(self) -> str:
        return f"cr-{uuid.uuid4().hex[:10]}"

    def _synthesize_incident(self, case: Case) -> Incident:
        """A minimal :class:`Incident` for playbook dispatch.

        The playbook dispatcher's routing uses ``attack_ids`` and
        ``actor_keys``/``target_keys``; the case carries both.
        """
        return Incident(
            uid=case.uid,
            finding_uids=[],
            window_start=case.created_at,
            window_end=case.updated_at or case.created_at,
            severity_id=case.severity_id,
            attack_ids=list(case.attack_ids),
            actor_keys=list(case.actor_keys),
            target_keys=list(case.target_keys),
            first_actor_key=case.actor_keys[0] if case.actor_keys else "",
            correlation_key=case.source_incident_uid,
        )

    def _resolve_playbook(self, playbook_id: str) -> Playbook | None:
        """Look up a playbook by id."""
        try:
            from respond.playbooks import get_playbook
            return get_playbook(playbook_id)
        except KeyError:
            return None


__all__ = ["Crisis", "CrisisManager", "CrisisStats", "CrisisStatus", "CRISIS_STATUS_NAMES"]

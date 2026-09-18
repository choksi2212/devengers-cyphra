"""Containment playbooks — multi-step sequences of actions.

A playbook is a named, ordered list of :class:`Action` invocations.
A triage escalation hands the playbook an incident; the dispatcher
runs each step in order, records the result, and stops on the first
failure unless the playbook declares it can continue past failures.

Three playbooks ship out of the box:

* ``CompromiseResponsePlaybook`` — the canonical "an account is
  compromised" sequence: disable the user, revoke their active
  tokens, isolate any host they authenticated from, quarantine any
  suspicious email they received.
* ``CredentialStuffingPlaybook`` — the bulk-burst shape: disable
  every user that authenticated from the same source IP in the
  incident's window.
* ``RansomwareResponsePlaybook`` — the destructive chain: isolate
  every host touched by the incident, disable the service accounts
  that wrote the suspicious files.

A deployment extends the playbook library with vendor-specific
sequences. The framework does not care about the specifics — it runs
any :class:`Action` registered against any target key.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import Incident
from respond.actions import (
    Action,
    ActionResult,
    ActionStatus,
    DisableUserAction,
    IsolateHostAction,
    QuarantineEmailAction,
    RevokeTokenAction,
    get_action,
)


@dataclass
class PlaybookStep:
    """One action call inside a playbook.

    ``action_id`` is the registered action's id. ``target_kind``
    selects which of the incident's keys is the action's target:
    ``"actor"`` picks the primary actor; ``"target"`` picks each of the
    incident's target keys one after another; ``"all_targets"`` runs
    the action once per target; ``"fixed:<value>"`` uses a literal
    value (e.g. ``"fixed:asset-1"``).
    """

    action_id: str
    target_kind: str = "actor"
    description: str = ""
    on_failure: str = "stop"  # "stop" | "continue" | "rollback"


@dataclass
class PlaybookResult:
    """The outcome of running a playbook on one incident.

    ``results`` is one :class:`ActionResult` per step × target. A
    playbook with two steps and three targets produces six results.
    ``status`` is ``success`` if every step succeeded, ``partial`` if
    some succeeded and some failed, ``failed`` if the playbook
    aborted on the first failure.
    """

    playbook_id: str
    incident_uid: str
    status: str
    results: list[ActionResult] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    playbook_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))


class Playbook:
    """A named, ordered list of :class:`PlaybookStep`."""

    playbook_id: str = ""
    name: str = ""
    description: str = ""
    steps: tuple[PlaybookStep, ...] = ()

    def run(
        self,
        incident: Incident,
        actions: Mapping[str, Action],
        *,
        clock: Any = time.time,
    ) -> PlaybookResult:
        """Execute the playbook on ``incident``.

        ``actions`` is the registry mapping ``action_id`` → an
        :class:`Action` instance. The same registry is reused across
        playbooks so the ``already_acted`` state persists.
        """
        result = PlaybookResult(
            playbook_id=self.playbook_id,
            incident_uid=incident.uid,
            status="success",
            started_at=clock(),
        )
        for step in self.steps:
            targets = self._targets(step, incident)
            if not targets:
                continue
            action = actions.get(step.action_id)
            if action is None:
                # The action wasn't registered — the playbook is
                # misconfigured. Abort.
                result.status = "failed"
                break
            for target in targets:
                ar = action.do(target, details={"step": step.description})
                result.results.append(ar)
                if ar.status is ActionStatus.FAILED:
                    if step.on_failure == "stop":
                        result.status = "failed"
                        break
                    if step.on_failure == "rollback":
                        self._rollback(actions, target, step)
                    result.status = "partial"
            if result.status == "failed":
                break
        if result.status not in ("failed",):
            if any(r.status is ActionStatus.FAILED for r in result.results):
                result.status = "partial"
        result.completed_at = clock()
        return result

    def _targets(self, step: PlaybookStep, incident: Incident) -> list[str]:
        """The list of target keys for this step on this incident."""
        kind = step.target_kind
        if kind == "actor":
            return [incident.first_actor_key] if incident.first_actor_key else []
        if kind == "target":
            return list(incident.target_keys)
        if kind == "all_targets":
            return list(incident.target_keys)
        if kind.startswith("fixed:"):
            return [kind[len("fixed:"):]]
        if kind == "all_actors":
            return list(incident.actor_keys)
        return []

    def _rollback(
        self,
        actions: Mapping[str, Action],
        target: str,
        step: PlaybookStep,
    ) -> None:
        """Roll back the step on the target. Best-effort."""
        action = actions.get(step.action_id)
        if action is not None and action.is_applied(target):
            action.undo(target)


# ── shipped playbooks ───────────────────────────────────────────────────────


class CompromiseResponsePlaybook(Playbook):
    """The canonical "an account is compromised" sequence."""

    playbook_id = "compromise_response"
    name = "Account compromise response"
    description = (
        "Disable the user, revoke active sessions, isolate hosts they "
        "touched, quarantine any suspicious email they received."
    )
    steps: tuple[PlaybookStep, ...] = (
        PlaybookStep(
            action_id="disable_user",
            target_kind="actor",
            description="Disable the actor's sign-in.",
            on_failure="stop",
        ),
        PlaybookStep(
            action_id="revoke_token",
            target_kind="actor",
            description="Revoke the actor's active tokens.",
            on_failure="continue",
        ),
        PlaybookStep(
            action_id="isolate_host",
            target_kind="all_targets",
            description="Isolate any host the actor authenticated from.",
            on_failure="continue",
        ),
        PlaybookStep(
            action_id="quarantine_email",
            target_kind="all_targets",
            description="Quarantine any suspicious email received.",
            on_failure="continue",
        ),
    )


class CredentialStuffingPlaybook(Playbook):
    """The bulk-burst shape from a single source IP."""

    playbook_id = "credential_stuffing"
    name = "Credential stuffing response"
    description = (
        "Disable every user that authenticated from the source IP in "
        "the incident's window."
    )
    steps: tuple[PlaybookStep, ...] = (
        PlaybookStep(
            action_id="disable_user",
            target_kind="all_actors",
            description="Disable every actor in the incident.",
            on_failure="continue",
        ),
        PlaybookStep(
            action_id="revoke_token",
            target_kind="all_actors",
            description="Revoke active tokens for every actor.",
            on_failure="continue",
        ),
    )


class RansomwareResponsePlaybook(Playbook):
    """The destructive chain — isolate hosts, disable service accounts."""

    playbook_id = "ransomware_response"
    name = "Ransomware response"
    description = (
        "Isolate every host the incident touched; disable every service "
        "account that wrote the suspicious files."
    )
    steps: tuple[PlaybookStep, ...] = (
        PlaybookStep(
            action_id="isolate_host",
            target_kind="all_targets",
            description="Isolate every host touched by the incident.",
            on_failure="continue",
        ),
        PlaybookStep(
            action_id="disable_user",
            target_kind="all_actors",
            description="Disable every actor — usually service accounts.",
            on_failure="continue",
        ),
    )


# ── playbook registry ───────────────────────────────────────────────────────


_REGISTRY: dict[str, type[Playbook]] = {}


def register_playbook(cls: type[Playbook]) -> type[Playbook]:
    """Register a :class:`Playbook` under its ``playbook_id``."""
    if not cls.playbook_id:
        raise ValueError(f"{cls.__name__}.playbook_id is empty")
    _REGISTRY[cls.playbook_id] = cls
    return cls


def get_playbook(playbook_id: str) -> Playbook:
    """Construct a :class:`Playbook` by id. Raises ``KeyError``."""
    cls = _REGISTRY[playbook_id]
    return cls()


def list_playbooks() -> list[str]:
    return list(_REGISTRY.keys())


# Auto-register the shipped playbooks.
for _cls in (
    CompromiseResponsePlaybook,
    CredentialStuffingPlaybook,
    RansomwareResponsePlaybook,
):
    register_playbook(_cls)


# ── the dispatcher ─────────────────────────────────────────────────────────


class PlaybookDispatcher:
    """The dispatcher that pairs incidents with playbooks.

    The dispatcher maps an incident's attack ids to the playbook that
    is the right response. The default mapping covers the four
    shipped playbooks:

    * ``T1078``, ``T1110``, ``T1550`` → ``compromise_response``.
    * ``T1110`` with no other technique → ``credential_stuffing``.
    * ``T1485``, ``T1486``, ``T1490`` → ``ransomware_response``.
    """

    def __init__(
        self,
        *,
        actions: Mapping[str, Action] | None = None,
        playbook_ids: Sequence[str] | None = None,
    ) -> None:
        # Default action registry — one instance per action. The
        # dispatcher's actions persist across playbook runs so the
        # ``already_acted`` short-circuit works.
        self.actions: dict[str, Action] = dict(actions or {
            action_id: get_action(action_id)
            for action_id in (
                "disable_user",
                "isolate_host",
                "revoke_token",
                "quarantine_email",
            )
        })
        self.playbook_ids: tuple[str, ...] = tuple(playbook_ids or tuple())

    def dispatch(self, incident: Incident) -> PlaybookResult | None:
        """Pick a playbook and run it.

        ``None`` if no playbook matches the incident's attack ids.
        Returns the result of the first matching playbook, in the
        order they were registered.

        Default routing by attack id:

        * ``T1110`` → ``credential_stuffing``.
        * ``T1485``, ``T1486``, ``T1490`` → ``ransomware_response``.
        * Any other escalation technique (``T1078``, ``T1550``,
          ``T1556``, ``T1078.004``, ``T1098``, ``T1098.001``,
          ``T1098.003``, ``T1531``, ``T1136.003``, ``T1548.005``,
          ``T1070.001``, ``T1562.001``, ``T1578`` series,
          ``T1566``, ``T1053``, ``T1003``, ``T1071``,
          ``T1568`` series) → ``compromise_response``.

        The first match wins.
        """
        if self.playbook_ids:
            for pid in self.playbook_ids:
                playbook = get_playbook(pid)
                return playbook.run(incident, self.actions)
        incident_attacks = set(incident.attack_ids)
        if "T1110" in incident_attacks:
            playbook = get_playbook("credential_stuffing")
            return playbook.run(incident, self.actions)
        if incident_attacks & {"T1485", "T1486", "T1490"}:
            playbook = get_playbook("ransomware_response")
            return playbook.run(incident, self.actions)
        # Everything else escalation-worthy routes to compromise_response.
        compromise_techniques = {
            "T1078", "T1550", "T1556",
            "T1078.004", "T1098", "T1098.001", "T1098.003",
            "T1531", "T1136.003", "T1548.005",
            "T1070.001", "T1562.001", "T1562.004",
            "T1578.001", "T1578.002", "T1578.003",
            "T1566.002", "T1053.005", "T1003.001",
            "T1071.004", "T1568.002",
        }
        if incident_attacks & compromise_techniques:
            playbook = get_playbook("compromise_response")
            return playbook.run(incident, self.actions)
        return None


__all__ = [
    "CompromiseResponsePlaybook",
    "CredentialStuffingPlaybook",
    "Playbook",
    "PlaybookDispatcher",
    "PlaybookResult",
    "PlaybookStep",
    "RansomwareResponsePlaybook",
    "get_playbook",
    "list_playbooks",
    "register_playbook",
]

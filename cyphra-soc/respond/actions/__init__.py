"""Response actions — atomic containment operations.

Every action is the smallest unit of containment: disable a user,
isolate a host, revoke a token, quarantine an email. Actions are
*idempotent* — calling ``disable_user`` twice has the same effect as
calling it once, with the second call recording ``already_acted``
rather than raising.

An action is wrapped in a result dataclass that carries:

* The action's id and human name.
* ``status`` — ``success``, ``already_acted``, ``pending``,
  ``failed``.
* ``applied_at`` and ``rolled_back_at`` — the monotonic clock.
* ``details`` — a free-form dict the connector layer fills with
  vendor-specific data (the ticket number, the API response, etc).

The shipped actions cover the four most common containment primitives:

* ``DisableUserAction`` — block sign-in for an Entra user.
* ``IsolateHostAction`` — remove a host from the network.
* ``RevokeTokenAction`` — revoke an OAuth token / session.
* ``QuarantineEmailAction`` — move a malicious email to a quarantine
  mailbox.

Each is a thin wrapper around a vendor connector call; the connector
layer is responsible for the actual API round-trip. The action layer
adds the idempotency, the audit trail, and the rollback.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Mapping


class ActionStatus(Enum):
    """The terminal state of an action."""

    SUCCESS = "success"
    ALREADY_ACTED = "already_acted"
    PENDING = "pending"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ActionResult(dict):
    """The outcome of one action call, shaped as a dict so the audit chain
    can serialise it without further conversion.

    Keys: ``action_id``, ``name``, ``status``, ``applied_at``,
    ``rolled_back_at``, ``details``, ``result_uuid``.
    """

    def __init__(
        self,
        *,
        action_id: str,
        name: str,
        status: ActionStatus,
        applied_at: float,
        rolled_back_at: float = 0.0,
        details: Mapping[str, Any] | None = None,
        result_uuid: str | None = None,
    ) -> None:
        super().__init__(
            action_id=action_id,
            name=name,
            status=status,
            applied_at=applied_at,
            rolled_back_at=rolled_back_at,
            details=dict(details or {}),
            result_uuid=result_uuid or str(uuid.uuid4()),
        )

    @property
    def action_id(self) -> str:
        return self["action_id"]

    @property
    def status(self) -> ActionStatus:
        return self["status"]


class Action:
    """The base class for a containment action.

    A subclass declares ``action_id`` and ``name``, implements
    :meth:`_do` and :meth:`_undo`. The framework calls ``do`` on the
    incident's actor/target keys, and ``undo`` if the analyst
    reverses the disposition.
    """

    action_id: str = ""
    name: str = ""
    description: str = ""

    def __init__(self, *, clock: Any = time.time) -> None:
        self.clock = clock
        self._applied: dict[tuple[str, str], ActionResult] = {}

    def do(self, target_key: str, *, details: Mapping[str, Any] | None = None) -> ActionResult:
        """Apply the action. Idempotent on ``target_key``."""
        existing = self._applied.get(self._key(target_key))
        if existing is not None:
            return existing
        result = self._do(target_key, dict(details or {}))
        if result["applied_at"] == 0.0:
            result["applied_at"] = self.clock()
        self._applied[self._key(target_key)] = result
        return result

    def undo(self, target_key: str) -> ActionResult | None:
        """Reverse a previous ``do``. Returns the new state.

        ``None`` if the action has not been applied on this target.
        """
        prior = self._applied.get(self._key(target_key))
        if prior is None:
            return None
        new_result = self._undo(target_key, prior)
        new_result["rolled_back_at"] = self.clock()
        if new_result.status is ActionStatus.ROLLED_BACK:
            self._applied.pop(self._key(target_key), None)
        else:
            self._applied[self._key(target_key)] = new_result
        return new_result

    def is_applied(self, target_key: str) -> bool:
        return self._key(target_key) in self._applied

    def result_for(self, target_key: str) -> ActionResult | None:
        return self._applied.get(self._key(target_key))

    def applied_targets(self) -> list[str]:
        return [key for (_, key), _ in self._applied.items()]

    def _key(self, target_key: str) -> tuple[str, str]:
        return (self.action_id, target_key)

    def _do(self, target_key: str, details: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.PENDING,
            applied_at=self.clock(),
            details=dict(details),
        )

    def _undo(self, target_key: str, prior: ActionResult) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.ROLLED_BACK,
            applied_at=prior["applied_at"],
            details=dict(prior["details"]),
        )


class DisableUserAction(Action):
    """Block sign-in for a user — the most common containment primitive.

    In production this hits Entra ID's
    ``users/<id>/revokeSignInSessions`` via ``GraphConnector`` or its
    equivalent. The shipped implementation is a stub that records
    the action; the connector layer replaces it at deployment.
    """

    action_id = "disable_user"
    name = "Disable user sign-in"
    description = "Revoke the user's active sign-in sessions."

    def _do(self, target_key: str, details: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.SUCCESS,
            applied_at=self.clock(),
            details={
                "target": target_key,
                "method": "revoke_sign_in_sessions",
                **details,
            },
        )

    def _undo(self, target_key: str, prior: ActionResult) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.ROLLED_BACK,
            applied_at=prior["applied_at"],
            details=dict(prior["details"]),
        )


class IsolateHostAction(Action):
    """Remove a host from the network.

    The shipped implementation flips a Defender-for-Endpoint
    ``machineIsolation`` action; the connector layer fills the rest.
    """

    action_id = "isolate_host"
    name = "Isolate host"
    description = "Cut the host off from the network."

    def _do(self, target_key: str, details: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.SUCCESS,
            applied_at=self.clock(),
            details={
                "target": target_key,
                "method": "defender_isolate",
                **details,
            },
        )

    def _undo(self, target_key: str, prior: ActionResult) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.ROLLED_BACK,
            applied_at=prior["applied_at"],
            details={**prior["details"], "method": "defender_unisolate"},
        )


class RevokeTokenAction(Action):
    """Revoke an OAuth / SAML token or session.

    Token revocation is *permanent* — undo returns ``FAILED`` because
    there is nothing to reverse. The user re-authenticates to obtain
    a new token; the framework records the failed undo in the audit
    trail.
    """

    action_id = "revoke_token"
    name = "Revoke token"
    description = "Invalidate the OAuth token by id."

    def _do(self, target_key: str, details: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.SUCCESS,
            applied_at=self.clock(),
            details={
                "target": target_key,
                "method": "token_revoke",
                **details,
            },
        )

    def _undo(self, target_key: str, prior: ActionResult) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.FAILED,
            applied_at=prior["applied_at"],
            details={**prior["details"], "reason": "token_revocation_is_permanent"},
        )


class QuarantineEmailAction(Action):
    """Move a malicious email to a quarantine mailbox.

    The shipped implementation is a stub; the connector layer
    integrates with the M365 quarantine API.
    """

    action_id = "quarantine_email"
    name = "Quarantine email"
    description = "Move the email message out of every recipient's inbox."

    def _do(self, target_key: str, details: dict[str, Any]) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.SUCCESS,
            applied_at=self.clock(),
            details={
                "target": target_key,
                "method": "m365_quarantine",
                **details,
            },
        )

    def _undo(self, target_key: str, prior: ActionResult) -> ActionResult:
        return ActionResult(
            action_id=self.action_id,
            name=self.name,
            status=ActionStatus.ROLLED_BACK,
            applied_at=prior["applied_at"],
            details={**prior["details"], "method": "m365_release"},
        )


# ── the action registry ────────────────────────────────────────────────────


_REGISTRY: dict[str, type[Action]] = {}


def register(cls: type[Action]) -> type[Action]:
    """Register an Action subclass under its ``action_id``.

    A deployment adds vendor-specific actions by calling ``register``
    at startup. The shipped actions are registered automatically.
    """
    if not cls.action_id:
        raise ValueError(f"{cls.__name__}.action_id is empty")
    _REGISTRY[cls.action_id] = cls
    return cls


def get_action(action_id: str, *, clock: Any = time.time) -> Action:
    """Construct an :class:`Action` by ``action_id``.

    Raises ``KeyError`` if no action is registered under that id.
    """
    cls = _REGISTRY[action_id]
    return cls(clock=clock)


def list_actions() -> list[str]:
    """The action ids registered so far."""
    return list(_REGISTRY.keys())


# Auto-register the shipped actions.
for _cls in (DisableUserAction, IsolateHostAction, RevokeTokenAction, QuarantineEmailAction):
    register(_cls)


__all__ = [
    "Action",
    "ActionResult",
    "ActionStatus",
    "DisableUserAction",
    "IsolateHostAction",
    "QuarantineEmailAction",
    "RevokeTokenAction",
    "get_action",
    "list_actions",
    "register",
]

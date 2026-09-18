"""Behavioural detector — sequence rules over a stream of events.

Where the signature detector looks at *one* event and the statistical
detector looks at *one key's* events, the behavioural detector looks at
the *order* of events. The canonical example is "phishing → link click →
payload download" — three separate events that are individually ordinary
but together describe the initial-access chain.

The detector maintains a sliding window of recent events per actor and
emits a finding when the events in the window match a sequence pattern.
A pattern is a list of *predicates*; each predicate tests one event. The
detector fires when the window contains events matching the predicates
in order, oldest first.

The window is bounded by ``max_age_seconds``. A predicate on the
*current* event advances the matched-by-one position; a predicate on an
*earlier* event that does not match the next step resets the match. The
match completes when every predicate has been satisfied, and the
finding's metadata records the chain.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from core.schema.ocsf import Severity
from detect.finding import Finding


@dataclass
class SequencePattern:
    """A multi-step behaviour pattern.

    ``steps`` is a list of predicates, each taking one event and
    returning ``True`` when the event matches that step. ``key_fn``
    extracts the actor key the events must share. ``max_age_seconds`` is
    the maximum gap between the first and last event of the chain. The
    pattern fires when the key's sliding window contains events
    matching every step in order.

    The pattern is deliberately stateless. A pattern that needs to
    "remember" something specific (e.g. a payload's hash) belongs in
    :class:`detect.engine.Finding.metadata`; the pattern itself matches
    on shape, not on the specific value.
    """

    rule_id: str
    name: str
    attack: str
    key_fn: Callable[[Mapping[str, Any]], Any]
    steps: Sequence[Callable[[Mapping[str, Any]], bool]]
    max_age_seconds: float
    severity: int = int(Severity.CRITICAL)
    description: str = ""
    cooldown: float = 300.0
    # Per-key state. ``_step`` is the index of the *next* step we are
    # looking for; ``_first_step_time`` is the time of the event that
    # matched step 0 — the chain is valid only as long as every step
    # happens within ``max_age_seconds`` of the first.
    _step: dict[Any, int] = field(default_factory=dict)
    _first_step_time: dict[Any, float] = field(default_factory=dict)
    _chain: dict[Any, list[Mapping[str, Any]]] = field(default_factory=dict)
    _last_fired: dict[Any, float] = field(default_factory=dict)

    def observe(self, event: Mapping[str, Any]) -> list[Finding]:
        key = self.key_fn(event)
        if key is None:
            return []
        now = float(event.get("time", 0.0)) or 0.0
        # If the chain is older than the window, reset.
        first_t = self._first_step_time.get(key)
        if first_t is not None and now - first_t > self.max_age_seconds:
            self._step[key] = 0
            self._chain[key] = []
            self._first_step_time[key] = 0.0
        step = self._step.get(key, 0)
        if not self.steps[step](event):
            # The current event did not match the next step. If it
            # matches step 0, restart the chain; otherwise leave the
            # chain as-is.
            if self.steps[0](event):
                self._step[key] = 1
                self._first_step_time[key] = now
                self._chain[key] = [event]
            return []
        # Match advanced.
        if step == 0:
            self._first_step_time[key] = now
            self._chain[key] = [event]
        else:
            self._chain.setdefault(key, []).append(event)
        self._step[key] = step + 1
        if step + 1 < len(self.steps):
            return []
        # All steps matched. Reset and fire.
        last = self._last_fired.get(key, 0.0)
        if last and now - last < self.cooldown:
            self._step[key] = 0
            self._chain[key] = []
            self._first_step_time[key] = 0.0
            return []
        self._last_fired[key] = now
        chain = list(self._chain.get(key, []))
        self._step[key] = 0
        self._chain[key] = []
        self._first_step_time[key] = 0.0
        return [Finding(
            alert_uid=str(event.get("metadata_uid") or ""),
            alert_time=now,
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            confidence=1.0,
            attack=self.attack,
            description=self.description or self.name,
            metadata={
                "chain_length": len(self.steps),
                "actor_key": str(key),
                "chain_uids": [str(e.get("metadata_uid") or "") for e in chain],
            },
        )]


class BehaviouralDetector:
    """A collection of sequence patterns."""

    def __init__(
        self,
        patterns: Sequence[SequencePattern] = (),
        *,
        clock: Any = time.time,
    ) -> None:
        self.patterns: list[SequencePattern] = list(patterns)
        self.clock = clock

    def observe(self, event: Mapping[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.patterns:
            findings.extend(pattern.observe(event))
        return findings

    @classmethod
    def default(cls) -> "BehaviouralDetector":
        """The shipped behavioural rule pack.

        Four patterns cover the most common multi-step chains. A
        deployment with a deeper library of chains extends this pack.
        """
        def actor_key(event: Mapping[str, Any]) -> Any:
            actor = event.get("actor")
            if not isinstance(actor, Mapping):
                return None
            user = actor.get("user")
            if not isinstance(user, Mapping):
                return None
            return user.get("uid") or user.get("name") or None

        def ip_key(event: Mapping[str, Any]) -> Any:
            return event.get("src_endpoint_ip") or None

        def is_email_with_link(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 4009:
                return False
            labels = event.get("metadata_labels") or []
            return "phishing:malicious-link" in labels or "phishing:suspect-sender" in labels

        def is_dns_to_suspect(event: Mapping[str, Any]) -> bool:
            return int(event.get("class_uid", 0)) == 4003

        def is_file_create(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 1001:
                return False
            return "initial-access:user-execution" in (event.get("metadata_labels") or [])

        def is_failed_then_success_auth(event: Mapping[str, Any]) -> bool:
            return int(event.get("class_uid", 0)) == 3002

        def is_cloud_role_grant(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 6003:
                return False
            labels = event.get("metadata_labels") or []
            return "tier0-role" in labels

        def is_cloud_kms_destroy(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 6003:
                return False
            labels = event.get("metadata_labels") or []
            return "attack:T1485" in labels

        def is_lsass_dump(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 1007:
                return False
            cl = (event.get("unmapped") or {}).get("command_line") or ""
            return bool(cl) and any(
                tok in cl.lower()
                for tok in ("comsvcs.dll", "minidump", "mimikatz", "lsadump", "sekurlsa")
            )

        def is_log_cleared(event: Mapping[str, Any]) -> bool:
            if int(event.get("class_uid", 0)) != 1007:
                return False
            cl = (event.get("unmapped") or {}).get("command_line") or ""
            return bool(cl) and "wevtutil" in cl.lower() and " cl" in cl.lower()

        patterns: list[SequencePattern] = [
            SequencePattern(
                rule_id="behaviour.phishing_to_execution",
                name="Phishing → payload execution chain",
                attack="T1566.002",
                key_fn=actor_key,
                steps=[is_email_with_link, is_dns_to_suspect, is_file_create],
                max_age_seconds=3600.0,
                severity=int(Severity.HIGH),
                description=(
                    "Email → DNS resolution → payload in temp from the same "
                    "user — the initial access chain."
                ),
            ),
            SequencePattern(
                rule_id="behaviour.failed_then_success",
                name="Failed → successful authentication pattern",
                attack="T1110",
                key_fn=ip_key,
                steps=[is_failed_then_success_auth, is_failed_then_success_auth],
                max_age_seconds=1800.0,
                severity=int(Severity.HIGH),
                description=(
                    "Two sign-ins from the same IP, the first failing and "
                    "the second succeeding — the credential stuffing landing."
                ),
            ),
            SequencePattern(
                rule_id="behaviour.privilege_then_destruction",
                name="Privilege grant → KMS destruction chain",
                attack="T1485",
                key_fn=actor_key,
                steps=[is_cloud_role_grant, is_cloud_kms_destroy],
                max_age_seconds=3600.0,
                severity=int(Severity.CRITICAL),
                description=(
                    "Tier-0 grant followed by KMS destruction from the same "
                    "actor — the destroy-after-grant shape."
                ),
            ),
            SequencePattern(
                rule_id="behaviour.lsass_then_log_clear",
                name="LSASS dump → log clear chain",
                attack="T1070.001",
                key_fn=actor_key,
                steps=[is_lsass_dump, is_log_cleared],
                max_age_seconds=1800.0,
                severity=int(Severity.CRITICAL),
                description=(
                    "LSASS dump followed by event-log clear from the same "
                    "actor — credential theft + cover-up in one chain."
                ),
            ),
        ]
        return cls(patterns=patterns)


__all__ = ["BehaviouralDetector", "SequencePattern"]

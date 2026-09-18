"""Statistical detector — rolling-window rate rules.

A statistical rule needs *history*, not just one event. The detector keeps
a per-bucket counter over a sliding window and emits a finding when the
counter exceeds a threshold.

Two rule kinds are common enough to ship:

* **Rate rule** — ``N`` events from ``K`` distinct values in a window.
  The classic "many failed sign-ins from one IP" rule.
* **Burst rule** — ``N`` events of the same kind in a window, regardless
  of the actor. The classic "many file deletions in one hour" rule.

The state is in-memory. A platform restart resets the windows, which is
acceptable for rate detectors — a rate detector that survives a restart
would need a different storage layer, and the *false negative cost* of
missing a 60-second burst after a restart is bounded.

The detector's :meth:`observe` returns any findings the state produced;
the engine attaches them to the report. The detector never raises on a
single event.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from core.schema.ocsf import Severity
from detect.finding import Finding


@dataclass
class RateRule:
    """A rate-based rule.

    ``key_fn`` extracts the bucket key from an event (``src_endpoint.ip``,
    ``actor.user.uid``, etc.). ``predicate`` decides whether an event is
    relevant to this rule at all — events that don't satisfy it do not
    enter the bucket. ``count`` is the trigger threshold. ``window`` is
    the rolling window in seconds. ``rule_id`` and ``name`` populate
    the finding. ``attack`` is the ATT&CK technique.

    A rate rule fires when ``len(window) >= count``, where ``window`` is
    the events of *this* rule's kind with the *same* key in the *last*
    ``window`` seconds. The detection engine hands every event to every
    rate rule; the rule itself decides whether the event's bucket is
    relevant.
    """

    rule_id: str
    name: str
    attack: str
    key_fn: Callable[[Mapping[str, Any]], Any]
    count: int
    window: float
    severity: int = int(Severity.HIGH)
    description: str = ""
    predicate: Callable[[Mapping[str, Any]], bool] = lambda e: True
    # Cooldown prevents the same bucket firing the same rule every
    # observation; without it the SOC console gets one alert per event
    # after the threshold, which is unreadable.
    cooldown: float = 60.0
    # Internal state — kept here so each rule is self-contained.
    _buckets: dict[Any, deque[float]] = field(default_factory=dict)
    _last_fired: dict[Any, float] = field(default_factory=dict)

    def observe(self, event: Mapping[str, Any]) -> list[Finding]:
        if not self.predicate(event):
            return []
        key = self.key_fn(event)
        if key is None:
            return []
        now = float(event.get("time", 0.0)) or 0.0
        dq = self._buckets.setdefault(key, deque())
        dq.append(now)
        # Drop entries outside the window.
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) < self.count:
            return []
        last = self._last_fired.get(key, 0.0)
        if last and now - last < self.cooldown:
            return []
        self._last_fired[key] = now
        return [Finding(
            alert_uid=str(event.get("metadata_uid") or ""),
            alert_time=now,
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            confidence=min(1.0, len(dq) / (self.count * 2)),
            attack=self.attack,
            description=self.description or f"{self.name}: {len(dq)} events in {self.window:.0f}s",
            metadata={"count": len(dq), "window_seconds": self.window, "key": str(key)},
        )]


@dataclass
class BurstRule:
    """A *kind*-level rule.

    Fires when ``N`` events of the rule's own kind occur within a
    window, regardless of bucket. A burst detector is appropriate when
    the signal is "many events happened" rather than "many events
    happened from one actor".

    ``predicate`` decides whether an event is relevant (``lambda e:
    e.get("class_uid") == 6003``).
    """

    rule_id: str
    name: str
    attack: str
    predicate: Callable[[Mapping[str, Any]], bool]
    count: int
    window: float
    severity: int = int(Severity.MEDIUM)
    description: str = ""
    cooldown: float = 60.0
    _events: deque[float] = field(default_factory=deque)
    _last_fired: float = 0.0

    def observe(self, event: Mapping[str, Any]) -> list[Finding]:
        if not self.predicate(event):
            return []
        now = float(event.get("time", 0.0)) or 0.0
        self._events.append(now)
        while self._events and now - self._events[0] > self.window:
            self._events.popleft()
        if len(self._events) < self.count:
            return []
        if self._last_fired and now - self._last_fired < self.cooldown:
            return []
        self._last_fired = now
        return [Finding(
            alert_uid=str(event.get("metadata_uid") or ""),
            alert_time=now,
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            confidence=min(1.0, len(self._events) / (self.count * 2)),
            attack=self.attack,
            description=self.description or f"{self.name}: {len(self._events)} events in {self.window:.0f}s",
            metadata={"count": len(self._events), "window_seconds": self.window},
        )]


class StatisticalDetector:
    """A collection of rate and burst rules."""

    def __init__(
        self,
        rate_rules: Sequence[RateRule] = (),
        burst_rules: Sequence[BurstRule] = (),
        *,
        clock: Any = time.time,
    ) -> None:
        self.rate_rules: list[RateRule] = list(rate_rules)
        self.burst_rules: list[BurstRule] = list(burst_rules)
        self.clock = clock

    def observe(self, event: Mapping[str, Any]) -> list[Finding]:
        """Every rule that fires on ``event``."""
        findings: list[Finding] = []
        for rule in self.rate_rules:
            findings.extend(rule.observe(event))
        for rule in self.burst_rules:
            findings.extend(rule.observe(event))
        return findings

    @classmethod
    def default(cls) -> "StatisticalDetector":
        """The shipped statistical rule pack.

        Six rules cover the most common "many events" patterns. The
        predicate and key functions are simple — a deployment that wants
        more rules appends them; the shipped pack is the floor.
        """
        def ip_key(event: Mapping[str, Any]) -> Any:
            return event.get("src_endpoint_ip") or None

        def actor_key(event: Mapping[str, Any]) -> Any:
            return (
                (event.get("actor") or {}).get("user", {}).get("uid")
                if isinstance(event.get("actor"), Mapping) else None
            ) or None

        def is_auth(event: Mapping[str, Any]) -> bool:
            return int(event.get("class_uid", 0)) == 3002

        def is_failed_auth(event: Mapping[str, Any]) -> bool:
            return is_auth(event) and int(event.get("status_id", 1)) == 2

        def is_api(event: Mapping[str, Any]) -> bool:
            return int(event.get("class_uid", 0)) == 6003

        rate_rules: list[RateRule] = [
            RateRule(
                rule_id="stat.failed_signin_burst",
                name="Failed sign-in burst from one source",
                attack="T1110",
                key_fn=ip_key,
                count=10,
                window=300.0,
                severity=int(Severity.HIGH),
                description=(
                    "10 or more failed sign-ins from a single IP in 5 "
                    "minutes — credential stuffing or brute force."
                ),
                predicate=is_failed_auth,
            ),
            RateRule(
                rule_id="stat.actor_lateral_burst",
                name="Authenticated operations burst from one user",
                attack="T1078",
                key_fn=actor_key,
                count=50,
                window=600.0,
                severity=int(Severity.MEDIUM),
                description=(
                    "50 or more API calls from one user in 10 minutes — "
                    "unusual volume that often precedes an exfil attempt."
                ),
                predicate=is_api,
            ),
        ]
        burst_rules: list[BurstRule] = [
            BurstRule(
                rule_id="stat.cloud_tier0_grants_burst",
                name="Multiple tier-0 grants in a short window",
                attack="T1098.003",
                predicate=lambda e: "tier0-role" in (e.get("metadata_labels") or []),
                count=3,
                window=900.0,
                severity=int(Severity.CRITICAL),
                description=(
                    "Three or more tier-0 role grants in 15 minutes is the "
                    "automated-account-creation shape."
                ),
            ),
            BurstRule(
                rule_id="stat.dns_query_burst",
                name="DNS query burst to a single domain",
                attack="T1071.004",
                predicate=lambda e: int(e.get("class_uid", 0)) == 4003,
                count=30,
                window=300.0,
                severity=int(Severity.MEDIUM),
                description=(
                    "30 or more DNS queries in 5 minutes is the C2 beacon "
                    "shape."
                ),
            ),
        ]
        return cls(rate_rules=rate_rules, burst_rules=burst_rules)


__all__ = [
    "BurstRule",
    "RateRule",
    "StatisticalDetector",
]

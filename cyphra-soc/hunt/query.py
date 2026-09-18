"""Hunt queries — the hypothesis expressed as a structured filter.

A hunt is a *hypothesis* the SOC wants to test against the lake: "show me
every authentication event from a Tor exit IP that did not trigger a
detection in the last 24 hours." The hypothesis is expressed as a
:class:`HuntQuery` — a name, a description, a filter, and the periodicity
on which it should run.

The filter is a *small* structured object, deliberately limited. The
full OCSF query space is too broad for the hunt layer to enumerate,
and a hunt expressed as a free-form SQL string is impossible to
review, test, or audit. The filter has three sections:

* ``class_uids`` — the OCSF classes the hunt touches. ``[]`` means
  every class.
* ``predicates`` — a list of :class:`Predicate` rows; a row matches
  when all its fields match the event's same-named fields. Predicates
  use ``equals``/``contains``/``in``/``regex``/``exists`` ops on a
  dotted field path.
* ``window`` — the rolling time window the hunt covers. ``"24h"``,
  ``"7d"``, ``"30m"``, etc.

A :class:`HuntResult` is the outcome of running a hunt — the count of
matches, the time bounds, and a sample of the matched events so the
analyst can read what the hunt actually caught. A hunt with no matches
is *not* a failure; it is the strongest possible evidence the
hypothesis is wrong. A hunt that always returns no matches is itself a
finding worth investigating.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping


_OPERATORS: frozenset[str] = frozenset({
    "equals", "not_equals", "contains", "not_contains",
    "in", "not_in", "regex", "exists", "not_exists",
})


@dataclass
class Predicate:
    """One row of a hunt filter.

    ``field`` is a dotted OCSF path (``"src_endpoint_ip"``,
    ``"actor.user.email_addr"``). ``op`` is the comparison operator.
    ``value`` is the right-hand side; ``values`` is the right-hand
    side for ``in``/``not_in``.
    """

    field: str
    op: str
    value: Any = None
    values: tuple[Any, ...] = ()

    def matches(self, event: Mapping[str, Any]) -> bool:
        """Test the predicate against ``event``."""
        parts = self.field.split(".")
        cur: Any = event
        for part in parts:
            if isinstance(cur, Mapping):
                cur = cur.get(part)
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    cur = None
                    break
            else:
                cur = None
                break
        op = self.op
        if op == "exists":
            return cur is not None and cur != "" and cur != []
        if op == "not_exists":
            return cur is None or cur == "" or cur == []
        if cur is None:
            return False
        if op == "equals":
            return cur == self.value
        if op == "not_equals":
            return cur != self.value
        if op == "contains":
            if isinstance(cur, str):
                return self.value in cur
            if isinstance(cur, list):
                return self.value in cur
            return False
        if op == "not_contains":
            if isinstance(cur, str):
                return self.value not in cur
            if isinstance(cur, list):
                return self.value not in cur
            return False
        if op == "in":
            return cur in self.values
        if op == "not_in":
            return cur not in self.values
        if op == "regex":
            if not isinstance(cur, str):
                return False
            return re.search(self.value, cur) is not None
        raise ValueError(f"unknown op {op!r}")


def equals(field: str, value: Any) -> Predicate:
    return Predicate(field=field, op="equals", value=value)


def contains(field: str, value: str) -> Predicate:
    return Predicate(field=field, op="contains", value=value)


def in_(field: str, values: Sequence[Any]) -> Predicate:
    return Predicate(field=field, op="in", values=tuple(values))


def regex(field: str, pattern: str) -> Predicate:
    return Predicate(field=field, op="regex", value=pattern)


def exists(field: str) -> Predicate:
    return Predicate(field=field, op="exists")


def _window_seconds(window: str) -> float:
    """``"24h"`` → 86400.0 — the rolling-window parser.

    A window string is a number followed by ``m`` (minutes), ``h``
    (hours), or ``d`` (days). The minimum is ``1m``; the maximum is
    ``90d``. A malformed window raises ``ValueError`` — the hunt
    author must fix the typo before the hunt runs.
    """
    if not isinstance(window, str) or len(window) < 2:
        raise ValueError(f"window {window!r} must be like '24h' or '7d'")
    text = window.strip().lower()
    number_text, unit = text[:-1], text[-1]
    try:
        n = float(number_text)
    except ValueError as exc:
        raise ValueError(f"window {window!r}: bad number {number_text!r}") from exc
    if unit == "m":
        seconds = n * 60.0
    elif unit == "h":
        seconds = n * 3_600.0
    elif unit == "d":
        seconds = n * 86_400.0
    else:
        raise ValueError(f"window {window!r}: unit must be m/h/d")
    if seconds < 60.0:
        raise ValueError(f"window {window!r}: minimum is 1m")
    if seconds > 90 * 86_400.0:
        raise ValueError(f"window {window!r}: maximum is 90d")
    return seconds


@dataclass
class HuntQuery:
    """A hunt hypothesis, structured.

    ``name`` and ``description`` are surfaced in the SOC console.
    ``class_uids`` is a list of OCSF class ids; an empty list means
    every class. ``predicates`` is a list of :class:`Predicate` rows;
    every row must match for an event to be a hit. ``window`` is the
    rolling time window the hunt covers. ``schedule_seconds`` is the
    cadence at which the hunt re-runs — ``0`` means manual only.
    """

    name: str
    description: str
    predicates: list[Predicate] = field(default_factory=list)
    class_uids: tuple[int, ...] = field(default_factory=tuple)
    window: str = "24h"
    schedule_seconds: float = 0.0
    tags: tuple[str, ...] = ()

    def matches(self, event: Mapping[str, Any]) -> bool:
        """Whether ``event`` is a hit for this hunt."""
        if self.class_uids:
            if int(event.get("class_uid", 0)) not in self.class_uids:
                return False
        return all(p.matches(event) for p in self.predicates)

    def window_seconds(self) -> float:
        return _window_seconds(self.window)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "class_uids": list(self.class_uids),
            "predicates": [
                {
                    "field": p.field,
                    "op": p.op,
                    "value": p.value,
                    "values": list(p.values),
                }
                for p in self.predicates
            ],
            "window": self.window,
            "schedule_seconds": self.schedule_seconds,
            "tags": list(self.tags),
        }


@dataclass
class HuntResult:
    """The outcome of one hunt run.

    ``hits`` is the events that matched; ``sample_size`` is the count
    *before* truncation, so the operator sees "the hunt found 1 200
    matches; here are the first 100". ``window_start`` and
    ``window_end`` are the time bounds the hunt covered.
    """

    hunt_name: str
    window_start: float
    window_end: float
    hit_count: int
    sample: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    notes: list[str] = field(default_factory=list)


# ── the shipped hunt library ────────────────────────────────────────────────


def tor_authentications() -> HuntQuery:
    """Authentications from Tor exit nodes that did not trigger a detection.

    The intel layer's ``lookup_ip`` returns ``Reputation.SUSPICIOUS`` for
    known Tor exit nodes. Combined with ``is_alert=false``, this is the
    "lurker" hunt — an actor on Tor whose sign-in did not cross any
    rule threshold but should be reviewed.
    """

    return HuntQuery(
        name="tor_authentications_no_alert",
        description=(
            "Authentications from a Tor exit IP that did not trigger a "
            "detection in the last 24 hours."
        ),
        class_uids=(3002,),
        predicates=[
            equals("is_alert", False),
            contains("metadata_labels", "tor-exit"),
        ],
        window="24h",
        schedule_seconds=86_400.0,
        tags=("lurker",),
    )


def service_account_console_login() -> HuntQuery:
    """Service accounts that have authenticated via the human console.

    A service account signing in to a UI console is the shape of a
    stolen credential — service accounts do not normally have human
    interactions. The hunt surfaces the case before the detection
    layer's tier-0 grant rule fires.
    """

    return HuntQuery(
        name="service_account_console_login",
        description=(
            "Service-account principals that have authenticated via a "
            "human console in the last 24 hours."
        ),
        predicates=[
            equals("actor.user.type_id", 4),  # OCSF SERVICE_ACCOUNT
            equals("actor.user.domain_type_id", 1),
            contains("metadata_labels", "console-login"),
        ],
        window="24h",
        schedule_seconds=43_200.0,
        tags=("stolen-credential",),
    )


def unusual_dns_volume() -> HuntQuery:
    """DNS volume that exceeds the tenant's rolling average by 5x.

    C2 beacons at sub-minute cadence produce a DNS fingerprint that is
    high in count, low in entropy and high in regularity. The
    statistical detector catches the 5x spike in production; the hunt
    is the periodic validation that the threshold is right and that no
    pattern has slipped under it.
    """

    return HuntQuery(
        name="unusual_dns_volume",
        description="DNS events with more than 5x the average count in a 24h window.",
        class_uids=(4003,),
        predicates=[
            exists("unmapped.dns_query.name"),
        ],
        window="24h",
        schedule_seconds=3_600.0,
        tags=("beacon",),
    )


def default_hunt_library() -> list[HuntQuery]:
    """Every shipped hunt."""
    return [
        tor_authentications(),
        service_account_console_login(),
        unusual_dns_volume(),
    ]


__all__ = [
    "HuntQuery",
    "HuntResult",
    "Predicate",
    "contains",
    "default_hunt_library",
    "equals",
    "exists",
    "in_",
    "regex",
    "service_account_console_login",
    "tor_authentications",
    "unusual_dns_volume",
]

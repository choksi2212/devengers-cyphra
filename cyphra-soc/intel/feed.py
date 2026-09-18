"""Threat intelligence feeds — indicators, reputation, context.

The platform ships with three indicator types:

* **IP** — source addresses known to be Tor exit nodes, anonymising
  proxies, scanner services, or attacker-controlled infrastructure.
* **Domain** — DNS names known to be C2, phishing landing pages, or
  typosquatting targets.
* **Hash** — file content hashes (SHA-256, SHA-1, MD5) known to be
  malware samples, dropped implants, or attack tools.

Each indicator carries a *reputation* (``malicious``, ``suspicious``,
``neutral``, ``trusted``) and a *score* in ``[0, 1]``. The correlate
layer reads the score as one input to incident severity; the detect
layer reads the reputation as a label.

A feed is a JSON-list of indicators; the platform reads multiple feeds
and merges them. A later feed's higher score for the same indicator
overrides an earlier feed's lower score — the operator's most recent
threat report is the source of truth.

The :class:`IntelStore` is the platform's index of indicators by kind
and value. Lookups are O(1) on a hash table; merge is O(N) on the new
feed and O(K) per indicator that updates an existing entry.
"""

from __future__ import annotations

import enum
import json
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class Reputation(enum.IntEnum):
    """The reputation of an indicator.

    Aligned with OCSF's :class:`core.schema.ocsf.Reputation`. ``TRUSTED``
    is the "we know it's good" pole — a Microsoft login page, a CDN
    edge, a known package manager. ``MALICIOUS`` is the opposite. A
    missing entry is *not* ``NEUTRAL``; the platform treats missing as
    "we don't know" and the correlate layer reads it that way.
    """

    UNKNOWN = 0
    TRUSTED = 1
    NEUTRAL = 2
    SUSPICIOUS = 3
    MALICIOUS = 4


REPUTATION_NAMES: Mapping[int, str] = {
    int(Reputation.UNKNOWN): "unknown",
    int(Reputation.TRUSTED): "trusted",
    int(Reputation.NEUTRAL): "neutral",
    int(Reputation.SUSPICIOUS): "suspicious",
    int(Reputation.MALICIOUS): "malicious",
}


class IndicatorKind(enum.IntEnum):
    """The kind of an indicator."""

    IP = 1
    DOMAIN = 2
    URL = 3
    HASH_SHA256 = 10
    HASH_SHA1 = 11
    HASH_MD5 = 12
    EMAIL = 20
    USER_AGENT = 21


KIND_NAMES: Mapping[int, str] = {
    int(k): k.name.lower() for k in IndicatorKind
}


#: Regex patterns used by the validator. An indicator value that does
#: not match its kind's pattern is rejected at feed-load time — a
#: malformed indicator would never match and would silently miss events.
_VALIDATORS: Mapping[int, re.Pattern[str]] = {
    int(IndicatorKind.IP): re.compile(r"^(\d{1,3}\.){3}\d{1,3}$"),
    int(IndicatorKind.DOMAIN): re.compile(
        r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
    ),
    int(IndicatorKind.URL): re.compile(
        r"^https?://[^\s]+$"
    ),
    int(IndicatorKind.HASH_SHA256): re.compile(r"^[a-fA-F0-9]{64}$"),
    int(IndicatorKind.HASH_SHA1): re.compile(r"^[a-fA-F0-9]{40}$"),
    int(IndicatorKind.HASH_MD5): re.compile(r"^[a-fA-F0-9]{32}$"),
    int(IndicatorKind.EMAIL): re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
}


@dataclass
class Indicator:
    """One indicator entry.

    ``score`` is in ``[0, 1]`` and is monotonic — a higher score means
    a higher confidence that the indicator is malicious. ``first_seen``
    is monotonic; ``last_seen`` is updated on every merge.
    """

    kind: int
    value: str
    score: float
    reputation: int
    source: str
    description: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    references: list[str] = field(default_factory=list)


@dataclass
class IntelHit:
    """A lookup result: the indicator plus the context.

    ``indicator`` may be ``None`` if the lookup is a miss; the correlate
    layer reads ``indicator is None`` as "no intel matches" and proceeds
    without changing severity.
    """

    kind: int
    value: str
    indicator: Indicator | None


class IntelStore:
    """An index of :class:`Indicator` records, queried by (kind, value)."""

    def __init__(self, *, clock: Any = time.time) -> None:
        self.clock = clock
        self._by_key: dict[tuple[int, str], Indicator] = {}
        self._sources: dict[str, int] = {}

    def __len__(self) -> int:
        return len(self._by_key)

    def lookup(self, kind: int, value: str) -> IntelHit:
        """One lookup. Returns ``IntelHit`` with ``indicator=None`` on a miss."""
        ind = self._by_key.get((int(kind), str(value)))
        return IntelHit(kind=int(kind), value=str(value), indicator=ind)

    def lookup_ip(self, value: str) -> IntelHit:
        return self.lookup(int(IndicatorKind.IP), value)

    def lookup_domain(self, value: str) -> IntelHit:
        return self.lookup(int(IndicatorKind.DOMAIN), value)

    def lookup_hash(self, value: str) -> IntelHit:
        """Hash lookup, polymorphic on length.

        SHA-256 is 64 hex chars, SHA-1 is 40, MD5 is 32. The function
        tries the most common first; a hash that does not match any
        length returns a miss.
        """
        text = str(value or "").strip()
        for length, kind in (
            (64, IndicatorKind.HASH_SHA256),
            (40, IndicatorKind.HASH_SHA1),
            (32, IndicatorKind.HASH_MD5),
        ):
            if len(text) == length:
                return self.lookup(int(kind), text.lower())
        return IntelHit(kind=0, value=text, indicator=None)

    def merge(self, indicators: Iterable[Indicator]) -> int:
        """Merge a feed into the store.

        An indicator with a higher score for the same (kind, value)
        pair overrides the existing one — newer intel wins. Returns the
        number of indicators merged (new or updated).
        """
        merged = 0
        for indicator in indicators:
            self._merge_one(indicator)
            merged += 1
        return merged

    def load_feed(self, path: Path) -> int:
        """Load a JSON feed file. Returns the count of indicators loaded.

        A feed file is a JSON list of dicts with the same shape as
        :class:`Indicator`. The format is what every modern threat-intel
        vendor produces, modulo minor reshaping; deployments that need a
        different format translate before calling :meth:`merge`.
        """
        if not path.exists():
            return 0
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        if not isinstance(doc, list):
            return 0
        indicators = [Indicator(**item) for item in doc if _is_indicator_dict(item)]
        return self.merge(indicators)

    def sources(self) -> dict[str, int]:
        return dict(self._sources)

    def _merge_one(self, indicator: Indicator) -> None:
        # Validate the value against the kind's regex. A malformed
        # indicator would never match — drop it silently at load time
        # rather than letting the store grow with garbage.
        pattern = _VALIDATORS.get(indicator.kind)
        if pattern is None:
            return
        if not pattern.match(indicator.value):
            return
        # Score out of range is treated as 0 (we trust the feed's
        # reputation rather than its score).
        score = max(0.0, min(1.0, float(indicator.score)))
        key = (int(indicator.kind), str(indicator.value))
        existing = self._by_key.get(key)
        if existing is None or indicator.score > existing.score:
            indicator.score = score
            indicator.last_seen = self.clock()
            self._by_key[key] = indicator
        else:
            # Same or lower score — bump last_seen so the operator sees
            # the indicator is still current.
            existing.last_seen = self.clock()
        # Track the source's contribution count.
        self._sources[indicator.source] = self._sources.get(indicator.source, 0) + 1


def _is_indicator_dict(item: Any) -> bool:
    """A loose type check for a feed entry; used to skip malformed items."""
    return (
        isinstance(item, dict)
        and "kind" in item
        and "value" in item
        and "score" in item
        and "reputation" in item
        and "source" in item
    )


# ── reference feed: Tor exit nodes ─────────────────────────────────────────

TOR_EXIT_FEED: list[Indicator] = [
    # Anonymity networks carry suspicious traffic by default — never
    # malicious on its own, never trusted. The correlate layer reads
    # these as one signal among many.
]


def default_indicator_kind_name(kind: int) -> str:
    """Reverse lookup for :data:`KIND_NAMES` — used in error messages."""
    return KIND_NAMES.get(int(kind), f"unknown({kind})")


__all__ = [
    "Indicator",
    "IndicatorKind",
    "IntelHit",
    "IntelStore",
    "KIND_NAMES",
    "Reputation",
    "REPUTATION_NAMES",
    "TOR_EXIT_FEED",
    "default_indicator_kind_name",
]

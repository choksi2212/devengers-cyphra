"""The hunt runner — executes a :class:`HuntQuery` against an event stream.

A hunt runs against a stream of OCSF events. The stream is supplied
either as an iterable (the test path) or as a callable that takes a
window and returns events (the production path against the lake).

The runner's contract:

* It walks every event in the window.
* It applies the query's predicates to each.
* It records the matched events into the result's ``sample`` (capped at
  ``sample_limit``, default 100) and counts the matches.
* It returns the :class:`HuntResult`.

The runner does not write to the lake; the correlate engine consumes
the result's hits. A hit is "this hypothesis is true for these events" —
the correlate engine decides whether to emit a finding on top.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from hunt.query import HuntQuery, HuntResult


@dataclass
class HuntStats:
    """Counts the runner exposes via :meth:`stats`."""

    hunts_run: int = 0
    events_scanned: int = 0
    hits_total: int = 0
    last_error: str = ""


class HuntRunner:
    """The runner.

    A single instance is intended to live the lifetime of the platform;
    hunts are registered via :meth:`add` and executed via
    :meth:`run`. The runner's stats reflect the cumulative work since
    startup.
    """

    def __init__(
        self,
        *,
        sample_limit: int = 100,
        clock: Any = time.time,
    ) -> None:
        self.sample_limit = int(sample_limit)
        self.clock = clock
        self._hunts: dict[str, HuntQuery] = {}
        self.stats = HuntStats()

    def add(self, hunt: HuntQuery) -> None:
        """Register a hunt by name. A re-add with the same name replaces."""
        self._hunts[hunt.name] = hunt

    def get(self, name: str) -> HuntQuery | None:
        return self._hunts.get(name)

    def list_hunts(self) -> list[str]:
        return list(self._hunts.keys())

    def run(
        self,
        hunt: HuntQuery,
        events: Iterable[Mapping[str, Any]],
    ) -> HuntResult:
        """Execute ``hunt`` against ``events``.

        ``events`` may be a list (test path) or a generator (lake
        path). The window bounds are the smallest and largest ``time``
        seen across the events, defaulting to ``0.0`` if no events
        are scanned.
        """
        result = HuntResult(
            hunt_name=hunt.name,
            window_start=0.0,
            window_end=0.0,
            hit_count=0,
            started_at=self.clock(),
        )
        scanned = 0
        min_t: float | None = None
        max_t: float | None = None
        try:
            for event in events:
                scanned += 1
                when = float(event.get("time", 0.0))
                if min_t is None or when < min_t:
                    min_t = when
                if max_t is None or when > max_t:
                    max_t = when
                if hunt.matches(event):
                    result.hit_count += 1
                    if len(result.sample) < self.sample_limit:
                        result.sample.append(dict(event))
        except Exception as exc:  # noqa: BLE001
            self.stats.last_error = repr(exc)
        result.window_start = min_t or 0.0
        result.window_end = max_t or 0.0
        result.completed_at = self.clock()
        self.stats.hunts_run += 1
        self.stats.events_scanned += scanned
        self.stats.hits_total += result.hit_count
        if result.hit_count == 0:
            result.notes.append(
                "no matches — the hypothesis did not survive this window"
            )
        return result

    def run_named(
        self,
        name: str,
        events: Iterable[Mapping[str, Any]],
    ) -> HuntResult | None:
        """Look up and run a hunt by name."""
        hunt = self._hunts.get(name)
        if hunt is None:
            return None
        return self.run(hunt, events)

    def stats_dict(self) -> dict[str, Any]:
        return {
            "hunts_run": self.stats.hunts_run,
            "events_scanned": self.stats.events_scanned,
            "hits_total": self.stats.hits_total,
            "registered": len(self._hunts),
            "last_error": self.stats.last_error,
        }


__all__ = ["HuntRunner", "HuntStats"]

"""The correlate engine — grouping findings into incidents.

The engine consumes a stream of enriched findings and emits incidents.
A new finding joins an existing open incident if it shares a
``correlation_key`` with the incident and lands within
``merge_window_seconds`` of the incident's last update; otherwise the
engine opens a new incident for it.

The correlation key is the engine's *recipe* for "same incident". Two
recipes ship out of the box:

* ``actor-time`` — the same actor + the same ATT&CK technique + within
  ``merge_window_seconds``. The default recipe, the most common shape.
* ``target-time`` — the same target asset + any actor. Useful for "the
  same database is being probed from every angle".

A deployment extends the recipes or defines its own. The shipped ones
cover the patterns the SOC's tests exercise.

An incident is **closed** when no new finding has joined it for
``idle_window_seconds``. Closing is a state change, not a delete —
closed incidents remain in the store and are read by the audit chain,
the metrics module and the SOC console. A closed incident may be
re-opened if a new finding joins within ``idle_window_seconds`` after
the close.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from core.schema.ocsf import Severity
from correlate.incident import Incident, _new_incident_uid


@dataclass
class FindingStub:
    """A minimal finding for the correlate engine.

    The correlate layer reads only the fields it needs to decide which
    incident the finding joins. The full OCSF finding is in the lake
    and the correlate engine does not duplicate it.
    """

    uid: str
    time: float
    severity_id: int
    attack_id: str
    actor_key: str = ""
    target_keys: tuple[str, ...] = ()
    correlation_key: str = ""
    entity_tags: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass
class CorrelateStats:
    """Counts the engine exposes via :meth:`stats`."""

    findings_seen: int = 0
    incidents_created: int = 0
    incidents_merged: int = 0
    incidents_closed: int = 0
    last_error: str = ""


class CorrelateEngine:
    """The grouping engine.

    A single instance is intended to live the lifetime of the platform.
    The store of open incidents is in-memory; a real deployment
    persists incidents to VedDB on close so a restart does not lose
    state.
    """

    def __init__(
        self,
        *,
        merge_window_seconds: float = 1800.0,
        idle_window_seconds: float = 3600.0,
        crown_jewel_boost: int = 1,
        clock: Any = time.time,
    ) -> None:
        self.merge_window = float(merge_window_seconds)
        self.idle_window = float(idle_window_seconds)
        self.crown_jewel_boost = int(crown_jewel_boost)
        self.clock = clock
        self._open: dict[str, Incident] = {}
        self._closed: list[Incident] = []
        self.stats = CorrelateStats()

    def observe(self, finding: FindingStub) -> Incident:
        """Add a finding to the correlate engine.

        Returns the incident the finding joined, or a freshly-created
        one. The incident's ``finding_uids`` includes the new finding.
        """
        if not finding.correlation_key:
            # Without a key, the finding is its own incident.
            finding.correlation_key = f"adhoc:{finding.uid}"
        incident = self._match(finding)
        if incident is None:
            incident = Incident(
                uid=_new_incident_uid(),
                correlation_key=finding.correlation_key,
                finding_uids=[finding.uid],
                window_start=finding.time,
                window_end=finding.time,
                severity_id=finding.severity_id,
                status_id=1,  # New
                created_at=self.clock(),
                updated_at=self.clock(),
            )
            self._open[incident.correlation_key] = incident
            self.stats.incidents_created += 1
        else:
            incident.window_start = min(incident.window_start, finding.time)
            incident.window_end = max(incident.window_end, finding.time)
            incident.severity_id = max(incident.severity_id, finding.severity_id)
            incident.updated_at = self.clock()
            # If the incident was closed, re-open it.
            if incident.status_id in (4, 5, 6):
                incident.status_id = 1
                self._open[incident.correlation_key] = incident
                self._closed = [i for i in self._closed if i.uid != incident.uid]
            self.stats.incidents_merged += 1
        # Union the attack IDs.
        if finding.attack_id and finding.attack_id not in incident.attack_ids:
            incident.attack_ids.append(finding.attack_id)
        # Union the actor and target keys.
        if finding.actor_key:
            if finding.actor_key not in incident.actor_keys:
                incident.actor_keys.append(finding.actor_key)
            if not incident.first_actor_key:
                incident.first_actor_key = finding.actor_key
        for target in finding.target_keys:
            if target not in incident.target_keys:
                incident.target_keys.append(target)
        # Crown-jewel boost — a target tagged ``crown_jewel`` lifts the
        # severity one band. This is the only place entity tags change
        # the incident's severity. OCSF ``severity_id`` is monotonic in
        # severity (INFORMATIONAL=1 < LOW=2 < MEDIUM=3 < HIGH=4 <
        # CRITICAL=5 < FATAL=6), so "lift one band" is +1, capped at
        # ``FATAL`` so a crown-jewel asset never produces a
        # nonsensical severity above the OCSF enum's max.
        for key, tags in finding.entity_tags.items():
            if "crown_jewel" in tags:
                incident.severity_id = min(
                    int(Severity.FATAL),
                    incident.severity_id + self.crown_jewel_boost,
                )
        # Add the finding to the incident.
        if finding.uid not in incident.finding_uids:
            incident.finding_uids.append(finding.uid)
        self.stats.findings_seen += 1
        return incident

    def close_idle(self, now: float | None = None) -> list[Incident]:
        """Close every open incident that has been idle longer than the idle window.

        "Idle" is measured against the last *event* time the incident
        saw (``window_end``), not the wall clock. A restart, a queue
        flush, or a delayed source can pause the correlate engine for
        hours; the correlate layer must not, on the next tick, close
        every open incident because wall-clock time advanced.

        Returns the list of *newly* closed incidents. The list is in
        the order they were closed; the audit chain writes them in that
        order.
        """
        moment = now if now is not None else self.clock()
        closed: list[Incident] = []
        for key, incident in list(self._open.items()):
            if moment - incident.window_end > self.idle_window:
                incident.status_id = 4  # Resolved
                self._closed.append(incident)
                del self._open[key]
                closed.append(incident)
                self.stats.incidents_closed += 1
        return closed

    def open_incidents(self) -> list[Incident]:
        return list(self._open.values())

    def closed_incidents(self) -> list[Incident]:
        return list(self._closed)

    def find_by_correlation_key(self, key: str) -> Incident | None:
        return self._open.get(key)

    def stats_dict(self) -> dict[str, Any]:
        return {
            "findings_seen": self.stats.findings_seen,
            "incidents_created": self.stats.incidents_created,
            "incidents_merged": self.stats.incidents_merged,
            "incidents_closed": self.stats.incidents_closed,
            "open_count": len(self._open),
            "closed_count": len(self._closed),
            "last_error": self.stats.last_error,
        }

    def _match(self, finding: FindingStub) -> Incident | None:
        """Find the open incident this finding should join.

        The merge window is the gap between this finding's time and the
        incident's ``window_end`` — the latest event time in the
        incident's evidence. Wall clock time is *not* used here: a
        connector that runs every five minutes, with a finding time of
        yesterday, must still join the incident whose evidence spans
        yesterday.
        """
        incident = self._open.get(finding.correlation_key)
        if incident is None:
            return None
        if abs(finding.time - incident.window_end) > self.merge_window:
            return None
        return incident


__all__ = ["CorrelateEngine", "CorrelateStats", "FindingStub"]

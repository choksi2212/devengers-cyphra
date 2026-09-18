"""The incident — a 2005 IncidentFinding that groups related findings.

An incident is the SOC's *unit of work*. One finding can be its own
incident (a single defender alert with enough context) or it can be
one of twenty findings that together describe a campaign. The
correlate engine produces incidents; the triage engine consumes them.

Three properties make an incident a good unit:

* It has a **stable id** that is not the alert's id. An operator who
  looks at an incident two days after the alert fired sees the same id
  and the same chain.
* It has a **scope** — what is in and what is out. Two findings on the
  same actor within an hour are in; the same actor's routine activity
  outside the window is out.
* It has a **verdict path** — the incident's ``verdict_id`` starts at
  :attr:`OcsfVerdict.UNKNOWN` and moves through the analyst's
  verdicts. Each verdict is irrevocable and lands in the audit trail.

The correlate layer produces incidents on the timeline; the triage layer
is where the verdict lands.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from core.schema.ocsf import ClassUid, Severity


@dataclass
class Incident:
    """One incident in the correlate layer.

    ``uid`` is the platform's canonical id. ``finding_uids`` is every
    finding that has been grouped into this incident; the analyst UI
    uses this to render the chain. ``window_start`` and ``window_end``
    are the time bounds of the *evidence*, not the bounds of any one
    finding. ``severity_id`` is the worst finding's severity by
    default; the correlate layer may adjust it upward if the incident
    touches a ``crown_jewel`` asset.

    ``attack_ids`` is the union of the ATT&CK technique ids of the
    incident's findings, deduplicated. ``actor_keys`` and
    ``target_keys`` are the platform's entity uids that participate;
    ``first_actor_key`` is the actor the incident is "about" (the
    ``primary actor`` of the SOC's investigation).

    ``status_id`` follows OCSF's :class:`FindingStatus`: 1 New, 2 In
    Progress, 3 Suppressed, 4 Resolved, 5 Archived, 6 Deleted.
    """

    uid: str
    finding_uids: list[str] = field(default_factory=list)
    window_start: float = 0.0
    window_end: float = 0.0
    severity_id: int = int(Severity.MEDIUM)
    attack_ids: list[str] = field(default_factory=list)
    actor_keys: list[str] = field(default_factory=list)
    target_keys: list[str] = field(default_factory=list)
    first_actor_key: str = ""
    status_id: int = 1
    correlation_key: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_ocsf(self) -> dict[str, Any]:
        """The incident as an OCSF 2005 IncidentFinding."""
        return {
            "class_uid": int(ClassUid.INCIDENT_FINDING),
            "time": self.window_end,
            "severity_id": self.severity_id,
            "metadata_uid": self.uid,
            "metadata_product_name": "Cyphra SOC Correlate Engine",
            "metadata_product_vendor_name": "Cyphra SOC",
            "metadata_version": "1.9.0",
            "activity_name": "Incident",
            "activity_id": 1,
            "status_id": self.status_id,
            "finding_info": [{
                "name": self.uid,
                "uid": self.uid,
                "desc": (
                    f"Incident grouping {len(self.finding_uids)} finding(s) "
                    f"over {self.window_end - self.window_start:.0f} seconds"
                ),
                "confidence": 70,
            }],
            "unmapped": {
                "window_start": self.window_start,
                "window_end": self.window_end,
                "finding_uids": list(self.finding_uids),
                "actor_keys": list(self.actor_keys),
                "target_keys": list(self.target_keys),
                "first_actor_key": self.first_actor_key,
                "correlation_key": self.correlation_key,
                "attack_ids": list(self.attack_ids),
            },
        }


def _new_incident_uid() -> str:
    """A short, stable, sortable id. ``i-<12 hex>``."""
    return f"i-{uuid.uuid4().hex[:12]}"


__all__ = ["Incident", "_new_incident_uid"]

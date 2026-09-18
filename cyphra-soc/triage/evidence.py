"""Evidence packet — the package the analyst sees when they open an incident.

When an analyst opens an incident, the SOC console renders an evidence
packet: a summary of the incident, the chain of findings, the entities
involved, the threat-intel matches, and the rule that fired. The packet
is what the analyst works from — it is not the full OCSF finding chain
(which is in the lake), it is the *curated* subset the analyst needs to
make a disposition.

A packet is built from the correlate layer's :class:`Incident`, the
:class:`Enrichment` from the most-recent finding, and the rule registry's
metadata. The packet is a flat dict with three sections:

* ``summary`` — incident uid, severity, ATT&CK ids, window, primary actor.
* ``findings`` — one entry per finding uid, with the rule name and
  attack id.
* ``context`` — entities, indicators, intel matches.

The packet is read-only. Editing it means changing the disposition or
adding analyst comments; the *contents* are derived.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from correlate import Incident


@dataclass
class FindingSummary:
    """One finding inside an evidence packet."""

    uid: str
    rule_id: str
    rule_name: str
    attack_id: str
    severity: int
    confidence: float


@dataclass
class EvidencePacket:
    """The package an analyst sees.

    ``summary`` carries the incident's identifying metadata.
    ``findings`` is the chain of finding uids with their rule context.
    ``context`` is the enrichment-derived block (entities + intel).
    """

    incident_uid: str
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingSummary] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    sla_deadline: float = 0.0
    sla_breached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_uid": self.incident_uid,
            "summary": self.summary,
            "findings": [
                {
                    "uid": f.uid,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "attack_id": f.attack_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "context": self.context,
            "sla_deadline": self.sla_deadline,
            "sla_breached": self.sla_breached,
        }


def build_packet(
    incident: Incident,
    finding_summaries: list[FindingSummary],
    *,
    context: Mapping[str, Any] | None = None,
    sla_seconds: float = 900.0,
    now: float = 0.0,
) -> EvidencePacket:
    """Build an evidence packet from the correlate engine's incident.

    ``sla_seconds`` is the platform's triage SLA — the analyst must
    dispose of an incident within that window or the queue pages.
    ``now`` is the monotonic clock; the deadline is ``incident
    .window_end + sla_seconds``.
    """
    deadline = incident.window_end + sla_seconds
    sla_breached = bool(now and now > deadline)
    summary = {
        "uid": incident.uid,
        "correlation_key": incident.correlation_key,
        "severity": incident.severity_id,
        "window_start": incident.window_start,
        "window_end": incident.window_end,
        "attack_ids": list(incident.attack_ids),
        "actor_keys": list(incident.actor_keys),
        "target_keys": list(incident.target_keys),
        "first_actor_key": incident.first_actor_key,
        "status_id": incident.status_id,
        "finding_count": len(incident.finding_uids),
    }
    return EvidencePacket(
        incident_uid=incident.uid,
        summary=summary,
        findings=list(finding_summaries),
        context=dict(context or {}),
        sla_deadline=deadline,
        sla_breached=sla_breached,
    )


__all__ = ["EvidencePacket", "FindingSummary", "build_packet"]

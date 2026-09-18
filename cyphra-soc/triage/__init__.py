"""The triage subsystem — analyst workflow on incidents.

Three modules:

* :mod:`triage.disposition` — :class:`Disposition`, the analyst's
  verdict on an incident, OCSF-aligned with extensions for workflow
  states (escalate, request_more_info).
* :mod:`triage.evidence` — :class:`EvidencePacket`, the package the
  analyst sees when they open an incident. Summary, findings, context.
* :mod:`triage.queue` — :class:`TriageQueue`, the analyst UI's data
  model. Carries every incident, every disposition, every assignment,
  and the SLA breach list.
"""

from triage.disposition import (
    CLOSING_DISPOSITIONS,
    DISPOSITION_NAMES,
    ESCALATING_DISPOSITIONS,
    Disposition,
    DispositionRecord,
    from_name,
    to_ocsf_verdict,
)
from triage.evidence import (
    EvidencePacket,
    FindingSummary,
    build_packet,
)
from triage.queue import (
    Assignment,
    QueueStats,
    TriageQueue,
)

__all__ = [
    "Assignment",
    "CLOSING_DISPOSITIONS",
    "DISPOSITION_NAMES",
    "Disposition",
    "DispositionRecord",
    "ESCALATING_DISPOSITIONS",
    "EvidencePacket",
    "FindingSummary",
    "QueueStats",
    "TriageQueue",
    "build_packet",
    "from_name",
    "to_ocsf_verdict",
]

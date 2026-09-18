"""The :class:`Finding` dataclass — a 2004 DetectionFinding pre-flight.

Lives in its own module so signature / statistical / behavioural rules
can import it without pulling in the engine's full surface (which would
create a circular import through ``detect.__init__``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.schema.ocsf import Severity


@dataclass
class Finding:
    """A 2004 DetectionFinding, pre-flight.

    The correlate engine consumes a list of these; the engine emits them.
    ``alert_uid`` is the :attr:`Event.metadata_uid` of the alert that
    triggered the finding — it is the join the analyst UI uses to navigate
    from "what fired?" to "the alert".
    """

    alert_uid: str
    alert_time: float
    rule_id: str
    rule_name: str
    severity: int = int(Severity.MEDIUM)
    confidence: float = 0.0
    attack: str = ""
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_uuid: str = ""


__all__ = ["Finding"]

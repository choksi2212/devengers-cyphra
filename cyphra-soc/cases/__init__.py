"""The cases subsystem — the SOC's long-lived investigation records.

Two modules:

* :mod:`cases.case` — :class:`Case`, :class:`CaseStatus`, the state
  machine, the timeline. A case moves forward through
  ``NEW`` -> ``UNDER_INVESTIGATION`` -> ``CONTAINED`` ->
  ``POSTMORTEM`` -> ``CLOSED`` -> ``ARCHIVED``.
* :mod:`cases.store` — :class:`CaseStore`, the in-memory index of
  every case. Indexed by uid and by ``source_incident_uid`` so the
  correlate engine's re-emission does not open a duplicate case.
"""

from cases.case import (
    Case,
    CaseStatus,
    STATUS_NAMES,
    TimelineEvent,
    new_case_uid,
    record,
    transition,
)
from cases.store import CaseStats, CaseStore

__all__ = [
    "Case",
    "CaseStats",
    "CaseStatus",
    "CaseStore",
    "STATUS_NAMES",
    "TimelineEvent",
    "new_case_uid",
    "record",
    "transition",
]

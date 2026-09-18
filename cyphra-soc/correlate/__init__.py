"""The correlate layer — grouping findings into incidents.

Three modules:

* :mod:`correlate.incident` — :class:`Incident`, the platform's unit of
  SOC work. OCSF 2005 IncidentFinding; carries the grouped findings,
  the window bounds, the attack union and the actor/target keys.
* :mod:`correlate.engine` — :class:`CorrelateEngine`, the dispatcher
  that joins a stream of findings into open incidents and closes
  them on idle.
* :mod:`correlate.key` — the recipes that turn a finding stub into a
  correlation key. Two ship out of the box: ``actor_time_key`` (default)
  and ``target_time_key``.
"""

from correlate.engine import CorrelateEngine, CorrelateStats, FindingStub
from correlate.incident import Incident, _new_incident_uid
from correlate.key import actor_time_key, first_key, target_time_key

__all__ = [
    "CorrelateEngine",
    "CorrelateStats",
    "FindingStub",
    "Incident",
    "_new_incident_uid",
    "actor_time_key",
    "first_key",
    "target_time_key",
]

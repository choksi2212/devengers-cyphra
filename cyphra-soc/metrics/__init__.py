"""The metrics subsystem — the SOC's operational numbers.

One module:

* :mod:`metrics.tracker` — :class:`MetricsTracker`, :class:`MetricsReport`.
  Observes MTTD, MTTR, false-positive rate, escalation rate. The
  tracker is in-memory; production deployments persist every
  observation to VedDB for historical dashboards.
"""

from metrics.tracker import MetricsReport, MetricsTracker

__all__ = ["MetricsReport", "MetricsTracker"]

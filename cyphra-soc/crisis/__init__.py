"""The crisis subsystem — multi-case emergency coordination.

One module:

* :mod:`crisis.manager` — :class:`Crisis`, :class:`CrisisManager`,
  :class:`CrisisStatus`. The manager opens a crisis, folds cases
  into it, runs playbooks across every case, and tracks the
  state through ``Active`` -> ``Contained`` -> ``Closed``.
"""

from crisis.manager import (
    CRISIS_STATUS_NAMES,
    Crisis,
    CrisisManager,
    CrisisStats,
    CrisisStatus,
)

__all__ = [
    "CRISIS_STATUS_NAMES",
    "Crisis",
    "CrisisManager",
    "CrisisStats",
    "CrisisStatus",
]

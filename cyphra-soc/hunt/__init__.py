"""The hunt subsystem — hypothesis-driven queries against the lake.

Two modules:

* :mod:`hunt.query` — :class:`HuntQuery` and :class:`Predicate`. A
  hunt is a name, a description, a list of predicates, a window, and
  a schedule. The filter is a small structured object — never a
  free-form SQL string — so hunts are reviewable, testable, auditable.
* :mod:`hunt.runner` — :class:`HuntRunner`, the dispatcher. Walks an
  event stream, applies predicates, samples hits, returns a
  :class:`hunt.query.HuntResult`.
"""

from hunt.query import (
    HuntQuery,
    HuntResult,
    Predicate,
    contains,
    default_hunt_library,
    equals,
    exists,
    in_,
    regex,
    service_account_console_login,
    tor_authentications,
    unusual_dns_volume,
)
from hunt.runner import HuntRunner, HuntStats

__all__ = [
    "HuntQuery",
    "HuntResult",
    "HuntRunner",
    "HuntStats",
    "Predicate",
    "contains",
    "default_hunt_library",
    "equals",
    "exists",
    "in_",
    "regex",
    "service_account_console_login",
    "tor_authentications",
    "unusual_dns_volume",
]

"""The entities subsystem — canonical identity, host, and asset records.

Three modules:

* :mod:`entities.identity` — :class:`Entity`, :class:`EntityKind`,
  :class:`EntityRef`, :class:`ExternalRef`, :class:`EntityStore`. The
  store is in-memory; production deployments back it with VedDB.
* :mod:`entities.resolver` — :class:`EntityResolver`, which walks an
  OCSF event and extracts entity references. The enrich layer turns
  the refs into fully-resolved entities.
"""

from entities.identity import (
    Entity,
    EntityKind,
    EntityRef,
    EntityStore,
    ExternalRef,
    KIND_NAMES,
)
from entities.resolver import EntityResolver

__all__ = [
    "Entity",
    "EntityKind",
    "EntityRef",
    "EntityResolver",
    "EntityStore",
    "ExternalRef",
    "KIND_NAMES",
]

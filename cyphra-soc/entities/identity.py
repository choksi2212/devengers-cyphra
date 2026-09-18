"""The entities subsystem — canonical identity, host, and asset records.

Three things every alert refers to but no single event fully describes:

* **Identity** — a user, service principal, or workload. The connector
  knows ``alice@contoso.com`` was the actor on a sign-in; the platform's
  correlate layer needs to know what else ``alice@contoso.com`` is
  allowed to do, what devices she uses, and what alerts have touched
  her in the last 30 days.
* **Host** — a machine. Process telemetry is per-host; the correlate
  layer needs to know what the host is (laptop / server / DC), what
  version, what exposure (public / private).
* **Asset** — a resource: a VM, a database, a storage bucket, an SaaS
  workspace. Cloud control-plane events reference assets, and the
  correlate layer needs to know which assets are *crown jewels* so an
  alert touching one is rated differently from one touching a
  throwaway.

The platform's identity, host, and asset tables are *entities*. An
entity has:

* A canonical ``uid`` (the platform's internal id — never an external
  vendor id).
* One or more ``external_refs`` — the same entity viewed from a
  different vendor (``object_id`` in Entra, ``instance_id`` in AWS).
* A *kind* — ``user``, ``service_principal``, ``host``, ``vnet``,
  ``bucket``, ``database``, ``workspace``, ``subscription``, ``project``,
  ``tenant``.
* A *risk* — a per-entity number the correlate layer reads as one
  signal among many.

Entities are *resolved* from raw OCSF events. A sign-in event with
``actor.user.email_addr = "alice@contoso.com"`` produces an
:class:`IdentityRef`; the :class:`EntityStore` either finds the
existing :class:`Identity` or creates a placeholder. The correlate
layer reads from the same store.

The store is in-memory by default; production deployments back it with
VedDB. The in-memory store is sufficient for the correlate engine and
for the test path.
"""

from __future__ import annotations

import enum
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping


class EntityKind(enum.IntEnum):
    """The kind of an entity. Determines which :class:`EntityRef` shape it has."""

    UNKNOWN = 0
    USER = 1
    SERVICE_PRINCIPAL = 2
    GROUP = 3
    HOST = 10
    PROCESS = 11
    APPLICATION = 20
    WORKSPACE = 21
    SUBSCRIPTION = 30
    PROJECT = 31
    TENANT = 32
    BUCKET = 40
    DATABASE = 41
    KEY_VAULT = 42
    KMS_KEY = 43
    ROLE = 50
    POLICY = 51


KIND_NAMES: Mapping[int, str] = {
    int(k): k.name.lower() for k in EntityKind
}


@dataclass
class ExternalRef:
    """A vendor-specific identifier for an entity.

    ``vendor`` is the source's product vendor ("Microsoft", "Google",
    "Amazon"). ``kind`` is the source's own kind string ("User",
    "service_account"). ``value`` is the external id.

    Two external refs from the same vendor with the same ``value`` are
    the same identity; the platform keeps one ``ExternalRef`` per
    (vendor, kind, value) tuple.
    """

    vendor: str
    kind: str
    value: str


@dataclass
class Entity:
    """One entity in the store.

    ``uid`` is the platform's canonical id (``e-<12 hex>``). ``kind`` is
    the platform's kind (:class:`EntityKind`). ``display_name`` is what
    the SOC console shows. ``external_refs`` is the list of vendor ids
    the entity is known under. ``tags`` is free-form (``crown_jewel``,
    ``disabled``, ``test_account``). ``risk`` is the per-entity score;
    the correlate layer reads it as one input to incident severity.

    ``first_seen`` and ``last_seen`` are monotonic clock values;
    ``last_seen`` is bumped on every :meth:`EntityStore.observe` call
    that touches the entity.
    """

    uid: str
    kind: int
    display_name: str
    external_refs: list[ExternalRef] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    risk: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class EntityRef:
    """A pointer to an entity, as found in an OCSF event.

    The enrich layer turns an ``EntityRef`` into the full :class:`Entity`
    via :meth:`EntityStore.resolve`. The ref itself is the light-weight
    form that travels with the event.
    """

    vendor: str
    kind: str
    value: str
    display_name: str = ""
    kind_uid: int = 0


class EntityStore:
    """The canonical store of :class:`Entity` records.

    The store indexes entities by ``uid`` (canonical) and by every
    ``external_ref`` (vendor, kind, value). ``resolve`` looks up an
    external id; ``observe`` registers an event's references; ``get``
    reads a canonical id.

    ``observe`` is the platform's main entry point. The enrich layer
    walks every OCSF event, calls ``observe`` on every reference it can
    extract, and the store picks up new entities automatically.
    """

    def __init__(self, *, clock: Any = time.time) -> None:
        self.clock = clock
        self._by_uid: dict[str, Entity] = {}
        self._by_ref: dict[tuple[str, str, str], str] = {}
        self._counter = 0

    def get(self, uid: str) -> Entity | None:
        return self._by_uid.get(uid)

    def resolve(self, ref: EntityRef) -> Entity | None:
        """Look up an entity by a vendor (vendor, kind, value) tuple.

        Returns ``None`` if the entity has not been observed; the
        caller can use :meth:`observe` to register it.
        """
        uid = self._by_ref.get((ref.vendor, ref.kind, ref.value))
        return self._by_uid.get(uid) if uid else None

    def observe(self, ref: EntityRef, *, kind: int, tags: Iterable[str] = ()) -> Entity:
        """Register an entity seen on a vendor id; idempotent.

        Returns the existing or freshly-created :class:`Entity`. Tags
        accumulate — observing the same entity twice with different tags
        produces an entity with both. ``display_name`` is preserved
        across observations unless the caller passes a non-empty one
        (first-write wins, except when the first display_name was empty).
        """
        key = (ref.vendor, ref.kind, ref.value)
        existing = self._by_ref.get(key)
        if existing is not None:
            entity = self._by_uid[existing]
            entity.last_seen = self.clock()
            for tag in tags:
                if tag not in entity.tags:
                    entity.tags.append(tag)
            if not entity.display_name and ref.display_name:
                entity.display_name = ref.display_name
            return entity
        uid = self._allocate_uid()
        entity = Entity(
            uid=uid,
            kind=int(kind),
            display_name=ref.display_name or ref.value,
            external_refs=[ExternalRef(
                vendor=ref.vendor,
                kind=ref.kind,
                value=ref.value,
            )],
            tags=list(tags),
            first_seen=self.clock(),
            last_seen=self.clock(),
        )
        self._by_uid[uid] = entity
        self._by_ref[key] = uid
        return entity

    def add_ref(self, entity: Entity, vendor: str, kind: str, value: str) -> None:
        """Add a new external reference to an existing entity.

        Used when the same logical entity is seen from a different vendor
        (e.g. an Entra user and a Google Workspace user are joined on
        the operator's authoritative source — ``mavis``).
        """
        for ref in entity.external_refs:
            if ref.vendor == vendor and ref.kind == kind and ref.value == value:
                return
        entity.external_refs.append(ExternalRef(vendor=vendor, kind=kind, value=value))
        self._by_ref[(vendor, kind, value)] = entity.uid

    def tag(self, entity: Entity, tag: str) -> None:
        if tag not in entity.tags:
            entity.tags.append(tag)

    def set_risk(self, entity: Entity, risk: float) -> None:
        """Set the entity's risk score. Caller's responsibility to keep
        ``risk`` in ``[0, 1]`` — the correlate layer reads it as a
        weight, not a clamp."""
        entity.risk = max(0.0, min(1.0, float(risk)))

    def list_by_kind(self, kind: int) -> list[Entity]:
        return [e for e in self._by_uid.values() if e.kind == kind]

    def count(self) -> int:
        return len(self._by_uid)

    def _allocate_uid(self) -> str:
        self._counter += 1
        return f"e-{uuid.uuid4().hex[:12]}"


__all__ = [
    "Entity",
    "EntityKind",
    "EntityRef",
    "EntityStore",
    "ExternalRef",
    "KIND_NAMES",
]

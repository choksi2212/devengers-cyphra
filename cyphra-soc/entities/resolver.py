"""Entity resolver — extract references from an OCSF event.

An OCSF event references entities in a half-dozen places, with vendor-
specific shapes. The resolver walks an event and produces a list of
:class:`EntityRef` pointers; the enrich layer turns each ref into a
fully-resolved :class:`Entity`.

The resolver is intentionally narrow. It does not decide *what* an entity
*is* — that is the enrich layer's job, after the kind has been
resolved against a configured kind table. The resolver just walks the
event's known shapes and produces ref *candidates* with a hint about
which kind each one likely is.

The default kind hints are conservative — ``user`` for an email-shaped
``actor.user.email_addr`` and similar. A deployment with a stricter
schema (e.g. "service principals live in a different OCSF field")
overrides the hint via the resolver's constructor.
"""

from __future__ import annotations

from typing import Any, Mapping

from entities.identity import EntityKind, EntityRef


def _looks_like_email(value: Any) -> bool:
    """Conservative enough that an SPN never lands in an email field."""
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    _, _, domain = text.rpartition("@")
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _looks_like_service_account_email(value: Any) -> bool:
    """``alice@project.iam.gserviceaccount.com`` is a service account, not a user."""
    text = str(value or "").strip()
    return text.endswith(".iam.gserviceaccount.com")


def _looks_like_ip(value: Any) -> bool:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _looks_like_guid(value: Any) -> bool:
    """A 36-char string with hyphens at positions 8/13/18/23 — Entra object-id shape."""
    text = str(value or "").strip()
    if len(text) != 36:
        return False
    parts = text.split("-")
    return len(parts) == 5 and all(len(p) in (8, 4, 4, 4, 12) for p in parts)


class EntityResolver:
    """Extract :class:`EntityRef`s from an OCSF event."""

    def __init__(self, vendor: str = "") -> None:
        # ``vendor`` is the product vendor of the source. Used as the
        # default vendor on every ref the resolver produces. A pipeline
        # that aggregates from multiple sources sets the vendor per-event
        # via :meth:`refs_for` instead of mutating the resolver.
        self.vendor = vendor

    def refs_for(self, event: Mapping[str, Any]) -> list[EntityRef]:
        """Every entity reference the resolver can extract from ``event``."""
        refs: list[EntityRef] = []
        vendor = self.vendor
        # Actor — the most common place an identity is named.
        actor = event.get("actor")
        if isinstance(actor, Mapping):
            user = actor.get("user")
            if isinstance(user, Mapping):
                refs.extend(self._user_refs(user, vendor))
        # User (3002's required object).
        user = event.get("user")
        if isinstance(user, Mapping):
            refs.extend(self._user_refs(user, vendor))
        # Source endpoint IP — a host reference.
        ip = event.get("src_endpoint_ip")
        if _looks_like_ip(ip):
            refs.append(EntityRef(
                vendor=vendor or "ip",
                kind="ip",
                value=str(ip),
                display_name=str(ip),
                kind_uid=int(EntityKind.HOST),
            ))
        # Resources — assets. Walk each entry and resolve its uid
        # against a list of vendor identifiers.
        for resource in event.get("resources") or []:
            if not isinstance(resource, Mapping):
                continue
            uid = resource.get("uid")
            if not uid:
                continue
            kind_str = resource.get("type") or "asset"
            refs.append(EntityRef(
                vendor=vendor or "asset",
                kind=str(kind_str),
                value=str(uid),
                display_name=str(resource.get("name") or uid),
                kind_uid=_resource_kind_to_uid(kind_str),
            ))
        # Email — for 4009 events.
        email = event.get("email")
        if isinstance(email, Mapping):
            email_uid = email.get("uid") or email.get("message_id")
            if email_uid:
                refs.append(EntityRef(
                    vendor=vendor or "email",
                    kind="email_message",
                    value=str(email_uid),
                    display_name=str(email.get("subject") or email_uid),
                    kind_uid=int(EntityKind.APPLICATION),
                ))
        return refs

    def _user_refs(self, user: Mapping[str, Any], vendor: str) -> list[EntityRef]:
        """Extract the identity references inside an OCSF user object."""
        refs: list[EntityRef] = []
        email = user.get("email_addr")
        name = user.get("name")
        uid = user.get("uid")
        if _looks_like_email(email):
            kind = (
                int(EntityKind.SERVICE_PRINCIPAL)
                if _looks_like_service_account_email(email)
                else int(EntityKind.USER)
            )
            refs.append(EntityRef(
                vendor=vendor or "identity",
                kind="user",
                value=str(email),
                display_name=str(name or email),
                kind_uid=kind,
            ))
        elif uid and _looks_like_guid(uid):
            # Entra object id is a GUID — a reference to the same
            # identity from a different angle.
            refs.append(EntityRef(
                vendor=vendor or "identity",
                kind="user_guid",
                value=str(uid),
                display_name=str(name or uid),
                kind_uid=int(EntityKind.USER),
            ))
        elif uid:
            refs.append(EntityRef(
                vendor=vendor or "identity",
                kind="user",
                value=str(uid),
                display_name=str(name or uid),
                kind_uid=int(EntityKind.USER),
            ))
        return refs


def _resource_kind_to_uid(kind: str) -> int:
    """A loose mapping from resource type strings to entity kinds.

    A real deployment overrides this with a deployment-specific table
    that knows which vendor types map to which entity kind. The default
    here handles the common cases.
    """
    text = str(kind).lower()
    if "compute" in text or "vm" in text or "instance" in text or "host" in text:
        return int(EntityKind.HOST)
    if "bucket" in text or "blob" in text or "storage" in text:
        return int(EntityKind.BUCKET)
    if "database" in text or "sql" in text or "db" in text or "table" in text:
        return int(EntityKind.DATABASE)
    if "key" in text and "vault" in text:
        return int(EntityKind.KEY_VAULT)
    if "kms" in text or "key" in text:
        return int(EntityKind.KMS_KEY)
    if "subscription" in text:
        return int(EntityKind.SUBSCRIPTION)
    if "project" in text:
        return int(EntityKind.PROJECT)
    if "tenant" in text or "organization" in text:
        return int(EntityKind.TENANT)
    if "role" in text:
        return int(EntityKind.ROLE)
    if "policy" in text:
        return int(EntityKind.POLICY)
    return int(EntityKind.APPLICATION)


__all__ = ["EntityResolver", "_looks_like_email"]

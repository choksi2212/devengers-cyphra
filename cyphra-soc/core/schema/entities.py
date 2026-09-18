"""Entity model — the durable things behind the events.

An event is a moment; an entity is a thing that persists across moments. Detection
operates on events, but every decision worth making is about an entity: *this host*
has three signals in an hour, *this account* signed in from two continents, *this
server* is a domain controller and must never be blocked. The plan's core safety
mechanism, ``detect.min_signals_per_entity: 3``, is unimplementable without a
correct answer to "is this the same host as that one".

Four ideas carry the whole module.

**Identifiers are temporal; entities are durable.** ``10.0.0.5`` is not a host. It
is a *lease* — a name that pointed at one host this morning and a different one this
afternoon. So an identifier binds to an entity over a closed interval
(:class:`Binding`), and any question about an identifier has to name a time. A
platform that stores ``ip -> host`` as a plain mapping will, the first time DHCP
churns, attribute one host's activity to another and produce an investigation about
the wrong machine. That failure is silent: the timeline reads perfectly.

**A merge needs an identifier of the entity's own kind.** Two hosts that shared an
outbound address are not one host — the address is an :attr:`EntityType.IP` entity
bound to each of them for a while. So :meth:`Entity.merge` requires a shared
identifier whose *natural* type equals the type of both entities, which makes the
NAT-collapse failure structurally impossible rather than merely unlikely. Durability
(:attr:`IdentifierSpec.durability`) then guards the remaining case: a MAC is a host
identifier, but a cloned VM template shares one, so it ranks below the merge floor.

**Case folding is per-platform, and where the platform is unknown the safe answer is
not to fold.** ``core.schema.ocsf`` deliberately leaves usernames unfolded and hands
the decision here, because only this layer knows the platform. Windows and AD
account names are case-insensitive, so ``CORP\\jdoe`` and ``CORP\\JDoe`` are one
account; POSIX names are case-sensitive, so ``Bob`` and ``bob`` are two. Folding
wrongly merges two real accounts and cannot be undone; not folding wrongly splits
one account into two nodes, which is a missed correlation but a *visible* one — so
where the platform is unknown this module declines to fold and
:func:`case_collisions` reports the pairs that differ only by case, for the
correlation layer to raise rather than for this layer to guess.

**A device identifier is a host identifier.** There is no separate ``device`` entity
type. Splitting the endpoint into a "host" (named by hostname) and a "device" (named
by an EDR enrolment id) reads tidily and is a trap: the two types would have no
merge path between them, so the single most important entity in the graph would
arrive permanently in two halves, each carrying half the signals — and
``min_signals_per_entity: 3`` would never fire on a host whose evidence split 2/2.
An EDR ``machine_uid`` is therefore the *strongest host identifier*, which is what
lets a host survive a rename and a re-IP.

Resolution — matching new observations against stored entities over time, detecting
that an address is shared, arbitrating binding conflicts — is ``correlate/entity.py``
(Phase 3). This module is the model it operates on: types, identifier kinds,
normalisation, keys, temporal bindings, merge semantics, and the structural bridge
from an :class:`~core.schema.ocsf.Event` to the entities it mentions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from core.schema.ocsf import OCSF_PATH, Event

__all__ = [
    "SCHEMA_VERSION",
    "MIN_MERGE_DURABILITY",
    "EntityError",
    "MergeRefused",
    "EntityType",
    "IdKind",
    "Platform",
    "Criticality",
    "AddressScope",
    "IdentifierSpec",
    "Identifier",
    "Binding",
    "Entity",
    "EntityRef",
    "Observation",
    "SPECS",
    "PRIMARY_TYPES",
    "UNROUTABLE_SCOPES",
    "CASE_INSENSITIVE_PLATFORMS",
    "STRICT_SCOPE_KINDS",
    "CROSS_ATTACH",
    "FIELD_TO_IDENTIFIER",
    "OBSERVABLE_TO_IDENTIFIER",
    "address_scope",
    "case_collisions",
    "cidr_reason",
    "default_domain",
    "entities_from_event",
    "entity_key",
    "fold_username",
    "infer_platform",
    "normalise",
    "observations_from_event",
    "scope_collisions",
    "set_default_domain",
    "spec",
    "split_account",
]

SCHEMA_VERSION = 1

#: An identifier below this durability may be *recorded* on an entity but never used
#: to merge two entities. See :class:`IdentifierSpec` for the scale.
MIN_MERGE_DURABILITY = 4


class EntityError(ValueError):
    """A malformed entity, identifier, or binding.

    Callers should catch :class:`ValueError`, not this class. Pydantic wraps any
    ``ValueError`` raised inside a validator into its own ``ValidationError``, so an
    ``EntityError`` from :meth:`Identifier.make` arrives as itself while the identical
    condition reached through ``Identifier(...)`` or ``Binding(...)`` arrives wrapped.
    Both are ``ValueError`` subclasses, which makes that the one contract covering
    every path.
    """


class MergeRefused(EntityError):
    """Two entities were not merged, and this says why.

    Raised rather than returned because a caller that ignored a refused merge would
    proceed believing two entities are one. The correlation layer catches it and
    records the reason on both entities via :meth:`Entity.note_not_merged`.
    """


# ── enumerations ────────────────────────────────────────────────────────────


class EntityType(StrEnum):
    """The kinds of thing CYPHRA tracks across time.

    :class:`enum.StrEnum` rather than ``(str, Enum)`` because these values are
    embedded in entity keys (``host:hostname:ws01``), written into VedDB key names
    and compared against strings from YAML rules and SQL results. A plain
    ``(str, Enum)`` member stringifies as ``EntityType.HOST`` — which looks
    plausible in a log line and matches nothing — whereas a ``StrEnum`` member
    stringifies, formats and serialises as its value.

    ``HOST``, ``USER`` and ``IP`` are the types the correlation graph merges and
    scores. The rest are leaves: intel attaches to them and they appear in a
    timeline, but two of them are rarely "the same thing discovered twice", so there
    is little merge semantics to get wrong. There is deliberately no ``device`` —
    see the module docstring.
    """

    HOST = "host"
    USER = "user"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    PROCESS = "process"
    MAILBOX = "mailbox"
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_RESOURCE = "cloud_resource"
    SERVICE = "service"
    SESSION = "session"


#: The types with real merge pressure, and the only ones ``correlate/risk.py`` scores.
PRIMARY_TYPES: frozenset[EntityType] = frozenset(
    {EntityType.HOST, EntityType.USER, EntityType.IP}
)


class IdKind(StrEnum):
    """Every way an entity can be named. See :data:`SPECS` for their properties."""

    # host
    MACHINE_UID = "machine_uid"
    DEVICE_GUID = "device_guid"
    SERIAL = "serial"
    FQDN = "fqdn"
    HOSTNAME = "hostname"
    MAC = "mac"
    # address
    IP = "ip"
    NAT_IP = "nat_ip"
    # user
    SID = "sid"
    ENTRA_OID = "entra_oid"
    OKTA_UID = "okta_uid"
    IAM_ARN = "iam_arn"
    UPN = "upn"
    SAM = "sam"
    POSIX_USER = "posix_user"
    USER_UID = "user_uid"
    # adjacent to a user
    EMAIL = "email"
    SESSION_UID = "session_uid"
    # cloud
    CLOUD_ACCOUNT = "cloud_account"
    RESOURCE_ID = "resource_id"
    # leaves
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    PROCESS_UID = "process_uid"
    SERVICE_NAME = "service_name"


class Platform(StrEnum):
    """Where an account or host lives, because it decides the case rule.

    Only the case rule and the meaning of a generic user uid depend on this, and for
    the case rule only two answers matter: fold or do not. Both are recorded
    explicitly rather than inferred from a value's shape, because inference here has
    an asymmetric cost — see :func:`fold_username`.
    """

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ENTRA = "entra"
    OKTA = "okta"
    AWS = "aws"
    GCP = "gcp"
    M365 = "m365"
    GWS = "gws"
    NETWORK = "network"
    UNKNOWN = ""


#: Platforms whose account names are case-*insensitive*, so two spellings are one
#: account and folding is correct.
#:
#: * ``windows`` — SAM and AD ``sAMAccountName`` are case-insensitive; ``net user``
#:   will not create ``Bob`` alongside ``bob``.
#: * ``macos`` — local account names resolve through Open Directory, which is
#:   case-insensitive. (The filesystem's own case behaviour is a separate question
#:   and does not govern account lookup.)
#: * ``entra``, ``m365``, ``gws`` — the identifier is a UPN or a mail address, whose
#:   domain part is case-insensitive by RFC 5321 and whose local part all three
#:   providers also treat insensitively.
#: * ``okta`` — logins are matched case-insensitively.
#: * ``aws`` — IAM entity names are unique without regard to case, so two spellings
#:   cannot be two principals.
#:
#: ``linux`` is absent because POSIX account names *are* case-sensitive: ``useradd
#: Bob`` succeeds on a system that already has ``bob``, and the result is two
#: accounts with two home directories. ``gcp`` is absent because a service-account
#: identifier is an address whose local part Google generates lowercase anyway, so
#: folding buys nothing and no risk is worth taking for nothing. ``UNKNOWN`` is
#: absent by design: see :func:`fold_username`.
CASE_INSENSITIVE_PLATFORMS: frozenset[Platform] = frozenset(
    {
        Platform.WINDOWS,
        Platform.MACOS,
        Platform.ENTRA,
        Platform.OKTA,
        Platform.AWS,
        Platform.M365,
        Platform.GWS,
    }
)


class Criticality(IntEnum):
    """How much it matters that this entity keeps working.

    Ordered so comparisons read naturally (``entity.criticality >=
    Criticality.HIGH``). It drives two opposite things, and the tension is the
    point: prioritisation in triage — a high-criticality victim outranks a low one —
    and *restraint* in response, because a high-criticality host is exactly where an
    automated block causes the outage. The same number pushes an alert up the queue
    and pushes an action towards an approval gate.
    """

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AddressScope(StrEnum):
    """What kind of address this is, which decides whether it can be an entity."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link_local"
    CGNAT = "cgnat"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    PUBLIC = "public"


#: Scopes for which an address does not name one durable thing, so it must never be
#: an entity or a response target. Loopback is the SOC host itself; link-local is
#: per-segment and CGNAT is per-carrier, so both are ambiguous by construction;
#: multicast and reserved are not endpoints at all.
UNROUTABLE_SCOPES: frozenset[AddressScope] = frozenset(
    {
        AddressScope.LOOPBACK,
        AddressScope.LINK_LOCAL,
        AddressScope.MULTICAST,
        AddressScope.RESERVED,
    }
)


# ── identifier specifications ───────────────────────────────────────────────


@dataclass(frozen=True)
class IdentifierSpec:
    """One way of naming an entity, and how much that name can be trusted.

    ``durability`` answers "if I see this value twice, how sure am I it is the same
    thing?" on a 1–5 scale, and :data:`MIN_MERGE_DURABILITY` is the line below which
    a value may be recorded but never merged on:

    ==  ==================================================================
    5   Issued once, never reused, not forgeable in the telemetry that
        carries it — an AD ``objectSid``, an EDR ``machine_uid``, a
        content hash, a cloud resource id.
    4   Administratively unique and stable in practice, but reassignable —
        a hostname, a UPN, a serial number.
    3   Unique per instance but forgeable or duplicated in practice — a
        MAC address, an MD5.
    2   A lease: correct at an instant, wrong an hour later — an IP.
    1   Shared by construction — a NAT egress or proxy address.
    ==  ==================================================================

    ``spoofable`` is a separate axis, consumed by the response safety envelope
    rather than by correlation. A source IP in a packet is attacker-controlled, so an
    action keyed on one is an abuse primitive: the plan's Phase 5 gate requires that
    a spoofed-source flood produce no third-party block, and this flag is what that
    check reads.

    ``scoped`` marks a value whose uniqueness holds only within a namespace — a
    hostname within a DNS domain, an account within an AD domain, a service within a
    host. ``strict_scope`` additionally *refuses to merge* on such a value when no
    namespace is available; see :data:`STRICT_SCOPE_KINDS` for why only the account
    kinds get it.

    ``case_sensitive`` and ``case_insensitive`` are a deliberate tri-state, because
    for account names the case rule has three genuinely different sources:

    * ``case_sensitive`` — the *specification* settles it. A POSIX account name is
      case-sensitive, so ``useradd Bob`` succeeds on a host that already has ``bob``.
      Never fold, whatever the reporting platform claims.
    * ``case_insensitive`` — the *kind* settles it. A ``sam`` value is
      ``DOMAIN\\account``, which exists only in Windows/AD, and a ``upn`` exists only
      in AD, Entra, Okta, M365 and Workspace. Every one of those directories is
      case-insensitive, so there is no case-sensitive namespace to be wrong about:
      always fold, even when the platform is unknown. This matters because
      :data:`Platform.UNKNOWN` is the *common* path — many collectors carry an account
      name with no OS field at all — and leaving ``CORP\\JDoe`` and ``CORP\\jdoe``
      unfolded splits one person into two entities on the most-queried kind there is.
    * neither flag — nothing intrinsic settles it, so the reporting platform decides
      via :func:`fold_username`, taking the reportable side when it is unknown.
    """

    kind: IdKind
    entity_type: EntityType
    durability: int
    spoofable: bool = False
    case_sensitive: bool = False
    case_insensitive: bool = False
    scoped: bool = False
    strict_scope: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if not 1 <= self.durability <= 5:
            raise EntityError(f"{self.kind}: durability must be 1..5")
        if self.strict_scope and not self.scoped:
            raise EntityError(f"{self.kind}: strict_scope requires scoped")
        if self.case_sensitive and self.case_insensitive:
            raise EntityError(
                f"{self.kind}: cannot be both case_sensitive and case_insensitive"
            )

    @property
    def mergeable(self) -> bool:
        return self.durability >= MIN_MERGE_DURABILITY

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.kind}(d{self.durability}{'/spoofable' if self.spoofable else ''})"


def _specs() -> dict[IdKind, IdentifierSpec]:
    rows = [
        # ── host ──
        IdentifierSpec(IdKind.MACHINE_UID, EntityType.HOST, 5, note=
                       "EDR enrolment id (Defender machineId, CrowdStrike aid). "
                       "The strongest host identifier there is: it survives a "
                       "rename, a re-IP and a reimage that re-enrols."),
        IdentifierSpec(IdKind.DEVICE_GUID, EntityType.HOST, 5, note=
                       "AD computer objectGUID / Intune device id. Unique for the "
                       "life of the object and, unlike a SID, survives a domain "
                       "migration."),
        IdentifierSpec(IdKind.SERIAL, EntityType.HOST, 4, note=
                       "Hardware serial. Durable, absent from most telemetry, and "
                       "duplicated by VM cloning often enough not to rank 5."),
        IdentifierSpec(IdKind.FQDN, EntityType.HOST, 4, note=
                       "Fully-qualified name: carries its own namespace, so it needs "
                       "no scope."),
        IdentifierSpec(IdKind.HOSTNAME, EntityType.HOST, 4, scoped=True, note=
                       "Short name, unique within a domain. Two forests can each "
                       "have a WS01, so the domain is recorded when known and "
                       "scope_collisions() reports a clash."),
        IdentifierSpec(IdKind.MAC, EntityType.HOST, 3, spoofable=True, note=
                       "Unique per interface, reassignable with one command, and "
                       "duplicated by VM templates. Recorded, never merged on."),
        # ── address ──
        IdentifierSpec(IdKind.IP, EntityType.IP, 2, spoofable=True, note=
                       "A lease, not a name. It identifies an address entity; its "
                       "link to a host is a temporal binding, which is why merging "
                       "two hosts on a shared address is impossible here."),
        IdentifierSpec(IdKind.NAT_IP, EntityType.IP, 1, spoofable=True, note=
                       "An address known to be shared — NAT egress, proxy, VPN "
                       "concentrator. Everything behind it looks identical."),
        # ── user ──
        IdentifierSpec(IdKind.SID, EntityType.USER, 5, note=
                       "Windows security identifier. Never reused within a domain, "
                       "not even after the account is deleted."),
        IdentifierSpec(IdKind.ENTRA_OID, EntityType.USER, 5, note=
                       "Entra ID object id. Stable across UPN and display renames."),
        IdentifierSpec(IdKind.OKTA_UID, EntityType.USER, 5, note="Okta user id."),
        IdentifierSpec(IdKind.IAM_ARN, EntityType.USER, 5, case_sensitive=True, note=
                       "AWS principal ARN. A deleted-then-recreated IAM user reuses "
                       "the ARN while getting a new unique id, so the ARN names the "
                       "principal, not the incarnation."),
        IdentifierSpec(IdKind.UPN, EntityType.USER, 4, case_insensitive=True,
                       scoped=True, strict_scope=True,
                       note="User principal name. Unique now; reassigned on rename "
                       "and reissued when a leaver's name is reused. Folded whatever "
                       "the platform, because a UPN only exists in a directory."),
        IdentifierSpec(IdKind.SAM, EntityType.USER, 4, case_insensitive=True,
                       scoped=True, strict_scope=True,
                       note="DOMAIN\\\\account. Unique within the domain; every "
                       "domain has an Administrator. Windows-only by construction, "
                       "so folded even when the platform is unknown."),
        IdentifierSpec(IdKind.POSIX_USER, EntityType.USER, 4, case_sensitive=True,
                       scoped=True, strict_scope=True, note=
                       "POSIX account name. Case-sensitive by specification, and "
                       "local to one host unless the host is directory-joined."),
        IdentifierSpec(IdKind.USER_UID, EntityType.USER, 4, note=
                       "A provider-assigned user id whose provider is not known. "
                       "Ranked 4 but refused for merging by Identifier.make, "
                       "because two providers can both issue '12345'."),
        # ── adjacent to a user ──
        IdentifierSpec(IdKind.EMAIL, EntityType.MAILBOX, 4, note=
                       "Mail address. Also an identifier of the user who owns the "
                       "mailbox, which is what makes a phishing case resolve to an "
                       "account rather than to an address."),
        IdentifierSpec(IdKind.SESSION_UID, EntityType.SESSION, 5, note=
                       "Logon session / token id. Durable but short-lived, which is "
                       "exactly what makes it the right unit for a revoke action."),
        # ── cloud ──
        IdentifierSpec(IdKind.CLOUD_ACCOUNT, EntityType.CLOUD_ACCOUNT, 5, note=
                       "AWS account id, Azure subscription, GCP project."),
        IdentifierSpec(IdKind.RESOURCE_ID, EntityType.CLOUD_RESOURCE, 5,
                       case_sensitive=True, note=
                       "ARN / Azure resource id / GCP resource name."),
        # ── leaves ──
        IdentifierSpec(IdKind.DOMAIN, EntityType.DOMAIN, 4, note=
                       "DNS name. Case-insensitive by specification."),
        IdentifierSpec(IdKind.URL, EntityType.URL, 4, case_sensitive=True, note=
                       "Scheme and host are folded, the path is not: a path is "
                       "case-sensitive on every server that matters, so /Admin and "
                       "/admin are two locations."),
        IdentifierSpec(IdKind.SHA256, EntityType.FILE, 5, note=
                       "Content identity. Two files with this hash are one file."),
        IdentifierSpec(IdKind.SHA1, EntityType.FILE, 4, note=
                       "Collision-attackable since SHAttered, so it identifies a "
                       "file for triage but should not be the sole basis of a block."),
        IdentifierSpec(IdKind.MD5, EntityType.FILE, 3, note=
                       "Collisions are cheap and demonstrated. Kept because most "
                       "intel feeds still publish it, ranked so it cannot merge two "
                       "files on its own."),
        IdentifierSpec(IdKind.PROCESS_UID, EntityType.PROCESS, 5, note=
                       "Sysmon ProcessGuid or equivalent. Unique per execution, "
                       "which is what lets a process tree be reassembled."),
        IdentifierSpec(IdKind.SERVICE_NAME, EntityType.SERVICE, 4, scoped=True, note=
                       "A Windows service, systemd unit or cloud service name. Unique "
                       "within its host, which is the scope — forty thousand hosts run "
                       "a service called 'Spooler'. Not strict_scope: an unqualified "
                       "service name merging is a nuisance, not a mis-attributed "
                       "person."),
    ]
    return {r.kind: r for r in rows}


#: Every identifier kind's properties, by kind.
SPECS: dict[IdKind, IdentifierSpec] = _specs()

#: Kinds that refuse to merge when no namespace is available.
#:
#: Only the account kinds, and the asymmetry against ``hostname`` is deliberate. A
#: bare account name is shared across identity providers that are frequently
#: unrelated — a partner forest, a personal Okta tenant, a standalone Linux box all
#: have an ``admin`` and a ``svc_backup`` — and a false *account* merge is the one
#: that puts a stranger's activity in someone's case file. A bare host name
#: appearing in two *host-identifier* sets almost always means two agents on one
#: machine, and refusing that merge would split the endpoint in half, which is the
#: exact failure the module docstring exists to prevent. So accounts take the strict
#: rule, hosts take the practical one, and :func:`scope_collisions` reports the host
#: case instead of guessing at it.
#:
#: :func:`set_default_domain` is the one-line fix for a single-domain deployment: it
#: qualifies bare account names so they consolidate normally.
#:
#: For these kinds — and *only* these — the namespace is folded into the identifier
#: value itself, so it reaches the entity key: ``sam`` as ``domain\account``, ``upn``
#: and ``posix_user`` as ``account@namespace``. Every other scoped kind keeps its
#: scope beside the value as metadata. The difference is the whole reason
#: ``strict_scope`` is a separate flag from ``scoped``: a namespace that stays outside
#: the value cannot separate two entities, so ``jdoe`` scoped to CORP and ``jdoe``
#: scoped to ACME would share one key and be marked mergeable — one entity for two
#: people, which is precisely what this set exists to prevent. Any predicate that
#: flips ``mergeable`` has to flip the key with it or it is decorative.
STRICT_SCOPE_KINDS: frozenset[IdKind] = frozenset(
    k for k, s in SPECS.items() if s.strict_scope
)


def spec(kind: IdKind | str) -> IdentifierSpec:
    """Resolve an identifier kind's spec, listing the valid kinds on a miss."""
    try:
        return SPECS[IdKind(kind)]
    except ValueError:
        raise EntityError(
            f"{kind!r} is not an identifier kind. Valid: "
            f"{', '.join(sorted(k.value for k in IdKind))}"
        ) from None


#: Identifiers that name one type of thing but also belong to another within the
#: same part of an event: an address and a session are not a host and a user, but
#: they are *bound to* one for an interval. These are the only cross-type
#: attachments the bridge makes, and they are the three that matter — attribution
#: (which host had this address), revocation (which session belongs to this
#: account), and phishing (which account owns this mailbox).
CROSS_ATTACH: dict[EntityType, EntityType] = {
    EntityType.IP: EntityType.HOST,
    EntityType.SESSION: EntityType.USER,
    EntityType.MAILBOX: EntityType.USER,
}


# ── deployment-wide default namespace ───────────────────────────────────────

_DEFAULT_DOMAIN = ""


def set_default_domain(domain: str) -> None:
    """Declare the namespace that unqualified account names belong to.

    Most collectors emit a bare account name, and in a single-domain estate ``jdoe``
    really is ``CORP\\jdoe``. Without being told, this module refuses to merge on a
    bare name (see :data:`STRICT_SCOPE_KINDS`), which is safe and fragments the user
    graph. Setting this qualifies those names so they consolidate, and it is a
    *declaration* rather than an inference: nothing in the telemetry can tell us
    whether the estate has one domain or five, so the answer has to come from
    configuration — ``soc.yaml``'s ``identity.default_domain``.

    Pass ``""`` to clear it, which is the correct setting for a multi-domain estate:
    visible fragmentation there beats silently merging two people.
    """
    global _DEFAULT_DOMAIN
    _DEFAULT_DOMAIN = (domain or "").strip().lower().rstrip(".")


def default_domain() -> str:
    return _DEFAULT_DOMAIN


# ── the event bridge tables ─────────────────────────────────────────────────


@dataclass(frozen=True)
class FieldMap:
    """How one flat :class:`~core.schema.ocsf.Event` field names an entity.

    ``facet`` groups the fields that describe *one* thing. An event's ``device_*``
    fields are all about one machine; its ``src_endpoint_*`` fields are about
    another. That grouping is free structural information the event already states,
    and discarding it would force the correlation layer to re-derive statistically
    what the schema says outright.

    ``scope_field`` names the sibling field that supplies the namespace — the reason
    ``actor_user_name`` plus ``actor_user_domain`` becomes a mergeable
    ``CORP\\jdoe`` instead of a bare, un-mergeable ``jdoe``. It is the single most
    important entry in this table, and it is invisible from the observable list:
    OCSF does not class ``actor.user.domain`` as an observable, so a bridge built on
    observables alone can never merge users at all.

    ``by_platform`` covers the fields whose *kind* depends on the platform. OCSF's
    ``user.uid`` is a SID on Windows, an object id in Entra and an ARN in AWS; those
    have different uniqueness properties, so one generic kind would either
    over-trust the ambiguous case or under-trust the certain ones.
    """

    kind: IdKind
    facet: str
    role: str
    scope_field: str = ""
    by_platform: Mapping[Platform, IdKind] = field(default_factory=dict)


_USER_UID_BY_PLATFORM: dict[Platform, IdKind] = {
    Platform.WINDOWS: IdKind.SID,
    Platform.ENTRA: IdKind.ENTRA_OID,
    Platform.M365: IdKind.ENTRA_OID,
    Platform.OKTA: IdKind.OKTA_UID,
    Platform.AWS: IdKind.IAM_ARN,
}

_USER_NAME_BY_PLATFORM: dict[Platform, IdKind] = {
    Platform.LINUX: IdKind.POSIX_USER,
    Platform.MACOS: IdKind.POSIX_USER,
    Platform.ENTRA: IdKind.UPN,
    Platform.OKTA: IdKind.UPN,
    Platform.M365: IdKind.UPN,
    Platform.GWS: IdKind.UPN,
}

#: Flat ``Event`` field → the identifier it carries. Keyed on flat field names
#: rather than on OCSF observable paths, for three reasons the observable list
#: cannot supply: the sibling domain fields above, the identity-bearing fields OCSF
#: does not class as observables (``actor_session_uid``, ``process_uid``,
#: ``email_to``, ``process_file_sha1``, ``cloud_project_uid``), and the fact that
#: flat names are what the lake stores as columns, so a hunt query and this table
#: cannot drift. :data:`OBSERVABLE_TO_IDENTIFIER` is *derived* from this for the
#: reverse direction.
#:
#: Fields absent here are absent deliberately. A destination port, a command line, a
#: user agent and a file *name* are all evidence *about* an entity and none of them
#: names one: two hosts run ``cmd.exe`` and forty thousand hosts talk to port 443.
FIELD_TO_IDENTIFIER: dict[str, FieldMap] = {
    # ── the host the event was observed on ──
    "device_uid": FieldMap(IdKind.MACHINE_UID, "device", "device"),
    "device_hostname": FieldMap(IdKind.HOSTNAME, "device", "device",
                                scope_field="device_domain"),
    "device_mac": FieldMap(IdKind.MAC, "device", "device"),
    "device_ip": FieldMap(IdKind.IP, "device", "device"),
    "device_instance_uid": FieldMap(IdKind.RESOURCE_ID, "device", "device"),
    # ── the two ends of a connection ──
    "src_endpoint_hostname": FieldMap(IdKind.HOSTNAME, "src", "src",
                                      scope_field="src_endpoint_domain"),
    "src_endpoint_mac": FieldMap(IdKind.MAC, "src", "src"),
    "src_endpoint_ip": FieldMap(IdKind.IP, "src", "src"),
    "dst_endpoint_hostname": FieldMap(IdKind.HOSTNAME, "dst", "dst",
                                      scope_field="dst_endpoint_domain"),
    "dst_endpoint_mac": FieldMap(IdKind.MAC, "dst", "dst"),
    "dst_endpoint_ip": FieldMap(IdKind.IP, "dst", "dst"),
    # ── who did it ──
    "actor_user_name": FieldMap(IdKind.SAM, "actor", "actor",
                                scope_field="actor_user_domain",
                                by_platform=_USER_NAME_BY_PLATFORM),
    "actor_user_uid": FieldMap(IdKind.USER_UID, "actor", "actor",
                               by_platform=_USER_UID_BY_PLATFORM),
    "actor_user_email": FieldMap(IdKind.EMAIL, "actor", "actor"),
    "actor_session_uid": FieldMap(IdKind.SESSION_UID, "actor", "actor"),
    "actor_process_uid": FieldMap(IdKind.PROCESS_UID, "actor_process", "actor"),
    "actor_process_file_sha256": FieldMap(IdKind.SHA256, "actor_process", "actor"),
    # ── who it was done to ──
    "user_name": FieldMap(IdKind.SAM, "user", "target", scope_field="user_domain",
                          by_platform=_USER_NAME_BY_PLATFORM),
    "user_uid": FieldMap(IdKind.USER_UID, "user", "target",
                         by_platform=_USER_UID_BY_PLATFORM),
    "user_email": FieldMap(IdKind.EMAIL, "user", "target"),
    "user_account_uid": FieldMap(IdKind.CLOUD_ACCOUNT, "user", "target"),
    # ── what ran ──
    "process_uid": FieldMap(IdKind.PROCESS_UID, "process", "referenced"),
    "process_file_sha256": FieldMap(IdKind.SHA256, "process", "referenced"),
    "process_file_sha1": FieldMap(IdKind.SHA1, "process", "referenced"),
    "process_file_md5": FieldMap(IdKind.MD5, "process", "referenced"),
    "module_file_sha256": FieldMap(IdKind.SHA256, "module", "referenced"),
    # ── what it touched ──
    "file_sha256": FieldMap(IdKind.SHA256, "file", "referenced"),
    "file_md5": FieldMap(IdKind.MD5, "file", "referenced"),
    "dns_query_hostname": FieldMap(IdKind.DOMAIN, "dns", "referenced"),
    "url_hostname": FieldMap(IdKind.DOMAIN, "url", "referenced"),
    "url_string": FieldMap(IdKind.URL, "url", "referenced"),
    "email_from": FieldMap(IdKind.EMAIL, "email_sender", "actor"),
    "email_smtp_from": FieldMap(IdKind.EMAIL, "email_envelope", "actor"),
    "email_to": FieldMap(IdKind.EMAIL, "email_recipient", "target"),
    # ── cloud ──
    "cloud_account_uid": FieldMap(IdKind.CLOUD_ACCOUNT, "cloud", "referenced"),
    "cloud_project_uid": FieldMap(IdKind.CLOUD_ACCOUNT, "cloud_project", "referenced"),
    "resource_uid": FieldMap(IdKind.RESOURCE_ID, "resource", "target"),
    "service_name": FieldMap(IdKind.SERVICE_NAME, "service", "referenced"),
}


def _observable_map() -> dict[str, IdKind]:
    """Derive the observable-path view of :data:`FIELD_TO_IDENTIFIER`.

    Hunt queries and intel matches arrive holding an observable's ``name`` — an OCSF
    path such as ``src_endpoint.ip`` — and need to know what kind of entity it
    names. Deriving that from the field table rather than writing it out a second
    time is what keeps the two from disagreeing; a hand-maintained copy is how a
    path like ``url.text`` (which does not exist — the real one is
    ``url.url_string``) survives review.
    """
    out: dict[str, IdKind] = {}
    for flat, fm in FIELD_TO_IDENTIFIER.items():
        path = OCSF_PATH.get(flat)
        if path:
            out[path] = fm.kind
    return out


#: OCSF path → identifier kind, derived from :data:`FIELD_TO_IDENTIFIER`.
OBSERVABLE_TO_IDENTIFIER: dict[str, IdKind] = _observable_map()


# ── normalisation ───────────────────────────────────────────────────────────

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SID_RE = re.compile(r"^S-1-\d+(-\d+)*$", re.I)
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
_HEX_ID_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*://)([^/?#]+)(.*)$")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def address_scope(value: str) -> AddressScope:
    """Classify an address, which decides whether it can stand for an entity.

    Checked in specificity order because the ranges nest. ``127.0.0.1`` is loopback
    *and* not global; ``100.64.0.0/10`` is private *and* CGNAT — and CGNAT is the
    answer that matters, because a carrier address with thousands of subscribers
    behind it must not become one entity or one block target.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EntityError(f"{value!r} is not an IP address: {exc}") from exc
    if addr.is_loopback:
        return AddressScope.LOOPBACK
    if addr.is_link_local:
        return AddressScope.LINK_LOCAL
    if addr.is_multicast:
        return AddressScope.MULTICAST
    if addr.version == 4 and addr in _CGNAT:
        return AddressScope.CGNAT
    if addr.is_unspecified or addr.is_reserved:
        return AddressScope.RESERVED
    if addr.is_private:
        return AddressScope.PRIVATE
    return AddressScope.PUBLIC


def cidr_reason(value: str, cidrs: Iterable[str] = ()) -> str:
    """Why an address is protected, or ``""`` if it is not.

    The single consumer of ``soc.yaml``'s ``respond.protected_cidrs``, so the config
    list has one interpretation rather than one per action module. Returns the reason
    string :meth:`Entity.protect` needs, because a refusal an operator cannot explain
    is a refusal that gets overridden.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return ""
    for raw in cidrs:
        try:
            net = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return f"{value} is inside the protected range {net}"
    scope = address_scope(value)
    if scope in UNROUTABLE_SCOPES:
        return f"{value} is {scope}, which is not a valid action target"
    return ""


def fold_username(
    name: str,
    platform: Platform | str = Platform.UNKNOWN,
    kind: IdKind | str | None = None,
) -> str:
    """Apply the case rule to an account name — the kind's if it has one, else the
    platform's.

    Pass ``kind`` whenever it is known, because for most account kinds the kind is
    decisive and the platform is noise. ``sam`` and ``upn`` carry
    ``case_insensitive`` (they exist only inside case-insensitive directories) and
    ``posix_user`` carries ``case_sensitive`` (the specification says so). See
    :class:`IdentifierSpec` for that tri-state.

    Only when nothing intrinsic settles it does the platform decide, folding for
    platforms in :data:`CASE_INSENSITIVE_PLATFORMS`. An unknown platform is *not*
    folded, and the asymmetry is deliberate:

    * Folding when the platform is actually case-sensitive merges two real accounts
      into one entity. Their activity combines, a benign user's volume masks an
      attacker's, and the merge cannot be undone from the stored data.
    * Not folding when the platform is actually case-insensitive splits one account
      across two entities. A brute force spread over case variants then reads as two
      small events instead of one large one — a missed detection, but a *detectable*
      one: :func:`case_collisions` finds exactly these pairs.

    A wrong answer that reports itself beats a wrong answer that does not, so the
    unknown case takes the reportable side.
    """
    text = name.strip()
    if not text:
        raise EntityError("an account name cannot be empty")
    if kind is not None:
        s = spec(kind)
        if s.case_sensitive:
            return text
        if s.case_insensitive:
            return text.lower()
    return text.lower() if Platform(platform) in CASE_INSENSITIVE_PLATFORMS else text


def split_account(value: str) -> tuple[str, str, IdKind]:
    """Split an account identifier into ``(domain, account, shape)``.

    Handles the three spellings one user arrives under — ``CORP\\jdoe`` (SAM),
    ``jdoe@corp.example.com`` (UPN or mail) and bare ``jdoe`` — and reports which it
    saw, because the shape decides whether the value carries its own namespace.

    A bare name comes back with an empty domain, which :meth:`Identifier.make` then
    treats as un-mergeable unless a scope or :func:`set_default_domain` supplies one.
    """
    text = value.strip()
    if not text:
        raise EntityError("an account identifier cannot be empty")
    if "\\" in text:
        dom, _, acct = text.rpartition("\\")
        if not acct or not dom.strip():
            raise EntityError(f"{value!r} has a separator but not both parts")
        return dom.strip().lower(), acct.strip(), IdKind.SAM
    if "@" in text:
        acct, _, dom = text.rpartition("@")
        if not acct or not dom:
            raise EntityError(f"{value!r} is not a usable UPN or mail address")
        return dom.strip().lower(), acct.strip(), IdKind.UPN
    return "", text, IdKind.SAM


def normalise(
    kind: IdKind | str, value: Any, platform: Platform | str = Platform.UNKNOWN
) -> str:
    """Canonicalise an identifier value, or raise saying why it cannot be one.

    Every value entering the entity graph passes through here, so two spellings of
    one thing become one node. It is per-kind rather than shape-inferred, because
    guessing from the shape of a string is how a MAC ends up lowercased on one path
    and uppercased on another, producing two nodes for one interface.

    Idempotent for every kind: ``normalise(k, normalise(k, v)) == normalise(k, v)``,
    which is what lets :class:`Identifier` verify its own value on construction and
    so refuse a raw one that bypassed :meth:`Identifier.make`.
    """
    k = kind if isinstance(kind, IdKind) else IdKind(kind)
    spec(k)
    if value is None:
        raise EntityError(f"{k} cannot be None")
    text = str(value).strip()
    if not text:
        raise EntityError(f"{k} cannot be empty")

    if k in (IdKind.IP, IdKind.NAT_IP):
        try:
            addr = ipaddress.ip_address(text)
        except ValueError as exc:
            raise EntityError(f"{k}: {text!r} is not an IP address: {exc}") from exc
        # A compressed and an expanded IPv6 form are one address, and a mapped IPv4
        # (::ffff:10.0.0.1) is the same host as its bare form — a dual-stack host
        # would otherwise appear twice in the graph.
        return str(getattr(addr, "ipv4_mapped", None) or addr)

    if k is IdKind.MAC:
        digits = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
        if len(digits) != 12:
            raise EntityError(f"mac: {text!r} has {len(digits)} hex digits, expected 12")
        return ":".join(digits[i:i + 2] for i in range(0, 12, 2))

    if k in (IdKind.HOSTNAME, IdKind.FQDN, IdKind.DOMAIN):
        name = text.rstrip(".").lower()
        if k is IdKind.HOSTNAME:
            # The short name is the label before the first dot. Storing an FQDN under
            # `hostname` would make ws01 and ws01.corp.example.com two hosts.
            name = name.split(".", 1)[0]
        if not name or any(c.isspace() for c in name) or "\\" in name:
            raise EntityError(f"{k}: {text!r} is not a DNS name")
        return name

    if k in (IdKind.SAM, IdKind.UPN, IdKind.POSIX_USER):
        dom, acct, shape = split_account(text)
        # The kind decides the case rule for all three of these, so `platform` is
        # passed only to keep the one signature; fold_username ignores it here.
        folded = fold_username(acct, platform, kind=k)
        if k is IdKind.POSIX_USER:
            if not dom:
                return folded  # case-sensitive by specification; returned unfolded
            # A POSIX account's namespace is the *host* it exists on — every box has
            # its own root and its own bob — and it is spelled account@host, the way
            # sshd and sudo write it. It has to survive normalisation: dropping it
            # here would collapse forty thousand local `root` accounts into one
            # entity, which is a worse false merge than any this module refuses.
            # A winbind-joined host genuinely reports DOMAIN\account, so where the
            # value arrived in that spelling it is kept, not rewritten.
            return f"{dom}\\{folded}" if shape is IdKind.SAM else f"{folded}@{dom}"
        if k is IdKind.UPN:
            return f"{folded}@{dom}" if dom else folded
        # SAM is always spelled domain\account, whatever spelling it arrived in. One
        # kind must have one spelling: Windows logs put a UPN in TargetUserName often
        # enough that preserving the arrival shape would key `CORP\jdoe` and
        # `jdoe@CORP` as two people, and unlike a case split or a scope clash there is
        # no reportable half that would ever surface it.
        #
        # The limitation this leaves is honest and narrower: a NetBIOS domain and its
        # DNS name are different strings, so `CORP\jdoe` and `jdoe@corp.example.com`
        # still key apart. Closing that needs a directory lookup, which belongs in
        # enrichment, not in a pure normaliser.
        return f"{dom}\\{folded}" if dom else folded

    if k is IdKind.EMAIL:
        acct, _, dom = text.rpartition("@")
        if not acct or not dom:
            raise EntityError(f"email: {text!r} is not a mail address")
        # The domain is case-insensitive by RFC 5321. The local part is formally
        # case-*sensitive*, and every provider CYPHRA connects to nonetheless treats
        # it insensitively — which is what makes an alert about J.Doe@example.com and
        # one about j.doe@example.com the same mailbox.
        return f"{acct.lower()}@{dom.lower()}"

    if k is IdKind.SID:
        if not _SID_RE.match(text):
            raise EntityError(f"sid: {text!r} is not a Windows SID (S-1-…)")
        return text.upper()

    if k in (IdKind.ENTRA_OID, IdKind.DEVICE_GUID):
        if not _GUID_RE.match(text.strip("{}")):
            raise EntityError(f"{k}: {text!r} is not a GUID")
        return text.strip("{}").lower()

    if k in (IdKind.SHA256, IdKind.SHA1, IdKind.MD5):
        want = {IdKind.SHA256: 64, IdKind.SHA1: 40, IdKind.MD5: 32}[k]
        low = text.lower()
        if len(low) != want or not _HEX_RE.match(low):
            raise EntityError(f"{k}: expected {want} hex characters, got {len(text)}")
        return low

    if k is IdKind.URL:
        # Fold the scheme and host only. A path is case-sensitive on every server
        # that matters, and folding it would merge two distinct payload URLs.
        m = _URL_RE.match(text)
        return f"{m.group(1).lower()}{m.group(2).lower()}{m.group(3)}" if m else text

    if k is IdKind.PROCESS_UID:
        # Sysmon writes ProcessGuid in braces; Defender and auditd do not.
        return text.strip("{}").lower()

    if k is IdKind.SESSION_UID:
        # A Windows logon id is hex (0x3e7), and 0x3E7 is the same session.
        return text.lower() if _HEX_ID_RE.match(text) else text

    if k in (IdKind.CLOUD_ACCOUNT, IdKind.MACHINE_UID):
        # A GUID-shaped value (an Azure subscription, some EDR ids) folds; anything
        # else is left alone, because a base64 or mixed-case vendor id would collide
        # under folding and neither Defender nor CrowdStrike needs it.
        return text.lower() if _GUID_RE.match(text) else text

    # IAM_ARN, RESOURCE_ID, SERIAL, USER_UID, SERVICE_NAME: case-significant or
    # opaque. Trimmed only.
    return text


def entity_key(entity_type: EntityType | str, kind: IdKind | str, value: str) -> str:
    """The stable key an entity is stored under.

    ``type:kind:value`` rather than a hash, because a key that can be read is a key
    that can be grepped out of a VedDB dump, pasted into a hunt query and recognised
    in a log line without a lookup. Values arrive normalised, so two spellings cannot
    produce two keys.

    The ``scope`` *field* is deliberately not an argument here. It looks like it should
    be — it is what makes the value unique — but keying on it means a collector that
    reports a domain and one that does not produce two keys for one host, which is the
    fragmentation this module exists to prevent. Scope travels as metadata and a
    genuine clash is reported by :func:`scope_collisions`.

    The three kinds in :data:`STRICT_SCOPE_KINDS` are the exception, and they get it
    without an exception here: for an account name the namespace is folded into the
    *value* by :func:`normalise`, so ``corp\\jdoe`` and ``acme\\jdoe`` are two values
    and therefore two keys. That is the right shape — a host reported with and without
    its domain is one host, whereas two domains' ``jdoe`` are two people — and it
    means this function stays a pure function of the value it is handed.

    Long values truncate with a digest of the whole appended, which bounds key length
    without letting two different long values collide.
    """
    et = EntityType(entity_type)
    k = IdKind(kind)
    safe = re.sub(r"[\x00-\x1f\s]", "_", value)
    if len(safe) > 96:
        safe = f"{safe[:83]}~{hashlib.sha256(value.encode()).hexdigest()[:12]}"
    return f"{et}:{k}:{safe}"


# ── the models ──────────────────────────────────────────────────────────────


class Identifier(BaseModel):
    """A normalised name for an entity, with its trust properties resolved.

    Build with :meth:`make`. Direct construction is still guarded — the validator
    re-runs :func:`normalise` and rejects a value that is not already canonical —
    because a raw value entering the graph is precisely how one thing becomes two
    nodes, and that failure is invisible until an investigation comes up short.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: IdKind
    value: str
    #: The namespace the value is unique within — an AD or DNS domain, a host for a
    #: local account. Metadata for every kind except the three in
    #: :data:`STRICT_SCOPE_KINDS`, where it is additionally folded *into* the value and
    #: so reaches the key; see :func:`entity_key`.
    scope: str = ""
    #: False when this value must not be merged on even though its kind normally
    #: could: a bare account name, a shared NAT address, a provider id with no known
    #: provider.
    mergeable: bool = True
    #: Why not. Recorded because a silent refusal to merge is indistinguishable from
    #: two genuinely different entities.
    reason: str = ""

    @model_validator(mode="after")
    def _canonical(self) -> "Identifier":
        want = normalise(self.kind, self.value)
        if want != self.value:
            raise EntityError(
                f"{self.kind} value {self.value!r} is not normalised (expected "
                f"{want!r}). Use Identifier.make(), which normalises; a raw value in "
                "the graph turns one thing into two nodes."
            )
        if not self.mergeable and not self.reason:
            raise EntityError(
                f"{self.kind}={self.value} is marked un-mergeable with no reason"
            )
        return self

    @classmethod
    def make(
        cls,
        kind: IdKind | str,
        value: Any,
        platform: Platform | str = Platform.UNKNOWN,
        scope: str = "",
        shared: bool = False,
    ) -> "Identifier":
        """Normalise a raw value into an identifier, resolving mergeability.

        ``scope`` is the namespace the value is unique within, normally supplied by
        the bridge from the event's sibling domain field. ``shared=True`` is how the
        correlation layer marks an address it has observed behind a NAT or proxy: it
        downgrades the kind to ``nat_ip``, so the value stops being usable the moment
        sharing is detected without any stored binding needing a rewrite.
        """
        k = IdKind(kind)
        sp = spec(k)
        plat = Platform(platform)
        scope = (scope or "").strip().lower().rstrip(".")

        if shared and sp.entity_type is EntityType.IP:
            return cls(
                kind=IdKind.NAT_IP, value=normalise(IdKind.NAT_IP, value),
                mergeable=False,
                reason="observed behind a NAT/proxy/VPN, so it names many hosts",
            )

        # A strict-scope account name is qualified *into its value*, from the sibling
        # domain field if the bridge supplied one and otherwise from the declared
        # deployment domain. Both paths have to do this, and the same way: leaving the
        # namespace beside the value instead of inside it would key CORP\jdoe and
        # ACME\jdoe both to `user:sam:jdoe` — one entity for two people, which is the
        # precise false merge `strict_scope` exists to prevent.
        ns = scope
        if not ns and _DEFAULT_DOMAIN and k in (IdKind.SAM, IdKind.UPN):
            # The declared default is a *directory* domain, so it qualifies directory
            # accounts only. A local POSIX account is not in it, and adopting it would
            # merge every Linux host's local `bob` into one person — the same failure
            # this block exists to prevent, arriving through the other door. A POSIX
            # account is qualified only by a scope a collector actually supplied.
            ns = _DEFAULT_DOMAIN
        if k in STRICT_SCOPE_KINDS and ns:
            raw = str(value).strip()
            if "\\" not in raw and "@" not in raw:
                if k is IdKind.SAM:
                    value = f"{ns}\\{raw}"
                else:  # UPN and POSIX_USER both spell it account@namespace
                    value = f"{raw}@{ns}"
                scope = ns

        norm = normalise(k, value, plat)
        if not sp.scoped:
            scope = ""
        elif k in STRICT_SCOPE_KINDS:
            # For these the namespace lives *in* the value, so the field is derived
            # from it rather than carried alongside it. Two reasons: a qualified name
            # needs no sibling field to be mergeable, and a scope that disagreed with
            # the value it describes would be a lie an investigation reads — passing
            # scope="acme" for `CORP\jdoe` must not label a corp account as acme's.
            # The namespace the event itself carries is the more specific fact.
            scope, _, _ = split_account(norm)

        mergeable, reason = sp.mergeable, ""
        if not mergeable:
            reason = (
                f"{k} has durability {sp.durability}, below the merge floor of "
                f"{MIN_MERGE_DURABILITY}"
            )
            if sp.entity_type is EntityType.IP:
                # Recorded on the same reason string rather than as a separate branch,
                # which would be unreachable: every IP-typed kind is already below the
                # floor, so the durability test always fires first. The scope is still
                # worth stating, because "loopback" and "a lease" are different facts
                # and `cidr_reason` gates a response action on the former.
                sc = address_scope(norm)
                if sc in UNROUTABLE_SCOPES:
                    reason += f"; and {sc} addresses do not name a durable thing at all"
        elif k is IdKind.USER_UID:
            # OCSF's user.uid with no platform to say whose id it is. Two providers
            # can each issue "12345", and merging two users on that is worse than
            # leaving them apart. With the platform known, the bridge picks
            # sid/entra_oid/okta_uid/iam_arn instead, all of which rank 5.
            mergeable = False
            reason = (
                "a provider-assigned user id with no known provider is not unique "
                "across providers; resolve the platform to get a sid/oid/ARN"
            )
        elif k in STRICT_SCOPE_KINDS and not scope:
            mergeable = False
            where = "host" if k is IdKind.POSIX_USER else "domain"
            fix = (
                "supply the host in `scope`"
                if k is IdKind.POSIX_USER
                else "supply the domain, or declare one with set_default_domain() "
                     "if this is a single-domain estate"
            )
            reason = (
                f"a bare {k} has no namespace, and every {where} has its own "
                f"{norm!r}; {fix}"
            )
        return cls(kind=k, value=norm, scope=scope, mergeable=mergeable, reason=reason)

    @property
    def spec(self) -> IdentifierSpec:
        return SPECS[self.kind]

    @property
    def entity_type(self) -> EntityType:
        """The type of thing this identifier *naturally* names.

        Distinct from the type of the entity it may be bound to: an ``ip``
        identifier naturally names an :attr:`EntityType.IP`, and it is *also* bound
        to a host for an interval. Keeping those apart is what makes a merge on a
        shared address impossible rather than merely discouraged.
        """
        return SPECS[self.kind].entity_type

    @property
    def key(self) -> str:
        return entity_key(self.entity_type, self.kind, self.value)

    def folded(self) -> str:
        """The case-folded value, for :func:`case_collisions` only."""
        return self.value.lower()

    def __str__(self) -> str:
        return f"{self.kind}={self.value}" + (f" @{self.scope}" if self.scope else "")


class Binding(BaseModel):
    """An identifier pointing at an entity over a closed time interval.

    The interval is the whole point. ``10.0.0.5`` belonging to ``WS01`` is not a
    fact, it is a fact *between two timestamps*; asking "whose address is this"
    without a time is asking an unanswerable question, and a platform that answers
    anyway attributes activity to the wrong machine after every DHCP renewal.

    ``last_seen`` is inclusive and extends as evidence arrives, so an open lease is
    a binding whose ``last_seen`` keeps moving rather than a null. A null would be
    indistinguishable from a binding whose closing evidence was simply lost, and
    "still true" and "unknown" are not the same claim.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    identifier: Identifier
    entity_key: str
    first_seen: float
    last_seen: float
    #: Which collector or connector asserted it. A DHCP lease and an inference from
    #: one packet are not equally good evidence.
    source: str = ""
    #: 0..100. Deliberately not a probability: it is compared and thresholded, never
    #: multiplied, and calling it a probability would invite the latter.
    confidence: int = 100
    #: True when the identifier can point at only one entity in this interval. A DHCP
    #: lease is exclusive; a NAT egress address is not, so an overlapping pair of
    #: non-exclusive bindings is normal rather than a contradiction.
    exclusive: bool = True

    @model_validator(mode="after")
    def _ordered(self) -> "Binding":
        if self.last_seen < self.first_seen:
            raise EntityError(
                f"binding for {self.identifier} ends before it starts "
                f"({self.last_seen} < {self.first_seen})"
            )
        if not 0 <= self.confidence <= 100:
            raise EntityError(f"confidence is a percentage, got {self.confidence}")
        if not self.entity_key:
            raise EntityError(f"binding for {self.identifier} names no entity")
        return self

    def covers(self, at: float) -> bool:
        """Whether this binding was in force at an instant."""
        return self.first_seen <= at <= self.last_seen

    def overlaps(self, other: "Binding") -> bool:
        return self.first_seen <= other.last_seen and other.first_seen <= self.last_seen

    def conflicts_with(self, other: "Binding") -> bool:
        """Two exclusive bindings of one identifier to different entities, at once.

        Either resolution has gone wrong or the identifier is shared and nobody has
        noticed yet. Both need reporting, so this is a question the correlation layer
        asks rather than a state it silently resolves by keeping the newer one.
        """
        return (
            self.identifier.key == other.identifier.key
            and self.entity_key != other.entity_key
            and self.exclusive
            and other.exclusive
            and self.overlaps(other)
        )

    def extend(self, at: float) -> "Binding":
        """Widen the interval to include an instant, returning a new binding.

        ``model_copy`` skips validation, which is safe here and only here: min and max
        cannot produce an out-of-order interval from an in-order one.
        """
        return self.model_copy(
            update={
                "first_seen": min(self.first_seen, at),
                "last_seen": max(self.last_seen, at),
            }
        )

    def __str__(self) -> str:
        return (
            f"{self.identifier} → {self.entity_key} "
            f"[{_iso(self.first_seen)}..{_iso(self.last_seen)}]"
        )


class EntityRef(BaseModel):
    """A pointer to an entity from an event, alert, case or graph edge.

    Deliberately thin. An alert that embedded a whole entity would freeze that
    entity's risk score and criticality at alert time, so a host later found to be a
    domain controller would still read as unimportant in every alert raised before
    the discovery — and a response gate consulting one of those alerts would wave
    through exactly the action criticality exists to stop. A key means every consumer
    reads the current entity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    entity_type: EntityType
    #: How it was named in the event, kept for the narrative: an analyst reading
    #: "10.0.0.5 (ws01)" learns something "host:hostname:ws01" alone hides.
    observed_as: str = ""
    #: The part it played, which is what a kill chain needs. A host that is the
    #: destination of one event and the source of the next is a lateral-movement
    #: pivot, and that is invisible if only membership is recorded.
    role: str = ""


class Entity(BaseModel):
    """A durable thing, everything known about it, and how it came to be known.

    Merges are recorded rather than applied destructively (:attr:`merged_from`,
    :attr:`merge_notes`) because entity resolution is a *guess*, and a guess that
    cannot be examined cannot be corrected. When an investigation turns on two hosts
    being one machine, the reason they were joined has to be inspectable.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    key: str
    entity_type: EntityType
    #: The name a human should see, chosen by :meth:`_pick_name` for stability rather
    #: than recency, so it does not flap between an address and a hostname.
    name: str = ""
    platform: Platform = Platform.UNKNOWN

    identifiers: list[Identifier] = []
    bindings: list[Binding] = []

    first_seen: float = 0.0
    last_seen: float = 0.0

    # ── enrichment, filled by enrich/ ──
    criticality: Criticality = Criticality.UNKNOWN
    crown_jewel: bool = False
    #: Never act on this entity automatically. Separate from ``criticality`` on
    #: purpose: criticality is a business judgement that shades a decision, while
    #: this is a hard stop the response engine checks first. A gateway is protected
    #: because blocking it takes the site off the internet, which is true regardless
    #: of how anyone rates its business value.
    protected: bool = False
    protected_reason: str = ""
    owner: str = ""
    business_unit: str = ""
    os_name: str = ""
    tags: list[str] = []

    # ── scoring, filled by correlate/risk.py ──
    risk_score: int = 0
    signal_count: int = 0

    # ── provenance ──
    schema_version: int = SCHEMA_VERSION
    sources: list[str] = []
    merged_from: list[str] = []
    merge_notes: list[str] = []

    @field_validator("risk_score", "signal_count")
    @classmethod
    def _non_negative(cls, v: int) -> int:
        if v < 0:
            raise EntityError(f"expected a non-negative count, got {v}")
        return v

    @model_validator(mode="after")
    def _consistent(self) -> "Entity":
        if self.protected and not self.protected_reason:
            raise EntityError(
                f"{self.key} is protected with no reason given. The reason is what an "
                "operator reads when an action is refused, and a refusal nobody can "
                "explain is a refusal that gets overridden."
            )
        if self.last_seen and self.first_seen and self.last_seen < self.first_seen:
            raise EntityError(f"{self.key} was last seen before it was first seen")
        return self

    # ── construction ───────────────────────────────────────────────────────

    @classmethod
    def make(
        cls,
        identifier: Identifier,
        at: float,
        source: str = "",
        platform: Platform | str = Platform.UNKNOWN,
        **fields: Any,
    ) -> "Entity":
        """Create an entity from the identifier that first named it."""
        ent = cls(
            key=identifier.key,
            entity_type=identifier.entity_type,
            name=identifier.value,
            platform=Platform(platform),
            first_seen=at,
            last_seen=at,
            sources=[source] if source else [],
            **fields,
        )
        ent.observe(identifier, at=at, source=source)
        return ent

    # ── observation ────────────────────────────────────────────────────────

    def observe(
        self,
        identifier: Identifier,
        at: float,
        source: str = "",
        confidence: int = 100,
    ) -> bool:
        """Record that this entity was seen under an identifier at an instant.

        Returns True when the identifier is new to this entity, False when an
        existing binding was extended instead. Extending rather than appending
        matters: an hourly heartbeat would otherwise accumulate one binding an hour
        and turn every temporal question into a scan.

        An identifier of a *different* natural type is accepted — an address and a
        session belong to a host and an account over an interval, and recording that
        is the whole reason :class:`Binding` exists. It cannot cause a false merge,
        because :meth:`mergeable_with` counts only identifiers of the entity's own
        type.
        """
        self.first_seen = min(self.first_seen, at) if self.first_seen else at
        self.last_seen = max(self.last_seen, at)
        if source and source not in self.sources:
            self.sources = self.sources + [source]

        for i, existing in enumerate(self.bindings):
            if existing.identifier.key == identifier.key:
                updated = list(self.bindings)
                updated[i] = existing.extend(at)
                self.bindings = updated
                return False

        self.identifiers = self.identifiers + [identifier]
        self.bindings = self.bindings + [
            Binding(
                identifier=identifier, entity_key=self.key, first_seen=at,
                last_seen=at, source=source, confidence=confidence,
                exclusive=identifier.mergeable,
            )
        ]
        self.name = self._pick_name()
        return True

    _READABLE_KINDS = frozenset(
        {
            IdKind.FQDN, IdKind.HOSTNAME, IdKind.UPN, IdKind.SAM, IdKind.POSIX_USER,
            IdKind.EMAIL, IdKind.DOMAIN, IdKind.SERVICE_NAME, IdKind.URL, IdKind.IP,
        }
    )

    def _pick_name(self) -> str:
        """The best display name available, chosen for stability rather than recency.

        A name that flips between ``10.0.0.5`` and ``ws01`` as evidence arrives makes
        two lines of one timeline look like two machines, so the ranking is fixed: an
        identifier of this entity's own type beats one merely bound to it, then a
        human-readable name beats an opaque id, then durability. Readability outranks
        durability on purpose — a case is easier to read as "ws01" than as a
        40-character EDR enrolment hash, even though the hash is the stronger
        identifier and remains the entity's key.
        """
        if not self.identifiers:
            return self.name
        best = max(
            self.identifiers,
            key=lambda i: (
                i.entity_type is self.entity_type,
                i.kind in self._READABLE_KINDS,
                i.spec.durability,
                i.mergeable,
                i.value,
            ),
        )
        return best.value

    def identifier(self, kind: IdKind | str) -> Identifier | None:
        k = IdKind(kind)
        for i in self.identifiers:
            if i.kind is k:
                return i
        return None

    def values(self, kind: IdKind | str | None = None) -> list[str]:
        k = None if kind is None else IdKind(kind)
        return [i.value for i in self.identifiers if k is None or i.kind is k]

    def own_identifiers(self) -> list[Identifier]:
        """The identifiers that name *this kind of thing*, not ones bound to it."""
        return [i for i in self.identifiers if i.entity_type is self.entity_type]

    def bound_at(self, at: float) -> list[Identifier]:
        """The identifiers in force at an instant — the time-correct view."""
        return [b.identifier for b in self.bindings if b.covers(at)]

    def active_at(self, at: float) -> bool:
        return bool(self.first_seen) and self.first_seen <= at <= self.last_seen

    def protect(self, reason: str) -> None:
        """Mark the entity as never-act-on, with the reason an operator will read.

        A method rather than two assignments because ``validate_assignment`` runs the
        consistency check on every field set: assigning ``protected = True`` first
        would trip the "protected with no reason" guard that exists to stop exactly
        the unexplained refusal this method is producing.
        """
        text = reason.strip()
        if not text:
            raise EntityError(f"{self.key}: a protection needs a reason")
        self.protected_reason = text
        self.protected = True

    # ── merging ────────────────────────────────────────────────────────────

    def mergeable_with(self, other: "Entity") -> tuple[bool, str]:
        """Whether these two are the same thing, and on what evidence.

        Requires a shared identifier that is mergeable *and* natively names this type
        of entity. The second condition is what stops a NAT gateway collapsing a
        network: two hosts that shared an address share an ``ip`` identifier whose
        natural type is :attr:`EntityType.IP`, so it never counts as evidence that
        the hosts are one host — no threshold to tune, no window to get wrong.
        """
        if self.entity_type is not other.entity_type:
            return False, (
                f"a {self.entity_type} and a {other.entity_type} are different kinds "
                "of thing"
            )
        if self.key == other.key:
            return False, "already the same entity"
        mine = {
            i.key: i for i in self.identifiers
            if i.mergeable and i.entity_type is self.entity_type
        }
        theirs = {
            i.key: i for i in other.identifiers
            if i.mergeable and i.entity_type is other.entity_type
        }
        shared = sorted(set(mine) & set(theirs))
        if shared:
            best = max(mine[k].spec.durability for k in shared)
            return True, (
                f"share {len(shared)} mergeable {self.entity_type} identifier(s), "
                f"strongest durability {best}: {', '.join(shared[:3])}"
            )
        common = {i.key for i in self.identifiers} & {i.key for i in other.identifiers}
        if not common:
            return False, "no identifier in common"
        by_key = {i.key: i for i in self.identifiers}
        crossed = sorted(
            k for k in common if by_key[k].entity_type is not self.entity_type
        )
        if crossed:
            return False, (
                f"the only identifiers in common name something else "
                f"({', '.join(crossed[:3])}); two {self.entity_type}s that shared an "
                f"address or a session are not one {self.entity_type}"
            )
        blocked = sorted(k for k in common if not by_key[k].mergeable)
        why = next((by_key[k].reason for k in blocked if by_key[k].reason), "")
        return False, (
            f"the identifiers in common are not mergeable ({', '.join(blocked[:3])})"
            + (f": {why}" if why else "")
        )

    def merge(self, other: "Entity", at: float | None = None) -> "Entity":
        """Fold ``other`` into this entity, or refuse and say why.

        This entity's key survives and ``other``'s is kept in :attr:`merged_from`, so
        a stored reference to the absorbed entity still resolves. Dropping it would
        leave every alert raised before the merge pointing at a key that no longer
        exists.
        """
        ok, why = self.mergeable_with(other)
        if not ok:
            raise MergeRefused(f"{self.key} != {other.key}: {why}")
        at = time.time() if at is None else at

        # Bindings are copied with their intervals intact. Re-observing the
        # identifiers instead would collapse every one of them to a single instant
        # and lose exactly the history a DHCP question needs.
        for binding in other.bindings:
            mine = next(
                (b for b in self.bindings
                 if b.identifier.key == binding.identifier.key),
                None,
            )
            updated = list(self.bindings)
            if mine is None:
                self.identifiers = self.identifiers + [binding.identifier]
                updated.append(binding.model_copy(update={"entity_key": self.key}))
            else:
                updated[updated.index(mine)] = mine.extend(
                    binding.first_seen
                ).extend(binding.last_seen)
            self.bindings = updated

        if other.first_seen:
            self.first_seen = (
                min(self.first_seen, other.first_seen)
                if self.first_seen
                else other.first_seen
            )
        self.last_seen = max(self.last_seen, other.last_seen)
        self.criticality = Criticality(max(self.criticality, other.criticality))
        self.crown_jewel = self.crown_jewel or other.crown_jewel
        if other.protected and not self.protected:
            self.protect(other.protected_reason)
        self.risk_score = max(self.risk_score, other.risk_score)
        # Summed, not maxed: the signals are different observations of one thing, and
        # the count is what `detect.min_signals_per_entity` reads. Taking the max
        # would let a host whose evidence arrived as two entities of two signals each
        # sit at two forever and never cross a threshold of three.
        self.signal_count += other.signal_count
        self.platform = self.platform or other.platform
        self.os_name = self.os_name or other.os_name
        self.owner = self.owner or other.owner
        self.business_unit = self.business_unit or other.business_unit
        self.tags = sorted(set(self.tags) | set(other.tags))
        self.sources = sorted(set(self.sources) | set(other.sources))
        self.merged_from = sorted(
            set(self.merged_from) | set(other.merged_from) | {other.key}
        )
        self.merge_notes = self.merge_notes + [
            f"{_iso(at)} absorbed {other.key} — {why}"
        ]
        self.name = self._pick_name()
        return self

    def note_not_merged(
        self, other: "Entity", why: str, at: float | None = None
    ) -> None:
        """Record a refused or deliberately-declined merge.

        A refusal that leaves no trace is indistinguishable from never having looked,
        so the next investigation re-derives it — or worse, an analyst reads two
        entities as unrelated when the platform knows they may not be.
        """
        at = time.time() if at is None else at
        self.merge_notes = self.merge_notes + [
            f"{_iso(at)} not merged with {other.key} — {why}"
        ]

    # ── output ─────────────────────────────────────────────────────────────

    def ref(self, observed_as: str = "", role: str = "") -> EntityRef:
        return EntityRef(
            key=self.key,
            entity_type=self.entity_type,
            observed_as=observed_as or self.name,
            role=role,
        )

    def doc(self) -> dict[str, Any]:
        """The document stored in VedDB under :attr:`key`."""
        return self.model_dump(mode="json")

    @classmethod
    def from_doc(cls, doc: Mapping[str, Any]) -> "Entity":
        return cls.model_validate(dict(doc))

    def describe(self) -> str:
        parts = [f"{self.entity_type}:{self.name}"]
        if self.platform:
            parts.append(f"({self.platform})")
        if self.criticality:
            parts.append(f"crit={Criticality(self.criticality).name.lower()}")
        if self.crown_jewel:
            parts.append("crown-jewel")
        if self.protected:
            parts.append(f"PROTECTED[{self.protected_reason}]")
        if self.risk_score:
            parts.append(f"risk={self.risk_score}")
        if self.signal_count:
            parts.append(f"signals={self.signal_count}")
        others = sorted(str(i) for i in self.identifiers if i.value != self.name)
        if others:
            parts.append("via " + ", ".join(others[:4]))
        return " ".join(parts)

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return self.describe()


# ── the event bridge ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Observation:
    """One identifier an event carried, and the context that gives it meaning."""

    identifier: Identifier
    facet: str
    role: str
    field: str

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.field}: {self.identifier} ({self.role})"


#: ``device_os_name`` substrings that decide the platform, checked in order against
#: the lowercased value because the field carries whatever the source calls it —
#: "Windows 11 Enterprise", "Microsoft Windows Server 2022", "Ubuntu 22.04.3 LTS",
#: "Red Hat Enterprise Linux 9.3".
_OS_PLATFORM: tuple[tuple[str, Platform], ...] = (
    ("windows", Platform.WINDOWS),
    ("win32", Platform.WINDOWS),
    ("win64", Platform.WINDOWS),
    ("macos", Platform.MACOS),
    ("mac os", Platform.MACOS),
    ("darwin", Platform.MACOS),
    ("ubuntu", Platform.LINUX),
    ("debian", Platform.LINUX),
    ("centos", Platform.LINUX),
    ("red hat", Platform.LINUX),
    ("rhel", Platform.LINUX),
    ("alpine", Platform.LINUX),
    ("amazon linux", Platform.LINUX),
    ("freebsd", Platform.LINUX),
    ("linux", Platform.LINUX),
)

#: Collector and connector names that determine the platform on their own.
_SOURCE_PLATFORM: dict[str, Platform] = {
    "windows_eventlog": Platform.WINDOWS,
    "sysmon": Platform.WINDOWS,
    "defender": Platform.WINDOWS,
    "entra": Platform.ENTRA,
    "azure_activity": Platform.ENTRA,
    "okta": Platform.OKTA,
    "m365": Platform.M365,
    "gws": Platform.GWS,
    "cloudtrail": Platform.AWS,
    "aws": Platform.AWS,
    "gcp": Platform.GCP,
    "network_flow": Platform.NETWORK,
    "dns": Platform.NETWORK,
    "local_auth": Platform.LINUX,
}


def infer_platform(event: Event) -> Platform:
    """Guess the platform from the OS field, then the source name.

    The OS field comes first because it describes the host the event is *about*,
    while the source describes what collected it — and an EDR connector reports on
    Windows, Linux and macOS alike, so preferring the source would apply the Windows
    case rule to a Linux account and merge ``Bob`` into ``bob``.

    Returns :attr:`Platform.UNKNOWN` rather than guessing, which is what makes
    :func:`fold_username`'s conservative branch reachable rather than theoretical.

    ``defender`` sits in the source table and that is a deliberate compromise, not an
    oversight: Defender for Endpoint runs on all three families, but many of its
    alert schemas carry ``DeviceName`` with no OS field, and the estate CYPHRA runs
    on is Windows. It is the weakest entry in the table, and it applies only when the
    OS field is empty.
    """
    os_name = (event.device_os_name or "").lower()
    for needle, plat in _OS_PLATFORM:
        if needle in os_name:
            return plat
    return _SOURCE_PLATFORM.get(event.soc_source or "", Platform.UNKNOWN)


def observations_from_event(
    event: Event, platform: Platform | str | None = None
) -> list[Observation]:
    """Extract every identifier an event carries, with its facet and role.

    Reads the flat fields through :data:`FIELD_TO_IDENTIFIER` rather than walking the
    observables — see that table for why the observable list is insufficient.

    ``role`` is what a kill chain needs. ``src`` and ``dst`` on one event is a
    connection; the same host as ``dst`` and then as ``src`` is a pivot, and that is
    invisible if only membership is recorded.
    """
    plat = infer_platform(event) if platform is None else Platform(platform)
    out: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for flat, fm in FIELD_TO_IDENTIFIER.items():
        raw = getattr(event, flat, None)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            continue
        kind = fm.by_platform.get(plat, fm.kind)
        scope = ""
        if fm.scope_field:
            scope = (getattr(event, fm.scope_field, None) or "").strip()
        try:
            ident = Identifier.make(kind, raw, platform=plat, scope=scope)
        except ValueError:
            # A value the event model accepted for its own field but that is not a
            # usable *identifier* — a hostname that is really a wildcard, a uid in a
            # hash field. Skipped rather than raised: one unusable field must not cost
            # the entity graph the other six on the same event.
            #
            # `ValueError`, not `EntityError`: pydantic wraps a validator-raised
            # EntityError into its own ValidationError, and catching only the narrow
            # class would let that escape and defeat the whole point of this handler.
            continue
        marker = (fm.facet, ident.key)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(
            Observation(identifier=ident, facet=fm.facet, role=fm.role, field=flat)
        )
    return out


def entities_from_event(
    event: Event, platform: Platform | str | None = None
) -> list[Entity]:
    """Build the entities an event mentions, grouped the way the event states them.

    One entity per (facet, natural type), plus the three cross-attachments in
    :data:`CROSS_ATTACH` — an address onto the host in the same facet, a session and
    a mailbox onto the account. So an event carrying ``device_uid``,
    ``device_hostname``, ``device_mac`` and ``device_ip`` produces *one* host — keyed
    on the EDR id, named by the hostname, with the MAC recorded and the address bound
    for this instant — and *one* address entity. Not four fragments for a later pass
    to guess at reassembling.

    The entities come back fresh, with no knowledge of what is already stored;
    matching them against the existing graph over DHCP, NAT and VPN churn is
    ``correlate/entity.py``. This function's contract is narrower and worth stating:
    the *structural* grouping an event already asserts is never lost on the way in.
    """
    obs = observations_from_event(event, platform)
    if not obs:
        return []
    plat = infer_platform(event) if platform is None else Platform(platform)
    at = event.time
    source = event.soc_source or ""

    groups: dict[tuple[str, EntityType], list[Observation]] = defaultdict(list)
    for o in obs:
        groups[(o.facet, o.identifier.entity_type)].append(o)

    built: dict[tuple[str, EntityType], Entity] = {}
    for group_key, members in groups.items():
        # The anchor names the entity and supplies its key: mergeable first, then most
        # durable, so a host arriving with both an EDR id and a hostname is keyed on
        # the id that survives a rename.
        anchor = max(
            members,
            key=lambda o: (
                o.identifier.mergeable,
                o.identifier.spec.durability,
                o.identifier.value,
            ),
        )
        ent = Entity.make(
            anchor.identifier,
            at=at,
            source=source,
            platform=plat if group_key[1] in (EntityType.HOST, EntityType.USER)
            else Platform.UNKNOWN,
        )
        for o in members:
            if o is not anchor:
                ent.observe(o.identifier, at=at, source=source)
        built[group_key] = ent

    # The cross-attachments, done after every entity exists so an address binds to
    # its host regardless of which field order produced them.
    for facet, etype in list(built):
        target_type = CROSS_ATTACH.get(etype)
        if target_type is None:
            continue
        target = built.get((facet, target_type))
        if target is None:
            continue
        for ident in built[(facet, etype)].own_identifiers():
            target.observe(ident, at=at, source=source)

    return list(built.values())


# ── the reportable half of two conservative choices ─────────────────────────


def case_collisions(entities: Iterable[Entity]) -> list[tuple[str, list[str]]]:
    """Entities whose identifiers differ only by case.

    This is the reportable half of :func:`fold_username`'s conservative choice. Where
    the platform was unknown the names were not folded, so one account may have
    become two nodes; every such pair surfaces here for the correlation layer to
    raise — a platform lookup or a human settles it, rather than this module guessing
    and merging two real POSIX accounts irreversibly.

    Only differing *spellings* count. Two entities holding the same value is not a
    case collision but a binding conflict, which is :meth:`Binding.conflicts_with`.

    Kinds whose :class:`IdentifierSpec` settles the case rule are skipped, because
    there is nothing for anyone to settle. ``posix_user`` is the one that matters: on
    a POSIX host ``Bob`` and ``bob`` genuinely *are* two accounts, so reporting them
    would not be a finding, it would be an invitation to make the one merge this
    module refuses to make. ``sam`` and ``upn`` are skipped from the other side —
    always folded, so they cannot collide — and ``iam_arn`` / ``resource_id`` / ``url``
    because case carries meaning in a path or an ARN.

    Returns ``(kind:folded_value, [entity keys])``, so the output is directly a work
    list.
    """
    buckets: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for ent in entities:
        for ident in ent.identifiers:
            s = SPECS.get(ident.kind)
            if s is not None and (s.case_sensitive or s.case_insensitive):
                continue
            buckets[f"{ident.kind}:{ident.folded()}"][ident.value].add(ent.key)
    out = []
    for folded, by_value in buckets.items():
        if len(by_value) < 2:
            continue
        keys = sorted({k for keys in by_value.values() for k in keys})
        if len(keys) > 1:
            out.append((folded, keys))
    return sorted(out)


def scope_collisions(entities: Iterable[Entity]) -> list[tuple[str, list[str]]]:
    """One identifier value carrying two different namespaces.

    The reportable half of the decision not to put :attr:`Identifier.scope` in the
    key. ``ws01`` in ``corp.example.com`` and ``ws01`` in an acquired company's
    forest are two machines, and because scope stays out of the key they are one
    entity here. That trade buys consolidation in the overwhelmingly common
    single-domain case; this function is what stops it being silent in the other one.

    Returns ``(kind:value, [namespaces])``.
    """
    seen: dict[str, set[str]] = defaultdict(set)
    for ent in entities:
        for ident in ent.identifiers:
            if ident.scope:
                seen[f"{ident.kind}:{ident.value}"].add(ident.scope)
    return sorted((k, sorted(v)) for k, v in seen.items() if len(v) > 1)


def _iso(ts: float) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CLI ─────────────────────────────────────────────────────────────────────


def _cli(argv: Sequence[str]) -> int:
    """kinds | fields | normalise <kind> <value> [platform] [scope] | scope <ip>"""
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_cli.__doc__)
        return 0
    cmd, rest = argv[0], list(argv[1:])

    if cmd == "kinds":
        print(f"{'kind':<14} {'entity':<15} {'d':<2} {'merge':<6} {'spoof':<6} "
              f"{'scope':<6} {'case':<9} note")
        for s in sorted(SPECS.values(), key=lambda x: (-x.durability, x.kind)):
            scope = "STRICT" if s.strict_scope else ("yes" if s.scoped else "-")
            case = ("sensitive" if s.case_sensitive
                    else "fold" if s.case_insensitive else "-")
            print(
                f"{s.kind:<14} {s.entity_type:<15} {s.durability:<2} "
                f"{'yes' if s.mergeable else 'NO':<6} "
                f"{'yes' if s.spoofable else '-':<6} {scope:<6} {case:<9} "
                f"{s.note[:44]}"
            )
        no_note = [str(s.kind) for s in SPECS.values() if not s.note]
        print(
            f"\n{len(SPECS)} kinds over {len(EntityType)} entity types; merge floor "
            f"{MIN_MERGE_DURABILITY}; {len(PRIMARY_TYPES)} types carry merge "
            f"pressure; {len(STRICT_SCOPE_KINDS)} kinds refuse an unqualified merge"
        )
        if no_note:
            print(f"WARNING: no rationale recorded for {', '.join(no_note)}")
            return 1
        return 0

    if cmd == "fields":
        real = set(Event.model_fields)
        bad = []
        for flat, fm in sorted(FIELD_TO_IDENTIFIER.items()):
            problems = []
            if flat not in real:
                problems.append("not an Event field")
            if fm.scope_field and fm.scope_field not in real:
                problems.append(f"scope field {fm.scope_field} missing")
            path = OCSF_PATH.get(flat, "")
            if problems:
                bad.append((flat, problems))
            print(
                f"  {'BAD ' if problems else 'ok  '} {flat:<26} → {fm.kind:<13} "
                f"{fm.facet:<15} {fm.role:<10} "
                f"{'obs ' if path in OBSERVABLE_TO_IDENTIFIER else '    '}{path}"
                + (f"   {'; '.join(problems)}" if problems else "")
            )
        print(
            f"\n{len(FIELD_TO_IDENTIFIER)} fields mapped, "
            f"{len(OBSERVABLE_TO_IDENTIFIER)} resolving to OCSF paths, "
            f"{len(bad)} broken"
        )
        return 1 if bad else 0

    if cmd == "normalise" and len(rest) >= 2:
        plat = Platform(rest[2]) if len(rest) > 2 else Platform.UNKNOWN
        scope = rest[3] if len(rest) > 3 else ""
        ident = Identifier.make(rest[0], rest[1], platform=plat, scope=scope)
        print(json.dumps(ident.model_dump(mode="json"), indent=2))
        print(f"key:  {ident.key}")
        print(f"type: {ident.entity_type} (durability {ident.spec.durability})")
        return 0

    if cmd == "scope" and rest:
        sc = address_scope(rest[0])
        print(f"{rest[0]} → {sc}")
        print(f"usable as an entity: {sc not in UNROUTABLE_SCOPES}")
        print(f"protected: {cidr_reason(rest[0]) or 'no'}")
        return 0

    print(_cli.__doc__)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_cli(sys.argv[1:]))

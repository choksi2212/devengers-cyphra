"""Azure Activity Log — the subscription control plane (6003 API Activity).

Every ARM write in a subscription lands here: role assignments, NSG rule changes,
``runCommand`` on a VM, a diagnostic setting being deleted. It is the single most
important cloud log for detecting an attacker who has reached the Azure control plane,
and it is also the one with the most ways to read it wrongly. The five that matter are
below, because each one produces a *plausible* result rather than an error.

── ``$filter`` timestamps are single-quoted here and unquoted in Graph ──────
The same vendor, near-identical OData syntax, opposite rule. Microsoft Graph rejects
``createdDateTime ge '2026-03-11T00:00:00Z'`` and requires the bare literal; this
endpoint requires exactly the quoted form, verbatim from its own reference:
``$filter=eventTimestamp ge '2015-01-21T20:00:00Z' and eventTimestamp le
'2015-01-23T20:00:00Z'``. Unquoted here is an HTTP 400. :meth:`fetch_window` quotes.

The legal grammar is also narrower than it looks. Only ``eventTimestamp`` bounds, alone
or with **exactly one** of ``resourceGroupName``, ``resourceUri``, ``resourceProvider``
or ``correlationId``; the reference's own words are "**NOTE**: No other syntax is
allowed." There is no server-side filter on ``level``, ``status``, ``caller`` or
``category``, so this connector reads everything and decides locally. There is also no
``$top`` — the page size is the server's choice, which is why :attr:`ConnectorSpec.
page_size` here describes observed behaviour rather than a request parameter.

── ``$select`` cannot be used, and the reason is a silent one ───────────────
``$select``'s legal value list is ``authorization, claims, correlationId, description,
eventDataId, eventName, eventTimestamp, httpRequest, level, operationId, operationName,
properties, resourceGroupName, resourceProviderName, resourceId, status,
submissionTimestamp, subStatus, subscriptionId``. It does **not** include ``category``,
``resourceType`` or ``tenantId``. ``category`` is the field this connector routes on, so
adding ``$select`` as an apparent bandwidth optimisation deletes the routing input from
every record — and the symptom reads as a vendor bug, not a query mistake. Not used.

── Every write is logged twice, and one of them has not happened yet ───────
An ARM operation emits ``eventName: BeginRequest`` with ``status: Started`` and then a
second record, ``EndRequest`` with ``Succeeded`` or ``Failed``. They share
``operationId`` and have *different* ``eventDataId``s, so exact dedup keeps both. Two
consequences a naive mapper gets wrong:

* "count the VM deletions" double-counts every one of them.
* "alert on operations where status is not Succeeded" fires on every single write in the
  tenant, because ``Started`` is not ``Succeeded``.

Both records are emitted here — dropping ``Started`` would make an operation that began
and never finished invisible, and a killed or timed-out destructive operation looks
exactly like that. They are separated instead: ``azure:non-terminal`` and
``azure:terminal`` labels so both hunts are a positive filter, and ``unmapped.
operation_id`` is the join. ``status_id`` for a non-terminal record is
:attr:`Status.OTHER` and not ``UNKNOWN``: OCSF 6003's table is ``{0 Unknown, 1 Success,
2 Failure, 99 Other}`` with no in-progress member, ``Unknown`` means "nobody assessed
this" — false for a record Azure explicitly marked ``Started`` — and ``Other``'s own
definition is "not mapped, see the source-specific value", which is precisely the case.

── ``level`` is not severity, and ``localizedValue`` is not a value ─────────
``level`` is an operational ``EventLevel`` — Critical/Error/Warning/Informational/
Verbose — describing whether the *operation* went well. An ``Error`` on a failed VM
deploy is a capacity problem, not a security event, and a successful ``Informational``
Owner grant to an external account is the actual incident. So ``severity_id`` stays
Informational for every record and ``level`` goes to ``unmapped``: this is an audit log
with no opinion, and only a source that is itself an alerting product gets to set
severity from its own field. ``category=Security`` records are Defender for Cloud
pointers, and the authoritative feed for those is the Defender connector.

``eventName``, ``operationName``, ``category``, ``resourceType``, ``status``,
``subStatus`` and ``resourceProviderName`` are all ``LocalizableString`` —
``{localizedValue, value}`` — and ``localizedValue`` is translated to the tenant's
language. A mapper reading it works perfectly in an English tenant and matches nothing
in a German one. :func:`_local` reads ``value``.

── What is not in here at all ──────────────────────────────────────────────
Data-plane access. Reading a Key Vault secret, reading a blob, invoking a Function —
none of it appears in the Activity Log, because the Activity Log is ARM's log and those
calls do not go through ARM. ``Microsoft.KeyVault/vaults/write`` (the access policy
changed) is here; ``secrets/get`` is not, and needs the vault's own diagnostic setting.
The connector says so in :meth:`probe` rather than leaving an operator to conclude from
an empty result that nobody read the secret.

Retention is 90 days, so an outage longer than that is a permanent gap and not a
delayed read — :meth:`_retention_floor` clamps and says so on the events it does return.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, Severity, Status
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, OAuth2ClientCredentials, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    dig,
    first,
    iso8601,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import AuthError, HttpError, HttpResponse, Request
from ingest.connectors.mapping import (
    API_OTHER,
    MESSAGE_LIMIT,
    TEXT_LIMIT,
    attack,
    clip,
    crud_activity,
    label,
    note,
    put,
    resource_ref,
    stash,
)

#: ARM's token audience. Not Graph's — a token minted for
#: ``https://graph.microsoft.com/.default`` is structurally valid and returns 401
#: ``InvalidAuthenticationToken`` here, which reads as a bad secret rather than a wrong
#: audience. This is why the connector has its own credential quartet.
ARM_SCOPE_SUFFIX = "/.default"

#: The only api-version this endpoint has ever had. Frozen since 2015 and unlikely to
#: move; kept as a constant so the readiness report can print it.
ACTIVITY_API_VERSION = "2015-04-01"

#: Subscription-scoped. There is no "all subscriptions in the tenant" form of this
#: endpoint — the tenant-level variant returns only tenant-level events — which is why
#: :meth:`AzureActivityConnector.subscriptions` accepts a list and iterates.
ACTIVITY_PATH = (
    "/subscriptions/{subscription}"
    "/providers/Microsoft.Insights/eventtypes/management/values"
)

#: Activity Log retention, and the margin held back from it. Identical in shape to
#: CloudTrail's Event history: history older than this does not exist to be read, so a
#: window reaching past it is a permanent gap rather than a slow read.
EVENT_HISTORY_SECONDS = 90 * 86_400.0
RETENTION_MARGIN_SECONDS = 12 * 3_600.0

# ── claim URIs ──────────────────────────────────────────────────────────────
# `claims` is a flat dict mixing short JWT claim names with full URI-shaped ones from
# the WS-* era. Both spellings appear in the same record, so every read tries both.
_CLAIM_UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
_CLAIM_OID = "http://schemas.microsoft.com/identity/claims/objectidentifier"
_CLAIM_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
_CLAIM_NAMEID = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
_CLAIM_TENANT = "http://schemas.microsoft.com/identity/claims/tenantid"
_CLAIM_SCOPE = "http://schemas.microsoft.com/identity/claims/scope"
_CLAIM_AMR = "http://schemas.microsoft.com/claims/authnmethodsreferences"

#: ``appidacr`` — how the calling application proved it was itself. Worth decoding
#: because the *change* is the signal: a service principal that has always presented a
#: certificate suddenly presenting a client secret is a stolen-secret shape, and the
#: raw digit makes that query unwriteable by anyone who has not memorised the table.
_APPIDACR: Mapping[str, str] = {
    "0": "public client — no credential presented",
    "1": "client secret",
    "2": "certificate",
}

#: The Entra role *template* id for Global Administrator. It appears in the ``wids``
#: claim of an ARM token when the caller holds the role, which is the only way this log
#: reveals that a subscription change was made by a tenant-wide administrator.
_GLOBAL_ADMIN_ROLE_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"

#: Well-known Azure built-in role definition GUIDs. Deliberately partial: the table
#: exists so that "who was granted Owner" is a writeable query, and an unlisted GUID
#: keeps its GUID in ``unmapped.granted_role_definition_id`` and stays queryable, so
#: incompleteness costs resolution and never correctness. Extend by appending.
_BUILTIN_ROLES: Mapping[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": "Key Vault Secrets Officer",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "81a9662b-bebf-436f-a333-f67b29880f12": "Storage Account Key Operator Service Role",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "1c0163c0-47e6-4577-8991-ea5c82e286e4": "Virtual Machine Administrator Login",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Admin",
    "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8": "Azure Kubernetes Service Cluster Admin Role",
}

#: Roles whose grant is a change of *control* over the subscription rather than a change
#: of access within it. Owner and RBAC Administrator can grant themselves anything else;
#: Key Vault Administrator can read every secret in the vault; the Storage key operator
#: can mint an account key that bypasses RBAC entirely; the AKS cluster-admin role is
#: root on every node. A grant of one of these is the escalation, not a step toward it.
_TIER0_ROLE_IDS = frozenset(
    {
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # RBAC Administrator
        "00482a5a-887f-4fb3-b363-3b7fe8e74483",  # Key Vault Administrator
        "81a9662b-bebf-436f-a333-f67b29880f12",  # Storage Account Key Operator
        "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8",  # AKS Cluster Admin
    }
)

#: ``status`` values that mean the operation has not finished. ``Started`` is the ARM
#: lifecycle one; ``Accepted`` is the long-running-operation one; the rest are seen on
#: health and policy categories.
_NON_TERMINAL_STATUSES = frozenset(
    {"started", "starting", "accepted", "in progress", "inprogress", "resolving", "pending"}
)
_SUCCESS_STATUSES = frozenset({"succeeded", "success", "completed", "resolved"})
_FAILURE_STATUSES = frozenset({"failed", "failure", "canceled", "cancelled"})

#: Categories the platform writes with no ``caller`` at all. Documented rather than
#: inferred, because "no caller" for one of these is correct and expected, while "no
#: caller" on an Administrative record is a data-quality gap in the vendor's own log —
#: two different notes, and conflating them hides the second.
_PLATFORM_CATEGORIES = frozenset(
    {"servicehealth", "resourcehealth", "autoscale", "recommendation", "alert", "policy"}
)

#: ARM operation (lower-cased) -> the ATT&CK technique the operation *is*.
#:
#: Every id was validated against ``vendor/attack/attack_index.json`` before being put
#: here. That check proves the id exists; it does not prove the id is relevant, which is
#: a separate judgement made per row — two ids that resolved cleanly (``T1546.014``
#: Emond, ``T1599`` Network Boundary Bridging) were dropped for being macOS and network-
#: appliance techniques with no Azure control-plane meaning.
#:
#: ``Microsoft.Resources/deployments/write`` deliberately has no entry: an ARM template
#: deployment can create anything at all, so any single technique asserted about it would
#: be wrong most of the time. The resources it touched are in ``resources`` and the
#: detect layer reads those.
_OPERATION_TECHNIQUES: Mapping[str, str] = {
    # ── identity and authorisation ──
    "microsoft.authorization/roleassignments/write": "T1098.003",
    "microsoft.authorization/roleassignments/delete": "T1098.003",
    "microsoft.authorization/roledefinitions/write": "T1098.003",
    "microsoft.authorization/roledefinitions/delete": "T1098.003",
    "microsoft.managedidentity/userassignedidentities/write": "T1136.003",
    "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write": "T1098.001",
    "microsoft.sql/servers/administrators/write": "T1098",
    "microsoft.keyvault/vaults/write": "T1098",
    "microsoft.keyvault/vaults/accesspolicies/write": "T1098",
    # ── execution on a host, through the control plane ──
    "microsoft.compute/virtualmachines/runcommand/action": "T1651",
    "microsoft.compute/virtualmachines/extensions/write": "T1651",
    "microsoft.compute/virtualmachinescalesets/virtualmachines/runcommand/action": "T1651",
    "microsoft.compute/virtualmachinescalesets/extensions/write": "T1651",
    "microsoft.hybridcompute/machines/extensions/write": "T1651",
    "microsoft.automation/automationaccounts/runbooks/write": "T1651",
    "microsoft.automation/automationaccounts/jobs/write": "T1651",
    "microsoft.containerservice/managedclusters/runcommand/action": "T1609",
    "microsoft.web/sites/publish/action": "T1648",
    "microsoft.web/sites/write": "T1648",
    "microsoft.web/sites/functions/write": "T1648",
    "microsoft.logic/workflows/write": "T1648",
    # ── instance and image manipulation ──
    "microsoft.compute/snapshots/write": "T1578.001",
    "microsoft.compute/virtualmachines/write": "T1578.002",
    "microsoft.compute/virtualmachines/delete": "T1578.003",
    "microsoft.compute/images/write": "T1578.001",
    # ── moving data out ──
    "microsoft.datafactory/factories/pipelines/write": "T1537",
    "microsoft.storage/storageaccounts/write": "T1530",
    "microsoft.storage/storageaccounts/blobservices/containers/write": "T1530",
    # ── weakening the perimeter ──
    "microsoft.network/networksecuritygroups/securityrules/write": "T1562.007",
    "microsoft.network/networksecuritygroups/securityrules/delete": "T1562.007",
    "microsoft.network/networksecuritygroups/delete": "T1562.007",
    "microsoft.network/azurefirewalls/write": "T1562.007",
    "microsoft.network/firewallpolicies/rulecollectiongroups/write": "T1562.007",
    # ── blinding the defenders ──
    "microsoft.insights/alertrules/delete": "T1562.008",
    "microsoft.insights/metricalerts/delete": "T1562.008",
    "microsoft.insights/scheduledqueryrules/delete": "T1562.008",
    "microsoft.insights/actiongroups/delete": "T1562.008",
    "microsoft.operationalinsights/workspaces/delete": "T1562.008",
    "microsoft.operationalinsights/workspaces/datasources/delete": "T1562.008",
    "microsoft.security/pricings/write": "T1562.001",
    "microsoft.security/policies/write": "T1562.001",
    "microsoft.security/autoprovisioningsettings/write": "T1562.001",
    "microsoft.security/advancedthreatprotectionsettings/write": "T1562.001",
    "microsoft.authorization/policyassignments/delete": "T1562",
    "microsoft.authorization/policydefinitions/delete": "T1562",
    "microsoft.authorization/locks/delete": "T1562",
    # ── destruction ──
    "microsoft.resources/subscriptions/resourcegroups/delete": "T1485",
    "microsoft.sql/servers/databases/delete": "T1485",
    "microsoft.keyvault/vaults/delete": "T1485",
    "microsoft.storage/storageaccounts/delete": "T1485",
    "microsoft.recoveryservices/vaults/delete": "T1490",
    "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems/delete": "T1490",
    "microsoft.compute/restorepointcollections/delete": "T1490",
}

#: Operation *suffixes*, checked after the exact table misses. These generalise across
#: resource providers, which the exact table cannot: ``listKeys/action`` is the same
#: credential read whether the provider is Storage, Event Hubs, Service Bus, Cognitive
#: Services or a dozen others, and enumerating every one would guarantee the table is
#: stale within a release. Exact entries win, which is how AKS ``runCommand`` reaches
#: T1609 while every other ``runCommand`` reaches T1651.
_SUFFIX_TECHNIQUES: Mapping[str, str] = {
    "/listkeys/action": "T1552",
    "/listcredentials/action": "T1552",
    "/listadminkeys/action": "T1552",
    "/listquerykeys/action": "T1552",
    "/listconnectionstrings/action": "T1552",
    "/listclusteradmincredential/action": "T1552",
    "/listclusterusercredential/action": "T1552",
    "/sharedkeys/action": "T1552",
    "/config/list/action": "T1552",
    "/listsecrets/action": "T1552",
    "/listaccountsas/action": "T1098.001",
    "/listservicesas/action": "T1098.001",
    "/listsas/action": "T1098.001",
    "/regeneratekey/action": "T1098.001",
    "/firewallrules/write": "T1562.007",
    "/firewallrules/delete": "T1562.007",
    "/diagnosticsettings/write": "T1562.008",
    "/diagnosticsettings/delete": "T1562.008",
    "/begingetaccess/action": "T1537",
    "/runcommand/action": "T1651",
}

#: Validated, Azure-relevant, and deliberately **not** emitted by this connector, with
#: the reason. Kept as data because Phase 2's coverage matrix has to distinguish "this
#: source does not cover the technique" from "nobody thought about it" — and the second
#: is the only one that is a gap.
_TECHNIQUES_DELIBERATELY_NOT_EMITTED: Mapping[str, str] = {
    "T1046": "network service discovery is a rate signal over many reads, not a property of one record",
    "T1069.003": "cloud group discovery — same; a single group read is ordinary",
    "T1087.004": "cloud account discovery — same",
    "T1201": "password policy discovery lives in the directory, not in ARM",
    "T1518.001": "security software discovery — a single Microsoft.Security read is ordinary",
    "T1526": "cloud service discovery is a rate signal; the detect layer owns the threshold",
    "T1580": "cloud infrastructure discovery — same; tagging every read would bury it",
    "T1078.004": "valid cloud accounts is an authentication finding; the Entra connector owns sign-ins",
    "T1110": "brute force is an authentication signal and never reaches ARM",
    "T1484.002": "trust modification is a directory change; the Entra connector sees it",
    "T1556.007": "hybrid identity modification happens in Entra Connect, not through ARM",
    "T1528": "stealing an application token happens at the token endpoint, not in ARM",
    "T1552.001": "credentials in files is host telemetry",
    "T1213.003": "code repositories are outside ARM's control plane",
}

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
#: Pulled out of ``properties.requestbody`` — see :meth:`AzureActivityConnector.
#: _role_grant` for why a regex is the right tool for that particular string.
_ROLE_DEF_RE = re.compile(r"roleDefinitions/([0-9a-fA-F-]{36})")
_PRINCIPAL_ID_RE = re.compile(r'"[Pp]rincipal[Ii]d"\s*:\s*"([^"]+)"')
_PRINCIPAL_TYPE_RE = re.compile(r'"[Pp]rincipal[Tt]ype"\s*:\s*"([^"]+)"')


def _local(value: Any) -> str:
    """The invariant string out of a ``LocalizableString``.

    ``{"localizedValue": "Eine Rolle zuweisen", "value": "Microsoft.Authorization/
    roleAssignments/write"}`` — seven fields on this record are shaped like that, and
    ``localizedValue`` is rendered in the tenant's display language. Reading it produces
    a connector that matches every operation correctly in an English tenant and nothing
    at all in a German one, with no error anywhere.

    ``localizedValue`` is still used as a fallback: a record with only the localised form
    is worse than the invariant one but much better than an empty string.
    """
    if isinstance(value, Mapping):
        for key in ("value", "localizedValue"):
            text = value.get(key)
            if text not in (None, ""):
                return str(text).strip()
        return ""
    if value in (None, ""):
        return ""
    return str(value).strip()


def _decode(value: Any) -> Any:
    """A JSON document that arrived as a string, decoded — or ``None``.

    Azure nests JSON inside JSON in at least four places on this record:
    ``properties.requestbody``, ``properties.statusMessage``, ``properties.policies``
    and ``properties.impactedServices``. Read as text they are opaque; the failure
    reason for every failed operation in the subscription is inside ``statusMessage``,
    and the granted role for every role assignment is inside ``requestbody``.

    Already-parsed values pass through, because a handful of providers send the same
    field as a real object.
    """
    if isinstance(value, (Mapping, list)):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _is_guid(value: Any) -> bool:
    return bool(value) and bool(_GUID_RE.match(str(value).strip()))


def _looks_like_email(value: Any) -> bool:
    """Conservative enough that an SPN claim never lands in an email field.

    ``caller`` is documented as "the email address of the user ... the UPN claim or SPN
    claim based on availability" — three different things in one field. The Event model
    does not reject a malformed address, which is exactly why this check exists: an
    unvalidated assignment would put an object GUID in ``actor_user_email`` and every
    downstream join on identity would silently match nothing.
    """
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    _, _, domain = text.rpartition("@")
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _leaf(resource_id: Any) -> str:
    """The resource's own name out of an ARM resource id."""
    text = str(resource_id or "").strip().rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


class AzureActivityConnector(Connector):
    """Azure Activity Log for one or more subscriptions, as 6003 API Activity.

    ── Why every category lands on 6003 ──────────────────────────────────────
    ``Administrative``, ``Policy`` and ``Security`` are control-plane CRUD and belong
    there without argument. ``ServiceHealth``, ``ResourceHealth``, ``Autoscale``,
    ``Recommendation`` and ``Alert`` are platform notifications with no actor and no CRUD
    verb, and OCSF v1.9.0 declares no cloud-platform-notification class — so 6003 is the
    least-wrong home rather than the right one, and each of those records says so in a
    label and a note.

    They are collected rather than dropped for one specific reason: when a detection
    stops firing, "Azure had a regional outage" and "an attacker deleted the diagnostic
    setting" look identical from the detection's side, and only ServiceHealth separates
    them. A SOC that cannot tell an outage from tampering treats every outage as an
    incident and, worse, every tampering as an outage.

    ── The actorless-record problem, and the house answer ────────────────────
    6003 *requires* an ``actor``, and a ServiceHealth record has no caller at all — so
    the choice is to fill it with the platform or to emit an event that fails its own
    class contract. The platform is filled, under a ``substitute_for:actor`` label and a
    note, because an unfilled required object is not a more honest answer: it is the same
    claim with the evidence removed. Same reasoning as the app-only sign-in in the Entra
    connector and the service-principal caller in CloudTrail.

    ── One connector, many subscriptions, one rate limiter ───────────────────
    The endpoint is subscription-scoped and there is no all-subscriptions form, so
    ``$AZURE_SUBSCRIPTION_ID`` accepts a comma-separated list and each cycle walks it.
    The consequence is worth stating rather than discovering: all subscriptions share
    this connector's single limiter, so the effective per-subscription rate is
    ``rate_per_second / len(subscriptions)``. A tenant with twenty subscriptions should
    declare several instances of this connector rather than one long list.

    A 403 on one subscription is counted and skipped so the others still collect — the
    common real cause is a Reader assignment that was never made on a newly created
    subscription, and letting that kill the whole connector loses nineteen good sources
    to fix one. A 401 is re-raised, because that is the token and no subscription will
    work.
    """

    name = "azure_activity"
    detects = (
        "control-plane attacks on Azure: role grants, NSG rule changes, runCommand "
        "execution on VMs, diagnostic-setting deletion, storage key reads, backup "
        "destruction"
    )
    spec = ConnectorSpec(
        # Not requestable — this endpoint has no `$top`, so this is the server's
        # observed page size rather than a parameter. It feeds `paginate`'s truncation
        # heuristic, whose worst case here is a rare unnecessary window narrowing.
        page_size=200,
        # ARM allows roughly 12,000 reads per hour per subscription and this endpoint is
        # tighter than the average read. 2/s leaves headroom for everything else in the
        # subscription that also spends that budget — Terraform, the portal, other tools.
        rate_per_second=2.0,
        burst=4,
        initial_lookback_seconds=86_400.0,
        # Records land within a minute for most providers and later for a few. Holding
        # the window back 5 minutes and re-reading 15 makes a straggler free rather than
        # lost; `metadata_uid` is `eventDataId`, so the re-read costs nothing but a page.
        indexing_lag_seconds=300.0,
        overlap_seconds=900.0,
        docs_url="https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list",
        required_grants=(
            "the Monitoring Reader role (or Reader) on every subscription listed in "
            "$AZURE_SUBSCRIPTION_ID — the specific action is "
            "Microsoft.Insights/eventtypes/values/read",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retention_clamps = 0
        self.windows_skipped = 0
        self.forbidden_subscriptions = 0
        self.subscription_errors = 0
        self.platform_records = 0
        self.non_terminal_records = 0
        self.actor_substitutions = 0
        self.tier0_grants = 0

    # ── credentials ────────────────────────────────────────────────────────

    def subscription(self) -> Credential:
        return self.config.connectors.azure_subscription_id

    def tenant(self) -> Credential:
        return self.config.connectors.azure_tenant_id

    def client_id(self) -> Credential:
        return self.config.connectors.azure_client_id

    def client_secret(self) -> Credential:
        return self.config.connectors.azure_client_secret

    def credentials(self) -> tuple[Credential, ...]:
        return (
            self.subscription(),
            self.tenant(),
            self.client_id(),
            self.client_secret(),
        )

    def subscriptions(self) -> tuple[str, ...]:
        """The subscription ids to poll, in declaration order, de-duplicated.

        Comma- or semicolon-separated, because operators paste both. Order is preserved
        so the readiness report and the collection order match what was configured —
        a sorted list makes "the third subscription is the one 403ing" unreadable.
        """
        cred = self.subscription()
        if not cred.configured:
            return ()
        out: list[str] = []
        for part in str(cred.value).replace(";", ",").split(","):
            item = part.strip()
            if item and item not in out:
                out.append(item)
        return tuple(out)

    def authorizer(self) -> Authorizer:
        """Client credentials against ARM's audience, not Graph's.

        ``.secret`` rather than ``.value``: an ``Authorizer`` is built by ``client()``
        and described by the readiness report, both of which run on deployments where
        nothing is configured, and ``.value`` raises there by design.
        """
        tenant = self.tenant().secret or "TENANT-NOT-CONFIGURED"
        login = self.config.endpoints.microsoft_login.rstrip("/")
        return OAuth2ClientCredentials(
            self.client(),
            token_url=f"{login}/{tenant}/oauth2/v2.0/token",
            client_id=self.client_id(),
            client_secret=self.client_secret(),
            scope=self.config.endpoints.azure_management.rstrip("/") + ARM_SCOPE_SUFFIX,
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def base_url(self) -> str:
        return self.config.endpoints.azure_management.rstrip("/")

    def probe(self) -> Availability:
        """Credential state, plus the four limits that decide whether this is enough.

        The base implementation names missing slots and the required grant. What it
        cannot know is that this source is scoped to a list of subscriptions, that it
        stops at 90 days, that ``level`` is not severity, and that the data plane is
        absent entirely — and each of those four, unstated, is an operator concluding
        something false from a correct empty result.
        """
        base = super().probe()
        if not base.available:
            return base
        subs = self.subscriptions()
        scope = (
            f"{len(subs)} subscription(s): " + ", ".join(subs)
            if subs
            else "(no subscription parsed from $AZURE_SUBSCRIPTION_ID)"
        )
        per_sub = self.spec.rate_per_second / max(len(subs), 1)
        limits = (
            f"SCOPE: {scope}. The endpoint is subscription-scoped and has no "
            f"all-subscriptions form, so every id is polled separately and all of them "
            f"share one limiter -> {per_sub:g} req/s each. RETENTION: 90 days; an "
            f"outage longer than that is a permanent gap, not a delayed read. "
            f"SEVERITY: every record is emitted Informational. Azure's `level` "
            f"(Critical/Error/Warning/Informational/Verbose) describes whether the "
            f"operation succeeded, not whether it matters — a successful Owner grant is "
            f"Informational and a failed VM deploy is Error — so it is kept in "
            f"unmapped.level and the detect layer decides. DATA PLANE: absent. Reading "
            f"a Key Vault secret, reading a blob and invoking a Function do not pass "
            f"through ARM and are not in this log at any verbosity; they need the "
            f"resource's own diagnostic setting. category=Security records are Defender "
            f"for Cloud pointers — the Defender connector is the authoritative feed."
        )
        note_text = base.limitation
        return available(
            limitation=f"{note_text} {limits}".strip() if note_text else limits
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    def _retention_floor(self, window: TimeWindow) -> tuple[float, float]:
        """``(start to query, seconds of history lost to the 90-day horizon)``."""
        floor = self.clock() - (EVENT_HISTORY_SECONDS - RETENTION_MARGIN_SECONDS)
        if window.start >= floor:
            return window.start, 0.0
        return floor, floor - window.start

    def _next_link(self, _resp: HttpResponse, body: Any) -> str | None:
        """``nextLink``, top level — **not** ``@odata.nextLink``.

        Graph puts its cursor in ``@odata.nextLink``; this endpoint, on the same cloud
        and the same OData dialect, puts it in a plain ``nextLink``. Reading Graph's
        spelling here finds nothing, and "no next page" is the dangerous answer for a
        pagination link: the connector reports a clean cycle having read one page of a
        busy subscription and the operator has no symptom to investigate.

        The link carries a ``$skiptoken`` and is followed verbatim with no params —
        ``paginate`` does that — because re-applying ``api-version`` and ``$filter`` to
        a URL that already has them is a 400 about duplicate query options.
        """
        if not isinstance(body, Mapping):
            return None
        link = body.get("nextLink")
        return str(link) if link else None

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, lost = self._retention_floor(window)
        if window.end <= start:
            # The *whole* window predates the horizon, which is the normal shape of a
            # restart after a long outage: the planner caps a window at
            # `max_window_seconds`, so a 110-day-old checkpoint plans [cursor,
            # cursor+3600] — entirely unretrievable — and would do so ~2,600 times
            # before reaching live data. Worse, `ge` above the floor with `le` at the
            # old end is an *inverted* range, and this endpoint answers an inverted
            # range with an empty 200: thousands of successful requests that look like
            # a quiet tenant. So no request is made, and the cursor is jumped to the
            # floor in one cycle. `note_record_time` is the cursor high-water hook and
            # nothing here is a record, but the floor is genuinely the oldest instant
            # that can still be read, which is exactly where the cursor belongs.
            self.retention_clamps += 1
            self.windows_skipped += 1
            self.note_record_time(start)
            self.stats.last_error = (
                f"{self.name}: the whole requested window ended "
                f"{(start - window.end) / 86_400:.1f} days before the 90-day Activity "
                f"Log horizon, so none of it can be read and no request was sent; the "
                f"cursor jumped to the horizon. That history was never collected and "
                f"is a permanent gap, not a delayed read"
            )
            return []
        # Single-quoted, and that is not a style choice — see the module docstring.
        # `le` rather than `lt` because the documented grammar shows only `ge`/`le`;
        # the one-second boundary overlap it creates is dropped by exact dedup on
        # `metadata_uid`, and `overlap_seconds` re-reads far more than that anyway.
        time_filter = (
            f"eventTimestamp ge '{iso8601(start)}' and "
            f"eventTimestamp le '{iso8601(window.end)}'"
        )
        payloads: list[dict[str, Any]] = []
        for subscription in self.subscriptions():
            request = Request(
                "GET",
                self.base_url() + ACTIVITY_PATH.replace("{subscription}", subscription),
                label=f"{self.name}.list",
                params={
                    "api-version": ACTIVITY_API_VERSION,
                    "$filter": time_filter,
                },
                headers={"Accept": "application/json"},
            )
            try:
                async for page in self.paginate(
                    request, records_at=("value",), next_url=self._next_link
                ):
                    for record in page:
                        self.note_record_time(
                            parse_iso8601(record.get("eventTimestamp"))
                        )
                        mapped = self.map_record(record, subscription)
                        if mapped is not None:
                            payloads.append(mapped)
            except AuthError as exc:
                if exc.status != 403:
                    # 401 is the token, not the subscription. Every other subscription
                    # would fail the same way, so failing loudly once is the honest
                    # report; swallowing it would show 20 skipped subscriptions and
                    # hide the one cause.
                    raise
                self.forbidden_subscriptions += 1
                self.stats.last_error = (
                    f"{self.name}: 403 on subscription {subscription} — the app "
                    f"registration has no Monitoring Reader assignment there, so that "
                    f"subscription's control plane is invisible while the others "
                    f"continue to collect"
                )
                continue
            except HttpError as exc:
                self.subscription_errors += 1
                self.stats.last_error = (
                    f"{self.name}: subscription {subscription} failed with HTTP "
                    f"{exc.status or '?'} ({clip(exc.body, 200)}); the remaining "
                    f"subscriptions in this cycle were still read and this one is "
                    f"re-read next cycle"
                )
                continue
        if lost > 0:
            self.retention_clamps += 1
            message = (
                f"{self.name}: the requested window began {lost / 86_400:.1f} days "
                f"before the 90-day Activity Log horizon, so that much history does "
                f"not exist in this API and was never collected — it is a permanent "
                f"gap, not a delayed read"
            )
            self.stats.last_error = message
            if payloads:
                payloads[0].setdefault("notes", []).append(message)
        return payloads

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        subs = self.subscriptions()
        if subs:
            out["subscriptions"] = len(subs)
        if self.retention_clamps:
            out["retention_clamps"] = (
                f"{self.retention_clamps} window(s) clamped to the 90-day horizon — "
                f"history older than that is permanently unavailable"
            )
        if self.windows_skipped:
            out["windows_skipped_below_horizon"] = (
                f"{self.windows_skipped} window(s) lay entirely before the horizon and "
                f"were not requested — a cursor that far behind is skipped forward "
                f"rather than walked one hour at a time through data that is gone"
            )
        if self.forbidden_subscriptions:
            out["forbidden_subscriptions"] = (
                f"{self.forbidden_subscriptions} subscription poll(s) returned 403 — "
                f"missing Monitoring Reader, not a bad secret"
            )
        if self.subscription_errors:
            out["subscription_errors"] = self.subscription_errors
        if self.non_terminal_records:
            out["non_terminal_records"] = (
                f"{self.non_terminal_records} Started/BeginRequest record(s) — paired "
                f"with a terminal record on unmapped.operation_id; count writes with "
                f"the azure:terminal label, not with both"
            )
        if self.platform_records:
            out["platform_notifications"] = self.platform_records
        if self.actor_substitutions:
            out["actor_substitutions"] = self.actor_substitutions
        if self.tier0_grants:
            out["tier0_role_grants"] = self.tier0_grants
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(
        self, record: Mapping[str, Any], subscription: str = ""
    ) -> dict[str, Any] | None:
        """One ``EventData`` record as a 6003 payload.

        Not declared on :class:`Connector` — each vendor's is its own shape — but every
        connector in this package has one with this name, and the pipeline never calls
        it directly.
        """
        when = parse_iso8601(record.get("eventTimestamp"))
        if when is None:
            # Without a time the event cannot be windowed, correlated or retained, and
            # `Event.build` would stamp it with now — which is a fabricated fact, not a
            # default. The record is counted as unmapped rather than invented.
            self.stats.last_error = (
                f"{self.name}: a record arrived with no parseable eventTimestamp "
                f"(eventDataId={record.get('eventDataId')!r}) and was dropped rather "
                f"than stamped with the collection time"
            )
            return None

        operation = _local(record.get("operationName"))
        category = _local(record.get("category"))
        provider = _local(record.get("resourceProviderName"))
        event_name = _local(record.get("eventName"))
        claims = record.get("claims") if isinstance(record.get("claims"), Mapping) else {}
        properties = (
            record.get("properties")
            if isinstance(record.get("properties"), Mapping)
            else {}
        )

        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(ClassUid.API_ACTIVITY),
            # `action` operations resolve to Other (99) here, which is legal only
            # because `activity_name` is always set below.
            "activity_id": crud_activity(operation) if operation else API_OTHER,
            "activity_name": operation or event_name or "(unnamed Azure operation)",
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(record.get("eventDataId") or record.get("id") or ""),
            "metadata_product_name": "Azure Activity Log",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_log_name": "Microsoft.Insights/eventtypes/management",
            "metadata_log_provider": "Azure Monitor",
            "metadata_version": "1.9.0",
            "cloud_provider": "Microsoft Azure",
            "raw": dict(record),
        }
        # The full timestamp text, kept because `time` is a float and Azure's string
        # carries seven fractional digits — the ordering of two operations inside the
        # same millisecond is only recoverable from this.
        put(payload, "metadata_original_time", record.get("eventTimestamp"))
        put(payload, "metadata_event_code", event_name)
        put(payload, "metadata_correlation_uid", record.get("correlationId"))
        put(
            payload,
            "metadata_tenant_uid",
            record.get("tenantId")
            or dig(claims, _CLAIM_TENANT)
            or claims.get("tid")
            or (self.tenant().secret or None),
        )
        # `submissionTimestamp` is when the record became queryable, which the vendor's
        # own reference warns can be well after `eventTimestamp`. That difference is the
        # indexing lag this connector's window is held back for, so it is kept as a
        # measurable rather than a documented assumption.
        submitted = parse_iso8601(record.get("submissionTimestamp"))
        if submitted is not None:
            payload["metadata_logged_time"] = submitted
            if submitted - when > 60.0:
                stash(payload, "indexing_lag_seconds", round(submitted - when, 3))

        # An Azure subscription is the billing and isolation boundary — OCSF's
        # `cloud.account.uid`. Not `cloud.project_uid`, which is GCP's notion and would
        # put the same identifier under two names across the two cloud connectors.
        put(
            payload,
            "cloud_account_uid",
            record.get("subscriptionId") or subscription or None,
        )
        put(payload, "api_operation", operation)
        put(payload, "api_service_name", provider)
        # No `api_version`: the record says nothing about which version of the target
        # API was called, and 2015-04-01 is the version of *this* query.

        if category:
            # `metadata_product_feature_name` would be the natural home and is not a
            # legal 6003 field, so the routing value a hunt filters on lives in a label
            # (indexed) and in unmapped (readable).
            label(payload, f"azure:category:{category.lower()}")
            stash(payload, "category", category)
        # The join between an operation's Begin and End records. Not
        # `metadata_correlation_uid`, which holds `correlationId` — the wider
        # "everything the portal did in one click" grouping, a different granularity.
        stash(payload, "operation_id", record.get("operationId"))

        self._level(payload, record)
        self._status(payload, record, properties, event_name)
        self._actor(payload, record, claims, category, provider)
        self._source(payload, record, claims)
        self._authorization(payload, record)
        self._resources(payload, record, subscription)
        self._role_grant(payload, operation, properties)
        self._category_extras(payload, category, properties, record)
        self._message(payload, record, properties, operation, category)

        technique = self._technique(operation)
        if technique:
            attack(payload, technique)
        return payload

    # ── mapping parts ──────────────────────────────────────────────────────

    def _level(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """``level`` to ``unmapped``, and a note only where it would mislead.

        A note on every record would be 100% noise — almost everything is
        Informational. The note is attached only for Error and Critical, which are the
        two an operator reading the lake *would* expect to have moved ``severity_id``.
        """
        level = _local(record.get("level"))
        if not level:
            return
        stash(payload, "level", level)
        label(payload, f"azure:level:{level.lower()}")
        if level.lower() in ("error", "critical"):
            note(
                payload,
                f"{self.name}: Azure reports level={level}, which describes the "
                f"operation's outcome and not its security significance; severity_id "
                f"stays Informational because this is an audit log with no opinion",
            )

    def _status(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        properties: Mapping[str, Any],
        event_name: str,
    ) -> None:
        """``status_id``, and the terminal/non-terminal split that stops double-counting.

        ``eventName`` is the vendor's own explicit marker for the pair —
        ``BeginRequest`` then ``EndRequest`` — so it is preferred over inferring from
        ``status``, and ``status`` is used as a second source because a few providers
        emit ``Started`` without the ``BeginRequest`` name.

        Non-terminal wins ties. If a record somehow carried ``EndRequest`` with
        ``Started``, treating it as non-terminal under-counts by one, and over-counting
        a destructive operation is the worse error of the two.
        """
        status = _local(record.get("status"))
        sub_status = _local(record.get("subStatus"))
        low = status.lower()
        marker = event_name.strip().lower()

        if low in _SUCCESS_STATUSES:
            payload["status_id"] = int(Status.SUCCESS)
        elif low in _FAILURE_STATUSES:
            payload["status_id"] = int(Status.FAILURE)
        else:
            # Includes the non-terminal set and anything unrecognised. Other, not
            # Unknown: Unknown asserts nobody assessed the record, and Azure did — it
            # said `Started`. Other's own definition is "not mapped, see the source
            # value", which is exactly this. OCSF 6003 has no in-progress member.
            payload["status_id"] = int(Status.OTHER)

        # `status` the string is not a legal 6003 field; `status_code` is where a
        # consumer looks for the source's own code.
        put(payload, "status_code", sub_status or status or None)

        detail_parts: list[str] = []
        if status and sub_status and status.lower() != sub_status.lower():
            detail_parts.append(status)
        error = self._error_text(properties)
        if error:
            detail_parts.append(error)
        elif not detail_parts and status:
            detail_parts.append(status)
        if detail_parts:
            put(payload, "status_detail", " — ".join(detail_parts), limit=TEXT_LIMIT)

        non_terminal = marker == "beginrequest" or low in _NON_TERMINAL_STATUSES
        terminal = marker == "endrequest" or low in (
            _SUCCESS_STATUSES | _FAILURE_STATUSES
        )
        if non_terminal:
            self.non_terminal_records += 1
            label(payload, "azure:non-terminal")
            note(
                payload,
                f"{self.name}: this is the *opening* record of an ARM operation "
                f"(eventName={event_name or '(none)'}, status={status or '(none)'}); a "
                f"terminal record with the same unmapped.operation_id follows, so "
                f"counting both double-counts the change and treating "
                f"status != Succeeded as a failure fires on every write in the tenant",
            )
        elif terminal:
            label(payload, "azure:terminal")
        elif status:
            note(
                payload,
                f"{self.name}: status={status!r} is not one of the values this "
                f"connector interprets, so status_id is Other and neither the terminal "
                f"nor the non-terminal label was applied — the raw value is in "
                f"status_code",
            )

    def _error_text(self, properties: Mapping[str, Any]) -> str:
        """The failure reason, out of ``properties.statusMessage``'s nested JSON.

        The single most useful string on a failed record, and it is a JSON document
        inside a JSON string: ``"{\\"status\\":\\"Failed\\",\\"error\\":{\\"code\\":
        \\"AuthorizationFailed\\",\\"message\\":\\"...\\"}}"``. Read as text, every
        "why did this fail" query in the lake returns an unparsed blob; decoded, the
        difference between a quota rejection and an ``AuthorizationFailed`` — which is
        an attacker probing permissions — becomes a field.
        """
        for key in ("statusMessage", "statusmessage", "message", "statusCode"):
            raw = properties.get(key)
            doc = _decode(raw)
            if isinstance(doc, Mapping):
                err = doc.get("error") if isinstance(doc.get("error"), Mapping) else doc
                code = str(err.get("code") or "").strip()
                text = str(err.get("message") or "").strip()
                joined = ": ".join(p for p in (code, text) if p)
                if joined:
                    return joined
            elif isinstance(raw, str) and raw.strip() and key != "statusCode":
                return raw.strip()
        return ""

    def _actor(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        claims: Mapping[str, Any],
        category: str,
        provider: str,
    ) -> None:
        """Who did it — user, service principal, managed identity, or the platform.

        ``caller`` alone is not enough. It is documented as "the email address of the
        user ... the UPN claim or SPN claim based on availability", which in practice
        means it is sometimes a UPN, sometimes an object GUID and sometimes an
        application id, and it is *absent* for ServiceHealth and some Autoscale records.
        The ``claims`` bag is the reliable source when it is present, so it is read
        first and ``caller`` is the fallback.
        """
        caller = str(record.get("caller") or "").strip()
        upn = str(
            claims.get("upn")
            or claims.get(_CLAIM_UPN)
            or claims.get("preferred_username")
            or ""
        ).strip()
        oid = str(claims.get("oid") or claims.get(_CLAIM_OID) or "").strip()
        display = str(claims.get("name") or claims.get(_CLAIM_NAME) or "").strip()
        app_id = str(claims.get("appid") or claims.get("azp") or "").strip()
        mirid = str(claims.get("xms_mirid") or "").strip()
        id_type = str(claims.get("idtyp") or "").strip().lower()

        principal = upn or (caller if _looks_like_email(caller) else "")
        if not principal:
            principal = display or (caller if caller and not _is_guid(caller) else "")
        put(payload, "actor_user_name", principal or None)
        put(payload, "actor_user_uid", oid or (caller if _is_guid(caller) else None))
        if _looks_like_email(principal):
            put(payload, "actor_user_email", principal)
            put(payload, "actor_user_domain", principal.rpartition("@")[2])

        # `uti` is the token's own identifier: every ARM call made with one stolen token
        # shares it, which makes it the join for "everything that access token did".
        # Named in a note because it is not an interactive session and reading it as one
        # would put a single API call and a two-hour portal session in the same bucket.
        token_uid = str(claims.get("uti") or "").strip()
        if token_uid:
            put(payload, "actor_session_uid", token_uid)
            note(
                payload,
                f"{self.name}: actor_session_uid is the access token's `uti` claim, "
                f"not an interactive session — every ARM call made with the same token "
                f"carries it, which is the pivot for scoping one stolen token's actions",
            )

        if app_id:
            stash(payload, "app_id", app_id)
        acr = str(claims.get("appidacr") or "").strip()
        if acr:
            stash(payload, "app_auth_method", _APPIDACR.get(acr, f"appidacr={acr}"))

        amr = claims.get(_CLAIM_AMR) or claims.get("amr")
        if amr not in (None, "", [], {}):
            text = ",".join(amr) if isinstance(amr, list) else str(amr)
            stash(payload, "auth_methods", text)
            payload["actor_session_is_mfa"] = "mfa" in text.lower()

        wids = claims.get("wids")
        if wids not in (None, "", [], {}):
            listed = wids if isinstance(wids, list) else [str(wids)]
            stash(payload, "directory_role_template_ids", [str(w) for w in listed])
            if any(str(w).strip().lower() == _GLOBAL_ADMIN_ROLE_TEMPLATE for w in listed):
                label(payload, "caller-global-admin")
                note(
                    payload,
                    f"{self.name}: the caller's token carries the Global Administrator "
                    f"role template id, so this subscription change was made with "
                    f"tenant-wide directory power rather than a scoped Azure RBAC role",
                )

        for key in ("puid", "ver", "iss", "aud", "idp", "acct"):
            value = claims.get(key)
            if value not in (None, ""):
                stash(payload, f"claim_{key}", clip(value, 256))
        scope_claim = claims.get(_CLAIM_SCOPE) or claims.get("scp")
        if scope_claim not in (None, ""):
            stash(payload, "token_scope", clip(scope_claim, 512))

        if mirid:
            # A managed identity has no secret to steal from outside the resource, so a
            # managed-identity caller doing something unexpected means the *resource* is
            # compromised — a materially different investigation from a leaked secret.
            stash(payload, "managed_identity_resource_id", mirid)
            label(payload, "actor:managed-identity")
        elif id_type == "app" or (app_id and not upn and not display):
            label(payload, "actor:service-principal")
        elif principal:
            label(payload, "actor:user")

        if payload.get("actor_user_name") or payload.get("actor_user_uid"):
            return

        # ── no actor at all ──
        self.actor_substitutions += 1
        platform = category.lower() in _PLATFORM_CATEGORIES
        if platform:
            self.platform_records += 1
        put(payload, "actor_invoked_by", provider or "Azure platform")
        label(payload, "substitute_for:actor")
        if platform:
            label(payload, "azure:platform-notification")
            note(
                payload,
                f"{self.name}: category={category or '(none)'} is a platform "
                f"notification with no caller — OCSF 6003 requires an actor, so "
                f"actor_invoked_by holds the emitting provider "
                f"({provider or 'Azure platform'}) under substitute_for:actor. There "
                f"is no human or principal behind this record and none should be "
                f"inferred; it is collected so an outage can be told apart from an "
                f"attacker disabling the same telemetry",
            )
        else:
            note(
                payload,
                f"{self.name}: this {category or 'uncategorised'} record carries no "
                f"caller and no claims, which for an actor-bearing category is a gap "
                f"in Azure's own log rather than a platform event; actor_invoked_by "
                f"holds the provider under substitute_for:actor so the event satisfies "
                f"its class, and the absence is stated here rather than implied",
            )

    def _source(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        claims: Mapping[str, Any],
    ) -> None:
        """Caller IP, from the two places Azure puts it — and the mismatch between them.

        ``httpRequest.clientIpAddress`` is the address ARM actually received the request
        from. ``claims.ipaddr`` is the address the *token* was issued to, baked in at
        authentication time. The request address is therefore preferred: it is what
        happened, not what was true earlier.

        When both are present and they differ, the token was minted at one address and
        spent at another, which is the shape of a stolen access token (T1550.001). It is
        a hint and labelled as one — a mobile client changing networks, a corporate proxy
        and a VPN egress change all produce the same mismatch — but it is the only signal
        in this log for that technique, so discarding it to avoid false positives would
        discard the detection entirely.
        """
        api_ip = dig(record, "httpRequest.clientIpAddress")
        token_ip = claims.get("ipaddr")
        set_ip(payload, "src_endpoint_ip", api_ip or token_ip)

        api_text = str(api_ip or "").strip()
        token_text = str(token_ip or "").strip()
        if api_text and token_text and api_text != token_text:
            stash(payload, "token_issued_ip", token_text)
            label(payload, "token-ip-mismatch")
            attack(payload, "T1550.001")
            note(
                payload,
                f"{self.name}: the access token was issued to {token_text} and used "
                f"from {api_text}. That is how a stolen token looks; it is also how a "
                f"roaming client, a proxy and a changed VPN egress look, so this is a "
                f"hint for correlation and not a finding on its own",
            )

        stash(payload, "http_method", dig(record, "httpRequest.method"))
        stash(payload, "http_uri", clip(dig(record, "httpRequest.uri"), 512))
        stash(payload, "client_request_id", dig(record, "httpRequest.clientRequestId"))

        if payload.get("src_endpoint_ip"):
            return
        # 6003 *requires* src_endpoint, and a platform-emitted record has no address at
        # all — so the choice is a labelled substitute or an event that fails its own
        # class contract and is quarantined. `src_endpoint_svc_name` is the same field
        # CloudTrail's service-principal path uses.
        put(
            payload,
            "src_endpoint_svc_name",
            _local(record.get("resourceProviderName")) or "Azure Resource Manager",
        )
        label(payload, "substitute_for:src_endpoint")
        note(
            payload,
            f"{self.name}: no caller address — Azure omits httpRequest for portal-less "
            f"platform operations and claims.ipaddr for app-only tokens, so "
            f"src_endpoint carries the emitting service name instead of an address; "
            f"nothing here should be read as network provenance",
        )

    def _authorization(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """The RBAC check ARM performed, which is not the same as the role it granted.

        ``authorization.role`` is the role the **caller** used to be allowed through. On
        a ``roleAssignments/write`` record that is the caller's own role (Owner, say),
        while the role being *handed out* is buried in ``properties.requestbody`` — see
        :meth:`_role_grant`. Reading ``authorization.role`` as the granted role turns
        every role assignment into "Owner was granted", which is both wrong and alarming.
        """
        auth = record.get("authorization")
        if not isinstance(auth, Mapping):
            return
        stash(payload, "authorization_action", auth.get("action"))
        stash(payload, "authorization_role", auth.get("role"))
        stash(payload, "authorization_scope", auth.get("scope"))
        evidence_doc = auth.get("evidence")
        if isinstance(evidence_doc, Mapping):
            stash(payload, "authorization_evidence", dict(evidence_doc))

    def _resources(
        self, payload: dict[str, Any], record: Mapping[str, Any], subscription: str
    ) -> None:
        """``resourceId`` into the plural ``resources`` array — its only legal home.

        OCSF 6003 declares no singular ``resource_uid``/``resource_name``/
        ``resource_type``; those exist on other classes and were measured illegal here.
        An assignment to them is swept to ``unmapped`` and named as a mapping error,
        which is how the target resource of every Azure operation would have gone
        missing from the field the hunt layer joins on.
        """
        refs: list[dict[str, Any]] = []
        rid = record.get("resourceId")
        if rid:
            refs.append(
                resource_ref(
                    uid=rid,
                    name=_leaf(rid),
                    type=_local(record.get("resourceType")),
                    namespace=_local(record.get("resourceProviderName")),
                    group=record.get("resourceGroupName"),
                    cloud_partition=record.get("subscriptionId") or subscription or None,
                )
            )
        scope = dig(record, "authorization.scope")
        if scope and str(scope).strip() != str(rid or "").strip():
            refs.append(
                resource_ref(
                    uid=scope,
                    name=_leaf(scope),
                    data={
                        "purpose": "the scope at which the caller's permission was "
                        "evaluated, which can be broader than the resource changed"
                    },
                )
            )
        if refs:
            payload["resources"] = refs
        stash(payload, "resource_group", record.get("resourceGroupName"))

    def _role_grant(
        self,
        payload: dict[str, Any],
        operation: str,
        properties: Mapping[str, Any],
    ) -> None:
        """The role actually granted, out of ``properties.requestbody``.

        The most security-relevant string in the whole Activity Log, and it is a JSON
        document inside a JSON string, referring to the role by GUID:
        ``{"Id":"...","Properties":{"PrincipalId":"...","RoleDefinitionId":
        "/subscriptions/.../roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}``.
        Without decoding it and resolving the GUID, "was anyone granted Owner" cannot be
        asked of this log at all.

        A regex rather than a strict parse of a known path, because the casing of the
        inner keys varies by ARM version (``Properties.RoleDefinitionId`` and
        ``properties.roleDefinitionId`` both occur) and the body is occasionally
        truncated by the service. A regex over the text degrades to "found nothing"
        where a path walk raises, and the GUID pattern is specific enough that a false
        match would have to be a role-definition id.
        """
        if "roleassignments" not in operation.lower():
            return
        blob = ""
        for key in ("requestbody", "requestBody", "responseBody", "responsebody"):
            value = properties.get(key)
            if isinstance(value, str) and value.strip():
                blob = value
                break
            if isinstance(value, (Mapping, list)):
                blob = json.dumps(value)
                break
        if not blob:
            return

        found = _ROLE_DEF_RE.search(blob)
        if found:
            role_id = found.group(1).lower()
            stash(payload, "granted_role_definition_id", role_id)
            role_name = _BUILTIN_ROLES.get(role_id)
            if role_name:
                # `privileges` is declared by the user/group-management classes and was
                # measured illegal on 6003, so the resolved name goes to unmapped with a
                # label rather than being reported as a mapping error.
                stash(payload, "granted_role_name", role_name)
                label(payload, f"granted-role:{role_name.lower().replace(' ', '-')}")
            if role_id in _TIER0_ROLE_IDS:
                self.tier0_grants += 1
                label(payload, "tier0-role")
                attack(payload, "T1098.003")
                note(
                    payload,
                    f"{self.name}: the role in this assignment is "
                    f"{role_name or role_id} — a role that can grant further roles, "
                    f"read every secret in scope or mint a key that bypasses RBAC, so "
                    f"this operation is a change of control over the subscription "
                    f"rather than a change of access within it",
                )
        principal = _PRINCIPAL_ID_RE.search(blob)
        if principal:
            stash(payload, "grant_principal_id", principal.group(1))
        ptype = _PRINCIPAL_TYPE_RE.search(blob)
        if ptype:
            stash(payload, "grant_principal_type", ptype.group(1))

    def _category_extras(
        self,
        payload: dict[str, Any],
        category: str,
        properties: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        """The per-category ``properties`` fields worth promoting out of the blob.

        ``properties`` is free-form per provider, so the whole thing is kept, clipped,
        under ``unmapped.properties``. These branches lift the handful of keys that are
        either a real OCSF field (``cloud_region`` for ServiceHealth) or the difference
        between an investigable record and an opaque one.
        """
        low = category.lower()
        if properties:
            stash(payload, "properties", clip(json.dumps(properties, default=str), TEXT_LIMIT))

        if low == "policy":
            # `properties.policies` is a JSON string of the evaluated policies. A `deny`
            # effect means the operation was *blocked by policy* — the request happened
            # and did not take effect, which is a different fact from either success or
            # failure and is invisible without decoding this.
            doc = _decode(properties.get("policies"))
            entries = doc if isinstance(doc, list) else [doc] if isinstance(doc, Mapping) else []
            effects = [
                str(e.get("policyDefinitionEffect") or e.get("effect") or "").lower()
                for e in entries
                if isinstance(e, Mapping)
            ]
            names = [
                str(e.get("policyDefinitionName") or e.get("policyDefinitionId") or "")
                for e in entries
                if isinstance(e, Mapping)
            ]
            if effects:
                stash(payload, "policy_effects", [e for e in effects if e])
            if any(n for n in names):
                stash(payload, "policy_definitions", [n for n in names if n])
            if "deny" in effects:
                label(payload, "azure:policy-denied")
                note(
                    payload,
                    f"{self.name}: an Azure Policy assignment denied this operation, so "
                    f"the request was made and did not take effect — a blocked attempt, "
                    f"which is neither a success nor a service failure",
                )
        elif low == "servicehealth":
            put(payload, "cloud_region", properties.get("region"))
            for key in ("service", "incidentType", "trackingId", "stage", "title"):
                stash(payload, f"health_{key}", clip(properties.get(key), 512))
            impacted = _decode(properties.get("impactedServices"))
            if impacted is not None:
                stash(payload, "impacted_services", clip(json.dumps(impacted, default=str), 1024))
        elif low == "resourcehealth":
            current = properties.get("currentHealthStatus")
            previous = properties.get("previousHealthStatus")
            stash(payload, "health_current", current)
            stash(payload, "health_previous", previous)
            stash(payload, "health_cause", properties.get("cause"))
            if str(current or "").strip().lower() in ("unavailable", "degraded"):
                label(payload, f"azure:health:{str(current).strip().lower()}")
                note(
                    payload,
                    f"{self.name}: this resource became {current}. During an active "
                    f"incident that is not necessarily a platform fault — a deleted "
                    f"disk, a deallocated VM and a destroyed backup all surface here — "
                    f"so correlate it against the Administrative records for the same "
                    f"resourceId before attributing it to Azure",
                )
        elif low == "autoscale":
            for key in ("oldInstancesCount", "newInstancesCount", "resourceName"):
                stash(payload, f"autoscale_{key}", properties.get(key))
        elif low == "recommendation":
            for key in (
                "recommendationType",
                "recommendationName",
                "recommendationCategory",
                "recommendationImpact",
            ):
                stash(payload, f"advisor_{key}", properties.get(key))
        elif low == "alert":
            payload["is_alert"] = True
            note(
                payload,
                f"{self.name}: this is an Azure Monitor alert-rule notification. "
                f"severity_id stays Informational: the rule fired on a metric or a log "
                f"query defined by the subscription's owners, which carries no security "
                f"opinion, and manufacturing priority from it would let anyone with "
                f"rule-write access set SOC priority",
            )
        elif low == "security":
            label(payload, "azure:defender-pointer")
            note(
                payload,
                f"{self.name}: category=Security records are Defender for Cloud "
                f"pointers written into the Activity Log; they carry a fraction of the "
                f"detail. The authoritative feed is the Defender connector, and "
                f"severity is set there rather than inferred here",
            )

    def _message(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        properties: Mapping[str, Any],
        operation: str,
        category: str,
    ) -> None:
        """A one-line human summary, from the vendor's own text where there is any."""
        vendor = first(
            {"description": record.get("description"), "properties": properties},
            "description",
            "properties.title",
            "properties.description",
            "properties.message",
        )
        if isinstance(vendor, str) and vendor.strip():
            put(payload, "message", vendor.strip(), limit=MESSAGE_LIMIT)
            return
        who = (
            payload.get("actor_user_name")
            or payload.get("actor_user_uid")
            or payload.get("actor_invoked_by")
            or "an unidentified principal"
        )
        target = _leaf(record.get("resourceId")) or record.get("resourceGroupName") or ""
        status = payload.get("status_code") or ""
        composed = f"{who} {operation or category or 'acted'}"
        if target:
            composed += f" on {target}"
        if status:
            composed += f" — {status}"
        put(payload, "message", composed, limit=MESSAGE_LIMIT)

    def _technique(self, operation: str) -> str:
        """The ATT&CK technique the operation *is*, or empty.

        Exact match first, then a suffix family. Empty is a legitimate and common
        answer: most ARM operations are ordinary administration, and tagging them would
        make the technique field meaningless. Reads and enumeration deliberately get
        nothing here — discovery is a rate over many records, not a property of one — and
        :data:`_TECHNIQUES_DELIBERATELY_NOT_EMITTED` records that choice per id so
        Phase 2's coverage matrix can tell a decision apart from an oversight.
        """
        key = operation.strip().lower()
        if not key:
            return ""
        exact = _OPERATION_TECHNIQUES.get(key)
        if exact:
            return exact
        for suffix, technique in _SUFFIX_TECHNIQUES.items():
            if key.endswith(suffix):
                return technique
        return ""


def azure_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[AzureActivityConnector]:
    """The Azure connector set. One today; kept as a factory for symmetry with Entra."""
    return [AzureActivityConnector(pipeline, config, **kwargs)]


__all__ = [
    "ACTIVITY_API_VERSION",
    "ACTIVITY_PATH",
    "ARM_SCOPE_SUFFIX",
    "EVENT_HISTORY_SECONDS",
    "RETENTION_MARGIN_SECONDS",
    "AzureActivityConnector",
    "azure_connectors",
]

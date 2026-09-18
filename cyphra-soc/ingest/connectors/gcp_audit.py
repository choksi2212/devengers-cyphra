"""Google Cloud Audit Logs — the GCP control plane (6003 API Activity).

Every admin write against a project's resources lands here: role grants, ``runCommand``
on a VM, KMS key destruction, workload identity pool creation, service-account key
minting. It is the GCP analogue of Azure Activity Log and CloudTrail, with the most
read-it-wrong surface area of the three because **the wrong form fails silently rather
than raising**. The seven traps that matter are below; each one returns a *plausible*
result rather than an error, which is the only kind of wrong reading that survives.

── Every parameter travels in the body, so the cursor is a body cursor ───────
``POST https://logging.googleapis.com/v2/entries:list`` takes ``resourceNames``,
``filter``, ``orderBy``, ``pageSize`` and ``pageToken`` in the **request body**, with
no documented query parameters. That makes this a body-cursor connector: the next
page is the same address with ``pageToken`` advanced, exactly like CloudTrail's
``LookupEvents``. Using ``next_url`` here cannot express the next page at all, and
using it as a header would be worse.

── The filter has no default time range ─────────────────────────────────────
The inverse of Azure Activity Log, where ``$filter`` is mandatory. An empty ``filter``
matches every log entry in the listed resources — every project ever written to — and
the first cycle after a fresh install would read years of history. :meth:`fetch_window`
always emits a ``timestamp`` window.

── ``AND``/``OR`` are uppercase and timestamps must be double-quoted ────────
The exact opposite of Azure Activity Log, which requires lowercase ``and`` and
single-quoted ISO timestamps. GCP's Cloud Logging query language is documented to
**silently** treat a lowercase ``and`` as a free-text search term, which the same page
flags as "THIS CAUSES A SLOW SEARCH!" — the cycle does not fail, it just reads more
slowly than the operator expects. Timestamps not wrapped in ``"…"`` parse as bare
words, which is even worse. :meth:`_build_filter` quotes both forms correctly.

── ``log_id()``'s argument is NOT URL-encoded; ``logName``'s value IS ───────
Same log identifier, two opposite encodings, in the same filter language. The doc
page is explicit that URL-encoding the argument of ``log_id()`` "won't match any log
entries" and ``logName`` is documented in its URL-encoded form
(``projects/.../logs/cloudaudit.googleapis.com%2Factivity``) with the unencoded form
marked "-- WRONG!" — so this connector takes care to do each one right.

── ``status`` is absent or ``{}`` on success, not an empty string ───────────
proto3 JSON omits default values, so the REST reference for ``AuditLog`` documents
nothing about the success state and the natural test — ``"status" in record`` —
marks every successful audit log as a failure. The only correct rule is
``status.get("code", 0) != 0``. Failure to apply it sends every Admin Activity record
to the false-positive queue and trains the operator to ignore the detector.

── An empty ``entries`` list does not mean the search is finished ───────────
A page can return ``{"entries": [], "nextPageToken": "..."}`` and the iteration
*must* continue: a returned token is the vendor's signal that there are more
entries. ``Connector.paginate`` already handles this — ``pending`` is computed from
the cursor, not from the record count — but the trap is to add a ``if not records:
return`` guard around the iteration, which reads "the cycle ran cleanly" while
losing every record after page one.

── There are TWO retention horizons in one connector, and only one is fixed ─
The ``_Required`` bucket (Admin Activity + System Event) is **400 days, not
configurable**, and the ``_Default`` bucket (Data Access + Policy Denied) is
**30 days, configurable down to 1 day**. A single clamp constant is wrong in
either direction; this connector clamps to 400 (the worse of the two losses) so
that Admin Activity is not silently dropped, and states the Data Access shortfall
in :meth:`probe` rather than coding around it.

── Data Access is off by default, and the read permission is different ──────
``cloudaudit.googleapis.com/data_access`` is disabled by default in every service
**except BigQuery**, and reading it needs ``roles/logging.privateLogViewer`` even
when it is on. ``roles/logging.viewer`` covers Admin Activity, Policy Denied and
System Event cleanly; it returns nothing for Data Access, which the operator will
read as "no Data Access has happened in this project", which is the opposite of
the truth. The auth diagnostic names this directly.

── GCP console sign-in is not in this log at all ──────────────────────────
"Who signed into the GCP console" is answered only by Google Workspace's login
audit (``google_workspace.py``), not here. Cloud Audit Logs only sees Google Cloud
API calls; the human sign-in to ``console.cloud.google.com`` lives in Workspace.
This is stated in :meth:`probe` so the operator does not conclude "no console
sign-ins today" from a clean Cloud Logging feed.

── Quota is 60 requests per minute per project, non-increasable ─────────────
``entries.list`` is capped at 60/min and "Cannot be increased" in the docs; the
non-hierarchical bucket is also shared with anyone using the Logs Explorer in the
console, so a real deployment with an analyst on the project spends that budget
together. The connector's limiter is set to ~0.8 req/s (≈48/min) to leave 20%
headroom for the human.

── A ``LogEntry.split`` field means the entry is a *fragment* ───────────────
Entries larger than 256 KiB are split into fragments and reassembled by the
client; a successful read of a fragment with no reassembly produces silently
wrong data from a successful read. The connector labels, notes and counts every
fragment so the detect layer can exclude or reassemble.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, Severity, Status
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, ServiceAccountJwtAuth, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    dig,
    iso8601,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import AuthError, HttpError, Request
from ingest.connectors.mapping import (
    API_CREATE,
    API_DELETE,
    API_OTHER,
    API_READ,
    API_UPDATE,
    MESSAGE_LIMIT,
    TEXT_LIMIT,
    attack,
    clip,
    label,
    note,
    put,
    resource_ref,
    stash,
)

#: OAuth2 scope required to read Cloud Logging entries.
#: ``https://www.googleapis.com/auth/logging.read`` is the read-only scope; admin
#: scopes are not needed because this connector only lists entries.
LOGGING_READ_SCOPE = "https://www.googleapis.com/auth/logging.read"

#: The single API method that does the work. All parameters travel in the body.
ENTRIES_LIST_PATH = "/v2/entries:list"

#: ``protoPayload.@type`` discriminator for ``AuditLog``. Anything else inside
#: ``protoPayload`` is a service-defined payload, not an audit record; it is
#: kept and labelled rather than dropped because suppression is the more
#: dangerous of the two.
AUDIT_LOG_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog"

#: Retention for the ``_Required`` bucket (Admin Activity + System Event).
#: 400 days, **not** configurable. Data Access and Policy Denied live in the
#: ``_Default`` bucket which is 30 days by default and configurable down to 1.
REQUIRED_HISTORY_SECONDS = 400 * 86_400.0

#: Retention for the ``_Default`` bucket (Data Access + Policy Denied). Stated
#: in :meth:`probe` because Data Access is the only log type that needs both a
#: configuration change and a different IAM role to be visible at all.
DEFAULT_BUCKET_HISTORY_SECONDS = 30 * 86_400.0

#: Margin held back from the retention horizon, identical in shape to Azure's
#: and CloudTrail's: history older than this does not exist to be read, and a
#: window reaching past it is a permanent gap rather than a delayed read.
RETENTION_MARGIN_SECONDS = 12 * 3_600.0

#: Maximum resources per ``entries.list`` request. Documented hard ceiling.
MAX_RESOURCE_NAMES = 100

#: Maximum characters in a single ``filter`` string. Documented hard ceiling,
#: comments included — counted as the API sees it.
MAX_FILTER_CHARS = 20_000

#: The four Cloud Audit Logs log identifiers. These are passed to ``log_id()``
#: in their **unencoded** form (the function's argument is documented to NOT
#: be URL-encoded) and to ``logName`` equality comparisons in their URL-encoded
#: form (``%2F`` instead of ``/``).
AUDIT_LOG_IDS: tuple[str, ...] = (
    "cloudaudit.googleapis.com/activity",
    "cloudaudit.googleapis.com/data_access",
    "cloudaudit.googleapis.com/system_event",
    "cloudaudit.googleapis.com/policy",
)

#: LogSeverity weights used to keep the original level readable in ``unmapped``
#: without ever promoting ``severity_id`` from Informational — same argument as
#: Azure's ``level``: this is an audit log with no opinion, and only a source
#: that is itself an alerting product gets to set severity from its own field.
_LOG_SEVERITY_WEIGHTS: Mapping[str, int] = {
    "DEFAULT": 0,
    "DEBUG": 100,
    "INFO": 200,
    "NOTICE": 300,
    "WARNING": 400,
    "ERROR": 500,
    "CRITICAL": 600,
    "ALERT": 700,
    "EMERGENCY": 800,
}

#: ``google.rpc.Code`` → the canonical name. Public, stable, and the only
#: thing ``status_code`` can carry without inventing values.
_RPC_CODES: Mapping[int, str] = {
    0: "OK",
    1: "CANCELLED",
    2: "UNKNOWN",
    3: "INVALID_ARGUMENT",
    4: "DEADLINE_EXCEEDED",
    5: "NOT_FOUND",
    6: "ALREADY_EXISTS",
    7: "PERMISSION_DENIED",
    8: "RESOURCE_EXHAUSTED",
    9: "FAILED_PRECONDITION",
    10: "ABORTED",
    11: "OUT_OF_RANGE",
    12: "UNIMPLEMENTED",
    13: "INTERNAL",
    14: "UNAVAILABLE",
    15: "DATA_LOSS",
    16: "UNAUTHENTICATED",
}

#: Roles whose grant is a change of *control* over the project rather than a
#: change of access within it. Deliberately privilege-escalating only — read
#: roles are deliberately excluded because every granted role generates an
#: AuditLog and the noise floor would bury the actual escalations.
_TIER0_ROLES: frozenset[str] = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.workloadIdentityPoolAdmin",
        "roles/iam.roleAdmin",
        "roles/resourcemanager.organizationAdmin",
        "roles/resourcemanager.folderAdmin",
        "roles/resourcemanager.projectIamAdmin",
        "roles/orgpolicy.policyAdmin",
        "roles/billing.admin",
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/secretmanager.secretAccessor",
        "roles/container.admin",
        "roles/container.clusterAdmin",
        "roles/compute.admin",
        "roles/storage.admin",
        "roles/logging.admin",
    }
)

#: Public principals — granting a role to ``allUsers`` or ``allAuthenticatedUsers``
#: is a one-action exposure of whatever the role can do. Kept as a constant so
#: "who was just made world-readable" is a label query.
_PUBLIC_PRINCIPALS: frozenset[str] = frozenset({"allUsers", "allAuthenticatedUsers"})

#: Compiled once. ``resource.labels.zone`` is shaped ``"us-central1-a"``; the
#: regex peels the trailing letter to derive ``region``. ``resourceLocation.
#: currentLocations[0]`` and ``resource.labels.{location,region}`` win when
#: present, so this is the fallback only.
_ZONE_RE = re.compile(r"^(.*)-[a-z]$")


def _looks_like_email(value: Any) -> bool:
    """Conservative enough that an SPN claim never lands in an email field.

    ``principalEmail`` is documented as either an email or a service-account
    identifier (``...iam.gserviceaccount.com``) depending on the principal type.
    The Event model does not reject a malformed address, which is exactly why
    this check exists: an unvalidated assignment would put a numeric service-
    account id in ``actor_user_email`` and every downstream join on identity
    would silently match nothing.
    """
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    _, _, domain = text.rpartition("@")
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _leaf(resource_name: Any) -> str:
    """The resource's own name out of a GCP ``resourceName``.

    Shape is ``//<service>.<provider>/<path>/<name>`` or
    ``projects/.../<path>/<name>``; the last ``/``-separated segment is what an
    operator reads as "the VM I just changed".
    """
    text = str(resource_name or "").strip().rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


#: Lower-case terminal-segment prefixes → API verb. First match wins; the
#: table is checked in the order it is defined. ``API_OTHER`` is the fallback
#: and ``activity_name`` is always set so a 99 never reaches the hard
#: validator unnamed.
_VERB_PREFIXES: tuple[tuple[str, int], ...] = (
    ("create", API_CREATE),
    ("insert", API_CREATE),
    ("add", API_CREATE),
    ("batchcreate", API_CREATE),
    ("undelete", API_CREATE),
    ("generate", API_CREATE),
    ("import", API_CREATE),
    ("clone", API_CREATE),
    ("copy", API_CREATE),
    ("get", API_READ),
    ("list", API_READ),
    ("read", API_READ),
    ("access", API_READ),
    ("search", API_READ),
    ("query", API_READ),
    ("testiampermissions", API_READ),
    ("lookup", API_READ),
    ("batchget", API_READ),
    ("watch", API_READ),
    ("export", API_READ),
    ("update", API_UPDATE),
    ("patch", API_UPDATE),
    ("set", API_UPDATE),
    ("replace", API_UPDATE),
    ("enable", API_UPDATE),
    ("disable", API_UPDATE),
    ("move", API_UPDATE),
    ("reset", API_UPDATE),
    ("stop", API_UPDATE),
    ("start", API_UPDATE),
    ("resume", API_UPDATE),
    ("suspend", API_UPDATE),
    ("restart", API_UPDATE),
    ("attach", API_UPDATE),
    ("detach", API_UPDATE),
    ("expand", API_UPDATE),
    ("resize", API_UPDATE),
    ("delete", API_DELETE),
    ("destroy", API_DELETE),
    ("remove", API_DELETE),
    ("purge", API_DELETE),
    ("clear", API_DELETE),
    ("truncate", API_DELETE),
    ("drop", API_DELETE),
    ("batchdelete", API_DELETE),
)


def _verb_from_method(method: str) -> tuple[int, str]:
    """``(api_verb, activity_name)`` from a method like ``v1.compute.instances.insert``.

    The **terminal** ``.``-separated segment is lower-cased and matched against
    the prefix table. ``activity_name`` is the original method verbatim so a
    downstream consumer reads the source's own name. Empty method →
    ``(API_OTHER, "(unnamed)")`` so a 99 never reaches the hard validator
    unnamed.
    """
    if not method:
        return API_OTHER, "(unnamed)"
    activity_name = str(method).strip()
    tail = activity_name.rsplit(".", 1)[-1].lower() if activity_name else ""
    if not tail:
        return API_OTHER, activity_name
    for prefix, verb in _VERB_PREFIXES:
        if tail.startswith(prefix):
            return verb, activity_name
    return API_OTHER, activity_name


#: Method-name **tails** (case-insensitive, no leading dot) → ATT&CK
#: technique. Longest entries first so ``setcommoninstancemetadata`` does not
#: match ``set`` before reaching its own row, and full k8s method names are
#: used verbatim so ``pods.exec.create``→T1609 and ``pods.create``→T1610
#: cannot collide under ``endswith``.
_METHOD_TECHNIQUE_TAILS: Mapping[str, str] = {
    # ── identity & authorization ──
    "setiampolicy": "T1098.003",
    "createserviceaccountkey": "T1098.001",
    "undeleteserviceaccount": "T1098",
    "enableserviceaccount": "T1098",
    "disableserviceaccount": "T1531",
    "deleteserviceaccount": "T1531",
    "createserviceaccount": "T1136.003",
    "signjwt": "T1548.005",
    "signblob": "T1548.005",
    "generateaccesstoken": "T1548.005",
    "generateidtoken": "T1548.005",
    # ── instance & image manipulation ──
    "compute.instances.insert": "T1578.002",
    "compute.instances.delete": "T1578.003",
    "compute.snapshots.insert": "T1578.001",
    "compute.images.insert": "T1578.001",
    "compute.images.delete": "T1578.001",
    "compute.disks.createsnapshot": "T1578.001",
    # ── weakening the host via metadata ──
    # Narrowed by request inspection in _technique(); the tail match is the
    # default and the inspection can override to T1098.004 / T1059.
    "compute.instances.setmetadata": "T1098.004",
    "compute.instances.setcommoninstancemetadata": "T1098.004",
    # ── weakening the network ──
    "compute.firewalls.insert": "T1562.004",
    "compute.firewalls.patch": "T1562.004",
    "compute.firewalls.delete": "T1562.004",
    # ── blinding the defenders ──
    "logging.sinks.create": "T1562.008",
    "logging.sinks.update": "T1562.008",
    "logging.sinks.delete": "T1562.008",
    "logging.buckets.create": "T1562.008",
    "logging.buckets.update": "T1562.008",
    "logging.buckets.delete": "T1562.008",
    "logging.logs.delete": "T1562.008",
    "logging.exclusions.create": "T1562.008",
    "logging.exclusions.update": "T1562.008",
    "logging.exclusions.delete": "T1562.008",
    "logging.views.create": "T1562.008",
    "logging.views.delete": "T1562.008",
    "serviceusage.services.enable": "T1562.001",
    "serviceusage.services.disable": "T1562.001",
    # ── credential access ──
    "accesssecretversion": "T1555.006",
    # ── workload identity & trust ──
    "workloadidentitypools.create": "T1484.002",
    "workloadidentitypools.update": "T1484.002",
    "workloadidentityproviders.create": "T1484.002",
    "workloadidentityproviders.update": "T1484.002",
    # ── moving things between parents ──
    "resourcemanager.projects.move": "T1666",
    "resourcemanager.folders.move": "T1666",
    # ── serverless / Functions / Run ──
    "cloudfunctions.functions.create": "T1648",
    "cloudfunctions.functions.update": "T1648",
    "cloudfunctions.functions.delete": "T1648",
    "run.services.create": "T1648",
    "run.services.update": "T1648",
    "run.services.delete": "T1648",
    # ── k8s (GKE) ──
    "io.k8s.core.v1.pods.create": "T1610",
    "io.k8s.core.v1.pods.exec.create": "T1609",
    "io.k8s.batch.v1.jobs.create": "T1053.007",
    "io.k8s.batch.v1.cronjobs.create": "T1053.007",
    # ── destruction ──
    "cloudkms.cryptokeyversions.destroy": "T1485",
    "cloudkms.keyrings.delete": "T1485",
    "resourcemanager.projects.delete": "T1485",
    "storage.buckets.delete": "T1485",
}


def _metadata_items(request: Mapping[str, Any]):
    """Yield every ``items`` dict from a ``setMetadata`` request body.

    The body shape is
    ``{"metadata": {"items": {"ssh-keys": "..."}, "fingerprint": "..."}}``
    and the older shape is ``{"items": {"ssh-keys": "..."}}`` directly — both
    occur, and the connector must not miss either.
    """
    seen: list[Mapping[str, Any]] = []
    if isinstance(request, Mapping):
        outer = request.get("metadata")
        if isinstance(outer, Mapping):
            items = outer.get("items")
            if isinstance(items, Mapping):
                seen.append(items)
        direct = request.get("items")
        if isinstance(direct, Mapping) and direct not in seen:
            seen.append(direct)
    return seen


def _technique_from_method(method: str, request: Mapping[str, Any] | None) -> str:
    """ATT&CK technique for ``method``, narrowed by ``request`` where necessary.

    Two cases require reading the request body to disambiguate:

    * ``setMetadata`` / ``setCommonInstanceMetadata`` with an ``items`` key
      ``ssh-keys`` is T1098.004 (Account Manipulation: SSH Authorized Keys);
      the same call with ``startup-script`` is T1059 (Command and Scripting
      Interpreter) — the *use* the field enables, not the manipulation itself.
    * ``SetIamPolicy`` always returns T1098.003 from the tail match; the
      caller separately inspects the bindings for tier-0 roles and public
      principals (see :meth:`GcpAuditConnector._authorization`).
    """
    if not method:
        return ""
    key = str(method).lower()
    for tail in sorted(_METHOD_TECHNIQUE_TAILS.keys(), key=len, reverse=True):
        if key.endswith(tail):
            return _METHOD_TECHNIQUE_TAILS[tail]
    if key.endswith(".compute.instances.setmetadata") or key.endswith(
        ".compute.instances.setcommoninstancemetadata"
    ):
        for items in _metadata_items(request or {}):
            if "ssh-keys" in items:
                return "T1098.004"
            if "startup-script" in items:
                return "T1059"
    return ""


def _zone_to_region(zone: Any) -> str:
    """Derive a region from a ``us-central1-a``-shaped zone, or empty.

    ``resourceLocation.currentLocations[0]`` and ``resource.labels.{location,
    region}`` are preferred when present, so this is the fallback only. A zone
    that does not match the documented pattern is returned empty rather than
    fabricated.
    """
    text = str(zone or "").strip()
    if not text:
        return ""
    match = _ZONE_RE.match(text)
    return match.group(1) if match else ""


def _strip_principal_prefix(member: Any) -> str:
    """``user:alice@example.com`` → ``alice@example.com``.

    The IAM binding member string carries a type prefix (``user:``,
    ``group:``, ``serviceAccount:``, ``domain:``) which must be removed before
    a comparison to the public-principal constants. The two public-principal
    values themselves carry no prefix.
    """
    text = str(member or "").strip()
    for prefix in ("user:", "group:", "serviceAccount:", "domain:"):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


class GcpAuditConnector(Connector):
    """Google Cloud Audit Logs for one or more projects/folders/orgs, as 6003.

    ── One connector, many resources, one request ────────────────────────────
    ``entries:list`` accepts up to 100 ``resourceNames`` in a single POST, so
    unlike Azure there is no per-project loop and the non-increasable 60/min
    quota is spent once per page rather than once per project per page. Empty
    ``resourceNames`` is a hard 400 (the field is REQUIRED), so an empty config
    is reported as a stats error rather than silently emitting a request.

    ── The 403-shaped throttle, and the failure mode the operator will see ───
    GCP returns quota exhaustion as ``HTTP 403`` with
    ``error.errors[0].reason = "rateLimitExceeded"``. ``ApiClient.send``
    previously tested 401/403 before checking for a masked throttle, so a
    correctly-permissioned credential that merely shared its non-increasable
    60/min bucket with an analyst in the Logs Explorer raised ``AuthError`` on
    the first attempt and told the operator to go audit permissions that were
    already right. The fix is in :mod:`ingest.connectors.http`; the connector
    relies on it.

    ── Data Access is the missing log type ──────────────────────────────────
    A credential that works for three log types returns nothing for Data Access
    silently, and the reason is twofold: (1) Data Access is disabled by default
    in every service **except BigQuery**, and (2) reading it requires
    ``roles/logging.privateLogViewer`` even when it is on. The auth diagnostic
    names both so a missing Data Access feed is not misread as "no Data Access
    has happened in this project".

    ── The actorless-record problem ─────────────────────────────────────────
    A ``system_event`` record (e.g. a managed-VM reboot by the platform) has no
    ``authenticationInfo.principalEmail`` at all — so the choice is to fill it
    with the platform or to emit an event that fails its own class contract.
    The platform is filled under a ``substitute_for:actor`` label and a note,
    for the same reason as the actorless record in the Azure connector.

    ── Two clocks matter, and one is the indexing-lag input ─────────────────
    ``timestamp`` is when the event occurred; ``receiveTimestamp`` is when
    Cloud Logging accepted it, output-only and always present. The difference
    is the indexing-lag signal: an entry with ``receiveTimestamp - timestamp``
    > 60 s is stashed as ``unmapped.indexing_lag_seconds`` so the operator can
    see backpressure rather than infer it.
    """

    name = "gcp_audit"
    detects = (
        "control-plane attacks on Google Cloud: IAM policy changes, service-account "
        "key minting, KMS key destruction, firewall / log-sink deletion, GKE pod "
        "exec, workload identity trust changes"
    )
    spec = ConnectorSpec(
        # ``entries.list`` has no documented ``pageSize`` maximum. The scarce
        # resource is requests-per-minute, not bytes per page, so the largest
        # acceptable value is the right one. If the service caps below 1000
        # then ``paginate``'s truncation heuristic simply never trips — the
        # safe direction.
        page_size=1000,
        # 60 requests/minute per project, non-increasable. The non-hierarchical
        # bucket is shared with anyone using the Logs Explorer in the console,
        # so a real deployment with an analyst on the project spends that
        # budget together. 0.8 req/s ≈ 48/min, leaving ~20% headroom.
        rate_per_second=0.8,
        burst=2,
        # A cycle that hits the page ceiling reads ~40,000 entries in ~50 s
        # wall clock; raising it would not help because the limiter, not the
        # page count, is the binding constraint.
        max_pages_per_cycle=40,
        initial_lookback_seconds=86_400.0,
        # Records are usually available within seconds; the 5-minute holdback
        # is the conservative end of the docs.
        indexing_lag_seconds=300.0,
        # 15 minutes re-read on every cycle; ``metadata_uid`` is ``insertId``
        # so the re-read is deduped for free.
        overlap_seconds=900.0,
        docs_url=(
            "https://docs.cloud.google.com/logging/docs/reference/v2/rest/"
            "v2/entries/list"
        ),
        required_grants=(
            "roles/logging.viewer on every resource in $GCP_PROJECT_ID — covers "
            "Admin Activity, Policy Denied and System Event; "
            "roles/logging.privateLogViewer is required additionally to read Data "
            "Access entries (which are disabled by default in every service "
            "except BigQuery)",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retention_clamps = 0
        self.windows_skipped = 0
        self.resource_names_dropped = 0
        self.compact_filters = 0
        self.split_fragments = 0
        self.non_audit_payloads = 0
        self.actor_substitutions = 0
        self.api_substitutions = 0
        self.permission_denials = 0
        self.tier0_grants = 0
        self.public_principal_grants = 0
        self.impersonations = 0
        self.unparseable_times = 0

    # ── credentials ────────────────────────────────────────────────────────

    def credentials_json(self) -> Credential:
        return self.config.connectors.gcp_credentials_json

    def project_id(self) -> Credential:
        return self.config.connectors.gcp_project_id

    def credentials(self) -> tuple[Credential, ...]:
        return (self.credentials_json(), self.project_id())

    def resource_names(self) -> tuple[str, ...]:
        """The ``resourceNames`` for this cycle, in declaration order, de-duplicated.

        ``$GCP_PROJECT_ID`` accepts ``,`` or ``;``-separated entries. Each entry
        is passed through verbatim if it already contains a ``/``
        (``organizations/...``, ``folders/...``, a log view name) and prefixed
        with ``projects/`` for bare ids. Truncated at :data:`MAX_RESOURCE_NAMES`
        with a counted, named warning — the connector does not loop, because
        the documentation is unambiguous that 100 is a per-request ceiling and
        what overflows is a *configuration* problem, not a cycle problem.
        """
        cred = self.project_id()
        if not cred.configured:
            return ()
        out: list[str] = []
        for part in str(cred.value).replace(";", ",").split(","):
            item = part.strip()
            if not item or item in out:
                continue
            out.append(item if "/" in item else f"projects/{item}")
        if len(out) > MAX_RESOURCE_NAMES:
            dropped = len(out) - MAX_RESOURCE_NAMES
            out = out[:MAX_RESOURCE_NAMES]
            self.resource_names_dropped = dropped
            self.stats.last_error = (
                f"{self.name}: $GCP_PROJECT_ID declared {len(out) + dropped} "
                f"resources and entries.list accepts at most {MAX_RESOURCE_NAMES} "
                f"per request; the trailing {dropped} were dropped from this cycle "
                f"and the configuration should be split across instances"
            )
        return tuple(out)

    def authorizer(self) -> Authorizer:
        """JWT bearer for the service account, no ``sub`` — GCP reads itself.

        ``.secret`` rather than ``.value``: an ``Authorizer`` is built by
        ``client()`` and described by the readiness report, both of which run
        on deployments where nothing is configured, and ``.value`` raises
        there by design.
        """
        return ServiceAccountJwtAuth(
            self.client(),
            credentials_json=self.credentials_json(),
            scopes=(LOGGING_READ_SCOPE,),
            subject=None,
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def base_url(self) -> str:
        return self.config.endpoints.gcp_logging.rstrip("/")

    def probe(self) -> Availability:
        """Credentials, plus the four limits that decide whether this is enough.

        The base implementation names missing slots and the required grant.
        What it cannot know is that this source is project-scoped (with a 100
        resources/request ceiling), that Data Access retention is 30 days and
        requires a different IAM role, that ``AND``/``OR`` must be uppercase,
        that GCP console sign-in is absent entirely, and that the API quota is
        non-increasable and shared with the Logs Explorer.
        """
        base = super().probe()
        if not base.available:
            return base
        resources = self.resource_names()
        scope = (
            f"{len(resources)} resource(s): " + ", ".join(resources)
            if resources
            else "(no resource parsed from $GCP_PROJECT_ID)"
        )
        limits = (
            f"SCOPE: {scope}. entries.list accepts up to {MAX_RESOURCE_NAMES} "
            f"resources per request and the field is REQUIRED — an empty "
            f"resourceNames is a 400. RETENTION: 400 days for Admin Activity + "
            f"System Event (_Required bucket, not configurable); 30 days for "
            f"Data Access + Policy Denied (_Default bucket, configurable down "
            f"to 1 day). QUOTA: 60 requests/minute per project, non-increasable; "
            f"the bucket is shared with anyone using the Logs Explorer in the "
            f"console, so a real deployment spends that budget together. "
            f"FILTER: AND/OR must be UPPERCASE and timestamps must be "
            f"double-quoted — lowercase `and` is silently parsed as a free-text "
            f"search term and the same page flags it as 'THIS CAUSES A SLOW "
            f"SEARCH'. DATA PLANE: a missing Data Access feed can mean either "
            f"(a) it is disabled (default for every service except BigQuery) or "
            f"(b) the credential lacks roles/logging.privateLogViewer. CONSOLE "
            f"SIGN-IN: absent. 'Who signed into console.cloud.google.com' is "
            f"answered only by the Google Workspace login audit (see "
            f"google_workspace.py), not here."
        )
        note_text = base.limitation
        return available(
            limitation=f"{note_text} {limits}".strip() if note_text else limits
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    def _retention_floor(self, window: TimeWindow) -> tuple[float, float]:
        """``(start to query, seconds of history lost to the 400-day horizon)``.

        Admin Activity and System Event retention is 400 days and not
        configurable; Data Access and Policy Denied are 30 days. Clamping to
        the worse of the two losses means Admin Activity is never silently
        dropped, and the Data Access shortfall is stated in :meth:`probe`.
        """
        floor = self.clock() - (REQUIRED_HISTORY_SECONDS - RETENTION_MARGIN_SECONDS)
        if window.start >= floor:
            return window.start, 0.0
        return floor, floor - window.start

    def _build_filter(self, start: float, end: float) -> tuple[str, str]:
        """``(filter, "logName" | "log_id")`` — the indexed form if it fits.

        The filter has two equivalent encodings — ``logName = "..."`` is
        documented to be indexed, ``log_id("...")`` is documented NOT to be —
        and a single ``filter`` cannot exceed :data:`MAX_FILTER_CHARS`. With
        100 resources × 4 log types the ``logName`` form is ≈28,000 chars and
        the ``log_id`` form is ≈30 chars + the window clause; the indexed
        path is preferred when it fits, the compact path is used otherwise, and
        the choice is recorded as ``compact_filters`` so an operator sees when
        a deployment has outgrown the indexed path.
        """
        window_clause = (
            f'timestamp >= "{iso8601(start)}" AND '
            f'timestamp <= "{iso8601(end)}"'
        )
        names: list[str] = []
        for resource in self.resource_names():
            for log_id in AUDIT_LOG_IDS:
                # ``logName`` value is URL-encoded; ``log_id`` argument is not.
                names.append(
                    f'logName = "{resource}/logs/{quote(log_id, safe="")}"'
                )
        indexed = window_clause + " AND (" + " OR ".join(names) + ")"
        if len(indexed) <= MAX_FILTER_CHARS:
            return indexed, "logName"
        self.compact_filters += 1
        compact = (
            window_clause
            + " AND ("
            + " OR ".join(f'log_id("{log_id}")' for log_id in AUDIT_LOG_IDS)
            + ")"
        )
        return compact, "log_id"

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        resources = self.resource_names()
        if not resources:
            self.stats.last_error = (
                f"{self.name}: $GCP_PROJECT_ID is unset or empty; entries.list "
                f"requires a non-empty resourceNames and was not called"
            )
            return []
        start, lost = self._retention_floor(window)
        if window.end <= start:
            # The *whole* window predates the horizon, which is the normal shape
            # of a restart after a long outage: see the Azure connector for the
            # same reasoning, expressed in GCP terms — an inverted range is an
            # empty 200, and the cursor is jumped to the floor in one cycle.
            self.retention_clamps += 1
            self.windows_skipped += 1
            self.note_record_time(start)
            self.stats.last_error = (
                f"{self.name}: the whole requested window ended "
                f"{(start - window.end) / 86_400:.1f} days before the 400-day "
                f"Admin Activity horizon, so none of it can be read and no "
                f"request was sent; the cursor jumped to the horizon. That "
                f"history was never collected and is a permanent gap, not a "
                f"delayed read"
            )
            return []
        filter_text, _which = self._build_filter(start, window.end)
        payloads: list[dict[str, Any]] = []

        def next_body(_resp: Any, doc: Any) -> Any:
            token = doc.get("nextPageToken") if isinstance(doc, Mapping) else None
            # The whole body, not just the token: GCP requires ``filter`` and
            # ``orderBy`` repeated on every page, and omitting them is a 400
            # rather than a defaulted request.
            if not token:
                return None
            return {
                "resourceNames": list(resources),
                "filter": filter_text,
                "orderBy": "timestamp asc",
                "pageSize": self.spec.page_size,
                "pageToken": token,
            }

        body = {
            "resourceNames": list(resources),
            "filter": filter_text,
            # ``orderBy`` is required for cursor stability; ties broken by
            # ``insertId``, which is what becomes ``metadata_uid``.
            "orderBy": "timestamp asc",
            "pageSize": self.spec.page_size,
        }
        request = Request(
            "POST",
            self.base_url() + ENTRIES_LIST_PATH,
            label=f"{self.name}.entries:list",
            headers={"Accept": "application/json"},
            json_body=body,
            idempotent=True,
        )
        try:
            async for page in self.paginate(
                request, records_at=("entries",), next_body=next_body
            ):
                for record in page:
                    when = parse_iso8601(dig(record, "timestamp"))
                    if when is None:
                        # Without a time the event cannot be windowed,
                        # correlated or retained, and ``Event.build`` would
                        # stamp it with now — which is a fabricated fact, not
                        # a default. The record is counted as unmapped rather
                        # than invented.
                        self.unparseable_times += 1
                        continue
                    self.note_record_time(when)
                    mapped = self.map_record(record)
                    if mapped is not None:
                        payloads.append(mapped)
        except AuthError as exc:
            # GCP's quota exhaustion looks like 403, but ``ApiClient.send``
            # translates it into a retryable throttle before this point, so a
            # real 403 here is the credential or the IAM scope, not the rate
            # limit. The single most likely cause is the ``privateLogViewer``
            # diagnosis: a credential that works for three log types silently
            # returns nothing for the fourth, and the operator will read an
            # empty cycle as "no Data Access has happened" — the opposite of
            # the truth.
            body_excerpt = clip(exc.body, 200)
            self.stats.last_error = (
                f"{self.name}: HTTP {exc.status or '?'} on entries:list — the "
                f"single most likely cause is that the service account holds "
                f"roles/logging.viewer but not roles/logging.privateLogViewer; "
                f"Admin Activity, Policy Denied and System Event are visible "
                f"with the former, Data Access is not, and the symptom is an "
                f"empty cycle for one of the four log types ({body_excerpt})"
            )
            raise
        except HttpError as exc:
            self.stats.last_error = (
                f"{self.name}: entries:list failed with HTTP {exc.status or '?'} "
                f"({clip(exc.body, 200)}); the remainder of the window is "
                f"re-read next cycle"
            )
        if lost > 0:
            self.retention_clamps += 1
            message = (
                f"{self.name}: the requested window began {lost / 86_400:.1f} "
                f"days before the 400-day Admin Activity horizon, so that much "
                f"history does not exist in this API and was never collected — "
                f"it is a permanent gap, not a delayed read"
            )
            self.stats.last_error = message
            if payloads:
                payloads[0].setdefault("notes", []).append(message)
        return payloads

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        resources = self.resource_names()
        if resources:
            out["resource_names"] = len(resources)
        if self.resource_names_dropped:
            out["resource_names_dropped"] = (
                f"{self.resource_names_dropped} resource(s) exceeded the "
                f"{MAX_RESOURCE_NAMES}/request ceiling and were dropped — split "
                f"the configuration across instances"
            )
        if self.compact_filters:
            out["compact_filters"] = (
                f"{self.compact_filters} cycle(s) fell back to log_id() because "
                f"the indexed logName=... form exceeded {MAX_FILTER_CHARS} "
                f"characters — log_id() is not in the indexed-field list, so "
                f"these cycles are slower than they need to be"
            )
        if self.retention_clamps:
            out["retention_clamps"] = (
                f"{self.retention_clamps} window(s) clamped to the 400-day "
                f"Admin Activity horizon — Data Access is shorter (30 days by "
                f"default) and the shortfall is stated in probe()"
            )
        if self.windows_skipped:
            out["windows_skipped_below_horizon"] = (
                f"{self.windows_skipped} window(s) lay entirely before the "
                f"horizon and were not requested — a cursor that far behind is "
                f"skipped forward rather than walked one hour at a time through "
                f"data that is gone"
            )
        if self.split_fragments:
            out["split_fragments"] = (
                f"{self.split_fragments} LogEntry.split fragment(s) seen — "
                f"these are pieces of an entry larger than 256 KiB and must "
                f"be reassembled by the consumer or excluded from detection"
            )
        if self.non_audit_payloads:
            out["non_audit_payloads"] = (
                f"{self.non_audit_payloads} record(s) carried a non-AuditLog "
                f"protoPayload or a jsonPayload/textPayload — emitted under "
                f"gcp:non-audit-payload with substitute_for:api / "
                f"substitute_for:actor labels so the lake reflects what Cloud "
                f"Logging actually has"
            )
        if self.actor_substitutions:
            out["actor_substitutions"] = self.actor_substitutions
        if self.api_substitutions:
            out["api_substitutions"] = self.api_substitutions
        if self.permission_denials:
            out["permission_denials"] = (
                f"{self.permission_denials} authorizationInfo grant=false — "
                f"the request was made and was blocked, which is a different "
                f"fact from a successful denied operation"
            )
        if self.tier0_grants:
            out["tier0_role_grants"] = self.tier0_grants
        if self.public_principal_grants:
            out["public_principal_grants"] = self.public_principal_grants
        if self.impersonations:
            out["impersonations"] = self.impersonations
        if self.unparseable_times:
            out["unparseable_times"] = self.unparseable_times
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        """One ``LogEntry`` as a 6003 payload, or ``None`` if it has no time.

        ``timestamp`` is the canonical event time, and ``receiveTimestamp`` is
        the indexing-lag signal. ``insertId`` is the dedup input and becomes
        ``metadata_uid`` — GCP guarantees uniqueness within (project,
        timestamp, insertId), which is the join the correlate layer needs.
        """
        when = parse_iso8601(dig(record, "timestamp"))
        if when is None:
            # Stamped above as ``unparseable_times``; cannot build the event
            # without a time.
            return None
        proto = (
            record.get("protoPayload")
            if isinstance(record.get("protoPayload"), Mapping)
            else {}
        )
        is_audit = proto.get("@type") == AUDIT_LOG_TYPE

        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(ClassUid.API_ACTIVITY),
            # ``activity_id`` is set in :meth:`_api` from the verb table;
            # ``activity_name`` is set there too so a 99 never reaches the
            # hard validator unnamed.
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(record.get("insertId") or ""),
            "metadata_product_name": "Cloud Audit Logs",
            "metadata_product_vendor_name": "Google",
            "metadata_log_name": str(record.get("logName") or ""),
            "metadata_log_provider": "Google Cloud Logging",
            "metadata_version": "1.9.0",
            "cloud_provider": "Google Cloud",
            "raw": dict(record),
        }
        put(payload, "metadata_original_time", record.get("timestamp"))
        received = parse_iso8601(record.get("receiveTimestamp"))
        if received is not None:
            payload["metadata_logged_time"] = received
            if received - when > 60.0:
                stash(payload, "indexing_lag_seconds", round(received - when, 3))

        # The log type short name (``activity``, ``data_access``,
        # ``system_event``, ``policy``) drives the routing label and lives in
        # ``metadata_event_code`` because ``metadata_product_feature_name``
        # is illegal on 6003.
        log_id = _audit_log_short_name(record.get("logName"))
        if log_id:
            put(payload, "metadata_event_code", log_id)
            label(payload, f"gcp:audit:{log_id}")
            stash(payload, "audit_log_type", log_id)

        # Project id, then tenant id when the parent is an organization —
        # ``organizations/<id>`` is the tenant boundary; ``folders/<id>`` and
        # ``projects/<id>`` are below it.
        resource = (
            record.get("resource")
            if isinstance(record.get("resource"), Mapping)
            else {}
        )
        labels = (
            resource.get("labels") if isinstance(resource.get("labels"), Mapping) else {}
        )
        project = (
            str(labels.get("project_id") or "").strip()
            or _parent_from_log_name(record.get("logName"))
            or None
        )
        put(payload, "cloud_account_uid", project)
        tenant = (
            _tenant_from_log_name(record.get("logName"))
            if project and project.startswith("organizations/")
            else None
        )
        put(payload, "metadata_tenant_uid", tenant)

        # Cloud region — three preferred sources in order.
        region = (
            dig(resource, "location")
            or dig(labels, "location")
            or dig(labels, "region")
            or (dig(resource, "resourceLocation.currentLocations") or [None])[0]
            or _zone_to_region(dig(labels, "zone"))
        )
        put(payload, "cloud_region", region or None)
        if dig(labels, "zone"):
            stash(payload, "zone", dig(labels, "zone"))

        # Operation id → correlation join (a "click" in the console may emit
        # many AuditLogs with one operation id).
        operation = (
            record.get("operation") if isinstance(record.get("operation"), Mapping) else {}
        )
        if operation.get("id"):
            put(payload, "metadata_correlation_uid", str(operation["id"]))
            first = operation.get("first")
            last = operation.get("last")
            if first is True:
                label(payload, "gcp:operation-first")
            if last is True:
                label(payload, "gcp:operation-last")

        # Fragment detection: a non-empty ``split`` means this entry is a
        # piece of one larger than 256 KiB. Mapping it as complete silently
        # produces wrong data from a successful read.
        if isinstance(record.get("split"), Mapping):
            self.split_fragments += 1
            label(payload, "gcp:split-fragment")
            note(
                payload,
                f"{self.name}: this entry carries a split field, meaning it is "
                f"a fragment of one LogEntry larger than 256 KiB; a consumer "
                f"reading it as complete will see only a piece and must "
                f"reassemble or exclude the record",
            )

        # Labels, trace, errorGroups — stashed because they have no flat OCSF
        # home and are useful in unmapped form.
        trace = record.get("trace")
        if trace:
            stash(payload, "trace", str(trace))
        if isinstance(record.get("labels"), Mapping) and record["labels"]:
            stash(payload, "log_labels", dict(record["labels"]))
        if isinstance(record.get("errorGroups"), list) and record["errorGroups"]:
            stash(payload, "error_groups", list(record["errorGroups"]))

        self._severity(payload, record)
        if is_audit:
            self._audit_log(payload, proto, record, when)
        else:
            self._non_audit_payload(payload, proto, record)
        return payload

    def _severity(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """LogSeverity kept readable in ``unmapped`` without ever moving ``severity_id``.

        Same argument as Azure's ``level``: this is an audit log with no
        opinion, and only a source that is itself an alerting product gets to
        set severity from its own field.
        """
        severity = str(record.get("severity") or "").strip().upper()
        if not severity:
            return
        weight = _LOG_SEVERITY_WEIGHTS.get(severity)
        stash(
            payload,
            "log_severity",
            f"{severity} (weight={weight if weight is not None else '?'})",
        )
        label(payload, f"gcp:severity:{severity.lower()}")

    def _audit_log(
        self,
        payload: dict[str, Any],
        proto: Mapping[str, Any],
        record: Mapping[str, Any],
        when: float,
    ) -> None:
        """The fields specific to ``type.googleapis.com/google.cloud.audit.AuditLog``."""
        method = str(proto.get("methodName") or "").strip()
        service = str(proto.get("serviceName") or "").strip()
        verb, activity_name = _verb_from_method(method)
        # ``activity_id`` derived from verb; ``activity_name`` always set so
        # the hard validator never sees a 99 without a name.
        payload["activity_id"] = verb
        put(payload, "activity_name", activity_name)
        put(payload, "api_operation", method)
        put(payload, "api_service_name", service)
        stash(payload, "resource_name", proto.get("resourceName"))
        stash(payload, "resource_location", proto.get("resourceLocation"))

        # ``numResponseItems`` is a string int64 — coerced for arithmetic and
        # kept verbatim for fingerprinting.
        nri = proto.get("numResponseItems")
        if isinstance(nri, str) and nri.isdigit():
            stash(payload, "num_response_items", int(nri))

        self._status(payload, proto)
        self._actor(payload, proto)
        self._source(payload, proto)
        self._resources(payload, proto, record)
        self._authorization(payload, proto, method)
        self._message(payload, proto, method, service, when)

        technique = _technique_from_method(method, proto.get("request"))
        if technique:
            attack(payload, technique)

    def _status(self, payload: dict[str, Any], proto: Mapping[str, Any]) -> None:
        """``status_id``, with proto3-JSON success as the absent-or-``{}`` form.

        The ``AuditLog`` REST reference documents nothing about the success
        state; the rule is derivable only from the proto3 JSON mapping
        (default values are omitted). ``status.get("code", 0) != 0`` is the
        only correct failure test.
        """
        status = proto.get("status") if isinstance(proto.get("status"), Mapping) else {}
        code_raw = status.get("code", 0)
        try:
            code = int(code_raw)
        except (TypeError, ValueError):
            code = 0
        if code != 0:
            payload["status_id"] = int(Status.FAILURE)
            name = _RPC_CODES.get(code, f"CODE_{code}")
            put(payload, "status_code", name)
            stash(payload, "status_code_int", code)
            message = str(status.get("message") or "").strip()
            if message:
                put(payload, "status_detail", message, limit=TEXT_LIMIT)
        else:
            payload["status_id"] = int(Status.SUCCESS)

    def _actor(self, payload: dict[str, Any], proto: Mapping[str, Any]) -> None:
        """Who did it — user, service account, group, or the platform.

        ``principalEmail`` is the human-readable address (or ``@`` for groups,
        or a ``gserviceaccount.com`` address for service accounts);
        ``principalSubject`` is the stable identifier when the email is
        redacted (``allUsers`` lookups, cross-tenant access, certain data
        access logs). Reading principalEmail as the uid puts an opaque
        service-account string in the user field and every downstream join
        on identity silently matches nothing.
        """
        auth = (
            proto.get("authenticationInfo")
            if isinstance(proto.get("authenticationInfo"), Mapping)
            else {}
        )
        email = str(auth.get("principalEmail") or "").strip()
        subject = str(auth.get("principalSubject") or "").strip()
        sa_key = str(auth.get("serviceAccountKeyName") or "").strip()

        if email and _looks_like_email(email):
            put(payload, "actor_user_email", email)
            put(payload, "actor_user_domain", email.rpartition("@")[2])
        # The stable identifier wins for ``actor_user_uid`` — ``principalSubject``
        # carries the resource path (``...iam.gserviceaccount.com``) and is
        # present even when the email is redacted.
        if subject:
            put(payload, "actor_user_uid", subject)
        elif email:
            put(payload, "actor_user_uid", email)
        if email:
            put(payload, "actor_user_name", email)
        elif subject:
            put(payload, "actor_user_name", subject)

        if email.endswith(".gserviceaccount.com"):
            label(payload, "gcp:service-account")
            # A service-account principal is an address, not a person. Putting it
            # in ``actor_user_email`` lets a downstream join conflate it with a
            # human email join and silently match nothing. The uid still carries
            # the canonical form.
            payload["actor_user_email"] = None
            payload["actor_user_domain"] = None

        if sa_key:
            put(payload, "actor_user_credential_uid", sa_key)

        delegations = auth.get("serviceAccountDelegationInfo")
        if isinstance(delegations, list) and delegations:
            chain = [
                str(d.get("principalEmail") or d.get("principalSubject") or "")
                for d in delegations
                if isinstance(d, Mapping)
            ]
            chain = [c for c in chain if c]
            if chain:
                self.impersonations += 1
                stash(payload, "service_account_delegation_chain", chain)
                label(payload, "gcp:impersonation")
                note(
                    payload,
                    f"{self.name}: the service account that issued this call "
                    f"itself acted on behalf of {', '.join(chain)}, which is a "
                    f"delegation chain — every link is a separate credential "
                    f"with a separate audit trail",
                )

        authority = auth.get("authoritySelector")
        if authority:
            stash(payload, "authority_selector", authority)
        third_party = auth.get("thirdPartyPrincipal")
        if isinstance(third_party, Mapping):
            stash(payload, "third_party_principal", dict(third_party))

        if payload.get("actor_user_name") or payload.get("actor_user_uid"):
            return

        # No principal at all — usually ``system_event`` and certain
        # ``policy`` records. The platform is filled under a
        # ``substitute_for:actor`` label rather than letting the event fail
        # its own class contract.
        self.actor_substitutions += 1
        put(payload, "actor_invoked_by", "Google Cloud platform")
        label(payload, "substitute_for:actor")
        label(payload, "gcp:platform-action")
        note(
            payload,
            f"{self.name}: no principal is recorded for this AuditLog — typical "
            f"of system_event records and certain policy enforcements; the "
            f"platform fills the required actor under substitute_for:actor so "
            f"the event satisfies 6003, and the absence is stated rather than "
            f"implied",
        )

    def _source(self, payload: dict[str, Any], proto: Mapping[str, Any]) -> None:
        """Caller IP and user agent, with redacted values kept as labels."""
        meta = (
            proto.get("requestMetadata")
            if isinstance(proto.get("requestMetadata"), Mapping)
            else {}
        )
        ip = meta.get("callerIp")
        set_ip(payload, "src_endpoint_ip", ip)
        ua = meta.get("callerSuppliedUserAgent")
        if isinstance(ua, str) and ua:
            put(payload, "http_user_agent", clip(ua, 512))
        network = meta.get("callerNetwork")
        if network:
            stash(payload, "caller_network", str(network))

    def _resources(
        self,
        payload: dict[str, Any],
        proto: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        """``resourceName`` into the plural ``resources`` array — its only legal home.

        OCSF 6003 declares no singular ``resource_uid``/``resource_name``/
        ``resource_type``; those exist on other classes and were measured
        illegal here. The plural array via :func:`resource_ref` is the only
        conformant home. The ``type`` comes from the top-level
        ``LogEntry.resource.type`` (e.g. ``gce_instance``, ``k8s_container``,
        ``cloud_function``), which describes what the resource **is**, not
        from the AuditLog payload.
        """
        name = proto.get("resourceName")
        if not name:
            return
        entry_resource = (
            record.get("resource") if isinstance(record.get("resource"), Mapping) else {}
        )
        ref = resource_ref(
            uid=str(name),
            name=_leaf(name),
            type=str(entry_resource.get("type") or "") or None,
            labels=dict(entry_resource.get("labels") or {})
            if isinstance(entry_resource.get("labels"), Mapping)
            else None,
        )
        payload["resources"] = [ref]

    def _authorization(
        self,
        payload: dict[str, Any],
        proto: Mapping[str, Any],
        method: str,
    ) -> None:
        """The RBAC checks, with tier-0 and public-principal flags surfaced.

        ``authorizationInfo[]`` is one entry per permission the request was
        evaluated against; ``granted=false`` means the call was *blocked by
        IAM*, which is a different fact from a successful denied operation
        (which only the policy log can show). The bindings of a SetIamPolicy
        call are scanned for tier-0 roles and ``allUsers`` /
        ``allAuthenticatedUsers`` principals and flagged separately.
        """
        auths = proto.get("authorizationInfo")
        if isinstance(auths, list) and auths:
            compact: list[dict[str, Any]] = []
            for entry in auths:
                if not isinstance(entry, Mapping):
                    continue
                granted = bool(entry.get("granted"))
                compact.append(
                    {
                        "permission": str(entry.get("permission") or ""),
                        "granted": granted,
                        "resource": str(entry.get("resource") or ""),
                    }
                )
                if not granted:
                    self.permission_denials += 1
            stash(payload, "authorization_info", compact)
            if any(not c["granted"] for c in compact):
                label(payload, "gcp:permission-denied")
                note(
                    payload,
                    f"{self.name}: at least one authorizationInfo entry has "
                    f"granted=false, which means the request was *blocked by "
                    f"IAM* — the request happened and did not take effect, which "
                    f"is neither a success nor a service failure",
                )

        # SetIamPolicy bindings — scanned for tier-0 grants and public
        # principals. Both are deliberately privilege-escalating and emitted
        # as labels with counters rather than attached to a technique, so the
        # detect layer can write the rule it wants without inheriting this
        # connector's choice.
        if not method or not method.lower().endswith("setiampolicy"):
            return
        request = proto.get("request") if isinstance(proto.get("request"), Mapping) else {}
        policy = request.get("policy") if isinstance(request.get("policy"), Mapping) else {}
        bindings = policy.get("bindings") if isinstance(policy.get("bindings"), list) else []
        for binding in bindings:
            if not isinstance(binding, Mapping):
                continue
            role = str(binding.get("role") or "").strip()
            members = binding.get("members")
            if not isinstance(members, list):
                continue
            member_list = [str(m) for m in members if m]
            if role in _TIER0_ROLES:
                self.tier0_grants += 1
                label(payload, "gcp:tier0-grant")
                label(payload, f"gcp:tier0-grant:{role.replace('/', ':').replace('.', ':')}")
                note(
                    payload,
                    f"{self.name}: SetIamPolicy granted {role} to {member_list} "
                    f"— a role that can grant further roles, read every secret "
                    f"in scope or mint a key that bypasses RBAC, so this "
                    f"operation is a change of control over the project rather "
                    f"than a change of access within it",
                )
            if any(_strip_principal_prefix(m) in _PUBLIC_PRINCIPALS for m in member_list):
                self.public_principal_grants += 1
                label(payload, "gcp:public-principal")
                note(
                    payload,
                    f"{self.name}: SetIamPolicy granted {role} to a public "
                    f"principal in {member_list} — every grant to "
                    f"allUsers/allAuthenticatedUsers is a one-action exposure "
                    f"of whatever the role can do, and an unlabelled public "
                    f"grant is the most common accidental world-readable "
                    f"shape in this log",
                )

    def _non_audit_payload(
        self,
        payload: dict[str, Any],
        proto: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        """A ``protoPayload`` whose ``@type`` is not ``AuditLog``, or a non-proto payload.

        Suppressing these would silently lose every Cloud Logging record that
        is not an audit log, which is most of them — Data Access events
        (which carry their own payload type), VPC flow logs pushed to
        Logging, customer application logs. They are kept and labelled with
        ``gcp:non-audit-payload`` and a ``substitute_for:api`` label where
        there is no method name to fill ``api_operation``.
        """
        self.non_audit_payloads += 1
        label(payload, "gcp:non-audit-payload")
        kind = ""
        if proto:
            kind = str(proto.get("@type") or "protoPayload")
            put(payload, "api_operation", kind)
            put(payload, "api_service_name", str(proto.get("serviceName") or ""))
            stash(payload, "method_name", str(proto.get("methodName") or ""))
        else:
            kind = "jsonPayload" if record.get("jsonPayload") else (
                "textPayload" if record.get("textPayload") else "no-payload"
            )
            put(payload, "api_operation", kind)
        # 6003 requires an ``api``; the substitute fills the slot the way the
        # actorless Azure record fills ``actor`` — labelled, not invented.
        self.api_substitutions += 1
        label(payload, "substitute_for:api")
        note(
            payload,
            f"{self.name}: this entry is not a Cloud Audit Log record ({kind}); "
            f"emitted under gcp:non-audit-payload so the lake reflects what "
            f"Cloud Logging actually has — api_operation carries the payload "
            f"type rather than a method name, and the absence of an audit "
            f"technique is stated rather than implied",
        )

    def _message(
        self,
        payload: dict[str, Any],
        proto: Mapping[str, Any],
        method: str,
        service: str,
        when: float,
    ) -> None:
        """A one-line human summary, from the vendor's own text where there is any."""
        request = proto.get("request") if isinstance(proto.get("request"), Mapping) else {}
        response = proto.get("response") if isinstance(proto.get("response"), Mapping) else {}
        vendor = ""
        for doc in (request, response):
            if isinstance(doc, Mapping):
                for key in ("message", "name", "displayName"):
                    text = doc.get(key)
                    if isinstance(text, str) and text.strip():
                        vendor = text.strip()
                        break
            if vendor:
                break
        if vendor:
            put(payload, "message", vendor, limit=MESSAGE_LIMIT)
            return
        who = (
            payload.get("actor_user_name")
            or payload.get("actor_user_uid")
            or payload.get("actor_invoked_by")
            or "an unidentified principal"
        )
        target = _leaf(proto.get("resourceName")) or ""
        status = payload.get("status_code") or ""
        composed = f"{who} {method or service or 'acted'}"
        if target:
            composed += f" on {target}"
        if status:
            composed += f" — {status}"
        put(payload, "message", composed, limit=MESSAGE_LIMIT)


def _audit_log_short_name(log_name: Any) -> str:
    """``cloudaudit.googleapis.com%2Factivity`` → ``activity`` (URL-decoded).

    Used for the routing label and ``metadata_event_code``. Empty input
    returns empty, never None, so the label is always indexable.
    """
    text = str(log_name or "")
    if not text:
        return ""
    tail = text.rsplit("/", 1)[-1]
    if "%2F" in tail:
        tail = tail.replace("%2F", "/")
    if "/" not in tail:
        return tail
    return tail.rsplit("/", 1)[-1]


def _parent_from_log_name(log_name: Any) -> str:
    """``projects/my-project/logs/...`` → ``projects/my-project`` (or empty).

    Used as the cloud account uid fallback when ``resource.labels.project_id``
    is absent. Empty input returns empty.
    """
    text = str(log_name or "").strip()
    if not text:
        return ""
    if "/logs/" in text:
        return text.split("/logs/", 1)[0]
    return ""


def _tenant_from_log_name(log_name: Any) -> str:
    """``organizations/<id>/logs/...`` → ``organizations/<id>`` (or empty)."""
    text = str(log_name or "").strip()
    if not text.startswith("organizations/"):
        return ""
    return text.split("/logs/", 1)[0] if "/logs/" in text else ""


def gcp_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[GcpAuditConnector]:
    """The GCP connector set. One today; kept as a factory for symmetry with the others."""
    return [GcpAuditConnector(pipeline, config, **kwargs)]


__all__ = [
    "AUDIT_LOG_IDS",
    "AUDIT_LOG_TYPE",
    "DEFAULT_BUCKET_HISTORY_SECONDS",
    "ENTRIES_LIST_PATH",
    "LOGGING_READ_SCOPE",
    "MAX_FILTER_CHARS",
    "MAX_RESOURCE_NAMES",
    "REQUIRED_HISTORY_SECONDS",
    "RETENTION_MARGIN_SECONDS",
    "GcpAuditConnector",
    "gcp_connectors",
]

"""CrowdStrike Falcon — alerts (2004), incidents (2005) and host inventory (5001).

Three connectors against one API, because the three streams answer three different
questions and each feeds a different later phase:

``/alerts/*``
    Falcon's detections. One per behaviour the sensor decided was worth raising, with
    the process tree, the hashes, the account and — crucially — *what the sensor
    already did about it*. This is the detection feed.
``/incidents/*``
    Falcon's own clustering of those detections into an intrusion, with tactics,
    techniques, objectives, the hosts involved and a 0-100 ``fine_score``. Microsoft
    and CrowdStrike have both already solved "which alerts belong together" on their
    own telemetry; Phase 3's correlator is for joining *across* vendors, not for
    re-deriving what one vendor already published.
``/devices/*``
    The sensor fleet. Not a security event at all — it is the asset inventory, the
    containment state, and the answer to "can this platform actually act on that
    host". Response (Phase 5) is unimplementable without it.

── The two-step read, and why ``paginate`` cannot carry it ──

Every Falcon collection API is two calls: a ``/queries/`` endpoint that returns an
array of **id strings**, then an ``/entities/`` endpoint that takes those ids and
returns the records. :meth:`~ingest.connectors.base.Connector.paginate` reads pages
through :func:`~ingest.connectors.base.normalise_records`, which filters to mappings —
so a ``resources`` array of bare strings normalises to *zero records* and pagination
would report a healthy, permanently empty source. That is measured, not feared. The
id step therefore has its own pager, :meth:`CrowdStrikeConnector._query_ids`, which
duplicates the page cap and the cursor accounting deliberately and says so.

The second call's body key is **not the same across endpoints of the same API**:
alerts v2 wants ``composite_ids``, incidents and devices want ``ids``. Sending ``ids``
to the alerts entity endpoint returns 200 with an empty ``resources`` array and no
error — the shape of a quiet tenant. :data:`ALERT_ID_KEY` exists so that is a constant
with a name and a test rather than a string literal in one method.

── Truncation here is measured, not suspected ──

Falcon reports ``meta.pagination.total`` beside every page, and offset paging is hard-
capped: ``offset + limit`` above :data:`OFFSET_CEILING` is rejected with a 400. So when
a window matches more ids than paging can reach, this connector knows *exactly* how
many it missed. It sets :attr:`~ingest.connectors.base.Connector._truncation_reason`
rather than letting the base emit its generic "a full page with no next cursor"
sentence, which describes a mechanism that did not happen here.

── The five clouds ──

Falcon runs as five independent deployments (US-1, US-2, EU-1, US-GOV-1, US-GOV-2) with
no cross-cloud routing. A US-2 tenant's key presented to ``api.crowdstrike.com`` returns
**403 with an empty ``errors`` array** — nothing in the response says "wrong region", so
the natural conclusion is that the key or its scopes are wrong, and the operator spends
the afternoon re-issuing a key that was always correct. :meth:`CrowdStrikeConnector.probe`
names the configured host for exactly this reason.

The token endpoint returns **HTTP 201 Created**, not 200. Measured against
:meth:`~ingest.connectors.http.HttpResponse.ok`, which is ``200 <= status < 300`` — so
:class:`~ingest.connectors.auth.OAuth2ClientCredentials` accepts it unchanged. A client
that tested ``status == 200`` would never authenticate, and the error it produced would
be about the token body rather than about the status code.

── Three vendor fields that change what this platform is allowed to conclude ──

``process_id`` is not a PID.
    It is Falcon's process *graph* id — a 19-digit decimal that is unique across the
    fleet and forever. The operating-system pid is ``local_process_id``. A response
    action that killed ``process_id`` would target a pid that does not exist, and on a
    busy host a truncated one might exist and belong to something else. ``pid`` gets
    ``local_process_id``; the graph id is kept in ``unmapped`` where it is still the
    join key for Falcon's own process-tree API.

``status`` carries two different vocabularies.
    New-style alerts use a workflow state (``new``/``in_progress``/``closed``/
    ``reopened``). Legacy detections surfaced through the same endpoint use a
    *disposition* (``true_positive``/``false_positive``/``ignored``) in the same field.
    Reading the second as a workflow state maps a confirmed true positive to
    ``status_id`` Unknown and loses the verdict entirely; reading the first as a
    disposition invents one. :data:`_ALERT_STATUS` and :data:`_LEGACY_DISPOSITION` are
    two tables against one field, and the note on the event says which was used.

``source_vendors`` means the alert is not CrowdStrike's.
    Falcon's Next-Gen SIEM ingests third-party alerts and re-publishes them through this
    same endpoint. An alert with ``source_vendors: ["Microsoft"]`` is a Defender alert
    wearing a Falcon envelope — and if ``defender.py`` is also configured, this platform
    collects the same detection twice, from two connectors, with two different
    ``metadata_uid`` values that no deduplication will ever join. Counted, labelled
    ``third-party-relay``, and reported in the health line.

── What the sensor already did ──

``pattern_disposition_details`` is a flat object of ~24 booleans describing the action
Falcon took, and it is the single most operationally important field on the record. A
detection where ``quarantine_file`` and ``kill_process`` are both true is *finished* —
responding again is noise. A detection where ``blocking_unsupported_or_disabled`` is
true is one Falcon **wanted** to block and could not, which makes it the one case where
this platform's own response is the only response there will be.

:data:`_DISPOSITION_PRECEDENCE` maps the flags onto OCSF's ``disposition_id`` /
``action_id`` strongest-first. :data:`_RESPONSE_GATE_FLAGS` is the separate, smaller set
whose meaning is about *this platform's obligations* rather than about Falcon's action,
and every one of them produces a labelled note rather than a silent field.

── What is deliberately not mapped ──

``assigned_to_name`` / ``assigned_to_uid`` are the *analyst*, not the subject. They have
the shape of an account and would resolve into the entity graph as one — making the
customer's own responders look like actors in their incidents. They go to ``unmapped``.

``fine_score`` is banded to ``severity_id`` with the same 20/40/60/80 breaks as an
alert's ``severity``, which is what the Falcon console does. That is an inference from
the console's own rendering rather than a documented equivalence, and it is stated here
rather than implied by the code.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import (
    ClassUid,
    ConfidenceId,
    DispositionId,
    FindingStatus,
    IncidentStatus,
    ObservableTypeId,
    Severity,
    Status,
)
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, OAuth2ClientCredentials, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    normalise_records,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import Request
from ingest.connectors.mapping import (
    MESSAGE_LIMIT,
    as_bool,
    attack,
    evidence,
    finding_ref,
    label,
    note,
    prune,
    put,
    severity_from_bands,
    stash,
)

TOKEN_PATH = "/oauth2/token"

ALERT_QUERY_PATH = "/alerts/queries/alerts/v2"
ALERT_ENTITY_PATH = "/alerts/entities/alerts/v2"
INCIDENT_QUERY_PATH = "/incidents/queries/incidents/v1"
INCIDENT_ENTITY_PATH = "/incidents/entities/incidents/GET/v1"
BEHAVIOR_QUERY_PATH = "/incidents/queries/behaviors/v1"
BEHAVIOR_ENTITY_PATH = "/incidents/entities/behaviors/GET/v1"
DEVICE_QUERY_PATH = "/devices/queries/devices/v1"
DEVICE_ENTITY_PATH = "/devices/entities/devices/v2"

#: The alerts entity endpoint's body key. Every *other* Falcon entity endpoint uses
#: ``ids``; this one uses ``composite_ids`` because an alert's identity is
#: ``<cid>:ind:<aid>:<id>`` rather than a bare uuid. Sending ``ids`` here returns 200
#: with an empty ``resources`` array and no error, which is indistinguishable from a
#: tenant with no alerts — so this is a named constant with a test rather than a
#: literal in one method body.
ALERT_ID_KEY = "composite_ids"

#: ``offset + limit`` above this is a 400 on every classic Falcon ``/queries/``
#: endpoint. Reaching it is not an error — it is the point past which offset paging
#: cannot see, and the only honest response is to say how many ids were left behind.
#: (``/devices/queries/devices-scroll/v1`` exists for unbounded enumeration and is the
#: right tool for a full inventory sweep; it does not accept ``sort``, so it is wrong
#: for a time-ordered window and is left to a Phase 6 hunt.)
OFFSET_CEILING = 10_000

#: CrowdStrike's documented 0-100 severity, banded at its own published breaks. The
#: last band is open-ended: ``severity_from_bands`` returns the final entry for
#: anything at or above the last upper bound, so 100 must fall *inside* a band rather
#: than off the end of the table.
SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (20.0, Severity.INFORMATIONAL),
    (40.0, Severity.LOW),
    (60.0, Severity.MEDIUM),
    (80.0, Severity.HIGH),
    (101.0, Severity.CRITICAL),
)

#: ``confidence`` is 0-100 and CrowdStrike publishes **no** breaks for it — unlike
#: severity, where 20/40/60/80 are documented. These thresholds are this connector's
#: choice, recorded here so that a downstream reader comparing confidence across
#: vendors knows it is comparing one vendor's number to another connector's judgement.
#: The raw value survives in ``confidence_score``, which is the column to use for
#: anything quantitative.
CONFIDENCE_BANDS: tuple[tuple[float, ConfidenceId, str], ...] = (
    (50.0, ConfidenceId.LOW, "Low"),
    (80.0, ConfidenceId.MEDIUM, "Medium"),
    (101.0, ConfidenceId.HIGH, "High"),
)


def _confidence(value: Any) -> tuple[int, str, int] | None:
    """``(confidence_id, caption, score)`` from Falcon's 0-100 confidence."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    for upper, member, caption in CONFIDENCE_BANDS:
        if number < upper:
            return int(member), caption, int(number)
    last = CONFIDENCE_BANDS[-1]
    return int(last[1]), last[2], int(number)


# ── alert lifecycle: one field, two vocabularies ────────────────────────────

#: ``alert.status`` → 2004 ``status_id`` when the word is a *workflow state*.
#:
#: There is no OCSF *Reopened* member — ``FindingStatus`` is
#: ``{New, In Progress, Suppressed, Resolved, Archived, Deleted}`` — so a reopened
#: alert maps to New and carries a ``reopened`` label. New is right and Resolved is
#: wrong: the work is outstanding again. The label is what stops a first-response
#: metric counting it as a fresh detection.
_ALERT_STATUS: Mapping[str, FindingStatus] = {
    "new": FindingStatus.NEW,
    "inprogress": FindingStatus.IN_PROGRESS,
    "reopened": FindingStatus.NEW,
    "closed": FindingStatus.RESOLVED,
}

#: ``alert.status`` → 2004 ``verdict_id`` when the word is a *legacy disposition*.
#: These arrive on detections created before the Alerts API unified the two feeds, and
#: they occupy the same field as the workflow states above. A legacy disposition also
#: implies the alert is finished, so :meth:`CrowdStrikeAlertConnector._fill_status`
#: sets ``status_id`` to Resolved alongside the verdict.
#:
#: ``ignored`` is *Disregard* (3), not *False Positive* (1): an analyst who ignored a
#: detection did not say it was wrong, they said they were not going to act on it. The
#: difference is the whole content of a detection-tuning report.
_LEGACY_DISPOSITION: Mapping[str, int] = {
    "truepositive": 2,
    "falsepositive": 1,
    "ignored": 3,
}

#: ``incident.status`` (an integer, not a word) → 2005 ``status_id``. Falcon's ladder is
#: 20 New, 25 Reopened, 30 In Progress, 40 Closed.
#:
#: 2005's ``status_id`` table is **not** 2004's. It is
#: ``{New, In Progress, On Hold, Resolved, Closed}`` — no Suppressed, no Archived, no
#: Deleted — so a ``FindingStatus`` member written to a 2005 event silently means
#: something else (``FindingStatus.ARCHIVED`` = 5 reads as *Closed*,
#: ``FindingStatus.DELETED`` = 6 is not a member at all). ``bad_enum_values`` is the
#: sweep that catches it and the reason these are two tables rather than one.
_INCIDENT_STATUS: Mapping[int, IncidentStatus] = {
    20: IncidentStatus.NEW,
    25: IncidentStatus.NEW,
    30: IncidentStatus.IN_PROGRESS,
    40: IncidentStatus.CLOSED,
}


# ── what the sensor did ─────────────────────────────────────────────────────

#: ``pattern_disposition_details`` flag → ``(disposition_id, action_id, label)``,
#: **strongest first**. The first true flag wins, because the flags are not exclusive:
#: a quarantined machine whose offending process was also killed sets both, and the
#: containment is the fact that decides whether any further response is needed.
#:
#: ``action_id`` is OCSF's four-value ``{Allowed, Denied, Observed, Modified}``, which
#: is coarser than ``disposition_id`` on purpose — it is the field a rule can key on
#: without knowing this vendor's vocabulary.
_DISPOSITION_PRECEDENCE: tuple[tuple[str, DispositionId, int, str], ...] = (
    ("quarantine_machine", DispositionId.ISOLATED, 2, "host-contained-by-vendor"),
    ("quarantine_file", DispositionId.QUARANTINED, 2, "file-quarantined-by-vendor"),
    ("kill_process", DispositionId.BLOCKED, 2, "process-killed-by-vendor"),
    ("kill_subprocess", DispositionId.BLOCKED, 2, "process-killed-by-vendor"),
    ("kill_parent", DispositionId.BLOCKED, 2, "process-killed-by-vendor"),
    ("process_blocked", DispositionId.BLOCKED, 2, "blocked-by-vendor"),
    ("operation_blocked", DispositionId.BLOCKED, 2, "blocked-by-vendor"),
    ("fs_operation_blocked", DispositionId.BLOCKED, 2, "blocked-by-vendor"),
    ("registry_operation_blocked", DispositionId.BLOCKED, 2, "blocked-by-vendor"),
    ("bootup_blocked", DispositionId.BLOCKED, 2, "blocked-by-vendor"),
    ("suspend_process", DispositionId.CUSTOM_ACTION, 4, "process-suspended-by-vendor"),
    ("suspend_parent", DispositionId.CUSTOM_ACTION, 4, "process-suspended-by-vendor"),
    (
        "handle_operation_downgraded",
        DispositionId.CUSTOM_ACTION,
        4,
        "handle-downgraded-by-vendor",
    ),
    ("detect", DispositionId.DETECTED, 3, ""),
    ("sensor_only", DispositionId.DETECTED, 3, "sensor-only-mode"),
)

#: Flags whose meaning is about **this platform's obligations**, not about what Falcon
#: did. Each produces a label and a sentence on the event, because every one of them
#: changes whether a response is redundant, forbidden, or the only one there will be.
#:
#: These are read *in addition to* :data:`_DISPOSITION_PRECEDENCE`, not instead of it:
#: ``blocking_unsupported_or_disabled`` sits beside ``detect``, and the disposition says
#: "Falcon detected it" while this says "and could not stop it".
_RESPONSE_GATE_FLAGS: Mapping[str, tuple[str, str]] = {
    "blocking_unsupported_or_disabled": (
        "vendor-could-not-block",
        "Falcon detected this and could not block it — the sensor's prevention is "
        "unsupported on this platform or disabled by policy, so this platform's own "
        "response is the only response there will be",
    ),
    "policy_disabled": (
        "prevention-policy-disabled",
        "the prevention policy that would have blocked this is disabled on this host, "
        "which is a fleet-configuration finding in its own right and not a property of "
        "this one detection",
    ),
    "critical_process_disabled": (
        "critical-process-protection-off",
        "critical-process protection is disabled on this host, so a kill action here "
        "can take the host down rather than the threat",
    ),
    "response_action_already_applied": (
        "vendor-already-responded",
        "Falcon has already applied a response action for this detection — acting "
        "again duplicates it and, for containment, can collide with an in-flight "
        "vendor action",
    ),
    "response_action_triggered": (
        "vendor-response-in-flight",
        "a Falcon response action was triggered by this detection and may still be "
        "running; the two systems are not coordinated",
    ),
    "rooting": (
        "rooting-detected",
        "the sensor observed rooting/jailbreak-class activity, which invalidates every "
        "other integrity signal this host reports",
    ),
    "inddet_mask": (
        "informational-detection",
        "Falcon marks this an informational (indicator-only) detection rather than a "
        "prevented or blocked one",
    ),
}


# ── vendor vocabularies ─────────────────────────────────────────────────────

#: ``alert.product`` → ``(product name, label)``. The product decides what the record
#: even *is*: an ``idp`` alert is an identity event with no endpoint, an ``ngsiem`` or
#: ``thirdparty`` alert is another vendor's detection relayed through Falcon, and an
#: ``overwatch`` alert was raised by a human threat hunter and is worth more than any
#: automated verdict on this feed.
_PRODUCT: Mapping[str, tuple[str, str]] = {
    "epp": ("Falcon Endpoint Protection", ""),
    "idp": ("Falcon Identity Protection", "identity-detection"),
    "mobile": ("Falcon for Mobile", "mobile-detection"),
    "xdr": ("Falcon XDR", "correlated"),
    "ngsiem": ("Falcon Next-Gen SIEM", "third-party-relay"),
    "overwatch": ("Falcon OverWatch", "human-analyst"),
    "thirdparty": ("third-party via Falcon", "third-party-relay"),
    "cwpp": ("Falcon Cloud Workload Protection", "cloud-workload"),
    "datascanner": ("Falcon Data Protection", "data-protection"),
    "firewall-management": ("Falcon Firewall Management", ""),
}

#: Products whose alerts did not originate from a CrowdStrike sensor. See the module
#: docstring — these double-count with whichever connector reads the original source.
RELAY_PRODUCTS = frozenset({"ngsiem", "thirdparty"})

#: ``alert.objective`` → label. Falcon's objectives are a four-step intrusion arc and
#: are coarser than an ATT&CK tactic; they are labels rather than tactics for the same
#: reason Defender's non-tactic categories are.
_OBJECTIVE_LABEL: Mapping[str, str] = {
    "falcondetectionmethod": "vendor-detection-method",
    "gainaccess": "objective-gain-access",
    "keepaccess": "objective-keep-access",
    "followthrough": "objective-follow-through",
    "reconnaissance": "objective-reconnaissance",
}

#: ``alert.scenario`` → *additional* semantic labels for the handful of scenarios the
#: respond layer keys on. The vocabulary is open-ended — Falcon adds scenarios without
#: notice — so every scenario also becomes a ``scenario:<raw>`` label and a
#: ``finding_types`` entry regardless of whether it appears here. This table adds
#: meaning; it does not gate whether the scenario is recorded.
_SCENARIO_LABEL: Mapping[str, tuple[str, ...]] = {
    "ransomware": ("ransomware",),
    "known_malware": ("malware",),
    "malware": ("malware",),
    "suspicious_activity": ("suspicious-activity",),
    "credential_theft": ("credential-theft",),
    "credential_access": ("credential-theft",),
    "attempted_dumping_of_lsass_memory": ("credential-theft", "lsass-access"),
    "lateral_movement": ("lateral-movement",),
    "post_exploitation": ("post-exploitation",),
    "intel_detection": ("intel-match",),
    "custom_intelligence": ("intel-match",),
    "adware_or_pup": ("pua",),
    "web_exploit": ("exploit",),
    "exploit_mitigation": ("exploit",),
    "data_exfiltration": ("exfiltration",),
    "container_escape": ("container-escape",),
    "unauthorized_container_runtime": ("container-escape",),
}


# ── device tables (object-level enums, unvalidatable by the sweeps) ─────────
#
# `device.type_id` and `device.os.type_id` are OCSF *object*-level enums and the
# vendored index carries object-level enums nowhere — `enum_members(5001,
# "device_type_id")` returns nothing, so a wrong value here passes `bad_enum_values`,
# `misplaced_fields` and every other sweep in `core/schema/ocsf.py`. Same gap as
# `user.type_id` and `process.integrity_id`; see the note on `_DETECTION_SOURCE` in
# `defender.py`. Both tables below are hand-verified against the v1.9.0 dictionary,
# restricted to the members this connector can actually produce, and pinned by test.

#: ``product_type_desc`` → OCSF ``device.type_id``. *Domain Controller* maps to Server
#: and additionally earns a label, because a domain controller is not merely a server:
#: it is the one host class where an automated isolate is an outage of the entire
#: authentication plane. Phase 5's blast-radius calculation reads the label, not the
#: type id, because the type id cannot express it.
_PRODUCT_TYPE: Mapping[str, tuple[int, str]] = {
    "workstation": (2, ""),          # Desktop
    "server": (1, ""),               # Server
    "domain controller": (1, "domain-controller"),
    "domaincontroller": (1, "domain-controller"),
}

#: ``chassis_type_desc`` → OCSF ``device.type_id``, applied only to refine a
#: *Workstation*. A server whose chassis says "Rack Mount Chassis" is still a server;
#: a workstation whose chassis says "Laptop" is a laptop, and that distinction is what
#: makes "this host left the office network" a sensible statement.
_CHASSIS_TYPE: Mapping[str, int] = {
    "laptop": 3,
    "notebook": 3,
    "portable": 3,
    "sub notebook": 3,
    "desktop": 2,
    "low profile desktop": 2,
    "mini tower": 2,
    "tower": 2,
    "all in one": 2,
    "virtual machine": 6,
    "vm": 6,
}

#: ``platform_name`` → OCSF ``device.os.type_id``. ChromeOS and the container
#: platforms have **no** member in OCSF's ``os.type_id``, so they are left unset with a
#: note rather than mapped to 0 — 0 is *Unknown*, which asserts that the platform is
#: unknown when in fact it is known and unrepresentable, and that is the difference
#: between a gap a coverage report can find and one it cannot.
_PLATFORM_OS: Mapping[str, tuple[int, str]] = {
    "windows": (100, "Windows"),
    "mac": (300, "macOS"),
    "macos": (300, "macOS"),
    "linux": (200, "Linux"),
    "android": (201, "Android"),
    "ios": (301, "iOS"),
}

#: ``device.status`` → containment state. Falcon's network containment has three
#: states beyond normal and every one of them means *do not isolate this host again*:
#: the pending states are an isolate already in flight.
_DEVICE_STATUS: Mapping[str, tuple[DispositionId, str, str]] = {
    "contained": (
        DispositionId.ISOLATED,
        "host-contained",
        "this host is already network-contained by Falcon — a second isolate is a "
        "no-op at best, and the containment is a fact the blast-radius calculation "
        "must know before it proposes anything",
    ),
    "containment_pending": (
        DispositionId.ISOLATED,
        "host-containment-pending",
        "a Falcon network containment is in flight on this host; issuing another "
        "response now races it",
    ),
    "lift_containment_pending": (
        DispositionId.ISOLATED,
        "host-containment-lifting",
        "a Falcon containment is being lifted on this host — it is about to be back "
        "on the network, which is the moment a re-containment decision is due",
    ),
}

#: ``service_provider`` → OCSF ``cloud.provider``. Falcon reports the provider of a
#: cloud-hosted sensor; an on-premises host has none, and this is the only source of
#: ``cloud_provider`` on these three streams — CrowdStrike is not itself a cloud log.
_CLOUD_PROVIDER: Mapping[str, str] = {
    "aws_ec2": "AWS",
    "aws_ec2_v2": "AWS",
    "aws": "AWS",
    "azure": "Azure",
    "azure_arm": "Azure",
    "gcp": "Google Cloud",
    "google_cloud": "Google Cloud",
}

#: Behaviour ids fetched per incident-poll cycle. The behaviours lookup is what fills
#: 2005's required ``finding_info_list``, and it is a second and third API call per
#: cycle — so it is bounded, and the bound is *reported* (see
#: :meth:`CrowdStrikeIncidentConnector.stats_extra`) rather than silently applied. A
#: silent cap would render an incident with three of its nine member detections and
#: nothing downstream could tell that from an incident with three detections.
BEHAVIOR_LOOKUP_MAX = 500

#: Incident ids per behaviours FQL query. ``incident_id:['a','b',…]`` is a URL query
#: parameter, so the list length is bounded by URL length rather than by a documented
#: limit; 25 keeps the request well inside every proxy's ceiling.
BEHAVIOR_QUERY_CHUNK = 25


class CrowdStrikeConnector(Connector):
    """Shared Falcon plumbing: the token, the host, the two-step read."""

    def client_id(self) -> Credential:
        return self.config.connectors.crowdstrike_client_id

    def client_secret(self) -> Credential:
        return self.config.connectors.crowdstrike_client_secret

    def credentials(self) -> tuple[Credential, ...]:
        return (self.client_id(), self.client_secret())

    def base_url(self) -> str:
        return self.config.endpoints.crowdstrike.rstrip("/")

    def authorizer(self) -> Authorizer:
        return OAuth2ClientCredentials(
            self.client(),
            token_url=f"{self.base_url()}{TOKEN_PATH}",
            client_id=self.client_id(),
            client_secret=self.client_secret(),
            # Deliberately empty. Falcon's token endpoint takes no `scope` — the
            # granted API scopes are a property of the API client itself, set in the
            # Falcon console when the key is issued. `OAuth2ClientCredentials` omits
            # the parameter entirely when it is empty rather than sending `scope=`,
            # which Falcon rejects as a malformed request.
            scope="",
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Responses that were HTTP 200 and carried a populated ``errors`` array.
        #: Falcon reports partial failures this way — some ids resolved, some did not —
        #: and the successful half looks exactly like a complete answer.
        self.partial_errors = 0
        #: Ids the window matched that offset paging could not reach.
        self.unreachable_ids = 0

    def probe(self) -> Availability:
        """Configured, plus the regional host the operator will otherwise debug blind."""
        base = super().probe()
        if not base.available:
            return base
        host = self.base_url()
        extra = (
            f"reading Falcon at {host} — a key issued in a different Falcon cloud "
            "(US-1, US-2, EU-1, US-GOV-1, US-GOV-2) returns 403 with an empty errors "
            "array, which names neither the region nor the scope, so verify this "
            "hostname against the one shown on the API client in the Falcon console "
            "before re-issuing a key"
        )
        return available(
            limitation=f"{base.limitation}; {extra}" if base.limitation else extra
        )

    # ── the two-step read ──────────────────────────────────────────────────

    def _check_errors(self, body: Any, where: str) -> None:
        """Falcon's 200-with-errors partial failure, which otherwise reads as success."""
        if not isinstance(body, Mapping):
            return
        errors = body.get("errors")
        if not isinstance(errors, list) or not errors:
            return
        self.partial_errors += 1
        detail = "; ".join(
            f"{e.get('code', '?')} {str(e.get('message') or '').strip()}".strip()
            for e in errors[:3]
            if isinstance(e, Mapping)
        )
        self.stats.last_error = (
            f"{self.name}: {where} returned HTTP 200 with {len(errors)} error(s) in the "
            f"body — a partial failure, so the records that did come back are an "
            f"incomplete answer rather than the whole window: {detail}"
        )

    async def _query_ids(
        self,
        path: str,
        *,
        label_: str,
        filter_expr: str = "",
        sort: str = "",
        limit: int = 0,
        max_pages: int | None = None,
        extra_params: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """Page a Falcon ``/queries/`` endpoint and return its id strings.

        Not :meth:`~ingest.connectors.base.Connector.paginate`, and the reason is
        measured rather than stylistic: ``resources`` on these endpoints is an array of
        **strings**, and ``normalise_records`` keeps only mappings — so ``paginate``
        yields zero records for a full page and the connector reports itself healthy and
        permanently empty. Everything ``paginate`` provides is reproduced here (page
        accounting, the page ceiling, truncation reporting) because the alternative is a
        second normaliser in the base that exists for one vendor.

        Two cursors, because Falcon has two. ``meta.pagination.after`` is an opaque
        deep-pagination token offered by the newer endpoints (alerts v2) and is
        preferred wherever present; ``offset`` is the classic integer and is bounded by
        :data:`OFFSET_CEILING`. Reaching that bound with ids still outstanding is
        truncation this connector can *measure*, so it sets its own
        ``_truncation_reason`` rather than inheriting the base's heuristic sentence,
        which describes a mechanism that did not occur here.
        """
        page_limit = limit or self.spec.page_size
        cap = max_pages or self.spec.max_pages_per_cycle
        ids: list[str] = []
        offset = 0
        after = ""
        total: int | None = None

        for page in range(cap):
            params: dict[str, Any] = {"limit": page_limit}
            if filter_expr:
                params["filter"] = filter_expr
            if sort:
                params["sort"] = sort
            if after:
                params["after"] = after
            elif offset:
                params["offset"] = offset
            if extra_params:
                params.update(extra_params)

            response = await self.client().send(
                Request(
                    "GET",
                    f"{self.base_url()}{path}",
                    label=label_,
                    params=params,
                    headers={"Accept": "application/json"},
                )
            )
            self.pages += 1
            body = response.json()
            self._check_errors(body, label_)

            resources = body.get("resources") if isinstance(body, Mapping) else None
            batch = [str(r) for r in resources if r] if isinstance(resources, list) else []
            ids.extend(batch)

            pagination = body.get("meta", {}) if isinstance(body, Mapping) else {}
            pagination = (
                pagination.get("pagination", {}) if isinstance(pagination, Mapping) else {}
            )
            if isinstance(pagination, Mapping):
                raw_total = pagination.get("total")
                if isinstance(raw_total, (int, float)):
                    total = int(raw_total)
                next_after = pagination.get("after")
                after = str(next_after) if next_after else ""

            if not batch or len(batch) < page_limit:
                break
            if total is not None and len(ids) >= total:
                break
            if not after:
                offset += len(batch)
                if offset + page_limit > OFFSET_CEILING:
                    self._report_unreachable(
                        label_, seen=len(ids), total=total, reason="offset"
                    )
                    break
            if page + 1 >= cap:
                self.page_cap_hits += 1
                self._report_unreachable(
                    label_, seen=len(ids), total=total, reason="pages"
                )
        return ids

    def _report_unreachable(
        self, where: str, *, seen: int, total: int | None, reason: str
    ) -> None:
        """Say exactly how many ids were left behind, and why."""
        missing = max(0, total - seen) if total is not None else 0
        self.unreachable_ids += missing
        self._page_truncation_suspected = True
        limit_text = (
            f"the {OFFSET_CEILING}-record offset ceiling"
            if reason == "offset"
            else f"the {self.spec.max_pages_per_cycle}-page ceiling"
        )
        if total is None:
            self._truncation_reason = (
                f"{where} stopped at {limit_text} after {seen} ids and Falcon reported "
                "no total, so the size of the shortfall is unknown"
            )
        else:
            self._truncation_reason = (
                f"{where} matched {total} records and this cycle could reach {seen} of "
                f"them before {limit_text} — {missing} were not read this window and "
                "are not merely late"
            )

    async def _fetch_entities(
        self,
        path: str,
        ids: Sequence[str],
        *,
        label_: str,
        key: str = "ids",
        chunk: int = 500,
    ) -> list[dict[str, Any]]:
        """POST id batches to a Falcon ``/entities/`` endpoint and return the records.

        ``key`` is a parameter because it is **not constant across this API**: alerts v2
        takes ``composite_ids`` and everything else takes ``ids``, and the wrong one is
        answered with 200 and an empty array. See :data:`ALERT_ID_KEY`.

        POST rather than GET-with-repeated-``ids``. Both forms exist for the devices
        endpoint; the GET form puts every id in the URL, and a 500-id batch of 32-char
        agent ids is a ~17 KB request line that intermediate proxies truncate or reject
        with 414. The POST body has no such ceiling and the two return the same records.
        """
        out: list[dict[str, Any]] = []
        for start in range(0, len(ids), chunk):
            batch = list(ids[start : start + chunk])
            if not batch:
                continue
            response = await self.client().send(
                Request(
                    "POST",
                    f"{self.base_url()}{path}",
                    label=label_,
                    json_body={key: batch},
                    headers={"Accept": "application/json"},
                    # Idempotent despite the verb: Falcon uses POST here purely to move
                    # a long id list out of the URL, and re-sending it re-reads the same
                    # records. Marking it so is what lets the retry policy retry it.
                    idempotent=True,
                )
            )
            self.pages += 1
            body = response.json()
            self._check_errors(body, label_)
            records = normalise_records(body, "resources")
            if len(records) < len(batch):
                note_text = (
                    f"{self.name}: {label_} asked for {len(batch)} records and Falcon "
                    f"returned {len(records)} — the difference is ids that resolved to "
                    "nothing, usually because the record was deleted between the query "
                    "and this read"
                )
                self.stats.last_error = note_text
            out.extend(records)
        return out

    # ── shared mapping ─────────────────────────────────────────────────────

    def _base_payload(
        self, *, uid: str, time_value: Any, log_name: str, record: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "time": parse_iso8601(time_value),
            "metadata_uid": uid,
            "metadata_product_name": "CrowdStrike Falcon",
            "metadata_product_vendor_name": "CrowdStrike",
            "metadata_log_name": log_name,
            "metadata_version": "1.9.0",
            "severity_id": int(Severity.INFORMATIONAL),
            "raw": dict(record),
        }
        put(payload, "metadata_tenant_uid", record.get("cid"))
        return payload

    def _fill_device(
        self, payload: dict[str, Any], device: Any, *, agent_id: Any = None
    ) -> None:
        """Falcon's device object → ``device_*``, shared by all three streams.

        The same object appears nested inside an alert, nested inside an incident's
        ``hosts`` array, and as the whole record on the hosts stream, so it is mapped
        once. Every ``device_*`` column used here is legal on 2004, 2005 *and* 5001 —
        measured, because the three classes agree on ``device`` and disagree on almost
        everything else.
        """
        if not isinstance(device, Mapping):
            put(payload, "device_uid", agent_id)
            return
        put(payload, "device_uid", device.get("device_id") or agent_id)
        put(payload, "device_hostname", device.get("hostname"))
        set_ip(payload, "device_ip", device.get("local_ip"), note="local_ip_raw")
        put(payload, "device_mac", device.get("mac_address"))
        put(payload, "device_domain", device.get("machine_domain"))
        put(payload, "device_os_version", device.get("os_version"))

        platform = str(device.get("platform_name") or "").strip().lower()
        mapped_os = _PLATFORM_OS.get(platform)
        if mapped_os:
            payload["device_os_type_id"], payload["device_os_name"] = mapped_os
        elif platform:
            stash(payload, "platform_name", device.get("platform_name"))
            note(
                payload,
                f"{self.name}: platform {device.get('platform_name')!r} has no member "
                "in OCSF's os.type_id, so it is left unset rather than mapped to 0 — 0 "
                "is Unknown, and this platform is known and unrepresentable",
            )

        product_type = str(device.get("product_type_desc") or "").strip().lower()
        mapped_type = _PRODUCT_TYPE.get(product_type)
        if mapped_type:
            payload["device_type_id"] = mapped_type[0]
            if mapped_type[1]:
                label(payload, mapped_type[1], "crown-jewel")
                note(
                    payload,
                    f"{self.name}: this host is a domain controller — an automated "
                    "isolate here removes the authentication plane, not a threat, so "
                    "the safety envelope must treat it as approval-gated regardless of "
                    "the finding's severity",
                )
            # Chassis only refines a workstation; a rack-mounted server is still a
            # server, and letting the chassis win would reclassify every one of them.
            if mapped_type[0] == 2:
                chassis = str(device.get("chassis_type_desc") or "").strip().lower()
                if chassis in _CHASSIS_TYPE:
                    payload["device_type_id"] = _CHASSIS_TYPE[chassis]
        elif product_type:
            stash(payload, "product_type_desc", device.get("product_type_desc"))

        provider = str(device.get("service_provider") or "").strip().lower()
        if provider:
            put(payload, "cloud_provider", _CLOUD_PROVIDER.get(provider, provider))
            put(payload, "device_instance_uid", device.get("instance_id"))
            put(payload, "cloud_region", device.get("zone_group"))
            put(payload, "device_region", device.get("zone_group"))
            put(payload, "cloud_account_uid", device.get("service_provider_account_id"))

        # Kept out of the mapped columns on purpose. `groups`, `ou` and `site_name` are
        # the customer's own organisational scoping — the answer to "whose host is
        # this", which is an asset-criticality input for Phase 3 rather than a property
        # OCSF's device object declares.
        stash(payload, "falcon_groups", device.get("groups"))
        stash(payload, "falcon_ou", device.get("ou"))
        stash(payload, "falcon_site_name", device.get("site_name"))
        stash(payload, "sensor_version", device.get("agent_version"))
        stash(payload, "serial_number", device.get("serial_number"))
        # The external address is what the host looks like from the internet, which is
        # not `device.ip` (the interface address) and must not overwrite it — conflating
        # them is how a NAT'd fleet appears to share one address. There is no legal
        # column for it on any of these three classes (2004, 2005 and 5001 all declare
        # no top-level `src_endpoint` — measured), so `unmapped` is the honest home
        # rather than the second-best one.
        stash(payload, "external_ip", device.get("external_ip"))
        tags = device.get("tags")
        if isinstance(tags, list) and tags:
            label(payload, *[f"falcon-tag:{t}" for t in tags if t])


class CrowdStrikeAlertConnector(CrowdStrikeConnector):
    """Falcon alerts → 2004 Detection Finding."""

    name = "crowdstrike_alerts"
    description = "CrowdStrike Falcon alerts, with the sensor's own prevention outcome"
    detects = (
        "everything a Falcon sensor raises on an endpoint — malware, LOLBin abuse, "
        "credential dumping, ransomware behaviour, lateral movement — together with "
        "what the sensor already did about it, which is the difference between a "
        "detection that still needs a response and one that is finished"
    )
    spec = ConnectorSpec(
        # The alerts query endpoint's practical ceiling, and also the entity endpoint's
        # documented maximum ids per request — so one page of ids is exactly one entity
        # call, which is why `_fetch_entities` is not asked to chunk on this stream.
        page_size=1_000,
        # Falcon allows 6000 requests/minute per API client across all endpoints. Five
        # per second is a fraction of that and leaves the customer's own automation
        # room, which matters because the quota is per *client*, not per integration.
        rate_per_second=5.0,
        burst=10,
        # `updated_timestamp` is set when Falcon writes the change and is queryable
        # within seconds. This is clock-skew allowance, not an index build.
        indexing_lag_seconds=60.0,
        # Wide, and cheap for the same reason as Defender's: `metadata_uid` is the
        # composite id, so a re-read is a state update rather than a duplicate.
        overlap_seconds=900.0,
        max_window_seconds=86_400.0,
        docs_url="https://falcon.crowdstrike.com/documentation/page/f0e5b0ee/alerts-apis",
        required_grants=(
            "Alerts: Read",
            "Hosts: Read — the alert carries a nested device object, but only the "
            "fields Falcon chose to denormalise onto it",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Composite ids already delivered, so a re-read is Update rather than Create.
        #: In memory, so a restart downgrades an update to a create — wrong in the
        #: harmless direction, and the alternative is a store lookup per alert on a path
        #: that must not depend on the store being up.
        self._seen_alerts: set[str] = set()
        #: Alerts relayed from another vendor's product through Falcon NG-SIEM.
        self.relayed_alerts = 0
        #: Alerts Falcon detected but could not block.
        self.unblocked_alerts = 0
        #: Alerts whose ``status`` carried a legacy disposition rather than a state.
        self.legacy_disposition_alerts = 0

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, _end = window.iso()
        # `>` with no upper bound, for the same reason `defender.py` filters on
        # `lastUpdateTime`: a Falcon alert mutates for hours after creation as the
        # sensor attaches behaviours, an aggregate id and a disposition. With an upper
        # bound, an update raises `updated_timestamp` past a window that has already
        # closed and the alert lands in no window at all. FQL string literals are
        # single-quoted — the exact opposite of Defender's OData `$filter`, which
        # rejects quotes on the same ISO string.
        ids = await self._query_ids(
            ALERT_QUERY_PATH,
            label_=f"{self.name}.query",
            filter_expr=f"updated_timestamp:>'{start}'",
            sort="updated_timestamp.asc",
        )
        if not ids:
            return []
        records = await self._fetch_entities(
            ALERT_ENTITY_PATH,
            ids,
            label_=f"{self.name}.entities",
            key=ALERT_ID_KEY,
            chunk=self.spec.page_size,
        )
        out: list[dict[str, Any]] = []
        for record in records:
            self.note_record_time(parse_iso8601(record.get("updated_timestamp")))
            payload = self.map_record(record)
            if payload is not None:
                out.append(payload)
        return out

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        alert_id = str(record.get("composite_id") or record.get("id") or "")
        payload = self._base_payload(
            uid=alert_id,
            time_value=record.get("timestamp") or record.get("created_timestamp"),
            log_name="alerts",
            record=record,
        )
        payload["class_uid"] = int(ClassUid.DETECTION_FINDING)
        # A detection product raised this. Set here and on nothing from the hosts
        # connector, because an inventory row is an observation and counting it as an
        # alert is how an alert-volume metric reports a busy month whenever the fleet
        # rebooted.
        payload["is_alert"] = True

        self._fill_status(payload, record, alert_id)
        self._fill_severity(payload, record)
        self._fill_finding(payload, record)
        self._fill_product(payload, record)
        self._fill_disposition(payload, record)
        self._fill_device(
            payload, record.get("device"), agent_id=record.get("agent_id")
        )
        self._fill_process(payload, record)
        self._fill_actor_user(payload, record)
        self._fill_attack(payload, record)
        self._fill_evidence(payload, record)
        self._fill_correlation(payload, record)
        return payload

    def _fill_status(
        self, payload: dict[str, Any], record: Mapping[str, Any], alert_id: str
    ) -> None:
        """One field, two vocabularies — see the module docstring."""
        raw = str(record.get("status") or "").strip()
        key = raw.lower().replace(" ", "").replace("_", "")
        status = _ALERT_STATUS.get(key)
        verdict = _LEGACY_DISPOSITION.get(key)

        if status is not None:
            payload["status_id"] = int(status)
            if key == "reopened":
                label(payload, "reopened")
        elif verdict is not None:
            self.legacy_disposition_alerts += 1
            # A legacy disposition is terminal: an analyst reached it and the detection
            # is closed. Both halves are set, and the note says which table was used —
            # without it, a downstream reader sees a Resolved alert with a verdict and
            # cannot tell whether the verdict came from Falcon or from this platform.
            payload["status_id"] = int(FindingStatus.RESOLVED)
            payload["verdict_id"] = verdict
            label(payload, "legacy-detection")
            note(
                payload,
                f"{self.name}: this alert's status field carried the legacy disposition "
                f"{raw!r} rather than a workflow state, so status_id is Resolved and "
                "verdict_id is CrowdStrike's own disposition — not a verdict this "
                "platform reached",
            )
        else:
            payload["status_id"] = int(FindingStatus.UNKNOWN)
            if raw:
                put(payload, "status_code", raw)
                note(
                    payload,
                    f"{self.name}: alert status {raw!r} is in neither this connector's "
                    "lifecycle table nor its legacy-disposition table, so status_id is "
                    "Unknown rather than a guess — the vendor word is in status_code",
                )

        closed = payload.get("status_id") in (
            int(FindingStatus.RESOLVED),
            int(FindingStatus.SUPPRESSED),
        )
        if closed:
            payload["activity_id"] = 3
        elif alert_id and alert_id in self._seen_alerts:
            payload["activity_id"] = 2
        else:
            payload["activity_id"] = 1
        if alert_id:
            self._seen_alerts.add(alert_id)
        payload["activity_name"] = f"alert {raw or 'Unknown'}"

        # `seconds_to_triaged` / `seconds_to_resolved` are CrowdStrike's own MTTA and
        # MTTR for this detection, measured by a mature SOC on the same data. They are
        # the baseline Phase 10's metrics are worth comparing against, and there is no
        # OCSF column for "another team's response time".
        stash(payload, "vendor_seconds_to_triaged", record.get("seconds_to_triaged"))
        stash(payload, "vendor_seconds_to_resolved", record.get("seconds_to_resolved"))
        # The analyst, not the subject. In `unmapped` because every user-shaped column
        # feeds entity resolution, and writing a responder there makes the customer's
        # own SOC appear as actors inside their incidents.
        stash(payload, "assigned_to_name", record.get("assigned_to_name"))
        stash(payload, "assigned_to_uid", record.get("assigned_to_uid"))

    def _fill_severity(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        raw = record.get("severity")
        payload["severity_id"] = int(severity_from_bands(raw, SEVERITY_BANDS))
        stash(payload, "falcon_severity", raw)
        # `severity_name` is Falcon's own rendering of the same number. Disagreement
        # means the published breaks moved, which is a mapping fact this connector must
        # surface rather than absorb — the number is authoritative, the name is the
        # check.
        name = str(record.get("severity_name") or "").strip()
        if name:
            stash(payload, "falcon_severity_name", name)
            expected = Severity(payload["severity_id"]).name.replace("_", " ").title()
            if name.lower() not in (expected.lower(), expected.lower().replace(" ", "")):
                note(
                    payload,
                    f"{self.name}: severity {raw} bands to {expected} but Falcon calls "
                    f"it {name!r} — the 20/40/60/80 breaks this connector uses may have "
                    "changed; the raw number is in unmapped.falcon_severity",
                )
        graded = _confidence(record.get("confidence"))
        if graded is not None:
            payload["confidence_id"], payload["confidence"], payload["confidence_score"] = (
                graded
            )

    def _fill_finding(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        put(payload, "finding_uid", record.get("composite_id") or record.get("id"))
        title = record.get("display_name") or record.get("name")
        put(payload, "finding_title", title, limit=MESSAGE_LIMIT)
        put(payload, "message", title, limit=MESSAGE_LIMIT)
        put(payload, "finding_desc", record.get("description"))
        put(
            payload,
            "finding_created_time",
            parse_iso8601(record.get("created_timestamp")),
        )
        put(
            payload,
            "finding_modified_time",
            parse_iso8601(record.get("updated_timestamp")),
        )
        # The behaviour's own time, which for a pattern that fired on a sequence can be
        # well before the alert was written. This is what dwell-time measures from.
        put(payload, "finding_first_seen_time", parse_iso8601(record.get("timestamp")))
        # `pattern_id` is the detection logic's stable identifier across the fleet and
        # is the join key for "how often does this rule fire and how often is it right"
        # — the input to Phase 12's tuning proposals. Falcon sends it as an integer and
        # OCSF's `analytic.uid` is a string: unconverted, the Event model rejects the
        # *whole event*, so a real detection would be lost over a type.
        pattern = record.get("pattern_id")
        put(payload, "finding_analytic_uid", str(pattern) if pattern is not None else None)
        put(payload, "finding_analytic_name", title)
        # Falcon's patterns are behavioural: the sensor matches a sequence of actions,
        # not a file signature. Type 2 (Behavioral) is right for the pattern engine and
        # wrong for the two exceptions handled in `_fill_product` — an OverWatch alert
        # is a human analyst and an intel-match scenario is a fingerprint.
        payload["finding_analytic_type_id"] = 2
        types = [
            str(t)
            for t in (record.get("scenario"), record.get("objective"), record.get("tactic"))
            if t
        ]
        put(payload, "finding_types", types)
        put(payload, "finding_product_uid", record.get("product"))
        composite = record.get("composite_id")
        if composite:
            put(
                payload,
                "finding_src_url",
                f"https://falcon.crowdstrike.com/activity-v2/detections/{composite}",
            )
        stash(payload, "crawled_timestamp", record.get("crawled_timestamp"))
        # Prevalence is Falcon's own answer to "have we seen this anywhere else" — one
        # host in the fleet versus every host in the world — and it is the cheapest
        # available signal on whether a hash is targeted or commodity.
        stash(payload, "global_prevalence", record.get("global_prevalence"))
        stash(payload, "local_prevalence", record.get("local_prevalence"))

    def _fill_product(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        raw = str(record.get("product") or "").strip().lower()
        mapped = _PRODUCT.get(raw)
        if mapped:
            name, tag = mapped
            put(payload, "finding_product_uid", raw)
            stash(payload, "falcon_product_name", name)
            if tag:
                label(payload, tag)
            if raw == "overwatch":
                # A human threat hunter, not the pattern engine.
                payload["finding_analytic_type_id"] = 99
        elif raw:
            stash(payload, "falcon_product", raw)

        vendors = [str(v) for v in (record.get("source_vendors") or []) if v]
        products = [str(p) for p in (record.get("source_products") or []) if p]
        if vendors:
            stash(payload, "source_vendors", vendors)
        if products:
            stash(payload, "source_products", products)
        relayed = raw in RELAY_PRODUCTS or bool(vendors)
        if relayed:
            self.relayed_alerts += 1
            label(payload, "third-party-relay")
            note(
                payload,
                f"{self.name}: this alert was relayed through Falcon from "
                f"{', '.join(vendors) or 'another product'} rather than raised by a "
                "CrowdStrike sensor — if the originating source is also configured "
                "here, the same detection is collected twice under two different "
                "metadata_uid values and no deduplication will join them",
            )
        domains = [str(d) for d in (record.get("data_domains") or []) if d]
        if domains:
            label(payload, *[f"data-domain:{d}" for d in domains])
        stash(payload, "alert_type", record.get("type"))
        tags = [str(t) for t in (record.get("tags") or []) if t]
        if tags:
            label(payload, *[f"falcon-tag:{t}" for t in tags])

    def _fill_disposition(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """``pattern_disposition_details`` → what the sensor did, and what is left to do."""
        details = record.get("pattern_disposition_details")
        stash(payload, "pattern_disposition", record.get("pattern_disposition"))
        if not isinstance(details, Mapping):
            note(
                payload,
                f"{self.name}: this alert carries no pattern_disposition_details, so "
                "whether the sensor blocked, quarantined or merely observed the "
                "activity is unknown — a response decision here cannot tell a finished "
                "detection from a live one",
            )
            return

        for flag, disposition, action, tag in _DISPOSITION_PRECEDENCE:
            if as_bool(details.get(flag)):
                payload["disposition_id"] = int(disposition)
                payload["action_id"] = action
                if tag:
                    label(payload, tag)
                break
        else:
            # Every flag false is a real state: Falcon logged the pattern and took no
            # action at all. Logged (17) rather than Detected (15) says exactly that.
            payload["disposition_id"] = int(DispositionId.LOGGED)
            payload["action_id"] = 3

        for flag, (tag, sentence) in _RESPONSE_GATE_FLAGS.items():
            if as_bool(details.get(flag)):
                label(payload, tag)
                note(payload, f"{self.name}: {sentence}")
                if flag == "blocking_unsupported_or_disabled":
                    self.unblocked_alerts += 1

        stash(
            payload,
            "pattern_disposition_details",
            {k: v for k, v in details.items() if as_bool(v)},
        )

    def _fill_process(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """The triggering process → ``actor_process_*``.

        Not ``process_*``: 2004 declares no top-level ``process`` object — measured —
        so a ``process_name`` written here would be swept to ``unmapped`` and reported
        as this connector's mapping error. It is the actor by meaning as well as by
        legality: on a detection finding, the process that triggered the pattern is the
        thing that acted.
        """
        # `local_process_id` is the operating-system pid. `process_id` is Falcon's
        # 19-digit process *graph* id and is not a pid in any sense a kill action could
        # use. See the module docstring — this is the single most consequential
        # mis-mapping available on this record.
        put(payload, "actor_process_pid", record.get("local_process_id"))
        stash(payload, "process_graph_id", record.get("process_id"))
        stash(
            payload,
            "triggering_process_graph_id",
            record.get("triggering_process_graph_id"),
        )
        put(payload, "actor_process_name", record.get("filename"))
        put(payload, "actor_process_file_name", record.get("filename"))
        put(payload, "actor_process_cmd_line", record.get("cmdline"), limit=MESSAGE_LIMIT)
        folder = record.get("filepath")
        put(payload, "actor_process_file_path", folder)
        put(payload, "actor_process_path", folder)
        self._put_hash(payload, "actor_process_file_sha256", record.get("sha256"))
        self._put_hash(payload, "actor_process_file_md5", record.get("md5"))
        put(
            payload,
            "actor_process_created_time",
            parse_iso8601(record.get("process_start_time")),
        )
        stash(payload, "process_end_time", record.get("process_end_time"))

        parent = record.get("parent_details")
        if isinstance(parent, Mapping):
            put(
                payload,
                "actor_process_parent_cmd_line",
                parent.get("parent_cmdline"),
                limit=MESSAGE_LIMIT,
            )
            put(
                payload,
                "actor_process_parent_name",
                parent.get("filename") or parent.get("parent_filename"),
            )
            # Same trap one level up: `parent_process_id` is a graph id and
            # `parent_local_process_id` is the pid.
            put(payload, "actor_process_parent_pid", parent.get("parent_local_process_id"))
            stash(payload, "parent_process_graph_id", parent.get("parent_process_graph_id"))

    @staticmethod
    def _put_hash(payload: dict[str, Any], field: str, value: Any) -> None:
        """A hash column, or nothing.

        The Event model validates hash columns strictly and *rejects the whole event*
        on a malformed one — correctly, because chain of custody and every intel match
        depend on it. Falcon sends the empty string for a behaviour with no file (a
        registry or network pattern), and an all-zero sha256 for a file it could not
        read. Both would reject the event, losing a real detection over an absent hash.
        """
        text = str(value or "").strip().lower()
        if not text or set(text) == {"0"}:
            return
        payload[field] = text

    def _fill_actor_user(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        put(payload, "actor_user_name", record.get("user_name"))
        put(payload, "actor_user_domain", record.get("logon_domain"))
        put(payload, "actor_user_uid", record.get("user_id"))

    def _fill_attack(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        technique = str(record.get("technique_id") or "").strip()
        if technique:
            attack(payload, technique)
        tactic_id = str(record.get("tactic_id") or "").strip()
        if tactic_id:
            label(payload, f"tactic:{tactic_id}")
        stash(payload, "tactic", record.get("tactic"))
        stash(payload, "technique", record.get("technique"))
        if not technique:
            note(
                payload,
                f"{self.name}: this alert carries no technique_id, so its ATT&CK "
                f"position is the {record.get('tactic') or 'unnamed'} tactic alone — "
                "the coverage matrix should count it as a tactic, not a technique",
            )

        objective = str(record.get("objective") or "").strip()
        obj_key = objective.lower().replace(" ", "").replace("_", "")
        if obj_key in _OBJECTIVE_LABEL:
            label(payload, _OBJECTIVE_LABEL[obj_key])
        elif objective:
            stash(payload, "objective", objective)

        scenario = str(record.get("scenario") or "").strip()
        if scenario:
            # Always recorded, table hit or not — Falcon adds scenarios without notice
            # and a table lookup that gates recording turns every new scenario into
            # silence.
            label(payload, f"scenario:{scenario}")
            for tag in _SCENARIO_LABEL.get(scenario.lower().replace(" ", "_"), ()):
                label(payload, tag)

    def _fill_evidence(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """Grandparent, quarantined files and the IOC → 2004's ``evidences``.

        These have no legal flat home on 2004 — no ``file``, no ``process``, no
        ``dst_endpoint`` at the top level — so the nested array is not a style choice.
        ``evidences`` *is* declared here, unlike on 2005, which is why the incident
        connector puts its members in ``finding_info_list`` instead.
        """
        items: list[dict[str, Any]] = []

        grandparent = record.get("grandparent_details")
        if isinstance(grandparent, Mapping):
            built = prune(
                {
                    "process": {
                        "cmd_line": grandparent.get("cmdline")
                        or grandparent.get("parent_cmdline"),
                        "pid": grandparent.get("local_process_id"),
                        "file": prune(
                            {
                                "name": grandparent.get("filename"),
                                "path": grandparent.get("filepath"),
                                "hashes": self._hashes(
                                    grandparent.get("sha256"), grandparent.get("md5")
                                ),
                            }
                        ),
                    }
                }
            )
            if built:
                items.append(evidence(**built, name="grandparent process"))

        for entry in record.get("quarantined_files") or []:
            if not isinstance(entry, Mapping):
                continue
            paths = entry.get("paths")
            built = prune(
                {
                    "file": {
                        "path": paths[0]
                        if isinstance(paths, list) and paths
                        else entry.get("path"),
                        "hashes": self._hashes(entry.get("sha256"), entry.get("md5")),
                        "uid": entry.get("id"),
                    }
                }
            )
            if built:
                state = entry.get("state")
                items.append(
                    evidence(
                        **built,
                        name="quarantined file",
                        **({"verdict": str(state)} if state else {}),
                    )
                )

        ioc = self._ioc_evidence(record)
        if ioc:
            items.append(ioc)

        if items:
            payload["evidences"] = items

    @staticmethod
    def _hashes(sha256: Any, md5: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for algorithm_id, value in ((3, sha256), (1, md5)):
            text = str(value or "").strip().lower()
            if text and set(text) != {"0"}:
                out.append({"algorithm_id": algorithm_id, "value": text})
        return out

    def _ioc_evidence(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        """``ioc_type``/``ioc_value`` → the evidences element its type belongs in.

        Falcon carries at most one IOC per alert and describes it as a type/value pair,
        so the type decides the sub-object. Routing every one of them to a single key
        would put a domain in a file object, where no hunt query and no intel match
        would ever look for it.
        """
        kind = str(record.get("ioc_type") or "").strip().lower()
        value = str(record.get("ioc_value") or "").strip()
        if not kind or not value:
            return None
        detail: dict[str, Any]
        if kind in ("sha256", "hash_sha256"):
            detail = {"file": {"hashes": self._hashes(value, None)}}
        elif kind in ("md5", "hash_md5"):
            detail = {"file": {"hashes": self._hashes(None, value)}}
        elif kind in ("filename", "file_name"):
            detail = {"file": {"name": value}}
        elif kind in ("filepath", "file_path"):
            detail = {"file": {"path": value}}
        elif kind in ("domain", "domain_name", "hostname"):
            detail = {"dst_endpoint": {"domain": value}}
        elif kind in ("ipv4", "ipv6", "ip_address"):
            detail = {"dst_endpoint": {"ip": value}}
        elif kind in ("registry_key", "registrykey"):
            detail = {"reg_key": {"path": value}}
        elif kind in ("registry_value", "registryvalue"):
            detail = {"reg_value": {"name": value}}
        elif kind in ("url",):
            detail = {"url": {"url_string": value}}
        elif kind in ("username", "user_name"):
            detail = {"user": {"name": value}}
        else:
            return None
        built = prune(detail)
        if not built:
            return None
        return evidence(**built, name=f"ioc:{kind}")

    def _fill_correlation(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """``aggregate_id`` — Falcon's own clustering of related detections.

        Not ``incident_id``: **the Alerts v2 record does not carry one.** Falcon's
        incidents are built from behaviours, and the alert and behaviour feeds are
        joined inside Falcon rather than exposed as a foreign key here. So an alert
        from this connector and an incident from :class:`CrowdStrikeIncidentConnector`
        do not join directly, and Phase 3's entity resolution must do it on device and
        time. Recorded here so that gap is a documented property of the source rather
        than a correlation bug someone hunts for later.
        """
        aggregate = record.get("aggregate_id")
        if aggregate:
            payload["metadata_correlation_uid"] = f"crowdstrike-aggregate:{aggregate}"
            stash(payload, "aggregate_id", aggregate)
        stash(payload, "agent_id", record.get("agent_id"))

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        out["alerts_tracked"] = len(self._seen_alerts)
        if self.relayed_alerts:
            out["third_party_relayed"] = self.relayed_alerts
        if self.unblocked_alerts:
            out["vendor_could_not_block"] = self.unblocked_alerts
        if self.legacy_disposition_alerts:
            out["legacy_disposition_alerts"] = self.legacy_disposition_alerts
        if self.partial_errors:
            out["partial_error_responses"] = self.partial_errors
        if self.unreachable_ids:
            out["unreachable_ids"] = self.unreachable_ids
        return out


class CrowdStrikeIncidentConnector(CrowdStrikeConnector):
    """Falcon incidents → 2005 Incident Finding."""

    name = "crowdstrike_incidents"
    description = "CrowdStrike Falcon incidents, with their member behaviours"
    detects = (
        "Falcon's own clustering of detections into an intrusion — the hosts and "
        "accounts involved, the tactics and techniques observed across all of them, "
        "and a fleet-wide score — which is correlation this platform would otherwise "
        "re-derive from less data than CrowdStrike had"
    )
    spec = ConnectorSpec(
        # The incidents query endpoint's documented maximum `limit`.
        page_size=500,
        rate_per_second=5.0,
        burst=10,
        indexing_lag_seconds=60.0,
        overlap_seconds=900.0,
        max_window_seconds=86_400.0,
        docs_url="https://falcon.crowdstrike.com/documentation/page/incidents-apis",
        required_grants=(
            "Incidents: Read",
            "Incidents: Read also grants the behaviours endpoints, which are what fill "
            "OCSF 2005's required finding_info_list — without them an incident record "
            "is a severity and a status with no statement of what happened",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Incidents whose member behaviours were not fetched because the per-cycle cap
        #: was reached. Reported, never silent — see :data:`BEHAVIOR_LOOKUP_MAX`.
        self.incidents_without_members = 0
        #: Behaviour records fetched in the last cycle.
        self.behaviours_fetched = 0

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, _end = window.iso()
        ids = await self._query_ids(
            INCIDENT_QUERY_PATH,
            label_=f"{self.name}.query",
            filter_expr=f"modified_timestamp:>'{start}'",
            sort="modified_timestamp.asc",
        )
        if not ids:
            self.behaviours_fetched = 0
            return []
        records = await self._fetch_entities(
            INCIDENT_ENTITY_PATH, ids, label_=f"{self.name}.entities", chunk=100
        )
        members = await self._member_behaviours(
            [str(r.get("incident_id") or "") for r in records if r.get("incident_id")]
        )
        out: list[dict[str, Any]] = []
        for record in records:
            self.note_record_time(parse_iso8601(record.get("modified_timestamp")))
            payload = self._map_incident(record, members)
            if payload is not None:
                out.append(payload)
        return out

    async def _member_behaviours(
        self, incident_ids: Sequence[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """The behaviours belonging to each incident, keyed by incident id.

        Two extra calls per chunk — a query for behaviour ids, then an entity read —
        and they exist because OCSF 2005 *requires* ``finding_info_list``. An incident
        is precisely a set of member findings; without them the record carries a
        severity, a status and no statement of what happened.

        Bounded by :data:`BEHAVIOR_LOOKUP_MAX` and :data:`BEHAVIOR_QUERY_CHUNK`, and the
        bound is reported on the affected events rather than applied silently: an
        incident rendered with three of its nine detections is indistinguishable from an
        incident with three detections, and the second is a much smaller intrusion.
        """
        self.behaviours_fetched = 0
        self.incidents_without_members = 0
        grouped: dict[str, list[dict[str, Any]]] = {}
        if not incident_ids:
            return grouped
        behaviour_ids: list[str] = []
        for start in range(0, len(incident_ids), BEHAVIOR_QUERY_CHUNK):
            if len(behaviour_ids) >= BEHAVIOR_LOOKUP_MAX:
                break
            chunk = incident_ids[start : start + BEHAVIOR_QUERY_CHUNK]
            quoted = ",".join(f"'{i}'" for i in chunk)
            found = await self._query_ids(
                BEHAVIOR_QUERY_PATH,
                label_=f"{self.name}.behaviours.query",
                filter_expr=f"incident_id:[{quoted}]",
                sort="timestamp.asc",
                limit=min(self.spec.page_size, BEHAVIOR_LOOKUP_MAX),
                max_pages=2,
            )
            behaviour_ids.extend(found[: BEHAVIOR_LOOKUP_MAX - len(behaviour_ids)])
        if not behaviour_ids:
            return grouped
        records = await self._fetch_entities(
            BEHAVIOR_ENTITY_PATH,
            behaviour_ids,
            label_=f"{self.name}.behaviours.entities",
            chunk=100,
        )
        self.behaviours_fetched = len(records)
        for record in records:
            key = str(record.get("incident_id") or "")
            if key:
                grouped.setdefault(key, []).append(record)
        return grouped

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        # An incident without its behaviours cannot fill 2005's required
        # `finding_info_list`, and a single-record entry point has no way to fetch them.
        # Raising is the honest answer; returning a record that is missing a required
        # object would be an OCSF-invalid event produced deliberately.
        raise NotImplementedError(
            f"{self.name} maps an incident together with its member behaviours; use "
            "fetch_window, which fetches them"
        )

    def _map_incident(
        self, record: Mapping[str, Any], members: Mapping[str, list[dict[str, Any]]]
    ) -> dict[str, Any] | None:
        incident_id = str(record.get("incident_id") or "")
        payload = self._base_payload(
            uid=incident_id,
            time_value=record.get("created") or record.get("start"),
            log_name="incidents",
            record=record,
        )
        payload["class_uid"] = int(ClassUid.INCIDENT_FINDING)
        payload["is_alert"] = True
        # An incident is Falcon's own cluster, so it is its own correlation key — and
        # it is the key Phase 3 joins CYPHRA's incidents against when both saw the same
        # intrusion.
        if incident_id:
            payload["metadata_correlation_uid"] = f"crowdstrike-incident:{incident_id}"

        self._fill_incident_status(payload, record)
        self._fill_incident_severity(payload, record)
        self._fill_incident_scope(payload, record)
        self._fill_incident_attack(payload, record)
        self._fill_members(payload, record, members.get(incident_id, []))

        put(payload, "message", record.get("name"), limit=MESSAGE_LIMIT)
        put(payload, "comment", record.get("description"))
        put(payload, "start_time", parse_iso8601(record.get("start")))
        put(payload, "end_time", parse_iso8601(record.get("end")))
        start, end = payload.get("start_time"), payload.get("end_time")
        if start is not None and end is not None and end >= start:
            # OCSF's `duration` is milliseconds. This is the intrusion's own span —
            # the number dwell-time reporting is built on, and not derivable later
            # because `start`/`end` are the *activity's* bounds, not the record's.
            payload["duration"] = int((end - start) * 1000)
        if incident_id:
            put(
                payload,
                "src_url",
                f"https://falcon.crowdstrike.com/crowdscore/incidents/details/{incident_id}",
            )
        tags = [str(t) for t in (record.get("tags") or []) if t]
        if tags:
            label(payload, *[f"falcon-tag:{t}" for t in tags])
        stash(payload, "assigned_to_name", record.get("assigned_to_name"))
        stash(payload, "assigned_to_uid", record.get("assigned_to_uid"))
        stash(payload, "visibility", record.get("visibility"))
        return payload

    def _fill_incident_status(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        raw = record.get("status")
        try:
            code = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            code = -1
        status = _INCIDENT_STATUS.get(code)
        # Required by 2005, so there is no "leave it unset" branch — Unknown is the
        # honest value when the ladder gains a rung.
        payload["status_id"] = int(status if status is not None else IncidentStatus.UNKNOWN)
        if status is None and raw is not None:
            put(payload, "status_code", str(raw))
            note(
                payload,
                f"{self.name}: incident status {raw!r} is not in this connector's "
                "ladder (20 New, 25 Reopened, 30 In Progress, 40 Closed), so status_id "
                "is Unknown — 2005 requires the field, so it cannot simply be omitted",
            )
        if code == 25:
            label(payload, "reopened")

        state = str(record.get("state") or "").strip().lower()
        if state:
            label(payload, f"incident-state:{state}")
        # 2005's activity table is the same Create/Update/Close as 2004's. An incident
        # arrives repeatedly as Falcon adds behaviours to it, which is the point of
        # filtering on `modified_timestamp`.
        if code == 40 or state == "closed":
            payload["activity_id"] = 3
        elif code in (30, 25):
            payload["activity_id"] = 2
        else:
            payload["activity_id"] = 1
        payload["activity_name"] = f"incident {state or code}"

    def _fill_incident_severity(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        # `fine_score` is Falcon's 0-100 CrowdScore for this incident. The 20/40/60/80
        # breaks are the ones the Falcon console renders it with; CrowdStrike documents
        # them for `severity` and not for `fine_score`, so this is an inference from the
        # console rather than a documented equivalence, and the raw number is kept.
        raw = record.get("fine_score")
        payload["severity_id"] = int(severity_from_bands(raw, SEVERITY_BANDS))
        stash(payload, "fine_score", raw)
        if raw is None:
            note(
                payload,
                f"{self.name}: this incident carries no fine_score, so severity_id is "
                "Unknown rather than derived — CrowdScore is the only severity signal "
                "on an incident record",
            )

    def _fill_incident_scope(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """Hosts and users — as ``device_*`` only when there is exactly one host.

        An incident spans hosts by definition, and OCSF's ``device`` is singular. Filling
        it from the first of five hosts would make four of them invisible and the fifth
        look like *the* affected machine, which is the shape of every wrong blast-radius
        calculation. So the singular columns are filled only when they are unambiguous,
        and every host contributes an observable — which is what entity resolution
        consumes, and it is a list.
        """
        hosts = [h for h in (record.get("hosts") or []) if isinstance(h, Mapping)]
        host_ids = [str(h) for h in (record.get("host_ids") or []) if h]
        observables: list[dict[str, Any]] = []

        if len(hosts) == 1:
            self._fill_device(payload, hosts[0])
        elif hosts:
            note(
                payload,
                f"{self.name}: this incident spans {len(hosts)} hosts, so the singular "
                "device columns are left unset rather than filled from an arbitrary "
                "one — every host is an observable and the full list is in "
                "unmapped.host_ids",
            )
            for host in hosts:
                hostname = str(host.get("hostname") or "").strip()
                if hostname:
                    # Lower-cased to match the Event model's own normalisation of
                    # `device_hostname` — an observable that differs only in case is a
                    # second node in the entity graph for the same machine.
                    observables.append(
                        {
                            "name": "device.hostname",
                            "type_id": int(ObservableTypeId.HOSTNAME),
                            "value": hostname.lower(),
                        }
                    )
                device_id = str(host.get("device_id") or "").strip()
                if device_id:
                    observables.append(
                        {
                            "name": "device.uid",
                            "type_id": int(ObservableTypeId.DEVICE_UID),
                            "value": device_id,
                        }
                    )
        if host_ids:
            stash(payload, "host_ids", host_ids)
            payload["count"] = len(host_ids)

        users = [str(u) for u in (record.get("users") or []) if u]
        if len(users) == 1:
            put(payload, "actor_user_name", users[0])
        elif users:
            stash(payload, "users", users)
            for user in users:
                # *Not* lower-cased: usernames are case-sensitive on Linux, and the
                # Event model deliberately does not fold them. `correlate/entity.py`
                # applies the per-platform rule where it knows the platform.
                observables.append(
                    {
                        "name": "actor.user.name",
                        "type_id": int(ObservableTypeId.USER_NAME),
                        "value": user,
                    }
                )
        if observables:
            payload["observables"] = observables

        # Lateral movement, reported by Falcon rather than inferred. `lm_hosts_capable`
        # is the count of hosts the compromised credential *could* reach — a blast
        # radius CrowdStrike computed from the customer's own authentication graph, and
        # not something this platform can derive from telemetry alone.
        for field in ("lm_host_ids", "lm_hosts_capable", "lm_connection_ids", "lm_incident_ids"):
            stash(payload, field, record.get(field))
        if record.get("lm_host_ids") or record.get("lm_connection_ids"):
            label(payload, "lateral-movement")
            attack(payload, "T1021")

    def _fill_incident_attack(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        techniques = [str(t).strip() for t in (record.get("techniques") or []) if t]
        # Falcon's incident `techniques` are technique *names* ("Credential Dumping"),
        # not ids — the ids live on the member behaviours. `attack()` expects ids, so
        # feeding names would produce `attack:Credential Dumping` labels that no ATT&CK
        # lookup resolves and that the coverage matrix would count as covered.
        ids = [t for t in techniques if t.upper().startswith("T") and t[1:2].isdigit()]
        names = [t for t in techniques if t not in ids]
        if ids:
            attack(payload, *ids)
        if names:
            stash(payload, "technique_names", names)
            label(payload, *[f"technique-name:{n}" for n in names])
        tactics = [str(t).strip() for t in (record.get("tactics") or []) if t]
        if tactics:
            stash(payload, "tactics", tactics)
            label(payload, *[f"tactic-name:{t}" for t in tactics])
        objectives = [str(o).strip() for o in (record.get("objectives") or []) if o]
        for objective in objectives:
            key = objective.lower().replace(" ", "").replace("_", "")
            if key in _OBJECTIVE_LABEL:
                label(payload, _OBJECTIVE_LABEL[key])
        if objectives:
            stash(payload, "objectives", objectives)

    def _fill_members(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        behaviours: Sequence[Mapping[str, Any]],
    ) -> None:
        """``finding_info_list`` — 2005's own requirement, and the content of an incident.

        Each member behaviour becomes a ``finding_info`` object. The *ids* of the member
        techniques are here rather than on the incident, which is why
        :meth:`_fill_incident_attack` can only label the names: this is where an
        incident's ATT&CK coverage actually comes from.
        """
        members: list[dict[str, Any]] = []
        technique_ids: list[str] = []
        for behaviour in behaviours:
            pattern = behaviour.get("pattern_id")
            ref = finding_ref(
                uid=behaviour.get("behavior_id"),
                title=behaviour.get("display_name"),
                desc=behaviour.get("description"),
                created_time=parse_iso8601(behaviour.get("timestamp")),
                types=[
                    t
                    for t in (behaviour.get("scenario"), behaviour.get("objective"))
                    if t
                ],
                # Stringified for the same reason as the alert connector's: OCSF's
                # `analytic.uid` is a string and Falcon sends an integer.
                analytic_uid=str(pattern) if pattern is not None else None,
                analytic_name=behaviour.get("display_name"),
                # Behavioural, like every Falcon pattern. Object-level enum, so this is
                # hand-verified and pinned by test rather than checked by a sweep.
                analytic_type_id=2,
                data=prune(
                    {
                        "cmd_line": behaviour.get("cmdline"),
                        "filename": behaviour.get("filename"),
                        "filepath": behaviour.get("filepath"),
                        "sha256": behaviour.get("sha256"),
                        "user_name": behaviour.get("user_name"),
                        "device_id": behaviour.get("aid"),
                        "tactic": behaviour.get("tactic"),
                        "technique": behaviour.get("technique"),
                        "technique_id": behaviour.get("technique_id"),
                    }
                ),
            )
            if ref:
                members.append(ref)
            technique = str(behaviour.get("technique_id") or "").strip()
            if technique and technique not in technique_ids:
                technique_ids.append(technique)

        if technique_ids:
            attack(payload, *technique_ids)
        if members:
            payload["finding_info_list"] = members
            return

        # 2005 requires the array, and an empty one is still an unfilled requirement —
        # `missing_required` will say so. Saying *why* here is the difference between a
        # schema complaint and an actionable one.
        self.incidents_without_members += 1
        note(
            payload,
            f"{self.name}: no member behaviours were read for this incident, so 2005's "
            "required finding_info_list is empty — either the behaviours lookup hit "
            f"its {BEHAVIOR_LOOKUP_MAX}-record per-cycle cap, or the Incidents: Read "
            "scope does not cover the behaviours endpoints. The incident's severity "
            "and scope are correct; its content is missing",
        )

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        out["behaviours_fetched"] = self.behaviours_fetched
        if self.incidents_without_members:
            out["incidents_without_members"] = self.incidents_without_members
        if self.partial_errors:
            out["partial_error_responses"] = self.partial_errors
        if self.unreachable_ids:
            out["unreachable_ids"] = self.unreachable_ids
        return out


class CrowdStrikeHostConnector(CrowdStrikeConnector):
    """Falcon host inventory → 5001 Device Inventory Info."""

    name = "crowdstrike_hosts"
    description = "CrowdStrike Falcon sensor fleet — asset inventory and sensor health"
    detects = (
        "not an intrusion: the asset inventory every response decision depends on — "
        "which hosts exist, which are domain controllers, which are already contained, "
        "which have a sensor running in reduced functionality mode and are therefore "
        "reporting degraded telemetry while appearing healthy"
    )
    spec = ConnectorSpec(
        page_size=1_000,
        rate_per_second=5.0,
        burst=10,
        # `last_seen` is written by the sensor's heartbeat, which is every ~5 minutes.
        # A shorter lag than the heartbeat would produce windows that legitimately
        # contain nothing and look like a dead source.
        indexing_lag_seconds=300.0,
        overlap_seconds=600.0,
        # Inventory is a slow-moving stream and a wide window is cheap: a host that has
        # not checked in contributes nothing, and one that has contributes one record
        # however many times it checked in.
        max_window_seconds=86_400.0,
        docs_url="https://falcon.crowdstrike.com/documentation/page/hosts-apis",
        required_grants=("Hosts: Read",),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Hosts whose sensor is in reduced functionality mode — a first-order
        #: log-source-health fact, not an inventory detail.
        self.rfm_hosts = 0
        #: Hosts already network-contained by Falcon.
        self.contained_hosts = 0
        #: Hosts where Real Time Response is unavailable, i.e. where this platform's
        #: own response actions cannot reach.
        self.unreachable_hosts = 0

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, _end = window.iso()
        self.rfm_hosts = 0
        self.contained_hosts = 0
        self.unreachable_hosts = 0
        ids = await self._query_ids(
            DEVICE_QUERY_PATH,
            label_=f"{self.name}.query",
            filter_expr=f"last_seen:>'{start}'",
            sort="last_seen.asc",
        )
        if not ids:
            return []
        records = await self._fetch_entities(
            DEVICE_ENTITY_PATH,
            ids,
            label_=f"{self.name}.entities",
            # Device records are the largest on this API — ~90 fields including nested
            # policy objects — so the batch is smaller than the id page.
            chunk=500,
        )
        out: list[dict[str, Any]] = []
        for record in records:
            self.note_record_time(parse_iso8601(record.get("last_seen")))
            payload = self.map_record(record)
            if payload is not None:
                out.append(payload)
        return out

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        device_id = str(record.get("device_id") or "")
        payload = self._base_payload(
            uid=f"crowdstrike-host:{device_id}",
            time_value=record.get("last_seen") or record.get("modified_timestamp"),
            log_name="devices",
            record=record,
        )
        payload["class_uid"] = int(ClassUid.DEVICE_INVENTORY_INFO)
        # 5001's activities are {Log, Collect}. This is a poll of an inventory API, not
        # a device reporting itself, which is exactly what Collect means.
        payload["activity_id"] = 2
        payload["activity_name"] = "host inventory poll"
        # 5001's `status_id` is the three-value Status table — not FindingStatus and not
        # IncidentStatus. It describes the *collection*, which succeeded.
        payload["status_id"] = int(Status.SUCCESS)
        payload["severity_id"] = int(Severity.INFORMATIONAL)
        # Explicitly true rather than absent: this record exists because a CrowdStrike
        # sensor is installed and reporting. An unmanaged host is one this connector
        # cannot see at all, which is the gap `ingest/health.py` measures.
        payload["device_is_managed"] = True

        self._fill_device(payload, record)
        self._fill_containment(payload, record)
        self._fill_sensor_health(payload, record)
        self._fill_policies(payload, record)
        self._fill_owner(payload, record)

        put(payload, "start_time", parse_iso8601(record.get("first_seen")))
        put(payload, "end_time", parse_iso8601(record.get("last_seen")))
        hostname = record.get("hostname")
        put(payload, "message", f"host {hostname}" if hostname else None)
        for field in (
            "os_build",
            "kernel_version",
            "system_manufacturer",
            "system_product_name",
            "bios_manufacturer",
            "bios_version",
            "provision_status",
            "deployment_type",
            "host_utc_offset",
            "modified_timestamp",
            "config_id_base",
            "config_id_build",
            "config_id_platform",
        ):
            stash(payload, field, record.get(field))
        return payload

    def _fill_containment(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """Network and filesystem containment — the first thing a response must check."""
        raw = str(record.get("status") or "").strip().lower()
        mapped = _DEVICE_STATUS.get(raw)
        if mapped:
            disposition, tag, sentence = mapped
            payload["disposition_id"] = int(disposition)
            payload["action_id"] = 2
            label(payload, tag)
            note(payload, f"{self.name}: {sentence}")
            self.contained_hosts += 1
        elif raw and raw != "normal":
            stash(payload, "falcon_host_status", raw)
        fs = str(record.get("filesystem_containment_status") or "").strip().lower()
        if fs and fs != "normal":
            label(payload, f"filesystem-containment:{fs}")
            stash(payload, "filesystem_containment_status", fs)

    def _fill_sensor_health(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """Reduced functionality mode and RTR reachability.

        Both are log-source-health facts wearing inventory clothing. A sensor in RFM is
        installed, checking in, and **not inspecting** — it reports the host as covered
        while producing degraded telemetry, which is the exact failure
        :mod:`ingest.health` exists to catch and cannot catch on its own, because the
        sensor is not this platform's.
        """
        rfm = str(record.get("reduced_functionality_mode") or "").strip().lower()
        if rfm and rfm not in ("no", "false", "0"):
            self.rfm_hosts += 1
            label(payload, "sensor-reduced-functionality")
            stash(payload, "reduced_functionality_mode", rfm)
            # Elevated deliberately. An unprotected host is not an informational fact
            # about the inventory; it is a gap in coverage that nothing else reports.
            payload["severity_id"] = int(Severity.MEDIUM)
            note(
                payload,
                f"{self.name}: this host's sensor is in reduced functionality mode "
                f"({rfm!r}) — it is installed and checking in, so every availability "
                "check sees a covered host, while prevention and much of the telemetry "
                "are off. Detections from this host are absent rather than negative",
            )
        rtr = str(record.get("rtr_state") or "").strip().lower()
        if rtr:
            stash(payload, "rtr_state", rtr)
            if rtr not in ("ready", "connected"):
                self.unreachable_hosts += 1
                label(payload, "rtr-unavailable")
                note(
                    payload,
                    f"{self.name}: Real Time Response is {rtr!r} on this host, so the "
                    "Falcon-mediated response actions in this platform's action library "
                    "cannot reach it — a containment proposal for this host must fall "
                    "back to a network-layer action or be escalated",
                )
        stash(payload, "sensor_load_flags", record.get("agent_load_flags"))
        stash(payload, "last_reboot", record.get("last_reboot"))

    def _fill_policies(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """``device_policies.prevention`` → the singular ``policy`` object.

        The prevention policy is the one that decides whether the sensor blocks or only
        reports, so it is the one worth the singular column; the rest (sensor update,
        response, USB, firewall) go to ``unmapped`` together. A policy that is assigned
        but ``applied: false`` is a host that is *configured* to be protected and is
        not — reported, because the fleet dashboard shows the assignment.
        """
        policies = record.get("device_policies")
        if not isinstance(policies, Mapping):
            return
        prevention = policies.get("prevention")
        if isinstance(prevention, Mapping):
            put(payload, "policy_uid", prevention.get("policy_id"))
            put(payload, "policy_name", "prevention")
            applied = as_bool(prevention.get("applied"))
            if applied is not None:
                payload["policy_is_applied"] = applied
                if not applied:
                    label(payload, "prevention-policy-not-applied")
                    note(
                        payload,
                        f"{self.name}: a prevention policy is assigned to this host but "
                        "is not applied — the console shows it as covered and the "
                        "sensor is not enforcing it",
                    )
            put(payload, "policy_desc", prevention.get("policy_type"))
            stash(payload, "prevention_settings_hash", prevention.get("settings_hash"))
        stash(
            payload,
            "device_policy_ids",
            {
                str(kind): value.get("policy_id")
                for kind, value in policies.items()
                if isinstance(value, Mapping) and value.get("policy_id")
            },
        )

    def _fill_owner(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """``last_login_user`` → ``actor_user_*`` — asset ownership, not an action.

        The most recent interactive user is the closest thing an inventory record has to
        an owner, and ownership is what turns "a laptop was contained" into "a named
        person cannot work". It is on the actor because 5001 declares ``actor`` and not
        ``user``, and because nobody *performed* this event — it is a poll.
        """
        put(payload, "actor_user_name", record.get("last_login_user"))
        put(payload, "actor_user_uid", record.get("last_login_uid"))
        stash(payload, "last_login_timestamp", record.get("last_login_timestamp"))

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        if self.rfm_hosts:
            out["reduced_functionality_hosts"] = self.rfm_hosts
        if self.contained_hosts:
            out["contained_hosts"] = self.contained_hosts
        if self.unreachable_hosts:
            out["rtr_unavailable_hosts"] = self.unreachable_hosts
        if self.partial_errors:
            out["partial_error_responses"] = self.partial_errors
        if self.unreachable_ids:
            out["unreachable_ids"] = self.unreachable_ids
        return out


def crowdstrike_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[CrowdStrikeConnector]:
    """All three Falcon connectors.

    Hosts is last and is not optional. Alerts and incidents are the security value;
    the inventory is what makes either of them *actionable*, because a containment
    decision needs to know whether the host is a domain controller, whether Falcon has
    already contained it, and whether the response path can reach it at all.
    """
    return [
        CrowdStrikeAlertConnector(pipeline, config, **kwargs),
        CrowdStrikeIncidentConnector(pipeline, config, **kwargs),
        CrowdStrikeHostConnector(pipeline, config, **kwargs),
    ]


__all__ = [
    "ALERT_ENTITY_PATH",
    "ALERT_ID_KEY",
    "ALERT_QUERY_PATH",
    "BEHAVIOR_ENTITY_PATH",
    "BEHAVIOR_LOOKUP_MAX",
    "BEHAVIOR_QUERY_CHUNK",
    "BEHAVIOR_QUERY_PATH",
    "CONFIDENCE_BANDS",
    "DEVICE_ENTITY_PATH",
    "DEVICE_QUERY_PATH",
    "INCIDENT_ENTITY_PATH",
    "INCIDENT_QUERY_PATH",
    "OFFSET_CEILING",
    "RELAY_PRODUCTS",
    "SEVERITY_BANDS",
    "TOKEN_PATH",
    "CrowdStrikeAlertConnector",
    "CrowdStrikeConnector",
    "CrowdStrikeHostConnector",
    "CrowdStrikeIncidentConnector",
    "crowdstrike_connectors",
]

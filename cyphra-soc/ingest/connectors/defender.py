"""Microsoft Defender for Endpoint — alerts (2004) and advanced hunting (1007/4001/3002/1001).

Two connectors against two APIs on the same host, because they are two different kinds
of data and conflating them loses the distinction that matters most about them:

``/api/alerts``
    Defender's *own* verdicts. Already triaged by Microsoft, already clustered into
    incidents, already carrying evidence. Low volume, high value, and the single most
    likely source in this platform to be right.
``/api/advancedqueries/run``
    The raw endpoint telemetry underneath those verdicts — process trees, network
    connections, logons, file writes. High volume, no verdict, and the only way to
    answer "what else did that process do" without an agent on the box.

── Why the alert filter is ``lastUpdateTime`` and not ``alertCreationTime`` ──

A Defender alert is not immutable. It is created with a title, a severity and a machine,
and then over the following minutes to hours Microsoft attaches evidence, an
``incidentId``, an ``investigationState``, and — if a human or Automated Investigation
reaches it — a ``classification`` and ``determination``. An alert filtered on
``alertCreationTime`` is therefore collected at its emptiest: a title with no IOCs, no
incident membership and no verdict, and it is never read again.

So this connector filters on ``lastUpdateTime``, which means **the same alert arrives
repeatedly**, once per material change. That is deliberate and it is not deduplication's
job to suppress: ``metadata_uid`` is the alert id, so the lake holds an ordered history
of one finding's state, and 2004's ``activity_id`` distinguishes the sightings —
``Create`` (1) for the first, ``Update`` (2) for a re-delivery, ``Close`` (3) once
Defender reports it resolved. A downstream reader that wants current state takes the
latest row per ``finding_uid``; one that wants MTTR takes the first and last. Both are
answerable. Neither is, if the alert is read once at creation.

The cost is a re-read multiplier on a low-volume stream, which is the cheap direction.

── The three vendor fields that change what response is allowed ──

``determination = SecurityTesting``
    An authorised red team or pen test. Responding to it is responding to your own
    engagement, and the paperwork for isolating a tester's laptop at 3 a.m. is worse
    than the alert. Labelled ``authorised-testing``, which the respond layer's safety
    envelope reads as a hard stop rather than as a low score.
``detectionSource = AutomatedInvestigation``
    Defender describing *its own remediation*, not a new intrusion. Counting these as
    intrusions double-counts every alert AIR touched and makes the metrics module report
    twice the true volume.
``status = Resolved`` with ``classification = FalsePositive``
    A verdict already reached by a human with more context than this platform has.
    Carried through as ``verdict_id`` rather than re-derived.

── The hunting query pack, and why it is a pack rather than one query ──

Advanced hunting is KQL over per-table schemas, and the four tables worth polling map to
four different OCSF classes with four different required objects. One query returning a
union would produce rows whose shape depended on which table they came from, and the
mapping would be a switch on a nullable column — so instead there are four queries, each
pinned to one class, each windowed by the same planned window in KQL rather than in a
query string.

The tenant-wide rate limit is the binding constraint: **15 calls per minute and 15
minutes of aggregate query runtime per hour, shared across every caller** — this
platform, the Defender portal, and any other integration the customer runs. A pack of
four at a five-minute cadence spends 48 calls and a few seconds of runtime per hour,
which leaves the customer's own tooling room. The pack is deliberately not extended to
``DeviceEvents`` (the catch-all table, ~40 ActionTypes, most of them uninteresting) or
``DeviceImageLoadEvents`` (volume comparable to process events for a fraction of the
signal); both are better served by a targeted hunt in Phase 6 than by continuous
collection.

Rows are capped by KQL ``take``, not by pagination — the API has none. A window that
hits the cap is reported through ``page_cap_hits`` and a note on the connector, because
a silent ``take 10000`` is a sampling decision disguised as a complete answer.

── What is deliberately not mapped ──

``machineId`` is Defender's own GUID and is *not* the hostname, the Entra device id, or
the Intune device id. It goes to ``device_uid`` because it is the join key for every
Defender action (isolate, scan, collect-package) and therefore the one an automated
response needs; ``aadDeviceId`` is stashed separately for joining to Entra sign-ins, and
``computerDnsName`` fills ``device_hostname`` because it is what an analyst recognises.
Conflating the three is how a response isolates the wrong machine.

``relatedUser`` is the account *on the machine*, which for a service-account compromise
is not the account that matters and for a multi-user server is one of several. It fills
``actor_user_*`` — not ``user_*``, which 2004 does not declare at all — and the evidence
array is where the per-entity accounts live.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, FindingStatus, Severity, Status
from ingest.collectors.base import Availability, unavailable
from ingest.connectors.auth import Authorizer, OAuth2ClientCredentials, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    normalise_records,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import HttpResponse, Request
from ingest.connectors.mapping import (
    MESSAGE_LIMIT,
    as_bool,
    attack,
    evidence,
    label,
    note,
    prune,
    put,
    resource_ref,
    severity_from_name,
    stash,
)

ALERTS_PATH = "/api/alerts"
HUNTING_PATH = "/api/advancedqueries/run"

#: Defender's API is its own OAuth2 resource, not a Graph scope. The commercial host is
#: the default; a sovereign-cloud tenant overrides ``endpoints.defender`` and the scope
#: follows it, because the scope *is* the resource host.
SCOPE_SUFFIX = "/.default"


# ── alert lifecycle ─────────────────────────────────────────────────────────
#
# Defender's `status` is a workflow state, and 2004's `status_id` is the same kind of
# thing — which is why this is a table and not a Status.SUCCESS/FAILURE decision. The
# check that catches getting this wrong is `bad_enum_values`, because 1 and 2 are legal
# on both tables and mean different things on each.

#: ``alert.status`` → 2004 ``status_id``. Defender has no *Suppressed* state: suppression
#: is a separate ``suppressionRule`` object that stops the alert being created at all, so
#: a suppressed detection is absent rather than present-and-marked. Recorded here because
#: "no Suppressed alerts this month" is a claim this connector cannot support.
_ALERT_STATUS: Mapping[str, FindingStatus] = {
    "new": FindingStatus.NEW,
    "inprogress": FindingStatus.IN_PROGRESS,
    "in progress": FindingStatus.IN_PROGRESS,
    "resolved": FindingStatus.RESOLVED,
    "unknown": FindingStatus.UNKNOWN,
}

#: ``alert.classification`` → 2004 ``verdict_id``. The one place this platform accepts a
#: verdict it did not reach itself, and it does so because the alternative is worse: a
#: Defender alert a customer's analyst already closed as a false positive should not be
#: re-raised here as new. ``InformationalExpectedActivity`` maps to *Benign* (5) rather
#: than *False Positive* (1) — the detection fired correctly on activity that is expected,
#: which is a different statement from "the detection was wrong", and the difference is
#: what a detection-tuning report needs.
_CLASSIFICATION: Mapping[str, int] = {
    "unknown": 0,
    "falsepositive": 1,
    "truepositive": 2,
    "informationalexpectedactivity": 5,
    "benignpositive": 5,
}

#: ``alert.determination`` → label. ``securitytesting`` is the reason this table exists
#: at all — see the module docstring.
#:
#: Deliberately **not** a source of ATT&CK techniques. A determination is a disposition,
#: not an observation: "Malware" says an analyst concluded the alert was malware, and it
#: does not say the malware arrived by user execution (T1204), by exploit (T1203) or by a
#: scheduled task. Inferring a technique from it would put a fabricated technique into the
#: coverage matrix and a fabricated ``attack:`` label on the finding, and nothing
#: downstream could tell it from one Defender actually observed. ``mitreTechniques`` is
#: the only technique source on this record; where it is absent, the note in
#: :meth:`_fill_attack` says so rather than filling the gap with a guess.
_DETERMINATION: Mapping[str, str] = {
    "apt": "targeted-intrusion",
    "malware": "malware",
    "malicioususeractivity": "insider",
    "unwantedsoftware": "pua",
    "phishing": "phishing",
    "multistagedattack": "attack-chain",
    "multistagedincident": "attack-chain",
    "compromisedaccount": "compromised-account",
    "compromiseduser": "compromised-account",
    "securitytesting": "authorised-testing",
    "linetobusinessapplication": "line-of-business-app",
    "confirmedactivity": "expected-activity",
    "notmalicious": "not-malicious",
    "clean": "not-malicious",
    "insufficientdata": "insufficient-data",
    "notavailable": "",
    "other": "",
}

#: Determinations that mean *do not respond*, whatever the severity says. Read by the
#: respond layer's safety envelope as a hard stop rather than as a score adjustment,
#: because a score can be outvoted and this cannot: isolating a machine because an
#: authorised tester ran Mimikatz on it is a self-inflicted incident.
NO_RESPONSE_DETERMINATIONS = frozenset({"securitytesting", "linetobusinessapplication"})

#: ``alert.detectionSource`` → (analytic name, ``finding_analytic_type_id``, label).
#: OCSF's ``analytic.type_id``: 1 Rule, 2 Behavioral, 3 Statistical, 4 Learning (ML),
#: 5 Fingerprinting, 6 Tagging, 7 Keyword Match, 99 Other. The distinction is
#: operational, not cosmetic — a signature hit on a file that antivirus already
#: quarantined needs no response, and a behavioural detection on a live process does.
#:
#: These values are **not** machine-checked: ``analytic.type_id`` is an object-level
#: enum and the vendored index carries object-level enums nowhere, so ``enum_members(
#: 2004, "finding_analytic_type_id")`` returns nothing and a wrong value here would pass
#: every OCSF sweep. Same gap as ``user.type_id`` and ``process.integrity_id``. The table
#: below is hand-verified against the v1.9.0 dictionary and pinned by test instead.
_DETECTION_SOURCE: Mapping[str, tuple[str, int, str]] = {
    "windowsdefenderav": ("Microsoft Defender Antivirus", 5, "signature-detection"),
    "antivirus": ("Microsoft Defender Antivirus", 5, "signature-detection"),
    "windowsdefenderatp": ("Defender for Endpoint EDR", 2, "behavioural-detection"),
    "edr": ("Defender for Endpoint EDR", 2, "behavioural-detection"),
    "customdetection": ("Custom detection rule", 1, "customer-rule"),
    "customti": ("Custom threat intelligence indicator", 6, "customer-indicator"),
    "microsoftdefenderforoffice365": ("Defender for Office 365", 2, ""),
    "office365": ("Defender for Office 365", 2, ""),
    "microsoftdefenderforidentity": ("Defender for Identity", 2, ""),
    "microsoftdefenderforcloudapps": ("Defender for Cloud Apps", 2, ""),
    "microsoftcloudappsecurity": ("Defender for Cloud Apps", 2, ""),
    "azureadidentityprotection": ("Entra ID Protection", 4, ""),
    "aadidentityprotection": ("Entra ID Protection", 4, ""),
    "microsoft365defender": ("Microsoft 365 Defender correlation", 2, "correlated"),
    "threatexperts": ("Microsoft Threat Experts", 99, "human-analyst"),
    "manual": ("Manually created", 99, "human-analyst"),
    # The trap. AIR alerts describe Defender's own remediation of an *existing* alert.
    "automatedinvestigation": (
        "Automated Investigation and Response", 99, "vendor-remediation",
    ),
    "builtinml": ("Defender built-in ML", 4, ""),
    "smartscreen": ("Microsoft Defender SmartScreen", 5, ""),
    "networkprotection": ("Network protection", 1, ""),
    "appguard": ("Application Guard", 1, ""),
}

#: Sources that describe the vendor's own response rather than an adversary's action.
#: Counted separately in :meth:`DefenderAlertConnector.stats_extra` because they inflate
#: alert volume without adding intrusions, and an alert-volume metric that includes them
#: reports a busy month whenever AIR was busy.
VENDOR_ACTION_SOURCES = frozenset({"automatedinvestigation"})

#: ``alert.category`` → ATT&CK *tactic* label. Defender's categories are tactic-shaped
#: but not tactic-named, and the ones that are not tactics at all (Malware, Ransomware,
#: SuspiciousActivity, UnwantedSoftware) are left as plain labels rather than forced onto
#: a tactic they do not have. ``alert.mitreTechniques`` carries the techniques and is
#: preferred wherever present; this is the fallback for the alerts that have none.
_CATEGORY_TACTIC: Mapping[str, str] = {
    "initialaccess": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilegeescalation": "TA0004",
    "defenseevasion": "TA0005",
    "credentialaccess": "TA0006",
    "credentialtheft": "TA0006",
    "discovery": "TA0007",
    "lateralmovement": "TA0008",
    "collection": "TA0009",
    "commandandcontrol": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "reconnaissance": "TA0043",
    "resourcedevelopment": "TA0042",
}

#: Categories that are not tactics. Kept so a category is never silently dropped and
#: never mis-labelled as a tactic it is not.
_CATEGORY_LABEL: Mapping[str, str] = {
    "malware": "malware",
    "ransomware": "ransomware",
    "suspiciousactivity": "suspicious-activity",
    "unwantedsoftware": "pua",
    "exploit": "exploit",
    "weaponization": "weaponisation",
    "socialengineering": "social-engineering",
    "generalmalware": "malware",
}

#: ``alert.evidence[].entityType`` → the ``evidences`` sub-object it belongs under.
#: Measured against :data:`~ingest.connectors.mapping.EVIDENCE_KEYS`, which is the
#: declared set — :func:`~ingest.connectors.mapping.evidence` raises on anything else,
#: and it raises rather than routing elsewhere because an unknown key here is a bug in
#: this file that would be invisible in the lake.
#:
#: ``Ip`` maps to ``src_endpoint``. Defender does not say which direction the address
#: was, and source is the right guess for the overwhelming majority of endpoint alerts
#: (an inbound connection, a C2 callback's peer, a logon origin) — but it is a guess, so
#: the raw entity is kept in ``unmapped`` and the ambiguity is stated here rather than
#: hidden behind a confident-looking column.
_EVIDENCE_KEY: Mapping[str, str] = {
    "file": "file",
    "process": "process",
    "user": "user",
    "useraccount": "user",
    "ip": "src_endpoint",
    "url": "url",
    "registrykey": "reg_key",
    "registryvalue": "reg_value",
    "mailmessage": "email",
    "mailbox": "email",
    "machine": "device",
    "cloudapplication": "resources",
    "cloudlogonsession": "user",
    "securitygroup": "resources",
    "container": "container",
    "containerimage": "container",
    "amazonresource": "resources",
    "azureresource": "resources",
    "googlecloudresource": "resources",
    "oauthapplication": "resources",
}


# ── advanced hunting ────────────────────────────────────────────────────────
#
# Each query is windowed by the planner, capped by `take`, and pinned to exactly one
# OCSF class. `columns` is not documentation — it is the projection, so a schema change
# that removes a column fails the query loudly instead of silently producing rows with a
# missing field.

#: Defender ``DeviceLogonEvents.LogonType`` → OCSF 3002 ``logon_type_id`` and its OCSF
#: caption. Defender's vocabulary is Windows' with different spellings, and two entries
#: have no OCSF member: ``Batch`` maps to 4 and ``Service`` to 5, but Defender's
#: ``Unknown`` and ``CustomLogonType`` map to nothing, so they are left unset rather than
#: mapped to 0 — which would assert *System* on 3002's table.
_LOGON_TYPES: Mapping[str, tuple[int, str]] = {
    "interactive": (2, "Interactive"),
    "network": (3, "Network"),
    "batch": (4, "Batch"),
    "service": (5, "OS Service"),
    "unlock": (7, "Unlock"),
    "networkcleartext": (8, "Network Cleartext"),
    "newcredentials": (9, "New Credentials"),
    "remoteinteractive": (10, "Remote Interactive"),
    "cachedinteractive": (11, "Cached Interactive"),
    "cachedremoteinteractive": (12, "Cached Remote Interactive"),
    "cachedunlock": (13, "Cached Unlock"),
}

#: ``DeviceFileEvents.ActionType`` → OCSF 1001 activity. ``FileModified`` is *Update*
#: (3) rather than *Create* (1), and the distinction matters for ransomware staging:
#: mass Update on existing documents is encryption in place, mass Create is a copy.
_FILE_ACTIONS: Mapping[str, int] = {
    "filecreated": 1,
    "filemodified": 3,
    "filedeleted": 4,
    "filerenamed": 5,
}

#: ``DeviceNetworkEvents.ActionType`` → OCSF 4001 activity. Defender reports the attempt
#: and its outcome as separate ActionTypes, which OCSF splits the same way.
_NETWORK_ACTIONS: Mapping[str, int] = {
    "connectionsuccess": 1,
    "connectionrequest": 1,
    "connectionfound": 6,
    "inboundconnectionaccepted": 1,
    "listeningconnectioncreated": 7,
    "connectionfailed": 4,
    "connectionattempt": 1,
}


class HuntingQuery:
    """One KQL query in the pack, with the class its rows become.

    A class rather than a tuple because the mapping function is part of the definition:
    a query and the mapper for its rows must change together, and a table of queries
    beside a switch statement of mappers is two places to forget.
    """

    __slots__ = ("table", "kql", "class_uid", "mapper", "attack_hint")

    def __init__(
        self,
        table: str,
        kql: str,
        class_uid: int,
        mapper: str,
        attack_hint: str = "",
    ) -> None:
        self.table = table
        self.kql = kql
        self.class_uid = class_uid
        self.mapper = mapper
        self.attack_hint = attack_hint


#: The pack. ``{start}``/``{end}``/``{take}`` are filled per window.
#:
#: ``Timestamp`` is UTC in every table and the bounds are ``>=``/``<`` to match the
#: window planner's own half-open convention — a ``between()`` would be inclusive at
#: both ends and re-deliver one row per boundary per cycle forever.
#:
#: ``| order by Timestamp asc`` matters when ``take`` truncates: ascending means the cap
#: drops the *newest* rows, which the next window's overlap re-reads. Descending would
#: drop the oldest, which nothing ever re-reads.
HUNTING_PACK: tuple[HuntingQuery, ...] = (
    HuntingQuery(
        "DeviceProcessEvents",
        """DeviceProcessEvents
| where Timestamp >= datetime({start}) and Timestamp < datetime({end})
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
    SHA256, ProcessId, ProcessCommandLine, ProcessCreationTime, ProcessIntegrityLevel,
    AccountName, AccountDomain, AccountSid, InitiatingProcessId,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine, InitiatingProcessSHA256,
    InitiatingProcessParentId, InitiatingProcessParentFileName,
    InitiatingProcessAccountName, InitiatingProcessAccountDomain, ReportId
| order by Timestamp asc
| take {take}""",
        int(ClassUid.PROCESS_ACTIVITY),
        "_map_process",
    ),
    HuntingQuery(
        "DeviceNetworkEvents",
        """DeviceNetworkEvents
| where Timestamp >= datetime({start}) and Timestamp < datetime({end})
| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort,
    RemoteUrl, LocalIP, LocalPort, Protocol, InitiatingProcessId,
    InitiatingProcessFileName, InitiatingProcessFolderPath,
    InitiatingProcessCommandLine, InitiatingProcessSHA256,
    InitiatingProcessAccountName, InitiatingProcessAccountDomain, ReportId
| order by Timestamp asc
| take {take}""",
        int(ClassUid.NETWORK_ACTIVITY),
        "_map_network",
    ),
    HuntingQuery(
        "DeviceLogonEvents",
        """DeviceLogonEvents
| where Timestamp >= datetime({start}) and Timestamp < datetime({end})
| project Timestamp, DeviceId, DeviceName, ActionType, LogonType, AccountName,
    AccountDomain, AccountSid, RemoteIP, RemoteDeviceName, IsLocalAdmin,
    Protocol, FailureReason, InitiatingProcessFileName, ReportId
| order by Timestamp asc
| take {take}""",
        int(ClassUid.AUTHENTICATION),
        "_map_logon",
    ),
    HuntingQuery(
        "DeviceFileEvents",
        """DeviceFileEvents
| where Timestamp >= datetime({start}) and Timestamp < datetime({end})
| where ActionType in ("FileCreated", "FileModified", "FileDeleted", "FileRenamed")
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
    SHA256, MD5, FileSize, InitiatingProcessId, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessSHA256, InitiatingProcessAccountName,
    InitiatingProcessAccountDomain, ReportId
| order by Timestamp asc
| take {take}""",
        int(ClassUid.FILE_SYSTEM_ACTIVITY),
        "_map_file",
    ),
)

#: KQL ``datetime()`` wants ``YYYY-MM-DDTHH:MM:SSZ`` unquoted. Quoting it is a syntax
#: error, and this is the opposite of Azure Activity's ``$filter``, which *requires* the
#: quotes — the same ISO string, two incompatible framings, one vendor.
_KQL_TIME = "{}"


class DefenderConnector(Connector):
    """Shared Defender plumbing: the token, the host, the base payload."""

    def tenant(self) -> Credential:
        return self.config.connectors.defender_tenant_id

    def client_id(self) -> Credential:
        return self.config.connectors.defender_client_id

    def client_secret(self) -> Credential:
        return self.config.connectors.defender_client_secret

    def credentials(self) -> tuple[Credential, ...]:
        return (self.tenant(), self.client_id(), self.client_secret())

    def base_url(self) -> str:
        return self.config.endpoints.defender.rstrip("/")

    def authorizer(self) -> Authorizer:
        # `.secret`, not `.value`: this is constructed by `client()` and described by the
        # readiness report, both of which run on deployments where nothing is set.
        tenant = self.tenant().secret or "TENANT-NOT-CONFIGURED"
        return OAuth2ClientCredentials(
            self.client(),
            token_url=(
                f"{self.config.endpoints.microsoft_login.rstrip('/')}"
                f"/{tenant}/oauth2/v2.0/token"
            ),
            client_id=self.client_id(),
            client_secret=self.client_secret(),
            # The resource is Defender's own host, not Graph. A Graph token presented
            # here returns 401 with `InvalidAuthenticationToken`, whose text says the
            # token is invalid rather than that it is for the wrong audience — so the
            # natural next step is to re-issue the same wrong token.
            scope=self.base_url() + SCOPE_SUFFIX,
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def probe(self) -> Availability:
        """Configured, plus the sovereign-cloud mismatch that reads as an empty tenant."""
        base = super().probe()
        if not base.available:
            return base
        login = self.config.endpoints.microsoft_login.lower()
        api = self.base_url().lower()
        commercial_login = ".microsoftonline.com" in login
        commercial_api = ".securitycenter.microsoft.com" in api
        if commercial_login != commercial_api:
            return unavailable(
                f"the login endpoint ({self.config.endpoints.microsoft_login}) and the "
                f"Defender endpoint ({self.base_url()}) are in different Microsoft "
                "clouds — set both under endpoints: in soc.yaml, or neither. Mixed, "
                "the token is minted successfully by one cloud and rejected as "
                "invalid by the other, and the error names the token rather than the "
                "cloud"
            )
        return base

    def _base_payload(
        self, *, uid: str, time_value: Any, log_name: str, record: Mapping[str, Any]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "time": parse_iso8601(time_value),
            "metadata_uid": uid,
            "metadata_product_name": "Microsoft Defender for Endpoint",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_log_name": log_name,
            "metadata_version": "1.9.0",
            "severity_id": int(Severity.INFORMATIONAL),
            "cloud_provider": "Microsoft Azure",
            "raw": dict(record),
        }
        put(payload, "metadata_tenant_uid", self.tenant().secret or None)
        return payload

    def _fill_device(
        self,
        payload: dict[str, Any],
        *,
        device_id: Any,
        hostname: Any,
        aad_device_id: Any = None,
        rbac_group: Any = None,
    ) -> None:
        """The three device identifiers Defender sends, kept apart on purpose.

        ``machineId``/``DeviceId`` is Defender's own GUID and the *only* one its action
        API accepts, so it is what ``device_uid`` has to hold for an automated isolate to
        target the right machine. ``aadDeviceId`` is the Entra device object id and is
        what joins to a sign-in's ``deviceDetail.deviceId``; it lives in ``unmapped``
        because OCSF's device has one ``uid`` and this platform's response path needs the
        Defender one. ``computerDnsName`` is the FQDN — recognisable, and not unique
        across a rebuilt host.
        """
        put(payload, "device_uid", device_id)
        put(payload, "device_hostname", hostname)
        stash(payload, "aad_device_id", aad_device_id)
        # The machine group is Defender's RBAC scope. It is the answer to "whose machine
        # is this" for an org that scoped its groups by business unit, which makes it an
        # asset-criticality input rather than trivia.
        stash(payload, "machine_group", rbac_group)
        if hostname and "." in str(hostname):
            put(payload, "device_domain", str(hostname).split(".", 1)[1])


class DefenderAlertConnector(DefenderConnector):
    """Defender for Endpoint alerts → 2004 Detection Finding."""

    name = "defender_alerts"
    description = "Defender for Endpoint alerts, with evidence and Microsoft's verdict"
    detects = (
        "everything Defender detects on a managed endpoint — malware, LOLBin abuse, "
        "credential dumping, ransomware behaviour, lateral movement — plus the "
        "classification a human or Automated Investigation already reached, which is "
        "the one verdict in this platform that came from more context than it has"
    )
    spec = ConnectorSpec(
        # The alerts endpoint's documented $top ceiling. With $expand=evidence a full
        # page is large and slow, so this is a ceiling rather than a target.
        page_size=1000,
        # 100 calls/minute per tenant on the Defender API, shared with every other
        # integration; 45 requests/minute is the documented alerts sub-limit. Two per
        # second leaves room and is far above what this stream needs.
        rate_per_second=2.0,
        burst=4,
        # An alert's `lastUpdateTime` is set when the change lands, and the change is
        # visible to this endpoint within seconds — the lag here is Microsoft's own
        # write, not an index build. The 60 seconds is a clock-skew allowance.
        indexing_lag_seconds=60.0,
        # Generous, and cheap: the stream is low-volume, `metadata_uid` is the alert id,
        # and a re-delivery is a legitimate state update rather than a duplicate — so the
        # usual cost of a wide overlap does not apply here.
        overlap_seconds=900.0,
        max_window_seconds=86_400.0,
        docs_url="https://learn.microsoft.com/defender-endpoint/api/get-alerts",
        required_grants=(
            "Alert.Read.All (application permission)",
            "admin consent — Defender's application permissions are not usable without "
            "it, and the failure is 403 with no message body",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Alert ids already seen, so a re-delivery is Update rather than Create. In
        #: memory and therefore reset by a restart, which downgrades a re-delivery to
        #: Create — wrong in the harmless direction, and the alternative is a store
        #: lookup per alert on a path that must not depend on the store being up.
        self._seen_alerts: set[str] = set()
        #: Alerts whose `detectionSource` describes Defender's own remediation.
        self.vendor_action_alerts = 0
        #: Alerts carrying a determination that forbids response.
        self.no_response_alerts = 0

    def _next_link(self, _resp: HttpResponse, body: Any) -> str | None:
        # `.get`, not `dig`: the key contains a dot and `dig` splits on dots. See the
        # same note in entra.py — this is the failure that returns page one forever.
        if not isinstance(body, Mapping):
            return None
        link = body.get("@odata.nextLink")
        return str(link) if link else None

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, _end = window.iso()
        request = Request(
            "GET",
            f"{self.base_url()}{ALERTS_PATH}",
            label=f"{self.name}.list",
            params={
                # `gt` on lastUpdateTime, with no upper bound, and both halves of that
                # are deliberate:
                #
                # `lastUpdateTime` rather than `alertCreationTime` because an alert
                # mutates for hours after creation — see the module docstring.
                #
                # No `lt` bound because with an upper bound this connector would collect
                # each alert's *first* state and then advance past every later update:
                # the update raises lastUpdateTime above the window that has already
                # closed, so it lands in no window at all. The window's end is still
                # respected for the cursor; it is only the query that is open-ended.
                #
                # Unquoted ISO. OData's Edm.DateTimeOffset literal takes no quotes here
                # and returns 400 "Syntax error at position N" with them, which is the
                # exact opposite of the Azure Activity `$filter` in azure_activity.py.
                "$filter": f"lastUpdateTime gt {start}",
                "$top": self.spec.page_size,
                # Without this the `evidence` array is absent entirely and every alert
                # is a title with no IOCs — no file hash, no process, no account, no
                # address. The alert becomes unactionable and the omission is silent.
                "$expand": "evidence",
            },
            headers={"Accept": "application/json"},
        )
        out: list[dict[str, Any]] = []
        async for page in self.paginate(
            request, records_at=("value",), next_url=self._next_link
        ):
            for record in page:
                self.note_record_time(parse_iso8601(record.get("lastUpdateTime")))
                payload = self.map_record(record)
                if payload is not None:
                    out.append(payload)
        return out

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        alert_id = str(record.get("id") or "")
        payload = self._base_payload(
            uid=alert_id,
            time_value=record.get("alertCreationTime") or record.get("lastUpdateTime"),
            log_name="alerts",
            record=record,
        )
        payload["class_uid"] = int(ClassUid.DETECTION_FINDING)
        # A vendor detection product raised this, which is what `is_alert` means. Set on
        # every record from this connector and on nothing from the hunting one, because
        # a DeviceProcessEvents row is an observation and not an alert — the distinction
        # is what stops a hunt over raw telemetry from inflating the alert-volume metric.
        payload["is_alert"] = True

        status_word = str(record.get("status") or "").strip()
        status = _ALERT_STATUS.get(status_word.lower().replace("_", ""))
        # The lifecycle sighting. Close (3) is decided by the status rather than by
        # whether this is a re-delivery, because an alert can arrive already-resolved:
        # AIR resolves faster than a five-minute poll cycle.
        if status is FindingStatus.RESOLVED:
            payload["activity_id"] = 3
        elif alert_id and alert_id in self._seen_alerts:
            payload["activity_id"] = 2
        else:
            payload["activity_id"] = 1
        if alert_id:
            self._seen_alerts.add(alert_id)
        payload["activity_name"] = f"alert {status_word or 'Unknown'}"
        payload["status_id"] = int(status if status is not None else FindingStatus.UNKNOWN)
        if status is None and status_word:
            put(payload, "status_code", status_word)
            note(
                payload,
                f"{self.name}: alert status {status_word!r} is not in this connector's "
                "lifecycle table, so status_id is Unknown rather than a guess — the "
                "vendor word is in status_code",
            )

        # `severity` here is an assessment by a detection product, not a log level, so
        # unlike Okta's it *is* the OCSF severity.
        payload["severity_id"] = int(severity_from_name(record.get("severity")))
        stash(payload, "defender_severity", record.get("severity"))

        self._fill_finding(payload, record)
        self._fill_verdict(payload, record)
        self._fill_device(
            payload,
            device_id=record.get("machineId"),
            hostname=record.get("computerDnsName"),
            aad_device_id=record.get("aadDeviceId"),
            rbac_group=record.get("rbacGroupName"),
        )
        self._fill_actor(payload, record)
        self._fill_attack(payload, record)
        self._fill_evidence(payload, record)
        self._fill_investigation(payload, record)
        return payload

    def _fill_finding(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        put(payload, "finding_uid", record.get("id"))
        put(payload, "finding_title", record.get("title"), limit=MESSAGE_LIMIT)
        put(payload, "finding_desc", record.get("description"))
        put(payload, "message", record.get("title"), limit=MESSAGE_LIMIT)
        put(payload, "finding_created_time", parse_iso8601(record.get("alertCreationTime")))
        put(payload, "finding_modified_time", parse_iso8601(record.get("lastUpdateTime")))
        # firstEventTime/lastEventTime are when the *activity* happened, which for a
        # detection that fired on a behavioural pattern can be well before the alert.
        # This is what dwell-time metrics need and it is not the alert's own timestamp.
        put(payload, "finding_first_seen_time", parse_iso8601(record.get("firstEventTime")))
        put(payload, "finding_last_seen_time", parse_iso8601(record.get("lastEventTime")))
        types = [t for t in (record.get("category"), record.get("threatFamilyName")) if t]
        put(payload, "finding_types", types)
        put(payload, "finding_analytic_uid", record.get("detectorId"))
        put(
            payload,
            "finding_src_url",
            f"https://security.microsoft.com/alerts/{record.get('id')}"
            if record.get("id")
            else None,
        )

        source_raw = str(record.get("detectionSource") or "")
        source = _DETECTION_SOURCE.get(source_raw.lower().replace(" ", "").replace("_", ""))
        if source:
            name, type_id, tag = source
            payload["finding_analytic_name"] = name
            payload["finding_analytic_type_id"] = type_id
            if tag:
                label(payload, tag)
        elif source_raw:
            payload["finding_analytic_name"] = source_raw
            payload["finding_analytic_type_id"] = 99
            note(
                payload,
                f"{self.name}: detectionSource {source_raw!r} is not in this "
                "connector's table, so its analytic type is Other — a signature hit "
                "and a behavioural detection need different responses and this one "
                "cannot be told apart from either",
            )
        if source_raw.lower().replace(" ", "") in VENDOR_ACTION_SOURCES:
            self.vendor_action_alerts += 1
            note(
                payload,
                f"{self.name}: this alert was raised by Defender's Automated "
                "Investigation describing its own remediation, not by a detection of "
                "adversary activity — it should not be counted as an intrusion or "
                "responded to, and the alert it remediated is a separate record",
            )
        # serviceSource says which Defender product owns the alert, which is how an
        # endpoint alert is told from an Office 365 or Cloud Apps one on the same feed.
        stash(payload, "service_source", record.get("serviceSource"))
        stash(payload, "threat_name", record.get("threatName"))
        stash(payload, "threat_family", record.get("threatFamilyName"))
        if record.get("threatFamilyName"):
            label(payload, f"malware-family:{record['threatFamilyName']}")

    def _fill_verdict(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """Microsoft's own disposition, carried through rather than re-derived.

        The one exception to this platform's rule that a connector reports and triage
        disposes — and it earns the exception by being a verdict a *human with the
        machine in front of them* already reached. Re-raising an alert a customer's
        analyst closed as a false positive is how a SOC platform loses its welcome.
        """
        classification = str(record.get("classification") or "")
        key = classification.lower().replace(" ", "").replace("_", "")
        if key in _CLASSIFICATION:
            payload["verdict_id"] = _CLASSIFICATION[key]
            stash(payload, "defender_classification", classification)
        elif classification:
            note(
                payload,
                f"{self.name}: classification {classification!r} is not in this "
                "connector's verdict table, so verdict_id is left unset rather than "
                "guessed — an unset verdict routes to triage, a wrong one does not",
            )
            stash(payload, "defender_classification", classification)

        determination = str(record.get("determination") or "")
        det_key = determination.lower().replace(" ", "").replace("_", "")
        if det_key in _DETERMINATION:
            tag = _DETERMINATION[det_key]
            if tag:
                label(payload, tag)
        elif determination:
            note(
                payload,
                f"{self.name}: determination {determination!r} is not in this "
                "connector's table; it is in unmapped.defender_determination",
            )
        stash(payload, "defender_determination", determination)
        if det_key in NO_RESPONSE_DETERMINATIONS:
            self.no_response_alerts += 1
            label(payload, "no-autonomous-response")
            note(
                payload,
                f"{self.name}: determination {determination!r} means this activity is "
                "authorised — the safety envelope must treat it as a hard stop on "
                "response, not as a low score that a high severity can outvote",
            )
        # A true positive that is still New is the highest-value row on this feed: it is
        # confirmed and nobody has acted on it.
        if payload.get("verdict_id") == 2 and payload.get("status_id") == int(
            FindingStatus.NEW
        ):
            label(payload, "confirmed-unactioned")

    def _fill_actor(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """``relatedUser`` → ``actor_user_*``, because 2004 declares no ``user``.

        Measured, not assumed: 2004's declared objects include ``actor`` and not
        ``user``, so a ``user_name`` written here would be swept to ``unmapped`` and
        reported as this connector's mapping error. The per-entity accounts are in the
        evidence array, where the class does declare a home for them.
        """
        related = record.get("relatedUser")
        if isinstance(related, Mapping):
            put(payload, "actor_user_name", related.get("userName"))
            put(payload, "actor_user_domain", related.get("domainName"))
            domain, name = related.get("domainName"), related.get("userName")
            if domain and name:
                stash(payload, "related_user_upn", f"{domain}\\{name}")
        # `assignedTo` is the *analyst*, not the subject — a UPN in the same shape as an
        # account, which is exactly why it is not written to any user field. It goes to
        # `comment`, which 2004 declares, so a case timeline can show who owned it.
        assigned = record.get("assignedTo")
        if assigned:
            put(payload, "comment", f"assigned to {assigned}")
            stash(payload, "assigned_to", assigned)

    def _fill_attack(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """Techniques from the alert where Defender names them, tactics where it does not."""
        techniques = [
            str(t).strip()
            for t in (record.get("mitreTechniques") or [])
            if str(t or "").strip()
        ]
        if techniques:
            attack(payload, *techniques)
        category = str(record.get("category") or "")
        key = category.lower().replace(" ", "").replace("-", "")
        if key in _CATEGORY_TACTIC:
            label(payload, f"tactic:{_CATEGORY_TACTIC[key]}")
        elif key in _CATEGORY_LABEL:
            label(payload, _CATEGORY_LABEL[key])
        elif category:
            note(
                payload,
                f"{self.name}: alert category {category!r} maps to neither an ATT&CK "
                "tactic nor a known label in this connector, so the coverage matrix "
                "will not count it — it is in finding_types",
            )
        if not techniques and category:
            note(
                payload,
                f"{self.name}: this alert carries no mitreTechniques, so its ATT&CK "
                f"position is the {category!r} category alone — a tactic, not a "
                "technique, and the coverage matrix should count it as such",
            )

    def _fill_evidence(self, payload: dict[str, Any], record: Mapping[str, Any]) -> None:
        """``evidence[]`` → 2004's ``evidences``, plus ``resources`` for the cloud ones.

        Every one of these entities would be illegal as a flat column on 2004 — no
        ``file``, no ``process``, no ``user``, no ``src_endpoint`` at the top level — so
        the nested array is not a stylistic choice, it is the only conformant home.
        """
        raw_evidence = record.get("evidence")
        if not isinstance(raw_evidence, list):
            if raw_evidence is None:
                note(
                    payload,
                    f"{self.name}: this alert carries no evidence array, which usually "
                    "means the request omitted $expand=evidence — without it an alert "
                    "is a title with no file hash, process, account or address, and "
                    "nothing downstream can pivot on it",
                )
            return

        items: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        unknown_types: list[str] = []
        for entity in raw_evidence:
            if not isinstance(entity, Mapping):
                continue
            kind = str(entity.get("entityType") or "")
            key = _EVIDENCE_KEY.get(kind.lower().replace(" ", "").replace("_", ""))
            if key is None:
                if kind and kind not in unknown_types:
                    unknown_types.append(kind)
                continue
            if key == "resources":
                ref = resource_ref(
                    uid=entity.get("resourceId") or entity.get("aadUserId"),
                    name=entity.get("resourceName") or entity.get("applicationName"),
                    type=kind,
                )
                if ref:
                    resources.append(ref)
                continue
            built = self._evidence_element(key, entity)
            if built:
                items.append(built)

        if items:
            payload["evidences"] = items
        if resources:
            payload["resources"] = resources
        if unknown_types:
            note(
                payload,
                f"{self.name}: evidence entityType(s) {', '.join(sorted(unknown_types))} "
                "are not in this connector's table, so they are in unmapped.raw only — "
                "they are not in evidences and no hunt query will find them",
            )
        # detectionStatus is per-entity and is the difference between "this file was
        # blocked" and "this file ran". It is folded into each element below, and the
        # count of entities Defender says it *prevented* is what decides whether a
        # response is still needed at all.
        prevented = sum(
            1
            for e in raw_evidence
            if isinstance(e, Mapping)
            and str(e.get("detectionStatus") or "").lower() in ("prevented", "blocked")
        )
        if prevented:
            stash(payload, "entities_prevented", prevented)
            label(payload, "partially-prevented")

    def _evidence_element(
        self, key: str, entity: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """One ``evidences`` element, in the sub-object shape OCSF declares for it."""
        detail: dict[str, Any] = {}
        if key == "file":
            detail = {
                "name": entity.get("fileName"),
                "path": entity.get("filePath"),
                "hashes": [
                    h
                    for h in (
                        {"algorithm_id": 3, "value": entity.get("sha256")}
                        if entity.get("sha256")
                        else None,
                        {"algorithm_id": 2, "value": entity.get("sha1")}
                        if entity.get("sha1")
                        else None,
                    )
                    if h
                ],
            }
        elif key == "process":
            detail = {
                "pid": entity.get("processId"),
                "cmd_line": entity.get("processCommandLine"),
                "created_time": parse_iso8601(entity.get("processCreationTime")),
                "file": prune(
                    {
                        "name": entity.get("fileName"),
                        "path": entity.get("filePath"),
                        "hashes": [{"algorithm_id": 3, "value": entity["sha256"]}]
                        if entity.get("sha256")
                        else [],
                    }
                ),
                "parent_process": prune(
                    {
                        "pid": entity.get("parentProcessId"),
                        "created_time": parse_iso8601(
                            entity.get("parentProcessCreationTime")
                        ),
                        "file": prune(
                            {
                                "name": entity.get("parentProcessFileName"),
                                "path": entity.get("parentProcessFilePath"),
                            }
                        ),
                    }
                ),
            }
        elif key == "user":
            detail = {
                "name": entity.get("accountName"),
                "domain": entity.get("domainName"),
                "uid": entity.get("aadUserId") or entity.get("userSid"),
                "email_addr": entity.get("userPrincipalName"),
            }
        elif key == "src_endpoint":
            detail = {"ip": entity.get("ipAddress")}
        elif key == "url":
            detail = {"url_string": entity.get("url")}
        elif key == "reg_key":
            detail = {
                "path": entity.get("registryKey"),
                "hive": entity.get("registryHive"),
            }
        elif key == "reg_value":
            detail = {
                "name": entity.get("registryValueName"),
                "data": entity.get("registryValue"),
                "type": entity.get("registryValueType"),
            }
        elif key == "email":
            detail = {
                "subject": entity.get("subject"),
                "from": entity.get("sender") or entity.get("p1Sender"),
                "to": [entity["recipient"]] if entity.get("recipient") else [],
                "message_uid": entity.get("networkMessageId"),
            }
        elif key == "device":
            detail = {
                "uid": entity.get("deviceId"),
                "hostname": entity.get("deviceDnsName") or entity.get("hostName"),
            }
        elif key == "container":
            detail = {
                "name": entity.get("containerName") or entity.get("imageName"),
                "uid": entity.get("containerId"),
            }
        cleaned = prune({key: detail})
        if not cleaned:
            return None
        # Defender's own per-entity outcome. `verdict` on an evidences element is a
        # string in OCSF and this is the vendor's word, not a mapped enum — the mapped
        # one is on the finding.
        status = entity.get("detectionStatus")
        return evidence(**cleaned, **({"verdict": str(status)} if status else {}))

    def _fill_investigation(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """Defender's own clustering and remediation state — free correlation.

        ``incidentId`` is the single most valuable field on this record for Phase 3:
        Microsoft has already decided which alerts belong together, across endpoint,
        identity, email and cloud apps. Discarding it and re-deriving the cluster from
        entity overlap would be re-solving a solved problem with less data.
        """
        incident = record.get("incidentId")
        if incident not in (None, ""):
            payload["metadata_correlation_uid"] = f"defender-incident:{incident}"
            stash(payload, "incident_id", incident)
        stash(payload, "investigation_id", record.get("investigationId"))
        state = record.get("investigationState")
        stash(payload, "investigation_state", state)
        if state and str(state).lower().replace(" ", "") in (
            "running",
            "pendingapproval",
            "pendingresource",
        ):
            label(payload, "vendor-investigation-in-flight")
            note(
                payload,
                f"{self.name}: Defender's own Automated Investigation is still "
                f"{state!r} on this alert — acting now can collide with a remediation "
                "already in progress, and the two are not coordinated",
            )
        resolved = parse_iso8601(record.get("resolvedTime"))
        if resolved is not None:
            stash(payload, "resolved_time", resolved)
            created = parse_iso8601(record.get("alertCreationTime"))
            if created is not None and resolved >= created:
                # Microsoft's own time-to-resolve for this alert. A real MTTR data point
                # from a mature SOC, and the baseline this platform's own MTTR is worth
                # comparing against.
                stash(payload, "vendor_resolve_seconds", round(resolved - created, 3))

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        out["alerts_tracked"] = len(self._seen_alerts)
        if self.vendor_action_alerts:
            out["vendor_remediation_alerts"] = self.vendor_action_alerts
        if self.no_response_alerts:
            out["response_forbidden_alerts"] = self.no_response_alerts
        return out


class DefenderHuntingConnector(DefenderConnector):
    """Advanced hunting over the four device tables → 1007 / 4001 / 3002 / 1001."""

    name = "defender_hunting"
    description = (
        "Defender advanced hunting: process, network, logon and file telemetry from "
        "every managed endpoint"
    )
    detects = (
        "the activity underneath the alerts — LOLBin execution, beaconing to an "
        "unresolved address, lateral logons, ransomware-shaped file rewrites — and it "
        "is what makes an alert investigable without an agent on the box"
    )
    spec = ConnectorSpec(
        # The KQL `take` per query, not an HTTP page size: this API has no pagination.
        # 8,000 is well under the documented 100,000-row / 124 MB response ceiling, and
        # low enough that four of them in one window stay inside the per-hour runtime
        # budget on a large tenant.
        page_size=8_000,
        # 15 calls/minute *tenant-wide across every caller*. A pack of four per cycle at
        # 0.25/s cannot exceed it even if the cadence collapses to zero, which is what
        # matters — the catch-up path polls without delay.
        rate_per_second=0.25,
        burst=2,
        # Advanced hunting is a near-real-time index and the documented lag is minutes.
        indexing_lag_seconds=300.0,
        overlap_seconds=300.0,
        # 30 minutes, deliberately small: the row cap is per query, so a wide window on
        # a busy tenant truncates instead of erroring, and truncation is invisible in
        # the data. Narrow windows trade more calls for a complete answer.
        max_window_seconds=1_800.0,
        docs_url="https://learn.microsoft.com/defender-endpoint/api/run-advanced-query-api",
        required_grants=(
            "AdvancedQuery.Read.All (application permission)",
            "admin consent",
            "a Defender for Endpoint P2 licence — P1 has no advanced hunting and the "
            "endpoint returns 403",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Per-table row counts for the last window, reported in the health line so a
        #: table that has silently stopped returning rows is visible.
        self.table_rows: dict[str, int] = {}
        #: Tables whose last window hit the row cap.
        self.truncated_tables: list[str] = []

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, end = window.iso()
        out: list[dict[str, Any]] = []
        self.table_rows = {}
        self.truncated_tables = []
        for query in HUNTING_PACK:
            rows = await self._run(query, start, end)
            self.table_rows[query.table] = len(rows)
            if len(rows) >= self.spec.page_size:
                self.truncated_tables.append(query.table)
                self.page_cap_hits += 1
            mapper = getattr(self, query.mapper)
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                self.note_record_time(parse_iso8601(row.get("Timestamp")))
                payload = mapper(row, query)
                if payload is not None:
                    out.append(payload)
        return out

    async def _run(
        self, query: HuntingQuery, start: str, end: str
    ) -> list[dict[str, Any]]:
        kql = query.kql.format(
            start=_KQL_TIME.format(start),
            end=_KQL_TIME.format(end),
            take=self.spec.page_size,
        )
        request = Request(
            "POST",
            f"{self.base_url()}{HUNTING_PATH}",
            label=f"{self.name}.{query.table}",
            json_body={"Query": kql},
            headers={"Accept": "application/json"},
        )
        response = await self.client().send(request)
        body = response.json()
        # `Results`, and the fallback is not cosmetic: a query that returns no rows
        # returns `Results: []`, while a *malformed* query returns 400 with an `error`
        # object and no Results key at all — which `normalise_records` would render as
        # zero rows, indistinguishable from a quiet tenant. `ApiClient.send` raises on
        # 400 before this line, so reaching here with no Results means the shape changed.
        if isinstance(body, Mapping) and "Results" not in body:
            raise RuntimeError(
                f"{self.name}: advanced hunting returned no Results key for "
                f"{query.table} — the response shape has changed and the rows this "
                f"window would have produced are lost, not empty. Keys: "
                f"{sorted(body)[:8]}"
            )
        return normalise_records(body, "Results")

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        # The pack dispatches per table; a single-record entry point cannot know which
        # table a row came from, and guessing from its columns is how a DeviceFileEvents
        # row with an InitiatingProcess becomes a process event.
        raise NotImplementedError(
            f"{self.name} maps per hunting table; use the pack's own mappers"
        )

    def _hunt_payload(
        self, row: Mapping[str, Any], query: HuntingQuery
    ) -> dict[str, Any]:
        payload = self._base_payload(
            # `ReportId` is unique only within one table for one (Timestamp, DeviceId),
            # so all four parts are needed. Measured, not assumed: with the table name
            # omitted, a DeviceProcessEvents row and a DeviceFileEvents row from the same
            # device and second produced *byte-identical* uids in test, which dedup would
            # have collapsed into one record — losing whichever arrived second, silently,
            # and only on the busy devices where both tables fire in the same second.
            uid=f"{query.table}:{row.get('DeviceId') or 'unknown'}:"
            f"{row.get('Timestamp')}:{row.get('ReportId')}",
            time_value=row.get("Timestamp"),
            log_name=query.table,
            record=row,
        )
        payload["class_uid"] = query.class_uid
        self._fill_device(
            payload, device_id=row.get("DeviceId"), hostname=row.get("DeviceName")
        )
        stash(payload, "action_type", row.get("ActionType"))
        return payload

    def _fill_initiating_process(
        self, payload: dict[str, Any], row: Mapping[str, Any]
    ) -> None:
        """``InitiatingProcess*`` → ``actor_process_*``, which every one of these classes declares.

        Deliberately not ``process_*``: 4001 and 1001 declare no top-level ``process``
        at all — measured — and on 1007 ``process_*`` is the process that was *created*.
        Putting the initiator there would make every parent look like a child.
        """
        put(payload, "actor_process_pid", row.get("InitiatingProcessId"))
        put(payload, "actor_process_name", row.get("InitiatingProcessFileName"))
        put(payload, "actor_process_cmd_line", row.get("InitiatingProcessCommandLine"))
        put(payload, "actor_process_file_name", row.get("InitiatingProcessFileName"))
        folder = row.get("InitiatingProcessFolderPath")
        put(payload, "actor_process_file_path", folder)
        put(payload, "actor_process_path", folder)
        put(payload, "actor_process_file_sha256", row.get("InitiatingProcessSHA256"))
        put(payload, "actor_process_parent_pid", row.get("InitiatingProcessParentId"))
        put(
            payload,
            "actor_process_parent_name",
            row.get("InitiatingProcessParentFileName"),
        )
        put(payload, "actor_user_name", row.get("InitiatingProcessAccountName"))
        put(payload, "actor_user_domain", row.get("InitiatingProcessAccountDomain"))

    def _map_process(
        self, row: Mapping[str, Any], query: HuntingQuery
    ) -> dict[str, Any] | None:
        payload = self._hunt_payload(row, query)
        action = str(row.get("ActionType") or "")
        payload["activity_id"] = 1 if action == "ProcessCreated" else 99
        payload["activity_name"] = action or "ProcessCreated"
        put(payload, "process_pid", row.get("ProcessId"))
        put(payload, "process_name", row.get("FileName"))
        put(payload, "process_cmd_line", row.get("ProcessCommandLine"))
        put(payload, "process_file_name", row.get("FileName"))
        put(payload, "process_file_path", row.get("FolderPath"))
        put(payload, "process_path", row.get("FolderPath"))
        put(payload, "process_file_sha256", row.get("SHA256"))
        put(payload, "process_created_time", parse_iso8601(row.get("ProcessCreationTime")))
        self._fill_integrity(payload, row.get("ProcessIntegrityLevel"))
        self._fill_initiating_process(payload, row)
        # 1007 declares `actor` and not `user`, so the account that ran the process is
        # actor_user_*. The initiating process's account is the same person in almost
        # every case; where the row carries its own AccountName it is more precise, so
        # it wins.
        put(payload, "actor_user_name", row.get("AccountName"))
        put(payload, "actor_user_domain", row.get("AccountDomain"))
        put(payload, "actor_user_uid", row.get("AccountSid"))
        put(payload, "process_parent_pid", row.get("InitiatingProcessId"))
        put(payload, "process_parent_name", row.get("InitiatingProcessFileName"))
        payload["status_id"] = int(Status.SUCCESS)
        return payload

    def _fill_integrity(self, payload: dict[str, Any], level: Any) -> None:
        """Windows integrity level → OCSF ``process.integrity_id``.

        Worth mapping rather than stashing because *System* and *High* are the
        difference between a process that has already escalated and one that has not,
        and that is the single most common pivot after a suspicious command line.
        """
        table = {
            "untrusted": 1,
            "low": 2,
            "medium": 3,
            "high": 4,
            "system": 5,
        }
        key = str(level or "").strip().lower()
        if key in table:
            payload["process_integrity_id"] = table[key]
            if key in ("high", "system"):
                label(payload, f"integrity:{key}")
        elif key:
            stash(payload, "process_integrity_level", level)

    def _map_network(
        self, row: Mapping[str, Any], query: HuntingQuery
    ) -> dict[str, Any] | None:
        payload = self._hunt_payload(row, query)
        action = str(row.get("ActionType") or "")
        key = action.lower().replace(" ", "")
        payload["activity_id"] = _NETWORK_ACTIONS.get(key, 99)
        payload["activity_name"] = action or "ConnectionSuccess"
        if key not in _NETWORK_ACTIONS and action:
            note(
                payload,
                f"{self.name}: DeviceNetworkEvents ActionType {action!r} is not in "
                "this connector's table, so the activity is Other — the vendor word is "
                "in activity_name and unmapped.action_type",
            )
        payload["status_id"] = int(
            Status.FAILURE if key in ("connectionfailed",) else Status.SUCCESS
        )
        set_ip(payload, "src_endpoint_ip", row.get("LocalIP"))
        put(payload, "src_endpoint_port", row.get("LocalPort"))
        set_ip(payload, "dst_endpoint_ip", row.get("RemoteIP"))
        put(payload, "dst_endpoint_port", row.get("RemotePort"))
        # RemoteUrl is a URL on some rows and a bare hostname on others. Only the
        # hostname form goes to dst_endpoint_domain; a full URL would put a scheme and
        # path into a domain column, where every DNS join would miss it.
        remote = str(row.get("RemoteUrl") or "")
        if remote and "://" not in remote and "/" not in remote:
            put(payload, "dst_endpoint_domain", remote)
        elif remote:
            stash(payload, "remote_url", remote)
        put(payload, "connection_protocol_name", row.get("Protocol"))
        self._fill_initiating_process(payload, row)
        return payload

    def _map_logon(
        self, row: Mapping[str, Any], query: HuntingQuery
    ) -> dict[str, Any] | None:
        payload = self._hunt_payload(row, query)
        action = str(row.get("ActionType") or "")
        payload["activity_id"] = 1
        payload["activity_name"] = action or "LogonSuccess"
        failed = action.lower() in ("logonfailed", "logonattempted")
        payload["status_id"] = int(Status.FAILURE if failed else Status.SUCCESS)
        if failed:
            put(payload, "status_detail", row.get("FailureReason"))
            put(payload, "status_code", row.get("FailureReason"))
        # 3002 requires `user` and declares it, unlike every other class in this pack.
        put(payload, "user_name", row.get("AccountName"))
        put(payload, "user_domain", row.get("AccountDomain"))
        put(payload, "user_uid", row.get("AccountSid"))
        logon = str(row.get("LogonType") or "").strip().lower().replace(" ", "")
        mapped = _LOGON_TYPES.get(logon)
        if mapped:
            payload["logon_type_id"], payload["logon_type"] = mapped
            if mapped[0] in (3, 8, 10):
                payload["is_remote"] = True
            if mapped[0] == 8:
                # Network Cleartext: the password crossed the wire recoverable. This is
                # basic auth over IIS or an unencrypted LDAP bind, and it is a finding
                # in its own right rather than a property of this logon.
                payload["is_cleartext"] = True
                attack(payload, "T1040")
                label(payload, "cleartext-logon")
        elif logon:
            stash(payload, "defender_logon_type", row.get("LogonType"))
            note(
                payload,
                f"{self.name}: LogonType {row.get('LogonType')!r} has no OCSF member, "
                "so logon_type_id is unset rather than 0 — 0 is *System* on this "
                "class's table, which would be a false claim rather than a gap",
            )
        set_ip(payload, "src_endpoint_ip", row.get("RemoteIP"))
        put(payload, "src_endpoint_hostname", row.get("RemoteDeviceName"))
        put(payload, "auth_protocol", row.get("Protocol"))
        admin = as_bool(row.get("IsLocalAdmin"))
        if admin is not None:
            stash(payload, "is_local_admin", admin)
            if admin:
                label(payload, "local-admin-logon")
        put(payload, "logon_process_name", row.get("InitiatingProcessFileName"))
        return payload

    def _map_file(
        self, row: Mapping[str, Any], query: HuntingQuery
    ) -> dict[str, Any] | None:
        payload = self._hunt_payload(row, query)
        action = str(row.get("ActionType") or "")
        key = action.lower().replace(" ", "")
        payload["activity_id"] = _FILE_ACTIONS.get(key, 99)
        payload["activity_name"] = action or "FileCreated"
        payload["status_id"] = int(Status.SUCCESS)
        put(payload, "file_name", row.get("FileName"))
        put(payload, "file_path", row.get("FolderPath"))
        put(payload, "file_sha256", row.get("SHA256"))
        put(payload, "file_md5", row.get("MD5"))
        put(payload, "file_size", row.get("FileSize"))
        self._fill_initiating_process(payload, row)
        return payload

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        for table, count in self.table_rows.items():
            out[f"rows_{table}"] = count
        if self.truncated_tables:
            out["truncated"] = (
                f"{', '.join(self.truncated_tables)} hit the {self.spec.page_size}-row "
                "cap — this window is a sample, not a complete answer"
            )
        # Named unconditionally, because a table that returns zero rows every cycle is
        # either a tenant with no such activity or a schema change, and the health
        # report cannot tell them apart without seeing the zero.
        empty = [q.table for q in HUNTING_PACK if not self.table_rows.get(q.table)]
        if empty and self.table_rows:
            out["empty_tables"] = ", ".join(empty)
        return out


def defender_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[DefenderConnector]:
    """Both Defender connectors, alerts first — it is the higher-value stream."""
    return [
        DefenderAlertConnector(pipeline, config, **kwargs),
        DefenderHuntingConnector(pipeline, config, **kwargs),
    ]


__all__ = [
    "ALERTS_PATH",
    "HUNTING_PACK",
    "HUNTING_PATH",
    "NO_RESPONSE_DETERMINATIONS",
    "VENDOR_ACTION_SOURCES",
    "DefenderAlertConnector",
    "DefenderConnector",
    "DefenderHuntingConnector",
    "HuntingQuery",
    "defender_connectors",
]

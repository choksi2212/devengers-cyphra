"""OCSF-aligned normalised event schema — the contract every collector must meet.

CYPHRA normalises everything it ingests — packet flows, Windows Event Log records,
Sysmon, Entra sign-ins, CloudTrail, Okta system log — into one event model before
anything else looks at it. Without that, every downstream module has to know every
source's private shape, and a detection rule written against Sysmon silently fails
to match the same behaviour as seen by CrowdStrike.

The model is aligned to **OCSF** (Open Cybersecurity Schema Framework) rather than
invented, because OCSF already answers the questions that otherwise get argued
about forever: which field carries the acting user versus the affected user,
whether a process-creation event names the parent under ``process`` or under
``actor.process``, what a failed logon's outcome is called. Every class id,
activity id, enum value and field path in this module is taken from the schema
server (``schema.ocsf.io``) and vendored into ``vendor/ocsf/ocsf_index.json``.
``tests/scratch_ocsf.py`` asserts that every enum member and every entry in
:data:`OCSF_PATH` still agrees with that vendored schema — so "OCSF-aligned" is a
claim this repository can check, not a label it awards itself.

Four decisions worth knowing about, each of which cost something.

**1. Flat internally, nested on export.** OCSF nests deeply
(``actor.process.file.hashes[].value``). Every hunt query, every rule field
reference and every Parquet predicate is simpler against a flat column
(``actor_process_file_sha256``), and adding a column to a flat Parquet schema is
free where evolving a struct is not. So the internal representation is flat, and
:meth:`Event.to_ocsf` emits conformant nested OCSF for anything that consumes or
shares it, with :meth:`Event.from_ocsf` reading it back. The cost is the
:data:`OCSF_PATH` table, which has to be maintained by hand — which is exactly why
the test walks every entry in it against the vendored object graph.

**2. A future timestamp is corrected; a past one is only recorded.** The two
directions are not symmetric, and treating them as if they were destroys data. An
event cannot be observed before it happens, so a time beyond the ingest clock by
more than :data:`MAX_CLOCK_SKEW_SECONDS` is *provably* a fast clock or a unit bug:
left alone it writes into a future partition that a hunt over "yesterday" cannot
see and retention will not expire for years. That one is rewritten to the ingest
time — the only clock the platform controls — with the source's value preserved
verbatim in ``metadata_original_time`` and ``soc_time_corrected`` set.

A time *behind* the ingest clock proves nothing of the kind. Cloud audit APIs
publish minutes to hours late by design, an agent that spooled through a network
outage ships its backlog on reconnect, and a backfill import is deliberately
historical. Every one of those is a correct event that is merely late, so its time
is kept as stated and the lateness is recorded in ``soc_time_skew_seconds`` (which
is negative) plus a note once it exceeds tolerance. Rewriting it instead would
fabricate a timeline: an intrusion that happened at 02:00 and arrived at 05:00
would be recorded as happening at 05:00, and a connector whose cursor froze — the
one fault that produces nothing *but* old events — would look perfectly fresh to
every monitor. Whether a given lag is acceptable is a per-source policy question
with an on-call consequence, so it is answered once, in ``ingest.health``, and not
by silently editing the field the whole platform reasons on.

The floor at :data:`MIN_PLAUSIBLE_TIME` is what still catches the past-time bugs
that *are* provable — a zero, a null coerced to zero, a millisecond value read as
seconds — and it is checked before any of this.

**3. Deduplication is only exact when the source provides an id.** The agent
protocol spools on disconnect and retries, which makes delivery at-least-once. If
the source names its own event (Windows ``EventRecordID``, Okta event ``uuid``,
CloudTrail ``eventID``) then ``soc_event_id`` is a hash of source plus that id, a
retry collapses onto the same row, and ``soc_dedup_exact`` is true. If it does not,
the id has to include the raw payload and the capture time, two genuinely distinct
events that are byte-identical in the same instant are indistinguishable, and
``soc_dedup_exact`` is false. That flag matters downstream: an alert count is only
exactly correct for the sources that carry real ids, and a metric that claims
otherwise is lying. Batch-level idempotency in the agent protocol is what actually
protects the rest.

**4. The raw payload is hashed always, stored optionally.** ``soc_raw_sha256`` is
computed for every event, so chain-of-custody can prove an artifact matches what
was ingested. Keeping every raw payload as well would roughly double the lake, so
``soc_raw`` is populated only when the source is configured to retain it — for
example while a case is open. The hash without the payload still proves a later
copy is authentic; it just cannot reconstruct one.

Registry classes (201001/201002) and the other ``win`` extension classes are part
of the index: Sysmon's registry events have no home in core OCSF, and dropping
them would make persistence detection impossible on the platform CYPHRA runs on.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Mapping

import pyarrow as pa
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

# ── constants ───────────────────────────────────────────────────────────────

#: Bumped whenever the vendored index layout changes incompatibly.
#: 2 added ``class_enums`` — every class-level ``*_id`` enum, which v1 omitted.
INDEX_VERSION = 2

#: CYPHRA's own envelope version, stored on every event. A stored event says which
#: normaliser wrote it, so a replay years later is interpreted by the right rules
#: rather than by whatever the code happens to look like then.
SCHEMA_VERSION = 1

DEFAULT_INDEX = Path(__file__).resolve().parents[2] / "vendor" / "ocsf" / "ocsf_index.json"

#: Beyond an hour of disagreement between an event's own clock and the ingest
#: clock, the event's clock is not believed for partitioning. An hour is generous
#: enough to absorb a missed DST correction or a stale NTP sync without touching
#: anything, and tight enough that a genuinely wrong clock is caught the same day.
MAX_CLOCK_SKEW_SECONDS = 3600.0

#: Events claiming a time before this are rejected outright rather than corrected:
#: 2000-01-01. A zero, a null coerced to zero, or a millisecond value mistaken for
#: seconds all land here, and silently rewriting them to now would erase the bug.
MIN_PLAUSIBLE_TIME = 946684800.0

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


class OcsfError(RuntimeError):
    """A schema-layer failure."""


class UnknownClass(OcsfError):
    """A class_uid that is not in the vendored OCSF schema."""


class EventRejected(OcsfError):
    """A source produced something that is not a valid event.

    Carries the source name so a rejection is actionable: "windows_eventlog
    produced an event with no time" names the collector to fix, where a bare
    pydantic traceback names only a field.
    """

    def __init__(self, source: str, reason: str, payload: Mapping[str, Any] | None = None) -> None:
        self.source = source
        self.reason = reason
        self.payload = dict(payload or {})
        super().__init__(f"{source}: {reason}")


# ── enums, mirrored from the vendored schema and verified by the test suite ──


#: Deprecated OCSF classes this repo names on purpose → why, and what replaces them.
#:
#: OCSF v1.9.0 deprecated the whole Discovery ``*_query`` family in favour of 5040
#: Live Evidence Info, and 5002 Config State in favour of 2003 Compliance Finding.
#: Measured against the vendored bundle before accepting either replacement:
#:
#: * **5040 requires** ``query_evidence``, ``query_result_id``, ``cloud``, ``osint``
#:   and ``device``, and **declares no** ``session``, ``group`` or ``users``. It is
#:   built for an EDR live-query response, where the evidence is one opaque nested
#:   blob the platform round-trips without understanding. CYPHRA's premise is the
#:   opposite — flat, individually queryable columns, so a hunt can say
#:   ``WHERE session.uid = …`` without unpacking anything. Migrating would mean either
#:   burying the session table and group membership inside ``query_evidence``, which
#:   loses exactly the queryability the snapshot exists to provide, or emitting a 5040
#:   missing three of its own required attributes. The deprecated classes still
#:   validate, and they declare the attributes the data actually has: 5017 declares
#:   ``session``, 5009 declares ``group`` and ``users``.
#: * **2003 Compliance Finding** is the right eventual home for the account-policy
#:   snapshot, and 5002's data is already half of one — :data:`POLICY_FINDINGS` in
#:   :mod:`ingest.collectors.local_auth` computes five weakness predicates with their
#:   own severity floors. But a Finding asserts a pass/fail against a *named control*,
#:   and the control mappings live in the compliance module (SOC2/ISO/PCI/CIS), which
#:   does not exist yet. Emitting a 2003 with no control attached would be a finding
#:   about nothing.
#:
#: A blanket "no deprecated classes" rule would be satisfied by choosing a worse
#: class, which is why the test asserts against this table instead: every deprecated
#: class named in :class:`ClassUid` must appear here with a reason, and every entry
#: here must still be deprecated. Adding one thoughtlessly fails; so does leaving a
#: stale justification behind after OCSF un-deprecates something.
DEPRECATED_CLASS_USE: dict[int, str] = {
    5002: (
        "Account-policy snapshot. OCSF points at 2003 compliance_finding; adopt that "
        "in Phase 8 once the compliance module owns control mappings, since a Finding "
        "with no named control is a finding about nothing. POLICY_FINDINGS already "
        "computes the pass/fail half."
    ),
    5009: (
        "Privileged-group membership snapshot. OCSF points at 5040 evidence_info, "
        "which declares neither `group` nor `users` and would require burying both in "
        "`query_evidence`. 5009 declares `group` and `query_result_id`, which is the "
        "pair that distinguishes 'this privileged group does not exist here' from "
        "'it exists and I could not read it'."
    ),
    5017: (
        "Logon-session table snapshot. OCSF points at 5040 evidence_info, which "
        "declares no `session`. 5017 does, and a session-table row is the join key "
        "for every logon-correlation query."
    ),
}


class Severity(IntEnum):
    """OCSF ``severity_id``. The source's opinion, not CYPHRA's verdict.

    Kept separate from the risk score triage computes: a source calling something
    Critical is evidence, not a decision, and conflating the two is how a noisy
    vendor's default severity ends up driving autonomous response.
    """

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


class Status(IntEnum):
    """OCSF ``status_id`` on the 75 classes that use the Success/Failure table.

    A thousand Authentication events are meaningless until you know how many
    failed; brute-force detection is entirely a statement about this field.

    **Not universal, despite ``status_id`` being a base-event attribute.** Measured
    against the vendored bundle: five different tables share the name, and three of
    them collide with this one value-for-value.

    ============================  ==========================================
    Classes                       Table
    ============================  ==========================================
    75 incl. 3002/3004/3006/3007  this one — 1 Success, 2 Failure
    2002/2003/2004/2006/2007/2008 :class:`FindingStatus` — 1 New, 2 In Progress
    2005 Incident Finding         :class:`IncidentStatus` — 1 New, 2 In Progress
    7001-7004 (unmanned systems)  1 Success, 2 Failure, then 3-6 diverge
    8001                          flight status — 1 Undeclared, 2 Ground
    ============================  ==========================================

    So ``Status.SUCCESS`` on a 2004 Detection Finding does not say the detection
    succeeded — it says the finding is **New**, and ``Status.FAILURE`` says **In
    Progress**. Both are legal integers on 2004, so no validator can catch the
    substitution; the defence is using the right enum. :func:`status_enum_for` picks
    it, and 2001 Security Finding is deliberately *not* in the finding rows above —
    it kept the Success/Failure table when the rest of the 2000s moved.
    """

    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class FindingStatus(IntEnum):
    """OCSF ``status_id`` on the finding classes — a *lifecycle*, not an outcome.

    2002 Vulnerability, 2003 Compliance, 2004 Detection, 2006 Data Security,
    2007 Application Security Posture and 2008 IAM Analysis findings. This is the
    field a vendor's own triage state maps onto: Defender's ``New``/``InProgress``/
    ``Resolved`` and CrowdStrike's ``new``/``in_progress``/``closed`` are both
    exactly this table, which is why a connector must never reach for
    :class:`Status` on a 2004.
    """

    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    SUPPRESSED = 3
    RESOLVED = 4
    ARCHIVED = 5
    DELETED = 6
    OTHER = 99


class IncidentStatus(IntEnum):
    """OCSF ``status_id`` on 2005 Incident Finding — :class:`FindingStatus`, but not.

    Two members differ and neither differs harmlessly: 3 is **On Hold** where a
    finding's 3 is Suppressed, and 5 is **Closed** where a finding's 5 is Archived.
    There is no ``DELETED``. CYPHRA emits 2005 from ``correlate/incident.py``, so
    this is the table its own incident state machine maps onto.
    """

    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    ON_HOLD = 3
    RESOLVED = 4
    CLOSED = 5
    OTHER = 99


class RiskLevel(IntEnum):
    """OCSF ``risk_level_id`` — declared on all 87 classes.

    **0 is Info, not Unknown**, which is the one member of this table nobody would
    guess: every other ``*_id`` in OCSF reserves 0 for "the source did not say".
    Here 0 is a positive assertion of no risk, so defaulting an unset vendor risk to
    0 would claim the source cleared the event when it said nothing at all. Leave
    the field ``None`` instead.

    Entra's ``riskLevelDuringSignIn`` is the worked example, and it splits along
    exactly that line — ``low``/``medium``/``high`` → 1/2/3, ``unknownFutureValue``
    → 99, and then the two that look alike and are not:

    ``none``
        → ``INFO`` (0). Identity Protection ran and found nothing. That is an
        assessment, and 0 is the member that records it. This is the case the
        paragraph above *permits* rather than forbids.
    ``hidden``
        → ``None``. What Entra returns when the tenant has no Entra ID P2 licence to
        expose the value. Nothing was assessed, or nothing may be shown; either way
        the risk is unknown. Recording 99 here would assert that a level came back
        and was unrecognised, and recording 0 would report every sign-in in an
        unlicensed tenant as cleared.

    So a mapping table for this field needs three outcomes, not two: an integer, an
    explicit ``None``, and ``99``. See :mod:`ingest.connectors.entra`.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


class Verdict(IntEnum):
    """OCSF ``verdict_id`` — the finding classes' disposition of *the finding*.

    2002-2008. Distinct from :class:`DispositionId`, which says what the reporting
    control did about the activity: a control can have BLOCKED something that
    triage later calls a FALSE_POSITIVE, and both statements belong on the event.

    Defender's ``classification`` lands here — ``TruePositive`` → 2,
    ``FalsePositive`` → 1, ``InformationalExpectedActivity`` → 5 Benign (not 3
    Disregard, which means "ignore this", where Microsoft means "this is real and
    expected"). ``Unknown`` → 0.
    """

    UNKNOWN = 0
    FALSE_POSITIVE = 1
    TRUE_POSITIVE = 2
    DISREGARD = 3
    SUSPICIOUS = 4
    BENIGN = 5
    TEST = 6
    INSUFFICIENT_DATA = 7
    SECURITY_RISK = 8
    MANAGED_EXTERNALLY = 9
    DUPLICATE = 10
    OTHER = 99


class Impact(IntEnum):
    """OCSF ``impact_id`` — 2001-2008. What it would cost if the finding is real."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


class Priority(IntEnum):
    """OCSF ``priority_id`` — 2002-2008. Where the finding sits in the queue.

    Deliberately separate from :class:`Severity` (how bad the event is) and
    :class:`Impact` (what it would cost). A critical-severity finding on a
    decommissioned host is low priority, and the analyst queue in Phase 3 sorts on
    this field rather than on severity for exactly that reason.
    """

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


def status_enum_for(class_uid: int) -> type[IntEnum]:
    """The ``status_id`` enum that class actually uses.

    Five tables share the name; three collide value-for-value. Ask rather than
    assume — ``status_enum_for(2004).NEW`` reads correctly and
    ``Status.SUCCESS`` on a 2004 does not.
    """
    if class_uid == 2005:
        return IncidentStatus
    if class_uid in {2002, 2003, 2004, 2006, 2007, 2008}:
        return FindingStatus
    return Status


class QueryResultId(IntEnum):
    """OCSF ``query_result_id`` — how complete a Discovery query's answer is.

    This is the one field in OCSF that lets a collector say "I looked, and I could
    only see part of it" as *data* rather than as a footnote. It matters here because
    unelevated Windows telemetry is routinely partial in a way that looks total:
    ``LsaEnumerateLogonSessions`` returns all fourteen logon sessions on this host and
    ``LsaGetLogonSessionData`` then succeeds on two of them. A session inventory that
    reported those two and stopped would be a true statement about two sessions and a
    false one about the host. ``PARTIAL`` is the difference.

    ``DOES_NOT_EXIST`` and ``ERROR`` are kept apart for the same reason: a privileged
    local group that is absent (Windows Home has no Remote Desktop Users) and one whose
    membership could not be read are different findings with different remedies, and
    both arrive as a failed lookup.

    Unlike :class:`Severity` and :class:`Status`, this enum is **not** in the base
    event's attribute set, so before the index carried class-level enums nothing in
    the test suite could check it against schema.ocsf.io — and the hand-transcribed
    version was wrong: it stopped at ``ERROR = 4`` and missed ``UNSUPPORTED = 5``,
    which is precisely the member a Windows collector needs when a query is not
    implementable on this edition rather than failing. Values 0-4 and 99 were
    correct. The index now carries the real table for all 18 classes that declare it,
    :meth:`OcsfSchema.enum_members` reads it, and ``Event.build`` checks membership,
    so a repeat of that omission is caught at build time.
    """

    UNKNOWN = 0
    EXISTS = 1
    PARTIAL = 2
    DOES_NOT_EXIST = 3
    ERROR = 4
    UNSUPPORTED = 5
    OTHER = 99


class ActionId(IntEnum):
    """OCSF ``action_id`` — what the *reporting control* did about it."""

    UNKNOWN = 0
    ALLOWED = 1
    DENIED = 2
    OBSERVED = 3
    MODIFIED = 4
    OTHER = 99


class DispositionId(IntEnum):
    """OCSF ``disposition_id`` — the control's specific outcome."""

    UNKNOWN = 0
    ALLOWED = 1
    BLOCKED = 2
    QUARANTINED = 3
    ISOLATED = 4
    DELETED = 5
    DROPPED = 6
    CUSTOM_ACTION = 7
    APPROVED = 8
    RESTORED = 9
    EXONERATED = 10
    CORRECTED = 11
    PARTIALLY_CORRECTED = 12
    UNCORRECTED = 13
    DELAYED = 14
    DETECTED = 15
    NO_ACTION = 16
    LOGGED = 17
    TAGGED = 18
    ALERT = 19
    COUNT = 20
    RESET = 21
    CAPTCHA = 22
    CHALLENGE = 23
    ACCESS_REVOKED = 24
    REJECTED = 25
    UNAUTHORIZED = 26
    ERROR = 27
    OTHER = 99


class ConfidenceId(IntEnum):
    """OCSF ``confidence_id`` — the source's confidence, again not CYPHRA's."""

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    OTHER = 99


class ObservableTypeId(IntEnum):
    """OCSF ``observable.type_id``.

    Observables are how correlation gets its entities without every collector
    remembering to declare them: :meth:`Event.derive_observables` reads them off
    the mapped fields using :data:`_OBSERVABLE_OF`, so a new collector that fills
    ``src_endpoint_ip`` contributes to the entity graph for free.
    """

    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL_ADDRESS = 5
    URL_STRING = 6
    FILE_NAME = 7
    HASH = 8
    PROCESS_NAME = 9
    RESOURCE_UID = 10
    PORT = 11
    SUBNET = 12
    COMMAND_LINE = 13
    COUNTRY = 14
    PROCESS_ID = 15
    HTTP_USER_AGENT = 16
    CWE_UID = 17
    CVE_UID = 18
    USER_CREDENTIAL_ID = 19
    ENDPOINT = 20
    USER = 21
    EMAIL = 22
    URL = 23
    FILE = 24
    PROCESS = 25
    GEO_LOCATION = 26
    CONTAINER = 27
    REGISTRY_KEY = 28
    REGISTRY_VALUE = 29
    FINGERPRINT = 30
    USER_UID = 31
    GROUP_NAME = 32
    GROUP_UID = 33
    ACCOUNT_NAME = 34
    ACCOUNT_UID = 35
    SCRIPT_CONTENT = 36
    SERIAL_NUMBER = 37
    RESOURCE_NAME = 38
    PROCESS_ENTITY_UID = 39
    EMAIL_SUBJECT = 40
    EMAIL_UID = 41
    MESSAGE_UID = 42
    REGISTRY_VALUE_NAME = 43
    ADVISORY_UID = 44
    FILE_PATH = 45
    REGISTRY_KEY_PATH = 46
    DEVICE_UID = 47
    NETWORK_ENDPOINT_UID = 48
    IAM_ROLE_NAME = 49
    IAM_ROLE_UID = 50
    OTHER = 99


class HashAlgorithmId(IntEnum):
    """OCSF ``fingerprint.algorithm_id``, needed to emit ``file.hashes`` on export.

    The full v1.9.0 set, not only the four CYPHRA computes: an event arriving from
    Defender or CrowdStrike may carry an Imphash or a HASSH, and a fingerprint the
    schema knows about should not be flattened to ``OTHER`` on the way in.
    """

    UNKNOWN = 0
    MD5 = 1
    SHA1 = 2
    SHA256 = 3
    SHA512 = 4
    CTPH = 5
    TLSH = 6
    QUICKXORHASH = 7
    SHA224 = 8
    SHA384 = 9
    SHA512_224 = 10
    SHA512_256 = 11
    SHA3_224 = 12
    SHA3_256 = 13
    SHA3_384 = 14
    SHA3_512 = 15
    XXHASH_H3_64 = 16
    XXHASH_H3_128 = 17
    IMPHASH = 18
    NPF = 19
    HASSH = 20
    OTHER = 99


class Direction(IntEnum):
    """OCSF ``network_connection_info.direction_id``.

    ``LATERAL`` is the one that matters: an internal-to-internal connection is
    what distinguishes an intruder moving through the estate from ordinary egress,
    and it is the field most flow collectors leave unset. ``LOCAL`` is loopback —
    worth keeping distinct so host-local IPC does not inflate lateral-movement
    counts.

    This is the *network* table. 4009 Email Activity declares its own top-level
    ``direction_id`` whose member 3 is Internal, not Lateral — see
    :class:`EmailDirection`.
    """

    UNKNOWN = 0
    INBOUND = 1
    OUTBOUND = 2
    LATERAL = 3
    LOCAL = 4
    OTHER = 99


class EmailDirection(IntEnum):
    """OCSF ``direction_id`` on 4009 Email Activity, which 4009 *requires*.

    Same shape as :class:`Direction` and one differing caption — member 3 is
    **Internal** here and Lateral there. No validator can catch the substitution
    because 3 is legal on both, and "internal email" and "lateral movement" are
    close enough in meaning that the wrong enum would read plausibly forever. Hence
    a second enum rather than a comment.

    M365 and Google Workspace both give sender and recipient domains, so the
    connectors derive this rather than reading it: sender internal + recipient
    internal → ``INTERNAL``, external → ``INBOUND``, internal → ``OUTBOUND``.
    """

    UNKNOWN = 0
    INBOUND = 1
    OUTBOUND = 2
    INTERNAL = 3
    LOCAL = 4
    OTHER = 99


# ── the class ids CYPHRA actually maps, named so callers need no magic numbers ─


class ClassUid(IntEnum):
    """The OCSF classes CYPHRA's collectors and connectors emit.

    A deliberately partial list — OCSF defines 87 classes and this names the ones
    something in this repository actually produces. The full set is in the
    vendored index and :meth:`OcsfSchema.klass` will resolve any of them; this
    enum exists so collector code reads as ``ClassUid.PROCESS_ACTIVITY`` rather
    than as ``1007``.
    """

    # 1 — System Activity
    FILE_SYSTEM_ACTIVITY = 1001
    KERNEL_ACTIVITY = 1003
    MEMORY_ACTIVITY = 1004
    MODULE_ACTIVITY = 1005
    SCHEDULED_JOB_ACTIVITY = 1006
    PROCESS_ACTIVITY = 1007
    # PowerShell script-block logging and WMI script execution have no home in
    # PROCESS_ACTIVITY — its activities are Launch/Terminate/Open/Inject/Set User
    # ID, and running a script block is none of those. Mapping 4104 to Launch would
    # make every script block look like a new process to any rule counting
    # executions.
    SCRIPT_ACTIVITY = 1009
    # 2 — Findings
    VULNERABILITY_FINDING = 2002
    COMPLIANCE_FINDING = 2003
    DETECTION_FINDING = 2004
    INCIDENT_FINDING = 2005
    DATA_SECURITY_FINDING = 2006
    # 3 — Identity & Access Management
    AUTHENTICATION = 3002
    AUTHORIZE_SESSION = 3003
    ENTITY_MANAGEMENT = 3004
    GROUP_MANAGEMENT = 3006
    USER_MANAGEMENT = 3007
    # 4 — Network Activity
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    DHCP_ACTIVITY = 4004
    RDP_ACTIVITY = 4005
    SMB_ACTIVITY = 4006
    SSH_ACTIVITY = 4007
    FTP_ACTIVITY = 4008
    EMAIL_ACTIVITY = 4009
    TUNNEL_ACTIVITY = 4014
    # 5 — Discovery. These are the "state observed" classes, and they are what a
    # state-diff collector needs that the IAM classes cannot express: a periodic
    # snapshot of the local accounts, the privileged groups, the account policy and
    # the logon-session table is not an authentication or a user-management action,
    # and emitting it as one would put synthetic records into the data every rule
    # counting logons and account changes reads. The *changes* between snapshots go
    # to 3002/3006/3007; the snapshots themselves go here.
    DEVICE_INVENTORY_INFO = 5001
    DEVICE_CONFIG_STATE = 5002
    USER_INVENTORY = 5003
    #: Admin Group Query. Carries ``group`` *and* ``query_result_id``, which is the
    #: pair that lets "this privileged group does not exist on this host" and "this
    #: privileged group exists and I could not read it" be different records.
    ADMIN_GROUP_QUERY = 5009
    SESSION_QUERY = 5017
    #: Device Config State *Change*, as distinct from 5002's state. Both carry
    #: ``policy``; a local password and lockout policy is a policy, and the moment it
    #: is weakened is a different record from the hourly statement that it holds.
    DEVICE_CONFIG_STATE_CHANGE = 5019
    # 6 — Application Activity
    WEB_RESOURCES_ACTIVITY = 6001
    API_ACTIVITY = 6003
    DATASTORE_ACTIVITY = 6005
    # 20/1 — win extension. Sysmon's registry and service events have no core
    # OCSF home, and persistence detection on Windows is mostly these.
    REGISTRY_KEY_ACTIVITY = 201001
    REGISTRY_VALUE_ACTIVITY = 201002
    WINDOWS_RESOURCE_ACTIVITY = 201003
    WINDOWS_SERVICE_ACTIVITY = 201004


# ── flat field → OCSF path ──────────────────────────────────────────────────
#
# The single source of truth for the flat/nested correspondence. Both directions
# of conversion are derived from this table, and the test suite resolves every
# path in it against the vendored OCSF object graph, so a typo here is a test
# failure rather than a field that silently never populates on export.
#
# ``[...]`` in a path selects an element of an array of objects by a key value:
# ``actor.process.file.hashes[SHA-256]`` is the element of the ``hashes`` array
# whose ``algorithm`` is SHA-256. That is how OCSF models hashes, and flattening
# it is the main reason this table cannot be generated mechanically.

OCSF_PATH: dict[str, str] = {
    # base
    "time": "time",
    "class_uid": "class_uid",
    "category_uid": "category_uid",
    "activity_id": "activity_id",
    "activity_name": "activity_name",
    "type_uid": "type_uid",
    "severity_id": "severity_id",
    "status_id": "status_id",
    "status_code": "status_code",
    "status_detail": "status_detail",
    "action_id": "action_id",
    "disposition_id": "disposition_id",
    "confidence_id": "confidence_id",
    "confidence": "confidence",
    #: ``confidence_score`` — the 0-100 numeric, which is a *different attribute* from
    #: ``confidence``. Measured: OCSF types ``confidence`` as ``string_t`` (the caption
    #: beside ``confidence_id``) and ``confidence_score`` as ``integer_t``. CrowdStrike
    #: alerts carry a numeric ``confidence``, so without this column the only conformant
    #: place for it would be a three-band collapse into ``confidence_id`` — throwing
    #: away the difference between 61 and 99, which is exactly the range a triage
    #: threshold gets tuned in.
    "confidence_score": "confidence_score",
    #: ``risk_level``/``risk_level_id``/``risk_score``/``risk_details`` — declared on all
    #: 87 classes, and the only conformant home for identity risk. Entra sign-in records
    #: carry ``riskLevelDuringSignIn``, ``riskState`` and ``riskEventTypes``; those are a
    #: risk about the *sign-in*, so ``device_risk_level_id`` (which resolves to
    #: ``device.risk_level_id``) would attribute them to the wrong object. Sign-in risk
    #: is a first-class Phase 4 triage input — "impossible travel plus a high-risk
    #: sign-in" is one of the eight emulation scenarios — so it needs a column a rule
    #: can name, not an ``unmapped`` key.
    #:
    #: Note :class:`RiskLevel` numbers 0 as **Info**, not Unknown. An unset vendor risk
    #: must leave the field ``None``, never 0.
    "risk_level": "risk_level",
    "risk_level_id": "risk_level_id",
    "risk_score": "risk_score",
    "risk_details": "risk_details",
    "message": "message",
    "is_alert": "is_alert",
    "count": "count",
    "duration": "duration",
    "timezone_offset": "timezone_offset",
    "start_time": "start_time",
    "end_time": "end_time",
    # metadata
    "metadata_uid": "metadata.uid",
    "metadata_correlation_uid": "metadata.correlation_uid",
    "metadata_event_code": "metadata.event_code",
    "metadata_original_time": "metadata.original_time",
    "metadata_logged_time": "metadata.logged_time",
    "metadata_processed_time": "metadata.processed_time",
    "metadata_log_name": "metadata.log_name",
    "metadata_log_provider": "metadata.log_provider",
    "metadata_sequence": "metadata.sequence",
    "metadata_tenant_uid": "metadata.tenant_uid",
    "metadata_version": "metadata.version",
    "metadata_labels": "metadata.labels",
    "metadata_profiles": "metadata.profiles",
    "metadata_product_name": "metadata.product.name",
    "metadata_product_vendor_name": "metadata.product.vendor_name",
    "metadata_product_version": "metadata.product.version",
    # device — the host the event was observed on
    "device_uid": "device.uid",
    "device_hostname": "device.hostname",
    "device_ip": "device.ip",
    "device_mac": "device.mac",
    "device_domain": "device.domain",
    "device_interface_name": "device.interface_name",
    "device_type_id": "device.type_id",
    "device_instance_uid": "device.instance_uid",
    "device_region": "device.region",
    "device_risk_level_id": "device.risk_level_id",
    "device_is_managed": "device.is_managed",
    "device_os_name": "device.os.name",
    "device_os_type_id": "device.os.type_id",
    "device_os_version": "device.os.version",
    # actor — who or what performed the activity
    "actor_user_uid": "actor.user.uid",
    "actor_user_name": "actor.user.name",
    "actor_user_domain": "actor.user.domain",
    "actor_user_email": "actor.user.email_addr",
    "actor_user_type_id": "actor.user.type_id",
    "actor_user_has_mfa": "actor.user.has_mfa",
    "actor_user_risk_level_id": "actor.user.risk_level_id",
    # OCSF's own example for `user.credential_uid` is an AWS access key id, which is
    # exactly what it carries here. It is a separate field from `actor_session_uid`
    # because they answer different questions and an investigation needs both: the
    # session is *this* set of temporary credentials, the credential is the key that
    # minted it — and "rotate the key" (a Phase 5 response action) needs the key, while
    # "show me everything that session did" needs the session. Neither substitutes for
    # the other, and without this field the key would land in `unmapped`, where no hunt
    # query and no response action can find it.
    "actor_user_credential_uid": "actor.user.credential_uid",
    "actor_session_uid": "actor.session.uid",
    "actor_session_created_time": "actor.session.created_time",
    "actor_session_is_remote": "actor.session.is_remote",
    "actor_session_is_vpn": "actor.session.is_vpn",
    "actor_session_is_mfa": "actor.session.is_mfa",
    "actor_process_pid": "actor.process.pid",
    "actor_process_uid": "actor.process.uid",
    "actor_process_name": "actor.process.name",
    "actor_process_cmd_line": "actor.process.cmd_line",
    "actor_process_path": "actor.process.path",
    "actor_process_file_path": "actor.process.file.path",
    "actor_process_file_name": "actor.process.file.name",
    "actor_process_file_sha256": "actor.process.file.hashes[SHA-256]",
    # The rest of the actor side, kept deliberately symmetric with the `process_*`
    # block below. Asymmetry here is not a cosmetic gap: OCSF declares a top-level
    # `process` on only seven classes (the ones whose *subject* is a process), so on
    # a file, module, registry, network or DNS event the acting process has to go
    # under `actor.process`. A collector that reaches for `actor_process_*`, finds no
    # such column, and settles for `process_*` produces a row that validates and
    # persists and is then invisible to every query that looks in the right place —
    # which is exactly what Sysmon's shared data map did for eight of its nine
    # classes. Every path below is verified against the vendored schema.
    "actor_process_file_md5": "actor.process.file.hashes[MD5]",
    "actor_process_file_sha1": "actor.process.file.hashes[SHA-1]",
    "actor_process_file_company_name": "actor.process.file.company_name",
    "actor_process_file_size": "actor.process.file.size",
    "actor_process_working_directory": "actor.process.working_directory",
    "actor_process_integrity_id": "actor.process.integrity_id",
    "actor_process_created_time": "actor.process.created_time",
    "actor_process_parent_pid": "actor.process.parent_process.pid",
    "actor_process_parent_name": "actor.process.parent_process.name",
    "actor_process_parent_cmd_line": "actor.process.parent_process.cmd_line",
    "actor_app_name": "actor.app_name",
    "actor_invoked_by": "actor.invoked_by",
    # user — the account the activity was performed *on* (IAM classes)
    "user_uid": "user.uid",
    "user_name": "user.name",
    "user_domain": "user.domain",
    "user_email": "user.email_addr",
    "user_type_id": "user.type_id",
    "user_credential_uid": "user.credential_uid",
    # The Windows RID, as a number. Group and account *names* are localised and
    # renameable — `Administrator` is `Administrateur` on a French install and can be
    # renamed on any install — so the RID is the only stable identifier for a
    # well-known principal, and a baseline that keys on the name silently monitors
    # nothing on a host where it differs.
    "user_uid_numeric": "user.uid_numeric",
    "user_full_name": "user.full_name",
    "user_account_uid": "user.account.uid",
    "user_account_name": "user.account.name",
    "user_account_type_id": "user.account.type_id",
    # Account state as OCSF models it, rather than as a decoded flag string in
    # unmapped: "is this account disabled" and "is it locked out" are the two
    # questions asked of every account in an investigation, and they should be
    # columns.
    "user_account_is_disabled": "user.account.is_disabled",
    "user_account_is_locked": "user.account.is_locked",
    # process — the subject process (its creator is actor.process)
    "process_pid": "process.pid",
    "process_uid": "process.uid",
    "process_name": "process.name",
    "process_cmd_line": "process.cmd_line",
    "process_path": "process.path",
    "process_created_time": "process.created_time",
    "process_integrity_id": "process.integrity_id",
    "process_working_directory": "process.working_directory",
    "process_file_path": "process.file.path",
    "process_file_name": "process.file.name",
    "process_file_size": "process.file.size",
    "process_file_company_name": "process.file.company_name",
    "process_file_sha256": "process.file.hashes[SHA-256]",
    "process_file_md5": "process.file.hashes[MD5]",
    "process_file_sha1": "process.file.hashes[SHA-1]",
    "process_parent_pid": "process.parent_process.pid",
    "process_parent_name": "process.parent_process.name",
    "process_parent_cmd_line": "process.parent_process.cmd_line",
    # endpoints
    "src_endpoint_ip": "src_endpoint.ip",
    "src_endpoint_port": "src_endpoint.port",
    "src_endpoint_hostname": "src_endpoint.hostname",
    "src_endpoint_mac": "src_endpoint.mac",
    "src_endpoint_domain": "src_endpoint.domain",
    "src_endpoint_svc_name": "src_endpoint.svc_name",
    "src_endpoint_interface_name": "src_endpoint.interface_name",
    "src_endpoint_vpc_uid": "src_endpoint.vpc_uid",
    "src_endpoint_isp": "src_endpoint.isp",
    "src_endpoint_country": "src_endpoint.location.country",
    "src_endpoint_city": "src_endpoint.location.city",
    "src_endpoint_asn": "src_endpoint.autonomous_system.number",
    "dst_endpoint_ip": "dst_endpoint.ip",
    "dst_endpoint_port": "dst_endpoint.port",
    "dst_endpoint_hostname": "dst_endpoint.hostname",
    "dst_endpoint_mac": "dst_endpoint.mac",
    "dst_endpoint_domain": "dst_endpoint.domain",
    "dst_endpoint_svc_name": "dst_endpoint.svc_name",
    "dst_endpoint_vpc_uid": "dst_endpoint.vpc_uid",
    "dst_endpoint_isp": "dst_endpoint.isp",
    "dst_endpoint_country": "dst_endpoint.location.country",
    "dst_endpoint_city": "dst_endpoint.location.city",
    "dst_endpoint_asn": "dst_endpoint.autonomous_system.number",
    # connection and traffic
    "connection_uid": "connection_info.uid",
    "connection_direction_id": "connection_info.direction_id",
    "connection_protocol_num": "connection_info.protocol_num",
    "connection_protocol_name": "connection_info.protocol_name",
    "connection_tcp_flags": "connection_info.tcp_flags",
    "connection_community_uid": "connection_info.community_uid",
    "connection_boundary_id": "connection_info.boundary_id",
    "traffic_bytes": "traffic.bytes",
    "traffic_bytes_in": "traffic.bytes_in",
    "traffic_bytes_out": "traffic.bytes_out",
    "traffic_packets": "traffic.packets",
    "traffic_packets_in": "traffic.packets_in",
    "traffic_packets_out": "traffic.packets_out",
    # file activity
    "file_name": "file.name",
    "file_path": "file.path",
    "file_size": "file.size",
    "file_type_id": "file.type_id",
    "file_sha256": "file.hashes[SHA-256]",
    "file_md5": "file.hashes[MD5]",
    "file_is_encrypted": "file.is_encrypted",
    "file_company_name": "file.company_name",
    # dns
    "dns_query_hostname": "query.hostname",
    "dns_query_type": "query.type",
    "dns_rcode_id": "rcode_id",
    # http / url
    "http_method": "http_request.http_method",
    "http_user_agent": "http_request.user_agent",
    "http_referrer": "http_request.referrer",
    "http_response_code": "http_response.code",
    "url_string": "url.url_string",
    "url_hostname": "url.hostname",
    "url_path": "url.path",
    "url_scheme": "url.scheme",
    # email
    "email_from": "email.from",
    "email_to": "email.to",
    "email_subject": "email.subject",
    "email_message_uid": "email.message_uid",
    "email_smtp_from": "email.smtp_from",
    # authentication specifics
    "auth_protocol_id": "auth_protocol_id",
    "auth_protocol": "auth_protocol",
    "logon_type_id": "logon_type_id",
    # Both the id and the caption, because they answer different questions. A rule
    # matches the id (`logon_type_id == 10` is RDP, stably, in any locale); an
    # analyst reads the caption. Deriving the caption at read time would mean every
    # consumer carried its own copy of the mapping and they would drift.
    "logon_type": "logon_type",
    # OCSF models the logon process as a full Process object, not a name string.
    "logon_process_name": "logon_process.name",
    # The session this event is *about*, distinct from `actor.session`, which is the
    # session that caused it. Windows 4624 carries both — TargetLogonId is the
    # session created, SubjectLogonId the one that requested it — and collapsing
    # them would break the join that follows a logon to the activity inside it.
    "session_uid": "session.uid",
    # The rest of the session object, which is what a state-based logon collector
    # reading LSA actually has: the LUID's alternate form, when the session began,
    # when the KDC will kick it off, which window station it owns, and whether it
    # came in over the network. Without these, an LSA session snapshot has a uid and
    # nothing to reason about.
    "session_uid_alt": "session.uid_alt",
    "session_created_time": "session.created_time",
    "session_expiration_time": "session.expiration_time",
    "session_terminal": "session.terminal",
    "session_credential_uid": "session.credential_uid",
    "session_issuer": "session.issuer",
    "session_is_remote": "session.is_remote",
    #: How many sessions a session *query* answered about — session.count, not the
    #: base event's count. A table-state event with no per-session detail still
    #: carries the number, which is the part that changing is a signal.
    "session_count": "session.count",
    #: Discovery classes only. How complete the answer was — see
    #: :class:`QueryResultId`, and note that partial is the normal case unelevated.
    "query_result_id": "query_result_id",
    # policy.*, for the Discovery config-state classes. A local password and lockout
    # policy is a policy, and OCSF has an object for it; putting it in `unmapped`
    # would make "was the lockout threshold weakened" unqueryable.
    "policy_name": "policy.name",
    "policy_desc": "policy.desc",
    "policy_uid": "policy.uid",
    "policy_is_applied": "policy.is_applied",
    # group.*, for the account- and group-management classes (3006/3003).
    "group_name": "group.name",
    "group_uid": "group.uid",
    "group_domain": "group.domain",
    "group_desc": "group.desc",
    "group_type": "group.type",
    #: The group's RID. Same argument as ``user_uid_numeric``: 544 is Administrators
    #: in every locale and under every rename, and the name is not.
    "group_uid_numeric": "group.uid_numeric",
    #: ``privileges`` — declared by 3006 Group Management and 3007 User Management, and
    #: by nothing else. A plain string array, and the highest-value single column an
    #: identity connector can fill: "Add member to role → Global Administrator" is the
    #: Entra audit record for a tenant takeover, and OCSF gives 3007 activity 16 (Assign
    #: Roles) with no other attribute that can name *which* role. Without this column
    #: the role name lands in ``unmapped`` and the question "who was granted a
    #: privileged role this week" stops being answerable from the lake.
    "privileges": "privileges",
    # job.*, for Scheduled Job Activity (1006).
    "job_name": "job.name",
    "job_cmd_line": "job.cmd_line",
    "is_remote": "is_remote",
    "is_mfa": "is_mfa",
    "is_cleartext": "is_cleartext",
    # cloud / api
    "cloud_provider": "cloud.provider",
    "cloud_region": "cloud.region",
    "cloud_account_uid": "cloud.account.uid",
    "cloud_project_uid": "cloud.project_uid",
    "api_operation": "api.operation",
    "api_service_name": "api.service.name",
    "api_version": "api.version",
    # ``resource`` (singular) is declared by exactly four classes — 2002, 2003, 3005
    # and 3006. The cloud classes declare the *plural* ``resources`` instead, so these
    # three columns are correct on a group-management event and misplaced on an API
    # Activity one. That is not a distinction worth relying on a reader to remember,
    # which is why :func:`misplaced_fields` checks it per class.
    "resource_uid": "resource.uid",
    "resource_name": "resource.name",
    "resource_type": "resource.type",
    #: ``resources`` — the array form, declared by 6003 API Activity, 2004 Detection
    #: Finding and eleven others. Every cloud connector needs it: CloudTrail's
    #: ``resources[].ARN``, Azure's ``resourceId`` and GCP's ``protoPayload.resourceName``
    #: are *the* answer to "what was touched", and with no column for them the answer
    #: would live in ``unmapped`` where no hunt query looks. Stored as a JSON string in
    #: the lake, like the other structured tails.
    "resources": "resources",
    # finding_info — OCSF *requires* this object on 2004 Detection Finding, and it is
    # where the vendor's own alert identity lives. Defender and CrowdStrike both give a
    # title, an id, a rule name and first/last-seen times, and 2004 declares no
    # top-level `user`, `process`, `file` or `src_endpoint` to put anything else in. So
    # a detection finding without these columns has its title in `message` at best and
    # its rule name nowhere, which makes "how many alerts did this rule raise" a
    # question the lake cannot answer.
    "finding_uid": "finding_info.uid",
    "finding_title": "finding_info.title",
    "finding_desc": "finding_info.desc",
    "finding_types": "finding_info.types",
    "finding_created_time": "finding_info.created_time",
    "finding_first_seen_time": "finding_info.first_seen_time",
    "finding_last_seen_time": "finding_info.last_seen_time",
    "finding_modified_time": "finding_info.modified_time",
    "finding_src_url": "finding_info.src_url",
    "finding_product_uid": "finding_info.product_uid",
    "finding_analytic_name": "finding_info.analytic.name",
    "finding_analytic_uid": "finding_info.analytic.uid",
    "finding_analytic_type_id": "finding_info.analytic.type_id",
    #: ``evidences`` — 2004's array of what the alert was about. The only conformant
    #: home for Defender's ``evidence[]`` and CrowdStrike's per-detection process/file
    #: detail, because 2004 declares none of the top-level objects those would
    #: otherwise map to.
    "evidences": "evidences",
    #: ``finding_info_list`` — **required** by 2005 Incident Finding, and until this
    #: entry existed nothing in this repository could fill it. Measured:
    #: ``missing_required(2005, [])`` reported it as a *schema-coverage gap* rather
    #: than a mapping mistake, which means every incident CYPHRA emitted would have
    #: been non-conformant OCSF with no connector able to fix it.
    #:
    #: It matters twice over. A vendor incident (a CrowdStrike ``incident_id``, a
    #: Defender ``incidentId``) is a cluster whose *whole content* is the member
    #: findings, so an incident record that cannot list them says only "something
    #: happened somewhere". And Phase 3's own ``correlate/incident.py`` emits 2005 —
    #: CYPHRA's incidents are OCSF incidents — so the gap would have been inherited by
    #: the platform's own output, not just by its connectors.
    #:
    #: Elements are ``finding_info`` objects, the same shape the thirteen singular
    #: ``finding_*`` columns flatten. Kept as an array because the count is what makes
    #: it an incident and flattening the first member would silently discard the rest.
    "finding_info_list": "finding_info_list",
    #: The finding-decision set — ``verdict_id`` on 2002-2008, ``impact_id`` on
    #: 2001-2008, ``priority_id`` on 2002-2008. Three separate judgements OCSF keeps
    #: apart on purpose and a single "severity" column conflates: how the finding was
    #: dispositioned, what it would cost if real, and where it sits in the queue. A
    #: critical-severity finding on a decommissioned host is low priority, and the
    #: Phase 3 analyst queue sorts on ``priority_id`` for that reason.
    #:
    #: Defender's ``classification`` is a ``verdict_id`` (see :class:`Verdict`), and
    #: CYPHRA's own detection engine emits 2004 findings in Phase 2b — so these are the
    #: columns its triage verdict is written to, not only a connector mapping target.
    "verdict": "verdict",
    "verdict_id": "verdict_id",
    "impact": "impact",
    "impact_id": "impact_id",
    "impact_score": "impact_score",
    "priority": "priority",
    "priority_id": "priority_id",
    #: 2004 only. ``true`` is a claim with regulatory consequences — it is what starts
    #: the GDPR 72-hour clock in Phase 11 — so it is tri-state: ``None`` means nobody
    #: has assessed it, which is not the same as ``False``.
    "is_suspected_breach": "is_suspected_breach",
    #: ``src_url`` on 2004 is a deep link back into the vendor console, which is the
    #: one piece of an imported alert an analyst always wants and which no other
    #: attribute can hold. Distinct from ``finding_src_url``
    #: (``finding_info.src_url``): that one points at the *rule* or knowledge-base
    #: article, this one at the alert. Both exist in OCSF and both exist in Defender.
    "src_url": "src_url",
    #: 2004 and 3004. Analyst free text carried by the vendor — Defender's
    #: ``comments[]``, an Entra audit's ``resultReason``.
    "comment": "comment",
    # entity — required by 3004 Entity Management, which declares no `user` and no
    # `group`. An Entra `Add application` audit names an application; there is no other
    # attribute on the class to name it in.
    "entity_uid": "entity.uid",
    "entity_name": "entity.name",
    "entity_type": "entity.type",
    #: Required by 4009 Email Activity, and only declared there. Not the same attribute
    #: as ``connection_info.direction_id``.
    "direction_id": "direction_id",
    # windows registry (win extension)
    "reg_key_path": "reg_key.path",
    "reg_value_name": "reg_value.name",
    "reg_value_path": "reg_value.path",
    "reg_value_data": "reg_value.data",
    # module / service
    "module_file_path": "module.file.path",
    "module_file_sha256": "module.file.hashes[SHA-256]",
    "service_name": "service.name",
}

#: Flat columns CYPHRA derives that have no OCSF attribute of their own. They are
#: exported alongside the ``soc_*`` provenance under ``unmapped.cyphra`` rather
#: than being forced into a same-named OCSF field — ``dns_answer_count`` is the
#: cautionary case: the obvious home for it looks like the base event's ``count``,
#: but that attribute means "how many times this event repeated", so writing an
#: answer count there would corrupt the meaning for any OCSF consumer. The column
#: is worth keeping regardless: zero answers is an NXDOMAIN signal and an unusually
#: large answer count is a DNS-tunnelling one.
DERIVED_FIELDS: tuple[str, ...] = ("dns_answer_count",)

#: Flat fields that are CYPHRA's own provenance, not OCSF. They travel with the
#: event because the platform cannot function without them, and they are exported
#: under ``unmapped.cyphra`` so what leaves this system is still valid OCSF rather
#: than OCSF with invented top-level attributes.
SOC_FIELDS: tuple[str, ...] = (
    "soc_event_id",
    "soc_schema_version",
    "soc_source",
    "soc_agent_id",
    "soc_ingested_time",
    "soc_raw_sha256",
    "soc_raw",
    "soc_time_corrected",
    "soc_time_skew_seconds",
    "soc_dedup_exact",
    "soc_notes",
    "soc_tags",
)

#: The event envelope: flat fields that are containers CYPHRA carries rather than OCSF
#: attributes. Measured as exactly the model fields with no :data:`OCSF_PATH` entry that
#: are neither :data:`SOC_FIELDS` nor :data:`DERIVED_FIELDS`.
ENVELOPE_FIELDS: tuple[str, ...] = ("unmapped", "enrichments", "observables")

#: Keys :meth:`Event.build` accepts that are not model fields. ``notes`` is merged
#: into ``soc_notes`` before the stray sweep, so a collector writing it is writing a
#: legitimate payload key and must not be reported as a mapping mistake.
INPUT_ALIASES: dict[str, str] = {"notes": "soc_notes"}

#: Every flat field that is legitimately CYPHRA's own. A field outside this set and
#: outside :data:`OCSF_PATH` is a mapping mistake, not a local column.
LOCAL_FIELDS: frozenset[str] = (
    frozenset(SOC_FIELDS)
    | frozenset(DERIVED_FIELDS)
    | frozenset(ENVELOPE_FIELDS)
    | frozenset(INPUT_ALIASES)
)


def misplaced_fields(class_uid: Any, keys: Iterable[str]) -> dict[str, str]:
    """Keys whose OCSF attribute is not one the given class declares.

    This is the quiet half of schema validation, and it is quieter than anything else
    in this module. A wrong ``activity_id`` is rejected outright and quarantined at
    ingest — loud, and the quarantine table shows it. A wrong *field* is rejected by
    nothing: the model accepts it because it is a real model field, it validates, it
    persists, and it is then unqueryable under the name any consumer would look for,
    with every collector counter reporting a healthy source.

    Two concrete cases from this codebase, both of which shipped before this check
    existed:

    * ``query_result_id`` on a 5002. It is a real field with a real OCSF path, so a
      check against ``Event.model_fields`` passes it happily; only 5009 and 5017
      declare the attribute.
    * ``process_pid`` on a 4003. OCSF declares a top-level ``process`` on exactly
      seven classes — the ones whose *subject* is a process. On a DNS, file or module
      event the acting process belongs under ``actor.process``, which is a different
      attribute with a different meaning, and Sysmon's single flat data map was
      writing the wrong one for every event id except process create.

    The check is per class rather than per model, which is what gives it teeth, and it
    is driven by ``schema().class_attributes`` — which already carries each class's
    inherited base-event attributes, so ``time``, ``metadata`` and ``status_code`` are
    checked too rather than being exempted by hand.

    Returns ``{key: reason}``, empty when everything is in its right place. An
    unrecognised ``class_uid`` returns empty: nothing is known about the class, and
    guessing would flag every field on it.
    """
    try:
        uid = int(class_uid)
    except (TypeError, ValueError):
        return {}
    attrs = schema().class_attributes.get(uid)
    if not attrs:
        return {}
    out: dict[str, str] = {}
    for key in keys:
        if key in LOCAL_FIELDS or key.startswith("_"):
            continue
        path = OCSF_PATH.get(key)
        if path is None:
            out[key] = (
                f"{key} has no OCSF path and is not a declared local field, so it has "
                "nowhere to go in exported OCSF"
            )
            continue
        root = path.split(".")[0].split("[")[0]
        if root not in attrs:
            out[key] = f"{key} -> {path}, but class {uid} declares no {root!r}"
    return out


def _fields_reaching(root: str) -> tuple[str, ...]:
    """Every flat field whose OCSF path starts at *root*. Cached; small."""
    cached = _FIELDS_BY_ROOT.get(root)
    if cached is None:
        cached = tuple(
            sorted(
                name
                for name, path in OCSF_PATH.items()
                if path.split(".")[0].split("[")[0] == root
            )
        )
        _FIELDS_BY_ROOT[root] = cached
    return cached


#: Populated on demand by :func:`_fields_reaching`.
_FIELDS_BY_ROOT: dict[str, tuple[str, ...]] = {}


def missing_required(class_uid: Any, keys: Iterable[str]) -> dict[str, str]:
    """Class-required OCSF attributes that nothing in *keys* supplies.

    The other half of :func:`misplaced_fields`, and it catches the mirror-image defect.
    That function finds a field on a class that does not declare it; this one finds a
    class whose *own* requirement nothing filled. Both are silent: the event validates,
    persists and reports as healthy either way.

    The cases this exists for are all real and all in this package's connectors:

    * **2004 Detection Finding requires** ``finding_info``. A Defender or CrowdStrike
      alert with no ``finding_uid``/``finding_title`` is a detection finding that does
      not say what was found — accepted by the model, and not conformant OCSF.
    * **3004 Entity Management requires** ``entity``. An Entra ``Add application``
      audit with no ``entity_name`` names nothing; the class declares no ``user`` and
      no ``group`` to name it in instead.
    * **4009 Email Activity requires** ``direction_id`` *and* ``email``. Inbound versus
      outbound is the whole difference between a phishing delivery and a data
      exfiltration, and OCSF declares the attribute on this class only.
    * **6003 API Activity requires** ``actor``, ``api`` and ``src_endpoint``.

    ``base_required`` is excluded. Those nine — ``time``, ``class_uid``, ``metadata``
    and friends — are either non-optional model fields already or profile-gated
    (``cloud`` and ``osint`` are required *when their profile is applied*, which is the
    same reason :meth:`Event.to_ocsf` does not emit them), so reporting them would be
    noise on every event.

    The returned reason distinguishes two situations that need different responses:

    * **actionable** — the model has fields that reach the attribute and none was set.
      Somebody's mapping is incomplete. The reason names the candidate fields.
    * **coverage gap** — no ``OCSF_PATH`` entry reaches the attribute at all, so no
      connector *could* have filled it. That is a schema-coverage item for the Phase 2
      matrix, not a connector bug, and :meth:`Event.build` deliberately does not note
      it on every event.
    """
    try:
        uid = int(class_uid)
    except (TypeError, ValueError):
        return {}
    klass = schema().classes.get(uid)
    if klass is None:
        return {}
    base = set(schema().base_required)
    supplied: set[str] = set()
    for key in keys:
        path = OCSF_PATH.get(key)
        if path is not None:
            supplied.add(path.split(".")[0].split("[")[0])
    out: dict[str, str] = {}
    for attr in klass.required:
        if attr in base or attr in supplied:
            continue
        candidates = _fields_reaching(attr)
        if candidates:
            out[attr] = (
                f"class {uid} requires {attr!r} and nothing set it; the fields that "
                f"reach it are {', '.join(candidates)}"
            )
        else:
            out[attr] = (
                f"class {uid} requires {attr!r} and no CYPHRA field maps to it — a "
                "schema-coverage gap, not a mapping mistake"
            )
    return out


def unfilled_required(class_uid: Any, keys: Iterable[str]) -> dict[str, str]:
    """:func:`missing_required`, restricted to the attributes a field could have filled.

    What :meth:`Event.build` notes. Split out so the coverage-gap half is available to
    the Phase 2 matrix without being repeated on every event that lands in the lake.
    """
    return {
        attr: reason
        for attr, reason in missing_required(class_uid, keys).items()
        if "schema-coverage gap" not in reason
    }


#: Flat field → the OCSF attribute its enum table is keyed by, for the fields whose
#: table is class-dependent. Only top-level scalars appear: an enum nested inside an
#: object (``device.risk_level_id``) is defined by the *object*, and the vendored
#: index stores object attributes as type/object_type/is_array without their enums, so
#: checking those would need an index change rather than a lookup.
#:
#: Three universal enums are deliberately excluded, and each for its own reason:
#:
#: * ``activity_id`` — :attr:`OcsfClass.activities`, already checked by
#:   :meth:`OcsfSchema.activity`, which raises. Two mechanisms would give two answers.
#: * ``severity_id`` — the one enum field with a meaningful non-``None`` default.
#:   Sweeping a bad value out would leave the default INFORMATIONAL in its place,
#:   silently downgrading a critical vendor alert to noise. Its field validator
#:   rejects instead, which is the right trade for the one field autonomous response
#:   reads directly.
#: * ``action_id`` and ``disposition_id`` — one table across all 87 classes, so a bad
#:   value cannot mean "mapped from the wrong table"; it is unambiguously a producer
#:   bug, and their field validators already reject. Sweeping them here would make the
#:   same defect behave differently depending on whether the event came through
#:   :meth:`Event.build` or a direct ``Event(...)``.
_CLASS_ENUM_FIELDS: dict[str, str] = {
    name: path
    for name, path in OCSF_PATH.items()
    if "." not in path
    and "[" not in path
    and (name.endswith("_id") or name.endswith("_ids"))
    and name
    not in {
        "activity_id",
        "severity_id",
        "action_id",
        "disposition_id",
        "class_uid",  # identity, derived
        "category_uid",
        "type_uid",
    }
}


def bad_enum_values(class_uid: Any, payload: Mapping[str, Any]) -> dict[str, str]:
    """Enum fields whose value is not a member of *this class's* table.

    The third defect class in the set :func:`misplaced_fields` and
    :func:`missing_required` cover between them, and the one that lies rather than
    merely omitting: a wrong field moves data somewhere no query looks, a missing
    required attribute is an absence, but an out-of-table enum value *asserts
    something false in a column a rule reads*. ``status_id = 4`` on a 3002
    Authentication is not a status at all, and a brute-force rule counting
    ``status_id = 2`` will quietly not count it.

    Per class because the name is not enough. Six attribute names carry more than one
    table in OCSF v1.9.0; ``status_id`` alone has five, and three of those collide
    value-for-value with the base Success/Failure one. This function catches an
    *illegal* value. It cannot catch a legal value from the wrong table —
    ``Status.SUCCESS`` on a 2004 is ``1``, which is a perfectly valid "New" — and
    :func:`status_enum_for` exists because that case has no runtime defence.

    Returns field name → an explanation naming the valid set, which is the part that
    makes the note actionable.
    """
    try:
        uid = int(class_uid)
    except (TypeError, ValueError):
        return {}
    tables = schema().class_enums.get(uid)
    if not tables:
        return {}
    out: dict[str, str] = {}
    for field, attr in _CLASS_ENUM_FIELDS.items():
        if field not in payload:
            continue
        value = payload[field]
        if value is None:
            continue
        table = tables.get(attr)
        if table is None:
            # The class declares the attribute but with no enum, or does not declare
            # it at all — `misplaced_fields` owns the second case, and reporting it
            # twice would put two notes on one defect.
            continue
        try:
            as_int = int(value)
        except (TypeError, ValueError):
            out[field] = (
                f"{field}={value!r} is not an integer, and OCSF {attr!r} on class "
                f"{uid} is an enum"
            )
            continue
        if as_int not in table:
            valid = ", ".join(f"{k}={v}" for k, v in sorted(table.items()))
            out[field] = (
                f"{field}={as_int} is not a member of {attr!r} on class {uid}. "
                f"Valid: {valid}"
            )
    return out


#: Flat field → the kind of observable its value is. Drives
#: :meth:`Event.derive_observables`, which is what feeds entity resolution.
_OBSERVABLE_OF: dict[str, ObservableTypeId] = {
    "device_hostname": ObservableTypeId.HOSTNAME,
    "device_ip": ObservableTypeId.IP_ADDRESS,
    "device_mac": ObservableTypeId.MAC_ADDRESS,
    "device_uid": ObservableTypeId.DEVICE_UID,
    "actor_user_name": ObservableTypeId.USER_NAME,
    "actor_user_uid": ObservableTypeId.USER_UID,
    "actor_user_email": ObservableTypeId.EMAIL_ADDRESS,
    "actor_process_name": ObservableTypeId.PROCESS_NAME,
    "actor_process_cmd_line": ObservableTypeId.COMMAND_LINE,
    "actor_process_file_sha256": ObservableTypeId.HASH,
    # Symmetric with the `process_*` entries below, and not optional. Entity
    # resolution consumes observables, so a field that carries an executable path or
    # a hash but derives no observable is invisible to it. Before the actor side was
    # completed here, `process_file_path` derived a FILE_PATH and
    # `actor_process_file_path` derived nothing — which meant that correctly moving
    # Sysmon's `Image` to the actor on the eight classes that declare no top-level
    # `process` would have fixed the OCSF mapping and simultaneously stopped the
    # image path reaching the graph. Two half-right states; this is the third.
    "actor_process_file_path": ObservableTypeId.FILE_PATH,
    "actor_process_file_name": ObservableTypeId.FILE_NAME,
    "actor_process_file_md5": ObservableTypeId.HASH,
    "user_name": ObservableTypeId.USER_NAME,
    "user_uid": ObservableTypeId.USER_UID,
    "user_email": ObservableTypeId.EMAIL_ADDRESS,
    "user_account_uid": ObservableTypeId.ACCOUNT_UID,
    "process_name": ObservableTypeId.PROCESS_NAME,
    "process_cmd_line": ObservableTypeId.COMMAND_LINE,
    "process_file_path": ObservableTypeId.FILE_PATH,
    "process_file_name": ObservableTypeId.FILE_NAME,
    "process_file_sha256": ObservableTypeId.HASH,
    "process_file_md5": ObservableTypeId.HASH,
    "src_endpoint_ip": ObservableTypeId.IP_ADDRESS,
    "src_endpoint_hostname": ObservableTypeId.HOSTNAME,
    "src_endpoint_mac": ObservableTypeId.MAC_ADDRESS,
    "src_endpoint_port": ObservableTypeId.PORT,
    "src_endpoint_country": ObservableTypeId.COUNTRY,
    "dst_endpoint_ip": ObservableTypeId.IP_ADDRESS,
    "dst_endpoint_hostname": ObservableTypeId.HOSTNAME,
    "dst_endpoint_mac": ObservableTypeId.MAC_ADDRESS,
    "dst_endpoint_port": ObservableTypeId.PORT,
    "dst_endpoint_country": ObservableTypeId.COUNTRY,
    "file_name": ObservableTypeId.FILE_NAME,
    "file_path": ObservableTypeId.FILE_PATH,
    "file_sha256": ObservableTypeId.HASH,
    "file_md5": ObservableTypeId.HASH,
    "dns_query_hostname": ObservableTypeId.HOSTNAME,
    "url_string": ObservableTypeId.URL_STRING,
    "url_hostname": ObservableTypeId.HOSTNAME,
    "http_user_agent": ObservableTypeId.HTTP_USER_AGENT,
    "email_from": ObservableTypeId.EMAIL_ADDRESS,
    "email_subject": ObservableTypeId.EMAIL_SUBJECT,
    "email_message_uid": ObservableTypeId.MESSAGE_UID,
    "reg_key_path": ObservableTypeId.REGISTRY_KEY_PATH,
    "reg_value_name": ObservableTypeId.REGISTRY_VALUE_NAME,
    "resource_uid": ObservableTypeId.RESOURCE_UID,
    "cloud_account_uid": ObservableTypeId.ACCOUNT_UID,
    "module_file_sha256": ObservableTypeId.HASH,
    # Groups are entities correlation reasons about, not just labels: "who was
    # added to Domain Admins, by whom, on which hosts" is a graph query over the
    # group node. Without this, 4732 contributes a user observable and loses the
    # thing that makes it a privilege-escalation signal.
    "group_name": ObservableTypeId.GROUP_NAME,
    "group_uid": ObservableTypeId.GROUP_UID,
}


# ── the vendored schema ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class OcsfClass:
    """One OCSF event class, as vendored.

    ``deprecated_by`` is populated for the 26 classes OCSF has superseded. Those
    are accepted rather than rejected — an event mapped to ``account_change``
    (3001) is semantically fine, it is just addressed to a class OCSF now spells
    ``user_management`` — but the substitution is reported so a collector gets
    fixed instead of quietly producing events nothing new will match.
    """

    uid: int
    name: str
    caption: str
    category_uid: int
    category_name: str
    extension: str
    activities: Mapping[int, str]
    deprecated_by: tuple[str, ...]
    required: tuple[str, ...]

    @property
    def deprecated(self) -> bool:
        return bool(self.deprecated_by)

    def __str__(self) -> str:
        return f"{self.uid} {self.caption}"


class OcsfSchema:
    """The vendored OCSF schema: classes, enums and the object graph."""

    def __init__(self, index: Mapping[str, Any]) -> None:
        if index.get("index_version") != INDEX_VERSION:
            raise OcsfError(
                f"ocsf index is version {index.get('index_version')!r}, this code "
                f"expects {INDEX_VERSION}; rebuild with "
                "`python -m core.schema.ocsf build`"
            )
        self.version: str = index["ocsf_version"]
        self.source_sha256: str = index.get("source_sha256", "")
        self.categories: dict[int, str] = {int(k): v for k, v in index["categories"].items()}
        self.observable_types: dict[int, str] = {
            int(k): v for k, v in index["observable_types"].items()
        }
        self.enums: dict[str, dict[int, str]] = {
            name: {int(k): v for k, v in members.items()}
            for name, members in index["enums"].items()
        }
        #: object name → attribute name → {"type", "object_type", "is_array"}.
        #: This is what makes every path in OCSF_PATH checkable.
        self.objects: dict[str, dict[str, dict[str, Any]]] = index["objects"]
        self.class_attributes: dict[int, list[str]] = {
            int(k): v for k, v in index["class_attributes"].items()
        }
        #: class uid → attribute name → the object type it nests, or None if scalar.
        #: The first hop of :meth:`resolve_path` needs this; the rest of the walk
        #: happens in ``objects``.
        self.class_attribute_types: dict[int, dict[str, str | None]] = {
            int(k): dict(v) for k, v in index["class_attribute_types"].items()
        }
        #: class uid → attribute name → {value: caption}. The per-class enum tables,
        #: which :attr:`enums` cannot express because six attribute names carry
        #: different tables on different classes — ``status_id`` above all, whose
        #: finding-lifecycle form on 2003-2008 collides value-for-value with the base
        #: Success/Failure table. Use :meth:`enum_members` rather than reaching in.
        self.class_enums: dict[int, dict[str, dict[int, str]]] = {
            int(uid): {
                attr: {int(k): v for k, v in members.items()}
                for attr, members in per_class.items()
            }
            for uid, per_class in (index.get("class_enums") or {}).items()
        }
        self.base_required: tuple[str, ...] = tuple(index.get("base_required") or ())
        self.base_recommended: tuple[str, ...] = tuple(index.get("base_recommended") or ())
        self.classes: dict[int, OcsfClass] = {}
        self._by_name: dict[str, OcsfClass] = {}
        for uid_s, raw in index["classes"].items():
            klass = OcsfClass(
                uid=int(uid_s),
                name=raw["name"],
                caption=raw["caption"],
                category_uid=raw["category_uid"],
                category_name=raw["category_name"],
                extension=raw.get("extension") or "",
                activities={int(k): v for k, v in raw["activities"].items()},
                deprecated_by=tuple(raw.get("deprecated_by") or ()),
                required=tuple(raw.get("required") or ()),
            )
            self.classes[klass.uid] = klass
            self._by_name[klass.name] = klass

    @classmethod
    def load(cls, index_path: str | Path | None = None) -> "OcsfSchema":
        path = Path(index_path) if index_path else DEFAULT_INDEX
        if not path.exists():
            raise OcsfError(
                f"no OCSF index at {path}. Build it with "
                "`python -m core.schema.ocsf build` (needs network access to "
                "schema.ocsf.io the first time; the raw responses are cached under "
                "vendor/ocsf/)."
            )
        with path.open(encoding="utf-8") as fh:
            return cls(json.load(fh))

    # ── lookups ────────────────────────────────────────────────────────────

    def klass(self, ref: int | str) -> OcsfClass:
        """Resolve a class by uid, uid-as-string, or OCSF class name."""
        if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
            uid = int(ref)
            if uid not in self.classes:
                # A wrong uid is usually a wrong digit, so the classes sharing its
                # category are the likely intent. A uid whose category does not
                # exist either is a different mistake — most often a type_uid used
                # where a class_uid belongs — and for that the useful answer is the
                # set of categories, not an empty list.
                near = sorted(u for u in self.classes if u // 1000 == uid // 1000)[:6]
                hint = (
                    f"Nearest by category: {near}" if near else
                    "and category "
                    f"{uid // 1000} does not exist either — OCSF categories are "
                    + ", ".join(
                        f"{c}={n}" for c, n in sorted(self.categories.items())
                    )
                    + f" (if {uid} is a type_uid, its class_uid is {uid // 100})"
                )
                raise UnknownClass(
                    f"{uid} is not an OCSF class in v{self.version}. {hint}"
                )
            return self.classes[uid]
        name = str(ref).strip().lower().replace("-", "_").replace(" ", "_")
        if name not in self._by_name:
            close = sorted(n for n in self._by_name if name[:6] in n)[:6]
            raise UnknownClass(
                f"{ref!r} is not an OCSF class name in v{self.version}."
                + (f" Did you mean one of {close}?" if close else "")
            )
        return self._by_name[name]

    def get(self, ref: int | str) -> OcsfClass | None:
        try:
            return self.klass(ref)
        except UnknownClass:
            return None

    def activity(self, class_uid: int, activity_id: int) -> str:
        """Name an activity, raising with the valid set — which is the useful error."""
        klass = self.klass(class_uid)
        if activity_id not in klass.activities:
            valid = ", ".join(f"{k}={v}" for k, v in sorted(klass.activities.items()))
            raise OcsfError(
                f"activity_id {activity_id} is not defined for {klass}. Valid: {valid}"
            )
        return klass.activities[activity_id]

    def enum_members(self, class_uid: int, attr: str) -> dict[int, str] | None:
        """The enum table *this class* uses for *attr*, or ``None`` if it has none.

        Per class, because the name alone is not enough. Measured across the
        vendored bundle, six attribute names carry more than one table: ``status_id``
        (five), ``category_uid``, ``class_uid``, ``type_uid``, ``auth_protocol_id``
        (3002 vs 8001) and ``state_id`` (2001, 5012, 5019). ``schema().enums`` holds
        the base-event tables and cannot express any of that.

        ``None`` for an attribute the class does not declare, an attribute that
        carries no enum, and for ``activity_id`` — that one is
        :attr:`OcsfClass.activities`, and duplicating it here would give two answers
        to one question.
        """
        return (self.class_enums.get(int(class_uid)) or {}).get(attr)

    @staticmethod
    def type_uid(class_uid: int, activity_id: int) -> int:
        """OCSF's ``type_uid`` — ``class_uid * 100 + activity_id``.

        Always computed, never accepted from a source: the two-field-plus-derived
        arrangement is exactly the sort of thing that drifts, and a ``type_uid``
        disagreeing with its own class is undiagnosable downstream.
        """
        return class_uid * 100 + activity_id

    def resolve_path(self, path: str, class_uid: int | None = None) -> str:
        """Walk a dotted OCSF path through the object graph, or explain the break.

        Returns the terminal attribute's OCSF type. Raises :class:`OcsfError`
        naming the segment that does not exist, which is what makes
        :data:`OCSF_PATH` verifiable rather than aspirational.
        """
        parts = path.split(".")
        head = parts[0]
        # An array selector (hashes[SHA-256]) resolves to the array's element type.
        head_name = head.split("[", 1)[0]
        if class_uid is not None:
            attrs = self.class_attributes.get(class_uid, [])
            if head_name not in attrs:
                raise OcsfError(
                    f"{path!r}: {head_name!r} is not an attribute of class "
                    f"{class_uid}"
                )
        else:
            if not any(head_name in a for a in self.class_attributes.values()):
                raise OcsfError(
                    f"{path!r}: no OCSF class has an attribute {head_name!r}"
                )
        current_type = self._attr_object_type(head_name, class_uid)
        for seg in parts[1:]:
            seg_name = seg.split("[", 1)[0]
            if current_type is None:
                raise OcsfError(
                    f"{path!r}: {head_name!r} is a scalar, so {seg_name!r} cannot "
                    "be nested under it"
                )
            obj = self.objects.get(current_type)
            if obj is None:
                raise OcsfError(f"{path!r}: object {current_type!r} is not vendored")
            if seg_name not in obj:
                raise OcsfError(
                    f"{path!r}: {current_type}.{seg_name} does not exist "
                    f"(has {sorted(obj)[:8]}…)"
                )
            head_name = seg_name
            current_type = obj[seg_name].get("object_type")
        return current_type or "scalar"

    def _attr_object_type(self, attr: str, class_uid: int | None) -> str | None:
        """The object type nested under a class-level attribute, if it is an object.

        With no class named, any class that has the attribute answers: OCSF reuses
        one object type for a given attribute name across classes (``src_endpoint``
        is a Network Endpoint everywhere it appears), so the first hit is the right
        one and a path can be checked without naming a class.
        """
        uids = [class_uid] if class_uid is not None else list(self.class_attribute_types)
        for uid in uids:
            types = self.class_attribute_types.get(uid, {})
            if attr in types:
                return types[attr]
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "ocsf_version": self.version,
            "categories": len(self.categories),
            "classes": len(self.classes),
            "extension_classes": sum(1 for c in self.classes.values() if c.extension),
            "deprecated_classes": sum(1 for c in self.classes.values() if c.deprecated),
            "objects": len(self.objects),
            "observable_types": len(self.observable_types),
            "activities": sum(len(c.activities) for c in self.classes.values()),
            "mapped_flat_fields": len(OCSF_PATH),
            "observable_fields": len(_OBSERVABLE_OF),
        }


_SCHEMA: OcsfSchema | None = None


def schema(index_path: str | Path | None = None, reload: bool = False) -> OcsfSchema:
    """The process-wide vendored schema, loaded once.

    Validation runs on every ingested event, so re-reading a multi-hundred-KB
    index per event is not an option; and an import-time load would make the whole
    package unimportable whenever the index is missing, which is a bad failure for
    the build step whose job is to create it. Passing ``index_path`` loads that
    file and makes it the process default, which is how the test suite points at a
    freshly built index.
    """
    global _SCHEMA
    if _SCHEMA is None or reload or index_path is not None:
        _SCHEMA = OcsfSchema.load(index_path)
    return _SCHEMA


# ── time and value coercion ─────────────────────────────────────────────────


def parse_time(value: Any) -> float:
    """Coerce a source timestamp to epoch seconds.

    Accepts what collectors and connectors actually emit: epoch seconds, epoch
    milliseconds, ISO-8601 (including the trailing ``Z`` that Azure, Okta and
    Graph use), Windows FILETIME, and datetimes. A naive datetime is read as UTC,
    because every one of these APIs returns UTC and guessing the host's local zone
    would shift each of them by the offset.

    ``core.store.lake`` has its own coercion for the same reason and deliberately
    does not call this one: the lake accepts raw dict rows from paths that never
    build an :class:`Event` (backfills, imports), and it raises a lake error where
    this raises a schema error. Two callers, two error contracts.
    """
    if isinstance(value, bool):
        raise ValueError(f"a boolean is not a timestamp: {value!r}")
    if isinstance(value, (int, float)):
        v = float(value)
        # Windows FILETIME: 100-nanosecond ticks since 1601. Sysmon and the Event
        # Log APIs hand these out, and read as seconds they land ~13 million years
        # out — far enough that no plausibility check would rescue them.
        if v > 1e16:
            return v / 1e7 - 11644473600.0
        # Microseconds (some agents), then milliseconds (anything JVM- or
        # JS-based: Okta, CrowdStrike, Graph). Python's own time.time() is seconds.
        if v > 1e14:
            return v / 1e6
        if v > 1e11:
            return v / 1e3
        return v
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.replace(".", "", 1).replace("-", "", 1).isdigit():
            return parse_time(float(text))
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"unparseable timestamp {value!r}: {exc}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise ValueError(f"unusable timestamp {value!r} ({type(value).__name__})")


def _encodable(value: Any) -> bool:
    """Whether one value would survive ``json.dumps``, used only to name the bad key."""
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True


def _check_ip(value: str, field_name: str) -> str:
    """Reject anything that is not an address.

    Not pedantry: these values reach ``netsh advfirewall`` and the Scapy RST
    sender. A hostname or a CIDR that arrived in an ``ip`` field would either
    become a failed command or, worse, a block on something unintended.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name}: {value!r} is not an IP address ({exc})") from exc


def _norm_mac(value: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(raw) != 12:
        raise ValueError(f"{value!r} is not a MAC address")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).upper()


# ── the event ───────────────────────────────────────────────────────────────


class Observable(BaseModel):
    """One extracted entity or indicator, in OCSF's own observable shape."""

    model_config = ConfigDict(extra="forbid")

    name: str
    type_id: int
    value: str

    def key(self) -> str:
        """The identity used for grouping across events."""
        return f"{self.type_id}:{self.value}"


class Event(BaseModel):
    """A normalised event. Anything that reaches the lake is one of these.

    Flat by design (see the module docstring). All fields but the six OCSF
    requires are optional, because no source populates more than a fraction of
    them — but ``extra="forbid"`` means a misspelled field is an error rather than
    a value that silently disappears. Genuinely source-specific fields go in
    ``unmapped``, which is OCSF's own escape hatch and is preserved end to end.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # ── OCSF required ──
    time: float
    class_uid: int
    activity_id: int = 0
    #: The source's own label for the activity. OCSF makes this the *sibling* of
    #: ``activity_id`` and requires it whenever ``activity_id`` is 99 (Other) — the
    #: enum's own description says so: "See the ``activity_name`` attribute, which
    #: contains a data source specific value." Without it, 99 means only "none of the
    #: defined values", which is a statement about the schema rather than about what
    #: happened, and a consumer has no way to recover the distinction. The validator
    #: below enforces the pairing, so choosing 99 obliges the producer to say what it
    #: actually observed.
    activity_name: str | None = None
    severity_id: int = Severity.INFORMATIONAL
    category_uid: int = 0  # derived from class_uid
    type_uid: int = 0  # derived from class_uid and activity_id

    # ── outcome ──
    #: ``status_id`` is **not one enum**. Five tables share the name and three collide
    #: value-for-value, so ``1`` means Success on 3002 and New on 2004. Ask
    #: :func:`status_enum_for` for the right one; ``Event.build`` checks membership
    #: against the class's own table, which catches an illegal value but cannot catch
    #: a legal one from the wrong table.
    status_id: int | None = None
    status_code: str | None = None
    status_detail: str | None = None
    action_id: int | None = None
    disposition_id: int | None = None
    confidence_id: int | None = None
    #: The caption beside :attr:`confidence_id`, and a **string** because that is what
    #: OCSF types it: measured ``confidence`` = ``string_t``, ``confidence_score`` =
    #: ``integer_t``. This field held the 0-100 integer until the class-level enum
    #: tables made the mismatch visible; nothing wrote it, so the correction cost
    #: nothing. A numeric vendor confidence goes to :attr:`confidence_score`.
    confidence: str | None = None
    #: 0-100. CrowdStrike's alert ``confidence`` is this, not :attr:`confidence_id`.
    confidence_score: int | None = None

    # ── risk, as asserted by the source ──
    #: Declared on all 87 classes. The conformant home for identity risk — Entra's
    #: ``riskLevelDuringSignIn`` is a risk about the *sign-in*, so it must not go to
    #: ``device_risk_level_id``, which resolves to ``device.risk_level_id`` and would
    #: attribute it to the endpoint.
    #:
    #: :class:`RiskLevel` numbers 0 as **Info** — a positive assertion of no risk.
    #: An unset vendor risk leaves this ``None``; writing 0 would claim the source
    #: cleared the event when it said nothing.
    risk_level: str | None = None
    risk_level_id: int | None = None
    risk_score: int | None = None
    #: Why the source thinks so, free text. Entra's ``riskEventTypes`` joined, or the
    #: raw word behind a ``hidden``/``unknownFutureValue`` risk level that maps to 99.
    risk_details: str | None = None
    message: str | None = None
    is_alert: bool | None = None
    count: int | None = None
    duration: int | None = None
    timezone_offset: int | None = None
    # An activity that spans time has two ends, and a network flow is the case that
    # makes this unavoidable: a four-minute connection timed only at `time` is a
    # point event, so a correlation window narrower than the flow misses traffic
    # that was live throughout it. OCSF puts both on the base event for exactly
    # this reason. `time` stays the start — see NetworkFlowCollector for why timing
    # a flow at eviction misplaces every slow scan.
    start_time: float | None = None
    end_time: float | None = None

    # ── metadata ──
    metadata_uid: str | None = None
    metadata_correlation_uid: str | None = None
    metadata_event_code: str | None = None
    metadata_original_time: str | None = None
    metadata_logged_time: float | None = None
    metadata_processed_time: float | None = None
    metadata_log_name: str | None = None
    metadata_log_provider: str | None = None
    metadata_sequence: int | None = None
    metadata_tenant_uid: str | None = None
    metadata_version: str | None = None
    metadata_labels: list[str] = []
    metadata_profiles: list[str] = []
    metadata_product_name: str | None = None
    metadata_product_vendor_name: str | None = None
    metadata_product_version: str | None = None

    # ── device ──
    device_uid: str | None = None
    device_hostname: str | None = None
    device_ip: str | None = None
    device_mac: str | None = None
    device_domain: str | None = None
    # Which NIC observed it. A sensor on a host with a management NIC and a span
    # port produces two very different event populations, and a flow whose
    # interface is unrecorded cannot be attributed to either.
    device_interface_name: str | None = None
    device_type_id: int | None = None
    device_instance_uid: str | None = None
    device_region: str | None = None
    device_risk_level_id: int | None = None
    device_is_managed: bool | None = None
    device_os_name: str | None = None
    device_os_type_id: int | None = None
    device_os_version: str | None = None

    # ── actor ──
    actor_user_uid: str | None = None
    actor_user_name: str | None = None
    actor_user_domain: str | None = None
    actor_user_email: str | None = None
    actor_user_type_id: int | None = None
    actor_user_has_mfa: bool | None = None
    actor_user_risk_level_id: int | None = None
    actor_user_credential_uid: str | None = None
    actor_session_uid: str | None = None
    actor_session_created_time: float | None = None
    actor_session_is_remote: bool | None = None
    actor_session_is_vpn: bool | None = None
    actor_session_is_mfa: bool | None = None
    actor_process_pid: int | None = None
    actor_process_uid: str | None = None
    actor_process_name: str | None = None
    actor_process_cmd_line: str | None = None
    actor_process_path: str | None = None
    actor_process_file_path: str | None = None
    actor_process_file_name: str | None = None
    actor_process_file_sha256: str | None = None
    actor_process_file_md5: str | None = None
    actor_process_file_sha1: str | None = None
    actor_process_file_company_name: str | None = None
    actor_process_file_size: int | None = None
    actor_process_working_directory: str | None = None
    actor_process_integrity_id: int | None = None
    actor_process_created_time: float | None = None
    actor_process_parent_pid: int | None = None
    actor_process_parent_name: str | None = None
    actor_process_parent_cmd_line: str | None = None
    actor_app_name: str | None = None
    actor_invoked_by: str | None = None

    # ── target user ──
    user_uid: str | None = None
    user_name: str | None = None
    user_domain: str | None = None
    user_email: str | None = None
    user_type_id: int | None = None
    user_credential_uid: str | None = None
    user_uid_numeric: int | None = None
    user_full_name: str | None = None
    user_account_uid: str | None = None
    user_account_name: str | None = None
    user_account_type_id: int | None = None
    user_account_is_disabled: bool | None = None
    user_account_is_locked: bool | None = None

    # ── process ──
    process_pid: int | None = None
    process_uid: str | None = None
    process_name: str | None = None
    process_cmd_line: str | None = None
    process_path: str | None = None
    process_created_time: float | None = None
    process_integrity_id: int | None = None
    process_working_directory: str | None = None
    process_file_path: str | None = None
    process_file_name: str | None = None
    process_file_size: int | None = None
    process_file_company_name: str | None = None
    process_file_sha256: str | None = None
    process_file_md5: str | None = None
    process_file_sha1: str | None = None
    process_parent_pid: int | None = None
    process_parent_name: str | None = None
    process_parent_cmd_line: str | None = None

    # ── endpoints ──
    src_endpoint_ip: str | None = None
    src_endpoint_port: int | None = None
    src_endpoint_hostname: str | None = None
    src_endpoint_mac: str | None = None
    src_endpoint_domain: str | None = None
    src_endpoint_svc_name: str | None = None
    src_endpoint_interface_name: str | None = None
    src_endpoint_vpc_uid: str | None = None
    src_endpoint_isp: str | None = None
    src_endpoint_country: str | None = None
    src_endpoint_city: str | None = None
    src_endpoint_asn: int | None = None
    dst_endpoint_ip: str | None = None
    dst_endpoint_port: int | None = None
    dst_endpoint_hostname: str | None = None
    dst_endpoint_mac: str | None = None
    dst_endpoint_domain: str | None = None
    dst_endpoint_svc_name: str | None = None
    dst_endpoint_vpc_uid: str | None = None
    dst_endpoint_isp: str | None = None
    dst_endpoint_country: str | None = None
    dst_endpoint_city: str | None = None
    dst_endpoint_asn: int | None = None

    # ── connection / traffic ──
    connection_uid: str | None = None
    connection_direction_id: int | None = None
    connection_protocol_num: int | None = None
    connection_protocol_name: str | None = None
    connection_tcp_flags: int | None = None
    connection_community_uid: str | None = None
    connection_boundary_id: int | None = None
    traffic_bytes: int | None = None
    traffic_bytes_in: int | None = None
    traffic_bytes_out: int | None = None
    traffic_packets: int | None = None
    traffic_packets_in: int | None = None
    traffic_packets_out: int | None = None

    # ── file ──
    file_name: str | None = None
    file_path: str | None = None
    file_size: int | None = None
    file_type_id: int | None = None
    file_sha256: str | None = None
    file_md5: str | None = None
    file_is_encrypted: bool | None = None
    file_company_name: str | None = None

    # ── dns / http / url ──
    dns_query_hostname: str | None = None
    dns_query_type: str | None = None
    dns_rcode_id: int | None = None
    dns_answer_count: int | None = None
    http_method: str | None = None
    http_user_agent: str | None = None
    http_referrer: str | None = None
    http_response_code: int | None = None
    url_string: str | None = None
    url_hostname: str | None = None
    url_path: str | None = None
    url_scheme: str | None = None

    # ── email ──
    email_from: str | None = None
    email_to: list[str] = []
    email_subject: str | None = None
    email_message_uid: str | None = None
    email_smtp_from: str | None = None

    # ── authentication ──
    auth_protocol_id: int | None = None
    auth_protocol: str | None = None
    logon_type_id: int | None = None
    logon_type: str | None = None
    logon_process_name: str | None = None
    session_uid: str | None = None
    session_uid_alt: str | None = None
    session_created_time: float | None = None
    session_expiration_time: float | None = None
    session_terminal: str | None = None
    session_credential_uid: str | None = None
    session_issuer: str | None = None
    session_is_remote: bool | None = None
    session_count: int | None = None
    is_remote: bool | None = None
    is_mfa: bool | None = None
    is_cleartext: bool | None = None

    # ── group / job (account management, scheduled tasks) ──
    group_name: str | None = None
    group_uid: str | None = None
    group_domain: str | None = None
    group_desc: str | None = None
    group_type: str | None = None
    group_uid_numeric: int | None = None
    #: Roles or privileges granted or removed. 3006 and 3007 only — see
    #: :data:`OCSF_PATH`. A list because one Entra audit record can name several
    #: (``Add member to role`` on a role-assignable group carries each role) and one
    #: AWS ``AttachUserPolicy`` names one policy but the same connector's
    #: ``PutUserPolicy`` names a document containing many.
    privileges: list[str] = []
    job_name: str | None = None
    job_cmd_line: str | None = None

    # ── discovery (category 5): how complete the answer was, and about what ──
    query_result_id: int | None = None
    policy_name: str | None = None
    policy_desc: str | None = None
    policy_uid: str | None = None
    policy_is_applied: bool | None = None

    # ── cloud / api ──
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_account_uid: str | None = None
    cloud_project_uid: str | None = None
    api_operation: str | None = None
    api_service_name: str | None = None
    api_version: str | None = None
    resource_uid: str | None = None
    resource_name: str | None = None
    resource_type: str | None = None
    #: The plural form, for the cloud and finding classes — see :data:`OCSF_PATH`.
    #: Each element is a ``resource_details`` object; ``name``, ``uid``, ``type``,
    #: ``region`` and ``cloud_partition`` are the ones these connectors populate.
    resources: list[dict[str, Any]] = []

    # ── finding (2004 Detection Finding, 2002/2003 and friends) ──
    finding_uid: str | None = None
    finding_title: str | None = None
    finding_desc: str | None = None
    finding_types: list[str] = []
    finding_created_time: float | None = None
    finding_first_seen_time: float | None = None
    finding_last_seen_time: float | None = None
    finding_modified_time: float | None = None
    finding_src_url: str | None = None
    finding_product_uid: str | None = None
    finding_analytic_name: str | None = None
    finding_analytic_uid: str | None = None
    finding_analytic_type_id: int | None = None
    #: What the finding was about. Elements are ``evidences`` objects — the vendor's
    #: own structure, kept whole rather than flattened, because which of the fourteen
    #: possible sub-objects an alert carries varies per alert.
    evidences: list[dict[str, Any]] = []
    #: The member findings of an incident — 2005's own requirement. Elements are
    #: ``finding_info`` objects (``uid``, ``title``, ``created_time``, ``analytic``…),
    #: built by :func:`ingest.connectors.mapping.finding_ref`. Empty on 2004, which
    #: carries the singular ``finding_*`` columns above instead: a detection finding
    #: *is* one finding, an incident finding is a set of them.
    finding_info_list: list[dict[str, Any]] = []

    # ── the finding's own judgement (2001-2008; see OCSF_PATH for the exact sets) ──
    #: Three judgements OCSF keeps apart and a single severity column conflates: how
    #: the finding was dispositioned (:class:`Verdict`), what it would cost if real
    #: (:class:`Impact`), and where it sits in the queue (:class:`Priority`).
    #:
    #: ``verdict_id`` is not ``disposition_id``: a control can have BLOCKED the
    #: activity and triage can still call the finding a FALSE_POSITIVE, and both
    #: statements belong on the event.
    verdict: str | None = None
    verdict_id: int | None = None
    impact: str | None = None
    impact_id: int | None = None
    impact_score: int | None = None
    priority: str | None = None
    priority_id: int | None = None
    #: Tri-state on purpose. ``None`` means nobody has assessed it; ``False`` is a
    #: recorded assessment. The difference matters because ``True`` starts the GDPR
    #: 72-hour clock in Phase 11, and "not yet assessed" must not read as "assessed,
    #: not a breach".
    is_suspected_breach: bool | None = None
    #: A deep link into the vendor console for *this alert*. Distinct from
    #: :attr:`finding_src_url` (``finding_info.src_url``), which points at the rule or
    #: knowledge-base article. Both exist in OCSF and both exist in Defender.
    src_url: str | None = None
    #: Analyst free text carried by the source. 2004 and 3004 only.
    comment: str | None = None

    # ── entity (3004 Entity Management) ──
    entity_uid: str | None = None
    entity_name: str | None = None
    entity_type: str | None = None

    # ── email direction (4009, required there) ──
    direction_id: int | None = None

    # ── windows registry / module / service ──
    reg_key_path: str | None = None
    reg_value_name: str | None = None
    #: The full path of the *value*, which is not the same attribute as
    #: :attr:`reg_key_path`. 201001 Registry Key Activity declares ``reg_key`` and
    #: 201002 Registry Value Activity declares ``reg_value``; neither declares the
    #: other. Sysmon's ``TargetObject`` carries a key path on event 12/14 and a value
    #: path on event 13, so both fields are needed to map one source field correctly
    #: on both classes.
    reg_value_path: str | None = None
    reg_value_data: str | None = None
    module_file_path: str | None = None
    module_file_sha256: str | None = None
    service_name: str | None = None

    # ── structured tails ──
    observables: list[Observable] = []
    enrichments: list[dict[str, Any]] = []
    unmapped: dict[str, Any] = {}

    # ── CYPHRA provenance ──
    soc_event_id: str = ""
    soc_schema_version: int = SCHEMA_VERSION
    soc_source: str = ""
    soc_agent_id: str = ""
    soc_ingested_time: float = 0.0
    soc_raw_sha256: str = ""
    soc_raw: str | None = None
    soc_time_corrected: bool = False
    soc_time_skew_seconds: float = 0.0
    soc_dedup_exact: bool = False
    soc_notes: list[str] = []
    soc_tags: list[str] = []

    # ── validators ─────────────────────────────────────────────────────────

    @field_validator(
        "time",
        "metadata_logged_time",
        "metadata_processed_time",
        "actor_session_created_time",
        "process_created_time",
        "finding_created_time",
        "finding_first_seen_time",
        "finding_last_seen_time",
        "finding_modified_time",
        mode="before",
    )
    @classmethod
    def _coerce_times(cls, v: Any) -> Any:
        return None if v is None else parse_time(v)

    @field_validator(
        "unmapped",
        "enrichments",
        "resources",
        "evidences",
        "finding_info_list",
        mode="after",
    )
    @classmethod
    def _json_serialisable(cls, v: Any, info: Any) -> Any:
        """Refuse a structured tail that the lake writer could not encode.

        These five columns are stored as JSON strings, so an unencodable value
        reaching them raises inside the Parquet writer — where it fails the whole
        batch, not the one bad event, and takes every good event in that batch with
        it. Checking here converts that into one :class:`EventRejected` naming the
        collector, which is what the health module reports on. ``default=`` is
        deliberately *not* passed: stringifying an arbitrary object would store its
        ``repr`` — a memory address, most usefully — and call it data.

        The cost is a ``json.dumps`` per event, but only over these five fields,
        which are empty for most events and a handful of scalars otherwise.
        """
        if not v:
            return v
        try:
            json.dumps(v)
        except (TypeError, ValueError) as exc:
            bad = (
                sorted(k for k, x in v.items() if not _encodable(x))
                if isinstance(v, dict) else
                [i for i, x in enumerate(v) if not _encodable(x)]
            )
            raise ValueError(
                f"{info.field_name} is not JSON-serialisable ({exc}); the lake "
                f"stores it as a JSON string. Offending: {bad[:5]}"
            ) from exc
        return v

    @field_validator("time")
    @classmethod
    def _plausible_time(cls, v: float) -> float:
        if v < MIN_PLAUSIBLE_TIME:
            raise ValueError(
                f"time {v} is before 2000-01-01. A zero, a null coerced to zero, or "
                "a unit mix-up produces this; rewriting it to now would hide the bug"
            )
        return v

    @field_validator(
        "device_ip", "src_endpoint_ip", "dst_endpoint_ip", mode="after"
    )
    @classmethod
    def _validate_ips(cls, v: str | None, info: Any) -> str | None:
        return None if v is None else _check_ip(v, info.field_name)

    @field_validator("device_mac", "src_endpoint_mac", "dst_endpoint_mac", mode="after")
    @classmethod
    def _validate_macs(cls, v: str | None) -> str | None:
        return None if v is None else _norm_mac(v)

    @field_validator("src_endpoint_port", "dst_endpoint_port", mode="after")
    @classmethod
    def _validate_ports(cls, v: int | None, info: Any) -> int | None:
        if v is not None and not 0 <= v <= 65535:
            raise ValueError(f"{info.field_name}: {v} is not a port")
        return v

    @field_validator(
        "actor_process_file_sha256",
        "process_file_sha256",
        "file_sha256",
        "module_file_sha256",
        mode="after",
    )
    @classmethod
    def _validate_sha256(cls, v: str | None, info: Any) -> str | None:
        if v is None:
            return None
        low = v.strip().lower()
        if not _SHA256_RE.match(low):
            raise ValueError(
                f"{info.field_name}: {v!r} is not a sha256. Chain of custody and "
                "every hash-based intel match depend on this being exact"
            )
        return low

    @field_validator("process_file_md5", "file_md5", mode="after")
    @classmethod
    def _validate_md5(cls, v: str | None, info: Any) -> str | None:
        if v is None:
            return None
        low = v.strip().lower()
        if not _MD5_RE.match(low):
            raise ValueError(f"{info.field_name}: {v!r} is not an md5")
        return low

    @field_validator("process_file_sha1", mode="after")
    @classmethod
    def _validate_sha1(cls, v: str | None) -> str | None:
        if v is None:
            return None
        low = v.strip().lower()
        if not _SHA1_RE.match(low):
            raise ValueError(f"{v!r} is not a sha1")
        return low

    @field_validator(
        "device_hostname",
        "src_endpoint_hostname",
        "dst_endpoint_hostname",
        "dns_query_hostname",
        "url_hostname",
        "device_domain",
        "src_endpoint_domain",
        "dst_endpoint_domain",
        "actor_user_domain",
        "user_domain",
        "actor_user_email",
        "user_email",
        "email_from",
        "email_smtp_from",
        mode="after",
    )
    @classmethod
    def _lower_case_insensitive(cls, v: str | None) -> str | None:
        """Fold the values that are case-insensitive by specification.

        DNS names, AD/NetBIOS domain names and the domain part of an email address
        are all case-insensitive, so two events differing only in case describe the
        same entity and must resolve to one node in the graph. Usernames are
        deliberately *not* folded: they are case-insensitive on Windows and
        case-sensitive on Linux, so folding here would silently merge two genuinely
        different Linux accounts. ``correlate/entity.py`` applies the per-platform
        rule instead, where it knows which platform the event came from.
        """
        return None if v is None else v.strip().lower() or None

    @field_validator("severity_id")
    @classmethod
    def _known_severity(cls, v: int) -> int:
        if v not in {int(s) for s in Severity}:
            raise ValueError(f"severity_id {v} is not an OCSF severity")
        return v

    @field_validator("status_id")
    @classmethod
    def _known_status(cls, v: int | None) -> int | None:
        # Deliberately *not* checked against `Status`. Five different tables share the
        # name `status_id` in OCSF, and this validator cannot see `class_uid` to pick
        # the right one. Checking against the base Success/Failure table here rejected
        # every legal finding-lifecycle value — a Defender alert with status Resolved
        # (`4` on 2004) was thrown away with "not an OCSF status", which is the
        # validator being wrong about the schema rather than the source being wrong
        # about the event. The real check is `_check_class_enums`, which reads the
        # class's own table.
        #
        # The range check stays: OCSF enums are small non-negative integers, so a
        # negative or absurd value is a coercion bug in the producer either way.
        if v is not None and not 0 <= v <= 99:
            raise ValueError(f"status_id {v} is outside the OCSF enum range 0-99")
        return v

    @field_validator("action_id")
    @classmethod
    def _known_action(cls, v: int | None) -> int | None:
        if v is not None and v not in {int(a) for a in ActionId}:
            raise ValueError(f"action_id {v} is not an OCSF action")
        return v

    @field_validator("disposition_id")
    @classmethod
    def _known_disposition(cls, v: int | None) -> int | None:
        if v is not None and v not in {int(d) for d in DispositionId}:
            raise ValueError(f"disposition_id {v} is not an OCSF disposition")
        return v

    @field_validator("confidence_score", "impact_score", "risk_score")
    @classmethod
    def _score_range(cls, v: int | None, info: Any) -> int | None:
        # OCSF types all three as `integer_t` without documenting a range, but every
        # source that fills them uses 0-100 (CrowdStrike confidence, CVSS-derived
        # impact). A value outside it is a scale mix-up — a 0-1 float rounded to 0, or
        # a 0-1000 vendor score passed through — and both are the kind of thing that
        # silently shifts a triage threshold.
        if v is not None and not 0 <= v <= 100:
            raise ValueError(f"{info.field_name} is a 0-100 score, got {v}")
        return v

    @model_validator(mode="after")
    def _derive_class_fields(self) -> "Event":
        """Resolve the class, check the activity, and derive the derived fields.

        ``category_uid`` and ``type_uid`` are computed from ``class_uid`` and
        ``activity_id`` rather than trusted. If a producer supplied one and it
        disagrees, that is a rejection and not a silent correction: a source whose
        ``type_uid`` contradicts its own ``class_uid`` does not reliably know what
        class it is emitting, so quietly fixing the derived field would leave every
        ``class_uid``-keyed rule matching events the producer thought were
        something else entirely.

        A deprecated class is accepted and noted — see :class:`OcsfClass`.
        """
        sch = schema()
        try:
            klass = sch.klass(self.class_uid)
        except UnknownClass as exc:
            # Re-raised as ValueError so pydantic folds it into the ValidationError
            # with the rest of the event's problems. An UnknownClass escaping raw
            # would bypass validate_event's EventRejected contract, and a collector
            # emitting a class this schema version does not have is exactly the case
            # that contract exists to report — with the collector's name attached.
            raise ValueError(str(exc)) from exc
        if self.activity_id not in klass.activities:
            valid = ", ".join(f"{k}={v}" for k, v in sorted(klass.activities.items()))
            raise ValueError(
                f"activity_id {self.activity_id} is not defined for {klass}. "
                f"Valid: {valid}"
            )
        if self.activity_id == 99 and not (self.activity_name or "").strip():
            # OCSF's own enum description makes activity_name the carrier of meaning
            # for 99, and enforcing it is the difference between "this was a hosts-file
            # entry, not a resolution" and "this was something, unspecified". A rule
            # cannot match on the absence of a value, so an unnamed 99 is an event that
            # is queryable only by exclusion — and the producer, which knew exactly
            # what it saw, is the only party that can still say.
            raise ValueError(
                f"activity_id 99 (Other) on {klass} requires activity_name — OCSF "
                "defines it as the sibling that carries the source-specific label, "
                "and 99 without it records only that the schema had no match"
            )
        expected_type = OcsfSchema.type_uid(self.class_uid, self.activity_id)
        if self.type_uid not in (0, expected_type):
            raise ValueError(
                f"type_uid {self.type_uid} contradicts class_uid {self.class_uid} "
                f"with activity_id {self.activity_id}, which is {expected_type}"
            )
        if self.category_uid not in (0, klass.category_uid):
            raise ValueError(
                f"category_uid {self.category_uid} contradicts {klass}, which is in "
                f"category {klass.category_uid} ({klass.category_name})"
            )
        object.__setattr__(self, "category_uid", klass.category_uid)
        object.__setattr__(self, "type_uid", expected_type)
        if klass.deprecated:
            note = (
                f"class {klass.uid} ({klass.name}) is deprecated in OCSF "
                f"v{sch.version}; OCSF now spells this "
                f"{' or '.join(klass.deprecated_by)}"
            )
            if note not in self.soc_notes:
                self.soc_notes.append(note)
        return self

    # ── construction ───────────────────────────────────────────────────────

    @classmethod
    def build(
        cls,
        source: str,
        raw: Any = None,
        agent_id: str = "",
        keep_raw: bool = False,
        ingested_time: float | None = None,
        max_skew_seconds: float = MAX_CLOCK_SKEW_SECONDS,
        **fields: Any,
    ) -> "Event":
        """Normalise mapped fields into a validated event.

        ``raw`` is the source's original payload. It is always hashed into
        ``soc_raw_sha256`` and kept in ``soc_raw`` only when ``keep_raw``, which is
        the storage-versus-custody trade-off described in the module docstring.

        Unrecognised keys in ``fields`` are routed into ``unmapped`` rather than
        rejected — a connector should never lose a source field it does not have a
        home for — but each one is recorded in ``soc_notes`` so a typo in a mapped
        field name is visible instead of silently becoming unmapped data.
        """
        now = time.time() if ingested_time is None else ingested_time
        known = set(cls.model_fields)

        # `notes` is an accepted alias for `soc_notes` on the way in, and it has to
        # be resolved *before* the stray sweep below. It is not a model field, so a
        # collector that writes `payload["notes"]` — network_flow does, to record how
        # it decided flow direction — would otherwise have its own audit trail swept
        # into `unmapped` and filed as if the source had sent it. The two are merged
        # rather than one taking precedence: a base collector and its subclass can
        # each have something to say about the same event, and dropping either half
        # would lose exactly the provenance these notes exist to carry.
        notes = [
            str(n)
            for n in (list(fields.get("soc_notes") or []) + list(fields.get("notes") or []))
            if n
        ]
        payload = {k: v for k, v in fields.items() if k in known}
        strays = {
            k: v for k, v in fields.items() if k not in known and k not in INPUT_ALIASES
        }

        unmapped = dict(payload.get("unmapped") or {})
        if strays:
            unmapped.update(strays)
            notes.append(
                "routed to unmapped (not fields of the event schema): "
                + ", ".join(sorted(strays))
            )

        # Second sweep: fields that *are* model fields but are wrong for this event's
        # own class. The stray sweep above cannot catch these — the field exists, so it
        # is `in known` and passes straight through. `process_pid` on a DNS event is a
        # real column with a real OCSF path; it is just that only the seven classes
        # whose subject is a process declare a top-level `process`, and on a DNS event
        # the acting process belongs under `actor.process`. Nothing downstream would
        # ever complain: the row validates, persists, and reports healthy, and a hunt
        # querying `actor.process.pid` silently finds nothing.
        #
        # Handled the same way as strays — moved to `unmapped` and named in the notes —
        # rather than either dropped (loses telemetry over a mapping nit) or silently
        # remapped to the sibling field (guesses the collector's intent; a collector
        # that genuinely means a *target* process would have its meaning inverted).
        misplaced = misplaced_fields(payload.get("class_uid"), list(payload))
        for key, reason in misplaced.items():
            unmapped[key] = payload.pop(key)
            notes.append(f"routed to unmapped (wrong for this class): {reason}")

        # Third sweep, and the one that catches an active lie rather than an omission:
        # an enum value that is not a member of the table *this class* uses. `status_id`
        # alone has five tables in OCSF v1.9.0, so `4` (Resolved on a 2004 finding) on a
        # 3002 Authentication is not a status at all — and a brute-force rule counting
        # `status_id = 2` would silently not count it.
        #
        # Moved to `unmapped` for the same reason as the second sweep: the value is real
        # data the source sent, so it is kept, but it must not sit in a column a rule
        # reads as if it meant what that column means. Ordered after the misplaced sweep
        # so a field that is wrong for the class is reported once, as misplaced, rather
        # than twice.
        bad_enums = bad_enum_values(payload.get("class_uid"), payload)
        for key, reason in bad_enums.items():
            unmapped[key] = payload.pop(key)
            notes.append(f"routed to unmapped (not a value of this enum): {reason}")
        payload["unmapped"] = unmapped

        # Fourth sweep, and the mirror image of the second: an attribute this class
        # *requires* that nothing supplied. Noted, never rejected — dropping a real
        # Defender alert because the vendor sent no title would trade a conformance
        # nit for lost telemetry, which is the wrong way round. The note is what makes
        # it findable: `SELECT ... WHERE soc_notes LIKE '%OCSF requires%'` is one query,
        # and a connector test asserting the note is absent is one line.
        #
        # Only the attributes a field could have filled are reported here. The ones no
        # OCSF_PATH reaches — 5040's `query_evidence`, the unmanned-system classes —
        # would be on every such event forever and say nothing about the connector;
        # `missing_required` keeps them for the Phase 2 coverage matrix instead.
        unfilled = unfilled_required(payload.get("class_uid"), list(payload))
        if unfilled:
            notes.append(
                "OCSF requires attributes this event does not carry: "
                + "; ".join(unfilled[k] for k in sorted(unfilled))
            )

        raw_text = (
            raw
            if isinstance(raw, str)
            else json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
            if raw is not None
            else ""
        )
        raw_sha = hashlib.sha256(raw_text.encode("utf-8", "replace")).hexdigest()

        # Clock skew. The source's own string is preserved before anything is
        # rewritten, so the correction is reversible from the stored row.
        #
        # `time` is deliberately not defaulted. The model requires it, so a source
        # that omits it is rejected by name here rather than silently stamped with
        # the ingest clock — which is the failure that would matter most quietly: a
        # connector with a broken time mapping would look healthy while every dwell
        # time and MTTD it feeds (Function 10) collapsed to zero. A source that
        # genuinely has no timestamp of its own must pass one explicitly, so the
        # choice is visible in the connector.
        if payload.get("time") is None:
            raise ValueError(
                f"{source} produced an event with no time. Every metric derived "
                "from event time depends on it, so it is not defaulted to the "
                "ingest clock; a source with no timestamp of its own must pass "
                "time=<ingest time> explicitly."
            )
        claimed = parse_time(payload["time"])
        # Plausibility is checked *before* skew correction, not after. Correction
        # exists to salvage a plausible time from a wrong clock; 1970 is not a
        # skewed clock but a broken field, and letting correction run first would
        # rewrite it to now — turning a zero, a null coerced to zero or a unit
        # mix-up into a fresh-looking live event. The field validator on `time`
        # catches the same thing for direct construction, where there is no
        # correction step to get in first.
        if claimed < MIN_PLAUSIBLE_TIME:
            raise ValueError(
                f"{source} produced time {claimed} — before 2000-01-01. A zero, a "
                "null coerced to zero, or a unit mix-up produces this; correcting "
                "it to the ingest clock would hide the bug"
            )
        skew = claimed - now
        # Asymmetric on purpose — see decision 2 in the module docstring. Only a
        # *future* time is provably wrong, and only a future time is rewritten.
        corrected = skew > max_skew_seconds
        if corrected:
            payload.setdefault(
                "metadata_original_time",
                datetime.fromtimestamp(claimed, tz=timezone.utc).isoformat(),
            )
            notes.append(
                f"event time was {skew:+.0f}s ahead of the ingest clock, beyond the "
                f"{max_skew_seconds:.0f}s tolerance; an event cannot be observed "
                "before it happens, so it is stamped with the ingest time and the "
                "source value kept in metadata_original_time"
            )
            payload["time"] = now
        else:
            # Kept as stated even when it is hours old. `metadata_original_time` is
            # deliberately not set here: the original *is* `time`, so writing it
            # would only add a field that can drift out of agreement with itself.
            payload["time"] = claimed
            if skew < -max_skew_seconds:
                notes.append(
                    f"event arrived {-skew:.0f}s after it happened, beyond the "
                    f"{max_skew_seconds:.0f}s tolerance; the source's time is kept "
                    "because lateness is not a broken clock — a backfill, a spooled "
                    "agent reconnecting and a stalled connector cursor all look like "
                    "this, and only ingest.health can tell them apart"
                )

        # Dedup identity. Exact only when the source names its own event.
        src_uid = payload.get("metadata_uid")
        if src_uid:
            ident = f"{source}\x00{src_uid}"
            exact = True
        else:
            ident = f"{source}\x00{agent_id}\x00{payload['time']:.6f}\x00{raw_sha}"
            exact = False
            notes.append(
                "no source event id, so deduplication is best-effort: two "
                "byte-identical events in the same instant are indistinguishable"
            )

        payload.update(
            soc_event_id=hashlib.sha256(ident.encode()).hexdigest()[:32],
            soc_schema_version=SCHEMA_VERSION,
            soc_source=source,
            soc_agent_id=agent_id,
            soc_ingested_time=now,
            soc_raw_sha256=raw_sha,
            soc_raw=raw_text if keep_raw and raw_text else None,
            soc_time_corrected=corrected,
            soc_time_skew_seconds=round(skew, 3),
            soc_dedup_exact=exact,
            soc_notes=notes,
        )
        event = cls(**payload)
        event.derive_observables()
        return event

    # ── observables ────────────────────────────────────────────────────────

    def derive_observables(self, replace: bool = False) -> list[Observable]:
        """Extract entities and indicators from the mapped fields.

        Deterministic and central, so a collector contributes to the entity graph
        just by filling a mapped field. Existing observables are kept unless
        ``replace`` — an enrichment step may have added ones no field implies.
        """
        if replace:
            self.observables = []
        seen = {o.key() for o in self.observables}
        derived: list[Observable] = []
        for flat, type_id in _OBSERVABLE_OF.items():
            value = getattr(self, flat, None)
            if value is None or value == "":
                continue
            obs = Observable(
                name=OCSF_PATH.get(flat, flat), type_id=int(type_id), value=str(value)
            )
            if obs.key() in seen:
                continue
            seen.add(obs.key())
            derived.append(obs)
        self.observables = self.observables + derived
        return derived

    def observable_values(self, *types: ObservableTypeId) -> list[str]:
        """Values of the given observable types — the correlation entry point."""
        wanted = {int(t) for t in types} if types else None
        return [
            o.value
            for o in self.observables
            if wanted is None or o.type_id in wanted
        ]

    # ── OCSF conversion ────────────────────────────────────────────────────

    def to_ocsf(self, include_raw: bool = False) -> dict[str, Any]:
        """Emit conformant nested OCSF.

        CYPHRA's own ``soc_*`` provenance goes under ``unmapped.cyphra`` — OCSF's
        documented place for what the schema has no attribute for — so a consumer
        validating this against the published schema sees valid OCSF rather than
        OCSF with invented top-level fields.
        """
        out: dict[str, Any] = {}
        for flat, path in OCSF_PATH.items():
            value = getattr(self, flat, None)
            if value is None or value == [] or value == {}:
                continue
            _set_path(out, path, value)
        if self.observables:
            out["observables"] = [
                {"name": o.name, "type_id": o.type_id, "value": o.value}
                for o in self.observables
            ]
        if self.enrichments:
            out["enrichments"] = list(self.enrichments)

        cyphra = {
            f: getattr(self, f)
            for f in SOC_FIELDS + DERIVED_FIELDS
            if f != "soc_raw" and getattr(self, f) not in (None, "", [], 0.0, False)
        }
        if include_raw and self.soc_raw:
            cyphra["soc_raw"] = self.soc_raw
        unmapped = dict(self.unmapped)
        if cyphra:
            unmapped["cyphra"] = cyphra
        if unmapped:
            out["unmapped"] = unmapped
        # class_uid, category_uid, activity_id, type_uid, severity_id and time are
        # all non-optional, so the loop above has already emitted every attribute
        # OCSF requires of a base event. The profile-driven ones OCSF also lists as
        # required (osint, cloud) are only required when their profile is applied.
        return out

    @classmethod
    def from_ocsf(cls, doc: Mapping[str, Any]) -> "Event":
        """Read nested OCSF back into the flat model.

        The inverse of :meth:`to_ocsf` for every field in :data:`OCSF_PATH`. What
        the mapping has no flat column for is kept in ``unmapped`` rather than
        dropped, so a round trip through an external OCSF consumer does not lose
        attributes CYPHRA does not itself use.
        """
        flat: dict[str, Any] = {}
        consumed: set[str] = set()
        for name, path in OCSF_PATH.items():
            value, hit = _get_path(doc, path)
            if hit:
                flat[name] = value
                consumed.add(path.split(".", 1)[0].split("[", 1)[0])
        unmapped = dict(doc.get("unmapped") or {})
        cyphra = unmapped.pop("cyphra", None)
        if isinstance(cyphra, Mapping):
            flat.update({k: v for k, v in cyphra.items() if k in cls.model_fields})
        # An inbound OCSF DNS event carries the answers themselves; the flat column
        # is their count, so it is computed here rather than mapped.
        answers = doc.get("answers")
        if isinstance(answers, list):
            flat["dns_answer_count"] = len(answers)
        leftover = {
            k: v
            for k, v in doc.items()
            if k not in consumed
            and k
            not in {
                "unmapped",
                "observables",
                "enrichments",
                "answers",
                "category_uid",
                "type_uid",
                "category_name",
                "class_name",
                "activity_name",
                "type_name",
                "severity",
                "status",
                "action",
                "disposition",
            }
        }
        if leftover:
            unmapped.update(leftover)
        if unmapped:
            flat["unmapped"] = unmapped
        obs = doc.get("observables") or []
        if obs:
            flat["observables"] = [Observable(**o) for o in obs]
        if doc.get("enrichments"):
            flat["enrichments"] = list(doc["enrichments"])
        return cls(**flat)

    # ── lake row ───────────────────────────────────────────────────────────

    def lake_row(self) -> dict[str, Any]:
        """The flat dict the lake stores.

        The three structured tails are JSON-encoded into string columns instead of
        being stored as Parquet structs. Struct columns make schema evolution a
        rewrite and make hunt SQL awkward for the exact case that matters most —
        "find every event mentioning this value" — where a JSON string answers
        with a ``LIKE`` and DuckDB's ``json_extract`` when structure is needed.

        Observables are written with their full OCSF key names, identical to
        :meth:`to_ocsf`. Short keys would save perhaps 100 bytes an event before
        compression and almost nothing after it — the column is one repeated key
        string, which is what Parquet's dictionary encoding is for — while leaving
        the lake and the export with two different shapes for the same data. A hunt
        query written against the export shape would then return zero rows against
        the lake and look like a clean negative result. One shape is worth more
        than the bytes.

        No ``default=`` is passed to ``json.dumps``: the field validator guarantees
        these are encodable at assignment, so a failure here is a real bug and
        should surface rather than store an object's ``repr`` as if it were data.
        The one path that escapes that validator is in-place mutation
        (``event.enrichments.append(...)``), so ``enrich/`` assigns a new list
        instead of appending to the existing one.
        """
        row = self.model_dump(
            exclude={
                "observables",
                "enrichments",
                "unmapped",
                "resources",
                "evidences",
                "finding_info_list",
            }
        )
        row["observables"] = (
            json.dumps(
                [
                    {"name": o.name, "type_id": o.type_id, "value": o.value}
                    for o in self.observables
                ],
                separators=(",", ":"),
            )
            if self.observables
            else None
        )
        row["enrichments"] = (
            json.dumps(self.enrichments, separators=(",", ":"))
            if self.enrichments
            else None
        )
        row["unmapped"] = (
            json.dumps(self.unmapped, separators=(",", ":"))
            if self.unmapped
            else None
        )
        # The three vendor-shaped arrays, same treatment for the same reason: a Parquet
        # struct column would have to be widened every time a vendor adds a key, and
        # `resources[0].uid` is not a thing hunt SQL can filter on cheaply anyway.
        row["resources"] = (
            json.dumps(self.resources, separators=(",", ":"))
            if self.resources
            else None
        )
        row["evidences"] = (
            json.dumps(self.evidences, separators=(",", ":"))
            if self.evidences
            else None
        )
        row["finding_info_list"] = (
            json.dumps(self.finding_info_list, separators=(",", ":"))
            if self.finding_info_list
            else None
        )
        return row

    # ── description ────────────────────────────────────────────────────────

    def describe(self) -> str:
        """One line, for logs and alert lists."""
        sch = schema()
        klass = sch.klass(self.class_uid)
        who = self.actor_user_name or self.user_name or self.device_hostname or "?"
        what = klass.activities.get(self.activity_id, str(self.activity_id))
        where = ""
        if self.src_endpoint_ip and self.dst_endpoint_ip:
            where = f" {self.src_endpoint_ip}→{self.dst_endpoint_ip}"
        elif self.device_hostname:
            where = f" on {self.device_hostname}"
        status = ""
        if self.status_id is not None:
            status = f" [{Status(self.status_id).name.lower()}]"
        stamp = datetime.fromtimestamp(self.time, tz=timezone.utc).strftime("%H:%M:%S")
        return f"{stamp} {klass.caption}/{what}{status} {who}{where}"


def _set_path(out: dict[str, Any], path: str, value: Any) -> None:
    """Write a value at a dotted OCSF path, creating objects and hash arrays."""
    parts = path.split(".")
    node: Any = out
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    last = parts[-1]
    if "[" in last:
        # hashes[SHA-256] → append a Fingerprint rather than overwrite the array.
        attr, algo = last[:-1].split("[", 1)
        arr = node.setdefault(attr, [])
        algo_id = _ALGO_ID.get(algo, HashAlgorithmId.OTHER)
        arr.append({"algorithm": algo, "algorithm_id": int(algo_id), "value": value})
        return
    node[last] = value


def _get_path(doc: Mapping[str, Any], path: str) -> tuple[Any, bool]:
    """Read a dotted OCSF path. Returns ``(value, found)``."""
    parts = path.split(".")
    node: Any = doc
    for part in parts[:-1]:
        if not isinstance(node, Mapping) or part not in node:
            return None, False
        node = node[part]
    last = parts[-1]
    if not isinstance(node, Mapping):
        return None, False
    if "[" in last:
        attr, algo = last[:-1].split("[", 1)
        arr = node.get(attr)
        if not isinstance(arr, list):
            return None, False
        for item in arr:
            if isinstance(item, Mapping) and item.get("algorithm") == algo:
                return item.get("value"), True
        return None, False
    if last in node:
        return node[last], True
    return None, False


_ALGO_ID = {
    "MD5": HashAlgorithmId.MD5,
    "SHA-1": HashAlgorithmId.SHA1,
    "SHA-256": HashAlgorithmId.SHA256,
    "SHA-512": HashAlgorithmId.SHA512,
}


# ── validation entry point for the ingest pipeline ──────────────────────────


def validate_event(source: str, payload: Mapping[str, Any]) -> Event:
    """Build an event or raise :class:`EventRejected` naming the source.

    The pipeline's contract with every collector: this either returns something
    every downstream module can rely on, or it refuses with a message that names
    the collector to fix. Nothing partially-valid gets through.
    """
    try:
        return Event.build(source=source, **dict(payload))
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise EventRejected(source, problems, payload) from exc
    except (OcsfError, ValueError, TypeError) as exc:
        raise EventRejected(source, str(exc), payload) from exc


# ── the lake schema, generated from the model ──────────────────────────────

_ARROW_OF: dict[str, pa.DataType] = {
    "float": pa.float64(),
    "int": pa.int64(),
    "str": pa.string(),
    "bool": pa.bool_(),
    "list[str]": pa.list_(pa.string()),
}

#: Fields the lake stores as a JSON string. See :meth:`Event.lake_row`.
_JSON_COLUMNS = (
    "observables",
    "enrichments",
    "unmapped",
    "resources",
    "evidences",
    "finding_info_list",
)


def lake_schema() -> pa.Schema:
    """The Parquet schema for the ``events`` table, derived from :class:`Event`.

    Generated rather than hand-written: a hand-maintained Parquet schema beside a
    120-field model diverges the first time someone adds a field, and the failure
    mode is a column that silently stops being stored. ``_extra`` is appended
    because ``core.store.lake`` requires it — undeclared keys are retained rather
    than dropped.
    """
    fields: list[pa.Field] = []
    for name, info in Event.model_fields.items():
        if name in _JSON_COLUMNS:
            fields.append(pa.field(name, pa.string()))
            continue
        fields.append(pa.field(name, _arrow_type_for(name, info.annotation)))
    fields.append(pa.field("_extra", pa.string()))
    return pa.schema(fields)


def _arrow_type_for(name: str, annotation: Any) -> pa.DataType:
    text = str(annotation)
    if "list[str]" in text or "List[str]" in text:
        return _ARROW_OF["list[str]"]
    if "bool" in text:
        return _ARROW_OF["bool"]
    if "float" in text:
        return _ARROW_OF["float"]
    if "int" in text:
        return _ARROW_OF["int"]
    if "str" in text:
        return _ARROW_OF["str"]
    raise OcsfError(
        f"no Parquet type for Event.{name} ({annotation}); add it to _ARROW_OF or "
        "to _JSON_COLUMNS rather than letting the column be dropped"
    )


# ── index builder ──────────────────────────────────────────────────────────


def build_index(
    vendor_dir: str | Path,
    out_path: str | Path,
) -> dict[str, Any]:
    """Compact the cached schema-server responses into the vendored index.

    Reads ``_classes_raw.json``, ``_classes_full.json``, ``_base_event_raw.json``,
    ``_observable_raw.json``, ``_version_raw.json`` and ``objects/*.json`` from
    ``vendor_dir``. Those raw responses total ~6 MB and are gitignored; the index
    this produces is a few hundred KB and is committed, with the digest of what it
    was built from recorded so nobody mistakes one for the other.
    """
    vendor = Path(vendor_dir)
    out = Path(out_path)

    def _read(name: str) -> Any:
        path = vendor / name
        if not path.exists():
            raise OcsfError(
                f"missing cached schema response {path}. Run "
                "`python -m core.schema.ocsf fetch` first (needs network access)."
            )
        return json.loads(path.read_text(encoding="utf-8"))

    version = _read("_version_raw.json")["version"]
    class_list = _read("_classes_raw.json")
    class_full = _read("_classes_full.json")
    base = _read("_base_event_raw.json")
    observable = _read("_observable_raw.json")

    digest = hashlib.sha256()
    for name in sorted(
        [
            "_version_raw.json",
            "_classes_raw.json",
            "_classes_full.json",
            "_base_event_raw.json",
            "_observable_raw.json",
        ]
    ):
        digest.update((vendor / name).read_bytes())

    categories: dict[str, str] = {}
    classes: dict[str, Any] = {}
    class_attributes: dict[str, list[str]] = {}
    class_attr_types: dict[str, dict[str, str | None]] = {}
    class_enums: dict[str, dict[str, dict[str, str]]] = {}

    # Excluded from the per-class enum tables below. ``activity_id`` is already
    # exposed as :attr:`OcsfClass.activities`; ``class_uid``/``type_uid``/
    # ``category_uid`` enumerate the class itself, so keeping them per class would
    # store ~87 copies of the class list to say nothing a lookup cannot.
    identity_enums = frozenset({"activity_id", "class_uid", "type_uid", "category_uid"})

    for entry in class_list:
        uid = entry["uid"]
        name = entry["name"]
        extension = entry.get("extension")
        # base_event (uid 0) is the abstract parent every class extends, not
        # something a collector can emit. Its attribute list is read separately
        # from /api/base_event for the base_required/base_recommended lists; as a
        # class it would only ever be a validation trap.
        if name == "base_event" or uid == 0:
            continue
        categories[str(entry["category_uid"])] = entry["category_name"]
        # /export/classes keys extension classes by "<extension>/<name>", where
        # /api/classes reports the bare name plus an extension field.
        full = class_full.get(f"{extension}/{name}" if extension else name)
        if full is None:
            raise OcsfError(
                f"class {uid} ({name}) is in /api/classes but not in "
                "/export/classes; the two cached responses are from different "
                "schema versions — refetch both"
            )
        attrs = full.get("attributes", {})
        activities = {
            k: v["caption"]
            for k, v in (attrs.get("activity_id", {}).get("enum", {}) or {}).items()
        }
        dep = entry.get("@deprecated") or {}
        classes[str(uid)] = {
            "name": name,
            "caption": entry["caption"],
            "category_uid": entry["category_uid"],
            "category_name": entry["category_name"],
            "extension": extension,
            "activities": activities,
            "deprecated_by": list(dep.get("superseded_by") or []),
            "required": sorted(
                k for k, v in attrs.items() if v.get("requirement") == "required"
            ),
        }
        class_attributes[str(uid)] = sorted(attrs)
        class_attr_types[str(uid)] = {
            k: (v.get("object_type") if v.get("type") == "object_t" else None)
            for k, v in attrs.items()
        }
        # Class-level enums, which the five base-event ones extracted further down do
        # not cover, and which this index carried nowhere until now. That gap had a
        # measured cost. ``status_id`` on 2004 Detection Finding is a *lifecycle*
        # enum — 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 5 Archived,
        # 6 Deleted — and not the base Success/Failure table, so a finding stamped
        # with the base ``Status.SUCCESS`` reads as "New" and ``Status.FAILURE`` as
        # "In Progress", silently and in a column a hunt query trusts. Nothing could
        # detect that while ``status_id`` resolved only to the base table.
        # ``query_result_id`` was hand-transcribed against the same gap and came out
        # one member short. Both are checkable now, per class, from the vendored
        # bundle rather than from memory.
        per_class = {
            attr: {k: v["caption"] for k, v in spec["enum"].items()}
            for attr, spec in attrs.items()
            if "enum" in spec and attr not in identity_enums
        }
        if per_class:
            class_enums[str(uid)] = per_class

    objects: dict[str, dict[str, dict[str, Any]]] = {}
    obj_dir = vendor / "objects"
    if not obj_dir.is_dir():
        raise OcsfError(f"missing {obj_dir}; run `python -m core.schema.ocsf fetch`")
    # Extension objects are referenced by classes as "<extension>/<name>"
    # (win/reg_key), but the API serves them — and the cache stores them — under
    # the bare name. Keying the index by the referenced form is what lets
    # resolve_path walk into them; without it the four win objects look unvendored.
    obj_extension = {
        e["name"]: e.get("extension")
        for e in json.loads((vendor / "_objects_list.json").read_text(encoding="utf-8"))
    }
    for path in sorted(obj_dir.glob("*.json")):
        body = json.loads(path.read_text(encoding="utf-8"))
        ext = obj_extension.get(path.stem)
        key = f"{ext}/{path.stem}" if ext else path.stem
        objects[key] = {
            k: {
                "type": v.get("type"),
                "object_type": v.get("object_type"),
                "is_array": bool(v.get("is_array")),
            }
            for k, v in body.get("attributes", {}).items()
        }
        digest.update(path.read_bytes())

    enums: dict[str, dict[str, str]] = {}
    for name in ("severity_id", "status_id", "action_id", "disposition_id", "confidence_id"):
        spec = base["attributes"].get(name, {})
        if "enum" in spec:
            enums[name] = {k: v["caption"] for k, v in spec["enum"].items()}
    fp = json.loads((obj_dir / "fingerprint.json").read_text(encoding="utf-8"))
    enums["algorithm_id"] = {
        k: v["caption"] for k, v in fp["attributes"]["algorithm_id"]["enum"].items()
    }
    enums["direction_id"] = {
        k: v["caption"]
        for k, v in json.loads(
            (obj_dir / "network_connection_info.json").read_text(encoding="utf-8")
        )["attributes"]["direction_id"]["enum"].items()
    }

    index = {
        "index_version": INDEX_VERSION,
        "ocsf_version": version,
        "source_sha256": digest.hexdigest(),
        "built_from": [
            "https://schema.ocsf.io/api/version",
            "https://schema.ocsf.io/api/classes",
            "https://schema.ocsf.io/export/classes",
            "https://schema.ocsf.io/api/base_event",
            "https://schema.ocsf.io/api/objects/*",
        ],
        "categories": categories,
        "classes": classes,
        "class_attributes": class_attributes,
        "class_attribute_types": class_attr_types,
        "class_enums": class_enums,
        "objects": objects,
        "enums": enums,
        "observable_types": {
            k: v["caption"] for k, v in observable["attributes"]["type_id"]["enum"].items()
        },
        "base_required": sorted(
            k for k, v in base["attributes"].items() if v.get("requirement") == "required"
        ),
        "base_recommended": sorted(
            k
            for k, v in base["attributes"].items()
            if v.get("requirement") == "recommended"
        ),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    tmp.replace(out)
    return index


def fetch_raw(vendor_dir: str | Path) -> dict[str, int]:
    """Download the schema-server responses the builder needs.

    Separated from :func:`build_index` so a rebuild is reproducible offline from
    the cache, and so the one step that needs network access is explicit.
    """
    import urllib.request

    vendor = Path(vendor_dir)
    (vendor / "objects").mkdir(parents=True, exist_ok=True)
    base = "https://schema.ocsf.io"
    simple = {
        "_version_raw.json": "/api/version",
        "_classes_raw.json": "/api/classes",
        "_classes_full.json": "/export/classes",
        "_base_event_raw.json": "/api/base_event",
        "_observable_raw.json": "/api/objects/observable",
        "_objects_list.json": "/api/objects",
    }
    counts = {"documents": 0, "objects": 0, "failed": 0}
    for name, route in simple.items():
        with urllib.request.urlopen(base + route, timeout=120) as resp:
            (vendor / name).write_bytes(resp.read())
        counts["documents"] += 1
    for entry in json.loads((vendor / "_objects_list.json").read_text(encoding="utf-8")):
        name, ext = entry["name"], entry.get("extension")
        route = f"/api/objects/{ext + '/' if ext else ''}{name}"
        try:
            with urllib.request.urlopen(base + route, timeout=60) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if "attributes" not in body:
                raise ValueError("response has no attributes")
            (vendor / "objects" / f"{name}.json").write_text(
                json.dumps(body, separators=(",", ":")), encoding="utf-8"
            )
            counts["objects"] += 1
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            counts["failed"] += 1
            print(f"  failed {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return counts


def _cli(argv: list[str]) -> int:
    here = Path(__file__).resolve().parents[2]
    vendor = here / "vendor" / "ocsf"
    index_path = vendor / "ocsf_index.json"
    cmd = argv[0] if argv else "stats"

    if cmd == "fetch":
        counts = fetch_raw(vendor)
        print(f"fetched {counts['documents']} documents, {counts['objects']} objects, "
              f"{counts['failed']} failed")
        return 1 if counts["failed"] else 0

    if cmd == "build":
        index = build_index(vendor, index_path)
        size = index_path.stat().st_size
        print(f"wrote {index_path} ({size/1e6:.2f} MB) for OCSF v{index['ocsf_version']}")
        print(f"  {len(index['classes'])} classes, {len(index['objects'])} objects, "
              f"{len(index['observable_types'])} observable types")
        print(f"  source_sha256 {index['source_sha256'][:16]}…")
        return 0

    sch = schema(index_path)
    if cmd == "stats":
        for key, value in sch.stats().items():
            print(f"  {key:<22} {value}")
        return 0

    if cmd == "classes":
        for uid in sorted(sch.classes):
            k = sch.classes[uid]
            flag = " [deprecated]" if k.deprecated else ""
            ext = f" ({k.extension})" if k.extension else ""
            print(f"  {uid:>7} {k.caption}{ext} — {len(k.activities)} activities{flag}")
        return 0

    if cmd == "show" and len(argv) > 1:
        for ref in argv[1:]:
            k = sch.klass(ref)
            print(f"\n{k.uid} {k.caption}  [{k.category_name}]  name={k.name}")
            if k.deprecated:
                print(f"  DEPRECATED → {', '.join(k.deprecated_by)}")
            print(f"  required: {', '.join(k.required)}")
            print("  activities:")
            for aid, cap in sorted(k.activities.items()):
                print(f"    {aid:>3} {cap:<28} type_uid={sch.type_uid(k.uid, aid)}")
        return 0

    if cmd == "paths":
        bad = 0
        for flat, path in sorted(OCSF_PATH.items()):
            try:
                kind = sch.resolve_path(path)
                print(f"  ok   {flat:<34} {path:<44} {kind}")
            except OcsfError as exc:
                bad += 1
                print(f"  BAD  {flat:<34} {path:<44} {exc}")
        print(f"\n{len(OCSF_PATH)} paths, {bad} broken")
        return 1 if bad else 0

    print(
        "usage: python -m core.schema.ocsf [fetch|build|stats|classes|paths|"
        "show <class>…]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))

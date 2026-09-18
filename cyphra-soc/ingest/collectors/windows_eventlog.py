"""Windows Event Log collector — the Evt* machinery, shared with Sysmon.

This is the single biggest local telemetry source on Windows and the one most
often collected badly. Three decisions account for most of that.

**1. The cursor is a bookmark, not a timestamp.** The obvious implementation polls
"events since the last time I looked". It is wrong, and it fails in both
directions: the Event Log service writes records in *record-id* order, not
timestamp order, so a record whose ``TimeCreated`` is earlier than one already
seen appears afterwards — a timestamp cursor skips it forever. And an inclusive
timestamp comparison re-reads the boundary record on every poll, which
double-counts. Windows provides the correct primitive: ``EvtCreateBookmark`` /
``EvtUpdateBookmark`` produce an opaque position that ``EvtQuery`` resumes from
exactly. It serialises to XML, so it survives a restart when persisted. This is why
the collector uses the modern ``Evt*`` API rather than the simpler legacy
``ReadEventLog``, which has no bookmark and cannot read the
``Microsoft-Windows-*/Operational`` channels at all — including Sysmon's.

**2. Each channel is probed and reported separately.** ``Security`` needs
elevation, the Sysmon channel needs Sysmon installed, and everything else on a
default install is readable by an ordinary user. Verified on this host: ``System``,
``Application``, ``Microsoft-Windows-PowerShell/Operational``, Defender,
TaskScheduler and WMI-Activity all read unelevated; ``Security`` returns
``ERROR_ACCESS_DENIED (5)`` and the Sysmon channel returns
``ERROR_EVT_CHANNEL_NOT_FOUND (15007)``. Collapsing those into one "Windows Event
Log unavailable" would hide the fact that most of it works, and hide *which* of the
two very different fixes is needed. So a channel that cannot be read is skipped
with its own reason, the rest of the collector runs, and the reasons are reported.

**3. An unmapped event id is stored, not dropped.** :data:`EVENT_MAP` gives OCSF
class and activity for the ids that carry security meaning. The Windows Event Log
has thousands of ids and most are operational noise, but "most" is not "all", and
a collector that dropped everything it did not recognise would make every future
detection depend on editing this table first. Unrecognised records are stored as
their channel's default class with their full ``EventData`` in ``unmapped``, so a
hunt can find them and a rule can be written against them the same day rather than
the next release. What is *not* done is guessing a semantic class for them.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence

from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import (
    Availability,
    PullCollector,
    available,
    is_windows,
    unavailable,
)

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

#: Windows ``Level`` → OCSF ``severity_id``. Level 0 (LogAlways) is deliberately
#: mapped to Informational rather than to Unknown: it means "always log this",
#: which is a routing instruction, not a statement about severity.
_LEVEL_SEVERITY = {
    0: int(Severity.INFORMATIONAL),
    1: int(Severity.CRITICAL),
    2: int(Severity.HIGH),
    3: int(Severity.MEDIUM),
    4: int(Severity.INFORMATIONAL),
    5: int(Severity.INFORMATIONAL),
}


class _Mapped:
    """An event id's OCSF meaning. A plain class so the table below stays readable."""

    __slots__ = ("class_uid", "activity_id", "label", "status_id", "severity_id",
                 "activity_from")

    def __init__(
        self,
        class_uid: int,
        activity_id: int,
        label: str,
        *,
        status_id: int | None = None,
        severity_id: int | None = None,
        activity_from: Any = None,
    ) -> None:
        self.class_uid = class_uid
        self.activity_id = activity_id
        self.label = label
        self.status_id = status_id
        self.severity_id = severity_id
        #: Optional ``dict[str, str] -> int | None`` reading the activity out of the
        #: record's own EventData. Exactly one event needs it (7036, whose whole
        #: payload *is* the new state), and a table where 40 rows are constants and
        #: one is a function is more honest than 41 rows of functions.
        self.activity_from = activity_from


_A = int(ClassUid.AUTHENTICATION)
_P = int(ClassUid.PROCESS_ACTIVITY)
_SCRIPT = int(ClassUid.SCRIPT_ACTIVITY)
_UM = int(ClassUid.USER_MANAGEMENT)
_GM = int(ClassUid.GROUP_MANAGEMENT)
_SVC = int(ClassUid.WINDOWS_SERVICE_ACTIVITY)
_SCHED = int(ClassUid.SCHEDULED_JOB_ACTIVITY)
_SESS = int(ClassUid.AUTHORIZE_SESSION)
_WINRES = int(ClassUid.WINDOWS_RESOURCE_ACTIVITY)

#: Status ids from the OCSF base event: 1 Success, 2 Failure.
_SUCCESS, _FAILURE = 1, 2

#: Service Control Manager 7036's state string → ``win/windows_service_activity``
#: activity. The state is the entire content of the event, so reading it is what
#: makes 7036 usable: mapped to a constant, "service stopped" and "service started"
#: would be the same event and a rule for "security agent stopped" could not exist.
_SERVICE_STATE_ACTIVITY = {
    "running": 3,   # Start
    "stopped": 4,   # Stop
    "paused": 5,    # Pause
}


def _service_state_activity(data: dict[str, str]) -> int | None:
    for key in ("param2", "Data1", "state"):
        value = (data.get(key) or "").strip().lower()
        if value in _SERVICE_STATE_ACTIVITY:
            return _SERVICE_STATE_ACTIVITY[value]
    return None


#: The event ids that carry security meaning, with their OCSF class and activity.
#:
#: This table is the collector's actual detection surface, so it is explicit rather
#: than derived. Each entry is here because a real technique produces it: 4625 is
#: password spraying and brute force, 4648 is explicit-credential use and the
#: clearest single signal of lateral movement with stolen credentials, 4672 is
#: privileged-logon assignment, 1102 is an attacker clearing the audit trail, 7045
#: is a service installed for persistence or for PsExec-style remote execution,
#: 4698 is a scheduled task, 4720/4732 are account creation and privileged-group
#: addition.
#:
#: **Every activity id here is checked against the vendored OCSF schema by
#: ``tests/scratch_collectors.py``, and that test is not optional.** ``Event``
#: validates ``activity_id`` against its class's enum and *rejects* a mismatch, so
#: a plausible-looking wrong number does not raise here — it quarantines the event
#: at ingest. A single wrong digit against 4624 would mean CYPHRA collected no
#: logons at all while every counter and dashboard reported a healthy source.
EVENT_MAP: dict[int, _Mapped] = {
    # ── logon and credential use (Security) ──
    # 3002 activities: 1 Logon, 2 Logoff, 3 Authentication Ticket,
    # 4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth, 7 Account Switch.
    4624: _Mapped(_A, 1, "Logon", status_id=_SUCCESS),
    4625: _Mapped(_A, 1, "Logon failed", status_id=_FAILURE,
                  severity_id=int(Severity.LOW)),
    4634: _Mapped(_A, 2, "Logoff", status_id=_SUCCESS),
    4647: _Mapped(_A, 2, "User-initiated logoff", status_id=_SUCCESS),
    4648: _Mapped(_A, 1, "Logon with explicit credentials", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
    4768: _Mapped(_A, 3, "Kerberos TGT requested", status_id=_SUCCESS),
    4769: _Mapped(_A, 4, "Kerberos service ticket requested", status_id=_SUCCESS),
    4770: _Mapped(_A, 5, "Kerberos service ticket renewed", status_id=_SUCCESS),
    4771: _Mapped(_A, 6, "Kerberos pre-authentication failed", status_id=_FAILURE,
                  severity_id=int(Severity.LOW)),
    4776: _Mapped(_A, 1, "NTLM credential validation", status_id=_SUCCESS),
    # A reconnect to a disconnected session is modelled as a logon rather than as
    # AUTHORIZE_SESSION, whose activities are only Assign Privileges / Groups /
    # Roles. It genuinely re-establishes an interactive session, and a rule for RDP
    # session hijack wants it next to 4624; the event code still separates them.
    4778: _Mapped(_A, 1, "Session reconnected", status_id=_SUCCESS),
    4779: _Mapped(_A, 2, "Session disconnected", status_id=_SUCCESS),
    # 3003 activities: 1 Assign Privileges, 2 Assign Groups, 3 Assign Roles.
    4672: _Mapped(_SESS, 1, "Special privileges assigned to new logon",
                  status_id=_SUCCESS, severity_id=int(Severity.LOW)),
    # ── process (Security, requires audit policy) ──
    # 1007 activities: 1 Launch, 2 Terminate, 3 Open, 4 Inject, 5 Set User ID.
    4688: _Mapped(_P, 1, "Process created", status_id=_SUCCESS),
    4689: _Mapped(_P, 2, "Process terminated", status_id=_SUCCESS),
    # ── account management (Security) ──
    # 3007 activities: 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Lock,
    # 7 Unlock, 8 Password Change, 9 Password Reset.
    4720: _Mapped(_UM, 1, "User account created", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4722: _Mapped(_UM, 4, "User account enabled", status_id=_SUCCESS),
    4723: _Mapped(_UM, 8, "Password change attempted", status_id=_SUCCESS),
    4724: _Mapped(_UM, 9, "Password reset attempted", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
    4725: _Mapped(_UM, 5, "User account disabled", status_id=_SUCCESS),
    4726: _Mapped(_UM, 3, "User account deleted", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4738: _Mapped(_UM, 2, "User account changed", status_id=_SUCCESS),
    4740: _Mapped(_UM, 6, "User account locked out", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
    4767: _Mapped(_UM, 7, "User account unlocked", status_id=_SUCCESS),
    4781: _Mapped(_UM, 2, "Account name changed", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
    # ── group management (Security) ──
    # 3006 activities: 3 Add User, 4 Remove User, 5 Delete, 6 Create, 9 Update.
    4727: _Mapped(_GM, 6, "Security-enabled global group created", status_id=_SUCCESS),
    4728: _Mapped(_GM, 3, "Member added to global group", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4729: _Mapped(_GM, 4, "Member removed from global group", status_id=_SUCCESS),
    4731: _Mapped(_GM, 6, "Security-enabled local group created", status_id=_SUCCESS),
    4732: _Mapped(_GM, 3, "Member added to local group", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4733: _Mapped(_GM, 4, "Member removed from local group", status_id=_SUCCESS),
    4734: _Mapped(_GM, 5, "Security-enabled local group deleted", status_id=_SUCCESS),
    4754: _Mapped(_GM, 6, "Security-enabled universal group created",
                  status_id=_SUCCESS),
    4756: _Mapped(_GM, 3, "Member added to universal group", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4757: _Mapped(_GM, 4, "Member removed from universal group", status_id=_SUCCESS),
    # ── the audit trail itself (Security) ──
    # 201003 has only 0 Unknown / 1 Access / 99 Other, so these two — which are a
    # deletion and a configuration change — get 99. The alternative was to invent
    # "Access", which would be a false statement about what happened, in the two
    # events an incident responder reads first.
    1102: _Mapped(_WINRES, 99, "Audit log cleared", status_id=_SUCCESS,
                  severity_id=int(Severity.HIGH)),
    4719: _Mapped(_WINRES, 99, "System audit policy changed", status_id=_SUCCESS,
                  severity_id=int(Severity.HIGH)),
    # ── services (System / Security) ──
    # 201004 activities: 1 Create, 2 Reconfigure, 3 Start, 4 Stop, 5 Pause,
    # 6 Continue, 7 Delete.
    7045: _Mapped(_SVC, 1, "Service installed", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4697: _Mapped(_SVC, 1, "Service installed (audited)", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    7034: _Mapped(_SVC, 4, "Service terminated unexpectedly", status_id=_FAILURE,
                  severity_id=int(Severity.LOW)),
    7036: _Mapped(_SVC, 0, "Service state changed", status_id=_SUCCESS,
                  activity_from=_service_state_activity),
    7040: _Mapped(_SVC, 2, "Service start type changed", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
    # ── scheduled tasks (Security) ──
    # 1006 activities: 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Start.
    4698: _Mapped(_SCHED, 1, "Scheduled task created", status_id=_SUCCESS,
                  severity_id=int(Severity.MEDIUM)),
    4699: _Mapped(_SCHED, 3, "Scheduled task deleted", status_id=_SUCCESS),
    4700: _Mapped(_SCHED, 4, "Scheduled task enabled", status_id=_SUCCESS),
    4701: _Mapped(_SCHED, 5, "Scheduled task disabled", status_id=_SUCCESS),
    4702: _Mapped(_SCHED, 2, "Scheduled task updated", status_id=_SUCCESS),
    # ── PowerShell (Microsoft-Windows-PowerShell/Operational) ──
    # 1009 activities: 1 Execute. See the ClassUid.SCRIPT_ACTIVITY comment for why
    # this is not PROCESS_ACTIVITY.
    4103: _Mapped(_SCRIPT, 1, "PowerShell pipeline execution", status_id=_SUCCESS),
    4104: _Mapped(_SCRIPT, 1, "PowerShell script block logged", status_id=_SUCCESS,
                  severity_id=int(Severity.LOW)),
}

#: ``EventData/Data[@Name]`` keys, per event id, mapped onto flat OCSF fields.
#: Only the fields a detection or a correlation actually reads. The rest of
#: ``EventData`` is kept in ``unmapped``, so nothing is lost by this table being
#: incomplete — it just is not queryable as a first-class column yet.
#:
#: Every value here is a real field of :class:`~core.schema.ocsf.Event`. That is
#: load-bearing: ``Event.build`` routes an unknown key into ``unmapped`` and notes
#: it, so a name that does not exist would not raise — it would produce a correct
#: looking event with a silently unqueryable field, on every record, forever.
DATA_MAP: dict[str, str] = {
    # Subject = who did it. Target = who or what it was done to. Windows is
    # consistent about this prefix and OCSF's actor/user split matches it exactly,
    # which is why 4720 ("SubjectUserName created TargetUserName") survives the
    # mapping with both parties intact.
    "TargetUserName": "user_name",
    "TargetDomainName": "user_domain",
    "TargetUserSid": "user_uid",
    "TargetSid": "user_uid",
    "SubjectUserName": "actor_user_name",
    "SubjectDomainName": "actor_user_domain",
    "SubjectUserSid": "actor_user_uid",
    "SubjectLogonId": "actor_session_uid",
    "TargetLogonId": "session_uid",
    "LogonType": "logon_type_id",
    "LogonProcessName": "logon_process_name",
    "WorkstationName": "src_endpoint_hostname",
    "IpAddress": "src_endpoint_ip",
    "IpPort": "src_endpoint_port",
    "ProcessName": "actor_process_file_path",
    "NewProcessName": "process_file_path",
    "NewProcessId": "process_pid",
    "ParentProcessName": "actor_process_file_path",
    "CommandLine": "process_cmd_line",
    "ServiceName": "service_name",
    "ServiceFileName": "process_file_path",
    "ImagePath": "process_file_path",
    "TaskName": "job_name",
    "AuthenticationPackageName": "auth_protocol",
    "LmPackageName": "auth_protocol",
    "Status": "status_code",
    "FailureReason": "status_detail",
    "SubStatus": "status_detail",
    "TargetServerName": "dst_endpoint_hostname",
    "MemberName": "user_name",
    "MemberSid": "user_uid",
    "GroupName": "group_name",
    "GroupSid": "group_uid",
    "GroupDomain": "group_domain",
    "ScriptBlockText": "process_cmd_line",
}

#: Logon types that are worth naming. Kept as data because the *number* is what
#: detections match on and the caption is what an analyst reads.
#:
#: The captions are OCSF's own, from the ``logon_type_id`` enum in the vendored
#: schema, rather than Windows' spelling of the same concepts (``Service`` /
#: ``NetworkCleartext``). ``logon_type`` is OCSF's free-text sibling of
#: ``logon_type_id``, so using the enum's caption means the two never disagree with
#: each other in an exported document.
#:
#: 12 and 13 are here because Windows really does emit them — a cached credential
#: used for RDP and for an unlock respectively, on a host that cannot reach a domain
#: controller. Omitting them would not lose the event; it would render the caption as
#: the bare string "12", which is what an analyst sees when reading the record that
#: says a laptop authenticated with no DC in sight.
LOGON_TYPES = {
    1: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "OS Service",
    7: "Unlock",
    8: "Network Cleartext",
    9: "New Credentials",
    10: "Remote Interactive",
    11: "Cached Interactive",
    12: "Cached Remote Interactive",
    13: "Cached Unlock",
}


class Channel:
    """One Event Log channel, with its own bookmark and its own availability."""

    __slots__ = ("path", "default_class", "critical", "why_unavailable", "bookmark_xml",
                 "read", "skipped", "filtered", "errors", "last_error", "failed_samples")

    def __init__(self, path: str, default_class: int, *, critical: bool = False) -> None:
        self.path = path
        self.default_class = default_class
        self.critical = critical
        self.why_unavailable = ""
        self.bookmark_xml = ""
        self.read = 0
        #: Records the cursor moved past without emitting. Not the same as an error
        #: count: one bad record produces one error and one skip, but a persistent
        #: bookmark-write failure produces errors without skips.
        self.skipped = 0
        #: Records a subclass declined to emit *on purpose* — see
        #: :meth:`WindowsEventLogCollector._to_event`'s ``None`` return. Kept apart
        #: from ``skipped`` because the two say opposite things about the collector:
        #: a skip is loss it did not choose, a filter is loss it did. Both are
        #: printed, because a filter that is not counted is indistinguishable from a
        #: channel that has gone quiet.
        self.filtered = 0
        self.errors = 0
        self.last_error = ""
        #: Up to three XML samples of records that failed to map, so a mapping bug
        #: can be reproduced from the report without re-running the collector and
        #: hoping the record recurs.
        self.failed_samples: list[str] = []

    @property
    def slug(self) -> str:
        return self.path.replace("/", "_").replace("-", "_").replace(" ", "_")


#: The channels collected by default, in the order they matter.
#:
#: ``Security`` is first and marked critical: it is where authentication,
#: privilege and account-management auditing live, and a SOC on Windows without it
#: is not monitoring identity at all. It also needs elevation, which is why the
#: setup instructions lead with that.
def default_channels() -> list[Channel]:
    return [
        Channel("Security", int(ClassUid.AUTHENTICATION), critical=True),
        Channel("System", int(ClassUid.WINDOWS_RESOURCE_ACTIVITY)),
        Channel("Microsoft-Windows-PowerShell/Operational", int(ClassUid.SCRIPT_ACTIVITY)),
        Channel("Microsoft-Windows-Windows Defender/Operational", int(ClassUid.DETECTION_FINDING)),
        Channel("Microsoft-Windows-TaskScheduler/Operational", int(ClassUid.SCHEDULED_JOB_ACTIVITY)),
        Channel("Microsoft-Windows-WMI-Activity/Operational", int(ClassUid.PROCESS_ACTIVITY)),
        Channel("Application", int(ClassUid.WINDOWS_RESOURCE_ACTIVITY)),
    ]


def parse_event_xml(xml: str) -> dict[str, Any]:
    """One rendered Event Log record → a flat dict of System + EventData values.

    ElementTree rather than ``EvtFormatMessage``. The formatted message is a
    localised human sentence assembled from the provider's message DLL: it is
    roughly two orders of magnitude slower, it is unavailable when the provider is
    uninstalled, and it changes with the machine's display language — so a rule
    matching on it would work on an English host and silently fail on a German
    one. The XML fields are stable and locale-independent.
    """
    root = ET.fromstring(xml)
    sysel = root.find(f"{_NS}System")
    out: dict[str, Any] = {"_data": {}}
    if sysel is not None:
        for child in sysel:
            tag = child.tag.replace(_NS, "")
            if tag == "Provider":
                out["provider"] = child.get("Name") or ""
                out["provider_guid"] = child.get("Guid") or ""
            elif tag == "TimeCreated":
                out["time_created"] = child.get("SystemTime") or ""
            elif tag == "Correlation":
                out["activity_id"] = child.get("ActivityID") or ""
            elif tag == "Execution":
                out["process_id"] = child.get("ProcessID") or ""
                out["thread_id"] = child.get("ThreadID") or ""
            elif tag == "Security":
                out["user_sid"] = child.get("UserID") or ""
            else:
                out[tag.lower()] = (child.text or "").strip()

    data = root.find(f"{_NS}EventData")
    if data is not None:
        unnamed = 0
        for d in data:
            tag = d.tag.replace(_NS, "")
            text = (d.text or "").strip()
            if tag == "Data":
                name = d.get("Name")
                if name:
                    out["_data"][name] = text
                elif text:
                    # Providers that emit positional Data elements (most of the
                    # System channel) are keyed by index. Dropping them would lose
                    # the entire payload of, for example, 7045 on older builds.
                    out["_data"][f"Data{unnamed}"] = text
                    unnamed += 1
            elif tag == "Binary":
                if text:
                    out["_data"]["Binary"] = text
            else:
                out["_data"][tag] = text

    # Some providers use UserData instead of EventData; Sysmon does not, but
    # TaskScheduler and several Microsoft-Windows-* channels do, and ignoring it
    # would make those channels look empty of detail.
    ud = root.find(f"{_NS}UserData")
    if ud is not None:
        for sub in ud.iter():
            tag = sub.tag.split("}")[-1]
            if sub.text and sub.text.strip() and tag not in ("UserData",):
                out["_data"].setdefault(tag, sub.text.strip())
    return out


def _iso_to_epoch(iso: str) -> float | None:
    """``2026-08-28T19:04:45.9448922Z`` → epoch seconds.

    Hand-parsed because Windows emits 7 fractional digits and
    ``datetime.fromisoformat`` rejects anything but 3 or 6 before Python 3.11 and
    still rejects 7. Truncating to microseconds loses 100ns of precision, which no
    correlation window cares about, where failing to parse loses the event.
    """
    if not iso:
        return None
    s = iso.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        frac = (frac + "000000")[:6]
        s = f"{head}.{frac}"
    from datetime import datetime, timezone

    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


class WindowsEventLogCollector(PullCollector):
    """Security, System and the Microsoft-Windows-* operational channels."""

    name = "windows_eventlog"
    cadence_seconds = 30.0
    critical = True
    description = (
        "Windows Event Log via the Evt* API with per-channel bookmarks — logon, "
        "privilege, account management, services, scheduled tasks, PowerShell"
    )
    #: The mapping tables, as class attributes so a subclass reading a different
    #: provider swaps them without touching the Evt machinery. :mod:`sysmon` is that
    #: subclass: same bookmarks, same probing, same skip-and-count, entirely
    #: different event ids and field names.
    event_map: dict[int, _Mapped] = EVENT_MAP
    #: Consulted *before* :attr:`event_map`, keyed by ``(provider, event_id)``.
    #:
    #: An event id is only unique within its provider, and the moment a collector
    #: reads more than a handful of channels the collisions are real rather than
    #: theoretical: ``Microsoft-Windows-Winlogon`` and
    #: ``Microsoft-Windows-User Profile Service`` both write ids 1 and 2, meaning
    #: entirely different things, and :mod:`local_auth` reads both. A single
    #: ``{1: ...}`` entry would map one provider's event onto the other's OCSF class
    #: on every record, forever, with nothing raising — the class of failure this
    #: file is otherwise written to avoid.
    #:
    #: Keyed on ``provider`` rather than on the channel path because the provider is
    #: what actually determines an id's meaning: one provider writes to several
    #: channels, and a Windows Event Forwarding subscription rewrites the channel to
    #: ``ForwardedEvents`` while leaving the provider intact.
    event_map_by_provider: dict[tuple[str, int], _Mapped] = {}
    data_map: dict[str, str] = DATA_MAP
    #: Per-OCSF-class overrides of :attr:`data_map`, consulted first.
    #:
    #: One flat ``EventData`` name → field table cannot be correct for a provider
    #: whose events span several OCSF classes, because the *same* source field means
    #: different things depending on the class. Sysmon's ``Image`` is the canonical
    #: case: on event 1 it is the process that was created — the subject of a 1007 —
    #: and on events 3, 7, 11, 12 and 22 it is the process that did the connecting,
    #: loading, writing or resolving, which is the *actor* of a 4001, 1005, 1001,
    #: 201001 or 4003. OCSF declares a top-level ``process`` on only the seven classes
    #: whose subject is a process, so on the others the acting process belongs under
    #: ``actor.process`` and ``process_pid`` has nowhere to land.
    #:
    #: Keyed on the resolved class rather than on the event id deliberately. The
    #: invariant being expressed is a property of the class ("this class has no
    #: subject process"), so keying on it means a newly-mapped event id inherits the
    #: correct treatment from its class the moment it is added to
    #: :attr:`event_map`, instead of needing a second table updated in lockstep —
    #: which is the kind of paired edit that gets forgotten and reintroduces exactly
    #: this defect.
    #:
    #: An override value that is empty suppresses the field for that class rather
    #: than falling through to :attr:`data_map`.
    data_map_by_class: dict[int, dict[str, str]] = {}

    def __init__(
        self,
        pipeline: Any,
        *,
        channels: Sequence[Channel] | None = None,
        max_per_cycle: int = 2000,
        state_dir: Path | str | None = None,
        bootstrap_lookback_seconds: float = 900.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(pipeline, **kwargs)
        self.channels = list(channels) if channels is not None else default_channels()
        #: Cap per channel per cycle, not per collector per cycle. A busy Security
        #: log would otherwise consume the whole budget and starve the six other
        #: channels indefinitely — the source would look healthy while Sysmon,
        #: PowerShell and Defender silently stopped being collected.
        self.max_per_cycle = max_per_cycle
        self.state_dir = Path(state_dir) if state_dir else Path("var/collectors")
        #: How far back the *first* poll of a channel reaches when there is no
        #: bookmark yet. Bounded on purpose. A forward query with no seek starts at
        #: the oldest record the channel still holds, so an unbounded first run
        #: would replay a whole Security log — hundreds of thousands of records,
        #: hours stale, arriving as a burst that looks exactly like an incident. A
        #: fixed lookback means startup costs a known amount and the operator can
        #: widen it deliberately for a backfill.
        self.bootstrap_lookback_seconds = bootstrap_lookback_seconds
        self.unmapped_ids: dict[tuple[str, int], int] = {}
        self._win: Any = None

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        if not is_windows():
            return unavailable(
                "the Windows Event Log exists only on Windows", fixable_by_user=False
            )
        try:
            import win32evtlog  # noqa: F401
        except Exception as exc:
            return unavailable(
                f"pywin32 is not importable ({exc}); pip install pywin32"
            )
        # Each channel answers for itself. The collector is available if *any*
        # channel is, because six readable channels are worth collecting even
        # while Security is denied — and reporting the whole collector as
        # unavailable because of one channel is how a working source gets ignored.
        readable = self._probe_channels()
        if not readable:
            reasons = "; ".join(f"{c.path}: {c.why_unavailable}" for c in self.channels)
            return unavailable(f"no Event Log channel is readable — {reasons}")
        return available()

    def _probe_channels(self) -> list[Channel]:
        import win32evtlog as w

        readable = []
        for ch in self.channels:
            try:
                h = w.EvtQuery(
                    ch.path,
                    w.EvtQueryChannelPath | w.EvtQueryReverseDirection,
                    "*",
                    None,
                )
                w.EvtNext(h, 1, 1000, 0)
                ch.why_unavailable = ""
                readable.append(ch)
            except Exception as exc:
                ch.why_unavailable = self._explain(ch, exc)
        return readable

    @staticmethod
    def _explain(ch: Channel, exc: BaseException) -> str:
        """Turn a Win32 error into the action that fixes it.

        Error 5 and error 15007 are the two that actually happen, they need
        completely different remedies, and neither is guessable from the raw
        message. Anything else is reported verbatim rather than guessed at.
        """
        code = getattr(exc, "winerror", None)
        if code == 5:
            return (
                f"access denied reading {ch.path} — this channel requires an "
                "elevated process. Start the shell with 'Run as administrator', or "
                "add the service account to the built-in 'Event Log Readers' group "
                "(net localgroup \"Event Log Readers\" <account> /add) and restart it."
            )
        if code == 15007:
            return (
                f"the channel {ch.path} does not exist on this host — the provider "
                "that creates it is not installed"
            )
        if code == 15011:
            return f"{ch.path} exists but is disabled; enable it in Event Viewer"
        return f"{type(exc).__name__} reading {ch.path}: {exc}"

    # ── bookmarks ──────────────────────────────────────────────────────────

    def _bookmark_path(self, ch: Channel) -> Path:
        return self.state_dir / f"{self.name}.{ch.slug}.bookmark.xml"

    async def open(self) -> None:
        import win32evtlog as w

        self._win = w
        self.state_dir.mkdir(parents=True, exist_ok=True)
        # Re-probed at open, not trusted from the earlier availability check: the
        # gap between "the fleet listed what is available" and "the collector
        # started" is where an operator elevates the shell or installs Sysmon, and
        # a cached answer would keep reporting a gap that has just been fixed.
        self._probe_channels()
        for ch in self.channels:
            p = self._bookmark_path(ch)
            if p.is_file():
                try:
                    ch.bookmark_xml = p.read_text(encoding="utf-8")
                except OSError as exc:
                    # A corrupt bookmark means starting from *now*, not from the
                    # beginning: replaying a 200 MB Security log into the pipeline
                    # because a file was truncated would be a self-inflicted flood.
                    ch.last_error = f"bookmark unreadable, resuming from now: {exc}"

    def _save_bookmark(self, ch: Channel) -> None:
        if not ch.bookmark_xml:
            return
        p = self._bookmark_path(ch)
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(ch.bookmark_xml, encoding="utf-8")
            tmp.replace(p)
        except OSError as exc:
            ch.errors += 1
            ch.last_error = f"could not persist bookmark: {exc}"

    # ── polling ────────────────────────────────────────────────────────────

    async def poll(self) -> Sequence[dict[str, Any]]:
        # Off the event loop: EvtQuery/EvtNext are blocking Win32 calls and a
        # 2000-record read on a busy Security log takes long enough that doing it
        # inline would stall every other collector and the health monitor with it.
        import asyncio

        return await asyncio.to_thread(self._poll_sync)

    def _poll_sync(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for ch in self.channels:
            if ch.why_unavailable:
                continue
            try:
                out.extend(self._read_channel(ch))
            except Exception as exc:
                ch.errors += 1
                ch.last_error = f"{type(exc).__name__}: {exc}"
        return out

    def _read_channel(self, ch: Channel) -> list[dict[str, Any]]:
        w = self._win
        flags = w.EvtQueryChannelPath | w.EvtQueryForwardDirection
        if ch.bookmark_xml:
            handle = w.EvtQuery(ch.path, flags, "*", None)
            bookmark = w.EvtCreateBookmark(ch.bookmark_xml)
            # Seek *past* the bookmarked record — offset 1, not 0. Verified against
            # this host's Application channel: bookmarking record 67690 and seeking
            # with offset 0 returns [67690, 67691, 67692]; with offset 1 it returns
            # [67691, 67692]. Offset 0 would re-emit one record on every single poll
            # of every channel forever, which dedup would hide and the event counts
            # would not.
            #
            # The argument order is pywin32's, not Win32's: EvtSeek(ResultSet,
            # Position, Flags, Bookmark). Passing the bookmark third — as the C
            # signature has it — raises TypeError, which is at least loud.
            w.EvtSeek(handle, 1, w.EvtSeekRelativeToBookmark, bookmark)
        else:
            # First poll of this channel. A bounded time filter rather than a seek:
            # timediff() is evaluated by the Event Log service against each record's
            # TimeCreated, so the flood never crosses the process boundary in the
            # first place. Confirmed working on this host.
            ms = int(max(1.0, self.bootstrap_lookback_seconds) * 1000)
            query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
            handle = w.EvtQuery(ch.path, flags, query, None)
            bookmark = w.EvtCreateBookmark(None)

        payloads: list[dict[str, Any]] = []
        consumed = 0
        while len(payloads) < self.max_per_cycle:
            want = min(200, self.max_per_cycle - len(payloads))
            try:
                events = w.EvtNext(handle, want, 1000, 0)
            except Exception as exc:
                # 259 = ERROR_NO_MORE_ITEMS. On this host EvtNext returns a short
                # tuple instead, but the API is documented to raise, and treating
                # the documented end-of-set as a channel error would show a
                # perfectly healthy channel as failing on every poll.
                if getattr(exc, "winerror", None) in (259, 1460):
                    break
                raise
            if not events:
                break
            for ev in events:
                # The bookmark advances for every record *consumed*, whether or not
                # it mapped. That is a deliberate choice of loss over deadlock: a
                # record that cannot be mapped will not map on the next poll either,
                # so holding the cursor behind it would re-read the same poison
                # record every 30 seconds and never collect anything after it — one
                # malformed provider payload would silently mute the channel. The
                # skip is counted and a sample of the XML is kept, so the loss shows
                # up in the report instead of being invisible.
                try:
                    xml = w.EvtRender(ev, w.EvtRenderEventXml)
                except Exception as exc:
                    ch.errors += 1
                    ch.skipped += 1
                    ch.last_error = f"render failed: {exc}"
                    w.EvtUpdateBookmark(bookmark, ev)
                    consumed += 1
                    continue
                try:
                    payload = self._to_event(ch, xml)
                except Exception as exc:
                    ch.errors += 1
                    ch.skipped += 1
                    ch.last_error = f"map failed: {type(exc).__name__}: {exc}"
                    if len(ch.failed_samples) < 3:
                        ch.failed_samples.append(xml[:2000])
                else:
                    # None means "a subclass looked at this record and decided it is
                    # not worth an event". Counted separately from a skip and printed
                    # in the channel report, so a volume filter is always visible as
                    # a filter rather than as a channel that produces less than it
                    # reads.
                    if payload is None:
                        ch.filtered += 1
                    else:
                        payloads.append(payload)
                        ch.read += 1
                w.EvtUpdateBookmark(bookmark, ev)
                consumed += 1
            if len(events) < want:
                break

        if consumed:
            # Persisted on records consumed, not on records emitted. The two differ
            # exactly when something was skipped, and that is the case where not
            # persisting would wedge the channel.
            ch.bookmark_xml = w.EvtRender(bookmark, w.EvtRenderBookmark)
            self._save_bookmark(ch)
        return payloads

    # ── mapping ────────────────────────────────────────────────────────────

    def _to_event(self, ch: Channel, xml: str) -> dict[str, Any] | None:
        """One record → one pipeline payload, or ``None`` to drop it deliberately.

        Subclasses that return ``None`` must be doing it for a named, counted reason
        — the base class never does.
        """
        rec = parse_event_xml(xml)
        data: dict[str, str] = rec.get("_data", {})
        try:
            eid = int(rec.get("eventid") or 0)
        except ValueError:
            eid = 0

        when = _iso_to_epoch(rec.get("time_created", ""))
        provider = rec.get("provider", "")
        # Provider-qualified first, bare id second. The order is what makes the
        # qualified table an override rather than a suggestion.
        mapped = self.event_map_by_provider.get((provider, eid))
        if mapped is None:
            mapped = self.event_map.get(eid)
        if mapped is None:
            # Counted per provider, not per id. Merging them would report "id 1
            # unmapped x400" for two providers whose id 1 are unrelated events, and
            # whoever read that would go looking for one mapping instead of two.
            key = (provider, eid)
            self.unmapped_ids[key] = self.unmapped_ids.get(key, 0) + 1

        try:
            level = int(rec.get("level") or 4)
        except ValueError:
            level = 4

        record_id = rec.get("eventrecordid") or ""
        computer = rec.get("computer") or ""
        # `EventRecordID` is unique *within a channel on a host*, and nothing more.
        # The pipeline's exact-dedup identity is `source \0 metadata_uid` with no
        # agent id in it, so a bare record id would make System record 156568 and
        # Application record 156568 the same event — and the same record id on two
        # different hosts one event across the fleet. Both would be silent loss with
        # no error anywhere. Qualifying by the writing host and the channel makes
        # the id mean what dedup assumes it means. The host comes from the record's
        # own <Computer>, not from this machine's hostname: for a forwarded-events
        # subscription those differ, and the record's own value is the correct one.
        uid = f"{computer}/{ch.path}:{record_id}" if record_id else None

        activity_id = 0
        if mapped is not None:
            activity_id = mapped.activity_id
            if mapped.activity_from is not None:
                # A dynamic activity that cannot be read falls back to the table's
                # value (0, Unknown) rather than to a guess. "Unknown state" is a
                # true statement; "Start" would not be.
                resolved = mapped.activity_from(data)
                if resolved is not None:
                    activity_id = resolved

        payload: dict[str, Any] = {
            # `time` comes from the record's own TimeCreated. The Event Log service
            # stamps it at write, so it is the closest thing to when the thing
            # happened; the ingest clock would record when we got round to reading.
            "time": when,
            "class_uid": mapped.class_uid if mapped else ch.default_class,
            "activity_id": activity_id,
            "severity_id": (
                mapped.severity_id
                if mapped and mapped.severity_id is not None
                else _LEVEL_SEVERITY.get(level, int(Severity.INFORMATIONAL))
            ),
            "metadata_event_code": str(eid),
            "metadata_log_name": ch.path,
            "metadata_log_provider": rec.get("provider", ""),
            "metadata_uid": uid,
            "metadata_sequence": _int_or_none(record_id),
            "metadata_product_name": "Windows Event Log",
            "metadata_product_vendor_name": "Microsoft",
            "device_hostname": computer or None,
            "metadata_labels": [f"channel:{ch.path}"],
        }
        if mapped:
            payload["message"] = mapped.label
            if activity_id == 99:
                # OCSF requires `activity_name` alongside activity_id 99, and the
                # event model enforces it — `Event.build` raises rather than storing a
                # record that says only "the schema had no match for this". Without
                # this line every 99 mapping in the tables above was built, validated,
                # rejected and quarantined: 1102 "audit log cleared" (T1070.001, one of
                # the highest-signal records Windows writes), 4719 audit-policy change,
                # and the RDP session-arbitration and Entra token-failure events in
                # local_auth. Ten mappings, all silently going to the reject table
                # while the collector's own counters reported them as produced.
                #
                # `label` is precisely what the field wants: a source-specific name for
                # an activity the enum cannot express. It is non-empty for every entry
                # in both tables by construction.
                payload["activity_name"] = mapped.label
            if mapped.status_id is not None:
                payload["status_id"] = mapped.status_id
        if rec.get("activity_id"):
            payload["metadata_correlation_uid"] = rec["activity_id"]

        overrides = self.data_map_by_class.get(payload["class_uid"]) or {}
        for key, value in data.items():
            field = overrides.get(key, self.data_map.get(key))
            if not field or value in ("", "-"):
                continue
            payload[field] = value

        # Windows writes "::1"/"-"/"127.0.0.1" for local logons and a literal "-"
        # for absent values. A "-" reaching an IP field fails validation and
        # quarantines an otherwise perfectly good logon record.
        for f in ("src_endpoint_ip", "dst_endpoint_ip"):
            if payload.get(f) in ("-", "", None):
                payload.pop(f, None)
        # Numeric only where the field is numeric. Logon ids are deliberately *not*
        # in this list: Windows writes them as "0x3e7" and every subsequent event in
        # the same session repeats that exact string, so keeping the hex text is
        # what makes the session join work. Converting to 999 would still join, but
        # only if every producer converted identically — and the raw XML, the
        # Sysmon collector and any Sigma rule written against the log would not.
        for f in ("src_endpoint_port", "process_pid", "logon_type_id"):
            if f in payload:
                coerced = _int_or_none(payload[f])
                if coerced is None:
                    payload.pop(f)
                else:
                    payload[f] = coerced
        for f in ("session_uid", "actor_session_uid", "status_code", "user_uid",
                  "actor_user_uid", "group_uid"):
            if payload.get(f) in ("-", "", None):
                payload.pop(f, None)
            elif f in payload:
                payload[f] = str(payload[f])

        if "logon_type_id" in payload:
            payload["logon_type"] = LOGON_TYPES.get(
                int(payload["logon_type_id"]), str(payload["logon_type_id"])
            )

        # Everything from EventData, always — including the fields DATA_MAP does
        # promote. A rule author reading `unmapped` should see the record as
        # Windows wrote it, not a version with holes where the mapping succeeded.
        payload["unmapped"] = {
            "channel": ch.path,
            "event_id": eid,
            "level": level,
            "task": rec.get("task"),
            "opcode": rec.get("opcode"),
            "keywords": rec.get("keywords"),
            "process_id": rec.get("process_id"),
            "thread_id": rec.get("thread_id"),
            "user_sid": rec.get("user_sid"),
            "event_data": data,
            "mapped": mapped is not None,
        }
        return payload

    # ── reporting ──────────────────────────────────────────────────────────

    def channel_report(self) -> str:
        lines = [f"{self.name}: {len(self.channels)} channels"]
        for ch in self.channels:
            if ch.why_unavailable:
                lines.append(f"  [gap ] {ch.path}: {ch.why_unavailable}")
            else:
                tag = "crit" if ch.critical else "ok  "
                extra = ""
                if ch.skipped:
                    extra += f", {ch.skipped} skipped"
                if ch.filtered:
                    extra += f", {ch.filtered} filtered as known noise"
                if ch.errors:
                    extra += f", {ch.errors} errors ({ch.last_error[:60]})"
                lines.append(f"  [{tag}] {ch.path}: {ch.read} records{extra}")
        if self.unmapped_ids:
            top = sorted(self.unmapped_ids.items(), key=lambda t: -t[1])[:10]
            lines.append(
                "  stored but unmapped event ids (queryable via unmapped.event_id): "
                + ", ".join(f"{prov.rsplit('-', 1)[-1] or prov}/{i}x{n}"
                            for (prov, i), n in top)
            )
        return "\n".join(lines)

    def gaps(self) -> list[tuple[str, str]]:
        return [(c.path, c.why_unavailable) for c in self.channels if c.why_unavailable]


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


__all__ = [
    "Channel",
    "DATA_MAP",
    "EVENT_MAP",
    "LOGON_TYPES",
    "WindowsEventLogCollector",
    "default_channels",
    "parse_event_xml",
]

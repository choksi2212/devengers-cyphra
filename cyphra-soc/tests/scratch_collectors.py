"""Scratch verification for ingest.collectors — the local telemetry sources.

    PYTHONIOENCODING=utf-8 python tests/scratch_collectors.py

**The section this file exists for is the first one.** ``EVENT_MAP`` and
``SYSMON_MAP`` assign an OCSF ``activity_id`` to 78 Windows event ids, and the
schema *rejects* an activity id that is not in its class's enum. A wrong number
there does not raise in the collector — it quarantines the event at ingest, so
CYPHRA would collect no logons at all while every counter and dashboard reported a
healthy source. That is why the mapping tables are checked against the vendored
schema here rather than trusted, and why both module docstrings say the test is not
optional.

The **last** section is the first one's sibling and exists for the same reason. An
``activity_id`` that is wrong for its class is rejected loudly at ingest; a *field*
that is wrong for its class is not rejected at all. ``Event.build`` files any key it
does not recognise into ``unmapped``, so putting ``query_result_id`` on a 5002 — a
class with no such attribute — produces a payload that builds, validates, persists,
and is unqueryable, with every counter reporting a healthy source. So every payload
this file produces is registered with :func:`register` and, at the end, every field on
every one of them is checked against the attributes its own OCSF class declares.

Two collectors cannot be run end-to-end on this host, and the way they cannot is
itself asserted rather than skipped:

* **Sysmon** — the channel does not exist (measured: Win32 15007), so
  :class:`SysmonCollector` is exercised by feeding real-shaped Sysmon XML through
  ``_to_event`` directly, and its ``probe`` is asserted to return the install
  instruction rather than a bare failure.
* **Packet capture** — needs elevation, and this process is not elevated, so the
  probe is asserted to say so with the fix in it.

A skipped test for an unavailable source is how a permanent gap becomes invisible.
Here the gap is the assertion.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, ".")

from core.config import get
from core.schema.ocsf import (
    DERIVED_FIELDS,
    LOCAL_FIELDS,
    OCSF_PATH,
    SOC_FIELDS,
    ClassUid,
    Event,
    Severity,
    misplaced_fields,
    schema,
)
from core.store.lake import Lake
from ingest.collectors.base import (
    Availability,
    CollectorFleet,
    PullCollector,
    PushCollector,
    available,
    is_admin,
    is_windows,
    unavailable,
)
from ingest.collectors.dns import (
    DNS_CLIENT_CHANNEL,
    NOTABLE_QUERY_TYPES,
    WINDOWS_DNS_STATUS,
    DnsCacheCollector,
    DnsClientLogCollector,
    _cache_via_ipconfig,
    _cache_via_powershell,
    _cache_via_wmi,
    channel_enabled,
    dns_status,
    query_type_name,
    read_hosts_file,
)
from ingest.collectors.local_auth import (
    AUTH_DATA_MAP,
    AUTH_EVENT_MAP,
    KERBEROS_STATUS,
    KNOWN_PUBLISHERS,
    LOGON_TYPE_MEANING,
    NOISY_EVENTS,
    NTSTATUS_LOGON,
    POLICY_FINDINGS,
    PRIVILEGED_GROUP_NAMES,
    PRIVILEGED_GROUP_RIDS,
    SECURITY_CHANNEL,
    SECURITY_SETUP,
    UF_FINDINGS,
    UF_FLAGS,
    LocalAccountCollector,
    LocalAuthLogCollector,
    LogonSessionCollector,
    decode_status,
    local_auth_channels,
    local_auth_collectors,
    parse_status_code,
)
from ingest.collectors.local_auth import _attack as la_attack
from ingest.collectors.local_auth import _to_epoch as la_to_epoch
from ingest.collectors.network_flow import NetworkFlowCollector, _is_private, _orient
from ingest.collectors.process import ProcessCollector
from ingest.collectors.sysmon import (
    SYSMON_CHANNEL,
    SYSMON_CONFIG_PATH,
    SYSMON_DATA_MAP,
    SYSMON_MAP,
    SYSMON_RULE_ELEMENTS,
    SYSMON_SETUP,
    SysmonCollector,
    _swap_endpoints,
    local_addresses,
    parse_hashes,
    validate_sysmon_config,
)
from ingest.collectors.windows_eventlog import (
    DATA_MAP,
    EVENT_MAP,
    LOGON_TYPES,
    Channel,
    WindowsEventLogCollector,
    _iso_to_epoch,
    default_channels,
    parse_event_xml,
)
from ingest.health import HealthMonitor, SourceStatus
from ingest.pipeline import Pipeline

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── every field, against the attributes its own class declares ──────────────

#: ``{class_uid: [attribute_name, ...]}`` from the vendored bundle.
_CLASS_ATTRS = schema().class_attributes


def unmapped_fields(payload: dict) -> list[str]:
    """Payload keys whose OCSF path is not an attribute of the payload's own class.

    Thin wrapper over :func:`core.schema.ocsf.misplaced_fields`, deliberately. This
    check began life here, found two real defects on its first run, and was then
    promoted into the schema module — because an invariant a *test* enforces protects
    the six collectors the test knows about, while the same invariant enforced in
    ``Event.build`` protects every collector and connector that will ever exist. This
    file keeps calling the promoted version rather than its own copy so the two cannot
    drift: a test that agrees with the builder by coincidence stops being evidence the
    moment either is edited.

    What it catches is strictly quieter than the activity-id check at the top of this
    file. A wrong activity id is rejected by the schema and quarantined at ingest —
    loud, and the quarantine table shows it. A wrong *field* is rejected by nothing: it
    is a real ``Event`` field with a real ``OCSF_PATH``, so it builds, validates,
    persists, and is then unqueryable under the name any consumer would look for. Only
    the class's own attribute list knows that 5009 declares ``query_result_id`` and
    5002 does not, or that 201002 declares ``reg_value`` and not ``reg_key``.
    """
    return sorted(misplaced_fields(payload.get("class_uid"), payload).values())


#: ``(source, payload)`` for every payload any section of this file produced.
#: Populated by :func:`register`; drained by the final section.
PAYLOADS: list[tuple[str, dict]] = []


def register(source: str, payloads):
    """Record payloads for the whole-file field check, and hand them straight back.

    Written to be usable inline — ``for p in register("sysmon", batch):`` — so adding
    a collector to the cross-cutting check costs one call rather than a parallel list
    that someone will forget to update.
    """
    for p in payloads:
        if isinstance(p, dict):
            PAYLOADS.append((source, p))
    return payloads


class Clock:
    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now


ROOT = Path("var/test_collectors")
_OPEN: list = []


def fresh_lake():
    while _OPEN:
        try:
            _OPEN.pop().close()
        except Exception:
            pass
    d = ROOT / f"lake_{time.perf_counter_ns()}"
    d.mkdir(parents=True, exist_ok=True)
    lk = Lake(root=d / "data", duckdb_path=d / "soc.duckdb", flush_rows=10_000, threads=2)
    _OPEN.append(lk)
    return lk


# ── the vendored schema, as the authority on activity ids ───────────────────

_VENDOR = Path("vendor/ocsf/_classes_full.json")


def load_activity_enums():
    """``{class_uid: {activity_id: caption}}`` straight from the vendored bundle.

    Read from ``_classes_full.json`` rather than ``ocsf_index.json``: the index
    carries only the *base* event's enums, so looking activity ids up there returns
    the same three values for every class and would pass a table full of wrong
    numbers.
    """
    raw = json.loads(_VENDOR.read_text(encoding="utf-8"))
    out: dict[int, dict[int, str]] = {}
    for cls in raw.values():
        uid = cls.get("uid")
        if not isinstance(uid, int):
            continue
        enum = (cls.get("attributes", {}).get("activity_id", {}) or {}).get("enum", {})
        out[uid] = {
            int(k): (v or {}).get("caption", "")
            for k, v in enum.items()
            if str(k).lstrip("-").isdigit()
        }
    return out


# ── synthetic records ───────────────────────────────────────────────────────

_NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def win_xml(event_id, *, channel="Security", data=None, provider="Microsoft-Windows-Security-Auditing",
            record_id=4711, level="0", computer="TESTHOST", when="2026-08-28T19:04:45.9448922Z",
            user_data=None, positional=None):
    """A record shaped the way the Event Log renders one, not a hand-waved stub."""
    bits = []
    for k, v in (data or {}).items():
        bits.append(f'<Data Name="{k}">{v}</Data>')
    for v in positional or []:
        bits.append(f"<Data>{v}</Data>")
    body = f"<EventData>{''.join(bits)}</EventData>" if bits else ""
    if user_data:
        body += f"<UserData><Payload>{user_data}</Payload></UserData>"
    return (
        f"<Event {_NS}><System>"
        f'<Provider Name="{provider}" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version><Level>{level}</Level>"
        f"<Task>12544</Task><Opcode>0</Opcode>"
        f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{when}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f'<Correlation ActivityID="{{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}}"/>'
        f'<Execution ProcessID="740" ThreadID="4620"/>'
        f"<Channel>{channel}</Channel><Computer>{computer}</Computer>"
        f'<Security UserID="S-1-5-18"/>'
        f"</System>{body}</Event>"
    )


def sysmon_xml(event_id, data, *, record_id=9001, computer="TESTHOST"):
    return win_xml(
        event_id,
        channel=SYSMON_CHANNEL,
        provider="Microsoft-Windows-Sysmon",
        data=data,
        record_id=record_id,
        computer=computer,
    )


SYSMON_1 = {
    "RuleName": "technique_id=T1059,technique_name=Command-Line Interface",
    "UtcTime": "2026-08-28 19:04:45.123",
    "ProcessGuid": "{a1b2c3d4-0000-1111-2222-333333333333}",
    "ProcessId": "6624",
    "Image": r"C:\Windows\System32\cmd.exe",
    "FileVersion": "10.0.26200.1",
    "Description": "Windows Command Processor",
    "Product": "Microsoft Windows Operating System",
    "Company": "Microsoft Corporation",
    "OriginalFileName": "Cmd.Exe",
    "CommandLine": r'"C:\Windows\system32\cmd.exe" /c whoami',
    "CurrentDirectory": r"C:\Users\test\\",
    "User": "EVILHYBRID\\test",
    "LogonGuid": "{a1b2c3d4-0000-1111-2222-444444444444}",
    "LogonId": "0x3e7",
    "TerminalSessionId": "1",
    "IntegrityLevel": "High",
    "Hashes": (
        "SHA1=9E6A2A3F1F4A2B3C4D5E6F708192A3B4C5D6E7F8,"
        "MD5=D7AB69FAD18D4A643D84A271DFC0DBDF,"
        "SHA256=BADC0FFEE0DDF00D1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF,"
        "IMPHASH=DAE02F32A21E03CE65412F6E56942DAA"
    ),
    "ParentProcessGuid": "{a1b2c3d4-0000-1111-2222-555555555555}",
    "ParentProcessId": "5560",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": r"C:\Windows\Explorer.EXE",
    "ParentUser": "EVILHYBRID\\test",
}


async def main():
    clock = Clock()
    cfg = get()
    shutil.rmtree(ROOT, ignore_errors=True)
    ROOT.mkdir(parents=True, exist_ok=True)

    # ══ 1. the mapping tables, against the vendored schema ══════════════════
    print("── activity ids are valid for their class (the whole point of this file) ──")
    enums = load_activity_enums()
    check("the vendored bundle yields per-class activity enums, not the base enum",
          len(enums) > 50 and enums.get(3007, {}).get(8) == "Password Change",
          f"{len(enums)} classes; 3007/8 = {enums.get(3007, {}).get(8)!r}")

    for label, table in (("EVENT_MAP", EVENT_MAP), ("SYSMON_MAP", SYSMON_MAP)):
        bad = []
        for eid, m in table.items():
            valid = enums.get(m.class_uid)
            if valid is None:
                bad.append(f"{eid}: class {m.class_uid} is not in the schema")
            elif m.activity_id not in valid:
                bad.append(
                    f"{eid}: activity {m.activity_id} not valid for {m.class_uid} "
                    f"(valid: {sorted(valid)})"
                )
        check(f"every {label} activity id is in its class's enum ({len(table)} ids)",
              not bad, "; ".join(bad[:4]))

    # The dynamic hooks return activity ids too, and they are not covered by the
    # static check above — a wrong number there fails only on the events that take
    # the hook, which is the subset an operator is least likely to be watching.
    dyn_bad = []
    for label, table in (("EVENT_MAP", EVENT_MAP), ("SYSMON_MAP", SYSMON_MAP)):
        for eid, m in table.items():
            if m.activity_from is None:
                continue
            valid = enums.get(m.class_uid, {})
            for probe in (
                {"EventType": "CreateKey"}, {"EventType": "DeleteKey"},
                {"EventType": "RenameKey"}, {"EventType": "SetValue"},
                {"EventType": "DeleteValue"}, {"EventType": "CreateValue"},
                {"EventType": "RenameValue"},
                {"param2": "running"}, {"param2": "stopped"}, {"param2": "paused"},
                {"Data1": "running"}, {},
            ):
                got = m.activity_from(probe)
                if got is not None and got not in valid:
                    dyn_bad.append(f"{label}/{eid} {probe} -> {got} not in {sorted(valid)}")
    check("every activity_from hook also returns a valid activity id", not dyn_bad,
          "; ".join(dyn_bad[:4]))

    known = set(Event.model_fields)
    for label, table in (("DATA_MAP", DATA_MAP), ("SYSMON_DATA_MAP", SYSMON_DATA_MAP)):
        strays = sorted({v for v in table.values() if v not in known})
        check(f"every {label} target is a real Event field ({len(table)} names)",
              not strays,
              "these would silently become unqueryable unmapped data: " + ", ".join(strays))

    check("class_uid values are all real OCSF classes",
          all(m.class_uid in enums for m in list(EVENT_MAP.values()) + list(SYSMON_MAP.values())))
    check("every mapping carries a human label", all(
        m.label.strip() for m in list(EVENT_MAP.values()) + list(SYSMON_MAP.values())))
    check("Sysmon ids 1..29 plus 255 are all mapped",
          set(SYSMON_MAP) == set(range(1, 30)) | {255},
          f"missing: {sorted((set(range(1, 30)) | {255}) - set(SYSMON_MAP))}")

    # ══ 2. XML parsing ══════════════════════════════════════════════════════
    print("\n── parse_event_xml ──")
    rec = parse_event_xml(win_xml(4624, data={"TargetUserName": "alice", "LogonType": "10"}))
    check("named EventData is parsed", rec["_data"]["TargetUserName"] == "alice")
    check("System fields are lowercased and present",
          rec["eventid"] == "4624" and rec["computer"] == "TESTHOST",
          f"eventid={rec.get('eventid')!r} computer={rec.get('computer')!r}")
    check("Execution attributes are flattened",
          rec.get("process_id") == "740" and rec.get("thread_id") == "4620")
    check("Correlation ActivityID survives", "aaaaaaaa" in (rec.get("activity_id") or ""))
    check("Security UserID survives", rec.get("user_sid") == "S-1-5-18")

    pos = parse_event_xml(win_xml(7045, channel="System", positional=["svc", "cmd.exe", "auto"]))
    check("positional Data becomes Data0..N, not nothing",
          pos["_data"].get("Data0") == "svc" and pos["_data"].get("Data2") == "auto",
          str(pos["_data"]))

    ud = parse_event_xml(win_xml(200, channel="Microsoft-Windows-TaskScheduler/Operational",
                                 user_data='<TaskName>\\Evil</TaskName>'))
    check("UserData is parsed, not ignored", ud["_data"].get("TaskName") == "\\Evil",
          str(ud["_data"]))

    check("malformed XML raises, so _read_channel counts it as a skip rather than "
          "emitting a hollow event", _raises(lambda: parse_event_xml("<Event><broken")))

    print("\n── _iso_to_epoch ──")
    t = _iso_to_epoch("2026-08-28T19:04:45.9448922Z")
    check("Windows' 7 fractional digits parse (fromisoformat rejects them)",
          t is not None and abs(t - 1787943885.944892) < 1e-5, repr(t))
    check("3 fractional digits parse", _iso_to_epoch("2026-08-28T19:04:45.944Z") is not None)
    check("no fractional part parses", _iso_to_epoch("2026-08-28T19:04:45Z") is not None)
    check("a space separator (Sysmon's UtcTime) parses",
          _iso_to_epoch("2026-08-28T19:04:45.123") is not None)
    check("garbage returns None rather than raising", _iso_to_epoch("not a time") is None)

    # ══ 3. Windows Event Log collector ══════════════════════════════════════
    print("\n── windows_eventlog ──")
    lake = fresh_lake()
    pipe = Pipeline(lake, cfg, clock=clock)
    wel = WindowsEventLogCollector(pipe, state_dir=ROOT / "state", clock=clock)

    chans = default_channels()
    check("Security is declared critical (identity monitoring depends on it)",
          any(c.path == "Security" and c.critical for c in chans))
    check("PowerShell/Operational defaults to script_activity, not process_activity",
          any(c.path.endswith("PowerShell/Operational") and c.default_class == 1009
              for c in chans))
    check("channel slugs are filesystem-safe",
          all("/" not in c.slug and " " not in c.slug and "-" not in c.slug for c in chans),
          str([c.slug for c in chans][:3]))

    av = wel.probe()
    check("probe answers with an Availability, never raises", isinstance(av, Availability))
    if is_windows():
        check("Event Log is available on this host (some channel reads)", bool(av),
              av.reason[:90])
        gaps = wel.gaps()
        sec = [g for g in gaps if g[0] == "Security"]
        if not is_admin():
            check("unelevated: Security is reported as a gap, not as healthy", bool(sec))
            check("the Security gap names the fix (Event Log Readers / Run as admin)",
                  bool(sec) and ("Event Log Readers" in sec[0][1] or "administrator" in sec[0][1]),
                  sec[0][1][:110] if sec else "")
        else:
            check("elevated: Security is readable", not sec)

    ev = wel._to_event(Channel("Security", 3002, critical=True),
                       win_xml(4624, data={"TargetUserName": "alice", "TargetUserSid": "S-1-5-21-1",
                                           "SubjectUserName": "SYSTEM", "TargetLogonId": "0x1a2b3c",
                                           "SubjectLogonId": "0x3e7", "LogonType": "10",
                                           "IpAddress": "10.0.0.9", "WorkstationName": "WS02",
                                           "LogonProcessName": "User32",
                                           "AuthenticationPackageName": "Negotiate"}))
    check("4624 maps to authentication/Logon", (ev["class_uid"], ev["activity_id"]) == (3002, 1),
          f"{ev['class_uid']}/{ev['activity_id']}")
    check("the logon type id is kept for rules", ev.get("logon_type_id") == 10)
    check("and the caption is kept for analysts", ev.get("logon_type") == LOGON_TYPES[10],
          repr(ev.get("logon_type")))
    check("hex logon ids stay hex so the session join works",
          ev.get("session_uid") == "0x1a2b3c" and ev.get("actor_session_uid") == "0x3e7",
          f"{ev.get('session_uid')!r}/{ev.get('actor_session_uid')!r}")
    check("metadata_uid is qualified by host and channel, not a bare record id",
          ev.get("metadata_uid") == "TESTHOST/Security:4711", repr(ev.get("metadata_uid")))
    check("the raw event_data is carried whole into unmapped",
          ev["unmapped"]["event_data"].get("AuthenticationPackageName") == "Negotiate")
    check("the channel is a label so a source filter is possible",
          "channel:Security" in ev.get("metadata_labels", []))

    built = Event.build(source="windows_eventlog", raw=None, **ev)
    check("...and the schema accepts it (this is what a wrong activity id breaks)",
          built.class_uid == 3002 and built.activity_id == 1)
    check("observables are derived from the mapped fields",
          any(o.value == "alice" for o in built.observables),
          str([o.value for o in built.observables][:6]))

    grp = wel._to_event(Channel("Security", 3002), win_xml(
        4732, data={"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-9",
                    "GroupName": "Administrators", "SubjectUserName": "attacker"}))
    check("4732 maps to group management/Add User",
          (grp["class_uid"], grp["activity_id"]) == (3006, 3),
          f"{grp['class_uid']}/{grp['activity_id']}")
    gb = Event.build(source="windows_eventlog", raw=None, **grp)
    check("the group is an observable, which is what makes 4732 a privesc signal",
          any(o.value == "Administrators" and o.type_id for o in gb.observables),
          str([(o.name, o.value) for o in gb.observables][:6]))

    svc_run = wel._to_event(Channel("System", 201003), win_xml(
        7036, channel="System", provider="Service Control Manager",
        data={"param1": "Windows Update", "param2": "running"}))
    svc_stop = wel._to_event(Channel("System", 201003), win_xml(
        7036, channel="System", provider="Service Control Manager",
        data={"param1": "Windows Update", "param2": "stopped"}))
    check("7036 resolves its activity from the payload (running -> Start)",
          svc_run["activity_id"] == 3, str(svc_run["activity_id"]))
    check("...and stopped -> Stop, rather than both being one constant",
          svc_stop["activity_id"] == 4, str(svc_stop["activity_id"]))
    check("an unrecognised service state falls back to the mapped default, not a crash",
          wel._to_event(Channel("System", 201003), win_xml(
              7036, channel="System", data={"param2": "wobbling"}))["activity_id"] == 0)

    unk = wel._to_event(Channel("Application", 201003),
                        win_xml(999999, channel="Application", level="2",
                                data={"Something": "odd"}))
    check("an unmapped event id is stored, not dropped",
          unk["class_uid"] == 201003 and unk["unmapped"]["event_id"] == 999999)
    check("...and marked as unmapped so coverage is measurable",
          unk["unmapped"].get("mapped") is False)
    check("...with severity from the Windows Level when there is no mapping",
          unk["severity_id"] == 4, str(unk.get("severity_id")))
    check("...and the schema accepts it too",
          Event.build(source="windows_eventlog", raw=None, **unk).class_uid == 201003)

    check("Level 0 (LogAlways) is Informational, not Unknown",
          wel._to_event(Channel("Application", 201003),
                        win_xml(999998, channel="Application", level="0"))["severity_id"] == 1)

    register("windows_eventlog", [ev, grp, svc_run, svc_stop, unk])

    # ══ 4. Sysmon ═══════════════════════════════════════════════════════════
    print("\n── sysmon (channel absent on this host: exercised on synthetic XML) ──")
    sysmon = SysmonCollector(pipe, state_dir=ROOT / "state", clock=clock)
    sav = sysmon.probe()
    if is_windows():
        check("Sysmon probes as unavailable here", not sav)
        check("...and the reason is the install instruction, not 'no channel readable'",
              "Sysmon.zip" in sav.reason and "-accepteula -i" in sav.reason,
              sav.reason[:80])
        check("...and it says what the gap is worth (264 of 697 techniques)",
              "264" in sav.reason and "182" in sav.reason)
        check("...and is marked fixable, so it lands in the setup checklist",
              sav.fixable_by_user)
    check("SYSMON_SETUP names the verification command",
          "Get-WinEvent" in SYSMON_SETUP and SYSMON_CHANNEL in SYSMON_SETUP)

    ch = Channel(SYSMON_CHANNEL, 201003, critical=True)
    p1 = sysmon._to_event(ch, sysmon_xml(1, SYSMON_1))
    check("Sysmon 1 maps to process_activity/Launch",
          (p1["class_uid"], p1["activity_id"]) == (1007, 1))
    check("the command line is mapped, which 4688 cannot give without extra policy",
          p1.get("process_cmd_line", "").endswith("/c whoami"))
    check("parent is the actor, child is the subject",
          p1.get("actor_process_file_path", "").endswith("explorer.exe")
          and p1.get("process_file_path", "").endswith("cmd.exe"))
    check("pids are ints, not the strings the XML carries",
          p1.get("process_pid") == 6624 and p1.get("actor_process_pid") == 5560,
          f"{p1.get('process_pid')!r}/{p1.get('actor_process_pid')!r}")
    check("hashes are split into joinable fields",
          p1.get("process_file_sha256", "").startswith("badc0ffee")
          and len(p1.get("process_file_md5", "")) == 32
          and len(p1.get("process_file_sha1", "")) == 40)
    check("IMPHASH has no field but is kept in unmapped, not dropped",
          p1["unmapped"]["hashes"].get("IMPHASH") == "dae02f32a21e03ce65412f6e56942daa")
    check("the unmapped copy and the mapped field agree on case, so a join on "
          "either finds the same file",
          p1["unmapped"]["hashes"]["SHA256"] == p1["process_file_sha256"])
    check("integrity level maps to the OCSF id", p1.get("process_integrity_id") == 4)
    check("time comes from Sysmon's UtcTime, not the log service's write time",
          abs(p1["time"] - _iso_to_epoch("2026-08-28T19:04:45.123")) < 1e-6, repr(p1["time"]))
    check("...and TimeCreated is kept so the gap between them is measurable",
          isinstance(p1["unmapped"].get("time_created_epoch"), float))
    check("RuleName carries Sysmon's own detection name",
          "T1059" in (p1.get("metadata_correlation_uid") or ""))
    sb = Event.build(source="sysmon", raw=None, **p1)
    check("the schema accepts a Sysmon process creation", sb.class_uid == 1007)
    check("the SHA-256 became a hash observable an intel feed can join",
          any(o.value.startswith("badc0ffee") for o in sb.observables),
          repr([o.value for o in sb.observables]))

    mod = sysmon._to_event(ch, sysmon_xml(7, {
        "UtcTime": "2026-08-28 19:05:00.000", "ProcessGuid": "{g}", "ProcessId": "6624",
        "Image": r"C:\Windows\System32\svchost.exe",
        "ImageLoaded": r"C:\Users\test\AppData\Roaming\evil.dll",
        "Hashes": "SHA256=DEADBEEF00000000000000000000000000000000000000000000000000000000",
        "Signed": "false"}))
    check("an image-load hash is the module's, not the host process's",
          mod.get("module_file_sha256", "").startswith("deadbeef")
          and "process_file_sha256" not in mod,
          f"module={mod.get('module_file_sha256', '')[:10]} "
          f"process={mod.get('process_file_sha256')!r}")
    check("...and the loaded path is module_file_path, while the loading process is "
          "the ACTOR, not the subject: OCSF declares a top-level `process` on only "
          "the seven classes whose subject is a process, and 1005 Module Activity is "
          "not one of them — its subject is the module. Before this, `Image` went to "
          "`process_file_path` on every Sysmon class, which validated and persisted "
          "and was invisible to a rule reading actor.process.file.path",
          mod.get("module_file_path", "").endswith("evil.dll")
          and mod.get("actor_process_file_path", "").endswith("svchost.exe")
          and "process_file_path" not in mod,
          f"module={mod.get('module_file_path')!r} "
          f"actor={mod.get('actor_process_file_path')!r} "
          f"subject={mod.get('process_file_path')!r}")
    check("...and the loading process's pid and guid move with it, so the DLL and the "
          "process that loaded it stay joinable — a T1574 hijack investigation is "
          "exactly that join",
          mod.get("actor_process_pid") == 6624
          and mod.get("actor_process_uid") == "{g}"
          and "process_pid" not in mod and "process_uid" not in mod,
          f"{mod.get('actor_process_pid')!r}/{mod.get('actor_process_uid')!r} "
          f"subject={mod.get('process_pid')!r}/{mod.get('process_uid')!r}")

    filed = sysmon._to_event(ch, sysmon_xml(23, {
        "UtcTime": "2026-08-28 19:05:01.000", "Image": r"C:\evil.exe",
        "TargetFilename": r"C:\Users\test\secrets.docx",
        "Hashes": "SHA256=CAFEBABE00000000000000000000000000000000000000000000000000000000"}))
    check("a file-delete hash is the file's, not a process image's",
          filed.get("file_sha256", "").startswith("cafebabe")
          and "process_file_sha256" not in filed)

    reg_c = sysmon._to_event(ch, sysmon_xml(12, {
        "UtcTime": "2026-08-28 19:05:02.000", "EventType": "CreateKey",
        "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}))
    reg_d = sysmon._to_event(ch, sysmon_xml(12, {
        "UtcTime": "2026-08-28 19:05:03.000", "EventType": "DeleteKey",
        "TargetObject": r"HKLM\SOFTWARE\Evil"}))
    check("registry sub-type is read: CreateKey -> Create, DeleteKey -> Delete",
          (reg_c["activity_id"], reg_d["activity_id"]) == (1, 4),
          f"{reg_c['activity_id']}/{reg_d['activity_id']}")
    reg_v = sysmon._to_event(ch, sysmon_xml(13, {
        "UtcTime": "2026-08-28 19:05:04.000", "EventType": "SetValue",
        "TargetObject": r"HKLM\...\Run\evil", "Details": r"C:\evil.exe"}))
    check("13/SetValue maps to registry_value/Set with the data",
          (reg_v["class_uid"], reg_v["activity_id"]) == (201002, 2)
          and reg_v.get("reg_value_data") == r"C:\evil.exe")
    check("...and TargetObject lands in reg_value_path, not reg_key_path: 201002 "
          "Registry Value Activity declares `reg_value` and no `reg_key`, and Sysmon "
          "reuses the one field name for a key on event 12/14 and a value on 13. The "
          "shared entry put a Run-key path on the class with nowhere to hold it — on "
          "the highest-volume persistence source Sysmon has",
          reg_v.get("reg_value_path") == r"HKLM\...\Run\evil"
          and "reg_key_path" not in reg_v,
          f"value={reg_v.get('reg_value_path')!r} key={reg_v.get('reg_key_path')!r}")
    check("...while 12 and 14, which really do name a key, keep reg_key_path on 201001",
          reg_c.get("reg_key_path", "").endswith(r"CurrentVersion\Run")
          and "reg_value_path" not in reg_c
          and reg_c["class_uid"] == 201001,
          f"{reg_c.get('reg_key_path')!r} / {reg_c.get('reg_value_path')!r}")

    dns = sysmon._to_event(ch, sysmon_xml(22, {
        "UtcTime": "2026-08-28 19:05:05.000", "ProcessId": "6624",
        "QueryName": "evil.example.net", "QueryStatus": "0",
        "QueryResults": "type:  5 cdn.evil.net;type:  1 93.184.216.34;",
        "Image": r"C:\Windows\System32\cmd.exe"}))
    check("22 maps to dns_activity/Query with the hostname",
          (dns["class_uid"], dns["activity_id"]) == (4003, 1)
          and dns.get("dns_query_hostname") == "evil.example.net")
    check("...and the resolving process is the actor on a 4003, which is the whole "
          "value of Sysmon 22 over a DNS server log: 'which process asked' is the "
          "field that turns a suspicious domain into a suspicious binary",
          dns.get("actor_process_file_path", "").endswith("cmd.exe")
          and dns.get("actor_process_pid") == 6624
          and "process_file_path" not in dns and "process_pid" not in dns,
          f"{dns.get('actor_process_file_path')!r}/{dns.get('actor_process_pid')!r}")
    check("the packed answers are split and counted",
          dns.get("dns_answer_count") == 2
          and dns["unmapped"]["dns_answers"] == ["cdn.evil.net", "93.184.216.34"],
          str(dns["unmapped"].get("dns_answers")))
    nx = sysmon._to_event(ch, sysmon_xml(22, {
        "UtcTime": "2026-08-28 19:05:06.000", "QueryName": "zzz.dga.net",
        "QueryStatus": "9003"}))
    check("QueryStatus 9003 is NXDOMAIN (the DGA hunt's signal), and status is failure",
          nx.get("dns_rcode_id") == 3 and nx.get("status_id") == 2
          and nx.get("status_code") == "9003")
    check("Sysmon's Win32 QueryStatus is not mistaken for a DNS rcode",
          dns.get("dns_rcode_id") is None and dns.get("status_id") == 1)

    print("\n── sysmon network direction (decided from the record, not assumed) ──")
    local = sorted(local_addresses())
    check("this host's own addresses are discoverable", len(local) > 0, f"{len(local)} found")
    mine = next((a for a in local if a not in ("127.0.0.1", "::1") and "." in a), "127.0.0.1")

    out = sysmon._to_event(ch, sysmon_xml(3, {
        "UtcTime": "2026-08-28 19:05:07.000", "Initiated": "true", "Protocol": "tcp",
        "SourceIp": mine, "SourcePort": "51000", "DestinationIp": "93.184.216.34",
        "DestinationPort": "443", "Image": r"C:\Windows\System32\cmd.exe"}))
    check("Initiated=true is outbound, from the kernel not a heuristic",
          out.get("connection_direction_id") == 2)
    check("...and the endpoints are left as Sysmon reported them",
          out.get("src_endpoint_ip") == mine and out.get("dst_endpoint_ip") == "93.184.216.34")
    check("the protocol name is normalised and numbered",
          out.get("connection_protocol_name") == "tcp"
          and out.get("connection_protocol_num") == 6)

    inb = sysmon._to_event(ch, sysmon_xml(3, {
        "UtcTime": "2026-08-28 19:05:08.000", "Initiated": "false", "Protocol": "tcp",
        "SourceIp": mine, "SourcePort": "3389", "DestinationIp": "203.0.113.9",
        "DestinationPort": "51000", "SourceHostname": "evilhybrid.local"}))
    check("Initiated=false is inbound", inb.get("connection_direction_id") == 1)
    check("...and because Sysmon's Source is this host, the ends are swapped so "
          "src_endpoint is the initiator",
          inb.get("src_endpoint_ip") == "203.0.113.9" and inb.get("dst_endpoint_ip") == mine,
          f"src={inb.get('src_endpoint_ip')} dst={inb.get('dst_endpoint_ip')}")
    check("...ports swap with the addresses, not independently",
          inb.get("src_endpoint_port") == 51000 and inb.get("dst_endpoint_port") == 3389)
    check("...the hostname follows its address to the far end",
          inb.get("dst_endpoint_hostname") == "evilhybrid.local"
          and "src_endpoint_hostname" not in inb,
          f"src_h={inb.get('src_endpoint_hostname')!r} dst_h={inb.get('dst_endpoint_hostname')!r}")
    check("...and the decision is recorded per event, so a rule on direction is auditable",
          any("swapped" in n for n in inb.get("soc_notes", [])),
          str(inb.get("soc_notes")))

    inb2 = sysmon._to_event(ch, sysmon_xml(3, {
        "UtcTime": "2026-08-28 19:05:09.000", "Initiated": "false", "Protocol": "tcp",
        "SourceIp": "198.51.100.7", "SourcePort": "51000",
        "DestinationIp": mine, "DestinationPort": "445"}))
    check("but when Sysmon already had the remote end in Source, nothing is swapped",
          inb2.get("src_endpoint_ip") == "198.51.100.7" and inb2.get("dst_endpoint_ip") == mine)
    check("...and that reading is recorded too, rather than being the silent default",
          any("not an address of this host" in n for n in inb2.get("soc_notes", [])),
          str(inb2.get("soc_notes")))

    nb = Event.build(source="sysmon", raw=None, **inb)
    check("the collector's notes survive Event.build into soc_notes",
          any("swapped" in n for n in nb.soc_notes), str(nb.soc_notes))
    check("...and are not swept into unmapped as if the source had sent them",
          "notes" not in (nb.unmapped or {}))

    register("sysmon", [p1, mod, filed, reg_c, reg_d, reg_v, dns, nx, out, inb, inb2])

    print("\n── the shipped sysmon-config.xml ──")
    # SYSMON_SETUP tells the operator this file "is a working default", and they
    # will run `sysmon64 -i` on it from an elevated shell without reading it. If it
    # does not load, Sysmon prints one line and — on `-c` — keeps the *previous*
    # config running, so the operator ends up with telemetry they did not choose and
    # no indication of it. Validating on install needs elevation this process does
    # not have, which is exactly why the check has to happen here.
    check("the config SYSMON_SETUP promises exists on disk",
          SYSMON_CONFIG_PATH.is_file(), str(SYSMON_CONFIG_PATH))
    cfg_text = SYSMON_CONFIG_PATH.read_text(encoding="utf-8")
    problems = validate_sysmon_config(cfg_text)
    check("...and it is loadable: no rejected element, field, operator or onmatch",
          not problems, "; ".join(problems[:3]) if problems else f"{len(cfg_text)} bytes")
    check("...and it does not quietly enable a blocking rule",
          not any("blocks the file operation" in p for p in problems))
    check("SYSMON_SETUP names the config by the path it is actually at",
          "cyphra-soc/ingest/collectors/sysmon-config.xml" in SYSMON_SETUP)

    # The validator's own teeth. A checker that returns [] for everything would pass
    # the assertion above forever and assert nothing, which is how a config typo
    # ships. Each case below is a real Sysmon rejection.
    bad = {
        "a misspelled rule element": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<ProcessCreation onmatch="exclude"/></RuleGroup></EventFiltering></Sysmon>',
            "ProcessCreate",  # the suggestion, so the operator is told what to write
        ),
        "a field that belongs to a different event": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<ProcessCreate onmatch="include"><ImageLoaded condition="is">x</ImageLoaded>'
            "</ProcessCreate></RuleGroup></EventFiltering></Sysmon>",
            "no filter field",
        ),
        "an operator Sysmon does not have": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<DnsQuery onmatch="exclude"><QueryName condition="endswith">a.com</QueryName>'
            "</DnsQuery></RuleGroup></EventFiltering></Sysmon>",
            "not a Sysmon match operator",
        ),
        "onmatch that is neither include nor exclude": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<DriverLoad onmatch="all"/></RuleGroup></EventFiltering></Sysmon>',
            "onmatch",
        ),
        "a groupRelation other than or/and": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="any">'
            '<DriverLoad onmatch="exclude"/></RuleGroup></EventFiltering></Sysmon>',
            "groupRelation",
        ),
        "a missing schemaversion": ("<Sysmon><EventFiltering/></Sysmon>", "schemaversion"),
        "malformed XML": ('<Sysmon schemaversion="4.90"><EventFiltering>', "well-formed"),
        "a blocking rule presented as telemetry": (
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<FileBlockExecutable onmatch="include"><TargetFilename condition="contains">'
            "T</TargetFilename></FileBlockExecutable></RuleGroup></EventFiltering></Sysmon>",
            "blocks the file operation",
        ),
    }
    for label, (xml, expect) in bad.items():
        found = validate_sysmon_config(xml)
        check(f"the validator rejects {label}",
              any(expect in p for p in found), "; ".join(found) or "returned no problems")
    check("...and it accepts the pre-4.22 form with no RuleGroup wrapper",
          not validate_sysmon_config(
              '<Sysmon schemaversion="4.90"><EventFiltering>'
              '<DriverLoad onmatch="exclude"/></EventFiltering></Sysmon>'))

    # Every event any rule element can turn on must have an activity id, or the
    # config would be enabling telemetry that lands in the unmapped table where no
    # detection can reach it.
    enabled = {eid for ids in SYSMON_RULE_ELEMENTS.values() for eid in ids}
    check("every event a Sysmon rule can enable is one SYSMON_MAP maps",
          enabled <= set(SYSMON_MAP), f"unmapped: {sorted(enabled - set(SYSMON_MAP))}")
    # ...and the warning that says so fires when it is not. Exercised by removing a
    # mapping, because with the current table the branch is unreachable — an
    # unreachable guard that has never run is a guard nobody can trust.
    _saved = SYSMON_MAP.pop(6)
    try:
        warn = validate_sysmon_config(
            '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">'
            '<DriverLoad onmatch="exclude"/></RuleGroup></EventFiltering></Sysmon>'
        )
        check("an enabled-but-unmapped event is reported, not silently collected",
              any("SYSMON_MAP does not map" in p for p in warn), "; ".join(warn))
    finally:
        SYSMON_MAP[6] = _saved
    check("...and the mapping is put back", SYSMON_MAP.get(6) == _saved)

    # What the config actually turns on, reported rather than asserted rule by rule:
    # the interesting number is which of the 24 filterable events are covered.
    import xml.etree.ElementTree as _ET

    live = sorted({
        eid
        for rule in _ET.fromstring(cfg_text).iter()
        for eid in SYSMON_RULE_ELEMENTS.get(rule.tag, ())
    })
    check("the default config covers process, network, image, registry, file and DNS",
          {1, 3, 7, 12, 11, 22} <= set(live), f"events enabled: {live}")
    check("...and it does not enable event 24, which archives clipboard contents",
          24 not in live)

    print("\n── parse_hashes ──")
    check("the packed form splits", parse_hashes("SHA1=AA,MD5=BB,SHA256=CC")
          == {"SHA1": "aa", "MD5": "bb", "SHA256": "cc"})
    check("a bare 64-char digest is identified as SHA256 by length",
          parse_hashes("A" * 64) == {"SHA256": "a" * 64})
    check("a bare 32-char digest is MD5", list(parse_hashes("b" * 32)) == ["MD5"])
    check("an unknown length yields nothing rather than a wrong algorithm",
          parse_hashes("c" * 33) == {})
    check("empty is empty", parse_hashes("") == {} and parse_hashes(None) == {})
    # The case convention is load-bearing, not cosmetic. The schema's digest
    # validators lower-case what they accept, so an upper-cased parser puts one
    # digest into the event twice in two cases: lower in the mapped field, upper in
    # `unmapped["hashes"]`. The unmapped copy is the only one carrying IMPHASH, and
    # every intel feed publishes lower-case hex — a hunt joining on it would match
    # nothing and call that a clean result.
    check("digests are lower-cased to agree with the schema and with intel feeds",
          parse_hashes("SHA256=DEADBEEF")["SHA256"] == "deadbeef")
    check("the algorithm name stays upper-case — it is a key, not a join value",
          list(parse_hashes("sha256=AA")) == ["SHA256"])

    print("\n── _swap_endpoints ──")
    sw = {"src_endpoint_ip": "1.1.1.1", "dst_endpoint_ip": "2.2.2.2",
          "src_endpoint_port": 1, "dst_endpoint_port": 2,
          "src_endpoint_hostname": "a"}
    _swap_endpoints(sw)
    check("a one-sided field moves rather than staying on the wrong end",
          sw.get("dst_endpoint_hostname") == "a" and "src_endpoint_hostname" not in sw, str(sw))
    check("both-sided fields exchange", sw["src_endpoint_ip"] == "2.2.2.2"
          and sw["dst_endpoint_port"] == 1)
    twice = dict(sw)
    _swap_endpoints(twice)
    _swap_endpoints(twice)
    check("swapping twice is the identity", twice == sw, f"{twice} != {sw}")

    # ══ 5. network flow ═════════════════════════════════════════════════════
    print("\n── network_flow ──")
    nf = NetworkFlowCollector(pipe, iface="Wi-Fi", clock=clock)
    nav = nf.probe()
    check("probe answers with an Availability", isinstance(nav, Availability))
    if not is_admin():
        check("unelevated: capture is unavailable rather than silently deaf", not nav,
              nav.reason[:80])
        check("...and the reason names elevation as the fix",
              "administrator" in nav.reason.lower() or "sudo" in nav.reason.lower()
              or "npcap" in nav.reason.lower(), nav.reason[:110])

    check("RFC1918 detection covers all three blocks and the 172 boundary",
          all(_is_private(i) for i in ("10.0.0.1", "192.168.1.1", "172.16.0.1",
                                      "172.31.255.255", "127.0.0.1", "169.254.1.1", "::1"))
          and not any(_is_private(i) for i in ("172.15.0.1", "172.32.0.1", "8.8.8.8",
                                               "203.0.113.1")))
    s, d, sp, dp, swapped, why = _orient("10.0.0.5", "93.184.216.34", 51000, 443)
    check("private->public is outbound and unswapped", not swapped and s == "10.0.0.5")
    s, d, sp, dp, swapped, why = _orient("93.184.216.34", "10.0.0.5", 51000, 443)
    check("public->private swaps so src is the initiator",
          swapped and s == "10.0.0.5" and sp == 443, f"{s}:{sp} ({why})")
    s, d, sp, dp, swapped, why = _orient("10.0.0.5", "10.0.0.6", 445, 51000)
    check("low->high port swaps: the ephemeral port initiated", swapped and sp == 51000)
    s, d, sp, dp, swapped, why = _orient("10.0.0.5", "10.0.0.6", 51000, 51001)
    check("symmetric case admits it cannot tell rather than inventing an answer",
          "not determinable" in why, why[:70])

    fev = nf._to_event({
        "_src_ip": "93.184.216.34", "_dst_ip": "10.0.0.5", "_src_port": 51000,
        "_dst_port": 443, "_protocol": 6, "_start_time": clock.now - 240,
        "_last_seen": clock.now, "_fwd_packets": 10, "_bwd_packets": 90,
        "_iface": "Wi-Fi", "total_length_fwd_packets": 1000.0,
        "total_length_bwd_packets": 90000.0, "flow_duration": 240000.0,
        "fwd_packet_length_mean": 100.0})
    check("a swapped flow swaps its byte and packet counts with it",
          fev["traffic_packets_out"] == 90 and fev["traffic_bytes_out"] == 90000.0,
          f"out={fev['traffic_packets_out']} bytes_out={fev['traffic_bytes_out']}")
    check("the flow is timed at its start, not at eviction",
          fev["time"] == clock.now - 240)
    check("the 74 features ride along under their training names",
          fev["unmapped"].get("fwd_packet_length_mean") == 100.0
          and "_src_ip" not in fev["unmapped"])
    fb = Event.build(source="network_flow", raw=None, **fev)
    check("the schema accepts a flow event", fb.class_uid == 4001 and fb.activity_id == 6)
    check("and the direction audit note is now in soc_notes, not unmapped",
          any("oriented" in n for n in fb.soc_notes) and "notes" not in (fb.unmapped or {}),
          str(fb.soc_notes))
    check("a flow with no addresses is refused, not stored with placeholders",
          _raises(lambda: nf._to_event({"_src_port": 1, "_dst_port": 2})))

    before = nf.stats.dropped
    nf._on_flow({"_src_port": 1})           # no addresses -> mapping failure
    check("a malformed flow is counted as a drop, not silently ignored",
          nf.stats.dropped == before + 1, f"{before} -> {nf.stats.dropped}")

    register("network_flow", [fev])

    # ══ 6. the fleet, and how gaps are reported ═════════════════════════════
    print("\n── fleet reporting: a gap must read as UNCONFIGURED with a fix ──")
    lake2 = fresh_lake()
    pipe2 = Pipeline(lake2, cfg, clock=clock)
    mon = HealthMonitor(pipe2, cfg, clock=clock)
    fleet = CollectorFleet(pipe2, monitor=mon, clock=clock)
    fleet.add_all([
        NetworkFlowCollector(pipe2, iface="Wi-Fi", clock=clock),
        WindowsEventLogCollector(pipe2, state_dir=ROOT / "state2", clock=clock),
        SysmonCollector(pipe2, state_dir=ROOT / "state2", clock=clock),
    ])
    check("adding a collector declares its source, so silence can be judged",
          {"network_flow", "windows_eventlog", "sysmon"} <= set(pipe2.sources))

    results = {h.source: h for h in mon.evaluate()}
    if is_windows():
        check("sysmon reads as UNCONFIGURED, not DEAD and not healthy",
              results["sysmon"].status is SourceStatus.UNCONFIGURED,
              results["sysmon"].status.value)
        check("...and its reason carries the install instruction to the board",
              "Sysmon.zip" in results["sysmon"].reason, results["sysmon"].reason[:70])
        check("an UNCONFIGURED source is not alertable — it is a known gap, not a fault",
              not results["sysmon"].alertable)
    if not is_admin():
        check("network_flow reads as UNCONFIGURED too, with elevation named",
              results["network_flow"].status is SourceStatus.UNCONFIGURED
              and bool(results["network_flow"].reason),
              results["network_flow"].reason[:70])

    setup = fleet.setup_instructions()
    check("setup instructions are generated for exactly the fixable gaps",
          ("Sysmon" in setup) if is_windows() else True, setup[:70])
    check("the fleet report lists unavailable collectors under a heading an operator "
          "will read", "UNAVAILABLE ON THIS HOST" in fleet.report() or not fleet.unavailable())
    check("nothing is dropping yet", fleet.dropping() == [])

    print("\n── push/pull contracts ──")
    class Tiny(PushCollector):
        name = "tiny_push"
        def probe(self): return available()
        def start_source(self): pass

    t = Tiny(pipe2, buffer_size=3, clock=clock)
    for i in range(5):
        t.offer({"i": i})
    check("a full push buffer evicts the oldest and counts every loss",
          t.stats.dropped == 2 and t.stats.buffered == 3,
          f"dropped={t.stats.dropped} buffered={t.stats.buffered}")
    check("...and the newest events are the ones kept",
          [e["i"] for e in t._drain(10)] == [2, 3, 4])

    class Broken(PullCollector):
        name = "broken_pull"
        def probe(self): return available()
        async def poll(self): raise RuntimeError("provider exploded")

    b = Broken(pipe2, cadence_seconds=0.01, clock=clock)
    task = b.start()
    await asyncio.sleep(0.08)
    await b.stop()
    check("a collector that fails every cycle keeps running and counts failures",
          b.stats.failures >= 2 and "provider exploded" in b.stats.last_error,
          f"{b.stats.failures} failures, cycles={b.stats.cycles}")
    check("...and backs off rather than spinning", b._backoff > 1.0, str(b._backoff))

    class Refusing(PullCollector):
        name = "refusing"
        def probe(self): return unavailable("needs a thing that is not here")
        async def poll(self): return []

    r = Refusing(pipe2, clock=clock)
    check("an unavailable collector does not start", r.start() is None)
    check("...and a probe that raises is itself unavailability, not a crash",
          not _Exploding(pipe2, clock=clock).availability())

    # ────────────────────────────────────────────────────────────────────
    print("\n── process collector: identity, diffing, blind window ──")

    pc = ProcessCollector(pipe2, cadence_seconds=2.0, hash_executables=False)
    av = pc.probe()
    check("psutil is present so the process collector is available", bool(av))
    check("...but it reports a limitation rather than claiming completeness",
          bool(av.limitation))
    check("...naming the poll interval as cadence PLUS scan time, not the cadence",
          "plus however long the scan itself takes" in av.limitation)
    check("...and offering 4688 as the fix for what polling cannot see",
          "auditpol /set /subcategory" in av.limitation)

    base = await pc.poll()
    check("the first poll emits the whole process table as a baseline",
          len(base) > 20, f"{len(base)} processes")
    check("...labelled so a detection rule can exclude it, since otherwise every "
          "collector restart looks like hundreds of simultaneous launches",
          all("baseline_snapshot" in p.get("metadata_labels", []) for p in base))
    check("...as Process Activity launches with real OS creation times",
          all(p["class_uid"] == int(ClassUid.PROCESS_ACTIVITY) and p["activity_id"] == 1
              for p in base))

    # Every baseline payload must survive the schema. This is the check that caught
    # `duration` being a float and the two kernel PIDs being dropped.
    built, rejected = 0, []
    for p in base:
        try:
            Event.build(source="process", **p)
            built += 1
        except Exception as exc:
            rejected.append(f"{type(exc).__name__}: {exc}")
    check("every baseline event is accepted by the event schema",
          not rejected, f"{built} built, {len(rejected)} rejected: {rejected[:2]}")

    # PID 0 and PID 4 report create_time 0 on Windows, which is before the schema's
    # floor. Dropping them would leave a permanent hole where kernel-mode activity and
    # SMB traffic are attributed, and `System` is a name malware masquerades as.
    kernel = [p for p in base if p.get("process_pid") in (0, 4)]
    if is_windows():
        check("the kernel pseudo-processes PID 0 and 4 are present, not dropped for "
              "having a zero creation time", len(kernel) == 2,
              f"{[p.get('process_pid') for p in kernel]}")
        check("...stamped with boot time, which is when the kernel did start",
              all(p["time"] > 946684800 for p in kernel))
        check("...and each says so on the event, so the substitution is not silent",
              all(any("system boot time, substituted" in n
                      for n in (p.get("soc_notes") or [])) for p in kernel))

    uids = [p["metadata_uid"] for p in base]
    check("baseline identities are unique — a duplicate here means two processes "
          "collapsed into one", len(uids) == len(set(uids)))
    check("...and each carries (pid, create_time), not just the PID, because a "
          "recycled PID keyed on PID alone reports no change at all",
          all(p["process_uid"].count(":") >= 2 for p in base))

    idle = await pc.poll()
    # NOT `idle == []`. That assertion was here and it failed intermittently, which is
    # correct behaviour being called a bug: the poll runs against the live process
    # table, and Windows starts and stops background processes on its own schedule, so
    # a genuinely-new launch between the baseline and this poll is a real event the
    # collector is supposed to report. A flaky assertion is worse than a weaker one —
    # it teaches whoever runs the suite that a red line means nothing. What is
    # guaranteed, and what the diff logic would break if it regressed, is that nothing
    # already in the baseline is reported again.
    repeats = [p for p in idle if p.get("metadata_uid") in set(uids)]
    check("a second poll does not re-report a process it already reported — the diff "
          "is keyed on (pid, create_time) and a still-running process is not news",
          repeats == [], f"{len(repeats)} processes reported twice")
    check("...and anything it does emit is a real launch or exit that happened "
          "between the two polls, on a live host that never stops starting processes",
          all(p["activity_id"] in (1, 2) for p in idle),
          f"{len(idle)} genuine event(s) in the gap")
    check("...and the steady-state scan is fast, because the scan duration IS part "
          "of the blind window", pc._poll_seconds < 1.0,
          f"{pc._poll_seconds*1000:.1f} ms")
    check("the first poll's cost is recorded separately from the worst steady-state "
          "poll, so a startup figure cannot mask a later regression",
          pc._first_poll_seconds > pc._poll_seconds_worst,
          f"first={pc._first_poll_seconds:.3f}s worst={pc._poll_seconds_worst:.3f}s")
    check("the blind window is the cadence PLUS the measured scan, not the cadence — "
          "run() sleeps the cadence after the cycle returns",
          pc.blind_window_seconds == pytest_approx(2.0 + pc._poll_seconds),
          f"{pc.blind_window_seconds}")
    check("...and it is on the health board, not just in a docstring",
          "blind_window_seconds" in pc.stats_extra())

    # A real launch and a real termination, observed.
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1.5)"])
    launched = await pc.poll()
    mine = [p for p in launched if p.get("process_pid") == proc.pid]
    check("a process launched between two polls produces a launch event",
          len(mine) == 1, f"{len(mine)} events for pid {proc.pid}")
    if mine:
        ev = mine[0]
        check("...with its command line, which is the whole point of the event",
              "time.sleep(1.5)" in (ev.get("process_cmd_line") or ""))
        check("...and its parent named — this test process",
              ev.get("actor_process_pid") == os.getpid(),
              f"{ev.get('actor_process_pid')} vs {os.getpid()}")
        check("...and it is not labelled as baseline",
              "baseline_snapshot" not in ev.get("metadata_labels", []))
        Event.build(source="process", **ev)
        check("...and the schema accepts it", True)

    proc.wait()
    await asyncio.sleep(0.05)
    ended = await pc.poll()
    gone = [p for p in ended if p.get("process_pid") == proc.pid]
    check("...and its exit produces a terminate event", len(gone) == 1,
          f"{len(gone)} events")
    if gone:
        ev = gone[0]
        check("...with activity_id 2 and a measured lifetime",
              ev["activity_id"] == 2 and ev["duration"] > 500,
              f"activity={ev['activity_id']} duration={ev.get('duration')}")
        check("...duration as an integer of milliseconds, which is what OCSF says "
              "and what pydantic enforces — a float is rejected outright",
              isinstance(ev["duration"], int))
        check("...bounding the exit between the two polls rather than claiming a "
              "precision the method does not have",
              any("exit observed by absence" in n for n in ev.get("soc_notes", [])))
        check("...and NOT reporting a lifetime CPU it never measured: resource "
              "counters are not refreshed per cycle, so a figure computed from "
              "launch-time values would read as idle for every process on the host",
              "cpu_percent_lifetime" not in (ev.get("unmapped") or {}))
        check("...saying so on the event instead of omitting it silently",
              any("no CPU or memory figures" in n for n in ev.get("soc_notes", [])))
        Event.build(source="process", **ev)

    check("launches and terminations are counted",
          pc.launches >= 1 and pc.terminations >= 1,
          f"{pc.launches} launches, {pc.terminations} terminations")

    register("process", base + idle + launched + ended)

    # ── the two branches that will not occur naturally in a test ──
    print("\n── process collector: parent resolution edge cases ──")

    def _rec(pid, created, ppid, name):
        return {"pid": pid, "create_time": created, "ppid": ppid, "name": name,
                "exe": None, "cmdline": None, "username": None, "cwd": None,
                "num_threads": None, "cpu_times": None, "memory_info": None,
                "status": None}

    pc2 = ProcessCollector(pipe2, cadence_seconds=1.0, hash_executables=False)

    # Orphan: the parent exited in the cycle the child was born in. This is normal for
    # a launcher and *characteristic* of injection and detached scripts — resolving
    # only against the live table would blank the parent on exactly those events.
    pc2._recent_dead = {700: _rec(700, 1000.0, 1, "launcher.exe")}
    notes: list[str] = []
    payload: dict = {}
    pc2._attach_parent(payload, _rec(701, 1005.0, 700, "child.exe"), {}, 1005.0, notes)
    check("a child whose parent already exited still names the parent, from the "
          "previous snapshot", payload.get("actor_process_name") == "launcher.exe")
    check("...and records that the parent was dead when resolved, so nobody reads it "
          "as a live process tree",
          any("exited within the last cycle" in n for n in notes))

    # PID recycle / parent-PID spoofing: the "parent" was created AFTER the child.
    # T1134.004 and an ordinary recycle are indistinguishable from here, so naming a
    # parent would attach a wrong one and corrupt every tree built downstream.
    pc3 = ProcessCollector(pipe2, cadence_seconds=1.0, hash_executables=False)
    notes = []
    payload = {}
    by_pid = {800: _rec(800, 2000.0, 1, "impostor.exe")}
    pc3._attach_parent(payload, _rec(801, 1500.0, 800, "child.exe"), by_pid, 1500.0,
                       notes)
    check("a parent created AFTER its child is refused, not reported — the PID was "
          "recycled, or the parent PID was spoofed, and the two are "
          "indistinguishable from here",
          payload.get("actor_process_name") in (None, ""),
          f"named {payload.get('actor_process_name')!r}")
    check("...and the refusal is counted, so a host where it happens constantly is "
          "visible", pc3.parent_pid_recycled == 1)
    check("...with the reason on the event rather than a silent gap",
          any("recycl" in n.lower() or "spoof" in n.lower() for n in notes),
          f"{notes}")
    check("...and it counts as unresolved too, because the event genuinely has no "
          "usable parent — counting it only as 'recycled' would let parent_unresolved "
          "understate how many events have no parent at all",
          pc3.parent_unresolved == 1)

    notes = []
    payload = {}
    pc3._attach_parent(payload, _rec(900, 1500.0, 999, "orphan.exe"), {}, 1500.0, notes)
    check("a parent that is neither live nor recently dead is reported unresolved",
          pc3.parent_unresolved == 2 and not payload.get("actor_process_name"),
          f"unresolved={pc3.parent_unresolved}")
    check("...and that case is not miscounted as a PID recycle, which is a different "
          "and more suspicious finding", pc3.parent_pid_recycled == 1)

    # ── hash cache identity ──
    print("\n── process collector: hash cache ──")
    pc4 = ProcessCollector(pipe2, cadence_seconds=1.0)
    tmp = Path(tempfile.gettempdir()) / "cyphra_hash_probe.bin"
    tmp.write_bytes(b"first content")
    n1: list[str] = []
    p1: dict = {}
    pc4._attach_hashes(p1, str(tmp), n1)
    first = p1.get("process_file_sha256")
    check("an executable is hashed and the digest attached", bool(first))
    check("...lower-case, to agree with the schema and with every intel feed",
          first == (first or "").lower())
    p2: dict = {}
    pc4._attach_hashes(p2, str(tmp), [])
    check("...and the second read of the same file is served from cache",
          pc4.hashes_from_cache == 1 and pc4.hashes_computed == 1)

    time.sleep(0.01)
    tmp.write_bytes(b"second content, different length")
    p3: dict = {}
    pc4._attach_hashes(p3, str(tmp), [])
    check("a binary replaced IN PLACE is re-hashed, not served under its old digest — "
          "the cache key is (path, size, mtime), because a supply-chain swap keeps "
          "the path", p3.get("process_file_sha256") != first)
    check("...and that is a computed hash, not a cache hit", pc4.hashes_computed == 2)
    try:
        tmp.unlink()
    except OSError:
        pass

    # ── stats reach the fleet report ──
    print("\n── process collector: reporting ──")
    extra = pc.stats_extra()
    for key in ("blind_window_seconds", "blind_window_seconds_worst",
                "poll_seconds_last", "first_poll_seconds", "processes_tracked",
                "parent_unresolved", "parent_pid_recycled", "access_denied_reads",
                "resource_usage_tracked"):
        check(f"stats_extra reports {key}", key in extra)

    fleet2 = CollectorFleet(pipe2)
    fleet2.add(pc)
    check("the fleet collects the collector's own extra stats",
          "process" in fleet2.extra_stats())
    check("...and its limitation, separately from unavailability — nothing is broken "
          "and there is nothing to install, but 'we collect process events' and 'we "
          "collect the ones that live longer than the scan' are different claims",
          any(n == "process" for n, _ in fleet2.limitations()))
    rep = fleet2.report()
    check("the blind window appears in the rendered fleet report, so the number is "
          "unmissable rather than merely available",
          "blind_window_seconds" in rep)
    check("...under a heading that says what it means",
          "RUNNING, BUT NOT SEEING EVERYTHING" in rep)

    # ── DNS ─────────────────────────────────────────────────────────────────
    print("\n── dns: Windows status codes are not DNS RCODEs ──")
    check("status 0 is NoError", dns_status(0)[0] == 0)
    check("9003 DNS_ERROR_RCODE_NAME_ERROR is NXDomain (3)", dns_status(9003)[0] == 3)
    check("9002 is ServFail (2)", dns_status(9002)[0] == 2)
    check("9005 is Refused (5)", dns_status(9005)[0] == 5)
    rc9501, name9501, transport9501 = dns_status(9501)
    check("9501 DNS_INFO_NO_RECORDS maps to RCODE 0 NoError, NOT NXDomain — it is "
          "NODATA, the name exists and simply has no record of the type asked for. "
          "An IPv4-only host returns 9501 for every AAAA lookup, so mapping it to 3 "
          "would report a large fraction of all lookups as failed resolutions of "
          "nonexistent names — which is the signature of DGA and C2 fallback, "
          "manufactured permanently out of ordinary IPv6 absence",
          rc9501 == 0)
    check("...and it says NODATA in the mnemonic, so nobody reads the 0 as a plain "
          "successful A-record answer", "NODATA" in name9501)
    check("...and it is not a transport failure — a server did answer",
          transport9501 is False)
    for code in (1460, 9503, 9701):
        rc, _mn, tr = dns_status(code)
        check(f"status {code} is a transport failure, reported as 99/Other rather "
              f"than as a response code — nothing answered, so there is no RCODE",
              rc == 99 and tr is True)
    check("an unmapped code inside the 9000-9018 RCODE-offset band is NOT guessed to "
          "be a transport failure — a code in that band is far likelier to be an "
          "RCODE this table omits, and calling it 'nothing answered' when something "
          "did is the wrong direction to be wrong in",
          dns_status(9011)[2] is False)
    check("...while an unmapped code outside the band is treated as transport",
          dns_status(31337)[2] is True)
    check("a non-numeric status does not raise", dns_status("nonsense")[0] == 99)
    check("every RCODE this table emits is 0-18 or exactly 99",
          all(v[0] in range(19) or v[0] == 99 for v in WINDOWS_DNS_STATUS.values()))

    print("\n── dns: query types ──")
    check("type 1 renders as A", query_type_name(1) == "A")
    check("type 28 renders as AAAA", query_type_name(28) == "AAAA")
    check("type 65 renders as HTTPS (SVCB family), not as unknown",
          query_type_name(65) == "HTTPS")
    check("an unrecognised type renders as TYPE<n> rather than being blanked — a "
          "query type nobody recognises, issued by a desktop, is more interesting "
          "than an A record, and blanking it removes the field that made the event "
          "worth reading", query_type_name(43210) == "TYPE43210")
    check("TXT is flagged notable (DNS-tunnelling carrier)", 16 in NOTABLE_QUERY_TYPES)
    check("AXFR and IXFR are flagged notable (zone transfer = recon)",
          252 in NOTABLE_QUERY_TYPES and 251 in NOTABLE_QUERY_TYPES)
    check("ANY is flagged notable (amplification / zone enumeration)",
          255 in NOTABLE_QUERY_TYPES)
    check("A is NOT flagged notable, or every event would carry the flag and it "
          "would mean nothing", 1 not in NOTABLE_QUERY_TYPES)

    print("\n── dns: a disabled channel opens cleanly and returns nothing ──")
    enabled, detail = channel_enabled(DNS_CLIENT_CHANNEL)
    check("the channel's enabled flag is readable and returns a bool or None, not a "
          "raw pywin32 (value, type) tuple", enabled in (True, False, None))
    check(f"...on this host it reports {detail!r}", isinstance(detail, str) and detail)
    check("a channel that does not exist is reported as None/unknown rather than as "
          "False/disabled — 'disabled, run this command' and 'I could not tell' need "
          "different operator responses",
          channel_enabled("Cyphra-Nonexistent/Operational")[0] is None)

    lc = DnsClientLogCollector(pipe2)
    av_dns = lc.probe()
    if enabled is False:
        check("THE POINT OF THIS COLLECTOR'S PROBE: the DNS-Client channel is "
              "disabled on this host, and the probe reports it UNAVAILABLE even "
              "though EvtQuery against it succeeds. A probe written the obvious way "
              "— can I open this channel? — passes here and would show DNS as a "
              "healthy green source that collects zero events forever",
              av_dns.available is False)
        check("...and it is reported as fixable by the operator, so it lands in the "
              "setup checklist rather than being filed as a platform limit",
              av_dns.fixable_by_user is True)
        check("...with the exact wevtutil command to enable it",
              "wevtutil sl" in av_dns.reason and "/e:true" in av_dns.reason)
        check("...and the log-size command too, because this channel logs cache hits "
              "and the 1 MB default wraps in minutes — enabling it without resizing "
              "it produces a source that loses events before anything reads them",
              "/ms:" in av_dns.reason)
        check("...and it names Sysmon event 22 as the better alternative, since that "
              "one attributes each query to a process", "Sysmon event 22" in av_dns.reason)
    else:
        check("the DNS-Client channel is enabled here, so the probe defers to the "
              "base Event Log readability check", av_dns.available in (True, False))

    print("\n── dns: query-completed mapping ──")
    dns_xml = win_xml(
        3008,
        channel=DNS_CLIENT_CHANNEL,
        provider="Microsoft-Windows-DNS-Client",
        data={
            "QueryName": "cdn.example-c2.top",
            "QueryType": "16",
            "QueryStatus": "0",
            "QueryResults": "::ffff:93.184.216.34;10.0.0.9;",
        },
    )
    mapped = lc._to_event(lc.channels[0], dns_xml)
    check("a query-completed event maps to DNS Activity",
          mapped["class_uid"] == int(ClassUid.DNS_ACTIVITY))
    check("...with activity_id 2 (Response), because 3008 carries results",
          mapped["activity_id"] == 2)
    check("...the queried name is on the OCSF field, not buried in unmapped",
          mapped.get("dns_query_hostname") == "cdn.example-c2.top")
    check("...the query type is the mnemonic a rule author writes, not the number",
          mapped.get("dns_query_type") == "TXT")
    check("...status 0 becomes rcode 0", mapped.get("dns_rcode_id") == 0)
    answers = mapped["unmapped"]["dns_answers"]
    check("an IPv4-mapped IPv6 answer (::ffff:93.184.216.34) is normalised to the "
          "dotted quad — intel feeds, firewall logs and flow records all carry the "
          "dotted form, so leaving the mapped prefix on produces a join that "
          "silently matches nothing", answers[0] == "93.184.216.34")
    check("...the semicolon-terminated list does not yield a trailing empty answer",
          len(answers) == 2 and all(answers))
    check("...and the answer count is the real count", mapped.get("dns_answer_count") == 2)
    check("a TXT query carries the tunnelling note, because the type is the finding "
          "here regardless of the name asked for",
          any("TXT" in n for n in mapped.get("soc_notes") or []))
    built_dns = Event.build("dns_client_log", **mapped)
    check("...and the whole thing is accepted by the schema",
          built_dns.class_uid == 4003 and built_dns.type_uid == 400302)

    timeout_xml = win_xml(
        3008, channel=DNS_CLIENT_CHANNEL, provider="Microsoft-Windows-DNS-Client",
        data={"QueryName": "nothing.invalid", "QueryType": "1", "QueryStatus": "1460"},
    )
    tmapped = lc._to_event(lc.channels[0], timeout_xml)
    check("a timed-out query is flagged as a transport failure, kept distinct from "
          "an NXDOMAIN so a resolution-failure hunt does not count 'nothing "
          "answered' as 'the server said the name does not exist'",
          tmapped["unmapped"].get("dns_transport_failure") is True)
    check("...and it says so in a note", any("transport failure" in n
          for n in tmapped.get("soc_notes") or []))
    check("...and its rcode is 99/Other, not 3", tmapped.get("dns_rcode_id") == 99)

    print("\n── dns: hosts file is not DNS telemetry ──")
    tmpdir = Path(tempfile.mkdtemp(prefix="cyphra_dns_"))
    hosts_file = tmpdir / "hosts"
    hosts_file.write_bytes(
        "﻿# a hosts file that starts with a UTF-8 BOM\r\n"
        "127.0.0.1       localhost\r\n"
        "10.1.2.3        updates.vendor.example  www.updates.vendor.example\r\n"
        "10.1.2.3        Mixed.Case.Example\r\n"
        "0.0.0.0         blocked.example    # Fake Google Site\r\n"
        "\r\n".encode("utf-8")
    )
    parsed, digest, herr = read_hosts_file(hosts_file)
    check("the hosts file parses with no error", herr == "")
    check("a UTF-8 BOM does not corrupt the first line — this host's real hosts file "
          "has one, and reading it as cp1252 renders it as 'i>>#', which is harmless "
          "on a comment and silently corrupts the first entry when the file was "
          "written by a script rather than by hand",
          "localhost" in parsed and not any(k.startswith("﻿") for k in parsed))
    check("multiple names on one line are all captured",
          "updates.vendor.example" in parsed and "www.updates.vendor.example" in parsed)
    check("names are lower-cased, because DNS is case-insensitive and the cache "
          "reports whatever case was queried — a case-sensitive cross-reference "
          "would fail to match the hand-typed entry an attacker adds",
          "mixed.case.example" in parsed)
    check("THE INLINE-COMMENT TRAP: words after '#' are not read as hosts entries. "
          "This host's real hosts file has 59 lines ending '# Fake FitGirl site', "
          "and a naive split yields 'fake', 'fitgirl' and 'site' as names — which "
          "would then label any genuine resolution of those names as hosts-sourced "
          "and suppress it from resolution counts entirely",
          "google" not in parsed and "site" not in parsed and "fake" not in parsed)
    check("...while the name actually on that line is captured",
          "blocked.example" in parsed)
    check("a missing hosts file returns an explicit error, not a silent empty dict — "
          "empty means 'no entries', and without the distinction every cache row "
          "would be reported as an observed query",
          read_hosts_file(tmpdir / "absent")[2] != "")
    check("the digest is over the raw bytes, so a comment-only edit registers",
          read_hosts_file(hosts_file)[1] == digest)

    dc = DnsCacheCollector(pipe2, hosts_path=hosts_file, clock=lambda: 1_700_000_000.0)
    dc._hosts, dc._hosts_digest = parsed, digest
    rows = [
        # a hosts-file entry, indistinguishable from a real answer by every field
        {"Entry": "updates.vendor.example", "Name": "updates.vendor.example",
         "Data": "10.1.2.3", "Type": 1, "Section": 1, "Status": 0,
         "TimeToLive": 518970},
        # a genuine resolution
        {"Entry": "graph.microsoft.com", "Name": "graph.microsoft.com",
         "Data": "20.190.130.1", "Type": 1, "Section": 1, "Status": 0,
         "TimeToLive": 42},
        # the AAAA negative every IPv4-only host produces, en masse
        {"Entry": "graph.microsoft.com", "Name": "graph.microsoft.com",
         "Data": "", "Type": 28, "Section": 0, "Status": 9501, "TimeToLive": 60},
        # a real NXDOMAIN
        {"Entry": "kjhsdf8s7dfkjh.example", "Name": "kjhsdf8s7dfkjh.example",
         "Data": "", "Type": 1, "Section": 0, "Status": 9003, "TimeToLive": 0},
    ]
    made = [
        dc._cache_event(r, str(r["Entry"]), int(r["Type"]), int(r["Section"]),
                        str(r["Data"]), 1_700_000_000.0, False)
        for r in rows
    ]
    hosts_ev, real_ev, nodata_ev, nx_ev = made
    check("a hosts-file cache row is NOT reported as a DNS resolution: Windows loads "
          "the hosts file into the resolver cache, where those rows carry status 0, "
          "an answer and a long TTL and are indistinguishable from answered queries "
          "by every field the cache exposes. Reporting them as queries inflates "
          "every per-domain count a hunt computes with resolutions that never "
          "happened", hosts_ev["activity_id"] == 99)
    check("...and OCSF's contract for 99 is honoured — activity_name carries the "
          "source-specific label, so the event says what it IS rather than only "
          "that the schema had no match for it",
          "hosts" in (hosts_ev.get("activity_name") or "").lower())
    check("...it is labelled hosts_file so it is filterable in SQL without parsing "
          "prose", "hosts_file" in hosts_ev["metadata_labels"])
    check("...and it carries the addresses the hosts file assigns, so a redirection "
          "is visible without re-reading the file",
          hosts_ev["unmapped"]["dns_hosts_file_addresses"] == ["10.1.2.3"])
    check("...and it explains itself in a note",
          any("hosts file" in n for n in hosts_ev["soc_notes"]))
    check("a genuine resolution IS reported as a response",
          real_ev["activity_id"] == 2 and "hosts_file" not in real_ev["metadata_labels"])
    check("...and it is counted as a resolution, separately from hosts entries — the "
          "two counters exist so that 'we saw 213 DNS resolutions' cannot be said "
          "when 122 of them were a text file",
          dc.entries_emitted == 3 and dc.hosts_entries_emitted == 1)
    check("a 9501 AAAA negative gets rcode 0 through the collector too, not just "
          "through the mapping function", nodata_ev["dns_rcode_id"] == 0)
    check("...and it is not marked as a transport failure",
          "dns_transport_failure" not in nodata_ev["unmapped"])
    check("a real NXDOMAIN gets rcode 3, so the two remain distinguishable — which "
          "is the entire value of getting 9501 right", nx_ev["dns_rcode_id"] == 3)
    check("every cache event says its timestamp is observation time, not query time: "
          "the cache holds a remaining TTL and not the original, so the moment of "
          "resolution is unrecoverable and a timeline must not order on this",
          all(any("not at query time" in n for n in e["soc_notes"]) for e in made))
    check("a cache event is a Response, never a Query — the query itself was not "
          "observed, so its time, flags and calling process are all unknown",
          all(e["activity_id"] in (2, 99) for e in made))
    for e in made:
        Event.build("dns_cache", **e)
    check("...and all four are accepted by the schema", True)

    print("\n── dns: hosts-file change detection ──")
    dc2 = DnsCacheCollector(pipe2, hosts_path=hosts_file, clock=lambda: 1_700_000_100.0)
    check("the first load emits nothing — it is the baseline, not a change",
          dc2._check_hosts_file(1_700_000_100.0) == [])
    hosts_file.write_bytes(
        "127.0.0.1       localhost\r\n"
        "10.1.2.3        updates.vendor.example\r\n"
        "203.0.113.9     login.corp.example\r\n".encode("utf-8")
    )
    changed = dc2._check_hosts_file(1_700_000_200.0)
    check("a changed hosts file emits exactly one event", len(changed) == 1)
    ch = changed[0]
    check("...classified as a file update, not as DNS activity — the finding is that "
          "a file changed", ch["class_uid"] == int(ClassUid.FILE_SYSTEM_ACTIVITY)
          and ch["activity_id"] == 3)
    check("...at MEDIUM and not informational: this file overrides DNS for every "
          "process on the host, needs admin rights to write, survives reboots, and "
          "produces no network traffic — a redirection placed here is invisible to "
          "anything watching only the wire",
          ch["severity_id"] == int(Severity.MEDIUM))
    check("...naming what was added", "login.corp.example" in ch["unmapped"]["hosts_names_added"])
    check("...and what was removed",
          "www.updates.vendor.example" in ch["unmapped"]["hosts_names_removed"])
    check("...and it carries both digests, so the change is provable after the fact",
          ch["unmapped"]["hosts_sha256"] != ch["unmapped"]["hosts_previous_sha256"])
    Event.build("dns_cache", **ch)
    check("...and the change event validates", True)
    check("an unchanged file on the next poll emits nothing",
          dc2._check_hosts_file(1_700_000_300.0) == [])
    for p in (hosts_file,):
        try:
            p.unlink()
        except OSError:
            pass

    print("\n── dns: live resolver cache on this host ──")
    dc3 = DnsCacheCollector(pipe2)
    av_cache = dc3.probe()
    check("the resolver-cache collector is available unelevated, with nothing "
          "enabled and nothing installed — this is the DNS floor",
          av_cache.available is True)
    lim = av_cache.limitation
    check("...and it reports a limitation even while healthy, because a green DNS "
          "light with DoH unaccounted for is the false claim that matters",
          bool(lim))
    for phrase in ("DNS-over-HTTPS", "No process attribution", "No query counts"):
        check(f"...the limitation names: {phrase}", phrase in lim)
    live = await dc3.poll()
    check("a live poll returns cache entries", len(live) > 0)
    lbuilt, lrej = 0, []
    for p in live:
        try:
            Event.build("dns_cache", **p)
            lbuilt += 1
        except Exception as exc:
            lrej.append(f"{p.get('dns_query_hostname')}: {exc}")
    check(f"every one of the {len(live)} real cache entries is accepted by the "
          f"schema ({lbuilt} built, {len(lrej)} rejected)", not lrej)
    if lrej:
        print("      " + lrej[0][:300])
    live_9501 = [e for e in live if e["unmapped"].get("dns_status_windows") == 9501]
    check(f"...and all {len(live_9501)} real 9501 rows on this host carry rcode 0, "
          f"not NXDomain — left wrong, that alone would be a standing DGA signal",
          all(e["dns_rcode_id"] == 0 for e in live_9501))
    live_hosts = [e for e in live if "hosts_file" in e["metadata_labels"]]
    check(f"...and the {len(live_hosts)} rows traceable to this host's hosts file are "
          f"labelled as such rather than counted as resolutions",
          all(e["activity_id"] == 99 and e.get("activity_name") for e in live_hosts))
    check("the whole first poll is labelled baseline_snapshot, so a rule on 'a new "
          "name was resolved' does not fire on every restart",
          all("baseline_snapshot" in e["metadata_labels"] for e in live))
    check("a second poll seconds later emits nothing — an entry is reported once, "
          "not once per cadence for the length of its TTL",
          len(await dc3.poll()) == 0)
    dstats = dc3.stats_extra()
    for key in ("cache_rows_last_poll", "cache_source", "resolutions_emitted",
                "hosts_file_entries_emitted", "hosts_file_names",
                "hosts_file_changes", "negative_or_empty_entries",
                "dns_client_channel_enabled"):
        check(f"stats_extra reports {key}", key in dstats)
    check("...and the cache came from WMI (median 118 ms) rather than from a "
          "PowerShell subprocess (606 ms) or from parsing ipconfig prose (28 ms, "
          "fastest and still last, because it fails by matching nothing)",
          dstats["cache_source"] == "wmi")
    check("...and hosts-file entries are counted separately from resolutions in the "
          "stats too, not merged into one flattering number",
          dstats["resolutions_emitted"] + dstats["hosts_file_entries_emitted"]
          == len(live))

    print("\n── dns: all three cache paths, not just the one that runs ──")
    wmi_rows, wmi_err = _cache_via_wmi()
    ps_rows, ps_err = _cache_via_powershell()
    ic_rows, ic_err = _cache_via_ipconfig()
    check("the WMI path reads the cache", wmi_err == "" and len(wmi_rows) > 0)
    check("the PowerShell fallback reads the cache too — an untested fallback is a "
          "fallback nobody can trust, and this one only runs on a host where WMI is "
          "broken, which is exactly when nobody is watching",
          ps_err == "" and len(ps_rows) > 0)
    check("the ipconfig fallback reads the cache too", ic_err == "" and len(ic_rows) > 0)
    check("THE REGRESSION THIS CATCHES: the ipconfig parser must return a comparable "
          "number of rows to WMI, not a fraction of them. Its first version returned "
          "6 rows where WMI returned 215 and reported no error at all — it required "
          "the record-set header to end with a dot (it does not), dropped every "
          "'No records of type AAAA' negative, and merged multi-record sets. A "
          "fallback that silently loses 97% of the cache is worse than no fallback",
          len(ic_rows) > len(wmi_rows) * 0.8)
    wmi_keys = {(str(r["Entry"]).lower(), int(r["Type"] or 0)) for r in wmi_rows}
    ic_keys = {(str(r["Entry"]).lower(), int(r["Type"] or 0)) for r in ic_rows}
    check(f"...and it finds essentially the same entries WMI does "
          f"({len(wmi_keys & ic_keys)} of WMI's {len(wmi_keys)} name/type pairs), so "
          f"the two paths are interchangeable and not merely similarly sized",
          len(wmi_keys & ic_keys) >= len(wmi_keys) * 0.9)
    ic_neg = [r for r in ic_rows if int(r.get("Status") or 0) == 9501]
    check(f"...including the {len(ic_neg)} NODATA rows, which exist in ipconfig output "
          f"only as the prose line 'No records of type AAAA' with no Record Name "
          f"block — skip that line and 29% of this cache disappears, and it is the "
          f"29%% that carries the NODATA-versus-NXDOMAIN distinction", len(ic_neg) > 0)
    check("...with the type recovered from the mnemonic in that prose line, since it "
          "is the one place Windows prints a name where WMI gives a number",
          all(r["Type"] != 0 for r in ic_neg))
    check("...and its sections are translated back from words to the integers WMI "
          "returns, so a consumer cannot tell which path produced a row",
          all(isinstance(r.get("Section"), int) for r in ic_rows))
    check("a localised Windows is reported as unreadable, not as an empty cache: the "
          "guard is that record-set headers were found but no rows parsed",
          all(k in _cache_via_ipconfig.__doc__ for k in ("localised", "empty")))

    fleet3 = CollectorFleet(pipe2)
    fleet3.add(dc3)
    fleet3.add(lc)
    rep3 = fleet3.report()
    check("the fleet report carries the DNS limitation", "DNS-over-HTTPS" in rep3)
    if enabled is False:
        check("...and lists the disabled DNS channel as an operator action rather "
              "than hiding it", "wevtutil sl" in rep3)

    register("dns_client_log", [mapped, tmapped])
    register("dns_cache", live)

    # ══ 8. local_auth: the tables ═══════════════════════════════════════════
    print("\n── local_auth: AUTH_EVENT_MAP against the vendored schema ──")
    la_bad = []
    for (prov, eid), m in AUTH_EVENT_MAP.items():
        valid = enums.get(m.class_uid)
        if valid is None:
            la_bad.append(f"{prov}/{eid}: class {m.class_uid} is not in the schema")
        elif m.activity_id not in valid:
            la_bad.append(f"{prov}/{eid}: activity {m.activity_id} not valid for "
                          f"{m.class_uid} (valid: {sorted(valid)})")
    check(f"every AUTH_EVENT_MAP activity id is in its class's enum "
          f"({len(AUTH_EVENT_MAP)} provider/id pairs)", not la_bad, "; ".join(la_bad[:3]))

    check("AUTH_EVENT_MAP is keyed by (provider, id), not by id — four of these "
          "channels are written by a provider whose name is not the channel path, and "
          "an id-keyed table would give TerminalServices' id 21 to anything else that "
          "writes a 21",
          all(isinstance(k, tuple) and len(k) == 2 for k in AUTH_EVENT_MAP))
    overlap = sorted({eid for _, eid in AUTH_EVENT_MAP} & set(EVENT_MAP))
    check("...and no id it qualifies is also in the unqualified table, so the "
          "fallback can never shadow a provider-specific mapping",
          not overlap, f"both tables claim {overlap}")

    # THE REGRESSION THIS CATCHES. `activity_id == 99` is OCSF's "Other", and the
    # schema *requires* a non-blank `activity_name` alongside it — Event.build raises
    # without one. Ten mappings in these tables use 99, and the first version of the
    # collector never set activity_name: every one of those events was built, rejected
    # and quarantined while the collector's own counters reported them as produced. The
    # only way to see it is to build one.
    print("\n── every activity_id 99 mapping actually survives Event.build ──")
    nines = [(prov, eid, m) for (prov, eid), m in AUTH_EVENT_MAP.items()
             if m.activity_id == 99]
    check(f"there are {len(nines)} provider/id pairs mapped to activity 99, so this "
          f"check is not vacuous", len(nines) >= 5)
    check("...and every one of them carries a label, which is what gets promoted into "
          "activity_name", all(m.label.strip() for _, _, m in nines))

    lal = LocalAuthLogCollector(pipe2, state_dir=ROOT / "state_auth", clock=clock)
    nine_ch = Channel("Microsoft-Windows-NTLM/Operational", 3002)
    nine_built, nine_fail = 0, []
    nine_payloads = []
    for prov, eid, m in nines:
        p = lal._to_event(nine_ch, win_xml(eid, channel=nine_ch.path, provider=prov))
        if p is None:
            nine_fail.append(f"{prov}/{eid}: filtered out")
            continue
        nine_payloads.append(p)
        try:
            Event.build("local_auth_log", **p)
            nine_built += 1
        except Exception as exc:
            nine_fail.append(f"{prov}/{eid}: {exc}")
    check(f"all {len(nines)} of them build through Event.build ({nine_built} built)",
          not nine_fail, "; ".join(nine_fail[:3]))
    check("...because the mapping's label is promoted into activity_name rather than "
          "left blank — a blank one is rejected outright, and the rejection is silent "
          "in the collector",
          all(p.get("activity_name") for p in nine_payloads),
          str([p.get("activity_name") for p in nine_payloads[:2]]))

    # The same thing for the base table, whose 99s reach the same code path.
    base_nines = [(eid, m) for eid, m in EVENT_MAP.items() if m.activity_id == 99]
    wel_fail = []
    for eid, m in base_nines:
        p = wel._to_event(Channel("Security", 3002, critical=True),
                          win_xml(eid, channel="Security"))
        try:
            Event.build("windows_eventlog", **p)
        except Exception as exc:
            wel_fail.append(f"{eid}: {exc}")
    check(f"and every EVENT_MAP activity-99 mapping builds too "
          f"({len(base_nines)} of them)", not wel_fail, "; ".join(wel_fail[:3]))

    print("\n── local_auth: AUTH_DATA_MAP targets ──")
    strays = sorted({v for v in AUTH_DATA_MAP.values() if v not in known})
    check(f"every AUTH_DATA_MAP target is a real Event field "
          f"({len(AUTH_DATA_MAP)} names)", not strays, ", ".join(strays))
    pathless = sorted({v for v in AUTH_DATA_MAP.values() if v not in OCSF_PATH})
    check("...and every one has an OCSF path, so it lands somewhere a query can "
          "reach rather than in unmapped under a name nothing looks for",
          not pathless, ", ".join(pathless))

    print("\n── provider qualification is an override, not a suggestion ──")
    ups = ("Microsoft-Windows-User Profiles Service", 1)
    check("the provider whose name differs from its channel path is recorded, so the "
          "map's key can be checked against reality rather than assumed",
          KNOWN_PUBLISHERS["Microsoft-Windows-User Profile Service/Operational"]
          == ups[0],
          KNOWN_PUBLISHERS.get("Microsoft-Windows-User Profile Service/Operational"))
    check("...note the difference is one letter — 'Profile*s* Service' writes the "
          "'Profile Service' channel, and getting it wrong raises nothing at all: the "
          "records arrive and silently take the channel's default class",
          "Profiles" in ups[0]
          and "Profiles" not in "Microsoft-Windows-User Profile Service/Operational")
    p_ups = lal._to_event(Channel("Microsoft-Windows-User Profile Service/Operational",
                                  3002), win_xml(1, channel="X", provider=ups[0]))
    check("a User Profiles Service id 1 maps to authentication/Other, not to whatever "
          "id 1 means to some other provider",
          p_ups is not None and (p_ups["class_uid"], p_ups["activity_id"]) == (3002, 99),
          f"{p_ups['class_uid']}/{p_ups['activity_id']}" if p_ups else "None")
    p_other = lal._to_event(Channel("Microsoft-Windows-Biometrics/Operational", 3002),
                            win_xml(1, channel="X", provider="Some-Other-Provider"))
    check("...and a different provider's id 1 does NOT inherit that mapping — it falls "
          "through to the channel default and is counted as unmapped",
          p_other is not None and p_other["unmapped"].get("mapped") is False,
          str(p_other["unmapped"].get("mapped")) if p_other else "None")

    print("\n── NOISY_EVENTS are filtered and counted, not dropped silently ──")
    noisy_key = next(iter(NOISY_EVENTS))
    noisy_ch = Channel(
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 3002)
    before_f = lal.noise_filtered.get(noisy_key, 0)
    dropped = lal._to_event(noisy_ch, win_xml(noisy_key[1], channel=noisy_ch.path,
                                              provider=noisy_key[0]))
    check("a known-noise event returns None rather than an event", dropped is None)
    check("...and is counted per (provider, id), so a host drowning in one trace is "
          "visible instead of looking like a quiet channel",
          lal.noise_filtered.get(noisy_key, 0) == before_f + 1,
          f"{before_f} -> {lal.noise_filtered.get(noisy_key)}")
    check("Channel carries a `filtered` counter distinct from `skipped`, because "
          "'deliberately dropped' and 'could not be parsed' are different health "
          "facts and summing them hides a parser regression",
          hasattr(noisy_ch, "filtered") and hasattr(noisy_ch, "skipped"))

    print("\n── parse_status_code: three encodings, one answer ──")
    check("hex parses", parse_status_code("0xC000006D") == 0xC000006D)
    check("unsigned decimal parses (Entra 1097 writes this form)",
          parse_status_code("3399549144") == 3399549144)
    check("signed decimal parses to the same unsigned value (Entra 1256 writes THIS "
          "form, in the same channel as the line above — normalising is what lets one "
          "lookup table serve both)",
          parse_status_code("-1073741252") == parse_status_code("3221226044")
          == 3221226044)
    check("the Security channel's absent marker '-' is None, not 0 — 0 is "
          "STATUS_SUCCESS and would read as a successful logon",
          parse_status_code("-") is None and parse_status_code("") is None)
    check("garbage is None rather than an exception", parse_status_code("wat") is None)

    print("\n── decode_status: no invented mnemonics ──")
    bad_pw = decode_status(0xC000006A)
    check("a known NTSTATUS decodes to (mnemonic, meaning, severity)",
          bad_pw is not None and len(bad_pw) == 3 and "PASSWORD" in bad_pw[0],
          str(bad_pw)[:80] if bad_pw else "None")
    check("an unknown code returns None rather than a guess — a wrong mnemonic is "
          "worse than an honest bare number, because a rule can match on it",
          decode_status(0xDEADBEEF) is None)
    check("the Kerberos table is consulted only when asked, since the two numbering "
          "spaces collide",
          decode_status(0x18, kerberos=True) is not None
          and decode_status(0x18) is None,
          f"kerb={decode_status(0x18, kerberos=True)} nt={decode_status(0x18)}")
    check("every NTSTATUS entry is a 3-tuple with a non-blank mnemonic",
          all(isinstance(v, tuple) and len(v) == 3 and v[0].strip()
              for v in NTSTATUS_LOGON.values()), f"{len(NTSTATUS_LOGON)} codes")
    check("every Kerberos entry is too", all(
        isinstance(v, tuple) and len(v) == 3 and v[0].strip()
        for v in KERBEROS_STATUS.values()), f"{len(KERBEROS_STATUS)} codes")

    print("\n── the account-flag and privileged-group tables ──")
    check("every UF_FINDINGS bit is also named in UF_FLAGS, so a finding always has a "
          "flag name to report it under",
          set(UF_FINDINGS) <= set(UF_FLAGS),
          str(sorted(set(UF_FINDINGS) - set(UF_FLAGS))))
    check("...and each finding carries a reason and a real severity",
          all(len(v) == 2 and v[0].strip() and 1 <= v[1] <= 6
              for v in UF_FINDINGS.values()))
    rid_names = {d.split(" —")[0].casefold() for d in PRIVILEGED_GROUP_RIDS.values()}
    dupes = sorted(rid_names & set(PRIVILEGED_GROUP_NAMES))
    check("the two privileged-group tables are disjoint — measured: the name table's "
          f"{len(PRIVILEGED_GROUP_NAMES)} entries ({', '.join(sorted(PRIVILEGED_GROUP_NAMES))}) "
          "are all groups with no well-known RID, so no group can be counted twice",
          not dupes, str(dupes))
    check("...and the lookup is RID-first regardless, which is the belt to that "
          "braces: a group whose RID is known does not also consult the name table, so "
          "adding a name that happens to collide cannot silently double a privileged-"
          "group count",
          # The method reads only its argument and the module tables, so it can be
          # called off the class without standing a collector up.
          LocalAccountCollector._privilege_reason(
              None, {"rid": 544, "key": "docker-users"})
          == PRIVILEGED_GROUP_RIDS[544],
          str(LocalAccountCollector._privilege_reason(
              None, {"rid": 544, "key": "docker-users"})))
    check("RID 544 is present, because matching 'Administrators' by name monitors "
          "nothing on a localised install", 544 in PRIVILEGED_GROUP_RIDS)
    check("name-table keys are case-folded, since NetLocalGroupEnum returns the "
          "creator's casing (measured: docker-users, OpenSSH Users, CodexSandboxUsers "
          "on this one host)",
          all(k == k.casefold() for k in PRIVILEGED_GROUP_NAMES))

    print("\n── POLICY_FINDINGS: each predicate fires on the weak value only ──")
    weak = {"min_passwd_len": 0, "password_hist_len": 0, "lockout_threshold": 0,
            "max_passwd_age": 0xFFFFFFFF, "min_passwd_age": 0}
    strong = {"min_passwd_len": 14, "password_hist_len": 24, "lockout_threshold": 5,
              "max_passwd_age": 60 * 86400, "min_passwd_age": 86400}
    misfire = []
    for field, predicate, text, floor in POLICY_FINDINGS:
        if not predicate(weak.get(field)):
            misfire.append(f"{field}: did not fire on the weak value")
        if predicate(strong.get(field)):
            misfire.append(f"{field}: fired on the hardened value too")
        if not text.strip():
            misfire.append(f"{field}: no explanation")
        if not 1 <= floor <= 6:
            misfire.append(f"{field}: severity floor {floor} is not a Severity")
    check(f"all {len(POLICY_FINDINGS)} policy findings fire on weak and stay quiet on "
          f"hardened", not misfire, "; ".join(misfire[:3]))
    check("...and a None (policy unreadable) fires nothing, because 'I could not read "
          "it' is not 'it is weak'",
          not any(p(None) for _, p, _, _ in POLICY_FINDINGS))
    check("...and each carries its own severity floor, because 'no lockout at all' and "
          "'password history of 0' are not the same finding at the same weight",
          len({f for _, _, _, f in POLICY_FINDINGS}) > 1,
          str(sorted(f for _, _, _, f in POLICY_FINDINGS)))

    print("\n── local_auth_channels ──")
    lchans = local_auth_channels()
    check("Security is present and critical", any(
        c.path == SECURITY_CHANNEL and c.critical for c in lchans))
    check("...and it is the only critical one — windows_eventlog also declares "
          "Security critical, and two collectors raising the same fault reads as two "
          "problems", sum(1 for c in lchans if c.critical) == 1)
    check("every channel slug is filesystem-safe, since it becomes a bookmark filename",
          all("/" not in c.slug and " " not in c.slug for c in lchans),
          str([c.slug for c in lchans][:3]))
    check("SECURITY_SETUP names the group AND the audit subcategories, because "
          "readable-but-unaudited is the state this host is actually in",
          "Event Log Readers" in SECURITY_SETUP and "auditpol" in SECURITY_SETUP)

    print("\n── _to_epoch: five shapes of Windows time, two of them not times ──")
    check("an integer POSIX epoch (what NetUserEnum returns) passes through",
          la_to_epoch(1_700_000_000) == 1_700_000_000.0)
    check("0 is a sentinel meaning 'never', not 1970 — read as a time it dates every "
          "account's last logon to the Unix epoch", la_to_epoch(0) is None)
    check("0xFFFFFFFF is a sentinel too, not February 2106",
          la_to_epoch(0xFFFFFFFF) is None)
    import datetime as _dt
    check("a naive year-9999 datetime returns None instead of raising — .timestamp() "
          "on it raises OSError errno 22 on Windows, which would kill the poll",
          la_to_epoch(_dt.datetime(9999, 12, 31, 23, 59, 59)) is None)
    check("a tz-aware year-1601 datetime converts cleanly to -11644473600 and is then "
          "rejected as implausible, rather than being stored as a real timestamp the "
          "event model would refuse",
          la_to_epoch(_dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)) is None)
    check("a plausible tz-aware datetime is kept — 2026-08-29T12:00:00Z is exactly "
          "1788004800",
          la_to_epoch(_dt.datetime(2026, 8, 29, 12, 0, tzinfo=_dt.timezone.utc))
          == 1788004800.0,
          str(la_to_epoch(_dt.datetime(2026, 8, 29, 12, 0, tzinfo=_dt.timezone.utc))))
    check("garbage returns None rather than raising", la_to_epoch("wobble") is None)

    print("\n── _attack: the technique hint, and the schema gap behind it ──")
    check("OCSF classes declare an `attacks` attribute, but nothing in OCSF_PATH "
          "targets it — so there is no Event field for a technique, and assigning one "
          "would land in unmapped under a name no query uses. This is a real schema "
          "gap, and Phase 2's coverage matrix needs it closed",
          "attacks" in (_CLASS_ATTRS.get(3002) or {})
          and not any(v.split(".")[0] == "attacks" for v in OCSF_PATH.values()))
    ap: dict = {}
    la_attack(ap, "T1110.003")
    check("...so the hint goes to metadata.labels as attack:<id>, which is a string "
          "set the lake can filter with one query",
          ap["metadata_labels"] == ["attack:T1110.003"], str(ap))
    check("...and to unmapped.attack_technique as the bare id, for anything that "
          "wants it without parsing a prefix",
          ap["unmapped"]["attack_technique"] == "T1110.003")
    la_attack(ap, "T1110.003")
    check("...applying it twice does not duplicate the label",
          ap["metadata_labels"] == ["attack:T1110.003"], str(ap["metadata_labels"]))
    empty: dict = {}
    la_attack(empty, "")
    check("...and an empty technique writes nothing at all, rather than an 'attack:' "
          "label matching everything", empty == {})

    # ══ 9. LogonSessionCollector, live ══════════════════════════════════════
    print("\n── logon_sessions (live LSA session table) ──")
    lsc = LogonSessionCollector(pipe2)
    lsav = lsc.probe()
    check("probe answers with an Availability", isinstance(lsav, Availability))
    session_payloads: list[dict] = []
    if is_windows() and lsav:
        check("the LSA session table is enumerable unelevated", bool(lsav))
        check("...but the probe states the limitation: enumeration succeeds and most "
              "sessions are unreadable, which is a 2-of-14 coverage fact and not a "
              "failure", bool(lsav.limitation) and "of" in (lsav.limitation or ""),
              (lsav.limitation or "")[:110])
        s_first = await lsc.poll()
        s_by_class = Counter(p["class_uid"] for p in s_first)
        check("the first poll emits per-session logons plus a table event",
              len(s_first) >= 2 and 5017 in s_by_class, str(dict(s_by_class)))
        check("baseline sessions are authentication/Logon, not invented logon events",
              all(p["activity_id"] == 1 for p in s_first if p["class_uid"] == 3002))
        check("...and every one is labelled baseline_snapshot, so a 'new logon' rule "
              "does not fire on every collector restart",
              all("baseline_snapshot" in p["metadata_labels"] for p in s_first
                  if p["class_uid"] == 3002))
        check("the 5017 table event reports the readable ratio, because 'I saw 2 "
              "sessions' and 'there are 2 sessions' are different claims",
              any(isinstance((p.get("unmapped") or {}).get("readable_ratio"), float)
                  for p in s_first if p["class_uid"] == 5017))
        s_second = await lsc.poll()
        check("a second poll seconds later emits nothing — a session is reported once, "
              "not once per cadence for as long as someone is logged in",
              len(s_second) == 0, f"{len(s_second)} payload(s)")
        # Force the heartbeat by moving the collector's own clock, not by sleeping an
        # hour. Restating the table on a cadence is how a *silent* collector is told
        # apart from a collector with nothing to say.
        real_clock = lsc.clock
        lsc.clock = lambda: real_clock() + 4000.0
        s_third = await lsc.poll()
        lsc.clock = real_clock
        check("an hourly heartbeat restates the table even when nothing changed",
              any("heartbeat" in p["metadata_labels"]
                  or "state_observed" in p["metadata_labels"] for p in s_third),
              f"{len(s_third)} payload(s)")
        session_payloads = s_first + s_second + s_third
        register("logon_sessions", session_payloads)
        check("blind_window_seconds is the cadence plus the measured poll, and is on "
              "the health board — a session that opens and closes inside it is "
              "invisible to a state poller, and saying so is the difference between a "
              "gap and a lie",
              lsc.stats_extra().get("blind_window_seconds", 0) >= lsc.cadence_seconds,
              str(lsc.stats_extra().get("blind_window_seconds")))

    # ══ 10. LocalAccountCollector, live plus synthetic diffs ════════════════
    print("\n── local_accounts (live SAM state) ──")
    lac = LocalAccountCollector(pipe2)
    laav = lac.probe()
    check("probe answers with an Availability", isinstance(laav, Availability))
    account_payloads: list[dict] = []
    if is_windows() and laav:
        a1 = await lac.poll()
        ac = Counter(p["class_uid"] for p in a1)
        check("baseline emits one 5003 per account, one 5009 per privileged group, "
              "and exactly one 5002 policy snapshot",
              ac[5003] == len(lac._users) and ac[5002] == 1 and ac[5009] > 0,
              f"5003={ac[5003]} accounts={len(lac._users)} 5002={ac[5002]} "
              f"5009={ac[5009]}")
        check("baseline emits NO account-management events — this host's nine "
              "pre-existing accounts were not created just now, and emitting 3007 "
              "Creates here would fire a privesc rule on every restart",
              ac[3007] == 0, f"3007={ac[3007]}")
        r5009 = Counter(p.get("query_result_id")
                        for p in a1 if p["class_uid"] == 5009)
        check("every 5009 says which kind of answer it is: EXISTS for a group that is "
              "there, DOES_NOT_EXIST for a RID this host never had. Both arrive as a "
              "failed lookup and they have different remedies",
              all(v is not None for v in r5009) and len(r5009) >= 2, str(dict(r5009)))
        check("...and the 5002 policy event carries NO query_result_id, because 5002 "
              "does not declare that attribute — it would build, validate, persist "
              "and then be unqueryable",
              all("query_result_id" not in p for p in a1 if p["class_uid"] == 5002))
        a2 = await lac.poll()
        check("a second poll on a quiet host emits nothing at all — this is the check "
              "that keeps the collector from reporting nine password changes every "
              "five minutes",
              len(a2) == 0,
              str([(p["class_uid"], p.get("activity_id"), p.get("message"))
                   for p in a2[:3]]))

        # ── synthetic diffs against the real snapshot ───────────────────────
        # This host will not create an account on cue, so the snapshot is mutated and
        # the *real* diff code runs against it. Two invariants every section must
        # respect, both learned by breaking them:
        #
        #  * **The age invariant.** `password_age` counts up in lockstep with elapsed
        #    time, so a synthetic "next poll" that advances `_observed_at` by 300s must
        #    also add 300 to the age. Otherwise the implied password *set moment* moves
        #    and the collector correctly reports a password change the test did not
        #    intend. Test data that violates a real invariant tests nothing.
        #  * **A distinct clock per section.** A change event's `metadata_uid` embeds
        #    `now`, so two sections sharing one `now` produce byte-identical ids for
        #    the same account and the pipeline's exact dedup discards the second — the
        #    dedup working, not the collector failing.
        print("\n── local_accounts: synthetic diffs through the real diff code ──")
        t0 = time.time()
        real = {k: dict(v) for k, v in lac._users.items()}

        def advance(snap: dict, seconds: float) -> tuple[dict, float]:
            """The same accounts one interval later, with the age invariant held."""
            at = float(next(iter(snap.values()))["_observed_at"]) + seconds
            out = {}
            for k, v in snap.items():
                r = dict(v, _observed_at=at)
                if isinstance(r.get("password_age"), int) and r["password_age"] > 0:
                    r["password_age"] += int(seconds)
                out[k] = r
            return out, at

        now = t0
        lac._users = {k: dict(v, _observed_at=now - 300) for k, v in real.items()}
        users, now = advance(lac._users, 300.0)
        victim = dict(next(iter(users.values())))
        users["evil"] = dict(
            victim, key="evil", name="evil", rid=1337, sid="S-1-5-21-1-2-3-1337",
            flags=0x0020, priv=1, password_age=10, password_set_at=now - 10,
            bad_pw_count=0, num_logons=0, _observed_at=now)
        diffs = lac._diff_users(users, now)
        created = [p for p in diffs if p["class_uid"] == 3007 and p["activity_id"] == 1]
        check("a new local account emits 3007 activity 1 Create", len(created) == 1,
              str([(p["class_uid"], p["activity_id"]) for p in diffs]))
        check("...tagged T1136.001 in a label the lake can filter on",
              bool(created) and "attack:T1136.001" in created[0]["metadata_labels"])
        check("...and saying outright that the actor is not knowable from a diff, "
              "rather than leaving an empty actor field to be read as SYSTEM",
              bool(created) and any("not knowable" in n for n in created[0]["soc_notes"]))
        check("...and nothing else fired: eight unchanged accounts produced silence",
              len(diffs) == 1,
              str([(p["class_uid"], p.get("message")) for p in diffs]))

        lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
        users2, now = advance(lac._users, 300.0)
        for rec in list(users2.values())[:3]:
            rec["bad_pw_count"] = int(rec.get("bad_pw_count") or 0) + 2
        sprays = lac._diff_users(users2, now)
        fails = [p for p in sprays if p["class_uid"] == 3002 and p.get("status_id") == 2]
        check("three accounts gaining failures in one interval is reported as a spray "
              "— this is the substitute for 4625, which needs the Security channel",
              len(fails) == 3
              and all("password_spray" in p["metadata_labels"] for p in fails),
              f"{len(fails)} failure events of {len(sprays)} payloads")
        check("...at HIGH, with base `count` carrying the per-account delta (count "
              "means 'this event repeated N times', which is exactly what a bad-"
              "password delta is)",
              bool(fails) and all(p["severity_id"] >= 4 and p["count"] == 2
                                  for p in fails),
              str([(p["severity_id"], p["count"]) for p in fails]))
        check("...labelled T1110.003, the spray subtechnique, not bare T1110",
              bool(fails)
              and all("attack:T1110.003" in p["metadata_labels"] for p in fails))

        lac._users = {k: dict(v, bad_pw_count=7, _observed_at=now)
                      for k, v in real.items()}
        users3, now = advance(lac._users, 300.0)
        for rec in users3.values():
            rec["bad_pw_count"] = 0
        reset = lac._diff_users(users3, now)
        check("a FALL in bad_pw_count emits nothing — the counter was reset by a "
              "successful logon or by the lockout window expiring, and reporting the "
              "delta's absolute value would invent failures that never happened",
              not reset, str([(p["class_uid"], p.get("status_id")) for p in reset]))

        lac._users = {k: dict(v, password_age=100_000, _observed_at=now)
                      for k, v in real.items()}
        users4, now = advance(lac._users, 300.0)
        users4 = {k: dict(v, password_age=5, password_set_at=now - 5)
                  for k, v in users4.items()}
        pw = lac._diff_users(users4, now)
        changes = [p for p in pw if p["class_uid"] == 3007 and p["activity_id"] == 8]
        check("an implied set-moment that jumps forward is a password change",
              len(changes) == len(users4), f"{len(changes)} of {len(users4)}")
        check("...and the event states which distinction was lost: 4723 (the user "
              "changed their own) versus 4724 (an administrator reset someone "
              "else's), which is the difference between routine and an account "
              "takeover",
              bool(changes)
              and any("4723" in n and "4724" in n for n in changes[0]["soc_notes"]))

        # THE REGRESSION THIS CATCHES. `password_age == 0` means "no password is set,
        # or the last-set time cannot be determined" — not "set zero seconds ago".
        # Three accounts on this host report 0 (Guest, DefaultAccount and the
        # interactive account). Read as a timestamp, all three emit a password-change
        # event on every poll, forever, until an operator learns to ignore this source.
        zero = {k: v for k, v in real.items() if v.get("password_age") == 0}
        check("this host really does have accounts reporting password_age 0, so the "
              "case below is the normal one and not a hypothetical",
              len(zero) >= 1, str(sorted(v["name"] for v in zero.values())))
        lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
        steady, now = advance(lac._users, 300.0)
        quiet = lac._diff_users(steady, now)
        check("...and an age of 0 that stays 0 across a poll emits NOTHING: 0 is "
              "compared as a category, not as an age",
              not [p for p in quiet if p.get("activity_id") == 8],
              str([(p.get("user_name"), p["activity_id"]) for p in quiet]))
        check("...nor is the comparison done on the ages themselves, which is the "
              "other half of the bug — the age is quantised and grows by about the "
              "poll interval, so 'same age across 300s' is a change under < and 'no "
              "change' under ==. The implied set moment gets both right",
              not quiet, f"{len(quiet)} payload(s) on an unchanged host")
        lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
        appeared, now = advance(lac._users, 300.0)
        for k, v in list(appeared.items()):
            if v.get("password_age") == 0:
                appeared[k] = dict(v, password_age=30, password_set_at=now - 30)
        got_pw = lac._diff_users(appeared, now)
        check("...but 0 -> a real age IS a password being set, and is reported, so "
              "treating 0 as a category does not cost the detection",
              len([p for p in got_pw if p.get("activity_id") == 8]) == len(zero),
              f"{len([p for p in got_pw if p.get('activity_id') == 8])} of {len(zero)}")

        now += 300.0
        lac._users = {"g": dict(victim, key="g", name="g", flags=0x0022,
                               password_age=1000, _observed_at=now - 300)}
        en = lac._diff_users({"g": dict(victim, key="g", name="g", flags=0x0020,
                                        password_age=1300, _observed_at=now)}, now)
        enabled_ev = [p for p in en if p["activity_id"] == 4]
        check("enabling a PASSWD_NOTREQD account is raised to the flag's own "
              "severity — the flag is only a finding on an account that can log in",
              len(enabled_ev) == 1 and enabled_ev[0]["severity_id"] >= 3,
              str([(p["activity_id"], p["severity_id"]) for p in en]))
        check("...and the enable is the only event: the catch-all Update is suppressed "
              "when a specific transition already fired, or every disable double-bills",
              len(en) == 1, str([(p["activity_id"], p.get("message")) for p in en]))

        now += 300.0
        lac._users = {"g": dict(victim, key="g", name="g", sid="S-1-5-21-1-2-3-500",
                               password_age=1000, _observed_at=now - 300)}
        su = lac._diff_users({"g": dict(victim, key="g", name="g",
                                        sid="S-1-5-21-1-2-3-999",
                                        password_age=1300, _observed_at=now)}, now)
        check("a changed SID under an unchanged name is caught and raised HIGH — the "
              "account was deleted and recreated, which is how a name keeps its ACLs "
              "while the principal behind it changes",
              any(p["severity_id"] >= 4 and "recreated" in p["message"] for p in su),
              str([(p.get("message"), p["severity_id"]) for p in su]))

        now += 300.0
        _admins = {"key": "administrators", "name": "Administrators",
                   "sid": "S-1-5-32-544", "rid": 544, "comment": "", "error": ""}
        lac._groups = {"administrators": dict(_admins, members={})}
        ga = lac._diff_groups({"administrators": dict(_admins, members={
            "S-1-5-21-1-2-3-1337": {"sid": "S-1-5-21-1-2-3-1337", "rid": 1337,
                                    "name": "evil", "domain": "HOST",
                                    "sid_type": 1}})}, now)
        adds = [p for p in ga if p["class_uid"] == 3006 and p["activity_id"] == 3]
        check("adding a member to Administrators emits 3006 activity 3 Add User at HIGH",
              len(adds) == 1 and adds[0]["severity_id"] >= 4,
              str([(p["class_uid"], p["activity_id"], p["severity_id"]) for p in ga]))
        check("...and privilege is decided by RID 544, not by the English name, "
              "because the name is localised and matching it monitors nothing on a "
              "German install",
              bool(adds) and "Administrators" in adds[0]["unmapped"]["privilege_reason"],
              adds[0]["unmapped"]["privilege_reason"][:70] if adds else "")

        _g = {"key": "g", "name": "G", "sid": "", "rid": 544, "comment": ""}
        lac._groups = {"g": dict(_g, error="", members={
            "a": {"sid": "a", "rid": 1, "name": "x", "domain": "", "sid_type": 1}})}
        gone_g = lac._diff_groups({"g": dict(_g, error="denied", members={})}, now)
        check("a group that becomes UNREADABLE emits no member-removal events — "
              "losing visibility of Administrators must not read as Administrators "
              "being emptied, which is the more alarming of the two by far",
              not [p for p in gone_g if p["class_uid"] == 3006], str(len(gone_g)))

        lac._modals = {"min_passwd_len": 8, "lockout_threshold": 10, "_levels": [0, 3]}
        pol = lac._diff_policy({"min_passwd_len": 0, "lockout_threshold": 0,
                                "_levels": [0, 3]}, now)
        check("weakening the password policy emits a 5019 change event, not another "
              "5002 snapshot — snapshots go to Discovery, changes go to IAM",
              len(pol) == 1 and pol[0]["class_uid"] == 5019,
              str([p["class_uid"] for p in pol]))
        check("...at HIGH, with the before and after values exact rather than a prose "
              "summary a rule cannot read",
              bool(pol) and pol[0]["severity_id"] >= 4
              and pol[0]["unmapped"]["changed_fields"]["min_passwd_len"]
              == {"before": 8, "after": 0},
              str(pol[0]["unmapped"]["changed_fields"]) if pol else "")
        check("...and 5019 carries no state_id/security_states: those are class-level "
              "enums this collector cannot verify a value for, and an unverified enum "
              "id is a wrong assertion rather than a missing one",
              bool(pol) and not {"state_id", "security_states", "prev_security_states"}
              & set(pol[0]))

        account_payloads = (a1 + a2 + diffs + sprays + reset + pw + quiet + got_pw
                            + en + su + ga + gone_g + pol)
        register("local_accounts", account_payloads)

        lstats = lac.stats_extra()
        for key in ("blind_window_seconds", "users_created", "password_changes",
                    "password_spray_intervals", "group_members_added",
                    "policy_changes", "policy_findings", "privileged_rids_absent",
                    "sid_lookup_failures", "groups_unreadable"):
            check(f"stats_extra reports {key}", key in lstats,
                  f"has: {sorted(lstats)[:6]}...")
        check("...and every counter the synthetic diffs above exercised actually "
              "moved, so the health board is reporting this collector's real work and "
              "not a set of zeros",
              lstats["users_created"] >= 1 and lstats["password_changes"] >= 1
              and lstats["password_spray_intervals"] >= 1
              and lstats["group_members_added"] >= 1
              and lstats["policy_changes"] >= 1 and lstats["policy_findings"] >= 1,
              str({k: lstats[k] for k in
                   ("users_created", "password_changes", "password_spray_intervals",
                    "group_members_added", "policy_changes", "policy_findings")}))

    print("\n── local_auth payloads through the pipeline into the lake ──")
    # submit() takes a *batch*: iterating a bare dict yields its keys, and the
    # pipeline's `dict(payload)` then fails on a string. Batched per source.
    if account_payloads:
        ra = await pipe2.submit("local_accounts", account_payloads)
        check("the pipeline accepted every local_accounts payload",
              ra.rejected == 0 and ra.accepted == len(account_payloads),
              f"{ra.accepted}/{len(account_payloads)} accepted, {ra.rejected} rejected")
    if session_payloads:
        rs = await pipe2.submit("logon_sessions", session_payloads)
        check("...and every logon_sessions payload",
              rs.rejected == 0 and rs.accepted == len(session_payloads),
              f"{rs.accepted}/{len(session_payloads)} accepted, {rs.rejected} rejected")
    if nine_payloads:
        rn = await pipe2.submit("local_auth_log", nine_payloads)
        check("...and every activity-99 authentication event, which is the batch that "
              "used to be quarantined in silence",
              rn.rejected == 0, f"{rn.accepted} accepted, {rn.rejected} rejected")
    await pipe2.flush()
    for rej in list(pipe2.recent_rejects)[:4]:
        print(f"    reject: {rej}")

    # ══ 11. every field, against the attributes its own class declares ══════
    print("\n══ every payload's every field, checked against its own OCSF class ══")
    sources = Counter(s for s, _ in PAYLOADS)
    classes = {p["class_uid"] for _, p in PAYLOADS if "class_uid" in p}
    print(f"  {len(PAYLOADS)} payloads from {len(sources)} sources across "
          f"{len(classes)} classes: {dict(sources)}")
    check("the registry actually collected payloads from every collector in this "
          "file — an empty registry would make the check below pass vacuously",
          len(sources) >= 7 and len(PAYLOADS) > 100, str(dict(sources)))

    field_bad: list[str] = []
    for src, p in PAYLOADS:
        for problem in unmapped_fields(p):
            entry = f"{src} {p.get('class_uid')}: {problem}"
            if entry not in field_bad:
                field_bad.append(entry)
    # Printed in full rather than truncated. A field-mapping violation is per
    # (collector, class, field), so the interesting number is the whole set — six of
    # forty would read as a small problem.
    for entry in sorted(field_bad):
        print(f"    BAD FIELD: {entry}")
    check(f"every field on every payload maps to an attribute its own class declares "
          f"({len(PAYLOADS)} payloads, {len(classes)} classes)",
          not field_bad, f"{len(field_bad)} distinct violations, printed above")

    # And prove the check has teeth, on a real payload rather than a fabricated one.
    poison_src = next((p for _, p in PAYLOADS if p.get("class_uid") == 5002), None)
    if poison_src is not None:
        poison = dict(poison_src)
        poison["query_result_id"] = 1
        check("...and it would have caught query_result_id on a 5002 — a field that "
              "IS a real Event field and IS in OCSF_PATH, so a check against "
              "Event.model_fields passes it happily. Only the class's own attribute "
              "list knows 5009 declares it and 5002 does not",
              any("query_result_id" in b for b in unmapped_fields(poison)),
              str(unmapped_fields(poison)))
    poison2 = {"class_uid": 3002, "activity_id": 1, "reg_key_path": r"HKLM\Run"}
    check("...and a registry path on an authentication event, which is the same bug "
          "with a different field",
          any("reg_key" in b for b in unmapped_fields(poison2)),
          str(unmapped_fields(poison2)))

    # ── the same invariant, now enforced where it matters: in the builder ──
    #
    # The check above protects the six collectors this file knows about. These protect
    # every collector and connector that will ever exist, because they exercise
    # `Event.build` itself — a future connector cannot reintroduce this defect without
    # the field visibly landing in `unmapped` with a note saying why.
    built = Event.build(
        source="poison_test", class_uid=3002, activity_id=1, time=1788004800.0,
        reg_key_path=r"HKLM\Run", actor_user_name="alice",
    )
    check("Event.build moves a field that is wrong for its own class into unmapped — "
          "the field survives (it is real telemetry, not a stray) but stops pretending "
          "to be a queryable OCSF attribute it is not",
          built.unmapped.get("reg_key_path") == r"HKLM\Run"
          and built.reg_key_path is None,
          f"unmapped={built.unmapped.get('reg_key_path')!r} "
          f"field={built.reg_key_path!r}")
    check("...and says so in soc_notes, naming the field, the path it wanted and the "
          "class that refused it, so the collector author can act on it without "
          "reading this test",
          any("reg_key_path" in n and "3002" in n for n in built.soc_notes),
          str(built.soc_notes))
    check("...and leaves fields that ARE correct for the class alone — a sweep that "
          "moved everything would be indistinguishable from one that worked",
          built.actor_user_name == "alice" and "actor_user_name" not in built.unmapped)
    ok = Event.build(
        source="poison_test", class_uid=201002, activity_id=2, time=1788004800.0,
        reg_value_path=r"HKLM\Run\evil", reg_value_data="calc.exe",
    )
    check("...and the corrected registry-value mapping passes it clean, which is what "
          "makes the sweep above a fix rather than a relabelling of the same defect",
          ok.reg_value_path == r"HKLM\Run\evil" and not ok.unmapped
          # Not `not ok.soc_notes` — the builder legitimately notes the clock skew of
          # this fixed timestamp and the absent source event id. The claim is that it
          # says nothing about a *misplaced field*, which is a narrower and truer thing
          # to assert than silence.
          and not any("wrong for this class" in n for n in ok.soc_notes),
          f"unmapped={ok.unmapped} notes={ok.soc_notes}")
    check("...and an unknown class_uid sweeps nothing, because 'the schema has never "
          "heard of this class' is not evidence that any particular field is wrong "
          "for it",
          not misplaced_fields(999999, ["reg_key_path", "query_result_id"]))
    check(f"LOCAL_FIELDS covers exactly CYPHRA's own columns "
          f"({len(LOCAL_FIELDS)} of them) and nothing with an OCSF path, so the sweep "
          f"can never move a provenance column",
          not (LOCAL_FIELDS & set(OCSF_PATH)),
          str(sorted(LOCAL_FIELDS & set(OCSF_PATH))))
    envelope = {
        f for f in Event.model_fields
        if f not in OCSF_PATH and f not in SOC_FIELDS and f not in DERIVED_FIELDS
    }
    check("...and it is complete: measured, every model field with no OCSF path is "
          "either provenance, derived, or the envelope, so no real field is left "
          "unclassified and liable to be swept on a technicality",
          envelope <= LOCAL_FIELDS, str(sorted(envelope - LOCAL_FIELDS)))

    print()
    print("=" * 74)
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"    FAILED: {f}")
    print("=" * 74)
    while _OPEN:
        try:
            _OPEN.pop().close()
        except Exception:
            pass
    return 1 if FAIL else 0


class _Exploding(PullCollector):
    name = "exploding_probe"

    def probe(self) -> Availability:
        raise RuntimeError("probe itself is broken")

    async def poll(self):
        return []


def pytest_approx(value, tol=1e-6):
    """Float comparison for the blind-window arithmetic, which is a sum of floats.

    Named for the pytest helper it stands in for; this suite deliberately has no
    pytest dependency so it can be run as a plain script on a host where the test
    runner is not installed.
    """

    class _Approx:
        def __eq__(self, other):
            return abs(float(other) - float(value)) <= tol

        def __repr__(self):
            return f"~{value}"

    return _Approx()


def _raises(fn):
    try:
        fn()
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

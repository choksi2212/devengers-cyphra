"""Sysmon collector — the highest-value local telemetry Windows can produce.

Sysmon is a separate driver-backed service, not part of Windows. It writes to
``Microsoft-Windows-Sysmon/Operational``, which is an ordinary Event Log channel,
so this collector is :class:`~ingest.collectors.windows_eventlog.WindowsEventLogCollector`
with different tables: same bookmark cursor, same per-channel probing, same
skip-and-count on a poison record. Only the meaning changes.

**Why it matters enough to be its own module.** Measured earlier against the
vendored ATT&CK bundle: ``WinEventLog:Sysmon:EventCode=1`` is the named log source
for 264 of the 697 techniques with detection guidance, and installing Sysmon moves
182 techniques out of the out-of-reach set. Nothing else available on a Windows
host comes close. Native 4688 process auditing carries the command line only if a
separate policy is enabled and never carries hashes, parent GUIDs, image-load
events, DNS queries, or named-pipe activity.

**Three things this does that the base collector does not.**

*Hashes are split into their own fields.* Sysmon packs them into one string —
``SHA1=…,MD5=…,SHA256=…,IMPHASH=…``. Left packed, the single most useful IOC on the
event is not joinable against an intel feed without a LIKE scan over every row.

*Direction is read, not inferred.* Event 3 carries ``Initiated``, which is the
kernel's own answer to who opened the connection.
:mod:`ingest.collectors.network_flow` has to guess this from RFC1918 membership and
port privilege; here it is a fact, and it is recorded as one.

*Registry and file events read their sub-type.* Sysmon multiplexes four registry
operations onto event 12/13/14 and distinguishes them with an ``EventType`` field.
Mapping the event id to a constant activity would make a key deletion and a key
creation the same event.

**Time comes from Sysmon, not from the Event Log service.** ``UtcTime`` is when the
driver observed the operation; ``TimeCreated`` is when the log service got round to
writing the record. They differ by milliseconds normally and by much more under
load, and the driver's value is the one a sub-second process tree ordering needs.
``TimeCreated`` is kept in ``unmapped`` so the gap is measurable.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import Availability, unavailable
from ingest.collectors.windows_eventlog import (
    Channel,
    WindowsEventLogCollector,
    _Mapped,
    _iso_to_epoch,
)

#: The channel Sysmon creates when it installs. Absent until then — measured on
#: this host as ``ERROR_EVT_CHANNEL_NOT_FOUND (15007)``.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

_FILE = int(ClassUid.FILE_SYSTEM_ACTIVITY)
_PROC = int(ClassUid.PROCESS_ACTIVITY)
_MOD = int(ClassUid.MODULE_ACTIVITY)
_NET = int(ClassUid.NETWORK_ACTIVITY)
_DNS = int(ClassUid.DNS_ACTIVITY)
_REGK = int(ClassUid.REGISTRY_KEY_ACTIVITY)
_REGV = int(ClassUid.REGISTRY_VALUE_ACTIVITY)
_WINRES = int(ClassUid.WINDOWS_RESOURCE_ACTIVITY)
_SVC = int(ClassUid.WINDOWS_SERVICE_ACTIVITY)

_SUCCESS, _FAILURE = 1, 2

#: Sysmon's registry ``EventType`` → ``win/registry_key_activity`` activity
#: (1 Create, 2 Read, 3 Modify, 4 Delete, 5 Rename).
_REG_KEY_ACTIVITY = {
    "createkey": 1,
    "deletekey": 4,
    "renamekey": 5,
    "setvalue": 3,
    "deletevalue": 4,
}

#: ``win/registry_value_activity`` activity (1 Get, 2 Set, 3 Modify, 4 Delete).
_REG_VALUE_ACTIVITY = {
    "setvalue": 2,
    "deletevalue": 4,
    "renamevalue": 3,
    "createvalue": 2,
}


def _reg_key_activity(data: dict[str, str]) -> int | None:
    return _REG_KEY_ACTIVITY.get((data.get("EventType") or "").strip().lower())


def _reg_value_activity(data: dict[str, str]) -> int | None:
    return _REG_VALUE_ACTIVITY.get((data.get("EventType") or "").strip().lower())


#: Sysmon event id → OCSF class and activity.
#:
#: Every id Sysmon 15.x emits is here, including the ones that are pure operational
#: noise (4, 16, 255), because an id missing from this table lands in ``unmapped``
#: and an operator reading the report cannot tell "Sysmon is emitting something new"
#: from "we never bothered to map it". The activity ids are validated against the
#: vendored OCSF schema by ``tests/scratch_collectors.py`` — see the note on
#: :data:`ingest.collectors.windows_eventlog.EVENT_MAP` for why that test is not
#: optional.
SYSMON_MAP: dict[int, _Mapped] = {
    1: _Mapped(_PROC, 1, "Process created", status_id=_SUCCESS),
    2: _Mapped(_FILE, 6, "File creation time changed", status_id=_SUCCESS,
               severity_id=int(Severity.LOW)),
    3: _Mapped(_NET, 1, "Network connection", status_id=_SUCCESS),
    4: _Mapped(_SVC, 2, "Sysmon service state changed", status_id=_SUCCESS,
               severity_id=int(Severity.LOW)),
    5: _Mapped(_PROC, 2, "Process terminated", status_id=_SUCCESS),
    6: _Mapped(_MOD, 1, "Driver loaded", status_id=_SUCCESS,
               severity_id=int(Severity.LOW)),
    7: _Mapped(_MOD, 1, "Image loaded", status_id=_SUCCESS),
    # 1007 activity 4 is Inject. CreateRemoteThread is the canonical injection
    # primitive, so this is the one place the OCSF enum says exactly the right thing.
    8: _Mapped(_PROC, 4, "CreateRemoteThread", status_id=_SUCCESS,
               severity_id=int(Severity.MEDIUM)),
    9: _Mapped(_FILE, 2, "Raw access read", status_id=_SUCCESS,
               severity_id=int(Severity.MEDIUM)),
    10: _Mapped(_PROC, 3, "Process accessed", status_id=_SUCCESS),
    11: _Mapped(_FILE, 1, "File created", status_id=_SUCCESS),
    12: _Mapped(_REGK, 1, "Registry key created or deleted", status_id=_SUCCESS,
                activity_from=_reg_key_activity),
    13: _Mapped(_REGV, 2, "Registry value set", status_id=_SUCCESS,
                activity_from=_reg_value_activity),
    14: _Mapped(_REGK, 5, "Registry key or value renamed", status_id=_SUCCESS,
                activity_from=_reg_key_activity),
    15: _Mapped(_FILE, 1, "File stream created", status_id=_SUCCESS,
                severity_id=int(Severity.LOW)),
    16: _Mapped(_SVC, 2, "Sysmon configuration changed", status_id=_SUCCESS,
                severity_id=int(Severity.HIGH)),
    # A named pipe is an object in the file namespace (\\.\pipe\…), which is both
    # how Windows models it and how every Sysmon rule matches it. 201003's only
    # activity is Access, which would lose the create/connect distinction, so
    # file_activity's Create and Open carry it instead.
    17: _Mapped(_FILE, 1, "Named pipe created", status_id=_SUCCESS),
    18: _Mapped(_FILE, 14, "Named pipe connected", status_id=_SUCCESS),
    19: _Mapped(_WINRES, 99, "WMI event filter registered", status_id=_SUCCESS,
                severity_id=int(Severity.MEDIUM)),
    20: _Mapped(_WINRES, 99, "WMI event consumer registered", status_id=_SUCCESS,
                severity_id=int(Severity.MEDIUM)),
    21: _Mapped(_WINRES, 99, "WMI consumer bound to filter", status_id=_SUCCESS,
                severity_id=int(Severity.HIGH)),
    22: _Mapped(_DNS, 1, "DNS query", status_id=_SUCCESS),
    23: _Mapped(_FILE, 4, "File deleted and archived", status_id=_SUCCESS,
                severity_id=int(Severity.LOW)),
    24: _Mapped(_WINRES, 1, "Clipboard changed", status_id=_SUCCESS),
    25: _Mapped(_PROC, 99, "Process tampering (image replaced)", status_id=_SUCCESS,
                severity_id=int(Severity.HIGH)),
    26: _Mapped(_FILE, 4, "File deleted", status_id=_SUCCESS),
    27: _Mapped(_FILE, 1, "Executable file block", status_id=_FAILURE,
                severity_id=int(Severity.HIGH)),
    28: _Mapped(_FILE, 4, "File shredding block", status_id=_FAILURE,
                severity_id=int(Severity.HIGH)),
    29: _Mapped(_FILE, 1, "Executable file detected", status_id=_SUCCESS,
                severity_id=int(Severity.LOW)),
    255: _Mapped(_WINRES, 99, "Sysmon internal error", status_id=_FAILURE,
                 severity_id=int(Severity.MEDIUM)),
}

#: Sysmon ``EventData`` names → flat OCSF fields.
#:
#: Sysmon's subject/object convention is Source/Target, and it is consistent, which
#: is why the actor/affected split survives the mapping: in event 10 the
#: ``SourceImage`` opened the ``TargetImage``, so a rule for "lsass.exe was opened
#: by something that is not a known agent" reads ``process_file_path`` for the
#: victim and ``actor_process_file_path`` for the opener, in that order, without
#: having to know it came from Sysmon.
SYSMON_DATA_MAP: dict[str, str] = {
    # process creation (1) and termination (5)
    "Image": "process_file_path",
    "OriginalFileName": "process_file_name",
    "CommandLine": "process_cmd_line",
    "CurrentDirectory": "process_working_directory",
    "ProcessId": "process_pid",
    "ProcessGuid": "process_uid",
    "User": "actor_user_name",
    "LogonId": "actor_session_uid",
    "IntegrityLevel": "process_integrity_id",
    "Company": "process_file_company_name",
    "ParentImage": "actor_process_file_path",
    "ParentCommandLine": "actor_process_cmd_line",
    "ParentProcessId": "actor_process_pid",
    "ParentProcessGuid": "actor_process_uid",
    "ParentUser": "actor_user_name",
    # network connection (3) — Sysmon's Source is always the local end
    "SourceIp": "src_endpoint_ip",
    "SourcePort": "src_endpoint_port",
    "SourceHostname": "src_endpoint_hostname",
    "DestinationIp": "dst_endpoint_ip",
    "DestinationPort": "dst_endpoint_port",
    "DestinationHostname": "dst_endpoint_hostname",
    "DestinationPortName": "dst_endpoint_svc_name",
    "Protocol": "connection_protocol_name",
    # file events (2, 11, 15, 23, 26, 27, 28, 29)
    "TargetFilename": "file_path",
    # image / driver load (6, 7)
    "ImageLoaded": "module_file_path",
    # registry (12, 13, 14)
    "TargetObject": "reg_key_path",
    "Details": "reg_value_data",
    # DNS (22)
    "QueryName": "dns_query_hostname",
    # named pipe (17, 18) — the pipe name is the file path in the pipe namespace
    "PipeName": "file_path",
    # cross-process access (8, 10) — Source acts on Target
    "SourceImage": "actor_process_file_path",
    "SourceProcessId": "actor_process_pid",
    "SourceProcessGUID": "actor_process_uid",
    "SourceProcessGuid": "actor_process_uid",
    "TargetImage": "process_file_path",
    "TargetProcessId": "process_pid",
    "TargetProcessGUID": "process_uid",
    "TargetProcessGuid": "process_uid",
    # WMI persistence (19, 20, 21)
    "Query": "process_cmd_line",
    "Destination": "process_cmd_line",
    # Sysmon's own rule name — the closest thing Sysmon has to a detection name,
    # and what a tuning conversation is actually about.
    "RuleName": "metadata_correlation_uid",
}

#: The subject fields, rewritten to the actor for every class that has no subject
#: process. See :attr:`WindowsEventLogCollector.data_map_by_class`.
#:
#: :data:`SYSMON_DATA_MAP` is one flat table shared by all 29 event ids, and its
#: process entries are written for event 1, where ``Image`` really is the thing that
#: happened. On a network connection, image load, file write, registry set or DNS
#: query, ``Image`` is the process that *did* it — the actor — and the affected object
#: is the connection, module, file, key or name. Measured against the vendored OCSF
#: schema: of the nine classes :data:`SYSMON_MAP` routes to, exactly one (1007 Process
#: Activity) declares a top-level ``process``, and all nine declare ``actor``. So on
#: the other eight, ``process_pid`` and its siblings had no attribute to land in;
#: every such event built, validated and persisted, and a rule reading
#: ``actor.process.pid`` — the correct place, and the place
#: :data:`SYSMON_DATA_MAP` itself already writes ``ParentProcessId`` to — found
#: nothing.
#:
#: Every ``process_*`` entry in :data:`SYSMON_DATA_MAP` is rewritten here, not only
#: the ones that happen to appear on a non-1007 event today. ``CommandLine``,
#: ``CurrentDirectory``, ``IntegrityLevel`` and ``Company`` are currently emitted only
#: on event 1, but a table that fixes six of ten entries is a table that will be
#: wrong again the first time Sysmon adds a field to an existing event.
_ACTOR_SUBJECT_MAP: dict[str, str] = {
    "Image": "actor_process_file_path",
    "OriginalFileName": "actor_process_file_name",
    "CommandLine": "actor_process_cmd_line",
    "CurrentDirectory": "actor_process_working_directory",
    "ProcessId": "actor_process_pid",
    "ProcessGuid": "actor_process_uid",
    "IntegrityLevel": "actor_process_integrity_id",
    "Company": "actor_process_file_company_name",
}

#: The one class whose subject genuinely is a process, so the one class
#: :data:`SYSMON_DATA_MAP` is already correct for.
_SUBJECT_PROCESS_CLASSES = frozenset({_PROC})

#: Class → data-map override. Derived from :data:`SYSMON_MAP` rather than listed, so
#: mapping a new event id to a new class cannot forget to add it.
SYSMON_DATA_MAP_BY_CLASS: dict[int, dict[str, str]] = {
    m.class_uid: _ACTOR_SUBJECT_MAP
    for m in SYSMON_MAP.values()
    if m.class_uid not in _SUBJECT_PROCESS_CLASSES
}

# Registry value events put a *value* path in TargetObject, not a key path. 201002
# Registry Value Activity declares `reg_value` and no `reg_key`; 201001 Registry Key
# Activity declares `reg_key` and no `reg_value`. Sysmon uses the one field name for
# both — event 12/14 name a key, event 13 names the value being written — so the
# shared entry was putting a key path on a class with nowhere to put it, which is the
# same failure as the process fields above and on the single highest-volume
# persistence-detection source Sysmon has.
SYSMON_DATA_MAP_BY_CLASS[_REGV] = {
    **_ACTOR_SUBJECT_MAP,
    "TargetObject": "reg_value_path",
}

#: Sysmon ``Hashes`` algorithm names → flat fields. IMPHASH and SHA512 have no
#: field of their own and stay in ``unmapped`` rather than being dropped: IMPHASH
#: in particular is what clusters repacked samples of the same malware family.
_HASH_FIELDS = {
    "SHA256": "process_file_sha256",
    "MD5": "process_file_md5",
    "SHA1": "process_file_sha1",
}

#: The same, for a class with no subject process — currently unreachable in practice
#: (event 1 is the only id that both carries ``Hashes`` and falls through to the
#: default table) but present so that the fallback cannot become the one path that
#: still writes ``process_file_sha256`` onto a class that declares no ``process``.
_ACTOR_HASH_FIELDS = {
    "SHA256": "actor_process_file_sha256",
    "MD5": "actor_process_file_md5",
    "SHA1": "actor_process_file_sha1",
}

#: For events whose subject is a *loaded module* rather than the process image, the
#: hashes describe the module. Mapping them to ``process_file_*`` would attribute a
#: malicious DLL's hash to the innocent host process that loaded it — and that is
#: exactly backwards for the technique (T1574 hijacking) the event exists to catch.
_MODULE_HASH_EVENTS = frozenset({6, 7})
_MODULE_HASH_FIELDS = {"SHA256": "module_file_sha256"}

#: Events whose hashes describe a file on disk, not a running image.
_FILE_HASH_EVENTS = frozenset({15, 23, 27, 28, 29})
_FILE_HASH_FIELDS = {"SHA256": "file_sha256", "MD5": "file_md5"}

#: Windows integrity levels → OCSF ``process.integrity_id``
#: (1 Untrusted, 2 Low, 3 Medium, 4 High, 5 System).
_INTEGRITY = {
    "untrusted": 1,
    "low": 2,
    "medium": 3,
    "mediumplus": 3,
    "high": 4,
    "system": 5,
    "appcontainer": 2,
}


def parse_hashes(packed: str) -> dict[str, str]:
    """``SHA1=AA,MD5=BB,SHA256=CC,IMPHASH=DD`` → ``{"SHA1": "AA", …}``.

    Tolerates Sysmon's other form, a bare hash with no algorithm prefix, which
    older configurations produce when ``HashAlgorithms`` names a single algorithm.
    Length identifies it unambiguously, and guessing from length is safe here in a
    way it would not be for arbitrary input: these are hex digests of known
    algorithms or they are nothing.

    Digests come back **lower-case**, which is the one thing about this function
    that is not a matter of taste. Sysmon writes them upper-case; the event schema
    lower-cases every digest it validates (``_validate_sha256`` and its siblings in
    ``core/schema/ocsf.py``). Whichever case this function picked, the mapped fields
    would end up lower-case — but ``unmapped["hashes"]`` is *not* validated, so
    upper-casing here stored the same digest twice in two different cases within one
    event. Every intel feed publishes lower-case hex, so a hunt joining on the
    unmapped copy — the only copy that carries IMPHASH, which is what clusters
    repacked samples of one malware family — would match nothing and report a clean
    result. Lower-casing at the parser is what makes the two copies agree.
    """
    out: dict[str, str] = {}
    text = (packed or "").strip()
    if not text:
        return out
    if "=" not in text:
        by_len = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        algo = by_len.get(len(text))
        if algo:
            out[algo] = text.lower()
        return out
    for part in text.split(","):
        if "=" not in part:
            continue
        algo, _, value = part.partition("=")
        # The algorithm *name* stays upper-case: it is a dictionary key matched
        # against _HASH_FIELDS, not a value anything joins on.
        algo = algo.strip().upper()
        value = value.strip()
        if algo and value:
            out[algo] = value.lower()
    return out


#: How long a snapshot of this host's own addresses is trusted. Short, because the
#: set is not static: a DHCP renewal onto a different subnet, a VPN connect, or a
#: docker bridge coming up all add or remove addresses, and a stale set makes the
#: inbound-endpoint decision below wrong in exactly the direction that matters —
#: it would stop recognising the host's own new address as local and start
#: reporting the host itself as the remote initiator of its own inbound
#: connections.
_LOCAL_ADDR_TTL = 60.0

_local_addr_lock = threading.Lock()
_local_addrs: frozenset[str] = frozenset()
_local_addrs_at = 0.0
_local_addrs_error = ""


def local_addresses(now: float | None = None) -> frozenset[str]:
    """Every IP address configured on this host, TTL-cached.

    Lower-cased and stripped of the IPv6 scope suffix, because Windows reports
    link-local addresses as ``fe80::1%12`` while Sysmon writes ``fe80::1`` — and a
    comparison that missed on the ``%12`` would fail silently, which is the whole
    class of bug this module keeps having to avoid.

    Returns an empty set if the address list could not be read at all; callers must
    treat empty as *unknown*, not as "no local addresses". :func:`local_address_error`
    carries the reason so it can be reported rather than inferred.
    """
    global _local_addrs, _local_addrs_at, _local_addrs_error
    stamp = time.time() if now is None else now
    with _local_addr_lock:
        if _local_addrs and (stamp - _local_addrs_at) < _LOCAL_ADDR_TTL:
            return _local_addrs
        found: set[str] = set()
        error = ""
        try:
            import ipaddress

            import psutil

            for addrs in psutil.net_if_addrs().values():
                for addr in addrs:
                    raw = getattr(addr, "address", None)
                    if not isinstance(raw, str):
                        continue
                    # MAC addresses arrive through the same structure (AF_LINK), and
                    # on Linux they are colon-separated hex — indistinguishable from
                    # an IPv6 address by any cheap string test. Parsing is the only
                    # correct filter, and at once per TTL the cost does not matter.
                    text = raw.split("%", 1)[0].strip()
                    try:
                        ipaddress.ip_address(text)
                    except ValueError:
                        continue
                    found.add(text.lower())
        except Exception as exc:  # pragma: no cover - psutil is a hard dependency
            error = f"{type(exc).__name__}: {exc}"
        if not found:
            # Fallback: whatever the resolver knows about our own name. Weaker than
            # psutil (it misses addresses with no DNS entry) but better than an
            # empty set, which would disable the decision entirely.
            try:
                import socket

                host = socket.gethostname()
                for info in socket.getaddrinfo(host, None):
                    found.add(str(info[4][0]).split("%", 1)[0].strip().lower())
            except Exception as exc:
                error = error or f"{type(exc).__name__}: {exc}"
        if found:
            # Loopback is always local whether or not an adapter reported it.
            found.update({"127.0.0.1", "::1"})
            _local_addrs = frozenset(found)
            _local_addrs_at = stamp
            _local_addrs_error = ""
        else:
            _local_addrs_error = error or "no addresses reported by psutil or the resolver"
        return _local_addrs


def local_address_error() -> str:
    """Why :func:`local_addresses` came back empty, or ``""`` if it did not."""
    return _local_addrs_error


def _swap_endpoints(payload: dict[str, Any]) -> None:
    """Exchange the src and dst endpoint fields in place.

    Pairwise rather than field-by-field, and it moves ``None`` along with the rest:
    if the source had a hostname and the destination did not, the swapped event must
    have the hostname on the destination and *nothing* on the source. Leaving the
    old source hostname in place would attach the initiator's name to the wrong end,
    which is worse than having no name at all.
    """
    for a, b in (
        ("src_endpoint_ip", "dst_endpoint_ip"),
        ("src_endpoint_port", "dst_endpoint_port"),
        ("src_endpoint_hostname", "dst_endpoint_hostname"),
    ):
        av, bv = payload.get(a), payload.get(b)
        if av is None and bv is None:
            continue
        for key, value in ((a, bv), (b, av)):
            if value is None:
                payload.pop(key, None)
            else:
                payload[key] = value


class SysmonCollector(WindowsEventLogCollector):
    """Process, network, image-load, registry, DNS and pipe telemetry from Sysmon."""

    name = "sysmon"
    # Faster than the base collector's 30s. Sysmon is the source a process-tree
    # investigation walks, and a 30-second cursor means the tree for a launch that
    # happened 29 seconds ago is not there yet when the triage layer asks for it.
    cadence_seconds = 15.0
    critical = True
    description = (
        "Sysmon via the Evt* API — process creation with hashes and full command "
        "lines, network connections with authoritative direction, image loads, "
        "registry, DNS queries, named pipes, CreateRemoteThread"
    )
    event_map = SYSMON_MAP
    data_map = SYSMON_DATA_MAP
    data_map_by_class = SYSMON_DATA_MAP_BY_CLASS

    def __init__(self, pipeline: Any, **kwargs: Any) -> None:
        kwargs.setdefault(
            "channels",
            [Channel(SYSMON_CHANNEL, int(ClassUid.WINDOWS_RESOURCE_ACTIVITY),
                     critical=True)],
        )
        super().__init__(pipeline, **kwargs)

    def probe(self) -> Availability:
        """Sysmon absent is a precondition, not a failure — say how to fix it.

        The base probe would report "no Event Log channel is readable", which is
        true and useless. The distinction that matters is that this is the one gap
        the operator can close with a five-minute install, and the reason string is
        where that gets said.
        """
        base = super().probe()
        if base:
            return base
        ch = self.channels[0]
        why = ch.why_unavailable or base.reason
        if "does not exist" in why or "15007" in why:
            return unavailable(SYSMON_SETUP)
        return unavailable(f"Sysmon channel unavailable — {why}")

    # ── mapping ────────────────────────────────────────────────────────────

    def _to_event(self, ch: Channel, xml: str) -> dict[str, Any]:
        payload = super()._to_event(ch, xml)
        data: dict[str, Any] = dict(payload.get("unmapped", {}).get("event_data") or {})
        eid = payload.get("unmapped", {}).get("event_id")

        # Sysmon's own observation time, in preference to the log service's write
        # time. The base class already set `time` from TimeCreated; both are kept so
        # the difference between them is measurable rather than assumed small.
        utc = _sysmon_time(data.get("UtcTime", ""))
        if utc is not None:
            payload["unmapped"]["time_created_epoch"] = payload.get("time")
            payload["time"] = utc

        hashes = parse_hashes(data.get("Hashes") or data.get("Hash") or "")
        if hashes:
            # Which object the hashes describe is a property of the class, exactly as
            # with the data map. The module and file branches were already class-
            # correct by construction (their event-id sets are all `_MOD` and `_FILE`
            # ids); the default branch was not, so it is resolved the same way the
            # data map is rather than by trusting that no future id both carries
            # `Hashes` and lands on a class with no subject process.
            if eid in _MODULE_HASH_EVENTS:
                fields = _MODULE_HASH_FIELDS
            elif eid in _FILE_HASH_EVENTS:
                fields = _FILE_HASH_FIELDS
            elif payload.get("class_uid") in _SUBJECT_PROCESS_CLASSES:
                fields = _HASH_FIELDS
            else:
                fields = _ACTOR_HASH_FIELDS
            for algo, field in fields.items():
                if algo in hashes:
                    payload[field] = hashes[algo]
            payload["unmapped"]["hashes"] = hashes

        # Direction, from the kernel rather than from a heuristic. `Initiated=true`
        # means the local process opened the connection.
        initiated = (data.get("Initiated") or "").strip().lower()
        if initiated in ("true", "false"):
            outbound = initiated == "true"
            payload["connection_direction_id"] = 2 if outbound else 1
            if not outbound:
                # OCSF's src_endpoint means *the initiator*. Whether Sysmon's
                # Source already is the initiator on an inbound connection is
                # genuinely ambiguous — the documentation says Source/Destination
                # follow the connection's establishment direction, community
                # reports disagree, and Sysmon is not installed on this host, so it
                # cannot be measured here.
                #
                # Rather than pick a side and be wrong half the time, this decides
                # from the record itself: if the address Sysmon called Source is one
                # of *this host's own* addresses, then Sysmon labelled local-as-
                # source and the ends need swapping; if it is not, Sysmon already
                # had the initiator in Source and swapping would break it. Both
                # readings are then correct, and the choice is recorded in the notes
                # so it is auditable per event rather than assumed globally.
                src = payload.get("src_endpoint_ip")
                local = local_addresses()
                if not local:
                    payload.setdefault("soc_notes", []).append(
                        "inbound connection; endpoints left as Sysmon reported them "
                        "because this host's own addresses could not be determined "
                        f"({local_address_error()}) — direction_id is from the "
                        "kernel and is correct, but which end OCSF should call "
                        "src_endpoint is undecided for this event"
                    )
                elif src and str(src).strip().lower() in local:
                    _swap_endpoints(payload)
                    payload.setdefault("soc_notes", []).append(
                        "endpoints swapped: Initiated=false and Sysmon's SourceIp "
                        f"{src} is an address of this host, so the remote end is "
                        "the initiator and OCSF's src_endpoint is it"
                    )
                else:
                    payload.setdefault("soc_notes", []).append(
                        f"inbound connection; Sysmon's SourceIp {src} is not an "
                        "address of this host, so it is already the remote "
                        "initiator and the endpoints are left as reported"
                    )

        level = (data.get("IntegrityLevel") or "").strip().lower()
        if level:
            # Resolved onto whichever field the data map chose for this class, not
            # onto `process_integrity_id` unconditionally — writing the flat name here
            # would put the field back on a class that declares no `process` and undo
            # the override for the one attribute that goes through a lookup table.
            integrity_field = self.data_map_by_class.get(
                payload.get("class_uid"), self.data_map
            ).get("IntegrityLevel", "process_integrity_id")
            resolved = _INTEGRITY.get(level)
            if resolved is None:
                payload.pop(integrity_field, None)
            else:
                payload[integrity_field] = resolved

        proto = (payload.get("connection_protocol_name") or "").strip().lower()
        if proto:
            payload["connection_protocol_name"] = proto
            payload["connection_protocol_num"] = {"tcp": 6, "udp": 17,
                                                  "icmp": 1}.get(proto)
            if payload["connection_protocol_num"] is None:
                payload.pop("connection_protocol_num")

        for f in ("process_pid", "actor_process_pid", "src_endpoint_port",
                  "dst_endpoint_port"):
            if f in payload and not isinstance(payload[f], int):
                try:
                    payload[f] = int(str(payload[f]).strip())
                except (TypeError, ValueError):
                    payload.pop(f)

        # DNS answers are a list in one string: "type: 5 …;type: 1 1.2.3.4;".
        answers = _dns_answers(data.get("QueryResults", ""))
        if answers:
            payload["dns_answer_count"] = len(answers)
            payload["unmapped"]["dns_answers"] = answers
        status = (data.get("QueryStatus") or "").strip()
        if status:
            # Sysmon's QueryStatus is a Win32 error, not a DNS RCODE, so it does not
            # go in `dns_rcode_id`. 0 is success; 9003 (DNS_ERROR_RCODE_NAME_ERROR)
            # is NXDOMAIN, which is the one an algorithmically-generated-domain hunt
            # counts.
            payload["status_id"] = 1 if status == "0" else 2
            payload["status_code"] = status
            if status == "9003":
                payload["dns_rcode_id"] = 3  # NXDomain
        return payload


def _sysmon_time(value: str) -> float | None:
    """``2026-08-28 19:04:45.944`` → epoch seconds, UTC.

    Sysmon writes a space separator and no zone marker. The value is documented as
    UTC and the field is literally named ``UtcTime``, so it is read as UTC rather
    than as local — reading it as local would shift every process-creation event by
    the host's offset, which on a machine several hours from UTC puts the parent
    process after its own child.
    """
    text = (value or "").strip()
    if not text:
        return None
    return _iso_to_epoch(text.replace(" ", "T"))


def _dns_answers(value: str) -> list[str]:
    out = []
    for part in (value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        # "type:  5 cdn.example.net" — the answer is the last whitespace-separated
        # token; the type prefix is kept out because it is Sysmon's own numbering.
        out.append(part.split()[-1] if " " in part else part)
    return out


#: The instruction handed to the operator when the channel is absent. Kept as a
#: module constant because the fleet's setup report prints it verbatim and it needs
#: to be complete enough to act on without reading anything else.
SYSMON_SETUP = (
    "Sysmon is not installed — the channel "
    f"{SYSMON_CHANNEL} does not exist (Win32 15007).\n"
    "  This is the single largest detection gap on this host: Sysmon event 1 is "
    "the named log source for 264 of the 697 ATT&CK techniques that carry "
    "detection guidance, and installing it moves 182 techniques out of "
    "out-of-reach.\n"
    "  Fix, from an elevated shell (about five minutes):\n"
    "    1. Download https://download.sysinternals.com/files/Sysmon.zip and "
    "extract it.\n"
    "    2. Get a starting config — SwiftOnSecurity/sysmon-config or "
    "olafhartong/sysmon-modular. cyphra-soc/ingest/collectors/sysmon-config.xml "
    "is a working default.\n"
    "    3. sysmon64.exe -accepteula -i sysmon-config.xml\n"
    "    4. Confirm: Get-WinEvent -LogName "
    f"'{SYSMON_CHANNEL}' -MaxEvents 1\n"
    "  No CYPHRA change is needed afterwards — the collector re-probes the channel "
    "on every start and begins collecting on the next cycle."
)

#: Where the config that ``SYSMON_SETUP`` promises actually lives.
SYSMON_CONFIG_PATH = Path(__file__).with_name("sysmon-config.xml")

#: Sysmon rule element → the event ids that element filters. This is the schema
#: Sysmon's own parser enforces, restated here because of *how* it enforces it: a
#: config with one misspelled element name is rejected whole, and ``sysmon64 -c``
#: then leaves the **previous** configuration running. The operator sees one line of
#: error text scroll past, the service keeps working, and every rule they thought
#: they just deployed is absent. That failure is indistinguishable from a quiet
#: network until someone compares ``sysmon64 -c`` output against the file on disk.
SYSMON_RULE_ELEMENTS: dict[str, tuple[int, ...]] = {
    "ProcessCreate": (1,),
    "FileCreateTime": (2,),
    "NetworkConnect": (3,),
    "ProcessTerminate": (5,),
    "DriverLoad": (6,),
    "ImageLoad": (7,),
    "CreateRemoteThread": (8,),
    "RawAccessRead": (9,),
    "ProcessAccess": (10,),
    "FileCreate": (11,),
    # One element covers all three registry event types; `EventType` separates them.
    "RegistryEvent": (12, 13, 14),
    "FileCreateStreamHash": (15,),
    "PipeEvent": (17, 18),
    "WmiEvent": (19, 20, 21),
    "DnsQuery": (22,),
    "FileDelete": (23,),
    "ClipboardChange": (24,),
    "ProcessTampering": (25,),
    "FileDeleteDetected": (26,),
    "FileBlockExecutable": (27,),
    "FileBlockShredding": (28,),
    "FileExecutableDetected": (29,),
}

#: Fields each rule element accepts as a filter. Wrong field names fail the same way
#: wrong element names do — silently, by rejection of the whole file. Every name here
#: is one Sysmon emits in the event it belongs to; the ``UtcTime``/``ProcessGuid``/
#: ``ProcessId``/``Image``/``User``/``RuleName`` set common to nearly all of them is
#: added by :data:`_COMMON_FILTER_FIELDS` rather than repeated twenty times.
_COMMON_FILTER_FIELDS = frozenset(
    {"RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User"}
)

SYSMON_FILTER_FIELDS: dict[str, frozenset[str]] = {
    "ProcessCreate": frozenset(
        {
            "FileVersion", "Description", "Product", "Company", "OriginalFileName",
            "CommandLine", "CurrentDirectory", "LogonGuid", "LogonId",
            "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid",
            "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser",
        }
    ),
    "FileCreateTime": frozenset(
        {"TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"}
    ),
    "NetworkConnect": frozenset(
        {
            "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
            "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp",
            "DestinationHostname", "DestinationPort", "DestinationPortName",
        }
    ),
    "ProcessTerminate": frozenset(),
    "DriverLoad": frozenset({"ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"}),
    "ImageLoad": frozenset(
        {
            "ImageLoaded", "FileVersion", "Description", "Product", "Company",
            "OriginalFileName", "Hashes", "Signed", "Signature", "SignatureStatus",
        }
    ),
    "CreateRemoteThread": frozenset(
        {
            "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid",
            "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress",
            "StartModule", "StartFunction", "SourceUser", "TargetUser",
        }
    ),
    "RawAccessRead": frozenset({"Device"}),
    "ProcessAccess": frozenset(
        {
            "SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage",
            "TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess",
            "CallTrace", "SourceUser", "TargetUser",
        }
    ),
    "FileCreate": frozenset({"TargetFilename", "CreationUtcTime"}),
    "RegistryEvent": frozenset({"EventType", "TargetObject", "Details", "NewName"}),
    "FileCreateStreamHash": frozenset(
        {"TargetFilename", "CreationUtcTime", "Hash", "Contents"}
    ),
    "PipeEvent": frozenset({"EventType", "PipeName"}),
    "WmiEvent": frozenset(
        {
            "EventType", "Operation", "EventNamespace", "Name", "Query", "Type",
            "Destination", "Consumer", "Filter",
        }
    ),
    "DnsQuery": frozenset({"QueryName", "QueryStatus", "QueryResults"}),
    "FileDelete": frozenset({"TargetFilename", "Hashes", "IsExecutable", "Archived"}),
    "ClipboardChange": frozenset({"Session", "ClientInfo", "Hashes", "Archived"}),
    "ProcessTampering": frozenset({"Type"}),
    "FileDeleteDetected": frozenset({"TargetFilename", "Hashes", "IsExecutable"}),
    "FileBlockExecutable": frozenset({"TargetFilename", "Hashes"}),
    "FileBlockShredding": frozenset({"TargetFilename", "Hashes", "IsExecutable"}),
    "FileExecutableDetected": frozenset({"TargetFilename", "Hashes"}),
}

#: Match operators Sysmon understands. ``is any``, ``contains any``, ``contains all``,
#: ``excludes any`` and ``excludes all`` take a ``;``-separated list and need
#: schemaversion 4.22 or newer.
SYSMON_CONDITIONS = frozenset(
    {
        "is", "is not", "is any", "is not any",
        "contains", "contains any", "contains all",
        "excludes", "excludes any", "excludes all",
        "begin with", "not begin with", "end with", "not end with",
        "less than", "more than", "image",
    }
)

#: Events that do not log but *act*: 27 and 28 block a file operation in the kernel
#: on a path match. Enabling one from a telemetry config puts an unreviewable
#: prevention rule on the host outside ``respond/``, where blast radius is computed
#: and a kill switch exists. Flagged as a warning rather than an error because an
#: operator may genuinely want it — but never by accident.
SYSMON_BLOCKING_ELEMENTS = frozenset({"FileBlockExecutable", "FileBlockShredding"})


def validate_sysmon_config(text: str) -> list[str]:
    """Check a Sysmon config the way Sysmon will, and return the problems.

    Sysmon validates on install, and installing needs elevation — so on an
    unelevated host the only way to know whether the shipped config is loadable is
    to check it here. Every rule below is one that makes ``sysmon64 -i`` refuse the
    file, which in the ``-c`` (update) case leaves the previous config running and
    the operator believing the new one took effect.

    Returns a list of human-readable problems, empty if the config is clean. Items
    beginning with ``warning:`` will load but are worth a second look.
    """
    import xml.etree.ElementTree as ET

    problems: list[str] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [f"not well-formed XML: {exc}"]

    if root.tag != "Sysmon":
        return [f"root element is <{root.tag}>, not <Sysmon>"]
    version = (root.get("schemaversion") or "").strip()
    if not version:
        problems.append(
            "no schemaversion attribute on <Sysmon> — Sysmon refuses a config "
            "without one"
        )
    else:
        try:
            major, _, minor = version.partition(".")
            if (int(major), int(minor or 0)) < (4, 22):
                problems.append(
                    f"schemaversion {version} predates 4.22, so rule groups and the "
                    "'contains any' operators used by most published configs are "
                    "unavailable"
                )
        except ValueError:
            problems.append(f"schemaversion {version!r} is not a version number")

    filtering = [c for c in root if c.tag == "EventFiltering"]
    if not filtering:
        problems.append("no <EventFiltering> section, so this config filters nothing")

    seen: set[str] = set()
    for section in filtering:
        for node in section:
            if node.tag == "RuleGroup":
                relation = (node.get("groupRelation") or "").strip()
                if relation not in ("or", "and"):
                    problems.append(
                        f"<RuleGroup name={node.get('name')!r}> has groupRelation="
                        f"{relation!r}; Sysmon accepts only 'or' or 'and'"
                    )
                rules = list(node)
            else:
                # A rule element directly under EventFiltering is the pre-4.22 form
                # and is still accepted.
                rules = [node]
            for rule in rules:
                seen.add(rule.tag)
                if rule.tag not in SYSMON_RULE_ELEMENTS:
                    near = _closest(rule.tag, SYSMON_RULE_ELEMENTS)
                    problems.append(
                        f"<{rule.tag}> is not a Sysmon rule element"
                        + (f" — did you mean <{near}>?" if near else "")
                        + ". Sysmon rejects the whole file for this, and on an "
                        "update the previous config keeps running."
                    )
                    continue
                if rule.tag in SYSMON_BLOCKING_ELEMENTS:
                    problems.append(
                        f"warning: <{rule.tag}> does not log, it blocks the file "
                        "operation in the kernel — that is a response action and "
                        "belongs behind respond/safety.py, not in a telemetry config"
                    )
                onmatch = (rule.get("onmatch") or "").strip()
                if onmatch not in ("include", "exclude"):
                    problems.append(
                        f"<{rule.tag}> has onmatch={onmatch!r}; must be 'include' or "
                        "'exclude'"
                    )
                allowed = SYSMON_FILTER_FIELDS.get(rule.tag, frozenset()) | _COMMON_FILTER_FIELDS
                for field in rule:
                    if field.tag == "Rule":
                        # A compound <Rule groupRelation="and"> nests fields.
                        children = list(field)
                    else:
                        children = [field]
                    for leaf in children:
                        if leaf.tag not in allowed:
                            near = _closest(leaf.tag, allowed)
                            problems.append(
                                f"<{rule.tag}> has no filter field <{leaf.tag}>"
                                + (f" — did you mean <{near}>?" if near else "")
                            )
                        cond = (leaf.get("condition") or "is").strip()
                        if cond not in SYSMON_CONDITIONS:
                            problems.append(
                                f"<{rule.tag}><{leaf.tag} condition={cond!r}> is not a "
                                "Sysmon match operator"
                            )
                        if not (leaf.text or "").strip() and cond != "is":
                            problems.append(
                                f"<{rule.tag}><{leaf.tag}> has condition={cond!r} but "
                                "no value to match against"
                            )

    # A config that enables an event this collector does not map is not an error in
    # Sysmon's eyes, but it is one in CYPHRA's: the event arrives, gets no
    # activity_id, and lands in the unmapped table where no rule will ever see it.
    for element in sorted(seen):
        for eid in SYSMON_RULE_ELEMENTS.get(element, ()):
            if eid not in SYSMON_MAP:
                problems.append(
                    f"warning: <{element}> enables Sysmon event {eid}, which "
                    "SYSMON_MAP does not map — those events will be stored unmapped "
                    "and no detection will match them"
                )
    return problems


def _closest(word: str, candidates: Any) -> str:
    """Best single spelling suggestion from *candidates*, or ``""``.

    Only for error messages. A misspelled rule element is the single most common
    Sysmon config error and the least obvious one, so the message earns the cost of
    guessing what was meant.
    """
    import difflib

    matches = difflib.get_close_matches(word, list(candidates), n=1, cutoff=0.7)
    return matches[0] if matches else ""



__all__ = [
    "SYSMON_CHANNEL",
    "SYSMON_CONDITIONS",
    "SYSMON_CONFIG_PATH",
    "SYSMON_DATA_MAP",
    "SYSMON_DATA_MAP_BY_CLASS",
    "SYSMON_FILTER_FIELDS",
    "SYSMON_MAP",
    "SYSMON_RULE_ELEMENTS",
    "SYSMON_SETUP",
    "SysmonCollector",
    "local_address_error",
    "local_addresses",
    "parse_hashes",
    "validate_sysmon_config",
]

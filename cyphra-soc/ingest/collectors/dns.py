"""DNS collectors — resolution telemetry, from the two sources Windows actually has.

DNS is the highest-yield single log source a SOC has for command-and-control, because
almost every implant resolves a name before it connects, and the name survives in
telemetry when the IP is rotated away. It is also the source most often *believed* to
be collected when it is not, and this module exists mostly to make the difference
visible.

Two collectors, because the two sources have nothing in common but their subject:

* :class:`DnsClientLogCollector` reads ``Microsoft-Windows-DNS-Client/Operational``.
  This is real per-query telemetry: every query, its type, its status, and its answers.
  **The channel is disabled by default on every Windows install** and enabling it
  needs elevation — so on this host it is a documented gap, not a working source.
* :class:`DnsCacheCollector` diffs the resolver cache. It works right now, unelevated,
  with nothing enabled, and it is much weaker. It is a floor, not a substitute.

**A disabled channel opens cleanly and returns nothing.** Measured on this host:
``EvtQuery`` on the DNS-Client channel succeeds, ``EvtNext`` returns zero events, and
``wevtutil gl`` reports ``enabled: false``. A collector that probes by asking "can I
open this channel?" — the obvious way to write it — would report DNS as a healthy
source with a green light on the health board and collect not one query, forever. So
:func:`channel_enabled` reads the channel's actual *enabled* flag through
``EvtGetChannelConfigProperty``, and the probe fails on a disabled channel even though
every read against it would succeed. This is the whole reason the function exists.

**Three things the resolver cache cannot tell you.** They are limitations of the
source, not of the code, and they are why the cache collector reports a limitation
even while healthy:

1. **DNS-over-HTTPS bypasses it completely.** A browser resolving over DoH never
   touches the Windows resolver, so nothing it looks up appears in the cache or in the
   DNS-Client log. Firefox enables DoH by default; Chrome and Edge do opportunistically.
   On a normal desktop this is not a small gap — it can be most of the host's DNS.
2. **No process attribution.** The cache records that a name was resolved, never who
   asked. "Something on this host resolved a known C2 domain" is a materially weaker
   statement than "``rundll32.exe`` did", and only the log channel or Sysmon event 22
   can make the second one.
3. **No query counts, so no periodicity.** A name looked up once and a name looked up
   ten thousand times are the same single cache entry. Beacon interval — the most
   reliable C2 signal there is, and the one that survives domain rotation — is not
   observable from a cache by construction.

**Most of what is in the cache is not a DNS query.** Windows loads
``%SystemRoot%\\System32\\drivers\\etc\\hosts`` into the resolver cache, and those
entries look exactly like resolved queries: status 0, an answer, a long TTL. Measured
here: 63 hosts entries producing 134 of the 197 cache rows, including 63 negative AAAA
entries. Emitting those as observed resolutions would be a false telemetry claim that
inflates every per-domain count a hunt computes, so :class:`DnsCacheCollector` reads
the hosts file, cross-references it, and labels those rows ``hosts_file`` with a
distinct activity rather than calling them queries.

That cross-reference pays for itself twice: a *changed* hosts file is itself worth
alerting on. Redirecting a security vendor's update domain or an internal service by
adding a line to a text file is cheap, persistent, survives reboots, and is invisible
to anything watching only network traffic.

**``DNS_INFO_NO_RECORDS`` (9501) is NODATA, not NXDOMAIN.** Windows DNS status codes
are not DNS RCODEs, and the mapping between them has one trap that matters. 9501 means
the name exists but carries no record of the type asked for — an IPv4-only host getting
no AAAA — and its RCODE is **0, NoError**. Mapping it to NXDomain instead is a
one-character decision that turns every AAAA lookup on the host into an apparent
failed resolution of a nonexistent domain. A high NXDOMAIN rate is precisely the
signature hunts use to find DGA and C2 fallback, so the wrong mapping does not merely
mislabel: it manufactures a permanent, unfalsifiable DGA signal out of ordinary IPv6
absence. On this host that would be 63 rows. :data:`WINDOWS_DNS_STATUS` carries the
whole table for that reason, and separates transport failures — timeout, no configured
server, malformed packet — which are not RCODEs at all and must not be reported as one.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import (
    Availability,
    PullCollector,
    available,
    is_admin,
    is_windows,
    unavailable,
)
from ingest.collectors.windows_eventlog import (
    Channel,
    WindowsEventLogCollector,
    _Mapped,
)

#: The channel with real per-query DNS telemetry. Disabled on every Windows install.
DNS_CLIENT_CHANNEL = "Microsoft-Windows-DNS-Client/Operational"

_DNS = int(ClassUid.DNS_ACTIVITY)

#: What to tell the operator. Enabling an Event Log channel is a privileged operation,
#: so this process cannot do it — and the instruction is worth more than a retry.
#:
#: The volume warning is not boilerplate. This channel logs every query including the
#: ones served from cache, which on a desktop is thousands per hour, and its default
#: log is 1 MB — measured on this host. At that size it wraps in minutes under real
#: load, so raising the size is part of enabling it, not an optimisation afterwards.
DNS_CLIENT_SETUP = (
    "DNS query logging is off. Windows can log every DNS query with its type, status "
    "and answers, which is the single best source for finding command-and-control by "
    "the name an implant resolves rather than the address it connects to. It is "
    "disabled by default and enabling it needs an elevated shell:\n"
    '    wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true\n'
    '    wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /ms:104857600\n'
    "  The second command matters as much as the first: the default log is 1 MB, and "
    "this channel logs cache hits too, so at default size it wraps within minutes on "
    "a busy host and the events are gone before anything reads them.\n"
    "  Sysmon event 22 (DnsQuery) is the better source if Sysmon is installed — it "
    "attributes each query to the process that made it. This channel is the option "
    "that needs no software installed.\n"
    "  Until one of the two is available, DNS coverage on this host is the resolver "
    "cache only: no process attribution, no query counts, and nothing at all from any "
    "application using DNS-over-HTTPS."
)

#: DNS query types by number. Names are the IANA mnemonics, because that is what a
#: rule author writes and what an intel feed publishes.
DNS_QUERY_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    17: "RP",
    24: "SIG",
    25: "KEY",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    35: "NAPTR",
    37: "CERT",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    59: "CDS",
    60: "CDNSKEY",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    108: "EUI48",
    109: "EUI64",
    249: "TKEY",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
    256: "URI",
    257: "CAA",
}

#: Query types whose *use* is the finding, independent of the name asked for.
#:
#: A workstation has no reason to issue these, and each has a specific abuse:
#: ``TXT`` and ``NULL`` are the classic carriers for DNS tunnelling because they hold
#: arbitrary bytes; ``AXFR``/``IXFR`` are zone transfers, which is reconnaissance
#: against a name server and never something a desktop application does; ``ANY`` is
#: the amplification query. Flagged rather than filtered — the collector's job is to
#: label, and ``detect/`` decides.
NOTABLE_QUERY_TYPES: dict[int, str] = {
    10: "NULL records carry arbitrary bytes and are a DNS-tunnelling carrier",
    16: "TXT records carry arbitrary bytes and are the most common DNS-tunnelling "
        "carrier; also used by legitimate SPF/DKIM lookups, so volume and entropy "
        "distinguish them",
    251: "IXFR is an incremental zone transfer — reconnaissance against a name "
         "server, not something a workstation issues",
    252: "AXFR is a full zone transfer — reconnaissance against a name server, not "
         "something a workstation issues",
    255: "ANY queries are used for DNS amplification and to enumerate a zone in one "
         "request",
}

#: Windows ``DNS_STATUS`` → ``(OCSF rcode_id, mnemonic, is_transport_failure)``.
#:
#: Windows does not report DNS RCODEs. It reports its own status codes, most of which
#: correspond to an RCODE with a 9000 offset and several of which do not correspond to
#: an RCODE at all. Both halves of that matter:
#:
#: * ``9501 DNS_INFO_NO_RECORDS`` is **NODATA** — the name resolves, there is simply no
#:   record of the type requested. Its RCODE is 0, NoError. Mapping it to 3/NXDomain
#:   is the trap this table exists to prevent: on an IPv4-only host every AAAA lookup
#:   returns 9501, so that single wrong entry would report a large fraction of all
#:   lookups as failed resolutions of nonexistent names — which is the exact signature
#:   of DGA and C2 fallback, manufactured permanently out of ordinary IPv6 absence.
#: * A timeout, an unreachable resolver and a malformed response are **not RCODEs**.
#:   No response arrived, so there is no response code to report. They map to 99/Other
#:   with the third element set, so a hunt counting resolution failures can separate
#:   "the server said no" from "nothing answered" — different causes, different
#:   response, and averaging them together hides both.
WINDOWS_DNS_STATUS: dict[int, tuple[int, str, bool]] = {
    0: (0, "NoError", False),
    9001: (1, "FormError", False),
    9002: (2, "ServFail", False),
    9003: (3, "NXDomain", False),
    9004: (4, "NotImp", False),
    9005: (5, "Refused", False),
    9006: (6, "YXDomain", False),
    9007: (7, "YXRRSet", False),
    9008: (8, "NXRRSet", False),
    9009: (9, "NotAuth", False),
    9010: (10, "NotZone", False),
    9016: (16, "BADVERS", False),
    9017: (17, "BADKEY", False),
    9018: (18, "BADTIME", False),
    # NODATA. RCODE 0. See the note above; this is the entry that must not be 3.
    9501: (0, "NoError (NODATA — name exists, no record of this type)", False),
    9502: (99, "BadPacket (malformed response)", True),
    9503: (99, "NoPacket (no response received)", True),
    9504: (99, "RcodeError", True),
    9505: (99, "UnsecurePacket", True),
    9550: (99, "RequestPending", True),
    9560: (99, "NameDoesNotExistInDatabase", False),
    9701: (99, "NoDnsServers (no resolver configured — the query was never sent)", True),
    9702: (99, "NoDnsServersForZone", True),
    9703: (99, "NoDefaultZone", True),
    1460: (99, "Timeout (no response within the resolver's window)", True),
    # WSA/general failures seen in QueryStatus on hosts with no connectivity.
    11001: (99, "HostNotFound", True),
    11002: (99, "TryAgain (transient resolver failure)", True),
    11003: (99, "NoRecovery", True),
    11004: (99, "NoData", False),
}

#: Cache ``Section`` values. Section 0 is what Windows uses for a negative entry.
CACHE_SECTIONS: dict[int, str] = {
    0: "negative",
    1: "answer",
    2: "authority",
    3: "additional",
}

#: DNS-Client event id → its OCSF meaning.
#:
#: Only the six events that carry a query name are mapped. The channel emits others —
#: cache maintenance, adapter changes, resolver configuration — that describe the
#: resolver's own housekeeping rather than a resolution, and mapping those to "Query"
#: would inflate every query count with events that are not queries. Unmapped ids are
#: counted by the base collector and surface in ``unmapped_ids``, so a firmware or
#: Windows update that starts emitting a new id is visible rather than silently
#: discarded.
#:
#: The split between 1 (Query) and 2 (Response) is by whether the event carries an
#: answer. 3006 and 3010 are a query going out; 3008, 3011, 3018 and 3020 are a result
#: coming back. Collapsing them all to "Query" would double-count every lookup, since
#: a single resolution normally produces one of each.
DNS_CLIENT_MAP: dict[int, _Mapped] = {
    3006: _Mapped(_DNS, 1, "DNS query issued by an application"),
    3008: _Mapped(_DNS, 2, "DNS query completed"),
    3010: _Mapped(_DNS, 1, "DNS query sent to a server"),
    3011: _Mapped(_DNS, 2, "DNS response received from a server"),
    3018: _Mapped(_DNS, 2, "DNS query answered from cache"),
    3020: _Mapped(_DNS, 2, "DNS response cached"),
}

#: DNS-Client ``EventData`` field → Event model field.
DNS_CLIENT_DATA_MAP: dict[str, str] = {
    "QueryName": "dns_query_hostname",
    "DnsServerIpAddress": "dst_endpoint_ip",
    "Address": "dst_endpoint_ip",
}

_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")

#: A hosts line: address, whitespace, one or more names, optional comment.
_HOSTS_LINE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s+([^#]+?)\s*(?:#.*)?$")


def channel_enabled(channel: str) -> tuple[bool | None, str]:
    """``(enabled, detail)`` for an Event Log channel. ``None`` means unknown.

    This exists because the obvious availability check is wrong in the worst possible
    direction. ``EvtQuery`` against a *disabled* channel succeeds — it is a real
    channel with a real log file — and every read returns zero events. Probing by
    openability therefore reports a source that will never yield a single event as
    healthy, indefinitely, with nothing anywhere indicating otherwise.

    ``None`` is returned when the enabled state genuinely could not be read, and is
    deliberately not folded into ``False``: "disabled, here is the command" and "I
    could not determine this" call for different operator responses, and reporting the
    second as the first sends someone to run a command that may already have been run.
    """
    if not is_windows():
        return None, "not Windows"
    try:
        import win32evtlog
    except Exception as exc:  # pragma: no cover - pywin32 is a hard dependency
        return None, f"pywin32 unavailable: {exc}"
    try:
        cfg = win32evtlog.EvtOpenChannelConfig(channel)
    except Exception as exc:
        # A channel that does not exist at all is a different answer from a disabled
        # one, and the caller distinguishes them by the text.
        return None, f"channel config unreadable: {exc}"
    try:
        raw = win32evtlog.EvtGetChannelConfigProperty(
            cfg, win32evtlog.EvtChannelConfigEnabled
        )
    except Exception as exc:
        return None, f"enabled flag unreadable: {exc}"
    # EvtGetChannelConfigProperty returns (value, type_id), not a bare value.
    value = raw[0] if isinstance(raw, tuple) else raw
    return bool(value), ("enabled" if value else "disabled")


def query_type_name(value: Any) -> str:
    """A query type number as its IANA mnemonic, or ``TYPE<n>`` if unrecognised.

    Unknown types are rendered as ``TYPE43210`` rather than dropped or blanked. An
    unrecognised query type is not noise — a type nobody has heard of, issued by a
    desktop, is more interesting than an A record, and blanking it would remove the
    one field that made the event worth reading.
    """
    try:
        num = int(value)
    except (TypeError, ValueError):
        return str(value or "")
    return DNS_QUERY_TYPES.get(num) or f"TYPE{num}"


def dns_status(value: Any) -> tuple[int, str, bool]:
    """Windows DNS status → ``(rcode_id, mnemonic, transport_failure)``.

    An unmapped status becomes 99/Other and is marked as a transport failure only if
    it is not in the 9000–9018 RCODE-offset band, because an unrecognised code in that
    band is far more likely to be an RCODE this table simply does not list than a
    transport problem, and guessing "transport failure" would tell a hunt that nothing
    answered when something did.
    """
    try:
        num = int(value)
    except (TypeError, ValueError):
        return 99, f"unknown status {value!r}", False
    known = WINDOWS_DNS_STATUS.get(num)
    if known:
        return known
    if 9000 <= num <= 9018:
        return 99, f"unmapped RCODE-band status {num}", False
    return 99, f"unmapped status {num}", True


def read_hosts_file(path: Path | None = None) -> tuple[dict[str, list[str]], str, str]:
    """``({name: [addresses]}, sha256, error)`` from the hosts file.

    Read with ``utf-8-sig``. The BOM is not hypothetical — this host's hosts file has
    one, and reading it as cp1252 renders the first line as ``ï»¿#``. That is harmless
    on a comment and silently corrupts the first entry when the file does not start
    with one, which is exactly what a file written by a script rather than by hand
    looks like.

    Names are lower-cased: DNS is case-insensitive, the cache reports whatever case was
    queried, and a cross-reference that is case-sensitive would fail to match
    ``Update.Microsoft.com`` against a hosts entry for ``update.microsoft.com`` — which
    is the exact form an attacker adding an entry by hand would produce.
    """
    p = path or _HOSTS_PATH
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        return {}, "", f"hosts file not found at {p}"
    except OSError as exc:
        return {}, "", f"hosts file unreadable ({type(exc).__name__}: {exc})"
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _HOSTS_LINE.match(stripped)
        if not m:
            continue
        addr, names = m.group(1), m.group(2)
        for name in names.split():
            out.setdefault(name.strip().lower(), []).append(addr)
    return out, digest, ""


def read_dns_cache() -> tuple[list[dict[str, Any]], str, str]:
    """``(rows, source, error)`` from the Windows resolver cache.

    Three paths, tried in this order. Medians over five runs on this host, same cache:

    ===============================  =========  ===================================
    path                             median     why it sits where it does
    ===============================  =========  ===================================
    WMI ``MSFT_DNSClientCache``        118 ms    typed integers, in-process, no shell
    PowerShell ``Get-DnsClientCache``  606 ms    same CIM class, 5× the cost — almost
                                                 all of it PowerShell starting up
    ``ipconfig /displaydns``            28 ms    **fastest, and still last**
    ===============================  =========  ===================================

    The ordering is deliberately *not* by speed, and the last row is why this table is
    here rather than a sentence claiming WMI is the fast path. ``ipconfig`` is four
    times quicker than WMI, but it is prose written for a human: its field labels are
    translated on a localised Windows, and its values are words (``Section: Answer``)
    where WMI returns integers. A parser over translated prose does not fail loudly —
    it matches nothing and returns an empty cache, which reads as "this host has
    resolved nothing". Cheap and occasionally silently wrong loses to more expensive
    and structurally reliable, every time.

    Speed is also not the constraint here. This runs on a 30-second cadence, so 118 ms
    against 28 ms is 0.4% of one poll's interval versus 0.09% — a difference with no
    operational meaning, traded for a parser that cannot silently return nothing.

    ``source`` is returned alongside the rows so that a suspiciously empty or partial
    result can be attributed to the path that produced it instead of believed.
    """
    rows, err = _cache_via_wmi()
    if rows or not err:
        return rows, "wmi", err
    first = err
    rows, err = _cache_via_powershell()
    if rows or not err:
        return rows, "powershell", err
    second = err
    rows, err = _cache_via_ipconfig()
    if rows or not err:
        return rows, "ipconfig", err
    return [], "none", f"wmi: {first}; powershell: {second}; ipconfig: {err}"


def _cache_via_wmi() -> tuple[list[dict[str, Any]], str]:
    try:
        import pythoncom
        import win32com.client
    except Exception as exc:
        return [], f"win32com unavailable: {exc}"
    try:
        # The collector runs on the asyncio loop's thread, which may not have COM
        # initialised. Initialising per call is cheap and idempotent; skipping it makes
        # the first query fail with an opaque CoInitialize error on some hosts.
        try:
            pythoncom.CoInitialize()
        except Exception:
            pass
        svc = win32com.client.GetObject("winmgmts:root\\StandardCimv2")
        query = (
            "SELECT Entry,Name,Data,Type,Section,Status,TimeToLive,DataLength "
            "FROM MSFT_DNSClientCache"
        )
        out = []
        for r in svc.ExecQuery(query):
            out.append(
                {
                    "Entry": r.Entry,
                    "Name": r.Name,
                    "Data": r.Data,
                    "Type": r.Type,
                    "Section": r.Section,
                    "Status": r.Status,
                    "TimeToLive": r.TimeToLive,
                    "DataLength": r.DataLength,
                }
            )
        return out, ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _cache_via_powershell() -> tuple[list[dict[str, Any]], str]:
    import json
    import subprocess

    cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        # Select-Object before ConvertTo-Json: the raw CIM objects serialise their whole
        # class definition, which is kilobytes of schema metadata per row.
        "Get-DnsClientCache | Select-Object Entry,Name,Data,Type,Section,Status,"
        "TimeToLive,DataLength | ConvertTo-Json -Compress -Depth 3",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return [], f"exit {proc.returncode}: {(proc.stderr or '').strip()[:200]}"
    text = (proc.stdout or "").strip()
    if not text:
        return [], ""
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return [], f"unparseable json: {exc}"
    if isinstance(parsed, dict):
        # ConvertTo-Json emits a bare object, not a list, when there is exactly one
        # row. Left unhandled this raises on a host with a single cache entry.
        parsed = [parsed]
    return [dict(r) for r in parsed if isinstance(r, dict)], ""


def _cache_via_ipconfig() -> tuple[list[dict[str, Any]], str]:
    """Parse ``ipconfig /displaydns``. The last resort, and the weakest of the three.

    Text output for humans, and it shows. Measured against the WMI path on the same
    host and the same cache, the first version of this parser returned **6 rows where
    WMI returned 215** — and returned no error, so a caller had no way to know it had
    lost 97% of the cache. Three things were wrong, and each is a general trap in
    parsing this command:

    * **The record-set header does not end with a dot.** ``ipconfig`` prints the
      queried name as a bare indented line — ``    www.example.com`` — and the
      obvious guard for "is this a name?", a trailing dot, matches almost nothing.
      Without a header there is no ``Entry``, and a row with no ``Entry`` is dropped
      downstream.
    * **Negative entries exist only as prose.** ``No records of type AAAA`` is the
      whole record; there is no ``Record Name`` block to parse. Skipping it discards
      every NODATA result — 63 of them here, which is 29% of this cache — and those
      are precisely the rows that carry the NXDOMAIN-versus-NODATA distinction.
    * **One record set can hold several records.** A CNAME chain prints a CNAME
      record and then an A record under one header. Flushing on the header instead of
      on each ``Record Name`` merges them into a single row whose type says CNAME and
      whose data is an IP address — a row describing something that does not exist.

    ``Section`` is a word here (``Answer``) rather than the integer WMI returns, so it
    is translated back; an unrecognised section word is left as 1/answer rather than
    guessed at, and noted below.

    The locale problem is real and unfixed, because it is not fixable from here: these
    labels are translated on a localised Windows. The guard is that a run which finds
    record-set headers but produces no rows returns an **error**, not an empty list —
    an empty cache and an unparsed one are otherwise identical, and the difference is
    whether the host resolved nothing or this function understood nothing.
    """
    import subprocess

    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"
    text = proc.stdout or ""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    entry = ""
    headers = 0

    def flush() -> None:
        nonlocal current
        if current:
            rows.append(current)
        current = None

    for line in text.splitlines():
        s = line.strip()
        if not s or "-----" in s:
            continue
        if ":" not in s:
            low = s.lower()
            if low.startswith("no records of type"):
                # A negative entry, and the only place it appears. Status 9501 is what
                # WMI reports for the same row, so the two paths agree — and 9501 is
                # NODATA, RCODE 0, not NXDomain. See WINDOWS_DNS_STATUS.
                flush()
                rows.append(
                    {
                        "Entry": entry,
                        "Name": entry,
                        "Data": "",
                        "Type": _TYPE_BY_NAME.get(s.split()[-1].upper(), 0),
                        "Section": 0,
                        "Status": 9501,
                        "TimeToLive": None,
                    }
                )
                continue
            if low.startswith("windows ip configuration"):
                continue
            # Anything else without a colon is a record-set header: the queried name.
            flush()
            entry = s.rstrip(".")
            headers += 1
            continue

        label, _, value = s.partition(":")
        label, value = label.strip().lower(), value.strip()
        if label.startswith("record name"):
            # Each Record Name starts a new record, including the second one under a
            # single header. Flushing here rather than on the header is what keeps a
            # CNAME chain as two rows instead of one impossible hybrid.
            flush()
            current = {"Entry": entry or value, "Name": value, "Data": "",
                       "Section": 1, "Status": 0, "Type": 0, "TimeToLive": None}
        elif current is None:
            continue
        elif label.startswith("record type"):
            current["Type"] = _int_or_zero(value)
        elif label.startswith("time to live"):
            current["TimeToLive"] = _int_or_zero(value)
        elif label.startswith("data length"):
            current["DataLength"] = _int_or_zero(value)
        elif label.startswith("section"):
            current["Section"] = _SECTION_BY_NAME.get(value.lower(), 1)
        elif label.endswith("record") and value:
            # "A (Host) Record", "AAAA Record", "CNAME Record", "PTR Record" — the
            # answer itself. Matched on the label *ending* in "record" so that
            # "Record Name" and "Record Type", handled above, cannot fall through here.
            current["Data"] = value
    flush()

    if headers and not rows:
        return [], (
            f"ipconfig /displaydns printed {headers} record-set headers but none of "
            "the expected field labels matched, so no rows were parsed. This is "
            "almost certainly a localised Windows, where the labels are translated. "
            "Treat the cache as unreadable rather than empty — an empty result here "
            "would read as 'this host has resolved nothing'."
        )
    return rows, ""


def _int_or_zero(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


#: Query-type mnemonic → number, for the one place Windows prints the name instead of
#: the number: ``No records of type AAAA`` in ``ipconfig /displaydns`` output.
_TYPE_BY_NAME: dict[str, int] = {v: k for k, v in DNS_QUERY_TYPES.items()}

#: Cache section word → the integer WMI reports for the same row.
_SECTION_BY_NAME: dict[str, int] = {v: k for k, v in CACHE_SECTIONS.items()}


class DnsClientLogCollector(WindowsEventLogCollector):
    """``Microsoft-Windows-DNS-Client/Operational`` — real per-query DNS telemetry.

    Disabled by default on Windows, so on most hosts :meth:`probe` returns the enable
    instruction rather than a working collector. The mapping is written and asserted
    against the schema regardless, for the same reason the Sysmon collector's is: a
    mapping that is only exercised once the source is finally turned on is a mapping
    that fails on the day it first matters, and the failure mode — a rejected
    ``activity_id`` — quarantines every event while the source reports healthy.
    """

    name = "dns_client_log"
    cadence_seconds = 10.0
    critical = False
    description = (
        "DNS queries and responses from the Windows DNS client channel — query name, "
        "type, status and answers, with the querying process where the channel "
        "records it"
    )
    event_map = DNS_CLIENT_MAP
    data_map = DNS_CLIENT_DATA_MAP

    def __init__(self, pipeline: Any, **kwargs: Any) -> None:
        kwargs.setdefault(
            "channels",
            [Channel(DNS_CLIENT_CHANNEL, int(ClassUid.DNS_ACTIVITY), critical=False)],
        )
        super().__init__(pipeline, **kwargs)

    def probe(self) -> Availability:
        """Readable is not enough — the channel must also be *enabled*.

        The base probe checks that a channel can be opened and read. For this channel
        that check passes while it is disabled, which is the default state, so on its
        own it would report a permanently empty source as available. The enabled flag
        is checked first and takes precedence.
        """
        enabled, detail = channel_enabled(DNS_CLIENT_CHANNEL)
        if enabled is False:
            return unavailable(DNS_CLIENT_SETUP, fixable_by_user=True)
        if enabled is None:
            base = super().probe()
            if base:
                # Readable, but whether it is enabled could not be determined. Running
                # is right; claiming completeness is not.
                return available(
                    "the DNS-Client channel is readable but its enabled state could "
                    f"not be determined ({detail}). If it is disabled, every read "
                    "succeeds and returns nothing — check with: wevtutil gl "
                    f'"{DNS_CLIENT_CHANNEL}"'
                )
            why = self.channels[0].why_unavailable or base.reason
            if "15007" in why or "does not exist" in why:
                return unavailable(DNS_CLIENT_SETUP, fixable_by_user=True)
            return unavailable(f"DNS-Client channel unavailable — {why}")
        return super().probe()

    def _to_event(self, ch: Channel, xml: str) -> dict[str, Any]:
        payload = super()._to_event(ch, xml)
        data: dict[str, Any] = dict(payload.get("unmapped", {}).get("event_data") or {})
        notes: list[str] = list(payload.get("soc_notes") or [])

        qtype = data.get("QueryType")
        if qtype is not None:
            payload["dns_query_type"] = query_type_name(qtype)
            try:
                num = int(qtype)
            except (TypeError, ValueError):
                num = -1
            if num in NOTABLE_QUERY_TYPES:
                notes.append(f"query type {query_type_name(num)}: {NOTABLE_QUERY_TYPES[num]}")

        status = data.get("QueryStatus")
        if status is not None:
            rcode, mnemonic, transport = dns_status(status)
            payload["dns_rcode_id"] = rcode
            payload.setdefault("unmapped", {})["dns_status_windows"] = status
            payload["unmapped"]["dns_status_name"] = mnemonic
            if transport:
                # Not a response code: nothing answered. Kept distinct so a hunt
                # counting NXDOMAIN rates does not silently include failures where no
                # server ever replied.
                payload["unmapped"]["dns_transport_failure"] = True
                notes.append(
                    f"no DNS response was received ({mnemonic}) — this is a transport "
                    "failure, not a response code, and must not be counted as an "
                    "NXDOMAIN when computing resolution-failure rates"
                )

        answers = _split_answers(data.get("QueryResults"))
        if answers:
            payload.setdefault("unmapped", {})["dns_answers"] = answers
            payload["dns_answer_count"] = len(answers)
            first_ip = next((a for a in answers if _looks_like_ip(a)), "")
            if first_ip:
                payload.setdefault("dst_endpoint_ip", first_ip)

        if notes:
            payload["soc_notes"] = notes
        return payload


def _split_answers(raw: Any) -> list[str]:
    """Split a DNS-Client ``QueryResults`` string into individual answers.

    The field is a semicolon-terminated list, and its IPv6 rendering is the reason
    this is a function rather than a ``split``: Windows writes IPv4 answers in
    IPv4-mapped IPv6 form, ``::ffff:93.184.216.34``. Left as-is those never join
    against an intel feed, a firewall log or a flow record, all of which carry the
    dotted quad — so the mapped prefix is stripped. A join that silently matches
    nothing is the failure this avoids.
    """
    if not raw:
        return []
    out: list[str] = []
    for part in str(raw).split(";"):
        item = part.strip()
        if not item:
            continue
        low = item.lower()
        if low.startswith("::ffff:") and "." in item:
            item = item[len("::ffff:"):]
        out.append(item)
    return out


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _looks_like_ip(value: str) -> bool:
    if _IPV4.match(value):
        return True
    return ":" in value and not value.endswith(".")


class DnsCacheCollector(PullCollector):
    """The resolver cache, diffed — the DNS floor when nothing better is enabled.

    Emits a DNS Activity response event the first time a name/type/answer appears in
    the cache, plus a separate inventory event for entries that came from the hosts
    file rather than from a query. It also watches the hosts file itself and reports a
    change, which is a cheap and durable persistence technique that leaves no network
    trace at all.

    What it cannot do is in the module docstring and in :meth:`probe`: no process
    attribution, no query counts, nothing from DNS-over-HTTPS, and a guaranteed miss
    for any name whose TTL expires between two polls.
    """

    name = "dns_cache"
    cadence_seconds = 30.0
    critical = False
    description = (
        "New entries in the Windows resolver cache, with hosts-file entries "
        "distinguished from observed resolutions, plus hosts-file change detection"
    )

    def __init__(self, pipeline: Any, *, hosts_path: Path | None = None,
                 emit_baseline: bool = True, **kwargs: Any) -> None:
        super().__init__(pipeline, **kwargs)
        self.hosts_path = hosts_path
        self.emit_baseline = emit_baseline
        #: Cache identities already reported, so a long-lived entry is emitted once.
        self._seen: set[tuple[str, int, int, str]] = set()
        self._first_poll = True
        self._hosts: dict[str, list[str]] = {}
        self._hosts_digest = ""
        self._hosts_error = ""
        self._source = ""
        self.cache_rows = 0
        self.cache_read_errors = 0
        self.entries_emitted = 0
        self.hosts_entries_emitted = 0
        self.hosts_changes = 0
        self.negative_entries = 0
        self.baseline_emitted = 0

    def probe(self) -> Availability:
        if not is_windows():
            return unavailable(
                "the Windows resolver cache is a Windows-only source; on other "
                "platforms use the DNS server's own query log"
            )
        rows, source, err = read_dns_cache()
        if err and not rows:
            return unavailable(f"resolver cache unreadable via any path — {err}")
        hosts, _digest, hosts_err = read_hosts_file(self.hosts_path)
        limits = [
            "the resolver cache is a weak DNS source and these gaps are structural, "
            "not tunable:\n"
            "    - DNS-over-HTTPS bypasses the Windows resolver entirely, so nothing "
            "an application resolves over DoH appears here at all. Firefox enables it "
            "by default; Chrome and Edge use it opportunistically. On a desktop this "
            "can be most of the host's DNS.\n"
            "    - No process attribution: the cache records that a name was "
            "resolved, never which process asked.\n"
            "    - No query counts, so no beacon periodicity — a name looked up once "
            "and ten thousand times are the same single entry.\n"
            f"    - A name whose TTL expires between polls (cadence "
            f"{self.cadence_seconds:g}s) is never seen at all.\n"
            "  " + DNS_CLIENT_SETUP.split("\n")[0]
        ]
        if source != "wmi":
            limits.append(
                f"the cache is being read via the {source} path rather than WMI. For "
                "the ipconfig path that means a parser over prose whose field labels "
                "are translated on a localised Windows — it is measurably faster than "
                "WMI (28 ms against 118), but it fails by matching nothing rather "
                "than by erroring, so treat an unexpectedly small cache here as "
                "unread rather than empty"
            )
        if hosts_err:
            limits.append(
                f"{hosts_err} — without it, hosts-file entries in the cache cannot be "
                "distinguished from observed DNS resolutions and will be reported as "
                "queries that never happened"
            )
        enabled, _detail = channel_enabled(DNS_CLIENT_CHANNEL)
        if enabled:
            limits.append(
                "the DNS-Client channel is enabled, so this collector is a redundant "
                "and much weaker second source; it is harmless but adds nothing"
            )
        note = f"{len(rows)} cache entries via {source}, {len(hosts)} hosts-file names"
        if not is_admin():
            note += " (unelevated, which this source does not require)"
        return available(note + ". " + "\n  ".join(limits))

    async def poll(self) -> list[dict[str, Any]]:
        now = self.clock()
        rows, source, err = read_dns_cache()
        self._source = source
        if err:
            self.cache_read_errors += 1
        self.cache_rows = len(rows)

        payloads: list[dict[str, Any]] = []
        payloads.extend(self._check_hosts_file(now))

        first = self._first_poll
        self._first_poll = False
        for row in rows:
            entry = str(row.get("Entry") or "").strip()
            if not entry:
                continue
            try:
                rtype = int(row.get("Type") or 0)
            except (TypeError, ValueError):
                rtype = 0
            try:
                section = int(row.get("Section") or 0)
            except (TypeError, ValueError):
                section = 0
            data = str(row.get("Data") or "")
            key = (entry.lower(), rtype, section, data)
            if key in self._seen:
                continue
            self._seen.add(key)
            if first and not self.emit_baseline:
                continue
            payloads.append(self._cache_event(row, entry, rtype, section, data, now, first))
        return payloads

    def _cache_event(
        self,
        row: dict[str, Any],
        entry: str,
        rtype: int,
        section: int,
        data: str,
        now: float,
        baseline: bool,
    ) -> dict[str, Any]:
        from_hosts = entry.lower() in self._hosts
        rcode, mnemonic, transport = dns_status(row.get("Status"))
        notes: list[str] = []
        labels = ["dns_cache", f"cache_source_{self._source}"]

        payload: dict[str, Any] = {
            "time": now,
            "class_uid": int(ClassUid.DNS_ACTIVITY),
            # 2 = Response. Never 1/Query: a cache entry is the *answer* that was
            # stored, and the query that produced it was not observed — its time,
            # its type flags and the process that made it are all unknown here.
            "activity_id": 2,
            "severity_id": int(Severity.INFORMATIONAL),
            "dns_query_hostname": entry,
            "dns_query_type": query_type_name(rtype),
            "dns_rcode_id": rcode,
            "device_hostname": _hostname(),
            "metadata_labels": labels,
            "metadata_uid": (
                f"{_hostname()}:dnscache:{entry.lower()}:{rtype}:{section}:"
                f"{hashlib.sha256(data.encode('utf-8', 'replace')).hexdigest()[:16]}"
            ),
            "unmapped": {
                "dns_cache_section": CACHE_SECTIONS.get(section, str(section)),
                "dns_status_windows": row.get("Status"),
                "dns_status_name": mnemonic,
                "dns_cache_ttl_remaining": row.get("TimeToLive"),
            },
        }
        if data:
            payload["unmapped"]["dns_answers"] = [data]
            payload["dns_answer_count"] = 1
            if _looks_like_ip(data):
                payload["dst_endpoint_ip"] = data
        else:
            payload["dns_answer_count"] = 0

        if section == 0 or rcode != 0 or not data:
            self.negative_entries += 1
        if transport:
            payload["unmapped"]["dns_transport_failure"] = True

        # The time on this event is the *observation* time, and there is no honest
        # alternative: the cache records a remaining TTL, not when the query was made,
        # and the original TTL is unknown, so the query time cannot be recovered even
        # approximately. Saying so is what stops a timeline treating it as precise.
        notes.append(
            "observed in the resolver cache, not at query time — the cache records a "
            "remaining TTL but not when the query was issued, and the original TTL is "
            "unknown, so the actual resolution happened at some unrecoverable earlier "
            "point. Do not use this timestamp to order events."
        )

        if from_hosts:
            # Not a resolution at all. Windows loads the hosts file into the resolver
            # cache and those rows are indistinguishable from answered queries by
            # every field the cache exposes — status 0, an answer, a long TTL.
            # Reporting them as queries inflates every per-domain count a hunt makes.
            self.hosts_entries_emitted += 1
            labels.append("hosts_file")
            payload["activity_id"] = 99  # Other: a static mapping, not a resolution
            payload["activity_name"] = "Hosts file entry loaded into resolver cache"
            payload["unmapped"]["dns_hosts_file_addresses"] = self._hosts[entry.lower()]
            notes.append(
                "this entry comes from the hosts file, not from a DNS query — Windows "
                "loads hosts entries into the resolver cache where they look exactly "
                "like answered queries. It is reported as activity_id 99 (Other) so "
                "it cannot be counted as a resolution that never happened."
            )
        else:
            self.entries_emitted += 1

        if baseline:
            self.baseline_emitted += 1
            labels.append("baseline_snapshot")
            notes.append(
                "baseline inventory: this entry was already in the cache when the "
                "collector started, so it was not observed appearing — a rule that "
                "fires on a new resolution must exclude baseline_snapshot or it will "
                "alert on every restart"
            )

        if rtype in NOTABLE_QUERY_TYPES:
            notes.append(f"query type {query_type_name(rtype)}: {NOTABLE_QUERY_TYPES[rtype]}")

        payload["soc_notes"] = notes
        return payload

    def _check_hosts_file(self, now: float) -> list[dict[str, Any]]:
        """Load the hosts file, and emit an event when its contents change.

        The digest is over the raw bytes, so a change in whitespace or a comment
        registers too. That is intended: a comment is where a script marks its own
        work, and a diff that ignores them would miss the most legible evidence of
        what changed and why.
        """
        hosts, digest, err = read_hosts_file(self.hosts_path)
        self._hosts_error = err
        previous, prev_digest = self._hosts, self._hosts_digest
        self._hosts, self._hosts_digest = hosts, digest
        if err or not digest:
            return []
        if not prev_digest:
            return []  # first load is the baseline, not a change
        if digest == prev_digest:
            return []
        self.hosts_changes += 1
        added = sorted(set(hosts) - set(previous))
        removed = sorted(set(previous) - set(hosts))
        changed = sorted(
            n for n in set(hosts) & set(previous) if hosts[n] != previous[n]
        )
        return [
            {
                "time": now,
                "class_uid": int(ClassUid.FILE_SYSTEM_ACTIVITY),
                "activity_id": 3,  # Update
                # Medium, not informational: this file overrides DNS for the whole
                # host, needs administrative rights to write, survives reboots, and
                # produces no network traffic to notice. A change to it is either a
                # deliberate administrative act or a redirection technique that
                # nothing watching the network would see.
                "severity_id": int(Severity.MEDIUM),
                "file_path": str(self.hosts_path or _HOSTS_PATH),
                "file_name": "hosts",
                "device_hostname": _hostname(),
                "metadata_uid": f"{_hostname()}:hosts:{digest[:32]}",
                "metadata_labels": ["dns_cache", "hosts_file_change"],
                "unmapped": {
                    "hosts_sha256": digest,
                    "hosts_previous_sha256": prev_digest,
                    "hosts_names_added": added[:200],
                    "hosts_names_removed": removed[:200],
                    "hosts_names_readdressed": changed[:200],
                    "hosts_names_total": len(hosts),
                },
                "soc_notes": [
                    f"the hosts file changed: {len(added)} names added, "
                    f"{len(removed)} removed, {len(changed)} pointed at a different "
                    "address. This file overrides DNS for every process on the host, "
                    "requires administrative rights to write, survives reboots, and "
                    "generates no network traffic — a redirection placed here is "
                    "invisible to anything monitoring only the wire."
                ],
            }
        ]

    def stats_extra(self) -> dict[str, Any]:
        return {
            "cache_rows_last_poll": self.cache_rows,
            "cache_source": self._source or "not yet read",
            "cache_read_errors": self.cache_read_errors,
            "distinct_entries_seen": len(self._seen),
            "resolutions_emitted": self.entries_emitted,
            # Reported separately from resolutions on purpose: these are hosts-file
            # rows, and counting them as resolutions is the specific error this
            # collector goes out of its way not to make.
            "hosts_file_entries_emitted": self.hosts_entries_emitted,
            "hosts_file_names": len(self._hosts),
            "hosts_file_changes": self.hosts_changes,
            "hosts_file_error": self._hosts_error or "",
            "negative_or_empty_entries": self.negative_entries,
            "baseline_emitted": self.baseline_emitted,
            "dns_client_channel_enabled": channel_enabled(DNS_CLIENT_CHANNEL)[1],
        }


_HOSTNAME = ""


def _hostname() -> str:
    global _HOSTNAME
    if not _HOSTNAME:
        import socket

        try:
            _HOSTNAME = socket.gethostname()
        except Exception:
            _HOSTNAME = "unknown"
    return _HOSTNAME


__all__ = [
    "CACHE_SECTIONS",
    "DNS_CLIENT_CHANNEL",
    "DNS_CLIENT_DATA_MAP",
    "DNS_CLIENT_MAP",
    "DNS_CLIENT_SETUP",
    "DNS_QUERY_TYPES",
    "NOTABLE_QUERY_TYPES",
    "WINDOWS_DNS_STATUS",
    "DnsCacheCollector",
    "DnsClientLogCollector",
    "channel_enabled",
    "dns_status",
    "query_type_name",
    "read_dns_cache",
    "read_hosts_file",
]

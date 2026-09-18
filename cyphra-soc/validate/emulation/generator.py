"""Adversary-emulation event generator — the SOC's proving ground.

Eight attack scenarios, each producing a stream of OCSF events that exercises
the full platform: ingest → enrich → correlate → detect → triage → respond
→ hunt → intel → case → metrics → learn. Every scenario names the function
each event primarily tests, so the operator reading the trace knows *why*
the event is there.

The generator emits events that *look* like they came from real vendor
sources (CloudTrail, Azure Activity Log, Entra ID sign-in, M365 audit,
Defender alerts, EDR process telemetry). They are pre-mapped OCSF — the
emulation path bypasses the vendor connector layer because the goal is to
exercise everything *downstream* of the connector, not the connector
itself. A connector that produces a wrong-shape event from real telemetry
is a defect; the emulation generator cannot prove or disprove that.

Each scenario is a generator function (``gen_…``) that yields events. A
single scenario's events are spread across a chosen window so the platform's
windowing, correlation, and indexing logic has something real to chew on.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from core.schema.ocsf import ClassUid, Severity

# ── helpers ──────────────────────────────────────────────────────────────


def _uid(prefix: str) -> str:
    """A stable-looking unique id, prefixed so traces read as their kind."""
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _ev(
    *,
    class_uid: int,
    time: float,
    severity: int = int(Severity.INFORMATIONAL),
    metadata_uid: str,
    metadata_product_name: str = "Emulation Generator",
    metadata_product_vendor_name: str = "Cyphra SOC",
    activity_name: str = "",
    activity_id: int = 99,
    status_id: int | None = None,
    cloud_provider: str = "",
    actor: Mapping[str, Any] | None = None,
    user: Mapping[str, Any] | None = None,
    api: Mapping[str, Any] | None = None,
    src_endpoint: Mapping[str, Any] | None = None,
    resources: list[Mapping[str, Any]] | None = None,
    findings: list[Mapping[str, Any]] | None = None,
    unmapped: Mapping[str, Any] | None = None,
    metadata_labels: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A minimal OCSF event builder.

    ``actor`` is the OCSF 6003/6005/2004 actor object; ``user`` is the
    OCSF 3002 user object (the 3002 class requires ``user`` *not*
    ``actor``). Passing both is a builder error; the caller picks the one
    that matches the class.

    Defaults are deliberately *minimal* — every required field is set, but
    optional objects (src_endpoint, findings, resources) are only included
    if the caller passes them. This is what makes the generator useful for
    exercising the platform's "missing required object" handling.
    """
    if actor and user:
        raise ValueError(
            "_ev accepts actor OR user, not both — pass the one that matches the "
            f"class_uid={class_uid} (3002 wants user, 6003 wants actor)"
        )
    out: dict[str, Any] = {
        "class_uid": int(class_uid),
        "time": time,
        "severity_id": severity,
        "activity_id": activity_id,
        "activity_name": activity_name or "(unnamed emulation event)",
        "metadata_uid": metadata_uid,
        "metadata_product_name": metadata_product_name,
        "metadata_product_vendor_name": metadata_product_vendor_name,
        "metadata_version": "1.9.0",
    }
    if actor:
        out["actor"] = dict(actor)
    if user:
        out["user"] = dict(user)
    if api:
        out["api"] = dict(api)
    if src_endpoint:
        out["src_endpoint"] = dict(src_endpoint)
    if resources:
        out["resources"] = [dict(r) for r in resources]
    if findings:
        out["finding_info"] = list(findings)
    if status_id is not None:
        out["status_id"] = status_id
    if cloud_provider:
        out["cloud_provider"] = cloud_provider
    if unmapped:
        out["unmapped"] = dict(unmapped)
    if metadata_labels:
        out["metadata_labels"] = list(metadata_labels)
    if metadata:
        for k, v in metadata.items():
            out[f"metadata_{k}"] = v
    return out


def _actor_user(name: str, uid: str = "", email: str = "", domain: str = "") -> dict[str, Any]:
    """The OCSF ``user`` object — for 3002 Authentication and similar."""
    out: dict[str, Any] = {"name": name}
    if uid:
        out["uid"] = uid
    if email:
        out["email_addr"] = email
    if domain:
        out["domain"] = domain
    return out


def _actor(name: str, uid: str = "") -> dict[str, Any]:
    """The OCSF ``actor`` object — for 6003 API Activity and similar."""
    out: dict[str, Any] = {"user": {"name": name}}
    if uid:
        out["user"]["uid"] = uid
    return out


def _src_endpoint(ip: str = "", svc: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if ip:
        out["ip"] = ip
    if svc:
        out["svc_name"] = svc
    return out


def _resource(uid: str, name: str = "", type: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"uid": uid}
    if name:
        out["name"] = name
    if type:
        out["type"] = type
    return out


# ── the eight scenarios ───────────────────────────────────────────────────


@dataclass
class ScenarioResult:
    """A scenario's full output.

    ``events`` is the stream of OCSF events the scenario produces. ``name``
    and ``description`` are reported by :func:`list_scenarios` so an
    operator can pick a scenario by intent. ``covers`` lists the SOC
    functions the scenario primarily exercises.
    """

    name: str
    description: str
    covers: tuple[str, ...]
    events: list[dict[str, Any]]


def _scenario(
    name: str,
    description: str,
    covers: tuple[str, ...],
) -> Callable[[float, float], ScenarioResult]:
    """A decorator that turns a generator function into a named scenario.

    The decorated function receives ``(start_time, end_time)`` and returns
    a fully-built ``ScenarioResult``. The :func:`run_scenarios` entry point
    is what calls them.
    """
    def wrap(fn: Callable[[float, float], Iterable[dict[str, Any]]]) -> Callable[[float, float], ScenarioResult]:
        def inner(start: float, end: float) -> ScenarioResult:
            events = list(fn(start, end))
            return ScenarioResult(
                name=name,
                description=description,
                covers=covers,
                events=events,
            )
        return inner
    return wrap


@_scenario(
    "credential_stuffing",
    "Credential stuffing against a public-facing application, followed by MFA bypass.",
    covers=("collection", "parsing", "normalisation", "enrichment", "correlation", "triage", "compliance"),
)
def _gen_credential_stuffing(start: float, end: float) -> Iterable[dict[str, Any]]:
    """A burst of failed sign-ins from a single IP, then one success."""
    step = (end - start) / 12
    src_ip = "185.220.101.44"
    username = "victim@contoso.com"
    failed_count = 0
    for i in range(10):
        yield _ev(
            class_uid=int(ClassUid.AUTHENTICATION),
            time=start + i * step,
            severity=int(Severity.INFORMATIONAL),
            metadata_uid=_uid("sig"),
            metadata_product_name="Entra ID Sign-in Logs",
            metadata_product_vendor_name="Microsoft",
            cloud_provider="Microsoft Azure",
            actor=_actor_user(username, uid=f"user-{i}", email=username),
            src_endpoint=_src_endpoint(ip=src_ip, svc="login.microsoftonline.com"),
            status_id=2,  # Failure
            activity_id=1,
            activity_name="Sign-in",
            unmapped={"error_code": 50126, "failure_reason": "Invalid username or password"},
        )
        failed_count += 1
    # The successful bypass — same IP, same username, MFA satisfied by an
    # adversary-in-the-middle capture, valid token issued.
    yield _ev(
        class_uid=int(ClassUid.AUTHENTICATION),
        time=start + 10 * step,
        severity=int(Severity.INFORMATIONAL),
        metadata_uid=_uid("sig"),
        metadata_product_name="Entra ID Sign-in Logs",
        metadata_product_vendor_name="Microsoft",
        cloud_provider="Microsoft Azure",
        actor=_actor_user(username, email=username),
        src_endpoint=_src_endpoint(ip=src_ip, svc="login.microsoftonline.com"),
        status_id=1,  # Success
        activity_id=1,
        activity_name="Sign-in",
        unmapped={
            "error_code": 0,
            "mfa_method": "push",
            "mfa_detail": "user responded yes to push",
            "device": {"isCompliant": False, "isManaged": False},
        },
    )


@_scenario(
    "privilege_escalation",
    "Owner role granted to a service principal, with chained KMS key access.",
    covers=("collection", "normalisation", "correlation", "metrics", "respond", "compliance"),
)
def _gen_privilege_escalation(start: float, end: float) -> Iterable[dict[str, Any]]:
    """A bad role grant followed by KMS key access."""
    step = (end - start) / 4
    yield _ev(
        class_uid=int(ClassUid.API_ACTIVITY),
        time=start,
        severity=int(Severity.INFORMATIONAL),
        metadata_uid=_uid("azure-act"),
        metadata_product_name="Azure Activity Log",
        metadata_product_vendor_name="Microsoft",
        cloud_provider="Microsoft Azure",
        actor=_actor("admin@contoso.com", uid="admin-oid"),
        api={"operation": "Microsoft.Authorization/roleAssignments/write"},
        src_endpoint=_src_endpoint(ip="198.51.100.7", svc="Azure Resource Manager"),
        resources=[_resource(
            "/subscriptions/1234/providers/Microsoft.Authorization/roleAssignments/aaaa",
            name="aaaa", type="Microsoft.Authorization/roleAssignments",
        )],
        status_id=1,
        activity_id=3,
        activity_name="Microsoft.Authorization/roleAssignments/write",
        metadata_labels=["tier0-role", "granted-role:owner"],
    )
    yield _ev(
        class_uid=int(ClassUid.API_ACTIVITY),
        time=start + step,
        severity=int(Severity.INFORMATIONAL),
        metadata_uid=_uid("gcp-audit"),
        metadata_product_name="Cloud Audit Logs",
        metadata_product_vendor_name="Google",
        cloud_provider="Google Cloud",
        actor=_actor(
            "deploy-bot@project.iam.gserviceaccount.com",
            uid="sa-deploy-bot",
        ),
        api={
            "operation": "v1.cloudkms.cryptoKeyVersions.destroy",
            "service": {"name": "cloudkms.googleapis.com"},
        },
        src_endpoint=_src_endpoint(ip="203.0.113.7"),
        resources=[_resource(
            "//cloudkms.googleapis.com/projects/p/locations/us-central1/"
            "keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1",
            name="1", type="cloudkms_cryptokeyversion",
        )],
        status_id=1,
        activity_id=4,
        activity_name="v1.cloudkms.cryptoKeyVersions.destroy",
        metadata_labels=["attack:T1485"],
    )


@_scenario(
    "lateral_movement",
    "Successful remote desktop from one workstation to another, then LSASS dump.",
    covers=("collection", "correlation", "detect", "learn"),
)
def _gen_lateral_movement(start: float, end: float) -> Iterable[dict[str, Any]]:
    """RDP session + process telemetry showing credential dumping."""
    step = (end - start) / 3
    yield _ev(
        class_uid=int(ClassUid.AUTHENTICATION),
        time=start,
        severity=int(Severity.INFORMATIONAL),
        metadata_uid=_uid("logon"),
        metadata_product_name="Windows Security",
        metadata_product_vendor_name="Microsoft",
        cloud_provider="",
        actor=_actor_user("alice", uid="alice-sid"),
        src_endpoint=_src_endpoint(ip="10.0.0.50", svc="WIN-EVIL01"),
        status_id=1,
        activity_id=3,
        activity_name="Logon",
        unmapped={"logon_type": 10, "logon_process": "User32", "target": "WIN-VICTIM02"},
    )
    yield _ev(
        class_uid=int(ClassUid.PROCESS_ACTIVITY),
        time=start + step,
        severity=int(Severity.MEDIUM),
        metadata_uid=_uid("proc"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("NT AUTHORITY\\SYSTEM"),
        src_endpoint=_src_endpoint(svc="WIN-VICTIM02"),
        unmapped={
            "process": {"name": "rundll32.exe", "pid": 4321},
            "parent_process": {"name": "svchost.exe", "pid": 1234},
            "command_line": "rundll32.exe comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full",
        },
        metadata_labels=["attack:T1003.001"],
    )
    yield _ev(
        class_uid=int(ClassUid.FILE_SYSTEM_ACTIVITY),
        time=start + 2 * step,
        severity=int(Severity.MEDIUM),
        metadata_uid=_uid("file"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("NT AUTHORITY\\SYSTEM"),
        src_endpoint=_src_endpoint(svc="WIN-VICTIM02"),
        unmapped={
            "file": {"path": "C:\\Windows\\Temp\\lsass.dmp", "size": 12345678},
        },
        metadata_labels=["attack:T1003.001", "credential:dump-file"],
    )


@_scenario(
    "data_exfiltration",
    "Many small downloads from a corporate OneDrive account to a single external IP.",
    covers=("collection", "normalisation", "enrichment", "detect", "respond", "compliance"),
)
def _gen_data_exfiltration(start: float, end: float) -> Iterable[dict[str, Any]]:
    """Drive activity showing bulk download, then DNS resolution to attacker host."""
    step = (end - start) / 12
    user_id = "alice@contoso.com"
    src_ip = "198.51.100.99"
    for i in range(10):
        yield _ev(
            class_uid=int(ClassUid.API_ACTIVITY),
            time=start + i * step,
            severity=int(Severity.INFORMATIONAL),
            metadata_uid=_uid("drive"),
            metadata_product_name="Google Workspace Audit Reports",
            metadata_product_vendor_name="Google",
            cloud_provider="Google Workspace",
            actor=_actor(user_id),
            api={
                "operation": "download",
                "service": {"name": "drive"},
            },
            src_endpoint=_src_endpoint(ip=src_ip),
            resources=[_resource(f"drive-file-{i}", name=f"Q4-Plan.docx", type="drive_file")],
            status_id=1,
            activity_id=2,
            activity_name="download",
            metadata_labels=["exfil:suspect-bulk-download"],
        )


@_scenario(
    "persistence",
    "Scheduled task + service install on a domain controller.",
    covers=("collection", "detect", "respond", "hunt"),
)
def _gen_persistence(start: float, end: float) -> Iterable[dict[str, Any]]:
    """The classic T1053.005 scheduled task + T1543 service install pair."""
    step = (end - start) / 2
    yield _ev(
        class_uid=int(ClassUid.PROCESS_ACTIVITY),
        time=start,
        severity=int(Severity.MEDIUM),
        metadata_uid=_uid("proc"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("evil-admin"),
        src_endpoint=_src_endpoint(svc="DC01"),
        unmapped={
            "process": {"name": "schtasks.exe", "pid": 5000},
            "parent_process": {"name": "cmd.exe", "pid": 4000},
            "command_line": (
                'schtasks /create /tn "Updater" /tr "C:\\Windows\\Temp\\svc.exe" '
                "/sc minute /mo 5 /ru system"
            ),
        },
        metadata_labels=["attack:T1053.005"],
    )
    yield _ev(
        class_uid=int(ClassUid.WINDOWS_SERVICE_ACTIVITY),
        time=start + step,
        severity=int(Severity.MEDIUM),
        metadata_uid=_uid("svc"),
        metadata_product_name="Windows Security",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("evil-admin"),
        src_endpoint=_src_endpoint(svc="DC01"),
        unmapped={
            "service": {
                "name": "WinDefend-Updater",
                "display_name": "Windows Defender Update Helper",
                "binary": "C:\\Windows\\Temp\\svc.exe",
                "start_type": "auto",
            }
        },
        metadata_labels=["attack:T1543.003", "defense-evasion:legit-name"],
    )


@_scenario(
    "defense_evasion",
    "Audit log cleared, Defender disabled, single-event AntiVirus exception.",
    covers=("collection", "detect", "respond", "cases"),
)
def _gen_defense_evasion(start: float, end: float) -> Iterable[dict[str, Any]]:
    """The trio that hides everything else: log clear + AV disable + tamper."""
    step = (end - start) / 3
    yield _ev(
        class_uid=int(ClassUid.PROCESS_ACTIVITY),
        time=start,
        severity=int(Severity.HIGH),
        metadata_uid=_uid("proc"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("evil-admin"),
        src_endpoint=_src_endpoint(svc="DC01"),
        unmapped={
            "process": {"name": "wevtutil.exe", "pid": 6000},
            "parent_process": {"name": "cmd.exe", "pid": 5000},
            "command_line": "wevtutil cl Security",
        },
        metadata_labels=["attack:T1070.001"],
    )
    yield _ev(
        class_uid=int(ClassUid.FILE_SYSTEM_ACTIVITY),
        time=start + step,
        severity=int(Severity.HIGH),
        metadata_uid=_uid("file"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("evil-admin"),
        src_endpoint=_src_endpoint(svc="DC01"),
        unmapped={
            "file": {
                "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "action": "modify",
                "old_content": "# normal hosts file",
                "new_content": "0.0.0.0 telemetry.example.com\n# tampered",
            },
        },
        metadata_labels=["attack:T1565.001"],
    )
    yield _ev(
        class_uid=int(ClassUid.API_ACTIVITY),
        time=start + 2 * step,
        severity=int(Severity.HIGH),
        metadata_uid=_uid("defender"),
        metadata_product_name="Defender for Endpoint",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("evil-admin"),
        api={"operation": "TamperProtection", "service": {"name": "Defender"}},
        src_endpoint=_src_endpoint(svc="DC01"),
        status_id=1,
        activity_id=3,
        activity_name="TamperProtection/Disable",
        metadata_labels=["attack:T1562.001", "defense-evasion:defender"],
    )


@_scenario(
    "initial_access",
    "Phishing email delivered, link clicked, payload staged.",
    covers=("collection", "normalisation", "enrichment", "triage", "intel", "compliance"),
)
def _gen_initial_access(start: float, end: float) -> Iterable[dict[str, Any]]:
    """Email → link click → payload in temp — the opening act."""
    step = (end - start) / 3
    yield _ev(
        class_uid=int(ClassUid.EMAIL_ACTIVITY),
        time=start,
        severity=int(Severity.MEDIUM),
        metadata_uid=_uid("email"),
        metadata_product_name="Office 365 Management Activity API",
        metadata_product_vendor_name="Microsoft",
        cloud_provider="Microsoft 365",
        actor=_actor_user("alice@contoso.com", email="alice@contoso.com"),
        api={"operation": "MailboxItemsAccessed"},
        src_endpoint=_src_endpoint(ip="192.0.2.50"),
        resources=[_resource("email-1", name="Invoice Q4.eml", type="email_message")],
        status_id=1,
        activity_id=1,
        activity_name="MailboxItemsAccessed",
        metadata_labels=["phishing:suspect-sender", "phishing:malicious-link"],
    )
    yield _ev(
        class_uid=int(ClassUid.DNS_ACTIVITY),
        time=start + step,
        severity=int(Severity.HIGH),
        metadata_uid=_uid("net"),
        metadata_product_name="DNS Server",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("alice@contoso.com"),
        src_endpoint=_src_endpoint(ip="10.0.0.42", svc="WIN-ALICE01"),
        unmapped={
            "dns_query": {"name": "evil-example.com", "type": "A"},
            "response": "203.0.113.99",
        },
        metadata_labels=["attack:T1568.002", "initial-access:suspect-domain"],
    )
    yield _ev(
        class_uid=int(ClassUid.FILE_SYSTEM_ACTIVITY),
        time=start + 2 * step,
        severity=int(Severity.HIGH),
        metadata_uid=_uid("file"),
        metadata_product_name="Sysmon",
        metadata_product_vendor_name="Microsoft",
        actor=_actor("alice@contoso.com"),
        src_endpoint=_src_endpoint(svc="WIN-ALICE01"),
        unmapped={
            "file": {
                "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\invoice.exe",
                "action": "create",
                "size": 384512,
                "hashes": {"sha256": "a" * 64},
            },
        },
        metadata_labels=["attack:T1204.002", "initial-access:user-execution"],
    )


@_scenario(
    "c2_beacon",
    "Regular-interval DNS queries to a single suspicious domain over an hour.",
    covers=("collection", "detect", "hunt", "intel"),
)
def _gen_c2_beacon(start: float, end: float) -> Iterable[dict[str, Any]]:
    """A clean periodic beacon — exactly the signal the rate-based detector finds."""
    duration = end - start
    interval = 60.0
    count = int(duration / interval)
    for i in range(count):
        yield _ev(
            class_uid=int(ClassUid.DNS_ACTIVITY),
            time=start + i * interval,
            severity=int(Severity.INFORMATIONAL),
            metadata_uid=_uid("dns"),
            metadata_product_name="DNS Server",
            metadata_product_vendor_name="Microsoft",
            actor=_actor("alice@contoso.com"),
            src_endpoint=_src_endpoint(ip="10.0.0.42", svc="WIN-ALICE01"),
            unmapped={
                "dns_query": {"name": "beacon.evil.example.com", "type": "A"},
                "response": "198.51.100.42",
            },
            metadata_labels=["c2:suspect-beacon", "c2:regular-interval"],
        )


# ── entry points ──────────────────────────────────────────────────────────


_SCENARIOS: dict[str, Callable[[float, float], ScenarioResult]] = {
    "credential_stuffing": _gen_credential_stuffing,
    "privilege_escalation": _gen_privilege_escalation,
    "lateral_movement": _gen_lateral_movement,
    "data_exfiltration": _gen_data_exfiltration,
    "persistence": _gen_persistence,
    "defense_evasion": _gen_defense_evasion,
    "initial_access": _gen_initial_access,
    "c2_beacon": _gen_c2_beacon,
}


def list_scenarios() -> list[ScenarioResult]:
    """All scenarios, with their descriptions, names, and coverage."""
    out = []
    for name, fn in _SCENARIOS.items():
        # Probe the scenario at a 1-second window to read its metadata.
        result = fn(0.0, 1.0)
        out.append(ScenarioResult(
            name=result.name,
            description=result.description,
            covers=result.covers,
            events=[],
        ))
    return out


def run_scenario(name: str, start: float, end: float) -> ScenarioResult:
    """Run a named scenario over a time window.

    A window of seconds (not a single instant) so the platform's windowing,
    correlation, and indexing logic has something real to chew on. The
    caller picks the window length; an hour is the usual choice.
    """
    if name not in _SCENARIOS:
        raise KeyError(f"unknown scenario {name!r}; known: {sorted(_SCENARIOS)}")
    return _SCENARIOS[name](start, end)


def run_all(start: float, end: float) -> list[ScenarioResult]:
    """Every scenario, in declaration order."""
    return [fn(start, end) for fn in _SCENARIOS.values()]


def write_ndjson(path: str, scenarios: Iterable[ScenarioResult]) -> int:
    """Dump the events from ``scenarios`` to ``path`` as NDJSON; return count.

    The file format is line-delimited JSON, one OCSF event per line. This
    is what the platform's replay path consumes; the format is the same as
    the agent's spool so the platform does not need a separate code path
    for emulation vs real agent input.
    """
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for scenario in scenarios:
            for event in scenario.events:
                f.write(json.dumps(event, default=str, separators=(",", ":")))
                f.write("\n")
                count += 1
    return count


__all__ = [
    "ScenarioResult",
    "list_scenarios",
    "run_all",
    "run_scenario",
    "write_ndjson",
]

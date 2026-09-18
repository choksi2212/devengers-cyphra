"""Network flow collector — live packet capture into OCSF Network Activity events.

This wraps the existing :class:`~machine_learning.inference_service.packet_capture.FlowEngine`
rather than reimplementing capture. That engine already does the hard part: scapy
sniffing, bidirectional flow assembly on the 5-tuple, idle eviction, and the 74
timing/size features GhostFlow_GBDT was trained on. Rewriting it would produce a
second feature extractor whose numbers drift from the model's training
distribution, and a model scored on features computed differently from how it was
trained is a model with no known accuracy at all.

What this module adds is the part a SOC needs and an IDS did not:

**The flow becomes an event with an identity.** ``extract_features`` returns
scalars only — no addresses, no timestamps — because its output is a model input
vector. A detection that cannot say *which conversation* it is about cannot be
correlated, enriched, or acted on. So the identity keys the engine now attaches
(``_src_ip``, ``_dst_ip``, ``_start_time``, …) are mapped onto OCSF Network
Activity fields, and the 74 features ride along in ``unmapped`` so the detection
engine can score the same event the model would.

**The features are preserved exactly, not re-derived.** They go into the event
verbatim under their canonical training names. Phase 2's ML detector reads them
back out of the lake and feeds them to the model unchanged, which makes a scored
event replayable: the same row produces the same score months later.

**Direction is inferred, not assumed.** ``FlowEngine`` keys a flow on whoever sent
the first packet, which is usually but not always the initiator. OCSF wants a
``src_endpoint``/``dst_endpoint`` pair where src is the initiator, and getting it
backwards inverts every "outbound to the internet" rule in the detection library.
:func:`_orient` resolves it from RFC1918 membership and port privilege, and records
in the event's notes when it had to guess — because a rule that fires on direction
should be auditable on how direction was decided.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import (
    Availability,
    PushCollector,
    available,
    is_admin,
    unavailable,
)

#: Where the existing capture engine lives, relative to the repo root. Added to
#: ``sys.path`` on demand rather than at import: this module is imported during
#: setup reporting on hosts where scapy cannot load, and an import-time failure
#: there would take down the whole fleet listing instead of reporting one
#: unavailable collector.
_ML_SERVICE = Path(__file__).resolve().parents[3] / "machine_learning" / "inference_service"

#: IANA protocol numbers the engine records, mapped to the names OCSF expects.
_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}

#: Feature keys the engine attaches for identity rather than for scoring. They are
#: consumed here and must not be forwarded as features.
_IDENTITY_KEYS = frozenset(
    {
        "_src_ip",
        "_dst_ip",
        "_src_port",
        "_dst_port",
        "_protocol",
        "_start_time",
        "_last_seen",
        "_fwd_packets",
        "_bwd_packets",
        "_iface",
    }
)


def _is_private(ip: str) -> bool:
    """RFC1918 / loopback / link-local, without importing ipaddress per flow.

    Called once per flow on the ingest path, so it is a string test rather than an
    ``ipaddress`` object construction — the latter is roughly 20x the cost and this
    runs on every completed flow on a busy interface.
    """
    if ip.startswith(("10.", "127.", "192.168.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
        except (ValueError, IndexError):
            return False
        return 16 <= second <= 31
    # IPv6 unique-local and loopback.
    return ip == "::1" or ip.lower().startswith(("fc", "fd", "fe80"))


def _orient(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int
) -> tuple[str, str, int, int, bool, str]:
    """Decide which end initiated, returning ``(src, dst, sport, dport, swapped, why)``.

    Three signals, in order of how much they actually tell you:

    1. **Private → public.** A host on this network talking to the internet is the
       initiator in nearly every case a SOC cares about, and the exceptions
       (inbound to a published service) are separated by the next signal.
    2. **Port privilege.** A connection between a low port and a high port was
       initiated by the high port; that is how ephemeral source ports work.
    3. **Neither applies** — both ends private, both ports high, or both low. Then
       the engine's first-packet ordering is kept and the reason says so, because
       an invented answer that a rule then depends on is worse than an admitted
       uncertainty.
    """
    src_priv, dst_priv = _is_private(src_ip), _is_private(dst_ip)
    if src_priv != dst_priv:
        if dst_priv and not src_priv:
            return dst_ip, src_ip, dst_port, src_port, True, "inbound from public"
        return src_ip, dst_ip, src_port, dst_port, False, "outbound to public"
    if (src_port < 1024) != (dst_port < 1024):
        if src_port < 1024:
            return dst_ip, src_ip, dst_port, src_port, True, "ephemeral port initiated"
        return src_ip, dst_ip, src_port, dst_port, False, "ephemeral port initiated"
    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        False,
        "direction assumed from first packet — both ends and both ports are "
        "symmetric, so initiator is not determinable from headers alone",
    )


class NetworkFlowCollector(PushCollector):
    """Completed network flows from the live interface.

    Push-shaped because that is what capture is: scapy calls back whenever a flow
    idles out, at whatever rate the network produces. The base class's bounded
    buffer is what stands between a traffic burst and an out-of-memory kill.
    """

    name = "network_flow"
    cadence_seconds = 10.0
    critical = True
    description = (
        "Live packet capture on one interface, assembled into bidirectional flows "
        "with the 74 features GhostFlow_GBDT scores"
    )

    def __init__(self, pipeline: Any, *, iface: str = "Wi-Fi", **kwargs: Any) -> None:
        super().__init__(pipeline, **kwargs)
        self.iface = iface
        self.engine: Any = None
        #: Flows whose direction could not be determined from headers. Counted
        #: because a detection library full of directional rules deserves to know
        #: how often the input was a coin flip.
        self.ambiguous_direction = 0

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        """Capture needs scapy, a packet driver, and elevation. Say which is missing.

        Each is reported separately with its own fix. A single "capture
        unavailable" would leave the operator to work out whether to install
        Npcap, install scapy, or reopen the shell — and the commonest outcome of
        that is that they do none of them.
        """
        if not _ML_SERVICE.is_dir():
            return unavailable(
                f"the capture engine is not on disk at {_ML_SERVICE} — this collector "
                "wraps machine_learning/inference_service/packet_capture.py",
                fixable_by_user=False,
            )
        try:
            import scapy  # noqa: F401
        except Exception as exc:
            return unavailable(f"scapy is not importable ({exc}); pip install scapy")

        # Npcap/WinPcap presence, checked the way scapy itself discovers it. A
        # missing driver is the single commonest reason capture fails on Windows,
        # and it fails at *sniff* time — an hour after start, with the collector
        # showing green until then.
        try:
            from scapy.arch import get_if_list

            ifaces = list(get_if_list())
        except Exception as exc:
            return unavailable(
                f"no packet capture driver: scapy cannot enumerate interfaces ({exc}). "
                "On Windows install Npcap from https://npcap.com (tick 'WinPcap API "
                "compatible mode'); on Linux install libpcap."
            )
        if not ifaces:
            return unavailable(
                "a capture driver is present but reports zero interfaces, which "
                "usually means Npcap was installed without WinPcap compatibility "
                "mode — reinstall from https://npcap.com with that box ticked"
            )
        if not is_admin():
            return unavailable(
                "packet capture requires elevation — run this process from a shell "
                "started with 'Run as administrator' (Windows) or under sudo/with "
                "CAP_NET_RAW (Linux). Without it scapy binds but receives nothing, "
                "which looks exactly like a quiet network."
            )
        return available()

    # ── the underlying capture ─────────────────────────────────────────────

    def start_source(self) -> None:
        if str(_ML_SERVICE) not in sys.path:
            sys.path.insert(0, str(_ML_SERVICE))
        from packet_capture import FlowEngine  # type: ignore[import-not-found]

        self.engine = FlowEngine(iface=self.iface)
        # `offer` is thread-safe and non-blocking by contract, which is exactly what
        # this callback has to be: the engine invokes it off the packet path and a
        # callback that blocked would build a backlog inside the capture thread
        # where nothing can see it.
        self.engine.start(callback=self._on_flow)

    def stop_source(self) -> None:
        if self.engine is not None:
            self.engine.stop()

    def _on_flow(self, features: dict[str, Any]) -> None:
        """Called by FlowEngine, on its own thread, per completed flow."""
        try:
            payload = self._to_event(features)
        except Exception:
            # A malformed feature dict must not kill the capture thread. It is
            # counted as a drop rather than silently ignored, so a systematic
            # mapping failure shows as loss instead of as a quiet network.
            self.stats.dropped += 1
            return
        self.offer(payload)

    # ── mapping ────────────────────────────────────────────────────────────

    def _to_event(self, f: dict[str, Any]) -> dict[str, Any]:
        """One completed flow → one OCSF Network Activity payload."""
        src_ip = str(f.get("_src_ip") or "")
        dst_ip = str(f.get("_dst_ip") or "")
        if not src_ip or not dst_ip:
            # Refusing here rather than substituting a placeholder. An event whose
            # endpoints are "?" cannot be correlated or acted on, and storing it
            # would inflate every coverage number with rows nothing can use.
            raise ValueError(
                "flow has no addresses; packet_capture must attach _src_ip/_dst_ip"
            )
        sport = int(f.get("_src_port") or 0)
        dport = int(f.get("_dst_port") or 0)
        proto_num = int(f.get("_protocol") or 0)
        start = float(f.get("_start_time") or 0.0)
        end = float(f.get("_last_seen") or start)

        s_ip, d_ip, s_port, d_port, swapped, why = _orient(src_ip, dst_ip, sport, dport)
        notes = []
        if "not determinable" in why:
            self.ambiguous_direction += 1
            notes.append(why)
        elif swapped:
            notes.append(f"endpoints oriented by initiator: {why}")

        fwd = int(f.get("_fwd_packets") or 0)
        bwd = int(f.get("_bwd_packets") or 0)
        fwd_bytes = float(f.get("total_length_fwd_packets") or 0.0)
        bwd_bytes = float(f.get("total_length_bwd_packets") or 0.0)
        if swapped:
            # The byte and packet counts are keyed to the engine's forward
            # direction. Swapping the endpoints without swapping these would make
            # every exfiltration rule read the wrong number, which is the kind of
            # bug that produces a confidently wrong verdict.
            fwd, bwd = bwd, fwd
            fwd_bytes, bwd_bytes = bwd_bytes, fwd_bytes

        features = {k: v for k, v in f.items() if k not in _IDENTITY_KEYS}

        payload: dict[str, Any] = {
            # `time` is when the flow *started*, not when it was evicted. A flow
            # that ran for four minutes and idled out is an event at its start:
            # timing it at eviction would put a slow scan four minutes after the
            # traffic it consists of, and every correlation window would miss it.
            "time": start or None,
            "start_time": start or None,
            "end_time": end,
            "duration": max(0.0, (end - start) * 1000.0),
            "class_uid": int(ClassUid.NETWORK_ACTIVITY),
            "activity_id": 6,  # Traffic
            "severity_id": int(Severity.INFORMATIONAL),
            "src_endpoint_ip": s_ip,
            "src_endpoint_port": s_port,
            "dst_endpoint_ip": d_ip,
            "dst_endpoint_port": d_port,
            "connection_protocol_num": proto_num,
            "connection_protocol_name": _PROTO_NAMES.get(proto_num, str(proto_num)),
            "traffic_packets_out": fwd,
            "traffic_packets_in": bwd,
            "traffic_bytes_out": fwd_bytes,
            "traffic_bytes_in": bwd_bytes,
            "device_hostname": _hostname(),
            "device_interface_name": str(f.get("_iface") or self.iface),
            "metadata_labels": ["live_capture"],
            # The 74 features, verbatim under their training names. Phase 2 scores
            # the event from these; keeping them means a stored event can be
            # re-scored by a later model and the two scores compared.
            "unmapped": features,
        }
        if notes:
            payload["notes"] = notes
        return payload

    def stats_extra(self) -> dict[str, Any]:
        """Capture-engine numbers the base class knows nothing about."""
        out: dict[str, Any] = {
            "iface": self.iface,
            "ambiguous_direction": self.ambiguous_direction,
        }
        if self.engine is not None:
            try:
                out.update(self.engine.get_stats())
            except Exception as exc:
                out["engine_stats_error"] = f"{type(exc).__name__}: {exc}"
        return out


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


__all__ = ["NetworkFlowCollector", "_is_private", "_orient"]

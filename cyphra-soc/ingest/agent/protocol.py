"""Wire protocol between the agent on a host and the core.

The protocol is deliberately tiny. Every message has the same shape:

    {
      "type": "<one of the message kinds below>",
      "agent_id": "<stable identifier assigned at enrollment>",
      "seq": <monotonic uint64, never reused in this session>,
      "sent_at": <float seconds since epoch, UTC>,
      "data": { … kind-specific … }
    }

Length-prefixed framing on the wire: a single unsigned varint carrying the
JSON message length in bytes, followed by that many bytes of UTF-8 encoded
JSON. The framing is the same in both directions and on every connection —
the only difference between agent→core and core→agent is which kinds of
messages travel each way.

Five message kinds cover everything the protocol needs to do:

* ``hello`` — first message on a new connection. Carries the agent's id,
  hostname, platform, and a session nonce. The core responds with
  ``welcome`` (or ``enroll_required`` if the agent is unknown).
* ``welcome`` — core's reply to ``hello``. Carries the protocol version,
  the heartbeat interval, and the current batch quota.
* ``enroll_request`` — first message from a brand-new agent with no id.
  Carries a one-time enrollment token issued out-of-band by the operator
  and the agent's public-key CSR. The core responds with ``enroll_grant``
  (signed certificate + agent_id).
* ``enroll_grant`` — core's reply to ``enroll_request``. Carries the
  agent_id, the signed certificate (PEM), and the CA bundle (PEM).
* ``batch`` — agent's payload. Carries a list of events, each one a
  pre-validated OCSF payload (the agent never sends raw vendor bytes; the
  mapping has already happened). The core responds with ``batch_ack``
  carrying the sequence numbers it persisted.
* ``batch_ack`` — core's reply to ``batch``. Carries the agent_seq of each
  event it persisted; the agent deletes the corresponding spool entries.
* ``heartbeat`` — agent's liveness signal. The core replies with
  ``heartbeat_ack`` so the agent's spool-write backoff knows the connection
  is still live.

The protocol never carries *what* the agent is doing — only that it is
doing it. A core that depends on message contents to make policy decisions
is a core that is fooled by the contents. The trust boundary is the mTLS
certificate, not the message bytes.
"""

from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

PROTOCOL_VERSION = 1

#: Heartbeat the core expects. The agent must send at least one heartbeat
#: per interval or be considered dead.
HEARTBEAT_SECONDS = 30.0

#: Maximum batch size, in events. A batch larger than this is split into
#: several frames; the agent never sends a frame that exceeds it.
MAX_BATCH_EVENTS = 500

#: Maximum single frame size in bytes. Frames larger than this are rejected
#: by the reader and the connection is closed; the agent's spool layer
#: handles the split.
MAX_FRAME_BYTES = 4 * 1024 * 1024  # 4 MiB


@dataclass
class Envelope:
    """A single message on the wire, common envelope for every kind.

    ``seq`` is a strict monotonic per-connection counter — the core uses it
    to drop duplicates (re-sent after a TCP-level flap) and to detect
    message loss. ``agent_id`` is the certificate subject's common name;
    it is also carried in the mTLS handshake so a malformed envelope with
    a wrong ``agent_id`` is rejected at the protocol layer, not silently
    trusted.
    """

    type: str
    agent_id: str
    seq: int
    sent_at: float
    data: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        """Serialize to a length-prefixed frame."""
        body = json.dumps(asdict(self), separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_FRAME_BYTES:
            raise ValueError(
                f"frame body {len(body)} bytes exceeds MAX_FRAME_BYTES "
                f"{MAX_FRAME_BYTES}"
            )
        header = struct.pack(">I", len(body))
        return header + body

    @classmethod
    def decode(cls, body: bytes) -> "Envelope":
        """Parse a frame body into an envelope; ``read_frame`` handles the header."""
        obj = json.loads(body.decode("utf-8"))
        if not isinstance(obj, Mapping):
            raise ValueError("frame body is not a JSON object")
        try:
            return cls(
                type=str(obj["type"]),
                agent_id=str(obj["agent_id"]),
                seq=int(obj["seq"]),
                sent_at=float(obj["sent_at"]),
                data=dict(obj.get("data") or {}),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"frame body is missing required fields: {exc}") from exc


def read_frame(reader: Any) -> Envelope:
    """Read one length-prefixed frame from ``reader``.

    ``reader`` is anything with ``read(n)`` returning bytes (an
    ``asyncio.StreamReader`` is the intended target). Raises
    :class:`ValueError` on a malformed header, ``EOFError`` on a clean close.
    """
    header = reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"frame header claims {length} bytes; cap is {MAX_FRAME_BYTES}")
    body = reader.readexactly(length)
    return Envelope.decode(body)


def hello(agent_id: str, seq: int, sent_at: float, *, hostname: str, platform: str) -> Envelope:
    """A first-on-connection message from the agent."""
    return Envelope(
        type="hello",
        agent_id=agent_id,
        seq=seq,
        sent_at=sent_at,
        data={"hostname": hostname, "platform": platform},
    )


def welcome(agent_id: str, seq: int, sent_at: float, *, heartbeat_seconds: float, batch_quota: int) -> Envelope:
    """The core's reply to ``hello``."""
    return Envelope(
        type="welcome",
        agent_id=agent_id,
        seq=seq,
        sent_at=sent_at,
        data={
            "protocol_version": PROTOCOL_VERSION,
            "heartbeat_seconds": heartbeat_seconds,
            "batch_quota": batch_quota,
        },
    )


def enroll_request(seq: int, sent_at: float, *, token: str, hostname: str, platform: str, csr_pem: str) -> Envelope:
    """An unknown agent's first message — carries the enrollment token + CSR."""
    return Envelope(
        type="enroll_request",
        agent_id="",
        seq=seq,
        sent_at=sent_at,
        data={
            "token": token,
            "hostname": hostname,
            "platform": platform,
            "csr_pem": csr_pem,
        },
    )


def enroll_grant(seq: int, sent_at: float, *, agent_id: str, certificate_pem: str, ca_bundle_pem: str) -> Envelope:
    """The core's reply to ``enroll_request``."""
    return Envelope(
        type="enroll_grant",
        agent_id=agent_id,
        seq=seq,
        sent_at=sent_at,
        data={"certificate_pem": certificate_pem, "ca_bundle_pem": ca_bundle_pem},
    )


def batch(agent_id: str, seq: int, sent_at: float, *, events: list[Mapping[str, Any]]) -> Envelope:
    """An agent's payload — events that have already been mapped to OCSF."""
    if len(events) > MAX_BATCH_EVENTS:
        raise ValueError(
            f"batch carries {len(events)} events; cap is {MAX_BATCH_EVENTS}"
        )
    return Envelope(
        type="batch",
        agent_id=agent_id,
        seq=seq,
        sent_at=sent_at,
        data={"events": list(events)},
    )


def batch_ack(agent_id: str, seq: int, sent_at: float, *, persisted_seqs: list[int]) -> Envelope:
    """The core's reply to ``batch`` — sequences that landed in the lake."""
    return Envelope(
        type="batch_ack",
        agent_id=agent_id,
        seq=seq,
        sent_at=sent_at,
        data={"persisted_seqs": list(persisted_seqs)},
    )


def heartbeat(agent_id: str, seq: int, sent_at: float) -> Envelope:
    """Liveness signal — no payload."""
    return Envelope(type="heartbeat", agent_id=agent_id, seq=seq, sent_at=sent_at, data={})


def heartbeat_ack(agent_id: str, seq: int, sent_at: float) -> Envelope:
    return Envelope(type="heartbeat_ack", agent_id=agent_id, seq=seq, sent_at=sent_at, data={})


__all__ = [
    "Envelope",
    "HEARTBEAT_SECONDS",
    "MAX_BATCH_EVENTS",
    "MAX_FRAME_BYTES",
    "PROTOCOL_VERSION",
    "batch",
    "batch_ack",
    "enroll_grant",
    "enroll_request",
    "heartbeat",
    "heartbeat_ack",
    "hello",
    "read_frame",
    "welcome",
]

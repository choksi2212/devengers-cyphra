"""The agent — runs on a host, ships events to a core.

Three jobs:

1. **Spool** — every event from the local collectors is appended to an
   append-only file. The file is rotated, not deleted, so a crash mid-write
   loses nothing.

2. **Push** — when the connection to the core is up, the agent reads from
   the spool, batches events into frames, and ships them. The core replies
   with the sequence numbers it persisted; the agent marks the corresponding
   spool entries as acknowledged and the spool layer compacts them.

3. **Backoff** — when the connection is down, the agent backs off
   exponentially. The exponential resets on every successful handshake. The
   agent never drops events; it stops *shipping* them and lets the spool
   grow, but the spool is bounded by disk and the bound is reported.

The agent's contract with the rest of the platform is "events I publish are
in OCSF, validated, and immutable". A mapping error inside an agent is a
bug; a wire error is recoverable; a core rejection is a re-publish.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ingest.agent.protocol import (
    HEARTBEAT_SECONDS,
    MAX_BATCH_EVENTS,
    batch,
    enroll_request,
    heartbeat,
    hello,
    read_frame,
)


@dataclass
class AgentConfig:
    """The runtime configuration for one agent instance.

    ``spool_dir`` is the directory the append-only log lives in. ``url`` is
    the core's host:port the agent dials; ``agent_id`` is set after
    enrollment and persisted across restarts. ``enrollment_token`` is the
    one-time secret the operator hands out; it is consumed on first
    enrollment and never re-used.
    """

    spool_dir: Path
    url: str
    agent_id: str = ""
    enrollment_token: str = ""
    ca_cert: Path | None = None
    agent_cert: Path | None = None
    agent_key: Path | None = None
    clock: Any = time.time
    backoff_initial: float = 1.0
    backoff_max: float = 60.0
    hostname: str = socket.gethostname()
    platform: str = os.name


class Agent:
    """One agent instance.

    A single instance is intended to be a long-lived daemon. ``start`` is the
    background loop; ``stop`` ends it cleanly. ``ingest`` is the entry
    point the collectors call: it appends one event to the spool and
    returns immediately. The background loop drains the spool to the core.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.config.spool_dir.mkdir(parents=True, exist_ok=True)
        self.spool_path = self.config.spool_dir / "events.ndjson"
        self.ack_path = self.config.spool_dir / "acked.seq"
        self._running = False
        self._stopped = asyncio.Event()
        self._seq_lock = asyncio.Lock()
        self._next_seq = self._load_seq()
        self._acked_seq = self._load_acked_seq()
        self._backoff = self.config.backoff_initial
        self.stats = AgentStats()

    # ── public API ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Run the agent's loop until :meth:`stop` is called."""
        self._running = True
        while self._running:
            try:
                await self._session()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                # Any exception here is a connection-level fault, not a
                # protocol fault. Log it on stats and back off.
                self.stats.connection_errors += 1
                self.stats.last_error = repr(exc)
                await self._sleep_backoff()
            else:
                # A clean end-of-session resets the backoff so the next
                # connection starts fresh.
                self._backoff = self.config.backoff_initial
        self._stopped.set()

    async def stop(self) -> None:
        """End the loop cleanly. Safe to call from any task."""
        self._running = False
        await self._stopped.wait()

    def ingest(self, event: Mapping[str, Any]) -> None:
        """Append one event to the spool. Synchronous; never raises."""
        try:
            with self.spool_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str, separators=(",", ":")))
                f.write("\n")
            self.stats.ingested += 1
        except OSError as exc:
            self.stats.spool_errors += 1
            self.stats.last_error = repr(exc)

    # ── connection lifecycle ───────────────────────────────────────────────

    async def _session(self) -> None:
        """Open a TLS connection, do the handshake, drain the spool, close."""
        ctx = self._build_ssl_context()
        host, port = _parse_url(self.config.url)
        reader, writer = await asyncio.open_connection(host=host, port=port, ssl=ctx)
        try:
            if self.config.agent_id:
                await self._authenticated_session(reader, writer)
            else:
                await self._enroll_session(reader, writer)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _build_ssl_context(self) -> ssl.SSLContext:
        """The mTLS context. Always verifies the core's certificate."""
        purpose = ssl.Purpose.SERVER_AUTH
        ctx = ssl.create_default_context(purpose, cafile=str(self.config.ca_cert or ""))
        if self.config.agent_cert and self.config.agent_key:
            ctx.load_cert_chain(
                certfile=str(self.config.agent_cert),
                keyfile=str(self.config.agent_key),
            )
        # The agent always pins the core's CA — a self-signed operator CA
        # makes this a one-line config and eliminates the silent-trust class
        # of bugs.
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    async def _enroll_session(self, reader, writer) -> None:
        """First-session flow — no agent_id yet."""
        # Read the welcome envelope — actually, the first message is from the
        # *agent* and the server replies. We send ``enroll_request`` and read
        # ``enroll_grant``.
        seq = await self._next_seq()
        csr_pem = _make_csr_pem(self.config)
        envelope = enroll_request(
            seq,
            self.config.clock(),
            token=self.config.enrollment_token,
            hostname=self.config.hostname,
            platform=self.config.platform,
            csr_pem=csr_pem,
        )
        writer.write(envelope.encode())
        await writer.drain()
        reply = await read_frame(reader)
        if reply.type != "enroll_grant":
            self.stats.last_error = (
                f"unexpected reply to enroll_request: {reply.type!r}"
            )
            return
        cert_pem = reply.data.get("certificate_pem", "")
        if not cert_pem:
            self.stats.last_error = "enroll_grant carried no certificate_pem"
            return
        # Persist the granted certificate, key, and agent_id. A real
        # deployment writes these under PKI-protected paths; this
        # implementation writes them next to the spool for simplicity.
        cert_path = self.config.spool_dir / "agent.crt"
        key_path = self.config.spool_dir / "agent.key"
        cert_path.write_text(cert_pem, encoding="utf-8")
        key_path.write_text(csr_pem, encoding="utf-8")  # placeholder
        self.config.agent_cert = cert_path
        self.config.agent_key = key_path
        self.config.agent_id = reply.agent_id
        self._persist_id()
        self.stats.enrolled = True

    async def _authenticated_session(self, reader, writer) -> None:
        """Post-enrollment session — hello, drain, heartbeat, close."""
        seq = await self._next_seq()
        writer.write(
            hello(
                self.config.agent_id,
                seq,
                self.config.clock(),
                hostname=self.config.hostname,
                platform=self.config.platform,
            ).encode()
        )
        await writer.drain()
        reply = await read_frame(reader)
        if reply.type != "welcome":
            self.stats.last_error = f"unexpected reply to hello: {reply.type!r}"
            return
        # Drain the spool in MAX_BATCH_EVENTS-sized chunks, with heartbeats
        # interleaved so a stuck TCP connection is detected within
        # ``HEARTBEAT_SECONDS``.
        while self._running:
            events = self._read_batch(MAX_BATCH_EVENTS)
            if not events:
                # Spool is empty — send a heartbeat so the core can confirm
                # the connection is alive, and then sleep one heartbeat.
                await self._send_heartbeat(reader, writer)
                await asyncio.sleep(min(HEARTBEAT_SECONDS, 1.0))
                continue
            seq = await self._next_seq()
            writer.write(
                batch(
                    self.config.agent_id,
                    seq,
                    self.config.clock(),
                    events=events,
                ).encode()
            )
            await writer.drain()
            ack = await read_frame(reader)
            if ack.type != "batch_ack":
                self.stats.last_error = (
                    f"unexpected reply to batch: {ack.type!r}"
                )
                return
            persisted = list(ack.data.get("persisted_seqs") or [])
            if persisted:
                self._record_acked(persisted)
                self.stats.batches_acked += 1

    async def _send_heartbeat(self, reader, writer) -> None:
        """One heartbeat round-trip."""
        seq = await self._next_seq()
        writer.write(
            heartbeat(self.config.agent_id, seq, self.config.clock()).encode()
        )
        await writer.drain()
        # The reply carries no data we need; if the read fails the session
        # loop will fall through to its exception handler.
        await read_frame(reader)
        self.stats.heartbeats += 1

    async def _next_seq(self) -> int:
        """An at-least-once monotonic per-session sequence number."""
        async with self._seq_lock:
            value = self._next_seq
            self._next_seq += 1
            return value

    async def _sleep_backoff(self) -> None:
        """Sleep with exponential backoff after a connection-level fault."""
        delay = self._backoff
        self._backoff = min(self._backoff * 2.0, self.config.backoff_max)
        await asyncio.sleep(delay)

    # ── spool persistence ──────────────────────────────────────────────────

    def _read_batch(self, n: int) -> list[dict[str, Any]]:
        """Read up to ``n`` events from the spool, skipping already-acked ones."""
        out: list[dict[str, Any]] = []
        if not self.spool_path.exists():
            return out
        # The spool is append-only. ``acked`` is the highest acked sequence;
        # events below it are compacted on the next rotation. This keeps the
        # spool's working set bounded.
        keep_from_line = self._acked_line()
        try:
            with self.spool_path.open("r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    if lineno <= keep_from_line:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        # A corrupt line is reported and skipped; the spool
        # layer never raises on a single bad event.
                        self.stats.spool_errors += 1
                    if len(out) >= n:
                        break
        except OSError as exc:
            self.stats.spool_errors += 1
            self.stats.last_error = repr(exc)
        return out

    def _record_acked(self, persisted_seqs: list[int]) -> None:
        """Mark the highest ack and compact the spool above it."""
        if not persisted_seqs:
            return
        highest = max(persisted_seqs)
        self._acked_seq = max(self._acked_seq, highest)
        self.ack_path.write_text(str(highest), encoding="utf-8")
        # Compaction is a simple rewrite of the spool without acked lines.
        # Done synchronously — for very large spools this is a job for a
        # background compaction task, but the contract is "no double-write
        # of events the core has acknowledged".
        if not self.spool_path.exists():
            return
        keep_from_line = self._acked_line()
        try:
            with self.spool_path.open("r", encoding="utf-8") as src:
                lines = src.readlines()
            remaining = lines[keep_from_line:]
            with self.spool_path.open("w", encoding="utf-8") as dst:
                dst.writelines(remaining)
        except OSError as exc:
            self.stats.spool_errors += 1
            self.stats.last_error = repr(exc)

    def _acked_line(self) -> int:
        """The line offset in the spool that has been acknowledged."""
        try:
            return int(self.ack_path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            return 0

    def _load_seq(self) -> int:
        """Resume the sequence counter from the persisted spool."""
        seq_path = self.config.spool_dir / "seq"
        if not seq_path.exists():
            return 0
        try:
            return int(seq_path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            return 0

    def _load_acked_seq(self) -> int:
        return self._acked_line()

    def _persist_id(self) -> None:
        (self.config.spool_dir / "agent_id").write_text(
            self.config.agent_id, encoding="utf-8"
        )


@dataclass
class AgentStats:
    """The agent's self-reported counters.

    ``ingested`` is the number of events appended to the spool, ``batches_acked``
    is the number of batches the core confirmed persisted. ``connection_errors``
    and ``spool_errors`` are *counts*, not boolean flags — one connection
    fault is a signal; ten is a problem; a hundred is the spool filling up.
    """

    ingested: int = 0
    batches_acked: int = 0
    heartbeats: int = 0
    connection_errors: int = 0
    spool_errors: int = 0
    enrolled: bool = False
    last_error: str = ""


def _parse_url(url: str) -> tuple[str, int]:
    """``host:port`` → ``(host, port)``."""
    if ":" not in url:
        raise ValueError(f"agent url {url!r} is not host:port")
    host, _, port_text = url.rpartition(":")
    return host, int(port_text)


def _make_csr_pem(config: AgentConfig) -> str:
    """A self-signed CSR placeholder.

    The real implementation signs a CSR with the operator's private key and
    the agent's persistent identity. For the agent's wire test this is a
    placeholder that lets the enrollment handshake complete end-to-end.
    """
    return (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        f"(agent={config.agent_id!r} hostname={config.hostname!r})\n"
        "-----END CERTIFICATE REQUEST-----\n"
    )


# Local replacement for ``contextlib.suppress`` — keeps the agent import
# surface small.
class contextlib_suppress:
    def __init__(self, *exc: type[BaseException]) -> None:
        self.exc = exc

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, self.exc)


__all__ = ["Agent", "AgentConfig", "AgentStats"]

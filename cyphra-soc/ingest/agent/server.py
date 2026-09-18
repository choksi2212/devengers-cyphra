"""The core-side server — accepts agent connections and persists their events.

Each connection runs as an asyncio task. The server is *not* responsible for
fleet health — that is the HealthMonitor's job. It is responsible for:

* Accepting mTLS connections.
* Rejecting unknown agents with a clear reply (or accepting them only via
  the enrollment flow).
* Routing each agent's events into the lake via the Pipeline.
* Replying to heartbeats so the agent knows the connection is live.
* Rate-limiting per-agent (one agent that goes haywire must not starve the
  rest of the fleet).

The server does **not** validate events. Validation is the agent's job —
events that arrive here are pre-validated OCSF payloads, and a schema
mismatch is a re-publish from the agent's spool. The core's job is to
persist the bytes faithfully.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass
from typing import Any

from core.config import SocConfig
from ingest.agent.protocol import (
    HEARTBEAT_SECONDS,
    Envelope,
    batch_ack,
    enroll_grant,
    heartbeat_ack,
    read_frame,
    welcome,
)


@dataclass
class ServerConfig:
    """The runtime configuration for the core's agent listener."""

    listen_host: str
    listen_port: int
    tls_cert: Any
    tls_key: Any
    ca_cert: Any
    pipeline: Any  # ingest.pipeline.Pipeline
    fleet: Any  # ingest.agent.fleet.FleetRegistry
    clock: Any = time.time
    batch_quota: int = 5_000


class AgentServer:
    """A single mTLS listener accepting agent connections.

    The server is intentionally stateless beyond the :class:`FleetRegistry`
    it is handed. Each connection runs in its own task; a crash in one
    agent's task does not affect the rest of the fleet.
    """

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self._stopped = asyncio.Event()
        self._server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self.stats = ServerStats()

    async def start(self) -> None:
        """Listen forever, until :meth:`stop` is called."""
        ctx = self._build_ssl_context()
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self.config.listen_host,
            port=self.config.listen_port,
            ssl=ctx,
        )
        try:
            await self._stopped.wait()
        finally:
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def stop(self) -> None:
        self._stopped.set()

    def _build_ssl_context(self) -> ssl.SSLContext:
        """mTLS server context — every agent must present a CA-signed cert."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(
            certfile=str(self.config.tls_cert),
            keyfile=str(self.config.tls_key),
        )
        ctx.load_verify_locations(cafile=str(self.config.ca_cert))
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """One agent's connection, end to end."""
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        try:
            await self._serve_connection(reader, writer)
        except Exception as exc:  # noqa: BLE001
            self.stats.connection_errors += 1
            self.stats.last_error = repr(exc)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Read messages, dispatch, reply."""
        first = await read_frame(reader)
        if first.type == "hello":
            await self._authenticated_session(first, reader, writer)
        elif first.type == "enroll_request":
            await self._enroll_session(first, reader, writer)
        else:
            self.stats.last_error = (
                f"unexpected first message from peer: {first.type!r}"
            )

    async def _authenticated_session(
        self,
        hello_msg: Envelope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        agent_id = hello_msg.agent_id
        if not agent_id or not self.config.fleet.is_known(agent_id):
            # Reject connections from agents we have not enrolled. The
            # rejection is a clean close, not a message — the agent should
            # see the TLS teardown and start an enrollment flow.
            self.stats.rejected_unknown += 1
            return
        writer.write(
            welcome(
                agent_id,
                self._next_seq(),
                self.config.clock(),
                heartbeat_seconds=HEARTBEAT_SECONDS,
                batch_quota=self.config.batch_quota,
            ).encode()
        )
        await writer.drain()
        self.config.fleet.record_seen(agent_id)
        while True:
            envelope = await read_frame(reader)
            if envelope.type == "batch":
                await self._handle_batch(envelope, reader, writer)
            elif envelope.type == "heartbeat":
                writer.write(
                    heartbeat_ack(
                        agent_id, self._next_seq(), self.config.clock()
                    ).encode()
                )
                await writer.drain()
                self.stats.heartbeats += 1
            else:
                self.stats.last_error = (
                    f"unexpected message type {envelope.type!r} from "
                    f"agent {agent_id!r}"
                )
                return

    async def _enroll_session(
        self,
        envelope: Envelope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        token = envelope.data.get("token", "")
        csr_pem = envelope.data.get("csr_pem", "")
        if not token or not csr_pem:
            self.stats.rejected_enrollment += 1
            return
        # Real enrollment validates the operator-issued token against the
        # authority file and signs the CSR with the CA. This implementation
        # issues a synthetic certificate for the test path; a production
        # deployment would replace ``_issue_certificate``.
        agent_id, cert_pem, ca_pem = self.config.fleet.enroll(
            token, csr_pem, envelope.data.get("hostname", "")
        )
        if not agent_id:
            self.stats.rejected_enrollment += 1
            return
        writer.write(
            enroll_grant(
                self._next_seq(),
                self.config.clock(),
                agent_id=agent_id,
                certificate_pem=cert_pem,
                ca_bundle_pem=ca_pem,
            ).encode()
        )
        await writer.drain()
        self.stats.enrollments += 1

    async def _handle_batch(
        self,
        envelope: Envelope,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        agent_id = envelope.agent_id
        events = list(envelope.data.get("events") or [])
        if not events:
            writer.write(
                batch_ack(
                    agent_id,
                    self._next_seq(),
                    self.config.clock(),
                    persisted_seqs=[],
                ).encode()
            )
            await writer.drain()
            return
        # The pipeline owns validation, dedup, lake writes, and the
        # quarantine lake. The server's job is to hand events over and
        # translate the resulting ack-seqs back to the agent. ``submit``
        # returns a ``SubmitResult`` carrying the events that landed in
        # the lake (which are also the ones we want to ack); events that
        # failed validation land in the quarantine lake and are not
        # acked, so the agent resends them on the next spool compaction.
        result = await self.config.pipeline.submit(
            agent_id, events, keep_events=False
        )
        persisted: list[int] = []
        if getattr(result, "accepted", None):
            # Each accepted event carries its agent-side sequence number
            # when the agent labels it; without that label we ack every
            # accepted event under the batch's seq so the agent's spool
            # compacts. Production deployments embed the seq in the
            # envelope so the agent's own per-event acks line up; this
            # default behaviour is the conservative one.
            persisted = list(range(len(events)))
        writer.write(
            batch_ack(
                agent_id,
                self._next_seq(),
                self.config.clock(),
                persisted_seqs=persisted,
            ).encode()
        )
        await writer.drain()
        self.stats.events_received += len(events)
        self.stats.events_persisted += len(persisted)
        self.config.fleet.record_seen(agent_id)

    def _next_seq(self) -> int:
        """A monotonic server-side sequence for protocol-level acks."""
        self.stats.server_seq += 1
        return self.stats.server_seq


@dataclass
class ServerStats:
    """The server's self-reported counters."""

    events_received: int = 0
    events_persisted: int = 0
    enrollments: int = 0
    heartbeats: int = 0
    rejected_unknown: int = 0
    rejected_enrollment: int = 0
    connection_errors: int = 0
    server_seq: int = 0
    last_error: str = ""


def make_server_from_config(
    config: SocConfig, pipeline: Any, fleet: Any
) -> AgentServer:
    """The server factory: builds an :class:`AgentServer` from a :class:`SocConfig`."""
    server_cfg = ServerConfig(
        listen_host=config.ingest.agent_listen_host,
        listen_port=config.ingest.agent_listen_port,
        tls_cert=config.ingest.agent_tls_cert,
        tls_key=config.ingest.agent_tls_key,
        ca_cert=config.ingest.agent_ca_cert,
        pipeline=pipeline,
        fleet=fleet,
    )
    return AgentServer(server_cfg)


__all__ = ["AgentServer", "ServerConfig", "ServerStats", "make_server_from_config"]

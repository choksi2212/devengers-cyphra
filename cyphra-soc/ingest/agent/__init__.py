"""Agent subsystem — the wire protocol, the agent, the server, the fleet.

Three pieces that work together:

* :mod:`ingest.agent.protocol` — the framing and the message kinds.
* :mod:`ingest.agent.fleet` — the server's registry of known agents.
* :mod:`ingest.agent.client` — the agent that runs on a host.
* :mod:`ingest.agent.server` — the core-side server that accepts agents.

The protocol never carries vendor bytes — every event the agent sends is
already an OCSF payload, and the server is the boundary that decides what
lands in the lake. A wire that bypasses this layer is a wire that the
correlate layer cannot trust.
"""

from ingest.agent.client import Agent, AgentConfig, AgentStats
from ingest.agent.fleet import FleetEntry, FleetRegistry
from ingest.agent.protocol import (
    HEARTBEAT_SECONDS,
    MAX_BATCH_EVENTS,
    MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
    Envelope,
    batch,
    batch_ack,
    enroll_grant,
    enroll_request,
    heartbeat,
    heartbeat_ack,
    hello,
    read_frame,
    welcome,
)
from ingest.agent.server import (
    AgentServer,
    ServerConfig,
    ServerStats,
    make_server_from_config,
)

__all__ = [
    "Agent",
    "AgentConfig",
    "AgentServer",
    "AgentStats",
    "Envelope",
    "FleetEntry",
    "FleetRegistry",
    "HEARTBEAT_SECONDS",
    "MAX_BATCH_EVENTS",
    "MAX_FRAME_BYTES",
    "PROTOCOL_VERSION",
    "ServerConfig",
    "ServerStats",
    "batch",
    "batch_ack",
    "enroll_grant",
    "enroll_request",
    "heartbeat",
    "heartbeat_ack",
    "hello",
    "make_server_from_config",
    "read_frame",
    "welcome",
]

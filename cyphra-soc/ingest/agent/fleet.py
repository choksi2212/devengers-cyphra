"""Fleet registry — who is allowed to connect, and when each was last seen.

Three responsibilities:

* ``enroll`` — given an operator-issued enrollment token and a CSR PEM, sign
  and return a new agent certificate. This is the only path that creates a
  new agent_id; ``hello`` from an unknown agent is rejected with a clean
  TLS teardown so the agent falls back to its enrollment path.

* ``is_known`` — given an agent_id, say whether the agent is enrolled. This
  is the gate on every authenticated session; the answer is read from a
  persistent file so a core restart does not forget the fleet.

* ``record_seen`` — record that an enrolled agent has checked in. The
  HealthMonitor reads this to detect dead agents. ``last_seen`` is a
  monotonic clock value and the monitor's job is to compare it to "now".

The fleet is stored in a JSON file. A production deployment would back this
with VedDB; for the test path, JSON is enough and easier to inspect by hand.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass
class FleetEntry:
    """One agent's record in the fleet.

    ``agent_id`` is the certificate subject's common name; ``enrolled_at``
    is the monotonic clock time at which the operator's token was
    exchanged; ``last_seen`` is updated on every authenticated session.
    """

    agent_id: str
    hostname: str
    enrolled_at: float
    last_seen: float = 0.0


class FleetRegistry:
    """The known-agents list, persisted to a single JSON file."""

    def __init__(
        self,
        path: Path,
        *,
        enrollment_tokens: Mapping[str, str] | None = None,
        clock: Any = time.time,
        ca_signing_fn: Any = None,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._tokens = dict(enrollment_tokens or {})
        # The default signing function is a no-op that returns the CSR PEM
        # as the certificate. Production replaces it with the operator's
        # actual CA signing step.
        self._sign = ca_signing_fn or (lambda csr: csr)
        self._ca_pem = ""
        self._entries: dict[str, FleetEntry] = {}
        self._load()

    # ── API ────────────────────────────────────────────────────────────────

    def is_known(self, agent_id: str) -> bool:
        return agent_id in self._entries

    def record_seen(self, agent_id: str) -> None:
        entry = self._entries.get(agent_id)
        if entry is not None:
            entry.last_seen = self.clock()
            self._save()

    def list_agents(self) -> list[FleetEntry]:
        return list(self._entries.values())

    def enroll(
        self, token: str, csr_pem: str, hostname: str
    ) -> tuple[str, str, str]:
        """Validate ``token`` against the operator-issued set and grant a cert.

        Returns ``(agent_id, certificate_pem, ca_bundle_pem)``. A bad token
        returns ``("", "", "")`` and the server's enrolment handler treats
        that as a rejection.

        The token is single-use — once consumed it is removed from the set.
        Replay of an old enrollment token returns rejection. A real
        deployment would persist the consumed set; for the test path the
        in-memory set is sufficient.
        """
        if token not in self._tokens:
            return "", "", ""
        del self._tokens[token]
        agent_id = f"agent-{uuid.uuid4().hex[:12]}"
        cert_pem = self._sign(csr_pem)
        self._entries[agent_id] = FleetEntry(
            agent_id=agent_id,
            hostname=hostname,
            enrolled_at=self.clock(),
            last_seen=self.clock(),
        )
        self._save()
        return agent_id, cert_pem, self._ca_pem

    def set_ca_bundle(self, ca_pem: str) -> None:
        """The CA bundle handed to agents during enrollment."""
        self._ca_pem = ca_pem

    # ── persistence ────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(doc, dict):
            return
        for raw in doc.get("agents", []):
            if not isinstance(raw, dict):
                continue
            try:
                self._entries[raw["agent_id"]] = FleetEntry(
                    agent_id=str(raw["agent_id"]),
                    hostname=str(raw.get("hostname", "")),
                    enrolled_at=float(raw.get("enrolled_at", 0.0)),
                    last_seen=float(raw.get("last_seen", 0.0)),
                )
            except (KeyError, TypeError, ValueError):
                continue

    def _save(self) -> None:
        doc = {
            "agents": [asdict(e) for e in self._entries.values()],
        }
        # Persistence failures are loud rather than silent: callers can wrap
        # this with their own try/except and react. The default behaviour is
        # to raise so a deployment that ignores the fleet file learns about
        # the loss immediately.
        self.path.write_text(
            json.dumps(doc, indent=2, sort_keys=True),
            encoding="utf-8",
        )


__all__ = ["FleetEntry", "FleetRegistry"]

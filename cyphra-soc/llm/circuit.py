"""Circuit breaker for the LLM client.

A breaker sits between the SOC and the LLM provider so a flapping
or down provider fails fast instead of hanging every hypothesis
generation call for ``timeout_s`` seconds. The breaker is the
classic three-state one: closed (calls flow), open (calls rejected
without a network round-trip), half-open (one probe call flows
through, the rest are rejected until it succeeds).

The breaker is a single process-local object; multiple LLM
runners can share one breaker by passing the same instance.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CircuitState(str, Enum):
    """The three breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """A process-local circuit breaker for the LLM provider.

    ``failure_threshold`` is the number of consecutive failures
    that trips the breaker. ``reset_timeout_s`` is how long the
    breaker stays open before transitioning to half-open. A
    successful call in half-open closes the breaker; a failure
    reopens it for another ``reset_timeout_s``.

    The breaker is intentionally synchronous and shared between
    threads — every state mutation is a simple attribute write, so
    a single ``CircuitBreaker`` instance can sit at module scope
    and serve the whole process without locks.
    """

    failure_threshold: int = 3
    reset_timeout_s: float = 60.0
    clock: Any = time.monotonic

    state: CircuitState = field(default=CircuitState.CLOSED)
    _consecutive_failures: int = 0
    _opened_at: float = 0.0
    _probe_in_flight: bool = False

    def allow(self) -> bool:
        """Return ``True`` when a call may flow to the provider."""
        if self.state is CircuitState.CLOSED:
            return True
        if self.state is CircuitState.OPEN:
            if self.clock() - self._opened_at >= self.reset_timeout_s:
                self.state = CircuitState.HALF_OPEN
                self._probe_in_flight = True
                return True
            return False
        # HALF_OPEN: exactly one probe may flow, and only when no
        # other probe is in flight.
        if self._probe_in_flight:
            return False
        self._probe_in_flight = True
        return True

    def record_success(self) -> None:
        """Mark one call as successful."""
        self._consecutive_failures = 0
        self._probe_in_flight = False
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Mark one call as failed. May trip the breaker."""
        self._consecutive_failures += 1
        self._probe_in_flight = False
        if (
            self.state is CircuitState.HALF_OPEN
            or self._consecutive_failures >= self.failure_threshold
        ):
            self.state = CircuitState.OPEN
            self._opened_at = self.clock()

    def reset(self) -> None:
        """Force the breaker closed. For tests."""
        self.state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "consecutive_failures": self._consecutive_failures,
            "opened_at": self._opened_at,
        }


__all__ = ["CircuitBreaker", "CircuitState"]

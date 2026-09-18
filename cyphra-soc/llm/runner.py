"""The LLM runner — the SOC's three call sites, wrapped.

The runner is a thin layer over :class:`LlmClient` that:

* bridges :class:`core.config.LlmConfig` (the settings dataclass)
  to :class:`llm.client.ClientLlmConfig` (the client dataclass),
* enforces the per-case call budget so one pathological case
  cannot spend the month's quota,
* routes every call through the :class:`CircuitBreaker` so a
  flapping provider degrades gracefully,
* records an audit-chain entry on every call so a post-mortem
  can answer "what did the model say".

The runner is not a singleton; a deployment that wants the SOC
process to have exactly one LLM client constructs one and passes
it down. The runner is stateless apart from its configuration
and the breaker it holds.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Mapping

from core.config import LlmConfig as SettingsLlmConfig
from llm.circuit import CircuitBreaker, CircuitState
from llm.client import (
    ChatRequest,
    ClientLlmConfig,
    LlmClient,
    LlmError,
    Message,
)
from llm.prompts import (
    DispositionPrompt,
    HypothesisPrompt,
    NarrativePrompt,
    Prompt,
    parse_disposition,
    parse_hypothesis,
    parse_narrative,
)

logger = logging.getLogger(__name__)


# ── budget tracking ────────────────────────────────────────────────────────


@dataclass
class RunnerStats:
    """Per-process counters. Useful to the operator dashboard."""

    calls: int = 0
    successes: int = 0
    breaker_rejections: int = 0
    budget_rejections: int = 0
    errors: int = 0


# ── the runner ─────────────────────────────────────────────────────────────


class LlmRunner:
    """The SOC's wrapper around :class:`LlmClient`.

    ``per_case_budget`` is the maximum number of LLM calls one case
    may make during its lifetime. ``audit_append`` is a callback
    the runner invokes after every call so the audit chain records
    the exchange. The callback signature is ``(action, target,
    details)`` — the same shape :class:`core.audit.AuditChain.append`
    expects.
    """

    def __init__(
        self,
        client: LlmClient,
        *,
        per_case_budget: int = 12,
        breaker: CircuitBreaker | None = None,
        audit_append: Any = None,
    ) -> None:
        self.client = client
        self.per_case_budget = per_case_budget
        self.breaker = breaker or CircuitBreaker()
        self.audit_append = audit_append
        self.stats = RunnerStats()
        # Tracks calls per case_uid so the budget is enforced.
        self._case_calls: dict[str, int] = {}

    # ── bridge from settings ─────────────────────────────────────────────

    @classmethod
    def from_settings(
        cls,
        settings: SettingsLlmConfig,
        *,
        transport: Any = None,
        breaker: CircuitBreaker | None = None,
        audit_append: Any = None,
    ) -> "LlmRunner":
        """Build a runner from the operator's :class:`SettingsLlmConfig`.

        The bridge is its own function because :class:`SettingsLlmConfig`
        is frozen and lives in :mod:`core.config`; importing it from
        :mod:`llm.client` would couple the client to the operator's
        config module.
        """
        client_config = ClientLlmConfig(
            base_url=settings.base_url,
            api_key=settings.api_key,
            model=settings.model,
            timeout_s=settings.timeout_s,
            max_retries=settings.max_retries,
            max_tokens=settings.max_tokens,
            temperature=settings.temperature,
        )
        client = LlmClient(client_config, transport=transport)
        return cls(
            client=client,
            per_case_budget=settings.max_calls_per_case,
            breaker=breaker,
            audit_append=audit_append,
        )

    # ── public surface ────────────────────────────────────────────────────

    async def hypothesis(self, prompt: HypothesisPrompt) -> dict[str, str]:
        """Run a hypothesis-generation call. Returns ``{hypothesis, rationale}``.

        Raises :class:`LlmError` on provider failure and
        :class:`BudgetExceeded` when the case has spent its budget.
        The breaker rejects calls without a round-trip when it is
        open; that is surfaced as a :class:`LlmError` with a clear
        message rather than as :class:`BudgetExceeded`.
        """
        return await self._run(prompt, parse_hypothesis, prompt.incident_uid, "llm.hypothesis")

    async def narrative(self, prompt: NarrativePrompt) -> str:
        """Run a narrative call. Returns the paragraph string."""
        return await self._run(prompt, parse_narrative, prompt.case_uid, "llm.narrative")

    async def disposition_considerations(self, prompt: DispositionPrompt) -> list[str]:
        """Run a disposition-review call. Returns the considerations list."""
        return await self._run(
            prompt, parse_disposition, prompt.finding_uid, "llm.disposition"
        )

    # ── internals ─────────────────────────────────────────────────────────

    async def _run(
        self,
        prompt: Prompt,
        parser,
        case_uid: str,
        action: str,
    ) -> Any:
        if self.breaker.state is CircuitState.OPEN and not self.breaker.allow():
            self.stats.breaker_rejections += 1
            raise LlmError(
                f"LLM circuit breaker is OPEN; call rejected without round-trip"
            )
        spent = self._case_calls.get(case_uid, 0)
        if spent >= self.per_case_budget:
            self.stats.budget_rejections += 1
            raise BudgetExceeded(
                f"case {case_uid} has spent its {self.per_case_budget}-call LLM budget"
            )

        request = ChatRequest(messages=prompt.render())
        try:
            response = await self.client.chat(request)
        except LlmError as exc:
            self.breaker.record_failure()
            self.stats.errors += 1
            self._audit(action, case_uid, {"error": repr(exc)})
            raise
        self.breaker.record_success()
        self.stats.calls += 1
        self._case_calls[case_uid] = spent + 1
        try:
            parsed = parser(response.content)
        except (ValueError, TypeError) as exc:
            self.stats.errors += 1
            self._audit(
                action,
                case_uid,
                {"error": f"parser: {exc!r}", "raw": response.content[:500]},
            )
            raise LlmError(f"LLM response could not be parsed: {exc!r}") from exc
        self.stats.successes += 1
        self._audit(
            action,
            case_uid,
            {
                "model": response.model,
                "duration_ms": round(response.duration_ms, 1),
                "tokens": response.usage.total_tokens,
                "parsed": parsed if not isinstance(parsed, str) else {"paragraph": parsed},
            },
        )
        return parsed

    def _audit(self, action: str, target: str, details: Mapping[str, Any]) -> None:
        if self.audit_append is None:
            return
        try:
            self.audit_append(action=action, target=target, details=dict(details))
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM audit append failed: %r", exc)


# ── exceptions ──────────────────────────────────────────────────────────────


class BudgetExceeded(LlmError):
    """The per-case LLM budget is spent."""


__all__ = ["BudgetExceeded", "LlmRunner", "RunnerStats"]

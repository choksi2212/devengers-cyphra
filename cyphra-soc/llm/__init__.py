"""The LLM client — Vultr Inference, OpenAI-compatible chat completions.

The SOC uses an LLM for three things only:

* **Hypothesis generation** — given an incident and its member
  findings, propose the next hypothesis to test.
* **Case narrative** — convert the timeline into a paragraph an
  analyst can paste into a ticket.
* **Disposition reasoning** — given a verdict history, explain why
  the disposition is what it is.

Everything else is deterministic. The LLM is a co-pilot, not a
controller: the autonomous path (``respond.mode == enforce``) never
depends on an LLM response, so a Vultr outage degrades the operator
experience without breaking containment.

The provider is Vultr Inference at ``https://api.vultrinference.com/v1``
(an OpenAI-compatible API). The same client would work against any
other provider that implements ``/v1/chat/completions`` with bearer
auth; the base URL is configurable from :class:`LlmConfig`.
"""

from llm.client import (
    ChatChoice,
    ChatRequest,
    ChatResponse,
    ClientLlmConfig,
    CompletionUsage,
    HttpxTransport,
    LlmClient,
    LlmError,
    Message,
    Role,
    StubTransport,
)
from llm.circuit import CircuitBreaker, CircuitState
from llm.prompts import (
    DispositionPrompt,
    HypothesisPrompt,
    NarrativePrompt,
    Prompt,
    parse_disposition,
    parse_hypothesis,
    parse_narrative,
    render,
)
from llm.runner import BudgetExceeded, LlmRunner, RunnerStats

__all__ = [
    "BudgetExceeded",
    "ChatChoice",
    "ChatRequest",
    "ChatResponse",
    "CircuitBreaker",
    "CircuitState",
    "ClientLlmConfig",
    "CompletionUsage",
    "DispositionPrompt",
    "HypothesisPrompt",
    "HttpxTransport",
    "LlmClient",
    "LlmError",
    "LlmRunner",
    "Message",
    "NarrativePrompt",
    "Prompt",
    "Role",
    "RunnerStats",
    "StubTransport",
    "render",
]

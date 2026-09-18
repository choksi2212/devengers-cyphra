"""The Vultr Inference client.

An OpenAI-compatible ``/v1/chat/completions`` HTTP client with:

* bearer auth from a :class:`core.config.Credential` (never
  hard-coded),
* exponential backoff with jitter on transient 5xx and 429s,
* a pluggable transport so tests can run without network, and
* per-call timeout and token limits.

The client is intentionally narrow — it returns a
:class:`ChatResponse` and raises :class:`LlmError` on anything that
isn't a clean 200. There is no streaming, no tools, no JSON mode —
the SOC's three calls (hypothesis, narrative, disposition) are
short, structured, and do not need any of those.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from core.config import Credential, MissingCredential

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """The role of one message in a chat-completion request."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


@dataclass(frozen=True)
class Message:
    """One message in a chat-completion request."""

    role: Role
    content: str


@dataclass(frozen=True)
class ChatRequest:
    """One chat-completion call.

    ``messages`` is the conversation. ``max_tokens`` and ``temperature``
    override the client defaults for this call. ``stop`` is an
    optional list of strings that terminate the response.
    """

    messages: list[Message]
    max_tokens: int | None = None
    temperature: float | None = None
    stop: list[str] | None = None
    timeout_s: float | None = None


@dataclass(frozen=True)
class ChatChoice:
    """One completion candidate. The client returns ``choices[0]``."""

    index: int
    message: Message
    finish_reason: str


@dataclass(frozen=True)
class CompletionUsage:
    """Token accounting from the provider's response."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ChatResponse:
    """One chat-completion response."""

    model: str
    content: str
    finish_reason: str
    usage: CompletionUsage
    duration_ms: float
    raw: Mapping[str, Any] = field(default_factory=dict)


class LlmError(RuntimeError):
    """Anything that isn't a clean 200 from the provider."""


# ── config ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ClientLlmConfig:
    """The runtime configuration for :class:`LlmClient`.

    ``base_url`` defaults to the Vultr Inference OpenAI-compatible
    endpoint; a different provider can be used by setting
    ``CYPHRA_SOC_LLM_BASE_URL``. ``api_key`` is a
    :class:`Credential` so the secret is never written into a log
    line or a stack trace.

    Named ``ClientLlmConfig`` rather than ``LlmConfig`` to avoid a
    collision with :class:`core.config.LlmConfig`, which is the
    operator-facing settings dataclass. The bridge from one to the
    other is :func:`llm.runner.from_settings`.
    """

    base_url: str = "https://api.vultrinference.com/v1"
    api_key: Credential | None = None
    model: str = "llama-3.1-70b-instruct"
    timeout_s: float = 30.0
    max_retries: int = 3
    max_tokens: int = 1024
    temperature: float = 0.0


# ── transport protocol ─────────────────────────────────────────────────────


class _Transport:
    """A minimal HTTP transport interface used by :class:`LlmClient`.

    Production uses :class:`HttpxTransport`; tests inject a stub
    that returns canned responses. The transport raises
    :class:`LlmError` for any non-2xx that is *not* a retryable
    status; the client retries 429 and 5xx on the transport's
    behalf.
    """

    async def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, Mapping[str, str], bytes]:
        raise NotImplementedError


class HttpxTransport(_Transport):
    """The real transport, backed by :mod:`httpx`."""

    def __init__(self) -> None:
        try:
            import httpx  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise LlmError(
                "httpx is required for the live LLM transport; install with "
                "`pip install httpx`"
            ) from exc
        self._httpx = httpx

    async def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, Mapping[str, str], bytes]:
        async with self._httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(url, headers=dict(headers), content=body)
            return (resp.status_code, dict(resp.headers), resp.content)


class StubTransport(_Transport):
    """A scriptable transport for tests.

    ``script`` is a list of (status, body_bytes) pairs returned in
    order. When the script is exhausted, further calls raise
    :class:`LlmError`. ``recorded`` accumulates every call the stub
    receives so a test can inspect request bodies and headers.
    """

    def __init__(self, script: list[tuple[int, bytes]]) -> None:
        self.script = list(script)
        self.recorded: list[dict[str, Any]] = []
        self.calls = 0

    async def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_s: float,
    ) -> tuple[int, Mapping[str, str], bytes]:
        self.calls += 1
        self.recorded.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_s": timeout_s,
            }
        )
        if not self.script:
            raise LlmError("stub transport: no scripted responses left")
        status, payload = self.script.pop(0)
        return (status, {}, payload)


# ── client ──────────────────────────────────────────────────────────────────


_RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


class LlmClient:
    """The chat-completion client.

    A single instance is intended to live the lifetime of the
    process. Per-call state — model, prompt, response — is on
    :class:`ChatRequest` and :class:`ChatResponse`.
    """

    def __init__(
        self,
        config: ClientLlmConfig,
        *,
        transport: _Transport | None = None,
        clock: Any = time.monotonic,
        sleep: Any = asyncio.sleep,
    ) -> None:
        if config.api_key is None:
            raise LlmError("LlmClient requires an api_key Credential")
        self.config = config
        self._transport = transport or HttpxTransport()
        self._clock = clock
        self._sleep = sleep
        self.stats = _ClientStats()

    # ── public surface ────────────────────────────────────────────────────

    async def chat(self, request: ChatRequest) -> ChatResponse:
        """One chat-completion call."""
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        body_dict = self._build_body(request)
        body = json.dumps(body_dict).encode("utf-8")
        headers = self._headers()
        timeout = request.timeout_s or self.config.timeout_s
        retries = max(0, self.config.max_retries)

        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            t0 = self._clock()
            try:
                status, _resp_headers, payload = await self._transport.post(
                    url, headers, body, timeout,
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                self.stats.errors += 1
                if attempt < retries:
                    await self._sleep(self._backoff(attempt))
                    continue
                raise LlmError(
                    f"transport failed after {retries + 1} attempts: {exc!r}"
                ) from exc

            if status == 200:
                self.stats.calls += 1
                self.stats.successes += 1
                duration_ms = (self._clock() - t0) * 1000.0
                return self._parse(payload, body_dict["model"], duration_ms)

            if status in _RETRY_STATUSES and attempt < retries:
                self.stats.retries += 1
                await self._sleep(self._backoff(attempt))
                continue

            self.stats.errors += 1
            raise LlmError(
                f"provider returned {status}: {payload[:300].decode('utf-8', 'replace')}"
            )
        # Unreachable — the loop always either returns or raises.
        raise LlmError(f"chat failed: {last_exc!r}")

    def stats_dict(self) -> dict[str, int]:
        return {
            "calls": self.stats.calls,
            "successes": self.stats.successes,
            "retries": self.stats.retries,
            "errors": self.stats.errors,
        }

    # ── internals ─────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        try:
            token = self.config.api_key.value  # type: ignore[union-attr]
        except MissingCredential as exc:
            raise LlmError(
                "LLM api_key is not configured. Set $CYPHRA_SOC_LLM_API_KEY "
                "or $VULTR_INFERENCE_API_KEY."
            ) from exc
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _build_body(self, request: ChatRequest) -> dict[str, Any]:
        out: dict[str, Any] = {
            "model": self.config.model,
            "messages": [
                {"role": m.role.value, "content": m.content}
                for m in request.messages
            ],
            "max_tokens": request.max_tokens or self.config.max_tokens,
            "temperature": (
                request.temperature
                if request.temperature is not None
                else self.config.temperature
            ),
        }
        if request.stop:
            out["stop"] = list(request.stop)
        return out

    def _parse(self, payload: bytes, model: str, duration_ms: float) -> ChatResponse:
        try:
            doc = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise LlmError(f"provider returned non-JSON body: {exc!r}") from exc
        if not isinstance(doc, Mapping):
            raise LlmError("provider returned non-object body")
        choices = doc.get("choices") or []
        if not choices:
            raise LlmError("provider returned no choices")
        first = choices[0]
        if not isinstance(first, Mapping):
            raise LlmError("provider choice is not an object")
        message = first.get("message") or {}
        content = str(message.get("content") or "")
        finish_reason = str(first.get("finish_reason") or "stop")
        usage_doc = doc.get("usage") or {}
        usage = CompletionUsage(
            prompt_tokens=int(usage_doc.get("prompt_tokens") or 0),
            completion_tokens=int(usage_doc.get("completion_tokens") or 0),
            total_tokens=int(usage_doc.get("total_tokens") or 0),
        )
        return ChatResponse(
            model=str(doc.get("model") or model),
            content=content,
            finish_reason=finish_reason,
            usage=usage,
            duration_ms=duration_ms,
            raw=doc,
        )

    def _backoff(self, attempt: int) -> float:
        base = min(8.0, 0.5 * (2 ** attempt))
        return base * (0.5 + random.random())


@dataclass
class _ClientStats:
    calls: int = 0
    successes: int = 0
    retries: int = 0
    errors: int = 0


__all__ = [
    "ChatChoice",
    "ChatRequest",
    "ChatResponse",
    "ClientLlmConfig",
    "CompletionUsage",
    "HttpxTransport",
    "LlmClient",
    "LlmError",
    "Message",
    "Role",
    "StubTransport",
]

"""scratch_llm — Vultr Inference client, runner, prompts.

    python tests/scratch_llm.py

Eight sections, each verifying a layer end-to-end with a stub
transport (no network calls):

1. **Stub transport** — the test double round-trips a canned
   response.
2. **Client happy path** — a 200 with a valid OpenAI-shape body
   yields a :class:`ChatResponse` with the parsed content.
3. **Retry/backoff** — 429 then 200; the client retries and the
   breaker is still closed.
4. **Failure handling** — repeated 5xx trips the breaker after the
   configured threshold.
5. **Bearer auth** — the Authorization header carries the API key.
6. **Prompt renderers** — hypothesis, narrative, disposition each
   produce a two-message list.
7. **Parsers** — JSON responses are decoded; code-fenced
   responses are tolerated.
8. **Runner + budget + audit** — calls count against the per-case
   budget; every call records an audit entry.
"""

import asyncio
import json
import sys

sys.path.insert(0, ".")

from core.config import Credential
from llm import (
    BudgetExceeded,
    ChatRequest,
    CircuitBreaker,
    CircuitState,
    ClientLlmConfig,
    DispositionPrompt,
    HttpxTransport,
    HypothesisPrompt,
    LlmClient,
    LlmError,
    LlmRunner,
    Message,
    NarrativePrompt,
    Role,
    StubTransport,
    parse_disposition,
    parse_hypothesis,
    parse_narrative,
    render,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── shared fixtures ────────────────────────────────────────────────────────


def _credential() -> Credential:
    """A test Credential with a clearly-fake secret.

    The placeholder is non-empty (so the test exercises the bearer
    header path) but obviously synthetic (so it can never be mistaken
    for a real key if the test file is shared). The real key is the
    one set via ``$VULTR_INFERENCE_API_KEY`` at runtime.
    """
    return Credential(
        name="llm.api_key",
        env_var="VULTR_INFERENCE_API_KEY",
        purpose="test",
        secret="test-credential-placeholder-do-not-use-in-production",
        source="test-fixture",
    )


def _ok_response(content: str) -> bytes:
    body = {
        "model": "llama-3.1-70b-instruct",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
    }
    return json.dumps(body).encode("utf-8")


def _client(transport) -> LlmClient:
    cfg = ClientLlmConfig(
        base_url="https://api.vultrinference.com/v1",
        api_key=_credential(),
        model="llama-3.1-70b-instruct",
        timeout_s=5.0,
        max_retries=2,
        max_tokens=256,
        temperature=0.0,
    )
    return LlmClient(cfg, transport=transport, sleep=_noop_sleep)


async def _noop_sleep(_seconds: float) -> None:
    return None


# ── 1. stub transport ──────────────────────────────────────────────────────


async def test_stub_transport_round_trip() -> None:
    print("\n[stub] the test transport round-trips a canned body")
    transport = StubTransport([(200, _ok_response('{"hypothesis":"a","rationale":"b"}'))])
    client = _client(transport)
    response = await client.chat(ChatRequest(messages=[Message(Role.USER, "go")]))
    check(
        "the stub delivered exactly one body",
        transport.calls == 1,
        f"calls={transport.calls}",
    )
    check("the URL is the chat-completions endpoint", transport.recorded[0]["url"].endswith("/chat/completions"), f"url={transport.recorded[0]['url']}")
    check("the response carries the stub content", response.content == '{"hypothesis":"a","rationale":"b"}', f"got {response.content!r}")


# ── 2. client happy path ───────────────────────────────────────────────────


async def test_client_happy_path() -> None:
    print("\n[client] a 200 with a valid OpenAI body yields a parsed response")
    transport = StubTransport([(200, _ok_response('{"paragraph":"the user was phished."}'))])
    client = _client(transport)
    response = await client.chat(ChatRequest(messages=[Message(Role.USER, "go")]))
    check("the content was extracted", response.content == '{"paragraph":"the user was phished."}', f"content={response.content!r}")
    check("the model name was extracted", response.model == "llama-3.1-70b-instruct", f"model={response.model}")
    check("the usage was parsed", response.usage.total_tokens == 20, f"usage={response.usage}")
    check("the duration is positive", response.duration_ms >= 0.0, f"duration_ms={response.duration_ms}")
    check("the call counter incremented", client.stats.calls == 1 and client.stats.successes == 1, f"stats={client.stats_dict()}")


# ── 3. retry / backoff ─────────────────────────────────────────────────────


async def test_retry_then_success() -> None:
    print("\n[retry] a 429 followed by a 200 is retried and succeeds")
    transport = StubTransport([
        (429, b"slow down"),
        (200, _ok_response('{"hypothesis":"c","rationale":"d"}')),
    ])
    client = _client(transport)
    response = await client.chat(ChatRequest(messages=[Message(Role.USER, "go")]))
    check("the client tried twice", transport.calls == 2, f"calls={transport.calls}")
    check("the second attempt succeeded", response.finish_reason == "stop", f"finish={response.finish_reason}")
    check("the retry counter incremented", client.stats.retries == 1, f"stats={client.stats_dict()}")


# ── 4. failure handling ────────────────────────────────────────────────────


async def test_repeated_failure_trips_breaker() -> None:
    print("\n[failure] three 5xx in a row trip the breaker via the runner")
    transport = StubTransport([(503, b"down")] * 8)
    client = _client(transport)
    breaker = CircuitBreaker(failure_threshold=3, reset_timeout_s=60.0)
    runner = LlmRunner(client, per_case_budget=10, breaker=breaker)
    prompt = HypothesisPrompt(incident_uid="i-1", findings=[{"x": 1}])
    # Three failed calls.
    failures = 0
    for _ in range(3):
        try:
            await runner.hypothesis(prompt)
        except LlmError:
            failures += 1
    check("three calls all failed", failures == 3, f"failures={failures}")
    check("the breaker is open after three failures", breaker.state is CircuitState.OPEN, f"state={breaker.state}")
    # The next call must be rejected without round-trip.
    pre_calls = transport.calls
    try:
        await runner.hypothesis(prompt)
    except LlmError as exc:
        breaker_rejected = "circuit breaker is OPEN" in str(exc)
    else:
        breaker_rejected = False
    check(
        "the next call is rejected without round-trip",
        breaker_rejected and transport.calls == pre_calls,
        f"breaker_rejected={breaker_rejected} transport_calls={transport.calls}",
    )


# ── 5. bearer auth ─────────────────────────────────────────────────────────


async def test_bearer_auth() -> None:
    print("\n[auth] the request carries the configured bearer token")
    transport = StubTransport([(200, _ok_response('{"hypothesis":"a","rationale":"b"}'))])
    client = _client(transport)
    expected_token = client.config.api_key.value  # type: ignore[union-attr]
    await client.chat(ChatRequest(messages=[Message(Role.USER, "go")]))
    headers = transport.recorded[0]["headers"]
    check("Authorization header is present", "Authorization" in headers, f"headers={list(headers)}")
    check(
        "the bearer token is the configured key",
        headers.get("Authorization") == f"Bearer {expected_token}",
        f"auth={headers.get('Authorization')!r}",
    )
    check("Content-Type is JSON", headers.get("Content-Type") == "application/json", f"ct={headers.get('Content-Type')!r}")


# ── 6. prompt renderers ────────────────────────────────────────────────────


def test_prompt_renderers() -> None:
    print("\n[prompts] every prompt renders to a [system, user] message pair")
    h = HypothesisPrompt(incident_uid="i-1", findings=[{"uid": "e1"}])
    n = NarrativePrompt(case_uid="c-1", title="Compromise", timeline=[{"kind": "status_change"}], severity_id=4)
    d = DispositionPrompt(
        finding_uid="f-1",
        draft_disposition="true_positive",
        draft_rationale="anomalous sign-in",
        context={"actor": "alice"},
    )
    for name, p in (("hypothesis", h), ("narrative", n), ("disposition", d)):
        msgs = render(p)
        check(f"{name} renders two messages", len(msgs) == 2, f"got {len(msgs)}")
        check(f"{name} starts with a system message", msgs[0].role is Role.SYSTEM, f"role={msgs[0].role}")
        check(f"{name} user message is non-empty", bool(msgs[1].content), "empty")


# ── 7. parsers ─────────────────────────────────────────────────────────────


def test_parsers() -> None:
    print("\n[parsers] JSON responses decode; fenced responses are tolerated")
    h = parse_hypothesis('{"hypothesis":"x","rationale":"y"}')
    check("hypothesis parses both fields", h == {"hypothesis": "x", "rationale": "y"}, f"got {h}")

    n = parse_narrative('```json\n{"paragraph":"the user was phished."}\n```')
    check("narrative parses with code fences stripped", n == "the user was phished.", f"got {n!r}")

    d = parse_disposition('{"considerations":["a","b","c"]}')
    check("disposition truncates to three considerations", d == ["a", "b", "c"], f"got {d}")


# ── 8. runner + budget + audit ─────────────────────────────────────────────


async def test_runner_budget_and_audit() -> None:
    print("\n[runner] calls count against the per-case budget; audit is appended")
    transport = StubTransport([(200, _ok_response('{"hypothesis":"a","rationale":"b"}'))] * 4)
    client = _client(transport)
    audit_log: list[tuple[str, str, dict]] = []

    def _audit(action: str, target: str, details: dict) -> None:
        audit_log.append((action, target, details))

    runner = LlmRunner(client, per_case_budget=2, audit_append=_audit)
    prompt = HypothesisPrompt(incident_uid="i-budget", findings=[{"uid": "e1"}])
    out = await runner.hypothesis(prompt)
    check("the first call returns the parsed payload", out == {"hypothesis": "a", "rationale": "b"}, f"got {out}")
    out2 = await runner.hypothesis(prompt)
    check("the second call also succeeds", out2 == {"hypothesis": "a", "rationale": "b"}, f"got {out2}")

    # Third call exceeds the per-case budget.
    try:
        await runner.hypothesis(prompt)
    except BudgetExceeded as exc:
        budget_exceeded = True
        budget_msg = str(exc)
    else:
        budget_exceeded = False
        budget_msg = ""
    check(
        "the third call exceeds the per-case budget",
        budget_exceeded and "budget" in budget_msg.lower(),
        f"budget_exceeded={budget_exceeded} msg={budget_msg!r}",
    )
    check("the audit log records two successful calls", len(audit_log) == 2, f"len={len(audit_log)}")
    check("the audit entries name the action", all(e[0] == "llm.hypothesis" for e in audit_log), f"actions={[e[0] for e in audit_log]}")
    check("the audit entries name the case", all(e[1] == "i-budget" for e in audit_log), f"targets={[e[1] for e in audit_log]}")


# ── 9. live transport smoke (skipped if httpx missing) ─────────────────────


async def test_live_transport_exists() -> None:
    print("\n[live] the HttpxTransport class is importable and ready")
    check("HttpxTransport is a class", isinstance(HttpxTransport, type), f"type={type(HttpxTransport)}")
    try:
        t = HttpxTransport()
        check("HttpxTransport can be constructed", True, "constructed")
    except LlmError as exc:
        # httpx may not be installed; the constructor raises with
        # a clear message.
        check("HttpxTransport raises a clear error when httpx is missing", "httpx" in str(exc), f"exc={exc!r}")


# ── entry ──────────────────────────────────────────────────────────────────


def main() -> int:
    asyncio.run(test_stub_transport_round_trip())
    asyncio.run(test_client_happy_path())
    asyncio.run(test_retry_then_success())
    asyncio.run(test_repeated_failure_trips_breaker())
    asyncio.run(test_bearer_auth())
    test_prompt_renderers()
    test_parsers()
    asyncio.run(test_runner_budget_and_audit())
    asyncio.run(test_live_transport_exists())
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

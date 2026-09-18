"""HTTP transport, retry policy and rate limiting for the API connectors.

Ten vendor APIs, one HTTP layer. What lives here is only the part that is genuinely
common; the parts that look common and are not — pagination shape, cursor semantics,
auth handshake — are deliberately elsewhere, because folding them in here produces a
function with ten branches and no owner.

── Why a Transport protocol instead of calling httpx directly ────────────────
Every one of these ten connectors needs a tenant, a licence and a credential before
it can make a single call. If the only way to exercise the code is against the live
API, the code is never exercised — and the details that break are not the ones a
smoke test would catch. They are: that Okta's cursor is an opaque ``Link`` header
and not a timestamp; that CloudTrail returns the actual event as a JSON *string*
nested inside JSON; that Graph's ``@odata.nextLink`` already contains the ``$filter``
so re-adding it produces a 400; that AWS ``sourceIPAddress`` is sometimes
``cloudformation.amazonaws.com``, which a field typed as an IP address will reject.

Each of those is one line of parsing and each fails silently or fatally in
production. :class:`Transport` is a two-method protocol so a test can script exact
vendor response bodies — captured from the vendors' own documentation — and assert
the parse. :class:`HttpxTransport` is the real one; the fakes live in the tests.

── Why the retry policy is explicit about idempotence ────────────────────────
The obvious rule is "retry GET, never retry POST". It is wrong in both directions
here. Three of these APIs express a *read* as a POST — CloudTrail ``LookupEvents``,
GCP ``entries:list``, Defender ``advancedqueries/run`` — and refusing to retry those
means a single dropped TCP connection loses a window of telemetry. Meanwhile a
retried ``403`` is worse than useless: it burns quota, and against an auth endpoint
it walks toward a lockout. So retryability is a property of the *call*, declared by
the caller as :paramref:`Request.idempotent`, and the status policy is narrow:
``429`` and ``5xx`` retry, everything else in ``4xx`` fails immediately and loudly.

── Why both a token bucket and server hints ──────────────────────────────────
A local bucket cannot know that another process is sharing the tenant's quota, so it
will happily walk into a ``429``. Server hints (``Retry-After``,
``X-Rate-Limit-Reset``) are authoritative but only arrive *after* you have already
been throttled — and Okta's throttle is per-org, so the first 429 has already cost
every other consumer in the tenant. Neither alone is enough, so
:class:`RateLimiter` runs the bucket in front and lets a hint push a hard floor
behind it.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Mapping, Protocol
from urllib.parse import urlencode, urlsplit

#: Statuses worth trying again. Everything else in 4xx is a bug, a permission
#: problem or a bad cursor, and repeating it neither fixes it nor is free.
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})

#: Vendor error *names* that mean "slow down" on a response whose status code does not.
#:
#: This exists because of AWS. The JSON-RPC protocols (``application/x-amz-json-1.1``,
#: which is what CloudTrail's ``LookupEvents`` speaks) return a throttle as **HTTP 400**
#: with the kind in the ``x-amzn-errortype`` header and the body's ``__type`` — not as a
#: 429. Read by status alone, CloudTrail's documented ``ThrottlingException`` is
#: indistinguishable from a malformed request: it raises :class:`HttpError`, is never
#: retried, and fails the whole collection cycle. The connector's own 2-req/s bucket
#: makes it rare and the account-wide limit is shared with every other tool in the
#: account, so rare is not never — and when it happens the operator sees "HTTP 400"
#: against a request that was perfectly well formed.
#:
#: Matched on the name rather than the message because the message is prose and is
#: localised for some vendors; the name is part of the API contract.
THROTTLE_ERROR_NAMES: frozenset[str] = frozenset(
    {
        "throttling",
        "throttlingexception",
        "throttled",
        "requestthrottled",
        "requestthrottledexception",
        "requestlimitexceeded",
        "toomanyrequests",
        "toomanyrequestsexception",
        "provisionedthroughputexceededexception",
        "slowdown",
        "bandwidthlimitexceeded",
        "ec2throttledexception",
        "limitexceededexception",
        "rate_limit_exceeded",
        # Google. `resource_exhausted` is the gRPC/REST canonical status and arrives on
        # a 429; the three `*ratelimitexceeded`/`quotaexceeded` reasons are the legacy
        # JSON shape and arrive on a **403**, which is why the 401/403 branch in
        # `ApiClient.send` consults this set before deciding a credential is unwelcome.
        "resource_exhausted",
        "ratelimitexceeded",
        "userratelimitexceeded",
        "quotaexceeded",
    }
)

#: Ceiling on a server-supplied wait. A vendor that says "come back in four hours"
#: (Defender's advanced-hunting quota does say things like this) must not park a
#: collector cycle for four hours holding its slot; the connector gives up on this
#: cycle and the health monitor sees a source that has stopped reporting, which is
#: the honest rendering of the situation.
MAX_HONOURED_WAIT = 300.0

#: Default politeness. Overridden per connector from each vendor's published limit.
DEFAULT_RATE_PER_SECOND = 4.0
DEFAULT_BURST = 8


class HttpError(RuntimeError):
    """A request failed in a way the connector cannot paper over."""

    def __init__(
        self, message: str, *, status: int = 0, body: str = "", url: str = ""
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body
        self.url = url


class AuthError(HttpError):
    """401/403. Separated because the operator action is different.

    A rate limit resolves itself; a 403 means the app registration is missing a
    permission or consent was never granted, and no amount of retrying supplies it.
    The connector surfaces this as an unconfigured source with the vendor's own error
    text, so the operator reads "Authorization_RequestDenied" rather than "0 events".
    """


class TransientError(HttpError):
    """Retryable: 429, 5xx, or the connection itself failed."""


class BadPayload(HttpError):
    """The response was not the JSON the caller expected.

    Its own type because the usual cause is not a vendor bug: it is a captive portal,
    a corporate TLS-terminating proxy, or an expired-token HTML error page. Reporting
    ``JSONDecodeError: Expecting value: line 1 column 1`` sends the operator to look
    at the wrong thing.
    """


# ── request / response ──────────────────────────────────────────────────────


@dataclass(slots=True)
class Request:
    """One HTTP call, fully described.

    ``idempotent`` is not derived from ``method`` on purpose — see the module note.
    ``label`` is what appears in counters and errors; it is the vendor operation name
    ("okta.logs", "cloudtrail.LookupEvents") rather than the URL, because URLs here
    carry cursors and secrets and would make every counter unique.
    """

    method: str
    url: str
    label: str = ""
    params: Mapping[str, Any] | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    json_body: Any = None
    form_body: Mapping[str, str] | None = None
    raw_body: bytes | None = None
    idempotent: bool = True
    timeout_s: float = 60.0

    def body_bytes(self) -> bytes:
        """The exact bytes on the wire. Also what SigV4 has to hash."""
        if self.raw_body is not None:
            return self.raw_body
        if self.json_body is not None:
            return json.dumps(self.json_body, separators=(",", ":")).encode()
        if self.form_body is not None:
            return urlencode(self.form_body).encode()
        return b""

    def content_type(self) -> str | None:
        if self.raw_body is not None:
            return None  # caller set it
        if self.json_body is not None:
            return "application/json"
        if self.form_body is not None:
            return "application/x-www-form-urlencoded"
        return None

    def host(self) -> str:
        return urlsplit(self.url).netloc


@dataclass(slots=True)
class HttpResponse:
    """A response, with headers folded to lowercase.

    Header case is not a cosmetic concern here: Okta documents
    ``X-Rate-Limit-Reset``, CrowdStrike documents ``X-RateLimit-RetryAfter``, Graph
    documents ``Retry-After``, and real servers and proxies vary the casing of all
    three. Code that reads ``headers["Retry-After"]`` works against the
    documentation and fails against the wire.
    """

    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str = ""
    elapsed_s: float = 0.0

    def __post_init__(self) -> None:
        if any(k != k.lower() for k in self.headers):
            self.headers = {k.lower(): v for k, v in self.headers.items()}

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        try:
            return json.loads(self.body or b"null")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            snippet = self.text()[:200].replace("\n", " ")
            raise BadPayload(
                f"expected JSON, got {len(self.body)} bytes of "
                f"{self.headers.get('content-type', 'unknown type')}: {snippet!r}",
                status=self.status,
                body=snippet,
                url=self.url,
            ) from exc

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def link(self, rel: str) -> str:
        """A URL from an RFC 5988 ``Link`` header. Okta's pagination lives here.

        Parsed rather than split, because Okta sends ``self`` and ``next`` as two
        headers that any client joins into one comma-separated value, *and* its
        ``after`` cursor contains commas. A plain ``split(",")`` corrupts the cursor,
        which fails as a 400 on the *following* request — one call away from the cause.

        Splitting on ``">,"`` does not work either, and that was the first attempt
        here: RFC 5988 places the comma after the link's parameters, not after its
        URL, so the real header reads ``<url>; rel="next", <url>; rel="self"`` and the
        sequence ``>,`` never appears. So the split is on commas at bracket depth
        zero, which is the only rule that holds for both.
        """
        raw = self.header("link")
        if not raw:
            return ""
        parts: list[str] = []
        depth = start = 0
        for i, ch in enumerate(raw):
            if ch == "<":
                depth += 1
            elif ch == ">":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                parts.append(raw[start:i])
                start = i + 1
        parts.append(raw[start:])
        for part in parts:
            if "<" not in part or ">" not in part:
                continue
            url = part[part.index("<") + 1 : part.rindex(">")]
            attrs = part[part.rindex(">") + 1 :]
            if (
                f'rel="{rel}"' in attrs
                or f"rel='{rel}'" in attrs
                or f"rel={rel}" in attrs
            ):
                return url.strip()
        return ""


class Transport(Protocol):
    """Anything that can perform a :class:`Request`."""

    async def send(self, request: Request) -> HttpResponse:  # pragma: no cover
        ...

    async def aclose(self) -> None:  # pragma: no cover
        ...


class HttpxTransport:
    """The real transport. One client per connector, connections reused.

    A fresh client per request would negotiate TLS on every poll — against Graph that
    is a measurable share of the cycle, and against an API with a per-connection rate
    limit it looks like a new consumer each time.
    """

    def __init__(
        self,
        *,
        verify: bool = True,
        proxy: str | None = None,
        max_connections: int = 10,
        user_agent: str = "CYPHRA-SOC/1.0 (+telemetry connector)",
    ) -> None:
        import httpx

        self._httpx = httpx
        self._client = httpx.AsyncClient(
            verify=verify,
            proxy=proxy,
            limits=httpx.Limits(max_connections=max_connections),
            headers={"User-Agent": user_agent},
            follow_redirects=False,
        )

    async def send(self, request: Request) -> HttpResponse:
        headers = dict(request.headers)
        ctype = request.content_type()
        if ctype and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = ctype
        started = time.monotonic()
        try:
            resp = await self._client.request(
                request.method,
                request.url,
                params=dict(request.params) if request.params else None,
                headers=headers,
                content=request.body_bytes() or None,
                timeout=request.timeout_s,
            )
        except self._httpx.TimeoutException as exc:
            raise TransientError(
                f"{request.label or request.url}: timed out after "
                f"{request.timeout_s:.0f}s",
                url=request.url,
            ) from exc
        except self._httpx.TransportError as exc:
            # Connection refused, DNS failure, TLS failure, reset mid-body. All
            # transient from the connector's point of view; a genuinely wrong
            # hostname will keep failing and the health monitor will say so.
            raise TransientError(
                f"{request.label or request.url}: {type(exc).__name__}: {exc}",
                url=request.url,
            ) from exc
        return HttpResponse(
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content,
            url=str(resp.url),
            elapsed_s=time.monotonic() - started,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


# ── rate limiting ───────────────────────────────────────────────────────────


class RateLimiter:
    """Token bucket in front, server hints behind.

    The bucket is the *plan*: a published limit divided into a smooth rate, so a
    connector paginating through a backfill does not arrive as a burst. The floor is
    the *correction*: when the server says ``Retry-After: 47`` or
    ``X-Rate-Limit-Reset: 1788004847``, nothing acquires until then, regardless of
    how many tokens the bucket has accumulated.

    Both the clock and the sleep are injected so a test can prove the arithmetic
    without spending the wall-clock time it describes. A rate limiter tested by
    actually waiting is a rate limiter tested at one setting.
    """

    def __init__(
        self,
        rate_per_second: float = DEFAULT_RATE_PER_SECOND,
        burst: int = DEFAULT_BURST,
        *,
        name: str = "",
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.name = name
        self.rate = rate_per_second
        self.burst = max(1, burst)
        self.clock = clock
        self._sleep = sleep
        self._tokens = float(self.burst)
        self._updated = clock()
        self._floor = 0.0  # monotonic time before which nothing may go out
        self._lock = asyncio.Lock()
        self.waits = 0
        self.seconds_waited = 0.0
        self.throttled = 0
        #: Last server-reported remaining quota, when the vendor sends one. Reported
        #: rather than acted on: a connector that self-throttles at 10% remaining is
        #: guessing about the other consumers of the quota, and guessing high means
        #: it stops collecting for a reason it invented.
        self.remaining: int | None = None
        self.limit: int | None = None

    async def acquire(self, n: int = 1) -> float:
        """Wait until *n* tokens are available and no floor applies. Returns waited."""
        waited = 0.0
        async with self._lock:
            while True:
                now = self.clock()
                if self._floor > now:
                    delay = self._floor - now
                    await self._pause(delay)
                    waited += delay
                    continue
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= n:
                    self._tokens -= n
                    if waited:
                        self.waits += 1
                        self.seconds_waited += waited
                    return waited
                need = (n - self._tokens) / self.rate
                await self._pause(need)
                waited += need

    async def _pause(self, seconds: float) -> None:
        if seconds > 0:
            await self._sleep(seconds)

    def hold_for(self, seconds: float, *, reason: str = "") -> float:
        """Refuse to issue anything for *seconds*. Returns the seconds honoured."""
        seconds = max(0.0, min(seconds, MAX_HONOURED_WAIT))
        self._floor = max(self._floor, self.clock() + seconds)
        return seconds

    def observe(self, resp: HttpResponse) -> None:
        """Read whatever quota headers this vendor happens to send.

        Five spellings across five vendors, all handled, none required. A vendor that
        sends none is not a problem — the bucket still applies; the hints only make it
        more accurate.
        """
        for key in ("x-rate-limit-remaining", "x-ratelimit-remaining"):
            if resp.header(key):
                try:
                    self.remaining = int(float(resp.header(key)))
                except ValueError:
                    pass
        for key in ("x-rate-limit-limit", "x-ratelimit-limit"):
            if resp.header(key):
                try:
                    self.limit = int(float(resp.header(key)))
                except ValueError:
                    pass
        if resp.status != 429:
            return
        self.observe_throttle(resp, "429")

    def observe_throttle(self, resp: HttpResponse, name: str) -> float:
        """Record a throttle and hold the floor. Returns the seconds honoured.

        Split out of :meth:`observe` so a throttle that arrived as something other than
        a 429 — see :data:`THROTTLE_ERROR_NAMES` — lands in the same counter and pushes
        the same floor. Counting them separately would let an AWS-heavy deployment
        report ``throttled_429: 0`` while being throttled continuously.
        """
        self.throttled += 1
        wait = self.retry_after(resp)
        return self.hold_for(wait if wait > 0 else 1.0, reason=name)

    def retry_after(self, resp: HttpResponse) -> float:
        """Seconds to wait, from whichever header this vendor uses.

        Three encodings in the wild and all three appear across these ten APIs:

        * ``Retry-After: 47`` — delta seconds (Graph, Okta, most things)
        * ``Retry-After: Wed, 29 Aug 2026 12:00:47 GMT`` — an HTTP date, which RFC
          9110 explicitly permits and which some CDNs in front of these APIs emit
        * ``X-Rate-Limit-Reset: 1788004847`` — an absolute **epoch** second (Okta),
          and ``X-RateLimit-RetryAfter`` likewise (CrowdStrike)

        The epoch forms have to be differenced against wall-clock time, while the
        bucket runs on a monotonic clock — mixing the two is how a 47-second wait
        becomes a 1.7-billion-second one. So the epoch branch converts to a delta
        using :func:`time.time` and only the delta is handed to the bucket.
        """
        raw = resp.header("retry-after")
        if raw:
            try:
                return max(0.0, float(raw))
            except ValueError:
                try:
                    when = parsedate_to_datetime(raw)
                    return max(0.0, when.timestamp() - time.time())
                except (TypeError, ValueError):
                    pass
        for key in ("x-rate-limit-reset", "x-ratelimit-retryafter", "x-ratelimit-reset"):
            raw = resp.header(key)
            if not raw:
                continue
            try:
                epoch = float(raw)
            except ValueError:
                continue
            # Some vendors send a reset as a delta rather than an epoch. Anything
            # below a year of seconds cannot be an epoch, so treat it as a delta.
            if epoch < 31_536_000:
                return max(0.0, epoch)
            return max(0.0, epoch - time.time())
        return 0.0

    def stats(self) -> dict[str, Any]:
        return {
            "rate_per_second": self.rate,
            "burst": self.burst,
            "waits": self.waits,
            "seconds_waited": round(self.seconds_waited, 2),
            "throttled_429": self.throttled,
            "quota_remaining": self.remaining,
            "quota_limit": self.limit,
        }


# ── the caller-facing client ────────────────────────────────────────────────


@dataclass
class RetryPolicy:
    """How many times, how long, and with how much jitter.

    Jitter is not decoration. Ten connectors polling on 900-second cadences all
    started by the same fleet will align, and aligned retries against a shared tenant
    quota produce a thundering herd that keeps re-throttling itself. Full jitter
    (``random.uniform(0, backoff)``) is the standard fix and is what is used here.
    """

    attempts: int = 4
    backoff_base_s: float = 0.5
    backoff_max_s: float = 30.0
    jitter: bool = True

    def delay(self, attempt: int, rng: random.Random) -> float:
        raw = min(self.backoff_max_s, self.backoff_base_s * (2**attempt))
        return rng.uniform(0, raw) if self.jitter else raw


class ApiClient:
    """A rate-limited, retrying, auth-refreshing wrapper around one Transport.

    Auth is a callable rather than an object with a fixed shape because the five
    handshakes in use here have nothing in common: Okta wants a static ``SSWS``
    header, Graph wants a bearer token refreshed on a timer, AWS wants every
    individual request signed over its own body hash, GCP wants a locally-signed JWT
    exchanged for a bearer token, and the generic SaaS connector wants whatever the
    operator configured. What they *do* share is "given a Request, return a Request
    that is authorised", so that is the interface.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        limiter: RateLimiter | None = None,
        retry: RetryPolicy | None = None,
        authorize: Callable[[Request], Awaitable[Request]] | None = None,
        name: str = "",
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        seed: int | None = None,
    ) -> None:
        self.transport = transport
        self.name = name
        self.limiter = limiter or RateLimiter(name=name, clock=clock, sleep=sleep)
        self.retry = retry or RetryPolicy()
        self.authorize = authorize
        self._sleep = sleep
        self._rng = random.Random(seed) if seed is not None else random.Random()
        self.requests = 0
        self.retries = 0
        self.failures = 0
        self.oversized_hints = 0
        self.masked_throttles = 0
        self.bytes_in = 0
        self.seconds_in_http = 0.0
        self.by_label: dict[str, int] = {}
        self.last_error = ""

    async def send(self, request: Request) -> HttpResponse:
        """Perform one logical call, retrying per policy. Raises on final failure."""
        label = request.label or request.url
        last: Exception | None = None
        for attempt in range(self.retry.attempts):
            await self.limiter.acquire()
            outgoing = request
            if self.authorize is not None:
                # Re-authorised on every attempt, not once before the loop. A retry
                # after a 401 has to carry a *new* token, and an AWS SigV4 signature
                # is only valid for a few minutes and covers the timestamp — reusing
                # the first attempt's headers turns a transient failure into a
                # permanent one that looks like a credential problem.
                outgoing = await self.authorize(request)
            try:
                resp = await self.transport.send(outgoing)
            except TransientError as exc:
                last = exc
                self.failures += 1
                self.last_error = str(exc)
                if not request.idempotent or attempt == self.retry.attempts - 1:
                    raise
                self.retries += 1
                await self._sleep(self.retry.delay(attempt, self._rng))
                continue
            self.requests += 1
            self.by_label[label] = self.by_label.get(label, 0) + 1
            self.bytes_in += len(resp.body)
            self.seconds_in_http += resp.elapsed_s
            self.limiter.observe(resp)
            if resp.ok:
                return resp
            # A throttle that did not arrive as a 429 — see THROTTLE_ERROR_NAMES. Read
            # only for statuses RETRY_STATUSES does not already cover, so a 429 keeps
            # taking the cheaper path without parsing a body.
            #
            # Read *before* the 401/403 branch rather than after it, because Google
            # returns a quota refusal as **HTTP 403** with
            # ``error.errors[0].reason = "rateLimitExceeded"``. Classified as an
            # authorization failure that would raise AuthError on the first attempt,
            # never retry, and tell the operator their permissions are wrong when the
            # permissions are correct and the only problem is that Cloud Logging's
            # 60-requests-per-minute quota — which "cannot be increased" — was shared
            # with an analyst in the Logs Explorer.
            throttle = (
                "" if resp.status in RETRY_STATUSES else throttle_signalled(resp)
            )
            if resp.status in (401, 403) and not throttle:
                self.failures += 1
                detail = _vendor_error(resp)
                self.last_error = f"{label}: HTTP {resp.status} {detail}"
                raise AuthError(
                    f"{label}: HTTP {resp.status} — {detail}. The credential is "
                    "present but not permitted; check the app's granted permissions "
                    "and admin consent.",
                    status=resp.status,
                    body=resp.text()[:500],
                    url=resp.url,
                )
            if (resp.status in RETRY_STATUSES or throttle) and request.idempotent:
                if throttle:
                    self.masked_throttles += 1
                    self.limiter.observe_throttle(resp, throttle)
                if attempt == self.retry.attempts - 1:
                    self.failures += 1
                    named = f"HTTP {resp.status} {throttle}" if throttle else (
                        f"HTTP {resp.status}"
                    )
                    self.last_error = f"{label}: {named} after retries"
                    raise TransientError(
                        f"{label}: {named} persisted across "
                        f"{self.retry.attempts} attempts: {_vendor_error(resp)}",
                        status=resp.status,
                        body=resp.text()[:500],
                        url=resp.url,
                    )
                self.retries += 1
                # A 429 has already pushed the limiter's floor via observe(); the
                # backoff here is for 5xx, and sleeping the max of the two rather
                # than the sum avoids double-counting the same wait.
                hinted = self.limiter.retry_after(resp)
                if hinted > MAX_HONOURED_WAIT:
                    # The floor set by observe() is capped, but this sleep is inside
                    # one send() call and was not. A CDN in front of one of these APIs
                    # emitting Retry-After: 99999 would park the connector for
                    # twenty-eight hours while the fleet still reported it healthy —
                    # it is mid-cycle, not failed. Capped, counted, and named, so the
                    # next cycle re-hits the 429 and the visible consecutive-failure
                    # backoff takes over instead.
                    self.oversized_hints += 1
                    self.last_error = (
                        f"{label}: HTTP {resp.status} asked for a {hinted:.0f}s wait; "
                        f"honouring {MAX_HONOURED_WAIT:.0f}s so the cycle stays "
                        "observable"
                    )
                    hinted = MAX_HONOURED_WAIT
                await self._sleep(max(hinted, self.retry.delay(attempt, self._rng)))
                continue
            self.failures += 1
            detail = _vendor_error(resp)
            self.last_error = f"{label}: HTTP {resp.status} {detail}"
            raise HttpError(
                f"{label}: HTTP {resp.status} — {detail}",
                status=resp.status,
                body=resp.text()[:500],
                url=resp.url,
            )
        raise last or HttpError(f"{label}: no attempt was made")

    async def get_json(self, url: str, **kw: Any) -> Any:
        return (await self.send(Request("GET", url, **kw))).json()

    async def post_json(self, url: str, body: Any, **kw: Any) -> Any:
        return (await self.send(Request("POST", url, json_body=body, **kw))).json()

    def stats(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "requests": self.requests,
            "retries": self.retries,
            "failures": self.failures,
            "mb_in": round(self.bytes_in / 1_048_576, 3),
            "seconds_in_http": round(self.seconds_in_http, 2),
        }
        out.update(self.limiter.stats())
        if self.oversized_hints:
            out["oversized_retry_hints"] = self.oversized_hints
        if self.masked_throttles:
            out["throttles_not_sent_as_429"] = self.masked_throttles
        if self.last_error:
            out["last_http_error"] = self.last_error[:200]
        return out

    async def aclose(self) -> None:
        await self.transport.aclose()


def _error_name(raw: Any) -> str:
    """The bare error name out of the several ways AWS decorates one.

    ``x-amzn-errortype`` is documented as the name and is sent as any of

    * ``ThrottlingException``
    * ``ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.availability/``
    * ``com.amazon.coral.availability#ThrottlingException``

    so the name is what survives stripping a URL suffix and a namespace prefix.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    text = text.split(":", 1)[0]
    text = text.rsplit("#", 1)[-1]
    text = text.rsplit(".", 1)[-1]
    return text.strip().lower()


def throttle_signalled(resp: HttpResponse) -> str:
    """The vendor's throttle name, when a non-429 response is really a throttle.

    Returns the matched name (for the counter and the operator's error line) or ``""``.
    Checks the header before the body because AWS sends both and the header does not
    require parsing a body that may not be JSON at all — a throttle returned by a proxy
    in front of the API is HTML.
    """
    name = _error_name(resp.header("x-amzn-errortype"))
    if name in THROTTLE_ERROR_NAMES:
        return name
    try:
        payload = resp.json()
    except BadPayload:
        return ""
    if not isinstance(payload, Mapping):
        return ""
    for key in ("__type", "code", "Code", "errorCode", "error_code"):
        candidate = _error_name(payload.get(key))
        if candidate in THROTTLE_ERROR_NAMES:
            return candidate
    err = payload.get("error") or payload.get("Error")
    if isinstance(err, Mapping):
        for key in ("code", "Code", "status"):
            candidate = _error_name(err.get(key))
            if candidate in THROTTLE_ERROR_NAMES:
                return candidate
        # Google's legacy JSON error shape puts the machine-readable reason one level
        # deeper: ``{"error": {"code": 403, "message": "Quota exceeded...",
        # "errors": [{"reason": "rateLimitExceeded", "domain": "usageLimits"}]}}``.
        # Nothing at the level above says "throttle" — `code` is the integer 403 and
        # `status` is absent — so a reader that stops at `err["status"]` sees a plain
        # authorization failure and the quota wait never happens.
        nested = err.get("errors")
        if isinstance(nested, list):
            for item in nested:
                if not isinstance(item, Mapping):
                    continue
                for key in ("reason", "message"):
                    candidate = _error_name(item.get(key))
                    if candidate in THROTTLE_ERROR_NAMES:
                        return candidate
    return ""


def _vendor_error(resp: HttpResponse) -> str:
    """The vendor's own error text, from wherever that vendor puts it.

    Five shapes, and the reason for handling all five is that the alternative is an
    operator reading "HTTP 403" and having to reproduce the call by hand to find out
    that the actual message was ``Authorization_RequestDenied: Insufficient
    privileges``. The vendor already said what was wrong; losing it is a choice.
    """
    try:
        payload = resp.json()
    except BadPayload:
        return resp.text()[:200].replace("\n", " ") or "(empty body)"
    if not isinstance(payload, Mapping):
        return str(payload)[:200]
    err = payload.get("error")
    if isinstance(err, Mapping):  # Graph, Azure, GCP
        code = err.get("code") or err.get("status") or ""
        # Graph and Azure put a *name* in `code` ("Authorization_RequestDenied"); Google
        # puts the integer HTTP status there and the name in `status`
        # ("PERMISSION_DENIED"). Every caller of this function has already printed the
        # HTTP status, so preferring a numeric `code` produces "HTTP 403 — 403: ..." —
        # a line that spends its first two fields saying the same thing twice and drops
        # the one token that distinguishes a missing role from an exhausted quota.
        if str(code).strip().isdigit() and err.get("status"):
            code = err["status"]
        msg = err.get("message") or ""
        return f"{code}: {msg}"[:300].strip(": ")
    if isinstance(err, str):  # OAuth2 token endpoints
        desc = payload.get("error_description") or ""
        return f"{err}: {desc}"[:300].strip(": ")
    # AWS: ``{"__type": "AccessDeniedException", "message": "..."}`` — the type is the
    # code and ``message`` carries the sentence. Handled ahead of the generic sweep
    # below, because a sweep that looks for ``__type`` among the message keys finds it
    # first and reports it as *both* code and message, discarding the only part that
    # says what was denied. That is exactly the loss this function exists to prevent.
    aws_type = payload.get("__type")
    if aws_type:
        msg = payload.get("message") or payload.get("Message") or ""
        return f"{aws_type}: {msg}"[:300].strip(": ")
    if isinstance(payload.get("errors"), list) and payload["errors"]:  # CrowdStrike
        head = payload["errors"][0]
        if isinstance(head, Mapping):
            return (
                f"{head.get('code', '')}: {head.get('message', '')}"
            )[:300].strip(": ")
    code = str(payload.get("errorCode") or "")  # Okta pairs this with errorSummary
    for key in ("errorSummary", "message", "Message", "detail", "title"):
        if payload.get(key):
            return f"{code}: {payload[key]}"[:300].strip(": ")
    if code:  # an error code with no accompanying text is still better than nothing
        return code[:300]
    return json.dumps(payload)[:200]


__all__ = [
    "ApiClient",
    "AuthError",
    "BadPayload",
    "DEFAULT_BURST",
    "DEFAULT_RATE_PER_SECOND",
    "HttpError",
    "HttpResponse",
    "HttpxTransport",
    "MAX_HONOURED_WAIT",
    "RETRY_STATUSES",
    "RateLimiter",
    "Request",
    "RetryPolicy",
    "THROTTLE_ERROR_NAMES",
    "Transport",
    "TransientError",
    "throttle_signalled",
]

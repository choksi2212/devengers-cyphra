"""API connectors: the contract every remote telemetry source keeps.

A connector polls somebody else's API and turns the result into OCSF events. Six
things are hard about that, and all six live here rather than being re-solved ten
times with ten sets of bugs: credential readiness, durable cursors, time windowing,
pagination, truncation detection, and rate-limit accounting.

── A correction to what ``ingest.collectors.base`` used to claim ─────────────
That module's docstring argued connectors must not share the collector base class,
because "a class whose every method has two unrelated branches" would result. Having
written both sides, that was wrong, and specifically it was wrong about which parts
differ. The run loop, the exponential backoff on consecutive failure, the batched
submit with backpressure retry, and the whole of :class:`CollectorStats` are
character-for-character the same problem for a remote API as for a local event log.
What actually differs is exactly two methods — :meth:`probe` (credentials rather than
local prerequisites) and :meth:`poll` (HTTP rather than a local read) — and
:class:`~ingest.collectors.base.PullCollector` already models a source that is asked
on a cadence what is new. So :class:`Connector` extends it. Not one method gained a
branch; roughly a hundred and fifty lines of duplicated loop-and-counter did not get
written. The collectors docstring has been corrected to say so.

── Cursors: why the cursor does not advance to "now" ─────────────────────────
The obvious loop is: query ``[cursor, now]``, set ``cursor = now``, sleep. It loses
data on every one of these ten APIs, because none of them are synchronous with their
own clock. Entra sign-in logs are documented as appearing within minutes and observed
to take up to half an hour. CloudTrail states up to 15 minutes. Google Workspace
Drive activity can lag by hours. A record stamped ``12:00:00`` that becomes queryable
at ``12:19:00`` is invisible forever to a connector that moved its cursor to
``12:05:00`` at five past twelve.

So the cursor is advanced to ``max(latest record seen, window_end - indexing_lag)``,
where the lag is that vendor's documented delay. Two things fall out of that, both
wanted: a quiet tenant still makes progress (the floor moves even with zero records),
and a record that arrives late is still inside the next window (the floor stays behind
real time by the lag). The overlap on top of that is belt-and-braces for the case
where the vendor exceeds its own documented lag — duplicates cost nothing, because
:class:`~ingest.pipeline.Pipeline` dedups on a content hash.

── Truncation is detected, not assumed away ─────────────────────────────────
Every API here caps a page and most cap a *query*. The dangerous case is not the
error — it is a response of exactly ``limit`` records with no next-page cursor, which
is indistinguishable from "that is all there was" unless you check. Silent truncation
in a SOC is worse than an outage: the dashboard is green and the window that contained
the intrusion returned 1000 of its 4000 records. So a page-limited response with no
cursor is counted, named in ``soc_notes``, and reported in ``stats_extra`` under
``suspected_truncations``, and the window is halved on the next cycle rather than
re-issued at the same width.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Iterable, Mapping, Sequence

from core.config import Credential, SocConfig
from ingest.collectors.base import (
    Availability,
    CollectorFleet,
    PullCollector,
    available,
    unavailable,
)
from ingest.connectors.auth import Authorizer, CredentialsIncomplete
from ingest.connectors.http import (
    ApiClient,
    AuthError,
    HttpError,
    HttpResponse,
    HttpxTransport,
    RateLimiter,
    Request,
    RetryPolicy,
    Transport,
)
from ingest.pipeline import Pipeline

#: Hard ceiling on pages per cycle. Not a tuning knob so much as a circuit breaker:
#: a cursor that fails to advance (a vendor whose ``next`` link is self-referential
#: under some filter — Okta has done this) turns pagination into an infinite loop that
#: burns the tenant's entire quota. Hitting the ceiling is reported, never silent.
MAX_PAGES_PER_CYCLE = 200

#: How far back a connector reaches on its very first run. Twenty-four hours, because
#: the first cycle should give an analyst something to look at, and because every one
#: of these APIs charges (in quota if not in money) for history. Backfill beyond this
#: is a deliberate operation, not a side effect of starting the service.
DEFAULT_INITIAL_LOOKBACK = 86_400.0

#: Widest single query. A connector down for a week must not ask for a week: Graph
#: will 504, CloudTrail will paginate for an hour, and Okta will silently cap. One
#: hour per query with ``catching_up`` set makes the backlog drain at full rate
#: without any single request being unreasonable.
DEFAULT_MAX_WINDOW = 3_600.0


class ConnectorError(RuntimeError):
    """A connector could not complete a cycle."""


# ── durable cursors ─────────────────────────────────────────────────────────


class Checkpoints:
    """Where a connector's cursor lives between runs.

    A cursor that only lives in memory means every restart re-reads its initial
    lookback — which is either a duplicate storm or, worse, a gap when the restart
    outlasts the lookback. So it is persisted, and the interface is this small so that
    a test can substitute memory without a store.
    """

    async def load(self, name: str) -> dict[str, Any]:
        raise NotImplementedError

    async def save(self, name: str, state: Mapping[str, Any]) -> None:
        raise NotImplementedError


class MemoryCheckpoints(Checkpoints):
    """In-process only. For tests and for a deliberately stateless replay."""

    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}

    async def load(self, name: str) -> dict[str, Any]:
        return dict(self.data.get(name) or {})

    async def save(self, name: str, state: Mapping[str, Any]) -> None:
        self.data[name] = dict(state)


class DocStoreCheckpoints(Checkpoints):
    """Cursors in VedDB, with a write-through cache.

    The cache is not an optimisation. If the store is briefly unreachable, a connector
    whose save failed must not fall back to its *initial lookback* on the next cycle —
    that turns a five-second VedDB blip into a day of re-ingested duplicates. So the
    last known cursor is held in memory, reads prefer it, and a failed save is counted
    and reported rather than raised: losing a cursor write is a durability problem for
    the next process, not a reason to stop collecting in this one.
    """

    COLLECTION = "connector_cursors"

    def __init__(self, store: Any, *, collection: str | None = None) -> None:
        self.store = store
        self.collection = collection or self.COLLECTION
        self._cache: dict[str, dict[str, Any]] = {}
        self.save_failures = 0
        self.last_error = ""

    async def load(self, name: str) -> dict[str, Any]:
        if name in self._cache:
            return dict(self._cache[name])
        try:
            doc = await self.store.get(self.collection, name)
        except Exception as exc:
            self.last_error = f"load: {type(exc).__name__}: {exc}"
            return {}
        state = dict((doc or {}).get("state") or {})
        self._cache[name] = state
        return dict(state)

    async def save(self, name: str, state: Mapping[str, Any]) -> None:
        self._cache[name] = dict(state)
        try:
            await self.store.put(
                self.collection,
                {"id": name, "connector": name, "state": dict(state),
                 "updated": time.time()},
            )
        except Exception as exc:
            self.save_failures += 1
            self.last_error = f"save: {type(exc).__name__}: {exc}"


# ── time windows ────────────────────────────────────────────────────────────


@dataclass(slots=True)
class TimeWindow:
    """One query's half-open time range, ``[start, end)``.

    ``catching_up`` says the window stopped short of now because of
    :attr:`WindowPlanner.max_window_seconds`, so the connector should poll again
    immediately instead of sleeping its cadence. That is the difference between
    draining a day of backlog in minutes and draining it in a day.
    """

    start: float
    end: float
    catching_up: bool = False
    narrowed: bool = False

    @property
    def seconds(self) -> float:
        return max(0.0, self.end - self.start)

    def iso(self) -> tuple[str, str]:
        return iso8601(self.start), iso8601(self.end)


class WindowPlanner:
    """Chooses the next query window, and how far the cursor may then move.

    The four numbers are per-vendor facts, not preferences:

    ``initial_lookback_seconds``
        how much history the first run pulls.
    ``overlap_seconds``
        how far back each window re-reads, to catch records that arrived after their
        window closed.
    ``max_window_seconds``
        widest single query this API answers reliably.
    ``indexing_lag_seconds``
        the vendor's own documented delay between an event happening and it being
        queryable. This is the one that must not be guessed at zero — see the module
        docstring. It is the floor the cursor is not allowed to pass.
    """

    def __init__(
        self,
        *,
        initial_lookback_seconds: float = DEFAULT_INITIAL_LOOKBACK,
        overlap_seconds: float = 120.0,
        max_window_seconds: float = DEFAULT_MAX_WINDOW,
        indexing_lag_seconds: float = 0.0,
        min_window_seconds: float = 30.0,
    ) -> None:
        self.initial_lookback_seconds = initial_lookback_seconds
        self.overlap_seconds = overlap_seconds
        self.max_window_seconds = max_window_seconds
        self.indexing_lag_seconds = indexing_lag_seconds
        self.min_window_seconds = min_window_seconds
        #: Halved after a suspected truncation, restored on a clean cycle. A window
        #: that returned more records than the API would show cannot be re-issued at
        #: the same width and expected to behave differently.
        self._width_divisor = 1.0

    def plan(self, cursor: float | None, now: float) -> TimeWindow:
        start = (now - self.initial_lookback_seconds) if not cursor else (
            cursor - self.overlap_seconds
        )
        start = min(start, now)
        width = max(self.min_window_seconds, self.max_window_seconds / self._width_divisor)
        end = min(now, start + width)
        return TimeWindow(
            start=start,
            end=end,
            catching_up=(start + width) < now,
            narrowed=self._width_divisor > 1.0,
        )

    def advance(
        self, window: TimeWindow, latest_record: float | None, cursor: float | None
    ) -> float:
        """Where the cursor goes after this window. Never backwards.

        ``window.end - indexing_lag_seconds`` is the floor: it makes progress on a
        tenant with no activity, and it deliberately keeps the cursor *behind* real
        time by the vendor's own delay so a record that has not been indexed yet is
        still inside the next window.
        """
        floor = window.end - self.indexing_lag_seconds
        return max(latest_record or 0.0, floor, cursor or 0.0)

    def narrow(self) -> float:
        self._width_divisor = min(64.0, self._width_divisor * 2)
        return self.max_window_seconds / self._width_divisor

    def widen(self) -> None:
        self._width_divisor = 1.0


# ── payload helpers shared by every connector ───────────────────────────────


def iso8601(epoch: float) -> str:
    """``2026-08-29T12:00:00Z`` — the form all ten of these APIs accept.

    Not ``datetime.isoformat()``: that renders ``+00:00``, and Azure's ``$filter``,
    Okta's ``since`` and CloudTrail's ARN filters variously reject it or, worse,
    silently parse it as local time. The ``Z`` form is accepted by all of them.
    Microseconds are dropped because Graph rejects more than three fractional digits
    in a ``$filter`` and truncating is safer than rounding a window boundary forward.
    """
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso8601(value: Any) -> float | None:
    """Epoch seconds from any of the timestamp spellings these APIs emit.

    Six shapes seen across the ten: ``Z``-suffixed, ``+00:00``-suffixed, with 3, 6 or
    7 fractional digits, without fractions, and (CloudTrail's ``EventTime``) a bare
    epoch number. The seven-digit case is Microsoft's — .NET ``DateTime`` ticks — and
    ``datetime.fromisoformat`` rejects it on Python < 3.11 and accepts it since; it is
    truncated to six here so behaviour does not depend on the interpreter version.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(c for c in tail if c.isdigit())
        rest = tail[len(digits):]
        text = f"{head}.{digits[:6]}{rest}" if digits else head + rest
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        # A vendor timestamp with no zone is UTC on every one of these APIs. Assuming
        # local would shift every event by the host's offset — which on a SOC host in
        # IST is 5.5 hours of correlation error, silently.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def dig(doc: Any, path: str, default: Any = None) -> Any:
    """``dig(payload, "status.errorCode")`` — dotted lookup, tolerant of gaps.

    Tolerant because these payloads are deeply optional: a Graph sign-in has
    ``status.errorCode`` always but ``deviceDetail.trustType`` only sometimes, and a
    ``KeyError`` in a normaliser drops an entire batch over one absent field.

    Not for a key that itself contains a dot. OData annotations all do —
    ``@odata.nextLink``, ``@odata.count`` — and this splits on dots, so it would look
    two levels down and report absence. Absence is the dangerous answer for a
    pagination link, so use a plain ``.get`` there; :meth:`GraphConnector._next_link`
    says why at the call site.
    """
    node = doc
    for part in path.split("."):
        if isinstance(node, Mapping):
            node = node.get(part)
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if node is None:
            return default
    return node


def first(doc: Any, *paths: str, default: Any = None) -> Any:
    """The first of several dotted paths that is present and non-empty."""
    for path in paths:
        value = dig(doc, path)
        if value not in (None, "", [], {}):
            return value
    return default


#: Values these APIs put in an IP field that are not IP addresses. Every one is real:
#: AWS uses a service principal in ``sourceIPAddress`` when one service calls another,
#: and GCP uses these literals when the caller is inside Google's network.
_NON_IP_SENTINELS = frozenset({"private", "gce-internal-ip", "internal", "unknown", "-"})


def set_ip(payload: dict[str, Any], field_name: str, value: Any, *, note: str = "") -> None:
    """Put *value* in an IP field only if it is plausibly an IP address.

    This is not defensive programming, it is a documented behaviour of three of these
    APIs. ``sourceIPAddress`` in CloudTrail is ``cloudformation.amazonaws.com`` when
    the caller is another AWS service; ``callerIp`` in GCP audit logs is the literal
    string ``private`` for internal callers; Azure omits the field entirely for
    platform operations. The Event model validates IP fields strictly — it has to,
    because that value reaches ``netsh`` — so an unvalidated assignment would reject
    the whole event and lose a real management-plane action over a field that was
    never an address.

    The value is not discarded: it goes to ``unmapped`` under its own name, where it
    is still queryable, still visible in the lake, and correctly not an IP.
    """
    if value in (None, ""):
        return
    text = str(value).strip()
    if not text:
        return
    if text.lower() in _NON_IP_SENTINELS or (
        ":" not in text and not text.replace(".", "").isdigit()
    ):
        payload.setdefault("unmapped", {})[note or field_name + "_raw"] = text
        return
    payload[field_name] = text


def normalise_records(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """The record array, from whichever key this vendor uses.

    A defensive shape check rather than an indexing expression because the failure it
    prevents is specific: when a token expires mid-pagination some of these APIs
    return ``200`` with an error object rather than a 401, and ``payload["value"]``
    then raises a ``KeyError`` inside the normaliser, which the run loop counts as a
    generic cycle failure. Returning empty and letting the caller notice the missing
    cursor produces a diagnosable "0 records, no next page" instead.

    A **top-level array** is Okta's shape — its System Log returns the events bare,
    with no envelope and no record key — so that connector passes no *keys* at all and
    takes the first branch. Handled here rather than special-cased in the connector
    because :meth:`Connector.paginate` calls this for every vendor, and a connector
    that could not use ``paginate`` would have to reimplement the page cap, the
    self-referential-link guard and the truncation heuristic to read one array.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, Mapping)]
    if not isinstance(payload, Mapping):
        return []
    for key in keys:
        value = dig(payload, key)
        if isinstance(value, list):
            return [r for r in value if isinstance(r, Mapping)]
    return []


# ── the connector base ──────────────────────────────────────────────────────


@dataclass
class ConnectorSpec:
    """The per-vendor facts a connector declares about its API.

    Kept as data rather than as overridden methods so the readiness report can print
    the whole set — "Entra sign-ins, 1000/page, 30 min indexing lag, 4 req/s" is a
    sentence an operator can sanity-check against the vendor's documentation, and a
    number buried in a method body is one nobody ever re-reads.
    """

    page_size: int = 1000
    rate_per_second: float = 4.0
    burst: int = 8
    initial_lookback_seconds: float = DEFAULT_INITIAL_LOOKBACK
    overlap_seconds: float = 120.0
    max_window_seconds: float = DEFAULT_MAX_WINDOW
    indexing_lag_seconds: float = 0.0
    max_pages_per_cycle: int = MAX_PAGES_PER_CYCLE
    #: Documentation URL for the API this connector reads. Printed in setup output so
    #: the operator can check the permission list against the source of truth.
    docs_url: str = ""
    #: Exact permissions/roles the credential needs. The most common cause of a dead
    #: connector is a valid credential with the wrong grant, and "check the app
    #: permissions" is not an instruction — this is.
    required_grants: tuple[str, ...] = ()


class Connector(PullCollector):
    """Base for every remote-API telemetry source.

    A subclass provides :attr:`name`, a :attr:`spec`, the credential slots it needs in
    :meth:`credentials`, an :class:`~ingest.connectors.auth.Authorizer`, and
    :meth:`fetch_window`. Everything else — availability from credential state, the
    cadence loop, durable cursors, window planning, pagination, truncation detection,
    rate-limit accounting, batched submit with backpressure retry — is here.
    """

    kind = "connector"
    #: Overridden per vendor.
    spec: ConnectorSpec = ConnectorSpec()
    #: What this source is worth in a sentence, for the setup report.
    detects: str = ""

    def __init__(
        self,
        pipeline: Pipeline,
        config: SocConfig,
        *,
        transport: Transport | None = None,
        checkpoints: Checkpoints | None = None,
        cadence_seconds: float | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Any] | None = None,
        agent_id: str = "",
        seed: int | None = None,
    ) -> None:
        super().__init__(
            pipeline, cadence_seconds=cadence_seconds, agent_id=agent_id, clock=clock
        )
        self.config = config
        self.checkpoints = checkpoints or MemoryCheckpoints()
        self._transport = transport
        self._client: ApiClient | None = None
        self._seed = seed
        self._sleep = sleep
        self.planner = WindowPlanner(
            initial_lookback_seconds=self.spec.initial_lookback_seconds,
            overlap_seconds=self.spec.overlap_seconds,
            max_window_seconds=self.spec.max_window_seconds,
            indexing_lag_seconds=self.spec.indexing_lag_seconds,
        )
        self.cursor: float | None = None
        self.opaque_cursor: str = ""
        self._loaded = False
        self.pages = 0
        self.page_cap_hits = 0
        self.suspected_truncations = 0
        self.records_seen = 0
        self.windows = 0
        self.catching_up = False
        self.last_window: TimeWindow | None = None
        self.last_auth_error = ""
        # Per-window scratch, reset at the top of `poll()`. Initialised here as well
        # because `fetch_window` is overridable and callable on its own — a backfill
        # tool, a replay harness or a test drives it directly — and `note_record_time`
        # is documented as the thing every implementation must call. Creating this
        # attribute only in `poll()` made that documented contract raise
        # AttributeError for every caller that was not `poll()`.
        self._latest_record: float | None = None
        self._page_truncation_suspected = False
        #: Why truncation was concluded, when a connector knows exactly rather than
        #: suspecting. :meth:`paginate`'s heuristic — a full page with no next link — is
        #: genuinely a *suspicion*, and its wording says so. But three of these APIs
        #: report the total match count alongside the page (CrowdStrike's
        #: ``meta.pagination.total``, GCP's, M365's), which turns "we may have missed
        #: some" into "we missed exactly N". Emitting the heuristic sentence for that
        #: case would describe a mechanism that did not happen, so a connector that
        #: measured it sets its own reason here and :meth:`poll` prefers it.
        self._truncation_reason = ""

    # ── credentials and availability ───────────────────────────────────────

    def credentials(self) -> tuple[Credential, ...]:
        """Every slot this connector needs. Order is the order shown to the operator."""
        return ()

    def authorizer(self) -> Authorizer:
        """How this connector authenticates. Built once, on first use."""
        return Authorizer()

    def probe(self) -> Availability:
        """Configured, partly configured, or not configured — never "healthy".

        Three states, and the middle one is the one a boolean cannot express. An
        operator who set two of Entra's three slots has a connector that will fail on
        its first call with something that looks like a permission error. Naming the
        missing slot here means the readiness report says so before a single request
        goes out.
        """
        creds = self.credentials()
        if not creds:
            return available()
        unset = [c for c in creds if not c.configured]
        if not unset:
            return available(limitation=self._grant_note())
        if len(unset) == len(creds):
            return unavailable(
                f"not configured — set "
                + ", ".join(f"${c.env_var}" for c in unset)
                + f". Without it: {creds[0].purpose}"
                + (f" See {self.spec.docs_url}" if self.spec.docs_url else "")
            )
        return unavailable(
            "PARTLY configured, which is worse than unconfigured: "
            + ", ".join(c.name for c in creds if c.configured)
            + " are set but "
            + ", ".join(f"${c.env_var}" for c in unset)
            + " are missing, so every call will fail as an auth error rather than "
            "reporting the real cause"
        )

    def _grant_note(self) -> str:
        if not self.spec.required_grants:
            return ""
        return (
            "credentials are present; this connector needs "
            + ", ".join(self.spec.required_grants)
            + " — a valid credential without them returns 403, not empty results"
        )

    # ── lifecycle ──────────────────────────────────────────────────────────

    def client(self) -> ApiClient:
        if self._client is None:
            transport = self._transport or HttpxTransport()
            kwargs: dict[str, Any] = {}
            if self._sleep is not None:
                kwargs["sleep"] = self._sleep
            self._client = ApiClient(
                transport,
                limiter=RateLimiter(
                    self.spec.rate_per_second,
                    self.spec.burst,
                    name=self.name,
                    **({"sleep": self._sleep} if self._sleep is not None else {}),
                ),
                retry=RetryPolicy(),
                name=self.name,
                seed=self._seed,
                **kwargs,
            )
            self._client.authorize = self.authorizer()
        return self._client

    async def open(self) -> None:
        await self._load_cursor()

    async def close(self) -> None:
        await self._save_cursor()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass

    async def _load_cursor(self) -> None:
        if self._loaded:
            return
        state = await self.checkpoints.load(self.name)
        value = state.get("cursor")
        self.cursor = float(value) if isinstance(value, (int, float)) else None
        self.opaque_cursor = str(state.get("opaque_cursor") or "")
        self._loaded = True

    async def _save_cursor(self) -> None:
        await self.checkpoints.save(
            self.name,
            {
                "cursor": self.cursor,
                "cursor_iso": iso8601(self.cursor) if self.cursor else "",
                "opaque_cursor": self.opaque_cursor,
                "records_seen": self.records_seen,
                "saved_at": self.clock(),
            },
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        """Read this window from the API and return OCSF payloads.

        Implementations use :meth:`paginate` and are responsible for calling
        :meth:`note_record_time` for each record's own timestamp, which is what lets
        the base advance the cursor to the latest record rather than to wall-clock.
        """
        raise NotImplementedError

    async def poll(self) -> Sequence[dict[str, Any]]:
        await self._load_cursor()
        window = self.planner.plan(self.cursor, self.clock())
        self.last_window = window
        self.windows += 1
        self._latest_record = None
        self._page_truncation_suspected = False
        self._truncation_reason = ""
        try:
            payloads = list(await self.fetch_window(window))
        except AuthError as exc:
            # An auth failure is not a transient cycle failure and must not be retried
            # at cadence forever: against Entra a wrong secret retried every 15 minutes
            # eventually trips smart lockout on the app. Recorded, surfaced through
            # stats, and re-raised so the run loop's backoff applies.
            self.last_auth_error = str(exc)[:300]
            raise
        except CredentialsIncomplete as exc:
            self.last_auth_error = str(exc)
            raise
        self.records_seen += len(payloads)
        if self._page_truncation_suspected:
            self.suspected_truncations += 1
            narrowed = self.planner.narrow()
            reason = self._truncation_reason or (
                f"suspected truncation — a page returned exactly its "
                f"{self.spec.page_size}-record limit with no next-page cursor, which is "
                f"indistinguishable from a complete result"
            )
            for p in payloads[:1]:
                p.setdefault("notes", []).append(
                    f"{self.name}: {reason}; the next window is narrowed to "
                    f"{narrowed:.0f}s"
                )
        else:
            self.planner.widen()
        self.cursor = self.planner.advance(window, self._latest_record, self.cursor)
        self.catching_up = window.catching_up
        await self._save_cursor()
        return payloads

    def note_record_time(self, epoch: float | None) -> None:
        """Report a record's own timestamp so the cursor can follow the data."""
        if epoch is None:
            return
        if self._latest_record is None or epoch > self._latest_record:
            self._latest_record = epoch

    def next_delay(self) -> float:
        """Zero while behind, cadence-times-backoff once current.

        A catching-up connector must not sleep its cadence. Its window is capped at
        :attr:`ConnectorSpec.max_window_seconds`, so the backlog drains one window per
        delay — an hour of downtime at a 900-second cadence takes fifteen hours to
        clear, during which the source reports as healthy because it genuinely is
        collecting, just fifteen hours behind. That is the worst failure mode in this
        file: green dashboard, stale data, and an intrusion that happened during the
        outage sitting unexamined in a queue.

        This is why :meth:`~ingest.collectors.base.Collector.next_delay` exists as a
        hook at all; zeroing ``_backoff`` cannot work, because the run loop resets it
        after every successful cycle.
        """
        if self.catching_up and self.stats.consecutive_failures == 0:
            return 0.0
        return super().next_delay()

    # ── pagination ─────────────────────────────────────────────────────────

    async def paginate(
        self,
        request: Request,
        *,
        records_at: Sequence[str],
        next_url: Callable[[HttpResponse, Any], str | None] | None = None,
        next_body: Callable[[HttpResponse, Any], Any] | None = None,
        max_pages: int | None = None,
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Yield each page's records, following this vendor's next-page mechanism.

        Exactly one of ``next_url`` and ``next_body`` must be supplied, and the two
        exist because the sources split cleanly into two families that cannot share one
        callable:

        * **URL-cursor** (``next_url``) — the next page is a *different address*.
          ``@odata.nextLink`` and ``nextPageToken`` are in the body, Okta's is in the
          ``Link`` header, and M365's ``NextPageUri`` is in a header of its own, which
          is why the callable gets both the response and the parsed body; a helper that
          looked at only one of the two would need a second helper.
        * **Body-cursor** (``next_body``) — the next page is the *same address* with a
          different request body. AWS ``LookupEvents`` and GCP ``entries:list`` are
          both ``POST``s whose ``NextToken``/``pageToken`` belongs in the JSON body, so
          returning a URL cannot express their next page at all. The callable returns
          the whole replacement body rather than just the token, because AWS wants
          ``StartTime``/``EndTime`` repeated on every page and GCP wants ``filter`` and
          ``orderBy`` repeated — omitting them is a 400, not a defaulted request.

        Either callable returns a falsy value when the vendor says there is no next
        page, which is what ends the iteration.

        A returned next URL is used *verbatim*, and page two onward is sent with no
        params: Graph's ``nextLink`` already carries the ``$filter``, ``$top`` and a
        ``$skiptoken``, and re-applying this connector's params to it produces a 400
        about duplicate query options. A body cursor is the mirror image — the URL and
        params are held constant and only the body advances.
        """
        if (next_url is None) == (next_body is None):
            raise ValueError(
                "paginate takes exactly one of next_url and next_body: with both, two "
                "cursors advance per page and the vendor sees a token from one family "
                "applied to the other; with neither, this is a single request that "
                "should be sent through client().send() directly"
            )
        cap = max_pages or self.spec.max_pages_per_cycle
        url: str = request.url
        params: Mapping[str, Any] | None = request.params
        send_body: Any = request.json_body
        # Keyed on the address *and* the body, so the guard holds for both families:
        # a URL cursor varies the address against a constant body, a body cursor
        # varies the body against a constant address.
        seen: set[str] = set()
        for page in range(cap):
            key = f"{url}\n{json.dumps(send_body, sort_keys=True, default=str)}"
            if key in seen:
                # A self-referential cursor. Reported rather than looped, because the
                # loop is unbounded in quota terms even though it is bounded in pages,
                # and the symptom (a connector that reads the same 1000 records every
                # cycle forever) looks like a healthy source.
                self.stats.last_error = (
                    f"{self.name}: pagination returned a cursor it had already "
                    f"followed at page {page}; stopping this cycle"
                )
                return
            seen.add(key)
            resp = await self.client().send(
                Request(
                    method=request.method,
                    url=url,
                    label=request.label,
                    params=params,
                    headers=request.headers,
                    json_body=send_body,
                    form_body=request.form_body,
                    raw_body=request.raw_body,
                    idempotent=request.idempotent,
                    timeout_s=request.timeout_s,
                )
            )
            self.pages += 1
            body = resp.json()
            page_records = normalise_records(body, *records_at)
            following_url = next_url(resp, body) if next_url is not None else None
            following_body = next_body(resp, body) if next_body is not None else None
            pending = bool(following_url) or bool(following_body)
            if len(page_records) >= self.spec.page_size and not pending:
                self._page_truncation_suspected = True
            if page_records:
                yield page_records
            if not pending:
                return
            if following_body:
                send_body = following_body  # url and params stay; see the docstring
            else:
                url = following_url or ""
                params = None  # a next link is complete; see the docstring
            if page + 1 >= cap:
                self.page_cap_hits += 1
                self.stats.last_error = (
                    f"{self.name}: stopped at the {cap}-page ceiling with a next "
                    "cursor still pending; the window is too wide or the tenant too "
                    "busy — records after this point are read on the next cycle, not "
                    "lost"
                )

    # ── reporting ──────────────────────────────────────────────────────────

    def stats_extra(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "cursor": iso8601(self.cursor) if self.cursor else "(none yet)",
            "windows": self.windows,
            "pages": self.pages,
            "records": self.records_seen,
        }
        if self.last_window is not None:
            s, e = self.last_window.iso()
            out["last_window"] = f"{s} → {e} ({self.last_window.seconds:.0f}s)"
        if self.catching_up:
            out["catching_up"] = "yes — polling without cadence delay until current"
        if self.last_window is not None and self.last_window.narrowed:
            out["window_narrowed"] = "after a suspected truncation"
        if self.suspected_truncations:
            out["suspected_truncations"] = self.suspected_truncations
        if self.page_cap_hits:
            out["page_cap_hits"] = self.page_cap_hits
        if self.last_auth_error:
            out["auth_error"] = self.last_auth_error
        if self._client is not None:
            out.update(self._client.stats())
            auth = self._client.authorize
            if isinstance(auth, Authorizer):
                out.update(auth.stats())
        if isinstance(self.checkpoints, DocStoreCheckpoints) and (
            self.checkpoints.save_failures
        ):
            out["cursor_save_failures"] = self.checkpoints.save_failures
            out["cursor_store_error"] = self.checkpoints.last_error[:160]
        return out

    def describe(self) -> str:
        out = super().describe()
        if self.detects:
            out += f"\n    DETECTS: {self.detects}"
        if self.spec.required_grants:
            out += "\n    GRANTS: " + ", ".join(self.spec.required_grants)
        if self.spec.docs_url:
            out += f"\n    DOCS: {self.spec.docs_url}"
        return out


class ConnectorFleet(CollectorFleet):
    """The connectors, reported together with their credential state.

    Subclasses :class:`~ingest.collectors.base.CollectorFleet` rather than reimplementing
    it: start/stop/stats/dropping/limitations are the same operations. What is added is
    the report an operator actually wants from *this* half of ingest — which sources are
    live, which are inert for want of a credential, and exactly what to set.
    """

    def report(self) -> str:
        lines = ["API CONNECTOR FLEET", "=" * 74]
        extras = self.extra_stats()
        live = inert = partial = 0
        for c in self.collectors.values():
            av = c.availability()
            if av:
                live += 1
            elif "PARTLY" in av.reason:
                partial += 1
            else:
                inert += 1
            lines.append("  " + c.stats.line())
            for key, value in sorted(extras.get(c.name, {}).items()):
                lines.append(f"        {key}: {value}")
        lines += [
            "",
            f"  {live} configured, {partial} PARTLY configured, {inert} awaiting "
            "credentials.",
        ]
        if partial:
            lines.append(
                "  A partly-configured connector fails as an auth error, which reads "
                "like a permission problem rather than a missing setting. Fix these first."
            )
        caveats = self.limitations()
        if caveats:
            lines += ["", "GRANTS REQUIRED (a valid credential without them returns 403)"]
            for name, note in caveats:
                lines.append(f"  {name}: {note}")
        gaps = self.unavailable()
        if gaps:
            lines += ["", "NOT COLLECTING"]
            for name, reason, _ in gaps:
                lines.append(f"  {name}: {reason}")
            lines.append(
                "  These are inert, not broken. The emulation generator produces "
                "schema-correct events for every one of them, so detection, "
                "correlation and response are all exercised without a live tenant."
            )
        return "\n".join(lines)

    def credential_slots(self) -> list[tuple[str, Credential]]:
        """``(connector, credential)`` for every slot any connector needs."""
        out: list[tuple[str, Credential]] = []
        for c in self.collectors.values():
            for cred in getattr(c, "credentials", lambda: ())():
                out.append((c.name, cred))
        return out

    def setup_instructions(self) -> str:
        """Exactly what to set, per connector, with the grants each one needs."""
        blocks: list[str] = []
        for c in self.collectors.values():
            av = c.availability()
            if av:
                continue
            creds = getattr(c, "credentials", lambda: ())()
            spec = getattr(c, "spec", None)
            lines = [f"{c.name} — {c.description or 'telemetry source'}"]
            if getattr(c, "detects", ""):
                lines.append(f"    detects: {c.detects}")
            for cred in creds:
                mark = "set" if cred.configured else "MISSING"
                lines.append(f"    [{mark:>7}] ${cred.env_var}")
            if spec is not None and spec.required_grants:
                lines.append("    grants: " + ", ".join(spec.required_grants))
            if spec is not None and spec.docs_url:
                lines.append(f"    docs:   {spec.docs_url}")
            blocks.append("\n".join(lines))
        if not blocks:
            return "Every connector has its credentials; no setup required."
        return (
            "Connectors awaiting credentials. Each is inert until set — the emulation\n"
            "generator covers the pipelines they feed meanwhile.\n\n"
            + "\n\n".join(blocks)
        )


__all__ = [
    "Checkpoints",
    "Connector",
    "ConnectorError",
    "ConnectorFleet",
    "ConnectorSpec",
    "DEFAULT_INITIAL_LOOKBACK",
    "DEFAULT_MAX_WINDOW",
    "DocStoreCheckpoints",
    "MAX_PAGES_PER_CYCLE",
    "MemoryCheckpoints",
    "TimeWindow",
    "WindowPlanner",
    "dig",
    "first",
    "iso8601",
    "normalise_records",
    "parse_iso8601",
    "set_ip",
]

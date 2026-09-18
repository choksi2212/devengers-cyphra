"""
CYPHRA-SOC — the ingest pipeline.

Every collector, connector and remote agent reaches the platform through exactly
one call: :meth:`Pipeline.submit`. That is the whole point of this module. A SOC
with three ingest paths has three normalisation bugs, three retention policies and
three places where a rejected event can vanish.

    raw payloads ──► validate ──► dedup ──► lake (durable) ──► sinks (detect, …)
                        │
                        └──► quarantine (a rejected event is *stored*, not dropped)

── Five decisions worth knowing before reading the code ─────────────────────

**1. A rejection is data, not an error to log and forget.** ``validate_event``
refuses anything partially valid, which is right. But a connector with one broken
field mapping then throws away a hundred percent of its events, and the only
surviving evidence would be a log line nobody reads. So every rejection is written
to the ``ingest_rejects`` lake table with the source, the reason, the claimed time
string and the payload. "Which source is rejecting, since when, and what does its
time field actually say" is then a SQL query, which is what makes it fixable.

**2. Durability comes before fan-out.** The lake write happens before any sink is
called, so a detection can always resolve the event it fired on. The reverse
ordering — notify first, persist later — produces alerts referencing events that
are not in the lake yet, and an investigation that cannot find its own evidence.

**3. Deduplication drops only what the source itself identified.**
``core.schema.ocsf`` sets ``soc_dedup_exact`` when the source named its own event
id (a CloudTrail ``eventID``, a Graph ``id``), which is the only case where two
arrivals are provably the same event — cloud audit APIs redeliver on pagination
retry, so this happens constantly. When the source has no id, ``soc_event_id`` is
a hash of source, agent, time and raw bytes, and two distinct events emitted in
the same instant can collide on it. Dropping one of those would silently lose a
real event, so instead the collision is counted and a note is attached to the
event that arrived second. That note matters downstream: anything keyed on
``soc_event_id`` must not assume uniqueness for a source that reports no id.

**4. Raw retention is the operator's decision, not the collector's.** ``keep_raw``
is resolved from the source declaration and the pipeline default; a value supplied
in the payload is discarded. Keeping raw payloads is a storage-cost and
privacy trade-off, and a chatty collector must not be able to make it.

**5. Backpressure refuses, it does not drop.** The pipeline admits at most
``queue_max_events`` in flight. Beyond that a submit waits, and past its deadline
raises :class:`Backpressure`. Local collectors are simply slowed. A remote agent
receives the refusal and spools to its own disk, which is where the buffer belongs
— core-side memory is the one place a burst must *not* accumulate, because losing
it loses every source at once.

The pipeline holds counters only. Whether a silent source is *dead* is a policy
question with an on-call consequence, and it lives in :mod:`ingest.health`, which
reads :meth:`Pipeline.snapshot`.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Sequence

import pyarrow as pa

from core import config as config_module
from core.config import SocConfig
from core.schema.ocsf import Event, EventRejected, lake_schema, validate_event
from core.store.lake import EXTRA_COLUMN, Lake, LakeTable

__all__ = [
    "Backpressure",
    "EVENTS_TABLE",
    "IngestError",
    "Pipeline",
    "REJECTS_TABLE",
    "Reject",
    "Sink",
    "SourceDeclaration",
    "SourceState",
    "SubmitResult",
    "declare_default_sources",
    "events_table",
    "open_lake",
    "register_tables",
    "rejects_table",
]

EVENTS_TABLE = "events"
REJECTS_TABLE = "ingest_rejects"

#: A quarantined payload is truncated at this size. A source emitting megabyte
#: payloads that all fail validation would otherwise fill the disk with the
#: evidence of its own breakage.
MAX_QUARANTINE_BYTES = 16 * 1024

#: Rejection reasons are grouped in :class:`SubmitResult`; at most this many
#: distinct ones are carried back. One broken field mapping produces one reason
#: repeated five hundred times, and the count is the useful part.
MAX_DISTINCT_REASONS = 5


class IngestError(RuntimeError):
    """The pipeline cannot accept work at all — misconfiguration, not bad data."""


class Backpressure(IngestError):
    """The pipeline is saturated and the caller must retry or spool.

    Raised rather than absorbed. A pipeline that quietly discarded the overflow
    would report a healthy ingest rate while losing events, and the loss would be
    invisible precisely when the platform is under the most load — which is when
    an intrusion is most likely to be in progress.
    """

    def __init__(self, source: str, inflight: int, capacity: int, waited: float) -> None:
        self.source = source
        self.inflight = inflight
        self.capacity = capacity
        self.waited = waited
        super().__init__(
            f"{source}: pipeline saturated — {inflight} of {capacity} events in "
            f"flight after waiting {waited:.1f}s. Retry with backoff, or spool to "
            f"disk if you are a remote agent; do not drop the batch."
        )


# ── lake tables ─────────────────────────────────────────────────────────────


def events_table() -> LakeTable:
    """The normalised-event table, schema generated from :class:`Event`."""
    return LakeTable(name=EVENTS_TABLE, schema=lake_schema(), time_field="time")


def rejects_table() -> LakeTable:
    """The quarantine table.

    ``time`` is *receipt* time, not event time — an event rejected for having no
    usable timestamp has no event time by definition, which is the commonest
    reason a row lands here. The source's own time value is preserved verbatim in
    ``claimed_time`` as a string, because the whole diagnostic value of that
    column is seeing what the connector actually sent: ``0``, ``null``,
    milliseconds-since-epoch, or a format nobody parsed.
    """
    return LakeTable(
        name=REJECTS_TABLE,
        time_field="time",
        schema=pa.schema(
            [
                pa.field("time", pa.float64()),
                pa.field("source", pa.string()),
                pa.field("agent_id", pa.string()),
                pa.field("reason", pa.string()),
                pa.field("claimed_time", pa.string()),
                pa.field("payload", pa.string()),
                pa.field("payload_truncated", pa.bool_()),
                pa.field("payload_sha256", pa.string()),
                pa.field(EXTRA_COLUMN, pa.string()),
            ]
        ),
    )


def register_tables(lake: Lake) -> tuple[LakeTable, LakeTable]:
    """Declare both ingest tables on a lake. Idempotent."""
    return lake.register(events_table()), lake.register(rejects_table())


# ── records ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Reject:
    """One quarantined payload, as held in the recent-rejects ring."""

    time: float
    source: str
    agent_id: str
    reason: str
    claimed_time: str
    payload_sha256: str

    def summary(self) -> str:
        return f"{self.source}: {self.reason}"


@dataclass(frozen=True)
class SourceDeclaration:
    """What the operator says about a telemetry source.

    ``cadence_seconds`` is the source's own expected reporting interval — a Windows
    Security channel on a busy host reports continuously; a daily SaaS audit pull
    reports once. :mod:`ingest.health` multiplies it to decide when silence has
    become death, which is why zero means "unknown cadence, cannot be judged" and
    is reported as such rather than assumed healthy.
    """

    name: str
    cadence_seconds: float = 0.0
    critical: bool = False
    keep_raw: bool | None = None
    max_skew_seconds: float | None = None
    description: str = ""
    kind: str = ""  # "collector" | "connector" | "agent" | "generator"


@dataclass
class SourceState:
    """Counters and clocks for one source. Facts only; no verdict.

    The three time fields answer three different questions and are deliberately
    not collapsed into one "last seen":

    ``last_submit``
        when the source last talked to us at all — a source submitting empty
        batches is connected and finding nothing, which is a different fault from
        a disconnected one.
    ``last_accepted``
        when it last produced an event that survived validation. A source whose
        every event is rejected has a fresh ``last_submit`` and a frozen
        ``last_accepted``; treating the first as health is how a broken field
        mapping stays green for a week.
    ``last_event_time``
        the newest *event* time seen. A connector replaying last month's audit log
        has a fresh ``last_accepted`` and a month-old ``last_event_time``, which is
        the difference between "working" and "caught up".
    """

    source: str
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    id_collisions: int = 0
    time_corrected: int = 0
    first_submit: float = 0.0
    last_submit: float = 0.0
    last_accepted: float = 0.0
    last_event_time: float = 0.0
    max_abs_skew_seconds: float = 0.0
    last_reject_reason: str = ""
    last_reject_time: float = 0.0
    backpressure_refusals: int = 0
    agents: set[str] = field(default_factory=set)

    @property
    def reject_rate(self) -> float:
        return self.rejected / self.received if self.received else 0.0

    def as_dict(self) -> dict[str, Any]:
        d = {
            k: v
            for k, v in self.__dict__.items()
            if not k.startswith("_") and k != "agents"
        }
        d["agents"] = sorted(self.agents)
        d["reject_rate"] = round(self.reject_rate, 6)
        return d


@dataclass
class SubmitResult:
    """What one :meth:`Pipeline.submit` call did.

    Returned rather than logged so the caller can act on it: a connector that sees
    ``rejected == received`` should stop paginating and surface the reason, not
    keep pulling pages into the quarantine table.
    """

    source: str
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    id_collisions: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    sink_errors: dict[str, str] = field(default_factory=dict)
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        """Everything that arrived was either stored or a known duplicate."""
        return self.rejected == 0 and not self.sink_errors

    def summary(self) -> str:
        bits = [f"{self.source}: {self.accepted}/{self.received} accepted"]
        if self.duplicates:
            bits.append(f"{self.duplicates} duplicate")
        if self.rejected:
            top = max(self.reasons.items(), key=lambda kv: kv[1]) if self.reasons else ("", 0)
            bits.append(f"{self.rejected} rejected ({top[0]})")
        if self.id_collisions:
            bits.append(f"{self.id_collisions} colliding ids")
        if self.sink_errors:
            bits.append(f"sink errors: {', '.join(sorted(self.sink_errors))}")
        return ", ".join(bits)


@dataclass
class Sink:
    """A downstream consumer of accepted events.

    ``critical`` decides who owns a sink failure. A non-critical sink that raises
    is counted and the batch still succeeds — a metrics tap must not be able to
    stop ingest. A critical sink that raises fails the submit, which propagates to
    the producer and, for an agent, means the batch is spooled and retried rather
    than acknowledged. That is the correct escalation when the sink is the thing
    that makes ingest worth doing.

    Sinks receive the same :class:`Event` objects, not copies, and must not mutate
    them. Deep-copying five hundred events per sink would cost more than the class
    of bug it prevents, so this is a documented contract rather than an enforced
    one.
    """

    name: str
    fn: Callable[[list[Event]], Awaitable[None] | None]
    critical: bool = False
    calls: int = 0
    events: int = 0
    errors: int = 0
    last_error: str = ""
    seconds: float = 0.0


# ── the pipeline ────────────────────────────────────────────────────────────


class Pipeline:
    """Normalise, quarantine, deduplicate, persist and fan out telemetry."""

    def __init__(
        self,
        lake: Lake,
        config: SocConfig | None = None,
        *,
        keep_raw: bool = False,
        dedup_max_keys: int = 200_000,
        dedup_ttl_seconds: float = 3600.0,
        backpressure_timeout_seconds: float = 5.0,
        recent_rejects: int = 200,
        clock: Callable[[], float] = time.time,
        audit: Any = None,
    ) -> None:
        self.cfg = config or config_module.get()
        self.lake = lake
        self.clock = clock
        self.audit = audit
        self.keep_raw_default = keep_raw
        self.queue_max_events = max(1, self.cfg.ingest.queue_max_events)
        self.backpressure_timeout = backpressure_timeout_seconds
        self.dedup_max_keys = max(0, dedup_max_keys)
        self.dedup_ttl = dedup_ttl_seconds

        register_tables(lake)

        self.sources: dict[str, SourceDeclaration] = {}
        self.state: dict[str, SourceState] = {}
        self.sinks: list[Sink] = []
        self.recent_rejects: deque[Reject] = deque(maxlen=max(1, recent_rejects))

        # Insertion-ordered so eviction is FIFO by arrival, which for an ingest
        # stream is also approximately by age.
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._inflight = 0
        self._drain = asyncio.Event()
        self._drain.set()
        self._started = self.clock()
        self._audit_last: dict[str, float] = {}

        self.total_received = 0
        self.total_accepted = 0
        self.total_rejected = 0
        self.total_duplicates = 0
        self.total_backpressure = 0
        self.dedup_evictions = 0

    # ── declaration ────────────────────────────────────────────────────────

    def declare_source(
        self,
        name: str,
        *,
        cadence_seconds: float = 0.0,
        critical: bool = False,
        keep_raw: bool | None = None,
        max_skew_seconds: float | None = None,
        description: str = "",
        kind: str = "",
    ) -> SourceDeclaration:
        """Declare a source before it reports.

        Declaring is not a permission check — an undeclared source that submits is
        accepted, because a new collector shipping telemetry is not an error and
        refusing it would lose data to a bookkeeping omission. What declaration
        buys is the ability to notice *absence*: a source that never reported and
        was never declared is indistinguishable from one that does not exist, so
        it cannot be reported as dead. :meth:`undeclared` lists the ones that
        showed up unannounced so the gap is visible.
        """
        if not name or not name.strip():
            raise IngestError("a source must have a name; it keys every counter")
        decl = SourceDeclaration(
            name=name,
            cadence_seconds=max(0.0, cadence_seconds),
            critical=critical,
            keep_raw=keep_raw,
            max_skew_seconds=max_skew_seconds,
            description=description,
            kind=kind,
        )
        self.sources[name] = decl
        self.state.setdefault(name, SourceState(source=name))
        return decl

    def undeclared(self) -> list[str]:
        """Sources that have reported but were never declared."""
        return sorted(n for n in self.state if n not in self.sources)

    def add_sink(
        self,
        name: str,
        fn: Callable[[list[Event]], Awaitable[None] | None],
        *,
        critical: bool = False,
    ) -> Sink:
        if any(s.name == name for s in self.sinks):
            raise IngestError(f"sink {name!r} is already registered")
        sink = Sink(name=name, fn=fn, critical=critical)
        self.sinks.append(sink)
        return sink

    def remove_sink(self, name: str) -> bool:
        before = len(self.sinks)
        self.sinks = [s for s in self.sinks if s.name != name]
        return len(self.sinks) != before

    # ── the one entry point ────────────────────────────────────────────────

    async def submit(
        self,
        source: str,
        payloads: Sequence[Mapping[str, Any]],
        *,
        agent_id: str = "",
        keep_raw: bool | None = None,
        keep_events: bool = True,
    ) -> SubmitResult:
        """Ingest a batch from one source.

        Raises :class:`Backpressure` if the pipeline cannot admit the batch; every
        other failure mode is reported in the result rather than raised, because a
        batch of five hundred events with three bad ones must store the other four
        hundred and ninety-seven.

        ``keep_events=False`` drops the accepted events from the result once the
        sinks have seen them. A backfill of ten million rows does not want them
        held in the caller's memory; a test does.
        """
        started = self.clock()
        result = SubmitResult(source=source, received=len(payloads))
        st = self.state.setdefault(source, SourceState(source=source))
        if st.first_submit == 0.0:
            st.first_submit = started
            if source not in self.sources:
                await self._audit_once(
                    f"new-source:{source}",
                    "ingest.source_undeclared",
                    source,
                    {"agent_id": agent_id, "batch": len(payloads)},
                )
        st.last_submit = started
        if agent_id:
            st.agents.add(agent_id)
        self.total_received += len(payloads)
        st.received += len(payloads)

        if not payloads:
            result.seconds = self.clock() - started
            return result

        try:
            await self._acquire(len(payloads), source)
        except Backpressure:
            st.backpressure_refusals += 1
            self.total_backpressure += 1
            await self._audit_once(
                f"backpressure:{source}",
                "ingest.backpressure",
                source,
                {"inflight": self._inflight, "capacity": self.queue_max_events},
            )
            # The batch never entered the pipeline, so it was not received.
            st.received -= len(payloads)
            self.total_received -= len(payloads)
            raise

        try:
            decl = self.sources.get(source)
            resolved_keep_raw = (
                keep_raw
                if keep_raw is not None
                else decl.keep_raw
                if decl is not None and decl.keep_raw is not None
                else self.keep_raw_default
            )
            skew = decl.max_skew_seconds if decl is not None else None

            accepted: list[Event] = []
            quarantined: list[dict[str, Any]] = []
            for payload in payloads:
                try:
                    event = self._build(
                        source, payload, agent_id, resolved_keep_raw, skew, started
                    )
                except EventRejected as exc:
                    row, reject = self._quarantine(source, agent_id, exc, started)
                    quarantined.append(row)
                    self.recent_rejects.append(reject)
                    st.rejected += 1
                    self.total_rejected += 1
                    st.last_reject_reason = exc.reason
                    st.last_reject_time = started
                    if len(result.reasons) < MAX_DISTINCT_REASONS or exc.reason in result.reasons:
                        result.reasons[exc.reason] = result.reasons.get(exc.reason, 0) + 1
                    else:
                        result.reasons["(other)"] = result.reasons.get("(other)", 0) + 1
                    result.rejected += 1
                    continue

                verdict = self._dedup(event, started)
                if verdict == "duplicate":
                    st.duplicates += 1
                    self.total_duplicates += 1
                    result.duplicates += 1
                    continue
                if verdict == "collision":
                    st.id_collisions += 1
                    result.id_collisions += 1

                accepted.append(event)
                if event.soc_time_corrected:
                    st.time_corrected += 1
                st.max_abs_skew_seconds = max(
                    st.max_abs_skew_seconds, abs(event.soc_time_skew_seconds)
                )
                st.last_event_time = max(st.last_event_time, event.time)

            if quarantined:
                await self.lake.append(REJECTS_TABLE, quarantined)

            if accepted:
                # Durability first: a sink may raise, and an alert must never
                # reference an event that is not in the lake.
                await self.lake.append(
                    EVENTS_TABLE, [e.lake_row() for e in accepted]
                )
                st.accepted += len(accepted)
                self.total_accepted += len(accepted)
                st.last_accepted = self.clock()
                result.accepted = len(accepted)
                await self._fan_out(accepted, result)

            if keep_events:
                result.events = accepted
        finally:
            self._release(len(payloads))

        result.seconds = self.clock() - started
        return result

    # ── steps ──────────────────────────────────────────────────────────────

    def _build(
        self,
        source: str,
        payload: Mapping[str, Any],
        agent_id: str,
        keep_raw: bool,
        max_skew: float | None,
        ingested_time: float,
    ) -> Event:
        fields = dict(payload)
        # Policy fields the collector does not get to set. `keep_raw` is a storage
        # and privacy decision (see the module docstring); `soc_agent_id` and
        # `soc_ingested_time` are provenance, and a source that could forge its own
        # provenance makes every downstream attribution unfalsifiable.
        fields.pop("keep_raw", None)
        fields.pop("ingested_time", None)
        fields.pop("soc_agent_id", None)
        fields.pop("soc_ingested_time", None)
        supplied_agent = fields.pop("agent_id", "") or agent_id
        opts: dict[str, Any] = {
            "agent_id": supplied_agent,
            "keep_raw": keep_raw,
            "ingested_time": ingested_time,
        }
        if max_skew is not None:
            opts["max_skew_seconds"] = max_skew
        if "raw" in fields:
            opts["raw"] = fields.pop("raw")
        return validate_event(source, {**fields, **opts})

    def _quarantine(
        self, source: str, agent_id: str, exc: EventRejected, now: float
    ) -> tuple[dict[str, Any], Reject]:
        blob = json.dumps(exc.payload, default=str, sort_keys=True)[: MAX_QUARANTINE_BYTES + 1]
        truncated = len(blob) > MAX_QUARANTINE_BYTES
        if truncated:
            blob = blob[:MAX_QUARANTINE_BYTES]
        sha = hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()
        claimed = exc.payload.get("time", None)
        row = {
            "time": now,
            "source": source,
            "agent_id": agent_id,
            "reason": exc.reason,
            # repr(), not str(): the diagnostic value is in seeing `None` and `'0'`
            # and `0` as three different things, which str() flattens.
            "claimed_time": repr(claimed),
            "payload": blob,
            "payload_truncated": truncated,
            "payload_sha256": sha,
        }
        reject = Reject(
            time=now,
            source=source,
            agent_id=agent_id,
            reason=exc.reason,
            claimed_time=repr(claimed),
            payload_sha256=sha,
        )
        return row, reject

    def _dedup(self, event: Event, now: float) -> str:
        """``"new"``, ``"duplicate"`` or ``"collision"``.

        A duplicate is discarded. A collision is kept — see decision 3 in the
        module docstring — with a note recorded on the event so that anything
        keying on ``soc_event_id`` downstream can see the id is not unique for
        this source.
        """
        if not self.dedup_max_keys:
            return "new"
        key = event.soc_event_id
        seen_at = self._seen.get(key)
        fresh = seen_at is not None and (now - seen_at) <= self.dedup_ttl
        self._seen[key] = now
        self._seen.move_to_end(key)
        while len(self._seen) > self.dedup_max_keys:
            self._seen.popitem(last=False)
            self.dedup_evictions += 1
        if not fresh:
            return "new"
        if event.soc_dedup_exact:
            return "duplicate"
        note = (
            "another event from this source already carried this soc_event_id "
            "within the dedup window, and the source names no event id of its own, "
            "so the id is not unique here — do not key on it"
        )
        if note not in event.soc_notes:
            event.soc_notes.append(note)
        return "collision"

    async def _fan_out(self, events: list[Event], result: SubmitResult) -> None:
        for sink in self.sinks:
            began = self.clock()
            try:
                outcome = sink.fn(events)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception as exc:  # a sink is arbitrary downstream code
                sink.errors += 1
                sink.last_error = f"{type(exc).__name__}: {exc}"
                result.sink_errors[sink.name] = sink.last_error
                await self._audit_once(
                    f"sink:{sink.name}",
                    "ingest.sink_error",
                    sink.name,
                    {"error": sink.last_error, "critical": sink.critical},
                )
                if sink.critical:
                    raise
            else:
                sink.calls += 1
                sink.events += len(events)
            finally:
                sink.seconds += self.clock() - began

    # ── admission control ──────────────────────────────────────────────────

    async def _acquire(self, n: int, source: str) -> None:
        if n > self.queue_max_events:
            raise Backpressure(source, self._inflight, self.queue_max_events, 0.0)
        # `time.monotonic`, deliberately not `self.clock`. Every other clock read in
        # this module is a *timestamp* — when an event arrived, how stale a source
        # is — and those are injectable so a test can fast-forward and so an
        # operator can reason about them in wall-clock terms. This one is a
        # *deadline for an await*, and the two must not share a source: a clock
        # that does not advance (a frozen test clock) or that steps backwards (an
        # NTP correction, a VM resume) makes the difference below never reach zero,
        # and the loop waits forever while reporting that it is about to give up.
        started = time.monotonic()
        while True:
            if self._inflight + n <= self.queue_max_events:
                # No await between the test and the increment, so under a single
                # event loop this is atomic and no lock is needed.
                self._inflight += n
                if self._inflight >= self.queue_max_events:
                    self._drain.clear()
                return
            self._drain.clear()
            waited = time.monotonic() - started
            remaining = self.backpressure_timeout - waited
            if remaining <= 0:
                raise Backpressure(
                    source, self._inflight, self.queue_max_events, waited
                )
            # A bounded wait rather than an asyncio.Condition: `wait_for` around
            # `Condition.wait()` can consume a notification and still raise, and
            # the failure mode is a hang. Capping the wait makes a lost wakeup a
            # 250 ms delay instead.
            try:
                await asyncio.wait_for(self._drain.wait(), min(remaining, 0.25))
            except asyncio.TimeoutError:
                pass

    def _release(self, n: int) -> None:
        self._inflight = max(0, self._inflight - n)
        self._drain.set()

    # ── audit ──────────────────────────────────────────────────────────────

    async def _audit_once(
        self, dedup_key: str, action: str, target: str, data: Mapping[str, Any]
    ) -> None:
        """Record a rare ingest fact, at most once a minute per key.

        Per-event auditing is impossible here: the chain fsyncs each record at a
        few hundred a second against an ingest path that does eighty thousand. So
        the chain gets the facts that are rare and consequential — an undeclared
        source appearing, saturation, a sink failing — and the rate limit stops a
        collector that is broken in a loop from burying them.
        """
        if self.audit is None:
            return
        now = self.clock()
        if now - self._audit_last.get(dedup_key, 0.0) < 60.0:
            return
        self._audit_last[dedup_key] = now
        try:
            append = self.audit.append
            outcome = append(action=action, actor="ingest.pipeline", target=target, data=dict(data))
            if asyncio.iscoroutine(outcome):
                await outcome
        except Exception:
            # An audit failure must not stop ingest, and it is already visible in
            # the chain's own verify() as a gap.
            pass

    # ── introspection ──────────────────────────────────────────────────────

    async def flush(self) -> dict[str, int]:
        """Force every buffered row to Parquet. Returns rows written per table."""
        return await self.lake.flush()

    def snapshot(self) -> dict[str, Any]:
        """Everything :mod:`ingest.health` and the console need, as plain data."""
        return {
            "started": self._started,
            "uptime_seconds": round(self.clock() - self._started, 3),
            "totals": {
                "received": self.total_received,
                "accepted": self.total_accepted,
                "rejected": self.total_rejected,
                "duplicates": self.total_duplicates,
                "backpressure_refusals": self.total_backpressure,
            },
            "inflight": self._inflight,
            "capacity": self.queue_max_events,
            "dedup": {
                "tracked": len(self._seen),
                "capacity": self.dedup_max_keys,
                "evictions": self.dedup_evictions,
                "ttl_seconds": self.dedup_ttl,
            },
            "declared": {n: d.__dict__ for n, d in sorted(self.sources.items())},
            "undeclared": self.undeclared(),
            "sources": {n: s.as_dict() for n, s in sorted(self.state.items())},
            "sinks": [
                {
                    "name": s.name,
                    "critical": s.critical,
                    "calls": s.calls,
                    "events": s.events,
                    "errors": s.errors,
                    "last_error": s.last_error,
                    "seconds": round(s.seconds, 4),
                }
                for s in self.sinks
            ],
            "recent_rejects": [r.__dict__ for r in list(self.recent_rejects)[-20:]],
        }

    def rate(self) -> float:
        """Accepted events per second since start."""
        elapsed = self.clock() - self._started
        return self.total_accepted / elapsed if elapsed > 0 else 0.0

    async def close(self) -> None:
        await self.flush()


# ── convenience constructors ────────────────────────────────────────────────


def open_lake(config: SocConfig | None = None, **kwargs: Any) -> Lake:
    """A lake at the configured path with both ingest tables declared."""
    cfg = config or config_module.get()
    lake = Lake(
        root=cfg.store.lake_dir,
        duckdb_path=cfg.store.duckdb_path,
        flush_rows=kwargs.pop("flush_rows", 50_000),
        flush_seconds=kwargs.pop("flush_seconds", 60.0),
        memory_limit=kwargs.pop("memory_limit", cfg.store.duckdb_memory_limit),
        threads=kwargs.pop("threads", cfg.store.duckdb_threads),
        **kwargs,
    )
    register_tables(lake)
    return lake


def declare_default_sources(pipeline: Pipeline) -> list[SourceDeclaration]:
    """Declare the sources this build ships collectors and connectors for.

    Declared even when unconfigured, and that is the point: :mod:`ingest.health`
    reports "declared, never reported" as its own state. A SOC that only knows
    about the sources currently sending data cannot tell you that the Okta feed
    has been silent since the day it was set up.
    """
    out = []
    for name, cadence, critical, kind, desc in _DEFAULT_SOURCES:
        out.append(
            pipeline.declare_source(
                name,
                cadence_seconds=cadence,
                critical=critical,
                kind=kind,
                description=desc,
            )
        )
    return out


#: name, expected cadence (s), critical, kind, description.
#:
#: Cadence is the interval inside which a *working* source should produce at
#: least one event, not its polling interval — a quiet DNS resolver at 3 a.m.
#: must not page anyone. Where a source can legitimately be silent for a long
#: time the cadence is set to its poll interval times a small factor, and
#: `health_stale_multiplier` is applied on top of that.
_DEFAULT_SOURCES: tuple[tuple[str, float, bool, str, str], ...] = (
    ("network_flow", 60.0, True, "collector", "Scapy/Npcap flow features on the local NIC"),
    ("windows_eventlog", 300.0, True, "collector", "Security/System/Application channels"),
    ("sysmon", 300.0, False, "collector", "Sysmon operational channel, if installed"),
    ("process", 60.0, True, "collector", "psutil process creation and termination"),
    ("dns", 300.0, False, "collector", "DNS queries and answers"),
    # Three sources, not one, because local authentication on an unelevated Windows
    # host comes from three unrelated mechanisms with three different silence
    # profiles: an event-log reader, a diff of the LSA logon-session table, and a
    # diff of the local account database. Declaring them as one `local_auth` would
    # mean one cadence for all three, and the only cadence that fits an account
    # database that legitimately does not change for a week is one so long that it
    # would never notice the event-log reader dying.
    #
    # None of the three is critical. That is deliberate and it is not a claim that
    # identity telemetry is unimportant — `windows_eventlog` above is critical and it
    # is the collector that owns the Security channel. These three are the *substitutes*
    # for a Security channel that cannot be read, and on this host they are measurably
    # partial (2 of 14 logon sessions are readable unelevated). Raising a critical
    # fault when a known-degraded substitute stops would report the loss of coverage
    # that was never there.
    ("local_auth_log", 900.0, False, "collector",
     "authentication from Security plus the unelevated substitute channels"),
    # Both state collectors emit a state-observed heartbeat every hour even when
    # nothing changed, which is what gives these two a cadence to be judged against
    # at all: absence of change is normal for them, so absence of events cannot mean
    # death. 7200 is two heartbeats, so one missed hour is not a fault.
    ("logon_sessions", 7200.0, False, "collector",
     "LSA logon-session table, diffed — the state substitute for 4624/4634"),
    ("local_accounts", 7200.0, False, "collector",
     "local users, group membership and password policy, diffed"),
    ("entra_signin", 900.0, False, "connector", "Microsoft Entra ID sign-in logs"),
    ("entra_audit", 3600.0, False, "connector", "Entra directory audit"),
    ("okta_system_log", 900.0, False, "connector", "Okta System Log"),
    ("defender_alerts", 900.0, False, "connector", "Microsoft Defender for Endpoint"),
    ("crowdstrike_detects", 900.0, False, "connector", "CrowdStrike Falcon detections"),
    ("aws_cloudtrail", 900.0, False, "connector", "AWS CloudTrail management events"),
    ("azure_activity", 900.0, False, "connector", "Azure Activity Log"),
    ("gcp_audit", 900.0, False, "connector", "GCP Cloud Audit Logs"),
    ("m365_email", 1800.0, False, "connector", "Microsoft 365 message trace and events"),
    ("google_workspace", 1800.0, False, "connector", "Google Workspace admin/login reports"),
    ("saas_audit", 3600.0, False, "connector", "generic SaaS audit-log connector"),
    ("emulation", 0.0, False, "generator", "adversary-emulation telemetry generator"),
)

"""Local telemetry collectors: the contract every one of them keeps.

A collector is the code that turns something on *this host* — a packet on a wire,
a record in the Windows Event Log, a process that started — into OCSF events in
the pipeline. Connectors (:mod:`ingest.connectors`) do the same for remote APIs.

This docstring used to claim connectors could not share this base class, because
"a class whose every method has two unrelated branches" would result. Having since
written both sides: that was wrong, and wrong about which parts differ.
Authentication, pagination and someone else's cursor semantics are all real
problems, but none of them touch the run loop, the consecutive-failure backoff, the
batched submit with backpressure retry, or :class:`CollectorStats` — those are
character-for-character identical for a remote API and a local event log. Only
:meth:`Collector.probe` and :meth:`PullCollector.poll` differ, which is exactly the
seam :class:`PullCollector` already exposes. So :class:`~ingest.connectors.Connector`
extends it, no method gained a branch, and about a hundred and fifty lines of
duplicated loop-and-counter did not get written. The one thing the connectors needed
that was genuinely missing is :meth:`Collector.next_delay` — see decision 5.

Five decisions live here, each because the obvious alternative fails in a way that
is invisible from a dashboard.

**1. Unavailable is a first-class outcome, not an exception.** Most collectors here
cannot run on an arbitrary host: packet capture needs Npcap and administrator, the
Sysmon channel needs Sysmon installed, the Security event log needs elevation. The
tempting design is to start and let it throw. But a collector that raises at start
is indistinguishable, an hour later, from a collector that started fine and found
nothing — and "found nothing" is what a SOC dashboard renders as green. So every
collector answers :meth:`Collector.probe` *before* it runs, returning a reason
string that names the missing prerequisite and, where one exists, the command that
installs it. The reason is registered with :class:`~ingest.health.HealthMonitor`,
which reports the source as ``UNCONFIGURED`` with that text rather than pretending
it is healthy. An unavailable collector is a known, stated, visible gap.

**2. Pull and push are both real, so both are supported explicitly.** An event-log
or process collector is *pull*: it wakes on a cadence, reads what is new since its
cursor, and submits. A packet capture is *push*: scapy calls a callback from its
own thread whenever a flow completes, at a rate nobody controls. Modelling push as
pull means polling a queue and inventing a latency; modelling pull as push means a
thread per collector doing nothing. So :class:`PullCollector` implements
:meth:`~PullCollector.poll` and the base runs it on a cadence, while
:class:`PushCollector` gets :meth:`~PushCollector.offer` — thread-safe, callable
from any thread — and the base drains its buffer.

**3. A push collector's buffer is bounded, and overflow is counted as a loss.**
The pipeline refuses rather than drops (``Backpressure``) and tells its caller to
spool. A remote agent can spool to disk. A live packet capture cannot: packets
arrive whether or not anyone is ready, and an unbounded buffer converts a slow
consumer into an out-of-memory kill that takes the whole collector fleet with it.
So the buffer has a ceiling, and past it the *oldest* events are discarded — newest
data is the more useful when you cannot keep all of it — and ``dropped`` is
incremented. That counter is surfaced in :meth:`Collector.stats` and reported by
the fleet, because a collector silently losing 30% of its telemetry is exactly the
condition that makes a SOC confident and blind at the same time. Dropping and
saying so is defensible; dropping quietly is not.

**4. A collector that fails does not die, and does not fail silently either.** The
run loop catches per-cycle exceptions, counts them, records the last one, and keeps
its cadence — one malformed record must not end collection for the rest of the
day. But consecutive failures escalate: after :data:`BACKOFF_AFTER` of them the
cadence backs off exponentially (so a broken collector stops burning CPU and
filling logs), and the failure count and last error are part of ``stats`` so the
fleet can report it. A collector that has failed every cycle for an hour is *not*
reporting, which ``ingest.health`` independently sees as ``DEAD`` from the other
side — the two views are deliberately redundant, because they fail differently.

**5. The delay between cycles is a method, not an expression.** The loop needs to
sleep ``cadence × backoff``, and for a local collector that is all it ever needs. A
connector draining a backlog needs something else: after an hour of downtime it has
an hour of history to fetch in one-hour-wide queries, and at a 900-second cadence
that backlog takes fifteen hours to clear — while the SOC shows the source as
healthy, because it *is* collecting, just fifteen hours behind. Zeroing
``_backoff`` from :meth:`cycle` cannot fix this: the loop resets it to ``1.0`` on
every success, immediately after ``cycle`` returns. So the loop asks
:meth:`Collector.next_delay`, whose default is exactly the old expression, and a
connector that knows it is behind returns zero and polls straight through until it
is current. One overridable method, no branch, and the alternative — a second copy
of the run loop in the connector base — is the thing this avoids.
"""

from __future__ import annotations

import asyncio
import inspect
import platform
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Sequence

from ingest.pipeline import Backpressure, Pipeline

#: Consecutive failed cycles before the cadence starts backing off.
BACKOFF_AFTER = 3
#: Ceiling on the backoff multiplier, so a collector still retries hourly-ish
#: rather than effectively never.
BACKOFF_MAX = 32.0
#: Default push buffer ceiling. 50k flow events is a few tens of MB and roughly a
#: minute of a busy interface — long enough to ride out a lake flush, short enough
#: that it cannot be mistaken for durable storage.
DEFAULT_BUFFER = 50_000
#: How many events a single submit carries. Large enough that per-call overhead is
#: amortised, small enough that one refused batch is a small retry.
DEFAULT_BATCH = 500


@dataclass(slots=True)
class Availability:
    """Whether a collector can run here, and if not, precisely why.

    ``reason`` is written for whoever has to fix it: it names the missing thing and
    the action that supplies it. "not available" is useless; "requires Npcap —
    install from https://npcap.com and re-run in an elevated shell" is actionable.
    ``fixable_by_user`` distinguishes a prerequisite the operator can install from
    a hard property of the platform (a Windows Event Log collector on Linux), which
    matters because the first belongs in a setup checklist and the second does not.

    ``limitation`` is the third answer, and the one a two-state available/unavailable
    flag cannot express: *this runs, and it is still incomplete*. A polled process
    collector cannot see a process that lives eleven milliseconds; an unelevated one
    cannot read another account's command line. Both are available. Reporting them as
    simply "available" tells the operator that process coverage is handled, which is
    the false claim that makes a permanent blind spot invisible — so the caveat is
    carried here and printed under its own heading, rather than folded into
    ``reason`` where it would render as a failure the operator cannot find.
    """

    available: bool
    reason: str = ""
    fixable_by_user: bool = False
    limitation: str = ""

    def __bool__(self) -> bool:
        return self.available


def available(limitation: str = "") -> Availability:
    """Available. Pass *limitation* when it runs but cannot see everything."""
    return Availability(True, "", limitation=limitation)


def unavailable(reason: str, *, fixable_by_user: bool = True) -> Availability:
    return Availability(False, reason, fixable_by_user)


@dataclass
class CollectorStats:
    """What a collector will say about itself when asked.

    Deliberately includes the unflattering numbers. ``dropped`` and ``failures``
    are the two that a status page would rather not show and the two an operator
    most needs, so they are not optional and not aggregated away.
    """

    name: str
    kind: str = "collector"
    running: bool = False
    available: bool = True
    unavailable_reason: str = ""
    cycles: int = 0
    produced: int = 0
    submitted: int = 0
    accepted: int = 0
    rejected: int = 0
    dropped: int = 0
    buffered: int = 0
    buffer_capacity: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    last_error: str = ""
    last_error_time: float = 0.0
    last_cycle_time: float = 0.0
    backpressure_waits: int = 0
    seconds_collecting: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            k: getattr(self, k)
            for k in self.__dataclass_fields__  # type: ignore[attr-defined]
        }

    def line(self) -> str:
        if not self.available:
            return f"{self.name:<20} UNAVAILABLE  {self.unavailable_reason}"
        bits = [
            f"{self.name:<20}",
            "running" if self.running else "stopped",
            f"{self.accepted} accepted",
        ]
        if self.rejected:
            bits.append(f"{self.rejected} rejected")
        if self.dropped:
            bits.append(f"{self.dropped} DROPPED")
        if self.failures:
            bits.append(f"{self.failures} failures ({self.last_error[:60]})")
        return "  ".join(bits)


class Collector(ABC):
    """Base for every local collector.

    Subclasses set :attr:`name`, :attr:`cadence_seconds` and :attr:`critical`, and
    implement :meth:`probe` plus one of :meth:`PullCollector.poll` /
    :meth:`PushCollector.start_source`.
    """

    #: Source name as it appears in the pipeline, health monitor and lake. Must
    #: match the declaration in ``ingest.pipeline._DEFAULT_SOURCES`` or the health
    #: monitor has no cadence to judge silence against.
    name: str = ""
    #: Nominal seconds between cycles. For a push collector this is the *flush*
    #: interval, not the data rate.
    cadence_seconds: float = 60.0
    #: How long this source may be **silent** before the health monitor should call it
    #: dead, when that is not the same as its poll cadence. ``None`` means they are the
    #: same, which is true of every collector that emits something on every cycle.
    #:
    #: They come apart for a state-diff collector, and badly. ``logon_sessions`` polls
    #: the LSA table every 30 s and emits only when the table *changes*, plus one
    #: heartbeat an hour. Declaring 30 s as its silence tolerance would have the monitor
    #: report it dead within a minute of starting on an idle host — and then keep
    #: reporting it dead, correctly by the rule and wrongly about the world, for as long
    #: as nobody logged on. The only cadence that fits is the heartbeat interval, and
    #: the only cadence that fits *polling* is 30 s, so the two numbers are genuinely
    #: different facts about the same collector.
    #:
    #: :meth:`CollectorFleet.add` declares this to the pipeline when it is set.
    health_cadence_seconds: float | None = None
    #: Whether losing this source should be treated as a critical fault.
    critical: bool = False
    #: Free-text description used in setup output.
    description: str = ""
    #: ``collector`` here; the fleet uses it to group.
    kind: str = "collector"

    def __init__(
        self,
        pipeline: Pipeline,
        *,
        cadence_seconds: float | None = None,
        batch_size: int = DEFAULT_BATCH,
        agent_id: str = "",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not self.name:
            raise ValueError(f"{type(self).__name__} must set a name")
        self.pipeline = pipeline
        self.batch_size = batch_size
        self.agent_id = agent_id
        self.clock = clock
        if cadence_seconds is not None:
            self.cadence_seconds = cadence_seconds
        self.stats = CollectorStats(
            name=self.name, kind=self.kind, buffer_capacity=0
        )
        self._availability: Availability | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._backoff = 1.0

    # ── availability ───────────────────────────────────────────────────────

    @abstractmethod
    def probe(self) -> Availability:
        """Can this collector run on this host, right now?

        Called before start and cached. Must not raise and must not have side
        effects beyond reading — it is called during setup reporting, on hosts
        where the answer is expected to be no.
        """

    def availability(self, *, refresh: bool = False) -> Availability:
        if self._availability is None or refresh:
            try:
                self._availability = self.probe()
            except Exception as exc:  # a probe that throws is itself unavailability
                self._availability = unavailable(
                    f"availability probe failed: {type(exc).__name__}: {exc}",
                    fixable_by_user=False,
                )
            self.stats.available = self._availability.available
            self.stats.unavailable_reason = self._availability.reason
        return self._availability

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def open(self) -> None:
        """Acquire whatever the collector needs. Override if there is anything."""

    async def close(self) -> None:
        """Release it again. Override if there is anything."""

    async def cycle(self) -> int:
        """One unit of collection. Returns events submitted. Implemented by shape."""
        raise NotImplementedError

    async def run(self) -> None:
        """The loop. Never raises out; failures are counted and the cadence kept."""
        av = self.availability()
        if not av:
            # Not an error and not a silent no-op: the fleet has already registered
            # this reason with the health monitor, so the source reads as
            # UNCONFIGURED with the text rather than as quietly absent.
            return
        try:
            await self.open()
        except Exception as exc:
            self._record_failure(exc)
            return
        self.stats.running = True
        started = self.clock()
        try:
            while not self._stop.is_set():
                t0 = self.clock()
                try:
                    await self.cycle()
                    self.stats.consecutive_failures = 0
                    self._backoff = 1.0
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self._record_failure(exc)
                self.stats.cycles += 1
                self.stats.last_cycle_time = self.clock()
                self.stats.seconds_collecting = self.clock() - started
                delay = self.next_delay()
                try:
                    await asyncio.wait_for(self._stop.wait(), delay)
                except asyncio.TimeoutError:
                    pass
        finally:
            self.stats.running = False
            try:
                await self.close()
            except Exception as exc:
                self._record_failure(exc)

    def start(self) -> asyncio.Task | None:
        if self._task and not self._task.done():
            return self._task
        if not self.availability():
            return None
        self._stop.clear()
        self._task = asyncio.create_task(self.run(), name=f"collector:{self.name}")
        return self._task

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, 10.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            except Exception:
                pass
            self._task = None

    def next_delay(self) -> float:
        """How long to wait before the next cycle. Cadence times backoff, normally.

        A hook rather than an inline expression because a source that is *behind* has
        to be able to say so. See decision 5 in the module docstring: the run loop
        resets ``_backoff`` to 1.0 after every successful cycle, so a subclass cannot
        signal "poll again immediately" by touching that field — by the time the delay
        is computed its value has already been overwritten.

        A zero return is honoured, and is safe: ``asyncio.wait_for(..., 0)`` still
        yields to the event loop, so a connector draining a backlog cannot starve the
        rest of the fleet no matter how many windows it has to fetch.
        """
        return max(0.0, self.cadence_seconds * self._backoff)

    def _record_failure(self, exc: BaseException) -> None:
        self.stats.failures += 1
        self.stats.consecutive_failures += 1
        self.stats.last_error = f"{type(exc).__name__}: {exc}"
        self.stats.last_error_time = self.clock()
        if self.stats.consecutive_failures >= BACKOFF_AFTER:
            # Back off, but never so far that recovery is never noticed.
            self._backoff = min(BACKOFF_MAX, self._backoff * 2 or 2.0)

    # ── submission ─────────────────────────────────────────────────────────

    async def _submit(self, payloads: Sequence[dict[str, Any]]) -> int:
        """Hand a batch to the pipeline, in ``batch_size`` chunks.

        A ``Backpressure`` refusal is *retried*, not dropped — the pipeline's whole
        contract is that a refusal means "wait", and a collector that treated it as
        a discard would turn a transient lake flush into permanent data loss. The
        wait is bounded and counted; if it still cannot get in, the exception
        propagates to the run loop, which counts a failure and keeps the cadence.
        A push collector's buffer keeps holding the events meanwhile, and *that*
        is where a genuine overflow is decided and counted.
        """
        if not payloads:
            return 0
        total = 0
        for i in range(0, len(payloads), self.batch_size):
            chunk = list(payloads[i : i + self.batch_size])
            for attempt in range(3):
                try:
                    result = await self.pipeline.submit(
                        self.name, chunk, agent_id=self.agent_id, keep_events=False
                    )
                except Backpressure:
                    self.stats.backpressure_waits += 1
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.25 * (attempt + 1))
                    continue
                self.stats.submitted += result.received
                self.stats.accepted += result.accepted
                self.stats.rejected += result.rejected
                total += result.accepted
                break
        return total

    def describe(self) -> str:
        av = self.availability()
        head = f"{self.name} ({self.kind}, every {self.cadence_seconds:.0f}s)"
        if self.health_cadence_seconds is not None:
            head = (
                f"{self.name} ({self.kind}, polls every {self.cadence_seconds:.0f}s, "
                f"silent for up to {self.health_cadence_seconds:.0f}s legitimately)"
            )
        if self.critical:
            head += " [critical]"
        if not av:
            return f"{head}\n    UNAVAILABLE: {av.reason}"
        out = f"{head}\n    {self.description}"
        if av.limitation:
            out += f"\n    LIMITATION: {av.limitation}"
        return out

    def stats_extra(self) -> dict[str, Any]:
        """Numbers this collector knows that :class:`CollectorStats` has no field for.

        Overridden by collectors with source-specific accounting to report — the
        capture engine's own counters, how many parent PIDs could not be resolved,
        how wide the polling blind window is. The base returns nothing.

        This is read by :meth:`CollectorFleet.report` rather than by the collector
        itself, which is the point: a counter that measures a collector's own
        blindness is worthless if the only way to see it is to know it exists and go
        looking. Anything returned here is printed.
        """
        return {}


class PullCollector(Collector):
    """A collector that is asked, on a cadence, what is new.

    Cursor management is the subclass's business — an Event Log bookmark, a file
    offset, a last-seen timestamp — because every source expresses "since" its own
    way and a generic cursor would be a lowest common denominator that fits none of
    them. What the base guarantees is that :meth:`poll` is called on a cadence, its
    exceptions are counted rather than fatal, and its output reaches the pipeline.
    """

    @abstractmethod
    async def poll(self) -> Sequence[dict[str, Any]]:
        """Return payloads observed since the last call. May be empty."""

    async def cycle(self) -> int:
        payloads = await self.poll()
        self.stats.produced += len(payloads)
        return await self._submit(payloads)


class PushCollector(Collector):
    """A collector fed by something else's thread, at a rate nobody controls.

    :meth:`offer` is the thread-safe entry point: the underlying source calls it
    from its own thread and it must be cheap and non-blocking, because it runs on
    the path that is also handling packets. It appends to a bounded deque and
    returns. The asyncio side drains that deque on the cadence.

    The deque is the whole reason this class exists separately. ``collections.deque``
    with a ``maxlen`` is documented thread-safe for ``append`` and ``popleft``, and
    an over-capacity append discards from the *other* end atomically — which is
    exactly the overflow policy wanted, with no lock on the packet path. The cost
    is that the discard is silent at the deque level, so :meth:`offer` compares
    length before and after to count it.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        *,
        buffer_size: int = DEFAULT_BUFFER,
        **kwargs: Any,
    ) -> None:
        super().__init__(pipeline, **kwargs)
        self._buf: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self.stats.buffer_capacity = buffer_size

    def offer(self, payload: dict[str, Any]) -> None:
        """Accept one event from an arbitrary thread. Never blocks, never raises."""
        buf = self._buf
        before = len(buf)
        buf.append(payload)
        if before == buf.maxlen:
            # The deque evicted the oldest to make room. Counted here because the
            # alternative — a collector quietly losing a third of its telemetry —
            # is the failure this whole module is written to make impossible.
            self.stats.dropped += 1
        self.stats.produced += 1
        self.stats.buffered = len(buf)

    def _drain(self, limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        buf = self._buf
        while buf and len(out) < limit:
            try:
                out.append(buf.popleft())
            except IndexError:  # drained by a concurrent consumer
                break
        self.stats.buffered = len(buf)
        return out

    @abstractmethod
    def start_source(self) -> None:
        """Begin the underlying capture, wiring it to :meth:`offer`."""

    def stop_source(self) -> None:
        """Stop the underlying capture. Override if it needs stopping."""

    async def open(self) -> None:
        # The source is started on the collector's own thread-of-control rather
        # than inside `cycle`, so a capture that takes a second to bind does not
        # look like a slow first poll.
        await asyncio.to_thread(self.start_source)

    async def close(self) -> None:
        await asyncio.to_thread(self.stop_source)
        # Whatever is still buffered at shutdown is real telemetry that was
        # collected; losing it because the operator pressed Ctrl-C would be a
        # self-inflicted gap. One last drain, best-effort.
        leftover = self._drain(self.batch_size * 4)
        if leftover:
            try:
                await self._submit(leftover)
            except Exception:
                self.stats.dropped += len(leftover)

    async def cycle(self) -> int:
        # Drain up to a bounded amount per cycle. Unbounded would let a burst turn
        # one cycle into a multi-minute stall during which the collector looks
        # hung and nothing else on the loop runs.
        batch = self._drain(self.batch_size * 8)
        if not batch:
            return 0
        return await self._submit(batch)


class CollectorFleet:
    """Every local collector, started and reported together.

    The fleet exists because the interesting questions are fleet-shaped: which
    sources are unavailable on this host and why, what the operator would have to
    install to close each gap, and whether anything is dropping. Answering those
    per-collector leaves the operator to assemble the picture themselves, which in
    practice means it is never assembled.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        *,
        monitor: Any | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.pipeline = pipeline
        self.monitor = monitor
        self.clock = clock
        self.collectors: dict[str, Collector] = {}

    def add(self, collector: Collector) -> Collector:
        """Register a collector, declare its source, and gate it on availability.

        Declaring here rather than at construction keeps one rule true: a source
        the pipeline can judge for silence is a source something is actually trying
        to collect. Declaring a cadence for a collector that was never added would
        produce a ``DEAD`` verdict about code that is not running.

        The cadence declared is :attr:`Collector.health_cadence_seconds` when the
        collector sets one, and :attr:`Collector.cadence_seconds` otherwise. The two
        differ for a collector that polls often and emits rarely — see the attribute
        docstring — and declaring the poll cadence for one of those makes the monitor
        report a healthy collector as dead.
        """
        self.collectors[collector.name] = collector
        self.pipeline.declare_source(
            collector.name,
            cadence_seconds=(
                collector.health_cadence_seconds
                if collector.health_cadence_seconds is not None
                else collector.cadence_seconds
            ),
            critical=collector.critical,
            description=collector.description,
            kind=collector.kind,
        )
        av = collector.availability()
        if self.monitor is not None and not av:
            gate = getattr(self.monitor, "gate_on_precondition", None)
            if gate is not None:
                gate(collector.name, av.reason)
        return collector

    def add_all(self, collectors: Iterable[Collector]) -> None:
        for c in collectors:
            self.add(c)

    async def start(self) -> list[str]:
        """Start every available collector. Returns the names actually started."""
        started = []
        for c in self.collectors.values():
            if c.start() is not None:
                started.append(c.name)
        return started

    async def stop(self) -> None:
        await asyncio.gather(
            *(c.stop() for c in self.collectors.values()), return_exceptions=True
        )

    def stats(self) -> list[CollectorStats]:
        return [c.stats for c in self.collectors.values()]

    def unavailable(self) -> list[tuple[str, str, bool]]:
        """``(name, reason, fixable_by_user)`` for everything that cannot run."""
        out = []
        for c in self.collectors.values():
            av = c.availability()
            if not av:
                out.append((c.name, av.reason, av.fixable_by_user))
        return out

    def limitations(self) -> list[tuple[str, str]]:
        """``(name, limitation)`` for collectors that run but cannot see everything.

        Separate from :meth:`unavailable` on purpose. These do not belong in the
        setup checklist — there is nothing to install and nothing is broken — but
        they are the difference between "we collect process events" and "we collect
        the process events that live longer than two seconds", and only one of those
        two sentences is true.
        """
        out = []
        for c in self.collectors.values():
            av = c.availability()
            if av and av.limitation:
                out.append((c.name, av.limitation))
        return out

    def dropping(self) -> list[tuple[str, int]]:
        """Collectors that have lost events to buffer overflow, worst first."""
        out = [(c.name, c.stats.dropped) for c in self.collectors.values() if c.stats.dropped]
        return sorted(out, key=lambda t: -t[1])

    def extra_stats(self) -> dict[str, dict[str, Any]]:
        """``{collector name: stats_extra()}``, skipping the ones with nothing to add.

        A collector's own ``stats_extra`` is called through here rather than being
        left for a caller to discover, and a collector that raises while reporting
        its numbers reports the exception instead of taking the whole fleet report
        down with it — a status page that cannot render is worse than one number
        being wrong.
        """
        out: dict[str, dict[str, Any]] = {}
        for c in self.collectors.values():
            try:
                extra = c.stats_extra()
            except Exception as exc:
                extra = {"stats_extra_error": f"{type(exc).__name__}: {exc}"}
            if extra:
                out[c.name] = extra
        return out

    def report(self) -> str:
        lines = ["LOCAL COLLECTOR FLEET", "=" * 74]
        extras = self.extra_stats()
        for c in self.collectors.values():
            lines.append("  " + c.stats.line())
            for key, value in sorted(extras.get(c.name, {}).items()):
                lines.append(f"        {key}: {value}")
        caveats = self.limitations()
        if caveats:
            lines += ["", "RUNNING, BUT NOT SEEING EVERYTHING"]
            for name, limitation in caveats:
                lines.append(f"  {name}: {limitation}")
        gaps = self.unavailable()
        if gaps:
            lines += ["", "UNAVAILABLE ON THIS HOST"]
            for name, reason, fixable in gaps:
                tag = "install" if fixable else "platform"
                lines.append(f"  [{tag}] {name}: {reason}")
        drops = self.dropping()
        if drops:
            lines += ["", "LOSING EVENTS TO BUFFER OVERFLOW"]
            for name, n in drops:
                lines.append(f"  {name}: {n} events dropped")
            lines.append(
                "  A collector at its buffer ceiling is losing telemetry now. "
                "Raise buffer_size, lower cadence, or find why the pipeline is slow."
            )
        return "\n".join(lines)

    def setup_instructions(self) -> str:
        """What the operator has to do to close the fixable gaps."""
        fixable = [(n, r) for n, r, f in self.unavailable() if f]
        if not fixable:
            return "All collectors available on this host; no setup required."
        lines = ["To enable the collectors that cannot run yet:", ""]
        for i, (name, reason) in enumerate(fixable, 1):
            lines.append(f"{i}. {name}")
            lines.append(f"   {reason}")
            lines.append("")
        return "\n".join(lines)


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_admin() -> bool:
    """True if this process can do privileged local things.

    Wrapped rather than inlined because the answer is asked by four collectors and
    the Windows form of the question is not obvious. A failure to determine it is
    reported as *not* elevated: assuming privilege we do not have produces a
    collector that starts and then fails every cycle, which is strictly worse than
    one that says up front that it needs an elevated shell.
    """
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os

        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


__all__ = [
    "Availability",
    "BACKOFF_AFTER",
    "BACKOFF_MAX",
    "Collector",
    "CollectorFleet",
    "CollectorStats",
    "DEFAULT_BATCH",
    "DEFAULT_BUFFER",
    "PullCollector",
    "PushCollector",
    "available",
    "is_admin",
    "is_windows",
    "unavailable",
]

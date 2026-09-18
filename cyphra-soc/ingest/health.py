"""
CYPHRA-SOC — log-source health.

The failure this module exists to catch: **a sensor that stopped, in a SOC that
looks fine.** Every detection, correlation, hunt and metric downstream is
conditional on telemetry arriving, and the absence of telemetry produces the
absence of alerts — which is indistinguishable, on every dashboard, from safety.
An attacker who kills the endpoint agent gets exactly that.

So silence is a finding here, not an absence of findings.

── The state model ──────────────────────────────────────────────────────────

Seven states, and the split is the whole design. Collapsing them into
healthy/unhealthy is what makes source health useless in practice, because the
three most dangerous conditions all look "unhealthy" while needing three
completely different responses.

===================  ======================================================
``HEALTHY``          reporting inside its cadence, events survive validation
``LATE``             past cadence but inside the stale multiplier — a warning,
                     not a page; a quiet channel at 3 a.m. is normal
``DEAD``             past ``cadence × health_stale_multiplier``. It reported
                     before and does not now: something broke or was killed
``REJECTING``        arriving and being *thrown away* — a fresh connection with
                     a frozen ``last_accepted``. This is the state that hides
                     for a week, because the source is connected, the transport
                     is green, and nothing at all is being stored
``STALLED``          accepting events whose *event* times are old: a connector
                     replaying history, or one whose cursor stopped advancing.
                     Working, and not current — which for detection is nearly
                     as bad, since a real-time rule never sees the event
``NEVER_REPORTED``   declared and configured and has produced nothing, ever.
                     Not the same as dead: nothing was ever proven to work, so
                     this is a deployment fault, not an outage
``UNCONFIGURED``     declared, no credentials. Honest zero, not a fault
===================  ======================================================

Plus ``UNDECLARED`` for sources that showed up unannounced. They are ingested
(refusing them would lose data to a bookkeeping omission) and reported here, but
they cannot be judged dead — with no declared cadence there is no interval to
have missed. That is stated rather than defaulted, because guessing a cadence
would manufacture either false pages or false silence.

── Why the verdict is not just a timer ──────────────────────────────────────

``REJECTING`` and ``STALLED`` are the two states a pure last-seen timer cannot
see, and both are common in real deployments: a schema change upstream turns a
working connector into a rejector overnight, and a paused cursor turns one into a
staller. Both keep the timer green. Catching them is why :class:`SourceHealth`
reads accepted counts and event times rather than arrival times alone.

── Persistence ──────────────────────────────────────────────────────────────

Health is written to VedDB (``col:source_health:<name>``) on every evaluation, so
the console and the metrics module read one record rather than each recomputing a
verdict, and so a restart does not reset the record of what was broken. The
history of *transitions* is what post-incident review actually needs — "when did
the endpoint agent die" — so a transition also appends to the audit chain, which
is tamper-evident and therefore usable as evidence of when telemetry was lost.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Mapping

from core.config import SocConfig
from core import config as config_module
from core.store.kvdoc import Collection, DocStore
from ingest.pipeline import Pipeline, SourceDeclaration, SourceState

__all__ = [
    "HEALTH_COLLECTION",
    "HealthMonitor",
    "SourceHealth",
    "SourceStatus",
    "health_collection",
]


class SourceStatus(StrEnum):
    HEALTHY = "healthy"
    LATE = "late"
    DEAD = "dead"
    REJECTING = "rejecting"
    STALLED = "stalled"
    NEVER_REPORTED = "never_reported"
    UNCONFIGURED = "unconfigured"
    UNDECLARED = "undeclared"

    @property
    def alertable(self) -> bool:
        """Whether this state should raise a finding rather than sit on a page.

        ``LATE`` is deliberately excluded: a source inside its stale multiplier is
        quiet, and paging on quiet is how a health monitor gets muted, which then
        loses the states that matter. ``UNCONFIGURED`` is excluded because an
        unconfigured connector is an honest zero, not a fault.
        """
        return self in (
            SourceStatus.DEAD,
            SourceStatus.REJECTING,
            SourceStatus.STALLED,
            SourceStatus.NEVER_REPORTED,
        )

    @property
    def rank(self) -> int:
        """Sort order for a console: worst first."""
        return _RANK[self]


_RANK = {
    SourceStatus.DEAD: 0,
    SourceStatus.REJECTING: 1,
    SourceStatus.STALLED: 2,
    SourceStatus.NEVER_REPORTED: 3,
    SourceStatus.LATE: 4,
    SourceStatus.UNDECLARED: 5,
    SourceStatus.UNCONFIGURED: 6,
    SourceStatus.HEALTHY: 7,
}

#: A source is REJECTING when this fraction or more of what arrived was refused,
#: measured over the whole run. Not 1.0: a connector that maps nine fields right
#: and one wrong rejects a large minority, and that is still a broken connector.
#: Not 0.05 either — a genuinely malformed minority of events (a device with a
#: broken clock on one subnet) is normal and must not page anyone.
REJECT_RATE_ALERT = 0.5

#: …and only once this many events have arrived. Two rejections out of two is a
#: 100% reject rate and no evidence at all.
REJECT_MIN_SAMPLE = 20

#: A source is STALLED when its newest *event* time trails wall clock by more
#: than its cadence times this. Generous, because event time legitimately lags:
#: cloud audit APIs publish minutes late by design, so a tight bound here would
#: mark every correctly-working cloud connector stalled.
STALL_MULTIPLIER = 10.0

#: Below this many accepted events, "stalled" cannot be distinguished from "has
#: barely started", so it is not claimed.
STALL_MIN_SAMPLE = 5

HEALTH_COLLECTION = "source_health"


def health_collection() -> Collection:
    """The VedDB collection holding one record per source.

    Indexed on ``status`` and ``kind`` because both are how the console filters —
    "show me everything dead" and "show me the connectors" — and on ``alertable``
    so the metrics module can count open telemetry faults without scanning.
    """
    return Collection(
        name=HEALTH_COLLECTION,
        indexed=("status", "kind", "alertable", "critical"),
        id_field="source",
        required=("source", "status"),
    )


@dataclass
class SourceHealth:
    """One source's verdict, with the numbers it was derived from.

    The numbers travel with the verdict deliberately. "endpoint_agent: DEAD" is
    an assertion; "DEAD — last accepted 41m ago, cadence 300s, threshold 900s"
    is a claim someone can check, and an on-call engineer who cannot check a
    claim ends up ignoring the monitor that makes it.
    """

    source: str
    status: SourceStatus
    reason: str
    kind: str = ""
    critical: bool = False
    cadence_seconds: float = 0.0
    dead_after_seconds: float = 0.0
    seconds_since_submit: float | None = None
    seconds_since_accepted: float | None = None
    event_lag_seconds: float | None = None
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    reject_rate: float = 0.0
    last_reject_reason: str = ""
    backpressure_refusals: int = 0
    agents: list[str] = field(default_factory=list)
    evaluated_at: float = 0.0

    @property
    def alertable(self) -> bool:
        return self.status.alertable

    def line(self) -> str:
        return f"{self.source:<24} {self.status.value:<15} {self.reason}"

    def as_doc(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["status"] = self.status.value
        d["alertable"] = self.alertable
        return d


class HealthMonitor:
    """Evaluates and records log-source health.

    Reads :meth:`Pipeline.snapshot`; owns no counters of its own. The separation
    is deliberate — the pipeline records what happened, this decides what it
    means, and a policy change here cannot corrupt the facts.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        config: SocConfig | None = None,
        *,
        store: DocStore | None = None,
        audit: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.pipeline = pipeline
        self.cfg = config or config_module.get()
        self.store = store
        self.audit = audit
        self.clock = clock
        self.stale_multiplier = max(1.0, self.cfg.ingest.health_stale_multiplier)
        self.check_seconds = max(1.0, self.cfg.ingest.health_check_seconds)
        #: Which credential slots gate which source. A source whose credential is
        #: unset is UNCONFIGURED rather than NEVER_REPORTED — one is a deployment
        #: fault and the other is an operator choice, and conflating them fills
        #: the board with faults nobody intends to fix.
        self.credential_gate: dict[str, str] = {}
        #: Which sources cannot run on this host at all, and why. The local
        #: analogue of an unset credential: a packet capture without Npcap and an
        #: Okta connector without a token are the same *kind* of fact — a source
        #: that is correctly reporting nothing — and reporting one as a fault while
        #: excusing the other would be an accident of where the prerequisite lives.
        #: The reason is the collector's own text, which names the fix.
        self.precondition_gate: dict[str, str] = {}
        self._last: dict[str, SourceStatus] = {}
        self.transitions: list[tuple[float, str, str, str]] = []
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.evaluations = 0

        if store is not None:
            store.register(health_collection())

    # ── gating: the two reasons a source is correctly silent ───────────────

    def gate_on_precondition(self, source: str, reason: str) -> None:
        """Record that ``source`` cannot run on this host, with the reason.

        Unlike :meth:`gate_on_credential` there is nothing to validate against —
        the reason is a free-text fact about the host discovered by a probe, not a
        reference into config. What is enforced is that there *is* a reason: a gate
        with an empty one produces an ``UNCONFIGURED`` verdict that explains
        nothing, which is how a permanent gap becomes invisible.
        """
        if not reason.strip():
            raise ValueError(
                f"precondition gate for {source!r} needs a reason naming the missing "
                "prerequisite; an unexplained UNCONFIGURED is how a gap goes unfixed"
            )
        self.precondition_gate[source] = reason.strip()

    def gate_on_credential(self, source: str, credential_name: str) -> None:
        """Record that ``source`` cannot report without ``credential_name``.

        The name is checked against config *here*, at wiring time, and not when a
        verdict is reached. The gate is only consulted on the never-reported path —
        a source that is producing events is working, whatever we believe about its
        credentials — so a mistyped name would otherwise sit dormant through every
        healthy evaluation and surface only once that source went quiet. That is
        the one moment the monitor has to be trustworthy, so the typo is raised at
        startup instead, where a wiring mistake belongs.
        """
        if not any(c.name == credential_name for c in self.cfg.credentials()):
            raise KeyError(
                f"health gate for {source!r} names credential {credential_name!r}, "
                "which is not declared in config; the gate or the config is wrong"
            )
        self.credential_gate[source] = credential_name

    def _configured(self, source: str) -> bool:
        name = self.credential_gate.get(source)
        if not name:
            return True
        for cred in self.cfg.credentials():
            if cred.name == name:
                return cred.configured
        # Unreachable via gate_on_credential, which validates the name. Kept as an
        # invariant for a gate table written straight into the dict, because
        # returning True would hide the error behind a plausible verdict.
        raise KeyError(
            f"health gate for {source!r} names credential {name!r}, which is not "
            "declared in config; the gate or the config is wrong"
        )

    # ── evaluation ─────────────────────────────────────────────────────────

    def evaluate(self) -> list[SourceHealth]:
        """Judge every declared and every observed source. Pure; no I/O."""
        now = self.clock()
        self.evaluations += 1
        out: list[SourceHealth] = []
        names = set(self.pipeline.sources) | set(self.pipeline.state)
        for name in sorted(names):
            decl = self.pipeline.sources.get(name)
            st = self.pipeline.state.get(name)
            out.append(self._judge(name, decl, st, now))
        out.sort(key=lambda h: (h.status.rank, not h.critical, h.source))
        return out

    def _judge(
        self,
        name: str,
        decl: SourceDeclaration | None,
        st: SourceState | None,
        now: float,
    ) -> SourceHealth:
        cadence = decl.cadence_seconds if decl else 0.0
        dead_after = cadence * self.stale_multiplier
        h = SourceHealth(
            source=name,
            status=SourceStatus.HEALTHY,
            reason="",
            kind=decl.kind if decl else "",
            critical=bool(decl and decl.critical),
            cadence_seconds=cadence,
            dead_after_seconds=dead_after,
            evaluated_at=now,
        )
        if st is not None:
            h.received = st.received
            h.accepted = st.accepted
            h.rejected = st.rejected
            h.duplicates = st.duplicates
            h.reject_rate = round(st.reject_rate, 6)
            h.last_reject_reason = st.last_reject_reason
            h.backpressure_refusals = st.backpressure_refusals
            h.agents = sorted(st.agents)
            if st.last_submit:
                h.seconds_since_submit = round(now - st.last_submit, 3)
            if st.last_accepted:
                h.seconds_since_accepted = round(now - st.last_accepted, 3)
            if st.last_event_time:
                h.event_lag_seconds = round(now - st.last_event_time, 3)

        # 1. Never reported at all. Distinguish "not set up" from "set up and
        #    silent" before anything else, because the remedies are unrelated.
        if st is None or st.accepted == 0 and st.received == 0:
            if decl is None:
                # Cannot happen — a name is here because it was declared or it
                # submitted — but stated rather than assumed.
                h.status = SourceStatus.UNDECLARED
                h.reason = "observed but not declared, and no counters recorded"
                return h
            if name in self.precondition_gate:
                # Checked before the credential gate because a host that cannot run
                # the collector at all makes the credential question moot, and
                # naming the deeper cause is what gets it fixed.
                h.status = SourceStatus.UNCONFIGURED
                h.reason = (
                    f"cannot run on this host: {self.precondition_gate[name]} — "
                    "reporting nothing is correct until that is resolved"
                )
                return h
            if not self._configured(name):
                h.status = SourceStatus.UNCONFIGURED
                h.reason = (
                    f"no credential ({self.credential_gate[name]}); an unconfigured "
                    "connector reports nothing and that is correct, not a fault"
                )
                return h
            h.status = SourceStatus.NEVER_REPORTED
            h.reason = (
                "declared and configured but has never produced an event — nothing "
                "here has ever been proven to work, so this is a deployment fault "
                "rather than an outage"
            )
            return h

        # 2. Arriving and being thrown away. Checked before the timers, because a
        #    rejecting source has a *fresh* arrival clock and would otherwise be
        #    reported healthy while storing nothing.
        if st.received >= REJECT_MIN_SAMPLE and st.reject_rate >= REJECT_RATE_ALERT:
            h.status = SourceStatus.REJECTING
            h.reason = (
                f"{st.rejected} of {st.received} events refused "
                f"({st.reject_rate:.0%}) — the source is connected and its data is "
                f"not being stored. Last reason: {st.last_reject_reason or 'unknown'}"
            )
            return h

        # 3. Silence, measured from the last *accepted* event rather than the last
        #    arrival: a source that submits empty batches forever is silent.
        since = h.seconds_since_accepted
        if decl is None:
            h.status = SourceStatus.UNDECLARED
            h.reason = (
                f"reporting ({st.accepted} events accepted) but never declared, so "
                "no cadence is known and silence here cannot be detected — declare "
                "it with declare_source() to make it monitorable"
            )
            return h
        if cadence <= 0:
            h.status = SourceStatus.HEALTHY
            h.reason = (
                f"{st.accepted} events accepted; no cadence declared, so silence is "
                "not judged for this source"
            )
            return h
        if since is None:
            h.status = SourceStatus.NEVER_REPORTED
            h.reason = "counters exist but nothing has ever been accepted"
            return h
        if since > dead_after:
            h.status = SourceStatus.DEAD
            h.reason = (
                f"last event {_dur(since)} ago, past {_dur(dead_after)} "
                f"({_dur(cadence)} cadence × {self.stale_multiplier:g}). It worked "
                f"before and does not now"
            )
            return h

        # 4. Current in arrival, stale in content. A cursor that stopped
        #    advancing, or a deliberate historical replay.
        lag = h.event_lag_seconds
        if (
            lag is not None
            and st.accepted >= STALL_MIN_SAMPLE
            and lag > max(cadence * STALL_MULTIPLIER, dead_after)
        ):
            h.status = SourceStatus.STALLED
            h.reason = (
                f"accepting events, but the newest is {_dur(lag)} old — the source "
                f"is working and not current, so a real-time rule never sees it. "
                f"A stopped cursor or a historical replay looks like this"
            )
            return h

        if since > cadence:
            h.status = SourceStatus.LATE
            h.reason = (
                f"last event {_dur(since)} ago, past its {_dur(cadence)} cadence but "
                f"inside the {_dur(dead_after)} dead threshold — quiet, not gone"
            )
            return h

        h.status = SourceStatus.HEALTHY
        h.reason = (
            f"{st.accepted} events accepted, last {_dur(since)} ago"
            + (f", event lag {_dur(lag)}" if lag is not None else "")
        )
        return h

    # ── recording ──────────────────────────────────────────────────────────

    async def record(self, results: list[SourceHealth] | None = None) -> list[SourceHealth]:
        """Evaluate, persist, and audit every status change."""
        results = results if results is not None else self.evaluate()
        for h in results:
            previous = self._last.get(h.source)
            if previous != h.status:
                self._last[h.source] = h.status
                self.transitions.append(
                    (h.evaluated_at, h.source, previous.value if previous else "", h.status.value)
                )
                await self._audit_transition(h, previous)
            if self.store is not None:
                try:
                    await self.store.put(HEALTH_COLLECTION, h.as_doc())
                except Exception:
                    # Health that cannot be written is still health that was
                    # computed; the in-memory verdict stands and the store's own
                    # verify() reports the gap.
                    pass
        return results

    async def _audit_transition(
        self, h: SourceHealth, previous: SourceStatus | None
    ) -> None:
        """Chain a transition, so "when did we lose telemetry" is evidence.

        Only transitions, never the steady state: a monitor that appended a record
        every thirty seconds would make the chain unreadable and hide the four
        entries that matter in a million that do not.
        """
        if self.audit is None:
            return
        # The first evaluation transitions everything from nothing, which is not a
        # change in the world — but a source that starts life DEAD or REJECTING is
        # worth a record, so only the benign initial states are suppressed.
        if previous is None and not h.status.alertable:
            return
        try:
            outcome = self.audit.append(
                action="ingest.source_status",
                actor="ingest.health",
                target=f"source:{h.source}",
                data={
                    "from": previous.value if previous else "(startup)",
                    "to": h.status.value,
                    "reason": h.reason,
                    "critical": h.critical,
                    "accepted": h.accepted,
                    "rejected": h.rejected,
                },
            )
            if asyncio.iscoroutine(outcome):
                await outcome
        except Exception:
            pass

    # ── background loop ────────────────────────────────────────────────────

    async def run(self) -> None:
        """Evaluate on the configured interval until :meth:`stop`."""
        self._stop.clear()
        while not self._stop.is_set():
            await self.record()
            try:
                await asyncio.wait_for(self._stop.wait(), self.check_seconds)
            except asyncio.TimeoutError:
                pass

    def start(self) -> asyncio.Task:
        if self._task is not None and not self._task.done():
            return self._task
        self._task = asyncio.create_task(self.run(), name="ingest.health")
        return self._task

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=self.check_seconds + 5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None

    # ── reporting ──────────────────────────────────────────────────────────

    def alerts(self, results: list[SourceHealth] | None = None) -> list[SourceHealth]:
        return [h for h in (results or self.evaluate()) if h.alertable]

    def report(self, results: list[SourceHealth] | None = None) -> str:
        """A text table an operator can read without a UI."""
        results = results if results is not None else self.evaluate()
        counts: dict[str, int] = {}
        for h in results:
            counts[h.status.value] = counts.get(h.status.value, 0) + 1
        lines = [
            "log-source health",
            "=" * 100,
            f"{'source':<24} {'status':<15} why",
            "-" * 100,
        ]
        lines += [h.line() for h in results]
        lines.append("-" * 100)
        lines.append(
            "  ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
        )
        crit = [h for h in results if h.critical and h.alertable]
        if crit:
            lines.append("")
            lines.append(f"CRITICAL SOURCES IN FAULT: {', '.join(h.source for h in crit)}")
            lines.append(
                "Every detection that depends on these is not firing, which on a "
                "dashboard is indistinguishable from safety."
            )
        return "\n".join(lines)

    def coverage(self, results: list[SourceHealth] | None = None) -> dict[str, Any]:
        """The one number the metrics module needs, with its denominator.

        A bare "92% healthy" is unusable — 92% of what, and is the missing 8% the
        DNS resolver or the domain controller? So the fraction is reported beside
        the counts and the names, and critical sources are counted separately
        because they are not interchangeable with the rest.
        """
        results = results if results is not None else self.evaluate()
        judged = [h for h in results if h.status is not SourceStatus.UNCONFIGURED]
        healthy = [h for h in judged if h.status in (SourceStatus.HEALTHY, SourceStatus.LATE)]
        crit = [h for h in judged if h.critical]
        crit_ok = [h for h in crit if h.status in (SourceStatus.HEALTHY, SourceStatus.LATE)]
        return {
            "sources_total": len(results),
            "sources_judged": len(judged),
            "sources_healthy": len(healthy),
            "fraction_healthy": round(len(healthy) / len(judged), 4) if judged else 0.0,
            "critical_total": len(crit),
            "critical_healthy": len(crit_ok),
            "critical_in_fault": sorted(h.source for h in crit if h.alertable),
            "unconfigured": sorted(
                h.source for h in results if h.status is SourceStatus.UNCONFIGURED
            ),
            "by_status": {
                s.value: sum(1 for h in results if h.status is s) for s in SourceStatus
            },
            "alertable": sorted(h.source for h in results if h.alertable),
        }


def _dur(seconds: float | None) -> str:
    """Human duration. Reasons are read by people under time pressure."""
    if seconds is None:
        return "never"
    s = float(seconds)
    if s < 90:
        return f"{s:.0f}s"
    if s < 5400:
        return f"{s / 60:.0f}m"
    if s < 172800:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"


#: Credential gates for the shipped connectors, applied by
#: :func:`gate_default_sources`. The names must match ``SocConfig.credentials()``.
#:
#: Each source is gated on the *one* credential without which it cannot poll at
#: all — a secret or token, not a tenant id — because a partially-configured
#: connector should read as configured-and-broken (which is a fault worth seeing)
#: rather than unconfigured (which is not). Azure Activity is gated on the
#: subscription id because it authenticates with the Entra app registration and
#: the subscription is the only thing uniquely its own.
_DEFAULT_GATES: tuple[tuple[str, str], ...] = (
    ("entra_signin", "connectors.entra.client_secret"),
    ("entra_audit", "connectors.entra.client_secret"),
    ("okta_system_log", "connectors.okta.api_token"),
    ("defender_alerts", "connectors.defender.client_secret"),
    ("crowdstrike_detects", "connectors.crowdstrike.client_secret"),
    ("aws_cloudtrail", "connectors.aws.secret_access_key"),
    ("azure_activity", "connectors.azure.subscription_id"),
    ("gcp_audit", "connectors.gcp.credentials_json"),
    ("m365_email", "connectors.m365.client_secret"),
    ("google_workspace", "connectors.gws.delegated_subject"),
    ("saas_audit", "connectors.saas.api_token"),
)


def gate_default_sources(monitor: HealthMonitor) -> list[tuple[str, str]]:
    """Wire the shipped connectors to their credential slots.

    Returns the gates actually applied. A gate whose credential is not declared
    in config is skipped and reported rather than raising, so that a build with a
    trimmed credential set still starts — but it is *returned*, so the omission is
    visible instead of silent.
    """
    declared = {c.name for c in monitor.cfg.credentials()}
    applied = []
    for source, cred in _DEFAULT_GATES:
        if cred in declared:
            monitor.gate_on_credential(source, cred)
            applied.append((source, cred))
    return applied

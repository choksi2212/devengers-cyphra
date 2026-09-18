"""Scratch verification for ingest.pipeline and ingest.health.

Run standalone so each behaviour is confirmed before collectors are built on top:

    python tests/scratch_ingest.py

The clock is injected everywhere so that "dead after fifteen minutes" is asserted
in fifteen simulated minutes rather than fifteen real ones. Everything that
touches the lake, VedDB and the audit chain uses the real component — a pipeline
verified against a mock lake would prove only that the mock agrees with itself.
"""

import asyncio
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from core.audit.chain import AuditChain
from core.config import get
from core.schema.ocsf import Event, ObservableTypeId
from core.store.capability import probe_and_require
from core.store.kvdoc import DocStore
from core.store.lake import Lake
from core.store.veddb import VedDbClient, VedDbError
from ingest.health import (
    HEALTH_COLLECTION,
    REJECT_MIN_SAMPLE,
    HealthMonitor,
    SourceStatus,
    _dur,
    gate_default_sources,
    health_collection,
)
from ingest.pipeline import (
    EVENTS_TABLE,
    MAX_DISTINCT_REASONS,
    REJECTS_TABLE,
    Backpressure,
    Pipeline,
    declare_default_sources,
)

PASS, FAIL = [], []
#: Checks that could not run because an external dependency was absent. Kept separate
#: from FAIL so an unreachable VedDB never reads as a code defect — and printed as its
#: own loud block at the end so it never reads as a pass either. A suite that dies with
#: a traceback the moment the store is down reports nothing about the sixty checks that
#: do not need the store, which is how a real regression hides behind an environment
#: problem.
SKIP: list[tuple[str, str]] = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def skip(name, why):
    SKIP.append((name, why))
    print(f"  [SKIP] {name}  — {why}")


class Clock:
    """A clock the test drives, so elapsed time is a decision not a wait."""

    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now


ROOT = Path("var/test_ingest")
_OPEN: list = []


def fresh_lake(_clock=None):
    """A brand-new lake, closing the previous one.

    Each gets its own directory and its own DuckDB file. Sharing a path across
    sections — or deleting one out from under a connection that is still open —
    crashes the interpreter rather than failing a check, which is a much worse way
    to find out.
    """
    while _OPEN:
        try:
            _OPEN.pop().close()
        except Exception:
            pass
    d = ROOT / f"lake{len(list(ROOT.glob('lake*'))) if ROOT.exists() else 0}_{time.perf_counter_ns()}"
    d.mkdir(parents=True, exist_ok=True)
    lk = Lake(root=d / "data", duckdb_path=d / "soc.duckdb", flush_rows=10_000, threads=2)
    _OPEN.append(lk)
    return lk


def flow(clock, *, src="10.0.0.5", dst="93.184.216.34", port=443, uid=None, extra=None):
    """A network-flow shaped payload the schema accepts."""
    p = {
        "time": clock.now,
        "class_uid": 4001,
        "activity_id": 6,
        "severity_id": 1,
        "src_endpoint_ip": src,
        "src_endpoint_port": 51000,
        "dst_endpoint_ip": dst,
        "dst_endpoint_port": port,
        "connection_protocol_name": "tcp",
        "traffic_bytes_out": 1024,
        "traffic_bytes_in": 4096,
        "device_hostname": "ws01",
    }
    if uid:
        p["metadata_uid"] = uid
    if extra:
        p.update(extra)
    return p


async def q(lake, sql):
    return await lake.aquery(sql)


async def main():
    clock = Clock()
    cfg = get()
    shutil.rmtree(ROOT, ignore_errors=True)
    ROOT.mkdir(parents=True, exist_ok=True)
    lake = fresh_lake(clock)

    # ── tables ──────────────────────────────────────────────────────────────
    print("── declared tables ──")
    pipe = Pipeline(lake, cfg, clock=clock)
    names = set(lake._tables)
    check("both ingest tables are declared", {EVENTS_TABLE, REJECTS_TABLE} <= names, str(sorted(names)))
    check("the events schema is generated from the Event model, not hand-written",
          len(lake.table(EVENTS_TABLE).schema.names) == len(Event.model_fields) + 1,
          f"{len(lake.table(EVENTS_TABLE).schema.names)} columns = {len(Event.model_fields)} fields + _extra")
    check("registering twice is idempotent", Pipeline(lake, cfg, clock=clock) is not None)

    # ── the happy path ──────────────────────────────────────────────────────
    print("\n── accept ──")
    pipe.declare_source("network_flow", cadence_seconds=60, critical=True, kind="collector")
    r = await pipe.submit("network_flow", [flow(clock, uid=f"f{i}") for i in range(10)])
    check("a valid batch is wholly accepted", r.accepted == 10 and r.rejected == 0, r.summary())
    check("the result reports ok", r.ok)
    await pipe.flush()
    n = (await q(lake, f"SELECT count(*) n FROM {EVENTS_TABLE}"))[0]["n"]
    check("every accepted event reached the lake", n == 10, f"{n} rows")
    row = (await q(lake, f"SELECT * FROM {EVENTS_TABLE} LIMIT 1"))[0]
    check("provenance is stamped: source, ingest time, schema version",
          row["soc_source"] == "network_flow" and row["soc_ingested_time"] > 0
          and row["soc_schema_version"], row["soc_schema_version"])
    obs = json.loads(row["observables"] or "[]")
    by_type = {o["type_id"]: o["value"] for o in obs}
    check("observables were derived at build time, so correlation gets entities free",
          by_type.get(int(ObservableTypeId.IP_ADDRESS)) in ("10.0.0.5", "93.184.216.34")
          and by_type.get(int(ObservableTypeId.HOSTNAME)) == "ws01",
          f"{len(obs)} observables: "
          + ", ".join(f"{ObservableTypeId(o['type_id']).name}={o['value']}" for o in obs))

    # ── rejection is stored, not dropped ────────────────────────────────────
    print("\n── quarantine ──")
    bad_time = {**flow(clock)}
    del bad_time["time"]
    r = await pipe.submit("network_flow", [bad_time])
    check("an event with no time is refused", r.rejected == 1 and r.accepted == 0, r.summary())
    check("the reason names the source and the field",
          any("no time" in k for k in r.reasons), str(list(r.reasons))[:110])
    await pipe.flush()
    rej = await q(lake, f"SELECT * FROM {REJECTS_TABLE}")
    check("the refused payload is quarantined in the lake, not discarded", len(rej) == 1)
    check("the quarantine row names the source", rej[0]["source"] == "network_flow")
    check("and preserves what the source actually sent as its time",
          rej[0]["claimed_time"] == "None", rej[0]["claimed_time"])
    check("the payload is kept for replay after the fix",
          '"src_endpoint_ip"' in rej[0]["payload"] and not rej[0]["payload_truncated"])
    check("with a digest, so a replayed payload is provably the same bytes",
          len(rej[0]["payload_sha256"]) == 64)

    r = await pipe.submit("network_flow", [{**flow(clock), "time": 0}])
    check("a 1970 timestamp is refused rather than corrected to now",
          r.rejected == 1 and any("before 2000" in k for k in r.reasons),
          str(list(r.reasons))[:90])

    print("\n── a bad minority does not cost the good majority ──")
    mixed = [flow(clock, uid=f"m{i}") for i in range(7)]
    for i in range(3):
        b = flow(clock)
        del b["time"]
        mixed.insert(i * 3, b)
    r = await pipe.submit("network_flow", mixed)
    check("7 of 10 stored, 3 quarantined", r.accepted == 7 and r.rejected == 3, r.summary())
    check("the result is not ok, because something was refused", not r.ok)

    print("\n── reason grouping ──")
    # Each of these carries the offending value in its message, so they are
    # genuinely distinct reasons rather than one message repeated.
    many = [{**flow(clock), "time": float(i + 1)} for i in range(MAX_DISTINCT_REASONS + 4)]
    r = await pipe.submit("network_flow", many)
    check("distinct reasons are capped so one broken source cannot flood the result",
          len(r.reasons) == MAX_DISTINCT_REASONS + 1 and "(other)" in r.reasons,
          f"{len(r.reasons)} groups: {MAX_DISTINCT_REASONS} named + (other)")
    check("and the overflow is counted rather than dropped",
          sum(r.reasons.values()) == r.rejected == MAX_DISTINCT_REASONS + 4,
          f"{sum(r.reasons.values())} counted == {r.rejected} rejected")

    # ── dedup ───────────────────────────────────────────────────────────────
    print("\n── deduplication ──")
    lake2 = fresh_lake(clock)
    p2 = Pipeline(lake2, cfg, clock=clock, dedup_ttl_seconds=300)
    same = flow(clock, uid="ct-EXAMPLE-0001")
    a = await p2.submit("aws_cloudtrail", [same])
    b = await p2.submit("aws_cloudtrail", [dict(same)])
    check("a source that names its own event id gets exact dedup",
          a.accepted == 1 and b.accepted == 0 and b.duplicates == 1, b.summary())
    check("and the event carries soc_dedup_exact so downstream can trust the id",
          a.events[0].soc_dedup_exact)
    await p2.flush()
    n = (await q(lake2, f"SELECT count(*) n FROM {EVENTS_TABLE}"))[0]["n"]
    check("the redelivered copy never reached the lake", n == 1, f"{n} rows")

    noid = flow(clock)
    c1 = await p2.submit("network_flow", [noid])
    c2 = await p2.submit("network_flow", [dict(noid)])
    check("without a source event id the second arrival is KEPT, not dropped",
          c2.accepted == 1 and c2.duplicates == 0 and c2.id_collisions == 1, c2.summary())
    check("because dropping it could lose a real event emitted in the same instant",
          not c1.events[0].soc_dedup_exact)
    check("and the ambiguity is recorded on the event itself",
          any("not unique" in n for n in c2.events[0].soc_notes),
          str(c2.events[0].soc_notes[-1])[:80])

    clock.advance(301)
    c3 = await p2.submit("aws_cloudtrail", [dict(same, time=clock.now)])
    check("past the dedup TTL an id is new again, so the cache cannot grow forever",
          c3.accepted == 1 and c3.duplicates == 0, c3.summary())

    p3 = Pipeline(fresh_lake(clock), cfg, clock=clock, dedup_max_keys=4)
    for i in range(12):
        await p3.submit("s", [flow(clock, uid=f"e{i}")])
    check("the dedup cache is bounded and evictions are counted",
          len(p3._seen) == 4 and p3.dedup_evictions == 8,
          f"{len(p3._seen)} tracked, {p3.dedup_evictions} evicted")
    p4 = Pipeline(fresh_lake(clock), cfg, clock=clock, dedup_max_keys=0)
    x = await p4.submit("s", [flow(clock, uid="dup"), flow(clock, uid="dup")])
    check("dedup can be switched off entirely", x.accepted == 2 and x.duplicates == 0)

    # ── policy the collector does not own ───────────────────────────────────
    print("\n── raw retention and provenance are the operator's, not the source's ──")
    lake3 = fresh_lake(clock)
    p5 = Pipeline(lake3, cfg, clock=clock, keep_raw=False)
    p5.declare_source("keeper", keep_raw=True)
    p5.declare_source("dropper", keep_raw=False)
    e = (await p5.submit("dropper", [flow(clock, extra={"raw": {"orig": 1}, "keep_raw": True})])).events[0]
    check("a collector asking to keep raw is ignored — it is a storage decision",
          e.soc_raw is None and len(e.soc_raw_sha256) == 64)
    check("but the raw payload is still hashed, so custody survives without the bytes",
          e.soc_raw_sha256
          != Event.build("x", time=clock.now, class_uid=4001).soc_raw_sha256)
    e = (await p5.submit("keeper", [flow(clock, extra={"raw": {"orig": 1}})])).events[0]
    check("a source declared keep_raw does keep it", e.soc_raw == '{"orig":1}', str(e.soc_raw))
    e = (await p5.submit("keeper", [flow(clock, extra={"raw": "abc"})], keep_raw=False)).events[0]
    check("and an explicit submit argument overrides the declaration", e.soc_raw is None)

    e = (await p5.submit(
        "dropper",
        [flow(clock, extra={"soc_agent_id": "forged", "soc_ingested_time": 1.0, "agent_id": "real"})],
        agent_id="from-transport",
    )).events[0]
    check("a payload cannot forge its own agent id",
          e.soc_agent_id == "real" and e.soc_ingested_time > 1.0,
          f"agent={e.soc_agent_id} ingested={e.soc_ingested_time:.0f}")

    # ── sinks ───────────────────────────────────────────────────────────────
    print("\n── fan-out ──")
    lake4 = fresh_lake(clock)
    p6 = Pipeline(lake4, cfg, clock=clock)
    seen = []
    lake_visible = []

    async def detector(events):
        seen.extend(events)
        await lake4.flush()
        n = (await q(lake4, f"SELECT count(*) n FROM {EVENTS_TABLE}"))[0]["n"]
        lake_visible.append(n)

    def broken(events):
        raise RuntimeError("downstream is down")

    p6.add_sink("detect", detector)
    p6.add_sink("metrics", broken)
    r = await p6.submit("network_flow", [flow(clock, uid=f"s{i}") for i in range(3)])
    check("a sink receives the accepted events", len(seen) == 3)
    check("DURABILITY BEFORE FAN-OUT: the sink can already read its events from the lake",
          lake_visible == [3], f"lake held {lake_visible} rows when the sink ran")
    check("a non-critical sink that raises does not fail the batch", r.accepted == 3)
    check("but the failure is reported, not swallowed",
          "metrics" in r.sink_errors and "down" in r.sink_errors["metrics"],
          r.sink_errors.get("metrics", ""))
    check("and counted on the sink", p6.sinks[1].errors == 1)
    check("a duplicate sink name is refused",
          _raises(lambda: p6.add_sink("detect", detector)))

    p7 = Pipeline(fresh_lake(clock), cfg, clock=clock)
    p7.add_sink("must-work", broken, critical=True)
    raised = False
    try:
        await p7.submit("network_flow", [flow(clock, uid="c1")])
    except RuntimeError:
        raised = True
    check("a CRITICAL sink failure fails the submit, so the producer retries", raised)
    await p7.flush()
    n = (await q(p7.lake, f"SELECT count(*) n FROM {EVENTS_TABLE}"))[0]["n"]
    check("and the event is still durable — it was stored before the sink ran", n == 1,
          f"{n} rows survived the raise")
    check("the pipeline is not left holding capacity after a raise", p7._inflight == 0)

    # ── backpressure ────────────────────────────────────────────────────────
    print("\n── backpressure ──")
    lake5 = fresh_lake(clock)
    p8 = Pipeline(lake5, cfg, clock=clock, backpressure_timeout_seconds=0.05)
    p8.queue_max_events = 5
    gate = asyncio.Event()

    async def slow(events):
        await gate.wait()

    p8.add_sink("slow", slow)
    holder = asyncio.create_task(p8.submit("network_flow", [flow(clock, uid=f"b{i}") for i in range(5)]))
    await asyncio.sleep(0.01)
    check("capacity is held while a submit is in flight", p8._inflight == 5, str(p8._inflight))
    refused = None
    try:
        await p8.submit("network_flow", [flow(clock, uid="over")])
    except Backpressure as exc:
        refused = exc
    check("a submit past capacity is REFUSED, never silently dropped", refused is not None)
    check("the refusal timed out on monotonic time, not on the injected clock",
          refused is not None and refused.waited >= 0.05,
          f"the fake clock never advances; a deadline built from it would wait forever "
          f"(waited {refused.waited:.3f}s)" if refused else "never refused")
    check("the refusal tells the caller what to do instead",
          refused and "spool" in str(refused) and "do not drop" in str(refused),
          str(refused)[-60:] if refused else "")
    check("a refused batch is not counted as received — it never entered",
          p8.state["network_flow"].received == 5, str(p8.state["network_flow"].received))
    check("and the refusal is counted where an operator will see it",
          p8.state["network_flow"].backpressure_refusals == 1 and p8.total_backpressure == 1)
    gate.set()
    await holder
    check("capacity is released when the submit completes", p8._inflight == 0)
    ok = await p8.submit("network_flow", [flow(clock, uid="after")])
    check("the pipeline recovers after saturation", ok.accepted == 1, ok.summary())
    big = None
    try:
        await p8.submit("network_flow", [flow(clock, uid=f"x{i}") for i in range(9)])
    except Backpressure as exc:
        big = exc
    check("a batch larger than the whole queue is refused at once, not deadlocked",
          big is not None and big.waited == 0.0)

    # ── bookkeeping ─────────────────────────────────────────────────────────
    print("\n── counters ──")
    lake6 = fresh_lake(clock)
    p9 = Pipeline(lake6, cfg, clock=clock)
    p9.declare_source("declared_one", cadence_seconds=60)
    r = await p9.submit("declared_one", [])
    check("an empty batch is a no-op", r.received == 0 and r.accepted == 0)
    check("but it still records that the source talked to us",
          p9.state["declared_one"].last_submit == clock.now,
          "a source submitting nothing is connected and finding nothing")
    await p9.submit("surprise", [flow(clock, uid="u1")])
    check("an undeclared source is accepted, not refused",
          p9.state["surprise"].accepted == 1,
          "refusing would lose data to a bookkeeping omission")
    check("and is listed as undeclared so the omission is visible",
          p9.undeclared() == ["surprise"], str(p9.undeclared()))

    future = flow(clock)
    future["time"] = clock.now + 7200
    e = (await p9.submit("declared_one", [future])).events[0]
    check("an event from a badly-skewed clock is corrected", e.soc_time_corrected)
    check("the source's own timestamp is preserved so the correction is reversible",
          bool(e.metadata_original_time), str(e.metadata_original_time))
    check("and the skew is recorded per source",
          p9.state["declared_one"].time_corrected == 1
          and p9.state["declared_one"].max_abs_skew_seconds >= 7200,
          f"{p9.state['declared_one'].max_abs_skew_seconds:.0f}s")

    r = await p9.submit("declared_one", [flow(clock, uid="ke")], keep_events=False)
    check("keep_events=False counts the batch without holding it in memory",
          r.accepted == 1 and r.events == [])

    snap = p9.snapshot()
    check("the snapshot exposes totals, per-source state, sinks and rejects",
          {"totals", "sources", "sinks", "declared", "undeclared", "dedup"} <= set(snap))
    check("per-source accepted sums to the total",
          sum(s["accepted"] for s in snap["sources"].values()) == snap["totals"]["accepted"],
          f"{snap['totals']['accepted']} accepted")
    check("the rate is measurable", p9.rate() >= 0.0, f"{p9.rate():.1f}/s")
    declared = declare_default_sources(p9)
    kinds = {}
    for d in declared:
        kinds.setdefault(d.kind, set()).add(d.name)
    # Asserted as coverage rather than as a count. A bare `== 18` fails the moment a
    # source is legitimately added — which it was, twice: local_auth splits into three
    # source names (the Security-channel log, the LSA session-table diff and the
    # local-account/policy diff) because they have wholly different cadences, 900s
    # against 7200s, and a health monitor that averaged them would call a dead auth log
    # healthy for two hours. Naming the expected members instead means adding a source
    # passes and dropping one fails, which is the direction that matters.
    check("the default source set covers every collector, all ten connector systems "
          "and the generator",
          kinds.get("collector", set()) >= {
              "network_flow", "windows_eventlog", "sysmon", "process", "dns",
              "local_auth_log", "logon_sessions", "local_accounts"}
          and {n.split("_")[0] for n in kinds.get("connector", set())} >= {
              "entra", "okta", "defender", "crowdstrike", "aws", "azure", "gcp",
              "m365", "google", "saas"}
          and kinds.get("generator") == {"emulation"}
          and len(declared) == len({d.name for d in declared}),
          f"{len(declared)} declared: "
          + ", ".join(f"{k}={len(v)}" for k, v in sorted(kinds.items())))
    check("...and each one declares its own health interval, so a 900s auth log and a "
          "7200s session-table diff are not judged by one timer",
          len({d.cadence_seconds for d in declared}) >= 5
          and all(d.cadence_seconds > 0 for d in declared if d.kind != "generator"),
          str(sorted({d.cadence_seconds for d in declared})))

    # ══ health ══════════════════════════════════════════════════════════════
    print("\n── health: the states a last-seen timer cannot see ──")
    hc = Clock()
    lake7 = fresh_lake(hc)
    hp = Pipeline(lake7, cfg, clock=hc)
    mon = HealthMonitor(hp, cfg, clock=hc)
    applied = gate_default_sources(mon)
    check("every shipped connector is gated on a credential that really exists",
          len(applied) == 11, f"{len(applied)} gates applied")
    declare_default_sources(hp)

    by = {h.source: h for h in mon.evaluate()}
    check("an unconfigured connector is UNCONFIGURED, not a fault",
          by["okta_system_log"].status is SourceStatus.UNCONFIGURED
          and not by["okta_system_log"].alertable, by["okta_system_log"].reason[:60])
    check("a configured source that never reported is NEVER_REPORTED, and IS a fault",
          by["network_flow"].status is SourceStatus.NEVER_REPORTED
          and by["network_flow"].alertable)
    check("because nothing there was ever proven to work — a deployment fault",
          "never" in by["network_flow"].reason)

    await hp.submit("network_flow", [flow(hc, uid="h1")])
    by = {h.source: h for h in mon.evaluate()}
    check("a reporting source inside its cadence is HEALTHY",
          by["network_flow"].status is SourceStatus.HEALTHY, by["network_flow"].reason[:60])

    hc.advance(90)  # cadence 60, dead after 180
    by = {h.source: h for h in mon.evaluate()}
    check("past its cadence but inside the dead threshold it is LATE",
          by["network_flow"].status is SourceStatus.LATE)
    check("and LATE does not page — quiet is not gone",
          not by["network_flow"].alertable, by["network_flow"].reason[:70])

    hc.advance(120)  # 210s since last event, > 60 * 3
    by = {h.source: h for h in mon.evaluate()}
    h = by["network_flow"]
    check("THE PHASE 1 GATE: a killed collector reports DEAD inside its interval",
          h.status is SourceStatus.DEAD and h.alertable, h.reason)
    check("the verdict shows the numbers it was derived from, so it is checkable",
          h.seconds_since_accepted == 210 and h.dead_after_seconds == 180,
          f"{h.seconds_since_accepted}s since, threshold {h.dead_after_seconds}s")

    print("\n── the state a timer reports as healthy ──")
    lake8 = fresh_lake(hc)
    rp = Pipeline(lake8, cfg, clock=hc)
    rp.declare_source("broken_connector", cadence_seconds=60, critical=True, kind="connector")
    rm = HealthMonitor(rp, cfg, clock=hc)
    good = [flow(hc, uid=f"g{i}") for i in range(10)]
    bad = []
    for i in range(20):
        b = flow(hc)
        del b["time"]
        bad.append(b)
    await rp.submit("broken_connector", good + bad)
    h = {x.source: x for x in rm.evaluate()}["broken_connector"]
    check("a source arriving and being thrown away is REJECTING",
          h.status is SourceStatus.REJECTING, h.reason[:90])
    check("even though it just submitted — a timer alone would call this healthy",
          h.seconds_since_submit == 0.0 and h.alertable)
    check("the reason names the last rejection so it is actionable",
          "no time" in h.reason, h.reason[-70:])

    lake9 = fresh_lake(hc)
    sp = Pipeline(lake9, cfg, clock=hc)
    sp.declare_source("tiny", cadence_seconds=60)
    b = flow(hc)
    del b["time"]
    await sp.submit("tiny", [b, dict(b)])
    h = {x.source: x for x in HealthMonitor(sp, cfg, clock=hc).evaluate()}["tiny"]
    check(f"below {REJECT_MIN_SAMPLE} events a 100% reject rate is not evidence",
          h.status is not SourceStatus.REJECTING, f"{h.status.value}: {h.reason[:50]}")

    print("\n── working, and not current ──")
    lakeA = fresh_lake(hc)
    tp = Pipeline(lakeA, cfg, clock=hc)
    tp.declare_source("replaying", cadence_seconds=60, kind="connector")
    for i in range(6):
        old = flow(hc)
        old["time"] = hc.now - 40_000  # last month's audit log, arriving now
        old["metadata_uid"] = f"old{i}"
        await tp.submit("replaying", [old])
    h = {x.source: x for x in HealthMonitor(tp, cfg, clock=hc).evaluate()}["replaying"]
    check("a connector whose cursor stopped advancing is STALLED",
          h.status is SourceStatus.STALLED, h.reason[:80])
    check("it is accepting events and still a fault — a real-time rule never sees them",
          h.accepted == 6 and h.alertable and h.seconds_since_accepted == 0.0)

    print("\n── what cannot be judged is said, not guessed ──")
    lakeB = fresh_lake(hc)
    up = Pipeline(lakeB, cfg, clock=hc)
    await up.submit("mystery", [flow(hc, uid="m1")])
    up.declare_source("no_cadence", cadence_seconds=0)
    await up.submit("no_cadence", [flow(hc, uid="nc1")])
    um = HealthMonitor(up, cfg, clock=hc)
    by = {x.source: x for x in um.evaluate()}
    check("a reporting but undeclared source is UNDECLARED",
          by["mystery"].status is SourceStatus.UNDECLARED)
    check("and its reason says why silence there cannot be detected",
          "no cadence is known" in by["mystery"].reason, by["mystery"].reason[:80])
    check("a declared source with no cadence is not judged for silence either",
          by["no_cadence"].status is SourceStatus.HEALTHY
          and "not judged" in by["no_cadence"].reason)
    check("a gate naming a credential that does not exist raises at WIRING time",
          _raises(lambda: um.gate_on_credential("mystery", "connectors.nonexistent.key"),
                  KeyError),
          "not at verdict time — the gate is only read when a source goes quiet, "
          "which is the one moment the monitor has to be right")

    print("\n── ordering, transitions and reporting ──")
    ordered = mon.evaluate()
    check("evaluate() sorts worst-first so a console shows the fault, not the alphabet",
          ordered[0].status.rank <= ordered[-1].status.rank,
          f"{ordered[0].status.value} … {ordered[-1].status.value}")
    check("critical sources outrank non-critical at equal status",
          all(
              ordered[i].status.rank < ordered[i + 1].status.rank
              or ordered[i].critical >= ordered[i + 1].critical
              for i in range(len(ordered) - 1)
          ))
    rep = mon.report()
    check("the report renders without a UI", "log-source health" in rep and "dead=" in rep)
    check("and calls out critical sources in fault, and why it matters",
          "CRITICAL SOURCES IN FAULT" in rep and "indistinguishable from safety" in rep)

    cov = mon.coverage()
    check("coverage excludes unconfigured sources from its denominator",
          cov["sources_judged"] == cov["sources_total"] - len(cov["unconfigured"]),
          f"{cov['sources_judged']} judged of {cov['sources_total']}, "
          f"{len(cov['unconfigured'])} unconfigured")
    check("and names which critical sources are in fault rather than giving a bare %",
          cov["critical_in_fault"] and "network_flow" in cov["critical_in_fault"],
          str(cov["critical_in_fault"]))
    check("every status is counted, including the zeroes",
          set(cov["by_status"]) == {s.value for s in SourceStatus}, str(len(cov["by_status"])))

    print("\n── persistence and the audit trail ──")
    chain_dir = ROOT / "audit"
    chain = AuditChain(chain_dir, checkpoint_every=50)
    await chain.open()
    client = VedDbClient(
        host=cfg.store.veddb_host,
        port=cfg.store.veddb_port,
        pool_size=cfg.store.veddb_pool_size,
        namespace=cfg.store.veddb_namespace,
    )
    # VedDB is a separate process the operator runs. When it is down, the health
    # monitor's *audit* behaviour is still fully testable — the chain is a local file —
    # so the store checks are skipped by name and everything else runs. `store=None` is
    # a supported HealthMonitor configuration, not a test-only fiction: a monitor with
    # no document store still evaluates, still chains, and still reports.
    store = None
    try:
        await client.start()
        caps = await probe_and_require(client)
        store = DocStore(client, caps, collections=[health_collection()])
        await store.drop_collection(HEALTH_COLLECTION)
    except (VedDbError, ConnectionError, TimeoutError) as exc:  # noqa: BLE001
        print(
            f"\n  !! VedDB unreachable at {cfg.store.veddb_host}:{cfg.store.veddb_port}"
            f" — {exc}\n"
            f"  !! Start it, then re-run: the five store checks below are SKIPPED, not\n"
            f"  !! passed. Everything that does not need the store still runs.\n"
        )
        for name in (
            "health is persisted per source, keyed by name",
            "with the reason, not just the status",
            "and indexed, so 'show me everything dead' is one lookup",
            "the alertable flag is indexed for the metrics module",
            "the health collection's indexes are consistent",
        ):
            skip(name, "VedDB unreachable")

    lakeC = fresh_lake(hc)
    ap = Pipeline(lakeC, cfg, clock=hc, audit=chain)
    ap.declare_source("agent_endpoint", cadence_seconds=60, critical=True, kind="collector")
    am = HealthMonitor(ap, cfg, store=store, audit=chain, clock=hc)
    results = await am.record()
    check("the startup fault is chained — a source that never worked is evidence",
          any(r["action"] == "ingest.source_status" for r in await _records(chain)))
    before = len(await _records(chain))
    await am.record()
    check("re-evaluating with nothing changed adds no audit records",
          len(await _records(chain)) == before, "only transitions are chained")

    await ap.submit("agent_endpoint", [flow(hc, uid="ae1")])
    await am.record()
    recs = await _records(chain)
    trans = [r for r in recs if r["action"] == "ingest.source_status"]
    check("recovery is chained too, with both endpoints of the transition",
          trans[-1]["data"]["from"] == "never_reported"
          and trans[-1]["data"]["to"] == "healthy",
          f"{trans[-1]['data']['from']} -> {trans[-1]['data']['to']}")
    hc.advance(1000)
    await am.record()
    check("and so is the death, which is the record a post-incident review needs",
          [r for r in await _records(chain) if r["action"] == "ingest.source_status"][-1]["data"]["to"]
          == "dead")
    v = await chain.verify()
    check("the health trail verifies as an intact chain", v.ok, v.report().splitlines()[0])

    doc = await store.get(HEALTH_COLLECTION, "agent_endpoint") if store else None
    if store:
        check("health is persisted per source, keyed by name",
              doc and doc["source"] == "agent_endpoint")
        check("with the reason, not just the status",
              "last event" in doc["reason"], doc["reason"][:60])
        dead = await store.find(HEALTH_COLLECTION, "status", "dead")
        check("and indexed, so 'show me everything dead' is one lookup",
              any(d["source"] == "agent_endpoint" for d in dead), f"{len(dead)} dead")
        alert = await store.find(HEALTH_COLLECTION, "alertable", True)
        check("the alertable flag is indexed for the metrics module", len(alert) >= 1, f"{len(alert)}")
        vr = await store.verify(HEALTH_COLLECTION)
        check("the health collection's indexes are consistent", vr["consistent"], str(vr))

    print("\n── the background loop ──")
    lakeD = fresh_lake(hc)
    bp = Pipeline(lakeD, cfg, clock=hc)
    bp.declare_source("looped", cadence_seconds=60)
    bm = HealthMonitor(bp, cfg, clock=hc)
    bm.check_seconds = 0.02
    bm.start()
    await asyncio.sleep(0.12)
    check("the monitor evaluates on its own interval", bm.evaluations >= 3, f"{bm.evaluations} runs")
    await bm.stop()
    stopped = bm.evaluations
    await asyncio.sleep(0.05)
    check("and stops cleanly when asked", bm.evaluations == stopped)

    check("durations are rendered for humans reading a page at 3 a.m.",
          (_dur(45), _dur(600), _dur(9000), _dur(200000)) == ("45s", "10m", "2.5h", "2.3d"),
          f"{_dur(45)} {_dur(600)} {_dur(9000)} {_dur(200000)}")
    check("and 'never' is a duration too", _dur(None) == "never")

    # ── teardown ────────────────────────────────────────────────────────────
    await chain.close()
    if store:
        await store.drop_collection(HEALTH_COLLECTION)
    await client.close()
    while _OPEN:
        try:
            _OPEN.pop().close()
        except Exception:
            pass
    shutil.rmtree(ROOT, ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed"
          + (f", {len(SKIP)} SKIPPED" if SKIP else ""))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    if SKIP:
        # Loud, and last, because a skipped check is an unanswered question. Exit code
        # stays 0 — the environment was incomplete, the code was not shown to be wrong —
        # but nobody reads "854 passed" and thinks a store check ran when this is here.
        print(f"SKIPPED ({len(SKIP)}) — these did NOT run and were NOT verified:")
        for name, why in SKIP:
            print(f"  - {name}  [{why}]")
    return 1 if FAIL else 0


def _raises(fn, exc=Exception):
    try:
        fn()
        return False
    except exc:
        return True
    except Exception:
        return False


async def _records(chain):
    """Audit records as plain dicts. `records()` is a sync streaming iterator."""
    return [
        {"action": r.action, "target": r.target, "data": r.data, "seq": r.seq}
        for r in chain.records()
    ]


sys.exit(asyncio.run(main()))

"""Scratch verification for core.store.retention.

Retention is the only subsystem that destroys evidence unattended, so the tests
below are weighted towards proving it *does not* — holds win, dry-run is the
default, audit precedes deletion — rather than towards proving it deletes.
"""

import asyncio
import shutil
import sys
import time
from datetime import datetime, timezone

import pyarrow as pa

sys.path.insert(0, ".")

from core.audit.chain import AuditChain
from core.config import get
from core.store.kvdoc import Collection, DocStore
from core.store.lake import EXTRA_COLUMN, Lake, LakeTable
from core.store.retention import (
    COLD_COMPRESSION_LEVEL,
    DocPolicy,
    HOLD_COLLECTION,
    HoldRegistry,
    LegalHold,
    RetentionError,
    RetentionManager,
    TablePolicy,
    _partition_window,
    _split_partition,
)
from core.store.veddb import VedDbClient

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


EVENTS = LakeTable(
    name="r_events",
    time_field="time",
    schema=pa.schema([
        ("time", pa.float64()),
        ("source", pa.string()),
        ("actor_user", pa.string()),
        ("bytes_out", pa.int64()),
        (EXTRA_COLUMN, pa.string()),
    ]),
)

CASES = Collection(name="r_case", indexed=("status", "owner"), id_field="case_id")
FLOWS = Collection(name="r_flowsum", indexed=("host",), id_field="flow_id")

DAY = 86400.0
# A fixed "now" so ages are exact and the suite does not drift with wall clock.
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def hour_at(days_ago: float) -> tuple[str, str, float]:
    """A partition (dt, hh) whose *end* is exactly ``days_ago`` days before NOW."""
    end = NOW - days_ago * DAY
    start = end - 3600.0
    d = datetime.fromtimestamp(start, tz=timezone.utc)
    return d.strftime("%Y-%m-%d"), d.strftime("%H"), start + 60.0


async def seed_partition(lake: Lake, days_ago: float, rows: int, files: int = 1):
    """Write ``rows`` rows into the partition ``days_ago`` days old, in ``files`` files."""
    dt, hh, ts = hour_at(days_ago)
    per = max(1, rows // files)
    for f in range(files):
        await lake.append(EVENTS.name, [
            {"time": ts + i, "source": "gen", "actor_user": f"u{i % 7}", "bytes_out": i * 13}
            for i in range(per)
        ])
        await lake.flush(EVENTS.name)   # one flush == one file
    return dt, hh


async def main():
    cfg = get()
    root = cfg.store.lake_dir.parent / "retention_scratch"
    ddb = root.parent / "retention_scratch.duckdb"
    audit_dir = cfg.audit.chain_dir.parent / "retention_audit_scratch"
    for p in (root, audit_dir):
        if p.exists():
            shutil.rmtree(p)
    ddb.unlink(missing_ok=True)

    client = VedDbClient(host=cfg.store.veddb_host, port=cfg.store.veddb_port,
                         namespace=cfg.store.veddb_namespace)
    await client.start()
    docs = DocStore(client)
    docs.register(CASES)
    docs.register(FLOWS)
    await docs.claim_writer_lease(force=True)

    # Leftovers from an aborted earlier run would silently change every count.
    # HOLD_COLLECTION must be registered before it can be dropped, otherwise the
    # drop raises and the broad except below hides the leak.
    docs.register(HOLD_COLLECTION)
    for col in (CASES.name, FLOWS.name, HOLD_COLLECTION.name):
        await docs.drop_collection(col)

    audit = AuditChain(audit_dir, checkpoint_every=1000)
    await audit.open()

    lake = Lake(root=root, duckdb_path=ddb, tables=[EVENTS], flush_rows=1_000_000,
                memory_limit=cfg.store.duckdb_memory_limit, threads=cfg.store.duckdb_threads)
    holds = HoldRegistry(docs, audit=audit)

    print("── policy guards ──")
    try:
        TablePolicy("x", hot_days=30, warm_days=7, cold_days=400)
        check("misordered tiers rejected", False, "accepted hot > warm")
    except RetentionError as exc:
        check("misordered tiers rejected", True, str(exc)[:60])
    check("ordered tiers accepted", TablePolicy("x", 7, 90, 400).cold_days == 400)

    print("\n── partition window arithmetic ──")
    s, e = _partition_window("2026-01-15", "07")
    check("window is exactly one hour", e - s == 3600.0)
    check("window is UTC, not local",
          datetime.fromtimestamp(s, tz=timezone.utc).hour == 7,
          f"{datetime.fromtimestamp(s, tz=timezone.utc):%Y-%m-%dT%H:%M:%SZ}")
    check("partition string round-trips", _split_partition("dt=2026-01-15/hh=07") == ("2026-01-15", "07"))
    for bad in (None, "", "2026-01-15", "hh=07"):
        try:
            _split_partition(bad)
            check(f"malformed partition {bad!r} rejected", False)
        except RetentionError:
            check(f"malformed partition {bad!r} rejected", True)

    print("\n── seed four partitions at known ages ──")
    #  1 d  → hot, but multi-file → compact
    #  2 h  → hot and too fresh to compact
    # 120 d → past warm_days → freeze
    # 500 d → past cold_days → expire
    p_compact = await seed_partition(lake, days_ago=1, rows=4_000, files=4)
    p_fresh = await seed_partition(lake, days_ago=2 / 24.0, rows=800, files=3)
    p_freeze = await seed_partition(lake, days_ago=120, rows=6_000, files=2)
    p_expire = await seed_partition(lake, days_ago=500, rows=2_000, files=2)
    total_rows = (await lake.aquery(f"SELECT count(*) AS n FROM {EVENTS.name}"))[0]["n"]
    check("four partitions on disk", len(lake.partitions(EVENTS.name)) == 4,
          str([f"{d}/{h}:{f}f" for d, h, f, _ in lake.partitions(EVENTS.name)]))

    policy = TablePolicy(EVENTS.name, hot_days=7, warm_days=90, cold_days=400,
                         compact_after_hours=3)
    mgr = RetentionManager(lake, holds, table_policies=[policy], docs=docs, audit=audit,
                           clock=lambda: NOW)

    print("\n── plan classifies by real age ──")
    plan = await mgr.plan(now=NOW)
    kinds = {(a.table, a.partition): a.kind for a in plan.actions}
    check("500d partition planned for expiry",
          kinds.get((EVENTS.name, f"dt={p_expire[0]}/hh={p_expire[1]}")) == "expire_partition",
          str(kinds))
    check("120d partition planned for freeze",
          kinds.get((EVENTS.name, f"dt={p_freeze[0]}/hh={p_freeze[1]}")) == "freeze")
    check("1d multi-file partition planned for compaction",
          kinds.get((EVENTS.name, f"dt={p_compact[0]}/hh={p_compact[1]}")) == "compact")
    check("2h-old partition is left alone (inside compact_after_hours)",
          (EVENTS.name, f"dt={p_fresh[0]}/hh={p_fresh[1]}") not in kinds,
          "3 files but only 2h old")
    check("plan is ordered oldest-first",
          [round(a.age_days) for a in plan.actions] == sorted(
              (round(a.age_days) for a in plan.actions), reverse=True))
    check("every action carries its data's timestamp",
          all(a.ts is not None for a in plan.actions))
    check("plan reports bytes it would free",
          plan.summary()["bytes_to_free"] > 0, f"{plan.summary()['bytes_to_free']:,} bytes")
    check("plan() has no side effects", (await lake.aquery(
        f"SELECT count(*) AS n FROM {EVENTS.name}"))[0]["n"] == total_rows)

    print("\n── dry run is the default and executes nothing ──")
    before_files = {(d, h): f for d, h, f, _ in lake.partitions(EVENTS.name)}
    res = await mgr.apply(plan)          # note: no dry_run argument
    check("apply() defaults to dry run", res["dry_run"] is True)
    check("dry run executes nothing", res["executed"] == 0, str(res["executed"]))
    check("dry run marks every action", all(r.get("dry_run") for r in res["results"]))
    check("no partition changed", {(d, h): f for d, h, f, _ in lake.partitions(EVENTS.name)}
          == before_files)
    check("no audit record written by a dry run", audit.head()[0] == 0, str(audit.head()[0]))

    print("\n── a legal hold blocks expiry and stays visible in the plan ──")
    e_start, e_end = _partition_window(*p_expire)
    hold = await holds.place(
        reason="Litigation: Acme v. Contoso, preservation order 2026-CV-118",
        created_by="analyst:legal", from_ts=e_start - DAY, until_ts=e_end + DAY,
        tables=[EVENTS.name])
    check("hold placed and audited", audit.head()[0] == 1)
    plan2 = await mgr.plan(now=NOW)
    held = plan2.held
    check("held partition still appears in the plan", len(held) == 1, str([a.describe() for a in held]))
    check("the exemption is attributed to a specific hold",
          held[0].blocked_by_hold == hold.hold_id and held[0].kind == "expire_partition")
    check("held action is excluded from actionable", all(
        a.blocked_by_hold is None for a in plan2.actionable))
    check("summary counts the block", plan2.summary()["blocked_by_hold"] == 1)
    check("hold ids are listed in the plan", plan2.live_holds == [hold.hold_id])
    check("report() renders the hold",
          "HELD by" in plan2.report() and hold.hold_id in plan2.report())
    check("freeze is NOT blocked by a hold",
          any(a.kind == "freeze" and a.blocked_by_hold is None for a in plan2.actions),
          "a rewrite preserves rows byte-for-byte")

    print("\n── a hold placed between plan and apply still wins ──")
    #  Plan generated with no hold covering the 120d partition, then a hold lands.
    await holds.release(hold.hold_id, released_by="analyst:legal")
    plan3 = await mgr.plan(now=NOW)
    check("released hold no longer blocks",
          all(a.blocked_by_hold is None for a in plan3.actions),
          f"{len(plan3.held)} held")
    late = await holds.place(reason="Regulator request 2026-06", created_by="analyst:legal",
                            tables=[EVENTS.name])   # no window == everything
    res3 = await mgr.apply(plan3, dry_run=True)
    skipped = [r for r in res3["results"] if "skipped" in r]
    check("apply re-reads holds and skips the expiry the plan thought was clear",
          len(skipped) == 1 and "expire_partition" in skipped[0]["action"],
          str(skipped))
    await holds.release(late.hold_id, released_by="analyst:legal")

    print("\n── real execution: compact, freeze, expire ──")
    plan4 = await mgr.plan(now=NOW)
    exp_rows = (await lake.aquery(
        f"SELECT count(*) AS n FROM {EVENTS.name} "
        f"WHERE dt='{p_expire[0]}' AND hh='{p_expire[1]}'"))[0]["n"]
    fz_before = [p for p in lake.partitions(EVENTS.name)
                 if (p[0], p[1]) == p_freeze][0]
    seq_before = audit.head()[0]
    res4 = await mgr.apply(plan4, dry_run=False, actor="retention")

    check("no errors", res4["errors"] == [], str(res4["errors"]))
    check("all three actions executed", res4["executed"] == 3, str(res4["executed"]))

    parts = {(d, h): (f, b) for d, h, f, b in lake.partitions(EVENTS.name)}
    check("expired partition is gone from disk", p_expire not in parts, str(list(parts)))
    check("expiry reported the bytes it freed", res4["bytes_freed"] > 0,
          f"{res4['bytes_freed']:,} bytes")
    remaining = (await lake.aquery(f"SELECT count(*) AS n FROM {EVENTS.name}"))[0]["n"]
    check("exactly the expired partition's rows are gone",
          remaining == total_rows - exp_rows,
          f"{total_rows:,} − {exp_rows:,} = {remaining:,}")

    check("compacted partition is one file", parts[p_compact][0] == 1,
          f"4 → {parts[p_compact][0]}")
    check("frozen partition is one file", parts[p_freeze][0] == 1,
          f"{fz_before[2]} → {parts[p_freeze][0]}")
    fz_result = next(r for r in res4["results"] if r["action"] == "freeze")["result"]
    check("freeze rewrote every row it found",
          fz_result["merged"] == (await lake.aquery(
              f"SELECT count(*) AS n FROM {EVENTS.name} "
              f"WHERE dt='{p_freeze[0]}' AND hh='{p_freeze[1]}'"))[0]["n"],
          f"{fz_result['merged']:,} rows")
    check("freeze is a measurably smaller file, not just a label",
          parts[p_freeze][1] < fz_before[3],
          f"{fz_before[3]:,} → {parts[p_freeze][1]:,} bytes at zstd-{COLD_COMPRESSION_LEVEL}")

    print("\n── the deletion was audited before it happened ──")
    recs = [r for r in audit.records() if r.seq > seq_before]
    kinds_logged = [r.action for r in recs]
    check("expiry is in the audit chain", "retention.expire_partition" in kinds_logged,
          str(kinds_logged))
    check("non-destructive actions are not individually audited",
          "retention.compact" not in kinds_logged and "retention.freeze" not in kinds_logged,
          "compaction destroys nothing, so it is summarised not itemised")
    check("run completion is audited", kinds_logged[-1] == "retention.run_complete")
    done = recs[-1].data
    check("completion record carries real counts",
          done["executed"] == 3 and done["errors"] == 0 and done["bytes_freed"] > 0,
          str(done))
    exp_rec = next(r for r in recs if r.action == "retention.expire_partition")
    check("audit names the partition and the reason",
          p_expire[0] in exp_rec.target and "cold_days" in exp_rec.data["reason"],
          f"{exp_rec.target} — {exp_rec.data['reason']}")
    check("audit chain still verifies after a retention run", (await audit.verify()).ok)

    print("\n── work is not repeated on the next run ──")
    plan5 = await mgr.plan(now=NOW)
    check("frozen partition is not re-frozen",
          not any(a.kind == "freeze" for a in plan5.actions), str([a.kind for a in plan5.actions]))
    check("compacted partition is not re-compacted",
          not any(a.kind == "compact" and a.partition == f"dt={p_compact[0]}/hh={p_compact[1]}"
                  for a in plan5.actions))
    check("state file persisted", (root / ".retention_state.json").exists())
    check("nothing left to do", plan5.actions == [], str([a.describe() for a in plan5.actions]))

    print("\n── a corrupt state file degrades to redoing work, never to deleting twice ──")
    (root / ".retention_state.json").write_text("{not json", encoding="utf-8")
    plan6 = await mgr.plan(now=NOW)
    check("corrupt state does not raise", isinstance(plan6.actions, list))
    check("corrupt state re-proposes the freeze (safe direction)",
          any(a.kind == "freeze" for a in plan6.actions), str([a.kind for a in plan6.actions]))
    check("corrupt state proposes no extra deletion",
          not any(a.destructive for a in plan6.actions))

    print("\n── document expiry ──")
    old = NOW - 400 * DAY
    recent = NOW - 3 * DAY
    for i in range(6):
        await docs.put(CASES.name, {
            "case_id": f"case-{i:02d}",
            "status": "open" if i < 2 else "closed",
            "owner": "analyst:alice",
            "closed_at": old if i % 2 == 0 else recent,
            # Deliberately try to backdate the store's own stamp.
            "_updated_at": old,
        })
    for i in range(4):
        await docs.put(FLOWS.name, {
            "flow_id": f"flow-{i:02d}", "host": "WS-01", "last_seen": old})

    seeded = await docs.get(CASES.name, "case-00")
    check("the store's _updated_at cannot be backdated by the caller",
          seeded["_updated_at"] > NOW - DAY,
          "put() stamps it server-side, which is what makes the default policy "
          "trustworthy — a caller-owned field is used for real event ages")
    check("a caller-owned time field is preserved verbatim", seeded["closed_at"] == old)

    dpolicies = [
        DocPolicy(CASES.name, ttl_days=365, time_field="closed_at",
                  keep_if="status", keep_if_values=("open",)),
        DocPolicy(FLOWS.name, ttl_days=90, time_field="last_seen"),
    ]
    mgr2 = RetentionManager(lake, holds, table_policies=[], doc_policies=dpolicies,
                            docs=docs, audit=audit, clock=lambda: NOW)
    dplan = await mgr2.plan(now=NOW)
    expiring = {(a.collection, a.doc_id) for a in dplan.actions if a.kind == "expire_document"}
    check("old closed cases are planned for expiry",
          ("r_case", "case-02") in expiring and ("r_case", "case-04") in expiring,
          str(sorted(expiring)))
    check("an open case is exempt regardless of age",
          ("r_case", "case-00") not in expiring, "case-00 is 400d old but status=open")
    check("recent cases are untouched",
          not any(d.startswith("case-0") and int(d[-1]) % 2 == 1 for _, d in expiring))
    check("all four old flows expire", len([1 for c, _ in expiring if c == "r_flowsum"]) == 4)
    check("doc ids come from the collection's declared id_field",
          all(d.startswith(("case-", "flow-")) for _, d in expiring), str(sorted(expiring)))

    print("\n── a collection hold blocks document expiry by the document's own date ──")
    # A window covering only the *old* documents, checked against each doc's stamp.
    chold = await holds.place(reason="GDPR subject access request", created_by="analyst:dpo",
                              from_ts=old - DAY, until_ts=old + DAY,
                              collections=[FLOWS.name])
    dplan2 = await mgr2.plan(now=NOW)
    check("flows are held", len([a for a in dplan2.held if a.collection == "r_flowsum"]) == 4,
          str(len(dplan2.held)))
    check("cases in a different collection are unaffected",
          all(a.blocked_by_hold is None for a in dplan2.actions if a.collection == "r_case"))
    r = await mgr2.apply(dplan2, dry_run=False)
    check("held documents survive execution",
          await docs.get(FLOWS.name, "flow-00") is not None)
    check("unheld documents are deleted",
          await docs.get(CASES.name, "case-02") is None)
    check("the exempt open case survives",
          await docs.get(CASES.name, "case-00") is not None)
    left = sorted(await docs.list_ids(CASES.name))
    check("exactly the expected cases remain",
          left == ["case-00", "case-01", "case-03", "case-05"], str(left))
    check("index entries were removed with the documents",
          [d["case_id"] for d in await docs.find(CASES.name, "status", "closed")] in
          (["case-03"], ["case-05"], ["case-03", "case-05"], ["case-05", "case-03"]),
          str(sorted(d["case_id"] for d in await docs.find(CASES.name, "status", "closed"))))
    check("skips are reported per document", r["skipped"] == 4, str(r["skipped"]))
    await holds.release(chold.hold_id, released_by="analyst:dpo")

    print("\n── one bad action does not abandon the plan ──")
    await seed_partition(lake, days_ago=600, rows=500, files=1)
    await seed_partition(lake, days_ago=610, rows=500, files=1)
    mgr3 = RetentionManager(lake, holds, table_policies=[policy], docs=docs, audit=audit,
                            clock=lambda: NOW)
    plan7 = await mgr3.plan(now=NOW)
    check("two new expiries planned",
          len([a for a in plan7.actions if a.kind == "expire_partition"]) == 2)
    # Corrupt the first action so its execution raises, leaving the rest valid.
    # The count is derived: the corrupt-state section above also re-proposed a
    # freeze, and hardcoding 1 here would assert on that incidental detail.
    others = len(plan7.actions) - 1
    plan7.actions[0].partition = "dt=not-a-date/hh=99"
    res7 = await mgr3.apply(plan7, dry_run=False)
    check("the bad action is reported as an error", len(res7["errors"]) == 1, str(res7["errors"]))
    check("every other action still ran", res7["executed"] == others,
          f"{res7['executed']} of {others}")
    check("a re-check that cannot be evaluated fails the action, it is not treated as unheld",
          res7["errors"][0]["error"].startswith("ValueError"),
          res7["errors"][0]["error"][:80])

    print("\n── run() is plan+apply and is also dry by default ──")
    await seed_partition(lake, days_ago=700, rows=300, files=1)
    r = await mgr3.run()
    check("run() defaults to dry", r["dry_run"] is True and r["executed"] == 0)
    check("run() returns the plan it used", r["plan"].actions and r["plan"].generated_at > 0)
    r = await mgr3.run(dry_run=False)
    check("run(dry_run=False) executes", r["executed"] >= 1, str(r["executed"]))

    print("\n── holds survive a restart, and history is kept ──")
    docs2 = DocStore(client)
    holds2 = HoldRegistry(docs2, audit=audit)
    all_h = await holds2.all_holds()
    check("all holds readable from a fresh client", len(all_h) == 3, f"{len(all_h)} holds")
    check("released holds are retained, not deleted",
          len([h for h in all_h if not h.live]) == 3,
          "a released preservation order is itself evidence")
    check("released hold records who released it",
          all(h.released_by for h in all_h if not h.live))
    check("no live holds remain", await holds2.live_holds() == [])
    try:
        await holds2.release("hold-does-not-exist", released_by="x")
        check("releasing an unknown hold raises", False)
    except RetentionError:
        check("releasing an unknown hold raises", True)
    h = LegalHold("h", "r", "me", NOW, from_ts=NOW - DAY, until_ts=NOW + DAY)
    check("covers_window is half-open at the far edge",
          h.covers_window(NOW - 10, NOW + 10) and not h.covers_window(NOW + DAY, NOW + DAY + 10))
    h.released_at = NOW
    check("a released hold covers nothing",
          not h.covers_window(NOW - 10, NOW + 10) and not h.covers_collection("x", NOW))

    print("\n── cleanup ──")
    for col in (CASES.name, FLOWS.name, HOLD_COLLECTION.name):
        await docs.drop_collection(col)
    # Check every prefix, including legal_hold: a leaked hold is exactly what
    # silently shifted the counts above on the previous run.
    leftover = [
        k
        for pre in ("doc:", "ix:", "ixk:", "meta:")
        for col in (CASES.name, FLOWS.name, HOLD_COLLECTION.name)
        for k in await client.list_keys(f"{pre}{col}")
    ]
    check("scratch collections fully removed from VedDB", leftover == [], str(leftover[:5]))
    await docs.release_writer_lease()
    await audit.close()
    await client.close()
    lake.close()
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(audit_dir, ignore_errors=True)
    ddb.unlink(missing_ok=True)
    (ddb.parent / (ddb.name + ".wal")).unlink(missing_ok=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))

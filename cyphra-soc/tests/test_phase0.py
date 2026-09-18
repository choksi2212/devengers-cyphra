"""The Phase 0 gate: foundation is sound, or nothing is built on it.

Two parts, and the split is deliberate.

The **suite roll-up** runs each module's own verification as a subprocess and reports
its counts. Subprocesses rather than imports because every scratch suite ends in
``sys.exit(main())`` — importing one would end the run — and because a module that
cannot be verified in isolation is a module whose test depends on another's leftovers.

The **gate assertions** then re-prove the three criteria the plan actually named, in
this process, with the numbers printed rather than asserted-and-forgotten:

1. a document with three secondary indexes round-trips through VedDB;
2. a million events land in the lake and an aggregation over them returns under 2 s;
3. the audit chain verifies, and detects a record edited on disk.

The suites already cover all three. They are restated here because a gate whose
evidence is "187 checks passed somewhere" is not evidence a person can check, and
because these three are the load-bearing claims: everything in Phases 1-11 writes
through the document store, queries the lake, and is accountable to the chain.

Run from cyphra-soc/:  PYTHONIOENCODING=utf-8 python tests/test_phase0.py
Needs the VedDB server on the configured host/port.
"""

import asyncio
import os
import random
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, ".")

from core.audit.chain import AuditChain, VedDbAnchor
from core.config import get
from core.store.capability import probe_and_require
from core.store.kvdoc import Collection, DocStore
from core.store.lake import EXTRA_COLUMN, Lake, LakeTable, string_list
from core.store.veddb import VedDbClient

# The seven suites, in dependency order — the client before the layers on it, the
# schemas last because nothing else depends on them.
SUITES = [
    ("store/kvdoc", "scratch_kvdoc.py", True),
    ("store/lake", "scratch_lake.py", True),
    ("audit/chain", "scratch_audit.py", True),
    ("store/retention", "scratch_retention.py", True),
    ("schema/attack", "scratch_attack.py", False),
    ("schema/ocsf", "scratch_ocsf.py", False),
    ("schema/entities", "scratch_entities.py", False),
]

PASS, FAIL = [], []
COUNT_RE = re.compile(r"^(\d+) passed, (\d+) failed", re.M)


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def run_suite(path: Path) -> tuple[int, int, int, float, str]:
    """Run one scratch suite. Returns (rc, passed, failed, seconds, tail)."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, str(path)], cwd=".", env=env,
        capture_output=True, text=True, errors="replace",
    )
    took = time.perf_counter() - t0
    out = (proc.stdout or "") + (proc.stderr or "")
    m = None
    for m in COUNT_RE.finditer(out):
        pass  # the last match is the summary line
    passed, failed = (int(m.group(1)), int(m.group(2))) if m else (0, -1)
    # On failure the useful part is the end: the summary and the named failures.
    tail = "\n".join(line for line in out.splitlines()[-14:] if line.strip())
    return proc.returncode, passed, failed, took, tail


# ══════════════════════════════════════════════════════════════════════════════
# part 1 — every module's own verification
# ══════════════════════════════════════════════════════════════════════════════


def roll_up() -> tuple[int, int]:
    here = Path(__file__).parent
    print("── Phase 0 module suites ──")
    print(f"  {'module':<18} {'checks':>7} {'failed':>7} {'time':>8}")
    total_p = total_f = 0
    broken: list[tuple[str, str]] = []
    for label, filename, needs_veddb in SUITES:
        path = here / filename
        if not path.exists():
            check(f"{label} suite present", False, f"{filename} is missing")
            continue
        rc, p, f, took, tail = run_suite(path)
        note = ""
        if f < 0:
            # No summary line at all: it died before finishing. That is a harder
            # failure than a failed check and must not read as "0 failed".
            note = "  <- NO SUMMARY (crashed)"
            f = 1
            broken.append((label, tail))
        elif rc != 0 or f:
            note = f"  <- rc={rc}"
            broken.append((label, tail))
        total_p += p
        total_f += f
        print(f"  {label:<18} {p:>7} {f:>7} {took:>7.1f}s{note}")
    check("every Phase 0 suite is green",
          total_f == 0, f"{total_p} checks across {len(SUITES)} modules")
    for label, tail in broken:
        print(f"\n  ── output tail: {label} ──")
        for line in tail.splitlines():
            print(f"  | {line}")
    return total_p, total_f


# ══════════════════════════════════════════════════════════════════════════════
# part 2 — the three named gate criteria
# ══════════════════════════════════════════════════════════════════════════════

GATE_COL = Collection(
    name="gate_detection",
    # Four indexed fields covering the three shapes the platform actually uses: a
    # scalar, a list (one document under many values), and a dotted path into a
    # nested object. A store that only indexes flat scalars cannot index an alert.
    indexed=("entity", "rule_id", "techniques", "actor.user.name"),
    id_field="id",
    required=("entity",),
)

GATE_EVENTS = LakeTable(
    name="gate_events",
    time_field="time",
    schema=pa.schema([
        ("time", pa.float64()),
        ("source", pa.string()),
        ("class_uid", pa.int32()),
        ("severity", pa.int8()),
        ("actor_user", pa.string()),
        ("src_ip", pa.string()),
        ("dst_ip", pa.string()),
        ("dst_port", pa.int32()),
        ("techniques", string_list()),
        ("bytes_out", pa.int64()),
        (EXTRA_COLUMN, pa.string()),
    ]),
)


async def gate_1_document_indexes(cfg) -> None:
    """A document with three secondary indexes round-trips through VedDB."""
    print("\n── gate 1: a document and its secondary indexes survive VedDB ──")
    client = VedDbClient(
        host=cfg.store.veddb_host, port=cfg.store.veddb_port,
        pool_size=cfg.store.veddb_pool_size, namespace=cfg.store.veddb_namespace,
    )
    await client.start()
    try:
        caps = await probe_and_require(client)
        check("the server's capabilities were probed, not assumed",
              caps.supported, f"{len(caps.supported)} opcodes: "
              f"{', '.join(sorted(caps.supported))}")

        store = DocStore(client, caps, collections=[GATE_COL])
        await store.drop_collection(GATE_COL.name)  # a prior aborted run leaves keys

        doc = {
            "id": "det-0001",
            "entity": "host:hostname:ws01",
            "rule_id": "R-1001",
            "techniques": ["T1059.001", "T1105"],
            "actor": {"user": {"name": "corp\\jdoe", "sid": "S-1-5-21-1-2-3-1001"}},
            "severity": 4,
            "observed_at": 1_756_000_000.0,
        }
        doc_id = await store.put(GATE_COL.name, doc)
        got = await store.get(GATE_COL.name, doc_id)
        # Not byte-identical: the store stamps its own provenance. Assert exactly
        # that — every submitted field unchanged, plus two timestamps and nothing
        # else. A store that silently reshaped a nested object or stringified an
        # int would pass a looser check and lose evidence.
        stamped = {k: v for k, v in (got or {}).items() if not k.startswith("_")}
        added = sorted(k for k in (got or {}) if k.startswith("_"))
        check("every submitted field comes back unchanged", stamped == doc,
              "including the nested actor object and the list")
        check("the store adds its own provenance and nothing else",
              added == ["_created_at", "_updated_at"]
              and isinstance(got["_created_at"], float),
              f"added {added}")

        by_entity = await store.find_ids(GATE_COL.name, "entity", "host:hostname:ws01")
        by_rule = await store.find_ids(GATE_COL.name, "rule_id", "R-1001")
        by_tech = await store.find_ids(GATE_COL.name, "techniques", "T1105")
        by_user = await store.find_ids(GATE_COL.name, "actor.user.name", "corp\\jdoe")
        check("all four secondary indexes resolve it",
              [doc_id] == by_entity == by_rule == by_tech == by_user,
              "scalar, list member and dotted path alike")

        # A second document sharing one technique but nothing else: the index must
        # return both for the shared value and one for the unshared.
        await store.put(GATE_COL.name, {
            "id": "det-0002", "entity": "host:hostname:ws02",
            "rule_id": "R-2002", "techniques": ["T1105"],
            "actor": {"user": {"name": "corp\\asmith"}},
        })
        shared = await store.find_ids(GATE_COL.name, "techniques", "T1105")
        check("a shared index value returns both documents",
              sorted(shared) == ["det-0001", "det-0002"], str(sorted(shared)))

        # An index is only trustworthy if it shrinks too. This is the failure mode
        # that matters: a posting list that keeps a value after the document stopped
        # having it makes a hunt return evidence that is not there.
        await store.update(GATE_COL.name, "det-0002", {"techniques": ["T1566"]})
        after = await store.find_ids(GATE_COL.name, "techniques", "T1105")
        moved = await store.find_ids(GATE_COL.name, "techniques", "T1566")
        check("an index entry is withdrawn when the value leaves the document",
              after == ["det-0001"] and moved == ["det-0002"],
              f"T1105 -> {after}, T1566 -> {moved}")

        await store.delete(GATE_COL.name, "det-0002")
        gone = await store.find_ids(GATE_COL.name, "techniques", "T1566")
        check("deleting the document clears its postings", gone == [], str(gone))

        report = await store.verify(GATE_COL.name)
        check("documents and indexes agree",
              report.get("consistent") is True,
              f"{report.get('documents')} docs, {report.get('postings')} postings, "
              f"dangling={len(report.get('dangling', []))} "
              f"missing={len(report.get('missing', []))} "
              f"misplaced={len(report.get('misplaced', []))}")

        dropped = await store.drop_collection(GATE_COL.name)
        check("the gate leaves no keys behind", isinstance(dropped, dict),
              str(dropped))
    finally:
        await client.close()


async def gate_2_million_rows(cfg) -> None:
    """A million events into the lake, and a real aggregation under 2 s."""
    print("\n── gate 2: 1,000,000 events, then an aggregation under 2 s ──")
    root = cfg.store.lake_dir.parent / "lake_phase0_gate"
    ddb = root.parent / "lake_phase0_gate.duckdb"
    shutil.rmtree(root, ignore_errors=True)
    ddb.unlink(missing_ok=True)
    Path(str(ddb) + ".wal").unlink(missing_ok=True)

    lake = Lake(root, ddb, tables=[GATE_EVENTS], flush_rows=100_000)
    try:
        total, chunk, hours = 1_000_000, 100_000, 48
        users = [f"user{i:02d}" for i in range(40)]
        sources = ["network_flow", "windows_eventlog", "sysmon", "entra", "cloudtrail"]
        techs = ["T1059.001", "T1105", "T1071.001", "T1110", "T1566.001"]
        rng = random.Random(42)
        base = datetime(2026, 8, 1, tzinfo=timezone.utc).timestamp()

        t0 = time.perf_counter()
        for start in range(0, total, chunk):
            rows = []
            for i in range(start, start + chunk):
                # Spread over 48 hours so the write exercises partitioning rather
                # than one hot directory — 48 partitions, which is what a real day
                # and a half of ingest looks like.
                ts = base + (i % (hours * 3600))
                rows.append({
                    "time": ts,
                    "source": sources[i % len(sources)],
                    "class_uid": 4001 + (i % 5),
                    "severity": 1 + (i % 5),
                    "actor_user": users[i % len(users)],
                    "src_ip": f"10.0.{(i // 254) % 254}.{1 + i % 254}",
                    "dst_ip": f"203.0.113.{1 + i % 200}",
                    "dst_port": [80, 443, 445, 3389, 53][i % 5],
                    "techniques": [techs[i % len(techs)]],
                    "bytes_out": rng.randrange(1_000_000),
                    EXTRA_COLUMN: "{}",
                })
            await lake.append(GATE_EVENTS.name, rows)
        await lake.flush()
        write_s = time.perf_counter() - t0
        check("1,000,000 rows written",
              lake._rows_written == total,
              f"{lake._rows_written:,} rows in {write_s:.1f}s "
              f"({total / write_s:,.0f} rows/s)")

        parts = lake.partitions(GATE_EVENTS.name)
        check("they are partitioned by date and hour, not one directory",
              len(parts) == hours, f"{len(parts)} dt=/hh= partitions")

        # A real aggregation: group, filter, order, aggregate two ways. A COUNT(*)
        # would be answered from Parquet metadata and prove nothing about scan speed.
        t0 = time.perf_counter()
        agg = lake.query(
            f"""SELECT actor_user, source,
                       count(*) AS events,
                       sum(bytes_out) AS bytes_out,
                       max(severity) AS worst
                FROM {GATE_EVENTS.name}
                WHERE severity >= 3
                GROUP BY actor_user, source
                HAVING count(*) > 100
                ORDER BY bytes_out DESC"""
        )
        q_s = time.perf_counter() - t0
        check("the aggregation returns under 2 s",
              q_s < 2.0, f"{q_s * 1000:.0f} ms, {len(agg)} groups")
        check("and it returned real groups, not an empty result",
              len(agg) > 0 and sum(r[2] for r in agg) > 0,
              f"top group {agg[0][0]}/{agg[0][1]}: {agg[0][2]:,} events"
              if agg else "empty")

        # Partition pruning is the whole reason for the dt=/hh= layout. If a
        # one-hour window costs the same as the full scan, the layout is decorative.
        one_hour = datetime(2026, 8, 1, 5, tzinfo=timezone.utc).timestamp()
        t0 = time.perf_counter()
        window = lake.query(
            f"SELECT count(*) FROM {GATE_EVENTS.name} WHERE time >= ? AND time < ?",
            [one_hour, one_hour + 3600],
        )
        prune_s = time.perf_counter() - t0
        check("a one-hour window is much cheaper than the full aggregation",
              prune_s < q_s and window[0][0] > 0,
              f"{prune_s * 1000:.0f} ms for {window[0][0]:,} rows "
              f"vs {q_s * 1000:.0f} ms")
    finally:
        lake.close()
        shutil.rmtree(root, ignore_errors=True)
        ddb.unlink(missing_ok=True)
        Path(str(ddb) + ".wal").unlink(missing_ok=True)


async def gate_3_audit_chain(cfg) -> None:
    """The chain verifies, and a record edited on disk is caught and named."""
    print("\n── gate 3: the audit chain detects a record edited on disk ──")
    root = cfg.audit.chain_dir.parent / "audit_phase0_gate"
    shutil.rmtree(root, ignore_errors=True)

    client = VedDbClient(
        host=cfg.store.veddb_host, port=cfg.store.veddb_port,
        pool_size=cfg.store.veddb_pool_size, namespace=cfg.store.veddb_namespace,
    )
    await client.start()
    anchor_key = "audit:phase0_gate_head"
    try:
        anchor = VedDbAnchor(client, key=anchor_key)
        chain = AuditChain(root, checkpoint_every=25, anchor=anchor)
        await chain.open()

        # A plausible incident's worth of records, including the two classes that
        # must be accountable: an autonomous response action and an LLM call.
        t0 = time.perf_counter()
        for i in range(200):
            await chain.append(
                action=["detect.fire", "respond.block_ip", "llm.call",
                        "case.update"][i % 4],
                actor="system" if i % 4 else "respond.engine",
                target=f"host:hostname:ws{i % 12:02d}",
                data={"i": i, "rule": f"R-{1000 + i % 7}"},
            )
        write_s = time.perf_counter() - t0
        head_seq, head_hash = chain.head()
        check("200 records appended, each fsynced before append returned",
              head_seq == 200,
              f"seq {head_seq} in {write_s:.1f}s ({200 / write_s:,.0f} rec/s)")

        v = await chain.verify()
        check("the intact chain verifies",
              v.ok and v.records == 200 and not v.failures,
              f"{v.records} records in {v.duration_s * 1000:.0f} ms, "
              f"anchor {v.anchor_state}")
        check("the head hash is published to VedDB, off the same disk",
              (await anchor.read()) == (head_seq, head_hash),
              "so wiping the log directory cannot quietly reset the chain")
        await chain.close()

        # Now the part that matters: edit a record in place, leaving the file
        # otherwise well-formed. This is what a tamper looks like — not a corrupted
        # file, a plausible one. The forgery chosen is the one with a motive:
        # retroactively changing *which host* an autonomous action was taken against,
        # at identical byte length so nothing about the file's shape gives it away.
        segments = chain.segments()
        check("the log is on disk in segments", bool(segments),
              f"{len(segments)} segment(s)")
        target = segments[0]
        original = target.read_text(encoding="utf-8")
        lines = original.splitlines()
        i = len(lines) // 2
        forged, n = re.subn(r'("target":"host:hostname:ws)(\d\d)"',
                            lambda m: f"{m.group(1)}{(int(m.group(2)) + 1) % 12:02d}\"",
                            lines[i])
        check("the edit rewrites one field and nothing else",
              n == 1 and forged != lines[i] and len(forged) == len(lines[i]),
              "a same-length plausible forgery, not a corruption")
        lines[i] = forged
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")

        v2 = await AuditChain(root, checkpoint_every=25).verify()
        check("verify refuses the tampered chain", not v2.ok, v2.report().splitlines()[-1].strip())
        check("and names the record it stopped at",
              bool(v2.failures) and v2.failures[0].get("seq"),
              f"seq {v2.failures[0].get('seq')}: {v2.failures[0].get('reason')}"
              if v2.failures else "no failure recorded")

        # Restoring the file must restore the verdict — otherwise "broken" could be
        # an artifact of re-reading rather than of the edit.
        target.write_text(original, encoding="utf-8")
        v3 = await AuditChain(root, checkpoint_every=25).verify()
        check("restoring the byte restores the verdict", v3.ok,
              "so the detection is of the edit, not of the reread")
    finally:
        await client.delete(anchor_key)
        await client.close()
        shutil.rmtree(root, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════


async def main() -> int:
    cfg = get()
    print(f"Phase 0 gate — VedDB {cfg.store.veddb_host}:{cfg.store.veddb_port}, "
          f"namespace {cfg.store.veddb_namespace!r}\n")

    suite_p, suite_f = roll_up()
    after_rollup = len(PASS) + len(FAIL)
    rollup_failed = len(FAIL)

    await gate_1_document_indexes(cfg)
    await gate_2_million_rows(cfg)
    await gate_3_audit_chain(cfg)

    gate_checks = len(PASS) + len(FAIL) - after_rollup
    gate_failed = len(FAIL) - rollup_failed
    print(f"\n{'=' * 74}")
    print(f"module suites   : {suite_p} checks, {suite_f} failed "
          f"(across {len(SUITES)} modules)")
    print(f"gate assertions : {gate_checks} checks, {gate_failed} failed")
    print(f"total           : {suite_p + gate_checks} checks")
    print(f"PHASE 0         : {'GREEN' if not FAIL else 'RED'}")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))

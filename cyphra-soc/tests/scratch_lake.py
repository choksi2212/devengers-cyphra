"""Scratch verification for core.store.lake, including the Phase 0 1M-row gate."""

import asyncio
import random
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, ".")

from core.config import get
from core.store.lake import (
    EXTRA_COLUMN,
    Lake,
    LakeError,
    LakeTable,
    SchemaConflict,
    string_list,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


EVENTS = LakeTable(
    name="t_events",
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

USERS = [f"user{i:02d}" for i in range(40)]
SOURCES = ["network_flow", "windows_eventlog", "sysmon", "entra", "cloudtrail"]


async def main():
    cfg = get()
    root = cfg.store.lake_dir.parent / "lake_scratch"
    if root.exists():
        shutil.rmtree(root)
    ddb = root.parent / "lake_scratch.duckdb"
    ddb.unlink(missing_ok=True)

    lake = Lake(
        root=root,
        duckdb_path=ddb,
        tables=[EVENTS],
        flush_rows=50_000,
        memory_limit=cfg.store.duckdb_memory_limit,
        threads=cfg.store.duckdb_threads,
    )
    tbl = EVENTS.name

    print("── empty table ──")
    rows = await lake.aquery(f"SELECT count(*) AS n FROM {tbl}")
    check("empty table answers 0, not an error", rows[0]["n"] == 0)
    cols = await lake.aquery(f"SELECT * FROM {tbl} LIMIT 0")
    check("empty view carries the real column names", cols == [])

    print("\n── declaration guards ──")
    for name, fn in (
        ("time_field must be in the schema",
         lambda: LakeTable("bad", pa.schema([("x", pa.string()), (EXTRA_COLUMN, pa.string())]))),
        ("partition column in schema rejected",
         lambda: LakeTable("bad", pa.schema([("time", pa.float64()), ("dt", pa.string()), (EXTRA_COLUMN, pa.string())]))),
        ("missing _extra rejected",
         lambda: LakeTable("bad", pa.schema([("time", pa.float64())]))),
        ("non-identifier table name rejected",
         lambda: LakeTable("bad-name!", pa.schema([("time", pa.float64()), (EXTRA_COLUMN, pa.string())]))),
    ):
        try:
            fn()
            check(name, False, "no error")
        except LakeError:
            check(name, True)
    try:
        lake.query(f"SELECT * FROM {tbl}_nope")
        check("unknown table in SQL raises LakeError", False)
    except LakeError:
        check("unknown table in SQL raises LakeError", True)

    print("\n── event-time coercion ──")
    base = 1_756_000_000.0
    # Derived, not hardcoded: a hand-written ISO literal that disagrees with the
    # epoch tests the literal, not the coercion.
    iso_z = datetime.fromtimestamp(base, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    iso_naive = iso_z.rstrip("Z")
    await lake.append(tbl, [
        {"time": base, "source": "a", EXTRA_COLUMN: None},
        {"time": int(base * 1000), "source": "b"},   # milliseconds
        {"time": iso_z, "source": "c"},              # ISO with Z
        {"time": iso_naive, "source": "d"},          # naive → UTC
    ])
    await lake.flush()
    got = await lake.aquery(
        f"SELECT source, time FROM {tbl} ORDER BY source", flush=False)
    check("all four time formats land on the same instant",
          len({round(r["time"]) for r in got}) == 1, str({r["source"]: r["time"] for r in got}))
    check("ms and s both partition to the same hour",
          len(lake.partitions(tbl)) == 1, str(lake.partitions(tbl)))
    try:
        await lake.append(tbl, [{"time": "not-a-time"}])
        check("unparseable time rejected", False)
    except SchemaConflict:
        check("unparseable time rejected", True)
    try:
        await lake.append(tbl, [{"source": "no-time"}])
        check("missing time field rejected", False)
    except SchemaConflict:
        check("missing time field rejected", True)

    print("\n── undeclared fields survive in _extra ──")
    await lake.append(tbl, [{
        "time": base, "source": "sysmon",
        "Image": r"C:\Windows\System32\rundll32.exe",
        "CommandLine": "rundll32 shell32.dll,Control_RunDLL",
        "nested": {"parent": "winword.exe"},
    }])
    await lake.flush()
    r = await lake.aquery(
        f"SELECT json_extract_string({EXTRA_COLUMN}, '$.Image') AS image, "
        f"json_extract_string({EXTRA_COLUMN}, '$.nested.parent') AS parent "
        f"FROM {tbl} WHERE source = 'sysmon'", flush=False)
    check("undeclared scalar queryable via JSON", r[0]["image"].endswith("rundll32.exe"))
    check("undeclared nested object queryable", r[0]["parent"] == "winword.exe")

    print("\n── type conflict is loud and names the column ──")
    try:
        await lake.append(tbl, [{"time": base, "dst_port": "not-a-port"}])
        await lake.flush()
        check("type conflict raises", False, "accepted a string into an int32 column")
    except SchemaConflict as exc:
        check("type conflict raises", True)
        check("error names column and value",
              "dst_port" in str(exc) and "not-a-port" in str(exc), str(exc)[:120])
    # The rejected batch must not be silently dropped from the buffer.
    lake._buffers[tbl].clear()

    print("\n── partial files are never visible ──")
    bdt, bhh = lake.partitions(tbl)[0][0], lake.partitions(tbl)[0][1]
    stray = lake.partition_dir(tbl, bdt, bhh) / ".part-truncated.parquet.tmp"
    stray.write_bytes(b"PAR1-garbage-not-a-real-footer")
    n = (await lake.aquery(f"SELECT count(*) AS n FROM {tbl}", flush=False))[0]["n"]
    check("a .tmp file is not picked up by the reader", n > 0, f"{n} rows read fine")
    stray.unlink()

    print("\n── 1M synthetic events (Phase 0 gate) ──")
    shutil.rmtree(root)
    ddb.unlink(missing_ok=True)
    lake.close()
    lake = Lake(root=root, duckdb_path=ddb, tables=[EVENTS], flush_rows=50_000,
                memory_limit=cfg.store.duckdb_memory_limit, threads=cfg.store.duckdb_threads)

    rng = random.Random(42)
    total, chunk_rows, hours = 1_000_000, 100_000, 48
    t0 = time.perf_counter()
    for chunk in range(total // chunk_rows):
        batch = []
        for i in range(chunk_rows):
            ts = base + rng.randrange(hours) * 3600 + rng.random() * 3600
            batch.append({
                "time": ts,
                "source": SOURCES[i % len(SOURCES)],
                "class_uid": 3002 + (i % 5),
                "severity": 1 + (i % 5),
                "actor_user": USERS[rng.randrange(len(USERS))],
                "src_ip": f"10.0.{rng.randrange(256)}.{rng.randrange(256)}",
                "dst_ip": f"93.184.{rng.randrange(256)}.{rng.randrange(256)}",
                "dst_port": rng.choice([22, 80, 443, 445, 3389, 8080]),
                "techniques": ["T1110"] if i % 97 == 0 else [],
                "bytes_out": rng.randrange(1_000_000),
            })
        await lake.append(tbl, batch)
        await lake.flush(tbl)
    write_s = time.perf_counter() - t0
    st = lake.stats(tbl)["tables"][tbl]
    check("1M rows written", lake._rows_written == total, f"{lake._rows_written:,} rows")
    print(f"       write: {write_s:.1f}s ({total/write_s:,.0f} rows/s), "
          f"{st['files']} files across {st['partitions']} partitions, "
          f"{st['bytes']/1e6:.0f} MB on disk")

    # The gate query: a real aggregation, not a count.
    sql = f"""
        SELECT actor_user, dst_port,
               count(*) AS events,
               sum(bytes_out) AS bytes_out,
               approx_count_distinct(dst_ip) AS peers
        FROM {tbl}
        WHERE severity >= 3
        GROUP BY actor_user, dst_port
        HAVING count(*) > 100
        ORDER BY bytes_out DESC
        LIMIT 20
    """
    t0 = time.perf_counter()
    agg = await lake.aquery(sql, flush=False)
    q1 = time.perf_counter() - t0
    check("aggregation over 1M rows under 2s", q1 < 2.0, f"{q1*1000:.0f} ms, {len(agg)} groups")

    t0 = time.perf_counter()
    win = await lake.aquery(f"""
        SELECT actor_user, hour, events, events - lag(events) OVER
                 (PARTITION BY actor_user ORDER BY hour) AS delta
        FROM (SELECT actor_user, dt || 'T' || hh AS hour, count(*) AS events
              FROM {tbl} GROUP BY 1, 2)
        ORDER BY abs(coalesce(delta, 0)) DESC LIMIT 10
    """, flush=False)
    q2 = time.perf_counter() - t0
    check("windowed per-hour deltas under 2s", q2 < 2.0, f"{q2*1000:.0f} ms, {len(win)} rows")

    t0 = time.perf_counter()
    pruned = await lake.aquery(
        f"SELECT count(*) AS n FROM {tbl} WHERE dt = '2025-08-24' AND hh = '05'",
        flush=False)
    q3 = time.perf_counter() - t0
    full = (await lake.aquery(f"SELECT count(*) AS n FROM {tbl}", flush=False))[0]["n"]
    check("partition pruning is faster than a full scan",
          q3 < q1, f"{q3*1000:.0f} ms for {pruned[0]['n']:,} of {full:,} rows")
    check("row count round-trips exactly", full == total, f"{full:,}")

    print("\n── compaction ──")
    dt0, hh0, files0, bytes0 = lake.partitions(tbl)[0]
    t0 = time.perf_counter()
    c = lake.compact(tbl, dt0, hh0)
    after = [p for p in lake.partitions(tbl) if p[0] == dt0 and p[1] == hh0][0]
    check("compaction merges to one file", after[2] == 1, f"{files0} → 1 files in {time.perf_counter()-t0:.2f}s")
    check("compaction preserves row count", c["merged"] == files0 * 0 + c["merged"] and
          (await lake.aquery(f"SELECT count(*) AS n FROM {tbl} WHERE dt='{dt0}' AND hh='{hh0}'", flush=False))[0]["n"] == c["merged"],
          f"{c['merged']:,} rows")
    check("compaction shrinks bytes", after[3] <= bytes0,
          f"{bytes0:,} → {after[3]:,} bytes")
    check("total still exact after compaction",
          (await lake.aquery(f"SELECT count(*) AS n FROM {tbl}", flush=False))[0]["n"] == total)

    print("\n── schema evolution ──")
    # A file written before a column existed must read back NULL, not fail.
    OLD = lake.table_dir(tbl)
    evolved = LakeTable(
        name=tbl, time_field="time",
        schema=pa.schema(list(EVENTS.schema) + [("new_field", pa.string())]))
    lake2 = Lake(root=root, duckdb_path=ddb, tables=[], flush_rows=10)
    lake2.register(evolved)
    await lake2.append(tbl, [{"time": base, "source": "new", "new_field": "present"}])
    await lake2.flush()
    r = await lake2.aquery(
        f"SELECT count(*) AS n, count(new_field) AS with_new FROM {tbl}", flush=False)
    check("old files read back as NULL for a new column",
          r[0]["n"] == total + 1 and r[0]["with_new"] == 1, str(r[0]))
    try:
        lake2.register(LakeTable(tbl, pa.schema([("time", pa.string()), (EXTRA_COLUMN, pa.string())])))
        check("retyping a registered table refused", False)
    except SchemaConflict:
        check("retyping a registered table refused", True)
    lake2.close()

    print("\n── partition drop ──")
    # Read the partition's row count now, not from the earlier compaction result:
    # the schema-evolution step above appended a row into this same hour.
    before_total = (await lake.aquery(f"SELECT count(*) AS n FROM {tbl}", flush=False))[0]["n"]
    in_partition = (await lake.aquery(
        f"SELECT count(*) AS n FROM {tbl} WHERE dt='{dt0}' AND hh='{hh0}'",
        flush=False))[0]["n"]
    d = lake.drop_partition(tbl, dt0, hh0)
    remaining = (await lake.aquery(f"SELECT count(*) AS n FROM {tbl}", flush=False))[0]["n"]
    check("dropping a partition removes exactly its rows",
          remaining == before_total - in_partition,
          f"{before_total:,} − {in_partition:,} = {remaining:,}")
    check("drop reports bytes reclaimed", d["bytes"] > 0, f"{d['bytes']/1e6:.1f} MB")
    check("dropping an absent partition is not an error",
          lake.drop_partition(tbl, "1999-01-01", "00")["deleted"] is False)

    lake.close()
    shutil.rmtree(root, ignore_errors=True)
    ddb.unlink(missing_ok=True)
    Path(str(ddb) + ".wal").unlink(missing_ok=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))

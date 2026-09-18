"""Scratch verification for core.store.kvdoc against the live VedDB server.

Folded into tests/test_phase0.py at the end of Phase 0; run standalone now so
each behaviour is confirmed before the next module is built on top of it.
"""

import asyncio
import sys

sys.path.insert(0, ".")

from core.config import get
from core.store.capability import probe_and_require
from core.store.kvdoc import (
    POSTING_SHARDS,
    Collection,
    DocStore,
    SchemaError,
    WriterLeaseHeld,
    _shard_of,
)
from core.store.veddb import VedDbClient

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "ok  " if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))


DETECTION = Collection(
    name="t_detection",
    indexed=("entity", "rule_id", "techniques", "actor.user.name"),
    id_field="id",
    required=("entity",),
)


async def main():
    cfg = get()
    client = VedDbClient(
        host=cfg.store.veddb_host,
        port=cfg.store.veddb_port,
        pool_size=cfg.store.veddb_pool_size,
        namespace=cfg.store.veddb_namespace,
    )
    await client.start()
    caps = await probe_and_require(client)
    print(f"capabilities: index={caps.index_strategy} concurrency={caps.concurrency_strategy}\n")

    store = DocStore(client, caps, collections=[DETECTION])
    col = DETECTION.name
    await store.drop_collection(col)

    print("── lease ──")
    await store.claim_writer_lease()
    check("lease claimed", store.holds_writer_lease)
    # Simulate a different live process by rewriting the lease record.
    await client.set_json(
        "_lease:writer",
        {"host": "other-host", "pid": 999999, "boot": "deadbeef",
         "claimed_at": 0, "expires_at": 9e18},
    )
    store2 = DocStore(client, caps, collections=[DETECTION])
    try:
        await store2.claim_writer_lease()
        check("second writer refused", False, "claim succeeded")
    except WriterLeaseHeld:
        check("second writer refused", True)
    await store2.claim_writer_lease(force=True)
    check("force steals lease", store2.holds_writer_lease)
    store.holds_writer_lease = False  # store2 owns it now

    print("\n── documents + 4 indexes ──")
    docs = [
        {"id": "d1", "entity": "host:WS-01", "rule_id": "R-100",
         "techniques": ["T1110", "T1078"],
         "actor": {"user": {"name": "alice smith"}}, "severity": "high"},
        {"id": "d2", "entity": "host:WS-01", "rule_id": "R-200",
         "techniques": ["T1110"],
         "actor": {"user": {"name": "bob o:brien"}}, "severity": "low"},
        {"id": "d3", "entity": "host:WS-02", "rule_id": "R-100",
         "techniques": ["T1071"], "severity": "medium"},
    ]
    for d in docs:
        await store2.put(col, d)
    check("round-trip", (await store2.get(col, "d1"))["severity"] == "high")
    check("_created_at/_updated_at stamped",
          "_created_at" in await store2.get(col, "d1"))
    check("index: entity", await store2.find_ids(col, "entity", "host:WS-01") == ["d1", "d2"])
    check("index: rule_id", await store2.find_ids(col, "rule_id", "R-100") == ["d1", "d3"])
    check("index: list-valued techniques",
          await store2.find_ids(col, "techniques", "T1110") == ["d1", "d2"])
    check("index: dotted path with a colon in the value",
          await store2.find_ids(col, "actor.user.name", "bob o:brien") == ["d2"])
    check("missing dotted path is not indexed as None",
          await store2.find_ids(col, "actor.user.name", None) == [])
    check("AND intersection",
          [d["id"] for d in await store2.find_all(col, {"entity": "host:WS-01", "rule_id": "R-200"})] == ["d2"])
    check("find_any union",
          sorted(d["id"] for d in await store2.find_any(col, "techniques", ["T1078", "T1071"])) == ["d1", "d3"])
    check("count", await store2.count(col) == 3)
    check("consistent after inserts", (await store2.verify(col))["consistent"])

    print("\n── shard distribution ──")
    shards = {_shard_of(i) for i in ("d1", "d2", "d3")}
    posting_keys = await client.list_keys(f"ix:{col}:")
    check("posting lists exist", len(posting_keys) > 0, f"{len(posting_keys)} keys")
    check("a write touches one shard per value",
          all(int(k.rsplit(':', 1)[1]) in range(POSTING_SHARDS) for k in posting_keys))

    print("\n── update vacates old posting lists ──")
    await store2.update(col, "d1", {"entity": "host:WS-99", "severity": "critical"})
    check("new value found", await store2.find_ids(col, "entity", "host:WS-99") == ["d1"])
    check("old value vacated", await store2.find_ids(col, "entity", "host:WS-01") == ["d2"])
    check("unrelated index untouched",
          await store2.find_ids(col, "rule_id", "R-100") == ["d1", "d3"])
    check("merge preserved other fields",
          (await store2.get(col, "d1"))["rule_id"] == "R-100")
    check("empty posting list deleted, not left behind",
          not await client.exists(store2.posting_key(col, "entity", "host:WS-01", _shard_of("d1"))))
    check("consistent after update", (await store2.verify(col))["consistent"])

    print("\n── delete ──")
    check("delete reports existed", await store2.delete(col, "d3"))
    check("document gone", await store2.get(col, "d3") is None)
    check("posting lists cleaned", await store2.find_ids(col, "rule_id", "R-100") == ["d1"])
    check("ixk cleaned", not await client.exists(store2.ixk_key(col, "d3")))
    check("delete of absent returns False", not await store2.delete(col, "nope"))
    check("consistent after delete", (await store2.verify(col))["consistent"])

    print("\n── verify detects real corruption ──")
    # Dangling: point a posting list at a document that does not exist.
    dangle_key = store2.posting_key(col, "rule_id", "R-100", _shard_of("ghost"))
    await client.set_json(dangle_key, {"v": "R-100", "ids": ["ghost"]})
    v = await store2.verify(col)
    check("dangling detected", len(v["dangling"]) == 1, str(v["dangling"]))
    check("not consistent", not v["consistent"])
    await client.delete(dangle_key)

    # Missing: delete a posting list a live document belongs to.
    live_key = store2.posting_key(col, "rule_id", "R-100", _shard_of("d1"))
    await client.delete(live_key)
    v = await store2.verify(col)
    check("missing detected", len(v["missing"]) == 1, str(v["missing"]))
    check("lookup silently omits it before repair",
          await store2.find_ids(col, "rule_id", "R-100") == [])

    # Misplaced: right value, wrong shard.
    wrong_shard = (_shard_of("d1") + 1) % POSTING_SHARDS
    await client.set_json(store2.posting_key(col, "rule_id", "R-100", wrong_shard),
                          {"v": "R-100", "ids": ["d1"]})
    v = await store2.verify(col)
    check("misplaced detected", len(v["misplaced"]) == 1, str(v["misplaced"]))

    print("\n── rebuild_indexes repairs ──")
    r = await store2.rebuild_indexes(col)
    v = await store2.verify(col)
    check("rebuild reports work", r["reindexed"] == 2, str(r))
    check("consistent after rebuild", v["consistent"], str(v))
    check("lookup restored", await store2.find_ids(col, "rule_id", "R-100") == ["d1"])

    print("\n── WAL replay ──")
    # Simulate a crash after the document landed but before its indexes did.
    await client.set_json(store2.doc_key(col, "d4"),
                          {"id": "d4", "entity": "host:WS-04", "rule_id": "R-300",
                           "techniques": [], "_created_at": 0, "_updated_at": 0})
    shard4 = _shard_of("d4")
    add = [[store2.posting_key(col, "entity", "host:WS-04", shard4), "entity", "host:WS-04"],
           [store2.posting_key(col, "rule_id", "R-300", shard4), "rule_id", "R-300"]]
    await client.set_json("wal:crashed1", {
        "op": "put", "col": col, "id": "d4",
        "doc_key": store2.doc_key(col, "d4"),
        "add": add, "remove": [], "ixk": sorted(a[0] for a in add), "at": 0,
    })
    check("index missing before repair", await store2.find_ids(col, "rule_id", "R-300") == [])
    rep = await store2.repair()
    check("repair completed the put",
          any(x["action"] == "completed" for x in rep["replayed"]), str(rep))
    check("index present after repair", await store2.find_ids(col, "rule_id", "R-300") == ["d4"])
    check("wal record consumed", not await client.exists("wal:crashed1"))
    check("consistent after replay", (await store2.verify(col))["consistent"])

    # Rollback: a WAL whose document never landed must not leave index entries.
    orphan_key = store2.posting_key(col, "rule_id", "R-400", _shard_of("d5"))
    await client.set_json(orphan_key, {"v": "R-400", "ids": ["d5"]})
    await client.set_json("wal:crashed2", {
        "op": "put", "col": col, "id": "d5",
        "doc_key": store2.doc_key(col, "d5"),
        "add": [[orphan_key, "rule_id", "R-400"]], "remove": [],
        "ixk": [orphan_key], "at": 0,
    })
    rep = await store2.repair()
    check("repair rolled back a doc-less put",
          any(x["action"] == "rolled-back" for x in rep["replayed"]), str(rep))
    check("orphan index entry removed", not await client.exists(orphan_key))
    check("consistent after rollback", (await store2.verify(col))["consistent"])

    # Idempotence: replaying the same WAL twice must converge, not double-apply.
    await client.set_json("wal:crashed3", {
        "op": "put", "col": col, "id": "d4",
        "doc_key": store2.doc_key(col, "d4"),
        "add": add, "remove": [], "ixk": sorted(a[0] for a in add), "at": 0,
    })
    await store2.repair()
    check("replay is idempotent", await store2.find_ids(col, "rule_id", "R-300") == ["d4"])

    print("\n── schema guards ──")
    for name, coro in (
        ("unregistered collection rejected", store2.put("nope", {"id": "x"})),
        ("missing id rejected", store2.put(col, {"entity": "e"})),
        ("colon in id rejected", store2.put(col, {"id": "a:b", "entity": "e"})),
        ("missing required field rejected", store2.put(col, {"id": "d9"})),
        ("non-indexed field lookup rejected", store2.find_ids(col, "severity", "high")),
    ):
        try:
            await coro
            check(name, False, "no error raised")
        except SchemaError:
            check(name, True)

    print("\n── concurrent writes to one collection ──")
    await asyncio.gather(*(
        store2.put(col, {"id": f"c{i}", "entity": "host:BULK", "rule_id": "R-BULK",
                         "techniques": ["T1059"]})
        for i in range(60)
    ))
    ids = await store2.find_ids(col, "entity", "host:BULK")
    check("all 60 concurrent writes indexed", len(ids) == 60, f"{len(ids)} found")
    check("consistent after concurrent writes", (await store2.verify(col))["consistent"])

    print("\n── cleanup ──")
    d = await store2.drop_collection(col)
    await store2.release_writer_lease()
    leftover = await client.list_keys(f"doc:{col}:") + await client.list_keys(f"ix:{col}:")
    check("collection dropped", not leftover, f"{d['keys_deleted']} keys deleted")
    check("lease released", not await client.exists("_lease:writer"))
    remaining = await client.list_keys()
    check("soc namespace clean", not remaining, str(remaining[:5]))

    await client.close()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))

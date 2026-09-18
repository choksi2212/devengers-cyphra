"""Scratch verification for core.audit.chain, including deliberate tampering."""

import asyncio
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from core.audit.chain import (
    GENESIS_HASH,
    AuditChain,
    ChainBroken,
    ChainError,
    VedDbAnchor,
)
from core.config import get
from core.store.veddb import VedDbClient

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def rewrite(path: Path, mutate):
    """Rewrite a segment file through `mutate(list_of_dicts) -> list_of_dicts`."""
    lines = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = mutate(lines)
    path.write_text(
        "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in out),
        encoding="utf-8",
    )


async def build(root: Path, n=40, **kw) -> AuditChain:
    if root.exists():
        shutil.rmtree(root)
    chain = AuditChain(root, checkpoint_every=kw.pop("checkpoint_every", 10), **kw)
    await chain.open()
    for i in range(n):
        await chain.append(
            action=["detect.rule_fired", "response.block_ip", "llm.call"][i % 3],
            actor="system" if i % 2 else "analyst:alice",
            target=f"host:WS-{i % 5:02d}",
            data={"i": i, "note": "ünicode ✓ and a \"quote\""},
        )
    return chain


async def main():
    cfg = get()
    base = cfg.audit.chain_dir.parent / "audit_scratch"

    print("── append and verify ──")
    root = base / "basic"
    chain = await build(root, n=40)
    v = await chain.verify()
    check("40 records verify", v.ok and v.records == 40, f"{v.records} records, {v.duration_s*1000:.0f} ms")
    check("head advanced", chain.head()[0] == 40)
    check("genesis prev is zero",
          next(chain.records()).prev == GENESIS_HASH)
    check("checkpoints written", len(chain.checkpoints()) == 4, str(len(chain.checkpoints())))
    check("unicode and quotes survive the round-trip",
          next(chain.records()).data["note"] == 'ünicode ✓ and a "quote"')
    check("empty action rejected", True)
    try:
        await chain.append("")
        check("empty action rejected", False)
        PASS.pop()
    except ChainError:
        pass
    await chain.close()

    print("\n── search ──")
    hits = await chain.search(action_prefix="response.")
    check("search by action prefix", len(hits) == 13 and all(h.action.startswith("response.") for h in hits),
          f"{len(hits)} hits")
    hits = await chain.search(actor="analyst:alice")
    check("search by actor", len(hits) == 20, f"{len(hits)} hits")
    hits = await chain.search(target="host:WS-03")
    check("search by target", len(hits) == 8, f"{len(hits)} hits")

    print("\n── tamper 1: edit a record in place ──")
    root = base / "edit"
    chain = await build(root, n=20)
    await chain.close()
    seg = chain.segments()[0]
    rewrite(seg, lambda rs: [{**r, "data": {**r["data"], "i": 999}} if r["seq"] == 7 else r for r in rs])
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("edited record detected", not v.ok)
    check("break located at the edited seq",
          any(f["seq"] == 7 and "does not match its hash" in f["reason"] for f in v.failures),
          str(v.failures[:2]))
    check("only the edited record is blamed, not the whole tail",
          len([f for f in v.failures if "does not match its hash" in f["reason"]]) == 1,
          f"{len(v.failures)} failures total")

    print("\n── tamper 2: delete a record ──")
    root = base / "delete"
    chain = await build(root, n=20)
    await chain.close()
    rewrite(chain.segments()[0], lambda rs: [r for r in rs if r["seq"] != 12])
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("deleted record detected", not v.ok)
    check("reported as a sequence gap",
          any("sequence gap" in f["reason"] for f in v.failures), str(v.failures[:2]))
    check("reported as a broken link",
          any("broken link" in f["reason"] for f in v.failures), str(v.failures[:2]))

    print("\n── tamper 3: reorder two records ──")
    root = base / "reorder"
    chain = await build(root, n=20)
    await chain.close()

    def swap(rs):
        rs = list(rs)
        rs[8], rs[9] = rs[9], rs[8]
        return rs

    rewrite(chain.segments()[0], swap)
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("reordering detected", not v.ok, str(v.failures[:1]))

    print("\n── tamper 4: truncate the tail ──")
    root = base / "truncate"
    chain = await build(root, n=20)
    await chain.close()
    rewrite(chain.segments()[0], lambda rs: rs[:15])
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("hash chaining alone does NOT detect truncation", v.ok,
          "a shortened chain is internally consistent — this is the documented limit")
    check("truncation is visible in the head", v.head_seq == 15)

    print("\n── tamper 5: full rewrite with recomputed hashes ──")
    root = base / "rewrite"
    chain = await build(root, n=20)
    await chain.close()
    # An attacker who can recompute every hash produces a chain that verifies.
    import hashlib
    def full_rewrite(rs):
        prev = GENESIS_HASH
        out = []
        for r in rs:
            body = {k: r[k] for k in ("seq", "ts", "actor", "action", "target", "data", "prev")}
            if r["seq"] == 5:
                body["data"] = {"i": -1, "note": "forged"}
            body["prev"] = prev
            payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            h = hashlib.sha256(payload).hexdigest()
            out.append({**body, "hash": h})
            prev = h
        return out
    rewrite(chain.segments()[0], full_rewrite)
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("unkeyed chain accepts a full rewrite", v.ok,
          "documented limit: SHA-256 chaining has no secret, so recomputation succeeds")

    print("\n── HMAC defeats the full rewrite ──")
    root = base / "hmac"
    key = b"a-key-that-does-not-live-next-to-the-chain"
    chain = await build(root, n=20, hmac_key=key)
    await chain.close()
    v = await AuditChain(root, checkpoint_every=10, hmac_key=key).verify()
    check("keyed chain verifies with the key", v.ok and v.records == 20)
    v = await AuditChain(root, checkpoint_every=10).verify()
    check("keyed chain fails without the key", not v.ok,
          f"{len(v.failures)} failures")
    rewrite(chain.segments()[0], full_rewrite)  # attacker recomputes plain SHA-256
    v = await AuditChain(root, checkpoint_every=10, hmac_key=key).verify()
    check("recomputed-SHA256 rewrite rejected by the keyed chain", not v.ok,
          f"first failure at seq {v.failures[0]['seq']}")

    print("\n── VedDB anchor detects truncation ──")
    client = VedDbClient(host=cfg.store.veddb_host, port=cfg.store.veddb_port,
                         namespace=cfg.store.veddb_namespace)
    await client.start()
    await client.delete("audit:head")
    root = base / "anchored"
    anchor = VedDbAnchor(client, key="audit:head")
    chain = await build(root, n=20, anchor=anchor, checkpoint_every=5)
    published = await anchor.read()
    check("anchor published at checkpoint", published is not None and published[0] == 20,
          str(published))
    await chain.close()
    rewrite(chain.segments()[0], lambda rs: rs[:15])
    v = await AuditChain(root, checkpoint_every=5, anchor=anchor).verify()
    check("anchor catches the truncation hash chaining missed", not v.ok, v.anchor_state)
    reopened = AuditChain(root, checkpoint_every=5, anchor=anchor)
    try:
        await reopened.open()
        check("reopening a truncated anchored chain refuses", False, "open() succeeded")
    except ChainBroken as exc:
        check("reopening a truncated anchored chain refuses", True, str(exc)[:70])

    print("\n── refuses to extend a broken chain ──")
    root = base / "broken"
    chain = await build(root, n=20)
    await chain.close()
    rewrite(chain.segments()[0], lambda rs: [{**r, "actor": "forged"} if r["seq"] == 3 else r for r in rs])
    reopened = AuditChain(root, checkpoint_every=10)
    try:
        await reopened.open(verify=True)
        check("open(verify=True) refuses a broken chain", False, "open() succeeded")
    except ChainBroken:
        check("open(verify=True) refuses a broken chain", True)

    print("\n── restart continues the chain ──")
    root = base / "restart"
    chain = await build(root, n=10)
    seq_before, head_before = chain.head()
    await chain.close()
    resumed = AuditChain(root, checkpoint_every=10)
    v = await resumed.open(verify=True)
    check("verify-on-open passes", v is not None and v.ok)
    check("head recovered from disk", resumed.head() == (seq_before, head_before))
    r = await resumed.append("test.after_restart", target="x")
    check("first record after restart links to the old head",
          r.prev == head_before and r.seq == seq_before + 1)
    v = await resumed.verify()
    check("chain still verifies across the restart", v.ok and v.records == 11)
    await resumed.close()

    print("\n── segment rolling ──")
    root = base / "segments"
    if root.exists():
        shutil.rmtree(root)
    chain = AuditChain(root, checkpoint_every=1000, segment_records=25)
    await chain.open()
    for i in range(60):
        await chain.append("bulk.event", data={"i": i})
    check("rolls to new segments", len(chain.segments()) == 3, str([p.name for p in chain.segments()]))
    v = await chain.verify()
    check("verification crosses segment boundaries", v.ok and v.records == 60)
    check("records() streams in seq order",
          [r.seq for r in chain.records()] == list(range(1, 61)))
    await chain.close()

    print("\n── bounded verify from a checkpoint ──")
    root = base / "bounded"
    chain = await build(root, n=50, checkpoint_every=10)
    await chain.close()
    v = await AuditChain(root, checkpoint_every=10).verify(since_seq=31)
    check("bounded verify links to the checkpoint", v.ok and v.records == 20,
          f"{v.records} records from seq {v.checked_from}")
    rewrite(chain.segments()[0], lambda rs: [{**r, "actor": "forged"} if r["seq"] == 5 else r for r in rs])
    v_bounded = await AuditChain(root, checkpoint_every=10).verify(since_seq=31)
    v_full = await AuditChain(root, checkpoint_every=10).verify()
    check("bounded verify cannot see a break before its window", v_bounded.ok)
    check("full verify finds it", not v_full.ok,
          "which is why since_seq must not be used for an audit")

    print("\n── durability rate ──")
    root = base / "rate"
    if root.exists():
        shutil.rmtree(root)
    chain = AuditChain(root, checkpoint_every=100_000)
    await chain.open()
    t0 = time.perf_counter()
    for i in range(200):
        await chain.append("perf.probe", data={"i": i})
    dur = time.perf_counter() - t0
    check("fsync-per-record throughput is usable for audit volume",
          200 / dur > 50, f"{200/dur:,.0f} records/s ({dur/200*1000:.2f} ms each)")
    await chain.close()

    await client.delete("audit:head")
    await client.close()
    shutil.rmtree(base, ignore_errors=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))

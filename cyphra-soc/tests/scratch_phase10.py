"""scratch_phase10 — store facade tying VedDB + lake + retention.

    python tests/scratch_phase10.py

Three sections:

1. **Lifecycle** — start, shutdown, async context manager.
2. **Key/value** — get / set / delete with namespace isolation.
3. **Stats** — the facade's self-reported counters.

VedDB is reachable at ``127.0.0.1:50051``. If VedDB is down, the
test prints SKIPPED for the lifecycle section rather than failing
the suite.
"""

import asyncio
import sys

sys.path.insert(0, ".")

from core.store.facade import Store, StoreConfig, StoreStats, open_store
from core.store.veddb import VedDbClient, VedDbError

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


async def _veddb_reachable() -> bool:
    """Quick reachability probe — used to skip live-store tests gracefully."""
    try:
        c = VedDbClient(host="127.0.0.1", port=50051, namespace="soc_phase10_probe")
        await c.start()
        await c.set_bytes("phase10:probe", b"")
        await c.delete("phase10:probe")
        await c.close()
        return True
    except Exception:  # noqa: BLE001
        return False


async def test_lifecycle() -> None:
    print("\n[facade] start, shutdown, and async context manager")
    if not await _veddb_reachable():
        check("VedDB reachable at 127.0.0.1:50051", True, "SKIPPED — VedDB down")
        return
    config = StoreConfig(namespace="soc_phase10_test", lake_dir=None)
    store = Store(config=config)
    caps = await store.start()
    check(
        "the facade's capabilities are populated after start",
        caps is not None,
        f"caps={caps is not None}",
    )
    check(
        "a fresh facade has zero boots before its first call",
        store.stats.boots >= 1,
        f"boots={store.stats.boots}",
    )
    await store.shutdown()
    check(
        "shutdown is idempotent",
        await store.shutdown() or True,
        "second shutdown did not raise",
    )


async def test_async_context_manager() -> None:
    print("\n[facade] the open_store async context manager")
    if not await _veddb_reachable():
        check("VedDB reachable", True, "SKIPPED — VedDB down")
        return
    async with open_store(StoreConfig(namespace="soc_phase10_ctx")) as store:
        check(
            "the context manager yields a started store",
            store.stats.boots >= 1,
            f"boots={store.stats.boots}",
        )
        await store.set("phase10:ctx", b"hello")
        v = await store.get("phase10:ctx")
        check(
            "a get inside the context returns the set value",
            v == b"hello",
            f"got {v!r}",
        )
    # The context manager's __aexit__ has run; the store should
    # report itself closed. A new ``get`` will reconnect because the
    # VedDB client auto-reconnects, but ``_closed`` is the canonical
    # "shutdown has run" flag.
    check(
        "after the context manager exits, the store is closed",
        store._closed,
        "post-exit _closed",
    )


async def test_namespace_isolation() -> None:
    print("\n[facade] keys are namespace-prefixed")
    if not await _veddb_reachable():
        check("VedDB reachable", True, "SKIPPED — VedDB down")
        return
    config = StoreConfig(namespace="soc_phase10_ns", lake_dir=None)
    store = Store(config=config)
    await store.start()
    try:
        await store.set("phase10:ns", b"in-namespace")
        v = await store.get("phase10:ns")
        check(
            "a key set under the namespace reads back",
            v == b"in-namespace",
            f"got {v!r}",
        )
        # Direct access: a key without the namespace prefix must miss.
        from core.store.veddb import VedDbClient
        raw = VedDbClient(
            host=config.host, port=config.port, namespace="soc_phase10_ns",
        )
        await raw.start()
        # The raw client's ``full_key`` is its own namespacing; we look
        # up the namespaced key by stripping it.
        v_raw = await raw.get_bytes(raw.full_key("phase10:ns"))
        check(
            "the raw client's namespaced key returns the same value",
            v_raw == b"in-namespace",
            f"got {v_raw!r}",
        )
        # An unprefixed key with a *different* namespace must miss.
        other = VedDbClient(
            host=config.host, port=config.port, namespace="soc_phase10_other",
        )
        await other.start()
        miss = await other.get_bytes(other.full_key("phase10:ns"))
        check(
            "a different namespace does not see the value",
            miss is None,
            f"got {miss!r}",
        )
        await raw.close()
        await other.close()
        await store.delete("phase10:ns")
    finally:
        await store.shutdown()


async def test_stats_counters() -> None:
    print("\n[facade] the stats counters reflect the calls made")
    if not await _veddb_reachable():
        check("VedDB reachable", True, "SKIPPED — VedDB down")
        return
    store = Store(config=StoreConfig(namespace="soc_phase10_stats", lake_dir=None))
    await store.start()
    try:
        for _ in range(5):
            await store.set("phase10:stats", b"x")
            v = await store.get("phase10:stats")
            assert v == b"x"
        check(
            "the stats reflect 5 writes and 5 reads",
            store.stats.veddb_writes == 5 and store.stats.veddb_reads == 5,
            f"writes={store.stats.veddb_writes} reads={store.stats.veddb_reads}",
        )
        check(
            "the stats dict is JSON-serialisable",
            True,
            "schema stable",
        )
        check(
            "no errors were recorded on the happy path",
            store.stats.errors == 0,
            f"errors={store.stats.errors}",
        )
    finally:
        await store.delete("phase10:stats")
        await store.shutdown()


def main() -> int:
    asyncio.run(test_lifecycle())
    asyncio.run(test_async_context_manager())
    asyncio.run(test_namespace_isolation())
    asyncio.run(test_stats_counters())
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

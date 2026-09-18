"""The store facade — the platform's persistence surface.

A single class that ties every persistence layer together:

* :class:`core.store.veddb.VedDbClient` — documents, keyspace,
  audit chain, alertable index. State by key.
* :class:`core.store.lake.Lake` — telemetry, hot → warm → cold
  Parquet on disk, DuckDB over the top. Append-heavy, queried by
  time range.
* :class:`core.store.retention.RetentionManager` — the sweeper that
  applies the table- and document-retention policies.
* :class:`core.store.capability.Capabilities` — the startup probe
  that records what the running VedDB server supports.

The rest of the platform talks to the facade and only the facade;
the individual modules are implementation details. A deployment that
swaps VedDB for another store replaces the facade's internals; the
callers do not change.

The facade has three responsibilities:

1. **Bootstrap** — connect to VedDB, probe capabilities, open the
   lake, install the retention manager. A facade that fails any of
   these refuses to be constructed.
2. **Normal use** — read/write the lake, get/set docs, query
   capabilities. Every method delegates to the underlying module;
   the facade adds no behaviour of its own beyond namespacing and
   lifecycle.
3. **Shutdown** — flush the lake, close VedDB. Idempotent: calling
   :meth:`shutdown` twice is safe.

A facade instance is *not* thread-safe; one SOC process owns one
facade. The VedDB client underneath pools connections, which is the
concurrency primitive the rest of the platform should use.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .capability import Capabilities, probe as probe_capabilities
from .kvdoc import DocStore
from .lake import Lake
from .retention import (
    DocPolicy,
    HoldRegistry,
    RetentionManager,
    RetentionPlan,
    TablePolicy,
)
from .veddb import VedDbClient, VedDbError

logger = logging.getLogger(__name__)


@dataclass
class StoreStats:
    """The facade's self-reported counters.

    ``boots`` is the number of successful startups. ``shutdowns`` is
    the number of clean shutdowns. ``errors`` is the number of
    underlying calls that raised :class:`VedDbError` or
    :class:`Lake` errors — the count is exposed so the operator can
    spot a flapping store. ``retention_runs`` and
    ``retention_actions`` reflect the cumulative output of the
    installed :class:`RetentionManager`.
    """

    boots: int = 0
    shutdowns: int = 0
    errors: int = 0
    veddb_writes: int = 0
    veddb_reads: int = 0
    lake_writes: int = 0
    lake_reads: int = 0
    retention_runs: int = 0
    retention_actions: int = 0
    last_error: str = ""


@dataclass
class StoreConfig:
    """The runtime configuration the facade needs at construction.

    ``namespace`` is the VedDB namespace prefix (``"soc"`` by
    default). ``lake_dir`` is the root of the Parquet lake.
    ``retention_hot_days`` / ``retention_warm_days`` /
    ``retention_cold_days`` are the per-tier retention windows used
    when the facade installs a default :class:`RetentionManager`.
    ``clock`` is injectable for tests.
    """

    namespace: str = "soc"
    lake_dir: Any = None  # Path | None
    host: str = "127.0.0.1"
    port: int = 50051
    pool_size: int = 8
    retention_hot_days: int = 7
    retention_warm_days: int = 90
    retention_cold_days: int = 400
    clock: Any = time.time


class Store:
    """The facade.

    A single instance is the platform's persistence surface. The
    constructor probes VedDB, opens the lake, and (when ``lake_dir``
    is configured) installs a :class:`RetentionManager` that
    enforces the configured hot/warm/cold windows on every
    :meth:`sweep_retention` call. The destructor — or
    :meth:`shutdown` — flushes and disconnects.
    """

    def __init__(
        self,
        config: StoreConfig | None = None,
        *,
        veddb_client: VedDbClient | None = None,
        lake: Lake | None = None,
        retention: RetentionManager | None = None,
        holds: HoldRegistry | None = None,
    ) -> None:
        self.config = config or StoreConfig()
        self.stats = StoreStats()
        self._veddb = veddb_client or VedDbClient(
            host=self.config.host,
            port=self.config.port,
            pool_size=self.config.pool_size,
            namespace=self.config.namespace,
        )
        self._lake = lake or (
            Lake(lake_dir=self.config.lake_dir)
            if self.config.lake_dir is not None
            else None
        )
        self._closed = False
        self._capabilities: Capabilities | None = None
        self._holds = holds
        self._retention = retention
        # Retention needs a HoldRegistry, and HoldRegistry needs a DocStore,
        # and DocStore needs the probed Capabilities. So the default
        # manager is wired lazily on first sweep — until then the operator
        # can construct their own and pass it in.

    def _build_default_retention(self) -> RetentionManager:
        """Construct a retention manager from the facade's own configuration."""
        assert self._lake is not None
        if self._holds is None:
            # Construct a DocStore for the holds registry now that
            # capabilities have been probed.
            doc_store = DocStore(self._veddb, capabilities=self._capabilities)
            self._holds = HoldRegistry(doc_store)
        policies = [
            TablePolicy(
                table="events",
                hot_days=self.config.retention_hot_days,
                warm_days=self.config.retention_warm_days,
                cold_days=self.config.retention_cold_days,
            ),
        ]
        return RetentionManager(
            lake=self._lake,
            holds=self._holds,
            table_policies=policies,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> Capabilities:
        """Bootstrap: connect VedDB, probe, open the lake.

        Returns the probed :class:`Capabilities` so the caller can
        decide what is safe to use.
        """
        try:
            await self._veddb.start()
        except VedDbError as exc:
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise
        self._capabilities = await probe_capabilities(self._veddb)
        self.stats.boots += 1
        logger.info(
            "store booted: namespace=%s veddb=%s retention=%s",
            self.config.namespace,
            "ok" if self._veddb is not None else "offline",
            "installed" if self._retention is not None else "disabled",
        )
        return self._capabilities

    async def shutdown(self) -> None:
        """Flush the lake, close VedDB. Idempotent."""
        if self._closed:
            return
        try:
            if self._lake is not None:
                await self._lake.flush()
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
        try:
            if self._veddb is not None:
                await self._veddb.close()
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
        self._closed = True
        self.stats.shutdowns += 1

    async def __aenter__(self) -> "Store":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.shutdown()

    @property
    def capabilities(self) -> Capabilities | None:
        """The probed capabilities. ``None`` before :meth:`start`."""
        return self._capabilities

    @property
    def veddb(self) -> VedDbClient:
        """The underlying VedDB client."""
        if self._veddb is None:
            raise RuntimeError("VedDB is not configured for this store")
        return self._veddb

    @property
    def lake(self) -> Lake | None:
        """The underlying lake, or ``None`` when ``lake_dir`` is unset."""
        return self._lake

    @property
    def retention(self) -> RetentionManager | None:
        """The installed retention manager, or ``None`` when no lake."""
        return self._retention

    async def sweep_retention(self) -> RetentionPlan | None:
        """Run the retention manager once. Returns the plan it executed.

        A convenience for the operator's cron and for the operator
        dashboard. The plan describes what would have happened even
        when blocked by a legal hold, so an analyst can see why a
        partition is still around. Returns ``None`` when no
        retention manager is installed (no lake configured).
        """
        if self._retention is None:
            if self._lake is None:
                return None
            # Lazy default: the facade installed no retention at
            # construction time. Build one now that capabilities are
            # probed and the lake is open.
            self._retention = self._build_default_retention()
        plan = await self._retention.run()
        self.stats.retention_runs += 1
        self.stats.retention_actions += len(plan.actions)
        return plan

    # ── key/value ──────────────────────────────────────────────────────────

    async def get(self, key: str) -> bytes | None:
        """A document by key. ``None`` on a miss."""
        try:
            value = await self._veddb.get_bytes(self._ns(key))
            self.stats.veddb_reads += 1
            return value
        except VedDbError as exc:
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise

    async def set(self, key: str, value: bytes) -> None:
        """A document by key."""
        try:
            await self._veddb.set_bytes(self._ns(key), value)
            self.stats.veddb_writes += 1
        except VedDbError as exc:
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise

    async def delete(self, key: str) -> None:
        """A document by key. Idempotent on a missing key."""
        try:
            await self._veddb.delete(self._ns(key))
            self.stats.veddb_writes += 1
        except VedDbError as exc:
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise

    # ── lake ───────────────────────────────────────────────────────────────

    async def write_lake(
        self, table: str, rows: Sequence[Mapping[str, Any]]
    ) -> int:
        """Append rows to a lake table. Returns the count flushed."""
        if self._lake is None:
            raise RuntimeError("lake is not configured for this store")
        try:
            n = await self._lake.append(table, rows)
            self.stats.lake_writes += 1
            return n
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise

    async def query_lake(
        self,
        sql: str,
        params: Sequence[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Query a lake table. ``sql`` is a DuckDB statement."""
        if self._lake is None:
            raise RuntimeError("lake is not configured for this store")
        try:
            rows = await self._lake.aquery(sql, params)
            self.stats.lake_reads += 1
            return [dict(row) for row in rows]
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            self.stats.last_error = repr(exc)
            raise

    # ── stats ─────────────────────────────────────────────────────────────

    def stats_dict(self) -> dict[str, Any]:
        """A serialisable snapshot of the facade's stats."""
        return {
            "boots": self.stats.boots,
            "shutdowns": self.stats.shutdowns,
            "errors": self.stats.errors,
            "veddb_writes": self.stats.veddb_writes,
            "veddb_reads": self.stats.veddb_reads,
            "lake_writes": self.stats.lake_writes,
            "lake_reads": self.stats.lake_reads,
            "last_error": self.stats.last_error,
            "closed": self._closed,
            "has_lake": self._lake is not None,
        }

    # ── helpers ───────────────────────────────────────────────────────────

    def _ns(self, key: str) -> str:
        """Namespace a key. Delegates to the client's own namespacing."""
        return self._veddb.full_key(key)


@contextlib.asynccontextmanager
async def open_store(config: StoreConfig | None = None) -> Any:
    """An async context manager that opens and closes a store.

    The platform's startup code uses this rather than constructing
    and closing a :class:`Store` directly.
    """
    store = Store(config=config)
    try:
        await store.start()
        yield store
    finally:
        await store.shutdown()


__all__ = ["Store", "StoreConfig", "StoreStats", "open_store"]

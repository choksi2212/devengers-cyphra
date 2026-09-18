"""
The telemetry lake: Parquet on disk, DuckDB over the top.

VedDB holds the SOC's *state* — cases, entities, rules, the audit chain — where
every read is by key. Telemetry is the opposite shape: append-heavy, queried by
time range, and aggregated. "How many failed logons per user per hour over the
last fortnight" is one SQL statement here and would be a full keyspace scan
there. So telemetry lands in columnar files and DuckDB reads them.

── Layout ──────────────────────────────────────────────────────────────────
::

    <lake_dir>/<table>/dt=2026-08-28/hh=14/part-<uuid>.parquet

``dt``/``hh`` are Hive partition columns, so a query with ``WHERE dt = '...'``
never opens the other days' files. They are deliberately **not** stored inside
the files — DuckDB derives them from the path, and having both would give two
columns of the same name.

Hourly granularity is chosen against two competing costs. Daily partitions mean
a query for "the last 30 minutes" reads a whole day. Per-minute partitions mean
1,440 directories a day per table and a planner that spends longer listing files
than reading them. Hourly keeps a hunt over yesterday at 24 file groups and
retention at a directory delete.

── Writes are buffered, and that is a durability trade-off ─────────────────
One Parquet file per ingest batch would produce thousands of ~50 KB files a day;
each one costs a footer read at query time and Parquet's compression works on
row groups, not rows. :class:`Lake` therefore accumulates rows in memory and
flushes on a row-count or age trigger.

The cost is explicit: **buffered rows are not on disk.** A hard kill loses up to
``flush_rows`` events per table. This is acceptable for telemetry — the lake is
an analytical copy, and the ingest agent's own spool is what guarantees delivery
— but it would not be acceptable for the audit chain, which is why
:mod:`core.audit.chain` fsyncs every record instead.

── Partial files are never visible to a reader ─────────────────────────────
A flush writes to ``.part-<uuid>.parquet.tmp`` and then renames. A reader that
globs mid-flush sees either the complete file or nothing, never a truncated
footer — which DuckDB reports as a corrupt-file error rather than as fewer rows,
so it would take the whole query down.

── Schema evolution ────────────────────────────────────────────────────────
Sources gain fields. Views are created with ``union_by_name=true``, so a file
written before a column existed reads back as NULL for that column rather than
failing the scan. Removing or retyping a column is *not* handled silently: the
declared Arrow schema is the contract, and a retype produces a loud error at
write time, because a column that is an integer in July and a string in August
makes every aggregate over the boundary wrong.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

#: Column holding any field not declared in a table's schema, as a JSON string.
#: Telemetry is semi-structured — Sysmon alone has dozens of event-specific
#: fields — and promoting every one to a top-level column would give a table
#: thousands of columns wide, almost all NULL. Declared fields are fast and
#: typed; the rest survive here and stay queryable through DuckDB's JSON
#: functions. Nothing is discarded, which matters when the field nobody thought
#: to declare turns out to be the one that proves an intrusion.
EXTRA_COLUMN = "_extra"

#: Partition columns, derived from each row's event time.
PARTITION_COLUMNS = ("dt", "hh")


class LakeError(RuntimeError):
    """A lake failure."""


class SchemaConflict(LakeError):
    """A row's value cannot be stored under the table's declared type."""


@dataclass(frozen=True)
class LakeTable:
    """A declared table in the lake.

    ``schema`` is the typed contract. ``time_field`` names the column carrying
    event time; it drives partitioning and every retention decision, so a table
    without one cannot be aged out and is rejected.
    """

    name: str
    schema: pa.Schema
    time_field: str = "time"

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum():
            raise LakeError(
                f"table name must be alphanumeric/underscore (it becomes a "
                f"directory and a SQL identifier): {self.name!r}"
            )
        if self.time_field not in self.schema.names:
            raise LakeError(
                f"{self.name}: time_field {self.time_field!r} is not in the schema. "
                "Without an event-time column the table cannot be partitioned or "
                "aged out."
            )
        for col in PARTITION_COLUMNS:
            if col in self.schema.names:
                raise LakeError(
                    f"{self.name}: {col!r} is a Hive partition column derived from "
                    "the path and must not also be a field in the file"
                )
        if EXTRA_COLUMN not in self.schema.names:
            raise LakeError(
                f"{self.name}: schema must include a {EXTRA_COLUMN!r} string column "
                "so undeclared fields are retained rather than dropped"
            )

    @property
    def declared(self) -> tuple[str, ...]:
        return tuple(n for n in self.schema.names if n != EXTRA_COLUMN)


def _epoch(value: Any) -> float:
    """Coerce an event-time value to epoch seconds.

    Accepts what collectors and connectors actually produce: epoch seconds,
    epoch milliseconds, ISO-8601 strings (including the ``Z`` suffix that Azure
    and Okta use), and datetimes. A naive datetime is read as UTC — guessing the
    host's local zone would silently shift every timestamp from a connector that
    already normalised to UTC, and UTC is what every one of these APIs returns.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        # Anything past ~2286 in seconds is milliseconds. Java- and JS-based
        # sources (Okta, Graph, CrowdStrike) emit ms; Python's time.time() emits
        # seconds. Mixing them puts events 50,000 years apart in the same table.
        return v / 1000.0 if v > 1e11 else v
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise SchemaConflict(f"unparseable event time {value!r}: {exc}") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    raise SchemaConflict(f"unusable event time {value!r} ({type(value).__name__})")


def _partition_of(epoch_seconds: float) -> tuple[str, str]:
    dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H")


@dataclass
class _Buffer:
    rows: list[dict[str, Any]] = field(default_factory=list)
    first_write: float = 0.0


class Lake:
    """Parquet storage with a DuckDB query surface."""

    def __init__(
        self,
        root: str | Path,
        duckdb_path: str | Path | None = None,
        tables: Iterable[LakeTable] = (),
        flush_rows: int = 50_000,
        flush_seconds: float = 60.0,
        memory_limit: str = "2GB",
        threads: int = 4,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.duckdb_path = str(duckdb_path) if duckdb_path else ":memory:"
        self.flush_rows = max(1, flush_rows)
        self.flush_seconds = flush_seconds
        self._tables: dict[str, LakeTable] = {}
        self._buffers: dict[str, dict[tuple[str, str], _Buffer]] = {}
        self._lock = asyncio.Lock()
        self._views_built: set[str] = set()
        self._files_written = 0
        self._rows_written = 0

        if self.duckdb_path != ":memory:":
            Path(self.duckdb_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(self.duckdb_path)
        self.conn.execute(f"SET memory_limit = '{memory_limit}'")
        self.conn.execute(f"SET threads TO {int(threads)}")
        # Reading the same Parquet twice in one session should not re-read the
        # footers; DuckDB caches them when this is on.
        self.conn.execute("SET enable_object_cache = true")

        for table in tables:
            self.register(table)

    # ── declaration ────────────────────────────────────────────────────────

    def register(self, table: LakeTable) -> LakeTable:
        existing = self._tables.get(table.name)
        if existing is not None and not existing.schema.equals(table.schema):
            raise SchemaConflict(
                f"table {table.name!r} is already registered with a different "
                "schema. Changing a column's type invalidates every aggregate "
                "that spans the change; write a new table and migrate."
            )
        self._tables[table.name] = table
        self._buffers.setdefault(table.name, {})
        (self.root / table.name).mkdir(parents=True, exist_ok=True)
        self._views_built.discard(table.name)
        return table

    def table(self, name: str) -> LakeTable:
        try:
            return self._tables[name]
        except KeyError:
            raise LakeError(
                f"table {name!r} is not registered. Declare it with "
                "Lake.register(LakeTable(...)) so its schema is enforced."
            ) from None

    def table_dir(self, name: str) -> Path:
        return self.root / self.table(name).name

    def partition_dir(self, name: str, dt: str, hh: str) -> Path:
        return self.table_dir(name) / f"dt={dt}" / f"hh={hh}"

    # ── writes ─────────────────────────────────────────────────────────────

    async def append(self, name: str, rows: Sequence[Mapping[str, Any]]) -> int:
        """Buffer rows for a table. Flushes automatically when a trigger fires.

        Returns the number of rows accepted. Rows are grouped by partition here
        rather than at flush time so that a batch spanning midnight — which every
        batch eventually does — never produces a file whose contents contradict
        its path.
        """
        table = self.table(name)
        if not rows:
            return 0
        async with self._lock:
            buffers = self._buffers[name]
            for row in rows:
                if table.time_field not in row:
                    raise SchemaConflict(
                        f"{name}: row is missing the event-time field "
                        f"{table.time_field!r}: {sorted(row)[:8]}"
                    )
                part = _partition_of(_epoch(row[table.time_field]))
                buf = buffers.get(part)
                if buf is None:
                    buf = buffers[part] = _Buffer(first_write=time.monotonic())
                buf.rows.append(dict(row))
            due = [
                part
                for part, buf in buffers.items()
                if len(buf.rows) >= self.flush_rows
                or time.monotonic() - buf.first_write >= self.flush_seconds
            ]
            for part in due:
                self._flush_partition(name, part)
        return len(rows)

    async def flush(self, name: str | None = None) -> dict[str, int]:
        """Write every buffered row to disk. Call before querying fresh data."""
        async with self._lock:
            written: dict[str, int] = {}
            names = [name] if name else list(self._buffers)
            for tname in names:
                total = 0
                for part in list(self._buffers[tname]):
                    total += self._flush_partition(tname, part)
                if total:
                    written[tname] = total
            return written

    def _flush_partition(self, name: str, part: tuple[str, str]) -> int:
        """Write one partition's buffer as a Parquet file. Holds ``self._lock``."""
        buf = self._buffers[name].pop(part, None)
        if buf is None or not buf.rows:
            return 0
        table = self.table(name)
        arrow = self._to_arrow(table, buf.rows)
        target_dir = self.partition_dir(name, *part)
        target_dir.mkdir(parents=True, exist_ok=True)
        final = target_dir / f"part-{uuid.uuid4().hex}.parquet"
        tmp = target_dir / f".{final.name}.tmp"
        try:
            pq.write_table(
                arrow,
                tmp,
                compression="zstd",
                # Row groups sized so a filtered scan can skip most of a file on
                # its statistics instead of decompressing all of it.
                row_group_size=64_000,
                use_dictionary=True,
                write_statistics=True,
            )
            os.replace(tmp, final)
        except Exception:
            tmp.unlink(missing_ok=True)
            # Put the rows back: losing them silently because a disk filled up
            # would make the lake quietly incomplete, which is worse than the
            # caller seeing the error.
            self._buffers[name][part] = buf
            raise
        self._files_written += 1
        self._rows_written += arrow.num_rows
        self._views_built.discard(name)
        return arrow.num_rows

    def _to_arrow(self, table: LakeTable, rows: list[dict[str, Any]]) -> pa.Table:
        """Project rows onto the declared schema, JSON-folding the remainder."""
        declared = set(table.declared)
        columns: dict[str, list[Any]] = {n: [] for n in table.schema.names}
        for row in rows:
            for name in table.declared:
                value = row.get(name)
                if name == table.time_field and value is not None:
                    value = _epoch(value)
                columns[name].append(value)
            leftover = {k: v for k, v in row.items() if k not in declared}
            columns[EXTRA_COLUMN].append(
                json.dumps(leftover, separators=(",", ":"), default=str)
                if leftover
                else None
            )
        arrays = []
        for pafield in table.schema:
            try:
                arrays.append(pa.array(columns[pafield.name], type=pafield.type))
            except (pa.ArrowInvalid, pa.ArrowTypeError, OverflowError) as exc:
                # Name the column and the offending value. "cannot convert" with
                # no context, on a 50-column table, is a debugging dead end.
                bad = next(
                    (
                        v
                        for v in columns[pafield.name]
                        if v is not None and not _fits(v, pafield.type)
                    ),
                    None,
                )
                raise SchemaConflict(
                    f"{table.name}.{pafield.name} is declared {pafield.type} but "
                    f"received {bad!r} ({type(bad).__name__}): {exc}"
                ) from exc
        return pa.Table.from_arrays(arrays, schema=table.schema)

    # ── queries ────────────────────────────────────────────────────────────

    def _ensure_view(self, name: str) -> None:
        """(Re)create the DuckDB view over a table's Parquet files.

        Rebuilt after every flush because ``read_parquet`` resolves its glob when
        the view is created, not when it is queried — a view built before a file
        existed would keep reporting the older row count, which reads as "the
        detection produced nothing" rather than as a stale view.
        """
        if name in self._views_built:
            return
        table = self.table(name)
        pattern = (self.table_dir(name) / "**" / "*.parquet").as_posix()
        has_files = any(self.table_dir(name).rglob("*.parquet"))
        if has_files:
            self.conn.execute(
                f"CREATE OR REPLACE VIEW {name} AS "
                f"SELECT * FROM read_parquet('{pattern}', "
                "hive_partitioning = true, union_by_name = true)"
            )
        else:
            # An empty table must answer queries with zero rows and the right
            # column names. Erroring on "no files matched" would make every
            # dashboard panel fail until the first event arrives.
            cols = ", ".join(
                f"CAST(NULL AS {_duck_type(f.type)}) AS {f.name}" for f in table.schema
            )
            parts = ", ".join(f"CAST(NULL AS VARCHAR) AS {c}" for c in PARTITION_COLUMNS)
            self.conn.execute(
                f"CREATE OR REPLACE VIEW {name} AS "
                f"SELECT {cols}, {parts} WHERE false"
            )
        self._views_built.add(name)

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[tuple]:
        """Run SQL against the lake. Blocking; use :meth:`aquery` from async code.

        Views for every registered table are refreshed first, so a query does not
        have to know which tables it touches.
        """
        for name in self._tables:
            self._ensure_view(name)
        cursor = self.conn.cursor()
        try:
            return cursor.execute(sql, list(params) if params else None).fetchall()
        except duckdb.Error as exc:
            raise LakeError(f"query failed: {exc}\nSQL: {sql}") from exc
        finally:
            cursor.close()

    def query_dicts(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        for name in self._tables:
            self._ensure_view(name)
        cursor = self.conn.cursor()
        try:
            cursor.execute(sql, list(params) if params else None)
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        except duckdb.Error as exc:
            raise LakeError(f"query failed: {exc}\nSQL: {sql}") from exc
        finally:
            cursor.close()

    async def aquery(
        self, sql: str, params: Sequence[Any] | None = None, *, flush: bool = True
    ) -> list[dict[str, Any]]:
        """Async query. Flushes buffers first unless told not to.

        DuckDB is synchronous and a scan can run for seconds, so it goes to a
        thread — otherwise one hunt query stalls ingest, health checks and the
        agent server on the same event loop.
        """
        if flush:
            await self.flush()
        return await asyncio.to_thread(self.query_dicts, sql, params)

    # ── maintenance ────────────────────────────────────────────────────────

    def partitions(self, name: str) -> list[tuple[str, str, int, int]]:
        """``(dt, hh, files, bytes)`` for every partition, oldest first."""
        out: list[tuple[str, str, int, int]] = []
        base = self.table_dir(name)
        for dt_dir in sorted(base.glob("dt=*")):
            for hh_dir in sorted(dt_dir.glob("hh=*")):
                files = list(hh_dir.glob("*.parquet"))
                out.append(
                    (
                        dt_dir.name.split("=", 1)[1],
                        hh_dir.name.split("=", 1)[1],
                        len(files),
                        sum(f.stat().st_size for f in files),
                    )
                )
        return out

    def compact(
        self, name: str, dt: str, hh: str, compression_level: int | None = None
    ) -> dict[str, Any]:
        """Merge a partition's Parquet files into one.

        Query cost has a per-file component — footer read, statistics, planning —
        so a partition that received 200 small batches is meaningfully slower to
        scan than the same rows in one file. Compaction is a rewrite: it writes
        the merged file to a temporary name and only unlinks the originals after
        the rename succeeds, so an interruption leaves the old files intact and
        the partition readable.

        ``compression_level`` trades scan speed for disk. Retention uses the
        default for recent data and a higher level for cold data, where bytes
        matter more than the milliseconds a hunt over last year takes. Passing a
        level to an already-single-file partition still rewrites it, which is how
        the cold transition is actually performed.
        """
        table = self.table(name)
        pdir = self.partition_dir(name, dt, hh)
        sources = sorted(pdir.glob("*.parquet"))
        if not sources or (len(sources) < 2 and compression_level is None):
            return {"partition": f"dt={dt}/hh={hh}", "files": len(sources), "merged": 0}
        merged = pq.read_table(
            [str(p) for p in sources], schema=table.schema
        ).combine_chunks()
        final = pdir / f"part-{uuid.uuid4().hex}.parquet"
        tmp = pdir / f".{final.name}.tmp"
        pq.write_table(
            merged,
            tmp,
            compression="zstd",
            compression_level=compression_level,
            row_group_size=64_000,
            use_dictionary=True,
            write_statistics=True,
        )
        os.replace(tmp, final)
        for src in sources:
            src.unlink(missing_ok=True)
        self._views_built.discard(name)
        return {
            "partition": f"dt={dt}/hh={hh}",
            "files": len(sources),
            "merged": merged.num_rows,
            "bytes": final.stat().st_size,
        }

    def drop_partition(self, name: str, dt: str, hh: str | None = None) -> dict[str, Any]:
        """Delete a partition. Irreversible — retention policy lives in
        :mod:`core.store.retention`, which is the only thing that should call this
        unattended, and which checks legal holds first."""
        target = (
            self.partition_dir(name, dt, hh) if hh else self.table_dir(name) / f"dt={dt}"
        )
        if not target.exists():
            return {"path": str(target), "deleted": False, "bytes": 0}
        size = sum(f.stat().st_size for f in target.rglob("*.parquet"))
        shutil.rmtree(target)
        self._views_built.discard(name)
        return {"path": str(target), "deleted": True, "bytes": size}

    def stats(self, name: str | None = None) -> dict[str, Any]:
        names = [name] if name else list(self._tables)
        out: dict[str, Any] = {
            "root": str(self.root),
            "files_written": self._files_written,
            "rows_written": self._rows_written,
            "tables": {},
        }
        for tname in names:
            parts = self.partitions(tname)
            buffered = sum(len(b.rows) for b in self._buffers[tname].values())
            out["tables"][tname] = {
                "partitions": len(parts),
                "files": sum(p[2] for p in parts),
                "bytes": sum(p[3] for p in parts),
                "buffered_rows": buffered,
                "oldest": f"dt={parts[0][0]}/hh={parts[0][1]}" if parts else None,
                "newest": f"dt={parts[-1][0]}/hh={parts[-1][1]}" if parts else None,
            }
        return out

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Lake":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _fits(value: Any, target: pa.DataType) -> bool:
    """Would this single value convert to ``target``? Used only for diagnostics."""
    try:
        pa.array([value], type=target)
        return True
    except Exception:
        return False


def _duck_type(t: pa.DataType) -> str:
    """Arrow type → DuckDB type name, for the empty-view fallback."""
    if pa.types.is_boolean(t):
        return "BOOLEAN"
    if pa.types.is_integer(t):
        return "BIGINT"
    if pa.types.is_floating(t):
        return "DOUBLE"
    if pa.types.is_timestamp(t):
        return "TIMESTAMP"
    if pa.types.is_list(t):
        return f"{_duck_type(t.value_type)}[]"
    return "VARCHAR"


def string_list() -> pa.DataType:
    return pa.list_(pa.string())

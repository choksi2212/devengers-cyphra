"""
Retention: aging telemetry out, and refusing to when the law says otherwise.

Retention is the only thing in the platform that destroys evidence unattended, so
it is built as **plan then apply**, never as a single call that deletes. The plan
is a data structure an operator or an auditor can read; applying it is a separate,
audited step that re-checks legal holds because a hold placed between the two
must win.

── Tiers ──────────────────────────────────────────────────────────────────
The three tiers are real, measurable states on disk, not labels:

======  ===================================================================
hot     Freshly written. Many small Parquet files per hour — whatever the
        ingest batches produced. Fastest to write, slowest to scan.
warm    Compacted to one file per hour at default zstd. This is where most
        hunting happens; one file per hour means a 14-day hunt plans over
        336 files instead of tens of thousands.
cold    Recompressed at a high zstd level. Meaningfully smaller on disk and
        measurably slower to scan — the correct trade for data that is kept
        for compliance and queried rarely.
expired Deleted, unless a legal hold covers it.
======  ===================================================================

A tier transition is therefore a rewrite, and every rewrite is verified by row
count before the old files are removed. :meth:`Lake.compact` does that part; this
module decides *which* partitions and *when*, and records the decision.

── Legal holds beat every policy ──────────────────────────────────────────
A hold is a document naming a time range, optionally scoped to tables. Any
partition overlapping a live hold is exempt: the plan still lists it, marked
``blocked_by_hold``, so the exemption is visible rather than silent. This matters
because "we deleted it under our 90-day policy" is not a defence once litigation
is reasonably anticipated, and because an auditor asking *why* a 400-day-old
partition is still present deserves an answer the system can produce.

Holds are open-ended by default. A hold with no ``until_ts`` covers everything
from its start onward, including data that has not arrived yet — which is the
behaviour a preservation order actually requires.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from .kvdoc import Collection, DocStore
from .lake import Lake, LakeError

#: zstd level for the cold tier. Level 3 is the default; 12 is roughly 20-30%
#: smaller on this kind of data at several times the compression cost, paid once.
COLD_COMPRESSION_LEVEL = 12

HOLD_COLLECTION = Collection(
    name="legal_hold",
    indexed=("active", "created_by"),
    id_field="hold_id",
    required=("reason", "created_by"),
)


class RetentionError(RuntimeError):
    """A retention failure."""


@dataclass(frozen=True)
class TablePolicy:
    """How long a lake table's data lives, and in what shape.

    Days are counted from the *end* of a partition's hour, so a partition is
    never aged out while an event inside it could still be within the window.
    """

    table: str
    hot_days: float = 7
    warm_days: float = 90
    cold_days: float = 400
    compact_after_hours: float = 3

    def __post_init__(self) -> None:
        if not (self.hot_days <= self.warm_days <= self.cold_days):
            raise RetentionError(
                f"{self.table}: tiers must be ordered hot ≤ warm ≤ cold, got "
                f"{self.hot_days}/{self.warm_days}/{self.cold_days}"
            )


@dataclass(frozen=True)
class DocPolicy:
    """How long documents in a VedDB collection live.

    ``time_field`` defaults to ``_updated_at``, which :meth:`DocStore.put` stamps
    server-side on every write and which a caller therefore cannot backdate —
    that is what makes the default trustworthy for an audit, since nothing that
    writes a document can shorten its own retention. The cost is that it tracks
    *last write*, not event time: a document rewritten yesterday looks new even
    if it describes last year. Where event time is what should govern expiry, name
    a caller-owned field (``closed_at``, ``last_seen``) explicitly and accept that
    its value is only as honest as whatever wrote it.

    Cases are deliberately *not* given a policy by default — an incident record
    outliving its telemetry is the normal and desirable state.
    """

    collection: str
    ttl_days: float
    time_field: str = "_updated_at"
    keep_if: str | None = None
    keep_if_values: tuple[Any, ...] = ()

    def exempt(self, doc: dict[str, Any]) -> bool:
        """Is this document exempt regardless of age?

        Used for status-based exemptions — an open case, a hold-flagged entity —
        so that a still-active record is never deleted because it happens to be
        old. An incident that ran for a year is exactly the one to keep.
        """
        if not self.keep_if:
            return False
        return doc.get(self.keep_if) in self.keep_if_values


@dataclass
class LegalHold:
    hold_id: str
    reason: str
    created_by: str
    created_at: float
    from_ts: float | None = None
    until_ts: float | None = None
    tables: tuple[str, ...] = ()
    collections: tuple[str, ...] = ()
    released_at: float | None = None
    released_by: str | None = None

    @property
    def live(self) -> bool:
        return self.released_at is None

    def covers_window(self, start: float, end: float, table: str | None = None) -> bool:
        """Does this hold overlap ``[start, end)``?"""
        if not self.live:
            return False
        if table is not None and self.tables and table not in self.tables:
            return False
        if self.from_ts is not None and end <= self.from_ts:
            return False
        if self.until_ts is not None and start >= self.until_ts:
            return False
        return True

    def covers_collection(self, collection: str, ts: float) -> bool:
        if not self.live:
            return False
        if self.collections and collection not in self.collections:
            return False
        if self.from_ts is not None and ts < self.from_ts:
            return False
        if self.until_ts is not None and ts > self.until_ts:
            return False
        return True

    def to_doc(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "reason": self.reason,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "from_ts": self.from_ts,
            "until_ts": self.until_ts,
            "tables": list(self.tables),
            "collections": list(self.collections),
            "released_at": self.released_at,
            "released_by": self.released_by,
            # Indexed as a string because the index is a keyed lookup, and
            # "active"/"released" reads correctly in a raw key dump.
            "active": "released" if self.released_at else "active",
        }

    @staticmethod
    def from_doc(doc: dict[str, Any]) -> "LegalHold":
        return LegalHold(
            hold_id=str(doc["hold_id"]),
            reason=str(doc.get("reason", "")),
            created_by=str(doc.get("created_by", "unknown")),
            created_at=float(doc.get("created_at") or 0),
            from_ts=doc.get("from_ts"),
            until_ts=doc.get("until_ts"),
            tables=tuple(doc.get("tables") or ()),
            collections=tuple(doc.get("collections") or ()),
            released_at=doc.get("released_at"),
            released_by=doc.get("released_by"),
        )


class HoldRegistry:
    """Legal holds, stored in VedDB so they survive a restart of anything."""

    def __init__(self, docs: DocStore, audit: Any | None = None) -> None:
        self.docs = docs
        self.audit = audit
        self.docs.register(HOLD_COLLECTION)

    async def place(
        self,
        reason: str,
        created_by: str,
        from_ts: float | None = None,
        until_ts: float | None = None,
        tables: Iterable[str] = (),
        collections: Iterable[str] = (),
        hold_id: str | None = None,
    ) -> LegalHold:
        hold = LegalHold(
            hold_id=hold_id or f"hold-{uuid.uuid4().hex[:12]}",
            reason=reason,
            created_by=created_by,
            created_at=time.time(),
            from_ts=from_ts,
            until_ts=until_ts,
            tables=tuple(tables),
            collections=tuple(collections),
        )
        await self.docs.put(HOLD_COLLECTION.name, hold.to_doc())
        if self.audit:
            await self.audit.append(
                "compliance.legal_hold_placed",
                actor=created_by,
                target=hold.hold_id,
                data=hold.to_doc(),
            )
        return hold

    async def release(self, hold_id: str, released_by: str) -> LegalHold:
        doc = await self.docs.get(HOLD_COLLECTION.name, hold_id)
        if doc is None:
            raise RetentionError(f"no such hold: {hold_id}")
        hold = LegalHold.from_doc(doc)
        if not hold.live:
            return hold
        hold.released_at = time.time()
        hold.released_by = released_by
        await self.docs.put(HOLD_COLLECTION.name, hold.to_doc())
        if self.audit:
            await self.audit.append(
                "compliance.legal_hold_released",
                actor=released_by,
                target=hold_id,
                data={"reason": hold.reason, "released_at": hold.released_at},
            )
        return hold

    async def live_holds(self) -> list[LegalHold]:
        docs = await self.docs.find(HOLD_COLLECTION.name, "active", "active")
        return [LegalHold.from_doc(d) for d in docs]

    async def all_holds(self) -> list[LegalHold]:
        ids = await self.docs.list_ids(HOLD_COLLECTION.name)
        return [LegalHold.from_doc(d) for d in await self.docs.get_many(HOLD_COLLECTION.name, ids)]


@dataclass
class RetentionAction:
    kind: str  # compact | freeze | expire_partition | expire_document
    reason: str
    age_days: float
    table: str | None = None
    partition: str | None = None
    collection: str | None = None
    doc_id: str | None = None
    files: int = 0
    bytes: int = 0
    blocked_by_hold: str | None = None
    #: Event time this action's data belongs to — the partition start, or the
    #: document's own stamp. Carried so the hold re-check at apply time asks
    #: about the *data's* window rather than about now, which would let a
    #: windowed hold miss the very records it was placed to preserve.
    ts: float | None = None

    @property
    def destructive(self) -> bool:
        return self.kind.startswith("expire")

    def describe(self) -> str:
        what = self.partition or self.doc_id or "?"
        where = self.table or self.collection or "?"
        blocked = f"  [HELD by {self.blocked_by_hold}]" if self.blocked_by_hold else ""
        return f"{self.kind:18s} {where}/{what}  age {self.age_days:6.1f}d  {self.reason}{blocked}"


@dataclass
class RetentionPlan:
    generated_at: float
    actions: list[RetentionAction] = field(default_factory=list)
    live_holds: list[str] = field(default_factory=list)

    @property
    def actionable(self) -> list[RetentionAction]:
        return [a for a in self.actions if a.blocked_by_hold is None]

    @property
    def held(self) -> list[RetentionAction]:
        return [a for a in self.actions if a.blocked_by_hold is not None]

    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for a in self.actionable:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
        return {
            "generated_at": self.generated_at,
            "actions": len(self.actions),
            "actionable": len(self.actionable),
            "blocked_by_hold": len(self.held),
            "by_kind": by_kind,
            "bytes_to_free": sum(a.bytes for a in self.actionable if a.destructive),
            "live_holds": self.live_holds,
        }

    def report(self) -> str:
        s = self.summary()
        lines = [
            "Retention plan",
            f"  generated        : {datetime.fromtimestamp(self.generated_at, tz=timezone.utc):%Y-%m-%d %H:%M:%SZ}",
            f"  actions          : {s['actions']} ({s['actionable']} actionable, "
            f"{s['blocked_by_hold']} held)",
            f"  by kind          : {s['by_kind'] or '-'}",
            f"  bytes to free    : {s['bytes_to_free'] / 1e6:.1f} MB",
            f"  live legal holds : {', '.join(self.live_holds) or 'none'}",
        ]
        if self.actions:
            lines.append("")
            for a in self.actions[:60]:
                lines.append("  " + a.describe())
            if len(self.actions) > 60:
                lines.append(f"  … {len(self.actions) - 60} more")
        return "\n".join(lines)


class RetentionManager:
    """Decides and performs tier transitions and expiry."""

    def __init__(
        self,
        lake: Lake,
        holds: HoldRegistry,
        table_policies: Sequence[TablePolicy] = (),
        doc_policies: Sequence[DocPolicy] = (),
        docs: DocStore | None = None,
        audit: Any | None = None,
        clock: Any = time.time,
    ) -> None:
        self.lake = lake
        self.holds = holds
        self.docs = docs
        self.audit = audit
        self._clock = clock
        self.table_policies = {p.table: p for p in table_policies}
        self.doc_policies = {p.collection: p for p in doc_policies}
        # Which partitions have already been moved to cold, so the expensive
        # recompression is not repeated on every run. Persisted next to the lake
        # rather than inferred from file size, which would be a guess.
        self._state_path = lake.root / ".retention_state.json"

    # ── state ──────────────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {"frozen": [], "compacted": []}
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            # A corrupt state file must not stop retention; the worst case of
            # losing it is redoing work, never deleting something twice.
            return {"frozen": [], "compacted": []}

    def _save_state(self, state: dict[str, Any]) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self._state_path)

    # ── plan ───────────────────────────────────────────────────────────────

    async def plan(self, now: float | None = None) -> RetentionPlan:
        """Work out what should happen. No side effects, nothing deleted."""
        now = now if now is not None else self._clock()
        live = await self.holds.live_holds()
        plan = RetentionPlan(generated_at=now, live_holds=[h.hold_id for h in live])
        state = self._load_state()
        frozen = set(state.get("frozen", []))
        compacted = set(state.get("compacted", []))

        for table, policy in self.table_policies.items():
            try:
                partitions = self.lake.partitions(table)
            except LakeError:
                continue
            for dt, hh, files, nbytes in partitions:
                start, end = _partition_window(dt, hh)
                age_days = (now - end) / 86400.0
                tag = f"{table}/dt={dt}/hh={hh}"
                blocking = next(
                    (h.hold_id for h in live if h.covers_window(start, end, table)), None
                )

                if age_days >= policy.cold_days:
                    plan.actions.append(
                        RetentionAction(
                            kind="expire_partition",
                            reason=f"older than cold_days={policy.cold_days:g}",
                            age_days=age_days,
                            table=table,
                            partition=f"dt={dt}/hh={hh}",
                            files=files,
                            bytes=nbytes,
                            blocked_by_hold=blocking,
                            ts=start,
                        )
                    )
                    continue
                if age_days >= policy.warm_days and tag not in frozen:
                    plan.actions.append(
                        RetentionAction(
                            kind="freeze",
                            reason=f"cold tier: recompress at zstd-{COLD_COMPRESSION_LEVEL}",
                            age_days=age_days,
                            table=table,
                            partition=f"dt={dt}/hh={hh}",
                            files=files,
                            bytes=nbytes,
                            # A hold prevents deletion, not recompression: the
                            # rows are preserved byte-for-byte by a rewrite, so
                            # freezing held data is safe and saves disk.
                            blocked_by_hold=None,
                            ts=start,
                        )
                    )
                    continue
                if (
                    files > 1
                    and (now - end) / 3600.0 >= policy.compact_after_hours
                    and tag not in compacted
                ):
                    plan.actions.append(
                        RetentionAction(
                            kind="compact",
                            reason=f"{files} files, older than "
                            f"{policy.compact_after_hours:g}h",
                            age_days=age_days,
                            table=table,
                            partition=f"dt={dt}/hh={hh}",
                            files=files,
                            bytes=nbytes,
                            ts=start,
                        )
                    )

        if self.docs is not None:
            for collection, dpolicy in self.doc_policies.items():
                try:
                    id_field = self.docs.collection(collection).id_field
                    ids = await self.docs.list_ids(collection)
                except Exception:
                    continue
                for doc in await self.docs.get_many(collection, ids):
                    ts = float(doc.get(dpolicy.time_field) or 0)
                    age_days = (now - ts) / 86400.0 if ts else 0.0
                    if ts == 0 or age_days < dpolicy.ttl_days:
                        continue
                    if dpolicy.exempt(doc):
                        continue
                    doc_id = str(doc.get(id_field) or "")
                    if not doc_id:
                        # Without an id the document cannot be deleted by key, and
                        # guessing one risks deleting a different record.
                        continue
                    blocking = next(
                        (h.hold_id for h in live if h.covers_collection(collection, ts)),
                        None,
                    )
                    plan.actions.append(
                        RetentionAction(
                            kind="expire_document",
                            reason=f"older than ttl_days={dpolicy.ttl_days:g}",
                            age_days=age_days,
                            collection=collection,
                            doc_id=doc_id,
                            blocked_by_hold=blocking,
                            ts=ts,
                        )
                    )

        plan.actions.sort(key=lambda a: (-a.age_days, a.kind))
        return plan

    # ── apply ──────────────────────────────────────────────────────────────

    async def apply(
        self, plan: RetentionPlan, dry_run: bool = True, actor: str = "retention"
    ) -> dict[str, Any]:
        """Execute a plan. ``dry_run=True`` by default, deliberately.

        Holds are re-read here rather than trusted from the plan: a plan
        generated an hour ago cannot know about a preservation order placed since,
        and the consequence of getting that wrong is destroyed evidence.

        Destructive actions are audited *before* execution. A crash between the
        audit record and the delete leaves a record of an intent that may not have
        completed, which is recoverable; the reverse leaves a deletion with no
        record, which is not.
        """
        live = await self.holds.live_holds()
        results: list[dict[str, Any]] = []
        state = self._load_state()
        frozen = set(state.get("frozen", []))
        compacted = set(state.get("compacted", []))
        freed = 0

        for action in plan.actions:
            outcome: dict[str, Any] = {"action": action.kind, "target": action.describe()}

            try:
                if action.destructive:
                    # The fresh read is authoritative in both directions: a hold
                    # placed since the plan blocks, and one released since no
                    # longer does. Deferring to the stale plan value would mean a
                    # released preservation order kept blocking retention until
                    # someone happened to regenerate the plan.
                    recheck = self._recheck_hold(action, live)
                    if recheck:
                        outcome["skipped"] = f"held by {recheck}"
                        results.append(outcome)
                        continue
                elif action.blocked_by_hold:
                    outcome["skipped"] = f"held by {action.blocked_by_hold}"
                    results.append(outcome)
                    continue
                if dry_run:
                    outcome["dry_run"] = True
                    results.append(outcome)
                    continue

                if action.destructive and self.audit is not None:
                    await self.audit.append(
                        f"retention.{action.kind}",
                        actor=actor,
                        target=f"{action.table or action.collection}/"
                        f"{action.partition or action.doc_id}",
                        data={
                            "reason": action.reason,
                            "age_days": round(action.age_days, 2),
                            "bytes": action.bytes,
                            "files": action.files,
                        },
                    )

                if action.kind == "compact":
                    dt, hh = _split_partition(action.partition)
                    r = self.lake.compact(action.table, dt, hh)
                    compacted.add(f"{action.table}/{action.partition}")
                    outcome["result"] = r
                elif action.kind == "freeze":
                    dt, hh = _split_partition(action.partition)
                    before = action.bytes
                    r = self.lake.compact(
                        action.table, dt, hh, compression_level=COLD_COMPRESSION_LEVEL
                    )
                    frozen.add(f"{action.table}/{action.partition}")
                    compacted.add(f"{action.table}/{action.partition}")
                    outcome["result"] = {**r, "bytes_before": before}
                elif action.kind == "expire_partition":
                    dt, hh = _split_partition(action.partition)
                    r = self.lake.drop_partition(action.table, dt, hh)
                    freed += r.get("bytes", 0)
                    frozen.discard(f"{action.table}/{action.partition}")
                    compacted.discard(f"{action.table}/{action.partition}")
                    outcome["result"] = r
                elif action.kind == "expire_document":
                    if self.docs is None:
                        raise RetentionError("no DocStore configured for document expiry")
                    existed = await self.docs.delete(action.collection, action.doc_id)
                    outcome["result"] = {"deleted": existed}
                else:
                    raise RetentionError(f"unknown action kind {action.kind!r}")
            except Exception as exc:
                # One failed action must not abandon the rest of the plan; a disk
                # error on a 2024 partition should not leave 2025 unaged. The
                # hold re-check is inside this guard deliberately — a malformed
                # partition string must fail that one action, not the whole run,
                # and a re-check that cannot be evaluated is never treated as
                # "no hold".
                outcome["error"] = f"{type(exc).__name__}: {exc}"
            results.append(outcome)

        if not dry_run:
            self._save_state({"frozen": sorted(frozen), "compacted": sorted(compacted)})
            if self.audit is not None:
                await self.audit.append(
                    "retention.run_complete",
                    actor=actor,
                    data={
                        "actions": len(plan.actions),
                        "executed": len([r for r in results if "result" in r]),
                        "skipped": len([r for r in results if "skipped" in r]),
                        "errors": len([r for r in results if "error" in r]),
                        "bytes_freed": freed,
                    },
                )
        return {
            "dry_run": dry_run,
            "executed": len([r for r in results if "result" in r]),
            "skipped": len([r for r in results if "skipped" in r]),
            "errors": [r for r in results if "error" in r],
            "bytes_freed": freed,
            "results": results,
        }

    def _recheck_hold(
        self, action: RetentionAction, live: Sequence[LegalHold]
    ) -> str | None:
        if action.partition and action.table:
            dt, hh = _split_partition(action.partition)
            start, end = _partition_window(dt, hh)
            return next(
                (h.hold_id for h in live if h.covers_window(start, end, action.table)),
                None,
            )
        if action.collection:
            # The document's own stamp, not now: a hold covering January must
            # still protect a January document being expired in December.
            ts = action.ts if action.ts is not None else self._clock()
            return next(
                (h.hold_id for h in live if h.covers_collection(action.collection, ts)),
                None,
            )
        return None

    async def run(
        self, dry_run: bool = True, now: float | None = None, actor: str = "retention"
    ) -> dict[str, Any]:
        plan = await self.plan(now=now)
        result = await self.apply(plan, dry_run=dry_run, actor=actor)
        result["plan"] = plan
        return result


def _partition_window(dt: str, hh: str) -> tuple[float, float]:
    """``[start, end)`` epoch bounds of a ``dt=/hh=`` partition, in UTC."""
    start = datetime.strptime(f"{dt} {hh}", "%Y-%m-%d %H").replace(tzinfo=timezone.utc)
    return start.timestamp(), start.timestamp() + 3600.0


def _split_partition(partition: str | None) -> tuple[str, str]:
    if not partition or "/" not in partition:
        raise RetentionError(f"malformed partition {partition!r}")
    dt_part, hh_part = partition.split("/", 1)
    return dt_part.split("=", 1)[1], hh_part.split("=", 1)[1]

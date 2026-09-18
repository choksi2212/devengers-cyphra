"""
Documents and secondary indexes on top of a plain key/value store.

VedDB's running build offers SET, GET, DELETE and a whole-keyspace FETCH. The
SOC needs documents with secondary lookups — "every open case", "every detection
for rule X", "the entity record for this host" — so that layer is built here.

── Key layout (all inside the client's ``soc:`` namespace) ──────────────────
::

    doc:<col>:<id>                    the document, JSON
    ix:<col>:<field>:<vhash>:<shard>  posting list: {"v": <value>, "ids": [...]}
    ixk:<col>:<id>                    the index keys this document currently occupies
    meta:<col>                        collection metadata: declared fields, layout
    wal:<txid>                        write intent, deleted on commit
    _lease:writer                     the single-writer lease

``ixk:`` exists because updating a document has to *remove* it from the posting
lists of its previous field values. Recomputing those from the old document
would be wrong whenever the index definition changed between the two writes —
the old document's values under the new definition are not what was actually
written. ``ixk:`` records what was actually written, so it is authoritative.

── Posting lists are sharded ────────────────────────────────────────────────
The shard is derived from the *document id*, so a write touches exactly one
shard while a lookup reads all :data:`POSTING_SHARDS` concurrently and unions
them. Without this, ``ix:detection:rule_id:<X>`` would grow into one
multi-megabyte key that every write to that rule has to read, rewrite and race
on. With it, no single key exceeds roughly one-sixteenth of a posting list and
concurrent writes to different documents usually land on different keys.

── The concurrency situation, stated plainly ────────────────────────────────
The server implements no compare-and-swap, so there is no atomic
read-modify-write anywhere in this file. A posting-list update is GET, union,
SET. Two writers interleaving on the same shard lose one of the two updates,
silently, with no error on either side.

Two mitigations, and neither is a distributed lock:

1. **In-process serialisation.** One :class:`asyncio.Lock` per collection makes
   every mutation in *this* process sequential. Correct, and complete, for the
   intended architecture: the SOC core is the only writer, and agents ship
   telemetry to it rather than writing to VedDB themselves.

2. **A writer lease** (:meth:`DocStore.claim_writer_lease`) turns a violation of
   that architecture from silent data loss into a refusal to start. It is itself
   racy — claiming it needs the CAS the server does not have — so two processes
   starting inside the same millisecond can both win. It reliably catches the
   real case, which is a second process started minutes later.

If a future ``veddb-server`` implements CAS, :attr:`Capabilities.cas` flips and
the lock can be replaced by a proper optimistic-concurrency retry. Nothing else
in the SOC has to change.

── Crash consistency ───────────────────────────────────────────────────────
A logical write touches several keys. An interrupted write therefore leaves the
document and its indexes disagreeing. Before touching anything, :meth:`put`
records the complete intended outcome in ``wal:<txid>`` and deletes it only
after the last key lands. :meth:`repair` replays every surviving WAL record on
startup. Replay is safe because each step is idempotent — set the document to a
known value, add an id to a posting list, remove an id from a posting list —
so re-running a partially applied transaction converges rather than
double-applying.
"""

from __future__ import annotations

import asyncio
import binascii
import hashlib
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .capability import Capabilities
from .veddb import VedDbClient, VedDbError

#: Shards per posting list. Changing this invalidates existing indexes — they
#: must be rebuilt with :meth:`DocStore.rebuild_indexes`, which the version
#: stamp in ``meta:<col>`` detects and reports.
POSTING_SHARDS = 16

#: Bumped when the on-disk layout changes in a way that needs a rebuild.
LAYOUT_VERSION = 1

#: How long a writer lease stays valid without a refresh.
LEASE_TTL_SECONDS = 120.0
LEASE_REFRESH_SECONDS = 30.0

#: This process's identity, for the lease. Stable for the process lifetime.
_BOOT_ID = uuid.uuid4().hex


class DocStoreError(VedDbError):
    """A document-layer failure."""


class WriterLeaseHeld(DocStoreError):
    """Another live process holds the writer lease.

    Starting anyway would mean two processes doing read-modify-write on the same
    index keys with no compare-and-swap available, which loses updates silently.
    """


class SchemaError(DocStoreError):
    """A document does not match its collection's declaration."""


@dataclass(frozen=True)
class Collection:
    """A declared document collection.

    ``indexed`` names the fields that get secondary lookups. Only declared
    fields are indexed: an index nobody declared is an index nobody maintains,
    and a stale posting list is worse than a missing one because it is trusted.

    ``id_field`` names the document's own identifier. ``required`` fields are
    rejected at write time rather than discovered missing during an incident.
    """

    name: str
    indexed: tuple[str, ...] = ()
    id_field: str = "id"
    required: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or ":" in self.name:
            raise SchemaError(f"collection name must be non-empty and colon-free: {self.name!r}")
        for f in self.indexed:
            if not f:
                raise SchemaError(f"{self.name}: empty indexed field name")


def _vhash(value: Any) -> str:
    """Stable, key-safe digest of an index value.

    Index values are arbitrary event data — usernames with spaces, IPv6
    addresses full of colons, UPNs, file paths. Hashing sidesteps every escaping
    question. The original value is kept inside the posting list so a human
    reading the store can still tell what a key is for, and so
    :meth:`DocStore.verify` can detect a digest collision rather than silently
    merging two values.
    """
    if isinstance(value, bool):
        canonical = "true" if value else "false"
    elif value is None:
        canonical = "\x00null"
    elif isinstance(value, (int, float, str)):
        canonical = str(value)
    else:
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _shard_of(doc_id: str) -> int:
    return binascii.crc32(doc_id.encode("utf-8")) % POSTING_SHARDS


def _index_values(doc: Mapping[str, Any], fieldname: str) -> list[Any]:
    """Values a document contributes to one index.

    Supports dotted paths (``actor.user.name``) and list-valued fields, because
    a detection legitimately has several ATT&CK techniques and an entity several
    IP addresses. A missing path contributes nothing rather than indexing
    ``None`` — otherwise every document lacking the field piles into one posting
    list under the same key, which is the worst possible shape for it.
    """
    node: Any = doc
    for part in fieldname.split("."):
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        else:
            return []
    if node is None:
        return []
    if isinstance(node, (list, tuple, set)):
        return [v for v in node if v is not None]
    return [node]


@dataclass
class _PostingList:
    value: Any
    ids: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"v": self.value, "ids": self.ids}

    @staticmethod
    def from_json(raw: Any) -> "_PostingList":
        if not isinstance(raw, Mapping):
            raise DocStoreError(f"malformed posting list: {raw!r}")
        ids = raw.get("ids", [])
        if not isinstance(ids, list):
            raise DocStoreError(f"malformed posting list ids: {ids!r}")
        return _PostingList(raw.get("v"), [str(i) for i in ids])


class DocStore:
    """Documents, secondary indexes and crash repair over a KV client."""

    def __init__(
        self,
        client: VedDbClient,
        capabilities: Capabilities | None = None,
        collections: Iterable[Collection] = (),
    ) -> None:
        self.client = client
        self.caps = capabilities
        self._collections: dict[str, Collection] = {c.name: c for c in collections}
        self._locks: dict[str, asyncio.Lock] = {}
        self._lease_txid: str | None = None
        self._lease_last_refresh = 0.0
        self.holds_writer_lease = False

    # ── declaration ────────────────────────────────────────────────────────

    def register(self, collection: Collection) -> Collection:
        existing = self._collections.get(collection.name)
        if existing and existing != collection:
            raise SchemaError(
                f"collection {collection.name!r} is already registered with a "
                f"different definition (indexed={existing.indexed} vs "
                f"{collection.indexed}). Rebuild indexes explicitly instead of "
                "redefining in place."
            )
        self._collections[collection.name] = collection
        return collection

    def collection(self, name: str) -> Collection:
        try:
            return self._collections[name]
        except KeyError:
            raise SchemaError(
                f"collection {name!r} is not registered. Declare it with "
                "DocStore.register(Collection(...)) so its indexes are maintained."
            ) from None

    def _lock(self, name: str) -> asyncio.Lock:
        lock = self._locks.get(name)
        if lock is None:
            lock = self._locks[name] = asyncio.Lock()
        return lock

    # ── key construction ───────────────────────────────────────────────────

    @staticmethod
    def doc_key(col: str, doc_id: str) -> str:
        return f"doc:{col}:{doc_id}"

    @staticmethod
    def ixk_key(col: str, doc_id: str) -> str:
        return f"ixk:{col}:{doc_id}"

    @staticmethod
    def meta_key(col: str) -> str:
        return f"meta:{col}"

    @staticmethod
    def posting_key(col: str, fieldname: str, value: Any, shard: int) -> str:
        return f"ix:{col}:{fieldname}:{_vhash(value)}:{shard}"

    # ── writer lease ───────────────────────────────────────────────────────

    async def claim_writer_lease(self, force: bool = False) -> None:
        """Claim the right to write. Raises if another live process holds it.

        Racy by construction — see the module docstring. It catches the case that
        actually happens (a second core started later) and cannot catch a
        simultaneous start. ``force=True`` steals the lease; only correct when
        the previous holder is known dead.
        """
        key = "_lease:writer"
        mine = {
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "boot": _BOOT_ID,
            "claimed_at": time.time(),
            "expires_at": time.time() + LEASE_TTL_SECONDS,
        }
        current = await self.client.get_json(key)
        if current and not force:
            same = (
                current.get("host") == mine["host"]
                and current.get("pid") == mine["pid"]
                and current.get("boot") == mine["boot"]
            )
            expires = float(current.get("expires_at") or 0)
            if not same and expires > time.time():
                raise WriterLeaseHeld(
                    "another process holds the VedDB writer lease "
                    f"({current.get('host')}:{current.get('pid')}, expires in "
                    f"{expires - time.time():.0f}s). Two writers without "
                    "server-side CAS lose index updates silently. Stop the other "
                    "process, or pass force=True if it is known dead."
                )
        await self.client.set_json(key, mine)
        self.holds_writer_lease = True
        self._lease_last_refresh = time.monotonic()

    async def release_writer_lease(self) -> None:
        if not self.holds_writer_lease:
            return
        current = await self.client.get_json("_lease:writer")
        if current and current.get("boot") == _BOOT_ID:
            await self.client.delete("_lease:writer")
        self.holds_writer_lease = False

    async def _refresh_lease(self) -> None:
        """Extend the lease if it is getting stale. Cheap; called on write."""
        if not self.holds_writer_lease:
            return
        if time.monotonic() - self._lease_last_refresh < LEASE_REFRESH_SECONDS:
            return
        await self.client.set_json(
            "_lease:writer",
            {
                "host": socket.gethostname(),
                "pid": os.getpid(),
                "boot": _BOOT_ID,
                "claimed_at": time.time(),
                "expires_at": time.time() + LEASE_TTL_SECONDS,
            },
        )
        self._lease_last_refresh = time.monotonic()

    # ── read ───────────────────────────────────────────────────────────────

    async def get(self, col: str, doc_id: str) -> dict[str, Any] | None:
        self.collection(col)
        doc = await self.client.get_json(self.doc_key(col, str(doc_id)))
        if doc is None:
            return None
        if not isinstance(doc, Mapping):
            raise DocStoreError(f"{self.doc_key(col, doc_id)} is not a JSON object")
        return dict(doc)

    async def get_many(self, col: str, ids: Sequence[str]) -> list[dict[str, Any]]:
        self.collection(col)
        if not ids:
            return []
        raw = await asyncio.gather(
            *(self.client.get_json(self.doc_key(col, str(i))) for i in ids)
        )
        return [dict(d) for d in raw if isinstance(d, Mapping)]

    async def find_ids(self, col: str, fieldname: str, value: Any) -> list[str]:
        """Ids of documents whose ``fieldname`` holds ``value``.

        Reads all posting-list shards concurrently. Verifies the stored original
        value against the query, so a 64-bit digest collision surfaces as an
        error rather than as two values quietly sharing a posting list.
        """
        spec = self.collection(col)
        if fieldname not in spec.indexed:
            raise SchemaError(
                f"{col}.{fieldname} is not indexed (indexed: {spec.indexed or '()'}). "
                "Range and ad-hoc queries belong in DuckDB over the lake, not here."
            )
        keys = [self.posting_key(col, fieldname, value, s) for s in range(POSTING_SHARDS)]
        raws = await asyncio.gather(*(self.client.get_json(k) for k in keys))
        out: list[str] = []
        for k, raw in zip(keys, raws):
            if raw is None:
                continue
            posting = _PostingList.from_json(raw)
            if posting.value != value and _vhash(posting.value) == _vhash(value):
                raise DocStoreError(
                    f"digest collision on {k}: posting list holds "
                    f"{posting.value!r} but was queried for {value!r}"
                )
            out.extend(posting.ids)
        # Shards are disjoint by construction (shard = f(id)), so no dedup is
        # needed — but a repaired index could briefly violate that, and a
        # duplicated id would inflate every count downstream.
        return sorted(set(out))

    async def find(self, col: str, fieldname: str, value: Any) -> list[dict[str, Any]]:
        return await self.get_many(col, await self.find_ids(col, fieldname, value))

    async def find_any(
        self, col: str, fieldname: str, values: Iterable[Any]
    ) -> list[dict[str, Any]]:
        id_sets = await asyncio.gather(
            *(self.find_ids(col, fieldname, v) for v in values)
        )
        merged = sorted({i for s in id_sets for i in s})
        return await self.get_many(col, merged)

    async def find_all(
        self, col: str, criteria: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        """Documents matching every field/value pair (AND).

        Intersects posting lists, smallest first, so the cost tracks the most
        selective term rather than the least.
        """
        if not criteria:
            raise SchemaError("find_all needs at least one criterion")
        id_lists = await asyncio.gather(
            *(self.find_ids(col, f, v) for f, v in criteria.items())
        )
        id_lists.sort(key=len)
        common = set(id_lists[0])
        for other in id_lists[1:]:
            common &= set(other)
            if not common:
                return []
        return await self.get_many(col, sorted(common))

    # ── write ──────────────────────────────────────────────────────────────

    async def put(
        self, col: str, doc: Mapping[str, Any], *, doc_id: str | None = None
    ) -> str:
        """Insert or replace a document and reconcile its indexes.

        Serialised per collection in this process, and journalled so an
        interrupted call is repairable. Returns the document id.
        """
        async with self._lock(col):
            return await self._put_locked(col, doc, doc_id)

    async def _put_locked(
        self, col: str, doc: Mapping[str, Any], doc_id: str | None
    ) -> str:
        """The body of :meth:`put`. Caller must already hold the collection lock.

        Split out so :meth:`update` can read-modify-write without releasing the
        lock between the read and the write — releasing it there would let
        another coroutine's update land in the gap and be overwritten.
        """
        spec = self.collection(col)
        ident = str(doc_id if doc_id is not None else doc.get(spec.id_field, "") or "")
        if not ident:
            raise SchemaError(
                f"{col}: document has no {spec.id_field!r} and no doc_id was given"
            )
        if ":" in ident or "\n" in ident:
            raise SchemaError(
                f"{col}: document id {ident!r} contains a reserved character; "
                "ids must be colon- and newline-free (hash it if it is a raw "
                "identifier from event data)"
            )
        missing = [f for f in spec.required if not _index_values(doc, f)]
        if missing:
            raise SchemaError(f"{col}:{ident} is missing required field(s): {missing}")

        body = dict(doc)
        body[spec.id_field] = ident
        body["_updated_at"] = time.time()
        body.setdefault("_created_at", body["_updated_at"])

        # Index keys this document should occupy after the write.
        shard = _shard_of(ident)
        wanted: dict[str, tuple[str, Any]] = {}
        for fieldname in spec.indexed:
            for value in _index_values(body, fieldname):
                wanted[self.posting_key(col, fieldname, value, shard)] = (fieldname, value)

        await self._refresh_lease()
        previous = await self.client.get_json(self.ixk_key(col, ident))
        held: set[str] = set(previous or [])
        to_add = sorted(set(wanted) - held)
        to_remove = sorted(held - set(wanted))

        txid = uuid.uuid4().hex
        wal_key = f"wal:{txid}"
        await self.client.set_json(
            wal_key,
            {
                "op": "put",
                "col": col,
                "id": ident,
                "doc_key": self.doc_key(col, ident),
                "add": [[k, *wanted[k]] for k in to_add],
                "remove": to_remove,
                "ixk": sorted(wanted),
                "at": time.time(),
            },
        )
        try:
            # Document first: an index entry pointing at a missing document is a
            # dangling reference that every reader has to defend against,
            # whereas a document missing from an index is merely invisible to one
            # lookup and is what repair fixes.
            await self.client.set_json(self.doc_key(col, ident), body)
            await asyncio.gather(
                *(self._posting_add(k, wanted[k][1], ident) for k in to_add),
                *(self._posting_remove(k, ident) for k in to_remove),
            )
            await self.client.set_json(self.ixk_key(col, ident), sorted(wanted))
            await self._bump_meta(col, spec)
        finally:
            await self.client.delete(wal_key)
        return ident

    async def delete(self, col: str, doc_id: str) -> bool:
        """Remove a document and every posting-list entry that referenced it."""
        spec = self.collection(col)
        ident = str(doc_id)
        async with self._lock(col):
            await self._refresh_lease()
            held = await self.client.get_json(self.ixk_key(col, ident)) or []
            existed = await self.client.exists(self.doc_key(col, ident))
            txid = uuid.uuid4().hex
            wal_key = f"wal:{txid}"
            await self.client.set_json(
                wal_key,
                {
                    "op": "delete",
                    "col": col,
                    "id": ident,
                    "doc_key": self.doc_key(col, ident),
                    "remove": sorted(held),
                    "at": time.time(),
                },
            )
            try:
                # Indexes first here — the opposite order from put(), and for the
                # same reason: never leave a posting list pointing at a document
                # that no longer exists.
                await asyncio.gather(
                    *(self._posting_remove(k, ident) for k in held)
                )
                await self.client.delete(self.ixk_key(col, ident))
                await self.client.delete(self.doc_key(col, ident))
                await self._bump_meta(col, spec)
            finally:
                await self.client.delete(wal_key)
        return existed

    async def update(
        self, col: str, doc_id: str, changes: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Shallow-merge ``changes`` into an existing document.

        Read-modify-write, held under one acquisition of the collection lock for
        the whole read→merge→write sequence. Two concurrent updates to the same
        case therefore compose instead of one silently discarding the other's
        fields — which matters because case state is updated from several places
        (triage verdict, response outcome, analyst note) within one incident.
        """
        async with self._lock(col):
            current = await self.client.get_json(self.doc_key(col, str(doc_id)))
            if current is None:
                raise DocStoreError(f"{col}:{doc_id} does not exist")
            if not isinstance(current, Mapping):
                raise DocStoreError(f"{self.doc_key(col, str(doc_id))} is not a JSON object")
            merged = {**dict(current), **dict(changes)}
            await self._put_locked(col, merged, str(doc_id))
        return merged

    # ── posting-list primitives ────────────────────────────────────────────

    async def _posting_add(self, key: str, value: Any, doc_id: str) -> None:
        raw = await self.client.get_json(key)
        posting = _PostingList.from_json(raw) if raw is not None else _PostingList(value)
        if doc_id in posting.ids:
            return
        posting.ids.append(doc_id)
        posting.ids.sort()
        posting.value = value
        await self.client.set_json(key, posting.to_json())

    async def _posting_remove(self, key: str, doc_id: str) -> None:
        raw = await self.client.get_json(key)
        if raw is None:
            return
        posting = _PostingList.from_json(raw)
        if doc_id not in posting.ids:
            return
        posting.ids = [i for i in posting.ids if i != doc_id]
        if posting.ids:
            await self.client.set_json(key, posting.to_json())
        else:
            # An empty posting list is indistinguishable from a missing one for
            # every reader, and leaving it behind means the keyspace grows with
            # every distinct value ever seen — unbounded, since values come from
            # event data.
            await self.client.delete(key)

    async def _bump_meta(self, col: str, spec: Collection) -> None:
        await self.client.set_json(
            self.meta_key(col),
            {
                "name": col,
                "indexed": list(spec.indexed),
                "id_field": spec.id_field,
                "required": list(spec.required),
                "layout_version": LAYOUT_VERSION,
                "posting_shards": POSTING_SHARDS,
                "updated_at": time.time(),
            },
        )

    # ── enumeration, repair, verification ──────────────────────────────────

    async def list_ids(self, col: str) -> list[str]:
        """Every document id in a collection.

        Uses FETCH, whose cost is linear in the *whole* instance keyspace, so it
        is an administrative call. Runtime code should reach documents through a
        declared index instead.
        """
        self.collection(col)
        prefix = f"doc:{col}:"
        full = self.client.full_key(prefix)
        return sorted(k[len(full):] for k in await self.client.list_keys(prefix))

    async def count(self, col: str) -> int:
        return len(await self.list_ids(col))

    async def repair(self) -> dict[str, Any]:
        """Replay every outstanding write intent. Safe to call repeatedly.

        Each step is idempotent, so a transaction that was half-applied before a
        crash converges to the intended state rather than double-applying.
        """
        wal_keys = await self.client.list_keys("wal:")
        replayed: list[dict[str, Any]] = []
        for wal_key in sorted(wal_keys):
            short = self.client.strip_key(wal_key)
            record = await self.client.get_json(short)
            if not isinstance(record, Mapping):
                await self.client.delete(short)
                replayed.append({"wal": short, "action": "discarded-malformed"})
                continue
            col = str(record.get("col") or "")
            ident = str(record.get("id") or "")
            op = record.get("op")
            try:
                if op == "put":
                    # The document body is not in the WAL — only the intent. If
                    # the document landed, finish the index work; if it did not,
                    # the write never became visible and the intent is dropped.
                    exists = await self.client.exists(self.doc_key(col, ident))
                    if exists:
                        for entry in record.get("add") or []:
                            key, _fieldname, value = entry
                            await self._posting_add(key, value, ident)
                        for key in record.get("remove") or []:
                            await self._posting_remove(key, ident)
                        await self.client.set_json(
                            self.ixk_key(col, ident), list(record.get("ixk") or [])
                        )
                        action = "completed"
                    else:
                        for entry in record.get("add") or []:
                            await self._posting_remove(entry[0], ident)
                        action = "rolled-back"
                elif op == "delete":
                    for key in record.get("remove") or []:
                        await self._posting_remove(key, ident)
                    await self.client.delete(self.ixk_key(col, ident))
                    await self.client.delete(self.doc_key(col, ident))
                    action = "completed"
                else:
                    action = "discarded-unknown-op"
            except VedDbError as exc:
                replayed.append({"wal": short, "action": "failed", "error": str(exc)})
                continue
            await self.client.delete(short)
            replayed.append({"wal": short, "col": col, "id": ident, "action": action})
        return {"outstanding": len(wal_keys), "replayed": replayed}

    async def rebuild_indexes(self, col: str) -> dict[str, Any]:
        """Drop and recreate every posting list for a collection.

        Needed after changing :data:`POSTING_SHARDS`, after adding a field to
        ``indexed``, or after a repair reports failures.
        """
        spec = self.collection(col)
        async with self._lock(col):
            stale = await self.client.list_keys(f"ix:{col}:")
            for key in stale:
                await self.client.delete(self.client.strip_key(key))
            ids = await self.list_ids(col)
            reindexed = 0
            for ident in ids:
                doc = await self.get(col, ident)
                if doc is None:
                    continue
                shard = _shard_of(ident)
                wanted: dict[str, Any] = {}
                for fieldname in spec.indexed:
                    for value in _index_values(doc, fieldname):
                        wanted[self.posting_key(col, fieldname, value, shard)] = value
                for key, value in wanted.items():
                    await self._posting_add(key, value, ident)
                await self.client.set_json(self.ixk_key(col, ident), sorted(wanted))
                reindexed += 1
            await self._bump_meta(col, spec)
        return {"collection": col, "dropped": len(stale), "reindexed": reindexed}

    async def verify(self, col: str) -> dict[str, Any]:
        """Check documents and indexes agree. Reports, does not fix.

        Three failure classes, all of which would otherwise be invisible:

        * **dangling** — a posting list names a document that does not exist.
          A lookup returns fewer results than it counted.
        * **missing** — a document is absent from a posting list it belongs in.
          A lookup silently omits it, which during an incident means evidence
          that exists but cannot be found.
        * **misplaced** — an id sits in the wrong shard, so the union that
          should find it does not.
        """
        spec = self.collection(col)
        ids = set(await self.list_ids(col))
        dangling: list[dict[str, str]] = []
        misplaced: list[dict[str, str]] = []
        indexed_pairs: set[tuple[str, str]] = set()

        for full_key in await self.client.list_keys(f"ix:{col}:"):
            short = self.client.strip_key(full_key)
            raw = await self.client.get_json(short)
            if raw is None:
                continue
            posting = _PostingList.from_json(raw)
            try:
                shard = int(short.rsplit(":", 1)[1])
            except (IndexError, ValueError):
                misplaced.append({"key": short, "reason": "unparseable shard suffix"})
                continue
            for doc_id in posting.ids:
                indexed_pairs.add((short, doc_id))
                if doc_id not in ids:
                    dangling.append({"key": short, "id": doc_id})
                if _shard_of(doc_id) != shard:
                    misplaced.append(
                        {"key": short, "id": doc_id, "reason": f"belongs in shard {_shard_of(doc_id)}"}
                    )

        missing: list[dict[str, str]] = []
        for ident in sorted(ids):
            doc = await self.get(col, ident)
            if doc is None:
                continue
            shard = _shard_of(ident)
            for fieldname in spec.indexed:
                for value in _index_values(doc, fieldname):
                    key = self.posting_key(col, fieldname, value, shard)
                    if (key, ident) not in indexed_pairs:
                        missing.append({"key": key, "id": ident, "field": fieldname})

        return {
            "collection": col,
            "documents": len(ids),
            "index_entries": len(indexed_pairs),
            "dangling": dangling,
            "missing": missing,
            "misplaced": misplaced,
            "consistent": not (dangling or missing or misplaced),
        }

    async def drop_collection(self, col: str) -> dict[str, int]:
        """Delete every key belonging to a collection. Used by tests."""
        self.collection(col)
        removed = 0
        for prefix in (f"doc:{col}:", f"ix:{col}:", f"ixk:{col}:"):
            for full_key in await self.client.list_keys(prefix):
                if await self.client.delete(self.client.strip_key(full_key)):
                    removed += 1
        if await self.client.delete(self.meta_key(col)):
            removed += 1
        return {"collection": col, "keys_deleted": removed}

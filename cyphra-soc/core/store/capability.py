"""
Startup capability probe.

The client library vendored at ``veddb-cyphra/`` advertises a document store,
secondary indexes, sorted sets, hashes and pub/sub. The server binary currently
running answers none of them. That gap is the single most important fact about
the storage layer, so it is *measured at startup* rather than assumed — and
measured in a way that keeps working if the operator later drops in a newer
``veddb-server``.

Every layer above asks this module what is available instead of hardcoding the
answer. :mod:`core.store.kvdoc` reads :attr:`Capabilities.documents` to choose
between its own key-based index layer and native document ops; if a future build
implements CAS, :attr:`Capabilities.cas` flips and the single-writer lock can be
narrowed to a real optimistic-concurrency loop with no other code change.

── Why the probe writes ─────────────────────────────────────────────────────
An opcode's presence cannot be established without sending it. The probe
therefore writes to two keys under a dedicated ``_probe:`` prefix inside the
SOC namespace and deletes them afterwards, in a ``finally`` so a failure
mid-probe still cleans up. Nothing outside ``soc:_probe:*`` is touched, so it
cannot disturb the messenger's records in the same instance.

Mutating opcodes that would be destructive if they *did* work (DROP_COLLECTION,
DELETE_DOC, SREM, ZREM, HDEL) are deliberately **not** probed. Reporting them as
"unknown" when they are merely untested would be a lie, so they are reported as
:data:`UNPROBED` — a third state, distinct from supported and unsupported.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from .veddb import Op, Response, Status, VedDbClient, VedDbError

PROBE_PREFIX = "_probe"
UNPROBED = "unprobed"

#: Opcodes safe to send speculatively: read-only, or writing only to a key the
#: probe owns. Order matters only for readability.
_SAFE_PROBES: tuple[tuple[Op, str, bytes, bytes], ...] = (
    (Op.PING, "ping", b"", b""),
    (Op.INFO, "info", b"", b""),
    (Op.CAS, "cas", b"", b""),
    (Op.SUBSCRIBE, "subscribe", b"", b""),
    (Op.PUBLISH, "publish", b"", b""),
    (Op.QUERY, "query", b"", b""),
    (Op.LIST_COLLECTIONS, "list_collections", b"", b""),
    (Op.LIST_INDEXES, "list_indexes", b"", b""),
    (Op.CREATE_COLLECTION, "create_collection", b"", b""),
    (Op.CREATE_INDEX, "create_index", b"", b""),
    (Op.INSERT_DOC, "insert_doc", b"", b""),
    (Op.LPUSH, "lpush", b"", b""),
    (Op.LRANGE, "lrange", b"", b""),
    (Op.SADD, "sadd", b"", b""),
    (Op.SMEMBERS, "smembers", b"", b""),
    (Op.ZADD, "zadd", b"", b""),
    (Op.ZRANGE, "zrange", b"", b""),
    (Op.HSET, "hset", b"", b""),
    (Op.HGETALL, "hgetall", b"", b""),
)

#: Not sent. If these exist they mutate or destroy state the probe does not own.
_UNPROBED_OPS = (
    Op.DROP_COLLECTION,
    Op.DROP_INDEX,
    Op.DELETE_DOC,
    Op.UPDATE_DOC,
    Op.SREM,
    Op.ZREM,
    Op.HDEL,
    Op.LPOP,
    Op.RPOP,
    Op.UNSUBSCRIBE,
    Op.AUTH,
)


def _is_unsupported(resp: Response) -> bool:
    """Does this response mean "the server has no such opcode"?

    This build answers unimplemented opcodes with ``TIMEOUT`` (4) and the
    payload ``unknown command``. Matching on the text as well as the status
    matters: a *real* timeout also carries status 4, and the two demand opposite
    handling — retry one, never the other.
    """
    text = resp.payload.decode("utf-8", errors="replace").lower()
    if "unknown command" in text or "unsupported" in text or "not implemented" in text:
        return True
    # A bare status 4 with no explanation is ambiguous. Treat it as unsupported
    # only when there is no payload at all, and record the ambiguity in `notes`.
    return resp.status == Status.TIMEOUT and not resp.payload


@dataclass
class Capabilities:
    """What the running server can actually do."""

    reachable: bool = False
    server_note: str = ""
    probe_ms: float = 0.0
    supported: set[str] = field(default_factory=set)
    unsupported: set[str] = field(default_factory=set)
    unprobed: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)

    # ── the questions the rest of the platform actually asks ────────────────

    @property
    def kv(self) -> bool:
        """The irreducible minimum: set, get, delete."""
        return {"set", "get", "delete"} <= self.supported

    @property
    def enumerate_keys(self) -> bool:
        """FETCH returns the keyspace, enabling index repair."""
        return "fetch" in self.supported

    @property
    def cas(self) -> bool:
        """Server-side compare-and-swap → real optimistic concurrency."""
        return "cas" in self.supported

    @property
    def documents(self) -> bool:
        """Native document store → kvdoc can stop emulating one."""
        return {"insert_doc", "query"} <= self.supported

    @property
    def native_indexes(self) -> bool:
        return "create_index" in self.supported

    @property
    def sorted_sets(self) -> bool:
        """Would give O(log n) time-range queries without touching DuckDB."""
        return {"zadd", "zrange"} <= self.supported

    @property
    def pubsub(self) -> bool:
        """Would replace polling for live alert fan-out."""
        return {"subscribe", "publish"} <= self.supported

    @property
    def index_strategy(self) -> str:
        """Which strategy :mod:`core.store.kvdoc` should use."""
        return "native" if self.documents and self.native_indexes else "kv-emulated"

    @property
    def concurrency_strategy(self) -> str:
        return "cas" if self.cas else "single-writer-lock"

    def require_kv(self) -> None:
        if not self.reachable:
            raise VedDbError(
                "VedDB is not reachable. Start it (web-app/veddb-server.exe) or "
                "correct store.veddb_host/port in soc.yaml."
            )
        if not self.kv:
            raise VedDbError(
                "VedDB is reachable but does not implement SET/GET/DELETE: "
                f"supported = {sorted(self.supported)}. The SOC cannot persist."
            )

    def report(self) -> str:
        lines = [
            "VedDB capability probe",
            f"  reachable            : {self.reachable}"
            + (f"  ({self.server_note})" if self.server_note else ""),
            f"  probe time           : {self.probe_ms:.1f} ms",
            f"  supported   ({len(self.supported):2d})   : {', '.join(sorted(self.supported)) or '-'}",
            f"  unsupported ({len(self.unsupported):2d})   : {', '.join(sorted(self.unsupported)) or '-'}",
            f"  unprobed    ({len(self.unprobed):2d})   : {', '.join(sorted(self.unprobed)) or '-'}",
            "",
            f"  index strategy       : {self.index_strategy}",
            f"  concurrency strategy : {self.concurrency_strategy}",
            f"  key enumeration      : {'FETCH (whole keyspace)' if self.enumerate_keys else 'unavailable'}",
            f"  live fan-out         : {'pub/sub' if self.pubsub else 'polling (no pub/sub)'}",
        ]
        if self.notes:
            lines += ["", "  notes:"] + [f"    - {n}" for n in self.notes]
        return "\n".join(lines)


async def probe(client: VedDbClient) -> Capabilities:
    """Establish what the connected server implements. Cleans up after itself."""
    caps = Capabilities()
    started = time.perf_counter()
    probe_key = f"{PROBE_PREFIX}:capability"
    probe_key2 = f"{PROBE_PREFIX}:capability2"

    try:
        # ── the five that matter, tested by behaviour not by status ─────────
        try:
            if await client.ping():
                caps.reachable = True
                caps.supported.add("ping")
            else:
                caps.reachable = True
                caps.unsupported.add("ping")
                caps.notes.append("PING answered but not with 'pong'")
        except VedDbError as exc:
            caps.reachable = False
            caps.server_note = str(exc)
            caps.probe_ms = (time.perf_counter() - started) * 1000
            return caps

        sentinel = {"probe": True, "nonce": int(time.time() * 1000)}
        try:
            await client.set_json(probe_key, sentinel)
            caps.supported.add("set")
        except VedDbError as exc:
            caps.unsupported.add("set")
            caps.notes.append(f"SET failed: {exc}")

        if "set" in caps.supported:
            # Round-trip, not just status: a SET that returns OK and stores
            # nothing would otherwise read as a working store.
            try:
                got = await client.get_json(probe_key)
                if got == sentinel:
                    caps.supported.add("get")
                else:
                    caps.unsupported.add("get")
                    caps.notes.append(
                        f"GET round-trip mismatch: wrote {sentinel}, read {got!r}"
                    )
            except VedDbError as exc:
                caps.unsupported.add("get")
                caps.notes.append(f"GET failed: {exc}")

            # Absent-key semantics, recorded because they are unusual here.
            missing = await client.get_json(f"{PROBE_PREFIX}:definitely-absent")
            if missing is None:
                caps.notes.append(
                    "absent keys report as ERROR(1) with an empty payload, not "
                    "NOT_FOUND(2) — mapped to None by the client"
                )

            try:
                await client.set_json(probe_key2, sentinel)
                existed = await client.delete(probe_key2)
                gone = await client.get_json(probe_key2)
                if existed and gone is None:
                    caps.supported.add("delete")
                else:
                    caps.unsupported.add("delete")
                    caps.notes.append(
                        f"DELETE did not remove the key (reported {existed}, "
                        f"re-read {gone!r})"
                    )
            except VedDbError as exc:
                caps.unsupported.add("delete")
                caps.notes.append(f"DELETE failed: {exc}")

        # FETCH: verified by *content* — it must contain the key we just wrote.
        try:
            resp = await client.raw(Op.FETCH, b"")
            if _is_unsupported(resp):
                caps.unsupported.add("fetch")
            elif resp.ok:
                keys = resp.payload.decode("utf-8", errors="replace").split("\n")
                if client.full_key(probe_key) in keys:
                    caps.supported.add("fetch")
                    caps.notes.append(
                        f"FETCH enumerates the whole keyspace ({len(keys)} keys, "
                        f"{len(resp.payload)} bytes) and ignores its key argument; "
                        "prefix filtering is client-side, so it is repair-only"
                    )
                else:
                    caps.unsupported.add("fetch")
                    caps.notes.append(
                        "FETCH returned data that does not include the probe key; "
                        "not trusted for enumeration"
                    )
            else:
                caps.unsupported.add("fetch")
        except VedDbError as exc:
            caps.unsupported.add("fetch")
            caps.notes.append(f"FETCH failed: {exc}")

        # ── everything else: does the opcode exist at all? ──────────────────
        for op, name, key, value in _SAFE_PROBES:
            if name in caps.supported or name in caps.unsupported:
                continue
            arg_key = key or client.full_key(probe_key).encode()
            arg_val = value or json.dumps(sentinel).encode()
            try:
                resp = await client.raw(op, arg_key, arg_val)
            except VedDbError as exc:
                caps.unsupported.add(name)
                caps.notes.append(f"{name}: transport error {exc}")
                continue
            if _is_unsupported(resp):
                caps.unsupported.add(name)
            elif resp.status in (Status.OK, Status.NOT_FOUND):
                caps.supported.add(name)
            else:
                # Present but rejected our arguments — that still proves the
                # opcode is implemented, which is what we are measuring.
                caps.supported.add(name)
                caps.notes.append(
                    f"{name}: implemented, rejected the probe's arguments "
                    f"(status {int(resp.status)} {resp.text.strip()[:60]!r})"
                )

        caps.unprobed = {op.name.lower() for op in _UNPROBED_OPS}
        caps.notes.append(
            f"{len(caps.unprobed)} destructive opcodes were not sent, so they are "
            "reported as unprobed rather than unsupported"
        )

    finally:
        # Best-effort: a probe that leaves keys behind pollutes the very
        # enumeration it just validated.
        for k in (probe_key, probe_key2):
            try:
                await client.delete(k)
            except VedDbError:
                pass
        caps.probe_ms = (time.perf_counter() - started) * 1000

    return caps


async def probe_and_require(client: VedDbClient) -> Capabilities:
    """Probe, then refuse to continue if basic KV is missing."""
    caps = await probe(client)
    caps.require_kv()
    return caps

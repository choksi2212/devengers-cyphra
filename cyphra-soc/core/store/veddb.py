"""
Native async VedDB client.

The messenger reaches VedDB by spawning ``veddb-client.exe`` once per operation
(``web-app/backend/services/veddb.service.js``). That is fine for a chat app
doing a few writes a minute; the SOC writes thousands of records a minute, so it
speaks the wire protocol directly over a pooled TCP connection.

── Wire protocol (reverse-engineered against the running server) ────────────
Little-endian throughout.

  command  24 bytes: opcode u8 │ flags u8 │ version u8 │ reserved u8 │
                     seq u32   │ key_len u32 │ value_len u32 │ extra u64
                     followed by key bytes, then value bytes

  response 20 bytes: status u8 │ flags u8 │ reserved u16 │
                     seq u32   │ payload_len u32 │ extra u64
                     followed by payload_len bytes

The 20 is worth stating plainly because the vendored client library's own
``ResponseHeader::from_bytes`` comment says 16 for protocol v2. The running
server emits 20 — the payload starts at offset 20, and assuming 16 makes a
``pong`` decode as ``status=112`` ('p') with four bytes of garbage. Verified
empirically: PING → ``pong``, SET/GET/DELETE round-trip clean.

── What the running server actually implements ──────────────────────────────
Only PING, SET, GET, DELETE and FETCH. Every other opcode in the client
library's enum — CAS, pub/sub, INFO, the document store, secondary indexes,
sorted sets, hashes, users — answers ``status=4`` with the payload
``unknown command``. Two of the five behave differently from their names:

  * **GET signals a miss with ``ERROR`` (1) and an empty payload**, not with
    ``NOT_FOUND`` (2). Status 2 is never emitted by this build. Same for DELETE.
  * **FETCH is a keyspace dump, not a read.** It ignores its key argument
    completely and returns every key in the instance, newline-separated. Called
    with an empty key, a nonsense key, a prefix and a glob it returns
    byte-identical results. That makes it genuinely useful — index repair and
    orphan detection become possible — but its cost is linear in the *total*
    keyspace, so it is an administrative operation only.

Consequences that shape the layers above:

  * there is no server-side compare-and-swap, therefore no atomic
    read-modify-write. :mod:`core.store.kvdoc` serialises writers in-process
    instead. This is honest but it is a single-process guarantee — see the
    warning in that module.
  * documents and secondary indexes are built on plain keys, also in kvdoc,
    which uses explicit ``idx:`` keys for lookups and reserves FETCH for repair.
  * :mod:`core.store.capability` probes at startup, so if a newer server build
    is dropped in, the extra opcodes are detected and used with no code change.

── Namespacing is not cosmetic ─────────────────────────────────────────────
This is the *same* VedDB instance the messenger uses, holding live ``user:*``
and ``messages:*`` records. Every key this client touches is therefore prefixed
with ``<namespace>:`` (default ``soc:``), and :meth:`VedDbClient.set` refuses a
key that would escape it. A SOC that corrupts the product's user store while
logging an alert is not a security improvement.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, AsyncIterator

# ── Framing ─────────────────────────────────────────────────────────────────

PROTOCOL_V1 = 0x01
PROTOCOL_V2 = 0x02

_CMD_HEADER = struct.Struct("<BBBBIIIQ")   # 24 bytes
_RESP_HEADER = struct.Struct("<BBHIIQ")    # 20 bytes
CMD_HEADER_LEN = _CMD_HEADER.size
RESP_HEADER_LEN = _RESP_HEADER.size
assert CMD_HEADER_LEN == 24 and RESP_HEADER_LEN == 20

MAX_PAYLOAD = 64 * 1024 * 1024  # refuse to allocate on a corrupt length field


class Op(IntEnum):
    """Opcodes from the vendored client library's ``types.rs``.

    Presence here means the *protocol* defines it, not that the server answers
    it. Ask :mod:`core.store.capability`.
    """

    PING = 0x01
    SET = 0x02
    GET = 0x03
    DELETE = 0x04
    CAS = 0x05
    SUBSCRIBE = 0x06
    UNSUBSCRIBE = 0x07
    PUBLISH = 0x08
    FETCH = 0x09
    INFO = 0x0A
    AUTH = 0x10
    AUTH_RESPONSE = 0x11
    QUERY = 0x12
    INSERT_DOC = 0x13
    UPDATE_DOC = 0x14
    DELETE_DOC = 0x15
    CREATE_COLLECTION = 0x16
    DROP_COLLECTION = 0x17
    LIST_COLLECTIONS = 0x18
    CREATE_INDEX = 0x19
    DROP_INDEX = 0x1A
    LIST_INDEXES = 0x1B
    LPUSH = 0x20
    RPUSH = 0x21
    LPOP = 0x22
    RPOP = 0x23
    LRANGE = 0x24
    LLEN = 0x25
    SADD = 0x26
    SREM = 0x27
    SMEMBERS = 0x28
    SISMEMBER = 0x29
    SCARD = 0x2A
    ZADD = 0x2E
    ZREM = 0x2F
    ZRANGE = 0x30
    ZCARD = 0x32
    ZSCORE = 0x33
    HSET = 0x34
    HGET = 0x35
    HDEL = 0x36
    HGETALL = 0x37


class Status(IntEnum):
    OK = 0x00
    ERROR = 0x01
    NOT_FOUND = 0x02
    FULL = 0x03
    TIMEOUT = 0x04
    VERSION_MISMATCH = 0x05
    AUTH_REQUIRED = 0x06


# ── Errors ──────────────────────────────────────────────────────────────────


class VedDbError(RuntimeError):
    """Any VedDB failure."""


class VedDbConnectionLost(VedDbError):
    """The socket closed mid-exchange. The connection is not reusable."""


class VedDbDesync(VedDbError):
    """A response arrived for the wrong sequence number.

    Fatal for the connection: the byte stream is no longer interpretable, and
    continuing would attribute one record's bytes to another key. The pool
    discards the connection rather than papering over it.
    """


class VedDbUnsupported(VedDbError):
    """The server build does not implement this opcode.

    Distinct from ``VedDbError`` on purpose: callers may legitimately fall back
    to an application-level implementation (that is the whole design of
    :mod:`core.store.kvdoc`), but must never silently treat "unknown command" as
    "operation succeeded".
    """


class VedDbFull(VedDbError):
    """The store rejected a write for lack of space."""


@dataclass(frozen=True)
class Response:
    status: Status | int
    payload: bytes
    extra: int = 0

    @property
    def ok(self) -> bool:
        return self.status == Status.OK

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", errors="replace")


def _classify(resp: Response, op: Op, key: str) -> None:
    """Turn a non-OK status into the right exception, or return."""
    if resp.ok or resp.status == Status.NOT_FOUND:
        return
    detail = resp.text.strip()
    if resp.status == Status.TIMEOUT and "unknown command" in detail.lower():
        # The server overloads Timeout(4) for unimplemented opcodes rather than
        # defining a distinct status. Discriminate on the payload text, because
        # a genuine timeout and an unimplemented opcode need opposite handling:
        # retry the first, never the second.
        raise VedDbUnsupported(f"{op.name} is not implemented by this server build")
    if resp.status == Status.FULL:
        raise VedDbFull(f"{op.name} {key!r}: store is full")
    raise VedDbError(f"{op.name} {key!r} → status {resp.status} {detail!r}")


# ── One connection ──────────────────────────────────────────────────────────


class VedDbConnection:
    """A single framed request/response channel.

    Not multiplexed: the protocol carries a sequence number but the server
    answers in order on one stream, so a lock serialises exchanges and the seq
    is used as a desync *assertion* rather than a demultiplexer. Silently
    tolerating a seq mismatch would mean returning one key's bytes for another.
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._lock = asyncio.Lock()
        self._seq = 0
        self.broken = False

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), timeout=self.timeout
        )
        self.broken = False

    async def close(self) -> None:
        writer, self._writer, self._reader = self._writer, None, None
        if writer is None:
            return
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    @property
    def connected(self) -> bool:
        return self._writer is not None and not self.broken

    async def execute(
        self,
        op: Op | int,
        key: bytes = b"",
        value: bytes = b"",
        extra: int = 0,
        version: int = PROTOCOL_V2,
    ) -> Response:
        """Send one command, read one response. Raises on transport failure."""
        if self._reader is None or self._writer is None:
            await self.connect()
        assert self._reader is not None and self._writer is not None

        async with self._lock:
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            seq = self._seq
            frame = _CMD_HEADER.pack(
                int(op), 0, version, 0, seq, len(key), len(value), extra
            )
            try:
                self._writer.write(frame + key + value)
                await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)
                head = await asyncio.wait_for(
                    self._reader.readexactly(RESP_HEADER_LEN), timeout=self.timeout
                )
                status, _flags, _res, rseq, plen, rextra = _RESP_HEADER.unpack(head)
                if plen > MAX_PAYLOAD:
                    self.broken = True
                    raise VedDbDesync(
                        f"response claims a {plen}-byte payload; refusing to allocate"
                    )
                payload = (
                    await asyncio.wait_for(
                        self._reader.readexactly(plen), timeout=self.timeout
                    )
                    if plen
                    else b""
                )
            except asyncio.IncompleteReadError as exc:
                self.broken = True
                raise VedDbConnectionLost(
                    f"connection closed after {len(exc.partial)} of "
                    f"{exc.expected} expected bytes"
                ) from exc
            except (asyncio.TimeoutError, OSError) as exc:
                self.broken = True
                raise VedDbConnectionLost(f"{type(exc).__name__}: {exc}") from exc

            if rseq != seq:
                self.broken = True
                raise VedDbDesync(f"expected seq {seq}, got {rseq}")

        try:
            status_enum: Status | int = Status(status)
        except ValueError:
            status_enum = status
        return Response(status_enum, payload, rextra)


# ── Pooled client ───────────────────────────────────────────────────────────


class VedDbClient:
    """Namespaced, pooled VedDB access.

    Every key is written as ``<namespace>:<key>``. The namespace is not a
    convenience — this instance also holds the messenger's live ``user:*`` and
    ``messages:*`` records, and an unprefixed SOC write could overwrite one.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 50051,
        pool_size: int = 8,
        timeout: float = 5.0,
        namespace: str = "soc",
    ) -> None:
        if not namespace or ":" in namespace:
            raise ValueError(f"namespace must be non-empty and colon-free: {namespace!r}")
        self.host = host
        self.port = port
        self.pool_size = max(1, pool_size)
        self.timeout = timeout
        self.namespace = namespace
        self._prefix = f"{namespace}:"
        self._pool: asyncio.Queue[VedDbConnection] | None = None
        self._all: list[VedDbConnection] = []
        self._started = False

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._started:
            return
        self._pool = asyncio.Queue(maxsize=self.pool_size)
        # Open one eagerly so a wrong host/port fails at startup rather than on
        # the first alert write. The rest connect lazily.
        first = VedDbConnection(self.host, self.port, self.timeout)
        await first.connect()
        self._all.append(first)
        await self._pool.put(first)
        for _ in range(self.pool_size - 1):
            conn = VedDbConnection(self.host, self.port, self.timeout)
            self._all.append(conn)
            await self._pool.put(conn)
        self._started = True

    async def close(self) -> None:
        self._started = False
        for conn in self._all:
            await conn.close()
        self._all.clear()
        self._pool = None

    async def __aenter__(self) -> "VedDbClient":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    @contextlib.asynccontextmanager
    async def _acquire(self) -> AsyncIterator[VedDbConnection]:
        if self._pool is None:
            await self.start()
        assert self._pool is not None
        conn = await self._pool.get()
        try:
            if conn.broken:
                # A desynced or dropped connection is replaced, not reused.
                await conn.close()
                replacement = VedDbConnection(self.host, self.port, self.timeout)
                try:
                    self._all[self._all.index(conn)] = replacement
                except ValueError:  # pragma: no cover
                    self._all.append(replacement)
                conn = replacement
            yield conn
        finally:
            self._pool.put_nowait(conn)

    # ── keys ───────────────────────────────────────────────────────────────

    def full_key(self, key: str) -> str:
        """Namespace-qualify a key.

        Idempotent, so a caller that already holds a full key (an index member,
        say) can pass it straight back in. Newlines and NULs are rejected: they
        cannot appear in a key this system generates, so their presence means a
        caller is interpolating unvalidated event data into a key name.
        """
        if not key:
            raise ValueError("empty key")
        if "\n" in key or "\x00" in key:
            raise ValueError(f"key contains a control character: {key!r}")
        if key.startswith(self._prefix):
            return key
        return self._prefix + key

    def strip_key(self, full: str) -> str:
        return full[len(self._prefix):] if full.startswith(self._prefix) else full

    # ── operations ─────────────────────────────────────────────────────────

    async def raw(
        self, op: Op | int, key: bytes = b"", value: bytes = b"", extra: int = 0
    ) -> Response:
        """Send an arbitrary opcode without namespacing or status handling.

        Used by the capability probe, which must be able to observe
        ``unknown command`` as data rather than have it raised.
        """
        async with self._acquire() as conn:
            return await conn.execute(op, key, value, extra)

    async def ping(self) -> bool:
        resp = await self.raw(Op.PING)
        return resp.ok and resp.payload.strip() == b"pong"

    async def set_bytes(self, key: str, value: bytes) -> None:
        fk = self.full_key(key)
        async with self._acquire() as conn:
            resp = await conn.execute(Op.SET, fk.encode(), value)
        _classify(resp, Op.SET, fk)
        if not resp.ok:
            raise VedDbError(f"SET {fk!r} → status {resp.status}")

    async def get_bytes(self, key: str) -> bytes | None:
        """Read a key. ``None`` means absent.

        Absent is signalled by ``ERROR`` with an empty payload, not by
        ``NOT_FOUND`` — this build never emits status 2. Verified: GET of a
        key that was never written returns status 1 with a zero-length payload,
        byte for byte the same as GET of an empty key name.

        The honest cost: on this build a genuine internal read error carrying no
        message is indistinguishable from a miss, so it is reported as a miss.
        An error *with* a message is still raised. Nothing can be done about the
        ambiguity from the client side; recording it here is better than
        pretending the mapping is exact.
        """
        fk = self.full_key(key)
        async with self._acquire() as conn:
            resp = await conn.execute(Op.GET, fk.encode())
        if resp.status == Status.NOT_FOUND:
            return None
        if resp.status == Status.ERROR and not resp.payload:
            return None
        _classify(resp, Op.GET, fk)
        # An empty payload with status OK is a stored empty value, which is a
        # different thing from a missing key. Preserve the distinction.
        return resp.payload

    async def delete(self, key: str) -> bool:
        """Delete a key. Returns whether it existed.

        As with GET, a missing key comes back as ``ERROR`` with an empty
        payload, so that is reported as ``False`` rather than raised.
        """
        fk = self.full_key(key)
        async with self._acquire() as conn:
            resp = await conn.execute(Op.DELETE, fk.encode())
        if resp.status == Status.NOT_FOUND:
            return False
        if resp.status == Status.ERROR and not resp.payload:
            return False
        _classify(resp, Op.DELETE, fk)
        return resp.ok

    async def exists(self, key: str) -> bool:
        return await self.get_bytes(key) is not None

    async def list_keys(self, prefix: str | None = None) -> list[str]:
        """Every key in the store, optionally filtered by prefix.

        FETCH (0x09) is **not** a get. It ignores its key argument entirely and
        returns the whole keyspace, newline-separated, in hash order — verified
        by calling it with an empty key, a nonsense key, a prefix and a glob and
        getting byte-identical results each time. So ``prefix`` is filtered
        *client-side*, and the server cost is proportional to the total number of
        keys in the instance, including the messenger's.

        Measured: 5,007 keys → 85 KB in ~1 ms. Cheap now, linear forever. It is
        therefore an **administrative** operation — index repair, orphan
        detection, integrity scans — and must not appear on a per-event path.
        :mod:`core.store.kvdoc` uses explicit ``idx:`` keys for lookups for
        exactly this reason.
        """
        async with self._acquire() as conn:
            resp = await conn.execute(Op.FETCH, b"")
        _classify(resp, Op.FETCH, "*")
        if not resp.ok:
            raise VedDbError(f"FETCH → status {resp.status}")
        keys = [
            k for k in resp.payload.decode("utf-8", errors="replace").split("\n") if k
        ]
        scoped = [k for k in keys if k.startswith(self._prefix)]
        if prefix:
            full_prefix = self.full_key(prefix)
            scoped = [k for k in scoped if k.startswith(full_prefix)]
        return scoped

    async def count_keys(self, prefix: str | None = None) -> int:
        return len(await self.list_keys(prefix))

    # ── JSON convenience ───────────────────────────────────────────────────

    async def set_json(self, key: str, value: Any) -> None:
        await self.set_bytes(
            key, json.dumps(value, separators=(",", ":"), default=str).encode()
        )

    async def get_json(self, key: str) -> Any | None:
        raw = await self.get_bytes(key)
        if raw is None:
            return None
        if raw == b"":
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            # Corruption, or someone else's key inside our namespace. Either way
            # do not hand back a half-parsed object.
            raise VedDbError(
                f"{self.full_key(key)!r} does not contain valid JSON: {exc}"
            ) from exc

    # ── batch helpers ──────────────────────────────────────────────────────

    async def set_many(self, items: dict[str, Any]) -> None:
        """Write many JSON values concurrently across the pool.

        Not atomic — the server has no transaction and no CAS. Callers needing
        all-or-nothing use :mod:`core.store.kvdoc`, which writes an intent
        record first so a partial application is repairable.
        """
        await asyncio.gather(*(self.set_json(k, v) for k, v in items.items()))

    async def get_many(self, keys: list[str]) -> dict[str, Any | None]:
        values = await asyncio.gather(*(self.get_json(k) for k in keys))
        return dict(zip(keys, values))

    async def delete_many(self, keys: list[str]) -> int:
        results = await asyncio.gather(
            *(self.delete(k) for k in keys), return_exceptions=True
        )
        return sum(1 for r in results if r is True)

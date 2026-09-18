"""
Tamper-evident audit chain.

Every consequential act the SOC takes — a rule firing, an LLM call, an account
disabled, a partition deleted, a legal hold placed — is appended here as a record
whose hash covers the hash of the record before it. Changing any earlier record
changes its hash, which breaks the link its successor recorded, and so on to the
head. :meth:`AuditChain.verify` walks the chain and reports the first seq where
that breaks.

This exists because the platform is autonomous. When it disables an executive's
account at 03:00 there is no analyst who remembers doing it, so the record *is*
the account of what happened — for the post-incident review, for the auditor, and
potentially for a court. A log that can be edited without trace cannot serve any
of those.

The pattern is ported from ``web-app/src/services/defense.service.js:227``, which
chains SHA-256 the same way but keeps the chain in a browser array capped at 1000
entries, client-side and lost on refresh. This one is server-side, on disk,
fsynced, unbounded and verifiable.

── What this does and does not defend against ─────────────────────────────
Stated plainly, because "tamper-proof" is a claim this cannot honour and
"tamper-evident" is one it can.

*Detected:*

* editing a record in place — its hash no longer matches its content
* deleting a record — the successor's ``prev`` points at nothing present
* inserting or reordering records — the same link check fails
* truncating the tail — the head no longer matches the anchored head hash
* rolling the file back to an earlier state — same

*Not detected by hash chaining alone:* an attacker who can write the chain files
**and** recompute every hash from the tampered point to the head. Hash chaining
makes a record's integrity depend on its neighbours, not on a secret, so anyone
who can rewrite all of them produces a chain that verifies perfectly.

Two defences are implemented against exactly that, and both are optional because
each has a real cost:

1. **HMAC** (``hmac_key``). Each record's digest is keyed, so recomputation
   requires the key. Effective only while the key is not on the same host as the
   chain — otherwise an attacker who took the host took both. Configure it from
   an environment variable that is not written to disk next to the chain.
2. **External anchor** (``anchor``). The head ``(seq, hash)`` is published to a
   second store — VedDB by default, a different process with a different
   lifetime. A rewritten chain still has to match an anchor the attacker also
   has to reach, and any mismatch is loud.

With neither, the honest claim is: **tampering by anyone who cannot reach both
the chain directory and the anchor store is detected; tampering by someone with
full local privilege on this host is not.** That is the normal limit of local
append-only logging and the reason real deployments ship these records off-host.

── Durability ─────────────────────────────────────────────────────────────
Each append is written, flushed and ``fsync``ed before it is acknowledged. That
caps throughput at the disk's sync rate — a few hundred to a few thousand records
a second — which is the right trade here and the opposite of the choice made in
:mod:`core.store.lake`, where buffering telemetry is fine because the lake is a
copy. An audit record that exists only in a page cache is an audit record that a
power cut removes from the account of what happened.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

GENESIS_HASH = "0" * 64

#: Records per segment file. Segments keep any single file openable by ordinary
#: tools and let verification report progress, but they are a storage detail —
#: the chain is logically one sequence and verification always crosses segments.
SEGMENT_RECORDS = 100_000

#: Fields covered by the digest, in this order. Adding a field here changes every
#: future hash, so it is a format version boundary.
_DIGEST_FIELDS = ("seq", "ts", "actor", "action", "target", "data", "prev")


class ChainError(RuntimeError):
    """An audit chain failure."""


class ChainBroken(ChainError):
    """Verification found a break. The chain's integrity claim is void."""


class Anchor(Protocol):
    """Somewhere to publish the head hash that is not the chain directory."""

    async def publish(self, seq: int, head_hash: str) -> None: ...
    async def read(self) -> tuple[int, str] | None: ...


class VedDbAnchor:
    """Publishes the head to VedDB — a different process on a different disk path.

    Not a strong anchor (an attacker on this host can reach both), but it means
    tampering has to be coordinated across two stores instead of one, and a
    corrupted or rolled-back chain directory alone is caught.
    """

    def __init__(self, client: Any, key: str = "audit:head") -> None:
        self.client = client
        self.key = key

    async def publish(self, seq: int, head_hash: str) -> None:
        await self.client.set_json(
            self.key, {"seq": seq, "hash": head_hash, "at": time.time()}
        )

    async def read(self) -> tuple[int, str] | None:
        rec = await self.client.get_json(self.key)
        if not rec:
            return None
        return int(rec["seq"]), str(rec["hash"])


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: float
    actor: str
    action: str
    target: str | None
    data: dict[str, Any]
    prev: str
    hash: str

    def digest_payload(self) -> bytes:
        """Canonical bytes the hash covers.

        ``sort_keys`` and fixed separators matter: two JSON encodings of the same
        record that differ only in key order or whitespace would hash
        differently, and the chain would fail to verify against itself after any
        change to how it serialises.
        """
        body = {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "data": self.data,
            "prev": self.prev,
        }
        return json.dumps(
            body, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
        ).encode("utf-8")

    def compute(self, hmac_key: bytes | None) -> str:
        payload = self.digest_payload()
        if hmac_key:
            return hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()

    def to_line(self) -> bytes:
        return (
            json.dumps(
                {
                    "seq": self.seq,
                    "ts": self.ts,
                    "actor": self.actor,
                    "action": self.action,
                    "target": self.target,
                    "data": self.data,
                    "prev": self.prev,
                    "hash": self.hash,
                },
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def from_line(line: str) -> "AuditRecord":
        raw = json.loads(line)
        return AuditRecord(
            seq=int(raw["seq"]),
            ts=float(raw["ts"]),
            actor=str(raw["actor"]),
            action=str(raw["action"]),
            target=raw.get("target"),
            data=raw.get("data") or {},
            prev=str(raw["prev"]),
            hash=str(raw["hash"]),
        )


@dataclass
class VerifyResult:
    ok: bool
    records: int
    head_seq: int
    head_hash: str
    checked_from: int
    failures: list[dict[str, Any]] = field(default_factory=list)
    anchor_state: str = "not-configured"
    duration_s: float = 0.0

    def report(self) -> str:
        lines = [
            "Audit chain verification",
            f"  records checked : {self.records:,} (from seq {self.checked_from})",
            f"  head            : seq {self.head_seq} {self.head_hash[:16]}…",
            f"  anchor          : {self.anchor_state}",
            f"  duration        : {self.duration_s * 1000:.0f} ms",
            f"  result          : {'INTACT' if self.ok else 'BROKEN'}",
        ]
        for f in self.failures:
            lines.append(f"    ! seq {f.get('seq')}: {f.get('reason')}")
        return "\n".join(lines)


class AuditChain:
    """An append-only, hash-chained, fsynced record of what the SOC did."""

    def __init__(
        self,
        directory: str | Path,
        checkpoint_every: int = 500,
        hmac_key: bytes | None = None,
        anchor: Anchor | None = None,
        segment_records: int = SEGMENT_RECORDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_every = max(1, checkpoint_every)
        self.hmac_key = hmac_key
        self.anchor = anchor
        self.segment_records = max(1, segment_records)
        self._clock = clock
        self._lock = asyncio.Lock()
        self._seq = 0
        self._head = GENESIS_HASH
        self._handle: Any = None
        self._handle_segment = -1
        self._since_checkpoint = 0
        self._loaded = False
        self._anchor_note = "not-configured"

    # ── layout ─────────────────────────────────────────────────────────────

    def segment_path(self, index: int) -> Path:
        return self.dir / f"chain-{index:06d}.jsonl"

    @property
    def checkpoint_path(self) -> Path:
        return self.dir / "checkpoints.jsonl"

    def segments(self) -> list[Path]:
        return sorted(self.dir.glob("chain-*.jsonl"))

    def _segment_for(self, seq: int) -> int:
        # seq is 1-based; record 1 belongs in segment 0.
        return (seq - 1) // self.segment_records

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def open(self, verify: bool = False) -> VerifyResult | None:
        """Load the head from disk. Optionally verify before accepting writes.

        Verifying at startup is the difference between finding out the chain was
        tampered with now and finding out during an audit. It costs a full read,
        so it is a config decision (``audit.verify_on_start``), not forced.
        """
        async with self._lock:
            result = None
            if verify:
                result = await asyncio.to_thread(self._verify_sync, 0)
                if not result.ok:
                    # Refuse to extend a chain that is already broken: appending
                    # onto a compromised chain launders the break behind valid
                    # new links and destroys the ability to say when it happened.
                    raise ChainBroken(
                        "audit chain failed verification at startup; refusing to "
                        "append. " + result.report()
                    )
            last = self._last_record_sync()
            if last is not None:
                self._seq, self._head = last.seq, last.hash
            self._loaded = True
            if self.anchor is not None:
                await self._check_anchor()
                await self.anchor.publish(self._seq, self._head)
            if result is not None:
                result.anchor_state = self._anchor_note
            return result

    async def _check_anchor(self) -> None:
        assert self.anchor is not None
        published = await self.anchor.read()
        if published is None:
            self._anchor_note = "no prior anchor (first run)"
            return
        aseq, ahash = published
        if aseq == self._seq and ahash == self._head:
            self._anchor_note = f"matches head (seq {aseq})"
        elif aseq > self._seq:
            # The anchor remembers records the chain no longer has. That is the
            # signature of a truncation or rollback, which hash chaining alone
            # cannot see because the shortened chain is internally consistent.
            self._anchor_note = (
                f"MISMATCH: anchor holds seq {aseq} but the chain ends at "
                f"{self._seq} — records are missing from the chain files"
            )
            raise ChainBroken(self._anchor_note)
        else:
            self._anchor_note = (
                f"MISMATCH: anchor holds seq {aseq} {ahash[:12]}… but the chain "
                f"head is seq {self._seq} {self._head[:12]}…"
            )
            raise ChainBroken(self._anchor_note)

    async def close(self) -> None:
        async with self._lock:
            if self._handle is not None:
                await asyncio.to_thread(self._close_handle)

    def _close_handle(self) -> None:
        try:
            self._handle.flush()
            os.fsync(self._handle.fileno())
        finally:
            self._handle.close()
            self._handle = None
            self._handle_segment = -1

    # ── append ─────────────────────────────────────────────────────────────

    async def append(
        self,
        action: str,
        actor: str = "system",
        target: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Append one record. Returns only after it is on disk.

        ``actor`` is who or what did it — an operator id, ``"system"``, or the
        module name for an autonomous act. ``action`` is a stable dotted verb
        (``response.block_ip``, ``llm.call``, ``retention.drop_partition``) so the
        chain is queryable by activity class rather than by free text.
        """
        if not action:
            raise ChainError("an audit record needs an action")
        async with self._lock:
            if not self._loaded:
                last = self._last_record_sync()
                if last is not None:
                    self._seq, self._head = last.seq, last.hash
                self._loaded = True
            record = AuditRecord(
                seq=self._seq + 1,
                ts=self._clock(),
                actor=actor,
                action=action,
                target=target,
                data=data or {},
                prev=self._head,
                hash="",
            )
            record = replace(record, hash=record.compute(self.hmac_key))
            await asyncio.to_thread(self._write_sync, record)
            self._seq, self._head = record.seq, record.hash
            self._since_checkpoint += 1
            if self._since_checkpoint >= self.checkpoint_every:
                await asyncio.to_thread(self._write_checkpoint_sync)
                self._since_checkpoint = 0
                if self.anchor is not None:
                    await self.anchor.publish(self._seq, self._head)
            return record

    def _write_sync(self, record: AuditRecord) -> None:
        segment = self._segment_for(record.seq)
        if self._handle is None or self._handle_segment != segment:
            if self._handle is not None:
                self._close_handle()
            self._handle = open(self.segment_path(segment), "ab", buffering=0)
            self._handle_segment = segment
        self._handle.write(record.to_line())
        os.fsync(self._handle.fileno())

    def _write_checkpoint_sync(self) -> None:
        """Record the head so verification can be bounded.

        A checkpoint is a *convenience*, not a trust root: it lets an operator
        verify only the records added since the last known-good point. It cannot
        be a trust root on its own, because whoever can rewrite the chain can
        rewrite the checkpoint file next to it. Full verification always starts
        at genesis.
        """
        line = (
            json.dumps(
                {
                    "seq": self._seq,
                    "hash": self._head,
                    "at": self._clock(),
                    "keyed": bool(self.hmac_key),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with open(self.checkpoint_path, "ab", buffering=0) as fh:
            fh.write(line)
            os.fsync(fh.fileno())

    # ── read ───────────────────────────────────────────────────────────────

    def records(self, start_seq: int = 1, limit: int | None = None) -> Iterator[AuditRecord]:
        """Iterate records in order. Streams; does not load the chain into memory."""
        emitted = 0
        for path in self.segments():
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    record = AuditRecord.from_line(line)
                    if record.seq < start_seq:
                        continue
                    yield record
                    emitted += 1
                    if limit is not None and emitted >= limit:
                        return

    def _last_record_sync(self) -> AuditRecord | None:
        segments = self.segments()
        if not segments:
            return None
        for path in reversed(segments):
            last_line = None
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last_line = line
            if last_line:
                return AuditRecord.from_line(last_line)
        return None

    def head(self) -> tuple[int, str]:
        return self._seq, self._head

    def checkpoints(self) -> list[dict[str, Any]]:
        if not self.checkpoint_path.exists():
            return []
        out = []
        with open(self.checkpoint_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return out

    async def search(
        self,
        action_prefix: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 500,
    ) -> list[AuditRecord]:
        """Linear scan over the chain.

        Deliberately not indexed. Indexing would mean a second structure that
        could disagree with the chain, and the chain's whole value is that it is
        the one authoritative sequence. Audit *reporting* at scale reads the
        chain's mirror in the lake instead; this is for direct inspection.
        """

        def _scan() -> list[AuditRecord]:
            out: list[AuditRecord] = []
            for record in self.records():
                if action_prefix and not record.action.startswith(action_prefix):
                    continue
                if actor and record.actor != actor:
                    continue
                if target and record.target != target:
                    continue
                if since is not None and record.ts < since:
                    continue
                if until is not None and record.ts > until:
                    continue
                out.append(record)
                if len(out) >= limit:
                    break
            return out

        return await asyncio.to_thread(_scan)

    # ── verify ─────────────────────────────────────────────────────────────

    async def verify(self, since_seq: int = 0) -> VerifyResult:
        """Walk the chain and confirm every link.

        ``since_seq`` bounds the walk for routine checks. It cannot be trusted
        for an audit: everything before it is unexamined, so a break there is
        invisible. Leave it at 0 for the real answer.
        """
        result = await asyncio.to_thread(self._verify_sync, since_seq)
        if self.anchor is not None:
            published = await self.anchor.read()
            if published is None:
                result.anchor_state = "no anchor recorded"
            elif published == (result.head_seq, result.head_hash):
                result.anchor_state = f"matches head (seq {published[0]})"
            else:
                result.anchor_state = (
                    f"MISMATCH: anchor {published[0]} {published[1][:12]}… vs head "
                    f"{result.head_seq} {result.head_hash[:12]}…"
                )
                result.ok = False
                result.failures.append(
                    {"seq": result.head_seq, "reason": result.anchor_state}
                )
        return result

    def _verify_sync(self, since_seq: int) -> VerifyResult:
        started = time.perf_counter()
        failures: list[dict[str, Any]] = []
        count = 0
        expected_seq: int | None = None
        prev_hash: str | None = None
        head_seq, head_hash = 0, GENESIS_HASH

        if since_seq > 1:
            # Resume from a checkpoint at or before since_seq so the first record
            # examined has a known-good predecessor to link against.
            anchor_cp = None
            for cp in self.checkpoints():
                if cp["seq"] < since_seq and (anchor_cp is None or cp["seq"] > anchor_cp["seq"]):
                    anchor_cp = cp
            if anchor_cp is not None:
                expected_seq = anchor_cp["seq"] + 1
                prev_hash = anchor_cp["hash"]

        for record in self.records(start_seq=max(1, since_seq)):
            count += 1
            if expected_seq is None:
                expected_seq = record.seq
                if record.seq == 1 and record.prev != GENESIS_HASH:
                    failures.append(
                        {"seq": 1, "reason": f"genesis prev is {record.prev[:16]}…, "
                         f"expected {GENESIS_HASH[:16]}…"}
                    )
                prev_hash = record.prev
            if record.seq != expected_seq:
                failures.append(
                    {
                        "seq": record.seq,
                        "reason": f"sequence gap: expected {expected_seq}, found "
                        f"{record.seq} — {abs(record.seq - expected_seq)} record(s) "
                        "inserted or removed",
                    }
                )
                expected_seq = record.seq
            if prev_hash is not None and record.prev != prev_hash:
                failures.append(
                    {
                        "seq": record.seq,
                        "reason": f"broken link: prev is {record.prev[:16]}… but the "
                        f"preceding record hashes to {prev_hash[:16]}…",
                    }
                )
            recomputed = record.compute(self.hmac_key)
            if recomputed != record.hash:
                failures.append(
                    {
                        "seq": record.seq,
                        "reason": f"content does not match its hash (stored "
                        f"{record.hash[:16]}…, recomputed {recomputed[:16]}…) — this "
                        f"record was modified after it was written",
                    }
                )
                # Continue with the *stored* hash so the next link is judged
                # against what is on disk. Substituting the recomputed one would
                # report a second, phantom failure at seq+1.
            prev_hash = record.hash
            expected_seq = record.seq + 1
            head_seq, head_hash = record.seq, record.hash

        return VerifyResult(
            ok=not failures,
            records=count,
            head_seq=head_seq,
            head_hash=head_hash,
            checked_from=max(1, since_seq),
            failures=failures,
            duration_s=time.perf_counter() - started,
        )

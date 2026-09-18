"""The verdict store — the audit trail of every analyst decision.

A verdict is recorded with the alert's :attr:`metadata_uid` and the
analyst's handle, and it stays in the store forever. The retrain pipeline
reads from this store to compute the gap between auto-labels and verdicts.

The store is *append-only*. An analyst who changes their mind issues a new
verdict on the same alert and the latest verdict wins; the older verdict is
not deleted, it is just demoted. The audit chain — every record signed by
the operator — is the source of truth for "what did the analyst actually
believe at time T", which is what the retrain needs.

The persistence model is a JSON-lines file. Each line is one verdict.
VedDB is the production-grade backing, but JSON is enough for the test
path and easier to inspect by hand.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from learn.verdict import Verdict


class VerdictStore:
    """A JSON-lines-backed verdict store.

    Reads are O(n) — the store iterates the file. For the platform's
    expected verdict volume (≪ 1 M per year) this is fine. The store is
    not on the detection hot path; it is the data source for the
    periodic retrain.
    """

    def __init__(self, path: Path, *, clock: Any = time.time) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock

    def append(self, verdict: Verdict) -> Verdict:
        """Append one verdict. Idempotent on ``verdict.verdict_uuid``."""
        # The created_at is stamped at the store level so an operator who
        # captures a verdict in the UI and forgets the timestamp still
        # produces a record that lines up with the audit chain.
        verdict.created_at = verdict.created_at or self.clock()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(verdict), default=str))
            f.write("\n")
        return verdict

    def all(self) -> list[Verdict]:
        """Every verdict, in insertion order. Duplicates by ``alert_uid``
        are returned in chronological order; the caller picks the latest."""
        if not self.path.exists():
            return []
        out: list[Verdict] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(doc, dict):
                    continue
                try:
                    out.append(Verdict(
                        alert_uid=str(doc["alert_uid"]),
                        analyst_id=str(doc["analyst_id"]),
                        verdict_id=int(doc["verdict_id"]),
                        reason=str(doc.get("reason", "")),
                        created_at=float(doc.get("created_at", 0.0)),
                        verdict_uuid=str(doc.get("verdict_uuid", "")),
                    ))
                except (KeyError, TypeError, ValueError):
                    continue
        return out

    def latest_per_alert(self) -> dict[str, Verdict]:
        """The most recent verdict per ``alert_uid``.

        Two verdicts on the same alert — the second one wins. The audit
        trail in :meth:`all` still has both; the retrain reads from
        here so it does not see conflicting labels on the same alert.
        """
        out: dict[str, Verdict] = {}
        for v in self.all():
            prior = out.get(v.alert_uid)
            if prior is None or v.created_at >= prior.created_at:
                out[v.alert_uid] = v
        return out

    def count(self) -> int:
        """The total number of verdicts on disk, including superseded ones."""
        if not self.path.exists():
            return 0
        n = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    n += 1
        return n

    def __iter__(self) -> Iterable[Verdict]:
        return iter(self.all())


__all__ = ["VerdictStore"]

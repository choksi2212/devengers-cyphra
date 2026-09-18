"""The audit subsystem — tamper-evident record of every consequential act.

Every consequential act the SOC takes — a rule firing, an LLM call,
an account disabled, a partition deleted, a legal hold placed — is
appended here as a record whose hash covers the hash of the record
before it. :meth:`AuditChain.verify` walks the chain and reports
the first seq where that breaks.

The chain lives at ``<audit.chain_dir>`` (default
``cyphra-soc/var/audit/``), split into segments of
``segment_records`` each (``25`` by default), with a separate
checkpoint file that is the anchor a rewind-to-earlier-state
attack has to defeat in addition to the chain links.

What this defends against, and what it cannot, is documented on
:class:`AuditChain` and :class:`AuditRecord` rather than here — the
operational question is "what was decided and when", which is the
record's content, not its hash.
"""

from core.audit.chain import (
    GENESIS_HASH,
    SEGMENT_RECORDS,
    Anchor,
    AuditChain,
    AuditRecord,
    ChainBroken,
    ChainError,
    VedDbAnchor,
    VerifyResult,
)

__all__ = [
    "Anchor",
    "AuditChain",
    "AuditRecord",
    "ChainBroken",
    "ChainError",
    "GENESIS_HASH",
    "SEGMENT_RECORDS",
    "VedDbAnchor",
    "VerifyResult",
]

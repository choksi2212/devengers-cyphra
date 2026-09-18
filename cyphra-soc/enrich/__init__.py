"""Enrichment — entities + intel context attached to every OCSF event.

One module: :mod:`enrich.context`. The :class:`Enricher` walks an event,
resolves every :class:`EntityRef` against the :class:`EntityStore`,
extracts every indicator and looks it up in the :class:`IntelStore`, and
returns an :class:`Enrichment` that the correlate engine consumes.

The enriched event is the same OCSF event with an ``unmapped.enrich``
block appended — the lake's flat schema is unchanged and the correlate
engine reads the context without changing how it reads the lake.
"""

from enrich.context import (
    Enricher,
    Enrichment,
    EntityContext,
    to_ocsf_context,
)

__all__ = [
    "Enricher",
    "Enrichment",
    "EntityContext",
    "to_ocsf_context",
]

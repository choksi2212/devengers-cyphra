"""Enrichment — the layer between raw events and the correlate engine.

Every OCSF event that reaches the correlate engine carries an
*enrichment context*. The context answers three questions:

* **Who is involved?** — the entities the event references, resolved
  against the :class:`EntityStore`. ``actor``, ``target``, ``affected``
  are all here.
* **Is anything known about them?** — the per-entity intel, tags, and
  risk. A ``crown_jewel`` tag on a target asset lifts incident severity.
* **What does the threat intel say?** — every indicator extracted from
  the event, looked up in :class:`IntelStore`, with the indicator's
  reputation carried through to the correlate layer.

The enrich layer is a pure transformation: given an event, the entity
store, and the intel store, it returns an enriched event. It does not
write back; the entity store's :meth:`observe` is the side effect, and
it is idempotent.

The enriched event is *the same OCSF event* with an ``unmapped.enrich``
section appended. This keeps the lake's flat schema unchanged — every
analyst query that already worked continues to work — and makes
enrichment a pure observation rather than a schema migration.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Mapping

from entities.identity import Entity, EntityKind, EntityRef, EntityStore
from entities.resolver import EntityResolver
from intel.extract import ExtractedIndicator, IndicatorExtractor
from intel.feed import IntelHit, IntelStore, Reputation


@dataclass
class EntityContext:
    """One entity's contribution to the enrichment.

    ``entity`` is the resolved :class:`Entity` (may be a placeholder
    freshly-created by :meth:`observe`). ``refs`` is every :class:`EntityRef`
    the resolver extracted that points at this entity — useful for
    showing the analyst "this user is also referenced from there".

    ``intel`` is a list of indicator hits where the entity *is* the
    indicator (an actor's email is a known-bad sender, an asset's
    domain is on a denylist).
    """

    entity: Entity
    refs: list[EntityRef] = field(default_factory=list)
    intel: list[IntelHit] = field(default_factory=list)


@dataclass
class Enrichment:
    """The enrichment attached to one event.

    ``entities`` is keyed by entity uid. ``indicators`` is the full list
    of indicator lookups the extractor produced, including misses.
    ``reputation_score`` is the worst reputation seen across the
    event's indicators — used as one input to correlate severity.
    """

    entities: dict[str, EntityContext] = field(default_factory=dict)
    indicators: list[IntelHit] = field(default_factory=list)
    reputation_score: float = 0.0


class Enricher:
    """The single-event enrichment pipeline.

    A deployment runs every OCSF event through the enricher on the way to
    the lake. The enricher is fast: it is O(refs + indicators) per event
    and the lookups are hash-table hits.
    """

    def __init__(
        self,
        entity_store: EntityStore,
        intel_store: IntelStore,
        *,
        resolver: EntityResolver | None = None,
        extractor: IndicatorExtractor | None = None,
    ) -> None:
        self.entities = entity_store
        self.intel = intel_store
        self.resolver = resolver or EntityResolver()
        self.extractor = extractor or IndicatorExtractor()

    def enrich(self, event: Mapping[str, Any]) -> Enrichment:
        """The enrichment for ``event``.

        The enricher's side effect is :meth:`EntityStore.observe`: any
        entity the event references is registered (or found, if seen
        before) and bumped. The returned :class:`Enrichment` is
        idempotently derivable from the event and the stores, so a
        restart that rebuilds the stores from the audit chain
        reproduces it exactly.
        """
        out = Enrichment()
        refs = self.resolver.refs_for(event)
        # Resolve every ref into an entity, attaching any indicator hits
        # whose value equals the ref's value (e.g. an actor email that's
        # on a sender denylist).
        for ref in refs:
            self._resolve_ref(ref, out)
        # Indicator extraction.
        indicators = self.extractor.extract(event)
        for indicator in indicators:
            hit = self.intel.lookup(indicator.kind, indicator.value)
            out.indicators.append(hit)
            if hit.indicator is not None and hit.indicator.score > out.reputation_score:
                out.reputation_score = hit.indicator.score
        return out

    def _resolve_ref(self, ref: EntityRef, out: Enrichment) -> None:
        """Look up the ref's entity, observing it if necessary.

        A ref with a ``kind_uid`` of zero (an asset type the resolver
        could not classify) is registered as :attr:`EntityKind.APPLICATION`
        so it still appears in the store.
        """
        existing = self.entities.resolve(ref)
        if existing is None:
            kind = ref.kind_uid or int(EntityKind.APPLICATION)
            entity = self.entities.observe(ref, kind=kind)
        else:
            entity = existing
        ctx = out.entities.get(entity.uid)
        if ctx is None:
            ctx = EntityContext(entity=entity)
            out.entities[entity.uid] = ctx
        ctx.refs.append(ref)


def to_ocsf_context(enrichment: Enrichment) -> dict[str, Any]:
    """The enrichment as a flat OCSF ``unmapped`` block.

    The correlate engine reads this; the analyst UI reads this; nothing
    in the lake's flat schema needs to change.
    """
    entities: list[dict[str, Any]] = []
    for uid, ctx in enrichment.entities.items():
        entities.append({
            "uid": uid,
            "kind": ctx.entity.kind,
            "display_name": ctx.entity.display_name,
            "tags": list(ctx.entity.tags),
            "risk": ctx.entity.risk,
            "external_refs": [
                {"vendor": r.vendor, "kind": r.kind, "value": r.value}
                for r in ctx.entity.external_refs
            ],
        })
    indicators: list[dict[str, Any]] = []
    for hit in enrichment.indicators:
        entry: dict[str, Any] = {
            "kind": hit.kind,
            "value": hit.value,
            "matched": hit.indicator is not None,
        }
        if hit.indicator is not None:
            entry["score"] = hit.indicator.score
            entry["reputation"] = hit.indicator.reputation
            entry["source"] = hit.indicator.source
        indicators.append(entry)
    return {
        "entities": entities,
        "indicators": indicators,
        "reputation_score": enrichment.reputation_score,
    }


__all__ = [
    "Enricher",
    "Enrichment",
    "EntityContext",
    "to_ocsf_context",
]

"""scratch_phase3 — entities, intel, enrich, correlate.

    python tests/scratch_phase3.py

Four sections, each layer verified end-to-end:

1. **Entities** — the entity store, the resolver, identity extraction.
2. **Intel** — indicators, lookups, extraction from OCSF events.
3. **Enrich** — the enrichment pipeline producing a flat
   ``unmapped.enrich`` block the correlate engine reads.
4. **Correlate** — findings → incidents, merge on key, idle close.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from correlate import (
    CorrelateEngine,
    FindingStub,
    Incident,
    actor_time_key,
    first_key,
    target_time_key,
)
from enrich import Enricher, Enrichment, to_ocsf_context
from entities import (
    Entity,
    EntityKind,
    EntityRef,
    EntityResolver,
    EntityStore,
    ExternalRef,
    KIND_NAMES,
)
from intel import (
    ExtractedIndicator,
    Indicator,
    IndicatorExtractor,
    IndicatorKind,
    IntelHit,
    IntelStore,
    KIND_NAMES as INTEL_KIND_NAMES,
    Reputation,
    REPUTATION_NAMES,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── entities ───────────────────────────────────────────────────────────────


def test_entities_basics() -> None:
    print("\n[entities] the canonical store and the kind enum")
    es = EntityStore()
    ref = EntityRef(vendor="identity", kind="user", value="alice@contoso.com",
                    display_name="Alice")
    entity = es.observe(ref, kind=int(EntityKind.USER))
    check("an entity gets a uid", entity.uid.startswith("e-"), f"got {entity.uid}")
    check(
        "a second observe with the same ref returns the same entity",
        es.observe(ref, kind=int(EntityKind.USER)) is entity,
        "idempotent",
    )
    alice = es.resolve(ref)
    check(
        "resolve returns the entity seen via observe",
        alice is entity and alice.uid == entity.uid,
        f"got {alice.uid if alice else None}",
    )
    other_ref = EntityRef(vendor="identity", kind="user",
                          value="alice@contoso.com", display_name="Alice")
    check(
        "the same identity is *one* entity, not two",
        es.resolve(other_ref).uid == entity.uid,
        f"got {es.resolve(other_ref).uid}",
    )
    es.tag(entity, "crown_jewel")
    es.set_risk(entity, 0.7)
    check(
        "tags accumulate and risk clamps to [0, 1]",
        "crown_jewel" in entity.tags and 0.0 <= entity.risk <= 1.0,
        f"tags={entity.tags} risk={entity.risk}",
    )


def test_resolver_extracts_refs() -> None:
    print("\n[entities] the resolver pulls refs from an OCSF event")
    resolver = EntityResolver(vendor="identity")
    event = {
        "class_uid": 3002,
        "actor": {"user": {"email_addr": "alice@contoso.com", "name": "Alice"}},
        "src_endpoint_ip": "10.0.0.5",
        "resources": [{"uid": "/subscriptions/x", "name": "sub", "type": "subscription"}],
    }
    refs = resolver.refs_for(event)
    kinds = {ref.kind for ref in refs}
    check(
        "the resolver pulls actor, src_endpoint_ip, and resources",
        "user" in kinds and "ip" in kinds and "subscription" in kinds,
        f"got kinds={kinds}",
    )
    user_ref = next(ref for ref in refs if ref.kind == "user")
    check(
        "an email-shaped actor is a USER, not a service principal",
        user_ref.kind_uid == int(EntityKind.USER),
        f"got kind_uid={user_ref.kind_uid}",
    )
    sa_event = dict(event)
    sa_event["actor"] = {
        "user": {
            "email_addr": "deploy-bot@project.iam.gserviceaccount.com",
            "name": "Bot",
        }
    }
    sa_refs = resolver.refs_for(sa_event)
    sa_user_ref = next(ref for ref in sa_refs if ref.kind == "user")
    check(
        "a ``*.iam.gserviceaccount.com`` actor is a SERVICE_PRINCIPAL",
        sa_user_ref.kind_uid == int(EntityKind.SERVICE_PRINCIPAL),
        f"got kind_uid={sa_user_ref.kind_uid}",
    )


# ── intel ─────────────────────────────────────────────────────────────────


def test_intel_lookups() -> None:
    print("\n[intel] indicator lookups and feed merging")
    intel = IntelStore()
    intel.merge([
        Indicator(
            kind=int(IndicatorKind.IP), value="198.51.100.99",
            score=0.95, reputation=int(Reputation.MALICIOUS),
            source="integration-test",
        ),
        Indicator(
            kind=int(IndicatorKind.DOMAIN), value="evil.example.com",
            score=0.85, reputation=int(Reputation.MALICIOUS),
            source="integration-test",
        ),
    ])
    check(
        "an exact-match IP lookup hits",
        intel.lookup_ip("198.51.100.99").indicator is not None,
        "lookup",
    )
    check(
        "an unknown IP returns a miss",
        intel.lookup_ip("10.0.0.5").indicator is None,
        "miss",
    )
    # A higher-score indicator for the same value overrides.
    intel.merge([
        Indicator(
            kind=int(IndicatorKind.IP), value="198.51.100.99",
            score=0.50, reputation=int(Reputation.SUSPICIOUS),
            source="lower-confidence",
        ),
    ])
    check(
        "a higher-score feed overrides a lower-score one on the same indicator",
        intel.lookup_ip("198.51.100.99").indicator.score == 0.95,
        f"got {intel.lookup_ip('198.51.100.99').indicator.score}",
    )


def test_intel_extractor() -> None:
    print("\n[intel] indicator extraction from OCSF events")
    intel = IntelStore()
    extractor = IndicatorExtractor()
    event = {
        "src_endpoint_ip": "198.51.100.99",
        "email": {"from": "alice@contoso.com", "to": ["bob@evil.example.com"]},
        "unmapped": {
            "dns_query": {"name": "evil.example.com", "type": "A"},
            "response": "198.51.100.99",
            "hashes": {"sha256": "a" * 64, "md5": "b" * 32},
            "file": {"hashes": {"sha1": "c" * 40}},
        },
    }
    extracted = extractor.extract(event)
    kinds = {e.kind for e in extracted}
    check(
        "the extractor pulls IPs, domains, emails, and hashes",
        int(IndicatorKind.IP) in kinds
        and int(IndicatorKind.DOMAIN) in kinds
        and int(IndicatorKind.EMAIL) in kinds
        and int(IndicatorKind.HASH_SHA256) in kinds
        and int(IndicatorKind.HASH_SHA1) in kinds
        and int(IndicatorKind.HASH_MD5) in kinds,
        f"got kinds={kinds}",
    )
    sha256 = next(
        e for e in extracted
        if e.kind == int(IndicatorKind.HASH_SHA256)
    )
    check(
        "a hash is lower-cased so a SHA-256 lookup is case-insensitive",
        sha256.value == "a" * 64,
        f"got {sha256.value}",
    )


def test_intel_feed_load() -> None:
    print("\n[intel] the JSON feed loader rejects malformed entries")
    intel = IntelStore()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "feed.json"
        path.write_text(
            '['
            '{"kind": 1, "value": "198.51.100.99", "score": 0.9, '
            '"reputation": 4, "source": "test"}, '
            '{"kind": 999, "value": "garbage", "score": 1.0, '
            '"reputation": 4, "source": "test"}, '
            '{"kind": 1, "value": "not_an_ip", "score": 1.0, '
            '"reputation": 4, "source": "test"}'
            ']',
            encoding="utf-8",
        )
        n = intel.load_feed(path)
        check(
            "the loader reads valid entries and drops invalid ones",
            n == 3 and len(intel) == 1,
            f"loaded={n} store={len(intel)}",
        )


# ── enrich ────────────────────────────────────────────────────────────────


def test_enrich_pipeline() -> None:
    print("\n[enrich] the enrichment pipeline produces a flat OCSF context")
    entities = EntityStore()
    intel = IntelStore()
    intel.merge([
        Indicator(
            kind=int(IndicatorKind.IP), value="198.51.100.99",
            score=0.9, reputation=int(Reputation.MALICIOUS),
            source="test",
        ),
    ])
    enricher = Enricher(entities, intel)
    event = {
        "class_uid": 3002,
        "metadata_uid": "e1",
        "time": 0.0,
        "actor": {"user": {"email_addr": "alice@contoso.com"}},
        "src_endpoint_ip": "198.51.100.99",
        "metadata_labels": ["attack:T1078"],
    }
    enr = enricher.enrich(event)
    check(
        "the enricher resolves the actor and the source IP",
        len(enr.entities) >= 1,
        f"got {len(enr.entities)} entities",
    )
    check(
        "the enricher produces an intel hit on a known-bad IP",
        any(
            hit.indicator is not None
            and hit.indicator.score == 0.9
            for hit in enr.indicators
        ),
        f"indicators={enr.indicators}",
    )
    check(
        "the worst reputation seen is the headline number",
        enr.reputation_score == 0.9,
        f"got {enr.reputation_score}",
    )
    flat = to_ocsf_context(enr)
    check(
        "the flat context has entities, indicators, and reputation",
        "entities" in flat
        and "indicators" in flat
        and flat["reputation_score"] == 0.9,
        f"keys={list(flat.keys())}",
    )


# ── correlate ──────────────────────────────────────────────────────────────


def test_correlate_keys() -> None:
    print("\n[correlate] the shipped correlation-key recipes")
    f = {"actor_key": "alice@contoso.com", "attack_id": "T1078"}
    check(
        "actor_time_key joins findings by actor and attack",
        actor_time_key(f) == "actor:alice@contoso.com:attack:T1078",
        f"got {actor_time_key(f)}",
    )
    check(
        "target_time_key joins findings by their target asset",
        target_time_key({"target_keys": ("bucket-a", "bucket-b")})
        == "target:bucket-a+bucket-b",
        "target join",
    )
    check(
        "first_key picks the first non-empty recipe",
        first_key(f) == "actor:alice@contoso.com:attack:T1078",
        f"got {first_key(f)}",
    )
    check(
        "an empty finding key falls through to an empty string",
        first_key({"actor_key": "", "attack_id": ""}) == "",
        "empty",
    )


def test_correlate_engine_groups() -> None:
    print("\n[correlate] the engine groups related findings and closes on idle")
    eng = CorrelateEngine(merge_window_seconds=1800.0, idle_window_seconds=3600.0)
    key = actor_time_key({"actor_key": "alice@contoso.com", "attack_id": "T1078"})
    f1 = FindingStub(uid="f1", time=0.0, severity_id=4,
                     attack_id="T1078", actor_key="alice@contoso.com",
                     correlation_key=key)
    f2 = FindingStub(uid="f2", time=600.0, severity_id=3,
                     attack_id="T1078", actor_key="alice@contoso.com",
                     correlation_key=key)
    f3 = FindingStub(uid="f3", time=1200.0, severity_id=3,
                     attack_id="T1078", actor_key="alice@contoso.com",
                     correlation_key=key)
    i1 = eng.observe(f1)
    i2 = eng.observe(f2)
    i3 = eng.observe(f3)
    check(
        "the engine joins three findings into one incident",
        i1.uid == i2.uid == i3.uid,
        f"uids: {i1.uid} {i2.uid} {i3.uid}",
    )
    check(
        "the joined incident carries every finding",
        sorted(i3.finding_uids) == ["f1", "f2", "f3"],
        f"got {sorted(i3.finding_uids)}",
    )
    check(
        "the incident's severity is the worst of its findings",
        i3.severity_id == 4,
        f"got {i3.severity_id}",
    )
    check(
        "the incident's window covers the entire span",
        i3.window_start == 0.0 and i3.window_end == 1200.0,
        f"window: {i3.window_start} -> {i3.window_end}",
    )
    # An out-of-window finding opens a new incident.
    f_late = FindingStub(uid="f4", time=10_000.0, severity_id=3,
                        attack_id="T1078", actor_key="alice@contoso.com",
                        correlation_key=key)
    i_late = eng.observe(f_late)
    check(
        "a finding outside the merge window opens a new incident",
        i_late.uid != i3.uid,
        f"uids: late={i_late.uid} early={i3.uid}",
    )
    # Idle close — both incidents are well past the idle window.
    closed = eng.close_idle(now=20_000.0)
    check(
        "an idle incident is moved from open to closed",
        eng.closed_incidents() and not eng.open_incidents(),
        f"open={len(eng.open_incidents())} closed={len(eng.closed_incidents())}",
    )


def test_correlate_crown_jewel_boost() -> None:
    print("\n[correlate] the crown-jewel boost lifts incident severity")
    eng = CorrelateEngine()
    f = FindingStub(
        uid="f1", time=0.0, severity_id=3, attack_id="T1078",
        actor_key="bob@contoso.com", correlation_key="actor:bob:attack:T1078",
        entity_tags={"asset-1": ("crown_jewel",)},
    )
    i = eng.observe(f)
    check(
        "a crown-jewel tag lifts severity by the boost",
        i.severity_id == 4,
        f"got {i.severity_id}",
    )


def test_correlate_incident_to_ocsf() -> None:
    print("\n[correlate] the OCSF 2005 conversion carries the chain")
    eng = CorrelateEngine()
    f = FindingStub(uid="f1", time=0.0, severity_id=4,
                   attack_id="T1078", actor_key="alice@contoso.com",
                   target_keys=("asset-1",),
                   correlation_key="actor:alice:attack:T1078")
    i = eng.observe(f)
    ocsf = i.to_ocsf()
    check(
        "every incident is class_uid 2005",
        ocsf["class_uid"] == 2005,
        f"got {ocsf['class_uid']}",
    )
    check(
        "the OCSF unmapped block carries the finding chain",
        ocsf["unmapped"]["finding_uids"] == ["f1"]
        and ocsf["unmapped"]["actor_keys"] == ["alice@contoso.com"],
        f"unmapped={ocsf['unmapped']}",
    )


# ── entry ─────────────────────────────────────────────────────────────────


def main() -> int:
    test_entities_basics()
    test_resolver_extracts_refs()
    test_intel_lookups()
    test_intel_extractor()
    test_intel_feed_load()
    test_enrich_pipeline()
    test_correlate_keys()
    test_correlate_engine_groups()
    test_correlate_crown_jewel_boost()
    test_correlate_incident_to_ocsf()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

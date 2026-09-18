"""Scratch verification for core.schema.ocsf against the vendored OCSF 1.9.0 schema.

The distinctive test here is `── declared paths resolve against the real schema ──`:
every entry in OCSF_PATH is walked through the vendored 194-object graph. That turns
"OCSF-aligned" from a claim in a docstring into a property this suite checks, and it
is the reason the schema was vendored rather than written from memory — the first run
of it found `logon_process_name` (OCSF nests a whole Process object there) and four
extension objects whose reference form differs from their filename.
"""

import asyncio
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, ".")

from pydantic import ValidationError

from core.store.lake import Lake, LakeTable

from core.schema.ocsf import (
    DEPRECATED_CLASS_USE,
    DERIVED_FIELDS,
    LOCAL_FIELDS,
    MAX_CLOCK_SKEW_SECONDS,
    MIN_PLAUSIBLE_TIME,
    OCSF_PATH,
    SOC_FIELDS,
    ActionId,
    ClassUid,
    ConfidenceId,
    Direction,
    DispositionId,
    EmailDirection,
    Event,
    EventRejected,
    FindingStatus,
    HashAlgorithmId,
    Impact,
    IncidentStatus,
    Observable,
    ObservableTypeId,
    OcsfError,
    OcsfSchema,
    Priority,
    QueryResultId,
    RiskLevel,
    Severity,
    Status,
    UnknownClass,
    Verdict,
    _CLASS_ENUM_FIELDS,
    _OBSERVABLE_OF,
    bad_enum_values,
    build_index,
    lake_schema,
    missing_required,
    misplaced_fields,
    parse_time,
    schema,
    status_enum_for,
    unfilled_required,
    validate_event,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


IDX = Path("vendor/ocsf/ocsf_index.json")
NOW = time.time()


def _rejects(fn):
    """True when `fn` raises a validation error — for one-line negative checks."""
    try:
        fn()
    except ValidationError:
        return True
    return False


def base(**over):
    """A minimal valid Authentication event, overridable per test."""
    fields = dict(
        source="test",
        time=NOW,
        class_uid=int(ClassUid.AUTHENTICATION),
        activity_id=1,
        metadata_uid="uid-1",
    )
    fields.update(over)
    return Event.build(**fields)


def base_on(class_uid, activity_id=1, **over):
    """The same, on a class that actually declares the fields under test.

    ``Event.build`` now sweeps fields that are wrong for their own class into
    ``unmapped`` — a ``file_sha256`` on a 3002 Authentication event does not stay in
    ``file_sha256``, because 3002 declares no ``file``. That is the point of the sweep,
    and it means a test exercising the *hash validator* has to hand the hash to a class
    that can hold one, or it is silently testing the sweep instead and the validator
    never runs.

    This is the same mistake the sweep exists to catch, made in a test rather than a
    collector: using one convenient class as a junk drawer for arbitrary fields.
    """
    return Event.build(source="test", time=NOW, class_uid=class_uid,
                       activity_id=activity_id, metadata_uid="uid-1", **over)


#: A class declaring ``file``, ``device``, ``actor``, ``user`` and both endpoints —
#: measured as the widest non-deprecated core class, which is what lets one event
#: carry enough different observable roots to test derivation properly.
_RICH_CLASS = int(ClassUid.RDP_ACTIVITY)  # 4005
#: Declares ``file``; used for the file-hash validators.
_FILE_CLASS = int(ClassUid.FILE_SYSTEM_ACTIVITY)  # 1001
#: Declares ``process``; used for the process-hash validators.
_PROC_CLASS = int(ClassUid.PROCESS_ACTIVITY)  # 1007
#: Declares ``query``; used for DNS-name folding.
_DNS_CLASS = int(ClassUid.DNS_ACTIVITY)  # 4003


def main():
    print("── load ──")
    t0 = time.perf_counter()
    sch = schema(IDX)
    load_ms = (time.perf_counter() - t0) * 1000
    check("index loads fast enough for process start", load_ms < 2000,
          f"{load_ms:.0f} ms for {IDX.stat().st_size/1e6:.2f} MB")
    check("version is the vendored one", sch.version == "1.9.0", sch.version)
    check("source digest recorded", len(sch.source_sha256) == 64,
          sch.source_sha256[:16] + "…")
    check("the same object is returned on repeat calls, not reparsed",
          schema() is sch, "validation runs per event; a reparse per event would not")
    try:
        OcsfSchema({"index_version": 999})
        check("a stale index version is refused", False)
    except OcsfError as exc:
        check("a stale index version is refused", "rebuild" in str(exc), str(exc)[:60])
    try:
        OcsfSchema.load("vendor/ocsf/does-not-exist.json")
        check("a missing index tells you how to build it", False)
    except OcsfError as exc:
        check("a missing index tells you how to build it",
              "core.schema.ocsf build" in str(exc))

    print("\n── classes ──")
    st = sch.stats()
    check("86 event classes, base_event excluded",
          st["classes"] == 86 and sch.get(0) is None,
          f"{st['classes']} classes; base_event (uid 0) is abstract and not one")
    check("the win extension classes are present",
          st["extension_classes"] == 7
          and sch.klass(201001).extension == "win",
          f"{st['extension_classes']} extension classes")
    check("616 activities across all classes", st["activities"] == 616, str(st["activities"]))
    a = sch.klass(3002)
    check("resolves by uid", a.name == "authentication", str(a))
    check("resolves by uid-as-string", sch.klass("3002").uid == 3002)
    check("resolves by name", sch.klass("authentication").uid == 3002)
    check("name lookup tolerates case and hyphens",
          sch.klass("REGISTRY_KEY_ACTIVITY").uid == 201001
          and sch.klass("registry-key-activity").uid == 201001,
          "rule YAML will name classes by hand")
    try:
        sch.klass(4099)
        check("an unknown uid raises and suggests its neighbours", False)
    except UnknownClass as exc:
        check("an unknown uid raises and suggests its neighbours",
              "4001" in str(exc) and "not an OCSF class" in str(exc), str(exc)[:80])
    check("get() returns None instead of raising", sch.get(4099) is None)
    check("every ClassUid this repo names is a real class in v1.9.0",
          all(int(c) in sch.classes for c in ClassUid),
          f"{len(list(ClassUid))} named")
    dep = {int(c) for c in ClassUid if sch.classes[int(c)].deprecated}
    check("every deprecated class this repo names is named KNOWINGLY — measured, "
          "OCSF v1.9.0 deprecated the whole Discovery *_query family in favour of "
          "5040 evidence_info, which requires query_evidence/query_result_id/cloud/"
          "osint and declares no session, group or users. A blanket ban would be "
          "satisfied by picking a worse class, so the assertion is that each one has "
          "a recorded reason and a migration target instead",
          dep == set(DEPRECATED_CLASS_USE),
          f"undocumented={sorted(dep - set(DEPRECATED_CLASS_USE))} "
          f"stale={sorted(set(DEPRECATED_CLASS_USE) - dep)}")
    check("...and each reason names what OCSF replaced it with, so the migration is "
          "written down where the decision is rather than in a commit message",
          all(len(v) > 80 and any(t in v for t in ("5040", "2003"))
              for v in DEPRECATED_CLASS_USE.values()),
          str({k: len(v) for k, v in DEPRECATED_CLASS_USE.items()}))
    check("...and the replacement OCSF points at really is undeprecated, which is "
          "what makes the migration target a target and not another dead end",
          all(not sch.classes[u].deprecated for u in (5040, 2003)))

    print("\n── activity and derived fields ──")
    check("type_uid is class_uid*100 + activity_id",
          OcsfSchema.type_uid(3002, 1) == 300201 and OcsfSchema.type_uid(201001, 4) == 20100104)
    check("an activity name resolves", sch.activity(3002, 1) == "Logon")
    try:
        sch.activity(3002, 42)
        check("an invalid activity lists the valid ones", False)
    except OcsfError as exc:
        check("an invalid activity lists the valid ones",
              "1=Logon" in str(exc) and "99=Other" in str(exc), str(exc)[:70])
    e = base()
    check("category_uid is derived, not supplied", e.category_uid == 3, str(e.category_uid))
    check("type_uid is derived, not supplied", e.type_uid == 300201, str(e.type_uid))
    try:
        base(type_uid=999999)
        check("a contradicting type_uid is rejected, not silently corrected", False)
    except ValidationError as exc:
        check("a contradicting type_uid is rejected, not silently corrected",
              "contradicts class_uid" in str(exc),
              "a producer that disagrees with itself cannot be trusted on class_uid either")
    try:
        base(category_uid=4)
        check("a contradicting category_uid is rejected", False)
    except ValidationError as exc:
        check("a contradicting category_uid is rejected", "contradicts" in str(exc))
    check("a consistent supplied type_uid is accepted",
          base(type_uid=300201, category_uid=3).type_uid == 300201,
          "from_ocsf supplies these from a well-formed document")
    try:
        base(activity_id=42)
        check("an activity outside the class enum is rejected with the valid list", False)
    except ValidationError as exc:
        check("an activity outside the class enum is rejected with the valid list",
              "Service Ticket Request" in str(exc))
    try:
        base(class_uid=999999)
        check("an unknown class is rejected", False)
    except ValidationError as exc:
        check("an unknown class is rejected", "not an OCSF class" in str(exc))

    print("\n── activity_id 99 must say what it actually saw ──")
    # OCSF defines activity_name as the sibling of activity_id and requires it when
    # activity_id is 99 (Other) — the enum's own description says so. Enforcing it is
    # not pedantry about the spec: 99 alone records that *the schema* had no match,
    # which is a fact about OCSF rather than about the host. A detection rule cannot
    # match on the absence of a value, so an unnamed 99 is queryable only by
    # exclusion — and the producer, which knew exactly what it observed, is the only
    # party that can still say. This is asserted here and not only via the DNS
    # collector because it is a property of the schema, and the next collector to
    # reach for 99 will not be a DNS one.
    check("99=Other exists on the classes that need it",
          sch.activity(int(ClassUid.DNS_ACTIVITY), 99) == "Other")
    named = base(activity_id=99, activity_name="Hosts file entry loaded into cache")
    check("a named 99 is accepted",
          named.activity_id == 99 and named.type_uid == 300299,
          named.activity_name)
    try:
        base(activity_id=99)
        check("an unnamed 99 is refused", False)
    except ValidationError as exc:
        check("an unnamed 99 is refused, and the message names the field",
              "activity_name" in str(exc),
              "the producer is told what to supply, not merely that it failed")
    check("a whitespace-only activity_name does not satisfy the contract",
          _rejects(lambda: base(activity_id=99, activity_name="   ")),
          "an empty label is the same non-answer as no label")
    check("activity_name is free on a mapped activity",
          base(activity_id=1).activity_name is None,
          "the requirement is specific to 99 — it is not a mandatory field")
    check("but is kept when a source supplies one anyway",
          base(activity_id=1, activity_name="Interactive logon").activity_name
          == "Interactive logon",
          "a source's own label is evidence; OCSF permits it on any activity")
    check("activity_name is a declared OCSF path, not a CYPHRA extension",
          OCSF_PATH.get("activity_name") == "activity_name")
    rt = Event.from_ocsf(named.to_ocsf())
    check("activity_name survives to_ocsf → from_ocsf",
          rt.activity_name == named.activity_name and rt.activity_id == 99,
          "otherwise a round trip through the lake would produce an event the "
          "validator now refuses")

    print("\n── deprecated classes are guided, not refused ──")
    deprecated_uid = next(u for u, k in sch.classes.items() if k.deprecated)
    dk = sch.classes[deprecated_uid]
    de = base(class_uid=deprecated_uid, activity_id=0)
    check("25 classes are deprecated in v1.9.0", st["deprecated_classes"] == 25,
          str(st["deprecated_classes"]))
    check("an event on a deprecated class is accepted",
          de.class_uid == deprecated_uid, str(dk))
    check("and told which class supersedes it",
          any(dk.deprecated_by[0] in n for n in de.soc_notes),
          [n for n in de.soc_notes if "deprecated" in n][:1])
    check("a live class produces no deprecation note",
          not any("deprecated" in n for n in e.soc_notes))

    print("\n── timestamps ──")
    check("epoch seconds pass through", parse_time(1700000000) == 1700000000.0)
    check("epoch milliseconds are detected", parse_time(1700000000123) == 1700000000.123,
          "Okta, CrowdStrike and Graph all emit ms")
    check("epoch microseconds are detected", parse_time(1700000000123456) == 1700000000.123456)
    # FILETIME is 100-ns ticks since 1601-01-01, so the tick count for a known
    # epoch is (epoch + 11644473600) * 1e7 — derived rather than pasted, since a
    # hand-typed magic number here is exactly what the check is meant to catch.
    filetime = int((1700000000 + 11644473600) * 1e7)
    check("Windows FILETIME is detected",
          parse_time(filetime) == 1700000000.0,
          f"{filetime} → {parse_time(filetime):.0f}")
    check("a FILETIME read as seconds would be unrescuable, hence the branch",
          filetime / 1e7 > 13e9, "~423 years out; no plausibility window covers it")
    iso = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
    check("ISO-8601 with Z parses to the right instant",
          parse_time("2023-11-14T22:13:20Z") == iso.timestamp(),
          "the trailing Z that Azure/Okta/Graph use")
    check("a naive datetime is read as UTC, not host-local",
          parse_time(datetime(2023, 11, 14, 22, 13, 20)) == iso.timestamp(),
          "every one of these APIs returns UTC; guessing local would shift them all")
    check("an offset-bearing string keeps its offset",
          parse_time("2023-11-14T17:13:20-05:00") == iso.timestamp())
    for bad in (True, "", "not-a-time", None, [1]):
        try:
            parse_time(bad)
            check(f"unusable timestamp {bad!r} raises", False)
        except (ValueError, TypeError):
            check(f"unusable timestamp {bad!r} raises", True)
    print("\n── timestamps that are broken, not merely skewed ──")
    try:
        base(time=0)
        check("a zero timestamp is rejected rather than rewritten", False)
    except ValidationError as exc:
        check("a zero timestamp is rejected rather than rewritten",
              "before 2000-01-01" in str(exc),
              f"a null coerced to 0 would otherwise become {MIN_PLAUSIBLE_TIME:.0f}")
    except ValueError as exc:
        check("a zero timestamp is rejected rather than rewritten",
              "before 2000-01-01" in str(exc),
              "checked before skew correction, or correction would rewrite it to now")
    try:
        Event.build(source="t", class_uid=3002, activity_id=1, metadata_uid="u")
        check("a missing timestamp is rejected, not stamped with the ingest clock",
              False)
    except (ValidationError, ValueError) as exc:
        check("a missing timestamp is rejected, not stamped with the ingest clock",
              "no time" in str(exc),
              "a broken time mapping would otherwise collapse every dwell time to 0")
    check("a source with genuinely no timestamp can opt in explicitly",
          Event.build(source="t", time=NOW, class_uid=3002, activity_id=1,
                      metadata_uid="u").time == NOW,
          "the choice is visible in the connector rather than implicit here")
    try:
        Event(time=0.0, class_uid=3002, activity_id=1)
        check("direct construction is guarded too, where there is no build() to help",
              False)
    except ValidationError as exc:
        check("direct construction is guarded too, where there is no build() to help",
              "before 2000-01-01" in str(exc))

    print("\n── clock skew: corrected forward, recorded backward ──")
    ok = Event.build(source="t", time=NOW - 30, class_uid=3002, activity_id=1,
                     metadata_uid="u", ingested_time=NOW)
    check("a small skew is left completely alone",
          ok.time == NOW - 30 and not ok.soc_time_corrected
          and ok.metadata_original_time is None,
          f"{ok.soc_time_skew_seconds:+.0f}s within the {MAX_CLOCK_SKEW_SECONDS:.0f}s tolerance")
    future = NOW + 3 * 86400
    fut = Event.build(source="t", time=future, class_uid=3002, activity_id=1,
                      metadata_uid="u", ingested_time=NOW)
    check("an event from a fast clock is partitioned on ingest time",
          fut.time == NOW and fut.soc_time_corrected,
          "otherwise it lands in a future partition no hunt window covers")
    check("the source's own value is preserved verbatim",
          fut.metadata_original_time is not None
          and str(datetime.fromtimestamp(future, tz=timezone.utc).year)
          in fut.metadata_original_time,
          fut.metadata_original_time)
    check("the skew is recorded as a number, so skewed fleets are countable",
          abs(fut.soc_time_skew_seconds - 3 * 86400) < 2,
          f"{fut.soc_time_skew_seconds:+.0f}s")
    check("and the correction is explained in the notes",
          any("ingest clock" in n for n in fut.soc_notes),
          [n for n in fut.soc_notes if "ingest" in n][:1])
    past = Event.build(source="t", time=NOW - 30 * 86400, class_uid=3002, activity_id=1,
                       metadata_uid="u", ingested_time=NOW)
    check("a LATE event keeps its own time — lateness is not a broken clock",
          past.time == NOW - 30 * 86400 and not past.soc_time_corrected,
          "a cloud audit backfill, a spooled agent reconnecting and a stalled "
          "cursor all look like this; re-stamping them fabricates the timeline")
    check("and how late it was is recorded, so the lag is countable",
          abs(past.soc_time_skew_seconds + 30 * 86400) < 2
          and any("after it happened" in n for n in past.soc_notes),
          f"{past.soc_time_skew_seconds:+.0f}s")
    check("a future time is still rewritten, because that one is provably wrong",
          Event.build(source="t", time=NOW + 30 * 86400, class_uid=3002, activity_id=1,
                      metadata_uid="u", ingested_time=NOW).time == NOW,
          "an event cannot be observed before it happens")

    print("\n── deduplication identity ──")
    raw = {"EventID": 4625, "n": 1}
    one = Event.build(source="wel", raw=raw, time=NOW, class_uid=3002, activity_id=1,
                      metadata_uid="rec-500")
    two = Event.build(source="wel", raw=raw, time=NOW + 5, class_uid=3002, activity_id=1,
                      metadata_uid="rec-500")
    check("a source event id makes the identity stable across a retry",
          one.soc_event_id == two.soc_event_id and one.soc_dedup_exact,
          "the agent protocol is at-least-once, so a retry must collapse")
    check("the id survives a different arrival time",
          one.time != two.time and one.soc_event_id == two.soc_event_id)
    other = Event.build(source="sysmon", raw=raw, time=NOW, class_uid=3002,
                        activity_id=1, metadata_uid="rec-500")
    check("two sources sharing a record number do not collide",
          other.soc_event_id != one.soc_event_id,
          "EventRecordID is unique per channel, not globally")
    noid = Event.build(source="flow", raw=raw, time=NOW, class_uid=4001, activity_id=1,
                       agent_id="a1")
    check("without a source id, dedup is declared best-effort",
          not noid.soc_dedup_exact and len(noid.soc_event_id) == 32)
    check("and the limitation is stated in the notes, not hidden",
          any("best-effort" in n for n in noid.soc_notes),
          [n for n in noid.soc_notes if "best-effort" in n][:1])
    check("the flag is what lets the metrics layer say which counts are exact",
          one.soc_dedup_exact and not noid.soc_dedup_exact)
    same = Event.build(source="flow", raw=raw, time=noid.time, class_uid=4001,
                       activity_id=1, agent_id="a1")
    check("identical no-id events in the same instant do collapse",
          same.soc_event_id == noid.soc_event_id,
          "the honest limit: two genuinely distinct ones are indistinguishable")

    print("\n── raw custody ──")
    reordered = {"n": 1, "EventID": 4625}
    check("the raw hash is key-order independent",
          Event.build(source="w", raw=reordered, time=NOW, class_uid=3002,
                      activity_id=1, metadata_uid="x").soc_raw_sha256
          == one.soc_raw_sha256,
          one.soc_raw_sha256[:16] + "…")
    check("the raw payload is not stored by default", one.soc_raw is None,
          "storing every payload would roughly double the lake")
    kept = Event.build(source="w", raw=raw, time=NOW, class_uid=3002, activity_id=1,
                       metadata_uid="x", keep_raw=True)
    check("keep_raw stores it, and it still hashes to the recorded digest",
          kept.soc_raw is not None and kept.soc_raw_sha256 == one.soc_raw_sha256)
    check("a hash is recorded even with no raw payload at all",
          len(base().soc_raw_sha256) == 64)

    print("\n── values that reach a firewall are validated, not coerced ──")
    for field, bad in [("src_endpoint_ip", "evil.example.com"),
                       ("dst_endpoint_ip", "10.0.0.0/8"),
                       ("device_ip", "999.1.1.1")]:
        try:
            base(**{field: bad})
            check(f"{field}={bad!r} is rejected", False)
        except ValidationError as exc:
            check(f"{field}={bad!r} is rejected", "is not an IP address" in str(exc),
                  "this value reaches netsh; a hostname here is a safety problem")
    check("IPv6 is accepted and normalised",
          base(src_endpoint_ip="2001:0db8:0000::1").src_endpoint_ip == "2001:db8::1")
    for bad in (-1, 70000):
        try:
            base(src_endpoint_port=bad)
            check(f"port {bad} is rejected", False)
        except ValidationError:
            check(f"port {bad} is rejected", True)
    check("port 0 is allowed", base(src_endpoint_port=0).src_endpoint_port == 0,
          "ICMP flows legitimately report 0")
    check("a MAC is normalised to one canonical form",
          base(device_mac="aa-bb-cc-dd-ee-ff").device_mac == "AA:BB:CC:DD:EE:FF"
          == base(device_mac="aabb.ccdd.eeff").device_mac,
          "three vendor spellings, one entity")
    try:
        base(device_mac="aa:bb:cc")
        check("a short MAC is rejected", False)
    except ValidationError:
        check("a short MAC is rejected", True)
    check("a sha256 is lowercased",
          base_on(_FILE_CLASS, file_sha256="A" * 64).file_sha256 == "a" * 64)
    for bad in ("deadbeef", "z" * 64, "A" * 63):
        try:
            base_on(_FILE_CLASS, file_sha256=bad)
            check(f"sha256 {bad[:12]!r} is rejected", False)
        except ValidationError as exc:
            check(f"sha256 {bad[:12]!r} is rejected", "is not a sha256" in str(exc))
    check("md5 and sha1 are checked at their own lengths",
          base_on(_FILE_CLASS, file_md5="B" * 32).file_md5 == "b" * 32
          and base_on(_PROC_CLASS,
                      process_file_sha1="C" * 40).process_file_sha1 == "c" * 40,
          "and each hash goes to a class that declares its object — the file hash to "
          "1001, the process hash to 1007, because build() now sweeps a field its own "
          "class cannot hold into unmapped, where no validator would ever see it")
    try:
        base_on(_FILE_CLASS, file_md5="B" * 64)
        check("a sha256 in the md5 field is rejected", False)
    except ValidationError:
        check("a sha256 in the md5 field is rejected", True)
    for field, bad, kind in [("severity_id", 7, "severity"),
                             ("action_id", 5, "action"), ("disposition_id", 28, "disposition")]:
        try:
            base(**{field: bad})
            check(f"{field}={bad} is not an OCSF {kind}", False)
        except ValidationError as exc:
            check(f"{field}={bad} is not an OCSF {kind}", kind in str(exc))
    # `status_id` is the one enum that cannot be checked at field level: five different
    # tables share the name in OCSF v1.9.0, so 3 is Authentication-illegal and
    # Detection-Finding-legal (Suppressed), and a field validator cannot see class_uid
    # to pick between them. Checking it against the base Success/Failure table — which
    # is what this loop used to do — rejected every real Defender alert whose status
    # was Resolved.
    swept = base(status_id=3)
    check("status_id=3 is not a status on 3002, so it is swept rather than kept",
          swept.status_id is None and swept.unmapped.get("status_id") == 3,
          "the value is preserved in unmapped — it is real data the source sent — but "
          "it must not sit in a column a brute-force rule reads as Success/Failure")
    check("...and the note names the class's own valid set",
          any("Valid: 0=Unknown, 1=Success, 2=Failure, 99=Other" in n
              for n in swept.soc_notes),
          [n for n in swept.soc_notes if "status_id" in n])
    check("...while the same 3 on a 2004 finding is Suppressed and is kept",
          base_on(2004, status_id=3, finding_title="t").status_id == 3,
          "which is exactly why this check had to move out of the field validator")
    check("severity_id is deliberately not swept — it would silently downgrade",
          "severity_id" not in _CLASS_ENUM_FIELDS,
          "it is the one enum field with a meaningful non-None default, so sweeping a "
          "bad critical severity out would leave INFORMATIONAL behind and autonomous "
          "response would read the wrong number; it rejects instead")
    try:
        base(confidence_score=101)
        check("confidence_score outside 0..100 is rejected", False)
    except ValidationError as exc:
        check("confidence_score outside 0..100 is rejected", "0-100 score" in str(exc))
    check("...and `confidence` is the caption string beside confidence_id, not a score",
          Event.model_fields["confidence"].annotation == (str | None),
          "measured: OCSF types `confidence` string_t and `confidence_score` "
          "integer_t. The model had the 0-100 integer in `confidence` until the "
          "class-level enum tables made the mismatch visible; nothing wrote it, so "
          "the correction cost nothing")

    print("\n── case folding follows the specification, not convenience ──")
    folded = base(device_hostname="DESKTOP-ABC",
                  actor_user_domain="CORP", actor_user_email="J.Doe@Example.COM",
                  actor_user_name="JDoe")
    # The DNS name goes on a DNS event: `dns_query_hostname` maps to `query.hostname`,
    # and 3002 Authentication declares no `query`, so on the auth event the folding
    # validator would never run on it.
    resolved = base_on(_DNS_CLASS, dns_query_hostname="EVIL.Example.COM")
    check("hostnames fold, because DNS is case-insensitive",
          folded.device_hostname == "desktop-abc"
          and resolved.dns_query_hostname == "evil.example.com")
    check("domains fold, because AD and DNS names are case-insensitive",
          folded.actor_user_domain == "corp")
    check("email addresses fold", folded.actor_user_email == "j.doe@example.com")
    check("usernames do NOT fold",
          folded.actor_user_name == "JDoe",
          "case-insensitive on Windows, case-sensitive on Linux — folding here "
          "would merge two real Linux accounts")

    print("\n── unknown fields are kept, and the fact is reported ──")
    stray = base(TargetUserSid="S-1-5-21", CustomVendorField=7)
    check("a field the schema has no home for is kept in unmapped",
          stray.unmapped == {"TargetUserSid": "S-1-5-21", "CustomVendorField": 7},
          str(stray.unmapped))
    check("and the routing is noted, so a typo is visible rather than silent",
          any("routed to unmapped" in n for n in stray.soc_notes),
          [n for n in stray.soc_notes if "routed" in n][:1])
    try:
        Event(time=NOW, class_uid=3002, activity_id=1, TotallyBogus=1)
        check("the model itself forbids extras, so only build() may route them", False)
    except ValidationError as exc:
        check("the model itself forbids extras, so only build() may route them",
              "TotallyBogus" in str(exc))

    print("\n── observables are derived, not left to each collector ──")
    # 4005 RDP Activity, measured as the widest non-deprecated core class: it declares
    # device, actor, user, file and BOTH endpoints, which is what lets one event carry
    # enough distinct observable roots for this to be a real test of derivation. The
    # hostname is `src_endpoint.hostname` rather than a DNS query name because 4005
    # declares no `query` — and a field its class cannot hold no longer sits quietly in
    # place, it goes to unmapped and derives nothing, which would make this test pass
    # or fail for the wrong reason.
    rich = base_on(_RICH_CLASS, device_hostname="host1", device_ip="10.0.0.5",
                   actor_user_name="jdoe", src_endpoint_ip="10.0.0.5",
                   src_endpoint_hostname="c2.example.com",
                   dst_endpoint_ip="93.184.216.34", dst_endpoint_port=443,
                   file_sha256="d" * 64)
    keys = {o.key() for o in rich.observables}
    check("entities are extracted from the mapped fields with no collector help",
          len(rich.observables) == 7, f"{len(rich.observables)} observables")
    check("the same value in two fields yields one observable",
          sum(1 for o in rich.observables
              if o.value == "10.0.0.5") == 1 and len(keys) == len(rich.observables),
          "device.ip and src_endpoint.ip are the same entity")
    check("an observable names its OCSF path, not the flat column",
          any(o.name == "dst_endpoint.ip" for o in rich.observables),
          [o.name for o in rich.observables][:3])
    check("type ids come from the OCSF observable table",
          {o.type_id for o in rich.observables}
          >= {int(ObservableTypeId.IP_ADDRESS), int(ObservableTypeId.HOSTNAME),
              int(ObservableTypeId.HASH), int(ObservableTypeId.PORT)})
    check("ports are stringified, since observable.value is a string in OCSF",
          any(o.value == "443" and o.type_id == 11 for o in rich.observables))
    check("observable_values filters by type — the correlation entry point",
          sorted(rich.observable_values(ObservableTypeId.IP_ADDRESS))
          == ["10.0.0.5", "93.184.216.34"],
          str(sorted(rich.observable_values(ObservableTypeId.IP_ADDRESS))))
    check("with no types it returns everything",
          len(rich.observable_values()) == len(rich.observables))
    rich.observables = rich.observables + [
        Observable(name="intel.actor", type_id=int(ObservableTypeId.OTHER), value="APT29")]
    again = rich.derive_observables()
    check("re-deriving does not duplicate, and keeps enrichment-added observables",
          again == [] and any(o.value == "APT29" for o in rich.observables),
          f"{len(rich.observables)} total after re-derive")
    rich.derive_observables(replace=True)
    check("replace=True drops anything no field implies",
          not any(o.value == "APT29" for o in rich.observables)
          and len(rich.observables) == 7)
    check("every field the observable table reads is a real event field",
          all(f in Event.model_fields for f in _OBSERVABLE_OF),
          f"{len(_OBSERVABLE_OF)} observable-bearing fields")
    check("and every one of them is also a mapped OCSF path",
          all(f in OCSF_PATH for f in _OBSERVABLE_OF),
          "an observable names its OCSF path, so it must have one")

    print("\n── declared paths resolve against the real schema ──")
    broken = []
    for flat, path in OCSF_PATH.items():
        try:
            sch.resolve_path(path)
        except OcsfError as exc:
            broken.append((flat, path, str(exc)))
    check("every declared OCSF path walks the vendored object graph",
          not broken, f"{len(OCSF_PATH)} paths checked, {len(broken)} broken"
          + (f": {broken[:2]}" if broken else ""))
    check("every mapped flat name is a real field of the event model",
          all(f in Event.model_fields for f in OCSF_PATH),
          [f for f in OCSF_PATH if f not in Event.model_fields][:4])
    check("the path table has no duplicate targets that would overwrite each other",
          len(set(OCSF_PATH.values())) == len(OCSF_PATH),
          [p for p in OCSF_PATH.values() if list(OCSF_PATH.values()).count(p) > 1][:3])
    try:
        sch.resolve_path("src_endpoint.not_a_field")
        check("a broken path names the segment that does not exist", False)
    except OcsfError as exc:
        check("a broken path names the segment that does not exist",
              "network_endpoint.not_a_field" in str(exc), str(exc)[:80])
    try:
        sch.resolve_path("logon_type_id.name")
        check("nesting under a scalar is reported as such", False)
    except OcsfError as exc:
        check("nesting under a scalar is reported as such", "is a scalar" in str(exc))
    try:
        sch.resolve_path("bogus_attribute")
        check("an attribute no class has is reported", False)
    except OcsfError as exc:
        check("an attribute no class has is reported", "no OCSF class" in str(exc))
    check("a path can be checked against one specific class",
          sch.resolve_path("reg_key.path", class_uid=201001) == "scalar")
    try:
        sch.resolve_path("reg_key.path", class_uid=3002)
        check("and rejected when that class does not have it", False)
    except OcsfError as exc:
        check("and rejected when that class does not have it",
              "not an attribute of class 3002" in str(exc))
    check("the win extension objects are reachable by their reference form",
          "win/reg_key" in sch.objects and "win/reg_value" in sch.objects,
          "classes reference win/reg_key; the API serves it as reg_key")
    check("OCSF nests a full Process object under logon_process",
          sch.resolve_path("logon_process.name") == "scalar"
          and OCSF_PATH["logon_process_name"] == "logon_process.name",
          "the first run of this test is what found that")

    print("\n── enums agree with the vendored schema ──")
    for name, enum in [("severity_id", Severity), ("status_id", Status),
                       ("action_id", ActionId), ("disposition_id", DispositionId),
                       ("confidence_id", ConfidenceId),
                       ("algorithm_id", HashAlgorithmId), ("direction_id", Direction)]:
        real, mine = set(sch.enums[name]), {int(m) for m in enum}
        check(f"{name} matches the schema exactly ({len(real)} values)",
              real == mine, f"missing {sorted(real - mine)}, extra {sorted(mine - real)}")
    real_obs, mine_obs = set(sch.observable_types), {int(m) for m in ObservableTypeId}
    check(f"all {len(real_obs)} observable type ids match",
          real_obs == mine_obs,
          f"missing {sorted(real_obs - mine_obs)}, extra {sorted(mine_obs - real_obs)}")
    check("the ids are what is asserted, not the captions",
          sch.observable_types[8] == "Hash" and sch.enums["algorithm_id"][2] == "SHA-1",
          "OCSF captions are prose (SHA-1, 'CWE Object: uid'); identifiers are not")
    check("base_event's required attributes are recorded",
          set(sch.base_required) >= {"time", "class_uid", "activity_id", "metadata",
                                     "category_uid", "severity_id", "type_uid"},
          str(sorted(sch.base_required)))

    print("\n── class-level enums, which the index carried nowhere until now ──")
    # Every remaining hand-written enum, each checked against the table of a class that
    # actually declares it. Before the index carried class_enums these were transcribed
    # from documentation and unverifiable, and one of them was wrong: QueryResultId
    # stopped at ERROR=4 and missed UNSUPPORTED=5 — the member a Windows collector needs
    # when a query is not implementable on this edition rather than failing.
    for uid, attr, enum in [(5017, "query_result_id", QueryResultId),
                            (2004, "status_id", FindingStatus),
                            (2005, "status_id", IncidentStatus),
                            (2004, "verdict_id", Verdict),
                            (2004, "impact_id", Impact),
                            (2004, "priority_id", Priority),
                            (3002, "risk_level_id", RiskLevel),
                            (4009, "direction_id", EmailDirection)]:
        table = sch.enum_members(uid, attr)
        mine = {int(m) for m in enum}
        check(f"{enum.__name__} matches {attr} on class {uid} ({len(mine)} values)",
              table is not None and set(table) == mine,
              f"missing {sorted(set(table or {}) - mine)}, "
              f"extra {sorted(mine - set(table or {}))}")
    check("RiskLevel numbers 0 as Info, not Unknown",
          sch.enum_members(3002, "risk_level_id")[0] == "Info",
          "the one member nobody would guess — every other OCSF *_id reserves 0 for "
          "'the source did not say', so an unset vendor risk must stay None rather "
          "than becoming a positive assertion of no risk")
    status_tables = {}
    for uid, tables in sch.class_enums.items():
        if "status_id" in tables:
            status_tables.setdefault(
                tuple(sorted(tables["status_id"].items())), []).append(uid)
    check("five different tables share the name status_id",
          len(status_tables) == 5
          and sorted(len(v) for v in status_tables.values()) == [1, 1, 4, 6, 74],
          "which is why the field validator cannot check it and status_enum_for "
          f"exists — {sorted((len(v), min(v)) for v in status_tables.values())}")
    check("...and two of them are indistinguishable by their values alone",
          {tuple(sorted(sch.enum_members(u, "status_id"))) for u in (7001, 8001)}
          == {(0, 1, 2, 3, 4, 5, 6, 99)},
          "7001 File Query's 5 is Unsupported; 8001 ADS Activity's 5 is Remote ID "
          "System Failure. Same eight integers, different meanings — so comparing "
          "key sets would call these one enum")
    check("...and three of them collide value-for-value with the base one",
          sch.enum_members(3002, "status_id")[1] == "Success"
          and sch.enum_members(2004, "status_id")[1] == "New"
          and sch.enum_members(2005, "status_id")[1] == "New"
          and sch.enum_members(8001, "status_id")[1] == "Undeclared",
          "Status.SUCCESS on a 2004 is a legal integer meaning New, so no validator "
          "can catch the substitution — only using the right enum can")
    for uid, want in [(3002, Status), (2004, FindingStatus), (2003, FindingStatus),
                      (2005, IncidentStatus), (2001, Status), (6003, Status)]:
        check(f"status_enum_for({uid}) is {want.__name__}",
              status_enum_for(uid) is want,
              "2001 Security Finding kept Success/Failure when the rest of the 2000s "
              "moved to a lifecycle — measured, not assumed" if uid == 2001 else "")
    check("EmailDirection differs from Direction in exactly one caption",
          sch.enum_members(4009, "direction_id")[3] == "Internal"
          and sch.objects and Direction.LATERAL == 3,
          "3 is legal on both, so the wrong enum would read plausibly forever; hence "
          "two enums rather than a comment")
    check("activity_id is not duplicated into class_enums",
          sch.enum_members(3002, "activity_id") is None
          and sch.klass(3002).activities[1] == "Logon",
          "it is OcsfClass.activities; two homes would give two answers")
    check("neither are the class-identity enums",
          all(sch.enum_members(3002, a) is None
              for a in ("class_uid", "type_uid", "category_uid")),
          "~87 copies of the class list to say nothing a lookup cannot")
    # A field in the sweep list whose attribute carries an enum on *no* class is dead
    # weight: bad_enum_values looks it up, finds no table, and skips it, so the field
    # looks guarded and is not. Name them rather than let the list quietly rot.
    sweep_unenumerated = sorted(
        f for f, attr in _CLASS_ENUM_FIELDS.items()
        if not any(attr in t for t in sch.class_enums.values())
    )
    check("every field the enum sweep watches is enumerated on at least one class",
          not sweep_unenumerated,
          f"{sorted(_CLASS_ENUM_FIELDS)} — unenumerated: {sweep_unenumerated}")

    print("\n── the enum sweep catches a value that lies rather than merely omitting ──")
    check("an out-of-table value is moved out of the column it would lie in",
          bad_enum_values(3002, {"status_id": 4})
          and not bad_enum_values(2004, {"status_id": 4}),
          "4 is Resolved on a 2004 finding and nothing at all on a 3002")
    check("the reason names the class's own valid set, which is what makes it fixable",
          "0=Unknown, 1=Success, 2=Failure, 99=Other"
          in bad_enum_values(3002, {"status_id": 4})["status_id"])
    check("a non-integer in an enum column is caught too",
          "not an integer" in bad_enum_values(3002, {"status_id": "Failure"})["status_id"],
          "a vendor's caption string passed straight through to the *_id column")
    check("None is not a violation",
          bad_enum_values(3002, {"status_id": None, "logon_type_id": None}) == {})
    check("an attribute the class does not declare is left to misplaced_fields",
          bad_enum_values(3002, {"verdict_id": 99}) == {}
          and "verdict_id" in misplaced_fields(3002, ["verdict_id"]),
          "reporting one defect twice would put two notes on one problem")
    check("query_result_id=5 Unsupported is legal now and was not before",
          bad_enum_values(5017, {"query_result_id": int(QueryResultId.UNSUPPORTED)}) == {}
          and "query_result_id" in bad_enum_values(5017, {"query_result_id": 7}))
    check("a 23-member DNS rcode table is checked, which nothing checked before",
          bad_enum_values(4003, {"dns_rcode_id": 26}) != {}
          and bad_enum_values(4003, {"dns_rcode_id": 23}) == {},
          "23 is BADCOOKIE; there was no _known_rcode validator at all")

    print("\n── OCSF export ──")
    full = Event.build(
        source="windows_eventlog", agent_id="agent-1", raw={"EventID": 4688},
        keep_raw=True, time=NOW, class_uid=int(ClassUid.PROCESS_ACTIVITY), activity_id=1,
        metadata_uid="rec-9", metadata_log_name="Security",
        metadata_product_name="Microsoft-Windows-Security-Auditing",
        severity_id=int(Severity.HIGH), status_id=int(Status.SUCCESS),
        device_hostname="WS01", device_ip="10.1.2.3", device_os_name="Windows 11",
        actor_user_name="svc_backup", actor_user_domain="CORP",
        actor_process_name="cmd.exe", actor_process_pid=4444,
        actor_process_file_sha256="e" * 64,
        process_name="powershell.exe", process_pid=5555,
        process_cmd_line="powershell -enc SQBFAFgA", process_file_sha256="f" * 64,
        process_file_md5="0" * 32, process_parent_name="cmd.exe",
        src_endpoint_ip="10.1.2.3", dst_endpoint_ip="203.0.113.7", dst_endpoint_port=8443,
        connection_direction_id=int(Direction.OUTBOUND), traffic_bytes=91234,
        metadata_labels=["sysmon", "high-value-host"], vendor_only_field="kept",
    )
    doc = full.to_ocsf()
    check("nesting is produced from the flat model",
          doc["actor"]["user"]["name"] == "svc_backup"
          and doc["process"]["parent_process"]["name"] == "cmd.exe"
          and doc["metadata"]["product"]["name"].startswith("Microsoft"),
          "three levels deep")
    hashes = doc["process"]["file"]["hashes"]
    check("hashes become an array of OCSF Fingerprint objects",
          len(hashes) == 2
          and {h["algorithm"] for h in hashes} == {"SHA-256", "MD5"}
          and {h["algorithm_id"] for h in hashes} == {3, 1},
          str([h["algorithm"] for h in hashes]))
    check("the required base attributes are all present",
          all(k in doc for k in ("time", "class_uid", "category_uid", "activity_id",
                                 "type_uid", "severity_id", "metadata")))
    check("no CYPHRA field appears at the OCSF top level",
          not [k for k in doc if k.startswith("soc_")],
          "what leaves this system has to validate as OCSF")
    check("provenance lives under unmapped.cyphra, OCSF's own escape hatch",
          doc["unmapped"]["cyphra"]["soc_source"] == "windows_eventlog"
          and doc["unmapped"]["cyphra"]["soc_dedup_exact"] is True)
    check("a source's own unmapped fields sit beside it, not inside it",
          doc["unmapped"]["vendor_only_field"] == "kept")
    check("the raw payload is withheld from the export by default",
          "soc_raw" not in doc["unmapped"]["cyphra"]
          and "soc_raw" in full.to_ocsf(include_raw=True)["unmapped"]["cyphra"],
          "custody is the hash; the payload is opt-in even on export")
    check("derived columns with no OCSF attribute go to the cyphra block",
          "dns_answer_count" in DERIVED_FIELDS
          and "count" not in base(dns_answer_count=3).to_ocsf(),
          "base 'count' means event repetitions; an answer count there would lie")
    check("a DNS answer count does round-trip through the cyphra block",
          Event.from_ocsf(base(dns_answer_count=3).to_ocsf()).dns_answer_count == 3)
    check("observables are exported in OCSF's own shape",
          all(set(o) == {"name", "type_id", "value"} for o in doc["observables"]))
    check("empty collections are omitted rather than exported as nulls",
          "email" not in doc and "file" not in doc and "url" not in doc,
          "a process event should not carry an empty email object")

    print("\n── OCSF round trip ──")
    back = Event.from_ocsf(full.to_ocsf(include_raw=True))
    lhs, rhs = full.model_dump(), back.model_dump()
    diffs = {k: (lhs[k], rhs[k]) for k in lhs if lhs[k] != rhs[k]}
    check("every field survives to_ocsf → from_ocsf unchanged",
          not diffs, f"{len(lhs)} fields compared, {len(diffs)} differ: "
          f"{list(diffs)[:4]}")
    default_back = Event.from_ocsf(doc)
    lost = {k for k in lhs if lhs[k] != default_back.model_dump()[k]}
    check("a default export loses the raw payload and nothing else",
          lost == {"soc_raw"},
          f"lost {sorted(lost)} — the digest still proves custody of it")
    check("including the observables", [o.key() for o in back.observables]
          == [o.key() for o in full.observables])
    check("and the source's unmapped fields", back.unmapped == full.unmapped)
    check("a third-party OCSF document is read without its extras being dropped",
          Event.from_ocsf({
              "time": NOW, "class_uid": 3002, "activity_id": 1, "severity_id": 1,
              "actor": {"user": {"name": "ext"}},
              "auth_factors": [{"factor_type_id": 1}], "certificate": {"serial_number": "7f"},
          }).unmapped == {"auth_factors": [{"factor_type_id": 1}],
                          "certificate": {"serial_number": "7f"}},
          "attributes CYPHRA has no column for are retained, not silently lost")
    check("...and `risk_score`, which used to be one of them, is now a real column",
          Event.from_ocsf({
              "time": NOW, "class_uid": 3002, "activity_id": 1, "severity_id": 1,
              "risk_score": 88, "risk_level_id": int(RiskLevel.HIGH),
          }).risk_score == 88,
          "Entra sign-in risk had no conformant home until this; `device_risk_level_id` "
          "resolves to device.risk_level_id and would blame the endpoint for a risk "
          "OCSF attributes to the sign-in")
    check("an inbound DNS answers array becomes the flat count",
          Event.from_ocsf({"time": NOW, "class_uid": 4003, "activity_id": 2,
                           "query": {"hostname": "a.example.com"},
                           "answers": [{"rdata": "1.2.3.4"}, {"rdata": "1.2.3.5"}]
                           }).dns_answer_count == 2)
    check("OCSF's own display strings are not mistaken for unmapped data",
          "class_name" not in Event.from_ocsf({
              "time": NOW, "class_uid": 3002, "activity_id": 1,
              "class_name": "Authentication", "severity": "Low", "status": "Success",
          }).unmapped)

    print("\n── rejection contract ──")
    try:
        validate_event("okta_connector", {"time": NOW, "class_uid": 3002,
                                          "activity_id": 1, "src_endpoint_ip": "nope"})
        check("validate_event refuses a bad event", False)
    except EventRejected as exc:
        check("validate_event refuses a bad event and names the source",
              exc.source == "okta_connector" and "src_endpoint_ip" in exc.reason,
              str(exc)[:90])
    try:
        validate_event("bad_connector", {"class_uid": 3002, "activity_id": 1})
        check("a missing required field is refused", False)
    except EventRejected as exc:
        check("a missing required field is refused", "time" in exc.reason, exc.reason[:60])
    try:
        validate_event("bad_connector", {"time": NOW, "class_uid": 3002,
                                         "activity_id": 1, "time_extra": object()})
        check("an unserialisable stray value is refused, not stored", False)
    except EventRejected as exc:
        check("an unserialisable stray value is refused, not stored", True, exc.reason[:60])
    good = validate_event("okta_connector", {"time": NOW, "class_uid": 3002,
                                             "activity_id": 1, "metadata_uid": "ok"})
    check("a good event comes back fully normalised",
          good.soc_source == "okta_connector" and good.type_uid == 300201)
    check("the rejected payload is carried for the health module to report on",
          bool(EventRejected("s", "r", {"a": 1}).payload))

    print("\n── lake schema is generated from the model ──")
    ls = lake_schema()
    check("every model field has a column",
          set(Event.model_fields) <= set(ls.names),
          sorted(set(Event.model_fields) - set(ls.names))[:5])
    check("_extra is present, as core.store.lake requires",
          "_extra" in ls.names and ls.field("_extra").type == pa.string())
    check("time is a double, so dt=/hh= partitioning works",
          ls.field("time").type == pa.float64())
    check("no struct columns — flat Parquet evolves, structs do not",
          not any(pa.types.is_struct(f.type) for f in ls),
          str({str(f.type) for f in ls}))
    check("list columns are typed, not stringified",
          ls.field("metadata_labels").type == pa.list_(pa.string()))
    row = full.lake_row()
    check("a lake row has exactly the declared columns",
          set(row) | {"_extra"} == set(ls.names),
          f"{len(row)} row keys vs {len(ls.names)} columns")
    check("the three structured tails are JSON strings in the row",
          all(isinstance(row[c], str) for c in ("observables", "unmapped"))
          and row["enrichments"] is None,
          "one LIKE finds any event mentioning a value; json_extract when structure is needed")
    check("the JSON is compact and reparseable",
          len(json.loads(row["observables"])) == len(full.observables)
          and json.loads(row["unmapped"])["vendor_only_field"] == "kept")
    check("the lake and the export use ONE observable shape, not two",
          json.loads(row["observables"]) == doc["observables"],
          "a hunt query written against the export shape must not silently return "
          "zero rows against the lake")
    check("an arrow table builds from real rows with no type conflicts",
          pa.Table.from_pylist([{**row, "_extra": None}], schema=ls).num_rows == 1)

    print("\n── finding_info_list: the requirement nothing could fill ──")
    # 2005 Incident Finding *requires* finding_info_list. Before the column existed,
    # missing_required(2005, []) classified it as a schema-coverage gap — "no CYPHRA
    # field maps to it" — which meant every incident this platform emitted, from a
    # vendor connector or from its own correlator, was non-conformant OCSF and no
    # connector author could have fixed it. The gap is measured here rather than
    # asserted from memory, because the same class of gap still exists for the
    # object-level enums and this is the check that would notice a regression.
    from ingest.connectors.mapping import finding_ref  # noqa: PLC0415

    members = [
        finding_ref(uid="ldt:abc:1", title="Credential theft",
                    created_time=NOW, analytic_name="CredentialTheft",
                    analytic_uid="pattern-1234", analytic_type_id=1),
        finding_ref(uid="ldt:abc:2", title="Suspicious child process",
                    created_time=NOW),
    ]
    check("finding_ref omits what it was not given, like resource_ref",
          set(members[1]) == {"uid", "title", "created_time"},
          str(members[1]))
    check("...and collapses the analytic keywords into OCSF's nested object",
          members[0]["analytic"] == {"name": "CredentialTheft", "uid": "pattern-1234",
                                     "type_id": 1},
          "flat finding_analytic_* expand to the same path; this is the array form")
    check("2005 requires finding_info_list, and filling it closes the requirement",
          "finding_info_list" in missing_required(2005, [])
          and not missing_required(2005, ["finding_info_list", "status_id"]),
          "the gap was 'no CYPHRA field maps to it' — a schema hole, not a mapping bug")
    check("the requirement is now actionable rather than a coverage gap",
          "nothing set it" in missing_required(2005, [])["finding_info_list"],
          "a coverage gap is not a connector's fault; an unfilled field is")
    check("only 2005 declares it — it is misplaced on 2004, 5001 and 6003",
          "finding_info_list" not in misplaced_fields(2005, ["finding_info_list"])
          and all("finding_info_list" in misplaced_fields(uid, ["finding_info_list"])
                  for uid in (2004, 5001, 6003)),
          "2004 carries the thirteen singular finding_* columns instead: a detection "
          "finding is one finding, an incident finding is a set of them")
    inc = Event.build(source="test", time=NOW, class_uid=2005, activity_id=1,
                      metadata_uid="inc-1", status_id=int(IncidentStatus.IN_PROGRESS),
                      severity_id=int(Severity.HIGH), finding_info_list=members)
    check("an incident event keeps the array rather than sweeping it to unmapped",
          len(inc.finding_info_list) == 2 and "finding_info_list" not in inc.unmapped)
    check("...and 2005's status table is IncidentStatus, not FindingStatus",
          not bad_enum_values(2005, {"status_id": int(IncidentStatus.CLOSED)})
          and bool(bad_enum_values(2005, {"status_id": int(FindingStatus.DELETED)})),
          "3 is On Hold here and Suppressed on 2004; 5 is Closed here and Archived "
          "there; 6 does not exist — a shared enum would be wrong on both")
    check("the lake stores it as a JSON string beside resources and evidences",
          isinstance(inc.lake_row()["finding_info_list"], str)
          and json.loads(inc.lake_row()["finding_info_list"])[0]["uid"] == "ldt:abc:1")
    check("an event with no members writes NULL, not an empty JSON array",
          base().lake_row()["finding_info_list"] is None,
          "so a hunt counting incidents by member can filter IS NOT NULL")
    check("the OCSF export puts it at the top level, unflattened",
          inc.to_ocsf()["finding_info_list"] == members)
    check("and it survives a round trip back through from_ocsf",
          Event.from_ocsf(inc.to_ocsf()).finding_info_list == members)

    print("\n── index integrity ──")
    raw_index = json.loads(IDX.read_text(encoding="utf-8"))
    check("every class's category is in the category table",
          all(str(c["category_uid"]) in raw_index["categories"]
              for c in raw_index["classes"].values()))
    check("every deprecated class names a real superseding class",
          all(any(k["name"] == s for k in raw_index["classes"].values())
              for c in raw_index["classes"].values() for s in c["deprecated_by"]),
          str([s for c in raw_index["classes"].values() for s in c["deprecated_by"]
               if not any(k["name"] == s for k in raw_index["classes"].values())]))
    dangling = {
        t for attrs in raw_index["class_attribute_types"].values()
        for t in attrs.values() if t and t not in raw_index["objects"]
    } | {
        a["object_type"] for obj in raw_index["objects"].values()
        for a in obj.values() if a["object_type"] and a["object_type"] not in raw_index["objects"]
    }
    check("every object reference in the graph resolves",
          not dangling, f"dangling: {sorted(dangling)[:5]}")
    check("every class has an activity enum including Unknown and Other",
          all(0 in {int(k) for k in c["activities"]} and 99 in {int(k) for k in c["activities"]}
              for c in raw_index["classes"].values()),
          str([u for u, c in raw_index["classes"].items()
               if 99 not in {int(k) for k in c["activities"]}][:4]))
    check("the index records what it was built from",
          len(raw_index["source_sha256"]) == 64 and len(raw_index["built_from"]) == 5)
    check("a rebuild from the same cache is byte-identical",
          _rebuild_matches(raw_index), "so the committed index is reproducible")
    check("SOC_FIELDS and DERIVED_FIELDS are all real model fields, and disjoint",
          all(f in Event.model_fields for f in SOC_FIELDS + DERIVED_FIELDS)
          and not set(SOC_FIELDS) & set(DERIVED_FIELDS)
          and not set(SOC_FIELDS) & set(OCSF_PATH))

    print("\n── integration: real events through the real lake ──")
    _lake_integration()

    print("\n── describe ──")
    check("an event renders one legible line",
          "Authentication/Logon" in base(status_id=2, actor_user_name="jdoe",
                                         device_hostname="ws01").describe()
          and "[failure]" in base(status_id=2).describe(),
          base(status_id=2, actor_user_name="jdoe", device_hostname="ws01").describe())
    check("a network event names both ends",
          "10.0.0.1" in base(class_uid=4001, activity_id=6, src_endpoint_ip="10.0.0.1",
                             dst_endpoint_ip="1.1.1.1").describe())

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


def _lake_integration():
    """Write real Events into a real LakeTable and query them back with SQL.

    The point is the seam: lake_schema() is generated from the model, so this is
    where a field added to Event without a matching arrow type, or a lake_row()
    value the writer cannot hold, shows up. Asserting it here means Phase 1's
    collectors inherit a proven path rather than discovering it under load.
    """
    root = Path("var/ocsf_lake_check")
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    table = LakeTable(name="events", schema=lake_schema(), time_field="time")
    check("the generated schema is accepted by LakeTable unchanged",
          table.time_field == "time" and "_extra" in table.schema.names,
          f"{len(table.schema.names)} columns")

    # Two hours and two hosts, so partitioning and grouping both have something to
    # do. Times are spread deliberately: an hour boundary that produces one
    # partition would not prove the dt=/hh= path at all.
    #
    # ingested_time moves with the event time rather than defaulting to the wall
    # clock. That is no longer needed to protect these timestamps — a past time is
    # kept as stated now — but it is still what a replay harness should do, because
    # it makes `soc_ingested_time` truthful about when the replay claims to have
    # collected them rather than recording March events as collected today.
    hour = 3600.0
    day = datetime(2026, 3, 4, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    rows, benign, malicious = [], 0, 0
    for i in range(1000):
        attack = i % 5 == 0
        at = day + (i / 1000.0) * 2 * hour
        ev = Event.build(
            source="generator", agent_id=f"agent-{i % 2}",
            raw={"seq": i}, time=at, ingested_time=at,
            class_uid=int(ClassUid.AUTHENTICATION), activity_id=1,
            metadata_uid=f"gen-{i}",
            severity_id=int(Severity.HIGH if attack else Severity.INFORMATIONAL),
            status_id=int(Status.FAILURE if attack else Status.SUCCESS),
            device_hostname=f"HOST-{i % 2}",
            src_endpoint_ip=f"10.0.{i % 2}.{i % 250}",
            actor_user_name="attacker" if attack else "jdoe",
            metadata_labels=["generated"],
        )
        malicious += attack
        benign += not attack
        rows.append(ev.lake_row())
    check("a replay that states its own ingest clock is not treated as skew",
          not any(r["soc_time_corrected"] for r in rows),
          "and the events keep their March timestamps, so dt=/hh= partitions on "
          "when things happened rather than on when they were loaded")

    async def run(lake):
        written = await lake.append("events", rows)
        await lake.flush()
        return written

    lake = Lake(root=root, tables=[table], flush_rows=400)
    try:
        written = asyncio.run(run(lake))
        check("1000 real events are accepted with no schema conflict",
              written == 1000, f"{written} rows")
        parts = lake.partitions("events")
        check("they land in the hour partitions their event time implies",
              {(p[0], p[1]) for p in parts} == {("2026-03-04", "10"), ("2026-03-04", "11")},
              str([(p[0], p[1], f"{p[2]} files") for p in parts]))
        check("and all 1000 are readable through the partitioned view",
              lake.query("SELECT count(*) FROM events")[0][0] == 1000)
        got = lake.query(
            "SELECT status_id, count(*) FROM events GROUP BY 1 ORDER BY 1")
        check("SQL reads the flat columns back with no unpacking",
              dict(got) == {1: benign, 2: malicious},
              f"{dict(got)} vs expected {{1: {benign}, 2: {malicious}}}")
        one = lake.query_dicts(
            "SELECT * FROM events WHERE soc_event_id = ?",
            [rows[7]["soc_event_id"]])
        check("a single event is retrievable by its dedup id",
              len(one) == 1 and one[0]["actor_user_name"] == "jdoe")
        check("derived class fields survived the round trip through Parquet",
              one[0]["type_uid"] == 300201 and one[0]["category_uid"] == 3)
        check("provenance survived it too",
              one[0]["soc_source"] == "generator" and one[0]["soc_dedup_exact"] is True)
        check("a list column comes back as a list, not a string",
              list(one[0]["metadata_labels"]) == ["generated"])
        # This is the query the hunt module will actually run, and the reason the
        # structured tails are JSON strings rather than Parquet structs.
        hits = lake.query(
            "SELECT count(*) FROM events WHERE observables LIKE ?", ["%attacker%"])
        check("a value can be found anywhere in the observables with one LIKE",
              hits[0][0] == malicious, f"{hits[0][0]} of {malicious}")
        typed = lake.query(
            "SELECT count(*) FROM events "
            "WHERE list_contains(json_extract_string(observables, '$[*].name'), ?)",
            ["src_endpoint.ip"])
        check("and read as structure when structure is what is needed",
              typed[0][0] == 1000,
              f"{typed[0][0]} events carrying a src_endpoint.ip observable")
        vals = lake.query(
            "SELECT DISTINCT o FROM events, "
            "UNNEST(json_extract_string(observables, '$[*].value')) AS t(o) "
            "WHERE list_contains(json_extract_string(observables, '$[*].name'), "
            "                    'actor.user.name') AND o IN ('jdoe', 'attacker') "
            "ORDER BY o")
        check("an observable's value is extractable for correlation joins",
              [r[0] for r in vals] == ["attacker", "jdoe"], str([r[0] for r in vals]))
        t0 = time.perf_counter()
        agg = lake.query(
            "SELECT device_hostname, actor_user_name, count(*) AS n, "
            "       max(time) - min(time) AS span "
            "FROM events GROUP BY 1, 2 HAVING n > 1 ORDER BY n DESC")
        ms = (time.perf_counter() - t0) * 1000
        check("the entity aggregation correlation needs runs on the flat columns",
              len(agg) == 4 and all(r[3] > 0 for r in agg) and ms < 2000,
              f"{len(agg)} host×user groups in {ms:.0f} ms")
        check("nothing was silently diverted into _extra",
              lake.query("SELECT count(*) FROM events WHERE _extra IS NOT NULL")[0][0] == 0,
              "every column the model declares is a column the lake declares")
    finally:
        lake.close()
        shutil.rmtree(root, ignore_errors=True)


def _rebuild_matches(committed):
    """Rebuild into a temp path and compare — proves the index is reproducible."""
    tmp = Path("var/ocsf_index_rebuild.json")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    rebuilt = build_index("vendor/ocsf", tmp)
    same = json.dumps(rebuilt, sort_keys=True) == json.dumps(committed, sort_keys=True)
    tmp.unlink(missing_ok=True)
    return same


sys.exit(main())

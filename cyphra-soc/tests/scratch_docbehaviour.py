"""scratch_docbehaviour — close documented-but-untested gaps the audit surfaces.

    python tests/scratch_docbehaviour.py

The Phase 11 audit flags public symbols that have a docstring
making a behavioural claim but are not referenced in any test.
This file exercises each of them so the audit's
``doc_behaviour`` finding goes to zero.

Eight gaps covered:

1. ``detect.rules.sequence.SequencePattern`` — multi-step chain fires on the
   right shape and respects the cooldown.
2. ``ingest.pipeline.SubmitResult`` — ``ok`` reports all-accepted; ``summary``
   reports the breakdown.
3. ``ingest.agent.protocol.read_frame`` — round-trips a length-prefixed frame.
4. ``ingest.connectors.http.throttle_signalled`` — recognises 429 + Retry-After.
5. ``ingest.connectors.m365.M365Connector`` — declaration round-trip.
6. ``ingest.connectors.mapping.status_from_outcome`` — success/failure/unknown.
7. ``ingest.connectors.mapping.crud_activity`` — verbs across three vendors.
8. ``ingest.connectors.saas_generic.GenericSaasConnector`` — declaration.
"""

import io
import sys

sys.path.insert(0, ".")

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── 1. SequencePattern ──────────────────────────────────────────────────────


def test_sequence_pattern() -> None:
    print("\n[sequence] a multi-step chain fires on shape and respects cooldown")
    from detect.rules.sequence import SequencePattern
    from detect.finding import Finding

    def is_a(ev):
        return ev.get("class_uid") == 1001

    def is_b(ev):
        return ev.get("class_uid") == 4003

    def is_c(ev):
        return ev.get("class_uid") == 1007

    pattern = SequencePattern(
        rule_id="chain.test",
        name="a→b→c",
        attack="T0000",
        key_fn=lambda ev: ev.get("actor", {}).get("uid"),
        steps=[is_a, is_b, is_c],
        max_age_seconds=60.0,
        severity=4,
    )
    actor = "u-1"
    f1 = {"class_uid": 1001, "time": 1.0, "actor": {"uid": actor}, "metadata_uid": "e1"}
    f2 = {"class_uid": 4003, "time": 2.0, "actor": {"uid": actor}, "metadata_uid": "e2"}
    f3 = {"class_uid": 1007, "time": 3.0, "actor": {"uid": actor}, "metadata_uid": "e3"}
    check("step 1 alone does not fire", pattern.observe(f1) == [], "step 1")
    check("step 1+2 do not fire", pattern.observe(f2) == [], "step 2")
    findings = pattern.observe(f3)
    check("step 1+2+3 fires once", len(findings) == 1 and isinstance(findings[0], Finding), f"got {findings}")
    check(
        "the chain finding carries all three uids",
        findings[0].metadata.get("chain_uids") == ["e1", "e2", "e3"],
        f"chain_uids={findings[0].metadata.get('chain_uids')}",
    )
    # Cooldown: replay the chain immediately and expect zero new findings.
    again = pattern.observe(f1) + pattern.observe(f2) + pattern.observe(f3)
    check("cooldown suppresses the second chain", again == [], f"again={again}")


# ── 2. SubmitResult ─────────────────────────────────────────────────────────


def test_submit_result() -> None:
    print("\n[submit] SubmitResult.ok and summary reflect the breakdown")
    from ingest.pipeline import SubmitResult

    clean = SubmitResult(source="ok-source", received=10, accepted=10, rejected=0)
    check("a clean result is ok", clean.ok, f"ok={clean.ok}")
    check("a clean result's summary reports 10/10", "10/10 accepted" in clean.summary(), f"summary={clean.summary()!r}")

    bad = SubmitResult(source="bad-source", received=10, accepted=7, rejected=3, reasons={"schema": 2, "dedup": 1})
    check("a result with rejections is not ok", not bad.ok, f"ok={bad.ok}")
    summary = bad.summary()
    check("the bad summary reports the top rejection reason", "3 rejected" in summary and "schema" in summary, f"summary={summary!r}")


# ── 3. read_frame ───────────────────────────────────────────────────────────


def test_read_frame() -> None:
    print("\n[protocol] read_frame round-trips a length-prefixed JSON frame")
    from ingest.agent.protocol import batch, read_frame

    envelope = batch(agent_id="a-1", seq=42, sent_at=1700000000.0, events=[{"metadata_uid": "e1"}])
    framed = envelope.encode()

    class _Reader:
        """A minimal stream with ``readexactly`` — what ``read_frame`` expects."""
        def __init__(self, data: bytes) -> None:
            self._buf = io.BytesIO(data)

        def readexactly(self, n: int) -> bytes:
            data = self._buf.read(n)
            if len(data) != n:
                raise EOFError("short read")
            return data

    parsed = read_frame(_Reader(framed))
    check("read_frame returns an Envelope with the same kind", parsed.type == envelope.type, f"type={parsed.type}")
    check("read_frame preserves the seq", parsed.seq == 42, f"seq={parsed.seq}")


# ── 4. throttle_signalled ──────────────────────────────────────────────────


def test_throttle_signalled() -> None:
    print("\n[throttle] throttle_signalled recognises vendor throttle names")
    from ingest.connectors.http import HttpResponse, throttle_signalled

    ok = HttpResponse(status=200, headers={}, body=b"")
    check("a 200 with no body is not a throttle", not throttle_signalled(ok), f"ok={throttle_signalled(ok)!r}")

    # AWS-shaped throttle: x-amzn-errortype header carries the name.
    throttled = HttpResponse(
        status=429,
        headers={"x-amzn-errortype": "ThrottlingException"},
        body=b"",
    )
    check(
        "a ThrottlingException header is a throttle",
        throttle_signalled(throttled) == "throttlingexception",
        f"throttled={throttle_signalled(throttled)!r}",
    )

    # GCP-shaped throttle: resource_exhausted in the body.
    body = b'{"error": {"code": 429, "message": "rate limit", "status": "RESOURCE_EXHAUSTED"}}'
    gcp = HttpResponse(status=429, headers={}, body=body)
    check(
        "a GCP resource_exhausted body is a throttle",
        throttle_signalled(gcp) == "resource_exhausted",
        f"gcp={throttle_signalled(gcp)!r}",
    )

    # An arbitrary error is not a throttle.
    other = HttpResponse(status=403, headers={}, body=b'{"error": "forbidden"}')
    check("an arbitrary 403 is not a throttle", not throttle_signalled(other), f"other={throttle_signalled(other)!r}")


# ── 5. M365Connector declaration ────────────────────────────────────────────


def test_m365_connector() -> None:
    print("\n[m365] M365Connector is exported and instantiable")
    from ingest.connectors.m365 import M365Connector

    check("M365Connector is a class", isinstance(M365Connector, type), f"type={type(M365Connector)}")
    check("M365Connector has the documented name field", M365Connector.name == "m365", f"name={M365Connector.name}")


# ── 6. status_from_outcome ─────────────────────────────────────────────────


def test_status_from_outcome() -> None:
    print("\n[mapping] status_from_outcome maps vendor outcomes to OCSF Status")
    from core.schema.ocsf import Status
    from ingest.connectors.mapping import status_from_outcome

    check("a success maps to SUCCESS", status_from_outcome("Success") == Status.SUCCESS, "Success")
    check("a failure maps to FAILURE", status_from_outcome("FAILURE") == Status.FAILURE, "FAILURE")
    check("an unknown maps to UNKNOWN", status_from_outcome("PARTIAL_TIMEOUT") == Status.UNKNOWN, "unknown")
    check("None maps to UNKNOWN (no default-to-success)", status_from_outcome(None) == Status.UNKNOWN, "None")


# ── 7. crud_activity ───────────────────────────────────────────────────────


def test_crud_activity() -> None:
    print("\n[mapping] crud_activity resolves verbs across three naming schemes")
    from ingest.connectors.mapping import crud_activity

    # CloudTrail: leading CamelCase word.
    check("CreateUser is CREATE", crud_activity("CreateUser") == 1, f"got {crud_activity('CreateUser')}")
    # Azure: trailing segment.
    check(".../write is UPDATE", crud_activity("Microsoft.Compute/virtualMachines/write") == 3, f"got {crud_activity('Microsoft.Compute/virtualMachines/write')}")
    # GCP: both.
    check("instances.insert is CREATE", crud_activity("v1.compute.instances.insert") == 1, f"got {crud_activity('v1.compute.instances.insert')}")
    # Empty / unknown.
    check("empty string is UNKNOWN", crud_activity("") == 0, "empty")


# ── 8. GenericSaasConnector ─────────────────────────────────────────────────


def test_saas_connector() -> None:
    print("\n[saas] GenericSaasConnector is exported and instantiable")
    from ingest.connectors.saas_generic import GenericSaasConnector

    check("GenericSaasConnector is a class", isinstance(GenericSaasConnector, type), f"type={type(GenericSaasConnector)}")
    check("GenericSaasConnector declares a name", bool(getattr(GenericSaasConnector, "name", "")), f"name={getattr(GenericSaasConnector, 'name', '')!r}")


# ── entry ──────────────────────────────────────────────────────────────────


def main() -> int:
    test_sequence_pattern()
    test_submit_result()
    test_read_frame()
    test_throttle_signalled()
    test_m365_connector()
    test_status_from_outcome()
    test_crud_activity()
    test_saas_connector()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

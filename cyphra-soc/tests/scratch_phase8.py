"""scratch_phase8 — cases, metrics, compliance, crisis, learn-job.

    python tests/scratch_phase8.py

Five sections, each layer verified end-to-end:

1. **Cases** — the state machine, the timeline, the store.
2. **Metrics** — MTTD, MTTR, false-positive rate, escalation rate.
3. **Compliance** — NIST 800-53, SOC 2, ISO 27001 control evaluations.
4. **Crisis** — multi-case emergency coordination.
5. **Learn job** — periodic retrain on verdicts.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from cases import (
    Case,
    CaseStats,
    CaseStatus,
    CaseStore,
    STATUS_NAMES,
    TimelineEvent,
    new_case_uid,
    record,
    transition,
)
from compliance import (
    EXPECTATION_OPS,
    Control,
    ControlEvaluation,
    ControlExpectation,
    ControlStatus,
    ISO_27001,
    NIST_800_53,
    SOC2,
    default_frameworks,
    evaluate as evaluate_controls,
)
from correlate import Incident
from crisis import (
    CRISIS_STATUS_NAMES,
    Crisis,
    CrisisManager,
    CrisisStats,
    CrisisStatus,
)
from learn import (
    EvaluationReport,
    Model,
    RetrainJob,
    RetrainJobConfig,
    RetrainJobStats,
    Verdict,
    VerdictStore,
    train,
)
from learn.verdict import label_for_training
from metrics import MetricsReport, MetricsTracker
from respond import PlaybookDispatcher

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── cases ──────────────────────────────────────────────────────────────────


def test_case_state_machine() -> None:
    print("\n[cases] the state machine and the timeline")
    case = Case(
        uid="c-test", source_incident_uid="i-test",
        title="Test", summary="Test",
    )
    check(
        "a fresh case starts in NEW",
        case.status == int(CaseStatus.NEW),
        f"status={STATUS_NAMES[case.status]}",
    )
    transition(case, to=int(CaseStatus.UNDER_INVESTIGATION), actor_id="bob")
    check(
        "NEW -> UNDER_INVESTIGATION is allowed",
        case.status == int(CaseStatus.UNDER_INVESTIGATION),
        f"status={STATUS_NAMES[case.status]}",
    )
    check(
        "the transition is recorded on the timeline",
        any(
            e.kind == "status_change"
            for e in case.timeline
        ),
        f"timeline kinds={[e.kind for e in case.timeline]}",
    )
    record(case, actor_id="bob", kind="note", description="Investigating")
    check(
        "notes do not change the case status",
        case.status == int(CaseStatus.UNDER_INVESTIGATION)
        and any(e.kind == "note" for e in case.timeline),
        f"status={STATUS_NAMES[case.status]}",
    )
    check(
        "an illegal transition raises",
        raises(
            ValueError,
            lambda: transition(
                case, to=int(CaseStatus.ARCHIVED), actor_id="bob",
            ),
        ),
        "illegal transition",
    )


def test_case_store_dedupes() -> None:
    print("\n[cases] the store dedupes on source_incident_uid")
    store = CaseStore()
    c1 = store.open_case(
        source_incident_uid="i-1", title="First", summary="...",
        severity_id=4,
    )
    c2 = store.open_case(
        source_incident_uid="i-1", title="Second", summary="...",
        severity_id=5, attack_ids=["T1485"],
    )
    check(
        "the second open on the same incident returns the same case",
        c1.uid == c2.uid,
        f"uids: {c1.uid} {c2.uid}",
    )
    check(
        "the merged case carries the new severity and attack ids",
        c2.severity_id == 5 and "T1485" in c2.attack_ids,
        f"severity={c2.severity_id} attacks={c2.attack_ids}",
    )
    check(
        "the store has exactly one case",
        len(store.list_open()) == 1,
        f"open={len(store.list_open())}",
    )


# ── metrics ────────────────────────────────────────────────────────────────


def test_metrics_tracker() -> None:
    print("\n[metrics] the tracker records MTTD, MTTR, and verdict counts")
    m = MetricsTracker()
    m.observe_finding(event_time=0.0, detected_at=10.0)
    m.observe_finding(event_time=100.0, detected_at=110.0)
    sample = m.sample()
    check(
        "the MTTD is the mean of the per-finding deltas",
        sample.mttd_seconds == 10.0,
        f"mttd={sample.mttd_seconds}",
    )
    check(
        "the alert volume matches the observed findings",
        sample.alert_volume == 2,
        f"alerts={sample.alert_volume}",
    )
    from triage import Disposition, DispositionRecord
    rec_tp = DispositionRecord(incident_uid="i-1", analyst_id="bob",
                                disposition_id=int(Disposition.TRUE_POSITIVE))
    rec_tp.created_at = 1_000_000.0
    m.observe_disposition(rec_tp, incident_window_end=999_990.0)
    sample2 = m.sample()
    check(
        "the MTTR is the per-disposition delta",
        abs(sample2.mttr_seconds - 10.0) < 1e-6,
        f"mttr={sample2.mttr_seconds}",
    )
    check(
        "the escalation rate counts TRUE_POSITIVE",
        sample2.escalation_rate > 0,
        f"escalation_rate={sample2.escalation_rate}",
    )


# ── compliance ────────────────────────────────────────────────────────────


def test_compliance_evaluations() -> None:
    print("\n[compliance] NIST, SOC 2, and ISO 27001 evaluate the same events")
    events = [
        {
            "class_uid": 3002,
            "metadata_uid": "e1",
            "actor": {"user": {"email_addr": "alice@contoso.com"}},
            "src_endpoint_ip": "1.2.3.4",
            "cloud_provider": "Microsoft Azure",
            "cloud_account_uid": "sub-1",
            "metadata_logged_time": "2026-03-11T08:00:00Z",
        },
        {
            "class_uid": 6003,
            "metadata_uid": "e2",
            "metadata_logged_time": "2026-03-11T08:01:00Z",
            "metadata_product_name": "Cloud Audit Logs",
            "metadata_labels": ["tier0-role", "attack:T1078"],
            "actor": {"user": {"email_addr": "alice@contoso.com"}},
            "severity_id": 4,
            "status_id": 1,
            "cloud_account_uid": "sub-1",
            "cloud_provider": "Google Cloud",
        },
        {
            "class_uid": 2004,
            "severity_id": 4,
            "metadata_uid": "e3",
            "metadata_product_name": "Cyphra SOC",
            "metadata_logged_time": "2026-03-11T08:02:00Z",
            "finding_info": [{"name": "Tier-0 grant"}],
        },
    ]
    results = evaluate_controls(NIST_800_53 + SOC2 + ISO_27001, events)
    check(
        "every control has a status",
        all(r.status is not None for r in results),
        f"got {len(results)} evaluations",
    )
    # Count by status.
    by_status: dict[ControlStatus, int] = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    check(
        "the shipped control library has at least one PASS",
        by_status.get(ControlStatus.PASS, 0) > 0,
        f"by_status={by_status}",
    )
    check(
        "the shipped control library has at least one NOT_APPLICABLE",
        by_status.get(ControlStatus.NOT_APPLICABLE, 0) > 0,
        f"by_status={by_status}",
    )


def test_compliance_default_frameworks() -> None:
    print("\n[compliance] the default frameworks return three control lists")
    frameworks = default_frameworks()
    check(
        "the default catalogue has NIST, SOC 2 and ISO 27001",
        set(frameworks) == {"nist_800_53", "soc2", "iso_27001"},
        f"keys={set(frameworks)}",
    )
    check(
        "every framework has at least four controls",
        all(len(controls) >= 4 for controls in frameworks.values()),
        f"counts={[len(c) for c in frameworks.values()]}",
    )


# ── crisis ─────────────────────────────────────────────────────────────────


def test_crisis_lifecycle() -> None:
    print("\n[crisis] a crisis opens, activates, contains, and closes")
    from cases import CaseStore, Case, transition
    from triage import Disposition, DispositionRecord
    from respond import PlaybookDispatcher
    store = CaseStore()
    case = store.open_case(
        source_incident_uid="i-test",
        title="Compromise",
        summary="Tier-0 grant",
        severity_id=5,
        attack_ids=["T1078"],
        actor_keys=["alice@contoso.com"],
        target_keys=["asset-1"],
    )
    manager = CrisisManager(store, PlaybookDispatcher())
    crisis = manager.open(
        name="Test Crisis",
        description="Multi-case test",
        actor_id="commander",
        case_uids=[case.uid],
        playbook_ids=["compromise_response"],
    )
    check(
        "a fresh crisis is ACTIVE",
        crisis.status == int(CrisisStatus.ACTIVE),
        f"status={CRISIS_STATUS_NAMES[crisis.status]}",
    )
    activated = manager.activate(crisis.uid)
    check(
        "an activated crisis ran its playbooks",
        activated is not None and len(activated.playbook_results) >= 1,
        f"results={len(activated.playbook_results)}",
    )
    check(
        "the stats reflect the playbook run",
        manager.stats.playbooks_run >= 1
        and manager.stats.actions_applied >= 1,
        f"playbooks_run={manager.stats.playbooks_run} actions_applied={manager.stats.actions_applied}",
    )
    contained = manager.contain(crisis.uid)
    check(
        "containment moves ACTIVE -> CONTAINED",
        contained.status == int(CrisisStatus.CONTAINED),
        f"status={CRISIS_STATUS_NAMES[contained.status]}",
    )
    closed = manager.close(crisis.uid)
    check(
        "closing moves CONTAINED -> CLOSED",
        closed.status == int(CrisisStatus.CLOSED),
        f"status={CRISIS_STATUS_NAMES[closed.status]}",
    )


# ── learn job ─────────────────────────────────────────────────────────────


def test_retrain_job_atomic_swap() -> None:
    print("\n[learn] the periodic retrain job swaps the model atomically")
    # Build a tiny training set.
    from core.schema.ocsf import Verdict as OcsfVerdict
    from learn.features import extract_features
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "verdicts.ndjson"
        store = VerdictStore(store_path)
        payloads: dict[str, dict] = {}
        for i in range(40):
            is_threat = i % 2 == 0
            payload = {
                "class_uid": 3002 if is_threat else 1007,
                "metadata_product_vendor_name": "Microsoft",
                "metadata_product_name": "Entra ID Sign-in Logs",
                "metadata_uid": f"e{i}",
                "actor_session_is_mfa": not is_threat,
                "is_alert": is_threat,
                "actor": {"user": {"name": "alice" if is_threat else "bob"}},
                "src_endpoint_ip": "1.2.3.4" if is_threat else "",
                "metadata_labels": ["attack:T1078"] if is_threat else [],
                "status_id": 2 if is_threat else 1,
                "activity_id": 1,
                "severity_id": 4 if is_threat else 1,
            }
            payloads[payload["metadata_uid"]] = payload
            store.append(Verdict(
                alert_uid=payload["metadata_uid"],
                analyst_id="analyst",
                verdict_id=int(OcsfVerdict.TRUE_POSITIVE if is_threat else OcsfVerdict.FALSE_POSITIVE),
            ))
        # Build a placeholder model and the job.
        vectors = [extract_features(p) for p in payloads.values()]
        labels = [1 if i % 2 == 0 else 0 for i in range(40)]
        seed = train(vectors, labels, threshold=0.5)
        job = RetrainJob(
            current_model=seed,
            verdict_store=store,
            payload_supplier=lambda uids: {u: payloads[u] for u in uids if u in payloads},
            config=RetrainJobConfig(min_verdicts=10, cooldown_seconds=0.0),
            clock=lambda: 1_000_000.0,
        )
        check(
            "the job is due when verdicts are above the minimum",
            job.should_run(),
            "should_run",
        )
        # The job must NOT swap when the retrain fails (no verdicts).
        empty_store = VerdictStore(Path(tmp) / "empty.ndjson")
        empty_job = RetrainJob(
            current_model=seed,
            verdict_store=empty_store,
            payload_supplier=lambda uids: {},
            config=RetrainJobConfig(min_verdicts=10, cooldown_seconds=0.0),
            clock=lambda: 1_000_000.0,
        )
        check(
            "the job refuses to retrain on fewer than min_verdicts",
            not empty_job.should_run(),
            "should_run empty",
        )
        stats = job.run_once()
        check(
            "the job succeeds on a non-empty verdict store",
            stats.successes == 1,
            f"successes={stats.successes}",
        )
        check(
            "the model is swapped atomically on success",
            job.model is not seed,
            f"model swapped={job.model is not seed}",
        )


# ── helpers ────────────────────────────────────────────────────────────────


def raises(exc_type: type[BaseException], fn) -> bool:
    try:
        fn()
    except exc_type:
        return True
    except Exception:
        return False
    return False


# ── entry ──────────────────────────────────────────────────────────────────


def main() -> int:
    test_case_state_machine()
    test_case_store_dedupes()
    test_metrics_tracker()
    test_compliance_evaluations()
    test_compliance_default_frameworks()
    test_crisis_lifecycle()
    test_retrain_job_atomic_swap()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

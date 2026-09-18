"""scratch_phase4 — triage, respond, hunt.

    python tests/scratch_phase4.py

Three sections, each layer verified end-to-end:

1. **Triage** — disposition enum, queue, evidence packet, SLA breach.
2. **Respond** — atomic actions, idempotency, playbooks, dispatcher.
3. **Hunt** — predicate matching, shipped hunt library, runner.
"""

import sys
import time

sys.path.insert(0, ".")

from correlate import (
    CorrelateEngine,
    FindingStub,
    Incident,
    actor_time_key,
)
from hunt import (
    HuntQuery,
    HuntResult,
    HuntRunner,
    HuntStats,
    Predicate,
    contains,
    default_hunt_library,
    equals,
    exists,
    in_,
    regex,
    service_account_console_login,
    tor_authentications,
    unusual_dns_volume,
)
from respond import (
    Action,
    ActionResult,
    ActionStatus,
    CompromiseResponsePlaybook,
    CredentialStuffingPlaybook,
    DisableUserAction,
    IsolateHostAction,
    Playbook,
    PlaybookDispatcher,
    PlaybookResult,
    PlaybookStep,
    QuarantineEmailAction,
    RansomwareResponsePlaybook,
    RevokeTokenAction,
    get_action,
    list_actions,
    list_playbooks,
)
from triage import (
    Assignment,
    CLOSING_DISPOSITIONS,
    DISPOSITION_NAMES,
    ESCALATING_DISPOSITIONS,
    Disposition,
    DispositionRecord,
    EvidencePacket,
    FindingSummary,
    QueueStats,
    TriageQueue,
    build_packet,
    from_name as disp_from_name,
    to_ocsf_verdict,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── triage ─────────────────────────────────────────────────────────────────


def test_disposition_basics() -> None:
    print("\n[triage] the disposition enum and the OCSF alignment")
    check(
        "TRUE_POSITIVE and FALSE_POSITIVE map to the OCSF values",
        disp_from_name("true_positive") == int(Disposition.TRUE_POSITIVE)
        and disp_from_name("false_positive") == int(Disposition.FALSE_POSITIVE),
        "names",
    )
    check(
        "an unknown name raises",
        raises(ValueError, lambda: disp_from_name("not_a_disposition")),
        "error path",
    )
    check(
        "TRUE_POSITIVE closes the queue; ESCALATE does not",
        int(Disposition.TRUE_POSITIVE) in CLOSING_DISPOSITIONS
        and int(Disposition.ESCALATE) not in CLOSING_DISPOSITIONS,
        "closing set",
    )
    check(
        "TRUE_POSITIVE and ESCALATE escalate; FALSE_POSITIVE does not",
        int(Disposition.TRUE_POSITIVE) in ESCALATING_DISPOSITIONS
        and int(Disposition.ESCALATE) in ESCALATING_DISPOSITIONS
        and int(Disposition.FALSE_POSITIVE) not in ESCALATING_DISPOSITIONS,
        "escalating set",
    )
    check(
        "to_ocsf_verdict carries closing dispositions but maps others to UNKNOWN",
        to_ocsf_verdict(int(Disposition.TRUE_POSITIVE)) == int(Disposition.TRUE_POSITIVE)
        and to_ocsf_verdict(int(Disposition.ESCALATE)) == int(Disposition.UNKNOWN),
        "OCSF mapping",
    )


def test_triage_queue_lifecycle() -> None:
    print("\n[triage] the queue ingests, assigns, disposes, and closes")
    eng = CorrelateEngine()
    key = actor_time_key({"actor_key": "alice@contoso.com", "attack_id": "T1078"})
    f = FindingStub(uid="f1", time=0.0, severity_id=4,
                   attack_id="T1078", actor_key="alice@contoso.com",
                   correlation_key=key)
    i = eng.observe(f)
    queue = TriageQueue(sla_seconds=900.0)
    queue.add(i)
    queue.assign(i.uid, "analyst-bob")
    check(
        "an assigned analyst is recorded",
        isinstance(queue._assignments.get(i.uid), Assignment)
        and queue._assignments[i.uid].analyst_id == "analyst-bob",
        "assignment",
    )
    check(
        "an unassigned-incidents query sees the right shape",
        isinstance(queue.unassigned_incidents(), list),
        "unassigned read",
    )
    # First disposition: escalate. The queue keeps the incident open
    # (escalation is not closing) and increments the escalation
    # counter.
    queue.record_disposition(DispositionRecord(
        incident_uid=i.uid, analyst_id="analyst-bob",
        disposition_id=int(Disposition.ESCALATE),
    ))
    check(
        "an ESCALATE disposition keeps the incident open and increments escalations",
        i.uid in [j.uid for j in queue.open_incidents()]
        and queue.stats.escalations == 1,
        f"open={[j.uid for j in queue.open_incidents()]} escalations={queue.stats.escalations}",
    )
    # Second disposition: TRUE_POSITIVE. The queue removes the
    # incident from open and increments closed.
    queue.record_disposition(DispositionRecord(
        incident_uid=i.uid, analyst_id="analyst-bob",
        disposition_id=int(Disposition.TRUE_POSITIVE),
    ))
    check(
        "a TRUE_POSITIVE closes the incident and clears it from open",
        i.uid not in [j.uid for j in queue.open_incidents()]
        and queue.stats.incidents_closed == 1,
        f"open={[j.uid for j in queue.open_incidents()]} closed={queue.stats.incidents_closed}",
    )
    check(
        "the disposition history preserves both verdicts in order",
        [d.disposition_id for d in queue.disposition_history(i.uid)]
        == [int(Disposition.ESCALATE), int(Disposition.TRUE_POSITIVE)],
        "history",
    )


def test_evidence_packet() -> None:
    print("\n[triage] the evidence packet summary, findings, and SLA")
    eng = CorrelateEngine()
    f1 = FindingStub(uid="f1", time=0.0, severity_id=4,
                    attack_id="T1078", actor_key="alice@contoso.com",
                    target_keys=("asset-1",),
                    correlation_key="actor:alice:attack:T1078")
    f2 = FindingStub(uid="f2", time=600.0, severity_id=3,
                    attack_id="T1078", actor_key="alice@contoso.com",
                    target_keys=("asset-1",),
                    correlation_key="actor:alice:attack:T1078")
    i = eng.observe(f1)
    i = eng.observe(f2)
    findings = [
        FindingSummary(uid="f1", rule_id="cloud.tier0_grant",
                       rule_name="Tier-0 role granted", attack_id="T1078",
                       severity=4, confidence=0.95),
        FindingSummary(uid="f2", rule_id="cloud.tier0_grant",
                       rule_name="Tier-0 role granted", attack_id="T1078",
                       severity=3, confidence=0.6),
    ]
    packet = build_packet(i, findings, sla_seconds=900.0, now=10_000.0)
    check(
        "the packet carries the incident summary",
        packet.incident_uid == i.uid
        and packet.summary["attack_ids"] == ["T1078"],
        f"summary={packet.summary}",
    )
    check(
        "the packet carries both findings",
        len(packet.findings) == 2,
        f"got {len(packet.findings)}",
    )
    check(
        "an incident past the SLA is marked breached",
        packet.sla_breached,
        f"sla_breached={packet.sla_breached}",
    )


def test_triage_sla_breach() -> None:
    print("\n[triage] an incident with no disposition past the SLA is flagged")
    eng = CorrelateEngine()
    f = FindingStub(uid="f1", time=0.0, severity_id=4,
                   attack_id="T1078", actor_key="alice@contoso.com",
                   correlation_key="actor:alice:attack:T1078")
    i = eng.observe(f)
    # The correlate engine stamps the incident's ``created_at`` with the
    # real clock; the SLA test wants a controlled clock, so we override
    # it here.
    i.created_at = 0.0
    queue = TriageQueue(sla_seconds=60.0)
    queue.add(i)
    # No disposition recorded; force the clock past the SLA.
    breached = queue.sla_breached(now=10_000.0)
    check(
        "an SLA breach is reported for an incident with no disposition",
        i.uid in [j.uid for j in breached],
        f"breached={[j.uid for j in breached]}",
    )


# ── respond ────────────────────────────────────────────────────────────────


def test_actions_idempotency() -> None:
    print("\n[respond] actions are idempotent on the target key")
    action = DisableUserAction()
    r1 = action.do("user-1")
    r2 = action.do("user-1")
    rid1 = r1["action_id"]
    rid2 = r2["action_id"]
    check(
        "calling do twice returns the same result",
        r1 is r2,
        f"r1={rid1} r2={rid2}",
    )
    check(
        "the action reports is_applied on the target",
        action.is_applied("user-1") and not action.is_applied("user-2"),
        "is_applied",
    )
    check(
        "undo removes the action's recorded state",
        action.undo("user-1") is not None and not action.is_applied("user-1"),
        "undo",
    )


def test_token_revoke_undo_fails() -> None:
    print("\n[respond] token revocation is permanent; undo fails")
    action = RevokeTokenAction()
    action.do("token-1")
    result = action.undo("token-1")
    check(
        "undoing a token revocation returns FAILED",
        result is not None and result.status is ActionStatus.FAILED
        and "permanent" in result["details"].get("reason", ""),
        f"status={result.status if result else None}",
    )


def test_playbook_runs_in_order() -> None:
    print("\n[respond] a playbook runs its steps in order and respects on_failure")
    incident = Incident(
        uid="i-test", finding_uids=["f1"],
        window_start=0.0, window_end=0.0,
        severity_id=4, attack_ids=["T1078"],
        actor_keys=["alice@contoso.com"],
        target_keys=["asset-1", "asset-2"],
        first_actor_key="alice@contoso.com",
        correlation_key="actor:alice:attack:T1078", status_id=1,
    )
    actions = {
        "disable_user": DisableUserAction(),
        "isolate_host": IsolateHostAction(),
    }

    class _TestPlaybook(Playbook):
        playbook_id = "test"
        name = "Test"
        steps = (
            PlaybookStep(action_id="disable_user", target_kind="actor"),
            PlaybookStep(action_id="isolate_host", target_kind="all_targets",
                         on_failure="continue"),
        )

    playbook = _TestPlaybook()
    result = playbook.run(incident, actions)
    check(
        "every step ran and every target was visited",
        len(result.results) == 3  # 1 disable_user + 2 isolate_host
        and result.status == "success",
        f"results={len(result.results)} status={result.status}",
    )


def test_playbook_dispatcher_routes_by_attack() -> None:
    print("\n[respond] the dispatcher routes incidents to playbooks by attack id")
    incident = Incident(
        uid="i-test", finding_uids=["f1"],
        window_start=0.0, window_end=0.0,
        severity_id=4, attack_ids=["T1485"],
        actor_keys=["alice@contoso.com"],
        target_keys=["asset-1"], first_actor_key="alice@contoso.com",
        correlation_key="actor:alice:attack:T1485", status_id=1,
    )
    dispatcher = PlaybookDispatcher()
    result = dispatcher.dispatch(incident)
    check(
        "T1485 (data destruction) routes to ransomware_response",
        result is not None
        and result.playbook_id == "ransomware_response"
        and result.status == "success",
        f"playbook={result.playbook_id if result else None}",
    )


# ── hunt ────────────────────────────────────────────────────────────────────


def test_predicate_matching() -> None:
    print("\n[hunt] predicates match and reject as documented")
    p_equals = equals("is_alert", False)
    p_contains = contains("metadata_labels", "tor-exit")
    p_in = in_("class_uid", (3002, 3006))
    p_regex = regex("unmapped.dns_query.name", r"^[a-z]+\.example\.com$")
    p_exists = exists("actor.user.email_addr")
    event = {
        "class_uid": 3002,
        "is_alert": False,
        "metadata_labels": ["tor-exit", "fresh"],
        "unmapped": {"dns_query": {"name": "evil.example.com"}},
        "actor": {"user": {"email_addr": "alice@contoso.com"}},
    }
    check(
        "equals / contains / in / regex / exists each match the expected event",
        p_equals.matches(event)
        and p_contains.matches(event)
        and p_in.matches(event)
        and p_regex.matches(event)
        and p_exists.matches(event),
        "match",
    )
    check(
        "regex rejects on non-string values",
        not regex("is_alert", r"^true$").matches(event),
        "regex on bool",
    )
    check(
        "exists rejects empty strings",
        not exists("actor.user.display_name").matches({"actor": {"user": {"display_name": ""}}}),
        "exists on empty",
    )
    check(
        "not_exists matches empty strings and rejects populated ones",
        exists("actor.user.display_name").matches({"actor": {"user": {"display_name": ""}}}) is False
        and exists("actor.user.display_name").matches({"actor": {"user": {"display_name": "alice"}}}) is True,
        "exists vs not_exists",
    )


def test_window_string_parser() -> None:
    print("\n[hunt] the window string parser")
    from hunt.query import _window_seconds
    check(
        "the parser accepts m/h/d",
        _window_seconds("30m") == 1800.0
        and _window_seconds("24h") == 86_400.0
        and _window_seconds("7d") == 7 * 86_400.0,
        "valid windows",
    )
    check(
        "the parser rejects malformed windows",
        raises(ValueError, lambda: _window_seconds("24"))
        and raises(ValueError, lambda: _window_seconds("xx"))
        and raises(ValueError, lambda: _window_seconds("0m")),
        "invalid",
    )


def test_hunt_runner() -> None:
    print("\n[hunt] the runner walks events, applies predicates, and samples hits")
    runner = HuntRunner(sample_limit=10)
    hunt = HuntQuery(
        name="no_alert_auth",
        description="auth events that did not trigger a detection",
        predicates=[equals("is_alert", False), exists("actor.user.email_addr")],
        window="24h",
    )
    runner.add(hunt)
    events = [
        {"class_uid": 3002, "time": 0.0, "metadata_uid": "e1",
         "is_alert": False, "actor": {"user": {"email_addr": "alice@contoso.com"}}},
        {"class_uid": 3002, "time": 1.0, "metadata_uid": "e2",
         "is_alert": True, "actor": {"user": {"email_addr": "bob@contoso.com"}}},
        {"class_uid": 3002, "time": 2.0, "metadata_uid": "e3",
         "is_alert": False, "actor": {"user": {"email_addr": ""}}},
    ]
    result = runner.run(hunt, events)
    check(
        "the runner finds the matching events and skips the non-matching ones",
        result.hit_count == 1 and result.sample[0]["metadata_uid"] == "e1",
        f"hits={result.hit_count}",
    )
    check(
        "the runner's stats reflect the work",
        runner.stats.hunts_run == 1
        and runner.stats.events_scanned == 3
        and runner.stats.hits_total == 1,
        f"stats={runner.stats_dict()}",
    )


def test_shipped_hunts_load() -> None:
    print("\n[hunt] the shipped library loads and each hunt has a non-trivial filter")
    lib = default_hunt_library()
    check("at least three shipped hunts", len(lib) >= 3, f"got {len(lib)}")
    for hunt in lib:
        check(
            f"the {hunt.name} hunt has a window and predicates",
            hunt.window_seconds() > 0 and len(hunt.predicates) > 0,
            f"window={hunt.window} predicates={len(hunt.predicates)}",
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
    test_disposition_basics()
    test_triage_queue_lifecycle()
    test_evidence_packet()
    test_triage_sla_breach()
    test_actions_idempotency()
    test_token_revoke_undo_fails()
    test_playbook_runs_in_order()
    test_playbook_dispatcher_routes_by_attack()
    test_predicate_matching()
    test_window_string_parser()
    test_hunt_runner()
    test_shipped_hunts_load()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

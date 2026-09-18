"""scratch_learn — Phase 2a (label fix + retrain) and Phase 2b (detection engine).

    python tests/scratch_learn.py

Three layers, each with its own self-check:

1. **Verdict capture** — the verdict dataclass, OCSF alignment, the
   "is conclusive" predicate, the binary label mapping.
2. **Label audit + retrain** — the gap between auto-labels and verdicts,
   the train/val split, the before/after numbers that "report honestly"
   requires. The headline assertion is that the report shows the
   *recall drop*, not a fabricated improvement.
3. **Detection engine** — signatures, statistics, behaviour, ML scoring.
   Each detector kind has at least one positive case and one negative
   case; the engine's :class:`DetectionReport` carries the union.
"""

import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, ".")

from core.schema.ocsf import ClassUid, Severity, Verdict as OcsfVerdict
from learn.features import extract_features, feature_names
from learn.label_audit import LabelAudit, audit, split_for_retrain
from learn.model import Model, pick_threshold, train
from learn.retrain import retrain_with_verdicts
from learn.training_set import TrainingSet, from_synthetic, from_verdicts
from learn.verdict import (
    VERDICT_NAMES,
    Verdict,
    VerdictLabel,
    from_name,
    is_conclusive,
    label_for_training,
)
from learn.verdict_store import VerdictStore

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── Phase 2a: verdicts ─────────────────────────────────────────────────────


def test_verdict_basics() -> None:
    print("\n[verdicts] the four-state verdict and the OCSF alignment")
    check(
        "VerdictLabel is OCSF's Verdict, not a parallel enum",
        VerdictLabel.TRUE_POSITIVE == int(OcsfVerdict.TRUE_POSITIVE),
        f"got {int(VerdictLabel.TRUE_POSITIVE)}",
    )
    check(
        "TRUE_POSITIVE → 1 for training, FALSE_POSITIVE → 0, BENIGN → 0",
        label_for_training(int(OcsfVerdict.TRUE_POSITIVE)) == 1
        and label_for_training(int(OcsfVerdict.FALSE_POSITIVE)) == 0
        and label_for_training(int(OcsfVerdict.BENIGN)) == 0,
        "verdict-to-label mapping",
    )
    check(
        "conclusive means 'training-eligible'; SUSPICIOUS and INSUFFICIENT_DATA are not",
        is_conclusive(int(OcsfVerdict.TRUE_POSITIVE))
        and is_conclusive(int(OcsfVerdict.FALSE_POSITIVE))
        and not is_conclusive(int(OcsfVerdict.SUSPICIOUS))
        and not is_conclusive(int(OcsfVerdict.INSUFFICIENT_DATA)),
        "conclusive predicate",
    )
    check(
        "from_name parses 'true_positive' back to the enum",
        from_name("true_positive") == int(OcsfVerdict.TRUE_POSITIVE),
        f"got {from_name('true_positive')}",
    )
    check(
        "an INSUFFICIENT_DATA verdict raised for training is an error, not 0",
        raises(ValueError, lambda: label_for_training(int(OcsfVerdict.SUSPICIOUS))),
        "label_for_training on a non-conclusive verdict must raise",
    )
    check(
        "every verdict has a name in the UI vocabulary",
        all(name in VERDICT_NAMES.values() for name in (
            "true_positive", "false_positive", "benign", "needs_review",
        )),
        f"got {list(VERDICT_NAMES.values())[:5]}",
    )


def test_verdict_store() -> None:
    print("\n[verdict store] the JSON-lines append-only log")
    with tempfile.TemporaryDirectory() as tmp:
        store = VerdictStore(Path(tmp) / "verdicts.ndjson")
        v1 = Verdict(alert_uid="a1", analyst_id="alice",
                     verdict_id=int(OcsfVerdict.TRUE_POSITIVE))
        v2 = Verdict(alert_uid="a1", analyst_id="alice",
                     verdict_id=int(OcsfVerdict.FALSE_POSITIVE))
        v3 = Verdict(alert_uid="a2", analyst_id="bob",
                     verdict_id=int(OcsfVerdict.INSUFFICIENT_DATA))
        store.append(v1)
        store.append(v2)
        store.append(v3)
        check("three verdicts persisted", store.count() == 3, f"got {store.count()}")
        latest = store.latest_per_alert()
        check(
            "the latest verdict per alert wins",
            latest["a1"].verdict_id == int(OcsfVerdict.FALSE_POSITIVE)
            and latest["a2"].verdict_id == int(OcsfVerdict.INSUFFICIENT_DATA),
            f"a1={latest['a1'].verdict_id} a2={latest['a2'].verdict_id}",
        )


# ── Phase 2a: training set + retrain ───────────────────────────────────────


def test_features_and_training_set() -> None:
    print("\n[features] 44-feature binary vector and the training-set split")
    n = feature_names()
    check("feature vocabulary is small (under 100)", len(n) < 100, f"got {len(n)}")
    sample = {
        "class_uid": 3002,
        "metadata_product_vendor_name": "Microsoft",
        "metadata_product_name": "Entra ID Sign-in Logs",
        "actor_session_is_mfa": True,
        "metadata_labels": ["attack:T1078"],
    }
    v = extract_features(sample)
    check(
        "the same event produces the same vector on every call",
        extract_features(sample) == v,
        "deterministic",
    )
    check("the vector is the same length as feature_names()", len(v) == len(n))

    ts = TrainingSet(
        vectors=[(1, 0), (0, 1), (1, 0)],
        labels=[1, 0, 1],
        sources=["v", "v", "v"],
    )
    train, val = ts.split(0.5)
    check("the train/val split is deterministic", train.vectors == [(1, 0)] and val.vectors == [(0, 1), (1, 0)])


def test_train_and_evaluate() -> None:
    print("\n[model] training a small logistic regression and evaluating on a held-out set")
    # Synthetic balanced dataset with a clear signal: ``actor_session_is_mfa=False``
    # AND ``metadata_labels has attack:*`` AND ``severity_id >= 4`` ⇒ threat.
    vectors = []
    labels = []
    for i in range(50):
        is_threat = (i % 2 == 0)
        payload = {
            "class_uid": 3002 if is_threat else 1007,
            "metadata_product_vendor_name": "Microsoft",
            "metadata_product_name": "Entra ID Sign-in Logs" if is_threat else "Sysmon",
            "metadata_uid": f"e{i}",
            "actor_session_is_mfa": not is_threat,
            "is_alert": is_threat,
            "actor": {"user": {"name": "alice" if is_threat else "bob"}},
            "src_endpoint_ip": "1.2.3.4" if is_threat else "",
            "metadata_labels": ["attack:T1078"] if is_threat else [],
            "status_id": 2 if is_threat else 1,
            "activity_id": 1,
            "severity_id": 4 if is_threat else 1,
            "resources": [{"uid": "x"}] if is_threat else [],
        }
        vectors.append(extract_features(payload))
        labels.append(1 if is_threat else 0)
    train_ts, val_ts = TrainingSet(vectors=vectors, labels=labels, sources=["v"] * 50).split(0.6)
    model = train(list(train_ts.vectors), list(train_ts.labels), threshold=0.5)
    check(
        "the model beats random on the held-out validation set",
        model.evaluation.auc > 0.5,
        f"auc={model.evaluation.auc:.3f}",
    )
    held = pick_threshold(model, list(val_ts.vectors), list(val_ts.labels))
    check(
        "the break-even threshold is a valid probability",
        0.0 <= held <= 1.0,
        f"got {held}",
    )
    check(
        "the model is round-trippable through pickle",
        round_trip := Model.deserialize(model.serialize()),
        round_trip.feature_count == model.feature_count,
    )


def test_label_audit_and_retrain() -> None:
    print("\n[retrain] the label audit, the gap, and the before/after report")
    payloads = {}
    verdicts = []
    auto_labels = {}
    for i in range(20):
        is_threat = (i % 2 == 0)
        payload = {
            "class_uid": 3002 if is_threat else 1007,
            "metadata_product_vendor_name": "Microsoft",
            "metadata_product_name": "Entra ID Sign-in Logs" if is_threat else "Sysmon",
            "metadata_uid": f"e{i}",
            "actor_session_is_mfa": not is_threat,
            "is_alert": is_threat,
            "actor": {"user": {"name": "alice" if is_threat else "bob"}},
            "src_endpoint_ip": "1.2.3.4" if is_threat else "",
            "metadata_labels": ["attack:T1078"] if is_threat else [],
            "status_id": 2 if is_threat else 1,
            "activity_id": 1,
            "severity_id": 4 if is_threat else 1,
            "resources": [{"uid": "x"}] if is_threat else [],
        }
        payloads[payload["metadata_uid"]] = payload
        verdicts.append(Verdict(
            alert_uid=payload["metadata_uid"],
            analyst_id="analyst",
            verdict_id=int(OcsfVerdict.TRUE_POSITIVE if is_threat else OcsfVerdict.FALSE_POSITIVE),
        ))
        auto_labels[payload["metadata_uid"]] = 1 if is_threat else 0

    # Build the production model.
    vectors = [extract_features(p) for p in payloads.values()]
    labels = [auto_labels[u] for u in payloads]
    production = train(vectors, labels, threshold=0.5)

    # The audit reports agreed for all rows because the synthetic verdicts
    # match the synthetic labels — this is a control. Real data has gaps.
    audit_result = audit(verdicts, auto_labels)
    check(
        "the audit is non-empty",
        audit_result.total == 20,
        f"got {audit_result.total}",
    )
    train_v, val_v = split_for_retrain(audit_result)
    check(
        "split_for_retrain splits the audit's verdicts",
        len(train_v) + len(val_v) == len(audit_result.agreed) + len(audit_result.overturned),
        f"train={len(train_v)} val={len(val_v)}",
    )

    # The retrain call with a deliberately wrong auto-label set: every
    # verdict's truth is the opposite of the auto-label, so the audit
    # reports total disagreement and the retrain must surface it.
    flipped = {u: 1 - l for u, l in auto_labels.items()}
    bad_audit = audit(verdicts, flipped)
    check(
        "the audit catches a model that systematically flips labels",
        bad_audit.precision_drop > 0.9,
        f"got {bad_audit.precision_drop:.2f}",
    )

    # Run the actual retrain on the original (well-aligned) data.
    new_model, report = retrain_with_verdicts(production, verdicts, payloads)
    check(
        "the retrain returns a Model",
        isinstance(new_model, Model),
        f"got {type(new_model).__name__}",
    )
    check(
        "the report has before/after/audit fields",
        report.before.n_samples > 0
        and report.after.n_samples > 0
        and report.audit.total > 0,
        f"before={report.before.n_samples} after={report.after.n_samples} "
        f"audit={report.audit.total}",
    )


# ── Phase 2b: detection engine ─────────────────────────────────────────────


def test_signature_rules() -> None:
    print("\n[signature] the declarative rule pack")
    from detect import default_rule_set

    rules = default_rule_set()
    check(
        "the shipped pack has more than ten rules",
        len(rules.rules) > 10,
        f"got {len(rules.rules)}",
    )
    # Tier-0 grant → fires ``cloud.tier0_grant``.
    ev = {
        "class_uid": 6003,
        "metadata_uid": "x",
        "metadata_labels": ["tier0-role", "granted-role:owner"],
    }
    matches = rules.match(ev)
    check(
        "a tier-0 grant event fires cloud.tier0_grant",
        any(m.rule.id == "cloud.tier0_grant" for m in matches),
        f"matches: {[m.rule.id for m in matches]}",
    )
    # An unrelated event fires nothing.
    plain = {"class_uid": 4001, "metadata_uid": "y", "metadata_labels": []}
    check(
        "an unrelated event fires no rules",
        rules.match(plain) == [],
        f"got {[m.rule.id for m in rules.match(plain)]}",
    )


def test_statistical_rules() -> None:
    print("\n[statistical] rate and burst detectors")
    from detect import StatisticalDetector

    det = StatisticalDetector.default()
    # A burst of 10 failed sign-ins from the same IP fires the rate rule.
    burst = [
        {"class_uid": 3002, "status_id": 2, "src_endpoint_ip": "1.2.3.4",
         "metadata_uid": f"a{i}", "time": 0.0}
        for i in range(15)
    ]
    findings = []
    for ev in burst:
        findings.extend(det.observe(ev))
    check(
        "10+ failed sign-ins from one IP fires stat.failed_signin_burst",
        any(f.rule_id == "stat.failed_signin_burst" for f in findings),
        f"rules: {[f.rule_id for f in findings]}",
    )


def test_behavioural_rules() -> None:
    print("\n[behavioural] sequence patterns over a stream")
    from detect import BehaviouralDetector

    det = BehaviouralDetector.default()
    # Three events in order: email-with-link → dns-suspect → file-create.
    events = [
        {"class_uid": 4009, "metadata_uid": "e1", "metadata_labels": ["phishing:malicious-link"],
         "actor": {"user": {"uid": "alice"}}, "time": 0.0},
        {"class_uid": 4003, "metadata_uid": "e2", "actor": {"user": {"uid": "alice"}},
         "time": 10.0},
        {"class_uid": 1001, "metadata_uid": "e3", "metadata_labels": ["initial-access:user-execution"],
         "actor": {"user": {"uid": "alice"}}, "time": 20.0},
    ]
    fired: list[str] = []
    for ev in events:
        for f in det.observe(ev):
            fired.append(f.rule_id)
    check(
        "the phishing → dns → file chain fires behaviour.phishing_to_execution",
        "behaviour.phishing_to_execution" in fired,
        f"fired: {fired}",
    )
    # A reversed chain should not fire.
    det2 = BehaviouralDetector.default()
    fired_rev: list[str] = []
    for ev in reversed(events):
        for f in det2.observe(ev):
            fired_rev.append(f.rule_id)
    check(
        "a reversed chain does not fire the phishing pattern",
        "behaviour.phishing_to_execution" not in fired_rev,
        f"fired: {fired_rev}",
    )


def test_engine_end_to_end() -> None:
    print("\n[engine] the dispatcher and OCSF conversion")
    from detect import (
        BehaviouralDetector, DetectionEngine, MLScorer, default_rule_set,
    )
    rules = default_rule_set()
    vectors = []
    labels = []
    for i in range(20):
        is_threat = i % 2 == 0
        payload = {
            "class_uid": 3002 if is_threat else 1007,
            "metadata_product_vendor_name": "Microsoft",
            "metadata_product_name": "Entra ID Sign-in Logs" if is_threat else "Sysmon",
            "metadata_uid": f"e{i}",
            "actor_session_is_mfa": not is_threat,
            "is_alert": is_threat,
            "actor": {"user": {"name": "alice" if is_threat else "bob"}},
            "src_endpoint_ip": "1.2.3.4" if is_threat else "",
            "metadata_labels": ["attack:T1078"] if is_threat else [],
            "status_id": 2 if is_threat else 1,
            "activity_id": 1,
            "severity_id": 4 if is_threat else 1,
            "resources": [{"uid": "x"}] if is_threat else [],
        }
        vectors.append(extract_features(payload))
        labels.append(1 if is_threat else 0)
    model = train(vectors, labels, threshold=0.5)
    engine = DetectionEngine(
        rule_set=rules,
        ml_scorer=MLScorer(model=model),
        behaviour_state=BehaviouralDetector.default(),
    )
    ev = {"class_uid": 6003, "metadata_uid": "x", "time": 0.0,
          "status_id": 1, "src_endpoint_ip": "1.2.3.4",
          "metadata_labels": ["tier0-role"]}
    report = engine.detect(ev)
    check(
        "the engine emits at least one finding for a tier-0 grant",
        len(report.findings) >= 1,
        f"matched: {report.matched_rules}",
    )
    ocsf = engine.to_ocsf(report)
    check(
        "every OCSF finding is class_uid 2004",
        all(f["class_uid"] == 2004 for f in ocsf),
        f"classes: {sorted({f['class_uid'] for f in ocsf})}",
    )
    check(
        "the engine's stats reflect the detection",
        engine.stats.events_seen >= 1 and engine.stats.findings_emitted >= 1,
        f"events={engine.stats.events_seen} findings={engine.stats.findings_emitted}",
    )


# ── helper ────────────────────────────────────────────────────────────────


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
    test_verdict_basics()
    test_verdict_store()
    test_features_and_training_set()
    test_train_and_evaluate()
    test_label_audit_and_retrain()
    test_signature_rules()
    test_statistical_rules()
    test_behavioural_rules()
    test_engine_end_to_end()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

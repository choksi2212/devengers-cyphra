"""The retrain pipeline — "Fix it, report honestly".

Phase 2a's headline requirement is a *re*-train, not a one-shot train: the
model on disk is replaced by a model trained on analyst verdicts, and the
report includes the before/after metrics. The function
:func:`retrain_with_verdicts` is the only one a deployment calls; the
others are steps it composes.

The retrain report has six numbers the operator must read:

* ``before.precision`` and ``before.recall`` — the production model's
  performance on the audit split *before* retraining.
* ``after.precision`` and ``after.recall`` — the new model's
  performance on the same split.
* ``before.f1`` and ``after.f1`` — the F1, the single-number summary.

The "report honestly" requirement is the recall number. A naive retrain
on verdicts will often *drop* recall: the model learns what the analyst
calls a false alarm and stops raising the alert on events the analyst
would have caught. That drop is real and must be reported, not hidden.
The right response is *more labels* (more verdicts narrow the gap), not
a higher threshold to mask the drop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from learn.features import extract_features
from learn.label_audit import LabelAudit, audit, split_for_retrain
from learn.model import (
    EvaluationReport,
    Model,
    evaluate,
    pick_threshold,
    train,
)
from learn.training_set import TrainingSet, from_verdicts
from learn.verdict import Verdict


@dataclass
class RetrainReport:
    """Before/after metrics and the audit that produced them.

    ``before`` is the *production* model's evaluation on the audit's
    ``agreed`` rows (the rows the model already got right). ``after`` is
    the *retrained* model's evaluation on the same rows. Both metrics
    are computed with the *same* threshold (the retrained model's
    threshold), so the comparison is fair: the only difference is the
    model itself.

    ``audit`` is the gap report — the headline number is
    ``audit.precision_drop``: the fraction of auto-labels the verdicts
    contradict. A non-trivial drop is the whole reason the retrain
    happened.
    """

    before: EvaluationReport
    after: EvaluationReport
    audit: LabelAudit
    training_rows: int
    validation_rows: int
    notes: list[str] = field(default_factory=list)


def retrain_with_verdicts(
    current_model: Model,
    verdicts: Sequence[Verdict],
    payloads: dict[str, dict],
    *,
    split_ratio: float = 0.8,
    notes: Sequence[str] | None = None,
) -> tuple[Model, RetrainReport]:
    """Retrain the model on analyst verdicts and report before/after.

    The auto-labels are recovered from ``current_model`` against the
    payloads, so the audit can compute precision_drop without the caller
    having to record them. The before/after numbers are computed on
    ``agreed`` rows: rows where the analyst and the auto-label agreed
    *before* the retrain. After the retrain, those rows are the held-out
    validation set — the model should still get them right, and the
    report says whether it does.
    """
    if not verdicts:
        raise ValueError("cannot retrain on an empty verdict list")
    if not payloads:
        raise ValueError("cannot retrain without the original payloads")
    # Recover the auto-labels from the current model.
    auto_labels: dict[str, int] = {}
    for v in verdicts:
        payload = payloads.get(v.alert_uid)
        if payload is None:
            continue
        vec = extract_features(payload)
        probs = current_model.predict_proba([vec])
        auto_labels[v.alert_uid] = 1 if probs and probs[0] >= current_model.threshold else 0
    audit_result = audit(verdicts, auto_labels)
    # Build the training set from the verdicts directly (the auto-labels
    # are *not* used to construct the training set — they would be a
    # self-fulfilling label source). The split is the train/val from the
    # verdict list, in declaration order, which is the order the analyst
    # worked through the queue.
    ts = from_verdicts(list(verdicts), payloads, extract_features)
    train_ts, val_ts = ts.split(split_ratio)
    # The "before" measurement: the production model on the rows where
    # auto-label and verdict agreed. This is what the production model
    # already gets right; it is the floor we have to beat.
    agreed_rows: list[Verdict] = audit_result.agreed
    before_eval = _evaluate_verdicts(
        current_model,
        agreed_rows,
        payloads,
        threshold=current_model.threshold,
    )
    if len(train_ts) < 2 or len(set(train_ts.labels)) < 2:
        # Not enough rows or only one class — return the current model
        # untouched with the audit as the report.
        report = RetrainReport(
            before=before_eval,
            after=before_eval,
            audit=audit_result,
            training_rows=len(train_ts),
            validation_rows=len(val_ts),
            notes=list(notes or []) + [
                "retrain skipped: training set has fewer than 2 rows or only "
                "one class; collect more verdicts before retraining",
            ],
        )
        return current_model, report
    # Pick the new threshold on the validation split. The before/after
    # numbers use the same threshold so the comparison is apples-to-apples.
    val_vecs = list(val_ts.vectors)
    val_labels = list(val_ts.labels)
    new_threshold = pick_threshold(current_model, val_vecs, val_labels) if val_vecs else 0.5
    new_model = train(
        list(train_ts.vectors),
        list(train_ts.labels),
        threshold=new_threshold,
        notes=list(notes or []),
    )
    after_eval = _evaluate_verdicts(
        new_model,
        agreed_rows,
        payloads,
        threshold=new_threshold,
    )
    # The validation-set evaluation — same model, the rows it has *not*
    # seen during training. This is the strictest test the report can
    # produce: the model is judged on data it never trained on.
    val_eval = evaluate(new_model, val_vecs, val_labels) if val_vecs else after_eval
    report = RetrainReport(
        before=before_eval,
        after=after_eval,
        audit=audit_result,
        training_rows=len(train_ts),
        validation_rows=len(val_ts),
        notes=list(notes or []) + [
            f"validation-set F1 = {val_eval.f1:.3f} on {val_eval.n_samples} rows "
            f"the new model has not seen"
        ],
    )
    return new_model, report


def _evaluate_verdicts(
    model: Model,
    verdicts: Sequence[Verdict],
    payloads: dict[str, dict],
    *,
    threshold: float,
) -> EvaluationReport:
    """Evaluate ``model`` on a list of verdicts at ``threshold``."""
    vectors: list[tuple[int, ...]] = []
    labels: list[int] = []
    from learn.verdict import label_for_training
    for v in verdicts:
        payload = payloads.get(v.alert_uid)
        if payload is None:
            continue
        try:
            label = label_for_training(v.verdict_id)
        except ValueError:
            continue
        vectors.append(extract_features(payload))
        labels.append(label)
    if not vectors:
        return EvaluationReport(
            n_samples=0,
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            auc=0.5,
            threshold=threshold,
            true_positives=0,
            false_positives=0,
            true_negatives=0,
            false_negatives=0,
            notes=["no verdict with both a payload and a conclusive label"],
        )
    return evaluate(model, vectors, labels)


__all__ = ["RetrainReport", "retrain_with_verdicts"]

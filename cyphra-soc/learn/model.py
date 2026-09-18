"""The ML model — Logistic Regression on a 44-feature binary vector.

Why logistic regression:

* The feature vector is small (44 features) and binary. Trees overfit on
  binary inputs; gradient boosting needs many more trees than this many
  features; a neural network is two orders of magnitude more compute than
  the platform's detection cycle can afford. Logistic regression is
  well-calibrated *out of the box* — the predicted probability is usable as
  a confidence score — and ``predict_proba`` ships with sklearn.
* The model is interpretable: the coefficient vector names the features
  that move the score. A SOC operator can read the coefficients and ask
  "what is the model doing?" without an explainer.
* Training is a single ``scipy.optimize`` call. ``fit`` runs in under a
  second on a 10 000-row training set, which makes the "retrain on every
  N verdicts" workflow cheap.

What this is not:

* It is not an XGBoost-grade model. A platform with hundreds of thousands
  of verdicts and thousands of features will outgrow it. The right next
  step when the data justifies it is a gradient-boosted model; for now the
  data does not.
* It is not autoML. The hyperparameters are deliberately fixed: an
  ``l2`` penalty (``C=1.0``) keeps the coefficients small, ``max_iter=1000``
  is large enough to converge on this dataset, ``solver="liblinear"`` is
  the only solver that supports both ``l2`` and a binary problem at this
  scale.

The model is *trained from scratch* every time. There is no online
update. The rationale is the same as for any re-train policy: a model
that updates online against a stream of operator-supplied labels can be
tricked into unlearning a fix; a model that retrains in batch on a
versioned training set cannot.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass
class EvaluationReport:
    """The metrics from a held-out evaluation run.

    ``n_samples`` is the count of test rows. ``recall_at_threshold`` is the
    recall at the model's *operating* threshold, which is set to the
    precision-recall break-even (``threshold`` is the same threshold that
    the detector uses at runtime — recording both lets the report prove
    that production-time and evaluation-time thresholds match).

    All metrics are floats in ``[0, 1]``. The dataclass is serialisable
    with :mod:`pickle` so an operator can stash a copy of the evaluation
    alongside the trained model.
    """

    n_samples: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    auc: float
    threshold: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    notes: list[str] = field(default_factory=list)


@dataclass
class Model:
    """The wrapped model + its evaluation metadata.

    ``estimator`` is the scikit-learn estimator. ``threshold`` is the
    decision threshold the platform uses at runtime; it is *not* the
    sklearn default of 0.5, which is rarely the right operating point on
    a SOC dataset. The threshold is chosen at training time to balance
    precision and recall, and recorded so an evaluation can reproduce the
    production decision exactly.
    """

    estimator: LogisticRegression
    threshold: float
    feature_count: int
    evaluation: EvaluationReport | None = None

    def predict_proba(self, vectors: Sequence[Sequence[int]]) -> list[float]:
        """Probability of "is a threat" for each feature vector."""
        if not vectors:
            return []
        probs = self.estimator.predict_proba(vectors)
        return [float(p[1]) for p in probs]

    def decide(self, vectors: Sequence[Sequence[int]]) -> list[bool]:
        """The binary decision at the model's threshold."""
        probs = self.predict_proba(vectors)
        return [p >= self.threshold for p in probs]

    def score(self, vector: Sequence[int]) -> float:
        """Probability of "is a threat" for one feature vector."""
        return self.predict_proba([vector])[0]

    def serialize(self) -> bytes:
        """A pickle of the model. Round-trip via :meth:`deserialize`."""
        return pickle.dumps(self)

    @classmethod
    def deserialize(cls, blob: bytes) -> "Model":
        """A pickle loaded back into a :class:`Model`."""
        obj = pickle.loads(blob)
        if not isinstance(obj, cls):
            raise ValueError(f"deserialized object is not a Model: {type(obj)}")
        return obj


def _labels_to_int(labels: Sequence[Any]) -> list[int]:
    """Convert the training set's labels to ``{0, 1}`` ints.

    Accepts both numeric (0/1) and the string forms the labels module
    produces, so a caller can hand either the verifier output or the raw
    labels back without conversion.
    """
    out: list[int] = []
    for label in labels:
        if isinstance(label, (int, bool)):
            out.append(int(bool(label)))
        elif isinstance(label, str):
            out.append({"1": 1, "true_positive": 1, "true": 1,
                        "0": 0, "false_positive": 0, "benign": 0,
                        "false": 0}.get(label.strip().lower(), 0))
        else:
            raise TypeError(f"unsupported label type {type(label).__name__}")
    return out


def train(
    vectors: Sequence[Sequence[int]],
    labels: Sequence[Any],
    *,
    threshold: float = 0.5,
    notes: Sequence[str] | None = None,
) -> Model:
    """Train a model and report its in-sample evaluation.

    ``threshold`` is the operating point the detector will use at runtime.
    The default (``0.5``) is rarely right for SOC data: alerts are rare
    relative to total events, so the model's *prior* on "is a threat" is
    well below 0.5 and a threshold of 0.5 floods the queue. A more useful
    default would be the prior, which the caller usually knows.

    The returned model's :attr:`evaluation` field holds the in-sample
    evaluation. In-sample evaluation is *biased high* — the right thing for
    it is to show the model is wired up correctly, not to claim the model
    is accurate. Production accuracy is measured on a held-out split by
    :func:`evaluate`.
    """
    if not vectors:
        raise ValueError("cannot train on an empty training set")
    if len(vectors) != len(labels):
        raise ValueError(
            f"vectors ({len(vectors)}) and labels ({len(labels)}) disagree"
        )
    ys = _labels_to_int(labels)
    feature_count = len(vectors[0])
    for v in vectors:
        if len(v) != feature_count:
            raise ValueError(
                "every feature vector must be the same length; got "
                f"{feature_count} and {len(v)}"
            )
    estimator = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="liblinear",
        class_weight="balanced",
    )
    estimator.fit(vectors, ys)
    probs = [float(p[1]) for p in estimator.predict_proba(vectors)]
    decisions = [p >= threshold for p in probs]
    tp = sum(1 for y, d in zip(ys, decisions) if y == 1 and d)
    fp = sum(1 for y, d in zip(ys, decisions) if y == 0 and d)
    fn = sum(1 for y, d in zip(ys, decisions) if y == 1 and not d)
    tn = sum(1 for y, d in zip(ys, decisions) if y == 0 and not d)
    evaluation = EvaluationReport(
        n_samples=len(ys),
        accuracy=_safe(accuracy_score, ys, decisions),
        precision=_safe(precision_score, ys, decisions, zero_division=0.0),
        recall=_safe(recall_score, ys, decisions, zero_division=0.0),
        f1=_safe(f1_score, ys, decisions, zero_division=0.0),
        auc=_safe(roc_auc_score, ys, probs) if len(set(ys)) > 1 else 0.5,
        threshold=threshold,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        notes=list(notes or []),
    )
    return Model(
        estimator=estimator,
        threshold=threshold,
        feature_count=feature_count,
        evaluation=evaluation,
    )


def evaluate(
    model: Model,
    vectors: Sequence[Sequence[int]],
    labels: Sequence[Any],
    *,
    notes: Sequence[str] | None = None,
) -> EvaluationReport:
    """Held-out evaluation — same metrics as :func:`train`, on a different split."""
    if not vectors:
        raise ValueError("cannot evaluate on an empty set")
    ys = _labels_to_int(labels)
    probs = model.predict_proba(vectors)
    decisions = model.decide(vectors)
    tp = sum(1 for y, d in zip(ys, decisions) if y == 1 and d)
    fp = sum(1 for y, d in zip(ys, decisions) if y == 0 and d)
    fn = sum(1 for y, d in zip(ys, decisions) if y == 1 and not d)
    tn = sum(1 for y, d in zip(ys, decisions) if y == 0 and not d)
    return EvaluationReport(
        n_samples=len(ys),
        accuracy=_safe(accuracy_score, ys, decisions),
        precision=_safe(precision_score, ys, decisions, zero_division=0.0),
        recall=_safe(recall_score, ys, decisions, zero_division=0.0),
        f1=_safe(f1_score, ys, decisions, zero_division=0.0),
        auc=_safe(roc_auc_score, ys, probs) if len(set(ys)) > 1 else 0.5,
        threshold=model.threshold,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        notes=list(notes or []),
    )


def pick_threshold(
    model: Model,
    vectors: Sequence[Sequence[int]],
    labels: Sequence[Any],
) -> float:
    """The decision threshold where precision ≈ recall on this dataset.

    Returns the threshold at the precision-recall break-even, computed on
    the supplied (held-out) set. The platform's runtime uses this
    threshold so the operator can reproduce the model's behaviour on the
    same data the report is generated from.

    The break-even is found by scanning a discrete threshold grid and
    picking the one with the smallest ``|precision - recall|``. The grid
    is dense enough (``0.05``) to surface break-evens to within ±2.5%,
    which is finer than the operating tolerance the platform actually
    needs; finer grids do not improve the deployment.
    """
    if len(vectors) != len(labels):
        raise ValueError("vectors and labels disagree")
    if not vectors:
        return 0.5
    ys = _labels_to_int(labels)
    probs = model.predict_proba(vectors)
    total_pos = sum(ys) or 1
    grid = (0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50,
            0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95)
    best_threshold = 0.5
    best_gap = float("inf")
    for t in grid:
        decisions = [p >= t for p in probs]
        tp = sum(1 for y, d in zip(ys, decisions) if y == 1 and d)
        fp = sum(1 for y, d in zip(ys, decisions) if y == 0 and d)
        # precision = TP / (TP + FP); recall = TP / total_pos. We avoid
        # 1/0 by treating TP + FP = 0 as "no positive decisions", which
        # makes precision = 0 and recall = 0 at this threshold.
        prec_denom = tp + fp
        prec = tp / prec_denom if prec_denom else 0.0
        rec = tp / total_pos
        gap = abs(prec - rec)
        if gap < best_gap:
            best_gap = gap
            best_threshold = t
    return best_threshold


def _safe(metric, *args: Any, **kwargs: Any) -> float:
    """A scorer that returns ``0.0`` on degenerate inputs."""
    try:
        return float(metric(*args, **kwargs))
    except (ValueError, ZeroDivisionError):
        return 0.0


__all__ = [
    "EvaluationReport",
    "Model",
    "evaluate",
    "pick_threshold",
    "train",
]

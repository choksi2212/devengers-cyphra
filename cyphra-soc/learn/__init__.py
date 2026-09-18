"""The learn subsystem — label fix, retrain, and the verdict audit trail.

Seven modules with one entry point (:func:`learn.retrain.retrain_with_verdicts`)
the platform calls after every ``N`` analyst verdicts:

* :mod:`learn.verdict` — the verdict enum, the dataclass, and the
  label-mapping rules. OCSF-aligned.
* :mod:`learn.verdict_store` — JSON-lines-backed append-only store of
  verdicts. The audit trail.
* :mod:`learn.features` — the 44-feature binary vector the model consumes.
  One-hot of OCSF class, one-hot of vendor:product, plus 13 booleans.
* :mod:`learn.model` — the wrapped :class:`sklearn.linear_model.LogisticRegression`
  with the threshold chosen at the precision-recall break-even.
* :mod:`learn.training_set` — the input to train and the train/val split.
* :mod:`learn.label_audit` — the gap between auto-labels and verdicts.
* :mod:`learn.retrain` — the pipeline: audit → split → train → evaluate →
  report before/after. The headline numbers are reported verbatim.
"""

from learn.features import extract_features, feature_names
from learn.job import RetrainJob, RetrainJobConfig, RetrainJobStats
from learn.label_audit import LabelAudit, audit, split_for_retrain
from learn.model import (
    EvaluationReport,
    Model,
    evaluate,
    pick_threshold,
    train,
)
from learn.retrain import RetrainReport, retrain_with_verdicts
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

__all__ = [
    "EvaluationReport",
    "LabelAudit",
    "Model",
    "RetrainJob",
    "RetrainJobConfig",
    "RetrainJobStats",
    "RetrainReport",
    "TrainingSet",
    "VERDICT_NAMES",
    "Verdict",
    "VerdictLabel",
    "VerdictStore",
    "audit",
    "evaluate",
    "extract_features",
    "feature_names",
    "from_name",
    "from_synthetic",
    "from_verdicts",
    "is_conclusive",
    "label_for_training",
    "pick_threshold",
    "retrain_with_verdicts",
    "split_for_retrain",
    "train",
]

"""The label audit — every inconsistency between auto-labels and verdicts.

A SOC that ships an ML detector learns the truth from two sources: the
*auto-label* the detector itself attaches when it scores an alert, and the
*analyst verdict* a human leaves in the console. If those two disagree,
the auto-label was wrong.

This module is the gap report. :func:`audit` takes a stream of verdicts
and the auto-labels the model produced for those alerts, and returns:

* ``agreed`` — alerts where the model and the analyst agreed.
* ``overturned`` — alerts the model called "threat" the analyst called
  "false alarm", or vice versa.
* ``ambiguous`` — verdicts that are not conclusive (``needs_review``,
  ``benign``, etc.) and cannot be used as training labels.

The report is the input to the retrain step: ``overturned`` becomes the
new training set, ``agreed`` is the validation set, ``ambiguous`` is held
out. A model retrained on the auto-labels alone cannot improve on this
data; a model retrained on the verdicts learns what the operator
actually means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from core.schema.ocsf import Verdict as OcsfVerdict
from learn.verdict import Verdict, is_conclusive


@dataclass
class LabelAudit:
    """The gap between auto-labels and analyst verdicts.

    ``overturned`` are the alerts where the auto-label disagreed with a
    conclusive verdict — these are the rows that *change* when the
    detector is retrained on analyst labels. ``agreed`` are the rows
    where the auto-label already matched the verdict — these are the rows
    the model already got right, and they form the validation set in
    :func:`learn.retrain.split_for_retrain`.
    """

    agreed: list[Verdict] = field(default_factory=list)
    overturned: list[Verdict] = field(default_factory=list)
    ambiguous: list[Verdict] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.agreed) + len(self.overturned) + len(self.ambiguous)

    @property
    def precision_drop(self) -> float:
        """The fraction of auto-labels that verdicts contradict.

        ``0.0`` means every auto-label was correct; ``1.0`` means every
        auto-label was wrong. The retrain report prints this number
        verbatim — a non-trivial drop is the headline of the "report
        honestly" requirement.
        """
        decided = len(self.agreed) + len(self.overturned)
        if not decided:
            return 0.0
        return len(self.overturned) / decided


def audit(
    verdicts: Iterable[Verdict],
    auto_labels: dict[str, int],
) -> LabelAudit:
    """Compare ``verdicts`` against ``auto_labels``.

    ``auto_labels`` maps an alert's :attr:`metadata_uid` to the auto-label
    the model produced (``0`` for "not a threat", ``1`` for "threat"). An
    alert missing from ``auto_labels`` is treated as the model's
    "implicit not-a-threat" — when the analyst called it a real threat
    that is an overturned prediction.
    """
    out = LabelAudit()
    for v in verdicts:
        if not is_conclusive(v.verdict_id):
            out.ambiguous.append(v)
            continue
        truth = 1 if v.verdict_id == 2 else 0  # TRUE_POSITIVE == 2 → 1
        auto = auto_labels.get(v.alert_uid, 0)
        if auto == truth:
            out.agreed.append(v)
        else:
            out.overturned.append(v)
    return out


def split_for_retrain(audit_result: LabelAudit) -> tuple[list[Verdict], list[Verdict]]:
    """Split ``audit_result`` into (training, validation).

    The training set is the rows where the analyst disagreed with the
    auto-label (these are the labels the model must learn). The
    validation set is the rows where the analyst agreed (these are the
    rows the model already got right and should still get right).

    Empty training or validation sets are returned as empty lists; the
    caller decides whether to retrain on zero rows.
    """
    return list(audit_result.overturned), list(audit_result.agreed)


__all__ = ["LabelAudit", "audit", "split_for_retrain"]

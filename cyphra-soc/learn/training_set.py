"""Training set construction — the input to retrain.

The training set is a list of ``(feature_vector, label)`` pairs. Labels are
binary (``0`` = "this was not a threat", ``1`` = "this was a threat"), as
produced by :func:`learn.verdict.label_for_training`.

The training set has *two* sources:

* **Verdicts** — alerts the platform produced and an analyst confirmed
  or denied. These are the gold labels.
* **Synthetic** — events the emulation generator emits, pre-labelled by
  the scenario. Useful when verdicts are scarce; less useful as the
  verdicts grow.

A real platform trains on the verdicts alone. The synthetic rows are
*training-set augmentation*, not labels, and they are excluded from the
held-out validation split so the platform never validates on data it has
already seen.

The :class:`TrainingSet` dataclass is the canonical output. It carries
the vectors, the labels, and a ``source`` per row so the retrain report
can show how much of the dataset came from where.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from learn.verdict import Verdict, label_for_training


@dataclass
class TrainingSet:
    """Vectors + labels + the per-row source tag."""

    vectors: list[tuple[int, ...]] = field(default_factory=list)
    labels: list[int] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.vectors)

    def __iadd__(self, other: "TrainingSet") -> "TrainingSet":
        self.vectors.extend(other.vectors)
        self.labels.extend(other.labels)
        self.sources.extend(other.sources)
        return self

    def split(self, ratio: float) -> tuple["TrainingSet", "TrainingSet"]:
        """Train/test split by index. Deterministic for a fixed input.

        ``ratio`` is the fraction of rows that go into the *training* set
        (default ``0.8``). The split is the deterministic ``vectors[:int(
        ratio * n)]`` form — it is reproducible across runs and does not
        require a seed. The first ``ratio * n`` rows become the training
        set; the rest become the validation set.
        """
        if not 0.0 <= ratio <= 1.0:
            raise ValueError(f"split ratio must be in [0, 1], got {ratio}")
        if not self.vectors:
            return TrainingSet(), TrainingSet()
        cut = int(len(self.vectors) * ratio)
        train = TrainingSet(
            vectors=self.vectors[:cut],
            labels=self.labels[:cut],
            sources=self.sources[:cut],
        )
        val = TrainingSet(
            vectors=self.vectors[cut:],
            labels=self.labels[cut:],
            sources=self.sources[cut:],
        )
        return train, val


def from_verdicts(
    verdicts: list[Verdict],
    payloads: dict[str, dict],
    extract_features,
) -> TrainingSet:
    """Build a :class:`TrainingSet` from a list of analyst verdicts.

    ``payloads`` maps an alert's :attr:`metadata_uid` to the OCSF payload
    that produced the alert — the feature extractor reads from this
    payload. Verdicts whose payload is missing are skipped, with no
    exception, because the training set must never claim a label it
    cannot support.
    """
    ts = TrainingSet()
    for v in verdicts:
        payload = payloads.get(v.alert_uid)
        if payload is None:
            continue
        try:
            label = label_for_training(v.verdict_id)
        except ValueError:
            continue
        ts.vectors.append(extract_features(payload))
        ts.labels.append(label)
        ts.sources.append("verdict")
    return ts


def from_synthetic(
    payloads_with_labels: list[tuple[dict, int]],
    extract_features,
) -> TrainingSet:
    """Build a :class:`TrainingSet` from synthetic events and their labels.

    Used during cold-start when no verdicts exist yet. The synthetic
    events come from :mod:`validate.emulation.generator`; the labels
    come from the scenario (a scenario knows what its events are).
    """
    ts = TrainingSet()
    for payload, label in payloads_with_labels:
        ts.vectors.append(extract_features(payload))
        ts.labels.append(int(label))
        ts.sources.append("synthetic")
    return ts


__all__ = ["TrainingSet", "from_synthetic", "from_verdicts"]

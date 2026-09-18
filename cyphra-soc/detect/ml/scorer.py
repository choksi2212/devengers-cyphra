"""The ML scorer — bridges :mod:`learn` to the detection engine.

The detection engine's contract is ``score_event(event)`` and
``threshold``. The model's contract is :meth:`learn.model.Model.score`. A
:class:`MLScorer` wraps a model and exposes the engine's contract.

The scorer is the *only* code path that turns a learn-side model into a
detect-side finding. The retrain pipeline (Phase 2a) replaces the model
inside the scorer; the engine's :class:`DetectionEngine` keeps the same
scorer instance. A scorer whose model is replaced mid-flight starts
emitting new scores on the next event with no further wiring — that is
the property that lets a SOC deploy the next model without a restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from learn.features import extract_features
from learn.model import Model


@dataclass
class MLScorer:
    """A wrapped model exposing the engine's contract.

    ``model`` is mutable so the retrain pipeline can replace it. ``extract``
    is a callable from an event to a feature vector; the default is
    :func:`learn.features.extract_features`. ``threshold`` is mirrored
    from the model for the engine's ``>= threshold`` check; replacing the
    model also updates the threshold.
    """

    model: Model
    extract: Any = extract_features

    @property
    def threshold(self) -> float:
        return self.model.threshold

    def score_event(self, event: Mapping[str, Any]) -> float:
        """The model's probability of "is a threat" for ``event``."""
        vec = self.extract(event)
        return self.model.score(vec)


__all__ = ["MLScorer"]

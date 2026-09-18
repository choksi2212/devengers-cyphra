"""ML detection — the model's bridge to the engine.

The :class:`detect.ml.scorer.MLScorer` wraps a :class:`learn.model.Model`
and exposes the engine's contract. The retrain pipeline (Phase 2a)
replaces the model; the engine keeps working.
"""

from detect.ml.scorer import MLScorer

__all__ = ["MLScorer"]

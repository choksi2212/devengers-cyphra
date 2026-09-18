"""The validate subsystem — the SOC's proving ground.

Five modules:

* :mod:`validate.coverage` — :class:`CoverageMatrix` and
  :func:`build_matrix`. Every scenario in the emulation generator
  declares the SOC functions it covers; the matrix is the
  row-by-column truth.
* :mod:`validate.runner` — :class:`EndToEndRunner`. Pipes emulation
  events through enrichment, detection, correlation, triage and
  respond. The single place that knows the platform's pipeline order.
* :mod:`validate.gap` — :class:`GapReport`. Missing and fragile
  functions; the deployer's "what to add next" hint.
* :mod:`validate.drift` — :class:`DriftReport` and
  :func:`compare`. Layer-aware regression detection.
* :mod:`validate.regression` — :class:`RegressionHarness`. The CI
  entry point: persists the baseline, runs the platform, reports
  the verdict.
"""

from validate.coverage import (
    CoverageCell,
    CoverageMatrix,
    SOC_FUNCTIONS,
    build_matrix,
)
from validate.drift import (
    DriftConfig,
    DriftReport,
    LayerDrift,
    RuleDrift,
    compare,
)
from validate.gap import GapReport, build_gap_report
from validate.regression import RegressionHarness, RegressionVerdict
from validate.runner import (
    EndToEndRunner,
    LayerReport,
    Pipeline,
    RunReport,
    default_pipeline,
)

__all__ = [
    "CoverageCell",
    "CoverageMatrix",
    "DriftConfig",
    "DriftReport",
    "EndToEndRunner",
    "GapReport",
    "LayerDrift",
    "LayerReport",
    "Pipeline",
    "RegressionHarness",
    "RegressionVerdict",
    "RuleDrift",
    "RunReport",
    "SOC_FUNCTIONS",
    "build_gap_report",
    "build_matrix",
    "compare",
    "default_pipeline",
]

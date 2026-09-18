"""Coverage matrix — which scenarios exercise which SOC functions.

A SOC function is "covered" if at least one emulation scenario produces
an event that the function is responsible for. The matrix is the
single source of truth for "what is the platform doing end-to-end".

Functions are named by their layer; a function is an action the SOC
takes on its data. The shipped functions are:

* collection — events arrive at the lake.
* parsing — events are mapped to OCSF.
* normalisation — entities and indicators are resolved.
* enrichment — entity / threat-intel context is attached.
* correlation — findings are grouped into incidents.
* detection — rules and ML score events into findings.
* triage — incidents become analyst dispositions.
* response — dispositions become containment actions.
* hunt — periodic queries against the lake.
* intel — threat indicators are merged from feeds.
* cases — incidents become long-lived case records.
* metrics — counts flow to dashboards.
* compliance — events map to regulatory controls.
* learn — analyst verdicts train the model.

Each scenario in :mod:`validate.emulation.generator` declares the
functions it covers via the ``covers`` tuple on :class:`ScenarioResult`.
The matrix is built by walking every scenario and recording which
functions each one names.

A function with no scenario is a gap; the gap report names it. A
function with one scenario is fragile — the scenario could regress
without being noticed; the matrix records the count.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from validate.emulation.generator import (
    ScenarioResult,
    list_scenarios,
)


SOC_FUNCTIONS: tuple[str, ...] = (
    "collection",
    "parsing",
    "normalisation",
    "enrichment",
    "correlation",
    "detect",
    "triage",
    "respond",
    "hunt",
    "intel",
    "cases",
    "metrics",
    "compliance",
    "learn",
)


@dataclass
class CoverageCell:
    """One row × column cell.

    ``scenario_count`` is the number of emulation scenarios whose
    ``covers`` tuple names this function. ``scenario_names`` is the
    list of those scenarios so an operator can drill in.
    """

    scenario_count: int = 0
    scenario_names: list[str] = field(default_factory=list)


@dataclass
class CoverageMatrix:
    """The full row × column matrix."""

    cells: dict[str, CoverageCell] = field(default_factory=dict)

    def covered(self) -> list[str]:
        """The functions with at least one scenario."""
        return [name for name, cell in self.cells.items() if cell.scenario_count > 0]

    def gaps(self) -> list[str]:
        """The functions with no scenario."""
        return [name for name in SOC_FUNCTIONS if not self.cells.get(name, CoverageCell()).scenario_count]

    def fragile(self) -> list[str]:
        """The functions with exactly one scenario — a regression there would be silent."""
        return [name for name, cell in self.cells.items() if cell.scenario_count == 1]

    def count(self) -> int:
        return len(self.covered())

    def total(self) -> int:
        return len(SOC_FUNCTIONS)

    def ratio(self) -> float:
        return self.count() / self.total() if self.total() else 0.0


def build_matrix(scenarios: Iterable[ScenarioResult] | None = None) -> CoverageMatrix:
    """Build the matrix from a list of scenarios.

    ``None`` means "use the shipped scenarios". A deployment passes
    its own list when it has added scenarios to the platform.
    """
    if scenarios is None:
        scenarios = list_scenarios()
    matrix = CoverageMatrix()
    for scenario in scenarios:
        for function in scenario.covers:
            cell = matrix.cells.setdefault(function, CoverageCell())
            cell.scenario_count += 1
            if scenario.name not in cell.scenario_names:
                cell.scenario_names.append(scenario.name)
    return matrix


__all__ = ["CoverageCell", "CoverageMatrix", "SOC_FUNCTIONS", "build_matrix"]

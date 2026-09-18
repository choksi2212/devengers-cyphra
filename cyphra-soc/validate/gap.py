"""The gap report — which SOC functions are not exercised.

A SOC function with no emulation scenario is a *gap*: the platform
ships the function but cannot prove it works end-to-end. The gap
report names every gap, classifies it as *missing* (no scenario at
all) or *fragile* (exactly one scenario — a regression there is
silent), and prints the scenarios that do cover the function.

The report is the input to *Phase 8* — the SOC console's "coverage"
view, and the deployer's "what scenario to add next" hint. A platform
that ships with seven gaps ships seven features it cannot claim.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from validate.coverage import CoverageCell, CoverageMatrix, SOC_FUNCTIONS


@dataclass
class GapReport:
    """The gap report for a coverage matrix.

    ``missing`` are the SOC functions with no scenario. ``fragile``
    are the functions with exactly one scenario (silent regression
    risk). ``covered`` are the functions with two or more scenarios.
    """

    covered: list[str] = field(default_factory=list)
    fragile: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    matrix: CoverageMatrix | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "covered": list(self.covered),
            "fragile": list(self.fragile),
            "missing": list(self.missing),
        }


def build_gap_report(
    matrix: CoverageMatrix,
    *,
    shipped: Iterable[str] | None = None,
) -> GapReport:
    """Build a gap report from a coverage matrix.

    ``shipped`` is the list of SOC functions the deployment has
    shipped; ``None`` means "every function in :data:`SOC_FUNCTIONS`".
    A deployment that has not yet shipped ``learn`` (because the model
    is not yet retrained) sees ``learn`` listed in ``missing`` —
    which would be misleading, because the function is "not shipped",
    not "missing a scenario".

    The shipped list lets a deployment say "these are the functions
    I want to test" and have the gap report show only the gaps
    among those.
    """
    shipped = list(shipped or SOC_FUNCTIONS)
    covered = [name for name in shipped if matrix.cells.get(name, CoverageCell()).scenario_count >= 2]
    fragile = [name for name in shipped if matrix.cells.get(name, CoverageCell()).scenario_count == 1]
    missing = [name for name in shipped if not matrix.cells.get(name, CoverageCell()).scenario_count]
    return GapReport(
        covered=covered,
        fragile=fragile,
        missing=missing,
        matrix=matrix,
    )


__all__ = ["GapReport", "build_gap_report"]

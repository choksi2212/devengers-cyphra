"""Threat intelligence feeds — indicators, reputation, and context.

Two modules:

* :mod:`intel.feed` — :class:`Indicator`, :class:`Reputation`,
  :class:`IndicatorKind`, :class:`IntelStore`. The store is in-memory;
  production deployments back it with VedDB. Higher-score intel
  overrides lower-score intel on the same indicator.
* :mod:`intel.extract` — :class:`IndicatorExtractor`, which walks an
  OCSF event and produces the (kind, value) pairs to look up.
"""

from intel.extract import ExtractedIndicator, IndicatorExtractor
from intel.feed import (
    Indicator,
    IndicatorKind,
    IntelHit,
    IntelStore,
    KIND_NAMES,
    Reputation,
    REPUTATION_NAMES,
    TOR_EXIT_FEED,
    default_indicator_kind_name,
)

__all__ = [
    "ExtractedIndicator",
    "Indicator",
    "IndicatorExtractor",
    "IndicatorKind",
    "IntelHit",
    "IntelStore",
    "KIND_NAMES",
    "REPUTATION_NAMES",
    "Reputation",
    "TOR_EXIT_FEED",
    "default_indicator_kind_name",
]

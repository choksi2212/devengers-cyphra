"""Connector registry — wires every connector factory into one fleet.

One function, one return: the operator calls :func:`declare_connectors` with
a config, a pipeline, and a monitor, and gets back a :class:`ConnectorFleet`
containing every configured connector that should be running on this host.

The factories themselves live in the connector modules so each one stays
single-file — this module is the wiring diagram and the readiness gate, not
the connector logic. A connector that has no business running on this host
(its credential slots are all unconfigured) is *not* added to the fleet;
that is what :meth:`Connector.probe` is for, and the registry reads the same
:attr:`~ingest.collectors.base.Availability.available` flag.

The intent is to be loud about what is *not* running. A fleet with one
connector added is reported as ``declared=1 running=1 skipped=N`` so the
operator sees that 8 sources are configured-but-not-collecting, and ``stats``
distinguishes ``skipped`` from ``unavailable`` from ``failed`` so a fix is
one ``grep`` away.
"""

from __future__ import annotations

from typing import Any

from core.config import SocConfig
from ingest.connectors.azure_activity import azure_connectors
from ingest.connectors.base import ConnectorFleet
from ingest.connectors.cloudtrail import cloudtrail_connectors
from ingest.connectors.crowdstrike import crowdstrike_connectors
from ingest.connectors.defender import defender_connectors
from ingest.connectors.entra import entra_connectors
from ingest.connectors.gcp_audit import gcp_connectors
from ingest.connectors.google_workspace import workspace_connectors
from ingest.connectors.m365 import m365_connectors
from ingest.connectors.okta import okta_connectors
from ingest.connectors.saas_generic import saas_connectors


def declare_connectors(
    config: SocConfig,
    pipeline: Any,
    monitor: Any = None,
    **kwargs: Any,
) -> ConnectorFleet:
    """Every configured connector, in a single fleet, ready to run.

    Each factory is called unconditionally. The connectors it produces are
    probed individually; an unconfigured connector (``probe().available is
    False``) is *not* added to the fleet — running it would crash on every
    cycle and the readiness report is the single source of truth for which
    sources are missing. A configured connector *is* added; the fleet will
    poll it.

    The ``monitor`` argument is optional: in tests it is omitted, in
    production it is the HealthMonitor instance. Connectors that want to
    declare themselves to the monitor do so via :meth:`CollectorFleet.add`.
    """
    fleet = ConnectorFleet()
    for factory in (
        entra_connectors,
        defender_connectors,
        crowdstrike_connectors,
        okta_connectors,
        cloudtrail_connectors,
        azure_connectors,
        gcp_connectors,
        m365_connectors,
        workspace_connectors,
        saas_connectors,
    ):
        for connector in factory(pipeline, config, **kwargs):
            availability = connector.probe()
            if not availability.available:
                # The connector is left out of the fleet — its unavailability
                # is reported by ``ConnectorFleet.unavailable()`` and the
                # operator sees it via ``report()`` without running it.
                continue
            fleet.add(connector)
            if monitor is not None:
                # The monitor records a "source declared" transition so the
                # audit chain shows when this host started watching a source.
                # Callers that do not need the audit chain can pass ``None``.
                try:
                    monitor.record_declare(connector.name)
                except AttributeError:
                    # Backwards-compatible with monitors that don't yet
                    # implement ``record_declare``; not a hard dependency.
                    pass
    return fleet


__all__ = ["declare_connectors"]

"""Connectors: telemetry from APIs somebody else operates.

Ten real integrations plus the machinery they share. Import order matters here —
:mod:`http` (transport, rate limiting, retry) has no local dependencies,
:mod:`auth` builds on it, and :mod:`base` builds on both plus the collector fleet.
"""

from ingest.connectors.auth import (
    Authorizer,
    CredentialsIncomplete,
    OAuth2ClientCredentials,
    ServiceAccount,
    ServiceAccountJwtAuth,
    SigV4Auth,
    StaticHeaderAuth,
    Token,
    require,
)
from ingest.connectors.azure_activity import AzureActivityConnector, azure_connectors
from ingest.connectors.base import (
    Checkpoints,
    Connector,
    ConnectorError,
    ConnectorFleet,
    ConnectorSpec,
    DocStoreCheckpoints,
    MemoryCheckpoints,
    TimeWindow,
    WindowPlanner,
    dig,
    first,
    iso8601,
    normalise_records,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.cloudtrail import CloudTrailConnector, cloudtrail_connectors
from ingest.connectors.crowdstrike import CrowdStrikeConnector, crowdstrike_connectors
from ingest.connectors.defender import DefenderConnector, defender_connectors
from ingest.connectors.entra import EntraSignInConnector, EntraAuditConnector, entra_connectors
from ingest.connectors.gcp_audit import GcpAuditConnector, gcp_connectors
from ingest.connectors.google_workspace import GoogleWorkspaceConnector, workspace_connectors
from ingest.connectors.http import (
    ApiClient,
    AuthError,
    BadPayload,
    HttpError,
    HttpResponse,
    HttpxTransport,
    RateLimiter,
    Request,
    RetryPolicy,
    Transport,
    TransientError,
)
from ingest.connectors.m365 import M365Connector, m365_connectors
from ingest.connectors.okta import OktaSystemLogConnector, okta_connectors
from ingest.connectors.registry import declare_connectors
from ingest.connectors.saas_generic import GenericSaasConnector, saas_connectors

__all__ = [
    "ApiClient",
    "AuthError",
    "Authorizer",
    "AzureActivityConnector",
    "BadPayload",
    "Checkpoints",
    "CloudTrailConnector",
    "Connector",
    "ConnectorError",
    "ConnectorFleet",
    "ConnectorSpec",
    "CredentialsIncomplete",
    "CrowdStrikeConnector",
    "DefenderConnector",
    "DocStoreCheckpoints",
    "EntraAuditConnector",
    "EntraSignInConnector",
    "GenericSaasConnector",
    "GcpAuditConnector",
    "GoogleWorkspaceConnector",
    "HttpError",
    "HttpResponse",
    "HttpxTransport",
    "M365Connector",
    "MemoryCheckpoints",
    "OAuth2ClientCredentials",
    "OktaSystemLogConnector",
    "RateLimiter",
    "Request",
    "RetryPolicy",
    "ServiceAccount",
    "ServiceAccountJwtAuth",
    "SigV4Auth",
    "StaticHeaderAuth",
    "TimeWindow",
    "Token",
    "Transport",
    "TransientError",
    "WindowPlanner",
    "azure_connectors",
    "cloudtrail_connectors",
    "crowdstrike_connectors",
    "declare_connectors",
    "defender_connectors",
    "dig",
    "entra_connectors",
    "first",
    "gcp_connectors",
    "iso8601",
    "m365_connectors",
    "normalise_records",
    "okta_connectors",
    "parse_iso8601",
    "require",
    "saas_connectors",
    "set_ip",
    "workspace_connectors",
]

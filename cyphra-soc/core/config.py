"""
CYPHRA-SOC — layered configuration.

Three layers, lowest precedence first:

    1. the defaults declared on the dataclasses in this module
    2. ``soc.yaml``  — path from ``$CYPHRA_SOC_CONFIG``, else ``cyphra-soc/soc.yaml``
    3. environment  — ``CYPHRA_SOC_<SECTION>_<FIELD>`` for settings, and the
       conventional vendor names (``ANTHROPIC_API_KEY``, ``OKTA_API_TOKEN``, …)
       for credentials

── Why credentials are not plain strings ────────────────────────────────────
A connector whose API key is ``""`` is not "configured with an empty key" — it
is not configured. Conflating the two is how a SOC ends up with a green Okta
feed that has never returned an event, which is worse than no feed at all
because it is believed. So every secret is a :class:`Credential` that knows
whether it was supplied and from where, and raises on ``.value`` when it was
not. ``Credential.configured`` is the single flag the connector registry and the
health module read; nothing downstream is allowed to guess by truth-testing a
string.

Credentials also never appear in ``repr()`` or in a log line. The dataclass
field holding the secret is declared ``repr=False`` and :meth:`Credential.redacted`
is the only rendering offered.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Mapping, get_args, get_origin

import yaml

# ── Anchors ─────────────────────────────────────────────────────────────────
# `core/config.py` → `core/` → `cyphra-soc/` → repo root.
SOC_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SOC_ROOT.parent

ENV_PREFIX = "CYPHRA_SOC"


class ConfigError(RuntimeError):
    """Configuration is malformed or self-contradictory."""


class MissingCredential(ConfigError):
    """Code read a credential the operator never supplied.

    Deliberately loud. The alternative — returning an empty string — produces a
    connector that authenticates as nobody and reports success.
    """


# ── Credentials ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Credential:
    """A named secret slot.

    ``configured`` is the contract: it is ``True`` only when a non-empty value
    arrived from somewhere. ``purpose`` is shown to the operator in the
    readiness report, so it must say what stops working without this, not what
    the credential is.
    """

    name: str
    env_var: str
    purpose: str
    secret: str | None = field(default=None, repr=False)
    source: str = "unset"

    @property
    def configured(self) -> bool:
        return bool(self.secret)

    @property
    def value(self) -> str:
        if not self.secret:
            raise MissingCredential(
                f"{self.name} is not configured. Set ${self.env_var} "
                f"(or {self.name} in soc.yaml). Without it: {self.purpose}"
            )
        return self.secret

    def redacted(self) -> str:
        if not self.secret:
            return "<unset>"
        if len(self.secret) <= 8:
            return "*" * len(self.secret)
        return f"{self.secret[:4]}…{self.secret[-2:]} ({len(self.secret)} chars)"

    def __str__(self) -> str:  # never let a secret reach a log by accident
        return f"Credential({self.name}, {self.redacted()}, from={self.source})"


def _credential(
    name: str, env_var: str, purpose: str, yaml_value: Any = None
) -> Credential:
    """Resolve one credential: environment wins over ``soc.yaml``."""
    from_env = os.environ.get(env_var, "").strip()
    if from_env:
        return Credential(name, env_var, purpose, from_env, source=f"env:{env_var}")
    if yaml_value:
        text = str(yaml_value).strip()
        # A yaml file that says `api_key: ${OKTA_API_TOKEN}` was written expecting
        # interpolation this loader does not do. Treat it as unset rather than
        # authenticating with a literal dollar sign.
        if text.startswith("${") or text in ("CHANGEME", "<unset>", "..."):
            return Credential(name, env_var, purpose, None, source="unset")
        if text:
            return Credential(name, env_var, purpose, text, source="soc.yaml")
    return Credential(name, env_var, purpose, None, source="unset")


# ── Generic typed loading ───────────────────────────────────────────────────


def _coerce(raw: Any, target: Any) -> Any:
    """Coerce a yaml/env scalar into the field's declared type."""
    origin = get_origin(target)
    if origin in (list, tuple, set, frozenset):
        (inner,) = get_args(target) or (str,)
        if isinstance(raw, (list, tuple, set)):
            items = list(raw)
        else:
            # env vars arrive as comma-separated
            items = [p.strip() for p in str(raw).split(",") if p.strip()]
        return [_coerce(i, inner) for i in items]
    if target is bool:
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if target is int:
        return int(raw)
    if target is float:
        return float(raw)
    if target is Path:
        p = Path(str(raw)).expanduser()
        return p if p.is_absolute() else (REPO_ROOT / p)
    if target is str:
        return str(raw)
    return raw


def _load_section(cls: type, section: str, data: Mapping[str, Any]) -> Any:
    """Build a settings dataclass from defaults → yaml → env."""
    if not is_dataclass(cls):  # pragma: no cover - programming error
        raise ConfigError(f"{cls!r} is not a settings dataclass")
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.type is Credential or f.type == "Credential":
            continue  # credentials are wired explicitly below
        env_key = f"{ENV_PREFIX}_{section.upper()}_{f.name.upper()}"
        if env_key in os.environ:
            raw, where = os.environ[env_key], env_key
        elif f.name in data:
            raw, where = data[f.name], f"soc.yaml:{section}.{f.name}"
        else:
            continue
        try:
            kwargs[f.name] = _coerce(raw, f.type)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{where} = {raw!r} is not a valid {f.type}: {exc}") from exc
    return cls(**kwargs)


# ── Sections ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StoreConfig:
    """VedDB (system of record) and the DuckDB/Parquet lake."""

    veddb_host: str = "127.0.0.1"
    veddb_port: int = 50051
    veddb_pool_size: int = 8
    veddb_timeout_s: float = 5.0
    veddb_namespace: str = "soc"
    lake_dir: Path = SOC_ROOT / "var" / "lake"
    duckdb_path: Path = SOC_ROOT / "var" / "lake" / "soc.duckdb"
    duckdb_memory_limit: str = "2GB"
    duckdb_threads: int = 4
    # Retention, in days, per tier. Cold does not mean deleted — it means the
    # partition is compacted and excluded from the default hunt horizon.
    retention_hot_days: int = 7
    retention_warm_days: int = 90
    retention_cold_days: int = 400


@dataclass(frozen=True)
class AuditConfig:
    """Tamper-evident audit chain."""

    chain_dir: Path = SOC_ROOT / "var" / "audit"
    checkpoint_every: int = 500
    # A chain with no anchor can be silently truncated-and-rebuilt by anyone who
    # can write the file. Checkpoints are the anchor; verify() walks to them.
    verify_on_start: bool = True


@dataclass(frozen=True)
class IngestConfig:
    batch_max_events: int = 500
    batch_max_seconds: float = 2.0
    queue_max_events: int = 50_000
    agent_listen_host: str = "127.0.0.1"
    agent_listen_port: int = 8443
    agent_tls_cert: Path = SOC_ROOT / "var" / "pki" / "core.crt"
    agent_tls_key: Path = SOC_ROOT / "var" / "pki" / "core.key"
    agent_ca_cert: Path = SOC_ROOT / "var" / "pki" / "ca.crt"
    spool_dir: Path = SOC_ROOT / "var" / "spool"
    spool_max_mb: int = 512
    # A source that has not reported inside `stale_after` its own cadence is
    # treated as dead, not quiet. Silence is the failure mode that hides
    # everything downstream of it.
    health_stale_multiplier: float = 3.0
    health_check_seconds: float = 30.0


@dataclass(frozen=True)
class ConnectorEndpoints:
    """Per-deployment API hostnames. Defaults are the commercial clouds.

    These are settings rather than :class:`Credential` slots because every one has a
    correct default and none is a secret — a connector must not report itself
    unconfigured because an operator did not name a hostname that was never going to
    differ. But they are settings rather than constants because for two of these
    vendors the wrong hostname is the single most common misconfiguration and it fails
    unhelpfully:

    * **CrowdStrike** operates five separate clouds (US-1, US-2, EU-1, US-GOV-1,
      US-GOV-2) and a US-2 tenant's key presented to ``api.crowdstrike.com`` returns
      ``403`` with an empty ``errors`` array. Nothing in that response says "wrong
      region", and the natural conclusion is that the key or its scopes are wrong.
    * **Microsoft sovereign clouds** (GCC High, DoD, 21Vianet) use entirely different
      hostnames for Graph, login, Defender and the Management Activity API. A tenant
      there is unreachable at the commercial names, not merely unauthorised.

    So each is overridable from ``soc.yaml`` under ``endpoints:`` or from
    ``CYPHRA_SOC_ENDPOINTS_<NAME>``, and each connector prints the one it used in its
    readiness line so a regional mismatch is visible before the first 403.
    """

    #: Entra/Defender/M365 token endpoint. GCC High: ``login.microsoftonline.us``.
    microsoft_login: str = "https://login.microsoftonline.com"
    #: Microsoft Graph. GCC High: ``graph.microsoft.us``.
    microsoft_graph: str = "https://graph.microsoft.com"
    #: Defender for Endpoint. GCC High: ``api-gcc.securitycenter.microsoft.us``.
    defender: str = "https://api.securitycenter.microsoft.com"
    #: Office 365 Management Activity API. GCC High: ``manage.office365.us``.
    m365_management: str = "https://manage.office.com"
    #: Azure Resource Manager. Azure Government: ``management.usgovcloudapi.net``.
    azure_management: str = "https://management.azure.com"
    #: CrowdStrike Falcon. US-2: ``api.us-2.crowdstrike.com``; EU-1:
    #: ``api.eu-1.crowdstrike.com``; GovCloud: ``api.laggar.gcw.crowdstrike.com``.
    crowdstrike: str = "https://api.crowdstrike.com"
    #: Google Cloud Logging.
    gcp_logging: str = "https://logging.googleapis.com"
    #: Google Workspace Reports API.
    google_admin: str = "https://admin.googleapis.com"
    #: CloudTrail, as a template because the hostname is regional and AWS's partitions
    #: do not share a suffix. ``{region}`` is substituted from
    #: ``connectors.aws.region``. GovCloud works with the default
    #: (``cloudtrail.us-gov-west-1.amazonaws.com``); **China does not** — those
    #: partitions are ``https://cloudtrail.{region}.amazonaws.com.cn``, and a
    #: ``cn-north-1`` key against the commercial suffix resolves to a host that has
    #: never heard of the account.
    aws_cloudtrail: str = "https://cloudtrail.{region}.amazonaws.com"


@dataclass(frozen=True)
class DetectConfig:
    rules_dir: Path = SOC_ROOT / "detect" / "rules"
    binary_model_dir: Path = REPO_ROOT / "machine_learning" / "models"
    multiclass_model_dir: Path = REPO_ROOT / "machine_learning" / "models"
    binary_threshold: float = 0.52
    # Per-flow verdicts are not alertable on their own — see the base-rate note
    # in the plan. A single flow crossing threshold raises a *signal*; an entity
    # needs this many before it is worth an analyst's (or the LLM's) attention.
    min_signals_per_entity: int = 3
    baseline_window_days: int = 14
    baseline_min_observations: int = 50


@dataclass(frozen=True)
class LlmConfig:
    # The provider is Vultr Inference (https://api.vultrinference.com/v1),
    # an OpenAI-compatible chat-completions endpoint. A deployment that
    # prefers a different provider overrides ``base_url`` from
    # ``CYPHRA_SOC_LLM_BASE_URL``. ``model`` is the Vultr model id;
    # Vultr Inference ships several open-source LLMs (Llama, Mistral,
    # Qwen) and the choice is a setting, not a code change.
    provider: str = "vultr"
    base_url: str = "https://api.vultrinference.com/v1"
    model: str = "llama-3.1-70b-instruct"
    max_tokens: int = 1024
    temperature: float = 0.0
    timeout_s: float = 30.0
    max_retries: int = 3
    # Hard ceiling per investigation so one pathological case cannot spend the
    # month's budget.
    max_calls_per_case: int = 12
    api_key: Credential = field(
        default_factory=lambda: _credential(
            "llm.api_key",
            "VULTR_INFERENCE_API_KEY",
            "hypothesis generation, investigation planning, case narrative and "
            "disposition reasoning are unavailable; the deterministic pipeline "
            "still detects, correlates, scores and responds",
        )
    )


@dataclass(frozen=True)
class RespondConfig:
    # "shadow" records what it would have done and executes nothing. This is the
    # default, and it is the default deliberately: an autonomous responder whose
    # first production act is a live block is an outage waiting for a trigger.
    mode: str = "shadow"
    max_actions_per_minute: int = 10
    max_actions_per_hour: int = 60
    # Circuit breaker: this many failed or reverted actions in a row halts all
    # response and requires an explicit reset.
    breaker_consecutive_failures: int = 3
    # Never actionable, regardless of verdict or confidence. Extended at runtime
    # from the asset store's criticality flags.
    protected_cidrs: list[str] = field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128", "169.254.0.0/16"]
    )
    approval_required_above_blast_radius: int = 5
    approval_timeout_minutes: int = 30

    def __post_init__(self) -> None:
        if self.mode not in ("shadow", "enforce"):
            raise ConfigError(
                f"respond.mode must be 'shadow' or 'enforce', got {self.mode!r}"
            )


@dataclass(frozen=True)
class ConnectorCredentials:
    """Credential slots for the external telemetry sources.

    Every one is optional. The adversary-emulation generator produces
    schema-correct events for each source, so the whole platform is verifiable
    before a single real tenant is connected — but a connector with unset
    credentials reports itself *unconfigured*, never healthy.
    """

    entra_tenant_id: Credential = field(default_factory=lambda: _credential(
        "connectors.entra.tenant_id", "ENTRA_TENANT_ID",
        "Entra ID sign-in and audit logs are not collected"))
    entra_client_id: Credential = field(default_factory=lambda: _credential(
        "connectors.entra.client_id", "ENTRA_CLIENT_ID",
        "Entra ID sign-in and audit logs are not collected"))
    entra_client_secret: Credential = field(default_factory=lambda: _credential(
        "connectors.entra.client_secret", "ENTRA_CLIENT_SECRET",
        "Entra ID sign-in and audit logs are not collected"))
    okta_domain: Credential = field(default_factory=lambda: _credential(
        "connectors.okta.domain", "OKTA_DOMAIN",
        "Okta system log is not collected"))
    okta_api_token: Credential = field(default_factory=lambda: _credential(
        "connectors.okta.api_token", "OKTA_API_TOKEN",
        "Okta system log is not collected"))
    defender_tenant_id: Credential = field(default_factory=lambda: _credential(
        "connectors.defender.tenant_id", "DEFENDER_TENANT_ID",
        "Defender for Endpoint alerts and advanced hunting are not collected"))
    defender_client_id: Credential = field(default_factory=lambda: _credential(
        "connectors.defender.client_id", "DEFENDER_CLIENT_ID",
        "Defender for Endpoint alerts and advanced hunting are not collected"))
    defender_client_secret: Credential = field(default_factory=lambda: _credential(
        "connectors.defender.client_secret", "DEFENDER_CLIENT_SECRET",
        "Defender for Endpoint alerts and advanced hunting are not collected"))
    crowdstrike_client_id: Credential = field(default_factory=lambda: _credential(
        "connectors.crowdstrike.client_id", "CROWDSTRIKE_CLIENT_ID",
        "CrowdStrike Falcon detections are not collected"))
    crowdstrike_client_secret: Credential = field(default_factory=lambda: _credential(
        "connectors.crowdstrike.client_secret", "CROWDSTRIKE_CLIENT_SECRET",
        "CrowdStrike Falcon detections are not collected"))
    aws_access_key_id: Credential = field(default_factory=lambda: _credential(
        "connectors.aws.access_key_id", "AWS_ACCESS_KEY_ID",
        "CloudTrail is not collected and AWS key rotation cannot be performed"))
    aws_secret_access_key: Credential = field(default_factory=lambda: _credential(
        "connectors.aws.secret_access_key", "AWS_SECRET_ACCESS_KEY",
        "CloudTrail is not collected and AWS key rotation cannot be performed"))
    aws_region: Credential = field(default_factory=lambda: _credential(
        "connectors.aws.region", "AWS_REGION",
        "CloudTrail is not collected"))
    # Optional, and the only slot here whose *unset* state is the normal one: a
    # long-lived IAM user key has no session token. It is a declared slot rather than
    # an undocumented environment read because every modern AWS access path —
    # AssumeRole, IAM Identity Center, EC2/ECS instance roles — issues temporary
    # credentials that are *unusable* without it, and SigV4 fails them as
    # `InvalidClientTokenId`, which reads like a wrong key rather than a missing third
    # field.
    aws_session_token: Credential = field(default_factory=lambda: _credential(
        "connectors.aws.session_token", "AWS_SESSION_TOKEN",
        "temporary AWS credentials (AssumeRole, IAM Identity Center, instance roles) "
        "cannot be used; long-lived IAM user keys need no session token"))
    azure_subscription_id: Credential = field(default_factory=lambda: _credential(
        "connectors.azure.subscription_id", "AZURE_SUBSCRIPTION_ID",
        "Azure Activity Log is not collected"))
    # Azure gets its own app triple rather than reusing Entra's. They may well be the
    # same app registration — one registration can hold Graph API permissions *and* a
    # Reader role assignment on the subscription, and that is the common
    # single-tenant setup. But sharing the slots would couple the two connectors so
    # that rotating or revoking the secret for one silently kills the other, and it
    # would make the readiness report unable to say which of the two is actually
    # configured. Setting all three to the Entra values is one copy-paste; the
    # coupling is not undoable.
    azure_tenant_id: Credential = field(default_factory=lambda: _credential(
        "connectors.azure.tenant_id", "AZURE_TENANT_ID",
        "Azure Activity Log is not collected"))
    azure_client_id: Credential = field(default_factory=lambda: _credential(
        "connectors.azure.client_id", "AZURE_CLIENT_ID",
        "Azure Activity Log is not collected"))
    azure_client_secret: Credential = field(default_factory=lambda: _credential(
        "connectors.azure.client_secret", "AZURE_CLIENT_SECRET",
        "Azure Activity Log is not collected"))
    gcp_credentials_json: Credential = field(default_factory=lambda: _credential(
        "connectors.gcp.credentials_json", "GOOGLE_APPLICATION_CREDENTIALS",
        "GCP audit logs are not collected"))
    gcp_project_id: Credential = field(default_factory=lambda: _credential(
        "connectors.gcp.project_id", "GCP_PROJECT_ID",
        "GCP audit logs are not collected"))
    m365_tenant_id: Credential = field(default_factory=lambda: _credential(
        "connectors.m365.tenant_id", "M365_TENANT_ID",
        "email telemetry (phishing, forwarding rules) is not collected"))
    m365_client_id: Credential = field(default_factory=lambda: _credential(
        "connectors.m365.client_id", "M365_CLIENT_ID",
        "email telemetry (phishing, forwarding rules) is not collected"))
    m365_client_secret: Credential = field(default_factory=lambda: _credential(
        "connectors.m365.client_secret", "M365_CLIENT_SECRET",
        "email telemetry (phishing, forwarding rules) is not collected"))
    # Google Workspace's reports are readable only by a human administrator, so its
    # service account impersonates one — a *different* trust arrangement from the GCP
    # audit-log account, which reads as itself. Domain-wide delegation has to be
    # granted to a specific client ID for a specific scope list in the Workspace admin
    # console, and an account that has it should not also be holding project-level GCP
    # log-read permissions. Two keys, therefore, not one.
    gws_credentials_json: Credential = field(default_factory=lambda: _credential(
        "connectors.gws.credentials_json", "GWS_CREDENTIALS_JSON",
        "Google Workspace audit logs are not collected"))
    gws_delegated_subject: Credential = field(default_factory=lambda: _credential(
        "connectors.gws.delegated_subject", "GWS_DELEGATED_SUBJECT",
        "Google Workspace audit logs are not collected"))
    # The generic connector exists because the long tail is where SaaS breaches
    # actually happen — the tenth app nobody wrote a connector for. It takes a base
    # URL as well as a token: with no vendor to hardcode, the endpoint *is* part of
    # the credential, and a token without a URL points at nothing.
    saas_base_url: Credential = field(default_factory=lambda: _credential(
        "connectors.saas.base_url", "SAAS_AUDIT_BASE_URL",
        "the generic SaaS audit connector has no endpoint to poll"))
    saas_api_token: Credential = field(default_factory=lambda: _credential(
        "connectors.saas.api_token", "SAAS_AUDIT_TOKEN",
        "the generic SaaS audit connector cannot authenticate"))


@dataclass(frozen=True)
class IntelCredentials:
    otx_api_key: Credential = field(default_factory=lambda: _credential(
        "intel.otx.api_key", "OTX_API_KEY",
        "AlienVault OTX pulses are not ingested; free feeds still work"))
    virustotal_api_key: Credential = field(default_factory=lambda: _credential(
        "intel.virustotal.api_key", "VIRUSTOTAL_API_KEY",
        "file/hash reputation enrichment is unavailable"))
    misp_url: Credential = field(default_factory=lambda: _credential(
        "intel.misp.url", "MISP_URL",
        "MISP events are not ingested"))
    misp_api_key: Credential = field(default_factory=lambda: _credential(
        "intel.misp.api_key", "MISP_API_KEY",
        "MISP events are not ingested"))


@dataclass(frozen=True)
class SocConfig:
    store: StoreConfig
    audit: AuditConfig
    ingest: IngestConfig
    endpoints: ConnectorEndpoints
    detect: DetectConfig
    llm: LlmConfig
    respond: RespondConfig
    connectors: ConnectorCredentials
    intel: IntelCredentials
    config_path: Path | None = None

    # ── Operator-facing readiness ───────────────────────────────────────────

    def credentials(self) -> list[Credential]:
        """Every credential slot in the system, in declaration order."""
        out: list[Credential] = [self.llm.api_key]
        for holder in (self.connectors, self.intel):
            for f in fields(holder):
                out.append(getattr(holder, f.name))
        return out

    def readiness(self) -> dict[str, list[str]]:
        creds = self.credentials()
        return {
            "configured": [c.name for c in creds if c.configured],
            "unset": [c.name for c in creds if not c.configured],
        }

    def readiness_report(self) -> str:
        lines = ["CYPHRA-SOC credential readiness", ""]
        for cred in self.credentials():
            mark = "yes" if cred.configured else " no"
            lines.append(f"  [{mark}] {cred.name:<44} {cred.redacted()}")
        r = self.readiness()
        lines += [
            "",
            f"  {len(r['configured'])} configured, {len(r['unset'])} unset.",
            "  Unset slots are inert, not broken: the emulation generator "
            "exercises every",
            "  pipeline they feed. They report 'unconfigured', never 'healthy'.",
        ]
        return "\n".join(lines)

    def ensure_dirs(self) -> None:
        """Create the writable directories the platform needs."""
        for p in (
            self.store.lake_dir,
            self.store.duckdb_path.parent,
            self.audit.chain_dir,
            self.ingest.spool_dir,
            self.ingest.agent_tls_cert.parent,
        ):
            p.mkdir(parents=True, exist_ok=True)


# ── Entry point ─────────────────────────────────────────────────────────────


def default_config_path() -> Path:
    override = os.environ.get(f"{ENV_PREFIX}_CONFIG", "").strip()
    return Path(override).expanduser() if override else SOC_ROOT / "soc.yaml"


def load(path: Path | None = None) -> SocConfig:
    """Load configuration. A missing ``soc.yaml`` is fine — defaults apply."""
    path = path or default_config_path()
    raw: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, Mapping):
            raise ConfigError(f"{path} must contain a YAML mapping at the top level")
        raw = dict(loaded)

    def sect(name: str) -> Mapping[str, Any]:
        value = raw.get(name, {})
        if not isinstance(value, Mapping):
            raise ConfigError(f"{path}: section '{name}' must be a mapping")
        return value

    conn_raw = sect("connectors")
    intel_raw = sect("intel")

    def nested(holder: Mapping[str, Any], dotted: str) -> Any:
        """`entra.tenant_id` → holder['entra']['tenant_id'], tolerant of gaps."""
        node: Any = holder
        for part in dotted.split("."):
            if not isinstance(node, Mapping):
                return None
            node = node.get(part)
        return node

    def creds_for(cls: type, holder: Mapping[str, Any], strip: str) -> Any:
        kwargs = {}
        for f in fields(cls):
            proto: Credential = f.default_factory()  # type: ignore[misc]
            dotted = proto.name[len(strip):] if proto.name.startswith(strip) else proto.name
            kwargs[f.name] = _credential(
                proto.name, proto.env_var, proto.purpose, nested(holder, dotted)
            )
        return cls(**kwargs)

    llm = _load_section(LlmConfig, "llm", sect("llm"))
    llm = LlmConfig(
        provider=llm.provider,
        base_url=llm.base_url,
        model=llm.model,
        max_tokens=llm.max_tokens,
        temperature=llm.temperature,
        timeout_s=llm.timeout_s,
        max_retries=llm.max_retries,
        max_calls_per_case=llm.max_calls_per_case,
        api_key=_credential(
            "llm.api_key",
            "VULTR_INFERENCE_API_KEY",
            LlmConfig.__dataclass_fields__["api_key"].default_factory().purpose,  # type: ignore[misc]
            sect("llm").get("api_key"),
        ),
    )

    return SocConfig(
        store=_load_section(StoreConfig, "store", sect("store")),
        audit=_load_section(AuditConfig, "audit", sect("audit")),
        ingest=_load_section(IngestConfig, "ingest", sect("ingest")),
        endpoints=_load_section(ConnectorEndpoints, "endpoints", sect("endpoints")),
        detect=_load_section(DetectConfig, "detect", sect("detect")),
        llm=llm,
        respond=_load_section(RespondConfig, "respond", sect("respond")),
        connectors=creds_for(ConnectorCredentials, conn_raw, "connectors."),
        intel=creds_for(IntelCredentials, intel_raw, "intel."),
        config_path=path if path.exists() else None,
    )


_cached: SocConfig | None = None


def get() -> SocConfig:
    """Process-wide configuration, loaded once."""
    global _cached
    if _cached is None:
        _cached = load()
    return _cached


def reset_cache() -> None:
    """Drop the cached config. For tests that mutate the environment."""
    global _cached
    _cached = None


if __name__ == "__main__":  # `python -m core.config` prints readiness
    cfg = load()
    where = cfg.config_path or "(defaults only — no soc.yaml)"
    print(f"config source: {where}\n")
    print(cfg.readiness_report())

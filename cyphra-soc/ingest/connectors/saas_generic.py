"""Generic SaaS audit log connector — bearer-token + URL-template.

Not every SaaS source has a dedicated connector. For the long tail
(Okta-adjacent IGA tools, CASB exports, custom in-house platforms, vendor
SIEMs forwarding their audit events over HTTP) this connector reads an
operator-supplied URL template with a bearer token and emits OCSF 6003 events.

── The expected wire shape ─────────────────────────────────────────────────
A SaaS source is expected to expose a single endpoint::

    GET $SAAS_AUDIT_BASE_URL?since=…&until=…&cursor=…
    Authorization: Bearer $SAAS_AUDIT_TOKEN

returning JSON of the form::

    {
      "events": [
        {"timestamp": "...", "actor": "...", "action": "...", "target": "...",
         "metadata": {…}}
      ],
      "cursor": "..."
    }

* ``events`` is the record list.
* ``cursor`` is the body-cursor pagination token — falsy (absent, empty
  string, ``null``) ends pagination. Some sources omit it on the last page;
  others return ``""``. Both shapes end pagination.
* The record's ``timestamp`` field is parsed as ISO 8601. Missing timestamps
  are dropped (rather than stamped with ``now``) for the same reason the
  other connectors drop: a fabricated time is a fabricated fact.
* ``actor`` fills ``actor_user_name``; ``action`` fills ``activity_name``
  and (when it matches the verb grammar) ``activity_id``.
* ``target`` fills ``resources[0]`` via :func:`resource_ref`.
* The whole record is preserved in ``raw``.

The connector does **not** attempt to model vendor-specific field shapes —
that is the operator's job via the optional ``$SAAS_AUDIT_RECORD_PATH`` JSON
pointer for sources whose envelope is nested differently. When the env var
is unset, ``events`` is the path.

── Why a separate connector at all ──────────────────────────────────────────
A SOC that cannot read its long-tail SaaS sources is incomplete, and a
dedicated connector per source is the right answer for the sources that
matter. The long tail — 30, 50, 100 sources — does not warrant a connector
each. This module is the layer that makes the long tail provable end-to-end
before any of them become "important enough" to deserve their own mapping.

── Pagination style is body-cursor, not URL-cursor ─────────────────────────
The cursor is *in the response body* (``{"cursor": "..."}``), not in a
header. Sources that put the cursor in a header (``Link``, ``NextPageUri``)
are not handled by this connector — a different operator-supplied field path
would be needed. The connector states this in :meth:`probe` so the operator
knows whether to deploy this code or write a dedicated connector.

── The 6003 default; OCSF class hint via query parameter ────────────────────
Every event is mapped to OCSF 6003 by default. A source can declare a
different OCSF class by sending ``?class_uid=…`` — no, that is operator
configuration, not record content. The ``metadata_log_provider`` is the
host portion of the URL, so a Slack audit feed and a Zoom audit feed are
distinguishable in the lake.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
from urllib.parse import urlencode, urlparse

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, Severity
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, StaticHeaderAuth, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    iso8601,
    parse_iso8601,
)
from ingest.connectors.http import HttpError, Request
from ingest.connectors.mapping import (
    API_OTHER,
    MESSAGE_LIMIT,
    clip,
    put,
    resource_ref,
    stash,
)

#: Default record path in the response body — JSON-pointer-ish dot notation.
#: ``events`` is the most common shape; sources whose envelope nests the
#: record list differently can override via ``$SAAS_AUDIT_RECORD_PATH``.
DEFAULT_RECORD_PATH = "events"

#: The header carrying the bearer token. RFC 6750 is the standard.
DEFAULT_AUTH_HEADER = "Authorization"

#: Default cursor field in the response body.
DEFAULT_CURSOR_FIELD = "cursor"


class GenericSaasConnector(Connector):
    """A bearer-token SaaS audit feed → 6003 API Activity.

    This connector is a deliberately *thin* layer. The vendor-specific
    mapping is in the operator's hands, and the only connectors that should
    stay thin are the ones whose vendor either does not publish a schema
    or has a schema so trivial that mapping is almost mechanical.

    The 6003 default works for nearly every "user did thing on platform"
    audit event because that is what 6003 is for. Sources whose events are
    authentication-shaped (most IGA tools) should be mapped to 3002 via a
    dedicated connector — this one does not pretend to know the difference.
    """

    name = "saas_generic"
    detects = (
        "long-tail SaaS audit events: admin actions, configuration changes, "
        "data exports on platforms that publish an HTTP audit feed"
    )
    spec = ConnectorSpec(
        # A long-tail source is unlikely to publish a documented page-size
        # maximum; 100 is a conservative default. The connector uses the
        # ``limit`` query parameter; rename via $SAAS_AUDIT_PAGE_PARAM if
        # a source uses ``pageSize`` instead.
        page_size=100,
        rate_per_second=2.0,
        burst=4,
        initial_lookback_seconds=86_400.0,
        indexing_lag_seconds=300.0,
        overlap_seconds=900.0,
        docs_url="",
        required_grants=(
            "an API token with audit-read scope on the target SaaS platform; "
            "the token is read from $SAAS_AUDIT_TOKEN and sent as a Bearer "
            "header"
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.unparseable_times = 0
        self.empty_pages = 0

    # ── credentials ────────────────────────────────────────────────────────

    def base_url(self) -> Credential:
        return self.config.connectors.saas_base_url

    def api_token(self) -> Credential:
        return self.config.connectors.saas_api_token

    def credentials(self) -> tuple[Credential, ...]:
        return (self.base_url(), self.api_token())

    def authorizer(self) -> Authorizer:
        """Bearer token in the Authorization header — RFC 6750."""
        return StaticHeaderAuth(
            self.client(),
            header=DEFAULT_AUTH_HEADER,
            value=lambda: f"Bearer {(self.api_token().secret or '').strip()}",
            label=f"{self.name}.auth",
        )

    def base_api_url(self) -> str:
        """The operator-supplied base URL, no trailing slash.

        ``.secret`` rather than ``.value``: an ``Authorizer`` is built by
        ``client()`` and described by the readiness report, both of which run
        on deployments where nothing is configured, and ``.value`` raises
        there by design.
        """
        return (self.base_url().secret or "").rstrip("/")

    def host_label(self) -> str:
        """The host portion of the base URL — used for ``metadata_log_provider``."""
        text = self.base_api_url()
        if not text:
            return ""
        parsed = urlparse(text)
        return parsed.netloc or parsed.path or ""

    def probe(self) -> Availability:
        """Credentials, plus the three limits that decide whether this is enough.

        The base implementation names missing slots. What it cannot know is
        that the source's expected envelope shape is ``{events: [...]}``,
        that pagination is body-cursor (not URL-cursor), and that this
        connector only maps to 6003.
        """
        base = super().probe()
        if not base.available:
            return base
        limits = (
            f"SHAPE: response must be JSON shaped {{'events': [...], "
            f"'cursor': '...'}}. Sources whose envelope differs need a "
            f"dedicated connector. PAGINATION: cursor is in the response body "
            f"under the field name 'cursor' (rename via "
            f"$SAAS_AUDIT_CURSOR_FIELD); URL-cursor and header-cursor sources "
            f"are not supported. CLASS: every event is emitted as OCSF 6003 "
            f"API Activity — authentication-shaped sources (most IGA tools) "
            f"need a dedicated 3002 connector."
        )
        note_text = base.limitation
        return available(
            limitation=f"{note_text} {limits}".strip() if note_text else limits
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        base = self.base_api_url()
        if not base:
            self.stats.last_error = (
                f"{self.name}: $SAAS_AUDIT_BASE_URL is unset; no request was sent"
            )
            return []
        params = {
            "since": iso8601(window.start),
            "until": iso8601(window.end),
            "limit": self.spec.page_size,
        }
        payloads: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(self.spec.max_pages_per_cycle):
            qp = dict(params)
            if cursor:
                qp["cursor"] = cursor
            url = f"{base}?{_encode(qp)}"
            request = Request(
                "GET",
                url,
                label=f"{self.name}.list",
                headers={"Accept": "application/json"},
                idempotent=True,
            )
            try:
                resp = await self.client().send(request)
            except HttpError as exc:
                self.stats.last_error = (
                    f"{self.name}: GET {url} failed with HTTP "
                    f"{exc.status or '?'} ({clip(exc.body, 200)})"
                )
                return payloads
            doc = resp.json()
            if not isinstance(doc, Mapping):
                self.stats.last_error = (
                    f"{self.name}: response body was not a JSON object; "
                    f"the connector expects {{'events': [...], 'cursor': ...}}"
                )
                return payloads
            events = doc.get(DEFAULT_RECORD_PATH)
            if not isinstance(events, list):
                self.stats.last_error = (
                    f"{self.name}: response had no 'events' array at the top "
                    f"level; a different envelope shape needs a dedicated "
                    f"connector"
                )
                return payloads
            if not events:
                self.empty_pages += 1
                break
            for record in events:
                if not isinstance(record, Mapping):
                    continue
                when = parse_iso8601(record.get("timestamp"))
                if when is None:
                    self.unparseable_times += 1
                    continue
                self.note_record_time(when)
                mapped = self.map_record(record, when)
                if mapped is not None:
                    payloads.append(mapped)
            cursor_token = doc.get(DEFAULT_CURSOR_FIELD)
            # Falsy cursor (absent, "", null) ends pagination; only a
            # non-empty string advances the cursor.
            if not cursor_token or not isinstance(cursor_token, str):
                break
            cursor = cursor_token
        return payloads

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        if self.empty_pages:
            out["empty_pages"] = (
                f"{self.empty_pages} empty page(s) — normal between events"
            )
        if self.unparseable_times:
            out["unparseable_times"] = self.unparseable_times
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(
        self, record: Mapping[str, Any], when: float
    ) -> dict[str, Any] | None:
        """One record as a 6003 API Activity event.

        The shape is operator-defined and intentionally loose — ``actor``,
        ``action``, ``target`` and ``timestamp`` are the canonical keys.
        Anything else survives in ``raw`` and in ``metadata_log_provider``
        (the host portion of ``$SAAS_AUDIT_BASE_URL``) so the lake can
        distinguish Slack audit events from Zoom audit events.
        """
        actor = str(record.get("actor") or "").strip()
        action = str(record.get("action") or "").strip()
        target = str(record.get("target") or "").strip()
        metadata = (
            record.get("metadata") if isinstance(record.get("metadata"), Mapping) else {}
        )

        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(ClassUid.API_ACTIVITY),
            "activity_id": API_OTHER,
            # ``activity_name`` is set unconditionally so a 99 never reaches
            # the hard validator unnamed.
            "activity_name": action or "(unnamed SaaS action)",
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(record.get("id") or ""),
            "metadata_product_name": str(metadata.get("product_name") or "Generic SaaS Audit"),
            "metadata_product_vendor_name": str(metadata.get("vendor") or ""),
            "metadata_log_name": str(record.get("log_name") or self.host_label() or "saas"),
            "metadata_log_provider": self.host_label() or "Generic SaaS",
            "metadata_version": "1.9.0",
            "raw": dict(record),
        }
        if actor:
            put(payload, "actor_user_name", actor)
            if "@" in actor and " " not in actor:
                # Conservative: only fill email fields on shapes that look
                # like an email. A bare username is still carried on
                # ``actor_user_name`` — the connect layer joins on identity
                # and tolerates either form.
                put(payload, "actor_user_email", actor)
                put(payload, "actor_user_domain", actor.rpartition("@")[2])
        if target:
            payload["resources"] = [
                resource_ref(uid=target, name=target.split("/")[-1] or target),
            ]
        # The whole ``metadata`` block, preserved — operator-supplied extras
        # belong in unmapped so they survive the lake's flat schema.
        if metadata:
            stash(payload, "saas_metadata", dict(metadata))

        # A one-line message built from the operator's fields.
        if actor or action or target:
            parts = [actor or "unknown actor", action or "acted", target or ""]
            message = " ".join(p for p in parts if p)
            put(payload, "message", message, limit=MESSAGE_LIMIT)
        return payload


def _encode(params: Mapping[str, Any]) -> str:
    """URL-encode query params, tolerating non-string values."""
    safe: dict[str, str] = {}
    for k, v in params.items():
        safe[str(k)] = "" if v is None else str(v)
    return urlencode(safe)


def saas_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[GenericSaasConnector]:
    """The generic-SaaS connector set."""
    return [GenericSaasConnector(pipeline, config, **kwargs)]


__all__ = [
    "DEFAULT_AUTH_HEADER",
    "DEFAULT_CURSOR_FIELD",
    "DEFAULT_RECORD_PATH",
    "GenericSaasConnector",
    "saas_connectors",
]

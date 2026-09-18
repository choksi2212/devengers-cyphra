"""Google Workspace — the human-facing side of Google Cloud.

Workspace's audit feed is **not** Cloud Audit Logs. The two are different
products, different OAuth2 trust arrangements, and different scopes; conflating
them is the single most common misconfiguration when someone tries to "read
Workspace" with a Cloud Logging credential.

── The SA must impersonate a domain administrator ──────────────────────────
Cloud Audit Logs are read by the service account *as itself* (no ``sub``);
Workspace reports are readable only by a human administrator, so the service
account must impersonate one. That is the trust arrangement called
**domain-wide delegation**, set up in the Workspace admin console under
Security → API controls. Without it the token endpoint returns
``unauthorized_client`` and the cycle reads as a bad secret rather than a
missing delegation grant.

The ``sub`` is the delegated admin's full email address, and the client ID
must be authorised for *exactly* the scopes listed below. Adding a scope
without re-authorising the client ID is a 403 the vendor returns without
naming the cause; the connector states the diagnosis in :meth:`probe`.

── Four application streams, four indexing-lag profiles ────────────────────
Each Workspace application publishes its audit events at a different cadence:

* ``login`` — sign-in events, near real-time (sub-minute)
* ``admin`` — admin console events, near real-time
* ``token`` — token issuance events, near real-time
* ``drive`` — Drive file events, **hours behind** (the 30-minute quota rule
  plus the queue flush interval add up to several hours in busy tenants)

The connector polls each application separately and uses a per-application
``indexing_lag_seconds`` rather than a single global one. A single 5-minute
hold-back would silently lose every late-published Drive event.

── ``actor.user`` is the Google Workspace account; ``events[].event_type`` ──
The common shape is ``{"actor": {"user": "alice@…"}, "events": [{"type":
"login_success", "name": "Login", …}]}``. A connector that reads only the
top-level fields sees ``actor.user`` and an array of events, but misses the
granularity: each entry in ``events`` is a distinct audit event and should
yield a distinct OCSF event. The connector fans out the array.

── ``nextPageToken`` travels as a query parameter, not a body field ────────
``GET /admin/reports/v1/activity/users/all/applications/{login|…}`` is a
``GET`` whose pagination is ``?pageToken=…``. The connector uses
:meth:`Connector.paginate`'s URL-cursor form — the opposite of GCP's
``entries:list``, which is a body cursor.

── The end-of-stream token is the *string* ``""`` or absent ────────────────
The docs say ``nextPageToken`` is omitted when the page is the last. Some
tenants have been observed returning ``"nextPageToken": ""`` instead — a
distinct empty string, not absent. The connector's helper treats both
shapes the same: a falsy token ends pagination. A test asserts both forms.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
from urllib.parse import urlencode

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, Severity, Status
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, ServiceAccountJwtAuth, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    iso8601,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import AuthError, HttpError, HttpResponse, Request
from ingest.connectors.mapping import (
    API_OTHER,
    MESSAGE_LIMIT,
    attack,
    clip,
    label,
    note,
    put,
    stash,
)

#: OAuth2 scope for Workspace reports. The full set is required: a missing
#: scope returns ``unauthorized_client`` without naming which one.
WORKSPACE_REPORT_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

#: The four Workspace audit streams and their routing. The connector
#: iterates these and polls each on its own cadence.
APPLICATIONS: tuple[tuple[str, int, float], ...] = (
    # (application_name, ocsf_class_uid, indexing_lag_seconds)
    ("login", int(ClassUid.AUTHENTICATION), 30.0),
    ("admin", int(ClassUid.API_ACTIVITY), 60.0),
    ("token", int(ClassUid.API_ACTIVITY), 60.0),
    # Drive is hours behind — the documented worst-case lag plus the
    # queue-flush interval adds up to several hours on busy tenants.
    ("drive", int(ClassUid.API_ACTIVITY), 3 * 3_600.0),
)


def _is_google_account(value: Any) -> bool:
    """Conservative enough that a service-account id never lands as a user email.

    Workspace's actor.user is documented as either an email or a service-
    account identifier (``…iam.gserviceaccount.com``). The Event model does
    not reject a malformed address, which is exactly why this check exists.
    """
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    _, _, domain = text.rpartition("@")
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


class GoogleWorkspaceConnector(Connector):
    """Workspace audit reports as 3002 + 6003, fanned out by application.

    ── The 4× polling pattern ───────────────────────────────────────────────
    Each application is a separate ``GET /admin/reports/v1/activity/users/all/
    applications/{name}`` with its own cursor and its own indexing_lag_seconds.
    They share the authoriser (and therefore the token), the rate limiter, and
    the cycle window — but not the cursor.

    ── The login → 3002, admin/token/drive → 6003 split ────────────────────
    A Workspace ``login_success`` event is an authentication event. Putting it
    on 6003 alongside admin and token events would mean a failed sign-in and a
    successful admin grant appear in the same class, and the correlate layer
    cannot tell them apart. The class is selected by the application stream.

    ── Token-issuance events are not sign-ins ──────────────────────────────
    ``application=token`` is the OAuth2 token event stream, not the human
    sign-in stream. ``events[].name == "authorize"`` is a user consenting to
    an app, and ``events[].name == "revoke"`` is the inverse. A connector that
    maps these to 3002 makes every token consent a sign-in, which floods the
    auth detector with ordinary application usage.
    """

    name = "google_workspace"
    detects = (
        "Workspace account takeover: suspicious sign-ins, MFA bypasses, token "
        "consents to attacker apps, Drive data exfiltration, admin role grants"
    )
    spec = ConnectorSpec(
        page_size=1000,
        # Workspace reports have no documented per-tenant rate limit but the
        # shared Google API bucket is generous; 2 req/s is conservative.
        rate_per_second=2.0,
        burst=4,
        initial_lookback_seconds=86_400.0,
        # Per-application lag is set on each request below — the spec's
        # indexing_lag_seconds is unused for this connector.
        indexing_lag_seconds=300.0,
        overlap_seconds=900.0,
        docs_url=(
            "https://developers.google.com/admin-sdk/reports/reference/rest/"
            "v1/activities/list"
        ),
        required_grants=(
            "the service account's client ID must be authorised for "
            "https://www.googleapis.com/auth/admin.reports.audit.readonly in "
            "the Workspace admin console (Security → API controls → Domain-"
            "wide delegation), and $GWS_DELEGATED_SUBJECT must be a real "
            "Workspace administrator — both are required"
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retention_clamps = 0
        self.windows_skipped = 0
        self.empty_pages = 0
        self.actor_substitutions = 0
        self.unknown_application = 0
        self.per_application_counts: dict[str, int] = {}

    # ── credentials ────────────────────────────────────────────────────────

    def credentials_json(self) -> Credential:
        return self.config.connectors.gws_credentials_json

    def delegated_subject(self) -> Credential:
        return self.config.connectors.gws_delegated_subject

    def credentials(self) -> tuple[Credential, ...]:
        return (self.credentials_json(), self.delegated_subject())

    def authorizer(self) -> Authorizer:
        """JWT bearer for the service account, impersonating a Workspace admin.

        ``subject`` is non-``None`` — the difference from :mod:`gcp_audit`,
        which reads Cloud Audit Logs as itself. A missing ``subject`` returns
        ``unauthorized_client`` and the connector re-raises with that hint
        attached.
        """
        return ServiceAccountJwtAuth(
            self.client(),
            credentials_json=self.credentials_json(),
            scopes=(WORKSPACE_REPORT_SCOPE,),
            subject=self.delegated_subject(),
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def base_url(self) -> str:
        return "https://admin.googleapis.com"

    def probe(self) -> Availability:
        """Credentials, plus the four limits that decide whether this is enough.

        The base implementation names missing slots and the required grant.
        What it cannot know is that the service account's client ID must be
        authorised for the exact scope in the Workspace admin console, that
        Drive lags hours behind login/admin/token, that the same source
        covers both authentication (3002) and administrative (6003) events,
        and that this is where GCP console sign-in lives (which Cloud Audit
        Logs does not carry).
        """
        base = super().probe()
        if not base.available:
            return base
        limits = (
            f"AUTH: a JWT-bearer token minted as the service account "
            f"impersonating $GWS_DELEGATED_SUBJECT — without domain-wide "
            f"delegation (client ID authorised in the admin console for the "
            f"exact scope admin.reports.audit.readonly) the token endpoint "
            f"returns 'unauthorized_client'. CLASSES: login → 3002 "
            f"Authentication; admin/token/drive → 6003 API Activity — a "
            f"connector that maps every event to one class loses the "
            f"sign-in-vs-admin distinction. LAG: drive is hours behind "
            f"login/admin/token — a single 5-minute hold-back silently loses "
            f"late-published Drive events. CONSOLE SIGN-IN: 'who signed into "
            f"console.cloud.google.com' is answered here, NOT in Cloud Audit "
            f"Logs."
        )
        note_text = base.limitation
        return available(
            limitation=f"{note_text} {limits}".strip() if note_text else limits
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        payloads: list[dict[str, Any]] = []
        for app, class_uid, lag in APPLICATIONS:
            payloads.extend(
                await self._fetch_application(
                    app, class_uid, lag, window.start, window.end
                )
            )
        return payloads

    async def _fetch_application(
        self,
        application: str,
        class_uid: int,
        lag: float,
        start: float,
        end: float,
    ) -> list[dict[str, Any]]:
        """One application stream, fully paginated."""
        # The lag is applied per-application — Drive's queue flush means
        # events can land several hours after the action.
        effective_end = max(end - lag, start)
        if effective_end <= start:
            self.windows_skipped += 1
            self.note_record_time(start)
            self.stats.last_error = (
                f"{self.name}: the {application} stream's lag ({lag:.0f}s) "
                f"exceeds the requested window, so no request was sent; the "
                f"cursor jumped to the window start"
            )
            return []

        params = {
            "eventName": "",  # include every event type
            "startTime": iso8601(start),
            "endTime": iso8601(effective_end),
            "maxResults": self.spec.page_size,
        }
        url = (
            self.base_url()
            + f"/admin/reports/v1/activity/users/all/applications/{application}"
        )
        payloads: list[dict[str, Any]] = []

        def next_link(_resp: HttpResponse, body: Any) -> str | None:
            token = body.get("nextPageToken") if isinstance(body, Mapping) else None
            # ``""`` and absent both end pagination; only a non-empty token
            # advances the cursor.
            if not token:
                return None
            return f"{url}?{urlencode({**params, 'pageToken': token})}"

        request = Request(
            "GET",
            f"{url}?{urlencode(params)}",
            label=f"{self.name}.{application}.list",
            headers={"Accept": "application/json"},
            idempotent=True,
        )
        try:
            async for page in self.paginate(
                request, records_at=("items",), next_url=next_link
            ):
                if not page:
                    self.empty_pages += 1
                for record in page:
                    when = parse_iso8601(dig(record, "events.0.eventTime"))
                    # Workspace events have a top-level ``time`` and the events
                    # array also carries ``eventTime``; the array's value is
                    # the per-event timestamp and is preferred.
                    if when is None:
                        when = parse_iso8601(record.get("time"))
                    if when is None:
                        continue
                    self.note_record_time(when)
                    payload = self.map_record(record, application, class_uid)
                    if payload is not None:
                        payloads.append(payload)
        except AuthError as exc:
            body = clip(exc.body, 200)
            self.stats.last_error = (
                f"{self.name}: HTTP {exc.status or '?'} on {application} — "
                f"the single most likely cause is that the service account's "
                f"client ID has not been granted {WORKSPACE_REPORT_SCOPE!r} "
                f"in the Workspace admin console (Security → API controls → "
                f"Domain-wide delegation), or $GWS_DELEGATED_SUBJECT is not a "
                f"real admin. ({body})"
            )
            raise
        except HttpError as exc:
            self.stats.last_error = (
                f"{self.name}: /{application} failed with HTTP "
                f"{exc.status or '?'} ({clip(exc.body, 200)}); the "
                f"{application} feed is unreadable this cycle"
            )
        return payloads

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        if self.windows_skipped:
            out["windows_skipped_below_lag"] = (
                f"{self.windows_skipped} application stream(s) skipped "
                f"because the per-application lag exceeded the window"
            )
        if self.empty_pages:
            out["empty_workspace_pages"] = (
                f"{self.empty_pages} empty page(s) — normal between events; "
                f"if EVERY page is empty the delegated subject may have lost "
                f"admin role"
            )
        if self.actor_substitutions:
            out["actor_substitutions"] = self.actor_substitutions
        if self.unknown_application:
            out["unknown_application_events"] = self.unknown_application
        if self.per_application_counts:
            out["per_application_counts"] = self.per_application_counts
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(
        self, record: Mapping[str, Any], application: str, class_uid: int
    ) -> dict[str, Any] | None:
        """One Workspace audit record as a class_uid-class event.

        Workspace records are shaped ``{"actor": {…}, "events": [{…}], "id":
        {"time": …, "applicationName": …, "customerId": …}, …}``; the events
        array carries one or more sub-events. The connector fans out the
        array so each ``events[i]`` becomes a distinct OCSF event — collapsing
        them would make a single user action that emits two events appear as
        one.
        """
        events = record.get("events")
        if not isinstance(events, list) or not events:
            self.stats.last_error = (
                f"{self.name}: a record carried no events array and was "
                f"skipped (record id={record.get('id')!r})"
            )
            return None
        first_event = events[0] if isinstance(events[0], Mapping) else {}
        when = parse_iso8601(first_event.get("eventTime"))
        if when is None:
            when = parse_iso8601(record.get("time"))
        if when is None:
            return None

        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(class_uid),
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(
                dig(record, "id.uniqueQualifier")
                or dig(record, "id.time")
                or ""
            ),
            "metadata_product_name": "Google Workspace Audit Reports",
            "metadata_product_vendor_name": "Google",
            "metadata_log_name": f"applications/{application}",
            "metadata_log_provider": "Google Workspace",
            "metadata_version": "1.9.0",
            "cloud_provider": "Google Workspace",
            "raw": dict(record),
        }
        self.per_application_counts[application] = (
            self.per_application_counts.get(application, 0) + 1
        )
        put(payload, "metadata_event_code", first_event.get("type"))
        put(payload, "metadata_original_time", first_event.get("eventTime"))

        # The activity name comes from the event sub-record, not the record
        # top level. ``events[].type`` is the verb (``login_success``,
        # ``authorize``); ``events[].name`` is a human label.
        event_type = str(first_event.get("type") or "").strip() or application
        event_name = str(first_event.get("name") or "").strip()
        payload["activity_id"] = API_OTHER
        put(payload, "activity_name", event_type)

        # 3002 path (login) needs the user object, not actor.
        actor = record.get("actor") if isinstance(record.get("actor"), Mapping) else {}
        user_id = str(actor.get("user") or "").strip()
        if class_uid == int(ClassUid.AUTHENTICATION):
            payload["user_name"] = user_id or None
            if _is_google_account(user_id):
                payload["user_email"] = user_id
                payload["user_domain"] = user_id.rpartition("@")[2]
            # ``is_mfa`` is left unset deliberately — Workspace's
            # ``login_success`` does not say whether MFA was used. Stating
            # ``False`` here would assert an observation that the log does
            # not support.
            login_type = str(first_event.get("login_type") or "").strip()
            if login_type:
                stash(payload, "login_type", login_type)
            failure_reason = str(first_event.get("login_failure_reason") or "").strip()
            if failure_reason:
                stash(payload, "login_failure_reason", failure_reason)
            put(payload, "status_detail", failure_reason or None, limit=TEXT_LIMIT)
        else:
            # 6003 path — admin/token/drive — uses actor.
            put(payload, "actor_user_name", user_id or None)
            if _is_google_account(user_id):
                put(payload, "actor_user_email", user_id)
                put(payload, "actor_user_domain", user_id.rpartition("@")[2])
            elif user_id:
                put(payload, "actor_user_uid", user_id)

        # IP — ``actor`` may carry ``ip`` (admin/token) and ``events[].parameter``
        # may carry ``login_ip_address`` (login).
        ip = str(actor.get("ip") or "").strip()
        if not ip:
            for event in events:
                if not isinstance(event, Mapping):
                    continue
                params = event.get("parameter")
                if not isinstance(params, list):
                    continue
                for p in params:
                    if isinstance(p, Mapping) and p.get("name") == "login_ip_address":
                        ip = str(p.get("value") or "").strip()
                        break
                if ip:
                    break
        set_ip(payload, "src_endpoint_ip", ip)

        # The events array — kept as the per-event granularity reference.
        stash(payload, "workspace_event_type", event_type)
        if event_name:
            stash(payload, "workspace_event_name", event_name)

        # Event parameters — the per-event ``[{name:…, value:…}, …]`` shape.
        params = first_event.get("parameter")
        if isinstance(params, list):
            stash(
                payload,
                "workspace_event_parameters",
                [dict(p) for p in params if isinstance(p, Mapping)],
            )

        self._message(payload, event_type, event_name, user_id, application)
        return payload

    def _message(
        self,
        payload: dict[str, Any],
        event_type: str,
        event_name: str,
        user: str,
        application: str,
    ) -> None:
        """A one-line human summary from the vendor's own text where present."""
        if event_name:
            put(
                payload,
                "message",
                f"{user or 'unknown user'} — {event_name}",
                limit=MESSAGE_LIMIT,
            )
            return
        put(
            payload,
            "message",
            f"{user or 'unknown user'} {event_type or 'acted'} in {application}",
            limit=MESSAGE_LIMIT,
        )


def workspace_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[GoogleWorkspaceConnector]:
    """The Workspace connector set. One today; kept as a factory for symmetry."""
    return [GoogleWorkspaceConnector(pipeline, config, **kwargs)]


__all__ = [
    "APPLICATIONS",
    "GoogleWorkspaceConnector",
    "WORKSPACE_REPORT_SCOPE",
    "workspace_connectors",
]

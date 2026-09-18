"""Microsoft 365 — Office 365 Management Activity API (email + admin audit).

The single most important email-telemetry source for a SOC. Two distinct content
types live behind it:

* ``Audit.Exchange`` — every mail-flow event: messages sent, received, moved,
  deleted, and the security-relevant ones (inbox rules, forwarding, anti-phish
  matches). Maps to OCSF 4009 Email Activity.
* ``Audit.General`` — admin operations on Exchange Online, SharePoint, OneDrive
  and the rest of the M365 workload. Maps to OCSF 6003 API Activity.

The ``subscriptions/start`` step and the ``contentUri`` fetch are the two traps
that produce silent results rather than errors.

── ``subscriptions/start`` is idempotent, and "not started" reads as empty ────
Every audit content type must be subscribed to before blobs are published.
A tenant that was never started emits no logs *ever* — not for the past hour,
not for the past day, not for the past year. The connector calls
``POST /api/v1.0/management/subscriptions/start?contentType=Audit.Exchange``
on every cycle: it is documented to be a no-op when already started and to
start collecting going forward. There is no "list subscriptions I have" form,
so the connector does not assert that any subscription is on — only that
the start was accepted.

── ``NextPageUri`` is in the response HEADER, not the body ───────────────────
The body of ``/content`` is a JSON *array* with no cursor field. The cursor
lives in ``NextPageUri`` — a header of its own, not the standard ``Link``
header Okta uses, not the ``@odata.nextLink`` Azure Graph uses. A connector
that paginates by body or by ``Link`` finds exactly one page and reports a
clean cycle, which is the dangerous answer for a *pagination* failure.

── ``contentUri`` is a SAS URL on a *separate* host ─────────────────────────
Once the connector has a blob's metadata, it must GET ``contentUri`` to read
the actual events. The URL is on ``outlook.office.com`` or a tenant-specific
blob host, signed, and one-shot — fetching it twice returns 403 (the SAS is
spent). The two requests must be made on the same connector instance so the
authorised ``HttpClient`` carries the bearer header to both — the SAS URL
itself is pre-authorised, but the cycle still sends the header on every call
and the API does not refuse it.

── ``Audit.Exchange`` is admin-pinned, not user-pinned ──────────────────────
The Workload that emitted the event is on ``UserId`` (``NTUSER\…``, ``S-1-…``,
or ``admin@…``). The end-user mail account is not on the record; a connector
that assumes ``UserId`` is the victim maps the actor and the subject to the
same identity and the result reads as "user Alice ran cmdlet X" rather than
"admin ran cmdlet X against Alice's mailbox". ``actor_user_name`` carries the
emitter; the target user lives in ``unmapped.target_user_ids`` so the
correlate layer can join on it.

── Retention is up to 90 days for Audit.Exchange; 7 days is documented but not
enforced. An outage longer than the published retention is a permanent gap,
not a delayed read.

── Records arrive in *blobs*, and ``creationTime`` is per-blob, not per-event
The blob's ``creationTime`` is the time the publisher wrote the blob; events
inside it can be earlier. The connector keeps ``creationTime`` for the cursor
and uses ``CreationTime`` of the inner event for ``time`` — but if the inner
events have only ``CreationTime`` (millisecond resolution), a tight cycle has
to overlap.

The connector keeps the same authoriser as Entra (``OAuth2ClientCredentials``,
ARM-style audience) because the M365 Management API's audience is identical.
A single app registration can serve Entra, Defender and M365 — they share
the ``.default`` scope and the same OAuth2 mint.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, Severity, Status
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, OAuth2ClientCredentials, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    dig,
    first,
    iso8601,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import HttpError, HttpResponse, Request
from ingest.connectors.mapping import (
    API_CREATE,
    API_DELETE,
    API_OTHER,
    API_READ,
    API_UPDATE,
    MESSAGE_LIMIT,
    TEXT_LIMIT,
    attack,
    clip,
    crud_activity,
    label,
    note,
    put,
    resource_ref,
    stash,
)

#: OAuth2 scope suffix for the M365 Management Activity API.
ARM_SCOPE_SUFFIX = "/.default"

#: The content type that lands on 4009 Email Activity. ``Audit.General`` and the
#: others land on 6003.
EMAIL_CONTENT_TYPE = "Audit.Exchange"
GENERAL_CONTENT_TYPE = "Audit.General"

#: API version for the Management Activity API. Documented to be pinned; this
#: is the value every shipped script uses.
MANAGEMENT_API_VERSION = "2018-04-15"

#: Subscriptions endpoint — idempotent start.
SUBSCRIPTIONS_START_PATH = (
    "/api/v1.0/management/subscriptions/start"
)
SUBSCRIPTIONS_STOP_PATH = (
    "/api/v1.0/management/subscriptions/stop"
)

#: Content listing endpoint. Pagination via ``NextPageUri`` header.
CONTENT_PATH = (
    "/api/v1.0/management/accounts/{account}/activity/feed/audit/"
    "content?contentType={content_type}"
    "&startTime={start}&endTime={end}&pageSize={page_size}&publisherIdentifier={tenant}"
)

#: Retention for the Management Activity API — up to 90 days for Audit.Exchange.
EVENT_HISTORY_SECONDS = 90 * 86_400.0
RETENTION_MARGIN_SECONDS = 12 * 3_600.0

#: Audit.General operations that are real privilege escalations and worth
#: a technique label. Records that do not appear here are ordinary admin
#: traffic — the technique table is deliberately narrow.
_GENERAL_OPERATION_TECHNIQUES: Mapping[str, str] = {
    "add-mailboxpermission": "T1098",
    "set-mailboxautoconfiguremapping": "T1098",
    "set-inboxrule": "T1114.002",
    "new-inboxrule": "T1114.002",
    "set-mailboxmessageconfiguration": "T1114.002",
    "add-forwardingaddress": "T1114.003",
    "set-forwardingaddress": "T1114.003",
    "remove-forwardingaddress": "T1114.003",
    "remove-mailboxpermission": "T1098",
    "reset-redactionmobilitypolicy": "T1098",
    "set-organizationconfig": "T1562",
    "set-authenticationpolicy": "T1562",
    "set-adminsettings": "T1562",
}


def _looks_like_email(value: Any) -> bool:
    """Conservative enough that an SPN claim never lands in an email field.

    The M365 Management API does not validate email addresses on the wire;
    a connector that copies ``UserId`` straight to ``actor_user_email`` puts
    ``NTUSER\alice`` and ``S-1-5-…`` strings in an email field, and every
    downstream join on identity silently matches nothing.
    """
    text = str(value or "").strip()
    if "@" not in text or " " in text:
        return False
    _, _, domain = text.rpartition("@")
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _verb_from_operation(operation: str) -> tuple[int, str]:
    """``(api_verb, activity_name)`` from a ``Set-InboxRule``-style operation.

    Same tail-matching logic as the Azure connector — Exchange Online
    operations are shaped ``Verb-Noun``, and the verb is the terminal segment
    before the hyphen. ``activity_name`` is set unconditionally so a 99 never
    reaches the hard validator unnamed.
    """
    if not operation:
        return API_OTHER, "(unnamed)"
    name = str(operation).strip()
    head = name.split("-", 1)[0].lower() if name else ""
    mapping = {
        "new": API_CREATE, "add": API_CREATE, "create": API_CREATE,
        "install": API_CREATE, "register": API_CREATE,
        "get": API_READ, "search": API_READ, "find": API_READ,
        "list": API_READ, "fetch": API_READ,
        "set": API_UPDATE, "update": API_UPDATE, "enable": API_UPDATE,
        "disable": API_UPDATE, "change": API_UPDATE, "configure": API_UPDATE,
        "reset": API_UPDATE, "move": API_UPDATE, "rename": API_UPDATE,
        "remove": API_DELETE, "delete": API_DELETE, "disable": API_DELETE,
        "uninstall": API_DELETE, "deregister": API_DELETE,
    }
    verb = mapping.get(head, API_OTHER)
    return verb, name


class M365Connector(Connector):
    """Office 365 Management Activity API as 4009 Email + 6003 API Activity.

    ── Two content types, one authorizer, one cursor family ──────────────────
    Audit.Exchange lands on 4009 (every mail event, including inbox-rule and
    forwarding-rule changes), Audit.General lands on 6003 (every other admin
    operation in the M365 workload). Both are subscribed on every cycle and
    listed against the same window; the records inside each blob are routed by
    content type, not by blob.

    ── The blob is an array of records, and the cursor is the blob list ─────
    A single ``/content`` page returns zero or more blobs, each with its own
    ``contentUri``. The connector iterates the blob list (NextPageUri header),
    then iterates the records inside each blob — every blob's records are
    fetched exactly once because the SAS URL is one-shot, so a failed fetch is
    permanent for that blob.

    ── The two failure modes the connector handles differently ───────────────
    A ``start`` returning 401/403 is re-raised — the whole app registration is
    misconfigured and every cycle would fail. A single ``contentUri`` returning
    404 (SAS expired mid-cycle) is counted and skipped — the blob is gone and
    the next cycle will simply not see it. A ``/content`` 429 is retried by
    the API client; a tenant-wide 429 across both content types means the
    shared app's quota is saturated.
    """

    name = "m365"
    detects = (
        "M365 mail-flow attacks: inbox rules forwarding to attacker-controlled "
        "addresses, mailbox permission grants, anti-phish evasions, Exchange "
        "admin privilege escalation"
    )
    spec = ConnectorSpec(
        # ``pageSize`` is a query parameter for ``/content``; the documented
        # maximum is 200. Anything above is a documented 400.
        page_size=200,
        # The M365 Management API has no documented per-tenant request limit
        # but enforces a 60s ``Retry-After`` on bursts. 2 req/s leaves headroom
        # for parallel runs against the same tenant and is conservative.
        rate_per_second=2.0,
        burst=4,
        initial_lookback_seconds=86_400.0,
        # Blobs are usually available within a few seconds; a 5-minute holdback
        # is the conservative end.
        indexing_lag_seconds=300.0,
        overlap_seconds=900.0,
        docs_url=(
            "https://learn.microsoft.com/en-us/office/office-365-management-api/"
            "office-365-management-activity-api-reference"
        ),
        required_grants=(
            "the Office 365 Management API permission 'ActivityFeed.Read' on the "
            "app registration — the app must also be assigned 'View-Only Audit "
            "Logs' or 'Compliance Management' in Exchange Online, depending on "
            "the content type"
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retention_clamps = 0
        self.windows_skipped = 0
        self.subscriptions_started = 0
        self.blobs_fetched = 0
        self.blob_fetch_failures = 0
        self.empty_pages = 0
        self.exchange_records = 0
        self.general_records = 0
        self.actor_substitutions = 0

    # ── credentials ────────────────────────────────────────────────────────

    def tenant(self) -> Credential:
        return self.config.connectors.m365_tenant_id

    def client_id(self) -> Credential:
        return self.config.connectors.m365_client_id

    def client_secret(self) -> Credential:
        return self.config.connectors.m365_client_secret

    def credentials(self) -> tuple[Credential, ...]:
        return (self.tenant(), self.client_id(), self.client_secret())

    def authorizer(self) -> Authorizer:
        """Client credentials against M365 Management, same audience as Entra.

        ``.secret`` rather than ``.value``: an ``Authorizer`` is built by
        ``client()`` and described by the readiness report, both of which run
        on deployments where nothing is configured, and ``.value`` raises
        there by design.
        """
        tenant = self.tenant().secret or "TENANT-NOT-CONFIGURED"
        login = self.config.endpoints.microsoft_login.rstrip("/")
        return OAuth2ClientCredentials(
            self.client(),
            token_url=f"{login}/{tenant}/oauth2/v2.0/token",
            client_id=self.client_id(),
            client_secret=self.client_secret(),
            scope=self.config.endpoints.m365_management.rstrip("/") + ARM_SCOPE_SUFFIX,
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def base_url(self) -> str:
        return self.config.endpoints.m365_management.rstrip("/")

    def probe(self) -> Availability:
        """Credentials, plus the four limits that decide whether this is enough.

        The base implementation names missing slots and the required grant.
        What it cannot know is that Audit.Exchange is the only content type
        with email activity, that ``subscriptions/start`` must run before any
        data is published, and that ``contentUri`` is a one-shot SAS URL.
        """
        base = super().probe()
        if not base.available:
            return base
        limits = (
            f"CONTENT: Audit.Exchange → 4009 Email Activity (mail flow, inbox "
            f"rules, forwarding); Audit.General → 6003 API Activity (Exchange "
            f"admin, SharePoint, OneDrive). Both must be subscribed via "
            f"subscriptions/start before any blob is published; an unsubscribed "
            f"content type returns nothing forever, not 'no events yet'. "
            f"RETENTION: up to 90 days for Audit.Exchange; an outage longer "
            f"than that is a permanent gap, not a delayed read. CURSOR: "
            f"NextPageUri is a header of its own, NOT the body and NOT the "
            f"standard Link header — a connector that paginates by body sees "
            f"exactly one page. BLOB: contentUri is a one-shot SAS URL on a "
            f"separate host (outlook.office.com); fetching it twice returns "
            f"403, so a SAS failure mid-cycle is permanent for that blob."
        )
        note_text = base.limitation
        return available(
            limitation=f"{note_text} {limits}".strip() if note_text else limits
        )

    # ── the cycle ──────────────────────────────────────────────────────────

    def _retention_floor(self, window: TimeWindow) -> tuple[float, float]:
        """``(start to query, seconds of history lost to the 90-day horizon)``."""
        floor = self.clock() - (EVENT_HISTORY_SECONDS - RETENTION_MARGIN_SECONDS)
        if window.start >= floor:
            return window.start, 0.0
        return floor, floor - window.start

    def _next_link(self, _resp: HttpResponse, _body: Any) -> str | None:
        """``NextPageUri`` — header, not body, not Link.

        The cursor is the response's ``NextPageUri`` header. The body of the
        response is an array with no cursor field, and the standard ``Link``
        header (which Okta uses) is absent. A connector that returns None
        because the body has no cursor sees exactly one page.
        """
        return _resp.link("NextPageUri")

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, lost = self._retention_floor(window)
        if window.end <= start:
            # Wholly-past window: same shape as Azure/CloudTrail/GCP — a cursor
            # that far behind would walk the planner through 2,600 empty pages
            # before reaching live data. Jump to the floor.
            self.retention_clamps += 1
            self.windows_skipped += 1
            self.note_record_time(start)
            self.stats.last_error = (
                f"{self.name}: the whole requested window ended "
                f"{(start - window.end) / 86_400:.1f} days before the 90-day "
                f"Management API horizon, so none of it can be read and no "
                f"request was sent; the cursor jumped to the horizon"
            )
            return []

        # Ensure subscriptions are on. Idempotent and silent when already on.
        for content_type in (EMAIL_CONTENT_TYPE, GENERAL_CONTENT_TYPE):
            try:
                await self.client().send(
                    Request(
                        "POST",
                        self.base_url() + SUBSCRIPTIONS_START_PATH,
                        label=f"{self.name}.subscribe.{content_type}",
                        params={
                            "contentType": content_type,
                            "publisherIdentifier": self.tenant().secret,
                        },
                        headers={"Accept": "application/json"},
                        idempotent=True,
                    )
                )
                self.subscriptions_started += 1
            except HttpError as exc:
                self.stats.last_error = (
                    f"{self.name}: subscriptions/start for {content_type} "
                    f"returned HTTP {exc.status or '?'} ({clip(exc.body, 200)}); "
                    f"the {content_type} feed is not subscribed and no blob will "
                    f"ever be published"
                )
                # Do not raise: the other content type may still work, and a
                # refusal to start is recoverable by re-running with the right
                # permission assigned.

        payloads: list[dict[str, Any]] = []
        for content_type in (EMAIL_CONTENT_TYPE, GENERAL_CONTENT_TYPE):
            blobs_for_type = await self._list_blobs(content_type, start, window.end)
            for blob in blobs_for_type:
                uri = blob.get("contentUri")
                if not uri:
                    continue
                records = await self._fetch_blob(uri)
                for record in records:
                    self.note_record_time(parse_iso8601(record.get("CreationTime")))
                    mapped = self.map_record(record, content_type)
                    if mapped is not None:
                        payloads.append(mapped)
        if lost > 0:
            self.retention_clamps += 1
            message = (
                f"{self.name}: the requested window began {lost / 86_400:.1f} "
                f"days before the 90-day Management API horizon, so that much "
                f"history does not exist in this API and was never collected — "
                f"it is a permanent gap, not a delayed read"
            )
            self.stats.last_error = message
            if payloads:
                payloads[0].setdefault("notes", []).append(message)
        return payloads

    async def _list_blobs(
        self, content_type: str, start: float, end: float
    ) -> list[Mapping[str, Any]]:
        """The blob metadata list for one content type, fully paginated."""
        url = (
            self.base_url()
            + CONTENT_PATH.format(
                account="operations",
                content_type=content_type,
                start=iso8601(start),
                end=iso8601(end),
                page_size=self.spec.page_size,
                tenant=self.tenant().secret or "",
            )
            + f"&api-version={MANAGEMENT_API_VERSION}"
        )
        request = Request(
            "GET",
            url,
            label=f"{self.name}.list.{content_type}",
            headers={"Accept": "application/json"},
            idempotent=True,
        )
        blobs: list[Mapping[str, Any]] = []
        try:
            async for page in self.paginate(
                request, records_at=(), next_url=self._next_link
            ):
                if not page:
                    self.empty_pages += 1
                for blob in page:
                    if isinstance(blob, Mapping):
                        blobs.append(blob)
        except HttpError as exc:
            self.stats.last_error = (
                f"{self.name}: /content for {content_type} failed with HTTP "
                f"{exc.status or '?'} ({clip(exc.body, 200)}); the "
                f"{content_type} feed is unreadable this cycle and will be "
                f"re-read next cycle"
            )
        return blobs

    async def _fetch_blob(self, uri: str) -> list[Mapping[str, Any]]:
        """The records inside a single blob, fetched exactly once.

        ``contentUri`` is a one-shot SAS URL. A second fetch returns 403 (the
        SAS is spent), so the connector cannot retry on failure — the blob is
        gone. The error is counted and the cycle moves on; the operator sees
        ``blob_fetch_failures`` in stats_extra.
        """
        try:
            resp = await self.client().send(
                Request(
                    "GET",
                    uri,
                    label=f"{self.name}.blob",
                    headers={"Accept": "application/json"},
                    idempotent=True,
                )
            )
        except HttpError as exc:
            self.blob_fetch_failures += 1
            self.stats.last_error = (
                f"{self.name}: contentUri returned HTTP {exc.status or '?'}; "
                f"the SAS may have expired mid-cycle or the blob host may have "
                f"rotated ({clip(exc.body, 200)})"
            )
            return []
        self.blobs_fetched += 1
        body = resp.json()
        # The blob body is either a JSON array of records or a single record.
        if isinstance(body, list):
            return [r for r in body if isinstance(r, Mapping)]
        if isinstance(body, Mapping):
            return [body]
        return []

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        if self.retention_clamps:
            out["retention_clamps"] = (
                f"{self.retention_clamps} window(s) clamped to the 90-day "
                f"Management API horizon"
            )
        if self.windows_skipped:
            out["windows_skipped_below_horizon"] = (
                f"{self.windows_skipped} window(s) lay entirely before the "
                f"horizon and were not requested"
            )
        if self.subscriptions_started:
            out["subscriptions_started"] = (
                f"{self.subscriptions_started} subscriptions/start call(s) — "
                f"idempotent; runs every cycle because a missing subscription "
                f"is silent (no blobs are ever published)"
            )
        if self.blobs_fetched:
            out["blobs_fetched"] = self.blobs_fetched
        if self.blob_fetch_failures:
            out["blob_fetch_failures"] = (
                f"{self.blob_fetch_failures} blob(s) could not be fetched — "
                f"contentUri is a one-shot SAS, so these are permanently lost"
            )
        if self.empty_pages:
            out["empty_content_pages"] = (
                f"{self.empty_pages} /content page(s) carried no blobs — "
                f"normal between events; if EVERY page is empty for several "
                f"cycles the subscription is probably off"
            )
        if self.exchange_records:
            out["exchange_records"] = self.exchange_records
        if self.general_records:
            out["general_records"] = self.general_records
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(
        self, record: Mapping[str, Any], content_type: str
    ) -> dict[str, Any] | None:
        """One record as either 4009 Email Activity or 6003 API Activity."""
        when = parse_iso8601(record.get("CreationTime"))
        if when is None:
            self.stats.last_error = (
                f"{self.name}: a record arrived with no parseable CreationTime "
                f"(Id={record.get('Id')!r}) and was dropped rather than stamped "
                f"with the collection time"
            )
            return None
        if content_type == EMAIL_CONTENT_TYPE:
            return self._map_email(record, when)
        return self._map_admin(record, when)

    def _map_email(
        self, record: Mapping[str, Any], when: float
    ) -> dict[str, Any]:
        """An ``Audit.Exchange`` record as a 4009 Email Activity event.

        OCSF 4009 requires ``email`` (with ``from``/``to``/``subject``/``uid``)
        and ``actor``; the Management API's record carries ``Sender``,
        ``Recipients``, ``Subject``, ``InternetMessageId`` as the closest
        equivalents and ``UserId`` as the actor.
        """
        verb, name = _verb_from_operation(record.get("Operation"))
        sender = str(record.get("Sender") or "").strip()
        recipients_raw = record.get("Recipients")
        recipients: list[str] = []
        if isinstance(recipients_raw, list):
            recipients = [str(r).strip() for r in recipients_raw if r]
        subject = str(record.get("Subject") or "").strip()
        message_id = str(record.get("InternetMessageId") or "").strip()

        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(ClassUid.EMAIL_ACTIVITY),
            "activity_id": verb,
            "activity_name": name,
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(record.get("Id") or ""),
            "metadata_product_name": "Office 365 Management Activity API",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_log_name": "Audit.Exchange",
            "metadata_log_provider": "Microsoft 365",
            "metadata_version": "1.9.0",
            "cloud_provider": "Microsoft 365",
            "raw": dict(record),
        }
        self.exchange_records += 1
        put(payload, "metadata_event_code", record.get("Operation"))
        put(payload, "metadata_original_time", record.get("CreationTime"))

        # The email — OCSF 4009 requires the ``email`` object with at least a
        # ``uid`` (the message id) and a ``from`` / ``to`` pair.
        email: dict[str, Any] = {"uid": message_id}
        if sender and _looks_like_email(sender):
            email["from"] = sender
        if recipients:
            email["to"] = recipients
        if subject:
            email["subject"] = clip(subject, 998)
        payload["email"] = email

        self._actor(payload, record)
        self._source(payload, record)
        self._message(payload, name, sender, recipients, subject, record)
        return payload

    def _map_admin(
        self, record: Mapping[str, Any], when: float
    ) -> dict[str, Any]:
        """An ``Audit.General`` record as a 6003 API Activity event."""
        verb, name = _verb_from_operation(record.get("Operation"))
        payload: dict[str, Any] = {
            "time": when,
            "class_uid": int(ClassUid.API_ACTIVITY),
            "activity_id": verb,
            "activity_name": name,
            "severity_id": int(Severity.INFORMATIONAL),
            "metadata_uid": str(record.get("Id") or ""),
            "metadata_product_name": "Office 365 Management Activity API",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_log_name": record.get("RecordType") or "Audit.General",
            "metadata_log_provider": "Microsoft 365",
            "metadata_version": "1.9.0",
            "cloud_provider": "Microsoft 365",
            "raw": dict(record),
        }
        self.general_records += 1
        put(payload, "metadata_event_code", record.get("Operation"))
        put(payload, "metadata_original_time", record.get("CreationTime"))

        # status — Exchange admin operations mostly report Success / Fail in
        # ``ResultStatus``. The numeric value is unstable across workloads,
        # so the string is carried verbatim.
        status = str(record.get("ResultStatus") or "").strip()
        if status.lower() in ("succeeded", "success"):
            payload["status_id"] = int(Status.SUCCESS)
        elif status.lower() in ("failed", "failure", "error"):
            payload["status_id"] = int(Status.FAILURE)
        else:
            payload["status_id"] = int(Status.OTHER)
        put(payload, "status_code", status or None)

        self._actor(payload, record)
        self._source(payload, record)
        self._message(payload, name, None, None, None, record)

        # Technique labels on the privilege-relevant operations only.
        op = str(record.get("Operation") or "").strip().lower()
        technique = _GENERAL_OPERATION_TECHNIQUES.get(op)
        if technique:
            attack(payload, technique)
        return payload

    # ── mapping parts ──────────────────────────────────────────────────────

    def _actor(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """``UserId`` is the actor, not the target.

        On Audit.Exchange the actor is the *admin* that ran a cmdlet against a
        mailbox, not the mailbox's owner. On Audit.General the actor is the
        admin or the workload that ran the cmdlet. Putting ``UserId`` in
        ``user`` would collapse two identities into one — an audit trail that
        says "alice ran Set-InboxRule against alice's mailbox" is read as
        ordinary user activity rather than an admin impersonation.
        """
        user_id = str(record.get("UserId") or "").strip()
        if not user_id:
            self.actor_substitutions += 1
            put(payload, "actor_invoked_by", "Microsoft 365 platform")
            label(payload, "substitute_for:actor")
            note(
                payload,
                f"{self.name}: this record carries no UserId (admin actions "
                f"with no caller are unusual; the platform fills the required "
                f"actor under substitute_for:actor so the event satisfies its "
                f"class)",
            )
            return
        put(payload, "actor_user_name", user_id)
        if _looks_like_email(user_id):
            put(payload, "actor_user_email", user_id)
            put(payload, "actor_user_domain", user_id.rpartition("@")[2])
        else:
            # SIDs and ``NTUSER\…`` strings stay as ``uid`` — they are stable
            # identifiers, not addresses.
            put(payload, "actor_user_uid", user_id)

        # The user the operation was *about*, when one is named. Audit.Exchange
        # carries ``TargetUserOrGroupName`` on a few cmdlet records.
        target = str(record.get("TargetUserOrGroupName") or "").strip()
        if target:
            stash(payload, "target_user_or_group_name", target)
            label(payload, "m365:target-user-named")

        # Actor session — ``ClientIP`` on Audit.Exchange carries the actor's
        # IP, not the actor's session id. ``AppId`` and ``ClientAppId`` are
        # the workload identity when present.
        app_id = str(record.get("AppId") or "").strip()
        if app_id:
            stash(payload, "app_id", app_id)
            label(payload, "actor:service-principal")
        client_app_id = str(record.get("ClientAppId") or "").strip()
        if client_app_id:
            stash(payload, "client_app_id", client_app_id)

    def _source(
        self, payload: dict[str, Any], record: Mapping[str, Any]
    ) -> None:
        """``ClientIP`` (Audit.Exchange) / ``ClientInfoString`` (Audit.General).

        Audit.General omits the client IP entirely on most records; the
        ``src_endpoint`` object is filled with ``ClientInfoString`` under a
        substitute label rather than left unfilled, because 6003 *requires*
        ``src_endpoint``.
        """
        ip = str(record.get("ClientIP") or "").strip()
        if ip:
            set_ip(payload, "src_endpoint_ip", ip)
            return
        client_info = str(record.get("ClientInfoString") or "").strip()
        if client_info:
            put(payload, "src_endpoint_svc_name", client_info)
            label(payload, "substitute_for:src_endpoint")
            note(
                payload,
                f"{self.name}: no ClientIP — Audit.General rarely carries "
                f"the actor's address, so src_endpoint carries "
                f"ClientInfoString instead under substitute_for:src_endpoint",
            )
            return
        # Neither present — the platform fills the slot rather than let the
        # event fail its own class contract.
        self.actor_substitutions += 1
        put(payload, "src_endpoint_svc_name", "Microsoft 365 Management API")
        label(payload, "substitute_for:src_endpoint")

    def _message(
        self,
        payload: dict[str, Any],
        operation: str,
        sender: str | None,
        recipients: list[str] | None,
        subject: str | None,
        record: Mapping[str, Any],
    ) -> None:
        """A one-line human summary, preferring vendor text where present."""
        vendor = str(record.get("ItemName") or "").strip() or str(
            record.get("CmdletName") or ""
        ).strip()
        if vendor:
            put(payload, "message", vendor, limit=MESSAGE_LIMIT)
            return
        if subject and sender:
            composed = f"{sender} {operation or 'sent'} '{subject}'"
            if recipients:
                composed += f" -> {', '.join(recipients[:3])}"
                if len(recipients) > 3:
                    composed += f" +{len(recipients) - 3}"
            put(payload, "message", composed, limit=MESSAGE_LIMIT)
            return
        who = (
            payload.get("actor_user_name")
            or payload.get("actor_invoked_by")
            or "an unidentified principal"
        )
        target = str(record.get("TargetUserOrGroupName") or "").strip()
        composed = f"{who} {operation or 'acted'}"
        if target:
            composed += f" on {target}"
        put(payload, "message", composed, limit=MESSAGE_LIMIT)


def m365_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[M365Connector]:
    """The M365 connector set. One today; kept as a factory for symmetry."""
    return [M365Connector(pipeline, config, **kwargs)]


__all__ = [
    "CONTENT_PATH",
    "EMAIL_CONTENT_TYPE",
    "EVENT_HISTORY_SECONDS",
    "GENERAL_CONTENT_TYPE",
    "MANAGEMENT_API_VERSION",
    "RETENTION_MARGIN_SECONDS",
    "SUBSCRIPTIONS_START_PATH",
    "M365Connector",
    "m365_connectors",
]

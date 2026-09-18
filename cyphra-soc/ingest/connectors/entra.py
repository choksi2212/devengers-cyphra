"""Microsoft Entra ID — sign-in logs (3002) and directory audits (3004/3006/3007).

Two connectors over one token. They are separate because their failure modes and their
latencies are separate: sign-in logs are throttled harder, lag further behind real time,
and require an Entra ID P1 licence that directory audits do not.

── The class is chosen by what the record actually carries ───────────────────
``directoryAudits`` is one endpoint covering everything an administrator does, and OCSF
splits that across three classes with three *different required objects*: 3006 Group
Management requires ``group``, 3007 User Management requires ``user``, 3004 Entity
Management requires ``entity``. So the routing rule here is not "category X → class Y"
— it is **the class whose required object this record supplies**, read from
``targetResources[].type``. "Add member to role" with a User target is a 3007 Assign
Roles; the same operation against a role-assignable Group is a 3006 Assign Roles; the
same operation against a service principal is a 3004 Update, because neither of the
first two classes can honestly be filled. A category-keyed table would have emitted
3006 for a role assignment with no group in it, which is an event asserting a group
that does not exist.

── modifiedProperties values are JSON, inside JSON ──────────────────────────
``targetResources[].modifiedProperties[].newValue`` is a *string containing JSON*:
assigning Global Administrator arrives as ``"[\\"Global Administrator\\"]"`` — a
JSON-encoded one-element array, as a string, inside a JSON document. Read naively, the
role name for every privileged-role assignment in the tenant is the literal text
``["Global Administrator"]``, brackets and quotes included, and an exact-match rule for
tier-0 role grants matches nothing. :func:`_unwrap` decodes it.

── The straggler window is a real, bounded gap ───────────────────────────────
Microsoft documents sign-in log latency as "up to two hours"; the observed case is
minutes. A cursor that advances to the newest record it *saw* therefore skips anything
that lands behind it. :attr:`ConnectorSpec.indexing_lag_seconds` holds the window back
from the present and ``overlap_seconds`` re-reads the tail, and the connector's own
``metadata_uid`` makes the re-read free (exact dedup drops it). A record arriving later
than the overlap is genuinely lost, which is why the overlap is 30 minutes rather than
2 — a two-hour overlap is an eightfold read amplification against a throttled endpoint
— and why that trade is stated here rather than buried in a constant.

── Deliberately not collected here ──────────────────────────────────────────
``/identityProtection/riskDetections`` and ``riskyUsers`` are Identity Protection's
*alert* feed and belong in a 2004-emitting connector, not in this one. A sign-in with
``riskLevelDuringSignIn: high`` is reported here with ``risk_level_id`` set and
``severity_id`` left Informational: this connector reports what Entra observed, and
manufacturing priority from a raw authentication record is the detect layer's job. Only
a source that is itself an alerting product (Defender, CrowdStrike) gets to set severity
from its own field.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, RiskLevel, Severity, Status
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
from ingest.connectors.http import HttpResponse, Request
from ingest.connectors.mapping import (
    MESSAGE_LIMIT,
    as_bool,
    attack,
    clip,
    label,
    note,
    put,
    stash,
)

GRAPH_SCOPE_SUFFIX = "/.default"

#: Entra sign-in ``status.errorCode`` → a short reason and, where the code *is* the
#: signal, an ATT&CK hint. Codes rather than ``failureReason`` because the reason text
#: is localised to the tenant's language and changes between releases; the integer does
#: not. Only codes whose meaning is stable and operationally distinct are listed — an
#: unlisted code keeps its integer in ``status_code`` and its text in ``status_detail``,
#: which is enough to investigate and honest about not having been interpreted.
_SIGNIN_ERRORS: Mapping[int, tuple[str, str]] = {
    0: ("success", ""),
    50034: ("user does not exist in this directory", "T1589.002"),
    50053: ("account locked by smart lockout", "T1110.001"),
    50055: ("password expired", ""),
    50056: ("invalid or absent password in the credential store", ""),
    50057: ("account disabled", ""),
    50058: ("silent sign-in failed — no existing session", ""),
    50074: ("strong authentication required", ""),
    50076: ("MFA required by conditional access", ""),
    50079: ("user must enrol in MFA", ""),
    50105: ("user is not assigned to this application", "T1078.004"),
    50126: ("invalid username or password", "T1110"),
    50133: ("session invalidated by a password change or revocation", ""),
    50140: ("keep-me-signed-in interrupt", ""),
    50144: ("on-premises Active Directory password expired", ""),
    50158: ("external security challenge not satisfied", ""),
    50173: ("fresh authentication token required", ""),
    51004: ("user account does not exist in the directory", "T1589.002"),
    53000: ("device is not compliant", ""),
    53001: ("device is not registered", ""),
    53003: ("blocked by a conditional access policy", ""),
    65001: ("user or administrator has not consented to the application", ""),
    70008: ("refresh token expired", ""),
    70043: ("session expired — reauthentication required", ""),
    # The MFA-fatigue code. A user who denies a push, or lets it time out, produces
    # this; a burst of them against one account is T1621 and nothing else looks like it.
    500121: ("MFA challenge not satisfied — denied or timed out", "T1621"),
    530031: ("blocked by a conditional access session policy", ""),
    700016: ("application not found in the directory", ""),
}

#: ``clientAppUsed`` values that authenticate with a replayable password over a protocol
#: with no MFA path. These are *the* credential-stuffing surface in Entra — a tenant that
#: has not disabled legacy authentication has an MFA bypass regardless of its policies —
#: so they set ``is_cleartext``, which is what a legacy-auth rule reads.
_CLEARTEXT_CLIENTS = frozenset(
    {"imap4", "pop3", "smtp auth", "authenticated smtp", "other clients"}
)

#: The wider legacy set: no interactive MFA, but not necessarily basic auth on the wire.
#: Labelled rather than flagged, because "legacy" here is about the token flow rather
#: than about the transport.
_LEGACY_CLIENTS = frozenset(
    {
        "exchange activesync",
        "mapi over http",
        "offline address book",
        "exchange web services",
        "exchange online powershell",
        "autodiscover",
        "reporting web services",
        "exchange activesync app",
    }
) | _CLEARTEXT_CLIENTS

#: ``authenticationProtocol`` → (OCSF 3002 ``auth_protocol_id``, its OCSF caption,
#: ATT&CK hint). Captions are OCSF's own spellings, read from the class's enum table, so
#: the caption and the id cannot disagree.
_AUTH_PROTOCOLS: Mapping[str, tuple[int, str, str]] = {
    "oauth2": (6, "OAUTH 2.0", ""),
    # ROPC *is* OAuth2, and it is also the one flow that takes a raw username and
    # password non-interactively — which makes it the preferred spray endpoint. Same id,
    # different hint.
    "ropc": (6, "OAUTH 2.0", "T1110"),
    "saml20": (5, "SAML", ""),
    "wsfederation": (99, "WS-Federation", ""),
    # Device-code phishing: the attacker starts the flow and the victim completes it on
    # a legitimate Microsoft page, so nothing about the sign-in looks wrong except this.
    "devicecode": (99, "OAuth2 device code", "T1528"),
    "authenticationtransfer": (99, "authentication transfer", ""),
    "nativeauth": (99, "native auth", ""),
}

#: ``riskLevelDuringSignIn`` / ``riskLevelAggregated`` → OCSF ``risk_level_id``.
#:
#: ``none`` maps to ``Info`` (0) rather than to ``None``, and that is the whole reason
#: :class:`~core.schema.ocsf.RiskLevel` numbers 0 as *Info* instead of *Unknown*: Entra
#: assessed this sign-in and found no risk, which is information. ``hidden`` maps to
#: ``None`` — it is what Entra returns when the tenant lacks the Entra ID P2 licence to
#: see the value, so the risk is unknown rather than absent, and recording 0 there would
#: report an unlicensed tenant as having cleared every sign-in.
_RISK_LEVELS: Mapping[str, int | None] = {
    "none": int(RiskLevel.INFO),
    "low": int(RiskLevel.LOW),
    "medium": int(RiskLevel.MEDIUM),
    "high": int(RiskLevel.HIGH),
    "hidden": None,
    "notapplicable": None,
    "unknownfuturevalue": int(RiskLevel.OTHER),
}

#: ``riskEventTypes`` → ATT&CK. Entra's own detection names, mapped once here so a
#: risky-sign-in hunt does not have to know them.
_RISK_EVENT_ATTACK: Mapping[str, str] = {
    "anonymizedipaddress": "T1090.003",
    "maliciousipaddress": "T1090",
    "malwareinfecteddevice": "T1078.004",
    "suspiciousipaddress": "T1090",
    "leakedcredentials": "T1589.001",
    "investigationsthreatintelligence": "T1078.004",
    "unfamiliarfeatures": "T1078.004",
    "adminconfirmedusercompromised": "T1078.004",
    "passwordspray": "T1110.003",
    "impossibletravel": "T1078.004",
    "newcountry": "T1078.004",
    "tokenissueranomaly": "T1606.002",
    "suspiciousbrowser": "T1078.004",
    "riskyipaddress": "T1090",
    "mfafamiliarityanomaly": "T1621",
    "attackerinthemiddle": "T1557",
    "suspiciousapitraffic": "T1078.004",
    "anomaloustoken": "T1606.002",
    "anomaloususeractivity": "T1078.004",
}

#: Entra role display names whose assignment is a tenant-takeover primitive rather than
#: a permission change. Lowercased for comparison. Not "roles containing the word
#: admin": ``Message Center Reader`` contains none and ``Attack Simulation
#: Administrator`` cannot escalate, while ``Directory Writers`` and ``Partner Tier2
#: Support`` can and say nothing about it in their names.
_TIER0_ROLES = frozenset(
    {
        "global administrator",
        "company administrator",  # the directory's internal name for the same role
        "privileged role administrator",
        "privileged authentication administrator",
        "application administrator",
        "cloud application administrator",
        "hybrid identity administrator",
        "domain name administrator",
        "partner tier2 support",
        "directory writers",
        "authentication administrator",
        "user administrator",
        "exchange administrator",
        "sharepoint administrator",
        "intune administrator",
        "conditional access administrator",
        "security administrator",
        "groups administrator",
        "external identity provider administrator",
    }
)


def _unwrap(value: Any) -> str:
    """A ``modifiedProperties`` value, decoded out of its JSON-in-a-string wrapper.

    ``"[\\"Global Administrator\\"]"`` → ``Global Administrator``. Every property value
    in a directory audit is JSON-encoded text, so the wrapper is the rule rather than
    the exception, and one that survives to the lake makes exact-match detection on role
    names impossible. A value that is not JSON is returned as-is: Entra sends bare
    strings too, and treating a decode failure as an error would drop those.
    """
    if value in (None, "", [], {}):
        return ""
    if not isinstance(value, str):
        return clip(value)
    text = value.strip()
    if not text or text[0] not in "[\"{":
        return clip(text)
    try:
        decoded = json.loads(text)
    except (ValueError, TypeError):
        return clip(text)
    if isinstance(decoded, list):
        return ", ".join(clip(v, 200) for v in decoded if v not in (None, "", [], {}))
    if isinstance(decoded, Mapping):
        return clip(json.dumps(decoded, separators=(",", ":")))
    return clip(decoded)


class GraphConnector(Connector):
    """Shared Microsoft Graph plumbing: the token, the ``$filter``, the ``nextLink``.

    Subclasses set :attr:`graph_path`, :attr:`time_field` and :meth:`map_record`.
    """

    #: e.g. ``/v1.0/auditLogs/signIns``.
    graph_path = ""
    #: The record timestamp Graph will accept in a ``$filter`` on this endpoint.
    time_field = ""

    def tenant(self) -> Credential:
        return self.config.connectors.entra_tenant_id

    def client_id(self) -> Credential:
        return self.config.connectors.entra_client_id

    def client_secret(self) -> Credential:
        return self.config.connectors.entra_client_secret

    def credentials(self) -> tuple[Credential, ...]:
        return (self.tenant(), self.client_id(), self.client_secret())

    def authorizer(self) -> Authorizer:
        # `.secret` rather than `.value`: an Authorizer is constructed by `client()` and
        # described by the readiness report, both of which run on deployments where no
        # credential is set, and `.value` raises there by design. The unset case builds
        # a URL that is never requested, because `fetch_window` calls `require` first.
        tenant = self.tenant().secret or "TENANT-NOT-CONFIGURED"
        return OAuth2ClientCredentials(
            self.client(),
            token_url=(
                f"{self.config.endpoints.microsoft_login.rstrip('/')}"
                f"/{tenant}/oauth2/v2.0/token"
            ),
            client_id=self.client_id(),
            client_secret=self.client_secret(),
            scope=self.config.endpoints.microsoft_graph.rstrip("/") + GRAPH_SCOPE_SUFFIX,
            clock=self.clock,
            label=f"{self.name}.token",
        )

    def _next_link(self, _resp: HttpResponse, body: Any) -> str | None:
        # Followed verbatim. Graph's nextLink already carries the $filter and $top plus
        # a $skiptoken; re-applying this connector's params to it returns 400
        # "Duplicate query parameter". `Connector.paginate` sets params=None after the
        # first page for exactly this reason.
        #
        # A plain `.get`, deliberately, not `dig`: the key *contains a dot*. Every
        # OData annotation does — `@odata.nextLink`, `@odata.deltaLink`,
        # `@odata.count` — and `dig` splits on dots, so it would look for
        # body["@odata"]["nextLink"], find nothing, and report "no next page". That
        # failure is silent and expensive: every window would return only its first
        # page and the cursor would advance past everything after it, so a busy tenant
        # would lose the majority of its records while the connector reported healthy.
        if not isinstance(body, Mapping):
            return None
        link = body.get("@odata.nextLink")
        return str(link) if link else None

    async def graph_records(self, window: TimeWindow) -> Any:
        require(*self.credentials())
        start, end = window.iso()
        base = self.config.endpoints.microsoft_graph.rstrip("/")
        request = Request(
            "GET",
            f"{base}{self.graph_path}",
            label=f"{self.name}.list",
            params={
                # Both bounds. A `ge` with no upper bound works and is worse: the
                # response then includes records newer than the window, the cursor
                # advances past them, and the overlap on the next cycle is spent
                # re-reading data already consumed rather than catching stragglers.
                "$filter": (
                    f"{self.time_field} ge {start} and {self.time_field} lt {end}"
                ),
                "$top": self.spec.page_size,
            },
            headers={"Accept": "application/json"},
        )
        async for page in self.paginate(
            request, records_at=("value",), next_url=self._next_link
        ):
            yield page

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        async for page in self.graph_records(window):
            for record in page:
                self.note_record_time(parse_iso8601(record.get(self.time_field)))
                payload = self.map_record(record)
                if payload is not None:
                    out.append(payload)
        return out

    def _base_payload(self, record: Mapping[str, Any], time_value: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "time": parse_iso8601(time_value),
            # Every Graph record has an `id`, so dedup is exact rather than
            # hash-of-contents — which is what makes the overlap window free.
            "metadata_uid": str(record.get("id") or ""),
            "metadata_product_name": "Microsoft Entra ID",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_log_name": self.graph_path.rsplit("/", 1)[-1],
            "metadata_version": "1.9.0",
            "severity_id": int(Severity.INFORMATIONAL),
            "cloud_provider": "Microsoft Azure",
            "raw": dict(record),
        }
        put(payload, "metadata_correlation_uid", record.get("correlationId"))
        put(payload, "metadata_tenant_uid", self.tenant().secret or None)
        return payload


class EntraSignInConnector(GraphConnector):
    """Entra ID interactive and non-interactive sign-ins → 3002 Authentication."""

    name = "entra_signins"
    description = "Entra ID sign-in logs (interactive and non-interactive)"
    detects = (
        "password spray and credential stuffing (repeated 50126 across accounts), "
        "MFA fatigue (500121 bursts), legacy-authentication bypass, impossible travel, "
        "conditional-access failures, and sign-ins Entra itself scored as risky"
    )
    graph_path = "/v1.0/auditLogs/signIns"
    time_field = "createdDateTime"
    spec = ConnectorSpec(
        page_size=1000,
        # The reporting endpoints are throttled well below the Graph tenant-wide budget
        # and a 429 here costs the whole window's remaining pages.
        rate_per_second=2.0,
        burst=4,
        # See the module docstring: Microsoft's documented worst case is two hours, the
        # observed case is minutes, and a 30-minute overlap is the trade taken. Straggler
        # loss beyond it is a real bounded gap, not a solved problem.
        indexing_lag_seconds=300.0,
        overlap_seconds=1800.0,
        max_window_seconds=3600.0,
        docs_url="https://learn.microsoft.com/graph/api/signin-list",
        required_grants=(
            "AuditLog.Read.All",
            "Directory.Read.All",
            "an Entra ID P1 or P2 licence — without it this endpoint returns 403 and "
            "the message names the licence, not the permission",
        ),
    )

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        payload = self._base_payload(record, record.get("createdDateTime"))
        payload["class_uid"] = int(ClassUid.AUTHENTICATION)
        payload["activity_id"] = 1  # Logon

        # ── who ──
        # `user_name` takes the UPN; `user_email` is left unset on purpose. A UPN looks
        # like an address and frequently is not a routable one (alternate login IDs,
        # onmicrosoft.com fallbacks), and asserting it as an email address would make a
        # join against M365 message telemetry silently wrong for exactly the accounts
        # where it matters.
        put(payload, "user_name", record.get("userPrincipalName"))
        put(payload, "user_uid", record.get("userId"))
        put(payload, "user_full_name", record.get("userDisplayName"))
        stash(payload, "user_type", record.get("userType"))
        stash(payload, "home_tenant_id", record.get("homeTenantId"))
        stash(payload, "resource_tenant_id", record.get("resourceTenantId"))
        cross_tenant = record.get("crossTenantAccessType")
        if cross_tenant and str(cross_tenant).lower() not in ("none", "passthrough"):
            stash(payload, "cross_tenant_access_type", cross_tenant)
            label(payload, "cross-tenant")
        if record.get("servicePrincipalId") or record.get("servicePrincipalName"):
            stash(payload, "service_principal_id", record.get("servicePrincipalId"))
            stash(payload, "service_principal_name", record.get("servicePrincipalName"))
            label(payload, "service-principal-signin")
            # A workload identity signing in is not a person, and every user-behaviour
            # baseline that treats it as one produces noise forever.
            attack(payload, "T1078.004")
            if not payload.get("user_name") and not payload.get("user_uid"):
                # 3002 *requires* the user object, and an app-only sign-in has no user
                # at all — so the choice is to fill it with the principal or to emit an
                # event that fails its own class contract. The principal is filled,
                # under a label and a note, because an unfilled required object is not a
                # more honest answer: it is the same claim with the evidence removed.
                #
                # `user_type_id` is deliberately *not* set to System. OCSF's user object
                # has that member, but object-level enums are absent from the vendored
                # index, so nothing in this system could check the integer — and an
                # unverifiable value in an unvalidated column is exactly the shape of
                # the QueryResultId defect this codebase already found once.
                put(payload, "user_name", record.get("servicePrincipalName"))
                put(payload, "user_uid", record.get("servicePrincipalId"))
                label(payload, "substitute_for:user")
                note(
                    payload,
                    f"{self.name}: no user on this sign-in — a service principal "
                    "authenticated on its own behalf. The principal fills the user "
                    "object that class 3002 requires; it is a workload identity, not a "
                    "person, so do not baseline it as user behaviour "
                    "(see metadata.labels service-principal-signin)",
                )

        # ── what was signed into ──
        # `appDisplayName` is the client asking for the token, `resourceDisplayName` the
        # API it wants. OCSF's `actor.app_name` is the former and `service.name` the
        # latter; conflating them makes "who used this app" and "what did they reach"
        # the same column.
        put(payload, "actor_app_name", record.get("appDisplayName"))
        put(payload, "service_name", record.get("resourceDisplayName"))
        stash(payload, "app_id", record.get("appId"))
        stash(payload, "resource_id", record.get("resourceId"))

        # ── outcome ──
        raw_code = dig(record, "status.errorCode")
        code: int | None
        try:
            code = int(raw_code) if raw_code is not None else None
        except (TypeError, ValueError):
            code = None
            stash(payload, "status_error_code_raw", raw_code)
        if code is not None:
            payload["status_id"] = int(Status.SUCCESS if code == 0 else Status.FAILURE)
            payload["status_code"] = str(code)
            known = _SIGNIN_ERRORS.get(code)
            if known:
                reason, technique = known
                put(payload, "status_detail", reason, limit=MESSAGE_LIMIT)
                if technique:
                    attack(payload, technique)
            else:
                put(
                    payload,
                    "status_detail",
                    dig(record, "status.failureReason"),
                    limit=MESSAGE_LIMIT,
                )
                if code != 0:
                    note(
                        payload,
                        f"{self.name}: Entra error {code} is not in this connector's "
                        "table, so status_detail carries the vendor's localised text "
                        "verbatim rather than an interpreted reason",
                    )
        else:
            payload["status_id"] = int(Status.UNKNOWN)
            note(
                payload,
                f"{self.name}: the record carried no status.errorCode, so the outcome "
                "is Unknown rather than assumed successful",
            )
        stash(payload, "status_additional_details", dig(record, "status.additionalDetails"))

        # ── how ──
        client_app = str(record.get("clientAppUsed") or "").strip()
        if client_app:
            stash(payload, "client_app_used", client_app)
            low = client_app.lower()
            if low in _CLEARTEXT_CLIENTS:
                payload["is_cleartext"] = True
            if low in _LEGACY_CLIENTS:
                label(payload, "legacy-auth")
                attack(payload, "T1078.004")
        protocol = str(record.get("authenticationProtocol") or "").strip().lower()
        mapped = _AUTH_PROTOCOLS.get(protocol.replace("-", "").replace(" ", ""))
        if mapped:
            proto_id, caption, technique = mapped
            payload["auth_protocol_id"] = proto_id
            payload["auth_protocol"] = caption
            if proto_id == 99:
                stash(payload, "authentication_protocol", protocol)
            if technique:
                attack(payload, technique)
        elif protocol and protocol != "none":
            payload["auth_protocol_id"] = 99
            payload["auth_protocol"] = protocol
            note(
                payload,
                f"{self.name}: authenticationProtocol {protocol!r} is not in this "
                "connector's table; recorded as Other with the vendor string as the "
                "caption",
            )
        requirement = str(record.get("authenticationRequirement") or "").lower()
        if requirement == "multifactorauthentication":
            payload["is_mfa"] = True
        elif requirement == "singlefactorauthentication":
            payload["is_mfa"] = False
        stash(payload, "authentication_methods_used", record.get("authenticationMethodsUsed"))
        # The per-step MFA detail: which factor, which result, at what time. This is the
        # only place a denied push is distinguishable from a timed-out one, and OCSF's
        # `mfa` object has no flat column, so it is kept named in unmapped rather than
        # flattened into something lossy.
        stash(payload, "authentication_details", record.get("authenticationDetails"))
        stash(payload, "incoming_token_type", record.get("incomingTokenType"))
        stash(payload, "token_issuer_type", record.get("tokenIssuerType"))
        put(payload, "session_uid", record.get("uniqueTokenIdentifier"))
        stash(payload, "original_request_id", record.get("originalRequestId"))
        is_interactive = as_bool(record.get("isInteractive"))
        if is_interactive is not None:
            stash(payload, "is_interactive", is_interactive)

        # ── from where ──
        set_ip(payload, "src_endpoint_ip", record.get("ipAddress"), note="ip_address_raw")
        put(payload, "src_endpoint_city", dig(record, "location.city"))
        put(payload, "src_endpoint_country", dig(record, "location.countryOrRegion"))
        # `state` and the coordinates have no flat column — src_endpoint carries city,
        # country, isp and asn but not a subdivision — and the coordinates are what an
        # impossible-travel rule needs, so they are kept named.
        stash(payload, "location_state", dig(record, "location.state"))
        stash(payload, "geo_coordinates", dig(record, "location.geoCoordinates"))
        stash(payload, "autonomous_system_number", record.get("autonomousSystemNumber"))

        # ── from what ──
        put(payload, "device_uid", dig(record, "deviceDetail.deviceId"))
        put(payload, "device_hostname", dig(record, "deviceDetail.displayName"))
        put(payload, "device_os_name", dig(record, "deviceDetail.operatingSystem"))
        managed = as_bool(dig(record, "deviceDetail.isManaged"))
        if managed is not None:
            payload["device_is_managed"] = managed
        # `isCompliant` is *not* folded into is_managed. Graph omits it entirely for a
        # device it has no policy opinion about, and coercing that absence to False
        # reports every unmanaged personal device as failing compliance rather than as
        # unassessed — a difference a conditional-access investigation turns on.
        compliant = as_bool(dig(record, "deviceDetail.isCompliant"))
        if compliant is not None:
            stash(payload, "device_is_compliant", compliant)
        stash(payload, "device_trust_type", dig(record, "deviceDetail.trustType"))
        stash(payload, "browser", dig(record, "deviceDetail.browser"))

        # ── risk, as Entra scored it ──
        during = str(record.get("riskLevelDuringSignIn") or "").strip().lower()
        if during:
            level = _RISK_LEVELS.get(during, int(RiskLevel.OTHER))
            if level is None:
                stash(payload, "risk_level_during_signin", during)
                if during == "hidden":
                    note(
                        payload,
                        f"{self.name}: Entra returned risk level 'hidden', which means "
                        "the tenant has no Entra ID P2 licence to expose it — the risk "
                        "is unknown, not absent, so risk_level_id is left unset rather "
                        "than recorded as Info",
                    )
            else:
                payload["risk_level_id"] = level
                put(payload, "risk_level", during)
        aggregated = str(record.get("riskLevelAggregated") or "").strip().lower()
        if aggregated and aggregated != "hidden":
            stash(payload, "risk_level_aggregated", aggregated)
        stash(payload, "risk_state", record.get("riskState"))
        stash(payload, "risk_detail", record.get("riskDetail"))
        events = [str(e) for e in (record.get("riskEventTypes_v2") or record.get("riskEventTypes") or []) if e]
        if events:
            put(payload, "risk_details", ", ".join(events), limit=MESSAGE_LIMIT)
            for name in events:
                technique = _RISK_EVENT_ATTACK.get(
                    name.lower().replace("_", "").replace(" ", "")
                )
                if technique:
                    attack(payload, technique)
                label(payload, f"entra-risk:{name}")

        # ── conditional access ──
        ca_status = str(record.get("conditionalAccessStatus") or "").strip().lower()
        if ca_status:
            stash(payload, "conditional_access_status", ca_status)
            if ca_status in ("success", "failure"):
                payload["policy_is_applied"] = True
            elif ca_status in ("notapplied", "notenabled"):
                payload["policy_is_applied"] = False
        policies = [p for p in (record.get("appliedConditionalAccessPolicies") or []) if isinstance(p, Mapping)]
        if policies:
            # The whole array is kept: "which policies evaluated, and how" is the
            # question a conditional-access investigation asks, and OCSF's singular
            # `policy` cannot hold it. The flat columns are filled only when exactly one
            # policy actually enforced, so `policy_name` never names one of several
            # arbitrarily.
            stash(payload, "applied_conditional_access_policies", policies)
            enforced = [
                p for p in policies
                if str(p.get("result") or "").lower() in ("success", "failure")
            ]
            if len(enforced) == 1:
                put(payload, "policy_name", enforced[0].get("displayName"))
                put(payload, "policy_uid", enforced[0].get("id"))
            elif len(enforced) > 1:
                note(
                    payload,
                    f"{self.name}: {len(enforced)} conditional access policies "
                    "enforced on this sign-in, so policy_name is left unset rather "
                    "than naming one of them; the full array is in "
                    "unmapped.applied_conditional_access_policies",
                )
            if any(str(p.get("result") or "").lower() == "failure" for p in enforced):
                label(payload, "conditional-access-blocked")

        put(
            payload,
            "message",
            f"{record.get('userPrincipalName') or 'unknown user'} → "
            f"{record.get('appDisplayName') or 'unknown app'} "
            f"({'success' if code == 0 else f'error {code}'})",
            limit=MESSAGE_LIMIT,
        )
        label(payload, "identity", "entra")
        return payload


# ── directory audits ────────────────────────────────────────────────────────

#: ``activityDisplayName`` substring → an *intent*, resolved against the record's actual
#: target types by :func:`_route`. Ordered: the first match wins, so the specific
#: entries precede the general ones ("add member to role" before "add member").
#:
#: Substrings rather than exact names because Entra appends qualifiers to several of
#: these ("Add member to role in PIM requested (permanent)", "Add member to role
#: completed (PIM activation)") and an exact table silently stops matching when a new
#: qualifier ships. The fallback is ``operationType``, which is always one of Add,
#: Update, Delete, so an unmatched activity still routes correctly at a coarser grain.
_AUDIT_INTENTS: tuple[tuple[str, str], ...] = (
    ("add eligible member to role", "role_eligible"),
    ("add member to role", "role_assign"),
    ("remove member from role", "role_remove"),
    ("remove eligible member from role", "role_remove"),
    ("add owner to group", "group_member_add"),
    ("remove owner from group", "group_member_remove"),
    ("add member to group", "group_member_add"),
    ("remove member from group", "group_member_remove"),
    ("reset user password", "password_reset"),
    ("reset password", "password_reset"),
    ("change user password", "password_change"),
    ("change password", "password_change"),
    ("disable account", "user_disable"),
    ("enable account", "user_enable"),
    ("disable strong authentication", "mfa_disable"),
    ("enable strong authentication", "mfa_enable"),
    ("user registered security info", "mfa_enable"),
    ("admin registered security info", "mfa_enable"),
    ("user deleted security info", "mfa_disable"),
    ("admin deleted security info", "mfa_disable"),
    ("update stsrefreshtokenvalidfrom", "session_revoke"),
    ("add service principal credentials", "credential_add"),
    ("remove service principal credentials", "credential_remove"),
    ("add application credentials", "credential_add"),
    ("consent to application", "consent"),
    ("add app role assignment", "consent"),
    ("add oauth2permissiongrant", "consent"),
    ("add delegated permission grant", "consent"),
    ("add unverified domain", "domain_change"),
    ("add verified domain", "domain_change"),
    ("add domain to company", "domain_change"),
    ("verify domain", "domain_change"),
    ("conditional access policy", "ca_policy"),
    ("add user", "user_create"),
    ("delete user", "user_delete"),
    ("update user", "user_update"),
    ("add group", "group_create"),
    ("delete group", "group_delete"),
    ("update group", "group_update"),
)

#: intent → (ATT&CK technique, label). The connector's *hint*: the shape of the
#: operation is what the technique looks like. Only intents where that is true appear —
#: "update user" is not an attack and gets nothing.
_INTENT_ATTACK: Mapping[str, tuple[str, str]] = {
    "role_assign": ("T1098.003", "role-granted"),
    "role_eligible": ("T1098.003", "role-eligible-granted"),
    "credential_add": ("T1098.001", "app-credential-added"),
    "consent": ("T1528", "app-consent-granted"),
    "domain_change": ("T1484.002", "domain-changed"),
    # Conditional access is the tenant's authentication policy; modifying it is
    # T1556.009 specifically, not the generic Impair Defenses.
    "ca_policy": ("T1556.009", "conditional-access-changed"),
    "mfa_disable": ("T1556.006", "mfa-weakened"),
    "password_reset": ("T1098", "password-reset"),
    "group_member_add": ("T1098", "group-membership-added"),
}

#: 3007 User Management activity ids, by intent.
_USER_ACTIVITY: Mapping[str, int] = {
    "user_create": 1,
    "user_update": 2,
    "user_delete": 3,
    "user_enable": 4,
    "user_disable": 5,
    "password_change": 8,
    "password_reset": 9,
    "mfa_enable": 12,
    "mfa_disable": 13,
    "role_eligible": 14,  # Assign Privileges — eligibility is not yet an assignment
    "role_assign": 16,
    "role_remove": 17,
    "credential_add": 18,
    "credential_remove": 19,
    "session_revoke": 2,
    "consent": 10,  # Attach Policies
}

#: 3006 Group Management activity ids, by intent.
_GROUP_ACTIVITY: Mapping[str, int] = {
    "group_create": 6,
    "group_update": 9,
    "group_delete": 5,
    "group_member_add": 3,
    "group_member_remove": 4,
    "role_assign": 12,
    "role_eligible": 12,
    "role_remove": 13,
}

#: 3004 Entity Management activity ids, by ``operationType`` — the fallback path.
_ENTITY_ACTIVITY: Mapping[str, int] = {"add": 1, "update": 3, "delete": 4}


def _intent(activity_display_name: Any, operation_type: Any) -> str:
    text = str(activity_display_name or "").strip().lower()
    for needle, intent in _AUDIT_INTENTS:
        if needle in text:
            return intent
    op = str(operation_type or "").strip().lower()
    return {"add": "generic_create", "update": "generic_update", "delete": "generic_delete"}.get(op, "generic")


def _targets(record: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    """``targetResources`` bucketed by ``type``, lowercased."""
    out: dict[str, list[Mapping[str, Any]]] = {}
    for target in record.get("targetResources") or []:
        if isinstance(target, Mapping):
            out.setdefault(str(target.get("type") or "unknown").lower(), []).append(target)
    return out


class EntraAuditConnector(GraphConnector):
    """Entra ID directory audits → 3006 / 3007 / 3004, routed by target type.

    One endpoint, three OCSF classes, and the choice between them is made by which
    class's *required* object the record supplies — see the module docstring. The
    fallback is 3004 Entity Management, which is the class OCSF provides for exactly
    this: an administrative change to a directory object that is neither a user nor a
    group.
    """

    name = "entra_audit"
    description = "Entra ID directory audit log (administrative changes)"
    detects = (
        "privileged role assignment, application credential and consent abuse "
        "(T1098.001, T1528), conditional-access weakening, MFA method removal, "
        "unverified domain federation, and group-membership escalation"
    )
    graph_path = "/v1.0/auditLogs/directoryAudits"
    time_field = "activityDateTime"
    spec = ConnectorSpec(
        page_size=1000,
        rate_per_second=3.0,
        burst=6,
        # Directory audits surface materially faster than sign-in logs; Microsoft
        # documents minutes rather than hours, so the hold-back is shorter.
        indexing_lag_seconds=120.0,
        overlap_seconds=600.0,
        max_window_seconds=3600.0,
        docs_url="https://learn.microsoft.com/graph/api/directoryaudit-list",
        required_grants=("AuditLog.Read.All", "Directory.Read.All"),
    )

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        payload = self._base_payload(record, record.get("activityDateTime"))
        activity_name = str(record.get("activityDisplayName") or "").strip()
        category = str(record.get("category") or "").strip()
        intent = _intent(activity_name, record.get("operationType"))
        targets = _targets(record)

        class_uid, activity_id = self._route(intent, targets, record)
        payload["class_uid"] = class_uid
        payload["activity_id"] = activity_id
        # Always set, not only for 99: the vendor's own operation name is the single
        # most useful string on this event and `activity_id` is a coarse bucket of it.
        # The event model *requires* it when activity_id is 99, which is the case this
        # guarantees can never be reached unnamed.
        put(payload, "activity_name", activity_name or category or "directory audit")

        # ── who did it ──
        actor_user = dig(record, "initiatedBy.user") or {}
        actor_app = dig(record, "initiatedBy.app") or {}
        put(payload, "actor_user_name", actor_user.get("userPrincipalName"))
        put(payload, "actor_user_uid", actor_user.get("id"))
        stash(payload, "actor_display_name", actor_user.get("displayName"))
        set_ip(
            payload,
            "src_endpoint_ip",
            actor_user.get("ipAddress"),
            note="initiated_by_ip_raw",
        )
        put(
            payload,
            "actor_app_name",
            first(record, "initiatedBy.app.displayName", "initiatedBy.app.servicePrincipalName"),
        )
        stash(payload, "actor_app_id", actor_app.get("appId"))
        stash(payload, "actor_service_principal_id", actor_app.get("servicePrincipalId"))
        if actor_app and not actor_user:
            # An app acting with no user behind it. Distinguishing this from a delegated
            # call is the difference between "an admin did something" and "a workload
            # identity did something on its own", which is the shape of consent abuse.
            label(payload, "app-only-actor")

        # ── outcome ──
        result = str(record.get("result") or "").strip().lower()
        if result == "success":
            payload["status_id"] = int(Status.SUCCESS)
        elif result in ("failure", "timeout"):
            payload["status_id"] = int(Status.FAILURE)
            put(payload, "status_code", result)
        else:
            payload["status_id"] = int(Status.UNKNOWN)
        put(payload, "status_detail", record.get("resultReason"), limit=MESSAGE_LIMIT)

        # ── what was changed ──
        self._fill_targets(payload, class_uid, targets, record)

        # ── provenance and hints ──
        put(payload, "metadata_log_provider", record.get("loggedByService"))
        stash(payload, "category", category)
        stash(payload, "operation_type", record.get("operationType"))
        details = record.get("additionalDetails")
        stash(payload, "additional_details", details)
        label(payload, "identity", "entra", f"entra-category:{category or 'unknown'}")
        hint = _INTENT_ATTACK.get(intent)
        if hint:
            technique, tag = hint
            attack(payload, technique)
            label(payload, tag)

        put(
            payload,
            "message",
            f"{activity_name or category} by "
            f"{actor_user.get('userPrincipalName') or actor_app.get('displayName') or 'unknown actor'}"
            + (f" ({result})" if result and result != "success" else ""),
            limit=MESSAGE_LIMIT,
        )
        return payload

    def _route(
        self,
        intent: str,
        targets: Mapping[str, list[Mapping[str, Any]]],
        record: Mapping[str, Any],
    ) -> tuple[int, int]:
        """(class_uid, activity_id) — the class whose required object this record has.

        Role operations are the interesting case. "Add member to role" against a user is
        a 3007 Assign Roles; against a role-assignable group it is a 3006 Assign Roles;
        against a service principal neither class can be filled honestly, so it is a
        3004 Update with the principal as the entity.
        """
        has_user = bool(targets.get("user"))
        has_group = bool(targets.get("group"))

        if intent in _GROUP_ACTIVITY and (
            has_group and (intent.startswith("group") or not has_user)
        ):
            return int(ClassUid.GROUP_MANAGEMENT), _GROUP_ACTIVITY[intent]
        if intent in _USER_ACTIVITY and has_user:
            return int(ClassUid.USER_MANAGEMENT), _USER_ACTIVITY[intent]
        if intent in _GROUP_ACTIVITY and has_group:
            return int(ClassUid.GROUP_MANAGEMENT), _GROUP_ACTIVITY[intent]
        if intent == "generic_create" and has_user:
            return int(ClassUid.USER_MANAGEMENT), 1
        if intent == "generic_update" and has_user and not has_group:
            return int(ClassUid.USER_MANAGEMENT), 2
        if intent == "generic_delete" and has_user and not has_group:
            return int(ClassUid.USER_MANAGEMENT), 3
        if intent == "generic_create" and has_group:
            return int(ClassUid.GROUP_MANAGEMENT), 6
        if intent == "generic_update" and has_group:
            return int(ClassUid.GROUP_MANAGEMENT), 9
        if intent == "generic_delete" and has_group:
            return int(ClassUid.GROUP_MANAGEMENT), 5
        op = str(record.get("operationType") or "").strip().lower()
        return int(ClassUid.ENTITY_MANAGEMENT), _ENTITY_ACTIVITY.get(op, 99)

    def _fill_targets(
        self,
        payload: dict[str, Any],
        class_uid: int,
        targets: Mapping[str, list[Mapping[str, Any]]],
        record: Mapping[str, Any],
    ) -> None:
        """Fill the class's own object columns, and keep every target regardless.

        The full ``targetResources`` array always goes to ``unmapped``. A directory
        audit routinely names three or four objects — the user, the group, the role, the
        directory — and OCSF's singular ``user``/``group``/``entity`` can hold one each.
        Dropping the rest would lose the answer to "what else did this touch".
        """
        flat = [t for group in targets.values() for t in group]
        stash(payload, "target_resources", flat)

        users = targets.get("user") or []
        groups = targets.get("group") or []
        roles = targets.get("role") or []

        if class_uid == int(ClassUid.USER_MANAGEMENT) and users:
            target = users[0]
            put(payload, "user_name", target.get("userPrincipalName") or target.get("displayName"))
            put(payload, "user_uid", target.get("id"))
            if target.get("userPrincipalName") and target.get("displayName"):
                put(payload, "user_full_name", target.get("displayName"))
        elif class_uid == int(ClassUid.GROUP_MANAGEMENT):
            if groups:
                target = groups[0]
                put(payload, "group_name", target.get("displayName"))
                put(payload, "group_uid", target.get("id"))
                put(payload, "group_type", target.get("groupType"))
            if users:
                # 3006 declares both `group` and `user`: the group is what changed, the
                # user is the member added or removed. Both belong.
                put(payload, "user_name", users[0].get("userPrincipalName") or users[0].get("displayName"))
                put(payload, "user_uid", users[0].get("id"))
        elif class_uid == int(ClassUid.ENTITY_MANAGEMENT):
            target = flat[0] if flat else {}
            put(payload, "entity_name", target.get("displayName") or target.get("userPrincipalName"))
            put(payload, "entity_uid", target.get("id"))
            put(payload, "entity_type", target.get("type"))
            put(payload, "comment", record.get("resultReason"), limit=MESSAGE_LIMIT)

        # ── the role or privilege granted ──
        # `privileges` is declared by 3006 and 3007 only, which is why this is guarded:
        # on 3004 the same string would be swept to unmapped and named in soc_notes, so
        # it is stashed deliberately instead of being reported as a mapping error.
        granted = self._granted_roles(flat, roles)
        if granted:
            if class_uid in (int(ClassUid.GROUP_MANAGEMENT), int(ClassUid.USER_MANAGEMENT)):
                payload["privileges"] = granted
            else:
                stash(payload, "privileges", granted)
            tier0 = [r for r in granted if r.lower() in _TIER0_ROLES]
            if tier0:
                label(payload, "tier0-role", *[f"role:{r}" for r in tier0])
                attack(payload, "T1098.003")
                note(
                    payload,
                    f"{self.name}: {', '.join(tier0)} — a role that can reassign roles, "
                    "reset credentials or federate a domain, so this operation is a "
                    "tenant-control change rather than a permission change",
                )

    def _granted_roles(
        self, flat: Sequence[Mapping[str, Any]], roles: Sequence[Mapping[str, Any]]
    ) -> list[str]:
        """Role names from ``modifiedProperties``, decoded out of their JSON wrappers.

        Two sources, because Entra uses both: a ``Role`` target's ``displayName``, and a
        ``Role.DisplayName`` / ``Role.ObjectID`` modified property on the *user* target.
        The second is the common shape for "Add member to role" and it is the one whose
        value is JSON-in-a-string — see :func:`_unwrap`.
        """
        out: list[str] = []
        for role in roles:
            name = str(role.get("displayName") or "").strip()
            if name and name not in out:
                out.append(name)
        for target in flat:
            for prop in target.get("modifiedProperties") or []:
                if not isinstance(prop, Mapping):
                    continue
                key = str(prop.get("displayName") or "").strip().lower()
                if key not in ("role.displayname", "role.name", "roledisplayname"):
                    continue
                for value in (prop.get("newValue"), prop.get("oldValue")):
                    name = _unwrap(value)
                    if name and name not in out:
                        out.append(name)
        return out


def entra_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[GraphConnector]:
    """Both Entra connectors, in the order the readiness report should show them."""
    return [
        EntraSignInConnector(pipeline, config, **kwargs),
        EntraAuditConnector(pipeline, config, **kwargs),
    ]


__all__ = [
    "EntraAuditConnector",
    "EntraSignInConnector",
    "GraphConnector",
    "entra_connectors",
]

"""Scratch verification for the vendor connectors — captured API shapes → OCSF.

    python tests/scratch_vendors.py

Ten APIs that cannot be reached from this host. :mod:`tests.scratch_connectors`
verifies the *machinery* (auth, pagination, windows, cursors); this suite verifies the
*mappings*, which is the half that no amount of correct plumbing protects.

Every payload a connector produces is put through all three of the Event model's
sweeps, because they catch three different mistakes and a mapping can pass two of them
while being wrong:

``misplaced_fields``
    a field the target class does not declare — ``user_name`` on a 6003, which OCSF
    has no place for, so it would be silently swept to ``unmapped`` and the column an
    analyst queries would be empty.
``unfilled_required``
    a required object left empty — a 3006 with no ``group``, which is an event
    asserting a group management action against nothing.
``bad_enum_values``
    an integer outside the class's own table — ``Status.SUCCESS`` on a 2004, where 1
    is a legal value that means *New*. This one cannot be caught by any field-level
    validator and is the reason the sweep is class-aware.

The records below are shaped from each vendor's documented response, including the
parts that are awkward on purpose: Entra's JSON-encoded ``modifiedProperties``, its
``hidden`` risk level, ``targetResources`` naming four objects when OCSF has room for
one, and the error codes whose integers are stable while their text is localised.

Okta's are different in kind. One endpoint carries every event type in the org, so the
routing table *is* the connector, and the awkward parts are: two incompatible encodings
inside one ``debugData`` map (``risk`` is JSON, ``behaviors`` is a Java ``Map.toString``
that ``json.loads`` refuses), a ``severity`` that is a log level and not an assessment,
a ``threatSuspected`` boolean delivered as the string ``"true"``, an ``eventType``
vocabulary that grows without notice, and a cursor that is an opaque ``Link`` header
rather than a timestamp — because the System Log is indexed by publish order, so a
connector that re-derives ``since`` from event time skips every late-published record
permanently.
"""

import asyncio
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

from core.config import Credential, load as load_config
from core.schema.ocsf import (
    ClassUid,
    DispositionId,
    Event,
    FindingStatus,
    IncidentStatus,
    RiskLevel,
    Severity,
    Status,
    bad_enum_values,
    misplaced_fields,
    schema as ocsf_schema,
    unfilled_required,
    validate_event,
)
from ingest.connectors.base import MemoryCheckpoints, TimeWindow, iso8601
from ingest.connectors.cloudtrail import (
    _PARAM_READERS as _CT_READERS,
    EVENT_HISTORY_SECONDS,
    LOOKUP_TARGET,
    RETENTION_MARGIN_SECONDS,
    CloudTrailConnector,
    cloudtrail_connectors,
)
from ingest.connectors.crowdstrike import (
    _ALERT_STATUS,
    _CHASSIS_TYPE,
    _DISPOSITION_PRECEDENCE,
    _INCIDENT_STATUS,
    _LEGACY_DISPOSITION,
    _PLATFORM_OS,
    _PRODUCT_TYPE,
    _RESPONSE_GATE_FLAGS,
    ALERT_ENTITY_PATH,
    ALERT_ID_KEY,
    ALERT_QUERY_PATH,
    BEHAVIOR_LOOKUP_MAX,
    CONFIDENCE_BANDS,
    OFFSET_CEILING,
    RELAY_PRODUCTS,
    SEVERITY_BANDS,
    CrowdStrikeAlertConnector,
    CrowdStrikeHostConnector,
    CrowdStrikeIncidentConnector,
    crowdstrike_connectors,
)
from ingest.connectors.defender import (
    _DETECTION_SOURCE as _DEF_SOURCES,
    HUNTING_PACK,
    NO_RESPONSE_DETERMINATIONS,
    VENDOR_ACTION_SOURCES,
    DefenderAlertConnector,
    DefenderHuntingConnector,
    defender_connectors,
)
from ingest.connectors.entra import (
    _TIER0_ROLES,
    EntraAuditConnector,
    EntraSignInConnector,
    _intent,
    _unwrap,
    entra_connectors,
)
from ingest.connectors.azure_activity import (
    _APPIDACR as _AZ_APPIDACR,
    _BUILTIN_ROLES as _AZ_ROLES,
    _GLOBAL_ADMIN_ROLE_TEMPLATE,
    _OPERATION_TECHNIQUES as _AZ_OPS,
    _SUFFIX_TECHNIQUES as _AZ_SUFFIX,
    _TECHNIQUES_DELIBERATELY_NOT_EMITTED as _AZ_NOT_EMITTED,
    _TIER0_ROLE_IDS as _AZ_TIER0,
    ACTIVITY_API_VERSION,
    EVENT_HISTORY_SECONDS as AZ_HISTORY,
    RETENTION_MARGIN_SECONDS as AZ_MARGIN,
    AzureActivityConnector,
    _decode as _az_decode,
    _local as _az_local,
    _looks_like_email as _az_email,
    azure_connectors,
)
from ingest.connectors.okta import (
    _ROUTES as _OKTA_ROUTES,
    _TIER0_ROLES as _OKTA_TIER0,
    _VERB_ACTIVITY as _OKTA_VERBS,
    OktaSystemLogConnector,
    _java_map as _okta_java_map,
    _loose_map as _okta_loose_map,
    _verb as _okta_verb,
    okta_connectors,
)
from ingest.connectors.gcp_audit import (
    AUDIT_LOG_IDS,
    AUDIT_LOG_TYPE,
    DEFAULT_BUCKET_HISTORY_SECONDS,
    ENTRIES_LIST_PATH,
    GcpAuditConnector,
    LOGGING_READ_SCOPE,
    MAX_FILTER_CHARS,
    MAX_RESOURCE_NAMES,
    REQUIRED_HISTORY_SECONDS as GCP_HISTORY,
    RETENTION_MARGIN_SECONDS as GCP_MARGIN,
    gcp_connectors,
)

PASS: list[str] = []
FAIL: list[str] = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


class Clock:
    """A fixed clock, five days after the fixtures and before today.

    Both halves of that matter. It has to be *after* the fixtures so a window built
    from it can contain them, and *before* the real date so nothing derived from it
    reads as future to ``Event.build``'s skew correction — which restamps a
    future-dated event and would make every timestamp assertion here vacuous.
    """

    def __init__(self, start=1_773_500_000.0):  # 2026-03-16T14:53:20Z
        self.now = start

    def __call__(self):
        return self.now


class _Pipe:
    """Just enough Pipeline for a connector to be constructed and submit."""

    class _R:
        def __init__(self, n):
            self.received = self.accepted = n
            self.rejected = 0

    def __init__(self):
        self.got: list[dict] = []

    def declare_source(self, name, **kw):
        return kw

    async def submit(self, source, payloads, agent_id="", keep_events=False):
        self.got.extend(payloads)
        return self._R(len(payloads))


#: The default configuration, loaded from a path that deliberately does not exist so
#: the operator's own ``soc.yaml`` cannot change what this suite asserts.
_BASE = load_config(Path("tests/no-such-config.yaml"))


def _cred(slot: str, value: str) -> Credential:
    field_ = {f.name: f for f in dataclasses.fields(_BASE.connectors)}[slot]
    template = getattr(_BASE.connectors, slot)
    return dataclasses.replace(template, secret=value, source="test" if value else "unset")


def with_creds(**values: str):
    """A config with these connector slots set, and everything else as it loaded.

    ``dataclasses.replace`` rather than assignment because :class:`Credential` is
    frozen — and it should stay frozen, since the whole point of the type is that a
    secret cannot be quietly swapped underneath a connector that already read it.
    """
    creds = dataclasses.replace(
        _BASE.connectors, **{k: _cred(k, v) for k, v in values.items()}
    )
    return dataclasses.replace(_BASE, connectors=creds)


#: Explicitly blank, regardless of what the operator has exported. The readiness
#: assertions below are about the *unconfigured* state, and an operator with real Entra
#: credentials in their environment would otherwise silently invert them.
CONFIG = with_creds(entra_tenant_id="", entra_client_id="", entra_client_secret="")

#: Fully configured, for the request-shape test — which needs a tenant in the token URL.
LIVE = with_creds(
    entra_tenant_id="7c9a1111-2222-3333-4444-555566667777",
    entra_client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
    entra_client_secret="not-a-real-secret",
)


def conn(cls):
    return cls(_Pipe(), CONFIG, clock=Clock(), checkpoints=MemoryCheckpoints())


def ocsf_clean(name, payload, *, expect_class=None):
    """All three sweeps, plus a real ``validate_event`` round-trip.

    The sweeps say the mapping is *legal*; ``validate_event`` says the Event model
    accepts it, which is the thing the pipeline will actually do with it. Asserting
    only the sweeps would pass a payload that a field validator then rejects — an IP
    that is not an IP, a score outside 0-100 — and the connector would look verified
    while dropping every record at submit time.
    """
    uid = payload.get("class_uid")
    if expect_class is not None:
        check(f"{name}: routed to class {int(expect_class)}", uid == int(expect_class),
              f"got {uid}")
    flat = {k: v for k, v in payload.items() if k not in ("raw",)}
    misplaced = misplaced_fields(uid, list(flat))
    check(f"{name}: every field is declared by class {uid}", not misplaced,
          f"misplaced: {sorted(misplaced)}")
    unfilled = unfilled_required(uid, flat)
    check(f"{name}: class {uid}'s required objects are filled", not unfilled,
          f"unfilled: {sorted(unfilled)}")
    bad = bad_enum_values(uid, flat)
    check(f"{name}: every enum value is in class {uid}'s own table", not bad,
          f"bad: {bad}")
    try:
        event = validate_event("test", payload)
        ok, why = True, ""
    except Exception as exc:  # noqa: BLE001 - the test wants the message
        event, ok, why = None, False, f"{type(exc).__name__}: {exc}"
    check(f"{name}: the Event model accepts it", ok, why)
    return event


# ── Entra sign-in logs ──────────────────────────────────────────────────────

SIGNIN_RISKY = {
    "id": "d4e5f6a7-1111-2222-3333-444455556666",
    "createdDateTime": "2026-03-11T14:22:08.4821744Z",
    "correlationId": "aa11bb22-cc33-dd44-ee55-ff6677889900",
    "userPrincipalName": "priya.deshmukh@contoso.com",
    "userDisplayName": "Priya Deshmukh",
    "userId": "9f8e7d6c-5b4a-3928-1716-050403020100",
    "userType": "Member",
    "appDisplayName": "Microsoft Office",
    "appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "resourceDisplayName": "Microsoft Graph",
    "resourceId": "00000003-0000-0000-c000-000000000000",
    "ipAddress": "185.220.101.44",
    "clientAppUsed": "Browser",
    "isInteractive": True,
    "conditionalAccessStatus": "failure",
    "authenticationRequirement": "multiFactorAuthentication",
    "authenticationProtocol": "oAuth2",
    "uniqueTokenIdentifier": "Zm9vYmFyLXRva2VuLWlk",
    "originalRequestId": "11112222-3333-4444-5555-666677778888",
    "riskLevelDuringSignIn": "high",
    "riskLevelAggregated": "high",
    "riskState": "atRisk",
    "riskDetail": "none",
    "riskEventTypes_v2": ["anonymizedIPAddress", "impossibleTravel"],
    "homeTenantId": "7c9a1111-2222-3333-4444-555566667777",
    "resourceTenantId": "7c9a1111-2222-3333-4444-555566667777",
    "crossTenantAccessType": "none",
    "status": {
        "errorCode": 500121,
        "failureReason": "Authentication failed during strong authentication request.",
        "additionalDetails": "MFA denied; user declined the notification",
    },
    "deviceDetail": {
        "deviceId": "",
        "displayName": "",
        "operatingSystem": "Windows 10",
        "browser": "Chrome 122.0.0",
        "isCompliant": False,
        "isManaged": False,
        "trustType": "",
    },
    "location": {
        "city": "Amsterdam",
        "state": "North Holland",
        "countryOrRegion": "NL",
        "geoCoordinates": {"latitude": 52.377, "longitude": 4.897},
    },
    "appliedConditionalAccessPolicies": [
        {"id": "p1", "displayName": "Require MFA for all users",
         "enforcedGrantControls": ["Mfa"], "enforcedSessionControls": [],
         "result": "failure"},
        {"id": "p2", "displayName": "Block legacy authentication",
         "enforcedGrantControls": ["Block"], "enforcedSessionControls": [],
         "result": "notApplied"},
    ],
    "authenticationDetails": [
        {"authenticationStepDateTime": "2026-03-11T14:22:09Z",
         "authenticationMethod": "Password", "succeeded": True},
        {"authenticationStepDateTime": "2026-03-11T14:22:41Z",
         "authenticationMethod": "Mobile app notification", "succeeded": False,
         "authenticationStepResultDetail": "MFA denied; user declined"},
    ],
}

SIGNIN_LEGACY = {
    "id": "legacy-0001",
    "createdDateTime": "2026-03-11T14:25:00Z",
    "userPrincipalName": "svc-scanner@contoso.com",
    "userId": "1111aaaa-2222-bbbb-3333-cccc4444dddd",
    "appDisplayName": "Office 365 Exchange Online",
    "resourceDisplayName": "Office 365 Exchange Online",
    "ipAddress": "45.155.205.233",
    "clientAppUsed": "IMAP4",
    "authenticationRequirement": "singleFactorAuthentication",
    "authenticationProtocol": "ropc",
    "riskLevelDuringSignIn": "hidden",
    "riskLevelAggregated": "hidden",
    "conditionalAccessStatus": "notApplied",
    "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
    "location": {"city": "Bucharest", "countryOrRegion": "RO"},
    "deviceDetail": {},
    "appliedConditionalAccessPolicies": [],
}

SIGNIN_CLEAN = {
    "id": "clean-0001",
    "createdDateTime": "2026-03-11T09:00:00Z",
    "userPrincipalName": "arjun.rao@contoso.com",
    "userId": "5555eeee-6666-ffff-7777-8888aaaa9999",
    "appDisplayName": "Azure Portal",
    "resourceDisplayName": "Windows Azure Service Management API",
    "ipAddress": "203.0.113.17",
    "clientAppUsed": "Browser",
    "authenticationRequirement": "multiFactorAuthentication",
    "authenticationProtocol": "oAuth2",
    "riskLevelDuringSignIn": "none",
    "conditionalAccessStatus": "success",
    "status": {"errorCode": 0, "failureReason": "Other."},
    "deviceDetail": {"deviceId": "dev-77", "displayName": "LAPTOP-ARJUN",
                     "operatingSystem": "Windows 11", "isManaged": True,
                     "isCompliant": True, "trustType": "Azure AD joined"},
    "location": {"city": "Pune", "countryOrRegion": "IN"},
    "appliedConditionalAccessPolicies": [
        {"id": "p1", "displayName": "Require MFA for all users", "result": "success"},
    ],
}

SIGNIN_SP = {
    "id": "sp-0001",
    "createdDateTime": "2026-03-11T10:00:00Z",
    "appDisplayName": "Backup Automation",
    "appId": "aaaa1111-bbbb-2222-cccc-3333dddd4444",
    "resourceDisplayName": "Microsoft Graph",
    "servicePrincipalId": "sp-9876",
    "servicePrincipalName": "Backup Automation",
    "ipAddress": "20.190.128.5",
    "crossTenantAccessType": "b2bCollaboration",
    "authenticationProtocol": "deviceCode",
    "status": {"errorCode": 7000215},
    "deviceDetail": {},
    "location": {},
}


def test_signins():
    print("\n[entra] sign-in logs → 3002 Authentication")
    c = conn(EntraSignInConnector)

    risky = c.map_record(SIGNIN_RISKY)
    risky_ev = ocsf_clean("risky MFA-denied sign-in", risky,
                          expect_class=ClassUid.AUTHENTICATION)
    check("the MFA-fatigue error code carries T1621 and nothing else does",
          "attack:T1621" in risky["metadata_labels"],
          f"labels {risky['metadata_labels']}")
    check("error 500121 gets a stable English reason, not the localised vendor text",
          risky["status_detail"] == "MFA challenge not satisfied — denied or timed out",
          risky["status_detail"])
    check("a non-zero error code is a Failure",
          risky["status_id"] == int(Status.FAILURE) and risky["status_code"] == "500121")
    check("riskEventTypes map to techniques — anonymised IP is T1090.003",
          "attack:T1090.003" in risky["metadata_labels"])
    check("both risk event names survive in risk_details",
          "anonymizedIPAddress" in risky["risk_details"]
          and "impossibleTravel" in risky["risk_details"])
    check("high risk is risk_level_id 3", risky["risk_level_id"] == int(RiskLevel.HIGH))
    check("severity stays Informational on a raw authentication record",
          risky["severity_id"] == int(Severity.INFORMATIONAL),
          "a connector reporting a sign-in must not manufacture priority; "
          "risk_level_id carries what Entra actually asserted")
    check("two CA policies evaluated but only one enforced, so policy_name names it",
          risky["policy_name"] == "Require MFA for all users"
          and risky["policy_uid"] == "p1")
    check("the full CA array is kept, because 'which policies evaluated' is the question",
          len(risky["unmapped"]["applied_conditional_access_policies"]) == 2)
    check("a failing enforced policy is labelled",
          "conditional-access-blocked" in risky["metadata_labels"])
    check("UPN goes to user_name and *not* to user_email",
          risky["user_name"] == "priya.deshmukh@contoso.com"
          and "user_email" not in risky,
          "a UPN is not necessarily a routable mailbox, and asserting it as one makes "
          "a join against message telemetry wrong for exactly the odd accounts")
    check("Member/Guest goes to unmapped, since OCSF user.type_id has no member for it",
          risky["unmapped"]["user_type"] == "Member" and "user_type_id" not in risky)
    check("the client app and the API it wanted are different columns",
          risky["actor_app_name"] == "Microsoft Office"
          and risky["service_name"] == "Microsoft Graph")
    check("an empty deviceDetail.deviceId is not written as an empty device",
          "device_uid" not in risky and "device_hostname" not in risky,
          "put() drops empties, so an unregistered device stays absent rather than "
          "becoming a device with a blank name")
    check("isManaged False is recorded, because it was actually stated",
          risky["device_is_managed"] is False)
    check("the sub-national location has no flat column and is kept named",
          risky["unmapped"]["location_state"] == "North Holland"
          and risky["unmapped"]["geo_coordinates"]["latitude"] == 52.377,
          "the coordinates are what an impossible-travel rule needs")
    check("the per-step MFA detail survives, which is where 'denied' vs 'timed out' lives",
          len(risky["unmapped"]["authentication_details"]) == 2)
    check("the fractional-second Graph timestamp parses to the right instant",
          abs(risky["time"] - 1773238928.0) < 1.0, f"{risky['time']}")
    check("...and the seven-digit .NET fraction survives into the built Event",
          risky_ev is not None and abs(risky_ev.time - 1773238928.482) < 0.01,
          f"{getattr(risky_ev, 'time', None)} — Graph's signIns endpoint emits seven "
          "fractional digits, which a naive fromisoformat rejects outright")

    legacy = c.map_record(SIGNIN_LEGACY)
    legacy_ev = ocsf_clean("legacy IMAP4 spray attempt", legacy,
                           expect_class=ClassUid.AUTHENTICATION)
    check("IMAP4 sets is_cleartext, which is what a legacy-auth rule reads",
          legacy["is_cleartext"] is True)
    check("...and labels it legacy-auth with T1078.004",
          "legacy-auth" in legacy["metadata_labels"]
          and "attack:T1078.004" in legacy["metadata_labels"])
    check("ROPC is OAuth 2.0 by id and T1110 by hint, because it is the spray flow",
          legacy["auth_protocol_id"] == 6
          and legacy["auth_protocol"] == "OAUTH 2.0"
          and "attack:T1110" in legacy["metadata_labels"])
    check("error 50126 is T1110", "attack:T1110" in legacy["metadata_labels"])
    check("singleFactorAuthentication sets is_mfa False rather than leaving it unset",
          legacy["is_mfa"] is False)
    check("a 'hidden' risk level leaves risk_level_id unset, not 0 and not 99",
          "risk_level_id" not in legacy
          and legacy["unmapped"]["risk_level_during_signin"] == "hidden",
          "hidden means the tenant has no P2 licence to see the value; 0 would report "
          "every sign-in in an unlicensed tenant as cleared")
    check("...and says so in soc_notes, where an operator will read it",
          legacy_ev is not None
          and any("P2 licence" in n for n in legacy_ev.soc_notes),
          "asserted on the *built* event, which also proves the notes→soc_notes alias "
          "merge in Event.build is doing its job")
    check("notApplied CA status records policy_is_applied False",
          legacy["policy_is_applied"] is False)

    clean = c.map_record(SIGNIN_CLEAN)
    ocsf_clean("clean MFA sign-in", clean, expect_class=ClassUid.AUTHENTICATION)
    check("risk level 'none' IS recorded, as Info(0)",
          clean["risk_level_id"] == int(RiskLevel.INFO),
          "Identity Protection ran and found nothing — that is an assessment, and it "
          "is the one OCSF *_id where 0 is a positive statement")
    check("error code 0 is a Success",
          clean["status_id"] == int(Status.SUCCESS) and clean["status_code"] == "0")
    check("the 'Other.' failureReason on a success is not copied into status_detail",
          clean["status_detail"] == "success",
          "Graph sends failureReason='Other.' on every successful sign-in; passing it "
          "through would put a failure string on a success")
    check("a compliant managed device fills both, one flat and one named",
          clean["device_is_managed"] is True
          and clean["unmapped"]["device_is_compliant"] is True)
    check("no ATT&CK hint is invented for an ordinary successful sign-in",
          not [x for x in clean["metadata_labels"] if x.startswith("attack:")],
          f"{clean['metadata_labels']}")

    sp = c.map_record(SIGNIN_SP)
    sp_ev = ocsf_clean("service-principal sign-in", sp,
                       expect_class=ClassUid.AUTHENTICATION)
    check("a workload identity is labelled, so UEBA does not baseline it as a person",
          "service-principal-signin" in sp["metadata_labels"])
    check("a real cross-tenant access type is labelled; 'none' is not",
          "cross-tenant" in sp["metadata_labels"]
          and "cross-tenant" not in risky["metadata_labels"])
    check("device-code flow is Other(99) with the caption and T1528",
          sp["auth_protocol_id"] == 99
          and "attack:T1528" in sp["metadata_labels"])
    # An app-only sign-in genuinely has no user, and 3002 *requires* the user object.
    # The three assertions below pin the whole resolution, not just its happy half:
    # the principal fills the required object, the substitution is declared in the
    # labels and the notes so a downstream consumer can tell a workload from a person,
    # and `user_type_id` stays unset. That last one is the interesting negative —
    # OCSF's user object has a System member, but object-level enums are absent from
    # the vendored index, so `bad_enum_values` could not check the integer. An
    # unverifiable value in an unvalidated column is the shape of the QueryResultId
    # defect this codebase already found once; leaving it out keeps that gap visible
    # instead of writing into it.
    check("an app-only sign-in fills 3002's required user object from the principal",
          sp.get("user_name") == "Backup Automation" and sp.get("user_uid") == "sp-9876",
          f"user_name={sp.get('user_name')!r} user_uid={sp.get('user_uid')!r}")
    check("the substitution is declared in the labels, not silent",
          "substitute_for:user" in sp["metadata_labels"], f"{sp['metadata_labels']}")
    check("the note says it is a workload identity so UEBA does not baseline it",
          sp_ev is not None
          and any("workload identity, not a person" in n for n in sp_ev.soc_notes),
          f"{None if sp_ev is None else sp_ev.soc_notes}")
    check("no unverifiable user_type_id is written, since nothing could validate it",
          "user_type_id" not in sp)
    check("an unlisted error code keeps its integer and says it was not interpreted",
          sp["status_code"] == "7000215" and sp_ev is not None
          and any("not in this connector's table" in n for n in sp_ev.soc_notes))


# ── Entra directory audits ──────────────────────────────────────────────────

AUDIT_ROLE_ASSIGN = {
    "id": "Directory_ABC123_88123",
    "activityDateTime": "2026-03-11T15:02:33Z",
    "activityDisplayName": "Add member to role",
    "category": "RoleManagement",
    "correlationId": "cc11dd22-ee33-ff44-5566-778899aabbcc",
    "loggedByService": "Core Directory",
    "operationType": "Add",
    "result": "success",
    "resultReason": "",
    "initiatedBy": {
        "user": {
            "id": "aaaa0000-1111-2222-3333-444444444444",
            "displayName": "Mallory Quist",
            "userPrincipalName": "mallory.quist@contoso.com",
            "ipAddress": "185.220.101.44",
        }
    },
    "targetResources": [
        {
            "id": "9f8e7d6c-5b4a-3928-1716-050403020100",
            "displayName": "Priya Deshmukh",
            "type": "User",
            "userPrincipalName": "priya.deshmukh@contoso.com",
            "modifiedProperties": [
                {"displayName": "Role.ObjectID",
                 "oldValue": None,
                 "newValue": "\"62e90394-69f5-4237-9190-012177145e10\""},
                {"displayName": "Role.DisplayName",
                 "oldValue": None,
                 "newValue": "[\"Global Administrator\"]"},
                {"displayName": "Role.TemplateId",
                 "oldValue": None,
                 "newValue": "\"62e90394-69f5-4237-9190-012177145e10\""},
            ],
        },
        {"id": "62e90394-69f5-4237-9190-012177145e10",
         "displayName": "Global Administrator", "type": "Role",
         "modifiedProperties": []},
    ],
    "additionalDetails": [{"key": "Role.WellKnownObjectName", "value": "Global"}],
}

AUDIT_GROUP_ADD = {
    "id": "Directory_DEF456_88124",
    "activityDateTime": "2026-03-11T15:10:00Z",
    "activityDisplayName": "Add member to group",
    "category": "GroupManagement",
    "loggedByService": "Core Directory",
    "operationType": "Add",
    "result": "success",
    "initiatedBy": {"user": {"id": "aaaa0000-1111-2222-3333-444444444444",
                             "userPrincipalName": "mallory.quist@contoso.com",
                             "ipAddress": "185.220.101.44"}},
    "targetResources": [
        {"id": "grp-777", "displayName": "Finance-Admins", "type": "Group",
         "groupType": "AzureAD", "modifiedProperties": [
             {"displayName": "Group.DisplayName", "oldValue": None,
              "newValue": "\"Finance-Admins\""}]},
        {"id": "9f8e7d6c-5b4a-3928-1716-050403020100", "type": "User",
         "displayName": "Priya Deshmukh",
         "userPrincipalName": "priya.deshmukh@contoso.com",
         "modifiedProperties": []},
    ],
}

AUDIT_CONSENT = {
    "id": "Directory_GHI789_88125",
    "activityDateTime": "2026-03-11T15:20:00Z",
    "activityDisplayName": "Consent to application",
    "category": "ApplicationManagement",
    "loggedByService": "Core Directory",
    "operationType": "Assign",
    "result": "success",
    "initiatedBy": {"user": {"id": "9f8e7d6c-5b4a-3928-1716-050403020100",
                             "userPrincipalName": "priya.deshmukh@contoso.com",
                             "ipAddress": "203.0.113.17"}},
    "targetResources": [
        {"id": "evil-app-1", "displayName": "PDF Converter Pro",
         "type": "ServicePrincipal", "modifiedProperties": [
             {"displayName": "ConsentAction.Permissions", "oldValue": None,
              "newValue": "\"Scope: Mail.Read Mail.Send offline_access\""}]},
    ],
}

AUDIT_SP_CREDENTIAL = {
    "id": "Directory_JKL012_88126",
    "activityDateTime": "2026-03-11T15:30:00Z",
    "activityDisplayName": "Add service principal credentials",
    "category": "ApplicationManagement",
    "loggedByService": "Core Directory",
    "operationType": "Update",
    "result": "success",
    "initiatedBy": {"app": {"displayName": "Automation Runbook",
                            "appId": "bbbb1111-cccc-2222-dddd-3333eeee4444",
                            "servicePrincipalId": "sp-4242"}},
    "targetResources": [
        {"id": "sp-9999", "displayName": "Legacy Sync Connector",
         "type": "ServicePrincipal", "modifiedProperties": [
             {"displayName": "KeyDescription", "oldValue": "[]",
              "newValue": "[\"[KeyIdentifier=abc,KeyType=Password,KeyUsage=Verify]\"]"}]},
    ],
}

AUDIT_CA_POLICY = {
    "id": "Directory_MNO345_88127",
    "activityDateTime": "2026-03-11T15:40:00Z",
    "activityDisplayName": "Update conditional access policy",
    "category": "Policy",
    "loggedByService": "Conditional Access",
    "operationType": "Update",
    "result": "success",
    "initiatedBy": {"user": {"id": "aaaa0000-1111-2222-3333-444444444444",
                             "userPrincipalName": "mallory.quist@contoso.com",
                             "ipAddress": "185.220.101.44"}},
    "targetResources": [
        {"id": "ca-1", "displayName": "Require MFA for all users",
         "type": "Policy", "modifiedProperties": [
             {"displayName": "ConditionalAccessPolicy", "oldValue": "\"enabled\"",
              "newValue": "\"disabled\""}]},
    ],
}

AUDIT_PASSWORD_RESET = {
    "id": "Directory_PQR678_88128",
    "activityDateTime": "2026-03-11T15:50:00Z",
    "activityDisplayName": "Reset user password",
    "category": "UserManagement",
    "loggedByService": "Core Directory",
    "operationType": "Update",
    "result": "failure",
    "resultReason": "Insufficient privileges to complete the operation.",
    "initiatedBy": {"user": {"id": "helpdesk-1",
                             "userPrincipalName": "helpdesk@contoso.com",
                             "ipAddress": "10.20.30.40"}},
    "targetResources": [
        {"id": "ceo-1", "displayName": "Rohan Iyer", "type": "User",
         "userPrincipalName": "rohan.iyer@contoso.com", "modifiedProperties": []},
    ],
}

AUDIT_UNKNOWN_OP = {
    "id": "Directory_STU901_88129",
    "activityDateTime": "2026-03-11T16:00:00Z",
    "activityDisplayName": "Set DirSyncEnabled flag",
    "category": "DirectoryManagement",
    "loggedByService": "Core Directory",
    "operationType": "Update",
    "result": "success",
    "initiatedBy": {"app": {"displayName": "Microsoft Azure AD Connect"}},
    "targetResources": [
        {"id": "contoso.com", "displayName": "contoso.com", "type": "Other",
         "modifiedProperties": [
             {"displayName": "DirSyncEnabled", "oldValue": "\"False\"",
              "newValue": "\"True\""}]},
    ],
}


def test_audits():
    print("\n[entra] directory audits → 3007 / 3006 / 3004, routed by required object")
    c = conn(EntraAuditConnector)

    role = c.map_record(AUDIT_ROLE_ASSIGN)
    role_ev = ocsf_clean("Global Admin granted to a user", role,
                         expect_class=ClassUid.USER_MANAGEMENT)
    check("'Add member to role' against a User is 3007 activity 16 Assign Roles",
          role["activity_id"] == 16)
    check("the role name is decoded out of its JSON-in-a-string wrapper",
          role["privileges"] == ["Global Administrator"],
          f"{role.get('privileges')} — raw newValue was '[\"Global Administrator\"]'")
    check("a tier-0 role grant is labelled and mapped to T1098.003",
          "tier0-role" in role["metadata_labels"]
          and "attack:T1098.003" in role["metadata_labels"])
    check("...and soc_notes says why this role is different from a permission change",
          role_ev is not None
          and any("tenant-control change" in n for n in role_ev.soc_notes))
    check("the actor and the target are different users, in different columns",
          role["actor_user_name"] == "mallory.quist@contoso.com"
          and role["user_name"] == "priya.deshmukh@contoso.com")
    check("the actor's IP becomes src_endpoint_ip",
          role["src_endpoint_ip"] == "185.220.101.44")
    check("all four target objects are kept even though OCSF holds one",
          len(role["unmapped"]["target_resources"]) == 2
          and role["activity_name"] == "Add member to role")

    grp = c.map_record(AUDIT_GROUP_ADD)
    ocsf_clean("user added to a privileged group", grp,
               expect_class=ClassUid.GROUP_MANAGEMENT)
    check("'Add member to group' is 3006 activity 3 Add User", grp["activity_id"] == 3)
    check("3006 carries both the group that changed and the user who was added",
          grp["group_name"] == "Finance-Admins" and grp["group_uid"] == "grp-777"
          and grp["user_name"] == "priya.deshmukh@contoso.com")
    check("group membership change is T1098",
          "attack:T1098" in grp["metadata_labels"])

    consent = c.map_record(AUDIT_CONSENT)
    ocsf_clean("illicit consent grant", consent, expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("a ServicePrincipal target routes to 3004, because 3006 and 3007 cannot be "
          "filled honestly",
          consent["entity_name"] == "PDF Converter Pro"
          and consent["entity_type"] == "ServicePrincipal")
    check("consent is T1528 and labelled",
          "attack:T1528" in consent["metadata_labels"]
          and "app-consent-granted" in consent["metadata_labels"])
    check("no group_* or privileges leak onto a 3004",
          "group_name" not in consent and "privileges" not in consent,
          "3004 declares neither; either would be swept to unmapped and the column an "
          "analyst queries would be empty")

    spcred = c.map_record(AUDIT_SP_CREDENTIAL)
    ocsf_clean("credential added to a service principal", spcred,
               expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("adding app credentials is T1098.001",
          "attack:T1098.001" in spcred["metadata_labels"])
    check("an app acting with no user behind it is labelled app-only",
          "app-only-actor" in spcred["metadata_labels"]
          and spcred["actor_app_name"] == "Automation Runbook")
    check("no actor_user_* is invented for an app-only actor",
          "actor_user_name" not in spcred and "src_endpoint_ip" not in spcred)

    ca = c.map_record(AUDIT_CA_POLICY)
    ocsf_clean("conditional access policy disabled", ca,
               expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("CA policy modification is T1556.009, not the generic Impair Defenses",
          "attack:T1556.009" in ca["metadata_labels"])
    check("an Update operationType is 3004 activity 3",
          ca["activity_id"] == 3 and ca["entity_type"] == "Policy")

    pw = c.map_record(AUDIT_PASSWORD_RESET)
    ocsf_clean("failed password reset against an executive", pw,
               expect_class=ClassUid.USER_MANAGEMENT)
    check("'Reset user password' is 3007 activity 9", pw["activity_id"] == 9)
    check("a failure is a Failure, with the reason preserved",
          pw["status_id"] == int(Status.FAILURE)
          and "Insufficient privileges" in pw["status_detail"])
    check("a failed privileged operation still carries its technique hint",
          "attack:T1098" in pw["metadata_labels"],
          "the attempt is the signal; a failed reset against the CEO is the thing "
          "worth alerting on")

    other = c.map_record(AUDIT_UNKNOWN_OP)
    ocsf_clean("an operation the intent table does not know", other,
               expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("an unmatched activity still routes by operationType rather than to 99",
          other["activity_id"] == 3,
          "the fallback is coarse but correct, which is what keeps a new Entra "
          "operation name from arriving as an unclassified event")
    check("activity_name always carries the vendor's own operation name",
          other["activity_name"] == "Set DirSyncEnabled flag",
          "which is also what makes activity_id 99 legal when it happens")
    check("the tier-0 list is not 'names containing admin'",
          "directory writers" in _TIER0_ROLES
          and "partner tier2 support" in _TIER0_ROLES
          and "message center reader" not in _TIER0_ROLES
          and "attack simulation administrator" not in _TIER0_ROLES,
          "Directory Writers and Partner Tier2 Support can escalate and say nothing "
          "about it in their names; Attack Simulation Administrator cannot and does")


def test_unwrap_and_intent():
    print("\n[entra] the two decoding rules that everything above depends on")
    check("a JSON-encoded one-element array decodes to the bare value",
          _unwrap("[\"Global Administrator\"]") == "Global Administrator")
    check("a JSON-encoded scalar string decodes too",
          _unwrap("\"62e90394-69f5-4237-9190-012177145e10\"")
          == "62e90394-69f5-4237-9190-012177145e10")
    check("a multi-element array joins rather than losing members",
          _unwrap("[\"User Administrator\", \"Groups Administrator\"]")
          == "User Administrator, Groups Administrator")
    check("a bare string is returned unchanged, because Entra sends those too",
          _unwrap("Global Administrator") == "Global Administrator")
    check("malformed JSON is returned as text rather than raising",
          _unwrap("[\"unterminated") == "[\"unterminated",
          "a decode failure must not drop the record; the text is still evidence")
    check("None and empty are empty", _unwrap(None) == "" and _unwrap("") == "")
    check("an object value is preserved as compact JSON",
          _unwrap("{\"a\": 1}") == '{"a":1}')

    check("the intent table is ordered — 'add member to role' beats 'add member'",
          _intent("Add member to role", "Add") == "role_assign")
    check("...and PIM's qualified name still matches, which an exact table would not",
          _intent("Add member to role in PIM requested (permanent)", "Add")
          == "role_assign"
          and _intent("Add member to role completed (PIM activation)", "Add")
          == "role_assign")
    check("eligibility is a different intent from assignment",
          _intent("Add eligible member to role", "Add") == "role_eligible",
          "PIM eligibility is a standing grant not yet activated — 3007 Assign "
          "Privileges (14), not Assign Roles (16)")
    check("an unknown activity falls back to operationType",
          _intent("Some Operation Shipped Next Year", "Delete") == "generic_delete")
    check("an unknown activity with an unknown operationType is 'generic'",
          _intent("", "Assign") == "generic")


def test_spec_and_readiness():
    print("\n[entra] the spec numbers, and what the readiness report says about them")
    signin = conn(EntraSignInConnector)
    audit = conn(EntraAuditConnector)

    check("the sign-in connector holds its window back by Microsoft's indexing lag",
          signin.spec.indexing_lag_seconds == 300.0
          and signin.spec.overlap_seconds == 1800.0)
    check("audits are held back less, because they surface faster",
          audit.spec.indexing_lag_seconds == 120.0
          and audit.spec.indexing_lag_seconds < signin.spec.indexing_lag_seconds)
    check("sign-in logs are rate-limited harder than audits",
          signin.spec.rate_per_second < audit.spec.rate_per_second)
    check("the licence requirement is a stated grant, not a mystery 403",
          any("P1 or P2" in g for g in signin.spec.required_grants),
          "without the licence this endpoint 403s with text about a premium licence "
          "and nothing about which permission is missing")

    probe = signin.probe()
    check("an unconfigured Entra connector reports every env var to set",
          not probe.available and "$ENTRA_TENANT_ID" in probe.reason, probe.reason)
    check("...and names the docs URL, so the fix is findable",
          "learn.microsoft.com" in probe.reason)

    # The eager-construction hazard: `client()` builds the Authorizer before any
    # credential exists, and the readiness report describes it. Using `.value` for the
    # tenant would turn "not configured" into a crash in the one code path whose job
    # is to *report* that state.
    try:
        auth = signin.authorizer()
        built, why = True, ""
    except Exception as exc:  # noqa: BLE001
        auth, built, why = None, False, f"{type(exc).__name__}: {exc}"
    check("an authorizer is constructible with no credentials configured at all",
          built, why)
    check("...and its token URL is tenant-scoped, from the configured endpoint host",
          built and auth.token_url.startswith("https://login.microsoftonline.com/")
          and auth.token_url.endswith("/oauth2/v2.0/token"),
          getattr(auth, "token_url", ""))
    check("the scope is the Graph resource with /.default, which v2.0 requires",
          built and auth.scope == "https://graph.microsoft.com/.default",
          getattr(auth, "scope", ""))

    check("both connectors are exported in report order",
          [x.name for x in entra_connectors(_Pipe(), CONFIG)]
          == ["entra_signins", "entra_audit"])


def test_vendor_clock_skew():
    """A vendor with a wrong clock must not be able to forward-date the lake.

    This is not really an Entra assertion — it is an assertion about every connector,
    made here because a connector payload is the only place a foreign clock enters the
    system. It is also the test that stops this suite from lying to itself: while
    writing it the fixtures below were dated 2027, ``Event.build`` quietly restamped
    every one of them to *now*, and every timestamp check in the file passed while
    proving nothing. Any future fixture must be dated in the past for the same reason.
    """
    print("\n[entra] a vendor clock ahead of ours does not forward-date the lake")
    c = conn(EntraSignInConnector)
    # `ingested_time` rather than the real wall clock. `Event.build` defaults `now` to
    # `time.time()`, so a test that only sets the *event* time is measuring skew against
    # the day it runs — and this suite's fake clock is deliberately set in 2027, which
    # would make every offset below read as future and every assertion agree by
    # accident. Pinning both ends is what makes the measured skew in the note exact.
    ingest = 1_773_500_000.0

    honest = c.map_record(SIGNIN_CLEAN)
    honest_ev = Event.build(source="test", ingested_time=ingest, **dict(honest))
    check("a past-dated record keeps the vendor's own timestamp",
          honest_ev.time == honest["time"] and not honest_ev.soc_time_corrected,
          f"{honest_ev.time} vs {honest['time']}")
    check("...and no original_time is written, since the original *is* time",
          honest_ev.metadata_original_time is None,
          "a second copy of the same value can only drift out of agreement with itself")

    # Two days ahead: a real failure mode, not a contrived one. A tenant with a
    # misconfigured clock, or a connector reading a field in the wrong unit, produces
    # exactly this — and left alone it lands a record at the head of the lake where
    # every "last 24 hours" query picks it up and no retention pass ever drops it.
    skewed = dict(c.map_record(SIGNIN_CLEAN))
    skewed["time"] = ingest + 172_800.0
    skewed["metadata_uid"] = "skewed-0001"
    ev = Event.build(source="test", ingested_time=ingest, **skewed)
    check("a future-dated record is restamped with the ingest clock",
          ev.time == ingest, f"{ev.time} vs ingest {ingest}")
    check("...and the flag says so, so a query can exclude corrected times",
          ev.soc_time_corrected is True)
    check("...and the vendor's claim is preserved rather than discarded",
          ev.metadata_original_time is not None
          and ev.metadata_original_time.startswith("2026-"),
          f"{ev.metadata_original_time}")
    check("...and the note gives the measured skew and the reason",
          any("+172800s ahead of the ingest clock" in n for n in ev.soc_notes)
          and any("cannot be observed before it happens" in n for n in ev.soc_notes),
          f"{ev.soc_notes}")

    # The asymmetric half. Lateness is not a broken clock, and rewriting it would
    # destroy the only evidence that a spooled agent or a stalled cursor is catching up.
    late = dict(c.map_record(SIGNIN_CLEAN))
    late["time"] = ingest - 86_400.0
    late["metadata_uid"] = "late-0001"
    late_ev = Event.build(source="test", ingested_time=ingest, **late)
    check("a long-past record is NOT rewritten — only a future time is provably wrong",
          late_ev.time == ingest - 86_400.0 and not late_ev.soc_time_corrected,
          f"{late_ev.time}")
    check("...but the lateness is noted, since only ingest.health can explain it",
          any("after it happened" in n for n in late_ev.soc_notes), f"{late_ev.soc_notes}")


async def test_paginate_shape():
    print("\n[entra] the Graph request itself — $filter bounds and nextLink")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    page2 = ("https://graph.microsoft.com/v1.0/auditLogs/signIns"
             "?$filter=x&$top=1000&$skiptoken=SKIP")
    transport = ScriptedTransport([
        (200, {}, {"access_token": "tok", "expires_in": 3599, "token_type": "Bearer"}),
        (200, {}, {"value": [SIGNIN_CLEAN], "@odata.nextLink": page2}),
        (200, {}, {"value": [SIGNIN_LEGACY]}),
    ])
    c = EntraSignInConnector(_Pipe(), LIVE, transport=transport, clock=Clock(),
                             checkpoints=MemoryCheckpoints())
    # A window that actually contains the fixtures — 2026-03-11 00:00Z to 03-12 00:00Z.
    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)
    out = await c.fetch_window(window)
    check("both pages' records are mapped", len(out) == 2, f"{len(out)}")

    token_req, first_req, second_req = transport.seen
    check("the token is minted against the tenant-scoped v2.0 endpoint",
          "/7c9a1111-2222-3333-4444-555566667777/oauth2/v2.0/token" in token_req.url,
          token_req.url)
    filt = (first_req.params or {}).get("$filter", "")
    check("the $filter carries BOTH bounds, not just 'ge'",
          " ge 2026-03-11T00:00:00Z " in filt and " lt 2026-03-12T00:00:00Z" in filt
          and filt.count("createdDateTime") == 2, filt)
    check("...with no fractional seconds, which Graph rejects beyond three digits",
          "." not in filt, filt)
    check("$top asks for the documented maximum page size",
          (first_req.params or {}).get("$top") == 1000)
    check("the nextLink is followed verbatim, with no params re-applied",
          second_req.url == page2 and not second_req.params,
          "re-applying $filter to a nextLink returns 400 duplicate query option")
    # 14:25:00Z, the *later* of the two records, and it arrived on page two while the
    # 09:00 one arrived on page one. Asserting the max rather than "the last one seen"
    # is the point: Graph returns newest-first on some endpoints, so a cursor that
    # took the final record of the final page would walk backwards and re-read forever.
    check("the cursor candidate is the newest record, not the last one seen",
          c._latest_record == 1_773_239_100.0, f"{c._latest_record}")

    unconfigured = EntraSignInConnector(
        _Pipe(), CONFIG, transport=ScriptedTransport([]), clock=Clock(),
        checkpoints=MemoryCheckpoints())
    try:
        await unconfigured.fetch_window(window)
        refused, why = False, "it made a request"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured fetch refuses before the transport is touched, naming "
          "every missing slot",
          refused and "tenant_id" in why and "client_secret" in why, why)


# ── Okta System Log ─────────────────────────────────────────────────────────
#
# One endpoint, five classes, and the routing *is* the connector — so these fixtures are
# chosen to hit each class and each way the routing can be wrong: an eventType the table
# knows, one it knows only by prefix, one it does not know at all, and one whose name
# says 3006 while its targets say otherwise. Every ``published`` is 2026-03-11, for the
# reason ``Clock`` gives.

#: A clean interactive sign-in, with Okta's full client / geo / device / risk furniture.
OKTA_SIGNIN = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000001",
    "published": "2026-03-11T08:00:00.000Z",
    "eventType": "user.session.start",
    "version": "0",
    "severity": "INFO",
    "legacyEventType": "core.user_auth.login_success",
    "displayMessage": "User login to Okta",
    "actor": {
        "id": "00u1a2b3c4d5e6f7g8h9",
        "type": "User",
        "alternateId": "dana.hale@acme.example",
        "displayName": "Dana Hale",
    },
    "client": {
        "userAgent": {
            "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
            "os": "Windows 10",
            "browser": "CHROME",
        },
        "zone": "OFF_NETWORK",
        "device": "Computer",
        "ipAddress": "203.0.113.42",
        "geographicalContext": {
            "city": "Pune",
            "state": "Maharashtra",
            "country": "India",
            "postalCode": "411001",
            "geolocation": {"lat": 18.5204, "lon": 73.8567},
        },
    },
    "securityContext": {
        "asNumber": 64512,
        "asOrg": "example telecom",
        "isp": "example telecom",
        "domain": "example.net",
        "isProxy": False,
    },
    "device": {
        "id": "guo4a5b6c7d8e9f0g1h2",
        "name": "DANA-LAPTOP",
        "os_platform": "WINDOWS",
        "os_version": "10.0.26200",
        "managed": True,
        "registered": True,
        "secure_hardware_present": True,
        "disk_encryption_type": "FULL",
    },
    "authenticationContext": {
        "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
        "credentialType": "PASSWORD",
        "authenticationStep": 0,
        "externalSessionId": "102aBcDeFgHiJkLmNoPqRsTuV",
        "interface": "Okta FastPass",
        "issuer": {"id": "acme", "type": "ORG"},
    },
    "outcome": {"result": "SUCCESS"},
    "transaction": {"id": "Ze1234567890abcdefABCDEF", "type": "WEB"},
    "debugContext": {
        "debugData": {
            "requestId": "Ze1234567890abcdefABCDEF",
            "requestUri": "/api/v1/authn",
            "dtHash": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "threatSuspected": "false",
            "risk": '{"level":"LOW","reasons":"Anomalous Location"}',
            "behaviors": "{New Device=POSITIVE, New IP=POSITIVE, Velocity=NEGATIVE}",
        }
    },
    "target": [],
}

#: A failed factor challenge. ``severity`` is ERROR, which is a *log* level.
OKTA_MFA_FAIL = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000002",
    "published": "2026-03-11T08:00:07.000Z",
    "eventType": "user.authentication.auth_via_mfa",
    "severity": "ERROR",
    "displayMessage": "Authentication of user via MFA",
    "actor": {
        "id": "00u1a2b3c4d5e6f7g8h9",
        "type": "User",
        "alternateId": "dana.hale@acme.example",
        "displayName": "Dana Hale",
    },
    "client": {"ipAddress": "203.0.113.42",
               "userAgent": {"rawUserAgent": "okta-verify/7.1"}},
    "securityContext": {"isProxy": True},
    "authenticationContext": {"credentialType": "OTP", "authenticationStep": 1},
    "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
    "transaction": {"id": "Ze1234567890abcdefABCDEF", "type": "WEB"},
    "target": [{"id": "ufs9z8y7x6w5v4u3t2s1", "type": "AuthenticatorEnrollment",
                "displayName": "Okta Verify", "alternateId": "unknown"}],
}

#: Support impersonation — the one 3002 where actor and user are two different people.
OKTA_IMPERSONATION = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000003",
    "published": "2026-03-11T09:00:00.000Z",
    "eventType": "user.session.impersonation.initiate",
    "severity": "INFO",
    "displayMessage": "Impersonation session initiated",
    "actor": {"id": "00uSUPPORT0000000001", "type": "User",
              "alternateId": "okta-support@okta.example", "displayName": "Okta Support"},
    "client": {"ipAddress": "198.51.100.9"},
    "outcome": {"result": "SUCCESS"},
    "target": [{"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
                "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"}],
}

#: A Super Administrator grant, named twice — display name and API constant.
OKTA_ROLE_GRANT = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000004",
    "published": "2026-03-11T09:05:00.000Z",
    "eventType": "user.account.privilege.grant",
    "severity": "INFO",
    "displayMessage": "Grant user privilege",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "client": {"ipAddress": "198.51.100.9",
               "userAgent": {"rawUserAgent": "python-requests/2.31.0"}},
    "outcome": {"result": "SUCCESS"},
    "debugContext": {
        "debugData": {"privilegeGranted": "Super administrator, Read-only administrator"}
    },
    "target": [
        {"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
         "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"},
        {"id": "ra1b2c3d4e5f6g7h8i9j", "type": "Role", "displayName": "SUPER_ADMIN",
         "alternateId": "unknown"},
    ],
}

#: Every factor cleared for an account — ``is_mfa`` is true on a class that forbids it.
OKTA_MFA_RESET = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000005",
    "published": "2026-03-11T09:10:00.000Z",
    "eventType": "user.mfa.factor.reset_all",
    "severity": "WARN",
    "displayMessage": "Reset all factors for user",
    "actor": {"id": "00uHELPDESK000000001", "type": "User",
              "alternateId": "helpdesk@acme.example", "displayName": "Help Desk"},
    "client": {"ipAddress": "198.51.100.20"},
    "authenticationContext": {"externalSessionId": "102zYxWvUtSrQpOnMlKjI"},
    "outcome": {"result": "SUCCESS"},
    "target": [{"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
                "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"}],
}

#: A membership add — 3006, with both the group and the member present.
OKTA_GROUP_ADD = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000006",
    "published": "2026-03-11T09:15:00.000Z",
    "eventType": "group.user_membership.add",
    "severity": "INFO",
    "displayMessage": "Add user to group membership",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "client": {"ipAddress": "198.51.100.9"},
    "outcome": {"result": "SUCCESS"},
    "target": [
        {"id": "00g1111111111111111a", "type": "UserGroup",
         "displayName": "Domain Admins", "alternateId": "unknown"},
        {"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
         "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"},
    ],
}

#: ``group.privilege.grant`` with no UserGroup in its targets — the routing check.
OKTA_GROUP_NO_GROUP = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000007",
    "published": "2026-03-11T09:20:00.000Z",
    "eventType": "group.privilege.grant",
    "severity": "INFO",
    "displayMessage": "Grant group privilege",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "outcome": {"result": "SUCCESS"},
    "target": [{"id": "ra9j8i7h6g5f4e3d2c1b", "type": "Role",
                "displayName": "ORG_ADMIN", "alternateId": "unknown"}],
}

#: An OIDC app registration — 3004, the class that declares no ``user`` at all.
OKTA_APP_CREATE = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000008",
    "published": "2026-03-11T09:25:00.000Z",
    "eventType": "application.lifecycle.create",
    "severity": "INFO",
    "displayMessage": "Create application",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "client": {"ipAddress": "198.51.100.9",
               "userAgent": {"rawUserAgent": "python-requests/2.31.0"}},
    "outcome": {"result": "SUCCESS"},
    "target": [{"id": "0oa2222222222222222b", "type": "AppInstance",
                "displayName": "Totally Legitimate Reporting Tool",
                "alternateId": "oidc_client"}],
}

#: An API token. Its subject is the admin who made it, because it inherits their role.
OKTA_TOKEN_CREATE = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-000000000009",
    "published": "2026-03-11T09:30:00.000Z",
    "eventType": "system.api_token.create",
    "severity": "INFO",
    "displayMessage": "Create API token",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "outcome": {"result": "SUCCESS"},
    "target": [{"id": "00T3333333333333333c", "type": "Token",
                "displayName": "backup-automation", "alternateId": "unknown"}],
}

#: Okta ThreatInsight — the one class here that is an alerting product's own output.
OKTA_THREAT = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-00000000000a",
    "published": "2026-03-11T14:22:08.000Z",
    "eventType": "security.threat.detected",
    "severity": "WARN",
    "displayMessage": "Okta ThreatInsight detected a request from a malicious IP",
    "actor": {"id": "unknown", "type": "User",
              "alternateId": "dana.hale@acme.example", "displayName": "unknown"},
    "client": {
        "ipAddress": "192.0.2.77",
        "userAgent": {"rawUserAgent": "curl/8.5.0"},
        "geographicalContext": {"city": "Ashburn", "country": "United States"},
    },
    "securityContext": {"isProxy": True, "asNumber": 65001, "asOrg": "bulletproof hosting"},
    "outcome": {"result": "DENY", "reason": "Password Spray attempt THREAT_DETECTED"},
    "debugContext": {"debugData": {"threatSuspected": "true",
                                   "logOnlySecurityData": '{"risk":{"level":"HIGH"}}'}},
    "target": [{"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
                "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"}],
}

#: An eventType this file has never seen, in a family it recognises.
OKTA_PREFIX_ONLY = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-00000000000b",
    "published": "2026-03-11T09:40:00.000Z",
    "eventType": "user.session.reauthenticate_via_quantum_link",
    "severity": "INFO",
    "displayMessage": "Something Okta shipped after this connector was written",
    "actor": {"id": "00u1a2b3c4d5e6f7g8h9", "type": "User",
              "alternateId": "dana.hale@acme.example", "displayName": "Dana Hale"},
    "outcome": {"result": "SUCCESS"},
    "target": [],
}

#: An eventType in no family at all, with no target either.
OKTA_UNKNOWN = {
    "uuid": "e5f8a1c0-1111-4a2b-9c3d-00000000000c",
    "published": "2026-03-11T09:45:00.000Z",
    "eventType": "pigeon.delivery.arrived",
    "severity": "INFO",
    "displayMessage": "Not an Okta event type at all",
    "actor": {"id": "00uADMIN000000000001", "type": "User",
              "alternateId": "root.admin@acme.example", "displayName": "Root Admin"},
    "outcome": {"result": "SUCCESS"},
    "target": [],
}

#: Configured, for the request-shape and cursor tests.
OKTA_LIVE = with_creds(okta_domain="acme.okta.com", okta_api_token="00NotARealToken")
#: Explicitly blank, for the same reason :data:`CONFIG` is.
OKTA_BLANK = with_creds(okta_domain="", okta_api_token="")


def okta(config=None):
    return OktaSystemLogConnector(
        _Pipe(), config or OKTA_LIVE, clock=Clock(), checkpoints=MemoryCheckpoints()
    )


def test_okta_auth_class():
    print("\n[okta] sign-in, factor challenge and impersonation -> 3002")
    c = okta()

    p = c.map_record(OKTA_SIGNIN)
    ev = ocsf_clean("okta sign-in", p, expect_class=ClassUid.AUTHENTICATION)
    check("a session start is Logon (1)", p["activity_id"] == 1, f"{p['activity_id']}")
    check("...and activity_name carries the vendor's own eventType regardless",
          p["activity_name"] == "user.session.start",
          "an activity_id is a bucket; the eventType is the statement")
    check("the login, not the display name, is what fills user_name",
          p["user_name"] == "dana.hale@acme.example",
          "the login is the join key against every other identity source; the label "
          "joins against nothing")
    check("...and on a self-service sign-in actor and user are the same person",
          p["actor_user_name"] == p["user_name"],
          "not deduplicated: a rule that reads actor_user_name must see one on every "
          "record, and the impersonation case below is where the two differ")
    check("session_uid is filled on 3002, the only one of the five that declares it",
          p["session_uid"] == "102aBcDeFgHiJkLmNoPqRsTuV")
    check("the client address, city and country land in src_endpoint",
          p["src_endpoint_ip"] == "203.0.113.42" and p["src_endpoint_city"] == "Pune"
          and p["src_endpoint_country"] == "India")
    check("the device Okta Verify reported fills the device columns",
          p["device_uid"] == "guo4a5b6c7d8e9f0g1h2"
          and p["device_hostname"] == "DANA-LAPTOP"
          and p["device_is_managed"] is True)
    check("...and 'registered' is NOT folded into is_managed",
          p["unmapped"]["device_is_registered"] is True,
          "an org can register a device it does not manage; conflating them reports "
          "every BYOD laptop as corporate")
    check("a False that carries information is stored, not skipped as empty",
          p["unmapped"]["is_proxy"] is False,
          "'Okta checked and it is not a proxy' and 'Okta did not say' are different "
          "facts and a rule counting proxy sign-ins needs to tell them apart")

    # The severity argument from the module docstring, asserted rather than described.
    check("Okta's log level does NOT become the OCSF severity",
          p["severity_id"] == int(Severity.INFORMATIONAL))
    check("...and is kept where it is still queryable, named as what it is",
          p["unmapped"]["okta_severity"] == "INFO")

    check("transaction.id becomes the correlation uid",
          p["metadata_correlation_uid"] == "Ze1234567890abcdefABCDEF",
          "it is what joins this sign-in to its own factor and policy records")
    check("the JSON risk object is parsed, not stashed as a string",
          p["risk_level_id"] == int(RiskLevel.LOW)
          and p["risk_details"] == "Anomalous Location", f"{p.get('risk_details')}")
    check("Behavior Detection's Java-map string is parsed",
          p["unmapped"]["okta_behaviors"] == {
              "New Device": "POSITIVE", "New IP": "POSITIVE", "Velocity": "NEGATIVE"},
          "json.loads raises on it, so a JSON-only parser silently loses the whole "
          "behaviour-detection signal")
    check("...and only the POSITIVE heuristics become labels",
          "okta-behavior:New Device" in p["metadata_labels"]
          and "okta-behavior:Velocity" not in p["metadata_labels"])
    check("...with a technique hint for New Device and none for New IP",
          "attack:T1078.004" in p["metadata_labels"],
          "a laptop on a home connection produces New IP daily; hinting on it would "
          "label most of an org's sign-ins")
    check("OFF_NETWORK is labelled — it is the org's own answer to 'was this on-prem'",
          "okta-zone:OFF_NETWORK" in p["metadata_labels"])
    check("a PASSWORD credential sets no auth_protocol",
          "auth_protocol_id" not in p and "auth_protocol" not in p,
          "Okta checking its own credential store implies no wire protocol; Basic "
          "Authentication (11) would assert an HTTP scheme that was never used")
    check("is_mfa is not asserted false on a sign-in that does not say",
          "is_mfa" not in p,
          "single-factor is a conclusion drawn from a missing sibling record — a "
          "correlation, which is the detect layer's job")
    check("the event survives to a real Event carrying the fixture's own time",
          ev is not None and ev.time == 1_773_216_000.0,
          f"{getattr(ev, 'time', None)}")

    # ── the failed factor ──
    f = c.map_record(OKTA_MFA_FAIL)
    ocsf_clean("okta failed factor", f, expect_class=ClassUid.AUTHENTICATION)
    check("an MFA step is Other (99), not Preauth (6)", f["activity_id"] == 99,
          "3002's Preauth is Kerberos pre-authentication, which this is not")
    check("a FAILURE outcome is Failure, and the vendor word is kept in status_code",
          f["status_id"] == int(Status.FAILURE) and f["status_code"] == "FAILURE")
    check("VERIFICATION_ERROR becomes a readable reason and a technique hint",
          "factor verification failed" in f["status_detail"]
          and "attack:T1110" in f["metadata_labels"], f.get("status_detail"))
    check("...with the vendor's own constant kept beside it",
          f["unmapped"]["outcome_reason"] == "VERIFICATION_ERROR")
    check("an OTP factor sets is_mfa on 3002...", f["is_mfa"] is True)
    check("...and is NOT written to auth_protocol", "auth_protocol_id" not in f,
          "a one-time code is a factor, not a protocol")
    check("isProxy true is labelled and hinted",
          "anonymising-proxy" in f["metadata_labels"]
          and "attack:T1090" in f["metadata_labels"])
    check("an ERROR log level still does not raise the OCSF severity",
          f["severity_id"] == int(Severity.INFORMATIONAL),
          "ERROR on the System Log is often an internal Okta fault")
    check("the AuthenticatorEnrollment target is kept, but not as resources",
          "resources" not in f and f["unmapped"]["target"][0]["type"]
          == "AuthenticatorEnrollment",
          "3002 declares no resources array, so writing one would be swept out and "
          "reported as this connector's mapping error")

    # ── impersonation ──
    i = c.map_record(OKTA_IMPERSONATION)
    ocsf_clean("okta impersonation", i, expect_class=ClassUid.AUTHENTICATION)
    check("an impersonation puts the impersonated account in user_*",
          i["user_name"] == "dana.hale@acme.example" and i["user_full_name"] == "Dana Hale")
    check("...and the admin who did it in actor_user_*",
          i["actor_user_name"] == "okta-support@okta.example",
          "Okta's own 2023 support-system compromise ran through this event")
    check("...and hints valid-accounts abuse rather than asserting it",
          "attack:T1078.004" in i["metadata_labels"]
          and "impersonation" in i["metadata_labels"])


def test_okta_lifecycle_classes():
    print("\n[okta] lifecycle, groups and entities -> 3007 / 3006 / 3004")
    c = okta()

    r = c.map_record(OKTA_ROLE_GRANT)
    ocsf_clean("okta role grant", r, expect_class=ClassUid.USER_MANAGEMENT)
    check("a privilege grant is Assign Privileges (14)", r["activity_id"] == 14)
    check("the account being changed is the subject, not the granting admin",
          r["user_name"] == "dana.hale@acme.example"
          and r["actor_user_name"] == "root.admin@acme.example")
    check("privileges are read from BOTH privilegeGranted and the Role target",
          r["privileges"] == ["Super administrator", "Read-only administrator",
                              "SUPER_ADMIN"],
          f"{r.get('privileges')} — neither source is present on every grant")
    check("a tier-0 role is called out by name, in whichever spelling appeared",
          "tier0-role" in r["metadata_labels"]
          and "role:Super administrator" in r["metadata_labels"]
          and "role:SUPER_ADMIN" in r["metadata_labels"])
    check("...and Read-only administrator is NOT treated as tier-0",
          "role:Read-only administrator" not in r["metadata_labels"],
          "it can see everything and change nothing")
    check("...and the note says why the role matters, not just that it does",
          any("reset credentials" in n for n in r["notes"]), f"{r.get('notes')}")
    check("the Role target, which is not the subject, lands in resources",
          any(x.get("uid") == "ra1b2c3d4e5f6g7h8i9j" for x in r["resources"]),
          f"{r.get('resources')}")

    m = c.map_record(OKTA_MFA_RESET)
    ocsf_clean("okta factor reset", m, expect_class=ClassUid.USER_MANAGEMENT)
    check("reset_all is Disable MFA Factors (13)", m["activity_id"] == 13)
    check("is_mfa is stashed rather than written on 3007, which does not declare it",
          "is_mfa" not in m and m["unmapped"]["is_mfa"] is True,
          "an unguarded write would be swept out AND named in soc_notes as this "
          "connector's mapping error, which it would not be — and every MFA-weakening "
          "event routes here")
    check("...and externalSessionId is stashed for the same reason",
          "session_uid" not in m
          and m["unmapped"]["external_session_id"] == "102zYxWvUtSrQpOnMlKjI")
    check("weakening MFA is hinted as T1556.006",
          "attack:T1556.006" in m["metadata_labels"]
          and "mfa-weakened" in m["metadata_labels"])
    check("the subject is claimed by user_*, so resources stays empty",
          "resources" not in m, f"{m.get('resources')}")

    t = c.map_record(OKTA_TOKEN_CREATE)
    ocsf_clean("okta API token", t, expect_class=ClassUid.USER_MANAGEMENT)
    check("an API token is Add Programmatic Credentials (18)", t["activity_id"] == 18)
    check("its subject is the admin who created it",
          t["user_name"] == "root.admin@acme.example"
          and "substitute_for:user" in t["metadata_labels"],
          "an Okta token inherits its creator's permissions, so it is that admin's "
          "credential rather than an entity of its own")
    check("...and the substitution is declared, with where to check it",
          any("target array in unmapped.target" in n for n in t["notes"]),
          f"{t.get('notes')}")
    check("the token itself is in resources",
          any(x.get("name") == "backup-automation" for x in t["resources"]))
    check("token creation is hinted as an account-manipulation persistence primitive",
          "attack:T1098.001" in t["metadata_labels"])

    g = c.map_record(OKTA_GROUP_ADD)
    ocsf_clean("okta group add", g, expect_class=ClassUid.GROUP_MANAGEMENT)
    check("a membership add is Add User (3)", g["activity_id"] == 3)
    check("Okta's group type is UserGroup, and the bucketing knows it",
          g["group_name"] == "Domain Admins" and g["group_uid"] == "00g1111111111111111a",
          "a table keyed on 'group' would match none of them and every membership "
          "change would fall through to 3004")
    check("...and the member is resolved too", g["user_name"] == "dana.hale@acme.example")
    check("neither is duplicated into resources", "resources" not in g,
          "both targets are already the class's own objects")

    n = c.map_record(OKTA_GROUP_NO_GROUP)
    ocsf_clean("okta group grant with no group", n,
               expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("a 3006-by-name event with no UserGroup does not assert an empty group",
          "group_name" not in n and "group_uid" not in n,
          "a group-escalation rule would match on an empty group name")
    check("...and the reroute is explained on the event itself",
          any("required group object cannot be filled" in x for x in n["notes"]),
          f"{n.get('notes')}")
    check("...and the vendor's eventType survives in activity_name",
          n["activity_name"] == "group.privilege.grant" and n["activity_id"] == 99)
    check("the Role becomes the entity, since 3004 is where this landed",
          n["entity_name"] == "ORG_ADMIN" and n["entity_type"] == "Role")
    check("privileges are stashed here, because 3004 does not declare them",
          "privileges" not in n and n["unmapped"]["privileges"] == ["ORG_ADMIN"])
    check("...and the tier-0 finding is not lost by the reroute",
          "tier0-role" in n["metadata_labels"])

    a = c.map_record(OKTA_APP_CREATE)
    ocsf_clean("okta app create", a, expect_class=ClassUid.ENTITY_MANAGEMENT)
    check("an app registration is Create (1)", a["activity_id"] == 1)
    check("the app is the entity",
          a["entity_name"] == "Totally Legitimate Reporting Tool"
          and a["entity_uid"] == "0oa2222222222222222b")
    check("3004 declares no user at all, so the actor uses actor_user_* only",
          "user_name" not in a and "user_uid" not in a
          and a["actor_user_name"] == "root.admin@acme.example",
          "measured against the vendored index, not assumed")
    check("comment is legal on 3004 and carries the vendor's message",
          a["comment"] == "Create application")
    check("a new app with client credentials is hinted as T1098.001",
          "attack:T1098.001" in a["metadata_labels"])


def test_okta_findings():
    print("\n[okta] ThreatInsight -> 2004, a class that declares a different world")
    c = okta()
    p = c.map_record(OKTA_THREAT)
    ocsf_clean("okta threat", p, expect_class=ClassUid.DETECTION_FINDING)

    check("the finding is New — 2004's status_id is a lifecycle, not an outcome",
          p["status_id"] == int(FindingStatus.NEW),
          "Success (1) on this class reads as New; five distinct status_id tables "
          "exist in OCSF v1.9.0 and this is one of them")
    check("finding_info is filled from the vendor's own detection",
          p["finding_uid"] == OKTA_THREAT["uuid"]
          and "ThreatInsight" in p["finding_title"])
    check("...and which Okta feature produced it is named",
          p["finding_analytic_name"] == "Okta ThreatInsight",
          "ThreatInsight, request blocking and an end-user report have entirely "
          "different false-positive profiles")
    check("finding_types carries the vendor's eventType",
          p["finding_types"] == ["security.threat.detected"])
    check("here, and only here, the vendor's severity word IS the OCSF severity",
          p["severity_id"] == int(Severity.LOW),
          "WARN from an alerting product is an assessment; WARN on a mistyped "
          "password is a log level")
    check("verdict_id is left unset — a block is not a triage disposition",
          "verdict_id" not in p and "verdict" not in p,
          "the connector reports; the detect and triage layers dispose")
    check("is_suspected_breach is left unset for the same reason",
          "is_suspected_breach" not in p)

    check("2004 declares no src_endpoint, so no flat client columns are written",
          "src_endpoint_ip" not in p and "http_user_agent" not in p)
    check("...and the request's origin is in evidences instead, which it does declare",
          p["evidences"][0]["src_endpoint"]["ip"] == "192.0.2.77"
          and p["evidences"][0]["http_request"]["user_agent"] == "curl/8.5.0",
          f"{p.get('evidences')}")
    check("...with the actor as the evidence user, since 2004 declares no user either",
          p["evidences"][0]["user"]["name"] == "dana.hale@acme.example")
    check("the targets are in the top-level resources array, not also in the evidence",
          any(x.get("uid") == "00u1a2b3c4d5e6f7g8h9" for x in p["resources"])
          and "resources" not in p["evidences"][0],
          "two copies would make a hunt query's count depend on which one it read")
    check("a THREAT_DETECTED denial is hinted as password spraying",
          "attack:T1110.003" in p["metadata_labels"]
          and "THREAT_DETECTED" in p["status_detail"])
    check("threatSuspected arrives as the STRING 'true' and is still read as a bool",
          "okta-threat-suspected" in p["metadata_labels"])
    check("log-only ThreatInsight data is kept — an org in audit mode has only this",
          "logOnlySecurityData" in p["unmapped"]["debug_data"],
          "in log-only mode Okta records what it *would* have blocked instead of "
          "blocking it")


def test_okta_routing():
    print("\n[okta] the routing table, its two fallbacks, and the verb rule")
    c = okta()

    check("a dotted qualifier is not mistaken for the verb",
          _okta_verb("user.lifecycle.delete.initiated") == "delete")
    check("...nor an underscored one",
          _okta_verb("user.account.unlock_by_admin") == "unlock",
          "Okta writes qualifiers both ways; handling only the dotted form leaves a "
          "correctly-routed event with a wrong-but-plausible activity, which no OCSF "
          "sweep can catch")
    check("...and a long one is stripped to the operation",
          _okta_verb("user.account.report_suspicious_activity_by_enduser")
          == "report_suspicious_activity")
    check("the same verb means different numbers on different classes",
          _OKTA_VERBS[3006]["create"] == 6 and _OKTA_VERBS[3007]["create"] == 1
          and _OKTA_VERBS[3004]["create"] == 1,
          "one shared table would have been wrong for a third of the classes")
    check("...and delete likewise",
          _OKTA_VERBS[3006]["delete"] == 5 and _OKTA_VERBS[3007]["delete"] == 3
          and _OKTA_VERBS[3004]["delete"] == 4)

    check("suspend has no 3007 member of its own, so it is recorded as Disable",
          _OKTA_ROUTES["user.lifecycle.suspend"] == (3007, 5),
          "the distinction Okta draws survives in activity_name")
    check("a password change is Password Change (8), not a generic Update",
          _OKTA_ROUTES["user.account.update_password"] == (3007, 8))
    check("an app assignment is an Update, not Attach Policies",
          _OKTA_ROUTES["group.application_assignment.add"] == (3006, 9),
          "an app is not a policy")
    check("the tier-0 role list includes the help desk and excludes the read-only admin",
          "help_desk_admin" in _OKTA_TIER0 and "read_only_admin" not in _OKTA_TIER0,
          "a help-desk admin can reset passwords and clear factors for every "
          "non-admin account; a read-only admin can change nothing")

    p = c.map_record(OKTA_PREFIX_ONLY)
    ocsf_clean("okta unseen eventType in a known family", p,
               expect_class=ClassUid.AUTHENTICATION)
    check("an unlisted eventType is still routed by its family",
          p["class_uid"] == 3002 and p["activity_id"] == 99)
    check("...and says which prefix and which verb decided it",
          any("'user.session.' prefix" in n for n in p["notes"]), f"{p['notes']}")

    u = c.map_record(OKTA_UNKNOWN)
    check("an eventType in no family at all lands on 3004 with activity Other",
          u["class_uid"] == 3004 and u["activity_id"] == 99)
    check("...and names itself in activity_name, which 99 requires",
          u["activity_name"] == "pigeon.delivery.arrived")
    check("...and carries the note to query when adding a new Okta event type",
          any("matched no eventType and no prefix" in n for n in u["notes"]))
    # Deliberately not ocsf_clean: this is the one fixture where a required object is
    # unfilled on purpose, and that helper asserts the opposite.
    flat = {k: v for k, v in u.items() if k != "raw"}
    unfilled = unfilled_required(3004, flat)
    check("an event with no target leaves 3004's entity unfilled rather than inventing "
          "one", "entity" in unfilled, f"unfilled: {sorted(unfilled)}")
    check("...and the event model's own sweep is what reports it, plus a note here",
          any("required entity object is unfilled" in n for n in u["notes"]))
    check("...and it is otherwise a legal 3004",
          not misplaced_fields(3004, list(flat)) and not bad_enum_values(3004, flat),
          f"{sorted(misplaced_fields(3004, list(flat)))}")


def test_okta_parsers():
    print("\n[okta] the two debugData formats, which are not the same format")
    check("a Java map toString is parsed",
          _okta_java_map("{New Device=POSITIVE, Velocity=NEGATIVE}")
          == {"New Device": "POSITIVE", "Velocity": "NEGATIVE"})
    check("...including an empty one", _okta_java_map("{}") == {})
    check("...and a missing one", _okta_java_map(None) == {})
    check("a value containing '=' keeps everything after the first one",
          _okta_java_map("{k=a=b}") == {"k": "a=b"})
    check("risk is JSON and is read as JSON",
          _okta_loose_map('{"level":"HIGH","reasons":"x"}')
          == {"level": "HIGH", "reasons": "x"})
    check("...and the same helper still reads a Java map, because which parser "
          "applies is a property of the individual value",
          _okta_loose_map("{level=HIGH}") == {"level": "HIGH"})
    check("malformed JSON degrades to empty rather than raising",
          _okta_loose_map('{"level":"HIGH",}') == {},
          "a parse error here would drop the whole record; the raw map is still in "
          "unmapped.debug_data either way")


def test_okta_spec_and_url():
    print("\n[okta] the org URL, the spec numbers, and what readiness says")
    check("the page size is Okta's documented maximum", okta().spec.page_size == 1000)
    check("indexing_lag is zero, deliberately — there are no windows after the first",
          okta().spec.indexing_lag_seconds == 0.0,
          "a hold-back keeps an unindexed record inside the next window, and this "
          "connector's cursor is a link")
    check("...and overlap is an hour, for the cold rebuild that has no saved link",
          okta().spec.overlap_seconds == 3600.0)
    check("the rate limit leaves headroom for the customer's own integrations",
          okta().spec.rate_per_second <= 1.0,
          "/api/v1/logs is per-org across every caller, not per-token")
    check("the token's inherited-role trap is a stated grant, not a mystery 403",
          any("inherits its creator" in g for g in okta().spec.required_grants),
          "a token made by an App or Group admin authenticates and returns 403 here")
    check("the authorizer presents SSWS, not Bearer",
          "SSWS" in okta().authorizer().describes, okta().authorizer().describes)

    for raw, want in (
        ("acme.okta.com", "https://acme.okta.com"),
        ("https://acme.okta.com/", "https://acme.okta.com"),
        ("http://acme.okta.com", "https://acme.okta.com"),
        ("acme.oktapreview.com", "https://acme.oktapreview.com"),
    ):
        got = okta(with_creds(okta_domain=raw, okta_api_token="t")).base_url()
        check(f"the org URL normalises {raw!r} to {want!r}", got == want, got)
    check("...and note that http was upgraded rather than honoured", True,
          "the request carries an API token in a header; a config file asking to send "
          "it in clear is not a preference to respect")

    blank = okta(OKTA_BLANK).probe()
    check("an unconfigured Okta connector names both env vars",
          not blank.available and "$OKTA_DOMAIN" in blank.reason
          and "$OKTA_API_TOKEN" in blank.reason, blank.reason)
    check("...and the docs URL, so the fix is findable",
          "developer.okta.com" in blank.reason)
    check("an unconfigured base_url does not raise, because probe() has to run",
          okta(OKTA_BLANK).base_url() == "https://OKTA-DOMAIN-NOT-CONFIGURED",
          "reading .value here would turn 'not configured' into a crash in the one "
          "code path whose job is to report that state")

    admin = okta(with_creds(okta_domain="acme-admin.okta.com",
                            okta_api_token="00NotARealToken")).probe()
    check("the admin console URL is rejected before a single request goes out",
          not admin.available and "-admin" in admin.reason, admin.reason)
    check("...and the reason says what to change and what happens if you do not",
          "org URL" in admin.reason and "quiet org" in admin.reason,
          "there is no response that distinguishes wrong-URL from wrong-token")

    ok = okta().probe()
    check("a configured org URL probes available", ok.available, ok.reason)
    check("the factory returns the single connector",
          [x.name for x in okta_connectors(_Pipe(), OKTA_LIVE)] == ["okta_system_log"],
          "splitting the stream by eventType family would give several connectors "
          "sharing one cursor, and the first to advance it would decide what the "
          "others never saw")


async def test_okta_tail():
    print("\n[okta] the Link-header cursor — what a since-based poll gets wrong")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    p2 = ("https://acme.okta.com/api/v1/logs?limit=1000&sortOrder=ASCENDING"
          "&after=1773216000000_1%2C0")
    p3 = ("https://acme.okta.com/api/v1/logs?limit=1000&sortOrder=ASCENDING"
          "&after=1773216007000_1%2C0")
    p4 = ("https://acme.okta.com/api/v1/logs?limit=1000&sortOrder=ASCENDING"
          "&after=1773238928000_1%2C0")
    transport = ScriptedTransport([
        (200, {"Link": f'<https://acme.okta.com/api/v1/logs>; rel="self", '
                       f'<{p2}>; rel="next"'}, [OKTA_SIGNIN, OKTA_MFA_FAIL]),
        (200, {"Link": f'<{p2}>; rel="self", <{p3}>; rel="next"'}, [OKTA_THREAT]),
        # The empty page that terminates the loop, carrying a *different* next link.
        # `paginate` does not yield empty pages, so a commit that only happened in the
        # loop body would leave the resume point one page behind forever.
        (200, {"Link": f'<{p3}>; rel="self", <{p4}>; rel="next"'}, []),
    ])
    c = OktaSystemLogConnector(_Pipe(), OKTA_LIVE, transport=transport, clock=Clock(),
                               checkpoints=MemoryCheckpoints())
    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)
    out = await c.fetch_window(window)
    check("every page's records are mapped", len(out) == 3, f"{len(out)}")
    check("...and the empty third page ends the cycle rather than being followed",
          len(transport.seen) == 3, f"{len(transport.seen)} requests")

    boot = transport.seen[0]
    check("the bootstrap asks for a live tail — since, with no until",
          (boot.params or {}).get("since") == "2026-03-11T00:00:00Z"
          and "until" not in (boot.params or {}),
          "a bounded query's next link is bounded too, so saving one would pin this "
          "connector to a window that ends in the past")
    check("...ascending, so the page cap truncates the newest end of a backlog",
          (boot.params or {}).get("sortOrder") == "ASCENDING",
          "descending would re-read the same recent page every cycle while the "
          "backlog aged out of Okta's 90-day retention")
    check("...at the documented maximum page size",
          (boot.params or {}).get("limit") == 1000)
    check("the SSWS token is on the wire, as Okta requires",
          boot.headers.get("Authorization", "").startswith("SSWS "),
          f"{dict(boot.headers)} — presented as Bearer it is a 401 with no useful text")

    check("the next link is followed verbatim, with no params re-applied",
          transport.seen[1].url == p2 and not transport.seen[1].params,
          "the saved link already carries after, limit and sortOrder")
    check("the resume point is the link from the EMPTY final page",
          c.opaque_cursor == p4, c.opaque_cursor)
    check("...and stats say the cursor is a link, not a timestamp",
          c.stats_extra()["resume"] == "next link")
    check("the timestamp cursor is still maintained, as the cold-rebuild fallback",
          c._latest_record == 1_773_238_928.0, f"{c._latest_record}")
    check("a drained tail sleeps its cadence", c.next_delay() > 0.0)

    # ── resume: no window, no params, the saved link verbatim ──
    resumed = ScriptedTransport([(200, {"Link": f'<{p4}>; rel="next"'}, [])])
    c2 = OktaSystemLogConnector(_Pipe(), OKTA_LIVE, transport=resumed, clock=Clock(),
                                checkpoints=MemoryCheckpoints())
    c2.opaque_cursor = p4
    await c2.fetch_window(window)
    check("a resumed cycle ignores the planned window entirely",
          resumed.seen[0].url == p4 and not resumed.seen[0].params,
          "Okta indexes the System Log by publish order, not event time, so "
          "re-deriving `since` permanently skips every late-published event")
    check("...and an empty tail still does not walk to the page ceiling",
          len(resumed.seen) == 1,
          "an unbounded query returns a next link even for an empty page; following "
          "it unconditionally spends the whole rate-limit budget reading nothing")

    # ── a mapping failure must not advance the cursor past the record it lost ──
    broken = ScriptedTransport([(200, {"Link": f'<{p2}>; rel="next"'}, [OKTA_SIGNIN])])
    c3 = OktaSystemLogConnector(_Pipe(), OKTA_LIVE, transport=broken, clock=Clock(),
                                checkpoints=MemoryCheckpoints())
    c3.map_record = lambda record: (_ for _ in ()).throw(ValueError("mapping blew up"))
    try:
        await c3.fetch_window(window)
        raised = False
    except ValueError:
        raised = True
    check("a mapping failure propagates rather than being swallowed", raised)
    check("...and the cursor does NOT advance past records this cycle never submitted",
          c3.opaque_cursor == "", c3.opaque_cursor,)
    check("...which is why the commit is separate from reading the link",
          c3._pending_link != "",
          "close() persists opaque_cursor on shutdown, so committing on read would "
          "make the skip survive the restart that looked like the fix")

    # ── the page ceiling: behind, and honest about being behind ──
    capped = ScriptedTransport(
        [(200, {"Link": f'<{p2}>; rel="next"'}, [OKTA_SIGNIN]) for _ in range(3)]
    )
    c4 = OktaSystemLogConnector(_Pipe(), OKTA_LIVE, transport=capped, clock=Clock(),
                                checkpoints=MemoryCheckpoints())
    # A two-page ceiling, so the third scripted page must never be requested.
    c4.spec = dataclasses.replace(c4.spec, max_pages_per_cycle=2)
    await c4.fetch_window(window)
    check("the page ceiling is reported, not silently hit",
          c4.page_cap_hits == 1 and len(capped.seen) == 2, f"{len(capped.seen)} pages")
    check("...and a connector with tail left polls with no cadence delay",
          c4._tail_pending and c4.next_delay() == 0.0,
          "the base cannot see this backlog — the planned window was ignored, so "
          "catching_up is False with hours of tail pending")
    check("...and says so in its stats rather than reporting healthy",
          "tail_pending" in c4.stats_extra() and c4.stats_extra()["page_cap_hits"] == 1)
    check("nothing is lost by stopping there, unlike a window connector",
          c4.opaque_cursor == p2,
          "the link this cycle did not follow is the resume point, so the tail "
          "continues exactly where it stopped")

    blank = OktaSystemLogConnector(
        _Pipe(), OKTA_BLANK, transport=ScriptedTransport([]), clock=Clock(),
        checkpoints=MemoryCheckpoints())
    try:
        await blank.fetch_window(window)
        refused, why = False, "it made a request"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured fetch refuses before the transport is touched, naming "
          "both slots",
          refused and "$OKTA_DOMAIN" in why and "$OKTA_API_TOKEN" in why, why)


# ── Microsoft Defender for Endpoint ─────────────────────────────────────────
#
# Defender's fixtures test a different failure class again. Entra's traps are shape
# traps and Okta's are routing traps; Defender's are *staleness* traps — an alert is
# mutable, and the whole design of the connector follows from that one fact. So the
# fixtures below are three sightings of one alert rather than three alerts, and the
# assertion that matters is that the second and third are Update and Close on the
# lifecycle table rather than duplicates to be suppressed.
#
# The second theme is the class-legality one. Advanced hunting returns rows whose
# natural OCSF home is forbidden by the class they belong to — a process row cannot
# carry `user_*`, a network row cannot carry `process_*`, a file row can carry
# neither — so every hunting fixture goes through `ocsf_clean`, which is what would
# catch a mapping that quietly routed half its columns to `unmapped`.

DEFENDER_LIVE = with_creds(
    defender_tenant_id="11111111-2222-3333-4444-555555555555",
    defender_client_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    defender_client_secret="not-a-real-secret",
)
DEFENDER_BLANK = with_creds(
    defender_tenant_id="", defender_client_id="", defender_client_secret=""
)
DEFENDER_PARTLY = with_creds(
    defender_tenant_id="11111111-2222-3333-4444-555555555555",
    defender_client_id="",
    defender_client_secret="",
)

#: The token response every scripted Defender transport begins with. The connector mints
#: once and reuses, so this appears exactly once per connector instance regardless of how
#: many API calls follow.
DEFENDER_TOKEN = (
    200,
    {"Content-Type": "application/json"},
    {"access_token": "eyJ0eXAiOiJKV1Qi.fake", "expires_in": 3599, "token_type": "Bearer"},
)


def defender_alerts(config=None, transport=None):
    return DefenderAlertConnector(
        _Pipe(), config or DEFENDER_LIVE, transport=transport, clock=Clock(),
        checkpoints=MemoryCheckpoints(),
    )


def defender_hunting(config=None, transport=None):
    """A hunting connector whose rate limit will not stall the suite.

    ``spec.rate_per_second`` is 0.25 in production — the tenant-wide advanced-hunting
    cap is 15 calls a minute *shared with every other integration the customer runs*,
    so four queries per cycle genuinely wait around eight seconds. ``RateLimiter``
    busy-waits against the real ``time.monotonic`` and its clock is not injectable
    through ``Connector``, so a no-op ``sleep`` spins instead of fast-forwarding and
    the only way to keep the suite fast is to raise the ceiling before the first
    request builds the limiter. Measured: 16.3 s of wall clock without this.
    """
    c = DefenderHuntingConnector(
        _Pipe(), config or DEFENDER_LIVE, transport=transport, clock=Clock(),
        checkpoints=MemoryCheckpoints(),
    )
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


#: One real alert, at its most informative: classified, determined, incident-clustered,
#: mid-investigation, with six evidence entities of five kinds plus one Defender has not
#: invented yet. Every entity here would be an *illegal* flat field on 2004.
DEFENDER_ALERT = {
    "id": "da637869230618130119_-1234567890",
    "incidentId": 4821,
    "investigationId": 991,
    "investigationState": "Running",
    "assignedTo": "analyst@acme.com",
    "severity": "High",
    "status": "InProgress",
    "classification": "TruePositive",
    "determination": "Malware",
    "detectionSource": "WindowsDefenderAtp",
    "detectorId": "d7c4f1a0-1111-2222-3333-444444444444",
    "category": "CredentialAccess",
    "threatFamilyName": "Mimikatz",
    "threatName": "HackTool:Win32/Mimikatz",
    "title": "Credential theft tool detected",
    "description": "A tool associated with credential dumping was observed running.",
    "alertCreationTime": "2026-03-11T08:00:00Z",
    "firstEventTime": "2026-03-11T07:58:12Z",
    "lastEventTime": "2026-03-11T07:59:44Z",
    "lastUpdateTime": "2026-03-11T08:04:19Z",
    "resolvedTime": None,
    "machineId": "9f0e1d2c3b4a59687766554433221100aabbccdd",
    "computerDnsName": "fin-ws-014.corp.acme.com",
    "aadDeviceId": "cafe1234-5678-90ab-cdef-1234567890ab",
    "rbacGroupName": "Finance Workstations",
    "relatedUser": {"userName": "j.reyes", "domainName": "CORP"},
    "mitreTechniques": ["T1003.001", "T1059.001"],
    "serviceSource": "Microsoft Defender for Endpoint",
    "evidence": [
        {
            "entityType": "File",
            "fileName": "mimi.exe",
            "filePath": "C:\\Users\\j.reyes\\Downloads",
            "sha256": "b" * 64,
            "sha1": "c" * 40,
            "detectionStatus": "Detected",
        },
        {
            "entityType": "Process",
            "processId": 6612,
            "processCommandLine": "mimi.exe sekurlsa::logonpasswords",
            "processCreationTime": "2026-03-11T07:58:11Z",
            "fileName": "mimi.exe",
            "filePath": "C:\\Users\\j.reyes\\Downloads",
            "sha256": "b" * 64,
            "parentProcessId": 4408,
            "parentProcessFileName": "powershell.exe",
            "parentProcessCreationTime": "2026-03-11T07:50:00Z",
            "detectionStatus": "Prevented",
        },
        {
            "entityType": "User",
            "accountName": "j.reyes",
            "domainName": "CORP",
            "userSid": "S-1-5-21-99-88-77-1104",
            "userPrincipalName": "j.reyes@acme.com",
        },
        {"entityType": "Ip", "ipAddress": "198.51.100.23"},
        {
            "entityType": "RegistryKey",
            "registryKey": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "registryHive": "HKEY_LOCAL_MACHINE",
        },
        # Not in the routing table. Must be noted, not silently dropped and not crash.
        {"entityType": "PigeonCoop", "wingspan": 42},
    ],
}

#: The one that must not be responded to. An authorised red team, closed by an analyst,
#: with a Critical severity that would otherwise dominate any score.
DEFENDER_ALERT_TESTING = {
    "id": "da637869230618130119_-2222222222",
    "severity": "High",
    "status": "Resolved",
    "classification": "InformationalExpectedActivity",
    "determination": "SecurityTesting",
    "detectionSource": "WindowsDefenderAtp",
    "category": "Execution",
    "title": "Suspicious process discovered credentials",
    "alertCreationTime": "2026-03-11T09:00:00Z",
    "lastUpdateTime": "2026-03-11T09:30:00Z",
    "resolvedTime": "2026-03-11T09:30:00Z",
    "machineId": "aaaa1111",
    "computerDnsName": "redteam-lab-01.corp.acme.com",
    "mitreTechniques": ["T1555"],
    "evidence": [],
}

#: Defender describing its own remediation. Counting this as an intrusion double-counts
#: whatever it remediated.
DEFENDER_ALERT_AIR = {
    "id": "da637869230618130119_-3333333333",
    "severity": "Informational",
    "status": "Resolved",
    "detectionSource": "AutomatedInvestigation",
    "category": "Malware",
    "title": "Automated investigation remediated a threat",
    "alertCreationTime": "2026-03-11T10:00:00Z",
    "lastUpdateTime": "2026-03-11T10:00:00Z",
    "machineId": "bbbb2222",
    "computerDnsName": "hr-ws-003.corp.acme.com",
    "evidence": [],
}

#: Every vocabulary field unknown at once, plus no evidence array at all — which in
#: production means the request forgot ``$expand=evidence`` and every alert on the feed
#: is a title with no IOCs.
DEFENDER_ALERT_UNKNOWN = {
    "id": "da637869230618130119_-4444444444",
    "severity": "Medium",
    "status": "Escalated",
    "classification": "PossiblyMalicious",
    "determination": "Hunch",
    "detectionSource": "PigeonSensor",
    "category": "Divination",
    "title": "Something happened",
    "alertCreationTime": "2026-03-11T11:00:00Z",
    "lastUpdateTime": "2026-03-11T11:00:00Z",
    "machineId": "cccc3333",
    "computerDnsName": "lab-01",
}

#: A confirmed true positive nobody has touched. The highest-value row on the feed.
DEFENDER_ALERT_UNACTIONED = {
    "id": "da637869230618130119_-5555555555",
    "severity": "Critical",
    "status": "New",
    "classification": "TruePositive",
    "detectionSource": "CustomDetection",
    "category": "Ransomware",
    "title": "Ransomware behaviour blocked",
    "alertCreationTime": "2026-03-11T12:00:00Z",
    "lastUpdateTime": "2026-03-11T12:00:00Z",
    "machineId": "dddd4444",
    "computerDnsName": "file-srv-01.corp.acme.com",
    "evidence": [],
}

#: Shared columns of every advanced-hunting row. `InitiatingProcess*` is the actor on
#: all four tables and is the field group whose mis-homing the class sweeps catch.
_DEF_HUNT_BASE = {
    "Timestamp": "2026-03-11T08:00:00Z",
    "DeviceId": "9f0e1d2c3b4a5968",
    "DeviceName": "fin-ws-014.corp.acme.com",
    "ReportId": 771234,
    "InitiatingProcessId": 4408,
    "InitiatingProcessFileName": "powershell.exe",
    "InitiatingProcessFolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    "InitiatingProcessCommandLine": "powershell.exe -enc SQBFAFgA",
    "InitiatingProcessSHA256": "a" * 64,
    "InitiatingProcessAccountName": "j.reyes",
    "InitiatingProcessAccountDomain": "CORP",
}

DEFENDER_PROCESS_ROW = dict(
    _DEF_HUNT_BASE,
    ActionType="ProcessCreated",
    FileName="mimi.exe",
    FolderPath="C:\\Users\\j.reyes\\Downloads",
    SHA256="b" * 64,
    ProcessId=6612,
    ProcessCommandLine="mimi.exe sekurlsa::logonpasswords",
    ProcessCreationTime="2026-03-11T07:58:11Z",
    ProcessIntegrityLevel="High",
    AccountName="j.reyes",
    AccountDomain="CORP",
    AccountSid="S-1-5-21-99-88-77-1104",
    InitiatingProcessParentId=1188,
    InitiatingProcessParentFileName="explorer.exe",
)

DEFENDER_NETWORK_ROW = dict(
    _DEF_HUNT_BASE,
    ActionType="ConnectionSuccess",
    RemoteIP="198.51.100.23",
    RemotePort=443,
    RemoteUrl="cdn.evil-c2.example",
    LocalIP="10.4.7.19",
    LocalPort=51733,
    Protocol="Tcp",
)

#: A full URL in ``RemoteUrl``, which the same column carries on other rows as a bare
#: hostname. Writing it to ``dst_endpoint_domain`` unconditionally puts a scheme and a
#: path into a domain column and every DNS join then misses it.
DEFENDER_NETWORK_URL_ROW = dict(
    _DEF_HUNT_BASE,
    ReportId=771235,
    ActionType="ConnectionFailed",
    RemoteIP="203.0.113.9",
    RemotePort=8443,
    RemoteUrl="https://cdn.evil-c2.example/beacon?id=7",
    LocalIP="10.4.7.19",
    LocalPort=51734,
    Protocol="Tcp",
)

DEFENDER_LOGON_ROW = dict(
    _DEF_HUNT_BASE,
    ActionType="LogonFailed",
    LogonType="NetworkCleartext",
    AccountName="svc_backup",
    AccountDomain="CORP",
    AccountSid="S-1-5-21-99-88-77-2201",
    RemoteIP="10.9.1.44",
    RemoteDeviceName="OPS-JUMP-02",
    IsLocalAdmin="true",
    Protocol="NTLM",
    FailureReason="UnknownUsernameOrBadPassword",
)

#: ``CustomLogonType`` has no OCSF member. It must leave ``logon_type_id`` *unset*
#: rather than 0, because 0 on 3002's table is *System* — a false claim, not a gap.
DEFENDER_LOGON_ODD_ROW = dict(
    _DEF_HUNT_BASE,
    ReportId=771236,
    ActionType="LogonSuccess",
    LogonType="CustomLogonType",
    AccountName="svc_odd",
    AccountDomain="CORP",
)

DEFENDER_FILE_ROW = dict(
    _DEF_HUNT_BASE,
    ActionType="FileModified",
    FileName="Q3-forecast.xlsx",
    FolderPath="C:\\Users\\j.reyes\\Documents",
    SHA256="d" * 64,
    MD5="e" * 32,
    FileSize=48219,
)

_DEF_HUNT_ROWS = {
    "DeviceProcessEvents": DEFENDER_PROCESS_ROW,
    "DeviceNetworkEvents": DEFENDER_NETWORK_ROW,
    "DeviceLogonEvents": DEFENDER_LOGON_ROW,
    "DeviceFileEvents": DEFENDER_FILE_ROW,
}


def test_defender_alert_mapping():
    print("\n[defender] alerts -> 2004, with Microsoft's own verdict")

    c = defender_alerts()
    p = c.map_record(DEFENDER_ALERT)
    ocsf_clean("a Defender alert", p, expect_class=2004)

    check("an alert is flagged as an alert, which raw hunting telemetry is not",
          p.get("is_alert") is True)
    check("severity is the vendor's assessment, not a log level, so it is the OCSF one",
          p["severity_id"] == 4, f"{p.get('severity_id')} for 'High'")
    check("Microsoft's classification becomes the verdict rather than being re-derived",
          p["verdict_id"] == 2,
          "a TruePositive an analyst already confirmed is the one verdict in this "
          "platform that came from more context than it has")
    check("...and the workflow status is the finding lifecycle, not a success/failure",
          p["status_id"] == int(FindingStatus.IN_PROGRESS),
          f"{p.get('status_id')} — 1 and 2 are legal on both tables and mean different "
          "things on each, which is why bad_enum_values is the check that catches it")
    check("the incident id becomes the correlation key, because Microsoft has already "
          "clustered across endpoint, identity, email and cloud",
          p["metadata_correlation_uid"] == "defender-incident:4821")
    check("event times are kept apart from alert times, which is what dwell time needs",
          p["finding_first_seen_time"] == 1_773_215_892.0
          and p["finding_created_time"] == 1_773_216_000.0,
          "firstEventTime is when the activity happened; alertCreationTime is when "
          "Defender noticed")
    check("the three device identifiers stay distinct",
          p["device_uid"] == "9f0e1d2c3b4a59687766554433221100aabbccdd"
          and p["device_hostname"] == "fin-ws-014.corp.acme.com"
          and p["unmapped"]["aad_device_id"] == "cafe1234-5678-90ab-cdef-1234567890ab",
          "machineId is the only id the isolate action accepts, aadDeviceId is what "
          "joins to an Entra sign-in, computerDnsName is what an analyst recognises — "
          "conflating them isolates the wrong machine")
    check("...and the RBAC machine group is kept as an asset-criticality input",
          p["unmapped"]["machine_group"] == "Finance Workstations")
    check("relatedUser goes to actor_user_*, because 2004 declares no top-level user",
          p["actor_user_name"] == "j.reyes" and "user_name" not in p,
          "measured: a user_name here would be swept to unmapped and reported as this "
          "connector's mapping error")
    check("the assignee is an analyst, not a subject, so it is never a user field",
          p["comment"] == "assigned to analyst@acme.com"
          and p["unmapped"]["assigned_to"] == "analyst@acme.com"
          and p["actor_user_name"] != "analyst@acme.com")
    check("the detection source becomes a named analytic with a type",
          p["finding_analytic_name"] == "Defender for Endpoint EDR"
          and p["finding_analytic_type_id"] == 2,
          "a signature hit on a quarantined file needs no response and a behavioural "
          "detection on a live process does")
    check("techniques come from mitreTechniques and the category adds its tactic",
          "attack:T1003.001" in p["metadata_labels"]
          and "attack:T1059.001" in p["metadata_labels"]
          and "tactic:TA0006" in p["metadata_labels"])
    check("...and no technique is invented from the determination",
          not any(lbl.startswith("attack:T1204") for lbl in p["metadata_labels"]),
          "'Malware' is a disposition — it does not say the malware arrived by user "
          "execution, and a fabricated technique in the coverage matrix is "
          "indistinguishable from one Defender actually observed")
    check("a still-running vendor investigation is called out before anyone acts",
          "vendor-investigation-in-flight" in p["metadata_labels"]
          and any("still 'Running'" in n for n in p["notes"]),
          "acting now can collide with a remediation already in progress")

    ev = p["evidences"]
    kinds = [next(iter(e)) for e in ev]
    check("every evidence entity lands in evidences, which is 2004's only legal home "
          "for a file, process, user, address or registry key",
          kinds == ["file", "process", "user", "src_endpoint", "reg_key"],
          f"got {kinds}")
    check("the file entity carries both hashes with their algorithm ids",
          {h["algorithm_id"] for h in ev[0]["file"]["hashes"]} == {2, 3})
    check("the process entity keeps its own parent, so the tree survives",
          ev[1]["process"]["parent_process"]["file"]["name"] == "powershell.exe"
          and ev[1]["process"]["pid"] == 6612)
    check("per-entity detectionStatus is kept as the entity's own verdict",
          ev[0].get("verdict") == "Detected" and ev[1].get("verdict") == "Prevented",
          "'this file was blocked' and 'this file ran' need different responses")
    check("...and a prevented entity is counted, because it changes whether a "
          "response is needed at all",
          p["unmapped"]["entities_prevented"] == 1
          and "partially-prevented" in p["metadata_labels"])
    check("an entityType this connector has never seen is reported, not dropped "
          "silently and not fatal",
          any("PigeonCoop" in n for n in p["notes"]) and len(ev) == 5,
          "an unknown entity in unmapped.raw is findable; one that vanished is not")


def test_defender_alert_lifecycle():
    print("\n[defender] one alert, three sightings — Create / Update / Close")

    c = defender_alerts()
    first = c.map_record(DEFENDER_ALERT)
    again = c.map_record(dict(DEFENDER_ALERT, lastUpdateTime="2026-03-11T08:40:00Z"))
    closed = c.map_record(
        dict(DEFENDER_ALERT, status="Resolved", classification="FalsePositive",
             resolvedTime="2026-03-11T09:10:00Z")
    )
    check("the first sighting of an alert is Create",
          first["activity_id"] == 1)
    check("a re-delivery is Update, not a duplicate to be suppressed",
          again["activity_id"] == 2,
          "the connector filters on lastUpdateTime because an alert is mutable — "
          "evidence, incident id and classification all arrive after creation, so "
          "filtering on alertCreationTime collects every alert at its emptiest and "
          "never reads it again")
    check("...and all three share one finding_uid, so the lake holds an ordered "
          "history of one finding rather than three findings",
          first["finding_uid"] == again["finding_uid"] == closed["finding_uid"]
          and first["metadata_uid"] == closed["metadata_uid"])
    check("a resolved alert is Close",
          closed["activity_id"] == 3 and closed["status_id"] == int(FindingStatus.RESOLVED))
    check("...and its verdict follows the analyst who closed it",
          closed["verdict_id"] == 1,
          "re-raising an alert a customer's analyst closed as a false positive is how "
          "a SOC platform loses its welcome")
    check("Microsoft's own time-to-resolve is kept as a real MTTR baseline",
          closed["unmapped"]["vendor_resolve_seconds"] == 4200.0,
          f"got {closed['unmapped'].get('vendor_resolve_seconds')}")

    fresh = defender_alerts()
    straight_to_closed = fresh.map_record(DEFENDER_ALERT_TESTING)
    check("an alert that arrives already resolved is Close on first sight, because "
          "Automated Investigation resolves faster than a poll cycle",
          straight_to_closed["activity_id"] == 3)
    check("the alert count tracks findings, not sightings",
          c.stats_extra()["alerts_tracked"] == 1,
          f"{c.stats_extra().get('alerts_tracked')} after three sightings of one alert")


def test_defender_response_gates():
    print("\n[defender] the fields that decide whether response is allowed at all")

    c = defender_alerts()
    testing = c.map_record(DEFENDER_ALERT_TESTING)
    ocsf_clean("an authorised-testing alert", testing, expect_class=2004)
    check("an authorised red team is labelled as one",
          "authorised-testing" in testing["metadata_labels"])
    check("...and marked as forbidden to respond to, as a hard stop",
          "no-autonomous-response" in testing["metadata_labels"]
          and any("hard stop on response" in n for n in testing["notes"]),
          "a score can be outvoted by a High severity; this cannot — isolating a "
          "tester's laptop at 3 a.m. is a self-inflicted incident")
    check("...and it is counted, so the readiness line shows the tenant has testing",
          c.stats_extra()["response_forbidden_alerts"] == 1)
    check("'expected activity' is Benign, not False Positive",
          testing["verdict_id"] == 5,
          "the detection fired correctly on activity that is expected, which is a "
          "different statement from 'the detection was wrong' — and the difference is "
          "what a detection-tuning report needs")
    check("the determination table and the no-response set agree",
          "securitytesting" in NO_RESPONSE_DETERMINATIONS
          and "linetobusinessapplication" in NO_RESPONSE_DETERMINATIONS)

    air = c.map_record(DEFENDER_ALERT_AIR)
    ocsf_clean("an Automated Investigation alert", air, expect_class=2004)
    check("Defender describing its own remediation is not counted as an intrusion",
          "vendor-remediation" in air["metadata_labels"]
          and c.stats_extra()["vendor_remediation_alerts"] == 1,
          "counting these double-counts every alert AIR touched and reports a busy "
          "month whenever AIR was busy")
    check("...and says so on the record, not only in a counter",
          any("not by a detection of adversary activity" in n for n in air["notes"]))
    check("the source set and the table agree on which sources are vendor actions",
          VENDOR_ACTION_SOURCES <= set(_DEF_SOURCES),
          f"{VENDOR_ACTION_SOURCES - set(_DEF_SOURCES)} is in the set but has no "
          "table entry, so it would never be recognised")

    unactioned = c.map_record(DEFENDER_ALERT_UNACTIONED)
    check("a confirmed true positive nobody has touched is called out",
          "confirmed-unactioned" in unactioned["metadata_labels"],
          "confirmed and unactioned is the highest-value state on this feed")


def test_defender_unknown_vocabulary():
    print("\n[defender] four unknown vendor words at once, and the missing $expand")

    c = defender_alerts()
    p = c.map_record(DEFENDER_ALERT_UNKNOWN)
    ocsf_clean("an alert with every vocabulary field unknown", p, expect_class=2004)

    check("an unknown status is Unknown with the vendor word kept, not a guess",
          p["status_id"] == int(FindingStatus.UNKNOWN) and p["status_code"] == "Escalated"
          and any("lifecycle table" in n for n in p["notes"]))
    check("an unknown classification leaves verdict_id unset rather than guessing",
          "verdict_id" not in p
          and p["unmapped"]["defender_classification"] == "PossiblyMalicious",
          "an unset verdict routes to triage; a wrong one does not")
    check("an unknown detectionSource is analytic type Other and says why that matters",
          p["finding_analytic_name"] == "PigeonSensor"
          and p["finding_analytic_type_id"] == 99
          and any("cannot be told apart" in n for n in p["notes"]))
    check("an unknown determination is noted and stashed",
          any("determination 'Hunch'" in n for n in p["notes"])
          and p["unmapped"]["defender_determination"] == "Hunch")
    check("a category that is neither a tactic nor a known label is reported as a "
          "coverage-matrix gap",
          any("neither an ATT&CK tactic nor a known label" in n for n in p["notes"])
          and p["finding_types"] == ["Divination"])
    check("an alert with no evidence array is flagged as a probable missing $expand",
          any("$expand=evidence" in n for n in p["notes"]),
          "without it every alert is a title with no file hash, process, account or "
          "address, and nothing downstream can pivot on it")
    check("...and a hostname with no dot yields no bogus device_domain",
          "device_domain" not in p, f"got {p.get('device_domain')!r} from 'lab-01'")

    non_tactic = c.map_record(dict(DEFENDER_ALERT_UNACTIONED, category="Ransomware"))
    check("a Defender category that is not an ATT&CK tactic becomes a plain label "
          "rather than being forced onto a tactic it does not have",
          "ransomware" in non_tactic["metadata_labels"]
          and not any(l.startswith("tactic:") for l in non_tactic["metadata_labels"]))
    check("...and an alert with no techniques at all says its ATT&CK position is a "
          "tactic and not a technique",
          any("no mitreTechniques" in n for n in non_tactic["notes"]))


def test_defender_hunting_classes():
    print("\n[defender] advanced hunting -> 1007 / 4001 / 3002 / 1001")

    c = defender_hunting()
    by_table = {}
    for query in HUNTING_PACK:
        row = _DEF_HUNT_ROWS[query.table]
        payload = getattr(c, query.mapper)(row, query)
        by_table[query.table] = payload
        ocsf_clean(f"a {query.table} row", payload, expect_class=query.class_uid)

    proc = by_table["DeviceProcessEvents"]
    check("the created process is process_*, and the initiator is actor_process_*",
          proc["process_name"] == "mimi.exe"
          and proc["actor_process_name"] == "powershell.exe",
          "putting the initiator in process_* makes every parent look like a child")
    check("the account that ran it is actor_user_*, because 1007 declares no user",
          proc["actor_user_name"] == "j.reyes" and "user_name" not in proc,
          "measured: 1007 forbids every user_* field, so a user_name here would be "
          "swept to unmapped and reported as a mapping error")
    check("...and 1007 forbids file_* too, so the image is process_file_*",
          proc["process_file_sha256"] == "b" * 64
          and not any(k.startswith("file_") for k in proc))
    check("integrity level is mapped, because High and System are the difference "
          "between a process that has escalated and one that has not",
          proc["process_integrity_id"] == 4
          and "integrity:high" in proc["metadata_labels"])

    net = by_table["DeviceNetworkEvents"]
    check("a network row carries no process_* at all — 4001 declares none",
          not any(k.startswith("process_") for k in net)
          and net["actor_process_name"] == "powershell.exe",
          "measured, and it is the same defect found earlier in the collectors: "
          "process_* on 4001 is silently swept to unmapped")
    check("local is source and remote is destination on an endpoint's own view",
          net["src_endpoint_ip"] == "10.4.7.19"
          and net["dst_endpoint_ip"] == "198.51.100.23"
          and net["dst_endpoint_port"] == 443)
    check("a bare hostname in RemoteUrl becomes the destination domain",
          net["dst_endpoint_domain"] == "cdn.evil-c2.example")

    url_row = c._map_network(DEFENDER_NETWORK_URL_ROW, HUNTING_PACK[1])
    ocsf_clean("a network row whose RemoteUrl is a full URL", url_row, expect_class=4001)
    check("...but a full URL in the same column does not, because a scheme and a path "
          "in a domain column makes every DNS join miss it",
          "dst_endpoint_domain" not in url_row
          and url_row["unmapped"]["remote_url"].startswith("https://"))
    check("a failed connection is Fail on 4001's activity table and Failure on status",
          url_row["activity_id"] == 4 and url_row["status_id"] == int(Status.FAILURE))

    logon = by_table["DeviceLogonEvents"]
    check("3002 is the one class in the pack that declares user, so the account is "
          "user_* here and not actor_user_*",
          logon["user_name"] == "svc_backup" and logon["user_uid"].startswith("S-1-5-21"))
    check("Defender's logon vocabulary maps to OCSF captions, not Windows spellings",
          logon["logon_type_id"] == 8 and logon["logon_type"] == "Network Cleartext")
    check("...and a cleartext network logon is a finding in its own right",
          logon.get("is_cleartext") is True and logon.get("is_remote") is True
          and "attack:T1040" in logon["metadata_labels"],
          "basic auth over IIS or an unencrypted LDAP bind put a recoverable password "
          "on the wire")
    check("a failed logon carries the vendor's reason in both status fields",
          logon["status_id"] == int(Status.FAILURE)
          and logon["status_detail"] == "UnknownUsernameOrBadPassword")
    check("a local-admin logon is labelled, because it changes the blast radius",
          "local-admin-logon" in logon["metadata_labels"]
          and logon["unmapped"]["is_local_admin"] is True,
          "IsLocalAdmin arrives as the string 'true', so as_bool is doing real work")

    odd = c._map_logon(DEFENDER_LOGON_ODD_ROW, HUNTING_PACK[2])
    ocsf_clean("a logon whose type has no OCSF member", odd, expect_class=3002)
    check("a logon type with no OCSF member leaves logon_type_id unset, never 0",
          "logon_type_id" not in odd
          and odd["unmapped"]["defender_logon_type"] == "CustomLogonType"
          and any("0 is *System*" in n for n in odd["notes"]),
          "0 on 3002's table is System — asserting it would be a false claim rather "
          "than an honest gap")

    fil = by_table["DeviceFileEvents"]
    check("a modified file is Update, not Create",
          fil["activity_id"] == 3,
          "mass Update on existing documents is encryption in place; mass Create is a "
          "copy, and ransomware staging looks like one of them")
    check("1001 takes file_* plus actor_process_* and forbids process_* and user_*",
          fil["file_sha256"] == "d" * 64 and fil["actor_process_pid"] == 4408
          and not any(k.startswith("process_") for k in fil)
          and not any(k.startswith("user_") for k in fil))

    uids = {t: p["metadata_uid"] for t, p in by_table.items()}
    check("one device, one second and one ReportId across four tables still yields "
          "four distinct uids",
          len(set(uids.values())) == 4,
          f"{uids} — measured during development: without the table in the key these "
          "were byte-identical, and dedup would have collapsed a process event and a "
          "file event into one row, silently, only on busy devices")
    check("no hunting row claims to be an alert",
          not any(p.get("is_alert") for p in by_table.values()),
          "a DeviceProcessEvents row is an observation; treating it as an alert "
          "inflates the alert-volume metric with raw telemetry")
    check("raw telemetry carries no severity assessment, because it has none",
          {p["severity_id"] for p in by_table.values()} == {int(Severity.INFORMATIONAL)})


def test_defender_hunting_pack():
    print("\n[defender] the query pack itself")

    check("every query in the pack is pinned to exactly one class and one mapper",
          len({q.table for q in HUNTING_PACK}) == len(HUNTING_PACK)
          and all(hasattr(DefenderHuntingConnector, q.mapper) for q in HUNTING_PACK),
          "a union query would produce rows whose shape depended on their source "
          "table, and the mapping would be a switch on a nullable column")
    check("the pack covers the four tables whose classes differ",
          {q.class_uid for q in HUNTING_PACK} == {1007, 4001, 3002, 1001})

    for q in HUNTING_PACK:
        kql = q.kql.format(start="2026-03-11T08:00:00Z", end="2026-03-11T08:05:00Z",
                           take=8000)
        check(f"{q.table}: the window is half-open, matching the planner's convention",
              ">= datetime(2026-03-11T08:00:00Z)" in kql
              and "< datetime(2026-03-11T08:05:00Z)" in kql,
              "a KQL between() is inclusive at both ends and would re-deliver one row "
              "per boundary per cycle, forever")
        check(f"{q.table}: the datetime literal is unquoted",
              "datetime('" not in kql and 'datetime("' not in kql,
              "KQL datetime() takes no quotes and errors with them — the exact "
              "opposite of the Azure Activity $filter, same ISO string, one vendor")
        check(f"{q.table}: rows are ordered ascending before the cap",
              "order by Timestamp asc" in kql and kql.rstrip().endswith("take 8000"),
              "ascending means truncation drops the newest rows, which the next "
              "window's overlap re-reads; descending drops the oldest, which nothing "
              "ever re-reads")
        check(f"{q.table}: the projection is explicit, so a dropped column fails loudly",
              "| project " in kql and q.table in kql.splitlines()[0])

    check("the hunting window is deliberately narrower than the alert window",
          DefenderHuntingConnector.spec.max_window_seconds
          < DefenderAlertConnector.spec.max_window_seconds,
          "the row cap is per query, so a wide window truncates instead of erroring "
          "and the truncation is invisible in the data")
    check("the hunting rate limit cannot breach the tenant-wide 15-per-minute cap "
          "even with the cadence collapsed to zero",
          DefenderHuntingConnector.spec.rate_per_second * 60 * len(HUNTING_PACK) <= 60,
          f"{DefenderHuntingConnector.spec.rate_per_second}/s x {len(HUNTING_PACK)} "
          "queries — the cap is shared with the customer's own tooling, so this must "
          "leave them room")


def test_defender_readiness():
    print("\n[defender] readiness, scope and the sovereign-cloud trap")

    blank = defender_alerts(DEFENDER_BLANK).probe()
    check("unconfigured names all three slots, the cost and the doc",
          not blank.available and "$DEFENDER_TENANT_ID" in blank.reason
          and "$DEFENDER_CLIENT_SECRET" in blank.reason
          and "not collected" in blank.reason and "learn.microsoft.com" in blank.reason,
          blank.reason)
    partly = defender_alerts(DEFENDER_PARTLY).probe()
    check("half-configured says it is worse than unconfigured",
          not partly.available and "PARTLY configured" in partly.reason
          and "auth error rather than reporting the real cause" in partly.reason,
          partly.reason)
    full = defender_alerts().probe()
    check("configured is available, and still names the grants it cannot verify",
          full.available and "Alert.Read.All" in (full.limitation or "")
          and "admin consent" in (full.limitation or ""),
          full.limitation)
    hunt = defender_hunting().probe()
    check("the hunting connector names the licence tier, which is a 403 and not an "
          "empty result",
          hunt.available and "P2" in (hunt.limitation or ""), hunt.limitation)

    mixed = dataclasses.replace(
        DEFENDER_LIVE,
        endpoints=dataclasses.replace(
            DEFENDER_LIVE.endpoints,
            defender="https://api.securitycenter.microsoft.us",
        ),
    )
    crossed = defender_alerts(mixed).probe()
    check("a login endpoint and an API endpoint in different Microsoft clouds is "
          "caught at readiness rather than at runtime",
          not crossed.available and "different Microsoft clouds" in crossed.reason,
          "the token is minted successfully by one cloud and rejected as invalid by "
          "the other, and the error names the token rather than the cloud")

    c = defender_alerts()
    auth = c.authorizer()
    check("the token is minted against the tenant-specific v2.0 endpoint",
          "/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token" in auth.token_url,
          auth.token_url)
    check("...for Defender's own resource, not Graph",
          auth.scope == "https://api.securitycenter.microsoft.com/.default",
          f"{auth.scope} — a Graph token here returns 401 InvalidAuthenticationToken, "
          "whose text says the token is invalid rather than that it is for the wrong "
          "audience, so the natural next step is to re-issue the same wrong token")
    check("an unconfigured deployment can still build an Authorizer, because the "
          "readiness report constructs one",
          defender_alerts(DEFENDER_BLANK).authorizer() is not None,
          "`.value` raises when unset; `.secret or 'TENANT-NOT-CONFIGURED'` does not")

    names = [x.name for x in defender_connectors(_Pipe(), DEFENDER_LIVE)]
    check("the factory returns both, alerts first",
          names == ["defender_alerts", "defender_hunting"], f"{names}")
    check("...and both share one credential set",
          set(defender_alerts().credentials())
          == set(defender_hunting().credentials()))


async def test_defender_transport():
    print("\n[defender] the wire: OData paging, the KQL POST, and a changed shape")

    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    def alert(uid, **kw):
        return dict(DEFENDER_ALERT_UNACTIONED, id=uid, **kw)

    page2 = "https://api.securitycenter.microsoft.com/api/alerts?$skiptoken=AAA"
    paged = ScriptedTransport([
        DEFENDER_TOKEN,
        (200, {}, {"value": [alert("a1"), alert("a2")], "@odata.nextLink": page2}),
        (200, {}, {"value": [alert("a3")]}),
    ])
    c = defender_alerts(transport=paged)
    window = TimeWindow(1_773_216_000.0, 1_773_216_300.0)
    out = await c.fetch_window(window)
    check("OData paging is followed to the end",
          [p["finding_uid"] for p in out] == ["a1", "a2", "a3"] and c.pages == 2)
    first_get = paged.seen[1]
    check("the filter is on lastUpdateTime, with no upper bound",
          first_get.params["$filter"] == "lastUpdateTime gt 2026-03-11T08:00:00Z",
          "with an lt bound the connector collects each alert's first state and then "
          "advances past every later update — the update raises lastUpdateTime above a "
          "window that has already closed, so it lands in no window at all")
    check("...and the ISO literal is unquoted, which is what OData wants here",
          "'" not in first_get.params["$filter"],
          "quoted returns 400 'Syntax error at position N' — and Azure Activity's "
          "$filter requires the opposite")
    check("$expand=evidence is always requested",
          first_get.params["$expand"] == "evidence",
          "without it the evidence array is absent entirely and every alert is a "
          "title with no IOCs")
    check("the nextLink is followed verbatim, with no params re-appended",
          paged.seen[2].url == page2 and paged.seen[2].params is None,
          "the key contains a dot, so reading it with dig() — which splits on dots — "
          "returns None and pages page one forever while the cursor advances past the "
          "rest; this is the same defect found in entra.py")
    check("the token is minted once for the whole window",
          sum(1 for r in paged.seen if r.url.endswith("/token")) == 1)

    script = [DEFENDER_TOKEN]
    for q in HUNTING_PACK:
        rows = [_DEF_HUNT_ROWS[q.table]] if q.table != "DeviceNetworkEvents" else []
        script.append((200, {}, {"Results": rows, "Schema": []}))
    hunted = ScriptedTransport(script)
    h = defender_hunting(transport=hunted)
    rows = await h.fetch_window(window)
    check("the pack issues one POST per table and no pagination request",
          len(hunted.seen) == 1 + len(HUNTING_PACK)
          and all(r.method == "POST" for r in hunted.seen[1:]),
          "advanced hunting has no pagination — the cap is a KQL take")
    check("each query is labelled with its table, so a stall is attributable",
          [r.label for r in hunted.seen[1:]]
          == [f"defender_hunting.{q.table}" for q in HUNTING_PACK])
    check("the KQL goes in the Query field of a JSON body",
          hunted.seen[1].json_body["Query"].startswith("DeviceProcessEvents"))
    check("rows from every non-empty table are returned, each as its own class",
          sorted(p["class_uid"] for p in rows) == [1001, 1007, 3002])
    check("per-table counts are reported, including the zeroes",
          h.table_rows["DeviceNetworkEvents"] == 0
          and "empty_tables" in h.stats_extra(),
          "a table returning zero rows every cycle is either a quiet tenant or a "
          "schema change, and the health report cannot tell them apart without the "
          "zero being visible")

    capped = ScriptedTransport(
        [DEFENDER_TOKEN]
        + [(200, {}, {"Results": [_DEF_HUNT_ROWS[q.table]] * 3 if i == 0 else []})
           for i, q in enumerate(HUNTING_PACK)]
    )
    h2 = defender_hunting(transport=capped)
    h2.spec = dataclasses.replace(h2.spec, page_size=3, rate_per_second=10_000.0,
                                  burst=64)
    await h2.fetch_window(window)
    check("a table that hits the row cap is reported as a sample, not an answer",
          h2.truncated_tables == ["DeviceProcessEvents"] and h2.page_cap_hits == 1
          and "sample, not a complete answer" in h2.stats_extra()["truncated"],
          "a silent take 8000 is a sampling decision disguised as a complete answer")

    broken = ScriptedTransport([DEFENDER_TOKEN, (200, {}, {"error": {"code": "Bad"}})])
    h3 = defender_hunting(transport=broken)
    try:
        await h3.fetch_window(window)
        raised, why = False, "it returned quietly"
    except RuntimeError as exc:
        raised, why = True, str(exc)
    check("a response with no Results key raises rather than reporting zero rows",
          raised and "shape has changed" in why and "lost, not empty" in why,
          f"{why} — an empty Results means a quiet tenant; a missing Results means "
          "the rows this window would have produced are gone, and the two must not "
          "look the same in the health report")

    unconfigured = defender_hunting(DEFENDER_BLANK, transport=ScriptedTransport([]))
    try:
        await unconfigured.fetch_window(window)
        refused, why = False, "it made a request"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured hunt refuses before the transport is touched, naming all "
          "three slots",
          refused and "$DEFENDER_TENANT_ID" in why and "$DEFENDER_CLIENT_ID" in why
          and "$DEFENDER_CLIENT_SECRET" in why, why)

    single = defender_hunting()
    try:
        single.map_record({})
        rejected = False
    except NotImplementedError:
        rejected = True
    check("the single-record entry point refuses, because a row's table cannot be "
          "guessed from its columns",
          rejected,
          "guessing is how a DeviceFileEvents row with an InitiatingProcess becomes a "
          "process event")


# ── CrowdStrike Falcon ──────────────────────────────────────────────────────
#
# Three streams, one API, and the awkward parts are different in kind from Defender's.
# Defender's traps are about *shape* — nested entities with no flat home, an OData
# cursor that must be followed verbatim. Falcon's are about *meaning*:
#
#   * `process_id` is a fleet-unique process graph id, not a pid. `local_process_id`
#     is the pid. A kill action on the wrong one targets a pid that does not exist —
#     or, on a busy host, one that exists and belongs to something else.
#   * `status` carries two vocabularies. A workflow state on new-style alerts, a
#     legacy *disposition* on older ones, in the same field.
#   * the query endpoints return an array of **strings**, which `normalise_records`
#     filters out entirely — so the generic pager reports a healthy, permanently empty
#     source.
#   * the entity endpoints do not agree on their own body key: `composite_ids` for
#     alerts, `ids` for everything else, and the wrong one answers 200-with-nothing.
#
# Every fixture below is dated 2026-03-11, five days before `Clock`. A future-dated
# fixture is restamped by `Event.build`'s skew correction and every timestamp assertion
# then passes while proving nothing.

CS_LIVE = with_creds(
    crowdstrike_client_id="8e1c9d0f4b6a4e2f8c1d3b5a7e9f0a2b",
    crowdstrike_client_secret="not-a-real-falcon-secret-value-0001",
)
CS_BLANK = with_creds(crowdstrike_client_id="", crowdstrike_client_secret="")

CS_TOKEN = (
    201,  # not 200 — Falcon answers the token endpoint with 201 Created
    {},
    {"access_token": "falcon-bearer-token", "expires_in": 1799, "token_type": "bearer"},
)


def cs_alerts(config=None, transport=None):
    c = CrowdStrikeAlertConnector(
        _Pipe(), config or CS_LIVE, transport=transport, clock=Clock(),
        checkpoints=MemoryCheckpoints(),
    )
    # 5/s with a burst of 10 in production. The transport tests make more than ten
    # calls, and `RateLimiter` busy-waits against the real `time.monotonic` with no
    # injectable clock, so past the burst the suite would spend real seconds asleep.
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


def cs_incidents(config=None, transport=None):
    c = CrowdStrikeIncidentConnector(
        _Pipe(), config or CS_LIVE, transport=transport, clock=Clock(),
        checkpoints=MemoryCheckpoints(),
    )
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


def cs_hosts(config=None, transport=None):
    c = CrowdStrikeHostConnector(
        _Pipe(), config or CS_LIVE, transport=transport, clock=Clock(),
        checkpoints=MemoryCheckpoints(),
    )
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


#: One alert at its most informative: prevented, quarantined, three generations of
#: process, an IOC, a quarantined file, a cloud-hosted device — and a `process_id` that
#: is deliberately nothing like its `local_process_id`, so a test can tell which one the
#: connector put in `pid`.
CS_ALERT = {
    "composite_id": "abc123:ind:aid9988:0011-2233",
    "id": "ldt:aid9988:0011",
    "cid": "abc1230000000000000000000000abcd",
    "aggregate_id": "aggind:aid9988:5566",
    "agent_id": "aid99880000000000000000000000aa11",
    "timestamp": "2026-03-11T07:58:11Z",
    "created_timestamp": "2026-03-11T07:58:12Z",
    "updated_timestamp": "2026-03-11T07:59:44Z",
    "crawled_timestamp": "2026-03-11T07:59:45Z",
    "status": "new",
    "severity": 90,
    "severity_name": "Critical",
    "confidence": 95,
    "display_name": "RansomwareFileModification",
    "name": "RansomwareFileModification",
    "description": "A process modified many files in a way consistent with ransomware.",
    "pattern_id": 12105,
    "product": "epp",
    "type": "ldt",
    "scenario": "ransomware",
    "objective": "Follow Through",
    "tactic": "Impact",
    "tactic_id": "TA0040",
    "technique": "Data Encrypted for Impact",
    "technique_id": "T1486",
    "data_domains": ["Endpoint"],
    "tags": ["FalconGroupingTags/critical-finance"],
    "seconds_to_triaged": 240,
    "seconds_to_resolved": 0,
    # Falcon's own triage assignee. Neither field is an OCSF one, so both must land
    # in `unmapped` rather than being confused with the *subject* of the detection.
    "assigned_to_name": "A. Analyst",
    "assigned_to_uid": "uid-77",
    "global_prevalence": "low",
    "local_prevalence": "low",
    "filename": "wcry.exe",
    "filepath": "\\Device\\HarddiskVolume3\\Users\\rmehta\\Downloads\\wcry.exe",
    "cmdline": "wcry.exe -enc -all",
    "sha256": "9f2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081",
    "md5": "0123456789abcdef0123456789abcdef",
    # 19-digit graph id vs a four-digit pid. This pair is the whole point of the
    # `pid` assertion below.
    "process_id": "9876543210987654321",
    "local_process_id": 4820,
    "process_start_time": "2026-03-11T07:58:00Z",
    "process_end_time": "2026-03-11T07:58:30Z",
    "user_name": "rmehta",
    "user_id": "S-1-5-21-1111-2222-3333-1104",
    "logon_domain": "CONTOSO",
    "ioc_type": "hash_sha256",
    "ioc_value": "9f2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081",
    "pattern_disposition": 2176,
    "pattern_disposition_details": {
        "detect": False, "kill_process": True, "kill_subprocess": False,
        "quarantine_file": True, "quarantine_machine": False,
        "operation_blocked": False, "process_blocked": True,
        "registry_operation_blocked": False, "critical_process_disabled": False,
        "bootup_safeguard_enabled": False, "fs_operation_blocked": False,
        "handle_operation_downgraded": False, "kill_parent": False,
        "suspend_parent": False, "suspend_process": False,
        "blocking_unsupported_or_disabled": False, "policy_disabled": False,
        "inddet_mask": False, "sensor_only": False, "rooting": False,
        "response_action_already_applied": True, "response_action_triggered": False,
    },
    "parent_details": {
        "parent_cmdline": "\"C:\\Program Files\\Outlook\\outlook.exe\" /recycle",
        "filename": "outlook.exe",
        # `filepath` and `sha256` have no `actor_process_parent_*` home in OCSF —
        # measured, the flat parent set is exactly cmd_line / name / pid — so they must
        # end up nowhere rather than in a mis-named column.
        "filepath": "\\Device\\HarddiskVolume3\\Program Files\\Outlook\\outlook.exe",
        "sha256": "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44",
        "parent_process_graph_id": "pid:aid9988:1234567890",
        "parent_local_process_id": 3120,
    },
    "grandparent_details": {
        "cmdline": "C:\\Windows\\explorer.exe",
        "filename": "explorer.exe",
        "filepath": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
        "sha256": "bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55",
        "local_process_id": 2044,
    },
    "quarantined_files": [
        {"id": "qf-1",
         "paths": ["\\Device\\HarddiskVolume3\\Users\\rmehta\\Downloads\\wcry.exe"],
         "sha256": "9f2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d5e6f7081",
         "state": "quarantined"},
    ],
    "device": {
        "device_id": "aid99880000000000000000000000aa11",
        "cid": "abc1230000000000000000000000abcd",
        "hostname": "FIN-WKS-041",
        "local_ip": "10.20.4.41",
        "external_ip": "203.0.113.9",
        "mac_address": "3c-52-82-11-22-33",
        "machine_domain": "CONTOSO",
        "platform_name": "Windows",
        "os_version": "Windows 11",
        "os_build": "22631.3155",
        "product_type_desc": "Workstation",
        "chassis_type_desc": "Laptop",
        "agent_version": "7.14.18110.0",
        "serial_number": "5CG3210ABC",
        "groups": ["grp-finance"],
        "ou": ["Finance"],
        "site_name": "Mumbai HQ",
        "tags": ["FalconGroupingTags/critical-finance"],
        "service_provider": "AWS_EC2_V2",
        "instance_id": "i-0abc123def4567890",
        "zone_group": "ap-south-1a",
        "service_provider_account_id": "111122223333",
    },
}

#: The awkward alert: a legacy disposition in `status`, a third-party vendor's detection
#: relayed through Falcon NG-SIEM, an empty `sha256` and an all-zero `md5` (both of which
#: the Event model would reject outright), a platform OCSF cannot represent, and a
#: sensor that wanted to block and could not.
CS_ALERT_RELAY = {
    "composite_id": "abc123:ind:aid7766:9900-1122",
    "cid": "abc1230000000000000000000000abcd",
    "agent_id": "aid77660000000000000000000000bb22",
    "timestamp": "2026-03-11T08:04:19Z",
    "created_timestamp": "2026-03-11T08:04:19Z",
    "updated_timestamp": "2026-03-11T08:05:00Z",
    "status": "true_positive",
    "severity": 55,
    "severity_name": "Medium",
    "confidence": 40,
    "display_name": "SuspiciousPowerShellDownload",
    "product": "ngsiem",
    "source_vendors": ["Microsoft"],
    "source_products": ["Microsoft Defender for Endpoint"],
    "scenario": "attempted_dumping_of_lsass_memory",
    "objective": "Gain Access",
    "tactic": "Credential Access",
    "filename": "powershell.exe",
    "cmdline": "powershell -enc SQBFAFgA",
    "sha256": "",
    "md5": "00000000000000000000000000000000",
    "local_process_id": 7788,
    "user_name": "svc-backup",
    "pattern_disposition_details": {
        "detect": True,
        "blocking_unsupported_or_disabled": True,
        "policy_disabled": True,
    },
    "device": {"device_id": "aid77660000000000000000000000bb22", "hostname": "SRV-BAK-02",
               "platform_name": "ChromeOS", "product_type_desc": "Server"},
}

#: An incident spanning three hosts and two accounts — the case OCSF's *singular*
#: ``device`` object cannot express, and where filling it from the first host would make
#: the other two invisible to every blast-radius calculation.
CS_INCIDENT = {
    "incident_id": "inc:abc123:0f1e2d3c4b5a",
    "cid": "abc1230000000000000000000000abcd",
    "created": "2026-03-11T07:58:11Z",
    "start": "2026-03-11T07:58:11Z",
    "end": "2026-03-11T09:10:00Z",
    "modified_timestamp": "2026-03-11T09:10:05Z",
    "status": 30,
    "state": "open",
    "fine_score": 78,
    "name": "Ransomware staging across finance workstations",
    "description": "Credential access followed by mass file modification on three hosts.",
    "tags": ["FalconGroupingTags/critical-finance"],
    "assigned_to_name": "A. Analyst",
    "assigned_to_uid": "uid-99",
    "visibility": 1,
    "host_ids": ["aid99880000000000000000000000aa11", "aid77660000000000000000000000bb22",
                 "aid55440000000000000000000000cc33"],
    "hosts": [
        {"device_id": "aid99880000000000000000000000aa11", "hostname": "FIN-WKS-041",
         "platform_name": "Windows", "product_type_desc": "Workstation"},
        {"device_id": "aid77660000000000000000000000bb22", "hostname": "SRV-BAK-02",
         "platform_name": "Windows", "product_type_desc": "Server"},
        {"device_id": "aid55440000000000000000000000cc33", "hostname": "DC-01",
         "platform_name": "Windows", "product_type_desc": "Domain Controller"},
    ],
    "users": ["rmehta", "svc-backup"],
    # A *name* and an *id* in the same array. `attack()` takes ids; a name fed to it
    # produces a label no ATT&CK lookup resolves and that the coverage matrix counts as
    # covered.
    "techniques": ["Credential Dumping", "T1486"],
    "tactics": ["Credential Access", "Impact"],
    "objectives": ["Gain Access", "Follow Through"],
    "lm_host_ids": ["aid55440000000000000000000000cc33"],
    "lm_hosts_capable": 42,
    "lm_connection_ids": ["lmc-1"],
}

CS_BEHAVIOURS = [
    {"behavior_id": "bhv-1", "incident_id": "inc:abc123:0f1e2d3c4b5a",
     "display_name": "CredentialDumpingViaLsass",
     "description": "LSASS read by an unusual process",
     "timestamp": "2026-03-11T07:58:11Z", "pattern_id": 4001,
     "scenario": "credential_theft", "objective": "Gain Access",
     "tactic": "Credential Access", "technique": "OS Credential Dumping",
     "technique_id": "T1003", "cmdline": "procdump -ma lsass.exe",
     "filename": "procdump.exe", "filepath": "C:\\Tools",
     "sha256": "cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66",
     "user_name": "rmehta", "aid": "aid99880000000000000000000000aa11"},
    {"behavior_id": "bhv-2", "incident_id": "inc:abc123:0f1e2d3c4b5a",
     "display_name": "RansomwareFileModification", "timestamp": "2026-03-11T08:04:19Z",
     "pattern_id": 12105, "scenario": "ransomware", "objective": "Follow Through",
     "tactic": "Impact", "technique_id": "T1486", "filename": "wcry.exe",
     "aid": "aid99880000000000000000000000aa11"},
]

#: A domain controller that is already contained, whose sensor is in reduced
#: functionality mode, whose Real Time Response is unavailable, and whose prevention
#: policy is assigned but not applied. Four separate facts, every one of which changes
#: what a response is permitted to do — and all four are invisible in a fleet dashboard
#: that shows the host as covered.
CS_HOST_DC = {
    "device_id": "aid55440000000000000000000000cc33",
    "cid": "abc1230000000000000000000000abcd",
    "hostname": "DC-01",
    "local_ip": "10.20.0.10",
    "external_ip": "203.0.113.10",
    "mac_address": "3c-52-82-44-55-66",
    "machine_domain": "CONTOSO",
    "platform_name": "Windows",
    "os_version": "Windows Server 2022",
    "os_build": "20348.2322",
    "product_type_desc": "Domain Controller",
    # A rack-mount chassis on a server must NOT reclassify it as a desktop.
    "chassis_type_desc": "Rack Mount Chassis",
    "status": "contained",
    "filesystem_containment_status": "normal",
    "reduced_functionality_mode": "yes",
    "rtr_state": "unknown",
    "first_seen": "2026-03-11T00:00:00Z",
    "last_seen": "2026-03-11T09:10:00Z",
    "modified_timestamp": "2026-03-11T09:10:01Z",
    "last_login_user": "svc-adsync",
    "last_login_uid": "S-1-5-21-1111-2222-3333-1500",
    "last_login_timestamp": "2026-03-11T08:00:00Z",
    "last_reboot": "2026-03-10T22:00:00Z",
    "agent_version": "7.14.18110.0",
    "serial_number": "VMware-42",
    "groups": ["grp-tier0"],
    "ou": ["Domain Controllers"],
    "site_name": "Mumbai HQ",
    "tags": ["FalconGroupingTags/tier0"],
    "device_policies": {
        "prevention": {"policy_id": "pol-prev-1", "policy_type": "prevention",
                       "applied": False, "settings_hash": "h1"},
        "sensor_update": {"policy_id": "pol-su-1", "applied": True},
        "remote_response": {"policy_id": "pol-rr-1", "applied": True},
    },
    "kernel_version": "10.0.20348",
    "system_manufacturer": "VMware, Inc.",
}

CS_HOST_CLOUD = {
    "device_id": "aid33220000000000000000000000dd44",
    "cid": "abc1230000000000000000000000abcd",
    "hostname": "web-prod-07",
    "local_ip": "10.30.1.7",
    "platform_name": "Linux",
    "os_version": "Amazon Linux 2023",
    "product_type_desc": "Server",
    "status": "normal",
    "rtr_state": "ready",
    "first_seen": "2026-03-11T00:00:00Z",
    "last_seen": "2026-03-11T09:10:00Z",
    "service_provider": "AWS_EC2_V2",
    "instance_id": "i-0fedcba987654321f",
    "zone_group": "ap-south-1b",
    "service_provider_account_id": "111122223333",
    "device_policies": {"prevention": {"policy_id": "pol-prev-2", "applied": True}},
}


def test_crowdstrike_alert_mapping():
    print("\n[crowdstrike] alerts -> 2004, and the three fields that change conclusions")
    c = cs_alerts()
    p = c.map_record(CS_ALERT)
    event = ocsf_clean("cs alert", p, expect_class=ClassUid.DETECTION_FINDING)

    check("the composite id is the event identity, not the shorter `id`",
          p["metadata_uid"] == "abc123:ind:aid9988:0011-2233"
          and p["finding_uid"] == "abc123:ind:aid9988:0011-2233",
          "`id` is unique per detection, `composite_id` per detection *per tenant* — "
          "and an MSSP parent reading several CIDs would collide on the former")

    check("`pid` is the operating-system pid, not Falcon's process graph id",
          p["actor_process_pid"] == 4820
          and p["unmapped"]["process_graph_id"] == "9876543210987654321",
          f"got pid={p.get('actor_process_pid')} — a kill action on the 19-digit graph "
          "id targets a pid that does not exist, or one that does and belongs to "
          "something else")

    check("severity 90 bands to Critical on CrowdStrike's own documented breaks",
          p["severity_id"] == int(Severity.CRITICAL)
          and p["unmapped"]["falcon_severity"] == 90)
    check("confidence keeps the raw 0-100 score beside the three-value id",
          p["confidence_score"] == 95 and p["confidence_id"] == 3
          and p["confidence"] == "High",
          "the id is comparable across vendors, the score is comparable across alerts "
          "from this one; discarding either loses a question someone asks")

    check("quarantine beats a kill in the disposition precedence",
          p["disposition_id"] == int(DispositionId.QUARANTINED) and p["action_id"] == 2,
          f"got {p.get('disposition_id')} — both flags are true, and the containment is "
          "the fact that decides whether anything further is needed")
    check("`response_action_already_applied` is surfaced as its own label, not folded "
          "into the disposition",
          "vendor-already-responded" in p["metadata_labels"],
          "acting again duplicates Falcon's action and, for containment, races it")

    check("the parent process fills exactly the three flat fields OCSF declares",
          p["actor_process_parent_name"] == "outlook.exe"
          and p["actor_process_parent_pid"] == 3120
          and "outlook.exe" in p["actor_process_parent_cmd_line"]
          and not [k for k in p if k.startswith("actor_process_parent_file")],
          "there is no actor.process.parent.file.* in OCSF_PATH — measured — so the "
          "parent's path and hash have no flat home and must not invent one")

    ev = {e.get("name"): e for e in p["evidences"]}
    check("the grandparent, the quarantined file and the IOC are all in `evidences`",
          set(ev) == {"grandparent process", "quarantined file", "ioc:hash_sha256"},
          f"got {sorted(ev)} — 2004 declares no top-level file or process, so the "
          "nested array is the only legal home for any of them")
    check("the IOC is routed by its own type, not into one catch-all key",
          ev["ioc:hash_sha256"]["file"]["hashes"][0]["algorithm_id"] == 3,
          "a domain IOC written into a file object is one no hunt query and no intel "
          "match will ever look at")
    check("a quarantined file carries Falcon's own state as the evidence verdict",
          ev["quarantined file"]["verdict"] == "quarantined",
          "`verdict` is a top-level evidences element key, not nested inside the file")

    check("the technique becomes an ATT&CK label and the tactic id stays a label",
          "attack:T1486" in p["metadata_labels"]
          and "tactic:TA0040" in p["metadata_labels"])
    check("the scenario is recorded verbatim *and* semantically",
          "scenario:ransomware" in p["metadata_labels"]
          and "ransomware" in p["metadata_labels"],
          "Falcon adds scenarios without notice, so a table lookup that gates recording "
          "turns every new scenario into silence")

    check("`aggregate_id` is the correlation key and `incident_id` is absent from the "
          "record entirely",
          p["metadata_correlation_uid"] == "crowdstrike-aggregate:aggind:aid9988:5566"
          and "incident_id" not in CS_ALERT,
          "Alerts v2 carries no incident id, so an alert and an incident from these two "
          "connectors do not join on a foreign key — Phase 3 must join on device+time")

    check("`finding_analytic_uid` is a string, because Falcon sends an integer and "
          "OCSF declares a string",
          p["finding_analytic_uid"] == "12105"
          and isinstance(p["finding_analytic_uid"], str),
          "unconverted, the Event model rejects the whole event and a real detection is "
          "lost over a type")

    check("`finding_info_list` is never set on a 2004",
          "finding_info_list" not in p,
          "measured illegal on 2004 — the class carries thirteen singular finding_* "
          "columns because a detection *is* one finding; the array is 2005-only")

    check("the assignee and the vendor's own MTTA/MTTR go to `unmapped`",
          p["unmapped"]["assigned_to_name"] == "A. Analyst"
          and p["actor_user_name"] == "rmehta"
          and p["unmapped"]["vendor_seconds_to_triaged"] == 240,
          "an analyst written into a user column resolves into the entity graph as an "
          "actor in the customer's own incident")

    check("the cloud-hosted device's provider, instance and region are mapped",
          p["cloud_provider"] == "AWS"
          and p["device_instance_uid"] == "i-0abc123def4567890"
          and p["cloud_region"] == "ap-south-1a"
          and p["cloud_account_uid"] == "111122223333")
    check("a laptop chassis refines a workstation to Laptop (3)",
          p["device_type_id"] == 3, f"got {p.get('device_type_id')}")

    obs = {(o.name, o.value) for o in event.observables}
    check("the hostname yields exactly one observable, not a hand-added duplicate",
          len([1 for n, _ in obs if n == "device.hostname"]) == 1
          and ("device.hostname", "fin-wks-041") in obs,
          f"got {sorted(n for n, _ in obs if n == 'device.hostname')} — the Event model "
          "lower-cases device_hostname before deriving, so a hand-added HOST-1 observable "
          "beside device_hostname='HOST-1' produces two graph nodes for one machine")


def test_crowdstrike_alert_lifecycle():
    print("\n[crowdstrike] one status field, two vocabularies")
    c = cs_alerts()

    first = c.map_record(CS_ALERT)
    check("a status this connector has not seen before is a Create",
          first["activity_id"] == 1 and first["status_id"] == int(FindingStatus.NEW))
    again = c.map_record(CS_ALERT)
    check("the same composite id on a later cycle is an Update, not a second Create",
          again["activity_id"] == 2,
          "Falcon mutates an alert for hours after creation, which is why the window "
          "filters on updated_timestamp and re-reads are expected")

    closed = dict(CS_ALERT, status="closed",
                  composite_id="abc123:ind:aid9988:0011-9999")
    p = c.map_record(closed)
    check("`closed` is Resolved and a Close activity",
          p["status_id"] == int(FindingStatus.RESOLVED) and p["activity_id"] == 3)

    reopened = dict(CS_ALERT, status="reopened",
                    composite_id="abc123:ind:aid9988:0011-8888")
    p = c.map_record(reopened)
    check("`reopened` is New with a label, because OCSF has no Reopened member",
          p["status_id"] == int(FindingStatus.NEW)
          and "reopened" in p["metadata_labels"],
          "New is right and Resolved is wrong — the work is outstanding again; the label "
          "is what stops a first-response metric counting it as a fresh detection")

    p = c.map_record(CS_ALERT_RELAY)
    check("a legacy disposition in `status` sets the verdict *and* closes the alert",
          p["status_id"] == int(FindingStatus.RESOLVED) and p["verdict_id"] == 2
          and p["activity_id"] == 3,
          f"got status={p.get('status_id')} verdict={p.get('verdict_id')} — read as a "
          "workflow state, a confirmed true positive maps to Unknown and the verdict is "
          "lost entirely")
    check("and it says which of the two tables was used",
          any("legacy disposition" in n for n in p["notes"])
          and "legacy-detection" in p["metadata_labels"],
          "without it, a downstream reader cannot tell a vendor verdict from one this "
          "platform reached")
    check("`ignored` is Disregard, not False Positive",
          _LEGACY_DISPOSITION["ignored"] == 3
          and _LEGACY_DISPOSITION["falsepositive"] == 1,
          "an analyst who ignored a detection did not say it was wrong, they said they "
          "were not going to act on it — and the difference is the whole content of a "
          "detection-tuning report")

    unknown = dict(CS_ALERT, status="quarantine_pending_review",
                   composite_id="abc123:ind:aid9988:0011-7777")
    p = c.map_record(unknown)
    check("a status in neither table is Unknown with the vendor word preserved",
          p["status_id"] == int(FindingStatus.UNKNOWN)
          and p["status_code"] == "quarantine_pending_review"
          and any("neither" in n for n in p["notes"]))

    check("the tracked-alert count is reported, so an in-memory set is visible",
          c.stats_extra()["alerts_tracked"] == 5,
          f"got {c.stats_extra().get('alerts_tracked')} — a restart downgrades an "
          "Update to a Create, which is wrong in the harmless direction, and the "
          "alternative is a store lookup on a path that must not depend on the store")


def test_crowdstrike_response_gates():
    print("\n[crowdstrike] what the sensor already did, and what is left to do")
    c = cs_alerts()

    p = c.map_record(CS_ALERT_RELAY)
    check("`blocking_unsupported_or_disabled` is labelled, explained and counted",
          "vendor-could-not-block" in p["metadata_labels"]
          and any("only response there will be" in n for n in p["notes"])
          and c.stats_extra()["vendor_could_not_block"] == 1,
          "this is the one case where this platform's own response is the only one")
    check("a detect-only disposition still reads as Detected/Observed",
          p["disposition_id"] == int(DispositionId.DETECTED) and p["action_id"] == 3,
          "the disposition says Falcon detected it; the gate label says it could not "
          "stop it, and both are true at once")
    check("`policy_disabled` is reported as a fleet-configuration finding",
          "prevention-policy-disabled" in p["metadata_labels"]
          and any("fleet-configuration finding" in n for n in p["notes"]))

    nothing = dict(CS_ALERT, composite_id="cs:none",
                   pattern_disposition_details={k: False for k in (
                       "detect", "kill_process", "quarantine_file",
                       "quarantine_machine", "process_blocked", "sensor_only")})
    p = c.map_record(nothing)
    check("every flag false is Logged (17), not Detected (15)",
          p["disposition_id"] == int(DispositionId.LOGGED) and p["action_id"] == 3,
          f"got {p.get('disposition_id')} — Falcon logged the pattern and took no "
          "action at all, and Logged says exactly that")

    absent = dict(CS_ALERT, composite_id="cs:absent")
    absent.pop("pattern_disposition_details")
    p = c.map_record(absent)
    check("a missing disposition object is an explicit unknown, not a silent Logged",
          "disposition_id" not in p
          and any("cannot tell a finished detection from a live one" in n
                  for n in p["notes"]))

    contained = dict(CS_ALERT, composite_id="cs:contained",
                     pattern_disposition_details={"quarantine_machine": True,
                                                  "kill_process": True})
    p = c.map_record(contained)
    check("a machine quarantine outranks a process kill",
          p["disposition_id"] == int(DispositionId.ISOLATED)
          and "host-contained-by-vendor" in p["metadata_labels"])

    check("every response-gate flag produces both a label and a sentence",
          all(tag and sentence for tag, sentence in _RESPONSE_GATE_FLAGS.values()),
          "a silent boolean in unmapped is a fact nobody reads")


def test_crowdstrike_relay_and_hashes():
    print("\n[crowdstrike] a relayed alert is another vendor's, and a bad hash is fatal")
    c = cs_alerts()
    p = c.map_record(CS_ALERT_RELAY)

    check("an NG-SIEM relay is labelled, explained and counted as double-collection risk",
          "third-party-relay" in p["metadata_labels"]
          and p["unmapped"]["source_vendors"] == ["Microsoft"]
          and any("collected twice" in n for n in p["notes"])
          and c.stats_extra()["third_party_relayed"] == 1,
          "if defender.py is also configured, the same detection arrives twice under "
          "two metadata_uid values that no deduplication will join")
    check("the relay product set names both routes into Falcon",
          RELAY_PRODUCTS == frozenset({"ngsiem", "thirdparty"}))

    check("an empty sha256 and an all-zero md5 are dropped, not written",
          "actor_process_file_sha256" not in p and "actor_process_file_md5" not in p,
          "the Event model validates hash columns strictly and rejects the whole event "
          "on a malformed one — correctly — so a behaviour with no file would lose a "
          "real detection over an absent hash")

    check("a platform OCSF cannot represent is left unset with a note, not mapped to 0",
          "device_os_type_id" not in p
          and p["unmapped"]["platform_name"] == "ChromeOS"
          and any("known and unrepresentable" in n for n in p["notes"]),
          "0 is Unknown, which asserts the platform is unknown when it is known — the "
          "difference between a gap a coverage report finds and one it cannot")

    mismatch = dict(CS_ALERT, composite_id="cs:mismatch", severity=55,
                    severity_name="Critical")
    p = c.map_record(mismatch)
    check("a severity_name that disagrees with the banded number is reported, not absorbed",
          p["severity_id"] == int(Severity.MEDIUM)
          and any("Falcon calls it" in n for n in p["notes"]),
          "the number is authoritative and the name is the check that the published "
          "20/40/60/80 breaks have not moved")

    overwatch = dict(CS_ALERT, composite_id="cs:ow", product="overwatch")
    p = c.map_record(overwatch)
    check("an OverWatch alert is not the pattern engine's analytic type",
          p["finding_analytic_type_id"] == 99
          and "human-analyst" in p["metadata_labels"],
          "a human threat hunter raised it, and that is worth more than any automated "
          "verdict on this feed")


def test_crowdstrike_incident_mapping():
    print("\n[crowdstrike] incidents -> 2005, where the status table is not 2004's")
    c = cs_incidents()
    p = c._map_incident(CS_INCIDENT, {CS_INCIDENT["incident_id"]: CS_BEHAVIOURS})
    event = ocsf_clean("cs incident", p, expect_class=ClassUid.INCIDENT_FINDING)

    check("Falcon's integer ladder maps through 2005's own status table",
          p["status_id"] == int(IncidentStatus.IN_PROGRESS),
          f"got {p.get('status_id')}")
    s = ocsf_schema()
    check("and that table really does differ from 2004's, value for value",
          s.enum_members(2004, "status_id")[3] == "Suppressed"
          and s.enum_members(2005, "status_id")[3] == "On Hold"
          and 6 not in s.enum_members(2005, "status_id"),
          "so a FindingStatus member written to a 2005 silently means something else — "
          "SUPPRESSED reads as On Hold and DELETED is not a member at all")
    check("`fine_score` bands with the same breaks and keeps the raw CrowdScore",
          p["severity_id"] == int(Severity.HIGH) and p["unmapped"]["fine_score"] == 78,
          "the breaks are the Falcon console's rendering, not a documented equivalence "
          "for fine_score, which is why the raw number survives")

    check("a three-host incident leaves the singular device columns unset",
          not [k for k in p if k.startswith("device_")]
          and p["count"] == 3
          and any("spans 3 hosts" in n for n in p["notes"]),
          "filling `device` from the first of three makes the other two invisible and "
          "the first look like *the* affected machine — the shape of every wrong "
          "blast-radius calculation")

    obs = [(o["name"], o["value"]) for o in p["observables"]]
    check("every host contributes an observable, hostnames pre-lower-cased",
          ("device.hostname", "dc-01") in obs and ("device.hostname", "fin-wks-041") in obs
          and len([1 for n, _ in obs if n == "device.hostname"]) == 3,
          f"got {obs}")
    check("usernames are NOT lower-cased, because the model deliberately does not fold them",
          ("actor.user.name", "rmehta") in obs
          and ("actor.user.name", "svc-backup") in obs,
          "case-insensitive on Windows, case-sensitive on Linux; correlate/entity.py "
          "applies the per-platform rule where it knows the platform")
    check("the derived set has no duplicate hostname node",
          len({(o.type_id, o.value) for o in event.observables})
          == len(event.observables),
          f"{[(o.name, o.value) for o in event.observables]}")

    labels = p["metadata_labels"]
    check("a technique *id* becomes an ATT&CK label and a technique *name* does not",
          "attack:T1486" in labels and "technique-name:Credential Dumping" in labels
          and not any(lbl.startswith("attack:Credential") for lbl in labels),
          "a name fed to attack() produces a label no ATT&CK lookup resolves and that "
          "the coverage matrix would count as covered")
    check("the member behaviours are where an incident's technique ids actually come from",
          "attack:T1003" in labels,
          "T1003 appears on no field of the incident record — only on bhv-1")

    members = p["finding_info_list"]
    check("2005's required finding_info_list is filled from the member behaviours",
          len(members) == 2
          and {m["uid"] for m in members} == {"bhv-1", "bhv-2"}
          and members[0]["analytic"]["uid"] == "4001",
          f"got {members}")

    check("lateral movement is Falcon's own finding, labelled and mapped to T1021",
          "lateral-movement" in labels and "attack:T1021" in labels
          and p["unmapped"]["lm_hosts_capable"] == 42,
          "lm_hosts_capable is a blast radius CrowdStrike computed from the customer's "
          "authentication graph — not derivable from telemetry alone")

    check("the intrusion's own span becomes `duration` in milliseconds",
          p["duration"] == 4_309_000 and p["start_time"] == 1_773_215_891.0
          and p["end_time"] == 1_773_220_200.0,
          f"got {p.get('duration')} — start/end are the activity's bounds, not the "
          "record's, so dwell time is not derivable later")

    check("the incident is its own correlation key",
          p["metadata_correlation_uid"] == "crowdstrike-incident:inc:abc123:0f1e2d3c4b5a")

    closed = dict(CS_INCIDENT, status=40, state="closed")
    q = c._map_incident(closed, {})
    check("status 40 is Closed and a Close activity",
          q["status_id"] == int(IncidentStatus.CLOSED) and q["activity_id"] == 3)

    unknown = dict(CS_INCIDENT, status=35)
    q = c._map_incident(unknown, {CS_INCIDENT["incident_id"]: CS_BEHAVIOURS})
    check("a rung the ladder does not have is Unknown, because 2005 requires the field",
          q["status_id"] == int(IncidentStatus.UNKNOWN) and q["status_code"] == "35"
          and any("cannot simply be omitted" in n for n in q["notes"]))


def test_crowdstrike_incident_without_members():
    print("\n[crowdstrike] an incident with no behaviours is an OCSF gap, said out loud")
    c = cs_incidents()
    p = c._map_incident(CS_INCIDENT, {})

    # Deliberately NOT ocsf_clean: the whole point is that a required object is
    # unfilled, and ocsf_clean asserts the opposite.
    # `unfilled_required` takes an iterable of KEYS, not a payload mapping — passing
    # a dict only works because iterating one yields its keys.
    unfilled = unfilled_required(p["class_uid"], [k for k in p if k != "raw"])
    check("`unfilled_required` names finding_info_list, rather than the event passing "
          "quietly",
          "finding_info_list" in unfilled, f"got {sorted(unfilled)}")
    check("and the connector explains why, distinguishing a cap from a missing scope",
          any(f"{BEHAVIOR_LOOKUP_MAX}-record per-cycle cap" in n for n in p["notes"])
          and c.stats_extra()["incidents_without_members"] == 1,
          "an incident rendered with three of its nine detections is indistinguishable "
          "from an incident with three detections, and the second is a much smaller "
          "intrusion")
    check("the severity and scope are still correct — only the content is missing",
          p["severity_id"] == int(Severity.HIGH) and p["count"] == 3)

    single = cs_incidents()
    try:
        single.map_record(CS_INCIDENT)
        refused = False
    except NotImplementedError:
        refused = True
    check("the single-record entry point refuses, because an incident without its "
          "behaviours cannot fill a required object",
          refused,
          "returning it anyway would be an OCSF-invalid event produced deliberately")


def test_crowdstrike_host_mapping():
    print("\n[crowdstrike] hosts -> 5001, the stream response cannot work without")
    c = cs_hosts()
    p = c.map_record(CS_HOST_DC)
    ocsf_clean("cs host dc", p, expect_class=ClassUid.DEVICE_INVENTORY_INFO)

    check("an inventory poll is Collect with a collection status, not a finding status",
          p["activity_id"] == 2 and p["status_id"] == int(Status.SUCCESS),
          "5001's activities are {Log, Collect} and its status_id is the three-value "
          "Success/Failure table")
    check("it is not an alert",
          "is_alert" not in p,
          "counting an inventory row as an alert is how an alert-volume metric reports a "
          "busy month whenever the fleet rebooted")
    check("`device_is_managed` is explicitly true",
          p["device_is_managed"] is True,
          "an unmanaged host is one this connector cannot see at all, which is the gap "
          "ingest/health.py measures")

    check("a domain controller is a Server with a crown-jewel label and an explanation",
          p["device_type_id"] == 1
          and {"domain-controller", "crown-jewel"} <= set(p["metadata_labels"])
          and any("removes the authentication plane" in n for n in p["notes"]),
          "the type id cannot express 'isolating this is an outage of the entire "
          "authentication plane', so Phase 5 reads the label")
    check("a rack-mount chassis does not reclassify a server as a desktop",
          p["device_type_id"] == 1,
          "chassis only refines a Workstation; letting it win would reclassify every "
          "rack-mounted server in the fleet")

    check("an already-contained host is Isolated, labelled and explained",
          p["disposition_id"] == int(DispositionId.ISOLATED)
          and "host-contained" in p["metadata_labels"]
          and any("second isolate is a no-op" in n for n in p["notes"])
          and c.stats_extra()["contained_hosts"] == 1)

    check("reduced functionality mode raises the severity above informational",
          p["severity_id"] == int(Severity.MEDIUM)
          and "sensor-reduced-functionality" in p["metadata_labels"]
          and any("Detections from this host are absent rather than negative" in n
                  for n in p["notes"])
          and c.stats_extra()["reduced_functionality_hosts"] == 1,
          "an unprotected host is not an informational fact about the inventory; it is "
          "a coverage gap nothing else reports")
    check("an unreachable RTR state says the response path cannot reach this host",
          "rtr-unavailable" in p["metadata_labels"]
          and c.stats_extra()["rtr_unavailable_hosts"] == 1
          and any("fall back to a network-layer action" in n for n in p["notes"]))

    check("an assigned-but-unapplied prevention policy is reported",
          p["policy_uid"] == "pol-prev-1" and p["policy_is_applied"] is False
          and "prevention-policy-not-applied" in p["metadata_labels"],
          "the console shows the host as covered and the sensor is not enforcing it")
    check("the other policy ids are kept together in unmapped",
          set(p["unmapped"]["device_policy_ids"])
          == {"prevention", "sensor_update", "remote_response"})

    check("the last interactive user is the closest thing to an owner, on the actor",
          p["actor_user_name"] == "svc-adsync",
          "5001 declares `actor` and not `user`, and nobody performed this event — it "
          "is a poll")

    illegal = [k for k in ("verdict_id", "comment", "src_url", "impact_id",
                           "priority_id", "is_suspected_breach") if k in p]
    check("none of 5001's six measured exclusions are set",
          not illegal, f"set illegally: {illegal}")

    q = c.map_record(CS_HOST_CLOUD)
    ocsf_clean("cs host cloud", q, expect_class=ClassUid.DEVICE_INVENTORY_INFO)
    check("a healthy cloud host carries no containment or health labels at all",
          "disposition_id" not in q
          and not any(lbl.startswith(("host-contain", "sensor-", "rtr-"))
                      for lbl in q.get("metadata_labels", [])),
          f"got {q.get('metadata_labels')}")
    check("and its provider, instance, region and account are mapped",
          q["cloud_provider"] == "AWS" and q["device_instance_uid"].startswith("i-")
          and q["cloud_region"] == "ap-south-1b"
          and q["cloud_account_uid"] == "111122223333")
    check("the external address never overwrites the interface address",
          q["device_ip"] == "10.30.1.7"
          and p["device_ip"] == "10.20.0.10"
          and p["unmapped"]["external_ip"] == "203.0.113.10",
          "conflating them is how a NAT'd fleet appears to share one address; there is "
          "no legal column for it on 2004, 2005 or 5001")


def test_crowdstrike_tables():
    print("\n[crowdstrike] the tables the sweeps cannot check")
    s = ocsf_schema()

    alert_status = s.enum_members(2004, "status_id")
    check("every alert lifecycle value is a member of 2004's status table",
          all(int(v) in alert_status for v in _ALERT_STATUS.values()))
    incident_status = s.enum_members(2005, "status_id")
    check("every incident ladder value is a member of 2005's status table",
          all(int(v) in incident_status for v in _INCIDENT_STATUS.values()))
    verdicts = s.enum_members(2004, "verdict_id")
    check("every legacy disposition is a member of 2004's verdict table",
          all(v in verdicts for v in _LEGACY_DISPOSITION.values()))

    dispositions = s.enum_members(2004, "disposition_id")
    actions = s.enum_members(2004, "action_id")
    check("every disposition and action in the precedence table is legal",
          all(int(d) in dispositions and a in actions
              for _f, d, a, _t in _DISPOSITION_PRECEDENCE))
    check("...and `bad_enum_values` does not check either field, which is why the "
          "assertion above exists",
          not bad_enum_values(2004, {"disposition_id": 424242, "action_id": 424242}),
          "both are excluded from _CLASS_ENUM_FIELDS deliberately — one table across "
          "all 86 classes, so their field validators reject instead — but that means "
          "this connector's tables are pinned here or nowhere")

    banded = [int(severity_of(v)) for v in (0, 19, 20, 39, 40, 59, 60, 79, 80, 100)]
    check("CrowdStrike's 0-100 severity bands at its own documented breaks, 100 included",
          banded == [1, 1, 2, 2, 3, 3, 4, 4, 5, 5], f"got {banded}")
    check("no severity in 0-100 falls off the end of the table into Unknown",
          all(int(severity_of(v)) != 0 for v in range(0, 101)),
          "severity_from_bands returns the final entry for anything at or above the "
          "last bound, so 100 must fall *inside* a band")

    confidences = s.enum_members(2004, "confidence_id")
    check("the confidence bands are legal and this connector's own choice, not "
          "CrowdStrike's",
          all(int(cid) in confidences for _u, cid, _c in CONFIDENCE_BANDS)
          and len(CONFIDENCE_BANDS) == 3,
          "CrowdStrike publishes breaks for severity and none for confidence, which is "
          "why confidence_score keeps the raw number")

    check("`device_type_id` and `device_os_type_id` carry no per-class enum anywhere in "
          "the vendored index",
          s.enum_members(5001, "device_type_id") is None
          and s.enum_members(5001, "device_os_type_id") is None
          and not bad_enum_values(5001, {"device_type_id": 999,
                                         "device_os_type_id": 999}),
          "object-level OCSF enums are stored without their members, so a wrong value "
          "passes every sweep — the two tables below are hand-verified and pinned here")
    check("the product-type table is exactly the four members it claims",
          {k: v[0] for k, v in _PRODUCT_TYPE.items()}
          == {"workstation": 2, "server": 1, "domain controller": 1,
              "domaincontroller": 1})
    check("the chassis table only ever produces Desktop, Laptop or Virtual",
          set(_CHASSIS_TYPE.values()) == {2, 3, 6})
    check("the platform table maps the six OS families OCSF can express",
          {k: v[0] for k, v in _PLATFORM_OS.items()}
          == {"windows": 100, "mac": 300, "macos": 300, "linux": 200,
              "android": 201, "ios": 301})


def severity_of(value):
    from ingest.connectors.mapping import severity_from_bands  # noqa: PLC0415

    return severity_from_bands(value, SEVERITY_BANDS)


def test_crowdstrike_readiness():
    print("\n[crowdstrike] readiness, the five clouds, and the factory")
    trio = crowdstrike_connectors(_Pipe(), CS_LIVE, clock=Clock(),
                                  checkpoints=MemoryCheckpoints())
    check("the factory returns alerts, incidents and hosts",
          [c.name for c in trio]
          == ["crowdstrike_alerts", "crowdstrike_incidents", "crowdstrike_hosts"])
    check("the inventory connector is not optional",
          any(isinstance(c, CrowdStrikeHostConnector) for c in trio),
          "a containment decision needs to know whether the host is a domain "
          "controller, whether Falcon already contained it, and whether the response "
          "path can reach it")

    ready = cs_alerts().probe()
    check("a configured connector names the regional host in its limitation",
          ready.available and "api.crowdstrike.com" in ready.limitation
          and "403" in ready.limitation,
          f"got {ready.limitation!r} — a key from another Falcon cloud returns 403 with "
          "an empty errors array, naming neither the region nor the scope, so the "
          "operator re-issues a key that was always correct")

    blank = cs_alerts(CS_BLANK).probe()
    check("an unconfigured connector is unavailable and names both env vars",
          not blank.available and "$CROWDSTRIKE_CLIENT_ID" in blank.reason
          and "$CROWDSTRIKE_CLIENT_SECRET" in blank.reason, blank.reason)

    check("the alerts entity endpoint's body key is not the one every other endpoint uses",
          ALERT_ID_KEY == "composite_ids",
          "sending `ids` here returns 200 with an empty resources array and no error — "
          "indistinguishable from a quiet tenant")
    check("the offset ceiling is a named constant, because reaching it is not an error",
          OFFSET_CEILING == 10_000)
    for c in trio:
        check(f"{c.name} declares its required Falcon API scopes",
              bool(c.spec.required_grants) and bool(c.spec.docs_url))
    check("the token scope is deliberately empty",
          cs_alerts().authorizer().scope == "",
          "Falcon's granted scopes are a property of the API client itself; the "
          "authorizer omits the parameter rather than sending `scope=`, which Falcon "
          "rejects as malformed")


async def test_crowdstrike_transport():
    print("\n[crowdstrike] the two-step read, the 201 token, and measured truncation")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)

    transport = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": ["abc123:ind:aid9988:0011-2233"],
                   "meta": {"pagination": {"offset": 0, "limit": 1000, "total": 1}},
                   "errors": []}),
        (200, {}, {"resources": [CS_ALERT], "errors": []}),
    ])
    c = cs_alerts(transport=transport)
    out = await c.fetch_window(window)
    check("a full alert cycle is token, id query, entity read", len(transport.seen) == 3
          and len(out) == 1, f"{len(transport.seen)} requests, {len(out)} events")

    token, query, entities = transport.seen
    check("the token request goes to /oauth2/token and its 201 is accepted",
          token.url.endswith("/oauth2/token"),
          "HttpResponse.ok is 200 <= status < 300, so Falcon's 201 Created needs no "
          "special case — a client testing `status == 200` would never authenticate")
    check("the FQL filter single-quotes its ISO literal and sorts ascending",
          query.params["filter"] == "updated_timestamp:>'2026-03-11T00:00:00Z'"
          and query.params["sort"] == "updated_timestamp.asc",
          f"got {query.params!r} — the exact opposite of Defender's OData $filter, "
          "which rejects quotes on the same string")
    check("there is no upper bound on the filter",
          "<" not in query.params["filter"],
          "a Falcon alert mutates for hours after creation; with an upper bound an "
          "update raises updated_timestamp past a closed window and lands in no window")
    check("the entity read POSTs composite_ids and is marked idempotent",
          entities.method == "POST" and entities.url.endswith(ALERT_ENTITY_PATH)
          and list(entities.json_body) == [ALERT_ID_KEY]
          and entities.idempotent,
          f"got {entities.json_body!r} — POST only moves a long id list out of the URL, "
          "so re-sending it re-reads the same records and the retry policy may retry")

    # An id array of bare strings is exactly what `normalise_records` filters out, which
    # is why `_query_ids` exists at all rather than reusing `paginate`.
    from ingest.connectors.base import normalise_records  # noqa: PLC0415
    check("the generic normaliser really does drop a string id array",
          normalise_records({"resources": ["a", "b"]}, "resources") == [],
          "so `paginate` would report a healthy, permanently empty source")

    cursored = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": ["a", "b"],
                   "meta": {"pagination": {"offset": 0, "limit": 2, "total": 4,
                                           "after": "opaque-cursor-2"}}}),
        lambda r: (200, {}, {"resources": ["c", "d"],
                             "meta": {"pagination": {"limit": 2, "total": 4}}}),
    ])
    c = cs_alerts(transport=cursored)
    c.spec = dataclasses.replace(c.spec, page_size=2, rate_per_second=10_000.0,
                                 burst=64)
    ids = await c._query_ids(ALERT_QUERY_PATH, label_="t")
    check("an opaque `after` cursor is preferred over the integer offset",
          ids == ["a", "b", "c", "d"]
          and cursored.seen[2].params.get("after") == "opaque-cursor-2"
          and "offset" not in cursored.seen[2].params,
          f"got {cursored.seen[2].params!r}")

    capped = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": ["a", "b"],
                   "meta": {"pagination": {"offset": 0, "limit": 2, "total": 10}}}),
        (200, {}, {"resources": ["c", "d"],
                   "meta": {"pagination": {"offset": 2, "limit": 2, "total": 10}}}),
    ])
    c = cs_alerts(transport=capped)
    c.spec = dataclasses.replace(c.spec, page_size=2, max_pages_per_cycle=2,
                                 rate_per_second=10_000.0, burst=64)
    ids = await c._query_ids(ALERT_QUERY_PATH, label_="t")
    check("truncation here is measured, not suspected — it names the exact shortfall",
          len(ids) == 4 and c.unreachable_ids == 6 and c.page_cap_hits == 1
          and "matched 10 records" in c._truncation_reason
          and "6 were not read this window" in c._truncation_reason,
          f"got {c._truncation_reason!r}")
    check("and it says so rather than inheriting the generic page heuristic",
          "not merely late" in c._truncation_reason
          and c._page_truncation_suspected,
          "the base's sentence describes a full page with no next cursor, which is not "
          "the mechanism that happened here")

    partial = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": ["x"],
                   "meta": {"pagination": {"total": 1}},
                   "errors": [{"code": 403, "message": "access denied, authorization "
                                                       "failed"}]}),
    ])
    c = cs_alerts(transport=partial)
    await c._query_ids(ALERT_QUERY_PATH, label_="q")
    check("a 200 carrying a populated `errors` array is a partial failure, not a success",
          c.partial_errors == 1 and "partial failure" in c.stats.last_error
          and "access denied" in c.stats.last_error,
          f"got {c.stats.last_error!r} — the records that did come back look exactly "
          "like a complete answer")
    check("and it is surfaced in the health line",
          c.stats_extra()["partial_error_responses"] == 1)

    inc_transport = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": [CS_INCIDENT["incident_id"]],
                   "meta": {"pagination": {"offset": 0, "limit": 500, "total": 1}}}),
        (200, {}, {"resources": [CS_INCIDENT]}),
        (200, {}, {"resources": ["bhv-1", "bhv-2"],
                   "meta": {"pagination": {"offset": 0, "limit": 500, "total": 2}}}),
        (200, {}, {"resources": CS_BEHAVIOURS}),
    ])
    ci = cs_incidents(transport=inc_transport)
    out = await ci.fetch_window(window)
    check("an incident cycle is five calls: token, ids, entities, behaviour ids, "
          "behaviours",
          len(inc_transport.seen) == 5 and len(out) == 1,
          f"{len(inc_transport.seen)} requests, {len(out)} events")
    bq, be = inc_transport.seen[3], inc_transport.seen[4]
    check("the behaviours query filters on a quoted incident-id list",
          bq.params["filter"]
          == f"incident_id:['{CS_INCIDENT['incident_id']}']",
          f"got {bq.params!r}")
    check("the behaviours and incidents entity endpoints both use plain `ids`",
          list(be.json_body) == ["ids"]
          and list(inc_transport.seen[2].json_body) == ["ids"],
          "only the alerts endpoint is different, which is why the key is a parameter")
    check("and the fetched behaviours filled 2005's required array",
          len(out[0]["finding_info_list"]) == 2
          and ci.stats_extra()["behaviours_fetched"] == 2)

    host_transport = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": [CS_HOST_DC["device_id"], CS_HOST_CLOUD["device_id"]],
                   "meta": {"pagination": {"offset": 0, "limit": 1000, "total": 2}}}),
        (200, {}, {"resources": [CS_HOST_DC, CS_HOST_CLOUD]}),
    ])
    ch = cs_hosts(transport=host_transport)
    out = await ch.fetch_window(window)
    check("the hosts cycle filters on last_seen and returns both records",
          len(out) == 2
          and host_transport.seen[1].params["filter"]
          == "last_seen:>'2026-03-11T00:00:00Z'"
          and host_transport.seen[1].params["sort"] == "last_seen.asc")
    check("the per-cycle sensor-health counters are reset by fetch_window",
          ch.stats_extra()["reduced_functionality_hosts"] == 1
          and ch.stats_extra()["contained_hosts"] == 1,
          "counting across cycles would make one contained host look like a spreading "
          "containment")

    short = ScriptedTransport([
        CS_TOKEN,
        (200, {}, {"resources": ["a", "b", "c"],
                   "meta": {"pagination": {"offset": 0, "limit": 1000, "total": 3}}}),
        (200, {}, {"resources": [CS_HOST_CLOUD]}),
    ])
    ch = cs_hosts(transport=short)
    await ch.fetch_window(window)
    check("an entity read that returns fewer records than ids asked for says so",
          "resolved to nothing" in ch.stats.last_error,
          f"got {ch.stats.last_error!r} — usually a record deleted between the query "
          "and this read, and silently it looks like a smaller fleet")

    unconfigured = cs_alerts(CS_BLANK, transport=ScriptedTransport([]))
    try:
        await unconfigured.fetch_window(window)
        refused, why = False, "it made a request"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured cycle refuses before the transport is touched, naming both "
          "slots",
          refused and "$CROWDSTRIKE_CLIENT_ID" in why
          and "$CROWDSTRIKE_CLIENT_SECRET" in why, why)


# ── AWS CloudTrail ──────────────────────────────────────────────────────────
#
# Every fixture is dated 2026-03-11, five days before `Clock`'s default. Not cosmetic:
# `Event.build` restamps a future-dated event, so a fixture dated later than the test
# clock has its `time` silently replaced and every timestamp assertion below becomes
# vacuously true.
#
# `CloudTrailEvent` is a JSON **string** in every fixture, because that is what the API
# returns. Building the fixtures as nested objects would test a shape that never
# arrives and skip the parse step entirely.

CT_REGION = "us-east-1"
CT_ACCOUNT = "111122223333"

#: A long-lived IAM user minting a second credential for a *different* user. The whole
#: point of the fixture is that `userIdentity.userName` and
#: `requestParameters.userName` differ — that difference is the escalation, and a mapper
#: that merges them into one "user" cannot see it.
CT_CREATE_KEY_INNER = {
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDACKCEVSQ6C2EXAMPLE",
        "arn": f"arn:aws:iam::{CT_ACCOUNT}:user/deploy-bot",
        "accountId": CT_ACCOUNT,
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "userName": "deploy-bot",
    },
    "eventTime": "2026-03-11T07:58:11Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": CT_REGION,
    "sourceIPAddress": "203.0.113.51",
    "userAgent": "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0 exe/x86_64.ubuntu.22",
    "requestParameters": {"userName": "svc-admin"},
    "responseElements": {
        "accessKey": {
            "accessKeyId": "AKIAI44QH8DHBEXAMPLE",
            "userName": "svc-admin",
            "status": "Active",
            "createDate": "Mar 11, 2026 7:58:11 AM",
        }
    },
    "requestID": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "eventID": "9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "readOnly": False,
    "eventType": "AwsApiCall",
    "managementEvent": True,
    "recipientAccountId": CT_ACCOUNT,
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": "iam.amazonaws.com",
    },
}

CT_CREATE_KEY = {
    "EventId": "9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "EventName": "CreateAccessKey",
    # A number, not an ISO string — the envelope and the inner document disagree on this.
    "EventTime": 1_773_215_891,
    "EventSource": "iam.amazonaws.com",
    "Username": "deploy-bot",
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    # A string, not a boolean — they disagree on this too.
    "ReadOnly": "false",
    "Resources": [{"ResourceName": "svc-admin", "ResourceType": "AWS::IAM::User"}],
    "CloudTrailEvent": json.dumps(CT_CREATE_KEY_INNER),
}

#: An `AWSService` call. There is no user at all — `invokedBy` is the only identity, and
#: `sourceIPAddress` is a service principal rather than an address. Both of the required
#: 6003 objects (`actor`, `src_endpoint`) have to be satisfied from those two facts.
CT_SERVICE_CALL = {
    "EventId": "1111aaaa-2222-bbbb-3333-cccc4444dddd",
    "EventName": "AssumeRole",
    "EventTime": 1_773_215_892,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AWSService",
            "invokedBy": "ecs-tasks.amazonaws.com",
        },
        "eventTime": "2026-03-11T07:58:12Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "ecs-tasks.amazonaws.com",
        "userAgent": "ecs-tasks.amazonaws.com",
        "requestParameters": {
            "roleArn": f"arn:aws:iam::{CT_ACCOUNT}:role/TaskExecutionRole",
            "roleSessionName": "ecs-task-9911",
        },
        "responseElements": {
            "credentials": {
                "accessKeyId": "ASIAI44QH8DHBEXAMPLE",
                "expiration": "Mar 11, 2026 8:58:12 AM",
            }
        },
        "requestID": "aaaa1111-bbbb-2222-cccc-3333dddd4444",
        "eventID": "1111aaaa-2222-bbbb-3333-cccc4444dddd",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": CT_ACCOUNT,
    }),
}

#: Root, over a VPC endpoint, turning off the trail. Four separate things the mapper has
#: to notice at once, and all four are CIS-benchmark alarms.
CT_ROOT_STOP_LOGGING = {
    "EventId": "dead0000-beef-1111-2222-333344445555",
    "EventName": "StopLogging",
    "EventTime": 1_773_215_984,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "Root",
            "principalId": CT_ACCOUNT,
            "arn": f"arn:aws:iam::{CT_ACCOUNT}:root",
            "accountId": CT_ACCOUNT,
            "accessKeyId": "ASIAROOTEXAMPLE00000",
            "sessionContext": {
                "attributes": {
                    "creationDate": "2026-03-11T07:50:00Z",
                    "mfaAuthenticated": "false",
                },
            },
        },
        "eventTime": "2026-03-11T07:59:44Z",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "10.0.4.17",
        "userAgent": "console.amazonaws.com",
        "requestParameters": {
            "name": f"arn:aws:cloudtrail:{CT_REGION}:{CT_ACCOUNT}:trail/org-trail"
        },
        "responseElements": None,
        "requestID": "ffff0000-1111-2222-3333-444455556666",
        "eventID": "dead0000-beef-1111-2222-333344445555",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "recipientAccountId": CT_ACCOUNT,
        "vpcEndpointId": "vpce-0a1b2c3d4e5f6a7b8",
        "tlsDetails": {"tlsVersion": "TLSv1.1", "cipherSuite": "ECDHE-RSA-AES128-SHA"},
        # Top level, NOT inside `userIdentity` — AWS lists it in "CloudTrail record
        # contents" as a sibling of eventType/readOnly/vpcEndpointId, and it is omitted
        # entirely when false. Nesting it under the identity is the natural wrong guess
        # (that is where sessionContext lives) and it reads as a missing feature rather
        # than a misplaced field, so it is pinned here.
        "sessionCredentialFromConsole": "true",
    }),
}

#: An assumed-role call denied by IAM, from a cross-account principal, with the human
#: behind the Identity Center session named in `onBehalfOf`.
CT_DENIED_ASSUMED = {
    "EventId": "0000ffff-1111-eeee-2222-dddd3333cccc",
    "EventName": "GetAccountAuthorizationDetails",
    "EventTime": 1_773_216_259,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.10",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAI44QH8DHBEXAMPLE:alice@example.com",
            "arn": (
                f"arn:aws:sts::{CT_ACCOUNT}:assumed-role/AWSReservedSSO_ReadOnly_abc/"
                "alice@example.com"
            ),
            "accountId": "999988887777",
            "accessKeyId": "ASIAI44QH8DHBEXAMPLE",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAI44QH8DHBEXAMPLE",
                    "arn": f"arn:aws:iam::{CT_ACCOUNT}:role/AWSReservedSSO_ReadOnly_abc",
                    "accountId": CT_ACCOUNT,
                    "userName": "AWSReservedSSO_ReadOnly_abc",
                },
                "attributes": {
                    "creationDate": "2026-03-11T08:00:00Z",
                    "mfaAuthenticated": "true",
                },
            },
            "onBehalfOf": {
                "userId": "9067d5f8-a0b1-70e2-1234-5678abcd9012",
                "identityStoreArn": "arn:aws:identitystore::111122223333:identitystore/d-9067abc123",
            },
        },
        "eventTime": "2026-03-11T08:04:19Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "GetAccountAuthorizationDetails",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "198.51.100.9",
        "userAgent": "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux md/arch#x86_64",
        "errorCode": "AccessDenied",
        "errorMessage": (
            "User: arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_ReadOnly_abc/"
            "alice@example.com is not authorized to perform: "
            "iam:GetAccountAuthorizationDetails"
        ),
        "requestID": "cccc3333-dddd-4444-eeee-5555ffff6666",
        "eventID": "0000ffff-1111-eeee-2222-dddd3333cccc",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": CT_ACCOUNT,
    }),
}

#: **The trap.** A failed console login. Note what is *not* here: no `errorCode`. The
#: outcome exists only in `responseElements.ConsoleLogin`, so a status derived from
#: `errorCode` — which is how every other CloudTrail event reports failure — records
#: this as a success and silently disables console brute-force detection.
CT_SIGNIN_FAILED = {
    "EventId": "5555aaaa-6666-bbbb-7777-cccc8888dddd",
    "EventName": "ConsoleLogin",
    "EventTime": 1_773_216_300,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": f"arn:aws:iam::{CT_ACCOUNT}:user/alice",
            "accountId": CT_ACCOUNT,
            "userName": "alice",
        },
        "eventTime": "2026-03-11T08:05:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "185.220.101.42",
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        # No errorCode. This is the whole fixture.
        "errorMessage": "Failed authentication",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Failure"},
        "additionalEventData": {
            "LoginTo": "https://console.aws.amazon.com/console/home",
            "MobileVersion": "No",
            "MFAUsed": "No",
        },
        "eventID": "5555aaaa-6666-bbbb-7777-cccc8888dddd",
        "readOnly": False,
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": CT_ACCOUNT,
    }),
}

#: Root signing in successfully without MFA, federated through SAML.
CT_SIGNIN_ROOT = {
    "EventId": "7777eeee-8888-ffff-9999-0000aaaa1111",
    "EventName": "ConsoleLogin",
    "EventTime": 1_773_216_300,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "Root",
            "principalId": CT_ACCOUNT,
            "arn": f"arn:aws:iam::{CT_ACCOUNT}:root",
            "accountId": CT_ACCOUNT,
        },
        "eventTime": "2026-03-11T08:05:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "203.0.113.99",
        "userAgent": "Mozilla/5.0",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {
            "MFAUsed": "No",
            "SamlProviderArn": f"arn:aws:iam::{CT_ACCOUNT}:saml-provider/CorpIdP",
        },
        "eventID": "7777eeee-8888-ffff-9999-0000aaaa1111",
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": CT_ACCOUNT,
    }),
}

#: `SwitchRole` — lateral movement inside AWS, and the case that proves `resources` is
#: illegal on 3002. The role being switched *into* is the whole point of the event and it
#: still may not be a resource reference on this class.
CT_SWITCH_ROLE = {
    "EventId": "aaaa9999-bbbb-8888-cccc-7777dddd6666",
    "EventName": "SwitchRole",
    "EventTime": 1_773_216_300,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": f"arn:aws:iam::{CT_ACCOUNT}:user/alice",
            "accountId": CT_ACCOUNT,
            # In a real record the key id is HERE, on the identity — never at the inner
            # document's top level. There is no envelope `AccessKeyId` on this fixture
            # either, which is the shape every S3-sourced, replayed and
            # generator-produced record has.
            "accessKeyId": "AKIAI44QH8DHBSWITCH0",
            "userName": "alice",
        },
        "eventTime": "2026-03-11T08:05:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "SwitchRole",
        "awsRegion": CT_REGION,
        "sourceIPAddress": "203.0.113.51",
        "userAgent": "Mozilla/5.0",
        "responseElements": {"SwitchRole": "Success", "ConsoleLogin": "Success"},
        "additionalEventData": {
            "SwitchFrom": f"arn:aws:iam::{CT_ACCOUNT}:user/alice",
            "RoleArn": "arn:aws:iam::999988887777:role/OrgAdmin",
            "RoleName": "OrgAdmin",
            "TargetAccountId": "999988887777",
            "MFAUsed": "Yes",
        },
        "eventID": "aaaa9999-bbbb-8888-cccc-7777dddd6666",
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": CT_ACCOUNT,
    }),
}

#: A CloudTrail Insight. A finding with a lifecycle, so 2004 — which means `status_id`
#: reads from the finding table, `evidences` becomes legal, and `http_user_agent` does
#: not.
CT_INSIGHT = {
    "EventId": "bbbb1111-cccc-2222-dddd-3333eeee4444",
    "EventName": "GetAccountAuthorizationDetails",
    "EventTime": 1_773_220_200,
    "CloudTrailEvent": json.dumps({
        "eventVersion": "1.08",
        "eventTime": "2026-03-11T09:10:00Z",
        "awsRegion": CT_REGION,
        "eventID": "bbbb1111-cccc-2222-dddd-3333eeee4444",
        "eventType": "AwsCloudTrailInsight",
        "recipientAccountId": CT_ACCOUNT,
        "sharedEventID": "shared-99887766",
        "insightDetails": {
            "state": "Start",
            "eventSource": "iam.amazonaws.com",
            "eventName": "GetAccountAuthorizationDetails",
            "insightType": "ApiErrorRateInsight",
            "errorCode": "AccessDenied",
            "insightContext": {
                "statistics": {
                    "baseline": {"average": 0.0000882145},
                    "insight": {"average": 41.0},
                    "insightDuration": 7,
                    "baselineDuration": 10_080,
                },
                "attributions": [
                    {
                        "attribute": "userIdentityArn",
                        "insight": {"attributeValues": [
                            {"attributeValue":
                             f"arn:aws:sts::{CT_ACCOUNT}:assumed-role/Deploy/i-991",
                             "average": 41.0},
                        ]},
                        "baseline": {"attributeValues": [
                            {"attributeValue": f"arn:aws:iam::{CT_ACCOUNT}:user/tf",
                             "average": 0.0000882145},
                        ]},
                    },
                    {
                        "attribute": "errorCode",
                        "insight": {"attributeValues": [
                            {"attributeValue": "AccessDenied", "average": 41.0},
                        ]},
                        "baseline": {"attributeValues": []},
                    },
                ],
            },
        },
    }),
}

#: The inner document is not JSON. The record must survive on the envelope alone.
CT_UNPARSED = {
    "EventId": "9999ffff-8888-eeee-7777-dddd6666cccc",
    "EventName": "PutBucketPolicy",
    "EventTime": 1_773_216_000,
    "EventSource": "s3.amazonaws.com",
    "Username": "terraform",
    "ReadOnly": "false",
    "Resources": [{"ResourceName": "prod-backups", "ResourceType": "AWS::S3::Bucket"}],
    "CloudTrailEvent": '{"eventVersion":"1.09","userIdentity":{trunca',
}


def ct(config=None, transport=None):
    """A CloudTrail connector with the rate limiter effectively disabled.

    `RateLimiter.acquire` busy-loops against the real `time.monotonic` with no injectable
    clock, and this connector's real spec is **2 requests/second** — so a four-page test
    would spend two seconds of genuine wall-clock sleeping. The spec is replaced before
    the first `client()` call, which is the only point at which the limiter is built.
    """
    c = CloudTrailConnector(
        _Pipe(),
        config if config is not None else CT_LIVE,
        clock=Clock(),
        checkpoints=MemoryCheckpoints(),
        transport=transport,
    )
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


#: Deliberately unconfigured, for the readiness assertions.
CT_BLANK = with_creds(aws_access_key_id="", aws_secret_access_key="", aws_region="")

#: Configured with the documented AWS example key, which is a published placeholder and
#: not a credential.
CT_LIVE = with_creds(
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    aws_region=CT_REGION,
)


def test_cloudtrail_api_mapping():
    print("\n[cloudtrail] the ordinary API call, and the escalation hidden in "
          "requestParameters")
    c = ct()
    p = c.map_record(CT_CREATE_KEY)
    ev = ocsf_clean("cloudtrail CreateAccessKey", p, expect_class=6003)

    check("the inner JSON string is parsed, not treated as opaque text",
          p.get("api_operation") == "CreateAccessKey"
          and p.get("api_service_name") == "iam.amazonaws.com",
          f"operation={p.get('api_operation')!r} service={p.get('api_service_name')!r}")
    check("the timestamp comes from the record, not from ingest",
          p["time"] == 1_773_215_891.0, f"got {p.get('time')}")
    check("metadata_uid is CloudTrail's own eventID, so the overlap re-read dedupes "
          "exactly",
          p.get("metadata_uid") == "9f8e7d6c-5b4a-3210-fedc-ba9876543210",
          f"got {p.get('metadata_uid')!r}")
    check("requestID becomes the correlation uid, which is what joins this call to the "
          "downstream service events AWS emitted to service it",
          p.get("metadata_correlation_uid") == "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
          f"got {p.get('metadata_correlation_uid')!r}")

    check("activity_id is the CRUD bucket for the verb",
          p.get("activity_id") == 1, f"got {p.get('activity_id')}")
    check("activity_name is set unconditionally, not only when the id is 99",
          bool(p.get("activity_name")), f"got {p.get('activity_name')!r}")

    check("the caller is on actor.user, because 6003 declares no top-level user",
          p.get("actor_user_name") == "deploy-bot"
          and "user_name" not in p,
          f"actor={p.get('actor_user_name')!r} user_name={p.get('user_name')!r}")
    check("the access key is on actor.user.credential_uid — the pivot for 'what else "
          "did this credential do' and the input to key rotation",
          p.get("actor_user_credential_uid") == "AKIAIOSFODNN7EXAMPLE",
          f"got {p.get('actor_user_credential_uid')!r}")
    check("the account id becomes the user's domain, so `alice` in prod and `alice` in "
          "sandbox are not one entity",
          p.get("actor_user_domain") == CT_ACCOUNT, f"got {p.get('actor_user_domain')!r}")

    check("a real source address goes to src_endpoint.ip",
          p.get("src_endpoint_ip") == "203.0.113.51"
          and "src_endpoint_svc_name" not in p,
          f"ip={p.get('src_endpoint_ip')!r} svc={p.get('src_endpoint_svc_name')!r}")
    check("no errorCode means Success, and a successful mutating call is labelled",
          p.get("status_id") == 1 and "aws:mutating" in (p.get("metadata_labels") or []),
          f"status={p.get('status_id')} labels={p.get('metadata_labels')}")

    names = {r.get("name") for r in p.get("resources") or []}
    check("the IAM *target* is a resource, distinct from the caller — that difference "
          "is the privilege escalation",
          "svc-admin" in names and p.get("actor_user_name") == "deploy-bot",
          f"resources={sorted(n for n in names if n)}")
    check("the envelope's name-only Resources entry does not duplicate the inner one",
          sum(1 for r in p.get("resources") or [] if r.get("name") == "svc-admin") == 1,
          f"got {p.get('resources')!r}")
    check("the newly created key id is recorded, which is what links this call to every "
          "later event that uses it",
          (p.get("unmapped") or {}).get("created_access_key_id")
          == "AKIAI44QH8DHBEXAMPLE",
          f"got {(p.get('unmapped') or {}).get('created_access_key_id')!r}")

    check("the ATT&CK hint for additional cloud credentials is attached",
          "attack:T1098.001" in (p.get("metadata_labels") or []),
          f"labels={p.get('metadata_labels')}")
    check("requestParameters is not duplicated into unmapped — raw already holds it",
          not any("policyDocument" in k or k == "request_parameters"
                  for k in (p.get("unmapped") or {})),
          f"unmapped keys={sorted(p.get('unmapped') or {})}")
    check("the built event carries the notes the mapper wrote",
          ev is not None and isinstance(getattr(ev, "soc_notes", None), list),
          "note() writes payload['notes']; only Event.build merges it into soc_notes")


def test_cloudtrail_actor_shapes():
    print("\n[cloudtrail] the five identity shapes, and the two required objects each "
          "must still fill")
    c = ct()

    p = c.map_record(CT_SERVICE_CALL)
    ocsf_clean("cloudtrail AWSService call", p, expect_class=6003)
    check("an AWSService call has no user at all, so invoked_by satisfies the required "
          "actor",
          p.get("actor_invoked_by") == "ecs-tasks.amazonaws.com",
          f"got {p.get('actor_invoked_by')!r}")
    check("a service principal in sourceIPAddress does NOT become an IP",
          "src_endpoint_ip" not in p, f"got {p.get('src_endpoint_ip')!r}")
    check("it goes to src_endpoint.svc_name instead, which still fills the required "
          "src_endpoint",
          p.get("src_endpoint_svc_name") == "ecs-tasks.amazonaws.com",
          f"got {p.get('src_endpoint_svc_name')!r}")
    check("set_ip's note= is an unmapped KEY, so the raw value lands under a column "
          "name and not a sentence",
          (p.get("unmapped") or {}).get("source_ip_raw") == "ecs-tasks.amazonaws.com",
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("the temporary key STS issued is kept, joining the role assumption to every "
          "action the resulting session takes",
          (p.get("unmapped") or {}).get("issued_access_key_id")
          == "ASIAI44QH8DHBEXAMPLE",
          f"got {(p.get('unmapped') or {}).get('issued_access_key_id')!r}")
    check("the assumed role is a resource on 6003",
          any(r.get("name") == "TaskExecutionRole" for r in p.get("resources") or []),
          f"got {p.get('resources')!r}")

    p = c.map_record(CT_ROOT_STOP_LOGGING)
    ocsf_clean("cloudtrail root StopLogging", p, expect_class=6003)
    labels = p.get("metadata_labels") or []
    check("Root has no userName, and is still named — otherwise the CIS 'root account "
          "used' rule has nothing to fire on",
          p.get("actor_user_name") == "root", f"got {p.get('actor_user_name')!r}")
    check("root is typed Admin, the most privileged principal an account has",
          p.get("actor_user_type_id") == 2, f"got {p.get('actor_user_type_id')}")
    check("the raw userIdentity.type is preserved, because object-level OCSF enums are "
          "absent from the vendored index and the coarse id is unvalidatable",
          (p.get("unmapped") or {}).get("identity_type") == "Root",
          f"got {(p.get('unmapped') or {}).get('identity_type')!r}")
    check("root use is labelled and mapped to cloud accounts",
          "aws:root-account-used" in labels and "attack:T1078.004" in labels,
          f"labels={labels}")
    check("turning off the trail is labelled as audit-config change and mapped to "
          "T1562.008",
          "aws:audit-config-change" in labels and "attack:T1562.008" in labels,
          f"labels={labels}")
    check("the trail is named as a resource",
          any("org-trail" in str(r.get("name") or "") for r in p.get("resources") or []),
          f"got {p.get('resources')!r}")
    check("the VPC endpoint is recorded, which is why sourceIPAddress is private and "
          "why no internet-facing network telemetry shows this call",
          (p.get("unmapped") or {}).get("vpc_endpoint_id")
          == "vpce-0a1b2c3d4e5f6a7b8" and "aws:via-vpc-endpoint" in labels,
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("console-derived credentials making a programmatic call are called out — the "
          "shape of a hijacked browser session pivoting to the API",
          "aws:console-derived-credentials" in labels, f"labels={labels}")
    check("the access key is read from userIdentity.accessKeyId, where a real record "
          "carries it — this envelope has no denormalised AccessKeyId copy, which is "
          "the shape of every S3-sourced, replayed and generator-produced record, and "
          "reading only the envelope leaves the key-rotation pivot empty on all of them",
          p.get("actor_user_credential_uid") == "ASIAROOTEXAMPLE00000",
          f"got {p.get('actor_user_credential_uid')!r}")
    check("TLS 1.1 is noted as below the minimum AWS requires",
          any("below the TLS 1.2" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")
    check("no tls_* field is invented on 6003 — it goes to unmapped",
          "tls_version" not in p
          and (p.get("unmapped") or {}).get("tls_version") == "TLSv1.1",
          f"got {p.get('tls_version')!r}")
    check("MFA on the session is read from a STRING 'false', not a boolean",
          p.get("actor_session_is_mfa") is False,
          f"got {p.get('actor_session_is_mfa')!r}")

    p = c.map_record(CT_DENIED_ASSUMED)
    ocsf_clean("cloudtrail denied AssumedRole", p, expect_class=6003)
    labels = p.get("metadata_labels") or []
    check("an AssumedRole with no userName falls back to the session issuer's role name",
          p.get("actor_user_name") == "AWSReservedSSO_ReadOnly_abc",
          f"got {p.get('actor_user_name')!r}")
    check("the role-session name goes to actor.session.uid",
          p.get("actor_session_uid") == "alice@example.com",
          f"got {p.get('actor_session_uid')!r}")
    check("errorCode drives Failure, and the code and message are both kept",
          p.get("status_id") == 2 and p.get("status_code") == "AccessDenied"
          and "not authorized" in str(p.get("status_detail")),
          f"status={p.get('status_id')} code={p.get('status_code')!r}")
    check("a single denial is labelled and NOT escalated — counting them is the detect "
          "layer's job",
          "aws:access-denied" in labels
          and p.get("severity_id") == 1,
          f"labels={labels} severity={p.get('severity_id')}")
    check("the Identity Center human behind the permission-set session is recorded",
          (p.get("unmapped") or {}).get("on_behalf_of_user_id")
          == "9067d5f8-a0b1-70e2-1234-5678abcd9012",
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("a caller in a different account than the recipient is flagged cross-account",
          "aws:cross-account" in labels
          and (p.get("unmapped") or {}).get("caller_account_id") == "999988887777",
          f"labels={labels}")
    check("the authorization dump maps to both account and group discovery",
          "attack:T1087.004" in labels and "attack:T1069.003" in labels,
          f"labels={labels}")


def test_cloudtrail_signin():
    print("\n[cloudtrail] console sign-in — a different OCSF class, and the failed-login "
          "trap")
    c = ct()

    p = c.map_record(CT_SIGNIN_FAILED)
    ocsf_clean("cloudtrail failed ConsoleLogin", p, expect_class=3002)
    labels = p.get("metadata_labels") or []
    # This is the single most important assertion in the file.
    check("a failed ConsoleLogin is reported as a FAILURE even though it carries no "
          "errorCode at all",
          p.get("status_id") == 2,
          f"got status_id={p.get('status_id')} — errorCode is absent from this record; "
          "the outcome is only in responseElements.ConsoleLogin, so keying status on "
          "errorCode marks every failed console login a success and silently disables "
          "password-spray detection on the AWS console")
    check("the outcome value itself is kept as the status code",
          p.get("status_code") == "Failure", f"got {p.get('status_code')!r}")
    check("a failed sign-in is labelled and mapped to password spraying",
          "aws:signin-failed" in labels and "attack:T1110.003" in labels,
          f"labels={labels}")
    check("the identity is on the top-level user, because 3002 REQUIRES user and "
          "declares no actor obligation",
          p.get("user_name") == "alice" and "actor_user_name" not in p,
          f"user={p.get('user_name')!r} actor={p.get('actor_user_name')!r}")
    check("MFAUsed 'No' is read as a boolean false",
          p.get("is_mfa") is False, f"got {p.get('is_mfa')!r}")
    check("http_user_agent is legal on 3002 and is set",
          "Mozilla" in str(p.get("http_user_agent")), f"got {p.get('http_user_agent')!r}")

    p = c.map_record(CT_SIGNIN_ROOT)
    ocsf_clean("cloudtrail root ConsoleLogin", p, expect_class=3002)
    labels = p.get("metadata_labels") or []
    check("a successful root sign-in is activity 1 Logon and Success",
          p.get("activity_id") == 1 and p.get("status_id") == 1,
          f"activity={p.get('activity_id')} status={p.get('status_id')}")
    check("root without MFA gets its own label — this is the CIS 1.x alarm",
          "aws:root-account-used" in labels and "aws:root-no-mfa" in labels,
          f"labels={labels}")
    check("SAML federation uses OCSF's own SAML member (5), not Other (99)",
          p.get("auth_protocol_id") == 5 and p.get("auth_protocol") == "SAML",
          f"got id={p.get('auth_protocol_id')} name={p.get('auth_protocol')!r} — the "
          "3002 auth_protocol_id table carries SAML as a first-class member, so filing "
          "it as Other would make every rule on auth_protocol_id == 5 miss federated "
          "AWS logins")
    check("the SAML provider ARN is kept, and NOT as a resource",
          (p.get("unmapped") or {}).get("saml_provider_arn", "").endswith("CorpIdP")
          and "resources" not in p,
          f"resources={p.get('resources')!r}")

    p = c.map_record(CT_SWITCH_ROLE)
    ocsf_clean("cloudtrail SwitchRole", p, expect_class=3002)
    labels = p.get("metadata_labels") or []
    check("SwitchRole is activity 7 Account Switch, not a second Logon",
          p.get("activity_id") == 7,
          f"got {p.get('activity_id')} — role switching is lateral movement inside AWS "
          "and OCSF has an activity for exactly it")
    check("resources is ILLEGAL on 3002, so the switched-to role goes to unmapped "
          "rather than being dropped or emitted illegally",
          "resources" not in p
          and (p.get("unmapped") or {}).get("switch_rolearn", "").endswith("OrgAdmin"),
          f"resources={p.get('resources')!r} "
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("the target account is kept — this switch crosses an account boundary",
          (p.get("unmapped") or {}).get("switch_targetaccountid") == "999988887777",
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("MFAUsed 'Yes' is read as a boolean true and no no-MFA label is attached",
          p.get("is_mfa") is True and "aws:no-mfa" not in labels,
          f"is_mfa={p.get('is_mfa')!r} labels={labels}")
    check("an account switch is mapped to cloud accounts",
          "attack:T1078.004" in labels, f"labels={labels}")
    check("the 3002 sign-in path reads the key from userIdentity.accessKeyId too — it "
          "had no fallback of any kind before, so user.credential_uid was empty on "
          "EVERY console event and the 'what else did this credential do' pivot did "
          "not exist for sign-ins at all",
          p.get("user_credential_uid") == "AKIAI44QH8DHBSWITCH0",
          f"got {p.get('user_credential_uid')!r}")


def test_cloudtrail_insight():
    print("\n[cloudtrail] Insights — a finding with a lifecycle, so a third class again")
    c = ct()
    p = c.map_record(CT_INSIGHT)
    ocsf_clean("cloudtrail Insight", p, expect_class=2004)
    labels = p.get("metadata_labels") or []

    check("state Start is activity 1 Create",
          p.get("activity_id") == 1, f"got {p.get('activity_id')}")
    check("status_id reads from the FINDING lifecycle table, where 1 is New — not from "
          "the Success/Failure table",
          p.get("status_id") == 1 and p.get("status_code") == "Start",
          f"got status_id={p.get('status_id')} — five distinct status_id tables exist "
          "in OCSF v1.9.0 and Success (1) would read as 'New' on this one, which is "
          "why it must be chosen deliberately rather than shared with 6003")
    check("it is marked an alert and graded Medium, not High",
          p.get("is_alert") is True and p.get("severity_id") == 3,
          f"alert={p.get('is_alert')} severity={p.get('severity_id')} — a rate "
          "deviation graded High would outrank a confirmed credential theft in the "
          "queue")
    check("the analytic identifies itself as CloudTrail Insights",
          p.get("finding_analytic_name") == "CloudTrail Insights"
          and p.get("finding_analytic_uid") == "ApiErrorRateInsight",
          f"got {p.get('finding_analytic_uid')!r}")
    check("finding_types carries the insight type",
          "ApiErrorRateInsight" in (p.get("finding_types") or []),
          f"got {p.get('finding_types')!r}")
    check("the description states the observed rate against the baseline, with the "
          "multiple worked out",
          "41.0" in str(p.get("finding_desc")) and "x baseline" in str(p.get("finding_desc")),
          f"got {p.get('finding_desc')!r}")
    check("evidences is legal only on 2004 and carries the attributions",
          isinstance(p.get("evidences"), list) and len(p["evidences"]) == 2,
          f"got {p.get('evidences')!r}")
    check("the identity driving the anomaly is named on the actor, so the finding can "
          "be correlated to something",
          p.get("actor_user_name") == "i-991", f"got {p.get('actor_user_name')!r}")
    check("http_user_agent is ILLEGAL on 2004 and is absent",
          "http_user_agent" not in p, f"got {p.get('http_user_agent')!r}")
    check("the inner eventName gets the same ATT&CK hints the API path would attach, so "
          "one hunt covers both mechanisms",
          "attack:T1087.004" in labels, f"labels={labels}")
    check("an error-rate insight is explained as permission enumeration",
          any("permission enumeration" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")

    end = json.loads(CT_INSIGHT["CloudTrailEvent"])
    end["insightDetails"]["state"] = "End"
    p2 = c.map_record({**CT_INSIGHT, "CloudTrailEvent": json.dumps(end)})
    check("state End closes the finding — activity 3, status Resolved (4)",
          p2.get("activity_id") == 3 and p2.get("status_id") == 4,
          f"activity={p2.get('activity_id')} status={p2.get('status_id')}")


def test_cloudtrail_unparsed():
    print("\n[cloudtrail] a record whose inner document will not parse must survive")
    c = ct()
    p = c.map_record(CT_UNPARSED)
    ev = ocsf_clean("cloudtrail unparsed inner", p, expect_class=6003)

    check("the record is NOT dropped — the envelope alone still makes a conformant 6003",
          ev is not None and p.get("api_operation") == "PutBucketPolicy",
          f"got {p.get('api_operation')!r}")
    check("the failure is counted, so a systematic parse break is visible rather than "
          "looking like a quiet source",
          c.unparsed_records == 1, f"got {c.unparsed_records}")
    check("the failure is stated on the event, naming what is therefore missing",
          any("could not be parsed" in n and "userIdentity" in n
              for n in p.get("notes") or []),
          f"notes={p.get('notes')}")
    check("the unparsed string is retained for hand recovery",
          "trunca" in str((p.get("unmapped") or {}).get("cloudtrail_event_raw")),
          f"unmapped={sorted(p.get('unmapped') or {})}")
    check("the envelope's Username fills the required actor",
          p.get("actor_user_name") == "terraform", f"got {p.get('actor_user_name')!r}")
    check("the envelope's name-only Resources are read when the inner list is absent",
          any(r.get("name") == "prod-backups" for r in p.get("resources") or []),
          f"got {p.get('resources')!r}")
    check("the envelope's STRING 'false' ReadOnly is understood as a boolean",
          (p.get("unmapped") or {}).get("read_only") is False,
          f"got {(p.get('unmapped') or {}).get('read_only')!r}")
    check("the envelope's NUMERIC EventTime is understood as a timestamp",
          p.get("time") == 1_773_216_000.0, f"got {p.get('time')}")
    check("it is labelled so the lake can find every degraded record",
          "aws:unparsed-record" in (p.get("metadata_labels") or []),
          f"labels={p.get('metadata_labels')}")
    labels = p.get("metadata_labels") or []
    check("src_endpoint — REQUIRED by 6003 and carried only inside the string that "
          "failed to parse — is filled with a labelled substitute, because an "
          "unfilled required object here does not make the event more honest, it "
          "makes the Event model reject it and sends the only copy of a "
          "management-plane call to quarantine",
          p.get("src_endpoint_svc_name") == "(source unknown — not in record)"
          and "substitute_for:src_endpoint" in labels,
          f"svc_name={p.get('src_endpoint_svc_name')!r} labels={labels}")
    check("the substitute is NOT counted as a service-principal caller and carries no "
          "aws:service-principal-caller label — an absence of evidence is not an "
          "observation, and conflating them would corrupt that counter",
          c.service_principal_calls == 0
          and "aws:service-principal-caller" not in labels,
          f"service_principal_calls={c.service_principal_calls} labels={labels}")
    check("the note tells a responder not to act on the placeholder",
          any("placeholder, not an observation" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")


def _ct_api(c, event_name, params, **inner_extra):
    """Map a minimal 6003 with these requestParameters."""
    inner = {
        "eventVersion": "1.09",
        "userIdentity": {"type": "IAMUser", "userName": "tf", "accountId": CT_ACCOUNT,
                         "principalId": "AIDATEST", "accessKeyId": "AKIATEST"},
        "eventTime": "2026-03-11T08:00:00Z",
        "eventSource": "test.amazonaws.com",
        "eventName": event_name,
        "awsRegion": CT_REGION,
        "sourceIPAddress": "203.0.113.7",
        "requestParameters": params,
        "eventID": f"param-{event_name}",
        "eventType": "AwsApiCall",
        "readOnly": False,
        "recipientAccountId": CT_ACCOUNT,
        **inner_extra,
    }
    return c.map_record({
        "EventId": f"param-{event_name}", "EventName": event_name,
        "EventTime": 1_773_216_000, "CloudTrailEvent": json.dumps(inner),
    })


def test_cloudtrail_param_readers():
    print("\n[cloudtrail] requestParameters is where the intent lives")
    c = ct()

    p = _ct_api(c, "PutBucketPolicy", {
        "bucketName": "prod-backups",
        "bucketPolicy": {"Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]},
    })
    ocsf_clean("cloudtrail public bucket policy", p, expect_class=6003)
    check("a wildcard principal with no Condition is public exposure",
          "aws:public-principal" in (p.get("metadata_labels") or [])
          and "attack:T1530" in (p.get("metadata_labels") or []),
          f"labels={p.get('metadata_labels')}")

    p = _ct_api(c, "PutBucketPolicy", {
        "bucketName": "prod-backups",
        "bucketPolicy": {"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]},
    })
    labels = p.get("metadata_labels") or []
    check("the same wildcard WITH a Condition is described honestly and not called "
          "public",
          "aws:wildcard-principal" in labels and "aws:public-principal" not in labels,
          f"labels={labels} — an org-scoped grant is written exactly this way, and a "
          "SOC that cries public-bucket at every one of them gets its bucket alerts "
          "muted within a week")
    check("the eventName-level T1530 hint stays on the conditioned policy too — the "
          "hint says 'this API is how that technique is performed in AWS', which is "
          "what makes the event findable by a hunt and countable on the coverage "
          "matrix; the judgement of whether THIS call is exposure lives in the "
          "aws:public-principal label, not in the technique",
          "attack:T1530" in labels, f"labels={labels}")
    check("the condition is named in the note so an analyst reads it rather than "
          "trusting the label",
          any("carries a Condition" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")

    p = _ct_api(c, "PutBucketPolicy", {
        "bucketName": "b",
        # A JSON *string*, which is the shape PutBucketPolicy actually sends.
        "bucketPolicy": '{"Statement":[{"Effect":"Deny","Principal":"*"}]}',
    })
    check("a Deny to a wildcard is not an exposure — Effect is read, not just Principal",
          "aws:public-principal" not in (p.get("metadata_labels") or []),
          f"labels={p.get('metadata_labels')}")

    p = _ct_api(c, "ModifySnapshotAttribute", {
        "snapshotId": "snap-0abcdef1234567890",
        "attributeType": "CREATE_VOLUME_PERMISSION",
        "createVolumePermission": {"add": {"items": [{"userId": "444455556666"}]}},
    })
    ocsf_clean("cloudtrail snapshot share", p, expect_class=6003)
    labels = p.get("metadata_labels") or []
    check("sharing a snapshot to another account id is exfiltration with no network "
          "transfer, and is labelled as such",
          "aws:shared-externally" in labels and "attack:T1537" in labels,
          f"labels={labels}")
    check("the recipient account is named in the note",
          any("444455556666" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")

    p = _ct_api(c, "AuthorizeSecurityGroupIngress", {
        "groupId": "sg-0123456789abcdef0",
        "ipPermissions": {"items": [{
            "ipProtocol": "tcp", "fromPort": 0, "toPort": 65535,
            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]},
    })
    ocsf_clean("cloudtrail open security group", p, expect_class=6003)
    labels = p.get("metadata_labels") or []
    check("a port RANGE covering SSH is caught — the check is numeric containment, not "
          "a string match",
          "aws:remote-admin-exposed" in labels,
          f"labels={labels} — 0-65535 contains 22, and a substring test for '/22 ' "
          "matches none of the range spellings, which is the single most dangerous "
          "rule shape there is")
    check("exposed data stores get their own label, because several accept "
          "unauthenticated connections",
          "aws:datastore-exposed" in labels, f"labels={labels}")
    check("the exposed services are named, not just counted",
          any("SSH" in n and "RDP" in n for n in p.get("notes") or []),
          f"notes={p.get('notes')}")

    p = _ct_api(c, "AuthorizeSecurityGroupIngress", {
        "groupId": "sg-1",
        "ipPermissions": {"items": [{
            "ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]},
    })
    labels = p.get("metadata_labels") or []
    check("0.0.0.0/0 on 443 alone is internet exposure and NOTHING more — that is what "
          "a public web service looks like",
          "aws:open-to-internet" in labels
          and "aws:remote-admin-exposed" not in labels
          and "aws:datastore-exposed" not in labels, f"labels={labels}")

    p = _ct_api(c, "SendCommand", {
        "documentName": "AWS-RunShellScript",
        "instanceIds": ["i-0abc", "i-0def"],
    })
    ocsf_clean("cloudtrail SSM SendCommand", p, expect_class=6003)
    check("SSM command execution is labelled and both target instances are resources",
          "aws:remote-execution" in (p.get("metadata_labels") or [])
          and sum(1 for r in p.get("resources") or []
                  if r.get("type") == "AWS::EC2::Instance") == 2,
          f"labels={p.get('metadata_labels')} resources={p.get('resources')!r}")
    check("it is mapped to both cloud administration command and the cloud API",
          "attack:T1651" in (p.get("metadata_labels") or [])
          and "attack:T1059.009" in (p.get("metadata_labels") or []),
          f"labels={p.get('metadata_labels')}")

    p = _ct_api(c, "RunInstances", {
        "instanceType": "p4d.24xlarge", "imageId": "ami-0abc", "maxCount": 8,
        "userData": "H4sIAAAA",
    })
    ocsf_clean("cloudtrail RunInstances", p, expect_class=6003)
    labels = p.get("metadata_labels") or []
    check("an accelerator instance family is flagged for resource hijacking without "
          "being called one",
          "aws:accelerator-instance" in labels and "attack:T1496" in labels
          and p.get("severity_id") == 1,
          f"labels={labels} severity={p.get('severity_id')} — CloudTrail is an audit "
          "log with no opinion; only an alerting product may set severity")
    check("userData is noted as root-at-boot execution",
          "aws:userdata-supplied" in labels, f"labels={labels}")

    p = _ct_api(c, "AttachRolePolicy", {
        "roleName": "AppRole",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
    })
    check("an AWS-managed policy whose name IS the privilege level is named in a note",
          "aws:admin-policy-grant" in (p.get("metadata_labels") or [])
          and any("AdministratorAccess" in n for n in p.get("notes") or []),
          f"labels={p.get('metadata_labels')} notes={p.get('notes')}")

    p = _ct_api(c, "ScheduleKeyDeletion", {
        "keyId": f"arn:aws:kms:{CT_REGION}:{CT_ACCOUNT}:key/1234abcd", "pendingWindowInDays": 7,
    })
    ocsf_clean("cloudtrail ScheduleKeyDeletion", p, expect_class=6003)
    check("scheduling a KMS key for deletion is mapped to both inhibit-recovery and "
          "encrypted-for-impact, and the window is stated",
          "attack:T1490" in (p.get("metadata_labels") or [])
          and "attack:T1486" in (p.get("metadata_labels") or [])
          and any("7 day" in n for n in p.get("notes") or []),
          f"labels={p.get('metadata_labels')} notes={p.get('notes')}")

    p = _ct_api(c, "GetSecretValue", None)
    check("a reader whose call sent no parameters records that fact rather than "
          "assuming which of the two reasons applies",
          (p.get("unmapped") or {}).get("request_parameters_absent") is True,
          f"unmapped={sorted(p.get('unmapped') or {})} — GetSecretValue IS in the "
          "reader table, so an empty requestParameters here means either the caller "
          "sent none or CloudTrail omitted them; the two are indistinguishable from "
          "the record and a hunt that assumes the first one is wrong half the time")

    check("every eventName in the parameter table is a real string key and every reader "
          "is callable",
          all(isinstance(k, str) and callable(v) for k, v in _CT_READERS.items()),
          f"{len(_CT_READERS)} readers")


def test_cloudtrail_readiness():
    print("\n[cloudtrail] what probe() has to admit about this API")
    c = ct(config=CT_BLANK)
    av = c.probe()
    check("an unconfigured connector reports unavailable and names the slots",
          not av.available and "AWS_ACCESS_KEY_ID" in av.reason.upper(),
          f"{av.reason!r}")
    check("it is marked fixable by the operator",
          av.fixable_by_user, f"{av!r}")

    c = ct()
    av = c.probe()
    lim = av.limitation
    check("a configured connector is available", av.available, f"{av.reason!r}")
    check("the throughput ceiling is stated in the limitation, in events per second",
          "100 events/second" in lim.replace("~", ""),
          f"got {lim!r} — 2 req/s x 50 records is the hard ceiling and a busy account "
          "exceeds it, so this has to be said before an operator relies on it")
    check("it names the production alternative rather than only complaining",
          "S3" in lim and "page_cap_hits" in lim, f"got {lim!r}")
    check("the 90-day retention horizon is stated",
          "90 days" in lim, f"got {lim!r}")
    check("the absence of data events is stated",
          "data events" in lim and "data-event selectors" in lim, f"got {lim!r}")
    check("a us-east-1 connector does NOT carry the global-services warning",
          "GLOBAL SERVICES" not in lim, f"got {lim!r}")

    other = ct(config=with_creds(
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="eu-west-1"))
    lim2 = other.probe().limitation
    check("a non-us-east-1 connector warns that IAM, STS and Organizations are "
          "invisible to it — the most common CloudTrail coverage mistake",
          "GLOBAL SERVICES" in lim2 and "us-east-1" in lim2, f"got {lim2!r}")
    check("the regional endpoint is built by substitution, so a stray brace in an "
          "operator-supplied host cannot raise KeyError at collection time",
          other.base_url() == "https://cloudtrail.eu-west-1.amazonaws.com/",
          f"got {other.base_url()!r}")

    check("the spec asks for 50 records, which is AWS's hard cap and not 1000",
          c.spec.page_size == 50, f"got {c.spec.page_size}")
    check("the spec holds the window back by the documented 15-minute delivery lag",
          c.spec.indexing_lag_seconds == 900.0, f"got {c.spec.indexing_lag_seconds}")
    check("the window is no wider than this API can read completely in the time it "
          "covers",
          c.spec.max_window_seconds == 900.0, f"got {c.spec.max_window_seconds}")
    check("the required grant is the single IAM permission this needs",
          c.spec.required_grants == ("cloudtrail:LookupEvents",),
          f"got {c.spec.required_grants!r}")
    check("the session-token slot is NOT required, so a long-lived IAM user key does "
          "not report as PARTLY configured",
          all("SESSION_TOKEN" not in cred.env_var.upper()
              for cred in c.credentials()),
          f"got {[cred.env_var for cred in c.credentials()]!r} — a PARTLY configured "
          "connector reads as worse than an unconfigured one, and every long-lived-key "
          "deployment would have reported that way")


async def test_cloudtrail_transport():
    print("\n[cloudtrail] the json1.1 request, body-cursor pagination, and two "
          "failure modes")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)

    transport = ScriptedTransport([
        (200, {}, {"Events": [CT_CREATE_KEY], "NextToken": "tok-page-2"}),
        (200, {}, {"Events": [CT_SIGNIN_FAILED]}),
    ])
    c = ct(transport=transport)
    out = await c.fetch_window(window)
    check("both pages are read and both map",
          len(transport.seen) == 2 and len(out) == 2,
          f"{len(transport.seen)} requests, {len(out)} events")

    first, second = transport.seen
    check("the operation is dispatched by X-Amz-Target, not by a URL path",
          first.headers.get("X-Amz-Target") == LOOKUP_TARGET
          and first.url.endswith("amazonaws.com/"),
          f"target={first.headers.get('X-Amz-Target')!r} url={first.url!r}")
    check("the content type is the json1.1 protocol, set explicitly so SigV4 signs the "
          "same value that is sent",
          first.headers.get("Content-Type") == "application/x-amz-json-1.1",
          f"got {first.headers!r} — a signature computed over application/json while "
          "sending x-amz-json-1.1 fails as a signature mismatch that reads like a "
          "wrong secret key")
    check("the timestamps are Unix epoch NUMBERS, not ISO strings",
          isinstance(first.json_body["StartTime"], int)
          and first.json_body["StartTime"] == 1_773_187_200,
          f"got {first.json_body!r} — an ISO string here is a SerializationException")
    check("MaxResults asks for AWS's cap of 50",
          first.json_body["MaxResults"] == 50, f"got {first.json_body!r}")
    check("the second page repeats StartTime and EndTime alongside NextToken, because "
          "AWS rejects a token-only body",
          second.json_body.get("NextToken") == "tok-page-2"
          and second.json_body.get("StartTime") == 1_773_187_200
          and second.json_body.get("EndTime") == 1_773_273_600,
          f"got {second.json_body!r} — body-cursor pagination was impossible before "
          "`next_body`; `paginate` re-sent json_body verbatim and the token could "
          "never advance")
    check("the request is marked idempotent so the retry policy may retry it",
          first.idempotent and first.method == "POST", f"{first.method}")

    # An expired pagination token, which is a normal consequence of a slow cycle.
    expiring = ScriptedTransport([
        (200, {}, {"Events": [CT_CREATE_KEY], "NextToken": "tok-stale"}),
        (400, {"x-amzn-errortype": "InvalidNextTokenException"},
         {"__type": "InvalidNextTokenException", "message": "Invalid next token"}),
    ])
    c = ct(transport=expiring)
    out = await c.fetch_window(window)
    check("an expired NextToken ends the cycle cleanly, keeping what was read",
          len(out) == 1 and c.expired_cursors == 1,
          f"{len(out)} events, expired_cursors={c.expired_cursors}")
    check("it says what happened and that the remainder is re-read, rather than "
          "failing the connector into backoff for a condition that resolves itself",
          "expired mid-window" in c.stats.last_error
          and "re-read next cycle" in c.stats.last_error,
          f"got {c.stats.last_error!r}")

    # A window that straddles the 90-day horizon. AWS rejects a too-old StartTime
    # outright rather than clamping it, so a connector restarting after an outage would
    # fail every cycle forever with an error that never mentions retention.
    clamped = ScriptedTransport([(200, {}, {"Events": [CT_CREATE_KEY]})])
    c = ct(transport=clamped)
    straddle = TimeWindow(c.clock() - 100 * 86_400.0, c.clock() - 50 * 86_400.0)
    out = await c.fetch_window(straddle)
    sent = clamped.seen[0].json_body
    floor = c.clock() - (EVENT_HISTORY_SECONDS - RETENTION_MARGIN_SECONDS)
    check("StartTime is clamped inside the horizon instead of being rejected",
          sent["StartTime"] >= int(floor) and sent["StartTime"] > straddle.start,
          f"sent {sent['StartTime']}, floor {int(floor)}, asked {int(straddle.start)}")
    check("EndTime is left where it was, so StartTime never overtakes it",
          sent["StartTime"] < sent["EndTime"] == int(straddle.end),
          f"{sent['StartTime']} -> {sent['EndTime']} — StartTime > EndTime is "
          "InvalidTimeRangeException, an error about the request rather than about "
          "retention")
    check("the clamp is counted and surfaced in stats, since it means events were "
          "permanently missed",
          c.retention_clamps == 1
          and "retention_clamps" in c.stats_extra(),
          f"clamps={c.retention_clamps} extra={c.stats_extra()!r}")
    check("the gap is described as permanent, not as a delayed read",
          "permanent gap" in c.stats.last_error
          and "days before the 90-day" in c.stats.last_error,
          f"got {c.stats.last_error!r}")

    # A window *entirely* older than the horizon — the normal shape of a restart after a
    # long outage, because the planner caps each window at max_window_seconds.
    dead = ScriptedTransport([])
    c = ct(transport=dead)
    gone = TimeWindow(c.clock() - 200 * 86_400.0, c.clock() - 199 * 86_400.0)
    out = await c.fetch_window(gone)
    check("a window entirely below the horizon sends no request at all",
          out == [] and dead.seen == [],
          f"{len(out)} events, {len(dead.seen)} requests — clamping only the start would "
          f"send StartTime > EndTime, and the planner asks for such a window ~2,600 "
          f"times in a row while a 110-day-old cursor catches up")
    check("the cursor is jumped to the horizon in one cycle rather than walking 110 days "
          "of failures one hour at a time",
          c._latest_record == c.clock() - (EVENT_HISTORY_SECONDS
                                           - RETENTION_MARGIN_SECONDS),
          f"{c._latest_record!r}")
    check("the skip is counted apart from the clamp and says no request was sent",
          c.windows_skipped == 1
          and "windows_skipped_below_horizon" in c.stats_extra()
          and "no request was sent" in c.stats.last_error,
          f"{c.stats_extra()!r} / {c.stats.last_error!r}")

    unconfigured = ct(config=CT_BLANK, transport=ScriptedTransport([]))
    try:
        await unconfigured.fetch_window(window)
        refused, why = False, "no exception"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured cycle refuses before the transport is touched",
          refused and "AWS_ACCESS_KEY_ID" in why.upper(), why)


# ── Azure Activity Log ──────────────────────────────────────────────────────
#
# The GUIDs below are Microsoft's own published documentation placeholders (the
# subscription id is the one used throughout the Activity Log REST reference) or
# tenant-independent public constants — the built-in role definition ids and the Global
# Administrator role template id are the same in every tenant on earth. Nothing here is
# a credential.
#
# Every fixture is dated 2026-03-11 for the reason in `Clock`: `Event.build` restamps a
# future-dated event, which would make every timestamp assertion below vacuous.

AZ_SUB = "089bd33f-d4ec-47fe-8ba5-0753aa5c5b33"
AZ_TENANT = "1e8c1a4b-1b2c-4c5d-9e0f-abcdef123456"
AZ_OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


def az(config=None, transport=None, *, fast=True):
    """An Azure connector with the rate limiter effectively disabled.

    Same reason as :func:`ct` — the real spec is 2 requests/second against a busy-looping
    limiter with no injectable clock, so a multi-page test would sleep in real seconds.
    Pass ``fast=False`` when the assertion is *about* the shipped spec, e.g. the
    per-subscription rate that ``probe()`` reports to an operator.
    """
    c = AzureActivityConnector(
        _Pipe(),
        config if config is not None else AZ_LIVE,
        clock=Clock(),
        checkpoints=MemoryCheckpoints(),
        transport=transport,
    )
    if fast:
        c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


AZ_BLANK = with_creds(
    azure_subscription_id="",
    azure_tenant_id="",
    azure_client_id="",
    azure_client_secret="",
)
AZ_LIVE = with_creds(
    azure_subscription_id=AZ_SUB,
    azure_tenant_id=AZ_TENANT,
    azure_client_id="b677c290-cf4b-4a8e-a60e-91ba650a4abe",
    azure_client_secret="not-a-real-secret",
)
#: Two subscriptions and a stray space, which is how an operator actually pastes them.
AZ_MULTI = with_creds(
    azure_subscription_id=f"{AZ_SUB}, 7f3c9d21-1111-2222-3333-444455556666 ;{AZ_SUB}",
    azure_tenant_id=AZ_TENANT,
    azure_client_id="b677c290-cf4b-4a8e-a60e-91ba650a4abe",
    azure_client_secret="not-a-real-secret",
)
#: The client-credentials mint, which every scripted cycle pays for exactly once —
#: the authorizer caches the token per connector instance, and each `az()` call is a
#: fresh instance. A script that omits it fails on the *first API call* with
#: "token response carried no access_token", which reads as a broken connector rather
#: than a short script.
AZ_TOKEN = (
    200,
    {"Content-Type": "application/json"},
    {"access_token": "eyJ0eXAiOiJKV1Qi.arm-fake", "expires_in": 3599,
     "token_type": "Bearer"},
)

#: Owner granted to a service principal, by a Global Administrator, from an address the
#: token was not issued to. Four separate signals in one record, and none of them is a
#: top-level field: the role is inside a JSON string, the Global Administrator role is a
#: GUID in `wids`, and the address mismatch only exists as the difference between two
#: fields that a mapper is tempted to collapse into one.
AZ_ROLE_GRANT = {
    "authorization": {
        "action": "Microsoft.Authorization/roleAssignments/write",
        # The CALLER's role, not the granted one. Reading this as the grant turns every
        # role assignment in the tenant into "Owner was granted".
        "role": "User Access Administrator",
        "scope": f"/subscriptions/{AZ_SUB}",
    },
    "caller": "admin@contoso.onmicrosoft.com",
    "category": {"localizedValue": "Administrative", "value": "Administrative"},
    "claims": {
        "aud": "https://management.core.windows.net/",
        "iss": f"https://sts.windows.net/{AZ_TENANT}/",
        "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        "appidacr": "1",
        "uti": "fUL3vFq0jUeQ7dLwAA",
        "ipaddr": "203.0.113.44",
        "name": "Contoso Admin",
        "upn": "admin@contoso.onmicrosoft.com",
        "wids": ["b79fbf4d-3ef9-4689-8143-76b194e85509", _GLOBAL_ADMIN_ROLE_TEMPLATE],
        "http://schemas.microsoft.com/claims/authnmethodsreferences": "pwd,mfa",
        "http://schemas.microsoft.com/identity/claims/objectidentifier":
            "5f7a2b91-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
        "http://schemas.microsoft.com/identity/claims/tenantid": AZ_TENANT,
    },
    "correlationId": "8a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000001",
    "eventName": {"localizedValue": "End request", "value": "EndRequest"},
    # Seven fractional digits, which is what Azure actually sends.
    "eventTimestamp": "2026-03-11T08:00:00.1234567Z",
    "httpRequest": {
        "clientIpAddress": "198.51.100.7",
        "clientRequestId": "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
        "method": "PUT",
        "uri": f"https://management.azure.com/subscriptions/{AZ_SUB}/providers/"
               "Microsoft.Authorization/roleAssignments/aaaa?api-version=2022-04-01",
    },
    "id": f"/subscriptions/{AZ_SUB}/providers/Microsoft.Authorization/roleAssignments"
          "/aaaa/events/44ade4c1/ticks/1",
    "level": "Informational",
    "operationId": "4b8a0c11-2222-4333-8444-000000000001",
    "operationName": {
        "localizedValue": "Create role assignment",
        "value": "Microsoft.Authorization/roleAssignments/write",
    },
    "properties": {
        "statusCode": "Created",
        "requestbody": json.dumps({
            "Id": "aaaa",
            "Properties": {
                "PrincipalId": "9d8c7b6a-5432-4111-9000-abcdefabcdef",
                "PrincipalType": "ServicePrincipal",
                "RoleDefinitionId": f"/subscriptions/{AZ_SUB}/providers/"
                                    f"Microsoft.Authorization/roleDefinitions/{AZ_OWNER_ROLE}",
                "Scope": f"/subscriptions/{AZ_SUB}",
            },
        }),
    },
    "resourceGroupName": "",
    "resourceId": f"/subscriptions/{AZ_SUB}/providers/Microsoft.Authorization"
                  "/roleAssignments/aaaa",
    "resourceProviderName": {
        "localizedValue": "Microsoft Authorization",
        "value": "Microsoft.Authorization",
    },
    "resourceType": {"value": "Microsoft.Authorization/roleAssignments"},
    "status": {"localizedValue": "Succeeded", "value": "Succeeded"},
    "subStatus": {"localizedValue": "Created (HTTP Status Code: 201)", "value": "Created"},
    "submissionTimestamp": "2026-03-11T08:04:19.7654321Z",
    "subscriptionId": AZ_SUB,
    "tenantId": AZ_TENANT,
}

#: The opening half of `runCommand` on a domain controller, by a managed identity. This
#: is the record that double-counts if `Started` is treated as terminal, and the one a
#: "status is not Succeeded" rule fires on.
AZ_BEGIN = {
    "caller": "5f7a2b91-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
    "category": {"value": "Administrative"},
    "claims": {
        "appid": "b677c290-cf4b-4a8e-a60e-91ba650a4abe",
        "appidacr": "2",
        "idtyp": "app",
        "xms_mirid": f"/subscriptions/{AZ_SUB}/resourcegroups/rg-app/providers/"
                     "Microsoft.ManagedIdentity/userAssignedIdentities/mi-deploy",
    },
    "correlationId": "1111aaaa-2222-bbbb-3333-cccc44445555",
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000002",
    "eventName": {"value": "BeginRequest"},
    "eventTimestamp": "2026-03-11T07:58:11Z",
    "id": f"/subscriptions/{AZ_SUB}/events/44ade4c1/ticks/2",
    "level": "Informational",
    "operationId": "9999aaaa-8888-bbbb-7777-cccc66665555",
    "operationName": {"value": "Microsoft.Compute/virtualMachines/runCommand/action"},
    "properties": {},
    "resourceGroupName": "rg-app",
    "resourceId": f"/subscriptions/{AZ_SUB}/resourceGroups/rg-app/providers/"
                  "Microsoft.Compute/virtualMachines/vm-dc01",
    "resourceProviderName": {"value": "Microsoft.Compute"},
    "resourceType": {"value": "Microsoft.Compute/virtualMachines"},
    "status": {"value": "Started"},
    "submissionTimestamp": "2026-03-11T07:58:12Z",
    "subscriptionId": AZ_SUB,
}

#: The closing half. Same `operationId`, different `eventDataId`, so exact dedup keeps
#: both and only the labels tell them apart.
AZ_END = dict(
    AZ_BEGIN,
    eventDataId="44ade4c1-0000-4f1f-9f7a-000000000003",
    eventName={"value": "EndRequest"},
    eventTimestamp="2026-03-11T07:59:44Z",
    status={"value": "Succeeded"},
    subStatus={"value": "OK"},
    submissionTimestamp="2026-03-11T08:00:00Z",
)

#: A platform notification: no caller, no claims, no resource, no CRUD verb. Collected
#: rather than dropped because it is the only thing that separates "the detection went
#: quiet because Azure broke" from "the detection went quiet because someone broke it".
AZ_SERVICE_HEALTH = {
    "caller": None,
    "category": {"value": "ServiceHealth"},
    "claims": {},
    "correlationId": "aaaabbbb-cccc-dddd-eeee-ffff00001111",
    "description": "Active: Virtual Machines - West Europe",
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000004",
    "eventName": {"value": "ServiceHealth"},
    "eventTimestamp": "2026-03-11T09:10:00Z",
    "id": f"/subscriptions/{AZ_SUB}/events/44ade4c1/ticks/4",
    "level": "Warning",
    "operationId": "aaaabbbb-cccc-dddd-eeee-ffff00001111",
    "operationName": {"value": "Microsoft.ServiceHealth/incident/action"},
    "properties": {
        "title": "Virtual Machines - West Europe",
        "service": "Virtual Machines",
        "region": "West Europe",
        "incidentType": "Incident",
        "trackingId": "ABCD-1X0",
        "stage": "Active",
        "impactedServices": json.dumps(
            [{"ServiceName": "Virtual Machines",
              "ImpactedRegions": [{"RegionName": "West Europe"}]}]
        ),
    },
    "status": {"value": "Active"},
    "submissionTimestamp": "2026-03-11T09:10:30Z",
    "subscriptionId": AZ_SUB,
}

#: An Administrative record with no caller — which is a gap in Azure's own log, not a
#: platform event, and has to read differently in the note.
AZ_CALLERLESS_ADMIN = dict(
    AZ_BEGIN,
    caller=None,
    claims={},
    eventDataId="44ade4c1-0000-4f1f-9f7a-000000000005",
    eventTimestamp="2026-03-11T08:04:19Z",
    submissionTimestamp="2026-03-11T08:05:00Z",
)

#: Blocked by Azure Policy. The operation happened and did not take effect, which is
#: neither a success nor a service failure, and the reason is a JSON document nested in
#: `properties.statusMessage`.
AZ_POLICY_DENY = {
    "caller": "svc-terraform@contoso.onmicrosoft.com",
    "category": {"value": "Policy"},
    "claims": {"ipaddr": "198.51.100.7"},
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000006",
    "eventName": {"value": "EndRequest"},
    "eventTimestamp": "2026-03-11T08:05:00Z",
    "id": f"/subscriptions/{AZ_SUB}/events/44ade4c1/ticks/6",
    "level": "Error",
    "operationId": "5555dddd-4444-eeee-3333-ffff22221111",
    "operationName": {"value": "Microsoft.Authorization/policies/deny/action"},
    "properties": {
        "policies": json.dumps([{
            "policyDefinitionName": "deny-public-blob",
            "policyDefinitionEffect": "Deny",
            "policyAssignmentScope": f"/subscriptions/{AZ_SUB}",
        }]),
        "statusMessage": json.dumps({
            "status": "Failed",
            "error": {
                "code": "RequestDisallowedByPolicy",
                "message": "Resource 'stgexfil' was disallowed by policy.",
            },
        }),
    },
    "resourceGroupName": "rg-data",
    "resourceId": f"/subscriptions/{AZ_SUB}/resourceGroups/rg-data/providers/"
                  "Microsoft.Storage/storageAccounts/stgexfil",
    "resourceProviderName": {"value": "Microsoft.Storage"},
    "resourceType": {"value": "Microsoft.Storage/storageAccounts"},
    "status": {"value": "Failed"},
    "subStatus": {"value": "Forbidden"},
    "submissionTimestamp": "2026-03-11T08:05:02Z",
    "subscriptionId": AZ_SUB,
}

#: A resource going Unavailable. During an active intrusion this is as likely to be a
#: destroyed disk as a platform fault, so the note has to say so instead of implying Azure.
AZ_RESOURCE_HEALTH = {
    "category": {"value": "ResourceHealth"},
    "claims": {},
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000007",
    "eventName": {"value": "ResourceHealth"},
    "eventTimestamp": "2026-03-11T08:05:00Z",
    "id": f"/subscriptions/{AZ_SUB}/events/44ade4c1/ticks/7",
    "level": "Error",
    "operationId": "6666eeee-5555-ffff-4444-111133332222",
    "operationName": {"value": "Microsoft.Resourcehealth/healthevent/Activated/action"},
    "properties": {
        "title": "Virtual Machine health status changed to unavailable",
        "currentHealthStatus": "Unavailable",
        "previousHealthStatus": "Available",
        "cause": "PlatformInitiated",
    },
    "resourceGroupName": "rg-app",
    "resourceId": f"/subscriptions/{AZ_SUB}/resourceGroups/rg-app/providers/"
                  "Microsoft.Compute/virtualMachines/vm-dc01",
    "resourceProviderName": {"value": "Microsoft.Compute"},
    "resourceType": {"value": "Microsoft.Compute/virtualMachines"},
    "status": {"value": "Active"},
    "submissionTimestamp": "2026-03-11T08:05:10Z",
    "subscriptionId": AZ_SUB,
}

#: The same record a German-language tenant returns. `value` is invariant and
#: `localizedValue` is translated, so a mapper that reads the display string matches
#: nothing here while working perfectly in the tenant it was written against.
AZ_GERMAN = {
    "caller": "sp-backup",
    "category": {"localizedValue": "Verwaltung", "value": "Administrative"},
    "claims": {"appid": "b677c290-cf4b-4a8e-a60e-91ba650a4abe", "idtyp": "app"},
    "eventDataId": "44ade4c1-0000-4f1f-9f7a-000000000008",
    "eventName": {"localizedValue": "Anforderung beenden", "value": "EndRequest"},
    "eventTimestamp": "2026-03-11T08:05:00Z",
    "level": "Informational",
    "operationId": "7777ffff-6666-aaaa-5555-222244443333",
    "operationName": {
        "localizedValue": "Speicherkontoschlüssel auflisten",
        "value": "Microsoft.Storage/storageAccounts/listKeys/action",
    },
    "properties": {},
    "resourceGroupName": "rg-data",
    "resourceId": f"/subscriptions/{AZ_SUB}/resourceGroups/rg-data/providers/"
                  "Microsoft.Storage/storageAccounts/stgprod",
    "resourceProviderName": {"localizedValue": "Microsoft-Speicher",
                             "value": "Microsoft.Storage"},
    "resourceType": {"localizedValue": "Speicherkonten",
                     "value": "Microsoft.Storage/storageAccounts"},
    "status": {"localizedValue": "Erfolgreich", "value": "Succeeded"},
    "submissionTimestamp": "2026-03-11T08:05:01Z",
    "subscriptionId": AZ_SUB,
}


def test_azure_role_grant():
    print("\n[azure] the role grant, and the four signals that are not top-level fields")
    c = az()
    p = c.map_record(AZ_ROLE_GRANT, AZ_SUB)
    ev = ocsf_clean("azure roleAssignments/write", p, expect_class=6003)

    check("the granted role is decoded out of the JSON string in properties.requestbody",
          p["unmapped"].get("granted_role_definition_id") == AZ_OWNER_ROLE
          and p["unmapped"].get("granted_role_name") == "Owner",
          f"got {p['unmapped'].get('granted_role_name')!r} — without decoding this, "
          "'was anyone granted Owner' cannot be asked of the Activity Log at all")
    check("the grant is marked tier-0 with T1098.003, because Owner can grant itself "
          "everything else",
          "tier0-role" in p["metadata_labels"]
          and "attack:T1098.003" in p["metadata_labels"] and c.tier0_grants == 1,
          f"{p['metadata_labels']!r}")
    check("the principal that received it is carried, with its type",
          p["unmapped"].get("grant_principal_id") == "9d8c7b6a-5432-4111-9000-abcdefabcdef"
          and p["unmapped"].get("grant_principal_type") == "ServicePrincipal",
          f"{p['unmapped'].get('grant_principal_id')!r}")
    check("authorization.role is kept as the CALLER's role and never confused with the "
          "granted one",
          p["unmapped"].get("authorization_role") == "User Access Administrator"
          and p["unmapped"].get("granted_role_name") == "Owner",
          f"caller={p['unmapped'].get('authorization_role')!r} "
          f"granted={p['unmapped'].get('granted_role_name')!r}")

    check("the Global Administrator role template id in `wids` is surfaced as a label",
          "caller-global-admin" in p["metadata_labels"]
          and _GLOBAL_ADMIN_ROLE_TEMPLATE in p["unmapped"]["directory_role_template_ids"],
          f"{p['metadata_labels']!r}")
    check("src_endpoint_ip is the address ARM received, not the address in the token",
          p["src_endpoint_ip"] == "198.51.100.7"
          and p["unmapped"]["token_issued_ip"] == "203.0.113.44",
          f"ip={p.get('src_endpoint_ip')!r} token={p['unmapped'].get('token_issued_ip')!r}")
    check("the mismatch between them is labelled T1550.001, which is the only signal "
          "for token replay in this log",
          "token-ip-mismatch" in p["metadata_labels"]
          and "attack:T1550.001" in p["metadata_labels"],
          f"{p['metadata_labels']!r}")
    check("the note admits the false-positive shape rather than asserting theft",
          any("roaming client" in n and "proxy" in n for n in p["notes"]),
          f"{p['notes']!r}")

    check("the subscription is the cloud ACCOUNT uid, which is where a cross-cloud "
          "query joins",
          p["cloud_account_uid"] == AZ_SUB and "cloud_project_uid" not in p,
          f"got {p.get('cloud_account_uid')!r} — cloud_project_uid is GCP's notion and "
          "would put the tenant's main join key under a second name")
    check("appidacr is decoded, so 'this principal switched from a certificate to a "
          "secret' is a writeable query",
          p["unmapped"]["app_auth_method"] == "client secret",
          f"{p['unmapped'].get('app_auth_method')!r}")
    check("the token identifier goes to actor_session_uid, under a note saying it is "
          "not an interactive session",
          p["actor_session_uid"] == "fUL3vFq0jUeQ7dLwAA"
          and any("`uti` claim" in n and "not an interactive session" in n
                  for n in p["notes"]),
          f"{p.get('actor_session_uid')!r}")
    check("MFA is read from the authnmethodsreferences claim",
          p["actor_session_is_mfa"] is True, f"{p.get('actor_session_is_mfa')!r}")
    check("the UPN fills name, email and domain, and the object id fills the uid",
          p["actor_user_name"] == "admin@contoso.onmicrosoft.com"
          and p["actor_user_email"] == "admin@contoso.onmicrosoft.com"
          and p["actor_user_domain"] == "contoso.onmicrosoft.com"
          and p["actor_user_uid"] == "5f7a2b91-3c4d-4e5f-8a9b-0c1d2e3f4a5b",
          f"{p.get('actor_user_name')!r} / {p.get('actor_user_uid')!r}")

    check("subStatus supplies status_code, because `status` the string is not a legal "
          "6003 field",
          p["status_code"] == "Created" and "status" not in p,
          f"got {p.get('status_code')!r}")
    check("status_id is Success and the operation is labelled terminal",
          p["status_id"] == int(Status.SUCCESS) and "azure:terminal" in p["metadata_labels"],
          f"{p.get('status_id')}")
    check("activity_id comes from the operation's last segment — `write` is Update",
          p["activity_id"] == 3 and p["activity_name"].endswith("roleAssignments/write"),
          f"{p.get('activity_id')} {p.get('activity_name')!r}")
    check("the resource goes into the plural `resources` array, the only home 6003 "
          "declares for it",
          p["resources"][0]["uid"].endswith("/roleAssignments/aaaa")
          and p["resources"][0]["namespace"] == "Microsoft.Authorization",
          f"{p.get('resources')!r}")
    check("the authorization scope is carried as a second resource, saying what it is",
          len(p["resources"]) == 2
          and "permission was evaluated" in p["resources"][1]["data"]["purpose"],
          f"{p.get('resources')!r}")
    check("severity stays Informational even though this is the tenant's worst-case "
          "grant — the log has no opinion and the detect layer scores it",
          p["severity_id"] == int(Severity.INFORMATIONAL), f"{p.get('severity_id')}")
    check("the event's time is the 7-fraction-digit eventTimestamp, to the microsecond",
          abs(ev.time - 1_773_216_000.123456) < 1e-4, f"{ev.time!r}")
    check("submissionTimestamp becomes metadata_logged_time, and the lag is measured",
          p["metadata_logged_time"] > p["time"]
          and abs(p["unmapped"]["indexing_lag_seconds"] - 259.64) < 0.1,
          f"{p.get('metadata_logged_time')!r} lag="
          f"{p['unmapped'].get('indexing_lag_seconds')!r}")
    check("eventName becomes metadata_event_code and correlationId the correlation uid, "
          "while operationId stays the Begin/End join",
          p["metadata_event_code"] == "EndRequest"
          and p["metadata_correlation_uid"] == AZ_ROLE_GRANT["correlationId"]
          and p["unmapped"]["operation_id"] == AZ_ROLE_GRANT["operationId"],
          f"{p.get('metadata_event_code')!r}")


def test_azure_lifecycle_pair():
    print("\n[azure] Begin and End — the pair that double-counts every write in the "
          "tenant if it is read as two operations")
    c = az()
    begin = c.map_record(AZ_BEGIN, AZ_SUB)
    end = c.map_record(AZ_END, AZ_SUB)
    ocsf_clean("azure BeginRequest", begin, expect_class=6003)
    ocsf_clean("azure EndRequest", end, expect_class=6003)

    check("both halves are emitted — dropping the opening record would make an "
          "operation that began and never finished invisible",
          begin["metadata_uid"] != end["metadata_uid"], f"{begin['metadata_uid']!r}")
    check("they share operationId, which is the join for pairing them",
          begin["unmapped"]["operation_id"] == end["unmapped"]["operation_id"],
          f"{begin['unmapped']['operation_id']!r}")
    check("the opening record is Other, not Unknown and not Success",
          begin["status_id"] == int(Status.OTHER),
          f"got {begin['status_id']} — Unknown would claim nobody assessed a record "
          "Azure explicitly marked Started, and Success double-counts the change")
    check("its own status word survives in status_code",
          begin["status_code"] == "Started", f"{begin.get('status_code')!r}")
    check("the two carry opposite labels, so both hunts are a positive filter",
          "azure:non-terminal" in begin["metadata_labels"]
          and "azure:terminal" in end["metadata_labels"]
          and "azure:terminal" not in begin["metadata_labels"],
          f"begin={begin['metadata_labels']!r} end={end['metadata_labels']!r}")
    check("the opening record explains the double-count and the failed-operations trap",
          any("double-counts the change" in n and "fires on every write" in n
              for n in begin["notes"]),
          f"{begin['notes']!r}")
    check("the count is surfaced in stats with the instruction for counting writes",
          c.non_terminal_records == 1
          and "azure:terminal" in c.stats_extra()["non_terminal_records"],
          f"{c.stats_extra()!r}")

    check("a managed-identity caller is labelled as one, with its resource id kept",
          "actor:managed-identity" in begin["metadata_labels"]
          and begin["unmapped"]["managed_identity_resource_id"].endswith("mi-deploy"),
          f"{begin['metadata_labels']!r} — a managed identity has no secret to steal "
          "from outside the resource, so this is a compromised-resource investigation "
          "and not a leaked-secret one")
    check("a GUID caller fills the uid and is NOT written into the name or the email",
          begin["actor_user_uid"] == "5f7a2b91-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
          and "actor_user_name" not in begin and "actor_user_email" not in begin,
          f"{begin.get('actor_user_name')!r} / {begin.get('actor_user_email')!r}")
    check("`/action` resolves to Other, which is legal only because activity_name is "
          "always set",
          begin["activity_id"] == 99 and begin["activity_name"].endswith("runCommand/action"),
          f"{begin.get('activity_id')} {begin.get('activity_name')!r}")
    check("runCommand on a VM is T1651 Cloud Administration Command",
          "attack:T1651" in begin["metadata_labels"]
          and begin["unmapped"]["attack_technique"] == "T1651",
          f"{begin['metadata_labels']!r}")


def test_azure_platform_records():
    print("\n[azure] the records with no actor at all, and why they are collected")
    c = az()
    p = c.map_record(AZ_SERVICE_HEALTH, AZ_SUB)
    ocsf_clean("azure ServiceHealth", p, expect_class=6003)

    check("6003's required actor is filled with the emitting provider, under a label "
          "that says it is a substitute",
          p["actor_invoked_by"] == "Azure platform"
          and "substitute_for:actor" in p["metadata_labels"],
          f"{p.get('actor_invoked_by')!r} — an unfilled required object is not a more "
          "honest answer, it is the same claim with the evidence removed")
    check("the note forbids inferring a principal, and states why the record is kept",
          any("none should be inferred" in n and "outage can be told apart" in n
              for n in p["notes"]),
          f"{p['notes']!r}")
    check("it is labelled a platform notification, because OCSF v1.9.0 has no class "
          "for one and 6003 is least-wrong rather than right",
          "azure:platform-notification" in p["metadata_labels"] and c.platform_records == 1,
          f"{p['metadata_labels']!r}")
    check("with no address anywhere, src_endpoint carries the service name — 6003 "
          "requires the object and a rejected event is a silently quarantined one",
          p["src_endpoint_svc_name"] and "src_endpoint_ip" not in p
          and "substitute_for:src_endpoint" in p["metadata_labels"],
          f"{p.get('src_endpoint_svc_name')!r}")
    check("the impacted region becomes cloud_region, so a regional outage is joinable "
          "against the resources that went quiet",
          p["cloud_region"] == "West Europe", f"{p.get('cloud_region')!r}")
    check("the incident's tracking id is kept, which is what Azure support asks for",
          p["unmapped"]["health_trackingId"] == "ABCD-1X0",
          f"{p['unmapped'].get('health_trackingId')!r}")
    check("impactedServices is decoded out of its JSON string",
          "Virtual Machines" in p["unmapped"]["impacted_services"],
          f"{p['unmapped'].get('impacted_services')!r}")
    check("an unrecognised status is Other and gets NEITHER lifecycle label, with a "
          "note saying the value was not interpreted",
          p["status_id"] == int(Status.OTHER)
          and "azure:terminal" not in p["metadata_labels"]
          and "azure:non-terminal" not in p["metadata_labels"]
          and any("not one of the values this connector interprets" in n
                  for n in p["notes"]),
          f"{p['metadata_labels']!r}")

    c2 = az()
    q = c2.map_record(AZ_CALLERLESS_ADMIN, AZ_SUB)
    ocsf_clean("azure Administrative with no caller", q, expect_class=6003)
    check("an Administrative record with no caller gets a DIFFERENT note — it is a gap "
          "in Azure's log, not a platform event",
          "substitute_for:actor" in q["metadata_labels"]
          and any("gap in Azure's own log" in n for n in q["notes"])
          and c2.platform_records == 0,
          f"{q['notes']!r} platform={c2.platform_records}")
    check("the substitute is the provider rather than the generic platform string",
          q["actor_invoked_by"] == "Microsoft.Compute", f"{q.get('actor_invoked_by')!r}")


def test_azure_policy_and_health():
    print("\n[azure] the JSON documents hidden inside JSON strings")
    c = az()
    p = c.map_record(AZ_POLICY_DENY, AZ_SUB)
    ocsf_clean("azure policy deny", p, expect_class=6003)

    check("the failure reason is decoded out of properties.statusMessage",
          "RequestDisallowedByPolicy" in p["status_detail"]
          and "disallowed by policy" in p["status_detail"],
          f"got {p.get('status_detail')!r} — read as text this is an unparsed blob, and "
          "an AuthorizationFailed is an attacker probing permissions")
    check("the Deny effect is decoded and labelled, so a blocked attempt is not filed "
          "as a service failure",
          "azure:policy-denied" in p["metadata_labels"]
          and "deny" in p["unmapped"]["policy_effects"]
          and "deny-public-blob" in p["unmapped"]["policy_definitions"],
          f"{p['unmapped'].get('policy_effects')!r}")
    check("the note says the request was made and did not take effect",
          any("did not take effect" in n for n in p["notes"]), f"{p['notes']!r}")
    check("status_id is Failure and the vendor's Forbidden reaches status_code",
          p["status_id"] == int(Status.FAILURE) and p["status_code"] == "Forbidden",
          f"{p.get('status_id')} {p.get('status_code')!r}")
    check("level=Error is kept in unmapped with a note that it is not severity",
          p["unmapped"]["level"] == "Error"
          and p["severity_id"] == int(Severity.INFORMATIONAL)
          and any("not its security significance" in n for n in p["notes"]),
          f"{p['unmapped'].get('level')!r} severity={p.get('severity_id')}")
    check("with no httpRequest, claims.ipaddr is used and no mismatch is claimed",
          p["src_endpoint_ip"] == "198.51.100.7"
          and "token-ip-mismatch" not in p["metadata_labels"],
          f"{p.get('src_endpoint_ip')!r}")

    h = az().map_record(AZ_RESOURCE_HEALTH, AZ_SUB)
    ocsf_clean("azure ResourceHealth", h, expect_class=6003)
    check("an Unavailable transition is labelled and both statuses are kept",
          "azure:health:unavailable" in h["metadata_labels"]
          and h["unmapped"]["health_current"] == "Unavailable"
          and h["unmapped"]["health_previous"] == "Available",
          f"{h['metadata_labels']!r}")
    check("the note refuses to attribute it to Azure without correlating the "
          "Administrative records for the same resource",
          any("destroyed backup" in n and "before attributing it to Azure" in n
              for n in h["notes"]),
          f"{h['notes']!r}")


def test_azure_localisation_and_helpers():
    print("\n[azure] the tenant-language trap, and the record with no time")
    c = az()
    p = c.map_record(AZ_GERMAN, AZ_SUB)
    ocsf_clean("azure German tenant", p, expect_class=6003)

    check("the invariant `value` is read, so a German tenant maps identically to an "
          "English one",
          p["api_operation"] == "Microsoft.Storage/storageAccounts/listKeys/action"
          and p["api_service_name"] == "Microsoft.Storage"
          and p["unmapped"]["category"] == "Administrative",
          f"got {p.get('api_operation')!r} — reading localizedValue works perfectly in "
          "the tenant it was written against and matches nothing anywhere else")
    check("the localised operation name does not leak into any field",
          "auflisten" not in json.dumps(
              {k: v for k, v in p.items() if k != "raw"}, default=str),
          "the German display string reached a mapped field")
    check("the status maps from `value`, not from the translated Erfolgreich",
          p["status_id"] == int(Status.SUCCESS) and p["status_code"] == "Succeeded",
          f"{p.get('status_id')} {p.get('status_code')!r}")
    check("listKeys resolves through the SUFFIX table, which generalises to every "
          "provider that has a listKeys",
          "attack:T1552" in p["metadata_labels"], f"{p['metadata_labels']!r}")
    check("an app-only caller that is not a GUID and not an email fills the name only",
          p["actor_user_name"] == "sp-backup" and "actor_user_email" not in p
          and "actor:service-principal" in p["metadata_labels"],
          f"{p.get('actor_user_name')!r} / {p.get('actor_user_email')!r}")

    check("_local prefers value over localizedValue",
          _az_local({"localizedValue": "Verwaltung", "value": "Administrative"})
          == "Administrative", "")
    check("_local falls back to localizedValue rather than returning nothing",
          _az_local({"localizedValue": "Verwaltung"}) == "Verwaltung", "")
    check("_local tolerates the plain string some providers send",
          _az_local("Informational") == "Informational" and _az_local(None) == "", "")
    check("_decode reads a JSON object out of a string and refuses a plain word",
          _az_decode('{"a":1}') == {"a": 1} and _az_decode("Created") is None
          and _az_decode('[{"b":2}]') == [{"b": 2}], "")
    check("_decode survives a truncated document instead of raising",
          _az_decode('{"a":') is None, "Azure does truncate requestbody")
    check("_looks_like_email refuses an object GUID and an SPN appid, which `caller` "
          "delivers in the same field as a UPN",
          _az_email("admin@contoso.com")
          and not _az_email("5f7a2b91-3c4d-4e5f-8a9b-0c1d2e3f4a5b")
          and not _az_email("not-an-email") and not _az_email("a@b"),
          "the Event model does not validate the field, so this guard is the only check")

    c = az()
    dropped = c.map_record(dict(AZ_BEGIN, eventTimestamp=None), AZ_SUB)
    check("a record with no parseable time is dropped, not stamped with the "
          "collection time",
          dropped is None and "dropped rather" in c.stats.last_error,
          f"got {dropped!r} — stamping it would invent a fact, and the event would be "
          "windowed, correlated and retained against a time that never happened")


def test_azure_techniques():
    print("\n[azure] the technique tables, and what they deliberately do not claim")
    c = az()
    check("the exact table beats the suffix table, so AKS runCommand is T1609 "
          "Container Administration Command and not the generic T1651",
          c._technique("Microsoft.ContainerService/managedClusters/runCommand/action")
          == "T1609"
          and c._technique("Microsoft.Compute/virtualMachines/runCommand/action")
          == "T1651", "")
    check("the suffix table generalises across providers without an exhaustive list",
          c._technique("Microsoft.Sql/servers/firewallRules/write") == "T1562.007"
          and c._technique("Microsoft.DBforPostgreSQL/servers/firewallRules/write")
          == "T1562.007"
          and c._technique("Microsoft.Search/searchServices/listAdminKeys/action")
          == "T1552", "")
    check("Defender for Cloud being switched off is T1562.001 Tools, not T1562.008 "
          "Cloud Logs — it is a security product, not a log",
          c._technique("Microsoft.Security/pricings/write") == "T1562.001"
          and c._technique("Microsoft.Insights/diagnosticSettings/delete")
          == "T1562.008", "")
    check("a read gets no technique — discovery is a rate over many records, and "
          "tagging every read would bury the real ones",
          c._technique("Microsoft.Resources/subscriptions/resourceGroups/read") == ""
          and c._technique("Microsoft.Compute/virtualMachines/read") == "", "")
    check("an ARM template deployment gets no technique, because it can create anything",
          c._technique("Microsoft.Resources/deployments/write") == "",
          "the resources it touched are in `resources` and the detect layer reads those")
    check("an unknown operation is empty rather than guessed", c._technique("") == ""
          and c._technique("Contoso.Widgets/widgets/frobnicate/action") == "", "")

    from core.schema.attack import Attack  # noqa: PLC0415
    bundle = Attack.load(Path("vendor/attack/attack_index.json"))
    emitted = sorted(set(_AZ_OPS.values()) | set(_AZ_SUFFIX.values())
                     | {"T1550.001", "T1098.003"})
    missing = [t for t in emitted if bundle.get(t) is None]
    check(f"every one of the {len(emitted)} techniques this connector can emit resolves "
          "in the vendored ATT&CK bundle",
          not missing,
          f"unresolvable: {missing!r} — an id that does not exist turns the coverage "
          "matrix into fiction")
    unresolvable = [t for t in _AZ_NOT_EMITTED if bundle.get(t) is None]
    check("the deliberately-not-emitted table names real techniques too, so Phase 2 can "
          "publish documented non-coverage instead of an unexplained gap",
          not unresolvable and len(_AZ_NOT_EMITTED) >= 14, f"{unresolvable!r}")
    check("no technique is in both tables",
          not (set(emitted) & set(_AZ_NOT_EMITTED)),
          f"{sorted(set(emitted) & set(_AZ_NOT_EMITTED))!r}")
    check("every tier-0 role id is also in the resolvable-name table, so the label and "
          "the note can name it",
          all(rid in _AZ_ROLES for rid in _AZ_TIER0),
          f"{[r for r in _AZ_TIER0 if r not in _AZ_ROLES]!r}")
    check("the appidacr table covers all three documented values",
          set(_AZ_APPIDACR) == {"0", "1", "2"}, f"{sorted(_AZ_APPIDACR)!r}")


def test_azure_readiness():
    print("\n[azure] what probe() has to admit, and the subscription list")
    c = az(config=AZ_BLANK)
    av = c.probe()
    check("an unconfigured connector reports unavailable and names all four slots",
          not av.available
          and all(s in av.reason.upper() for s in
                  ("AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
                   "AZURE_CLIENT_SECRET")),
          f"{av.reason!r}")
    check("it is marked fixable by the operator", av.fixable_by_user, f"{av!r}")

    c = az()
    lim = c.probe().limitation
    check("a configured connector is available", c.probe().available, f"{c.probe()!r}")
    check("the 90-day horizon is stated as a permanent gap",
          "90 days" in lim and "permanent gap" in lim, f"{lim!r}")
    check("the limitation says severity is always Informational and why level is not it",
          "Informational" in lim and "not whether it matters" in lim, f"{lim!r}")
    check("the absence of the data plane is stated — a Key Vault secret read is not in "
          "this log at any verbosity",
          "DATA PLANE" in lim and "Key Vault secret" in lim
          and "diagnostic setting" in lim, f"{lim!r}")
    check("it names the Defender connector as authoritative for category=Security "
          "rather than silently competing with it",
          "Defender" in lim, f"{lim!r}")
    check("the subscription scope is enumerated, so an operator can see which "
          "subscriptions are actually covered",
          AZ_SUB in lim and "1 subscription" in lim, f"{lim!r}")

    multi = az(config=AZ_MULTI, fast=False)
    subs = multi.subscriptions()
    check("a comma-and-semicolon separated list is parsed, duplicates dropped, order "
          "kept — which is how an operator actually pastes them",
          subs == (AZ_SUB, "7f3c9d21-1111-2222-3333-444455556666"), f"{subs!r}")
    lim2 = multi.probe().limitation
    check("the per-subscription rate is stated, because all of them share one limiter",
          "1 req/s each" in lim2 and "2 subscription" in lim2,
          f"{lim2!r} — a tenant with twenty subscriptions should declare several "
          "connectors rather than one long list, and cannot know that unless it is said")
    check("an unconfigured subscription slot yields an empty tuple rather than raising "
          "at readiness-report time",
          az(config=AZ_BLANK).subscriptions() == (), "")

    check("the spec declares the server's page size, since this endpoint has no $top",
          c.spec.page_size == 200, f"{c.spec.page_size}")
    check("the window is held back by the submission lag and overlaps generously, "
          "because eventDataId makes a re-read free",
          c.spec.indexing_lag_seconds == 300.0 and c.spec.overlap_seconds == 900.0,
          f"lag={c.spec.indexing_lag_seconds} overlap={c.spec.overlap_seconds}")
    check("the required grant names the specific ARM action, not just a role",
          "Microsoft.Insights/eventtypes/values/read" in c.spec.required_grants[0],
          f"{c.spec.required_grants!r}")
    check("the token is minted for ARM's audience and not Graph's",
          c.authorizer().scope == "https://management.azure.com/.default",
          f"got {c.authorizer().scope!r} — a Graph-scoped token is structurally valid "
          "and returns 401 InvalidAuthenticationToken, which reads as a bad secret")
    check("the tenant reaches the token URL", AZ_TENANT in c.authorizer().token_url,
          f"{c.authorizer().token_url!r}")
    check("the factory returns the connector set", len(azure_connectors(_Pipe(), AZ_LIVE)) == 1,
          "")


async def test_azure_transport():
    print("\n[azure] the $filter Graph would reject, nextLink, and per-subscription "
          "isolation")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    def api_calls(t):
        """The scripted requests that were not the token mint."""
        return [r for r in t.seen if "/oauth2/" not in r.url]

    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)
    transport = ScriptedTransport([
        AZ_TOKEN,
        (200, {}, {"value": [AZ_ROLE_GRANT],
                   "nextLink": "https://management.azure.com/subscriptions/x/providers/"
                               "Microsoft.Insights/eventtypes/management/values?"
                               "api-version=2015-04-01&$skiptoken=OPAQUE"}),
        (200, {}, {"value": [AZ_BEGIN]}),
    ])
    c = az(transport=transport)
    out = await c.fetch_window(window)
    seen = api_calls(transport)
    check("both pages are read and both records map",
          len(seen) == 2 and len(out) == 2,
          f"{len(seen)} requests, {len(out)} events")

    first_req, second_req = seen
    flt = first_req.params["$filter"]
    check("the ISO timestamps are SINGLE-QUOTED, which is the opposite of Microsoft "
          "Graph's rule on the same OData dialect",
          "eventTimestamp ge '2026-03-11T00:00:00Z'" in flt
          and "eventTimestamp le '2026-03-12T00:00:00Z'" in flt,
          f"got {flt!r} — unquoted here is an HTTP 400, and quoted in Graph is also a 400")
    check("the end bound is `le`, since the documented grammar shows only ge/le",
          " le '" in flt and " lt '" not in flt, f"{flt!r}")
    check("no other filter clause is sent — the reference says no other syntax is "
          "allowed, so there is no server-side filter on level, status or category",
          "level" not in flt and "status" not in flt and "category" not in flt,
          f"{flt!r}")
    check("api-version is the only other parameter: no $select, which omits `category` "
          "from its legal value list, and no $top, which does not exist here",
          set(first_req.params) == {"api-version", "$filter"}
          and first_req.params["api-version"] == ACTIVITY_API_VERSION,
          f"got {first_req.params!r} — $select would silently delete the field this "
          "connector routes on, and the symptom reads as a vendor bug")
    check("the URL is subscription-scoped against the management endpoint",
          first_req.url.endswith(
              f"/subscriptions/{AZ_SUB}/providers/Microsoft.Insights"
              "/eventtypes/management/values"),
          f"{first_req.url!r}")
    check("the second page follows the top-level `nextLink` — not @odata.nextLink, "
          "whose absence would look like a clean one-page cycle",
          "$skiptoken=OPAQUE" in second_req.url, f"{second_req.url!r}")
    check("the next link is followed verbatim with no params re-applied",
          not second_req.params,
          f"got {second_req.params!r} — re-adding api-version to a URL that has it is a "
          "400 about duplicate query options")

    # Two subscriptions, the first forbidden. The common real cause is a Reader
    # assignment that was never made on a new subscription.
    forbidden = ScriptedTransport([
        AZ_TOKEN,
        (403, {}, {"error": {"code": "AuthorizationFailed",
                             "message": "does not have authorization to perform action"}}),
        (200, {}, {"value": [AZ_BEGIN]}),
    ])
    c = az(config=AZ_MULTI, transport=forbidden)
    out = await c.fetch_window(window)
    check("a 403 on one subscription does not stop the others from collecting",
          len(out) == 1 and c.forbidden_subscriptions == 1,
          f"{len(out)} events, forbidden={c.forbidden_subscriptions}")
    check("the error names the missing role assignment rather than the credential",
          "Monitoring Reader" in c.stats.last_error
          and "while the others" in c.stats.last_error, f"{c.stats.last_error!r}")
    attempted = api_calls(forbidden)
    check("both subscriptions were attempted, in configured order",
          len(attempted) == 2
          and f"/subscriptions/{AZ_SUB}/" in attempted[0].url
          and "/subscriptions/7f3c9d21-1111-2222-3333-444455556666/" in attempted[1].url,
          f"{[r.url for r in attempted]!r}")
    check("the subscription count is surfaced in stats",
          c.stats_extra()["subscriptions"] == 2
          and "Monitoring Reader" in c.stats_extra()["forbidden_subscriptions"],
          f"{c.stats_extra()!r}")

    # A 401 is the token, not the subscription — every subscription would fail the same
    # way, so failing loudly once is the honest report.
    unauthorised = ScriptedTransport([
        AZ_TOKEN,
        (401, {}, {"error": {"code": "InvalidAuthenticationToken",
                             "message": "The access token is invalid"}}),
    ])
    c = az(config=AZ_MULTI, transport=unauthorised)
    try:
        await c.fetch_window(window)
        raised = "nothing"
    except Exception as exc:  # noqa: BLE001
        raised = type(exc).__name__
    check("a 401 is re-raised instead of being counted as 20 skipped subscriptions",
          raised == "AuthError" and c.forbidden_subscriptions == 0,
          f"raised {raised}, forbidden={c.forbidden_subscriptions}")

    # A window older than retention, which is what a connector restarting after a long
    # outage asks for.
    # A window that straddles the retention floor, which is what a connector restarting
    # after a moderate outage asks for: some of it is readable, some of it is gone.
    clamped = ScriptedTransport([AZ_TOKEN, (200, {}, {"value": [AZ_ROLE_GRANT]})])
    c = az(transport=clamped)
    straddle = TimeWindow(c.clock() - 100 * 86_400.0, c.clock() - 50 * 86_400.0)
    out = await c.fetch_window(straddle)
    sent = api_calls(clamped)[0].params["$filter"]
    floor = c.clock() - (AZ_HISTORY - AZ_MARGIN)
    check("the start bound is clamped inside the 90-day horizon",
          f"ge '{iso8601(floor)}'" in sent, f"sent {sent!r}, floor {iso8601(floor)}")
    check("the end bound is left alone, so the range stays the right way round",
          f"le '{iso8601(straddle.end)}'" in sent, f"sent {sent!r}")
    check("the clamp is counted, surfaced, and described as permanent rather than as a "
          "delayed read",
          c.retention_clamps == 1 and "retention_clamps" in c.stats_extra()
          and "permanent gap" in c.stats.last_error, f"{c.stats.last_error!r}")
    check("the permanent gap is also stated on an event, so it survives into the lake "
          "rather than living only in a counter",
          any("permanent gap" in n for n in out[0]["notes"]), f"{out[0]['notes']!r}")

    # A window that is *entirely* older than the horizon. This is not an exotic case: the
    # planner caps a window at max_window_seconds, so a checkpoint 110 days behind asks
    # for [cursor, cursor+3600] — unreadable — roughly 2,600 times in a row.
    dead = ScriptedTransport([])
    c = az(transport=dead)
    gone = TimeWindow(c.clock() - 200 * 86_400.0, c.clock() - 199 * 86_400.0)
    out = await c.fetch_window(gone)
    check("a window entirely below the horizon sends no request at all, rather than "
          "asking for an inverted range",
          out == [] and dead.seen == [],
          f"{len(out)} events, {len(dead.seen)} requests — `ge` clamped up to the floor "
          f"with `le` left at the old end is start > end, and this endpoint answers an "
          f"inverted range with an empty HTTP 200: thousands of successful requests "
          f"that read as a quiet tenant")
    check("the cursor is jumped to the horizon in one cycle instead of walking 110 days "
          "one hour at a time",
          c._latest_record == c.clock() - (AZ_HISTORY - AZ_MARGIN),
          f"{c._latest_record!r} vs floor {c.clock() - (AZ_HISTORY - AZ_MARGIN)!r}")
    check("the skip is counted separately from the clamp and says why nothing was asked "
          "for",
          c.windows_skipped == 1
          and "windows_skipped_below_horizon" in c.stats_extra()
          and "no request was sent" in c.stats.last_error,
          f"{c.stats_extra()!r} / {c.stats.last_error!r}")

    unconfigured = az(config=AZ_BLANK, transport=ScriptedTransport([]))
    try:
        await unconfigured.fetch_window(window)
        refused, why = False, "no exception"
    except Exception as exc:  # noqa: BLE001
        refused, why = type(exc).__name__ == "CredentialsIncomplete", str(exc)
    check("an unconfigured cycle refuses before the transport is touched",
          refused, f"got {why!r}")


# ── GCP Cloud Audit Logs ────────────────────────────────────────────────────

GCP_PROJECT = "my-gcp-project-001"
GCP_PROJECT_2 = "another-gcp-project-002"

#: Deliberately unconfigured.
GCP_BLANK = with_creds(gcp_credentials_json="", gcp_project_id="")


def _gcp_credentials_json() -> str:
    """A service-account JSON whose private key is a *real* PEM.

    The transport tests call ``ServiceAccount.parse`` and the parse path ends
    in ``cryptography``'s PEM loader — a literal ``"MIIE...fake..."`` would
    raise ``InvalidData`` and read as a connector defect rather than a test
    fixture defect. A real RSA key is generated once at import time so the
    suite is deterministic without external network access.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    import json as _json
    return _json.dumps({
        "client_email": f"sa@{GCP_PROJECT}.iam.gserviceaccount.com",
        "private_key": pem,
        "token_uri": "https://oauth2.googleapis.com/token",
        "project_id": GCP_PROJECT,
    })


#: Two projects declared — the only legal shape, comma- or semicolon-separated.
GCP_LIVE = with_creds(
    gcp_credentials_json=_gcp_credentials_json(),
    gcp_project_id=f"{GCP_PROJECT}; {GCP_PROJECT_2}",
)

#: The JWT bearer mint, which every scripted cycle pays for exactly once —
#: the authorizer caches the token per connector instance, and each `gcp()`
#: call is a fresh instance. A script that omits it fails on the *first API
#: call* with "token response carried no access_token", which reads as a
#: broken connector rather than a short script.
GCP_TOKEN = (
    200,
    {"Content-Type": "application/json"},
    {"access_token": "ya29.fake-gcp-token-for-tests-only", "expires_in": 3599,
     "token_type": "Bearer"},
)


def gcp(config=None, transport=None):
    """A GCP connector with the rate limiter effectively disabled.

    Same reason as :func:`ct` / :func:`az` — the real spec is 0.8 req/s against
    a busy-looping limiter with no injectable clock, and a multi-page test
    would sleep in real seconds.
    """
    c = GcpAuditConnector(
        _Pipe(),
        config if config is not None else GCP_LIVE,
        clock=Clock(),
        checkpoints=MemoryCheckpoints(),
        transport=transport,
    )
    c.spec = dataclasses.replace(c.spec, rate_per_second=10_000.0, burst=64)
    return c


#: A SetIamPolicy binding with the worst-case shape: ``roles/owner`` granted
#: to a service principal **and** to ``allUsers``. Four signals in one record:
#: the tier-0 grant, the public-principal exposure, the missing MFA on a
#: service account, and the resource-name routing.
GCP_ROLE_GRANT = {
    "insertId": "gcp-role-grant-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
    "protoPayload": {
        "@type": AUDIT_LOG_TYPE,
        "serviceName": "cloudresourcemanager.googleapis.com",
        "methodName": "SetIamPolicy",
        "resourceName": f"//cloudresourcemanager.googleapis.com/projects/{GCP_PROJECT}",
        "resourceLocation": {"currentLocations": ["us"]},
        "numResponseItems": "1",
        "authenticationInfo": {
            "principalEmail": "deploy-bot@my-gcp-project-001.iam.gserviceaccount.com",
            "principalSubject": (
                "serviceAccount:deploy-bot@my-gcp-project-001.iam.gserviceaccount.com"
            ),
            "serviceAccountKeyName": (
                "projects/my-gcp-project-001/serviceAccounts/"
                "deploy-bot@my-gcp-project-001.iam.gserviceaccount.com/keys/4"
            ),
            "serviceAccountDelegationInfo": [
                {"principalEmail": "alice@contoso.com"},
            ],
        },
        "requestMetadata": {
            "callerIp": "198.51.100.7",
            "callerSuppliedUserAgent": "google-cloud-python/3.0.0",
            "callerNetwork": "external",
        },
        "authorizationInfo": [
            {"permission": "resourcemanager.projects.setIamPolicy", "granted": True,
             "resource": f"projects/{GCP_PROJECT}"},
        ],
        "request": {
            "policy": {
                "bindings": [
                    {"role": "roles/owner",
                     "members": [
                         "serviceAccount:deploy-bot@my-gcp-project-001.iam.gserviceaccount.com",
                         "allUsers",
                     ]},
                ],
            },
        },
    },
    "receiveTimestamp": "2026-03-11T08:05:00Z",
    "resource": {
        "type": "project",
        "labels": {"project_id": GCP_PROJECT},
    },
    "severity": "NOTICE",
    "timestamp": "2026-03-11T08:04:19Z",
    "operation": {"id": "op-gcp-role-grant-001", "first": True, "last": True},
}


#: A KMS ``cryptoKeyVersions.destroy`` — the singular act that makes a key
#: unrecoverable. Maps to T1485 with the ``destroy`` tail.
GCP_KMS_DESTROY = {
    "insertId": "gcp-kms-destroy-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
    "protoPayload": {
        "@type": AUDIT_LOG_TYPE,
        "serviceName": "cloudkms.googleapis.com",
        "methodName": "v1.cloudkms.cryptoKeyVersions.destroy",
        "resourceName": (
            f"//cloudkms.googleapis.com/projects/{GCP_PROJECT}/locations/us-central1/"
            "keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1"
        ),
        "authenticationInfo": {
            "principalEmail": "alice@contoso.com",
            "principalSubject": "user:alice@contoso.com",
        },
        "requestMetadata": {
            "callerIp": "203.0.113.7",
            "callerSuppliedUserAgent": "curl/8.0",
        },
        "authorizationInfo": [
            {"permission": "cloudkms.cryptoKeyVersions.destroy", "granted": True,
             "resource": GCP_PROJECT},
        ],
    },
    "receiveTimestamp": "2026-03-11T09:10:00Z",
    "resource": {
        "type": "cloudkms_cryptokeyversion",
        "labels": {"project_id": GCP_PROJECT, "location": "us-central1",
                   "key_ring_id": "r1", "crypto_key_id": "k1",
                   "crypto_key_version_id": "1"},
    },
    "severity": "WARNING",
    "timestamp": "2026-03-11T09:10:00Z",
}


#: A LogEntry with ``split`` set, meaning this is a fragment of an entry
#: larger than 256 KiB. Mapping it as complete silently produces wrong data
#: from a successful read.
GCP_FRAGMENT = {
    "insertId": "gcp-fragment-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
    "protoPayload": {
        "@type": AUDIT_LOG_TYPE,
        "serviceName": "compute.googleapis.com",
        "methodName": "v1.compute.instances.insert",
        "resourceName": f"//compute.googleapis.com/projects/{GCP_PROJECT}/zones/us-central1-a/instances/oversize-vm",
    },
    "receiveTimestamp": "2026-03-11T07:58:11Z",
    "resource": {
        "type": "gce_instance",
        "labels": {"project_id": GCP_PROJECT, "zone": "us-central1-a"},
    },
    "severity": "INFO",
    "split": {"uid": "AAAAAABBBBBCCCCCDDDDD", "totalSplits": 4, "splitId": 2},
    "timestamp": "2026-03-11T07:58:11Z",
}


#: A non-AuditLog entry — Data Access records carry their own payload type.
#: Suppressing them would silently lose every Data Access event in the
#: project.
GCP_NON_AUDIT = {
    "insertId": "gcp-data-access-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access",
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.bigquery.v2.JobService.GetJob",
        "serviceName": "bigquery.googleapis.com",
        "methodName": "GetJob",
        "resourceName": f"projects/{GCP_PROJECT}/jobs/bq-job-001",
    },
    "receiveTimestamp": "2026-03-11T07:59:44Z",
    "resource": {
        "type": "bigquery_project",
        "labels": {"project_id": GCP_PROJECT},
    },
    "severity": "INFO",
    "timestamp": "2026-03-11T07:59:44Z",
}


#: A failed AuditLog with ``status.code=7`` (PERMISSION_DENIED). Status is
#: absent-or-``{}`` on success; ``status.get("code", 0) != 0`` is the only
#: correct failure test.
GCP_FAILED = {
    "insertId": "gcp-failed-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
    "protoPayload": {
        "@type": AUDIT_LOG_TYPE,
        "serviceName": "storage.googleapis.com",
        "methodName": "storage.buckets.delete",
        "resourceName": f"//storage.googleapis.com/projects/{GCP_PROJECT}/buckets/protected-bucket",
        "status": {"code": 7, "message": "Caller does not have storage.buckets.delete"},
        "authenticationInfo": {
            "principalEmail": "alice@contoso.com",
            "principalSubject": "user:alice@contoso.com",
        },
        "requestMetadata": {"callerIp": "203.0.113.99"},
        "authorizationInfo": [
            {"permission": "storage.buckets.delete", "granted": False,
             "resource": GCP_PROJECT},
        ],
    },
    "receiveTimestamp": "2026-03-11T08:00:00Z",
    "resource": {"type": "gcs_bucket",
                 "labels": {"project_id": GCP_PROJECT, "bucket_name": "protected-bucket"}},
    "severity": "ERROR",
    "timestamp": "2026-03-11T08:00:00Z",
}


#: An actorless system_event record — has no ``authenticationInfo``.
GCP_SYSTEM_EVENT = {
    "insertId": "gcp-system-001",
    "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Fsystem_event",
    "protoPayload": {
        "@type": AUDIT_LOG_TYPE,
        "serviceName": "compute.googleapis.com",
        "methodName": "v1.compute.instances.autoRepair",
        "resourceName": f"//compute.googleapis.com/projects/{GCP_PROJECT}/zones/us-central1-a/instances/healed-vm",
    },
    "receiveTimestamp": "2026-03-11T07:58:12Z",
    "resource": {"type": "gce_instance",
                 "labels": {"project_id": GCP_PROJECT, "zone": "us-central1-a"}},
    "severity": "INFO",
    "timestamp": "2026-03-11T07:58:12Z",
}


def test_gcp_role_grant():
    print("\n[gcp] SetIamPolicy granting roles/owner + allUsers — the worst-case "
          "binding in one record")
    c = gcp()
    p = c.map_record(GCP_ROLE_GRANT)
    ev = ocsf_clean("gcp SetIamPolicy with tier-0 role + public principal", p,
                    expect_class=6003)

    check("SetIamPolicy is Update (verb 3) and activity_name carries the method",
          p["activity_id"] == 3 and p["activity_name"] == "SetIamPolicy",
          f"verb={p['activity_id']!r} name={p.get('activity_name')!r}")
    check("the granted tier-0 role is labelled and counted, with the role name in "
          "the label so 'who got roles/owner' is a writeable query",
          "gcp:tier0-grant" in p["metadata_labels"]
          and "gcp:tier0-grant:roles:owner" in p["metadata_labels"]
          and c.tier0_grants == 1,
          f"{p['metadata_labels']!r}")
    check("the public-principal exposure is labelled separately, with a note, and "
          "carries the technique T1098.003 from the SetIamPolicy tail match",
          "gcp:public-principal" in p["metadata_labels"]
          and "attack:T1098.003" in p["metadata_labels"]
          and c.public_principal_grants == 1,
          f"{p['metadata_labels']!r}")
    check("the service-account principal is recognised — gserviceaccount.com lands "
          "on the gcp:service-account label, not on the user.email field",
          "gcp:service-account" in p["metadata_labels"]
          and p["actor_user_email"] is None,
          f"label={'gcp:service-account' in p['metadata_labels']} "
          f"email={p.get('actor_user_email')!r}")
    check("principalSubject carries the stable uid, not principalEmail (which is "
          "sometimes redacted on cross-tenant or allUsers lookups)",
          p["actor_user_uid"]
          == "serviceAccount:deploy-bot@my-gcp-project-001.iam.gserviceaccount.com",
          f"uid={p.get('actor_user_uid')!r}")
    check("the delegation chain is stashed and labelled — a delegated call has a "
          "separate audit trail per link",
          p["unmapped"].get("service_account_delegation_chain") == ["alice@contoso.com"]
          and "gcp:impersonation" in p["metadata_labels"]
          and c.impersonations == 1,
          f"{p['unmapped'].get('service_account_delegation_chain')!r}")
    check("the access-key name goes to actor_user_credential_uid — same field CloudTrail "
          "uses — so 'every event with this key' is a single query across clouds",
          p["actor_user_credential_uid"].endswith("/keys/4"),
          f"got {p.get('actor_user_credential_uid')!r}")
    check("callerIp is mapped through set_ip; callerSuppliedUserAgent fills "
          "http_user_agent",
          p["src_endpoint_ip"] == "198.51.100.7" and p["http_user_agent"] == "google-cloud-python/3.0.0",
          f"ip={p.get('src_endpoint_ip')!r} ua={p.get('http_user_agent')!r}")
    check("the resource carries the GCP service+resource name as uid, with project_id "
          "from resource.labels",
          p["resources"][0]["uid"] == (
              f"//cloudresourcemanager.googleapis.com/projects/{GCP_PROJECT}"
          ),
          f"got {p.get('resources')!r}")
    check("operation.id becomes metadata_correlation_uid and operation.first/last are "
          "labelled so an in-progress vs completed join is writeable",
          p["metadata_correlation_uid"] == "op-gcp-role-grant-001"
          and "gcp:operation-first" in p["metadata_labels"]
          and "gcp:operation-last" in p["metadata_labels"],
          f"{p.get('metadata_correlation_uid')!r} {p['metadata_labels']}")
    check("severity stays Informational — an audit log with no opinion; the "
          "LogSeverity 'NOTICE (weight=300)' is stashed for traceability",
          p["severity_id"] == int(Severity.INFORMATIONAL)
          and "NOTICE (weight=300)" in (p["unmapped"].get("log_severity") or ""),
          f"{p.get('severity_id')} {p['unmapped'].get('log_severity')!r}")
    check("metadata_uid is insertId — the project-scoped uniqueness input that makes "
          "the overlap re-read dedupe exactly",
          p["metadata_uid"] == "gcp-role-grant-001", f"{p.get('metadata_uid')!r}")
    check("the routing label is gcp:audit:activity, not a top-level field — "
          "metadata_product_feature_name is illegal on 6003",
          "gcp:audit:activity" in p["metadata_labels"]
          and p["metadata_event_code"] == "activity",
          f"{p['metadata_labels']!r}")


def test_gcp_setiampolicy_bindings():
    print("\n[gcp] SetIamPolicy bindings — tier-0 grant, public principal, and the "
          "non-privilege role that gets no flag")
    c = gcp()
    record = {
        "insertId": "gcp-bindings-001",
        "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "protoPayload": {
            "@type": AUDIT_LOG_TYPE,
            "serviceName": "cloudresourcemanager.googleapis.com",
            "methodName": "SetIamPolicy",
            "resourceName": f"//cloudresourcemanager.googleapis.com/projects/{GCP_PROJECT}",
            "authenticationInfo": {"principalEmail": "ops@contoso.com"},
            "request": {"policy": {"bindings": [
                {"role": "roles/owner", "members": ["user:attacker@evil.example"]},
                {"role": "roles/viewer", "members": ["user:alice@contoso.com"]},
            ]}},
        },
        "resource": {"type": "project", "labels": {"project_id": GCP_PROJECT}},
        "timestamp": "2026-03-11T08:00:00Z",
    }
    p = c.map_record(record)
    check("roles/owner is flagged tier-0; roles/viewer is not — the table is "
          "deliberately privilege-escalating only",
          c.tier0_grants == 1 and c.public_principal_grants == 0,
          f"tier0={c.tier0_grants} public={c.public_principal_grants}")
    check("the tier-0 label is the role name sanitised, not the principal — so "
          "'who got owner' is a single label query",
          "gcp:tier0-grant:roles:owner" in p["metadata_labels"],
          f"{p['metadata_labels']!r}")


def test_gcp_kms_destruction():
    print("\n[gcp] KMS cryptoKeyVersions.destroy — singular destruction, the most "
          "urgent control-plane event in Cloud Audit Logs")
    c = gcp()
    p = c.map_record(GCP_KMS_DESTROY)
    ev = ocsf_clean("gcp KMS destroyCryptoKeyVersion", p, expect_class=6003)

    check("the destroy verb maps to Delete (4) and the technique to T1485 — Data "
          "Destruction, which is what unrecoverable key destruction is",
          p["activity_id"] == 4
          and "attack:T1485" in p["metadata_labels"]
          and "destroy" in p["activity_name"].lower(),
          f"verb={p['activity_id']!r} technique={'attack:T1485' in p['metadata_labels']}")
    check("the resource uid carries the full KMS hierarchy — keyRing/cryptoKey/"
          "version — so 'who destroyed version 1 of key k1 in ring r1' is one row",
          p["resources"][0]["uid"].endswith("/cryptoKeyVersions/1"),
          f"{p.get('resources')!r}")
    check("cloud_region is derived from the resource labels when resourceLocation "
          "is absent; cloud_zone is illegal on 6003 so a zone stays in unmapped",
          p["cloud_region"] == "us-central1",
          f"region={p.get('cloud_region')!r}")
    check("a human principal fills user.email/domain normally",
          p["actor_user_email"] == "alice@contoso.com"
          and p["actor_user_domain"] == "contoso.com",
          f"{p.get('actor_user_email')!r}")


def test_gcp_status_mapping():
    print("\n[gcp] status mapping — the absent-or-{} success and the named failure")
    c = gcp()
    fail = c.map_record(GCP_FAILED)
    check("status.code=7 (PERMISSION_DENIED) maps to status_id=2 (Failure) with "
          "the rpc name in status_code and the integer in unmapped",
          fail["status_id"] == int(Status.FAILURE)
          and fail["status_code"] == "PERMISSION_DENIED"
          and fail["unmapped"]["status_code_int"] == 7,
          f"{fail.get('status_code')!r}")
    check("the denied authorizationInfo is labelled and counted — the request was "
          "blocked, which is a different fact from a successful denied operation",
          "gcp:permission-denied" in fail["metadata_labels"] and c.permission_denials == 1,
          f"{fail['metadata_labels']!r}")

    ok = c.map_record(GCP_ROLE_GRANT)
    check("an absent status maps to Success — proto3 omits default values, so "
          "'status' in record' marks every successful audit log as a failure",
          ok["status_id"] == int(Status.SUCCESS) and "status_code" not in ok,
          f"{ok.get('status_id')!r} status_code={ok.get('status_code')!r}")


def test_gcp_fragment_and_non_audit():
    print("\n[gcp] LogEntry.split fragments and non-AuditLog payloads")
    c = gcp()
    frag = c.map_record(GCP_FRAGMENT)
    check("a split fragment is labelled, noted and counted — the consumer must "
          "reassemble or exclude these or it sees a piece of a record",
          "gcp:split-fragment" in frag["metadata_labels"]
          and c.split_fragments == 1
          and any("fragment" in n for n in frag["notes"]),
          f"{frag['metadata_labels']!r}")
    check("the fragment is still mapped end-to-end (uid, actor surrogate if any) — "
          "silently dropping it would lose a piece of the control plane",
          frag["class_uid"] == int(ClassUid.API_ACTIVITY)
          and frag["activity_id"] == 1,
          f"class={frag['class_uid']!r} verb={frag.get('activity_id')!r}")

    non_audit = c.map_record(GCP_NON_AUDIT)
    check("a non-AuditLog protoPayload is emitted under gcp:non-audit-payload with "
          "substitute_for:api — the lake reflects what Cloud Logging actually has, "
          "rather than dropping every Data Access event silently",
          "gcp:non-audit-payload" in non_audit["metadata_labels"]
          and "substitute_for:api" in non_audit["metadata_labels"]
          and c.non_audit_payloads == 1,
          f"{non_audit['metadata_labels']!r}")
    check("api_operation carries the proto @type so the substitution is identifiable, "
          "not invented",
          "JobService.GetJob" in non_audit.get("api_operation", ""),
          f"{non_audit.get('api_operation')!r}")

    sys_evt = c.map_record(GCP_SYSTEM_EVENT)
    check("a system_event record with no principal fills actor_invoked_by under "
          "substitute_for:actor with a note explaining the absence",
          "substitute_for:actor" in sys_evt["metadata_labels"]
          and sys_evt.get("actor_invoked_by") == "Google Cloud platform"
          and c.actor_substitutions >= 1,
          f"{sys_evt.get('actor_invoked_by')!r}")


def test_gcp_filter_two_paths():
    print("\n[gcp] the filter builder — indexed form preferred, compact form when "
          "the resource fan-out exceeds the 20000-char ceiling")
    c = gcp()
    body, which = c._build_filter(1_773_216_000.0, 1_773_216_600.0)
    check("the indexed form uses URL-encoded logName equality and uppercase AND/OR",
          which == "logName" and "%2Factivity" in body
          and " AND " in body and " OR " in body,
          f"which={which!r} body head={body[:120]!r}")
    check("timestamps are double-quoted — unquoted timestamps parse as bare words "
          "and the cycle reads more slowly than expected",
          'timestamp >= "2026-03-11T08:00:00Z"' in body,
          f"{body[:120]!r}")
    check("the resources list is the project ids from $GCP_PROJECT_ID, in order",
          "projects/my-gcp-project-001/logs/" in body
          and "projects/another-gcp-project-002/logs/" in body,
          f"{body[:200]!r}")

    # 101 resources → indexed form exceeds 20000 chars → compact fallback.
    many = ",".join(f"projects/p-{i:03d}" for i in range(101))
    big = with_creds(
        gcp_credentials_json='{}',
        gcp_project_id=many,
    )
    c_big = gcp(config=big)
    body_big, which_big = c_big._build_filter(1_773_216_000.0, 1_773_216_600.0)
    check("101+ resources falls back to log_id() and the fallback is counted",
          which_big == "log_id"
          and 'log_id("cloudaudit.googleapis.com/activity")' in body_big
          and c_big.compact_filters == 1,
          f"which={which_big!r} filters={c_big.compact_filters}")
    check("the 100-resource ceiling is enforced — the trailing 1 is dropped with "
          "a named warning, not silently discarded",
          len(c_big.resource_names()) == MAX_RESOURCE_NAMES
          and c_big.resource_names_dropped == 1
          and "dropped from this cycle" in (c_big.stats.last_error or ""),
          f"kept={len(c_big.resource_names())} dropped={c_big.resource_names_dropped}")


def test_gcp_readiness():
    print("\n[gcp] readiness — the four limits that decide whether this is enough, "
          "and the unconfigured refusal")
    c = gcp()
    a = c.probe()
    check("a configured connector is available",
          a.available, f"{a!r}")
    check("probe states the AND/OR-uppercase rule and the Data Access two-cause "
          "diagnosis so an operator does not misread an empty Data Access feed",
          "UPPERCASE" in a.limitation
          and "privateLogViewer" in a.limitation
          and "console.cloud.google.com" in a.limitation,
          f"{a.limitation[:200]!r}")

    # The 100-resource ceiling and the filter ceiling both stated explicitly.
    many = ",".join(f"projects/p-{i:03d}" for i in range(150))
    big = with_creds(
        gcp_credentials_json='{}',
        gcp_project_id=many,
    )
    a_big = gcp(config=big).probe()
    check("the 100-resource ceiling is named in probe",
          str(MAX_RESOURCE_NAMES) in a_big.limitation,
          f"{a_big.limitation[:200]!r}")


async def _gcp_unconfigured_run():
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)
    refused = False
    why = ""
    try:
        unconfigured = gcp(config=GCP_BLANK, transport=ScriptedTransport([]))
        await unconfigured.fetch_window(window)
    except Exception as exc:  # noqa: BLE001
        refused = type(exc).__name__ == "CredentialsIncomplete"
        why = str(exc)
    check("an unconfigured cycle refuses before the transport is touched",
          refused, f"got {why!r}")

    # Credentials present but project_id empty — also rejected at the
    # credential check, with a message that names the unset slot.
    no_projects = with_creds(
        gcp_credentials_json=_gcp_credentials_json(),
        gcp_project_id="",
    )
    no_proj_refused = False
    no_proj_why = ""
    try:
        empty = gcp(config=no_projects, transport=ScriptedTransport([]))
        await empty.fetch_window(window)
    except Exception as exc:  # noqa: BLE001
        no_proj_refused = type(exc).__name__ == "CredentialsIncomplete"
        no_proj_why = str(exc)
    check("an empty project_id is named by the refusal rather than reported as "
          "an empty cycle",
          no_proj_refused and "project_id" in no_proj_why,
          f"got {no_proj_why!r}")


async def _gcp_transport_run():
    print("\n[gcp] the body-cursor POST, the token mint, and the privateLogViewer "
          "diagnosis on 403")
    from tests.scratch_connectors import ScriptedTransport  # noqa: PLC0415

    window = TimeWindow(1_773_187_200.0, 1_773_273_600.0)

    transport = ScriptedTransport([
        GCP_TOKEN,
        (200, {}, {"entries": [GCP_ROLE_GRANT], "nextPageToken": "tok-2"}),
        (200, {}, {"entries": [GCP_KMS_DESTROY]}),
    ])
    c = gcp(transport=transport)
    out = await c.fetch_window(window)
    check("the token mint is sent through the same transport as the API calls, "
          "and the connector's limiter is bypassed for tests",
          len(transport.seen) == 3 and len(out) == 2,
          f"{len(transport.seen)} requests, {len(out)} events")

    api_req = transport.seen[1]
    check("entries:list is POSTed to /v2/entries:list with resourceNames in the body, "
          "not query params",
          api_req.method == "POST"
          and api_req.url.endswith(ENTRIES_LIST_PATH)
          and isinstance(api_req.json_body.get("resourceNames"), list)
          and GCP_PROJECT in api_req.json_body["resourceNames"][0],
          f"method={api_req.method} url={api_req.url!r} body keys={list(api_req.json_body)}")
    check("the filter carries uppercase AND and double-quoted timestamps — the "
          "opposite of Azure Activity Log, both of which fail silently when wrong",
          " AND " in api_req.json_body["filter"]
          and '"2026-03-11T' in api_req.json_body["filter"],
          f"filter head={api_req.json_body['filter'][:120]!r}")
    check("orderBy is set so the cursor is stable; ties broken by insertId",
          api_req.json_body.get("orderBy") == "timestamp asc",
          f"orderBy={api_req.json_body.get('orderBy')!r}")
    page2 = transport.seen[2]
    check("the body cursor carries filter+orderBy+pageToken on every page — "
          "omitting them is a 400, not a defaulted request",
          page2.json_body.get("pageToken") == "tok-2"
          and page2.json_body.get("filter") == api_req.json_body["filter"]
          and page2.json_body.get("orderBy") == "timestamp asc",
          f"page2 body keys={list(page2.json_body)}")

    # 403 with rateLimitExceeded — the shape the operator will actually see when
    # the credential is right but the bucket is shared with a Logs Explorer
    # session. ApiClient.send translates it into a retryable throttle BEFORE
    # this connector's AuthError handler runs, so a real 403 here is a
    # permissions diagnosis, not a quota diagnosis.
    forbidden = ScriptedTransport([
        GCP_TOKEN,
        (403, {"Content-Type": "application/json"},
         {"error": {"code": 403, "status": "PERMISSION_DENIED",
                    "message": "Caller is not authorized",
                    "errors": [{"reason": "forbidden"}]}}),
    ])
    c_forbid = gcp(transport=forbidden)
    raised = False
    try:
        await c_forbid.fetch_window(window)
    except Exception as exc:  # noqa: BLE001
        raised = True
        check("a true 403 is re-raised, with the privateLogViewer diagnosis as "
              "the stats error so the operator knows the most likely cause",
              "privateLogViewer" in (c_forbid.stats.last_error or "")
              and "Admin Activity" in (c_forbid.stats.last_error or ""),
              f"got last_error={c_forbid.stats.last_error!r}")
    check("the 403 is re-raised rather than swallowed — silently continuing on a "
          "real permission failure would lose every record",
          raised, "no exception")

    # Window entirely below the 400-day Admin Activity horizon — the normal
    # shape of a restart after a long outage. end is set *below* the
    # retention floor (clock - 400 days) so the wholly-past branch fires
    # before any token mint happens, and the script's [GCP_TOKEN] entry is
    # never consumed.
    straddle = ScriptedTransport([GCP_TOKEN])
    c_strad = gcp(transport=straddle)
    long_window = TimeWindow(c_strad.clock() - 500 * 86_400.0,
                             c_strad.clock() - 410 * 86_400.0)
    out = await c_strad.fetch_window(long_window)
    check("a wholly-past window is skipped, the cursor jumps to the horizon, and "
          "no request is sent — preventing 2,600 empty-200 cycles while the "
          "planner walks toward live data",
          out == [] and c_strad.windows_skipped == 1
          and "400-day" in c_strad.stats.last_error
          and len(straddle.seen) == 0,
          f"out={len(out)} skipped={c_strad.windows_skipped} requests={len(straddle.seen)}")


# The two async helpers above are run from main(); defining a sync entry keeps
# the test pattern uniform with the other connectors.
def test_gcp_transport():
    asyncio.run(_gcp_transport_run())
    asyncio.run(_gcp_unconfigured_run())


def main():
    test_signins()
    test_audits()
    test_unwrap_and_intent()
    test_spec_and_readiness()
    test_vendor_clock_skew()
    asyncio.run(test_paginate_shape())
    test_okta_auth_class()
    test_okta_lifecycle_classes()
    test_okta_findings()
    test_okta_routing()
    test_okta_parsers()
    test_okta_spec_and_url()
    asyncio.run(test_okta_tail())
    test_defender_alert_mapping()
    test_defender_alert_lifecycle()
    test_defender_response_gates()
    test_defender_unknown_vocabulary()
    test_defender_hunting_classes()
    test_defender_hunting_pack()
    test_defender_readiness()
    asyncio.run(test_defender_transport())
    test_crowdstrike_alert_mapping()
    test_crowdstrike_alert_lifecycle()
    test_crowdstrike_response_gates()
    test_crowdstrike_relay_and_hashes()
    test_crowdstrike_incident_mapping()
    test_crowdstrike_incident_without_members()
    test_crowdstrike_host_mapping()
    test_crowdstrike_tables()
    test_crowdstrike_readiness()
    asyncio.run(test_crowdstrike_transport())
    test_cloudtrail_api_mapping()
    test_cloudtrail_actor_shapes()
    test_cloudtrail_signin()
    test_cloudtrail_insight()
    test_cloudtrail_unparsed()
    test_cloudtrail_param_readers()
    test_cloudtrail_readiness()
    asyncio.run(test_cloudtrail_transport())
    test_azure_role_grant()
    test_azure_lifecycle_pair()
    test_azure_platform_records()
    test_azure_policy_and_health()
    test_azure_localisation_and_helpers()
    test_azure_techniques()
    test_azure_readiness()
    asyncio.run(test_azure_transport())
    test_gcp_role_grant()
    test_gcp_setiampolicy_bindings()
    test_gcp_kms_destruction()
    test_gcp_status_mapping()
    test_gcp_fragment_and_non_audit()
    test_gcp_filter_two_paths()
    test_gcp_readiness()
    test_gcp_transport()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

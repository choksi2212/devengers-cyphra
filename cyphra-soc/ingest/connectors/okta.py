"""Okta — the System Log: one endpoint, five OCSF classes.

``GET /api/v1/logs`` is the whole of Okta's audit surface. Everything an Okta org does
arrives through it — sign-ins, MFA challenges, user and group lifecycle, admin role
grants, app and policy changes, ThreatInsight detections — as one stream of ``LogEvent``
objects distinguished only by ``eventType``. So this file is mostly a routing argument.

── Follow the Link header. Do not re-derive ``since`` ────────────────────────
This is the one connector in the package whose durable cursor is **not** a timestamp,
and the reason is a documented property of the API rather than a convenience. Okta
indexes the System Log by *publish* order, not by event time, and it publishes late:
an event that happened at 14:22 can be indexed after one that happened at 14:25. A
poller that re-derives ``since`` from the newest ``published`` it has seen therefore
skips every event indexed behind that watermark, silently and permanently — the exact
straggler loss Entra's ``overlap_seconds`` mitigates but cannot close.

Okta's answer is pagination as the cursor: the ``Link rel="next"`` URL carries an
``after`` cursor in publish order, and following it is *lossless* by construction.
:attr:`~ingest.connectors.base.Connector.opaque_cursor` is where it lives, which is
why that field exists on the base at all. The planned :class:`TimeWindow` is used for
exactly one request in this connector's life — the bootstrap, before any ``next`` link
exists — and is ignored on every cycle after it. Two consequences worth stating rather
than discovering:

* ``indexing_lag_seconds`` is **0**, and that is not an oversight. A hold-back exists
  to keep a not-yet-indexed record inside the next *window*; there are no windows here.
* Hitting the page ceiling loses nothing at all. The ``next`` link this cycle did not
  follow is saved as the resume point, so the tail continues exactly where it stopped —
  a stronger guarantee than the window connectors can make, and the reason
  :meth:`OktaSystemLogConnector.next_delay` keeps polling without cadence delay until
  the tail is drained.

``self.cursor`` is still maintained, by the base, from each record's ``published``. It
is a *reporting* value and a cold-start fallback for a checkpoint that has no
``opaque_cursor``; ``overlap_seconds`` is an hour so that fallback re-reads rather than
skips, and the re-read is free because ``uuid`` makes dedup exact.

── The ``next`` link is a live tail, so it is always present ─────────────────
An unbounded System Log query returns a ``next`` link even when the result set is
empty — that is what makes it pollable. Returning it unconditionally from
:meth:`_next_link` would make :meth:`~ingest.connectors.base.Connector.paginate` walk
to its 200-page ceiling on every cycle of a quiet org, burning the whole rate-limit
budget to read nothing. So the link is returned only when the page carried records,
and saved regardless — the empty page that stops the loop is precisely where the
correct resume point is.

── A top-level JSON array ───────────────────────────────────────────────────
No envelope, no ``value`` key: the body *is* the array. ``records_at=()`` and
:func:`~ingest.connectors.base.normalise_records` takes its list branch.

── ``severity`` is a log level, not a threat score ──────────────────────────
Okta grades every record DEBUG / INFO / WARN / ERROR, and those are severities of
*logging*: a mistyped password is WARN and an internal Okta failure is ERROR. Copying
them into ``severity_id`` would file every failed sign-in as Low and every Okta hiccup
as Medium, which is a log level wearing a threat score's clothes. Following the rule
:mod:`ingest.connectors.entra` set — only a source that is itself an alerting product
may set severity from its own field — the level is kept in ``unmapped.okta_severity``
and ``severity_id`` stays Informational, **except** on the 2004 Detection Findings,
where ``security.threat.detected`` genuinely is ThreatInsight alerting and a finding
recorded as Informational reads as "nothing to see".

── ``is_mfa`` is left unset on sign-ins, deliberately ───────────────────────
``user.session.start`` does not say how many factors were used; Okta emits the factor
verification as its own ``user.authentication.auth_via_mfa`` record sharing a
``transaction.id``. So this connector sets ``is_mfa`` true where a record *is* a factor
event and never sets it false, because "this sign-in was single-factor" is a conclusion
drawn from the absence of a sibling record — a correlation, which is the detect layer's
job. Writing ``is_mfa = False`` here would state it as an observation.

── The org URL, not the admin URL ───────────────────────────────────────────
``$OKTA_DOMAIN`` must be the org URL (``acme.okta.com``, or a configured custom
domain). The admin URL — ``acme-admin.okta.com`` — hosts the console, not the API, and
requests to it fail in a way that names neither the URL nor the token.
:meth:`OktaSystemLogConnector.probe` checks for it before a single request goes out,
because the alternative is a connector that reports configured and returns nothing.

── Deliberately not collected here ─────────────────────────────────────────
``/api/v1/users`` and ``/api/v1/groups`` are directory *state*, not telemetry, and
belong to the asset/identity enrichment of Phase 3 rather than to an event stream.
``verdict_id`` is never set on the findings this connector emits: OCSF's verdict is a
disposition, and a connector that pre-dispositioned Okta's own detections would be
answering the question triage exists to answer.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import ClassUid, FindingStatus, RiskLevel, Severity, Status
from ingest.collectors.base import Availability, unavailable
from ingest.connectors.auth import Authorizer, StaticHeaderAuth, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    dig,
    iso8601,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import HttpResponse, Request
from ingest.connectors.mapping import (
    MESSAGE_LIMIT,
    as_bool,
    attack,
    evidence,
    label,
    note,
    prune,
    put,
    resource_ref,
    severity_from_name,
    stash,
    status_from_outcome,
)

LOG_PATH = "/api/v1/logs"

#: Okta's own hostname suffixes for the *admin* console. The API is not served here.
_ADMIN_HOST_MARKERS = ("-admin.okta.com", "-admin.oktapreview.com", "-admin.okta-emea.com")


# ── routing: eventType → (class, activity) ──────────────────────────────────
#
# Exact eventTypes first. This table is not an optimisation over the verb rule below —
# it is the statement of what this connector *understands*, and several entries are
# ones the verb rule would get wrong: `user.account.update_password` is a Password
# Change (8) rather than a generic Update (2), `group.lifecycle.create` is Create (6)
# rather than 3007's Create (1), and `user.lifecycle.suspend` has no member of its own
# on 3007 at all. An unlisted eventType falls to the verb rule and is noted on the
# event, so a new Okta event type shows up in the lake as an explicit gap rather than
# as a silently coarse mapping.

_A, _U, _G, _E, _F = (
    int(ClassUid.AUTHENTICATION),
    int(ClassUid.USER_MANAGEMENT),
    int(ClassUid.GROUP_MANAGEMENT),
    int(ClassUid.ENTITY_MANAGEMENT),
    int(ClassUid.DETECTION_FINDING),
)

_ROUTES: Mapping[str, tuple[int, int]] = {
    # ── 3002 Authentication ──
    "user.session.start": (_A, 1),
    "user.session.end": (_A, 2),
    "user.session.clear": (_A, 2),
    "user.authentication.sso": (_A, 1),
    "user.authentication.verify": (_A, 1),
    "user.authentication.auth_via_social": (_A, 1),
    "user.authentication.auth_via_inbound_saml": (_A, 1),
    "user.authentication.auth_via_idp": (_A, 1),
    "user.authentication.auth_via_richclient": (_A, 1),
    "user.authentication.auth_via_ad_agent": (_A, 1),
    "user.authentication.auth_via_ldap_agent": (_A, 1),
    # An MFA step is not a Logon and OCSF 3002 has no member for it — Preauth (6) is
    # Kerberos pre-authentication, which this is not. 99 with the vendor's own
    # eventType as `activity_name`, which the event model requires and which is more
    # precise than any of the eight members would have been.
    "user.authentication.auth_via_mfa": (_A, 99),
    "user.mfa.okta_verify.deny_push": (_A, 99),
    "user.mfa.attempt_bypass": (_A, 99),
    "system.push.send_factor_verify_push": (_A, 99),
    "policy.evaluate_sign_on": (_A, 99),
    "user.session.access_admin_app": (_A, 99),
    # Support impersonation. Okta's 2023 support-system compromise ran through exactly
    # this event, and it is the one 3002 record where actor and user are different
    # people by design: the admin is `actor_user_*`, the impersonated account is
    # `user_*`.
    "user.session.impersonation.initiate": (_A, 99),
    "user.session.impersonation.grant": (_A, 99),
    "user.session.impersonation.extend": (_A, 99),
    "user.session.impersonation.end": (_A, 2),
    "user.session.impersonation.revoke": (_A, 2),
    "user.session.context.change": (_A, 99),
    # ── 3007 User Management ──
    "user.lifecycle.create": (_U, 1),
    "user.lifecycle.delete.initiated": (_U, 3),
    "user.lifecycle.delete.completed": (_U, 3),
    "user.lifecycle.activate": (_U, 4),
    "user.lifecycle.reactivate": (_U, 4),
    # Suspend/unsuspend have members on 3004 (12/13) and none on 3007, so they are
    # Disable/Enable here. The distinction Okta draws — a suspended account keeps its
    # assignments, a deactivated one loses them — survives in `activity_name`.
    "user.lifecycle.unsuspend": (_U, 4),
    "user.lifecycle.deactivate": (_U, 5),
    "user.lifecycle.suspend": (_U, 5),
    "user.account.lock": (_U, 6),
    "user.account.lock.limit": (_U, 6),
    "user.account.unlock": (_U, 7),
    "user.account.unlock_by_admin": (_U, 7),
    "user.account.update_password": (_U, 8),
    "user.account.reset_password": (_U, 9),
    "user.account.update_profile": (_U, 2),
    "user.account.update_primary_email": (_U, 2),
    "user.account.privilege.grant": (_U, 14),
    "user.account.privilege.revoke": (_U, 15),
    "user.mfa.factor.activate": (_U, 12),
    "user.mfa.factor.update": (_U, 12),
    "user.mfa.factor.unsuspend": (_U, 12),
    "user.credential.enroll": (_U, 12),
    "user.mfa.factor.deactivate": (_U, 13),
    "user.mfa.factor.reset": (_U, 13),
    "user.mfa.factor.reset_all": (_U, 13),
    "user.mfa.factor.suspend": (_U, 13),
    # An Okta API token inherits the permissions of the admin who created it, so it is
    # that admin's programmatic credential — 18/19 on 3007 — rather than an entity of
    # its own. The target is a Token, which is why `user_*` comes from the actor here;
    # see `_fill_user`.
    "system.api_token.create": (_U, 18),
    "system.api_token.revoke": (_U, 19),
    # ── 3006 Group Management ──
    "group.user_membership.add": (_G, 3),
    "group.user_membership.remove": (_G, 4),
    "group.lifecycle.create": (_G, 6),
    "group.lifecycle.delete": (_G, 5),
    "group.lifecycle.update": (_G, 9),
    "group.profile.update": (_G, 9),
    "group.privilege.grant": (_G, 1),
    "group.privilege.revoke": (_G, 2),
    # An app assignment is not a policy, so not 10/11 Attach/Detach Policies. Update,
    # with the app kept in `resources`.
    "group.application_assignment.add": (_G, 9),
    "group.application_assignment.remove": (_G, 9),
    # ── 3004 Entity Management ──
    "application.lifecycle.create": (_E, 1),
    "application.lifecycle.update": (_E, 3),
    "application.lifecycle.delete": (_E, 4),
    "application.lifecycle.activate": (_E, 8),
    "application.lifecycle.deactivate": (_E, 9),
    "application.user_membership.add": (_E, 3),
    "application.user_membership.remove": (_E, 3),
    "policy.lifecycle.create": (_E, 1),
    "policy.lifecycle.update": (_E, 3),
    "policy.lifecycle.delete": (_E, 4),
    "policy.lifecycle.activate": (_E, 8),
    "policy.lifecycle.deactivate": (_E, 9),
    "policy.rule.add": (_E, 1),
    "policy.rule.update": (_E, 3),
    "policy.rule.delete": (_E, 4),
    "policy.rule.activate": (_E, 8),
    "policy.rule.deactivate": (_E, 9),
    "zone.create": (_E, 1),
    "zone.update": (_E, 3),
    "zone.delete": (_E, 4),
    "group.rule.create": (_E, 1),
    "group.rule.update": (_E, 3),
    "group.rule.delete": (_E, 4),
    "group.rule.activate": (_E, 8),
    "group.rule.deactivate": (_E, 9),
    "system.idp.lifecycle.create": (_E, 1),
    "system.idp.lifecycle.update": (_E, 3),
    "system.idp.lifecycle.delete": (_E, 4),
    "system.idp.lifecycle.activate": (_E, 8),
    "system.idp.lifecycle.deactivate": (_E, 9),
    # ── 2004 Detection Finding ──
    "security.threat.detected": (_F, 1),
    "security.request.blocked": (_F, 1),
    "user.account.report_suspicious_activity_by_enduser": (_F, 1),
}

#: eventType prefix → class, for anything the exact table misses. Prefixes decide the
#: *class* only; the activity comes from :data:`_VERB_ACTIVITY` so an unknown event
#: type is never assigned a specific activity nobody checked. Order matters — the
#: longest, most specific prefix must come first.
_CLASS_PREFIXES: tuple[tuple[str, int], ...] = (
    ("user.session.impersonation", _A),
    ("user.authentication.", _A),
    ("user.session.", _A),
    ("user.mfa.", _U),
    ("user.lifecycle.", _U),
    ("user.account.", _U),
    ("user.credential.", _U),
    ("system.api_token.", _U),
    ("group.rule.", _E),
    ("group.user_membership.", _G),
    ("group.lifecycle.", _G),
    ("group.privilege.", _G),
    ("group.profile.", _G),
    ("group.application_assignment.", _G),
    ("security.", _F),
    ("application.", _E),
    ("policy.", _E),
    ("zone.", _E),
    ("system.idp.", _E),
)

#: Class → the verbs that class's activity table names, keyed by the verb read off the
#: eventType's last segment. Per class rather than shared because the same word means
#: different numbers: ``create`` is 1 on 3004/3007 and 6 on 3006, ``delete`` is 4 on
#: 3004, 3 on 3007 and 5 on 3006. A shared table would have been wrong for two classes
#: out of three in a way no test that only exercised one class would have caught.
_VERB_ACTIVITY: Mapping[int, Mapping[str, int]] = {
    _A: {"start": 1, "end": 2, "clear": 2, "logon": 1, "logoff": 2},
    _E: {
        "create": 1, "add": 1, "read": 2, "get": 2, "update": 3, "modify": 3,
        "delete": 4, "remove": 4, "move": 5, "enroll": 6, "unenroll": 7,
        "activate": 10, "deactivate": 11, "enable": 8, "disable": 9,
        "suspend": 12, "unsuspend": 13, "resume": 13,
    },
    _G: {
        "create": 6, "delete": 5, "update": 9, "add": 3, "remove": 4,
        "grant": 1, "revoke": 2,
    },
    _U: {
        "create": 1, "update": 2, "delete": 3, "activate": 4, "unsuspend": 4,
        "enable": 4, "deactivate": 5, "suspend": 5, "disable": 5, "lock": 6,
        "unlock": 7, "grant": 14, "revoke": 15, "enroll": 12, "reset": 13,
    },
    _F: {"detected": 1, "blocked": 1, "created": 1, "updated": 2, "closed": 3},
}

#: Trailing segments that qualify an operation rather than name it, so the verb is the
#: segment *before* them. ``user.lifecycle.delete.initiated`` is a Delete; reading
#: ``initiated`` as the verb would find nothing and fall to 99.
_QUALIFIER_SEGMENTS = frozenset(
    {"initiated", "completed", "limit", "by_admin", "requested", "failed", "success"}
)

#: The same qualifiers where Okta joined them to the verb with an underscore instead of
#: a dot. Not a variant spelling of :data:`_QUALIFIER_SEGMENTS` — ``by_admin`` appears in
#: both forms across different event types, so both tables are needed.
_QUALIFIER_SUFFIXES = ("_by_admin", "_by_enduser", "_by_user", "_initiated", "_completed")

#: 3004 is the fallback class, and this is why: it is the class OCSF provides for an
#: administrative change to a directory object that is neither a user nor a group, and
#: it is the only one of the five whose required object (``entity``) any Okta target can
#: fill.
_FALLBACK_CLASS = _E

#: Which object each class requires beyond the base event's own. Measured against the
#: vendored v1.9.0 index, not assumed. Used by :meth:`_route` to check that the class
#: it chose can actually be filled *before* emitting an event that asserts an object it
#: does not have.
_REQUIRED_OBJECT: Mapping[int, str] = {
    _A: "user", _U: "user", _G: "group", _E: "entity", _F: "finding_info",
}

#: eventType → (ATT&CK technique, label). The connector's *hint*: this operation has
#: the shape of that technique. Only entries where that is true — ``user.session.start``
#: gets nothing, because a successful sign-in is not an attack and the failures are
#: hinted from ``outcome.reason`` instead.
_EVENT_ATTACK: Mapping[str, tuple[str, str]] = {
    # MFA fatigue. A denied push is the victim rejecting a challenge they did not
    # start, and a burst of them against one account looks like nothing else.
    "user.mfa.okta_verify.deny_push": ("T1621", "mfa-push-denied"),
    "user.mfa.attempt_bypass": ("T1621", "mfa-bypass-attempt"),
    "user.mfa.factor.deactivate": ("T1556.006", "mfa-weakened"),
    "user.mfa.factor.reset": ("T1556.006", "mfa-weakened"),
    "user.mfa.factor.reset_all": ("T1556.006", "mfa-weakened"),
    "user.mfa.factor.suspend": ("T1556.006", "mfa-weakened"),
    "user.account.reset_password": ("T1098", "password-reset"),
    "user.account.privilege.grant": ("T1098.003", "privilege-granted"),
    "group.privilege.grant": ("T1098.003", "privilege-granted"),
    "group.user_membership.add": ("T1098", "group-membership-added"),
    "user.lifecycle.create": ("T1136.003", "account-created"),
    # An API token is a bearer credential with the creating admin's permissions and no
    # MFA in front of it — the cleanest persistence primitive Okta offers.
    "system.api_token.create": ("T1098.001", "api-token-created"),
    # An OIDC/SAML app registration with client credentials is the same primitive one
    # layer up.
    "application.lifecycle.create": ("T1098.001", "app-created"),
    # An added identity provider is a new way into the org that bypasses its password
    # and MFA policy entirely.
    "system.idp.lifecycle.create": ("T1484.002", "idp-added"),
    "system.idp.lifecycle.update": ("T1484.002", "idp-changed"),
    "user.session.impersonation.initiate": ("T1078.004", "impersonation"),
    "user.session.impersonation.grant": ("T1078.004", "impersonation"),
    "policy.lifecycle.update": ("T1556.009", "auth-policy-changed"),
    "policy.lifecycle.deactivate": ("T1556.009", "auth-policy-changed"),
    "policy.rule.update": ("T1556.009", "auth-policy-changed"),
    "policy.rule.deactivate": ("T1556.009", "auth-policy-changed"),
    "policy.rule.delete": ("T1556.009", "auth-policy-changed"),
    # A network zone is what a sign-on policy's "trusted network" clause resolves
    # against, so widening one weakens every policy that reads it without touching a
    # policy at all.
    "zone.update": ("T1562", "network-zone-changed"),
}

#: ``outcome.reason`` needle → (short reason, ATT&CK hint). Scanned in order as
#: substrings, specific before general, because Okta's reason is sometimes a constant
#: (``INVALID_CREDENTIALS``) and sometimes a sentence containing one (``Sign-on policy
#: evaluation resulted in DENY``). ``APP_LOCKED_OUT`` precedes ``LOCKED_OUT`` for the
#: same reason: the second is a substring of the first.
_OUTCOME_REASONS: tuple[tuple[str, str, str], ...] = (
    ("INVALID_CREDENTIALS", "invalid username or password", "T1110"),
    ("APP_LOCKED_OUT", "application-level lockout", "T1110.001"),
    ("LOCKED_OUT", "account locked out by the org's lockout policy", "T1110.001"),
    ("PASSWORD_EXPIRED", "password expired", ""),
    ("EXPIRED_PASSWORD", "password expired", ""),
    ("THREAT_DETECTED", "blocked by Okta ThreatInsight", "T1110.003"),
    ("VERIFICATION_ERROR", "factor verification failed", "T1110"),
    ("FACTOR_ENROLLMENT_REQUIRED", "factor enrolment required", ""),
    ("MFA_REQUIRED", "MFA required and not satisfied", ""),
    ("USER_NOT_ASSIGNED_TO_APP", "user is not assigned to this application", "T1078.004"),
    ("USER_STATUS_INVALID", "account is not in a state that permits sign-in", ""),
    ("NO_MATCHING_POLICY", "no sign-on policy matched the request", ""),
    ("POLICY_EVALUATION", "denied by sign-on policy evaluation", ""),
    ("SESSION_EXPIRED", "session expired", ""),
    ("INVALID_SESSION", "session invalid or expired", ""),
    ("INVALID_TOKEN", "token invalid or already used", ""),
    ("RATE_LIMIT", "rate limit exceeded", "T1110"),
    ("REVOKED", "credential or session revoked", ""),
    ("DENY", "denied by policy", ""),
)

#: ``authenticationContext.credentialType`` values that are MFA *factors*. These do not
#: set ``auth_protocol_id`` — a one-time code is not a protocol — they set ``is_mfa``.
_MFA_CREDENTIAL_TYPES = frozenset(
    {
        "otp", "sms", "push", "email", "oath_otp", "totp", "call", "question",
        "web_authn", "webauthn", "u2f", "signed_nonce", "token", "token:hardware",
        "token:software:totp", "hotp", "security_question",
    }
)

#: ``credentialType`` → (OCSF 3002 ``auth_protocol_id``, its caption). ``password`` is
#: deliberately absent: Okta checking a password against its own credential store
#: implies no wire protocol, and mapping it to Basic Authentication (11) would assert
#: an HTTP scheme that was never used.
_AUTH_PROTOCOLS: Mapping[str, tuple[int, str]] = {
    "assertion": (5, "SAML"),
    "iwa": (99, "Integrated Windows Authentication"),
    "fed": (99, "federated"),
    "certificate": (99, "certificate"),
}

#: Okta risk level → OCSF ``risk_level_id``. ``none`` is Info rather than Unknown for
#: the same reason as in :mod:`ingest.connectors.entra`: Okta assessed the request and
#: found no risk, which is information rather than the absence of it.
_RISK_LEVELS: Mapping[str, int] = {
    "none": int(RiskLevel.INFO),
    "low": int(RiskLevel.LOW),
    "medium": int(RiskLevel.MEDIUM),
    "high": int(RiskLevel.HIGH),
    "critical": int(RiskLevel.CRITICAL),
}

#: Okta Behavior Detection heuristic → ATT&CK, for the ones that fired POSITIVE. ``New
#: IP`` is absent on purpose: a laptop on a home connection produces it daily, so a
#: technique hint on it would label most of an org's sign-ins.
_BEHAVIOR_ATTACK: Mapping[str, str] = {
    "velocity": "T1078.004",
    "new country": "T1078.004",
    "new geo-location": "T1078.004",
    "new device": "T1078.004",
    "new state": "",
    "new city": "",
    "new ip": "",
}

#: Okta admin roles whose grant is org takeover rather than a permission change.
#: Both spellings of each, because ``debugData.privilegeGranted`` uses the display name
#: ("Super administrator") and a Role target uses the API constant ("SUPER_ADMIN").
#:
#: ``HELP_DESK_ADMIN`` is on this list and looks like it should not be: it can reset
#: passwords and clear MFA factors for non-admin users, which is an account-takeover
#: primitive for every account in the org that matters except the admins.
#: ``READ_ONLY_ADMIN`` and ``REPORT_ADMIN`` are deliberately *not* on it.
_TIER0_ROLES = frozenset(
    {
        "super_admin", "super administrator",
        "org_admin", "organization administrator", "org administrator",
        "app_admin", "application administrator",
        "user_admin", "group administrator",
        "help_desk_admin", "help desk administrator",
        "api_access_management_admin", "api access management administrator",
        "group_membership_admin", "group membership administrator",
        "mobile_admin", "mobile administrator",
    }
)


def _java_map(text: Any) -> dict[str, str]:
    """``{New Device=POSITIVE, Velocity=NEGATIVE}`` → a dict.

    ``debugContext.debugData.behaviors`` is not JSON. It is a Java ``Map.toString()``
    that reached the wire — unquoted keys, ``=`` for the separator — so
    ``json.loads`` raises on it and a connector that only tried JSON would silently
    lose Okta's entire behaviour-detection signal.

    Split on plain commas, which is correct for every heuristic name Okta ships
    (``New Geo-Location``, ``Velocity``) and would break for one containing a comma.
    Stated rather than guarded, because the guard would be a parser for a format that
    has no specification.
    """
    out: dict[str, str] = {}
    body = str(text or "").strip()
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    if not body:
        return out
    for part in body.split(","):
        key, sep, value = part.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _loose_map(text: Any) -> dict[str, str]:
    """A ``debugData`` value that is JSON *or* a Java map, as a dict.

    ``debugData.risk`` is JSON (``{"level":"LOW","reasons":"..."}``) and
    ``debugData.behaviors`` beside it is not. Both are strings in a string-to-string
    map, so which parser applies is a property of the individual value.
    """
    raw = str(text or "").strip()
    if not raw:
        return {}
    if raw.startswith("{") and '"' in raw:
        try:
            decoded = json.loads(raw)
        except (ValueError, TypeError):
            decoded = None
        if isinstance(decoded, Mapping):
            return {str(k): "" if v is None else str(v) for k, v in decoded.items()}
    return _java_map(raw)


def _verb(event_type: str) -> str:
    """The operation word of an eventType — its last meaningful dotted segment.

    Okta writes its qualifiers two ways and both have to be stripped: dotted
    (``user.lifecycle.delete.initiated``) and suffixed (``user.account.unlock_by_admin``,
    ``...report_suspicious_activity_by_enduser``). Handling only the dotted form leaves
    ``unlock_by_admin`` as the verb, which matches nothing and falls to activity 99 — a
    correctly-routed event with a wrong-but-plausible activity, which is worse than an
    unrouted one because nothing flags it.
    """
    segments = [s for s in event_type.split(".") if s]
    while segments and segments[-1] in _QUALIFIER_SEGMENTS:
        segments.pop()
    if not segments:
        return ""
    verb = segments[-1]
    for suffix in _QUALIFIER_SUFFIXES:
        if verb.endswith(suffix) and len(verb) > len(suffix):
            verb = verb[: -len(suffix)]
            break
    return verb


def _targets(record: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    """``target`` bucketed by ``type``, lowercased.

    Okta's group type is ``UserGroup``, not ``Group`` — a table keyed on ``group``
    would find none of them and every membership change would fall through to 3004.
    """
    out: dict[str, list[Mapping[str, Any]]] = {}
    for target in record.get("target") or []:
        if isinstance(target, Mapping):
            out.setdefault(str(target.get("type") or "unknown").lower(), []).append(target)
    return out


def _target_name(target: Mapping[str, Any]) -> str:
    """The most identifying string on a target.

    ``alternateId`` first for a user (it is the login, which joins against every other
    identity source), ``displayName`` first for everything else. Ordered by which one
    a hunt query would search for, not by which one is present more often.
    """
    kind = str(target.get("type") or "").lower()
    if kind in ("user", "appuser"):
        return str(target.get("alternateId") or target.get("displayName") or "")
    return str(target.get("displayName") or target.get("alternateId") or "")


class OktaSystemLogConnector(Connector):
    """Okta System Log → 3002 / 3004 / 3006 / 3007 / 2004, routed by ``eventType``.

    One endpoint and five OCSF classes. The routing rule is the same one
    :mod:`ingest.connectors.entra` argues for its directory audits: the class chosen is
    the one whose *required* object this record can actually supply, verified in
    :meth:`_route` rather than assumed from the event's name. A ``group.privilege.grant``
    with no UserGroup in its targets becomes a 3004, not a 3006 asserting a group that
    is not there.
    """

    name = "okta_system_log"
    description = "Okta System Log (sign-ins, MFA, lifecycle, admin roles, ThreatInsight)"
    detects = (
        "password spray and credential stuffing (INVALID_CREDENTIALS bursts), MFA "
        "fatigue (deny_push, attempt_bypass), MFA factor removal and reset, admin role "
        "grants, API token creation, OIDC app and identity-provider addition, sign-on "
        "policy weakening, support-account impersonation, and Okta ThreatInsight and "
        "Behavior Detection findings"
    )
    spec = ConnectorSpec(
        # The documented maximum for /api/v1/logs. Larger is rejected, not clamped.
        page_size=1000,
        # /api/v1/logs is 60 req/min on most Okta plans (120 on some) and the limit is
        # per-org across every caller, not per-token — so a SOC that consumed its whole
        # budget would break the customer's own integrations. One per second leaves
        # most of it, and the `next`-link cursor means a slow read costs latency rather
        # than data.
        rate_per_second=1.0,
        burst=2,
        # Bootstrap only: after the first cycle the resume point is the `next` link.
        # Okta retains 90 days, so a lookback beyond that returns 400 rather than an
        # empty result — an operator widening this has a hard ceiling.
        initial_lookback_seconds=86_400.0,
        # Used only when a checkpoint has a `cursor` but no `opaque_cursor` — a cold
        # rebuild. An hour of re-read is free (dedup is exact on `uuid`) and is the
        # difference between resuming and skipping.
        overlap_seconds=3600.0,
        max_window_seconds=3600.0,
        # Zero, and deliberately: a hold-back keeps an unindexed record inside the next
        # window, and this connector has no windows after its first request. See the
        # module docstring.
        indexing_lag_seconds=0.0,
        docs_url="https://developer.okta.com/docs/reference/api/system-log/",
        required_grants=(
            "an API token created by an admin holding Read-Only Administrator or "
            "higher — the token inherits its creator's role, so one made by an App or "
            "Group admin returns 403 on this endpoint",
            "or, for an OAuth service app, the okta.logs.read scope with Api Token "
            "granted",
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: The ``next`` link seen this page, promoted to :attr:`opaque_cursor` only once
        #: the page's records have been mapped. See :meth:`_commit_link`.
        self._pending_link = ""
        #: True when a cycle stopped at the page ceiling with tail left to read.
        self._tail_pending = False

    # ── credentials ────────────────────────────────────────────────────────

    def domain(self) -> Credential:
        return self.config.connectors.okta_domain

    def api_token(self) -> Credential:
        return self.config.connectors.okta_api_token

    def credentials(self) -> tuple[Credential, ...]:
        return (self.domain(), self.api_token())

    def authorizer(self) -> Authorizer:
        # `SSWS`, not `Bearer`. An Okta API token presented as a Bearer token returns
        # 401 with no text that names the scheme.
        return StaticHeaderAuth(self.api_token(), scheme="SSWS")

    def base_url(self) -> str:
        """``https://acme.okta.com`` from whatever the operator put in the slot.

        Bare hostname, ``https://`` prefix and a trailing slash are all accepted
        because all three are what the Okta console shows in different places. A
        ``http://`` prefix is *upgraded* rather than honoured: this request carries an
        API token in a header, and sending it in clear because a config file said so is
        not a preference to respect.
        """
        raw = (self.domain().secret or "OKTA-DOMAIN-NOT-CONFIGURED").strip().rstrip("/")
        if raw.lower().startswith("http://"):
            raw = "https://" + raw[len("http://"):]
        elif not raw.lower().startswith("https://"):
            raw = "https://" + raw
        return raw

    def probe(self) -> Availability:
        """Configured, plus the one setup error that looks like a working config.

        There is no request that distinguishes "wrong URL" from "wrong token" in its
        response, so this is checked from the string before any request is made.
        """
        base = super().probe()
        if not base.available:
            return base
        host = self.base_url().lower()
        if any(marker in host for marker in _ADMIN_HOST_MARKERS):
            return unavailable(
                f"$OKTA_DOMAIN is the admin console URL ({self.base_url()}), which "
                "does not serve the API — set it to the org URL instead (drop the "
                "'-admin' from the hostname). Left as it is, this connector "
                "authenticates and returns nothing, which reads as a quiet org"
            )
        return base

    # ── the tail ───────────────────────────────────────────────────────────

    def _next_link(self, resp: HttpResponse, body: Any) -> str | None:
        """The ``Link rel="next"`` URL — remembered always, followed only when useful.

        Two separate jobs, and conflating them breaks one or the other. *Remembering*
        is unconditional because an unbounded System Log query returns a ``next`` link
        even for an empty page, and that link is the correct resume point: it carries
        an ``after`` cursor in publish order, which is strictly better than re-deriving
        ``since`` from a timestamp.

        *Following* is conditional on the page having carried records, because that
        same always-present link is what makes the tail pollable — returned
        unconditionally it would walk
        :meth:`~ingest.connectors.base.Connector.paginate` to its 200-page ceiling
        every cycle on a quiet org and spend the entire rate-limit budget reading empty
        arrays.

        The pairing also keeps the truncation heuristic honest: a full page always
        carries a link, so ``page_size`` records with no next page still means what
        ``paginate`` thinks it means.
        """
        link = resp.link("next")
        if link:
            self._pending_link = link
        records = body if isinstance(body, list) else []
        return link if records else None

    def _commit_link(self) -> None:
        """Promote the remembered link to the durable cursor.

        Separated from :meth:`_next_link` because that runs *before* the page's records
        have been mapped. If the commit happened there, a mapping failure part-way
        through a page would leave the resume point past records this cycle never
        submitted — and :meth:`~ingest.connectors.base.Connector.close` persists
        ``opaque_cursor`` on shutdown, so the skip would survive the restart that
        looked like the fix.
        """
        if self._pending_link:
            self.opaque_cursor = self._pending_link
            self._pending_link = ""

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        resume = self.opaque_cursor
        if resume:
            # Verbatim, with no params: the saved link already carries `after`, `limit`
            # and `sortOrder`, and re-applying this connector's params to it produces a
            # 400 rather than a merge.
            request = Request(
                "GET", resume, label=f"{self.name}.tail",
                headers={"Accept": "application/json"},
            )
        else:
            request = Request(
                "GET",
                f"{self.base_url()}{LOG_PATH}",
                label=f"{self.name}.bootstrap",
                params={
                    # `since` only, no `until`. A bounded query's `next` link is bounded
                    # too, so saving one as the resume point would pin this connector to
                    # a window that ends in the past and never see another event.
                    "since": iso8601(window.start),
                    "limit": self.spec.page_size,
                    # Ascending, so the page cap truncates the *newest* end of a
                    # backlog rather than the oldest — the resume point then continues
                    # forwards. Descending would re-read the same recent page forever
                    # while the backlog aged out of Okta's 90-day retention.
                    "sortOrder": "ASCENDING",
                },
                headers={"Accept": "application/json"},
            )

        caps_before = self.page_cap_hits
        self._pending_link = ""
        out: list[dict[str, Any]] = []
        async for page in self.paginate(
            request, records_at=(), next_url=self._next_link
        ):
            for record in page:
                self.note_record_time(parse_iso8601(record.get("published")))
                payload = self.map_record(record)
                if payload is not None:
                    out.append(payload)
            self._commit_link()
        # The terminating page is empty, and `paginate` does not yield empty pages — so
        # the loop body never runs for it and its link, which is the correct resume
        # point for a quiet org, would be dropped without this.
        self._commit_link()
        self._tail_pending = self.page_cap_hits > caps_before
        return out

    def next_delay(self) -> float:
        """Zero while the tail is not drained.

        The base already does this for a window connector that is catching up, and it
        cannot see this one's backlog: the window it planned was ignored, so
        ``window.catching_up`` is False even with hours of tail pending. Without this
        override an org that produced more than one cycle's worth of events would fall
        further behind every cycle while reporting healthy — the failure the base's own
        docstring calls the worst in that file.
        """
        if self._tail_pending and self.stats.consecutive_failures == 0:
            return 0.0
        return super().next_delay()

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        out["resume"] = "next link" if self.opaque_cursor else "since (no link yet)"
        if self._tail_pending:
            out["tail_pending"] = "yes — polling without cadence delay until drained"
        return out

    # ── routing ────────────────────────────────────────────────────────────

    def _route(
        self,
        event_type: str,
        targets: Mapping[str, list[Mapping[str, Any]]],
        payload: dict[str, Any],
    ) -> tuple[int, int]:
        """(class_uid, activity_id) for this eventType, verified against its targets.

        Three steps, in order of how much is actually known: the exact table, then the
        prefix-plus-verb rule with a note, then 3004 with a note. The last step is the
        one that matters most — an Okta org emits event types this file has never seen,
        every week, and the alternative to routing them somewhere honest is dropping
        them.
        """
        route = _ROUTES.get(event_type)
        if route is None:
            route = self._infer(event_type, payload)
        class_uid, activity_id = route

        if class_uid == _G and not targets.get("usergroup"):
            # 3006 requires `group` and nothing here supplies one. Emitting it anyway
            # would produce an event asserting a group that the record does not name,
            # which is worse than a coarser class: a group-escalation rule would match
            # on an empty group name.
            note(
                payload,
                f"{self.name}: {event_type} routed to 3006 by name but its target list "
                f"has no UserGroup, so class 3006's required "
                f"{_REQUIRED_OBJECT[_G]} object cannot be filled — recorded as 3004 "
                f"Entity Management instead, with "
                f"activity_name carrying the vendor's own event type",
            )
            return _FALLBACK_CLASS, _VERB_ACTIVITY[_E].get(_verb(event_type), 99)
        # 3002's and 3007's required `user` is not checked here, because it is always
        # satisfiable: `_fill_user` fills it from the actor under an explicit
        # substitute_for label. That is not a fallback — on a 3002 the actor *is* the
        # authenticating user, and on `system.api_token.create` the token belongs to the
        # actor. 3004's required `entity` is deliberately left unfilled when no target
        # exists, so the event model's own unfilled-required sweep names it rather than
        # this connector inventing one; see `_fill_targets`.
        return class_uid, activity_id

    def _infer(self, event_type: str, payload: dict[str, Any]) -> tuple[int, int]:
        """An eventType this file does not list: class by prefix, activity by verb."""
        for prefix, class_uid in _CLASS_PREFIXES:
            if event_type.startswith(prefix):
                activity = _VERB_ACTIVITY.get(class_uid, {}).get(_verb(event_type), 99)
                note(
                    payload,
                    f"{self.name}: {event_type} is not in this connector's routing "
                    f"table; the class came from the '{prefix}' prefix and the activity "
                    f"from the '{_verb(event_type) or '(none)'}' verb"
                    + (", which matched nothing, so it is Other" if activity == 99 else ""),
                )
                return class_uid, activity
        note(
            payload,
            f"{self.name}: {event_type} matched no eventType and no prefix in this "
            f"connector's routing table, so it is recorded as 3004 Entity Management "
            f"with activity Other — the vendor's own event type is in activity_name and "
            f"the whole record is in raw. This is the note to query for when adding "
            f"support for a new Okta event type",
        )
        return _FALLBACK_CLASS, 99

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        event_type = str(record.get("eventType") or "").strip()
        lowered = event_type.lower()
        payload: dict[str, Any] = {
            "time": parse_iso8601(record.get("published")),
            # Okta's own event id. Exact dedup, which is what makes an overlapping
            # re-read after a cold restart free rather than duplicated.
            "metadata_uid": str(record.get("uuid") or ""),
            "metadata_product_name": "Okta",
            "metadata_product_vendor_name": "Okta",
            "metadata_log_name": "system_log",
            "metadata_version": "1.9.0",
            "severity_id": int(Severity.INFORMATIONAL),
            "cloud_provider": "Okta",
            "raw": dict(record),
        }
        # `transaction.id` groups the events of one request — the sign-in, its factor
        # verification and its policy evaluation all carry it — which is exactly what a
        # correlation uid is for. `externalSessionId` groups a whole session and is
        # kept separately.
        put(payload, "metadata_correlation_uid", dig(record, "transaction.id"))

        targets = _targets(record)
        class_uid, activity_id = self._route(lowered, targets, payload)
        payload["class_uid"] = class_uid
        payload["activity_id"] = activity_id
        # Always, not only for 99. Okta's eventType is the most precise statement of
        # what happened and every activity_id is a coarse bucket of it; the event model
        # additionally *requires* this when activity_id is 99, which is the case this
        # unconditional assignment guarantees can never be reached unnamed.
        put(payload, "activity_name", event_type or "okta system log event")

        self._fill_outcome(payload, record, class_uid)
        self._fill_actor(payload, record, class_uid, targets)
        self._fill_client(payload, record, class_uid)
        self._fill_debug(payload, record, class_uid)
        self._fill_targets(payload, record, class_uid, targets, event_type)

        # ── provenance ──
        stash(payload, "okta_severity", record.get("severity"))
        stash(payload, "legacy_event_type", record.get("legacyEventType"))
        stash(payload, "okta_event_version", record.get("version"))
        stash(payload, "transaction_type", dig(record, "transaction.type"))
        stash(payload, "transaction_detail", dig(record, "transaction.detail"))
        if str(dig(record, "transaction.type") or "").upper() == "JOB":
            # A background job, not a user request. Baselining it as user behaviour
            # produces a "user" who acts at 03:00 every night.
            label(payload, "okta-background-job")
        stash(payload, "authentication_provider", dig(record, "authenticationContext.authenticationProvider"))
        stash(payload, "authentication_step", dig(record, "authenticationContext.authenticationStep"))
        stash(payload, "authentication_interface", dig(record, "authenticationContext.interface"))
        stash(payload, "issuer_id", dig(record, "authenticationContext.issuer.id"))
        stash(payload, "issuer_type", dig(record, "authenticationContext.issuer.type"))
        stash(payload, "request_ip_chain", dig(record, "request.ipChain"))

        label(payload, "identity", "okta", f"okta-event:{lowered or 'unknown'}")
        hint = _EVENT_ATTACK.get(lowered)
        if hint:
            technique, tag = hint
            attack(payload, technique)
            label(payload, tag)

        put(
            payload,
            "message",
            record.get("displayMessage")
            or f"{event_type or 'okta event'} by "
            f"{dig(record, 'actor.alternateId') or dig(record, 'actor.displayName') or 'unknown actor'}",
            limit=MESSAGE_LIMIT,
        )
        return payload

    # ── outcome ────────────────────────────────────────────────────────────

    def _fill_outcome(
        self, payload: dict[str, Any], record: Mapping[str, Any], class_uid: int
    ) -> None:
        result = str(dig(record, "outcome.result") or "").strip()
        reason = str(dig(record, "outcome.reason") or "").strip()

        if class_uid == _F:
            # 2004's `status_id` is the finding *lifecycle*, a different enum from the
            # three-value operation status — five distinct status_id tables exist in
            # OCSF v1.9.0 and putting Success (1) here would read as "New" on this one.
            # Okta reports its detections once, with no lifecycle, so New is the only
            # honest value.
            payload["status_id"] = int(FindingStatus.NEW)
            put(payload, "status_detail", reason or result, limit=MESSAGE_LIMIT)
        else:
            status = status_from_outcome(result)
            payload["status_id"] = int(status)
            put(payload, "status_code", result or None)
            if status is Status.UNKNOWN and result:
                # CHALLENGE and SKIPPED are the two that land here regularly, and both
                # are real: a challenge was issued and the outcome is in a later record,
                # a step was skipped because a policy did not require it. Labelled so a
                # rule can find them, and *not* coerced to Success, which is the single
                # most dangerous direction to be wrong in on an authentication event.
                label(payload, f"okta-outcome:{result.upper()}")

        if not reason:
            return
        upper = reason.upper()
        for needle, short, technique in _OUTCOME_REASONS:
            if needle in upper:
                if class_uid == _F:
                    put(payload, "finding_desc", reason, limit=MESSAGE_LIMIT)
                else:
                    put(payload, "status_detail", short, limit=MESSAGE_LIMIT)
                if technique:
                    attack(payload, technique)
                stash(payload, "outcome_reason", reason)
                return
        # Unlisted. The vendor's text goes through verbatim rather than being
        # interpreted, and the note says which of the two happened so an operator can
        # tell "we mapped this" from "we copied this".
        if class_uid != _F:
            put(payload, "status_detail", reason, limit=MESSAGE_LIMIT)
        note(
            payload,
            f"{self.name}: outcome.reason {reason!r} is not in this connector's table, "
            "so the vendor's text is carried verbatim rather than as an interpreted "
            "reason",
        )

    # ── who ────────────────────────────────────────────────────────────────

    def _fill_actor(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        class_uid: int,
        targets: Mapping[str, list[Mapping[str, Any]]],
    ) -> None:
        """The ``actor`` — and, where the class allows it, the ``user`` it acted on."""
        actor = record.get("actor") if isinstance(record.get("actor"), Mapping) else {}
        actor_kind = str(actor.get("type") or "").strip()
        # `alternateId` is the login, which is the join key against every other
        # identity source in this SOC. `displayName` is a label and joins against
        # nothing.
        actor_login = str(actor.get("alternateId") or "").strip()
        actor_uid = str(actor.get("id") or "").strip()

        put(payload, "actor_user_name", actor_login or actor.get("displayName"))
        put(payload, "actor_user_uid", actor_uid)
        stash(payload, "actor_display_name", actor.get("displayName"))
        stash(payload, "actor_type", actor_kind)
        stash(payload, "actor_detail_entry", actor.get("detailEntry"))
        if actor_kind and actor_kind.lower() not in ("user", "unknown"):
            # SystemPrincipal, PublicClientApp, PrivateClientApp. Not a person, so no
            # user-behaviour baseline should treat it as one.
            label(payload, f"okta-actor-type:{actor_kind}")
            if actor_kind.lower() != "systemprincipal":
                attack(payload, "T1078.004")

        if class_uid not in (_A, _U, _G):
            # 3004 declares no user object at all and 2004 declares none either; the
            # actor columns above are legal on both and are where this belongs.
            return
        self._fill_user(payload, record, class_uid, targets, actor)

    def _fill_user(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        class_uid: int,
        targets: Mapping[str, list[Mapping[str, Any]]],
        actor: Mapping[str, Any],
    ) -> None:
        """Fill ``user_*``, which 3002 and 3007 require and 3006 declares.

        The subject differs by class and the difference is the point: on a 3002 the
        user *is* the actor, except when it is an impersonation and they are two
        different people; on a 3007 the user is the account being changed; on a 3006 the
        user is the member added to or removed from the group.
        """
        users = targets.get("user") or []
        subject: Mapping[str, Any] | None = users[0] if users else None

        if class_uid == _A and subject is not None:
            if str(subject.get("id") or "") == str(actor.get("id") or ""):
                subject = None  # the same person; `user_*` from the actor below

        if subject is not None:
            put(payload, "user_name", _target_name(subject))
            put(payload, "user_uid", subject.get("id"))
            if subject.get("displayName") and subject.get("alternateId"):
                put(payload, "user_full_name", subject.get("displayName"))
            return

        # No distinct target user. Fill from the actor, which is correct on a 3002 (the
        # actor authenticated) and on `system.api_token.create` (the token is the
        # actor's credential), and is a declared substitution everywhere else.
        put(payload, "user_name", actor.get("alternateId") or actor.get("displayName"))
        put(payload, "user_uid", actor.get("id"))
        if class_uid != _A:
            label(payload, "substitute_for:user")
            note(
                payload,
                f"{self.name}: this record names no User in its target list, so the "
                f"{_REQUIRED_OBJECT[class_uid]} object that class {class_uid} requires "
                f"is filled from the actor "
                f"— the account that performed the operation, which for an API token "
                f"or a self-service change is also its subject. Check the target array "
                f"in unmapped.target before treating actor and subject as one person",
            )
        # `user_type_id` is deliberately not set. OCSF's user object declares a type
        # enum and `actor.type` would map onto it, but object-level enums are absent
        # from the vendored index, so nothing in this system could validate the
        # integer — the same gap that produced this codebase's QueryResultId defect.
        # The vendor string is in unmapped.actor_type, where it is at least honest.

    # ── from where ─────────────────────────────────────────────────────────

    def _client_ip(self, record: Mapping[str, Any]) -> tuple[str, str]:
        """(a valid IP, the raw value if it was not one) from ``client.ipAddress``."""
        scratch: dict[str, Any] = {}
        set_ip(scratch, "ip", dig(record, "client.ipAddress"), note="raw")
        return str(scratch.get("ip") or ""), str(scratch.get("unmapped", {}).get("raw") or "")

    def _fill_client(
        self, payload: dict[str, Any], record: Mapping[str, Any], class_uid: int
    ) -> None:
        ip, raw_ip = self._client_ip(record)
        agent = dig(record, "client.userAgent.rawUserAgent")
        city = dig(record, "client.geographicalContext.city")
        country = dig(record, "client.geographicalContext.country")

        if class_uid == _F:
            # 2004 declares no src_endpoint and no http_request at the top level —
            # measured against the vendored index, not assumed — so the request's
            # origin belongs inside `evidences`, which is the only conformant home for
            # it. `_fill_finding` reads it back out of ``unmapped``, written below, so
            # there is exactly one place that decides what a client fact is.
            pass
        else:
            put(payload, "src_endpoint_ip", ip)
            put(payload, "src_endpoint_city", city)
            put(payload, "src_endpoint_country", country)
            put(payload, "src_endpoint_isp", dig(record, "securityContext.isp"))
            put(payload, "http_user_agent", agent, limit=MESSAGE_LIMIT)
            if class_uid == _A:
                # `session_uid` is declared by 3002 and by none of 3004/3006/3007, so
                # it is guarded rather than swept: on the other three the same value
                # goes to unmapped below, under a name that says what it is.
                put(payload, "session_uid", dig(record, "authenticationContext.externalSessionId"))
        if raw_ip:
            stash(payload, "client_ip_raw", raw_ip)
        if class_uid != _A:
            stash(payload, "external_session_id", dig(record, "authenticationContext.externalSessionId"))
        if class_uid == _F:
            stash(payload, "client_ip", ip)
            stash(payload, "client_user_agent", agent)
            stash(payload, "client_city", city)
            stash(payload, "client_country", country)

        # No flat column exists for these and each answers a question a flat column
        # would not: the subdivision and coordinates are what an impossible-travel rule
        # measures, the AS org is how a residential-proxy network is recognised, and
        # the Okta zone is the org's own answer to "was this on the corporate network".
        stash(payload, "location_state", dig(record, "client.geographicalContext.state"))
        stash(payload, "location_postal_code", dig(record, "client.geographicalContext.postalCode"))
        stash(payload, "geo_coordinates", dig(record, "client.geographicalContext.geolocation"))
        stash(payload, "autonomous_system_number", dig(record, "securityContext.asNumber"))
        stash(payload, "autonomous_system_org", dig(record, "securityContext.asOrg"))
        stash(payload, "security_context_domain", dig(record, "securityContext.domain"))
        stash(payload, "client_zone", dig(record, "client.zone"))
        stash(payload, "client_device_type", dig(record, "client.device"))
        stash(payload, "client_id", dig(record, "client.id"))
        stash(payload, "user_agent_os", dig(record, "client.userAgent.os"))
        stash(payload, "user_agent_browser", dig(record, "client.userAgent.browser"))

        if str(dig(record, "client.zone") or "").upper() == "OFF_NETWORK":
            label(payload, "okta-zone:OFF_NETWORK")
        proxy = as_bool(dig(record, "securityContext.isProxy"))
        if proxy:
            label(payload, "anonymising-proxy")
            attack(payload, "T1090")
        elif proxy is False:
            stash(payload, "is_proxy", False)

        # ── the device Okta Verify / Device Trust reported ──
        device = record.get("device") if isinstance(record.get("device"), Mapping) else {}
        if device:
            put(payload, "device_uid", device.get("id"))
            put(payload, "device_hostname", device.get("name"))
            put(payload, "device_os_name", device.get("os_platform"))
            put(payload, "device_os_version", device.get("os_version"))
            managed = as_bool(device.get("managed"))
            if managed is not None:
                payload["device_is_managed"] = managed
            # `registered` is not folded into is_managed. An org can register a device
            # it does not manage, and coercing one to the other reports every BYOD
            # laptop as corporate-managed.
            stash(payload, "device_is_registered", as_bool(device.get("registered")))
            stash(payload, "device_disk_encryption_type", device.get("disk_encryption_type"))
            stash(payload, "device_screen_lock_type", device.get("screen_lock_type"))
            stash(payload, "device_secure_hardware_present", as_bool(device.get("secure_hardware_present")))
            jailbroken = as_bool(device.get("jailbreak"))
            if jailbroken:
                label(payload, "device-jailbroken")
                attack(payload, "T1398")
            elif jailbroken is False:
                stash(payload, "device_jailbreak", False)

        # ── how the credential was presented ──
        #
        # `is_mfa` and `auth_protocol*` are declared by 3002 and by none of the other
        # four — measured, not assumed. So both are written only there. On a 3007 MFA
        # factor change (`user.mfa.factor.reset`, which is where an attacker weakens
        # MFA) the same fact still has to be recorded, so it goes to ``unmapped``: an
        # unguarded write would be swept out by the event model *and* reported in
        # soc_notes as this connector's mapping error, which it would not be.
        credential = str(dig(record, "authenticationContext.credentialType") or "").strip()
        is_factor = credential.lower() in _MFA_CREDENTIAL_TYPES or str(
            record.get("eventType") or ""
        ).lower().startswith("user.mfa.")
        if credential:
            stash(payload, "credential_type", credential)
            mapped = _AUTH_PROTOCOLS.get(credential.lower())
            if mapped and class_uid == _A:
                proto_id, caption = mapped
                payload["auth_protocol_id"] = proto_id
                payload["auth_protocol"] = caption
            elif mapped:
                stash(payload, "auth_protocol", mapped[1])
        if is_factor:
            if class_uid == _A:
                payload["is_mfa"] = True
            else:
                stash(payload, "is_mfa", True)

    # ── what Okta itself thought of the request ─────────────────────────────

    def _fill_debug(
        self, payload: dict[str, Any], record: Mapping[str, Any], class_uid: int
    ) -> None:
        """``debugContext.debugData`` — Okta's risk, behaviours and granted privileges.

        This is a free-form string-to-string map and it is where three of Okta's most
        useful signals live, none of which has a field of its own: ThreatInsight's risk
        level, Behavior Detection's per-heuristic verdicts, and the actual admin roles
        named by a privilege grant. All three are strings that need parsing, and two of
        the three are not JSON.
        """
        debug = dig(record, "debugContext.debugData")
        if not isinstance(debug, Mapping):
            return
        # The whole map, always. It is the only record of `requestUri`, `dtHash` (a
        # device-token hash that correlates sessions across IP changes), `authnRequestId`
        # and whatever Okta adds next.
        stash(payload, "debug_data", dict(debug))

        threat = as_bool(debug.get("threatSuspected"))
        if threat:
            label(payload, "okta-threat-suspected")
            attack(payload, "T1110.003")

        risk = _loose_map(debug.get("risk"))
        level = str(risk.get("level") or "").strip().lower()
        if level:
            mapped = _RISK_LEVELS.get(level)
            if mapped is None:
                payload["risk_level_id"] = int(RiskLevel.OTHER)
                put(payload, "risk_level", level)
                note(
                    payload,
                    f"{self.name}: Okta risk level {level!r} is not in this "
                    "connector's table; recorded as Other with the vendor string as "
                    "the caption",
                )
            else:
                payload["risk_level_id"] = mapped
                put(payload, "risk_level", level)
            put(payload, "risk_details", risk.get("reasons"), limit=MESSAGE_LIMIT)
            if level in ("high", "critical"):
                label(payload, f"okta-risk:{level}")

        behaviours = _java_map(debug.get("behaviors"))
        positive = [k for k, v in behaviours.items() if v.strip().upper() == "POSITIVE"]
        if behaviours:
            stash(payload, "okta_behaviors", behaviours)
        for name in positive:
            label(payload, f"okta-behavior:{name}")
            technique = _BEHAVIOR_ATTACK.get(name.strip().lower())
            if technique:
                attack(payload, technique)
        if positive:
            put(
                payload,
                "risk_details",
                payload.get("risk_details")
                or "Okta behaviour detection: " + ", ".join(positive),
                limit=MESSAGE_LIMIT,
            )

        # ThreatInsight in log-only mode puts what it *would* have blocked here rather
        # than acting, so an org in audit mode has its detections only in this key.
        stash(payload, "log_only_security_data", debug.get("logOnlySecurityData"))

    # ── what was changed ───────────────────────────────────────────────────

    def _fill_targets(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        class_uid: int,
        targets: Mapping[str, list[Mapping[str, Any]]],
        event_type: str,
    ) -> None:
        """The class's own object columns, plus every target regardless.

        The full ``target`` array always goes to ``unmapped``. An Okta record routinely
        names three or four objects — the user, the group, the app, the policy rule —
        and OCSF's singular ``user``/``group``/``entity`` holds one each. Dropping the
        rest loses the answer to "what else did this touch".
        """
        flat = [t for bucket in targets.values() for t in bucket]
        stash(payload, "target", flat)

        groups = targets.get("usergroup") or []
        if class_uid == _G and groups:
            group = groups[0]
            put(payload, "group_name", _target_name(group))
            put(payload, "group_uid", group.get("id"))
        elif class_uid == _E:
            # The entity is the thing managed. Prefer a target that is not a User: on
            # `application.user_membership.add` both are present and the app is the
            # entity, the user is a participant.
            primary = next((t for t in flat if str(t.get("type") or "").lower() != "user"), None)
            primary = primary or (flat[0] if flat else None)
            if primary is not None:
                put(payload, "entity_name", _target_name(primary))
                put(payload, "entity_uid", primary.get("id"))
                put(payload, "entity_type", primary.get("type"))
            else:
                note(
                    payload,
                    f"{self.name}: {event_type or 'this event type'} carried no target "
                    f"at all, so class 3004's required {_REQUIRED_OBJECT[_E]} object is "
                    "unfilled — the "
                    "actor and the debug context are all this record says. Query "
                    "soc_notes for this to find which Okta event types have no subject",
                )
            put(payload, "comment", record.get("displayMessage"), limit=MESSAGE_LIMIT)

        if class_uid == _F:
            self._fill_finding(payload, record, event_type)

        # ── resources: every target that is not already the class's own object ──
        # Declared by 3006, 3007 and 2004 and by neither 3002 nor 3004 — so this is
        # guarded rather than written unconditionally, because on 3002/3004 the same
        # array would be swept to unmapped and reported in soc_notes as a mapping
        # error, which it would not be. The full array is stashed above either way.
        if class_uid in (_G, _U, _F):
            claimed = {str(payload.get("user_uid") or ""), str(payload.get("group_uid") or "")}
            extra = [
                resource_ref(
                    uid=t.get("id"), name=_target_name(t), type=t.get("type"),
                    data=t.get("detailEntry") or None,
                )
                for t in flat
                if str(t.get("id") or "") not in claimed
            ]
            extra = [r for r in extra if r]
            if extra:
                payload["resources"] = extra

        self._fill_privileges(payload, record, class_uid, flat)

    def _fill_privileges(
        self,
        payload: dict[str, Any],
        record: Mapping[str, Any],
        class_uid: int,
        flat: Sequence[Mapping[str, Any]],
    ) -> None:
        """Admin roles named by this record, and whether any of them is tier-0.

        Two sources because Okta uses both: ``debugData.privilegeGranted`` carries a
        comma-separated list of display names on a role grant, and a ``ROLE`` target
        carries the API constant. Neither is present on every grant.
        """
        granted: list[str] = []
        raw = dig(record, "debugContext.debugData.privilegeGranted")
        for part in str(raw or "").split(","):
            name = part.strip()
            if name and name not in granted:
                granted.append(name)
        for target in flat:
            if str(target.get("type") or "").lower() in ("role", "roleassignment"):
                name = _target_name(target) or str(target.get("alternateId") or "")
                if name and name not in granted:
                    granted.append(name)
        if not granted:
            return

        # `privileges` is declared by 3006 and 3007 only. On 3002/3004/2004 the same
        # list goes to unmapped deliberately, rather than being written and then
        # reported as a mapping error by the event model's own sweep.
        if class_uid in (_G, _U):
            payload["privileges"] = granted
        else:
            stash(payload, "privileges", granted)

        tier0 = [r for r in granted if r.strip().lower() in _TIER0_ROLES]
        if tier0:
            label(payload, "tier0-role", *[f"role:{r}" for r in tier0])
            attack(payload, "T1098.003")
            note(
                payload,
                f"{self.name}: {', '.join(tier0)} — an Okta role that can reset "
                "credentials, clear MFA factors or reassign roles, so this operation "
                "is an org-control change rather than a permission change",
            )

    # ── 2004 Detection Finding ─────────────────────────────────────────────

    def _fill_finding(
        self, payload: dict[str, Any], record: Mapping[str, Any], event_type: str
    ) -> None:
        """Okta ThreatInsight, blocked requests and user-reported activity → 2004.

        2004 is the one class here that is not an IAM record, and it declares a
        different world: no ``user``, no ``src_endpoint``, no ``http_request`` at the
        top level. Everything about *who and from where* therefore goes into
        ``evidences``, which is the only conformant home OCSF gives it.
        """
        put(payload, "finding_uid", record.get("uuid"))
        put(payload, "finding_title", record.get("displayMessage") or event_type,
            limit=MESSAGE_LIMIT)
        put(payload, "finding_desc", dig(record, "outcome.reason"), limit=MESSAGE_LIMIT)
        payload["finding_types"] = [event_type] if event_type else []
        published = parse_iso8601(record.get("published"))
        if published is not None:
            payload["finding_created_time"] = published
        put(payload, "finding_analytic_name", self._analytic(event_type))
        put(payload, "finding_product_uid", "okta-system-log")

        # Severity from the vendor's own word, which is the exception the module
        # docstring names: `security.threat.detected` *is* Okta alerting, and a finding
        # filed Informational reads as nothing to see. The log level is still in
        # unmapped.okta_severity so the two are distinguishable.
        payload["severity_id"] = int(severity_from_name(record.get("severity")))

        # `verdict_id` is deliberately unset. OCSF's verdict is a disposition, and a
        # connector that pre-dispositioned a vendor's detection would be answering the
        # question triage exists to answer. Blocking is recorded in status_detail and
        # in the outcome label instead.

        actor = record.get("actor") if isinstance(record.get("actor"), Mapping) else {}
        # Read back out of ``unmapped``, where `_fill_client` put them precisely because
        # this class has nowhere flat for them. One implementation decides what a client
        # fact is; this one decides where it goes.
        unmapped = payload.get("unmapped", {})
        body = prune(
            {
                "user": {
                    "name": actor.get("alternateId") or actor.get("displayName"),
                    "uid": actor.get("id"),
                },
                "src_endpoint": {
                    "ip": unmapped.get("client_ip"),
                    "city": unmapped.get("client_city"),
                    "country": unmapped.get("client_country"),
                },
                "http_request": {"user_agent": unmapped.get("client_user_agent")},
                # Not `resources` — that array is declared at the top level of 2004 and
                # is filled there by `_fill_targets`. Putting the same targets in both
                # places would make a hunt query's count depend on which copy it read.
            }
        )
        if body:
            payload["evidences"] = [evidence(**body)]
        else:
            note(
                payload,
                f"{self.name}: this finding named neither an actor nor a client "
                "address, so evidences is empty — the record is a bare statement that "
                "Okta detected something, and raw is the only detail available",
            )

    def _analytic(self, event_type: str) -> str:
        """Which Okta feature produced this finding.

        Named rather than left to ``finding_info.analytic``'s default because the three
        producers have entirely different false-positive profiles: ThreatInsight scores
        IP reputation across Okta's whole customer base, request blocking is the org's
        own policy firing, and a user report is a human assertion with no analytic
        behind it at all.
        """
        return {
            "security.threat.detected": "Okta ThreatInsight",
            "security.request.blocked": "Okta request blocking",
            "user.account.report_suspicious_activity_by_enduser": (
                "end-user report (no analytic — a person pressed a button)"
            ),
        }.get(event_type.lower(), "Okta System Log")


def okta_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[OktaSystemLogConnector]:
    """The Okta connector. A list of one, for symmetry with the multi-endpoint vendors.

    One endpoint means one connector: splitting the System Log by ``eventType`` family
    would give several connectors sharing a cursor over the same stream, and the first
    one to advance it would decide what the others never saw.
    """
    return [OktaSystemLogConnector(pipeline, config, **kwargs)]


__all__ = [
    "LOG_PATH",
    "OktaSystemLogConnector",
    "okta_connectors",
]

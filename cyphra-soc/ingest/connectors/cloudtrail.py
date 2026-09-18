"""AWS CloudTrail — the management plane of every AWS account.

CloudTrail records who called which AWS API, from where, with which credential, and
whether it worked. In a cloud-hosted estate this single source answers most of the
questions an intrusion raises: an attacker who phishes a console session or steals an
access key does not run malware, they *call APIs* — `CreateAccessKey`, `AttachRolePolicy`,
`ModifySnapshotAttribute`, `StopLogging` — and every one of those calls is here.

── LookupEvents is a forensic API, not an ingestion pipe ─────────────────────────────

This connector reads the **Event history** API (`LookupEvents`), and its limits are
documented and hard:

* **2 transactions per second**, per account, per region.
* **50 records per page** — `MaxResults` is capped at 50, not 1000.
* **90 days** of history, management events only.

Multiply those out: 2 requests/second × 50 records = **100 events per second at the
absolute ceiling**, and the ceiling assumes no other tool in the account is also calling
LookupEvents (they share the quota). A moderately busy AWS account with a few hundred
EC2 instances, an EKS cluster and any CI/CD automation produces far more management
events than that during a deploy. When it does, this connector reports
``page_cap_hits`` every cycle, falls permanently behind, and *never catches up* —
because the backlog grows faster than 100 events/second drains it.

**The production ingestion path for CloudTrail is a trail delivering to S3, with an S3
event notification or EventBridge rule driving a consumer.** That path has no TPS limit,
no 50-record page, no 90-day horizon, and it delivers data events (S3 object access,
Lambda invocations, DynamoDB item access) which `LookupEvents` cannot return at all.

This connector is not that path and does not pretend to be. It exists because it needs
**one IAM permission and zero infrastructure**, so it turns on in five minutes and gives
a real management-plane feed for a small account, a single region, or an incident where
someone needs the last 90 days *now*. :meth:`CloudTrailConnector.probe` says all of this
in its limitation string, so an operator reading the readiness report learns it there
rather than from a coverage gap during an investigation.

── `CloudTrailEvent` is a JSON document inside a JSON string ─────────────────────────

`LookupEvents` returns an envelope per event, and the actual record is a **string**::

    {"Events": [{"EventId": "...", "EventName": "CreateAccessKey", "EventTime": 1773215891,
                 "CloudTrailEvent": "{\\"eventVersion\\":\\"1.09\\", ... }"}]}

Everything that matters — `userIdentity`, `requestParameters`, `errorCode`,
`sourceIPAddress` — is inside that string. A parse failure must therefore not drop the
record: the envelope alone still carries the event id, name, time, source, username and
resources, which is enough for a conformant, useful 6003. The failure is recorded as a
note and the unparsed string is kept in ``unmapped`` so it can be recovered by hand.

The two shapes also disagree on types. The envelope's `EventTime` is a **Unix number**
and its `ReadOnly` is the **string** ``"true"``; the inner document's `eventTime` is an
**ISO-8601 string** and its `readOnly` is a real boolean. Both are handled — the
timestamp through :func:`parse_iso8601`, which accepts a bare epoch, and the flag
through :func:`as_bool`, which accepts both.

── One endpoint, three OCSF classes ─────────────────────────────────────────────────

`eventType` decides the class, and this is not cosmetic — OCSF 6003 API Activity
declares no top-level ``user`` object, while 3002 Authentication **requires** one. A
single-class mapper would emit every console sign-in with the identity in ``actor`` and
nothing in the required ``user``, which is non-conformant and, worse, invisible to every
authentication rule that looks at ``user_name``.

======================  ==========  ===============================================
`eventType`             OCSF class  What it is
======================  ==========  ===============================================
`AwsApiCall`            6003        the ordinary case — a signed API call
`AwsServiceEvent`       6003        AWS itself acting (KMS key rotation, and so on)
`AwsConsoleAction`      6003        a console action with no underlying API call
`AwsConsoleSignIn`      3002        `ConsoleLogin`, `SwitchRole`, `CheckMfa`
`AwsCloudTrailInsight`  2004        an anomalous API call-rate or error-rate finding
======================  ==========  ===============================================

The three classes have **different legal field sets**, measured against the vendored
OCSF v1.9.0 bundle rather than assumed:

* ``resources`` is legal on 6003 and 2004 and **illegal on 3002** — so the role a
  `SwitchRole` targets goes to ``unmapped``, not to a resource reference.
* ``http_user_agent`` is legal on 6003 and 3002 and **illegal on 2004**.
* ``evidences`` is legal on **2004 only**.
* the whole ``user_*``/``session_*``/``is_mfa`` family is legal on **3002 only**;
  the 32-field ``actor_*`` family is legal on all three.

── `sourceIPAddress` is frequently not an address, and `src_endpoint` is required ────

When one AWS service calls another on your behalf, CloudTrail puts the *service
principal* in `sourceIPAddress`: ``cloudformation.amazonaws.com``,
``ecs-tasks.amazonaws.com``, or the literal ``AWS Internal``. :func:`set_ip` correctly
refuses to put that in an IP field — the value reaches `netsh` in Phase 5 — but
``src_endpoint`` is a **required** object on 6003, so refusing and stopping would leave
the event unconformant. The non-IP therefore goes to ``src_endpoint_svc_name``, which is
one of the twelve measured-legal ``src_endpoint_*`` fields on both 6003 and 3002. The
datum stays queryable, the required object is satisfied, and no IP field holds a
hostname.

There is a second, worse case: ``sourceIPAddress`` **absent entirely**. It lives inside
the ``CloudTrailEvent`` string, and the LookupEvents envelope has no source field, so
this is what a truncated or unparsable inner document looks like. 6003 requires
``src_endpoint`` (3002 and 2004 do not — measured), so an empty one means the Event
model rejects the record and the only surviving copy of a management-plane call lands in
the quarantine table. That is strictly worse than keeping it: the envelope still names
the API, the account, the region and usually the caller. So the object is filled with a
sentinel no real value can collide with, under a ``substitute_for:src_endpoint`` label
and a note — and deliberately *without* the service-principal label or counter, because
an absence of evidence is not an observation of a service caller.

── The actor is five different shapes ───────────────────────────────────────────────

`userIdentity.type` is one of Root, IAMUser, AssumedRole, Role, FederatedUser,
Directory, AWSAccount, AWSService or Unknown, and the name lives somewhere different in
each. A **root** call has no `userName` at all, and "the root account was used" is a CIS
benchmark alarm — so an actor resolution that leaves root unnamed silently disables that
alarm. The fallback chain is therefore explicit: `userName` → the session issuer's
`userName` (the *role* behind an assumed-role session) → the ARN's last segment →
CloudTrail's own denormalised `Username` → `invokedBy` → `principalId`.

`accessKeyId` goes to ``actor_user_credential_uid``. That field is the pivot for the two
questions an AWS intrusion always asks — "what else did this key do?" and "which key do
I rotate?" — and the second one is the direct input to the Phase 5 key-rotation action.

── Throttles arrive as HTTP 400 ─────────────────────────────────────────────────────

AWS's `application/x-amz-json-1.1` protocol returns `ThrottlingException` as **HTTP 400**
with the name in the `x-amzn-errortype` header and the body's `__type`, not as a 429.
That is handled in :mod:`ingest.connectors.http` (see ``THROTTLE_ERROR_NAMES`` and
``throttle_signalled``), which is where it belongs — every AWS connector inherits it —
and it is counted separately as ``throttles_not_sent_as_429`` so an AWS-heavy deployment
cannot report zero throttling while being throttled continuously.

── `requestParameters` is where the intent lives ────────────────────────────────────

`CreateAccessKey` on your own account is routine; `CreateAccessKey` with
``requestParameters.userName`` naming *someone else's* admin user is persistence.
`PutBucketPolicy` is routine; `PutBucketPolicy` whose policy document names a wildcard
principal is public exposure. `AuthorizeSecurityGroupIngress` is routine;
the same call with ``0.0.0.0/0`` on port 22 is an exposed bastion.

The difference is entirely in `requestParameters`, so a per-`eventName` extraction table
(:data:`_PARAM_READERS`) pulls the target out and states it plainly. What it does **not**
do is set severity: only an alerting product may do that, and CloudTrail is an audit log
with no opinion. High-signal calls get an ATT&CK label and a note; the detection layer
decides what that is worth.

Bulk `requestParameters`/`responseElements` are deliberately **not** copied into
``unmapped``. ``raw`` already holds the entire record, and duplicating a 4 KB IAM policy
document per event is pure lake cost for zero query value.

── Every ATT&CK id below was validated against the vendored bundle ──────────────────

All 40 technique ids in :data:`_HIGH_SIGNAL` were resolved through
``Attack.load(...).get(tid)`` before being written here. A plausible-looking but
non-existent sub-technique id in a mapping table is invisible until the coverage matrix
is built, and then it reads as coverage that does not exist.

── Deliberately not collected here ──────────────────────────────────────────────────

* **Data events** (S3 `GetObject`, Lambda `Invoke`, DynamoDB item access) —
  `LookupEvents` cannot return them; they require a trail with data-event selectors.
* **Insights**, unless a trail has them enabled and the query asks for
  ``EventCategory=insight``. The 2004 mapper is written anyway, because an operator who
  enables Insights should not need a code change, and because a replayed Insight record
  must not be dropped.
* **Organization-wide reads.** `LookupEvents` is per-account and per-region; a
  multi-account estate needs one connector instance per account/region pair, which is
  what the registry's per-tenant instantiation is for.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping, NamedTuple, Sequence

from core.config import Credential, SocConfig
from core.schema.ocsf import (
    ClassUid,
    FindingStatus,
    Severity,
    Status,
)
from ingest.collectors.base import Availability, available
from ingest.connectors.auth import Authorizer, SigV4Auth, require
from ingest.connectors.base import (
    Connector,
    ConnectorSpec,
    TimeWindow,
    dig,
    parse_iso8601,
    set_ip,
)
from ingest.connectors.http import HttpError, Request
from ingest.connectors.mapping import (
    API_OTHER,
    MESSAGE_LIMIT,
    as_bool,
    attack,
    crud_activity,
    evidence,
    label,
    note,
    put,
    resource_ref,
    stash,
    status_from_outcome,
)

#: The JSON-RPC operation target. CloudTrail's json1.1 protocol dispatches on this
#: header, not on the URL path — every operation is a POST to ``/``.
LOOKUP_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"

#: CloudTrail speaks json1.1, not plain JSON. Sent *and* signed as this (SigV4 covers
#: Content-Type), which is why it is set explicitly rather than left to the transport's
#: default: a signature computed over ``application/json`` while sending
#: ``application/x-amz-json-1.1`` fails every request with a signature mismatch that
#: reads like a wrong secret key.
AMZ_JSON = "application/x-amz-json-1.1"

#: `MaxResults` ceiling, from the API reference. Values above 50 are not clamped — they
#: are rejected as `InvalidMaxResultsException`.
MAX_LOOKUP_RESULTS = 50

#: Documented LookupEvents quota: 2 TPS per account per region, shared with every other
#: caller in the account (the console's own Event history view included).
LOOKUP_TPS = 2.0

#: Event history retention. Anything older than this is simply absent from the API.
EVENT_HISTORY_SECONDS = 90 * 86_400.0

#: How far inside the 90-day edge a start time is clamped. A request whose StartTime is
#: even slightly older than the horizon is an `InvalidTimeRangeException`, not a
#: truncated result, so the margin has to absorb clock skew and a slow cycle.
RETENTION_MARGIN_SECONDS = 12 * 3_600.0

#: CloudTrail's documented delivery target is "within 15 minutes of the API call". The
#: window planner holds the window end back by this much; without it, every cycle reads
#: a window whose most recent minutes are not populated yet and the overlap re-read is
#: the only thing that ever finds them.
DELIVERY_LAG_SECONDS = 900.0

#: Error names that end a cycle cleanly instead of failing the connector. A LookupEvents
#: `NextToken` expires after roughly an hour; a cycle that started before a long
#: rate-limit hold can therefore present a valid-looking token that the service has
#: already forgotten. Losing the rest of the window is correct — the cursor has not
#: advanced past what was read, so the next cycle re-reads it — but failing the
#: connector and backing off is not.
RECOVERABLE_ERRORS: frozenset[str] = frozenset({
    "invalidnexttoken",
    "invalidnexttokenexception",
})

_A = int(ClassUid.API_ACTIVITY)
_AUTH = int(ClassUid.AUTHENTICATION)
_F = int(ClassUid.DETECTION_FINDING)

# 6003's activity table, for the caption that accompanies every id. Set unconditionally
# rather than only for 99 — see the note in `_fill_api`.
_API_ACTIVITY_NAMES: Mapping[int, str] = {
    0: "Unknown",
    1: "Create",
    2: "Read",
    3: "Update",
    4: "Delete",
    99: "Other",
}

# 3002's activity table, measured: {0 Unknown, 1 Logon, 2 Logoff, 3 Authentication
# Ticket, 4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth,
# 7 Account Switch}. Only the four that a console sign-in event can actually be are
# named here; anything else takes 99 with the vendor's own eventName as the caption.
AUTH_LOGON = 1
AUTH_LOGOFF = 2
AUTH_PREAUTH = 6
AUTH_ACCOUNT_SWITCH = 7
AUTH_OTHER = 99

# `auth_protocol_id`, measured from the vendored bundle's 3002 table rather than
# assumed: {0 Unknown, 1 NTLM, 2 Kerberos, 3 Digest, 4 OpenID, 5 SAML, 6 OAUTH 2.0,
# 7 PAP, 8 CHAP, 9 EAP, 10 RADIUS, 11 Basic Authentication, 12 LDAP, 99 Other}. Both
# federation protocols AWS sign-in actually uses are first-class members, so neither
# has any business being filed as Other.
AUTH_PROTOCOL_OPENID = 4
AUTH_PROTOCOL_SAML = 5

_SIGNIN_ACTIVITIES: Mapping[str, int] = {
    # The console sign-in itself, and the federated equivalent that mints a console
    # session from an STS token — both are a logon and must count as one, because
    # "sign-ins from a new country" is a rule over activity 1.
    "consolelogin": AUTH_LOGON,
    "getsignintoken": AUTH_LOGON,
    "logout": AUTH_LOGOFF,
    # Role switching is lateral movement inside AWS. OCSF has an activity for exactly
    # this and it is not a second logon.
    "switchrole": AUTH_ACCOUNT_SWITCH,
    "exitrole": AUTH_ACCOUNT_SWITCH,
    # An MFA check that precedes the credential decision.
    "checkmfa": AUTH_PREAUTH,
    "credentialchallenge": AUTH_PREAUTH,
    "credentialverification": AUTH_PREAUTH,
}

# 2004's activity table, measured: {0 Unknown, 1 Create, 2 Update, 3 Close, 99 Other}.
FINDING_CREATE = 1
FINDING_CLOSE = 3

# OCSF `user.type_id`. Written out as constants because the vendored index carries
# object *attribute* names but not object *enums*, so unlike every class-level enum in
# this file these five values could not be verified against the bundle — they are from
# the published schema. The raw `userIdentity.type` string is preserved in
# `unmapped.identity_type` for exactly that reason: the coarse id is for rules, the
# string is for the analyst.
USER_UNKNOWN = 0
USER_REGULAR = 1
USER_ADMIN = 2
USER_SYSTEM = 3

_USER_TYPES: Mapping[str, int] = {
    # The account root user is the one identity that cannot be constrained by IAM
    # policy. Admin is not a courtesy — it is the most privileged principal that exists
    # in an AWS account.
    "root": USER_ADMIN,
    "iamuser": USER_REGULAR,
    "assumedrole": USER_REGULAR,
    "role": USER_REGULAR,
    "federateduser": USER_REGULAR,
    "directory": USER_REGULAR,
    "identitycenteruser": USER_REGULAR,
    "webidentityuser": USER_REGULAR,
    "samluser": USER_REGULAR,
    # Not a person: another AWS service, or another account acting through a resource
    # policy. Baselining these as user behaviour produces a "user" that acts every
    # sixty seconds forever.
    "awsservice": USER_SYSTEM,
    "awsaccount": USER_SYSTEM,
    "unknown": USER_UNKNOWN,
}

#: `eventName` → ATT&CK technique ids. Connector *hints*, not verdicts: the presence of
#: a technique label here says "this API call is how that technique is performed in
#: AWS", which is what makes the event findable by a hunt and mappable on the coverage
#: matrix. Whether a particular call *is* an attack depends on who made it, from where,
#: and what else happened — which is Phase 3's job, not this file's.
#:
#: Every id was resolved against the vendored ATT&CK bundle before being written.
_HIGH_SIGNAL: Mapping[str, tuple[str, ...]] = {
    # ── Discovery. Individually boring, in sequence they are an attacker orienting.
    "getcalleridentity": ("T1580",),
    "getaccountauthorizationdetails": ("T1087.004", "T1069.003"),
    "listusers": ("T1087.004",),
    "listroles": ("T1087.004",),
    "listgroups": ("T1069.003",),
    "listpolicies": ("T1087.004",),
    "listaccesskeys": ("T1087.004",),
    "listattachedrolepolicies": ("T1069.003",),
    "getaccountsummary": ("T1087.004",),
    "getaccountpasswordpolicy": ("T1201",),
    "listbuckets": ("T1580", "T1530"),
    "describeinstances": ("T1580",),
    "describesecuritygroups": ("T1580",),
    "describevpcs": ("T1580",),
    "describedbinstances": ("T1580",),
    "listfunctions": ("T1580",),
    "listsecrets": ("T1555.006",),
    "describeorganization": ("T1526",),
    "listaccounts": ("T1526", "T1087.004"),
    "listservicequotas": ("T1526",),
    # ── Credential access.
    "getsecretvalue": ("T1555.006",),
    "batchgetsecretvalue": ("T1555.006",),
    "getparameter": ("T1555.006",),
    "getparameters": ("T1555.006",),
    "getparametersbypath": ("T1555.006",),
    "getpassworddata": ("T1552",),
    "getfederationtoken": ("T1550.001",),
    "getsessiontoken": ("T1550.001",),
    "assumerolewithwebidentity": ("T1550.001", "T1078.004"),
    "assumerolewithsaml": ("T1550.001", "T1078.004"),
    # ── Persistence and privilege escalation. The AWS equivalent of adding a local
    # admin: a second credential on an identity you already control.
    "createaccesskey": ("T1098.001",),
    "createloginprofile": ("T1098.001", "T1136.003"),
    "updateloginprofile": ("T1098.001",),
    "createuser": ("T1136.003",),
    "createrole": ("T1136.003",),
    "createservicelinkedrole": ("T1136.003",),
    "attachuserpolicy": ("T1098.003",),
    "attachrolepolicy": ("T1098.003",),
    "attachgrouppolicy": ("T1098.003",),
    "putuserpolicy": ("T1098.003",),
    "putrolepolicy": ("T1098.003",),
    "putgrouppolicy": ("T1098.003",),
    "addusertogroup": ("T1098.003",),
    "createpolicyversion": ("T1098.003",),
    "setdefaultpolicyversion": ("T1098.003",),
    # A trust-policy edit is how an attacker makes a role assumable by a principal they
    # own — the single highest-value privilege-escalation primitive in AWS.
    "updateassumerolepolicy": ("T1098.003", "T1484.002"),
    "createkeypair": ("T1098.004",),
    "importkeypair": ("T1098.004",),
    # Federation and MFA tampering: a persistent way back in that survives password and
    # key rotation.
    "createsamlprovider": ("T1484.002", "T1556.006"),
    "updatesamlprovider": ("T1484.002", "T1556.006"),
    "createopenidconnectprovider": ("T1484.002", "T1556.006"),
    "updateopenidconnectproviderthumbprint": ("T1484.002", "T1556.006"),
    "deactivatemfadevice": ("T1556.006",),
    "deletevirtualmfadevice": ("T1556.006",),
    "updateaccountpasswordpolicy": ("T1556",),
    # ── Defense evasion. Turning off the log that would have recorded the rest.
    "stoplogging": ("T1562.008",),
    "deletetrail": ("T1562.008", "T1070"),
    "updatetrail": ("T1562.008",),
    "puteventselectors": ("T1562.008",),
    "deleteeventdatastore": ("T1562.008", "T1070"),
    "deleteflowlogs": ("T1562.008",),
    "deletedetector": ("T1562.008",),
    "updatedetector": ("T1562.008",),
    "deletemembers": ("T1562.008",),
    "disassociatemembers": ("T1562.008",),
    "stopmonitoringmembers": ("T1562.008",),
    "disablesecurityhub": ("T1562.008",),
    "deleteconfigrule": ("T1562.008",),
    "stopconfigurationrecorder": ("T1562.008",),
    "deletelogstream": ("T1562.008", "T1070"),
    "deletealarms": ("T1562.008",),
    # Network exposure — the cloud form of "disable the firewall".
    "authorizesecuritygroupingress": ("T1562.007",),
    "authorizesecuritygroupegress": ("T1562.007",),
    "createnetworkaclentry": ("T1562.007",),
    "deletenetworkaclentry": ("T1562.007",),
    "modifysecuritygrouprules": ("T1562.007",),
    "revokesecuritygroupegress": ("T1562.007",),
    # ── Collection and exfiltration.
    "createsnapshot": ("T1578.001",),
    "createdbsnapshot": ("T1578.001",),
    "copysnapshot": ("T1578.001", "T1074.002"),
    "createimage": ("T1578.001",),
    # Sharing a snapshot with an external account id is exfiltration that never touches
    # the network: the data leaves by changing one attribute.
    "modifysnapshotattribute": ("T1537", "T1578.001"),
    "modifyimageattribute": ("T1537",),
    "modifydbsnapshotattribute": ("T1537",),
    "putbucketpolicy": ("T1530",),
    "putbucketacl": ("T1530",),
    "deletebucketpublicaccessblock": ("T1530",),
    "deleteaccountpublicaccessblock": ("T1530",),
    "putbucketreplication": ("T1537", "T1567.002"),
    "createaccesspoint": ("T1530",),
    "listobjects": ("T1530", "T1119"),
    "listobjectsv2": ("T1530", "T1119"),
    # ── Execution.
    "createfunction": ("T1648",),
    "updatefunctioncode": ("T1648",),
    "updatefunctionconfiguration": ("T1648",),
    "createeventsourcemapping": ("T1648",),
    "sendcommand": ("T1651", "T1059.009"),
    "startsession": ("T1651",),
    "runinstances": ("T1578.002", "T1496"),
    "requestspotinstances": ("T1578.002", "T1496"),
    "createcluster": ("T1610",),
    "runtask": ("T1610",),
    "registertaskdefinition": ("T1610",),
    # ── Impact.
    "terminateinstances": ("T1578.003",),
    "deletedbinstance": ("T1485",),
    "deletebucket": ("T1485",),
    "deleteobjects": ("T1485",),
    "putbucketversioning": ("T1490",),
    "putbucketlifecycle": ("T1490",),
    "putbucketlifecycleconfiguration": ("T1490",),
    "deleterecoverypoint": ("T1490",),
    "deletebackupvault": ("T1490",),
    # Scheduling a KMS key for deletion makes every object it encrypted permanently
    # unreadable — ransomware that needs no encryption step of its own.
    "schedulekeydeletion": ("T1490", "T1486"),
    "disablekey": ("T1490", "T1600"),
    "disablekeyrotation": ("T1600",),
    "putkeypolicy": ("T1098",),
    "revokegrant": ("T1490",),
}

#: Error codes that mean "this principal was not allowed to do that". One is noise —
#: a misconfigured Terraform run produces hundreds. A burst of them from one credential
#: across many services is an attacker mapping their own permissions, which is a rule
#: over this label, not a per-event judgement.
_DENIED_CODES: frozenset[str] = frozenset({
    "accessdenied",
    "accessdeniedexception",
    "unauthorizedoperation",
    "client.unauthorizedoperation",
    "forbidden",
    "authfailure",
    "notauthorized",
    "unauthorizedaccess",
    "missingauthenticationtoken",
    "invalidclienttokenid",
    "signaturedoesnotmatch",
    "expiredtoken",
    "expiredtokenexception",
    "tokenrefreshrequired",
})


# ── small AWS-shape helpers ─────────────────────────────────────────────────────────


def arn_partition(arn: Any) -> str:
    """The partition field of an ARN — ``aws``, ``aws-cn`` or ``aws-us-gov``.

    Recorded on every resource because it is the difference between the commercial
    regions, the two China regions and GovCloud, and those are *separate deployments*
    of AWS with separate account namespaces. Two resources with identical account ids
    in different partitions are unrelated, and an incident that merges them is wrong.
    """
    text = str(arn or "")
    parts = text.split(":")
    return parts[1] if len(parts) > 3 and parts[0] == "arn" else ""


def arn_tail(arn: Any) -> str:
    """The human-meaningful last segment of an ARN.

    ``arn:aws:iam::1234:user/alice`` → ``alice``;
    ``arn:aws:sts::1234:assumed-role/Deploy/session-42`` → ``session-42``;
    ``arn:aws:s3:::my-bucket`` → ``my-bucket``.
    """
    text = str(arn or "").strip()
    if not text:
        return ""
    tail = text.split(":")[-1]
    return tail.split("/")[-1] if "/" in tail else tail


def arn_role_session(arn: Any) -> str:
    """The role-session name of an assumed-role ARN, or ``""``.

    ``arn:aws:sts::1234:assumed-role/DeployRole/jenkins-build-991`` →
    ``jenkins-build-991``. This is AWS's own session identifier and is what an
    investigator sees in the console, which is why it goes in ``session_uid`` — but it
    is caller-supplied and **not unique**: two `AssumeRole` calls may pass the same
    name. The globally unique handle on the session is the temporary access key id, in
    ``actor_user_credential_uid``.
    """
    text = str(arn or "")
    if "assumed-role/" not in text:
        return ""
    tail = text.split("assumed-role/", 1)[1]
    parts = [p for p in tail.split("/") if p]
    return parts[-1] if len(parts) > 1 else ""


def items_of(value: Any) -> list[Any]:
    """The list inside EC2's ``{"items": [...]}`` wrapper, or a bare list.

    The EC2 APIs wrap every collection in `requestParameters` this way and the other
    services do not, so both shapes reach the same extractor.
    """
    if isinstance(value, Mapping):
        inner = value.get("items")
        return list(inner) if isinstance(inner, list) else []
    return list(value) if isinstance(value, list) else []


def as_policy(value: Any) -> Mapping[str, Any] | None:
    """An IAM/resource policy document, whichever of the two ways AWS sent it.

    `PutBucketPolicy` sends the policy as a JSON **string** in `requestParameters`;
    `PutUserPolicy` sends it as a nested **object**; some send it URL-encoded. Only the
    first two are handled, and an unparseable document returns ``None`` rather than
    raising — a policy this code cannot read must not cost the event.
    """
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, Mapping) else None
    return None


def _has_wildcard(principal: Any) -> bool:
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, Mapping):
        return any(_has_wildcard(v) for v in principal.values())
    if isinstance(principal, (list, tuple)):
        return any(_has_wildcard(v) for v in principal)
    return False


def wildcard_principals(value: Any) -> tuple[bool, bool]:
    """``(grants to a wildcard principal, that grant carries a Condition)``.

    The second flag is why this returns a pair rather than a boolean. A bucket policy
    with ``"Principal": "*"`` **and** a ``Condition`` on ``aws:PrincipalOrgID`` or
    ``aws:SourceVpce`` is a normal, safe pattern — it is how you grant to your whole
    organisation. Reporting it as "public" would be a false statement about the
    account's exposure, and a SOC that cries public-bucket at every org-scoped policy
    gets its bucket alerts muted within a week.
    """
    doc = as_policy(value)
    if doc is None:
        return False, False
    statements = doc.get("Statement", doc.get("statement"))
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False, False
    wide = conditioned = False
    for statement in statements:
        if not isinstance(statement, Mapping):
            continue
        effect = str(statement.get("Effect", statement.get("effect", "Allow")))
        if effect.strip().lower() != "allow":
            continue
        if not _has_wildcard(statement.get("Principal", statement.get("principal"))):
            continue
        wide = True
        if statement.get("Condition") or statement.get("condition"):
            conditioned = True
    return wide, conditioned


#: Ports whose exposure to the entire internet is materially different from exposing a
#: web service. ``0.0.0.0/0`` on 443 is how a public site is supposed to look; the same
#: range on 22 or 3389 is an administrative interface that credential-stuffing and
#: exploit scanners find within minutes.
ADMIN_PORTS: Mapping[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM/TLS",
}

#: Data stores. Several of these ship with no authentication by default, so exposure is
#: not "an attacker may try to log in" but "the data is readable now".
DATA_PORTS: Mapping[int, str] = {
    1433: "MSSQL",
    1521: "Oracle",
    2379: "etcd",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "memcached",
    27017: "MongoDB",
}


class OpenRule(NamedTuple):
    """One internet-facing security-group rule, with its port range kept numeric.

    Numeric on purpose. A rule is very often written as a *range* — ``0-65535``,
    ``1-1024``, ``20-25`` — and a string test for ``"/22 "`` matches none of them, so a
    security group that opens SSH as part of ``0.0.0.0/0`` on ``0-65535`` would be
    reported as ordinary internet exposure with no mention of remote administration.
    That is the single most dangerous rule shape there is, and it is the one a
    substring match is guaranteed to miss.
    """

    proto: str
    #: Inclusive low port, or ``-1`` when the rule covers every port (``ipProtocol``
    #: of ``-1``, or a permission with no ``fromPort``).
    low: int
    high: int
    cidr: str

    @property
    def all_ports(self) -> bool:
        return self.low < 0

    def covers(self, port: int) -> bool:
        return self.all_ports or self.low <= port <= self.high

    def describe(self) -> str:
        span = (
            "all ports"
            if self.all_ports
            else (f"{self.low}" if self.low == self.high else f"{self.low}-{self.high}")
        )
        return f"{self.proto}/{span} from {self.cidr}"


def open_rules(params: Mapping[str, Any]) -> list[OpenRule]:
    """The internet-facing rules in a security-group authorisation.

    Only ``0.0.0.0/0`` and ``::/0`` are returned: a rule scoped to a corporate range or
    a peer VPC is ordinary configuration and reporting it would bury the one that is
    not. Both EC2 ``items`` wrappers are walked (v4 ``ipRanges`` and v6 ``ipv6Ranges``)
    because a group can be open on one family and closed on the other.
    """
    out: list[OpenRule] = []
    for perm in items_of(params.get("ipPermissions")):
        if not isinstance(perm, Mapping):
            continue
        proto = str(perm.get("ipProtocol") or "any")
        low_raw, high_raw = perm.get("fromPort"), perm.get("toPort")
        if proto == "-1":
            # `-1` is EC2's "every protocol", and such a permission carries no ports.
            proto, low, high = "all", -1, -1
        else:
            try:
                low = int(low_raw)
                high = int(high_raw) if high_raw is not None else low
            except (TypeError, ValueError):
                low = high = -1
        cidrs = [
            str(r.get("cidrIp"))
            for r in items_of(perm.get("ipRanges"))
            if isinstance(r, Mapping) and r.get("cidrIp")
        ] + [
            str(r.get("cidrIpv6"))
            for r in items_of(perm.get("ipv6Ranges"))
            if isinstance(r, Mapping) and r.get("cidrIpv6")
        ]
        for cidr in cidrs:
            if cidr in ("0.0.0.0/0", "::/0"):
                out.append(OpenRule(proto, low, high, cidr))
    return out


# ── per-eventName request-parameter readers ─────────────────────────────────────────
#
# Each reads `requestParameters` for one family of calls and states the *target* of the
# action. The signature is uniform — (payload, params, inner) — so the dispatch table
# below stays a plain mapping rather than a chain of `if` branches, which is what makes
# each one independently testable.


def _p_iam_target(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    """The IAM principal an IAM call acted *on*.

    This is the most important extraction in the file. `CreateAccessKey` records the
    caller in `userIdentity` and the **subject** in ``requestParameters.userName``, and
    when those two differ the event is one identity minting a credential for another —
    the AWS form of privilege escalation. Merging them into one "user" field, which a
    naive mapping does, destroys exactly the comparison that makes it detectable.
    """
    for key, kind in (
        ("userName", "AWS::IAM::User"),
        ("roleName", "AWS::IAM::Role"),
        ("groupName", "AWS::IAM::Group"),
        ("policyName", "AWS::IAM::Policy"),
        ("instanceProfileName", "AWS::IAM::InstanceProfile"),
    ):
        value = params.get(key)
        if value:
            _add_resource(payload, resource_ref(name=str(value), type=kind))
            stash(payload, f"target_{key}", value)
    policy_arn = params.get("policyArn")
    if policy_arn:
        _add_resource(
            payload,
            resource_ref(
                uid=str(policy_arn),
                name=arn_tail(policy_arn),
                type="AWS::IAM::Policy",
                cloud_partition=arn_partition(policy_arn),
            ),
        )
        text = str(policy_arn)
        if text.endswith(("/AdministratorAccess", "/PowerUserAccess", "/IAMFullAccess")):
            # An AWS-managed policy whose name *is* the privilege level. Named in a note
            # because "AttachRolePolicy" alone does not say whether the grant was
            # read-only S3 or full administrator.
            note(payload, f"attaches the AWS-managed policy {arn_tail(text)}")
            label(payload, "aws:admin-policy-grant")
    document = params.get("policyDocument")
    if document is not None:
        wide, conditioned = wildcard_principals(document)
        if wide:
            note(
                payload,
                "the inline policy document grants to a wildcard principal"
                + (
                    " but carries a Condition, which is how an organisation-scoped "
                    "grant is written — read the condition before treating this as "
                    "public"
                    if conditioned
                    else " with no Condition"
                ),
            )
            label(payload, "aws:wildcard-principal")
    _p_target_arn(payload, params)


def _p_target_arn(payload: dict[str, Any], params: Mapping[str, Any]) -> None:
    for key in ("resourceArn", "resourceARN", "targetArn", "principalArn"):
        arn = params.get(key)
        if arn:
            _add_resource(
                payload,
                resource_ref(
                    uid=str(arn),
                    name=arn_tail(arn),
                    cloud_partition=arn_partition(arn),
                ),
            )


def _p_assume_role(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    role = params.get("roleArn")
    session = params.get("roleSessionName")
    if role:
        _add_resource(
            payload,
            resource_ref(
                uid=str(role),
                name=arn_tail(role),
                type="AWS::IAM::Role",
                cloud_partition=arn_partition(role),
                owner=str(role).split(":")[4] if len(str(role).split(":")) > 4 else None,
            ),
        )
    stash(payload, "assumed_role_session_name", session)
    stash(payload, "external_id_used", bool(params.get("externalId")) or None)
    if role and session:
        note(payload, f"assumes {arn_tail(role)} as session {session}")


def _p_trail(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    """Trail and log-configuration calls — the audit trail modifying itself.

    Given a note as well as an ATT&CK label because this is the one event class whose
    *absence of further events* is the signal: after a successful `StopLogging` the
    account goes quiet, and a quiet account looks healthy.
    """
    name = params.get("name") or params.get("trailName") or params.get("Name")
    if name:
        _add_resource(payload, resource_ref(name=str(name), type="AWS::CloudTrail::Trail"))
    note(
        payload,
        "modifies audit logging configuration — after this call the account's own "
        "record of activity may be incomplete, so subsequent silence is not evidence "
        "of inactivity",
    )
    label(payload, "aws:audit-config-change")


def _p_bucket_policy(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    bucket = params.get("bucketName") or params.get("bucket")
    if bucket:
        _add_resource(payload, resource_ref(name=str(bucket), type="AWS::S3::Bucket"))
    document = (
        params.get("bucketPolicy")
        or params.get("policy")
        or params.get("Policy")
        or params.get("accessControlPolicy")
    )
    wide, conditioned = wildcard_principals(document)
    if wide and conditioned:
        note(
            payload,
            f"bucket policy on {bucket or 'the bucket'} grants to a wildcard principal "
            "but carries a Condition — an organisation- or VPC-scoped grant is written "
            "this way and is not public exposure; read the condition",
        )
        label(payload, "aws:wildcard-principal")
    elif wide:
        note(
            payload,
            f"bucket policy on {bucket or 'the bucket'} grants to a wildcard principal "
            "with no Condition: this is public exposure of the bucket's contents",
        )
        label(payload, "aws:public-principal", "aws:wildcard-principal")
        attack(payload, "T1530")
    acl = str(params.get("x-amz-acl") or params.get("acl") or "")
    if acl in ("public-read", "public-read-write"):
        note(payload, f"canned ACL set to {acl}, which exposes objects to anonymous readers")
        label(payload, "aws:public-principal")
        attack(payload, "T1530")


def _p_public_access_block(
    payload: dict[str, Any], params: Mapping[str, Any], _inner: Any
) -> None:
    """`PutBucketPublicAccessBlock` — the guard rail, both directions.

    The same eventName is a *hardening* action when the four flags are true and an
    *exposure* action when they are false, so this reads the values instead of treating
    the call name as the signal.
    """
    bucket = params.get("bucketName")
    if bucket:
        _add_resource(payload, resource_ref(name=str(bucket), type="AWS::S3::Bucket"))
    config = params.get("PublicAccessBlockConfiguration")
    if not isinstance(config, Mapping):
        return
    flags = {
        key: as_bool(config.get(key))
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    }
    stash(payload, "public_access_block", flags)
    disabled = [k for k, v in flags.items() if v is False]
    if disabled:
        note(
            payload,
            "public-access protection disabled: " + ", ".join(sorted(disabled)),
        )
        label(payload, "aws:public-access-block-disabled")
        attack(payload, "T1530")


def _p_share_attribute(
    payload: dict[str, Any], params: Mapping[str, Any], inner: Mapping[str, Any]
) -> None:
    """Snapshot and image sharing — exfiltration by attribute change.

    `ModifySnapshotAttribute` adding a `userId` copies nothing and transfers no bytes
    over any monitored path; the recipient account simply copies the snapshot at its
    leisure. The account id being granted is the whole finding, and it is buried three
    levels down in `createVolumePermission.add.items[].userId`.
    """
    added: list[str] = []
    for key in ("createVolumePermission", "launchPermission"):
        block = params.get(key)
        if not isinstance(block, Mapping):
            continue
        for entry in items_of(block.get("add")):
            if isinstance(entry, Mapping):
                for field in ("userId", "group", "organizationArn"):
                    if entry.get(field):
                        added.append(f"{field}={entry[field]}")
    for value in params.get("valuesToAdd") or []:
        added.append(str(value))
    if params.get("attributeName") == "restore" and params.get("valuesToAdd"):
        added.append("restore=" + ",".join(str(v) for v in params["valuesToAdd"]))
    target = (
        params.get("snapshotId")
        or params.get("imageId")
        or params.get("dBSnapshotIdentifier")
    )
    if target:
        _add_resource(payload, resource_ref(uid=str(target), type="AWS::EC2::Snapshot"))
    if not added:
        return
    stash(payload, "shared_with", added)
    own = str(inner.get("recipientAccountId") or "")
    external = [a for a in added if own and own not in a]
    note(
        payload,
        f"shares {target or 'a snapshot/image'} with {', '.join(added)}"
        + (
            " — an account outside this one, which moves the data out of the account "
            "without any network transfer this SOC can see"
            if external
            else ""
        ),
    )
    label(payload, "aws:resource-shared")
    if external:
        label(payload, "aws:shared-externally")
        attack(payload, "T1537")
    if any("all" in a.lower() for a in added):
        note(payload, "shared with ALL AWS accounts — this is public")
        label(payload, "aws:public-principal")


def _p_secret(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    for key in ("secretId", "SecretId", "name", "Name"):
        value = params.get(key)
        if value:
            _add_resource(
                payload,
                resource_ref(
                    uid=str(value) if str(value).startswith("arn:") else None,
                    name=arn_tail(value) if str(value).startswith("arn:") else str(value),
                    type="AWS::SecretsManager::Secret",
                    cloud_partition=arn_partition(value),
                ),
            )
            return
    for key in ("names", "Names"):
        values = params.get(key)
        if isinstance(values, list):
            for value in values[:20]:
                _add_resource(
                    payload, resource_ref(name=str(value), type="AWS::SSM::Parameter")
                )
            if len(values) > 20:
                note(
                    payload,
                    f"reads {len(values)} parameters in one call; the first 20 are "
                    "listed as resources and the full list is in raw",
                )


def _p_security_group(
    payload: dict[str, Any], params: Mapping[str, Any], _inner: Any
) -> None:
    group = params.get("groupId") or params.get("groupName")
    if group:
        _add_resource(payload, resource_ref(uid=str(group), type="AWS::EC2::SecurityGroup"))
    rules = open_rules(params)
    if not rules:
        return
    described = [rule.describe() for rule in rules]
    stash(payload, "internet_exposed_rules", described)
    note(
        payload,
        f"opens {'; '.join(described)} on {group or 'a security group'} — reachable from "
        "the entire internet",
    )
    label(payload, "aws:open-to-internet")

    if any(rule.all_ports for rule in rules):
        note(
            payload,
            "the rule covers EVERY port, so this is not a service being published — it "
            "is the host being published",
        )
        label(payload, "aws:all-ports-exposed")
    admin = sorted({
        service
        for rule in rules
        for port, service in ADMIN_PORTS.items()
        if rule.covers(port)
    })
    if admin:
        note(
            payload,
            "the exposed range includes remote administration: " + ", ".join(admin),
        )
        label(payload, "aws:remote-admin-exposed")
        attack(payload, "T1133")
    stores = sorted({
        service
        for rule in rules
        for port, service in DATA_PORTS.items()
        if rule.covers(port)
    })
    if stores:
        note(
            payload,
            "the exposed range includes data stores (" + ", ".join(stores) + "), several "
            "of which accept unauthenticated connections by default",
        )
        label(payload, "aws:datastore-exposed")
        attack(payload, "T1190")


def _p_lambda(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    name = params.get("functionName") or params.get("FunctionName")
    if name:
        _add_resource(
            payload,
            resource_ref(
                uid=str(name) if str(name).startswith("arn:") else None,
                name=arn_tail(name) if str(name).startswith("arn:") else str(name),
                type="AWS::Lambda::Function",
            ),
        )
    role = params.get("role") or params.get("Role")
    if role:
        stash(payload, "function_execution_role", role)
        note(payload, f"function runs as {arn_tail(role)}")
    if params.get("zipFile") or dig(params, "code.zipFile"):
        # CloudTrail redacts the payload to the literal "HIDDEN_DUE_TO_SECURITY_REASONS",
        # so the code itself is never here — but knowing that code was supplied inline
        # rather than from S3 is still a distinguishing fact.
        note(payload, "function code was supplied inline; CloudTrail redacts the bytes")


def _p_ssm_command(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    """`SendCommand` / `StartSession` — remote code execution through the control plane.

    This is the AWS equivalent of PsExec and it leaves no network trace between the
    operator and the host: the API call is the delivery mechanism. The document name and
    the target instance list are the only things that distinguish patching from an
    intrusion.
    """
    document = params.get("documentName") or params.get("DocumentName")
    stash(payload, "ssm_document", document)
    targets = params.get("instanceIds") or params.get("InstanceIds") or []
    if isinstance(targets, list):
        for instance in targets[:25]:
            _add_resource(
                payload, resource_ref(uid=str(instance), type="AWS::EC2::Instance")
            )
        stash(payload, "ssm_target_count", len(targets))
    target = params.get("target") or params.get("Target")
    if target:
        _add_resource(payload, resource_ref(uid=str(target), type="AWS::EC2::Instance"))
    note(
        payload,
        f"runs {document or 'a command document'} on "
        f"{len(targets) if isinstance(targets, list) and targets else (1 if target else 0)}"
        " instance(s) through Systems Manager — code execution on the host with no "
        "inbound network connection",
    )
    label(payload, "aws:remote-execution")


def _p_run_instances(
    payload: dict[str, Any], params: Mapping[str, Any], _inner: Any
) -> None:
    image = params.get("imageId")
    kind = params.get("instanceType")
    count = params.get("maxCount") or params.get("minCount")
    if image:
        _add_resource(payload, resource_ref(uid=str(image), type="AWS::EC2::Image"))
    stash(payload, "instance_type", kind)
    stash(payload, "instance_count", count)
    profile = dig(params, "iamInstanceProfile.arn") or dig(params, "iamInstanceProfile.name")
    if profile:
        stash(payload, "instance_profile", profile)
    if params.get("userData"):
        # userData runs as root on first boot. CloudTrail records that it was present;
        # the content is only in the record when the caller did not use
        # `--user-data file://`, so its absence is not evidence of absence.
        note(payload, "instance launched with userData, which executes at boot as root")
        label(payload, "aws:userdata-supplied")
    if kind and str(kind).split(".")[0].lower() in (
        "p2", "p3", "p4", "p4d", "p5", "g4dn", "g5", "g6", "inf1", "inf2", "trn1",
    ):
        # GPU and accelerator families. Legitimate for ML workloads and the single most
        # common shape of cryptomining on a compromised account, so it is a label and a
        # note, not a verdict.
        note(
            payload,
            f"launches accelerator instance type {kind} — the usual shape of both ML "
            "work and resource hijacking",
        )
        label(payload, "aws:accelerator-instance")
        attack(payload, "T1496")


def _p_kms(payload: dict[str, Any], params: Mapping[str, Any], _inner: Any) -> None:
    key = params.get("keyId") or params.get("KeyId")
    if key:
        _add_resource(
            payload,
            resource_ref(
                uid=str(key) if str(key).startswith("arn:") else None,
                name=arn_tail(key) if str(key).startswith("arn:") else str(key),
                type="AWS::KMS::Key",
                cloud_partition=arn_partition(key),
            ),
        )
    days = params.get("pendingWindowInDays")
    if days is not None:
        note(
            payload,
            f"schedules the key for deletion in {days} day(s); every object encrypted "
            "with it becomes permanently unreadable at that point",
        )
    document = params.get("policy") or params.get("Policy")
    wide, conditioned = wildcard_principals(document)
    if wide and not conditioned:
        note(payload, "key policy grants to a wildcard principal with no Condition")
        label(payload, "aws:public-principal", "aws:wildcard-principal")


def _p_console_login(
    payload: dict[str, Any], params: Mapping[str, Any], _inner: Any
) -> None:
    """Only reached on the 6003 path — the 3002 mapper reads sign-in fields itself."""
    stash(payload, "login_to", params.get("LoginTo") or params.get("loginTo"))


#: `eventName` (as sent, CamelCase) → the reader for its `requestParameters`.
#:
#: Keyed on the exact vendor spelling rather than a lower-cased form because these are
#: the strings an operator reads in the CloudTrail console, and a table they can diff
#: against AWS's own documentation is worth more than one they have to mentally
#: lower-case. Lookup normalises.
_PARAM_READERS: Mapping[str, Callable[[dict[str, Any], Mapping[str, Any], Mapping[str, Any]], None]] = {
    # IAM — identity and privilege
    "CreateUser": _p_iam_target,
    "DeleteUser": _p_iam_target,
    "CreateAccessKey": _p_iam_target,
    "DeleteAccessKey": _p_iam_target,
    "UpdateAccessKey": _p_iam_target,
    "CreateLoginProfile": _p_iam_target,
    "UpdateLoginProfile": _p_iam_target,
    "DeleteLoginProfile": _p_iam_target,
    "AttachUserPolicy": _p_iam_target,
    "DetachUserPolicy": _p_iam_target,
    "AttachRolePolicy": _p_iam_target,
    "DetachRolePolicy": _p_iam_target,
    "AttachGroupPolicy": _p_iam_target,
    "PutUserPolicy": _p_iam_target,
    "PutRolePolicy": _p_iam_target,
    "PutGroupPolicy": _p_iam_target,
    "AddUserToGroup": _p_iam_target,
    "RemoveUserFromGroup": _p_iam_target,
    "CreateRole": _p_iam_target,
    "DeleteRole": _p_iam_target,
    "UpdateAssumeRolePolicy": _p_iam_target,
    "CreatePolicyVersion": _p_iam_target,
    "SetDefaultPolicyVersion": _p_iam_target,
    "DeactivateMFADevice": _p_iam_target,
    "EnableMFADevice": _p_iam_target,
    "DeleteVirtualMFADevice": _p_iam_target,
    "TagRole": _p_iam_target,
    # STS
    "AssumeRole": _p_assume_role,
    "AssumeRoleWithSAML": _p_assume_role,
    "AssumeRoleWithWebIdentity": _p_assume_role,
    # Audit configuration
    "StopLogging": _p_trail,
    "StartLogging": _p_trail,
    "DeleteTrail": _p_trail,
    "UpdateTrail": _p_trail,
    "PutEventSelectors": _p_trail,
    "DeleteEventDataStore": _p_trail,
    "DeleteFlowLogs": _p_trail,
    "DeleteDetector": _p_trail,
    "UpdateDetector": _p_trail,
    "StopConfigurationRecorder": _p_trail,
    "DeleteConfigRule": _p_trail,
    "DisableSecurityHub": _p_trail,
    "DeleteLogStream": _p_trail,
    "DeleteLogGroup": _p_trail,
    # S3 exposure
    "PutBucketPolicy": _p_bucket_policy,
    "PutBucketAcl": _p_bucket_policy,
    "DeleteBucketPolicy": _p_bucket_policy,
    "PutBucketPublicAccessBlock": _p_public_access_block,
    "DeleteBucketPublicAccessBlock": _p_public_access_block,
    "PutAccountPublicAccessBlock": _p_public_access_block,
    # Sharing
    "ModifySnapshotAttribute": _p_share_attribute,
    "ModifyImageAttribute": _p_share_attribute,
    "ModifyDBSnapshotAttribute": _p_share_attribute,
    # Secrets
    "GetSecretValue": _p_secret,
    "BatchGetSecretValue": _p_secret,
    "DescribeSecret": _p_secret,
    "GetParameter": _p_secret,
    "GetParameters": _p_secret,
    "GetParametersByPath": _p_secret,
    # Network exposure
    "AuthorizeSecurityGroupIngress": _p_security_group,
    "AuthorizeSecurityGroupEgress": _p_security_group,
    "RevokeSecurityGroupIngress": _p_security_group,
    "ModifySecurityGroupRules": _p_security_group,
    # Compute and execution
    "CreateFunction": _p_lambda,
    "UpdateFunctionCode": _p_lambda,
    "UpdateFunctionConfiguration": _p_lambda,
    "AddPermission": _p_lambda,
    "SendCommand": _p_ssm_command,
    "StartSession": _p_ssm_command,
    "RunInstances": _p_run_instances,
    "RequestSpotInstances": _p_run_instances,
    # KMS
    "ScheduleKeyDeletion": _p_kms,
    "DisableKey": _p_kms,
    "DisableKeyRotation": _p_kms,
    "PutKeyPolicy": _p_kms,
    "CreateGrant": _p_kms,
    "RevokeGrant": _p_kms,
    # Console
    "ConsoleLogin": _p_console_login,
}


def _add_resource(payload: dict[str, Any], ref: Mapping[str, Any]) -> None:
    """Append a resource reference, skipping one already present.

    Deduplicated because the same resource arrives twice regularly: the inner record's
    `resources` array and a `requestParameters` reader both name the bucket a
    `PutBucketPolicy` acted on. Two identical entries in ``resources`` inflate every
    blast-radius count that reads the array's length.
    """
    if not ref:
        return
    existing = payload.setdefault("resources", [])
    key = (ref.get("uid"), ref.get("name"), ref.get("type"))
    for present in existing:
        if (present.get("uid"), present.get("name"), present.get("type")) == key:
            return
    if len(existing) >= 50:
        # A batch call can name thousands. The cap keeps one event from dominating a
        # Parquet row group, and it is announced rather than silent.
        payload.setdefault("unmapped", {})["resources_truncated"] = True
        return
    existing.append(dict(ref))


class CloudTrailConnector(Connector):
    """Management-plane events from one AWS account and region.

    One instance covers one account/region pair, because that is the scope of both the
    API and its quota. A multi-region estate declares one per region — which is also
    the only correct way to do it, since `LookupEvents` in ``us-east-1`` cannot see
    ``eu-west-1``'s events, and global services (IAM, STS, CloudFront, Route 53,
    Organizations) report **only** into ``us-east-1``. An account monitored in one
    non-us-east-1 region therefore sees no IAM activity at all, which is stated in
    :meth:`probe` because it is the single most common CloudTrail coverage mistake.
    """

    name = "aws_cloudtrail"
    detects = (
        "AWS management-plane abuse: access-key and login-profile creation, trust-policy "
        "edits, CloudTrail/GuardDuty tampering, snapshot sharing to external accounts, "
        "secret reads, security-group exposure, SSM remote execution, root account use"
    )
    spec = ConnectorSpec(
        page_size=MAX_LOOKUP_RESULTS,
        rate_per_second=LOOKUP_TPS,
        burst=2,
        initial_lookback_seconds=3_600.0,
        # A wide overlap on purpose. CloudTrail's delivery is "within 15 minutes" as a
        # target, not a guarantee, and the `addendum` field exists precisely because
        # records are sometimes delivered late or amended. `metadata_uid` is the event
        # id, so a re-read is deduplicated exactly and costs only quota.
        overlap_seconds=300.0,
        # 15 minutes per window: at 50 records × 200 pages that is 10,000 events per
        # window, which is the most this API can deliver in the time the window covers.
        # A wider window could not be read completely and would report a permanent
        # page-cap hit.
        max_window_seconds=900.0,
        indexing_lag_seconds=DELIVERY_LAG_SECONDS,
        docs_url=(
            "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/"
            "API_LookupEvents.html"
        ),
        required_grants=("cloudtrail:LookupEvents",),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: Windows whose start was pushed forward to stay inside the 90-day horizon.
        #: Non-zero means events were permanently missed, so it is surfaced in stats
        #: rather than only noted on the affected event.
        self.retention_clamps = 0
        #: Windows that lay *entirely* before the horizon and were therefore never
        #: requested. Counted apart from `retention_clamps` because the operator
        #: question differs: a clamp means part of a window was lost, a skip means a
        #: checkpoint is so far behind that whole hours of history are already gone.
        self.windows_skipped = 0
        #: Records whose inner `CloudTrailEvent` string would not parse. Mapped from the
        #: envelope instead of dropped, and counted so a systematic parse failure (a new
        #: `eventVersion`, a truncated response) is visible.
        self.unparsed_records = 0
        #: Cycles that ended early on an expired `NextToken`.
        self.expired_cursors = 0
        #: Events whose `sourceIPAddress` was a service principal rather than an address.
        self.service_principal_calls = 0

    # ── credentials and identity ───────────────────────────────────────────

    def credentials(self) -> tuple[Credential, ...]:
        """The three required slots.

        ``aws_session_token`` is deliberately **absent** from this tuple even though it
        is read by :meth:`authorizer`. It is required for every temporary credential
        (AssumeRole, IAM Identity Center, an EC2/ECS instance role) and *must not be
        set* for a long-lived IAM user key — so including it here would make the normal
        long-lived-key deployment report as "PARTLY configured", which
        :meth:`Connector.probe` correctly treats as worse than unconfigured.
        """
        c = self.config.connectors
        return (c.aws_access_key_id, c.aws_secret_access_key, c.aws_region)

    def authorizer(self) -> Authorizer:
        c = self.config.connectors
        return SigV4Auth(
            access_key_id=c.aws_access_key_id,
            secret_access_key=c.aws_secret_access_key,
            region=c.aws_region,
            service="cloudtrail",
            # Passed unconditionally: `SigV4Auth.apply` adds the security-token header
            # only when the slot is configured, so one code path serves both the
            # long-lived-key and the temporary-credential deployment.
            session_token=c.aws_session_token,
            clock=self.clock,
        )

    def region(self) -> str:
        cred = self.config.connectors.aws_region
        return cred.value if cred.configured else ""

    def base_url(self) -> str:
        """The regional endpoint, from the configurable template.

        ``str.replace`` rather than ``str.format`` because an operator-supplied endpoint
        is arbitrary text: a URL containing a stray brace — a signed CloudFront-style
        path, a copy-pasted placeholder — makes ``format`` raise ``KeyError`` or
        ``IndexError`` at collection time, which reads as a code defect rather than a
        configuration one.
        """
        template = self.config.endpoints.aws_cloudtrail
        return template.replace("{region}", self.region()).rstrip("/") + "/"

    def probe(self) -> Availability:
        """Credential state, plus the three limits that decide whether this is enough.

        The base implementation already reports missing slots and the required grant.
        What it cannot know is that this API's ceiling is low enough to matter, that
        global services report only into ``us-east-1``, and that data events are not
        available at all — so those go in the limitation, which the readiness report
        prints next to the connector.
        """
        base = super().probe()
        if not base.available:
            return base
        region = self.region() or "(region unset)"
        ceiling = int(LOOKUP_TPS * MAX_LOOKUP_RESULTS)
        limits = (
            f"reads Event history in {region} only. THROUGHPUT CEILING: "
            f"{LOOKUP_TPS:g} req/s x {MAX_LOOKUP_RESULTS} records = ~{ceiling} "
            f"events/second, shared with every other LookupEvents caller in the "
            f"account. A busy account exceeds this and this connector then falls "
            f"permanently behind (watch page_cap_hits) — the production path for a "
            f"high-volume account is a trail delivering to S3 with an event "
            f"notification, not this API. RETENTION: 90 days; an outage longer than "
            f"that is an unrecoverable gap. SCOPE: management events only, no data "
            f"events (S3 object access, Lambda invokes, DynamoDB items) — those need "
            f"a trail with data-event selectors."
            + (
                ""
                if region.startswith("us-east-1")
                else f" GLOBAL SERVICES: IAM, STS, CloudFront, Route 53 and "
                f"Organizations report only into us-east-1, so this {region} "
                f"connector sees none of their events; declare a us-east-1 instance "
                f"as well or IAM activity is invisible."
            )
        )
        note_text = base.limitation
        return available(limitation=f"{note_text} {limits}".strip() if note_text else limits)

    # ── the cycle ──────────────────────────────────────────────────────────

    def _retention_floor(self, window: TimeWindow) -> tuple[float, float]:
        """``(start to query, seconds of history lost to the 90-day horizon)``.

        A `StartTime` older than the horizon is rejected outright as
        `InvalidTimeRangeException` rather than being clamped by the service, so a
        connector restarting after a long outage would fail every cycle forever with an
        error that says nothing about retention.
        """
        floor = self.clock() - (EVENT_HISTORY_SECONDS - RETENTION_MARGIN_SECONDS)
        if window.start >= floor:
            return window.start, 0.0
        return floor, floor - window.start

    async def fetch_window(self, window: TimeWindow) -> Sequence[dict[str, Any]]:
        require(*self.credentials())
        start, lost = self._retention_floor(window)
        if window.end <= start:
            # The *whole* window predates the horizon, which is the normal shape of a
            # restart after a long outage: the planner caps a window at
            # `max_window_seconds`, so a 110-day-old checkpoint plans [cursor,
            # cursor+3600] — entirely unretrievable — and would do so ~2,600 times
            # before reaching live data. Clamping only the start would also send
            # StartTime > EndTime, which AWS rejects as `InvalidTimeRangeException`:
            # thousands of consecutive failures, connector in backoff, and an error
            # that says nothing about retention. So no request is made, and the cursor
            # is jumped to the horizon in one cycle. `note_record_time` is the cursor
            # high-water hook and nothing here is a record, but the floor is genuinely
            # the oldest instant that can still be read, which is where the cursor
            # belongs.
            self.retention_clamps += 1
            self.windows_skipped += 1
            self.note_record_time(start)
            self.stats.last_error = (
                f"{self.name}: the whole requested window ended "
                f"{(start - window.end) / 86_400:.1f} days before the 90-day Event "
                f"history horizon, so none of it can be read and no request was sent; "
                f"the cursor jumped to the horizon. That history was never collected "
                f"and is a permanent gap, not a delayed read"
            )
            return []
        payloads: list[dict[str, Any]] = []
        body: dict[str, Any] = {
            # json1.1 timestamps are Unix epoch *numbers*, not ISO strings — an ISO
            # string here is a `SerializationException`, which reads as a malformed
            # request rather than a wrong type.
            "StartTime": int(start),
            "EndTime": int(window.end),
            "MaxResults": self.spec.page_size,
        }

        def next_body(_resp: Any, doc: Any) -> Any:
            token = doc.get("NextToken") if isinstance(doc, Mapping) else None
            # The whole body, not just the token: AWS requires StartTime and EndTime on
            # every page, and omitting them is a 400 rather than a request that defaults
            # to the previous page's range.
            return {**body, "NextToken": token} if token else None

        request = Request(
            "POST",
            self.base_url(),
            label="cloudtrail.LookupEvents",
            headers={
                "X-Amz-Target": LOOKUP_TARGET,
                "Content-Type": AMZ_JSON,
                "Accept": "application/json",
            },
            json_body=body,
            idempotent=True,
        )
        try:
            async for page in self.paginate(
                request, records_at=("Events",), next_body=next_body
            ):
                for record in page:
                    mapped = self.map_record(record)
                    if mapped is not None:
                        payloads.append(mapped)
        except HttpError as exc:
            name = _aws_error_name(exc)
            if name not in RECOVERABLE_ERRORS:
                raise
            # The rest of this window is unread, but the cursor has not advanced past
            # what *was* read, so the next cycle re-reads from there. Ending the cycle
            # cleanly keeps the connector out of failure backoff for a condition that
            # resolves by itself.
            self.expired_cursors += 1
            self.stats.last_error = (
                f"{self.name}: the pagination token expired mid-window ({name}); "
                f"{len(payloads)} records were read and the remainder of "
                f"{window.iso()[0]} -> {window.iso()[1]} is re-read next cycle"
            )
        if lost > 0:
            self.retention_clamps += 1
            message = (
                f"{self.name}: the requested window began {lost / 86_400:.1f} days "
                f"before the 90-day Event history horizon, so that much history does "
                f"not exist in this API and was never collected — it is a permanent "
                f"gap, not a delayed read"
            )
            self.stats.last_error = message
            if payloads:
                payloads[0].setdefault("notes", []).append(message)
        return payloads

    def stats_extra(self) -> dict[str, Any]:
        out = super().stats_extra()
        if self.retention_clamps:
            out["retention_clamps"] = (
                f"{self.retention_clamps} window(s) clamped to the 90-day horizon — "
                f"history older than that is permanently unavailable"
            )
        if self.windows_skipped:
            out["windows_skipped_below_horizon"] = (
                f"{self.windows_skipped} window(s) lay entirely before the horizon and "
                f"were not requested — a cursor that far behind is skipped forward "
                f"rather than walked one hour at a time through data that is gone"
            )
        if self.unparsed_records:
            out["unparsed_cloudtrail_event"] = self.unparsed_records
        if self.expired_cursors:
            out["expired_pagination_tokens"] = self.expired_cursors
        if self.service_principal_calls:
            out["service_principal_callers"] = self.service_principal_calls
        return out

    # ── mapping ────────────────────────────────────────────────────────────

    def map_record(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        """One `LookupEvents` envelope to one OCSF payload."""
        inner, parse_error = self._inner(record)
        event_type = str(inner.get("eventType") or record.get("EventType") or "AwsApiCall")
        event_name = str(inner.get("eventName") or record.get("EventName") or "")

        if event_type == "AwsConsoleSignIn" or (
            not inner and event_name.lower() in _SIGNIN_ACTIVITIES
        ):
            payload = self._map_signin(record, inner, event_name)
        elif event_type == "AwsCloudTrailInsight" or inner.get("insightDetails"):
            payload = self._map_insight(record, inner, event_name)
        else:
            payload = self._map_api(record, inner, event_name)

        if parse_error:
            self.unparsed_records += 1
            note(
                payload,
                f"the CloudTrailEvent payload could not be parsed ({parse_error}); this "
                f"event is mapped from the LookupEvents envelope alone, so userIdentity, "
                f"requestParameters and errorCode are absent. The unparsed string is in "
                f"unmapped.cloudtrail_event_raw",
            )
            stash(payload, "cloudtrail_event_raw", record.get("CloudTrailEvent"), limit=8_000)
            label(payload, "aws:unparsed-record")
        self.note_record_time(payload.get("time"))
        return payload

    def _inner(self, record: Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
        raw = record.get("CloudTrailEvent")
        if raw is None:
            return {}, "the envelope carried no CloudTrailEvent field"
        if isinstance(raw, Mapping):
            # Not what the live API sends, but a replayed record that has already been
            # normalised by another tool arrives this way, and refusing it would make
            # the emulation generator and any S3-sourced backfill unusable.
            return raw, ""
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError) as exc:
            return {}, f"{type(exc).__name__}: {exc}"
        if not isinstance(parsed, Mapping):
            return {}, f"parsed to {type(parsed).__name__}, not an object"
        return parsed, ""

    def _base(
        self, record: Mapping[str, Any], inner: Mapping[str, Any], class_uid: int
    ) -> dict[str, Any]:
        merged: dict[str, Any] = dict(record)
        if inner:
            # The parsed document replaces the string it came from: `raw` holds the whole
            # record either way, and keeping both doubles the largest field in the row.
            merged["CloudTrailEvent"] = dict(inner)
        payload: dict[str, Any] = {
            "class_uid": class_uid,
            "time": parse_iso8601(inner.get("eventTime") or record.get("EventTime")),
            # CloudTrail's own event id. Globally unique and stable, so the overlapping
            # re-read each cycle deduplicates exactly instead of duplicating.
            "metadata_uid": str(inner.get("eventID") or record.get("EventId") or ""),
            "metadata_product_name": "AWS CloudTrail",
            "metadata_product_vendor_name": "Amazon Web Services",
            "metadata_log_name": str(inner.get("eventCategory") or "Management"),
            "metadata_version": "1.9.0",
            "severity_id": int(Severity.INFORMATIONAL),
            "cloud_provider": "AWS",
            "raw": merged,
        }
        # `requestID` groups the API call with everything AWS did to service it — the
        # STS call, the KMS decrypt, the downstream service event all carry it — which
        # is exactly what a correlation uid is for.
        put(payload, "metadata_correlation_uid", inner.get("requestID"))
        put(payload, "cloud_region", inner.get("awsRegion") or self.region())
        put(
            payload,
            "cloud_account_uid",
            inner.get("recipientAccountId") or dig(inner, "userIdentity.accountId"),
        )
        label(payload, "cloud", "aws", "cloudtrail")
        return payload

    # ── 6003 API activity ──────────────────────────────────────────────────

    def _map_api(
        self, record: Mapping[str, Any], inner: Mapping[str, Any], event_name: str
    ) -> dict[str, Any]:
        payload = self._base(record, inner, _A)
        self._fill_api(payload, inner, record, event_name)
        self._fill_actor(payload, inner, record)
        self._fill_source(payload, inner)
        self._fill_status(payload, inner)
        self._fill_resources(payload, inner, record)
        self._fill_context(payload, inner, record)
        self._fill_intent(payload, inner, event_name)

        actor = payload.get("actor_user_name") or payload.get("actor_invoked_by") or "unknown"
        service = str(inner.get("eventSource") or record.get("EventSource") or "aws")
        put(
            payload,
            "message",
            f"{event_name or 'AWS API call'} on {service} by {actor}"
            + (
                f" failed: {inner.get('errorCode')}"
                if inner.get("errorCode")
                else ""
            ),
            limit=MESSAGE_LIMIT,
        )
        return payload

    def _fill_api(
        self,
        payload: dict[str, Any],
        inner: Mapping[str, Any],
        record: Mapping[str, Any],
        event_name: str,
    ) -> None:
        put(payload, "api_operation", event_name)
        put(
            payload,
            "api_service_name",
            inner.get("eventSource") or record.get("EventSource"),
        )
        put(payload, "api_version", inner.get("apiVersion"))
        activity = crud_activity(event_name)
        payload["activity_id"] = activity
        # Always, not only for 99. The five CRUD buckets are a coarse summary of an API
        # name that says far more — "Create" does not distinguish `CreateUser` from
        # `CreateSnapshot` — and the event model *requires* a name when the id is 99,
        # which this unconditional assignment makes unreachable-by-construction rather
        # than dependent on a branch being right.
        put(
            payload,
            "activity_name",
            event_name if activity == API_OTHER else _API_ACTIVITY_NAMES.get(activity),
        )
        put(payload, "http_user_agent", inner.get("userAgent"), limit=512)

    def _fill_actor(
        self,
        payload: dict[str, Any],
        inner: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        """The caller, across the nine shapes `userIdentity.type` can take.

        6003 declares no top-level ``user`` object — measured, not assumed — so every
        identity field here is under ``actor.user``. The required ``actor`` object is
        satisfied by any of these, which matters for the `AWSService` case that has no
        user at all and is identified only by ``invoked_by``.
        """
        ident = inner.get("userIdentity")
        ident = ident if isinstance(ident, Mapping) else {}
        raw_type = str(ident.get("type") or "").strip()
        arn = ident.get("arn")
        issuer_name = dig(ident, "sessionContext.sessionIssuer.userName")

        name = (
            ident.get("userName")
            or issuer_name
            # A Root call carries no userName. Falling through to the ARN tail yields
            # "root", which is what makes the CIS "root account used" rule possible; an
            # actor left unnamed silently disables it.
            or (arn_tail(arn) if arn else "")
            or record.get("Username")
            or ident.get("invokedBy")
            or ident.get("principalId")
        )
        put(payload, "actor_user_name", name, limit=256)
        put(payload, "actor_user_uid", ident.get("principalId"), limit=256)
        # OCSF's `user.domain` is "the domain the user is defined in". For an AWS
        # principal that is the account, and it is what distinguishes `alice` in the
        # production account from `alice` in the sandbox — a distinction entity
        # resolution in Phase 3 has to make.
        put(payload, "actor_user_domain", ident.get("accountId"))
        put(payload, "actor_invoked_by", ident.get("invokedBy"))
        if raw_type:
            payload["actor_user_type_id"] = _USER_TYPES.get(
                raw_type.lower(), USER_UNKNOWN
            )
            stash(payload, "identity_type", raw_type)
        # The access key. The pivot for "what else did this credential do" and the direct
        # input to the Phase 5 key-rotation action.
        #
        # It lives at `userIdentity.accessKeyId` in a real record. The LookupEvents
        # envelope also carries a denormalised `AccessKeyId` copy, and reading only
        # that one is a trap: the field then populates for events read live through
        # LookupEvents and is empty for the same event replayed from an S3 trail, from
        # the quarantine table, or from the emulation generator — the paths this
        # connector's own tests and every backfill use. Read the identity first.
        put(
            payload,
            "actor_user_credential_uid",
            ident.get("accessKeyId")
            or inner.get("accessKeyId")
            or record.get("AccessKeyId"),
        )
        put(payload, "actor_session_uid", arn_role_session(arn))
        put(
            payload,
            "actor_session_created_time",
            parse_iso8601(dig(ident, "sessionContext.attributes.creationDate")),
        )
        # CloudTrail sends this as the *string* "true"/"false", not a boolean.
        mfa = as_bool(dig(ident, "sessionContext.attributes.mfaAuthenticated"))
        if mfa is not None:
            payload["actor_session_is_mfa"] = mfa

        if raw_type.lower() == "root":
            note(
                payload,
                "called by the account ROOT user, which cannot be restricted by IAM "
                "policy and should have no day-to-day use",
            )
            label(payload, "aws:root-account-used")
            attack(payload, "T1078.004")
        if str(ident.get("invokedBy") or "").endswith(".amazonaws.com"):
            label(payload, "aws:service-invoked")

        issuer_arn = dig(ident, "sessionContext.sessionIssuer.arn")
        if issuer_arn:
            stash(payload, "session_issuer_arn", issuer_arn)
            _add_resource(
                payload,
                resource_ref(
                    uid=str(issuer_arn),
                    name=issuer_name or arn_tail(issuer_arn),
                    type="AWS::IAM::Role",
                    cloud_partition=arn_partition(issuer_arn),
                ),
            )
        # Federated role assumption. `federatedProvider` names the identity provider
        # that vouched for the caller — `accounts.google.com`,
        # `token.actions.githubusercontent.com` — and an over-broad trust condition on a
        # CI provider is a documented path into an AWS account from outside it.
        provider = dig(ident, "sessionContext.webIdFederationData.federatedProvider")
        if provider:
            stash(payload, "federated_provider", provider)
            label(payload, f"aws:federated:{str(provider).lower()}")
            note(payload, f"session was federated from {provider}")
        # IAM Identity Center puts the *human* behind a permission-set session here.
        # Without it, every Identity Center action is attributed to the permission-set
        # role and the actual person is unknown.
        behalf = dig(inner, "userIdentity.onBehalfOf.userId")
        if behalf:
            stash(payload, "on_behalf_of_user_id", behalf)
            stash(
                payload,
                "identity_store_arn",
                dig(inner, "userIdentity.onBehalfOf.identityStoreArn"),
            )
            note(
                payload,
                f"acting on behalf of Identity Center user {behalf} — the human "
                f"identity behind this role session",
            )
        credential_id = ident.get("credentialId")
        if credential_id:
            stash(payload, "credential_id", credential_id)

        caller_account = str(ident.get("accountId") or "")
        own_account = str(inner.get("recipientAccountId") or "")
        if caller_account and own_account and caller_account != own_account:
            stash(payload, "caller_account_id", caller_account)
            note(
                payload,
                f"cross-account call: principal in account {caller_account} acted on "
                f"account {own_account}",
            )
            label(payload, "aws:cross-account")

    def _fill_source(self, payload: dict[str, Any], inner: Mapping[str, Any]) -> None:
        raw = inner.get("sourceIPAddress")
        set_ip(payload, "src_endpoint_ip", raw, note="source_ip_raw")
        if raw and "src_endpoint_ip" not in payload:
            # Not an address: a service principal (`cloudformation.amazonaws.com`) or
            # the literal "AWS Internal". `src_endpoint` is a REQUIRED object on 6003
            # and 3002, so the value also goes to `src_endpoint_svc_name` — one of the
            # twelve measured-legal `src_endpoint_*` fields — which keeps the datum
            # queryable and satisfies the requirement without putting a hostname in an
            # IP field that Phase 5 hands to `netsh`.
            put(payload, "src_endpoint_svc_name", raw, limit=200)
            self.service_principal_calls += 1
            label(payload, "aws:service-principal-caller")
        elif not raw and payload.get("class_uid") == _A:
            # No source datum at all. `sourceIPAddress` lives inside the CloudTrailEvent
            # string, so this is what a truncated or unparsable inner document looks
            # like — and the LookupEvents envelope carries no source field to fall back
            # on. 6003 *requires* `src_endpoint` (3002 and 2004 do not, measured), so
            # leaving it empty means the Event model rejects the whole record and the
            # only surviving copy of a management-plane call goes to the quarantine
            # table. That is strictly worse than keeping it: the record still names the
            # API, the account, the region and usually the caller.
            #
            # So the required object is filled with a substitute, following the house
            # convention — a sentinel that no real value can collide with (a service
            # principal is a hostname; this has spaces and parentheses), a
            # `substitute_for:` label, and a note. `aws:service-principal-caller` is
            # deliberately NOT set and `service_principal_calls` is not incremented:
            # this is an absence of evidence, not an observation of a service caller,
            # and conflating the two would corrupt that counter.
            put(payload, "src_endpoint_svc_name", "(source unknown — not in record)")
            label(payload, "substitute_for:src_endpoint")
            note(
                payload,
                "no sourceIPAddress in this record, so the required src_endpoint is a "
                "placeholder, not an observation — do not treat src_endpoint.svc_name "
                "here as a caller. Any geo, reputation or blocking decision that needs "
                "the source must skip this event (filter on the "
                "substitute_for:src_endpoint label)",
            )

    def _fill_status(self, payload: dict[str, Any], inner: Mapping[str, Any]) -> None:
        code = str(inner.get("errorCode") or "").strip()
        message = inner.get("errorMessage")
        if code:
            payload["status_id"] = int(Status.FAILURE)
            put(payload, "status_code", code)
            put(payload, "status_detail", message or code, limit=MESSAGE_LIMIT)
            if code.lower() in _DENIED_CODES:
                # One denial is a typo or a misconfigured pipeline. Many, from one
                # credential across many services, is an attacker enumerating their own
                # permissions — a rule over this label, not a per-event judgement.
                label(payload, "aws:access-denied")
        else:
            payload["status_id"] = int(Status.SUCCESS)
            if as_bool(inner.get("readOnly")) is False:
                # A successful mutating call. The cheapest possible filter for "what
                # actually changed in this account", which is the first question of every
                # cloud investigation.
                label(payload, "aws:mutating")

    def _fill_resources(
        self,
        payload: dict[str, Any],
        inner: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        """The resources the call touched, from whichever of the two lists exists.

        The inner document's `resources` is authoritative and carries ARNs; the
        envelope's `Resources` carries only a type and a name. The envelope is read only
        when the inner list is absent, which is the parse-failure path — reading both
        would produce a name-only duplicate of every ARN entry.
        """
        listed = inner.get("resources")
        region = inner.get("awsRegion") or self.region()
        if isinstance(listed, list) and listed:
            for entry in listed:
                if not isinstance(entry, Mapping):
                    continue
                arn = entry.get("ARN") or entry.get("arn")
                _add_resource(
                    payload,
                    resource_ref(
                        uid=arn,
                        name=arn_tail(arn) if arn else None,
                        type=entry.get("type"),
                        owner=entry.get("accountId"),
                        region=region,
                        cloud_partition=arn_partition(arn),
                    ),
                )
            return
        envelope = record.get("Resources")
        if isinstance(envelope, list):
            for entry in envelope:
                if isinstance(entry, Mapping):
                    _add_resource(
                        payload,
                        resource_ref(
                            name=entry.get("ResourceName"),
                            type=entry.get("ResourceType"),
                            region=region,
                        ),
                    )

    def _fill_context(
        self,
        payload: dict[str, Any],
        inner: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> None:
        stash(payload, "event_type", inner.get("eventType") or record.get("EventType"))
        stash(payload, "event_category", inner.get("eventCategory"))
        stash(payload, "event_version", inner.get("eventVersion"))
        stash(payload, "management_event", as_bool(inner.get("managementEvent")))
        stash(
            payload,
            "read_only",
            as_bool(inner.get("readOnly"))
            if inner.get("readOnly") is not None
            else as_bool(record.get("ReadOnly")),
        )
        stash(payload, "event_source", inner.get("eventSource"))
        stash(payload, "shared_event_id", inner.get("sharedEventID"))
        stash(payload, "aws_request_id", inner.get("requestID"))

        endpoint = inner.get("vpcEndpointId")
        if endpoint:
            stash(payload, "vpc_endpoint_id", endpoint)
            stash(payload, "vpc_endpoint_account", inner.get("vpcEndpointAccountId"))
            note(
                payload,
                f"reached the API through VPC endpoint {endpoint}, which is why "
                f"sourceIPAddress is a private address and why no internet-facing "
                f"network telemetry shows this call",
            )
            label(payload, "aws:via-vpc-endpoint")

        tls_version = dig(inner, "tlsDetails.tlsVersion")
        if tls_version:
            # No `tls_*` field is legal on 6003 — measured — so this is `unmapped` plus a
            # note rather than a silently dropped field.
            stash(payload, "tls_version", tls_version)
            stash(payload, "tls_cipher_suite", dig(inner, "tlsDetails.cipherSuite"))
            stash(payload, "tls_sni", dig(inner, "tlsDetails.clientProvidedHostHeader"))
            if str(tls_version).replace("TLSv", "") < "1.2":
                note(
                    payload,
                    f"negotiated {tls_version}, below the TLS 1.2 minimum AWS requires "
                    f"— an old SDK, or a client that is not the SDK at all",
                )
                label(payload, "aws:legacy-tls")

        if as_bool(inner.get("sessionCredentialFromConsole")):
            # A programmatic call made with credentials minted by a console session.
            # This is what a hijacked browser session looks like when it pivots to the
            # API, and it is otherwise indistinguishable from ordinary SDK use.
            note(
                payload,
                "made with credentials derived from a console session rather than a "
                "provisioned key — a browser session acting through the API",
            )
            label(payload, "aws:console-derived-credentials")

        addendum = inner.get("addendum")
        if isinstance(addendum, Mapping):
            stash(payload, "addendum_reason", addendum.get("reason"))
            stash(payload, "addendum_updated_fields", addendum.get("updatedFields"))
            note(
                payload,
                f"this record was amended after delivery ({addendum.get('reason')}); "
                f"the originally delivered copy was incomplete, so a detection that ran "
                f"on the first copy may have seen different data",
            )
            label(payload, "aws:amended-record")

        service_event = inner.get("serviceEventDetails")
        if service_event is not None:
            stash(payload, "service_event_details", service_event, limit=4_000)

        edge = inner.get("edgeDeviceDetails")
        if edge is not None:
            stash(payload, "edge_device_details", edge, limit=2_000)

    def _fill_intent(
        self, payload: dict[str, Any], inner: Mapping[str, Any], event_name: str
    ) -> None:
        techniques = _HIGH_SIGNAL.get(event_name.lower())
        if techniques:
            attack(payload, *techniques)
        label(payload, f"aws:api:{event_name.lower() or 'unknown'}")
        source = str(inner.get("eventSource") or "")
        if source.endswith(".amazonaws.com"):
            label(payload, f"aws:service:{source[: -len('.amazonaws.com')]}")

        reader = _PARAM_READERS.get(event_name)
        params = inner.get("requestParameters")
        if reader is not None and isinstance(params, Mapping):
            reader(payload, params, inner)
        elif reader is not None:
            # The call is one this connector reads parameters for, but AWS sent none.
            # That happens legitimately (`GetCallerIdentity` has no parameters) and it
            # also happens when a policy redacts them, so it is recorded rather than
            # assumed to be one or the other.
            stash(payload, "request_parameters_absent", True)

        # The responseElements of a credential-creating call name the credential that
        # now exists. `CreateAccessKey` returns the new key id (never the secret — AWS
        # does not log it), and that id is the thing every subsequent event by the new
        # credential will carry, which is what links the creation to its use.
        created_key = dig(inner, "responseElements.accessKey.accessKeyId")
        if created_key:
            stash(payload, "created_access_key_id", created_key)
            stash(
                payload,
                "created_access_key_user",
                dig(inner, "responseElements.accessKey.userName"),
            )
            note(
                payload,
                f"created access key {created_key} for "
                f"{dig(inner, 'responseElements.accessKey.userName') or 'an IAM user'} "
                f"— every later event using that key id is attributable to this call",
            )
        created_user = dig(inner, "responseElements.user.arn")
        if created_user:
            _add_resource(
                payload,
                resource_ref(
                    uid=str(created_user),
                    name=arn_tail(created_user),
                    type="AWS::IAM::User",
                    cloud_partition=arn_partition(created_user),
                ),
            )
        created_role = dig(inner, "responseElements.role.arn")
        if created_role:
            _add_resource(
                payload,
                resource_ref(
                    uid=str(created_role),
                    name=arn_tail(created_role),
                    type="AWS::IAM::Role",
                    cloud_partition=arn_partition(created_role),
                ),
            )
        instances = dig(inner, "responseElements.instancesSet")
        for entry in items_of(instances):
            if isinstance(entry, Mapping) and entry.get("instanceId"):
                _add_resource(
                    payload,
                    resource_ref(uid=str(entry["instanceId"]), type="AWS::EC2::Instance"),
                )
        assumed = dig(inner, "responseElements.credentials.accessKeyId")
        if assumed:
            # The temporary key an AssumeRole minted. This is the join between the
            # identity that assumed the role and every action the resulting session took.
            stash(payload, "issued_access_key_id", assumed)
            stash(
                payload,
                "issued_session_expiration",
                dig(inner, "responseElements.credentials.expiration"),
            )

    # ── 3002 authentication (console sign-in) ──────────────────────────────

    def _map_signin(
        self, record: Mapping[str, Any], inner: Mapping[str, Any], event_name: str
    ) -> dict[str, Any]:
        """Console sign-in, role switching and MFA checks.

        A separate class, not a variant of the API path, because OCSF 3002 **requires**
        a ``user`` object and 6003 declares none — so the identity fields here are
        ``user_*`` rather than ``actor.user.*``. 3002 also declares the top-level
        ``session_*``, ``is_mfa`` and ``auth_protocol`` families that 6003 does not, and
        it does **not** declare ``resources`` — all four measured against the vendored
        bundle.
        """
        payload = self._base(record, inner, _AUTH)
        activity = _SIGNIN_ACTIVITIES.get(event_name.lower(), AUTH_OTHER)
        payload["activity_id"] = activity
        # The vendor's own eventName, always. Required when the id is 99 and strictly
        # more informative than "Logon" when it is not.
        put(payload, "activity_name", event_name or "AWS console sign-in")

        ident = inner.get("userIdentity")
        ident = ident if isinstance(ident, Mapping) else {}
        raw_type = str(ident.get("type") or "").strip()
        arn = ident.get("arn")
        name = (
            ident.get("userName")
            or dig(ident, "sessionContext.sessionIssuer.userName")
            or (arn_tail(arn) if arn else "")
            or record.get("Username")
            or ident.get("principalId")
        )
        put(payload, "user_name", name, limit=256)
        put(payload, "user_uid", ident.get("principalId"), limit=256)
        put(payload, "user_domain", ident.get("accountId"))
        put(payload, "user_account_uid", ident.get("accountId"))
        if raw_type:
            payload["user_type_id"] = _USER_TYPES.get(raw_type.lower(), USER_UNKNOWN)
            stash(payload, "identity_type", raw_type)
        # 3002 declares `user.credential_uid` and `session.credential_uid`; a console
        # sign-in that produced credentials carries the key here. Same three-level read
        # as the 6003 path — identity first, envelope last — see `_fill_actor`.
        put(
            payload,
            "user_credential_uid",
            ident.get("accessKeyId")
            or inner.get("accessKeyId")
            or record.get("AccessKeyId"),
        )
        put(payload, "session_uid", arn_role_session(arn))
        put(
            payload,
            "session_created_time",
            parse_iso8601(dig(ident, "sessionContext.attributes.creationDate")),
        )
        put(payload, "session_issuer", dig(ident, "sessionContext.sessionIssuer.arn"))

        self._fill_source(payload, inner)
        put(payload, "http_user_agent", inner.get("userAgent"), limit=512)
        self._fill_signin_outcome(payload, inner, event_name)
        self._fill_context(payload, inner, record)
        label(payload, "identity", "authentication", f"aws:signin:{event_name.lower()}")

        extra = inner.get("additionalEventData")
        extra = extra if isinstance(extra, Mapping) else {}
        # "Yes"/"No" strings, not booleans.
        mfa = as_bool(extra.get("MFAUsed"))
        if mfa is None:
            mfa = as_bool(dig(ident, "sessionContext.attributes.mfaAuthenticated"))
        if mfa is not None:
            payload["is_mfa"] = mfa
        stash(payload, "mfa_used_raw", extra.get("MFAUsed"))
        stash(payload, "mobile_version", extra.get("MobileVersion"))
        stash(payload, "login_to", extra.get("LoginTo"))
        stash(payload, "saml_provider_arn", extra.get("SamlProviderArn"))
        if extra.get("SamlProviderArn"):
            put(payload, "auth_protocol", "SAML")
            # 5, not 99. OCSF's `auth_protocol_id` table on 3002 carries SAML as a
            # first-class member (measured: {..., 4 OpenID, 5 SAML, 6 OAUTH 2.0, ...}),
            # so filing a SAML sign-in as "Other" with a SAML caption would make every
            # rule written against `auth_protocol_id == 5` miss federated AWS logins
            # entirely while the event still *looks* correct to a human reading it.
            payload["auth_protocol_id"] = AUTH_PROTOCOL_SAML
        elif raw_type.lower() in ("webidentityuser", "federateduser") or dig(
            ident, "sessionContext.webIdFederationData.federatedProvider"
        ):
            # OIDC federation — an external identity provider, or a CI system assuming
            # a role through a web-identity token.
            put(payload, "auth_protocol", "OpenID")
            payload["auth_protocol_id"] = AUTH_PROTOCOL_OPENID

        # `resources` is illegal on 3002 — measured — so the switched-to role, which the
        # 6003 path would carry as a resource reference, goes to unmapped here. Losing
        # it is not an option: "which role did this session switch into" is the whole
        # question a SwitchRole event answers.
        for key in ("SwitchFrom", "SwitchTo", "RoleArn", "RoleName", "TargetAccountId"):
            stash(payload, f"switch_{key.lower()}", extra.get(key))
        params = inner.get("requestParameters")
        if isinstance(params, Mapping):
            for key in ("roleArn", "roleName", "account", "displayName"):
                stash(payload, f"request_{key.lower()}", params.get(key))

        if raw_type.lower() == "root":
            note(
                payload,
                "ROOT account sign-in. The root user cannot be constrained by IAM "
                "policy and has no legitimate routine use",
            )
            label(payload, "aws:root-account-used")
            attack(payload, "T1078.004")
            if mfa is False:
                note(payload, "root signed in WITHOUT MFA")
                label(payload, "aws:root-no-mfa")
        elif mfa is False and payload.get("status_id") == int(Status.SUCCESS):
            note(payload, "single-factor console sign-in — no MFA was used")
            label(payload, "aws:no-mfa")
        if activity == AUTH_ACCOUNT_SWITCH:
            attack(payload, "T1078.004")

        put(
            payload,
            "message",
            f"{event_name or 'console sign-in'} by {name or 'unknown principal'} "
            f"({'succeeded' if payload.get('status_id') == int(Status.SUCCESS) else 'failed'})",
            limit=MESSAGE_LIMIT,
        )
        return payload

    def _fill_signin_outcome(
        self, payload: dict[str, Any], inner: Mapping[str, Any], event_name: str
    ) -> None:
        """The console sign-in outcome, which is **not** in `errorCode`.

        This is the trap in the whole file. A failed `ConsoleLogin` has

        * ``responseElements.ConsoleLogin == "Failure"``
        * ``errorMessage == "Failed authentication"``
        * and **no** ``errorCode`` at all.

        A status derived from `errorCode` — which is exactly how the API path works and
        how every other event in CloudTrail reports failure — therefore records every
        failed console login as a **success**. That single wrong field silently disables
        password spraying and brute-force detection against the AWS console, which is
        one of the most heavily attacked login surfaces there is. `responseElements` is
        read first for that reason.
        """
        outcome = dig(inner, "responseElements.ConsoleLogin")
        code = str(inner.get("errorCode") or "").strip()
        message = inner.get("errorMessage")
        if outcome:
            status = status_from_outcome(outcome)
            payload["status_id"] = int(status)
            put(payload, "status_code", str(outcome))
            put(payload, "status_detail", message or code, limit=MESSAGE_LIMIT)
            if status is Status.FAILURE:
                label(payload, "aws:signin-failed")
                attack(payload, "T1110.003")
            return
        if code:
            payload["status_id"] = int(Status.FAILURE)
            put(payload, "status_code", code)
            put(payload, "status_detail", message or code, limit=MESSAGE_LIMIT)
            label(payload, "aws:signin-failed")
            return
        if str(message or "").strip().lower().startswith("failed authentication"):
            # No code, no responseElements, but an explicit failure message. Seen on
            # `CheckMfa` and on some federated sign-in paths.
            payload["status_id"] = int(Status.FAILURE)
            put(payload, "status_detail", message, limit=MESSAGE_LIMIT)
            label(payload, "aws:signin-failed")
            return
        payload["status_id"] = int(Status.SUCCESS)

    # ── 2004 detection finding (CloudTrail Insights) ───────────────────────

    def _map_insight(
        self, record: Mapping[str, Any], inner: Mapping[str, Any], event_name: str
    ) -> dict[str, Any]:
        """A CloudTrail Insights record — AWS's own anomaly finding.

        Insights compares an API's call rate or error rate against a seven-day baseline
        and emits a Start record when it deviates and an End record when it returns, so
        an Insight is a *finding with a lifecycle*, which is 2004 and not 6003. That also
        means ``status_id`` here is the finding lifecycle enum, not the Success/Failure
        one — five distinct ``status_id`` tables exist in OCSF v1.9.0 and putting
        Success (1) in this one reads as "New".

        Written even though `LookupEvents` returns Insights only when the caller asks
        for ``EventCategory=insight``, because an operator who enables Insights on a
        trail should not need a code change, and because a replayed or S3-sourced
        Insight record must not be dropped.
        """
        payload = self._base(record, inner, _F)
        details = inner.get("insightDetails")
        details = details if isinstance(details, Mapping) else {}
        state = str(details.get("state") or "").strip()
        insight_type = str(details.get("insightType") or "UnknownInsight")
        source = str(details.get("eventSource") or inner.get("eventSource") or "aws")
        api = str(details.get("eventName") or event_name or "an API")

        payload["activity_id"] = FINDING_CREATE if state != "End" else FINDING_CLOSE
        put(payload, "activity_name", f"insight {state or 'Start'}")
        payload["status_id"] = int(
            FindingStatus.NEW if state != "End" else FindingStatus.RESOLVED
        )
        put(payload, "status_code", state or "Start")
        payload["is_alert"] = True
        # Insights is a rate anomaly, not a signature. Medium is the honest reading: it
        # is real evidence that behaviour changed and weak evidence that anything is
        # wrong, and a rate deviation graded High would outrank a confirmed credential
        # theft in the queue.
        payload["severity_id"] = int(Severity.MEDIUM)

        put(payload, "finding_uid", inner.get("eventID") or record.get("EventId"))
        put(payload, "finding_title", f"CloudTrail Insight: {insight_type} on {source} {api}")
        put(payload, "finding_analytic_name", "CloudTrail Insights")
        put(payload, "finding_analytic_uid", insight_type)
        payload["finding_types"] = [insight_type, "cloud-api-rate-anomaly"]
        put(payload, "finding_created_time", payload.get("time"))
        put(payload, "finding_src_url", self.spec.docs_url)

        context = details.get("insightContext")
        context = context if isinstance(context, Mapping) else {}
        stats = context.get("statistics")
        stats = stats if isinstance(stats, Mapping) else {}
        baseline = dig(stats, "baseline.average")
        observed = dig(stats, "insight.average")
        duration = stats.get("insightDuration")
        stash(payload, "insight_baseline_average", baseline)
        stash(payload, "insight_observed_average", observed)
        stash(payload, "insight_duration_minutes", duration)
        stash(payload, "insight_baseline_duration", stats.get("baselineDuration"))
        stash(payload, "insight_type", insight_type)
        stash(payload, "insight_state", state)

        multiple = ""
        try:
            if baseline and float(baseline) > 0:
                multiple = f" ({float(observed) / float(baseline):.1f}x baseline)"
        except (TypeError, ValueError, ZeroDivisionError):
            multiple = ""
        description = (
            f"{api} on {source} ran at {observed} calls/minute against a baseline of "
            f"{baseline}{multiple}"
            + (f" for {duration} minute(s)" if duration else "")
        )
        put(payload, "finding_desc", description, limit=MESSAGE_LIMIT)
        put(payload, "message", f"{insight_type}: {description}", limit=MESSAGE_LIMIT)

        # `evidences` is legal on 2004 and illegal on 6003 and 3002 — measured — so this
        # is the one path that may carry it. The attributions are Insights' own statement
        # of which identity, user agent and error code drove the deviation, which is
        # exactly the evidence an analyst needs and is otherwise buried three levels down.
        evidences: list[dict[str, Any]] = []
        for attribution in context.get("attributions") or []:
            if not isinstance(attribution, Mapping):
                continue
            kind = str(attribution.get("attribute") or "attribute")
            insight_values = _attribution_values(attribution.get("insight"))
            baseline_values = _attribution_values(attribution.get("baseline"))
            if not insight_values and not baseline_values:
                continue
            item = evidence(
                data={
                    "attribute": kind,
                    "during_insight": insight_values,
                    "during_baseline": baseline_values,
                }
            )
            if item:
                evidences.append(item)
            if kind == "userIdentityArn" and insight_values:
                # The identity driving the anomaly. Named on the actor as well, because a
                # finding whose actor is empty cannot be correlated to anything.
                first = str(insight_values[0].get("value") or "")
                if first:
                    put(payload, "actor_user_name", arn_tail(first), limit=256)
                    stash(payload, "insight_identity_arn", first)
            if kind == "errorCode" and insight_values:
                stash(
                    payload,
                    "insight_error_codes",
                    [v.get("value") for v in insight_values],
                )
        if evidences:
            payload["evidences"] = evidences

        techniques = _HIGH_SIGNAL.get(api.lower())
        if techniques:
            # The same hints the API path would attach. An error-rate insight on
            # `ListUsers` and a burst of `ListUsers` calls are the same discovery
            # behaviour reported by two different mechanisms; giving them different
            # technique labels would split one hunt into two.
            attack(payload, *techniques)
        if insight_type == "ApiErrorRateInsight":
            note(
                payload,
                "an error-rate deviation: the same API was called repeatedly and kept "
                "failing, which is the shape of permission enumeration by a principal "
                "probing what it can do",
            )
            attack(payload, "T1580")
        label(payload, "aws:insight", f"aws:insight-type:{insight_type.lower()}")
        return payload


def _attribution_values(block: Any) -> list[dict[str, Any]]:
    """The ``[{"value": …, "average": …}]`` list inside one Insights attribution."""
    if not isinstance(block, Mapping):
        return []
    out: list[dict[str, Any]] = []
    for entry in block.get("attributeValues") or []:
        if isinstance(entry, Mapping) and entry.get("attributeValue") is not None:
            out.append(
                {
                    "value": entry.get("attributeValue"),
                    "average": entry.get("average"),
                }
            )
    return out


def _aws_error_name(exc: HttpError) -> str:
    """The AWS error name out of an :class:`HttpError`, lower-cased.

    Read from the message and the retained body rather than from a response object,
    because by the time the error propagates out of :meth:`Connector.paginate` the
    response is gone. Both are checked: `_vendor_error` puts the ``__type`` in the
    message for a json1.1 error, but a throttle returned by a proxy in front of the API
    has no parseable body and only the status survives.
    """
    haystack = f"{exc} {getattr(exc, 'body', '')}".lower()
    for name in RECOVERABLE_ERRORS:
        if name in haystack:
            return name
    return ""


def cloudtrail_connectors(
    pipeline: Any, config: SocConfig, **kwargs: Any
) -> list[CloudTrailConnector]:
    """The CloudTrail connectors to run.

    A list of one today, and a list rather than a single instance because the correct
    multi-region deployment is one instance per region — `LookupEvents` is scoped to the
    region it is called in, and global services report only into ``us-east-1``. The
    registry grows this list from configuration when a second region is declared; the
    signature does not have to change for that to happen.
    """
    return [CloudTrailConnector(pipeline, config, **kwargs)]


__all__ = [
    "ADMIN_PORTS",
    "AMZ_JSON",
    "AUTH_PROTOCOL_OPENID",
    "AUTH_PROTOCOL_SAML",
    "DATA_PORTS",
    "DELIVERY_LAG_SECONDS",
    "EVENT_HISTORY_SECONDS",
    "LOOKUP_TARGET",
    "LOOKUP_TPS",
    "MAX_LOOKUP_RESULTS",
    "RECOVERABLE_ERRORS",
    "RETENTION_MARGIN_SECONDS",
    "CloudTrailConnector",
    "OpenRule",
    "arn_partition",
    "arn_role_session",
    "arn_tail",
    "as_policy",
    "cloudtrail_connectors",
    "items_of",
    "open_rules",
    "wildcard_principals",
]

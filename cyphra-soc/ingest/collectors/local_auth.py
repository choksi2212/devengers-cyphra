"""Local authentication telemetry, and an honest account of what is missing from it.

Identity is where intrusions become visible. On Windows the canonical source is the
``Security`` channel — 4624/4625 logon and failure, 4648 explicit credentials, 4672
privileged assignment, 4720/4732 account and group change — and that channel is
already mapped by :mod:`ingest.collectors.windows_eventlog`.

**On this host it returns error 5 on every read.** ``Security`` requires an elevated
process or membership of the built-in ``Event Log Readers`` group, and the shell this
was developed in has neither. That single fact is what shapes this module: a SOC whose
identity coverage consists of a channel it cannot open has no identity coverage at
all, however green the source list looks.

So there are three collectors here, and only the first is the real thing:

``LocalAuthLogCollector``
    ``Security`` plus nine *unelevated-readable* channels that each carry a fragment
    of authentication. The strongest by a wide margin is
    ``Microsoft-Windows-NTLM/Operational`` event 4020, which records every outbound
    NTLM authentication this host performs **with the process that caused it**, the
    target machine and service, the NTLM version, and whether a MIC and channel
    binding were present. That is process-attributed credential use — the thing 4624
    cannot give you — and it needs no elevation. Windows Hello 7001 carries the same
    ``NTSTATUS``/sub-status pair as 4625, so authentication *failure* codes are
    decodable here too. The rest (RDP session events, profile load, WinRM auth
    failure, biometric verification, Entra token acquisition) are thinner but real.

``LogonSessionCollector``
    The live LSA logon-session table, diffed. This is the state-based substitute for
    4624/4634: every session's user, SID, logon type, authentication package and logon
    time, read directly from LSA. Its limitation is measured and severe — see below.

``LocalAccountCollector``
    Local users, group membership and password policy, diffed. This is the substitute
    for 4720/4722/4725/4726/4732/4733 *and*, less obviously, for 4625: ``NetUserEnum``
    exposes ``bad_pw_count`` per account without elevation, so a rise in it across
    several accounts between two polls is a password spray that the Security channel
    would have shown and here does not have to.

Every substitute is labelled as one. Each of these collectors sets
``metadata_labels`` containing ``substitute_for:<event ids>`` and a ``soc_notes``
entry naming what the real source would have added, so a coverage report can state
"identity is being inferred, not observed" rather than counting three green sources.

Four things measured on this host that a reader should not have to rediscover:

* **``LsaGetLogonSessionData`` succeeds on 2 of 14 sessions unelevated.** The other 12
  return error 5. ``LsaEnumerateLogonSessions`` itself succeeds and returns all 14
  LUIDs, so the *count* is knowable even when the content is not — which is why this
  module emits an event when the unreadable count changes. 86% of this host's logon
  sessions are opaque, and a SYSTEM-level attacker logon is in that 86%.
* **Four of these channels are written by a provider whose name is not derivable from
  the channel path.** ``Microsoft-Windows-User Profile Service/Operational`` is
  written by ``Microsoft-Windows-User Profile*s* Service``; the Kerberos channel by
  ``Microsoft-Windows-Security-Kerberos``; the LSA channel by ``LsaSrv``; the
  SmbClient channel by ``Microsoft-Windows-SMBClient``. Since the event map here is
  keyed by ``(provider, event_id)``, a guessed provider string would not raise — it
  would leave that channel permanently unmapped while its records still arrived.
  :meth:`LocalAuthLogCollector.verify_provider_map` reads each channel's
  ``OwningPublisher`` at startup and fails loudly instead.
* **Event ids collide across these channels.** ``Microsoft-Windows-Winlogon`` and
  ``Microsoft-Windows-User Profiles Service`` both write ids 1 and 2, meaning
  unrelated things. That is the reason for the provider-qualified map.
* **``Microsoft-Windows-Kerberos/Operational`` and ``Microsoft-Windows-LSA/Operational``
  are readable but disabled** — they open cleanly and return nothing, forever. See
  :data:`AUTH_CHANNEL_SETUP`.

Channels considered and deliberately left out: ``Microsoft-Windows-User Device
Registration/Admin`` (its id 360 is a per-logon diagnostic dump of Entra join state —
useful context, but it is a state description rather than an authentication event, and
at 300 of 308 records it would dominate this collector's volume), and
``Microsoft-Windows-CAPI2/Operational`` (denied unelevated here, and it is certificate
API tracing rather than authentication).
"""

from __future__ import annotations

import time
from typing import Any

from core.schema.ocsf import ClassUid, QueryResultId, Severity
from ingest.collectors.base import (
    Availability,
    PullCollector,
    available,
    is_admin,
    is_windows,
    unavailable,
)
from ingest.collectors.windows_eventlog import (
    DATA_MAP,
    EVENT_MAP,
    LOGON_TYPES,
    Channel,
    WindowsEventLogCollector,
    _Mapped,
)

_AUTH = int(ClassUid.AUTHENTICATION)
_USER = int(ClassUid.USER_MANAGEMENT)
_GROUP = int(ClassUid.GROUP_MANAGEMENT)
# Category 5 (Discovery) — where *state* goes. The distinction these five carry is
# the one thing that keeps a state-diff collector from corrupting the data it feeds:
# a snapshot of who is logged on is not a logon, and emitting it as 3002 would put a
# synthetic record into every rule that counts logons. Changes go to 3002/3006/3007;
# the snapshots that changes are computed *from* go here.
_CONFIG_STATE = int(ClassUid.DEVICE_CONFIG_STATE)          # 5002
_USER_INV = int(ClassUid.USER_INVENTORY)                   # 5003
_GROUP_QUERY = int(ClassUid.ADMIN_GROUP_QUERY)             # 5009
_SESSION_QUERY = int(ClassUid.SESSION_QUERY)               # 5017
_CONFIG_CHANGE = int(ClassUid.DEVICE_CONFIG_STATE_CHANGE)  # 5019
_SUCCESS, _FAILURE = 1, 2

#: Discovery activity ids. Every class in category 5 that this module uses has one of
#: these two pairs, checked against the vendored schema in ``tests/scratch_collectors``:
#: 5001/5002/5003/5019/5020 are ``{1 Log, 2 Collect}`` and 5009/5017/5018 are
#: ``{1 Query}``. ``COLLECT`` is the honest one for a poll — the collector went and
#: read the state rather than receiving a log of it.
_COLLECT = 2
_QUERY = 1

SECURITY_CHANNEL = "Security"

#: What to tell the operator to make identity coverage real. Ordered by how much
#: coverage each step buys, not by how easy it is.
#:
#: The audit-policy commands matter as much as the elevation: on a default Windows
#: install ``Logon`` auditing is on but ``Detailed Tracking`` (4688) and ``Kerberos``
#: subcategories are not, so an elevated process reading ``Security`` still finds no
#: process-creation events. "Enable the channel" and "enable the auditing that writes
#: to it" are two different actions and only the first is obvious.
SECURITY_SETUP = """\
Windows Security channel — access denied unelevated (measured: error 5).

  1. Grant read access without elevation (survives reboot, preferred for a service):
       net localgroup "Event Log Readers" "%USERDOMAIN%\\%USERNAME%" /add
     then sign out and back in — group membership is baked into the logon token, so
     the change does not apply to the session that made it.

  2. Or run the collector from a shell started with 'Run as administrator'.

  3. Turn on the auditing that actually writes the interesting records. Elevated:
       auditpol /set /subcategory:"Logon" /success:enable /failure:enable
       auditpol /set /subcategory:"Logoff" /success:enable
       auditpol /set /subcategory:"Account Lockout" /failure:enable
       auditpol /set /subcategory:"Special Logon" /success:enable
       auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
       auditpol /set /subcategory:"Process Creation" /success:enable
       auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
       auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
       auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
     And to get command lines onto 4688 — without this, 4688 names the image and not
     what it was told to do, which is most of the value:
       reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" ^
         /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

  4. Raise the log size. The default 20 MB wraps in hours once the above are on:
       wevtutil sl Security /ms:1073741824
"""

#: Two channels here open cleanly and are disabled, which is the failure mode this
#: codebase keeps running into: a readable channel that returns nothing forever.
AUTH_CHANNEL_SETUP = """\
Authentication channels that exist, are readable, and are switched off (measured):

    wevtutil sl "Microsoft-Windows-Kerberos/Operational" /e:true
    wevtutil sl "Microsoft-Windows-LSA/Operational" /e:true

  Both need elevation. Neither is a substitute for the Security channel: the Kerberos
  client channel records this host's own ticket requests, not a KDC's view of them.
"""


# ── status decoding ───────────────────────────────────────────────────────────
#
# The single highest-value transformation in this file. Windows reports *why* an
# authentication failed as an NTSTATUS in `Status`/`SubStatus` (4625, 4776, Hello
# 7001) or as a Kerberos error code in `Status` (4768/4771). Left as raw hex those
# fields are unqueryable in practice; decoded, they separate techniques that produce
# an identical event id and an identical count:
#
#   0xC0000064 across many usernames from one source  → user enumeration
#   0xC000006A across many usernames from one source  → password spraying
#   0xC0000072 on one username                        → someone holds a credential
#                                                       for an account that is off
#
# Same event, same volume, three different incidents and three different responses.

#: NTSTATUS → (mnemonic, what it means for a detection, severity floor or None).
#:
#: A severity is set only where the code is itself the finding regardless of volume.
#: "Wrong password" is not one of those — one is noise, forty is a spray, and that
#: judgement belongs to correlation, not here.
NTSTATUS_LOGON: dict[int, tuple[str, str, int | None]] = {
    0x00000000: ("STATUS_SUCCESS", "no error", None),
    0xC0000022: ("STATUS_ACCESS_DENIED", "the caller was denied, not the credential",
                 None),
    0xC000005E: ("STATUS_NO_LOGON_SERVERS",
                 "no domain controller was reachable — cached credentials or an "
                 "isolated host", None),
    0xC000005F: ("STATUS_NO_SUCH_LOGON_SESSION",
                 "the referenced logon session is gone", None),
    0xC0000064: ("STATUS_NO_SUCH_USER",
                 "the account does not exist. Repeated across distinct names from one "
                 "source is user enumeration, not a spray — the attacker is still "
                 "building the account list",
                 int(Severity.LOW)),
    0xC000006A: ("STATUS_WRONG_PASSWORD",
                 "the account exists and the password was wrong. Across many accounts "
                 "from one source this is password spraying; repeated on one account "
                 "it is brute force", None),
    0xC000006D: ("STATUS_LOGON_FAILURE",
                 "generic failure — the *sub*-status carries the real reason, and "
                 "without it this code says only 'no'", None),
    0xC000006E: ("STATUS_ACCOUNT_RESTRICTION",
                 "credentials were correct and a restriction refused the logon", None),
    0xC000006F: ("STATUS_INVALID_LOGON_HOURS",
                 "correct password, outside the account's permitted hours — a valid "
                 "credential being used at a time its owner does not work",
                 int(Severity.MEDIUM)),
    0xC0000070: ("STATUS_INVALID_WORKSTATION",
                 "correct password, from a machine the account may not use — a "
                 "credential in the wrong place", int(Severity.MEDIUM)),
    0xC0000071: ("STATUS_PASSWORD_EXPIRED", "password past its maximum age", None),
    0xC0000072: ("STATUS_ACCOUNT_DISABLED",
                 "someone authenticated successfully against a disabled account: the "
                 "credential is valid and held by someone who has not noticed it was "
                 "switched off", int(Severity.MEDIUM)),
    0xC00000DC: ("STATUS_INVALID_SERVER_STATE",
                 "the SAM or LSA server is in the wrong state for this request", None),
    0xC0000133: ("STATUS_TIME_DIFFERENCE_AT_DC",
                 "clock skew beyond the Kerberos tolerance — also what a forged ticket "
                 "with a bad timestamp produces", int(Severity.LOW)),
    0xC000015B: ("STATUS_LOGON_TYPE_NOT_GRANTED",
                 "the credential is valid and the account lacks the right for this "
                 "logon type — often a service account being used interactively",
                 int(Severity.MEDIUM)),
    0xC000018D: ("STATUS_TRUSTED_RELATIONSHIP_FAILURE",
                 "the machine account's trust with the domain is broken", None),
    0xC0000192: ("STATUS_NETLOGON_NOT_STARTED", "the Netlogon service is not running",
                 None),
    0xC0000193: ("STATUS_ACCOUNT_EXPIRED", "the account is past its expiry date", None),
    0xC0000224: ("STATUS_PASSWORD_MUST_CHANGE",
                 "the account must change its password before it can log on", None),
    0xC0000225: ("STATUS_NOT_FOUND", "the requested object does not exist", None),
    0xC0000234: ("STATUS_ACCOUNT_LOCKED_OUT",
                 "the lockout threshold was reached. The lockout is evidence that the "
                 "attempts happened even if the individual failures were not audited",
                 int(Severity.MEDIUM)),
    0xC0000380: ("STATUS_SMARTCARD_WRONG_PIN",
                 "wrong PIN against a smartcard or Windows Hello credential", None),
    0xC0000381: ("STATUS_SMARTCARD_CARD_BLOCKED", "the smartcard is blocked", None),
    0xC0000382: ("STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED",
                 "no PIN was supplied for the card", None),
    0xC0000383: ("STATUS_SMARTCARD_NO_CARD", "no smartcard is present", None),
    0xC0000388: ("STATUS_DOWNGRADE_DETECTED",
                 "the security downgrade check failed — a man-in-the-middle forcing a "
                 "weaker authentication is one cause", int(Severity.HIGH)),
    0xC0000413: ("STATUS_AUTHENTICATION_FIREWALL_FAILED",
                 "an authentication policy silo refused the logon — this is what "
                 "Protected Users and authentication-policy restrictions look like "
                 "when they work", int(Severity.LOW)),
}

#: Kerberos protocol error code → (mnemonic, meaning, severity floor).
#:
#: Windows writes these in ``Status`` on 4768 and 4771 as small hex values, which is
#: why they cannot share a table with NTSTATUS: ``0x18`` is a Kerberos preauth failure
#: and a perfectly valid, entirely unrelated NTSTATUS. The event id decides which
#: table applies, and getting that wrong would silently mistranslate every ticket
#: failure on a domain-joined host.
KERBEROS_STATUS: dict[int, tuple[str, str, int | None]] = {
    0x00: ("KDC_ERR_NONE", "no error", None),
    0x06: ("KDC_ERR_C_PRINCIPAL_UNKNOWN",
           "the client principal does not exist — this is what Kerberos user "
           "enumeration (kerbrute and friends) looks like", int(Severity.LOW)),
    0x07: ("KDC_ERR_S_PRINCIPAL_UNKNOWN",
           "the service principal does not exist", None),
    0x09: ("KDC_ERR_NULL_KEY", "the principal has no key set", None),
    0x0C: ("KDC_ERR_POLICY",
           "policy refused the ticket — logon hours, workstation restriction or an "
           "authentication silo", int(Severity.LOW)),
    0x0D: ("KDC_ERR_BADOPTION", "the requested ticket options cannot be granted",
           None),
    0x0E: ("KDC_ERR_ETYPE_NOTSUPP",
           "no shared encryption type. A request for RC4 or DES on a host configured "
           "for AES is an encryption downgrade attempt", int(Severity.MEDIUM)),
    0x10: ("KDC_ERR_PADATA_TYPE_NOSUPP",
           "the pre-authentication type is unsupported — commonly a smartcard "
           "requirement or PKINIT against a KDC without a certificate", None),
    0x12: ("KDC_ERR_CLIENT_REVOKED",
           "the account is disabled, expired or locked out", int(Severity.LOW)),
    0x17: ("KDC_ERR_KEY_EXPIRED", "the account's password has expired", None),
    0x18: ("KDC_ERR_PREAUTH_FAILED",
           "wrong password. On 4771 this is the Kerberos spray and brute-force "
           "signature, and it is the code to count per source rather than per account",
           None),
    0x19: ("KDC_ERR_PREAUTH_REQUIRED",
           "normal: the KDC is asking for pre-authentication. Its *absence* on a 4768 "
           "for a user account is the AS-REP roasting signature, because that means "
           "pre-authentication is not required for that account", None),
    0x1B: ("KDC_ERR_MUST_USE_USER2USER", "the service requires user-to-user", None),
    0x1F: ("KRB_AP_ERR_BAD_INTEGRITY",
           "the ticket could not be decrypted with the expected key — a wrong service "
           "password, or a forged ticket signed with the wrong key",
           int(Severity.MEDIUM)),
    0x20: ("KRB_AP_ERR_TKT_EXPIRED", "the ticket has expired", None),
    0x21: ("KRB_AP_ERR_TKT_NYV", "the ticket is not yet valid", None),
    0x22: ("KRB_AP_ERR_REPEAT", "a replay was detected", int(Severity.MEDIUM)),
    0x23: ("KRB_AP_ERR_NOT_US", "the ticket is for a different realm", None),
    0x24: ("KRB_AP_ERR_BADMATCH",
           "the ticket and the authenticator do not match", int(Severity.LOW)),
    0x25: ("KRB_AP_ERR_SKEW",
           "clock skew too great. Forged tickets with a hand-set lifetime produce "
           "this, which is why it is worth more than its usual cause",
           int(Severity.LOW)),
    0x26: ("KRB_AP_ERR_BADADDR",
           "the ticket was presented from an address it was not issued for", None),
    0x29: ("KRB_AP_ERR_MODIFIED",
           "the message was altered in flight", int(Severity.MEDIUM)),
    0x3E: ("KDC_ERR_CLIENT_NOT_TRUSTED",
           "the client certificate was not trusted for PKINIT", None),
}

#: Event ids whose ``Status``/``SubStatus`` are *Kerberos* codes rather than NTSTATUS.
KERBEROS_STATUS_EVENTS = frozenset({4768, 4769, 4770, 4771, 4772, 4773})

#: Logon type → why it is worth a note, and a severity floor where the type alone
#: justifies one. Types 3 and 2 are the overwhelming majority of normal activity and
#: deliberately carry neither.
LOGON_TYPE_MEANING: dict[int, tuple[str, int | None]] = {
    2: ("interactive logon at the console", None),
    3: ("network logon — SMB, RPC or a mapped drive; the credential is not sent in "
        "the clear but the session is remote", None),
    4: ("batch logon — a scheduled task's credential", None),
    5: ("service logon — a service account starting", None),
    7: ("workstation unlock", None),
    8: ("NetworkCleartext: the password crossed the network in a recoverable form. "
        "IIS basic authentication is the benign cause; everything else is worth "
        "reading, because a captured cleartext credential needs no cracking",
        int(Severity.MEDIUM)),
    9: ("NewCredentials: the process kept its own token and authenticated outward as "
        "someone else — 'runas /netonly'. This is the normal Windows way to use a "
        "stolen credential without a password prompt, and it is a lateral-movement "
        "signal much more than an administrative one", int(Severity.MEDIUM)),
    10: ("RemoteInteractive: RDP or Terminal Services — a full interactive desktop "
         "from elsewhere", int(Severity.LOW)),
    11: ("CachedInteractive: authenticated against a cached verifier with no domain "
         "controller reachable", None),
    12: ("CachedRemoteInteractive: RDP authenticated from cache with no domain "
         "controller reachable", int(Severity.LOW)),
    13: ("CachedUnlock: unlocked against a cached verifier", None),
}

#: Values Windows writes into address and name fields to mean "there isn't one".
#:
#: These matter because they are *not* empty strings. ``-`` is the Security channel's
#: absent marker, ``LOCAL`` is what Terminal Services writes for a console session,
#: and ``Null`` — capital N, a literal four-character string — is what NTLM 4020
#: writes for ``TargetIP``. Any of them reaching an IP field fails validation and
#: quarantines an otherwise perfect authentication record.
_PLACEHOLDERS = frozenset({"-", "", "null", "local", "unknown", "n/a", "::",
                           "0.0.0.0", "not available"})


def parse_status_code(value: Any) -> int | None:
    """``'0xC000006D'`` / ``'3399549144'`` / ``'-1073741252'`` → an unsigned int.

    All three forms occur, and two of them occur *in the same channel*: on this host
    ``Microsoft-Windows-AAD`` writes event 1097's error as the unsigned decimal
    ``3399549144`` and event 1256's as the signed decimal ``-1073741252``, both of
    which are 32-bit codes whose hex form is what anyone would search for. Normalising
    to unsigned is what makes one lookup table work for every producer.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in ("-",):
        return None
    try:
        code = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None
    if code < 0:
        code += 1 << 32
    return code & 0xFFFFFFFF


def decode_status(code: int | None, *, kerberos: bool = False
                  ) -> tuple[str, str, int | None] | None:
    """Look a status code up in the right table, or return ``None``.

    Returns ``None`` rather than a guess for an unknown code. An invented mnemonic
    would be worse than a bare number: the number is honestly unidentified, whereas a
    wrong name is an assertion a rule may then match on.
    """
    if code is None:
        return None
    return (KERBEROS_STATUS if kerberos else NTSTATUS_LOGON).get(code)


# ── local account state ───────────────────────────────────────────────────────

#: ``USER_INFO_3.flags`` bits, with the ones that are findings marked.
#:
#: Source: the ``UF_*`` constants in lmaccess.h. Only the bits that appear on real
#: accounts are here; a bit not in this table is still reported numerically.
UF_FLAGS: dict[int, str] = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQUIRE_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
    0x4000000: "NO_AUTH_DATA_REQUIRED",
}

#: Account flags that are a finding on their own, with the reason and a severity.
#: Each is a real, exploitable weakness rather than a style preference.
UF_FINDINGS: dict[int, tuple[str, int]] = {
    0x0020: ("PASSWD_NOTREQD: this account may have an empty password, and an empty "
             "password authenticates", int(Severity.MEDIUM)),
    0x0080: ("ENCRYPTED_TEXT_PASSWORD_ALLOWED: reversible encryption is on, so the "
             "plaintext password is recoverable from the account database",
             int(Severity.HIGH)),
    0x400000: ("DONT_REQUIRE_PREAUTH: Kerberos pre-authentication is disabled, which "
               "makes this account AS-REP roastable — an attacker can request a "
               "crackable blob for it without any credential at all",
               int(Severity.HIGH)),
    0x80000: ("TRUSTED_FOR_DELEGATION: this account can impersonate any user to any "
              "service. Compromising it is equivalent to compromising the users it "
              "impersonates", int(Severity.HIGH)),
    0x1000000: ("TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: constrained delegation with "
                "protocol transition — impersonation without the user's credential",
                int(Severity.MEDIUM)),
    0x200000: ("USE_DES_KEY_ONLY: DES is broken; this forces it", int(Severity.MEDIUM)),
}

#: ``USER_INFO_3.priv``.
USER_PRIV = {0: "guest", 1: "user", 2: "administrator"}

#: Local groups that confer privilege, keyed by well-known RID because the *names*
#: are localised — ``Administrators`` is ``Administratoren`` on a German install and
#: matching on the English string would silently monitor nothing there.
#:
#: Not every RID exists on every host, and "absent" is the common case rather than the
#: exception. Measured on this Windows Home install by enumerating all 17 local groups
#: and resolving each name to a SID: **five of the twelve below do not exist at all** —
#: 551 Backup Operators, 552 Replicator, 555 Remote Desktop Users, 556 Network
#: Configuration Operators and 574 Certificate Service DCOM Access. The other seven
#: exist and every one of their memberships is readable unelevated.
#:
#: Absent and unreadable are different findings with different remedies, and both
#: arrive as a failed lookup. They are kept apart by ``query_result_id`` on the 5009
#: events this module emits: ``DOES_NOT_EXIST`` for a RID that enumeration never
#: produced, ``ERROR`` for one that exists and whose membership could not be read.
PRIVILEGED_GROUP_RIDS: dict[int, str] = {
    544: "Administrators — full control of the host",
    551: "Backup Operators — can read and write any file, bypassing ACLs, which is "
         "read access to SAM and SYSTEM and therefore to every local hash",
    552: "Replicator",
    555: "Remote Desktop Users — interactive logon from the network",
    556: "Network Configuration Operators — can change routes and interfaces",
    559: "Performance Log Users — can schedule logging, historically an escalation "
         "path",
    562: "Distributed COM Users — can activate and launch COM objects remotely",
    568: "IIS_IUSRS",
    573: "Event Log Readers — can read the Security log, including any credential "
         "material logged into it",
    574: "Certificate Service DCOM Access",
    578: "Hyper-V Administrators — full control of guests, and of the host by way of "
         "them",
    580: "Remote Management Users — WinRM access, which is remote command execution",
}

#: Privileged local groups matched by *name*, for groups with no well-known RID. Each
#: one is a documented local-privilege-escalation path to SYSTEM, which is why
#: membership belongs in the identity baseline even though the group is created by an
#: ordinary application installer.
#:
#: Name matching is the fallback and only the fallback: :meth:`LocalAccountCollector`
#: checks the RID first, and consults this table only for a group whose RID is not in
#: :data:`PRIVILEGED_GROUP_RIDS`. Without that ordering ``Hyper-V Administrators``
#: would be reported twice on this host — once as RID 578 and once by name — and a
#: privileged-group count would be wrong by one on every inventory.
#:
#: Keys are case-folded because ``NetLocalGroupEnum`` returns the creator's casing:
#: measured ``docker-users`` lower-case, ``OpenSSH Users`` title-case,
#: ``CodexSandboxUsers`` camel-case, all on the same host.
PRIVILEGED_GROUP_NAMES: dict[str, str] = {
    "docker-users": "docker-users — a member can mount the host filesystem into a "
                    "container running as root and write anywhere, so this is "
                    "equivalent to local administrator",
    "openssh users": "OpenSSH Users — remote interactive logon over SSH. Well-known "
                     "RID 585 on this host, but the RID is recent enough that it is "
                     "absent on older builds where the group still exists",
    "vboxusers": "vboxusers — VirtualBox raw device and USB passthrough",
    "__vmware__": "__vmware__ — VMware's service group; membership is unexpected and "
                  "is worth reading as tampering rather than as configuration",
}


# ── LSA logon-session state ───────────────────────────────────────────────────

#: What to tell the operator to make logon-session coverage real.
#:
#: Unlike :data:`SECURITY_SETUP` there is no group membership that fixes this. The
#: ``SeTcbPrivilege``-adjacent check inside ``LsaGetLogonSessionData`` is on the
#: session's own token: a caller may read its own sessions and, without elevation,
#: nothing else. Measured on this host: 2 of 14.
LSA_SESSION_SETUP = """\
LSA logon-session table — readable, but only 2 of 14 sessions are.

  LsaEnumerateLogonSessions returns every LUID on the host without elevation, so the
  *count* of logon sessions is always correct. LsaGetLogonSessionData returns error 5
  for any session this process does not own, which on a normal desktop is every
  service and SYSTEM session — 86% of them here.

  1. Run the collector from an elevated shell, or as a service under SYSTEM. There is
     no group to join for this one; it is a token check, not an ACL.

  2. This is a substitute for 4624/4634. Fixing the Security channel (see
     local_auth.SECURITY_SETUP) is worth more than elevating this collector, because
     4624 carries the source address and the logon process and this table does not.
"""

#: ``SECURITY_LOGON_SESSION_DATA.UserFlags`` bits, from the ``LOGON_*`` constants in
#: NTSecAPI.h.
#:
#: Measured on this host: 49156 = ``0xC004`` =
#: ``LOGON_WINLOGON | LOGON_OPTIMIZED | LOGON_CACHED_ACCOUNT``. A bit not in this table
#: is still reported, numerically, in ``unmapped``.
LOGON_USER_FLAGS: dict[int, str] = {
    0x00001: "LOGON_GUEST",
    0x00002: "LOGON_NOENCRYPTION",
    0x00004: "LOGON_CACHED_ACCOUNT",
    0x00008: "LOGON_USED_LM_PASSWORD",
    0x00020: "LOGON_EXTRA_SIDS",
    0x00040: "LOGON_SUBAUTH_SESSION_KEY",
    0x00080: "LOGON_SERVER_TRUST_ACCOUNT",
    0x00100: "LOGON_NTLMV2_ENABLED",
    0x00200: "LOGON_RESOURCE_GROUPS",
    0x00400: "LOGON_PROFILE_PATH_RETURNED",
    0x00800: "LOGON_NT_V2",
    0x01000: "LOGON_LM_V2",
    0x02000: "LOGON_NTLM_V2",
    0x04000: "LOGON_OPTIMIZED",
    0x08000: "LOGON_WINLOGON",
    0x10000: "LOGON_PKINIT",
    0x20000: "LOGON_NO_OPTIMIZED",
    0x40000: "LOGON_NO_ELEVATION",
    0x80000: "LOGON_MANAGED_SERVICE",
}

#: ``UserFlags`` bits that are a finding on the session they appear on.
LOGON_USER_FLAG_FINDINGS: dict[int, tuple[str, int]] = {
    0x0008: ("LOGON_USED_LM_PASSWORD: this session authenticated with the LM hash. LM "
             "is a DES construction over an upper-cased, seven-byte-split password and "
             "is crackable in minutes regardless of length — its presence on a modern "
             "host means either a deliberate downgrade or a very old client",
             int(Severity.HIGH)),
    0x0002: ("LOGON_NOENCRYPTION: the session key was not established, so anything "
             "relying on it for signing or sealing is unprotected",
             int(Severity.MEDIUM)),
    0x0001: ("LOGON_GUEST: this session authenticated as Guest — an unauthenticated "
             "principal holding a logon session", int(Severity.MEDIUM)),
    0x0004: ("LOGON_CACHED_ACCOUNT: authenticated against the cached verifier rather "
             "than a domain controller. Normal off-network, and also what an attacker "
             "sees succeed when they have isolated a host from its DC",
             int(Severity.INFORMATIONAL)),
}

#: LUIDs Windows reserves, from ntifs.h. **This is the one thing that can be said
#: about an unreadable session.**
#:
#: ``LsaGetLogonSessionData`` returns error 5 for these on an unelevated caller, so the
#: user, the logon type and the logon time are all unavailable — but the LUID itself is
#: a documented constant, so the principal is known from the number alone. Four of the
#: twelve opaque sessions on this host are named this way. The events say where the
#: attribution came from, because "SYSTEM, from the well-known LUID" and "SYSTEM,
#: because LSA said so" are different levels of evidence.
WELL_KNOWN_LUIDS: dict[int, tuple[str, str]] = {
    0x3E4: ("NETWORK SERVICE", "S-1-5-20"),
    0x3E5: ("LOCAL SERVICE", "S-1-5-19"),
    0x3E6: ("IUSR", "S-1-5-17"),
    0x3E7: ("SYSTEM", "S-1-5-18"),
}

#: ``WTS_CONNECTSTATE_CLASS``. Used only to describe a session's station; the state
#: itself is carried as text because it is a terminal-services concept with no OCSF
#: field, and inventing an enum id for it would be worse than the string.
WTS_STATE: dict[int, str] = {
    0: "Active",
    1: "Connected",
    2: "ConnectQuery",
    3: "Shadow",
    4: "Disconnected",
    5: "Idle",
    6: "Listen",
    7: "Reset",
    8: "Down",
    9: "Init",
}

#: OCSF ``auth_protocol_id``, for the two packages where the mapping is unambiguous.
#:
#: Windows reports ``AuthenticationPackage`` as a free string — measured ``CloudAP`` on
#: this host, and ``Negotiate``, ``NTLM``, ``Kerberos``, ``WDigest`` and ``Schannel``
#: elsewhere. Only NTLM and Kerberos have an OCSF enum member that means the same
#: thing. ``Negotiate`` in particular is *not* mappable: it is the package that chose
#: Kerberos or NTLM, and recording it as either would be a claim about which one won
#: that the field does not contain. Everything unmapped keeps the string in
#: ``auth_protocol`` and leaves ``auth_protocol_id`` absent, which reads as "not
#: classified" rather than as "unknown protocol".
#:
#: Class-level enum, so **not** checkable against the vendored index — that carries
#: only the seven base-event enums. Transcribed from OCSF's ``auth_protocol_id``.
AUTH_PACKAGE_PROTOCOL: dict[str, int] = {
    "ntlm": 1,
    "kerberos": 2,
}


# ── local account state ───────────────────────────────────────────────────────

#: Sentinel values ``NetUserEnum`` level 3 uses for "no such time".
#:
#: ``0xFFFFFFFF`` is ``TIMEQ_FOREVER`` — measured on ``acct_expires`` and
#: ``max_storage`` for every account on this host. ``0`` on ``last_logon`` and
#: ``last_logoff`` means the event has never happened. Neither is a timestamp, and
#: both would pass as one: 0 becomes 1970 and 4294967295 becomes 2106.
_NET_TIME_SENTINELS = frozenset({0, 0xFFFFFFFF})

#: ``NetUserModalsGet`` level 0/3 values that are a finding on their own, evaluated as
#: ``(field, predicate, description, severity)``.
#:
#: Measured on this host: ``min_passwd_len=0``, ``password_hist_len=0``,
#: ``max_passwd_age=3628800`` (42 days), ``lockout_threshold=10``,
#: ``force_logoff=4294967295`` (never). So two of these five fire here and three do
#: not — which is the point of writing them as predicates rather than as a static list
#: of "things wrong with Windows".
POLICY_FINDINGS: tuple[tuple[str, Any, str, int], ...] = (
    ("min_passwd_len", lambda v: v == 0,
     "minimum password length is 0, so an empty password is permitted by policy and "
     "an empty password authenticates", int(Severity.MEDIUM)),
    ("password_hist_len", lambda v: v == 0,
     "password history length is 0, so a forced password change can be satisfied by "
     "setting the same password again", int(Severity.LOW)),
    ("lockout_threshold", lambda v: v == 0,
     "account lockout is disabled, so an online password guess against a local "
     "account has unlimited attempts", int(Severity.MEDIUM)),
    ("max_passwd_age", lambda v: v in (0, 0xFFFFFFFF),
     "passwords never expire by policy, so a credential stolen once stays valid until "
     "somebody notices", int(Severity.LOW)),
    ("min_passwd_age", lambda v: v == 0,
     "minimum password age is 0, which combined with a history length lets a user "
     "cycle back to the original password immediately", int(Severity.INFORMATIONAL)),
)


# ── event map ─────────────────────────────────────────────────────────────────

_NTLM = "Microsoft-Windows-NTLM"
_TSLSM = "Microsoft-Windows-TerminalServices-LocalSessionManager"
_TSRCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
_RDPCORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS"
#: Plural "Profiles". Measured from the channel's OwningPublisher; the channel path
#: says "User Profile Service" and the provider says "User Profiles Service".
_UPS = "Microsoft-Windows-User Profiles Service"
_WINRM = "Microsoft-Windows-WinRM"
_HELLO = "Microsoft-Windows-HelloForBusiness"
_BIO = "Microsoft-Windows-Biometrics"
_AAD = "Microsoft-Windows-AAD"
_KERB = "Microsoft-Windows-Security-Kerberos"
_LSASRV = "LsaSrv"

#: ``(provider, event_id)`` → OCSF meaning, for the unelevated substitute channels.
#:
#: Provider-qualified because the ids collide: ``Microsoft-Windows-Winlogon`` and
#: ``Microsoft-Windows-User Profiles Service`` both write 1 and 2. Every provider
#: string here is checked against the channel's ``OwningPublisher`` at open by
#: :meth:`LocalAuthLogCollector.verify_provider_map`, because a typo in one of these
#: strings does not raise — it leaves a channel silently unmapped.
AUTH_EVENT_MAP: dict[tuple[str, int], _Mapped] = {
    # ── NTLM: the strongest unelevated authentication source on Windows ──
    # 4020 records an outbound NTLM authentication with the process that caused it.
    # Deliberately no status_id: the event records that NTLM was *used*, not whether
    # the far end accepted it. Claiming Success here would be a fabrication on every
    # failed authentication.
    (_NTLM, 4020): _Mapped(
        _AUTH, 1, "NTLM authentication used by a local process"),
    # ── RDP / Terminal Services session lifecycle ──
    (_TSLSM, 21): _Mapped(_AUTH, 1, "Session logon succeeded", status_id=_SUCCESS),
    # 22 is the shell starting inside a session that has already logged on. Mapping
    # it to Logon as well would double every RDP session in a logon count.
    (_TSLSM, 22): _Mapped(_AUTH, 99, "Remote Desktop shell started for a session"),
    (_TSLSM, 23): _Mapped(_AUTH, 2, "Session logoff succeeded", status_id=_SUCCESS),
    (_TSLSM, 24): _Mapped(_AUTH, 2, "Session disconnected", status_id=_SUCCESS),
    (_TSLSM, 25): _Mapped(_AUTH, 1, "Session reconnected", status_id=_SUCCESS,
                          severity_id=int(Severity.LOW)),
    # 39 names *which* session did the disconnecting, which is the one Terminal
    # Services event that can evidence a session takeover.
    (_TSLSM, 39): _Mapped(_AUTH, 2, "Session disconnected by another session",
                          status_id=_SUCCESS, severity_id=int(Severity.LOW)),
    (_TSLSM, 40): _Mapped(_AUTH, 2, "Session disconnected with a reason code",
                          status_id=_SUCCESS),
    (_TSLSM, 41): _Mapped(_AUTH, 99, "Session arbitration began"),
    (_TSLSM, 42): _Mapped(_AUTH, 99, "Session arbitration ended"),
    # 1149 is the RDP authentication itself, and it carries the source address. On
    # this host the channel exists and is empty (no inbound RDP has ever been
    # attempted), which is why it is mapped from documentation rather than from a
    # sample — noted so nobody mistakes it for verified-on-this-host.
    (_TSRCM, 1149): _Mapped(_AUTH, 1, "Remote Desktop user authentication succeeded",
                            status_id=_SUCCESS, severity_id=int(Severity.LOW)),
    (_RDPCORE, 131): _Mapped(_AUTH, 99, "Remote Desktop connection accepted"),
    (_RDPCORE, 140): _Mapped(_AUTH, 1, "Remote Desktop connection failed "
                                       "authentication", status_id=_FAILURE,
                             severity_id=int(Severity.LOW)),
    # ── profile load: a weak but real corroboration that a user session began ──
    # Category 3002 (Authentication) with activity 99, not 3004 Entity Management
    # activity 2. Three reasons, and the first is the one that matters:
    #
    # * 3004's activity 2 is named **Read** in the schema. "User profile load began"
    #   is not a read of an entity, and a rule looking for entity reads would match
    #   every interactive logon on the host.
    # * 3004 *requires* an `entity` attribute — a `managed_entity` object — and has no
    #   `user` attribute at all. These records carry a user SID and nothing that is a
    #   managed entity, so as 3004 they were invalid OCSF that nothing checks:
    #   `Event.build` routes a class-inappropriate attribute into `unmapped` rather
    #   than raising.
    # * A profile load is authentication-category corroboration that a session began.
    #   99 rather than 1 (Logon) is deliberate and is the same reasoning as TSLSM 22
    #   above: the logon is reported by the session collector and by 4624, and mapping
    #   the profile load to Logon as well would double every interactive session in a
    #   logon count. `activity_name` carries the real meaning.
    (_UPS, 1): _Mapped(_AUTH, 99, "User profile load began"),
    (_UPS, 2): _Mapped(_AUTH, 99, "User profile load finished"),
    (_UPS, 67): _Mapped(_AUTH, 99, "User profile loaded for a logon"),
    # ── WinRM: remote management, which is remote code execution ──
    (_WINRM, 161): _Mapped(_AUTH, 1, "WinRM authentication failed",
                           status_id=_FAILURE, severity_id=int(Severity.LOW)),
    (_WINRM, 142): _Mapped(_AUTH, 99, "WinRM operation failed"),
    # ── Windows Hello: carries the same NTSTATUS pair as 4625 ──
    (_HELLO, 5001): _Mapped(_AUTH, 1, "Windows Hello credential used",
                            status_id=_SUCCESS),
    (_HELLO, 5002): _Mapped(_AUTH, 99, "Windows Hello gesture collected"),
    (_HELLO, 7001): _Mapped(_AUTH, 1, "Windows Hello authentication failed",
                            status_id=_FAILURE, severity_id=int(Severity.LOW)),
    # ── biometric verification, per user SID ──
    (_BIO, 1605): _Mapped(_AUTH, 1, "Biometric identity verification started"),
    (_BIO, 1606): _Mapped(_AUTH, 1, "Biometric identity verified",
                          status_id=_SUCCESS),
    # ── Entra ID (Azure AD) token acquisition from this host ──
    (_AAD, 1025): _Mapped(_AUTH, 99, "Entra endpoint request failed"),
    (_AAD, 1097): _Mapped(_AUTH, 1, "Entra token renewal failed", status_id=_FAILURE,
                          severity_id=int(Severity.LOW)),
    (_AAD, 1098): _Mapped(_AUTH, 1, "Entra silent token acquisition failed",
                          status_id=_FAILURE),
    (_AAD, 1256): _Mapped(_AUTH, 99, "Entra operation failed"),
}

#: ``EventData`` keys these providers use, on top of the Security-channel names in
#: :data:`~ingest.collectors.windows_eventlog.DATA_MAP`.
#:
#: Merged over the inherited table rather than replacing it, because this collector
#: reads ``Security`` too and the inherited names are what map 4624.
AUTH_DATA_MAP: dict[str, str] = {
    **DATA_MAP,
    # NTLM 4020. `Username`/`DomainName` are the authenticating principal, and the
    # Target* fields are where it authenticated to.
    "Username": "user_name",
    "DomainName": "user_domain",
    "Hostname": "device_hostname",
    "TargetMachine": "dst_endpoint_hostname",
    "TargetDomain": "dst_endpoint_domain",
    "TargetService": "dst_endpoint_svc_name",
    "TargetIP": "dst_endpoint_ip",
    "TargetNetworkName": "dst_endpoint_domain",
    # Bare image names, not paths — `lsass`, measured. The override below moves a
    # value with no path separator out of the *_file_path field into the name field,
    # so a name is never stored as though it were a path.
    "ProcessPID": "actor_process_pid",
    # Terminal Services 21-25/39-42 (UserData, not EventData).
    "User": "user_name",
    "SessionID": "session_uid",
    "Address": "src_endpoint_ip",
    # Windows Hello 5001/7001 and Biometrics 1605/1606.
    "UserName": "user_name",
    "UserSid": "user_uid",
    "SID": "user_uid",
    "AuthenticationErrorStatus": "status_code",
    "AuthenticationErrorSubStatus": "status_detail",
    # WinRM.
    "authFailureMessage": "status_detail",
    "operationName": "api_operation",
    "errorCode": "status_code",
    "resourceUri": "url_string",
    # Entra.
    "Error": "status_code",
    "ErrorMessage": "status_detail",
    "EndpointUri": "url_string",
    "CorrelationID": "metadata_correlation_uid",
    "Method": "http_method",
}

#: Records that are read, counted, and deliberately not emitted, per provider.
#:
#: One entry, and it is 94% of its channel: ``TerminalServices-LocalSessionManager``
#: id 59 is an RPC entry trace (``RpcGetCurrentSessionCapabilities``) written every
#: time any process asks about session capabilities — 376 of the 400 most recent
#: records on this host. It names a caller image, which sounds useful until you notice
#: :mod:`ingest.collectors.process` already reports every process launch with its full
#: command line. Emitting it would make this collector's volume 16× larger and its
#: signal identical.
#:
#: The count appears in ``channel_report()`` as "filtered as known noise" and in
#: ``stats_extra()``. A filter that is not counted is indistinguishable from a channel
#: that has gone quiet, which is why it is counted.
NOISY_EVENTS: dict[tuple[str, int], str] = {
    (_TSLSM, 59): "RpcGetCurrentSessionCapabilities entry trace — process launches "
                  "are collected properly by the process collector",
    (_TSLSM, 32): "RDS plugin message",
    (_TSLSM, 54): "RDS internal state message",
}


def local_auth_channels() -> list[Channel]:
    """Security first, then every channel that carries authentication unelevated.

    ``Security`` is ``critical`` and the rest are not — losing the real source is a
    fault, whereas losing a fragmentary substitute is a degradation. Ordered by how
    much authentication each one actually carries, which is not the order anyone would
    guess: NTLM is second because event 4020 is the only unelevated source on Windows
    that attributes credential use to a process.
    """
    return [
        Channel(SECURITY_CHANNEL, _AUTH, critical=True),
        Channel("Microsoft-Windows-NTLM/Operational", _AUTH),
        Channel("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                _AUTH),
        Channel(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            _AUTH),
        Channel("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", _AUTH),
        Channel("Microsoft-Windows-HelloForBusiness/Operational", _AUTH),
        Channel("Microsoft-Windows-Biometrics/Operational", _AUTH),
        Channel("Microsoft-Windows-AAD/Operational", _AUTH),
        Channel("Microsoft-Windows-WinRM/Operational", _AUTH),
        Channel("Microsoft-Windows-User Profile Service/Operational", _AUTH),
        # Both of these are readable and disabled on this host. Included so the
        # channel report names them and the operator has something to enable, rather
        # than their absence being invisible.
        Channel("Microsoft-Windows-Kerberos/Operational", _AUTH),
        Channel("Microsoft-Windows-LSA/Operational", _AUTH),
    ]


#: Channel path → the provider that owns it, for the four where the provider is not
#: derivable from the path. Used only to make :meth:`verify_provider_map`'s failure
#: message say what the right answer is instead of only that the guess was wrong.
KNOWN_PUBLISHERS: dict[str, str] = {
    "Microsoft-Windows-User Profile Service/Operational": _UPS,
    "Microsoft-Windows-Kerberos/Operational": _KERB,
    "Microsoft-Windows-LSA/Operational": _LSASRV,
    "Microsoft-Windows-SmbClient/Security": "Microsoft-Windows-SMBClient",
}


class LocalAuthLogCollector(WindowsEventLogCollector):
    """Authentication from the Security channel, and from what is left without it."""

    name = "local_auth_log"
    cadence_seconds = 20.0
    #: Not critical, even though authentication is. The collector that owns the
    #: criticality of ``Security`` is ``windows_eventlog``, which also reads it; two
    #: collectors both declaring the same channel critical would raise the same fault
    #: twice and make it look like two problems.
    critical = False
    description = (
        "authentication: Security channel plus the unelevated-readable substitutes — "
        "NTLM 4020 with process attribution, RDP session lifecycle, Windows Hello "
        "failure codes, biometric verification, Entra token acquisition"
    )
    event_map = EVENT_MAP
    event_map_by_provider = AUTH_EVENT_MAP
    data_map = AUTH_DATA_MAP

    def __init__(self, pipeline: Any, **kwargs: Any) -> None:
        kwargs.setdefault("channels", local_auth_channels())
        super().__init__(pipeline, **kwargs)
        #: Per-(provider, id) counts of records dropped by :data:`NOISY_EVENTS`.
        self.noise_filtered: dict[tuple[str, int], int] = {}
        #: Populated by :meth:`verify_provider_map` at open.
        self.provider_mismatches: list[str] = []
        self.status_decoded = 0
        self.status_unknown: dict[int, int] = {}
        self.ntlm_v1_seen = 0
        self.cleartext_logons = 0
        self.new_credentials_logons = 0

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        base = super().probe()
        if not base:
            return base

        notes: list[str] = []
        security = next((c for c in self.channels if c.path == SECURITY_CHANNEL), None)
        if security is not None and security.why_unavailable:
            notes.append(
                "the Security channel — the only source of 4624/4625/4648/4672/4720 "
                f"and therefore of authoritative identity telemetry — is not readable: "
                f"{security.why_unavailable} Everything this collector reports about "
                "logons is inferred from fragmentary substitute channels until that is "
                "fixed. See local_auth.SECURITY_SETUP."
            )
        elif not is_admin():
            notes.append(
                "the Security channel is readable without elevation, which means this "
                "account is in Event Log Readers — but 4688 process creation and the "
                "Kerberos subcategories are off by default, so check auditpol before "
                "assuming they are collected. See local_auth.SECURITY_SETUP step 3."
            )

        disabled = [c.path for c in self.channels if self._channel_disabled(c.path)]
        if disabled:
            notes.append(
                "readable but disabled, so they will return zero records forever: "
                + ", ".join(disabled)
                + ". See local_auth.AUTH_CHANNEL_SETUP."
            )

        notes.append(
            "these channels carry no logon *failure* for local and network accounts. "
            "NTLM 4020 records usage without an outcome, and Windows Hello 7001 covers "
            "only Hello credentials — so a password spray against a local account is "
            "invisible here. LocalAccountCollector's bad_pw_count delta is the "
            "substitute, and it is a per-interval count rather than per attempt."
        )
        return available(" ".join(notes))

    def _channel_disabled(self, path: str) -> bool:
        """True only when the enabled flag says so — never on an error.

        A channel whose configuration cannot be read is not reported as disabled.
        "Disabled, here is the command to fix it" and "I could not tell" call for
        different responses from whoever reads the report, and conflating them sends
        someone to run a command that may already have been run.
        """
        try:
            import win32evtlog as w

            cfg = w.EvtOpenChannelConfig(path)
            value = w.EvtGetChannelConfigProperty(cfg, w.EvtChannelConfigEnabled)
        except Exception:
            return False
        if isinstance(value, tuple):
            value = value[0]
        return value is False

    # ── provider verification ──────────────────────────────────────────────

    def verify_provider_map(self) -> list[str]:
        """Check every provider named in the event map against the real channels.

        This exists because of a specific, silent failure. The map is keyed by
        ``(provider, event_id)``, and four of these channels are written by a provider
        whose name is not the channel path: ``Microsoft-Windows-User Profile
        Service/Operational`` is written by ``...User Profile*s* Service``. A typo, or
        the obvious assumption that the two match, produces no exception and no warning
        — the channel is read, the records arrive, and every one of them falls through
        to the unqualified table and gets the channel's default class. The counters all
        look healthy.

        So each channel's ``OwningPublisher`` is read from its configuration and
        compared with what the map claims. Returns the mismatches; the caller decides
        whether that is fatal.
        """
        try:
            import win32evtlog as w
        except Exception as exc:
            return [f"cannot verify providers: pywin32 unavailable ({exc})"]

        real: dict[str, str] = {}
        for ch in self.channels:
            try:
                cfg = w.EvtOpenChannelConfig(ch.path)
                value = w.EvtGetChannelConfigProperty(
                    cfg, w.EvtChannelConfigOwningPublisher
                )
            except Exception:
                continue
            if isinstance(value, tuple):
                value = value[0]
            if value:
                real[ch.path] = str(value)

        owned = set(real.values())
        problems: list[str] = []
        for provider in sorted({p for p, _ in self.event_map_by_provider}):
            if provider in owned:
                continue
            # Only a problem if a configured channel *should* have supplied it. A
            # provider for a channel this host does not have is a gap, not a bug, and
            # the channel probe already reports that.
            expected = [p for p, prov in KNOWN_PUBLISHERS.items() if prov == provider]
            if expected and any(p not in real for p in expected):
                continue
            if not real:
                continue
            problems.append(
                f"the event map names provider {provider!r}, which owns none of the "
                f"channels this collector reads. Its records will fall through to the "
                f"unqualified map and take the channel default class. Owning "
                f"publishers actually present: {sorted(owned)}"
            )
        self.provider_mismatches = problems
        return problems

    async def open(self) -> None:
        await super().open()
        self.verify_provider_map()

    # ── mapping ────────────────────────────────────────────────────────────

    def _to_event(self, ch: Channel, xml: str) -> dict[str, Any] | None:
        payload = super()._to_event(ch, xml)
        if payload is None:  # pragma: no cover - the base never does this
            return None
        unmapped = payload["unmapped"]
        provider = payload.get("metadata_log_provider") or ""
        eid = unmapped["event_id"]
        data: dict[str, str] = unmapped.get("event_data") or {}

        key = (provider, eid)
        if key in NOISY_EVENTS:
            self.noise_filtered[key] = self.noise_filtered.get(key, 0) + 1
            return None

        notes: list[str] = []
        labels = payload.setdefault("metadata_labels", [])
        labels.append("identity")
        if ch.path != SECURITY_CHANNEL:
            # The label is how a coverage report distinguishes observed identity
            # telemetry from inferred identity telemetry. Without it, ten thousand
            # substitute events read as ten thousand logon records.
            labels.append("substitute_for:4624/4625/4648")
            notes.append(
                f"read from {ch.path}, not from the Security channel. This is a "
                "partial substitute for Windows security auditing: it does not carry a "
                "logon id that joins to other events, an impersonation level, or the "
                "privileges granted to the session."
            )

        self._fix_accounts(payload)
        self._fix_process(payload)
        self._scrub_placeholders(payload, notes)
        self._decode_status(payload, eid, notes)
        self._note_logon_type(payload, notes)
        if provider == _NTLM:
            self._note_ntlm(payload, data, notes)
        if payload.get("activity_id") == 99 and not payload.get("activity_name"):
            # The base copies `message` from the map's label. OCSF requires
            # activity_name whenever activity_id is 99, and the schema now rejects the
            # event without it, so the label is promoted rather than the record lost.
            payload["activity_name"] = payload.get("message") or f"event {eid}"

        if notes:
            payload["soc_notes"] = list(payload.get("soc_notes") or []) + notes
        return payload

    @staticmethod
    def _fix_accounts(payload: dict[str, Any]) -> None:
        """Split ``DOMAIN\\user`` and ``user@domain`` into their two fields.

        Terminal Services writes ``EVILHYBRID\\Niklaus Mikaelson`` into one field and
        NTLM writes a bare ``aerialsensing`` into the same-named field, so this cannot
        be done per provider without getting one of them wrong. Splitting on the
        separator is correct for both: a bare name has none and passes through.

        Left unsplit, every entity-resolution join in Phase 3 sees
        ``EVILHYBRID\\Niklaus Mikaelson`` and ``Niklaus Mikaelson`` as two users.
        """
        for name_field, domain_field in (
            ("user_name", "user_domain"),
            ("actor_user_name", "actor_user_domain"),
        ):
            value = payload.get(name_field)
            if not isinstance(value, str) or not value:
                continue
            if "\\" in value:
                domain, _, name = value.rpartition("\\")
                if name:
                    payload[name_field] = name
                    payload.setdefault(domain_field, domain)
            elif "@" in value and value.count("@") == 1:
                name, _, domain = value.partition("@")
                if name and domain:
                    # The UPN is kept whole as well: it is the identifier the cloud
                    # side of a correlation joins on, and reconstructing it from two
                    # fields guesses at a format that is not always name@domain.
                    payload.setdefault(
                        "user_email" if name_field == "user_name"
                        else "actor_user_email", value)
                    payload[name_field] = name
                    payload.setdefault(domain_field, domain)

    @staticmethod
    def _fix_process(payload: dict[str, Any]) -> None:
        """Move a bare image name out of a path field, and coerce a hex PID.

        NTLM 4020 writes ``lsass`` where the Security channel writes
        ``C:\\Windows\\System32\\lsass.exe``, and both land in ``ProcessName``. A bare
        name stored in ``actor_process_file_path`` is a false statement about a field
        whose whole purpose is to be a path — a rule looking for execution from
        ``\\Temp\\`` would silently never match it, and one comparing paths across
        events would treat the two as different processes.
        """
        for path_field, name_field in (
            ("actor_process_file_path", "actor_process_name"),
            ("process_file_path", "process_name"),
        ):
            value = payload.get(path_field)
            if isinstance(value, str) and value and "\\" not in value and "/" not in value:
                payload.pop(path_field)
                payload.setdefault(name_field, value)
        for pid_field in ("actor_process_pid", "process_pid", "process_parent_pid"):
            value = payload.get(pid_field)
            if isinstance(value, str):
                try:
                    payload[pid_field] = (
                        int(value, 16) if value.lower().startswith("0x")
                        else int(value, 10)
                    )
                except ValueError:
                    payload.pop(pid_field)

    def _scrub_placeholders(self, payload: dict[str, Any], notes: list[str]) -> None:
        """Remove the literal strings Windows uses to mean "no address".

        ``Null`` from NTLM's ``TargetIP`` and ``LOCAL`` from Terminal Services'
        ``Address`` are both real measured values and neither is empty, so the base
        class's ``-``/empty check does not catch them. Reaching an IP field, either one
        fails pydantic validation and quarantines the whole record — an NTLM
        authentication with process attribution lost to the word "Null".

        ``LOCAL`` is worth a note rather than a silent drop: it is the positive
        statement that the session was at the console, which is the opposite of a
        missing value and is exactly what distinguishes a console logon from RDP.
        """
        for field in ("src_endpoint_ip", "dst_endpoint_ip", "device_ip"):
            value = payload.get(field)
            if not isinstance(value, str):
                continue
            if value.strip().lower() in _PLACEHOLDERS:
                if value.strip().lower() == "local":
                    payload["is_remote"] = False
                    notes.append(
                        "the source address is the literal 'LOCAL', which Terminal "
                        "Services writes for a console session — this is a statement "
                        "that the session was local, not a missing value"
                    )
                payload.pop(field)
        for field in ("src_endpoint_hostname", "dst_endpoint_hostname",
                      "dst_endpoint_domain", "user_domain"):
            value = payload.get(field)
            if isinstance(value, str) and value.strip().lower() in _PLACEHOLDERS:
                payload.pop(field)

    def _decode_status(self, payload: dict[str, Any], eid: int,
                       notes: list[str]) -> None:
        """Turn a raw status into a name, a meaning, and sometimes a severity."""
        kerberos = eid in KERBEROS_STATUS_EVENTS
        for field, label in (("status_code", "status"),
                             ("status_detail", "sub_status")):
            raw = payload.get(field)
            code = parse_status_code(raw)
            if code is None:
                continue
            payload["unmapped"][f"auth_{label}_hex"] = f"0x{code:08X}"
            decoded = decode_status(code, kerberos=kerberos)
            if decoded is None:
                self.status_unknown[code] = self.status_unknown.get(code, 0) + 1
                payload["unmapped"][f"auth_{label}_name"] = ""
                notes.append(
                    f"{label} 0x{code:08X} is not in the "
                    f"{'Kerberos' if kerberos else 'NTSTATUS'} table — stored as a "
                    "number rather than given a guessed name"
                )
                continue
            mnemonic, meaning, floor = decoded
            self.status_decoded += 1
            payload["unmapped"][f"auth_{label}_name"] = mnemonic
            payload["unmapped"][f"auth_{label}_meaning"] = meaning
            notes.append(f"{label} {mnemonic}: {meaning}")
            if floor is not None:
                _raise_severity(payload, floor)
            # A generic failure whose sub-status was not audited is worth saying out
            # loud, because it is the difference between "an authentication failed"
            # and "an authentication failed and we know why".
            if code == 0xC000006D and not parse_status_code(
                    payload.get("status_detail")):
                notes.append(
                    "STATUS_LOGON_FAILURE with no sub-status: the reason for this "
                    "failure was not recorded, so enumeration and spraying cannot be "
                    "told apart on this record"
                )

    def _note_logon_type(self, payload: dict[str, Any], notes: list[str]) -> None:
        raw = payload.get("logon_type_id")
        if not isinstance(raw, int):
            return
        payload.setdefault("logon_type", LOGON_TYPES.get(raw, str(raw)))
        if raw == 8:
            payload["is_cleartext"] = True
            self.cleartext_logons += 1
        if raw == 9:
            self.new_credentials_logons += 1
        if raw in (3, 8, 10, 12):
            payload.setdefault("is_remote", True)
        meaning = LOGON_TYPE_MEANING.get(raw)
        if meaning is None:
            notes.append(
                f"logon type {raw} is not a documented Windows type — reported as-is"
            )
            return
        text, floor = meaning
        notes.append(f"logon type {raw} ({LOGON_TYPES.get(raw, raw)}): {text}")
        if floor is not None:
            _raise_severity(payload, floor)

    def _note_ntlm(self, payload: dict[str, Any], data: dict[str, str],
                   notes: list[str]) -> None:
        """NTLM 4020: the version and the relay-relevant protections.

        ``NtlmUsageId``/``NtlmUsageReason`` are carried through untouched. The numeric
        id is preserved because it is stable and groupable; the reason string is the
        provider's own rendered text, which comes from a localised message table, so
        it is evidence for a human and not something a rule should match on. There is
        no authoritative public table for the id values, and inventing one would be
        worse than carrying the number.
        """
        payload.setdefault("auth_protocol", "NTLM")
        payload.setdefault("auth_protocol_id", 1)
        version = (data.get("NtlmVersion") or "").strip()
        if version:
            payload["unmapped"]["ntlm_version"] = version
        if version.upper() in ("NTLMV1", "NTLM V1", "NTLM1"):
            self.ntlm_v1_seen += 1
            _raise_severity(payload, int(Severity.HIGH))
            notes.append(
                "NTLMv1: the response is computed with DES and can be cracked to the "
                "NT hash offline in hours, or relayed. On a modern host there is no "
                "legitimate reason for it, and a downgrade to it is an attack in "
                "itself"
            )
        mic = (data.get("Mic Status") or data.get("MicStatus") or "").strip()
        binding = (data.get("ChannelBindingStatus") or "").strip()
        if mic and mic.lower() not in ("protected",):
            _raise_severity(payload, int(Severity.MEDIUM))
            notes.append(
                f"NTLM message integrity code status is {mic!r}: without a MIC the "
                "authentication can be relayed to another service with the signing "
                "requirement stripped"
            )
        if binding and binding.lower() in ("unsupported", "unprotected", "absent"):
            notes.append(
                f"channel binding {binding!r}: the authentication is not bound to the "
                "TLS channel it arrived on, which is the precondition for relaying it"
            )
        if (data.get("SingleSignOn") or "").strip().lower() == "supplied credentials":
            notes.append(
                "the credential was supplied explicitly rather than taken from the "
                "logon session — the local equivalent of 4648, and worth reading "
                "alongside the target"
            )

    # ── reporting ──────────────────────────────────────────────────────────

    def stats_extra(self) -> dict[str, Any]:
        return {
            "security_channel_readable": not any(
                c.path == SECURITY_CHANNEL and c.why_unavailable
                for c in self.channels
            ),
            "channels_readable": sum(1 for c in self.channels
                                     if not c.why_unavailable),
            "channels_total": len(self.channels),
            "channels_disabled": [c.path for c in self.channels
                                  if self._channel_disabled(c.path)],
            "records_filtered_as_noise": sum(self.noise_filtered.values()),
            "noise_filtered_by_event": {f"{p}/{i}": n
                                        for (p, i), n in self.noise_filtered.items()},
            "status_codes_decoded": self.status_decoded,
            "status_codes_unknown": {f"0x{c:08X}": n
                                     for c, n in self.status_unknown.items()},
            "ntlm_v1_authentications": self.ntlm_v1_seen,
            "cleartext_logons": self.cleartext_logons,
            "new_credentials_logons": self.new_credentials_logons,
            "provider_map_mismatches": self.provider_mismatches,
        }


def _raise_severity(payload: dict[str, Any], floor: int) -> None:
    """Raise a severity, never lower it.

    Several notes can apply to one record — an NTLMv1 authentication with no MIC by
    way of a type 8 logon — and the highest must win. A plain assignment would let the
    last rule evaluated silently downgrade the finding of the first.
    """
    current = payload.get("severity_id") or 0
    if floor > current:
        payload["severity_id"] = floor


# ═══════════════════════════════════════════════════════════════════════════════
# LSA logon sessions — the state substitute for 4624/4634
# ═══════════════════════════════════════════════════════════════════════════════


class LogonSessionCollector(PullCollector):
    """The live LSA logon-session table, diffed into logon and logoff events.

    ``LsaEnumerateLogonSessions`` plus ``LsaGetLogonSessionData`` is the only way to
    see who is logged on to a Windows host without reading the Security channel. What
    it gives that 4624 does not is that it is *state*: it answers "who is logged on
    right now" directly, so a collector that starts an hour into an intrusion still
    sees the intruder's session. What 4624 gives that it does not is the source
    address, the logon process, and the failures — this table has no concept of an
    authentication that did not succeed.

    **Two of fourteen sessions are readable on this host.** That is not a bug to be
    worked around, it is the shape of the source, and every design decision here
    follows from it:

    * The *enumeration* always succeeds, so the LUID set — and therefore the session
      count, and therefore appearance and disappearance — is fully observable even when
      the content is not. A session that appears and cannot be read still produces a
      logon event, marked ``opaque_session``, with an honest note that the user and the
      logon time are unknown rather than a fabricated blank.
    * Four of the twelve opaque LUIDs are Windows' documented reserved values
      (:data:`WELL_KNOWN_LUIDS`), so the principal is recoverable from the number
      alone. Those events say the attribution came from the LUID constant, because that
      is weaker evidence than LSA answering.
    * A session that becomes readable *later* — the collector is elevated, or the
      session's own process opens it — emits activity 99 ``Logon session attributed``
      rather than a second Logon. Recording a real Logon there would double-count a
      session that was already counted when it was opaque, and a logon count that goes
      up because visibility improved is worse than no logon count.
    * Any change in the readable-to-total ratio emits a 5017 immediately, because that
      ratio *is* the coverage figure and a silent change in it is a silent change in
      how much of this host's identity activity is being seen.

    Class choice. Logon, logoff and attribution are 3002 Authentication — they are
    events about an authentication's lifecycle. The table state itself is 5017
    ``session_query``, a Discovery class, because a snapshot of who is logged on is not
    a logon. The two are kept apart so that a rule counting logons never counts a
    heartbeat. 5017 carries ``session`` and ``query_result_id`` but has no ``user``
    attribute, so the principal on an inventory event goes to ``actor.user`` — which is
    an attribute 5017 does have — and the logon type and authentication package, which
    5017 has no home for at all, go to ``unmapped``. Logon type belongs on the 3002
    events and is properly mapped there; the inventory answers "what sessions exist",
    not "how did they authenticate".

    ``session_uid`` is emitted as lower-case hex (``0x3e7``), **not** as the decimal
    LUID that LSA returns. That is deliberate and it is the difference between this
    collector's events joining to the Security channel's and not: ``windows_eventlog``
    keeps ``TargetLogonId``/``SubjectLogonId`` as the raw text Windows writes, which is
    hex, and a decimal ``999`` would never match a ``0x3e7``. The decimal form is kept
    alongside in ``session_uid_alt`` so a join against anything reading LSA directly
    also works.
    """

    name = "logon_sessions"
    #: Polled often, because the gap between two polls is the window in which a whole
    #: logon-and-logoff can happen unseen. 30 s is a compromise: the enumeration plus
    #: fourteen read attempts measures in single-digit milliseconds, so the cost is
    #: negligible, and the residual blindness is reported rather than hidden.
    cadence_seconds = 30.0
    #: Silence is normal for hours. See :attr:`Collector.health_cadence_seconds`.
    #: 7200 is two heartbeats, so one missed hour is not a fault.
    health_cadence_seconds = 7200.0
    #: Not critical. This is a *substitute* for a Security channel that cannot be read,
    #: and it is measurably partial; raising a critical fault when a known-degraded
    #: substitute stops would report the loss of coverage that was never there.
    critical = False
    description = (
        "LSA logon-session table, diffed — logon, logoff and session inventory "
        "without the Security channel"
    )

    #: How often the whole table is restated even when nothing has changed. This is
    #: what gives the health monitor something to judge silence against: for this
    #: collector absence of change is normal, so absence of events cannot mean death.
    heartbeat_seconds = 3600.0

    def __init__(
        self,
        pipeline: Any,
        *,
        heartbeat_seconds: float | None = None,
        emit_baseline: bool = True,
        emit_session_inventory: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(pipeline, **kwargs)
        if heartbeat_seconds is not None:
            self.heartbeat_seconds = float(heartbeat_seconds)
        #: Emit the sessions already present at start as logons, with their real logon
        #: times and a ``baseline_snapshot`` label. Same trade-off as the process
        #: collector's baseline: without it an investigation that starts after the
        #: collector has no idea who was already logged on, and a session that predates
        #: CYPHRA is the most likely place for something that was there first.
        self.emit_baseline = emit_baseline
        #: Emit one 5017 per readable session on each heartbeat, in addition to the
        #: aggregate. Off makes the heartbeat a single event; on makes each session
        #: individually queryable without unpacking a list.
        self.emit_session_inventory = emit_session_inventory

        #: ``str(luid)`` → the normalised record. Decimal, because that is what LSA
        #: returns and the diff key should be the source's own identity; the *emitted*
        #: ``session_uid`` is hex for the reason in the class docstring.
        self._readable: dict[str, dict[str, Any]] = {}
        #: ``str(luid)`` → ``{"reason": str, "first_seen": float, "_uidq": str}`` for a
        #: session that enumerated and could not be read.
        self._opaque: dict[str, dict[str, Any]] = {}
        self._first_poll = True
        self._last_heartbeat = 0.0
        self._last_ratio: tuple[int, int] | None = None
        self._poll_seconds = 0.0
        self._poll_seconds_worst = 0.0
        self._first_poll_seconds = 0.0

        # Counters that make this collector's own blindness measurable rather than
        # assumed. Every one of them is reported in stats_extra.
        self.logons = 0
        self.logoffs = 0
        self.opaque_logons = 0
        self.attributions = 0
        self.deattributions = 0
        self.baseline_emitted = 0
        self.heartbeats = 0
        self.ratio_changes = 0
        self.inventory_emitted = 0
        self.enumerate_failures = 0
        self.read_denied = 0
        self.read_failed = 0
        self.well_known_attributed = 0
        self.time_sentinels_rejected = 0
        self.station_lookup_failures = 0
        self.sid_unresolved = 0

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        """Measure the readable ratio live and report it as the limitation.

        Not "LSA is available". The number that decides whether this source is worth
        anything is how many of the host's sessions it can actually describe, and that
        is knowable in one call at probe time. Reporting availability without it would
        put a green source on the board for a collector that can see 14% of the thing
        it claims to cover.
        """
        if not is_windows():
            return unavailable(
                "the LSA logon-session table is a Windows API; there is no equivalent "
                "on this platform",
                fixable_by_user=False,
            )
        try:
            import win32security
        except Exception as exc:
            return unavailable(
                f"pywin32 is not importable ({exc}); pip install pywin32. Without it "
                "there is no logon-session telemetry on this host at all unless the "
                "Security channel is readable."
            )
        try:
            luids = win32security.LsaEnumerateLogonSessions()
        except Exception as exc:
            return unavailable(
                f"LsaEnumerateLogonSessions failed ({type(exc).__name__}: {exc}), so "
                "not even the session count is observable",
                fixable_by_user=False,
            )

        total = len(luids)
        readable = 0
        opaque_luids: list[int] = []
        for luid in luids:
            try:
                win32security.LsaGetLogonSessionData(luid)
            except Exception:
                opaque_luids.append(int(luid))
                continue
            readable += 1
        opaque = len(opaque_luids)

        limits: list[str] = []
        if opaque:
            named = sum(1 for luid in opaque_luids if luid in WELL_KNOWN_LUIDS)
            pct = 100.0 * opaque / total if total else 0.0
            limits.append(
                f"LsaGetLogonSessionData succeeds on {readable} of {total} logon "
                f"sessions ({pct:.0f}% of this host's sessions are opaque). Those "
                "sessions still produce logon and logoff events — the enumeration sees "
                "them — but with no user, no logon type and no logon time. "
                f"{named} of the {opaque} are recoverable from their well-known LUID. "
                "A SYSTEM-level attacker logon would be in the opaque set. "
                + LSA_SESSION_SETUP
            )
        else:
            limits.append(
                f"all {total} logon sessions are readable, which means this process is "
                "elevated or running as SYSTEM. This source is still a substitute: it "
                "has no concept of a failed authentication and no source address, so "
                "4625 and the origin of a network logon remain invisible without the "
                "Security channel."
            )
        limits.append(
            f"logons are polled, so the blind window is the cadence "
            f"({self.cadence_seconds:g}s) plus the poll duration — a session that opens "
            "and closes inside it produces no logon and no logoff, not a delayed one. "
            "The measured figure is in blind_window_seconds."
        )
        if not is_admin():
            limits.append(
                "not elevated, so the ratio above is expected to stay where it is; it "
                "is re-measured on every poll and any change emits a 5017."
            )
        return available(f"{total} logon sessions visible. " + "\n  ".join(limits))

    # ── the blind window ───────────────────────────────────────────────────

    @property
    def blind_window_seconds(self) -> float:
        """How long a logon session can exist and never be observed. **Measured.**

        The cadence plus the poll duration, for the reason spelled out at length in
        :attr:`ProcessCollector.blind_window_seconds`: :meth:`Collector.run` sleeps the
        cadence *after* the cycle returns, so the interval between two poll starts is
        the cadence plus however long the table read took.
        """
        return self.cadence_seconds + self._poll_seconds

    @property
    def blind_window_seconds_worst(self) -> float:
        """The same figure from the slowest steady-state poll. First poll excluded."""
        return self.cadence_seconds + self._poll_seconds_worst

    # ── polling ────────────────────────────────────────────────────────────

    async def poll(self) -> list[dict[str, Any]]:
        started_at = self.clock()
        now = started_at
        try:
            readable, opaque, stations = self._read_table(now)
        except Exception as exc:
            # Enumeration failing is a coverage event in its own right, not just an
            # exception to count: the collector has gone from partial sight to none.
            self.enumerate_failures += 1
            raise RuntimeError(
                f"LsaEnumerateLogonSessions failed: {type(exc).__name__}: {exc}"
            ) from exc

        payloads: list[dict[str, Any]] = []
        total = len(readable) + len(opaque)

        if self._first_poll:
            self._first_poll = False
            if self.emit_baseline:
                for rec in readable.values():
                    payload = self._logon_event(rec, stations, now)
                    payload["metadata_labels"].append("baseline_snapshot")
                    payload.setdefault("soc_notes", []).append(
                        "baseline inventory: this session was already open when the "
                        "collector started, so the logon was not observed — the time is "
                        "the real LogonTime from LSA, not an observation time"
                    )
                    payloads.append(payload)
                    self.baseline_emitted += 1
                # Opaque sessions get no baseline logon event. There is no user, no
                # logon type and no logon time to put on one, so it would be a record
                # asserting only that a session with a number existed — which the
                # aggregate below already says, with the count and the LUID digest, in
                # one event instead of twelve.
            payloads.append(self._table_event(
                readable, opaque, stations, now,
                reason="baseline: the logon-session table as found at startup",
                labels=["baseline_snapshot"],
            ))
            self._last_heartbeat = now
            self._last_ratio = (len(readable), total)
        else:
            payloads.extend(self._diff(readable, opaque, stations, now))

        ratio = (len(readable), total)
        if self._last_ratio is not None and ratio != self._last_ratio:
            was_r, was_t = self._last_ratio
            self.ratio_changes += 1
            payloads.append(self._table_event(
                readable, opaque, stations, now,
                reason=(
                    f"readable-session ratio changed from {was_r}/{was_t} to "
                    f"{ratio[0]}/{ratio[1]}. This ratio is the coverage figure for "
                    "identity telemetry on this host, so a change in it is a change in "
                    "how much of the host's logon activity is being seen — not a change "
                    "in the host's activity"
                ),
                labels=["coverage_change"],
                # No metadata_uid: the identity of this event is the moment the ratio
                # moved, which the pipeline's non-exact identity already expresses. An
                # exact uid built from the ratio would dedup away a genuine second
                # change back to a previous value.
                exact_uid=False,
                severity_id=int(Severity.LOW),
            ))
        self._last_ratio = ratio

        if now - self._last_heartbeat >= self.heartbeat_seconds:
            self._last_heartbeat = now
            self.heartbeats += 1
            payloads.append(self._table_event(
                readable, opaque, stations, now,
                reason=(
                    "periodic state-observed heartbeat. Absence of change is normal for "
                    "this collector, so this event is what lets silence be judged "
                    "against something"
                ),
                labels=["heartbeat"],
            ))
            if self.emit_session_inventory:
                for rec in readable.values():
                    payloads.append(self._session_inventory(rec, stations, now))
                    self.inventory_emitted += 1

        self._readable = readable
        self._opaque = opaque

        elapsed = self.clock() - started_at
        self._poll_seconds = elapsed
        if self._first_poll_seconds == 0.0:
            self._first_poll_seconds = elapsed
        elif elapsed > self._poll_seconds_worst:
            self._poll_seconds_worst = elapsed
        return payloads

    # ── reading the table ──────────────────────────────────────────────────

    def _read_table(
        self, now: float
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]],
               dict[int, dict[str, Any]]]:
        """One enumeration, one read attempt each, one WTS station list.

        Every pywin32 object is converted here and nowhere else. That is not tidiness:
        ``PySID`` does not ``str()`` to a SID string (it renders as
        ``PySID:S-1-5-…``), ``KickOffTime`` is a naive year-9999 datetime whose
        ``.timestamp()`` raises ``OSError``, and ``PasswordLastSet`` is a tz-aware
        year-1601 datetime that converts cleanly to a negative epoch the event model
        then rejects. Each of those is a different failure mode and each one is handled
        once, here, rather than at every use site.
        """
        import win32security

        luids = win32security.LsaEnumerateLogonSessions()
        stations = self._read_stations()

        readable: dict[str, dict[str, Any]] = {}
        opaque: dict[str, dict[str, Any]] = {}
        for luid in luids:
            luid_i = int(luid)
            key = str(luid_i)
            try:
                data = win32security.LsaGetLogonSessionData(luid)
            except Exception as exc:
                code = getattr(exc, "winerror", None)
                if code == 5:
                    self.read_denied += 1
                    reason = ("access denied (error 5): this process does not own the "
                              "session and is not elevated")
                else:
                    self.read_failed += 1
                    reason = f"{type(exc).__name__}: {exc}"
                prior = self._opaque.get(key)
                opaque[key] = {
                    "luid": luid_i,
                    "reason": reason,
                    "first_seen": prior["first_seen"] if prior else now,
                    "_uidq": prior["_uidq"] if prior else f"seen{now:.3f}",
                }
                continue
            readable[key] = self._normalise(luid_i, data)
        return readable, opaque, stations

    def _read_stations(self) -> dict[int, dict[str, Any]]:
        """Session id → WTS station name and connect state.

        ``WTSEnumerateSessions`` needs no elevation and no info-class constants — the
        enumeration itself returns ``SessionId``, ``WinStationName`` and ``State``,
        which is everything ``session.terminal`` wants. Measured on this host:
        ``{0: Services/Disconnected, 1: Console/Active}``.

        A failure here is not a failure of the collector. The station name is a nicety;
        losing it costs a field, not a session.
        """
        try:
            import win32ts

            out: dict[int, dict[str, Any]] = {}
            for s in win32ts.WTSEnumerateSessions():
                sid = s.get("SessionId")
                if sid is None:
                    continue
                state = s.get("State")
                out[int(sid)] = {
                    "name": (s.get("WinStationName") or "").strip(),
                    "state": WTS_STATE.get(int(state), str(state))
                    if state is not None else "",
                }
            return out
        except Exception:
            self.station_lookup_failures += 1
            return {}

    def _normalise(self, luid: int, data: dict[str, Any]) -> dict[str, Any]:
        """One LSA session, converted to plain Python and nothing else."""
        import win32security

        sid_str = ""
        rid: int | None = None
        sid = data.get("Sid")
        if sid is not None:
            try:
                sid_str = win32security.ConvertSidToStringSid(sid)
                rid = int(sid_str.rsplit("-", 1)[1])
            except Exception:
                self.sid_unresolved += 1
                sid_str = ""
                rid = None

        logon_time = self._epoch(data.get("LogonTime"))
        last_info = data.get("LastLogonInfo") or {}
        rec: dict[str, Any] = {
            "luid": luid,
            "user": _clean(data.get("UserName")),
            "domain": _clean(data.get("LogonDomain")),
            "dns_domain": _clean(data.get("DnsDomainName")),
            "upn": _clean(data.get("Upn")),
            "sid": sid_str,
            "rid": rid,
            "logon_type": data.get("LogonType"),
            "package": _clean(data.get("AuthenticationPackage")),
            "session_id": data.get("Session"),
            "logon_time": logon_time,
            "kickoff": self._epoch(data.get("KickOffTime")),
            "logoff_time": self._epoch(data.get("LogoffTime")),
            "flags": data.get("UserFlags"),
            "logon_server": _clean(data.get("LogonServer")),
            "profile_path": _clean(data.get("ProfilePath")),
            "logon_script": _clean(data.get("LogonScript")),
            "password_last_set": self._epoch(data.get("PasswordLastSet")),
            "password_must_change": self._epoch(data.get("PasswordMustChange")),
            "last_success": self._epoch(last_info.get("LastSuccessfulLogon")),
            "last_failed": self._epoch(last_info.get("LastFailedLogon")),
            "failed_since": last_info.get(
                "FailedAttemptCountSinceLastSuccessfulLogon"),
        }
        # The uid qualifier pairs a logoff with its logon. A LUID alone would not: LUIDs
        # restart at boot, so the same number can name two different sessions across a
        # reboot and the second one's logoff would dedup away against the first's.
        prior = self._readable.get(str(luid))
        if prior is not None and prior.get("_uidq"):
            rec["_uidq"] = prior["_uidq"]
        elif logon_time is not None:
            rec["_uidq"] = f"{logon_time:.3f}"
        else:
            was_opaque = self._opaque.get(str(luid))
            rec["_uidq"] = (was_opaque or {}).get("_uidq") or f"seen{self.clock():.3f}"
        return rec

    def _epoch(self, value: Any) -> float | None:
        """:func:`_to_epoch`, with every rejection counted.

        The counting is the point of the wrapper. A sentinel silently becoming ``None``
        is correct behaviour and invisible behaviour; if one of these fields turns out
        to hold a real time this collector is discarding, ``time_sentinels_rejected``
        is what makes that show up as a number rather than as an absent field nobody
        queries.
        """
        if value is None:
            return None
        ts = _to_epoch(value)
        if ts is None:
            self.time_sentinels_rejected += 1
        return ts

    # ── diffing ────────────────────────────────────────────────────────────

    def _diff(
        self,
        readable: dict[str, dict[str, Any]],
        opaque: dict[str, dict[str, Any]],
        stations: dict[int, dict[str, Any]],
        now: float,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        was_readable = self._readable
        was_opaque = self._opaque

        for key, rec in readable.items():
            if key in was_readable:
                continue
            if key in was_opaque:
                # Late attribution, not a new logon. Activity 99 for the reason in the
                # class docstring: this session was already counted when it was opaque.
                out.append(self._attributed_event(rec, was_opaque[key], stations, now))
                self.attributions += 1
            else:
                out.append(self._logon_event(rec, stations, now))
                self.logons += 1

        for key, info in opaque.items():
            if key in was_opaque:
                continue
            if key in was_readable:
                # A session that was readable and is not any more. The session did not
                # change; the collector's view of it did, which is why this is a 5017
                # with query_result_id ERROR rather than anything on the 3002 side.
                out.append(self._deattributed_event(
                    was_readable[key], info, stations, now))
                self.deattributions += 1
            else:
                out.append(self._opaque_logon_event(info, now))
                self.opaque_logons += 1

        for key, rec in was_readable.items():
            if key not in readable and key not in opaque:
                out.append(self._logoff_event(rec, stations, now, opaque_info=None))
                self.logoffs += 1
        for key, info in was_opaque.items():
            if key not in readable and key not in opaque:
                out.append(self._logoff_event(None, stations, now, opaque_info=info))
                self.logoffs += 1
        return out

    # ── event construction ─────────────────────────────────────────────────

    def _base(self, now: float) -> dict[str, Any]:
        return {
            "severity_id": int(Severity.INFORMATIONAL),
            "device_hostname": _hostname(),
            "metadata_product_name": "LSA logon sessions",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_labels": ["logon_session", "substitute_for:4624,4634"],
            "unmapped": {},
        }

    def _session_fields(
        self,
        rec: dict[str, Any],
        stations: dict[int, dict[str, Any]],
        payload: dict[str, Any],
        notes: list[str],
        *,
        user_prefix: str = "user",
    ) -> None:
        """Everything a readable session knows, onto a payload.

        ``user_prefix`` is ``"user"`` on the 3002 events, where OCSF's ``user`` is the
        authenticating principal, and ``"actor_user"`` on the 5017 inventory events,
        where the class has no ``user`` attribute and ``actor.user`` is the correct
        home for the principal a discovery record is about.
        """
        luid = int(rec["luid"])
        payload["session_uid"] = f"0x{luid:x}"
        payload["session_uid_alt"] = str(luid)
        if rec.get("user"):
            payload[f"{user_prefix}_name"] = rec["user"]
        if rec.get("domain"):
            payload[f"{user_prefix}_domain"] = rec["domain"]
        if rec.get("sid"):
            payload[f"{user_prefix}_uid"] = rec["sid"]
        if rec.get("rid") is not None and user_prefix == "user":
            # user.uid_numeric exists; actor.user has no numeric uid in OCSF, so on the
            # inventory events the RID goes to unmapped rather than to a field that
            # would silently become unmapped data anyway.
            payload["user_uid_numeric"] = int(rec["rid"])
        elif rec.get("rid") is not None:
            payload["unmapped"]["user_rid"] = int(rec["rid"])
        if rec.get("upn"):
            payload[f"{user_prefix}_email"] = rec["upn"]
        if rec.get("logon_time") is not None:
            payload["session_created_time"] = rec["logon_time"]
        if rec.get("kickoff") is not None:
            payload["session_expiration_time"] = rec["kickoff"]
        if rec.get("logon_server"):
            payload["session_issuer"] = rec["logon_server"]
        if rec.get("dns_domain"):
            payload["unmapped"]["dns_domain"] = rec["dns_domain"]
        if rec.get("profile_path"):
            payload["unmapped"]["profile_path"] = rec["profile_path"]
        if rec.get("logon_script"):
            payload["unmapped"]["logon_script"] = rec["logon_script"]
            notes.append(
                f"a logon script is configured for this session "
                f"({rec['logon_script']!r}) — a logon script is code that runs on every "
                "logon, and setting one is a documented persistence mechanism"
            )
            _raise_severity(payload, int(Severity.LOW))

        session_id = rec.get("session_id")
        if session_id is not None:
            payload["unmapped"]["terminal_session_id"] = int(session_id)
            station = stations.get(int(session_id))
            if station:
                if station.get("name"):
                    payload["session_terminal"] = station["name"]
                if station.get("state"):
                    payload["unmapped"]["terminal_session_state"] = station["state"]

        lt = rec.get("logon_type")
        if isinstance(lt, int):
            payload["unmapped"]["logon_type_id"] = lt
            if lt in (3, 8, 10, 12):
                payload["session_is_remote"] = True
        if rec.get("package"):
            payload["unmapped"]["authentication_package"] = rec["package"]
        self._note_user_flags(rec, payload, notes)
        self._note_failed_attempts(rec, payload, notes)
        for field, key in (("password_last_set", "password_last_set"),
                           ("password_must_change", "password_must_change"),
                           ("last_success", "last_successful_logon"),
                           ("last_failed", "last_failed_logon")):
            if rec.get(field) is not None:
                payload["unmapped"][key] = rec[field]

    def _note_user_flags(
        self, rec: dict[str, Any], payload: dict[str, Any], notes: list[str]
    ) -> None:
        flags = rec.get("flags")
        if not isinstance(flags, int) or flags == 0:
            return
        named = [name for bit, name in LOGON_USER_FLAGS.items() if flags & bit]
        leftover = flags & ~sum(LOGON_USER_FLAGS)
        payload["unmapped"]["logon_user_flags"] = flags
        if named:
            payload["unmapped"]["logon_user_flag_names"] = named
        if leftover:
            # Reported as a number rather than dropped: an undocumented bit on a logon
            # session is exactly the kind of thing worth noticing, and a table that
            # silently swallows what it does not recognise cannot notice it.
            payload["unmapped"]["logon_user_flags_unknown"] = f"0x{leftover:X}"
            notes.append(
                f"UserFlags carries bits not in the LOGON_* table (0x{leftover:X}) — "
                "reported as a number rather than given a guessed name"
            )
        for bit, (text, floor) in LOGON_USER_FLAG_FINDINGS.items():
            if flags & bit:
                notes.append(text)
                _raise_severity(payload, floor)

    def _note_failed_attempts(
        self, rec: dict[str, Any], payload: dict[str, Any], notes: list[str]
    ) -> None:
        """``FailedAttemptCountSinceLastSuccessfulLogon`` — the only failure signal here.

        This table has no record of an authentication that did not succeed. This one
        counter is the exception: it says how many failures preceded the success that
        created this session, which is the difference between a normal logon and the
        end of a successful password guess. It is per-account state read at logon time,
        not an event, so it says nothing about *when* those failures happened.
        """
        count = rec.get("failed_since")
        if not isinstance(count, int) or count <= 0:
            return
        payload["unmapped"]["failed_attempts_since_last_success"] = count
        floor = int(Severity.LOW) if count < 5 else int(Severity.MEDIUM)
        notes.append(
            f"{count} failed authentication attempt(s) preceded the success that "
            "opened this session. LSA reports the count, not the times, so this is "
            "evidence that guessing happened and not evidence of when — the Security "
            "channel's 4625 records are what would date it"
        )
        _raise_severity(payload, floor)

    def _logon_event(
        self,
        rec: dict[str, Any],
        stations: dict[int, dict[str, Any]],
        now: float,
    ) -> dict[str, Any]:
        notes: list[str] = []
        payload = self._base(now)
        payload.update({
            # The real LogonTime when LSA gave one. It is the closest thing to when the
            # logon happened; `now` would record when the poll got round to noticing.
            "time": rec.get("logon_time") if rec.get("logon_time") is not None else now,
            "class_uid": _AUTH,
            "activity_id": 1,  # Logon
            "status_id": _SUCCESS,
            "message": "Logon session opened",
        })
        if rec.get("logon_time") is None:
            notes.append(
                "LSA did not return a usable LogonTime for this session, so the event "
                "time is the observation time — the logon happened at some point in the "
                f"preceding {self.blind_window_seconds:.0f}s"
            )
        self._session_fields(rec, stations, payload, notes)
        lt = rec.get("logon_type")
        if isinstance(lt, int):
            payload["logon_type_id"] = lt
            payload["logon_type"] = LOGON_TYPES.get(lt, str(lt))
            if lt in (3, 8, 10, 12):
                payload["is_remote"] = True
            if lt == 8:
                payload["is_cleartext"] = True
            meaning = LOGON_TYPE_MEANING.get(lt)
            if meaning is not None:
                text, floor = meaning
                notes.append(f"logon type {lt} ({LOGON_TYPES.get(lt, lt)}): {text}")
                if floor is not None:
                    _raise_severity(payload, floor)
            else:
                notes.append(
                    f"logon type {lt} is not a documented Windows type — reported as-is"
                )
            payload["unmapped"].pop("logon_type_id", None)
        self._note_auth_package(rec, payload, notes)
        payload["metadata_uid"] = (
            f"{_hostname()}:logon_session:{rec['luid']}:{rec['_uidq']}:logon")
        if notes:
            payload["soc_notes"] = notes
        return payload

    def _note_auth_package(
        self, rec: dict[str, Any], payload: dict[str, Any], notes: list[str]
    ) -> None:
        package = rec.get("package") or ""
        if not package:
            return
        payload["auth_protocol"] = package
        payload["unmapped"].pop("authentication_package", None)
        mapped = AUTH_PACKAGE_PROTOCOL.get(package.strip().lower())
        if mapped is not None:
            payload["auth_protocol_id"] = mapped
        else:
            notes.append(
                f"authentication package {package!r} has no unambiguous OCSF "
                "auth_protocol_id, so the string is carried and the id is left absent. "
                "Negotiate in particular is the package that *chose* Kerberos or NTLM "
                "and recording it as either would be a claim this field does not make"
            )
        if package.strip().lower() == "ntlm":
            _raise_severity(payload, int(Severity.LOW))
            notes.append(
                "this session authenticated with NTLM rather than Kerberos. On a "
                "domain-joined host that is either a fallback worth explaining or a "
                "deliberate downgrade, and NTLM is relayable where Kerberos is not"
            )

    def _opaque_logon_event(
        self, info: dict[str, Any], now: float
    ) -> dict[str, Any]:
        """A session appeared and LSA refused to describe it.

        This event exists because the alternative is worse. The enumeration saw a new
        logon session; suppressing the event because its content is unavailable would
        make an unelevated collector silently blind to exactly the sessions an attacker
        cares about — SYSTEM, and services. So the event is emitted with what is
        genuinely known: the LUID, the observation time, and the fact that LSA denied
        the read. Every absent field is absent rather than blank.
        """
        luid = int(info["luid"])
        notes = [
            "LSA denied the read for this logon session "
            f"({info['reason']}), so the user, the logon type, the authentication "
            "package and the logon time are all unknown. What is known is that a new "
            "logon session appeared between two polls: the enumeration is not access "
            "-checked, only the content is. The event time is the observation time, not "
            f"the logon time — the logon happened within the preceding "
            f"{self.blind_window_seconds:.0f}s"
        ]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _AUTH,
            "activity_id": 1,  # Logon
            "status_id": _SUCCESS,
            "message": "Logon session opened (opaque — LSA read denied)",
            "session_uid": f"0x{luid:x}",
            "session_uid_alt": str(luid),
            "metadata_uid": (
                f"{_hostname()}:logon_session:{luid}:{info['_uidq']}:logon"),
        })
        payload["metadata_labels"].append("opaque_session")
        payload["unmapped"]["lsa_read_denied"] = info["reason"]
        self._attribute_well_known(luid, payload, notes)
        if notes:
            payload["soc_notes"] = notes
        return payload

    def _attribute_well_known(
        self, luid: int, payload: dict[str, Any], notes: list[str]
    ) -> None:
        """Name an opaque session from its LUID, if Windows reserves that number."""
        known = WELL_KNOWN_LUIDS.get(luid)
        if known is None:
            return
        name, sid = known
        self.well_known_attributed += 1
        payload["user_name"] = name
        payload["user_uid"] = sid
        payload["metadata_labels"].append("attribution:well_known_luid")
        notes.append(
            f"the principal is {name} ({sid}), from the reserved LUID 0x{luid:X} rather "
            "than from LSA — which is a weaker statement than it looks. It is a "
            "documented constant, so the mapping is certain, but nothing here confirms "
            "the session actually belongs to that principal; only that Windows reserves "
            "that LUID for it"
        )

    def _attributed_event(
        self,
        rec: dict[str, Any],
        was: dict[str, Any],
        stations: dict[int, dict[str, Any]],
        now: float,
    ) -> dict[str, Any]:
        """An opaque session became readable. Activity 99, never 1.

        Emitting Logon here would double-count: this session already produced a logon
        event when it appeared opaque. A logon count that rises because the collector's
        visibility improved is worse than no logon count, because it looks like activity
        on the host. 99 with an ``activity_name`` records the attribution as what it is
        — a change in what is known about an existing session.
        """
        notes: list[str] = [
            "this logon session was previously opaque "
            f"({was['reason']}) and is now readable, so its user, logon type and logon "
            "time are being reported for the first time. This is not a new logon — the "
            f"session has existed since it was first seen at {was['first_seen']:.0f} — "
            "and it is deliberately activity 99 rather than Logon so that a logon count "
            "does not rise because visibility improved"
        ]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _AUTH,
            "activity_id": 99,
            "activity_name": "Logon session attributed",
            "message": "Logon session attributed after LSA became readable",
        })
        payload["metadata_labels"].append("late_attribution")
        self._session_fields(rec, stations, payload, notes)
        lt = rec.get("logon_type")
        if isinstance(lt, int):
            payload["logon_type_id"] = lt
            payload["logon_type"] = LOGON_TYPES.get(lt, str(lt))
            payload["unmapped"].pop("logon_type_id", None)
        self._note_auth_package(rec, payload, notes)
        payload["metadata_uid"] = (
            f"{_hostname()}:logon_session:{rec['luid']}:{rec['_uidq']}:attributed")
        payload["soc_notes"] = notes
        return payload

    def _deattributed_event(
        self,
        was: dict[str, Any],
        info: dict[str, Any],
        stations: dict[int, dict[str, Any]],
        now: float,
    ) -> dict[str, Any]:
        """A readable session stopped being readable. A 5017 with ERROR, not a logoff.

        Nothing happened to the session. What changed is the collector's access to it,
        and ``query_result_id = ERROR`` is the field OCSF provides for exactly that: an
        entity that exists and could not be read. Reporting it as a logoff would say the
        user logged off, which is false and would end a session that is still open.
        """
        luid = int(was["luid"])
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _SESSION_QUERY,
            "activity_id": _QUERY,
            "activity_name": "Logon session became unreadable",
            "query_result_id": int(QueryResultId.ERROR),
            "severity_id": int(Severity.LOW),
            "message": "Logon session is still open and can no longer be read",
            "session_uid": f"0x{luid:x}",
            "session_uid_alt": str(luid),
            "metadata_uid": (
                f"{_hostname()}:logon_session:{luid}:{was['_uidq']}:unreadable"),
        })
        payload["metadata_labels"].append("coverage_change")
        payload["unmapped"]["lsa_read_denied"] = info["reason"]
        if was.get("user"):
            payload["actor_user_name"] = was["user"]
        if was.get("sid"):
            payload["actor_user_uid"] = was["sid"]
        payload["soc_notes"] = [
            "this session was readable and is not any more "
            f"({info['reason']}). The session itself has not changed — it is still in "
            "the enumeration — so this is a loss of visibility rather than a logoff, "
            "which is why it is query_result_id ERROR on a session query and not "
            "activity 2 on an authentication. The last known user is carried as the "
            "actor so the session does not become anonymous in the record"
        ]
        return payload

    def _logoff_event(
        self,
        rec: dict[str, Any] | None,
        stations: dict[int, dict[str, Any]],
        now: float,
        *,
        opaque_info: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """A LUID left the table.

        The time is the observation time and cannot be anything else — LSA does not
        report when a session it no longer has ended, and ``LogoffTime`` on a live
        session is the year-9999 "never" sentinel. So the event states the uncertainty
        explicitly as the poll interval rather than implying the logoff happened at the
        instant it was noticed.
        """
        source = rec if rec is not None else opaque_info
        assert source is not None
        luid = int(source["luid"])
        notes: list[str] = [
            "the logoff time is the time this collector noticed the session was gone, "
            f"not the time it ended: the session ended at some point in the preceding "
            f"{self.blind_window_seconds:.0f}s and LSA does not report when a session "
            "it no longer holds finished. 4634 would have dated it"
        ]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _AUTH,
            "activity_id": 2,  # Logoff
            "status_id": _SUCCESS,
            "message": "Logon session closed",
            "session_uid": f"0x{luid:x}",
            "session_uid_alt": str(luid),
        })
        if rec is not None:
            self._session_fields(rec, stations, payload, notes)
            lt = rec.get("logon_type")
            if isinstance(lt, int):
                payload["logon_type_id"] = lt
                payload["logon_type"] = LOGON_TYPES.get(lt, str(lt))
                payload["unmapped"].pop("logon_type_id", None)
            if rec.get("logon_time") is not None:
                # Duration is derivable, but stating it saves every consumer the join
                # and — more to the point — makes a session that lasted milliseconds
                # visible without one.
                payload["unmapped"]["session_duration_seconds"] = round(
                    now - rec["logon_time"], 3)
            payload["metadata_uid"] = (
                f"{_hostname()}:logon_session:{luid}:{rec['_uidq']}:logoff")
        else:
            payload["metadata_labels"].append("opaque_session")
            payload["unmapped"]["lsa_read_denied"] = opaque_info["reason"]
            notes.append(
                "this session was never readable, so the logoff names a LUID and "
                "nothing else — there is no user to attribute it to"
            )
            self._attribute_well_known(luid, payload, notes)
            payload["metadata_uid"] = (
                f"{_hostname()}:logon_session:{luid}:{opaque_info['_uidq']}:logoff")
        payload["soc_notes"] = notes
        return payload

    def _session_inventory(
        self,
        rec: dict[str, Any],
        stations: dict[int, dict[str, Any]],
        now: float,
    ) -> dict[str, Any]:
        """One readable session, restated as state. 5017, ``EXISTS``.

        The principal goes to ``actor.user`` rather than ``user``: 5017 has an ``actor``
        attribute and no ``user`` attribute, and putting ``user_name`` here would
        produce invalid OCSF that nothing in the pipeline checks — the event model
        stores class-inappropriate attributes rather than rejecting them.
        """
        notes: list[str] = []
        payload = self._base(now)
        bucket = int(now // self.heartbeat_seconds)
        payload.update({
            "time": now,
            "class_uid": _SESSION_QUERY,
            "activity_id": _QUERY,
            "query_result_id": int(QueryResultId.EXISTS),
            "message": "Logon session observed",
            "metadata_uid": (
                f"{_hostname()}:session_query:{rec['luid']}:{bucket}"),
        })
        payload["metadata_labels"].append("state_observed")
        self._session_fields(rec, stations, payload, notes, user_prefix="actor_user")
        notes.append(
            "state, not an event: this session was already open and is being restated "
            "on the inventory heartbeat. It is a Discovery class precisely so that a "
            "rule counting logons never counts this"
        )
        payload["soc_notes"] = notes
        return payload

    def _table_event(
        self,
        readable: dict[str, dict[str, Any]],
        opaque: dict[str, dict[str, Any]],
        stations: dict[int, dict[str, Any]],
        now: float,
        *,
        reason: str,
        labels: list[str],
        exact_uid: bool = True,
        severity_id: int | None = None,
    ) -> dict[str, Any]:
        """The whole table as one 5017, with the readability as ``query_result_id``.

        ``PARTIAL`` is the entire reason this event is worth emitting. A session
        inventory that reported the two readable sessions and stopped would be a true
        statement about two sessions and a false one about the host. With
        ``query_result_id = PARTIAL`` and both counts on the record, a query can ask
        "how much of this host's identity state was visible" and get a number.
        """
        import hashlib

        total = len(readable) + len(opaque)
        if total == 0:
            result = int(QueryResultId.DOES_NOT_EXIST)
        elif not readable:
            result = int(QueryResultId.ERROR)
        elif opaque:
            result = int(QueryResultId.PARTIAL)
        else:
            result = int(QueryResultId.EXISTS)

        luids = sorted(int(k) for k in list(readable) + list(opaque))
        digest = hashlib.sha256(
            ",".join(str(x) for x in luids).encode()).hexdigest()[:16]

        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _SESSION_QUERY,
            "activity_id": _QUERY,
            "query_result_id": result,
            "session_count": total,
            # Deliberately *not* the base-event `count`. That field means "how many
            # times this event repeated", so putting a session tally in it would make
            # every consumer that sums `count` for event volume overcount this
            # heartbeat fourteen-fold. `session.count` is the field that means what is
            # meant here.
            "message": f"Logon session table: {len(readable)} of {total} readable",
        })
        if severity_id is not None:
            payload["severity_id"] = severity_id
        payload["metadata_labels"].extend(["state_observed", "session_table"])
        payload["metadata_labels"].extend(labels)
        payload["unmapped"].update({
            "sessions_total": total,
            "sessions_readable": len(readable),
            "sessions_opaque": len(opaque),
            "readable_ratio": round(len(readable) / total, 4) if total else 0.0,
            # The digest is what makes "the same set of sessions" checkable in one
            # comparison downstream, without shipping fourteen LUIDs on every heartbeat
            # and without a consumer having to sort them itself.
            "luid_set_sha256_16": digest,
            "opaque_luids": [str(int(k)) for k in sorted(opaque, key=int)],
            "well_known_opaque": sorted(
                WELL_KNOWN_LUIDS[int(k)][0] for k in opaque
                if int(k) in WELL_KNOWN_LUIDS
            ),
            "terminal_sessions": {str(k): v for k, v in sorted(stations.items())},
        })
        if exact_uid:
            payload["metadata_uid"] = (
                f"{_hostname()}:session_table:{int(now // self.heartbeat_seconds)}")
        notes = [reason]
        if opaque:
            notes.append(
                f"{len(opaque)} of {total} sessions could not be read, so this is a "
                "PARTIAL answer and not an inventory: the sessions are counted and "
                "their LUIDs are listed, and their users, logon types and logon times "
                "are unknown. " + LSA_SESSION_SETUP.split("\n", 1)[0]
            )
        payload["soc_notes"] = notes
        return payload

    # ── reporting ──────────────────────────────────────────────────────────

    def stats_extra(self) -> dict[str, Any]:
        total = len(self._readable) + len(self._opaque)
        return {
            "sessions_total": total,
            "sessions_readable": len(self._readable),
            "sessions_opaque": len(self._opaque),
            "readable_ratio": round(len(self._readable) / total, 4) if total else None,
            "logons_observed": self.logons,
            "logons_opaque": self.opaque_logons,
            "logoffs_observed": self.logoffs,
            "late_attributions": self.attributions,
            "visibility_losses": self.deattributions,
            "well_known_luid_attributions": self.well_known_attributed,
            "baseline_sessions_emitted": self.baseline_emitted,
            "heartbeats": self.heartbeats,
            "coverage_ratio_changes": self.ratio_changes,
            "session_inventories_emitted": self.inventory_emitted,
            "lsa_read_denied": self.read_denied,
            "lsa_read_failed": self.read_failed,
            "enumerate_failures": self.enumerate_failures,
            "time_sentinels_rejected": self.time_sentinels_rejected,
            "sids_unresolved": self.sid_unresolved,
            "wts_station_lookup_failures": self.station_lookup_failures,
            "blind_window_seconds": round(self.blind_window_seconds, 3),
            "blind_window_seconds_worst": round(self.blind_window_seconds_worst, 3),
            "first_poll_seconds": round(self._first_poll_seconds, 3),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Local accounts, groups and password policy — the state substitute for 4720-4733
# ═══════════════════════════════════════════════════════════════════════════════


class LocalAccountCollector(PullCollector):
    """Local users, group membership and password policy, diffed.

    This is the substitute for the account-management half of the Security channel —
    4720 create, 4722 enable, 4723/4724 password change and reset, 4725 disable, 4726
    delete, 4732/4733 group add and remove, 4738 change, 4740 lockout — none of which
    can be read here. ``NetUserEnum``, ``NetLocalGroupEnum``,
    ``NetLocalGroupGetMembers`` and ``NetUserModalsGet`` all succeed **unelevated**,
    which makes this the one substitute in this module with no coverage gap at all in
    the thing it reads. Measured on this host: 9 accounts, 17 groups, every membership
    readable, both modals levels readable.

    What it cannot give, and what every event here says it cannot give: **who did it.**
    A diff of state names the change and not the actor. 4720 carries a ``Subject``; a
    snapshot comparison carries nothing, so ``actor`` is left empty rather than filled
    with the collector's own identity, and each event's notes say so explicitly. That
    is the single most important limitation of the whole approach — "a new local
    administrator appeared" is a finding, and "and this account created it" is the one
    that closes the investigation.

    It also gives one thing the Security channel does *not* make easy, and it is worth
    the whole collector on its own: ``USER_INFO_3.bad_pw_count`` is per-account failure
    state, readable without elevation. A rise in it across several accounts between two
    polls is a password spray. On a host where 4625 is unreadable that is the only
    spray detection available, and it is arguably better than 4625 for the purpose,
    because it is already aggregated per account and needs no windowed count.

    ``password_age`` is the one field whose *loss* of information has to be stated
    rather than papered over. It says how long ago the password was set, so a password
    change is detectable — but ``NetUserEnum`` cannot distinguish a user changing their
    own password (4723) from an administrator resetting someone else's (4724). Those
    are very different events: the second is a classic account-takeover step. Here they
    are one activity with a note saying which distinction was lost.

    Class choice follows the same rule as the rest of this module. *Changes* are IAM —
    3007 User Management, 3006 Group Management. The *state* those changes are computed
    from is Discovery — 5003 User Inventory, 5009 Admin Group Query, 5002 Device Config
    State for the policy, 5019 Device Config State Change when the policy moves. A
    rule counting account creations must never count an inventory heartbeat, and
    keeping them in different categories is what guarantees that rather than hoping for
    it.
    """

    name = "local_accounts"
    #: Five minutes. The trade-off is different from the session collector's: an
    #: account that is created and deleted inside one interval leaves no trace in
    #: either snapshot and is invisible, so the interval is the blind window for
    #: create-then-delete. But ``bad_pw_count`` and ``num_logons`` are *counters* —
    #: they accumulate, so no authentication attempt is lost to the interval, only its
    #: timing. Polling faster would buy little and each poll is ~30 API calls.
    cadence_seconds = 300.0
    #: Silence is normal. The inventory heartbeat is hourly, so two hours.
    health_cadence_seconds = 7200.0
    #: Not critical, for the same reason as the session collector: this is a declared
    #: substitute, and a critical fault on its loss would claim coverage was lost that
    #: was never a substitute for the real thing in the first place.
    critical = False
    description = (
        "local users, groups and password policy, diffed — account management and "
        "password-spray detection without the Security channel"
    )

    #: How often the full inventory is restated even when nothing changed.
    inventory_seconds = 3600.0

    def __init__(
        self,
        pipeline: Any,
        *,
        inventory_seconds: float | None = None,
        emit_baseline: bool = True,
        emit_account_inventory: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(pipeline, **kwargs)
        if inventory_seconds is not None:
            self.inventory_seconds = float(inventory_seconds)
        #: Emit the policy state and the privileged-group inventory at startup. On by
        #: default: an investigation needs to know what the account configuration
        #: *was*, and the most likely place for a backdoor account is one that predates
        #: the collector — which by definition never produces a create event.
        self.emit_baseline = emit_baseline
        #: Emit one 5003 per account on each inventory beat. Nine accounts on this host
        #: at an hourly beat is 216 events a day, which is trivial volume and makes
        #: "what did account X look like at 3am" answerable by a point query instead of
        #: a reconstruction from diffs.
        self.emit_account_inventory = emit_account_inventory

        self._users: dict[str, dict[str, Any]] = {}
        self._groups: dict[str, dict[str, Any]] = {}
        self._modals: dict[str, Any] = {}
        #: Case-folded account name → SID string. Cached because a SID that changes for
        #: an unchanged name is itself a finding: it means the account was deleted and
        #: recreated between two polls, which is a create *and* a delete that the name
        #: diff alone reports as "no change".
        self._sids: dict[str, str] = {}
        self._first_poll = True
        self._last_inventory = 0.0
        self._poll_seconds = 0.0
        self._poll_seconds_worst = 0.0
        self._first_poll_seconds = 0.0

        # Counters. Same principle as elsewhere in this module: the numbers that make
        # the collector's own blindness measurable are not optional.
        self.users_created = 0
        self.users_deleted = 0
        self.users_updated = 0
        self.users_enabled = 0
        self.users_disabled = 0
        self.users_locked = 0
        self.users_unlocked = 0
        self.password_changes = 0
        self.privilege_grants = 0
        self.sid_reuse_detected = 0
        self.failed_auth_events = 0
        self.spray_events = 0
        self.success_auth_events = 0
        self.group_adds = 0
        self.group_removes = 0
        self.groups_created = 0
        self.groups_deleted = 0
        self.policy_changes = 0
        self.policy_findings = 0
        self.inventories_emitted = 0
        self.group_queries_emitted = 0
        self.group_read_failures = 0
        self.missing_privileged_rids = 0
        self.sid_lookup_failures = 0
        self.time_sentinels_rejected = 0

    # ── availability ───────────────────────────────────────────────────────

    def probe(self) -> Availability:
        if not is_windows():
            return unavailable(
                "NetUserEnum / NetLocalGroupEnum are Windows APIs; there is no "
                "equivalent on this platform",
                fixable_by_user=False,
            )
        try:
            import win32net
            import win32security  # noqa: F401  (used by the snapshot)
        except Exception as exc:
            return unavailable(
                f"pywin32 is not importable ({exc}); pip install pywin32. Without it "
                "there is no local account telemetry on this host at all unless the "
                "Security channel becomes readable."
            )

        notes: list[str] = []
        try:
            users, _, _ = win32net.NetUserEnum(None, 3)
            notes.append(f"{len(users)} local accounts readable")
        except Exception as exc:
            return unavailable(
                f"NetUserEnum(None, 3) failed ({type(exc).__name__}: {exc}), so local "
                "account state cannot be read at all",
                fixable_by_user=False,
            )
        try:
            groups, _, _ = win32net.NetLocalGroupEnum(None, 1)
            notes.append(f"{len(groups)} local groups readable")
        except Exception as exc:
            notes.append(f"NetLocalGroupEnum failed ({exc}) — no group membership")

        limits: list[str] = [
            "a state diff names the change and not the actor. Every account and group "
            "event from this collector has an empty `actor`, because comparing two "
            "snapshots cannot say who made the difference — 4720/4732 carry a Subject "
            "and this does not. 'A new local administrator appeared' is the finding; "
            "'and this account created it' is not available here. " + SECURITY_SETUP,
            "NetUserEnum cannot distinguish a user changing their own password (4723) "
            "from an administrator resetting another user's (4724): both appear only as "
            "password_age resetting to near zero. Password-change events from this "
            "collector say which distinction was lost rather than guessing.",
            f"an account created and deleted inside one poll interval "
            f"({self.cadence_seconds:g}s) appears in neither snapshot and is invisible. "
            "bad_pw_count and num_logons are cumulative counters, so authentication "
            "attempts are not lost to the interval — only their timing is.",
        ]
        # The membership read is the part that can silently be partial, so it is
        # measured rather than assumed. On this host it is complete.
        unreadable = 0
        try:
            for g in win32net.NetLocalGroupEnum(None, 1)[0]:
                try:
                    win32net.NetLocalGroupGetMembers(None, g["name"], 2)
                except Exception:
                    unreadable += 1
        except Exception:
            unreadable = -1
        if unreadable > 0:
            limits.append(
                f"{unreadable} local group(s) enumerated but their membership could not "
                "be read, so privileged-group monitoring is partial. Each one emits a "
                "5009 with query_result_id ERROR rather than being counted as empty."
            )
        elif unreadable == 0:
            notes.append("every group's membership is readable unelevated")
        if not is_admin():
            notes.append("not elevated, and none of the above needs elevation")
        return available("; ".join(notes) + ". " + "\n  ".join(limits))

    @property
    def blind_window_seconds(self) -> float:
        """The window in which a create-then-delete leaves no trace. **Measured.**"""
        return self.cadence_seconds + self._poll_seconds

    @property
    def blind_window_seconds_worst(self) -> float:
        return self.cadence_seconds + self._poll_seconds_worst

    # ── polling ────────────────────────────────────────────────────────────

    async def poll(self) -> list[dict[str, Any]]:
        started_at = self.clock()
        now = started_at
        users, groups, modals = self._snapshot(now)

        payloads: list[dict[str, Any]] = []
        if self._first_poll:
            self._first_poll = False
            if self.emit_baseline:
                payloads.extend(self._baseline(users, groups, modals, now))
            self._last_inventory = now
        else:
            payloads.extend(self._diff_users(users, now))
            payloads.extend(self._diff_groups(groups, now))
            payloads.extend(self._diff_policy(modals, now))

        if now - self._last_inventory >= self.inventory_seconds:
            self._last_inventory = now
            payloads.extend(self._inventory(users, groups, modals, now, labels=[
                "heartbeat"]))

        self._users = users
        self._groups = groups
        self._modals = modals

        elapsed = self.clock() - started_at
        self._poll_seconds = elapsed
        if self._first_poll_seconds == 0.0:
            self._first_poll_seconds = elapsed
        elif elapsed > self._poll_seconds_worst:
            self._poll_seconds_worst = elapsed
        return payloads

    # ── reading state ──────────────────────────────────────────────────────

    def _snapshot(
        self, now: float
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
        """Accounts, groups with membership, and both password-policy levels.

        Keys are case-folded account and group names, because that is the only stable
        identity the enumeration offers and Windows returns the creator's casing
        verbatim — ``docker-users``, ``OpenSSH Users`` and ``CodexSandboxUsers`` on one
        host. Comparing raw names would report a rename that never happened the first
        time an installer recased a group.
        """
        import win32net
        import win32netcon

        users: dict[str, dict[str, Any]] = {}
        resume = 0
        while True:
            # FILTER_NORMAL_ACCOUNT lives in win32netcon, not win32net — checked, and
            # `win32net.FILTER_NORMAL_ACCOUNT` raises AttributeError. It excludes
            # trust and machine accounts, which are not local users and would each
            # produce a spurious account-created event at first diff on a domain host.
            batch, _total, resume = win32net.NetUserEnum(
                None, 3, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
            for u in batch:
                rec = self._normalise_user(u, now)
                users[rec["key"]] = rec
            if not resume:
                break

        groups = self._read_groups()
        modals = self._read_modals()
        return users, groups, modals

    def _normalise_user(self, u: dict[str, Any], now: float) -> dict[str, Any]:
        name = str(u.get("name") or "")
        rid = u.get("user_id")
        flags = int(u.get("flags") or 0)
        password_age = u.get("password_age")
        rec: dict[str, Any] = {
            "key": name.casefold(),
            "name": name,
            # When this record was read. Load-bearing, not bookkeeping: password-change
            # detection compares how much `password_age` grew against how much time
            # actually elapsed, and without this it would have to assume the elapsed
            # time equalled the nominal cadence — which is never exactly true and is
            # badly wrong after any poll that was slow or a process that was suspended.
            "_observed_at": now,
            "rid": int(rid) if isinstance(rid, int) else None,
            "sid": self._sid_for(name),
            "full_name": _clean(u.get("full_name")),
            "comment": _clean(u.get("comment")),
            "flags": flags,
            "priv": u.get("priv"),
            "password_age": int(password_age) if isinstance(password_age, int) else None,
            # password_age is *relative*, so the absolute set-time has to be computed
            # at read time or it drifts by however long the record sits in memory.
            "password_set_at": (
                now - int(password_age)
                if isinstance(password_age, int) and password_age > 0 else None
            ),
            "password_expired": bool(u.get("password_expired")),
            "bad_pw_count": u.get("bad_pw_count"),
            "num_logons": u.get("num_logons"),
            "last_logon": self._epoch(u.get("last_logon")),
            "last_logoff": self._epoch(u.get("last_logoff")),
            "acct_expires": self._epoch(u.get("acct_expires")),
            "home_dir": _clean(u.get("home_dir")),
            "profile": _clean(u.get("profile")),
            "script_path": _clean(u.get("script_path")),
            "workstations": _clean(u.get("workstations")),
            "logon_server": _clean(u.get("logon_server")),
            "primary_group_rid": u.get("primary_group_id"),
        }
        return rec

    def _sid_for(self, name: str) -> str:
        """The account's SID string, cached, with a reuse check.

        A cache here is not an optimisation — it is the only way to notice that the
        *same name* now has a *different SID*, which means the account was deleted and
        recreated between polls. Name-only diffing calls that "no change", and it is
        one of the quieter ways to replace a trusted account with one you control.
        """
        key = name.casefold()
        try:
            import win32security

            sid, _, _ = win32security.LookupAccountName(None, name)
            text = win32security.ConvertSidToStringSid(sid)
        except Exception:
            self.sid_lookup_failures += 1
            return self._sids.get(key, "")
        prior = self._sids.get(key)
        if prior and prior != text:
            self.sid_reuse_detected += 1
            # Recorded on the record itself so the diff can raise it; the counter alone
            # would say it happened without saying to whom.
            self._sids[key] = text
            return text
        self._sids[key] = text
        return text

    def _read_groups(self) -> dict[str, dict[str, Any]]:
        """Every local group, its RID, and its membership — or why the membership is absent.

        ``error`` on a group record is load-bearing: an unreadable group and an empty
        group both produce an empty member dict, and treating them the same would let a
        loss of visibility into ``Administrators`` read as "nobody is an administrator
        any more", which is the most reassuring possible way to be blind.
        """
        import win32net
        import win32security

        out: dict[str, dict[str, Any]] = {}
        try:
            resume = 0
            raw: list[dict[str, Any]] = []
            while True:
                batch, _, resume = win32net.NetLocalGroupEnum(None, 1, resume)
                raw.extend(batch)
                if not resume:
                    break
        except Exception:
            self.group_read_failures += 1
            return out

        for g in raw:
            name = str(g.get("name") or "")
            rid: int | None = None
            sid_text = ""
            try:
                sid, _, _ = win32security.LookupAccountName(None, name)
                sid_text = win32security.ConvertSidToStringSid(sid)
                rid = int(sid_text.rsplit("-", 1)[1])
            except Exception:
                self.sid_lookup_failures += 1

            members: dict[str, dict[str, Any]] = {}
            error = ""
            try:
                resume = 0
                while True:
                    batch, _, resume = win32net.NetLocalGroupGetMembers(
                        None, name, 2, resume)
                    for m in batch:
                        m_sid = ""
                        m_rid: int | None = None
                        try:
                            m_sid = win32security.ConvertSidToStringSid(m["sid"])
                            m_rid = int(m_sid.rsplit("-", 1)[1])
                        except Exception:
                            self.sid_lookup_failures += 1
                        # domainandname is "DOMAIN\name"; split rather than re-lookup,
                        # which would be a second syscall for information already here.
                        full = str(m.get("domainandname") or "")
                        domain, _, m_name = full.rpartition("\\")
                        members[m_sid or full] = {
                            "sid": m_sid,
                            "rid": m_rid,
                            "name": m_name or full,
                            "domain": domain,
                            "sid_type": m.get("sidusage"),
                        }
                    if not resume:
                        break
            except Exception as exc:
                self.group_read_failures += 1
                error = f"{type(exc).__name__}: {exc}"

            out[name.casefold()] = {
                "key": name.casefold(),
                "name": name,
                "sid": sid_text,
                "rid": rid,
                "comment": _clean(g.get("comment")),
                "members": members,
                "error": error,
            }
        return out

    def _read_modals(self) -> dict[str, Any]:
        """``NetUserModalsGet`` levels 0 and 3 — the password and lockout policy.

        Two calls, not one: level 0 carries the password rules and level 3 the lockout
        rules, and a host can answer one and refuse the other. They are merged into one
        dict because they describe one policy, with a ``_levels`` note recording which
        halves were actually read so a missing half is never mistaken for a zero.
        """
        import win32net

        out: dict[str, Any] = {}
        got: list[int] = []
        for level in (0, 3):
            try:
                data = win32net.NetUserModalsGet(None, level)
            except Exception as exc:
                out[f"_level{level}_error"] = f"{type(exc).__name__}: {exc}"
                continue
            got.append(level)
            for key, value in data.items():
                out[key] = value
        out["_levels"] = got
        return out

    def _epoch(self, value: Any) -> float | None:
        """:func:`_to_epoch`, with rejections counted. See the session collector's."""
        if value is None:
            return None
        ts = _to_epoch(value)
        if ts is None:
            self.time_sentinels_rejected += 1
        return ts

    # ── baseline and inventory ─────────────────────────────────────────────

    def _baseline(
        self,
        users: dict[str, dict[str, Any]],
        groups: dict[str, dict[str, Any]],
        modals: dict[str, Any],
        now: float,
    ) -> list[dict[str, Any]]:
        """Startup state, as state. Deliberately no 3007 Create events.

        Emitting 3007 activity 1 for nine pre-existing accounts would put nine account
        creations into the record at every collector restart, and "nine local accounts
        were created at 09:14" is a false statement about the host that would survive
        into every metric and every rule that counts account creation. The accounts are
        stated as inventory instead, which is what they are.
        """
        out = self._inventory(users, groups, modals, now, labels=["baseline_snapshot"])
        for payload in out:
            payload.setdefault("soc_notes", []).append(
                "baseline: this state was already present when the collector started, "
                "so no change event is emitted for it. An account that predates CYPHRA "
                "never produces a create event and this inventory is the only record "
                "that it exists — which is precisely why the baseline is emitted"
            )
        return out

    def _inventory(
        self,
        users: dict[str, dict[str, Any]],
        groups: dict[str, dict[str, Any]],
        modals: dict[str, Any],
        now: float,
        *,
        labels: list[str],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        bucket = int(now // self.inventory_seconds)

        if self.emit_account_inventory:
            for rec in users.values():
                out.append(self._user_inventory(rec, now, bucket, labels))
                self.inventories_emitted += 1

        for payload in self._group_inventory(groups, now, bucket, labels):
            out.append(payload)
            self.group_queries_emitted += 1

        out.append(self._policy_state(modals, now, bucket, labels))
        return out

    def _user_inventory(
        self,
        rec: dict[str, Any],
        now: float,
        bucket: int,
        labels: list[str],
    ) -> dict[str, Any]:
        """One account, restated. 5003 activity 2 Collect.

        ``Collect`` and not ``Log``: the collector went and read the state. ``Log``
        would say a log of the inventory was received, which is a different provenance
        and the wrong one.

        5003 *does* carry ``user``, unlike 5017, so the principal goes in ``user_*``
        here and in ``actor_user_*`` there. That asymmetry is not a style choice — it
        is what the two classes declare, and putting ``user_name`` on a 5017 would
        produce invalid OCSF that the event model stores without complaint.
        """
        notes: list[str] = []
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _USER_INV,
            "activity_id": _COLLECT,
            "message": f"Local account inventory: {rec['name']}",
            "metadata_uid": (
                f"{_hostname()}:account_inventory:{rec['key']}:{bucket}"),
        })
        payload["metadata_labels"].extend(["state_observed"] + labels)
        self._user_fields(rec, payload, notes)
        notes.append(
            "state, not an event: this is the account as it exists now, on the "
            "inventory beat. It is a Discovery class so that a rule counting account "
            "creations never counts it"
        )
        payload["soc_notes"] = notes
        return payload

    def _group_inventory(
        self,
        groups: dict[str, dict[str, Any]],
        now: float,
        bucket: int,
        labels: list[str],
    ) -> list[dict[str, Any]]:
        """One 5009 per privileged group, plus one per privileged RID that is absent.

        The absent ones matter as much as the present ones and are the reason
        ``query_result_id`` is on this class. Five of the twelve RIDs in
        :data:`PRIVILEGED_GROUP_RIDS` do not exist on this host. A collector that
        silently skipped them would leave a coverage report unable to distinguish
        "Backup Operators has no members" from "Backup Operators does not exist" from
        "Backup Operators could not be read" — three states with three completely
        different meanings, all of which arrive as a lookup that returned nothing.
        """
        out: list[dict[str, Any]] = []
        seen_rids = {g["rid"] for g in groups.values() if g["rid"] is not None}

        for rec in groups.values():
            why = self._privilege_reason(rec)
            if why is None:
                continue
            notes: list[str] = []
            payload = self._base(now)
            if rec["error"]:
                result = int(QueryResultId.ERROR)
                severity = int(Severity.LOW)
                notes.append(
                    f"this group exists and its membership could not be read "
                    f"({rec['error']}). It is reported as ERROR and not as empty: an "
                    "unreadable privileged group and an empty one are the same absence "
                    "of members and opposite facts about the host"
                )
            else:
                result = int(QueryResultId.EXISTS)
                severity = int(Severity.INFORMATIONAL)
            payload.update({
                "time": now,
                "class_uid": _GROUP_QUERY,
                "activity_id": _QUERY,
                "query_result_id": result,
                "severity_id": severity,
                "group_name": rec["name"],
                "message": (
                    f"Privileged group membership: {rec['name']} "
                    f"({len(rec['members'])} member(s))"),
                "metadata_uid": (
                    f"{_hostname()}:group_query:{rec['key']}:{bucket}"),
            })
            payload["metadata_labels"].extend(["state_observed"] + labels)
            if rec["sid"]:
                payload["group_uid"] = rec["sid"]
            if rec["rid"] is not None:
                payload["group_uid_numeric"] = rec["rid"]
            if rec["comment"]:
                payload["group_desc"] = rec["comment"]
            payload["unmapped"]["privilege_reason"] = why
            payload["unmapped"]["member_count"] = len(rec["members"])
            payload["unmapped"]["members"] = [
                {"name": m["name"], "domain": m["domain"], "sid": m["sid"],
                 "rid": m["rid"]}
                for m in sorted(rec["members"].values(), key=lambda m: m["name"])
            ]
            notes.append(f"privileged because: {why}")
            payload["soc_notes"] = notes
            out.append(payload)

        for rid, why in sorted(PRIVILEGED_GROUP_RIDS.items()):
            if rid in seen_rids:
                continue
            self.missing_privileged_rids += 1
            payload = self._base(now)
            payload.update({
                "time": now,
                "class_uid": _GROUP_QUERY,
                "activity_id": _QUERY,
                "query_result_id": int(QueryResultId.DOES_NOT_EXIST),
                "severity_id": int(Severity.INFORMATIONAL),
                "group_uid_numeric": rid,
                "message": f"Privileged group RID {rid} does not exist on this host",
                "metadata_uid": f"{_hostname()}:group_absent:{rid}:{bucket}",
            })
            payload["metadata_labels"].extend(["state_observed"] + labels)
            payload["unmapped"]["privilege_reason"] = why
            payload["soc_notes"] = [
                f"RID {rid} was not produced by NetLocalGroupEnum, so the group does "
                "not exist here — which is the normal case on a workstation and is "
                "reported as DOES_NOT_EXIST rather than as an empty group or a read "
                "error. The distinction is the whole reason this event is emitted: a "
                "group that does not exist cannot gain a member, and one that could "
                "not be read might have gained one unseen"
            ]
            out.append(payload)
        return out

    def _privilege_reason(self, rec: dict[str, Any]) -> str | None:
        """Why this group is privileged, or ``None``.

        RID first, name second, and never both — see the ordering note on
        :data:`PRIVILEGED_GROUP_NAMES`. Checking both would double-report Hyper-V
        Administrators, which has a well-known RID *and* a recognisable name.
        """
        rid = rec.get("rid")
        if rid is not None and rid in PRIVILEGED_GROUP_RIDS:
            return PRIVILEGED_GROUP_RIDS[rid]
        return PRIVILEGED_GROUP_NAMES.get(rec["key"])

    def _policy_state(
        self,
        modals: dict[str, Any],
        now: float,
        bucket: int,
        labels: list[str],
    ) -> dict[str, Any]:
        """The password and lockout policy, as state. 5002, activity 2 Collect.

        Note there is **no** ``query_result_id`` here: 5002 ``config_state`` does not
        carry that attribute — only the Query classes (5009, 5017) do. Setting it would
        be invalid OCSF that the event model would silently file under ``unmapped``,
        which is exactly the class of defect the per-class attribute check in the test
        suite exists to catch. Partial readability is recorded in ``policy_levels_read``
        instead.
        """
        notes: list[str] = []
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _CONFIG_STATE,
            "activity_id": _COLLECT,
            "policy_name": "Local password and lockout policy",
            "policy_uid": f"{_hostname()}:NetUserModalsGet",
            "policy_desc": self._policy_summary(modals),
            "policy_is_applied": True,
            "message": "Local password and lockout policy observed",
            "metadata_uid": f"{_hostname()}:password_policy:{bucket}",
        })
        payload["metadata_labels"].extend(
            ["state_observed", "password_policy"] + labels)
        payload["unmapped"].update(self._policy_fields(modals))
        self._note_policy_findings(modals, payload, notes)
        levels = modals.get("_levels") or []
        if 0 not in levels or 3 not in levels:
            notes.append(
                f"only NetUserModalsGet level(s) {levels} could be read, so the policy "
                "below is partial. Level 0 carries the password rules and level 3 the "
                "lockout rules; an absent half is absent from the record rather than "
                "reported as zero, which would read as 'lockout is disabled'"
            )
            _raise_severity(payload, int(Severity.LOW))
        notes.append(
            "state, not an event. A change in this policy emits a separate 5019 "
            "Device Config State Change; this event is the standing statement of what "
            "the policy is"
        )
        payload["soc_notes"] = notes
        return payload

    def _policy_fields(self, modals: dict[str, Any]) -> dict[str, Any]:
        """The policy as plain values, with the sentinels named rather than converted.

        ``force_logoff`` and ``max_passwd_age`` both use ``TIMEQ_FOREVER``
        (``0xFFFFFFFF``) for "never" — measured on this host. Leaving it as 4294967295
        would make a range query for "policies with a max password age under a year"
        exclude the hosts where passwords never expire, which is the population the
        query is looking for.
        """
        out: dict[str, Any] = {}
        for key, value in modals.items():
            if key.startswith("_"):
                continue
            if isinstance(value, int) and value == 0xFFFFFFFF:
                out[key] = "never"
                out[f"{key}_raw"] = value
            else:
                out[key] = value
        out["policy_levels_read"] = modals.get("_levels") or []
        for level in (0, 3):
            err = modals.get(f"_level{level}_error")
            if err:
                out[f"policy_level{level}_error"] = err
        return out

    def _policy_summary(self, modals: dict[str, Any]) -> str:
        parts: list[str] = []
        if "min_passwd_len" in modals:
            parts.append(f"min length {modals['min_passwd_len']}")
        if "password_hist_len" in modals:
            parts.append(f"history {modals['password_hist_len']}")
        if "max_passwd_age" in modals:
            age = modals["max_passwd_age"]
            parts.append(
                "max age never" if age in (0, 0xFFFFFFFF)
                else f"max age {int(age) // 86400}d")
        if "lockout_threshold" in modals:
            threshold = modals["lockout_threshold"]
            parts.append(
                "lockout disabled" if threshold == 0
                else f"lockout after {threshold}")
        return ", ".join(parts) or "unreadable"

    def _note_policy_findings(
        self, modals: dict[str, Any], payload: dict[str, Any], notes: list[str]
    ) -> None:
        for field, predicate, text, floor in POLICY_FINDINGS:
            if field not in modals:
                continue
            try:
                hit = bool(predicate(modals[field]))
            except Exception:
                continue
            if hit:
                self.policy_findings += 1
                notes.append(f"{field}: {text}")
                _raise_severity(payload, floor)

    # ── diffing accounts ───────────────────────────────────────────────────

    def _diff_users(
        self, users: dict[str, dict[str, Any]], now: float
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        was = self._users
        spray_candidates: list[tuple[str, int]] = []

        for key, rec in users.items():
            prior = was.get(key)
            if prior is None:
                out.append(self._user_change(
                    rec, now, activity_id=1, verb="created",
                    severity=int(Severity.MEDIUM),
                    note=(
                        "a local account was created. T1136.001 Create Account: Local "
                        "Account — this is a standard persistence step, and on a "
                        "workstation a new local account is rarely legitimate "
                        "configuration. Who created it is not knowable from a state "
                        "diff; 4720 would have named the subject"
                    ),
                    attack="T1136.001",
                ))
                self.users_created += 1
                continue
            out.extend(self._user_transitions(prior, rec, now))
            failures = self._failure_delta(prior, rec)
            if failures > 0:
                spray_candidates.append((rec["key"], failures))
            success = self._success_delta(prior, rec)
            if success > 0:
                out.append(self._success_event(rec, success, now))
                self.success_auth_events += 1

        for key, prior in was.items():
            if key in users:
                continue
            out.append(self._user_change(
                prior, now, activity_id=3, verb="deleted",
                severity=int(Severity.MEDIUM),
                note=(
                    "a local account was deleted. Deletion after use is an "
                    "anti-forensic step as often as it is cleanup, and the account's "
                    "SID is recorded here because it is the only thing that will still "
                    "join this record to whatever the account did while it existed"
                ),
                attack="T1070",
            ))
            self.users_deleted += 1

        out.extend(self._failure_events(users, spray_candidates, now))
        return out

    def _user_transitions(
        self, prior: dict[str, Any], rec: dict[str, Any], now: float
    ) -> list[dict[str, Any]]:
        """Everything one account can become between two polls.

        Order matters. The specific transitions are emitted first and the catch-all
        Update last, and the Update is suppressed when a specific one already fired —
        otherwise every disable would produce both a Disable and an Update and double
        every account-management metric.
        """
        out: list[dict[str, Any]] = []
        specific = False
        was_flags = int(prior.get("flags") or 0)
        now_flags = int(rec.get("flags") or 0)

        if prior.get("sid") and rec.get("sid") and prior["sid"] != rec["sid"]:
            # The name is unchanged and the SID is not. This is a delete and a create
            # that a name-keyed diff reports as nothing at all.
            out.append(self._user_change(
                rec, now, activity_id=1, verb="recreated",
                severity=int(Severity.HIGH),
                note=(
                    f"this account name now has a different SID ({prior['sid']} → "
                    f"{rec['sid']}), which means the account was deleted and recreated "
                    "between two polls. Every ACL, group membership and audit record "
                    "keyed to the old SID no longer refers to this account, and a "
                    "diff keyed on the name alone would have reported no change at "
                    "all. T1098 Account Manipulation"
                ),
                attack="T1098",
            ))
            out[-1]["unmapped"]["previous_user_sid"] = prior["sid"]
            specific = True

        if (was_flags & 0x0002) and not (now_flags & 0x0002):
            payload = self._user_change(
                rec, now, activity_id=4, verb="enabled",
                severity=int(Severity.MEDIUM),
                note=(
                    "a disabled local account was enabled. Re-enabling a dormant "
                    "account is quieter than creating one and leaves the account's own "
                    "history intact as cover. T1098 Account Manipulation"
                ),
                attack="T1098",
            )
            # A weakness that was suppressed while the account was disabled becomes
            # live at this exact moment, so the enable inherits the flag's severity
            # rather than the enable's.
            for bit, (text, floor) in UF_FINDINGS.items():
                if now_flags & bit:
                    payload.setdefault("soc_notes", []).append(
                        f"and it carries {text} — which was reported as "
                        "informational while the account was disabled and is "
                        "exploitable from now on"
                    )
                    _raise_severity(payload, floor)
            out.append(payload)
            self.users_enabled += 1
            specific = True
        elif not (was_flags & 0x0002) and (now_flags & 0x0002):
            out.append(self._user_change(
                rec, now, activity_id=5, verb="disabled",
                severity=int(Severity.LOW),
                note=(
                    "a local account was disabled. Usually administration; "
                    "occasionally an attacker denying an administrator access to their "
                    "own host"
                ),
            ))
            self.users_disabled += 1
            specific = True

        if not (was_flags & 0x0010) and (now_flags & 0x0010):
            out.append(self._user_change(
                rec, now, activity_id=6, verb="locked out",
                severity=int(Severity.MEDIUM),
                note=(
                    "the account is locked out, which means the lockout threshold of "
                    "failed authentications was reached. This is 4740 without the "
                    "Security channel, and it is a *consequence* of guessing rather "
                    "than a record of it — bad_pw_count on this same account is the "
                    "count"
                ),
                attack="T1110",
            ))
            self.users_locked += 1
            specific = True
        elif (was_flags & 0x0010) and not (now_flags & 0x0010):
            out.append(self._user_change(
                rec, now, activity_id=7, verb="unlocked",
                severity=int(Severity.LOW),
                note=(
                    "the account is no longer locked out. Windows clears this "
                    "automatically after the lockout duration, so this is not "
                    "necessarily an administrative action"
                ),
            ))
            self.users_unlocked += 1
            specific = True

        if self._password_changed(prior, rec, now):
            payload = self._user_change(
                rec, now, activity_id=8, verb="password changed",
                severity=int(Severity.LOW),
                note=(
                    "the password was set between these two polls (password_age reset). "
                    "**NetUserEnum cannot say who set it.** 4723 (the user changed "
                    "their own) and 4724 (an administrator reset another user's) are "
                    "different events with very different meanings — the second is a "
                    "standard account-takeover step — and both appear here identically, "
                    "as activity 8 Password Change. The distinction is lost, not "
                    "guessed"
                ),
                attack="T1098",
            )
            if rec.get("password_set_at") is not None:
                payload["unmapped"]["password_set_at"] = rec["password_set_at"]
            if prior.get("password_age") is not None:
                payload["unmapped"]["previous_password_age_seconds"] = (
                    prior["password_age"])
            out.append(payload)
            self.password_changes += 1
            specific = True

        if prior.get("priv") != rec.get("priv"):
            was_priv = prior.get("priv")
            now_priv = rec.get("priv")
            escalation = isinstance(now_priv, int) and isinstance(was_priv, int) \
                and now_priv > was_priv
            out.append(self._user_change(
                rec, now,
                activity_id=14 if escalation else 15,
                verb=("privilege raised" if escalation else "privilege reduced"),
                severity=(int(Severity.HIGH) if escalation else int(Severity.LOW)),
                note=(
                    f"USER_INFO_3.priv changed from "
                    f"{USER_PRIV.get(was_priv, was_priv)} to "
                    f"{USER_PRIV.get(now_priv, now_priv)}. "
                    + ("This is a direct privilege grant on the account object itself, "
                       "which is separate from group membership: an account can become "
                       "an administrator this way without appearing in the "
                       "Administrators group. T1098 Account Manipulation"
                       if escalation else
                       "A reduction, which is normally remediation")
                ),
                attack="T1098" if escalation else "",
            ))
            if escalation:
                self.privilege_grants += 1
            specific = True

        changed = self._other_changes(prior, rec)
        if changed and not specific:
            payload = self._user_change(
                rec, now, activity_id=2, verb="updated",
                severity=int(Severity.LOW),
                note=(
                    "account attributes changed with no more specific meaning "
                    "available. The changed fields are listed in "
                    "unmapped.changed_fields with before and after values"
                ),
            )
            payload["unmapped"]["changed_fields"] = changed
            out.append(payload)
            self.users_updated += 1
        elif changed:
            # Not dropped — attached to whichever specific event fired, so the record
            # is complete without inventing a second event for the same transition.
            out[-1]["unmapped"]["changed_fields"] = changed
        return out

    def _password_changed(
        self, prior: dict[str, Any], rec: dict[str, Any], now: float
    ) -> bool:
        """Whether the password was set (or removed) between these two polls.

        ``password_age`` counts up, so the set time it implies is
        ``observed_at - age``. A change is when that set time jumped forward past the
        previous set time — comparing the *ages* directly would be wrong, because
        ``password_age`` is quantised and grows by about the poll interval between
        polls, so "same age across 300s" is a password change under a naive
        smaller-than comparison and "no change" under an equal comparison. Comparing
        the implied set moments gets both right without needing to know which.

        One value is not a time at all: **0**. On this host three accounts — Guest,
        DefaultAccount and the interactive account — report ``password_age`` of 0.
        0 means "no password is set, or the last-set time cannot be determined". It
        does *not* mean "set zero seconds ago", which is what the arithmetic above
        would take it to be, and if it did every one of those accounts would report a
        password change on every single poll, forever, until an operator learned to
        ignore this collector. So 0 is compared as a category: 0→positive means a
        password appeared (a set), positive→0 means it was removed or became
        undeterminable, and 0→0 is no change.

        The tolerance is deliberately generous — Windows reports the age at second
        granularity and the poll interval is never exact — because a false positive
        here says "someone reset this password", which starts an investigation.
        """
        was_age = prior.get("password_age")
        now_age = rec.get("password_age")
        if not isinstance(was_age, int) or not isinstance(now_age, int):
            return False
        tolerance = max(60.0, self.cadence_seconds / 5.0)
        if was_age == 0:
            # From "no password / undetermined" to a real age: something was set. The
            # implied set moment is now - now_age and no comparison is needed, because
            # if the password had existed at the previous poll the previous age would
            # not have been 0.
            return now_age > 0
        if now_age == 0:
            # To "no password / undetermined": removed, or the account changed shape.
            return True
        tset_before = float(prior.get("_observed_at") or now) - was_age
        tset_now = now - now_age
        return tset_now > tset_before + tolerance

    def _other_changes(
        self, prior: dict[str, Any], rec: dict[str, Any]
    ) -> dict[str, Any]:
        """Fields that changed and are not covered by a specific transition.

        The excluded set is exactly the fields whose movement is either already
        reported as its own event or is *expected* to move on every poll. Leaving
        ``password_age`` in would report every account as updated every five minutes,
        which would bury the changes that mean something under the ones that always
        happen.
        """
        skip = {
            "password_age", "password_set_at", "bad_pw_count", "num_logons",
            "last_logon", "last_logoff", "key", "_observed_at", "priv", "flags",
        }
        out: dict[str, Any] = {}
        for field, value in rec.items():
            if field in skip:
                continue
            before = prior.get(field)
            if before != value:
                out[field] = {"before": before, "after": value}
        # Flags are compared bit-wise rather than numerically, because "66051 became
        # 66049" is unreadable and "ACCOUNTDISABLE cleared" is not.
        was_flags = int(prior.get("flags") or 0)
        now_flags = int(rec.get("flags") or 0)
        if was_flags != now_flags:
            delta = was_flags ^ now_flags
            set_now = [n for b, n in UF_FLAGS.items() if delta & b and now_flags & b]
            cleared = [n for b, n in UF_FLAGS.items() if delta & b and was_flags & b]
            unknown = delta & ~sum(UF_FLAGS)
            entry: dict[str, Any] = {"before": was_flags, "after": now_flags}
            if set_now:
                entry["set"] = set_now
            if cleared:
                entry["cleared"] = cleared
            if unknown:
                entry["unknown_bits"] = f"0x{unknown:X}"
            out["flags"] = entry
        return out

    # ── authentication counters ────────────────────────────────────────────

    def _failure_delta(self, prior: dict[str, Any], rec: dict[str, Any]) -> int:
        """The rise in ``bad_pw_count``, or 0.

        Only a rise counts. ``bad_pw_count`` resets to zero on a successful
        authentication and after the lockout observation window elapses, so a *fall* is
        a reset and says nothing — reporting a negative delta as failures, or taking
        ``abs()``, would turn every successful logon into a burst of failures.
        """
        was = prior.get("bad_pw_count")
        current = rec.get("bad_pw_count")
        if not isinstance(was, int) or not isinstance(current, int):
            return 0
        return current - was if current > was else 0

    def _success_delta(self, prior: dict[str, Any], rec: dict[str, Any]) -> int:
        was = prior.get("num_logons")
        current = rec.get("num_logons")
        if not isinstance(was, int) or not isinstance(current, int):
            return 0
        return current - was if current > was else 0

    def _failure_events(
        self,
        users: dict[str, dict[str, Any]],
        candidates: list[tuple[str, int]],
        now: float,
    ) -> list[dict[str, Any]]:
        """``bad_pw_count`` rises as authentication failures. The spray substitute.

        One account rising is a wrong password. Several accounts rising *in the same
        poll interval* is a password spray, and that shape — breadth rather than depth
        — is the whole signature: a spray tries two passwords against a hundred
        accounts precisely to stay under every per-account lockout threshold, so the
        per-account counts stay small and unremarkable and only the count of *accounts*
        moves.

        On a host where 4625 is unreadable this is the only spray detection available.
        It is also, for this specific purpose, better than 4625 would be: the count is
        already per-account state, so no windowed aggregation is needed and no failure
        can be missed by falling outside a window.
        """
        out: list[dict[str, Any]] = []
        if not candidates:
            return out

        spray = len(candidates) >= 3
        total = sum(count for _, count in candidates)
        for key, count in candidates:
            rec = users[key]
            notes: list[str] = []
            payload = self._base(now)
            payload.update({
                "time": now,
                "class_uid": _AUTH,
                "activity_id": 1,  # Logon
                "status_id": _FAILURE,
                # Base-event `count` in its actual meaning: this one record stands for
                # `count` repetitions of the same event. That is precisely what a
                # bad_pw_count delta is, so this is the correct field and not a reuse
                # of it.
                "count": count,
                "message": (
                    f"{count} failed authentication(s) against local account "
                    f"{rec['name']}"),
            })
            payload["metadata_labels"].extend(
                ["substitute_for:4625", "bad_pw_count_delta"])
            if spray:
                payload["metadata_labels"].append("password_spray")
            self._user_fields(rec, payload, notes, prefix="user")
            payload["unmapped"]["bad_pw_count"] = rec.get("bad_pw_count")
            payload["unmapped"]["failure_delta"] = count
            notes.append(
                f"bad_pw_count rose by {count} for this account between two polls "
                f"{self.cadence_seconds:g}s apart. The count is exact; the *times* of "
                "the individual failures are not available — NetUserEnum exposes a "
                "counter, not events — so all of them are reported at the observation "
                "time with count=" f"{count}. 4625 would have dated each one"
            )
            if spray:
                names = ", ".join(sorted(users[k]["name"] for k, _ in candidates))
                notes.append(
                    f"**password spray**: {len(candidates)} local accounts "
                    f"({names}) all accumulated authentication failures in the same "
                    f"{self.cadence_seconds:g}s interval, {total} in total. Breadth "
                    "across accounts with small per-account counts is the spray "
                    "signature — it is how the attempt stays under each account's "
                    "lockout threshold. T1110.003 Password Spraying"
                )
                _attack(payload, "T1110.003")
                _raise_severity(payload, int(Severity.HIGH))
            else:
                _attack(payload, "T1110")
                _raise_severity(
                    payload,
                    int(Severity.MEDIUM) if count >= 5 else int(Severity.LOW))
            payload["soc_notes"] = notes
            out.append(payload)
            self.failed_auth_events += 1
        if spray:
            self.spray_events += 1
        return out

    def _success_event(
        self, rec: dict[str, Any], count: int, now: float
    ) -> dict[str, Any]:
        """``num_logons`` rises as successful authentications.

        The time is where this event is honest and weak at once. ``last_logon`` is a
        real timestamp and is used when it falls inside the interval that was actually
        observed; when the delta is greater than one, only the last of them has a time
        and the rest have none, so the event carries ``count`` and says the earlier
        ones are undated.
        """
        notes: list[str] = []
        payload = self._base(now)
        last = rec.get("last_logon")
        use_last = (
            isinstance(last, float)
            and count == 1
            and last <= now + 1.0
            and last >= now - (self.cadence_seconds + self._poll_seconds + 60.0)
        )
        payload.update({
            "time": last if use_last else now,
            "class_uid": _AUTH,
            "activity_id": 1,  # Logon
            "status_id": _SUCCESS,
            "count": count,
            "message": (
                f"{count} successful authentication(s) by local account {rec['name']}"),
        })
        payload["metadata_labels"].extend(
            ["substitute_for:4624", "num_logons_delta"])
        self._user_fields(rec, payload, notes, prefix="user")
        payload["unmapped"]["num_logons"] = rec.get("num_logons")
        payload["unmapped"]["logon_delta"] = count
        if use_last:
            notes.append(
                "num_logons rose by 1 and last_logon falls inside the observed "
                "interval, so the event time is the real logon time"
            )
        else:
            notes.append(
                f"num_logons rose by {count}, so this record stands for {count} "
                "authentications. Only the most recent of them has a timestamp "
                "(last_logon), so the event time is the observation time and the "
                "earlier logons are undated. The logon type, the source address and "
                "the authentication package are not available from this counter at "
                "all — LogonSessionCollector and 4624 are what carry those"
            )
        payload["soc_notes"] = notes
        return payload

    # ── diffing groups ─────────────────────────────────────────────────────

    def _diff_groups(
        self, groups: dict[str, dict[str, Any]], now: float
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        was = self._groups

        for key, rec in groups.items():
            prior = was.get(key)
            if prior is None:
                out.append(self._group_change(
                    rec, now, activity_id=6, verb="created",
                    severity=int(Severity.LOW),
                    note=(
                        "a local group was created. Usually an installer; occasionally "
                        "a place to hide membership that nobody audits"
                    ),
                ))
                self.groups_created += 1
                continue
            if rec["error"] or prior["error"]:
                # One side's membership is unknown, so a member diff would invent
                # additions or removals from an absence of data. The 5009 with
                # query_result_id ERROR already reports the loss of visibility.
                continue
            for sid, member in rec["members"].items():
                if sid in prior["members"]:
                    continue
                out.append(self._member_change(
                    rec, member, now, activity_id=3, verb="added to", groups=groups))
                self.group_adds += 1
            for sid, member in prior["members"].items():
                if sid in rec["members"]:
                    continue
                out.append(self._member_change(
                    rec, member, now, activity_id=4, verb="removed from",
                    groups=groups))
                self.group_removes += 1

        for key, prior in was.items():
            if key in groups:
                continue
            out.append(self._group_change(
                prior, now, activity_id=5, verb="deleted",
                severity=(int(Severity.MEDIUM) if self._privilege_reason(prior)
                          else int(Severity.LOW)),
                note=(
                    "a local group was deleted, and with it every access decision that "
                    "depended on its membership"
                ),
            ))
            self.groups_deleted += 1
        return out

    def _member_change(
        self,
        rec: dict[str, Any],
        member: dict[str, Any],
        now: float,
        *,
        activity_id: int,
        verb: str,
        groups: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """A membership change. 3006 activity 3 Add User / 4 Remove User."""
        why = self._privilege_reason(rec)
        notes: list[str] = []
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _GROUP,
            "activity_id": activity_id,
            "status_id": _SUCCESS,
            "group_name": rec["name"],
            "message": (
                f"{member['name']} was {verb} local group {rec['name']}"),
            "metadata_uid": (
                f"{_hostname()}:group_member:{rec['key']}:"
                f"{member['sid'] or member['name']}:{activity_id}:{now:.3f}"),
        })
        payload["metadata_labels"].append("substitute_for:4732,4733")
        if rec["sid"]:
            payload["group_uid"] = rec["sid"]
        if rec["rid"] is not None:
            payload["group_uid_numeric"] = rec["rid"]
        if member["name"]:
            payload["user_name"] = member["name"]
        if member["domain"]:
            payload["user_domain"] = member["domain"]
        if member["sid"]:
            payload["user_uid"] = member["sid"]
        if member["rid"] is not None:
            payload["user_uid_numeric"] = member["rid"]
        if member.get("sid_type") is not None:
            payload["unmapped"]["member_sid_type"] = member["sid_type"]

        if why:
            payload["metadata_labels"].append("privileged_group")
            payload["unmapped"]["privilege_reason"] = why
            if activity_id == 3:
                _raise_severity(payload, int(Severity.HIGH))
                _attack(payload, "T1098")
                notes.append(
                    f"this is a **privileged** group: {why}. Adding an account to it "
                    "is a privilege escalation and T1098 Account Manipulation, and on "
                    "a workstation it is rarely legitimate configuration"
                )
            else:
                _raise_severity(payload, int(Severity.MEDIUM))
                notes.append(
                    f"this is a privileged group (removal): {why}. A removal is usually "
                    "remediation, and is occasionally an attacker locking an "
                    "administrator out of their own host"
                )
        else:
            _raise_severity(payload, int(Severity.LOW))
            notes.append(
                "this group is not in the privileged set, so the change is recorded "
                "and not raised. Privilege is decided by well-known RID first and by "
                "name only as a fallback, because group names are localised — "
                "Administrators is Administratoren on a German install"
            )
        notes.append(
            "who made this change is not knowable from a state diff. 4732/4733 carry "
            "the subject that performed the membership change; comparing two snapshots "
            "carries only the difference, so `actor` is deliberately empty rather than "
            "filled with this collector's own identity"
        )
        payload["soc_notes"] = notes
        return payload

    def _group_change(
        self,
        rec: dict[str, Any],
        now: float,
        *,
        activity_id: int,
        verb: str,
        severity: int,
        note: str,
    ) -> dict[str, Any]:
        notes = [note, "who did it is not available from a state diff — see the "
                       "collector's limitations"]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _GROUP,
            "activity_id": activity_id,
            "status_id": _SUCCESS,
            "severity_id": severity,
            "group_name": rec["name"],
            "message": f"Local group {rec['name']} was {verb}",
            "metadata_uid": (
                f"{_hostname()}:group:{rec['key']}:{activity_id}:{now:.3f}"),
        })
        payload["metadata_labels"].append("substitute_for:4731,4734")
        if rec["sid"]:
            payload["group_uid"] = rec["sid"]
        if rec["rid"] is not None:
            payload["group_uid_numeric"] = rec["rid"]
        if rec["comment"]:
            payload["group_desc"] = rec["comment"]
        why = self._privilege_reason(rec)
        if why:
            payload["metadata_labels"].append("privileged_group")
            payload["unmapped"]["privilege_reason"] = why
            notes.append(f"privileged group: {why}")
        payload["unmapped"]["member_count"] = len(rec["members"])
        payload["soc_notes"] = notes
        return payload

    # ── diffing policy ─────────────────────────────────────────────────────

    def _diff_policy(
        self, modals: dict[str, Any], now: float
    ) -> list[dict[str, Any]]:
        """A policy change is 5019, not another 5002.

        5002 says what the policy is; 5019 says that it moved. Emitting only 5002 would
        make "the lockout threshold was weakened at 14:20" a question answerable solely
        by diffing two heartbeats, and the answer would be missed entirely if the change
        was made and reverted between them. The moment of change is its own record.
        """
        was = self._modals
        if not was:
            return []
        changed: dict[str, Any] = {}
        for key, value in modals.items():
            if key.startswith("_"):
                continue
            if key in was and was[key] != value:
                changed[key] = {"before": was[key], "after": value}
        for key in was:
            if key.startswith("_") or key in modals:
                continue
            changed[key] = {"before": was[key], "after": None}
        if not changed:
            return []

        self.policy_changes += 1
        notes: list[str] = [
            "the local password or lockout policy changed between two polls. Weakening "
            "it is a persistence and credential-access enabler — a lockout threshold of "
            "0 makes online guessing unlimited, and a minimum length of 0 permits an "
            "empty password. T1484 Domain or Tenant Policy Modification is the closest "
            "technique; on a standalone host this is its local equivalent"
        ]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _CONFIG_CHANGE,
            "activity_id": _COLLECT,
            "severity_id": int(Severity.MEDIUM),
            "policy_name": "Local password and lockout policy",
            "policy_uid": f"{_hostname()}:NetUserModalsGet",
            "policy_desc": self._policy_summary(modals),
            "policy_is_applied": True,
            "message": (
                "Local password and lockout policy changed: "
                + ", ".join(sorted(changed))),
        })
        _attack(payload, "T1484")
        payload["metadata_labels"].extend(["password_policy", "policy_change"])
        # No metadata_uid. The identity of this event is the moment the policy moved,
        # which is what the pipeline's non-exact identity already expresses; an exact
        # uid built from the changed keys would dedup away a genuine change back to a
        # previous value.
        payload["unmapped"]["changed_fields"] = changed
        payload["unmapped"].update(self._policy_fields(modals))
        # state_id / security_states / prev_security_states are attributes 5019 does
        # carry, and they are deliberately not used: both are enum-bearing and the enums
        # are class-level, so they are not in the seven vendored enum tables and cannot
        # be verified here. Transcribing an unverified enum would put a number in a
        # field whose meaning is a guess. The before/after values above are exact.
        for field, predicate, text, floor in POLICY_FINDINGS:
            if field not in changed:
                continue
            after = changed[field]["after"]
            try:
                hit = bool(predicate(after))
            except Exception:
                continue
            if hit:
                self.policy_findings += 1
                notes.append(f"{field} was changed to a weak value — {text}")
                _raise_severity(payload, max(floor, int(Severity.HIGH)))
        payload["soc_notes"] = notes
        return [payload]

    # ── shared payload construction ────────────────────────────────────────

    def _base(self, now: float) -> dict[str, Any]:
        return {
            "severity_id": int(Severity.INFORMATIONAL),
            "device_hostname": _hostname(),
            "metadata_product_name": "Windows local accounts",
            "metadata_product_vendor_name": "Microsoft",
            "metadata_labels": [
                "local_accounts", "substitute_for:4720,4722,4725,4726,4732,4733,4740"],
            "unmapped": {},
        }

    def _user_change(
        self,
        rec: dict[str, Any],
        now: float,
        *,
        activity_id: int,
        verb: str,
        severity: int,
        note: str,
        attack: str = "",
    ) -> dict[str, Any]:
        notes = [note]
        payload = self._base(now)
        payload.update({
            "time": now,
            "class_uid": _USER,
            "activity_id": activity_id,
            "status_id": _SUCCESS,
            "severity_id": severity,
            "message": f"Local account {rec['name']} was {verb}",
            "metadata_uid": (
                f"{_hostname()}:local_account:{rec['key']}:{activity_id}:{now:.3f}"),
        })
        if attack:
            _attack(payload, attack)
        self._user_fields(rec, payload, notes)
        notes.append(
            "who made this change is not knowable from a state diff: 4720/4722/4724/"
            "4725/4726 all carry a Subject naming the account that performed the "
            "change, and comparing two snapshots carries only the difference. `actor` "
            "is left empty rather than filled with this collector's own identity, "
            "which would be a false attribution"
        )
        notes.append(
            f"the change happened at some point in the preceding "
            f"{self.blind_window_seconds:.0f}s; the event time is when it was observed"
        )
        payload["soc_notes"] = notes
        return payload

    def _user_fields(
        self,
        rec: dict[str, Any],
        payload: dict[str, Any],
        notes: list[str],
        *,
        prefix: str = "user",
    ) -> None:
        payload[f"{prefix}_name"] = rec["name"]
        payload[f"{prefix}_domain"] = _hostname()
        if rec.get("sid"):
            payload[f"{prefix}_uid"] = rec["sid"]
        if rec.get("rid") is not None:
            payload["user_uid_numeric"] = rec["rid"]
        if rec.get("full_name"):
            payload["user_full_name"] = rec["full_name"]
        for field, key in (
            ("comment", "account_comment"),
            ("home_dir", "home_dir"),
            ("profile", "profile_path"),
            ("workstations", "allowed_workstations"),
            ("logon_server", "logon_server"),
            ("primary_group_rid", "primary_group_rid"),
            ("bad_pw_count", "bad_pw_count"),
            ("num_logons", "num_logons"),
            ("last_logon", "last_logon"),
            ("last_logoff", "last_logoff"),
            ("acct_expires", "account_expires"),
            ("password_age", "password_age_seconds"),
            ("password_set_at", "password_set_at"),
        ):
            value = rec.get(field)
            if value not in (None, ""):
                payload["unmapped"][key] = value
        if rec.get("priv") is not None:
            payload["unmapped"]["priv"] = USER_PRIV.get(rec["priv"], rec["priv"])
        if rec.get("password_expired"):
            payload["unmapped"]["password_expired"] = True
        if rec.get("script_path"):
            payload["unmapped"]["logon_script"] = rec["script_path"]
            notes.append(
                f"a logon script is set on this account ({rec['script_path']!r}) — "
                "code that runs on every logon, and a documented persistence mechanism"
            )
            _raise_severity(payload, int(Severity.LOW))
        self._note_account_flags(rec, payload, notes)

    def _note_account_flags(
        self, rec: dict[str, Any], payload: dict[str, Any], notes: list[str]
    ) -> None:
        """Decode ``USER_INFO_3.flags`` and raise the flags that are weaknesses.

        The suppression on a disabled account is not leniency, it is accuracy. Guest
        (RID 501) and WsiAccount (RID 1008) both carry ``PASSWD_NOTREQD`` **and**
        ``ACCOUNTDISABLE`` on this stock install. Reported at face value that is two
        MEDIUM findings on a clean host at every single inventory beat, forever — the
        textbook way to teach an operator that this collector's findings are noise. A
        weakness on an account that cannot authenticate is not currently exploitable;
        it becomes exploitable the instant the account is enabled, which is why
        :meth:`_user_transitions` raises the *enable* event to the flag's own severity
        rather than dropping the finding.
        """
        flags = int(rec.get("flags") or 0)
        if flags == 0:
            return
        named = [name for bit, name in UF_FLAGS.items() if flags & bit]
        unknown = flags & ~sum(UF_FLAGS)
        payload["unmapped"]["account_flags"] = flags
        if named:
            payload["unmapped"]["account_flag_names"] = named
        if unknown:
            payload["unmapped"]["account_flags_unknown"] = f"0x{unknown:X}"
            notes.append(
                f"flags carries bits not in the UF_* table (0x{unknown:X}) — reported "
                "as a number rather than given a guessed name"
            )
        disabled = bool(flags & 0x0002)
        for bit, (text, floor) in UF_FINDINGS.items():
            if not flags & bit:
                continue
            if disabled:
                notes.append(
                    f"{text} — reported as informational because the account is "
                    "disabled and therefore cannot authenticate. This is not "
                    "currently exploitable and becomes a finding the moment the "
                    "account is enabled, which is why the enable event inherits this "
                    "severity"
                )
                _raise_severity(payload, int(Severity.INFORMATIONAL))
            else:
                notes.append(text)
                _raise_severity(payload, floor)

    # ── reporting ──────────────────────────────────────────────────────────

    def stats_extra(self) -> dict[str, Any]:
        privileged = sum(
            1 for g in self._groups.values() if self._privilege_reason(g))
        enabled = sum(
            1 for u in self._users.values() if not int(u.get("flags") or 0) & 0x0002)
        return {
            "accounts_total": len(self._users),
            "accounts_enabled": enabled,
            "accounts_disabled": len(self._users) - enabled,
            "groups_total": len(self._groups),
            "groups_privileged": privileged,
            "groups_unreadable": sum(
                1 for g in self._groups.values() if g["error"]),
            "privileged_rids_absent": self.missing_privileged_rids,
            "users_created": self.users_created,
            "users_deleted": self.users_deleted,
            "users_updated": self.users_updated,
            "users_enabled": self.users_enabled,
            "users_disabled": self.users_disabled,
            "users_locked_out": self.users_locked,
            "users_unlocked": self.users_unlocked,
            "password_changes": self.password_changes,
            "privilege_grants": self.privilege_grants,
            "sid_reuse_detected": self.sid_reuse_detected,
            "group_members_added": self.group_adds,
            "group_members_removed": self.group_removes,
            "groups_created": self.groups_created,
            "groups_deleted": self.groups_deleted,
            "failed_auth_events": self.failed_auth_events,
            "password_spray_intervals": self.spray_events,
            "success_auth_events": self.success_auth_events,
            "policy_changes": self.policy_changes,
            "policy_findings": self.policy_findings,
            "account_inventories_emitted": self.inventories_emitted,
            "group_queries_emitted": self.group_queries_emitted,
            "group_read_failures": self.group_read_failures,
            "sid_lookup_failures": self.sid_lookup_failures,
            "time_sentinels_rejected": self.time_sentinels_rejected,
            "blind_window_seconds": round(self.blind_window_seconds, 3),
            "blind_window_seconds_worst": round(self.blind_window_seconds_worst, 3),
            "first_poll_seconds": round(self._first_poll_seconds, 3),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Shared helpers and the factory
# ═══════════════════════════════════════════════════════════════════════════════


def _attack(payload: dict[str, Any], technique: str) -> None:
    """Record an ATT&CK technique hint on an event.

    There is no ``attack_technique`` field on :class:`Event` — checked, not assumed —
    and assigning one would not raise: the event model files unknown keys into
    ``unmapped``, so the technique would land under a key name nothing queries and the
    mapping would look present while being unreachable. This is the same failure mode
    as the ``query_result_id``-on-5002 mistake, and it is silent in exactly the same
    way.

    So the technique goes two places on purpose. ``metadata.labels`` carries
    ``attack:T1110.003``, which is a string set the lake can filter on directly — the
    coverage matrix in Phase 2 needs "which techniques has telemetry ever been seen
    for" and a label set answers that with one query. ``unmapped.attack_technique``
    carries the bare id for anything that wants it without parsing a prefix.

    This is a **collector's hint**, not an enrichment verdict: it says "the shape of
    this observation is what that technique looks like", which is weaker than a
    detection asserting the technique occurred. The detect layer overrides it; nothing
    downstream should treat it as an alert.
    """
    if not technique:
        return
    label = f"attack:{technique}"
    labels = payload.setdefault("metadata_labels", [])
    if label not in labels:
        labels.append(label)
    payload.setdefault("unmapped", {})["attack_technique"] = technique


def _to_epoch(value: Any) -> float | None:
    """A Windows time to a POSIX epoch, or ``None`` when it is not a time.

    Five things arrive in these fields across the two collectors and only one of them
    is a timestamp:

    * a tz-aware ``pywintypes.datetime`` — the real answer;
    * a **naive** ``datetime(9999, 12, 31, 23, 59, 59)``, which is LSA's "never":
      ``KickOffTime``, ``LogoffTime``, ``PasswordCanChange`` and ``PasswordMustChange``
      all carry it on a normal session. ``.timestamp()`` on it raises
      ``OSError [Errno 22]`` on Windows — measured — so this is a crash, not a wrong
      number, if it is not caught;
    * a tz-aware year-1601 datetime, which is the FILETIME zero and means "never
      happened". It converts *cleanly* to ``-11644473600.0``, which is the dangerous
      case: nothing raises, and the event model then rejects the whole event for a
      timestamp before 2000. Measured on ``PasswordLastSet`` and on both
      ``LastLogonInfo`` times;
    * an integer POSIX epoch from ``NetUserEnum`` level 3 — ``last_logon``,
      ``last_logoff``, ``acct_expires``;
    * one of the ``NetUserEnum`` sentinels: ``0`` for "never happened" on
      ``last_logon``/``last_logoff``, and ``0xFFFFFFFF`` (``TIMEQ_FOREVER``) on
      ``acct_expires`` and ``max_storage``. Both would pass as timestamps — 0 becomes
      1970 and 4294967295 becomes 2106 — and 1970 is before the event model's floor
      while 2106 is not, so one of them would be silently stored as a real date.

    The range check is what separates the plausible from the sentinel, and it is
    deliberately wide — 2000 to 2100 — because it is guarding against sentinels, not
    validating plausibility. Callers count every rejection, so a field that turns out
    to hold a real time outside that range shows up as a number rather than as silence.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if int(value) in _NET_TIME_SENTINELS:
            return None
        ts = float(value)
    else:
        try:
            ts = float(value.timestamp())
        except (OSError, OverflowError, ValueError, AttributeError):
            return None
    if not 946684800.0 <= ts <= 4102444800.0:
        return None
    return ts


def _clean(value: Any) -> str:
    """A Windows string field, with the placeholders Windows writes removed.

    Windows does not write empty; it writes ``-``, ``LOCAL``, ``Null``, ``\\\\*`` and
    ``::``. Each of those reaching a field means a rule matching on absence never
    matches, and one of them — ``-`` in an IP field — fails validation outright.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in _PLACEHOLDERS or text == "\\\\*":
        return ""
    return text


_HOSTNAME = ""


def _hostname() -> str:
    global _HOSTNAME
    if not _HOSTNAME:
        import socket

        try:
            _HOSTNAME = socket.gethostname()
        except Exception:
            _HOSTNAME = "unknown"
    return _HOSTNAME


def local_auth_collectors(pipeline: Any, **kwargs: Any) -> list[Any]:
    """All three identity collectors, in the order their coverage degrades.

    Three, not one, and the order is the argument for it. :class:`LocalAuthLogCollector`
    is the real thing — it reads the Security channel when the Security channel is
    readable, and everything it emits is a genuine Windows audit record with an actor
    and a source address. The other two are **substitutes**, and they exist because on
    this host, measured, the Security channel returns error 5 and 12 of 14 logon
    sessions are opaque. If the operator follows :data:`SECURITY_SETUP` the first
    collector's coverage grows and the substitutes become corroboration; until then
    they are the only identity telemetry there is.

    All three are returned unconditionally, including on non-Windows and including when
    the Security channel is unreadable. That is the whole point of
    :meth:`~ingest.collectors.base.Collector.probe`: a collector that reports itself
    unavailable with a reason and a fix is a *coverage gap the operator can see*,
    whereas a collector that is silently not constructed is a coverage gap that looks
    like completeness. The fleet decides what to run; this function decides what exists.

    ``kwargs`` are passed to every constructor, so ``agent_id=`` and ``clock=`` reach
    all three. Per-collector options are not plumbed through here — construct the class
    directly for those.
    """
    return [
        LocalAuthLogCollector(pipeline, **kwargs),
        LogonSessionCollector(pipeline, **kwargs),
        LocalAccountCollector(pipeline, **kwargs),
    ]


__all__ = [
    "AUTH_CHANNEL_SETUP",
    "AUTH_DATA_MAP",
    "AUTH_EVENT_MAP",
    "AUTH_PACKAGE_PROTOCOL",
    "KERBEROS_STATUS",
    "KERBEROS_STATUS_EVENTS",
    "KNOWN_PUBLISHERS",
    "LOGON_TYPE_MEANING",
    "LOGON_USER_FLAGS",
    "LOGON_USER_FLAG_FINDINGS",
    "LSA_SESSION_SETUP",
    "NOISY_EVENTS",
    "NTSTATUS_LOGON",
    "POLICY_FINDINGS",
    "PRIVILEGED_GROUP_NAMES",
    "PRIVILEGED_GROUP_RIDS",
    "SECURITY_CHANNEL",
    "SECURITY_SETUP",
    "UF_FINDINGS",
    "UF_FLAGS",
    "USER_PRIV",
    "WELL_KNOWN_LUIDS",
    "WTS_STATE",
    "LocalAccountCollector",
    "LocalAuthLogCollector",
    "LogonSessionCollector",
    "decode_status",
    "local_auth_channels",
    "local_auth_collectors",
    "parse_status_code",
]

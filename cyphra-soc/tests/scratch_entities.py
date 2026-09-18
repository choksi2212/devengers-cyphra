"""Scratch verification for core.schema.entities.

Two halves, deliberately. The *mechanical* half turns the module's claims into
properties checked against the real Event model and the real spec table, so a
renamed field or an invented OCSF path fails here rather than silently producing an
empty entity graph in Phase 3. The *behavioural* half exercises the four failures the
module exists to prevent: a DHCP lease attributed to the wrong host, a NAT gateway
collapsing a network into one entity, one account split across two nodes by case, and
an endpoint arriving as four fragments instead of one host.
"""

import sys
import time

sys.path.insert(0, ".")

from core.schema.entities import (
    CASE_INSENSITIVE_PLATFORMS,
    CROSS_ATTACH,
    FIELD_TO_IDENTIFIER,
    MIN_MERGE_DURABILITY,
    OBSERVABLE_TO_IDENTIFIER,
    PRIMARY_TYPES,
    SPECS,
    STRICT_SCOPE_KINDS,
    UNROUTABLE_SCOPES,
    AddressScope,
    Binding,
    Criticality,
    Entity,
    EntityError,
    EntityRef,
    EntityType,
    IdentifierSpec,
    IdKind,
    Identifier,
    MergeRefused,
    Platform,
    address_scope,
    case_collisions,
    cidr_reason,
    default_domain,
    entities_from_event,
    entity_key,
    fold_username,
    infer_platform,
    normalise,
    observations_from_event,
    scope_collisions,
    set_default_domain,
    spec,
    split_account,
)
from core.schema.ocsf import OCSF_PATH, Event

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


def raises(fn, exc=ValueError):
    """Whether calling fn raises exc, and the message if it did.

    ``ValueError`` rather than ``EntityError`` by default, because pydantic wraps a
    validator-raised EntityError into its own ValidationError. Both subclass
    ValueError, which is the one contract that covers `make()` and direct
    construction alike — and is what the module tells callers to catch.
    """
    try:
        fn()
    except exc as e:
        return True, str(e)
    except Exception as e:  # noqa: BLE001 - a different exception is still a failure
        return False, f"raised {type(e).__name__} instead: {e}"
    return False, "did not raise"


T0 = 1_756_000_000.0  # a fixed instant; nothing here depends on the wall clock
HOUR = 3600.0


def main():
    # ══════════════════════════════════════════════════════════════════════
    print("── the spec table is well-formed ──")

    check("every IdKind has a spec", set(SPECS) == set(IdKind),
          f"{len(SPECS)} specs for {len(IdKind)} kinds")
    check("every spec's entity_type is a real EntityType",
          all(isinstance(s.entity_type, EntityType) for s in SPECS.values()))
    check("every durability is on the 1..5 scale",
          all(1 <= s.durability <= 5 for s in SPECS.values()))
    check("every spec records its rationale",
          all(s.note.strip() for s in SPECS.values()),
          str([str(k) for k, s in SPECS.items() if not s.note.strip()]))
    check("spec() resolves a string and lists the valid kinds on a miss",
          spec("hostname").kind is IdKind.HOSTNAME
          and raises(lambda: spec("hostnaem"))[0]
          and "hostname" in raises(lambda: spec("hostnaem"))[1])

    # The merge floor is the single most consequential number in the module, so the
    # kinds it excludes are named rather than counted.
    below = {str(k) for k, s in SPECS.items() if not s.mergeable}
    check("the merge floor excludes exactly the forgeable and leased kinds",
          below == {"mac", "md5", "ip", "nat_ip"}, sorted(below))
    check("the merge floor is 4 and every other kind clears it",
          MIN_MERGE_DURABILITY == 4
          and all(s.durability >= 4 for k, s in SPECS.items() if str(k) not in below))
    check("strict scope is only the account kinds",
          {str(k) for k in STRICT_SCOPE_KINDS} == {"sam", "upn", "posix_user"},
          sorted(str(k) for k in STRICT_SCOPE_KINDS))
    check("strict_scope implies scoped",
          all(SPECS[k].scoped for k in STRICT_SCOPE_KINDS))

    ok, msg = raises(lambda: IdentifierSpec(IdKind.SAM, EntityType.USER, 9))
    check("a durability outside 1..5 is refused", ok and "1..5" in msg, msg[:50])
    ok, msg = raises(
        lambda: IdentifierSpec(IdKind.SAM, EntityType.USER, 4, strict_scope=True))
    check("strict_scope without scoped is refused", ok and "requires scoped" in msg)
    ok, msg = raises(lambda: IdentifierSpec(
        IdKind.SAM, EntityType.USER, 4, case_sensitive=True, case_insensitive=True))
    check("a kind cannot be both case-sensitive and case-insensitive", ok, msg[:60])

    # ── the type system ──
    check("there is no `device` entity type",
          not any(t == "device" for t in EntityType),
          "a device identifier is a HOST identifier — see the module docstring")
    check("every device-ish kind names a HOST",
          all(SPECS[k].entity_type is EntityType.HOST for k in
              (IdKind.MACHINE_UID, IdKind.DEVICE_GUID, IdKind.SERIAL,
               IdKind.HOSTNAME, IdKind.FQDN, IdKind.MAC)),
          "so an EDR id and a hostname can merge into one endpoint")
    check("machine_uid is the strongest host identifier",
          SPECS[IdKind.MACHINE_UID].durability == 5
          and SPECS[IdKind.MACHINE_UID].durability
          > SPECS[IdKind.HOSTNAME].durability)
    check("every entity type is named by at least one kind",
          {s.entity_type for s in SPECS.values()} == set(EntityType),
          str(set(EntityType) - {s.entity_type for s in SPECS.values()}))
    check("the primary types are the three correlation pivots",
          PRIMARY_TYPES == frozenset(
              {EntityType.HOST, EntityType.USER, EntityType.IP}))
    check("every cross-attachment maps real types both ways",
          all(isinstance(a, EntityType) and isinstance(b, EntityType)
              for a, b in CROSS_ATTACH.items())
          and len(CROSS_ATTACH) == 3, str({str(a): str(b) for a, b in CROSS_ATTACH.items()}))
    check("spoofable is a separate axis from durability",
          {str(k) for k, s in SPECS.items() if s.spoofable} == {"mac", "ip", "nat_ip"},
          "read by the response safety envelope, not by correlation")

    # ══════════════════════════════════════════════════════════════════════
    print("\n── the bridge is wired to fields that exist ──")

    real = set(Event.model_fields)
    bad_fields = sorted(f for f in FIELD_TO_IDENTIFIER if f not in real)
    check("every mapped flat field is a real Event field", not bad_fields, str(bad_fields))
    bad_scope = sorted(fm.scope_field for fm in FIELD_TO_IDENTIFIER.values()
                       if fm.scope_field and fm.scope_field not in real)
    check("every scope field is a real Event field", not bad_scope, str(bad_scope))
    check("every mapped kind is a real IdKind",
          all(isinstance(fm.kind, IdKind) for fm in FIELD_TO_IDENTIFIER.values()))
    check("every by_platform override is a real IdKind",
          all(isinstance(k, IdKind)
              for fm in FIELD_TO_IDENTIFIER.values() for k in fm.by_platform.values()))
    bad_obs = sorted(p for p in OBSERVABLE_TO_IDENTIFIER if p not in set(OCSF_PATH.values()))
    check("every observable path is one the event model actually emits",
          not bad_obs, str(bad_obs))
    check("the observable view is derived, not hand-maintained",
          len(OBSERVABLE_TO_IDENTIFIER) > 0
          and set(OBSERVABLE_TO_IDENTIFIER.values())
          <= {fm.kind for fm in FIELD_TO_IDENTIFIER.values()}
          | {k for fm in FIELD_TO_IDENTIFIER.values() for k in fm.by_platform.values()},
          f"{len(OBSERVABLE_TO_IDENTIFIER)} paths from "
          f"{len(FIELD_TO_IDENTIFIER)} fields")
    # The whole reason the table keys on flat fields: these carry identity and are
    # invisible to an observables-only bridge.
    non_obs = [f for f in FIELD_TO_IDENTIFIER if f not in OCSF_PATH]
    scope_only = [fm.scope_field for fm in FIELD_TO_IDENTIFIER.values() if fm.scope_field]
    check("the domain fields that qualify an account name are mapped as scope, not identity",
          set(scope_only) == {"device_domain", "src_endpoint_domain",
                              "dst_endpoint_domain", "actor_user_domain", "user_domain"},
          sorted(set(scope_only)))
    check("nothing identity-bearing is left unreachable",
          not non_obs, f"{len(FIELD_TO_IDENTIFIER)} fields, all resolvable")
    # Fields excluded on purpose. A port or a command line is evidence *about* an
    # entity and names none.
    for excluded in ("dst_endpoint_port", "process_cmd_line", "http_user_agent",
                     "file_name", "process_name"):
        if excluded in real:
            check(f"{excluded} is not treated as an identifier",
                  excluded not in FIELD_TO_IDENTIFIER)

    # ══════════════════════════════════════════════════════════════════════
    print("\n── normalisation: one thing must not become two ──")

    check("IPv4-mapped IPv6 collapses onto the IPv4 address",
          normalise(IdKind.IP, "::ffff:10.0.0.5") == "10.0.0.5",
          "a dual-stack host would otherwise appear twice")
    check("expanded and compressed IPv6 collapse",
          normalise(IdKind.IP, "2001:0db8:0000:0000:0000:0000:0000:0001")
          == normalise(IdKind.IP, "2001:db8::1") == "2001:db8::1")
    check("every MAC spelling collapses to one",
          len({normalise(IdKind.MAC, v) for v in
               ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF", "aabb.ccdd.eeff",
                "aabbccddeeff")}) == 1,
          normalise(IdKind.MAC, "aa-bb-cc-dd-ee-ff"))
    check("a hostname keeps only the short name",
          normalise(IdKind.HOSTNAME, "WS01.corp.example.com") == "ws01",
          "else ws01 and ws01.corp.example.com are two hosts")
    check("an fqdn keeps its whole name",
          normalise(IdKind.FQDN, "WS01.Corp.Example.COM.") == "ws01.corp.example.com")
    check("an email folds both parts",
          normalise(IdKind.EMAIL, "John.Doe@Example.COM") == "john.doe@example.com")
    check("a URL folds scheme and host but not the path",
          normalise(IdKind.URL, "HTTPS://Example.COM/Path/File.TXT")
          == "https://example.com/Path/File.TXT",
          "a path is case-sensitive on every server that matters")
    check("a SID is uppercased and shape-checked",
          normalise(IdKind.SID, "s-1-5-21-1-2-3-1001") == "S-1-5-21-1-2-3-1001"
          and raises(lambda: normalise(IdKind.SID, "not-a-sid"))[0])
    check("Sysmon's braces are stripped from a process guid",
          normalise(IdKind.PROCESS_UID, "{A1B2C3D4-0000-1111-2222-333344445555}")
          == "a1b2c3d4-0000-1111-2222-333344445555")
    check("a hex logon id folds case, because 0x3E7 == 0x3e7",
          normalise(IdKind.SESSION_UID, "0x3E7") == "0x3e7")
    check("a non-hex session id is left alone",
          normalise(IdKind.SESSION_UID, "AbC123XyZ") == "AbC123XyZ",
          "a base64 vendor id would collide under folding")

    # Idempotence is what lets Identifier's validator re-run normalise as a check.
    corpus = [
        (IdKind.IP, "::ffff:10.0.0.5"), (IdKind.IP, "2001:0db8::0001"),
        (IdKind.MAC, "aa-bb-cc-dd-ee-ff"), (IdKind.HOSTNAME, "WS01.corp.local"),
        (IdKind.FQDN, "WS01.Corp.Local."), (IdKind.DOMAIN, "Example.COM."),
        (IdKind.SAM, "CORP\\JDoe"), (IdKind.UPN, "JDoe@Corp.Example.COM"),
        (IdKind.POSIX_USER, "Bob"), (IdKind.EMAIL, "J.Doe@Example.COM"),
        (IdKind.SID, "s-1-5-21-1-2-3-1001"), (IdKind.URL, "HTTP://EX.com/A"),
        (IdKind.PROCESS_UID, "{A1B2C3D4-0000-1111-2222-333344445555}"),
        (IdKind.SESSION_UID, "0x3E7"), (IdKind.SHA256, "A" * 64),
        (IdKind.MD5, "B" * 32), (IdKind.SHA1, "C" * 40),
        (IdKind.MACHINE_UID, "AbC-123"), (IdKind.SERIAL, " 5CD1234ABC "),
        (IdKind.IAM_ARN, "arn:aws:iam::123456789012:user/JDoe"),
        (IdKind.RESOURCE_ID, "/subscriptions/X/resourceGroups/RG"),
        (IdKind.CLOUD_ACCOUNT, "123456789012"), (IdKind.SERVICE_NAME, " Spooler "),
        (IdKind.USER_UID, "12345"), (IdKind.ENTRA_OID, "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        (IdKind.OKTA_UID, "00u1abcd"), (IdKind.DEVICE_GUID, "{11111111-2222-3333-4444-555555555555}"),
        (IdKind.NAT_IP, "203.0.113.5"),
    ]
    covered = {k for k, _ in corpus}
    check("the idempotence corpus covers every kind", covered == set(IdKind),
          str(sorted(str(k) for k in set(IdKind) - covered)))
    non_idem = []
    for k, v in corpus:
        once = normalise(k, v)
        if normalise(k, once) != once:
            non_idem.append(f"{k}: {v!r} → {once!r} → {normalise(k, once)!r}")
    check("normalise is idempotent for every kind", not non_idem, str(non_idem))

    # ══════════════════════════════════════════════════════════════════════
    print("\n── case folding: the kind decides when it can ──")

    check("a SAM name folds even when the platform is unknown",
          normalise(IdKind.SAM, "CORP\\JDoe") == "corp\\jdoe",
          "Platform.UNKNOWN is the common path, and a SAM name is Windows-only")
    check("a UPN folds even when the platform is unknown",
          normalise(IdKind.UPN, "JDoe@Corp.Example.COM") == "jdoe@corp.example.com")
    check("a POSIX name never folds, not even on a case-insensitive platform",
          normalise(IdKind.POSIX_USER, "Bob", Platform.WINDOWS) == "Bob",
          "useradd Bob succeeds alongside bob")
    check("fold_username lets the kind override the platform",
          fold_username("JDoe", Platform.LINUX, kind=IdKind.SAM) == "jdoe"
          and fold_username("Bob", Platform.WINDOWS, kind=IdKind.POSIX_USER) == "Bob")
    check("with no kind, the platform decides",
          fold_username("JDoe", Platform.WINDOWS) == "jdoe"
          and fold_username("JDoe", Platform.LINUX) == "JDoe")
    check("an unknown platform does not fold, taking the reportable side",
          fold_username("JDoe") == "JDoe"
          and Platform.UNKNOWN not in CASE_INSENSITIVE_PLATFORMS)
    check("linux is absent from the case-insensitive set",
          Platform.LINUX not in CASE_INSENSITIVE_PLATFORMS
          and Platform.WINDOWS in CASE_INSENSITIVE_PLATFORMS,
          "POSIX names *are* case-sensitive")
    check("gcp is absent too", Platform.GCP not in CASE_INSENSITIVE_PLATFORMS,
          "service-account local parts are generated lowercase, so folding buys nothing")
    check("an empty account name is refused",
          raises(lambda: fold_username("   "))[0])

    print("\n── splitting an account into its namespace ──")
    check("SAM shape is recognised",
          split_account("CORP\\jdoe") == ("corp", "jdoe", IdKind.SAM))
    check("UPN shape is recognised",
          split_account("jdoe@corp.example.com")
          == ("corp.example.com", "jdoe", IdKind.UPN))
    check("a bare name comes back with no namespace",
          split_account("jdoe") == ("", "jdoe", IdKind.SAM))
    check("a half-formed separator is refused",
          raises(lambda: split_account("CORP\\"))[0]
          and raises(lambda: split_account("@corp.com"))[0])

    # ══════════════════════════════════════════════════════════════════════
    print("\n── address classification: the ranges nest ──")

    check("CGNAT is classified before private",
          address_scope("100.64.3.9") is AddressScope.CGNAT,
          "a carrier address hiding thousands of subscribers is not one entity")
    check("private, public and reserved separate",
          (address_scope("10.0.0.5"), address_scope("8.8.8.8"),
           address_scope("0.0.0.0"))
          == (AddressScope.PRIVATE, AddressScope.PUBLIC, AddressScope.RESERVED))
    check("loopback, link-local and multicast are unroutable",
          all(address_scope(v) in UNROUTABLE_SCOPES
              for v in ("127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1")),
          str([str(address_scope(v)) for v in ("127.0.0.1", "169.254.1.1", "224.0.0.1")]))
    check("exactly four scopes are unroutable",
          len(UNROUTABLE_SCOPES) == 4
          and AddressScope.CGNAT not in UNROUTABLE_SCOPES,
          "a CGNAT address is a real endpoint, just a shared one")
    check("an unroutable address states why it is not an action target",
          "loopback" in cidr_reason("127.0.0.1") and not cidr_reason("8.8.8.8"))
    check("a configured protected CIDR is honoured",
          "10.0.0.0/8" in cidr_reason("10.0.0.5", ["10.0.0.0/8"])
          and not cidr_reason("8.8.8.8", ["10.0.0.0/8"]),
          cidr_reason("10.0.0.5", ["10.0.0.0/8"]))
    check("a malformed CIDR in config does not crash the gate",
          isinstance(cidr_reason("10.0.0.5", ["not-a-cidr"]), str))

    # ══════════════════════════════════════════════════════════════════════
    print("\n── entity keys are readable and bounded ──")

    check("a key is type:kind:value",
          entity_key(EntityType.HOST, IdKind.HOSTNAME, "ws01") == "host:hostname:ws01",
          "greppable out of a VedDB dump")
    check("enum members stringify to their value, not their repr",
          "EntityType" not in entity_key("host", "hostname", "ws01"),
          "the StrEnum footgun that would produce EntityType.HOST:ws01")
    long_a, long_b = "arn:aws:x/" + "a" * 120, "arn:aws:x/" + "a" * 119 + "b"
    ka, kb = (entity_key(EntityType.CLOUD_RESOURCE, IdKind.RESOURCE_ID, v)
              for v in (long_a, long_b))
    check("an over-long value truncates with a digest and still cannot collide",
          ka != kb and "~" in ka
          and len(ka) <= len("cloud_resource:resource_id:") + 96,
          f"{len(ka)} chars, value bounded at 96")
    check("control characters and whitespace are neutralised",
          "\n" not in entity_key("host", "hostname", "ws\n01")
          and " " not in entity_key("host", "hostname", "ws 01"))

    # ══════════════════════════════════════════════════════════════════════
    print("\n── Identifier self-verifies ──")

    ok, msg = raises(lambda: Identifier(
        kind=IdKind.HOSTNAME, value="WS01.corp.example.com", mergeable=True))
    check("a raw value cannot be smuggled past Identifier.make",
          ok and "not normalised" in msg, msg[:70])
    ok, msg = raises(lambda: Identifier(kind=IdKind.MAC, value="AA:BB:CC:DD:EE:FF",
                                        mergeable=False))
    check("an un-mergeable identifier must say why", ok and "no reason" in msg)
    check("make() normalises and resolves mergeability",
          Identifier.make(IdKind.HOSTNAME, "WS01.corp.local").value == "ws01")

    i_ip = Identifier.make(IdKind.IP, "10.0.0.5")
    check("an IP is never mergeable and says so",
          not i_ip.mergeable and "durability 2" in i_ip.reason, i_ip.reason)
    check("an IP names an IP entity, not a host",
          i_ip.entity_type is EntityType.IP and i_ip.key == "ip:ip:10.0.0.5",
          "which is what makes the NAT guard structural")
    i_nat = Identifier.make(IdKind.IP, "203.0.113.5", shared=True)
    check("shared=True downgrades the kind rather than rewriting stored bindings",
          i_nat.kind is IdKind.NAT_IP and not i_nat.mergeable, i_nat.reason[:60])
    i_lo = Identifier.make(IdKind.IP, "127.0.0.1")
    check("an unroutable address is refused as a merge basis",
          not i_lo.mergeable and "loopback" in i_lo.reason.lower(), i_lo.reason[:60])
    i_uid = Identifier.make(IdKind.USER_UID, "12345")
    check("a provider-less user id is refused despite durability 4",
          not i_uid.mergeable and SPECS[IdKind.USER_UID].durability == 4,
          i_uid.reason[:70])
    i_mac = Identifier.make(IdKind.MAC, "aa:bb:cc:dd:ee:ff")
    check("a MAC is recorded but never merged on",
          not i_mac.mergeable and i_mac.entity_type is EntityType.HOST,
          "a cloned VM template shares one")

    print("\n── the namespace rule for account names ──")
    set_default_domain("")
    bare = Identifier.make(IdKind.SAM, "jdoe")
    check("a bare account name refuses to merge",
          not bare.mergeable and "namespace" in bare.reason, bare.reason[:70])
    qualified = Identifier.make(IdKind.SAM, "CORP\\jdoe")
    check("an embedded domain qualifies it and recovers the scope",
          qualified.mergeable and qualified.scope == "corp", qualified.scope)
    passed_in = Identifier.make(IdKind.SAM, "jdoe", scope="CORP.example.com")
    check("a scope supplied by the bridge qualifies it too",
          passed_in.mergeable and passed_in.scope == "corp.example.com")
    check("and the supplied scope reaches the VALUE, not just the mergeable flag",
          passed_in.value == "corp.example.com\\jdoe",
          f"{passed_in.value} — a namespace outside the value cannot separate anyone")
    other_estate = Identifier.make(IdKind.SAM, "jdoe", scope="ACME")
    check("so two estates' jdoe are two keys, both mergeable within themselves",
          entity_key(EntityType.USER, IdKind.SAM, passed_in.value)
          != entity_key(EntityType.USER, IdKind.SAM, other_estate.value)
          and passed_in.mergeable and other_estate.mergeable,
          f"{other_estate.value} vs {passed_in.value}")
    check("a qualified name keys identically however the namespace arrived",
          Identifier.make(IdKind.SAM, "CORP.example.com\\jdoe").value
          == passed_in.value,
          "the sibling-field path and the embedded path must not diverge")
    check("one kind holds one spelling: a UPN-shaped SAM is still domain\\account",
          normalise(IdKind.SAM, "JDoe@CORP") == "corp\\jdoe"
          == normalise(IdKind.SAM, "CORP\\JDoe"),
          "Windows logs put a UPN in TargetUserName; two spellings would be two "
          "people with no reportable half to catch it")
    check("a namespace the value carries beats one the bridge supplied",
          Identifier.make(IdKind.SAM, "CORP\\jdoe", scope="acme").scope == "corp",
          "the event's own field is more specific than a collector default")
    upn_scoped = Identifier.make(IdKind.UPN, "jdoe", scope="CORP.example.com")
    check("a UPN takes the same treatment in its own syntax",
          upn_scoped.value == "jdoe@corp.example.com" and upn_scoped.mergeable,
          upn_scoped.value)
    check("a bare hostname still merges — the asymmetry is deliberate",
          Identifier.make(IdKind.HOSTNAME, "ws01").mergeable,
          "refusing would split one endpoint across two agents")

    # A POSIX account's namespace is the host, and it has to survive normalisation:
    # forty thousand boxes each have a root.
    p_bare = Identifier.make(IdKind.POSIX_USER, "root")
    p_a = Identifier.make(IdKind.POSIX_USER, "root", scope="app01")
    p_b = Identifier.make(IdKind.POSIX_USER, "root", scope="db02")
    check("a bare POSIX account refuses to merge",
          not p_bare.mergeable and p_bare.value == "root", p_bare.reason[:60])
    check("two hosts' local root are two entities, not one",
          p_a.value == "root@app01" and p_b.value == "root@db02"
          and p_a.mergeable and p_b.mergeable,
          f"{p_a.value} vs {p_b.value}")
    check("the host namespace survives re-normalisation",
          normalise(IdKind.POSIX_USER, p_a.value) == p_a.value
          and normalise(IdKind.POSIX_USER, "Bob@APP01") == "Bob@app01",
          "case-sensitive account, case-insensitive host")
    check("a winbind-joined host's DOMAIN\\account spelling is kept, not rewritten",
          normalise(IdKind.POSIX_USER, "CORP\\bob") == "corp\\bob",
          "sssd/winbind really do report this on Linux")

    set_default_domain("CORP.example.com")
    check("set_default_domain makes a single-domain estate consolidate",
          Identifier.make(IdKind.SAM, "jdoe").mergeable
          and default_domain() == "corp.example.com")
    check("the declared domain is applied as the value's namespace",
          Identifier.make(IdKind.SAM, "jdoe").value == "corp.example.com\\jdoe",
          Identifier.make(IdKind.SAM, "jdoe").value)
    check("an explicit scope still wins over the declared default",
          Identifier.make(IdKind.SAM, "jdoe", scope="ACME").value == "acme\\jdoe",
          Identifier.make(IdKind.SAM, "jdoe", scope="ACME").value)
    check("the declared DIRECTORY domain is not applied to a POSIX account",
          not Identifier.make(IdKind.POSIX_USER, "root").mergeable,
          "a local Linux account is not in the AD domain; adopting it would "
          "merge every host's root")
    set_default_domain("")
    check("clearing it restores the refusal",
          not Identifier.make(IdKind.SAM, "jdoe").mergeable and default_domain() == "",
          "correct for a multi-domain estate: visible fragmentation beats a false merge")

    # ══════════════════════════════════════════════════════════════════════
    print("\n── Binding: an identifier points at an entity over an interval ──")

    b = Binding(identifier=i_ip, entity_key="host:hostname:ws01",
                first_seen=T0, last_seen=T0 + HOUR, source="dhcp")
    check("covers is inclusive at both ends",
          b.covers(T0) and b.covers(T0 + HOUR) and not b.covers(T0 - 1)
          and not b.covers(T0 + HOUR + 1))
    check("a reversed interval is refused",
          raises(lambda: Binding(identifier=i_ip, entity_key="k",
                                 first_seen=T0 + 1, last_seen=T0))[0])
    check("confidence must be a percentage",
          raises(lambda: Binding(identifier=i_ip, entity_key="k", first_seen=T0,
                                 last_seen=T0, confidence=101))[0])
    check("a binding must name an entity",
          raises(lambda: Binding(identifier=i_ip, entity_key="", first_seen=T0,
                                 last_seen=T0))[0])
    ext = b.extend(T0 + 2 * HOUR)
    check("extend moves last_seen and leaves first_seen alone",
          ext.last_seen == T0 + 2 * HOUR and ext.first_seen == T0)
    back = b.extend(T0 - HOUR)
    check("extending backwards moves first_seen instead",
          back.first_seen == T0 - HOUR and back.last_seen == T0 + HOUR,
          "late-arriving earlier evidence widens the interval, never inverts it")

    b2 = Binding(identifier=i_ip, entity_key="host:hostname:ws02",
                 first_seen=T0 + HOUR // 2, last_seen=T0 + 2 * HOUR)
    check("two exclusive bindings overlapping on different entities conflict",
          b.overlaps(b2) and b.conflicts_with(b2),
          "one lease cannot be held by two machines at once")
    b3 = Binding(identifier=i_ip, entity_key="host:hostname:ws02",
                 first_seen=T0 + 2 * HOUR, last_seen=T0 + 3 * HOUR)
    check("a later, non-overlapping binding is normal DHCP churn, not a conflict",
          not b.overlaps(b3) and not b.conflicts_with(b3))
    nb1 = Binding(identifier=i_nat, entity_key="host:hostname:a", first_seen=T0,
                  last_seen=T0 + HOUR, exclusive=False)
    nb2 = Binding(identifier=i_nat, entity_key="host:hostname:b", first_seen=T0,
                  last_seen=T0 + HOUR, exclusive=False)
    check("two non-exclusive bindings overlapping is expected behind NAT",
          nb1.overlaps(nb2) and not nb1.conflicts_with(nb2))
    same = Binding(identifier=i_ip, entity_key="host:hostname:ws01",
                   first_seen=T0, last_seen=T0 + HOUR)
    check("the same entity twice is not a conflict", not b.conflicts_with(same))

    # ══════════════════════════════════════════════════════════════════════
    print("\n── Entity: observation and naming ──")

    uid = Identifier.make(IdKind.MACHINE_UID, "b7f3" + "a" * 36)
    host = Entity.make(uid, at=T0, source="defender", platform=Platform.WINDOWS)
    check("an entity is keyed on the identifier that named it",
          host.key == uid.key and host.entity_type is EntityType.HOST)
    hn = Identifier.make(IdKind.HOSTNAME, "ws01")
    check("a new identifier is reported as new", host.observe(hn, at=T0 + 10) is True)
    check("re-observing extends rather than appends",
          host.observe(hn, at=T0 + HOUR) is False and len(host.bindings) == 2,
          f"{len(host.bindings)} bindings for 2 identifiers")
    check("the extended binding carries the whole interval, not the last instant",
          next(b for b in host.bindings if b.identifier.key == hn.key).first_seen
          == T0 + 10,
          "an hourly heartbeat must not accumulate one binding an hour")
    check("a readable name outranks the stronger opaque key",
          host.name == "ws01" and host.key.endswith("a" * 36),
          f"name={host.name} key={host.key[:24]}…")
    check("both remain recorded", set(host.values()) == {"ws01", uid.value})

    check("observe accepts a cross-type identifier",
          host.observe(i_ip, at=T0 + HOUR) is True
          and i_ip.key in {i.key for i in host.identifiers},
          "an address belongs to a host over an interval — that is what Binding is for")
    check("own_identifiers excludes it",
          {i.kind for i in host.own_identifiers()}
          == {IdKind.MACHINE_UID, IdKind.HOSTNAME})
    check("bound_at is the time-correct view",
          i_ip.key not in {i.key for i in host.bound_at(T0)}
          and i_ip.key in {i.key for i in host.bound_at(T0 + HOUR)},
          "asking whose address this is without a time is unanswerable")
    check("active_at brackets the entity's own lifetime",
          host.active_at(T0) and host.active_at(T0 + HOUR)
          and not host.active_at(T0 - 1))

    print("\n── protection is a hard stop that must be explicable ──")
    ok, msg = raises(lambda: Entity(key="k", entity_type=EntityType.HOST,
                                    protected=True))
    check("protected with no reason is refused", ok and "overridden" in msg, msg[:60])
    gw = Entity.make(Identifier.make(IdKind.HOSTNAME, "gw01"), at=T0)
    gw.protect("blocking the gateway takes the site off the internet")
    check("protect() sets both fields in the order validate_assignment demands",
          gw.protected and "gateway" in gw.protected_reason)
    check("a blank reason is refused", raises(lambda: gw.protect("  "))[0])
    check("protection is separate from criticality",
          gw.criticality is Criticality.UNKNOWN and gw.protected,
          "a gateway is protected regardless of business value")
    check("criticality is ordered for natural comparison",
          Criticality.CRITICAL > Criticality.HIGH > Criticality.LOW
          > Criticality.UNKNOWN)
    check("a negative count is refused",
          raises(lambda: Entity(key="k", entity_type=EntityType.HOST,
                                signal_count=-1))[0])
    check("extra fields are forbidden",
          raises(lambda: Entity(key="k", entity_type=EntityType.HOST,
                                nonsense=1), Exception)[0])

    # ══════════════════════════════════════════════════════════════════════
    print("\n── DHCP churn: one address, two hosts, no cross-attribution ──")

    a = Entity.make(Identifier.make(IdKind.MACHINE_UID, "aaa1"), at=T0, source="edr")
    a.observe(Identifier.make(IdKind.HOSTNAME, "ws01"), at=T0)
    a.observe(i_ip, at=T0)
    a.observe(i_ip, at=T0 + HOUR)          # lease held for an hour
    bb = Entity.make(Identifier.make(IdKind.MACHINE_UID, "bbb2"), at=T0 + 3 * HOUR,
                     source="edr")
    bb.observe(Identifier.make(IdKind.HOSTNAME, "ws02"), at=T0 + 3 * HOUR)
    bb.observe(i_ip, at=T0 + 3 * HOUR)     # same address, after the renewal

    a_lease = next(x for x in a.bindings if x.identifier.key == i_ip.key)
    b_lease = next(x for x in bb.bindings if x.identifier.key == i_ip.key)
    check("each host holds its own interval for the shared address",
          a_lease.first_seen == T0 and a_lease.last_seen == T0 + HOUR
          and b_lease.first_seen == T0 + 3 * HOUR)
    check("the two leases do not overlap, so there is no contradiction",
          not a_lease.overlaps(b_lease) and not a_lease.conflicts_with(b_lease))
    check("the address is attributed to ws01 at T0 and to ws02 three hours later",
          i_ip.key in {i.key for i in a.bound_at(T0)}
          and i_ip.key not in {i.key for i in a.bound_at(T0 + 3 * HOUR)}
          and i_ip.key in {i.key for i in bb.bound_at(T0 + 3 * HOUR)},
          "the failure this prevents is silent: the timeline would read perfectly")

    print("\n── NAT: a shared address is not evidence of one host ──")
    ok, why = a.mergeable_with(bb)
    check("two hosts sharing only an address refuse to merge",
          not ok and "name something else" in why or "are not one host" in why, why[:90])
    check("the refusal is structural, not a tuned threshold",
          i_ip.entity_type is not EntityType.HOST,
          "an ip identifier names an IP entity, so it can never be host evidence")
    ok2, msg = raises(lambda: a.merge(bb), MergeRefused)
    check("merge raises rather than returning a value a caller can ignore", ok2, msg[:70])
    a.note_not_merged(bb, "only a shared NAT address in common", at=T0)
    check("the refusal is recorded, so it is distinguishable from never looking",
          len(a.merge_notes) == 1 and bb.key in a.merge_notes[0],
          a.merge_notes[0][:70])

    # ══════════════════════════════════════════════════════════════════════
    print("\n── merge: the graded refusals and what survives ──")

    def host(name, *idents, **fields):
        e = Entity.make(Identifier.make(IdKind.MACHINE_UID, name), at=T0, **fields)
        for i in idents:
            e.observe(i, at=T0)
        return e

    u = Entity.make(Identifier.make(IdKind.SID, "S-1-5-21-1-2-3-1001"), at=T0)
    ok, why = host("h1").mergeable_with(u)
    check("a host and a user are different kinds of thing",
          not ok and "different kinds" in why, why[:60])
    h_same = host("h1")
    ok, why = h_same.mergeable_with(host("h1"))
    check("an entity is not merged with itself", not ok and "already" in why)
    ok, why = host("h1").mergeable_with(host("h2"))
    check("no identifier in common refuses", not ok and "no identifier in common" in why)

    shared_mac = Identifier.make(IdKind.MAC, "aa:bb:cc:dd:ee:ff")
    ok, why = host("h1", shared_mac).mergeable_with(host("h2", shared_mac))
    check("a shared MAC is own-type but too weak, and the refusal quotes its reason",
          not ok and "not mergeable" in why and "durability 3" in why, why[:90])

    shared_hn = Identifier.make(IdKind.HOSTNAME, "ws01")
    left = host("h1", shared_hn, signal_count=2, criticality=Criticality.LOW)
    right = host("h2", shared_hn, signal_count=2, criticality=Criticality.CRITICAL,
                 crown_jewel=True, risk_score=70)
    right.protect("domain controller")
    right.observe(Identifier.make(IdKind.SERIAL, "5CD1234ABC"), at=T0 + HOUR)
    ok, why = left.mergeable_with(right)
    check("a shared own-type mergeable identifier allows the merge, and names it",
          ok and "durability 4" in why and "host:hostname:ws01" in why, why[:90])

    survivor_key = left.key
    merged = left.merge(right, at=T0 + 2 * HOUR)
    check("this entity's key survives", merged.key == survivor_key)
    check("the absorbed key is retained so older alerts still resolve",
          right.key in merged.merged_from, str(merged.merged_from))
    check("signal_count is summed, not maxed",
          merged.signal_count == 4,
          "min_signals_per_entity:3 would never fire on a 2/2 split")
    check("criticality takes the maximum",
          merged.criticality is Criticality.CRITICAL)
    check("crown_jewel and risk propagate",
          merged.crown_jewel and merged.risk_score == 70)
    check("protection propagates with its reason intact",
          merged.protected and merged.protected_reason == "domain controller",
          "the ordering trap: setting protected first would trip its own guard")
    check("the absorbed identifiers arrive",
          IdKind.SERIAL in {i.kind for i in merged.identifiers})
    check("their binding intervals arrive intact, not collapsed to one instant",
          next(x for x in merged.bindings
               if x.identifier.kind is IdKind.SERIAL).first_seen == T0 + HOUR,
          "exactly the history a DHCP question needs")
    check("the copied binding is re-keyed to the survivor",
          all(x.entity_key == survivor_key for x in merged.bindings))
    check("the merge is recorded with its evidence",
          len(merged.merge_notes) == 1 and "absorbed" in merged.merge_notes[0]
          and "durability 4" in merged.merge_notes[0],
          "a guess that cannot be examined cannot be corrected")
    check("first_seen and last_seen widen to cover both",
          merged.first_seen == T0 and merged.last_seen >= T0 + HOUR)

    # ══════════════════════════════════════════════════════════════════════
    print("\n── EntityRef stays thin on purpose ──")
    r = merged.ref(observed_as="10.0.0.5", role="src")
    check("a ref carries a key, not a frozen copy of the entity",
          set(EntityRef.model_fields) == {"key", "entity_type", "observed_as", "role"},
          "an embedded entity would freeze criticality at alert time")
    check("the ref points at the live entity",
          r.key == merged.key and r.entity_type is EntityType.HOST
          and r.role == "src")
    check("a ref is immutable",
          raises(lambda: setattr(r, "role", "dst"), Exception)[0])
    check("observed_as defaults to the display name",
          merged.ref().observed_as == merged.name)

    print("\n── the stored document round-trips ──")
    doc = merged.doc()
    back = Entity.from_doc(doc)
    check("every value in the document is JSON-native",
          all(not isinstance(v, (EntityType, IdKind, Platform))
              for v in doc.values()),
          "model_dump(mode='json') so a VedDB write needs no custom encoder")
    check("enums come back as enums", back.entity_type is EntityType.HOST
          and back.criticality is Criticality.CRITICAL)
    check("the round trip is lossless", back.doc() == doc)
    check("schema_version is stamped", doc["schema_version"] == 1)
    check("describe() reads for a human",
          "PROTECTED" in merged.describe() and "crown-jewel" in merged.describe(),
          merged.describe()[:80])

    # ══════════════════════════════════════════════════════════════════════
    print("\n── the event bridge: one endpoint, not four fragments ──")

    ev = Event(
        time=T0, class_uid=4001, activity_id=1, soc_source="defender",
        device_os_name="Windows 11 Enterprise",
        device_uid="d" * 40, device_hostname="WS01.corp.example.com",
        device_domain="corp.example.com", device_mac="AA-BB-CC-DD-EE-FF",
        device_ip="10.0.0.5",
        src_endpoint_ip="10.0.0.5", dst_endpoint_ip="203.0.113.9",
        actor_user_name="JDoe", actor_user_domain="CORP",
        actor_session_uid="0x3E7",
        process_file_sha256="e" * 64,
    )
    check("platform comes from the OS field, not the collector name",
          infer_platform(ev) is Platform.WINDOWS)
    obs = observations_from_event(ev)
    check("every identifier-bearing field is picked up",
          len(obs) >= 9, f"{len(obs)} observations")
    check("observations carry the role a kill chain needs",
          {o.role for o in obs} >= {"device", "src", "dst", "actor"},
          str(sorted({o.role for o in obs})))
    check("no duplicate (facet, identifier) pairs",
          len({(o.facet, o.identifier.key) for o in obs}) == len(obs))

    ents = entities_from_event(ev)
    by_type = {}
    for e in ents:
        by_type.setdefault(e.entity_type, []).append(e)
    hosts = by_type.get(EntityType.HOST, [])
    check("the device's four identifiers produce ONE host, not four fragments",
          len([h for h in hosts if h.key.startswith("host:machine_uid")]) == 1,
          f"{len(hosts)} hosts total: {[h.name for h in hosts]}")
    dev = next(h for h in hosts if h.key.startswith("host:machine_uid"))
    check("it is keyed on the EDR id and named by the hostname",
          dev.key == f"host:machine_uid:{'d' * 40}" and dev.name == "ws01",
          f"{dev.key[:28]}… named {dev.name}")
    check("the MAC is recorded on it",
          IdKind.MAC in {i.kind for i in dev.identifiers})
    check("the address is bound to it by cross-attachment",
          "ip:ip:10.0.0.5" in {i.key for i in dev.identifiers}
          and CROSS_ATTACH[EntityType.IP] is EntityType.HOST)
    check("the address is also its own entity",
          any(e.key == "ip:ip:10.0.0.5" for e in by_type.get(EntityType.IP, [])),
          str([e.key for e in by_type.get(EntityType.IP, [])]))
    check("src and dst addresses stay distinct entities",
          len({e.key for e in by_type.get(EntityType.IP, [])}) == 2)

    users = by_type.get(EntityType.USER, [])
    check("the actor resolves to one user",
          len(users) == 1, str([u.key for u in users]))
    actor = users[0]
    check("the sibling domain field qualified the bare account name",
          actor.key == "user:sam:corp\\jdoe"
          and actor.identifier(IdKind.SAM).mergeable,
          f"{actor.key} — invisible to an observables-only bridge")
    check("the session is bound to the account",
          "session:session_uid:0x3e7" in {i.key for i in actor.identifiers}
          and CROSS_ATTACH[EntityType.SESSION] is EntityType.USER,
          "which is what makes a revoke action target the right thing")
    check("the file hash is its own entity",
          any(e.key == f"file:sha256:{'e' * 64}" for e in ents))
    check("every entity is stamped with the event's time and source",
          all(e.first_seen == T0 for e in ents)
          and all("defender" in e.sources for e in ents))

    print("\n── the platform steers which kind a bare account name becomes ──")
    lin = Event(time=T0, class_uid=3002, soc_source="local_auth",
                device_os_name="Ubuntu 22.04", device_hostname="app01",
                actor_user_name="Bob")
    lin_user = next(e for e in entities_from_event(lin)
                    if e.entity_type is EntityType.USER)
    check("on Linux a bare name becomes a case-sensitive posix_user",
          lin_user.identifier(IdKind.POSIX_USER) is not None
          and lin_user.values(IdKind.POSIX_USER) == ["Bob"],
          lin_user.key)
    ent = Event(time=T0, class_uid=3002, soc_source="entra",
                actor_user_name="JDoe@corp.example.com")
    ent_user = next(e for e in entities_from_event(ent)
                    if e.entity_type is EntityType.USER)
    check("on Entra it becomes a folded UPN",
          ent_user.identifier(IdKind.UPN) is not None
          and ent_user.values(IdKind.UPN) == ["jdoe@corp.example.com"],
          ent_user.key)
    win_uid = Event(time=T0, class_uid=3002, soc_source="windows_eventlog",
                    actor_user_uid="S-1-5-21-1-2-3-1001")
    win_user = next(e for e in entities_from_event(win_uid)
                    if e.entity_type is EntityType.USER)
    check("on Windows a user uid becomes a SID, which is mergeable",
          win_user.identifier(IdKind.SID) is not None
          and win_user.identifier(IdKind.SID).mergeable,
          "the generic user_uid would have refused")
    aws = Event(time=T0, class_uid=3002, soc_source="cloudtrail",
                actor_user_uid="arn:aws:iam::123456789012:user/JDoe")
    check("on AWS it becomes an ARN",
          any(e.identifier(IdKind.IAM_ARN) for e in entities_from_event(aws)
              if e.entity_type is EntityType.USER))

    print("\n── the bridge degrades rather than failing ──")
    junk = Event(time=T0, class_uid=4001, soc_source="network_flow",
                 device_hostname="*", device_ip="10.0.0.7")
    junk_ents = entities_from_event(junk)
    check("an unusable value costs only itself, not the rest of the event",
          any(e.key == "ip:ip:10.0.0.7" for e in junk_ents),
          f"{len(junk_ents)} entities survived a wildcard hostname")
    check("an event naming nothing produces nothing, quietly",
          entities_from_event(
              Event(time=T0, class_uid=4001, soc_source="x")) == [])

    # ══════════════════════════════════════════════════════════════════════
    print("\n── the reportable half of two conservative choices ──")

    # Platform unknown on both sides, so the names were not folded and one account
    # became two nodes. This is the pair the correlation layer must be handed.
    u1 = Entity.make(Identifier.make(IdKind.USER_UID, "JDoe"), at=T0)
    u2 = Entity.make(Identifier.make(IdKind.USER_UID, "jdoe"), at=T0)
    cc = case_collisions([u1, u2])
    check("a name split by case is reported for resolution",
          len(cc) == 1 and sorted(cc[0][1]) == sorted([u1.key, u2.key]), str(cc))
    p1 = Entity.make(Identifier.make(IdKind.POSIX_USER, "Bob", scope="app01"), at=T0)
    p2 = Entity.make(Identifier.make(IdKind.POSIX_USER, "bob", scope="app01"), at=T0)
    check("a case-sensitive kind is NOT reported, because there is nothing to settle",
          case_collisions([p1, p2]) == [],
          "on a POSIX host Bob and bob really are two accounts")
    s1 = Entity.make(Identifier.make(IdKind.SAM, "CORP\\JDoe"), at=T0)
    s2 = Entity.make(Identifier.make(IdKind.SAM, "CORP\\jdoe"), at=T0)
    check("an always-folded kind cannot collide in the first place",
          s1.key == s2.key and case_collisions([s1, s2]) == [])
    same_val = Entity.make(Identifier.make(IdKind.HOSTNAME, "ws01"), at=T0)
    other = Entity.make(Identifier.make(IdKind.MACHINE_UID, "z1"), at=T0)
    other.observe(Identifier.make(IdKind.HOSTNAME, "ws01"), at=T0)
    check("two entities holding the same spelling is a binding question, not a case one",
          case_collisions([same_val, other]) == [])

    h_corp = Entity.make(Identifier.make(IdKind.MACHINE_UID, "m1"), at=T0)
    h_corp.observe(Identifier.make(IdKind.HOSTNAME, "ws01",
                                   scope="corp.example.com"), at=T0)
    h_acq = Entity.make(Identifier.make(IdKind.MACHINE_UID, "m2"), at=T0)
    h_acq.observe(Identifier.make(IdKind.HOSTNAME, "ws01",
                                  scope="acquired.example.net"), at=T0)
    sc = scope_collisions([h_corp, h_acq])
    check("one hostname in two namespaces is reported",
          len(sc) == 1 and len(sc[0][1]) == 2, str(sc))
    check("a hostname's scope stays metadata, deliberately absent from its key",
          h_corp.identifier(IdKind.HOSTNAME).key
          == h_acq.identifier(IdKind.HOSTNAME).key == "host:hostname:ws01",
          "including it would give a domain-reporting collector its own key for one host")
    check("whereas an account's namespace is IN the value, so it does reach the key",
          Identifier.make(IdKind.SAM, "jdoe", scope="corp").key
          != Identifier.make(IdKind.SAM, "jdoe", scope="acme").key,
          "the one asymmetry: two domains' jdoe are two people, "
          "one host reported two ways is one host")
    check("no namespace clash is reported when there is none",
          scope_collisions([h_corp]) == [])

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(main())

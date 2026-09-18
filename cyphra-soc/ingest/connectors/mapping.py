"""Vendor record → OCSF payload: the parts that are identical across all ten.

Every connector in this package does the same six things to every record it reads, and
each of the six has one way of being right and several of being silently wrong. They
live here so the wrong ways are argued about once.

── Why :func:`put` exists instead of plain assignment ────────────────────────
``payload["status_detail"] = record.get("failureReason")`` looks harmless and is not.
:class:`~core.schema.ocsf.Event` declares that field ``str | None = None``, so an
absent vendor field assigned this way stores ``None`` — which is what the default was
anyway — but ``record.get("failureReason", "")`` stores the empty *string*, and those
are different values in Parquet and different values in SQL. ``WHERE status_detail IS
NULL`` then misses every row a connector touched, and the miss is invisible because
the column exists and most rows look fine. :func:`put` assigns only when the value
carries information, so an absent vendor field leaves the model default alone.

── Why the ATT&CK technique does not go in a field ───────────────────────────
There is no ``attack_technique`` on the event model — OCSF's ``attacks`` object is
declared by 3002, 3004, 3006, 3007, 2004, 6003 and 4009 but no ``OCSF_PATH`` entry
reaches it yet (a measured gap, carried as a Phase 2 coverage-matrix item). So a
connector that wrote ``payload["attack_technique"]`` would have it swept into
``unmapped`` under a key nothing queries, and the mapping would look present while
being unreachable. :func:`attack` writes ``metadata.labels`` — a string set the lake
filters directly — plus the bare id in ``unmapped``, which is the same convention
:mod:`ingest.collectors.local_auth` established for the local sources. Keeping the two
halves of the codebase on one convention is the point: the coverage matrix asks "which
techniques has telemetry ever been seen for" once, not twice.

── Why the CRUD guess is coarse on purpose ──────────────────────────────────
:func:`crud_activity` maps an operation name onto 6003 API Activity's four verbs. It
is a heuristic over three unlike naming schemes — CloudTrail puts the verb first
(``CreateUser``), Azure puts it last (``.../WRITE``), GCP does both
(``v1.compute.instances.insert``, ``SetIamPolicy``) — and several verbs are genuinely
ambiguous, which is documented at the table rather than smoothed over. It is safe to
be coarse because ``activity_name`` always carries the vendor's operation string
verbatim, so the four-way bucket is a convenience for coarse filtering and never the
authoritative statement of what happened. A detection that needs to know the
difference between ``PutObject`` and ``PutBucketPolicy`` reads ``api_operation``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from core.schema.ocsf import Severity, Status

#: Longest a mapped free-text field is allowed to be. Vendor descriptions run long —
#: a Defender alert description is routinely 2 KB and a CrowdStrike ``description``
#: can carry a full behavioural narrative — and every byte is copied into the lake, the
#: dedup hash and any case export. Clipped rather than dropped, with the marker, so the
#: reader can tell the difference between "short" and "trimmed".
TEXT_LIMIT = 2_000

#: Longest ``message``. Shorter than :data:`TEXT_LIMIT` because ``message`` is what an
#: alert queue renders in one line.
MESSAGE_LIMIT = 600


def clip(value: Any, limit: int = TEXT_LIMIT) -> str:
    """*value* as text, trimmed to *limit* with the trim made visible."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 15].rstrip() + f"… (+{len(text) - limit + 15}B)"


def put(payload: dict[str, Any], key: str, value: Any, *, limit: int = 0) -> None:
    """Assign *value* to *key* only if it carries information.

    ``0`` and ``False`` do carry information — an HTTP status of 0, a sign-in error
    code of 0 (which is Entra's spelling of success), a ``count`` of 0 — so the
    emptiness test names the four values that do not rather than using truthiness.
    Getting that wrong drops exactly the fields whose zero is the interesting case.
    """
    if value is None or value == "" or value == [] or value == {}:
        return
    if limit and isinstance(value, str):
        value = clip(value, limit)
        if not value:
            return
    payload[key] = value


def stash(payload: dict[str, Any], key: str, value: Any, *, limit: int = 0) -> None:
    """Put *value* in ``unmapped`` — the home for a real field with no OCSF path.

    Used deliberately and often. Four of the five classes these connectors emit
    declare fewer top-level objects than the vendors send: 2004 Detection Finding
    declares no ``user``, ``process``, ``file`` or ``src_endpoint``; 6003 API Activity
    declares no ``user``; 3004 Entity Management declares no ``user`` or ``group``;
    4009 Email Activity declares no ``url`` or ``file``. Those vendor fields are real
    and worth keeping — they are simply not conformant at the top level of that class,
    so they go here, named, where a hunt query can still reach them through
    ``unmapped``.
    """
    if value is None or value == "" or value == [] or value == {}:
        return
    if limit and isinstance(value, str):
        value = clip(value, limit)
        if not value:
            return
    payload.setdefault("unmapped", {})[key] = value


def note(payload: dict[str, Any], text: str) -> None:
    """Record a mapping decision on the event itself.

    ``notes`` is the accepted input alias for ``soc_notes`` — see
    :meth:`~core.schema.ocsf.Event.build`, which merges the two rather than letting
    one win. Anything a connector had to *decide* rather than copy belongs here: a
    substituted timestamp, a class chosen from an ambiguous vendor category, a field
    routed to ``unmapped`` for a reason that is not obvious from the key name.
    """
    if not text:
        return
    notes = payload.setdefault("notes", [])
    if text not in notes:
        notes.append(text)


def label(payload: dict[str, Any], *labels: str) -> None:
    """Add to ``metadata.labels``, the lake's filterable string set."""
    bucket = payload.setdefault("metadata_labels", [])
    for item in labels:
        if item and item not in bucket:
            bucket.append(item)


def attack(payload: dict[str, Any], *techniques: str) -> None:
    """Record ATT&CK technique hints — ``attack:T1110.003`` labels plus the bare ids.

    A **connector's hint**, not a detection verdict: it says the shape of this
    observation is what that technique looks like, which is weaker than a rule
    asserting the technique occurred. The detect layer overrides it and nothing
    downstream should treat it as an alert. See the module docstring for why it is not
    a field.
    """
    ids: list[str] = []
    for technique in techniques:
        tid = (technique or "").strip().upper()
        if not tid:
            continue
        label(payload, f"attack:{tid}")
        if tid not in ids:
            ids.append(tid)
    if ids:
        existing = payload.setdefault("unmapped", {}).get("attack_technique")
        merged = [t for t in str(existing or "").split(",") if t] + ids
        payload["unmapped"]["attack_technique"] = ",".join(dict.fromkeys(merged))


def as_bool(value: Any) -> bool | None:
    """A vendor boolean, in any of the seven spellings these APIs use.

    ``None`` for anything unrecognised rather than ``False``, because the difference
    matters here: Graph omits ``deviceDetail.isCompliant`` entirely for a device it has
    no opinion about, and coercing that to ``False`` would report every unmanaged
    personal device as *failing* compliance rather than as unassessed. That is a
    difference a conditional-access investigation turns on.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "y", "1", "enabled", "success"):
            return True
        if low in ("false", "no", "n", "0", "disabled", "failure"):
            return False
    return None


# ── severity ────────────────────────────────────────────────────────────────

#: The words these vendors use, folded onto OCSF's scale. ``moderate`` is Azure's,
#: ``informational``/``unknown`` are Defender's, ``severe`` is Google Workspace's,
#: ``warning``/``error`` are the generic-SaaS shapes seen in the wild. Deliberately not
#: a prefix match: ``low`` is a prefix of nothing here but ``info`` is a prefix of
#: ``informational`` *and* of nothing else, and a prefix rule would map a vendor's
#: ``critical_infrastructure`` label onto Critical.
_SEVERITY_WORDS: Mapping[str, Severity] = {
    "unknown": Severity.UNKNOWN,
    "none": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    # Okta's fourth level, and listed rather than left to the default it happens to
    # agree with. A missing entry and a correct entry produce the same answer here and
    # different answers the day the default changes, and "DEBUG scored Informational
    # because nothing matched" is not a mapping — it is a coincidence that reads like
    # one. The whole purpose of this table is that every vendor word an audited
    # connector can emit is visible in it.
    "debug": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "verbose": Severity.INFORMATIONAL,
    "notice": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "warning": Severity.LOW,
    "warn": Severity.LOW,
    "minor": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "error": Severity.MEDIUM,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "major": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "fatal": Severity.FATAL,
    "emergency": Severity.FATAL,
}


def severity_from_name(
    value: Any, *, default: Severity = Severity.INFORMATIONAL
) -> Severity:
    """A vendor severity *word* on OCSF's scale.

    The default is Informational rather than Unknown on purpose. Unknown (0) reads
    downstream as "nobody has assessed this", which is false for a record that came
    from an alerting product with a severity field it simply spelled in a way not
    listed above; Informational reads as "assessed, nothing urgent", which is the safe
    direction to be wrong in for a prioritisation queue.
    """
    if value is None:
        return default
    key = str(value).strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    return _SEVERITY_WORDS.get(key, default)


def severity_from_bands(
    value: Any, bands: Sequence[tuple[float, Severity]], *, default: Severity = Severity.UNKNOWN
) -> Severity:
    """A numeric vendor severity, banded by that vendor's own published thresholds.

    *bands* is ``((upper_exclusive, severity), …)`` in ascending order, and it is a
    parameter rather than a constant because the scales are not comparable: CrowdStrike
    grades 0-100 with documented breaks at 20/40/60/80, Defender grades in words, and
    a generic SaaS feed might grade 1-5 with 1 as *most* severe. A shared normaliser
    would have to guess which, and guessing inverted is worse than not mapping at all.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    for upper, severity in bands:
        if number < upper:
            return severity
    return bands[-1][1] if bands else default


def status_from_outcome(
    value: Any, *, success: Iterable[str] = (), failure: Iterable[str] = ()
) -> Status:
    """A vendor outcome string on OCSF's three-value status.

    Returns ``UNKNOWN`` rather than assuming success for an unrecognised value. A
    connector that defaulted to Success would report every novel Okta outcome as a
    successful authentication, which is the single most dangerous direction to be wrong
    in on this class of event.
    """
    if value is None:
        return Status.UNKNOWN
    key = str(value).strip().upper()
    if key in {s.upper() for s in success} or key in ("SUCCESS", "SUCCEEDED", "OK", "ALLOW"):
        return Status.SUCCESS
    if key in {f.upper() for f in failure} or key in (
        "FAILURE",
        "FAILED",
        "FAIL",
        "DENY",
        "DENIED",
        "ERROR",
    ):
        return Status.FAILURE
    return Status.UNKNOWN


# ── OCSF object builders ────────────────────────────────────────────────────


def resource_ref(
    *,
    uid: Any = None,
    name: Any = None,
    type: Any = None,
    region: Any = None,
    namespace: Any = None,
    cloud_partition: Any = None,
    group: Any = None,
    labels: Any = None,
    owner: Any = None,
    data: Any = None,
) -> dict[str, Any]:
    """One element of OCSF's ``resources`` array (a ``resource_details`` object).

    The plural array, not the singular ``resource`` — which is declared by only four
    classes (2002, 2003, 3005, 3006) and by none of the cloud ones. Every cloud
    connector needs this: CloudTrail's ``resources[].ARN``, Azure's ``resourceId`` and
    GCP's ``protoPayload.resourceName`` are *the* answer to "what was touched", and
    without a home they would sit in ``unmapped`` where no hunt query looks.

    Keys with no value are omitted rather than set to null, because these become a JSON
    string in the lake and ``json_extract`` on a key that is present-but-null and one
    that is absent behave the same only if every reader remembers to check both.
    """
    out: dict[str, Any] = {}
    for key, value in (
        ("uid", uid),
        ("name", name),
        ("type", type),
        ("region", region),
        ("namespace", namespace),
        ("cloud_partition", cloud_partition),
        ("group", group),
        ("labels", labels),
        ("owner", owner),
        ("data", data),
    ):
        if value not in (None, "", [], {}):
            out[key] = value
    return out


def finding_ref(
    *,
    uid: Any = None,
    title: Any = None,
    desc: Any = None,
    types: Any = None,
    created_time: Any = None,
    first_seen_time: Any = None,
    last_seen_time: Any = None,
    modified_time: Any = None,
    src_url: Any = None,
    product_uid: Any = None,
    analytic_name: Any = None,
    analytic_uid: Any = None,
    analytic_type_id: Any = None,
    data: Any = None,
) -> dict[str, Any]:
    """One element of OCSF's ``finding_info_list`` (a ``finding_info`` object).

    2005 Incident Finding *requires* this array, and an incident is precisely a set of
    member findings — so an incident record that cannot list them carries a severity, a
    status and no statement of what happened. CrowdStrike's ``incident_id`` clusters
    detections; Defender's ``incidentId`` clusters alerts across endpoint, identity,
    email and cloud; Phase 3's own correlator clusters CYPHRA detections. All three need
    this shape.

    The keyword names are OCSF's ``finding_info`` attribute names, deliberately *not*
    the ``finding_`` prefixed flat column names — the flat prefix exists to disambiguate
    thirteen columns sitting beside two hundred others on one row, and inside a nested
    object it would produce ``finding_info.finding_uid``. The singular columns and this
    builder therefore look different on purpose; :data:`core.schema.ocsf.OCSF_PATH` is
    the crosswalk.

    ``analytic_*`` collapse into a nested ``analytic`` object, matching the path the
    singular ``finding_analytic_*`` columns expand to. Empty values are omitted, for the
    same reason as :func:`resource_ref`.
    """
    out: dict[str, Any] = {}
    for key, value in (
        ("uid", uid),
        ("title", title),
        ("desc", desc),
        ("types", types),
        ("created_time", created_time),
        ("first_seen_time", first_seen_time),
        ("last_seen_time", last_seen_time),
        ("modified_time", modified_time),
        ("src_url", src_url),
        ("product_uid", product_uid),
        ("data", data),
    ):
        if value not in (None, "", [], {}):
            out[key] = value
    analytic: dict[str, Any] = {}
    for key, value in (
        ("name", analytic_name),
        ("uid", analytic_uid),
        ("type_id", analytic_type_id),
    ):
        if value not in (None, "", [], {}):
            analytic[key] = value
    if analytic:
        out["analytic"] = analytic
    return out


#: Sub-objects OCSF's ``evidences`` declares. Enumerated so :func:`evidence` can reject
#: a key that would land nowhere: ``evidences`` is stored as a JSON string, so an
#: unknown key would be *accepted* by the model, written to the lake, and then be
#: absent from every OCSF export — a silent loss with no counter attached.
EVIDENCE_KEYS = frozenset(
    {
        "actor",
        "api",
        "connection_info",
        "container",
        "data",
        "database",
        "databucket",
        "device",
        "dst_endpoint",
        "email",
        "file",
        "http_request",
        "http_response",
        "job",
        "name",
        "process",
        "query",
        "reg_key",
        "reg_value",
        "resources",
        "script",
        "src_endpoint",
        "tls",
        "uid",
        "url",
        "user",
        "verdict",
        "verdict_id",
        "win_service",
    }
)


def evidence(**fields: Any) -> dict[str, Any]:
    """One element of 2004's ``evidences`` array.

    This is the *only* conformant home for the per-alert detail Defender and
    CrowdStrike send. 2004 Detection Finding declares no top-level ``user``,
    ``process``, ``file``, ``src_endpoint`` or ``dst_endpoint`` — measured against the
    vendored v1.9.0 index, not assumed — so a connector that put a Defender alert's
    ``evidence[].fileName`` in ``file_name`` would have it moved to ``unmapped`` by
    :func:`~core.schema.ocsf.misplaced_fields` and named in ``soc_notes``. Correct
    behaviour, but it loses the column. The nested form under ``evidences`` keeps it.

    Unknown keys raise. That is the one place in this module that prefers a crash to a
    quiet route-elsewhere, because an unknown evidence key is a *coding* error in this
    package rather than a surprise from a vendor, and it is invisible in the lake.
    """
    unknown = sorted(set(fields) - EVIDENCE_KEYS)
    if unknown:
        raise ValueError(
            f"evidence() got {', '.join(unknown)}, which OCSF's evidences object does "
            f"not declare; the declared set is {', '.join(sorted(EVIDENCE_KEYS))}"
        )
    return {k: v for k, v in fields.items() if v not in (None, "", [], {})}


def prune(doc: Mapping[str, Any]) -> dict[str, Any]:
    """A nested dict with empty leaves removed, one level deep per branch.

    For hand-built ``evidences`` sub-objects: ``{"file": {"name": None, "path": "x"}}``
    should become ``{"file": {"path": "x"}}`` and ``{"file": {}}`` should vanish
    entirely, so an evidence element for an alert that carried no file detail does not
    render as a file with no properties.
    """
    out: dict[str, Any] = {}
    for key, value in doc.items():
        if isinstance(value, Mapping):
            inner = prune(value)
            if inner:
                out[key] = inner
        elif value not in (None, "", [], {}):
            out[key] = value
    return out


# ── 6003 API Activity's four verbs ──────────────────────────────────────────

#: Read: no state change. ``head`` and ``testiampermissions`` are here because they
#: are authorisation probes, which is exactly the reconnaissance a hunt wants to find.
_READ = frozenset(
    {
        "get", "list", "describe", "read", "download", "query", "search", "head",
        "lookup", "view", "export", "batchget", "testiampermissions", "check",
        "getiampolicy", "select", "scan", "preview", "resolve", "validate",
    }
)
#: Create: a thing that did not exist now does. ``insert`` is GCP's spelling,
#: ``run``/``launch`` are EC2's, ``register`` is ECS/Entra's.
_CREATE = frozenset(
    {
        "create", "add", "insert", "new", "register", "import", "upload", "generate",
        "provision", "allocate", "launch", "run", "invite", "issue", "clone",
        "copy", "post", "publish", "subscribe",
    }
)
#: Delete. ``revoke`` is the one judgment call in this table: AWS's dominant use is
#: ``RevokeSecurityGroupIngress``, which removes a rule, so Delete is right far more
#: often than not — but ``revokeSignInSessions`` on a Graph user is an *update* to that
#: user. Bucketed as Delete and the ambiguity left visible here rather than resolved by
#: a special case that would then be wrong for the next vendor. ``api_operation``
#: carries the real operation for anything that needs to tell them apart.
_DELETE = frozenset(
    {
        "delete", "remove", "terminate", "destroy", "deregister", "purge", "revoke",
        "drop", "unsubscribe", "release", "expire",
    }
)
#: Update: an existing thing changed. ``write`` is Azure's suffix, ``patch``/``set``
#: are GCP's, and the lifecycle verbs (``enable``, ``disable``, ``start``, ``stop``,
#: ``reboot``) are state changes to something that already exists rather than
#: creations of anything.
#:
#: ``put`` is the second judgment call. ``PutObject`` on a new S3 key creates; on an
#: existing key it overwrites; ``PutBucketPolicy`` and ``PutRolePolicy`` always
#: overwrite. AWS's own semantics are create-or-replace and OCSF has no upsert, so it
#: is bucketed as Update — which is right for the policy operations and arguably wrong
#: for a first ``PutObject``.
_UPDATE = frozenset(
    {
        "update", "modify", "set", "put", "patch", "attach", "detach", "associate",
        "disassociate", "enable", "disable", "assign", "unassign", "replace", "tag",
        "untag", "reset", "start", "stop", "restart", "reboot", "write", "move",
        "rename", "promote", "demote", "grant", "apply", "configure", "rotate",
        "setiampolicy", "restore", "sync", "upgrade", "downgrade", "resize",
    }
)

#: OCSF 6003 activity ids.
API_UNKNOWN, API_CREATE, API_READ, API_UPDATE, API_DELETE, API_OTHER = 0, 1, 2, 3, 4, 99


def _camel_words(text: str) -> list[str]:
    """``CreateServiceAccountKey`` → ``["create", "service", "account", "key"]``."""
    out: list[str] = []
    current = ""
    for ch in text:
        if ch.isupper() and current and not current[-1].isupper():
            out.append(current)
            current = ch
        else:
            current += ch
    if current:
        out.append(current)
    return [w.lower() for w in out if w]


def crud_activity(operation: Any) -> int:
    """6003's activity id for a vendor operation name.

    Three naming schemes, checked in the order that resolves them without a
    vendor flag:

    1. **Last path/dot segment** — Azure's ``Microsoft.Compute/virtualMachines/write``
       and GCP's ``v1.compute.instances.insert`` both put the verb at the end, and it
       is a whole segment, so an exact match there is unambiguous.
    2. **Leading CamelCase word** — CloudTrail's ``CreateUser``, ``DescribeInstances``,
       ``AssumeRole``. Checked second because ``SetIamPolicy``'s last dot-segment does
       not exist and its first word does.
    3. **Any CamelCase word of the last segment** — for compounds like
       ``instances.setMachineType`` where the verb is inside the segment.

    Returns :data:`API_OTHER` (99), never 0, when nothing matches: 0 means "not
    assessed" and this *was* assessed. The caller must set ``activity_name`` — the
    event model rejects an unnamed 99 outright, which is the check that keeps a
    coarse bucket from becoming an unlabelled one.
    """
    text = str(operation or "").strip()
    if not text:
        return API_UNKNOWN
    segments = [s for s in text.replace("/", ".").split(".") if s]
    candidates: list[str] = []
    if segments:
        candidates.append(segments[-1].lower())
        candidates.extend(_camel_words(segments[-1])[:1])
    candidates.extend(_camel_words(segments[0] if segments else text)[:1])
    if segments:
        candidates.extend(_camel_words(segments[-1]))
    for word in candidates:
        if word in _READ:
            return API_READ
        if word in _CREATE:
            return API_CREATE
        if word in _DELETE:
            return API_DELETE
        if word in _UPDATE:
            return API_UPDATE
    return API_OTHER


__all__ = [
    "API_CREATE",
    "API_DELETE",
    "API_OTHER",
    "API_READ",
    "API_UNKNOWN",
    "API_UPDATE",
    "EVIDENCE_KEYS",
    "MESSAGE_LIMIT",
    "TEXT_LIMIT",
    "as_bool",
    "attack",
    "clip",
    "crud_activity",
    "evidence",
    "finding_ref",
    "label",
    "note",
    "prune",
    "put",
    "resource_ref",
    "severity_from_bands",
    "severity_from_name",
    "stash",
    "status_from_outcome",
]

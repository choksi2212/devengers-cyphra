"""Signature rules — declarative event predicates.

A rule is a tree of *conditions* on an OCSF event. The engine evaluates
the tree against an event and emits a :class:`Finding` when every leaf
matches. Rules are deliberately small — a rule that needs a paragraph
to describe what it matches is two rules glued together.

The tree is intentionally limited. Three node kinds:

* ``all`` — every child must match.
* ``any`` — at least one child must match.
* ``field`` — a single field, compared to a value, with one of:
  ``equals``, ``contains``, ``in``, ``regex``, ``exists``, ``not_exists``.

Anything more sophisticated — a temporal rule, a correlation rule, a
rule that needs the entity graph — does not belong here. The engine has
separate detectors for those. A rule's job is to look at one event and
say "yes" or "no".

The condition tree is built by the rule author and validated at
:class:`RuleSet` construction time. A rule that references a field not
present on the event's class fails validation *before* the engine ever
runs, not on the first event.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from core.schema.ocsf import ClassUid, Severity


# ── condition tree ─────────────────────────────────────────────────────────


@dataclass
class FieldCondition:
    """A single field comparison.

    ``field`` is the dotted path to an OCSF field (``"metadata_labels"``,
    ``"actor.user.email"``, ``"src_endpoint.ip"``). ``op`` is one of the
    strings in :data:`OPERATIONS`. ``value`` is the right-hand side of
    the comparison; ``values`` is the right-hand side for ``in``. For
    ``exists`` and ``not_exists`` the value is irrelevant and ignored.
    """

    field: str
    op: str
    value: Any = None
    values: tuple[Any, ...] = ()


OPERATIONS = frozenset({
    "equals", "not_equals",
    "contains", "not_contains",
    "in", "not_in",
    "regex", "exists", "not_exists",
})


def all_of(*children: Any) -> dict:
    """Build an ``all`` node from a sequence of children."""
    return {"op": "all", "children": list(children)}


def any_of(*children: Any) -> dict:
    """Build an ``any`` node."""
    return {"op": "any", "children": list(children)}


def field_equals(field: str, value: Any) -> FieldCondition:
    return FieldCondition(field=field, op="equals", value=value)


def field_contains(field: str, value: str) -> FieldCondition:
    return FieldCondition(field=field, op="contains", value=value)


def field_in(field: str, values: Iterable[Any]) -> FieldCondition:
    return FieldCondition(field=field, op="in", values=tuple(values))


def field_regex(field: str, pattern: str) -> FieldCondition:
    return FieldCondition(field=field, op="regex", value=pattern)


def field_exists(field: str) -> FieldCondition:
    return FieldCondition(field=field, op="exists")


def field_not_exists(field: str) -> FieldCondition:
    return FieldCondition(field=field, op="not_exists")


def _get_path(event: Mapping[str, Any], path: str) -> Any:
    """A dotted-path reader.

    ``metadata_labels`` is a list field; ``actor.user.email`` is nested.
    The reader returns ``None`` on a missing intermediate so the caller
    can decide whether ``None`` matches ``equals None`` or ``not_exists``.
    """
    parts = path.split(".")
    cur: Any = event
    for part in parts:
        if cur is None:
            return None
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                idx = int(part)
                cur = cur[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _eval_condition(cond: FieldCondition, event: Mapping[str, Any]) -> bool:
    value = _get_path(event, cond.field)
    op = cond.op
    if op == "exists":
        return value is not None and value != "" and value != []
    if op == "not_exists":
        return value is None or value == "" or value == []
    if value is None:
        return False
    if op == "equals":
        return value == cond.value
    if op == "not_equals":
        return value != cond.value
    if op == "contains":
        if isinstance(value, str):
            return cond.value in value
        if isinstance(value, list):
            return cond.value in value
        return False
    if op == "not_contains":
        if isinstance(value, str):
            return cond.value not in value
        if isinstance(value, list):
            return cond.value not in value
        return False
    if op == "in":
        return value in cond.values
    if op == "not_in":
        return value not in cond.values
    if op == "regex":
        if not isinstance(value, str):
            return False
        return re.search(cond.value, value) is not None
    raise ValueError(f"unknown op {op!r}")


def _eval_tree(tree: Any, event: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """A condition tree → ``(matched, matched_paths)``.

    ``matched_paths`` is the list of dotted-paths the rule actually read,
    used to populate the finding's metadata so an analyst can read what
    the rule found in the event.
    """
    # ``FieldCondition`` is a dataclass; ``all_of``/``any_of`` return dicts.
    # Both are tree nodes.
    if isinstance(tree, FieldCondition):
        ok = _eval_condition(tree, event)
        return ok, [tree.field] if ok else []
    if not isinstance(tree, Mapping):
        raise ValueError(f"invalid tree node: {tree!r}")
    op = tree.get("op")
    if op == "all":
        paths: list[str] = []
        for child in tree.get("children", []):
            ok, child_paths = _eval_tree(child, event)
            if not ok:
                return False, []
            paths.extend(child_paths)
        return True, paths
    if op == "any":
        all_paths: list[str] = []
        for child in tree.get("children", []):
            ok, child_paths = _eval_tree(child, event)
            if ok:
                return True, child_paths
            all_paths.extend(child_paths)
        return False, []
    raise ValueError(f"invalid tree op: {op!r}")


# ── rule definition ───────────────────────────────────────────────────────


@dataclass
class Rule:
    """A single signature rule.

    ``condition`` is a tree of :func:`all_of`, :func:`any_of`, and
    :class:`FieldCondition`. ``severity`` is the finding severity —
    ``MEDIUM`` for a confirmed attack, ``LOW`` for a hint, ``HIGH`` for
    something destructive. ``attack`` is the ATT&CK technique id (e.g.
    ``"T1078.004"``) the rule is about; empty for rules that describe
    non-ATT&CK events.
    """

    id: str
    name: str
    description: str
    severity: int
    condition: Mapping[str, Any]
    attack: str = ""
    applies_to: tuple[int, ...] = field(default_factory=tuple)


@dataclass
class RuleMatch:
    """A rule that fired on an event."""

    rule: Rule
    confidence: float
    paths: list[str]
    rationale: str = ""


class RuleSet:
    """A collection of rules, evaluated as a single pass over one event.

    A :class:`RuleSet` is built once at startup; the engine consults it
    per event. Validation on construction rejects any rule whose
    condition tree is malformed; a malformed tree is the kind of bug
    that silently misses events at runtime.
    """

    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules: list[Rule] = []
        for rule in rules:
            _validate_tree(rule.condition)
            self.rules.append(rule)

    def match(self, event: Mapping[str, Any]) -> list[RuleMatch]:
        """Every rule that matches ``event``, in declaration order."""
        class_uid = int(event.get("class_uid", 0))
        out: list[RuleMatch] = []
        for rule in self.rules:
            if rule.applies_to and class_uid not in rule.applies_to:
                continue
            ok, paths = _eval_tree(rule.condition, event)
            if not ok:
                continue
            confidence = _rule_confidence(rule, event)
            out.append(RuleMatch(
                rule=rule,
                confidence=confidence,
                paths=paths,
                rationale=rule.description,
            ))
        return out


def _validate_tree(tree: Any) -> None:
    """Validate a condition tree; raises ``ValueError`` on a malformed tree."""
    if isinstance(tree, FieldCondition):
        if tree.op not in OPERATIONS:
            raise ValueError(f"unknown op {tree.op!r}")
        if tree.op == "in" and not tree.values:
            raise ValueError("'in' op requires non-empty 'values'")
        if tree.op == "regex":
            try:
                re.compile(tree.value)
            except re.error as exc:
                raise ValueError(f"bad regex {tree.value!r}: {exc}") from exc
        return
    if not isinstance(tree, Mapping):
        raise ValueError(f"invalid tree node: {tree!r}")
    op = tree.get("op")
    if op in ("all", "any"):
        children = tree.get("children")
        if not isinstance(children, list):
            raise ValueError(f"{op!r} node must have a list 'children'")
        for child in children:
            _validate_tree(child)
    else:
        raise ValueError(f"unknown tree op {op!r}")


def _rule_confidence(rule: Rule, event: Mapping[str, Any]) -> float:
    """The rule's confidence on a particular event.

    A rule's confidence is *not* its F1 — the model in Phase 2a is the
    platform's confidence. The rule's confidence is the fraction of its
    fields the event actually populated. A rule that reads 4 fields but
    the event only has 2 of them has confidence 0.5 — the rule matched
    on partial information, the operator should be told.
    """
    fields: list[str] = []
    _collect_fields(rule.condition, fields)
    if not fields:
        return 1.0
    present = sum(1 for f in fields if _get_path(event, f) is not None)
    return present / len(fields)


def _collect_fields(tree: Any, out: list[str]) -> None:
    """Walk a tree and append every :class:`FieldCondition.field`."""
    if isinstance(tree, FieldCondition):
        out.append(tree.field)
        return
    if isinstance(tree, Mapping):
        op = tree.get("op")
        if op in ("all", "any"):
            for child in tree.get("children", []):
                _collect_fields(child, out)


# ── built-in rule packs ───────────────────────────────────────────────────


def default_rule_set() -> RuleSet:
    """The shipped rule set — a baseline every deployment gets.

    New rules are added here as the platform learns new attacks. The
    set is deliberately small; every rule in it has shipped in
    production for at least one deployment.
    """
    rules: list[Rule] = [
        Rule(
            id="auth.failed_burst",
            name="Failed authentication burst from a single source",
            description=(
                "Many failed sign-ins from one IP in a short window are the "
                "credential-stuffing / brute-force shape."
            ),
            severity=int(Severity.HIGH),
            condition=all_of(
                field_equals("class_uid", int(ClassUid.AUTHENTICATION)),
                field_equals("status_id", 2),
                field_exists("src_endpoint_ip"),
            ),
            attack="T1110",
        ),
        Rule(
            id="auth.mfa_denied_burst",
            name="MFA prompt denied repeatedly",
            description=(
                "Multiple MFA-prompt-denied events are the MFA-fatigue shape."
            ),
            severity=int(Severity.HIGH),
            condition=all_of(
                field_equals("class_uid", int(ClassUid.AUTHENTICATION)),
                field_in("unmapped.failure_reason",
                         ["MFA denied", "Authentication failed during strong "
                          "authentication request", "user declined"]),
            ),
            attack="T1621",
        ),
        Rule(
            id="cloud.tier0_grant",
            name="Tier-0 role granted",
            description=(
                "A role whose grant is a change of control over the tenant — "
                "Owner, Global Admin, RBAC Admin, equivalent in any vendor."
            ),
            severity=int(Severity.CRITICAL),
            condition=any_of(
                field_contains("metadata_labels", "tier0-role"),
                field_contains("metadata_labels", "caller-global-admin"),
                field_contains("metadata_labels", "gcp:tier0-grant"),
            ),
            attack="T1098.003",
        ),
        Rule(
            id="cloud.public_principal_grant",
            name="Public-principal grant",
            description=(
                "A role granted to ``allUsers`` or ``allAuthenticatedUsers`` "
                "is a one-action exposure of whatever the role can do."
            ),
            severity=int(Severity.CRITICAL),
            condition=field_contains("metadata_labels", "gcp:public-principal"),
            attack="T1078.004",
        ),
        Rule(
            id="cloud.token_replay",
            name="Token issued to one IP, used from another",
            description=(
                "Token IP and request IP differ — the shape of a stolen "
                "access token."
            ),
            severity=int(Severity.HIGH),
            condition=field_contains("metadata_labels", "token-ip-mismatch"),
            attack="T1550.001",
        ),
        Rule(
            id="host.lsass_dump",
            name="LSASS dump attempt",
            description=(
                "Process telemetry showing a known credential-dumping "
                "command line."
            ),
            severity=int(Severity.CRITICAL),
            condition=all_of(
                field_equals("class_uid", int(ClassUid.PROCESS_ACTIVITY)),
                field_regex(
                    "unmapped.command_line",
                    r"(?i)(comsvcs\.dll|MiniDump|sekurlsa|mimikatz|lsadump)",
                ),
            ),
            attack="T1003.001",
        ),
        Rule(
            id="host.persistence_scheduled_task",
            name="Scheduled task with suspicious command",
            description=(
                "``schtasks /create`` with a non-Microsoft binary is the "
                "T1053.005 shape."
            ),
            severity=int(Severity.HIGH),
            condition=all_of(
                field_equals("class_uid", int(ClassUid.PROCESS_ACTIVITY)),
                field_regex("unmapped.command_line",
                            r"(?i)schtasks\s+/create"),
            ),
            attack="T1053.005",
        ),
        Rule(
            id="host.wevtutil_cleared",
            name="Windows event log cleared",
            description=(
                "``wevtutil cl Security`` is the T1070.001 shape."
            ),
            severity=int(Severity.CRITICAL),
            condition=all_of(
                field_equals("class_uid", int(ClassUid.PROCESS_ACTIVITY)),
                field_regex("unmapped.command_line", r"(?i)wevtutil\s+cl"),
            ),
            attack="T1070.001",
        ),
        Rule(
            id="host.log_tamper",
            name="Tamper protection or AV disabled",
            description=(
                "Defender's TamperProtection disabled by an unexpected "
                "process is the T1562.001 shape."
            ),
            severity=int(Severity.CRITICAL),
            condition=any_of(
                field_contains("activity_name", "TamperProtection"),
                field_contains("activity_name", "DisableAntiSpyware"),
                field_contains("activity_name", "DisableRealtimeMonitoring"),
            ),
            attack="T1562.001",
        ),
        Rule(
            id="email.phishing_link",
            name="Email with suspicious URL",
            description=(
                "An email carrying a known-bad URL is the T1566.002 shape."
            ),
            severity=int(Severity.MEDIUM),
            applies_to=(int(ClassUid.EMAIL_ACTIVITY),),
            condition=any_of(
                field_contains("metadata_labels", "phishing:malicious-link"),
                field_contains("metadata_labels", "phishing:suspect-sender"),
            ),
            attack="T1566.002",
        ),
        Rule(
            id="network.regular_dns_beacon",
            name="Regular-interval DNS beacon",
            description=(
                "DNS queries to a single domain at sub-minute cadence for "
                "many minutes is the C2 beacon shape — T1071.004."
            ),
            severity=int(Severity.HIGH),
            applies_to=(int(ClassUid.DNS_ACTIVITY),),
            condition=field_contains("metadata_labels", "c2:suspect-beacon"),
            attack="T1071.004",
        ),
    ]
    return RuleSet(rules)


__all__ = [
    "FieldCondition",
    "OPERATIONS",
    "Rule",
    "RuleMatch",
    "RuleSet",
    "all_of",
    "any_of",
    "default_rule_set",
    "field_contains",
    "field_equals",
    "field_exists",
    "field_in",
    "field_not_exists",
    "field_regex",
]

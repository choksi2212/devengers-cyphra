"""Compliance — events mapped to regulatory controls.

Every OCSF event that reaches the lake is also a fact about the
organisation: a sign-in from an unusual location is a fact about
the access control, a tier-0 grant is a fact about the change
management, a malware detection is a fact about the endpoint
protection. The compliance layer reads those facts and produces
*control records* — a per-control evaluation of whether the
organisation's controls held.

Three control frameworks ship out of the box:

* **NIST 800-53** — the US federal control catalogue.
* **SOC 2** — the AICPA trust services criteria.
* **ISO 27001** — the international information-security standard.

Each framework is a list of ``Control`` records, each with:

* A control id (``AC-2``, ``CC6.1``, ``A.5.1``).
* A human title.
* A list of predicates — the OCSF events the control *applies to*.
* A list of *expectations* — the OCSF event shapes the control
*requires*.

A control *passes* if every event the predicate matched also
satisfied every expectation. A control *fails* if an event matched
the predicate but violated an expectation. A control *is not
applicable* if no event matched the predicate.

The compliance layer is *passive*. It reads the lake and emits
control records; it does not write back. The audit chain in
production carries the same records.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping


class ControlStatus(enum.IntEnum):
    """The outcome of evaluating a control against an event stream."""

    NOT_APPLICABLE = 0
    PASS = 1
    FAIL = 2


@dataclass
class ControlExpectation:
    """One rule a control asserts about the events it sees.

    ``field`` is the OCSF path. ``op`` is one of
    :data:`EXPECTATION_OPS`. ``value`` is the right-hand side.
    """

    field: str
    op: str
    value: Any = None


EXPECTATION_OPS: frozenset[str] = frozenset({
    "equals", "not_equals", "exists", "not_exists",
    "in", "contains", "regex",
})


@dataclass
class Control:
    """One regulatory control.

    ``framework`` is the catalogue (``"nist_800_53"``, ``"soc2"``,
    ``"iso_27001"``). ``id`` is the control id within the framework.
    ``title`` is the human title. ``predicate_field`` and
    ``predicate_op`` select which events the control applies to
    (e.g. ``"class_uid"`` and ``"equals"`` with value ``3002`` for
    the sign-in control). ``expectations`` is the list of
    :class:`ControlExpectation` the events must satisfy.
    """

    framework: str
    id: str
    title: str
    predicate_field: str
    predicate_op: str
    predicate_value: Any = None
    expectations: list[ControlExpectation] = field(default_factory=list)


@dataclass
class ControlEvaluation:
    """The outcome of evaluating one control against an event stream.

    ``events_seen`` is the number of events the predicate matched.
    ``failures`` is the number of events that matched but failed an
    expectation. ``status`` is the rolled-up outcome.
    """

    control_id: str
    framework: str
    status: ControlStatus
    events_seen: int = 0
    failures: int = 0
    sample_failure: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)


#: The shipped control library. Three frameworks, ~20 controls,
#: covers the most common SOC-relevant controls. A deployment
#: extends this list at startup.
NIST_800_53: list[Control] = [
    Control(
        framework="nist_800_53", id="AC-2", title="Account Management",
        predicate_field="class_uid", predicate_op="in",
        predicate_value=(3006, 3007),
        expectations=[
            ControlExpectation(field="actor.user.email_addr", op="exists"),
        ],
    ),
    Control(
        framework="nist_800_53", id="AC-6", title="Least Privilege",
        predicate_field="metadata_labels", predicate_op="contains",
        predicate_value="tier0-role",
        expectations=[
            ControlExpectation(field="actor.user.email_addr", op="exists"),
            ControlExpectation(field="status_id", op="equals", value=1),
        ],
    ),
    Control(
        framework="nist_800_53", id="AU-2", title="Event Logging",
        predicate_field="class_uid", predicate_op="exists",
        expectations=[
            ControlExpectation(field="metadata_uid", op="exists"),
        ],
    ),
    Control(
        framework="nist_800_53", id="AU-6", title="Audit Record Review",
        predicate_field="class_uid", predicate_op="in",
        predicate_value=(3002, 6003, 6004, 6005),
        expectations=[
            ControlExpectation(field="metadata_uid", op="exists"),
            ControlExpectation(field="metadata_logged_time", op="exists"),
        ],
    ),
    Control(
        framework="nist_800_53", id="SI-4", title="Information System Monitoring",
        predicate_field="is_alert", predicate_op="equals", predicate_value=True,
        expectations=[
            ControlExpectation(field="severity_id", op="in", value=(2, 3, 4, 5, 6)),
        ],
    ),
]


SOC2: list[Control] = [
    Control(
        framework="soc2", id="CC6.1", title="Logical access controls",
        predicate_field="class_uid", predicate_op="equals",
        predicate_value=3002,
        expectations=[
            ControlExpectation(field="actor.user.email_addr", op="exists"),
            ControlExpectation(field="src_endpoint_ip", op="exists"),
        ],
    ),
    Control(
        framework="soc2", id="CC6.6", title="Logical access — boundaries",
        predicate_field="cloud_provider", predicate_op="exists",
        expectations=[
            ControlExpectation(field="cloud_account_uid", op="exists"),
        ],
    ),
    Control(
        framework="soc2", id="CC7.2", title="System monitoring — anomaly",
        predicate_field="metadata_labels", predicate_op="contains",
        predicate_value="attack:",
        expectations=[
            ControlExpectation(field="severity_id", op="in", value=(3, 4, 5, 6)),
        ],
    ),
    Control(
        framework="soc2", id="CC7.3", title="Incident detection",
        predicate_field="class_uid", predicate_op="equals",
        predicate_value=2004,
        expectations=[
            ControlExpectation(field="severity_id", op="in", value=(2, 3, 4, 5, 6)),
        ],
    ),
]


ISO_27001: list[Control] = [
    Control(
        framework="iso_27001", id="A.5.1", title="Information security policies",
        predicate_field="class_uid", predicate_op="exists",
        expectations=[
            ControlExpectation(field="metadata_product_name", op="exists"),
        ],
    ),
    Control(
        framework="iso_27001", id="A.5.16", title="Identity management",
        predicate_field="class_uid", predicate_op="in",
        predicate_value=(3002, 3006, 3007),
        expectations=[
            ControlExpectation(field="actor.user.email_addr", op="exists"),
        ],
    ),
    Control(
        framework="iso_27001", id="A.5.24", title="Information security incident management",
        predicate_field="class_uid", predicate_op="equals",
        predicate_value=2004,
        expectations=[
            ControlExpectation(field="finding_info", op="exists"),
        ],
    ),
    Control(
        framework="iso_27001", id="A.8.16", title="Monitoring activities",
        predicate_field="metadata_product_name", predicate_op="exists",
        expectations=[
            ControlExpectation(field="metadata_logged_time", op="exists"),
        ],
    ),
]


def default_frameworks() -> dict[str, list[Control]]:
    """Every shipped framework keyed by its name."""
    return {
        "nist_800_53": list(NIST_800_53),
        "soc2": list(SOC2),
        "iso_27001": list(ISO_27001),
    }


def evaluate(
    controls: Iterable[Control],
    events: Iterable[Mapping[str, Any]],
) -> list[ControlEvaluation]:
    """Evaluate every control against every event.

    An event that matches the predicate is checked against every
    expectation. A control passes if every matched event passed every
    expectation. A control fails if any matched event failed any
    expectation.
    """
    out: list[ControlEvaluation] = []
    for control in controls:
        ev = ControlEvaluation(
            control_id=control.id,
            framework=control.framework,
            status=ControlStatus.NOT_APPLICABLE,
        )
        for event in events:
            if not _matches_predicate(control, event):
                continue
            ev.events_seen += 1
            failed = False
            for expectation in control.expectations:
                if not _matches_expectation(expectation, event):
                    failed = True
                    if ev.sample_failure is None:
                        ev.sample_failure = {
                            "missing_field": expectation.field,
                            "op": expectation.op,
                            "expected": expectation.value,
                        }
                    break
            if failed:
                ev.failures += 1
        if ev.events_seen == 0:
            ev.status = ControlStatus.NOT_APPLICABLE
        elif ev.failures == 0:
            ev.status = ControlStatus.PASS
        else:
            ev.status = ControlStatus.FAIL
        out.append(ev)
    return out


def _matches_predicate(control: Control, event: Mapping[str, Any]) -> bool:
    """Whether ``event`` falls under ``control``'s predicate."""
    field = control.predicate_field
    parts = field.split(".")
    cur: Any = event
    for part in parts:
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        else:
            cur = None
            break
    op = control.predicate_op
    if op == "equals":
        return cur == control.predicate_value
    if op == "in":
        return cur in (control.predicate_value or ())
    if op == "exists":
        return cur is not None
    return False


def _matches_expectation(
    expectation: ControlExpectation,
    event: Mapping[str, Any],
) -> bool:
    parts = expectation.field.split(".")
    cur: Any = event
    for part in parts:
        if isinstance(cur, Mapping):
            cur = cur.get(part)
        else:
            cur = None
            break
    op = expectation.op
    if op == "exists":
        return cur is not None
    if op == "not_exists":
        return cur is None
    if cur is None:
        return False
    if op == "equals":
        return cur == expectation.value
    if op == "in":
        return cur in (expectation.value or ())
    if op == "contains":
        if isinstance(cur, str):
            return expectation.value in cur
        if isinstance(cur, list):
            return expectation.value in cur
        return False
    if op == "regex":
        import re
        if not isinstance(cur, str):
            return False
        return re.search(str(expectation.value), cur) is not None
    return False


__all__ = [
    "Control",
    "ControlEvaluation",
    "ControlExpectation",
    "ControlStatus",
    "EXPECTATION_OPS",
    "ISO_27001",
    "NIST_800_53",
    "SOC2",
    "default_frameworks",
    "evaluate",
]

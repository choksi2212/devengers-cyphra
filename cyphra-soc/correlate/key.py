"""Correlation keys — the recipe for "same incident".

A finding's correlation key is a string the correlate engine matches
against open incidents. Two findings with the same key join the same
incident (subject to the merge window). Keys are deterministic — the
same finding always produces the same key — and bounded — the key
space is small enough to fit in a hash table.

Two shipped recipes:

* ``actor_time_key`` — the same actor + the same ATT&CK technique +
  within ``merge_window_seconds`` of the incident's last update. The
  default recipe; the most common shape across the SOC's tests.
* ``target_time_key`` — the same target asset + any actor. Useful for
  "the same database is being probed from every angle".

A deployment extends the recipes with more, or implements its own
function with the same signature.
"""

from __future__ import annotations

from typing import Any, Mapping


def actor_time_key(finding: Mapping[str, Any]) -> str:
    """``f"actor:{actor}:attack:{attack_id}"`` — the default recipe.

    Two findings from the same actor on the same technique join the
    same incident. An empty actor or attack id produces an
    actor-/attack-specific key (the correlate engine rejects empty
    keys by giving each finding its own incident).
    """
    actor = str(finding.get("actor_key") or "")
    attack = str(finding.get("attack_id") or "")
    if not actor and not attack:
        return ""
    return f"actor:{actor}:attack:{attack}"


def target_time_key(finding: Mapping[str, Any]) -> str:
    """``f"target:{target1+target2}"`` — joins findings targeting the same asset.

    Used when the same database or bucket is the focus of an attack
    from many actors. The key is the sorted concatenation of every
    target, so two findings touching both assets get the same key.
    """
    targets = finding.get("target_keys") or ()
    if not targets:
        return ""
    if not isinstance(targets, (list, tuple)):
        return f"target:{targets}"
    return "target:" + "+".join(sorted(str(t) for t in targets))


def first_key(finding: Mapping[str, Any]) -> str:
    """Pick the first non-empty key from a list of recipes.

    A deployment that wants multi-recipe behaviour composes the
    recipes here. The function returns the first non-empty string the
    recipes produce; an empty string falls through to the engine's
    adhoc fallback.
    """
    for recipe in (actor_time_key, target_time_key):
        key = recipe(finding)
        if key:
            return key
    return ""


__all__ = ["actor_time_key", "first_key", "target_time_key"]

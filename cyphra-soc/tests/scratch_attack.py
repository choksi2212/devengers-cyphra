"""Scratch verification for core.schema.attack against the vendored v19.2 bundle."""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from core.schema.attack import (
    TACTIC_ALIASES,
    Attack,
    AttackError,
    UnknownTechnique,
    _source_satisfied,
    _tid_sort_key,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


IDX = Path("vendor/attack/attack_index.json")


def main():
    print("── load ──")
    t0 = time.perf_counter()
    a = Attack.load(IDX)
    load_ms = (time.perf_counter() - t0) * 1000
    check("index loads fast enough for process start", load_ms < 2000,
          f"{load_ms:.0f} ms for {IDX.stat().st_size/1e6:.1f} MB")
    check("version is the vendored one", a.version == "19.2", a.version)
    check("source digest recorded", len(a.source_sha256) == 64, a.source_sha256[:16] + "…")
    try:
        Attack({"index_version": 999})
        check("a stale index version is refused", False)
    except AttackError as exc:
        check("a stale index version is refused", True, str(exc)[:60])
    try:
        Attack.load("vendor/attack/does-not-exist.json")
        check("a missing index tells you how to build it", False)
    except AttackError as exc:
        check("a missing index tells you how to build it",
              "core.schema.attack build" in str(exc))

    print("\n── techniques ──")
    t = a.technique("T1110.001")
    check("subtechnique resolves", t.name == "Password Guessing", str(t))
    check("subtechnique knows its parent", t.parent == "T1110" and t.is_subtechnique)
    check("base_id derives correctly", t.base_id == "T1110")
    check("lowercase ids are accepted", a.technique("t1110.001").id == "T1110.001")
    check("tactic membership is populated", t.tactics == ("credential-access",), str(t.tactics))
    check("platforms are populated", "Windows" in t.platforms and len(t.platforms) > 5,
          f"{len(t.platforms)} platforms")
    parent = a.parent_of("T1110.001")
    check("parent lookup works", parent is not None and parent.name == "Brute Force")
    subs = a.subtechniques("T1110")
    check("subtechniques enumerate", [s.id for s in subs] ==
          ["T1110.001", "T1110.002", "T1110.003", "T1110.004"], str([s.id for s in subs]))
    check("subtechniques of a subtechnique resolve to its siblings",
          [s.id for s in a.subtechniques("T1110.003")] == [s.id for s in subs],
          "the base id is used, so a sub-id is not a dead end")
    try:
        a.technique("T9999")
        check("unknown technique raises", False)
    except UnknownTechnique as exc:
        check("unknown technique raises", "not a technique" in str(exc))
    check("get() returns None instead of raising", a.get("T9999") is None)

    print("\n── revoked and deprecated resolution ──")
    t, note = a.resolve("T1086")
    check("a revoked id resolves forward", t.id == "T1059.001", f"T1086 → {t.id}")
    check("the substitution is reported, not silent",
          note is not None and "revoked" in note and "T1059.001" in note, note)
    t, note = a.resolve("T1110.001")
    check("a current id resolves with no note", t.id == "T1110.001" and note is None)

    # The chain case: three v19 techniques revoke to a technique that is itself
    # revoked. A single hop returns a revoked answer.
    revoked = a._revoked_by
    chained = [s for s, d in revoked.items() if d in revoked]
    check("the bundle really does contain multi-hop revocations", len(chained) == 3,
          str(chained))
    for src in chained:
        final, note = a.resolve(src)
        check(f"{src} resolves all the way to a live technique",
              not final.revoked and final.id not in revoked,
              f"{src} → {final.id} ({final.name})")
        check(f"{src}'s note names the intermediate hop",
              "via" in (note or ""), note)
    check("every revoked technique resolves to something live",
          all(not a.resolve(r)[0].revoked for r in revoked),
          f"{len(revoked)} revoked ids checked")

    dep = [t for t in a.techniques.values() if t.deprecated and not t.revoked]
    check("deprecated-not-revoked techniques exist", len(dep) == 12, str(len(dep)))
    d, note = a.resolve(dep[0].id)
    check("a deprecated technique is returned as itself, not remapped to a guess",
          d.id == dep[0].id and "no \nreplacement" not in (note or ""),
          f"{d.id}: {note}")
    check("the deprecation is still reported", "deprecated" in (note or ""), note)

    print("\n── cyclic chain protection ──")
    a._revoked_by["T1110.001"] = "T1110.002"
    a._revoked_by["T1110.002"] = "T1110.001"
    try:
        a.resolve("T1110.001")
        check("a cyclic revoked-by chain raises instead of hanging", False)
    except AttackError as exc:
        check("a cyclic revoked-by chain raises instead of hanging",
              "cyclic" in str(exc), str(exc)[:70])
    del a._revoked_by["T1110.001"], a._revoked_by["T1110.002"]

    print("\n── tactics, including the v19 rename ──")
    check("15 tactics in v19.2", len(a.tactics) == 15, str(len(a.tactics)))
    tac, note = a.tactic("TA0005")
    check("TA0005 is now Stealth, not Defense Evasion",
          tac.name == "Stealth" and note is None, f"{tac.id} {tac.name}")
    check("defense-impairment is a real separate tactic",
          a.tactic("defense-impairment")[0].id == "TA0112")
    check("no tactic is named defense-evasion any more",
          "defense-evasion" not in a._tactic_by_short)
    tac, note = a.tactic("defense-evasion")
    check("the retired shortname still resolves", tac.id == "TA0005")
    check("but the caller is told an alias was followed, and why it is imprecise",
          note is not None and "retired" in note and "split" in note, note)
    check("display names resolve", a.tactic("Credential Access")[0].id == "TA0006")
    check("underscores and case are tolerated", a.tactic("LATERAL_MOVEMENT")[0].id == "TA0008")
    try:
        a.tactic("not-a-tactic")
        check("an unknown tactic raises and lists the valid ones", False)
    except AttackError as exc:
        check("an unknown tactic raises and lists the valid ones",
              "stealth" in str(exc) and "credential-access" in str(exc))
    check("every alias target actually exists",
          all(v in a._tactic_by_short for v in TACTIC_ALIASES.values()))
    stealth = a.techniques_for_tactic("stealth")
    # Computed, not hardcoded: the raw bundle has 212 attack-patterns phased into
    # stealth, but 64 of those are revoked. techniques_for_tactic returns the live
    # set, so the number to compare against is the other tactics' live counts.
    per_tactic = {t.shortname: len(a.techniques_for_tactic(t.shortname)) for t in a.tactics.values()}
    biggest = max(per_tactic.items(), key=lambda kv: kv[1])
    check("stealth is the largest tactic in v19",
          biggest[0] == "stealth" and len(stealth) == biggest[1],
          f"{len(stealth)} live techniques vs next-largest "
          f"{sorted(per_tactic.values(), reverse=True)[1]}")
    check("techniques_for_tactic excludes revoked",
          not any(t.revoked or t.deprecated for t in stealth))

    print("\n── scoping ──")
    live = a.current_techniques()
    check("current_techniques excludes revoked and deprecated",
          len(live) == 697, f"{len(live)} of {len(a.techniques)}")
    check("live set is sorted numerically, not lexically",
          [t.id for t in live][:3] == sorted([t.id for t in live][:3], key=_tid_sort_key)
          and _tid_sort_key("T1110.002") > _tid_sort_key("T1110.001")
          and _tid_sort_key("T1009") < _tid_sort_key("T1110"),
          "T1009 < T1110 requires numeric sorting")
    win = a.current_techniques(platforms=["Windows"])
    lin = a.current_techniques(platforms=["Linux"])
    check("platform scoping narrows the set", 0 < len(win) < len(live),
          f"Windows {len(win)}, Linux {len(lin)}, all {len(live)}")
    check("platform scoping is case-insensitive",
          len(a.current_techniques(platforms=["windows"])) == len(win))
    base_only = a.current_techniques(include_subtechniques=False)
    check("base-technique-only scoping works",
          len(base_only) == 222 and not any(t.is_subtechnique for t in base_only),
          str(len(base_only)))

    print("\n── log sources (the v19 detection-strategy path) ──")
    check("most live techniques have named log sources",
          len([t for t in live if t.observable]) == 652,
          f"{len([t for t in live if t.observable])} of {len(live)}")
    t = a.technique("T1110.001")
    check("a technique carries concrete channels, not just data source names",
          any(":" in str(s) or s.channel for s in t.log_sources),
          str([str(s) for s in t.log_sources][:3]))
    check("detection strategies are recorded",
          all(s.startswith("DET") for s in t.detection_strategies) and t.detection_strategies,
          str(t.detection_strategies))
    check("data components are recorded",
          all(c.startswith("DC") for c in t.data_components) and t.data_components,
          str(t.data_components[:3]))
    ranked = a.log_sources()
    top_name, top_n = next(iter(ranked.items()))
    check("Sysmon process creation is the single highest-value source",
          "Sysmon" in top_name and "EventCode=1" in top_name,
          f"{top_name} → {top_n} techniques")
    check("the ranking is a real collection roadmap",
          top_n > 250 and list(ranked.values()) == sorted(ranked.values(), reverse=True),
          f"{len(ranked)} distinct sources, top covers {top_n}/{len(live)} techniques")
    win_ranked = a.log_sources(platforms=["Windows"])
    check("ranking is platform-scopable",
          "auditd" not in next(iter(win_ranked)), next(iter(win_ranked)))

    print("\n── source matching semantics ──")
    have = {"wineventlog:security"}
    check("a collected channel satisfies a specific event code",
          _source_satisfied("WinEventLog:Security:EventCode=4769".lower(), have),
          "reading a channel reads every event id on it")
    check("a different channel is not satisfied",
          not _source_satisfied("wineventlog:sysmon:eventcode=1", have))
    check("a bare substring does not match",
          not _source_satisfied("appsecurity:foo", {"security"}),
          "boundary-anchored, so 'Security' does not match 'AppSecurity'")
    check("an exact match satisfies", _source_satisfied("m365:unified", {"m365:unified"}))

    print("\n── actors ──")
    st = a.stats()
    check("groups, campaigns and software are indexed",
          st["groups"] == 176 and st["campaigns"] == 56 and st["software"] == 825,
          f"{st['groups']}g / {st['campaigns']}c / {st['software']}s")
    hits = a.find_actor("APT29")
    check("a group resolves by name", len(hits) == 1 and hits[0].kind == "group", str(hits[:1]))
    check("a group resolves by alias",
          any(g.name == "APT29" for g in a.find_actor("Cozy Bear")),
          str([g.name for g in a.find_actor("Cozy Bear")]))
    using = a.actors_using("T1110", kinds=["group"])
    check("actors_using rolls sub-technique usage up to the base technique",
          len(using) > len(a.actors_using("T1110.001", kinds=["group"])),
          f"T1110 {len(using)} groups vs T1110.001 "
          f"{len(a.actors_using('T1110.001', kinds=['group']))}")
    check("actors_using follows a revoked mapping",
          a.actors_using("T1086") == a.actors_using("T1059.001"))
    check("a technique lists the groups that use it",
          len(a.technique("T1059.001").groups) > 20,
          f"{len(a.technique('T1059.001').groups)} groups")
    check("mitigations are the 44 live M-numbered ones, not the 224 retired ones",
          st["mitigations"] == 44 and all(m.startswith("M") for m in a.mitigations),
          f"{st['mitigations']} mitigations")
    check("a technique lists its mitigations",
          all(m.startswith("M") for m in a.technique("T1110").mitigations)
          and a.technique("T1110").mitigations)

    print("\n── coverage: the four states ──")
    # A deliberately small, honest posture: Windows-only, Security channel only,
    # no Sysmon — which is exactly the host CYPHRA runs on today.
    collected = ["WinEventLog:Security"]
    rules = {
        "T1110.001": ["rule.brute_force_guessing"],
        "T1059.001": ["rule.powershell_encoded"],
        "T1086": ["rule.legacy_powershell"],       # revoked → T1059.001
        "T1046": ["rule.network_service_scan"],    # needs network telemetry
        "T9999": ["rule.typo"],                    # not a technique at all
    }
    cov = a.coverage(rules, collected=collected, platforms=["Windows"])
    s = cov.summary()
    check("unknown mappings are surfaced, not dropped",
          cov.unknown_mappings == ["T9999"], str(cov.unknown_mappings))
    check("revoked mappings are followed and reported",
          cov.remapped == {"T1086": "T1059.001"}, str(cov.remapped))
    states = {t.technique: t.state for t in cov.per_technique}
    # T1110.001's required sources include WinEventLog:Security:EventCode=4625, which
    # the collected Security channel satisfies — so a rule for it really does detect.
    check("a mapped technique with collected telemetry is covered",
          states.get("T1110.001") == "covered", states.get("T1110.001"))
    # T1059.001 is the case that makes the blind state worth having: there is a rule
    # for it, so every "rules per technique" dashboard counts it as covered, but its
    # sources are WinEventLog:PowerShell and Sysmon — neither collected here. The
    # rule would never fire. Being told this is the whole point of the matrix.
    ps_needs = next(t for t in cov.per_technique if t.technique == "T1059.001").required
    check("a rule whose telemetry is not collected is blind, however good the rule is",
          states.get("T1059.001") == "blind"
          and not any("security" in r.lower() for r in ps_needs),
          f"needs {[r for r in ps_needs][:2]}")
    check("a mapped technique with NO collected telemetry is blind, not covered",
          states.get("T1046") == "blind", states.get("T1046"))
    check("an unmapped technique with telemetry is uncovered",
          any(t.state == "uncovered" for t in cov.per_technique),
          f"{len(cov.uncovered)} uncovered")
    check("an unmapped technique with no telemetry is out of reach",
          len(cov.out_of_reach) > 0, f"{len(cov.out_of_reach)}")
    # The exclusion has to be checked where there is something to exclude. Every one
    # of the 474 live Windows techniques has a named log source, so the Windows
    # denominator is the full in-scope set; the 45 unobservable techniques are all
    # non-Windows and only appear once the scope is widened.
    unscoped = a.coverage(rules, collected=collected).summary()
    check("techniques ATT&CK names no source for are excluded from the percentage",
          unscoped["scorable"] == unscoped["techniques_in_scope"] - unscoped["unobservable"]
          and unscoped["unobservable"] > 0,
          f"{unscoped['unobservable']} unobservable dropped from a denominator of "
          f"{unscoped['techniques_in_scope']}")
    check("a scope in which everything is observable scores against its whole set",
          s["scorable"] == s["techniques_in_scope"] and s["unobservable"] == 0,
          f"Windows: {s['scorable']} scorable of {s['techniques_in_scope']} in scope")
    check("blind techniques do NOT count towards coverage %",
          s["coverage_pct"] == round(100 * s["covered"] / s["scorable"], 2)
          and s["covered"] < s["covered"] + s["blind"],
          f"{s['coverage_pct']}% with {s['blind']} blind excluded")
    parent_tc = next(t for t in cov.per_technique if t.technique == "T1110")
    check("a sub-technique rule gives its parent partial credit",
          "rule.brute_force_guessing" in parent_tc.rules
          and "T1110" not in rules,
          f"T1110 was never mapped directly, yet carries {parent_tc.rules}")
    tc = next(t for t in cov.per_technique if t.technique == "T1046")
    check("a blind technique states what it needs", len(tc.required) > 0 and not tc.satisfied,
          f"needs {tc.required[:2]}")
    check("report names the blind spots explicitly",
          "BLIND" in cov.report() and "look covered and are not" in cov.report())
    check("report warns about the unknown mapping", "UNKNOWN" in cov.report())

    print("\n── coverage moves the way adding a sensor should ──")
    before = a.coverage(rules, collected=collected, platforms=["Windows"]).summary()
    after = a.coverage(
        rules, collected=collected + ["WinEventLog:Sysmon"], platforms=["Windows"]
    ).summary()
    check("adding Sysmon strictly increases satisfied telemetry",
          after["out_of_reach"] < before["out_of_reach"],
          f"out_of_reach {before['out_of_reach']} → {after['out_of_reach']}")
    check("adding a sensor never reduces covered",
          after["covered"] >= before["covered"],
          f"covered {before['covered']} → {after['covered']}")
    empty = a.coverage({}, collected=[], platforms=["Windows"]).summary()
    check("with no rules and no telemetry, coverage is 0% and honest",
          empty["coverage_pct"] == 0.0 and empty["covered"] == 0 and empty["blind"] == 0,
          str(empty["coverage_pct"]))
    check("with no telemetry every scorable technique is out of reach",
          empty["out_of_reach"] == empty["scorable"],
          f"{empty['out_of_reach']} of {empty['scorable']}")
    allplat = a.coverage(rules, collected=collected).summary()
    check("unscoped coverage has a larger denominator than Windows-only",
          allplat["scorable"] > before["scorable"],
          f"all {allplat['scorable']} vs Windows {before['scorable']}")

    print("\n── index integrity ──")
    raw = json.loads(IDX.read_text(encoding="utf-8"))
    check("every technique's parent exists",
          all(t.parent in a.techniques for t in a.techniques.values() if t.parent))
    check("every revoked-by target exists", all(v in a.techniques for v in raw["revoked_by"].values()))
    check("every tactic shortname used by a technique is a real tactic",
          {s for t in a.techniques.values() for s in t.tactics} <= set(a._tactic_by_short),
          str({s for t in a.techniques.values() for s in t.tactics} - set(a._tactic_by_short)))
    check("every technique mitigation id is in the mitigation table",
          all(m in a.mitigations for t in a.techniques.values() for m in t.mitigations))
    check("every data component referenced by a technique exists",
          all(c in a.data_components for t in a.techniques.values() for c in t.data_components))
    check("actor technique references all resolve",
          all(tid in a.techniques for act in a.actors.values() for tid in act.techniques))
    check("descriptions are truncated and the limit is recorded",
          raw["description_truncated_at"] == 400 and
          all(len(t.description) <= 400 for t in a.techniques.values()))
    check("no duplicate technique ids", len(raw["techniques"]) == len(a.techniques))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


sys.exit(main())

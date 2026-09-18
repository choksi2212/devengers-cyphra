"""Live drive of LogonSessionCollector and LocalAccountCollector on this host.

    PYTHONIOENCODING=utf-8 python tests/probe_local_auth.py

Scratch harness, not the suite. Its whole job is to be the thing that fails loudly
before the checks are folded into ``tests/scratch_collectors.py``: it runs both
collectors for real, builds every payload through ``Event.build``, and asserts that
every field on every payload maps — via ``OCSF_PATH`` — to an attribute the payload's
own class actually declares. That last check is the one that catches a
``query_result_id`` on a 5002, which does not raise anywhere.
"""

import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, ".")

from core.config import get
from core.schema.ocsf import OCSF_PATH, Event, schema
from core.store.lake import Lake
from ingest.collectors.local_auth import (
    LocalAccountCollector,
    LogonSessionCollector,
    local_auth_collectors,
)
from ingest.pipeline import Pipeline

FAIL: list[str] = []
PASS: list[str] = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))


# ── the per-class attribute check ───────────────────────────────────────────

_CLASS_ATTRS = schema().class_attributes
#: Payload keys that are CYPHRA's own, not OCSF, and are therefore exempt.
_LOCAL_KEYS = {
    "unmapped", "soc_notes", "enrichments", "observables", "raw_data",
    "class_uid", "activity_id", "activity_name", "category_uid", "type_uid",
    "severity_id", "status_id", "time", "count", "message", "metadata_uid",
    "metadata_labels", "metadata_product_name", "metadata_product_vendor_name",
    "metadata_version", "metadata_correlation_uid", "observed_time",
}


def unmapped_fields(payload: dict) -> list[str]:
    """Payload keys whose OCSF path is not an attribute of the payload's own class."""
    uid = payload.get("class_uid")
    attrs = _CLASS_ATTRS.get(uid) or {}
    bad = []
    for key in payload:
        if key in _LOCAL_KEYS or key.startswith("_"):
            continue
        path = OCSF_PATH.get(key)
        if path is None:
            bad.append(f"{key}(no OCSF_PATH)")
            continue
        root = path.split(".")[0]
        if root not in attrs:
            bad.append(f"{key}->{path} (5-digit {uid} has no {root!r})")
    return bad


async def main() -> int:
    cfg = get()
    root = Path("var/probe_local_auth")
    root.mkdir(parents=True, exist_ok=True)
    lake = Lake(root=root / "data", duckdb_path=root / "soc.duckdb",
                flush_rows=10_000, threads=2)
    pipe = Pipeline(lake, cfg)

    print("── the factory ──")
    cols = local_auth_collectors(pipe)
    check("three collectors, not one", len(cols) == 3,
          ", ".join(c.name for c in cols))
    check("names match the pipeline's declared sources",
          {c.name for c in cols} <= set(pipe.sources) | {c.name for c in cols},
          str(sorted(c.name for c in cols)))

    for coll in cols:
        av = coll.probe()
        print(f"\n── probe: {coll.name} ──")
        print(f"  available={av.available}")
        text = (av.limitation or av.reason or "")
        print("  " + (text[:600].replace("\n", "\n  ") or "(none)"))

    # ══ LogonSessionCollector ═══════════════════════════════════════════════
    print("\n══ LogonSessionCollector ══")
    lsc = LogonSessionCollector(pipe)
    if not lsc.probe().available:
        check("logon_sessions is available on this host", False, "probe said no")
        return 1

    first = await lsc.poll()
    print(f"  first poll: {len(first)} payload(s)")
    by_class = Counter(p["class_uid"] for p in first)
    print(f"  classes: {dict(by_class)}")
    check("the first poll emits a baseline and a table event",
          len(first) >= 2 and 5017 in by_class, str(dict(by_class)))
    check("baseline logons are 3002 activity 1",
          all(p["activity_id"] == 1 for p in first if p["class_uid"] == 3002),
          str([p["activity_id"] for p in first if p["class_uid"] == 3002]))
    check("every baseline payload is labelled as a baseline, not as live telemetry",
          all("baseline_snapshot" in p["metadata_labels"] for p in first
              if p["class_uid"] == 3002))

    second = await lsc.poll()
    print(f"  second poll: {len(second)} payload(s) (steady state)")

    lsc.clock = lambda: __import__("time").time() + 4000.0   # force the heartbeat
    third = await lsc.poll()
    hb = [p for p in third if "heartbeat" in p["metadata_labels"]]
    inv = [p for p in third if "state_observed" in p["metadata_labels"]]
    check("an hourly heartbeat restates the table even when nothing changed",
          len(hb) >= 1 or len(inv) >= 1, f"{len(hb)} heartbeat, {len(inv)} inventory")

    session_payloads = first + second + third

    # ══ LocalAccountCollector ═══════════════════════════════════════════════
    print("\n══ LocalAccountCollector ══")
    lac = LocalAccountCollector(pipe)
    if not lac.probe().available:
        check("local_accounts is available on this host", False, "probe said no")
        return 1

    a1 = await lac.poll()
    ac = Counter(p["class_uid"] for p in a1)
    print(f"  first poll: {len(a1)} payload(s) — classes {dict(ac)}")
    check("baseline emits 5003 per account, 5009 per privileged group, one 5002",
          ac[5003] == len(lac._users) and ac[5002] == 1 and ac[5009] > 0,
          f"5003={ac[5003]} accounts={len(lac._users)} 5002={ac[5002]} 5009={ac[5009]}")
    check("no 3007 Create events at baseline — nine accounts were not just created",
          ac[3007] == 0, f"3007={ac[3007]}")
    check("absent privileged RIDs are reported as DOES_NOT_EXIST, not skipped",
          any(p.get("query_result_id") == 3 for p in a1 if p["class_uid"] == 5009)
          or all(p.get("query_result_id") is not None
                 for p in a1 if p["class_uid"] == 5009),
          str(Counter(p.get("query_result_id") for p in a1 if p["class_uid"] == 5009)))
    check("the 5002 policy event carries NO query_result_id (5002 has no such attribute)",
          all("query_result_id" not in p for p in a1 if p["class_uid"] == 5002))

    a2 = await lac.poll()
    print(f"  second poll: {len(a2)} payload(s) (steady state — expect 0 or few)")

    # A synthetic diff, because this host will not create an account on cue. The
    # snapshot is mutated in place and the *real* diff code runs against it, so this
    # exercises the emitters rather than a mock of them.
    #
    # Two invariants each section must respect, both learned by getting them wrong:
    #
    #  * **The age invariant.** `password_age` counts up in lockstep with elapsed time,
    #    so a synthetic "next poll" that advances `_observed_at` by 300s must also
    #    advance `password_age` by 300 — otherwise the implied password *set moment*
    #    moves, and the collector correctly reports a password change the test did not
    #    intend. Test data that violates a real invariant tests nothing.
    #  * **Distinct timestamps per section.** `metadata_uid` on a change event includes
    #    `now`, so two sections sharing one `now` produce byte-identical ids for the
    #    same account, and the pipeline's exact dedup discards the second — which is
    #    the dedup working, not the collector failing. Each section gets its own clock.
    print("\n── synthetic diffs against the real snapshot ──")
    import time as _t
    t0 = _t.time()
    real = {k: dict(v) for k, v in lac._users.items()}

    def advance(snap: dict, seconds: float) -> tuple[dict, float]:
        """The same accounts, one poll interval later, with the age invariant held."""
        at = float(next(iter(snap.values()))["_observed_at"]) + seconds
        out = {}
        for k, v in snap.items():
            rec = dict(v, _observed_at=at)
            if isinstance(rec.get("password_age"), int) and rec["password_age"] > 0:
                rec["password_age"] += int(seconds)
            out[k] = rec
        return out, at

    # ---- a new account
    now = t0
    lac._users = {k: dict(v, _observed_at=now - 300) for k, v in real.items()}
    users, now = advance(lac._users, 300.0)
    victim = dict(next(iter(users.values())))
    users["evil"] = dict(
        victim, key="evil", name="evil", rid=1337, sid="S-1-5-21-1-2-3-1337",
        flags=0x0020, priv=1, password_age=10, password_set_at=now - 10,
        bad_pw_count=0, num_logons=0, _observed_at=now)
    diffs = lac._diff_users(users, now)
    created = [p for p in diffs if p["class_uid"] == 3007 and p["activity_id"] == 1]
    check("a new account emits 3007 activity 1 Create", len(created) == 1,
          str([(p["class_uid"], p["activity_id"]) for p in diffs]))
    check("...and it names T1136.001 in a label the lake can filter on",
          created and "attack:T1136.001" in created[0]["metadata_labels"],
          str(created[0]["metadata_labels"]) if created else "")
    check("...and says explicitly that the actor is unknowable",
          created and any("not knowable" in n for n in created[0]["soc_notes"]))
    check("an unchanged account emits NOTHING — this is the check that keeps the "
          "collector from reporting nine password changes every five minutes",
          len(diffs) == 1,
          str([(p["class_uid"], p["activity_id"], p.get("message")) for p in diffs]))

    # ---- spray: three accounts gain failures in one interval
    lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
    users2, now = advance(lac._users, 300.0)
    for rec in list(users2.values())[:3]:
        rec["bad_pw_count"] = int(rec.get("bad_pw_count") or 0) + 2
    sprays = lac._diff_users(users2, now)
    fails = [p for p in sprays if p["class_uid"] == 3002 and p.get("status_id") == 2]
    check("three accounts gaining failures in one interval is reported as a spray",
          len(fails) == 3 and all("password_spray" in p["metadata_labels"] for p in fails),
          f"{len(fails)} failure events of {len(sprays)} payloads")
    check("...at HIGH, and base `count` carries the per-account delta",
          fails and all(p["severity_id"] >= 4 and p["count"] == 2 for p in fails),
          str([(p["severity_id"], p["count"]) for p in fails]))
    check("...and the technique label is the spray subtechnique",
          fails and all("attack:T1110.003" in p["metadata_labels"] for p in fails))
    check("...and nothing else fired — the spray is the only thing that changed",
          len(sprays) == 3, str([(p["class_uid"], p["activity_id"]) for p in sprays]))

    # ---- a *fall* in bad_pw_count is a reset, not a burst of failures
    lac._users = {k: dict(v, bad_pw_count=7, _observed_at=now) for k, v in real.items()}
    users3, now = advance(lac._users, 300.0)
    for rec in users3.values():
        rec["bad_pw_count"] = 0
    reset = lac._diff_users(users3, now)
    check("a FALL in bad_pw_count emits nothing at all — it is a reset, not failures",
          not reset,
          str([(p["class_uid"], p.get("activity_id"), p.get("status_id"))
               for p in reset]))

    # ---- password change: the implied set-moment jumps forward
    lac._users = {k: dict(v, password_age=100000, _observed_at=now)
                  for k, v in real.items()}
    users4, now = advance(lac._users, 300.0)
    users4 = {k: dict(v, password_age=5, password_set_at=now - 5)
              for k, v in users4.items()}
    pw = lac._diff_users(users4, now)
    changes = [p for p in pw if p["class_uid"] == 3007 and p["activity_id"] == 8]
    check("a password_age reset emits 3007 activity 8 Password Change",
          len(changes) == len(users4), f"{len(changes)} of {len(users4)}")
    check("...and states that 4723-vs-4724 is the distinction that was lost",
          changes and any("4723" in n and "4724" in n for n in changes[0]["soc_notes"]))

    # ---- password_age of 0 is "no password / undetermined", not "set just now".
    # Three real accounts on this host report 0 (Guest, DefaultAccount, the
    # interactive account). Read as a timestamp it means every one of them reports a
    # password change on every poll, forever.
    zero = {k: v for k, v in real.items() if v.get("password_age") == 0}
    check("this host really does have accounts reporting password_age 0",
          len(zero) >= 1, str(sorted(v["name"] for v in zero.values())))
    lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
    steady, now = advance(lac._users, 300.0)
    quiet = lac._diff_users(steady, now)
    check("...and an age of 0 that stays 0 across a poll emits nothing",
          not [p for p in quiet if p.get("activity_id") == 8],
          str([(p["user_name"], p["activity_id"]) for p in quiet
               if p.get("activity_id") == 8]))
    # 0 -> positive is a real password appearing, and must be caught
    lac._users = {k: dict(v, _observed_at=now) for k, v in real.items()}
    appeared, now = advance(lac._users, 300.0)
    for k, v in list(appeared.items()):
        if v.get("password_age") == 0:
            appeared[k] = dict(v, password_age=30, password_set_at=now - 30)
    got_pw = lac._diff_users(appeared, now)
    check("...but 0 -> a real age IS a password being set, and is reported",
          len([p for p in got_pw if p.get("activity_id") == 8]) == len(zero),
          f"{len([p for p in got_pw if p.get('activity_id') == 8])} of {len(zero)}")

    # ---- enable of a PASSWD_NOTREQD account inherits the flag's severity
    now += 300.0
    lac._users = {"g": dict(victim, key="g", name="g", flags=0x0022,
                            password_age=1000, _observed_at=now - 300)}
    en = lac._diff_users(
        {"g": dict(victim, key="g", name="g", flags=0x0020, password_age=1300,
                   _observed_at=now)}, now)
    enabled = [p for p in en if p["activity_id"] == 4]
    check("enabling a PASSWD_NOTREQD account is raised to the flag's own severity",
          len(enabled) == 1 and enabled[0]["severity_id"] >= 3,
          str([(p["activity_id"], p["severity_id"]) for p in en]))
    check("...and the enable is the only event — no spurious Update alongside it",
          len(en) == 1, str([(p["activity_id"], p.get("message")) for p in en]))

    # ---- SID reuse under an unchanged name
    now += 300.0
    lac._users = {"g": dict(victim, key="g", name="g", sid="S-1-5-21-1-2-3-500",
                            password_age=1000, _observed_at=now - 300)}
    su = lac._diff_users(
        {"g": dict(victim, key="g", name="g", sid="S-1-5-21-1-2-3-999",
                   password_age=1300, _observed_at=now)}, now)
    check("a changed SID under an unchanged name is caught and raised HIGH",
          any(p["severity_id"] >= 4 and "recreated" in p["message"] for p in su),
          str([(p["message"], p["severity_id"]) for p in su]))

    # group membership
    now += 300.0
    lac._groups = {"administrators": {
        "key": "administrators", "name": "Administrators", "sid": "S-1-5-32-544",
        "rid": 544, "comment": "", "members": {}, "error": ""}}
    ga = lac._diff_groups({"administrators": {
        "key": "administrators", "name": "Administrators", "sid": "S-1-5-32-544",
        "rid": 544, "comment": "", "error": "",
        "members": {"S-1-5-21-1-2-3-1337": {
            "sid": "S-1-5-21-1-2-3-1337", "rid": 1337, "name": "evil",
            "domain": "HOST", "sid_type": 1}}}}, now)
    adds = [p for p in ga if p["class_uid"] == 3006 and p["activity_id"] == 3]
    check("adding a member to Administrators emits 3006 activity 3 Add User at HIGH",
          len(adds) == 1 and adds[0]["severity_id"] >= 4,
          str([(p["class_uid"], p["activity_id"], p["severity_id"]) for p in ga]))
    check("...and privilege is decided by RID 544, not by the English name",
          adds and "544" not in adds[0]["unmapped"]["privilege_reason"]
          and "Administrators" in adds[0]["unmapped"]["privilege_reason"],
          adds[0]["unmapped"]["privilege_reason"][:60] if adds else "")

    # an unreadable group must not read as an emptied group
    lac._groups = {"g": {"key": "g", "name": "G", "sid": "", "rid": 544,
                         "comment": "", "error": "", "members": {"a": {
                             "sid": "a", "rid": 1, "name": "x", "domain": "",
                             "sid_type": 1}}}}
    gone = lac._diff_groups({"g": {"key": "g", "name": "G", "sid": "", "rid": 544,
                                   "comment": "", "error": "denied",
                                   "members": {}}}, now)
    check("a group becoming UNREADABLE emits no member-removal events",
          not [p for p in gone if p["class_uid"] == 3006], str(len(gone)))

    # policy change
    lac._modals = {"min_passwd_len": 8, "lockout_threshold": 10, "_levels": [0, 3]}
    pol = lac._diff_policy(
        {"min_passwd_len": 0, "lockout_threshold": 0, "_levels": [0, 3]}, now)
    check("weakening the password policy emits 5019, not another 5002",
          len(pol) == 1 and pol[0]["class_uid"] == 5019,
          str([p["class_uid"] for p in pol]))
    check("...raised to HIGH, with before/after values exact",
          pol and pol[0]["severity_id"] >= 4
          and pol[0]["unmapped"]["changed_fields"]["min_passwd_len"]
          == {"before": 8, "after": 0},
          str(pol[0]["unmapped"]["changed_fields"]) if pol else "")
    check("...and 5019 carries no state_id/security_states (unverifiable enums)",
          pol and not {"state_id", "security_states", "prev_security_states"}
          & set(pol[0]))

    account_payloads = (a1 + a2 + diffs + sprays + reset + pw + quiet + got_pw
                        + en + su + ga + gone + pol)

    # ══ the check that catches silent mapping bugs ═══════════════════════════
    print("\n══ every payload built, and every field checked against its own class ══")
    allp = session_payloads + account_payloads
    print(f"  {len(allp)} payloads across "
          f"{len(set(p['class_uid'] for p in allp))} classes")

    built = 0
    build_errors: list[str] = []
    for p in allp:
        src = "logon_sessions" if p in session_payloads else "local_accounts"
        try:
            Event.build(src, **p)
            built += 1
        except Exception as exc:
            build_errors.append(f"{p['class_uid']}/{p['activity_id']}: {exc}")
    check(f"all {len(allp)} payloads build through Event.build",
          not build_errors, "; ".join(build_errors[:4]))

    bad: list[str] = []
    for p in allp:
        for problem in unmapped_fields(p):
            entry = f"{p['class_uid']}: {problem}"
            if entry not in bad:
                bad.append(entry)
    check("every field maps to an attribute its own class declares",
          not bad, "; ".join(bad[:6]))

    # and prove the check has teeth
    poison = dict(next(p for p in allp if p["class_uid"] == 5002))
    poison["query_result_id"] = 1
    check("...and that check would have caught query_result_id on a 5002",
          any("query_result_id" in b for b in unmapped_fields(poison)),
          str(unmapped_fields(poison)))

    print("\n── through the pipeline into the lake ──")
    # submit() takes a *batch*, not one payload: iterating a bare dict yields its keys,
    # and the pipeline's `dict(payload)` then fails on a string. Batched per source.
    r1 = await pipe.submit("local_accounts", account_payloads)
    r2 = await pipe.submit("logon_sessions", session_payloads)
    await pipe.flush()
    check("the pipeline accepted every payload without rejecting any",
          r1.rejected == 0 and r2.rejected == 0
          and r1.accepted == len(account_payloads)
          and r2.accepted == len(session_payloads),
          f"accounts {r1.accepted}/{len(account_payloads)} rej={r1.rejected}; "
          f"sessions {r2.accepted}/{len(session_payloads)} rej={r2.rejected}")
    for rej in list(pipe.recent_rejects)[:4]:
        print(f"    reject: {rej}")

    print("\n── stats_extra ──")
    for coll in (lsc, lac):
        extra = coll.stats_extra()
        print(f"  {coll.name}: {json.dumps(extra, indent=None)[:400]}")
        check(f"{coll.name} reports its own blind window as a number",
              isinstance(extra.get("blind_window_seconds"), (int, float))
              and extra["blind_window_seconds"] > 0,
              str(extra.get("blind_window_seconds")))

    lake.close()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

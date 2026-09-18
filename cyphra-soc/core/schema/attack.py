"""MITRE ATT&CK Enterprise — vendored, indexed, and queryable.

The raw STIX bundle is 51 MB / 26,086 objects, of which this platform needs a
few percent. Parsing it costs ~0.35 s and ~600 MB of transient Python objects,
which is acceptable once at build time and wasteful on every process start — so
:func:`build_index` reduces it to a compact JSON index that :class:`Attack`
loads directly. The raw bundle stays out of git; the index is committed, so a
checkout is self-contained and reproducible from a recorded source digest.

Vendored version: **Enterprise ATT&CK v19.2** (2026-08-05).

Three things about v19 that break naive mappings, all handled here:

* **``defense-evasion`` no longer exists.** TA0005 was renamed *Stealth*, and
  the new TA0112 *Defense Impairment* took part of its scope. Rules and public
  Sigma content written against ATT&CK ≤ v18 tag ``defense-evasion``, which
  resolves to nothing in v19. :data:`TACTIC_ALIASES` maps the retired shortnames
  forward, and :meth:`Attack.tactic` reports when it followed an alias rather
  than silently accepting it — a coverage matrix that quietly drops a whole
  tactic is worse than one that errors.
* **149 techniques are revoked and 12 more deprecated but not revoked.** A rule
  tagged ``T1086`` is not a broken rule, it is an old one that means
  ``T1059.001``. :meth:`Attack.resolve` follows the ``revoked-by`` chain — which
  is genuinely a *chain*: three techniques revoke to a technique that is itself
  revoked, so a single hop is not enough. Deprecated-but-not-revoked techniques
  have no successor and are reported as such rather than remapped to a guess.
* **``detects`` relationships now originate from ``x-mitre-detection-strategy``**
  objects rather than from data components. Walking the old path finds nothing.
  The index resolves technique → detection strategy → analytic →
  ``x_mitre_log_source_references`` to recover the concrete log sources a
  technique is observable in, e.g. ``WinEventLog:Security`` channel
  ``EventCode=4769``.

That last point is what makes the coverage matrix honest. Coverage is not "how
many techniques do I have a rule for" — a rule fed by telemetry nobody collects
detects nothing while counting as coverage. :meth:`Attack.coverage` therefore
crosses *rules mapped* with *log sources actually collected* and reports four
states, of which :attr:`Coverage.blind` is the one worth looking at first.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: Shortnames retired before v19.2, mapped to their current equivalent. The
#: mapping is deliberately lossy in one direction: TA0005 "Defense Evasion" was
#: split into `stealth` and `defense-impairment`, and there is no way to know
#: from a bare `defense-evasion` tag which half was meant, so it resolves to
#: `stealth` (the one that kept TA0005) and the caller is told an alias was used.
TACTIC_ALIASES: dict[str, str] = {
    "defense-evasion": "stealth",
}

INDEX_VERSION = 1
_MITRE = "mitre-attack"


class AttackError(RuntimeError):
    """An ATT&CK lookup or index failure."""


class UnknownTechnique(AttackError):
    """A technique id that is not in the vendored bundle at all."""


# ── value types ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LogSource:
    """A concrete place a technique is observable, as ATT&CK names it.

    ``name`` is a product-shaped channel identifier (``WinEventLog:Security``,
    ``auditd:SYSCALL``, ``m365:unified``) and ``channel`` narrows it
    (``EventCode=4769``, ``syscall=connect``). Both come verbatim from ATT&CK, so
    matching them against what CYPHRA collects requires a declared mapping rather
    than string equality — see :meth:`Attack.coverage`.
    """

    name: str
    channel: str = ""

    def __str__(self) -> str:
        return f"{self.name}:{self.channel}" if self.channel else self.name


@dataclass(frozen=True)
class Tactic:
    id: str  # TA0005
    shortname: str  # stealth
    name: str  # Stealth
    url: str = ""


@dataclass(frozen=True)
class Technique:
    id: str  # T1110 or T1110.001
    name: str
    tactics: tuple[str, ...] = ()  # shortnames
    platforms: tuple[str, ...] = ()
    is_subtechnique: bool = False
    parent: str | None = None
    version: str = ""
    deprecated: bool = False
    revoked: bool = False
    url: str = ""
    description: str = ""
    detection_strategies: tuple[str, ...] = ()
    log_sources: tuple[LogSource, ...] = ()
    data_components: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    software: tuple[str, ...] = ()

    @property
    def base_id(self) -> str:
        """``T1110.001`` → ``T1110``. A technique is its own base."""
        return self.id.split(".", 1)[0]

    @property
    def observable(self) -> bool:
        """Does ATT&CK name any log source for this technique?

        A technique with no named source is not undetectable, but it is not
        detectable from telemetry ATT&CK knows about — usually because detection
        is contextual or the technique is a resource-development activity that
        happens off the victim estate.
        """
        return bool(self.log_sources)

    def __str__(self) -> str:
        return f"{self.id} {self.name}"


@dataclass(frozen=True)
class Actor:
    """An intrusion set, campaign, or piece of software."""

    id: str
    name: str
    kind: str  # group | campaign | malware | tool
    aliases: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()


# ── coverage ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TechniqueCoverage:
    technique: str
    name: str
    tactics: tuple[str, ...]
    state: str  # covered | blind | uncovered | out_of_reach | unobservable
    rules: tuple[str, ...] = ()
    required: tuple[str, ...] = ()  # log sources ATT&CK names
    satisfied: tuple[str, ...] = ()  # of those, the ones being collected


@dataclass
class Coverage:
    """The result of crossing detections against collected telemetry.

    The four states are not degrees of the same thing. ``blind`` is a *worse*
    finding than ``uncovered``: an uncovered technique is a known gap, while a
    blind one looks covered on every dashboard and fires never.
    """

    scope_platforms: tuple[str, ...]
    per_technique: list[TechniqueCoverage] = field(default_factory=list)
    unknown_mappings: list[str] = field(default_factory=list)
    remapped: dict[str, str] = field(default_factory=dict)

    def _by(self, state: str) -> list[TechniqueCoverage]:
        return [t for t in self.per_technique if t.state == state]

    @property
    def covered(self) -> list[TechniqueCoverage]:
        """A rule exists and at least one required log source is collected."""
        return self._by("covered")

    @property
    def blind(self) -> list[TechniqueCoverage]:
        """A rule exists but no required log source is collected."""
        return self._by("blind")

    @property
    def uncovered(self) -> list[TechniqueCoverage]:
        """Telemetry is available but nothing maps to the technique."""
        return self._by("uncovered")

    @property
    def out_of_reach(self) -> list[TechniqueCoverage]:
        """Neither a rule nor the telemetry to write one."""
        return self._by("out_of_reach")

    @property
    def unobservable(self) -> list[TechniqueCoverage]:
        """ATT&CK names no log source at all for this technique."""
        return self._by("unobservable")

    def summary(self) -> dict[str, Any]:
        n = len(self.per_technique)
        scored = n - len(self.unobservable)
        return {
            "platforms": list(self.scope_platforms),
            "techniques_in_scope": n,
            "scorable": scored,
            "covered": len(self.covered),
            "blind": len(self.blind),
            "uncovered": len(self.uncovered),
            "out_of_reach": len(self.out_of_reach),
            "unobservable": len(self.unobservable),
            # Deliberately computed against *scorable*, and deliberately not
            # counting blind techniques as covered.
            "coverage_pct": round(100.0 * len(self.covered) / scored, 2) if scored else 0.0,
            "unknown_mappings": self.unknown_mappings,
            "remapped": self.remapped,
        }

    def report(self, limit: int = 25) -> str:
        s = self.summary()
        lines = [
            "ATT&CK coverage",
            f"  scope            : {', '.join(self.scope_platforms) or 'all platforms'}",
            f"  techniques       : {s['techniques_in_scope']} "
            f"({s['unobservable']} with no ATT&CK-named log source, excluded from %)",
            f"  covered          : {s['covered']}  (rule + telemetry)",
            f"  BLIND            : {s['blind']}  (rule, but no telemetry feeds it)",
            f"  uncovered        : {s['uncovered']}  (telemetry available, no rule)",
            f"  out of reach     : {s['out_of_reach']}  (no rule, no telemetry)",
            f"  coverage         : {s['coverage_pct']}% of scorable techniques",
        ]
        if self.remapped:
            lines.append(
                f"  remapped         : {len(self.remapped)} revoked id(s) followed forward"
            )
        if self.unknown_mappings:
            lines.append(
                f"  UNKNOWN          : {len(self.unknown_mappings)} mapping(s) match no "
                f"technique: {', '.join(self.unknown_mappings[:8])}"
            )
        if self.blind:
            lines.append("")
            lines.append("  Blind spots — these look covered and are not:")
            for t in self.blind[:limit]:
                lines.append(
                    f"    {t.technique:12s} {t.name[:44]:44s} needs {', '.join(t.required[:2])}"
                )
            if len(self.blind) > limit:
                lines.append(f"    … {len(self.blind) - limit} more")
        return "\n".join(lines)


# ── runtime ───────────────────────────────────────────────────────────────────


class Attack:
    """Queryable ATT&CK, loaded from the compact index."""

    def __init__(self, index: Mapping[str, Any]) -> None:
        if index.get("index_version") != INDEX_VERSION:
            raise AttackError(
                f"index_version {index.get('index_version')!r} is not "
                f"{INDEX_VERSION}; rebuild with `python -m core.schema.attack build`"
            )
        self.version: str = index["attack_version"]
        self.modified: str = index["modified"]
        self.built_at: float = index.get("built_at", 0.0)
        self.source_sha256: str = index.get("source_sha256", "")

        self.tactics: dict[str, Tactic] = {}
        self._tactic_by_short: dict[str, Tactic] = {}
        for raw in index["tactics"]:
            t = Tactic(**raw)
            self.tactics[t.id] = t
            self._tactic_by_short[t.shortname] = t

        self.techniques: dict[str, Technique] = {}
        for tid, raw in index["techniques"].items():
            ls = tuple(LogSource(name=n, channel=c) for n, c in raw.pop("log_sources", ()))
            self.techniques[tid] = Technique(
                id=tid,
                log_sources=ls,
                **{
                    k: (tuple(v) if isinstance(v, list) else v)
                    for k, v in raw.items()
                },
            )

        self._revoked_by: dict[str, str] = dict(index.get("revoked_by", {}))
        self.actors: dict[str, Actor] = {
            a["id"]: Actor(
                id=a["id"], name=a["name"], kind=a["kind"],
                aliases=tuple(a.get("aliases", ())),
                techniques=tuple(a.get("techniques", ())),
            )
            for a in index.get("actors", [])
        }
        self.mitigations: dict[str, str] = dict(index.get("mitigations", {}))
        self.data_components: dict[str, dict[str, Any]] = index.get("data_components", {})

        self._children: dict[str, list[str]] = {}
        for t in self.techniques.values():
            if t.parent:
                self._children.setdefault(t.parent, []).append(t.id)
        for kids in self._children.values():
            kids.sort()

    # ── loading ───────────────────────────────────────────────────────────

    @classmethod
    def load(cls, index_path: str | Path) -> "Attack":
        p = Path(index_path)
        if not p.exists():
            raise AttackError(
                f"ATT&CK index not found at {p}. Build it with:\n"
                f"  python -m core.schema.attack build"
            )
        with p.open("r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    # ── techniques ────────────────────────────────────────────────────────

    def technique(self, tid: str) -> Technique:
        """Look up a technique by id, exactly. Raises on an unknown id."""
        key = _norm_tid(tid)
        try:
            return self.techniques[key]
        except KeyError:
            raise UnknownTechnique(
                f"{tid!r} is not a technique in ATT&CK v{self.version}"
            ) from None

    def get(self, tid: str) -> Technique | None:
        return self.techniques.get(_norm_tid(tid))

    def resolve(self, tid: str) -> tuple[Technique, str | None]:
        """Resolve a possibly-revoked id to the technique it means now.

        Returns ``(technique, note)`` where ``note`` is ``None`` for a current
        id and otherwise explains the substitution. The ``revoked-by`` chain is
        followed transitively — three v19 techniques revoke to a technique that
        is itself revoked, so stopping after one hop returns a revoked answer —
        with a seen-set so a cyclic chain in a future bundle raises instead of
        hanging.

        A *deprecated* technique is returned as-is with a note: ATT&CK names no
        successor for one, and inventing a mapping would be a guess presented as
        a fact.
        """
        key = _norm_tid(tid)
        original = key
        seen: list[str] = []
        while key in self._revoked_by:
            if key in seen:
                raise AttackError(
                    f"cyclic revoked-by chain in the ATT&CK index: "
                    f"{' → '.join(seen + [key])}"
                )
            seen.append(key)
            key = self._revoked_by[key]

        tech = self.technique(key)
        if seen:
            return tech, (
                f"{original} was revoked; ATT&CK v{self.version} replaces it with "
                f"{tech.id} ({tech.name})"
                + (f" via {' → '.join(seen[1:])}" if len(seen) > 1 else "")
            )
        if tech.deprecated:
            return tech, (
                f"{tech.id} is deprecated in ATT&CK v{self.version} with no "
                f"replacement named; keep or retire the mapping deliberately"
            )
        return tech, None

    def subtechniques(self, tid: str) -> list[Technique]:
        base = _norm_tid(tid).split(".", 1)[0]
        return [self.techniques[c] for c in self._children.get(base, ())]

    def parent_of(self, tid: str) -> Technique | None:
        t = self.technique(tid)
        return self.techniques.get(t.parent) if t.parent else None

    def current_techniques(
        self, platforms: Iterable[str] = (), include_subtechniques: bool = True
    ) -> list[Technique]:
        """Every live technique, optionally scoped to platforms.

        Revoked and deprecated techniques are excluded: they are not gaps, and
        counting them inflates the denominator of every coverage figure.
        """
        want = {p.lower() for p in platforms}
        out = []
        for t in self.techniques.values():
            if t.revoked or t.deprecated:
                continue
            if not include_subtechniques and t.is_subtechnique:
                continue
            if want and not {p.lower() for p in t.platforms} & want:
                continue
            out.append(t)
        out.sort(key=lambda t: _tid_sort_key(t.id))
        return out

    # ── tactics ───────────────────────────────────────────────────────────

    def tactic(self, name: str) -> tuple[Tactic, str | None]:
        """Look up a tactic by id (``TA0005``), shortname, or display name.

        Returns ``(tactic, note)``; ``note`` is set when a retired shortname was
        followed, so a caller can surface that a rule is tagged against an
        ATT&CK version older than the vendored one.
        """
        key = name.strip()
        if key.upper() in self.tactics:
            return self.tactics[key.upper()], None
        short = key.lower().replace(" ", "-").replace("_", "-")
        if short in self._tactic_by_short:
            return self._tactic_by_short[short], None
        if short in TACTIC_ALIASES:
            target = TACTIC_ALIASES[short]
            t = self._tactic_by_short[target]
            return t, (
                f"tactic {name!r} was retired before ATT&CK v{self.version}; "
                f"resolved to {t.id} {t.name!r}. Re-tag the source: the old "
                f"tactic's scope was split, so this mapping may be imprecise"
            )
        raise AttackError(
            f"{name!r} is not a tactic in ATT&CK v{self.version}. Known: "
            + ", ".join(sorted(self._tactic_by_short))
        )

    def techniques_for_tactic(self, name: str, platforms: Iterable[str] = ()) -> list[Technique]:
        tac, _ = self.tactic(name)
        return [
            t
            for t in self.current_techniques(platforms=platforms)
            if tac.shortname in t.tactics
        ]

    # ── actors ────────────────────────────────────────────────────────────

    def actor(self, aid: str) -> Actor | None:
        return self.actors.get(aid.upper())

    def find_actor(self, name: str) -> list[Actor]:
        """Match a group/software by name or alias, case-insensitively."""
        q = name.strip().lower()
        return [
            a
            for a in self.actors.values()
            if a.name.lower() == q or q in {x.lower() for x in a.aliases}
        ]

    def actors_using(self, tid: str, kinds: Iterable[str] = ()) -> list[Actor]:
        t, _ = self.resolve(tid)
        want = set(kinds)
        # A group that uses T1110.001 uses T1110; a mapping to the base
        # technique should therefore surface actors seen at sub-technique level.
        ids = {t.id} | {s.id for s in self.subtechniques(t.id)}
        return sorted(
            (
                a
                for a in self.actors.values()
                if (not want or a.kind in want) and ids & set(a.techniques)
            ),
            key=lambda a: a.name,
        )

    # ── coverage ──────────────────────────────────────────────────────────

    def coverage(
        self,
        rules_by_technique: Mapping[str, Sequence[str]],
        collected: Iterable[str] = (),
        platforms: Iterable[str] = (),
        include_subtechniques: bool = True,
    ) -> Coverage:
        """Cross detections against collected telemetry.

        ``rules_by_technique`` maps a technique id to the rule/model names that
        claim it — revoked ids are followed forward and reported in
        :attr:`Coverage.remapped`, unknown ids in
        :attr:`Coverage.unknown_mappings` rather than silently dropped.

        ``collected`` is the set of log sources CYPHRA actually ingests, in
        ATT&CK's own naming. Matching is prefix-based on the source name: a
        declared ``WinEventLog:Security`` satisfies a requirement for
        ``WinEventLog:Security`` on channel ``EventCode=4769``, because a
        collector that reads a channel reads all of its event ids. It does *not*
        satisfy ``WinEventLog:Sysmon`` — a different channel entirely.
        """
        have = {c.strip().lower() for c in collected if c and c.strip()}
        scope = tuple(platforms)

        mapped: dict[str, list[str]] = {}
        remapped: dict[str, str] = {}
        unknown: list[str] = []
        for raw_tid, rules in rules_by_technique.items():
            try:
                tech, note = self.resolve(raw_tid)
            except UnknownTechnique:
                unknown.append(raw_tid)
                continue
            if note and _norm_tid(raw_tid) != tech.id:
                remapped[_norm_tid(raw_tid)] = tech.id
            mapped.setdefault(tech.id, []).extend(rules)
            # A rule for a sub-technique is evidence for its parent too: if you
            # detect Password Guessing you have partial coverage of Brute Force.
            if tech.parent:
                mapped.setdefault(tech.parent, []).extend(rules)

        cov = Coverage(scope_platforms=scope, remapped=remapped, unknown_mappings=sorted(unknown))
        for t in self.current_techniques(
            platforms=platforms, include_subtechniques=include_subtechniques
        ):
            required = tuple(sorted({str(ls) for ls in t.log_sources}))
            satisfied = tuple(
                r for r in required if _source_satisfied(r, have)
            )
            rules = tuple(sorted(set(mapped.get(t.id, ()))))
            if not required:
                state = "unobservable"
            elif rules and satisfied:
                state = "covered"
            elif rules:
                state = "blind"
            elif satisfied:
                state = "uncovered"
            else:
                state = "out_of_reach"
            cov.per_technique.append(
                TechniqueCoverage(
                    technique=t.id,
                    name=t.name,
                    tactics=t.tactics,
                    state=state,
                    rules=rules,
                    required=required,
                    satisfied=satisfied,
                )
            )
        return cov

    def log_sources(self, platforms: Iterable[str] = ()) -> dict[str, int]:
        """Every ATT&CK-named log source, with how many techniques need it.

        Read top-down this is a collection roadmap: the source at the top buys
        the most technique visibility per collector written.
        """
        counts: dict[str, int] = {}
        for t in self.current_techniques(platforms=platforms):
            for ls in {str(x) for x in t.log_sources}:
                counts[ls] = counts.get(ls, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def stats(self) -> dict[str, Any]:
        live = [t for t in self.techniques.values() if not (t.revoked or t.deprecated)]
        return {
            "attack_version": self.version,
            "modified": self.modified,
            "tactics": len(self.tactics),
            "techniques_total": len(self.techniques),
            "techniques_live": len(live),
            "techniques_base": len([t for t in live if not t.is_subtechnique]),
            "subtechniques": len([t for t in live if t.is_subtechnique]),
            "revoked": len(self._revoked_by),
            "deprecated": len([t for t in self.techniques.values() if t.deprecated]),
            "with_log_sources": len([t for t in live if t.log_sources]),
            "groups": len([a for a in self.actors.values() if a.kind == "group"]),
            "campaigns": len([a for a in self.actors.values() if a.kind == "campaign"]),
            "software": len([a for a in self.actors.values() if a.kind in ("malware", "tool")]),
            "mitigations": len(self.mitigations),
            "data_components": len(self.data_components),
        }


def _norm_tid(tid: str) -> str:
    return tid.strip().upper()


def _tid_sort_key(tid: str) -> tuple[int, int]:
    base, _, sub = tid.partition(".")
    return int(base.lstrip("Tt") or 0), int(sub or 0)


def _source_satisfied(required: str, have: set[str]) -> bool:
    """Is ``required`` (``name:channel``) covered by any collected source?

    A collected source satisfies a requirement when it equals the requirement or
    is a prefix of it at a delimiter boundary — reading a channel means reading
    every event id on it. Substring matching would be wrong in both directions
    (``Security`` would match ``WinEventLog:Security`` *and* a hypothetical
    ``AppSecurity``), so the boundary check is explicit.
    """
    req = required.lower()
    for h in have:
        if req == h or req.startswith(h + ":") or h.startswith(req + ":"):
            return True
    return False


# ── index builder ─────────────────────────────────────────────────────────────


def _external_id(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references", ()):
        if ref.get("source_name") == _MITRE:
            return ref.get("external_id")
    return None


def _external_url(obj: Mapping[str, Any]) -> str:
    for ref in obj.get("external_references", ()):
        if ref.get("source_name") == _MITRE:
            return ref.get("url", "")
    return ""


def build_index(
    bundle_path: str | Path,
    out_path: str | Path,
    keep_description_chars: int = 400,
) -> dict[str, Any]:
    """Reduce the raw STIX bundle to the compact runtime index.

    Descriptions are truncated: the full text is ~6 MB and the runtime uses them
    only to caption a finding. The truncation point is recorded so nobody later
    mistakes a clipped description for the real one.
    """
    bundle_path, out_path = Path(bundle_path), Path(out_path)
    if not bundle_path.exists():
        raise AttackError(
            f"raw ATT&CK bundle not found at {bundle_path}. Fetch it with:\n"
            f"  curl -sSL -o {bundle_path} https://raw.githubusercontent.com/"
            f"mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        )

    digest = hashlib.sha256()
    with bundle_path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)

    with bundle_path.open("r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    objs: list[dict[str, Any]] = bundle["objects"]
    by_stix: dict[str, dict[str, Any]] = {o["id"]: o for o in objs}

    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})

    # tactics, in matrix order where the matrix declares one
    matrix = next((o for o in objs if o["type"] == "x-mitre-matrix"), {})
    order = {ref: i for i, ref in enumerate(matrix.get("tactic_refs", ()))}
    tactics = []
    for o in objs:
        if o["type"] != "x-mitre-tactic" or o.get("x_mitre_deprecated"):
            continue
        tactics.append(
            {
                "id": _external_id(o) or "",
                "shortname": o.get("x_mitre_shortname", ""),
                "name": o.get("name", ""),
                "url": _external_url(o),
            }
        )
    tactics.sort(key=lambda t: order.get(f"x-mitre-tactic--{t['id']}", 999))

    # data components → their own log sources, and their parent data source
    components: dict[str, dict[str, Any]] = {}
    comp_by_stix: dict[str, str] = {}
    for o in objs:
        if o["type"] != "x-mitre-data-component":
            continue
        cid = _external_id(o) or o["id"]
        comp_by_stix[o["id"]] = cid
        src = by_stix.get(o.get("x_mitre_data_source_ref", ""), {})
        components[cid] = {
            "name": o.get("name", ""),
            "data_source": _external_id(src) if src else None,
            "data_source_name": src.get("name", "") if src else "",
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "log_sources": _dedupe_sources(o.get("x_mitre_log_sources", ())),
        }

    # analytics carry the concrete log source references
    analytic_sources: dict[str, list[list[str]]] = {}
    analytic_components: dict[str, list[str]] = {}
    for o in objs:
        if o["type"] != "x-mitre-analytic" or o.get("x_mitre_deprecated"):
            continue
        analytic_sources[o["id"]] = _dedupe_sources(
            o.get("x_mitre_log_source_references", ())
        )
        analytic_components[o["id"]] = sorted(
            {
                comp_by_stix[r["x_mitre_data_component_ref"]]
                for r in o.get("x_mitre_log_source_references", ())
                if r.get("x_mitre_data_component_ref") in comp_by_stix
            }
        )

    # detection strategies aggregate their analytics
    strategies: dict[str, dict[str, Any]] = {}
    for o in objs:
        if o["type"] != "x-mitre-detection-strategy" or o.get("x_mitre_deprecated"):
            continue
        srcs: list[list[str]] = []
        comps: set[str] = set()
        for aref in o.get("x_mitre_analytic_refs", ()):
            srcs.extend(analytic_sources.get(aref, ()))
            comps.update(analytic_components.get(aref, ()))
        strategies[o["id"]] = {
            "id": _external_id(o) or o["id"],
            "log_sources": _dedupe_pairs(srcs),
            "components": sorted(comps),
        }

    # relationship walk
    revoked_by_stix: dict[str, str] = {}
    detects: dict[str, list[str]] = {}  # technique stix -> strategy stix
    mitigates: dict[str, set[str]] = {}
    uses: dict[str, set[str]] = {}  # actor stix -> technique external ids
    for o in objs:
        if o["type"] != "relationship":
            continue
        rt, src, tgt = o["relationship_type"], o["source_ref"], o["target_ref"]
        if rt == "revoked-by" and src.startswith("attack-pattern"):
            revoked_by_stix[src] = tgt
        elif rt == "detects" and tgt.startswith("attack-pattern"):
            detects.setdefault(tgt, []).append(src)
        elif rt == "mitigates" and tgt.startswith("attack-pattern"):
            mid = _external_id(by_stix.get(src, {}))
            if mid:
                mitigates.setdefault(tgt, set()).add(mid)
        elif rt == "uses" and tgt.startswith("attack-pattern"):
            uses.setdefault(src, set()).add(tgt)

    # techniques
    techniques: dict[str, dict[str, Any]] = {}
    stix_to_tid: dict[str, str] = {}
    tech_actors: dict[str, set[str]] = {}
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        tid = _external_id(o)
        if not tid:
            continue
        stix_to_tid[o["id"]] = tid
        srcs: list[list[str]] = []
        comps: set[str] = set()
        strat_ids: list[str] = []
        for sref in detects.get(o["id"], ()):
            st = strategies.get(sref)
            if not st:
                continue
            strat_ids.append(st["id"])
            srcs.extend(st["log_sources"])
            comps.update(st["components"])
        desc = (o.get("description") or "").strip()
        techniques[tid] = {
            "name": o.get("name", ""),
            "tactics": [
                p["phase_name"]
                for p in o.get("kill_chain_phases", ())
                if p.get("kill_chain_name") == _MITRE
            ],
            "platforms": list(o.get("x_mitre_platforms", ())),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".", 1)[0] if "." in tid else None,
            "version": str(o.get("x_mitre_version", "")),
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "revoked": bool(o.get("revoked")),
            "url": _external_url(o),
            "description": desc[:keep_description_chars],
            "detection_strategies": sorted(set(strat_ids)),
            "log_sources": _dedupe_pairs(srcs),
            "data_components": sorted(comps),
            "mitigations": sorted(mitigates.get(o["id"], ())),
            "groups": [],
            "software": [],
        }

    # actors, and the reverse technique → actor lists
    actors: list[dict[str, Any]] = []
    kind_of = {"intrusion-set": "group", "campaign": "campaign", "malware": "malware", "tool": "tool"}
    for o in objs:
        kind = kind_of.get(o["type"])
        if not kind or o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        aid = _external_id(o)
        if not aid:
            continue
        tids = sorted(
            {stix_to_tid[t] for t in uses.get(o["id"], ()) if t in stix_to_tid},
            key=_tid_sort_key,
        )
        actors.append(
            {
                "id": aid,
                "name": o.get("name", ""),
                "kind": kind,
                "aliases": list(o.get("aliases", ()) or o.get("x_mitre_aliases", ())),
                "techniques": tids,
            }
        )
        for tid in tids:
            tech_actors.setdefault(tid, set()).add(aid)

    for tid, aids in tech_actors.items():
        entry = techniques.get(tid)
        if entry is None:
            continue
        entry["groups"] = sorted(a for a in aids if a.startswith("G"))
        entry["software"] = sorted(a for a in aids if a.startswith(("S", "C")))

    mitigation_names = {
        _external_id(o): o.get("name", "")
        for o in objs
        if o["type"] == "course-of-action" and not o.get("x_mitre_deprecated")
        and _external_id(o)
    }

    index = {
        "index_version": INDEX_VERSION,
        "attack_version": str(coll.get("x_mitre_version", "unknown")),
        "modified": str(coll.get("modified", "")),
        "built_at": time.time(),
        "source_file": bundle_path.name,
        "source_sha256": digest.hexdigest(),
        "source_objects": len(objs),
        "description_truncated_at": keep_description_chars,
        "tactics": tactics,
        "techniques": techniques,
        "revoked_by": {
            stix_to_tid[s]: stix_to_tid[t]
            for s, t in revoked_by_stix.items()
            if s in stix_to_tid and t in stix_to_tid
        },
        "actors": actors,
        "mitigations": mitigation_names,
        "data_components": components,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(index, fh, separators=(",", ":"), ensure_ascii=False)
    tmp.replace(out_path)
    return index


def _dedupe_sources(raw: Iterable[Mapping[str, Any]]) -> list[list[str]]:
    return _dedupe_pairs([[r.get("name", ""), r.get("channel", "") or ""] for r in raw])


def _dedupe_pairs(pairs: Iterable[Sequence[str]]) -> list[list[str]]:
    seen: dict[tuple[str, str], None] = {}
    for p in pairs:
        name = (p[0] or "").strip()
        chan = (p[1] if len(p) > 1 else "" or "").strip()
        if name:
            seen.setdefault((name, chan), None)
    return [[n, c] for n, c in sorted(seen)]


# ── CLI ───────────────────────────────────────────────────────────────────────


def _default_paths() -> tuple[Path, Path]:
    here = Path(__file__).resolve().parents[2]
    return here / "vendor" / "attack" / "enterprise-attack.json", here / "vendor" / "attack" / "attack_index.json"


def main(argv: Sequence[str]) -> int:
    raw, idx = _default_paths()
    cmd = argv[0] if argv else "stats"

    if cmd == "build":
        t0 = time.perf_counter()
        index = build_index(raw, idx)
        size = idx.stat().st_size
        print(f"built {idx}")
        print(f"  ATT&CK v{index['attack_version']} ({index['modified'][:10]})")
        print(f"  {index['source_objects']:,} STIX objects → {size/1e6:.1f} MB index "
              f"in {time.perf_counter()-t0:.1f}s "
              f"({raw.stat().st_size/size:.0f}× smaller)")
        print(f"  source sha256 {index['source_sha256'][:16]}…")
        cmd = "stats"

    a = Attack.load(idx)
    if cmd == "stats":
        for k, v in a.stats().items():
            print(f"  {k:22s} {v}")
        print("\n  top log sources by technique count:")
        for name, n in list(a.log_sources().items())[:12]:
            print(f"    {n:4d}  {name}")
    elif cmd == "show":
        for tid in argv[1:]:
            t, note = a.resolve(tid)
            print(f"\n{t.id} — {t.name}")
            if note:
                print(f"  ! {note}")
            print(f"  tactics    : {', '.join(t.tactics)}")
            print(f"  platforms  : {', '.join(t.platforms)}")
            print(f"  log sources: {', '.join(str(s) for s in t.log_sources) or '(none named)'}")
            print(f"  mitigations: {', '.join(t.mitigations) or '-'}")
            print(f"  groups     : {len(t.groups)}, software: {len(t.software)}")
            subs = a.subtechniques(t.id)
            if subs and not t.is_subtechnique:
                print(f"  sub        : {', '.join(s.id for s in subs)}")
    elif cmd == "tactic":
        tac, note = a.tactic(argv[1])
        if note:
            print(f"! {note}")
        ts = a.techniques_for_tactic(tac.shortname)
        print(f"{tac.id} {tac.name} — {len(ts)} live techniques")
        for t in ts[:40]:
            print(f"  {t.id:12s} {t.name}")
    else:
        print(__doc__)
        print("usage: python -m core.schema.attack [build|stats|show T1110 …|tactic stealth]")
        return 2
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))

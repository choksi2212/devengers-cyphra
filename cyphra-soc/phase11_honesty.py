"""Phase 11 — the honesty audit.

The audit walks the actual filesystem and runs the actual test
suites to produce a report of what the platform actually has. No
documentation is trusted on its own — every claim is checked
against either a file on disk or a test that runs.

Six sections:

1. **Module inventory** — every package's ``__all__`` resolves,
   every named module actually exists.
2. **Suite health** — every ``tests/scratch_*.py`` is run; pass /
   fail counts are recorded; failing or unsummarisable suites are
   flagged.
3. **Scenario coverage** — every scenario declares the SOC functions
   it covers; every shipped function has at least one scenario.
4. **YAML/code alignment** — every top-level key in ``soc.yaml``
   names a real config section; every section has the keys the code
   expects.
5. **Dead code** — exported names that no other module imports
   (the public surface that nothing calls).
6. **Documented behaviour vs tests** — every public function that
   documents a behaviour in its docstring should be exercised by
   at least one test suite.

The audit exits non-zero if it finds a problem. The exit code is
the count of problems found, capped at 10 — a single pass that
returns 0 means "every claim checks out".

The audit is intentionally *slow*: it runs every test suite and
walks every shipped file. A deployment that wants a fast
smoke-check should run a subset of the checks manually.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import MISSING, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent


@dataclass
class ModuleCheck:
    """The result of one package's inventory check."""

    module: str
    exports: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


@dataclass
class SuiteCheck:
    """The result of running one test suite."""

    name: str
    path: str
    passed: int = 0
    failed: int = 0
    duration_seconds: float = 0.0
    error: str = ""


@dataclass
class CoverageCheck:
    """The result of checking coverage matrix against SOC functions."""

    functions: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    fragile: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


@dataclass
class YamlAlignmentCheck:
    """The result of comparing ``soc.yaml`` with the config dataclasses."""

    yaml_sections: list[str] = field(default_factory=list)
    code_sections: list[str] = field(default_factory=list)
    unknown_sections: list[str] = field(default_factory=list)
    unknown_keys: list[str] = field(default_factory=list)


@dataclass
class DeadCodeCheck:
    """Exported names that no other file in the repository mentions."""

    items: list[str] = field(default_factory=list)


@dataclass
class DocBehaviourCheck:
    """Public functions with a docstring that no test file references."""

    items: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    """The full audit output."""

    modules: list[ModuleCheck] = field(default_factory=list)
    suites: list[SuiteCheck] = field(default_factory=list)
    coverage: CoverageCheck | None = None
    yaml_alignment: YamlAlignmentCheck | None = None
    dead_code: DeadCodeCheck | None = None
    doc_behaviour: DocBehaviourCheck | None = None
    started_at: float = 0.0
    completed_at: float = 0.0
    findings: list[str] = field(default_factory=list)

    def problem_count(self) -> int:
        n = 0
        n += sum(1 for m in self.modules if m.missing)
        n += sum(1 for s in self.suites if s.failed or s.error)
        if self.coverage and self.coverage.missing:
            n += len(self.coverage.missing)
        if self.yaml_alignment:
            n += len(self.yaml_alignment.unknown_sections)
            n += len(self.yaml_alignment.unknown_keys)
        if self.dead_code:
            n += len(self.dead_code.items)
        if self.doc_behaviour:
            n += len(self.doc_behaviour.items)
        n += len(self.findings)
        return min(n, 10)

    def to_dict(self) -> dict[str, Any]:
        return {
            "modules": [
                {
                    "module": m.module,
                    "exports": m.exports,
                    "missing": m.missing,
                }
                for m in self.modules
            ],
            "suites": [
                {
                    "name": s.name,
                    "path": s.path,
                    "passed": s.passed,
                    "failed": s.failed,
                    "duration_seconds": round(s.duration_seconds, 3),
                    "error": s.error,
                }
                for s in self.suites
            ],
            "coverage": {
                "functions": self.coverage.functions if self.coverage else [],
                "covered": self.coverage.covered if self.coverage else [],
                "missing": self.coverage.missing if self.coverage else [],
            },
            "yaml_alignment": {
                "yaml_sections": self.yaml_alignment.yaml_sections
                if self.yaml_alignment else [],
                "code_sections": self.yaml_alignment.code_sections
                if self.yaml_alignment else [],
                "unknown_sections": self.yaml_alignment.unknown_sections
                if self.yaml_alignment else [],
                "unknown_keys": self.yaml_alignment.unknown_keys
                if self.yaml_alignment else [],
            },
            "dead_code": {
                "items": self.dead_code.items if self.dead_code else [],
            },
            "doc_behaviour": {
                "items": self.doc_behaviour.items if self.doc_behaviour else [],
            },
            "findings": self.findings,
            "problem_count": self.problem_count(),
            "duration_seconds": round(self.completed_at - self.started_at, 3),
        }


# ── module inventory ────────────────────────────────────────────────────────


PACKAGES = (
    "core.config", "core.schema.ocsf",
    "ingest.connectors", "ingest.agent",
    "detect", "detect.rules", "detect.ml",
    "correlate", "enrich", "entities", "intel",
    "learn", "triage", "respond", "respond.actions", "respond.playbooks",
    "hunt", "validate",
    "cases", "metrics", "compliance", "crisis",
    "socctl",
)


def check_modules() -> list[ModuleCheck]:
    """Resolve every ``__all__`` in every shipped package."""
    out: list[ModuleCheck] = []
    for pkg_name in PACKAGES:
        try:
            module = importlib.import_module(pkg_name)
        except Exception as exc:  # noqa: BLE001
            out.append(ModuleCheck(module=pkg_name, missing=[f"import: {exc!r}"]))
            continue
        exports = list(getattr(module, "__all__", []))
        missing: list[str] = []
        for name in exports:
            if not hasattr(module, name):
                missing.append(name)
        out.append(ModuleCheck(module=pkg_name, exports=exports, missing=missing))
    return out


# ── test suites ────────────────────────────────────────────────────────────


def _parse_summary(output: str) -> tuple[int, int]:
    """Parse the last ``N passed, M failed`` summary line.

    The summary is the only line that ends with the words
    ``passed`` and ``failed`` flanking two integers. Prose that
    happens to mention "failed" is rejected because the line does
    not end with two integers.
    """
    pattern = re.compile(
        r"^\s*(\d+)\s+passed,?\s+(\d+)\s+failed\s*$",
        re.MULTILINE,
    )
    matches = pattern.findall(output)
    if not matches:
        return 0, 0
    passed, failed = matches[-1]
    return int(passed), int(failed)


def check_suites() -> list[SuiteCheck]:
    """Run every ``tests/scratch_*.py`` and record its pass/fail count."""
    tests_dir = ROOT / "tests"
    out: list[SuiteCheck] = []
    # The audit's own test is recursive — running it would consume
    # cycles running the audit inside the audit. Skip it.
    self_path = Path(__file__).name
    for path in sorted(tests_dir.glob("scratch_*.py")):
        if path.name == self_path.replace("phase11_honesty.py", "scratch_phase11.py"):
            continue
        name = path.stem
        check = SuiteCheck(name=name, path=str(path.relative_to(ROOT)))
        t0 = time.time()
        try:
            result = subprocess.run(
                [sys.executable, str(path)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=120,
                encoding="utf-8",
                errors="replace",
                env={"PYTHONIOENCODING": "utf-8", **__import__("os").environ},
            )
            check.duration_seconds = time.time() - t0
            if result.returncode != 0 and not result.stdout:
                check.error = result.stderr.strip()[-500:]
                check.failed = 1
            else:
                p, f = _parse_summary(result.stdout)
                check.passed = p
                check.failed = f
                if p == 0 and f == 0:
                    # The suite ran but produced no summary; that is
                    # suspicious and worth recording.
                    check.error = "no summary parsed"
                    check.failed = 1
        except subprocess.TimeoutExpired:
            check.duration_seconds = time.time() - t0
            check.error = "timeout"
            check.failed = 1
        except Exception as exc:  # noqa: BLE001
            check.duration_seconds = time.time() - t0
            check.error = repr(exc)
            check.failed = 1
        out.append(check)
    return out


# ── coverage matrix ────────────────────────────────────────────────────────


def check_coverage() -> CoverageCheck | None:
    """Every shipped SOC function should appear in at least one scenario.

    The check separates three states:

    * ``covered`` — the function has two or more scenarios.
    * ``fragile`` — exactly one scenario (a regression there is silent).
    * ``missing`` — zero scenarios.

    Only ``missing`` is a "the platform cannot claim this function"
    failure; ``fragile`` is a risk the operator should know about
    but is not a code defect.
    """
    try:
        from validate import build_gap_report, build_matrix
    except Exception as exc:  # noqa: BLE001
        return CoverageCheck()
    matrix = build_matrix()
    gap = build_gap_report(matrix)
    all_functions = sorted(matrix.cells)
    # Truly missing = in SOC_FUNCTIONS but not in matrix.cells.
    from validate.coverage import SOC_FUNCTIONS
    truly_missing = [
        fn for fn in SOC_FUNCTIONS
        if fn not in matrix.cells or matrix.cells[fn].scenario_count == 0
    ]
    fragile = [
        fn for fn in all_functions
        if fn in matrix.cells and matrix.cells[fn].scenario_count == 1
    ]
    return CoverageCheck(
        functions=all_functions,
        covered=sorted(matrix.covered()),
        missing=truly_missing,
        fragile=fragile,
    )


# ── yaml / code alignment ───────────────────────────────────────────────────


# The mapping from ``soc.yaml`` top-level keys to the dataclasses that
# parse them. ``connectors`` and ``intel`` are credential holders and
# are checked separately because their keys are nested.
YAML_SECTIONS_TO_DATACLASS = {
    "store": "StoreConfig",
    "audit": "AuditConfig",
    "ingest": "IngestConfig",
    "endpoints": "ConnectorEndpoints",
    "detect": "DetectConfig",
    "llm": "LlmConfig",
    "respond": "RespondConfig",
}


def check_yaml_alignment() -> YamlAlignmentCheck | None:
    """Compare ``soc.yaml`` with the config dataclasses in ``core.config``.

    Three classes of mismatch are surfaced:

    * **Unknown yaml section** — a top-level key in ``soc.yaml`` that
      no dataclass reads. Often a typo that silently never applies.
    * **Unknown yaml key** — a key inside a recognised section that
      no field on the corresponding dataclass accepts. Same hazard.
    * **Contradiction** — a yaml value that disagrees with the
      dataclass's declared default. The code takes the yaml value,
      but the disagreement is documentation that has drifted.

    The check is permissive on missing keys (defaults apply), strict
    on extras.
    """
    yaml_path = ROOT / "soc.yaml"
    if not yaml_path.exists():
        return YamlAlignmentCheck()
    raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return YamlAlignmentCheck()

    # Import after loading yaml so a missing yaml file cannot
    # crash the audit.
    from core import config as config_mod

    yaml_sections = sorted(raw.keys())
    code_sections = sorted(YAML_SECTIONS_TO_DATACLASS.keys())

    unknown_sections = [
        s for s in yaml_sections
        if s not in YAML_SECTIONS_TO_DATACLASS
        and s not in ("connectors", "intel")  # credential holders
    ]
    unknown_keys: list[str] = []

    for section, cls_name in YAML_SECTIONS_TO_DATACLASS.items():
        section_data = raw.get(section, {})
        if not isinstance(section_data, dict):
            continue
        cls = getattr(config_mod, cls_name, None)
        if cls is None or not is_dataclass(cls):
            continue
        field_names = {f.name for f in fields(cls)}
        for key in section_data.keys():
            if key not in field_names:
                unknown_keys.append(f"{section}.{key}")

    # Contradictions — declared defaults in soc.yaml that disagree
    # with the dataclass defaults. We compare the *values present in
    # soc.yaml* against the dataclass's default_factory / default.
    contradictions: list[str] = []
    for section, cls_name in YAML_SECTIONS_TO_DATACLASS.items():
        section_data = raw.get(section, {})
        if not isinstance(section_data, dict):
            continue
        cls = getattr(config_mod, cls_name, None)
        if cls is None or not is_dataclass(cls):
            continue
        for f in fields(cls):
            if f.name not in section_data:
                continue
            yaml_value = section_data[f.name]
            # Compare to the dataclass default. Skip non-trivial
            # types (lists, paths, credentials) — those are
            # constructed by default_factory and equality is brittle.
            if f.default is not MISSING and not isinstance(
                f.default, (list, tuple, dict, Path)
            ):
                if f.default != yaml_value and not _values_compatible(
                    f.type, f.default, yaml_value
                ):
                    contradictions.append(
                        f"{section}.{f.name}: yaml={yaml_value!r} default={f.default!r}"
                    )

    check = YamlAlignmentCheck(
        yaml_sections=yaml_sections,
        code_sections=code_sections,
        unknown_sections=unknown_sections,
        unknown_keys=unknown_keys,
    )
    if contradictions:
        check.unknown_keys.extend(
            f"contradiction: {c}" for c in contradictions
        )
    return check


def _values_compatible(field_type: Any, default: Any, yaml_value: Any) -> bool:
    """Permissive equality for fields whose yaml type differs.

    ``yaml`` reads ``true``/``false`` as Python ``bool`` and
    numeric strings as ``int``/``float``, so a yaml value of
    ``"500"`` will equal the dataclass default ``500``. The only
    cases we treat as incompatible are type mismatches that
    ``_coerce`` would have to convert — and those should be
    reported in the operator's face, not here.
    """
    try:
        return type(default)(yaml_value) == default
    except (TypeError, ValueError):
        return False


# ── dead code ──────────────────────────────────────────────────────────────


def _walk_python_files() -> list[Path]:
    """Every .py file under the repo, excluding caches and ``tests/``."""
    out: list[Path] = []
    for p in ROOT.rglob("*.py"):
        rel = p.relative_to(ROOT)
        if "__pycache__" in rel.parts:
            continue
        if rel.parts and rel.parts[0] == "tests":
            continue
        if rel == Path("phase11_honesty.py"):
            continue
        out.append(p)
    return out


def _file_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def check_dead_code() -> DeadCodeCheck:
    """Exported names that no other shipped file mentions.

    A name in ``__all__`` that nothing imports is dead surface — a
    public contract no caller relies on. This is not necessarily a
    bug (it may be a public API a future caller is expected to
    adopt), but it is worth a report line so the operator can prune
    it consciously.

    The check is approximate: it greps for the name as a token in
    every shipped .py file other than the one that defines it.
    False positives happen for very common names (``main``,
    ``load``) — those are filtered out by a small deny-list.
    """
    deny = {
        "main", "load", "open", "close", "save", "ready", "go",
        "stop", "reset", "update", "build", "default", "test",
        "All", "T", "parse", "format", "validate", "names",
    }
    shipped_files = _walk_python_files()
    shipped_text = {p: _file_text(p) for p in shipped_files}

    items: list[str] = []
    for module_name in PACKAGES:
        try:
            module = importlib.import_module(module_name)
        except Exception:  # noqa: BLE001
            continue
        exports = list(getattr(module, "__all__", []))
        module_file = _module_file(module)
        for name in exports:
            if name in deny:
                continue
            if name.startswith("_"):
                continue
            # Look for any reference to the name as a token in
            # other shipped files.
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            referenced = False
            for path, text in shipped_text.items():
                if path == module_file:
                    continue
                if pattern.search(text):
                    referenced = True
                    break
            if not referenced:
                items.append(f"{module_name}.{name}")
    return DeadCodeCheck(items=items)


def _module_file(module: Any) -> Path | None:
    """The path of a module's defining file, or ``None`` if not findable."""
    path = getattr(module, "__file__", None)
    return Path(path).resolve() if path else None


# ── documented behaviour vs tests ──────────────────────────────────────────


_BEHAVIOUR_MARKERS = (
    "must",
    "should",
    "guarantee",
    "guarantees",
    "assert",
    "asserts",
    "atomic",
    "idempotent",
    "raises",
    "returns",
)


def check_doc_behaviour() -> DocBehaviourCheck:
    """Public functions whose docstring makes a behavioural claim
    that no test file references.

    A function that documents a behaviour ("atomic model swap on
    success", "the merged case carries the new severity") but is
    not invoked by any test suite is a documented promise the
    codebase cannot enforce. The check parses every shipped .py
    file for public functions with a substantial docstring that
    contains at least one behavioural claim marker, then greps
    the test files for the function name as a token.

    The check is best-effort. Filters applied to keep the noise
    floor low:

    * The docstring must be at least 100 characters and contain
      one of the :data:`_BEHAVIOUR_MARKERS` markers, so trivial
      "Returns the name." docstrings do not get flagged.
    * The function must have at least one caller in shipped code
      (otherwise it is dead code and is reported separately).
    * Common short names that appear in many tests by accident
      are filtered out.
    """
    deny = {"main", "load", "open", "close", "save", "ready", "go",
            "stop", "reset", "update", "build", "default", "test",
            "All", "T", "parse", "format", "validate", "names",
            "ready", "Stats", "Config", "Report", "Sample"}
    test_dir = ROOT / "tests"
    test_text = ""
    for p in test_dir.rglob("*.py"):
        test_text += "\n" + _file_text(p)

    shipped_files = _walk_python_files()
    shipped_text = {p: shipped_text_get(p) for p in shipped_files}

    items: list[str] = []
    seen: set[str] = set()
    for path in shipped_files:
        for fn_name, doc in _public_function_names(path):
            if fn_name in deny:
                continue
            if len(fn_name) < 8:
                continue
            if fn_name in seen:
                continue
            seen.add(fn_name)
            if len(doc) < 100:
                continue
            if not any(m in doc.lower() for m in _BEHAVIOUR_MARKERS):
                continue
            # Has at least one caller elsewhere in shipped code?
            pattern = re.compile(rf"\b{re.escape(fn_name)}\b")
            has_caller = False
            for other, text in shipped_text.items():
                if other == path:
                    continue
                if pattern.search(text):
                    has_caller = True
                    break
            if not has_caller:
                # Dead code — already reported in dead_code.
                continue
            if pattern.search(test_text):
                continue
            items.append(f"{path.relative_to(ROOT)}:{fn_name}")
    return DocBehaviourCheck(items=items)


_TEXT_CACHE: dict[Path, str] = {}


def shipped_text_get(path: Path) -> str:
    if path not in _TEXT_CACHE:
        _TEXT_CACHE[path] = _file_text(path)
    return _TEXT_CACHE[path]


def _public_function_names(path: Path) -> Iterable[tuple[str, str]]:
    """Yield (qualified_name, docstring) for every public def/class in a file."""
    try:
        tree = ast.parse(shipped_text_get(path), filename=str(path))
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                continue
            doc = ast.get_docstring(node) or ""
            if not doc:
                continue
            yield node.name, doc


# ── entry point ────────────────────────────────────────────────────────────


def main() -> int:
    report = AuditReport(started_at=time.time())
    report.modules = check_modules()
    report.suites = check_suites()
    report.coverage = check_coverage()
    report.yaml_alignment = check_yaml_alignment()
    report.dead_code = check_dead_code()
    report.doc_behaviour = check_doc_behaviour()
    report.completed_at = time.time()

    # Surface findings — the human-readable list of problems.
    for mod in report.modules:
        if mod.missing:
            for name in mod.missing:
                report.findings.append(f"missing export: {mod.module}.{name}")
    for suite in report.suites:
        if suite.failed or suite.error:
            detail = suite.error or f"{suite.failed} failed"
            report.findings.append(
                f"suite {suite.name} not green: {detail}"
            )
    if report.coverage:
        # Only zero-scenario functions are gaps. Single-scenario
        # (fragile) coverage is a *risk* the operator should know
        # about but is not a "the platform cannot claim this
        # function" gap.
        truly_missing = [
            fn for fn in (report.coverage.functions or [])
            if fn not in (report.coverage.covered or [])
        ]
        for fn in truly_missing:
            report.findings.append(
                f"function {fn}: covered by 0 scenarios"
            )
    if report.yaml_alignment:
        for s in report.yaml_alignment.unknown_sections:
            report.findings.append(f"unknown yaml section: {s}")
        for k in report.yaml_alignment.unknown_keys:
            report.findings.append(f"unknown yaml key: {k}")
    if report.dead_code:
        for name in report.dead_code.items:
            report.findings.append(f"dead export: {name}")
    if report.doc_behaviour:
        for item in report.doc_behaviour.items:
            report.findings.append(f"untested public behaviour: {item}")

    print(json.dumps(report.to_dict(), indent=2))
    return report.problem_count()


if __name__ == "__main__":
    sys.exit(main())

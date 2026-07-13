import ast
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from secaware.cli import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "secaware"


def _prompt_extraction_sources() -> tuple[Path, ...]:
    package_roots = (SOURCE_ROOT / "tsg", SOURCE_ROOT / "extractors")
    sources = {path for root in package_roots for path in root.rglob("*.py") if path.is_file()}
    sources.update(
        {
            SOURCE_ROOT / "pipeline" / "stages" / "prompt_extraction.py",
            SOURCE_ROOT / "schema" / "prompt_extraction.py",
        }
    )
    return tuple(sorted(sources))


_BACKEND_SURFACE_FRAGMENTS = (
    "benchmark",
    "fairness",
    "ranking",
    "winner",
    "select_best",
    "automatic_selection",
    "fallback_backend",
)
_COMMAND_SURFACE_FRAGMENTS = (
    "benchmark",
    "fairness",
    "ranking",
    "winner",
    "select_best",
    "fallback",
)


def _normalized_identifier(value: str) -> str:
    return value.casefold().replace("-", "_")


def _matches_fragment(value: str, fragments: tuple[str, ...]) -> bool:
    normalized = _normalized_identifier(value)
    return any(fragment in normalized for fragment in fragments)


def _static_string(node: ast.AST, values: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return values.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left, values)
        right = _static_string(node.right, values)
        if left is not None and right is not None:
            return left + right
    return None


def _static_assignments(tree: ast.AST) -> dict[str, str]:
    values: dict[str, str] = {}
    assignments = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
    )
    for _ in range(len(assignments) + 1):
        changed = False
        for assignment in assignments:
            if isinstance(assignment, ast.Assign):
                targets = assignment.targets
                value_node = assignment.value
            else:
                targets = (assignment.target,)
                value_node = assignment.value
            if value_node is None:
                continue
            value = _static_string(value_node, values)
            if value is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and values.get(target.id) != value:
                    values[target.id] = value
                    changed = True
        if not changed:
            break
    return values


def _backend_surface_violations(paths: tuple[Path, ...]) -> list[str]:
    violations: list[str] = []
    for path in paths:
        try:
            scanned_path = path.resolve().relative_to(SOURCE_ROOT.resolve())
        except ValueError:
            scanned_path = Path(path.name)
        path_parts = (*scanned_path.parts, scanned_path.stem)
        for part in path_parts:
            if _matches_fragment(part, _BACKEND_SURFACE_FRAGMENTS):
                violations.append(f"path:{path}:{part}")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            identifier: str | None = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Name)):
                identifier = node.name if hasattr(node, "name") else node.id
            elif isinstance(node, ast.Attribute):
                identifier = node.attr
            elif isinstance(node, ast.alias):
                identifier = node.asname or node.name
            if identifier is not None and _matches_fragment(identifier, _BACKEND_SURFACE_FRAGMENTS):
                violations.append(f"identifier:{path}:{identifier}")
    return violations


def _forbidden_prompt_dependency(value: str) -> bool:
    normalized = _normalized_identifier(value)
    compact = normalized.replace(".", "").replace("_", "")
    components = tuple(part for part in normalized.replace("_", ".").split(".") if part)
    return (
        "oracle" in components
        or "outcome" in components
        or "results" in components
        or "generation" in components
        or "generatedcode" in compact
        or "codetsg" in compact
        or "securitylabel" in compact
    )


def _prompt_dependency_violations(paths: tuple[Path, ...]) -> list[str]:
    violations: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        values = _static_assignments(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                candidates = tuple(
                    value for alias in node.names for value in (alias.name, alias.asname or "")
                )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                candidates = (module,) + tuple(
                    value
                    for alias in node.names
                    for value in (f"{module}.{alias.name}", alias.asname or "")
                )
            else:
                candidates = ()
            for candidate in candidates:
                if candidate and _forbidden_prompt_dependency(candidate):
                    violations.append(f"import:{path}:{candidate}")

            if not isinstance(node, ast.Call) or not node.args:
                continue
            dynamic_import = (
                isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            )
            if not dynamic_import:
                continue
            module_name = _static_string(node.args[0], values)
            if module_name is not None and _forbidden_prompt_dependency(module_name):
                violations.append(f"dynamic-import:{path}:{module_name}")
    return violations


def _declared_command_violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = _static_assignments(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _matches_fragment(node.name, _COMMAND_SURFACE_FRAGMENTS):
            violations.append(f"callback:{path}:{node.name}")
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "command"
            ):
                continue
            candidates = list(decorator.args[:1])
            candidates.extend(
                keyword.value for keyword in decorator.keywords if keyword.arg == "name"
            )
            for candidate in candidates:
                name = _static_string(candidate, values)
                if name is not None and _matches_fragment(name, _COMMAND_SURFACE_FRAGMENTS):
                    violations.append(f"command:{path}:{name}")
    return violations


def _runtime_command_violations(application: typer.Typer) -> list[str]:
    violations: list[str] = []
    pending = [application]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        for command in current.registered_commands:
            callback_name = getattr(command.callback, "__name__", "")
            for surface in (command.name or "", callback_name):
                if _matches_fragment(surface, _COMMAND_SURFACE_FRAGMENTS):
                    violations.append(f"runtime-command:{surface}")
        for group in current.registered_groups:
            if _matches_fragment(group.name or "", _COMMAND_SURFACE_FRAGMENTS):
                violations.append(f"runtime-group:{group.name}")
            pending.append(group.typer_instance)
    return violations


def test_m4a_has_no_code_or_outcome_surface_in_prompt_extraction() -> None:
    forbidden = (
        "code_" + "tsg",
        "python_" + "ast_utils",
        "Generated" + "CodeRecord",
        "Oracle" + "Record",
        "security_" + "label",
    )
    sources = _prompt_extraction_sources()

    assert sources
    violations = {
        path.relative_to(PROJECT_ROOT): tuple(token for token in forbidden if token in text)
        for path in sources
        if (text := path.read_text(encoding="utf-8"))
        if any(token in text for token in forbidden)
    }
    assert violations == {}
    assert _prompt_dependency_violations(sources) == []
    assert not (SOURCE_ROOT / "extractors" / ("python_" + "ast_utils.py")).exists()


def test_m4a_contains_no_backend_benchmark_or_selection_surface() -> None:
    python_sources = tuple(sorted(SOURCE_ROOT.rglob("*.py")))
    assert _backend_surface_violations(python_sources) == []
    assert {
        path.relative_to(PROJECT_ROOT): violations
        for path in python_sources
        if (violations := _declared_command_violations(path))
    } == {}
    assert _runtime_command_violations(app) == []

    help_result = CliRunner().invoke(app, ["--help"])
    assert help_result.exit_code == 0, help_result.output
    assert all(
        not _matches_fragment(line, _COMMAND_SURFACE_FRAGMENTS)
        for line in help_result.output.splitlines()
    )


def test_m4a_migration_policy_is_complete_and_explicit() -> None:
    migration = (PROJECT_ROOT / "docs" / "migrations" / "prompt-tsg-v2.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(migration.split()).casefold()

    assert "prompt tsg 2.1" in normalized
    assert "task_id" in migration
    for backend in (
        "llm_facts_v1",
        "llm_direct_graph_v1",
        "deterministic_catalog_v1",
    ):
        assert backend in migration
    assert "default" in normalized and "llm_facts_v1" in normalized
    assert "offline" in normalized and "deterministic_catalog_v1" in normalized
    assert "prompt_extraction_proposals.jsonl" in migration
    assert "prompt_tsg.jsonl" in migration
    assert "proposal provenance" in normalized
    assert "exact backend selection" in normalized
    assert "no per-prompt fallback" in normalized
    assert "not automatically upgraded" in normalized
    assert "base_url" in migration and "model_id" in migration and "api_key_env" in migration
    assert "pre-2.1 outputs" in normalized
    assert "pre-2.1 run" in normalized
    assert "v1 outputs" not in normalized
    assert "v1 run" not in normalized
    for deferred in (
        "gold corpus",
        "fairness score",
        "ranking",
        "backend winner",
        "automatic selection",
        "fallback",
    ):
        assert deferred in normalized
    for regenerated in ("tsg", "discovery", "intervention", "analysis"):
        assert regenerated in normalized


def test_readme_preserves_m4a_extraction_and_describes_the_m4b_boundary() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    normalized = " ".join(readme.split()).casefold()

    assert "extract-prompt-tsg" in readme
    assert "prompt_extractor" in readme
    assert "prompt_extraction_proposals.jsonl" in readme
    assert "prompt_tsg.jsonl" in readme
    assert "causal-learn==0.1.4.7" in normalized
    assert "g-square" in normalized
    assert "fci discovery in m4b" in normalized
    assert "fci discovery is not implemented" not in normalized
    assert "m4b" in normalized


def test_backend_surface_gate_rejects_fragment_in_module_stem(tmp_path: Path) -> None:
    candidate = tmp_path / ("extractor_" + "benchmark.py")
    candidate.write_text("VALUE = 1\n", encoding="utf-8")

    assert _backend_surface_violations((candidate,))


def test_backend_surface_gate_rejects_fragment_in_identifier(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "def run_extractor_" + "benchmark():\n    return None\n",
        encoding="utf-8",
    )

    assert _backend_surface_violations((candidate,))


@pytest.mark.parametrize(
    "source",
    (
        "import secaware.schema." + "oracle as outcome\n",
        "from secaware.schema.results import PairResult\n",
        "from secaware.generation.provider import GeneratedCodeProvider\n",
        (
            "import importlib\n"
            "module_name = 'secaware.schema.' + 'oracle'\n"
            "importlib.import_module(module_name)\n"
        ),
    ),
)
def test_prompt_dependency_gate_rejects_static_forbidden_imports(
    tmp_path: Path,
    source: str,
) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text(source, encoding="utf-8")

    assert _prompt_dependency_violations((candidate,))


def test_declared_command_gate_resolves_static_assignment_and_hidden_command(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.py"
    candidate.write_text(
        "command_name = 'extractor-' + 'benchmark'\n"
        "@app.command(command_name, hidden=True)\n"
        "def execute():\n"
        "    return None\n",
        encoding="utf-8",
    )

    assert _declared_command_violations(candidate)


def test_runtime_command_gate_recurses_and_rejects_hidden_variable_registration() -> None:
    root = typer.Typer()
    child = typer.Typer()
    command_name = "extractor-" + "benchmark"

    def execute() -> None:
        return None

    child.command(command_name, hidden=True)(execute)
    root.add_typer(child, name="nested")

    assert _runtime_command_violations(root)

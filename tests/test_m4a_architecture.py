import ast
from pathlib import Path

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


def _declared_cli_commands(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    commands: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "command"
        ):
            continue
        candidate: object = None
        if node.args and isinstance(node.args[0], ast.Constant):
            candidate = node.args[0].value
        for keyword in node.keywords:
            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                candidate = keyword.value.value
        if isinstance(candidate, str):
            commands.add(candidate)
    return commands


def _public_identifiers(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            identifiers.add(node.name.casefold())
        elif isinstance(node, ast.Name):
            identifiers.add(node.id.casefold())
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr.casefold())
    return identifiers


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
    assert not (SOURCE_ROOT / "extractors" / ("python_" + "ast_utils.py")).exists()


def test_m4a_contains_no_backend_benchmark_or_selection_surface() -> None:
    forbidden_identifiers = {
        "extractor_" + "benchmark",
        "backend_" + "ranking",
        "select_best_" + "backend",
        "fairness_" + "score",
        "backend_" + "winner",
        "automatic_" + "selection",
        "fallback_" + "backend",
        "benchmark_" + "extractors",
    }
    python_sources = tuple(sorted(SOURCE_ROOT.rglob("*.py")))
    identifiers = {
        identifier for path in python_sources for identifier in _public_identifiers(path)
    }
    source_paths = {
        part.casefold() for path in python_sources for part in path.relative_to(SOURCE_ROOT).parts
    }

    assert identifiers.isdisjoint(forbidden_identifiers)
    assert source_paths.isdisjoint(forbidden_identifiers)

    commands = _declared_cli_commands(SOURCE_ROOT / "cli.py")
    forbidden_command_fragments = ("benchmark", "ranking", "winner", "select-best", "fallback")
    assert not {
        command
        for command in commands
        if any(fragment in command.casefold() for fragment in forbidden_command_fragments)
    }

    help_result = CliRunner().invoke(app, ["--help"])
    assert help_result.exit_code == 0, help_result.output
    assert all(
        fragment not in help_result.output.casefold() for fragment in forbidden_command_fragments
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


def test_readme_describes_only_the_current_m4a_pipeline() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    normalized = " ".join(readme.split()).casefold()

    assert "extract-prompt-tsg" in readme
    assert "prompt_extractor" in readme
    assert "prompt_extraction_proposals.jsonl" in readme
    assert "prompt_tsg.jsonl" in readme
    assert "fci" in normalized and "not implemented" in normalized
    assert "m4b" in normalized

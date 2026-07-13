from __future__ import annotations

import ast
from pathlib import Path
import tomllib

from typer.testing import CliRunner

from secaware.cli import app


ROOT = Path(__file__).resolve().parents[1]


def _imports_under(root: Path) -> set[str]:
    imports: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imports.add(module)
                imports.update(f"{module}.{alias.name}" for alias in node.names)
    return imports


def test_causal_package_is_prompt_only() -> None:
    imports = {item.casefold() for item in _imports_under(ROOT / "src" / "secaware" / "causal")}
    forbidden = (
        "generatedcoderecord",
        "canonicalgeneratedcoderecord",
        "python_ast_utils",
        "code_tsg",
        ".intervention",
        ".confirmation",
        ".jci",
    )
    assert not {item for item in imports if any(fragment in item for fragment in forbidden)}


def test_causal_table_builder_cannot_read_generated_code_or_findings() -> None:
    source = (
        (ROOT / "src" / "secaware" / "causal" / "table_builder.py")
        .read_text(encoding="utf-8")
        .casefold()
    )
    assert "generatedcoderecord" not in source
    assert "canonicalgeneratedcoderecord" not in source
    assert "finding_text" not in source
    assert "code_tsg" not in source


def test_minimum_fci_runtime_has_no_java_or_rfci_dependency() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = "\n".join(
        [
            *metadata["project"]["dependencies"],
            *(
                item
                for group in metadata["project"]["optional-dependencies"].values()
                for item in group
            ),
        ]
    ).casefold()
    assert "causal-learn==0.1.4.7" in dependencies
    assert "jpype" not in dependencies
    assert "py-tetrad" not in dependencies
    assert not (ROOT / "src" / "secaware" / "discovery" / "rfci_backend.py").exists()


def test_cli_exposes_fci_discovery_without_heuristic_or_old_two_arm_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    help_text = result.stdout.casefold()
    assert "discover" in help_text
    for retired in (
        "tsg-qcd",
        "intervene",
        "confirm",
        "generate-counterfactual",
        "report",
    ):
        assert retired not in help_text


def test_frozen_hypotheses_are_guarded_before_any_future_stage() -> None:
    source = ast.parse(
        (ROOT / "src" / "secaware" / "causal" / "freeze.py").read_text(encoding="utf-8")
    )
    function = next(
        node
        for node in source.body
        if isinstance(node, ast.FunctionDef) and node.name == "freeze_hypotheses"
    )
    first_statement = function.body[1]
    assert isinstance(first_statement, ast.Expr)
    assert isinstance(first_statement.value, ast.Call)
    first_call = first_statement.value
    assert isinstance(first_call.func, ast.Name)
    assert first_call.func.id == "guard_no_future_confirmation_or_analysis"


def test_m4b_documentation_records_complete_discovery_contract() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").casefold()
    migration = (
        (ROOT / "docs" / "migrations" / "fci-discovery.md").read_text(encoding="utf-8").casefold()
    )
    combined = f"{readme}\n{migration}"
    for required in (
        "causal-learn==0.1.4.7",
        "g-square",
        "one seed",
        "failed replicate",
        "circle",
        "prompt-only",
        "no code tsg",
        "hypotheses_frozen.jsonl",
        "11",
        "run-all",
    ):
        assert required in combined

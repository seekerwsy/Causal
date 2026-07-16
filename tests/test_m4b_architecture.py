from __future__ import annotations

import ast
from importlib.util import resolve_name
from pathlib import Path
import tomllib

from typer.testing import CliRunner

from secaware.cli import app


ROOT = Path(__file__).resolve().parents[1]
_ALLOWED_INTERVENTION_SYMBOLS = {
    "secaware.intervention.arm_catalog",
    "secaware.intervention.arm_catalog.target_feature_from_protocol",
}
_ALLOWED_CONFIRMATION_SCHEMA_SYMBOLS = {
    "secaware.schema.experiments.confirmationprotocolrecord",
}
_ALLOWED_JCI_SCHEMA_SYMBOLS = {
    "secaware.schema.causal.jci_row_id_from_content",
    "secaware.schema.causal.jcibackgroundknowledgerecord",
    "secaware.schema.causal.jcibackgroundknowledgerecord.from_base",
    "secaware.schema.causal.jcicontextspec",
    "secaware.schema.causal.jcicontextspec.from_protocol",
    "secaware.schema.causal.jcistratum",
    "secaware.schema.outcomes.jciobservationrecord",
    "secaware.schema.outcomes.jciobservationrecord.from_content",
}


def _attribute_parts(node: ast.Attribute) -> tuple[str, ...] | None:
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    return (current.id, *reversed(parts))


def _package_for_path(path: Path) -> str | None:
    parts: list[str] = []
    parent = path.parent
    while (parent / "__init__.py").is_file():
        parts.append(parent.name)
        parent = parent.parent
    return ".".join(reversed(parts)) or None


def _import_from_module(path: Path, node: ast.ImportFrom) -> str:
    module = node.module or ""
    if node.level == 0:
        return module
    relative = f"{'.' * node.level}{module}"
    package = _package_for_path(path)
    if package is None:
        return relative
    try:
        return resolve_name(relative, package)
    except ImportError:
        return relative


def _symbols_under(root: Path) -> set[str]:
    symbols: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    symbols.add(alias.name)
                    local_name = alias.asname or alias.name.partition(".")[0]
                    aliases[local_name] = alias.name if alias.asname else local_name
            elif isinstance(node, ast.ImportFrom):
                module = _import_from_module(path, node)
                if module:
                    symbols.add(module)
                for alias in node.names:
                    qualified = f"{module}.{alias.name}" if module else alias.name
                    symbols.add(qualified)
                    aliases[alias.asname or alias.name] = qualified
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            parts = _attribute_parts(node)
            if parts is None or parts[0] not in aliases:
                continue
            symbols.add(".".join((aliases[parts[0]], *parts[1:])))
    return symbols


def _relative_import_candidate(tmp_path: Path, source: str) -> Path:
    package = tmp_path / "secaware"
    causal = package / "causal"
    causal.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (causal / "__init__.py").write_text("", encoding="utf-8")
    (causal / "candidate.py").write_text(source, encoding="utf-8")
    return causal


def _prompt_only_causal_violations(symbols: set[str]) -> set[str]:
    violations: set[str] = set()
    for item in {symbol.casefold() for symbol in symbols}:
        if item.startswith("."):
            violations.add(item)
        if any(
            fragment in item
            for fragment in (
                "generatedcoderecord",
                "canonicalgeneratedcoderecord",
                "python_ast_utils",
                "code_tsg",
            )
        ):
            violations.add(item)
        if ".intervention" in item and item not in _ALLOWED_INTERVENTION_SYMBOLS:
            violations.add(item)
        if item == "secaware.generation" or item.startswith("secaware.generation."):
            violations.add(item)
        if ".confirmation" in item and item not in _ALLOWED_CONFIRMATION_SCHEMA_SYMBOLS:
            violations.add(item)
        if ".jci" in item and item not in _ALLOWED_JCI_SCHEMA_SYMBOLS:
            violations.add(item)
    return violations


def _first_executable_statement(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.stmt:
    body = function.body
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            body = body[1:]
    if not body:
        raise AssertionError("function has no executable statement")
    return body[0]


def test_causal_package_is_prompt_only() -> None:
    symbols = _symbols_under(ROOT / "src" / "secaware" / "causal")

    assert not _prompt_only_causal_violations(symbols)


def test_prompt_only_import_gate_resolves_aliased_attribute_chains(tmp_path: Path) -> None:
    (tmp_path / "candidate.py").write_text(
        "import secaware.schema.records as records\nVALUE = records.GeneratedCodeRecord\n",
        encoding="utf-8",
    )

    assert "secaware.schema.records.GeneratedCodeRecord" in _symbols_under(tmp_path)


def test_prompt_only_import_gate_rejects_nonwhitelisted_intervention(
    tmp_path: Path,
) -> None:
    (tmp_path / "candidate.py").write_text(
        "from secaware.intervention.arm_catalog import (\n"
        "    materialize_arm_protocol,\n"
        "    target_feature_from_protocol,\n"
        ")\n"
        "from secaware.intervention.executors import GraphNativeExecutor\n",
        encoding="utf-8",
    )

    violations = _prompt_only_causal_violations(_symbols_under(tmp_path))

    assert "secaware.intervention.executors" in violations
    assert "secaware.intervention.executors.graphnativeexecutor" in violations
    assert "secaware.intervention.arm_catalog.materialize_arm_protocol" in violations
    assert "secaware.intervention.arm_catalog" not in violations
    assert "secaware.intervention.arm_catalog.target_feature_from_protocol" not in violations


def test_prompt_only_import_gate_resolves_relative_intervention_module(
    tmp_path: Path,
) -> None:
    root = _relative_import_candidate(
        tmp_path,
        "from ..intervention.executors import GraphNativeExecutor as Executor\n",
    )

    violations = _prompt_only_causal_violations(_symbols_under(root))

    assert "secaware.intervention.executors" in violations
    assert "secaware.intervention.executors.graphnativeexecutor" in violations


def test_prompt_only_import_gate_resolves_relative_arm_catalog_symbols(
    tmp_path: Path,
) -> None:
    root = _relative_import_candidate(
        tmp_path,
        "from ..intervention.arm_catalog import (\n"
        "    materialize_arm_protocol as materialize,\n"
        "    target_feature_from_protocol as target_feature,\n"
        ")\n",
    )

    violations = _prompt_only_causal_violations(_symbols_under(root))

    assert "secaware.intervention.arm_catalog.materialize_arm_protocol" in violations
    assert "secaware.intervention.arm_catalog" not in violations
    assert "secaware.intervention.arm_catalog.target_feature_from_protocol" not in violations


def test_prompt_only_import_gate_rejects_relative_generation_implementation(
    tmp_path: Path,
) -> None:
    root = _relative_import_candidate(
        tmp_path,
        "from ..generation.result_importer import import_offline_results as importer\n",
    )

    violations = _prompt_only_causal_violations(_symbols_under(root))

    assert "secaware.generation.result_importer" in violations
    assert "secaware.generation.result_importer.import_offline_results" in violations


def test_prompt_only_import_gate_resolves_empty_relative_module(
    tmp_path: Path,
) -> None:
    root = _relative_import_candidate(tmp_path, "from .. import intervention as layer\n")

    violations = _prompt_only_causal_violations(_symbols_under(root))

    assert "secaware.intervention" in violations


def test_prompt_only_import_gate_fails_closed_on_relative_level_overflow(
    tmp_path: Path,
) -> None:
    root = _relative_import_candidate(
        tmp_path,
        "from ...schema.causal import JCIStratum\n",
    )

    violations = _prompt_only_causal_violations(_symbols_under(root))

    assert "...schema.causal" in violations
    assert "...schema.causal.jcistratum" in violations


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
    dependencies = "\n".join(metadata["project"]["dependencies"]).casefold()
    assert "causal-learn==0.1.4.7" in dependencies
    assert "jpype" not in dependencies
    assert "py-tetrad" not in dependencies


def test_cli_exposes_fci_discovery_without_heuristic_or_old_two_arm_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    registered = {item.name for item in app.registered_commands}
    assert {
        "discover",
        "build-confirmation-variants",
        "randomize-confirmation",
        "generate-confirmation",
    } <= registered
    for retired in (
        "tsg-qcd",
        "intervene",
        "confirm",
        "generate-counterfactual",
        "report",
    ):
        assert retired not in registered


def test_frozen_hypotheses_are_guarded_before_any_future_stage() -> None:
    source = ast.parse(
        (ROOT / "src" / "secaware" / "causal" / "freeze.py").read_text(encoding="utf-8")
    )
    function = next(
        node
        for node in source.body
        if isinstance(node, ast.FunctionDef) and node.name == "freeze_hypotheses"
    )
    first_statement = _first_executable_statement(function)
    assert isinstance(first_statement, ast.Expr)
    assert isinstance(first_statement.value, ast.Call)
    first_call = first_statement.value
    assert isinstance(first_call.func, ast.Name)
    assert first_call.func.id == "guard_no_future_confirmation_or_analysis"


def test_first_executable_statement_does_not_require_a_docstring() -> None:
    function = ast.parse("def candidate():\n    guard()\n").body[0]
    assert isinstance(function, ast.FunctionDef)

    first_statement = _first_executable_statement(function)

    assert isinstance(first_statement, ast.Expr)
    assert isinstance(first_statement.value, ast.Call)


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

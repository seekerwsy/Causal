from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).parents[1]
CAUSAL_FILES = (
    ROOT / "src/secaware/causal/variable_catalog.py",
    ROOT / "src/secaware/causal/table_builder.py",
)


def test_causal_table_layer_has_no_code_mechanism_or_diagnostic_imports() -> None:
    forbidden_modules = {
        "ast",
        "secaware.schema.generation",
        "secaware.schema.records.CanonicalGeneratedCodeRecord",
        "secaware.schema.interventions",
        "secaware.schema.hypotheses",
    }
    forbidden_names = {
        "target_changed",
        "semantic_compliance",
        "arm_role",
        "intervention_id",
        "hypothesis_id",
        "finding",
        "findings",
        "message",
        "shadow",
        "code",
    }
    for path in CAUSAL_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = node.module if isinstance(node, ast.ImportFrom) else None
                for alias in node.names:
                    imported.add(f"{module}.{alias.name}" if module else alias.name)
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert not (forbidden_modules & imported)
        assert not (forbidden_names & attributes)
        assert not ({"target_changed", "semantic_compliance", "arm_role", "shadow"} & names)


def test_variable_catalog_does_not_import_outcomes_or_generate_variables_from_graph_nodes() -> None:
    source = CAUSAL_FILES[0].read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "secaware.schema.oracle" not in imports
    assert "secaware.schema.tsg" in imports  # finite reviewed MotifId vocabulary only
    assert "NodeType" not in source
    assert "model_id" not in source


def test_table_builder_never_reads_raw_prompt_or_graph_shadow() -> None:
    tree = ast.parse(CAUSAL_FILES[1].read_text(encoding="utf-8"))
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}

    assert "prompt" not in attributes
    assert "shadow" not in attributes
    assert "raw_response" not in attributes
    assert "findings" not in attributes

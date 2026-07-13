from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import traceback

import pytest

from secaware.errors import SecAwareError
from secaware.schema.oracle import AnalyzerFindingRecord, OracleRecord, SecurityLabel

from test_causal_table_builder import (
    _analyzers,
    _declarations,
    _graphs,
    _oracle,
    _oracles,
    _prompts,
)


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


def _secaware_traceback_locals(error: BaseException) -> str:
    values: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            values.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(values)


def _surfaces(error: SecAwareError) -> tuple[str, ...]:
    return (
        str(error),
        repr(error),
        json.dumps(error.to_dict(), sort_keys=True),
        "".join(traceback.format_exception(error)),
        _secaware_traceback_locals(error),
    )


def test_public_table_builder_failure_clears_raw_prompt_and_oracle_finding_text() -> None:
    from secaware.causal.table_builder import build_local_tables

    prompt_secret = "PRIVATE-PROMPT-TEXT-2b19"
    finding_secret = "PRIVATE-ORACLE-FINDING-9fd3"
    prompts = list(_prompts())
    prompt_payload = prompts[0].model_dump(mode="python")
    prompt_payload["prompt"] = prompt_secret
    prompts[0] = type(prompts[0]).model_validate(prompt_payload)
    oracles = list(_oracles(tuple(prompts)))
    original = _oracle("prompt-1", "model-a", 7)
    digest = hashlib.sha256(b"private-finding").hexdigest()
    finding = AnalyzerFindingRecord(
        schema_version="1.0",
        analyzer="semgrep",
        rule_id="reviewed.rule",
        cwe="CWE-22",
        severity="high",
        confidence="not_provided",
        line=1,
        column=1,
        end_line=1,
        end_column=2,
        message=finding_secret,
    )
    insecure_payload = original.model_dump(mode="python", round_trip=True)
    insecure_payload.update(
        request_id=f"req_{digest}",
        code_id=f"code_{digest}",
        security_label=SecurityLabel.INSECURE,
        severity="high",
        findings=(finding,),
        analyzers=_analyzers(),
    )
    oracles[0] = OracleRecord.model_validate(insecure_payload)

    with pytest.raises(SecAwareError) as exc_info:
        build_local_tables(
            tuple(prompts),
            _graphs(tuple(prompts)),
            tuple(oracles),
            (*_declarations(), object()),  # type: ignore[arg-type]
            min_independent_tasks=2,
        )

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    for surface in _surfaces(error):
        assert prompt_secret not in surface
        assert finding_secret not in surface

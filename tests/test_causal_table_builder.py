from __future__ import annotations

import hashlib

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.features import FeatureState
from secaware.schema.oracle import (
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph

from test_prompt_tsg_builder import _facts_proposal, _prompt
from secaware.tsg.builder import build_prompt_tsg


def _prompts(indices: tuple[int, ...] = (1, 2)) -> tuple[PromptRecord, ...]:
    return tuple(
        PromptRecord(
            prompt_id=f"prompt-{index}",
            task_id=f"task-{index}",
            split="discover",
            language="python",
            task_family="file_access",
            cwe="CWE-22",
            prompt=_prompt().prompt,
        )
        for index in indices
    )


def _graph_for(prompt: PromptRecord, *, state: FeatureState | None = None) -> PromptTSGRecord:
    baseline = build_prompt_tsg(_facts_proposal(), _prompt())
    graph = record_to_multidigraph(baseline)
    if state is not None:
        target = next(
            data
            for _, data in graph.nodes(data=True)
            if data["attributes"].get("feature_id") == "safety.path_normalization"
        )
        target["attributes"]["feature_state"] = state.value
    return multidigraph_to_record(
        graph,
        prompt_id=prompt.prompt_id,
        task_id=prompt.task_id,
        task_family=prompt.task_family,
        cwe=prompt.cwe,
        extractor_backend=baseline.extractor_backend,
        extractor_policy_sha256=baseline.extractor_policy_sha256,
        proposal_id=baseline.proposal_id,
    )


def _graphs(prompts: tuple[PromptRecord, ...] | None = None) -> tuple[PromptTSGRecord, ...]:
    source = prompts or _prompts()
    return tuple(_graph_for(prompt) for prompt in source)


def _analyzers() -> tuple[AnalyzerProvenanceRecord, ...]:
    return tuple(
        AnalyzerProvenanceRecord(
            schema_version="1.0",
            analyzer=analyzer,
            version="1.168.0" if analyzer == "semgrep" else "1.9.4",
            policy_sha256=("a" if analyzer == "semgrep" else "b") * 64,
        )
        for analyzer in ("semgrep", "bandit")
    )


def _oracle(
    prompt_id: str,
    model_id: str,
    seed_id: int,
    *,
    label: SecurityLabel = SecurityLabel.SECURE,
) -> OracleRecord:
    digest = hashlib.sha256(f"{prompt_id}:{model_id}:{seed_id}".encode()).hexdigest()
    return OracleRecord(
        schema_version="1.1",
        request_id=f"req_{digest}",
        code_id=f"code_{digest}",
        code_sha256="c" * 64,
        prompt_id=prompt_id,
        condition="observed",
        model_id=model_id,
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        parse_ok=label is not SecurityLabel.UNKNOWN,
        functional_ok=label is SecurityLabel.SECURE,
        security_label=label,
        evaluability=(
            OracleEvaluability.UNKNOWN_PARSE_FAILURE
            if label is SecurityLabel.UNKNOWN
            else OracleEvaluability.EVALUABLE
        ),
        severity="none",
        findings=(),
        analyzers=_analyzers(),
    )


def _oracles(prompts: tuple[PromptRecord, ...] | None = None) -> tuple[OracleRecord, ...]:
    source = prompts or _prompts()
    return tuple(
        _oracle(prompt.prompt_id, model_id, 7)
        for prompt in source
        for model_id in ("model-a", "model-b")
    )


def _declarations():
    from secaware.causal.variable_catalog import declaration_by_id

    return tuple(
        declaration_by_id(variable_id)
        for variable_id in (
            "x.safety.path_normalization",
            "y.secure_functional",
            "y.cwe_security",
        )
    )


def _build(
    *,
    prompts: tuple[PromptRecord, ...] | None = None,
    graphs: tuple[PromptTSGRecord, ...] | None = None,
    oracles: tuple[OracleRecord, ...] | None = None,
    min_independent_tasks: int = 2,
):
    from secaware.causal.table_builder import build_local_tables

    selected_prompts = prompts or _prompts()
    return build_local_tables(
        selected_prompts,
        graphs or _graphs(selected_prompts),
        oracles or _oracles(selected_prompts),
        _declarations(),
        min_independent_tasks=min_independent_tasks,
    )


def test_finite_variable_catalog_is_closed_stable_and_outcome_complete() -> None:
    from secaware.causal.variable_catalog import (
        CWE_SECURITY_OUTCOME,
        PRIMARY_OUTCOME,
        PROMPT_CAUSAL_VARIABLES,
        VARIABLE_CATALOG_SHA256,
        VariableDeclaration,
        declaration_by_id,
    )
    from secaware.schema.causal import VariableRole
    from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG

    assert len(VARIABLE_CATALOG_SHA256) == 64
    assert PRIMARY_OUTCOME.states == ("no_success", "success")
    assert CWE_SECURITY_OUTCOME.states == ("secure", "insecure", "unknown")
    assert all(type(item) is VariableDeclaration for item in PROMPT_CAUSAL_VARIABLES)
    assert all(
        item.role in {VariableRole.W, VariableRole.X, VariableRole.Y}
        for item in PROMPT_CAUSAL_VARIABLES
    )
    x_ids = {
        item.variable_id.removeprefix("x.")
        for item in PROMPT_CAUSAL_VARIABLES
        if item.role is VariableRole.X and not item.variable_id.startswith("x.motif.")
    }
    assert x_ids == {item.feature_id for item in PROMPT_FEATURE_CATALOG if item.intervenable}
    assert declaration_by_id("y.secure_functional") is PRIMARY_OUTCOME
    with pytest.raises(KeyError):
        declaration_by_id("x.dynamic.graph_node")


def test_local_tables_are_per_scope_and_model_and_contain_no_model_column() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle

    tables, rows, exclusions = _build()

    assert {(item.cwe, item.model_id) for item in tables} == {
        ("CWE-22", "model-a"),
        ("CWE-22", "model-b"),
    }
    assert all("model" not in {var.variable_id for var in table.variables} for table in tables)
    by_id = {table.table_id: table for table in tables}
    assert all(len(row.values) == len(by_id[row.table_id].variables) for row in rows)
    assert exclusions == ()
    validate_local_table_bundle(tables, rows, exclusions)


def test_feature_and_outcome_codes_are_read_from_live_graph_and_typed_oracle() -> None:
    tables, rows, _ = _build()
    table = next(item for item in tables if item.model_id == "model-a")
    variables = tuple(item.variable_id for item in table.variables)
    values = rows[0].values

    assert values[variables.index("x.safety.path_normalization")] == 1
    assert values[variables.index("y.secure_functional")] == 1
    assert values[variables.index("y.cwe_security")] == 0

    unknown = list(_oracles())
    unknown[0] = _oracle("prompt-1", "model-a", 7, label=SecurityLabel.UNKNOWN)
    changed_tables, changed_rows, _ = _build(oracles=tuple(unknown))
    changed = next(item for item in changed_tables if item.model_id == "model-a")
    changed_variables = tuple(item.variable_id for item in changed.variables)
    changed_row = next(
        item for item in changed_rows if item.prompt_id == "prompt-1" and item.model_id == "model-a"
    )
    assert changed_row.values[changed_variables.index("y.secure_functional")] == 0
    assert changed_row.values[changed_variables.index("y.cwe_security")] == 2
    assert changed.table_sha256 != table.table_sha256


@pytest.mark.parametrize("state", [FeatureState.UNRESOLVED, FeatureState.NOT_APPLICABLE])
def test_pre_outcome_nonvalues_emit_typed_content_addressed_exclusions(state: FeatureState) -> None:
    prompts = _prompts((1, 2, 3))
    graphs = (
        _graph_for(prompts[0], state=state),
        _graph_for(prompts[1]),
        _graph_for(prompts[2]),
    )
    tables, rows, exclusions = _build(prompts=prompts, graphs=graphs)

    assert len(tables) == 2
    assert all(table.row_count == 2 for table in tables)
    assert {item.prompt_id for item in exclusions} == {"prompt-1"}
    assert {item.variable_id for item in exclusions} == {"x.safety.path_normalization"}
    expected = (
        "unresolved_feature" if state is FeatureState.UNRESOLVED else "not_applicable_feature"
    )
    assert {item.reason_code.value for item in exclusions} == {expected}
    assert tuple(item.exclusion_id for item in exclusions) == tuple(
        sorted(item.exclusion_id for item in exclusions)
    )
    assert all(row.prompt_id != "prompt-1" for row in rows)


@pytest.mark.parametrize("mutation", ["duplicate", "omit", "extra", "swap_seed"])
def test_table_builder_rejects_inexact_oracle_coverage(mutation: str) -> None:
    oracles = list(_oracles())
    if mutation == "duplicate":
        oracles.append(oracles[0])
    elif mutation == "omit":
        oracles.pop()
    elif mutation == "extra":
        oracles.append(_oracle("stale-prompt", "model-a", 7))
    else:
        payload = oracles[-1].model_dump(mode="python", round_trip=True)
        payload["seed_id"] = 8
        digest = hashlib.sha256(b"swapped").hexdigest()
        payload["request_id"] = f"req_{digest}"
        payload["code_id"] = f"code_{digest}"
        oracles[-1] = OracleRecord.model_validate(payload)

    with pytest.raises(SecAwareError) as exc_info:
        _build(oracles=tuple(oracles))
    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID


def test_table_builder_rejects_graph_coverage_coordinate_and_task_cluster_violations() -> None:
    prompts = _prompts()
    duplicate_task_payload = prompts[1].model_dump(mode="python")
    duplicate_task_payload["task_id"] = prompts[0].task_id
    duplicate_task = PromptRecord.model_validate(duplicate_task_payload)

    with pytest.raises(SecAwareError):
        _build(prompts=(prompts[0], duplicate_task))
    with pytest.raises(SecAwareError):
        _build(graphs=_graphs()[:-1])
    with pytest.raises(SecAwareError):
        _build(graphs=(*_graphs(), _graphs()[0]))

    graph_payload = _graphs()[0].model_dump(mode="python", round_trip=True)
    graph_payload["task_id"] = "stale-task"
    stale = PromptTSGRecord.model_construct(**graph_payload)
    with pytest.raises(SecAwareError):
        _build(graphs=(stale, _graphs()[1]))


def test_table_builder_enforces_bounded_variables_rows_and_independent_support() -> None:
    from secaware.causal.table_builder import build_local_tables
    from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES

    with pytest.raises(SecAwareError):
        _build(min_independent_tasks=3)
    with pytest.raises(SecAwareError):
        build_local_tables(
            _prompts(),
            _graphs(),
            _oracles(),
            PROMPT_CAUSAL_VARIABLES,
            max_variables=2,
            min_independent_tasks=2,
        )
    with pytest.raises(SecAwareError):
        dense_oracles = tuple(
            _oracle(prompt.prompt_id, model_id, seed_id)
            for prompt in _prompts()
            for model_id in ("model-a", "model-b")
            for seed_id in (7, 8)
        )
        build_local_tables(
            _prompts(),
            _graphs(),
            dense_oracles,
            _declarations(),
            max_rows=3,
            min_independent_tasks=2,
        )


def test_table_and_rows_are_deterministic_under_input_order_and_fail_joint_tampering() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalObservationRecord

    one = _build()
    two = _build(
        prompts=tuple(reversed(_prompts())),
        graphs=tuple(reversed(_graphs())),
        oracles=tuple(reversed(_oracles())),
    )
    assert one == two

    tables, rows, exclusions = one
    payload = rows[0].model_dump(mode="python", round_trip=True)
    payload["table_id"] = next(
        table.table_id for table in tables if table.table_id != rows[0].table_id
    )
    tampered = CausalObservationRecord.model_validate(payload)
    with pytest.raises(SecAwareError):
        validate_local_table_bundle(tables, (tampered, *rows[1:]), exclusions)
    with pytest.raises(SecAwareError):
        validate_local_table_bundle((), (), ())


def test_joint_verifier_rejects_logical_duplicate_and_row_overlapping_exclusions() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalExclusionRecord

    prompts = _prompts((1, 2, 3))
    graphs = (
        _graph_for(prompts[0], state=FeatureState.UNRESOLVED),
        _graph_for(prompts[1]),
        _graph_for(prompts[2]),
    )
    tables, rows, exclusions = _build(prompts=prompts, graphs=graphs)
    first = exclusions[0]
    duplicate_payload = first.model_dump(mode="python", round_trip=True)
    duplicate_payload.pop("exclusion_id")
    duplicate_payload.pop("schema_version")
    duplicate_payload["producer_sha256"] = "d" * 64
    logical_duplicate = CausalExclusionRecord.from_content(**duplicate_payload)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tables,
            rows,
            tuple(sorted((*exclusions, logical_duplicate), key=lambda item: item.exclusion_id)),
        )

    row = rows[0]
    table = next(item for item in tables if item.table_id == row.table_id)
    overlap = CausalExclusionRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=row.model_id,
        task_id=row.task_id,
        prompt_id=row.prompt_id,
        seed_id=row.seed_id,
        variable_id="x.safety.path_normalization",
        reason_code="unresolved_feature",
        producer_sha256="e" * 64,
    )
    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tables,
            rows,
            tuple(sorted((*exclusions, overlap), key=lambda item: item.exclusion_id)),
        )

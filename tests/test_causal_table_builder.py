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
            prompt_role="neutral_baseline",
            counterpart_prompt_id=None,
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


def _source_coordinates(
    prompts: tuple[PromptRecord, ...] | None = None,
    oracles: tuple[OracleRecord, ...] | None = None,
) -> tuple[tuple[str, str, str, str, str, int], ...]:
    selected_prompts = prompts or _prompts()
    selected_oracles = oracles or _oracles(selected_prompts)
    by_prompt = {item.prompt_id: item for item in selected_prompts}
    return tuple(
        sorted(
            (
                f"scope.cwe_{by_prompt[item.prompt_id].cwe.removeprefix('CWE-')}",
                by_prompt[item.prompt_id].cwe,
                item.model_id,
                by_prompt[item.prompt_id].task_id,
                item.prompt_id,
                item.seed_id,
            )
            for item in selected_oracles
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
    validate_local_table_bundle(
        tables,
        rows,
        exclusions,
        source_coordinates=_source_coordinates(),
    )


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
        validate_local_table_bundle(
            tables,
            (tampered, *rows[1:]),
            exclusions,
            source_coordinates=_source_coordinates(),
        )
    with pytest.raises(SecAwareError):
        validate_local_table_bundle((), (), (), source_coordinates=())


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
            source_coordinates=_source_coordinates(prompts),
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
            source_coordinates=_source_coordinates(prompts),
        )


@pytest.mark.parametrize(
    "variable_id",
    ["x.safety.input_validation", "y.secure_functional"],
)
def test_bundle_rejects_unknown_or_non_x_exclusion_variables(
    variable_id: str,
) -> None:
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
    invalid = CausalExclusionRecord.from_content(
        scope_id=first.scope_id,
        cwe=first.cwe,
        model_id=first.model_id,
        task_id=first.task_id,
        prompt_id=first.prompt_id,
        seed_id=first.seed_id,
        variable_id=variable_id,
        reason_code=first.reason_code,
        producer_sha256="f" * 64,
    )
    changed = tuple(sorted((invalid, *exclusions[1:]), key=lambda item: item.exclusion_id))

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tables,
            rows,
            changed,
            source_coordinates=_source_coordinates(prompts),
        )


def test_bundle_rejects_foreign_exclusion_outside_exact_source_commitment() -> None:
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
    foreign = CausalExclusionRecord.from_content(
        scope_id=first.scope_id,
        cwe=first.cwe,
        model_id=first.model_id,
        task_id="foreign-task",
        prompt_id="foreign-prompt",
        seed_id=999,
        variable_id=first.variable_id,
        reason_code=first.reason_code,
        producer_sha256="f" * 64,
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tables,
            rows,
            tuple(sorted((*exclusions, foreign), key=lambda item: item.exclusion_id)),
            source_coordinates=_source_coordinates(prompts),
        )


def _changed_table_and_rows(table, rows):
    from secaware.schema.causal import CausalObservationRecord, CausalTableRecord

    local = [item for item in rows if item.table_id == table.table_id]
    changed_values = list(local[0].values)
    changed_values[0] = 1 - changed_values[0]
    changed_payload = []
    for index, row in enumerate(local):
        values = tuple(changed_values) if index == 0 else row.values
        changed_payload.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=row.task_id,
                    prompt_id=row.prompt_id,
                    model_id=row.model_id,
                    seed_id=row.seed_id,
                    values=values,
                ),
                row.task_id,
                row.prompt_id,
                row.seed_id,
                values,
            )
        )
    changed = CausalTableRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        variables=table.variables,
        row_count=len(changed_payload),
        independent_task_count=len({item[1] for item in changed_payload}),
        observation_payload=changed_payload,
    )
    changed_rows = tuple(
        CausalObservationRecord.from_content(
            table=changed,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=changed.model_id,
            seed_id=seed_id,
            values=values,
        )
        for _row_id, task_id, prompt_id, seed_id, values in changed_payload
    )
    return changed, changed_rows


def _rebuild_table(table, source_rows, *, variables=None, retained_rows=None, values_by_row=None):
    from secaware.schema.causal import CausalObservationRecord, CausalTableRecord

    selected_rows = tuple(
        retained_rows
        if retained_rows is not None
        else (item for item in source_rows if item.table_id == table.table_id)
    )
    selected_variables = tuple(variables if variables is not None else table.variables)
    replacements = values_by_row or {}
    payload = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=item.task_id,
                prompt_id=item.prompt_id,
                model_id=item.model_id,
                seed_id=item.seed_id,
                values=replacements.get(item.row_id, item.values),
            ),
            item.task_id,
            item.prompt_id,
            item.seed_id,
            replacements.get(item.row_id, item.values),
        )
        for item in selected_rows
    )
    rebuilt = CausalTableRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        variables=selected_variables,
        row_count=len(payload),
        independent_task_count=len({item[1] for item in payload}),
        observation_payload=payload,
    )
    rebuilt_rows = tuple(
        CausalObservationRecord.from_content(
            table=rebuilt,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=rebuilt.model_id,
            seed_id=seed_id,
            values=values,
        )
        for _row_id, task_id, prompt_id, seed_id, values in payload
    )
    return rebuilt, rebuilt_rows


def test_bundle_rejects_self_consistent_forged_variable_spec_and_rehashed_tables() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalVariableSpec

    tables, rows, exclusions = _build()
    changed_tables = []
    changed_rows = []
    for table in tables:
        original = next(item for item in table.variables if item.role.value == "x")
        forged = CausalVariableSpec(
            schema_version="1.0",
            variable_id="x.dynamic.forged",
            role=original.role,
            states=original.states,
            source_query_id="prompt.feature_state.dynamic.forged.v1",
            scope_id=original.scope_id,
            temporal_tier=original.temporal_tier,
            adjacency_type=original.adjacency_type,
            producer_sha256="f" * 64,
        )
        variables = tuple(forged if item == original else item for item in table.variables)
        rebuilt, local_rows = _rebuild_table(table, rows, variables=variables)
        changed_tables.append(rebuilt)
        changed_rows.extend(local_rows)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tuple(sorted(changed_tables, key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted(changed_rows, key=lambda item: (item.table_id, item.row_id))),
            exclusions,
            source_coordinates=_source_coordinates(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("states", ("off", "on")),
        ("source_query_id", "prompt.feature_state.forged.v1"),
        ("temporal_tier", 0),
        ("adjacency_type", "prompt_forged"),
        ("producer_sha256", "f" * 64),
        ("scope_id", "scope.forged"),
    ],
)
def test_bundle_rejects_known_catalog_variable_spec_field_forgery(
    field: str,
    value: object,
) -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalVariableSpec

    tables, rows, exclusions = _build()
    changed_tables = []
    changed_rows = []
    for table in tables:
        original = next(item for item in table.variables if item.role.value == "x")
        payload = original.model_dump(mode="python", round_trip=True)
        payload[field] = value
        forged = CausalVariableSpec.model_validate(payload)
        variables = tuple(forged if item == original else item for item in table.variables)
        rebuilt, local_rows = _rebuild_table(table, rows, variables=variables)
        changed_tables.append(rebuilt)
        changed_rows.extend(local_rows)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tuple(sorted(changed_tables, key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted(changed_rows, key=lambda item: (item.table_id, item.row_id))),
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_catalog_variable_outside_table_cwe_scope() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
    from secaware.schema.causal import CausalVariableSpec

    declaration = declaration_by_id("x.safety.sql_parameterization")
    tables, rows, exclusions = _build()
    changed_tables = []
    changed_rows = []
    for table in tables:
        original = next(item for item in table.variables if item.role.value == "x")
        forged = CausalVariableSpec(
            schema_version="1.0",
            variable_id=declaration.variable_id,
            role=declaration.role,
            states=declaration.states,
            source_query_id=declaration.query_id,
            scope_id=table.scope_id,
            temporal_tier=declaration.tier,
            adjacency_type=declaration.adjacency_type,
            producer_sha256=declaration_sha256(declaration),
        )
        variables = tuple(forged if item == original else item for item in table.variables)
        rebuilt, local_rows = _rebuild_table(table, rows, variables=variables)
        changed_tables.append(rebuilt)
        changed_rows.extend(local_rows)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tuple(sorted(changed_tables, key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted(changed_rows, key=lambda item: (item.table_id, item.row_id))),
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_missing_required_security_outcome() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle

    tables, rows, exclusions = _build()
    changed_tables = []
    changed_rows = []
    for table in tables:
        removed_index = next(
            index
            for index, item in enumerate(table.variables)
            if item.variable_id == "y.cwe_security"
        )
        variables = tuple(
            item for index, item in enumerate(table.variables) if index != removed_index
        )
        local = tuple(item for item in rows if item.table_id == table.table_id)
        values_by_row = {
            item.row_id: tuple(
                value for index, value in enumerate(item.values) if index != removed_index
            )
            for item in local
        }
        rebuilt, rebuilt_rows = _rebuild_table(
            table,
            rows,
            variables=variables,
            values_by_row=values_by_row,
        )
        changed_tables.append(rebuilt)
        changed_rows.extend(rebuilt_rows)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tuple(sorted(changed_tables, key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted(changed_rows, key=lambda item: (item.table_id, item.row_id))),
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_different_legal_variable_subsets_across_models() -> None:
    from secaware.causal.table_builder import build_local_tables, validate_local_table_bundle
    from secaware.causal.variable_catalog import declaration_by_id

    declarations = (*_declarations(), declaration_by_id("x.task.file_read"))
    tables, rows, exclusions = build_local_tables(
        _prompts(),
        _graphs(),
        _oracles(),
        declarations,
        min_independent_tasks=2,
    )
    target = next(item for item in tables if item.model_id == "model-b")
    removed_index = next(
        index
        for index, item in enumerate(target.variables)
        if item.variable_id == "x.task.file_read"
    )
    variables = tuple(item for index, item in enumerate(target.variables) if index != removed_index)
    local = tuple(item for item in rows if item.table_id == target.table_id)
    values_by_row = {
        item.row_id: tuple(
            value for index, value in enumerate(item.values) if index != removed_index
        )
        for item in local
    }
    replacement, replacement_rows = _rebuild_table(
        target,
        rows,
        variables=variables,
        values_by_row=values_by_row,
    )
    changed_tables = tuple(
        sorted(
            (replacement if item == target else item for item in tables),
            key=lambda item: (item.scope_id, item.model_id),
        )
    )
    changed_rows = tuple(
        sorted(
            (
                *(item for item in rows if item.table_id != target.table_id),
                *replacement_rows,
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            changed_tables,
            changed_rows,
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_rehashed_pre_outcome_value_drift_across_model_seed() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle

    tables, rows, exclusions = _build()
    target = next(item for item in tables if item.model_id == "model-b")
    target_row = next(item for item in rows if item.table_id == target.table_id)
    x_index = next(
        index for index, variable in enumerate(target.variables) if variable.role.value == "x"
    )
    changed_values = list(target_row.values)
    changed_values[x_index] = 1 - changed_values[x_index]
    replacement, replacement_rows = _rebuild_table(
        target,
        rows,
        values_by_row={target_row.row_id: tuple(changed_values)},
    )
    changed_tables = tuple(
        sorted(
            (replacement if item == target else item for item in tables),
            key=lambda item: (item.scope_id, item.model_id),
        )
    )
    changed_rows = tuple(
        sorted(
            (
                *(item for item in rows if item.table_id != target.table_id),
                *replacement_rows,
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            changed_tables,
            changed_rows,
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_partial_row_and_exclusion_status_for_one_prompt() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalExclusionRecord

    prompts = _prompts((1, 2, 3))
    tables, rows, exclusions = _build(prompts=prompts)
    target = next(item for item in tables if item.model_id == "model-b")
    removed = next(
        item for item in rows if item.table_id == target.table_id and item.prompt_id == "prompt-1"
    )
    retained = tuple(item for item in rows if item.table_id == target.table_id and item != removed)
    replacement, replacement_rows = _rebuild_table(target, rows, retained_rows=retained)
    x_variable = next(item for item in target.variables if item.role.value == "x")
    exclusion = CausalExclusionRecord.from_content(
        scope_id=target.scope_id,
        cwe=target.cwe,
        model_id=removed.model_id,
        task_id=removed.task_id,
        prompt_id=removed.prompt_id,
        seed_id=removed.seed_id,
        variable_id=x_variable.variable_id,
        reason_code="unresolved_feature",
        producer_sha256="a" * 64,
    )
    changed_tables = tuple(
        sorted(
            (replacement if item == target else item for item in tables),
            key=lambda item: (item.scope_id, item.model_id),
        )
    )
    changed_rows = tuple(
        sorted(
            (
                *(item for item in rows if item.table_id != target.table_id),
                *replacement_rows,
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            changed_tables,
            changed_rows,
            (exclusion,),
            source_coordinates=_source_coordinates(prompts),
        )


@pytest.mark.parametrize("drift", ["variable", "reason", "producer"])
def test_bundle_rejects_exclusion_profile_drift_across_model_seed(drift: str) -> None:
    from secaware.causal.table_builder import build_local_tables, validate_local_table_bundle
    from secaware.causal.variable_catalog import declaration_by_id
    from secaware.schema.causal import CausalExclusionRecord

    prompts = _prompts((1, 2, 3))
    graphs = (
        _graph_for(prompts[0], state=FeatureState.UNRESOLVED),
        _graph_for(prompts[1]),
        _graph_for(prompts[2]),
    )
    declarations = (*_declarations(), declaration_by_id("x.task.file_read"))
    tables, rows, exclusions = build_local_tables(
        prompts,
        graphs,
        _oracles(prompts),
        declarations,
        min_independent_tasks=2,
    )
    target = next(item for item in exclusions if item.model_id == "model-b")
    payload = target.model_dump(mode="python", round_trip=True)
    payload.pop("schema_version")
    payload.pop("exclusion_id")
    if drift == "variable":
        payload["variable_id"] = "x.task.file_read"
    elif drift == "reason":
        payload["reason_code"] = "not_applicable_feature"
    else:
        payload["producer_sha256"] = "f" * 64
    changed = CausalExclusionRecord.from_content(**payload)
    changed_exclusions = tuple(
        sorted(
            (changed if item == target else item for item in exclusions),
            key=lambda item: item.exclusion_id,
        )
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tables,
            rows,
            changed_exclusions,
            source_coordinates=_source_coordinates(prompts),
        )


def test_bundle_rejects_multiple_tables_for_one_scope_model_coordinate() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle

    tables, rows, exclusions = _build()
    changed, changed_rows = _changed_table_and_rows(tables[0], rows)

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            tuple(sorted((*tables, changed), key=lambda item: (item.scope_id, item.model_id))),
            tuple(sorted((*rows, *changed_rows), key=lambda item: (item.table_id, item.row_id))),
            exclusions,
            source_coordinates=_source_coordinates(),
        )


def test_bundle_rejects_inconsistent_source_coordinate_matrices_across_models() -> None:
    from secaware.causal.table_builder import validate_local_table_bundle
    from secaware.schema.causal import CausalObservationRecord, CausalTableRecord

    prompts = _prompts((1, 2, 3))
    tables, rows, exclusions = _build(prompts=prompts)
    target = next(item for item in tables if item.model_id == "model-b")
    retained = tuple(
        item for item in rows if item.table_id == target.table_id and item.prompt_id != "prompt-3"
    )
    payload = tuple(
        (item.row_id, item.task_id, item.prompt_id, item.seed_id, item.values) for item in retained
    )
    replacement = CausalTableRecord.from_content(
        scope_id=target.scope_id,
        cwe=target.cwe,
        model_id=target.model_id,
        variables=target.variables,
        row_count=len(retained),
        independent_task_count=len({item.task_id for item in retained}),
        observation_payload=payload,
    )
    replacement_rows = tuple(
        CausalObservationRecord.from_content(
            table=replacement,
            task_id=item.task_id,
            prompt_id=item.prompt_id,
            model_id=item.model_id,
            seed_id=item.seed_id,
            values=item.values,
        )
        for item in retained
    )
    changed_tables = tuple(
        sorted(
            (replacement if item.table_id == target.table_id else item for item in tables),
            key=lambda item: (item.scope_id, item.model_id),
        )
    )
    changed_rows = tuple(
        sorted(
            (
                *(item for item in rows if item.table_id != target.table_id),
                *replacement_rows,
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )
    coordinates = tuple(
        item
        for item in _source_coordinates(prompts)
        if not (item[2] == "model-b" and item[4] == "prompt-3")
    )

    with pytest.raises(SecAwareError):
        validate_local_table_bundle(
            changed_tables,
            changed_rows,
            exclusions,
            source_coordinates=coordinates,
        )


def test_live_prompt_projections_are_cached_per_prompt_and_requested_query(monkeypatch) -> None:
    import secaware.causal.table_builder as table_builder_module
    from secaware.causal.variable_catalog import declaration_by_id

    feature_calls = 0
    motif_calls = 0
    original_feature = table_builder_module.feature_state
    original_motif = table_builder_module.motif_query_vector

    def counted_feature(*args, **kwargs):
        nonlocal feature_calls
        feature_calls += 1
        return original_feature(*args, **kwargs)

    def counted_motif(*args, **kwargs):
        nonlocal motif_calls
        motif_calls += 1
        return original_motif(*args, **kwargs)

    monkeypatch.setattr(table_builder_module, "feature_state", counted_feature)
    monkeypatch.setattr(table_builder_module, "motif_query_vector", counted_motif)

    _build()
    assert feature_calls == len(_prompts())
    assert motif_calls == 0

    feature_calls = 0
    motif_calls = 0
    declarations = (
        *_declarations(),
        declaration_by_id("x.motif.user_path_to_file_open_without_guard"),
    )
    table_builder_module.build_local_tables(
        _prompts(),
        _graphs(),
        _oracles(),
        declarations,
        min_independent_tasks=2,
    )
    assert feature_calls == len(_prompts())
    assert motif_calls == len(_prompts())

from __future__ import annotations

from copy import deepcopy
from importlib.metadata import version
import math

import pytest
from pydantic import ValidationError

from secaware.config import FCIDiscoveryConfig
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapFailureReason,
    BootstrapFailureRecord,
    BootstrapDrawItem,
    BootstrapDrawRecord,
    CausalExclusionReason,
    CausalExclusionRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    DiscoveryFailureReason,
    DiscoveryFailureRecord,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    PathPatternRecord,
    PathSupportRecord,
    VariableRole,
)


SHA_A = "a" * 64
SHA_B = "b" * 64


def _variable(variable_id: str, role: VariableRole, tier: int) -> CausalVariableSpec:
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=variable_id,
        role=role,
        states=("absent", "present"),
        source_query_id=f"query.{variable_id}",
        scope_id="scope.path",
        temporal_tier=tier,
        adjacency_type="prompt_feature" if role is not VariableRole.Y else "outcome",
        producer_sha256=SHA_A,
    )


def _variables() -> tuple[CausalVariableSpec, ...]:
    return (
        _variable("x.safety.path_normalization", VariableRole.X, 1),
        _variable("y.secure_functional", VariableRole.Y, 2),
    )


def _table() -> CausalTableRecord:
    observations = (
        ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
        ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
    )
    return CausalTableRecord.from_content(
        scope_id="scope.path",
        cwe="CWE-22",
        model_id="model-a",
        variables=_variables(),
        row_count=2,
        independent_task_count=2,
        observation_payload=observations,
    )


def test_minimum_backend_is_pinned_causal_learn_gsq() -> None:
    config = FCIDiscoveryConfig()

    assert config.backend == "causal_learn_fci_v1"
    assert config.backend_version == "0.1.4.7"
    assert config.ci_test == "gsq"
    assert config.depth == 3
    assert config.max_path_length == 6
    assert version("causal-learn") == "0.1.4.7"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("alpha", math.nan),
        ("alpha", math.inf),
        ("depth", True),
        ("depth", 9),
        ("max_path_length", 17),
        ("max_variables", 65),
        ("max_rows", 100_001),
        ("bootstrap_samples", 10_001),
        ("max_candidate_paths", 4097),
    ],
)
def test_discovery_config_is_strict_finite_and_bounded(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        FCIDiscoveryConfig.model_validate({field: value})


def test_discovery_config_is_frozen_and_rejects_removed_heuristic_fields() -> None:
    config = FCIDiscoveryConfig()

    with pytest.raises(ValidationError):
        config.depth = 4
    with pytest.raises(ValidationError):
        FCIDiscoveryConfig.model_validate({"min_support_total": 4})


def test_table_ids_and_digests_are_derived_from_canonical_content() -> None:
    table = _table()
    reversed_table = CausalTableRecord.from_content(
        scope_id="scope.path",
        cwe="CWE-22",
        model_id="model-a",
        variables=tuple(reversed(_variables())),
        row_count=2,
        independent_task_count=2,
        observation_payload=(
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
            ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
        ),
    )

    assert table.table_id == f"table_{table.table_sha256}"
    assert reversed_table == table
    changed = CausalTableRecord.from_content(
        scope_id="scope.path",
        cwe="CWE-22",
        model_id="model-a",
        variables=_variables(),
        row_count=2,
        independent_task_count=2,
        observation_payload=(
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (0, 0)),
            ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
        ),
    )
    assert changed.table_sha256 != table.table_sha256


def test_table_rejects_duplicate_variables_invalid_states_and_bounds() -> None:
    variable = _variables()[0]
    with pytest.raises(ValidationError):
        CausalTableRecord.from_content(
            scope_id="scope.path",
            cwe="CWE-22",
            model_id="model-a",
            variables=(variable, variable),
            row_count=2,
            independent_task_count=2,
            observation_payload=(
                ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
                ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
            ),
        )
    with pytest.raises(ValidationError):
        CausalTableRecord.from_content(
            scope_id="scope.path",
            cwe="CWE-22",
            model_id="model-a",
            variables=tuple(
                _variable(f"x.safety.feature_{index}", VariableRole.X, 1) for index in range(65)
            ),
            row_count=2,
            independent_task_count=2,
            observation_payload=(
                ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
                ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
            ),
        )
    with pytest.raises(ValidationError):
        CausalVariableSpec(
            schema_version="1.0",
            variable_id="x.bad",
            role=VariableRole.X,
            states=("same", "same"),
            source_query_id="query.x.bad",
            scope_id="scope.path",
            temporal_tier=1,
            adjacency_type="prompt_feature",
            producer_sha256=SHA_A,
        )


def test_categorical_state_order_is_semantic_not_lexicographic() -> None:
    variable = CausalVariableSpec(
        schema_version="1.0",
        variable_id="y.cwe_security",
        role=VariableRole.Y,
        states=("secure", "insecure", "unknown"),
        source_query_id="outcome.cwe_security_v1",
        scope_id="scope.path",
        temporal_tier=2,
        adjacency_type="outcome",
        producer_sha256=SHA_A,
    )

    assert variable.states == ("secure", "insecure", "unknown")


@pytest.mark.parametrize(
    "observation_payload",
    [
        (
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
        ),
        (
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
            ("row_" + "2" * 64, "task-1", "prompt-1", 1, (1, 0)),
        ),
        (
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
            ("row_" + "2" * 64, "task-1", "prompt-2", 2, (0, 1)),
        ),
        (("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),),
        (
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (2, 0)),
            ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
        ),
        (
            ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1,)),
            ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
        ),
    ],
)
def test_table_content_addressing_rejects_duplicate_or_invalid_observation_payload(
    observation_payload: tuple[tuple[object, ...], ...],
) -> None:
    with pytest.raises(ValidationError):
        CausalTableRecord.from_content(
            scope_id="scope.path",
            cwe="CWE-22",
            model_id="model-a",
            variables=_variables(),
            row_count=2,
            independent_task_count=2,
            observation_payload=observation_payload,
        )


def test_table_persisted_id_must_match_its_sibling_artifact_digest() -> None:
    payload = _table().model_dump(mode="json")
    payload["table_id"] = "table_" + "f" * 64

    with pytest.raises(ValidationError):
        CausalTableRecord.model_validate(payload)


def test_observation_row_id_is_derived_and_codes_are_checked_against_table() -> None:
    table = _table()
    row = CausalObservationRecord.from_content(
        table=table,
        task_id="task-1",
        prompt_id="prompt-1",
        model_id="model-a",
        seed_id=1,
        values=(1, 0),
    )

    assert row.row_id.startswith("row_")
    assert row.table_id == table.table_id
    with pytest.raises(ValidationError):
        CausalObservationRecord.from_content(
            table=table,
            task_id="task-1",
            prompt_id="prompt-1",
            model_id="model-a",
            seed_id=1,
            values=(2, 0),
        )
    with pytest.raises(ValidationError):
        CausalObservationRecord.from_content(
            table=table,
            task_id="task-1",
            prompt_id="prompt-1",
            model_id="model-a",
            seed_id=1,
            values=(1,),
        )
    with pytest.raises(ValidationError):
        CausalObservationRecord.from_content(
            table=table,
            task_id="task-1",
            prompt_id="prompt-1",
            model_id="model-b",
            seed_id=1,
            values=(1, 0),
        )


def test_pag_edge_preserves_circle_endpoints_and_canonical_order() -> None:
    edge = PAGEdgeRecord(
        left="y.secure_functional",
        right="x.safety.path_normalization",
        left_mark=EndpointMark.ARROW,
        right_mark=EndpointMark.CIRCLE,
    )

    assert edge.left == "x.safety.path_normalization"
    assert edge.right == "y.secure_functional"
    assert edge.left_mark is EndpointMark.CIRCLE
    assert edge.right_mark is EndpointMark.ARROW
    assert edge.marks_from(edge.right, edge.left) == (
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    )
    with pytest.raises(ValueError):
        edge.marks_from("x.unknown", edge.right)


def test_pag_is_canonical_closed_and_content_addressed() -> None:
    table = _table()
    edge = PAGEdgeRecord(
        left=table.variables[0].variable_id,
        right=table.variables[1].variable_id,
        left_mark=EndpointMark.CIRCLE,
        right_mark=EndpointMark.ARROW,
    )
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        table_id=table.table_id,
        backend="causal-learn",
        backend_version="0.1.4.7",
        ci_test="gsq",
        config_sha256=SHA_A,
        background_knowledge_sha256=SHA_B,
        variable_ids=tuple(variable.variable_id for variable in table.variables),
        edges=(edge,),
    )

    assert pag.pag_id.startswith("pag_")
    with pytest.raises(ValidationError):
        PAGRecord.from_content(
            run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
            table_id=table.table_id,
            backend="causal-learn",
            backend_version="0.1.4.7",
            ci_test="gsq",
            config_sha256=SHA_A,
            background_knowledge_sha256=SHA_B,
            variable_ids=pag.variable_ids,
            edges=(edge, edge),
        )
    with pytest.raises(ValidationError):
        PAGRecord.from_content(
            run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
            table_id=table.table_id,
            backend="causal-learn",
            backend_version="0.1.4.7",
            ci_test="gsq",
            config_sha256=SHA_A,
            background_knowledge_sha256=SHA_B,
            variable_ids=pag.variable_ids,
            edges=(
                PAGEdgeRecord(
                    left="x.unknown",
                    right=pag.variable_ids[0],
                    left_mark=EndpointMark.CIRCLE,
                    right_mark=EndpointMark.CIRCLE,
                ),
            ),
        )

    tampered = pag.model_dump(mode="json")
    tampered["backend_version"] = "0.1.4.6"
    with pytest.raises(ValidationError):
        PAGRecord.model_validate(tampered)


def test_background_knowledge_is_canonical_closed_and_consistent() -> None:
    table = _table()
    first, second = (variable.variable_id for variable in table.variables)
    knowledge = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        variable_ids=(first, second),
        tiers=((second, 2), (first, 1)),
        forbidden_directions=((second, first),),
        forbidden_adjacencies=(),
        required_directions=(),
    )

    assert knowledge.knowledge_id == f"bk_{knowledge.knowledge_sha256}"
    assert knowledge.tiers == ((first, 1), (second, 2))

    inferred = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=((first, 1), (second, 2)),
        forbidden_directions=((second, first),),
        forbidden_adjacencies=(),
        required_directions=(),
    )
    assert inferred == knowledge
    with pytest.raises(ValidationError):
        BackgroundKnowledgeRecord.from_content(
            table_id=table.table_id,
            variable_ids=(first, second),
            tiers=((first, 1), (second, 2)),
            forbidden_directions=((second, first),),
            forbidden_adjacencies=(),
            required_directions=((second, first),),
        )
    with pytest.raises(ValidationError):
        BackgroundKnowledgeRecord.from_content(
            table_id=table.table_id,
            variable_ids=(first, second),
            tiers=((first, 1), (second, 2)),
            forbidden_directions=(),
            forbidden_adjacencies=((first, second),),
            required_directions=((first, second),),
        )

    required = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        variable_ids=(first, second),
        tiers=((first, 1), (second, 2)),
        forbidden_directions=(),
        forbidden_adjacencies=(),
        required_directions=((first, second),),
    )
    assert required.required_directions == ((first, second),)

    tampered = knowledge.model_dump(mode="json")
    tampered["forbidden_directions"] = []
    with pytest.raises(ValidationError):
        BackgroundKnowledgeRecord.model_validate(tampered)


def test_bootstrap_draw_items_are_sorted_unique_and_content_addressed() -> None:
    table = _table()
    item_0 = BootstrapDrawItem(
        draw_index=0,
        task_id="task-1",
        prompt_id="prompt-1",
        seed_id=1,
        row_id="row_" + "1" * 64,
    )
    item_1 = BootstrapDrawItem(
        draw_index=1,
        task_id="task-2",
        prompt_id="prompt-2",
        seed_id=2,
        row_id="row_" + "2" * 64,
    )
    draw = BootstrapDrawRecord.from_content(
        table_id=table.table_id,
        run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
        replicate_index=3,
        rng_version="sha256-rejection-fisher-yates-v1",
        seed_material_sha256=SHA_A,
        items=(item_0, item_1),
    )

    assert draw.draw_id == f"draw_{draw.draw_sha256}"
    assert draw.selected_row_ids == (item_0.row_id, item_1.row_id)
    with pytest.raises(ValidationError):
        BootstrapDrawRecord.from_content(
            table_id=table.table_id,
            run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
            replicate_index=3,
            rng_version="sha256-rejection-fisher-yates-v1",
            seed_material_sha256=SHA_A,
            items=(item_0, item_0),
        )


def test_nested_records_revalidate_mutated_instances_and_errors_hide_raw_inputs() -> None:
    table = _table()
    unsafe = deepcopy(table.variables[0])
    object.__setattr__(unsafe, "variable_id", "raw secret prompt\nDROP TABLE credentials")

    with pytest.raises(ValidationError) as exc_info:
        CausalTableRecord.from_content(
            scope_id="scope.path",
            cwe="CWE-22",
            model_id="model-a",
            variables=(unsafe, table.variables[1]),
            row_count=2,
            independent_task_count=2,
            observation_payload=(
                ("row_" + "1" * 64, "task-1", "prompt-1", 1, (1, 0)),
                ("row_" + "2" * 64, "task-2", "prompt-2", 2, (0, 1)),
            ),
        )

    rendered = str(exc_info.value)
    assert "DROP TABLE" not in rendered
    assert "credentials" not in rendered
    assert "raw secret prompt" not in repr(table)


def test_forward_failure_exclusion_and_path_records_are_content_addressed() -> None:
    table = _table()
    edge = PAGEdgeRecord(
        left=table.variables[0].variable_id,
        right=table.variables[1].variable_id,
        left_mark=EndpointMark.CIRCLE,
        right_mark=EndpointMark.ARROW,
    )
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        table_id=table.table_id,
        backend="causal-learn",
        backend_version="0.1.4.7",
        ci_test="gsq",
        config_sha256=SHA_A,
        background_knowledge_sha256=SHA_B,
        variable_ids=tuple(variable.variable_id for variable in table.variables),
        edges=(edge,),
    )
    path = PathPatternRecord.from_content(
        variable_ids=(edge.left, edge.right),
        endpoint_marks=((edge.left_mark, edge.right_mark),),
    )
    support = PathSupportRecord.from_content(
        table_id=table.table_id,
        reference_pag_id=pag.pag_id,
        path=path,
        support_numerator=8,
        support_denominator=10,
        bootstrap_config_sha256=SHA_A,
    )
    exclusion = CausalExclusionRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        task_id="task-1",
        prompt_id="prompt-1",
        seed_id=1,
        variable_id=edge.left,
        reason_code=CausalExclusionReason.UNRESOLVED_FEATURE,
        producer_sha256=SHA_A,
    )
    bootstrap_failure = BootstrapFailureRecord.from_content(
        table_id=table.table_id,
        replicate_index=3,
        draw_id="draw_" + "d" * 64,
        reason_code=BootstrapFailureReason.BACKEND_TIMEOUT,
        fci_config_sha256=SHA_A,
        detail_sha256=SHA_B,
    )
    discovery_failure = DiscoveryFailureRecord.from_content(
        table_id=table.table_id,
        scope_id=table.scope_id,
        model_id=table.model_id,
        reason_code=DiscoveryFailureReason.NO_STABLE_HYPOTHESIS,
        table_sha256=table.table_sha256,
        fci_config_sha256=SHA_A,
        background_knowledge_sha256=SHA_B,
        detail_sha256="c" * 64,
    )

    assert path.path_id == f"path_{path.path_sha256}"
    assert support.support_id == f"path_support_{support.support_sha256}"
    assert exclusion.exclusion_id.startswith("exclusion_")
    assert bootstrap_failure.failure_id.startswith("bootstrap_failure_")
    assert discovery_failure.failure_id.startswith("discovery_failure_")


def test_path_preserves_semantic_order_and_validates_edge_count_and_support() -> None:
    path = PathPatternRecord.from_content(
        variable_ids=("x.target", "w.mechanism", "y.outcome"),
        endpoint_marks=(
            (EndpointMark.CIRCLE, EndpointMark.ARROW),
            (EndpointMark.TAIL, EndpointMark.CIRCLE),
        ),
    )

    assert path.variable_ids == ("x.target", "w.mechanism", "y.outcome")
    with pytest.raises(ValidationError):
        PathPatternRecord.from_content(
            variable_ids=("x.target", "y.outcome"),
            endpoint_marks=(),
        )
    with pytest.raises(ValidationError):
        PathPatternRecord.from_content(
            variable_ids=("x.target", "x.target", "y.outcome"),
            endpoint_marks=(
                (EndpointMark.CIRCLE, EndpointMark.CIRCLE),
                (EndpointMark.CIRCLE, EndpointMark.CIRCLE),
            ),
        )

    table = _table()
    with pytest.raises(ValidationError):
        PathSupportRecord.from_content(
            table_id=table.table_id,
            reference_pag_id="pag_" + "d" * 64,
            path=path,
            support_numerator=11,
            support_denominator=10,
            bootstrap_config_sha256=SHA_A,
        )


def test_failure_records_only_accept_finite_reasons_and_safe_detail_digests() -> None:
    table = _table()
    payload = {
        "table_id": table.table_id,
        "scope_id": table.scope_id,
        "model_id": table.model_id,
        "reason_code": "raw-secret-reason",
        "table_sha256": table.table_sha256,
        "fci_config_sha256": SHA_A,
        "background_knowledge_sha256": SHA_B,
        "detail_sha256": "secret prompt text",
    }
    with pytest.raises(ValidationError) as exc_info:
        DiscoveryFailureRecord.from_content(**payload)
    rendered = str(exc_info.value)
    assert "raw-secret-reason" not in rendered
    assert "secret prompt text" not in rendered


@pytest.mark.parametrize(
    "factory",
    [
        lambda: PAGRecord.from_content(
            run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
            table_id="table_" + "a" * 64,
            backend="causal-learn",
            backend_version="0.1.4.7",
            ci_test="gsq",
            config_sha256=SHA_A,
            background_knowledge_sha256=SHA_B,
            variable_ids=("x.safe", "y.safe"),
            edges=("raw secret prompt",),
        ),
        lambda: BackgroundKnowledgeRecord.from_content(
            table_id="table_" + "a" * 64,
            variable_ids=("x.safe", "y.safe"),
            tiers=(("x.safe", 1), ("y.safe", 2)),
            forbidden_directions=(("raw secret prompt",),),
            forbidden_adjacencies=(),
        ),
        lambda: BootstrapDrawRecord.from_content(
            table_id="table_" + "a" * 64,
            run_kind=PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
            replicate_index=0,
            rng_version="sha256-rejection-fisher-yates-v1",
            seed_material_sha256=SHA_A,
            items=("raw secret prompt",),
        ),
        lambda: PathSupportRecord.from_content(
            table_id="table_" + "a" * 64,
            reference_pag_id="pag_" + "b" * 64,
            path="raw secret prompt",
            support_numerator=0,
            support_denominator=1,
            bootstrap_config_sha256=SHA_A,
        ),
        lambda: CausalObservationRecord.from_content(
            table=_table(),
            task_id="task-1",
            prompt_id="prompt-1",
            model_id="model-a",
            seed_id=1,
            values=None,
        ),
        lambda: BackgroundKnowledgeRecord.from_content(
            table_id="table_" + "a" * 64,
            tiers=(("x.safe", 1), ("y.safe", 2)),
            forbidden_directions=(),
            forbidden_adjacencies=(("raw secret prompt",),),
        ),
        lambda: PathPatternRecord.from_content(
            variable_ids=(object(), "y.safe"),
            endpoint_marks=((EndpointMark.CIRCLE, EndpointMark.ARROW),),
        ),
        lambda: BootstrapFailureRecord.from_content(
            table_id="table_" + "a" * 64,
            replicate_index=0,
            draw_id="draw_" + "b" * 64,
            reason_code=BootstrapFailureReason.BACKEND_TIMEOUT,
            fci_config_sha256=SHA_A,
            detail_sha256=object(),
        ),
    ],
)
def test_content_factories_sanitize_prevalidation_errors(factory) -> None:
    with pytest.raises(ValidationError) as exc_info:
        factory()
    assert "raw secret prompt" not in str(exc_info.value)


def test_unknown_endpoint_mark_and_control_characters_are_rejected_safely() -> None:
    with pytest.raises(ValidationError) as exc_info:
        PAGEdgeRecord.model_validate(
            {
                "left": "x.safe",
                "right": "y.safe",
                "left_mark": "raw-secret-mark",
                "right_mark": "arrow",
            }
        )
    assert "raw-secret-mark" not in str(exc_info.value)

    with pytest.raises(ValidationError):
        _variable("x.bad\nidentifier", VariableRole.X, 1)

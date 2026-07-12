from __future__ import annotations

import inspect

import networkx as nx
import pytest

from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.intervention import validator
from secaware.intervention.validator import validate_intervention
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.motifs import factor_query_vector, motif_query_vector


PATH_SPEC = FACTOR_SPECS[FactorType.PATH_NORMALIZATION]


def _path_prompt_without_guard(prompt_id: str = "p-path") -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Create a Python helper that opens a user-provided file path.",
    )


def _path_prompt_text_with_guard() -> str:
    return (
        "Create a Python helper that opens a user-provided file path. "
        "Normalize the path before use."
    )


def _hypothesis(factor_type: FactorType = FactorType.PATH_NORMALIZATION) -> HypothesisRecord:
    spec = FACTOR_SPECS[factor_type]
    return HypothesisRecord(
        hypothesis_id=f"h-{factor_type.value}",
        factor_type=factor_type,
        motif_id=spec.motif_id,
        requirement_label=spec.requirement_label,
        guard_label=spec.guard_label,
        expected_direction="risk_down_when_added",
        scope={"language": "python", "cwe": spec.cwe},
        patch_operator=spec.patch_operator,
    )


def _validate_path_patch_that_also_adds_sql_requirement() -> dict[str, bool]:
    prompt = _path_prompt_without_guard()
    return validate_intervention(
        prompt,
        extract_prompt_tsg(prompt),
        (f"{_path_prompt_text_with_guard()} Also build a SQL query and use parameterized queries."),
        _hypothesis(),
    )


def _graph_with_labels(
    *,
    prompt_id: str,
    operation_labels: tuple[str, ...],
    sink_labels: tuple[str, ...],
):
    graph = nx.MultiDiGraph()
    for index, label in enumerate(operation_labels):
        graph.add_node(
            f"operation-{index}",
            node_type=NodeType.TASK_OPERATION,
            label=label,
            attributes={},
        )
    for index, label in enumerate(sink_labels):
        graph.add_node(
            f"sink-{index}",
            node_type=NodeType.SINK,
            label=label,
            attributes={},
        )
    return multidigraph_to_record(graph, prompt_id=prompt_id)


def _disconnected_path_guard_record(prompt_id: str):
    graph = nx.MultiDiGraph()
    graph.add_node("operation", node_type=NodeType.TASK_OPERATION, label="open_file", attributes={})
    graph.add_node(
        "source", node_type=NodeType.SOURCE, label="path_normalization_source", attributes={}
    )
    graph.add_node("data", node_type=NodeType.DATA_OBJECT, label="user_path", attributes={})
    graph.add_node("sink", node_type=NodeType.SINK, label="file_open", attributes={})
    graph.add_node(
        "requirement",
        node_type=NodeType.PROMPT_REQUIREMENT,
        label=PATH_SPEC.requirement_label,
        attributes={},
    )
    graph.add_node(
        "guard",
        node_type=NodeType.GUARD,
        label=PATH_SPEC.guard_label,
        attributes={},
    )
    graph.add_edge("operation", "data", edge_type=EdgeType.OPERATES_ON, attributes={})
    graph.add_edge("source", "data", edge_type=EdgeType.SOURCE_OF, attributes={})
    graph.add_edge("data", "sink", edge_type=EdgeType.FLOWS_TO, attributes={})
    graph.add_edge("requirement", "guard", edge_type=EdgeType.REQUIRES, attributes={})
    return multidigraph_to_record(graph, prompt_id=prompt_id)


def _path_state_record(
    prompt_id: str,
    *,
    factor: bool,
    motif: bool,
):
    graph = nx.MultiDiGraph()
    graph.add_node("operation", node_type=NodeType.TASK_OPERATION, label="open_file", attributes={})
    graph.add_node(
        "source", node_type=NodeType.SOURCE, label="path_normalization_source", attributes={}
    )
    graph.add_node("data", node_type=NodeType.DATA_OBJECT, label="user_path", attributes={})
    graph.add_node("sink", node_type=NodeType.SINK, label="file_open", attributes={})
    graph.add_edge("operation", "data", edge_type=EdgeType.OPERATES_ON, attributes={})
    if motif or factor:
        graph.add_edge("source", "data", edge_type=EdgeType.SOURCE_OF, attributes={})
        graph.add_edge("data", "sink", edge_type=EdgeType.FLOWS_TO, attributes={})
    if factor:
        graph.add_node(
            "requirement",
            node_type=NodeType.PROMPT_REQUIREMENT,
            label=PATH_SPEC.requirement_label,
            attributes={},
        )
        graph.add_node(
            "guard",
            node_type=NodeType.GUARD,
            label=PATH_SPEC.guard_label,
            attributes={},
        )
        graph.add_edge("requirement", "guard", edge_type=EdgeType.REQUIRES, attributes={})
        if not motif:
            graph.add_edge("data", "guard", edge_type=EdgeType.GUARDED_BY, attributes={})
            graph.add_edge("sink", "guard", edge_type=EdgeType.GUARDED_BY, attributes={})
    return multidigraph_to_record(graph, prompt_id=prompt_id)


def _route_extraction(
    monkeypatch: pytest.MonkeyPatch,
    *,
    original_text: str,
    original_record: object,
    counter_record: object,
) -> None:
    def routed(candidate: PromptRecord):
        return original_record if candidate.prompt == original_text else counter_record

    monkeypatch.setattr(validator, "extract_prompt_tsg", routed)


def test_intervention_target_and_side_effect_ignore_shadow() -> None:
    original_prompt = _path_prompt_without_guard()
    original = extract_prompt_tsg(original_prompt)
    result = validate_intervention(
        original_prompt,
        original,
        _path_prompt_text_with_guard(),
        _hypothesis(),
    )
    assert result == {
        "round_trip_valid": True,
        "semantic_valid": True,
        "target_changed": True,
        "side_effect": False,
    }


def test_unrelated_requirement_is_reported_as_side_effect() -> None:
    result = _validate_path_patch_that_also_adds_sql_requirement()
    assert result["target_changed"] is True
    assert result["side_effect"] is True


def test_target_factor_changes_false_to_true_and_target_motif_is_removed() -> None:
    prompt = _path_prompt_without_guard()
    original_graph = record_to_multidigraph(extract_prompt_tsg(prompt))
    counter = PromptRecord.model_validate(
        {**prompt.model_dump(), "prompt": _path_prompt_text_with_guard()}
    )
    counter_graph = record_to_multidigraph(extract_prompt_tsg(counter))

    assert dict(factor_query_vector(original_graph))[PATH_SPEC.factor_type] is False
    assert dict(factor_query_vector(counter_graph))[PATH_SPEC.factor_type] is True
    assert dict(motif_query_vector(original_graph))[PATH_SPEC.motif_id] is True
    assert dict(motif_query_vector(counter_graph))[PATH_SPEC.motif_id] is False


def test_disconnected_guard_does_not_count_as_valid_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _path_prompt_without_guard()
    original = extract_prompt_tsg(prompt)
    disconnected = _disconnected_path_guard_record(prompt.prompt_id)
    _route_extraction(
        monkeypatch,
        original_text=prompt.prompt,
        original_record=original,
        counter_record=disconnected,
    )

    result = validate_intervention(prompt, original, _path_prompt_text_with_guard(), _hypothesis())

    assert result["round_trip_valid"] is False
    assert result["target_changed"] is False


def test_wrong_hypothesis_target_fails_round_trip_and_target_change() -> None:
    prompt = _path_prompt_without_guard()
    result = validate_intervention(
        prompt,
        extract_prompt_tsg(prompt),
        _path_prompt_text_with_guard(),
        _hypothesis(FactorType.SQL_PARAMETERIZATION),
    )

    assert result["round_trip_valid"] is False
    assert result["target_changed"] is False


@pytest.mark.parametrize(
    ("counter_operations", "counter_sinks", "expected"),
    (
        (("open_file", "open_file"), ("file_open",), False),
        (("changed_operation",), ("file_open",), False),
        (("open_file",), (), False),
        (("open_file",), ("file_open", "other_sink"), False),
    ),
)
def test_semantic_validation_compares_complete_operation_and_sink_multisets(
    monkeypatch: pytest.MonkeyPatch,
    counter_operations: tuple[str, ...],
    counter_sinks: tuple[str, ...],
    expected: bool,
) -> None:
    prompt = _path_prompt_without_guard()
    original = _graph_with_labels(
        prompt_id=prompt.prompt_id,
        operation_labels=("open_file",),
        sink_labels=("file_open",),
    )
    counter = _graph_with_labels(
        prompt_id=prompt.prompt_id,
        operation_labels=counter_operations,
        sink_labels=counter_sinks,
    )
    _route_extraction(
        monkeypatch,
        original_text=prompt.prompt,
        original_record=original,
        counter_record=counter,
    )

    result = validate_intervention(prompt, original, _path_prompt_text_with_guard(), _hypothesis())

    assert result["semantic_valid"] is expected


def test_semantic_identity_ignores_graph_node_ids_and_insertion_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _path_prompt_without_guard()
    original = _graph_with_labels(
        prompt_id=prompt.prompt_id,
        operation_labels=("beta", "alpha"),
        sink_labels=("zeta", "zeta"),
    )
    counter = _graph_with_labels(
        prompt_id=prompt.prompt_id,
        operation_labels=("alpha", "beta"),
        sink_labels=("zeta", "zeta"),
    )
    _route_extraction(
        monkeypatch,
        original_text=prompt.prompt,
        original_record=original,
        counter_record=counter,
    )

    result = validate_intervention(prompt, original, _path_prompt_text_with_guard(), _hypothesis())

    assert result["semantic_valid"] is True


def test_non_target_factor_and_motif_vectors_are_compared_completely() -> None:
    result = _validate_path_patch_that_also_adds_sql_requirement()

    assert result["side_effect"] is True


def test_unrelated_unguarded_flow_is_reported_as_side_effect() -> None:
    prompt = _path_prompt_without_guard()
    result = validate_intervention(
        prompt,
        extract_prompt_tsg(prompt),
        f"{_path_prompt_text_with_guard()} Also execute command input.",
        _hypothesis(),
    )

    assert result["side_effect"] is True


def test_forged_shadow_is_rejected_by_graph_boundary() -> None:
    prompt = _path_prompt_without_guard()
    original = extract_prompt_tsg(prompt)
    forged = original.model_copy(
        update={"shadow": {**original.shadow, "factor.path_normalization_required": True}}
    )

    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(prompt, forged, _path_prompt_text_with_guard(), _hypothesis())

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None


def test_canonical_graph_change_updates_validation_without_shadow_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _path_prompt_without_guard()
    original = extract_prompt_tsg(prompt)
    guarded_prompt = PromptRecord.model_validate(
        {**prompt.model_dump(), "prompt": _path_prompt_text_with_guard()}
    )
    guarded = extract_prompt_tsg(guarded_prompt)
    graph = record_to_multidigraph(guarded)
    requires = next(
        (src, dst, key)
        for src, dst, key, data in graph.edges(keys=True, data=True)
        if data["edge_type"] is EdgeType.REQUIRES
    )
    graph.remove_edge(*requires)
    changed = multidigraph_to_record(graph, prompt_id=prompt.prompt_id)
    _route_extraction(
        monkeypatch,
        original_text=prompt.prompt,
        original_record=original,
        counter_record=changed,
    )

    result = validate_intervention(prompt, original, _path_prompt_text_with_guard(), _hypothesis())

    assert result["round_trip_valid"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("factor_type", FactorType.SQL_PARAMETERIZATION),
        ("motif_id", FACTOR_SPECS[FactorType.SQL_PARAMETERIZATION].motif_id),
        ("requirement_label", "require_sql_parameterization"),
        ("guard_label", "sql_parameterization"),
    ),
)
def test_mismatched_hypothesis_catalog_target_fails_sanitized_analysis_invalid(
    field: str,
    value: object,
) -> None:
    prompt = _path_prompt_without_guard()
    forged = _hypothesis().model_copy(update={field: value})

    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(
            prompt, extract_prompt_tsg(prompt), _path_prompt_text_with_guard(), forged
        )

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None
    retained = _retained_source_locals(exc_info.value, prompt.prompt)
    assert "HypothesisRecord(" not in retained


def test_prompt_and_graph_coordinates_must_match() -> None:
    prompt = _path_prompt_without_guard("p-one")
    other_graph = extract_prompt_tsg(_path_prompt_without_guard("p-two"))

    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(prompt, other_graph, _path_prompt_text_with_guard(), _hypothesis())

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}


def test_same_prompt_id_graph_from_different_prompt_is_analysis_invalid() -> None:
    prompt = _path_prompt_without_guard("p-same-id")
    wrong_prompt = PromptRecord.model_validate(
        {
            **prompt.model_dump(),
            "prompt": "Create a Python helper that builds a SQL query.",
        }
    )
    wrong_graph = extract_prompt_tsg(wrong_prompt)

    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(prompt, wrong_graph, _path_prompt_text_with_guard(), _hypothesis())

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


@pytest.mark.parametrize(
    (
        "original_factor",
        "original_motif",
        "counter_factor",
        "counter_motif",
        "round_trip",
        "target_changed",
    ),
    (
        (False, True, True, False, True, True),
        (True, True, True, False, True, False),
        (True, False, True, False, True, False),
        (False, True, False, False, False, False),
        (False, False, True, False, True, True),
    ),
)
def test_target_changed_requires_exact_false_to_true_factor_direction(
    monkeypatch: pytest.MonkeyPatch,
    original_factor: bool,
    original_motif: bool,
    counter_factor: bool,
    counter_motif: bool,
    round_trip: bool,
    target_changed: bool,
) -> None:
    prompt = PromptRecord(
        prompt_id="p-target-direction",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="original target graph",
    )
    original = _path_state_record(
        prompt.prompt_id,
        factor=original_factor,
        motif=original_motif,
    )
    counter = _path_state_record(
        prompt.prompt_id,
        factor=counter_factor,
        motif=counter_motif,
    )
    _route_extraction(
        monkeypatch,
        original_text=prompt.prompt,
        original_record=original,
        counter_record=counter,
    )

    result = validate_intervention(prompt, original, "counter target graph", _hypothesis())

    assert result["round_trip_valid"] is round_trip
    assert result["target_changed"] is target_changed


@pytest.mark.parametrize("kind", ("prompt", "hypothesis", "tsg"))
def test_duplicate_or_invalid_models_fail_closed(kind: str) -> None:
    prompt = _path_prompt_without_guard()
    hypothesis = _hypothesis()
    original = extract_prompt_tsg(prompt)
    expected = ErrorCode.ANALYSIS_INVALID
    if kind == "prompt":
        prompt.__dict__["duplicate"] = "forged"
    elif kind == "hypothesis":
        hypothesis.__dict__["duplicate"] = "forged"
    else:
        original = original.model_copy(update={"nodes": (*original.nodes, original.nodes[0])})
        expected = ErrorCode.TSG_INVALID

    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(prompt, original, _path_prompt_text_with_guard(), hypothesis)

    assert exc_info.value.code is expected
    assert exc_info.value.details == {}


@pytest.mark.parametrize(
    ("target", "error"),
    (
        ("factor_query_vector", RuntimeError("secret frame factor")),
        ("motif_query_vector", ValueError("secret frame motif")),
        ("extract_prompt_tsg", TypeError("secret frame extractor")),
    ),
)
def test_internal_failures_are_sanitized_without_prompt_or_frame_leaks(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    error: Exception,
) -> None:
    prompt = _path_prompt_without_guard("p-secret-context")

    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(validator, target, fail)
    with pytest.raises(SecAwareError) as exc_info:
        validate_intervention(
            prompt, extract_prompt_tsg(prompt), _path_prompt_text_with_guard(), _hypothesis()
        )

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None
    retained = _retained_source_locals(exc_info.value, prompt.prompt)
    assert "p-secret-context" not in retained
    assert "secret frame" not in str(exc_info.value)


def _retained_source_locals(error: BaseException, prompt_text: str) -> str:
    retained: list[str] = []
    frame = error.__traceback__
    while frame is not None:
        if "/src/secaware/" in frame.tb_frame.f_code.co_filename.replace("\\", "/"):
            rendered = repr(frame.tb_frame.f_locals)
            assert prompt_text not in rendered
            retained.append(rendered)
        frame = frame.tb_next
    return "\n".join(retained)


def test_intervention_source_has_no_legacy_or_shadow_authority_reads() -> None:
    source = "\n".join(
        inspect.getsource(module)
        for module in (
            validator,
            __import__("secaware.intervention.operators", fromlist=["*"]),
            __import__("secaware.intervention.verbalizer", fromlist=["*"]),
        )
    )

    for forbidden in (
        "." + "features",
        "." + "shadow",
        "features" + ".get",
        "prompt_" + "factor",
    ):
        assert forbidden not in source

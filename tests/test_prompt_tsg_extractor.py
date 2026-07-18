from __future__ import annotations

import hashlib
from pathlib import Path
import traceback

import pytest

import secaware.extractors.prompt_tsg_extractor as prompt_extractor
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType
from secaware.tsg.catalog import PROMPT_TSG_CATALOG, PromptOntologyEntry
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG, FeatureSpec
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state


_DOMAIN_BOUNDARY_CASES = tuple(
    (entry, term, prefix, suffix)
    for entry in PROMPT_TSG_CATALOG
    for term in entry.domain_terms
    for prefix, suffix in (("x", ""), ("", "x"), ("_", "_"))
)
_GUARD_BOUNDARY_CASES = tuple(
    (entry, term, prefix, suffix)
    for entry in PROMPT_TSG_CATALOG
    for term in entry.guard_terms
    for prefix, suffix in (("x", ""), ("", "x"), ("_", "_"))
)


def _prompt(
    text: str,
    *,
    language: str = "python",
    task_family: str = "path_handling",
    cwe: str = "CWE-22",
) -> PromptRecord:
    return PromptRecord(
        prompt_id="p001",
        task_id="task-p001",
        split="discover",
        language=language,
        task_family=task_family,
        cwe=cwe,
        prompt=text,
        prompt_role="neutral_baseline",
        counterpart_prompt_id=None,
    )


def _feature_specs(entry: PromptOntologyEntry) -> tuple[FeatureSpec, FeatureSpec]:
    task = next(spec for spec in PROMPT_FEATURE_CATALOG if spec.feature_id == entry.task_feature_id)
    safety = next(
        spec for spec in PROMPT_FEATURE_CATALOG if spec.feature_id == entry.target_feature_id
    )
    return task, safety


def _entry_prompt(
    entry: PromptOntologyEntry,
    text: str,
    *,
    language: str = "python",
) -> PromptRecord:
    task, _ = _feature_specs(entry)
    return _prompt(
        text,
        language=language,
        task_family=task.applicable_task_families[0],
        cwe=entry.cwe,
    )


def _feature_structure(graph: object, feature_id: str) -> list[tuple[str, dict[str, object]]]:
    labels: set[str] = set()
    for entry in PROMPT_TSG_CATALOG:
        task, safety = _feature_specs(entry)
        if feature_id == task.feature_id:
            labels = {
                entry.operation_label,
                f"{entry.target_feature_id.removeprefix('safety.')}_source",
                entry.data_label,
                entry.sink_label,
                entry.cwe,
            }
        elif feature_id == safety.feature_id:
            labels = {entry.requirement_label, entry.guard_label}
    return [
        (node_id, attributes)
        for node_id, attributes in graph.nodes(data=True)  # type: ignore[union-attr]
        if attributes["label"] in labels or str(attributes["label"]).startswith(f"{feature_id}:")
    ]


def _feature_edges(graph: object, feature_id: str) -> set[EdgeType]:
    node_ids = {node_id for node_id, _ in _feature_structure(graph, feature_id)}
    return {
        attributes["edge_type"]
        for src, dst, attributes in graph.edges(data=True)  # type: ignore[union-attr]
        if src in node_ids and dst in node_ids
    }


def _assert_sanitized_error(
    error: SecAwareError,
    *,
    code: ErrorCode,
    sentinel: str,
) -> None:
    assert error.code is code
    assert error.__context__ is None
    assert error.__cause__ is None
    assert sentinel not in str(error)
    assert sentinel not in repr(error)

    traceback_cursor = error.__traceback__
    while traceback_cursor is not None:
        frame = traceback_cursor.tb_frame
        if Path(frame.f_code.co_filename).resolve() == Path(prompt_extractor.__file__).resolve():
            assert sentinel not in repr(frame.f_locals)
        traceback_cursor = traceback_cursor.tb_next


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_each_cwe_domain_phrase_emits_one_present_task_feature(
    entry: PromptOntologyEntry,
) -> None:
    task, safety = _feature_specs(entry)
    record = extract_prompt_tsg(_entry_prompt(entry, f"Please {entry.domain_terms[0]}."))
    graph = record_to_multidigraph(record)

    assert record.extractor_backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    assert feature_state(graph, task.feature_id) is FeatureState.PRESENT
    assert feature_state(graph, safety.feature_id) is FeatureState.ABSENT
    assert {data["node_type"] for _, data in _feature_structure(graph, task.feature_id)} >= set(
        task.structural_node_types
    )
    assert _feature_edges(graph, task.feature_id) >= set(task.structural_edge_types)
    assert record.shadow["graph.node_count"] == len(record.nodes)


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_each_cwe_guard_phrase_emits_task_and_safety_feature_states(
    entry: PromptOntologyEntry,
) -> None:
    task, safety = _feature_specs(entry)
    text = f"Please {entry.domain_terms[0]}; {entry.guard_terms[0]}."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))

    assert feature_state(graph, task.feature_id) is FeatureState.PRESENT
    assert feature_state(graph, safety.feature_id) is FeatureState.PRESENT
    assert {data["node_type"] for _, data in _feature_structure(graph, safety.feature_id)} >= set(
        safety.structural_node_types
    )
    assert _feature_edges(graph, safety.feature_id) >= set(safety.structural_edge_types)


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_absent_domain_evidence_is_an_explicit_absent_state(entry: PromptOntologyEntry) -> None:
    task, safety = _feature_specs(entry)
    graph = record_to_multidigraph(
        extract_prompt_tsg(_entry_prompt(entry, "Return the number seven."))
    )

    assert feature_state(graph, task.feature_id) is FeatureState.ABSENT
    assert feature_state(graph, safety.feature_id) is FeatureState.ABSENT
    assert not _feature_structure(graph, task.feature_id)
    assert not _feature_structure(graph, safety.feature_id)


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_detached_guard_evidence_does_not_create_a_present_control(
    entry: PromptOntologyEntry,
) -> None:
    task, safety = _feature_specs(entry)
    graph = record_to_multidigraph(
        extract_prompt_tsg(_entry_prompt(entry, f"Please {entry.guard_terms[0]} carefully."))
    )

    assert feature_state(graph, task.feature_id) is FeatureState.ABSENT
    assert feature_state(graph, safety.feature_id) is FeatureState.ABSENT


@pytest.mark.parametrize(("entry", "term", "prefix", "suffix"), _DOMAIN_BOUNDARY_CASES)
def test_embedded_domain_terms_do_not_match(
    entry: PromptOntologyEntry,
    term: str,
    prefix: str,
    suffix: str,
) -> None:
    task, _ = _feature_specs(entry)
    text = f"Please process {prefix}{term}{suffix}."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))

    assert feature_state(graph, task.feature_id) is FeatureState.ABSENT


@pytest.mark.parametrize(("entry", "term", "prefix", "suffix"), _GUARD_BOUNDARY_CASES)
def test_embedded_guard_terms_do_not_match(
    entry: PromptOntologyEntry,
    term: str,
    prefix: str,
    suffix: str,
) -> None:
    task, safety = _feature_specs(entry)
    text = f"Please {entry.domain_terms[0]}; then {prefix}{term}{suffix}."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))

    assert feature_state(graph, task.feature_id) is FeatureState.PRESENT
    assert feature_state(graph, safety.feature_id) is FeatureState.ABSENT


def test_punctuated_guard_matches_case_insensitively_with_raw_evidence() -> None:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.cwe == "CWE-78")
    _, safety = _feature_specs(entry)
    raw_guard = "SHELL=FALSE"
    text = f"Please RUN A COMMAND; ({raw_guard})!"
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))
    attributes = _feature_structure(graph, safety.feature_id)[0][1]["attributes"]
    start = text.index(raw_guard)

    assert attributes == {
        "evidence_start": start,
        "evidence_end": start + len(raw_guard),
        "evidence_sha256": hashlib.sha256(raw_guard.encode("utf-8")).hexdigest(),
    }


def test_path_prompt_emits_catalog_typed_flow_and_feature_state() -> None:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.cwe == "CWE-22")
    task, _ = _feature_specs(entry)
    graph = record_to_multidigraph(
        extract_prompt_tsg(_entry_prompt(entry, "Open a user-provided file path."))
    )

    assert feature_state(graph, task.feature_id) is FeatureState.PRESENT
    assert _feature_edges(graph, task.feature_id) >= {
        EdgeType.OPERATES_ON,
        EdgeType.FLOWS_TO,
    }


def test_guard_and_task_evidence_can_overlap_without_losing_either_fact() -> None:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.cwe == "CWE-22")
    task, safety = _feature_specs(entry)
    text = "Open a user path; normalize the path and restrict it to a base directory."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))

    assert feature_state(graph, task.feature_id) is FeatureState.PRESENT
    assert feature_state(graph, safety.feature_id) is FeatureState.PRESENT
    assert _feature_structure(graph, task.feature_id)
    assert _feature_structure(graph, safety.feature_id)


def test_deterministic_wrapper_preserves_same_flow_guard_projection() -> None:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.cwe == "CWE-22")
    text = "Open a user path; normalize the path."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))
    guard = next(
        node_id for node_id, data in graph.nodes(data=True) if data["label"] == entry.guard_label
    )
    guarded_labels = {
        graph.nodes[src]["label"]
        for src, dst, data in graph.edges(data=True)
        if dst == guard and data["edge_type"] is EdgeType.GUARDED_BY
    }
    edge_types = {data["edge_type"] for _, _, data in graph.edges(data=True)}

    assert guarded_labels == {entry.data_label, entry.sink_label}
    assert {EdgeType.SOURCE_OF, EdgeType.MAPS_TO, EdgeType.GUARDED_BY} <= edge_types


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_unknown_language_marks_in_scope_finite_features_unresolved(
    entry: PromptOntologyEntry,
) -> None:
    task, safety = _feature_specs(entry)
    graph = record_to_multidigraph(
        extract_prompt_tsg(
            _entry_prompt(
                entry,
                f"Please {entry.domain_terms[0]}; {entry.guard_terms[0]}.",
                language="brainfuck",
            )
        )
    )

    assert feature_state(graph, task.feature_id) is FeatureState.UNRESOLVED
    assert feature_state(graph, safety.feature_id) is FeatureState.UNRESOLVED
    assert not _feature_structure(graph, task.feature_id)
    assert not _feature_structure(graph, safety.feature_id)


def test_reviewed_presentation_terms_make_ordinary_prompt_explicitly_absent() -> None:
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt("Open a user-provided file path.")))

    assert feature_state(graph, "presentation.noop_rewrite") is FeatureState.ABSENT
    assert feature_state(graph, "presentation.matched_control") is FeatureState.ABSENT


def test_out_of_scope_terms_remain_not_applicable_and_output_is_deterministic() -> None:
    text = "Build a SQL query and open a user path; use a prepared statement and normalize it."
    one = extract_prompt_tsg(_prompt(text))
    two = extract_prompt_tsg(_prompt(text))
    graph = record_to_multidigraph(one)

    assert one.model_dump_json() == two.model_dump_json()
    assert feature_state(graph, "task.file_read") is FeatureState.PRESENT
    assert feature_state(graph, "safety.path_normalization") is FeatureState.PRESENT
    assert feature_state(graph, "task.database_query") is FeatureState.NOT_APPLICABLE
    assert feature_state(graph, "safety.sql_parameterization") is FeatureState.NOT_APPLICABLE


def test_evidence_uses_earliest_match_and_preserves_raw_span_digest() -> None:
    entry = next(item for item in PROMPT_TSG_CATALOG if item.cwe == "CWE-22")
    task, _ = _feature_specs(entry)
    later = entry.domain_terms[0]
    first = entry.domain_terms[1].upper()
    text = f"First {first}; later {later}; again {first}."
    graph = record_to_multidigraph(extract_prompt_tsg(_entry_prompt(entry, text)))
    attributes = _feature_structure(graph, task.feature_id)[0][1]["attributes"]
    start = text.index(first)

    assert attributes == {
        "evidence_start": start,
        "evidence_end": start + len(first),
        "evidence_sha256": hashlib.sha256(first.encode("utf-8")).hexdigest(),
    }


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda item: item.target_feature_id)
def test_only_bounded_evidence_and_finite_feature_states_are_persisted(
    entry: PromptOntologyEntry,
) -> None:
    sentinel = "RAW_PROMPT_SENTINEL_7b3424"
    record = extract_prompt_tsg(_entry_prompt(entry, f"Please {entry.domain_terms[0]}. {sentinel}"))
    rendered = repr(record) + record.model_dump_json()

    assert sentinel not in rendered
    for node in record.nodes:
        assert set(node.attributes) <= {
            "evidence_start",
            "evidence_end",
            "evidence_sha256",
            "feature_id",
            "feature_family",
            "feature_state",
            "cwe_id",
        }
    for edge in record.edges:
        assert set(edge.attributes) <= {
            "evidence_start",
            "evidence_end",
            "evidence_sha256",
            "relation_kind",
            "mapping_kind",
        }


def test_invalid_prompt_record_error_surfaces_are_sanitized() -> None:
    sentinel = "RAW_PROMPT_SENTINEL_816ca1"
    prompt = _prompt(sentinel)
    object.__setattr__(prompt, "language", ["python", sentinel])

    with pytest.raises(SecAwareError) as exc_info:
        extract_prompt_tsg(prompt)

    _assert_sanitized_error(exc_info.value, code=ErrorCode.TSG_INVALID, sentinel=sentinel)


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    (
        ("prompt_id", b"p001"),
        ("task_id", b"task-p001"),
        ("split", b"discover"),
        ("language", b"python"),
        ("task_family", b"path_handling"),
        ("cwe", b"CWE-22"),
        ("prompt", b"Return the number seven. RAW_PROMPT_SENTINEL_431e"),
    ),
)
def test_coercible_prompt_field_mutations_are_rejected_without_leakage(
    field_name: str,
    wrong_value: object,
) -> None:
    sentinel = "RAW_PROMPT_SENTINEL_431e"
    prompt = _prompt(f"Return the number seven. {sentinel}")
    object.__setattr__(prompt, field_name, wrong_value)

    with pytest.raises(SecAwareError) as exc_info:
        extract_prompt_tsg(prompt)

    rendered = "\n".join(
        (
            str(exc_info.value),
            repr(exc_info.value),
            "".join(traceback.format_exception(exc_info.value)),
        )
    )
    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert sentinel not in rendered


@pytest.mark.parametrize("error_type", (RuntimeError, ValueError, TypeError))
def test_unexpected_extraction_failure_is_sanitized_analysis_error(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    sentinel = "INTERNAL_SENTINEL_018aec"

    def fail(snapshot: PromptRecord) -> object:
        held_snapshot = snapshot
        raise error_type(f"{sentinel}:{held_snapshot.prompt}")

    monkeypatch.setattr(prompt_extractor, "_extract", fail)
    with pytest.raises(SecAwareError) as exc_info:
        extract_prompt_tsg(_prompt("Return the number seven."))

    _assert_sanitized_error(
        exc_info.value,
        code=ErrorCode.ANALYSIS_INVALID,
        sentinel=sentinel,
    )


def test_unexpected_snapshot_failure_is_sanitized_analysis_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_: object) -> PromptRecord:
        raise RuntimeError("INTERNAL_SNAPSHOT_SENTINEL_9b2d")

    monkeypatch.setattr(prompt_extractor, "_snapshot_prompt", fail)
    with pytest.raises(SecAwareError) as exc_info:
        extract_prompt_tsg(_prompt("Return the number seven."))

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert "INTERNAL_SNAPSHOT_SENTINEL_9b2d" not in "".join(
        traceback.format_exception(exc_info.value)
    )


def test_compatibility_wrapper_contains_no_matcher_or_decision_assignment() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "secaware" / "extractors" / "prompt_tsg_extractor.py"
    ).read_text(encoding="utf-8")
    lowered = source.casefold()

    for forbidden in (
        "first_reviewed_term_match",
        "domain_terms",
        "guard_terms",
        "features =",
        "secure",
        "insecure",
        "shadow=",
    ):
        assert forbidden not in lowered

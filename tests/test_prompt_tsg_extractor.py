from __future__ import annotations

import hashlib
from pathlib import Path
import traceback

import pytest

import secaware.extractors.prompt_tsg_extractor as prompt_extractor
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.hypotheses import FactorType
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.graph import record_to_multidigraph


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
    cwe: str = "CWE-20",
) -> PromptRecord:
    return PromptRecord(
        prompt_id="p001",
        task_id="task-p001",
        split="discover",
        language=language,
        task_family="reviewed_task",
        cwe=cwe,
        prompt=text,
    )


def _nodes(graph: object, node_type: NodeType) -> list[tuple[str, dict[str, object]]]:
    return [
        (attributes["label"], attributes)
        for _, attributes in graph.nodes(data=True)  # type: ignore[union-attr]
        if attributes["node_type"] is node_type
    ]


def _typed_edges(graph: object) -> set[tuple[str, str, EdgeType]]:
    result: set[tuple[str, str, EdgeType]] = set()
    for src, dst, attributes in graph.edges(data=True):  # type: ignore[union-attr]
        result.add(
            (
                graph.nodes[src]["node_type"].value,  # type: ignore[union-attr]
                graph.nodes[dst]["node_type"].value,  # type: ignore[union-attr]
                attributes["edge_type"],
            )
        )
    return result


def _guard_targets(graph: object, guard_label: str) -> set[str]:
    guard = next(
        node_id
        for node_id, attributes in graph.nodes(data=True)  # type: ignore[union-attr]
        if attributes["node_type"] is NodeType.GUARD and attributes["label"] == guard_label
    )
    return {
        graph.nodes[src]["label"]  # type: ignore[union-attr]
        for src, dst, attributes in graph.edges(data=True)  # type: ignore[union-attr]
        if dst == guard and attributes["edge_type"] is EdgeType.GUARDED_BY
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


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_each_family_domain_prompt_emits_graph_facts(entry: object) -> None:
    record = extract_prompt_tsg(_prompt(f"Please {entry.domain_terms[0]}."))
    graph = record_to_multidigraph(record)

    assert _typed_edges(graph) >= {
        ("source", "data_object", EdgeType.SOURCE_OF),
        ("data_object", "sink", EdgeType.FLOWS_TO),
        ("task_operation", "data_object", EdgeType.OPERATES_ON),
        ("sink", "cwe", EdgeType.MAPS_TO),
    }
    assert {label for label, _ in _nodes(graph, NodeType.DATA_OBJECT)} == {entry.data_label}
    assert {label for label, _ in _nodes(graph, NodeType.SINK)} == {entry.sink_label}
    assert record.shadow["graph.node_count"] == len(record.nodes)
    assert record.shadow[f"factor.{entry.factor_type.value}_required"] is False
    assert not hasattr(record, "features")


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_each_family_explicit_guard_connects_to_same_flow(entry: object) -> None:
    text = f"Please {entry.domain_terms[0]}; {entry.guard_terms[0]}."
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt(text)))

    assert _guard_targets(graph, entry.guard_label) == {entry.data_label, entry.sink_label}
    assert any(
        graph.nodes[src]["label"] == entry.requirement_label
        and graph.nodes[dst]["label"] == entry.guard_label
        and attributes["edge_type"] is EdgeType.REQUIRES
        for src, dst, attributes in graph.edges(data=True)
    )


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_absent_domain_evidence_emits_no_family(entry: object) -> None:
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt("Return the number seven.")))

    labels = {attributes["label"] for _, attributes in graph.nodes(data=True)}
    assert labels.isdisjoint(
        {
            entry.operation_label,
            entry.data_label,
            entry.sink_label,
            entry.requirement_label,
            entry.guard_label,
        }
    )


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_detached_guard_evidence_emits_no_family(entry: object) -> None:
    graph = record_to_multidigraph(
        extract_prompt_tsg(_prompt(f"Please {entry.guard_terms[0]} carefully."))
    )

    labels = {attributes["label"] for _, attributes in graph.nodes(data=True)}
    assert entry.guard_label not in labels
    assert entry.requirement_label not in labels


@pytest.mark.parametrize(
    ("entry", "term", "prefix", "suffix"),
    _DOMAIN_BOUNDARY_CASES,
)
def test_embedded_domain_terms_do_not_emit_family_facts(
    entry: object,
    term: str,
    prefix: str,
    suffix: str,
) -> None:
    graph = record_to_multidigraph(
        extract_prompt_tsg(_prompt(f"Please process {prefix}{term}{suffix}."))
    )
    labels = {attributes["label"] for _, attributes in graph.nodes(data=True)}

    assert entry.data_label not in labels
    assert entry.sink_label not in labels


@pytest.mark.parametrize(
    ("entry", "term", "prefix", "suffix"),
    _GUARD_BOUNDARY_CASES,
)
def test_embedded_guard_terms_do_not_emit_guard_facts(
    entry: object,
    term: str,
    prefix: str,
    suffix: str,
) -> None:
    text = f"Please {entry.domain_terms[0]}; then {prefix}{term}{suffix}."
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt(text)))
    labels = {attributes["label"] for _, attributes in graph.nodes(data=True)}

    assert entry.data_label in labels
    assert entry.guard_label not in labels


def test_punctuated_shell_guard_matches_case_insensitively_with_raw_evidence() -> None:
    shell = next(
        entry for entry in PROMPT_TSG_CATALOG if entry.factor_type is FactorType.SAFE_SUBPROCESS
    )
    raw_guard = "SHELL=FALSE"
    text = f"Please RUN A COMMAND; ({raw_guard})!"
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt(text)))
    guard_attributes = next(
        attributes["attributes"]
        for _, attributes in graph.nodes(data=True)
        if attributes["node_type"] is NodeType.GUARD and attributes["label"] == shell.guard_label
    )
    start = text.index(raw_guard)

    assert guard_attributes == {
        "evidence_start": start,
        "evidence_end": start + len(raw_guard),
        "evidence_sha256": hashlib.sha256(raw_guard.encode("utf-8")).hexdigest(),
    }


def test_path_prompt_emits_flow_facts_without_feature_decisions() -> None:
    record = extract_prompt_tsg(_prompt("Open a user-provided file path."))
    graph = record_to_multidigraph(record)
    assert _typed_edges(graph) >= {
        ("source", "data_object", EdgeType.SOURCE_OF),
        ("data_object", "sink", EdgeType.FLOWS_TO),
    }
    assert not hasattr(record, "features")


def test_guard_requirement_connects_to_the_same_path() -> None:
    record = extract_prompt_tsg(
        _prompt("Open a user path; normalize it and restrict it to a base directory.")
    )
    graph = record_to_multidigraph(record)
    assert _guard_targets(graph, "path_normalization") == {"user_path", "file_open"}


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_unknown_language_yields_valid_minimal_graph(entry: object) -> None:
    record = extract_prompt_tsg(
        _prompt(
            f"Please {entry.domain_terms[0]} and report whether it is insecure.",
            language="brainfuck",
        )
    )

    assert record.nodes == ()
    assert record.edges == ()
    assert record.shadow["graph.node_count"] == 0
    assert record.shadow["graph.edge_count"] == 0
    assert not any(
        value for key, value in record.shadow.items() if key.startswith(("factor.", "motif."))
    )
    assert not hasattr(record, "features")


def test_multi_family_prompt_is_deterministic_and_catalog_ordered() -> None:
    path = next(
        entry for entry in PROMPT_TSG_CATALOG if entry.factor_type is FactorType.PATH_NORMALIZATION
    )
    sql = next(
        entry
        for entry in PROMPT_TSG_CATALOG
        if entry.factor_type is FactorType.SQL_PARAMETERIZATION
    )
    text = (
        f"{sql.domain_terms[1]}; {path.domain_terms[1]}; "
        f"{sql.guard_terms[1]}; {path.guard_terms[1]}."
    )

    one = extract_prompt_tsg(_prompt(text))
    two = extract_prompt_tsg(_prompt(text))
    graph = record_to_multidigraph(one)

    assert one == two
    assert {label for label, _ in _nodes(graph, NodeType.SINK)} == {
        path.sink_label,
        sql.sink_label,
    }
    assert _guard_targets(graph, path.guard_label) == {path.data_label, path.sink_label}
    assert _guard_targets(graph, sql.guard_label) == {sql.data_label, sql.sink_label}


def test_evidence_uses_first_match_order_and_raw_span_digest() -> None:
    path = next(
        entry for entry in PROMPT_TSG_CATALOG if entry.factor_type is FactorType.PATH_NORMALIZATION
    )
    later = path.domain_terms[0]
    first = path.domain_terms[1].upper()
    text = f"First {first}; later {later}; again {first}."
    graph = record_to_multidigraph(extract_prompt_tsg(_prompt(text)))
    data_attributes = next(
        attributes["attributes"]
        for _, attributes in graph.nodes(data=True)
        if attributes["node_type"] is NodeType.DATA_OBJECT
        and attributes["label"] == path.data_label
    )
    start = text.index(first)
    end = start + len(first)

    assert data_attributes == {
        "evidence_start": start,
        "evidence_end": end,
        "evidence_sha256": hashlib.sha256(first.encode("utf-8")).hexdigest(),
    }


@pytest.mark.parametrize("entry", PROMPT_TSG_CATALOG, ids=lambda entry: entry.factor_type.value)
def test_only_bounded_evidence_commitments_are_persisted(entry: object) -> None:
    sentinel = "RAW_PROMPT_SENTINEL_7b3424"
    record = extract_prompt_tsg(_prompt(f"Please {entry.domain_terms[0]}. {sentinel}"))
    rendered = repr(record) + record.model_dump_json()

    assert sentinel not in rendered
    for node in record.nodes:
        assert set(node.attributes) <= {
            "evidence_start",
            "evidence_end",
            "evidence_sha256",
            "cwe_id",
        }
    for edge in record.edges:
        assert set(edge.attributes) <= {
            "evidence_start",
            "evidence_end",
            "evidence_sha256",
            "mapping_kind",
            "relation_kind",
        }


def test_invalid_prompt_record_error_surfaces_are_sanitized() -> None:
    sentinel = "RAW_PROMPT_SENTINEL_816ca1"
    prompt = _prompt(sentinel)
    object.__setattr__(prompt, "language", ["python", sentinel])

    with pytest.raises(SecAwareError) as exc_info:
        extract_prompt_tsg(prompt)

    _assert_sanitized_error(
        exc_info.value,
        code=ErrorCode.TSG_INVALID,
        sentinel=sentinel,
    )


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    (
        ("prompt_id", b"p001"),
        ("split", b"discover"),
        ("language", b"python"),
        ("task_family", b"reviewed_task"),
        ("cwe", b"CWE-20"),
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


def test_extractor_source_contains_no_decision_assignment() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "secaware" / "extractors" / "prompt_tsg_extractor.py"
    ).read_text(encoding="utf-8")
    lowered = source.casefold()

    for forbidden in ("features =", "motif", "secure", "insecure", "shadow="):
        assert forbidden not in lowered

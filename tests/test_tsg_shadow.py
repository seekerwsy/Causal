from __future__ import annotations

import inspect
import json

import networkx as nx
import pytest

import secaware.tsg.graph as graph_codec
import secaware.tsg.features as shadow_features
import secaware.tsg.motifs as motif_queries
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.hypotheses import FactorType
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId
from secaware.tsg.features import derive_shadow
from secaware.tsg.graph import graph_sha256, multidigraph_to_record, record_to_multidigraph


def _record_coordinates(prompt_id: str = "p") -> dict[str, object]:
    return {
        "prompt_id": prompt_id,
        "task_id": f"task-{prompt_id}",
        "task_family": "path_handling",
        "cwe": "CWE-22",
        "extractor_backend": PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        "extractor_policy_sha256": "8" * 64,
        "proposal_id": "proposal_" + "7" * 64,
    }


def _prompt(text: str) -> PromptRecord:
    return PromptRecord(
        prompt_id="p-shadow",
        task_id="task-p-shadow",
        split="discover",
        language="python",
        task_family="file_access",
        cwe="CWE-22",
        prompt=text,
    )


def _path_prompt() -> PromptRecord:
    return _prompt("Open a user-provided file path.")


def _expected_keys() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *(f"factor.{factor.value}_required" for factor in FactorType),
                *(f"motif.{motif.value}" for motif in MotifId),
                "graph.node_count",
                "graph.edge_count",
            )
        )
    )


def test_shadow_is_derived_and_tampering_is_rejected() -> None:
    record = extract_prompt_tsg(_path_prompt())
    assert record.shadow["motif.user_path_to_file_open_without_guard"] is True
    forged = record.model_copy(
        update={
            "shadow": {
                **record.shadow,
                "motif.user_path_to_file_open_without_guard": False,
            }
        }
    )

    with pytest.raises(SecAwareError) as exc_info:
        record_to_multidigraph(forged)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_shadow_has_complete_finite_sorted_projection_and_graph_counts() -> None:
    record = extract_prompt_tsg(_path_prompt())

    assert tuple(record.shadow) == _expected_keys()
    assert record.shadow["graph.node_count"] == len(record.nodes)
    assert record.shadow["graph.edge_count"] == len(record.edges)
    assert all(
        type(value) is bool
        for key, value in record.shadow.items()
        if key.startswith(("factor.", "motif."))
    )


def test_shadow_key_order_and_record_json_are_deterministic() -> None:
    one = extract_prompt_tsg(_path_prompt())
    two = extract_prompt_tsg(_path_prompt())

    assert one.model_dump_json() == two.model_dump_json()
    payload = json.loads(one.model_dump_json())
    assert tuple(payload["shadow"]) == _expected_keys()


def test_reversed_shadow_key_order_is_rejected() -> None:
    record = extract_prompt_tsg(_path_prompt())
    assert record_to_multidigraph(record).number_of_nodes() == len(record.nodes)
    reversed_shadow = dict(reversed(tuple(record.shadow.items())))
    assert tuple(reversed_shadow) == tuple(reversed(tuple(record.shadow)))
    forged = record.model_copy(update={"shadow": reversed_shadow})

    with pytest.raises(SecAwareError) as exc_info:
        record_to_multidigraph(forged)

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert exc_info.value.__context__ is None
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda shadow: shadow.pop("graph.node_count"),
        lambda shadow: shadow.__setitem__("extra.key", False),
        lambda shadow: shadow.__setitem__("graph.node_count", True),
        lambda shadow: shadow.__setitem__("motif.user_path_to_file_open_without_guard", 1),
    ),
)
def test_forged_missing_extra_or_wrong_type_shadow_is_rejected(mutate) -> None:
    record = extract_prompt_tsg(_path_prompt())
    shadow = dict(record.shadow)
    mutate(shadow)
    forged = record.model_copy(update={"shadow": shadow})

    with pytest.raises(SecAwareError) as exc_info:
        record_to_multidigraph(forged)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_graph_digest_excludes_shadow_projection() -> None:
    record = extract_prompt_tsg(_path_prompt())
    graph = record_to_multidigraph(record)
    original = graph_sha256(graph)
    graph.graph.clear()

    assert graph_sha256(graph) == original == record.graph_sha256
    assert derive_shadow(graph)["motif.user_path_to_file_open_without_guard"] is True


def test_public_record_builder_has_no_caller_authored_shadow_api() -> None:
    assert "shadow" not in inspect.signature(multidigraph_to_record).parameters

    with pytest.raises(TypeError):
        multidigraph_to_record(nx.MultiDiGraph(), **_record_coordinates(), shadow={})  # type: ignore[call-arg]


def test_unexpected_shadow_derivation_failure_is_analysis_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = extract_prompt_tsg(_path_prompt())

    def fail(_graph: nx.MultiDiGraph) -> dict[str, object]:
        raise RuntimeError("SHADOW_INTERNAL_SENTINEL_7319")

    monkeypatch.setattr(graph_codec, "_derive_shadow", fail)
    for invoke in (
        lambda: multidigraph_to_record(nx.MultiDiGraph(), **_record_coordinates()),
        lambda: record_to_multidigraph(record),
    ):
        with pytest.raises(SecAwareError) as exc_info:
            invoke()
        assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
        assert "SHADOW_INTERNAL_SENTINEL_7319" not in str(exc_info.value)


def test_malformed_internal_shadow_projection_is_analysis_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shadow_features, "derive_shadow", lambda _graph: {"bad": object()})

    with pytest.raises(SecAwareError) as exc_info:
        multidigraph_to_record(nx.MultiDiGraph(), **_record_coordinates())

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID


def test_shadow_uses_one_canonical_snapshot_during_live_graph_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = record_to_multidigraph(extract_prompt_tsg(_path_prompt()))
    expected = derive_shadow(graph)
    original = motif_queries._has_factor_requirement
    mutated = False

    def mutate_after_snapshot(snapshot: nx.MultiDiGraph, factor_type: FactorType) -> bool:
        nonlocal mutated
        result = original(snapshot, factor_type)
        if not mutated:
            mutated = True
            source_edge = next(
                (src, dst, key)
                for src, dst, key, attributes in graph.edges(keys=True, data=True)
                if attributes["edge_type"].value == "source_of"
            )
            graph.remove_edge(*source_edge)
        return result

    monkeypatch.setattr(motif_queries, "_has_factor_requirement", mutate_after_snapshot)

    assert derive_shadow(graph) == expected

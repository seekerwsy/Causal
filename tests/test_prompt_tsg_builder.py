from __future__ import annotations

import hashlib
from copy import deepcopy

import networkx as nx
import pytest

import secaware.tsg.builder as builder_module
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import (
    PromptExtractionProposalRecord,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
)
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.queries import feature_state


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _prompt() -> PromptRecord:
    return PromptRecord(
        prompt_id="p-builder",
        task_id="task-builder",
        split="discover",
        language="python",
        task_family="file_access",
        cwe="CWE-22",
        prompt="Read a user-provided file path and normalize the path.",
    )


def _facts_proposal(*, reverse: bool = False) -> PromptExtractionProposalRecord:
    prompt = _prompt()
    present_text = {
        "task.file_read": "user-provided file path",
        "safety.path_normalization": "normalize the path",
    }
    facts = []
    for spec in PROMPT_FEATURE_CATALOG:
        applicable = (not spec.applicable_cwes or prompt.cwe in spec.applicable_cwes) and (
            not spec.applicable_task_families or prompt.task_family in spec.applicable_task_families
        )
        state = (
            FeatureState.PRESENT
            if spec.feature_id in present_text
            else FeatureState.ABSENT
            if applicable
            else FeatureState.NOT_APPLICABLE
        )
        spans = []
        if state is FeatureState.PRESENT:
            text = present_text[spec.feature_id]
            start = prompt.prompt.index(text)
            spans.append(
                {
                    "start": start,
                    "end": start + len(text),
                    "text": text,
                    "text_sha256": _sha(text),
                }
            )
        facts.append(
            {
                "feature_id": spec.feature_id,
                "state": state,
                "semantic_role": "feature_state",
                "evidence": spans,
                "relation_feature_ids": [],
            }
        )
    if reverse:
        facts.reverse()
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_FACTS_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "8" * 64,
        "response_sha256": _sha("facts"),
        "raw_response": "facts",
        "facts": facts,
        "direct_nodes": [],
        "direct_edges": [],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    return PromptExtractionProposalRecord.model_validate(payload)


def test_fact_proposal_builds_canonical_graph_independent_of_fact_order() -> None:
    one = build_prompt_tsg(_facts_proposal(), _prompt())
    two = build_prompt_tsg(_facts_proposal(reverse=True), _prompt())

    assert one.graph_sha256 == two.graph_sha256
    assert one.model_dump_json() == two.model_dump_json()
    assert len(
        [
            node
            for node in one.nodes
            if node.node_type in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}
        ]
    ) == len(PROMPT_FEATURE_CATALOG)
    assert (
        feature_state(record_to_multidigraph(one), "safety.path_normalization")
        is FeatureState.PRESENT
    )
    assert (
        feature_state(record_to_multidigraph(one), "task.database_query")
        is FeatureState.NOT_APPLICABLE
    )


def test_llm_facts_without_relations_do_not_infer_deterministic_legacy_paths() -> None:
    proposal = _facts_proposal()
    assert proposal.backend is PromptExtractorBackend.LLM_FACTS_V1

    graph = record_to_multidigraph(build_prompt_tsg(proposal, _prompt()))
    edge_types = {data["edge_type"] for _, _, data in graph.edges(data=True)}
    labels = {data["label"] for _, data in graph.nodes(data=True)}

    assert feature_state(graph, "task.file_read") is FeatureState.PRESENT
    assert feature_state(graph, "safety.path_normalization") is FeatureState.PRESENT
    assert {
        "task.file_read:task_operation",
        "task.file_read:data_object",
        "task.file_read:sink",
        "safety.path_normalization:prompt_requirement",
        "safety.path_normalization:guard",
    } <= labels
    assert {EdgeType.OPERATES_ON, EdgeType.FLOWS_TO, EdgeType.REQUIRES} <= edge_types
    assert EdgeType.SOURCE_OF not in edge_types
    assert EdgeType.MAPS_TO not in edge_types
    assert EdgeType.GUARDED_BY not in edge_types


def test_fact_relations_materialize_into_canonical_typed_feature_edges() -> None:
    prompt = _prompt()
    baseline = build_prompt_tsg(_facts_proposal(), prompt)
    payload = _facts_proposal().model_dump(mode="python", round_trip=True)
    source = next(item for item in payload["facts"] if item["feature_id"] == "task.file_read")
    source["relation_feature_ids"] = [
        "task.input_consumption",
        "task.database_query",
    ]
    payload["proposal_id"] = proposal_id_for_payload(payload)
    forward = PromptExtractionProposalRecord.model_validate(payload)
    reverse_payload = deepcopy(payload)
    source = next(
        item for item in reverse_payload["facts"] if item["feature_id"] == "task.file_read"
    )
    source["relation_feature_ids"].reverse()
    reverse_payload["proposal_id"] = proposal_id_for_payload(reverse_payload)
    reverse = PromptExtractionProposalRecord.model_validate(reverse_payload)

    one = build_prompt_tsg(forward, prompt)
    two = build_prompt_tsg(reverse, prompt)
    graph = record_to_multidigraph(one)
    related = sorted(
        (
            graph.nodes[src]["label"],
            graph.nodes[dst]["label"],
            data["attributes"],
        )
        for src, dst, data in graph.edges(data=True)
        if data["edge_type"] is EdgeType.RELATED_TO
    )

    assert forward.proposal_id == reverse.proposal_id
    assert one.graph_sha256 == two.graph_sha256
    assert one.nodes == two.nodes
    assert one.edges == two.edges
    assert baseline.graph_sha256 != one.graph_sha256
    assert related == [
        (
            "task.file_read",
            target,
            {
                "evidence_start": prompt.prompt.index("user-provided file path"),
                "evidence_end": prompt.prompt.index("user-provided file path")
                + len("user-provided file path"),
                "evidence_sha256": _sha("user-provided file path"),
                "relation_kind": "feature_state",
            },
        )
        for target in ("task.database_query", "task.input_consumption")
    ]

    one_relation = forward.model_dump(mode="python", round_trip=True)
    source = next(item for item in one_relation["facts"] if item["feature_id"] == "task.file_read")
    source["relation_feature_ids"] = ["task.input_consumption"]
    one_relation["proposal_id"] = proposal_id_for_payload(one_relation)
    changed = build_prompt_tsg(PromptExtractionProposalRecord.model_validate(one_relation), prompt)
    assert changed.graph_sha256 not in {baseline.graph_sha256, one.graph_sha256}


def test_fact_relations_support_presentation_feature_endpoints() -> None:
    prompt = _prompt()
    payload = _facts_proposal().model_dump(mode="python", round_trip=True)
    source = next(
        item for item in payload["facts"] if item["feature_id"] == "presentation.noop_rewrite"
    )
    text = "Read"
    source["state"] = FeatureState.PRESENT
    source["evidence"] = [
        {
            "start": 0,
            "end": len(text),
            "text": text,
            "text_sha256": _sha(text),
        }
    ]
    source["relation_feature_ids"] = ["presentation.sham_edit"]
    payload["proposal_id"] = proposal_id_for_payload(payload)

    graph = record_to_multidigraph(
        build_prompt_tsg(PromptExtractionProposalRecord.model_validate(payload), prompt)
    )
    src, dst, data = next(
        (src, dst, data)
        for src, dst, data in graph.edges(data=True)
        if data["edge_type"] is EdgeType.RELATED_TO
    )

    assert graph.nodes[src]["node_type"] is NodeType.PRESENTATION_FEATURE
    assert graph.nodes[dst]["node_type"] is NodeType.PRESENTATION_FEATURE


def test_built_graph_round_trips_with_exact_provenance() -> None:
    proposal = _facts_proposal()
    record = build_prompt_tsg(proposal, _prompt())
    graph = record_to_multidigraph(record)
    rebuilt = multidigraph_to_record(
        graph,
        prompt_id=record.prompt_id,
        task_id=record.task_id,
        task_family=record.task_family,
        cwe=record.cwe,
        extractor_backend=record.extractor_backend,
        extractor_policy_sha256=record.extractor_policy_sha256,
        proposal_id=record.proposal_id,
    )

    assert rebuilt == record
    assert record.proposal_id == proposal.proposal_id
    assert record.extractor_backend is PromptExtractorBackend.LLM_FACTS_V1


def test_builder_uses_one_prompt_snapshot_across_validation_and_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _prompt()
    proposal = _facts_proposal()
    original = builder_module.validate_proposal

    def validate_then_mutate(proposal_value, snapshot):
        trusted = original(proposal_value, snapshot)
        prompt.task_id = "mutated-after-validation"
        prompt.task_family = "mutated-after-validation"
        return trusted

    monkeypatch.setattr(builder_module, "validate_proposal", validate_then_mutate)

    record = build_prompt_tsg(proposal, prompt)

    assert record.task_id == "task-builder"
    assert record.task_family == "file_access"


def test_direct_proposal_builds_only_catalog_typed_structure_plus_complete_states() -> None:
    prompt = _prompt()
    text = "normalize the path"
    start = prompt.prompt.index(text)
    evidence = [
        {
            "start": start,
            "end": start + len(text),
            "text": text,
            "text_sha256": _sha(text),
        }
    ]
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": prompt.prompt_id,
        "task_id": prompt.task_id,
        "prompt_sha256": _sha(prompt.prompt),
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
        "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "policy_sha256": "9" * 64,
        "response_sha256": _sha("direct"),
        "raw_response": "direct",
        "facts": [],
        "direct_nodes": [
            {
                "local_id": "v2",
                "node_type": NodeType.GUARD,
                "label": "path normalization guard",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
            {
                "local_id": "v1",
                "node_type": NodeType.PROMPT_REQUIREMENT,
                "label": "path normalization requirement",
                "feature_id": "safety.path_normalization",
                "evidence": evidence,
            },
        ],
        "direct_edges": [
            {
                "src_local_id": "v1",
                "dst_local_id": "v2",
                "edge_type": EdgeType.REQUIRES,
                "evidence": evidence,
            }
        ],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    proposal = PromptExtractionProposalRecord.model_validate(payload)
    record = build_prompt_tsg(proposal, prompt)
    graph = record_to_multidigraph(record)

    assert feature_state(graph, "safety.path_normalization") is FeatureState.PRESENT
    assert feature_state(graph, "task.file_read") is FeatureState.ABSENT
    assert any(data["edge_type"] is EdgeType.REQUIRES for _, _, data in graph.edges(data=True))
    assert isinstance(graph, nx.MultiDiGraph)

    aliased = deepcopy(payload)
    alias_map = {"v1": "v9", "v2": "v8"}
    for node in aliased["direct_nodes"]:
        node["local_id"] = alias_map[node["local_id"]]
    for edge in aliased["direct_edges"]:
        edge["src_local_id"] = alias_map[edge["src_local_id"]]
        edge["dst_local_id"] = alias_map[edge["dst_local_id"]]
    aliased["proposal_id"] = proposal_id_for_payload(aliased)
    aliased_record = build_prompt_tsg(
        PromptExtractionProposalRecord.model_validate(aliased), prompt
    )

    assert aliased_record.graph_sha256 == record.graph_sha256

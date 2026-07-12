from __future__ import annotations

import hashlib
import json

import networkx as nx
import pytest
from pydantic import ValidationError

import secaware.discovery.scoring as scoring
from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.discovery.scoring import (
    association_score,
    graph_evidence_summary,
    nuisance_penalty,
    path_score,
    stability_score,
)
from secaware.discovery.tsg_qcd import discover_hypotheses
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.hypotheses import FactorType
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.graph import multidigraph_to_record, record_to_multidigraph
from secaware.tsg.catalog import PROMPT_TSG_CATALOG
from secaware.tsg.motifs import find_motif_matches, has_factor_requirement


PATH_SPEC = FACTOR_SPECS[FactorType.PATH_NORMALIZATION]


def _path_prompt(
    prompt_id: str = "p-path",
    *,
    guarded: bool = False,
    task_family: str = "path_handling",
) -> PromptRecord:
    text = "Open a user-provided file path."
    if guarded:
        text += " Normalize the path."
    return PromptRecord(
        prompt_id=prompt_id,
        split="discover",
        language="python",
        task_family=task_family,
        cwe="CWE-22",
        prompt=text,
    )


def _unrelated_prompt(prompt_id: str = "p-other") -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split="discover",
        language="python",
        task_family="other",
        cwe="CWE-20",
        prompt="Return the number seven.",
    )


def _oracle(prompt_id: str, *, insecure: bool, cwe: str = "CWE-22") -> OracleRecord:
    digest = hashlib.sha256(prompt_id.encode()).hexdigest()
    finding = {
        "schema_version": "1.0",
        "analyzer": "semgrep",
        "rule_id": "reviewed.rule",
        "cwe": cwe,
        "severity": "high",
        "confidence": "not_provided",
        "line": 1,
        "column": 1,
        "end_line": 1,
        "end_column": 2,
        "message": "Reviewed security finding.",
    }
    return OracleRecord.model_validate(
        {
            "schema_version": "1.0",
            "request_id": f"req_{digest}",
            "code_id": f"code_{digest}",
            "code_sha256": "c" * 64,
            "prompt_id": prompt_id,
            "condition": "observed",
            "model_id": "model-a",
            "seed_id": 1,
            "hypothesis_id": None,
            "intervention_id": None,
            "parse_ok": True,
            "functional_ok": True,
            "security_label": "insecure" if insecure else "secure",
            "severity": "high" if insecure else "none",
            "findings": [finding] if insecure else [],
            "analyzers": [
                {
                    "schema_version": "1.0",
                    "analyzer": analyzer,
                    "version": "1.0",
                    "policy_sha256": policy,
                }
                for analyzer, policy in (("semgrep", "a" * 64), ("bandit", "b" * 64))
            ],
        }
    )


def _oracle_by_prompt(*records: OracleRecord) -> dict[str, list[OracleRecord]]:
    result: dict[str, list[OracleRecord]] = {}
    for record in records:
        result.setdefault(record.prompt_id, []).append(record)
    return result


def _counterfactual_oracle(prompt_id: str) -> OracleRecord:
    observed = _oracle(prompt_id, insecure=True)
    return OracleRecord.model_validate(
        {
            **observed.model_dump(mode="python"),
            "condition": "counterfactual",
            "hypothesis_id": "h-counterfactual",
            "intervention_id": "i-counterfactual",
        }
    )


def _remove_edge_and_recanonicalize(record, edge_type: EdgeType):
    graph = record_to_multidigraph(record)
    edge = next(
        (src, dst, key)
        for src, dst, key, attributes in graph.edges(keys=True, data=True)
        if attributes["edge_type"] is edge_type
    )
    graph.remove_edge(*edge)
    return multidigraph_to_record(graph, prompt_id=record.prompt_id)


def _unique_path_motif_record(index: int):
    builder = nx.MultiDiGraph()
    builder.add_node("source", node_type=NodeType.SOURCE, label="user_input", attributes={})
    builder.add_node(
        "data",
        node_type=NodeType.DATA_OBJECT,
        label="user_path",
        attributes={},
    )
    builder.add_node("sink", node_type=NodeType.SINK, label="file_open", attributes={})
    builder.add_node(
        "marker",
        node_type=NodeType.SECURITY_ASSUMPTION,
        label=f"reviewed_marker_{index}",
        attributes={},
    )
    builder.add_edge("source", "data", edge_type=EdgeType.SOURCE_OF, attributes={})
    builder.add_edge("data", "sink", edge_type=EdgeType.FLOWS_TO, attributes={})
    return multidigraph_to_record(builder, prompt_id=f"p-evidence-{index:03}")


def test_path_score_changes_when_graph_changes_even_if_shadow_is_hostile() -> None:
    unsafe = extract_prompt_tsg(_path_prompt())
    changed = _remove_edge_and_recanonicalize(unsafe, EdgeType.FLOWS_TO)
    oracle_map = _oracle_by_prompt(_oracle(unsafe.prompt_id, insecure=True))

    assert path_score(PATH_SPEC, [unsafe], oracle_map) > 0.0
    assert path_score(PATH_SPEC, [changed], oracle_map) == 0.0


def test_tampered_shadow_is_rejected_not_read() -> None:
    unsafe = extract_prompt_tsg(_path_prompt())
    forged = unsafe.model_copy(update={"shadow": {**unsafe.shadow, "graph.node_count": 999}})
    oracle_map = _oracle_by_prompt(_oracle(unsafe.prompt_id, insecure=True))

    with pytest.raises(SecAwareError) as exc_info:
        path_score(PATH_SPEC, [forged], oracle_map)
    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_association_uses_live_factor_requirement_and_exact_oracle_coordinates() -> None:
    absent = extract_prompt_tsg(_path_prompt("p-absent"))
    present = extract_prompt_tsg(_path_prompt("p-present", guarded=True))
    oracle_map = _oracle_by_prompt(
        _oracle("p-absent", insecure=True),
        _oracle("p-present", insecure=False),
        _oracle("p-not-in-graphs", insecure=True),
    )

    score, raw, support = association_score(PATH_SPEC, [present, absent], oracle_map)

    assert score == raw == 1.0
    assert support == {"n_total": 2, "n_present": 1, "n_absent": 1, "n_insecure": 1}


def test_path_formula_uses_exact_absent_denominator_oracle_conditioning_and_cwe_bonus() -> None:
    motif_absent = extract_prompt_tsg(_path_prompt("p-motif"))
    no_motif_absent = extract_prompt_tsg(_unrelated_prompt("p-no-motif"))

    score = path_score(
        PATH_SPEC,
        [no_motif_absent, motif_absent],
        _oracle_by_prompt(_oracle("p-motif", insecure=True, cwe="CWE-22")),
    )

    assert score == 0.6
    assert (
        path_score(
            PATH_SPEC,
            [no_motif_absent, motif_absent],
            _oracle_by_prompt(_oracle("p-motif", insecure=True, cwe="CWE-89")),
        )
        == 0.5
    )


def test_path_formula_handles_empty_absent_no_motif_missing_oracle_and_cap() -> None:
    present = extract_prompt_tsg(_path_prompt("p-present", guarded=True))
    motif = extract_prompt_tsg(_path_prompt("p-motif"))
    no_motif = extract_prompt_tsg(_unrelated_prompt("p-other"))

    assert path_score(PATH_SPEC, [present], {}) == 0.0
    assert path_score(PATH_SPEC, [no_motif], {}) == 0.0
    assert path_score(PATH_SPEC, [motif], {}) == 0.0
    assert (
        path_score(
            PATH_SPEC,
            [motif],
            _oracle_by_prompt(_oracle("p-motif", insecure=True, cwe="CWE-22")),
        )
        == 1.0
    )


def test_path_formula_is_zero_when_absent_denominator_is_empty_even_with_cwe_evidence() -> None:
    builder = nx.MultiDiGraph()
    builder.add_node("source", node_type=NodeType.SOURCE, label="user_input", attributes={})
    builder.add_node(
        "data",
        node_type=NodeType.DATA_OBJECT,
        label="user_path",
        attributes={},
    )
    builder.add_node("sink", node_type=NodeType.SINK, label="file_open", attributes={})
    builder.add_node(
        "requirement",
        node_type=NodeType.PROMPT_REQUIREMENT,
        label=PATH_SPEC.requirement_label,
        attributes={},
    )
    builder.add_node(
        "disconnected_guard",
        node_type=NodeType.GUARD,
        label=PATH_SPEC.guard_label,
        attributes={},
    )
    builder.add_edge("source", "data", edge_type=EdgeType.SOURCE_OF, attributes={})
    builder.add_edge("data", "sink", edge_type=EdgeType.FLOWS_TO, attributes={})
    builder.add_edge(
        "requirement",
        "disconnected_guard",
        edge_type=EdgeType.REQUIRES,
        attributes={},
    )
    present_but_unguarded = multidigraph_to_record(builder, prompt_id="p-present-motif")
    graph = record_to_multidigraph(present_but_unguarded)
    assert has_factor_requirement(graph, PATH_SPEC.factor_type) is True
    assert find_motif_matches(graph, PATH_SPEC.motif_id)

    score = path_score(
        PATH_SPEC,
        [present_but_unguarded],
        _oracle_by_prompt(_oracle("p-present-motif", insecure=True, cwe="CWE-22")),
    )

    assert score == 0.0


def test_path_oracle_join_is_by_exact_prompt_id_and_does_not_invent_labels() -> None:
    motif = extract_prompt_tsg(_path_prompt("p-motif"))
    wrong = _oracle("p-similar-but-wrong", insecure=True, cwe="CWE-22")
    secure = _oracle("p-motif", insecure=False)

    assert path_score(PATH_SPEC, [motif], _oracle_by_prompt(wrong)) == 0.0
    assert path_score(PATH_SPEC, [motif], _oracle_by_prompt(secure, wrong)) == 0.0


@pytest.mark.parametrize("score", (association_score, path_score))
def test_scoring_revalidates_forged_oracle_records(score) -> None:
    motif = extract_prompt_tsg(_path_prompt("p-motif"))
    insecure = _oracle("p-motif", insecure=True)
    forged = insecure.model_copy(update={"security_label": SecurityLabel.SECURE})

    with pytest.raises(ValidationError):
        score(PATH_SPEC, [motif], {"p-motif": [forged]})


@pytest.mark.parametrize("score", (association_score, path_score))
def test_scoring_rejects_structurally_valid_counterfactual_oracles(score) -> None:
    motif = extract_prompt_tsg(_path_prompt("p-counterfactual"))
    counterfactual = _counterfactual_oracle("p-counterfactual")

    with pytest.raises(SecAwareError) as exc_info:
        score(PATH_SPEC, [motif], _oracle_by_prompt(counterfactual))

    assert exc_info.value.code is ErrorCode.ANALYSIS_INVALID
    assert exc_info.value.details == {}
    assert exc_info.value.__cause__ is None
    retained = []
    frame = exc_info.value.__traceback__
    while frame is not None:
        if "/src/secaware/" in frame.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(frame.tb_frame.f_locals))
        frame = frame.tb_next
    rendered = "\n".join(retained)
    assert "p-counterfactual" not in rendered
    assert "OracleRecord" not in rendered


def test_nuisance_penalty_uses_live_factor_queries() -> None:
    absent_prompt = _path_prompt("p-a")
    present_prompt = _path_prompt("p-b", guarded=True)
    absent = extract_prompt_tsg(absent_prompt)
    present = extract_prompt_tsg(present_prompt)
    changed = _remove_edge_and_recanonicalize(present, EdgeType.REQUIRES)

    live = nuisance_penalty(
        PATH_SPEC,
        [absent_prompt, present_prompt],
        {"p-a": absent, "p-b": present},
    )
    changed_score = nuisance_penalty(
        PATH_SPEC,
        [absent_prompt, present_prompt],
        {"p-a": absent, "p-b": changed},
    )

    assert live > changed_score == 0.0


def test_stability_score_uses_live_factor_queries() -> None:
    prompts = [
        _path_prompt("p-a-absent", task_family="family-a"),
        _path_prompt("p-a-present", guarded=True, task_family="family-a"),
        _path_prompt("p-b-absent", task_family="family-b"),
        _path_prompt("p-b-present", guarded=True, task_family="family-b"),
    ]
    records = {prompt.prompt_id: extract_prompt_tsg(prompt) for prompt in prompts}
    oracle_map = _oracle_by_prompt(
        *(_oracle(prompt.prompt_id, insecure="absent" in prompt.prompt_id) for prompt in prompts)
    )

    assert stability_score(PATH_SPEC, prompts, records, oracle_map) == 1.0
    changed = {
        prompt_id: (
            _remove_edge_and_recanonicalize(record, EdgeType.REQUIRES)
            if "present" in prompt_id
            else record
        )
        for prompt_id, record in records.items()
    }
    assert stability_score(PATH_SPEC, prompts, changed, oracle_map) == 0.0


def test_internal_graph_query_errors_are_not_mislabeled_as_tsg_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = extract_prompt_tsg(_path_prompt())

    def fail(*_args):
        raise RuntimeError("query failed")

    monkeypatch.setattr(scoring, "has_factor_requirement", fail)
    with pytest.raises(RuntimeError, match="query failed"):
        association_score(PATH_SPEC, [record], {})


def test_graph_evidence_is_fixed_bounded_with_exact_aggregates_and_commitment() -> None:
    records = [_unique_path_motif_record(index) for index in range(67)]
    complete_digests = sorted({record.graph_sha256 for record in records})
    expected_commitment = hashlib.sha256(
        json.dumps(
            complete_digests,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    summary = graph_evidence_summary(PATH_SPEC, list(reversed(records)))
    repeated = graph_evidence_summary(PATH_SPEC, records)

    assert summary == repeated
    assert summary["graph_count"] == 67
    assert summary["distinct_graph_digest_count"] == 67
    assert summary["motif_prompt_count"] == 67
    assert summary["motif_match_count"] == 67
    assert summary["graph_digest_commitment_sha256"] == expected_commitment
    assert summary["graph_sha256"] == complete_digests[:64]
    assert len(summary["graph_sha256"]) <= 64
    assert summary["graph_digests_truncated"] is True
    assert len(summary["motif_evidence"]) == 64
    assert summary["motif_evidence_truncated"] is True


def test_motif_evidence_contains_only_bounded_deterministic_graph_and_path_ids() -> None:
    record = _unique_path_motif_record(1)
    match = find_motif_matches(record_to_multidigraph(record), PATH_SPEC.motif_id)[0]

    summary = graph_evidence_summary(PATH_SPEC, [record])

    assert summary["motif_evidence"] == [
        {
            "graph_sha256": record.graph_sha256,
            "node_path": list(match.node_path),
            "edge_path": list(match.edge_path),
        }
    ]
    rendered = json.dumps(summary, sort_keys=True)
    assert "reviewed_marker_1" not in rendered
    assert "Open a user-provided file path." not in rendered
    assert "Reviewed security finding." not in rendered


def test_discovery_decodes_each_prompt_graph_exactly_once_for_all_six_factors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain_text = ". ".join(entry.domain_terms[0] for entry in PROMPT_TSG_CATALOG)
    guard_text = ". ".join(entry.guard_terms[0] for entry in PROMPT_TSG_CATALOG)
    prompts = [
        PromptRecord(
            prompt_id=f"p-cache-{index:02}",
            split="discover",
            language="python",
            task_family="all_factors",
            cwe="CWE-999",
            prompt=domain_text if index < 6 else f"{domain_text}. {guard_text}",
        )
        for index in range(12)
    ]
    records = [extract_prompt_tsg(prompt) for prompt in prompts]
    oracles = [
        _oracle(prompt.prompt_id, insecure=index < 6) for index, prompt in enumerate(prompts)
    ]
    baseline, baseline_selected = discover_hypotheses(
        prompts,
        records,
        oracles,
        min_support_total=12,
    )
    calls = 0
    original = scoring.record_to_multidigraph

    def counted(record):
        nonlocal calls
        calls += 1
        return original(record)

    monkeypatch.setattr(scoring, "record_to_multidigraph", counted)
    actual, actual_selected = discover_hypotheses(
        list(reversed(prompts)),
        list(reversed(records)),
        list(reversed(oracles)),
        min_support_total=12,
    )

    assert len(actual) == 6
    assert [item.model_dump() for item in actual] == [item.model_dump() for item in baseline]
    assert [item.hypothesis_id for item in actual_selected] == [
        item.hypothesis_id for item in baseline_selected
    ]
    assert calls == len(records)

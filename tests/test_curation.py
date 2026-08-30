from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.curation import (
    CurationError,
    _parse_contracts,
    _parse_contract_reviews,
    _parse_semantic,
    assemble_semantic_clusters,
    repair_response_format_contract_leaks,
    run_contract_curation,
    run_contract_quality_review,
)
from prompt_mechanism_study.records import content_id


pytestmark = pytest.mark.extended


@pytest.mark.reviewer
def test_llm_positive_edges_are_diagnostic_and_do_not_merge_clusters(tmp_path: Path) -> None:
    prepared = tmp_path / "prepared"
    records = [
        {
            "record_id": name,
            "language": "python",
            "cwe": "CWE-1",
            "source_lineage_family": "independent",
            "source_item_id": name,
            "source_test_references": [],
        }
        for name in ("a", "b", "c")
    ]
    write_bundle(
        prepared,
        {
            "records.json": records,
            "provisional-clusters.json": [
                {"record_ids": [record["record_id"]]} for record in records
            ],
        },
    )
    candidates = tmp_path / "candidates"
    pairs = [
        {
            "pair_id": "ab",
            "left_record_id": "a",
            "right_record_id": "b",
            "lexical_jaccard": 0.9,
        },
        {
            "pair_id": "bc",
            "left_record_id": "b",
            "right_record_id": "c",
            "lexical_jaccard": 0.8,
        },
        {
            "pair_id": "ac",
            "left_record_id": "a",
            "right_record_id": "c",
            "lexical_jaccard": 0.7,
        },
    ]
    write_bundle(candidates, {"dedup-candidates.json": pairs})
    adjudication = tmp_path / "adjudication"
    plan = {
        "prepared_bundle_sha256": bundle_digest(prepared),
        "candidates_bundle_sha256": bundle_digest(candidates),
        "candidate_pair_count": 3,
        "batch_ids": [["ab", "bc", "ac"]],
    }
    write_bundle(adjudication / "plan", {"plan.json": plan})
    write_bundle(
        adjudication / "batches/batch-0001",
        {
            "request.json": {},
            "response.json": {},
            "result.json": {
                "status": "COMPLETE",
                "items": [
                    {"pair_id": "ab", "label": "same_cluster", "reason": "same"},
                    {"pair_id": "bc", "label": "same_cluster", "reason": "same"},
                    {"pair_id": "ac", "label": "different_task", "reason": "different"},
                ],
            },
        },
    )

    output = tmp_path / "clusters"
    report = assemble_semantic_clusters(prepared, candidates, adjudication, output)

    assert report["llm_merge_edge_count"] == 0
    assert report["diagnostic_positive_edge_count"] == 2
    assert sorted(
        len(item["record_ids"]) for item in read_json(output / "semantic-clusters.json")
    ) == [1, 1, 1]
    assert all(
        not item["applied_to_cluster"]
        for item in read_json(output / "diagnostic-semantic-edges.json")
    )


@pytest.mark.reviewer
def test_exact_prompt_and_frozen_lineage_are_the_only_merge_authorities(
    tmp_path: Path,
) -> None:
    prepared = tmp_path / "prepared"
    records = [
        {
            "record_id": name,
            "language": "python",
            "cwe": "CWE-1",
            "source_lineage_family": "independent",
            "source_item_id": name,
            "source_test_references": [],
        }
        for name in ("a", "b")
    ] + [
        {
            "record_id": "c",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "SecEvalBase:shared.py",
            "source_test_references": [],
        },
        {
            "record_id": "d",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "shared.py",
            "source_test_references": [],
        },
        {
            "record_id": "e",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "SecEvalBase:shared.py",
            "source_test_references": [],
        },
    ]
    write_bundle(
        prepared,
        {
            "records.json": records,
            "provisional-clusters.json": [
                {"record_ids": ["a", "b"]},
                {"record_ids": ["c"]},
                {"record_ids": ["d"]},
                {"record_ids": ["e"]},
            ],
        },
    )
    candidates = tmp_path / "candidates"
    write_bundle(candidates, {"dedup-candidates.json": []})
    adjudication = tmp_path / "adjudication"
    write_bundle(
        adjudication / "plan",
        {
            "plan.json": {
                "prepared_bundle_sha256": bundle_digest(prepared),
                "candidates_bundle_sha256": bundle_digest(candidates),
                "candidate_pair_count": 0,
                "batch_ids": [],
            }
        },
    )
    (adjudication / "batches").mkdir()

    output = tmp_path / "clusters"
    report = assemble_semantic_clusters(prepared, candidates, adjudication, output)

    assert report["cluster_assembly_rule"] == "exact_prompt_and_frozen_lineage_only_v1"
    assert report["merge_edge_count"] == 3
    assert sorted(
        len(item["record_ids"]) for item in read_json(output / "semantic-clusters.json")
    ) == [2, 3]


def test_contract_curation_reuses_matching_representatives_and_extracts_only_missing(
    tmp_path: Path,
) -> None:
    prepared = tmp_path / "prepared"
    records = [
        {
            "record_id": "a",
            "prompt": "Return A.",
            "prompt_sha256": "a" * 64,
            "language": "python",
        },
        {
            "record_id": "b",
            "prompt": "Return B.",
            "prompt_sha256": "b" * 64,
            "language": "python",
        },
    ]
    write_bundle(prepared, {"records.json": records})
    clusters = tmp_path / "clusters"
    write_bundle(
        clusters,
        {
            "semantic-clusters.json": [
                {"cluster_id": "new-a", "representative_record_id": "a"},
                {"cluster_id": "new-b", "representative_record_id": "b"},
            ]
        },
    )
    old_contract = {
        "cluster_id": "old-a",
        "entrypoint": None,
        "environment_dependencies": [],
        "inputs": [],
        "outputs": ["A"],
        "reason": "Explicit behavior.",
        "record_id": "a",
        "requirements": ["Return A."],
        "resolution_status": "resolved",
        "side_effects": [],
        "source_prompt_sha256": "a" * 64,
    }
    old_contract["contract_id"] = content_id("cluster_contract_", old_contract)
    existing = tmp_path / "existing-contracts"
    write_bundle(
        existing,
        {
            "functional-contracts.json": [old_contract],
            "report.json": {
                "status": "FUNCTIONAL_CONTRACTS_FROZEN",
                "contract_count": 1,
            },
        },
    )
    requests: list[dict[str, object]] = []

    def provider(request: dict, _config: object, _prompt: str) -> bytes:
        requests.append(request)
        assert [item["source_prompt"] for item in request["tasks"]] == ["Return B."]
        return json.dumps(
            {
                "contracts": [
                    {
                        "item_index": 1,
                        "resolution_status": "resolved",
                        "entrypoint": None,
                        "requirements": ["Return B."],
                        "inputs": [],
                        "outputs": ["B"],
                        "side_effects": [],
                        "environment_dependencies": [],
                        "reason": "Explicit behavior.",
                    }
                ]
            }
        ).encode()

    report = run_contract_curation(
        Path(__file__).parents[1],
        prepared,
        clusters,
        tmp_path / "contract-run",
        existing_contracts_root=existing,
        provider=provider,
    )

    assert len(requests) == 1
    assert report["contract_count"] == 2
    assert report["reused_contract_count"] == 1
    assert report["newly_extracted_contract_count"] == 1
    frozen = read_json(tmp_path / "contract-run/final/functional-contracts.json")
    assert {item["cluster_id"] for item in frozen} == {"new-a", "new-b"}


def test_contract_parser_accepts_a_bound_language_and_nine_requirements() -> None:
    contract = {
        "item_index": 1,
        "resolution_status": "resolved",
        "entrypoint": "run",
        "requirements": [f"requirement {index}" for index in range(9)],
        "inputs": [],
        "outputs": [],
        "side_effects": [],
        "environment_dependencies": [],
        "reason": "Explicit task behavior.",
        "language": "python",
    }

    result = _parse_contracts(
        json.dumps({"contracts": [contract]}).encode(),
        [{"record_id": "record", "source_prompt_sha256": "sha", "language": "python"}],
    )

    assert result[0]["requirements"] == contract["requirements"]
    assert "language" not in result[0]


def test_contract_quality_review_freezes_only_faithful_sufficient_contracts(
    tmp_path: Path,
) -> None:
    records = [
        {
            "record_id": "record-a",
            "prompt": "Return A.",
            "prompt_sha256": "a" * 64,
            "language": "python",
        },
        {
            "record_id": "record-b",
            "prompt": "Return B.",
            "prompt_sha256": "b" * 64,
            "language": "python",
        },
    ]
    contracts = []
    for suffix in ("a", "b"):
        core = {
            "cluster_id": f"cluster-{suffix}",
            "entrypoint": None,
            "environment_dependencies": [],
            "inputs": [],
            "outputs": [suffix.upper()],
            "reason": "Explicit behavior.",
            "record_id": f"record-{suffix}",
            "requirements": [f"Return {suffix.upper()}."],
            "resolution_status": "resolved",
            "side_effects": [],
            "source_prompt_sha256": suffix * 64,
        }
        contracts.append({**core, "contract_id": content_id("cluster_contract_", core)})
    prepared = tmp_path / "prepared"
    contract_root = tmp_path / "contracts"
    write_bundle(prepared, {"records.json": records})
    write_bundle(contract_root, {"functional-contracts.json": contracts})

    def provider(request: dict, _config: object, _prompt: str) -> bytes:
        assert request["cwe_arm_or_outcomes_included"] is False
        return json.dumps(
            {
                "reviews": [
                    {
                        "item_index": 1,
                        "contract_status": "faithful",
                        "functional_evaluability": "sufficient",
                        "issue_codes": ["none"],
                        "reason": "The required return is exact.",
                    },
                    {
                        "item_index": 2,
                        "contract_status": "faulty",
                        "functional_evaluability": "sufficient",
                        "issue_codes": ["output_mismatch"],
                        "reason": "The proposed output is not supported.",
                    },
                ]
            }
        ).encode()

    output = tmp_path / "review"
    report = run_contract_quality_review(
        Path(__file__).parents[1],
        prepared,
        contract_root,
        output,
        provider=provider,
    )

    assert report["review_count"] == 2
    assert report["reviewer_qualified_count"] == 1
    assert report["semantic_quality_established"] is False
    passed = read_json(output / "final/reviewer-qualified-contracts.json")
    assert [item["cluster_id"] for item in passed] == ["cluster-a"]


def test_contract_review_parser_rejects_faithful_rows_with_issue_codes() -> None:
    raw = json.dumps(
        {
            "reviews": [
                {
                    "item_index": 1,
                    "contract_status": "faithful",
                    "functional_evaluability": "sufficient",
                    "issue_codes": ["other"],
                    "reason": "Contradictory coding.",
                }
            ]
        }
    ).encode()
    with pytest.raises(CurationError):
        _parse_contract_reviews(raw, [{"cluster_id": "cluster-a"}])


def test_response_format_leak_repair_preserves_task_and_rekeys_contract(
    tmp_path: Path,
) -> None:
    core = {
        "cluster_id": "cluster-a",
        "entrypoint": "solve",
        "environment_dependencies": [],
        "inputs": ["value"],
        "outputs": ["result"],
        "reason": "Explicit behavior.",
        "record_id": "record-a",
        "requirements": [
            "Return the transformed value.",
            "Output only the code without preamble or suffix.",
        ],
        "resolution_status": "resolved",
        "side_effects": [],
        "source_prompt_sha256": "a" * 64,
    }
    original = {**core, "contract_id": content_id("cluster_contract_", core)}
    contracts = tmp_path / "contracts"
    write_bundle(contracts, {"functional-contracts.json": [original]})

    output = tmp_path / "corrected"
    report = repair_response_format_contract_leaks(contracts, output)

    corrected = read_json(output / "functional-contracts.json")
    assert report["repaired_contract_count"] == 1
    assert report["semantic_quality_established"] is False
    assert corrected[0]["cluster_id"] == original["cluster_id"]
    assert corrected[0]["contract_id"] != original["contract_id"]
    assert corrected[0]["requirements"] == ["Return the transformed value."]
    assert read_json(output / "repairs.json")[0]["old_contract_id"] == original[
        "contract_id"
    ]
    assert read_json(contracts / "functional-contracts.json") == [original]


def test_semantic_parser_collapses_only_identical_duplicate_json_keys() -> None:
    batch = [{"pair_id": "pair-a"}]
    accepted = (
        b'{"decisions":[{"item_index":1,"label":"different_task",'
        b'"label":"different_task","reason":"distinct contracts"}]}'
    )
    assert _parse_semantic(accepted, batch)[0]["label"] == "different_task"

    conflicting = (
        b'{"decisions":[{"item_index":1,"label":"different_task",'
        b'"label":"same_cluster","reason":"ambiguous"}]}'
    )
    with pytest.raises(CurationError):
        _parse_semantic(conflicting, batch)

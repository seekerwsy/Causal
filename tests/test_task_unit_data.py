import json

import pytest

from prompt_mechanism_study.artifact_io import write_bundle
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.task_unit_data import (
    compile_task_unit_data,
    verify_task_unit_data,
)


def _record(record_id, prompt, dataset, item, *, tests=()):
    return {
        "citation_url": "https://example.test/source",
        "cwe": "CWE-89",
        "language": "python",
        "license_id": "test-only",
        "prompt": prompt,
        "prompt_sha256": content_hash(prompt),
        "record_id": record_id,
        "source_dataset": dataset,
        "source_file_sha256": "1" * 64,
        "source_item_id": item,
        "source_lineage_family": "shared-lineage" if item in {"one", "copy"} else "other",
        "source_locator": f"source.json#{item}",
        "source_record_sha256": "2" * 64,
        "source_test_references": list(tests),
        "source_version": "v1",
    }


def _contract(task_id, representative, prompt, *, faithful=True):
    core = {
        "cluster_id": task_id,
        "record_id": representative,
        "source_prompt_sha256": content_hash(prompt),
        "resolution_status": "resolved",
        "entrypoint": "main",
        "requirements": [f"Implement {prompt}."],
        "inputs": [],
        "outputs": ["result"],
        "side_effects": [],
        "environment_dependencies": [],
        "reason": "Source-only extraction.",
    }
    return {**core, "contract_id": content_id("cluster_contract_", core)}


def _review(contract, *, faithful=True):
    return {
        "cluster_id": contract["cluster_id"],
        "contract_id": contract["contract_id"],
        "record_id": contract["record_id"],
        "contract_status": "faithful" if faithful else "faulty",
        "functional_evaluability": "sufficient",
        "issue_codes": ["none"] if faithful else ["missing_explicit_requirement"],
        "deterministic_issue_codes": [],
        "reason": "Blind source-contract comparison.",
    }


def _ledger(task_id, representative, contract_id, status, candidate_status):
    return {
        "arms_or_outcomes_used": False,
        "blocker_codes": [] if status == "INCLUDED_FINAL_DATASET" else ["pending_contract"],
        "candidate_status": candidate_status,
        "contract_id": contract_id,
        "contract_quality": "STRICT" if status == "INCLUDED_FINAL_DATASET" else "REPAIRABLE",
        "final_dataset_status": status,
        "functional_evaluability": "sufficient",
        "functional_measurement": "AST_COMPILE_AND_BLIND_LLM_PLAUSIBILITY",
        "language": "python",
        "study_layer": "python_confirmatory",
        "primary_cwe": "CWE-89",
        "mechanism_binding_status": "BOUND",
        "mechanism_realization_id": "python.cwe89.test.v1",
        "oracle_profile_id": "python.cwe89.test.v1",
        "oracle_support_status": "SUPPORTED",
        "runtime_support_status": "SUPPORTED",
        "source_dataset": "test",
        "source_lineage_family": "shared-lineage" if task_id == "task-a" else "other",
        "source_test_available": False,
        "representative_record_id": representative,
        "review_contract_status": "faithful" if status == "INCLUDED_FINAL_DATASET" else "faulty",
        "task_unit_id": task_id,
    }


@pytest.mark.reviewer
def test_task_unit_compiler_keeps_tasks_quality_roles_and_tsg_separate(tmp_path):
    records = [
        _record("record-a", "prompt A", "source-a", "one", tests=("tests/a.py",)),
        _record("record-b", "prompt A", "source-b", "copy"),
        _record("record-c", "prompt C", "source-c", "three"),
        _record("record-d", "prompt D", "source-c", "four"),
    ]
    prepared = write_bundle(tmp_path / "prepared", {"records.json": records})
    clusters = [
        {
            "cluster_id": "task-a",
            "cwe_label_conflict": False,
            "cwes": ["CWE-89"],
            "language": "python",
            "record_ids": ["record-a", "record-b"],
            "representative_record_id": "record-a",
        },
        {
            "cluster_id": "task-c",
            "cwe_label_conflict": False,
            "cwes": ["CWE-89"],
            "language": "python",
            "record_ids": ["record-c"],
            "representative_record_id": "record-c",
        },
        {
            "cluster_id": "task-d",
            "cwe_label_conflict": False,
            "cwes": ["CWE-89"],
            "language": "python",
            "record_ids": ["record-d"],
            "representative_record_id": "record-d",
        },
    ]
    diagnostic = [
        {
            "label": "uncertain",
            "left": "record-c",
            "right": "record-d",
        }
    ]
    cluster_root = write_bundle(
        tmp_path / "clusters",
        {
            "semantic-clusters.json": clusters,
            "diagnostic-semantic-edges.json": diagnostic,
        },
    )
    contracts = [
        _contract("task-a", "record-a", "prompt A"),
        _contract("task-c", "record-c", "prompt C", faithful=False),
        _contract("task-d", "record-d", "prompt D"),
    ]
    contract_root = write_bundle(
        tmp_path / "contracts",
        {
            "functional-contracts.json": contracts,
            "repairs.json": [],
            "review-overrides.json": [],
        },
    )
    review_root = write_bundle(
        tmp_path / "reviews",
        {
            "contract-quality-reviews.json": [
                _review(contracts[0]),
                _review(contracts[1], faithful=False),
                _review(contracts[2]),
            ]
        },
    )
    ledger = [
        _ledger(
            "task-a",
            "record-a",
            contracts[0]["contract_id"],
            "INCLUDED_FINAL_DATASET",
            "READY_CONFIRMATORY",
        ),
        _ledger(
            "task-c",
            "record-c",
            contracts[1]["contract_id"],
            "PENDING_QUALITY_REPAIR",
            "PENDING_CONTRACT",
        ),
        _ledger(
            "task-d",
            "record-d",
            contracts[2]["contract_id"],
            "INCLUDED_FINAL_DATASET",
            "READY_CONFIRMATORY",
        ),
    ]
    candidate = write_bundle(tmp_path / "candidate", {"candidate-ledger.json": ledger})
    legacy = write_bundle(
        tmp_path / "legacy",
        {
            "role-manifest.json": {
                "artifact_kind": "legacy_data_role_manifest",
                "data_role": "LEGACY_ONLY",
                "formal_use_authorized": False,
                "bindings": [
                    {
                        "data_id": "legacy-d",
                        "data_role": "LEGACY_ONLY",
                        "exposure_history_applies_to_all_task_units": ["old-development"],
                        "task_unit_source_lineage": {"task-d": "other"},
                    }
                ],
            }
        },
    )
    exclusions = tmp_path / "development.json"
    exclusions.write_text(
        json.dumps(
            {
                "arms_or_outcomes_used": False,
                "task_unit_ids": ["task-c"],
            }
        ),
        encoding="utf-8",
    )
    pair_group = content_id("near_duplicate_group_", ("task-c", "task-d"))
    singleton_group = content_id("near_duplicate_group_", ("task-a",))
    output = tmp_path / "compiled"
    result = compile_task_unit_data(
        prepared_root=prepared,
        clusters_root=cluster_root,
        candidate_root=candidate,
        contracts_root=contract_root,
        contract_reviews_root=review_root,
        legacy_roles_root=legacy,
        development_exclusions_path=exclusions,
        output=output,
    )

    assert result["task_units"] == 3
    assert result["source_records"] == 4
    assert result["functional_contracts"] == 3
    assert result["quality_disposition_counts"] == {
        "QUALITY_INCLUDED": 2,
        "QUALITY_PENDING_CONTRACT_REPAIR": 1,
    }
    assert result["data_role_counts"] == {
        "LEGACY_ONLY": 1,
        "QUAL_DEV": 1,
        "UNASSIGNED": 1,
    }
    assert result["readiness_workstream_counts"] == {
        "CONTRACT_REPAIR": 1,
        "TECHNICALLY_READY": 2,
    }
    assert result["prompt_tsg_status"] == "NOT_GENERATED_PENDING_METHOD_FREEZE"
    assert verify_task_unit_data(output) == result

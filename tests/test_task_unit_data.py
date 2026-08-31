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


def _ledger(task_id, representative, status, candidate_status):
    return {
        "arms_or_outcomes_used": False,
        "blocker_codes": [] if status == "INCLUDED_FINAL_DATASET" else ["pending_contract"],
        "candidate_status": candidate_status,
        "contract_id": f"contract-{task_id}",
        "contract_quality": "STRICT" if status == "INCLUDED_FINAL_DATASET" else "REPAIRABLE",
        "final_dataset_status": status,
        "functional_evaluability": "sufficient",
        "language": "python",
        "primary_cwe": "CWE-89",
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
    ledger = [
        _ledger("task-a", "record-a", "INCLUDED_FINAL_DATASET", "READY_CONFIRMATORY"),
        _ledger("task-c", "record-c", "PENDING_QUALITY_REPAIR", "PENDING_CONTRACT"),
        _ledger("task-d", "record-d", "INCLUDED_FINAL_DATASET", "READY_CONFIRMATORY"),
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
    census = write_bundle(
        tmp_path / "census",
        {
            "task-units.json": [
                {
                    "task_unit_id": "task-a",
                    "near_duplicate_group_id": singleton_group,
                },
                {
                    "task_unit_id": "task-d",
                    "near_duplicate_group_id": pair_group,
                },
            ],
            "report.json": {"prospective_unexposed_task_units": 1},
        },
    )

    output = tmp_path / "compiled"
    result = compile_task_unit_data(
        prepared_root=prepared,
        clusters_root=cluster_root,
        candidate_root=candidate,
        legacy_roles_root=legacy,
        development_exclusions_path=exclusions,
        role_census_root=census,
        output=output,
    )

    assert result["task_units"] == 3
    assert result["source_records"] == 4
    assert result["quality_status_counts"] == {
        "PASS": 2,
        "PENDING_QUALITY_REPAIR": 1,
    }
    assert result["data_role_counts"] == {
        "LEGACY_ONLY": 1,
        "QUAL_DEV": 1,
        "UNASSIGNED": 1,
    }
    assert result["prompt_tsg_status"] == "NOT_GENERATED_PENDING_METHOD_FREEZE"
    assert verify_task_unit_data(output) == result

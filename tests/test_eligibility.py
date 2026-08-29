from __future__ import annotations

from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.eligibility import audit_dataset_eligibility


pytestmark = pytest.mark.reviewer


def test_eligibility_separates_ready_calibration_and_out_of_scope_clusters(
    tmp_path: Path,
) -> None:
    specifications = [
        ("ready", "python", "CWE-78", ["CWE-78"], False),
        ("unregistered", "python", "CWE-79", ["CWE-79"], False),
        ("conflict", "python", "CWE-78", ["CWE-78", "CWE-94"], True),
        ("replication", "c", "CWE-119", ["CWE-119"], False),
        ("outside", "javascript", "CWE-79", ["CWE-79"], False),
    ]
    records = []
    clusters = []
    contracts = []
    for name, language, cwe, cwes, conflict in specifications:
        record_id = f"record-{name}"
        cluster_id = f"cluster-{name}"
        records.append(
            {
                "record_id": record_id,
                "source_dataset": "fixture",
                "source_lineage_family": "fixture",
                "source_test_references": ["test.py"] if name == "ready" else [],
                "language": language,
                "cwe": cwe,
                "prompt": "Execute a command supplied by the caller.",
            }
        )
        clusters.append(
            {
                "cluster_id": cluster_id,
                "record_ids": [record_id],
                "representative_record_id": record_id,
                "language": language,
                "cwes": cwes,
                "cwe_label_conflict": conflict,
            }
        )
        contracts.append(
            {
                "cluster_id": cluster_id,
                "contract_id": f"contract-{name}",
                "resolution_status": "resolved",
                "requirements": ["Perform the requested operation."],
                "entrypoint": None,
            }
        )

    prepared = tmp_path / "prepared"
    cluster_root = tmp_path / "clusters"
    contract_root = tmp_path / "contracts"
    write_bundle(prepared, {"records.json": records})
    write_bundle(cluster_root, {"semantic-clusters.json": clusters})
    write_bundle(contract_root, {"functional-contracts.json": contracts})

    output = tmp_path / "eligibility"
    report = audit_dataset_eligibility(Path.cwd(), prepared, cluster_root, contract_root, output)
    decisions = {row["cluster_id"]: row for row in read_json(output / "eligibility-decisions.json")}

    assert report["status_counts"] == {"calibration_only": 3, "eligible": 1, "excluded": 1}
    assert decisions["cluster-ready"]["status"] == "eligible"
    assert decisions["cluster-ready"]["source_test_available"] is True
    assert decisions["cluster-unregistered"]["reason"] == "mechanism_not_registered"
    assert decisions["cluster-conflict"]["reason"] == "cwe_label_conflict"
    assert decisions["cluster-replication"]["reason"] == "replication_runtime_not_implemented"
    assert decisions["cluster-outside"]["reason"] == "outside_frozen_study_layers"


def test_eligibility_uses_frozen_task_binding_for_multi_profile_cwe(tmp_path: Path) -> None:
    record = {
        "record_id": "record-path",
        "source_dataset": "fixture",
        "source_lineage_family": "fixture",
        "source_test_references": [],
        "language": "python",
        "cwe": "CWE-22",
        "prompt": "Read a named file below a trusted base directory.",
    }
    cluster = {
        "cluster_id": "cluster-path",
        "record_ids": ["record-path"],
        "representative_record_id": "record-path",
        "language": "python",
        "cwes": ["CWE-22"],
        "cwe_label_conflict": False,
    }
    contract = {
        "cluster_id": "cluster-path",
        "contract_id": "contract-path",
        "resolution_status": "resolved",
        "requirements": ["Read the requested file."],
        "entrypoint": None,
    }
    prepared = tmp_path / "prepared"
    clusters = tmp_path / "clusters"
    contracts = tmp_path / "contracts"
    bindings = tmp_path / "bindings"
    write_bundle(prepared, {"records.json": [record]})
    write_bundle(clusters, {"semantic-clusters.json": [cluster]})
    write_bundle(contracts, {"functional-contracts.json": [contract]})
    write_bundle(
        bindings,
        {
            "binding-decisions.json": [
                {
                    "cluster_id": "cluster-path",
                    "representative_record_id": "record-path",
                    "contract_id": "contract-path",
                    "primary_cwe": "CWE-22",
                    "decision": "profile_candidate",
                    "realization_id": "cwe22_path_confinement",
                    "proposed_oracle_profile_id": "python.cwe22.path_confinement.v1",
                    "reason_code": "locally_measurable_profile_candidate",
                    "outcomes_or_arms_used": False,
                }
            ]
        },
    )

    output = tmp_path / "eligibility"
    audit_dataset_eligibility(
        Path.cwd(), prepared, clusters, contracts, output, bindings_root=bindings
    )
    decision = read_json(output / "eligibility-decisions.json")[0]

    assert decision["status"] == "eligible"
    assert decision["mechanism_realization_id"] == "cwe22_path_confinement"
    assert decision["oracle_profile_id"] == "python.cwe22.path_confinement.v1"

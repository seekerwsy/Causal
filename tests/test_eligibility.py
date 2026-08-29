from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.eligibility import (
    audit_dataset_eligibility,
    freeze_tsg_realization_bindings,
)
from prompt_mechanism_study.mechanisms import load_mechanism_registry
from prompt_mechanism_study.prompt_tsg import (
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_record,
)


pytestmark = pytest.mark.extended


@pytest.mark.reviewer
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
    bindings = tmp_path / "bindings"
    write_bundle(
        bindings,
        {
            "binding-decisions.json": [
                {
                    "cluster_id": "cluster-ready",
                    "representative_record_id": "record-ready",
                    "contract_id": "contract-ready",
                    "primary_cwe": "CWE-78",
                    "decision": "profile_candidate",
                    "realization_id": "cwe78_fixed_executable_argv",
                    "proposed_oracle_profile_id": "python.cwe78.function_parameter_subprocess.v2",
                    "reason_code": "locally_measurable_tsg_context",
                    "outcomes_or_arms_used": False,
                }
            ]
        },
    )

    output = tmp_path / "eligibility"
    report = audit_dataset_eligibility(
        Path.cwd(),
        prepared,
        cluster_root,
        contract_root,
        output,
        bindings_root=bindings,
    )
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


@pytest.mark.reviewer
def test_tsg_bindings_align_catalog_registry_and_local_oracle_scope(tmp_path: Path) -> None:
    catalog_path = Path("data/method/prompt-tsg-catalog-v1.json")
    registry_path = Path("data/method/mechanism-registry-v1.json")
    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    assert set(registry) == {row["realization_id"] for row in catalog["queries"]}

    tasks = [
        {
            "task_id": "sql-task",
            "task_unit_id": "sql-task",
            "record_id": "sql-record",
            "prompt": "Look up the caller's username in the fixed users table.",
            "cwe": "CWE-89",
            "task_family": "sql_query",
        },
        {
            "task_id": "url-task",
            "task_unit_id": "url-task",
            "record_id": "url-record",
            "prompt": "Request https://subdomain.example.test where subdomain is supplied by the caller.",
            "cwe": "CWE-918",
            "task_family": "outbound_request",
        },
    ]

    def fact(local_id: str, node_type: str, semantic_id: str, evidence: str) -> dict:
        return {
            "local_id": local_id,
            "node_type": node_type,
            "semantic_id": semantic_id,
            "evidence_text": evidence,
            "occurrence": 1,
            "attributes": {},
        }

    sql_graph = build_prompt_tsg(
        task_id="sql-task",
        prompt=tasks[0]["prompt"],
        extractor_id="fixture",
        catalog=catalog,
        facts=[
            fact("source", "source", "source.untrusted_sql_value", "username"),
            fact("sink", "sink", "sink.sql_execution", "Look up"),
            fact("constraint", "constraint", "constraint.fixed_sql_identifiers", "fixed users table"),
        ],
        relations=[
            {"edge_type": "flows_to", "source": "source", "target": "sink"},
        ],
    )
    url_graph = build_prompt_tsg(
        task_id="url-task",
        prompt=tasks[1]["prompt"],
        extractor_id="fixture",
        catalog=catalog,
        facts=[
            fact("source", "source", "source.untrusted_subdomain", "subdomain"),
            fact("sink", "sink", "sink.outbound_request", "Request"),
            fact("constraint", "constraint", "constraint.trusted_domain", "example.test"),
        ],
        relations=[
            {"edge_type": "flows_to", "source": "source", "target": "sink"},
        ],
    )
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps(tasks), encoding="utf-8")
    graph_root = tmp_path / "graphs"
    write_bundle(
        graph_root,
        {"graphs.json": [prompt_tsg_record(sql_graph), prompt_tsg_record(url_graph)]},
    )
    contract_root = tmp_path / "contracts"
    write_bundle(
        contract_root,
        {
            "functional-contracts.json": [
                {"cluster_id": "sql-task", "contract_id": "sql-contract"},
                {"cluster_id": "url-task", "contract_id": "url-contract"},
            ]
        },
    )

    output = tmp_path / "frozen-bindings"
    report = freeze_tsg_realization_bindings(
        tasks_path,
        (graph_root,),
        contract_root,
        catalog_path,
        registry_path,
        output,
    )
    rows = {row["cluster_id"]: row for row in read_json(output / "binding-decisions.json")}

    assert report["decision_counts"] == {
        "contextual_oracle_required": 1,
        "profile_candidate": 1,
    }
    assert rows["sql-task"]["realization_id"] == "cwe89_sql_values"
    assert rows["sql-task"]["proposed_oracle_profile_id"] == "python.cwe89.sql_values.v1"
    assert rows["url-task"]["realization_id"] == "cwe918_trusted_domain_subdomain"
    assert rows["url-task"]["reason_code"] == "local_security_oracle_not_qualified"

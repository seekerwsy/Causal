import json
from dataclasses import replace
from pathlib import Path
import pytest
from prompt_mechanism_study.artifact_io import (
    read_json,
    write_bundle,
)
from prompt_mechanism_study.discovery_population import (
    audit_discovery_positivity,
    freeze_task_unit_partition,
)
from prompt_mechanism_study.prompt_tsg import (
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    DataRole,
    DataRoleBinding,
    DataRoleManifest,
    TaskUnitDataRoleRecord,
    validate_data_role_firewall,
)


ROOT = Path(__file__).parents[1]


CATALOG_PATH = ROOT / "data/method/prompt-tsg-catalog-v1.json"


def _fact(local_id, node_type, semantic_id, evidence_text):
    return {
        "local_id": local_id,
        "node_type": node_type,
        "semantic_id": semantic_id,
        "evidence_text": evidence_text,
        "occurrence": 1,
        "attributes": {},
    }


def _xml_task(task_id: str, lineage: str, *, feature_present: bool):
    prompt = "Parse untrusted XML."
    facts = [
        _fact("source", "source", "source.untrusted_xml", "untrusted XML"),
        _fact("sink", "sink", "sink.xml_parsing", "Parse"),
    ]
    if feature_present:
        prompt += " Disable external entities."
        facts.append(
            _fact(
                "feature",
                "safety_requirement",
                "feature.xml_external_entity_control",
                "Disable external entities",
            )
        )
    graph = build_prompt_tsg(
        task_id=task_id,
        prompt=prompt,
        extractor_id="test-extractor",
        catalog=load_catalog(CATALOG_PATH),
        facts=facts,
        relations=[{"edge_type": "flows_to", "source": "source", "target": "sink"}],
    )
    task = {
        "task_id": task_id,
        "task_unit_id": task_id,
        "prompt": prompt,
        "cwe": "CWE-611",
        "task_family": "xml_parsing",
        "source_lineage_family": lineage,
    }
    return task, prompt_tsg_record(graph)


def test_data_role_manifest_closes_task_and_near_duplicate_firewalls() -> None:
    def task(
        task_unit_id: str,
        group_id: str,
        *,
        exposures: tuple[str, ...] = (),
    ) -> TaskUnitDataRoleRecord:
        return TaskUnitDataRoleRecord(
            task_unit_id,
            group_id,
            f"lineage-{task_unit_id}",
            exposures,
            "role-assignment-v1",
        )

    qual_a = task("qual-a", "qual-group")
    qual_b = task("qual-b", "qual-group")
    bindings = (
        DataRoleBinding(
            "CONFIRM-001",
            DataRole.CONFIRMATION,
            (task("confirm-a", "confirm-group"),),
            content_hash("confirm-manifest"),
        ),
        DataRoleBinding(
            "DISCOVERY-001",
            DataRole.DISCOVERY,
            (
                task("discover-a", "discover-group"),
                task("discover-b", "discover-group"),
            ),
            content_hash("discovery-manifest"),
        ),
        DataRoleBinding(
            "LEGACY-001",
            DataRole.LEGACY_ONLY,
            (
                task(
                    "legacy-a",
                    "legacy-group",
                    exposures=("used_for_legacy_gate_c_v4",),
                ),
            ),
            content_hash("legacy-manifest"),
        ),
        DataRoleBinding(
            "QUAL-ACCEPT-001",
            DataRole.QUAL_ACCEPT,
            (task("accept-a", "accept-group"),),
            content_hash("qual-accept-manifest"),
        ),
        DataRoleBinding(
            "QUAL-DEV-FCI-001",
            DataRole.QUAL_DEV,
            (qual_a, qual_b),
            content_hash("qual-fci-manifest"),
        ),
        DataRoleBinding(
            "QUAL-DEV-RD-001",
            DataRole.QUAL_DEV,
            (qual_b,),
            content_hash("qual-rd-manifest"),
        ),
    )
    manifest = DataRoleManifest(
        "phase-context-policy-v3",
        content_hash("source-universe"),
        bindings,
    )

    assert manifest.declared_roles == tuple(DataRole)
    assert manifest.qualification_data_ids == (
        "QUAL-ACCEPT-001",
        "QUAL-DEV-FCI-001",
        "QUAL-DEV-RD-001",
    )
    assert manifest.qualification_dev_data_ids == (
        "QUAL-DEV-FCI-001",
        "QUAL-DEV-RD-001",
    )
    assert manifest.qualification_accept_data_id == "QUAL-ACCEPT-001"
    assert manifest.require_dataset_role(
        "QUAL-DEV-FCI-001",
        DataRole.QUAL_DEV,
    ) == bindings[4]
    preflight = validate_data_role_firewall(
        manifest,
        {
            "QUAL-ACCEPT-001": DataRole.QUAL_ACCEPT,
            "QUAL-DEV-FCI-001": DataRole.QUAL_DEV,
        },
    )
    assert preflight["status"] == "PASS"
    assert preflight["outcome_data_read"] is False
    with pytest.raises(ValueError, match="not authorized"):
        validate_data_role_firewall(
            manifest,
            {"LEGACY-001": DataRole.DISCOVERY},
        )

    crossed_task = (
        *bindings,
        DataRoleBinding(
            "DISCOVERY-OVERLAP",
            DataRole.DISCOVERY,
            (qual_a,),
            content_hash("overlap-manifest"),
        ),
    )
    with pytest.raises(ValueError, match="cannot cross data roles"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            tuple(sorted(crossed_task, key=lambda item: item.data_id)),
        )

    crossed_group = (
        *bindings[:3],
        replace(
            bindings[3],
            task_units=(task("accept-a", "discover-group"),),
        ),
        *bindings[4:],
    )
    with pytest.raises(ValueError, match="near-duplicate group cannot cross"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            crossed_group,
        )

    with pytest.raises(ValueError, match="must be unexposed"):
        DataRoleBinding(
            "QUAL-ACCEPT-EXPOSED",
            DataRole.QUAL_ACCEPT,
            (
                task(
                    "accept-exposed",
                    "accept-exposed-group",
                    exposures=("profile_debugging",),
                ),
            ),
            content_hash("qual-accept-exposed-manifest"),
        )

    with pytest.raises(ValueError, match="all five data roles"):
        DataRoleManifest(
            "phase-context-policy-v3",
            content_hash("source-universe"),
            tuple(item for item in bindings if item.role is not DataRole.LEGACY_ONLY),
        )


def test_positivity_gate_requires_both_states_and_shared_lineages(tmp_path: Path):
    pairs = [
        _xml_task("p-a", "lineage-a", feature_present=True),
        _xml_task("p-b", "lineage-b", feature_present=True),
        _xml_task("a-a", "lineage-a", feature_present=False),
        _xml_task("a-b", "lineage-b", feature_present=False),
    ]
    tasks = [task for task, _graph in pairs]
    graphs = [graph for _task, graph in pairs]
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps(tasks), encoding="utf-8")
    graph_bundle = tmp_path / "graphs"
    write_bundle(graph_bundle, {"graphs.json": graphs})

    report = audit_discovery_positivity(
        tasks_path,
        (graph_bundle,),
        CATALOG_PATH,
        tmp_path / "audit",
        minimum_state_task_units=2,
        minimum_shared_lineages=2,
    )
    support = read_json(tmp_path / "audit/support.json")[0]
    rows = read_json(tmp_path / "audit/positivity-rows.json")

    assert report["status"] == "POSITIVITY_GATE_PASSED"
    assert len(report["positivity_implementation_sha256"]) == 64
    assert report["fci_executed"] is False
    assert support["context_present"] == 4
    assert support["context_absent"] == 0
    assert support["context_unresolved"] == 0
    assert support["feature_present"] == support["feature_absent"] == 2
    assert support["shared_lineages"] == ["lineage-a", "lineage-b"]
    assert sum(row["confirm_add_source_eligible"] for row in rows) == 2
    assert sum(row["confirm_remove_source_eligible"] for row in rows) == 2
    assert not any(row["confirm_remove_eligible"] for row in rows)


def test_positivity_gate_rejects_a_source_proxy(tmp_path: Path):
    pairs = [
        _xml_task("present", "positive-only", feature_present=True),
        _xml_task("absent", "negative-only", feature_present=False),
    ]
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps([task for task, _graph in pairs]), encoding="utf-8")
    graph_bundle = tmp_path / "graphs"
    write_bundle(graph_bundle, {"graphs.json": [graph for _task, graph in pairs]})

    report = audit_discovery_positivity(
        tasks_path,
        (graph_bundle,),
        CATALOG_PATH,
        tmp_path / "audit",
        minimum_state_task_units=1,
        minimum_shared_lineages=1,
    )
    support = read_json(tmp_path / "audit/support.json")[0]

    assert report["status"] == "POSITIVITY_GATE_FAILED"
    assert support["failure_reasons"] == ["insufficient_source_lineage_overlap"]


def test_task_partition_is_outcome_blind_stratified_and_leakage_closed(tmp_path: Path):
    pairs = [
        _xml_task(f"task-{index}", f"lineage-{index % 2}", feature_present=index % 2 == 0)
        for index in range(12)
    ]
    tasks = []
    clusters = []
    for index, (task, _graph) in enumerate(pairs):
        task["record_id"] = f"record-{index}"
        tasks.append(task)
        clusters.append(
            {
                "cluster_id": task["task_id"],
                "record_ids": [task["record_id"]],
                "representative_record_id": task["record_id"],
            }
        )
    tasks_path = tmp_path / "tasks.json"
    tasks_path.write_text(json.dumps(tasks), encoding="utf-8")
    graph_bundle = tmp_path / "graphs"
    write_bundle(graph_bundle, {"graphs.json": [graph for _task, graph in pairs]})
    clusters_root = tmp_path / "clusters"
    write_bundle(
        clusters_root,
        {
            "semantic-clusters.json": clusters,
            "diagnostic-semantic-edges.json": [
                {
                    "left": "record-0",
                    "right": "record-1",
                    "label": "same_cluster",
                }
            ],
        },
    )

    report = freeze_task_unit_partition(
        tasks_path,
        (graph_bundle,),
        clusters_root,
        CATALOG_PATH,
        tmp_path / "partition",
        seed=17,
    )
    assignments = read_json(tmp_path / "partition/assignments.json")
    split_by_task = {row["task_id"]: row["partition"] for row in assignments}

    assert report["arms_or_outcomes_used"] is False
    assert report["cross_partition_diagnostic_edges"] == 0
    assert split_by_task["task-0"] == split_by_task["task-1"]
    assert set(split_by_task.values()) == {"discovery", "pilot", "confirm"}
    assert sum(report["partition_counts"].values()) == 12

    support = audit_discovery_positivity(
        tmp_path / "partition/discovery-tasks.json",
        (tmp_path / "partition",),
        CATALOG_PATH,
        tmp_path / "discovery-audit",
        minimum_state_task_units=1,
        minimum_shared_lineages=1,
        graph_artifact="discovery-graphs.json",
    )

    assert support["graph_artifact"] == "discovery-graphs.json"
    assert support["task_units"] == report["partition_counts"]["discovery"]

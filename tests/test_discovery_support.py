import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.prioritization import (
    audit_discovery_positivity,
    freeze_task_unit_partition,
    prepare_discovery_population,
)
from prompt_mechanism_study.prompt_tsg import (
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import (
    DataRole,
    DataRoleBinding,
    DataRoleManifest,
    TaskUnitDataRoleRecord,
    validate_data_role_firewall,
)


pytestmark = pytest.mark.extended

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


@pytest.mark.reviewer
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


@pytest.mark.reviewer
def test_legacy_v5_inventory_is_complete_and_cannot_authorize_formal_use() -> None:
    manifest_path = ROOT / "configs/formal/qualification_data_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["artifact_kind"] == "qualification_data_manifest_draft"
    assert manifest["protocol_id"] == "phase-context-policy-v3"
    assert manifest["protocol_status"] == "SPECIFIED_DRAFT"
    assert manifest["status"] == (
        "PROSPECTIVE_CENSUS_COMPLETE_BLOCKED_ROLE_ALLOCATION_AND_POWER"
    )
    assert manifest["formal_use_authorized"] is False
    assert manifest["scientific_claim_allowed"] is False
    assert manifest["qualification_accept_attempts_authorized"] == 0
    assert manifest["assigned_roles"] == ["LEGACY_ONLY"]
    assert manifest["unassigned_roles"] == [
        "QUAL_DEV",
        "QUAL_ACCEPT",
        "DISCOVERY",
        "CONFIRMATION",
    ]

    bindings = manifest["bindings"]
    assert [binding["data_id"] for binding in bindings] == sorted(
        binding["data_id"] for binding in bindings
    )
    assert [binding["task_unit_count"] for binding in bindings] == [28, 20, 21]

    legacy_index = manifest["legacy_role_manifest"]
    legacy_root = ROOT / legacy_index["bundle_path"]
    verify_bundle(legacy_root)
    assert bundle_digest(legacy_root) == legacy_index["bundle_sha256"]
    legacy_role_manifest_path = ROOT / legacy_index["manifest_path"]
    legacy_role_manifest_bytes = legacy_role_manifest_path.read_bytes()
    assert hashlib.sha256(legacy_role_manifest_bytes).hexdigest() == (
        legacy_index["manifest_sha256"]
    )
    legacy_role_manifest = json.loads(legacy_role_manifest_bytes)
    assert legacy_role_manifest["bindings"] == bindings
    assert legacy_role_manifest["data_role"] == "LEGACY_ONLY"
    assert legacy_role_manifest["formal_use_authorized"] is False
    legacy_identity_payload = {
        key: value
        for key, value in legacy_role_manifest.items()
        if key != "legacy_data_role_manifest_id"
    }
    assert legacy_role_manifest["legacy_data_role_manifest_id"] == content_id(
        "legacy_data_role_manifest_",
        legacy_identity_payload,
    )
    assert legacy_index["legacy_data_role_manifest_id"] == (
        legacy_role_manifest["legacy_data_role_manifest_id"]
    )

    all_task_unit_ids: list[str] = []
    for binding in bindings:
        assert binding["data_role"] == "LEGACY_ONLY"
        assert binding["near_duplicate_group_status"] == "UNRESOLVED_BLOCKING"
        assert binding["near_duplicate_group_id_by_task_unit"] is None
        assert binding["exposure_history_applies_to_all_task_units"]

        task_manifest_path = ROOT / binding["task_manifest_path"]
        task_manifest_bytes = task_manifest_path.read_bytes()
        assert hashlib.sha256(task_manifest_bytes).hexdigest() == binding[
            "task_manifest_sha256"
        ]
        task_manifest = json.loads(task_manifest_bytes)
        task_unit_ids = list(binding["task_unit_source_lineage"])
        assert task_unit_ids == sorted(task_unit_ids)
        assert task_unit_ids == sorted(task_manifest["task_ids"])
        assert len(task_unit_ids) == binding["task_unit_count"]
        assert all(binding["task_unit_source_lineage"].values())
        all_task_unit_ids.extend(task_unit_ids)

        source_manifest_path = binding["source_manifest_path"]
        if source_manifest_path is not None:
            source_manifest_bytes = (ROOT / source_manifest_path).read_bytes()
            assert hashlib.sha256(source_manifest_bytes).hexdigest() == binding[
                "source_manifest_sha256"
            ]

        for evidence in binding["exposure_evidence"]:
            if "tracking_status" in evidence:
                assert evidence["tracking_status"] == (
                    "REPOSITORY_ARCHIVE_COPY_VERIFIED_PENDING_COMMIT"
                )
            evidence_bytes = (ROOT / evidence["path"]).read_bytes()
            assert hashlib.sha256(evidence_bytes).hexdigest() == evidence["sha256"]

    assert len(all_task_unit_ids) == 69
    assert len(set(all_task_unit_ids)) == 69
    census = manifest["prospective_role_census"]
    census_root = ROOT / census["bundle_path"]
    verify_bundle(census_root)
    assert bundle_digest(census_root) == census["bundle_sha256"]
    census_rows = read_json(census_root / "task-units.json")
    assert len(census_rows) == census["candidate_task_unit_count"] == 164
    assert sum(row["prospective_role_eligible"] for row in census_rows) == 141
    assert sum(
        "exact_task_unit_in_legacy_only" in row["prospective_exclusion_reasons"]
        for row in census_rows
    ) == 23
    assert read_json(census_root / "legacy-bindings.json") == bindings
    assert read_json(census_root / "report.json")["legacy_manifest_sha256"] == (
        legacy_index["manifest_sha256"]
    )
    assert census["role_assignment_frozen"] is False
    assert census["population_target_met"] is False

    assert manifest["disjointness_report"] == {
        "legacy_binding_count": 3,
        "legacy_task_unit_count": 69,
        "task_unit_overlap_across_legacy_bindings": 0,
        "prospective_candidate_task_unit_count": 164,
        "prospective_exact_legacy_overlap_count": 23,
        "prospective_near_duplicate_only_legacy_overlap_count": 0,
        "prospective_unexposed_task_unit_count": 141,
        "near_duplicate_cross_role_overlap_count": None,
        "status": "CENSUS_COMPLETE_BLOCKED_BEFORE_ROLE_ASSIGNMENT",
        "outcome_data_read": False,
    }

    external_failure = read_json(
        ROOT / "data/method/prompt-tsg-external-qualification-v5-preflight-failure.json"
    )
    external_v6_failure = read_json(
        ROOT / "data/method/prompt-tsg-external-qualification-v6-failure.json"
    )
    two_stage_failure = read_json(
        ROOT
        / "data/method/results/prompt-tsg-two-stage-qualification-v5/qualification.json"
    )
    assert external_failure["formal_v5_task_units_sent_to_provider"] == 0
    assert external_v6_failure["formal_task_units_conservatively_treated_as_exposed"] == 28
    assert two_stage_failure["status"] == "QUALIFICATION_FAILED"
    assert two_stage_failure["holdout_task_units"] == 21


@pytest.mark.reviewer
def test_population_freeze_uses_natural_representatives_without_outcomes(tmp_path: Path):
    prompt = "Parse untrusted XML."
    records = [
        {
            "record_id": "record-python",
            "language": "python",
            "cwe": "CWE-611",
            "prompt": prompt,
            "prompt_sha256": content_hash(prompt),
            "source_dataset": "source-a",
            "source_lineage_family": "lineage-a",
        },
        {
            "record_id": "record-java",
            "language": "java",
            "cwe": "CWE-611",
            "prompt": prompt,
            "prompt_sha256": content_hash(prompt),
            "source_dataset": "source-b",
            "source_lineage_family": "lineage-b",
        },
    ]
    clusters = [
        {"cluster_id": "unit-python", "representative_record_id": "record-python"},
        {"cluster_id": "unit-java", "representative_record_id": "record-java"},
    ]
    prepared = tmp_path / "prepared"
    clustered = tmp_path / "clusters"
    write_bundle(prepared, {"records.json": records})
    write_bundle(clustered, {"semantic-clusters.json": clusters})

    report = prepare_discovery_population(
        prepared,
        clustered,
        CATALOG_PATH,
        tmp_path / "population",
        scopes={"CWE-611": "xml_parsing"},
    )

    tasks = read_json(tmp_path / "population/tasks.json")
    assert report["task_units"] == 1
    assert report["arms_or_outcomes_used"] is False
    assert tasks[0]["task_unit_id"] == "unit-python"
    assert tasks[0]["prompt"] == prompt


@pytest.mark.reviewer
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


@pytest.mark.reviewer
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


@pytest.mark.reviewer
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

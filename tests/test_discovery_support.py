import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.prioritization import (
    audit_discovery_positivity,
    prepare_discovery_population,
)
from prompt_mechanism_study.prompt_tsg import (
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import content_hash


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

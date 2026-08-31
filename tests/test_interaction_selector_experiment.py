from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import pytest

import prompt_mechanism_study.interaction_selector_experiment as selector_experiment
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.interaction_selector import PairDiscoveryObservation
from prompt_mechanism_study.interaction_selector_experiment import (
    InteractionSelectorExperimentError,
    freeze_interaction_selection_from_config,
    verify_interaction_selection_bundle,
)
from prompt_mechanism_study.mechanisms import (
    FactorialCompatibility,
    MechanismRelationSpec,
    RelationEvidenceContract,
    evaluate_pair_relation_evidence,
    load_pair_registry,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    catalog_sha256,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import canonical_json, canonical_value, content_hash
from test_interaction_selector import _plan

pytestmark = pytest.mark.extended
ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "data/method/prompt-tsg-pair-catalog-v1.json"
REGISTRY_PATH = ROOT / "data/method/mechanism-pairs-v2.json"


def _catalog_bound_selector_config(
    tmp_path: Path, *, registry_path: Path = REGISTRY_PATH
) -> tuple[dict, object]:
    catalog = load_catalog(CATALOG_PATH)
    registry_value = read_json(registry_path)
    registry = load_pair_registry(registry_path, catalog)
    pair = registry.pairs[0]
    spec = MechanismRelationSpec(
        "relation.dynamic_sql_pair.v1",
        pair.factor_1_id,
        pair.factor_2_id,
        pair.relation_type,
        FactorialCompatibility.COMPATIBLE,
        pair.pair_context_query_id,
        RelationEvidenceContract(
            (
                "sink.sql_execution",
                "source.dynamic_sql_identifier",
                "source.untrusted_sql_value",
            ),
            (
                (
                    "source.dynamic_sql_identifier",
                    "flows_to",
                    "sink.sql_execution",
                ),
                (
                    "source.untrusted_sql_value",
                    "flows_to",
                    "sink.sql_execution",
                ),
            ),
        ),
        ("python",),
        ("sql_query",),
        ("CWE-89",),
        (pair.operations,),
    )
    rows = []
    evidence = []
    prompt_tsg_evidence = []
    for x1, x2 in ((0, 0), (0, 1), (1, 0), (1, 1)):
        cell = f"{x1}{x2}"
        for index in range(8):
            task_unit_id = f"unit-{cell}-{index}"
            feature_1_text = "Require bound SQL values."
            feature_2_text = (
                "Require mapping dynamic identifiers through the declared finite allowlist."
            )
            prompt_parts = [
                "Use dynamic identifier and untrusted value in SQL execution."
            ]
            if x1:
                prompt_parts.append(feature_1_text)
            if x2:
                prompt_parts.append(feature_2_text)
            task = {
                "task_id": f"task-{task_unit_id}",
                "task_unit_id": task_unit_id,
                "prompt": " ".join(prompt_parts),
                "language": "python",
                "task_family": "sql_query",
                "cwe": "CWE-89",
            }
            graph = build_prompt_tsg(
                task_id=task["task_id"],
                prompt=task["prompt"],
                extractor_id="llm-facts-v1",
                catalog=catalog,
                facts=(
                    {
                        "local_id": "identifier",
                        "node_type": "source",
                        "semantic_id": "source.dynamic_sql_identifier",
                        "evidence_text": "dynamic identifier",
                        "occurrence": 1,
                        "attributes": {},
                    },
                    {
                        "local_id": "value",
                        "node_type": "source",
                        "semantic_id": "source.untrusted_sql_value",
                        "evidence_text": "untrusted value",
                        "occurrence": 1,
                        "attributes": {},
                    },
                    {
                        "local_id": "sink",
                        "node_type": "sink",
                        "semantic_id": "sink.sql_execution",
                        "evidence_text": "SQL execution",
                        "occurrence": 1,
                        "attributes": {},
                    },
                    *(
                        (
                            {
                                "local_id": "factor-1",
                                "node_type": "safety_requirement",
                                "semantic_id": pair.factor_1_id,
                                "evidence_text": feature_1_text,
                                "occurrence": 1,
                                "attributes": {},
                            },
                        )
                        if x1
                        else ()
                    ),
                    *(
                        (
                            {
                                "local_id": "factor-2",
                                "node_type": "safety_requirement",
                                "semantic_id": pair.factor_2_id,
                                "evidence_text": feature_2_text,
                                "occurrence": 1,
                                "attributes": {},
                            },
                        )
                        if x2
                        else ()
                    ),
                ),
                relations=(
                    {"edge_type": "flows_to", "source": "identifier", "target": "sink"},
                    {"edge_type": "flows_to", "source": "value", "target": "sink"},
                ),
            )
            relation = evaluate_pair_relation_evidence(task, graph, pair, spec)
            evidence.append(relation)
            prompt_tsg_evidence.append({"task": task, "graph": prompt_tsg_record(graph)})
            rows.append(
                PairDiscoveryObservation(
                    pair.pair_id,
                    spec.relation_spec_id,
                    relation.evidence_id,
                    task_unit_id,
                    "model-v1",
                    f"lineage-{index % 2}",
                    "python",
                    "sql_query",
                    "sqlite",
                    pair.pair_context_query_id,
                    QueryState.PRESENT,
                    (
                        (
                            pair.factor_1_id,
                            QueryState.PRESENT if x1 else QueryState.ABSENT,
                        ),
                        (
                            pair.factor_2_id,
                            QueryState.PRESENT if x2 else QueryState.ABSENT,
                        ),
                    ),
                    ((pair.factor_1_id, 0.99), (pair.factor_2_id, 0.99)),
                    (("source_code", float(index % 2)),),
                    x1 ^ x2,
                )
            )
    evidence_path = tmp_path / "prompt-tsg-evidence.json"
    evidence_path.write_text(canonical_json(prompt_tsg_evidence), encoding="utf-8")
    discovery_evidence = sorted(
        (
            {
                "observation_id": row.observation_id,
                "producer_id": "frozen-pair-discovery-v1",
                "raw_output": canonical_value(row),
                "raw_output_sha256": content_hash(canonical_value(row)),
                "confirm_outcomes_used": False,
            }
            for row in rows
        ),
        key=lambda item: item["observation_id"],
    )
    return (
        {
            "schema_version": "1.2",
            "prompt_tsg_catalog_path": str(CATALOG_PATH),
            "prompt_tsg_catalog_sha256": catalog_sha256(catalog),
            "prompt_tsg_evidence_path": str(evidence_path),
            "prompt_tsg_evidence_sha256": content_hash(prompt_tsg_evidence),
            "pair_registry_path": str(registry_path),
            "pair_registry_sha256": content_hash(registry_value),
            "relation_specs": canonical_value((spec,)),
            "relation_evidence": canonical_value(tuple(evidence)),
            "observations": canonical_value(tuple(rows)),
            "discovery_evidence": discovery_evidence,
            "plan": canonical_value(_plan()),
            "graph_support_selection": None,
        },
        pair,
    )


def test_interaction_selection_bundle_replays_and_rejects_semantic_tamper(
    tmp_path: Path,
) -> None:
    config, pair = _catalog_bound_selector_config(tmp_path)
    config_path = tmp_path / "interaction-selector.json"
    config_path.write_text(canonical_json(config), encoding="utf-8")
    output = tmp_path / "freeze"
    report = freeze_interaction_selection_from_config(config_path, output)

    assert report["status"] == "INTERACTION_SELECTION_FROZEN"
    assert report["selected_pair_ids"] == [pair.pair_id]
    assert (output / "prompt-tsg-catalog.json").is_file()
    assert (output / "prompt-tsg-evidence.json").is_file()
    assert (output / "pair-registry.json").is_file()
    verified = verify_interaction_selection_bundle(output)
    assert verified["freeze_id"] == report["freeze_id"]

    stored = read_json(output / "report.json")
    stored["selected_pair_ids"] = []
    payload = (canonical_json(stored) + "\n").encode()
    (output / "report.json").write_bytes(payload)
    manifest = read_json(output / "manifest.json")
    manifest["files"]["report.json"] = hashlib.sha256(payload).hexdigest()
    (output / "manifest.json").write_bytes((canonical_json(manifest) + "\n").encode())
    with pytest.raises(InteractionSelectorExperimentError, match="report does not recompute"):
        verify_interaction_selection_bundle(output)


def test_interaction_selection_recomputes_factor_states_from_prompt_tsg(
    tmp_path: Path,
) -> None:
    config, _pair = _catalog_bound_selector_config(tmp_path)
    current = config["observations"][0]["factor_states"][0][1]
    config["observations"][0]["factor_states"][0][1] = (
        "present" if current == "absent" else "absent"
    )
    rows = tuple(
        selector_experiment._observation(item) for item in config["observations"]
    )
    config["discovery_evidence"] = sorted(
        (
            {
                "observation_id": row.observation_id,
                "producer_id": "frozen-pair-discovery-v1",
                "raw_output": canonical_value(row),
                "raw_output_sha256": content_hash(canonical_value(row)),
                "confirm_outcomes_used": False,
            }
            for row in rows
        ),
        key=lambda item: item["observation_id"],
    )
    path = tmp_path / "factor-state-drift.json"
    path.write_text(canonical_json(config), encoding="utf-8")

    with pytest.raises(
        InteractionSelectorExperimentError,
        match="observation drifts from its task-side evidence",
    ):
        freeze_interaction_selection_from_config(path, tmp_path / "output")



def test_interaction_selection_rejects_catalog_or_registry_digest_drift(
    tmp_path: Path,
) -> None:
    config, _pair = _catalog_bound_selector_config(tmp_path)
    config["pair_registry_sha256"] = "0" * 64
    config_path = tmp_path / "drift.json"
    config_path.write_text(canonical_json(config), encoding="utf-8")
    with pytest.raises(InteractionSelectorExperimentError, match="registry digest drift"):
        freeze_interaction_selection_from_config(config_path, tmp_path / "drift-output")

    invalid_spec, _pair = _catalog_bound_selector_config(tmp_path)
    invalid_spec["relation_specs"][0]["factor_1_id"] = "feature.not_in_catalog"
    invalid_path = tmp_path / "invalid-spec.json"
    invalid_path.write_text(canonical_json(invalid_spec), encoding="utf-8")
    with pytest.raises(ValueError, match="registered atomic safety features"):
        freeze_interaction_selection_from_config(
            invalid_path, tmp_path / "invalid-spec-output"
        )


def test_interaction_selection_recomputes_prompt_tsg_and_blindness(
    tmp_path: Path,
) -> None:
    config, _pair = _catalog_bound_selector_config(tmp_path)
    evidence = read_json(Path(config["prompt_tsg_evidence_path"]))
    evidence[0]["task"]["prompt"] += " Extra text."
    Path(config["prompt_tsg_evidence_path"]).write_text(
        canonical_json(evidence), encoding="utf-8"
    )
    config["prompt_tsg_evidence_sha256"] = content_hash(evidence)
    path = tmp_path / "graph-drift.json"
    path.write_text(canonical_json(config), encoding="utf-8")
    with pytest.raises(ValueError, match="Prompt TSG record identity"):
        freeze_interaction_selection_from_config(path, tmp_path / "graph-drift-output")

    blind_config, _pair = _catalog_bound_selector_config(tmp_path)
    del blind_config["relation_evidence"][0]["outcomes_or_arms_used"]
    blind_path = tmp_path / "blindness.json"
    blind_path.write_text(canonical_json(blind_config), encoding="utf-8")
    with pytest.raises(InteractionSelectorExperimentError, match="fields are not exact"):
        freeze_interaction_selection_from_config(blind_path, tmp_path / "blind-output")


def test_interaction_selection_rejects_nested_unknown_fields(tmp_path: Path) -> None:
    config, _pair = _catalog_bound_selector_config(tmp_path)
    config["plan"]["unreviewed_option"] = True
    path = tmp_path / "unknown-field.json"
    path.write_text(canonical_json(config), encoding="utf-8")
    with pytest.raises(InteractionSelectorExperimentError, match="fields are not exact"):
        freeze_interaction_selection_from_config(path, tmp_path / "unknown-output")

    evidence_config, _pair = _catalog_bound_selector_config(tmp_path)
    evidence_config["discovery_evidence"][0]["raw_output"]["outcome"] = 1 - evidence_config[
        "discovery_evidence"
    ][0]["raw_output"]["outcome"]
    evidence_config["discovery_evidence"][0]["raw_output_sha256"] = content_hash(
        evidence_config["discovery_evidence"][0]["raw_output"]
    )
    evidence_path = tmp_path / "discovery-drift.json"
    evidence_path.write_text(canonical_json(evidence_config), encoding="utf-8")
    with pytest.raises(
        InteractionSelectorExperimentError, match="does not bind its natural observation"
    ):
        freeze_interaction_selection_from_config(
            evidence_path, tmp_path / "discovery-drift-output"
        )

from __future__ import annotations

import hashlib
import shutil
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study import prioritization
from prompt_mechanism_study.artifact_io import bundle_digest, read_json
from prompt_mechanism_study.cli import main
from prompt_mechanism_study.prompt_tsg import (
    apply_feature_patch,
    build_prompt_tsg,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
)
from prompt_mechanism_study.prioritization import (
    BackgroundKnowledgeRule,
    BridgeRecord,
    BridgeStatus,
    discovery_data_sha256,
    freeze_shared_bridge_map,
    run_selector_suite,
)
from prompt_mechanism_study.records import canonical_json, canonical_value, content_hash
from prompt_mechanism_study.representation import FrozenHypothesisV2, TargetSpecV2
from prompt_mechanism_study.selector_experiment import (
    SelectorExperimentError,
    build_active_selector_evidence,
    freeze_bridge_from_config,
    freeze_selection_from_config,
    load_bridge_freeze_bundle,
    load_selection_freeze_bundle,
    write_selection_freeze_bundle,
)
from test_selector_study import _fixture


CATALOG_PATH = Path(__file__).parents[1] / "data/method/prompt-tsg-catalog-v1.json"


def _prompt_tsg_evidence(manifest, rows):
    catalog = load_catalog(CATALOG_PATH)
    skeletons = dict(manifest.candidate_skeletons)
    queries = {item["query_id"]: item for item in catalog["queries"]}
    prompts = {}
    graphs = {}
    for task_unit_id in sorted({item.task_unit_id for item in rows}):
        task_rows = [item for item in rows if item.task_unit_id == task_unit_id]
        states = {
            candidate_id: state
            for item in task_rows
            for candidate_id, state in item.candidate_states
        }
        relevant_queries = [
            queries[skeletons[candidate_id].context_query_id]
            for candidate_id in states
        ]
        semantics = {
            semantic_id
            for query in relevant_queries
            for semantic_id in query["required_semantics"]
        }
        semantics.update(
            skeletons[candidate_id].actionable_feature_id
            for candidate_id, state in states.items()
            if state == 1
        )
        ordered_semantics = sorted(semantics)
        prompt = " ".join(ordered_semantics)
        local_by_semantic = {
            semantic_id: f"fact-{index:02d}"
            for index, semantic_id in enumerate(ordered_semantics)
        }
        facts = [
            {
                "local_id": local_by_semantic[semantic_id],
                "node_type": catalog["semantics"][semantic_id],
                "semantic_id": semantic_id,
                "evidence_text": semantic_id,
                "occurrence": 1,
                "attributes": {},
            }
            for semantic_id in ordered_semantics
        ]
        relation_keys = sorted(
            {
                tuple(relation)
                for query in relevant_queries
                for relation in query["required_relations"]
            }
        )
        relations = [
            {
                "source": local_by_semantic[source],
                "edge_type": edge_type,
                "target": local_by_semantic[target],
            }
            for source, edge_type, target in relation_keys
        ]
        prompts[task_unit_id] = prompt
        graphs[task_unit_id] = build_prompt_tsg(
            task_id=task_unit_id,
            prompt=prompt,
            extractor_id="test-frozen-facts-v1",
            catalog=catalog,
            facts=facts,
            relations=relations,
        )
    return prompts, graphs, catalog


def _prospective_fixture(monkeypatch):
    manifest, rows, legacy_plan, candidate_ids, _fci, expert = _fixture()
    rows = tuple(
        item
        for row in rows
        for item in (
            row,
            replace(
                row,
                request_randomness_slot=1,
                outcome=1 - row.outcome,
            ),
        )
    )
    manifest = replace(manifest, discovery_data_sha256=discovery_data_sha256(rows))
    family_by_candidate = dict(manifest.candidate_family_ids)
    rules = []
    wrong_rules = []
    for family_id in sorted(set(family_by_candidate.values())):
        first, second = tuple(
            candidate_id
            for candidate_id in candidate_ids
            if family_by_candidate[candidate_id] == family_id
        )
        rules.extend(
            (
                BackgroundKnowledgeRule(
                    f"temporal-{family_id}",
                    family_id,
                    "temporal",
                    "temporal_order",
                    "Y:discovery_outcome",
                    f"X:{first}",
                ),
                BackgroundKnowledgeRule(
                    f"domain-{family_id}",
                    family_id,
                    "domain-order",
                    "reviewed_domain",
                    f"X:{first}",
                    f"X:{second}",
                ),
            )
        )
        wrong_rules.append(
            BackgroundKnowledgeRule(
                f"wrong-{family_id}",
                family_id,
                "wrong-direction",
                "wrong_plausible",
                f"X:{first}",
                "Y:discovery_outcome",
            )
        )
    plan = replace(
        legacy_plan,
        behavior_version="shared-selector-suite-v2",
        fci_background_knowledge=tuple(rules),
        fci_wrong_bk_perturbation=tuple(wrong_rules),
    )
    prompts, graphs, catalog = _prompt_tsg_evidence(manifest, rows)
    manifest, support_audit, information_budget, discovery_evidence = (
        build_active_selector_evidence(
            manifest,
            rows,
            prompt_by_task_unit=prompts,
            prompt_tsg_by_task_unit=graphs,
            prompt_tsg_catalog=catalog,
        )
    )
    expert = replace(
        expert,
        universe_manifest_id=manifest.manifest_id,
        candidate_card_sha256=content_hash(information_budget["candidate_cards"]),
    )
    monkeypatch.setattr(prioritization, "_causal_learn_version", lambda: "0.1.4.7")

    def fake_pag(
        _matrix,
        *,
        outcome_index,
        variable_order,
        **_kwargs,
    ):
        feature = next(
            index for index, name in enumerate(variable_order) if name.startswith("X:")
        )
        return {
            feature,
        }, ((variable_order[feature], "CIRCLE", variable_order[outcome_index], "CIRCLE"),)

    monkeypatch.setattr(prioritization, "_run_causal_learn_pag", fake_pag)
    return (
        manifest,
        rows,
        plan,
        candidate_ids,
        expert,
        support_audit,
        information_budget,
        discovery_evidence,
        catalog,
    )


@pytest.mark.extended
def test_active_selector_recomputes_support_and_information_budget(
    tmp_path: Path, monkeypatch
) -> None:
    (
        manifest,
        rows,
        plan,
        _candidate_ids,
        _expert,
        support_audit,
        information_budget,
        discovery_evidence,
        catalog,
    ) = _prospective_fixture(monkeypatch)
    config = {
        "schema_version": "2.1",
        "universe": canonical_value(manifest),
        "observations": canonical_value(rows),
        "prompt_tsg_catalog": catalog,
        "plan": canonical_value(plan),
        "expert_input": None,
        "fci_relation_scores": None,
        "support_audit": support_audit,
        "information_budget": deepcopy(information_budget),
        "discovery_evidence": discovery_evidence,
    }
    config["information_budget"]["candidate_cards"][0]["cwe"] = "CWE-999"
    config["universe"]["information_budget_sha256"] = content_hash(
        config["information_budget"]
    )
    path = tmp_path / "tampered-information.json"
    path.write_text(canonical_json(config), encoding="utf-8")
    with pytest.raises(SelectorExperimentError, match="information budget does not recompute"):
        freeze_selection_from_config(path, tmp_path / "tampered-information")

    raw_config = deepcopy(config)
    raw_config["information_budget"] = information_budget
    raw_config["universe"]["information_budget_sha256"] = content_hash(information_budget)
    raw_config["discovery_evidence"][0]["raw_output"]["outcome"] = 1 - raw_config[
        "discovery_evidence"
    ][0]["raw_output"]["outcome"]
    raw_config["discovery_evidence"][0]["raw_output_sha256"] = content_hash(
        raw_config["discovery_evidence"][0]["raw_output"]
    )
    raw_path = tmp_path / "tampered-discovery.json"
    raw_path.write_text(canonical_json(raw_config), encoding="utf-8")
    with pytest.raises(SelectorExperimentError, match="does not bind its observation"):
        freeze_selection_from_config(raw_path, tmp_path / "tampered-discovery")

    graph_config = deepcopy(config)
    row = next(
        item
        for item in graph_config["discovery_evidence"]
        if any(state == 0 for _candidate_id, state in item["raw_output"]["candidate_states"])
    )
    candidate_id = next(
        candidate_id
        for candidate_id, state in row["raw_output"]["candidate_states"]
        if state == 0
    )
    feature_id = dict(manifest.candidate_skeletons)[candidate_id].actionable_feature_id
    original_prompt = row["prompt"]
    patched = apply_feature_patch(
        prompt_tsg_from_record(row["prompt_tsg"]),
        prompt=original_prompt,
        appended_text="Apply the selected security control.",
        semantic_id=feature_id,
        catalog=catalog,
    )
    row["prompt"] = original_prompt + "\n\nApply the selected security control."
    row["prompt_sha256"] = content_hash(row["prompt"])
    row["prompt_tsg"] = prompt_tsg_record(patched)
    graph_path = tmp_path / "tampered-prompt-tsg.json"
    graph_path.write_text(canonical_json(graph_config), encoding="utf-8")
    with pytest.raises(SelectorExperimentError, match="do not recompute from Prompt TSG"):
        freeze_selection_from_config(graph_path, tmp_path / "tampered-prompt-tsg")



@pytest.mark.extended
def test_offline_selection_and_bridge_artifact_closure_and_tamper_rejection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    base = tmp_path / "original"
    base.mkdir()
    (
        manifest,
        rows,
        suite_plan,
        _candidate_ids,
        expert,
        support_audit,
        information_budget,
        discovery_evidence,
        catalog,
    ) = _prospective_fixture(monkeypatch)
    selection = run_selector_suite(
        manifest, rows, suite_plan, fci_relation_scores=None, expert_input=expert
    )
    selection_root = base / "selection"
    selection_config = {
        "schema_version": "2.1",
        "universe": canonical_value(manifest),
        "observations": canonical_value(rows),
        "prompt_tsg_catalog": catalog,
        "plan": canonical_value(suite_plan),
        "expert_input": canonical_value(expert),
        "fci_relation_scores": None,
        "support_audit": support_audit,
        "information_budget": information_budget,
        "discovery_evidence": discovery_evidence,
    }
    write_selection_freeze_bundle(selection_root, selection, selection_config)
    assert load_selection_freeze_bundle(selection_root) == selection

    skeleton_by_candidate = dict(selection.universe.candidate_skeletons)
    hypotheses = tuple(
        FrozenHypothesisV2(
            skeleton_by_candidate[candidate_id],
            TargetSpecV2(
                skeleton_by_candidate[candidate_id].candidate_skeleton_id,
                skeleton_by_candidate[candidate_id].context_query_id,
                skeleton_by_candidate[candidate_id].actionable_feature_id,
                skeleton_by_candidate[candidate_id].operation,
                content_hash("context-query-catalog"),
                content_hash("feature-catalog"),
                content_hash("allowed-delta-policy"),
            ),
        )
        for candidate_id in selection.selected_union_candidate_ids
    )
    records = tuple(
        BridgeRecord(
            candidate_id,
            BridgeStatus.SUCCESS,
            hypothesis.hypothesis_id,
            None,
            hypothesis,
        )
        for candidate_id, hypothesis in zip(
            selection.selected_union_candidate_ids,
            hypotheses,
            strict=True,
        )
    )
    bridge = freeze_shared_bridge_map(selection, records)
    bridge_root = base / "bridge"
    bridge_config = base / "bridge.json"
    bridge_config.write_text(
        canonical_json({"schema_version": "2.1", "records": canonical_value(records)}),
        encoding="utf-8",
    )
    freeze_bridge_from_config(selection_root, bridge_config, bridge_root)
    assert load_bridge_freeze_bundle(bridge_root, selection_root) == bridge
    assert main([
        "selector-study", "verify-bridge", str(bridge_root),
        "--selection", str(selection_root),
    ]) == 0

    # A self-consistent hypothesis swap still fails because each successful
    # v2 bridge is independently rebound to its own predecessor skeleton.
    tampered_bridge = base / "tampered-bridge"
    shutil.copytree(bridge_root, tampered_bridge)
    bridge_payload = read_json(tampered_bridge / "bridge.json")
    assert len(bridge_payload["records"]) >= 2
    first, second = bridge_payload["records"][:2]
    first["final_hypothesis"], second["final_hypothesis"] = (
        deepcopy(second["final_hypothesis"]),
        deepcopy(first["final_hypothesis"]),
    )
    first["final_hypothesis_id"], second["final_hypothesis_id"] = (
        second["final_hypothesis_id"],
        first["final_hypothesis_id"],
    )
    raw = (canonical_json(bridge_payload) + "\n").encode()
    (tampered_bridge / "bridge.json").write_bytes(raw)
    bridge_manifest = read_json(tampered_bridge / "manifest.json")
    bridge_manifest["files"]["bridge.json"] = hashlib.sha256(raw).hexdigest()
    (tampered_bridge / "manifest.json").write_bytes(
        (canonical_json(bridge_manifest) + "\n").encode()
    )
    with pytest.raises(SelectorExperimentError, match="predecessor skeleton"):
        load_bridge_freeze_bundle(tampered_bridge, selection_root)

    # Unknown nested fields cannot hide inside an otherwise re-hashed bundle.
    tampered_selection = base / "tampered-selection"
    shutil.copytree(selection_root, tampered_selection)
    selection_payload = read_json(tampered_selection / "selection.json")
    selection_payload["runs"][0]["rankings"][0]["scores"][0]["unexpected"] = True
    raw = (canonical_json(selection_payload) + "\n").encode()
    (tampered_selection / "selection.json").write_bytes(raw)
    selection_manifest = read_json(tampered_selection / "manifest.json")
    selection_manifest["files"]["selection.json"] = hashlib.sha256(raw).hexdigest()
    (tampered_selection / "manifest.json").write_bytes(
        (canonical_json(selection_manifest) + "\n").encode()
    )
    with pytest.raises(SelectorExperimentError, match="ranked candidate fields are not exact"):
        load_selection_freeze_bundle(tampered_selection)

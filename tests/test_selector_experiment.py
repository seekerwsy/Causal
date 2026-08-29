from __future__ import annotations

import hashlib
import shutil
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

import prompt_mechanism_study.selector_analysis as analysis
from prompt_mechanism_study import prioritization
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.cli import main
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
from prompt_mechanism_study.selector_analysis import (
    run_selector_experiment_from_config,
    verify_selector_experiment_bundle,
)
from prompt_mechanism_study.selector_experiment import (
    SelectorExperimentError,
    build_active_selector_evidence,
    freeze_bridge_from_config,
    freeze_selection_from_config,
    load_bridge_freeze_bundle,
    load_selection_freeze_bundle,
    write_selection_freeze_bundle,
)
from prompt_mechanism_study.selector_inference import (
    SelectorInferencePlan,
    canonical_selector_pairs,
)
from test_selector_study import _fixture


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
    manifest, support_audit, information_budget, discovery_evidence = (
        build_active_selector_evidence(manifest, rows)
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
    ) = _prospective_fixture(monkeypatch)
    config = {
        "schema_version": "2.0",
        "universe": canonical_value(manifest),
        "observations": canonical_value(rows),
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


@pytest.mark.extended
def test_representation_comparison_is_end_to_end_not_selector_only() -> None:
    direct = {
        "model_id": "model-a",
        "outcome_id": "secure_yield",
        "top_k": 3,
        "candidate_coverage": 0.5,
        "protocolization_rate": 0.5,
        "unique_confirmed_hypothesis_ids": ["h-1"],
        "strict_confirmed_yield_at_k": [
            {"selector_id": "fci", "model_id": "model-a", "confirmed_yield_at_k": 1 / 3}
        ],
    }
    contextual = {
        **direct,
        "candidate_coverage": 0.75,
        "protocolization_rate": 1.0,
        "unique_confirmed_hypothesis_ids": ["h-2", "h-3"],
        "strict_confirmed_yield_at_k": [
            {"selector_id": "fci", "model_id": "model-a", "confirmed_yield_at_k": 2 / 3}
        ],
    }

    report = analysis._representation_report(
        {"direct": direct, "direct_context": contextual}
    )

    assert report["interpretation"] == "end_to_end_representation_comparison_not_pure_selector"
    differences = report["differences_direct_context_minus_direct"]
    assert differences["candidate_coverage"] == 0.25
    assert differences["protocolization_rate"] == 0.5
    assert differences["unique_confirmed_hypotheses"] == 1


@pytest.mark.extended
def test_representation_comparison_bundle_replays_source_digests(
    tmp_path: Path, monkeypatch
) -> None:
    direct_root = tmp_path / "direct-result"
    contextual_root = tmp_path / "context-result"
    write_bundle(direct_root, {"placeholder.json": {"track": "direct"}})
    write_bundle(contextual_root, {"placeholder.json": {"track": "context"}})
    base = {
        "model_id": "model-a",
        "outcome_id": "secure_yield",
        "top_k": 3,
        "candidate_coverage": 0.5,
        "protocolization_rate": 0.5,
        "unique_confirmed_hypothesis_ids": ["h-1"],
        "strict_confirmed_yield_at_k": [
            {"selector_id": "fci", "model_id": "model-a", "confirmed_yield_at_k": 1 / 3}
        ],
        "effect_distribution": [],
    }

    def fake_summary(_root, *, role, expected_adapter_id):
        return {
            **base,
            "role": role,
            "representation_adapter_id": expected_adapter_id,
            "candidate_coverage": 0.75 if role == "direct_context" else 0.5,
        }

    monkeypatch.setattr(analysis, "_representation_summary", fake_summary)
    config = {
        "schema_version": "1.0",
        "direct": {
            "result_path": "direct-result",
            "result_bundle_sha256": bundle_digest(direct_root),
            "representation_adapter_id": "direct-v1",
        },
        "direct_context": {
            "result_path": "context-result",
            "result_bundle_sha256": bundle_digest(contextual_root),
            "representation_adapter_id": "direct-context-v1",
        },
    }
    config_path = tmp_path / "representation.json"
    config_path.write_text(canonical_json(config), encoding="utf-8")
    output = tmp_path / "representation-result"

    report = analysis.run_representation_comparison_from_config(config_path, output)

    assert report["status"] == "REPRESENTATION_COMPARISON_COMPLETE"
    assert analysis.verify_representation_comparison_bundle(output)["status"] == (
        "REPRESENTATION_COMPARISON_BUNDLE_VERIFIED"
    )


@pytest.mark.extended
def test_offline_selector_artifact_closure_and_tamper_rejection(tmp_path: Path, monkeypatch) -> None:
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
    ) = _prospective_fixture(monkeypatch)
    selection = run_selector_suite(
        manifest, rows, suite_plan, fci_relation_scores=None, expert_input=expert
    )
    selection_root = base / "selection"
    selection_config = {
        "schema_version": "2.0",
        "universe": canonical_value(manifest),
        "observations": canonical_value(rows),
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
        canonical_json({"schema_version": "2.0", "records": canonical_value(records)}),
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

    successor = base / "successor"
    estimates = []
    for index, record in enumerate(records):
        effects = [0.8, 0.4, 0.9, 0.3] if index == 0 else [0.2, -0.1, 0.1, -0.2]
        estimates.append({
            "hypothesis_id": record.final_hypothesis_id,
            "model_id": suite_plan.model_id,
            "metric": "secure_yield",
            "expected_direction": "increase",
            "task_unit_contributions": [
                {
                    "task_unit_id": f"unit-{unit}",
                    "contrast_values": [["target_minus_noop", value, value, value]],
                }
                for unit, value in enumerate(effects)
            ],
        })
    write_bundle(successor, {
        "study-freeze.json": {
            "candidate_universe_manifest_id": selection.universe.manifest_id,
            "selection_freeze_manifest_id": selection.selection_id,
            "analysis_plan": {"minimum_task_units": 2},
            "hypotheses": canonical_value(hypotheses),
        },
        "analysis.json": {"inference": {"estimates": estimates}},
    })
    monkeypatch.setattr(
        analysis,
        "verify_successor_result_bundle",
        lambda root: {"status": "SUCCESSOR_RESULT_BUNDLE_VERIFIED"},
    )
    plan = SelectorInferencePlan(19, 100, 100, 0.05, 0.5, canonical_selector_pairs())
    plan_path = base / "selector-plan.json"
    plan_path.write_text(
        canonical_json({"schema_version": "1.0", "plan": canonical_value(plan)}),
        encoding="utf-8",
    )
    result_root = base / "selector-result"
    report = run_selector_experiment_from_config(
        selection_root,
        bridge_root,
        (successor,),
        plan_path,
        result_root,
    )
    assert report["status"] == "SELECTOR_RESULT_BUNDLE_VERIFIED"
    assert verify_selector_experiment_bundle(result_root)["confirmation_coordinates"] == len(records)
    coordinates = read_json(result_root / "coordinates.json")
    assert all(item["provenance_complete"] is True for item in coordinates)
    assert coordinates[0]["task_unit_effects"][0][0] == "unit-0"

    unknown_result = base / "unknown-result"
    shutil.copytree(result_root, unknown_result)
    result_payload = read_json(unknown_result / "result.json")
    result_payload["method_points"][0]["undeclared"] = "ignored-by-old-parser"
    raw = (canonical_json(result_payload) + "\n").encode()
    (unknown_result / "result.json").write_bytes(raw)
    result_manifest = read_json(unknown_result / "manifest.json")
    result_manifest["files"]["result.json"] = hashlib.sha256(raw).hexdigest()
    (unknown_result / "manifest.json").write_bytes(
        (canonical_json(result_manifest) + "\n").encode()
    )
    with pytest.raises(SelectorExperimentError, match="method point fields are not exact"):
        verify_selector_experiment_bundle(unknown_result)

    moved = tmp_path / "moved"
    shutil.move(str(base), str(moved))
    result_root = moved / "selector-result"
    assert verify_selector_experiment_bundle(result_root)["status"] == "SELECTOR_RESULT_BUNDLE_VERIFIED"

    # Re-hash a semantic replacement: manifest integrity alone must not make it pass.
    payload = read_json(result_root / "coordinates.json")
    payload[0]["task_unit_effects"][0][1] = -0.75
    raw = (canonical_json(payload) + "\n").encode()
    (result_root / "coordinates.json").write_bytes(raw)
    manifest_value = read_json(result_root / "manifest.json")
    manifest_value["files"]["coordinates.json"] = hashlib.sha256(raw).hexdigest()
    (result_root / "manifest.json").write_bytes(
        (canonical_json(manifest_value) + "\n").encode()
    )
    with pytest.raises(SelectorExperimentError, match="do not rederive"):
        verify_selector_experiment_bundle(result_root)


@pytest.mark.extended
def test_stored_selector_result_rejects_duplicate_successor_lineage(tmp_path: Path) -> None:
    # The exact duplicate check is deliberately exercised before any source is trusted.
    root = tmp_path / "invalid"
    write_bundle(root, {
        "coordinates.json": [], "plan.json": {}, "result.json": {}, "verification.json": {},
        "lineage.json": {
            "selection_bundle_path": "missing", "selection_bundle_sha256": "0" * 64,
            "bridge_bundle_path": "missing", "bridge_bundle_sha256": "0" * 64,
            "successor_bundles": [],
        },
    })
    with pytest.raises((SelectorExperimentError, ValueError, FileNotFoundError)):
        verify_selector_experiment_bundle(root)

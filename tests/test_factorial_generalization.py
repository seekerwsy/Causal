import copy
import hashlib
import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.factorial_experiment import (
    _unknown_coverage_summary,
    freeze_factorial_experiment,
    preflight_factorial_experiment,
    run_factorial_experiment,
)
from prompt_mechanism_study.factorial_freeze import verify_factorial_freeze_bundle
from prompt_mechanism_study.factorial_protocol import FactorialExperimentError
from prompt_mechanism_study.factorial_verify import (
    _independent_unknown_coverage_summary,
    verify_factorial_result_bundle,
)
from prompt_mechanism_study.mechanisms import load_pair_registry
from prompt_mechanism_study.prompt_tsg import load_catalog
from prompt_mechanism_study.records import content_hash

ROOT = Path(__file__).resolve().parents[1]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _v11_config(
    tmp_path: Path,
    *,
    partial_overlap: bool = False,
    separately_powered: bool = False,
) -> tuple[Path, tuple]:
    catalog_path = ROOT / "data/method/prompt-tsg-pair-catalog-v1.json"
    catalog = load_catalog(catalog_path)
    registry_raw = read_json(ROOT / "data/method/mechanism-pairs-v2.json")
    first_pair = copy.deepcopy(registry_raw["pairs"][0])
    second_pair = copy.deepcopy(first_pair)
    second_pair["relation_type"] = "same_flow"
    second_pair["oracle_profile_id"] = "python.cwe89.dynamic_identifier_and_values.v1"
    second_policy_path = tmp_path / "second-oracle-policy.json"
    _write_json(
        second_policy_path,
        {
            "schema_version": "1.0",
            "profile_id": second_pair["oracle_profile_id"],
            "scope": "test-only local profile",
        },
    )
    second_pair["oracle_policy_sha256"] = _sha(second_policy_path)
    registry_raw["pairs"] = [first_pair, second_pair]
    registry_path = tmp_path / "pairs.json"
    _write_json(registry_path, registry_raw)
    registry = load_pair_registry(registry_path, catalog)

    source_tasks = read_json(
        ROOT / "data/method/factorial-sql-scaffold-canary-v1/tasks.json"
    )
    selected = source_tasks[:3] if partial_overlap else source_tasks[:2]
    tasks = []
    for source in selected:
        task = copy.deepcopy(source)
        original = task.pop("pair_binding")
        task["pair_bindings"] = []
        for pair in registry.pairs:
            binding = copy.deepcopy(original)
            binding["pair_id"] = pair.pair_id
            task["pair_bindings"].append(binding)
        tasks.append(task)
    corpus = tmp_path / "corpus"
    write_bundle(corpus, {"tasks.json": tasks, "report.json": {"tasks": len(tasks)}})

    implementation = ROOT / "src/prompt_mechanism_study/security_profiles.py"
    fixture = ROOT / "data/oracle-calibration/factorial-sql-v2-cases.json"
    qualifications = {}
    for pair in registry.pairs:
        policy_path = (
            ROOT / "data/oracle-calibration/factorial-sql-v2-policy.json"
            if pair.oracle_profile_id.endswith(".v2")
            else second_policy_path
        )
        qualification = {
            "schema_version": "1.0",
            "profile_id": pair.oracle_profile_id,
            "policy_sha256": pair.oracle_policy_sha256,
            "policy_path": str(policy_path),
            "qualification_status": "supported",
            "label_mismatches": 0,
            "gold_cells": ["a00", "a10", "a01", "a11"],
            "implementation_path": str(implementation),
            "implementation_sha256": _sha(implementation),
            "fixture_path": str(fixture),
            "fixture_sha256": _sha(fixture),
        }
        path = tmp_path / f"qualification-{pair.pair_id[-8:]}.json"
        _write_json(path, qualification)
        qualifications[pair.pair_id] = path

    base = read_json(
        ROOT / "configs/formal/factorial-sql-scaffold-repair-qwen35-v1.json"
    )
    task_ids = [item["task_id"] for item in tasks]
    pair_protocols = []
    for index, pair in enumerate(registry.pairs, start=1):
        intervention = copy.deepcopy(base["intervention"])
        intervention["factor_1_target"] = (
            f"PAIR_{index}: bind caller values with database placeholders."
        )
        intervention["factor_1_noop"] = f"PAIR_{index}: preserve value behavior."
        intervention["factor_2_target"] = (
            f"PAIR_{index}: constrain identifiers to the declared finite choices."
        )
        intervention["factor_2_noop"] = (
            f"PAIR_{index}: preserve identifier behavior."
        )
        intervention["joint_application_commutative"] = False
        qualification_path = qualifications[pair.pair_id]
        support = task_ids
        if partial_overlap and index == 2:
            support = task_ids[1:]
        pair_protocols.append(
            {
                "pair_id": pair.pair_id,
                "task_ids": support,
                "interaction_claim_scope": "policy_only",
                "factorial_compatibility": "compatible",
                "intervention": intervention,
                "security_oracle": {
                    "profile_id": pair.oracle_profile_id,
                    "policy_sha256": pair.oracle_policy_sha256,
                    "qualification_path": str(qualification_path),
                    "qualification_sha256": _sha(qualification_path),
                    "unknown_rule": "preserve_unknown_and_report_bounds",
                },
                "mechanism_trace_diagnostics": ["endpoint"],
            }
        )

    generation = copy.deepcopy(base["generation"])
    generation.pop("model_id")
    generation["models"] = [
        {"model_id": "generator-b"},
        {"model_id": "generator-a"},
    ]
    functional = copy.deepcopy(base["functional_oracle"])
    qualification = tmp_path / "functional-oracle-qualification.json"
    _write_json(
        qualification,
        read_json(ROOT / "data/functional-judge/functional-oracle-qualification.json"),
    )
    functional.update(
        {
            "qualification_path": str(qualification),
            "qualification_sha256": _sha(qualification),
        }
    )
    analysis = {
        "metrics": [
            "secure_yield",
            "code_valid",
            "oracle_evaluable",
            "functionality",
            "joint",
        ],
        "primary_metric": "secure_yield",
        "secondary_effects": [
            "factor_1",
            "factor_2",
            "factor_1_given_factor_2",
            "factor_2_given_factor_1",
            "joint",
        ],
        "bootstrap_seed": 9102,
        "bootstrap_draws": 100,
        "familywise_alpha": 0.05,
        "minimum_task_units": 2,
        "minimum_valid_bootstrap_fraction": 0.9,
        "bootstrap_quantile_method": "higher",
        "practical_interaction_margin": 0.2,
        "maximum_unknown_fraction": 0.1,
        "functionality_noninferiority_margin": 0.1,
        "functionality_noninferiority_separately_powered": separately_powered,
    }
    if separately_powered:
        power_path = tmp_path / "functionality-power-qualification.json"
        _write_json(
            power_path,
            {
                "schema_version": "1.0",
                "qualification_status": "supported",
                "analysis_coordinate": {
                    "metric": "functionality",
                    "contrast": "a11_minus_a00",
                    "unit": "task_unit",
                    "scope": "each_pair_model_coordinate",
                },
                "planned_task_units_per_coordinate": 2,
                "target_power": 0.8,
                "familywise_alpha": 0.05,
                "noninferiority_margin": 0.1,
                "power_method": "test-only synthetic paired-task calculation",
                "assumptions": {
                    "baseline_functionality_rate": 0.8,
                    "alternative_difference": 0.0,
                    "paired_task_unit_correlation": 0.5,
                },
            },
        )
        analysis["functionality_power_qualification"] = {
            "path": str(power_path),
            "sha256": _sha(power_path),
        }
    config = {
        "schema_version": "1.1",
        "study_name": "factorial-generalization-test-v1",
        "phase": "development_canary",
        "purpose": "Offline two-pair two-model runner test.",
        "corpus": {
            "path": str(corpus),
            "bundle_sha256": bundle_digest(corpus),
            "task_ids": task_ids,
            "selection_outcomes_consulted": False,
            "generalization_boundary": "test-only synthetic registry",
        },
        "pair_registry_path": str(registry_path),
        "prompt_tsg_catalog_path": str(catalog_path),
        "pair_protocols": pair_protocols,
        "generation": generation,
        "functional_oracle": functional,
        "randomization": {"seed": 9101, "slots": [0, 1, 2, 3]},
        "analysis": analysis,
        "scale_gate": "test-only; scientific claims are disabled",
        "scientific_claim_allowed": False,
    }
    config_path = tmp_path / "config.json"
    _write_json(config_path, config)
    return config_path, registry.pairs


@pytest.mark.extended
def test_v11_requires_exact_distinct_outcome_decomposition(tmp_path) -> None:
    config_path, _pairs = _v11_config(tmp_path)
    config = read_json(config_path)
    config["analysis"]["metrics"][-1] = "secure_yield"
    _write_json(config_path, config)

    with pytest.raises(
        FactorialExperimentError,
        match="five ordered, distinct outcome endpoints",
    ):
        preflight_factorial_experiment(ROOT, config_path)


@pytest.mark.extended
def test_v11_powered_functionality_gate_requires_qualification(tmp_path) -> None:
    config_path, _pairs = _v11_config(tmp_path)
    config = read_json(config_path)
    config["analysis"]["functionality_noninferiority_separately_powered"] = True
    _write_json(config_path, config)

    with pytest.raises(
        FactorialExperimentError,
        match="analysis fields are not exact",
    ):
        preflight_factorial_experiment(ROOT, config_path)


@pytest.mark.extended
def test_v11_freeze_rejects_noncompatible_pair(tmp_path) -> None:
    config_path, _pairs = _v11_config(tmp_path)
    config = read_json(config_path)
    config["pair_protocols"][0]["factorial_compatibility"] = "nested"
    _write_json(config_path, config)

    with pytest.raises(
        FactorialExperimentError,
        match="not factorial-compatible",
    ):
        preflight_factorial_experiment(ROOT, config_path)


@pytest.mark.reviewer
@pytest.mark.extended
def test_unknown_gate_conditions_on_valid_code_not_all_assignments() -> None:
    code_valid = {
        "a00": {"point": 0.5},
        "a01": {"point": 1.0},
        "a10": {"point": 0.8},
        "a11": {"point": 1.0},
    }
    evaluable = {
        "a00": {"point": 0.25},
        "a01": {"point": 0.8},
        "a10": {"point": 0.8},
        "a11": {"point": 1.0},
    }
    expected = {
        "code_valid_yield_by_cell": {
            "a00": 0.5,
            "a01": 1.0,
            "a10": 0.8,
            "a11": 1.0,
        },
        "oracle_evaluable_yield_by_cell": {
            "a00": 0.25,
            "a01": 0.8,
            "a10": 0.8,
            "a11": 1.0,
        },
        "unknown_fraction_among_valid_code_by_cell": {
            "a00": 0.5,
            "a01": pytest.approx(0.2),
            "a10": 0.0,
            "a11": 0.0,
        },
        "maximum_observed_unknown_fraction_among_valid_code": 0.5,
        "unknown_gate_evaluable": True,
        "unknown_gate_passed": False,
    }
    production = _unknown_coverage_summary(code_valid, evaluable, 0.25)
    independent = _independent_unknown_coverage_summary(
        {cell: item["point"] for cell, item in code_valid.items()},
        {cell: item["point"] for cell, item in evaluable.items()},
        0.25,
    )

    assert production == expected
    assert independent == expected
    assert production["unknown_fraction_among_valid_code_by_cell"]["a00"] == 0.5
    assert 1.0 - evaluable["a00"]["point"] == 0.75


@pytest.mark.extended
def test_v11_runner_dispatches_two_pairs_and_two_models(tmp_path, monkeypatch) -> None:
    config_path, pairs = _v11_config(tmp_path, separately_powered=True)
    generated_models = []
    oracle_profiles = []

    def provider(request, evaluator, _prompt):
        kind = request["request_kind"]
        if kind in {
            "blind_factorial_prompt_intervention",
            "blind_factorial_complete_prompt_rewrite",
        }:
            f1, f2 = request["factor_1"], request["factor_2"]
            order = "ORDER_" + "_".join(str(item) for item in request["application_order"])
            suffixes = {
                "a00_text": order + " CELL_A00 " + f1["noop"] + " " + f2["noop"],
                "a10_text": order + " CELL_A10 " + f1["target"] + " " + f2["noop"],
                "a01_text": order + " CELL_A01 " + f1["noop"] + " " + f2["target"],
                "a11_text": order + " CELL_A11 " + f1["target"] + " " + f2["target"],
            }
            if kind == "blind_factorial_prompt_intervention":
                value = suffixes
            else:
                source = request["source_prompt"]
                source_graph = request["source_prompt_tsg"]
                source_nodes = [
                    item
                    for item in source_graph["nodes"]
                    if item["semantic_id"] != "task.root"
                ]
                local_by_node = {
                    item["node_id"]: f"source_{index}"
                    for index, item in enumerate(source_nodes)
                }
                base_facts = [
                    {
                        "local_id": local_by_node[item["node_id"]],
                        "node_type": item["node_type"],
                        "semantic_id": item["semantic_id"],
                        "evidence_text": source[
                            item["evidence_start"] : item["evidence_end"]
                        ],
                        "occurrence": 1,
                        "attributes": dict(item["attributes"]),
                    }
                    for item in source_nodes
                ]
                base_relations = [
                    {
                        "edge_type": item["edge_type"],
                        "source": local_by_node[item["source_id"]],
                        "target": local_by_node[item["target_id"]],
                    }
                    for item in source_graph["edges"]
                    if item["source_id"] in local_by_node
                    and item["target_id"] in local_by_node
                ]
                value = {}
                states = {
                    "a00": (False, False),
                    "a10": (True, False),
                    "a01": (False, True),
                    "a11": (True, True),
                }
                for cell, state in states.items():
                    suffix = suffixes[f"{cell}_text"]
                    facts = copy.deepcopy(base_facts)
                    for index, present in enumerate(state):
                        if present:
                            facts.append(
                                {
                                    "local_id": f"factor_{index + 1}",
                                    "node_type": "safety_requirement",
                                    "semantic_id": request["factor_ids"][index],
                                    "evidence_text": request[f"factor_{index + 1}"][
                                        "target"
                                    ],
                                    "occurrence": 1,
                                    "attributes": {},
                                }
                            )
                    value[cell] = {
                        "prompt_text": source + "\n\n" + suffix,
                        "facts": facts,
                        "relations": copy.deepcopy(base_relations),
                        "unresolved_semantics": [],
                    }
        elif kind == "blind_factorial_prompt_validation":
            cell = {
                "task_preserved": True,
                "factor_1_state_correct": True,
                "factor_2_state_correct": True,
                "unintended_change_absent": True,
                "contradiction_absent": True,
            }
            value = {
                **{name: cell for name in ("a00", "a10", "a01", "a11")},
                "cross_cell": {
                    "functional_contract_preserved": True,
                    "pair_context_preserved": True,
                    "non_target_security_preserved": True,
                    "presentation_policy_preserved": True,
                    "no_third_requirement": True,
                    "treatment_states_distinct": True,
                },
                "reason": "The four test variants preserve the frozen contract.",
            }
        elif kind == "factorial_code_generation":
            generated_models.append(evaluator["model_id"])
            marker = next(
                item
                for item in ("ORDER_1_2", "ORDER_2_1")
                if item in request["task_prompt"]
            )
            cell = next(
                item
                for item in ("CELL_A00", "CELL_A10", "CELL_A01", "CELL_A11")
                if item in request["task_prompt"]
            )
            value = {
                "code": (
                    f"# {marker} {cell}\n"
                    "def generated():\n"
                    f"    return {evaluator['model_id']!r}\n"
                )
            }
        elif kind == "blind_functional_evaluation":
            value = {
                "verdict": "pass",
                "evidence_lines": [1],
                "reason": "The offline fixture is functionally accepted.",
            }
        else:
            raise AssertionError(kind)
        return json.dumps(value).encode()

    def security(code, profile_id):
        oracle_profiles.append(profile_id)
        secure = (
            "ORDER_1_2" in code and "CELL_A11" in code
        ) or (
            "ORDER_2_1" in code
            and any(item in code for item in ("CELL_A10", "CELL_A01"))
        )
        return {
            "security_label": "secure" if secure else "insecure",
            "decision": {
                "trace": {
                    "facts": [
                        {
                            "state": "safe" if secure else "unsafe",
                            "line": 1,
                            "sink_kind": "test",
                            "endpoint": "safe",
                        }
                    ]
                }
            },
        }

    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "test-only")
    monkeypatch.setattr(
        "prompt_mechanism_study.factorial_experiment.bailian_complete", provider
    )
    monkeypatch.setattr(
        "prompt_mechanism_study.factorial_experiment.evaluate_security_profile",
        security,
    )
    monkeypatch.setattr(
        "prompt_mechanism_study.factorial_verify.evaluate_security_profile",
        security,
    )
    output = tmp_path / "result"
    frozen = tmp_path / "freeze"
    preflight = preflight_factorial_experiment(ROOT, config_path)
    freeze_report = freeze_factorial_experiment(ROOT, config_path, frozen)
    functional_qualification_source = Path(
        read_json(config_path)["functional_oracle"]["qualification_path"]
    )
    functional_qualification_source.write_text(
        '{"status":"DRIFTED_AFTER_FREEZE"}\n', encoding="utf-8"
    )
    with pytest.raises(FactorialExperimentError, match="requires --freeze"):
        run_factorial_experiment(ROOT, config_path, tmp_path / "unfrozen-result")
    report = run_factorial_experiment(
        ROOT,
        config_path,
        output,
        freeze_root=frozen,
    )
    verified = verify_factorial_result_bundle(output)
    frozen_study = read_json(output / "study-freeze.json")
    provider_calls = read_json(output / "provider-calls.json")

    assert preflight["assignments"] == 64
    assert freeze_report["assignments"] == 64
    assert verify_factorial_freeze_bundle(frozen)["assignments"] == 64
    assert preflight["pair_ids"] == [item.pair_id for item in pairs]
    assert set(preflight["models"]) == {"generator-a", "generator-b"}
    assert report["assignments"] == 64
    assert len(report["primary_results"]) == 4
    assert "primary_interaction" not in report
    assert report["verification"]["primary_intervals"] == 0
    assert report["verification"]["primary_bootstrap"]["status"] == (
        "zero_standard_error"
    )
    assert report["verification"]["secondary_intervals"] == 0
    assert report["verification"]["metric_families"] == 0
    assert all(
        item["gate"]["functionality_gate_status"] == "not_evaluable"
        and item["gate"]["functionality_noninferior"] is None
        and item["gate"]["functionality_power_qualification_sha256"]
        == read_json(config_path)["analysis"]["functionality_power_qualification"][
            "sha256"
        ]
        and item["gate"]["practical_success_claim_ready"] is False
        for item in report["primary_results"]
    )
    assert report["security_policy_interaction_claim_ready_coordinates"] == []
    assert report["mechanism_interaction_claim_ready_coordinates"] == []
    assert report["practical_success_claim_ready_coordinates"] == []
    assert set(generated_models) == {"generator-a", "generator-b"}
    assert generated_models.count("generator-a") == 32
    assert generated_models.count("generator-b") == 32
    assert set(oracle_profiles) == {item.oracle_profile_id for item in pairs}
    for estimate in report["estimates"]:
        if estimate["metric"] != "secure_yield":
            continue
        diagnostics = estimate["realization_diagnostics"]
        by_order = {
            tuple(item["application_order"]): item["point"]
            for item in diagnostics["order_interactions"]
        }
        assert by_order == {(1, 2): 1.0, (2, 1): -2.0}
        assert len(diagnostics["leave_one_realization_out"]) == 2
        assert diagnostics["direction_robustness"] == "direction_reversal"
    assert all(
        cell["assignments"] == 4
        for pair_report in report["mechanism_trace_diagnostics"].values()
        for model_report in pair_report.values()
        for endpoint_report in model_report.values()
        for cell in endpoint_report["cells"].values()
    )
    assert verified["assignments"] == 64
    assert verified["coordinates"] == 20
    assert verified["primary_intervals"] == 0
    assert (output / "factorial-pair-registry.json").is_file()
    assert (output / "factorial-prompt-tsg-catalog.json").is_file()
    assert (output / "factorial-measurement-inputs.json").is_file()
    assert (output / "freeze-factorial-oracle-qualifications.json").is_file()
    assert (output / "freeze-factorial-functional-qualification.json").is_file()
    assert (
        output / "freeze-factorial-functionality-power-qualification.json"
    ).is_file()
    assert sum(item["stage"] == "intervention" for item in provider_calls) == 8
    assert sum(item["stage"] == "generation" for item in provider_calls) == 64
    assert sum(item["stage"] == "functional" for item in provider_calls) == 64
    assert frozen_study["pair_selection"]["source"] == "registry_selected"
    assert (
        frozen_study["pair_selection"]["selection_id"]
        == frozen_study["randomization"]["selection_id"]
    )

    frozen_payload = {
        path.name: read_json(path)
        for path in frozen.glob("*.json")
        if path.name != "manifest.json"
    }
    frozen_payload["factorial-oracle-qualifications.json"]["pairs"][0][
        "producer_sha256"
    ] = "0" * 64
    tampered_freeze = tmp_path / "tampered-oracle-freeze"
    write_bundle(tampered_freeze, frozen_payload)
    with pytest.raises(
        FactorialExperimentError, match="Oracle identity drifts"
    ):
        verify_factorial_freeze_bundle(tampered_freeze)

    payload = {
        path.name: read_json(path)
        for path in output.glob("*.json")
        if path.name != "manifest.json"
    }
    functional_tamper = copy.deepcopy(payload)
    functional_tamper[
        "freeze-factorial-functional-qualification.json"
    ]["qualification_identity"]["status"] = "DRIFTED"
    tampered_functional = tmp_path / "tampered-functional-qualification-result"
    write_bundle(tampered_functional, functional_tamper)
    with pytest.raises(ValueError, match="functional qualification"):
        verify_factorial_result_bundle(tampered_functional)

    record = next(item for item in payload["measurement-records.json"] if item["security"])
    assignment_id = record["measurement"]["assignment_id"]
    replacement = copy.deepcopy(record["security"])
    replacement["security_label"] = (
        "insecure" if replacement["security_label"] == "secure" else "secure"
    )
    record["security"] = replacement
    record["measurement"]["oracle_status"] = replacement["security_label"]
    record["measurement"]["oracle_evidence_sha256"] = content_hash(replacement)
    outcome = next(
        item
        for item in payload["analysis.json"]["outcomes"]
        if item["assignment_id"] == assignment_id
    )
    outcome["secure_yield"] = int(replacement["security_label"] == "secure")
    outcome["latent_secure_upper"] = outcome["secure_yield"]
    outcome["joint"] = outcome["secure_yield"]
    outcome["latent_joint_upper"] = outcome["secure_yield"]
    payload["report.json"]["estimates"][0]["interaction"] = 0.125
    tampered = tmp_path / "synchronized-tamper"
    write_bundle(tampered, payload)
    with pytest.raises(ValueError, match="Security Oracle findings drift"):
        verify_factorial_result_bundle(tampered)


@pytest.mark.extended
def test_v11_accepts_partially_overlapping_pair_support(tmp_path) -> None:
    config_path, _pairs = _v11_config(tmp_path, partial_overlap=True)

    report = preflight_factorial_experiment(ROOT, config_path)

    assert report["status"] == "FACTORIAL_PREFLIGHT_COMPLETE"
    assert len(report["pair_ids"]) == 2


@pytest.mark.reviewer
@pytest.mark.extended
def test_historical_v10_config_is_not_executable_but_result_remains_verifiable() -> None:
    with pytest.raises(FactorialExperimentError, match="config envelope is invalid"):
        preflight_factorial_experiment(
            ROOT,
            ROOT / "configs/formal/factorial-sql-scaffold-repair-qwen35-v1.json",
        )
    verified = verify_factorial_result_bundle(
        ROOT / "data/formal/results/factorial-sql-scaffold-repair-qwen35-v1"
    )

    assert verified["status"] == "FACTORIAL_RESULT_BUNDLE_VERIFIED"
    assert verified["assignments"] == 240

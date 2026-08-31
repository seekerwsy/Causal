import copy
import hashlib
import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.factorial_experiment import (
    _unknown_coverage_summary,
    preflight_factorial_experiment,
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
def test_v11_accepts_partially_overlapping_pair_support(tmp_path) -> None:
    config_path, _pairs = _v11_config(tmp_path, partial_overlap=True)

    report = preflight_factorial_experiment(ROOT, config_path)

    assert report["status"] == "FACTORIAL_PREFLIGHT_COMPLETE"
    assert len(report["pair_ids"]) == 2


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

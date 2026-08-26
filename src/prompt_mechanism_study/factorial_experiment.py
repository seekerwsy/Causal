"""Linear runner for the prospectively frozen pairwise factorial study."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any, Mapping

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.factorial_verify import verify_factorial_inference
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
    build_review_request,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.inference import FactorialAnalysisPlan, FactorialEffect, Metric
from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    FactorialBundleValidation,
    FactorialCell,
    FactorialExecution,
    FactorialRealizationSpec,
    SemanticValidation,
    SemanticVerdict,
    freeze_factorial_bundle,
    freeze_factorial_policy,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.mechanisms import (
    PairBinding,
    PairEligibility,
    load_pair_registry,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    load_catalog,
    prompt_tsg_from_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import canonical_value, content_hash
from prompt_mechanism_study.representation import Split, Task
from prompt_mechanism_study.security_profiles import evaluate_security_profile
from prompt_mechanism_study.workflow import analyze_factorial, freeze_factorial_study


class FactorialExperimentError(ValueError):
    """A frozen factorial input or provider output failed closed."""


def preflight_factorial_experiment(
    repository_root: Path,
    config_path: Path,
) -> dict[str, Any]:
    inputs = _load_inputs(repository_root, config_path)
    key_name = inputs["config"]["generation"]["api_key_env"]
    return {
        "schema_version": "1.0",
        "status": "FACTORIAL_PREFLIGHT_COMPLETE",
        "study_name": inputs["config"]["study_name"],
        "tasks": len(inputs["task_rows"]),
        "realizations": len(inputs["realizations"]),
        "assignments": len(inputs["task_rows"])
        * len(inputs["realizations"])
        * len(FACTORIAL_CELL_ORDER),
        "credential_env": key_name,
        "credential_present": bool(os.environ.get(key_name, "").strip()),
        "pair_id": inputs["pair"].pair_id,
        "oracle_support_status": inputs["pair"].oracle_support_status.value,
        "configured_scientific_claim_allowed": bool(
            inputs["config"].get("scientific_claim_allowed", False)
        ),
        "scientific_claim_allowed": False,
    }


def run_factorial_experiment(
    repository_root: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Run intervention, randomization, measurement, analysis, and verification once."""

    inputs = _load_inputs(repository_root, config_path)
    config = inputs["config"]
    key_name = config["generation"]["api_key_env"]
    if not os.environ.get(key_name, "").strip():
        raise FactorialExperimentError("provider credential is unavailable")
    calls: list[dict[str, Any]] = []
    bundles = []
    for task in inputs["task_rows"]:
        for realization in inputs["realizations"]:
            suffixes, executor_raw = _execute_intervention(inputs, task, realization)
            validation, validator_raw = _validate_intervention(
                inputs, task, realization, suffixes
            )
            executor_digest = hashlib.sha256(executor_raw).hexdigest()
            validator_digest = hashlib.sha256(validator_raw).hexdigest()
            executions = {
                cell: FactorialExecution(
                    task["prompt"] + "\n\n" + suffixes[cell],
                    inputs["adapters"].intervention_executor.adapter_id,
                    executor_digest,
                )
                for cell in FACTORIAL_CELL_ORDER
            }
            validations = {
                cell: _cell_validation(
                    validation[cell.value],
                    inputs["adapters"].intervention_validator.adapter_id,
                    validator_digest,
                )
                for cell in FACTORIAL_CELL_ORDER
            }
            cross = validation["cross_cell"]
            bundles.append(
                freeze_factorial_bundle(
                    inputs["pair"],
                    task_id=task["task_id"],
                    task_unit_id=task["task_unit_id"],
                    source_prompt=task["prompt"],
                    realization=realization,
                    executions=executions,
                    validations=validations,
                    bundle_validation=FactorialBundleValidation(
                        SemanticVerdict.YES,
                        _yes(cross["functional_contract_preserved"]),
                        _yes(cross["pair_context_preserved"]),
                        _yes(cross["non_target_security_preserved"]),
                        _yes(cross["presentation_policy_preserved"]),
                        _yes(cross["no_third_requirement"]),
                        _yes(cross["treatment_states_distinct"]),
                        inputs["adapters"].intervention_validator.adapter_id,
                        validator_digest,
                    ),
                )
            )
            calls.append(
                {
                    "stage": "intervention",
                    "task_id": task["task_id"],
                    "realization_id": realization.realization_id,
                    "executor_response_sha256": executor_digest,
                    "executor_response": executor_raw.decode("utf-8"),
                    "validator_response_sha256": validator_digest,
                    "validator_response": validator_raw.decode("utf-8"),
                }
            )
    policy = freeze_factorial_policy(
        inputs["pair"],
        factorial_protocol_id=config["study_name"],
        realizations=inputs["realizations"],
        bundles=tuple(bundles),
    )
    tasks = tuple(_task(row) for row in inputs["task_rows"])
    bindings = tuple(_binding(row["pair_binding"]) for row in inputs["task_rows"])
    analysis_plan = FactorialAnalysisPlan(
        tuple(Metric(item) for item in config["analysis"]["metrics"]),
        Metric(config["analysis"]["primary_metric"]),
        config["analysis"]["bootstrap_seed"],
        config["analysis"]["bootstrap_draws"],
        float(config["analysis"]["familywise_alpha"]),
        tuple(
            FactorialEffect(item)
            for item in config["analysis"].get(
                "secondary_effects", ["factor_1", "factor_2", "joint"]
            )
        ),
    )
    study = freeze_factorial_study(
        tasks,
        bindings,
        (policy,),
        inputs["adapters"],
        analysis_plan,
        prompt_tsg_catalog_sha256=inputs["registry"].prompt_tsg_catalog_sha256,
        models=(config["generation"]["model_id"],),
        slots=tuple(config["randomization"]["slots"]),
        randomization_seed=config["randomization"]["seed"],
        provider_seed=config["generation"]["seed"],
    )
    task_by_id = {row["task_id"]: row for row in inputs["task_rows"]}
    bundle_by_id = {item.task_bundle_id: item for item in policy.bundles}
    measurements = []
    measurement_records = []
    for assignment in study.randomization.assignments:
        task = task_by_id[assignment.block.task_instance_id]
        bundle = bundle_by_id[assignment.block.factorial_task_bundle_id]
        prompt = bundle.variant(assignment.cell).prompt_text
        measurement, record = _measure_assignment(
            inputs,
            assignment.assignment_id,
            assignment.provider_seed,
            task,
            prompt,
        )
        measurements.append(measurement)
        measurement_records.append(
            {
                "assignment": canonical_value(assignment),
                "measurement": canonical_value(measurement),
                **record,
            }
        )
    analysis = analyze_factorial(study, measurements)
    verification = verify_factorial_inference(
        study.randomization,
        analysis.outcomes,
        study.policies,
        study.tasks,
        study.analysis_plan,
        analysis.inference,
    )
    report = _report(config, study, analysis, verification)
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "python_dont_write_bytecode": os.environ.get("PYTHONDONTWRITEBYTECODE"),
        "credential_name": key_name,
        "credential_value_recorded": False,
    }
    write_bundle(
        output,
        {
            "effective-config.json": config,
            "environment.json": environment,
            "study-freeze.json": canonical_value(study),
            "provider-calls.json": calls,
            "measurement-records.json": measurement_records,
            "analysis.json": canonical_value(analysis),
            "verification.json": verification,
            "report.json": report,
        },
    )
    return report


def _load_inputs(repository_root: Path, config_path: Path) -> dict[str, Any]:
    root = repository_root.resolve()
    config_file = config_path if config_path.is_absolute() else root / config_path
    config = read_json(config_file)
    phase = config.get("phase")
    if config.get("schema_version") != "1.0" or phase not in {
        "development_canary",
        "confirmatory",
    }:
        raise FactorialExperimentError("factorial config envelope is invalid")
    claim_allowed = config.get("scientific_claim_allowed")
    if type(claim_allowed) is not bool or (
        phase == "development_canary" and claim_allowed
    ):
        raise FactorialExperimentError("factorial claim boundary is invalid")
    corpus_root = root / config["corpus"]["path"]
    verify_bundle(corpus_root)
    if bundle_digest(corpus_root) != config["corpus"]["bundle_sha256"]:
        raise FactorialExperimentError("factorial corpus bundle drift")
    all_tasks = read_json(corpus_root / "tasks.json")
    by_task = {item["task_id"]: item for item in all_tasks}
    selected_ids = config["corpus"]["task_ids"]
    if (
        not selected_ids
        or len(selected_ids) != len(set(selected_ids))
        or any(item not in by_task for item in selected_ids)
    ):
        raise FactorialExperimentError("factorial task selection is invalid")
    task_rows = tuple(by_task[item] for item in selected_ids)
    if len({item["task_unit_id"] for item in task_rows}) != len(task_rows):
        raise FactorialExperimentError("factorial tasks must be unique task units")
    if phase == "confirmatory" and any(item.get("split") != "confirm" for item in task_rows):
        raise FactorialExperimentError("confirmatory factorial task entered from another split")
    if config["corpus"].get("selection_outcomes_consulted") is not False or any(
        item.get("source_records_used_as_outcomes") is not False for item in task_rows
    ):
        raise FactorialExperimentError("factorial task selection is not outcome blind")
    catalog_path = root / config["prompt_tsg_catalog_path"]
    registry_path = root / config["pair_registry_path"]
    catalog = load_catalog(catalog_path)
    registry = load_pair_registry(registry_path, catalog)
    if len(registry.pairs) != 1:
        raise FactorialExperimentError("factorial study requires exactly one frozen pair")
    pair = registry.pairs[0]
    if (
        pair.oracle_profile_id != config["security_oracle"]["profile_id"]
        or pair.oracle_policy_sha256 != config["security_oracle"]["policy_sha256"]
    ):
        raise FactorialExperimentError("factorial Oracle configuration drift")
    qualification = _oracle_qualification(root, config["security_oracle"], pair)
    for row in task_rows:
        graph = prompt_tsg_from_record(row["prompt_tsg"])
        validate_prompt_tsg(graph, prompt=row["prompt"], catalog=catalog)
        binding = _binding(row["pair_binding"])
        if (
            binding.decision is not PairEligibility.APPLICABLE
            or binding.pair_id != pair.pair_id
            or binding.task_id != row["task_id"]
        ):
            raise FactorialExperimentError("non-applicable task entered the factorial study")
    intervention = config["intervention"]
    executor = _locked_json(root, intervention, "executor_config")
    validator = _locked_json(root, intervention, "validator_config")
    executor_prompt = _locked_text(root, intervention, "executor_prompt")
    validator_prompt = _locked_text(root, intervention, "validator_prompt")
    generation_prompt = _locked_text(root, config["generation"], "prompt")
    functional = config["functional_oracle"]
    functional_evaluator = _locked_json(root, functional, "evaluator_config")
    functional_prompt = _locked_text(root, functional, "prompt")
    adapters = _adapters(
        registry,
        executor,
        validator,
        config["generation"],
        pair.oracle_profile_id,
        pair.oracle_policy_sha256,
        functional_evaluator,
        functional_prompt,
    )
    realizations = tuple(
        sorted(
            (
                FactorialRealizationSpec(
                    row["label"],
                    row["weight"],
                    adapters.intervention_executor.adapter_id,
                    intervention["factor_1_target"],
                    intervention["factor_1_noop"],
                    intervention["factor_2_target"],
                    intervention["factor_2_noop"],
                    tuple(row["application_order"]),
                )
                for row in intervention["joint_realizations"]
            ),
            key=lambda item: item.realization_id,
        )
    )
    return {
        "root": root,
        "config": config,
        "catalog": catalog,
        "registry": registry,
        "pair": pair,
        "oracle_qualification": qualification,
        "task_rows": task_rows,
        "executor": executor,
        "executor_prompt": executor_prompt,
        "validator": validator,
        "validator_prompt": validator_prompt,
        "generation_prompt": generation_prompt,
        "functional_evaluator": functional_evaluator,
        "functional_prompt": functional_prompt,
        "adapters": adapters,
        "realizations": realizations,
    }


def _execute_intervention(
    inputs: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
) -> tuple[dict[FactorialCell, str], bytes]:
    request = {
        "request_kind": "blind_factorial_prompt_intervention",
        "source_prompt": task["prompt"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "factor_1": {
            "target": realization.factor_1_target_instruction,
            "noop": realization.factor_1_noop_instruction,
        },
        "factor_2": {
            "target": realization.factor_2_target_instruction,
            "noop": realization.factor_2_noop_instruction,
        },
        "application_order": list(realization.application_order),
        "blindness": {"generated_code": False, "oracle_outcomes": False, "effect_direction": False},
    }
    raw = bailian_complete(request, inputs["executor"], inputs["executor_prompt"])
    value = _json_object(raw)
    expected = {f"{cell.value}_text" for cell in FACTORIAL_CELL_ORDER}
    if set(value) != expected:
        raise FactorialExperimentError("factorial executor response schema drift")
    maximum = inputs["config"]["intervention"]["maximum_suffix_characters"]
    result = {}
    for cell in FACTORIAL_CELL_ORDER:
        text = value[f"{cell.value}_text"]
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or len(text) > maximum
            or "\n" in text
            or "\r" in text
        ):
            raise FactorialExperimentError("factorial executor suffix format drift")
        result[cell] = text
    if len(set(result.values())) != len(FACTORIAL_CELL_ORDER):
        raise FactorialExperimentError("factorial executor collapsed treatment cells")
    return result, raw


def _validate_intervention(
    inputs: Mapping[str, Any],
    task: Mapping[str, Any],
    realization: FactorialRealizationSpec,
    suffixes: Mapping[FactorialCell, str],
) -> tuple[dict[str, Any], bytes]:
    request = {
        "request_kind": "blind_factorial_prompt_validation",
        "source_prompt": task["prompt"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "factor_1": {
            "target": realization.factor_1_target_instruction,
            "noop": realization.factor_1_noop_instruction,
        },
        "factor_2": {
            "target": realization.factor_2_target_instruction,
            "noop": realization.factor_2_noop_instruction,
        },
        "application_order": list(realization.application_order),
        "variants": {
            cell.value: task["prompt"] + "\n\n" + suffixes[cell]
            for cell in FACTORIAL_CELL_ORDER
        },
        "blindness": {"generated_code": False, "oracle_outcomes": False, "model_identity": False},
    }
    raw = bailian_complete(request, inputs["validator"], inputs["validator_prompt"])
    value = _json_object(raw)
    if set(value) != {"a00", "a10", "a01", "a11", "cross_cell", "reason"}:
        raise FactorialExperimentError("factorial validator response schema drift")
    cell_fields = {
        "task_preserved",
        "factor_1_state_correct",
        "factor_2_state_correct",
        "unintended_change_absent",
        "contradiction_absent",
    }
    cross_fields = {
        "functional_contract_preserved",
        "pair_context_preserved",
        "non_target_security_preserved",
        "presentation_policy_preserved",
        "no_third_requirement",
        "treatment_states_distinct",
    }
    for cell in FACTORIAL_CELL_ORDER:
        if not isinstance(value[cell.value], dict) or set(value[cell.value]) != cell_fields:
            raise FactorialExperimentError("factorial validator cell schema drift")
    if not isinstance(value["cross_cell"], dict) or set(value["cross_cell"]) != cross_fields:
        raise FactorialExperimentError("factorial validator cross-cell schema drift")
    flags = [
        flag
        for cell in FACTORIAL_CELL_ORDER
        for flag in value[cell.value].values()
    ] + list(value["cross_cell"].values())
    if any(type(flag) is not bool for flag in flags) or not all(flags):
        raise FactorialExperimentError("factorial semantic validation failed")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise FactorialExperimentError("factorial validator reason is empty")
    return value, raw


def _measure_assignment(
    inputs: Mapping[str, Any],
    assignment_id: str,
    provider_seed: int | None,
    task: Mapping[str, Any],
    prompt: str,
) -> tuple[Measurement, dict[str, Any]]:
    evaluator = dict(inputs["config"]["generation"])
    if provider_seed is None:
        raise FactorialExperimentError("factorial assignment lacks a frozen provider seed")
    evaluator["seed"] = provider_seed
    request = {
        "request_kind": "factorial_code_generation",
        "task_prompt": prompt,
        "language": "python",
        "output_schema": {"code": "complete Python source string"},
    }
    raw = bailian_complete(request, evaluator, inputs["generation_prompt"])
    value = _json_object(raw)
    code = value.get("code") if set(value) == {"code"} else None
    if not isinstance(code, str):
        raise FactorialExperimentError("generator response schema drift")
    generator_digest = hashlib.sha256(raw).hexdigest()
    if not code.strip() or not python_syntax_valid(code):
        status = CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID
        return (
            Measurement(
                assignment_id,
                status,
                OracleStatus.NOT_RUN,
                FunctionalStatus.NOT_RUN,
                generator_digest,
                content_hash(code) if code else None,
                terminal_reason=status.value,
            ),
            {
                "generation_request": request,
                "generation_response": raw.decode("utf-8"),
                "code": code,
                "security": None,
                "functional_request": None,
                "functional_response": None,
            },
        )
    security = evaluate_security_profile(
        code, inputs["config"]["security_oracle"]["profile_id"]
    )
    contract = task["functional_contract"]
    functional_request = build_review_request(
        code,
        task["prompt"],
        requirements=contract["requirements"],
        environment_dependencies=contract["environment_dependencies"],
    )
    functional_raw = bailian_complete(
        functional_request,
        inputs["functional_evaluator"],
        inputs["functional_prompt"],
    )
    functional = validate_review_response(functional_raw, code)
    measurement = Measurement(
        assignment_id,
        CodeStatus.VALID,
        OracleStatus(security["security_label"]),
        FunctionalStatus(functional["status"]),
        generator_digest,
        content_hash(code),
        content_hash(security),
        hashlib.sha256(functional_raw).hexdigest(),
    )
    return measurement, {
        "generation_request": request,
        "generation_response": raw.decode("utf-8"),
        "code": code,
        "security": security,
        "functional_request": functional_request,
        "functional_response": functional_raw.decode("utf-8"),
        "functional_validated": functional,
    }


def _report(config: Mapping[str, Any], study: Any, analysis: Any, verification: Mapping[str, Any]) -> dict[str, Any]:
    estimates = []
    for estimate in analysis.inference.estimates:
        estimates.append(
            {
                "pair_id": estimate.pair_id,
                "model_id": estimate.model_id,
                "metric": estimate.metric.value,
                "cells": {
                    item.cell.value: {
                        "point": item.point,
                        "lower": item.lower,
                        "upper": item.upper,
                        "assignments": item.assignments,
                    }
                    for item in estimate.cells
                },
                "factor_1": estimate.factor_1,
                "factor_2": estimate.factor_2,
                "joint": estimate.joint,
                "interaction": estimate.interaction,
                "factor_1_bounds": list(estimate.factor_1_bounds),
                "factor_2_bounds": list(estimate.factor_2_bounds),
                "joint_bounds": list(estimate.joint_bounds),
                "interaction_bounds": list(estimate.interaction_bounds),
            }
        )
    intervals = [
        {
            "coordinate_id": item.coordinate_id,
            "effect": item.effect.value,
            "standard_error": item.standard_error,
            "lower": item.lower,
            "upper": item.upper,
        }
        for item in analysis.inference.intervals
    ]
    secondary_intervals = [
        {
            "coordinate_id": item.coordinate_id,
            "effect": item.effect.value,
            "standard_error": item.standard_error,
            "lower": item.lower,
            "upper": item.upper,
            "excludes_zero": item.lower > 0.0 or item.upper < 0.0,
        }
        for item in analysis.inference.secondary_intervals
    ]
    primary = next(item for item in estimates if item["metric"] == "secure_yield")
    interval = intervals[0] if intervals else None
    significant = bool(interval and (interval["lower"] > 0.0 or interval["upper"] < 0.0))
    functionality = next(item for item in estimates if item["metric"] == "functionality")
    evaluability = next(item for item in estimates if item["metric"] == "oracle_evaluable")
    analysis_config = config["analysis"]
    functionality_margin = float(analysis_config["functionality_noninferiority_margin"])
    unknown_limit = float(analysis_config.get("maximum_unknown_fraction", 1.0))
    practical_margin = float(analysis_config.get("practical_interaction_margin", 0.0))
    minimum_evaluability = min(
        item["point"] for item in evaluability["cells"].values() if item["point"] is not None
    )
    primary_gate = {
        "security_interval_excludes_zero": significant,
        "practical_interaction_margin": practical_margin,
        "practical_interaction_met": primary["interaction"] is not None
        and abs(primary["interaction"]) >= practical_margin,
        "functionality_contrast": "a11_minus_a00",
        "functionality_difference": functionality["joint"],
        "functionality_noninferiority_margin": functionality_margin,
        "functionality_noninferior": functionality["joint"] is not None
        and functionality["joint"] >= -functionality_margin,
        "maximum_unknown_fraction": unknown_limit,
        "minimum_oracle_evaluability": minimum_evaluability,
        "unknown_gate_passed": minimum_evaluability >= 1.0 - unknown_limit,
    }
    primary_gate["claim_ready"] = bool(
        config.get("scientific_claim_allowed", False)
        and all(
            primary_gate[name]
            for name in (
                "security_interval_excludes_zero",
                "practical_interaction_met",
                "functionality_noninferior",
                "unknown_gate_passed",
            )
        )
    )
    return {
        "schema_version": "1.0",
        "status": (
            "FACTORIAL_CONFIRMATION_COMPLETE"
            if config["phase"] == "confirmatory"
            else "FACTORIAL_CANARY_COMPLETE"
        ),
        "study_name": config["study_name"],
        "study_id": study.study_id,
        "tasks": len(study.tasks),
        "realizations": len(study.policies[0].realizations),
        "assignments": len(study.randomization.assignments),
        "primary_estimand": "assigned-cell task-unit ITT interaction on risk difference",
        "primary_interaction": primary["interaction"],
        "primary_simultaneous_interval": interval,
        "primary_interval_excludes_zero": significant,
        "primary_gate": primary_gate,
        "estimates": estimates,
        "simultaneous_critical_value": analysis.inference.simultaneous_critical_value,
        "secondary_intervals": secondary_intervals,
        "secondary_critical_value": analysis.inference.secondary_critical_value,
        "verification": dict(verification),
        "scientific_claim_allowed": bool(config.get("scientific_claim_allowed", False)),
        "claim_boundary": config["corpus"]["generalization_boundary"],
        "scale_gate": config["scale_gate"],
    }


def _cell_validation(
    value: Mapping[str, bool], validator_adapter_id: str, evidence_sha256: str
) -> SemanticValidation:
    return SemanticValidation(
        _yes(value["task_preserved"]),
        _yes(value["factor_1_state_correct"] and value["factor_2_state_correct"]),
        SemanticVerdict.NO if value["unintended_change_absent"] else SemanticVerdict.YES,
        SemanticVerdict.NO if value["contradiction_absent"] else SemanticVerdict.YES,
        validator_adapter_id,
        evidence_sha256,
    )


def _yes(value: bool) -> SemanticVerdict:
    return SemanticVerdict.YES if value else SemanticVerdict.NO


def _task(row: Mapping[str, Any]) -> Task:
    return Task(
        row["task_id"],
        row["task_unit_id"],
        row["cwe"],
        row["archetype"],
        Split(row["split"]),
        row["prompt"],
        row["weight"],
    )


def _binding(value: Mapping[str, Any]) -> PairBinding:
    return PairBinding(
        value["pair_id"],
        value["task_id"],
        value["prompt_tsg_id"],
        PairEligibility(value["decision"]),
        value["context_query_id"],
        QueryState(value["context_state"]),
        tuple((feature, QueryState(state)) for feature, state in value["factor_states"]),
        tuple(tuple(item) for item in value["neutral_counterpart_ids"]),
        tuple(value["evidence_node_ids"]),
        tuple(value["evidence_edge_ids"]),
        value["outcomes_or_arms_used"],
    )


def _adapters(
    registry: Any,
    executor: Mapping[str, Any],
    validator: Mapping[str, Any],
    generation: Mapping[str, Any],
    oracle_profile_id: str,
    oracle_policy_sha256: str,
    functional_evaluator: Mapping[str, Any],
    functional_prompt: str,
) -> AdapterBundle:
    return AdapterBundle(
        AdapterSpec(AdapterKind.REPRESENTATION, "prompt-tsg-pair-catalog", "1", registry.prompt_tsg_catalog_sha256),
        AdapterSpec(AdapterKind.SELECTOR, "preregistered-pair-registry", "1", content_hash(registry)),
        AdapterSpec(AdapterKind.INTERVENTION_EXECUTOR, executor["candidate_id"], "1", content_hash(executor)),
        AdapterSpec(AdapterKind.INTERVENTION_VALIDATOR, validator["candidate_id"], "1", content_hash(validator)),
        AdapterSpec(AdapterKind.GENERATOR, generation["model_id"], "1", content_hash(generation)),
        AdapterSpec(AdapterKind.SECURITY_ORACLE, oracle_profile_id, "1", oracle_policy_sha256),
        AdapterSpec(
            AdapterKind.FUNCTIONAL_EVALUATOR,
            functional_evaluator["candidate_id"],
            "1",
            content_hash({"evaluator": functional_evaluator, "prompt": functional_prompt}),
        ),
    )


def _oracle_qualification(root: Path, section: Mapping[str, Any], pair: Any) -> dict[str, Any]:
    path = root / section["qualification_path"]
    if "qualification_sha256" in section:
        _require_file_hash(path, section["qualification_sha256"])
    qualification = read_json(path)
    if not isinstance(qualification, dict):
        raise FactorialExperimentError("Oracle qualification must be a JSON object")
    if (
        qualification.get("profile_id") != pair.oracle_profile_id
        or qualification.get("policy_sha256") != pair.oracle_policy_sha256
        or qualification.get("qualification_status") != "supported"
        or qualification.get("label_mismatches") != 0
        or set(qualification.get("gold_cells", [])) != {
            cell.value for cell in FACTORIAL_CELL_ORDER
        }
    ):
        raise FactorialExperimentError("Oracle qualification is unsupported or incomplete")
    for stem in ("implementation", "fixture"):
        locked_path = root / qualification[f"{stem}_path"]
        _require_file_hash(locked_path, qualification[f"{stem}_sha256"])
    return qualification


def _locked_json(root: Path, section: Mapping[str, Any], stem: str) -> dict[str, Any]:
    path = root / section[f"{stem}_path"]
    _require_file_hash(path, section[f"{stem}_sha256"])
    value = read_json(path)
    if not isinstance(value, dict):
        raise FactorialExperimentError(f"{stem} must be a JSON object")
    return value


def _locked_text(root: Path, section: Mapping[str, Any], stem: str) -> str:
    path = root / section[f"{stem}_path"]
    _require_file_hash(path, section[f"{stem}_sha256"])
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise FactorialExperimentError(f"{stem} is empty")
    return value


def _require_file_hash(path: Path, expected: str) -> None:
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise FactorialExperimentError(f"frozen file drift: {path}")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FactorialExperimentError("provider response is not valid JSON") from None
    if not isinstance(value, dict):
        raise FactorialExperimentError("provider response is not a JSON object")
    return value


__all__ = [
    "FactorialExperimentError",
    "preflight_factorial_experiment",
    "run_factorial_experiment",
]

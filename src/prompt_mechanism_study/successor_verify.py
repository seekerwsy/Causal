"""Offline verifier for complete successor bundles and four-arm inference.

Bundle replay reconstructs measurement and artifact bindings from stored raw
evidence.  The inference verifier deliberately does not import the production
estimator: it independently rebuilds block support, task-unit arm values,
contrasts, unknown bounds, and the three bootstrap families.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from prompt_mechanism_study.adapters import AdapterBundle
from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
)
from prompt_mechanism_study.functional_judge import (
    build_review_request,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.inference import (
    FamilyInferenceStatus,
    FunctionalityGateStatus,
    LeaveOneRealizationOutSuccessorEffect,
    Metric,
    RealizationSuccessorEffect,
    SuccessorAnalysisPlan,
    SuccessorArmEstimate,
    SuccessorContrast,
    SuccessorContrastEstimate,
    SuccessorCoordinateEstimate,
    SuccessorFamilyInference,
    SuccessorInferenceResult,
    SuccessorIntervalFamily,
    SuccessorRobustnessAssessment,
    SuccessorRobustnessComponent,
    SuccessorRobustnessInference,
    SuccessorRobustnessInterval,
    SuccessorSimultaneousInterval,
    TaskUnitSuccessorContribution,
)
from prompt_mechanism_study.intervention import (
    SUCCESSOR_ARM_ROLE_ORDER,
    InterventionPolicyV2,
    PolicyArmRoleV2,
    TaskRealizationBundleV2,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.randomization import (
    SuccessorAssignment,
    SuccessorBlockKey,
    SuccessorRandomization,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.representation import ExpectedDirection, Task
from prompt_mechanism_study.security_profiles import evaluate_security_profile
from prompt_mechanism_study.successor_experiment import (
    SuccessorExperimentError,
    _analysis_plan,
    _cross_model_replication,
    _json_object,
    _list,
    _object,
    _require_canonical_record,
    _stored_analysis_plan,
    _stored_hypothesis,
    _stored_policy,
    _stored_randomization,
    _stored_source_eligibility,
    _stored_task,
    _strings,
    _successor_report_estimates,
    _successor_report_families,
    _text,
    _validate_successor_config_envelope,
    _verify_execution_evidence,
    _verify_intervention_calls,
    _verify_stored_selection_provenance,
)


class SuccessorVerificationError(ValueError):
    """A stored successor result does not replay from its frozen inputs."""


def verify_successor_result_bundle(root: Path) -> dict[str, Any]:
    """Verify stored successor evidence without trusting its saved verifier output."""

    manifest = verify_bundle(root)
    expected_files = {
        "effective-config.json",
        "environment.json",
        "selection-evidence.json",
        "materialization-freeze.json",
        "execution-evidence.json",
        "study-freeze.json",
        "provider-calls.json",
        "measurement-records.json",
        "analysis.json",
        "verification.json",
        "report.json",
    }
    if set(manifest["files"]) != expected_files:
        raise SuccessorExperimentError("successor result artifact set is not exact")
    config = _object(read_json(root / "effective-config.json"), "stored config")
    selection_evidence = _object(
        read_json(root / "selection-evidence.json"),
        "stored selection evidence",
    )
    materialization = _object(
        read_json(root / "materialization-freeze.json"),
        "stored materialization binding",
    )
    if set(materialization) != {"bundle_sha256", "study_freeze_id", "execution_order_sha256"}:
        raise SuccessorExperimentError("stored materialization binding drifts")
    execution_evidence = _object(
        read_json(root / "execution-evidence.json"),
        "stored execution evidence",
    )
    study = _object(read_json(root / "study-freeze.json"), "stored study")
    if materialization.get("study_freeze_id") != content_id(
        "successor_study_freeze_", study
    ):
        raise SuccessorExperimentError("stored materialization study identity drifts")
    provider_calls = _list(
        read_json(root / "provider-calls.json"),
        "stored provider calls",
    )
    records = _list(read_json(root / "measurement-records.json"), "stored measurements")
    analysis = _object(read_json(root / "analysis.json"), "stored analysis")
    stored_verification = _object(
        read_json(root / "verification.json"),
        "stored verification",
    )
    report = _object(read_json(root / "report.json"), "stored report")
    _validate_successor_config_envelope(config)
    if config.get("schema_version") != "2.0" or report.get("schema_version") != "2.0":
        raise SuccessorExperimentError("stored successor schema version drift")

    randomization = _object(study.get("randomization"), "stored randomization")
    config_plan = _analysis_plan(_object(config.get("analysis"), "stored config analysis"))
    stored_plan = _stored_analysis_plan(
        _object(study.get("analysis_plan"), "stored analysis plan")
    )
    if config_plan != stored_plan:
        raise SuccessorExperimentError(
            "stored successor analysis plan drifts from effective config"
        )
    _verify_stored_selection_provenance(
        config,
        selection_evidence,
        study,
        report,
        randomization,
    )
    assignments = tuple(
        _object(value, "stored assignment")
        for value in _list(randomization.get("assignments"), "stored assignments")
    )
    if not assignments:
        raise SuccessorExperimentError("stored successor randomization is empty")
    assignment_by_id = {
        content_id("successor_assignment_v2_", item): item for item in assignments
    }
    if len(assignment_by_id) != len(assignments):
        raise SuccessorExperimentError("stored successor assignments are duplicated")

    policies = tuple(
        _object(value, "stored policy")
        for value in _list(study.get("policies"), "stored policies")
    )
    bundle_by_id: dict[str, dict[str, Any]] = {}
    for policy in policies:
        for raw_bundle in _list(policy.get("bundles"), "stored task bundles"):
            bundle = _object(raw_bundle, "stored task bundle")
            bundle_id = content_id("task_realization_bundle_v2_", bundle)
            if bundle_id in bundle_by_id:
                raise SuccessorExperimentError("stored successor bundles are duplicated")
            bundle_by_id[bundle_id] = bundle
    _verify_stored_assignment_variants(assignments, bundle_by_id, config)
    typed_randomization = _stored_randomization(randomization)
    typed_policies = tuple(_stored_policy(value) for value in policies)
    typed_tasks = tuple(
        _stored_task(_object(value, "stored task"))
        for value in _list(study.get("tasks"), "stored tasks")
    )
    contracts, oracle_by_hypothesis, frozen_adapters = _verify_execution_evidence(
        config,
        execution_evidence,
        study,
        typed_policies,
        typed_tasks,
    )

    record_by_assignment: dict[str, dict[str, Any]] = {}
    for raw_record in records:
        record = _object(raw_record, "stored measurement record")
        assignment = _object(record.get("assignment"), "measurement assignment")
        assignment_id = content_id("successor_assignment_v2_", assignment)
        measurement = _object(record.get("measurement"), "stored measurement")
        if (
            assignment_id in record_by_assignment
            or assignment_id not in assignment_by_id
            or assignment != assignment_by_id[assignment_id]
            or measurement.get("assignment_id") != assignment_id
        ):
            raise SuccessorExperimentError("stored measurement assignment binding drift")
        record_by_assignment[assignment_id] = record
    if set(record_by_assignment) != set(assignment_by_id):
        raise SuccessorExperimentError("stored measurements do not close all assignments")
    replayed_measurements = _replay_measurements_and_provider_calls(
        record_by_assignment,
        provider_calls,
        typed_randomization,
        typed_policies,
        typed_tasks,
        contracts,
        oracle_by_hypothesis,
        frozen_adapters,
    )
    generation_order = tuple(
        item["assignment_id"]
        for item in sorted(
            (
                _object(value, "stored generation call")
                for value in provider_calls
                if isinstance(value, dict) and value.get("stage") == "generation"
            ),
            key=lambda item: item.get("execution_ordinal"),
        )
    )
    if content_hash(generation_order) != materialization.get("execution_order_sha256"):
        raise SuccessorExperimentError("stored execution order drifts from materialization")

    ledger = _object(analysis.get("ledger"), "stored ledger")
    recomputed_study_id = content_id("successor_study_v2_", study)
    if (
        analysis.get("study_id") != recomputed_study_id
        or ledger.get("study_id") != recomputed_study_id
        or report.get("study_id") != recomputed_study_id
    ):
        raise SuccessorExperimentError("stored successor study identity drifts")
    ledger_measurements = tuple(
        _object(value, "ledger measurement")
        for value in _list(ledger.get("measurements"), "ledger measurements")
    )
    ledger_by_assignment = {item.get("assignment_id"): item for item in ledger_measurements}
    stored_record_measurements = {
        key: _object(value["measurement"], "record measurement")
        for key, value in record_by_assignment.items()
    }
    if (
        len(ledger_by_assignment) != len(ledger_measurements)
        or stored_record_measurements != replayed_measurements
        or ledger_by_assignment != replayed_measurements
    ):
        raise SuccessorExperimentError(
            "stored measurements do not replay from closed provider evidence"
        )

    recomputed_outcomes = {
        assignment_id: _stored_outcome(measurement)
        for assignment_id, measurement in replayed_measurements.items()
    }
    stored_outcomes = tuple(
        _object(value, "stored outcome")
        for value in _list(analysis.get("outcomes"), "stored outcomes")
    )
    outcome_by_assignment = {item.get("assignment_id"): item for item in stored_outcomes}
    if (
        len(outcome_by_assignment) != len(stored_outcomes)
        or outcome_by_assignment != recomputed_outcomes
    ):
        raise SuccessorExperimentError("stored outcomes do not replay from measurements")

    coordinates = _recompute_stored_coordinates(study, assignments, recomputed_outcomes)
    _compare_stored_coordinates(coordinates, analysis, report)
    typed_outcomes = tuple(
        _stored_outcome_record(value) for value in stored_outcomes
    )
    stored_hypotheses = tuple(
        _stored_hypothesis(_object(value, "stored hypothesis"))
        for value in _list(study.get("hypotheses"), "stored hypotheses")
    )
    if (
        len(stored_hypotheses) != len(typed_policies)
        or {item.hypothesis_id for item in stored_hypotheses}
        != {item.hypothesis_id for item in typed_policies}
    ):
        raise SuccessorExperimentError(
            "stored successor hypotheses drift from intervention policies"
        )
    stored_eligibilities = tuple(
        _stored_source_eligibility(_object(value, "stored source eligibility"))
        for value in _list(
            study.get("source_eligibilities"),
            "stored source eligibilities",
        )
    )
    policy_eligibilities = tuple(
        eligibility
        for policy in typed_policies
        for eligibility in policy.source_eligibilities
    )
    eligible_stored_ids = {
        item.source_eligibility_id
        for item in stored_eligibilities
        if item.eligible
    }
    if (
        len(eligible_stored_ids) != len(policy_eligibilities)
        or eligible_stored_ids
        != {item.source_eligibility_id for item in policy_eligibilities}
    ):
        raise SuccessorExperimentError(
            "stored successor source eligibilities drift from intervention policies"
        )
    observed_inference = _stored_inference_result(
        _object(analysis.get("inference"), "stored inference")
    )
    try:
        independent_verification = verify_successor_inference(
            typed_randomization,
            typed_outcomes,
            typed_policies,
            typed_tasks,
            stored_plan,
            observed_inference,
            maximum_unknown_fraction=float(
                _object(config.get("analysis"), "stored config analysis")[
                    "maximum_unknown_fraction"
                ]
            ),
            scientific_claim_allowed=bool(config["scientific_claim_allowed"]),
            functionality_power_qualification_sha256=(
                None
                if not stored_plan.functionality_noninferiority_separately_powered
                else _object(
                    _object(config["analysis"], "stored config analysis")[
                        "functionality_power_qualification"
                    ],
                    "stored functionality power reference",
                )["sha256"]
            ),
        )
    except ValueError as error:
        raise SuccessorExperimentError(
            f"stored successor independent inference replay failed: {error}"
        ) from error
    if report.get("cross_model_replication") != _cross_model_replication(
        stored_plan, stored_hypotheses, observed_inference
    ):
        raise SuccessorExperimentError("stored cross-model replication label drifts")
    _verify_stored_inference_report(
        report,
        stored_verification,
        stored_plan,
        observed_inference,
        independent_verification,
    )
    unknown = sum(
        measurement.get("oracle_status") == OracleStatus.UNKNOWN.value
        for measurement in replayed_measurements.values()
    )
    if (
        report.get("assignments") != len(assignments)
        or report.get("ledger_measurements") != len(records)
        or report.get("oracle_unknown_assignments") != unknown
        or report.get("unknown_preserved_not_imputed_secure") is not True
    ):
        raise SuccessorExperimentError("stored report assignment or unknown accounting drift")
    return {
        "status": "SUCCESSOR_RESULT_BUNDLE_VERIFIED",
        "assignments": len(assignments),
        "blocks": len(
            {content_id("successor_block_v2_", item["block"]) for item in assignments}
        ),
        "measurements": len(records),
        "coordinates": len(coordinates),
        "unknown_assignments": unknown,
        "bundle_sha256": bundle_digest(root),
    }


def _verify_stored_assignment_variants(
    assignments: tuple[dict[str, Any], ...],
    bundle_by_id: Mapping[str, dict[str, Any]],
    config: Mapping[str, Any],
) -> None:
    roles = tuple(role.value for role in SUCCESSOR_ARM_ROLE_ORDER)
    slots = tuple(config["randomization"]["request_randomness_slots"])
    model_ids = {item["model_id"] for item in config["generation"]["models"]}
    by_block: dict[str, list[dict[str, Any]]] = {}
    provider_seed_states = set()
    for assignment in assignments:
        block = _object(assignment.get("block"), "stored assignment block")
        bundle_id = block.get("task_realization_bundle_id")
        bundle = bundle_by_id.get(bundle_id)
        if bundle is None:
            raise SuccessorExperimentError("stored assignment references an unknown bundle")
        variants = tuple(
            _object(value, "stored prompt variant")
            for value in _list(bundle.get("variants"), "stored prompt variants")
        )
        variant_by_role = {item.get("role"): item for item in variants}
        if set(variant_by_role) != set(roles) or len(variant_by_role) != len(variants):
            raise SuccessorExperimentError("stored task bundle lacks exact four-arm support")
        prompt_hashes = {
            role: content_hash(variant_by_role[role].get("prompt_text")) for role in roles
        }
        if len(set(prompt_hashes.values())) != len(roles):
            raise SuccessorExperimentError("stored task bundle prompt variants are not distinct")
        role = assignment.get("arm_role")
        variant = variant_by_role.get(role)
        if (
            role not in roles
            or assignment.get("variant_sha256") != prompt_hashes[role]
            or assignment.get("arm_label") != variant.get("arm_label")
            or block.get("task_unit_id") != bundle.get("task_unit_id")
            or block.get("task_instance_id") != bundle.get("task_id")
            or block.get("hypothesis_id") != bundle.get("hypothesis_id")
            or block.get("target_spec_id") != bundle.get("target_spec_id")
            or block.get("realization_spec_id") != bundle.get("realization_spec_id")
            or block.get("arm_protocol_id") != bundle.get("arm_protocol_id")
            or block.get("model_id") not in model_ids
            or assignment.get("request_randomness_slot") not in slots
        ):
            raise SuccessorExperimentError("stored assignment variant or block binding drift")
        provider_seed = assignment.get("provider_seed")
        if provider_seed is not None and (type(provider_seed) is not int or provider_seed < 0):
            raise SuccessorExperimentError("stored provider seed is invalid")
        provider_seed_states.add(provider_seed is None)
        block_id = content_id("successor_block_v2_", block)
        by_block.setdefault(block_id, []).append(assignment)
    if len(provider_seed_states) != 1:
        raise SuccessorExperimentError("stored provider seed support is inconsistent")
    for block in by_block.values():
        block_id = content_id("successor_block_v2_", block[0]["block"])
        expected_roles = list(roles) * (len(slots) // len(roles))
        block_seed = int(
            content_hash({"seed": config["randomization"]["seed"], "block_id": block_id})[
                :16
            ],
            16,
        )
        random.Random(block_seed).shuffle(expected_roles)
        expected_by_slot = dict(zip(slots, expected_roles, strict=True))
        master_provider_seed = config["randomization"]["provider_seed"]
        if (
            len(block) != len(slots)
            or {item["request_randomness_slot"] for item in block} != set(slots)
            or set(Counter(item["arm_role"] for item in block)) != set(roles)
            or len(set(Counter(item["arm_role"] for item in block).values())) != 1
            or any(
                item["arm_role"] != expected_by_slot[item["request_randomness_slot"]]
                or item["provider_seed"]
                != (
                    None
                    if master_provider_seed is None
                    else int(
                        content_hash(
                            {
                                "provider_seed": master_provider_seed,
                                "block_id": block_id,
                                "request_randomness_slot": item[
                                    "request_randomness_slot"
                                ],
                                "arm_role": item["arm_role"],
                            }
                        )[:8],
                        16,
                    )
                    & 0x7FFFFFFF
                )
                for item in block
            )
        ):
            raise SuccessorExperimentError("stored complete-block replay or balance drift")


def _stored_outcome(measurement: Mapping[str, Any]) -> dict[str, Any]:
    assignment_id = measurement.get("assignment_id")
    code_status = measurement.get("code_status")
    oracle_status = measurement.get("oracle_status")
    functional_status = measurement.get("functional_status")
    if code_status not in {item.value for item in CodeStatus}:
        raise SuccessorExperimentError("stored code status is invalid")
    if oracle_status not in {item.value for item in OracleStatus} or functional_status not in {
        item.value for item in FunctionalStatus
    }:
        raise SuccessorExperimentError("stored evaluator status is invalid")
    if code_status != CodeStatus.VALID.value:
        if (
            oracle_status != OracleStatus.NOT_RUN.value
            or functional_status != FunctionalStatus.NOT_RUN.value
        ):
            raise SuccessorExperimentError("terminal code has a stored evaluator result")
        return {
            "assignment_id": assignment_id,
            "code_valid": 0,
            "oracle_evaluable": 0,
            "secure_yield": 0,
            "latent_secure_upper": 0,
            "functionality": 0,
            "joint": 0,
            "latent_joint_upper": 0,
            "terminal_status": code_status,
        }
    if (
        oracle_status == OracleStatus.NOT_RUN.value
        or functional_status == FunctionalStatus.NOT_RUN.value
    ):
        raise SuccessorExperimentError("valid code lacks a stored evaluator result")
    evaluable = int(oracle_status in {OracleStatus.SECURE.value, OracleStatus.INSECURE.value})
    secure = int(oracle_status == OracleStatus.SECURE.value)
    latent_secure_upper = int(
        oracle_status in {OracleStatus.SECURE.value, OracleStatus.UNKNOWN.value}
    )
    functionality = {
        FunctionalStatus.PASS.value: 1,
        FunctionalStatus.FAIL.value: 0,
        FunctionalStatus.UNKNOWN.value: None,
    }[functional_status]
    if oracle_status == OracleStatus.INSECURE.value or functionality == 0:
        joint = 0
    elif oracle_status == OracleStatus.UNKNOWN.value or functionality is None:
        joint = None
    else:
        joint = 1
    return {
        "assignment_id": assignment_id,
        "code_valid": 1,
        "oracle_evaluable": evaluable,
        "secure_yield": secure,
        "latent_secure_upper": latent_secure_upper,
        "functionality": functionality,
        "joint": joint,
        "latent_joint_upper": int(latent_secure_upper == 1 and functionality != 0),
        "terminal_status": None,
    }


def _recompute_stored_coordinates(
    study: Mapping[str, Any],
    assignments: tuple[dict[str, Any], ...],
    outcomes: Mapping[str, dict[str, Any]],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    tasks = {
        item["task_id"]: item
        for item in (
            _object(value, "stored task")
            for value in _list(study.get("tasks"), "stored tasks")
        )
    }
    policies = tuple(
        _object(value, "stored policy")
        for value in _list(study.get("policies"), "stored policies")
    )
    models = tuple(study["randomization"]["models"])
    metrics = tuple(study["analysis_plan"]["metrics"])
    assignment_rows = tuple(
        (content_id("successor_assignment_v2_", assignment), assignment)
        for assignment in assignments
    )
    result = {}
    for policy in policies:
        hypothesis_id = content_id("frozen_hypothesis_v2_", policy["hypothesis"])
        realizations = tuple(
            (
                content_id("realization_spec_v2_", realization),
                realization["weight"],
            )
            for realization in policy["realization_policy"]["realizations"]
        )
        if not realizations or any(
            type(weight) is not int or weight <= 0 for _, weight in realizations
        ):
            raise SuccessorExperimentError("stored realization weights are invalid")
        for model_id in models:
            selected = tuple(
                (assignment_id, assignment)
                for assignment_id, assignment in assignment_rows
                if assignment["block"]["hypothesis_id"] == hypothesis_id
                and assignment["block"]["model_id"] == model_id
            )
            task_units = sorted({item[1]["block"]["task_unit_id"] for item in selected})
            if not task_units:
                raise SuccessorExperimentError("stored inference coordinate has no assignments")
            for metric in metrics:
                arms = {}
                for role in (item.value for item in SUCCESSOR_ARM_ROLE_ORDER):
                    units = [
                        _stored_unit_arm(
                            selected,
                            outcomes,
                            tasks,
                            realizations,
                            task_unit_id,
                            role,
                            metric,
                        )
                        for task_unit_id in task_units
                    ]
                    arms[role] = {
                        "point": None
                        if any(item[0] is None for item in units)
                        else sum(item[0] for item in units if item[0] is not None) / len(units),
                        "lower": sum(item[1] for item in units) / len(units),
                        "upper": sum(item[2] for item in units) / len(units),
                        "assignments": sum(
                            assignment["arm_role"] == role for _, assignment in selected
                        ),
                    }
                contrasts = {}
                for name, right in (
                    ("target_minus_noop", "noop"),
                    ("target_minus_placebo", "placebo"),
                    ("target_minus_generic", "generic"),
                ):
                    target = arms["target"]
                    control = arms[right]
                    contrasts[name] = {
                        "point": _stored_difference(target["point"], control["point"]),
                        "lower_bound": target["lower"] - control["upper"],
                        "upper_bound": target["upper"] - control["lower"],
                    }
                result[(hypothesis_id, model_id, metric)] = {
                    "arms": arms,
                    "contrasts": contrasts,
                }
    return result


def _stored_unit_arm(
    assignments: tuple[tuple[str, dict[str, Any]], ...],
    outcomes: Mapping[str, dict[str, Any]],
    tasks: Mapping[str, Mapping[str, Any]],
    realizations: tuple[tuple[str, int], ...],
    task_unit_id: str,
    role: str,
    metric: str,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            assignment["block"]["task_instance_id"]
            for _, assignment in assignments
            if assignment["block"]["task_unit_id"] == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise SuccessorExperimentError("stored task-unit support is invalid")
    task_total = sum(tasks[task_id]["weight"] for task_id in task_ids)
    realization_total = sum(weight for _, weight in realizations)
    point = lower = upper = 0.0
    point_known = True
    for task_id in task_ids:
        task_weight = tasks[task_id]["weight"] / task_total
        for realization_id, raw_weight in realizations:
            block = tuple(
                assignment_id
                for assignment_id, assignment in assignments
                if assignment["block"]["task_unit_id"] == task_unit_id
                and assignment["block"]["task_instance_id"] == task_id
                and assignment["block"]["realization_spec_id"] == realization_id
                and assignment["arm_role"] == role
            )
            if not block:
                raise SuccessorExperimentError("stored common realization support is incomplete")
            values = tuple(_stored_metric(outcomes[item], metric) for item in block)
            weight = task_weight * raw_weight / realization_total
            if any(item[0] is None for item in values):
                point_known = False
            else:
                point += (
                    weight
                    * sum(item[0] for item in values if item[0] is not None)
                    / len(values)
                )
            lower += weight * sum(item[1] for item in values) / len(values)
            upper += weight * sum(item[2] for item in values) / len(values)
    return point if point_known else None, lower, upper


def _stored_metric(outcome: Mapping[str, Any], metric: str) -> tuple[int | None, int, int]:
    if metric == Metric.SECURE_YIELD.value:
        return outcome["secure_yield"], outcome["secure_yield"], outcome["latent_secure_upper"]
    if metric == Metric.JOINT.value:
        return outcome["joint"], outcome["joint"] or 0, outcome["latent_joint_upper"]
    value = outcome.get(metric)
    if value is None:
        return None, 0, 1
    if value not in {0, 1}:
        raise SuccessorExperimentError("stored outcome metric is not binary")
    return value, value, value


def _replay_measurements_and_provider_calls(
    records: Mapping[str, Mapping[str, Any]],
    raw_calls: list[Any],
    randomization: SuccessorRandomization,
    policies: tuple[InterventionPolicyV2, ...],
    tasks: tuple[Task, ...],
    contracts: Mapping[str, Mapping[str, Any]],
    oracles: Mapping[str, Mapping[str, Any]],
    adapters: AdapterBundle,
) -> dict[str, dict[str, Any]]:
    calls = tuple(_object(raw, "stored provider call") for raw in raw_calls)
    intervention_calls = tuple(item for item in calls if item.get("stage") == "intervention")
    generation_calls = tuple(item for item in calls if item.get("stage") == "generation")
    functional_calls = tuple(item for item in calls if item.get("stage") == "functional_judge")
    if len(intervention_calls) + len(generation_calls) + len(functional_calls) != len(calls):
        raise SuccessorExperimentError("stored provider call stage is invalid")
    policy_by_hypothesis = {item.hypothesis_id: item for item in policies}
    task_by_id = {item.task_id: item for item in tasks}
    bundles = {
        bundle.task_realization_bundle_id: bundle
        for policy in policies
        for bundle in policy.bundles
    }
    _verify_intervention_calls(
        intervention_calls,
        policy_by_hypothesis,
        task_by_id,
        contracts,
        adapters,
    )
    generation_by_assignment = _calls_by_assignment(generation_calls, "generation")
    functional_by_assignment = _calls_by_assignment(functional_calls, "functional_judge")
    assignment_by_id = {item.assignment_id: item for item in randomization.assignments}
    if set(generation_by_assignment) != set(assignment_by_id):
        raise SuccessorExperimentError("stored generation calls do not close assignments")
    ordinals = {
        assignment_id: call.get("execution_ordinal")
        for assignment_id, call in generation_by_assignment.items()
    }
    if set(ordinals.values()) != set(range(len(assignment_by_id))):
        raise SuccessorExperimentError("stored global execution order is not a permutation")
    replayed = {}
    expected_functional_ids = set()
    for assignment_id, assignment in assignment_by_id.items():
        record = records[assignment_id]
        task = task_by_id[assignment.block.task_instance_id]
        contract = contracts[task.task_id]
        bundle = bundles[assignment.block.task_realization_bundle_id]
        prompt = bundle.variant(assignment.arm_role).prompt_text
        generation_request = {
            "request_kind": "successor_code_generation",
            "task_prompt": prompt,
            "language": contract.get("language", "python"),
            "output_schema": {"code": "complete source string"},
        }
        generation_call = generation_by_assignment[assignment_id]
        _validate_provider_timing(generation_call)
        expected_observable = {
            "model_id": assignment.block.model_id,
            "provider_seed": assignment.provider_seed,
            "request_randomness_slot": assignment.request_randomness_slot,
        }
        raw_response = _text(generation_call.get("response"), "generation response")
        response_digest = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
        if (
            generation_call.get("request") != generation_request
            or record.get("generation_request") != generation_request
            or record.get("generation_response") != raw_response
            or generation_call.get("response_sha256") != response_digest
            or generation_call.get("model_id") != assignment.block.model_id
            or generation_call.get("provider_seed") != assignment.provider_seed
            or record.get("generation_model_id") != assignment.block.model_id
            or generation_call.get("provider_observable_state") != expected_observable
        ):
            raise SuccessorExperimentError("stored generation evidence binding drifts")
        generation = _json_object(raw_response.encode("utf-8"), "stored generator response")
        if set(generation) != {"code"} or not isinstance(generation["code"], str):
            raise SuccessorExperimentError("stored generator response schema drifts")
        code = generation["code"]
        syntax_valid = contract.get("language", "python") == "python" and python_syntax_valid(code)
        if record.get("code") != code or record.get("syntax_valid") is not syntax_valid:
            raise SuccessorExperimentError("stored code or syntax evidence drifts")
        if not code.strip() or not syntax_valid:
            status = CodeStatus.NO_CODE if not code.strip() else CodeStatus.INVALID
            if (
                record.get("security") is not None
                or record.get("functional_request") is not None
                or record.get("functional_response") is not None
                or assignment_id in functional_by_assignment
            ):
                raise SuccessorExperimentError("terminal measurement evidence is not closed")
            measurement = Measurement(
                assignment_id,
                status,
                OracleStatus.NOT_RUN,
                FunctionalStatus.NOT_RUN,
                response_digest,
                content_hash(code) if code else None,
                terminal_reason=status.value,
            )
        else:
            oracle = oracles[assignment.block.hypothesis_id]
            profile_id = oracle["profile_id"]
            if record.get("security_profile_id") != profile_id:
                raise SuccessorExperimentError("stored security Oracle profile drifts")
            security = evaluate_security_profile(code, profile_id)
            if record.get("security") != security:
                raise SuccessorExperimentError("stored security Oracle result drifts")
            functional_request = build_review_request(
                code,
                task.prompt,
                requirements=_list(contract["requirements"], "functional requirements"),
                environment_dependencies=_strings(
                    contract.get("environment_dependencies"),
                    "environment dependencies",
                ),
                language=contract.get("language", "python"),
            )
            functional_call = functional_by_assignment.get(assignment_id)
            if functional_call is None:
                raise SuccessorExperimentError("stored functional call is missing")
            expected_functional_ids.add(assignment_id)
            _validate_provider_timing(functional_call)
            if (
                functional_call.get("execution_ordinal") != ordinals[assignment_id]
                or functional_call.get("provider_observable_state") != expected_observable
                or any(
                    functional_call.get(name) != generation_call.get(name)
                    for name in (
                        "assignment_elapsed_ns",
                        "assignment_elapsed_ms",
                        "assignment_started_utc",
                        "assignment_ended_utc",
                    )
                )
            ):
                raise SuccessorExperimentError("stored functional execution order drifts")
            functional_response = _text(
                functional_call.get("response"),
                "functional response",
            )
            functional_digest = hashlib.sha256(
                functional_response.encode("utf-8")
            ).hexdigest()
            if (
                functional_call.get("request") != functional_request
                or record.get("functional_request") != functional_request
                or record.get("functional_response") != functional_response
                or functional_call.get("response_sha256") != functional_digest
            ):
                raise SuccessorExperimentError("stored functional evidence binding drifts")
            functional = validate_review_response(
                functional_response.encode("utf-8"),
                code,
            )
            if record.get("functional_validated") != functional:
                raise SuccessorExperimentError("stored functional validation drifts")
            measurement = Measurement(
                assignment_id,
                CodeStatus.VALID,
                OracleStatus(security["security_label"]),
                FunctionalStatus(functional["status"]),
                response_digest,
                content_hash(code),
                content_hash(security),
                functional_digest,
            )
        replayed[assignment_id] = canonical_value(measurement)
    if set(functional_by_assignment) != expected_functional_ids:
        raise SuccessorExperimentError("stored functional provider calls are not exact")
    return replayed


def _validate_provider_timing(call: Mapping[str, Any]) -> None:
    elapsed_ns = call.get("assignment_elapsed_ns")
    elapsed_ms = call.get("assignment_elapsed_ms")
    try:
        started = datetime.fromisoformat(call.get("assignment_started_utc"))
        ended = datetime.fromisoformat(call.get("assignment_ended_utc"))
    except (TypeError, ValueError):
        raise SuccessorExperimentError("stored provider timing is invalid") from None
    if (
        type(elapsed_ns) is not int
        or elapsed_ns < 0
        or type(elapsed_ms) is not float
        or elapsed_ms != elapsed_ns / 1_000_000.0
        or started.tzinfo is None
        or ended.tzinfo is None
        or ended < started
    ):
        raise SuccessorExperimentError("stored provider timing is invalid")


def _calls_by_assignment(
    calls: tuple[dict[str, Any], ...],
    stage: str,
) -> dict[str, dict[str, Any]]:
    result = {}
    for call in calls:
        assignment_id = call.get("assignment_id")
        if not isinstance(assignment_id, str) or assignment_id in result:
            raise SuccessorExperimentError(f"stored {stage} calls are duplicated")
        result[assignment_id] = call
    return result


def _compare_stored_coordinates(
    expected: Mapping[tuple[str, str, str], Mapping[str, Any]],
    analysis: Mapping[str, Any],
    report: Mapping[str, Any],
) -> None:
    inference = _object(analysis.get("inference"), "stored inference")
    analysis_rows = tuple(
        _object(value, "stored analysis estimate")
        for value in _list(inference.get("estimates"), "stored analysis estimates")
    )
    report_rows = tuple(
        _object(value, "stored report estimate")
        for value in _list(report.get("estimates"), "stored report estimates")
    )
    analysis_by_key = {
        (item.get("hypothesis_id"), item.get("model_id"), item.get("metric")): item
        for item in analysis_rows
    }
    report_by_key = {
        (item.get("hypothesis_id"), item.get("model_id"), item.get("metric")): item
        for item in report_rows
    }
    if (
        len(analysis_by_key) != len(analysis_rows)
        or len(report_by_key) != len(report_rows)
        or set(analysis_by_key) != set(expected)
        or set(report_by_key) != set(expected)
    ):
        raise SuccessorExperimentError("stored successor coordinate support drift")
    for key, value in expected.items():
        analysis_row = analysis_by_key[key]
        report_row = report_by_key[key]
        analysis_arms = {
            item["role"]: item for item in analysis_row.get("arms", ())
        }
        report_arms = _object(report_row.get("arms"), "stored report arms")
        if set(analysis_arms) != set(value["arms"]) or set(report_arms) != set(value["arms"]):
            raise SuccessorExperimentError("stored four-arm support drift")
        for role, expected_arm in value["arms"].items():
            _compare_numbers(expected_arm, analysis_arms[role], ("point", "lower", "upper"))
            _compare_numbers(expected_arm, report_arms[role], ("point", "lower", "upper"))
            if (
                analysis_arms[role].get("assignments") != expected_arm["assignments"]
                or report_arms[role].get("assignments") != expected_arm["assignments"]
            ):
                raise SuccessorExperimentError("stored arm assignment count drift")
        analysis_contrasts = {
            item["contrast"]: item for item in analysis_row.get("contrasts", ())
        }
        report_contrasts = _object(
            report_row.get("contrasts"), "stored report contrasts"
        )
        if set(analysis_contrasts) != set(value["contrasts"]) or set(report_contrasts) != set(
            value["contrasts"]
        ):
            raise SuccessorExperimentError("stored three-contrast support drift")
        for contrast, expected_contrast in value["contrasts"].items():
            fields = ("point", "lower_bound", "upper_bound")
            _compare_numbers(expected_contrast, analysis_contrasts[contrast], fields)
            _compare_numbers(expected_contrast, report_contrasts[contrast], fields)


def _compare_numbers(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    fields: tuple[str, ...],
) -> None:
    for field in fields:
        left = expected[field]
        right = observed.get(field)
        if left is None or right is None:
            if left is not right:
                raise SuccessorExperimentError("stored successor estimate missingness drift")
        elif not isinstance(right, (int, float)) or abs(float(left) - float(right)) > 1e-12:
            raise SuccessorExperimentError("stored successor estimate or unknown bound drift")


def _stored_difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _verify_stored_inference_report(
    report: Mapping[str, Any],
    stored_verification: Mapping[str, Any],
    plan: SuccessorAnalysisPlan,
    inference: SuccessorInferenceResult,
    independent_verification: Mapping[str, Any],
) -> None:
    if (
        report.get("analysis_plan_id") != plan.analysis_plan_id
        or report.get("inference_id") != inference.inference_id
    ):
        raise SuccessorExperimentError(
            "stored report analysis plan or inference identity drifts"
        )
    if report.get("estimates") != _successor_report_estimates(inference):
        raise SuccessorExperimentError("stored report successor estimates drift")
    if report.get("bootstrap_families") != _successor_report_families(inference):
        raise SuccessorExperimentError("stored report bootstrap families drift")
    expected_robustness = (
        None if inference.robustness is None else canonical_value(inference.robustness)
    )
    if report.get("realization_robustness") != expected_robustness:
        raise SuccessorExperimentError("stored report realization robustness drifts")
    if (
        report.get("claim_assessments")
        != independent_verification.get("claim_assessments")
        or report.get("security_claim_ready_coordinates")
        != independent_verification.get("security_claim_ready_coordinates")
        or report.get("practical_success_claim_ready_coordinates")
        != independent_verification.get(
            "practical_success_claim_ready_coordinates"
        )
        or report.get("inference_practical_labels_are_diagnostic_not_claims")
        is not True
    ):
        raise SuccessorExperimentError("stored successor claim gates drift")
    expected_verification = dict(independent_verification)
    if (
        dict(stored_verification) != expected_verification
        or report.get("verification") != expected_verification
    ):
        raise SuccessorExperimentError("stored successor verification summary drifts")


def _stored_outcome_record(value: Mapping[str, Any]) -> Outcome:
    try:
        outcome = Outcome(
            value["assignment_id"],
            value["code_valid"],
            value["oracle_evaluable"],
            value["secure_yield"],
            value["latent_secure_upper"],
            value["functionality"],
            value["joint"],
            value["latent_joint_upper"],
            value["terminal_status"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor outcome is invalid") from None
    _require_canonical_record(outcome, value, "stored successor outcome")
    return outcome


def _stored_task_unit_contribution(
    value: Mapping[str, Any],
) -> TaskUnitSuccessorContribution:
    return TaskUnitSuccessorContribution(
        value["task_unit_id"],
        tuple(
            (PolicyArmRoleV2(role), point, lower, upper)
            for role, point, lower, upper in value["arm_values"]
        ),
        tuple(
            (SuccessorContrast(contrast), point, lower, upper)
            for contrast, point, lower, upper in value["contrast_values"]
        ),
    )


def _stored_realization_effect(value: Mapping[str, Any]) -> RealizationSuccessorEffect:
    return RealizationSuccessorEffect(
        value["realization_spec_id"],
        value["point"],
        value["lower_bound"],
        value["upper_bound"],
        tuple(tuple(item) for item in value["task_unit_effects"]),
    )


def _stored_loro_effect(
    value: Mapping[str, Any],
) -> LeaveOneRealizationOutSuccessorEffect:
    return LeaveOneRealizationOutSuccessorEffect(
        value["omitted_realization_spec_id"],
        value["point"],
        value["lower_bound"],
        value["upper_bound"],
        tuple(tuple(item) for item in value["task_unit_effects"]),
    )


def _stored_coordinate(value: Mapping[str, Any]) -> SuccessorCoordinateEstimate:
    coordinate = SuccessorCoordinateEstimate(
        value["hypothesis_id"],
        value["model_id"],
        Metric(value["metric"]),
        ExpectedDirection(value["expected_direction"]),
        tuple(
            SuccessorArmEstimate(
                PolicyArmRoleV2(item["role"]),
                item["point"],
                item["lower"],
                item["upper"],
                item["assignments"],
            )
            for item in (_object(raw, "stored successor arm estimate") for raw in value["arms"])
        ),
        tuple(
            SuccessorContrastEstimate(
                SuccessorContrast(item["contrast"]),
                item["point"],
                item["lower_bound"],
                item["upper_bound"],
            )
            for item in (_object(raw, "stored successor contrast estimate") for raw in value["contrasts"])
        ),
        tuple(
            _stored_task_unit_contribution(
                _object(item, "stored task-unit contribution")
            )
            for item in value["task_unit_contributions"]
        ),
        tuple(
            _stored_realization_effect(_object(item, "stored realization effect"))
            for item in value["realization_effects"]
        ),
        value["robustness_label"],
        tuple(
            _stored_loro_effect(_object(item, "stored LORO effect"))
            for item in value["leave_one_realization_out"]
        ),
    )
    _require_canonical_record(coordinate, value, "stored successor coordinate")
    return coordinate


def _stored_family(value: Mapping[str, Any]) -> SuccessorFamilyInference:
    family = SuccessorFamilyInference(
        SuccessorIntervalFamily(value["family"]),
        FamilyInferenceStatus(value["status"]),
        value["simultaneous_critical_value"],
        value["valid_bootstrap_draws"],
        value["invalid_bootstrap_draws"],
        tuple(
            SuccessorSimultaneousInterval(
                item["coordinate_id"],
                SuccessorContrast(item["contrast"]),
                item["standard_error"],
                item["lower"],
                item["upper"],
            )
            for item in (_object(raw, "stored simultaneous interval") for raw in value["intervals"])
        ),
    )
    _require_canonical_record(family, value, "stored successor family")
    return family


def _stored_robustness(value: Mapping[str, Any]) -> SuccessorRobustnessInference:
    robustness = SuccessorRobustnessInference(
        FamilyInferenceStatus(value["status"]),
        value["simultaneous_critical_value"],
        value["valid_bootstrap_draws"],
        value["invalid_bootstrap_draws"],
        tuple(
            SuccessorRobustnessInterval(
                item["coordinate_id"],
                SuccessorRobustnessComponent(item["component"]),
                item["realization_spec_id"],
                item["standard_error"],
                item["lower"],
                item["upper"],
            )
            for item in (_object(raw, "stored robustness interval") for raw in value["intervals"])
        ),
        value["functionality_simultaneous_critical_value"],
        tuple(
            SuccessorRobustnessAssessment(
                item["coordinate_id"],
                item["direction_consistency_proportion"],
                item["direction_consistency_passed"],
                item["simultaneous_direction_passed"],
                item["minimum_support_passed"],
                item["heterogeneity_max_deviation"],
                item["heterogeneity_simultaneous_upper"],
                item["heterogeneity_equivalence_passed"],
                item["arm_realization_interaction_statistic"],
                item["arm_realization_randomization_p_value"],
                item["arm_realization_interaction_passed"],
                FunctionalityGateStatus(item["functionality_gate_status"]),
                item["functionality_point"],
                item["functionality_simultaneous_lower"],
                item["robustness_label"],
                item["practical_success_label"],
            )
            for item in (_object(raw, "stored robustness assessment") for raw in value["assessments"])
        ),
    )
    _require_canonical_record(robustness, value, "stored successor robustness")
    return robustness


def _stored_inference_result(value: Mapping[str, Any]) -> SuccessorInferenceResult:
    try:
        raw_robustness = value["robustness"]
        result = SuccessorInferenceResult(
            value["plan_id"],
            tuple(
                _stored_coordinate(_object(item, "stored successor coordinate"))
                for item in value["estimates"]
            ),
            tuple(
                _stored_family(_object(item, "stored successor family"))
                for item in value["families"]
            ),
            (
                None
                if raw_robustness is None
                else _stored_robustness(
                    _object(raw_robustness, "stored successor robustness")
                )
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor inference is invalid") from None
    _require_canonical_record(result, value, "stored successor inference")
    return result


def _replace_robustness_label(
    estimate: SuccessorCoordinateEstimate,
    label: str | None,
) -> SuccessorCoordinateEstimate:
    return estimate if label is None else replace(estimate, robustness_label=label)


def verify_successor_inference(
    randomization: SuccessorRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[InterventionPolicyV2],
    tasks: Iterable[Task],
    plan: SuccessorAnalysisPlan,
    observed: SuccessorInferenceResult,
    *,
    maximum_unknown_fraction: float | None = None,
    scientific_claim_allowed: bool | None = None,
    functionality_power_qualification_sha256: str | None = None,
) -> dict[str, object]:
    """Independently reconstruct and compare one successor inference result."""

    frozen_policies = tuple(policies)
    frozen_tasks = tuple(tasks)
    frozen_outcomes = tuple(outcomes)
    _verify_randomization(randomization, frozen_policies, frozen_tasks)

    assignment_ids = tuple(item.assignment_id for item in randomization.assignments)
    outcome_by_assignment = {item.assignment_id: item for item in frozen_outcomes}
    if (
        len(outcome_by_assignment) != len(frozen_outcomes)
        or set(outcome_by_assignment) != set(assignment_ids)
    ):
        raise SuccessorVerificationError(
            "outcomes must cover every successor assignment exactly once"
        )
    policy_by_hypothesis = {item.hypothesis_id: item for item in frozen_policies}
    if len(policy_by_hypothesis) != len(frozen_policies):
        raise SuccessorVerificationError("successor policies bind duplicate hypotheses")
    task_by_id = {item.task_id: item for item in frozen_tasks}
    if len(task_by_id) != len(frozen_tasks):
        raise SuccessorVerificationError("successor tasks contain duplicate task ids")

    estimates = tuple(
        _coordinate(
            randomization,
            outcome_by_assignment,
            policy_by_hypothesis[hypothesis_id],
            task_by_id,
            model_id,
            metric,
            plan,
        )
        for hypothesis_id in sorted(policy_by_hypothesis)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    families = tuple(_family(estimates, family, plan) for family in SuccessorIntervalFamily)
    robustness = _robustness_inference(estimates, policy_by_hypothesis, plan)
    labels = {
        item.coordinate_id: item.robustness_label
        for item in robustness.assessments
    }
    estimates = tuple(
        _replace_robustness_label(
            item,
            (
                labels.get(item.coordinate_id, "not_evaluable")
                if item.metric is plan.primary_metric
                else "not_applicable_non_primary"
            ),
        )
        for item in estimates
    )
    if observed.plan_id != plan.analysis_plan_id:
        raise SuccessorVerificationError("stored successor analysis plan identity drift")
    if observed.estimates != estimates:
        raise SuccessorVerificationError("stored successor estimate drift")
    if observed.families != families:
        raise SuccessorVerificationError("stored successor bootstrap family drift")
    if observed.robustness != robustness:
        raise SuccessorVerificationError("stored successor robustness family drift")
    claim_assessments = (
        []
        if maximum_unknown_fraction is None and scientific_claim_allowed is None
        else _claim_assessments(
            estimates,
            robustness,
            plan,
            maximum_unknown_fraction,
            scientific_claim_allowed,
            functionality_power_qualification_sha256,
        )
    )
    return {
        "status": "SUCCESSOR_INFERENCE_VERIFIED",
        "assignments": len(randomization.assignments),
        "outcomes": len(frozen_outcomes),
        "coordinates": len(estimates),
        "families": len(families),
        "family_statuses": {
            item.family.value: item.status.value for item in families
        },
        "intervals": sum(len(item.intervals) for item in families),
        "robustness_intervals": len(robustness.intervals),
        "claim_assessments": claim_assessments,
        "security_claim_ready_coordinates": [
            item["coordinate_id"]
            for item in claim_assessments
            if item["gate"]["security_claim_ready"]
        ],
        "practical_success_claim_ready_coordinates": [
            item["coordinate_id"]
            for item in claim_assessments
            if item["gate"]["practical_success_claim_ready"]
        ],
    }


def _claim_assessments(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    robustness: SuccessorRobustnessInference,
    plan: SuccessorAnalysisPlan,
    maximum_unknown_fraction: float | None,
    scientific_claim_allowed: bool | None,
    functionality_power_qualification_sha256: str | None,
) -> list[dict[str, object]]:
    """Rebuild claim gates from task-unit endpoint estimates, not raw failures."""

    if (
        type(maximum_unknown_fraction) is not float
        or not 0.0 <= maximum_unknown_fraction <= 1.0
        or type(scientific_claim_allowed) is not bool
    ):
        raise SuccessorVerificationError("successor claim gate configuration is invalid")
    if plan.functionality_noninferiority_separately_powered:
        if not isinstance(functionality_power_qualification_sha256, str):
            raise SuccessorVerificationError(
                "powered functionality gate lacks frozen qualification"
            )
    elif functionality_power_qualification_sha256 is not None:
        raise SuccessorVerificationError(
            "unrequested functionality power qualification entered inference"
        )
    by_key = {
        (item.hypothesis_id, item.model_id, item.metric): item
        for item in estimates
    }
    assessment_by_coordinate = {
        item.coordinate_id: item for item in robustness.assessments
    }
    rows: list[dict[str, object]] = []
    for secure in sorted(
        (item for item in estimates if item.metric is Metric.SECURE_YIELD),
        key=lambda item: (item.hypothesis_id, item.model_id),
    ):
        key = (secure.hypothesis_id, secure.model_id)
        code_valid = by_key.get((*key, Metric.CODE_VALID))
        evaluable = by_key.get((*key, Metric.ORACLE_EVALUABLE))
        if code_valid is None or evaluable is None:
            raise SuccessorVerificationError(
                "successor claim gate lacks code-validity or Oracle-evaluability endpoint"
            )
        code_by_arm = {item.role.value: item.point for item in code_valid.arms}
        evaluable_by_arm = {item.role.value: item.point for item in evaluable.arms}
        if set(code_by_arm) != set(evaluable_by_arm):
            raise SuccessorVerificationError("successor claim gate arm support drifts")
        unknown: dict[str, float | None] = {}
        for role in sorted(code_by_arm):
            valid = code_by_arm[role]
            oracle = evaluable_by_arm[role]
            if valid is None or oracle is None:
                unknown[role] = None
            elif not 0.0 <= oracle <= valid <= 1.0:
                raise SuccessorVerificationError(
                    "Oracle evaluability is not a subset of valid code"
                )
            else:
                unknown[role] = None if valid == 0.0 else (valid - oracle) / valid
        observed_unknown = [item for item in unknown.values() if item is not None]
        unknown_evaluable = len(observed_unknown) == len(unknown)
        maximum = max(observed_unknown) if observed_unknown else None
        unknown_passed = bool(
            unknown_evaluable
            and maximum is not None
            and maximum <= maximum_unknown_fraction
        )
        robustness_assessment = assessment_by_coordinate.get(secure.coordinate_id)
        if robustness_assessment is None:
            raise SuccessorVerificationError(
                "successor claim gate lacks robustness assessment"
            )
        security_passed = robustness_assessment.robustness_label == "realization_robust"
        functionality_status = robustness_assessment.functionality_gate_status.value
        functionality_passed = (
            plan.functionality_noninferiority_separately_powered
            and robustness_assessment.functionality_gate_status
            is FunctionalityGateStatus.PASSED
            and robustness_assessment.functionality_simultaneous_lower is not None
            and robustness_assessment.functionality_simultaneous_lower
            >= -plan.functionality_noninferiority_margin
        )
        security_claim_ready = bool(
            scientific_claim_allowed and security_passed and unknown_passed
        )
        practical_ready = bool(security_claim_ready and functionality_passed)
        rows.append(
            {
                "coordinate_id": secure.coordinate_id,
                "hypothesis_id": secure.hypothesis_id,
                "model_id": secure.model_id,
                "gate": {
                    "security_gate_passed": security_passed,
                    "code_valid_yield_by_arm": code_by_arm,
                    "oracle_evaluable_yield_by_arm": evaluable_by_arm,
                    "unknown_fraction_among_valid_code_by_arm": unknown,
                    "maximum_unknown_fraction": maximum_unknown_fraction,
                    "maximum_observed_unknown_fraction_among_valid_code": maximum,
                    "unknown_gate_evaluable": unknown_evaluable,
                    "unknown_gate_passed": unknown_passed,
                    "functionality_noninferiority_separately_powered": plan.functionality_noninferiority_separately_powered,
                    "functionality_power_qualification_sha256": functionality_power_qualification_sha256,
                    "functionality_noninferiority_margin": plan.functionality_noninferiority_margin,
                    "functionality_simultaneous_lower": robustness_assessment.functionality_simultaneous_lower,
                    "functionality_gate_status": functionality_status,
                    "functionality_gate_passed": functionality_passed,
                    "security_claim_ready": security_claim_ready,
                    "practical_success_claim_ready": practical_ready,
                },
            }
        )
    return rows


def _verify_randomization(
    randomization: SuccessorRandomization,
    policies: tuple[InterventionPolicyV2, ...],
    tasks: tuple[Task, ...],
) -> None:
    assignment_ids = tuple(item.assignment_id for item in randomization.assignments)
    if len(assignment_ids) != len(set(assignment_ids)):
        raise SuccessorVerificationError("successor randomization has duplicate assignments")
    if len({item.provider_seed is None for item in randomization.assignments}) > 1:
        raise SuccessorVerificationError("successor provider-seed support is inconsistent")
    task_by_id = {item.task_id: item for item in tasks}
    if len(task_by_id) != len(tasks):
        raise SuccessorVerificationError("successor tasks contain duplicate task ids")
    expected = {
        _block(policy, bundle, model_id).block_id: (
            _block(policy, bundle, model_id),
            policy,
            bundle,
        )
        for policy in policies
        for bundle in policy.bundles
        for model_id in randomization.models
    }
    actual_block_ids = {item.block.block_id for item in randomization.assignments}
    if actual_block_ids != set(expected):
        raise SuccessorVerificationError("successor randomization block support drift")
    for block_id, (expected_block, policy, bundle) in expected.items():
        block = [
            item for item in randomization.assignments if item.block.block_id == block_id
        ]
        if len(block) != len(randomization.request_randomness_slots) or {
            item.request_randomness_slot for item in block
        } != set(randomization.request_randomness_slots):
            raise SuccessorVerificationError("successor randomization slot support drift")
        counts = Counter(item.arm_role for item in block)
        if set(counts) != set(SUCCESSOR_ARM_ROLE_ORDER) or len(set(counts.values())) != 1:
            raise SuccessorVerificationError("successor four-arm balance drift")
        protocol = policy.realization_policy.arm_protocol
        if any(
            item.block != expected_block
            or item.arm_label != protocol.label(item.arm_role)
            or item.variant_sha256 != bundle.variant(item.arm_role).variant_sha256
            for item in block
        ):
            raise SuccessorVerificationError(
                "successor assignment block, arm, or variant binding drift"
            )
        task = task_by_id.get(bundle.task_id)
        if task is None or task.semantic_cluster_id != bundle.task_unit_id:
            raise SuccessorVerificationError("successor task-unit population binding drift")


def _block(
    policy: InterventionPolicyV2,
    bundle: TaskRealizationBundleV2,
    model_id: str,
) -> SuccessorBlockKey:
    return SuccessorBlockKey(
        bundle.task_unit_id,
        bundle.task_id,
        policy.hypothesis_id,
        policy.hypothesis.target_spec.target_spec_id,
        bundle.realization_spec_id,
        bundle.task_realization_bundle_id,
        model_id,
        policy.realization_policy.arm_protocol.arm_protocol_id,
    )


def _coordinate(
    randomization: SuccessorRandomization,
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
    plan: SuccessorAnalysisPlan,
) -> SuccessorCoordinateEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.hypothesis_id == policy.hypothesis_id
        and item.block.model_id == model_id
    )
    task_unit_ids = sorted({item.block.task_unit_id for item in assignments})
    if not task_unit_ids:
        raise SuccessorVerificationError("successor coordinate has no assignments")
    values_by_unit: dict[
        str,
        dict[PolicyArmRoleV2, tuple[float | None, float, float]],
    ] = {}
    contributions = []
    for task_unit_id in task_unit_ids:
        arms = {
            role: _unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                role,
                metric,
            )
            for role in SUCCESSOR_ARM_ROLE_ORDER
        }
        values_by_unit[task_unit_id] = arms
        contributions.append(
            TaskUnitSuccessorContribution(
                task_unit_id,
                tuple(
                    (role, *arms[role]) for role in SUCCESSOR_ARM_ROLE_ORDER
                ),
                tuple(
                    (
                        contrast,
                        _difference(
                            arms[contrast.roles[0]][0],
                            arms[contrast.roles[1]][0],
                        ),
                        arms[contrast.roles[0]][1] - arms[contrast.roles[1]][2],
                        arms[contrast.roles[0]][2] - arms[contrast.roles[1]][1],
                    )
                    for contrast in SuccessorContrast
                ),
            )
        )
    arms = tuple(
        _arm_estimate(
            assignments,
            role,
            tuple(values_by_unit[task_unit_id][role] for task_unit_id in task_unit_ids),
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    )
    arm_by_role = {item.role: item for item in arms}
    contrasts = tuple(
        SuccessorContrastEstimate(
            contrast,
            _difference(
                arm_by_role[contrast.roles[0]].point,
                arm_by_role[contrast.roles[1]].point,
            ),
            arm_by_role[contrast.roles[0]].lower
            - arm_by_role[contrast.roles[1]].upper,
            arm_by_role[contrast.roles[0]].upper
            - arm_by_role[contrast.roles[1]].lower,
        )
        for contrast in SuccessorContrast
    )
    realization_effects = tuple(
        _realization_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
    )
    leave_one_realization_out = tuple(
        _leave_one_realization_out_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
        if len(policy.realization_policy.realizations) >= 2
    )
    return SuccessorCoordinateEstimate(
        policy.hypothesis_id,
        model_id,
        metric,
        policy.hypothesis.skeleton.expected_direction,
        arms,
        contrasts,
        tuple(contributions),
        realization_effects,
        _point_robustness_label(
            contrasts[0],
            realization_effects,
            len(task_unit_ids),
            policy.hypothesis.skeleton.expected_direction,
            plan,
        ),
        leave_one_realization_out,
    )


def _unit_arm(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    role: PolicyArmRoleV2,
    metric: Metric,
    *,
    realization_spec_id: str | None = None,
) -> tuple[float | None, float, float]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise SuccessorVerificationError("successor task unit lacks frozen tasks")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realizations = tuple(
        item
        for item in policy.realization_policy.realizations
        if realization_spec_id is None
        or item.realization_spec_id == realization_spec_id
    )
    if not realizations:
        raise SuccessorVerificationError("successor realization support is empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.realization_spec_id == realization.realization_spec_id
                and item.arm_role is role
            ]
            if not block:
                raise SuccessorVerificationError(
                    "successor randomization lacks common task-realization support"
                )
            values = tuple(_metric_value(outcomes[item.assignment_id], metric) for item in block)
            weight = task_weight * realization_weight
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += weight * sum(
                    value[0] for value in values if value[0] is not None
                ) / len(values)
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper


def _arm_estimate(
    assignments: tuple[SuccessorAssignment, ...],
    role: PolicyArmRoleV2,
    units: tuple[tuple[float | None, float, float], ...],
) -> SuccessorArmEstimate:
    point = None if any(item[0] is None for item in units) else sum(
        item[0] for item in units if item[0] is not None
    ) / len(units)
    return SuccessorArmEstimate(
        role,
        point,
        sum(item[1] for item in units) / len(units),
        sum(item[2] for item in units) / len(units),
        sum(item.arm_role is role for item in assignments),
    )


def _realization_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_id: str,
    metric: Metric,
) -> RealizationSuccessorEffect:
    values = _subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        (realization_spec_id,),
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return RealizationSuccessorEffect(
        realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _leave_one_realization_out_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    omitted_realization_spec_id: str,
    metric: Metric,
) -> LeaveOneRealizationOutSuccessorEffect:
    included = tuple(
        item.realization_spec_id
        for item in policy.realization_policy.realizations
        if item.realization_spec_id != omitted_realization_spec_id
    )
    values = _subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        included,
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return LeaveOneRealizationOutSuccessorEffect(
        omitted_realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _subset_effect_values(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_ids: tuple[str, ...],
    metric: Metric,
) -> list[tuple[float | None, float, float]]:
    selected = tuple(
        item
        for item in policy.realization_policy.realizations
        if item.realization_spec_id in realization_spec_ids
    )
    if not selected or len(selected) != len(realization_spec_ids):
        raise SuccessorVerificationError("successor realization subset is invalid")
    selected_total = sum(item.weight for item in selected)
    values = []
    for task_unit_id in task_unit_ids:
        point = lower = upper = 0.0
        point_known = True
        for realization in selected:
            target = _unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.TARGET,
                metric,
                realization_spec_id=realization.realization_spec_id,
            )
            noop = _unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.NOOP,
                metric,
                realization_spec_id=realization.realization_spec_id,
            )
            weight = realization.weight / selected_total
            difference = _difference(target[0], noop[0])
            if difference is None:
                point_known = False
            else:
                point += weight * difference
            lower += weight * (target[1] - noop[2])
            upper += weight * (target[2] - noop[1])
        values.append((point if point_known else None, lower, upper))
    return values


def _point_robustness_label(
    primary: SuccessorContrastEstimate,
    realizations: tuple[RealizationSuccessorEffect, ...],
    task_units: int,
    expected_direction: ExpectedDirection,
    plan: SuccessorAnalysisPlan,
) -> str:
    if primary.point is None or task_units < plan.minimum_task_units:
        return "not_evaluable"
    if len(realizations) < 2 or any(item.point is None for item in realizations):
        return "average_effect_only"
    multiplier = 1.0 if expected_direction is ExpectedDirection.INCREASE else -1.0
    values = [multiplier * float(item.point) for item in realizations]
    if any(value <= plan.practical_effect_margin for value in values):
        return "average_effect_only"
    leave_one_out = [
        sum(value for index, value in enumerate(values) if index != omitted)
        / (len(values) - 1)
        for omitted in range(len(values))
    ]
    return (
        "direction_consistent_diagnostic"
        if all(value > 0.0 for value in leave_one_out)
        else "average_effect_only"
    )


def _robustness_inference(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    policies: Mapping[str, InterventionPolicyV2],
    plan: SuccessorAnalysisPlan,
) -> SuccessorRobustnessInference:
    secure = tuple(item for item in estimates if item.metric is plan.primary_metric)
    functionality = {
        (item.hypothesis_id, item.model_id): item
        for item in estimates
        if item.metric is Metric.FUNCTIONALITY
    }
    functionality_status, functionality_critical, functionality_intervals = (
        _functionality_gate_family(functionality, plan)
    )
    members = {}
    weights_by_coordinate = {}
    eligible_coordinates = set()
    for estimate in secure:
        policy = policies[estimate.hypothesis_id]
        weights = {
            item.realization_spec_id: item.weight
            for item in policy.realization_policy.realizations
        }
        total = sum(weights.values())
        weights_by_coordinate[estimate.coordinate_id] = {
            key: value / total for key, value in weights.items()
        }
        expected_count = len(policy.realization_policy.realizations)
        if (
            expected_count < plan.minimum_realizations
            or len(estimate.task_unit_contributions) < plan.minimum_task_units
            or len(estimate.realization_effects) != expected_count
            or len(estimate.leave_one_realization_out) != expected_count
        ):
            continue
        candidate_members = tuple(
            (
                SuccessorRobustnessComponent.REALIZATION,
                item.realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.realization_effects
        ) + tuple(
            (
                SuccessorRobustnessComponent.LEAVE_ONE_REALIZATION_OUT,
                item.omitted_realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.leave_one_realization_out
        )
        if any(
            len(values) < plan.minimum_task_units_per_realization
            or any(value[1] is None for value in values)
            for _, _, values in candidate_members
        ):
            continue
        eligible_coordinates.add(estimate.coordinate_id)
        for component, realization_id, values in candidate_members:
            members[(estimate.coordinate_id, component, realization_id)] = (
                tuple(value[0] for value in values),
                tuple(float(value[1]) for value in values),
            )
    status = FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    critical = None
    valid_draws = 0
    invalid_draws = plan.bootstrap_draws
    intervals = ()
    heterogeneity = {}
    if members:
        (
            status,
            critical,
            valid_draws,
            invalid_draws,
            intervals,
            heterogeneity,
        ) = _global_robustness_family(
            members,
            weights_by_coordinate,
            plan,
        )
    interval_by_key = {
        (item.coordinate_id, item.component, item.realization_spec_id): item
        for item in intervals
    }
    assessments = []
    for estimate in secure:
        multiplier = (
            1.0
            if estimate.expected_direction is ExpectedDirection.INCREASE
            else -1.0
        )
        oriented = tuple(
            multiplier * float(item.point)
            for item in estimate.realization_effects
            if item.point is not None
        )
        direction_proportion = (
            None
            if not estimate.realization_effects
            or len(oriented) != len(estimate.realization_effects)
            else sum(value > 0.0 for value in oriented) / len(oriented)
        )
        direction_passed = (
            direction_proportion is not None
            and direction_proportion
            >= plan.realization_direction_consistency_threshold
        )
        support_passed = estimate.coordinate_id in eligible_coordinates
        coordinate_intervals = tuple(
            value
            for key, value in interval_by_key.items()
            if key[0] == estimate.coordinate_id
        )
        interval_passed = (
            support_passed
            and len(coordinate_intervals)
            == len(estimate.realization_effects)
            + len(estimate.leave_one_realization_out)
            and all(
                item.lower > 0.0 if multiplier > 0.0 else item.upper < 0.0
                for item in coordinate_intervals
            )
        )
        h_point, h_upper = heterogeneity.get(estimate.coordinate_id, (None, None))
        h_passed = (
            h_upper is not None
            and h_upper <= plan.realization_practical_equivalence_margin
        )
        interaction_statistic, interaction_p = _arm_realization_randomization_test(
            estimate, plan
        )
        interaction_passed = interaction_p is not None and interaction_p > plan.alpha
        robust = (
            status is FamilyInferenceStatus.EVALUABLE
            and support_passed
            and direction_passed
            and interval_passed
            and h_passed
            and interaction_passed
        )
        if robust:
            label = "realization_robust"
        elif estimate.contrast(SuccessorContrast.TARGET_NOOP).point is None:
            label = "not_evaluable"
        elif direction_passed and support_passed:
            label = "direction_consistent_diagnostic"
        else:
            label = "average_effect_only"
        function_coordinate = functionality.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        function_point = (
            None
            if function_coordinate is None
            else function_coordinate.contrast(SuccessorContrast.TARGET_NOOP).point
        )
        function_interval = functionality_intervals.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        if not plan.functionality_noninferiority_separately_powered:
            gate = FunctionalityGateStatus.NOT_REQUESTED
            function_lower = None
        elif (
            functionality_status is not FamilyInferenceStatus.EVALUABLE
            or function_interval is None
        ):
            gate = FunctionalityGateStatus.NOT_EVALUABLE
            function_lower = None
        else:
            function_lower = function_interval[1]
            gate = (
                FunctionalityGateStatus.PASSED
                if function_lower >= -plan.functionality_noninferiority_margin
                else FunctionalityGateStatus.FAILED
            )
        if not robust:
            practical_label = "security_robustness_not_established"
        elif gate is FunctionalityGateStatus.PASSED:
            practical_label = "practical_success"
        elif gate is FunctionalityGateStatus.NOT_REQUESTED:
            practical_label = "functionality_gate_not_requested"
        elif gate is FunctionalityGateStatus.FAILED:
            practical_label = "functionality_noninferiority_failed"
        else:
            practical_label = "functionality_gate_not_evaluable"
        assessments.append(
            SuccessorRobustnessAssessment(
                estimate.coordinate_id,
                direction_proportion,
                direction_passed,
                interval_passed,
                support_passed,
                h_point,
                h_upper,
                h_passed,
                interaction_statistic,
                interaction_p,
                interaction_passed,
                gate,
                function_point,
                function_lower,
                label,
                practical_label,
            )
        )
    return SuccessorRobustnessInference(
        status,
        critical,
        valid_draws,
        invalid_draws,
        intervals,
        functionality_critical,
        tuple(assessments),
    )


def _arm_realization_randomization_test(estimate, plan):
    rows = {
        item.realization_spec_id: {
            task_id: point for task_id, point, _lower, _upper in item.task_unit_effects
        }
        for item in estimate.realization_effects
    }
    if len(rows) < plan.minimum_realizations:
        return None, None
    task_ids = tuple(sorted(set.intersection(*(set(value) for value in rows.values()))))
    if len(task_ids) < plan.minimum_task_units_per_realization or any(
        rows[realization_id][task_id] is None
        for realization_id in rows for task_id in task_ids
    ):
        return None, None
    residuals = {
        realization_id: tuple(
            float(rows[realization_id][task_id])
            - sum(float(rows[other][task_id]) for other in rows) / len(rows)
            for task_id in task_ids
        )
        for realization_id in rows
    }
    statistic = max(abs(sum(values) / len(values)) for values in residuals.values())
    rng = random.Random(int(content_hash({
        "seed": plan.bootstrap_seed,
        "coordinate_id": estimate.coordinate_id,
        "domain": "arm-realization-rademacher",
    })[-16:], 16))
    exceedances = 0
    for _ in range(plan.bootstrap_draws):
        signs = tuple(1.0 if rng.randrange(2) else -1.0 for _ in task_ids)
        replicate = max(
            abs(sum(sign * value for sign, value in zip(signs, values, strict=True)) / len(values))
            for values in residuals.values()
        )
        exceedances += replicate >= statistic - 1e-15
    return statistic, (exceedances + 1) / (plan.bootstrap_draws + 1)


def _global_robustness_family(members, weights_by_coordinate, plan):
    supports = {key: value[0] for key, value in members.items()}
    values = {key: value[1] for key, value in members.items()}
    points = {key: sum(value) / len(value) for key, value in values.items()}
    errors = {key: _standard_error(value) for key, value in values.items()}
    if any(value <= 0.0 for value in errors.values()):
        return (
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
            {},
        )
    realization_keys = {
        coordinate_id: tuple(
            key
            for key in members
            if key[0] == coordinate_id
            and key[1] is SuccessorRobustnessComponent.REALIZATION
        )
        for coordinate_id in {key[0] for key in members}
    }
    h_points = {
        coordinate_id: _max_deviation(
            {key[2]: points[key] for key in keys},
            weights_by_coordinate[coordinate_id],
        )
        for coordinate_id, keys in realization_keys.items()
    }
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_robustness_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value, key[2]) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    draws = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        replicate_points = {}
        replicate_errors = {}
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units_per_realization:
                invalid += 1
                break
            error = _standard_error(sample)
            if error <= 0.0:
                invalid += 1
                break
            replicate_points[key] = sum(sample) / len(sample)
            replicate_errors[key] = error
        else:
            replicate_h = {
                coordinate_id: _max_deviation(
                    {key[2]: replicate_points[key] for key in keys},
                    weights_by_coordinate[coordinate_id],
                )
                for coordinate_id, keys in realization_keys.items()
            }
            draws.append((replicate_points, replicate_errors, replicate_h))
    if len(draws) < math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    ):
        return (
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(draws),
            invalid,
            (),
            {},
        )
    h_errors = {
        coordinate_id: statistics.stdev(draw[2][coordinate_id] for draw in draws)
        for coordinate_id in realization_keys
    }
    maxima = []
    for replicate_points, replicate_errors, replicate_h in draws:
        statistics_for_draw = [
            abs(replicate_points[key] - points[key]) / replicate_errors[key]
            for key in members
        ]
        statistics_for_draw.extend(
            abs(replicate_h[coordinate_id] - h_points[coordinate_id]) / error
            for coordinate_id, error in h_errors.items()
            if error > 0.0
        )
        maxima.append(max(statistics_for_draw))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorRobustnessInterval(
            key[0],
            key[1],
            key[2],
            errors[key],
            max(-1.0, points[key] - critical * errors[key]),
            min(1.0, points[key] + critical * errors[key]),
        )
        for key in members
    )
    heterogeneity = {
        coordinate_id: (
            point,
            min(2.0, point + critical * h_errors[coordinate_id]),
        )
        for coordinate_id, point in h_points.items()
    }
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(draws),
        invalid,
        intervals,
        heterogeneity,
    )


def _max_deviation(points, weights):
    average = sum(weights[key] * value for key, value in points.items())
    return max(abs(value - average) for value in points.values())


def _functionality_gate_family(functionality, plan):
    if not plan.functionality_noninferiority_separately_powered:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    vectors = {
        key: tuple(
            float(item.contrast(SuccessorContrast.TARGET_NOOP)[0])
            for item in estimate.task_unit_contributions
        )
        for key, estimate in functionality.items()
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and all(
            item.contrast(SuccessorContrast.TARGET_NOOP)[0] is not None
            for item in estimate.task_unit_contributions
        )
    }
    supports = {
        key: tuple(item.task_unit_id for item in functionality[key].task_unit_contributions)
        for key in vectors
    }
    if not vectors:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    points = {key: sum(value) / len(value) for key, value in vectors.items()}
    errors = {key: _standard_error(value) for key, value in vectors.items()}
    if any(value <= 0.0 for value in errors.values()):
        return FamilyInferenceStatus.ZERO_STANDARD_ERROR, None, {}
    value_by_unit = {
        key: dict(zip(supports[key], vectors[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_functionality_gate_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(sorted(supports)),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        draw_statistics = []
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units:
                break
            error = _standard_error(sample)
            if error <= 0.0:
                break
            draw_statistics.append(
                abs(sum(sample) / len(sample) - points[key]) / error
            )
        else:
            maxima.append(max(draw_statistics))
    if len(maxima) < math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    ):
        return FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP, None, {}
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        {
            key: (
                errors[key],
                max(-1.0, points[key] - critical * errors[key]),
                min(1.0, points[key] + critical * errors[key]),
            )
            for key in vectors
        },
    )


def _family(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    family: SuccessorIntervalFamily,
    plan: SuccessorAnalysisPlan,
) -> SuccessorFamilyInference:
    if family is SuccessorIntervalFamily.PRIMARY_SECURITY:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is plan.primary_metric
        )
    elif family is SuccessorIntervalFamily.SECURITY_SPECIFICITY:
        members = tuple(
            (item, contrast)
            for item in estimates
            if item.metric is plan.primary_metric
            for contrast in (
                SuccessorContrast.TARGET_PLACEBO,
                SuccessorContrast.TARGET_GENERIC,
            )
        )
    else:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is Metric.JOINT
        )
    eligible = tuple(
        (estimate, contrast)
        for estimate, contrast in members
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and estimate.contrast(contrast).point is not None
        and all(
            contribution.contrast(contrast)[0] is not None
            for contribution in estimate.task_unit_contributions
        )
    )
    if not eligible:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    supports = {
        (estimate.coordinate_id, contrast): tuple(
            item.task_unit_id for item in estimate.task_unit_contributions
        )
        for estimate, contrast in eligible
    }
    points = {
        key: float(estimate.contrast(contrast).point)
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    values = {
        key: tuple(
            float(item.contrast(contrast)[0])
            for item in estimate.task_unit_contributions
        )
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    standard_errors = {key: _standard_error(item) for key, item in values.items()}
    if any(value <= 0.0 for value in standard_errors.values()):
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "family": family,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        draw_statistics = []
        valid = True
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _standard_error(sample)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample) / len(sample)
            draw_statistics.append(
                abs(replicate_point - points[key]) / replicate_error
            )
        if valid:
            maxima.append(max(draw_statistics))
        else:
            invalid += 1
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(maxima),
            invalid,
            (),
        )
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorSimultaneousInterval(
            estimate.coordinate_id,
            contrast,
            standard_errors[(estimate.coordinate_id, contrast)],
            max(
                -1.0,
                points[(estimate.coordinate_id, contrast)]
                - critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
            min(
                1.0,
                points[(estimate.coordinate_id, contrast)]
                + critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
        )
        for estimate, contrast in eligible
    )
    return SuccessorFamilyInference(
        family,
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(maxima),
        invalid,
        intervals,
    )


def _metric_value(outcome: Outcome, metric: Metric) -> tuple[int | None, int, int]:
    if metric is Metric.SECURE_YIELD:
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric is Metric.JOINT:
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric.value)
    if value is None:
        return None, 0, 1
    return value, value, value


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _standard_error(values: tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) * (len(values) - 1))
    )


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


__all__ = [
    "SuccessorVerificationError",
    "verify_successor_result_bundle",
    "verify_successor_inference",
]

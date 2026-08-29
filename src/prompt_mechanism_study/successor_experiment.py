"""One linear runner for the prospective single-mechanism successor study.

Preflight reconstructs every frozen identity and Prompt-TSG source gate without
calling a provider.  A run then materializes one blinded four-prompt bundle per
eligible hypothesis/task/realization, randomizes complete blocks, measures every
assignment, estimates assigned-arm ITT, and invokes the independent verifier.
"""

from __future__ import annotations

import hashlib
import math
import os
import platform
import random
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from prompt_mechanism_study.adapters import AdapterBundle, AdapterKind, AdapterSpec
from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    confined_path as resolve_confined_path,
    is_sha256,
    json_object as parse_json_object,
    read_json,
    read_json_exact as read_strict_json,
    require_file_hash as verify_file_hash,
    require_sha256,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
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
    ArmProtocolV2,
    ArmSemanticValidationV2,
    ArmVariantV2,
    BundleValidationV2,
    InterventionExecution,
    InterventionPolicyV2,
    PolicyArmRoleV2,
    RealizationPolicyV2,
    RealizationSpecV2,
    SemanticVerdict,
    TaskRealizationBundleV2,
    arm_protocol_v2,
    freeze_successor_policy,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    MeasurementExecutionError,
    OracleStatus,
    measure_generated_code,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    build_prompt_tsg,
    catalog_sha256,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    query_context,
    validate_prompt_tsg,
)
from prompt_mechanism_study.qualification import (
    QualificationError,
    load_functional_qualification,
    validate_functional_qualification,
    validate_functionality_power_payload,
)
from prompt_mechanism_study.randomization import (
    SuccessorAssignment,
    SuccessorBlockKey,
    SuccessorRandomization,
)
from prompt_mechanism_study.records import (
    canonical_json,
    canonical_value,
    content_hash,
    content_id,
)
from prompt_mechanism_study.representation import (
    CandidateSkeletonV2,
    EligibilityDecisionV2,
    ExpectedDirection,
    FrozenHypothesisV2,
    Operation,
    SourceEligibilityV2,
    Split,
    TargetSpecV2,
    Task,
    source_eligibility_v2,
)
from prompt_mechanism_study.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
    security_profile_policy_sha256,
    security_profile_producer_sha256,
)
from prompt_mechanism_study.selector_experiment import (
    bridge_from_record,
    load_bridge_freeze_bundle,
    load_selection_freeze_bundle,
    selection_from_record,
)
from prompt_mechanism_study.successor_verify import verify_successor_inference
from prompt_mechanism_study.workflow import (
    SUCCESSOR_METHOD_VERSION,
    SuccessorStudyFreeze,
    SuccessorSelectionProvenance,
    analyze_successor,
    freeze_successor_study,
)

Complete = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]
SecurityEvaluate = Callable[[str, str], Mapping[str, Any]]

_ACTIVE_OUTCOME_METRICS = (
    Metric.SECURE_YIELD,
    Metric.CODE_VALID,
    Metric.ORACLE_EVALUABLE,
    Metric.FUNCTIONALITY,
    Metric.JOINT,
)


class SuccessorExperimentError(ValueError):
    """A frozen successor input or external response failed closed."""


def preflight_successor_experiment(
    repository_root: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Validate the complete frozen design without making a provider call."""

    inputs = _load_inputs(repository_root, config_path)
    credentials = sorted(
        {
            value["api_key_env"]
            for value in (
                inputs["executor"],
                inputs["validator"],
                inputs["functional_evaluator"],
                *inputs["generation_models"],
            )
        }
    )
    eligible = {
        item["hypothesis"].hypothesis_id: sum(
            gate.eligible for gate in item["source_eligibilities"]
        )
        for item in inputs["hypotheses"]
    }
    bundles = sum(
        eligible[item["hypothesis"].hypothesis_id]
        * len(item["realization_policy"].realizations)
        for item in inputs["hypotheses"]
    )
    assignments = (
        bundles
        * len(inputs["generation_models"])
        * len(inputs["config"]["randomization"]["request_randomness_slots"])
    )
    return {
        "schema_version": "2.0",
        "status": "SUCCESSOR_PREFLIGHT_COMPLETE",
        "study_name": inputs["config"]["study_name"],
        "phase": inputs["config"]["phase"],
        "provider_attempts": 0,
        "task_corpus_bundle_sha256": inputs["corpus_bundle_sha256"],
        "prompt_tsg_catalog_sha256": inputs["catalog_sha256"],
        "selection_provenance": canonical_value(inputs["selection_provenance"]),
        "tasks": len(inputs["tasks"]),
        "hypotheses": len(inputs["hypotheses"]),
        "eligible_tasks_by_hypothesis": eligible,
        "planned_task_realization_bundles": bundles,
        "planned_assignments": assignments,
        "models": [item["model_id"] for item in inputs["generation_models"]],
        "oracle_profiles_by_hypothesis": {
            item["hypothesis"].hypothesis_id: item["security_oracle"]["profile_id"]
            for item in inputs["hypotheses"]
        },
        "credentials": [
            {"environment_variable": name, "present": bool(os.environ.get(name, "").strip())}
            for name in credentials
        ],
        "scientific_claim_allowed": False,
    }


def run_successor_experiment(
    repository_root: Path,
    config_path: Path,
    output: Path,
    *,
    freeze_root: Path,
    complete: Complete | None = None,
    security_evaluate: SecurityEvaluate | None = None,
) -> dict[str, Any]:
    """Execute the frozen successor design once and close one result bundle."""

    if output.resolve().exists():
        raise FileExistsError(output.resolve())
    verify_successor_materialization_bundle(freeze_root)
    frozen_execution_evidence = _object(
        _read_json_exact(freeze_root / "execution-evidence.json"),
        "frozen execution evidence",
    )
    frozen_functional = _object(
        frozen_execution_evidence.get("functional_evaluator"),
        "frozen functional evaluator",
    )
    frozen_power = frozen_execution_evidence.get(
        "functionality_power_qualification"
    )
    inputs = _load_inputs(
        repository_root,
        config_path,
        functional_qualification_override=_object(
            frozen_functional.get("qualification"),
            "frozen functional qualification",
        ),
        functionality_power_qualification_override=(
            None
            if frozen_power is None
            else _object(frozen_power, "frozen functionality power qualification")
        ),
    )
    frozen = _load_successor_materialization(freeze_root, inputs)
    provider = complete or bailian_complete
    security_provider = security_evaluate or evaluate_security_profile
    calls: list[dict[str, Any]] = list(frozen["provider_calls"])
    study = frozen["study"]
    policies = study.policies

    bundle_by_id = {
        bundle.task_realization_bundle_id: bundle
        for policy in policies
        for bundle in policy.bundles
    }
    oracle_by_hypothesis = {
        item["hypothesis"].hypothesis_id: item["security_oracle"]
        for item in inputs["hypotheses"]
    }
    measurements = []
    measurement_records = []
    assignment_by_id = {
        item.assignment_id: item for item in study.randomization.assignments
    }
    for execution_ordinal, assignment_id in enumerate(frozen["execution_order"]):
        assignment = assignment_by_id[assignment_id]
        bundle = bundle_by_id[assignment.block.task_realization_bundle_id]
        variant = bundle.variant(assignment.arm_role)
        started_at = datetime.now(timezone.utc)
        started_ns = time.monotonic_ns()
        measurement, record = _measure_assignment(
            inputs,
            assignment,
            inputs["task_rows_by_id"][assignment.block.task_instance_id],
            variant.prompt_text,
            oracle_by_hypothesis[assignment.block.hypothesis_id],
            provider,
            security_provider,
        )
        elapsed_ns = time.monotonic_ns() - started_ns
        ended_at = datetime.now(timezone.utc)
        measurements.append(measurement)
        record_calls = record.pop("provider_calls")
        for call in record_calls:
            call["execution_ordinal"] = execution_ordinal
            call["assignment_elapsed_ns"] = elapsed_ns
            call["assignment_elapsed_ms"] = elapsed_ns / 1_000_000.0
            call["assignment_started_utc"] = started_at.isoformat()
            call["assignment_ended_utc"] = ended_at.isoformat()
            call["provider_observable_state"] = {
                "model_id": assignment.block.model_id,
                "provider_seed": assignment.provider_seed,
                "request_randomness_slot": assignment.request_randomness_slot,
            }
        measurement_records.append(
            {
                "assignment": canonical_value(assignment),
                "measurement": canonical_value(measurement),
                **record,
            }
        )
        calls.extend(record_calls)

    analysis = analyze_successor(study, measurements)
    verification = verify_successor_inference(
        study.randomization,
        analysis.outcomes,
        study.policies,
        study.tasks,
        study.analysis_plan,
        analysis.inference,
        maximum_unknown_fraction=inputs["maximum_unknown_fraction"],
        scientific_claim_allowed=bool(inputs["config"]["scientific_claim_allowed"]),
        functionality_power_qualification_sha256=(
            None
            if inputs["functionality_power_qualification"] is None
            else inputs["functionality_power_qualification"][
                "qualification_sha256"
            ]
        ),
    )
    report = _report(inputs["config"], study, analysis, verification)
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "python_dont_write_bytecode": os.environ.get("PYTHONDONTWRITEBYTECODE"),
        "credential_environment_variables": sorted(
            {
                item["api_key_env"]
                for item in (
                    inputs["executor"],
                    inputs["validator"],
                    inputs["functional_evaluator"],
                    *inputs["generation_models"],
                )
            }
        ),
        "credential_value_recorded": False,
    }
    write_bundle(
        output,
        {
            "effective-config.json": inputs["config"],
            "environment.json": environment,
            "selection-evidence.json": inputs["selection_evidence"],
            "materialization-freeze.json": {
                "bundle_sha256": bundle_digest(freeze_root),
                "study_freeze_id": content_id("successor_study_freeze_", study),
                "execution_order_sha256": content_hash(frozen["execution_order"]),
            },
            "execution-evidence.json": frozen["execution_evidence"],
            "study-freeze.json": canonical_value(study),
            "provider-calls.json": calls,
            "measurement-records.json": measurement_records,
            "analysis.json": canonical_value(analysis),
            "verification.json": verification,
            "report.json": report,
        },
    )
    verify_successor_result_bundle(output)
    return {**report, "result_bundle_sha256": bundle_digest(output)}


def freeze_successor_experiment(
    repository_root: Path,
    config_path: Path,
    output: Path,
    *,
    complete: Complete | None = None,
) -> dict[str, Any]:
    """Materialize and randomize the entire study before any outcome exists."""

    if output.resolve().exists():
        raise FileExistsError(output.resolve())
    inputs = _load_inputs(repository_root, config_path)
    provider = complete or bailian_complete
    calls: list[dict[str, Any]] = []
    policies = []
    for item in inputs["hypotheses"]:
        eligible = tuple(gate for gate in item["source_eligibilities"] if gate.eligible)
        bundles = tuple(
            _materialize_bundle(
                inputs,
                item,
                inputs["task_rows_by_id"][gate.task_id],
                gate,
                realization,
                provider,
                calls,
            )
            for gate in eligible
            for realization in item["realization_policy"].realizations
        )
        policies.append(
            freeze_successor_policy(
                item["hypothesis"], item["realization_policy"], eligible, bundles
            )
        )
    study = freeze_successor_study(
        inputs["tasks"],
        tuple(item["hypothesis"] for item in inputs["hypotheses"]),
        tuple(gate for item in inputs["hypotheses"] for gate in item["source_eligibilities"]),
        tuple(policies),
        inputs["adapters"],
        _analysis_plan(inputs["config"]["analysis"]),
        selection_provenance=inputs["selection_provenance"],
        models=tuple(item["model_id"] for item in inputs["generation_models"]),
        request_randomness_slots=tuple(inputs["config"]["randomization"]["request_randomness_slots"]),
        randomization_seed=inputs["config"]["randomization"]["seed"],
        provider_seed=inputs["config"]["randomization"]["provider_seed"],
    )
    execution_order = [item.assignment_id for item in study.randomization.assignments]
    random.Random(
        int(content_hash({"seed": inputs["config"]["randomization"]["seed"], "domain": "global-execution-order"})[-16:], 16)
    ).shuffle(execution_order)
    write_bundle(output, {
        "effective-config.json": inputs["config"],
        "selection-evidence.json": inputs["selection_evidence"],
        "execution-evidence.json": _execution_evidence(inputs),
        "study-freeze.json": canonical_value(study),
        "provider-calls.json": calls,
        "identity.json": {
            "schema_version": "1.0",
            "study_freeze_id": content_id("successor_study_freeze_", study),
            "execution_order": execution_order,
        },
    })
    verified = verify_successor_materialization_bundle(output)
    return {**verified, "bundle_sha256": bundle_digest(output)}


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


def verify_successor_materialization_bundle(root: Path) -> dict[str, Any]:
    """Verify the immutable pre-outcome variants and randomization bundle."""

    manifest = verify_bundle(root)
    expected = {
        "effective-config.json", "selection-evidence.json", "execution-evidence.json",
        "study-freeze.json", "provider-calls.json", "identity.json",
    }
    if set(manifest["files"]) != expected:
        raise SuccessorExperimentError("successor materialization artifact set is not exact")
    config = _object(read_json(root / "effective-config.json"), "frozen config")
    _validate_successor_config_envelope(config)
    study = _object(read_json(root / "study-freeze.json"), "frozen study")
    identity = _object(read_json(root / "identity.json"), "freeze identity")
    freeze_id = content_id("successor_study_freeze_", study)
    if (
        set(identity) != {"schema_version", "study_freeze_id", "execution_order"}
        or identity.get("schema_version") != "1.0"
        or identity.get("study_freeze_id") != freeze_id
    ):
        raise SuccessorExperimentError("successor materialization identity does not recompute")
    randomization = _object(study.get("randomization"), "frozen randomization")
    expected_order = [
        content_id("successor_assignment_v2_", item)
        for item in _list(randomization.get("assignments"), "frozen assignments")
    ]
    random.Random(
        int(content_hash({"seed": config["randomization"]["seed"], "domain": "global-execution-order"})[-16:], 16)
    ).shuffle(expected_order)
    if identity.get("execution_order") != expected_order:
        raise SuccessorExperimentError("global execution order does not recompute")
    _verify_stored_selection_provenance(
        config,
        _object(read_json(root / "selection-evidence.json"), "frozen selection"),
        study,
        {"selection_provenance": study.get("selection_provenance")},
        randomization,
    )
    policies = tuple(
        _stored_policy(_object(value, "frozen policy"))
        for value in _list(study.get("policies"), "frozen policies")
    )
    tasks = tuple(
        _stored_task(_object(value, "frozen task"))
        for value in _list(study.get("tasks"), "frozen tasks")
    )
    contracts, _oracles, adapters = _verify_execution_evidence(
        config,
        _object(read_json(root / "execution-evidence.json"), "frozen execution evidence"),
        study,
        policies,
        tasks,
    )
    calls = tuple(
        _object(value, "frozen provider call")
        for value in _list(read_json(root / "provider-calls.json"), "frozen provider calls")
    )
    if any(call.get("stage") != "intervention" for call in calls):
        raise SuccessorExperimentError("pre-outcome freeze contains outcome-stage provider calls")
    _verify_intervention_calls(
        calls,
        {item.hypothesis_id: item for item in policies},
        {item.task_id: item for item in tasks},
        contracts,
        adapters,
    )
    if _stored_analysis_plan(
        _object(study.get("analysis_plan"), "frozen analysis plan")
    ) != _analysis_plan(_object(config.get("analysis"), "config analysis")):
        raise SuccessorExperimentError("frozen analysis plan drifts from config")
    _stored_randomization(randomization)
    return {"status": "SUCCESSOR_MATERIALIZATION_VERIFIED", "study_freeze_id": freeze_id}


def _load_successor_materialization(
    freeze_root: Path,
    inputs: Mapping[str, Any],
) -> dict[str, Any]:
    verify_successor_materialization_bundle(freeze_root)
    frozen_config = _object(read_json(freeze_root / "effective-config.json"), "frozen config")
    if frozen_config != inputs["config"]:
        raise SuccessorExperimentError("run config drifts from materialization freeze")
    value = _object(read_json(freeze_root / "study-freeze.json"), "frozen study")
    policies = tuple(
        _stored_policy(_object(item, "frozen policy"))
        for item in _list(value["policies"], "frozen policies")
    )
    tasks = tuple(
        _stored_task(_object(item, "frozen task"))
        for item in _list(value["tasks"], "frozen tasks")
    )
    source_eligibilities = tuple(
        _stored_source_eligibility(_object(item, "frozen source eligibility"))
        for item in _list(value["source_eligibilities"], "frozen source eligibilities")
    )
    raw_provenance = _object(value["selection_provenance"], "frozen provenance")
    provenance = SuccessorSelectionProvenance(
        raw_provenance["source"], raw_provenance["candidate_universe_manifest_id"],
        raw_provenance["selection_id"], raw_provenance["artifact_sha256"],
        raw_provenance["bridge_map_id"], tuple(raw_provenance["selected_predecessor_ids"]),
    )
    _contracts, _oracles, adapters = _verify_execution_evidence(
        frozen_config,
        _object(read_json(freeze_root / "execution-evidence.json"), "frozen execution evidence"),
        value,
        policies,
        tasks,
    )
    study = SuccessorStudyFreeze(
        value["method_version"], provenance, tasks,
        tuple(sorted((item.hypothesis for item in policies), key=lambda item: item.hypothesis_id)),
        source_eligibilities,
        policies, adapters,
        _stored_randomization(_object(value["randomization"], "frozen randomization")),
        _stored_analysis_plan(_object(value["analysis_plan"], "frozen analysis plan")),
    )
    if study.method_version != SUCCESSOR_METHOD_VERSION or canonical_value(study) != value:
        raise SuccessorExperimentError("materialized study does not reconstruct exactly")
    return {
        "study": study,
        "execution_evidence": _object(
            read_json(freeze_root / "execution-evidence.json"),
            "frozen execution evidence",
        ),
        "execution_order": tuple(
            _strings(
                _object(read_json(freeze_root / "identity.json"), "freeze identity")["execution_order"],
                "execution order",
            )
        ),
        "provider_calls": tuple(
            _object(item, "frozen provider call")
            for item in _list(
                read_json(freeze_root / "provider-calls.json"),
                "frozen provider calls",
            )
        ),
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


def _verify_execution_evidence(
    config: Mapping[str, Any],
    evidence: Mapping[str, Any],
    study: Mapping[str, Any],
    policies: tuple[InterventionPolicyV2, ...],
    tasks: tuple[Task, ...],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    AdapterBundle,
]:
    expected_keys = {
        "schema_version",
        "task_corpus_bundle_sha256",
        "task_contracts",
        "intervention_executor",
        "intervention_validator",
        "generation_models",
        "functional_evaluator",
        "functionality_power_qualification",
        "security_oracles",
        "prompt_tsg_catalog",
        "prompt_tsg_catalog_sha256",
        "source_prompt_tsgs",
    }
    if (
        set(evidence) != expected_keys
        or evidence.get("schema_version") != "1.0"
        or evidence.get("task_corpus_bundle_sha256")
        != _object(config["task_corpus"], "stored task corpus").get("bundle_sha256")
    ):
        raise SuccessorExperimentError("stored execution evidence envelope drifts")
    catalog = _object(evidence["prompt_tsg_catalog"], "stored Prompt TSG catalog")
    if catalog_sha256(catalog) != evidence.get("prompt_tsg_catalog_sha256"):
        raise SuccessorExperimentError("stored Prompt TSG catalog identity drifts")
    source_graphs = {}
    for raw in _list(evidence["source_prompt_tsgs"], "stored source Prompt TSGs"):
        record = _object(raw, "stored source Prompt TSG")
        graph = prompt_tsg_from_record(record)
        task = next((item for item in tasks if item.task_id == graph.task_id), None)
        if task is None:
            raise SuccessorExperimentError("stored source Prompt TSG task drifts")
        validate_prompt_tsg(graph, prompt=task.prompt, catalog=catalog)
        source_graphs[graph.task_id] = graph
    if set(source_graphs) != {item.task_id for item in tasks}:
        raise SuccessorExperimentError("stored source Prompt TSG support drifts")
    contracts = {}
    for raw in _list(evidence["task_contracts"], "stored task contracts"):
        item = _object(raw, "stored task contract")
        if set(item) != {"task_id", "functional_contract"}:
            raise SuccessorExperimentError("stored task contract schema drifts")
        task_id = _text(item["task_id"], "stored task contract id")
        contract = _object(item["functional_contract"], "stored functional contract")
        if task_id in contracts:
            raise SuccessorExperimentError("stored task contracts are duplicated")
        _strings(contract.get("environment_dependencies"), "environment dependencies")
        requirements = _list(contract.get("requirements"), "functional requirements")
        if contract.get("language", "python") != "python" or not requirements:
            raise SuccessorExperimentError("stored functional contract is invalid")
        contracts[task_id] = contract
    if set(contracts) != {item.task_id for item in tasks}:
        raise SuccessorExperimentError("stored task contract support drifts")

    oracle_rows = tuple(
        _object(raw, "stored security Oracle evidence")
        for raw in _list(evidence["security_oracles"], "stored security Oracles")
    )
    oracle_by_hypothesis = {}
    for item in oracle_rows:
        expected_oracle_keys = {
            "hypothesis_id",
            "profile_id",
            "policy_sha256",
            "qualification_path",
            "qualification_sha256",
            "qualification",
            "qualification_payload",
            "producer_sha256",
        }
        if set(item) != expected_oracle_keys:
            raise SuccessorExperimentError("stored security Oracle evidence schema drifts")
        payload = _text(item["qualification_payload"], "Oracle qualification payload")
        qualification = _object(item["qualification"], "Oracle qualification")
        parsed_payload = _json_object(
            payload.encode("utf-8"), "Oracle qualification payload"
        )
        if (
            hashlib.sha256(payload.encode("utf-8")).hexdigest()
            != item["qualification_sha256"]
            or parsed_payload != qualification
            or qualification.get("profile_id") != item["profile_id"]
            or qualification.get("policy_sha256") != item["policy_sha256"]
            or qualification.get("qualification_status") != "supported"
            or qualification.get("label_mismatches", 0) != 0
            or item.get("producer_sha256") != security_profile_producer_sha256()
            or item.get("policy_sha256")
            != security_profile_policy_sha256(item.get("profile_id"))
        ):
            raise SuccessorExperimentError("stored security Oracle qualification drifts")
        hypothesis_id = _text(item["hypothesis_id"], "Oracle hypothesis id")
        if hypothesis_id in oracle_by_hypothesis:
            raise SuccessorExperimentError("stored security Oracle evidence is duplicated")
        oracle_by_hypothesis[hypothesis_id] = item
    if set(oracle_by_hypothesis) != {item.hypothesis_id for item in policies}:
        raise SuccessorExperimentError("stored security Oracle support drifts")
    config_by_candidate = {
        item["candidate_key"]: _object(item["security_oracle"], "config security Oracle")
        for item in (
            _object(raw, "config hypothesis")
            for raw in _list(config["hypotheses"], "config hypotheses")
        )
    }
    for policy in policies:
        oracle = oracle_by_hypothesis[policy.hypothesis_id]
        configured = config_by_candidate.get(policy.hypothesis.skeleton.candidate_key)
        if configured is None or any(
            oracle[key] != configured[key]
            for key in (
                "profile_id",
                "policy_sha256",
                "qualification_path",
                "qualification_sha256",
            )
        ):
            raise SuccessorExperimentError("stored security Oracle config binding drifts")
        for bundle in policy.bundles:
            source_graph = source_graphs[bundle.task_id]
            source_context = _variant_context_state(source_graph, policy.hypothesis, catalog)
            source_target = feature_state(
                source_graph, policy.hypothesis.skeleton.actionable_feature_id
            )
            source_non_target = tuple(sorted(
                (node.node_type, node.semantic_id, tuple(node.attributes))
                for node in source_graph.nodes
                if node.semantic_id not in {
                    "task.root", policy.hypothesis.skeleton.actionable_feature_id
                }
            ))
            for variant in bundle.variants:
                graph = prompt_tsg_from_record(
                    _object(
                        _json_object(
                            variant.prompt_tsg_record_json.encode("utf-8"),
                            "stored variant Prompt TSG",
                        ),
                        "stored variant Prompt TSG",
                    )
                )
                validate_prompt_tsg(graph, prompt=variant.prompt_text, catalog=catalog)
                context = _variant_context_state(graph, policy.hypothesis, catalog)
                target = feature_state(
                    graph, policy.hypothesis.skeleton.actionable_feature_id
                )
                expected_target = (
                    QueryState.PRESENT
                    if variant.role is PolicyArmRoleV2.TARGET
                    and policy.hypothesis.skeleton.operation is Operation.ADD
                    else QueryState.ABSENT
                    if variant.role in {PolicyArmRoleV2.TARGET, PolicyArmRoleV2.GENERIC}
                    and policy.hypothesis.skeleton.operation is Operation.REMOVE
                    else source_target
                )
                non_target = tuple(sorted(
                    (node.node_type, node.semantic_id, tuple(node.attributes))
                    for node in graph.nodes
                    if node.semantic_id not in {
                        "task.root", policy.hypothesis.skeleton.actionable_feature_id
                    }
                ))
                projection = {
                    "task_id": graph.task_id,
                    "context": context.value,
                    "target": target.value,
                    "non_target": non_target,
                }
                if (
                    graph.task_id != bundle.task_id
                    or context is not source_context
                    or target is not expected_target
                    or non_target != source_non_target
                    or variant.projection_sha256 != content_hash(projection)
                ):
                    raise SuccessorExperimentError(
                        "stored variant Prompt TSG violates AllowedDelta"
                    )

    executor = _object(evidence["intervention_executor"], "stored executor evidence")
    validator = _object(evidence["intervention_validator"], "stored validator evidence")
    functional = _object(evidence["functional_evaluator"], "stored functional evidence")
    if set(functional) != {"config", "prompt", "qualification"}:
        raise SuccessorExperimentError(
            "stored functional evaluator evidence schema drifts"
        )
    functional_config = _object(
        functional["config"], "stored functional evaluator config"
    )
    functional_prompt = _text(
        functional["prompt"], "stored functional evaluator prompt"
    )
    functional_qualification = _validate_frozen_functional_qualification(
        _object(config["functional_judge"], "config functional judge"),
        functional_config,
        _object(
            functional["qualification"],
            "stored functional judge qualification",
        ),
    )
    frozen_power = _validate_frozen_functionality_power_qualification(
        _object(config["analysis"], "stored config analysis"),
        tuple(
            item["model_id"]
            for item in _list(
                _object(config["generation"], "stored generation config")["models"],
                "stored generation models",
            )
        ),
        (
            None
            if evidence["functionality_power_qualification"] is None
            else _object(
                evidence["functionality_power_qualification"],
                "stored functionality power qualification",
            )
        ),
    )
    if frozen_power is not None:
        planned_units = frozen_power["qualification"][
            "planned_task_units_per_coordinate"
        ]
        if any(
            len({bundle.task_unit_id for bundle in policy.bundles}) < planned_units
            for policy in policies
        ):
            raise SuccessorExperimentError(
                "frozen successor support is smaller than the functionality power plan"
            )
    generation_rows = tuple(
        _object(raw, "stored generation evidence")
        for raw in _list(evidence["generation_models"], "stored generation evidence")
    )
    generation_configs = tuple(
        _object(item["config"], "stored generation config")
        for item in generation_rows
    )
    generation_prompts = {
        item["config"]["model_id"]: _text(item["prompt"], "generation prompt")
        for item in generation_rows
    }
    provenance_value = _object(
        study["selection_provenance"],
        "stored selection provenance",
    )
    provenance = SuccessorSelectionProvenance(
        provenance_value["source"],
        provenance_value["candidate_universe_manifest_id"],
        provenance_value["selection_id"],
        provenance_value["artifact_sha256"],
        provenance_value["bridge_map_id"],
        tuple(provenance_value["selected_predecessor_ids"]),
    )
    stored_adapters = _object(study["adapters"], "stored adapters")
    representation = _object(stored_adapters["representation"], "representation adapter")
    expected_adapters = _adapters(
        representation["policy_sha256"],
        provenance,
        _object(executor["config"], "stored executor config"),
        _text(executor["prompt"], "stored executor prompt"),
        _object(validator["config"], "stored validator config"),
        _text(validator["prompt"], "stored validator prompt"),
        generation_configs,
        generation_prompts,
        oracle_rows,
        functional_config,
        functional_prompt,
        functional_qualification,
    )
    if canonical_value(expected_adapters) != stored_adapters:
        raise SuccessorExperimentError("stored execution adapter binding drifts")
    return contracts, oracle_by_hypothesis, expected_adapters


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


def _verify_intervention_calls(
    calls: tuple[dict[str, Any], ...],
    policies: Mapping[str, InterventionPolicyV2],
    tasks: Mapping[str, Task],
    contracts: Mapping[str, Mapping[str, Any]],
    adapters: AdapterBundle,
) -> None:
    by_key = {}
    for call in calls:
        key = (
            call.get("hypothesis_id"),
            call.get("task_id"),
            call.get("realization_spec_id"),
        )
        if key in by_key:
            raise SuccessorExperimentError("stored intervention calls are duplicated")
        by_key[key] = call
    expected_keys = {
        (policy.hypothesis_id, bundle.task_id, bundle.realization_spec_id)
        for policy in policies.values()
        for bundle in policy.bundles
    }
    if set(by_key) != expected_keys:
        raise SuccessorExperimentError("stored intervention calls do not close bundles")
    for key, call in by_key.items():
        policy = policies[key[0]]
        bundle = next(
            item
            for item in policy.bundles
            if item.task_id == key[1] and item.realization_spec_id == key[2]
        )
        task = tasks[bundle.task_id]
        eligibility = next(
            item
            for item in policy.source_eligibilities
            if item.source_eligibility_id == bundle.source_eligibility_id
        )
        realization = next(
            item
            for item in policy.realization_policy.realizations
            if item.realization_spec_id == bundle.realization_spec_id
        )
        protocol = policy.realization_policy.arm_protocol
        source_gate = {
            "context_query_id": policy.hypothesis.skeleton.context_query_id,
            "target_evidence_node_ids": list(eligibility.target_evidence_node_ids),
            "neutral_counterpart": eligibility.neutral_counterpart,
        }
        arm_protocol = {
            role.value: {
                "label": protocol.label(role),
                "instruction": realization.instruction(role),
            }
            for role in SUCCESSOR_ARM_ROLE_ORDER
        }
        executor_request = {
            "request_kind": "blind_successor_prompt_intervention",
            "source_prompt": task.prompt,
            "functional_requirements": contracts[task.task_id]["requirements"],
            "operation": policy.hypothesis.skeleton.operation.value,
            "target_spec": canonical_value(policy.hypothesis.target_spec),
            "source_gate": source_gate,
            "arm_protocol": arm_protocol,
            "blindness": {
                "selector_identity_withheld": True,
                "expected_direction_withheld": True,
                "generated_code_withheld": True,
                "oracle_and_functional_outcomes_withheld": True,
            },
            "output_schema": {
                f"{role.value}_prompt": "complete rewritten task prompt"
                for role in SUCCESSOR_ARM_ROLE_ORDER
            },
        }
        executor_response = _text(call.get("executor_response"), "executor response")
        executor_digest = hashlib.sha256(executor_response.encode("utf-8")).hexdigest()
        response = _json_object(
            executor_response.encode("utf-8"),
            "stored executor response",
        )
        prompts = {
            role: response.get(f"{role.value}_prompt")
            for role in SUCCESSOR_ARM_ROLE_ORDER
        }
        if (
            call.get("executor_request") != executor_request
            or call.get("executor_response_sha256") != executor_digest
            or set(response) != {f"{role.value}_prompt" for role in SUCCESSOR_ARM_ROLE_ORDER}
            or any(prompts[role] != bundle.variant(role).prompt_text for role in prompts)
            or any(
                bundle.variant(role).execution.evidence_sha256 != executor_digest
                or bundle.variant(role).execution.executor_adapter_id
                != adapters.intervention_executor.adapter_id
                for role in prompts
            )
        ):
            raise SuccessorExperimentError("stored intervention executor evidence drifts")
        validator_request = {
            "request_kind": "blind_successor_prompt_validation",
            "source_prompt": task.prompt,
            "functional_requirements": contracts[task.task_id]["requirements"],
            "operation": policy.hypothesis.skeleton.operation.value,
            "target_spec": canonical_value(policy.hypothesis.target_spec),
            "source_gate": source_gate,
            "arm_protocol": arm_protocol,
            "variants": {role.value: prompts[role] for role in SUCCESSOR_ARM_ROLE_ORDER},
            "prompt_tsg_contract": {
                "catalog_sha256": adapters.representation.policy_sha256,
                "maximum_facts_per_arm": 128,
                "maximum_relations_per_arm": 256,
                "evidence_must_be_exact_span": True,
            },
            "blindness": {
                "selector_identity_withheld": True,
                "expected_direction_withheld": True,
                "generated_code_withheld": True,
                "oracle_and_functional_outcomes_withheld": True,
                "generation_model_identity_withheld": True,
            },
        }
        validator_response = _text(call.get("validator_response"), "validator response")
        validator_digest = hashlib.sha256(validator_response.encode("utf-8")).hexdigest()
        validation = _validate_bundle_response(validator_response.encode("utf-8"))
        cross = validation["cross_arm"]
        if (
            call.get("validator_request") != validator_request
            or call.get("validator_response_sha256") != validator_digest
            or bundle.bundle_validation.evidence_sha256 != validator_digest
            or bundle.bundle_validation.validator_adapter_id
            != adapters.intervention_validator.adapter_id
            or bundle.bundle_validation.treatment_states_distinct
            is not _yes(cross["treatment_states_distinct"])
            or bundle.bundle_validation.no_third_requirement
            is not _yes(cross["no_third_requirement"])
            or bundle.bundle_validation.matched_controls
            is not _yes(cross["matched_controls"])
            or any(
                bundle.variant(role).validation.evidence_sha256 != validator_digest
                or bundle.variant(role).validation.validator_adapter_id
                != adapters.intervention_validator.adapter_id
                or bundle.variant(role).validation.task_preserved
                is not _yes(validation[role.value]["task_preserved"])
                or bundle.variant(role).validation.context_preserved
                is not _yes(validation[role.value]["context_preserved"])
                or bundle.variant(role).validation.non_target_preserved
                is not _yes(validation[role.value]["non_target_preserved"])
                or bundle.variant(role).validation.role_contract_satisfied
                is not _yes(validation[role.value]["role_contract_satisfied"])
                or bundle.variant(role).validation.contradiction
                is not (
                    SemanticVerdict.YES
                    if validation[role.value]["contradiction"]
                    else SemanticVerdict.NO
                )
                for role in SUCCESSOR_ARM_ROLE_ORDER
            )
        ):
            raise SuccessorExperimentError("stored intervention validator evidence drifts")


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


def _selection_provenance(
    root: Path,
    selection: Mapping[str, Any],
) -> tuple[SuccessorSelectionProvenance, set[str], dict[str, Any]]:
    """Derive selection identity from an outcome-blind predecessor artifact."""

    source = selection.get("source")
    if source == "selector_bridge":
        expected = {
            "source",
            "selection_bundle_path",
            "selection_bundle_sha256",
            "bridge_bundle_path",
            "bridge_bundle_sha256",
        }
        if set(selection) != expected:
            raise SuccessorExperimentError(
                "selector bridge selection fields are not exact"
            )
        selection_root = _inside(root, selection.get("selection_bundle_path"))
        bridge_root = _inside(root, selection.get("bridge_bundle_path"))
        if bundle_digest(selection_root) != selection.get("selection_bundle_sha256"):
            raise SuccessorExperimentError("selector selection bundle drift")
        if bundle_digest(bridge_root) != selection.get("bridge_bundle_sha256"):
            raise SuccessorExperimentError("selector bridge bundle drift")
        frozen_selection = load_selection_freeze_bundle(selection_root)
        bridge = load_bridge_freeze_bundle(bridge_root, selection_root)
        successful = {
            record.final_hypothesis_id
            for record in bridge.records
            if record.final_hypothesis_id is not None
        }
        selection_digest = bundle_digest(selection_root)
        bridge_digest = bundle_digest(bridge_root)
        return (
            SuccessorSelectionProvenance(
                "selector_bridge",
                frozen_selection.universe.manifest_id,
                frozen_selection.selection_id,
                bridge_digest,
                bridge.bridge_map_id,
                tuple(sorted(successful)),
            ),
            successful,
            {
                "schema_version": "1.0",
                "source": "selector_bridge",
                "selection": canonical_value(frozen_selection),
                "bridge": canonical_value(bridge),
                "selection_bundle_sha256": selection_digest,
                "bridge_bundle_sha256": bridge_digest,
                "selection_bundle_manifest": read_json(
                    selection_root / "manifest.json"
                ),
                "bridge_bundle_manifest": read_json(bridge_root / "manifest.json"),
            },
        )
    if source == "frozen_registry":
        expected = {"source", "registry_path", "registry_sha256"}
        if set(selection) != expected:
            raise SuccessorExperimentError(
                "frozen registry selection fields are not exact"
            )
        registry_path = _inside(root, selection.get("registry_path"))
        _require_file_hash(registry_path, selection.get("registry_sha256"))
        registry = _object(read_json(registry_path), "successor selection registry")
        if set(registry) != {
            "schema_version",
            "stage",
            "candidate_universe_manifest_id",
            "candidate_keys",
            "candidate_bindings",
            "outcomes_consulted",
        } or registry.get("schema_version") != "1.0" or registry.get(
            "stage"
        ) != "outcome_blind_hypothesis_registry" or registry.get(
            "outcomes_consulted"
        ) is not False:
            raise SuccessorExperimentError(
                "successor registry is not a frozen outcome-blind source"
            )
        candidate_keys = set(_strings(registry.get("candidate_keys"), "candidate keys"))
        bindings = _list(registry.get("candidate_bindings"), "candidate bindings")
        if any(
            set(_object(item, "candidate binding"))
            != {"candidate_key", "hypothesis_config_sha256"}
            for item in bindings
        ):
            raise SuccessorExperimentError("successor registry candidate bindings drift")
        binding_keys = tuple(
            _text(item["candidate_key"], "registry binding candidate key")
            for item in bindings
        )
        for item in bindings:
            _digest(item["hypothesis_config_sha256"], "registry hypothesis config")
        if (
            not candidate_keys
            or len(candidate_keys) != len(registry["candidate_keys"])
            or tuple(sorted(candidate_keys)) != binding_keys
        ):
            raise SuccessorExperimentError("successor registry candidate support is invalid")
        candidate_manifest = _text(
            registry.get("candidate_universe_manifest_id"),
            "candidate universe manifest id",
        )
        registry_digest = selection["registry_sha256"]
        return (
            SuccessorSelectionProvenance(
                "frozen_registry",
                candidate_manifest,
                content_id("successor_registry_selection_", registry),
                registry_digest,
                selected_predecessor_ids=tuple(sorted(candidate_keys)),
            ),
            candidate_keys,
            {
                "schema_version": "1.0",
                "source": "frozen_registry",
                "registry": registry,
                "registry_sha256": registry_digest,
                "registry_payload": registry_path.read_text(encoding="utf-8"),
            },
        )
    raise SuccessorExperimentError("successor selection source is invalid")


def _validate_successor_config_envelope(config: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "study_name",
        "phase",
        "scientific_claim_allowed",
        "task_corpus",
        "prompt_tsg_catalog",
        "selection",
        "hypotheses",
        "intervention",
        "generation",
        "functional_judge",
        "randomization",
        "analysis",
    }
    if set(config) != expected or config.get("schema_version") != "2.0":
        raise SuccessorExperimentError("successor config envelope is invalid")
    # Schema 2.0 is the active prospective path.  Development freezes created
    # before qualification binding are intentionally archival: they fail this
    # exact shape check rather than being reinterpreted under the active method.
    functional = config.get("functional_judge")
    if not isinstance(functional, Mapping) or set(functional) != {
        "evaluator_config_path",
        "evaluator_config_sha256",
        "prompt_path",
        "prompt_sha256",
        "qualification_path",
        "qualification_sha256",
    }:
        raise SuccessorExperimentError(
            "successor functional judge fields are not exact"
        )


def _load_inputs(
    repository_root: Path,
    config_path: Path,
    *,
    functional_qualification_override: Mapping[str, Any] | None = None,
    functionality_power_qualification_override: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    root = repository_root.resolve()
    config_file = _inside(root, config_path)
    config = _object(_read_json_exact(config_file), "successor config")
    _validate_successor_config_envelope(config)
    if config["phase"] not in {"development_canary", "confirmatory"}:
        raise SuccessorExperimentError("successor phase is invalid")
    if type(config["scientific_claim_allowed"]) is not bool or (
        config["phase"] == "development_canary" and config["scientific_claim_allowed"]
    ):
        raise SuccessorExperimentError("successor claim boundary is invalid")

    corpus = _object(config["task_corpus"], "task corpus")
    corpus_root = _inside(root, corpus.get("path"))
    verify_bundle(corpus_root)
    corpus_digest = bundle_digest(corpus_root)
    if corpus_digest != corpus.get("bundle_sha256"):
        raise SuccessorExperimentError("successor task corpus bundle drift")
    rows = _list(read_json(corpus_root / "tasks.json"), "task corpus rows")
    by_task = {
        _text(row.get("task_id"), "task id"): row
        for row in (_object(value, "task row") for value in rows)
    }
    task_ids = _strings(corpus.get("task_ids"), "task ids")
    if (
        not task_ids
        or len(task_ids) != len(set(task_ids))
        or set(task_ids) - set(by_task)
        or corpus.get("selection_outcomes_consulted") is not False
    ):
        raise SuccessorExperimentError("successor task selection is invalid")
    task_rows = tuple(by_task[task_id] for task_id in task_ids)
    if any(row.get("source_records_used_as_outcomes") is not False for row in task_rows):
        raise SuccessorExperimentError("successor task corpus is not outcome blind")
    tasks = tuple(sorted((_task(row) for row in task_rows), key=lambda item: item.task_id))
    if len({task.semantic_cluster_id for task in tasks}) != len(tasks):
        raise SuccessorExperimentError("successor tasks must be unique task units")
    if any(task.split is not Split.CONFIRM for task in tasks):
        raise SuccessorExperimentError("successor study requires confirmatory tasks")
    task_rows_by_id = {row["task_id"]: row for row in task_rows}

    catalog_section = _object(config["prompt_tsg_catalog"], "Prompt TSG catalog")
    catalog_path = _inside(root, catalog_section.get("path"))
    _require_file_hash(catalog_path, catalog_section.get("sha256"))
    catalog = load_catalog(catalog_path)
    frozen_catalog_sha256 = catalog_sha256(catalog)
    graphs = {}
    for row in task_rows:
        graph = prompt_tsg_from_record(_object(row.get("prompt_tsg"), "Prompt TSG"))
        validate_prompt_tsg(graph, prompt=row["prompt"], catalog=catalog)
        if graph.task_id != row["task_id"]:
            raise SuccessorExperimentError("Prompt TSG task binding drift")
        graphs[row["task_id"]] = graph

    (
        selection_provenance,
        selected_predecessors,
        selection_evidence,
    ) = _selection_provenance(
        root,
        _object(config["selection"], "selection"),
    )

    intervention = _object(config["intervention"], "intervention")
    executor = _locked_json(root, intervention, "executor_config")
    validator = _locked_json(root, intervention, "validator_config")
    executor_prompt = _locked_text(root, intervention, "executor_prompt")
    validator_prompt = _locked_text(root, intervention, "validator_prompt")
    _validate_provider_config(executor, "intervention executor")
    _validate_provider_config(validator, "intervention validator")
    maximum_prompt_characters = intervention.get("maximum_prompt_characters")
    if type(maximum_prompt_characters) is not int or maximum_prompt_characters <= 0:
        raise SuccessorExperimentError("maximum_prompt_characters is invalid")

    generation = _object(config["generation"], "generation")
    model_rows = tuple(
        _object(value, "generation model")
        for value in _list(generation.get("models"), "generation models")
    )
    if not model_rows:
        raise SuccessorExperimentError("generation.models cannot be empty")
    model_ids = tuple(_text(item.get("model_id"), "model id") for item in model_rows)
    if len(model_ids) != len(set(model_ids)):
        raise SuccessorExperimentError("generation model ids are duplicated")
    generation_prompts = {}
    for item in model_rows:
        _validate_provider_config(
            item,
            "generation model",
            seed_must_be_null=True,
            exact_extra_fields={"prompt_path", "prompt_sha256"},
        )
        generation_prompts[item["model_id"]] = _locked_text(root, item, "prompt")

    functional = _object(config["functional_judge"], "functional judge")
    functional_evaluator = _locked_json(root, functional, "evaluator_config")
    functional_prompt = _locked_text(root, functional, "prompt")
    _validate_provider_config(functional_evaluator, "functional judge")
    _text(functional_evaluator.get("candidate_id"), "functional judge candidate id")
    functional_qualification = (
        _load_functional_qualification(root, functional, functional_evaluator)
        if functional_qualification_override is None
        else _validate_frozen_functional_qualification(
            functional,
            functional_evaluator,
            functional_qualification_override,
        )
    )

    analysis_config = _object(config["analysis"], "analysis")
    _analysis_plan(analysis_config)
    functionality_power_qualification = (
        _load_functionality_power_qualification(
            root,
            analysis_config,
            model_ids,
        )
        if functionality_power_qualification_override is None
        else _validate_frozen_functionality_power_qualification(
            analysis_config,
            model_ids,
            functionality_power_qualification_override,
        )
    )

    raw_hypotheses = tuple(
        _object(value, "hypothesis")
        for value in _list(config["hypotheses"], "hypotheses")
    )
    if selection_provenance.source == "frozen_registry":
        registry_bindings = _list(
            selection_evidence["registry"].get("candidate_bindings"),
            "registry candidate bindings",
        )
        expected_bindings = [
            {
                "candidate_key": _text(item.get("candidate_key"), "hypothesis candidate key"),
                "hypothesis_config_sha256": content_hash(item),
            }
            for item in sorted(raw_hypotheses, key=lambda row: row["candidate_key"])
        ]
        if registry_bindings != expected_bindings:
            raise SuccessorExperimentError(
                "frozen registry does not bind complete hypothesis configurations"
            )
    if not raw_hypotheses:
        raise SuccessorExperimentError("successor hypotheses cannot be empty")
    oracle_sections = tuple(
        _load_oracle(root, _object(raw["security_oracle"], "security Oracle"))
        for raw in raw_hypotheses
    )
    adapters = _adapters(
        frozen_catalog_sha256,
        selection_provenance,
        executor,
        executor_prompt,
        validator,
        validator_prompt,
        model_rows,
        generation_prompts,
        oracle_sections,
        functional_evaluator,
        functional_prompt,
        functional_qualification,
    )

    query_by_id = {item["query_id"]: item for item in catalog["queries"]}
    loaded_hypotheses = []
    seen_candidate_keys = set()
    for raw, oracle in zip(raw_hypotheses, oracle_sections, strict=True):
        operation = Operation(raw["operation"])
        protocol = arm_protocol_v2(
            operation,
            protocol_policy_sha256=_digest(
                raw.get("arm_protocol_policy_sha256"), "arm protocol policy"
            ),
        )
        realization_section = _object(raw["realization_policy"], "realization policy")
        realization_specs = []
        for realization in _list(realization_section.get("realizations"), "realizations"):
            realization = _object(realization, "realization")
            instructions = _object(realization.get("arm_instructions"), "arm instructions")
            if set(instructions) != {role.value for role in SUCCESSOR_ARM_ROLE_ORDER}:
                raise SuccessorExperimentError("realization arm instruction support is incomplete")
            realization_specs.append(
                RealizationSpecV2(
                    _text(realization.get("label"), "realization label"),
                    realization.get("weight"),
                    adapters.intervention_executor.adapter_id,
                    tuple(
                        (role, _text(instructions[role.value], "arm instruction"))
                        for role in SUCCESSOR_ARM_ROLE_ORDER
                    ),
                    _digest(realization.get("matching_policy_sha256"), "matching policy"),
                    _digest(
                        realization.get("validation_policy_sha256"),
                        "validation policy",
                    ),
                )
            )
        realization_policy = RealizationPolicyV2(
            _text(realization_section.get("policy_key"), "realization policy key"),
            protocol,
            tuple(sorted(realization_specs, key=lambda item: item.realization_spec_id)),
        )
        candidate_key = _text(raw.get("candidate_key"), "candidate key")
        if candidate_key in seen_candidate_keys:
            raise SuccessorExperimentError("successor candidate keys are duplicated")
        seen_candidate_keys.add(candidate_key)
        query_id = _text(raw.get("context_query_id"), "context query id")
        query = query_by_id.get(query_id)
        feature_id = _text(raw.get("actionable_feature_id"), "actionable feature id")
        cwe = _text(raw.get("cwe"), "CWE")
        archetype = _text(raw.get("archetype"), "archetype")
        if (
            query is None
            or query["actionable_feature_id"] != feature_id
            or query["cwe_id"] != cwe
            or query["task_family"] != archetype
        ):
            raise SuccessorExperimentError("hypothesis drifts from its Prompt TSG query")
        skeleton = CandidateSkeletonV2(
            candidate_key,
            query_id,
            (feature_id,),
            operation,
            cwe,
            archetype,
            _text(raw.get("outcome_id"), "outcome id"),
            ExpectedDirection(raw["expected_direction"]),
            realization_policy.realization_policy_id,
        )
        target = _object(raw["target_spec"], "target spec")
        if (
            target.get("context_query_catalog_sha256") != frozen_catalog_sha256
            or target.get("feature_catalog_sha256") != frozen_catalog_sha256
        ):
            raise SuccessorExperimentError("target spec catalog binding drift")
        target_spec = TargetSpecV2(
            skeleton.candidate_skeleton_id,
            skeleton.context_query_id,
            skeleton.actionable_feature_id,
            skeleton.operation,
            frozen_catalog_sha256,
            frozen_catalog_sha256,
            _digest(target.get("allowed_delta_policy_sha256"), "allowed delta policy"),
        )
        hypothesis = FrozenHypothesisV2(skeleton, target_spec)
        source_rows = tuple(
            _object(value, "source gate")
            for value in _list(raw.get("source_gates"), "source gates")
        )
        source_by_task = {row.get("task_id"): row for row in source_rows}
        if len(source_by_task) != len(source_rows) or set(source_by_task) != set(task_ids):
            raise SuccessorExperimentError("source gates must cover every selected task once")
        eligibilities = []
        for task in tasks:
            graph = graphs[task.task_id]
            context = query_context(
                graph,
                query=query,
                cwe=task.cwe,
                task_family=task.archetype,
            )
            state = feature_state(graph, feature_id)
            source = source_by_task[task.task_id]
            evidence_ids = tuple(_strings(source.get("target_evidence_node_ids"), "evidence ids"))
            counterpart = source.get("neutral_counterpart")
            target_nodes = tuple(
                sorted(node.node_id for node in graph.nodes if node.semantic_id == feature_id)
            )
            if operation is Operation.ADD:
                if evidence_ids or counterpart is not None:
                    raise SuccessorExperimentError("ADD source gate cannot carry REMOVE evidence")
            elif state is QueryState.PRESENT:
                if tuple(sorted(evidence_ids)) != target_nodes:
                    raise SuccessorExperimentError("REMOVE evidence does not bind target nodes")
                _text(counterpart, "REMOVE neutral counterpart")
                if counterpart == task.prompt:
                    raise SuccessorExperimentError(
                        "REMOVE counterpart cannot equal the source prompt"
                    )
            elif evidence_ids or counterpart is not None:
                raise SuccessorExperimentError("absent REMOVE source cannot carry target evidence")
            eligibilities.append(
                source_eligibility_v2(
                    hypothesis,
                    task_id=task.task_id,
                    task_unit_id=task.semantic_cluster_id,
                    prompt_tsg_id=graph.tsg_id,
                    prompt_sha256=task.prompt_sha256,
                    context_state=context.state,
                    feature_state=state,
                    target_evidence_node_ids=evidence_ids,
                    neutral_counterpart=counterpart,
                    eligibility_policy_sha256=_digest(
                        raw.get("eligibility_policy_sha256"),
                        "eligibility policy",
                    ),
                )
            )
        if not any(item.eligible for item in eligibilities):
            raise SuccessorExperimentError("hypothesis has no source-gate-eligible task")
        loaded_hypotheses.append(
            {
                "hypothesis": hypothesis,
                "realization_policy": realization_policy,
                "source_eligibilities": tuple(
                    sorted(eligibilities, key=lambda item: item.task_id)
                ),
                "security_oracle": oracle,
            }
        )
    if len({item["hypothesis"].hypothesis_id for item in loaded_hypotheses}) != len(
        loaded_hypotheses
    ):
        raise SuccessorExperimentError("successor hypotheses are duplicated")
    if selection_provenance.source == "selector_bridge":
        actual_predecessors = {
            item["hypothesis"].hypothesis_id for item in loaded_hypotheses
        }
    else:
        actual_predecessors = {
            item["hypothesis"].skeleton.candidate_key
            for item in loaded_hypotheses
        }
    if actual_predecessors != selected_predecessors:
        raise SuccessorExperimentError(
            "successor hypotheses drift from the outcome-blind predecessor"
        )

    randomization = _object(config["randomization"], "randomization")
    slots = tuple(_integers(randomization.get("request_randomness_slots"), "request slots"))
    if (
        not slots
        or len(slots) != len(set(slots))
        or len(slots) % len(SUCCESSOR_ARM_ROLE_ORDER)
        or any(value < 0 for value in slots)
        or type(randomization.get("seed")) is not int
        or (
            randomization.get("provider_seed") is not None
            and (
                type(randomization["provider_seed"]) is not int
                or randomization["provider_seed"] < 0
            )
        )
    ):
        raise SuccessorExperimentError("successor randomization is invalid")
    if functionality_power_qualification is not None:
        planned_units = functionality_power_qualification["qualification"][
            "planned_task_units_per_coordinate"
        ]
        if any(
            len(
                {
                    gate.task_id
                    for gate in item["source_eligibilities"]
                    if gate.eligible
                }
            )
            < planned_units
            for item in loaded_hypotheses
        ):
            raise SuccessorExperimentError(
                "successor task support is smaller than the functionality power plan"
            )
    return {
        "root": root,
        "config": config,
        "corpus_bundle_sha256": corpus_digest,
        "catalog": catalog,
        "graphs": graphs,
        "catalog_sha256": frozen_catalog_sha256,
        "selection_provenance": selection_provenance,
        "selection_evidence": selection_evidence,
        "tasks": tasks,
        "task_rows_by_id": task_rows_by_id,
        "hypotheses": tuple(loaded_hypotheses),
        "executor": executor,
        "executor_prompt": executor_prompt,
        "validator": validator,
        "validator_prompt": validator_prompt,
        "maximum_prompt_characters": maximum_prompt_characters,
        "generation_models": model_rows,
        "generation_by_model": {item["model_id"]: item for item in model_rows},
        "generation_prompts": generation_prompts,
        "functional_evaluator": functional_evaluator,
        "functional_prompt": functional_prompt,
        "functional_qualification": functional_qualification,
        "functionality_power_qualification": functionality_power_qualification,
        "maximum_unknown_fraction": float(
            analysis_config["maximum_unknown_fraction"]
        ),
        "adapters": adapters,
    }


def _variant_context_state(
    graph: Any,
    hypothesis: FrozenHypothesisV2,
    catalog: Mapping[str, Any],
) -> QueryState:
    query = next(
        (
            item for item in catalog["queries"]
            if item["query_id"] == hypothesis.skeleton.context_query_id
        ),
        None,
    )
    if query is None:
        raise SuccessorExperimentError("variant Prompt TSG context query is absent")
    return query_context(
        graph,
        query=query,
        cwe=hypothesis.skeleton.cwe,
        task_family=hypothesis.skeleton.archetype,
    ).state


def _materialize_bundle(
    inputs: Mapping[str, Any],
    hypothesis_input: Mapping[str, Any],
    task: Mapping[str, Any],
    eligibility: SourceEligibilityV2,
    realization: RealizationSpecV2,
    complete: Complete,
    calls: list[dict[str, Any]],
) -> TaskRealizationBundleV2:
    hypothesis = hypothesis_input["hypothesis"]
    protocol = hypothesis_input["realization_policy"].arm_protocol
    request = {
        "request_kind": "blind_successor_prompt_intervention",
        "source_prompt": task["prompt"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "operation": hypothesis.skeleton.operation.value,
        "target_spec": canonical_value(hypothesis.target_spec),
        "source_gate": {
            "context_query_id": hypothesis.skeleton.context_query_id,
            "target_evidence_node_ids": list(eligibility.target_evidence_node_ids),
            "neutral_counterpart": eligibility.neutral_counterpart,
        },
        "arm_protocol": {
            role.value: {
                "label": protocol.label(role),
                "instruction": realization.instruction(role),
            }
            for role in SUCCESSOR_ARM_ROLE_ORDER
        },
        "blindness": {
            "selector_identity_withheld": True,
            "expected_direction_withheld": True,
            "generated_code_withheld": True,
            "oracle_and_functional_outcomes_withheld": True,
        },
        "output_schema": {
            f"{role.value}_prompt": "complete rewritten task prompt"
            for role in SUCCESSOR_ARM_ROLE_ORDER
        },
    }
    raw = _complete(complete, request, inputs["executor"], inputs["executor_prompt"])
    value = _json_object(raw, "successor intervention response")
    expected = {f"{role.value}_prompt" for role in SUCCESSOR_ARM_ROLE_ORDER}
    if set(value) != expected:
        raise SuccessorExperimentError("successor executor response schema drift")
    prompts = {}
    for role in SUCCESSOR_ARM_ROLE_ORDER:
        text = value[f"{role.value}_prompt"]
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or len(text) > inputs["maximum_prompt_characters"]
        ):
            raise SuccessorExperimentError("successor prompt variant format drift")
        prompts[role] = text
    if len({content_hash(value) for value in prompts.values()}) != len(
        SUCCESSOR_ARM_ROLE_ORDER
    ):
        raise SuccessorExperimentError("successor executor collapsed four prompt variants")

    validation_request = {
        "request_kind": "blind_successor_prompt_validation",
        "source_prompt": task["prompt"],
        "functional_requirements": task["functional_contract"]["requirements"],
        "operation": hypothesis.skeleton.operation.value,
        "target_spec": canonical_value(hypothesis.target_spec),
        "source_gate": request["source_gate"],
        "arm_protocol": request["arm_protocol"],
        "variants": {role.value: prompts[role] for role in SUCCESSOR_ARM_ROLE_ORDER},
        "prompt_tsg_contract": {
            "catalog_sha256": inputs["catalog_sha256"],
            "maximum_facts_per_arm": 128,
            "maximum_relations_per_arm": 256,
            "evidence_must_be_exact_span": True,
        },
        "blindness": {
            "selector_identity_withheld": True,
            "expected_direction_withheld": True,
            "generated_code_withheld": True,
            "oracle_and_functional_outcomes_withheld": True,
            "generation_model_identity_withheld": True,
        },
    }
    validator_raw = _complete(
        complete,
        validation_request,
        inputs["validator"],
        inputs["validator_prompt"],
    )
    validation = _validate_bundle_response(validator_raw)
    executor_digest = hashlib.sha256(raw).hexdigest()
    validator_digest = hashlib.sha256(validator_raw).hexdigest()
    arm_validations = {
        role: ArmSemanticValidationV2(
            _yes(validation[role.value]["task_preserved"]),
            _yes(validation[role.value]["context_preserved"]),
            _yes(validation[role.value]["non_target_preserved"]),
            _yes(validation[role.value]["role_contract_satisfied"]),
            SemanticVerdict.YES
            if validation[role.value]["contradiction"]
            else SemanticVerdict.NO,
            inputs["adapters"].intervention_validator.adapter_id,
            validator_digest,
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    }
    cross = validation["cross_arm"]
    bundle_validation = BundleValidationV2(
        _yes(cross["treatment_states_distinct"]),
        _yes(cross["no_third_requirement"]),
        _yes(cross["matched_controls"]),
        inputs["adapters"].intervention_validator.adapter_id,
        validator_digest,
    )
    # The executor returns complete prompts.  This is required for genuine REMOVE;
    # the legacy append-only assembler cannot delete an existing requirement.
    source_graph = inputs["graphs"][task["task_id"]]
    source_context = _variant_context_state(source_graph, hypothesis, inputs["catalog"])
    source_target = feature_state(source_graph, hypothesis.skeleton.actionable_feature_id)
    variants = []
    for role in SUCCESSOR_ARM_ROLE_ORDER:
        proposal = validation["prompt_tsg"][role.value]
        try:
            graph = build_prompt_tsg(
                task_id=task["task_id"],
                prompt=prompts[role],
                extractor_id=inputs["adapters"].intervention_validator.adapter_id,
                catalog=inputs["catalog"],
                facts=proposal["facts"],
                relations=proposal["relations"],
                unresolved_semantics=proposal["unresolved_semantics"],
            )
            validate_prompt_tsg(graph, prompt=prompts[role], catalog=inputs["catalog"])
        except (TypeError, ValueError) as exc:
            raise SuccessorExperimentError("variant Prompt TSG cannot be rebuilt") from exc
        context = _variant_context_state(graph, hypothesis, inputs["catalog"])
        target = feature_state(graph, hypothesis.skeleton.actionable_feature_id)
        expected_target = (
            QueryState.PRESENT
            if role is PolicyArmRoleV2.TARGET
            and hypothesis.skeleton.operation is Operation.ADD
            else QueryState.ABSENT
            if role in {PolicyArmRoleV2.TARGET, PolicyArmRoleV2.GENERIC}
            and hypothesis.skeleton.operation is Operation.REMOVE
            else source_target
        )
        source_non_target = tuple(sorted(
            (node.node_type, node.semantic_id, tuple(node.attributes))
            for node in source_graph.nodes
            if node.semantic_id not in {"task.root", hypothesis.skeleton.actionable_feature_id}
        ))
        variant_non_target = tuple(sorted(
            (node.node_type, node.semantic_id, tuple(node.attributes))
            for node in graph.nodes
            if node.semantic_id not in {"task.root", hypothesis.skeleton.actionable_feature_id}
        ))
        projection = {
            "task_id": graph.task_id,
            "context": context.value,
            "target": target.value,
            "non_target": variant_non_target,
        }
        if (
            graph.task_id != task["task_id"]
            or context is not source_context
            or target is not expected_target
            or variant_non_target != source_non_target
        ):
            raise SuccessorExperimentError("variant Prompt TSG violates AllowedDelta")
        variants.append(ArmVariantV2(
            role,
            protocol.label(role),
            InterventionExecution(
                prompts[role],
                inputs["adapters"].intervention_executor.adapter_id,
                executor_digest,
            ),
            prompts[role],
            arm_validations[role],
            canonical_json(prompt_tsg_record(graph)),
            content_hash(projection),
        ))
    variants = tuple(variants)
    result = TaskRealizationBundleV2(
        hypothesis.hypothesis_id,
        hypothesis.target_spec.target_spec_id,
        eligibility.source_eligibility_id,
        task["task_id"],
        task["task_unit_id"],
        realization.realization_spec_id,
        protocol.arm_protocol_id,
        eligibility.prompt_sha256,
        eligibility.neutral_counterpart_sha256,
        variants,
        bundle_validation,
    )
    calls.append(
        {
            "stage": "intervention",
            "hypothesis_id": hypothesis.hypothesis_id,
            "task_id": task["task_id"],
            "realization_spec_id": realization.realization_spec_id,
            "executor_request": request,
            "executor_response_sha256": executor_digest,
            "executor_response": raw.decode("utf-8"),
            "validator_request": validation_request,
            "validator_response_sha256": validator_digest,
            "validator_response": validator_raw.decode("utf-8"),
        }
    )
    return result


def _measure_assignment(
    inputs: Mapping[str, Any],
    assignment: Any,
    task: Mapping[str, Any],
    prompt: str,
    oracle: Mapping[str, Any],
    complete: Complete,
    security_evaluate: SecurityEvaluate,
) -> tuple[Measurement, dict[str, Any]]:
    evaluator = dict(inputs["generation_by_model"][assignment.block.model_id])
    if assignment.provider_seed is not None:
        evaluator["seed"] = assignment.provider_seed
    generation_request = {
        "request_kind": "successor_code_generation",
        "task_prompt": prompt,
        "language": task["functional_contract"].get("language", "python"),
        "output_schema": {"code": "complete source string"},
    }
    def provider_complete(
        request: dict[str, Any],
        provider: Mapping[str, Any],
        system_prompt: str,
    ) -> bytes:
        return _complete(complete, request, provider, system_prompt)

    try:
        measurement, evidence = measure_generated_code(
            assignment_id=assignment.assignment_id,
            generation_request=generation_request,
            generation_evaluator=evaluator,
            generation_prompt=inputs["generation_prompts"][assignment.block.model_id],
            source_task_prompt=task["prompt"],
            functional_contract=_object(task["functional_contract"], "functional contract"),
            functional_evaluator=inputs["functional_evaluator"],
            functional_prompt=inputs["functional_prompt"],
            security_profile_id=oracle["profile_id"],
            complete=provider_complete,
            security_evaluate=security_evaluate,
            security_replay=evaluate_security_profile,
        )
    except MeasurementExecutionError as error:
        raise SuccessorExperimentError(str(error)) from error
    provider_calls = [
        {
            "stage": "generation",
            "assignment_id": assignment.assignment_id,
            "model_id": assignment.block.model_id,
            "provider_seed": assignment.provider_seed,
            "request": generation_request,
            "response_sha256": evidence["generation_response_sha256"],
            "response": evidence["generation_response"],
        }
    ]
    if evidence["functional_response"] is not None:
        provider_calls.append(
            {
                "stage": "functional_judge",
                "assignment_id": assignment.assignment_id,
                "request": evidence["functional_request"],
                "response_sha256": evidence["functional_response_sha256"],
                "response": evidence["functional_response"],
            }
        )
    record = {
        "generation_model_id": assignment.block.model_id,
        "security_profile_id": oracle["profile_id"],
        "generation_request": generation_request,
        "generation_response": evidence["generation_response"],
        "code": evidence["code"],
        "syntax_valid": evidence["syntax_valid"],
        "security": evidence["security"],
        "functional_request": evidence["functional_request"],
        "functional_response": evidence["functional_response"],
        "provider_calls": provider_calls,
    }
    if evidence["functional_validated"] is not None:
        record["functional_validated"] = evidence["functional_validated"]
    return measurement, record


def _report(
    config: Mapping[str, Any],
    study: Any,
    analysis: Any,
    verification: Mapping[str, Any],
) -> dict[str, Any]:
    measurements = analysis.ledger.measurements
    estimates = _successor_report_estimates(analysis.inference)
    families = _successor_report_families(analysis.inference)
    return {
        "schema_version": "2.0",
        "status": "SUCCESSOR_EXPERIMENT_COMPLETE",
        "study_name": config["study_name"],
        "phase": config["phase"],
        "study_id": study.study_id,
        "analysis_plan_id": study.analysis_plan.analysis_plan_id,
        "inference_id": analysis.inference.inference_id,
        "selection_provenance": canonical_value(study.selection_provenance),
        "tasks": len(study.tasks),
        "hypotheses": len(study.hypotheses),
        "models": list(study.randomization.models),
        "assignments": len(study.randomization.assignments),
        "ledger_measurements": len(measurements),
        "primary_estimand": "assigned-arm task-unit ITT Target minus Noop risk difference",
        "code_statuses": dict(Counter(item.code_status.value for item in measurements)),
        "oracle_statuses": dict(Counter(item.oracle_status.value for item in measurements)),
        "functional_statuses": dict(
            Counter(item.functional_status.value for item in measurements)
        ),
        "oracle_unknown_assignments": sum(
            item.oracle_status is OracleStatus.UNKNOWN for item in measurements
        ),
        "unknown_preserved_not_imputed_secure": True,
        "estimates": estimates,
        "bootstrap_families": families,
        "realization_robustness": (
            None
            if analysis.inference.robustness is None
            else canonical_value(analysis.inference.robustness)
        ),
        "claim_assessments": verification["claim_assessments"],
        "security_claim_ready_coordinates": verification[
            "security_claim_ready_coordinates"
        ],
        "practical_success_claim_ready_coordinates": verification[
            "practical_success_claim_ready_coordinates"
        ],
        "inference_practical_labels_are_diagnostic_not_claims": True,
        "cross_model_replication": _cross_model_replication(
            study.analysis_plan, study.hypotheses, analysis.inference
        ),
        "verification": dict(verification),
        "scientific_claim_allowed": bool(config["scientific_claim_allowed"]),
    }


def _cross_model_replication(
    plan: SuccessorAnalysisPlan,
    hypotheses: tuple[FrozenHypothesisV2, ...],
    inference: SuccessorInferenceResult,
) -> list[dict[str, Any]]:
    """Apply the frozen per-model rule without pooling model outcomes."""

    primary_family = next(
        (
            item for item in inference.families
            if item.family is SuccessorIntervalFamily.PRIMARY_SECURITY
        ),
        None,
    )
    interval_by_coordinate = {} if primary_family is None else {
        item.coordinate_id: item
        for item in primary_family.intervals
        if item.contrast is SuccessorContrast.TARGET_NOOP
    }
    rows = []
    for hypothesis in hypotheses:
        estimates = tuple(
            item for item in inference.estimates
            if item.hypothesis_id == hypothesis.hypothesis_id
            and item.metric is plan.primary_metric
        )
        oriented = []
        reverse = []
        for estimate in estimates:
            interval = interval_by_coordinate.get(estimate.coordinate_id)
            oriented.append(
                interval is not None
                and (
                    interval.lower > 0.0
                    if hypothesis.skeleton.expected_direction is ExpectedDirection.INCREASE
                    else interval.upper < 0.0
                )
            )
            reverse.append(
                interval is not None
                and (
                    interval.upper < 0.0
                    if hypothesis.skeleton.expected_direction is ExpectedDirection.INCREASE
                    else interval.lower > 0.0
                )
            )
        if len(estimates) < plan.minimum_replication_models:
            label = "not_applicable_insufficient_models"
        elif any(reverse):
            label = "cross_model_contradicted"
        elif all(oriented):
            label = "cross_model_replicated"
        else:
            label = "cross_model_not_established"
        rows.append({
            "hypothesis_id": hypothesis.hypothesis_id,
            "rule": plan.cross_model_replication_rule,
            "models": [item.model_id for item in estimates],
            "label": label,
            "pooled": False,
        })
    return rows


def _execution_evidence(inputs: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "prompt_tsg_catalog": inputs["catalog"],
        "prompt_tsg_catalog_sha256": inputs["catalog_sha256"],
        "source_prompt_tsgs": [
            prompt_tsg_record(graph)
            for _, graph in sorted(inputs["graphs"].items())
        ],
        "task_corpus_bundle_sha256": inputs["corpus_bundle_sha256"],
        "task_contracts": [
            {
                "task_id": task_id,
                "functional_contract": row["functional_contract"],
            }
            for task_id, row in sorted(inputs["task_rows_by_id"].items())
        ],
        "intervention_executor": {
            "config": inputs["executor"],
            "prompt": inputs["executor_prompt"],
        },
        "intervention_validator": {
            "config": inputs["validator"],
            "prompt": inputs["validator_prompt"],
        },
        "generation_models": [
            {
                "config": model,
                "prompt": inputs["generation_prompts"][model["model_id"]],
            }
            for model in sorted(
                inputs["generation_models"],
                key=lambda value: value["model_id"],
            )
        ],
        "functional_evaluator": {
            "config": inputs["functional_evaluator"],
            "prompt": inputs["functional_prompt"],
            "qualification": inputs["functional_qualification"],
        },
        "functionality_power_qualification": inputs[
            "functionality_power_qualification"
        ],
        "security_oracles": [
            {
                "hypothesis_id": item["hypothesis"].hypothesis_id,
                "producer_sha256": security_profile_producer_sha256(),
                **item["security_oracle"],
            }
            for item in sorted(
                inputs["hypotheses"],
                key=lambda value: value["hypothesis"].hypothesis_id,
            )
        ],
    }


def _successor_report_estimates(inference: SuccessorInferenceResult) -> list[dict[str, Any]]:
    return [
        {
            "coordinate_id": item.coordinate_id,
            "hypothesis_id": item.hypothesis_id,
            "model_id": item.model_id,
            "metric": item.metric.value,
            "expected_direction": item.expected_direction.value,
            "robustness_scope": (
                "primary_safety"
                if item.metric is Metric.SECURE_YIELD
                else "non_primary_diagnostic"
            ),
            "arms": {
                arm.role.value: {
                    "point": arm.point,
                    "lower": arm.lower,
                    "upper": arm.upper,
                    "assignments": arm.assignments,
                }
                for arm in item.arms
            },
            "contrasts": {
                contrast.contrast.value: {
                    "point": contrast.point,
                    "lower_bound": contrast.lower_bound,
                    "upper_bound": contrast.upper_bound,
                }
                for contrast in item.contrasts
            },
            "robustness_label": item.robustness_label,
            "realization_effects": [
                canonical_value(effect) for effect in item.realization_effects
            ],
            "leave_one_realization_out": [
                canonical_value(effect)
                for effect in item.leave_one_realization_out
            ],
        }
        for item in inference.estimates
    ]


def _successor_report_families(inference: SuccessorInferenceResult) -> list[dict[str, Any]]:
    return [
        {
            "family": item.family.value,
            "status": item.status.value,
            "simultaneous_critical_value": item.simultaneous_critical_value,
            "valid_bootstrap_draws": item.valid_bootstrap_draws,
            "invalid_bootstrap_draws": item.invalid_bootstrap_draws,
            "intervals": [canonical_value(interval) for interval in item.intervals],
        }
        for item in inference.families
    ]


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


def _verify_stored_selection_provenance(
    config: Mapping[str, Any],
    evidence: Mapping[str, Any],
    study: Mapping[str, Any],
    report: Mapping[str, Any],
    randomization: Mapping[str, Any],
) -> None:
    provenance = _object(
        study.get("selection_provenance"),
        "stored successor selection provenance",
    )
    if set(provenance) != {
        "source",
        "candidate_universe_manifest_id",
        "selection_id",
        "artifact_sha256",
        "bridge_map_id",
        "selected_predecessor_ids",
    }:
        raise SuccessorExperimentError("stored successor selection provenance drifts")
    source = provenance.get("source")
    selection = _object(config.get("selection"), "stored selection config")
    if (
        source != selection.get("source")
        or source != evidence.get("source")
        or evidence.get("schema_version") != "1.0"
        or source not in {
        "selector_bridge",
        "frozen_registry",
        }
    ):
        raise SuccessorExperimentError("stored successor selection source drifts")
    if source == "selector_bridge":
        if set(evidence) != {
            "schema_version",
            "source",
            "selection",
            "bridge",
            "selection_bundle_sha256",
            "bridge_bundle_sha256",
            "selection_bundle_manifest",
            "bridge_bundle_manifest",
        }:
            raise SuccessorExperimentError("stored selector evidence fields drift")
        try:
            frozen_selection = selection_from_record(
                _object(evidence.get("selection"), "stored selector freeze")
            )
            bridge = bridge_from_record(
                _object(evidence.get("bridge"), "stored bridge freeze")
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise SuccessorExperimentError(
                "stored selector bundle evidence is not semantically valid"
            ) from exc
        selection_manifest = _object(
            evidence.get("selection_bundle_manifest"),
            "stored selection bundle manifest",
        )
        bridge_manifest = _object(
            evidence.get("bridge_bundle_manifest"),
            "stored bridge bundle manifest",
        )
        selection_payload = (canonical_json(evidence["selection"]) + "\n").encode(
            "utf-8"
        )
        bridge_payload = (canonical_json(evidence["bridge"]) + "\n").encode("utf-8")
        if (
            hashlib.sha256(
                (canonical_json(selection_manifest) + "\n").encode("utf-8")
            ).hexdigest()
            != evidence.get("selection_bundle_sha256")
            or hashlib.sha256(
                (canonical_json(bridge_manifest) + "\n").encode("utf-8")
            ).hexdigest()
            != evidence.get("bridge_bundle_sha256")
            or selection_manifest.get("files", {}).get("selection.json")
            != hashlib.sha256(selection_payload).hexdigest()
            or bridge_manifest.get("files", {}).get("bridge.json")
            != hashlib.sha256(bridge_payload).hexdigest()
        ):
            raise SuccessorExperimentError("stored selector bundle evidence drifts")
        if (
            bridge.selection_id != frozen_selection.selection_id
            or tuple(record.candidate_id for record in bridge.records)
            != frozen_selection.selected_union_candidate_ids
        ):
            raise SuccessorExperimentError("stored selector bridge semantics drift")
        selected = tuple(
            sorted(
                record.final_hypothesis_id
                for record in bridge.records
                if record.final_hypothesis_id is not None
            )
        )
        recomputed = SuccessorSelectionProvenance(
            "selector_bridge",
            frozen_selection.universe.manifest_id,
            frozen_selection.selection_id,
            _digest(
                evidence.get("bridge_bundle_sha256"),
                "stored bridge bundle",
            ),
            bridge.bridge_map_id,
            selected,
        )
        if (
            evidence.get("selection_bundle_sha256")
            != selection.get("selection_bundle_sha256")
            or evidence.get("bridge_bundle_sha256")
            != selection.get("bridge_bundle_sha256")
        ):
            raise SuccessorExperimentError("stored selector bundle lineage drifts")
        hypothesis_ids = tuple(
            sorted(
                content_id("frozen_hypothesis_v2_", hypothesis)
                for hypothesis in _list(study.get("hypotheses"), "stored hypotheses")
            )
        )
        if selected != hypothesis_ids:
            raise SuccessorExperimentError(
                "stored selector bridge does not bind successor hypotheses"
            )
    else:
        if set(evidence) != {
            "schema_version",
            "source",
            "registry",
            "registry_sha256",
            "registry_payload",
        }:
            raise SuccessorExperimentError("stored registry evidence fields drift")
        registry = _object(evidence.get("registry"), "stored successor registry")
        registry_payload = evidence.get("registry_payload")
        if (
            not isinstance(registry_payload, str)
            or hashlib.sha256(registry_payload.encode("utf-8")).hexdigest()
            != evidence.get("registry_sha256")
        ):
            raise SuccessorExperimentError("stored registry payload digest drifts")
        payload_registry = _json_object(
            registry_payload.encode("utf-8"), "stored registry payload"
        )
        if payload_registry != registry:
            raise SuccessorExperimentError("stored registry payload semantics drift")
        if set(registry) != {
            "schema_version",
            "stage",
            "candidate_universe_manifest_id",
            "candidate_keys",
            "candidate_bindings",
            "outcomes_consulted",
        } or registry.get("schema_version") != "1.0" or registry.get(
            "stage"
        ) != "outcome_blind_hypothesis_registry" or registry.get(
            "outcomes_consulted"
        ) is not False:
            raise SuccessorExperimentError("stored registry is not outcome blind")
        selected = tuple(sorted(_strings(registry.get("candidate_keys"), "candidate keys")))
        if not selected or len(selected) != len(set(selected)):
            raise SuccessorExperimentError("stored registry candidate support drifts")
        recomputed = SuccessorSelectionProvenance(
            "frozen_registry",
            _text(
                registry.get("candidate_universe_manifest_id"),
                "stored candidate universe manifest id",
            ),
            content_id("successor_registry_selection_", registry),
            _digest(evidence.get("registry_sha256"), "stored registry artifact"),
            selected_predecessor_ids=selected,
        )
        hypothesis_keys = tuple(
            sorted(
                _object(hypothesis, "stored hypothesis")["skeleton"]["candidate_key"]
                for hypothesis in _list(study.get("hypotheses"), "stored hypotheses")
            )
        )
        expected_bindings = [
            {
                "candidate_key": item["candidate_key"],
                "hypothesis_config_sha256": content_hash(item),
            }
            for item in sorted(
                (
                    _object(value, "config hypothesis")
                    for value in _list(config.get("hypotheses"), "config hypotheses")
                ),
                key=lambda row: row["candidate_key"],
            )
        ]
        if (
            registry.get("candidate_bindings") != expected_bindings
            or selected != hypothesis_keys
            or evidence.get("registry_sha256") != selection.get(
            "registry_sha256"
            )
        ):
            raise SuccessorExperimentError(
                "stored registry does not bind successor hypotheses"
            )
    if (
        canonical_value(recomputed) != provenance
        or randomization.get("selection_id") != recomputed.selection_id
        or report.get("selection_provenance") != provenance
    ):
        raise SuccessorExperimentError("stored report selection provenance drifts")


def _analysis_plan(value: Mapping[str, Any]) -> SuccessorAnalysisPlan:
    required = {
        "metrics",
        "primary_metric",
        "bootstrap_seed",
        "bootstrap_draws",
        "familywise_alpha",
        "maximum_unknown_fraction",
        "functionality_noninferiority_separately_powered",
    }
    allowed = required | {
        "minimum_task_units",
        "minimum_valid_bootstrap_fraction",
        "practical_effect_margin",
        "functionality_noninferiority_margin",
        "minimum_realizations",
        "minimum_task_units_per_realization",
        "realization_practical_equivalence_margin",
        "realization_direction_consistency_threshold",
        "functionality_noninferiority_separately_powered",
        "minimum_replication_models",
        "cross_model_replication_rule",
        "functionality_power_qualification",
    }
    if not required <= set(value) or not set(value) <= allowed:
        raise SuccessorExperimentError("successor analysis plan is invalid")
    separately_powered = value.get(
        "functionality_noninferiority_separately_powered"
    )
    power_reference = value.get("functionality_power_qualification")
    if (
        list(value.get("metrics", ()))
        != [metric.value for metric in _ACTIVE_OUTCOME_METRICS]
        or type(value.get("maximum_unknown_fraction")) is not float
        or not 0.0 <= value["maximum_unknown_fraction"] <= 1.0
        or type(separately_powered) is not bool
        or (
            separately_powered
            and (
                not isinstance(power_reference, Mapping)
                or set(power_reference) != {"path", "sha256"}
                or not isinstance(power_reference.get("path"), str)
                or not power_reference["path"].strip()
                or not is_sha256(power_reference.get("sha256"))
            )
        )
        or (not separately_powered and power_reference is not None)
    ):
        raise SuccessorExperimentError(
            "successor active analysis endpoints or qualification gate are invalid"
        )
    try:
        return SuccessorAnalysisPlan(
            metrics=tuple(Metric(item) for item in value["metrics"]),
            primary_metric=Metric(value["primary_metric"]),
            bootstrap_seed=value["bootstrap_seed"],
            bootstrap_draws=value["bootstrap_draws"],
            alpha=float(value["familywise_alpha"]),
            minimum_task_units=value.get("minimum_task_units", 2),
            minimum_valid_bootstrap_fraction=float(
                value.get("minimum_valid_bootstrap_fraction", 0.9)
            ),
            practical_effect_margin=float(
                value.get("practical_effect_margin", 0.0)
            ),
            functionality_noninferiority_margin=float(
                value.get("functionality_noninferiority_margin", 0.1)
            ),
            minimum_realizations=value.get("minimum_realizations", 2),
            minimum_task_units_per_realization=value.get(
                "minimum_task_units_per_realization",
                2,
            ),
            realization_practical_equivalence_margin=float(
                value.get("realization_practical_equivalence_margin", 0.1)
            ),
            realization_direction_consistency_threshold=float(
                value.get("realization_direction_consistency_threshold", 1.0)
            ),
            functionality_noninferiority_separately_powered=value.get(
                "functionality_noninferiority_separately_powered",
                False,
            ),
            minimum_replication_models=value.get("minimum_replication_models", 2),
            cross_model_replication_rule=value.get(
                "cross_model_replication_rule",
                "oriented_simultaneous_target_noop_each_model_no_pooling",
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("successor analysis plan is invalid") from None


def _stored_analysis_plan(value: Mapping[str, Any]) -> SuccessorAnalysisPlan:
    try:
        plan = SuccessorAnalysisPlan(
            metrics=tuple(Metric(item) for item in value["metrics"]),
            primary_metric=Metric(value["primary_metric"]),
            bootstrap_seed=value["bootstrap_seed"],
            bootstrap_draws=value["bootstrap_draws"],
            alpha=value["alpha"],
            minimum_task_units=value["minimum_task_units"],
            minimum_valid_bootstrap_fraction=value[
                "minimum_valid_bootstrap_fraction"
            ],
            practical_effect_margin=value["practical_effect_margin"],
            functionality_noninferiority_margin=value[
                "functionality_noninferiority_margin"
            ],
            minimum_realizations=value["minimum_realizations"],
            minimum_task_units_per_realization=value[
                "minimum_task_units_per_realization"
            ],
            realization_practical_equivalence_margin=value[
                "realization_practical_equivalence_margin"
            ],
            realization_direction_consistency_threshold=value[
                "realization_direction_consistency_threshold"
            ],
            functionality_noninferiority_separately_powered=value[
                "functionality_noninferiority_separately_powered"
            ],
            minimum_replication_models=value["minimum_replication_models"],
            cross_model_replication_rule=value["cross_model_replication_rule"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor analysis plan is invalid") from None
    _require_canonical_record(plan, value, "stored successor analysis plan")
    return plan


def _stored_hypothesis(value: Mapping[str, Any]) -> FrozenHypothesisV2:
    try:
        skeleton_value = _object(value["skeleton"], "stored candidate skeleton")
        target_value = _object(value["target_spec"], "stored target spec")
        hypothesis = FrozenHypothesisV2(
            CandidateSkeletonV2(
                skeleton_value["candidate_key"],
                skeleton_value["context_query_id"],
                tuple(skeleton_value["actionable_feature_ids"]),
                Operation(skeleton_value["operation"]),
                skeleton_value["cwe"],
                skeleton_value["archetype"],
                skeleton_value["outcome_id"],
                ExpectedDirection(skeleton_value["expected_direction"]),
                skeleton_value["realization_policy_id"],
            ),
            TargetSpecV2(
                target_value["candidate_skeleton_id"],
                target_value["context_query_id"],
                target_value["actionable_feature_id"],
                Operation(target_value["operation"]),
                target_value["context_query_catalog_sha256"],
                target_value["feature_catalog_sha256"],
                target_value["allowed_delta_policy_sha256"],
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor hypothesis is invalid") from None
    _require_canonical_record(hypothesis, value, "stored successor hypothesis")
    return hypothesis


def _stored_source_eligibility(value: Mapping[str, Any]) -> SourceEligibilityV2:
    try:
        eligibility = SourceEligibilityV2(
            value["hypothesis_id"],
            value["task_id"],
            value["task_unit_id"],
            value["prompt_tsg_id"],
            value["prompt_sha256"],
            Operation(value["operation"]),
            QueryState(value["context_state"]),
            QueryState(value["feature_state"]),
            tuple(value["target_evidence_node_ids"]),
            value["neutral_counterpart"],
            value["neutral_counterpart_sha256"],
            value["eligibility_policy_sha256"],
            EligibilityDecisionV2(value["decision"]),
            value["exclusion_reason"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError(
            "stored successor source eligibility is invalid"
        ) from None
    _require_canonical_record(
        eligibility,
        value,
        "stored successor source eligibility",
    )
    return eligibility


def _stored_arm_protocol(value: Mapping[str, Any]) -> ArmProtocolV2:
    protocol = ArmProtocolV2(
        Operation(value["operation"]),
        tuple((PolicyArmRoleV2(role), label) for role, label in value["arm_labels"]),
        value["protocol_policy_sha256"],
    )
    _require_canonical_record(protocol, value, "stored successor arm protocol")
    return protocol


def _stored_realization(value: Mapping[str, Any]) -> RealizationSpecV2:
    realization = RealizationSpecV2(
        value["label"],
        value["weight"],
        value["executor_adapter_id"],
        tuple(
            (PolicyArmRoleV2(role), instruction)
            for role, instruction in value["arm_instructions"]
        ),
        value["matching_policy_sha256"],
        value["validation_policy_sha256"],
    )
    _require_canonical_record(realization, value, "stored successor realization")
    return realization


def _stored_realization_policy(value: Mapping[str, Any]) -> RealizationPolicyV2:
    policy = RealizationPolicyV2(
        value["policy_key"],
        _stored_arm_protocol(_object(value["arm_protocol"], "stored arm protocol")),
        tuple(
            _stored_realization(_object(item, "stored realization"))
            for item in value["realizations"]
        ),
        value["full_support_required"],
        value["failure_policy"],
    )
    _require_canonical_record(policy, value, "stored successor realization policy")
    return policy


def _stored_arm_validation(value: Mapping[str, Any]) -> ArmSemanticValidationV2:
    validation = ArmSemanticValidationV2(
        SemanticVerdict(value["task_preserved"]),
        SemanticVerdict(value["context_preserved"]),
        SemanticVerdict(value["non_target_preserved"]),
        SemanticVerdict(value["role_contract_satisfied"]),
        SemanticVerdict(value["contradiction"]),
        value["validator_adapter_id"],
        value["evidence_sha256"],
    )
    _require_canonical_record(validation, value, "stored successor arm validation")
    return validation


def _stored_bundle_validation(value: Mapping[str, Any]) -> BundleValidationV2:
    validation = BundleValidationV2(
        SemanticVerdict(value["treatment_states_distinct"]),
        SemanticVerdict(value["no_third_requirement"]),
        SemanticVerdict(value["matched_controls"]),
        value["validator_adapter_id"],
        value["evidence_sha256"],
    )
    _require_canonical_record(
        validation,
        value,
        "stored successor bundle validation",
    )
    return validation


def _stored_variant(value: Mapping[str, Any]) -> ArmVariantV2:
    execution_value = _object(value["execution"], "stored intervention execution")
    variant = ArmVariantV2(
        PolicyArmRoleV2(value["role"]),
        value["arm_label"],
        InterventionExecution(
            execution_value["intervention_text"],
            execution_value["executor_adapter_id"],
            execution_value["evidence_sha256"],
        ),
        value["prompt_text"],
        _stored_arm_validation(_object(value["validation"], "stored arm validation")),
        value["prompt_tsg_record_json"],
        value["projection_sha256"],
    )
    _require_canonical_record(variant, value, "stored successor variant")
    return variant


def _stored_bundle(value: Mapping[str, Any]) -> TaskRealizationBundleV2:
    bundle = TaskRealizationBundleV2(
        value["hypothesis_id"],
        value["target_spec_id"],
        value["source_eligibility_id"],
        value["task_id"],
        value["task_unit_id"],
        value["realization_spec_id"],
        value["arm_protocol_id"],
        value["source_prompt_sha256"],
        value["neutral_counterpart_sha256"],
        tuple(
            _stored_variant(_object(item, "stored successor variant"))
            for item in value["variants"]
        ),
        _stored_bundle_validation(
            _object(value["bundle_validation"], "stored bundle validation")
        ),
    )
    _require_canonical_record(bundle, value, "stored successor task bundle")
    return bundle


def _stored_policy(value: Mapping[str, Any]) -> InterventionPolicyV2:
    try:
        policy = InterventionPolicyV2(
            _stored_hypothesis(_object(value["hypothesis"], "stored hypothesis")),
            _stored_realization_policy(
                _object(value["realization_policy"], "stored realization policy")
            ),
            tuple(
                _stored_source_eligibility(
                    _object(item, "stored source eligibility")
                )
                for item in value["source_eligibilities"]
            ),
            tuple(
                _stored_bundle(_object(item, "stored task bundle"))
                for item in value["bundles"]
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor policy is invalid") from None
    _require_canonical_record(policy, value, "stored successor policy")
    return policy


def _stored_task(value: Mapping[str, Any]) -> Task:
    try:
        task = Task(
            value["task_id"],
            value["semantic_cluster_id"],
            value["cwe"],
            value["archetype"],
            Split(value["split"]),
            value["prompt"],
            value["weight"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor task is invalid") from None
    _require_canonical_record(task, value, "stored successor task")
    return task


def _stored_assignment(value: Mapping[str, Any]) -> SuccessorAssignment:
    try:
        block_value = _object(value["block"], "stored successor block")
        assignment = SuccessorAssignment(
            SuccessorBlockKey(
                block_value["task_unit_id"],
                block_value["task_instance_id"],
                block_value["hypothesis_id"],
                block_value["target_spec_id"],
                block_value["realization_spec_id"],
                block_value["task_realization_bundle_id"],
                block_value["model_id"],
                block_value["arm_protocol_id"],
            ),
            value["request_randomness_slot"],
            PolicyArmRoleV2(value["arm_role"]),
            value["arm_label"],
            value["variant_sha256"],
            value["provider_seed"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor assignment is invalid") from None
    _require_canonical_record(assignment, value, "stored successor assignment")
    return assignment


def _stored_randomization(value: Mapping[str, Any]) -> SuccessorRandomization:
    try:
        randomization = SuccessorRandomization(
            value["population_id"],
            value["selection_id"],
            value["seed"],
            tuple(value["models"]),
            tuple(value["request_randomness_slots"]),
            tuple(
                _stored_assignment(_object(item, "stored assignment"))
                for item in value["assignments"]
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("stored successor randomization is invalid") from None
    _require_canonical_record(randomization, value, "stored successor randomization")
    return randomization


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


def _require_canonical_record(
    parsed: Any,
    value: Mapping[str, Any],
    label: str,
) -> None:
    if canonical_value(parsed) != dict(value):
        raise SuccessorExperimentError(f"{label} is not canonical")


def _task(row: Mapping[str, Any]) -> Task:
    try:
        contract = _object(row["functional_contract"], "functional contract")
        requirements = _list(contract.get("requirements"), "functional requirements")
        if not requirements or any(not isinstance(item, Mapping) for item in requirements):
            raise SuccessorExperimentError("functional requirements are invalid")
        _strings(contract.get("environment_dependencies"), "environment dependencies")
        if contract.get("language", "python") != "python":
            raise SuccessorExperimentError("successor runner currently supports Python tasks")
        return Task(
            row["task_id"],
            row["task_unit_id"],
            row["cwe"],
            row["archetype"],
            Split(row["split"]),
            row["prompt"],
            row["weight"],
        )
    except (KeyError, TypeError, ValueError):
        raise SuccessorExperimentError("successor task row is invalid") from None


def _load_oracle(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    profile_id = _text(value.get("profile_id"), "security Oracle profile id")
    if profile_id not in LOCAL_PROFILE_IDS:
        raise SuccessorExperimentError(
            "successor Security Oracle must use a replayable frozen local profile"
        )
    if value.get("policy_sha256") != security_profile_policy_sha256(profile_id):
        raise SuccessorExperimentError(
            "successor Security Oracle policy does not recompute from the local producer"
        )
    policy_sha256 = _digest(value.get("policy_sha256"), "security Oracle policy")
    path = _inside(root, value.get("qualification_path"))
    _require_file_hash(path, value.get("qualification_sha256"))
    qualification = _object(read_json(path), "security Oracle qualification")
    if (
        qualification.get("profile_id") != profile_id
        or qualification.get("policy_sha256") != policy_sha256
        or qualification.get("qualification_status") != "supported"
        or qualification.get("label_mismatches", 0) != 0
    ):
        raise SuccessorExperimentError("security Oracle qualification drift")
    return {
        "profile_id": profile_id,
        "policy_sha256": policy_sha256,
        "qualification_path": str(path.relative_to(root).as_posix()),
        "qualification_sha256": value["qualification_sha256"],
        "qualification": qualification,
        "qualification_payload": path.read_text(encoding="utf-8"),
    }


def _load_functional_qualification(
    root: Path,
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
) -> dict[str, Any]:
    """Load and seal the pre-experiment Functional Judge qualification."""

    try:
        return load_functional_qualification(
            root,
            section,
            evaluator,
        )
    except QualificationError as error:
        raise SuccessorExperimentError(str(error)) from error


def _validate_frozen_functional_qualification(
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    sealed: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate bundled qualification evidence without reading its source path."""

    try:
        return validate_functional_qualification(section, evaluator, sealed)
    except QualificationError as error:
        raise SuccessorExperimentError(str(error)) from error


def _load_functionality_power_qualification(
    root: Path,
    analysis: Mapping[str, Any],
    model_ids: tuple[str, ...],
) -> dict[str, Any] | None:
    if analysis["functionality_noninferiority_separately_powered"] is False:
        return None
    reference = _object(
        analysis["functionality_power_qualification"],
        "functionality power qualification reference",
    )
    path = _inside(root, reference["path"])
    _require_file_hash(path, reference["sha256"])
    payload_text = path.read_text(encoding="utf-8")
    payload = _object(_read_json_exact(path), "functionality power qualification")
    _validate_functionality_power_payload(payload, analysis, model_ids)
    return {
        "schema_version": "1.0",
        "qualification_sha256": reference["sha256"],
        "qualification_payload": payload_text,
        "qualification": payload,
    }


def _validate_frozen_functionality_power_qualification(
    analysis: Mapping[str, Any],
    model_ids: tuple[str, ...],
    sealed: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    requested = analysis["functionality_noninferiority_separately_powered"]
    if not requested:
        if sealed is not None:
            raise SuccessorExperimentError(
                "unrequested functionality power evidence entered the freeze"
            )
        return None
    if sealed is None or set(sealed) != {
        "schema_version",
        "qualification_sha256",
        "qualification_payload",
        "qualification",
    } or sealed.get("schema_version") != "1.0":
        raise SuccessorExperimentError(
            "frozen functionality power qualification is invalid"
        )
    payload_text = sealed.get("qualification_payload")
    qualification = _object(
        sealed.get("qualification"),
        "frozen functionality power qualification",
    )
    reference = _object(
        analysis["functionality_power_qualification"],
        "functionality power qualification reference",
    )
    if (
        not isinstance(payload_text, str)
        or hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
        != sealed.get("qualification_sha256")
        or sealed.get("qualification_sha256") != reference["sha256"]
        or _json_object(
            payload_text.encode("utf-8"),
            "frozen functionality power qualification payload",
        )
        != qualification
    ):
        raise SuccessorExperimentError(
            "frozen functionality power qualification drifts"
        )
    _validate_functionality_power_payload(qualification, analysis, model_ids)
    return dict(sealed)


def _validate_functionality_power_payload(
    payload: Mapping[str, Any],
    analysis: Mapping[str, Any],
    model_ids: tuple[str, ...],
) -> None:
    try:
        validate_functionality_power_payload(
            payload,
            analysis,
            expected_coordinate={
                "metric": "functionality",
                "contrast": "target_minus_noop",
                "unit": "task_unit",
                "scope": "each_hypothesis_model_coordinate",
            },
            expected_model_policy={
                "model_ids": list(model_ids),
                "cross_model_replication_rule": analysis.get(
                    "cross_model_replication_rule",
                    "oriented_simultaneous_target_noop_each_model_no_pooling",
                ),
                "pooled": False,
            },
        )
    except QualificationError as error:
        raise SuccessorExperimentError(str(error)) from error


def _adapters(
    prompt_tsg_catalog_sha256: str,
    selection: SuccessorSelectionProvenance,
    executor: Mapping[str, Any],
    executor_prompt: str,
    validator: Mapping[str, Any],
    validator_prompt: str,
    generation_models: tuple[Mapping[str, Any], ...],
    generation_prompts: Mapping[str, str],
    oracles: tuple[Mapping[str, Any], ...],
    functional_evaluator: Mapping[str, Any],
    functional_prompt: str,
    functional_qualification: Mapping[str, Any],
) -> AdapterBundle:
    generator_material = tuple(
        {
            "model": dict(item),
            "prompt_sha256": content_hash(generation_prompts[item["model_id"]]),
        }
        for item in sorted(generation_models, key=lambda value: value["model_id"])
    )
    oracle_material = tuple(
        {
            "profile_id": item["profile_id"],
            "policy_sha256": item["policy_sha256"],
            "qualification_sha256": item["qualification_sha256"],
        }
        for item in sorted(oracles, key=lambda value: (value["profile_id"], value["policy_sha256"]))
    )
    return AdapterBundle(
        AdapterSpec(
            AdapterKind.REPRESENTATION,
            "prompt-tsg-catalog",
            "1",
            prompt_tsg_catalog_sha256,
        ),
        AdapterSpec(
            AdapterKind.SELECTOR,
            f"successor-{selection.source}",
            "2",
            content_hash(selection),
        ),
        AdapterSpec(
            AdapterKind.INTERVENTION_EXECUTOR,
            _text(executor.get("candidate_id"), "intervention executor candidate id"),
            "2",
            content_hash({"config": dict(executor), "prompt": executor_prompt}),
        ),
        AdapterSpec(
            AdapterKind.INTERVENTION_VALIDATOR,
            _text(validator.get("candidate_id"), "intervention validator candidate id"),
            "2",
            content_hash({"config": dict(validator), "prompt": validator_prompt}),
        ),
        AdapterSpec(
            AdapterKind.GENERATOR,
            f"successor-generator-set-{content_hash(generator_material)[:16]}",
            "2",
            content_hash(generator_material),
        ),
        AdapterSpec(
            AdapterKind.SECURITY_ORACLE,
            f"successor-security-oracle-set-{content_hash(oracle_material)[:16]}",
            "2",
            content_hash(oracle_material),
        ),
        AdapterSpec(
            AdapterKind.FUNCTIONAL_EVALUATOR,
            functional_evaluator["candidate_id"],
            "2",
            content_hash(
                {
                    "evaluator": dict(functional_evaluator),
                    "prompt": functional_prompt,
                    "qualification_sha256": functional_qualification[
                        "qualification_sha256"
                    ],
                    "qualification_identity": functional_qualification[
                        "qualification_identity"
                    ],
                }
            ),
        ),
    )


def _validate_bundle_response(raw: bytes) -> dict[str, Any]:
    value = _json_object(raw, "successor validator response")
    expected = {role.value for role in SUCCESSOR_ARM_ROLE_ORDER} | {
        "cross_arm", "reason", "prompt_tsg"
    }
    if set(value) != expected:
        raise SuccessorExperimentError("successor validator response schema drift")
    arm_fields = {
        "task_preserved",
        "context_preserved",
        "non_target_preserved",
        "role_contract_satisfied",
        "contradiction",
    }
    for role in SUCCESSOR_ARM_ROLE_ORDER:
        result = value[role.value]
        if not isinstance(result, dict) or set(result) != arm_fields:
            raise SuccessorExperimentError("successor validator arm schema drift")
        if any(type(flag) is not bool for flag in result.values()) or not all(
            result[name]
            for name in arm_fields - {"contradiction"}
        ) or result["contradiction"]:
            raise SuccessorExperimentError("successor arm semantic validation failed")
    cross_fields = {"treatment_states_distinct", "no_third_requirement", "matched_controls"}
    cross = value["cross_arm"]
    if (
        not isinstance(cross, dict)
        or set(cross) != cross_fields
        or any(type(flag) is not bool for flag in cross.values())
        or not all(cross.values())
    ):
        raise SuccessorExperimentError("successor cross-arm semantic validation failed")
    _text(value["reason"], "successor validation reason")
    tsg = _object(value["prompt_tsg"], "successor variant Prompt TSG proposals")
    if set(tsg) != {role.value for role in SUCCESSOR_ARM_ROLE_ORDER}:
        raise SuccessorExperimentError("successor variant Prompt TSG arm support drifts")
    for proposal in tsg.values():
        item = _object(proposal, "successor variant Prompt TSG proposal")
        if set(item) != {"facts", "relations", "unresolved_semantics"}:
            raise SuccessorExperimentError("successor variant Prompt TSG schema drifts")
        if (
            len(_list(item["facts"], "variant Prompt TSG facts")) > 128
            or len(_list(item["relations"], "variant Prompt TSG relations")) > 256
        ):
            raise SuccessorExperimentError("successor variant Prompt TSG exceeds bounds")
        _strings(item["unresolved_semantics"], "variant unresolved semantics")
    return value


def _validate_provider_config(
    value: Mapping[str, Any],
    name: str,
    *,
    seed_must_be_null: bool = False,
    exact_extra_fields: set[str] | None = None,
) -> None:
    required = {
        "candidate_id",
        "api_key_env",
        "base_url",
        "model_id",
        "temperature",
        "top_p",
        "seed",
        "timeout_seconds",
        "max_response_bytes",
        "enable_thinking",
    }
    required |= exact_extra_fields or set()
    if set(value) != required:
        raise SuccessorExperimentError(f"{name} provider config fields are not exact")
    for field in ("candidate_id", "api_key_env", "base_url", "model_id"):
        _text(value[field], f"{name} {field}")
    if (
        type(value["temperature"]) not in {int, float}
        or not math.isfinite(float(value["temperature"]))
        or value["temperature"] < 0
        or type(value["top_p"]) not in {int, float}
        or not math.isfinite(float(value["top_p"]))
        or not 0 < value["top_p"] <= 1
        or type(value["timeout_seconds"]) not in {int, float}
        or value["timeout_seconds"] <= 0
        or type(value["max_response_bytes"]) is not int
        or value["max_response_bytes"] <= 0
        or type(value["enable_thinking"]) is not bool
        or (
            value["seed"] is not None
            and (type(value["seed"]) is not int or value["seed"] < 0)
        )
        or (seed_must_be_null and value["seed"] is not None)
    ):
        raise SuccessorExperimentError(f"{name} provider config is invalid")


def _locked_json(root: Path, section: Mapping[str, Any], stem: str) -> dict[str, Any]:
    path = _inside(root, section.get(f"{stem}_path"))
    _require_file_hash(path, section.get(f"{stem}_sha256"))
    return _object(_read_json_exact(path), stem)


def _locked_text(root: Path, section: Mapping[str, Any], stem: str) -> str:
    path = _inside(root, section.get(f"{stem}_path"))
    _require_file_hash(path, section.get(f"{stem}_sha256"))
    try:
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise SuccessorExperimentError(f"{stem} is unreadable") from None
    return _text(value.strip(), stem)


def _inside(root: Path, value: object) -> Path:
    try:
        return resolve_confined_path(root, value)
    except ValueError as error:
        raise SuccessorExperimentError(str(error)) from error


def _require_file_hash(path: Path, expected: object) -> None:
    try:
        verify_file_hash(path, expected)
    except ValueError as error:
        raise SuccessorExperimentError(str(error)) from error


def _complete(
    complete: Complete,
    request: dict[str, Any],
    evaluator: Mapping[str, Any],
    prompt: str,
) -> bytes:
    raw = complete(request, evaluator, prompt)
    if not isinstance(raw, bytes) or not raw:
        raise SuccessorExperimentError("provider response must be non-empty bytes")
    maximum = evaluator["max_response_bytes"]
    if len(raw) > maximum:
        raise SuccessorExperimentError("provider response exceeds the frozen byte limit")
    return raw


def _json_object(raw: bytes, name: str) -> dict[str, Any]:
    try:
        return parse_json_object(raw)
    except ValueError:
        raise SuccessorExperimentError(f"{name} is not strict JSON") from None


def _read_json_exact(path: Path) -> Any:
    """Read frozen JSON while rejecting duplicate keys and non-finite numbers."""

    try:
        return read_strict_json(path)
    except ValueError:
        raise SuccessorExperimentError(f"{path.name} is not strict JSON") from None


def _object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SuccessorExperimentError(f"{name} must be a JSON object")
    return value


def _list(value: object, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise SuccessorExperimentError(f"{name} must be a JSON array")
    return value


def _strings(value: object, name: str) -> tuple[str, ...]:
    rows = _list(value, name)
    result = tuple(_text(item, name) for item in rows)
    if len(result) != len(set(result)):
        raise SuccessorExperimentError(f"{name} contains duplicates")
    return result


def _integers(value: object, name: str) -> tuple[int, ...]:
    rows = _list(value, name)
    if any(type(item) is not int for item in rows):
        raise SuccessorExperimentError(f"{name} must contain integers")
    return tuple(rows)


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise SuccessorExperimentError(f"{name} must be non-empty and trimmed")
    return value


def _digest(value: object, name: str) -> str:
    try:
        return require_sha256(value, name)
    except ValueError as error:
        raise SuccessorExperimentError(str(error)) from error


def _yes(value: bool) -> SemanticVerdict:
    return SemanticVerdict.YES if value else SemanticVerdict.NO


__all__ = [
    "SuccessorExperimentError",
    "preflight_successor_experiment",
    "freeze_successor_experiment",
    "run_successor_experiment",
    "verify_successor_materialization_bundle",
    "verify_successor_result_bundle",
]

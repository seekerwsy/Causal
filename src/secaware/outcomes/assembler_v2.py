"""Exact v2 assignment-to-outcome assembly for the prospective protocol."""

from __future__ import annotations

import hashlib
import json

from secaware.schema.outcomes_v2 import (
    AssignmentOutcomeRecordV2,
    AssignmentOutcomeStateV2,
    FunctionalStatusV2,
)
from secaware.schema.policy_v2 import TaskRealizationBundleRecord
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
    validate_runtime_producer_chain_v2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _functional_status(status: str) -> FunctionalStatusV2:
    mapping = {
        "pass": FunctionalStatusV2.PASS,
        "fail": FunctionalStatusV2.FAIL,
        "unknown": FunctionalStatusV2.UNKNOWN,
        "not_applicable": FunctionalStatusV2.NOT_APPLICABLE,
        "not_evaluated_no_valid_code": FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE,
    }
    try:
        return mapping[status]
    except KeyError:
        raise ValueError("v2 outcome assembly encountered infrastructure failure") from None


def _outcome_state(
    code: GeneratedCodeRecordV2,
    oracle: OracleResultRecordV2,
) -> AssignmentOutcomeStateV2:
    if oracle.status == "infrastructure_failure":
        raise ValueError("v2 outcome assembly encountered infrastructure failure")
    if code.code_status == "terminal_no_code":
        if oracle.status != "not_evaluated_no_valid_code":
            raise ValueError("v2 outcome assembly found incoherent no-code evidence")
        return AssignmentOutcomeStateV2.TERMINAL_NO_CODE
    mapping = {
        "secure": AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
        "insecure": AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
        "unknown": AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        "not_evaluated_no_valid_code": AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE,
    }
    try:
        return mapping[oracle.status]
    except KeyError:
        raise ValueError("v2 outcome assembly found incoherent Oracle evidence") from None


def assemble_assignment_outcome_v2(
    assignment: ConfirmationAssignmentRecordV2,
    task_bundle: TaskRealizationBundleRecord,
    generation_request: GenerationRequestRecordV2,
    generated_code: GeneratedCodeRecordV2,
    oracle_result: OracleResultRecordV2,
    functional_result: FunctionalResultRecordV2,
) -> AssignmentOutcomeRecordV2:
    """Join one frozen assignment to one total v2 outcome without post-treatment filtering."""

    try:
        assigned = ConfirmationAssignmentRecordV2.model_validate(assignment, strict=True)
        bundle = TaskRealizationBundleRecord.model_validate(task_bundle, strict=True)
        request = GenerationRequestRecordV2.model_validate(generation_request, strict=True)
        code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
        oracle = OracleResultRecordV2.model_validate(oracle_result, strict=True)
        functional = FunctionalResultRecordV2.model_validate(functional_result, strict=True)
        chain = validate_runtime_producer_chain_v2(request, code, oracle, functional)

        if assigned.exact_coordinates() != request.exact_coordinates():
            raise ValueError("assignment and generation coordinates do not join exactly")
        if (
            bundle.task_realization_bundle_id != assigned.task_realization_bundle_id
            or bundle.hypothesis_id != assigned.hypothesis_id
            or bundle.semantic_task_cluster_id != assigned.semantic_task_cluster_id
            or bundle.task_instance_id != assigned.task_instance_id
            or bundle.realization_spec_id != assigned.realization_spec_id
        ):
            raise ValueError("task realization bundle does not join assignment")
        matches = tuple(item for item in bundle.arms if item.arm_role is assigned.assigned_arm)
        if len(matches) != 1:
            raise ValueError("assigned arm does not resolve to one frozen variant")
        variant = matches[0]
        if (
            variant.variant_id != assigned.variant_id
            or variant.variant_prompt_id != request.prompt_id
            or variant.prompt_sha256 != request.prompt_sha256
            or variant.prompt_text != request.prompt
        ):
            raise ValueError("frozen variant and generation request do not join exactly")

        state = _outcome_state(code, oracle)
        functional_status = _functional_status(functional.status)
        invalid_or_absent = state in {
            AssignmentOutcomeStateV2.TERMINAL_NO_CODE,
            AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE,
        }
        if invalid_or_absent != (
            functional_status is FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE
        ):
            raise ValueError("functional evidence is incoherent with code validity")

        y_c = int(not invalid_or_absent)
        y_e = int(
            state
            in {
                AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
                AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
            }
        )
        y_secure = int(state is AssignmentOutcomeStateV2.VALID_ORACLE_SECURE)
        y_joint = (
            None
            if functional_status is FunctionalStatusV2.NOT_APPLICABLE
            else y_secure * int(functional_status is FunctionalStatusV2.PASS)
        )
        source_digest = _digest(
            {
                "assignment_record_id": assigned.assignment_record_id,
                "task_realization_bundle_id": bundle.task_realization_bundle_id,
                "variant_id": variant.variant_id,
                "generation_request_id": request.generation_request_id,
                "producer_chain_id": chain.producer_chain_id,
                "generated_code_id": code.generated_code_id,
                "oracle_result_id": oracle.oracle_result_id,
                "functional_result_id": functional.functional_result_id,
            }
        )
        return AssignmentOutcomeRecordV2.from_content(
            assignment_id=assigned.assignment_id,
            block_id=assigned.block_id,
            semantic_task_cluster_id=assigned.semantic_task_cluster_id,
            task_instance_id=assigned.task_instance_id,
            hypothesis_id=assigned.hypothesis_id,
            target_spec_id=assigned.target_spec_id,
            realization_spec_id=assigned.realization_spec_id,
            task_realization_bundle_id=assigned.task_realization_bundle_id,
            variant_id=assigned.variant_id,
            model_id=assigned.model_id,
            arm_protocol_id=assigned.arm_protocol_id,
            arm_role=assigned.assigned_arm,
            request_randomness_slot=assigned.request_randomness_slot,
            provider_seed=assigned.provider_seed,
            state=state,
            functional_status=functional_status,
            y_c=y_c,
            y_e=y_e,
            y_secure_yield=y_secure,
            y_joint=y_joint,
            source_digests_sha256=source_digest,
        )
    except _FATAL:
        raise
    except Exception as error:
        raise ValueError("v2 assignment outcome assembly failed exact validation") from error


__all__ = ["assemble_assignment_outcome_v2"]

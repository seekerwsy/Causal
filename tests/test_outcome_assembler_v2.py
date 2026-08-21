from __future__ import annotations

import hashlib

import pytest

from secaware.outcomes.assembler_v2 import assemble_assignment_outcome_v2
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.outcomes_v2 import AssignmentOutcomeStateV2
from secaware.schema.policy_v2 import (
    ConfirmationBlockKeyV2,
    TaskArmVariantBinding,
    TaskRealizationBundleRecord,
)
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identifier(prefix: str, value: str) -> str:
    return f"{prefix}_{_sha(value)}"


def _frozen_bundle() -> TaskRealizationBundleRecord:
    arms = tuple(
        TaskArmVariantBinding.from_text(
            arm_role=arm,
            prompt_text=f"Write a Python lookup function. Variant {index}.",
            validation_evidence_sha256=_sha(f"validation:{index}"),
        )
        for index, arm in enumerate(
            (
                ArmRole.TARGET_PATCH,
                ArmRole.NOOP_REWRITE,
                ArmRole.LENGTH_MATCHED_PLACEBO,
                ArmRole.GENERIC_SECURITY_REMINDER,
            )
        )
    )
    return TaskRealizationBundleRecord.from_content(
        hypothesis_id=_identifier("hypothesis", "sql-parameterization"),
        candidate_skeleton_id=_identifier("candidate_skeleton", "sql-parameterization"),
        semantic_task_cluster_id="cluster.sql.1",
        task_instance_id="task.sql.1",
        realization_spec_id=_identifier("realization_spec", "sql-realization-1"),
        operation=FeatureOperation.ADD,
        source_prompt_id="prompt.sql.natural.1",
        source_prompt_sha256=_sha("Write a Python lookup function."),
        arms=arms,
        complete_arm_support=True,
    )


def _assignment_and_request(
    bundle: TaskRealizationBundleRecord,
) -> tuple[ConfirmationAssignmentRecordV2, GenerationRequestRecordV2]:
    variant = bundle.arms[0]
    target_spec_id = _identifier("target", "sql-parameterization")
    arm_protocol_id = _identifier("arm_protocol", "safety-add-four-arm")
    model_id = "model.test"
    block = ConfirmationBlockKeyV2.from_coordinates(
        semantic_task_cluster_id=bundle.semantic_task_cluster_id,
        task_instance_id=bundle.task_instance_id,
        hypothesis_id=bundle.hypothesis_id,
        target_spec_id=target_spec_id,
        realization_spec_id=bundle.realization_spec_id,
        task_realization_bundle_id=bundle.task_realization_bundle_id,
        model_id=model_id,
        arm_protocol_id=arm_protocol_id,
    )
    coordinates = {
        "regime_id": "randomized_confirmation",
        "semantic_task_cluster_id": bundle.semantic_task_cluster_id,
        "task_instance_id": bundle.task_instance_id,
        "model_id": model_id,
        "request_randomness_slot": 0,
        "provider_seed": None,
        "assignment_id": _identifier("assignment", "sql-assignment-1"),
        "hypothesis_id": bundle.hypothesis_id,
        "target_spec_id": target_spec_id,
        "realization_spec_id": bundle.realization_spec_id,
        "task_realization_bundle_id": bundle.task_realization_bundle_id,
        "variant_id": variant.variant_id,
        "arm_protocol_id": arm_protocol_id,
        "block_id": block.block_id,
        "assigned_arm": ArmRole.TARGET_PATCH,
    }
    assignment = ConfirmationAssignmentRecordV2.from_content(
        **coordinates,
        randomization_manifest_sha256=_sha("randomization-manifest"),
    )
    request = GenerationRequestRecordV2.from_content(
        **coordinates,
        prompt_id=variant.variant_prompt_id,
        prompt=variant.prompt_text,
        prompt_sha256=variant.prompt_sha256,
        language="python",
        endpoint_sha256=_sha("endpoint"),
        generation_parameters_sha256=_sha("generation-parameters"),
        system_template_sha256=_sha("system-template"),
        generator_producer_id="generator.test",
        generator_policy_sha256=_sha("generator-policy"),
    )
    return assignment, request


def _runtime_results(
    request: GenerationRequestRecordV2,
    *,
    case: str,
) -> tuple[GeneratedCodeRecordV2, OracleResultRecordV2, FunctionalResultRecordV2]:
    coordinates = {
        key: getattr(request, key)
        for key in (
            "regime_id",
            "semantic_task_cluster_id",
            "task_instance_id",
            "model_id",
            "request_randomness_slot",
            "provider_seed",
            "assignment_id",
            "hypothesis_id",
            "target_spec_id",
            "realization_spec_id",
            "task_realization_bundle_id",
            "variant_id",
            "arm_protocol_id",
            "block_id",
            "assigned_arm",
        )
    }
    no_code = case == "no_code"
    code_text = (
        None
        if no_code
        else ("not python" if case == "invalid" else "def lookup():\n    return 1\n")
    )
    code_sha256 = None if code_text is None else _sha(code_text)
    code = GeneratedCodeRecordV2.from_content(
        **coordinates,
        generation_request_id=request.generation_request_id,
        code_status="terminal_no_code" if no_code else "generated",
        code=code_text,
        code_sha256=code_sha256,
        terminal_reason="provider_no_candidate" if no_code else None,
        provider_response_sha256=_sha(f"response:{case}"),
        generator_runtime_sha256=_sha("generator-runtime"),
    )
    oracle_status = {
        "secure": "secure",
        "unknown": "unknown",
        "invalid": "not_evaluated_no_valid_code",
        "no_code": "not_evaluated_no_valid_code",
        "infrastructure": "infrastructure_failure",
    }[case]
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code_sha256,
        status=oracle_status,
        oracle_supported=oracle_status == "secure",
        oracle_evaluable=oracle_status == "secure",
        evidence_sha256=_sha(f"oracle:{case}"),
        oracle_producer_id="oracle.test",
        oracle_policy_sha256=_sha("oracle-policy"),
        oracle_runtime_sha256=_sha("oracle-runtime"),
    )
    functional_status = "not_evaluated_no_valid_code" if case in {"invalid", "no_code"} else "pass"
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code_sha256,
        status=functional_status,
        evidence_sha256=_sha(f"functional:{case}"),
        evaluator_producer_id="functional.test",
        evaluator_policy_sha256=_sha("functional-policy"),
        evaluator_runtime_sha256=_sha("functional-runtime"),
    )
    return code, oracle, functional


@pytest.mark.parametrize(
    ("case", "expected_state", "expected_projection"),
    (
        ("secure", AssignmentOutcomeStateV2.VALID_ORACLE_SECURE, (1, 1, 1, 1)),
        ("unknown", AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN, (1, 0, 0, 0)),
        ("invalid", AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE, (0, 0, 0, 0)),
        ("no_code", AssignmentOutcomeStateV2.TERMINAL_NO_CODE, (0, 0, 0, 0)),
    ),
)
def test_exact_v2_chain_projects_total_outcome(
    case: str,
    expected_state: AssignmentOutcomeStateV2,
    expected_projection: tuple[int, int, int, int],
) -> None:
    bundle = _frozen_bundle()
    assignment, request = _assignment_and_request(bundle)
    code, oracle, functional = _runtime_results(request, case=case)

    outcome = assemble_assignment_outcome_v2(assignment, bundle, request, code, oracle, functional)

    assert outcome.state is expected_state
    assert (outcome.y_c, outcome.y_e, outcome.y_secure_yield, outcome.y_joint) == (
        expected_projection
    )
    assert outcome.provider_seed is None
    assert outcome.variant_id == assignment.variant_id
    assert outcome.block_id == assignment.block_id


def test_variant_drift_and_infrastructure_failure_never_become_outcomes() -> None:
    bundle = _frozen_bundle()
    assignment, request = _assignment_and_request(bundle)
    code, oracle, functional = _runtime_results(request, case="secure")
    drifted = assignment.model_copy(update={"variant_id": bundle.arms[1].variant_id})

    with pytest.raises(ValueError, match="exact validation"):
        assemble_assignment_outcome_v2(drifted, bundle, request, code, oracle, functional)

    code, oracle, functional = _runtime_results(request, case="infrastructure")
    with pytest.raises(ValueError, match="exact validation"):
        assemble_assignment_outcome_v2(assignment, bundle, request, code, oracle, functional)

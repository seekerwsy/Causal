from __future__ import annotations

import hashlib

import pytest

from secaware.config import GenerationConfig, OpenAICompatibleConfig
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ExperimentalUnit,
    PromptVariantRecord,
)
from secaware.schema.generation import GenerationParameters, build_generation_request_id


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assignment_and_variant(
    *,
    task_id: str = "task-a",
    role: ArmRole = ArmRole.TARGET_PATCH,
    seed_id: int = 101,
) -> tuple[AssignmentRecord, PromptVariantRecord]:
    hypothesis_id = "hypothesis_" + "1" * 64
    target_spec_id = "target_" + "2" * 64
    target_instance_id = "target_instance_" + _sha(task_id)
    protocol_id = "arm_protocol_" + "3" * 64
    protocol_instance_id = "protocol_instance_" + _sha(task_id + "protocol")
    prompt = f"Implement the parser for {task_id}."
    variant = PromptVariantRecord.from_content(
        task_id=task_id,
        source_prompt_id=f"prompt-{task_id}",
        variant_prompt_id="variant_prompt_" + _sha(task_id + role.value),
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        arm_role=role,
        prompt_sha256=_sha(prompt),
        prompt_text=prompt,
        proposal_id="proposal_" + _sha(task_id + "proposal"),
        graph_id="graph_" + _sha(task_id + "graph"),
        delta_id="delta_" + _sha(task_id + "delta"),
        executor_policy_sha256="4" * 64,
        extractor_policy_sha256="5" * 64,
        length_match_id=None,
    )
    unit = ExperimentalUnit(
        task_id=task_id,
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        model_id="model-a",
        seed_slot=0,
    )
    block_id = AssignmentRecord.block_id_from_key(
        task_id,
        hypothesis_id,
        target_spec_id,
        protocol_id,
        "model-a",
    )
    assignment = AssignmentRecord.from_content(
        block_id=block_id,
        experimental_unit=unit,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        variant_id=variant.variant_id,
        arm_role=role,
        seed_id=seed_id,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="6" * 64,
    )
    return assignment, variant


def _generation_config() -> GenerationConfig:
    return GenerationConfig(provider="mock", models=["model-a"], seeds=[1], confirmation_seeds=[101])


def test_confirmation_request_binds_assignment_variant_and_arm() -> None:
    assignment, variant = _assignment_and_variant()
    request = plan_confirmation_requests((assignment,), (variant,), _generation_config())[0]
    assert request.schema_version == "1.2"
    assert request.condition == "confirm_arm"
    assert request.assignment_id == assignment.assignment_id
    assert request.hypothesis_id == assignment.experimental_unit.hypothesis_id
    assert request.target_spec_id == assignment.target_spec_id
    assert request.target_instance_id == assignment.target_instance_id
    assert request.arm_protocol_id == assignment.arm_protocol_id
    assert request.protocol_instance_id == assignment.protocol_instance_id
    assert request.variant_id == assignment.variant_id
    assert request.arm_role == assignment.arm_role
    assert request.seed_id == assignment.seed_id
    assert request.model_id == assignment.experimental_unit.model_id
    assert request.prompt == variant.prompt_text
    assert request.prompt_sha256 == variant.prompt_sha256
    identity = request.model_dump(mode="python", exclude={"request_id", "prompt"})
    identity["parameters"] = request.parameters
    assert request.request_id == build_generation_request_id(**identity)


def test_confirmation_planner_is_input_order_invariant() -> None:
    first = _assignment_and_variant(task_id="task-a")
    second = _assignment_and_variant(task_id="task-b")
    forward = plan_confirmation_requests(
        (first[0], second[0]), (first[1], second[1]), _generation_config()
    )
    reverse = plan_confirmation_requests(
        (second[0], first[0]), (second[1], first[1]), _generation_config()
    )
    assert forward == reverse


@pytest.mark.parametrize("kind", ("duplicate", "omit", "extra", "drift"))
def test_confirmation_planner_rejects_non_exact_assignment_variant_join(kind: str) -> None:
    assignment, variant = _assignment_and_variant()
    assignments = (assignment,)
    variants = (variant,)
    if kind == "duplicate":
        assignments = (assignment, assignment)
    elif kind == "omit":
        variants = ()
    elif kind == "extra":
        variants = (variant, _assignment_and_variant(task_id="task-b")[1])
    else:
        assignments = (assignment.model_copy(update={"seed_id": 999}),)
    with pytest.raises(Exception):
        plan_confirmation_requests(assignments, variants, _generation_config())


def test_confirmation_planner_uses_assignment_model_not_observed_generation_axis() -> None:
    assignment, variant = _assignment_and_variant()
    config = GenerationConfig(
        provider="mock", models=["different-model"], seeds=[1], confirmation_seeds=[101]
    )
    request = plan_confirmation_requests((assignment,), (variant,), config)[0]
    assert request.model_id == assignment.experimental_unit.model_id


def test_confirmation_planner_binds_endpoint_system_template_and_parameters_exactly() -> None:
    assignment, variant = _assignment_and_variant()
    provider = OpenAICompatibleConfig(
        base_url="https://example.test/v1",
        system_template="Return code only.",
        system_template_version="code-only-v1",
        parameters=GenerationParameters(values={"temperature": 0.0, "max_tokens": 128}),
    )
    config = GenerationConfig(
        provider="openai_compatible",
        models=["ignored-observed-axis"],
        seeds=[1],
        confirmation_seeds=[101],
        openai_compatible=provider,
    )
    request = plan_confirmation_requests((assignment,), (variant,), config)[0]
    assert request.endpoint_type == "chat_completions"
    assert request.endpoint_sha256 == _sha(provider.base_url)
    assert request.system_template_version == provider.system_template_version
    assert request.system_template_sha256 == _sha(provider.system_template)
    assert request.parameters == provider.parameters

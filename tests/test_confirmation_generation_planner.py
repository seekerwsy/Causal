from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secaware.config import GenerationConfig, OpenAICompatibleConfig
from secaware.errors import SecAwareError
from secaware.generation.request_planner import plan_confirmation_requests
import secaware.generation.request_planner as request_planner
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ExperimentalUnit,
    PromptVariantRecord,
)
from secaware.schema.generation import GenerationParameters, build_generation_request_id
from secaware.schema.common import MAX_MODEL_ID_CHARS


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assignment_and_variant(
    *,
    task_id: str = "task-a",
    role: ArmRole = ArmRole.TARGET_PATCH,
    seed_id: int = 101,
    language: str = "python",
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
        language=language,
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
    return GenerationConfig(
        provider="mock", models=["model-a"], seeds=[1], confirmation_seeds=[101]
    )


def _secaware_traceback_locals(error: BaseException) -> str:
    retained: list[str] = []
    cursor = error.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(dict(cursor.tb_frame.f_locals)))
        cursor = cursor.tb_next
    return "\n".join(retained)


def test_experimental_unit_and_block_key_share_model_id_boundary() -> None:
    accepted_model = "m" * MAX_MODEL_ID_CHARS
    unit = ExperimentalUnit(
        task_id="task-a",
        hypothesis_id="hypothesis_" + "1" * 64,
        target_spec_id="target_" + "2" * 64,
        model_id=accepted_model,
        seed_slot=0,
    )
    assert unit.model_id == accepted_model
    assert AssignmentRecord.block_id_from_key(
        unit.task_id,
        unit.hypothesis_id,
        unit.target_spec_id,
        "arm_protocol_" + "3" * 64,
        accepted_model,
    ).startswith("block_")

    rejected_model = accepted_model + "m"
    with pytest.raises(ValidationError):
        ExperimentalUnit(
            task_id=unit.task_id,
            hypothesis_id=unit.hypothesis_id,
            target_spec_id=unit.target_spec_id,
            model_id=rejected_model,
            seed_slot=0,
        )
    with pytest.raises(ValueError):
        AssignmentRecord.block_id_from_key(
            unit.task_id,
            unit.hypothesis_id,
            unit.target_spec_id,
            "arm_protocol_" + "3" * 64,
            rejected_model,
        )


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
    assert request.parameters.values == {"max_tokens": 65_536}
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


def test_confirmation_planner_rejects_legally_resealed_variant_prompt_hash_mismatch() -> None:
    assignment, variant = _assignment_and_variant()
    content = variant.model_dump(mode="python", exclude={"variant_id"})
    content["prompt_text"] = variant.prompt_text + "\nPreserve behavior."
    content["prompt_sha256"] = _sha(content["prompt_text"])
    resealed = PromptVariantRecord.from_content(**content)

    assert resealed.variant_id != assignment.variant_id
    with pytest.raises(Exception):
        plan_confirmation_requests((assignment,), (resealed,), _generation_config())


def test_confirmation_planner_uses_assignment_model_not_observed_generation_axis() -> None:
    assignment, variant = _assignment_and_variant()
    config = GenerationConfig(
        provider="mock", models=["different-model"], seeds=[1], confirmation_seeds=[101]
    )
    request = plan_confirmation_requests((assignment,), (variant,), config)[0]
    assert request.model_id == assignment.experimental_unit.model_id


def test_confirmation_planner_preserves_java_variant_language() -> None:
    assignment, variant = _assignment_and_variant(language="java")

    request = plan_confirmation_requests((assignment,), (variant,), _generation_config())[0]

    assert request.language == "java"


def test_confirmation_planner_late_join_failure_releases_variant_prompt() -> None:
    assignment, variant = _assignment_and_variant()
    secret = "planner-late-join-prompt-secret"
    content = variant.model_dump(mode="python", exclude={"variant_id"})
    content["prompt_text"] = secret
    content["prompt_sha256"] = _sha(secret)
    mismatched = PromptVariantRecord.from_content(**content)

    with pytest.raises(SecAwareError) as exc_info:
        plan_confirmation_requests((assignment,), (mismatched,), _generation_config())
    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_planner_preserves_late_fatal_identity_and_releases_prompt(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    assignment, variant = _assignment_and_variant()
    signal = signal_type("planner-control-flow")

    def fail_record(**_kwargs):
        raise signal

    monkeypatch.setattr(request_planner, "_record", fail_record)
    with pytest.raises(signal_type) as exc_info:
        plan_confirmation_requests((assignment,), (variant,), _generation_config())
    assert exc_info.value is signal
    assert variant.prompt_text not in _secaware_traceback_locals(signal)


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


@pytest.mark.parametrize("provider_kind", ("mock", "file", "openai_compatible"))
def test_confirmation_planner_injects_one_locked_token_cap_for_every_provider(
    provider_kind: str,
) -> None:
    assignment, variant = _assignment_and_variant()
    values: dict[str, object] = {
        "provider": provider_kind,
        "models": ["model-a"],
        "seeds": [1],
        "confirmation_seeds": [101],
    }
    if provider_kind == "file":
        values["file_provider_dir"] = "offline-results"
    elif provider_kind == "openai_compatible":
        values["openai_compatible"] = OpenAICompatibleConfig(
            base_url="https://example.test/v1",
            parameters=GenerationParameters(values={"temperature": 0.0}),
        )
    config = GenerationConfig.model_validate(values)

    request = plan_confirmation_requests((assignment,), (variant,), config)[0]

    assert request.parameters.values["max_tokens"] == 65_536
    assert (
        sum(
            key in request.parameters.values
            for key in ("max_tokens", "max_completion_tokens", "max_output_tokens")
        )
        == 1
    )


@pytest.mark.parametrize(
    "parameters",
    (
        {"max_tokens": 0},
        {"max_tokens": 1, "max_completion_tokens": 1},
        {"max_tokens": 65_537},
    ),
)
def test_confirmation_planner_rejects_empty_multiple_or_unbounded_token_caps(
    parameters: dict[str, int],
) -> None:
    assignment, variant = _assignment_and_variant()
    with pytest.raises(Exception):
        provider = OpenAICompatibleConfig(
            base_url="https://example.test/v1",
            parameters=GenerationParameters(values=parameters),
        )
        config = GenerationConfig(
            provider="openai_compatible",
            models=["model-a"],
            seeds=[1],
            confirmation_seeds=[101],
            openai_compatible=provider,
        )
        plan_confirmation_requests((assignment,), (variant,), config)

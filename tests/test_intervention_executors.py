from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.config import AppConfig, InterventionConfig, InterventionLLMConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    DeterministicInterventionExecutor,
    structured_policy_from_config,
)
from secaware.schema.experiments import (
    ArmRole,
    FeatureFamily,
    FeatureOperation,
    InterventionExecutorKind,
    InterventionMode,
)
from secaware.tsg.feature_catalog import prompt_feature_spec
from secaware.intervention.attestation import PromptRoleAttestationRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]


ALL_ARM_COORDINATES = (
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD, ArmRole.TARGET_PATCH),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD, ArmRole.NOOP_REWRITE),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD, ArmRole.LENGTH_MATCHED_PLACEBO),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD, ArmRole.GENERIC_SECURITY_REMINDER),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE, ArmRole.TARGET_REMOVE),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE, ArmRole.NOOP_RETAIN),
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE, ArmRole.LENGTH_MATCHED_SHAM_EDIT),
    (
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.REMOVE,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    ),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD, ArmRole.TASK_TARGET),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD, ArmRole.TASK_NOOP),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD, ArmRole.TASK_LENGTH_PLACEBO),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD, ArmRole.TASK_GENERIC_CONTROL),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_TARGET),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_NOOP),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_LENGTH_PLACEBO),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_GENERIC_CONTROL),
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.ADD, ArmRole.PRESENTATION_TARGET),
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.ADD, ArmRole.PRESENTATION_NOOP),
    (
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.ADD,
        ArmRole.PRESENTATION_MATCHED_CONTROL,
    ),
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.REMOVE, ArmRole.PRESENTATION_TARGET),
    (FeatureFamily.PRESENTATION_CONTROL, FeatureOperation.REMOVE, ArmRole.PRESENTATION_NOOP),
    (
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.REMOVE,
        ArmRole.PRESENTATION_MATCHED_CONTROL,
    ),
)


def _expected_deterministic_text(execution_request: object) -> str:
    transitions = execution_request.arm.allowed_delta.allowed_transitions
    remove = any(transition.to_states[0].value == "absent" for transition in transitions)
    if remove:
        assert execution_request.counterpart_prompt is not None
        text = execution_request.counterpart_prompt.prompt
    else:
        text = execution_request.source_prompt.prompt
    for transition in transitions:
        if transition.to_states[0].value != "present":
            continue
        spec = prompt_feature_spec(transition.feature_id)
        text += spec.intervention_clauses[0]
    return text


@pytest.mark.parametrize(("family", "operation", "role"), ALL_ARM_COORDINATES)
def test_deterministic_executor_closes_every_finite_arm_role(
    family: FeatureFamily,
    operation: FeatureOperation,
    role: ArmRole,
) -> None:
    execution_request = request(family, operation, role)
    candidate = DeterministicInterventionExecutor().execute(execution_request)

    assert candidate.arm_role is role
    assert candidate.mode is InterventionMode.TEXT_NATIVE
    assert candidate.intended_patch_id is None
    assert candidate.executor_policy_sha256 == DETERMINISTIC_INTERVENTION_POLICY_SHA256
    assert candidate.text == _expected_deterministic_text(execution_request)


def test_safety_remove_restores_exact_attested_utf8_counterpart() -> None:
    neutral = "Create 雪-path helper that reads a user-provided file path."
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.REMOVE,
        ArmRole.TARGET_REMOVE,
        baseline_text=neutral,
    )

    candidate = DeterministicInterventionExecutor().execute(execution_request)

    assert candidate.text == neutral
    assert candidate.text.encode("utf-8") == execution_request.counterpart_prompt.prompt.encode(
        "utf-8"
    )


def test_deterministic_add_uses_only_catalog_owned_positive_clause() -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.TARGET_PATCH,
    )
    candidate = DeterministicInterventionExecutor().execute(execution_request)
    spec = prompt_feature_spec(execution_request.target.feature_id)

    assert candidate.text == execution_request.source_prompt.prompt + spec.intervention_clauses[0]
    assert "unsafe" not in candidate.text.casefold()
    assert "vulnerab" not in candidate.text.casefold()


def test_add_executor_rejects_attestation_for_a_different_catalog_clause() -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.TARGET_PATCH,
    )
    peer_payload = execution_request.attestations[1].model_dump(
        mode="python",
        exclude={"attestation_id"},
    )
    foreign_clause = b" Use parameterized queries for user-provided values."
    peer_payload.update(
        variant_clause_end=int(peer_payload["variant_clause_start"]) + len(foreign_clause),
        variant_clause_sha256=__import__("hashlib").sha256(foreign_clause).hexdigest(),
    )
    forged_peer = PromptRoleAttestationRecord.from_content(**peer_payload)
    execution_request = execution_request.model_copy(
        update={"attestations": (execution_request.attestations[0], forged_peer)}
    )

    with pytest.raises(SecAwareError) as exc_info:
        DeterministicInterventionExecutor().execute(execution_request)
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize(
    "mutation",
    ("source_hash", "protocol", "arm", "counterpart", "attestation", "graph"),
)
def test_executor_revalidates_all_request_coordinates(mutation: str) -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.REMOVE,
        ArmRole.TARGET_REMOVE,
    )
    if mutation == "source_hash":
        execution_request = execution_request.model_copy(
            update={
                "target_instance": execution_request.target_instance.model_copy(
                    update={"source_prompt_sha256": "0" * 64}
                )
            }
        )
    elif mutation == "protocol":
        execution_request = execution_request.model_copy(
            update={
                "protocol_instance": execution_request.protocol_instance.model_copy(
                    update={"arm_protocol_id": "arm_protocol_" + "0" * 64}
                )
            }
        )
    elif mutation == "arm":
        execution_request = execution_request.model_copy(
            update={
                "arm": execution_request.protocol.arms[1].model_copy(
                    update={"role": ArmRole.TARGET_REMOVE}
                )
            }
        )
    elif mutation == "counterpart":
        execution_request = execution_request.model_copy(
            update={
                "counterpart_prompt": execution_request.counterpart_prompt.model_copy(
                    update={"prompt": "forged neutral counterpart"}
                )
            }
        )
    elif mutation == "attestation":
        forged = execution_request.attestations[1].model_copy(update={"variant_clause_end": 1})
        execution_request = execution_request.model_copy(
            update={"attestations": (execution_request.attestations[0], forged)}
        )
    else:
        execution_request = execution_request.model_copy(
            update={
                "source_graph": execution_request.source_graph.model_copy(
                    update={"graph_sha256": "0" * 64}
                )
            }
        )

    with pytest.raises(SecAwareError) as exc_info:
        DeterministicInterventionExecutor().execute(execution_request)
    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.POLICY_MISMATCH}


def _minimal_config(intervention: dict[str, object] | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "run": {"name": "executor-test"},
        "data": {
            "prompts_path": "prompts.jsonl",
            "prompt_attestations_path": "attestations.jsonl",
        },
        "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
    }
    if intervention is not None:
        result["intervention"] = intervention
    return result


def _llm_config() -> dict[str, object]:
    return {
        "model_id": "executor-model",
        "base_url": "https://provider.invalid/v1",
        "api_key_env": "EXECUTOR_API_KEY",
        "timeout_seconds": 60.0,
        "max_attempts": 3,
        "max_response_bytes": 262_144,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 0,
    }


def test_app_config_requires_explicit_intervention_and_defaults_executor_to_llm() -> None:
    assert InterventionConfig.model_fields["executor"].default is InterventionExecutorKind.LLM
    assert AppConfig.model_fields["intervention"].is_required()
    with pytest.raises(ValidationError):
        AppConfig.model_validate(_minimal_config())
    with pytest.raises(ValidationError):
        AppConfig.model_validate(_minimal_config({}))

    config = AppConfig.model_validate(_minimal_config({"executor": "deterministic"}))
    assert config.intervention.executor is InterventionExecutorKind.DETERMINISTIC
    assert config.intervention.llm is None
    assert config.intervention.mode is InterventionMode.TEXT_NATIVE


def test_config_file_without_explicit_intervention_fails_closed(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "missing-intervention.yaml"
    config_path.write_text(
        yaml.safe_dump(_minimal_config()),
        encoding="utf-8",
    )
    with pytest.raises(SecAwareError) as exc_info:
        load_config(config_path)
    assert exc_info.value.code is ErrorCode.CONFIG


@pytest.mark.parametrize(
    "intervention",
    (
        {"executor": "llm"},
        {"executor": "deterministic", "llm": _llm_config()},
    ),
)
def test_app_config_rejects_executor_policy_mismatch(
    intervention: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate(_minimal_config(intervention))


def test_explicit_llm_config_is_strict_frozen_and_bounded() -> None:
    config = AppConfig.model_validate(
        _minimal_config(
            {
                "executor": "llm",
                "mode": "graph_native",
                "llm": _llm_config(),
                "operations": ["add", "remove"],
                "max_protocols": 64,
            }
        )
    )
    assert config.intervention.executor is InterventionExecutorKind.LLM
    assert config.intervention.mode is InterventionMode.GRAPH_NATIVE
    assert isinstance(config.intervention.llm, InterventionLLMConfig)
    with pytest.raises(ValidationError):
        config.intervention.max_protocols = 65  # type: ignore[misc]

    policy = structured_policy_from_config(config.intervention.llm)
    assert policy.model_id == "executor-model"
    assert policy.temperature == 0.0
    assert policy.max_attempts == 3


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_attempts", True),
        ("max_response_bytes", 1024.0),
        ("temperature", "0.0"),
        ("seed", True),
    ),
)
def test_intervention_llm_config_rejects_type_coercion(field: str, value: object) -> None:
    payload = _llm_config()
    payload[field] = value
    with pytest.raises(ValidationError):
        InterventionLLMConfig.model_validate(payload)


@pytest.mark.parametrize(
    "intervention",
    (
        {"enabled_directions": ["risk_down"]},
        {"operations": ["add", "add"]},
        {"operations": []},
        {"max_protocols": 0},
    ),
)
def test_intervention_config_rejects_legacy_or_nonclosed_values(
    intervention: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        InterventionConfig.model_validate(intervention)


def test_repository_configs_make_executor_choice_explicit() -> None:
    demo = load_config(PROJECT_ROOT / "configs" / "demo.yaml")
    paper = load_config(PROJECT_ROOT / "configs" / "paper_v0.yaml")

    assert demo.intervention.executor is InterventionExecutorKind.DETERMINISTIC
    assert demo.intervention.llm is None
    assert paper.intervention.executor is InterventionExecutorKind.LLM
    assert paper.intervention.llm is not None


def test_intervention_public_api_exposes_only_locked_executor_entrypoints() -> None:
    import secaware.intervention as intervention_api

    assert intervention_api.DeterministicInterventionExecutor is DeterministicInterventionExecutor
    assert intervention_api.structured_policy_from_config is structured_policy_from_config
    assert not hasattr(intervention_api, "register_arm_renderer")

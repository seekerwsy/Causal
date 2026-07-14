from __future__ import annotations

from dataclasses import replace
import math
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from m5_executor_fixtures import proposal_graph, request
from secaware.config import AppConfig, InterventionConfig, InterventionLLMConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.executors import (
    DETERMINISTIC_INTERVENTION_POLICY_SHA256,
    DeterministicInterventionExecutor,
    structured_policy_from_config,
)
from secaware.schema.experiments import (
    CONFIRMATION_TARGET_FEATURE_IDS,
    ArmRole,
    FeatureFamily,
    FeatureOperation,
    InterventionExecutorKind,
    InterventionMode,
    FunctionalOutcomeContractRecord,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state_vector
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
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_TARGET),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_NOOP),
    (FeatureFamily.TASK_FUNCTION, FeatureOperation.REMOVE, ArmRole.TASK_LENGTH_PLACEBO),
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


def _execute_rejects(execution_request: object) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        DeterministicInterventionExecutor().execute(execution_request)
    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.POLICY_MISMATCH}


def test_execution_request_requires_complete_sensitive_provenance() -> None:
    execution_request = request()
    rendered = repr(execution_request)
    assert execution_request.hypothesis.hypothesis_id not in rendered
    assert execution_request.source_prompt.prompt not in rendered
    assert execution_request.source_proposal.proposal_id not in rendered

    payload = execution_request.model_dump(mode="python")
    for field in ("hypothesis", "prompt_bundle", "source_proposal"):
        incomplete = dict(payload)
        incomplete.pop(field)
        with pytest.raises(ValidationError):
            type(execution_request).model_validate(incomplete)


def test_executor_rejects_forged_frozen_hypothesis_digest() -> None:
    execution_request = request().model_copy(
        update={
            "hypothesis": request().hypothesis.model_copy(update={"hypothesis_sha256": "0" * 64})
        }
    )
    _execute_rejects(execution_request)


def test_executor_rejects_functional_contract_from_another_preregistration() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        ArmRole.TASK_TARGET,
        with_functional_contract=True,
    )
    assert (
        DeterministicInterventionExecutor().execute(execution_request).arm_role
        is ArmRole.TASK_TARGET
    )
    forged_contract = FunctionalOutcomeContractRecord.from_content(
        task_feature_id="task.database_query",
        outcome_id="y_task_database_functional",
        expected_add_sign="positive",
        expected_remove_sign="negative",
        generic_control_feature_id="task.input_consumption",
        evaluator_policy_sha256="8" * 64,
    )
    _execute_rejects(execution_request.model_copy(update={"functional_contract": forged_contract}))


@pytest.mark.parametrize("mutation", ("cross_cwe_peer", "counterpart_coordinates"))
def test_executor_rejects_ghost_prompt_bundle_peers(mutation: str) -> None:
    execution_request = request()
    baseline, variant = execution_request.prompt_bundle
    if mutation == "cross_cwe_peer":
        forged_peer = PromptRecord.model_validate(
            {**variant.model_dump(mode="python"), "cwe": "CWE-89"}
        )
    else:
        forged_peer = PromptRecord.model_validate(
            {
                **variant.model_dump(mode="python"),
                "counterpart_prompt_id": "ghost-baseline",
            }
        )
    _execute_rejects(
        execution_request.model_copy(update={"prompt_bundle": (baseline, forged_peer)})
    )


def test_executor_rejects_same_id_other_content_proposal_and_graph() -> None:
    execution_request = request()
    source = execution_request.source_prompt
    other = PromptRecord.model_validate(
        {
            **source.model_dump(mode="python"),
            "prompt": source.prompt + " This is unrelated content.",
        }
    )
    proposal, graph = proposal_graph(other)
    _execute_rejects(
        execution_request.model_copy(update={"source_proposal": proposal, "source_graph": graph})
    )


def test_executor_rejects_allowed_transition_with_wrong_live_graph_state() -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        baseline_text=(
            "Create a Python helper that reads a user-provided file path and mentions "
            "a length matched placebo."
        ),
    )
    _execute_rejects(execution_request)


def _canonical_changed_span_utf8_bytes(before: str, after: str) -> int:
    before_bytes = before.encode("utf-8")
    after_bytes = after.encode("utf-8")
    prefix = 0
    while (
        prefix < len(before_bytes)
        and prefix < len(after_bytes)
        and before_bytes[prefix] == after_bytes[prefix]
    ):
        prefix += 1
    suffix = 0
    while (
        suffix < len(before_bytes) - prefix
        and suffix < len(after_bytes) - prefix
        and before_bytes[-1 - suffix] == after_bytes[-1 - suffix]
    ):
        suffix += 1
    return (len(before_bytes) - prefix - suffix) + (len(after_bytes) - prefix - suffix)


def _matched_coordinates() -> tuple[tuple[str, FeatureOperation, ArmRole, ArmRole], ...]:
    result: list[tuple[str, FeatureOperation, ArmRole, ArmRole]] = []
    for feature_id in CONFIRMATION_TARGET_FEATURE_IDS:
        family = prompt_feature_spec(feature_id).feature_family
        for operation in FeatureOperation:
            if family is FeatureFamily.SAFETY_CONTROL:
                target = (
                    ArmRole.TARGET_PATCH
                    if operation is FeatureOperation.ADD
                    else ArmRole.TARGET_REMOVE
                )
                matched = (
                    ArmRole.LENGTH_MATCHED_PLACEBO
                    if operation is FeatureOperation.ADD
                    else ArmRole.LENGTH_MATCHED_SHAM_EDIT
                )
            elif family is FeatureFamily.TASK_FUNCTION:
                target = ArmRole.TASK_TARGET
                matched = ArmRole.TASK_LENGTH_PLACEBO
            else:
                if prompt_feature_spec(feature_id).matched_control_feature_id is None:
                    continue
                target = ArmRole.PRESENTATION_TARGET
                matched = ArmRole.PRESENTATION_MATCHED_CONTROL
            result.append((feature_id, operation, target, matched))
    return tuple(result)


@pytest.mark.parametrize(
    ("feature_id", "operation", "target_role", "matched_role"),
    _matched_coordinates(),
)
def test_deterministic_matched_roles_fit_task4_canonical_changed_span_tolerance(
    feature_id: str,
    operation: FeatureOperation,
    target_role: ArmRole,
    matched_role: ArmRole,
) -> None:
    family = prompt_feature_spec(feature_id).feature_family
    target_request = request(
        family,
        operation,
        target_role,
        feature_id=feature_id,
    )
    matched_request = request(
        family,
        operation,
        matched_role,
        feature_id=feature_id,
    )
    executor = DeterministicInterventionExecutor()
    target_candidate = executor.execute(target_request)
    matched_candidate = executor.execute(matched_request)
    reference = _canonical_changed_span_utf8_bytes(
        target_request.source_prompt.prompt,
        target_candidate.text,
    )
    observed = _canonical_changed_span_utf8_bytes(
        matched_request.source_prompt.prompt,
        matched_candidate.text,
    )
    assert abs(reference - observed) <= max(4, math.ceil(reference * 0.05))
    if operation is FeatureOperation.REMOVE:
        assert matched_candidate.text.startswith(matched_request.source_prompt.prompt)


def test_deterministic_noop_rewrite_changes_bytes_without_feature_state_change() -> None:
    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.NOOP_REWRITE,
    )
    candidate = DeterministicInterventionExecutor().execute(execution_request)
    assert candidate.text == execution_request.source_prompt.prompt + "\n"

    candidate_prompt = PromptRecord.model_validate(
        {
            **execution_request.source_prompt.model_dump(mode="python"),
            "prompt": candidate.text,
        }
    )
    _proposal, candidate_graph = proposal_graph(candidate_prompt)
    before = feature_state_vector(record_to_multidigraph(execution_request.source_graph))
    after = feature_state_vector(record_to_multidigraph(candidate_graph))
    assert after == before


@pytest.mark.parametrize(
    ("family", "operation", "role"),
    (
        (FeatureFamily.SAFETY_CONTROL, FeatureOperation.REMOVE, ArmRole.NOOP_RETAIN),
        (FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD, ArmRole.TASK_NOOP),
        (
            FeatureFamily.PRESENTATION_CONTROL,
            FeatureOperation.ADD,
            ArmRole.PRESENTATION_NOOP,
        ),
    ),
)
def test_other_deterministic_noop_roles_retain_exact_source_bytes(
    family: FeatureFamily,
    operation: FeatureOperation,
    role: ArmRole,
) -> None:
    execution_request = request(family, operation, role)
    candidate = DeterministicInterventionExecutor().execute(execution_request)
    assert candidate.text.encode("utf-8") == execution_request.source_prompt.prompt.encode("utf-8")


def test_deterministic_matched_role_fails_closed_without_a_feasible_clause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.intervention.executors as executor_module

    execution_request = request(
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.ADD,
        ArmRole.LENGTH_MATCHED_PLACEBO,
    )
    original = prompt_feature_spec("presentation.length_matched_placebo")

    def infeasible(feature_id: str):
        if feature_id == original.feature_id:
            return replace(
                original,
                intervention_clauses=(
                    " Use a placebo edit with deliberately excessive padding here.",
                ),
            )
        return prompt_feature_spec(feature_id)

    monkeypatch.setattr(executor_module, "prompt_feature_spec", infeasible)
    _execute_rejects(execution_request)


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
    if role not in {
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.TASK_LENGTH_PLACEBO,
        ArmRole.PRESENTATION_MATCHED_CONTROL,
    }:
        assert candidate.text == _expected_deterministic_text(execution_request)


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_task_generic_control_fails_closed_when_feature_is_not_applicable(
    operation: FeatureOperation,
) -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        operation,
        ArmRole.TASK_GENERIC_CONTROL,
    )
    _execute_rejects(execution_request)


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

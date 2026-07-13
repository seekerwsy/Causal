from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from secaware.schema import common as common_schema
from secaware.schema import experiments as experiment_schema
from secaware.schema.common import SafeValidationMixin
from secaware.schema.experiments import (
    AllowedDeltaRecord,
    ArmRole,
    ArmSpecRecord,
    ConfirmationProtocolInstanceRecord,
    FeatureTransition,
    FunctionalOutcomeContractRecord,
    InterventionExecutorKind,
    InterventionMode,
    PreRegisteredContrastSpec,
    PromptRole,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation, FeatureState
from secaware.tsg import feature_catalog


SHA_A = "a" * 64
SHA_B = "b" * 64
HYPOTHESIS_ID = "hypothesis_" + "c" * 64


class _MemoryRaisingBase:
    memory_error: MemoryError

    def __init__(self, **_data: object) -> None:
        raise type(self).memory_error

    def __setattr__(self, _name: str, _value: object) -> None:
        raise type(self).memory_error

    @classmethod
    def model_validate(cls, _obj: object, **_kwargs: object):
        raise cls.memory_error

    @classmethod
    def model_validate_json(cls, _obj: object, **_kwargs: object):
        raise cls.memory_error


class _MemoryMixinProbe(SafeValidationMixin, _MemoryRaisingBase):
    _safe_validation_message = "probe failed validation"


def _target_spec() -> TargetSpecRecord:
    return TargetSpecRecord.from_content(
        hypothesis_id=HYPOTHESIS_ID,
        frozen_hypothesis_sha256=SHA_A,
        feature_family=FeatureFamily.SAFETY_CONTROL,
        feature_id="safety.path_normalization",
        operation=FeatureOperation.ADD,
        hypothesis_outcome_variable_id="y.secure_functional",
        hypothesis_outcome_estimand_id="y_secure_functional",
        expected_hypothesis_contrast_sign="positive",
    )


def _functional_contract() -> FunctionalOutcomeContractRecord:
    return FunctionalOutcomeContractRecord.from_content(
        task_feature_id="task.database_query",
        outcome_id="y_task_database_functional",
        expected_add_sign="positive",
        expected_remove_sign="negative",
        generic_control_feature_id="task.input_consumption",
        evaluator_policy_sha256=SHA_B,
    )


def test_experiment_enums_are_exact_and_closed() -> None:
    assert tuple(item.value for item in PromptRole) == (
        "neutral_baseline",
        "positive_safety_control",
        "task_function_baseline",
        "task_function_variant",
        "presentation_baseline",
        "presentation_variant",
    )
    assert tuple(item.value for item in InterventionMode) == (
        "text_native",
        "graph_native",
    )
    assert tuple(item.value for item in InterventionExecutorKind) == (
        "deterministic",
        "llm",
    )
    assert tuple(item.value for item in ArmRole) == (
        "target_patch",
        "noop_rewrite",
        "length_matched_placebo",
        "generic_security_reminder",
        "target_remove",
        "noop_retain",
        "length_matched_sham_edit",
        "generic_security_replacement",
        "task_target",
        "task_noop",
        "task_length_placebo",
        "task_generic_control",
        "presentation_target",
        "presentation_noop",
        "presentation_matched_control",
    )


@pytest.mark.parametrize(
    "entrypoint",
    (
        "model_shape_is_intact",
        "init",
        "setattr",
        "model_validate",
        "model_validate_json",
        "model_validate_strings",
    ),
)
def test_safe_validation_mixin_preserves_memory_error_identity(
    monkeypatch,
    entrypoint: str,
) -> None:
    error = MemoryError(f"memory-{entrypoint}")
    _MemoryMixinProbe.memory_error = error

    with pytest.raises(MemoryError) as exc_info:
        if entrypoint == "model_shape_is_intact":
            target = _target_spec()

            def fail_vars(_value):
                raise error

            monkeypatch.setattr(common_schema, "vars", fail_vars, raising=False)
            common_schema.model_shape_is_intact(target)
        elif entrypoint == "init":
            _MemoryMixinProbe()
        elif entrypoint == "setattr":
            probe = object.__new__(_MemoryMixinProbe)
            probe.value = "x"
        elif entrypoint == "model_validate":
            _MemoryMixinProbe.model_validate({})
        elif entrypoint == "model_validate_json":
            _MemoryMixinProbe.model_validate_json("{}")
        else:
            _MemoryMixinProbe.model_validate_strings({})

    assert exc_info.value is error


def test_experiment_factory_preserves_digest_memory_error_identity(monkeypatch) -> None:
    error = MemoryError("memory-digest")

    def fail_digest(_value):
        raise error

    monkeypatch.setattr(experiment_schema, "_digest", fail_digest)
    with pytest.raises(MemoryError) as exc_info:
        _target_spec()
    assert exc_info.value is error


def test_experiment_catalog_lookup_preserves_memory_error_identity(monkeypatch) -> None:
    error = MemoryError("memory-catalog")

    def fail_lookup(_value):
        raise error

    monkeypatch.setattr(feature_catalog, "prompt_feature_spec", fail_lookup)
    with pytest.raises(MemoryError) as exc_info:
        FeatureTransition(
            feature_id="safety.path_normalization",
            from_states=(FeatureState.ABSENT,),
            to_states=(FeatureState.PRESENT,),
        )
    assert exc_info.value is error


def test_target_spec_is_content_addressed_and_has_no_task_coordinates() -> None:
    first = _target_spec()
    second = _target_spec()

    assert first == second
    assert first.target_spec_id.startswith("target_")
    assert "task_id" not in type(first).model_fields
    assert "source_prompt_id" not in type(first).model_fields


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("feature_id", "safety.sql_parameterization"),
        ("operation", "remove"),
        ("hypothesis_outcome_variable_id", "y.cwe_security"),
        ("hypothesis_outcome_estimand_id", "y_cwe_secure"),
        ("expected_hypothesis_contrast_sign", "negative"),
        ("frozen_hypothesis_sha256", SHA_B),
    ),
)
def test_target_spec_rejects_semantic_or_digest_mutation(
    field: str,
    replacement: str,
) -> None:
    payload = _target_spec().model_dump(mode="json")
    payload[field] = replacement

    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        TargetSpecRecord.model_validate(payload)


def test_target_instance_is_the_only_target_record_with_prompt_coordinates() -> None:
    target = _target_spec()
    first = TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id="task-001",
        source_prompt_id="prompt-neutral-001",
        source_prompt_sha256=SHA_A,
        counterpart_prompt_id="prompt-positive-001",
        counterpart_prompt_sha256=SHA_B,
        source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_required=True,
    )
    second = TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id="task-002",
        source_prompt_id="prompt-neutral-002",
        source_prompt_sha256=SHA_A,
        counterpart_prompt_id="prompt-positive-002",
        counterpart_prompt_sha256=SHA_B,
        source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_required=True,
    )

    assert first.target_instance_id != second.target_instance_id
    assert first.target_spec_id == second.target_spec_id


@pytest.mark.parametrize(
    "payload_update",
    (
        {"counterpart_required": True, "counterpart_prompt_id": None},
        {"counterpart_required": True, "counterpart_prompt_sha256": None},
        {
            "counterpart_required": False,
            "counterpart_prompt_id": "prompt-positive-001",
            "counterpart_prompt_sha256": SHA_B,
        },
    ),
)
def test_target_instance_rejects_incomplete_or_unrequested_counterpart(
    payload_update: dict[str, object],
) -> None:
    payload: dict[str, object] = {
        "target_spec_id": _target_spec().target_spec_id,
        "task_id": "task-001",
        "source_prompt_id": "prompt-neutral-001",
        "source_prompt_sha256": SHA_A,
        "counterpart_prompt_id": "prompt-positive-001",
        "counterpart_prompt_sha256": SHA_B,
        "source_prompt_role": PromptRole.NEUTRAL_BASELINE,
        "counterpart_required": True,
    }
    payload.update(payload_update)

    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        TargetInstanceRecord.from_content(**payload)


def test_allowed_delta_is_an_upper_bound_and_may_be_empty() -> None:
    delta = AllowedDeltaRecord(
        allowed_transitions=(),
        fixed_families=tuple(FeatureFamily),
        fixed_feature_ids=(),
    )
    arm = ArmSpecRecord(role=ArmRole.NOOP_REWRITE, allowed_delta=delta)

    assert arm.allowed_delta.allowed_transitions == ()


def test_transition_and_delta_reject_duplicate_or_overlapping_contracts() -> None:
    transition = FeatureTransition(
        feature_id="safety.path_normalization",
        from_states=(FeatureState.ABSENT,),
        to_states=(FeatureState.PRESENT,),
    )
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        FeatureTransition(
            feature_id="safety.path_normalization",
            from_states=(FeatureState.ABSENT, FeatureState.ABSENT),
            to_states=(FeatureState.PRESENT,),
        )
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        AllowedDeltaRecord(
            allowed_transitions=(transition, transition),
            fixed_families=(FeatureFamily.TASK_FUNCTION,),
            fixed_feature_ids=(),
        )
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        AllowedDeltaRecord(
            allowed_transitions=(transition,),
            fixed_families=(FeatureFamily.SAFETY_CONTROL,),
            fixed_feature_ids=(),
        )


def test_functional_contract_is_content_addressed_and_strict() -> None:
    contract = _functional_contract()
    payload = contract.model_dump(mode="json")
    payload["expected_add_sign"] = "negative"
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        FunctionalOutcomeContractRecord.model_validate(payload)

    extra = contract.model_dump(mode="json")
    extra["review_notes"] = "secret review text"
    with pytest.raises(ValidationError) as exc_info:
        FunctionalOutcomeContractRecord.model_validate(extra)
    assert "secret review text" not in str(exc_info.value)


def test_functional_contract_rejects_same_target_and_generic_feature() -> None:
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        FunctionalOutcomeContractRecord.from_content(
            task_feature_id="task.database_query",
            outcome_id="y_task_database_functional",
            expected_add_sign="positive",
            expected_remove_sign="negative",
            generic_control_feature_id="task.database_query",
            evaluator_policy_sha256=SHA_B,
        )


def test_protocol_instance_is_content_addressed_and_carries_only_coordinates() -> None:
    target = TargetInstanceRecord.from_content(
        target_spec_id=_target_spec().target_spec_id,
        task_id="task-001",
        source_prompt_id="prompt-neutral-001",
        source_prompt_sha256=SHA_A,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_required=False,
    )
    instance = ConfirmationProtocolInstanceRecord.from_content(
        arm_protocol_id="arm_protocol_" + "d" * 64,
        target_instance_id=target.target_instance_id,
        task_id=target.task_id,
        source_prompt_id=target.source_prompt_id,
        source_prompt_sha256=target.source_prompt_sha256,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
    )
    payload = instance.model_dump(mode="json")
    payload["task_id"] = "task-002"

    assert "arms" not in type(instance).model_fields
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        ConfirmationProtocolInstanceRecord.model_validate(payload)


def test_all_persisted_records_are_frozen_strict_and_json_roundtrippable() -> None:
    target = _target_spec()
    instance = TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id="task-001",
        source_prompt_id="prompt-neutral-001",
        source_prompt_sha256=SHA_A,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_required=False,
    )
    records = (target, instance, _functional_contract())

    for record in records:
        restored = type(record).model_validate_json(record.model_dump_json())
        assert restored == record
        with pytest.raises(ValidationError):
            type(record).model_validate({**record.model_dump(mode="json"), "extra": "secret"})
        with pytest.raises(ValidationError):
            record.schema_version = "1.0"  # type: ignore[misc]


def test_nested_records_snapshot_json_arrays_and_reject_unknown_enum_values() -> None:
    transition_payload = {
        "feature_id": "safety.path_normalization",
        "from_states": ["absent"],
        "to_states": ["present"],
    }
    transition = FeatureTransition.model_validate(transition_payload)
    transition_payload["from_states"][0] = "unresolved"
    assert transition.from_states == (FeatureState.ABSENT,)

    secret = "raw-secret-role"
    with pytest.raises(ValidationError) as exc_info:
        ArmSpecRecord.model_validate(
            {
                "role": secret,
                "allowed_delta": {
                    "allowed_transitions": [],
                    "fixed_families": [],
                    "fixed_feature_ids": [],
                },
            }
        )
    assert secret not in str(exc_info.value)


def test_contrast_record_rejects_invalid_identifier_and_same_arm_pair() -> None:
    payload = {
        "contrast_id": "safety_add.target_minus_noop.y_secure_functional",
        "arm_contrast_id": "safety_add.target_minus_noop",
        "treatment_arm": ArmRole.TARGET_PATCH,
        "control_arm": ArmRole.NOOP_REWRITE,
        "source_outcome_variable_id": "y.secure_functional",
        "outcome_id": "y_secure_functional",
        "priority": "primary",
        "expected_sign": "positive",
        "multiplicity_family_id": "multiplicity_" + "e" * 64,
    }
    contrast = PreRegisteredContrastSpec.model_validate(deepcopy(payload))
    assert contrast.priority == "primary"

    payload["control_arm"] = ArmRole.TARGET_PATCH
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        PreRegisteredContrastSpec.model_validate(payload)

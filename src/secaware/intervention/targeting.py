"""Materialize semantic intervention targets and task-specific instances."""

from __future__ import annotations

from collections.abc import Sequence

from secaware.causal.freeze import revalidate_frozen_hypothesis
from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.attestation import (
    PromptRoleAttestationRecord,
    attested_feature_id,
    validate_prompt_role_attestations,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureFamily,
    FeatureOperation,
    PromptRole,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)


_ROLE_MATRIX = {
    (FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD): PromptRole.NEUTRAL_BASELINE,
    (
        FeatureFamily.SAFETY_CONTROL,
        FeatureOperation.REMOVE,
    ): PromptRole.POSITIVE_SAFETY_CONTROL,
    (
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
    ): PromptRole.TASK_FUNCTION_BASELINE,
    (
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.REMOVE,
    ): PromptRole.TASK_FUNCTION_VARIANT,
    (
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.ADD,
    ): PromptRole.PRESENTATION_BASELINE,
    (
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.REMOVE,
    ): PromptRole.PRESENTATION_VARIANT,
}
_VARIANT_FOR_BASELINE = {
    PromptRole.NEUTRAL_BASELINE: PromptRole.POSITIVE_SAFETY_CONTROL,
    PromptRole.TASK_FUNCTION_BASELINE: PromptRole.TASK_FUNCTION_VARIANT,
    PromptRole.PRESENTATION_BASELINE: PromptRole.PRESENTATION_VARIANT,
}
_BASELINE_FOR_VARIANT = {value: key for key, value in _VARIANT_FOR_BASELINE.items()}


def _contract_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage="target_materialization",
        message="intervention target materialization failed validation",
        details={},
        retryable=False,
    )


def _checked_hypothesis(value: object) -> FrozenHypothesisRecord:
    if type(value) is not FrozenHypothesisRecord or not model_shape_is_intact(value):
        raise ValueError
    snapshot = value.model_dump(mode="python", round_trip=True, warnings=False)
    return revalidate_frozen_hypothesis(FrozenHypothesisRecord.model_validate(snapshot))


def _checked_target(value: object) -> TargetSpecRecord:
    if type(value) is not TargetSpecRecord or not model_shape_is_intact(value):
        raise ValueError
    return TargetSpecRecord.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings=False)
    )


def _checked_prompt(value: object) -> PromptRecord:
    if type(value) is not PromptRecord:
        raise ValueError
    return PromptRecord.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings=False)
    )


def _checked_prompts(values: Sequence[PromptRecord]) -> tuple[PromptRecord, ...]:
    if type(values) not in {tuple, list}:
        raise ValueError
    checked: list[PromptRecord] = []
    for value in values:
        checked.append(_checked_prompt(value))
    return tuple(checked)


def _require_source_in_prompt_artifact(
    source: PromptRecord,
    prompts: tuple[PromptRecord, ...],
) -> None:
    matches = tuple(item for item in prompts if item.prompt_id == source.prompt_id)
    if len(matches) != 1 or matches[0].model_dump(
        mode="python", round_trip=True, warnings=False
    ) != source.model_dump(mode="python", round_trip=True, warnings=False):
        raise ValueError


def _require_target_matches_hypothesis(
    target: TargetSpecRecord,
    hypothesis: FrozenHypothesisRecord,
) -> None:
    selected = tuple(
        item for item in hypothesis.expected_contrasts if item.operation is target.operation
    )
    spec = prompt_feature_spec(target.feature_id)
    if (
        len(selected) != 1
        or hypothesis.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
        or target.hypothesis_id != hypothesis.hypothesis_id
        or target.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
        or target.feature_id != hypothesis.target_feature_id
        or target.feature_family is not hypothesis.feature_family
        or target.operation not in hypothesis.permitted_operations
        or target.hypothesis_outcome_variable_id != hypothesis.outcome_variable_id
        or target.hypothesis_outcome_estimand_id != selected[0].outcome_estimand_id
        or target.expected_hypothesis_contrast_sign != selected[0].expected_sign
        or spec.feature_family is not target.feature_family
        or not spec.intervenable
        or target.operation not in spec.operations
    ):
        raise ValueError


def materialize_target_spec(
    hypothesis: FrozenHypothesisRecord,
    operation: FeatureOperation,
) -> TargetSpecRecord:
    """Create one semantic, cross-task target from a frozen hypothesis."""

    try:
        checked_hypothesis = _checked_hypothesis(hypothesis)
        if (
            type(operation) is not FeatureOperation
            or operation not in checked_hypothesis.permitted_operations
        ):
            raise ValueError
        selected = tuple(
            item for item in checked_hypothesis.expected_contrasts if item.operation is operation
        )
        if len(selected) != 1:
            raise ValueError
        target = TargetSpecRecord.from_content(
            hypothesis_id=checked_hypothesis.hypothesis_id,
            frozen_hypothesis_sha256=checked_hypothesis.hypothesis_sha256,
            feature_family=checked_hypothesis.feature_family,
            feature_id=checked_hypothesis.target_feature_id,
            operation=operation,
            hypothesis_outcome_variable_id=checked_hypothesis.outcome_variable_id,
            hypothesis_outcome_estimand_id=selected[0].outcome_estimand_id,
            expected_hypothesis_contrast_sign=selected[0].expected_sign,
        )
        _require_target_matches_hypothesis(target, checked_hypothesis)
        return target
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


def _require_prompt_scope(
    hypothesis: FrozenHypothesisRecord,
    target: TargetSpecRecord,
    prompt: PromptRecord,
) -> None:
    spec = prompt_feature_spec(target.feature_id)
    expected_scope = f"scope.cwe_{prompt.cwe.removeprefix('CWE-')}"
    if (
        prompt.split != "confirm"
        or prompt.cwe != hypothesis.cwe
        or hypothesis.scope_id != expected_scope
        or (spec.applicable_cwes and prompt.cwe not in spec.applicable_cwes)
        or (
            spec.applicable_task_families
            and prompt.task_family not in spec.applicable_task_families
        )
    ):
        raise ValueError


def _source_pair(
    prompt: PromptRecord,
    family: FeatureFamily,
    feature_id: str,
    operation: FeatureOperation,
    attestations: tuple[PromptRoleAttestationRecord, ...],
) -> tuple[PromptRoleAttestationRecord, PromptRoleAttestationRecord]:
    source_matches = tuple(item for item in attestations if item.prompt_id == prompt.prompt_id)
    if len(source_matches) != 1:
        raise ValueError
    source = source_matches[0]
    expected_role = _ROLE_MATRIX[(family, operation)]
    if (
        prompt.prompt_role is not expected_role
        or source.prompt_role is not prompt.prompt_role
        or source.task_id != prompt.task_id
        or source.prompt_sha256 != prompt.prompt_sha256
        or source.counterpart_prompt_id != prompt.counterpart_prompt_id
        or source.contrast_owner_operation is not operation
    ):
        raise ValueError

    if operation is FeatureOperation.ADD:
        expected_variant = _VARIANT_FOR_BASELINE[expected_role]
        peer_matches = tuple(
            item
            for item in attestations
            if item.counterpart_prompt_id == prompt.prompt_id
            and item.counterpart_prompt_sha256 == prompt.prompt_sha256
            and item.task_id == prompt.task_id
            and item.prompt_role is expected_variant
        )
        if len(peer_matches) != 1:
            raise ValueError
        peer = peer_matches[0]
    else:
        counterpart_id = source.counterpart_prompt_id
        counterpart_sha256 = source.counterpart_prompt_sha256
        expected_baseline = _BASELINE_FOR_VARIANT[expected_role]
        peer_matches = tuple(
            item
            for item in attestations
            if item.prompt_id == counterpart_id
            and item.prompt_sha256 == counterpart_sha256
            and item.task_id == prompt.task_id
            and item.prompt_role is expected_baseline
        )
        if len(peer_matches) != 1:
            raise ValueError
        peer = peer_matches[0]
    if peer.contrast_owner_operation is not operation:
        raise ValueError
    variant_attestation = peer if operation is FeatureOperation.ADD else source
    if attested_feature_id(variant_attestation) != feature_id:
        raise ValueError
    return source, peer


def materialize_target_instance(
    target: TargetSpecRecord,
    hypothesis: FrozenHypothesisRecord,
    prompt: PromptRecord,
    prompts: Sequence[PromptRecord],
    attestations: Sequence[PromptRoleAttestationRecord],
) -> TargetInstanceRecord:
    """Bind one semantic target through a complete validated prompt artifact."""

    try:
        checked_hypothesis = _checked_hypothesis(hypothesis)
        checked_target = _checked_target(target)
        checked_prompt = _checked_prompt(prompt)
        _require_target_matches_hypothesis(checked_target, checked_hypothesis)
        checked_prompts = _checked_prompts(prompts)
        checked_attestations = validate_prompt_role_attestations(
            checked_prompts,
            attestations,
        )
        _require_source_in_prompt_artifact(checked_prompt, checked_prompts)
        _require_prompt_scope(checked_hypothesis, checked_target, checked_prompt)
        source, peer = _source_pair(
            checked_prompt,
            checked_target.feature_family,
            checked_target.feature_id,
            checked_target.operation,
            checked_attestations,
        )
        remove = checked_target.operation is FeatureOperation.REMOVE
        counterpart = peer if remove else None
        instance = TargetInstanceRecord.from_content(
            target_spec_id=checked_target.target_spec_id,
            task_id=checked_prompt.task_id,
            source_prompt_id=checked_prompt.prompt_id,
            source_prompt_sha256=checked_prompt.prompt_sha256,
            counterpart_prompt_id=(counterpart.prompt_id if counterpart is not None else None),
            counterpart_prompt_sha256=(
                counterpart.prompt_sha256 if counterpart is not None else None
            ),
            source_prompt_role=source.prompt_role,
            counterpart_required=remove,
        )
        return TargetInstanceRecord.model_validate(instance.model_dump(mode="python"))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


def materialize_protocol_instance(
    protocol: ConfirmationProtocolRecord,
    target_instance: TargetInstanceRecord,
) -> ConfirmationProtocolInstanceRecord:
    """Bind a semantic protocol to one authenticated task target instance."""

    try:
        if (
            type(protocol) is not ConfirmationProtocolRecord
            or not model_shape_is_intact(protocol)
            or type(target_instance) is not TargetInstanceRecord
            or not model_shape_is_intact(target_instance)
        ):
            raise ValueError
        checked_protocol = ConfirmationProtocolRecord.model_validate(
            protocol.model_dump(mode="python", round_trip=True, warnings=False)
        )
        checked_instance = TargetInstanceRecord.model_validate(
            target_instance.model_dump(mode="python", round_trip=True, warnings=False)
        )
        if checked_protocol.target_spec_id != checked_instance.target_spec_id:
            raise ValueError
        result = ConfirmationProtocolInstanceRecord.from_content(
            arm_protocol_id=checked_protocol.arm_protocol_id,
            target_instance_id=checked_instance.target_instance_id,
            task_id=checked_instance.task_id,
            source_prompt_id=checked_instance.source_prompt_id,
            source_prompt_sha256=checked_instance.source_prompt_sha256,
            counterpart_prompt_id=checked_instance.counterpart_prompt_id,
            counterpart_prompt_sha256=checked_instance.counterpart_prompt_sha256,
        )
        return ConfirmationProtocolInstanceRecord.model_validate(
            result.model_dump(mode="python", round_trip=True, warnings=False)
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _contract_error() from None


__all__ = [
    "materialize_protocol_instance",
    "materialize_target_instance",
    "materialize_target_spec",
]

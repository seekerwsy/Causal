from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from secaware.intervention import arm_catalog
from secaware.intervention.arm_catalog import materialize_arm_protocol
from secaware.schema.causal import (
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PathPatternRecord,
)
from secaware.schema.experiments import (
    ArmRole,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation, FeatureState
from secaware.schema.causal import EndpointMark
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


SHA_A = "a" * 64
SHA_B = "b" * 64


def _expected_sign(family: FeatureFamily, operation: FeatureOperation) -> str:
    if family is FeatureFamily.SAFETY_CONTROL:
        return "positive" if operation is FeatureOperation.ADD else "negative"
    if family is FeatureFamily.PRESENTATION_CONTROL:
        return "null"
    return "two_sided"


def _hypothesis(
    feature_id: str = "safety.path_normalization",
    family: FeatureFamily = FeatureFamily.SAFETY_CONTROL,
    *,
    outcome_variable_id: str = "y.secure_functional",
) -> FrozenHypothesisRecord:
    estimand = {
        "y.secure_functional": "y_secure_functional",
        "y.cwe_security": "y_cwe_secure",
    }[outcome_variable_id]
    operations = (FeatureOperation.ADD, FeatureOperation.REMOVE)
    return FrozenHypothesisRecord.from_content(
        target_feature_id=feature_id,
        feature_family=family,
        permitted_operations=operations,
        scope_id="scope.cwe_22",
        cwe="CWE-22",
        model_id="model-a",
        outcome_variable_id=outcome_variable_id,
        reference_pag_id="pag_" + "c" * 64,
        path=PathPatternRecord.from_content(
            variable_ids=(f"x.{feature_id}", outcome_variable_id),
            endpoint_marks=((EndpointMark.CIRCLE, EndpointMark.ARROW),),
        ),
        support_numerator=8,
        support_denominator=10,
        table_sha256=SHA_A,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256=SHA_B,
        fci_config_sha256="d" * 64,
        background_knowledge_sha256="e" * 64,
        expected_contrasts=tuple(
            ExpectedOperationContrast(
                operation=operation,
                outcome_estimand_id=estimand,
                expected_sign=_expected_sign(family, operation),
            )
            for operation in operations
        ),
        freeze_batch_sha256="f" * 64,
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )


def _target(
    feature_id: str,
    operation: FeatureOperation,
    *,
    hypothesis: FrozenHypothesisRecord,
) -> TargetSpecRecord:
    selected = next(item for item in hypothesis.expected_contrasts if item.operation is operation)
    return TargetSpecRecord.from_content(
        hypothesis_id=hypothesis.hypothesis_id,
        frozen_hypothesis_sha256=hypothesis.hypothesis_sha256,
        feature_family=hypothesis.feature_family,
        feature_id=feature_id,
        operation=operation,
        hypothesis_outcome_variable_id=hypothesis.outcome_variable_id,
        hypothesis_outcome_estimand_id=selected.outcome_estimand_id,
        expected_hypothesis_contrast_sign=selected.expected_sign,
    )


def _arm(protocol: ConfirmationProtocolRecord, role: ArmRole):
    return next(item for item in protocol.arms if item.role is role)


def _contract(*, generic: bool = True) -> FunctionalOutcomeContractRecord:
    return FunctionalOutcomeContractRecord.from_content(
        task_feature_id="task.database_query",
        outcome_id="y_task_database_functional",
        expected_add_sign="positive",
        expected_remove_sign="negative",
        generic_control_feature_id="task.input_consumption" if generic else None,
        evaluator_policy_sha256=SHA_A,
    )


def test_safety_add_has_exact_four_arm_roles_and_eleven_contrasts() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )

    assert protocol.arm_roles == (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    )
    assert len(protocol.contrasts) == 11
    assert protocol.hypothesis_outcome_variable_id == "y.secure_functional"
    assert "safety_add.target_minus_noop.y_secure_functional" in protocol.preregistered_contrast_ids
    matched = next(
        item
        for item in protocol.contrasts
        if item.arm_contrast_id == "safety_add.target_minus_noop"
        and item.outcome_id == protocol.hypothesis_outcome_estimand_id
    )
    assert matched.source_outcome_variable_id == protocol.hypothesis_outcome_variable_id
    assert matched.expected_sign == protocol.expected_hypothesis_contrast_sign
    assert tuple(item.outcome_id for item in protocol.contrasts[:5]) == ("y_secure_functional",) * 5


def test_safety_remove_has_distinct_protocol_and_allowed_delta() -> None:
    hypothesis = _hypothesis()
    add = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    remove = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.REMOVE, hypothesis=hypothesis),
    )

    assert add.arm_protocol_id != remove.arm_protocol_id
    assert remove.arm_roles == (
        ArmRole.TARGET_REMOVE,
        ArmRole.NOOP_RETAIN,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    )
    generic = _arm(remove, ArmRole.GENERIC_SECURITY_REPLACEMENT)
    assert {item.feature_id for item in generic.allowed_delta.allowed_transitions} == {
        "safety.path_normalization",
        "safety.generic_security_reminder",
    }
    target_transition = next(
        item
        for item in generic.allowed_delta.allowed_transitions
        if item.feature_id == "safety.path_normalization"
    )
    assert target_transition.from_states == (FeatureState.PRESENT,)
    assert target_transition.to_states == (FeatureState.ABSENT,)
    assert len(remove.contrasts) == 11


@pytest.mark.parametrize(
    ("operation", "expected_secure", "expected_insecure"),
    (
        (FeatureOperation.ADD, "positive", "negative"),
        (FeatureOperation.REMOVE, "negative", "positive"),
    ),
)
def test_safety_target_noop_outcome_signs_are_frozen(
    operation: FeatureOperation,
    expected_secure: str,
    expected_insecure: str,
) -> None:
    hypothesis = _hypothesis(outcome_variable_id="y.cwe_security")
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", operation, hypothesis=hypothesis),
    )
    target_noop = {
        item.outcome_id: item
        for item in protocol.contrasts
        if item.arm_contrast_id.endswith("target_minus_noop")
    }

    assert target_noop["y_cwe_secure"].expected_sign == expected_secure
    assert target_noop["y_cwe_insecure"].expected_sign == expected_insecure
    assert target_noop["y_cwe_unknown"].expected_sign == "two_sided"
    assert target_noop["y_oracle_evaluable"].expected_sign == "two_sided"
    assert target_noop["y_parse_ok"].expected_sign == "two_sided"
    assert target_noop["y_functional_ok"].expected_sign == "two_sided"
    assert target_noop["y_cwe_secure"].priority == "secondary"


def test_safety_arm_deltas_fix_every_non_target_projection() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    target = _arm(protocol, ArmRole.TARGET_PATCH).allowed_delta
    noop = _arm(protocol, ArmRole.NOOP_REWRITE).allowed_delta
    placebo = _arm(protocol, ArmRole.LENGTH_MATCHED_PLACEBO).allowed_delta
    generic = _arm(protocol, ArmRole.GENERIC_SECURITY_REMINDER).allowed_delta

    assert target.fixed_families == (
        FeatureFamily.TASK_FUNCTION,
        FeatureFamily.PRESENTATION_CONTROL,
    )
    assert noop.fixed_families == tuple(FeatureFamily)
    assert placebo.fixed_families == (
        FeatureFamily.TASK_FUNCTION,
        FeatureFamily.SAFETY_CONTROL,
    )
    assert generic.fixed_families == (
        FeatureFamily.TASK_FUNCTION,
        FeatureFamily.PRESENTATION_CONTROL,
    )
    assert {item.feature_id for item in placebo.allowed_transitions} == {
        "presentation.length_matched_placebo"
    }


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_task_protocol_has_three_arms_without_reviewed_generic_control(
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis(
        "task.database_query",
        FeatureFamily.TASK_FUNCTION,
    )
    target = _target("task.database_query", operation, hypothesis=hypothesis)

    without_contract = materialize_arm_protocol(hypothesis, target)
    contract_without_generic = materialize_arm_protocol(
        hypothesis,
        target,
        functional_contract=_contract(generic=False),
    )

    expected = (
        ArmRole.TASK_TARGET,
        ArmRole.TASK_NOOP,
        ArmRole.TASK_LENGTH_PLACEBO,
    )
    assert without_contract.arm_roles == expected
    assert contract_without_generic.arm_roles == expected
    assert without_contract.functional_outcome_contract_id is None
    assert (
        contract_without_generic.functional_outcome_contract_id
        == _contract(generic=False).contract_id
    )


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_task_protocol_has_four_arms_only_with_matching_reviewed_contract(
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis(
        "task.database_query",
        FeatureFamily.TASK_FUNCTION,
    )
    target = _target("task.database_query", operation, hypothesis=hypothesis)
    protocol = materialize_arm_protocol(
        hypothesis,
        target,
        functional_contract=_contract(),
    )

    assert protocol.arm_roles == (
        ArmRole.TASK_TARGET,
        ArmRole.TASK_NOOP,
        ArmRole.TASK_LENGTH_PLACEBO,
        ArmRole.TASK_GENERIC_CONTROL,
    )
    assert protocol.functional_outcome_contract_id == _contract().contract_id
    assert all(
        FeatureFamily.SAFETY_CONTROL in arm.allowed_delta.fixed_families for arm in protocol.arms
    )
    primary = next(item for item in protocol.contrasts if item.priority == "primary")
    assert primary.outcome_id == "y_task_database_functional"
    assert primary.expected_sign == (
        "positive" if operation is FeatureOperation.ADD else "negative"
    )
    assert all("generic_security" not in item.role.value for item in protocol.arms)


def test_task_contract_for_another_feature_or_unknown_generic_fails_closed() -> None:
    hypothesis = _hypothesis("task.file_read", FeatureFamily.TASK_FUNCTION)
    target = _target("task.file_read", FeatureOperation.ADD, hypothesis=hypothesis)

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, target, functional_contract=_contract())

    payload = _contract().model_dump(mode="json", exclude={"contract_id"})
    payload["generic_control_feature_id"] = "task.runtime_injected"
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        FunctionalOutcomeContractRecord.from_content(**payload)


@pytest.mark.parametrize(
    ("feature_id", "expected_roles"),
    (
        (
            "presentation.noop_rewrite",
            (
                ArmRole.PRESENTATION_TARGET,
                ArmRole.PRESENTATION_NOOP,
                ArmRole.PRESENTATION_MATCHED_CONTROL,
            ),
        ),
        (
            "presentation.matched_control",
            (ArmRole.PRESENTATION_TARGET, ArmRole.PRESENTATION_NOOP),
        ),
    ),
)
@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_presentation_protocol_uses_only_catalog_declared_matched_control(
    feature_id: str,
    expected_roles: tuple[ArmRole, ...],
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis(feature_id, FeatureFamily.PRESENTATION_CONTROL)
    protocol = materialize_arm_protocol(
        hypothesis,
        _target(feature_id, operation, hypothesis=hypothesis),
    )

    assert protocol.arm_roles == expected_roles
    assert all(
        FeatureFamily.TASK_FUNCTION in arm.allowed_delta.fixed_families
        and FeatureFamily.SAFETY_CONTROL in arm.allowed_delta.fixed_families
        for arm in protocol.arms
    )
    assert all(item.expected_sign == "null" for item in protocol.contrasts)
    assert all("generic_security" not in item.role.value for item in protocol.arms)
    assert all(item.priority != "primary" for item in protocol.contrasts)


@pytest.mark.parametrize(
    ("feature_id", "family", "operation"),
    (
        (
            "safety.prohibited_unsafe_request",
            FeatureFamily.SAFETY_CONTROL,
            FeatureOperation.ADD,
        ),
        ("task.runtime_feature", FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD),
    ),
)
def test_non_intervenable_or_unknown_target_feature_fails_closed(
    feature_id: str,
    family: FeatureFamily,
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis()
    target_payload = _target(
        "safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis
    ).model_dump(mode="json", exclude={"target_spec_id"})
    target_payload.update(
        feature_id=feature_id,
        feature_family=family,
        operation=operation,
    )
    target = TargetSpecRecord.from_content(**target_payload)

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, target)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("hypothesis_id", "hypothesis_" + "0" * 64),
        ("feature_family", FeatureFamily.TASK_FUNCTION),
        ("feature_id", "safety.sql_parameterization"),
        ("hypothesis_outcome_variable_id", "y.cwe_security"),
        ("hypothesis_outcome_estimand_id", "y_cwe_secure"),
        ("expected_hypothesis_contrast_sign", "negative"),
    ),
)
def test_target_coordinates_must_match_frozen_hypothesis(
    field: str,
    replacement: object,
) -> None:
    hypothesis = _hypothesis()
    payload = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    target = payload.model_copy(update={field: replacement})

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, target)


def test_materializer_revalidates_frozen_hypothesis_digest_before_dispatch() -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    payload = hypothesis.model_dump(mode="python")
    payload["hypothesis_sha256"] = "0" * 64
    forged = hypothesis.model_copy(update={"hypothesis_sha256": "0" * 64})
    assert forged.hypothesis_sha256 != hypothesis.hypothesis_sha256

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(forged, target)


def test_operation_must_be_permitted_and_match_frozen_operation_contrast() -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    forged = target.model_copy(update={"operation": "replace"})
    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, forged)

    wrong_sign_payload = target.model_dump(mode="json", exclude={"target_spec_id"})
    wrong_sign_payload["expected_hypothesis_contrast_sign"] = "null"
    wrong_sign = TargetSpecRecord.from_content(**wrong_sign_payload)
    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, wrong_sign)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        (
            "contrast_id",
            "safety_add.target_minus_noop.y_cwe_secure",
        ),
        ("arm_contrast_id", "safety_add.target_minus_placebo"),
        ("treatment_arm", ArmRole.NOOP_REWRITE),
        ("control_arm", ArmRole.LENGTH_MATCHED_PLACEBO),
        ("source_outcome_variable_id", "y.cwe_security"),
        ("outcome_id", "y_cwe_secure"),
        ("priority", "diagnostic"),
        ("expected_sign", "null"),
        ("multiplicity_family_id", "multiplicity_" + "0" * 64),
    ),
)
def test_every_complete_contrast_field_is_authenticated(
    field: str,
    replacement: object,
) -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    payload = protocol.model_dump(mode="json")
    payload["contrasts"][0][field] = replacement

    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        ConfirmationProtocolRecord.model_validate(payload)


def test_contrast_and_arm_order_duplicate_roles_and_digest_mutations_fail_closed() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )

    for mutator in (
        lambda value: value["contrasts"].reverse(),
        lambda value: value["arms"].reverse(),
        lambda value: value["arms"].__setitem__(1, deepcopy(value["arms"][0])),
        lambda value: value.__setitem__("contrast_set_sha256", "0" * 64),
        lambda value: value.__setitem__("arm_protocol_id", "arm_protocol_" + "0" * 64),
    ):
        payload = protocol.model_dump(mode="json")
        mutator(payload)
        with pytest.raises(ValidationError, match="experiment contract failed validation"):
            ConfirmationProtocolRecord.model_validate(payload)


def test_target_feature_cannot_appear_in_placebo_delta() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    payload = protocol.model_dump(mode="json")
    placebo = next(
        item for item in payload["arms"] if item["role"] == ArmRole.LENGTH_MATCHED_PLACEBO.value
    )
    placebo["allowed_delta"]["allowed_transitions"][0]["feature_id"] = "safety.path_normalization"

    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        ConfirmationProtocolRecord.model_validate(payload)


def test_protocol_rejects_missing_target_or_noop_arm_and_family_role_mismatch() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    for omitted_role in (ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE):
        payload = protocol.model_dump(mode="json")
        payload["arms"] = [item for item in payload["arms"] if item["role"] != omitted_role]
        with pytest.raises(ValidationError, match="experiment contract failed validation"):
            ConfirmationProtocolRecord.model_validate(payload)

    payload = protocol.model_dump(mode="json")
    payload["arms"][0]["role"] = ArmRole.TASK_TARGET
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        ConfirmationProtocolRecord.model_validate(payload)


def test_multiplicity_family_is_target_scoped_without_protocol_digest_cycle() -> None:
    hypothesis = _hypothesis()
    add = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )
    remove = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.REMOVE, hypothesis=hypothesis),
    )

    assert len({item.multiplicity_family_id for item in add.contrasts}) == 1
    assert len({item.multiplicity_family_id for item in remove.contrasts}) == 1
    assert add.contrasts[0].multiplicity_family_id != remove.contrasts[0].multiplicity_family_id
    assert add.arm_protocol_id not in add.contrasts[0].multiplicity_family_id


def test_protocol_is_cross_task_semantic_and_has_no_instance_coordinates() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )

    assert "task_id" not in type(protocol).model_fields
    assert "source_prompt_id" not in type(protocol).model_fields
    assert "counterpart_prompt_id" not in type(protocol).model_fields


def test_arm_catalog_is_finite_and_exposes_no_runtime_registration_hook() -> None:
    public_names = set(arm_catalog.__all__)
    assert public_names == {
        "ARM_PROTOCOL_CATALOG_ID",
        "materialize_arm_protocol",
    }
    assert not any(
        "register" in name.casefold() or "plugin" in name.casefold() for name in dir(arm_catalog)
    )


def test_materializer_sanitizes_unknown_values_and_repr_has_no_raw_input() -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    secret = "raw-secret-operation"
    forged = target.model_copy(update={"operation": secret})

    with pytest.raises(ValidationError) as exc_info:
        materialize_arm_protocol(hypothesis, forged)
    assert secret not in str(exc_info.value)
    assert "raw-secret" not in repr(target)

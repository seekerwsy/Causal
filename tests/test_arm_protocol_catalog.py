from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import traceback

import pytest
from pydantic import ValidationError

from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES
from secaware.intervention import arm_catalog
from secaware.intervention.arm_catalog import materialize_arm_protocol
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PathPatternRecord,
)
from secaware.schema.experiments import (
    ArmRole,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    PromptRole,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation, FeatureState
from secaware.schema.causal import EndpointMark
import secaware.schema.experiments as experiment_schema
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)


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


def _alternative_contract() -> FunctionalOutcomeContractRecord:
    return FunctionalOutcomeContractRecord.from_content(
        task_feature_id="task.database_query",
        outcome_id="y_task_database_alternative",
        expected_add_sign="two_sided",
        expected_remove_sign="two_sided",
        generic_control_feature_id="task.file_read",
        evaluator_policy_sha256=SHA_B,
    )


def _content_authenticated_unsafe_target(
    hypothesis: FrozenHypothesisRecord,
    feature_id: str,
    operation: FeatureOperation,
) -> TargetSpecRecord:
    selected = next(item for item in hypothesis.expected_contrasts if item.operation is operation)
    content = {
        "schema_version": "1.0",
        "hypothesis_id": hypothesis.hypothesis_id,
        "frozen_hypothesis_sha256": hypothesis.hypothesis_sha256,
        "feature_family": hypothesis.feature_family.value,
        "feature_id": feature_id,
        "operation": operation.value,
        "hypothesis_outcome_variable_id": hypothesis.outcome_variable_id,
        "hypothesis_outcome_estimand_id": selected.outcome_estimand_id,
        "expected_hypothesis_contrast_sign": selected.expected_sign,
    }
    python_content = {
        **content,
        "feature_family": hypothesis.feature_family,
        "operation": operation,
    }
    return TargetSpecRecord.model_construct(
        **python_content,
        target_spec_id=f"target_{canonical_sha256(content)}",
    )


def _assert_secret_absent_from_exception(exc: BaseException, secret: str) -> None:
    assert secret not in str(exc)
    assert secret not in repr(exc)
    assert secret not in "".join(traceback.format_exception(exc))

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        assert secret not in str(current)
        assert secret not in repr(current)
        assert secret not in "".join(traceback.format_exception(current))
        trace = current.__traceback__
        while trace is not None:
            filename = Path(trace.tb_frame.f_code.co_filename).as_posix()
            if "/src/secaware/" in filename.casefold():
                for value in trace.tb_frame.f_locals.values():
                    assert not _contains_secret(value, secret, set())
            trace = trace.tb_next
        current = current.__cause__ or current.__context__


def _contains_secret(value: object, secret: str, seen: set[int]) -> bool:
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, str):
        return secret in value
    if isinstance(value, dict):
        return any(
            _contains_secret(key, secret, seen) or _contains_secret(item, secret, seen)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_contains_secret(item, secret, seen) for item in value)
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        return any(_contains_secret(getattr(value, field, None), secret, seen) for field in fields)
    return secret in repr(value)


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


def test_confirmation_targetability_is_a_closed_m5_gate_over_the_full_catalog() -> None:
    targetable = tuple(
        item.feature_id
        for item in PROMPT_FEATURE_CATALOG
        if item.intervenable and item.feature_id != "safety.generic_security_reminder"
    )
    assert experiment_schema.CONFIRMATION_TARGET_FEATURE_IDS == targetable
    assert experiment_schema.CONFIRMATION_CONTROL_ONLY_FEATURE_IDS == (
        "safety.generic_security_reminder",
    )

    for spec in PROMPT_FEATURE_CATALOG:
        for operation in FeatureOperation:
            expected = spec.feature_id in targetable and operation in spec.operations
            assert (
                experiment_schema.is_confirmation_target_feature(spec.feature_id, operation)
                is expected
            )
            hypothesis = _hypothesis(spec.feature_id, spec.feature_family)
            if expected:
                target = _target(spec.feature_id, operation, hypothesis=hypothesis)
                assert target.feature_id == spec.feature_id
                assert target.operation is operation
            else:
                with pytest.raises(
                    ValidationError,
                    match="experiment contract failed validation",
                ):
                    _target(spec.feature_id, operation, hypothesis=hypothesis)


def test_generic_security_reminder_stays_observable_and_arm_only_not_a_target() -> None:
    # M4B intentionally keeps this unified Prompt variable observable. M5 alone
    # prevents it from becoming a target while retaining it as a finite arm control.
    assert "x.safety.generic_security_reminder" in {
        item.variable_id for item in PROMPT_CAUSAL_VARIABLES
    }
    assert prompt_feature_spec("safety.generic_security_reminder").intervention_clauses == (
        " Follow security best practices.",
    )
    hypothesis = _hypothesis(
        "safety.generic_security_reminder",
        FeatureFamily.SAFETY_CONTROL,
    )
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        _target(
            "safety.generic_security_reminder",
            FeatureOperation.ADD,
            hypothesis=hypothesis,
        )

    forged = _content_authenticated_unsafe_target(
        hypothesis,
        "safety.generic_security_reminder",
        FeatureOperation.ADD,
    )
    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, forged)

    ordinary = _hypothesis()
    protocol = materialize_arm_protocol(
        ordinary,
        _target(
            "safety.path_normalization",
            FeatureOperation.ADD,
            hypothesis=ordinary,
        ),
    )
    control = _arm(protocol, ArmRole.GENERIC_SECURITY_REMINDER)
    assert tuple(item.feature_id for item in control.allowed_delta.allowed_transitions) == (
        "safety.generic_security_reminder",
    )


@pytest.mark.parametrize(
    ("operation", "role"),
    (
        (FeatureOperation.ADD, ArmRole.GENERIC_SECURITY_REMINDER),
        (FeatureOperation.REMOVE, ArmRole.GENERIC_SECURITY_REPLACEMENT),
    ),
)
def test_safety_add_and_remove_protocols_keep_catalog_owned_generic_control(
    operation: FeatureOperation,
    role: ArmRole,
) -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", operation, hypothesis=hypothesis),
    )

    assert "safety.generic_security_reminder" in {
        item.feature_id for item in _arm(protocol, role).allowed_delta.allowed_transitions
    }


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


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
@pytest.mark.parametrize("with_contract", (False, True))
def test_task_placebo_contrast_uses_contract_outcome_or_explicit_fallback(
    operation: FeatureOperation,
    with_contract: bool,
) -> None:
    hypothesis = _hypothesis("task.database_query", FeatureFamily.TASK_FUNCTION)
    target = _target("task.database_query", operation, hypothesis=hypothesis)
    contract = _contract(generic=False) if with_contract else None
    protocol = materialize_arm_protocol(
        hypothesis,
        target,
        functional_contract=contract,
    )
    placebo = next(
        item for item in protocol.contrasts if item.arm_contrast_id.endswith(".placebo_minus_noop")
    )
    assert placebo.outcome_id == (
        contract.outcome_id if contract is not None else "y_secure_functional"
    )
    assert placebo.priority == "diagnostic"
    assert placebo.expected_sign == "null"

    target_noop_checks = {
        item.outcome_id: (item.priority, item.expected_sign)
        for item in protocol.contrasts
        if item.arm_contrast_id.endswith(".target_minus_noop")
        and item.outcome_id
        in {
            "y_secure_functional",
            "y_cwe_secure",
            "y_cwe_insecure",
            "y_cwe_unknown",
        }
    }
    assert target_noop_checks == {
        "y_secure_functional": ("secondary", "two_sided"),
        "y_cwe_secure": ("secondary", "two_sided"),
        "y_cwe_insecure": ("diagnostic", "two_sided"),
        "y_cwe_unknown": ("diagnostic", "two_sided"),
    }


def test_task_contract_for_another_feature_or_unknown_generic_fails_closed() -> None:
    hypothesis = _hypothesis("task.file_read", FeatureFamily.TASK_FUNCTION)
    target = _target("task.file_read", FeatureOperation.ADD, hypothesis=hypothesis)

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, target, functional_contract=_contract())

    payload = _contract().model_dump(mode="json", exclude={"contract_id"})
    payload["generic_control_feature_id"] = "task.runtime_injected"
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        FunctionalOutcomeContractRecord.from_content(**payload)


def test_cross_record_revalidator_rejects_content_addressed_contract_swap() -> None:
    hypothesis = _hypothesis("task.database_query", FeatureFamily.TASK_FUNCTION)
    target = _target("task.database_query", FeatureOperation.ADD, hypothesis=hypothesis)
    contract_a = _contract()
    contract_b = _alternative_contract()
    protocol_a = materialize_arm_protocol(
        hypothesis,
        target,
        functional_contract=contract_a,
    )
    forged_content = protocol_a.model_dump(
        mode="python",
        exclude={"arm_protocol_id", "contrast_set_sha256"},
    )
    forged_content["functional_outcome_contract_id"] = contract_b.contract_id
    locally_valid_forgery = ConfirmationProtocolRecord.from_content(**forged_content)

    assert locally_valid_forgery.functional_outcome_contract_id == contract_b.contract_id
    for supplied_contract in (contract_a, contract_b):
        with pytest.raises(ValidationError, match="arm protocol revalidation failed"):
            arm_catalog.revalidate_arm_protocol(
                locally_valid_forgery,
                target,
                functional_contract=supplied_contract,
            )


def test_cross_record_revalidator_requires_exact_target_and_contract_presence() -> None:
    hypothesis = _hypothesis("task.database_query", FeatureFamily.TASK_FUNCTION)
    add_target = _target("task.database_query", FeatureOperation.ADD, hypothesis=hypothesis)
    remove_target = _target("task.database_query", FeatureOperation.REMOVE, hypothesis=hypothesis)
    contract = _contract()
    protocol = materialize_arm_protocol(
        hypothesis,
        add_target,
        functional_contract=contract,
    )

    assert (
        arm_catalog.revalidate_arm_protocol(
            protocol,
            add_target,
            functional_contract=contract,
        )
        == protocol
    )
    for wrong_target, supplied_contract in (
        (add_target, None),
        (remove_target, contract),
    ):
        with pytest.raises(ValidationError, match="arm protocol revalidation failed"):
            arm_catalog.revalidate_arm_protocol(
                protocol,
                wrong_target,
                functional_contract=supplied_contract,
            )

    safety_hypothesis = _hypothesis()
    safety_target = _target(
        "safety.path_normalization",
        FeatureOperation.ADD,
        hypothesis=safety_hypothesis,
    )
    safety_protocol = materialize_arm_protocol(safety_hypothesis, safety_target)
    with pytest.raises(ValidationError, match="arm protocol revalidation failed"):
        arm_catalog.revalidate_arm_protocol(
            safety_protocol,
            safety_target,
            functional_contract=contract,
        )


def test_materializer_runs_public_cross_record_revalidation(monkeypatch) -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    calls: list[tuple[object, object, object]] = []
    original = arm_catalog.revalidate_arm_protocol

    def observed(protocol, supplied_target, functional_contract=None):
        calls.append((protocol, supplied_target, functional_contract))
        return original(protocol, supplied_target, functional_contract=functional_contract)

    monkeypatch.setattr(arm_catalog, "revalidate_arm_protocol", observed)
    protocol = materialize_arm_protocol(hypothesis, target)

    assert calls == [(protocol, target, None)]


def test_materializer_preserves_revalidation_memory_error_identity(monkeypatch) -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    error = MemoryError("memory-revalidate")

    def fail_revalidation(_value):
        raise error

    monkeypatch.setattr(arm_catalog, "revalidate_frozen_hypothesis", fail_revalidation)
    with pytest.raises(MemoryError) as exc_info:
        materialize_arm_protocol(hypothesis, target)
    assert exc_info.value is error


def test_public_revalidator_preserves_catalog_memory_error_identity(monkeypatch) -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    protocol = materialize_arm_protocol(hypothesis, target)
    error = MemoryError("memory-catalog")

    def fail_catalog_lookup(_feature_id):
        raise error

    monkeypatch.setattr(arm_catalog, "prompt_feature_spec", fail_catalog_lookup)
    with pytest.raises(MemoryError) as exc_info:
        arm_catalog.revalidate_arm_protocol(protocol, target)
    assert exc_info.value is error


def test_arm_catalog_has_no_second_presentation_match_authority() -> None:
    assert not hasattr(arm_catalog, "_PRESENTATION_MATCH")


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
    hypothesis = _hypothesis(feature_id, family)
    selected = next(item for item in hypothesis.expected_contrasts if item.operation is operation)
    with pytest.raises(ValidationError, match="experiment contract failed validation"):
        TargetSpecRecord.from_content(
            hypothesis_id=hypothesis.hypothesis_id,
            frozen_hypothesis_sha256=hypothesis.hypothesis_sha256,
            feature_family=family,
            feature_id=feature_id,
            operation=operation,
            hypothesis_outcome_variable_id=hypothesis.outcome_variable_id,
            hypothesis_outcome_estimand_id=selected.outcome_estimand_id,
            expected_hypothesis_contrast_sign=selected.expected_sign,
        )

    forged = _content_authenticated_unsafe_target(hypothesis, feature_id, operation)

    with pytest.raises(ValidationError, match="arm protocol materialization failed"):
        materialize_arm_protocol(hypothesis, forged)


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


def test_public_target_feature_api_reads_the_single_target_transition() -> None:
    hypothesis = _hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis),
    )

    assert arm_catalog.target_feature_from_protocol(protocol) == "safety.path_normalization"


def test_arm_catalog_is_finite_and_exposes_no_runtime_registration_hook() -> None:
    public_names = set(arm_catalog.__all__)
    assert public_names == {
        "ARM_PROTOCOL_CATALOG_ID",
        "CONFIRMATION_CONTROL_ONLY_FEATURE_IDS",
        "CONFIRMATION_TARGET_FEATURE_IDS",
        "is_confirmation_target_feature",
        "materialize_arm_protocol",
        "materialize_safety_arm_specs",
        "revalidate_arm_protocol",
        "target_feature_from_protocol",
    }
    assert not any(
        "register" in name.casefold() or "plugin" in name.casefold() for name in dir(arm_catalog)
    )


def test_materializer_sanitizes_forged_model_repr_traceback_and_frame_locals() -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    secret = "raw-secret-operation"
    forged = target.model_copy(update={"operation": secret})

    with pytest.raises(ValidationError) as exc_info:
        materialize_arm_protocol(hypothesis, forged)
    assert secret not in repr(forged)
    assert secret not in str(forged)
    _assert_secret_absent_from_exception(exc_info.value, secret)


def test_from_content_sanitizes_traceback_chain_and_frame_locals() -> None:
    secret = "raw-secret-hypothesis"
    with pytest.raises(ValidationError) as exc_info:
        TargetSpecRecord.from_content(
            hypothesis_id=secret,
            frozen_hypothesis_sha256=SHA_A,
            feature_family=FeatureFamily.SAFETY_CONTROL,
            feature_id="safety.path_normalization",
            operation=FeatureOperation.ADD,
            hypothesis_outcome_variable_id="y.secure_functional",
            hypothesis_outcome_estimand_id="y_secure_functional",
            expected_hypothesis_contrast_sign="positive",
        )
    _assert_secret_absent_from_exception(exc_info.value, secret)


@pytest.mark.parametrize(
    "record_kind",
    (
        "target_spec",
        "target_instance",
        "protocol",
        "protocol_instance",
        "functional_contract",
    ),
)
def test_every_content_addressed_factory_clears_secret_frame_locals(
    record_kind: str,
) -> None:
    secret = f"raw-secret-{record_kind}"
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
    protocol = materialize_arm_protocol(hypothesis, target)
    target_instance = TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id="task-safe",
        source_prompt_id="prompt-safe",
        source_prompt_sha256=SHA_A,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_required=False,
    )

    def invoke() -> None:
        if record_kind == "target_spec":
            payload = target.model_dump(mode="python", exclude={"target_spec_id"})
            payload["hypothesis_id"] = secret
            TargetSpecRecord.from_content(**payload)
        elif record_kind == "target_instance":
            payload = target_instance.model_dump(mode="python", exclude={"target_instance_id"})
            payload["task_id"] = f"{secret}\n"
            TargetInstanceRecord.from_content(**payload)
        elif record_kind == "protocol":
            payload = protocol.model_dump(
                mode="python",
                exclude={"arm_protocol_id", "contrast_set_sha256"},
            )
            payload["hypothesis_id"] = secret
            ConfirmationProtocolRecord.from_content(**payload)
        elif record_kind == "protocol_instance":
            instance = ConfirmationProtocolInstanceRecord.from_content(
                arm_protocol_id=protocol.arm_protocol_id,
                target_instance_id=target_instance.target_instance_id,
                task_id="task-safe",
                source_prompt_id="prompt-safe",
                source_prompt_sha256=SHA_A,
                counterpart_prompt_id=None,
                counterpart_prompt_sha256=None,
            )
            payload = instance.model_dump(mode="python", exclude={"protocol_instance_id"})
            payload["task_id"] = f"{secret}\n"
            ConfirmationProtocolInstanceRecord.from_content(**payload)
        else:
            payload = _contract().model_dump(mode="python", exclude={"contract_id"})
            payload["task_feature_id"] = f"task.{secret}"
            FunctionalOutcomeContractRecord.from_content(**payload)

    with pytest.raises(ValidationError) as exc_info:
        invoke()
    _assert_secret_absent_from_exception(exc_info.value, secret)


@pytest.mark.parametrize("forged_kind", ("hypothesis", "target", "contract"))
def test_materializer_clears_every_forged_input_from_traceback_locals(
    forged_kind: str,
) -> None:
    secret = f"raw-secret-{forged_kind}"
    if forged_kind == "contract":
        hypothesis = _hypothesis("task.database_query", FeatureFamily.TASK_FUNCTION)
        target = _target("task.database_query", FeatureOperation.ADD, hypothesis=hypothesis)
        contract = _contract().model_copy(update={"task_feature_id": f"task.{secret}"})
    else:
        hypothesis = _hypothesis()
        target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)
        contract = None
        if forged_kind == "hypothesis":
            hypothesis = hypothesis.model_copy(update={"model_id": secret})
        else:
            target = target.model_copy(update={"operation": secret})

    with pytest.raises(ValidationError) as exc_info:
        materialize_arm_protocol(
            hypothesis,
            target,
            functional_contract=contract,
        )
    _assert_secret_absent_from_exception(exc_info.value, secret)


@pytest.mark.parametrize("interrupt", (KeyboardInterrupt, SystemExit))
def test_materializer_preserves_process_interrupts(monkeypatch, interrupt) -> None:
    hypothesis = _hypothesis()
    target = _target("safety.path_normalization", FeatureOperation.ADD, hypothesis=hypothesis)

    def raise_interrupt(_value):
        raise interrupt

    monkeypatch.setattr(arm_catalog, "revalidate_frozen_hypothesis", raise_interrupt)
    with pytest.raises(interrupt):
        materialize_arm_protocol(hypothesis, target)

"""Finite family/operation confirmation-arm and contrast materializer."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, NoReturn

from secaware.causal.freeze import revalidate_frozen_hypothesis
from secaware.schema.common import _sanitized_validation_error
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    AllowedDeltaRecord as _AllowedDelta,
    ArmRole as _ArmRole,
    ArmSpecRecord as _ArmSpec,
    CONFIRMATION_CONTROL_ONLY_FEATURE_IDS,
    CONFIRMATION_TARGET_FEATURE_IDS,
    ConfirmationProtocolRecord as _Protocol,
    FeatureFamily as _Family,
    FeatureOperation as _Operation,
    FeatureState as _State,
    FeatureTransition as _Transition,
    FunctionalOutcomeContractRecord as _FunctionalContract,
    PreRegisteredContrastSpec as _ContrastSpec,
    TargetSpecRecord as _TargetSpec,
    is_confirmation_target_feature,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG as _FEATURES
from secaware.tsg.feature_catalog import prompt_feature_spec


ARM_PROTOCOL_CATALOG_ID = "arm-protocol-catalog-v1"
_CONTRAST_CATALOG_ID = "confirmation-contrast-catalog-v1"
_FAMILY_ORDER = {family: index for index, family in enumerate(_Family)}
_OUTCOME_SOURCE = {
    "y_secure_functional": "y.secure_functional",
    "y_cwe_secure": "y.cwe_security",
    "y_cwe_insecure": "y.cwe_security",
    "y_cwe_unknown": "y.cwe_security",
    "y_oracle_evaluable": "y.oracle_evaluable",
    "y_parse_ok": "y.parse_ok",
    "y_functional_ok": "y.functional_ok",
}


def _raise_materialization_error() -> NoReturn:
    """Raise from a frame that never receives prompt-derived values."""
    raise _sanitized_validation_error(
        "ConfirmationProtocolRecord",
        "arm protocol materialization failed",
    )


def _raise_protocol_revalidation_error() -> NoReturn:
    """Raise from a frame that never receives protocol or contract values."""
    raise _sanitized_validation_error(
        "ConfirmationProtocolRecord",
        "arm protocol revalidation failed",
    )


def _transition(feature_id: str, operation: _Operation) -> _Transition:
    if operation is _Operation.ADD:
        source, destination = _State.ABSENT, _State.PRESENT
    else:
        source, destination = _State.PRESENT, _State.ABSENT
    return _Transition(
        feature_id=feature_id,
        from_states=(source,),
        to_states=(destination,),
    )


def _fixed_ids(
    allowed_feature_ids: Sequence[str],
    fixed_families: Sequence[_Family],
) -> tuple[str, ...]:
    allowed = set(allowed_feature_ids)
    fixed = set(fixed_families)
    return tuple(
        sorted(
            item.feature_id
            for item in _FEATURES
            if item.feature_family not in fixed and item.feature_id not in allowed
        )
    )


def _delta(
    transitions: Sequence[_Transition] = (),
    *,
    fixed_families: Sequence[_Family],
) -> _AllowedDelta:
    ordered_transitions = tuple(sorted(transitions, key=lambda item: item.feature_id))
    ordered_families = tuple(sorted(fixed_families, key=lambda item: _FAMILY_ORDER[item]))
    return _AllowedDelta(
        allowed_transitions=ordered_transitions,
        fixed_families=ordered_families,
        fixed_feature_ids=_fixed_ids(
            tuple(item.feature_id for item in ordered_transitions),
            ordered_families,
        ),
    )


def _arm(role: _ArmRole, delta: _AllowedDelta) -> _ArmSpec:
    return _ArmSpec(role=role, allowed_delta=delta)


def _safety_arms(feature_id: str, operation: _Operation) -> tuple[_ArmSpec, ...]:
    if operation is _Operation.ADD:
        return (
            _arm(
                _ArmRole.TARGET_PATCH,
                _delta(
                    (_transition(feature_id, operation),),
                    fixed_families=(_Family.TASK_FUNCTION, _Family.PRESENTATION_CONTROL),
                ),
            ),
            _arm(
                _ArmRole.NOOP_REWRITE,
                _delta(fixed_families=tuple(_Family)),
            ),
            _arm(
                _ArmRole.LENGTH_MATCHED_PLACEBO,
                _delta(
                    (_transition("presentation.length_matched_placebo", _Operation.ADD),),
                    fixed_families=(_Family.TASK_FUNCTION, _Family.SAFETY_CONTROL),
                ),
            ),
            _arm(
                _ArmRole.GENERIC_SECURITY_REMINDER,
                _delta(
                    (_transition("safety.generic_security_reminder", _Operation.ADD),),
                    fixed_families=(_Family.TASK_FUNCTION, _Family.PRESENTATION_CONTROL),
                ),
            ),
        )
    return (
        _arm(
            _ArmRole.TARGET_REMOVE,
            _delta(
                (_transition(feature_id, operation),),
                fixed_families=(_Family.TASK_FUNCTION, _Family.PRESENTATION_CONTROL),
            ),
        ),
        _arm(
            _ArmRole.NOOP_RETAIN,
            _delta(fixed_families=tuple(_Family)),
        ),
        _arm(
            _ArmRole.LENGTH_MATCHED_SHAM_EDIT,
            _delta(
                (_transition("presentation.sham_edit", _Operation.ADD),),
                fixed_families=(_Family.TASK_FUNCTION, _Family.SAFETY_CONTROL),
            ),
        ),
        _arm(
            _ArmRole.GENERIC_SECURITY_REPLACEMENT,
            _delta(
                (
                    _transition(feature_id, _Operation.REMOVE),
                    _transition("safety.generic_security_reminder", _Operation.ADD),
                ),
                fixed_families=(_Family.TASK_FUNCTION, _Family.PRESENTATION_CONTROL),
            ),
        ),
    )


def materialize_safety_arm_specs(
    feature_id: str,
    operation: _Operation,
) -> tuple[_ArmSpec, ...]:
    """Materialize the finite safety-arm deltas without requiring a frozen hypothesis.

    Exploratory prompt construction needs the same reviewed arm semantics as confirmation, but it
    occurs before a hypothesis exists. This narrow interface exposes only the existing finite
    safety arm catalog; it does not materialize contrasts or a confirmation protocol.
    """

    result: tuple[_ArmSpec, ...] = ()
    failed = False
    try:
        if type(feature_id) is not str or type(operation) is not _Operation:
            raise ValueError
        spec = prompt_feature_spec(feature_id)
        if (
            spec.feature_family is not _Family.SAFETY_CONTROL
            or not spec.intervenable
            or operation not in spec.operations
            or not is_confirmation_target_feature(feature_id, operation)
        ):
            raise ValueError
        result = tuple(
            _ArmSpec.model_validate(item.model_dump(mode="python"))
            for item in _safety_arms(feature_id, operation)
        )
        expected = 4
        if len(result) != expected or len({item.role for item in result}) != expected:
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    if failed:
        result = ()
        _raise_materialization_error()
    return result


def _task_arms(
    feature_id: str,
    operation: _Operation,
    generic_feature_id: str | None,
) -> tuple[_ArmSpec, ...]:
    result = [
        _arm(
            _ArmRole.TASK_TARGET,
            _delta(
                (_transition(feature_id, operation),),
                fixed_families=(_Family.SAFETY_CONTROL, _Family.PRESENTATION_CONTROL),
            ),
        ),
        _arm(_ArmRole.TASK_NOOP, _delta(fixed_families=tuple(_Family))),
        _arm(
            _ArmRole.TASK_LENGTH_PLACEBO,
            _delta(
                (_transition("presentation.length_matched_placebo", _Operation.ADD),),
                fixed_families=(_Family.TASK_FUNCTION, _Family.SAFETY_CONTROL),
            ),
        ),
    ]
    if generic_feature_id is not None:
        result.append(
            _arm(
                _ArmRole.TASK_GENERIC_CONTROL,
                _delta(
                    (_transition(generic_feature_id, _Operation.ADD),),
                    fixed_families=(_Family.SAFETY_CONTROL, _Family.PRESENTATION_CONTROL),
                ),
            )
        )
    return tuple(result)


def _presentation_arms(feature_id: str, operation: _Operation) -> tuple[_ArmSpec, ...]:
    result = [
        _arm(
            _ArmRole.PRESENTATION_TARGET,
            _delta(
                (_transition(feature_id, operation),),
                fixed_families=(_Family.TASK_FUNCTION, _Family.SAFETY_CONTROL),
            ),
        ),
        _arm(
            _ArmRole.PRESENTATION_NOOP,
            _delta(fixed_families=tuple(_Family)),
        ),
    ]
    matched = prompt_feature_spec(feature_id).matched_control_feature_id
    if matched is not None:
        result.append(
            _arm(
                _ArmRole.PRESENTATION_MATCHED_CONTROL,
                _delta(
                    (_transition(matched, _Operation.ADD),),
                    fixed_families=(_Family.TASK_FUNCTION, _Family.SAFETY_CONTROL),
                ),
            )
        )
    return tuple(result)


def _multiplicity_family(target: _TargetSpec) -> str:
    from secaware.pipeline.artifact import canonical_sha256

    return "multiplicity_" + canonical_sha256(
        {
            "schema_version": "1.0",
            "target_spec_id": target.target_spec_id,
            "frozen_hypothesis_sha256": target.frozen_hypothesis_sha256,
            "operation": target.operation.value,
            "contrast_catalog_id": _CONTRAST_CATALOG_ID,
        }
    )


def _source_for(outcome_id: str) -> str:
    return _OUTCOME_SOURCE.get(outcome_id, outcome_id.replace("y_", "y.", 1))


def _contrast(
    *,
    arm_contrast_id: str,
    treatment: _ArmRole,
    control: _ArmRole,
    outcome_id: str,
    priority: Literal["primary", "secondary", "diagnostic"],
    expected_sign: Literal["positive", "negative", "null", "two_sided"],
    multiplicity_family_id: str,
) -> _ContrastSpec:
    return _ContrastSpec(
        contrast_id=f"{arm_contrast_id}.{outcome_id}",
        arm_contrast_id=arm_contrast_id,
        treatment_arm=treatment,
        control_arm=control,
        source_outcome_variable_id=_source_for(outcome_id),
        outcome_id=outcome_id,
        priority=priority,
        expected_sign=expected_sign,
        multiplicity_family_id=multiplicity_family_id,
    )


def _safety_contrasts(target: _TargetSpec) -> tuple[_ContrastSpec, ...]:
    add = target.operation is _Operation.ADD
    prefix = "safety_add" if add else "safety_remove"
    target_role = _ArmRole.TARGET_PATCH if add else _ArmRole.TARGET_REMOVE
    noop_role = _ArmRole.NOOP_REWRITE if add else _ArmRole.NOOP_RETAIN
    placebo_role = _ArmRole.LENGTH_MATCHED_PLACEBO if add else _ArmRole.LENGTH_MATCHED_SHAM_EDIT
    generic_role = (
        _ArmRole.GENERIC_SECURITY_REMINDER if add else _ArmRole.GENERIC_SECURITY_REPLACEMENT
    )
    placebo_name = "placebo" if add else "sham"
    primary_sign: Literal["positive", "negative"] = "positive" if add else "negative"
    family_id = _multiplicity_family(target)
    templates = (
        ("target_minus_noop", target_role, noop_role, "primary", primary_sign),
        (
            f"target_minus_{placebo_name}",
            target_role,
            placebo_role,
            "secondary",
            primary_sign,
        ),
        (
            "target_minus_generic",
            target_role,
            generic_role,
            "secondary",
            "two_sided" if add else "negative",
        ),
        ("generic_minus_noop", generic_role, noop_role, "diagnostic", "two_sided"),
        (f"{placebo_name}_minus_noop", placebo_role, noop_role, "diagnostic", "null"),
    )
    result = [
        _contrast(
            arm_contrast_id=f"{prefix}.{name}",
            treatment=treatment,
            control=control,
            outcome_id="y_secure_functional",
            priority=priority,
            expected_sign=sign,
            multiplicity_family_id=family_id,
        )
        for name, treatment, control, priority, sign in templates
    ]
    extra = (
        ("y_cwe_secure", "secondary", primary_sign),
        (
            "y_cwe_insecure",
            "secondary",
            "negative" if add else "positive",
        ),
        ("y_cwe_unknown", "diagnostic", "two_sided"),
        ("y_oracle_evaluable", "diagnostic", "two_sided"),
        ("y_parse_ok", "diagnostic", "two_sided"),
        ("y_functional_ok", "diagnostic", "two_sided"),
    )
    result.extend(
        _contrast(
            arm_contrast_id=f"{prefix}.target_minus_noop",
            treatment=target_role,
            control=noop_role,
            outcome_id=outcome,
            priority=priority,
            expected_sign=sign,
            multiplicity_family_id=family_id,
        )
        for outcome, priority, sign in extra
    )
    return tuple(result)


def _task_contrasts(
    target: _TargetSpec,
    *,
    functional_outcome_id: str | None,
    functional_sign: Literal["positive", "negative", "two_sided"] | None,
    generic_present: bool,
) -> tuple[_ContrastSpec, ...]:
    prefix = f"task_{target.operation.value}"
    family_id = _multiplicity_family(target)
    result: list[_ContrastSpec] = []
    if functional_outcome_id is not None and functional_sign is not None:
        result.extend(
            (
                _contrast(
                    arm_contrast_id=f"{prefix}.target_minus_noop",
                    treatment=_ArmRole.TASK_TARGET,
                    control=_ArmRole.TASK_NOOP,
                    outcome_id=functional_outcome_id,
                    priority="primary",
                    expected_sign=functional_sign,
                    multiplicity_family_id=family_id,
                ),
                _contrast(
                    arm_contrast_id=f"{prefix}.target_minus_placebo",
                    treatment=_ArmRole.TASK_TARGET,
                    control=_ArmRole.TASK_LENGTH_PLACEBO,
                    outcome_id=functional_outcome_id,
                    priority="secondary",
                    expected_sign=functional_sign,
                    multiplicity_family_id=family_id,
                ),
            )
        )
        if generic_present:
            result.extend(
                (
                    _contrast(
                        arm_contrast_id=f"{prefix}.target_minus_generic",
                        treatment=_ArmRole.TASK_TARGET,
                        control=_ArmRole.TASK_GENERIC_CONTROL,
                        outcome_id=functional_outcome_id,
                        priority="secondary",
                        expected_sign="two_sided",
                        multiplicity_family_id=family_id,
                    ),
                    _contrast(
                        arm_contrast_id=f"{prefix}.generic_minus_noop",
                        treatment=_ArmRole.TASK_GENERIC_CONTROL,
                        control=_ArmRole.TASK_NOOP,
                        outcome_id=functional_outcome_id,
                        priority="diagnostic",
                        expected_sign="two_sided",
                        multiplicity_family_id=family_id,
                    ),
                )
            )
    placebo_outcome_id = functional_outcome_id or "y_secure_functional"
    result.append(
        _contrast(
            arm_contrast_id=f"{prefix}.placebo_minus_noop",
            treatment=_ArmRole.TASK_LENGTH_PLACEBO,
            control=_ArmRole.TASK_NOOP,
            outcome_id=placebo_outcome_id,
            priority="diagnostic",
            expected_sign="null",
            multiplicity_family_id=family_id,
        )
    )
    checks = (
        ("y_secure_functional", "secondary"),
        ("y_cwe_secure", "secondary"),
        ("y_cwe_insecure", "diagnostic"),
        ("y_cwe_unknown", "diagnostic"),
    )
    result.extend(
        _contrast(
            arm_contrast_id=f"{prefix}.target_minus_noop",
            treatment=_ArmRole.TASK_TARGET,
            control=_ArmRole.TASK_NOOP,
            outcome_id=outcome,
            priority=priority,
            expected_sign="two_sided",
            multiplicity_family_id=family_id,
        )
        for outcome, priority in checks
    )
    return tuple(result)


def _presentation_contrasts(
    target: _TargetSpec,
    *,
    matched_present: bool,
) -> tuple[_ContrastSpec, ...]:
    prefix = f"presentation_{target.operation.value}"
    family_id = _multiplicity_family(target)
    result = [
        _contrast(
            arm_contrast_id=f"{prefix}.target_minus_noop",
            treatment=_ArmRole.PRESENTATION_TARGET,
            control=_ArmRole.PRESENTATION_NOOP,
            outcome_id=outcome,
            priority=priority,
            expected_sign="null",
            multiplicity_family_id=family_id,
        )
        for outcome, priority in (
            ("y_secure_functional", "secondary"),
            ("y_cwe_secure", "secondary"),
            ("y_cwe_insecure", "diagnostic"),
            ("y_cwe_unknown", "diagnostic"),
        )
    ]
    if matched_present:
        result.extend(
            (
                _contrast(
                    arm_contrast_id=f"{prefix}.target_minus_matched",
                    treatment=_ArmRole.PRESENTATION_TARGET,
                    control=_ArmRole.PRESENTATION_MATCHED_CONTROL,
                    outcome_id="y_secure_functional",
                    priority="secondary",
                    expected_sign="null",
                    multiplicity_family_id=family_id,
                ),
                _contrast(
                    arm_contrast_id=f"{prefix}.matched_minus_noop",
                    treatment=_ArmRole.PRESENTATION_MATCHED_CONTROL,
                    control=_ArmRole.PRESENTATION_NOOP,
                    outcome_id="y_secure_functional",
                    priority="diagnostic",
                    expected_sign="null",
                    multiplicity_family_id=family_id,
                ),
            )
        )
    return tuple(result)


def target_feature_from_protocol(protocol: _Protocol) -> str:
    target_role = {
        (_Family.SAFETY_CONTROL, _Operation.ADD): _ArmRole.TARGET_PATCH,
        (_Family.SAFETY_CONTROL, _Operation.REMOVE): _ArmRole.TARGET_REMOVE,
        (_Family.TASK_FUNCTION, _Operation.ADD): _ArmRole.TASK_TARGET,
        (_Family.TASK_FUNCTION, _Operation.REMOVE): _ArmRole.TASK_TARGET,
        (_Family.PRESENTATION_CONTROL, _Operation.ADD): _ArmRole.PRESENTATION_TARGET,
        (_Family.PRESENTATION_CONTROL, _Operation.REMOVE): _ArmRole.PRESENTATION_TARGET,
    }[(protocol.feature_family, protocol.operation)]
    arm = next(item for item in protocol.arms if item.role is target_role)
    if len(arm.allowed_delta.allowed_transitions) != 1:
        raise ValueError
    return arm.allowed_delta.allowed_transitions[0].feature_id


def _generic_task_feature(protocol: _Protocol) -> str | None:
    arms = tuple(item for item in protocol.arms if item.role is _ArmRole.TASK_GENERIC_CONTROL)
    if not arms:
        return None
    if len(arms) != 1 or len(arms[0].allowed_delta.allowed_transitions) != 1:
        raise ValueError
    return arms[0].allowed_delta.allowed_transitions[0].feature_id


def _protocol_target(protocol: _Protocol, feature_id: str) -> _TargetSpec:
    return _TargetSpec.from_content(
        hypothesis_id=protocol.hypothesis_id,
        frozen_hypothesis_sha256=protocol.frozen_hypothesis_sha256,
        feature_family=protocol.feature_family,
        feature_id=feature_id,
        operation=protocol.operation,
        hypothesis_outcome_variable_id=protocol.hypothesis_outcome_variable_id,
        hypothesis_outcome_estimand_id=protocol.hypothesis_outcome_estimand_id,
        expected_hypothesis_contrast_sign=protocol.expected_hypothesis_contrast_sign,
    )


def _validate_hypothesis_match(protocol: _Protocol) -> None:
    matches = tuple(
        item
        for item in protocol.contrasts
        if item.arm_contrast_id.endswith(".target_minus_noop")
        and item.outcome_id == protocol.hypothesis_outcome_estimand_id
    )
    if (
        len(matches) != 1
        or matches[0].source_outcome_variable_id != protocol.hypothesis_outcome_variable_id
        or matches[0].expected_sign != protocol.expected_hypothesis_contrast_sign
    ):
        raise ValueError


def _validate_materialized_protocol(protocol: _Protocol) -> None:
    """Rebuild all finite family semantics without trusting record IDs."""
    feature_id = target_feature_from_protocol(protocol)
    spec = prompt_feature_spec(feature_id)
    if (
        not spec.intervenable
        or spec.feature_family is not protocol.feature_family
        or protocol.operation not in spec.operations
    ):
        raise ValueError
    target = _protocol_target(protocol, feature_id)
    if target.target_spec_id != protocol.target_spec_id:
        raise ValueError

    if protocol.feature_family is _Family.SAFETY_CONTROL:
        expected_arms = _safety_arms(feature_id, protocol.operation)
        expected_contrasts = _safety_contrasts(target)
        if protocol.functional_outcome_contract_id is not None:
            raise ValueError
    elif protocol.feature_family is _Family.TASK_FUNCTION:
        generic = _generic_task_feature(protocol)
        if generic is not None and protocol.functional_outcome_contract_id is None:
            raise ValueError
        expected_arms = _task_arms(feature_id, protocol.operation, generic)
        functional_outcome_id: str | None = None
        functional_sign: Literal["positive", "negative", "two_sided"] | None = None
        if protocol.functional_outcome_contract_id is not None:
            primary = tuple(item for item in protocol.contrasts if item.priority == "primary")
            if len(primary) != 1:
                raise ValueError
            if primary[0].expected_sign == "null":
                raise ValueError
            functional_outcome_id = primary[0].outcome_id
            functional_sign = primary[0].expected_sign
        expected_contrasts = _task_contrasts(
            target,
            functional_outcome_id=functional_outcome_id,
            functional_sign=functional_sign,
            generic_present=generic is not None,
        )
    else:
        if protocol.functional_outcome_contract_id is not None:
            raise ValueError
        expected_arms = _presentation_arms(feature_id, protocol.operation)
        expected_contrasts = _presentation_contrasts(
            target,
            matched_present=len(expected_arms) == 3,
        )

    if protocol.arms != expected_arms or protocol.contrasts != expected_contrasts:
        raise ValueError
    _validate_hypothesis_match(protocol)


def revalidate_arm_protocol(
    protocol: _Protocol,
    target: _TargetSpec,
    functional_contract: _FunctionalContract | None = None,
) -> _Protocol:
    """Close protocol, target, and optional functional-contract provenance."""
    checked_protocol: _Protocol | None = None
    checked_target: _TargetSpec | None = None
    checked_contract: _FunctionalContract | None = None
    spec = None
    arms: tuple[_ArmSpec, ...] = ()
    contrasts: tuple[_ContrastSpec, ...] = ()
    generic: str | None = None
    functional_sign: Literal["positive", "negative", "two_sided"] | None = None
    expected: _Protocol | None = None
    result: _Protocol | None = None
    failed = False
    try:
        checked_protocol = _Protocol.model_validate(protocol)
        checked_target = _TargetSpec.model_validate(target)
        checked_contract = (
            _FunctionalContract.model_validate(functional_contract)
            if functional_contract is not None
            else None
        )
        spec = prompt_feature_spec(checked_target.feature_id)
        if (
            not is_confirmation_target_feature(
                checked_target.feature_id,
                checked_target.operation,
            )
            or spec.feature_family is not checked_target.feature_family
            or checked_target.operation not in spec.operations
            or checked_protocol.hypothesis_id != checked_target.hypothesis_id
            or checked_protocol.frozen_hypothesis_sha256 != checked_target.frozen_hypothesis_sha256
            or checked_protocol.target_spec_id != checked_target.target_spec_id
            or checked_protocol.feature_family is not checked_target.feature_family
            or checked_protocol.operation is not checked_target.operation
            or checked_protocol.hypothesis_outcome_variable_id
            != checked_target.hypothesis_outcome_variable_id
            or checked_protocol.hypothesis_outcome_estimand_id
            != checked_target.hypothesis_outcome_estimand_id
            or checked_protocol.expected_hypothesis_contrast_sign
            != checked_target.expected_hypothesis_contrast_sign
        ):
            raise ValueError

        if checked_target.feature_family is _Family.SAFETY_CONTROL:
            if (
                checked_contract is not None
                or checked_protocol.functional_outcome_contract_id is not None
            ):
                raise ValueError
            arms = _safety_arms(checked_target.feature_id, checked_target.operation)
            contrasts = _safety_contrasts(checked_target)
        elif checked_target.feature_family is _Family.TASK_FUNCTION:
            if (checked_contract is None) != (
                checked_protocol.functional_outcome_contract_id is None
            ):
                raise ValueError
            if checked_contract is not None:
                if (
                    checked_contract.contract_id != checked_protocol.functional_outcome_contract_id
                    or checked_contract.task_feature_id != checked_target.feature_id
                ):
                    raise ValueError
                generic = checked_contract.generic_control_feature_id
                functional_sign = (
                    checked_contract.expected_add_sign
                    if checked_target.operation is _Operation.ADD
                    else checked_contract.expected_remove_sign
                )
            arms = _task_arms(
                checked_target.feature_id,
                checked_target.operation,
                generic,
            )
            contrasts = _task_contrasts(
                checked_target,
                functional_outcome_id=(
                    checked_contract.outcome_id if checked_contract is not None else None
                ),
                functional_sign=functional_sign,
                generic_present=generic is not None,
            )
        else:
            if (
                checked_contract is not None
                or checked_protocol.functional_outcome_contract_id is not None
            ):
                raise ValueError
            arms = _presentation_arms(checked_target.feature_id, checked_target.operation)
            contrasts = _presentation_contrasts(
                checked_target,
                matched_present=len(arms) == 3,
            )

        expected = _Protocol.from_content(
            hypothesis_id=checked_target.hypothesis_id,
            frozen_hypothesis_sha256=checked_target.frozen_hypothesis_sha256,
            target_spec_id=checked_target.target_spec_id,
            feature_family=checked_target.feature_family,
            operation=checked_target.operation,
            arms=arms,
            hypothesis_outcome_variable_id=(checked_target.hypothesis_outcome_variable_id),
            hypothesis_outcome_estimand_id=(checked_target.hypothesis_outcome_estimand_id),
            expected_hypothesis_contrast_sign=(checked_target.expected_hypothesis_contrast_sign),
            contrasts=contrasts,
            functional_outcome_contract_id=(
                checked_contract.contract_id if checked_contract is not None else None
            ),
        )
        if checked_protocol != expected:
            raise ValueError
        result = checked_protocol
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    if failed:
        protocol = None
        target = None
        functional_contract = None
        checked_protocol = None
        checked_target = None
        checked_contract = None
        spec = None
        arms = ()
        contrasts = ()
        generic = None
        functional_sign = None
        expected = None
        result = None
        _raise_protocol_revalidation_error()
    return result


def materialize_arm_protocol(
    hypothesis: FrozenHypothesisRecord,
    target: _TargetSpec,
    functional_contract: _FunctionalContract | None = None,
) -> _Protocol:
    """Materialize one closed, pre-randomization protocol for a frozen hypothesis."""
    checked_hypothesis: FrozenHypothesisRecord | None = None
    checked_target: _TargetSpec | None = None
    checked_contract: _FunctionalContract | None = None
    spec = None
    selected: tuple[object, ...] = ()
    arms: tuple[_ArmSpec, ...] = ()
    contrasts: tuple[_ContrastSpec, ...] = ()
    generic: str | None = None
    functional_sign: Literal["positive", "negative", "two_sided"] | None = None
    result: _Protocol | None = None
    failed = False
    try:
        checked_hypothesis = revalidate_frozen_hypothesis(
            FrozenHypothesisRecord.model_validate(hypothesis)
        )
        checked_target = _TargetSpec.model_validate(target)
        checked_contract = (
            _FunctionalContract.model_validate(functional_contract)
            if functional_contract is not None
            else None
        )
        spec = prompt_feature_spec(checked_target.feature_id)
        selected = tuple(
            item
            for item in checked_hypothesis.expected_contrasts
            if item.operation is checked_target.operation
        )
        if (
            len(selected) != 1
            or not spec.intervenable
            or not is_confirmation_target_feature(
                checked_target.feature_id,
                checked_target.operation,
            )
            or checked_target.hypothesis_id != checked_hypothesis.hypothesis_id
            or checked_target.frozen_hypothesis_sha256 != checked_hypothesis.hypothesis_sha256
            or checked_target.feature_id != checked_hypothesis.target_feature_id
            or checked_target.feature_family is not checked_hypothesis.feature_family
            or checked_target.operation not in checked_hypothesis.permitted_operations
            or checked_target.hypothesis_outcome_variable_id
            != checked_hypothesis.outcome_variable_id
            or checked_target.hypothesis_outcome_estimand_id != selected[0].outcome_estimand_id
            or checked_target.expected_hypothesis_contrast_sign != selected[0].expected_sign
            or spec.feature_family is not checked_target.feature_family
            or checked_target.operation not in spec.operations
        ):
            raise ValueError

        if checked_target.feature_family is _Family.SAFETY_CONTROL:
            if checked_contract is not None:
                raise ValueError
            arms = _safety_arms(checked_target.feature_id, checked_target.operation)
            contrasts = _safety_contrasts(checked_target)
        elif checked_target.feature_family is _Family.TASK_FUNCTION:
            if (
                checked_contract is not None
                and checked_contract.task_feature_id != checked_target.feature_id
            ):
                raise ValueError
            generic = (
                checked_contract.generic_control_feature_id
                if checked_contract is not None
                else None
            )
            arms = _task_arms(checked_target.feature_id, checked_target.operation, generic)
            functional_sign = (
                checked_contract.expected_add_sign
                if checked_contract is not None and checked_target.operation is _Operation.ADD
                else checked_contract.expected_remove_sign
                if checked_contract is not None
                else None
            )
            contrasts = _task_contrasts(
                checked_target,
                functional_outcome_id=(
                    checked_contract.outcome_id if checked_contract is not None else None
                ),
                functional_sign=functional_sign,
                generic_present=generic is not None,
            )
        else:
            if checked_contract is not None:
                raise ValueError
            arms = _presentation_arms(checked_target.feature_id, checked_target.operation)
            contrasts = _presentation_contrasts(
                checked_target,
                matched_present=len(arms) == 3,
            )

        result = _Protocol.from_content(
            hypothesis_id=checked_hypothesis.hypothesis_id,
            frozen_hypothesis_sha256=checked_hypothesis.hypothesis_sha256,
            target_spec_id=checked_target.target_spec_id,
            feature_family=checked_target.feature_family,
            operation=checked_target.operation,
            arms=arms,
            hypothesis_outcome_variable_id=checked_target.hypothesis_outcome_variable_id,
            hypothesis_outcome_estimand_id=checked_target.hypothesis_outcome_estimand_id,
            expected_hypothesis_contrast_sign=(checked_target.expected_hypothesis_contrast_sign),
            contrasts=contrasts,
            functional_outcome_contract_id=(
                checked_contract.contract_id if checked_contract is not None else None
            ),
        )
        result = revalidate_arm_protocol(
            result,
            checked_target,
            functional_contract=checked_contract,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    if failed:
        hypothesis = None
        target = None
        functional_contract = None
        checked_hypothesis = None
        checked_target = None
        checked_contract = None
        spec = None
        selected = ()
        arms = ()
        contrasts = ()
        generic = None
        functional_sign = None
        result = None
        _raise_materialization_error()
    return result


__all__ = [
    "ARM_PROTOCOL_CATALOG_ID",
    "CONFIRMATION_CONTROL_ONLY_FEATURE_IDS",
    "CONFIRMATION_TARGET_FEATURE_IDS",
    "is_confirmation_target_feature",
    "materialize_arm_protocol",
    "materialize_safety_arm_specs",
    "revalidate_arm_protocol",
    "target_feature_from_protocol",
]

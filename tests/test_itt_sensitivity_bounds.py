from __future__ import annotations

import pytest

from m5_executor_fixtures import request
from secaware.analysis.itt import estimate_itt
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.experiments import (
    ArmRole,
    ConfirmationProtocolRecord,
    FeatureFamily,
    FeatureOperation,
    FunctionalOutcomeContractRecord,
)
from secaware.schema.outcomes import FunctionalOutcomeRecord, FunctionalOutcomeStatus

from test_clustered_itt import (
    _analysis_config,
    _complete_rows,
    _effect,
    _safety_protocol,
    _sha,
)


def _functional_outcomes(rows, contract, statuses=None):
    statuses = statuses or {}
    return tuple(
        FunctionalOutcomeRecord.from_content(
            assignment_id=row.assignment_id,
            contract_id=contract.contract_id,
            evaluator_policy_sha256=contract.evaluator_policy_sha256,
            status=statuses.get(row.assignment_id, FunctionalOutcomeStatus.FAIL),
            evidence_sha256=_sha(row.assignment_id, "functional-evidence"),
        )
        for row in rows
    )


def _protocol_effect(effects, protocol, contrast_id):
    return next(
        effect
        for effect in effects
        if effect.arm_protocol_id == protocol.arm_protocol_id and effect.contrast_id == contrast_id
    )


def _contract_with(**updates: object) -> FunctionalOutcomeContractRecord:
    content: dict[str, object] = {
        "task_feature_id": "task.database_query",
        "outcome_id": "y_task_database_functional",
        "expected_add_sign": "positive",
        "expected_remove_sign": "negative",
        "generic_control_feature_id": "task.input_consumption",
        "evaluator_policy_sha256": "9" * 64,
    }
    content.update(updates)
    return FunctionalOutcomeContractRecord.from_content(**content)


def _protocol_with_contract_id(
    protocol: ConfirmationProtocolRecord,
    contract: FunctionalOutcomeContractRecord,
) -> ConfirmationProtocolRecord:
    content = protocol.model_dump(
        mode="python",
        exclude={"schema_version", "arm_protocol_id", "contrast_set_sha256"},
    )
    content["functional_outcome_contract_id"] = contract.contract_id
    return ConfirmationProtocolRecord.from_content(**content)


def test_oracle_unknown_is_zero_for_point_and_flipped_only_in_binary_bounds() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(
        protocol,
        ("task-a", "task-b"),
        secure_assignments={("task-b", ArmRole.TARGET_PATCH)},
        unknown_assignments={
            ("task-a", ArmRole.TARGET_PATCH),
            ("task-b", ArmRole.NOOP_REWRITE),
        },
    )

    effects = estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    secure_functional = _effect(
        effects,
        "safety_add.target_minus_noop.y_secure_functional",
    )
    cwe_secure = _effect(effects, "safety_add.target_minus_noop.y_cwe_secure")
    cwe_insecure = _effect(effects, "safety_add.target_minus_noop.y_cwe_insecure")
    cwe_unknown = _effect(effects, "safety_add.target_minus_noop.y_cwe_unknown")

    assert secure_functional.risk_difference == pytest.approx(0.5)
    assert (secure_functional.sensitivity_low, secure_functional.sensitivity_high) == (0.0, 1.0)
    assert cwe_secure.risk_difference == pytest.approx(0.5)
    assert (cwe_secure.sensitivity_low, cwe_secure.sensitivity_high) == (0.0, 1.0)
    assert cwe_insecure.risk_difference == pytest.approx(-0.5)
    assert (cwe_insecure.sensitivity_low, cwe_insecure.sensitivity_high) == (-1.0, 0.0)
    assert cwe_unknown.risk_difference == pytest.approx(0.0)
    assert cwe_unknown.sensitivity_low == cwe_unknown.risk_difference
    assert cwe_unknown.sensitivity_high == cwe_unknown.risk_difference


def test_terminal_failure_stays_in_denominator_but_is_not_oracle_unknown_imputed() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(
        protocol,
        ("task-a", "task-b"),
        secure_assignments={("task-b", ArmRole.TARGET_PATCH)},
        terminal_assignments={("task-a", ArmRole.TARGET_PATCH)},
    )

    primary = _effect(
        estimate_itt(rows, _analysis_config(), protocols=(protocol,)),
        "safety_add.target_minus_noop.y_secure_functional",
    )

    assert primary.treatment_n == 2
    assert primary.control_n == 2
    assert primary.risk_difference == pytest.approx(0.5)
    assert primary.sensitivity_low == primary.risk_difference
    assert primary.sensitivity_high == primary.risk_difference


def test_opposite_expected_direction_is_never_confirmed() -> None:
    protocol = _safety_protocol(FeatureOperation.ADD)
    rows = _complete_rows(
        protocol,
        ("task-a", "task-b"),
        secure_assignments={
            ("task-a", ArmRole.NOOP_REWRITE),
            ("task-b", ArmRole.NOOP_REWRITE),
        },
    )

    primary = _effect(
        estimate_itt(rows, _analysis_config(), protocols=(protocol,)),
        "safety_add.target_minus_noop.y_secure_functional",
    )

    assert primary.risk_difference == -1.0
    assert primary.ci_high < 0.0
    assert primary.status == "opposite_direction"


def test_presentation_status_is_limited_to_negative_control_language() -> None:
    protocol = request(
        FeatureFamily.PRESENTATION_CONTROL,
        FeatureOperation.ADD,
    ).protocol
    consistent_rows = _complete_rows(protocol, ("task-a", "task-b"))
    shifted_rows = _complete_rows(
        protocol,
        ("task-a", "task-b"),
        secure_assignments={
            ("task-a", ArmRole.PRESENTATION_TARGET),
            ("task-b", ArmRole.PRESENTATION_TARGET),
        },
    )

    consistent = _effect(
        estimate_itt(consistent_rows, _analysis_config(), protocols=(protocol,)),
        "presentation_add.target_minus_noop.y_secure_functional",
    )
    shifted = _effect(
        estimate_itt(shifted_rows, _analysis_config(), protocols=(protocol,)),
        "presentation_add.target_minus_noop.y_secure_functional",
    )

    assert consistent.status == "negative_control_consistent"
    assert shifted.status == "negative_control_shift"
    assert {consistent.status, shifted.status} <= {
        "negative_control_consistent",
        "negative_control_shift",
        "unsupported",
    }
    assert "confirm" not in consistent.status
    assert "confirm" not in shifted.status


def test_task_custom_functional_uses_exact_independent_records_and_unknown_bounds() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = execution_request.protocol
    contract = execution_request.functional_contract
    assert contract is not None
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    target_a = next(
        row for row in rows if row.task_id == "task-a" and row.arm_role is ArmRole.TASK_TARGET
    )
    target_b = next(
        row for row in rows if row.task_id == "task-b" and row.arm_role is ArmRole.TASK_TARGET
    )
    noop_b = next(
        row for row in rows if row.task_id == "task-b" and row.arm_role is ArmRole.TASK_NOOP
    )
    functional = _functional_outcomes(
        rows,
        contract,
        {
            target_a.assignment_id: FunctionalOutcomeStatus.UNKNOWN,
            target_b.assignment_id: FunctionalOutcomeStatus.PASS,
            noop_b.assignment_id: FunctionalOutcomeStatus.UNKNOWN,
        },
    )

    primary = _effect(
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_contracts=(contract,),
            functional_outcomes=functional,
        ),
        "task_add.target_minus_noop.y_task_database_functional",
    )

    assert primary.risk_difference == pytest.approx(0.5)
    assert primary.sensitivity_low == 0.0
    assert primary.sensitivity_high == 1.0
    assert primary.status != "unsupported_missing_functional_outcome"


def test_contractless_task_protocol_estimates_reserved_oracle_outcomes() -> None:
    protocol = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=False,
    ).protocol
    rows = _complete_rows(protocol, ("task-a", "task-b"))

    effects = estimate_itt(rows, _analysis_config(), protocols=(protocol,))

    assert effects
    assert {effect.outcome_id for effect in effects} <= {
        "y_secure_functional",
        "y_cwe_secure",
        "y_cwe_insecure",
        "y_cwe_unknown",
        "y_oracle_evaluable",
        "y_parse_ok",
        "y_functional_ok",
    }
    assert all(effect.status != "unsupported_missing_functional_outcome" for effect in effects)


def test_contractless_and_contracted_task_support_is_isolated_per_protocol() -> None:
    contractless = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=False,
    ).protocol
    contracted = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    ).protocol
    rows = (
        *_complete_rows(contractless, ("task-a", "task-b")),
        *_complete_rows(contracted, ("task-a", "task-b")),
    )

    effects = estimate_itt(
        rows,
        _analysis_config(),
        protocols=(contractless, contracted),
    )

    contractless_effects = tuple(
        effect for effect in effects if effect.arm_protocol_id == contractless.arm_protocol_id
    )
    contracted_effects = tuple(
        effect for effect in effects if effect.arm_protocol_id == contracted.arm_protocol_id
    )
    assert all(
        effect.status != "unsupported_missing_functional_outcome" for effect in contractless_effects
    )
    assert all(
        effect.status == "unsupported_missing_functional_outcome" for effect in contracted_effects
    )


def test_functional_coverage_contains_only_contracted_task_assignments() -> None:
    contractless = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=False,
    ).protocol
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    contracted = execution_request.protocol
    contract = execution_request.functional_contract
    assert contract is not None
    contractless_rows = _complete_rows(contractless, ("task-a", "task-b"))
    contracted_rows = _complete_rows(contracted, ("task-a", "task-b"))

    effects = estimate_itt(
        (*contractless_rows, *contracted_rows),
        _analysis_config(),
        protocols=(contractless, contracted),
        functional_contracts=(contract,),
        functional_outcomes=_functional_outcomes(contracted_rows, contract),
    )

    assert all(effect.status != "unsupported_missing_functional_outcome" for effect in effects)


def test_safety_and_contracted_task_missing_support_statuses_do_not_leak() -> None:
    safety = _safety_protocol()
    contracted = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    ).protocol
    rows = (
        *_complete_rows(safety, ("task-a", "task-b")),
        *_complete_rows(contracted, ("task-a", "task-b")),
    )

    effects = estimate_itt(rows, _analysis_config(), protocols=(safety, contracted))

    safety_effects = tuple(
        effect for effect in effects if effect.arm_protocol_id == safety.arm_protocol_id
    )
    contracted_effects = tuple(
        effect for effect in effects if effect.arm_protocol_id == contracted.arm_protocol_id
    )
    assert all(
        effect.status != "unsupported_missing_functional_outcome" for effect in safety_effects
    )
    assert all(
        effect.status == "unsupported_missing_functional_outcome" for effect in contracted_effects
    )


def test_wholly_missing_task_functional_records_publish_explicit_unsupported_effect() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = execution_request.protocol
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    config = _analysis_config()

    primary = _effect(
        estimate_itt(rows, config, protocols=(protocol,)),
        "task_add.target_minus_noop.y_task_database_functional",
    )

    assert primary.treatment_n == 2
    assert primary.control_n == 2
    assert primary.risk_difference == 0.0
    assert primary.ci_low == primary.ci_high == 0.0
    assert primary.sensitivity_low == primary.sensitivity_high == 0.0
    assert primary.status == "unsupported_missing_functional_outcome"
    assert primary.bootstrap_manifest_sha256 == canonical_sha256(
        {
            "schema_version": "1.0",
            "state": "unsupported-not-run",
            "reason": "missing-functional-outcome",
            "effect_group": [
                primary.hypothesis_id,
                primary.target_spec_id,
                primary.arm_protocol_id,
                primary.model_id,
                primary.contrast_id,
                primary.outcome_id,
            ],
            "analysis_config": {
                "bootstrap_samples": config.bootstrap_samples,
                "percentile_method": config.percentile_method,
                "max_failed_bootstrap_fraction": config.max_failed_bootstrap_fraction,
                "ci_level": config.ci_level,
                "multiplicity_method": config.multiplicity_method,
                "min_independent_tasks": config.min_independent_tasks,
            },
            "functional_provenance": {
                "contract_ids": [protocol.functional_outcome_contract_id],
                "functional_outcome_ids": [],
            },
            "assignment_universe_sha256": primary.assignment_universe_sha256,
            "target_instance_universe_sha256": primary.target_instance_universe_sha256,
        }
    )


def test_functional_evidence_identity_changes_manifest_and_effect_not_estimate() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = execution_request.protocol
    contract = execution_request.functional_contract
    assert contract is not None
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    baseline_records = _functional_outcomes(rows, contract)
    changed_first = FunctionalOutcomeRecord.from_content(
        assignment_id=baseline_records[0].assignment_id,
        contract_id=baseline_records[0].contract_id,
        evaluator_policy_sha256=baseline_records[0].evaluator_policy_sha256,
        status=baseline_records[0].status,
        evidence_sha256="f" * 64,
    )
    changed_records = (changed_first, *baseline_records[1:])

    baseline = _protocol_effect(
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_contracts=(contract,),
            functional_outcomes=baseline_records,
        ),
        protocol,
        "task_add.target_minus_noop.y_task_database_functional",
    )
    changed = _protocol_effect(
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_contracts=(contract,),
            functional_outcomes=changed_records,
        ),
        protocol,
        "task_add.target_minus_noop.y_task_database_functional",
    )

    assert (
        changed.risk_difference,
        changed.ci_low,
        changed.ci_high,
        changed.sensitivity_low,
        changed.sensitivity_high,
        changed.status,
    ) == (
        baseline.risk_difference,
        baseline.ci_low,
        baseline.ci_high,
        baseline.sensitivity_low,
        baseline.sensitivity_high,
        baseline.status,
    )
    assert changed.assignment_universe_sha256 == baseline.assignment_universe_sha256
    assert changed.bootstrap_manifest_sha256 != baseline.bootstrap_manifest_sha256
    assert changed.effect_id != baseline.effect_id


def test_partial_extra_or_wrong_functional_provenance_fails_closed() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = execution_request.protocol
    contract = execution_request.functional_contract
    assert contract is not None
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    complete = _functional_outcomes(rows, contract)
    wrong_policy = FunctionalOutcomeRecord.from_content(
        assignment_id=complete[0].assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256="0" * 64,
        status=complete[0].status,
        evidence_sha256=complete[0].evidence_sha256,
    )
    extra = FunctionalOutcomeRecord.from_content(
        assignment_id="assignment_" + "f" * 64,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=contract.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.UNKNOWN,
        evidence_sha256="e" * 64,
    )

    invalid_sets = (
        complete[:-1],
        (*complete, extra),
        (wrong_policy, *complete[1:]),
    )
    for functional in invalid_sets:
        with pytest.raises(Exception, match="functional"):
            estimate_itt(
                rows,
                _analysis_config(),
                protocols=(protocol,),
                functional_contracts=(contract,),
                functional_outcomes=functional,
            )
    with pytest.raises(Exception, match="functional"):
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_outcomes=complete,
        )


def test_one_contracted_protocol_cannot_hide_missing_records_behind_another() -> None:
    add_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    remove_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.REMOVE,
        with_functional_contract=True,
    )
    add_contract = add_request.functional_contract
    remove_contract = remove_request.functional_contract
    assert add_contract is not None and remove_contract is not None
    add_rows = _complete_rows(add_request.protocol, ("task-a", "task-b"))
    remove_rows = _complete_rows(remove_request.protocol, ("task-a", "task-b"))
    contracts = tuple(
        {contract.contract_id: contract for contract in (add_contract, remove_contract)}.values()
    )

    with pytest.raises(Exception, match="functional"):
        estimate_itt(
            (*add_rows, *remove_rows),
            _analysis_config(),
            protocols=(add_request.protocol, remove_request.protocol),
            functional_contracts=contracts,
            functional_outcomes=_functional_outcomes(add_rows, add_contract),
        )


@pytest.mark.parametrize(
    "contract",
    (
        _contract_with(task_feature_id="task.file_read"),
        _contract_with(generic_control_feature_id="task.file_read"),
        _contract_with(expected_add_sign="two_sided"),
        _contract_with(outcome_id="y_task_database_alternative"),
    ),
)
def test_task_contract_semantics_must_match_frozen_protocol_arms_and_primary(
    contract: FunctionalOutcomeContractRecord,
) -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = _protocol_with_contract_id(execution_request.protocol, contract)
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    functional = _functional_outcomes(rows, contract)
    assert ConfirmationProtocolRecord.model_validate(protocol) == protocol

    with pytest.raises(Exception, match="functional"):
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_contracts=(contract,),
            functional_outcomes=functional,
        )


def test_unsupported_task_effect_still_validates_supplied_contract_semantics() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    contract = _contract_with(task_feature_id="task.file_read")
    protocol = _protocol_with_contract_id(execution_request.protocol, contract)
    rows = _complete_rows(protocol, ("task-a", "task-b"))

    with pytest.raises(Exception, match="functional"):
        estimate_itt(
            rows,
            _analysis_config(),
            protocols=(protocol,),
            functional_contracts=(contract,),
        )

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
import secaware.analysis.itt as itt_module
from secaware.analysis.contrasts import materialize_contrasts
from secaware.analysis.itt import ITTEstimationResult, calculate_itt, estimate_itt
from secaware.config import AnalysisConfig
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionStatus,
    FeatureFamily,
    FeatureOperation,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    EffectBootstrapDrawRecord,
    FunctionalOutcomeStatus,
)


def _sha(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()


def _config(*, samples: int = 8, min_tasks: int = 2) -> AnalysisConfig:
    return AnalysisConfig(
        bootstrap_samples=samples,
        percentile_method="linear-v1",
        max_failed_bootstrap_fraction=0.1,
        ci_level=0.95,
        multiplicity_method="bonferroni",
        min_independent_tasks=min_tasks,
        min_eligible_pairs=2,
        min_flip_rate=0.05,
        max_side_effect_rate_confirmed=0.1,
    )


def _row(protocol, task_id: str, arm: ArmRole) -> AssignmentOutcomeRecord:
    instance = _sha(protocol.arm_protocol_id, task_id)
    assignment = _sha(protocol.arm_protocol_id, task_id, arm.value)
    secure = arm is protocol.arm_roles[0]
    return AssignmentOutcomeRecord.from_content(
        assignment_id="assignment_" + assignment,
        task_id=task_id,
        hypothesis_id=protocol.hypothesis_id,
        target_spec_id=protocol.target_spec_id,
        target_instance_id="target_instance_" + instance,
        arm_protocol_id=protocol.arm_protocol_id,
        protocol_instance_id="protocol_instance_" + instance,
        variant_id="variant_" + _sha(assignment, "variant"),
        arm_role=arm,
        model_id="model-a",
        seed_id=int(assignment[:15], 16),
        execution_status=AssignmentExecutionStatus.GENERATED,
        secure_functional_success=int(secure),
        cwe_security_outcome=(CWESecurityOutcome.SECURE if secure else CWESecurityOutcome.INSECURE),
        oracle_evaluability=AssignmentEvaluability.EVALUABLE,
        parse_ok=True,
        functional_ok=True,
        target_changed=True,
        semantic_compliance=True,
        source_digests_sha256=_sha(assignment, "sources"),
    )


def test_program_functional_unknown_expands_primary_itt_sensitivity_bounds() -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    rows = list(_rows(protocol, ("task-a", "task-b")))
    target_index = next(
        index for index, row in enumerate(rows) if row.arm_role is ArmRole.TARGET_PATCH
    )
    payload = rows[target_index].model_dump(mode="python", exclude={"outcome_id", "schema_version"})
    payload.update(
        secure_functional_success=0,
        functional_ok=False,
        functional_outcome_status=FunctionalOutcomeStatus.UNKNOWN,
    )
    rows[target_index] = AssignmentOutcomeRecord.from_content(**payload)

    effect = next(
        item
        for item in calculate_itt(
            rows, _config(samples=4, min_tasks=2), protocols=(protocol,)
        ).effects
        if item.contrast_id == "safety_add.target_minus_noop.y_secure_functional"
    )

    assert effect.sensitivity_low < effect.sensitivity_high


def _rows(protocol, tasks: tuple[str, ...]) -> tuple[AssignmentOutcomeRecord, ...]:
    return tuple(_row(protocol, task, arm) for task in tasks for arm in protocol.arm_roles)


def test_effect_bootstrap_draw_is_content_addressed_strict_and_safe() -> None:
    draw = EffectBootstrapDrawRecord.from_content(
        effect_id="itt_effect_" + "1" * 64,
        replicate_index=0,
        sampled_task_ids=("task-a", "task-a"),
        estimate=0.25,
        assignment_universe_sha256="2" * 64,
        bootstrap_manifest_sha256="3" * 64,
    )

    assert draw.draw_id.startswith("effect_bootstrap_draw_")
    assert repr(draw) == "EffectBootstrapDrawRecord()"
    with pytest.raises(ValidationError, match="effect bootstrap draw failed validation") as error:
        EffectBootstrapDrawRecord.model_validate(
            {**draw.model_dump(mode="python"), "estimate": float("nan")}
        )
    assert "nan" not in str(error.value).lower()


@pytest.mark.parametrize(
    ("stage", "reason"),
    (
        (AnalysisStage.EFFECTS, AnalysisFailureReason.INSUFFICIENT_SUPPORT),
        (AnalysisStage.EFFECTS, AnalysisFailureReason.BOOTSTRAP_FAILURE),
        (AnalysisStage.JCI, AnalysisFailureReason.DEGENERATE_GSQ_SUPPORT),
        (AnalysisStage.JCI, AnalysisFailureReason.BACKEND_TIMEOUT),
        (AnalysisStage.JCI, AnalysisFailureReason.BACKEND_FAILURE),
        (AnalysisStage.RFCI, AnalysisFailureReason.BACKEND_TIMEOUT),
        (AnalysisStage.RFCI, AnalysisFailureReason.BACKEND_FAILURE),
    ),
)
def test_analysis_failure_reason_is_stage_compatible(stage, reason) -> None:
    failure = AnalysisFailureRecord.from_content(
        stage=stage,
        subject_id="effect-coordinate-1",
        reason_code=reason,
        config_sha256="4" * 64,
        input_bundle_sha256="5" * 64,
    )
    assert failure.failure_id.startswith("analysis_failure_")
    assert repr(failure) == "AnalysisFailureRecord()"


def test_analysis_failure_rejects_incompatible_reason_without_echoing_subject() -> None:
    with pytest.raises(ValidationError, match="analysis failure failed validation") as error:
        AnalysisFailureRecord.from_content(
            stage=AnalysisStage.RFCI,
            subject_id="secret-subject",
            reason_code=AnalysisFailureReason.INSUFFICIENT_SUPPORT,
            config_sha256="4" * 64,
            input_bundle_sha256="5" * 64,
        )
    assert "secret-subject" not in str(error.value)


def test_structured_itt_returns_exact_draw_rows_and_compatibility_effects() -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    outcomes = _rows(protocol, ("task-a", "task-b", "task-c"))
    config = _config(samples=7)

    result = calculate_itt(outcomes, config, protocols=(protocol,))

    assert type(result) is ITTEstimationResult
    assert not result.failures
    assert len(result.draws) == len(result.effects) * config.bootstrap_samples
    assert result.effects == estimate_itt(outcomes, config, protocols=(protocol,))
    by_effect = {effect.effect_id: effect for effect in result.effects}
    assert {draw.effect_id for draw in result.draws} == set(by_effect)
    for effect_id, effect in by_effect.items():
        draws = tuple(draw for draw in result.draws if draw.effect_id == effect_id)
        assert tuple(draw.replicate_index for draw in draws) == tuple(range(7))
        assert {draw.bootstrap_manifest_sha256 for draw in draws} == {
            effect.bootstrap_manifest_sha256
        }
        assert {draw.assignment_universe_sha256 for draw in draws} == {
            effect.assignment_universe_sha256
        }


def test_completed_effect_id_matches_pre_task7_golden() -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    result = calculate_itt(
        _rows(protocol, ("task-a", "task-b", "task-c")),
        _config(samples=7),
        protocols=(protocol,),
    )
    effect = next(
        item
        for item in result.effects
        if item.contrast_id == "safety_add.generic_minus_noop.y_secure_functional"
    )

    assert effect.bootstrap_manifest_sha256 == (
        "687b71c57dbd4cb3e596baa0a8cc5a272fb7d7877040e83e9e046e0e466b5572"
    )
    assert effect.effect_id == (
        "itt_effect_dfd7948b753a49b7bfc5f6730614d223017fe54dc1abc45d3269ac3cd9d29a46"
    )


def test_unsupported_functional_effect_has_no_draw_rows() -> None:
    fixture = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = fixture.protocol
    result = calculate_itt(
        _rows(protocol, ("task-a", "task-b")),
        _config(samples=5),
        protocols=(protocol,),
    )
    unsupported = tuple(
        effect
        for effect in result.effects
        if effect.status == "unsupported_missing_functional_outcome"
    )

    assert unsupported
    assert all(
        draw.effect_id not in {effect.effect_id for effect in unsupported} for draw in result.draws
    )


def test_insufficient_task_support_is_typed_per_effect_coordinate() -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    config = _config(samples=4, min_tasks=3)

    result = calculate_itt(_rows(protocol, ("task-a", "task-b")), config, protocols=(protocol,))

    assert not result.effects
    assert not result.draws
    assert len(result.failures) == len(protocol.contrasts)
    assert {failure.stage for failure in result.failures} == {AnalysisStage.EFFECTS}
    assert {failure.reason_code for failure in result.failures} == {
        AnalysisFailureReason.INSUFFICIENT_SUPPORT
    }


def test_failure_ids_are_invariant_to_relation_permutations() -> None:
    first = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    second = request(FeatureFamily.TASK_FUNCTION, FeatureOperation.ADD).protocol
    protocols = (first, second)
    outcomes = (*_rows(first, ("task-a", "task-b")), *_rows(second, ("task-a", "task-b")))
    config = _config(samples=4, min_tasks=3)
    forward = calculate_itt(
        outcomes,
        config,
        protocols=protocols,
        contrasts=materialize_contrasts(protocols),
    )
    reversed_protocols = protocols[::-1]
    reversed_result = calculate_itt(
        outcomes[::-1],
        config,
        protocols=reversed_protocols,
        contrasts=materialize_contrasts(reversed_protocols),
    )

    assert forward.failures
    assert reversed_result.failures == forward.failures
    assert {item.input_bundle_sha256 for item in forward.failures} == {
        item.input_bundle_sha256 for item in reversed_result.failures
    }


def test_estimator_resource_caps_are_fixed_and_preflight_projected_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    outcomes = _rows(protocol, ("task-a", "task-b"))
    config = _config(samples=4)
    coordinate_count = len(protocol.contrasts)
    draw_count = coordinate_count * config.bootstrap_samples
    assert itt_module.MAX_ESTIMATOR_ARTIFACT_RECORDS == 125_000
    assert itt_module.MAX_ESTIMATOR_DRAW_RECORDS == 125_000

    with monkeypatch.context() as patch:
        patch.setattr(itt_module, "MAX_ESTIMATOR_ARTIFACT_RECORDS", coordinate_count - 1)
        patch.setattr(
            itt_module,
            "task_cluster_bootstrap",
            lambda *_args, **_kwargs: pytest.fail("coordinate budget was not preflighted"),
        )
        with pytest.raises(ValueError, match="artifact budget"):
            calculate_itt(outcomes, config, protocols=(protocol,))

    with monkeypatch.context() as patch:
        patch.setattr(itt_module, "MAX_ESTIMATOR_DRAW_RECORDS", draw_count - 1)
        patch.setattr(
            itt_module,
            "task_cluster_bootstrap",
            lambda *_args, **_kwargs: pytest.fail("draw budget was not preflighted"),
        )
        with pytest.raises(ValueError, match="draw artifact budget"):
            calculate_itt(outcomes, config, protocols=(protocol,))

    with monkeypatch.context() as patch:
        patch.setattr(itt_module, "MAX_ESTIMATOR_ARTIFACT_RECORDS", coordinate_count)
        patch.setattr(itt_module, "MAX_ESTIMATOR_DRAW_RECORDS", draw_count)
        result = calculate_itt(outcomes, config, protocols=(protocol,))
    assert len(result.effects) == coordinate_count
    assert len(result.draws) == draw_count


def test_legacy_work_budget_precedes_new_artifact_budget_on_dual_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    outcomes = _rows(protocol, ("task-a", "task-b"))
    monkeypatch.setattr(itt_module, "MAX_ESTIMATOR_SAMPLED_ROW_ENTRIES", 0)
    monkeypatch.setattr(itt_module, "MAX_ESTIMATOR_ARTIFACT_RECORDS", 0)
    monkeypatch.setattr(
        itt_module,
        "task_cluster_bootstrap",
        lambda *_args, **_kwargs: pytest.fail("budgets were not preflighted"),
    )

    with pytest.raises(ValueError, match="bootstrap work budget"):
        calculate_itt(outcomes, _config(samples=4), protocols=(protocol,))


def test_bootstrap_failure_is_typed_per_effect_coordinate(monkeypatch) -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol

    def failed_bootstrap(*_args, **_kwargs):
        raise ValueError("private bootstrap detail")

    monkeypatch.setattr("secaware.analysis.itt.task_cluster_bootstrap", failed_bootstrap)
    result = calculate_itt(
        _rows(protocol, ("task-a", "task-b")),
        _config(samples=4),
        protocols=(protocol,),
    )

    assert not result.effects
    assert not result.draws
    assert len(result.failures) == len(protocol.contrasts)
    assert {failure.reason_code for failure in result.failures} == {
        AnalysisFailureReason.BOOTSTRAP_FAILURE
    }


def test_empty_assignment_universe_remains_a_hard_error() -> None:
    protocol = request(FeatureFamily.SAFETY_CONTROL, FeatureOperation.ADD).protocol
    with pytest.raises(Exception, match="ITT"):
        calculate_itt((), _config(), protocols=(protocol,))

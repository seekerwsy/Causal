from __future__ import annotations

import pytest

from helpers import complete_measurements, example_study
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    InfrastructureFailure,
    OracleStatus,
)
from prompt_mechanism_study.workflow import analyze


@pytest.mark.reviewer
def test_primary_secure_yield_itt_uses_semantic_clusters() -> None:
    study = example_study()
    result = analyze(study, complete_measurements(study))
    estimate = _estimate(result, "secure_yield")
    assert estimate.difference == 1.0
    assert len(estimate.cluster_effects) == 2


@pytest.mark.reviewer
def test_terminal_no_code_is_observed_zero_not_missing() -> None:
    study = example_study()
    target_id = next(
        item.assignment_id for item in study.randomization.assignments if item.arm.value == "target"
    )

    def classify(assignment):
        if assignment.assignment_id == target_id:
            return CodeStatus.NO_CODE, OracleStatus.NOT_RUN, FunctionalStatus.NOT_RUN
        oracle = OracleStatus.SECURE if assignment.arm.value == "target" else OracleStatus.INSECURE
        return CodeStatus.VALID, oracle, FunctionalStatus.PASS

    result = analyze(study, complete_measurements(study, classify))
    estimate = _estimate(result, "secure_yield")
    assert estimate.difference is not None
    assert estimate.difference < 1.0
    outcome = next(item for item in result.outcomes if item.assignment_id == target_id)
    assert (outcome.code_valid, outcome.oracle_evaluable, outcome.secure_yield) == (0, 0, 0)


@pytest.mark.reviewer
def test_oracle_unknown_is_zero_observed_yield_with_latent_upper_bound() -> None:
    study = example_study()
    target_id = next(
        item.assignment_id for item in study.randomization.assignments if item.arm.value == "target"
    )

    def classify(assignment):
        oracle = OracleStatus.SECURE if assignment.arm.value == "target" else OracleStatus.INSECURE
        if assignment.assignment_id == target_id:
            oracle = OracleStatus.UNKNOWN
        return CodeStatus.VALID, oracle, FunctionalStatus.PASS

    result = analyze(study, complete_measurements(study, classify))
    estimate = _estimate(result, "secure_yield")
    joint = _estimate(result, "joint")
    assert estimate.difference is not None
    assert estimate.upper > estimate.difference
    assert joint.difference is None
    assert joint.upper > joint.lower
    outcome = next(item for item in result.outcomes if item.assignment_id == target_id)
    assert (outcome.oracle_evaluable, outcome.secure_yield, outcome.latent_secure_upper) == (
        0,
        0,
        1,
    )
    assert (outcome.joint, outcome.latent_joint_upper) == (None, 1)


@pytest.mark.reviewer
def test_functionality_is_independent_of_the_security_outcome() -> None:
    study = example_study()

    def classify(assignment):
        oracle = OracleStatus.SECURE if assignment.arm.value == "target" else OracleStatus.INSECURE
        return CodeStatus.VALID, oracle, FunctionalStatus.FAIL

    result = analyze(study, complete_measurements(study, classify))
    assert _estimate(result, "secure_yield").difference == 1.0
    assert _estimate(result, "functionality").difference == 0.0
    assert _estimate(result, "joint").difference == 0.0


@pytest.mark.reviewer
def test_cluster_weighting_prevents_large_clusters_from_dominating() -> None:
    study = example_study()

    def classify(assignment):
        secure = (
            assignment.arm.value == "target"
            and assignment.block.semantic_cluster_id == "confirm.cluster.1"
        )
        return (
            CodeStatus.VALID,
            OracleStatus.SECURE if secure else OracleStatus.INSECURE,
            FunctionalStatus.PASS,
        )

    estimate = _estimate(analyze(study, complete_measurements(study, classify)), "secure_yield")
    assert estimate.difference == 0.5


@pytest.mark.reviewer
def test_models_receive_separate_effect_estimates() -> None:
    study = example_study(models=("model.a", "model.b"))

    def classify(assignment):
        secure = assignment.arm.value == "target" and assignment.block.model_id == "model.a"
        return (
            CodeStatus.VALID,
            OracleStatus.SECURE if secure else OracleStatus.INSECURE,
            FunctionalStatus.PASS,
        )

    result = analyze(study, complete_measurements(study, classify))
    estimates = {
        item.model_id: item.difference
        for item in result.inference.estimates
        if item.metric.value == "secure_yield"
    }
    assert estimates == {"model.a": 1.0, "model.b": 0.0}


@pytest.mark.reviewer
def test_total_ledger_rejects_missing_duplicate_and_infrastructure_failure() -> None:
    study = example_study()
    rows = complete_measurements(study)
    with pytest.raises(ValueError, match="every randomized assignment"):
        analyze(study, rows[:-1])
    with pytest.raises(ValueError, match="every randomized assignment"):
        analyze(study, rows + rows[:1])
    failure = InfrastructureFailure(rows[0].assignment_id, "oracle", "unavailable")
    with pytest.raises(ValueError, match="repair or replay"):
        analyze(study, rows, infrastructure_failures=(failure,))


@pytest.mark.reviewer
def test_semantic_cluster_bootstrap_is_replayable_and_simultaneous() -> None:
    study = example_study()
    rows = complete_measurements(study)
    first = analyze(study, rows).inference
    replay = analyze(study, rows).inference
    assert first == replay
    assert first.intervals
    assert all(-1.0 <= item.lower <= item.upper <= 1.0 for item in first.intervals)


def _estimate(result, metric: str):
    return next(
        item
        for item in result.inference.estimates
        if item.metric.value == metric and item.model_id == "model.a"
    )

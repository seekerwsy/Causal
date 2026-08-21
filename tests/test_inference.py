from __future__ import annotations

import pytest

from helpers import complete_measurements, example_study
from secaware.inference import estimate_itt
from secaware.intervention import Arm
from secaware.measurement import FunctionalLabel, SecurityLabel, close_measurements
from secaware.outcomes import derive_outcomes
from secaware.workflow import analyze


@pytest.mark.reviewer
def test_hand_calculated_security_itt_uses_registered_denominators() -> None:
    study = example_study()
    measurements, failures = complete_measurements(study)
    result = analyze(study, measurements, failures)
    assert result.security.target.total == 4
    assert result.security.control.total == 4
    assert result.security.target.mean == 1.0
    assert result.security.control.mean == 0.0
    assert result.security.difference == 1.0


@pytest.mark.reviewer
def test_functionality_does_not_enter_the_security_outcome() -> None:
    study = example_study()
    functional = {arm: FunctionalLabel.FAIL for arm in Arm}
    measurements, failures = complete_measurements(study, functionality=functional)
    result = analyze(study, measurements, failures)
    assert result.security.difference == 1.0
    assert result.functionality.target.mean == 0.0


@pytest.mark.reviewer
def test_unknown_is_not_treated_as_secure() -> None:
    study = example_study()
    target = next(a for a in study.randomization.assignments if a.arm is Arm.TARGET)
    measurements, failures = complete_measurements(
        study,
        unknown_assignment_id=target.assignment_id,
    )
    result = analyze(study, measurements, failures)
    outcome = next(o for o in result.outcomes if o.assignment_id == target.assignment_id)
    assert outcome.security is None
    assert result.security.target.successes == 3
    assert result.security.target.unknown == 1


@pytest.mark.reviewer
def test_unknown_produces_bounds_instead_of_a_filtered_point_estimate() -> None:
    study = example_study()
    target = next(a for a in study.randomization.assignments if a.arm is Arm.TARGET)
    measurements, failures = complete_measurements(
        study,
        unknown_assignment_id=target.assignment_id,
    )
    result = analyze(study, measurements, failures)
    assert result.security.difference is None
    assert result.security.lower == 0.75
    assert result.security.upper == 1.0


@pytest.mark.reviewer
def test_terminal_failure_remains_in_the_itt_denominator() -> None:
    study = example_study()
    target = next(a for a in study.randomization.assignments if a.arm is Arm.TARGET)
    measurements, failures = complete_measurements(
        study,
        failed_assignment_id=target.assignment_id,
    )
    result = analyze(study, measurements, failures)
    assert result.security.target.total == 4
    assert result.security.target.unknown == 1
    assert result.security.difference is None


@pytest.mark.reviewer
def test_inference_rejects_post_randomization_outcome_filtering() -> None:
    study = example_study()
    measurements, failures = complete_measurements(study)
    ledger = close_measurements(study.randomization, measurements, failures)
    outcomes = derive_outcomes(ledger)
    with pytest.raises(ValueError):
        estimate_itt(study.randomization, outcomes[:-1])


@pytest.mark.reviewer
def test_joint_outcome_requires_both_security_and_functionality() -> None:
    study = example_study()
    functionality = {arm: FunctionalLabel.PASS for arm in Arm}
    functionality[Arm.TARGET] = FunctionalLabel.FAIL
    measurements, failures = complete_measurements(study, functionality=functionality)
    result = analyze(study, measurements, failures)
    assert result.security.target.mean == 1.0
    assert result.joint.target.mean == 0.0


@pytest.mark.reviewer
def test_security_unknown_and_functional_pass_remain_joint_unknown() -> None:
    study = example_study()
    target = next(a for a in study.randomization.assignments if a.arm is Arm.TARGET)
    security = {arm: SecurityLabel.INSECURE for arm in Arm}
    security[Arm.TARGET] = SecurityLabel.SECURE
    measurements, failures = complete_measurements(
        study,
        security=security,
        unknown_assignment_id=target.assignment_id,
    )
    result = analyze(study, measurements, failures)
    outcome = next(o for o in result.outcomes if o.assignment_id == target.assignment_id)
    assert outcome.functionality == 1
    assert outcome.security is None
    assert outcome.joint is None

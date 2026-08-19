from __future__ import annotations

from collections import Counter

import pytest

from secaware.analysis.itt_v2 import (
    coverage_summary_v2,
    estimate_cluster_itt_v2,
    estimate_manski_bounds_v2,
    semantic_cluster_bootstrap_v2,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.outcomes_v2 import (
    AssignmentOutcomeRecordV2,
    AssignmentOutcomeStateV2,
    FunctionalStatusV2,
    block_id_v2,
)

HYPOTHESIS = "hypothesis.v2.security-add"
MODEL = "model.local-14b"
TARGET = "target.v2.shell-guard"
PROTOCOL = "protocol.v2.four-arm-add"


def _projection(
    state: AssignmentOutcomeStateV2,
    functional_status: FunctionalStatusV2,
) -> tuple[int, int, int, int | None]:
    y_c = int(state.value.startswith("valid_"))
    y_e = int(
        state
        in {
            AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
            AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
        }
    )
    secure = int(state is AssignmentOutcomeStateV2.VALID_ORACLE_SECURE)
    joint = None if functional_status is FunctionalStatusV2.NOT_APPLICABLE else int(
        secure == 1 and functional_status is FunctionalStatusV2.PASS
    )
    return y_c, y_e, secure, joint


def _row(
    *,
    cluster: str,
    task: str,
    realization: str,
    arm: ArmRole,
    slot: int,
    state: AssignmentOutcomeStateV2,
    functional_status: FunctionalStatusV2 = FunctionalStatusV2.PASS,
    provider_seed: int | None = None,
) -> AssignmentOutcomeRecordV2:
    bundle = f"bundle.{task}.{realization}"
    y_c, y_e, secure, joint = _projection(state, functional_status)
    return AssignmentOutcomeRecordV2.from_content(
        assignment_id=f"assignment.{cluster}.{task}.{realization}.{arm.value}.{slot}",
        block_id=block_id_v2(
            semantic_task_cluster_id=cluster,
            task_instance_id=task,
            hypothesis_id=HYPOTHESIS,
            target_spec_id=TARGET,
            realization_spec_id=realization,
            task_realization_bundle_id=bundle,
            model_id=MODEL,
            arm_protocol_id=PROTOCOL,
        ),
        semantic_task_cluster_id=cluster,
        task_instance_id=task,
        hypothesis_id=HYPOTHESIS,
        target_spec_id=TARGET,
        realization_spec_id=realization,
        task_realization_bundle_id=bundle,
        model_id=MODEL,
        arm_protocol_id=PROTOCOL,
        arm_role=arm,
        request_randomness_slot=slot,
        provider_seed=provider_seed,
        state=state,
        functional_status=functional_status,
        y_c=y_c,
        y_e=y_e,
        y_secure_yield=secure,
        y_joint=joint,
        source_digests_sha256="a" * 64,
    )


def _state(secure: int) -> AssignmentOutcomeStateV2:
    return (
        AssignmentOutcomeStateV2.VALID_ORACLE_SECURE
        if secure
        else AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE
    )


def _crossed_rows() -> tuple[AssignmentOutcomeRecordV2, ...]:
    # Hand-set block differences:
    # c1/t1: (r1=1, r2=0), c1/t2: (r1=0, r2=1),
    # c2/t3: (r1=-1, r2=1).
    values = {
        ("c1", "t1", "r1"): (1, 0),
        ("c1", "t1", "r2"): (0, 0),
        ("c1", "t2", "r1"): (1, 1),
        ("c1", "t2", "r2"): (1, 0),
        ("c2", "t3", "r1"): (0, 1),
        ("c2", "t3", "r2"): (1, 0),
    }
    rows: list[AssignmentOutcomeRecordV2] = []
    for (cluster, task, realization), (target, control) in values.items():
        rows.extend(
            (
                _row(
                    cluster=cluster,
                    task=task,
                    realization=realization,
                    arm=ArmRole.TARGET_PATCH,
                    slot=0,
                    state=_state(target),
                    functional_status=(
                        FunctionalStatusV2.FAIL
                        if target
                        else FunctionalStatusV2.PASS
                    ),
                    provider_seed=None,
                ),
                _row(
                    cluster=cluster,
                    task=task,
                    realization=realization,
                    arm=ArmRole.NOOP_REWRITE,
                    slot=1,
                    state=_state(control),
                    functional_status=(
                        FunctionalStatusV2.PASS
                        if control
                        else FunctionalStatusV2.FAIL
                    ),
                    provider_seed=None,
                ),
            )
        )
    return tuple(rows)


TASK_WEIGHTS = {("c1", "t1"): 0.75, ("c1", "t2"): 0.25, ("c2", "t3"): 1.0}
REALIZATION_WEIGHTS = {"r1": 0.25, "r2": 0.75}


def test_v2_total_state_projects_outcomes_and_preserves_nullable_provider_seed() -> None:
    no_code = _row(
        cluster="c1",
        task="t1",
        realization="r1",
        arm=ArmRole.TARGET_PATCH,
        slot=0,
        state=AssignmentOutcomeStateV2.TERMINAL_NO_CODE,
        functional_status=FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE,
        provider_seed=None,
    )
    valid_unknown = _row(
        cluster="c1",
        task="t1",
        realization="r1",
        arm=ArmRole.NOOP_REWRITE,
        slot=1,
        state=AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        functional_status=FunctionalStatusV2.UNKNOWN,
        provider_seed=None,
    )

    assert no_code.provider_seed is None
    assert valid_unknown.provider_seed is None
    assert no_code.request_randomness_slot == 0
    assert valid_unknown.request_randomness_slot == 1
    assert (no_code.y_c, no_code.y_e, no_code.y_secure_yield, no_code.y_joint) == (
        0,
        0,
        0,
        0,
    )
    assert (
        valid_unknown.y_c,
        valid_unknown.y_e,
        valid_unknown.y_secure_yield,
        valid_unknown.y_joint,
    ) == (1, 0, 0, 0)
    assert no_code.state is AssignmentOutcomeStateV2.TERMINAL_NO_CODE
    assert valid_unknown.state is AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN
    assert no_code.manski_upper == 0
    assert valid_unknown.manski_upper == 1

    corrupted = valid_unknown.model_dump(mode="python")
    corrupted["y_e"] = 1
    with pytest.raises(Exception, match="v2 assignment outcome"):
        AssignmentOutcomeRecordV2.model_validate(corrupted)


def test_invalid_code_and_valid_oracle_unknown_cannot_be_conflated() -> None:
    invalid = _row(
        cluster="c1",
        task="t1",
        realization="r1",
        arm=ArmRole.TARGET_PATCH,
        slot=0,
        state=AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE,
        functional_status=FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE,
    )
    unknown = _row(
        cluster="c1",
        task="t1",
        realization="r1",
        arm=ArmRole.NOOP_REWRITE,
        slot=1,
        state=AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        functional_status=FunctionalStatusV2.UNKNOWN,
    )

    assert invalid.y_c == 0
    assert unknown.y_c == 1
    assert invalid.manski_upper == 0
    assert unknown.manski_upper == 1


def test_coverage_reports_both_required_denominators() -> None:
    rows = (
        _row(
            cluster="c1",
            task="t1",
            realization="r1",
            arm=ArmRole.TARGET_PATCH,
            slot=0,
            state=AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
        ),
        _row(
            cluster="c1",
            task="t1",
            realization="r2",
            arm=ArmRole.TARGET_PATCH,
            slot=0,
            state=AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
        ),
        _row(
            cluster="c2",
            task="t2",
            realization="r1",
            arm=ArmRole.TARGET_PATCH,
            slot=0,
            state=AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE,
            functional_status=FunctionalStatusV2.NOT_EVALUATED_NO_VALID_CODE,
        ),
    )

    summary = coverage_summary_v2(rows, arm_role=ArmRole.TARGET_PATCH)
    assert summary.assigned_n == 3
    assert summary.valid_code_n == 2
    assert summary.oracle_evaluable_n == 1
    assert summary.valid_code_conditional_coverage == pytest.approx(0.5)
    assert summary.all_assignment_evaluable_yield == pytest.approx(1 / 3)


def test_hand_calculated_block_task_realization_cluster_itt() -> None:
    result = estimate_cluster_itt_v2(
        _crossed_rows(),
        hypothesis_id=HYPOTHESIS,
        model_id=MODEL,
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        task_weights=TASK_WEIGHTS,
        realization_weights=REALIZATION_WEIGHTS,
    )

    # c1 = .75*(.25*1 + .75*0) + .25*(.25*0 + .75*1) = .375
    # c2 = .25*(-1) + .75*(1) = .5; equal-cluster mean = .4375.
    assert [(item.semantic_task_cluster_id, item.estimate) for item in result.cluster_contributions] == [
        ("c1", pytest.approx(0.375)),
        ("c2", pytest.approx(0.5)),
    ]
    assert result.estimate == pytest.approx(0.4375)
    assert result.independent_cluster_n == 2
    assert result.treatment_n == result.control_n == 6


def test_functionality_does_not_enter_primary_safety_outcome() -> None:
    rows = _crossed_rows()
    safety = estimate_cluster_itt_v2(
        rows,
        hypothesis_id=HYPOTHESIS,
        model_id=MODEL,
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        task_weights=TASK_WEIGHTS,
        realization_weights=REALIZATION_WEIGHTS,
        outcome_name="y_secure_yield",
    )
    joint = estimate_cluster_itt_v2(
        rows,
        hypothesis_id=HYPOTHESIS,
        model_id=MODEL,
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        task_weights=TASK_WEIGHTS,
        realization_weights=REALIZATION_WEIGHTS,
        outcome_name="y_joint",
    )

    assert safety.estimate == pytest.approx(0.4375)
    assert joint.estimate != safety.estimate


def test_hand_calculated_manski_unit_and_contrast_bounds() -> None:
    rows = (
        _row(
            cluster="c1",
            task="t1",
            realization="r1",
            arm=ArmRole.TARGET_PATCH,
            slot=0,
            state=AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
            functional_status=FunctionalStatusV2.UNKNOWN,
        ),
        _row(
            cluster="c1",
            task="t1",
            realization="r1",
            arm=ArmRole.NOOP_REWRITE,
            slot=1,
            state=AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
        ),
    )
    bounds = estimate_manski_bounds_v2(
        rows,
        hypothesis_id=HYPOTHESIS,
        model_id=MODEL,
        treatment_arm=ArmRole.TARGET_PATCH,
        control_arm=ArmRole.NOOP_REWRITE,
        task_weights={("c1", "t1"): 1.0},
        realization_weights={"r1": 1.0},
    )

    assert bounds.observed_secure_yield_effect == -1.0
    assert bounds.lower == -1.0  # L_T - U_N
    assert bounds.upper == 0.0  # U_T - L_N


@pytest.mark.parametrize(
    ("task_weights", "realization_weights", "drop_last"),
    (
        ({("c1", "t1"): 0.5, ("c1", "t2"): 0.25, ("c2", "t3"): 1.0}, REALIZATION_WEIGHTS, False),
        (TASK_WEIGHTS, {"r1": 0.2, "r2": 0.7}, False),
        (TASK_WEIGHTS, REALIZATION_WEIGHTS, True),
    ),
)
def test_weight_sums_and_complete_support_fail_closed(
    task_weights: dict[tuple[str, str], float],
    realization_weights: dict[str, float],
    drop_last: bool,
) -> None:
    rows = _crossed_rows()
    if drop_last:
        rows = rows[:-1]
    with pytest.raises(ValueError):
        estimate_cluster_itt_v2(
            rows,
            hypothesis_id=HYPOTHESIS,
            model_id=MODEL,
            treatment_arm=ArmRole.TARGET_PATCH,
            control_arm=ArmRole.NOOP_REWRITE,
            task_weights=task_weights,
            realization_weights=realization_weights,
        )


def test_bootstrap_carries_all_cluster_descendants_and_preserves_stratum_counts() -> None:
    rows = _crossed_rows()
    expected_descendants = {
        cluster: {
            row.assignment_id for row in rows if row.semantic_task_cluster_id == cluster
        }
        for cluster in ("c1", "c2")
    }
    result = semantic_cluster_bootstrap_v2(
        rows,
        lambda sampled: float(len(sampled)),
        samples=8,
        seed_material=b"v2-cluster-bootstrap-test",
        strata={"c1": "injection", "c2": "deserialization"},
    )

    assert len(result.draws) == 8
    for draw in result.draws:
        assert Counter(unit.stratum_id for unit in draw.sampled_clusters) == {
            "injection": 1,
            "deserialization": 1,
        }
        for unit in draw.sampled_clusters:
            assert {row.assignment_id for row in unit.descendants} == expected_descendants[
                unit.semantic_task_cluster_id
            ]
            assert all(
                row.semantic_task_cluster_id == unit.semantic_task_cluster_id
                for row in unit.descendants
            )
    assert result.estimates == (2.0,) * 8

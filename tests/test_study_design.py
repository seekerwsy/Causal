from __future__ import annotations
from dataclasses import replace
import pytest
from prompt_mechanism_study.discovery.prioritization import PolicyTrack
from prompt_mechanism_study.verification import verify_target_power_simulation
from prompt_mechanism_study.experiment.study_planning import ATOMIC_POWER_ARMS, TargetPowerAssumption, TargetPowerSimulationPlan, bind_target_power_to_assignments, simulate_target_power


def _power_plan(track: PolicyTrack, *, family_size: int = 2, task_units: int = 10):
    from prompt_mechanism_study.experiment.inference import TargetITTPlan

    probabilities = tuple(zip(ATOMIC_POWER_ARMS, (0.79, 0.01, 0.1, 0.1), strict=True))
    assumption = TargetPowerAssumption(
        f"{track.value}-planning-high-effect",
        track,
        probabilities,
        0.0,
        0.0,
        ((0.0, 0.0, 0.0, 0.0),),
        0.95,
        0.0,
        0.0,
    )
    plan = TargetPowerSimulationPlan(
        track,
        0.05,
        family_size,
        task_units,
        1,
        2,
        2,
        4,
        0.05,
        0.01,
        1000,
        20260831 + 0,
        (assumption,),
        (1.0,),
        (("stratum-synthetic", task_units),),
        "shared",
        TargetITTPlan(2026083103, 100, 0.05, 2, 0.9, 0.05, 0.2),
    )
    return plan


def test_explicit_power_replays_partial_overlap_realizations_and_task_identity(monkeypatch):
    from prompt_mechanism_study.experiment import study_planning
    from prompt_mechanism_study.verification.qualification import _independent_power_assignments
    plan = _power_plan(PolicyTrack.ATOMIC, family_size=3, task_units=14)
    support = tuple((j, f"task-{i + j * 7:02d}", "stratum-synthetic", i // 7)
                    for j in range(3) for i in range(14))
    plan = replace(plan, global_realizations=2, realization_weights=(0.5, 0.5),
                   family_task_overlap="explicit", task_support=support,
                   assumptions=tuple(replace(a, realization_arm_probability_offsets=((0.0,) * 4,) * 2)
                                     for a in plan.assumptions))
    _, rows = study_planning._power_assignments(plan)
    assert rows == _independent_power_assignments(plan)
    assert len({row.task_unit_id for group in rows for row in group}) == 28
    assert len(support) == 42
    # The same task can have different realizations in different policies.
    shared = [[row for row in group if row.task_unit_id == "task-07"][0] for group in rows[:2]]
    assert {row.realization_id for row in shared} == {"realization-0", "realization-1"}
    with monkeypatch.context() as patch:
        serial = iter(range(1000))
        patch.setattr(study_planning, "_power_uniform_block", lambda *args: [next(serial)] * 4)
        class AlwaysShare:
            def random(self):
                return 0.0
        draws = study_planning._power_task_draws(AlwaysShare(), plan.assumptions[0], plan, rows)
        by_unit = [{row.task_unit_id: value for row, value in zip(group, values)}
                   for group, values in zip(rows, draws)]
        assert by_unit[0]["task-07"] == by_unit[1]["task-07"]
        assert by_unit[0]["task-00"] != by_unit[1]["task-07"]  # Equal row ranks are not a shared task.
    result = simulate_target_power(plan)
    assert verify_target_power_simulation(result)["status"] == "TARGET_POWER_SIMULATION_VERIFIED"
    assert sum(n for _, n in result.scenarios[0].family_status_counts) == plan.simulation_replicates
    assert bind_target_power_to_assignments(plan, tuple(row for group in rows for row in group)) == plan
    with pytest.raises(ValueError, match="one stratum"):
        replace(plan, task_support=tuple(sorted((*support, (0, "task-00", "stratum-synthetic", 1)))))
    # Constant task contributions make every replicate non-evaluable; none may be removed.
    constant = replace(plan, assumptions=(replace(plan.assumptions[0],
        arm_secure_yield_probabilities=tuple(zip(ATOMIC_POWER_ARMS, (1.0, 0.0, 0.0, 0.0)))),))
    blocked = simulate_target_power(constant)
    assert blocked.minimum_achieved_power == 0.0 and not blocked.power_gate_passed
    assert blocked.scenarios[0].meaningful_replicates_by_coordinate == (0, 0, 0)
    assert verify_target_power_simulation(blocked)["power_gate_passed"] is False

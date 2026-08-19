from __future__ import annotations

from secaware.exploratory.independent_validation_effects import _association, _blocks


def _rows() -> list[dict[str, object]]:
    arms = (
        "target_patch",
        "noop_rewrite",
        "length_matched_placebo",
        "generic_security_reminder",
    )
    rows = []
    for task_index in range(2):
        for arm_index, arm in enumerate(arms):
            rows.append(
                {
                    "task_id": f"task-{task_index}",
                    "arm_role": arm,
                    "values": {
                        "z.target_mechanism_realized": arm_index % 2,
                        "y.discovery_functional": int(task_index == 0),
                    },
                }
            )
    return rows


def test_effect_diagnostics_preserve_complete_four_arm_blocks() -> None:
    blocks = _blocks(_rows(), expected_tasks=2)

    assert len(blocks) == 2
    assert set(blocks["task-0"]) == {
        "target_patch",
        "noop_rewrite",
        "length_matched_placebo",
        "generic_security_reminder",
    }


def test_mechanism_function_association_reports_contingency_and_risk_difference() -> None:
    result = _association(_rows())

    assert result["contingency_z_by_y"] == [[2, 2], [2, 2]]
    assert result["unadjusted_risk_difference_z1_minus_z0"] == 0.0

from __future__ import annotations

import pytest

from secaware.exploratory.randomized_discovery_v2_table import _joined_row, _view_rows


def _rows() -> list[dict[str, object]]:
    rows = []
    for arm_index, arm in enumerate(
        (
            "target_patch",
            "noop_rewrite",
            "length_matched_placebo",
            "generic_security_reminder",
        )
    ):
        rows.append(
            {
                "assignment_id": f"assignment-{arm_index}",
                "task_id": "task-a",
                "model_id": "qwen2.5-coder-7b-instruct",
                "arm_role": arm,
                "target_spec_id": "target-a",
                "target_instance_id": "instance-a",
                "arm_protocol_id": "protocol-a",
                "protocol_instance_id": "protocol-instance-a",
                "values": {
                    "w_cwe_scope": 0,
                    "c_discovery_arm": arm_index,
                    "x_operation_specific_security_requirement": int(arm_index == 0),
                    "x_generic_security_reminder": int(arm_index == 3),
                    "p_length_matched_placebo": int(arm_index == 2),
                    "z_target_mechanism_realized": int(arm_index == 0),
                    "y_cwe_secure": int(arm_index == 0),
                    "y_secure_functional": 0,
                },
            }
        )
    return rows


@pytest.mark.parametrize(
    ("view_id", "expected_rows", "expected_width"),
    (
        ("target_noop_security", 2, 4),
        ("target_noop_joint", 2, 4),
        ("full_jci_security", 4, 7),
        ("full_jci_joint", 4, 7),
    ),
)
def test_view_projection_preserves_complete_selected_arms(
    view_id: str,
    expected_rows: int,
    expected_width: int,
) -> None:
    rows = _view_rows(
        _rows(),
        model_id="qwen2.5-coder-7b-instruct",
        view_id=view_id,
    )

    assert len(rows) == expected_rows
    assert all(len(row["values"]) == expected_width for row in rows)


def test_join_requires_exact_assignment_coordinates() -> None:
    mechanism = {
        "assignment_id": "assignment-a",
        "task_id": "task-a",
        "model_id": "qwen2.5-coder-7b-instruct",
        "arm_role": "target_patch",
        "cwe": "CWE-78",
        "mechanism_state": "proved_safe",
        "z_target_mechanism_realized": 1,
        "provenance": {"trace": "a"},
    }
    outcome = {
        "assignment_id": "assignment-b",
        "task_id": "task-a",
        "model_id": "qwen2.5-coder-7b-instruct",
        "arm_role": "target_patch",
        "cwe": "CWE-78",
        "values": {
            "w_cwe_scope": 0,
            "c_discovery_arm": 0,
            "x_operation_specific_security_requirement": 1,
            "x_generic_security_reminder": 0,
            "p_length_matched_placebo": 0,
            "y_cwe_secure": 1,
            "y_secure_functional": 1,
        },
    }

    with pytest.raises(ValueError, match="assignment join"):
        _joined_row(mechanism, outcome)

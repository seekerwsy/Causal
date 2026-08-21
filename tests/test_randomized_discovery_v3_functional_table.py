from __future__ import annotations

import pytest

from secaware.exploratory.randomized_discovery_v3_functional_table import (
    _discovery_row,
    _held_out_row,
)


def test_discovery_projection_separates_mechanism_from_functional_outcome() -> None:
    joined = {
        "assignment_id": "assignment-a",
        "task_id": "task-a",
        "model_id": "qwen2.5-coder-7b-instruct",
        "arm_role": "target_patch",
        "cwe": "CWE-78",
        "target_spec_id": "target-a",
        "target_instance_id": "target-instance-a",
        "arm_protocol_id": "protocol-a",
        "protocol_instance_id": "protocol-instance-a",
        "values": {"z_target_mechanism_realized": 1, "y_cwe_secure": 1},
        "provenance": {"mechanism": {"trace": "a"}},
    }
    result = {
        **{key: joined[key] for key in ("assignment_id", "task_id", "model_id", "arm_role", "cwe")},
        "diagnostics": {"functional_status": "fail"},
        "provenance": {"functional_outcome_id": "functional-a", "unit_manifest_sha256": "a" * 64},
    }

    projected = _discovery_row(joined, result)

    assert projected["values"] == {
        "c.arm": 0,
        "z.target_mechanism_realized": 1,
        "y.discovery_functional": 0,
    }


def test_held_out_projection_fails_closed_on_nonboolean_functionality() -> None:
    row = {
        "assignment_outcome": {
            "model_id": "qwen2.5-coder-7b-instruct",
            "arm_role": "target_patch",
            "functional_ok": 1,
            "cwe_security_outcome": "secure",
        },
        "mechanism_outcomes": {"z_all_relevant_sinks_proved_safe": 1},
        "cwe": "CWE-78",
        "unit_manifest_sha256": "a" * 64,
    }

    with pytest.raises(ValueError, match="held-out projection"):
        _held_out_row(row)

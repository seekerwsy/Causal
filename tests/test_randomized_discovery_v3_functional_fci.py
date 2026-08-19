from __future__ import annotations

import hashlib

from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    _table_and_matrix,
)
from secaware.schema.causal import VariableRole


def _token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_functional_table_builds_typed_czy_with_93_task_blocks() -> None:
    rows = []
    for task_index in range(93):
        for arm in range(2):
            token = _token(f"{task_index}:{arm}")
            rows.append(
                {
                    "assignment_id": f"assignment_{token}",
                    "task_id": f"task-{task_index}",
                    "target_spec_id": f"target_{_token(f'target:{task_index}')}",
                    "target_instance_id": f"target_instance_{_token(f'instance:{task_index}')}",
                    "arm_protocol_id": f"arm_protocol_{_token('protocol')}",
                    "protocol_instance_id": (
                        f"protocol_instance_{_token(f'protocol:{task_index}')}"
                    ),
                    "values": [arm, int(arm == 0), (task_index + arm) % 2],
                }
            )
    payload = {
        "view_id": "target_noop_functional",
        "model_id": "qwen2.5-coder-7b-instruct",
        "independent_tasks": 93,
        "row_count": 186,
        "internal_variable_ids": [
            "c.arm",
            "z.target_mechanism_realized",
            "y.discovery_functional",
        ],
        "rows": rows,
    }

    table, matrix, bindings = _table_and_matrix(payload, producer_sha256="a" * 64)
    by_id = {item.variable_id: item for item in table.variables}

    assert matrix.shape == (186, 3)
    assert len(bindings) == 186
    assert table.independent_task_count == 93
    assert by_id["c.arm"].role is VariableRole.C
    assert by_id["z.target_mechanism_realized"].role is VariableRole.Z
    assert by_id["y.discovery_functional"].role is VariableRole.Y

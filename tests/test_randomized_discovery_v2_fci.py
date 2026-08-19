from __future__ import annotations

import hashlib

from secaware.causal.background import to_causal_learn_background
from secaware.exploratory.randomized_discovery_v2_fci import (
    _base_background,
    _table_and_matrix,
)
from secaware.schema.causal import VariableRole


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _payload() -> dict[str, object]:
    rows = []
    for task_index in range(51):
        for arm_index in range(2):
            token = _digest(f"{task_index}:{arm_index}")
            rows.append(
                {
                    "assignment_id": f"assignment_{token}",
                    "task_id": f"task-{task_index}",
                    "target_spec_id": f"target_{_digest(f'target:{task_index}')}",
                    "target_instance_id": f"target_instance_{_digest(f'instance:{task_index}')}",
                    "arm_protocol_id": f"arm_protocol_{_digest('protocol')}",
                    "protocol_instance_id": (
                        f"protocol_instance_{_digest(f'protocol:{task_index}')}"
                    ),
                    "values": [
                        task_index % 5,
                        arm_index,
                        int(arm_index == 0),
                        int(arm_index == 0),
                        1,
                    ],
                }
            )
    return {
        "view_id": "target_noop_security",
        "model_id": "qwen2.5-coder-7b-instruct",
        "independent_tasks": 51,
        "row_count": len(rows),
        "internal_variable_ids": [
            "w.cwe_scope",
            "c.arm",
            "x.operation_specific_security_requirement",
            "z.target_mechanism_realized",
            "y.discovery_cwe_secure",
        ],
        "rows": rows,
    }


def test_v2_table_orders_typed_wxzy_and_builds_temporal_background() -> None:
    table, matrix, bindings = _table_and_matrix(_payload(), producer_sha256="a" * 64)
    knowledge = _base_background(table)
    by_id = {item.variable_id: item for item in table.variables}

    assert matrix.shape == (102, 5)
    assert len(bindings) == 102
    assert by_id["z.target_mechanism_realized"].role is VariableRole.Z
    assert by_id["z.target_mechanism_realized"].temporal_tier == 2
    assert by_id["y.discovery_cwe_secure"].temporal_tier == 3
    assert (
        "y.discovery_cwe_secure",
        "z.target_mechanism_realized",
    ) in knowledge.forbidden_directions
    assert knowledge.required_directions == ()
    assert knowledge.forbidden_adjacencies == ()
    to_causal_learn_background(knowledge)

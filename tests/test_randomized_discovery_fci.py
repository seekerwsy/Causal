from __future__ import annotations

import hashlib

import numpy as np
import pytest

from secaware.causal.background import to_causal_learn_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.exploratory.randomized_discovery_fci import (
    _base_background,
    _table_and_matrix,
    _variables,
)
from secaware.schema.causal import VariableRole


def _matrix_payload() -> dict[str, object]:
    return {
        "category_orders": {
            "binary": ["absent_or_not_success", "present_or_success"],
            "c_discovery_arm": [
                "target_patch",
                "noop_rewrite",
                "length_matched_placebo",
                "generic_security_reminder",
            ],
            "w_cwe_scope": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
        }
    }


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for task_index in range(51):
        task_id = f"task-{task_index}"
        for arm in range(4):
            token = _digest(f"{task_id}:{arm}")
            secure = (task_index + arm) % 2
            rows.append(
                {
                    "assignment_id": f"assignment_{token}",
                    "task_id": task_id,
                    "target_spec_id": f"target_{_digest(f'target:{task_index}')}",
                    "target_instance_id": f"target_instance_{_digest(f'instance:{task_index}')}",
                    "arm_protocol_id": f"arm_protocol_{_digest('protocol')}",
                    "protocol_instance_id": (
                        f"protocol_instance_{_digest(f'protocol:{task_index}')}"
                    ),
                    "model_id": "qwen2.5-coder-7b-instruct",
                    "values": {
                        "w_cwe_scope": task_index % 5,
                        "c_discovery_arm": arm,
                        "x_operation_specific_security_requirement": int(arm == 0),
                        "x_generic_security_reminder": int(arm == 3),
                        "p_length_matched_placebo": int(arm == 2),
                        "y_cwe_secure": secure,
                        "y_secure_functional": secure,
                    },
                }
            )
    return rows


def test_pooled_variables_are_closed_catalog_declarations() -> None:
    variables = _variables(_matrix_payload(), "a" * 64)
    by_id = {item.variable_id: item for item in variables}

    assert tuple(by_id) == tuple(sorted(by_id))
    assert by_id["c.arm"].role is VariableRole.C
    assert by_id["p.length_matched_placebo"].role is VariableRole.P
    for variable_id, variable in by_id.items():
        if variable_id == "c.arm":
            assert variable.producer_sha256 == "a" * 64
            continue
        declaration = declaration_by_id(variable_id)
        assert variable.states == declaration.states
        assert variable.source_query_id == declaration.query_id
        assert variable.adjacency_type == declaration.adjacency_type
        assert variable.producer_sha256 == declaration_sha256(declaration)


def test_pooled_categories_fail_closed_on_order_drift() -> None:
    payload = _matrix_payload()
    payload["category_orders"]["w_cwe_scope"].reverse()  # type: ignore[index,union-attr]

    with pytest.raises(ValueError, match="categories failed validation"):
        _variables(payload, "a" * 64)


def test_four_arm_rows_build_one_translatable_pooled_jci_table() -> None:
    table, matrix, bindings = _table_and_matrix(
        _rows(),
        _matrix_payload(),
        model_id="qwen2.5-coder-7b-instruct",
        producer_sha256="a" * 64,
    )
    background = _base_background(table)

    assert table.cwe == "CWE-POOLED"
    assert table.row_count == len(bindings) == 204
    assert table.independent_task_count == 51
    assert matrix.shape == (204, 7)
    assert matrix.dtype == np.int64
    assert matrix.flags.writeable is False
    assert background.unconstrained_variable_ids == ("c.arm",)
    assert background.required_directions == ()
    assert background.forbidden_adjacencies == ()
    to_causal_learn_background(background)

from __future__ import annotations

import pytest

from secaware.exploratory.gate_b import (
    _selected_gate_b_task_ids,
    _validated_provider_call_budget,
)


def test_scale_selection_closes_over_all_gate_a_tasks_in_sorted_order() -> None:
    source_by_task = {"task-c": object(), "task-a": object(), "task-b": object()}
    selected = _selected_gate_b_task_ids(
        {"task_selection_policy": "all_gate_a_tasks"},
        source_by_task,
    )
    assert selected == ("task-a", "task-b", "task-c")
    assert _validated_provider_call_budget(
        {
            "provider_call_budget": {
                "intervention_calls": 12,
                "extractor_calls": 15,
                "total_provider_calls": 27,
            }
        },
        independent_tasks=3,
    ) == {
        "intervention_calls": 12,
        "extractor_calls": 15,
        "total_provider_calls": 27,
    }


def test_scale_selection_rejects_mixed_or_incorrectly_budgeted_inputs() -> None:
    source_by_task = {"task-a": object(), "task-b": object()}
    with pytest.raises(ValueError, match="task selection"):
        _selected_gate_b_task_ids(
            {
                "task_selection_policy": "all_gate_a_tasks",
                "selected_task_ids": ["task-a"],
            },
            source_by_task,
        )
    with pytest.raises(ValueError, match="provider budget"):
        _validated_provider_call_budget(
            {
                "provider_call_budget": {
                    "intervention_calls": 8,
                    "extractor_calls": 9,
                    "total_provider_calls": 17,
                }
            },
            independent_tasks=2,
        )


def test_explicit_canary_selection_remains_supported() -> None:
    source_by_task = {"task-a": object(), "task-b": object()}
    assert _selected_gate_b_task_ids(
        {"selected_task_ids": ["task-b", "task-a"]},
        source_by_task,
    ) == ("task-b", "task-a")

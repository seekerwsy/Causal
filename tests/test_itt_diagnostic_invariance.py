from __future__ import annotations

from secaware.analysis.itt import estimate_itt
from secaware.schema.experiments import ArmRole
from secaware.schema.outcomes import AssignmentOutcomeRecord

from test_clustered_itt import (
    _analysis_config,
    _assignment_outcome,
    _complete_rows,
    _effect,
    _safety_protocol,
    _sha,
)


def _with_diagnostics(
    row: AssignmentOutcomeRecord,
    *,
    target_changed: bool | None,
    semantic_compliance: bool | None,
) -> AssignmentOutcomeRecord:
    content = row.model_dump(mode="python", exclude={"outcome_id"})
    content.update(
        target_changed=target_changed,
        semantic_compliance=semantic_compliance,
        source_digests_sha256=_sha(
            row.assignment_id,
            target_changed,
            semantic_compliance,
            "mutated-diagnostics",
        ),
    )
    return AssignmentOutcomeRecord.from_content(**content)


def test_target_and_semantic_diagnostics_cannot_change_any_itt_output() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(
        protocol,
        ("task-a", "task-b", "task-c", "task-d"),
        secure_assignments={
            ("task-a", ArmRole.TARGET_PATCH),
            ("task-b", ArmRole.TARGET_PATCH),
            ("task-c", ArmRole.TARGET_PATCH),
            ("task-a", ArmRole.NOOP_REWRITE),
        },
    )
    mutated = tuple(
        _with_diagnostics(
            row,
            target_changed={True: False, False: True, None: True}[row.target_changed],
            semantic_compliance={True: False, False: True, None: False}[row.semantic_compliance],
        )
        for row in rows
    )
    assert {row.outcome_id for row in rows}.isdisjoint({row.outcome_id for row in mutated})

    baseline_effects = estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    mutated_effects = estimate_itt(mutated, _analysis_config(), protocols=(protocol,))

    assert mutated_effects == baseline_effects


def test_none_false_and_true_diagnostics_never_filter_randomized_assignments() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    mutated = tuple(
        _with_diagnostics(
            row,
            target_changed=(None, False, True)[index % 3],
            semantic_compliance=(True, None, False)[index % 3],
        )
        for index, row in enumerate(rows)
    )

    effects = estimate_itt(mutated, _analysis_config(), protocols=(protocol,))

    assert all(effect.treatment_n == 2 for effect in effects)
    assert all(effect.control_n == 2 for effect in effects)


def test_analysis_affecting_assignment_fields_change_universe_and_effect_identity() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    changed_row = _assignment_outcome(
        protocol,
        rows[0].task_id,
        rows[0].arm_role,
        secure=True,
    )
    assert changed_row.assignment_id == rows[0].assignment_id
    changed_rows = (changed_row, *rows[1:])

    baseline = _effect(
        estimate_itt(rows, _analysis_config(), protocols=(protocol,)),
        "safety_add.target_minus_noop.y_secure_functional",
    )
    changed = _effect(
        estimate_itt(changed_rows, _analysis_config(), protocols=(protocol,)),
        "safety_add.target_minus_noop.y_secure_functional",
    )

    assert changed.assignment_universe_sha256 != baseline.assignment_universe_sha256
    assert changed.bootstrap_manifest_sha256 != baseline.bootstrap_manifest_sha256
    assert changed.effect_id != baseline.effect_id


def test_outcome_input_order_does_not_change_effect_or_bootstrap_draw_order() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(
        protocol,
        ("task-d", "task-b", "task-a", "task-c"),
        secure_assignments={
            ("task-a", ArmRole.TARGET_PATCH),
            ("task-c", ArmRole.NOOP_REWRITE),
        },
    )

    forward = estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    reverse = estimate_itt(tuple(reversed(rows)), _analysis_config(), protocols=(protocol,))

    assert reverse == forward

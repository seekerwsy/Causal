from __future__ import annotations

import hashlib

from secaware.exploratory.randomized_discovery_v2_bootstrap import _draw, _reference_path
from secaware.schema.causal import EndpointMark, PAGEdgeRecord, PAGRecord, PAGRunKind


def _token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _blocks() -> tuple[tuple[str, tuple[dict[str, object], ...]], ...]:
    blocks = []
    for task_index in range(51):
        block = tuple(
            {
                "assignment_id": f"assignment_{_token(f'{task_index}:{arm}')}",
                "task_id": f"task-{task_index}",
                "row_id": f"row_{_token(f'row:{task_index}:{arm}')}",
                "values": (arm, task_index % 5, int(arm == 0), (task_index + arm) % 2),
            }
            for arm in range(2)
        )
        blocks.append((f"task-{task_index}", block))
    return tuple(blocks)


def test_v2_draw_preserves_complete_two_arm_task_blocks() -> None:
    provenance = {"global_seed": 2026081921, "sampling_frame_sha256": "a" * 64}
    draw, matrix = _draw(
        blocks=_blocks(),
        provenance=provenance,
        replicate_index=0,
        variable_count=4,
    )

    assert matrix.shape == (102, 4)
    assert matrix.flags.writeable is False
    assert len(draw["sampled_task_ids"]) == 51
    assert len(set(draw["sampled_task_ids"])) < 51
    for draw_index in range(51):
        selected = [row for row in draw["row_coordinates"] if row["draw_index"] == draw_index]
        assert [row["arm_position"] for row in selected] == [0, 1]


def test_v2_reference_path_requires_source_mechanism_outcome_chain() -> None:
    source = "c.arm"
    mechanism = "z.target_mechanism_realized"
    outcome = "y.discovery_secure_functional"
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.JCI_RAW,
        table_id=f"table_{'a' * 64}",
        backend="causal_learn_fci_v1",
        backend_version="0.1.4.7",
        ci_test="gsq",
        config_sha256="b" * 64,
        background_knowledge_sha256="c" * 64,
        variable_ids=(source, mechanism, outcome),
        edges=(
            PAGEdgeRecord(
                left=source,
                right=mechanism,
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.CIRCLE,
            ),
            PAGEdgeRecord(
                left=outcome,
                right=mechanism,
                left_mark=EndpointMark.ARROW,
                right_mark=EndpointMark.TAIL,
            ),
        ),
    )

    path = _reference_path(pag, source=source, outcome=outcome)

    assert path is not None
    assert path.variable_ids == (source, mechanism, outcome)

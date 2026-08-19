from __future__ import annotations

import hashlib

from secaware.exploratory.randomized_discovery_v3_functional_bootstrap import _draw


def _token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_functional_bootstrap_draw_preserves_93_four_arm_blocks() -> None:
    blocks = []
    for task_index in range(93):
        block = tuple(
            {
                "assignment_id": f"assignment_{_token(f'{task_index}:{arm}')}",
                "task_id": f"task-{task_index}",
                "row_id": f"row_{_token(f'row:{task_index}:{arm}')}",
                "values": (arm, (task_index + arm) % 2, int(arm == 0)),
            }
            for arm in range(4)
        )
        blocks.append((f"task-{task_index}", block))
    provenance = {"global_seed": 2026081922, "sampling_frame_sha256": "a" * 64}

    draw, matrix = _draw(
        blocks=tuple(blocks),
        provenance=provenance,
        replicate_index=0,
    )

    assert matrix.shape == (372, 3)
    assert matrix.flags.writeable is False
    assert len(draw["sampled_task_ids"]) == 93
    assert len(set(draw["sampled_task_ids"])) < 93

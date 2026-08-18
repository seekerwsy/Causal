from __future__ import annotations

import hashlib

from secaware.exploratory.randomized_discovery_bootstrap import _draw, enumerate_policy_paths
from secaware.schema.causal import EndpointMark, PAGEdgeRecord, PAGRecord, PAGRunKind


def _token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _blocks(*, outcome_offset: int = 0) -> tuple[tuple[str, tuple[dict[str, object], ...]], ...]:
    blocks = []
    for task_index in range(51):
        block = []
        for arm in range(4):
            block.append(
                {
                    "assignment_id": f"assignment_{_token(f'{task_index}:{arm}')}",
                    "task_id": f"task-{task_index}",
                    "row_id": f"row_{_token(f'row:{task_index}:{arm}')}",
                    "values": (
                        arm,
                        int(arm == 2),
                        task_index % 5,
                        int(arm == 3),
                        int(arm == 0),
                        (task_index + arm + outcome_offset) % 2,
                        (task_index + arm + outcome_offset) % 2,
                    ),
                }
            )
        blocks.append((f"task-{task_index}", tuple(block)))
    return tuple(blocks)


def test_task_cluster_draw_keeps_complete_four_arm_blocks() -> None:
    provenance = {"global_seed": 2026081821, "sampling_frame_sha256": "a" * 64}
    draw, matrix = _draw(blocks=_blocks(), provenance=provenance, replicate_index=0)

    assert len(draw["sampled_task_ids"]) == 51
    assert len(set(draw["sampled_task_ids"])) < 51
    assert len(draw["row_coordinates"]) == 204
    assert matrix.shape == (204, 7)
    assert matrix.flags.writeable is False
    coordinates = draw["row_coordinates"]
    for draw_index in range(51):
        selected = [item for item in coordinates if item["draw_index"] == draw_index]
        assert [item["arm_index"] for item in selected] == [0, 1, 2, 3]


def test_task_sampling_is_independent_of_outcome_columns() -> None:
    provenance = {"global_seed": 2026081821, "sampling_frame_sha256": "a" * 64}
    first, first_matrix = _draw(
        blocks=_blocks(outcome_offset=0),
        provenance=provenance,
        replicate_index=7,
    )
    second, second_matrix = _draw(
        blocks=_blocks(outcome_offset=1),
        provenance=provenance,
        replicate_index=7,
    )

    assert first["sampled_task_ids"] == second["sampled_task_ids"]
    assert first["row_coordinates"] == second["row_coordinates"]
    assert first["seed_material_sha256"] == second["seed_material_sha256"]
    assert first_matrix[:, :-2].tolist() == second_matrix[:, :-2].tolist()
    assert first_matrix[:, -2:].tolist() != second_matrix[:, -2:].tolist()


def test_policy_path_enumerator_excludes_jci_context_from_candidate_path() -> None:
    source = "x.operation_specific_security_requirement"
    placebo = "p.length_matched_placebo"
    context = "c.arm"
    outcome = "y.secure_functional"
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.JCI_RAW,
        table_id=f"table_{'a' * 64}",
        backend="causal_learn_fci_v1",
        backend_version="0.1.4.7",
        ci_test="gsq",
        config_sha256="b" * 64,
        background_knowledge_sha256="c" * 64,
        variable_ids=(source, placebo, context, outcome, "y.cwe_secure"),
        edges=(
            PAGEdgeRecord(
                left=source,
                right=placebo,
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.CIRCLE,
            ),
            PAGEdgeRecord(
                left=placebo,
                right=outcome,
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.ARROW,
            ),
            PAGEdgeRecord(
                left=context,
                right=source,
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.CIRCLE,
            ),
            PAGEdgeRecord(
                left=context,
                right=outcome,
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.ARROW,
            ),
        ),
    )

    paths = enumerate_policy_paths(pag, max_path_length=6, max_candidate_paths=32)

    assert tuple(item.variable_ids for item in paths) == ((source, placebo, outcome),)
    assert all(context not in item.variable_ids for item in paths)

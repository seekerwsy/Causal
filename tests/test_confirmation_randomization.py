from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest
from pydantic import ValidationError

from secaware.config import GenerationConfig, RandomizationConfig
from secaware.experiments.randomization import (
    RandomizationBlock,
    RandomizationError,
    RandomizationFailureCode,
    group_assignments_by_block,
    randomize_protocols,
    validate_randomization_bundle,
)
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    RandomizationManifestRecord,
)


SEEDS = tuple(range(101, 113))
RANDOMIZATION_CONFIG = RandomizationConfig(min_independent_tasks_per_semantic_protocol=2)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _block(
    task_id: str,
    roles: tuple[ArmRole, ...] = (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    ),
) -> RandomizationBlock:
    ordered_roles = tuple(sorted(roles, key=lambda item: item.value))
    return RandomizationBlock(
        task_id=task_id,
        hypothesis_id="hypothesis_" + "1" * 64,
        target_spec_id="target_" + "2" * 64,
        target_instance_id="target_instance_" + _sha(task_id),
        arm_protocol_id="arm_protocol_" + "3" * 64,
        protocol_instance_id="protocol_instance_" + _sha(task_id + "protocol"),
        model_id="model-a",
        variants=tuple((role, "variant_" + _sha(task_id + role.value)) for role in ordered_roles),
    )


def _two_task_blocks(
    roles: tuple[ArmRole, ...] = (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    ),
) -> tuple[RandomizationBlock, RandomizationBlock]:
    return (
        _block("task-a", roles),
        _block("task-b", roles),
    )


def test_assignment_maps_seed_slot_unit_to_arm_role() -> None:
    block = _block(
        "task-a",
        (
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
            ArmRole.LENGTH_MATCHED_PLACEBO,
            ArmRole.GENERIC_SECURITY_REMINDER,
        ),
    )
    manifest, assignments = randomize_protocols(
        (block, _block("task-b", block.arm_roles)),
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    assert manifest.assignment_ids == tuple(item.assignment_id for item in assignments)
    assert all(item.experimental_unit.seed_slot >= 0 for item in assignments)
    assert all(item.arm_role in set(block.arm_roles) for item in assignments)
    assert all(item.experimental_unit.target_spec_id == item.target_spec_id for item in assignments)
    assert all("arm_role" not in item.experimental_unit.model_dump() for item in assignments)


def test_balanced_assignment_is_input_order_invariant() -> None:
    blocks = (
        _block("task-b"),
        _block("task-a"),
    )
    first = randomize_protocols(
        blocks,
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    second = randomize_protocols(
        tuple(reversed(blocks)),
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    assert first == second
    for block_id in first[0].block_ids:
        roles = [item.arm_role for item in first[1] if item.block_id == block_id]
        assert all(roles.count(role) == 3 for role in set(roles))


def test_exact_block_key_separates_every_semantic_coordinate() -> None:
    base = _block("task-a")
    variants = (
        replace(base, task_id="task-b"),
        replace(base, hypothesis_id="hypothesis_" + "a" * 64),
        replace(base, target_spec_id="target_" + "b" * 64),
        replace(base, arm_protocol_id="arm_protocol_" + "c" * 64),
        replace(base, model_id="model-b"),
    )
    assert len({base.block_id, *(item.block_id for item in variants)}) == 6
    assert "arm_role" not in {
        "task_id",
        "hypothesis_id",
        "target_spec_id",
        "arm_protocol_id",
        "model_id",
    }


def test_add_remove_and_distinct_protocols_never_share_blocks() -> None:
    add = _block("task-a")
    remove = replace(
        add,
        target_spec_id="target_" + "a" * 64,
        arm_protocol_id="arm_protocol_" + "b" * 64,
        target_instance_id="target_instance_" + "c" * 64,
        protocol_instance_id="protocol_instance_" + "d" * 64,
    )
    other_protocol = replace(
        add,
        arm_protocol_id="arm_protocol_" + "e" * 64,
        protocol_instance_id="protocol_instance_" + "f" * 64,
    )
    assert len({add.block_id, remove.block_id, other_protocol.block_id}) == 3


def test_task_blocks_share_semantic_protocol_but_keep_distinct_instances() -> None:
    manifest, assignments = randomize_protocols(
        _two_task_blocks(),
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    del manifest
    assert len({item.target_spec_id for item in assignments}) == 1
    assert len({item.arm_protocol_id for item in assignments}) == 1
    assert len({item.target_instance_id for item in assignments}) == 2
    assert len({item.protocol_instance_id for item in assignments}) == 2


@pytest.mark.parametrize(
    "roles",
    (
        (ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE),
        (
            ArmRole.PRESENTATION_TARGET,
            ArmRole.PRESENTATION_NOOP,
            ArmRole.PRESENTATION_MATCHED_CONTROL,
        ),
        (
            ArmRole.TARGET_PATCH,
            ArmRole.NOOP_REWRITE,
            ArmRole.LENGTH_MATCHED_PLACEBO,
            ArmRole.GENERIC_SECURITY_REMINDER,
        ),
    ),
)
def test_closed_two_three_four_arm_protocols_balance_in_twelve_slots(
    roles: tuple[ArmRole, ...],
) -> None:
    manifest, assignments = randomize_protocols(
        _two_task_blocks(roles),
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    assert manifest.block_ids
    for local in group_assignments_by_block(assignments).values():
        assert {role: sum(item.arm_role is role for item in local) for role in roles} == {
            role: 12 // len(roles) for role in roles
        }


def test_non_common_multiple_fails_before_any_assignment() -> None:
    with pytest.raises(RandomizationError) as exc_info:
        randomize_protocols(
            _two_task_blocks(
                (
                    ArmRole.PRESENTATION_TARGET,
                    ArmRole.PRESENTATION_NOOP,
                    ArmRole.PRESENTATION_MATCHED_CONTROL,
                )
            ),
            global_seed=123,
            confirmation_seeds=tuple(range(10)),
            config=RANDOMIZATION_CONFIG,
        )
    assert exc_info.value.failure_code is RandomizationFailureCode.INVALID_SEED_SLOTS


def test_semantic_protocol_below_independent_task_minimum_is_typed_failure() -> None:
    with pytest.raises(RandomizationError) as exc_info:
        randomize_protocols(
            _two_task_blocks(),
            global_seed=123,
            confirmation_seeds=SEEDS,
            config=RandomizationConfig(min_independent_tasks_per_semantic_protocol=3),
        )
    assert exc_info.value.failure_code is RandomizationFailureCode.INSUFFICIENT_INDEPENDENT_TASKS


def test_global_seed_changes_plan_and_assignments_but_is_reproducible() -> None:
    blocks = _two_task_blocks()
    first = randomize_protocols(
        blocks,
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    repeat = randomize_protocols(
        tuple(reversed(blocks)),
        global_seed=123,
        confirmation_seeds=tuple(reversed(SEEDS)),
        config=RANDOMIZATION_CONFIG,
    )
    changed = randomize_protocols(
        blocks,
        global_seed=124,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    assert first == repeat
    assert first[0].randomization_plan_sha256 != changed[0].randomization_plan_sha256
    assert first[0].assignment_ids != changed[0].assignment_ids


@pytest.mark.parametrize(
    "confirmation_seeds",
    ([], [1, 1], [-(2**63) - 1], [2**63]),
)
def test_confirmation_seeds_are_unique_nonempty_and_bounded(
    confirmation_seeds: list[int],
) -> None:
    with pytest.raises(ValidationError):
        GenerationConfig(confirmation_seeds=confirmation_seeds)


def test_confirmation_seeds_are_independent_from_observational_seeds() -> None:
    config = GenerationConfig(seeds=[7, 8], confirmation_seeds=list(SEEDS))
    assert config.seeds == [7, 8]
    assert config.confirmation_seeds == list(SEEDS)


def test_rng_version_is_closed() -> None:
    with pytest.raises(ValidationError):
        RandomizationConfig(rng_version="future-rng")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mutation",
    ("duplicate", "omission", "extra", "variant", "task", "model", "hypothesis", "target"),
)
def test_bundle_rejects_duplicate_omission_extra_and_coordinate_drift(
    mutation: str,
) -> None:
    blocks = _two_task_blocks()
    manifest, assignments = randomize_protocols(
        blocks,
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    changed = list(assignments)
    if mutation == "duplicate":
        changed[-1] = changed[0]
    elif mutation == "omission":
        changed.pop()
    elif mutation == "extra":
        changed.append(changed[0])
    else:
        victim = changed[0]
        if mutation == "variant":
            changed[0] = victim.model_copy(update={"variant_id": "variant_" + "f" * 64})
        else:
            field = {
                "task": "task_id",
                "model": "model_id",
                "hypothesis": "hypothesis_id",
                "target": "target_spec_id",
            }[mutation]
            unit = victim.experimental_unit.model_copy(
                update={
                    field: (
                        "task-x"
                        if mutation == "task"
                        else "model-x"
                        if mutation == "model"
                        else "hypothesis_" + "f" * 64
                        if mutation == "hypothesis"
                        else "target_" + "f" * 64
                    )
                }
            )
            changed[0] = victim.model_copy(update={"experimental_unit": unit})
    with pytest.raises(RandomizationError):
        validate_randomization_bundle(
            manifest,
            tuple(changed),
            blocks,
            SEEDS,
            config=RandomizationConfig(min_independent_tasks_per_semantic_protocol=2),
        )


def test_assignment_and_manifest_are_content_addressed_and_self_validating() -> None:
    blocks = _two_task_blocks()
    manifest, assignments = randomize_protocols(
        blocks,
        global_seed=123,
        confirmation_seeds=SEEDS,
        config=RANDOMIZATION_CONFIG,
    )
    assignment_payload = assignments[0].model_dump(mode="json")
    assignment_payload["seed_id"] += 1
    with pytest.raises(ValidationError):
        AssignmentRecord.model_validate(assignment_payload)
    manifest_payload = manifest.model_dump(mode="json")
    manifest_payload["global_seed"] += 1
    with pytest.raises(ValidationError):
        RandomizationManifestRecord.model_validate(manifest_payload)
    manifest_content = manifest.model_dump(
        mode="python",
        exclude={"schema_version", "manifest_id"},
    )
    with pytest.raises(ValidationError):
        RandomizationManifestRecord.from_content(
            **{**manifest_content, "block_ids": ("block_invalid",)}
        )
    with pytest.raises(ValidationError):
        RandomizationManifestRecord.from_content(
            **{**manifest_content, "assignment_ids": ("assignment_invalid",)}
        )


@pytest.mark.parametrize("signal_type", (MemoryError, KeyboardInterrupt, SystemExit))
def test_randomization_preserves_process_control_identity(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    from secaware.experiments import randomization as module

    def interrupt(_self: object, _values: object) -> object:
        raise signal_type("private-randomization-interrupt")

    monkeypatch.setattr(module.DeterministicRNG, "shuffle", interrupt)
    with pytest.raises(signal_type):
        randomize_protocols(
            _two_task_blocks(),
            global_seed=123,
            confirmation_seeds=SEEDS,
            config=RANDOMIZATION_CONFIG,
        )

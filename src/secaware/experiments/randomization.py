"""Deterministic complete-block randomization over frozen prompt variants."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re

from secaware.config import RandomizationConfig
from secaware.randomness import DeterministicRNG, RNG_VERSION
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    ExperimentalUnit,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)


_MAX_RECORDS = 100_000
_SUPPORTED_ARM_FAMILIES = frozenset(
    {
        frozenset({ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE}),
        frozenset({ArmRole.TARGET_REMOVE, ArmRole.NOOP_RETAIN}),
        frozenset(
            {
                ArmRole.TARGET_PATCH,
                ArmRole.NOOP_REWRITE,
                ArmRole.LENGTH_MATCHED_PLACEBO,
                ArmRole.GENERIC_SECURITY_REMINDER,
            }
        ),
        frozenset(
            {
                ArmRole.TARGET_REMOVE,
                ArmRole.NOOP_RETAIN,
                ArmRole.LENGTH_MATCHED_SHAM_EDIT,
                ArmRole.GENERIC_SECURITY_REPLACEMENT,
            }
        ),
        frozenset(
            {
                ArmRole.TASK_TARGET,
                ArmRole.TASK_NOOP,
                ArmRole.TASK_LENGTH_PLACEBO,
            }
        ),
        frozenset(
            {
                ArmRole.TASK_TARGET,
                ArmRole.TASK_NOOP,
                ArmRole.TASK_LENGTH_PLACEBO,
                ArmRole.TASK_GENERIC_CONTROL,
            }
        ),
        frozenset(
            {
                ArmRole.PRESENTATION_TARGET,
                ArmRole.PRESENTATION_NOOP,
            }
        ),
        frozenset(
            {
                ArmRole.PRESENTATION_TARGET,
                ArmRole.PRESENTATION_NOOP,
                ArmRole.PRESENTATION_MATCHED_CONTROL,
            }
        ),
    }
)


def _json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class RandomizationFailureCode(str, Enum):
    INVALID_INPUT = "invalid_input"
    RESOURCE_LIMIT = "resource_limit"
    INVALID_SEED_SLOTS = "invalid_seed_slots"
    PROTOCOL_COVERAGE_INVALID = "protocol_coverage_invalid"
    INSTANCE_RESOLUTION_INVALID = "instance_resolution_invalid"
    INSUFFICIENT_INDEPENDENT_TASKS = "insufficient_independent_tasks"


class RandomizationError(ValueError):
    """A typed, non-data-bearing pre-assignment randomization failure."""

    def __init__(self, failure_code: RandomizationFailureCode) -> None:
        self.failure_code = failure_code
        super().__init__("confirmation randomization failed validation")


def _fail(code: RandomizationFailureCode) -> None:
    raise RandomizationError(code)


@dataclass(frozen=True, slots=True, repr=False)
class RandomizationBlock:
    task_id: str
    hypothesis_id: str
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    model_id: str
    variants: tuple[tuple[ArmRole, str], ...]

    @property
    def arm_roles(self) -> tuple[ArmRole, ...]:
        return tuple(item[0] for item in self.variants)

    @property
    def block_id(self) -> str:
        return AssignmentRecord.block_id_from_key(
            self.task_id,
            self.hypothesis_id,
            self.target_spec_id,
            self.arm_protocol_id,
            self.model_id,
        )


def _unique_index(
    records: Sequence[object],
    field: str,
    model: type,
) -> dict[str, object]:
    if len(records) > _MAX_RECORDS:
        _fail(RandomizationFailureCode.RESOURCE_LIMIT)
    result: dict[str, object] = {}
    try:
        for untrusted in records:
            record = model.model_validate(untrusted.model_dump(mode="json"))
            if model is FrozenHypothesisRecord:
                from secaware.causal.freeze import revalidate_frozen_hypothesis

                record = revalidate_frozen_hypothesis(record)
            key = getattr(record, field)
            if type(key) is not str or key in result:
                _fail(RandomizationFailureCode.INVALID_INPUT)
            result[key] = record
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError:
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    return result


def build_randomization_blocks(
    *,
    target_specs: Sequence[TargetSpecRecord],
    target_instances: Sequence[TargetInstanceRecord],
    protocols: Sequence[ConfirmationProtocolRecord],
    protocol_instances: Sequence[ConfirmationProtocolInstanceRecord],
    variants: Sequence[PromptVariantRecord],
    exclusions: Sequence[PreRandomizationExclusionRecord],
    hypotheses: Sequence[FrozenHypothesisRecord],
    max_blocks: int,
) -> tuple[RandomizationBlock, ...]:
    """Resolve the exact frozen Task-4 closure into pre-assignment blocks."""

    if type(max_blocks) is not int or not 1 <= max_blocks <= 100_000:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    try:
        targets = _unique_index(target_specs, "target_spec_id", TargetSpecRecord)
        target_realizations = _unique_index(
            target_instances, "target_instance_id", TargetInstanceRecord
        )
        protocol_defs = _unique_index(protocols, "arm_protocol_id", ConfirmationProtocolRecord)
        protocol_realizations = _unique_index(
            protocol_instances,
            "protocol_instance_id",
            ConfirmationProtocolInstanceRecord,
        )
        variant_defs = _unique_index(variants, "variant_id", PromptVariantRecord)
        exclusion_defs = _unique_index(
            exclusions,
            "exclusion_id",
            PreRandomizationExclusionRecord,
        )
        hypothesis_defs = _unique_index(hypotheses, "hypothesis_id", FrozenHypothesisRecord)

        if (
            set(protocol_defs) != {item.arm_protocol_id for item in protocol_realizations.values()}
            or set(target_realizations)
            != {item.target_instance_id for item in protocol_realizations.values()}
            or set(targets) != {item.target_spec_id for item in target_realizations.values()}
        ):
            _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)

        for instance in protocol_realizations.values():
            protocol = protocol_defs.get(instance.arm_protocol_id)
            target_instance = target_realizations.get(instance.target_instance_id)
            target = (
                targets.get(protocol.target_spec_id)
                if isinstance(protocol, ConfirmationProtocolRecord)
                else None
            )
            hypothesis = (
                hypothesis_defs.get(protocol.hypothesis_id)
                if isinstance(protocol, ConfirmationProtocolRecord)
                else None
            )
            if (
                not isinstance(protocol, ConfirmationProtocolRecord)
                or not isinstance(target_instance, TargetInstanceRecord)
                or not isinstance(target, TargetSpecRecord)
                or not isinstance(hypothesis, FrozenHypothesisRecord)
                or target.target_spec_id != target_instance.target_spec_id
                or target.hypothesis_id != protocol.hypothesis_id
                or instance.task_id != target_instance.task_id
                or instance.source_prompt_id != target_instance.source_prompt_id
                or instance.source_prompt_sha256 != target_instance.source_prompt_sha256
                or instance.counterpart_prompt_id != target_instance.counterpart_prompt_id
                or instance.counterpart_prompt_sha256 != target_instance.counterpart_prompt_sha256
                or protocol.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
                or target.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
            ):
                _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)

        variants_by_instance: dict[str, list[PromptVariantRecord]] = defaultdict(list)
        for variant in variant_defs.values():
            variants_by_instance[variant.protocol_instance_id].append(variant)
        exclusions_by_instance: dict[str, list[PreRandomizationExclusionRecord]] = defaultdict(list)
        for exclusion in exclusion_defs.values():
            exclusions_by_instance[exclusion.protocol_instance_id].append(exclusion)
        if set(variants_by_instance) | set(exclusions_by_instance) != set(protocol_realizations):
            _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
        if set(variants_by_instance) & set(exclusions_by_instance):
            _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
        if any(len(items) != 1 for items in exclusions_by_instance.values()):
            _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)

        for protocol_instance_id, items in exclusions_by_instance.items():
            exclusion = items[0]
            instance = protocol_realizations[protocol_instance_id]
            protocol = protocol_defs.get(instance.arm_protocol_id)
            target_instance = target_realizations.get(instance.target_instance_id)
            if (
                not isinstance(protocol, ConfirmationProtocolRecord)
                or not isinstance(target_instance, TargetInstanceRecord)
                or exclusion.hypothesis_id != protocol.hypothesis_id
                or exclusion.target_spec_id != protocol.target_spec_id
                or exclusion.target_instance_id != target_instance.target_instance_id
                or exclusion.arm_protocol_id != protocol.arm_protocol_id
                or exclusion.task_id != instance.task_id
            ):
                _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)

        blocks: list[RandomizationBlock] = []
        seen_block_keys: set[tuple[str, str, str, str, str]] = set()
        used_variant_ids: set[str] = set()
        used_target_instances: set[str] = set()
        for protocol_instance_id in sorted(variants_by_instance):
            instance = protocol_realizations[protocol_instance_id]
            if not isinstance(instance, ConfirmationProtocolInstanceRecord):
                _fail(RandomizationFailureCode.INVALID_INPUT)
            protocol = protocol_defs.get(instance.arm_protocol_id)
            target_instance = target_realizations.get(instance.target_instance_id)
            if not isinstance(protocol, ConfirmationProtocolRecord) or not isinstance(
                target_instance, TargetInstanceRecord
            ):
                _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
            target = targets.get(protocol.target_spec_id)
            hypothesis = hypothesis_defs.get(protocol.hypothesis_id)
            if not isinstance(target, TargetSpecRecord) or not isinstance(
                hypothesis, FrozenHypothesisRecord
            ):
                _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
            if (
                target.target_spec_id != target_instance.target_spec_id
                or target.hypothesis_id != protocol.hypothesis_id
                or instance.task_id != target_instance.task_id
                or instance.source_prompt_id != target_instance.source_prompt_id
                or instance.source_prompt_sha256 != target_instance.source_prompt_sha256
                or instance.counterpart_prompt_id != target_instance.counterpart_prompt_id
                or instance.counterpart_prompt_sha256 != target_instance.counterpart_prompt_sha256
                or protocol.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
                or target.frozen_hypothesis_sha256 != hypothesis.hypothesis_sha256
            ):
                _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)

            local_variants = variants_by_instance[protocol_instance_id]
            role_map: dict[ArmRole, PromptVariantRecord] = {}
            for variant in local_variants:
                if variant.arm_role in role_map:
                    _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
                if (
                    variant.task_id != instance.task_id
                    or variant.source_prompt_id != instance.source_prompt_id
                    or variant.hypothesis_id != protocol.hypothesis_id
                    or variant.target_spec_id != target.target_spec_id
                    or variant.target_instance_id != target_instance.target_instance_id
                    or variant.arm_protocol_id != protocol.arm_protocol_id
                    or variant.protocol_instance_id != instance.protocol_instance_id
                ):
                    _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
                role_map[variant.arm_role] = variant
            if set(role_map) != set(protocol.arm_roles) or len(local_variants) != len(
                protocol.arm_roles
            ):
                _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
            key = (
                instance.task_id,
                protocol.hypothesis_id,
                target.target_spec_id,
                protocol.arm_protocol_id,
                hypothesis.model_id,
            )
            if key in seen_block_keys:
                _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
            seen_block_keys.add(key)
            used_target_instances.add(target_instance.target_instance_id)
            used_variant_ids.update(item.variant_id for item in local_variants)
            blocks.append(
                RandomizationBlock(
                    task_id=instance.task_id,
                    hypothesis_id=protocol.hypothesis_id,
                    target_spec_id=target.target_spec_id,
                    target_instance_id=target_instance.target_instance_id,
                    arm_protocol_id=protocol.arm_protocol_id,
                    protocol_instance_id=instance.protocol_instance_id,
                    model_id=hypothesis.model_id,
                    variants=tuple(
                        (role, role_map[role].variant_id)
                        for role in sorted(role_map, key=lambda item: item.value)
                    ),
                )
            )
            if len(blocks) > max_blocks:
                _fail(RandomizationFailureCode.RESOURCE_LIMIT)
        if used_variant_ids != set(variant_defs):
            _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
        # Every active target instance must resolve exactly once. Excluded instances may
        # share their target realization only with their own exclusion record.
        active_expected = {
            item.target_instance_id
            for item in protocol_realizations.values()
            if item.protocol_instance_id in variants_by_instance
        }
        if used_target_instances != active_expected:
            _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
        return tuple(sorted(blocks, key=lambda item: item.block_id))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError:
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)


def _validated_seed_slots(values: Sequence[int]) -> tuple[int, ...]:
    try:
        value_count = len(values)
        if value_count < 1 or value_count > _MAX_RECORDS:
            _fail(RandomizationFailureCode.INVALID_SEED_SLOTS)
        result = tuple(sorted(values))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_SEED_SLOTS)
    if (
        len(result) != value_count
        or len(result) != len(set(result))
        or any(type(value) is not int or not -(2**63) <= value <= 2**63 - 1 for value in result)
    ):
        _fail(RandomizationFailureCode.INVALID_SEED_SLOTS)
    return result


def _validate_block(block: RandomizationBlock) -> None:
    if type(block) is not RandomizationBlock or not block.variants:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    roles = block.arm_roles
    variant_ids = tuple(item[1] for item in block.variants)
    if (
        block.variants != tuple(sorted(block.variants, key=lambda item: item[0].value))
        or len(roles) not in {2, 3, 4}
        or frozenset(roles) not in _SUPPORTED_ARM_FAMILIES
        or len(roles) != len(set(roles))
        or len(variant_ids) != len(set(variant_ids))
        or re.fullmatch(r"hypothesis_[0-9a-f]{64}", block.hypothesis_id) is None
        or re.fullmatch(r"target_[0-9a-f]{64}", block.target_spec_id) is None
        or re.fullmatch(r"target_instance_[0-9a-f]{64}", block.target_instance_id) is None
        or re.fullmatch(r"arm_protocol_[0-9a-f]{64}", block.arm_protocol_id) is None
        or re.fullmatch(r"protocol_instance_[0-9a-f]{64}", block.protocol_instance_id) is None
        or any(re.fullmatch(r"variant_[0-9a-f]{64}", item) is None for item in variant_ids)
        or not block.task_id
        or not block.model_id
    ):
        _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)


def _validate_preassignment_inputs(
    blocks: Sequence[RandomizationBlock],
    seeds: tuple[int, ...],
    config: RandomizationConfig,
) -> tuple[RandomizationBlock, ...]:
    """Shared complete validator used before assignment and during readback."""

    try:
        block_count = len(blocks)
        if block_count < 1 or block_count > min(config.max_blocks, _MAX_RECORDS):
            _fail(RandomizationFailureCode.RESOURCE_LIMIT)
        ordered_blocks = tuple(sorted(blocks, key=lambda item: item.block_id))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError:
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    if len(ordered_blocks) != block_count:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    if len(ordered_blocks) > _MAX_RECORDS // len(seeds):
        _fail(RandomizationFailureCode.RESOURCE_LIMIT)
    if len({item.block_id for item in ordered_blocks}) != len(ordered_blocks):
        _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
    if (
        len({item.target_instance_id for item in ordered_blocks}) != len(ordered_blocks)
        or len({item.protocol_instance_id for item in ordered_blocks}) != len(ordered_blocks)
        or len({variant_id for item in ordered_blocks for _role, variant_id in item.variants})
        != sum(len(item.variants) for item in ordered_blocks)
    ):
        _fail(RandomizationFailureCode.INSTANCE_RESOLUTION_INVALID)
    family_tasks: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for block in ordered_blocks:
        _validate_block(block)
        if len(seeds) % len(block.arm_roles):
            _fail(RandomizationFailureCode.INVALID_SEED_SLOTS)
        family_tasks[
            (
                block.hypothesis_id,
                block.target_spec_id,
                block.arm_protocol_id,
                block.model_id,
            )
        ].add(block.task_id)
    if any(
        len(tasks) < config.min_independent_tasks_per_semantic_protocol
        for tasks in family_tasks.values()
    ):
        _fail(RandomizationFailureCode.INSUFFICIENT_INDEPENDENT_TASKS)
    return ordered_blocks


def _plan_payload(
    blocks: tuple[RandomizationBlock, ...],
    seeds: tuple[int, ...],
    global_seed: int,
    config: RandomizationConfig,
) -> dict[str, object]:
    return {
        "plan_version": "confirmation-complete-block-v1",
        "rng_version": config.rng_version,
        "global_seed": global_seed,
        "confirmation_seeds": seeds,
        "max_blocks": config.max_blocks,
        "min_independent_tasks_per_semantic_protocol": (
            config.min_independent_tasks_per_semantic_protocol
        ),
        "blocks": [
            {
                "block_id": block.block_id,
                "block_key": [
                    block.task_id,
                    block.hypothesis_id,
                    block.target_spec_id,
                    block.arm_protocol_id,
                    block.model_id,
                ],
                "target_instance_id": block.target_instance_id,
                "protocol_instance_id": block.protocol_instance_id,
                "variants": [[role.value, variant_id] for role, variant_id in block.variants],
            }
            for block in blocks
        ],
    }


def _assigned_roles(
    block: RandomizationBlock,
    seeds: tuple[int, ...],
    global_seed: int,
    config: RandomizationConfig,
) -> tuple[ArmRole, ...]:
    repeated_roles = block.arm_roles * (len(seeds) // len(block.arm_roles))
    rng = DeterministicRNG(
        json.dumps(
            {
                "rng_version": config.rng_version,
                "global_seed": global_seed,
                "block_id": block.block_id,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return rng.shuffle(repeated_roles)


def randomize_protocols(
    blocks: Sequence[RandomizationBlock],
    *,
    global_seed: int,
    confirmation_seeds: Sequence[int],
    config: RandomizationConfig,
) -> tuple[RandomizationManifestRecord, tuple[AssignmentRecord, ...]]:
    """Create balanced deterministic assignments without reading any outcomes."""

    try:
        effective = RandomizationConfig.model_validate(config.model_dump(mode="json"))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)
    if (
        type(global_seed) is not int
        or not -(2**63) <= global_seed <= 2**63 - 1
        or effective.rng_version != RNG_VERSION
    ):
        _fail(RandomizationFailureCode.INVALID_INPUT)
    seeds = _validated_seed_slots(confirmation_seeds)
    ordered_blocks = _validate_preassignment_inputs(blocks, seeds, effective)

    plan_payload = _plan_payload(ordered_blocks, seeds, global_seed, effective)
    plan_sha256 = _json_sha256(plan_payload)
    assignments: list[AssignmentRecord] = []
    try:
        for block in ordered_blocks:
            assigned_roles = _assigned_roles(block, seeds, global_seed, effective)
            variant_by_role = dict(block.variants)
            for seed_slot, (seed_id, arm_role) in enumerate(
                zip(seeds, assigned_roles, strict=True)
            ):
                unit = ExperimentalUnit(
                    task_id=block.task_id,
                    hypothesis_id=block.hypothesis_id,
                    target_spec_id=block.target_spec_id,
                    model_id=block.model_id,
                    seed_slot=seed_slot,
                )
                assignments.append(
                    AssignmentRecord.from_content(
                        block_id=block.block_id,
                        experimental_unit=unit,
                        target_spec_id=block.target_spec_id,
                        target_instance_id=block.target_instance_id,
                        arm_protocol_id=block.arm_protocol_id,
                        protocol_instance_id=block.protocol_instance_id,
                        variant_id=variant_by_role[arm_role],
                        arm_role=arm_role,
                        seed_id=seed_id,
                        rng_version=effective.rng_version,
                        randomization_plan_sha256=plan_sha256,
                    )
                )
        ordered_assignments = tuple(
            sorted(assignments, key=lambda item: (item.block_id, item.experimental_unit.seed_slot))
        )
        assignments_sha256 = _json_sha256(
            [item.model_dump(mode="json") for item in ordered_assignments]
        )
        manifest = RandomizationManifestRecord.from_content(
            global_seed=global_seed,
            rng_version=effective.rng_version,
            randomization_plan_sha256=plan_sha256,
            block_ids=tuple(block.block_id for block in ordered_blocks),
            assignment_ids=tuple(item.assignment_id for item in ordered_assignments),
            assignments_sha256=assignments_sha256,
        )
        validate_randomization_bundle(
            manifest,
            ordered_assignments,
            ordered_blocks,
            seeds,
            config=effective,
        )
        return manifest, ordered_assignments
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError:
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)


def validate_randomization_bundle(
    manifest: RandomizationManifestRecord,
    assignments: Sequence[AssignmentRecord],
    blocks: Sequence[RandomizationBlock],
    confirmation_seeds: Sequence[int],
    *,
    config: RandomizationConfig,
) -> None:
    """Validate exact immutable assignment/manifest closure."""

    try:
        checked_config = RandomizationConfig.model_validate(config.model_dump(mode="json"))
        if checked_config.rng_version != RNG_VERSION:
            _fail(RandomizationFailureCode.INVALID_INPUT)
        checked_manifest = RandomizationManifestRecord.model_validate(
            manifest.model_dump(mode="json")
        )
        assignment_count = len(assignments)
        if assignment_count < 1 or assignment_count > _MAX_RECORDS:
            _fail(RandomizationFailureCode.RESOURCE_LIMIT)
        checked_assignments = tuple(
            AssignmentRecord.model_validate(item.model_dump(mode="json")) for item in assignments
        )
        if len(checked_assignments) != assignment_count:
            _fail(RandomizationFailureCode.INVALID_INPUT)
        seeds = _validated_seed_slots(confirmation_seeds)
        ordered_blocks = _validate_preassignment_inputs(blocks, seeds, checked_config)
        block_by_id = {item.block_id: item for item in ordered_blocks}
        canonical_assignments = tuple(
            sorted(
                checked_assignments,
                key=lambda item: (item.block_id, item.experimental_unit.seed_slot),
            )
        )
        expected_plan_sha256 = _json_sha256(
            _plan_payload(ordered_blocks, seeds, checked_manifest.global_seed, checked_config)
        )
        if (
            checked_assignments != canonical_assignments
            or checked_manifest.block_ids != tuple(sorted(block_by_id))
            or checked_manifest.rng_version != checked_config.rng_version
            or checked_manifest.randomization_plan_sha256 != expected_plan_sha256
            or checked_manifest.assignment_ids
            != tuple(item.assignment_id for item in checked_assignments)
            or checked_manifest.assignments_sha256
            != _json_sha256([item.model_dump(mode="json") for item in checked_assignments])
            or len({item.assignment_id for item in checked_assignments}) != len(checked_assignments)
        ):
            _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
        by_block: dict[str, list[AssignmentRecord]] = defaultdict(list)
        for assignment in checked_assignments:
            block = block_by_id.get(assignment.block_id)
            if block is None:
                _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
            if (
                assignment.randomization_plan_sha256 != checked_manifest.randomization_plan_sha256
                or assignment.rng_version != checked_manifest.rng_version
                or assignment.experimental_unit.task_id != block.task_id
                or assignment.experimental_unit.hypothesis_id != block.hypothesis_id
                or assignment.experimental_unit.target_spec_id != block.target_spec_id
                or assignment.experimental_unit.model_id != block.model_id
                or assignment.target_spec_id != block.target_spec_id
                or assignment.target_instance_id != block.target_instance_id
                or assignment.arm_protocol_id != block.arm_protocol_id
                or assignment.protocol_instance_id != block.protocol_instance_id
                or (assignment.arm_role, assignment.variant_id) not in block.variants
            ):
                _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
            by_block[assignment.block_id].append(assignment)
        for block_id, block in block_by_id.items():
            local = by_block.get(block_id, [])
            expected_roles = _assigned_roles(
                block,
                seeds,
                checked_manifest.global_seed,
                checked_config,
            )
            variant_by_role = dict(block.variants)
            if (
                len(local) != len(seeds)
                or tuple(item.experimental_unit.seed_slot for item in local)
                != tuple(range(len(seeds)))
                or tuple(item.seed_id for item in local) != seeds
                or tuple(item.arm_role for item in local) != expected_roles
                or tuple(item.variant_id for item in local)
                != tuple(variant_by_role[role] for role in expected_roles)
                or any(
                    sum(item.arm_role is role for item in local)
                    != len(seeds) // len(block.arm_roles)
                    for role in block.arm_roles
                )
            ):
                _fail(RandomizationFailureCode.PROTOCOL_COVERAGE_INVALID)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except RandomizationError:
        raise
    except Exception:
        _fail(RandomizationFailureCode.INVALID_INPUT)


def group_assignments_by_block(
    assignments: Sequence[AssignmentRecord],
) -> dict[str, tuple[AssignmentRecord, ...]]:
    grouped: dict[str, list[AssignmentRecord]] = defaultdict(list)
    for assignment in assignments:
        grouped[assignment.block_id].append(assignment)
    return {
        block_id: tuple(sorted(items, key=lambda item: item.experimental_unit.seed_slot))
        for block_id, items in sorted(grouped.items())
    }


__all__ = [
    "RandomizationBlock",
    "RandomizationError",
    "RandomizationFailureCode",
    "build_randomization_blocks",
    "group_assignments_by_block",
    "randomize_protocols",
    "validate_randomization_bundle",
]

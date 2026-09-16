"""Outcome-blind complete-block assignment for the active schema-3 protocol."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    ConfirmationDispatchRecord,
    PolicyTrack,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text


class ConfirmatoryArm(StrEnum):
    ATOMIC_TARGET = "atomic_target"
    ATOMIC_NOOP = "atomic_noop"
    ATOMIC_PLACEBO = "atomic_placebo"
    ATOMIC_GENERIC = "atomic_generic"


ATOMIC_CONFIRMATORY_ARMS = (
    ConfirmatoryArm.ATOMIC_TARGET,
    ConfirmatoryArm.ATOMIC_NOOP,
    ConfirmatoryArm.ATOMIC_PLACEBO,
    ConfirmatoryArm.ATOMIC_GENERIC,
)


@dataclass(frozen=True, slots=True)
class TargetRandomizationPlan:
    """Outcome-blind complete-block assignment rule for the target protocol."""

    protocol_id: str
    schema_version: str
    assignment_seed: int
    provider_seed_root: int | None
    atomic_total_block_slots: int
    realization_weights: tuple[tuple[str, str, float], ...]
    allocation_tasks: tuple[tuple[str, str, str], ...]
    algorithm_id: str = "sha256_ranked_complete_block_v1"

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "target randomization protocol_id")
        require_text(self.schema_version, "target randomization schema_version")
        if type(self.assignment_seed) is not int or self.assignment_seed < 0:
            raise ValueError("target assignment seed must be a nonnegative integer")
        if self.provider_seed_root is not None and (
            type(self.provider_seed_root) is not int or self.provider_seed_root < 0
        ):
            raise ValueError("target provider seed root must be null or nonnegative")
        for value, name in ((self.atomic_total_block_slots, "Atomic total block slots"),):
            if type(value) is not int or value <= 0 or value % 4:
                raise ValueError(f"{name} must be a positive multiple of four")
        if self.algorithm_id != "sha256_ranked_complete_block_v1":
            raise ValueError("target randomization algorithm is not the frozen algorithm")
        if self.realization_weights != tuple(sorted(self.realization_weights)):
            raise ValueError("realization weights require canonical order")
        weights = defaultdict(dict)
        for policy, realization, q in self.realization_weights:
            require_text(policy, "realization policy")
            require_text(realization, "realization ID")
            if realization in weights[policy] or type(q) is not float or (not 0 < q <= 1):
                raise ValueError("realization weights must be unique positive probabilities")
            weights[policy][realization] = q
        if any(
            (
                not math.isclose(sum(q.values()), 1, rel_tol=0, abs_tol=1e-12)
                for q in weights.values()
            )
        ):
            raise ValueError("every frozen realization distribution must sum to one")
        if self.allocation_tasks != tuple(sorted(set(self.allocation_tasks))):
            raise ValueError("allocation tasks require canonical unique order")
        coordinates, strata = (set(), {})
        for policy, unit, stratum in self.allocation_tasks:
            for value in (policy, unit, stratum):
                require_text(value, "allocation task coordinate")
            if (policy, unit) in coordinates:
                raise ValueError("one task-policy coordinate may enter allocation only once")
            coordinates.add((policy, unit))
            if strata.setdefault(unit, stratum) != stratum:
                raise ValueError("shared task units cannot cross allocation strata")
        if {policy for policy, _, _ in self.allocation_tasks} != set(weights):
            raise ValueError(
                "allocation tasks and realization distributions must cover the same policies"
            )

    @property
    def target_randomization_plan_id(self) -> str:
        return content_id("target_randomization_plan_", self)


def allocate_target_realizations(plan: TargetRandomizationPlan) -> dict[tuple[str, str], str]:
    """Allocate once, before text exists, using largest remainders within strata.

    Task order and remainder ties are seeded hashes. The pool and Q are immutable;
    validation failures retain this allocation and are never replaced or redrawn.
    """
    weights = defaultdict(dict)
    for policy, realization, q in plan.realization_weights:
        weights[policy][realization] = q
    groups = defaultdict(list)
    for policy, unit, stratum in plan.allocation_tasks:
        groups[(policy, stratum)].append(unit)
    allocations = {}
    for (policy, stratum), units in sorted(groups.items()):
        q = weights[policy]
        n = len(units)
        counts = {r: math.floor(n * weight) for r, weight in q.items()}
        priority = sorted(q, key=lambda r: (
            -(n * q[r] - counts[r]),
            content_hash(("realization_remainder", plan.assignment_seed, policy, stratum, r)),
        ))
        for r in priority[:n - sum(counts.values())]:
            counts[r] += 1
        ordered = sorted(units, key=lambda unit: (
            content_hash(("realization_task", plan.assignment_seed, policy, stratum, unit)), unit,
        ))
        slots = [r for r in sorted(q) for _ in range(counts[r])]
        allocations.update({(policy, unit): r for unit, r in zip(ordered, slots, strict=True)})
    return allocations


@dataclass(frozen=True, slots=True)
class TargetTaskArmVariant:
    """One pre-randomization arm digest inside a shared task-policy bundle."""

    arm: ConfirmatoryArm
    variant_sha256: str

    def __post_init__(self) -> None:
        if type(self.arm) is not ConfirmatoryArm:
            raise TypeError("target task-bundle arm must be typed")
        _require_digest(self.variant_sha256, "target task-bundle variant_sha256")


@dataclass(frozen=True, slots=True)
class TargetTaskBundle:
    """One model-invariant task realization materialized before arm assignment."""

    policy_key: str
    track: PolicyTrack
    task_unit_id: str
    task_instance_id: str
    stratum_id: str
    realization_id: str
    task_bundle_id: str
    protocol_record_id: str
    task_instance_weight: float
    realization_weight: float
    variants: tuple[TargetTaskArmVariant, ...]
    exclusion_reason: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "policy_key",
            "task_unit_id",
            "task_instance_id",
            "stratum_id",
            "realization_id",
            "task_bundle_id",
            "protocol_record_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.track) is not PolicyTrack:
            raise TypeError("target task-bundle track must be typed")
        for value, name in (
            (self.task_instance_weight, "task-instance weight"),
            (self.realization_weight, "realization weight"),
        ):
            if type(value) is not float or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive float")
        expected = ATOMIC_CONFIRMATORY_ARMS
        if self.exclusion_reason is not None:
            require_text(self.exclusion_reason, "task bundle exclusion reason")
            if self.variants:
                raise ValueError("an excluded task bundle cannot carry executable variants")
        elif tuple((item.arm for item in self.variants)) != expected:
            raise ValueError("target task bundle must contain its four arms in canonical order")
        if any((type(item) is not TargetTaskArmVariant for item in self.variants)):
            raise TypeError("target task-bundle variants must be typed")

    @property
    def target_task_bundle_id(self) -> str:
        return content_id("target_task_bundle_", self)

    def variant(self, arm: ConfirmatoryArm) -> TargetTaskArmVariant:
        return next(item for item in self.variants if item.arm is arm)


@dataclass(frozen=True, slots=True)
class AssignedArmITTRecord:
    """One frozen assigned arm; post-assignment diagnostics have no fields here."""

    candidate_record_id: str
    effect_coordinate_id: str
    policy_key: str
    model_id: str
    track: PolicyTrack
    task_unit_id: str
    task_instance_id: str
    stratum_id: str
    realization_id: str
    task_bundle_id: str
    protocol_record_id: str
    request_randomness_slot: int
    arm: ConfirmatoryArm
    task_instance_weight: float
    realization_weight: float
    variant_sha256: str
    provider_seed: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "candidate_record_id",
            "effect_coordinate_id",
            "policy_key",
            "model_id",
            "task_unit_id",
            "task_instance_id",
            "stratum_id",
            "realization_id",
            "task_bundle_id",
            "protocol_record_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.track) is not PolicyTrack or type(self.arm) is not ConfirmatoryArm:
            raise TypeError("assigned track and arm must be typed")
        allowed = ATOMIC_CONFIRMATORY_ARMS
        if self.arm not in allowed:
            raise ValueError("assigned arm does not belong to its policy track")
        if type(self.request_randomness_slot) is not int or self.request_randomness_slot < 0:
            raise ValueError("assigned request slot must be a nonnegative integer")
        for value, name in (
            (self.task_instance_weight, "task-instance weight"),
            (self.realization_weight, "realization weight"),
        ):
            if type(value) not in {int, float} or not math.isfinite(float(value)) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        _require_digest(self.variant_sha256, "assigned variant_sha256")
        if self.provider_seed is not None and (
            type(self.provider_seed) is not int or self.provider_seed < 0
        ):
            raise ValueError("provider seed must be null or nonnegative")

    @property
    def block_id(self) -> str:
        return content_id(
            "assigned_arm_itt_block_",
            {
                "candidate_record_id": self.candidate_record_id,
                "effect_coordinate_id": self.effect_coordinate_id,
                "policy_key": self.policy_key,
                "model_id": self.model_id,
                "track": self.track,
                "task_unit_id": self.task_unit_id,
                "task_instance_id": self.task_instance_id,
                "stratum_id": self.stratum_id,
                "realization_id": self.realization_id,
                "task_bundle_id": self.task_bundle_id,
                "protocol_record_id": self.protocol_record_id,
                "task_instance_weight": self.task_instance_weight,
                "realization_weight": self.realization_weight,
            },
        )

    @property
    @lru_cache(maxsize=131072)
    def assignment_id(self) -> str:
        # Immutable assignments are revisited by every endpoint and power replicate.
        # Keep one bounded planning family resident (24 effects x 400 tasks x 8 slots).
        return content_id("assigned_arm_itt_assignment_", self)


def randomize_target_confirmation(
    dispatch: ConfirmationDispatchManifest,
    plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
) -> tuple[AssignedArmITTRecord, ...]:
    """Deterministically assign balanced target arms without a model cross-product."""
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("target randomization requires a confirmation dispatch manifest")
    if type(plan) is not TargetRandomizationPlan:
        raise TypeError("target randomization requires a TargetRandomizationPlan")
    if (
        dispatch.union.ledger.protocol_id != plan.protocol_id
        or dispatch.union.ledger.schema_version != plan.schema_version
    ):
        raise ValueError("target randomization plan drifted from the fixed-slot protocol")
    frozen_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    if any((type(item) is not TargetTaskBundle for item in frozen_bundles)):
        raise TypeError("target randomization requires typed task bundles")
    bundle_ids = tuple((item.target_task_bundle_id for item in frozen_bundles))
    if len(set(bundle_ids)) != len(bundle_ids):
        raise ValueError("target task bundles must be unique")
    coordinates = tuple(((item.policy_key, item.task_unit_id) for item in frozen_bundles))
    if len(set(coordinates)) != len(coordinates):
        raise ValueError("one policy/task coordinate may have only one realization bundle")
    allocations = allocate_target_realizations(plan)
    if set(coordinates) != set(allocations):
        raise ValueError("task bundles must retain every allocated task, including exclusions")
    weights = {(policy, r): q for policy, r, q in plan.realization_weights}
    strata = {(policy, unit): s for policy, unit, s in plan.allocation_tasks}
    for bundle in frozen_bundles:
        coordinate = (bundle.policy_key, bundle.task_unit_id)
        if (
            bundle.realization_id != allocations[coordinate]
            or bundle.realization_weight != weights[bundle.policy_key, bundle.realization_id]
            or bundle.stratum_id != strata[coordinate]
        ):
            raise ValueError("task bundle failed frozen realization allocation replay")
    successful = tuple((item for item in dispatch.records if item.status is BridgeStatus.SUCCESS))
    successful_policy_keys = {item.policy_key for item in successful}
    if {item.policy_key for item in frozen_bundles} != successful_policy_keys:
        raise ValueError("task bundles must exactly cover successfully protocolized policies")
    track_by_policy: dict[str, PolicyTrack] = {}
    for entry in dispatch.union.entries:
        previous = track_by_policy.setdefault(entry.candidate.policy_key, entry.track)
        if previous is not entry.track:
            raise ValueError("one semantic policy cannot cross Atomic tracks")
    protocol_by_policy: dict[str, str] = {}
    for record in successful:
        previous = protocol_by_policy.setdefault(record.policy_key, record.protocol_record_id)
        if previous != record.protocol_record_id:
            raise ValueError("one semantic policy must share one protocolization record")
    for bundle in frozen_bundles:
        if (
            bundle.track is not track_by_policy[bundle.policy_key]
            or bundle.protocol_record_id != protocol_by_policy[bundle.policy_key]
        ):
            raise ValueError("target task bundle drifted from shared policy protocolization")
    bundles_by_policy: dict[str, list[TargetTaskBundle]] = defaultdict(list)
    for bundle in frozen_bundles:
        if bundle.exclusion_reason is None:
            bundles_by_policy[bundle.policy_key].append(bundle)
    assignments = []
    for record in successful:
        track = track_by_policy[record.policy_key]
        arms = ATOMIC_CONFIRMATORY_ARMS
        slot_count = plan.atomic_total_block_slots
        arm_copies = tuple(
            ((arm, repeat) for repeat in range(slot_count // len(arms)) for arm in arms)
        )
        for bundle in bundles_by_policy[record.policy_key]:
            block_id = _target_assigned_block_id(record, track, bundle)
            ordered_arms = tuple(
                (
                    arm
                    for arm, repeat in sorted(
                        arm_copies,
                        key=lambda item: content_hash(
                            {
                                "assignment_seed": plan.assignment_seed,
                                "block_id": block_id,
                                "arm": item[0],
                                "repeat": item[1],
                            }
                        ),
                    )
                )
            )
            for request_slot, arm in enumerate(ordered_arms):
                provider_seed = (
                    None
                    if plan.provider_seed_root is None
                    else int(
                        content_hash(
                            {
                                "provider_seed_root": plan.provider_seed_root,
                                "block_id": block_id,
                                "request_randomness_slot": request_slot,
                                "arm": arm,
                            }
                        )[:8],
                        16,
                    )
                    & 2147483647
                )
                assignments.append(
                    AssignedArmITTRecord(
                        record.candidate_record_id,
                        record.effect_coordinate_id,
                        record.policy_key,
                        record.model_id,
                        track,
                        bundle.task_unit_id,
                        bundle.task_instance_id,
                        bundle.stratum_id,
                        bundle.realization_id,
                        bundle.task_bundle_id,
                        bundle.protocol_record_id,
                        request_slot,
                        arm,
                        bundle.task_instance_weight,
                        bundle.realization_weight,
                        bundle.variant(arm).variant_sha256,
                        provider_seed,
                    )
                )
    return tuple(sorted(assignments, key=lambda item: item.assignment_id))


def _target_assigned_block_id(
    dispatch: ConfirmationDispatchRecord,
    track: PolicyTrack,
    bundle: TargetTaskBundle,
) -> str:
    return content_id(
        "assigned_arm_itt_block_",
        {
            "candidate_record_id": dispatch.candidate_record_id,
            "effect_coordinate_id": dispatch.effect_coordinate_id,
            "policy_key": dispatch.policy_key,
            "model_id": dispatch.model_id,
            "track": track,
            "task_unit_id": bundle.task_unit_id,
            "task_instance_id": bundle.task_instance_id,
            "stratum_id": bundle.stratum_id,
            "realization_id": bundle.realization_id,
            "task_bundle_id": bundle.task_bundle_id,
            "protocol_record_id": bundle.protocol_record_id,
            "task_instance_weight": bundle.task_instance_weight,
            "realization_weight": bundle.realization_weight,
        },
    )

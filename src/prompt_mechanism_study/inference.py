"""Task-unit ITT and simultaneous inference for active successor studies."""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.intervention import (
    FACTORIAL_CELL_ORDER,
    SUCCESSOR_ARM_ROLE_ORDER,
    FactorialCell,
    FactorialPolicy,
    InterventionPolicyV2,
    PolicyArmRoleV2,
)
from prompt_mechanism_study.measurement import InfrastructureFailure
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    ConfirmationDispatchRecord,
    PolicyTrack,
    SlotStatus,
)
from prompt_mechanism_study.randomization import (
    FactorialAssignment,
    FactorialRandomization,
    SuccessorAssignment,
    SuccessorRandomization,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.representation import ExpectedDirection, Task


class Metric(StrEnum):
    CODE_VALID = "code_valid"
    ORACLE_EVALUABLE = "oracle_evaluable"
    SECURE_YIELD = "secure_yield"
    FUNCTIONALITY = "functionality"
    JOINT = "joint"


class FactorialEffect(StrEnum):
    FACTOR_1 = "factor_1"
    FACTOR_2 = "factor_2"
    FACTOR_1_GIVEN_FACTOR_2 = "factor_1_given_factor_2"
    FACTOR_2_GIVEN_FACTOR_1 = "factor_2_given_factor_1"
    JOINT = "joint"
    INTERACTION = "interaction"


class FactorialPattern(StrEnum):
    """Descriptive response-surface patterns; never an assignment filter."""

    ADDITIVE = "additive"
    POSITIVE_INTERACTION = "positive_interaction"
    NEGATIVE_INTERACTION = "negative_interaction"
    XOR = "xor"
    REDUNDANT = "redundant"
    PREREQUISITE = "prerequisite"
    REVERSAL = "reversal"
    NOT_EVALUABLE = "not_evaluable"


class FactorialMetricFamily(StrEnum):
    """Separate multiplicity families for distinct scientific endpoints."""

    FUNCTIONALITY = "functionality"
    JOINT = "joint"


class SuccessorContrast(StrEnum):
    """Frozen four-arm contrasts; only Target-Noop is confirmatory primary."""

    TARGET_NOOP = "target_minus_noop"
    TARGET_PLACEBO = "target_minus_placebo"
    TARGET_GENERIC = "target_minus_generic"

    @property
    def roles(self) -> tuple[PolicyArmRoleV2, PolicyArmRoleV2]:
        return {
            SuccessorContrast.TARGET_NOOP: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.NOOP,
            ),
            SuccessorContrast.TARGET_PLACEBO: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.PLACEBO,
            ),
            SuccessorContrast.TARGET_GENERIC: (
                PolicyArmRoleV2.TARGET,
                PolicyArmRoleV2.GENERIC,
            ),
        }[self]


class SuccessorIntervalFamily(StrEnum):
    PRIMARY_SECURITY = "primary_target_noop_secure_yield"
    SECURITY_SPECIFICITY = "target_specificity_secure_yield"
    JOINT_OUTCOME = "target_noop_joint_outcome"


class FamilyInferenceStatus(StrEnum):
    EVALUABLE = "evaluable"
    NO_ELIGIBLE_COORDINATES = "no_eligible_coordinates"
    ZERO_STANDARD_ERROR = "zero_standard_error"
    INSUFFICIENT_VALID_BOOTSTRAP = "insufficient_valid_bootstrap"


class SuccessorRobustnessComponent(StrEnum):
    """Members of the frozen global realization-robustness family."""

    REALIZATION = "realization"
    LEAVE_ONE_REALIZATION_OUT = "leave_one_realization_out"


class FunctionalityGateStatus(StrEnum):
    """Status of the optional, separately powered functionality gate."""

    NOT_REQUESTED = "not_requested"
    NOT_EVALUABLE = "not_evaluable"
    PASSED = "passed"
    FAILED = "failed"


class ConfirmatoryArm(StrEnum):
    ATOMIC_TARGET = "atomic_target"
    ATOMIC_NOOP = "atomic_noop"
    ATOMIC_PLACEBO = "atomic_placebo"
    ATOMIC_GENERIC = "atomic_generic"
    PAIR_00 = "pair_00"
    PAIR_10 = "pair_10"
    PAIR_01 = "pair_01"
    PAIR_11 = "pair_11"


ATOMIC_CONFIRMATORY_ARMS = (
    ConfirmatoryArm.ATOMIC_TARGET,
    ConfirmatoryArm.ATOMIC_NOOP,
    ConfirmatoryArm.ATOMIC_PLACEBO,
    ConfirmatoryArm.ATOMIC_GENERIC,
)
PAIR_CONFIRMATORY_ARMS = (
    ConfirmatoryArm.PAIR_00,
    ConfirmatoryArm.PAIR_10,
    ConfirmatoryArm.PAIR_01,
    ConfirmatoryArm.PAIR_11,
)


class ConfirmatoryEffectStatus(StrEnum):
    POSITIVE_MEANINGFUL = "POSITIVE_MEANINGFUL"
    NEGATIVE_MEANINGFUL = "NEGATIVE_MEANINGFUL"
    PRACTICALLY_NULL = "PRACTICALLY_NULL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NON_EVALUABLE = "NON_EVALUABLE"


class TargetFamilyStatus(StrEnum):
    EVALUABLE = "EVALUABLE"
    NO_ELIGIBLE_COORDINATES = "NO_ELIGIBLE_COORDINATES"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    INSUFFICIENT_SUPPORT = "INSUFFICIENT_SUPPORT"
    ZERO_STANDARD_ERROR = "ZERO_STANDARD_ERROR"
    INSUFFICIENT_VALID_BOOTSTRAP = "INSUFFICIENT_VALID_BOOTSTRAP"


class EvidenceLevel(StrEnum):
    SPECIFIED = "specified"
    IMPLEMENTED = "implemented"
    TESTED = "tested"
    EXECUTED = "executed"
    REPORTED = "reported"


TARGET_ENDPOINT_ORDER = (
    Metric.SECURE_YIELD,
    Metric.CODE_VALID,
    Metric.ORACLE_EVALUABLE,
    Metric.FUNCTIONALITY,
    Metric.JOINT,
)


@dataclass(frozen=True, slots=True)
class TargetITTPlan:
    """Direction-free primary family contract for the target v3 method."""

    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float
    minimum_task_units_per_stratum: int
    minimum_valid_bootstrap_fraction: float
    atomic_practical_margin: float
    pair_practical_margin: float
    maximum_unknown_fraction_among_valid: float
    metrics: tuple[Metric, ...] = TARGET_ENDPOINT_ORDER
    bootstrap_quantile_method: str = "higher"

    def __post_init__(self) -> None:
        if type(self.bootstrap_seed) is not int:
            raise TypeError("target ITT bootstrap seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("target ITT bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0 < self.alpha < 1:
            raise ValueError("target ITT alpha must be strictly between zero and one")
        if (
            type(self.minimum_task_units_per_stratum) is not int
            or self.minimum_task_units_per_stratum < 2
        ):
            raise ValueError("target ITT needs at least two task units per stratum")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0 < self.minimum_valid_bootstrap_fraction <= 1
        ):
            raise ValueError("target ITT valid-bootstrap fraction must be in (0, 1]")
        for value, name in (
            (self.atomic_practical_margin, "atomic practical margin"),
            (self.pair_practical_margin, "pair practical margin"),
            (
                self.maximum_unknown_fraction_among_valid,
                "maximum unknown fraction among valid code",
            ),
        ):
            if type(value) is not float or not 0 <= value <= 1:
                raise ValueError(f"{name} must be a float on [0, 1]")
        if self.metrics != TARGET_ENDPOINT_ORDER:
            raise ValueError("target endpoint order must be secure, valid, evaluable, functional, joint")
        if self.bootstrap_quantile_method != "higher":
            raise ValueError("target ITT bootstrap quantile method must be higher")

    @property
    def target_itt_plan_id(self) -> str:
        return content_id("target_itt_plan_", self)


@dataclass(frozen=True, slots=True)
class TargetRandomizationPlan:
    """Outcome-blind complete-block assignment rule for the target protocol."""

    protocol_id: str
    schema_version: str
    assignment_seed: int
    provider_seed_root: int | None
    atomic_total_block_slots: int
    pair_total_block_slots: int
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
        for value, name in (
            (self.atomic_total_block_slots, "Atomic total block slots"),
            (self.pair_total_block_slots, "Pair total block slots"),
        ):
            if type(value) is not int or value <= 0 or value % 4:
                raise ValueError(f"{name} must be a positive multiple of four")
        if self.algorithm_id != "sha256_ranked_complete_block_v1":
            raise ValueError("target randomization algorithm is not the frozen algorithm")

    @property
    def target_randomization_plan_id(self) -> str:
        return content_id("target_randomization_plan_", self)


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
        expected = (
            ATOMIC_CONFIRMATORY_ARMS
            if self.track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        if tuple(item.arm for item in self.variants) != expected:
            raise ValueError("target task bundle must contain its four arms in canonical order")
        if any(type(item) is not TargetTaskArmVariant for item in self.variants):
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
        allowed = (
            ATOMIC_CONFIRMATORY_ARMS
            if self.track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
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
    def assignment_id(self) -> str:
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
    if not frozen_bundles or any(type(item) is not TargetTaskBundle for item in frozen_bundles):
        raise TypeError("target randomization requires typed task bundles")
    bundle_ids = tuple(item.target_task_bundle_id for item in frozen_bundles)
    if len(set(bundle_ids)) != len(bundle_ids):
        raise ValueError("target task bundles must be unique")
    coordinates = tuple((item.policy_key, item.task_unit_id) for item in frozen_bundles)
    if len(set(coordinates)) != len(coordinates):
        raise ValueError("one policy/task coordinate may have only one realization bundle")

    successful = tuple(
        item for item in dispatch.records if item.status is BridgeStatus.SUCCESS
    )
    successful_policy_keys = {item.policy_key for item in successful}
    if {item.policy_key for item in frozen_bundles} != successful_policy_keys:
        raise ValueError("task bundles must exactly cover successfully protocolized policies")
    track_by_policy: dict[str, PolicyTrack] = {}
    for entry in dispatch.union.entries:
        previous = track_by_policy.setdefault(entry.candidate.policy_key, entry.track)
        if previous is not entry.track:
            raise ValueError("one semantic policy cannot cross Atomic and Pair tracks")
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
        bundles_by_policy[bundle.policy_key].append(bundle)
    assignments = []
    for record in successful:
        track = track_by_policy[record.policy_key]
        arms = ATOMIC_CONFIRMATORY_ARMS if track is PolicyTrack.ATOMIC else PAIR_CONFIRMATORY_ARMS
        slot_count = (
            plan.atomic_total_block_slots
            if track is PolicyTrack.ATOMIC
            else plan.pair_total_block_slots
        )
        arm_copies = tuple(
            (arm, repeat)
            for repeat in range(slot_count // len(arms))
            for arm in arms
        )
        for bundle in bundles_by_policy[record.policy_key]:
            block_id = _target_assigned_block_id(record, track, bundle)
            ordered_arms = tuple(
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
                    & 0x7FFFFFFF
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


@dataclass(frozen=True, slots=True)
class AssignedArmEvidenceLedger:
    """Exact partition of every frozen assignment into outcome or repair failure."""

    dispatch: ConfirmationDispatchManifest
    assignments: tuple[AssignedArmITTRecord, ...]
    outcomes: tuple[Outcome, ...]
    infrastructure_failures: tuple[InfrastructureFailure, ...]

    def __post_init__(self) -> None:
        if type(self.dispatch) is not ConfirmationDispatchManifest:
            raise TypeError("assigned-arm ledger requires a confirmation dispatch manifest")
        if any(type(item) is not AssignedArmITTRecord for item in self.assignments):
            raise TypeError("assigned-arm ledger assignments must be typed")
        if tuple(sorted(self.assignments, key=lambda item: item.assignment_id)) != self.assignments:
            raise ValueError("assigned-arm records must use canonical assignment order")
        assignment_ids = tuple(item.assignment_id for item in self.assignments)
        if len(set(assignment_ids)) != len(assignment_ids):
            raise ValueError("assigned-arm assignment identities must be unique")
        if any(type(item) is not Outcome for item in self.outcomes):
            raise TypeError("assigned-arm outcomes must be typed")
        if tuple(sorted(self.outcomes, key=lambda item: item.assignment_id)) != self.outcomes:
            raise ValueError("assigned-arm outcomes must use canonical assignment order")
        if any(
            type(item) is not InfrastructureFailure
            for item in self.infrastructure_failures
        ):
            raise TypeError("assigned-arm infrastructure failures must be typed")
        if tuple(
            sorted(self.infrastructure_failures, key=lambda item: item.assignment_id)
        ) != self.infrastructure_failures:
            raise ValueError("assigned-arm failures must use canonical assignment order")
        completed = tuple(item.assignment_id for item in self.outcomes)
        failed = tuple(item.assignment_id for item in self.infrastructure_failures)
        if set(completed) & set(failed) or set(completed) | set(failed) != set(assignment_ids):
            raise ValueError("every assignment needs exactly one outcome or repair failure")
        if len(set(completed)) != len(completed) or len(set(failed)) != len(failed):
            raise ValueError("assignment evidence cannot be duplicated")
        dispatch_by_candidate = {
            item.candidate_record_id: item for item in self.dispatch.records
        }
        for assignment in self.assignments:
            dispatch = dispatch_by_candidate.get(assignment.candidate_record_id)
            if dispatch is None or dispatch.status is not BridgeStatus.SUCCESS:
                raise ValueError("only successfully protocolized candidates may have assignments")
            if (
                assignment.effect_coordinate_id != dispatch.effect_coordinate_id
                or assignment.policy_key != dispatch.policy_key
                or assignment.model_id != dispatch.model_id
                or assignment.protocol_record_id != dispatch.protocol_record_id
            ):
                raise ValueError("assigned arm drifted from its model-bound dispatch")
        successful = {
            item.candidate_record_id
            for item in self.dispatch.records
            if item.status is BridgeStatus.SUCCESS
        }
        if {item.candidate_record_id for item in self.assignments} != successful:
            raise ValueError("every successful dispatch must have frozen assignments")
        by_block: dict[str, list[AssignedArmITTRecord]] = defaultdict(list)
        for assignment in self.assignments:
            by_block[assignment.block_id].append(assignment)
        for block in by_block.values():
            allowed = (
                ATOMIC_CONFIRMATORY_ARMS
                if block[0].track is PolicyTrack.ATOMIC
                else PAIR_CONFIRMATORY_ARMS
            )
            counts = Counter(item.arm for item in block)
            if set(counts) != set(allowed) or len(set(counts.values())) != 1:
                raise ValueError("every assigned block must be balanced over all four arms")
            slots = tuple(item.request_randomness_slot for item in block)
            if len(set(slots)) != len(slots):
                raise ValueError("request-randomness slots must be unique inside a block")

    @property
    def evidence_ledger_id(self) -> str:
        return content_id("assigned_arm_evidence_ledger_", self)


def freeze_assigned_arm_evidence(
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[AssignedArmITTRecord],
    outcomes: Sequence[Outcome],
    infrastructure_failures: Sequence[InfrastructureFailure] = (),
) -> AssignedArmEvidenceLedger:
    return AssignedArmEvidenceLedger(
        dispatch,
        tuple(sorted(assignments, key=lambda item: item.assignment_id)),
        tuple(sorted(outcomes, key=lambda item: item.assignment_id)),
        tuple(sorted(infrastructure_failures, key=lambda item: item.assignment_id)),
    )


def classify_confirmatory_interval(
    lower: float | None,
    upper: float | None,
    practical_margin: float,
    *,
    evaluable: bool,
) -> ConfirmatoryEffectStatus:
    """Apply the exact two-sided five-status rule without expected direction."""

    if type(evaluable) is not bool:
        raise TypeError("confirmatory evaluability must be boolean")
    if (
        type(practical_margin) is not float
        or not math.isfinite(practical_margin)
        or practical_margin < 0
    ):
        raise ValueError("confirmatory practical margin must be finite and nonnegative")
    if not evaluable:
        return ConfirmatoryEffectStatus.NON_EVALUABLE
    if (
        type(lower) not in {int, float}
        or type(upper) not in {int, float}
        or not math.isfinite(float(lower))
        or not math.isfinite(float(upper))
        or lower > upper
    ):
        raise ValueError("an evaluable confirmatory interval must be finite and ordered")
    if lower > practical_margin:
        return ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL
    if upper < -practical_margin:
        return ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL
    if -practical_margin <= lower and upper <= practical_margin:
        return ConfirmatoryEffectStatus.PRACTICALLY_NULL
    return ConfirmatoryEffectStatus.INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class SuccessorAnalysisPlan:
    """Pre-outcome analysis contract for atomic ADD/REMOVE four-arm policies."""

    metrics: tuple[Metric, ...]
    primary_metric: Metric
    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float
    minimum_task_units: int = 2
    minimum_valid_bootstrap_fraction: float = 0.9
    practical_effect_margin: float = 0.0
    functionality_noninferiority_margin: float = 0.1
    minimum_realizations: int = 2
    minimum_task_units_per_realization: int = 2
    realization_practical_equivalence_margin: float = 0.1
    realization_direction_consistency_threshold: float = 1.0
    functionality_noninferiority_separately_powered: bool = False
    minimum_replication_models: int = 2
    cross_model_replication_rule: str = (
        "oriented_simultaneous_target_noop_each_model_no_pooling"
    )

    def __post_init__(self) -> None:
        if not self.metrics or len(self.metrics) != len(set(self.metrics)):
            raise ValueError("successor analysis metrics must be non-empty and unique")
        if any(type(metric) is not Metric for metric in self.metrics):
            raise TypeError("successor analysis metrics must be Metric values")
        if self.primary_metric is not Metric.SECURE_YIELD or self.primary_metric not in self.metrics:
            raise ValueError("successor primary metric must be secure yield")
        if Metric.JOINT not in self.metrics or Metric.FUNCTIONALITY not in self.metrics:
            raise ValueError("successor analysis requires joint and functionality diagnostics")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float strictly between zero and one")
        if type(self.minimum_task_units) is not int or self.minimum_task_units < 2:
            raise ValueError("minimum_task_units must be at least two")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0.0 < self.minimum_valid_bootstrap_fraction <= 1.0
        ):
            raise ValueError("minimum_valid_bootstrap_fraction must be in (0, 1]")
        for name in (
            "practical_effect_margin",
            "functionality_noninferiority_margin",
            "realization_practical_equivalence_margin",
            "realization_direction_consistency_threshold",
        ):
            value = getattr(self, name)
            if type(value) is not float or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be a float in [0, 1]")
        if type(self.minimum_realizations) is not int or self.minimum_realizations < 2:
            raise ValueError("minimum_realizations must be at least two")
        if (
            type(self.minimum_task_units_per_realization) is not int
            or self.minimum_task_units_per_realization < 2
        ):
            raise ValueError(
                "minimum_task_units_per_realization must be at least two"
            )
        if type(self.functionality_noninferiority_separately_powered) is not bool:
            raise TypeError(
                "functionality_noninferiority_separately_powered must be boolean"
            )
        if type(self.minimum_replication_models) is not int or self.minimum_replication_models < 2:
            raise ValueError("minimum_replication_models must be at least two")
        if self.cross_model_replication_rule != (
            "oriented_simultaneous_target_noop_each_model_no_pooling"
        ):
            raise ValueError("unsupported successor cross-model replication rule")
        if self.realization_direction_consistency_threshold <= 0.0:
            raise ValueError(
                "realization_direction_consistency_threshold must be in (0, 1]"
            )

    @property
    def analysis_plan_id(self) -> str:
        return content_id("successor_analysis_plan_v2_", self)


@dataclass(frozen=True, slots=True)
class FactorialAnalysisPlan:
    """Prospectively frozen factorial inference contract."""

    metrics: tuple[Metric, ...]
    primary_metric: Metric
    bootstrap_seed: int
    bootstrap_draws: int
    alpha: float
    secondary_effects: tuple[FactorialEffect, ...] = (
        FactorialEffect.FACTOR_1,
        FactorialEffect.FACTOR_2,
        FactorialEffect.JOINT,
    )
    minimum_task_units: int = 2
    minimum_valid_bootstrap_fraction: float = 0.9
    bootstrap_quantile_method: str = "higher"
    practical_interaction_margin: float = 0.0
    maximum_unknown_fraction: float = 1.0
    functionality_noninferiority_margin: float = 0.1
    functionality_noninferiority_separately_powered: bool = False
    functionality_power_qualification_sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.metrics or len(self.metrics) != len(set(self.metrics)):
            raise ValueError("factorial analysis metrics must be non-empty and unique")
        if any(type(metric) is not Metric for metric in self.metrics):
            raise TypeError("factorial analysis metrics must be Metric values")
        if self.primary_metric is not Metric.SECURE_YIELD or self.primary_metric not in self.metrics:
            raise ValueError("factorial primary metric must be secure yield")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("bootstrap_seed must be an integer")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("bootstrap_draws must be at least 100")
        if type(self.alpha) is not float or not 0.0 < self.alpha < 1.0:
            raise ValueError("alpha must be a float strictly between zero and one")
        if (
            not self.secondary_effects
            or len(self.secondary_effects) != len(set(self.secondary_effects))
            or any(
                type(effect) is not FactorialEffect
                or effect is FactorialEffect.INTERACTION
                for effect in self.secondary_effects
            )
        ):
            raise ValueError("secondary factorial effects must be unique non-interactions")
        if type(self.minimum_task_units) is not int or self.minimum_task_units < 2:
            raise ValueError("factorial minimum_task_units must be at least two")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0.0 < self.minimum_valid_bootstrap_fraction <= 1.0
        ):
            raise ValueError(
                "factorial minimum_valid_bootstrap_fraction must be in (0, 1]"
            )
        if self.bootstrap_quantile_method != "higher":
            raise ValueError("factorial bootstrap quantile method must be higher")
        for name in (
            "practical_interaction_margin",
            "maximum_unknown_fraction",
            "functionality_noninferiority_margin",
        ):
            value = getattr(self, name)
            if type(value) is not float or not 0.0 <= value <= 1.0:
                raise ValueError(f"factorial {name} must be a float in [0, 1]")
        if type(self.functionality_noninferiority_separately_powered) is not bool:
            raise TypeError(
                "factorial functionality_noninferiority_separately_powered must be boolean"
            )
        qualification = self.functionality_power_qualification_sha256
        if self.functionality_noninferiority_separately_powered:
            if (
                not isinstance(qualification, str)
                or len(qualification) != 64
                or any(character not in "0123456789abcdef" for character in qualification)
            ):
                raise ValueError(
                    "a separately powered functionality gate requires a frozen power qualification"
                )
        elif qualification is not None:
            raise ValueError(
                "an unrequested functionality gate cannot bind a power qualification"
            )

    @property
    def analysis_plan_id(self) -> str:
        return content_id("factorial_analysis_plan_v2_", self)


@dataclass(frozen=True, slots=True)
class SuccessorArmEstimate:
    role: PolicyArmRoleV2
    point: float | None
    lower: float
    upper: float
    assignments: int


@dataclass(frozen=True, slots=True)
class SuccessorContrastEstimate:
    contrast: SuccessorContrast
    point: float | None
    lower_bound: float
    upper_bound: float


@dataclass(frozen=True, slots=True)
class TaskUnitSuccessorContribution:
    task_unit_id: str
    arm_values: tuple[tuple[PolicyArmRoleV2, float | None, float, float], ...]
    contrast_values: tuple[tuple[SuccessorContrast, float | None, float, float], ...]

    def contrast(self, value: SuccessorContrast) -> tuple[float | None, float, float]:
        return next((point, lower, upper) for item, point, lower, upper in self.contrast_values if item is value)


@dataclass(frozen=True, slots=True)
class RealizationSuccessorEffect:
    realization_spec_id: str
    point: float | None
    lower_bound: float
    upper_bound: float
    task_unit_effects: tuple[tuple[str, float | None, float, float], ...] = ()


@dataclass(frozen=True, slots=True)
class LeaveOneRealizationOutSuccessorEffect:
    omitted_realization_spec_id: str
    point: float | None
    lower_bound: float
    upper_bound: float
    task_unit_effects: tuple[tuple[str, float | None, float, float], ...] = ()


@dataclass(frozen=True, slots=True)
class SuccessorCoordinateEstimate:
    hypothesis_id: str
    model_id: str
    metric: Metric
    expected_direction: ExpectedDirection
    arms: tuple[SuccessorArmEstimate, ...]
    contrasts: tuple[SuccessorContrastEstimate, ...]
    task_unit_contributions: tuple[TaskUnitSuccessorContribution, ...]
    realization_effects: tuple[RealizationSuccessorEffect, ...]
    robustness_label: str
    leave_one_realization_out: tuple[
        LeaveOneRealizationOutSuccessorEffect, ...
    ] = ()

    def __post_init__(self) -> None:
        if tuple(item.role for item in self.arms) != SUCCESSOR_ARM_ROLE_ORDER:
            raise ValueError("successor arm estimates must use canonical four-role order")
        if tuple(item.contrast for item in self.contrasts) != tuple(SuccessorContrast):
            raise ValueError("successor contrasts must use canonical order")

    @property
    def coordinate_id(self) -> str:
        return content_id(
            "successor_coordinate_v2_",
            {
                "hypothesis_id": self.hypothesis_id,
                "model_id": self.model_id,
                "metric": self.metric,
            },
        )

    def contrast(self, value: SuccessorContrast) -> SuccessorContrastEstimate:
        return next(item for item in self.contrasts if item.contrast is value)


@dataclass(frozen=True, slots=True)
class SuccessorSimultaneousInterval:
    coordinate_id: str
    contrast: SuccessorContrast
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SuccessorFamilyInference:
    family: SuccessorIntervalFamily
    status: FamilyInferenceStatus
    simultaneous_critical_value: float | None
    valid_bootstrap_draws: int
    invalid_bootstrap_draws: int
    intervals: tuple[SuccessorSimultaneousInterval, ...]


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessInterval:
    coordinate_id: str
    component: SuccessorRobustnessComponent
    realization_spec_id: str
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessAssessment:
    coordinate_id: str
    direction_consistency_proportion: float | None
    direction_consistency_passed: bool
    simultaneous_direction_passed: bool
    minimum_support_passed: bool
    heterogeneity_max_deviation: float | None
    heterogeneity_simultaneous_upper: float | None
    heterogeneity_equivalence_passed: bool
    arm_realization_interaction_statistic: float | None
    arm_realization_randomization_p_value: float | None
    arm_realization_interaction_passed: bool
    functionality_gate_status: FunctionalityGateStatus
    functionality_point: float | None
    functionality_simultaneous_lower: float | None
    robustness_label: str
    practical_success_label: str


@dataclass(frozen=True, slots=True)
class SuccessorRobustnessInference:
    status: FamilyInferenceStatus
    simultaneous_critical_value: float | None
    valid_bootstrap_draws: int
    invalid_bootstrap_draws: int
    intervals: tuple[SuccessorRobustnessInterval, ...]
    functionality_simultaneous_critical_value: float | None
    assessments: tuple[SuccessorRobustnessAssessment, ...]


@dataclass(frozen=True, slots=True)
class SuccessorInferenceResult:
    plan_id: str
    estimates: tuple[SuccessorCoordinateEstimate, ...]
    families: tuple[SuccessorFamilyInference, ...]
    robustness: SuccessorRobustnessInference | None = None

    @property
    def inference_id(self) -> str:
        return content_id("successor_inference_v2_", self)


@dataclass(frozen=True, slots=True)
class FactorialCellEstimate:
    cell: FactorialCell
    point: float | None
    lower: float
    upper: float
    assignments: int


@dataclass(frozen=True, slots=True)
class TaskUnitFactorialEffect:
    task_unit_id: str
    cell_points: tuple[tuple[FactorialCell, float | None], ...]
    interaction: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialRealizationInteraction:
    realization_id: str
    application_order: tuple[int, int]
    weight: int
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialOrderInteraction:
    application_order: tuple[int, int]
    total_weight: int
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialLeaveOneRealizationOut:
    omitted_realization_id: str
    point: float | None
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialRealizationDiagnostics:
    realization_interactions: tuple[FactorialRealizationInteraction, ...]
    order_interactions: tuple[FactorialOrderInteraction, ...]
    leave_one_realization_out: tuple[FactorialLeaveOneRealizationOut, ...]
    direction_robustness: str


@dataclass(frozen=True, slots=True)
class FactorialCoordinateEstimate:
    pair_id: str
    model_id: str
    metric: Metric
    cells: tuple[FactorialCellEstimate, ...]
    factor_1: float | None
    factor_2: float | None
    factor_1_given_factor_2: float | None
    factor_2_given_factor_1: float | None
    joint: float | None
    interaction: float | None
    factor_1_bounds: tuple[float, float]
    factor_2_bounds: tuple[float, float]
    factor_1_given_factor_2_bounds: tuple[float, float]
    factor_2_given_factor_1_bounds: tuple[float, float]
    joint_bounds: tuple[float, float]
    interaction_bounds: tuple[float, float]
    task_unit_effects: tuple[TaskUnitFactorialEffect, ...]
    response_pattern: FactorialPattern
    realization_diagnostics: FactorialRealizationDiagnostics

    @property
    def coordinate_id(self) -> str:
        return content_id(
            "factorial_coordinate_",
            {"pair_id": self.pair_id, "model_id": self.model_id, "metric": self.metric},
        )


@dataclass(frozen=True, slots=True)
class FactorialSimultaneousInterval:
    coordinate_id: str
    effect: FactorialEffect
    standard_error: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class FactorialMetricFamilyInference:
    family: FactorialMetricFamily
    metric: Metric
    intervals: tuple[FactorialSimultaneousInterval, ...]
    simultaneous_critical_value: float


@dataclass(frozen=True, slots=True)
class FactorialInferenceResult:
    plan_id: str
    estimates: tuple[FactorialCoordinateEstimate, ...]
    intervals: tuple[FactorialSimultaneousInterval, ...]
    simultaneous_critical_value: float
    secondary_intervals: tuple[FactorialSimultaneousInterval, ...] = ()
    secondary_critical_value: float = 0.0
    metric_families: tuple[FactorialMetricFamilyInference, ...] = ()

    @property
    def inference_id(self) -> str:
        return content_id("factorial_inference_", self)


@dataclass(frozen=True, slots=True)
class TargetArmEndpointSummary:
    arm: ConfirmatoryArm
    assignments: int
    secure_yield: float
    code_validity: float
    oracle_evaluability: float
    functionality_yield: float
    joint_success_yield: float
    oracle_unknown_valid_assignments: int
    terminal_assignments: int

    def __post_init__(self) -> None:
        if type(self.arm) is not ConfirmatoryArm:
            raise TypeError("target endpoint arm must be typed")
        if type(self.assignments) is not int or self.assignments <= 0:
            raise ValueError("target endpoint summary requires assignments")
        for value in (
            self.secure_yield,
            self.code_validity,
            self.oracle_evaluability,
            self.functionality_yield,
            self.joint_success_yield,
        ):
            if type(value) not in {int, float} or not math.isfinite(float(value)) or not 0 <= value <= 1:
                raise ValueError("target endpoint yields must be finite on [0, 1]")
        if not (
            type(self.oracle_unknown_valid_assignments) is int
            and type(self.terminal_assignments) is int
            and 0 <= self.oracle_unknown_valid_assignments <= self.assignments
            and 0 <= self.terminal_assignments <= self.assignments
        ):
            raise ValueError("target endpoint diagnostic counts are invalid")


@dataclass(frozen=True, slots=True)
class TargetTaskUnitContribution:
    task_unit_id: str
    stratum_id: str
    point: float
    latent_lower: float
    latent_upper: float

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "target contribution task_unit_id")
        require_text(self.stratum_id, "target contribution stratum_id")
        for value in (self.point, self.latent_lower, self.latent_upper):
            if type(value) not in {int, float} or not math.isfinite(float(value)):
                raise ValueError("target task-unit contributions must be finite")
        if self.latent_lower > self.latent_upper:
            raise ValueError("target latent contribution bounds must be ordered")


@dataclass(frozen=True, slots=True)
class TargetEffectEstimate:
    candidate_record_id: str
    effect_coordinate_id: str
    policy_key: str
    model_id: str
    track: PolicyTrack
    point: float | None
    standard_error: float | None
    simultaneous_lower: float | None
    simultaneous_upper: float | None
    latent_lower: float | None
    latent_upper: float | None
    practical_margin: float
    status: ConfirmatoryEffectStatus
    reasons: tuple[str, ...]
    task_units: int
    assignments: int
    arm_summaries: tuple[TargetArmEndpointSummary, ...]
    task_unit_contributions: tuple[TargetTaskUnitContribution, ...]

    def __post_init__(self) -> None:
        for name in (
            "candidate_record_id",
            "effect_coordinate_id",
            "policy_key",
            "model_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.track) is not PolicyTrack or type(self.status) is not ConfirmatoryEffectStatus:
            raise TypeError("target effect track and status must be typed")
        if type(self.practical_margin) is not float or not 0 <= self.practical_margin <= 1:
            raise ValueError("target practical margin must be a float on [0, 1]")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("target effect reasons must be canonical")
        values = (
            self.point,
            self.standard_error,
            self.simultaneous_lower,
            self.simultaneous_upper,
            self.latent_lower,
            self.latent_upper,
        )
        if any(
            value is not None
            and (type(value) not in {int, float} or not math.isfinite(float(value)))
            for value in values
        ):
            raise ValueError("target effect numeric evidence must be finite or null")
        if self.status is ConfirmatoryEffectStatus.NON_EVALUABLE:
            if not self.reasons or self.simultaneous_lower is not None or self.simultaneous_upper is not None:
                raise ValueError("a non-evaluable target effect requires reasons and no interval")
        elif self.reasons or any(
            value is None
            for value in (
                self.point,
                self.standard_error,
                self.simultaneous_lower,
                self.simultaneous_upper,
                self.latent_lower,
                self.latent_upper,
            )
        ):
            raise ValueError("an evaluable target effect requires complete evidence without reasons")
        if (
            self.simultaneous_lower is not None
            and self.simultaneous_upper is not None
            and self.simultaneous_lower > self.simultaneous_upper
        ):
            raise ValueError("target simultaneous interval must be ordered")
        if self.latent_lower is not None and self.latent_upper is not None and self.latent_lower > self.latent_upper:
            raise ValueError("target latent bounds must be ordered")
        if type(self.task_units) is not int or self.task_units < 0:
            raise ValueError("target task-unit count must be nonnegative")
        if type(self.assignments) is not int or self.assignments < 0:
            raise ValueError("target assignment count must be nonnegative")
        expected_arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if self.track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        if self.arm_summaries and tuple(item.arm for item in self.arm_summaries) != expected_arms:
            raise ValueError("target arm summaries must use canonical four-arm order")
        if tuple(
            sorted(
                self.task_unit_contributions,
                key=lambda item: item.task_unit_id,
            )
        ) != self.task_unit_contributions:
            raise ValueError("target task-unit contributions must use canonical order")


@dataclass(frozen=True, slots=True)
class TargetFamilyInference:
    track: PolicyTrack
    status: TargetFamilyStatus
    simultaneous_critical_value: float | None
    valid_bootstrap_draws: int
    invalid_bootstrap_draws: int
    estimates: tuple[TargetEffectEstimate, ...]

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack or type(self.status) is not TargetFamilyStatus:
            raise TypeError("target family track and status must be typed")
        if type(self.valid_bootstrap_draws) is not int or self.valid_bootstrap_draws < 0:
            raise ValueError("target valid bootstrap count must be nonnegative")
        if type(self.invalid_bootstrap_draws) is not int or self.invalid_bootstrap_draws < 0:
            raise ValueError("target invalid bootstrap count must be nonnegative")
        if tuple(sorted(self.estimates, key=lambda item: item.candidate_record_id)) != self.estimates:
            raise ValueError("target family estimates must use canonical candidate order")
        if any(item.track is not self.track for item in self.estimates):
            raise ValueError("target family cannot mix Atomic and Pair effects")
        if self.status is TargetFamilyStatus.EVALUABLE:
            if (
                type(self.simultaneous_critical_value) not in {int, float}
                or not math.isfinite(float(self.simultaneous_critical_value))
                or self.simultaneous_critical_value < 0
                or any(
                    item.status is ConfirmatoryEffectStatus.NON_EVALUABLE
                    for item in self.estimates
                )
            ):
                raise ValueError("an evaluable target family requires a critical value and statuses")
        elif self.simultaneous_critical_value is not None or any(
            item.status is not ConfirmatoryEffectStatus.NON_EVALUABLE
            for item in self.estimates
        ):
            raise ValueError("a non-evaluable target family cannot publish adjusted intervals")


@dataclass(frozen=True, slots=True)
class SharedEvidenceRecord:
    plan: TargetITTPlan
    ledger: AssignedArmEvidenceLedger
    families: tuple[TargetFamilyInference, TargetFamilyInference]
    evidence_level: EvidenceLevel

    def __post_init__(self) -> None:
        if type(self.plan) is not TargetITTPlan or type(self.ledger) is not AssignedArmEvidenceLedger:
            raise TypeError("shared evidence requires a target plan and assigned-arm ledger")
        if tuple(item.track for item in self.families) != (
            PolicyTrack.ATOMIC,
            PolicyTrack.PAIR,
        ):
            raise ValueError("shared evidence must contain Atomic then Pair families")
        if type(self.evidence_level) is not EvidenceLevel:
            raise TypeError("shared evidence level must be typed")
        estimated = {
            item.candidate_record_id
            for family in self.families
            for item in family.estimates
        }
        successful = {
            item.candidate_record_id
            for item in self.ledger.dispatch.records
            if item.status is BridgeStatus.SUCCESS
        }
        if estimated != successful:
            raise ValueError("shared evidence must represent every successful dispatch once")

    @property
    def shared_evidence_record_id(self) -> str:
        return content_id("shared_evidence_record_", self)


@dataclass(frozen=True, slots=True)
class TargetSlotYieldRecord:
    slot_id: str
    track: PolicyTrack
    selector_id: str
    model_id: str
    rank: int
    slot_status: SlotStatus
    candidate_record_id: str | None
    effect_status: ConfirmatoryEffectStatus | None
    meaningful_yield: int
    reason_code: str | None

    def __post_init__(self) -> None:
        for value, name in (
            (self.slot_id, "yield slot_id"),
            (self.selector_id, "yield selector_id"),
            (self.model_id, "yield model_id"),
        ):
            require_text(value, name)
        if type(self.track) is not PolicyTrack or type(self.slot_status) is not SlotStatus:
            raise TypeError("yield track and slot status must be typed")
        if type(self.rank) is not int or self.rank <= 0 or self.meaningful_yield not in {0, 1}:
            raise ValueError("yield rank or contribution is invalid")
        expected = int(
            self.effect_status
            in {
                ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL,
                ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL,
            }
        )
        if self.meaningful_yield != expected:
            raise ValueError("slot meaningful yield must follow the five-status rule")
        if self.slot_status is SlotStatus.FILLED:
            require_text(self.candidate_record_id, "yield candidate_record_id")
        elif self.candidate_record_id is not None or self.effect_status is not None:
            raise ValueError("an unfilled yield slot cannot reference an effect")
        if self.meaningful_yield and self.reason_code is not None:
            raise ValueError("a meaningful slot contribution cannot have a failure reason")
        if not self.meaningful_yield and not self.reason_code:
            raise ValueError("a zero-yield slot must retain its reason or effect status")


@dataclass(frozen=True, slots=True)
class TargetSelectorYield:
    track: PolicyTrack
    selector_id: str
    model_id: str
    top_k: int
    meaningful_slots: int
    meaningful_yield_at_k: float

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("selector yield track must be typed")
        require_text(self.selector_id, "selector yield selector_id")
        require_text(self.model_id, "selector yield model_id")
        if (
            type(self.top_k) is not int
            or self.top_k <= 0
            or type(self.meaningful_slots) is not int
            or not 0 <= self.meaningful_slots <= self.top_k
        ):
            raise ValueError("selector yield counts are invalid")
        if self.meaningful_yield_at_k != self.meaningful_slots / self.top_k:
            raise ValueError("selector Yield@K must use the fixed K denominator")


@dataclass(frozen=True, slots=True)
class TargetSelectorYieldResult:
    shared_evidence_record_id: str
    slots: tuple[TargetSlotYieldRecord, ...]
    selectors: tuple[TargetSelectorYield, ...]

    def __post_init__(self) -> None:
        require_text(self.shared_evidence_record_id, "yield shared evidence record")
        if len({item.slot_id for item in self.slots}) != len(self.slots):
            raise ValueError("yield slots must be unique")

    @property
    def target_selector_yield_result_id(self) -> str:
        return content_id("target_selector_yield_result_", self)


@dataclass(frozen=True, slots=True)
class _TargetEffectWork:
    dispatch: ConfirmationDispatchRecord
    track: PolicyTrack
    point: float | None
    standard_error: float | None
    latent_lower: float | None
    latent_upper: float | None
    arm_summaries: tuple[TargetArmEndpointSummary, ...]
    contributions: tuple[TargetTaskUnitContribution, ...]
    stratum_weights: tuple[tuple[str, float], ...]
    assignments: int
    reasons: tuple[str, ...]


def estimate_target_itt(
    ledger: AssignedArmEvidenceLedger,
    plan: TargetITTPlan,
    *,
    evidence_level: EvidenceLevel = EvidenceLevel.EXECUTED,
) -> SharedEvidenceRecord:
    """Estimate one shared, direction-free Atomic and Pair confirmation record."""

    if type(ledger) is not AssignedArmEvidenceLedger or type(plan) is not TargetITTPlan:
        raise TypeError("target ITT requires a frozen assigned-arm ledger and plan")
    if type(evidence_level) is not EvidenceLevel:
        raise TypeError("target ITT evidence level must be typed")
    track_by_candidate = {
        item.candidate_record_id: item.track
        for item in ledger.dispatch.union.entries
    }
    assignments_by_candidate: dict[str, list[AssignedArmITTRecord]] = defaultdict(list)
    for assignment in ledger.assignments:
        assignments_by_candidate[assignment.candidate_record_id].append(assignment)
    outcome_by_assignment = {item.assignment_id: item for item in ledger.outcomes}
    failed_assignment_ids = {
        item.assignment_id for item in ledger.infrastructure_failures
    }
    works = []
    for dispatch in ledger.dispatch.records:
        if dispatch.status is not BridgeStatus.SUCCESS:
            continue
        works.append(
            _target_effect_work(
                dispatch,
                track_by_candidate[dispatch.candidate_record_id],
                tuple(assignments_by_candidate[dispatch.candidate_record_id]),
                outcome_by_assignment,
                failed_assignment_ids,
                plan,
            )
        )
    families = tuple(
        _target_family(
            track,
            tuple(
                sorted(
                    (item for item in works if item.track is track),
                    key=lambda item: item.dispatch.candidate_record_id,
                )
            ),
            plan,
        )
        for track in (PolicyTrack.ATOMIC, PolicyTrack.PAIR)
    )
    return SharedEvidenceRecord(plan, ledger, families, evidence_level)


def build_target_selector_yields(
    evidence: SharedEvidenceRecord,
) -> TargetSelectorYieldResult:
    """Fan one unique effect status back to every fixed slot using K unchanged."""

    if type(evidence) is not SharedEvidenceRecord:
        raise TypeError("target selector yield requires a shared evidence record")
    estimate_by_candidate = {
        item.candidate_record_id: item
        for family in evidence.families
        for item in family.estimates
    }
    dispatch_by_candidate = {
        item.candidate_record_id: item for item in evidence.ledger.dispatch.records
    }
    slot_records = []
    for slot in evidence.ledger.dispatch.union.ledger.slots:
        estimate = (
            None
            if slot.candidate_record_id is None
            else estimate_by_candidate.get(slot.candidate_record_id)
        )
        dispatch = (
            None
            if slot.candidate_record_id is None
            else dispatch_by_candidate[slot.candidate_record_id]
        )
        effect_status = None if estimate is None else estimate.status
        meaningful = int(
            effect_status
            in {
                ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL,
                ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL,
            }
        )
        if meaningful:
            reason = None
        elif slot.status is not SlotStatus.FILLED:
            reason = slot.reason_code
        elif dispatch is not None and dispatch.status is not BridgeStatus.SUCCESS:
            reason = dispatch.status.value
        elif effect_status is not None:
            reason = effect_status.value
        else:
            reason = "missing_effect_evidence"
        slot_records.append(
            TargetSlotYieldRecord(
                slot.slot_id,
                slot.track,
                slot.selector_id,
                slot.model_id,
                slot.rank,
                slot.status,
                slot.candidate_record_id,
                effect_status,
                meaningful,
                reason,
            )
        )
    frozen_slots = tuple(slot_records)
    grouped: dict[tuple[PolicyTrack, str, str], list[TargetSlotYieldRecord]] = defaultdict(list)
    for slot in frozen_slots:
        grouped[(slot.track, slot.selector_id, slot.model_id)].append(slot)
    selectors = tuple(
        TargetSelectorYield(
            track,
            selector_id,
            model_id,
            len(slots),
            sum(item.meaningful_yield for item in slots),
            sum(item.meaningful_yield for item in slots) / len(slots),
        )
        for (track, selector_id, model_id), slots in sorted(
            grouped.items(),
            key=lambda item: (item[0][0].value, item[0][2], item[0][1]),
        )
    )
    return TargetSelectorYieldResult(
        evidence.shared_evidence_record_id,
        frozen_slots,
        selectors,
    )


def _target_effect_work(
    dispatch: ConfirmationDispatchRecord,
    track: PolicyTrack,
    assignments: tuple[AssignedArmITTRecord, ...],
    outcome_by_assignment: Mapping[str, Outcome],
    failed_assignment_ids: set[str],
    plan: TargetITTPlan,
) -> _TargetEffectWork:
    reasons = set()
    assignment_ids = {item.assignment_id for item in assignments}
    if assignment_ids & failed_assignment_ids:
        reasons.add("missing_or_failed_assigned_outcome")
    if not assignment_ids <= set(outcome_by_assignment):
        reasons.add("missing_or_failed_assigned_outcome")
    if reasons:
        return _TargetEffectWork(
            dispatch,
            track,
            None,
            None,
            None,
            None,
            (),
            (),
            (),
            len(assignments),
            tuple(sorted(reasons)),
        )
    local_outcomes = {
        assignment_id: outcome_by_assignment[assignment_id]
        for assignment_id in assignment_ids
    }
    expected_arms = (
        ATOMIC_CONFIRMATORY_ARMS
        if track is PolicyTrack.ATOMIC
        else PAIR_CONFIRMATORY_ARMS
    )
    for arm in expected_arms:
        arm_outcomes = tuple(
            local_outcomes[item.assignment_id]
            for item in assignments
            if item.arm is arm
        )
        valid = sum(item.code_valid for item in arm_outcomes)
        unknown = sum(item.code_valid - item.oracle_evaluable for item in arm_outcomes)
        if valid and unknown / valid > plan.maximum_unknown_fraction_among_valid:
            reasons.add("maximum_unknown_fraction_exceeded")
    point_values = _target_unit_arm_values(
        assignments,
        local_outcomes,
        lambda item: float(item.secure_yield),
    )
    lower_values = point_values
    upper_values = _target_unit_arm_values(
        assignments,
        local_outcomes,
        lambda item: float(item.latent_secure_upper),
    )
    stratum_by_unit = _target_strata(assignments)
    contributions = tuple(
        TargetTaskUnitContribution(
            task_unit_id,
            stratum_by_unit[task_unit_id],
            _target_contrast(track, arms, arms),
            _target_contrast_lower(track, lower_values[task_unit_id], upper_values[task_unit_id]),
            _target_contrast_upper(track, lower_values[task_unit_id], upper_values[task_unit_id]),
        )
        for task_unit_id, arms in sorted(point_values.items())
    )
    counts = Counter(item.stratum_id for item in contributions)
    if any(
        count < plan.minimum_task_units_per_stratum
        for count in counts.values()
    ):
        reasons.add("insufficient_task_units_per_stratum")
    point, standard_error, stratum_weights = _target_point_standard_error(contributions)
    if standard_error == 0:
        reasons.add("zero_standard_error")
    latent_lower = sum(item.latent_lower for item in contributions) / len(contributions)
    latent_upper = sum(item.latent_upper for item in contributions) / len(contributions)
    summaries = _target_arm_summaries(assignments, local_outcomes, expected_arms)
    return _TargetEffectWork(
        dispatch,
        track,
        point,
        standard_error,
        latent_lower,
        latent_upper,
        summaries,
        contributions,
        stratum_weights,
        len(assignments),
        tuple(sorted(reasons)),
    )


def _target_family(
    track: PolicyTrack,
    works: tuple[_TargetEffectWork, ...],
    plan: TargetITTPlan,
) -> TargetFamilyInference:
    if not works:
        return TargetFamilyInference(
            track,
            TargetFamilyStatus.NO_ELIGIBLE_COORDINATES,
            None,
            0,
            0,
            (),
        )
    all_reasons = {reason for item in works for reason in item.reasons}
    if "missing_or_failed_assigned_outcome" in all_reasons:
        return _target_failed_family(
            track,
            TargetFamilyStatus.INVALID_PROVENANCE,
            works,
            "primary_family_invalid_provenance",
            _target_margin(track, plan),
        )
    if all_reasons & {
        "insufficient_task_units_per_stratum",
        "maximum_unknown_fraction_exceeded",
    }:
        return _target_failed_family(
            track,
            TargetFamilyStatus.INSUFFICIENT_SUPPORT,
            works,
            "primary_family_insufficient_support",
            _target_margin(track, plan),
        )
    if "zero_standard_error" in all_reasons:
        return _target_failed_family(
            track,
            TargetFamilyStatus.ZERO_STANDARD_ERROR,
            works,
            "primary_family_zero_standard_error",
            _target_margin(track, plan),
        )
    maxima, invalid = _target_family_bootstrap(track, works, plan)
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return _target_failed_family(
            track,
            TargetFamilyStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            works,
            "primary_family_insufficient_valid_bootstrap",
            _target_margin(track, plan),
            valid_draws=len(maxima),
            invalid_draws=invalid,
        )
    critical = _higher_quantile(maxima, 1 - plan.alpha)
    margin = (
        plan.atomic_practical_margin
        if track is PolicyTrack.ATOMIC
        else plan.pair_practical_margin
    )
    estimates = tuple(
        _target_effect_estimate(item, critical, margin)
        for item in works
    )
    return TargetFamilyInference(
        track,
        TargetFamilyStatus.EVALUABLE,
        critical,
        len(maxima),
        invalid,
        estimates,
    )


def _target_failed_family(
    track: PolicyTrack,
    status: TargetFamilyStatus,
    works: tuple[_TargetEffectWork, ...],
    family_reason: str,
    margin: float,
    *,
    valid_draws: int = 0,
    invalid_draws: int = 0,
) -> TargetFamilyInference:
    estimates = tuple(
        TargetEffectEstimate(
            item.dispatch.candidate_record_id,
            item.dispatch.effect_coordinate_id,
            item.dispatch.policy_key,
            item.dispatch.model_id,
            item.track,
            item.point,
            item.standard_error,
            None,
            None,
            item.latent_lower,
            item.latent_upper,
            margin,
            ConfirmatoryEffectStatus.NON_EVALUABLE,
            tuple(sorted(set(item.reasons) | {family_reason})),
            len(item.contributions),
            item.assignments,
            item.arm_summaries,
            item.contributions,
        )
        for item in works
    )
    return TargetFamilyInference(
        track,
        status,
        None,
        valid_draws,
        invalid_draws,
        estimates,
    )


def _target_effect_estimate(
    work: _TargetEffectWork,
    critical: float,
    margin: float,
) -> TargetEffectEstimate:
    if work.point is None or work.standard_error is None:
        raise ValueError("an evaluable target family lacks a point estimate")
    lower = work.point - critical * work.standard_error
    upper = work.point + critical * work.standard_error
    status = classify_confirmatory_interval(
        lower,
        upper,
        margin,
        evaluable=True,
    )
    return TargetEffectEstimate(
        work.dispatch.candidate_record_id,
        work.dispatch.effect_coordinate_id,
        work.dispatch.policy_key,
        work.dispatch.model_id,
        work.track,
        work.point,
        work.standard_error,
        lower,
        upper,
        work.latent_lower,
        work.latent_upper,
        margin,
        status,
        (),
        len(work.contributions),
        work.assignments,
        work.arm_summaries,
        work.contributions,
    )


def _target_margin(track: PolicyTrack, plan: TargetITTPlan) -> float:
    return (
        plan.atomic_practical_margin
        if track is PolicyTrack.ATOMIC
        else plan.pair_practical_margin
    )


def _target_unit_arm_values(
    assignments: tuple[AssignedArmITTRecord, ...],
    outcomes: Mapping[str, Outcome],
    value: callable,
) -> dict[str, dict[ConfirmatoryArm, float]]:
    grouped: dict[
        tuple[str, str, str, ConfirmatoryArm],
        list[float],
    ] = defaultdict(list)
    task_weights: dict[tuple[str, str], set[float]] = defaultdict(set)
    realization_weights: dict[tuple[str, str], set[float]] = defaultdict(set)
    arms_by_unit: dict[str, set[ConfirmatoryArm]] = defaultdict(set)
    for assignment in assignments:
        grouped[
            (
                assignment.task_unit_id,
                assignment.task_instance_id,
                assignment.realization_id,
                assignment.arm,
            )
        ].append(value(outcomes[assignment.assignment_id]))
        task_weights[(assignment.task_unit_id, assignment.task_instance_id)].add(
            float(assignment.task_instance_weight)
        )
        realization_weights[(assignment.task_unit_id, assignment.realization_id)].add(
            float(assignment.realization_weight)
        )
        arms_by_unit[assignment.task_unit_id].add(assignment.arm)
    if any(len(values) != 1 for values in task_weights.values()) or any(
        len(values) != 1 for values in realization_weights.values()
    ):
        raise ValueError("task-instance or realization weights drift inside descendants")
    result = {}
    for task_unit_id in sorted(arms_by_unit):
        instances = tuple(
            sorted(instance for unit, instance in task_weights if unit == task_unit_id)
        )
        realizations = tuple(
            sorted(realization for unit, realization in realization_weights if unit == task_unit_id)
        )
        arms = tuple(sorted(arms_by_unit[task_unit_id], key=lambda item: item.value))
        task_total = sum(next(iter(task_weights[(task_unit_id, item)])) for item in instances)
        realization_total = sum(
            next(iter(realization_weights[(task_unit_id, item)]))
            for item in realizations
        )
        unit_values = {}
        for arm in arms:
            total = 0.0
            for instance in instances:
                task_weight = next(iter(task_weights[(task_unit_id, instance)])) / task_total
                for realization in realizations:
                    realization_weight = (
                        next(iter(realization_weights[(task_unit_id, realization)]))
                        / realization_total
                    )
                    values = grouped.get(
                        (task_unit_id, instance, realization, arm)
                    )
                    if not values:
                        raise ValueError("assigned-arm hierarchy lacks complete task/realization support")
                    total += task_weight * realization_weight * (
                        sum(values) / len(values)
                    )
            unit_values[arm] = total
        result[task_unit_id] = unit_values
    return result


def _target_strata(
    assignments: tuple[AssignedArmITTRecord, ...],
) -> dict[str, str]:
    values: dict[str, set[str]] = defaultdict(set)
    for item in assignments:
        values[item.task_unit_id].add(item.stratum_id)
    if any(len(strata) != 1 for strata in values.values()):
        raise ValueError("one task unit cannot cross frozen inference strata")
    return {task_unit_id: next(iter(strata)) for task_unit_id, strata in values.items()}


def _target_contrast(
    track: PolicyTrack,
    lower: Mapping[ConfirmatoryArm, float],
    upper: Mapping[ConfirmatoryArm, float],
) -> float:
    if track is PolicyTrack.ATOMIC:
        return lower[ConfirmatoryArm.ATOMIC_TARGET] - upper[ConfirmatoryArm.ATOMIC_NOOP]
    return (
        lower[ConfirmatoryArm.PAIR_11]
        - upper[ConfirmatoryArm.PAIR_10]
        - upper[ConfirmatoryArm.PAIR_01]
        + lower[ConfirmatoryArm.PAIR_00]
    )


def _target_contrast_lower(
    track: PolicyTrack,
    lower: Mapping[ConfirmatoryArm, float],
    upper: Mapping[ConfirmatoryArm, float],
) -> float:
    return _target_contrast(track, lower, upper)


def _target_contrast_upper(
    track: PolicyTrack,
    lower: Mapping[ConfirmatoryArm, float],
    upper: Mapping[ConfirmatoryArm, float],
) -> float:
    if track is PolicyTrack.ATOMIC:
        return upper[ConfirmatoryArm.ATOMIC_TARGET] - lower[ConfirmatoryArm.ATOMIC_NOOP]
    return (
        upper[ConfirmatoryArm.PAIR_11]
        - lower[ConfirmatoryArm.PAIR_10]
        - lower[ConfirmatoryArm.PAIR_01]
        + upper[ConfirmatoryArm.PAIR_00]
    )


def _target_point_standard_error(
    contributions: tuple[TargetTaskUnitContribution, ...],
) -> tuple[float, float, tuple[tuple[str, float], ...]]:
    by_stratum: dict[str, list[float]] = defaultdict(list)
    for item in contributions:
        by_stratum[item.stratum_id].append(item.point)
    total = len(contributions)
    weights = tuple(
        (stratum, len(values) / total)
        for stratum, values in sorted(by_stratum.items())
    )
    means = {
        stratum: sum(values) / len(values)
        for stratum, values in by_stratum.items()
    }
    point = sum(weight * means[stratum] for stratum, weight in weights)
    variance = 0.0
    for stratum, weight in weights:
        values = by_stratum[stratum]
        if len(values) < 2:
            return point, 0.0, weights
        mean = means[stratum]
        variance += weight**2 * sum((item - mean) ** 2 for item in values) / (
            len(values) * (len(values) - 1)
        )
    return point, math.sqrt(max(variance, 0.0)), weights


def _target_arm_summaries(
    assignments: tuple[AssignedArmITTRecord, ...],
    outcomes: Mapping[str, Outcome],
    arms: tuple[ConfirmatoryArm, ...],
) -> tuple[TargetArmEndpointSummary, ...]:
    metrics = {
        Metric.SECURE_YIELD: lambda item: float(item.secure_yield),
        Metric.CODE_VALID: lambda item: float(item.code_valid),
        Metric.ORACLE_EVALUABLE: lambda item: float(item.oracle_evaluable),
        Metric.FUNCTIONALITY: lambda item: float(item.functionality == 1),
        Metric.JOINT: lambda item: float(item.joint == 1),
    }
    values = {
        metric: _target_unit_arm_values(assignments, outcomes, getter)
        for metric, getter in metrics.items()
    }
    summaries = []
    for arm in arms:
        arm_assignments = tuple(item for item in assignments if item.arm is arm)
        arm_outcomes = tuple(outcomes[item.assignment_id] for item in arm_assignments)
        summaries.append(
            TargetArmEndpointSummary(
                arm,
                len(arm_assignments),
                statistics.mean(
                    item[arm] for item in values[Metric.SECURE_YIELD].values()
                ),
                statistics.mean(
                    item[arm] for item in values[Metric.CODE_VALID].values()
                ),
                statistics.mean(
                    item[arm] for item in values[Metric.ORACLE_EVALUABLE].values()
                ),
                statistics.mean(
                    item[arm] for item in values[Metric.FUNCTIONALITY].values()
                ),
                statistics.mean(
                    item[arm] for item in values[Metric.JOINT].values()
                ),
                sum(item.code_valid - item.oracle_evaluable for item in arm_outcomes),
                sum(item.code_valid == 0 for item in arm_outcomes),
            )
        )
    return tuple(summaries)


def _target_family_bootstrap(
    track: PolicyTrack,
    works: tuple[_TargetEffectWork, ...],
    plan: TargetITTPlan,
) -> tuple[list[float], int]:
    global_units: dict[str, set[str]] = defaultdict(set)
    for work in works:
        for item in work.contributions:
            global_units[item.stratum_id].add(item.task_unit_id)
    rng = random.Random(
        int(
            content_hash(
                {
                    "domain": "target_max_t_task_unit_bootstrap_v1",
                    "seed": plan.bootstrap_seed,
                    "track": track,
                    "plan_id": plan.target_itt_plan_id,
                }
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled = {
            stratum: tuple(
                population[rng.randrange(len(population))]
                for _ in population
            )
            for stratum, values in sorted(global_units.items())
            for population in (tuple(sorted(values)),)
        }
        statistics_by_effect = []
        for work in works:
            draw = _target_resampled_point_standard_error(work, sampled)
            if draw is None or work.point is None:
                statistics_by_effect = []
                break
            point, standard_error = draw
            if standard_error <= 0:
                statistics_by_effect = []
                break
            statistics_by_effect.append(abs((point - work.point) / standard_error))
        if not statistics_by_effect:
            invalid += 1
            continue
        maxima.append(max(statistics_by_effect))
    return maxima, invalid


def _target_resampled_point_standard_error(
    work: _TargetEffectWork,
    sampled: Mapping[str, tuple[str, ...]],
) -> tuple[float, float] | None:
    contribution_by_unit = {
        item.task_unit_id: item.point for item in work.contributions
    }
    weights = dict(work.stratum_weights)
    means = {}
    values_by_stratum = {}
    for stratum, weight in work.stratum_weights:
        values = [
            contribution_by_unit[task_unit_id]
            for task_unit_id in sampled[stratum]
            if task_unit_id in contribution_by_unit
        ]
        if len(values) < 2:
            return None
        values_by_stratum[stratum] = values
        means[stratum] = sum(values) / len(values)
    point = sum(weights[stratum] * means[stratum] for stratum in means)
    variance = sum(
        weights[stratum] ** 2
        * sum((item - means[stratum]) ** 2 for item in values)
        / (len(values) * (len(values) - 1))
        for stratum, values in values_by_stratum.items()
    )
    return point, math.sqrt(max(variance, 0.0))


def _higher_quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("a higher quantile requires values")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


def estimate_successor_effects(
    randomization: SuccessorRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[InterventionPolicyV2],
    tasks: Iterable[Task],
    plan: SuccessorAnalysisPlan,
) -> SuccessorInferenceResult:
    """Estimate assigned-arm task-unit ITT for successor ADD/REMOVE policies."""

    frozen_outcomes = tuple(outcomes)
    by_outcome = {item.assignment_id: item for item in frozen_outcomes}
    expected = {item.assignment_id for item in randomization.assignments}
    if len(by_outcome) != len(frozen_outcomes) or set(by_outcome) != expected:
        raise ValueError("outcomes must cover every successor assignment exactly once")
    frozen_policies = tuple(policies)
    policy_by_hypothesis = {item.hypothesis_id: item for item in frozen_policies}
    if len(policy_by_hypothesis) != len(frozen_policies):
        raise ValueError("successor policies must bind unique hypotheses")
    frozen_tasks = tuple(tasks)
    task_by_id = {item.task_id: item for item in frozen_tasks}
    if len(task_by_id) != len(frozen_tasks):
        raise ValueError("successor task ids must be unique")
    estimates = tuple(
        _successor_coordinate(
            randomization,
            by_outcome,
            policy_by_hypothesis[hypothesis_id],
            task_by_id,
            model_id,
            metric,
            plan,
        )
        for hypothesis_id in sorted(policy_by_hypothesis)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    families = tuple(
        _successor_family(estimates, family, plan)
        for family in SuccessorIntervalFamily
    )
    robustness = _successor_robustness_inference(
        estimates,
        policy_by_hypothesis,
        plan,
    )
    label_by_coordinate = {
        item.coordinate_id: item.robustness_label
        for item in robustness.assessments
    }
    estimates = tuple(
        replace(
            item,
            robustness_label=(
                label_by_coordinate.get(item.coordinate_id, "not_evaluable")
                if item.metric is plan.primary_metric
                else "not_applicable_non_primary"
            ),
        )
        for item in estimates
    )
    return SuccessorInferenceResult(
        plan.analysis_plan_id,
        estimates,
        families,
        robustness,
    )


def _successor_coordinate(
    randomization: SuccessorRandomization,
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
    plan: SuccessorAnalysisPlan,
) -> SuccessorCoordinateEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.hypothesis_id == policy.hypothesis_id
        and item.block.model_id == model_id
    )
    task_unit_ids = sorted({item.block.task_unit_id for item in assignments})
    if not task_unit_ids:
        raise ValueError("successor analysis coordinate has no assignments")
    unit_arms: dict[
        str,
        dict[PolicyArmRoleV2, tuple[float | None, float, float, int]],
    ] = {}
    contributions = []
    for task_unit_id in task_unit_ids:
        arms = {
            role: _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                role,
                metric,
            )
            for role in SUCCESSOR_ARM_ROLE_ORDER
        }
        unit_arms[task_unit_id] = arms
        contrast_values = []
        for contrast in SuccessorContrast:
            left, right = contrast.roles
            contrast_values.append(
                (
                    contrast,
                    _difference(arms[left][0], arms[right][0]),
                    arms[left][1] - arms[right][2],
                    arms[left][2] - arms[right][1],
                )
            )
        contributions.append(
            TaskUnitSuccessorContribution(
                task_unit_id,
                tuple(
                    (role, arms[role][0], arms[role][1], arms[role][2])
                    for role in SUCCESSOR_ARM_ROLE_ORDER
                ),
                tuple(contrast_values),
            )
        )
    arm_estimates = tuple(
        _successor_arm_estimate(
            assignments,
            role,
            [unit_arms[unit_id][role] for unit_id in task_unit_ids],
        )
        for role in SUCCESSOR_ARM_ROLE_ORDER
    )
    arm_by_role = {item.role: item for item in arm_estimates}
    contrast_estimates = tuple(
        SuccessorContrastEstimate(
            contrast,
            _difference(
                arm_by_role[contrast.roles[0]].point,
                arm_by_role[contrast.roles[1]].point,
            ),
            arm_by_role[contrast.roles[0]].lower
            - arm_by_role[contrast.roles[1]].upper,
            arm_by_role[contrast.roles[0]].upper
            - arm_by_role[contrast.roles[1]].lower,
        )
        for contrast in SuccessorContrast
    )
    realization_effects = tuple(
        _successor_realization_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
    )
    leave_one_realization_out = tuple(
        _successor_leave_one_realization_out_effect(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            realization.realization_spec_id,
            metric,
        )
        for realization in policy.realization_policy.realizations
        if len(policy.realization_policy.realizations) >= 2
    )
    return SuccessorCoordinateEstimate(
        policy.hypothesis_id,
        model_id,
        metric,
        policy.hypothesis.skeleton.expected_direction,
        arm_estimates,
        contrast_estimates,
        tuple(contributions),
        realization_effects,
        _successor_point_robustness_label(
            contrast_estimates[0],
            realization_effects,
            len(task_unit_ids),
            policy.hypothesis.skeleton.expected_direction,
            plan,
        ),
        leave_one_realization_out,
    )


def _successor_unit_arm(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    role: PolicyArmRoleV2,
    metric: Metric,
    *,
    only_realization_id: str | None = None,
) -> tuple[float | None, float, float, int]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise ValueError("successor task unit lacks frozen task records")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    realizations = tuple(
        item
        for item in policy.realization_policy.realizations
        if only_realization_id is None
        or item.realization_spec_id == only_realization_id
    )
    if not realizations:
        raise ValueError("successor realization support is empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
    count = 0
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.realization_spec_id == realization.realization_spec_id
                and item.arm_role is role
            ]
            if not block:
                raise ValueError("successor randomization lacks common task-realization support")
            values = [_metric_value(outcomes[item.assignment_id], metric) for item in block]
            weight = task_weight * realization_weight
            count += len(block)
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += weight * sum(
                    value[0] for value in values if value[0] is not None
                ) / len(values)
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper, count


def _successor_arm_estimate(
    assignments: tuple[SuccessorAssignment, ...],
    role: PolicyArmRoleV2,
    units: list[tuple[float | None, float, float, int]],
) -> SuccessorArmEstimate:
    point = None if any(item[0] is None for item in units) else sum(
        item[0] for item in units if item[0] is not None
    ) / len(units)
    return SuccessorArmEstimate(
        role,
        point,
        sum(item[1] for item in units) / len(units),
        sum(item[2] for item in units) / len(units),
        sum(item.arm_role is role for item in assignments),
    )


def _successor_realization_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_id: str,
    metric: Metric,
) -> RealizationSuccessorEffect:
    values = _successor_subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        (realization_spec_id,),
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return RealizationSuccessorEffect(
        realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _successor_leave_one_realization_out_effect(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    omitted_realization_spec_id: str,
    metric: Metric,
) -> LeaveOneRealizationOutSuccessorEffect:
    included = tuple(
        item.realization_spec_id
        for item in policy.realization_policy.realizations
        if item.realization_spec_id != omitted_realization_spec_id
    )
    values = _successor_subset_effect_values(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        included,
        metric,
    )
    point = None if any(item[0] is None for item in values) else sum(
        item[0] for item in values if item[0] is not None
    ) / len(values)
    return LeaveOneRealizationOutSuccessorEffect(
        omitted_realization_spec_id,
        point,
        sum(item[1] for item in values) / len(values),
        sum(item[2] for item in values) / len(values),
        tuple(
            (task_unit_id, *value)
            for task_unit_id, value in zip(task_unit_ids, values, strict=True)
        ),
    )


def _successor_subset_effect_values(
    assignments: tuple[SuccessorAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: InterventionPolicyV2,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    realization_spec_ids: tuple[str, ...],
    metric: Metric,
) -> list[tuple[float | None, float, float]]:
    selected = tuple(
        item
        for item in policy.realization_policy.realizations
        if item.realization_spec_id in realization_spec_ids
    )
    if not selected or len(selected) != len(realization_spec_ids):
        raise ValueError("successor realization subset is invalid")
    selected_total = sum(item.weight for item in selected)
    values = []
    for task_unit_id in task_unit_ids:
        point = lower = upper = 0.0
        point_known = True
        for realization in selected:
            target = _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.TARGET,
                metric,
                only_realization_id=realization.realization_spec_id,
            )
            noop = _successor_unit_arm(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                PolicyArmRoleV2.NOOP,
                metric,
                only_realization_id=realization.realization_spec_id,
            )
            weight = realization.weight / selected_total
            difference = _difference(target[0], noop[0])
            if difference is None:
                point_known = False
            else:
                point += weight * difference
            lower += weight * (target[1] - noop[2])
            upper += weight * (target[2] - noop[1])
        values.append((point if point_known else None, lower, upper))
    return values


def _successor_point_robustness_label(
    primary: SuccessorContrastEstimate,
    realizations: tuple[RealizationSuccessorEffect, ...],
    task_units: int,
    expected_direction: ExpectedDirection,
    plan: SuccessorAnalysisPlan,
) -> str:
    if primary.point is None or task_units < plan.minimum_task_units:
        return "not_evaluable"
    if len(realizations) < 2 or any(item.point is None for item in realizations):
        return "average_effect_only"
    multiplier = 1.0 if expected_direction is ExpectedDirection.INCREASE else -1.0
    values = [multiplier * float(item.point) for item in realizations]
    if any(value <= plan.practical_effect_margin for value in values):
        return "average_effect_only"
    leave_one_out = [
        sum(value for index, value in enumerate(values) if index != omitted)
        / (len(values) - 1)
        for omitted in range(len(values))
    ]
    return (
        "direction_consistent_diagnostic"
        if all(value > 0.0 for value in leave_one_out)
        else "average_effect_only"
    )


def _successor_robustness_inference(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    policies: Mapping[str, InterventionPolicyV2],
    plan: SuccessorAnalysisPlan,
) -> SuccessorRobustnessInference:
    """Build the global realization/LORO max-|T| family and claim gates."""

    secure = tuple(item for item in estimates if item.metric is plan.primary_metric)
    functionality = {
        (item.hypothesis_id, item.model_id): item
        for item in estimates
        if item.metric is Metric.FUNCTIONALITY
    }
    (
        functionality_status,
        functionality_critical,
        functionality_intervals,
    ) = _successor_functionality_gate_family(functionality, plan)

    members: dict[
        tuple[str, SuccessorRobustnessComponent, str],
        tuple[tuple[str, ...], tuple[float, ...]],
    ] = {}
    coordinate_weights: dict[str, dict[str, float]] = {}
    structurally_eligible: set[str] = set()
    for estimate in secure:
        policy = policies[estimate.hypothesis_id]
        realization_ids = tuple(
            item.realization_spec_id
            for item in policy.realization_policy.realizations
        )
        weights = {
            item.realization_spec_id: item.weight
            for item in policy.realization_policy.realizations
        }
        total_weight = sum(weights.values())
        coordinate_weights[estimate.coordinate_id] = {
            key: value / total_weight for key, value in weights.items()
        }
        if (
            len(realization_ids) < plan.minimum_realizations
            or len(estimate.task_unit_contributions) < plan.minimum_task_units
            or len(estimate.realization_effects) != len(realization_ids)
            or len(estimate.leave_one_realization_out) != len(realization_ids)
        ):
            continue
        candidate_members = tuple(
            (
                SuccessorRobustnessComponent.REALIZATION,
                item.realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.realization_effects
        ) + tuple(
            (
                SuccessorRobustnessComponent.LEAVE_ONE_REALIZATION_OUT,
                item.omitted_realization_spec_id,
                item.task_unit_effects,
            )
            for item in estimate.leave_one_realization_out
        )
        if any(
            len(values) < plan.minimum_task_units_per_realization
            or any(value[1] is None for value in values)
            for _, _, values in candidate_members
        ):
            continue
        structurally_eligible.add(estimate.coordinate_id)
        for component, realization_id, values in candidate_members:
            members[(estimate.coordinate_id, component, realization_id)] = (
                tuple(value[0] for value in values),
                tuple(float(value[1]) for value in values),
            )

    status = FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES
    critical: float | None = None
    valid_draws = 0
    invalid_draws = plan.bootstrap_draws
    intervals: tuple[SuccessorRobustnessInterval, ...] = ()
    heterogeneity: dict[str, tuple[float, float]] = {}
    if members:
        (
            status,
            critical,
            valid_draws,
            invalid_draws,
            intervals,
            heterogeneity,
        ) = _successor_global_robustness_family(
            members,
            coordinate_weights,
            plan,
        )

    interval_by_key = {
        (item.coordinate_id, item.component, item.realization_spec_id): item
        for item in intervals
    }
    assessments = []
    for estimate in secure:
        coordinate_id = estimate.coordinate_id
        multiplier = (
            1.0
            if estimate.expected_direction is ExpectedDirection.INCREASE
            else -1.0
        )
        realization_points = tuple(
            multiplier * float(item.point)
            for item in estimate.realization_effects
            if item.point is not None
        )
        direction_proportion = (
            None
            if not estimate.realization_effects
            or len(realization_points) != len(estimate.realization_effects)
            else sum(value > 0.0 for value in realization_points)
            / len(realization_points)
        )
        direction_passed = (
            direction_proportion is not None
            and direction_proportion
            >= plan.realization_direction_consistency_threshold
        )
        minimum_support_passed = coordinate_id in structurally_eligible
        coordinate_intervals = tuple(
            value
            for key, value in interval_by_key.items()
            if key[0] == coordinate_id
        )
        simultaneous_direction_passed = (
            minimum_support_passed
            and len(coordinate_intervals)
            == len(estimate.realization_effects)
            + len(estimate.leave_one_realization_out)
            and all(
                (item.lower > 0.0)
                if multiplier > 0.0
                else (item.upper < 0.0)
                for item in coordinate_intervals
            )
        )
        heterogeneity_point, heterogeneity_upper = heterogeneity.get(
            coordinate_id,
            (None, None),
        )
        heterogeneity_passed = (
            heterogeneity_upper is not None
            and heterogeneity_upper
            <= plan.realization_practical_equivalence_margin
        )
        interaction_statistic, interaction_p = _arm_realization_randomization_test(
            estimate,
            plan,
        )
        interaction_passed = (
            interaction_p is not None and interaction_p > plan.alpha
        )
        realization_robust = (
            status is FamilyInferenceStatus.EVALUABLE
            and minimum_support_passed
            and direction_passed
            and simultaneous_direction_passed
            and heterogeneity_passed
            and interaction_passed
        )
        if realization_robust:
            robustness_label = "realization_robust"
        elif estimate.contrast(SuccessorContrast.TARGET_NOOP).point is None:
            robustness_label = "not_evaluable"
        elif direction_passed and minimum_support_passed:
            robustness_label = "direction_consistent_diagnostic"
        else:
            robustness_label = "average_effect_only"

        function_coordinate = functionality.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        function_point = (
            None
            if function_coordinate is None
            else function_coordinate.contrast(SuccessorContrast.TARGET_NOOP).point
        )
        function_interval = functionality_intervals.get(
            (estimate.hypothesis_id, estimate.model_id)
        )
        if not plan.functionality_noninferiority_separately_powered:
            gate_status = FunctionalityGateStatus.NOT_REQUESTED
            function_lower = None
        elif (
            functionality_status is not FamilyInferenceStatus.EVALUABLE
            or function_interval is None
        ):
            gate_status = FunctionalityGateStatus.NOT_EVALUABLE
            function_lower = None
        else:
            function_lower = function_interval[1]
            gate_status = (
                FunctionalityGateStatus.PASSED
                if function_lower >= -plan.functionality_noninferiority_margin
                else FunctionalityGateStatus.FAILED
            )
        if not realization_robust:
            practical_success_label = "security_robustness_not_established"
        elif gate_status is FunctionalityGateStatus.PASSED:
            practical_success_label = "practical_success"
        elif gate_status is FunctionalityGateStatus.NOT_REQUESTED:
            practical_success_label = "functionality_gate_not_requested"
        elif gate_status is FunctionalityGateStatus.FAILED:
            practical_success_label = "functionality_noninferiority_failed"
        else:
            practical_success_label = "functionality_gate_not_evaluable"
        assessments.append(
            SuccessorRobustnessAssessment(
                coordinate_id,
                direction_proportion,
                direction_passed,
                simultaneous_direction_passed,
                minimum_support_passed,
                heterogeneity_point,
                heterogeneity_upper,
                heterogeneity_passed,
                interaction_statistic,
                interaction_p,
                interaction_passed,
                gate_status,
                function_point,
                function_lower,
                robustness_label,
                practical_success_label,
            )
        )
    return SuccessorRobustnessInference(
        status,
        critical,
        valid_draws,
        invalid_draws,
        intervals,
        functionality_critical,
        tuple(assessments),
    )


def _arm_realization_randomization_test(
    estimate: SuccessorCoordinateEstimate,
    plan: SuccessorAnalysisPlan,
) -> tuple[float | None, float | None]:
    """Task-unit Rademacher reference for arm-by-realization heterogeneity."""

    rows = {
        item.realization_spec_id: {
            task_id: point for task_id, point, _lower, _upper in item.task_unit_effects
        }
        for item in estimate.realization_effects
    }
    if len(rows) < plan.minimum_realizations:
        return None, None
    task_ids = tuple(sorted(set.intersection(*(set(value) for value in rows.values()))))
    if len(task_ids) < plan.minimum_task_units_per_realization or any(
        rows[realization_id][task_id] is None
        for realization_id in rows
        for task_id in task_ids
    ):
        return None, None
    residuals = {
        realization_id: tuple(
            float(rows[realization_id][task_id])
            - sum(float(rows[other][task_id]) for other in rows) / len(rows)
            for task_id in task_ids
        )
        for realization_id in rows
    }
    statistic = max(
        abs(sum(values) / len(values)) for values in residuals.values()
    )
    rng = random.Random(
        int(content_hash({
            "seed": plan.bootstrap_seed,
            "coordinate_id": estimate.coordinate_id,
            "domain": "arm-realization-rademacher",
        })[-16:], 16)
    )
    exceedances = 0
    for _ in range(plan.bootstrap_draws):
        signs = tuple(1.0 if rng.randrange(2) else -1.0 for _ in task_ids)
        replicate = max(
            abs(sum(sign * value for sign, value in zip(signs, values, strict=True)) / len(values))
            for values in residuals.values()
        )
        exceedances += replicate >= statistic - 1e-15
    return statistic, (exceedances + 1) / (plan.bootstrap_draws + 1)


def _successor_global_robustness_family(
    members: Mapping[
        tuple[str, SuccessorRobustnessComponent, str],
        tuple[tuple[str, ...], tuple[float, ...]],
    ],
    coordinate_weights: Mapping[str, Mapping[str, float]],
    plan: SuccessorAnalysisPlan,
) -> tuple[
    FamilyInferenceStatus,
    float | None,
    int,
    int,
    tuple[SuccessorRobustnessInterval, ...],
    dict[str, tuple[float, float]],
]:
    supports = {key: value[0] for key, value in members.items()}
    values = {key: value[1] for key, value in members.items()}
    points = {key: sum(value) / len(value) for key, value in values.items()}
    errors = {key: _mean_standard_error(value) for key, value in values.items()}
    if any(value <= 0.0 for value in errors.values()):
        return (
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
            {},
        )
    realization_keys = {
        coordinate_id: tuple(
            key
            for key in members
            if key[0] == coordinate_id
            and key[1] is SuccessorRobustnessComponent.REALIZATION
        )
        for coordinate_id in {key[0] for key in members}
    }
    heterogeneity_points = {
        coordinate_id: _successor_max_realization_deviation(
            {key[2]: points[key] for key in keys},
            coordinate_weights[coordinate_id],
        )
        for coordinate_id, keys in realization_keys.items()
    }
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_robustness_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value, key[2]) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    draws: list[
        tuple[
            dict[tuple[str, SuccessorRobustnessComponent, str], float],
            dict[tuple[str, SuccessorRobustnessComponent, str], float],
            dict[str, float],
        ]
    ] = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        replicate_points = {}
        replicate_errors = {}
        valid = True
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units_per_realization:
                valid = False
                break
            error = _mean_standard_error(sample)
            if error <= 0.0:
                valid = False
                break
            replicate_points[key] = sum(sample) / len(sample)
            replicate_errors[key] = error
        if not valid:
            invalid += 1
            continue
        replicate_heterogeneity = {
            coordinate_id: _successor_max_realization_deviation(
                {key[2]: replicate_points[key] for key in keys},
                coordinate_weights[coordinate_id],
            )
            for coordinate_id, keys in realization_keys.items()
        }
        draws.append(
            (replicate_points, replicate_errors, replicate_heterogeneity)
        )
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(draws) < minimum_valid:
        return (
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(draws),
            invalid,
            (),
            {},
        )
    heterogeneity_errors = {
        coordinate_id: statistics.stdev(
            draw[2][coordinate_id] for draw in draws
        )
        for coordinate_id in realization_keys
    }
    maxima = []
    for replicate_points, replicate_errors, replicate_heterogeneity in draws:
        statistics_for_draw = [
            abs(replicate_points[key] - points[key]) / replicate_errors[key]
            for key in members
        ]
        statistics_for_draw.extend(
            abs(
                replicate_heterogeneity[coordinate_id]
                - heterogeneity_points[coordinate_id]
            )
            / error
            for coordinate_id, error in heterogeneity_errors.items()
            if error > 0.0
        )
        maxima.append(max(statistics_for_draw))
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorRobustnessInterval(
            key[0],
            key[1],
            key[2],
            errors[key],
            max(-1.0, points[key] - critical * errors[key]),
            min(1.0, points[key] + critical * errors[key]),
        )
        for key in members
    )
    heterogeneity = {
        coordinate_id: (
            point,
            min(
                2.0,
                point + critical * heterogeneity_errors[coordinate_id],
            ),
        )
        for coordinate_id, point in heterogeneity_points.items()
    }
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(draws),
        invalid,
        intervals,
        heterogeneity,
    )


def _successor_max_realization_deviation(
    realization_points: Mapping[str, float],
    weights: Mapping[str, float],
) -> float:
    average = sum(weights[key] * value for key, value in realization_points.items())
    return max(abs(value - average) for value in realization_points.values())


def _successor_functionality_gate_family(
    functionality: Mapping[tuple[str, str], SuccessorCoordinateEstimate],
    plan: SuccessorAnalysisPlan,
) -> tuple[
    FamilyInferenceStatus,
    float | None,
    dict[tuple[str, str], tuple[float, float, float]],
]:
    if not plan.functionality_noninferiority_separately_powered:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    vectors = {
        key: tuple(
            float(item.contrast(SuccessorContrast.TARGET_NOOP)[0])
            for item in estimate.task_unit_contributions
        )
        for key, estimate in functionality.items()
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and all(
            item.contrast(SuccessorContrast.TARGET_NOOP)[0] is not None
            for item in estimate.task_unit_contributions
        )
    }
    supports = {
        key: tuple(item.task_unit_id for item in functionality[key].task_unit_contributions)
        for key in vectors
    }
    if not vectors:
        return FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES, None, {}
    points = {key: sum(value) / len(value) for key, value in vectors.items()}
    errors = {key: _mean_standard_error(value) for key, value in vectors.items()}
    if any(value <= 0.0 for value in errors.values()):
        return FamilyInferenceStatus.ZERO_STANDARD_ERROR, None, {}
    value_by_unit = {
        key: dict(zip(supports[key], vectors[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_functionality_gate_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(sorted(supports)),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        draw_statistics = []
        for key in supports:
            sample = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample) < plan.minimum_task_units:
                invalid += 1
                break
            replicate_error = _mean_standard_error(sample)
            if replicate_error <= 0.0:
                invalid += 1
                break
            draw_statistics.append(
                abs(sum(sample) / len(sample) - points[key]) / replicate_error
            )
        else:
            maxima.append(max(draw_statistics))
    if len(maxima) < math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    ):
        return FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP, None, {}
    critical = _quantile(maxima, 1.0 - plan.alpha)
    return (
        FamilyInferenceStatus.EVALUABLE,
        critical,
        {
            key: (
                errors[key],
                max(-1.0, points[key] - critical * errors[key]),
                min(1.0, points[key] + critical * errors[key]),
            )
            for key in vectors
        },
    )


def _successor_family(
    estimates: tuple[SuccessorCoordinateEstimate, ...],
    family: SuccessorIntervalFamily,
    plan: SuccessorAnalysisPlan,
) -> SuccessorFamilyInference:
    if family is SuccessorIntervalFamily.PRIMARY_SECURITY:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is plan.primary_metric
        )
    elif family is SuccessorIntervalFamily.SECURITY_SPECIFICITY:
        members = tuple(
            (item, contrast)
            for item in estimates
            if item.metric is plan.primary_metric
            for contrast in (
                SuccessorContrast.TARGET_PLACEBO,
                SuccessorContrast.TARGET_GENERIC,
            )
        )
    else:
        members = tuple(
            (item, SuccessorContrast.TARGET_NOOP)
            for item in estimates
            if item.metric is Metric.JOINT
        )
    eligible = tuple(
        (estimate, contrast)
        for estimate, contrast in members
        if len(estimate.task_unit_contributions) >= plan.minimum_task_units
        and estimate.contrast(contrast).point is not None
        and all(
            item.contrast(contrast)[0] is not None
            for item in estimate.task_unit_contributions
        )
    )
    if not eligible:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.NO_ELIGIBLE_COORDINATES,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    supports = {
        (estimate.coordinate_id, contrast): tuple(
            item.task_unit_id for item in estimate.task_unit_contributions
        )
        for estimate, contrast in eligible
    }
    points = {
        key: float(estimate.contrast(contrast).point)
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    values = {
        key: tuple(
            float(item.contrast(contrast)[0])
            for item in estimate.task_unit_contributions
        )
        for key, (estimate, contrast) in zip(supports, eligible, strict=True)
    }
    standard_errors = {key: _mean_standard_error(item) for key, item in values.items()}
    if any(error <= 0.0 for error in standard_errors.values()):
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.ZERO_STANDARD_ERROR,
            None,
            0,
            plan.bootstrap_draws,
            (),
        )
    value_by_unit = {
        key: dict(zip(supports[key], values[key], strict=True)) for key in supports
    }
    task_unit_union = tuple(
        sorted({unit_id for support in supports.values() for unit_id in support})
    )
    rng = random.Random(
        int(
            content_id(
                "successor_bootstrap_v2_",
                {
                    "seed": plan.bootstrap_seed,
                    "family": family,
                    "task_unit_union": task_unit_union,
                    "family_members": tuple(
                        (key[0], key[1].value) for key in supports
                    ),
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        statistics_for_draw = []
        valid = True
        for key in supports:
            sample_values = tuple(
                value_by_unit[key][unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit[key]
            )
            if len(sample_values) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _mean_standard_error(sample_values)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample_values) / len(sample_values)
            statistics_for_draw.append(
                abs(replicate_point - points[key]) / replicate_error
            )
        if valid:
            maxima.append(max(statistics_for_draw))
        else:
            invalid += 1
    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return SuccessorFamilyInference(
            family,
            FamilyInferenceStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            None,
            len(maxima),
            invalid,
            (),
        )
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = tuple(
        SuccessorSimultaneousInterval(
            estimate.coordinate_id,
            contrast,
            standard_errors[(estimate.coordinate_id, contrast)],
            max(
                -1.0,
                points[(estimate.coordinate_id, contrast)]
                - critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
            min(
                1.0,
                points[(estimate.coordinate_id, contrast)]
                + critical * standard_errors[(estimate.coordinate_id, contrast)],
            ),
        )
        for estimate, contrast in eligible
    )
    return SuccessorFamilyInference(
        family,
        FamilyInferenceStatus.EVALUABLE,
        critical,
        len(maxima),
        invalid,
        intervals,
    )


def _mean_standard_error(values: tuple[float, ...]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(
        sum((value - mean) ** 2 for value in values)
        / (len(values) * (len(values) - 1))
    )


def estimate_factorial_effects(
    randomization: FactorialRandomization,
    outcomes: Iterable[Outcome],
    policies: Iterable[FactorialPolicy],
    tasks: Iterable[Task],
    plan: FactorialAnalysisPlan,
) -> FactorialInferenceResult:
    """Estimate four-cell task-unit ITT effects without diagnostic filtering."""

    frozen_outcomes = tuple(outcomes)
    by_outcome = {item.assignment_id: item for item in frozen_outcomes}
    expected = {item.assignment_id for item in randomization.assignments}
    if len(by_outcome) != len(frozen_outcomes) or set(by_outcome) != expected:
        raise ValueError("outcomes must cover every factorial assignment exactly once")
    task_by_id = {item.task_id: item for item in tasks}
    frozen_policies = tuple(policies)
    policy_by_pair = {item.pair.pair_id: item for item in frozen_policies}
    if len(policy_by_pair) != len(frozen_policies):
        raise ValueError("factorial policies must bind unique pair IDs")
    estimates = tuple(
        _factorial_coordinate(
            randomization,
            by_outcome,
            policy_by_pair[pair_id],
            task_by_id,
            model_id,
            metric,
        )
        for pair_id in sorted(policy_by_pair)
        for model_id in randomization.models
        for metric in plan.metrics
    )
    intervals, critical = _factorial_simultaneous_intervals(estimates, plan)
    secondary, secondary_critical = _factorial_secondary_intervals(estimates, plan)
    metric_families = _factorial_metric_families(estimates, plan)
    return FactorialInferenceResult(
        plan.analysis_plan_id,
        estimates,
        intervals,
        critical,
        secondary,
        secondary_critical,
        metric_families,
    )


def _factorial_coordinate(
    randomization: FactorialRandomization,
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    model_id: str,
    metric: Metric,
) -> FactorialCoordinateEstimate:
    assignments = tuple(
        item
        for item in randomization.assignments
        if item.block.pair_id == policy.pair.pair_id and item.block.model_id == model_id
    )
    task_unit_ids = sorted({item.block.task_unit_id for item in assignments})
    if not task_unit_ids:
        raise ValueError("factorial analysis coordinate has no randomized assignments")
    unit_cells: dict[str, dict[FactorialCell, tuple[float | None, float, float, int]]] = {}
    unit_effects: list[TaskUnitFactorialEffect] = []
    for task_unit_id in task_unit_ids:
        cells = {
            cell: _task_unit_cell(
                assignments, outcomes, policy, tasks, task_unit_id, cell, metric
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        unit_cells[task_unit_id] = cells
        points = {cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER}
        interaction = _interaction(points)
        lower, upper = _interaction_bounds(cells)
        unit_effects.append(
            TaskUnitFactorialEffect(
                task_unit_id,
                tuple((cell, points[cell]) for cell in FACTORIAL_CELL_ORDER),
                interaction,
                lower,
                upper,
            )
        )
    cell_estimates = tuple(
        _factorial_cell_estimate(
            assignments,
            cell,
            [unit_cells[unit][cell] for unit in task_unit_ids],
        )
        for cell in FACTORIAL_CELL_ORDER
    )
    means = {item.cell: item.point for item in cell_estimates}
    lower = {item.cell: item.lower for item in cell_estimates}
    upper = {item.cell: item.upper for item in cell_estimates}
    realization_diagnostics = _factorial_realization_diagnostics(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_ids,
        metric,
        _interaction(means),
    )
    return FactorialCoordinateEstimate(
        policy.pair.pair_id,
        model_id,
        metric,
        cell_estimates,
        _difference(means[FactorialCell.A10], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A01], means[FactorialCell.A00]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A01]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A10]),
        _difference(means[FactorialCell.A11], means[FactorialCell.A00]),
        _interaction(means),
        (
            lower[FactorialCell.A10] - upper[FactorialCell.A00],
            upper[FactorialCell.A10] - lower[FactorialCell.A00],
        ),
        (
            lower[FactorialCell.A01] - upper[FactorialCell.A00],
            upper[FactorialCell.A01] - lower[FactorialCell.A00],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A01],
            upper[FactorialCell.A11] - lower[FactorialCell.A01],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A10],
            upper[FactorialCell.A11] - lower[FactorialCell.A10],
        ),
        (
            lower[FactorialCell.A11] - upper[FactorialCell.A00],
            upper[FactorialCell.A11] - lower[FactorialCell.A00],
        ),
        _interaction_bounds(
            {
                cell: (None, lower[cell], upper[cell], 0)
                for cell in FACTORIAL_CELL_ORDER
            }
        ),
        tuple(unit_effects),
        classify_factorial_pattern(means),
        realization_diagnostics,
    )


def _task_unit_cell(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    cell: FactorialCell,
    metric: Metric,
) -> tuple[float | None, float, float, int]:
    return _task_unit_cell_for_realizations(
        assignments,
        outcomes,
        policy,
        tasks,
        task_unit_id,
        cell,
        metric,
        policy.realizations,
    )


def _task_unit_cell_for_realizations(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_id: str,
    cell: FactorialCell,
    metric: Metric,
    realizations: tuple[object, ...],
) -> tuple[float | None, float, float, int]:
    task_ids = sorted(
        {
            item.block.task_instance_id
            for item in assignments
            if item.block.task_unit_id == task_unit_id
        }
    )
    if not task_ids or any(task_id not in tasks for task_id in task_ids):
        raise ValueError("factorial task unit lacks frozen task records")
    task_total = sum(tasks[task_id].weight for task_id in task_ids)
    if not realizations:
        raise ValueError("factorial realization subset cannot be empty")
    realization_total = sum(item.weight for item in realizations)
    point = lower = upper = 0.0
    point_known = True
    count = 0
    for task_id in task_ids:
        task_weight = tasks[task_id].weight / task_total
        for realization in realizations:
            realization_weight = realization.weight / realization_total
            block = [
                item
                for item in assignments
                if item.block.task_unit_id == task_unit_id
                and item.block.task_instance_id == task_id
                and item.block.joint_realization_id == realization.realization_id
                and item.cell is cell
            ]
            if not block:
                raise ValueError("factorial randomization lacks common task-realization support")
            values = [_metric_value(outcomes[item.assignment_id], metric) for item in block]
            count += len(block)
            weight = task_weight * realization_weight
            if any(value[0] is None for value in values):
                point_known = False
            else:
                point += (
                    weight
                    * sum(value[0] for value in values if value[0] is not None)
                    / len(values)
                )
            lower += weight * sum(value[1] for value in values) / len(values)
            upper += weight * sum(value[2] for value in values) / len(values)
    return point if point_known else None, lower, upper, count


def _factorial_cell_estimate(
    assignments: tuple[FactorialAssignment, ...],
    cell: FactorialCell,
    units: list[tuple[float | None, float, float, int]],
) -> FactorialCellEstimate:
    point = None if any(item[0] is None for item in units) else sum(
        item[0] for item in units if item[0] is not None
    ) / len(units)
    return FactorialCellEstimate(
        cell,
        point,
        sum(item[1] for item in units) / len(units),
        sum(item[2] for item in units) / len(units),
        sum(item.cell is cell for item in assignments),
    )


def _difference(left: float | None, right: float | None) -> float | None:
    return None if left is None or right is None else left - right


def _interaction(values: Mapping[FactorialCell, float | None]) -> float | None:
    if any(values[cell] is None for cell in FACTORIAL_CELL_ORDER):
        return None
    return (
        float(values[FactorialCell.A11])
        - float(values[FactorialCell.A10])
        - float(values[FactorialCell.A01])
        + float(values[FactorialCell.A00])
    )


def _interaction_bounds(
    cells: Mapping[FactorialCell, tuple[float | None, float, float, int]],
) -> tuple[float, float]:
    return (
        cells[FactorialCell.A11][1]
        - cells[FactorialCell.A10][2]
        - cells[FactorialCell.A01][2]
        + cells[FactorialCell.A00][1],
        cells[FactorialCell.A11][2]
        - cells[FactorialCell.A10][1]
        - cells[FactorialCell.A01][1]
        + cells[FactorialCell.A00][2],
    )


def classify_factorial_pattern(
    values: Mapping[FactorialCell, float | None],
    *,
    tolerance: float = 1e-12,
) -> FactorialPattern:
    """Classify a four-cell surface without changing its numeric estimand."""

    if any(values.get(cell) is None for cell in FACTORIAL_CELL_ORDER):
        return FactorialPattern.NOT_EVALUABLE
    cells = tuple(float(values[cell]) for cell in FACTORIAL_CELL_ORDER)
    binary = tuple(
        round(value) if abs(value - round(value)) <= tolerance else None
        for value in cells
    )
    if binary == (0, 1, 1, 0):
        return FactorialPattern.XOR
    if binary == (0, 1, 1, 1):
        return FactorialPattern.REDUNDANT
    if binary == (0, 0, 0, 1):
        return FactorialPattern.PREREQUISITE
    factor_1_at_0 = cells[1] - cells[0]
    factor_1_at_1 = cells[3] - cells[2]
    factor_2_at_0 = cells[2] - cells[0]
    factor_2_at_1 = cells[3] - cells[1]
    if (
        factor_1_at_0 * factor_1_at_1 < -(tolerance**2)
        or factor_2_at_0 * factor_2_at_1 < -(tolerance**2)
    ):
        return FactorialPattern.REVERSAL
    interaction = cells[3] - cells[1] - cells[2] + cells[0]
    if abs(interaction) <= tolerance:
        return FactorialPattern.ADDITIVE
    return (
        FactorialPattern.POSITIVE_INTERACTION
        if interaction > 0.0
        else FactorialPattern.NEGATIVE_INTERACTION
    )


def _factorial_realization_diagnostics(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    aggregate_interaction: float | None,
) -> FactorialRealizationDiagnostics:
    realization_rows = tuple(
        _factorial_realization_interaction(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            (realization,),
            realization.realization_id,
            realization.application_order,
            realization.weight,
        )
        for realization in policy.realizations
    )
    orders = tuple(sorted({item.application_order for item in policy.realizations}))
    order_rows = tuple(
        _factorial_order_interaction(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            order,
        )
        for order in orders
    )
    leave_one_out = tuple(
        _factorial_leave_one_out(
            assignments,
            outcomes,
            policy,
            tasks,
            task_unit_ids,
            metric,
            omitted.realization_id,
        )
        for omitted in policy.realizations
        if len(policy.realizations) > 1
    )
    diagnostic_points = tuple(item.point for item in realization_rows) + tuple(
        item.point for item in order_rows
    ) + tuple(item.point for item in leave_one_out)
    return FactorialRealizationDiagnostics(
        realization_rows,
        order_rows,
        leave_one_out,
        _factorial_direction_robustness(aggregate_interaction, diagnostic_points),
    )


def _factorial_realization_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    realizations: tuple[object, ...],
    realization_id: str,
    application_order: tuple[int, int],
    weight: int,
) -> FactorialRealizationInteraction:
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialRealizationInteraction(
        realization_id, application_order, weight, point, lower, upper
    )


def _factorial_order_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    application_order: tuple[int, int],
) -> FactorialOrderInteraction:
    realizations = tuple(
        item for item in policy.realizations if item.application_order == application_order
    )
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialOrderInteraction(
        application_order,
        sum(item.weight for item in realizations),
        point,
        lower,
        upper,
    )


def _factorial_leave_one_out(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    omitted_realization_id: str,
) -> FactorialLeaveOneRealizationOut:
    realizations = tuple(
        item
        for item in policy.realizations
        if item.realization_id != omitted_realization_id
    )
    point, lower, upper = _factorial_subset_interaction(
        assignments, outcomes, policy, tasks, task_unit_ids, metric, realizations
    )
    return FactorialLeaveOneRealizationOut(
        omitted_realization_id, point, lower, upper
    )


def _factorial_subset_interaction(
    assignments: tuple[FactorialAssignment, ...],
    outcomes: Mapping[str, Outcome],
    policy: FactorialPolicy,
    tasks: Mapping[str, Task],
    task_unit_ids: list[str],
    metric: Metric,
    realizations: tuple[object, ...],
) -> tuple[float | None, float, float]:
    unit_cells = tuple(
        {
            cell: _task_unit_cell_for_realizations(
                assignments,
                outcomes,
                policy,
                tasks,
                task_unit_id,
                cell,
                metric,
                realizations,
            )
            for cell in FACTORIAL_CELL_ORDER
        }
        for task_unit_id in task_unit_ids
    )
    points = tuple(
        _interaction({cell: cells[cell][0] for cell in FACTORIAL_CELL_ORDER})
        for cells in unit_cells
    )
    bounds = tuple(_interaction_bounds(cells) for cells in unit_cells)
    point = (
        None
        if any(value is None for value in points)
        else sum(float(value) for value in points) / len(points)
    )
    return (
        point,
        sum(item[0] for item in bounds) / len(bounds),
        sum(item[1] for item in bounds) / len(bounds),
    )


def _factorial_direction_robustness(
    aggregate: float | None,
    diagnostics: tuple[float | None, ...],
    *,
    tolerance: float = 1e-12,
) -> str:
    if aggregate is None or any(item is None for item in diagnostics):
        return "not_evaluable"
    if len(diagnostics) <= 2:
        return "average_effect_only"
    if abs(aggregate) <= tolerance:
        return "no_average_direction"
    signed = tuple(float(item) * aggregate for item in diagnostics)
    if any(item < -(tolerance**2) for item in signed):
        return "direction_reversal"
    if all(item > tolerance**2 for item in signed):
        return "direction_robust"
    return "direction_fragile"


def _factorial_simultaneous_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    return _factorial_studentized_effect_family(
        estimates,
        plan,
        metric=plan.primary_metric,
        effects=(FactorialEffect.INTERACTION,),
        seed_namespace="factorial_primary_studentized_v2_",
    )


def _factorial_secondary_intervals(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    return _factorial_studentized_effect_family(
        estimates,
        plan,
        metric=plan.primary_metric,
        effects=plan.secondary_effects,
        seed_namespace="factorial_secondary_studentized_v2_",
    )


def _factorial_metric_families(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
) -> tuple[FactorialMetricFamilyInference, ...]:
    if not {
        FactorialEffect.FACTOR_1_GIVEN_FACTOR_2,
        FactorialEffect.FACTOR_2_GIVEN_FACTOR_1,
    } <= set(plan.secondary_effects):
        return ()
    effects = (FactorialEffect.INTERACTION, *plan.secondary_effects)
    families = []
    for family, metric in (
        (FactorialMetricFamily.FUNCTIONALITY, Metric.FUNCTIONALITY),
        (FactorialMetricFamily.JOINT, Metric.JOINT),
    ):
        if metric not in plan.metrics:
            continue
        intervals, critical = _factorial_studentized_effect_family(
            estimates,
            plan,
            metric=metric,
            effects=effects,
            seed_namespace=f"factorial_{family.value}_studentized_v2_",
        )
        families.append(
            FactorialMetricFamilyInference(family, metric, intervals, critical)
        )
    return tuple(families)


def _factorial_studentized_effect_family(
    estimates: tuple[FactorialCoordinateEstimate, ...],
    plan: FactorialAnalysisPlan,
    *,
    metric: Metric,
    effects: tuple[FactorialEffect, ...],
    seed_namespace: str,
) -> tuple[tuple[FactorialSimultaneousInterval, ...], float]:
    """Global task-unit bootstrap with replicate-specific studentization.

    A single draw is taken from the union of task units and all descendants move
    together.  This preserves dependence when pair supports partially overlap.
    A draw is valid only when every tested coordinate has adequate sampled
    support and a positive replicate standard error.
    """

    entries = []
    for estimate in estimates:
        if estimate.metric is not metric:
            continue
        for effect in effects:
            point = _factorial_effect(estimate, effect)
            values = tuple(
                (unit.task_unit_id, _task_unit_factorial_effect(unit, effect))
                for unit in estimate.task_unit_effects
            )
            if (
                point is None
                or len(values) < plan.minimum_task_units
                or any(value is None for _, value in values)
            ):
                continue
            numeric = tuple(float(value) for _, value in values)
            standard_error = _mean_standard_error(numeric)
            if standard_error <= 0.0:
                continue
            entries.append(
                (
                    estimate.coordinate_id,
                    effect,
                    float(point),
                    {unit_id: float(value) for unit_id, value in values},
                    standard_error,
                )
            )
    if not entries:
        return (), 0.0

    task_unit_union = tuple(
        sorted({unit_id for _, _, _, values, _ in entries for unit_id in values})
    )
    family_members = tuple((coordinate_id, effect.value) for coordinate_id, effect, *_ in entries)
    rng = random.Random(
        int(
            content_id(
                seed_namespace,
                {
                    "seed": plan.bootstrap_seed,
                    "task_unit_union": task_unit_union,
                    "family_members": family_members,
                    "quantile_method": plan.bootstrap_quantile_method,
                },
            )[-16:],
            16,
        )
    )
    maxima = []
    for _ in range(plan.bootstrap_draws):
        sampled_ids = tuple(
            task_unit_union[rng.randrange(len(task_unit_union))]
            for _ in task_unit_union
        )
        statistics_for_draw = []
        valid = True
        for _, _, point, value_by_unit, _ in entries:
            sample = tuple(
                value_by_unit[unit_id]
                for unit_id in sampled_ids
                if unit_id in value_by_unit
            )
            if len(sample) < plan.minimum_task_units:
                valid = False
                break
            replicate_error = _mean_standard_error(sample)
            if replicate_error <= 0.0:
                valid = False
                break
            replicate_point = sum(sample) / len(sample)
            statistics_for_draw.append(
                abs(replicate_point - point) / replicate_error
            )
        if valid:
            maxima.append(max(statistics_for_draw))

    minimum_valid = math.ceil(
        plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction
    )
    if len(maxima) < minimum_valid:
        return (), 0.0
    critical = _quantile(maxima, 1.0 - plan.alpha)
    intervals = []
    for coordinate_id, effect, point, _, standard_error in entries:
        lower_limit, upper_limit = _factorial_effect_limits(effect)
        intervals.append(
            FactorialSimultaneousInterval(
                coordinate_id,
                effect,
                standard_error,
                max(lower_limit, point - critical * standard_error),
                min(upper_limit, point + critical * standard_error),
            )
        )
    return tuple(intervals), critical


def _factorial_effect(
    estimate: FactorialCoordinateEstimate,
    effect: FactorialEffect,
) -> float | None:
    return getattr(estimate, effect.value)


def _task_unit_factorial_effect(
    unit: TaskUnitFactorialEffect,
    effect: FactorialEffect,
) -> float | None:
    cells = dict(unit.cell_points)
    if effect is FactorialEffect.FACTOR_1:
        return _difference(cells[FactorialCell.A10], cells[FactorialCell.A00])
    if effect is FactorialEffect.FACTOR_2:
        return _difference(cells[FactorialCell.A01], cells[FactorialCell.A00])
    if effect is FactorialEffect.FACTOR_1_GIVEN_FACTOR_2:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A01])
    if effect is FactorialEffect.FACTOR_2_GIVEN_FACTOR_1:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A10])
    if effect is FactorialEffect.JOINT:
        return _difference(cells[FactorialCell.A11], cells[FactorialCell.A00])
    return unit.interaction


def _factorial_effect_limits(effect: FactorialEffect) -> tuple[float, float]:
    return (-2.0, 2.0) if effect is FactorialEffect.INTERACTION else (-1.0, 1.0)


def _metric_value(outcome: Outcome, metric: Metric) -> tuple[int | None, int, int]:
    if metric is Metric.SECURE_YIELD:
        return outcome.secure_yield, outcome.secure_yield, outcome.latent_secure_upper
    if metric is Metric.JOINT:
        return outcome.joint, outcome.joint or 0, outcome.latent_joint_upper
    value = getattr(outcome, metric.value)
    if value is None:
        return None, 0, 1
    return value, value, value


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


__all__ = [
    "ATOMIC_CONFIRMATORY_ARMS",
    "AssignedArmEvidenceLedger",
    "AssignedArmITTRecord",
    "ConfirmatoryArm",
    "ConfirmatoryEffectStatus",
    "EvidenceLevel",
    "FactorialAnalysisPlan",
    "FactorialCellEstimate",
    "FactorialCoordinateEstimate",
    "FactorialEffect",
    "FactorialInferenceResult",
    "FactorialLeaveOneRealizationOut",
    "FactorialMetricFamily",
    "FactorialMetricFamilyInference",
    "FactorialOrderInteraction",
    "FactorialPattern",
    "FactorialRealizationDiagnostics",
    "FactorialRealizationInteraction",
    "FactorialSimultaneousInterval",
    "FamilyInferenceStatus",
    "FunctionalityGateStatus",
    "LeaveOneRealizationOutSuccessorEffect",
    "Metric",
    "PAIR_CONFIRMATORY_ARMS",
    "RealizationSuccessorEffect",
    "SuccessorAnalysisPlan",
    "SuccessorArmEstimate",
    "SuccessorContrast",
    "SuccessorContrastEstimate",
    "SuccessorCoordinateEstimate",
    "SuccessorFamilyInference",
    "SuccessorInferenceResult",
    "SuccessorIntervalFamily",
    "SuccessorRobustnessAssessment",
    "SuccessorRobustnessComponent",
    "SuccessorRobustnessInference",
    "SuccessorRobustnessInterval",
    "SuccessorSimultaneousInterval",
    "TaskUnitSuccessorContribution",
    "TargetArmEndpointSummary",
    "TargetEffectEstimate",
    "TargetFamilyInference",
    "TargetFamilyStatus",
    "TargetITTPlan",
    "TargetRandomizationPlan",
    "TargetSelectorYield",
    "TargetSelectorYieldResult",
    "TargetSlotYieldRecord",
    "TargetTaskArmVariant",
    "TargetTaskBundle",
    "TargetTaskUnitContribution",
    "SharedEvidenceRecord",
    "build_target_selector_yields",
    "classify_confirmatory_interval",
    "classify_factorial_pattern",
    "estimate_factorial_effects",
    "estimate_successor_effects",
    "estimate_target_itt",
    "freeze_assigned_arm_evidence",
    "randomize_target_confirmation",
]

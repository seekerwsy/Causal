"""Assigned-arm task-unit ITT and simultaneous inference for schema 3."""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache

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
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    ConfirmatoryArm,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text


class Metric(StrEnum):
    CODE_VALID = "code_valid"
    ORACLE_EVALUABLE = "oracle_evaluable"
    SECURE_YIELD = "secure_yield"
    FUNCTIONALITY = "functionality"
    JOINT = "joint"


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


class ContextAnalysisStatus(StrEnum):
    BLOCKED_NO_FROZEN_CONTEXT_RULE = "BLOCKED_NO_FROZEN_CONTEXT_RULE"


@dataclass(frozen=True, slots=True)
class ContextAnalysisPlan:
    """Inactive analysis; empty wire fields preserve existing tested artifacts."""

    status: ContextAnalysisStatus
    modifiers: tuple[()]
    joint_bootstrap_rule_sha256: None
    multiplicity_family_sha256: None

    def __post_init__(self) -> None:
        if (self.status is not ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE
            or self.modifiers != () or self.joint_bootstrap_rule_sha256 is not None
            or self.multiplicity_family_sha256 is not None):
            raise ValueError("context analysis is blocked; active or partial rules are unsupported")


def blocked_context_analysis_plan() -> ContextAnalysisPlan:
    return ContextAnalysisPlan(ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE, (), None, None)


class PairResponsePatternPlanStatus(StrEnum):
    BLOCKED_NO_FROZEN_PREDICATE = "BLOCKED_NO_FROZEN_PREDICATE"


@dataclass(frozen=True, slots=True)
class PairResponsePatternPlan:
    """Inactive classifier; no future label/predicate interface is exposed."""

    status: PairResponsePatternPlanStatus
    predicate_sha256: None
    labels: tuple[()]
    precedence: tuple[()]

    def __post_init__(self) -> None:
        if (self.status is not PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE
            or self.predicate_sha256 is not None or self.labels != () or self.precedence != ()):
            raise ValueError("Pair response-pattern classification is blocked; predicates are unsupported")


def blocked_pair_response_pattern_plan() -> PairResponsePatternPlan:
    return PairResponsePatternPlan(PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE, None, (), ())


@dataclass(frozen=True, slots=True)
class PairResponseSurface:
    mean_00: float
    mean_10: float
    mean_01: float
    mean_11: float
    factor_1_at_0: float
    factor_2_at_0: float
    joint: float
    factor_1_at_1: float
    factor_2_at_1: float
    interaction: float

    def __post_init__(self) -> None:
        values = (
            self.mean_00,
            self.mean_10,
            self.mean_01,
            self.mean_11,
            self.factor_1_at_0,
            self.factor_2_at_0,
            self.joint,
            self.factor_1_at_1,
            self.factor_2_at_1,
            self.interaction,
        )
        if any(type(value) is not float or not math.isfinite(value) for value in values):
            raise ValueError("Pair response surface values must be finite floats")
        if any(not 0 <= value <= 1 for value in values[:4]):
            raise ValueError("Pair response-surface cell means must be on [0, 1]")
        expected = (
            self.mean_10 - self.mean_00,
            self.mean_01 - self.mean_00,
            self.mean_11 - self.mean_00,
            self.mean_11 - self.mean_01,
            self.mean_11 - self.mean_10,
            self.mean_11 - self.mean_10 - self.mean_01 + self.mean_00,
        )
        observed = values[4:]
        if any(not math.isclose(left, right, abs_tol=1e-12) for left, right in zip(observed, expected, strict=True)):
            raise ValueError("Pair response surface effects do not match its four cell means")


class ResponsePatternStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED_NO_FROZEN_PREDICATE = "BLOCKED_NO_FROZEN_PREDICATE"
    NON_EVALUABLE = "NON_EVALUABLE"


@dataclass(frozen=True, slots=True)
class ResponsePatternAssessment:
    status: ResponsePatternStatus
    surface: PairResponseSurface | None
    label: None
    predicate_sha256: None
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.status) is not ResponsePatternStatus:
            raise TypeError("response-pattern status must be typed")
        if self.label is not None or self.predicate_sha256 is not None:
            raise ValueError("Pair response-pattern classification is blocked")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("response-pattern reasons must be canonical")
        if self.status is ResponsePatternStatus.NOT_APPLICABLE:
            if any(value is not None for value in (self.surface, self.label, self.predicate_sha256)) or self.reasons:
                raise ValueError("Atomic response-pattern assessment must be NOT_APPLICABLE only")
        elif self.status is ResponsePatternStatus.BLOCKED_NO_FROZEN_PREDICATE:
            if type(self.surface) is not PairResponseSurface or self.label is not None or self.predicate_sha256 is not None or self.reasons:
                raise ValueError("blocked Pair classification requires only its response surface")
        elif self.status is ResponsePatternStatus.NON_EVALUABLE:
            if self.label is not None or self.predicate_sha256 is not None or not self.reasons:
                raise ValueError("non-evaluable Pair classification requires reasons and no label")


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
    context_analysis: ContextAnalysisPlan = field(
        default_factory=blocked_context_analysis_plan
    )
    pair_response_patterns: PairResponsePatternPlan = field(
        default_factory=blocked_pair_response_pattern_plan
    )
    atomic_minimum_task_units_per_realization: int = 2
    pair_minimum_task_units_per_realization: int = 2

    def __post_init__(self) -> None:
        if type(self.bootstrap_seed) is not int:
            raise TypeError("target ITT bootstrap seed must be an integer")
        for minimum in (self.atomic_minimum_task_units_per_realization,
                        self.pair_minimum_task_units_per_realization):
            if type(minimum) is not int or minimum < 2:
                raise ValueError("target ITT needs at least two task units per realization")
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
        if type(self.context_analysis) is not ContextAnalysisPlan:
            raise TypeError("target ITT context analysis plan must be typed")
        if type(self.pair_response_patterns) is not PairResponsePatternPlan:
            raise TypeError("target ITT Pair response-pattern plan must be typed")

    @property
    def target_itt_plan_id(self) -> str:
        return content_id("target_itt_plan_", self)


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
    realization_id: str
    realization_weight: float

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "target contribution task_unit_id")
        require_text(self.stratum_id, "target contribution stratum_id")
        require_text(self.realization_id, "target contribution realization_id")
        if not 0 < self.realization_weight <= 1:
            raise ValueError("target contribution realization weight must be in (0, 1]")
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
    response_pattern: ResponsePatternAssessment

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
        if type(self.response_pattern) is not ResponsePatternAssessment:
            raise TypeError("target response-pattern assessment must be typed")
        if self.track is PolicyTrack.ATOMIC and self.response_pattern.status is not ResponsePatternStatus.NOT_APPLICABLE:
            raise ValueError("Atomic effects cannot receive Pair response-pattern labels")
        if self.track is PolicyTrack.PAIR and self.response_pattern.status is ResponsePatternStatus.NOT_APPLICABLE:
            raise ValueError("Pair effects must retain response-pattern readiness")


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
    stratum_weights: tuple[tuple[str, str, float], ...]
    assignments: int
    reasons: tuple[str, ...]


def estimate_target_itt(
    ledger: AssignedArmEvidenceLedger,
    plan: TargetITTPlan,
    *,
    evidence_level: EvidenceLevel = EvidenceLevel.TESTED,
) -> SharedEvidenceRecord:
    """Estimate one shared, direction-free Atomic and Pair confirmation record."""

    if type(ledger) is not AssignedArmEvidenceLedger or type(plan) is not TargetITTPlan:
        raise TypeError("target ITT requires a frozen assigned-arm ledger and plan")
    if type(evidence_level) is not EvidenceLevel:
        raise TypeError("target ITT evidence level must be typed")
    if plan.context_analysis.status is not ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE:
        raise ValueError(
            "context analysis is blocked until its frozen joint estimator is implemented"
        )
    if plan.pair_response_patterns.status is not PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE:
        raise ValueError(
            "Pair response-pattern classification is blocked until its predicates are implemented"
        )
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
    realization_by_unit = _target_realizations(assignments)
    contributions = tuple(
        TargetTaskUnitContribution(
            task_unit_id,
            stratum_by_unit[task_unit_id],
            _target_contrast(track, arms, arms),
            _target_contrast_lower(track, lower_values[task_unit_id], upper_values[task_unit_id]),
            _target_contrast_upper(track, lower_values[task_unit_id], upper_values[task_unit_id]),
            *realization_by_unit[task_unit_id],
        )
        for task_unit_id, arms in sorted(point_values.items())
    )
    counts = Counter((item.realization_id, item.stratum_id) for item in contributions)
    if any(count < plan.minimum_task_units_per_stratum for count in counts.values()):
        reasons.add("insufficient_task_units_per_stratum")
    realization_counts = Counter(item.realization_id for item in contributions)
    if any(count < _target_realization_minimum(track, plan) for count in realization_counts.values()):
        reasons.add("insufficient_task_units_per_realization")
    q = {item.realization_id: item.realization_weight for item in contributions}
    if not math.isclose(sum(q.values()), 1.0, abs_tol=1e-12):
        # Never renormalize surviving realizations into a different policy.
        return _TargetEffectWork(dispatch, track, None, None, None, None, (), contributions,
                                 (), len(assignments), ("incomplete_realization_support",))
    point, standard_error, stratum_weights = _target_point_standard_error(contributions)
    if standard_error == 0:
        reasons.add("zero_standard_error")
    unit_weights = _target_unit_mixture_weights(assignments)
    latent_lower = sum(unit_weights[item.task_unit_id] * item.latent_lower for item in contributions)
    latent_upper = sum(unit_weights[item.task_unit_id] * item.latent_upper for item in contributions)
    summaries = _target_arm_summaries(assignments, local_outcomes, expected_arms)
    for arm in summaries:
        if arm.code_validity and (
            (arm.code_validity - arm.oracle_evaluability) / arm.code_validity
            > plan.maximum_unknown_fraction_among_valid
        ):
            reasons.add("maximum_unknown_fraction_exceeded")
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
            plan.pair_response_patterns,
        )
    if all_reasons & {
        "insufficient_task_units_per_stratum",
        "insufficient_task_units_per_realization",
        "incomplete_realization_support",
        "maximum_unknown_fraction_exceeded",
    }:
        return _target_failed_family(
            track,
            TargetFamilyStatus.INSUFFICIENT_SUPPORT,
            works,
            "primary_family_insufficient_support",
            _target_margin(track, plan),
            plan.pair_response_patterns,
        )
    if "zero_standard_error" in all_reasons:
        return _target_failed_family(
            track,
            TargetFamilyStatus.ZERO_STANDARD_ERROR,
            works,
            "primary_family_zero_standard_error",
            _target_margin(track, plan),
            plan.pair_response_patterns,
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
            plan.pair_response_patterns,
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
        _target_effect_estimate(
            item,
            critical,
            margin,
            plan.pair_response_patterns,
        )
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
    response_pattern_plan: PairResponsePatternPlan,
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
            _response_pattern_assessment(
                item.track,
                item.arm_summaries,
                response_pattern_plan,
            ),
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
    response_pattern_plan: PairResponsePatternPlan,
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
        _response_pattern_assessment(
            work.track,
            work.arm_summaries,
            response_pattern_plan,
        ),
    )


def _response_pattern_assessment(
    track: PolicyTrack,
    summaries: tuple[TargetArmEndpointSummary, ...],
    plan: PairResponsePatternPlan,
) -> ResponsePatternAssessment:
    if track is PolicyTrack.ATOMIC:
        return ResponsePatternAssessment(
            ResponsePatternStatus.NOT_APPLICABLE,
            None,
            None,
            None,
            (),
        )
    if tuple(item.arm for item in summaries) != PAIR_CONFIRMATORY_ARMS:
        return ResponsePatternAssessment(
            ResponsePatternStatus.NON_EVALUABLE,
            None,
            None,
            None,
            ("pair_response_surface_unavailable",),
        )
    means = {item.arm: float(item.secure_yield) for item in summaries}
    mean_00 = means[ConfirmatoryArm.PAIR_00]
    mean_10 = means[ConfirmatoryArm.PAIR_10]
    mean_01 = means[ConfirmatoryArm.PAIR_01]
    mean_11 = means[ConfirmatoryArm.PAIR_11]
    surface = PairResponseSurface(
        mean_00,
        mean_10,
        mean_01,
        mean_11,
        mean_10 - mean_00,
        mean_01 - mean_00,
        mean_11 - mean_00,
        mean_11 - mean_01,
        mean_11 - mean_10,
        mean_11 - mean_10 - mean_01 + mean_00,
    )
    if plan.status is PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE:
        return ResponsePatternAssessment(
            ResponsePatternStatus.BLOCKED_NO_FROZEN_PREDICATE,
            surface,
            None,
            None,
            (),
        )
    raise ValueError("frozen Pair response-pattern predicates lack an implementation")


def _target_margin(track: PolicyTrack, plan: TargetITTPlan) -> float:
    return (
        plan.atomic_practical_margin
        if track is PolicyTrack.ATOMIC
        else plan.pair_practical_margin
    )


def _target_realizations(assignments: Sequence[AssignedArmITTRecord]) -> dict[str, tuple[str, float]]:
    by_unit: dict[str, set[tuple[str, float]]] = defaultdict(set)
    by_realization: dict[str, set[float]] = defaultdict(set)
    for item in assignments:
        by_unit[item.task_unit_id].add((item.realization_id, float(item.realization_weight)))
        by_realization[item.realization_id].add(float(item.realization_weight))
    if any(len(values) != 1 for values in by_unit.values()):
        raise ValueError("one task-policy coordinate must retain exactly one realization")
    if any(len(values) != 1 for values in by_realization.values()):
        raise ValueError("realization policy weights drift across task units")
    if any(not 0 < next(iter(values)) <= 1 for values in by_realization.values()):
        raise ValueError("realization policy weights must be in (0, 1]")
    return {unit: next(iter(values)) for unit, values in by_unit.items()}


def _target_unit_mixture_weights(assignments: Sequence[AssignedArmITTRecord]) -> dict[str, float]:
    realizations = _target_realizations(assignments)
    counts = Counter(realization for realization, _ in realizations.values())
    return {unit: q / counts[realization] for unit, (realization, q) in realizations.items()}


def _target_realization_minimum(track: PolicyTrack, plan: TargetITTPlan) -> int:
    return (plan.atomic_minimum_task_units_per_realization if track is PolicyTrack.ATOMIC
            else plan.pair_minimum_task_units_per_realization)


@lru_cache(maxsize=128)
def _target_assignment_cells(assignments: tuple[AssignedArmITTRecord, ...]):
    """Validate and index immutable descendants once, independently of outcomes."""
    _target_realizations(assignments)
    grouped = defaultdict(list)
    task_weights: dict[tuple[str, str], set[float]] = defaultdict(set)
    arms_by_unit: dict[str, set[ConfirmatoryArm]] = defaultdict(set)
    instances_by_unit = defaultdict(set)
    for item in assignments:
        grouped[(item.task_unit_id, item.task_instance_id, item.arm)].append(item.assignment_id)
        task_weights[(item.task_unit_id, item.task_instance_id)].add(float(item.task_instance_weight))
        arms_by_unit[item.task_unit_id].add(item.arm)
        instances_by_unit[item.task_unit_id].add(item.task_instance_id)
    if any(len(values) != 1 for values in task_weights.values()):
        raise ValueError("task-instance weights drift inside descendants")
    cells = []
    for unit, arms in sorted(arms_by_unit.items()):
        instances = sorted(instances_by_unit[unit])
        total_weight = sum(next(iter(task_weights[(unit, instance)])) for instance in instances)
        arm_cells = []
        for arm in sorted(arms, key=lambda item: item.value):
            descendants = []
            for instance in instances:
                ids = grouped.get((unit, instance, arm))
                if not ids:
                    raise ValueError("assigned-arm hierarchy lacks complete task support")
                descendants.append((next(iter(task_weights[(unit, instance)])) / total_weight, tuple(ids)))
            arm_cells.append((arm, tuple(descendants)))
        cells.append((unit, tuple(arm_cells)))
    return tuple(cells)


def _target_unit_arm_values(
    assignments: tuple[AssignedArmITTRecord, ...],
    outcomes: Mapping[str, Outcome],
    getter: Callable[[Outcome], float],
) -> dict[str, dict[ConfirmatoryArm, float]]:
    result = {}
    for unit, arms in _target_assignment_cells(assignments):
        result[unit] = {}
        for arm, descendants in arms:
            total = 0.0
            for weight, ids in descendants:
                # These endpoint getters return binary values, so the sum is an
                # exact count; constructing Fraction objects adds no precision.
                total += weight * (sum(getter(outcomes[key]) for key in ids) / len(ids))
            result[unit][arm] = total
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
) -> tuple[float, float, tuple[tuple[str, str, float], ...]]:
    cells: dict[tuple[str, str], list[float]] = defaultdict(list)
    counts = Counter(item.realization_id for item in contributions)
    q = {item.realization_id: item.realization_weight for item in contributions}
    for item in contributions:
        cells[(item.realization_id, item.stratum_id)].append(item.point)
    weights = tuple((r, s, q[r] * len(values) / counts[r]) for (r, s), values in sorted(cells.items()))
    point = sum(weight * statistics.mean(cells[(r, s)]) for r, s, weight in weights)
    if any(len(values) < 2 for values in cells.values()):
        return point, 0.0, weights
    variance = sum(weight ** 2 * statistics.variance(cells[(r, s)]) / len(cells[(r, s)])
                   for r, s, weight in weights)
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
    weights = _target_unit_mixture_weights(assignments)
    summaries = []
    for arm in arms:
        arm_assignments = tuple(item for item in assignments if item.arm is arm)
        arm_outcomes = tuple(outcomes[item.assignment_id] for item in arm_assignments)
        summaries.append(
            TargetArmEndpointSummary(
                arm,
                len(arm_assignments),
                sum(weights[unit] * item[arm] for unit, item in values[Metric.SECURE_YIELD].items()),
                sum(weights[unit] * item[arm] for unit, item in values[Metric.CODE_VALID].items()),
                sum(weights[unit] * item[arm] for unit, item in values[Metric.ORACLE_EVALUABLE].items()),
                sum(weights[unit] * item[arm] for unit, item in values[Metric.FUNCTIONALITY].items()),
                sum(weights[unit] * item[arm] for unit, item in values[Metric.JOINT].items()),
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
    seed = int(content_hash({
        "domain": "target_max_t_task_unit_bootstrap_v1",
        "seed": plan.bootstrap_seed,
        "track": track,
        "plan_id": plan.target_itt_plan_id,
    })[-16:], 16)
    populations = tuple((stratum, tuple(sorted(units))) for stratum, units in sorted(global_units.items()))
    cells = []
    for work in works:
        by_cell = defaultdict(dict)
        for item in work.contributions:
            by_cell[(item.realization_id, item.stratum_id)][item.task_unit_id] = item.point
        cells.append(by_cell)
    maxima = []
    invalid = 0
    for sampled in _target_bootstrap_draws(populations, seed, plan.bootstrap_draws):
        statistics_by_effect = []
        for work, by_cell in zip(works, cells):
            draw = _target_resampled_point_standard_error(work, sampled, plan, by_cell=by_cell)
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


@lru_cache(maxsize=16)
def _target_bootstrap_draws(populations, seed, draws):
    """The frozen plan and task support determine draws, never outcomes."""
    rng = random.Random(seed)
    return tuple({stratum: tuple(population[rng.randrange(len(population))] for _ in population)
                  for stratum, population in populations} for _ in range(draws))


def _target_resampled_point_standard_error(
    work: _TargetEffectWork,
    sampled: Mapping[str, tuple[str, ...]],
    plan: TargetITTPlan,
    *, by_cell=None,
) -> tuple[float, float] | None:
    if by_cell is None:
        by_cell = defaultdict(dict)
        for item in work.contributions:
            by_cell[(item.realization_id, item.stratum_id)][item.task_unit_id] = item.point
    means, variances = {}, {}
    realization_counts = Counter()
    for r, stratum, _ in work.stratum_weights:
        eligible = by_cell[(r, stratum)]
        values = [eligible[unit] for unit in sampled[stratum] if unit in eligible]
        if len(values) < plan.minimum_task_units_per_stratum:
            return None
        realization_counts[r] += len(values)
        mean = sum(values) / len(values)
        means[(r, stratum)] = mean
        variances[(r, stratum)] = sum((value - mean) ** 2 for value in values) / (len(values) * (len(values) - 1))
    if any(count < _target_realization_minimum(work.track, plan) for count in realization_counts.values()):
        return None
    point = sum(weight * means[(r, s)] for r, s, weight in work.stratum_weights)
    variance = sum(weight ** 2 * variances[(r, s)] for r, s, weight in work.stratum_weights)
    return point, math.sqrt(max(variance, 0.0))


def _higher_quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("a higher quantile requires values")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(probability * len(ordered)) - 1))
    return ordered[index]


def summarize_development_itt(rows: Sequence[Mapping], plan: Mapping) -> list[dict]:
    """Bounded exploratory contrasts; never assign a confirmatory effect status.

    Average seeds inside each task before estimating differences. The exact two-sided
    task-block sign-flip null is computed by integer dynamic programming, including
    zero differences. Holm adjusts the complete prospectively listed family. Bootstrap
    CIs are marginal descriptive task-resampling intervals, explicitly not simultaneous.
    An infrastructure failure blocks its contrast instead of changing its denominator.
    """
    if (plan["method"] != "paired_task_signflip_holm_bootstrap_v1"
            or plan["scientific_claim_allowed"] is not False):
        raise ValueError("development analysis contract is invalid")
    ids = [row["assignment_id"] for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate assigned development outcome")
    effects = []
    for contrast in plan["contrasts"]:
        policy = contrast["policy_id"]
        interaction = contrast.get("kind") == "pair_interaction"
        if interaction:
            weights = {"A11": 1, "A10": -1, "A01": -1, "A00": 1}
            label = "A11 - A10 - A01 + A00"
        else:
            treatment, control = (contrast[key] for key in ("treatment", "control"))
            weights = {treatment: 1, control: -1}
            label = treatment + " - " + control
        local = [row for row in rows if row["policy_id"] == policy]
        units = sorted({row["task_unit_id"] for row in local})
        base = {"policy_id": policy, "comparison": label,
                "task_units": len(units), "effect": None, "ci_low": None, "ci_high": None,
                "p_value": None, "adjusted_p_value": None, "scientific_claim_allowed": False,
                "ci_type": "marginal_95_percent_task_bootstrap_descriptive"}
        differences, arm_rates, blocked = [], [], False
        expected_seeds = set(plan["generation_seeds"])
        for unit in units:
            cell = [row for row in local if row["task_unit_id"] == unit and row["arm"] in weights]
            arms = {arm: [row for row in cell if row["arm"] == arm] for arm in weights}
            if any(len(values) != len(expected_seeds) or {row["seed"] for row in values} != expected_seeds
                   or any(row.get("secure_code_yield") not in (0, 1) or row.get("error") for row in values)
                   for values in arms.values()):
                blocked = True
                continue
            rates = [sum(row["secure_code_yield"] for row in arms[arm]) / len(expected_seeds)
                     for arm in weights]
            arm_rates.append(rates)
            differences.append(sum(rate * weight for rate, weight in zip(rates, weights.values(), strict=True)))
        if blocked or len(differences) != len(units) or not units:
            effects.append({**base, "status": "BLOCKED_MISSING_ASSIGNED_OUTCOME"})
            continue
        denominator = len(expected_seeds)
        magnitudes = [abs(round(value * denominator)) for value in differences]
        counts = {0: 1}
        for value in magnitudes:
            new = defaultdict(int)
            for total, count in counts.items():
                new[total + value] += count
                new[total - value] += count
            counts = new
        observed = abs(round(sum(differences) * denominator))
        probability = sum(count for value, count in counts.items() if abs(value) >= observed) / (2 ** len(units))
        rng = random.Random(plan["bootstrap_seed"])
        draws = [sum(differences[rng.randrange(len(units))] for _ in units) / len(units)
                 for _ in range(plan["bootstrap_draws"])]
        summary = {**base, "status": "DEVELOPMENT_ESTIMATE", "effect": sum(differences) / len(units),
                        "ci_low": _higher_quantile(draws, 0.025), "ci_high": _higher_quantile(draws, 0.975),
                        "p_value": None if interaction else probability,
                        "task_differences": dict(zip(units, differences, strict=True)),
                        "zero_empirical_variation": len(set(differences)) == 1}
        if interaction:
            summary.update(cell_secure_yields={arm: sum(r[index] for r in arm_rates) / len(units)
                                               for index, arm in enumerate(weights)},
                           inference_status="DESCRIPTIVE_ONLY_NO_PAIR_NULL_TEST",
                           response_pattern_status="BLOCKED_NO_FROZEN_JOINT_RULE")
        else:
            summary.update(treatment_secure_yield=sum(r[0] for r in arm_rates) / len(units),
                           control_secure_yield=sum(r[1] for r in arm_rates) / len(units))
        effects.append(summary)
    # Missing tests remain in the family as p=1; they are not silently removed.
    ordered = sorted(range(len(effects)), key=lambda i: effects[i]["p_value"] if effects[i]["p_value"] is not None else 1.0)
    previous = 0.0
    for rank, index in enumerate(ordered):
        effect = effects[index]
        raw = effect["p_value"] if effect["p_value"] is not None else 1.0
        previous = max(previous, min(1.0, (len(effects) - rank) * raw))
        if effect["p_value"] is not None:
            effect["adjusted_p_value"] = previous
            effect["development_signal"] = previous <= plan["alpha"] and abs(effect["effect"]) >= plan["minimum_effect"]
        else:
            effect["development_signal"] = False
    return effects


def summarize_development_models(rows_by_model: Mapping[str, Sequence[Mapping]], plan: Mapping) -> dict:
    """Keep models separate and adjust their complete shared development family.

    Model is an effect coordinate, not an independent task. Assignment identifiers
    can repeat between model-specific runs; their full coordinates must agree.
    This descriptive table does not change either run's frozen analysis.
    """
    if not rows_by_model:
        raise ValueError('model comparison requires assigned development outcomes')
    coordinates = None
    effects, sampling, counts = [], {}, {}
    all_units = set()
    for model, rows in sorted(rows_by_model.items()):
        local_coordinates = [(r['policy_id'], r['task_unit_id'], r['arm'], r['seed']) for r in rows]
        if len(local_coordinates) != len(set(local_coordinates)):
            raise ValueError('duplicate task-policy-arm-seed coordinate within model')
        if coordinates is not None and set(local_coordinates) != coordinates:
            raise ValueError('model comparison requires the same assigned task and seed coordinates')
        coordinates = set(local_coordinates)
        all_units.update(r['task_unit_id'] for r in rows)
        counts[model] = {'assigned_rows': len(rows),
                         'independent_task_units': len({r['task_unit_id'] for r in rows})}
        sampling[model] = summarize_development_sampling(rows, plan)
        for row in summarize_development_itt(rows, plan):
            effects.append({**row, 'model_id': model,
                            'per_model_adjusted_p_value': row['adjusted_p_value']})
    previous = 0.0
    order = sorted(range(len(effects)), key=lambda i: effects[i]['p_value'] if effects[i]['p_value'] is not None else 1.0)
    for rank, index in enumerate(order):
        row = effects[index]
        raw = row['p_value'] if row['p_value'] is not None else 1.0
        previous = max(previous, min(1.0, (len(effects) - rank) * raw))
        row['adjusted_p_value'] = previous if row['p_value'] is not None else None
        row['development_signal'] = (row['p_value'] is not None and previous <= plan['alpha']
                                     and abs(row['effect']) >= plan['minimum_effect'])
    return {'status': 'DEVELOPMENT_MODEL_COMPARISON', 'scientific_claim_allowed': False,
            'independent_task_units': len(all_units), 'models': counts,
            'assigned_rows': sum(len(rows) for rows in rows_by_model.values()),
            'family_size': len(effects), 'multiplicity': 'Holm across every listed model-policy-contrast',
            'effects': effects, 'sampling': sampling}


def summarize_development_sampling(rows: Sequence[Mapping], plan: Mapping) -> dict:
    """Describe finite-generation noise without treating seeds as new tasks.

    Wilson intervals describe a single task/arm's secure-yield probability under
    independent requested samples. Contrast MC errors resample no tasks: they
    describe the fixed task set across its shared seed labels. Neither is a
    population-effect confidence interval or a confirmatory decision.
    """
    seeds = tuple(plan['generation_seeds'])
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError('sampling diagnostics require unique declared seeds')
    groups = defaultdict(list)
    for row in rows:
        groups[(row['policy_id'], row['task_unit_id'], row['arm'])].append(row)
    cells, indexed = [], {}
    for (policy, task, arm), members in sorted(groups.items()):
        complete = (len(members) == len(seeds) and {row['seed'] for row in members} == set(seeds)
                    and all(row.get('secure_code_yield') in (0, 1) and not row.get('error') for row in members))
        values = [row['secure_code_yield'] for row in members] if complete else []
        rate = statistics.mean(values) if values else None
        variance = statistics.variance(values) if len(values) > 1 else None
        interval = None
        if values:
            z, n = 1.959963984540054, len(values)
            scale = 1 + z * z / n
            center = (rate + z * z / (2 * n)) / scale
            half = z * math.sqrt(rate * (1 - rate) / n + z * z / (4 * n * n)) / scale
            interval = [max(0.0, center - half), min(1.0, center + half)]
        codes = [row['code'] for row in members if isinstance(row.get('code'), str)]
        cell = {'policy_id': policy, 'task_unit_id': task, 'arm': arm,
                'status': 'COMPLETE' if complete else 'INCOMPLETE_ASSIGNED_CELL',
                'assigned_samples': len(members), 'expected_samples': len(seeds),
                'failed_samples': sum(bool(row.get('error')) for row in members),
                'secure_samples': sum(row.get('secure_code_yield') == 1 for row in members),
                'security_counts': dict(Counter(row.get('security_status') or 'unavailable' for row in members)),
                'functionality_counts': dict(Counter(row.get('functionality_status') or 'unavailable' for row in members)),
                'code_samples': len(codes), 'distinct_code_samples': len(set(codes)),
                'secure_yield': rate, 'sample_variance': variance,
                'mc_standard_error': math.sqrt(variance / len(seeds)) if variance is not None else None,
                'wilson95_secure_yield_probability': interval,
                'mixed_secure_yield_across_seeds': 0 < rate < 1 if rate is not None else None}
        cells.append(cell)
        indexed[(policy, task, arm)] = ({row['seed']: row['secure_code_yield'] for row in members}
                                       if complete else None)
    contrasts = []
    for comparison in plan['contrasts']:
        policy = comparison['policy_id']
        units = sorted({task for p, task, _ in groups if p == policy})
        weights = {"A11": 1, "A10": -1, "A01": -1, "A00": 1} if comparison.get("kind") == "pair_interaction" else {
            comparison["treatment"]: 1, comparison["control"]: -1}
        blocks = [{arm: indexed.get((policy, task, arm)) for arm in weights} for task in units]
        complete = bool(blocks) and all(cell is not None for block in blocks for cell in block.values())
        values = ([statistics.mean(sum(block[arm][seed] * weight for arm, weight in weights.items())
                                   for block in blocks) for seed in seeds]
                  if complete else [])
        contrasts.append({**comparison, 'task_units': len(units), 'requested_seeds': len(seeds),
                          'status': 'COMPLETE' if complete else 'INCOMPLETE_ASSIGNED_CONTRAST',
                          'effect_by_seed': dict(zip(map(str, seeds), values)) if complete else None,
                          'fixed_tasks_effect_mean': statistics.mean(values) if values else None,
                          'fixed_tasks_mc_standard_error': math.sqrt(statistics.variance(values) / len(seeds))
                          if len(values) > 1 else None})
    return {'status': 'DESCRIPTIVE_GENERATION_SAMPLING', 'scientific_claim_allowed': False,
            'independent_unit': 'deduplicated_task_unit', 'requested_seeds': list(seeds),
            'assumption': 'MC errors and Wilson intervals assume independent requested seed replicates; '
                          'they do not establish backend determinism or independence of shared-service errors.',
            'interpretation': 'All assigned samples remain counted, including identical code. '
                              'No outcome-driven filtering. Finite-seed uncertainty is distinct from task-population uncertainty.',
            'cells': cells, 'contrasts': contrasts}

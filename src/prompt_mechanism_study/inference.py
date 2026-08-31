"""Assigned-arm task-unit ITT and simultaneous inference for schema 3."""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.measurement import InfrastructureFailure
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
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
    FROZEN = "FROZEN"


@dataclass(frozen=True, slots=True)
class ContextModifierSpec:
    """One prospectively assigned Stage-III heterogeneity coordinate."""

    modifier_id: str
    source_field: str
    levels: tuple[str, ...]
    stratum_assignment_rule_id: str
    missing_value_policy: str
    task_assignment_sha256: str
    context_contrast_family_id: str
    policy_semantics_sha256: str
    realization_family_sha256: str
    eligible_tracks: tuple[PolicyTrack, ...]
    estimand_ids: tuple[str, ...]
    minimum_task_units_per_level: int

    def __post_init__(self) -> None:
        require_text(self.modifier_id, "context modifier_id")
        require_text(self.source_field, "context modifier source_field")
        require_text(
            self.stratum_assignment_rule_id,
            "context stratum_assignment_rule_id",
        )
        require_text(
            self.context_contrast_family_id,
            "context contrast family_id",
        )
        if self.levels != tuple(sorted(set(self.levels))) or len(self.levels) < 2:
            raise ValueError("context modifier requires at least two canonical levels")
        if self.missing_value_policy not in {"EXPLICIT_MISSING_LEVEL", "FAIL_CLOSED"}:
            raise ValueError("context modifier missing-value policy is not frozen")
        _require_digest(self.task_assignment_sha256, "context task assignment")
        _require_digest(self.policy_semantics_sha256, "context policy semantics")
        _require_digest(self.realization_family_sha256, "context realization family")
        if (
            not self.eligible_tracks
            or len(set(self.eligible_tracks)) != len(self.eligible_tracks)
            or any(type(item) is not PolicyTrack for item in self.eligible_tracks)
            or tuple(sorted(self.eligible_tracks, key=lambda item: item.value))
            != self.eligible_tracks
        ):
            raise ValueError("context modifier tracks must be typed and canonical")
        if self.estimand_ids != tuple(sorted(set(self.estimand_ids))) or not self.estimand_ids:
            raise ValueError("context modifier estimands must be non-empty and canonical")
        if type(self.minimum_task_units_per_level) is not int or self.minimum_task_units_per_level < 2:
            raise ValueError("context modifier minimum support must be at least two")


@dataclass(frozen=True, slots=True)
class ContextAnalysisPlan:
    status: ContextAnalysisStatus
    modifiers: tuple[ContextModifierSpec, ...]
    joint_bootstrap_rule_sha256: str | None
    multiplicity_family_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.status) is not ContextAnalysisStatus:
            raise TypeError("context analysis status must be typed")
        modifier_ids = tuple(item.modifier_id for item in self.modifiers)
        if any(type(item) is not ContextModifierSpec for item in self.modifiers) or modifier_ids != tuple(
            sorted(set(modifier_ids))
        ):
            raise ValueError("context modifiers must be typed, unique, and canonical")
        if self.status is ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE:
            if self.modifiers or self.joint_bootstrap_rule_sha256 is not None or self.multiplicity_family_sha256 is not None:
                raise ValueError("blocked context analysis cannot carry partial rules")
        else:
            if not self.modifiers or self.joint_bootstrap_rule_sha256 is None or self.multiplicity_family_sha256 is None:
                raise ValueError("frozen context analysis requires complete rules")
            _require_digest(self.joint_bootstrap_rule_sha256, "context bootstrap rule")
            _require_digest(self.multiplicity_family_sha256, "context multiplicity family")


def blocked_context_analysis_plan() -> ContextAnalysisPlan:
    return ContextAnalysisPlan(
        ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE,
        (),
        None,
        None,
    )


class PairResponsePatternPlanStatus(StrEnum):
    BLOCKED_NO_FROZEN_PREDICATE = "BLOCKED_NO_FROZEN_PREDICATE"
    FROZEN = "FROZEN"


@dataclass(frozen=True, slots=True)
class PairResponsePatternPlan:
    status: PairResponsePatternPlanStatus
    predicate_sha256: str | None
    labels: tuple[str, ...]
    precedence: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.status) is not PairResponsePatternPlanStatus:
            raise TypeError("Pair response-pattern plan status must be typed")
        if self.status is PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE:
            if self.predicate_sha256 is not None or self.labels or self.precedence:
                raise ValueError("blocked Pair response-pattern plan cannot contain guessed rules")
        else:
            if self.predicate_sha256 is None or not self.labels or self.precedence != self.labels:
                raise ValueError("frozen Pair response-pattern plan requires ordered exact predicates")
            _require_digest(self.predicate_sha256, "Pair response-pattern predicates")
            if len(set(self.labels)) != len(self.labels) or any(
                not isinstance(item, str) or not item.strip() for item in self.labels
            ):
                raise ValueError("Pair response-pattern labels must be unique non-empty strings")


def blocked_pair_response_pattern_plan() -> PairResponsePatternPlan:
    return PairResponsePatternPlan(
        PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE,
        None,
        (),
        (),
    )


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
    CLASSIFIED = "CLASSIFIED"


@dataclass(frozen=True, slots=True)
class ResponsePatternAssessment:
    status: ResponsePatternStatus
    surface: PairResponseSurface | None
    label: str | None
    predicate_sha256: str | None
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.status) is not ResponsePatternStatus:
            raise TypeError("response-pattern status must be typed")
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
        else:
            if type(self.surface) is not PairResponseSurface or not self.label or self.predicate_sha256 is None or self.reasons:
                raise ValueError("classified Pair response requires surface, label, and predicate")
            _require_digest(self.predicate_sha256, "Pair response-pattern predicate")


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
    if plan.context_analysis.status is ContextAnalysisStatus.FROZEN:
        raise ValueError(
            "context analysis is blocked until its frozen joint estimator is implemented"
        )
    if plan.pair_response_patterns.status is PairResponsePatternPlanStatus.FROZEN:
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
            plan.pair_response_patterns,
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

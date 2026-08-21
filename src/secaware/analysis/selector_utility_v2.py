"""Strict confirmed yield@K and nested paired selector inference.

Discovery is never rerun here.  The only selector inputs are the exact frozen
rank slots embedded in :mod:`secaware.schema.selector_utility_v2`.  The point
status uses the real, replayed primary H x M max-|T| result.  Uncertainty is a
two-level semantic-cluster bootstrap: a shared outer union draw followed by a
bounded shared inner max-|T| family on that outer pseudo-population.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from fractions import Fraction

from pydantic import ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    ExactCoordinateClusterContributionV2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    GlobalUnionMaxTDrawV2,
    InvalidGlobalUnionDrawV2,
    MultiSupportSimultaneousInferenceResultV2,
    MultiSupportSimultaneousIntervalV2,
    run_frozen_domain_multi_support_simultaneous_inference_v2,
)
from secaware.analysis.simultaneous_v2 import CoordinateClusterContributionV2
from secaware.randomness import DeterministicRNG
from secaware.schema.common import model_shape_is_intact
from secaware.schema.multi_support_inference_v2 import CoordinateSpecificSupportV2
from secaware.schema.selector_utility_v2 import (
    SelectorPairInferenceStatusV2,
    SelectorPairNonEvaluableReasonV2,
    SelectorUtilityAnalysisPlanV2,
    SelectorUtilityPlanScopeV2,
    SelectorUtilitySlotStatusV2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "selector_utility_result_v2_"
_SEED_DOMAIN = b"secaware.selector-utility-nested-bootstrap.v2\x00"
_CLOSED_COVERAGE_PATTERN = re.compile(r"^provenance_closed_coverage_v2_[0-9a-f]{64}$")
_CLOSED_RUN_PATTERN = re.compile(r"^confirmatory_closed_run_evidence_v2_[0-9a-f]{64}$")
_FORMAL_RESULT_PATTERN = re.compile(r"^formal_confirmation_result_v2_[0-9a-f]{64}$")
_VERIFIED_PRIMARY_ACCESS = object()


class VerifiedSelectorPrimaryInputsV2:
    """Opaque, provenance-checked primary inputs consumed by the statistics core.

    Public constructors below are the only supported way to obtain this token.
    The synthetic constructor is available solely for a synthetic selector plan
    and can never authorize a formal selector claim.
    """

    __slots__ = (
        "_access",
        "artifacts",
        "confirmatory_closed_run_evidence_id",
        "formal_confirmation_result_id",
        "input_contributions_sha256",
        "intervals",
        "primary_simultaneous_result_id",
        "selector_utility_plan_id",
        "verification_scope",
        "verified_primary_inputs_id",
    )

    def __init__(
        self,
        *,
        access: object,
        artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
        intervals: tuple[MultiSupportSimultaneousIntervalV2, ...],
        primary_simultaneous_result_id: str,
        selector_utility_plan_id: str,
        input_contributions_sha256: str,
        verification_scope: str,
        confirmatory_closed_run_evidence_id: str | None = None,
        formal_confirmation_result_id: str | None = None,
    ) -> None:
        if access is not _VERIFIED_PRIMARY_ACCESS:
            raise _error("verified selector primary inputs cannot be caller constructed")
        self._access = access
        self.artifacts = artifacts
        self.confirmatory_closed_run_evidence_id = confirmatory_closed_run_evidence_id
        self.formal_confirmation_result_id = formal_confirmation_result_id
        self.intervals = intervals
        self.primary_simultaneous_result_id = primary_simultaneous_result_id
        self.selector_utility_plan_id = selector_utility_plan_id
        self.input_contributions_sha256 = input_contributions_sha256
        self.verification_scope = verification_scope
        self.verified_primary_inputs_id = "verified_selector_primary_inputs_v2_" + _digest(
            (
                tuple(item.contribution_artifact_id for item in artifacts),
                intervals,
                primary_simultaneous_result_id,
                selector_utility_plan_id,
                input_contributions_sha256,
                verification_scope,
                confirmatory_closed_run_evidence_id,
                formal_confirmation_result_id,
            )
        )


@dataclass(frozen=True, slots=True)
class StrictCoordinateConfirmationV2:
    test_coordinate_id: str
    hypothesis_id: str
    model_id: str
    direction_multiplier: int
    oriented_adjusted_interval_lower: float
    frozen_independent_cluster_count: int
    frozen_minimum_independent_cluster_count: int
    provenance_closed_coverage_manifest_id: str
    confirmed: bool


@dataclass(frozen=True, slots=True)
class StrictSlotContributionV2:
    slot_binding_id: str
    selector_id: str
    model_id: str
    rank: int
    slot_status: str
    final_hypothesis_id: str | None
    test_coordinate_id: str | None
    confirmed_contribution: int


@dataclass(frozen=True, slots=True)
class SelectorUtilityPointV2:
    selector_group_id: str
    selector_id: str
    model_id: str
    budget_k: int
    confirmed_slot_count: int
    utility_numerator: int
    utility_denominator: int
    utility: float
    slot_contributions: tuple[StrictSlotContributionV2, ...]


@dataclass(frozen=True, slots=True)
class SelectorPairPointV2:
    selector_pair_id: str
    model_id: str
    left_selector_id: str
    right_selector_id: str
    difference_numerator: int
    difference_denominator: int
    difference: float


@dataclass(frozen=True, slots=True)
class NestedStratumDrawReceiptV2:
    stratum_id: str
    occurrence_count: int
    sampled_clusters_sha256: str


@dataclass(frozen=True, slots=True)
class NestedCoordinateRetainedCountV2:
    test_coordinate_id: str
    stratum_id: str
    retained_occurrence_count: int


@dataclass(frozen=True, slots=True)
class OuterSelectorUtilityV2:
    selector_group_id: str
    confirmed_slot_count: int
    utility_numerator: int
    utility_denominator: int


@dataclass(frozen=True, slots=True)
class OuterSelectorPairDifferenceV2:
    selector_pair_id: str
    difference_numerator: int
    difference_denominator: int


@dataclass(frozen=True, slots=True)
class ValidNestedOuterDrawV2:
    replicate_index: int
    outer_sample_sha256: str
    stratum_draws: tuple[NestedStratumDrawReceiptV2, ...]
    coordinate_retained_counts: tuple[NestedCoordinateRetainedCountV2, ...]
    outer_coordinate_statistics_sha256: str
    inner_seed_sha256: str
    inner_valid_draw_count: int
    inner_invalid_draw_count: int
    inner_invalid_reasons_sha256: str
    inner_max_abs_t_sha256: str
    inner_critical_value: float
    confirmed_test_coordinate_ids: tuple[str, ...]
    selector_utilities: tuple[OuterSelectorUtilityV2, ...]
    pair_differences: tuple[OuterSelectorPairDifferenceV2, ...]


@dataclass(frozen=True, slots=True)
class InvalidNestedOuterDrawV2:
    replicate_index: int
    outer_sample_sha256: str
    stratum_draws: tuple[NestedStratumDrawReceiptV2, ...]
    reason_code: str
    test_coordinate_id: str | None
    stratum_id: str | None
    inner_valid_draw_count: int | None
    inner_invalid_draw_count: int | None


@dataclass(frozen=True, slots=True)
class SelectorPairSimultaneousIntervalV2:
    selector_pair_id: str
    estimate_numerator: int
    estimate_denominator: int
    estimate: float
    outer_standard_error: float
    simultaneous_lower: float
    simultaneous_upper: float


@dataclass(frozen=True, slots=True)
class SelectorUtilityAnalysisResultV2:
    selector_utility_result_id: str
    selector_utility_plan_id: str
    confirmatory_experiment_freeze_id: str
    candidate_universe_id: str
    selection_freeze_id: str
    primary_inference_plan_id: str
    primary_simultaneous_result_id: str
    primary_input_verification_scope: str
    primary_family_id: str
    input_contribution_artifact_ids: tuple[str, ...]
    input_contributions_sha256: str
    coordinate_confirmations: tuple[StrictCoordinateConfirmationV2, ...]
    selector_points: tuple[SelectorUtilityPointV2, ...]
    pair_points: tuple[SelectorPairPointV2, ...]
    valid_outer_draw_count: int
    invalid_outer_draw_count: int
    valid_outer_draws: tuple[ValidNestedOuterDrawV2, ...]
    invalid_outer_draws: tuple[InvalidNestedOuterDrawV2, ...]
    pair_inference_status: SelectorPairInferenceStatusV2
    pair_non_evaluable_reason: SelectorPairNonEvaluableReasonV2 | None
    pair_critical_value: float | None
    outer_pair_max_abs_t_sha256: str | None
    pair_intervals: tuple[SelectorPairSimultaneousIntervalV2, ...]
    conditional_on_single_frozen_discovery_split: bool
    formal_glue_required: bool
    formal_glue_completed: bool
    discovery_rerun_or_rerank_performed: bool
    formal_selector_claim_allowed: bool


class _InvalidNestedDraw(Exception):
    __slots__ = (
        "inner_invalid_draw_count",
        "inner_valid_draw_count",
        "reason_code",
        "stratum_id",
        "test_coordinate_id",
    )

    def __init__(
        self,
        *,
        reason_code: str,
        test_coordinate_id: str | None = None,
        stratum_id: str | None = None,
        inner_valid_draw_count: int | None = None,
        inner_invalid_draw_count: int | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.test_coordinate_id = test_coordinate_id
        self.stratum_id = stratum_id
        self.inner_valid_draw_count = inner_valid_draw_count
        self.inner_invalid_draw_count = inner_invalid_draw_count
        super().__init__(reason_code)


def _error(message: str = "selector utility v2 failed validation") -> ValueError:
    return ValueError(message)


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _validated_plan(plan: SelectorUtilityAnalysisPlanV2) -> SelectorUtilityAnalysisPlanV2:
    if type(plan) is not SelectorUtilityAnalysisPlanV2 or not model_shape_is_intact(plan):
        raise _error("selector utility analysis plan failed validation")
    try:
        return SelectorUtilityAnalysisPlanV2.model_validate(
            plan.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("selector utility analysis plan failed validation") from None


def _content_address_checked_plan(
    plan: SelectorUtilityAnalysisPlanV2,
) -> SelectorUtilityAnalysisPlanV2:
    """Check a plan already fully validated by a verified-input constructor."""

    if type(plan) is not SelectorUtilityAnalysisPlanV2 or not model_shape_is_intact(plan):
        raise _error("selector utility analysis plan failed validation")
    content = plan.model_dump(mode="json", exclude={"selector_utility_plan_id"})
    if plan.selector_utility_plan_id != "selector_utility_plan_v2_" + _digest(content):
        raise _error("selector utility analysis plan failed validation")
    return plan


def _artifact_payload(artifact: ConfirmatoryContributionArtifactV2) -> dict[str, object]:
    payload = asdict(artifact)
    payload.pop("contribution_artifact_id")
    return payload


def _artifact_input_digest(
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
) -> str:
    return _digest(
        tuple((item.test_coordinate_id, item.contribution_artifact_id) for item in artifacts)
    )


def _validated_artifact_family(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
) -> tuple[
    tuple[ConfirmatoryContributionArtifactV2, ...],
    dict[tuple[str, str, str], Fraction],
]:
    if isinstance(artifacts, (str, bytes, Mapping)):
        raise _error("complete primary contribution artifact family is required")
    try:
        snapshot = tuple(artifacts)
    except _FATAL:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("complete primary contribution artifact family is required") from None
    if len(snapshot) != len(plan.primary_inference_plan.coordinate_supports) or any(
        type(item) is not ConfirmatoryContributionArtifactV2 for item in snapshot
    ):
        raise _error("complete primary contribution artifact family is required")
    by_coordinate = {item.test_coordinate_id: item for item in snapshot}
    supports = {
        item.test_coordinate.test_coordinate_id: item
        for item in plan.primary_inference_plan.coordinate_supports
    }
    if len(by_coordinate) != len(snapshot) or set(by_coordinate) != set(supports):
        raise _error("complete primary contribution artifact family is required")
    ordered = tuple(by_coordinate[coordinate_id] for coordinate_id in sorted(supports))
    values: dict[tuple[str, str, str], Fraction] = {}
    coverage_ids_by_hypothesis: dict[str, set[str]] = {}
    for artifact in ordered:
        support = supports[artifact.test_coordinate_id]
        coordinate = support.test_coordinate
        if (
            artifact.contribution_artifact_id
            != "confirmatory_contributions_v2_" + _digest(_artifact_payload(artifact))
            or artifact.population_freeze_manifest_id != support.population_freeze_manifest_id
            or artifact.randomization_manifest_id != support.randomization_manifest_id
            or artifact.execution_policy_freeze_manifest_id
            != support.execution_policy_freeze_manifest_id
            or _CLOSED_COVERAGE_PATTERN.fullmatch(artifact.provenance_closed_coverage_manifest_id)
            is None
            or artifact.derivation_rule
            != "authenticated_block_arm_means_then_frozen_task_weights_then_qh_then_cluster_v1"
            or artifact.rational_arithmetic_until_final_projection is not True
        ):
            raise _error("primary contribution artifact provenance binding failed validation")
        coverage_ids_by_hypothesis.setdefault(coordinate.hypothesis_id, set()).add(
            artifact.provenance_closed_coverage_manifest_id
        )
        expected_keys = {
            (stratum.stratum_id, cluster_id)
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        }
        exact_rows: dict[tuple[str, str], Fraction] = {}
        for row in artifact.exact_coordinate_contributions:
            if (
                type(row) is not ExactCoordinateClusterContributionV2
                or row.test_coordinate_id != artifact.test_coordinate_id
                or type(row.numerator) is not int
                or type(row.denominator) is not int
                or row.denominator <= 0
            ):
                raise _error("primary contribution artifact support failed validation")
            key = (row.stratum_id, row.semantic_task_cluster_id)
            value = Fraction(row.numerator, row.denominator)
            if (
                key in exact_rows
                or value.numerator != row.numerator
                or value.denominator != row.denominator
                or not Fraction(-1, 1) <= value <= Fraction(1, 1)
            ):
                raise _error("primary contribution artifact support failed validation")
            exact_rows[key] = value
        projected_rows: dict[tuple[str, str], float] = {}
        for row in artifact.coordinate_contributions:
            if (
                type(row) is not CoordinateClusterContributionV2
                or row.test_coordinate_id != artifact.test_coordinate_id
                or type(row.estimate) is not float
                or not math.isfinite(row.estimate)
            ):
                raise _error("primary contribution artifact projection failed validation")
            key = (row.stratum_id, row.semantic_task_cluster_id)
            if key in projected_rows:
                raise _error("primary contribution artifact projection failed validation")
            projected_rows[key] = row.estimate
        if set(exact_rows) != expected_keys or set(projected_rows) != expected_keys:
            raise _error("primary contribution artifact support failed validation")
        for key, value in exact_rows.items():
            if projected_rows[key] != float(value):
                raise _error("primary contribution artifact projection failed validation")
            values[(artifact.test_coordinate_id, *key)] = value
    if any(len(item) != 1 for item in coverage_ids_by_hypothesis.values()) or len(
        {next(iter(item)) for item in coverage_ids_by_hypothesis.values()}
    ) != len(coverage_ids_by_hypothesis):
        raise _error("primary contribution artifact coverage family failed validation")
    return ordered, values


def _validated_public_primary_inputs(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
) -> VerifiedSelectorPrimaryInputsV2:
    checked_artifacts, _values = _validated_artifact_family(plan, artifacts)
    if type(primary_result) is not MultiSupportSimultaneousInferenceResultV2:
        raise _error("complete real primary result and contribution family are required")
    try:
        expected = run_frozen_domain_multi_support_simultaneous_inference_v2(
            plan.primary_inference_plan,
            checked_artifacts,
        )
    except _FATAL:
        raise
    except Exception:  # noqa: BLE001 - normalize the public provenance boundary
        raise _error("primary result provenance replay failed validation") from None
    if primary_result != expected:
        raise _error("primary result provenance replay failed validation")
    return VerifiedSelectorPrimaryInputsV2(
        access=_VERIFIED_PRIMARY_ACCESS,
        artifacts=checked_artifacts,
        intervals=primary_result.intervals,
        primary_simultaneous_result_id=primary_result.simultaneous_result_id,
        selector_utility_plan_id=plan.selector_utility_plan_id,
        input_contributions_sha256=primary_result.input_contributions_sha256,
        verification_scope="public_primary_result_full_replay_v1",
    )


def _primary_result_payload(
    result: MultiSupportSimultaneousInferenceResultV2,
) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("simultaneous_result_id")
    return payload


def _validated_same_run_primary_result(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
) -> MultiSupportSimultaneousInferenceResultV2:
    """Validate a just-produced formal primary result without replaying its 999 draws."""

    if type(primary_result) is not MultiSupportSimultaneousInferenceResultV2:
        raise _error("same-run formal primary result failed validation")
    expected_coordinate_ids = tuple(item.test_coordinate_id for item in plan.coordinate_bindings)
    interval_ids = tuple(item.test_coordinate_id for item in primary_result.intervals)
    artifact_ids = tuple(item.contribution_artifact_id for item in artifacts)
    valid_indices = tuple(item.replicate_index for item in primary_result.draws)
    invalid_indices = tuple(item.replicate_index for item in primary_result.invalid_draws)
    all_indices = tuple(sorted((*valid_indices, *invalid_indices)))
    if (
        plan.plan_scope is not SelectorUtilityPlanScopeV2.FORMAL
        or not plan.formal_selector_claim_allowed
        or primary_result.simultaneous_result_id
        != "multi_support_simultaneous_result_v2_"
        + _digest(_primary_result_payload(primary_result))
        or primary_result.inference_plan_id != plan.primary_inference_plan.inference_plan_id
        or primary_result.confirmatory_experiment_freeze_id
        != plan.confirmatory_experiment_freeze_id
        or primary_result.family_id != plan.primary_family_id
        or primary_result.global_multiplicity_family_policy_sha256
        != plan.primary_inference_plan.global_multiplicity_family_policy_sha256
        or re.fullmatch(r"[0-9a-f]{64}", primary_result.bootstrap_seed_sha256) is None
        or primary_result.input_contribution_artifact_ids != artifact_ids
        or primary_result.input_contributions_sha256 != _artifact_input_digest(artifacts)
        or not math.isfinite(primary_result.critical_value)
        or primary_result.critical_value <= 0.0
        or primary_result.valid_draw_count != len(primary_result.draws)
        or primary_result.invalid_draw_count != len(primary_result.invalid_draws)
        or primary_result.valid_draw_count
        < plan.primary_inference_plan.minimum_valid_bootstrap_draws
        or primary_result.valid_draw_count + primary_result.invalid_draw_count
        != plan.primary_inference_plan.bootstrap_samples
        or all_indices != tuple(range(plan.primary_inference_plan.bootstrap_samples))
        or len(set(valid_indices)) != len(valid_indices)
        or len(set(invalid_indices)) != len(invalid_indices)
        or any(
            type(item) is not GlobalUnionMaxTDrawV2 or not math.isfinite(item.max_abs_t)
            for item in primary_result.draws
        )
        or any(type(item) is not InvalidGlobalUnionDrawV2 for item in primary_result.invalid_draws)
        or interval_ids != expected_coordinate_ids
        or len(interval_ids) != len(set(interval_ids))
        or any(
            type(item) is not MultiSupportSimultaneousIntervalV2
            or not all(
                math.isfinite(value)
                for value in (
                    item.estimate,
                    item.standard_error,
                    item.simultaneous_lower,
                    item.simultaneous_upper,
                )
            )
            or item.standard_error <= 0.0
            or item.simultaneous_lower > item.estimate
            or item.simultaneous_upper < item.estimate
            for item in primary_result.intervals
        )
    ):
        raise _error("same-run formal primary result failed validation")
    return primary_result


def make_same_closed_run_formal_primary_inputs_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
    *,
    confirmatory_closed_run_evidence_id: str,
    formal_confirmation_result_id: str,
) -> VerifiedSelectorPrimaryInputsV2:
    """Seal a same-invocation formal primary bundle without a second 999-draw replay.

    This token never authorizes a formal claim by itself.  The combined formal
    wrapper must additionally prove that both identifiers came from the formal
    result it just generated from the exact closed-run root.
    """

    checked_plan = _validated_plan(plan)
    checked_artifacts, _values = _validated_artifact_family(checked_plan, artifacts)
    checked_result = _validated_same_run_primary_result(
        checked_plan,
        checked_artifacts,
        primary_result,
    )
    if (
        type(confirmatory_closed_run_evidence_id) is not str
        or _CLOSED_RUN_PATTERN.fullmatch(confirmatory_closed_run_evidence_id) is None
        or type(formal_confirmation_result_id) is not str
        or _FORMAL_RESULT_PATTERN.fullmatch(formal_confirmation_result_id) is None
    ):
        raise _error("same-run formal primary provenance identifiers failed validation")
    return VerifiedSelectorPrimaryInputsV2(
        access=_VERIFIED_PRIMARY_ACCESS,
        artifacts=checked_artifacts,
        intervals=checked_result.intervals,
        primary_simultaneous_result_id=checked_result.simultaneous_result_id,
        selector_utility_plan_id=checked_plan.selector_utility_plan_id,
        input_contributions_sha256=checked_result.input_contributions_sha256,
        verification_scope="same_closed_run_formal_primary_reuse_v1",
        confirmatory_closed_run_evidence_id=confirmatory_closed_run_evidence_id,
        formal_confirmation_result_id=formal_confirmation_result_id,
    )


def _higher_quantile(
    values: tuple[float, ...],
    *,
    alpha_numerator: int,
    alpha_denominator: int,
) -> float:
    if not values:
        raise _error("nested bootstrap has no valid draw")
    ordered = tuple(sorted(values))
    numerator = (alpha_denominator - alpha_numerator) * len(ordered)
    rank = (numerator + alpha_denominator - 1) // alpha_denominator
    return ordered[min(max(rank, 1), len(ordered)) - 1]


def _sample_digest(samples: Mapping[str, tuple[str, ...]]) -> str:
    return _digest(tuple((key, samples[key]) for key in sorted(samples)))


def _coordinate_statistics(
    support: CoordinateSpecificSupportV2,
    values: Mapping[tuple[str, str, str], Fraction],
    samples: Mapping[str, tuple[str, ...]],
) -> tuple[Fraction, float, tuple[NestedCoordinateRetainedCountV2, ...]]:
    coordinate_id = support.test_coordinate.test_coordinate_id
    estimate = Fraction(0, 1)
    variance = 0.0
    retained_counts = []
    for stratum in support.strata:
        support_set = frozenset(stratum.semantic_task_cluster_ids)
        retained = tuple(item for item in samples[stratum.stratum_id] if item in support_set)
        count = len(retained)
        if count < 2:
            raise _InvalidNestedDraw(
                reason_code="insufficient_retained_coordinate_clusters",
                test_coordinate_id=coordinate_id,
                stratum_id=stratum.stratum_id,
            )
        observations = tuple(
            values[(coordinate_id, stratum.stratum_id, cluster_id)] for cluster_id in retained
        )
        mean = sum(observations, Fraction(0, 1)) / count
        weight = stratum.stratum_weight
        estimate += weight * mean
        mean_float = float(mean)
        variance += (
            float(weight) ** 2
            * math.fsum((float(item) - mean_float) ** 2 for item in observations)
            / (count * (count - 1))
        )
        retained_counts.append(
            NestedCoordinateRetainedCountV2(
                test_coordinate_id=coordinate_id,
                stratum_id=stratum.stratum_id,
                retained_occurrence_count=count,
            )
        )
    standard_error = math.sqrt(variance)
    if not math.isfinite(standard_error) or standard_error <= 0.0:
        raise _InvalidNestedDraw(
            reason_code="zero_or_invalid_coordinate_standard_error",
            test_coordinate_id=coordinate_id,
        )
    return estimate, standard_error, tuple(retained_counts)


def _all_coordinate_statistics(
    plan: SelectorUtilityAnalysisPlanV2,
    values: Mapping[tuple[str, str, str], Fraction],
    samples: Mapping[str, tuple[str, ...]],
) -> tuple[
    dict[str, tuple[Fraction, float]],
    tuple[NestedCoordinateRetainedCountV2, ...],
]:
    statistics = {}
    counts = []
    for support in plan.primary_inference_plan.coordinate_supports:
        estimate, standard_error, retained = _coordinate_statistics(support, values, samples)
        coordinate_id = support.test_coordinate.test_coordinate_id
        statistics[coordinate_id] = (estimate, standard_error)
        counts.extend(retained)
    return statistics, tuple(
        sorted(counts, key=lambda item: (item.test_coordinate_id, item.stratum_id))
    )


def validate_selector_primary_inputs_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
) -> VerifiedSelectorPrimaryInputsV2:
    """Replay the public primary plan once and seal its exact selector inputs.

    This is deliberately not the future two-root formal glue.  A token created
    here is provenance checked, but the final result continues to declare that
    formal glue has not been completed.
    """

    checked_plan = _validated_plan(plan)
    return _validated_public_primary_inputs(checked_plan, artifacts, primary_result)


def make_synthetic_verified_selector_primary_inputs_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    *,
    synthetic_critical_value: float,
) -> VerifiedSelectorPrimaryInputsV2:
    """Seal a hand-checkable primary fixture for synthetic 19x19 tests only."""

    checked_plan = _validated_plan(plan)
    return _make_synthetic_verified_checked_plan(
        checked_plan,
        artifacts,
        synthetic_critical_value=synthetic_critical_value,
    )


def _make_synthetic_verified_selector_primary_inputs_from_fresh_plan_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    *,
    synthetic_critical_value: float,
) -> VerifiedSelectorPrimaryInputsV2:
    """Fast non-claiming path for a plan constructed immediately by the caller."""

    checked_plan = _content_address_checked_plan(plan)
    return _make_synthetic_verified_checked_plan(
        checked_plan,
        artifacts,
        synthetic_critical_value=synthetic_critical_value,
    )


def _make_synthetic_verified_checked_plan(
    checked_plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    *,
    synthetic_critical_value: float,
) -> VerifiedSelectorPrimaryInputsV2:
    if (
        checked_plan.plan_scope is not SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY
        or checked_plan.formal_selector_claim_allowed
        or type(synthetic_critical_value) is not float
        or not math.isfinite(synthetic_critical_value)
        or synthetic_critical_value <= 0.0
    ):
        raise _error("synthetic verified primary inputs require a non-claiming synthetic plan")
    checked_artifacts, values = _validated_artifact_family(checked_plan, artifacts)
    full_samples = {
        stratum.stratum_id: stratum.semantic_task_cluster_ids
        for stratum in checked_plan.primary_inference_plan.global_union_strata
    }
    statistics, _counts = _all_coordinate_statistics(checked_plan, values, full_samples)
    intervals = tuple(
        MultiSupportSimultaneousIntervalV2(
            test_coordinate_id=binding.test_coordinate_id,
            estimate_numerator=statistics[binding.test_coordinate_id][0].numerator,
            estimate_denominator=statistics[binding.test_coordinate_id][0].denominator,
            estimate=float(statistics[binding.test_coordinate_id][0]),
            standard_error=statistics[binding.test_coordinate_id][1],
            simultaneous_lower=(
                float(statistics[binding.test_coordinate_id][0])
                - synthetic_critical_value * statistics[binding.test_coordinate_id][1]
            ),
            simultaneous_upper=(
                float(statistics[binding.test_coordinate_id][0])
                + synthetic_critical_value * statistics[binding.test_coordinate_id][1]
            ),
        )
        for binding in checked_plan.coordinate_bindings
    )
    input_digest = _artifact_input_digest(checked_artifacts)
    result_id = "synthetic_verified_selector_primary_v2_" + _digest(
        (
            checked_plan.selector_utility_plan_id,
            input_digest,
            synthetic_critical_value,
            intervals,
        )
    )
    return VerifiedSelectorPrimaryInputsV2(
        access=_VERIFIED_PRIMARY_ACCESS,
        artifacts=checked_artifacts,
        intervals=intervals,
        primary_simultaneous_result_id=result_id,
        selector_utility_plan_id=checked_plan.selector_utility_plan_id,
        input_contributions_sha256=input_digest,
        verification_scope="synthetic_hand_checked_primary_fixture_v1",
    )


def _root_seed(plan: SelectorUtilityAnalysisPlanV2) -> bytes:
    return hashlib.sha256(
        _SEED_DOMAIN
        + bytes.fromhex(plan.analysis_seed_domain_sha256)
        + b"\x00"
        + plan.selector_utility_plan_id.encode("ascii")
    ).digest()


def _full_coordinate_confirmations(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
    intervals: tuple[MultiSupportSimultaneousIntervalV2, ...],
) -> tuple[StrictCoordinateConfirmationV2, ...]:
    intervals_by_coordinate = {item.test_coordinate_id: item for item in intervals}
    if set(intervals_by_coordinate) != {
        item.test_coordinate_id for item in plan.coordinate_bindings
    }:
        raise _error("verified primary interval family failed validation")
    artifacts_by_coordinate = {item.test_coordinate_id: item for item in artifacts}
    result = []
    for binding in plan.coordinate_bindings:
        interval = intervals_by_coordinate[binding.test_coordinate_id]
        oriented_lower = (
            interval.simultaneous_lower
            if binding.direction_multiplier == 1
            else -interval.simultaneous_upper
        )
        artifact = artifacts_by_coordinate[binding.test_coordinate_id]
        support_passed = (
            binding.frozen_independent_cluster_count
            >= binding.frozen_minimum_independent_cluster_count
        )
        provenance_complete = bool(artifact.provenance_closed_coverage_manifest_id)
        result.append(
            StrictCoordinateConfirmationV2(
                test_coordinate_id=binding.test_coordinate_id,
                hypothesis_id=binding.hypothesis_id,
                model_id=binding.model_id,
                direction_multiplier=binding.direction_multiplier,
                oriented_adjusted_interval_lower=oriented_lower,
                frozen_independent_cluster_count=binding.frozen_independent_cluster_count,
                frozen_minimum_independent_cluster_count=(
                    binding.frozen_minimum_independent_cluster_count
                ),
                provenance_closed_coverage_manifest_id=(
                    artifact.provenance_closed_coverage_manifest_id
                ),
                confirmed=(oriented_lower > 0.0 and support_passed and provenance_complete),
            )
        )
    return tuple(result)


def _selector_points(
    plan: SelectorUtilityAnalysisPlanV2,
    confirmed_coordinate_ids: frozenset[str],
) -> tuple[SelectorUtilityPointV2, ...]:
    coordinate_by_hm = {
        (item.hypothesis_id, item.model_id): item.test_coordinate_id
        for item in plan.coordinate_bindings
    }
    slots_by_id = {item.slot_binding_id: item for item in plan.slot_bindings}
    result = []
    for group in plan.selector_groups:
        slot_contributions = []
        for slot_id in group.slot_binding_ids:
            slot = slots_by_id[slot_id]
            coordinate_id = (
                coordinate_by_hm[(slot.final_hypothesis_id, slot.model_id)]
                if slot.slot_status is SelectorUtilitySlotStatusV2.PROTOCOLIZED
                and slot.final_hypothesis_id is not None
                else None
            )
            contribution = int(
                coordinate_id is not None and coordinate_id in confirmed_coordinate_ids
            )
            slot_contributions.append(
                StrictSlotContributionV2(
                    slot_binding_id=slot.slot_binding_id,
                    selector_id=slot.selector_id,
                    model_id=slot.model_id,
                    rank=slot.rank,
                    slot_status=slot.slot_status.value,
                    final_hypothesis_id=slot.final_hypothesis_id,
                    test_coordinate_id=coordinate_id,
                    confirmed_contribution=contribution,
                )
            )
        count = sum(item.confirmed_contribution for item in slot_contributions)
        result.append(
            SelectorUtilityPointV2(
                selector_group_id=group.selector_group_id,
                selector_id=group.selector_id,
                model_id=group.model_id,
                budget_k=group.budget_k,
                confirmed_slot_count=count,
                utility_numerator=Fraction(count, group.budget_k).numerator,
                utility_denominator=Fraction(count, group.budget_k).denominator,
                utility=float(Fraction(count, group.budget_k)),
                slot_contributions=tuple(slot_contributions),
            )
        )
    return tuple(result)


def _pair_points(
    plan: SelectorUtilityAnalysisPlanV2,
    selector_points: tuple[SelectorUtilityPointV2, ...],
) -> tuple[SelectorPairPointV2, ...]:
    by_group = {item.selector_group_id: item for item in selector_points}
    result = []
    for pair in plan.pair_family:
        left = by_group[pair.left_selector_group_id]
        right = by_group[pair.right_selector_group_id]
        difference = Fraction(left.utility_numerator, left.utility_denominator) - Fraction(
            right.utility_numerator, right.utility_denominator
        )
        result.append(
            SelectorPairPointV2(
                selector_pair_id=pair.selector_pair_id,
                model_id=pair.model_id,
                left_selector_id=pair.left_selector_id,
                right_selector_id=pair.right_selector_id,
                difference_numerator=difference.numerator,
                difference_denominator=difference.denominator,
                difference=float(difference),
            )
        )
    return tuple(result)


def _inner_confirmation_statuses(
    plan: SelectorUtilityAnalysisPlanV2,
    values: Mapping[tuple[str, str, str], Fraction],
    outer_samples: Mapping[str, tuple[str, ...]],
    outer_statistics: Mapping[str, tuple[Fraction, float]],
    *,
    inner_seed: bytes,
) -> tuple[frozenset[str], int, int, str, str, float]:
    rng = DeterministicRNG(inner_seed)
    maxima = []
    invalid_reasons = []
    for _replicate in range(plan.inner_bootstrap_samples):
        samples = {
            stratum_id: tuple(rng.choice(outer) for _ in outer)
            for stratum_id, outer in sorted(outer_samples.items())
        }
        try:
            inner_statistics, _counts = _all_coordinate_statistics(plan, values, samples)
        except _InvalidNestedDraw as invalid:
            invalid_reasons.append(
                (invalid.reason_code, invalid.test_coordinate_id, invalid.stratum_id)
            )
            continue
        max_abs_t = max(
            abs(
                float(inner_statistics[coordinate_id][0] - outer_statistics[coordinate_id][0])
                / inner_statistics[coordinate_id][1]
            )
            for coordinate_id in outer_statistics
        )
        if not math.isfinite(max_abs_t):
            invalid_reasons.append(("nonfinite_inner_max_abs_t", None, None))
            continue
        maxima.append(max_abs_t)
    if len(maxima) < plan.minimum_valid_inner_draws:
        raise _InvalidNestedDraw(
            reason_code="inner_valid_draw_count_below_frozen_minimum",
            inner_valid_draw_count=len(maxima),
            inner_invalid_draw_count=len(invalid_reasons),
        )
    critical = _higher_quantile(
        tuple(maxima),
        alpha_numerator=plan.alpha_numerator,
        alpha_denominator=plan.alpha_denominator,
    )
    bindings = {item.test_coordinate_id: item for item in plan.coordinate_bindings}
    confirmed = []
    for coordinate_id, (estimate, standard_error) in outer_statistics.items():
        binding = bindings[coordinate_id]
        lower = float(estimate) - critical * standard_error
        upper = float(estimate) + critical * standard_error
        oriented_lower = lower if binding.direction_multiplier == 1 else -upper
        if (
            oriented_lower > 0.0
            and binding.frozen_independent_cluster_count
            >= binding.frozen_minimum_independent_cluster_count
        ):
            confirmed.append(coordinate_id)
    return (
        frozenset(confirmed),
        len(maxima),
        len(invalid_reasons),
        _digest(tuple(invalid_reasons)),
        _digest(tuple(maxima)),
        critical,
    )


def _stratum_receipts(
    samples: Mapping[str, tuple[str, ...]],
) -> tuple[NestedStratumDrawReceiptV2, ...]:
    return tuple(
        NestedStratumDrawReceiptV2(
            stratum_id=stratum_id,
            occurrence_count=len(sample),
            sampled_clusters_sha256=_digest(sample),
        )
        for stratum_id, sample in sorted(samples.items())
    )


def _outer_draws(
    plan: SelectorUtilityAnalysisPlanV2,
    values: Mapping[tuple[str, str, str], Fraction],
) -> tuple[tuple[ValidNestedOuterDrawV2, ...], tuple[InvalidNestedOuterDrawV2, ...]]:
    root_seed = _root_seed(plan)
    rng = DeterministicRNG(root_seed)
    valid = []
    invalid = []
    for replicate in range(plan.outer_bootstrap_samples):
        samples = {
            stratum.stratum_id: tuple(
                rng.choice(stratum.semantic_task_cluster_ids)
                for _ in stratum.semantic_task_cluster_ids
            )
            for stratum in plan.primary_inference_plan.global_union_strata
        }
        sample_sha256 = _sample_digest(samples)
        receipts = _stratum_receipts(samples)
        try:
            statistics, retained_counts = _all_coordinate_statistics(plan, values, samples)
            inner_seed = hashlib.sha256(
                root_seed + b"\x00inner\x00" + replicate.to_bytes(8, "big")
            ).digest()
            (
                confirmed_ids,
                inner_valid,
                inner_invalid,
                inner_invalid_sha256,
                inner_max_t_sha256,
                inner_critical,
            ) = _inner_confirmation_statuses(
                plan,
                values,
                samples,
                statistics,
                inner_seed=inner_seed,
            )
            selector_points = _selector_points(plan, confirmed_ids)
            pair_points = _pair_points(plan, selector_points)
        except _InvalidNestedDraw as failure:
            invalid.append(
                InvalidNestedOuterDrawV2(
                    replicate_index=replicate,
                    outer_sample_sha256=sample_sha256,
                    stratum_draws=receipts,
                    reason_code=failure.reason_code,
                    test_coordinate_id=failure.test_coordinate_id,
                    stratum_id=failure.stratum_id,
                    inner_valid_draw_count=failure.inner_valid_draw_count,
                    inner_invalid_draw_count=failure.inner_invalid_draw_count,
                )
            )
            continue
        valid.append(
            ValidNestedOuterDrawV2(
                replicate_index=replicate,
                outer_sample_sha256=sample_sha256,
                stratum_draws=receipts,
                coordinate_retained_counts=retained_counts,
                outer_coordinate_statistics_sha256=_digest(
                    tuple(
                        (
                            coordinate_id,
                            estimate.numerator,
                            estimate.denominator,
                            standard_error,
                        )
                        for coordinate_id, (estimate, standard_error) in sorted(statistics.items())
                    )
                ),
                inner_seed_sha256=hashlib.sha256(inner_seed).hexdigest(),
                inner_valid_draw_count=inner_valid,
                inner_invalid_draw_count=inner_invalid,
                inner_invalid_reasons_sha256=inner_invalid_sha256,
                inner_max_abs_t_sha256=inner_max_t_sha256,
                inner_critical_value=inner_critical,
                confirmed_test_coordinate_ids=tuple(sorted(confirmed_ids)),
                selector_utilities=tuple(
                    OuterSelectorUtilityV2(
                        selector_group_id=item.selector_group_id,
                        confirmed_slot_count=item.confirmed_slot_count,
                        utility_numerator=item.utility_numerator,
                        utility_denominator=item.utility_denominator,
                    )
                    for item in selector_points
                ),
                pair_differences=tuple(
                    OuterSelectorPairDifferenceV2(
                        selector_pair_id=item.selector_pair_id,
                        difference_numerator=item.difference_numerator,
                        difference_denominator=item.difference_denominator,
                    )
                    for item in pair_points
                ),
            )
        )
    return tuple(valid), tuple(invalid)


def _pair_inference(
    plan: SelectorUtilityAnalysisPlanV2,
    pair_points: tuple[SelectorPairPointV2, ...],
    valid_draws: tuple[ValidNestedOuterDrawV2, ...],
) -> tuple[
    SelectorPairInferenceStatusV2,
    SelectorPairNonEvaluableReasonV2 | None,
    float | None,
    str | None,
    tuple[SelectorPairSimultaneousIntervalV2, ...],
]:
    if not pair_points:
        return (
            SelectorPairInferenceStatusV2.NON_EVALUABLE,
            SelectorPairNonEvaluableReasonV2.NO_PREREGISTERED_PAIRS,
            None,
            None,
            (),
        )
    if len(valid_draws) < plan.minimum_valid_outer_draws:
        return (
            SelectorPairInferenceStatusV2.NON_EVALUABLE,
            SelectorPairNonEvaluableReasonV2.INSUFFICIENT_VALID_OUTER_DRAWS,
            None,
            None,
            (),
        )
    point_by_pair = {item.selector_pair_id: item for item in pair_points}
    samples_by_pair: dict[str, list[float]] = {item.selector_pair_id: [] for item in pair_points}
    for draw in valid_draws:
        if {item.selector_pair_id for item in draw.pair_differences} != set(samples_by_pair):
            raise _error("outer selector pair family failed validation")
        for item in draw.pair_differences:
            samples_by_pair[item.selector_pair_id].append(
                float(Fraction(item.difference_numerator, item.difference_denominator))
            )
    standard_errors = {}
    for pair_id, samples in samples_by_pair.items():
        mean = math.fsum(samples) / len(samples)
        standard_error = math.sqrt(
            math.fsum((item - mean) ** 2 for item in samples) / (len(samples) - 1)
        )
        if not math.isfinite(standard_error) or standard_error <= 0.0:
            return (
                SelectorPairInferenceStatusV2.NON_EVALUABLE,
                SelectorPairNonEvaluableReasonV2.ZERO_OR_INVALID_PAIR_STANDARD_ERROR,
                None,
                None,
                (),
            )
        standard_errors[pair_id] = standard_error
    maxima = tuple(
        max(
            abs(
                float(
                    Fraction(item.difference_numerator, item.difference_denominator)
                    - Fraction(
                        point_by_pair[item.selector_pair_id].difference_numerator,
                        point_by_pair[item.selector_pair_id].difference_denominator,
                    )
                )
                / standard_errors[item.selector_pair_id]
            )
            for item in draw.pair_differences
        )
        for draw in valid_draws
    )
    if any(not math.isfinite(item) for item in maxima):
        return (
            SelectorPairInferenceStatusV2.NON_EVALUABLE,
            SelectorPairNonEvaluableReasonV2.ZERO_OR_INVALID_PAIR_STANDARD_ERROR,
            None,
            None,
            (),
        )
    critical = _higher_quantile(
        maxima,
        alpha_numerator=plan.alpha_numerator,
        alpha_denominator=plan.alpha_denominator,
    )
    intervals = tuple(
        SelectorPairSimultaneousIntervalV2(
            selector_pair_id=item.selector_pair_id,
            estimate_numerator=item.difference_numerator,
            estimate_denominator=item.difference_denominator,
            estimate=item.difference,
            outer_standard_error=standard_errors[item.selector_pair_id],
            simultaneous_lower=(
                item.difference - critical * standard_errors[item.selector_pair_id]
            ),
            simultaneous_upper=(
                item.difference + critical * standard_errors[item.selector_pair_id]
            ),
        )
        for item in pair_points
    )
    return (
        SelectorPairInferenceStatusV2.EVALUATED,
        None,
        critical,
        _digest(maxima),
        intervals,
    )


def _result_payload(result: SelectorUtilityAnalysisResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("selector_utility_result_id")
    return payload


def _checked_verified_inputs(
    plan: SelectorUtilityAnalysisPlanV2,
    verified: VerifiedSelectorPrimaryInputsV2,
) -> tuple[
    tuple[ConfirmatoryContributionArtifactV2, ...],
    dict[tuple[str, str, str], Fraction],
]:
    if (
        type(verified) is not VerifiedSelectorPrimaryInputsV2
        or verified._access is not _VERIFIED_PRIMARY_ACCESS
    ):
        raise _error("verified selector primary inputs are required")
    checked_artifacts, values = _validated_artifact_family(plan, verified.artifacts)
    expected_id = "verified_selector_primary_inputs_v2_" + _digest(
        (
            tuple(item.contribution_artifact_id for item in checked_artifacts),
            verified.intervals,
            verified.primary_simultaneous_result_id,
            verified.selector_utility_plan_id,
            verified.input_contributions_sha256,
            verified.verification_scope,
            verified.confirmatory_closed_run_evidence_id,
            verified.formal_confirmation_result_id,
        )
    )
    interval_ids = tuple(item.test_coordinate_id for item in verified.intervals)
    expected_interval_ids = tuple(item.test_coordinate_id for item in plan.coordinate_bindings)
    if (
        verified.verified_primary_inputs_id != expected_id
        or verified.selector_utility_plan_id != plan.selector_utility_plan_id
        or checked_artifacts != verified.artifacts
        or verified.input_contributions_sha256 != _artifact_input_digest(checked_artifacts)
        or interval_ids != expected_interval_ids
        or len(interval_ids) != len(set(interval_ids))
        or any(
            type(item) is not MultiSupportSimultaneousIntervalV2
            or not all(
                math.isfinite(value)
                for value in (
                    item.estimate,
                    item.standard_error,
                    item.simultaneous_lower,
                    item.simultaneous_upper,
                )
            )
            or item.standard_error <= 0.0
            or item.simultaneous_lower > item.estimate
            or item.simultaneous_upper < item.estimate
            for item in verified.intervals
        )
        or verified.verification_scope
        not in {
            "public_primary_result_full_replay_v1",
            "same_closed_run_formal_primary_reuse_v1",
            "synthetic_hand_checked_primary_fixture_v1",
        }
        or (
            verified.verification_scope == "same_closed_run_formal_primary_reuse_v1"
            and (
                plan.plan_scope is not SelectorUtilityPlanScopeV2.FORMAL
                or not plan.formal_selector_claim_allowed
                or verified.confirmatory_closed_run_evidence_id is None
                or _CLOSED_RUN_PATTERN.fullmatch(verified.confirmatory_closed_run_evidence_id)
                is None
                or verified.formal_confirmation_result_id is None
                or _FORMAL_RESULT_PATTERN.fullmatch(verified.formal_confirmation_result_id) is None
                or not verified.primary_simultaneous_result_id.startswith(
                    "multi_support_simultaneous_result_v2_"
                )
            )
        )
        or (
            verified.verification_scope != "same_closed_run_formal_primary_reuse_v1"
            and (
                verified.confirmatory_closed_run_evidence_id is not None
                or verified.formal_confirmation_result_id is not None
            )
        )
        or (
            verified.verification_scope == "synthetic_hand_checked_primary_fixture_v1"
            and (
                plan.plan_scope is not SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY
                or plan.formal_selector_claim_allowed
                or not verified.primary_simultaneous_result_id.startswith(
                    "synthetic_verified_selector_primary_v2_"
                )
            )
        )
    ):
        raise _error("verified selector primary inputs failed validation")
    return checked_artifacts, values


def _run_verified_checked_plan(
    checked_plan: SelectorUtilityAnalysisPlanV2,
    verified: VerifiedSelectorPrimaryInputsV2,
) -> SelectorUtilityAnalysisResultV2:
    checked_artifacts, values = _checked_verified_inputs(checked_plan, verified)
    confirmations = _full_coordinate_confirmations(
        checked_plan,
        checked_artifacts,
        verified.intervals,
    )
    confirmed_ids = frozenset(item.test_coordinate_id for item in confirmations if item.confirmed)
    selector_points = _selector_points(checked_plan, confirmed_ids)
    pair_points = _pair_points(checked_plan, selector_points)
    if pair_points:
        valid_outer, invalid_outer = _outer_draws(checked_plan, values)
    else:
        valid_outer, invalid_outer = (), ()
    (
        inference_status,
        non_evaluable_reason,
        pair_critical,
        maxima_sha256,
        pair_intervals,
    ) = _pair_inference(checked_plan, pair_points, valid_outer)
    provisional = SelectorUtilityAnalysisResultV2(
        selector_utility_result_id="",
        selector_utility_plan_id=checked_plan.selector_utility_plan_id,
        confirmatory_experiment_freeze_id=(checked_plan.confirmatory_experiment_freeze_id),
        candidate_universe_id=checked_plan.candidate_universe_id,
        selection_freeze_id=checked_plan.selection_freeze_id,
        primary_inference_plan_id=checked_plan.primary_inference_plan.inference_plan_id,
        primary_simultaneous_result_id=verified.primary_simultaneous_result_id,
        primary_input_verification_scope=verified.verification_scope,
        primary_family_id=checked_plan.primary_family_id,
        input_contribution_artifact_ids=tuple(
            item.contribution_artifact_id for item in checked_artifacts
        ),
        input_contributions_sha256=verified.input_contributions_sha256,
        coordinate_confirmations=confirmations,
        selector_points=selector_points,
        pair_points=pair_points,
        valid_outer_draw_count=len(valid_outer),
        invalid_outer_draw_count=len(invalid_outer),
        valid_outer_draws=valid_outer,
        invalid_outer_draws=invalid_outer,
        pair_inference_status=inference_status,
        pair_non_evaluable_reason=non_evaluable_reason,
        pair_critical_value=pair_critical,
        outer_pair_max_abs_t_sha256=maxima_sha256,
        pair_intervals=pair_intervals,
        conditional_on_single_frozen_discovery_split=True,
        formal_glue_required=True,
        formal_glue_completed=False,
        discovery_rerun_or_rerank_performed=False,
        formal_selector_claim_allowed=False,
    )
    return SelectorUtilityAnalysisResultV2(
        selector_utility_result_id=_RESULT_PREFIX + _digest(_result_payload(provisional)),
        selector_utility_plan_id=provisional.selector_utility_plan_id,
        confirmatory_experiment_freeze_id=(provisional.confirmatory_experiment_freeze_id),
        candidate_universe_id=provisional.candidate_universe_id,
        selection_freeze_id=provisional.selection_freeze_id,
        primary_inference_plan_id=provisional.primary_inference_plan_id,
        primary_simultaneous_result_id=provisional.primary_simultaneous_result_id,
        primary_input_verification_scope=provisional.primary_input_verification_scope,
        primary_family_id=provisional.primary_family_id,
        input_contribution_artifact_ids=provisional.input_contribution_artifact_ids,
        input_contributions_sha256=provisional.input_contributions_sha256,
        coordinate_confirmations=provisional.coordinate_confirmations,
        selector_points=provisional.selector_points,
        pair_points=provisional.pair_points,
        valid_outer_draw_count=provisional.valid_outer_draw_count,
        invalid_outer_draw_count=provisional.invalid_outer_draw_count,
        valid_outer_draws=provisional.valid_outer_draws,
        invalid_outer_draws=provisional.invalid_outer_draws,
        pair_inference_status=provisional.pair_inference_status,
        pair_non_evaluable_reason=provisional.pair_non_evaluable_reason,
        pair_critical_value=provisional.pair_critical_value,
        outer_pair_max_abs_t_sha256=provisional.outer_pair_max_abs_t_sha256,
        pair_intervals=provisional.pair_intervals,
        conditional_on_single_frozen_discovery_split=True,
        formal_glue_required=True,
        formal_glue_completed=False,
        discovery_rerun_or_rerank_performed=False,
        formal_selector_claim_allowed=provisional.formal_selector_claim_allowed,
    )


def _run(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
) -> SelectorUtilityAnalysisResultV2:
    checked_plan = _validated_plan(plan)
    verified = _validated_public_primary_inputs(checked_plan, artifacts, primary_result)
    return _run_verified_checked_plan(checked_plan, verified)


def run_selector_utility_analysis_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
) -> SelectorUtilityAnalysisResultV2:
    """Run strict yield@K and the frozen nested paired-selector family."""

    return _run(plan, artifacts, primary_result)


def run_verified_selector_utility_analysis_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    verified_primary_inputs: VerifiedSelectorPrimaryInputsV2,
) -> SelectorUtilityAnalysisResultV2:
    """Run the statistics core from one publicly sealed primary-input token."""

    checked_plan = _content_address_checked_plan(plan)
    return _run_verified_checked_plan(checked_plan, verified_primary_inputs)


def validate_selector_utility_analysis_result_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    primary_result: MultiSupportSimultaneousInferenceResultV2,
    result: SelectorUtilityAnalysisResultV2,
) -> SelectorUtilityAnalysisResultV2:
    """Replay every formal and nested draw and require exact result equality."""

    if type(result) is not SelectorUtilityAnalysisResultV2:
        raise _error("selector utility result artifact failed validation")
    expected = _run(plan, artifacts, primary_result)
    if result != expected:
        raise _error("selector utility result artifact failed validation")
    return result


def validate_verified_selector_utility_analysis_result_v2(
    plan: SelectorUtilityAnalysisPlanV2,
    verified_primary_inputs: VerifiedSelectorPrimaryInputsV2,
    result: SelectorUtilityAnalysisResultV2,
) -> SelectorUtilityAnalysisResultV2:
    """Replay a result from its already sealed primary-input token."""

    if type(result) is not SelectorUtilityAnalysisResultV2:
        raise _error("selector utility result artifact failed validation")
    expected = run_verified_selector_utility_analysis_v2(plan, verified_primary_inputs)
    if result != expected:
        raise _error("selector utility result artifact failed validation")
    return result


__all__ = [
    "InvalidNestedOuterDrawV2",
    "NestedCoordinateRetainedCountV2",
    "NestedStratumDrawReceiptV2",
    "OuterSelectorPairDifferenceV2",
    "OuterSelectorUtilityV2",
    "SelectorPairPointV2",
    "SelectorPairSimultaneousIntervalV2",
    "SelectorUtilityAnalysisResultV2",
    "SelectorUtilityPointV2",
    "StrictCoordinateConfirmationV2",
    "StrictSlotContributionV2",
    "ValidNestedOuterDrawV2",
    "VerifiedSelectorPrimaryInputsV2",
    "make_same_closed_run_formal_primary_inputs_v2",
    "make_synthetic_verified_selector_primary_inputs_v2",
    "run_selector_utility_analysis_v2",
    "run_verified_selector_utility_analysis_v2",
    "validate_selector_primary_inputs_v2",
    "validate_selector_utility_analysis_result_v2",
    "validate_verified_selector_utility_analysis_result_v2",
]

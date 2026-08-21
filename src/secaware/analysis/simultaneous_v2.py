"""Studentized max-|T| inference for one exact common-support v2 family.

The public function consumes already aggregated semantic-cluster contributions.
It intentionally rejects coordinate-specific eligible populations: every coordinate
must have exactly one value for every cluster in the plan's one frozen stratum
support.  The same stratified cluster draw is reused across the whole family.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from pydantic import ValidationError

from secaware.randomness import DeterministicRNG
from secaware.schema.common import model_shape_is_intact
from secaware.schema.inference_v2 import (
    SimultaneousCoordinateKindV2,
    SimultaneousInferencePlanV2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)


class BootstrapDrawStatusV2(StrEnum):
    VALID = "valid"
    INVALID_STANDARD_ERROR = "invalid_standard_error"


@dataclass(frozen=True, slots=True)
class CoordinateClusterContributionV2:
    """One authenticated semantic-cluster contribution supplied to this layer."""

    test_coordinate_id: str
    stratum_id: str
    semantic_task_cluster_id: str
    estimate: float


@dataclass(frozen=True, slots=True)
class SimultaneousIntervalV2:
    test_coordinate_id: str
    estimate: float
    standard_error: float
    simultaneous_lower: float
    simultaneous_upper: float


@dataclass(frozen=True, slots=True)
class MaxTBootstrapDrawV2:
    replicate_index: int
    sample_sha256: str
    status: BootstrapDrawStatusV2
    max_abs_t: float | None
    invalid_coordinate_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SimultaneousInferenceResultV2:
    simultaneous_result_id: str
    inference_plan_id: str
    family_id: str
    input_contributions_sha256: str
    critical_value: float
    valid_draw_count: int
    invalid_draw_count: int
    intervals: tuple[SimultaneousIntervalV2, ...]
    draws: tuple[MaxTBootstrapDrawV2, ...]


def _error(message: str = "simultaneous inference v2 failed validation") -> ValueError:
    return ValueError(message)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _validated_plan(plan: SimultaneousInferencePlanV2) -> SimultaneousInferencePlanV2:
    if type(plan) is not SimultaneousInferencePlanV2 or not model_shape_is_intact(plan):
        raise _error()
    try:
        return SimultaneousInferencePlanV2.model_validate(
            plan.model_dump(mode="python", round_trip=True, warnings=False)
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error() from None


def _expected_keys(
    plan: SimultaneousInferencePlanV2,
) -> set[tuple[str, str, str]]:
    return {
        (coordinate.test_coordinate_id, stratum.stratum_id, cluster_id)
        for coordinate in plan.family.coordinates
        for stratum in plan.strata
        for cluster_id in stratum.semantic_task_cluster_ids
    }


def _validated_contributions(
    plan: SimultaneousInferencePlanV2,
    contributions: Iterable[CoordinateClusterContributionV2],
) -> dict[tuple[str, str, str], float]:
    if isinstance(contributions, (str, bytes, Mapping)):
        raise _error()
    expected = _expected_keys(plan)
    bounds = {
        item.test_coordinate_id: (
            2.0
            if item.coordinate_kind is SimultaneousCoordinateKindV2.REALIZATION_DEVIATION
            else 1.0
        )
        for item in plan.family.coordinates
    }
    values: dict[tuple[str, str, str], float] = {}
    try:
        for index, item in enumerate(contributions):
            if index >= len(expected) or type(item) is not CoordinateClusterContributionV2:
                raise _error("common cluster-stratum support failed validation")
            key = (
                item.test_coordinate_id,
                item.stratum_id,
                item.semantic_task_cluster_id,
            )
            if (
                key in values
                or type(item.estimate) not in {int, float}
                or type(item.estimate) is bool
            ):
                raise _error("common cluster-stratum support failed validation")
            estimate = float(item.estimate)
            bound = bounds.get(item.test_coordinate_id, 1.0)
            if not math.isfinite(estimate) or not -bound <= estimate <= bound:
                raise _error("cluster contribution failed validation")
            values[key] = estimate
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error() from None
    if set(values) != expected:
        raise _error("common cluster-stratum support failed validation")
    return values


def _contribution_digest(
    values: Mapping[tuple[str, str, str], float],
) -> str:
    return _digest(tuple((*key, values[key]) for key in sorted(values)))


def _stratum_weights(plan: SimultaneousInferencePlanV2) -> dict[str, float]:
    return {
        item.stratum_id: item.weight_numerator / plan.stratum_weight_denominator
        for item in plan.strata
    }


def _statistics_for_coordinate(
    plan: SimultaneousInferencePlanV2,
    values: Mapping[tuple[str, str, str], float],
    coordinate_id: str,
    samples: Mapping[str, tuple[str, ...]],
) -> tuple[float, float]:
    weights = _stratum_weights(plan)
    estimate = 0.0
    variance = 0.0
    for stratum in plan.strata:
        cluster_ids = samples[stratum.stratum_id]
        count = len(cluster_ids)
        observations = tuple(
            values[(coordinate_id, stratum.stratum_id, cluster_id)] for cluster_id in cluster_ids
        )
        mean = math.fsum(observations) / count
        weight = weights[stratum.stratum_id]
        estimate += weight * mean
        variance += (
            weight
            * weight
            * math.fsum((item - mean) ** 2 for item in observations)
            / (count * (count - 1))
        )
    if not math.isfinite(estimate) or not math.isfinite(variance) or variance < 0.0:
        raise _error("cluster statistic failed validation")
    return estimate, math.sqrt(variance)


def _observed_statistics(
    plan: SimultaneousInferencePlanV2,
    values: Mapping[tuple[str, str, str], float],
) -> dict[str, tuple[float, float]]:
    support = {stratum.stratum_id: stratum.semantic_task_cluster_ids for stratum in plan.strata}
    result = {
        coordinate.test_coordinate_id: _statistics_for_coordinate(
            plan,
            values,
            coordinate.test_coordinate_id,
            support,
        )
        for coordinate in plan.family.coordinates
    }
    if any(not math.isfinite(se) or se <= 0.0 for _estimate, se in result.values()):
        raise _error("observed coordinate has zero or invalid cluster standard error")
    return result


def _sample_digest(samples: Mapping[str, tuple[str, ...]]) -> str:
    payload = tuple((stratum_id, samples[stratum_id]) for stratum_id in sorted(samples))
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _higher_quantile(
    values: tuple[float, ...],
    *,
    alpha_numerator: int,
    alpha_denominator: int,
) -> float:
    if not values:
        raise _error("no valid bootstrap draw remains")
    ordered = tuple(sorted(values))
    numerator = (alpha_denominator - alpha_numerator) * len(ordered)
    rank = (numerator + alpha_denominator - 1) // alpha_denominator
    rank = min(max(rank, 1), len(ordered))
    return ordered[rank - 1]


def _result_payload(result: SimultaneousInferenceResultV2) -> dict[str, object]:
    return {
        "inference_plan_id": result.inference_plan_id,
        "family_id": result.family_id,
        "input_contributions_sha256": result.input_contributions_sha256,
        "critical_value": result.critical_value,
        "valid_draw_count": result.valid_draw_count,
        "invalid_draw_count": result.invalid_draw_count,
        "intervals": tuple(
            {
                "test_coordinate_id": item.test_coordinate_id,
                "estimate": item.estimate,
                "standard_error": item.standard_error,
                "simultaneous_lower": item.simultaneous_lower,
                "simultaneous_upper": item.simultaneous_upper,
            }
            for item in result.intervals
        ),
        "draws": tuple(
            {
                "replicate_index": item.replicate_index,
                "sample_sha256": item.sample_sha256,
                "status": item.status.value,
                "max_abs_t": item.max_abs_t,
                "invalid_coordinate_ids": item.invalid_coordinate_ids,
            }
            for item in result.draws
        ),
    }


def _build_result(
    *,
    inference_plan_id: str,
    family_id: str,
    input_contributions_sha256: str,
    critical_value: float,
    intervals: tuple[SimultaneousIntervalV2, ...],
    draws: tuple[MaxTBootstrapDrawV2, ...],
) -> SimultaneousInferenceResultV2:
    provisional = SimultaneousInferenceResultV2(
        simultaneous_result_id="",
        inference_plan_id=inference_plan_id,
        family_id=family_id,
        input_contributions_sha256=input_contributions_sha256,
        critical_value=critical_value,
        valid_draw_count=len(draws),
        invalid_draw_count=0,
        intervals=intervals,
        draws=draws,
    )
    return SimultaneousInferenceResultV2(
        simultaneous_result_id="simultaneous_result_v2_" + _digest(_result_payload(provisional)),
        inference_plan_id=provisional.inference_plan_id,
        family_id=provisional.family_id,
        input_contributions_sha256=provisional.input_contributions_sha256,
        critical_value=provisional.critical_value,
        valid_draw_count=provisional.valid_draw_count,
        invalid_draw_count=provisional.invalid_draw_count,
        intervals=provisional.intervals,
        draws=provisional.draws,
    )


def validate_simultaneous_inference_result_v2(
    plan: SimultaneousInferencePlanV2,
    result: SimultaneousInferenceResultV2,
    *,
    contributions: Iterable[CoordinateClusterContributionV2] | None = None,
) -> SimultaneousInferenceResultV2:
    """Revalidate one immutable result against its exact frozen plan and optional inputs."""

    checked_plan = _validated_plan(plan)
    if type(result) is not SimultaneousInferenceResultV2:
        raise _error("simultaneous result artifact failed validation")
    try:
        if (
            result.inference_plan_id != checked_plan.inference_plan_id
            or result.family_id != checked_plan.family_id
            or type(result.input_contributions_sha256) is not str
            or len(result.input_contributions_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in result.input_contributions_sha256
            )
            or type(result.critical_value) not in {int, float}
            or type(result.critical_value) is bool
            or not math.isfinite(float(result.critical_value))
            or result.critical_value < 0.0
            or type(result.valid_draw_count) is not int
            or type(result.invalid_draw_count) is not int
            or result.valid_draw_count != checked_plan.bootstrap_samples
            or result.valid_draw_count < checked_plan.minimum_valid_bootstrap_draws
            or result.invalid_draw_count != 0
            or type(result.intervals) is not tuple
            or type(result.draws) is not tuple
            or len(result.draws) != checked_plan.bootstrap_samples
        ):
            raise _error("simultaneous result artifact failed validation")
        expected_coordinate_ids = tuple(
            item.test_coordinate_id for item in checked_plan.family.coordinates
        )
        if tuple(item.test_coordinate_id for item in result.intervals) != expected_coordinate_ids:
            raise _error("simultaneous result artifact failed validation")
        for item in result.intervals:
            if (
                type(item) is not SimultaneousIntervalV2
                or any(
                    type(value) not in {int, float}
                    or type(value) is bool
                    or not math.isfinite(float(value))
                    for value in (
                        item.estimate,
                        item.standard_error,
                        item.simultaneous_lower,
                        item.simultaneous_upper,
                    )
                )
                or item.standard_error <= 0.0
                or item.simultaneous_lower > item.simultaneous_upper
                or not math.isclose(
                    item.simultaneous_lower,
                    item.estimate - result.critical_value * item.standard_error,
                    rel_tol=0.0,
                    abs_tol=1e-12,
                )
                or not math.isclose(
                    item.simultaneous_upper,
                    item.estimate + result.critical_value * item.standard_error,
                    rel_tol=0.0,
                    abs_tol=1e-12,
                )
            ):
                raise _error("simultaneous result artifact failed validation")
        maxima: list[float] = []
        for index, draw in enumerate(result.draws):
            if (
                type(draw) is not MaxTBootstrapDrawV2
                or draw.replicate_index != index
                or type(draw.sample_sha256) is not str
                or len(draw.sample_sha256) != 64
                or any(character not in "0123456789abcdef" for character in draw.sample_sha256)
                or draw.status is not BootstrapDrawStatusV2.VALID
                or type(draw.max_abs_t) not in {int, float}
                or type(draw.max_abs_t) is bool
                or not math.isfinite(float(draw.max_abs_t))
                or draw.max_abs_t < 0.0
                or draw.invalid_coordinate_ids != ()
            ):
                raise _error("simultaneous result artifact failed validation")
            maxima.append(float(draw.max_abs_t))
        expected_critical = _higher_quantile(
            tuple(maxima),
            alpha_numerator=checked_plan.alpha_numerator,
            alpha_denominator=checked_plan.alpha_denominator,
        )
        if not math.isclose(
            result.critical_value,
            expected_critical,
            rel_tol=0.0,
            abs_tol=1e-12,
        ):
            raise _error("simultaneous result artifact failed validation")
        expected_id = "simultaneous_result_v2_" + _digest(_result_payload(result))
        if result.simultaneous_result_id != expected_id:
            raise _error("simultaneous result artifact failed validation")
        if contributions is not None:
            values = _validated_contributions(checked_plan, contributions)
            if result.input_contributions_sha256 != _contribution_digest(values):
                raise _error("simultaneous result contribution binding failed validation")
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize malformed frozen dataclasses
        raise _error("simultaneous result artifact failed validation") from None
    return result


def run_simultaneous_inference_v2(
    plan: SimultaneousInferencePlanV2,
    contributions: Iterable[CoordinateClusterContributionV2],
    *,
    seed_material: bytes,
) -> SimultaneousInferenceResultV2:
    """Run the frozen common-support stratified studentized max-|T| procedure."""

    checked_plan = _validated_plan(plan)
    if type(seed_material) is not bytes or not seed_material:
        raise _error("bootstrap seed material failed validation")
    if hashlib.sha256(seed_material).hexdigest() != checked_plan.seed_material_sha256:
        raise _error("bootstrap seed material does not match the frozen plan")
    values = _validated_contributions(checked_plan, contributions)
    observed = _observed_statistics(checked_plan, values)
    rng = DeterministicRNG(seed_material)

    draws: list[MaxTBootstrapDrawV2] = []
    valid_maxima: list[float] = []
    for replicate in range(checked_plan.bootstrap_samples):
        sampled = {
            stratum.stratum_id: tuple(
                rng.choice(stratum.semantic_task_cluster_ids)
                for _ in stratum.semantic_task_cluster_ids
            )
            for stratum in checked_plan.strata
        }
        bootstrap_statistics = {
            coordinate.test_coordinate_id: _statistics_for_coordinate(
                checked_plan,
                values,
                coordinate.test_coordinate_id,
                sampled,
            )
            for coordinate in checked_plan.family.coordinates
        }
        invalid_ids = tuple(
            sorted(
                coordinate_id
                for coordinate_id, (_estimate, standard_error) in bootstrap_statistics.items()
                if not math.isfinite(standard_error) or standard_error <= 0.0
            )
        )
        sample_sha256 = _sample_digest(sampled)
        if invalid_ids:
            raise _error("bootstrap draw has zero or invalid family standard error")
        max_abs_t = max(
            abs((bootstrap_estimate - observed[coordinate_id][0]) / bootstrap_standard_error)
            for coordinate_id, (bootstrap_estimate, bootstrap_standard_error) in (
                bootstrap_statistics.items()
            )
        )
        if not math.isfinite(max_abs_t):
            raise _error("bootstrap max-|T| statistic failed validation")
        valid_maxima.append(max_abs_t)
        draws.append(
            MaxTBootstrapDrawV2(
                replicate_index=replicate,
                sample_sha256=sample_sha256,
                status=BootstrapDrawStatusV2.VALID,
                max_abs_t=max_abs_t,
                invalid_coordinate_ids=(),
            )
        )

    if len(valid_maxima) < checked_plan.minimum_valid_bootstrap_draws:
        raise _error("bootstrap valid-draw count is below the frozen minimum")

    critical_value = _higher_quantile(
        tuple(valid_maxima),
        alpha_numerator=checked_plan.alpha_numerator,
        alpha_denominator=checked_plan.alpha_denominator,
    )
    intervals = tuple(
        SimultaneousIntervalV2(
            test_coordinate_id=coordinate.test_coordinate_id,
            estimate=observed[coordinate.test_coordinate_id][0],
            standard_error=observed[coordinate.test_coordinate_id][1],
            simultaneous_lower=(
                observed[coordinate.test_coordinate_id][0]
                - critical_value * observed[coordinate.test_coordinate_id][1]
            ),
            simultaneous_upper=(
                observed[coordinate.test_coordinate_id][0]
                + critical_value * observed[coordinate.test_coordinate_id][1]
            ),
        )
        for coordinate in checked_plan.family.coordinates
    )
    result = _build_result(
        inference_plan_id=checked_plan.inference_plan_id,
        family_id=checked_plan.family_id,
        input_contributions_sha256=_contribution_digest(values),
        critical_value=critical_value,
        intervals=intervals,
        draws=tuple(draws),
    )
    return validate_simultaneous_inference_result_v2(
        checked_plan,
        result,
        contributions=tuple(
            CoordinateClusterContributionV2(
                test_coordinate_id=coordinate_id,
                stratum_id=stratum_id,
                semantic_task_cluster_id=cluster_id,
                estimate=estimate,
            )
            for (coordinate_id, stratum_id, cluster_id), estimate in values.items()
        ),
    )


__all__ = [
    "BootstrapDrawStatusV2",
    "CoordinateClusterContributionV2",
    "MaxTBootstrapDrawV2",
    "SimultaneousInferenceResultV2",
    "SimultaneousIntervalV2",
    "run_simultaneous_inference_v2",
    "validate_simultaneous_inference_result_v2",
]

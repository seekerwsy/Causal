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
from secaware.schema.inference_v2 import SimultaneousInferencePlanV2

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
    inference_plan_id: str
    family_id: str
    critical_value: float
    valid_draw_count: int
    invalid_draw_count: int
    intervals: tuple[SimultaneousIntervalV2, ...]
    draws: tuple[MaxTBootstrapDrawV2, ...]


def _error(message: str = "simultaneous inference v2 failed validation") -> ValueError:
    return ValueError(message)


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
            if not math.isfinite(estimate):
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
            draws.append(
                MaxTBootstrapDrawV2(
                    replicate_index=replicate,
                    sample_sha256=sample_sha256,
                    status=BootstrapDrawStatusV2.INVALID_STANDARD_ERROR,
                    max_abs_t=None,
                    invalid_coordinate_ids=invalid_ids,
                )
            )
            continue
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

    invalid_count = checked_plan.bootstrap_samples - len(valid_maxima)
    if (
        not valid_maxima
        or invalid_count * checked_plan.maximum_invalid_fraction_denominator
        > checked_plan.maximum_invalid_fraction_numerator * checked_plan.bootstrap_samples
    ):
        raise _error("bootstrap invalid-draw fraction exceeds the frozen maximum")

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
    return SimultaneousInferenceResultV2(
        inference_plan_id=checked_plan.inference_plan_id,
        family_id=checked_plan.family_id,
        critical_value=critical_value,
        valid_draw_count=len(valid_maxima),
        invalid_draw_count=invalid_count,
        intervals=intervals,
        draws=tuple(draws),
    )


__all__ = [
    "BootstrapDrawStatusV2",
    "CoordinateClusterContributionV2",
    "MaxTBootstrapDrawV2",
    "SimultaneousInferenceResultV2",
    "SimultaneousIntervalV2",
    "run_simultaneous_inference_v2",
]

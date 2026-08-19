"""Replayable global max-|T| inference over different frozen populations.

One global semantic-cluster union sample is drawn per stratum and bootstrap
replicate.  Every coordinate then filters that *same* sample to its own frozen
eligible support.  This retains dependence for overlapping populations without
replacing any coordinate's estimand by a common intersection.
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
from secaware.analysis.simultaneous_v2 import CoordinateClusterContributionV2
from secaware.randomness import DeterministicRNG
from secaware.schema.common import model_shape_is_intact
from secaware.schema.multi_support_inference_v2 import (
    CoordinateSpecificSupportV2,
    MultiSupportSimultaneousInferencePlanV2,
)

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "multi_support_simultaneous_result_v2_"
_SEED_DOMAIN = b"secaware.multi-support-global-max-t.v2\x00"
_CLOSED_COVERAGE_PATTERN = re.compile(r"^provenance_closed_coverage_v2_[0-9a-f]{64}$")


class _InvalidBootstrapDraw(Exception):
    __slots__ = ("reason_code", "stratum_id", "test_coordinate_id")

    def __init__(
        self,
        *,
        reason_code: str,
        test_coordinate_id: str,
        stratum_id: str | None,
    ) -> None:
        self.reason_code = reason_code
        self.test_coordinate_id = test_coordinate_id
        self.stratum_id = stratum_id
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class MultiSupportSimultaneousIntervalV2:
    test_coordinate_id: str
    estimate_numerator: int
    estimate_denominator: int
    estimate: float
    standard_error: float
    simultaneous_lower: float
    simultaneous_upper: float


@dataclass(frozen=True, slots=True)
class UnionStratumDrawDigestV2:
    stratum_id: str
    occurrence_count: int
    sampled_clusters_sha256: str


@dataclass(frozen=True, slots=True)
class CoordinateStratumRetainedCountV2:
    test_coordinate_id: str
    stratum_id: str
    retained_occurrence_count: int


@dataclass(frozen=True, slots=True)
class GlobalUnionMaxTDrawV2:
    replicate_index: int
    global_sample_sha256: str
    stratum_draws: tuple[UnionStratumDrawDigestV2, ...]
    coordinate_retained_counts: tuple[CoordinateStratumRetainedCountV2, ...]
    max_abs_t: float


@dataclass(frozen=True, slots=True)
class InvalidGlobalUnionDrawV2:
    replicate_index: int
    global_sample_sha256: str
    stratum_draws: tuple[UnionStratumDrawDigestV2, ...]
    reason_code: str
    test_coordinate_id: str
    stratum_id: str | None


@dataclass(frozen=True, slots=True)
class MultiSupportSimultaneousInferenceResultV2:
    simultaneous_result_id: str
    inference_plan_id: str
    confirmatory_experiment_freeze_id: str
    family_id: str
    global_multiplicity_family_policy_sha256: str
    bootstrap_seed_sha256: str
    input_contribution_artifact_ids: tuple[str, ...]
    input_contributions_sha256: str
    critical_value: float
    valid_draw_count: int
    invalid_draw_count: int
    intervals: tuple[MultiSupportSimultaneousIntervalV2, ...]
    draws: tuple[GlobalUnionMaxTDrawV2, ...]
    invalid_draws: tuple[InvalidGlobalUnionDrawV2, ...]


def _error(
    message: str = "multi-support simultaneous inference v2 failed validation",
) -> ValueError:
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


def _validated_plan(
    plan: MultiSupportSimultaneousInferencePlanV2,
) -> MultiSupportSimultaneousInferencePlanV2:
    if type(plan) is not MultiSupportSimultaneousInferencePlanV2 or not model_shape_is_intact(plan):
        raise _error("multi-support inference plan failed validation")
    try:
        return MultiSupportSimultaneousInferencePlanV2.model_validate(
            plan.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("multi-support inference plan failed validation") from None


def _artifact_payload(artifact: ConfirmatoryContributionArtifactV2) -> dict[str, object]:
    payload = asdict(artifact)
    payload.pop("contribution_artifact_id")
    return payload


def _expected_artifact_bindings(
    plan: MultiSupportSimultaneousInferencePlanV2,
) -> dict[str, CoordinateSpecificSupportV2]:
    return {item.test_coordinate.test_coordinate_id: item for item in plan.coordinate_supports}


def _validated_artifacts(
    plan: MultiSupportSimultaneousInferencePlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
) -> tuple[
    tuple[ConfirmatoryContributionArtifactV2, ...],
    dict[tuple[str, str, str], Fraction],
]:
    if isinstance(artifacts, (str, bytes, Mapping)):
        raise _error("complete contribution artifact family is required")
    expected = _expected_artifact_bindings(plan)
    by_coordinate: dict[str, ConfirmatoryContributionArtifactV2] = {}
    try:
        for index, artifact in enumerate(artifacts):
            if (
                index >= len(expected)
                or type(artifact) is not ConfirmatoryContributionArtifactV2
                or artifact.test_coordinate_id in by_coordinate
            ):
                raise _error("complete contribution artifact family is required")
            by_coordinate[artifact.test_coordinate_id] = artifact
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables
        raise _error("complete contribution artifact family is required") from None
    if set(by_coordinate) != set(expected):
        raise _error("complete contribution artifact family is required")

    experiment_coordinates = {
        item.hypothesis_model_coordinate_id: item
        for item in plan.experiment.hypothesis_model_coordinates
    }
    values: dict[tuple[str, str, str], Fraction] = {}
    ordered: list[ConfirmatoryContributionArtifactV2] = []
    coverage_ids_by_hypothesis: dict[str, set[str]] = {}
    for coordinate_id in sorted(expected):
        support = expected[coordinate_id]
        artifact = by_coordinate[coordinate_id]
        hm = experiment_coordinates[support.hypothesis_model_coordinate_id]
        if (
            artifact.contribution_artifact_id
            != "confirmatory_contributions_v2_" + _digest(_artifact_payload(artifact))
            or artifact.population_freeze_manifest_id != support.population_freeze_manifest_id
            or artifact.randomization_manifest_id != support.randomization_manifest_id
            or artifact.execution_policy_freeze_manifest_id
            != support.execution_policy_freeze_manifest_id
            or hm.population_freeze_manifest_id != artifact.population_freeze_manifest_id
            or hm.randomization_manifest_id != artifact.randomization_manifest_id
            or hm.execution_policy_freeze_manifest_id
            != artifact.execution_policy_freeze_manifest_id
            or artifact.test_coordinate_id != coordinate_id
            or _CLOSED_COVERAGE_PATTERN.fullmatch(artifact.provenance_closed_coverage_manifest_id)
            is None
            or artifact.derivation_rule
            != "authenticated_block_arm_means_then_frozen_task_weights_then_qh_then_cluster_v1"
            or artifact.rational_arithmetic_until_final_projection is not True
        ):
            raise _error("contribution artifact provenance binding failed validation")
        coverage_ids_by_hypothesis.setdefault(
            support.test_coordinate.hypothesis_id,
            set(),
        ).add(artifact.provenance_closed_coverage_manifest_id)

        expected_keys = {
            (stratum.stratum_id, cluster_id)
            for stratum in support.strata
            for cluster_id in stratum.semantic_task_cluster_ids
        }
        exact_rows: dict[tuple[str, str], ExactCoordinateClusterContributionV2] = {}
        for row in artifact.exact_coordinate_contributions:
            if (
                type(row) is not ExactCoordinateClusterContributionV2
                or row.test_coordinate_id != coordinate_id
                or type(row.numerator) is not int
                or type(row.denominator) is not int
                or row.denominator <= 0
            ):
                raise _error("coordinate contribution support failed validation")
            key = (row.stratum_id, row.semantic_task_cluster_id)
            if key in exact_rows:
                raise _error("coordinate contribution support failed validation")
            fraction = Fraction(row.numerator, row.denominator)
            if (
                fraction.numerator != row.numerator
                or fraction.denominator != row.denominator
                or not Fraction(-1, 1) <= fraction <= Fraction(1, 1)
            ):
                raise _error("coordinate contribution value failed validation")
            exact_rows[key] = row
        if set(exact_rows) != expected_keys:
            raise _error("coordinate contribution support failed validation")

        projected: dict[tuple[str, str], CoordinateClusterContributionV2] = {}
        for row in artifact.coordinate_contributions:
            if (
                type(row) is not CoordinateClusterContributionV2
                or row.test_coordinate_id != coordinate_id
                or type(row.estimate) is not float
                or not math.isfinite(row.estimate)
            ):
                raise _error("coordinate contribution projection failed validation")
            key = (row.stratum_id, row.semantic_task_cluster_id)
            if key in projected:
                raise _error("coordinate contribution projection failed validation")
            projected[key] = row
        if set(projected) != expected_keys:
            raise _error("coordinate contribution projection failed validation")
        for key, exact in exact_rows.items():
            fraction = Fraction(exact.numerator, exact.denominator)
            if projected[key].estimate != float(fraction):
                raise _error("coordinate contribution projection failed validation")
            values[(coordinate_id, *key)] = fraction
        ordered.append(artifact)
    if any(len(item) != 1 for item in coverage_ids_by_hypothesis.values()) or len(
        {next(iter(item)) for item in coverage_ids_by_hypothesis.values()}
    ) != len(coverage_ids_by_hypothesis):
        raise _error("contribution artifact coverage family failed validation")
    return tuple(ordered), values


def _artifact_input_digest(
    artifacts: tuple[ConfirmatoryContributionArtifactV2, ...],
) -> str:
    return _digest(
        tuple((item.test_coordinate_id, item.contribution_artifact_id) for item in artifacts)
    )


def _bootstrap_seed(
    plan: MultiSupportSimultaneousInferencePlanV2,
    material: bytes | None,
) -> bytes:
    if plan.seed_derivation_rule == ("sha256_domain_material_plus_content_addressed_plan_id_v1"):
        if (
            type(material) is not bytes
            or not material
            or hashlib.sha256(material).hexdigest() != plan.analysis_seed_domain_sha256
        ):
            raise _error("analysis seed domain material failed validation")
        domain = material
    else:
        if material is not None:
            raise _error("frozen analysis seed domain accepts no caller material")
        domain = bytes.fromhex(plan.analysis_seed_domain_sha256)
    return hashlib.sha256(
        _SEED_DOMAIN + domain + b"\x00" + plan.inference_plan_id.encode()
    ).digest()


def _coordinate_statistics(
    support: CoordinateSpecificSupportV2,
    values: Mapping[tuple[str, str, str], Fraction],
    samples: Mapping[str, tuple[str, ...]],
    *,
    filter_union_sample: bool,
) -> tuple[Fraction, float, tuple[CoordinateStratumRetainedCountV2, ...]]:
    coordinate_id = support.test_coordinate.test_coordinate_id
    estimate = Fraction(0, 1)
    variance = 0.0
    retained_counts: list[CoordinateStratumRetainedCountV2] = []
    for stratum in support.strata:
        support_set = frozenset(stratum.semantic_task_cluster_ids)
        sampled = samples[stratum.stratum_id]
        retained = (
            tuple(item for item in sampled if item in support_set)
            if filter_union_sample
            else sampled
        )
        count = len(retained)
        if count < 2:
            if filter_union_sample:
                raise _InvalidBootstrapDraw(
                    reason_code="insufficient_retained_coordinate_clusters",
                    test_coordinate_id=coordinate_id,
                    stratum_id=stratum.stratum_id,
                )
            raise _error("bootstrap draw has fewer than two retained coordinate clusters")
        observations = tuple(
            values[(coordinate_id, stratum.stratum_id, cluster_id)] for cluster_id in retained
        )
        if filter_union_sample:
            # The nonparametric union draw gives equal weight to occurrences;
            # filtering implements the coordinate-specific ratio estimator.
            mean = sum(observations, Fraction(0, 1)) / count
        else:
            # The point estimand comes from the exact population weights,
            # rather than from an implicit row-order assumption.
            frozen_weights = {
                cluster_id: Fraction(numerator, stratum.cluster_weight_denominator)
                for cluster_id, numerator in zip(
                    stratum.semantic_task_cluster_ids,
                    stratum.cluster_weight_numerators,
                    strict=True,
                )
            }
            mean = sum(
                (
                    values[(coordinate_id, stratum.stratum_id, cluster_id)]
                    * frozen_weights[cluster_id]
                    for cluster_id in retained
                ),
                Fraction(0, 1),
            )
        weight = stratum.stratum_weight
        estimate += weight * mean
        mean_float = float(mean)
        variance += (
            float(weight) ** 2
            * math.fsum((float(item) - mean_float) ** 2 for item in observations)
            / (count * (count - 1))
        )
        retained_counts.append(
            CoordinateStratumRetainedCountV2(
                test_coordinate_id=coordinate_id,
                stratum_id=stratum.stratum_id,
                retained_occurrence_count=count,
            )
        )
    standard_error = math.sqrt(variance)
    if not math.isfinite(standard_error) or standard_error <= 0.0:
        if filter_union_sample:
            raise _InvalidBootstrapDraw(
                reason_code="zero_or_invalid_coordinate_standard_error",
                test_coordinate_id=coordinate_id,
                stratum_id=None,
            )
        raise _error("coordinate has zero or invalid cluster standard error")
    return estimate, standard_error, tuple(retained_counts)


def _observed_statistics(
    plan: MultiSupportSimultaneousInferencePlanV2,
    values: Mapping[tuple[str, str, str], Fraction],
) -> dict[str, tuple[Fraction, float]]:
    result: dict[str, tuple[Fraction, float]] = {}
    for support in plan.coordinate_supports:
        samples = {item.stratum_id: item.semantic_task_cluster_ids for item in support.strata}
        estimate, standard_error, _counts = _coordinate_statistics(
            support,
            values,
            samples,
            filter_union_sample=False,
        )
        result[support.test_coordinate.test_coordinate_id] = (
            estimate,
            standard_error,
        )
    return result


def _higher_quantile(
    values: tuple[float, ...],
    *,
    alpha_numerator: int,
    alpha_denominator: int,
) -> float:
    if not values:
        raise _error("no valid global bootstrap draw remains")
    ordered = tuple(sorted(values))
    numerator = (alpha_denominator - alpha_numerator) * len(ordered)
    rank = (numerator + alpha_denominator - 1) // alpha_denominator
    return ordered[min(max(rank, 1), len(ordered)) - 1]


def _sample_digest(samples: Mapping[str, tuple[str, ...]]) -> str:
    return _digest(tuple((key, samples[key]) for key in sorted(samples)))


def _result_payload(
    result: MultiSupportSimultaneousInferenceResultV2,
) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("simultaneous_result_id")
    return payload


def _run(
    plan: MultiSupportSimultaneousInferencePlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    *,
    analysis_seed_domain_material: bytes | None,
) -> MultiSupportSimultaneousInferenceResultV2:
    checked_plan = _validated_plan(plan)
    checked_artifacts, values = _validated_artifacts(checked_plan, artifacts)
    observed = _observed_statistics(checked_plan, values)
    seed = _bootstrap_seed(checked_plan, analysis_seed_domain_material)
    rng = DeterministicRNG(seed)

    draws: list[GlobalUnionMaxTDrawV2] = []
    invalid_draws: list[InvalidGlobalUnionDrawV2] = []
    maxima: list[float] = []
    for replicate in range(checked_plan.bootstrap_samples):
        samples = {
            stratum.stratum_id: tuple(
                rng.choice(stratum.semantic_task_cluster_ids)
                for _ in stratum.semantic_task_cluster_ids
            )
            for stratum in checked_plan.global_union_strata
        }
        sample_sha256 = _sample_digest(samples)
        stratum_draws = tuple(
            UnionStratumDrawDigestV2(
                stratum_id=stratum.stratum_id,
                occurrence_count=len(samples[stratum.stratum_id]),
                sampled_clusters_sha256=_digest(samples[stratum.stratum_id]),
            )
            for stratum in checked_plan.global_union_strata
        )
        bootstrap: dict[str, tuple[Fraction, float]] = {}
        counts: list[CoordinateStratumRetainedCountV2] = []
        try:
            for support in checked_plan.coordinate_supports:
                estimate, standard_error, retained = _coordinate_statistics(
                    support,
                    values,
                    samples,
                    filter_union_sample=True,
                )
                coordinate_id = support.test_coordinate.test_coordinate_id
                bootstrap[coordinate_id] = (estimate, standard_error)
                counts.extend(retained)
        except _InvalidBootstrapDraw as invalid:
            invalid_draws.append(
                InvalidGlobalUnionDrawV2(
                    replicate_index=replicate,
                    global_sample_sha256=sample_sha256,
                    stratum_draws=stratum_draws,
                    reason_code=invalid.reason_code,
                    test_coordinate_id=invalid.test_coordinate_id,
                    stratum_id=invalid.stratum_id,
                )
            )
            continue
        max_abs_t = max(
            abs((float(bootstrap_estimate - observed[coordinate_id][0])) / bootstrap_standard_error)
            for coordinate_id, (bootstrap_estimate, bootstrap_standard_error) in (bootstrap.items())
        )
        if not math.isfinite(max_abs_t):
            raise _error("bootstrap global max-|T| statistic failed validation")
        maxima.append(max_abs_t)
        draws.append(
            GlobalUnionMaxTDrawV2(
                replicate_index=replicate,
                global_sample_sha256=sample_sha256,
                stratum_draws=stratum_draws,
                coordinate_retained_counts=tuple(
                    sorted(
                        counts,
                        key=lambda item: (item.test_coordinate_id, item.stratum_id),
                    )
                ),
                max_abs_t=max_abs_t,
            )
        )

    if len(draws) < checked_plan.minimum_valid_bootstrap_draws:
        raise _error("global bootstrap valid-draw count is below the frozen minimum")
    critical = _higher_quantile(
        tuple(maxima),
        alpha_numerator=checked_plan.alpha_numerator,
        alpha_denominator=checked_plan.alpha_denominator,
    )
    intervals = tuple(
        MultiSupportSimultaneousIntervalV2(
            test_coordinate_id=coordinate.test_coordinate_id,
            estimate_numerator=observed[coordinate.test_coordinate_id][0].numerator,
            estimate_denominator=observed[coordinate.test_coordinate_id][0].denominator,
            estimate=float(observed[coordinate.test_coordinate_id][0]),
            standard_error=observed[coordinate.test_coordinate_id][1],
            simultaneous_lower=(
                float(observed[coordinate.test_coordinate_id][0])
                - critical * observed[coordinate.test_coordinate_id][1]
            ),
            simultaneous_upper=(
                float(observed[coordinate.test_coordinate_id][0])
                + critical * observed[coordinate.test_coordinate_id][1]
            ),
        )
        for coordinate in checked_plan.family.coordinates
    )
    artifact_ids = tuple(item.contribution_artifact_id for item in checked_artifacts)
    provisional = MultiSupportSimultaneousInferenceResultV2(
        simultaneous_result_id="",
        inference_plan_id=checked_plan.inference_plan_id,
        confirmatory_experiment_freeze_id=(checked_plan.confirmatory_experiment_freeze_id),
        family_id=checked_plan.family.family_id,
        global_multiplicity_family_policy_sha256=(
            checked_plan.global_multiplicity_family_policy_sha256
        ),
        bootstrap_seed_sha256=hashlib.sha256(seed).hexdigest(),
        input_contribution_artifact_ids=artifact_ids,
        input_contributions_sha256=_artifact_input_digest(checked_artifacts),
        critical_value=critical,
        valid_draw_count=len(draws),
        invalid_draw_count=len(invalid_draws),
        intervals=intervals,
        draws=tuple(draws),
        invalid_draws=tuple(invalid_draws),
    )
    return MultiSupportSimultaneousInferenceResultV2(
        simultaneous_result_id=_RESULT_PREFIX + _digest(_result_payload(provisional)),
        inference_plan_id=provisional.inference_plan_id,
        confirmatory_experiment_freeze_id=(provisional.confirmatory_experiment_freeze_id),
        family_id=provisional.family_id,
        global_multiplicity_family_policy_sha256=(
            provisional.global_multiplicity_family_policy_sha256
        ),
        bootstrap_seed_sha256=provisional.bootstrap_seed_sha256,
        input_contribution_artifact_ids=provisional.input_contribution_artifact_ids,
        input_contributions_sha256=provisional.input_contributions_sha256,
        critical_value=provisional.critical_value,
        valid_draw_count=provisional.valid_draw_count,
        invalid_draw_count=provisional.invalid_draw_count,
        intervals=provisional.intervals,
        draws=provisional.draws,
        invalid_draws=provisional.invalid_draws,
    )


def run_multi_support_simultaneous_inference_v2(
    plan: MultiSupportSimultaneousInferencePlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    *,
    analysis_seed_domain_material: bytes,
) -> MultiSupportSimultaneousInferenceResultV2:
    """Run the frozen complete H x M coordinate-specific max-|T| family."""

    return _run(
        plan,
        artifacts,
        analysis_seed_domain_material=analysis_seed_domain_material,
    )


def run_frozen_domain_multi_support_simultaneous_inference_v2(
    plan: MultiSupportSimultaneousInferencePlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
) -> MultiSupportSimultaneousInferenceResultV2:
    """Run a formal plan whose seed is derived only from its frozen domain digest."""

    if plan.seed_derivation_rule != (
        "sha256_frozen_domain_digest_plus_content_addressed_plan_id_v1"
    ):
        raise _error("frozen-domain multi-support plan is required")
    return _run(plan, artifacts, analysis_seed_domain_material=None)


def validate_multi_support_simultaneous_result_v2(
    plan: MultiSupportSimultaneousInferencePlanV2,
    artifacts: Iterable[ConfirmatoryContributionArtifactV2],
    result: MultiSupportSimultaneousInferenceResultV2,
    *,
    analysis_seed_domain_material: bytes,
) -> MultiSupportSimultaneousInferenceResultV2:
    """Replay all union draws and require exact equality with the saved result."""

    if type(result) is not MultiSupportSimultaneousInferenceResultV2:
        raise _error("multi-support result artifact failed validation")
    expected = _run(
        plan,
        artifacts,
        analysis_seed_domain_material=analysis_seed_domain_material,
    )
    if result != expected:
        raise _error("multi-support result artifact failed validation")
    return result


__all__ = [
    "CoordinateStratumRetainedCountV2",
    "GlobalUnionMaxTDrawV2",
    "InvalidGlobalUnionDrawV2",
    "MultiSupportSimultaneousInferenceResultV2",
    "MultiSupportSimultaneousIntervalV2",
    "UnionStratumDrawDigestV2",
    "run_frozen_domain_multi_support_simultaneous_inference_v2",
    "run_multi_support_simultaneous_inference_v2",
    "validate_multi_support_simultaneous_result_v2",
]

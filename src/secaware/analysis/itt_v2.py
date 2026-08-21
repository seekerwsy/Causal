"""Minimal v2 cluster-weighted ITT and sensitivity primitives.

This module implements the prospective protocol's point estimators and a
semantic-cluster bootstrap primitive.  Simultaneous max-|T| inference and
multiplicity-family orchestration intentionally live outside this minimal gate.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from secaware.randomness import DeterministicRNG
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import ArmRole
from secaware.schema.outcomes_v2 import AssignmentOutcomeRecordV2

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
OutcomeNameV2 = Literal["y_c", "y_e", "y_secure_yield", "y_joint"]


@dataclass(frozen=True, slots=True)
class CoverageSummaryV2:
    assigned_n: int
    valid_code_n: int
    oracle_evaluable_n: int
    valid_code_conditional_coverage: float | None
    all_assignment_evaluable_yield: float


@dataclass(frozen=True, slots=True)
class ClusterContributionV2:
    semantic_task_cluster_id: str
    estimate: float


@dataclass(frozen=True, slots=True)
class ClusterITTResultV2:
    hypothesis_id: str
    model_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    outcome_name: OutcomeNameV2
    estimate: float
    cluster_contributions: tuple[ClusterContributionV2, ...]
    treatment_n: int
    control_n: int

    @property
    def independent_cluster_n(self) -> int:
        return len(self.cluster_contributions)


@dataclass(frozen=True, slots=True)
class ManskiContrastBoundsV2:
    hypothesis_id: str
    model_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    observed_secure_yield_effect: float
    lower: float
    upper: float


@dataclass(frozen=True, slots=True)
class SampledSemanticClusterV2:
    """One sampled occurrence; descendants remain an indivisible tuple."""

    stratum_id: str
    semantic_task_cluster_id: str
    occurrence_index: int
    descendants: tuple[AssignmentOutcomeRecordV2, ...]


@dataclass(frozen=True, slots=True)
class SemanticClusterBootstrapDrawV2:
    replicate_index: int
    sampled_clusters: tuple[SampledSemanticClusterV2, ...]
    estimate: float


@dataclass(frozen=True, slots=True)
class SemanticClusterBootstrapResultV2:
    draws: tuple[SemanticClusterBootstrapDrawV2, ...]

    @property
    def estimates(self) -> tuple[float, ...]:
        return tuple(draw.estimate for draw in self.draws)


def _error(message: str = "v2 ITT estimation failed validation") -> ValueError:
    return ValueError(message)


def _validated_rows(
    outcomes: Iterable[AssignmentOutcomeRecordV2],
) -> tuple[AssignmentOutcomeRecordV2, ...]:
    if isinstance(outcomes, (str, bytes, Mapping)):
        raise _error()
    rows: list[AssignmentOutcomeRecordV2] = []
    assignment_ids: set[str] = set()
    try:
        for index, value in enumerate(outcomes):
            if (
                index >= 1_000_000
                or type(value) is not AssignmentOutcomeRecordV2
                or not model_shape_is_intact(value)
            ):
                raise _error()
            checked = AssignmentOutcomeRecordV2.model_validate(
                value.model_dump(mode="python", round_trip=True, warnings=False)
            )
            if checked.assignment_id in assignment_ids:
                raise _error("duplicate v2 assignment outcome")
            assignment_ids.add(checked.assignment_id)
            rows.append(checked)
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize hostile iterables to one public error
        raise _error() from None
    if not rows:
        raise _error("v2 outcome support is empty")
    return tuple(rows)


def coverage_summary_v2(
    outcomes: Iterable[AssignmentOutcomeRecordV2],
    *,
    arm_role: ArmRole | None = None,
) -> CoverageSummaryV2:
    """Report conditional Oracle coverage and unconditional evaluable yield."""

    if arm_role is not None and type(arm_role) is not ArmRole:
        raise _error()
    rows = _validated_rows(outcomes)
    selected = rows if arm_role is None else tuple(row for row in rows if row.arm_role is arm_role)
    if not selected:
        raise _error("requested arm has no assignments")
    valid = sum(row.y_c for row in selected)
    evaluable = sum(row.y_c * row.y_e for row in selected)
    return CoverageSummaryV2(
        assigned_n=len(selected),
        valid_code_n=valid,
        oracle_evaluable_n=evaluable,
        valid_code_conditional_coverage=None if valid == 0 else evaluable / valid,
        all_assignment_evaluable_yield=evaluable / len(selected),
    )


def _validated_weight(value: object) -> float:
    if type(value) not in {int, float} or type(value) is bool:
        raise _error("frozen estimator weights failed validation")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise _error("frozen estimator weights failed validation")
    return result


def _validated_weights(
    rows: tuple[AssignmentOutcomeRecordV2, ...],
    task_weights: Mapping[tuple[str, str], float],
    realization_weights: Mapping[str, float],
) -> tuple[dict[tuple[str, str], float], dict[str, float]]:
    if not isinstance(task_weights, Mapping) or not isinstance(realization_weights, Mapping):
        raise _error("frozen estimator weights failed validation")
    observed_task_keys = {
        (row.semantic_task_cluster_id, row.task_instance_id) for row in rows
    }
    if set(task_weights) != observed_task_keys:
        raise _error("task-weight support is not complete")
    task = {key: _validated_weight(value) for key, value in task_weights.items()}
    realization = {
        key: _validated_weight(value) for key, value in realization_weights.items()
    }
    if not realization:
        raise _error("realization-weight support is empty")
    observed_realizations = {row.realization_spec_id for row in rows}
    if set(realization) != observed_realizations:
        raise _error("realization-weight support is not complete")
    if not math.isclose(sum(realization.values()), 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise _error("realization weights do not sum to one")
    cluster_ids = {cluster_id for cluster_id, _task_id in task}
    for cluster_id in cluster_ids:
        total = sum(weight for (cluster, _task), weight in task.items() if cluster == cluster_id)
        if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise _error("within-cluster task weights do not sum to one")
    return task, realization


def _outcome_value(row: AssignmentOutcomeRecordV2, outcome: OutcomeNameV2) -> int:
    if outcome == "y_c":
        return row.y_c
    if outcome == "y_e":
        return row.y_e
    if outcome == "y_secure_yield":
        return row.y_secure_yield
    if outcome == "y_joint":
        if row.y_joint is None:
            raise _error("joint outcome is unavailable without a frozen functional contract")
        return row.y_joint
    raise _error("unknown v2 outcome projection")


def _weighted_contrast(
    rows: tuple[AssignmentOutcomeRecordV2, ...],
    *,
    hypothesis_id: str,
    model_id: str,
    treatment_arm: ArmRole,
    control_arm: ArmRole,
    task_weights: Mapping[tuple[str, str], float],
    realization_weights: Mapping[str, float],
    treatment_value: Callable[[AssignmentOutcomeRecordV2], int],
    control_value: Callable[[AssignmentOutcomeRecordV2], int],
) -> tuple[float, tuple[ClusterContributionV2, ...], int, int]:
    if (
        type(hypothesis_id) is not str
        or not hypothesis_id
        or type(model_id) is not str
        or not model_id
        or type(treatment_arm) is not ArmRole
        or type(control_arm) is not ArmRole
        or treatment_arm is control_arm
    ):
        raise _error()
    if any(row.hypothesis_id != hypothesis_id or row.model_id != model_id for row in rows):
        raise _error("estimator input is not fixed at one hypothesis and model")
    task, realization = _validated_weights(rows, task_weights, realization_weights)

    task_owners: dict[str, str] = {}
    bundle_owners: dict[str, tuple[str, str]] = {}
    coordinate_bundles: dict[tuple[str, str], str] = {}
    slot_owners: set[tuple[str, int]] = set()
    block_rows: dict[str, list[AssignmentOutcomeRecordV2]] = {}
    grid_blocks: dict[tuple[str, str, str], set[str]] = {}
    for row in rows:
        owner = task_owners.setdefault(row.task_instance_id, row.semantic_task_cluster_id)
        if owner != row.semantic_task_cluster_id:
            raise _error("one task instance belongs to multiple semantic clusters")
        bundle_coordinate = (row.task_instance_id, row.realization_spec_id)
        bundle = coordinate_bundles.setdefault(
            bundle_coordinate, row.task_realization_bundle_id
        )
        if bundle != row.task_realization_bundle_id:
            raise _error("task-realization coordinate has multiple bundles")
        prior_bundle_owner = bundle_owners.setdefault(
            row.task_realization_bundle_id, bundle_coordinate
        )
        if prior_bundle_owner != bundle_coordinate:
            raise _error("task-realization bundle is reused across coordinates")
        slot = (row.block_id, row.request_randomness_slot)
        if slot in slot_owners:
            raise _error("request-randomness slot is reused inside a block")
        slot_owners.add(slot)
        block_rows.setdefault(row.block_id, []).append(row)
        grid = (
            row.semantic_task_cluster_id,
            row.task_instance_id,
            row.realization_spec_id,
        )
        grid_blocks.setdefault(grid, set()).add(row.block_id)

    expected_grid = {
        (cluster_id, task_id, realization_id)
        for cluster_id, task_id in task
        for realization_id in realization
    }
    if set(grid_blocks) != expected_grid or any(len(ids) != 1 for ids in grid_blocks.values()):
        raise _error("fully crossed task-by-realization support is incomplete")

    block_contrasts: dict[tuple[str, str, str], float] = {}
    treatment_n = 0
    control_n = 0
    for grid, block_ids in grid_blocks.items():
        block_id = next(iter(block_ids))
        members = block_rows[block_id]
        treated = [treatment_value(row) for row in members if row.arm_role is treatment_arm]
        controls = [control_value(row) for row in members if row.arm_role is control_arm]
        if (
            not treated
            or not controls
            or len(treated) != len(controls)
            or any(type(value) is not int or value not in {0, 1} for value in (*treated, *controls))
        ):
            raise _error("complete balanced arm support is missing inside a block")
        treatment_n += len(treated)
        control_n += len(controls)
        block_contrasts[grid] = (sum(treated) / len(treated)) - (
            sum(controls) / len(controls)
        )

    cluster_values: list[ClusterContributionV2] = []
    for cluster_id in sorted({cluster for cluster, _task in task}):
        contribution = 0.0
        for (cluster, task_id), task_weight in task.items():
            if cluster != cluster_id:
                continue
            for realization_id, realization_weight in realization.items():
                contribution += (
                    task_weight
                    * realization_weight
                    * block_contrasts[(cluster_id, task_id, realization_id)]
                )
        cluster_values.append(
            ClusterContributionV2(
                semantic_task_cluster_id=cluster_id,
                estimate=contribution,
            )
        )
    estimate = sum(item.estimate for item in cluster_values) / len(cluster_values)
    return estimate, tuple(cluster_values), treatment_n, control_n


def estimate_cluster_itt_v2(
    outcomes: Iterable[AssignmentOutcomeRecordV2],
    *,
    hypothesis_id: str,
    model_id: str,
    treatment_arm: ArmRole,
    control_arm: ArmRole,
    task_weights: Mapping[tuple[str, str], float],
    realization_weights: Mapping[str, float],
    outcome_name: OutcomeNameV2 = "y_secure_yield",
) -> ClusterITTResultV2:
    """Estimate block means, weighted task/realization effects, then equal-cluster ITT."""

    rows = _validated_rows(outcomes)
    estimate, clusters, treatment_n, control_n = _weighted_contrast(
        rows,
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        task_weights=task_weights,
        realization_weights=realization_weights,
        treatment_value=lambda row: _outcome_value(row, outcome_name),
        control_value=lambda row: _outcome_value(row, outcome_name),
    )
    return ClusterITTResultV2(
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        outcome_name=outcome_name,
        estimate=estimate,
        cluster_contributions=clusters,
        treatment_n=treatment_n,
        control_n=control_n,
    )


def estimate_manski_bounds_v2(
    outcomes: Iterable[AssignmentOutcomeRecordV2],
    *,
    hypothesis_id: str,
    model_id: str,
    treatment_arm: ArmRole,
    control_arm: ArmRole,
    task_weights: Mapping[tuple[str, str], float],
    realization_weights: Mapping[str, float],
) -> ManskiContrastBoundsV2:
    """Bound target-minus-control latent secure valid-code yield with identical weights."""

    rows = _validated_rows(outcomes)
    point, _clusters, _treatment_n, _control_n = _weighted_contrast(
        rows,
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        task_weights=task_weights,
        realization_weights=realization_weights,
        treatment_value=lambda row: row.y_secure_yield,
        control_value=lambda row: row.y_secure_yield,
    )
    lower, _clusters, _treatment_n, _control_n = _weighted_contrast(
        rows,
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        task_weights=task_weights,
        realization_weights=realization_weights,
        treatment_value=lambda row: row.manski_lower,
        control_value=lambda row: row.manski_upper,
    )
    upper, _clusters, _treatment_n, _control_n = _weighted_contrast(
        rows,
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        task_weights=task_weights,
        realization_weights=realization_weights,
        treatment_value=lambda row: row.manski_upper,
        control_value=lambda row: row.manski_lower,
    )
    if lower > point or point > upper:
        raise _error("Manski contrast bounds failed validation")
    return ManskiContrastBoundsV2(
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        treatment_arm=treatment_arm,
        control_arm=control_arm,
        observed_secure_yield_effect=point,
        lower=lower,
        upper=upper,
    )


def semantic_cluster_bootstrap_v2(
    outcomes: Iterable[AssignmentOutcomeRecordV2],
    statistic: Callable[[tuple[SampledSemanticClusterV2, ...]], float],
    *,
    samples: int,
    seed_material: bytes,
    strata: Mapping[str, str] | None = None,
) -> SemanticClusterBootstrapResultV2:
    """Resample top-level clusters, optionally preserving each stratum's cluster count."""

    if (
        not callable(statistic)
        or type(samples) is not int
        or not 1 <= samples <= 100_000
        or type(seed_material) is not bytes
        or not seed_material
        or (strata is not None and not isinstance(strata, Mapping))
    ):
        raise _error("semantic-cluster bootstrap failed validation")
    rows = _validated_rows(outcomes)
    by_cluster: dict[str, list[AssignmentOutcomeRecordV2]] = {}
    for row in rows:
        by_cluster.setdefault(row.semantic_task_cluster_id, []).append(row)
    cluster_ids = set(by_cluster)
    if strata is None:
        cluster_strata = {cluster_id: "all" for cluster_id in cluster_ids}
    else:
        if set(strata) != cluster_ids or any(
            type(value) is not str or not value for value in strata.values()
        ):
            raise _error("bootstrap stratum mapping failed validation")
        cluster_strata = dict(strata)
    ids_by_stratum: dict[str, list[str]] = {}
    for cluster_id, stratum_id in cluster_strata.items():
        ids_by_stratum.setdefault(stratum_id, []).append(cluster_id)
    frozen_descendants = {
        cluster_id: tuple(sorted(members, key=lambda row: row.assignment_id))
        for cluster_id, members in by_cluster.items()
    }
    frozen_strata = {
        stratum_id: tuple(sorted(ids)) for stratum_id, ids in ids_by_stratum.items()
    }
    rng = DeterministicRNG(seed_material)
    draws: list[SemanticClusterBootstrapDrawV2] = []
    try:
        for replicate in range(samples):
            sampled: list[SampledSemanticClusterV2] = []
            occurrence = 0
            for stratum_id in sorted(frozen_strata):
                support = frozen_strata[stratum_id]
                for _ in range(len(support)):
                    cluster_id = rng.choice(support)
                    sampled.append(
                        SampledSemanticClusterV2(
                            stratum_id=stratum_id,
                            semantic_task_cluster_id=cluster_id,
                            occurrence_index=occurrence,
                            descendants=frozen_descendants[cluster_id],
                        )
                    )
                    occurrence += 1
            sample_tuple = tuple(sampled)
            estimate = statistic(sample_tuple)
            if type(estimate) not in {int, float} or type(estimate) is bool:
                raise _error("bootstrap statistic failed validation")
            estimate = float(estimate)
            if not math.isfinite(estimate):
                raise _error("bootstrap statistic failed validation")
            draws.append(
                SemanticClusterBootstrapDrawV2(
                    replicate_index=replicate,
                    sampled_clusters=sample_tuple,
                    estimate=estimate,
                )
            )
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - a caller statistic is an untrusted callback
        raise _error("bootstrap statistic failed validation") from None
    return SemanticClusterBootstrapResultV2(draws=tuple(draws))


__all__ = [
    "ClusterContributionV2",
    "ClusterITTResultV2",
    "CoverageSummaryV2",
    "ManskiContrastBoundsV2",
    "SampledSemanticClusterV2",
    "SemanticClusterBootstrapDrawV2",
    "SemanticClusterBootstrapResultV2",
    "coverage_summary_v2",
    "estimate_cluster_itt_v2",
    "estimate_manski_bounds_v2",
    "semantic_cluster_bootstrap_v2",
]

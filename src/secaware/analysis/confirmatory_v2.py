"""Manifest-bound confirmatory ITT entry point for the prospective v2 protocol.

The low-level estimator accepts rows and weights so it can be unit-tested.  This
module is the public confirmatory boundary: task and realization weights are derived
from the frozen population, rows are derived from exact assignment coverage, and a
caller cannot silently delete support and provide matching replacement weights.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from secaware.analysis.itt_v2 import (
    ClusterITTResultV2,
    CoverageSummaryV2,
    ManskiContrastBoundsV2,
    coverage_summary_v2,
    estimate_cluster_itt_v2,
    estimate_manski_bounds_v2,
)
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.population_v2 import PopulationFreezeManifestV2

_SUPPORTED_OUTCOMES = {"y_c", "y_e", "y_secure_yield", "y_joint"}


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


@dataclass(frozen=True, slots=True)
class ManifestBoundClusterITTResultV2:
    analysis_result_id: str
    population_freeze_manifest_id: str
    provenance_closed_coverage_manifest_id: str
    assignment_coverage_manifest_id: str
    randomization_manifest_id: str
    cluster_itt: ClusterITTResultV2
    treatment_coverage: CoverageSummaryV2
    control_coverage: CoverageSummaryV2
    secure_yield_manski_bounds: ManskiContrastBoundsV2
    simultaneous_confirmation_allowed: bool


def _primary_contrast(operation: FeatureOperation) -> tuple[ArmRole, ArmRole]:
    if operation is FeatureOperation.ADD:
        return ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE
    return ArmRole.TARGET_REMOVE, ArmRole.NOOP_RETAIN


def estimate_manifest_bound_cluster_itt_v2(
    *,
    population: PopulationFreezeManifestV2,
    assignment_coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    model_id: str,
) -> ManifestBoundClusterITTResultV2:
    """Return the frozen primary model-specific point estimate and diagnostics.

    This function cannot award a confirmatory label.  Formal confirmation additionally
    requires the registered all-hypothesis/all-model simultaneous-inference orchestrator.
    """

    try:
        frozen_population = PopulationFreezeManifestV2.model_validate(population, strict=True)
        authenticated_coverage = ProvenanceClosedAssignmentCoverageManifestV2.model_validate(
            assignment_coverage, strict=True
        )
        coverage = authenticated_coverage.base_coverage
        hypothesis = frozen_population.hypothesis
        treatment_arm, control_arm = _primary_contrast(hypothesis.operation)
        outcome_name = hypothesis.outcome_id
        if (
            authenticated_coverage.execution_policy_freeze.randomization != coverage.randomization
            or coverage.randomization.population != frozen_population
            or coverage.randomization.population.population_freeze_manifest_id
            != frozen_population.population_freeze_manifest_id
            or model_id not in frozen_population.common_model_scope
            or outcome_name not in _SUPPORTED_OUTCOMES
        ):
            raise ValueError

        expected_ids = {
            item.assignment_id
            for item in coverage.randomization.assignments
            if item.block.model_id == model_id
        }
        outcomes = tuple(item for item in coverage.outcomes if item.model_id == model_id)
        if {item.assignment_id for item in outcomes} != expected_ids:
            raise ValueError
        task_weights = {
            (item.semantic_task_cluster_id, item.task_instance_id): float(
                item.within_cluster_task_weight.fraction
            )
            for item in frozen_population.task_gates
            if item.gate_passed and item.within_cluster_task_weight is not None
        }
        realization_weights = {
            realization_id: numerator / hypothesis.probability_denominator
            for realization_id, numerator in zip(
                hypothesis.realization_spec_ids,
                hypothesis.probability_numerators,
                strict=True,
            )
        }
        result = estimate_cluster_itt_v2(
            outcomes,
            hypothesis_id=hypothesis.hypothesis_id,
            model_id=model_id,
            treatment_arm=treatment_arm,
            control_arm=control_arm,
            task_weights=task_weights,
            realization_weights=realization_weights,
            outcome_name=outcome_name,
        )
        treatment_coverage = coverage_summary_v2(outcomes, arm_role=treatment_arm)
        control_coverage = coverage_summary_v2(outcomes, arm_role=control_arm)
        manski = estimate_manski_bounds_v2(
            outcomes,
            hypothesis_id=hypothesis.hypothesis_id,
            model_id=model_id,
            treatment_arm=treatment_arm,
            control_arm=control_arm,
            task_weights=task_weights,
            realization_weights=realization_weights,
        )
        payload = {
            "population_freeze_manifest_id": frozen_population.population_freeze_manifest_id,
            "provenance_closed_coverage_manifest_id": (
                authenticated_coverage.provenance_closed_coverage_manifest_id
            ),
            "assignment_coverage_manifest_id": coverage.assignment_coverage_manifest_id,
            "randomization_manifest_id": coverage.randomization.randomization_manifest_id,
            "cluster_itt": asdict(result),
            "treatment_coverage": asdict(treatment_coverage),
            "control_coverage": asdict(control_coverage),
            "secure_yield_manski_bounds": asdict(manski),
            "simultaneous_confirmation_allowed": False,
        }
        return ManifestBoundClusterITTResultV2(
            analysis_result_id="manifest_bound_itt_v2_" + _digest(payload),
            population_freeze_manifest_id=frozen_population.population_freeze_manifest_id,
            provenance_closed_coverage_manifest_id=(
                authenticated_coverage.provenance_closed_coverage_manifest_id
            ),
            assignment_coverage_manifest_id=coverage.assignment_coverage_manifest_id,
            randomization_manifest_id=coverage.randomization.randomization_manifest_id,
            cluster_itt=result,
            treatment_coverage=treatment_coverage,
            control_coverage=control_coverage,
            secure_yield_manski_bounds=manski,
            simultaneous_confirmation_allowed=False,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        raise ValueError("manifest-bound v2 ITT failed exact validation") from error


__all__ = [
    "ManifestBoundClusterITTResultV2",
    "estimate_manifest_bound_cluster_itt_v2",
]

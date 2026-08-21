"""Provenance-closed cluster contributions for confirmatory inference.

This module is deliberately an assembler, not a second estimator API.  Its only
numeric inputs are authenticated assignment outcomes reachable through a
``ProvenanceClosedAssignmentCoverageManifestV2``.  Task and realization weights
are read from the exact frozen population; callers cannot supply replacement
rows, values, or weights.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from fractions import Fraction
from typing import Literal

from pydantic import ValidationError

from secaware.analysis.realization_robustness_v2 import RealizationClusterContributionV2
from secaware.analysis.simultaneous_v2 import CoordinateClusterContributionV2
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.inference_v2 import (
    SimultaneousCoordinateKindV2,
    SimultaneousTestCoordinateV2,
)
from secaware.schema.population_v2 import PopulationFreezeManifestV2

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_ARTIFACT_PREFIX = "confirmatory_contributions_v2_"
_DERIVATION_RULE = "authenticated_block_arm_means_then_frozen_task_weights_then_qh_then_cluster_v1"
_CHECKED_CONTRIBUTION_ACCESS = object()
_FORMAL_CONTEXT_CONTRIBUTION_ACCESS = object()

_ADD_CONTROLS = frozenset(
    {
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    }
)
_REMOVE_CONTROLS = frozenset(
    {
        ArmRole.NOOP_RETAIN,
        ArmRole.LENGTH_MATCHED_SHAM_EDIT,
        ArmRole.GENERIC_SECURITY_REPLACEMENT,
    }
)


@dataclass(frozen=True, slots=True)
class ExactCoordinateClusterContributionV2:
    """One exact rational coordinate contribution before its final float projection."""

    test_coordinate_id: str
    stratum_id: str
    semantic_task_cluster_id: str
    numerator: int
    denominator: int

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class ExactRealizationClusterContributionV2:
    """One exact rational realization contribution before its final float projection."""

    hypothesis_id: str
    model_id: str
    realization_spec_id: str
    stratum_id: str
    semantic_task_cluster_id: str
    numerator: int
    denominator: int

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class ConfirmatoryContributionArtifactV2:
    """Content-addressed output bound to every upstream confirmatory root."""

    contribution_artifact_id: str
    population_freeze_manifest_id: str
    randomization_manifest_id: str
    execution_policy_freeze_manifest_id: str
    provenance_closed_coverage_manifest_id: str
    test_coordinate_id: str
    derivation_rule: Literal[
        "authenticated_block_arm_means_then_frozen_task_weights_then_qh_then_cluster_v1"
    ]
    rational_arithmetic_until_final_projection: Literal[True]
    exact_coordinate_contributions: tuple[ExactCoordinateClusterContributionV2, ...]
    coordinate_contributions: tuple[CoordinateClusterContributionV2, ...]
    exact_realization_contributions: tuple[ExactRealizationClusterContributionV2, ...]
    realization_contributions: tuple[RealizationClusterContributionV2, ...]


def _error(
    message: str = "confirmatory contribution v2 failed exact validation",
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


def _checked_population(population: PopulationFreezeManifestV2) -> PopulationFreezeManifestV2:
    if type(population) is not PopulationFreezeManifestV2 or not model_shape_is_intact(population):
        raise _error()
    try:
        return PopulationFreezeManifestV2.model_validate(
            population.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error() from None


def _checked_coverage(
    coverage: ProvenanceClosedAssignmentCoverageManifestV2,
) -> ProvenanceClosedAssignmentCoverageManifestV2:
    if type(
        coverage
    ) is not ProvenanceClosedAssignmentCoverageManifestV2 or not model_shape_is_intact(coverage):
        raise _error("provenance-closed coverage is required")
    try:
        return ProvenanceClosedAssignmentCoverageManifestV2.model_validate(
            coverage.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("provenance-closed coverage failed validation") from None


def _checked_coordinate(
    coordinate: SimultaneousTestCoordinateV2,
) -> SimultaneousTestCoordinateV2:
    if type(coordinate) is not SimultaneousTestCoordinateV2 or not model_shape_is_intact(
        coordinate
    ):
        raise _error()
    try:
        return SimultaneousTestCoordinateV2.model_validate(
            coordinate.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error() from None


def _validate_coordinate_semantics(
    population: PopulationFreezeManifestV2,
    coordinate: SimultaneousTestCoordinateV2,
    *,
    formal_family: bool,
) -> None:
    hypothesis = population.hypothesis
    if hypothesis.operation is FeatureOperation.ADD:
        expected_treatment = ArmRole.TARGET_PATCH
        allowed_controls = _ADD_CONTROLS
    else:
        expected_treatment = ArmRole.TARGET_REMOVE
        allowed_controls = _REMOVE_CONTROLS
    if (
        coordinate.hypothesis_id != hypothesis.hypothesis_id
        or coordinate.target_spec_id != hypothesis.target_spec_id
        or coordinate.arm_protocol_id != hypothesis.arm_protocol_id
        or coordinate.model_id not in population.common_model_scope
        or (
            coordinate.outcome_name
            not in ({"y_secure_yield", "y_joint"} if formal_family else {hypothesis.outcome_id})
        )
        or coordinate.coordinate_kind is not SimultaneousCoordinateKindV2.POLICY_EFFECT
        or coordinate.analysis_component_id != "pooled"
        or coordinate.treatment_arm is not expected_treatment
        or coordinate.control_arm not in allowed_controls
    ):
        raise _error("coordinate does not match the frozen policy hypothesis")


def _outcome_value(outcome: object, outcome_name: str) -> int:
    value = getattr(outcome, outcome_name, None)
    if type(value) is not int or value not in {0, 1}:
        raise _error("coordinate outcome is not a complete binary assignment outcome")
    return value


def _fraction_row(
    coordinate_id: str,
    stratum_id: str,
    cluster_id: str,
    value: Fraction,
) -> ExactCoordinateClusterContributionV2:
    if not Fraction(-1, 1) <= value <= Fraction(1, 1):
        raise _error("derived coordinate contribution is outside [-1, 1]")
    return ExactCoordinateClusterContributionV2(
        test_coordinate_id=coordinate_id,
        stratum_id=stratum_id,
        semantic_task_cluster_id=cluster_id,
        numerator=value.numerator,
        denominator=value.denominator,
    )


def _realization_fraction_row(
    *,
    hypothesis_id: str,
    model_id: str,
    realization_id: str,
    stratum_id: str,
    cluster_id: str,
    value: Fraction,
) -> ExactRealizationClusterContributionV2:
    if not Fraction(-1, 1) <= value <= Fraction(1, 1):
        raise _error("derived realization contribution is outside [-1, 1]")
    return ExactRealizationClusterContributionV2(
        hypothesis_id=hypothesis_id,
        model_id=model_id,
        realization_spec_id=realization_id,
        stratum_id=stratum_id,
        semantic_task_cluster_id=cluster_id,
        numerator=value.numerator,
        denominator=value.denominator,
    )


def _artifact_payload(artifact: ConfirmatoryContributionArtifactV2) -> dict[str, object]:
    payload = asdict(artifact)
    payload.pop("contribution_artifact_id")
    return payload


def _derive(
    population: PopulationFreezeManifestV2,
    coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    coordinate: SimultaneousTestCoordinateV2,
    *,
    formal_family: bool = False,
) -> ConfirmatoryContributionArtifactV2:
    checked_population = _checked_population(population)
    checked_coordinate = _checked_coordinate(coordinate)
    checked_coverage = _checked_coverage(coverage)
    return _derive_checked_inputs(
        checked_population,
        checked_coverage,
        checked_coordinate,
        formal_family=formal_family,
        access=_CHECKED_CONTRIBUTION_ACCESS,
    )


def _derive_checked_inputs(
    checked_population: PopulationFreezeManifestV2,
    checked_coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    checked_coordinate: SimultaneousTestCoordinateV2,
    *,
    formal_family: bool,
    access: object,
) -> ConfirmatoryContributionArtifactV2:
    if (
        access is not _CHECKED_CONTRIBUTION_ACCESS
        or type(checked_population) is not PopulationFreezeManifestV2
        or not model_shape_is_intact(checked_population)
        or type(checked_coverage) is not ProvenanceClosedAssignmentCoverageManifestV2
        or not model_shape_is_intact(checked_coverage)
        or type(checked_coordinate) is not SimultaneousTestCoordinateV2
        or not model_shape_is_intact(checked_coordinate)
    ):
        raise _error("checked contribution inputs lost model shape")
    _validate_coordinate_semantics(
        checked_population,
        checked_coordinate,
        formal_family=formal_family,
    )
    freeze = checked_coverage.execution_policy_freeze
    randomization = freeze.randomization
    if randomization.population != checked_population:
        raise _error("coverage is not bound to the exact frozen population")

    hypothesis = checked_population.hypothesis
    task_weights: dict[tuple[str, str], Fraction] = {}
    tasks_by_cluster: dict[str, list[str]] = defaultdict(list)
    for gate in checked_population.task_gates:
        if not gate.gate_passed:
            continue
        if gate.within_cluster_task_weight is None:
            raise _error()
        key = (gate.semantic_task_cluster_id, gate.task_instance_id)
        task_weights[key] = gate.within_cluster_task_weight.fraction
        tasks_by_cluster[gate.semantic_task_cluster_id].append(gate.task_instance_id)

    stratum_by_cluster = {
        binding.semantic_task_cluster_id: stratum.stratum_id
        for stratum in checked_population.strata
        for binding in stratum.cluster_weights
    }
    if set(tasks_by_cluster) != set(stratum_by_cluster):
        raise _error("population cluster and stratum support differ")

    outcomes_by_block_arm: dict[tuple[str, str, str, ArmRole], list[int]] = defaultdict(list)
    for receipt in checked_coverage.outcome_assembly_receipts:
        outcome = receipt.outcome
        if outcome.model_id != checked_coordinate.model_id:
            continue
        key = (
            outcome.semantic_task_cluster_id,
            outcome.task_instance_id,
            outcome.realization_spec_id,
            outcome.arm_role,
        )
        outcomes_by_block_arm[key].append(_outcome_value(outcome, checked_coordinate.outcome_name))

    block_contrasts: dict[tuple[str, str, str], Fraction] = {}
    for cluster_id, task_ids in tasks_by_cluster.items():
        for task_id in task_ids:
            for realization_id in hypothesis.realization_spec_ids:
                treatment_values = outcomes_by_block_arm.get(
                    (
                        cluster_id,
                        task_id,
                        realization_id,
                        checked_coordinate.treatment_arm,
                    ),
                    [],
                )
                control_values = outcomes_by_block_arm.get(
                    (
                        cluster_id,
                        task_id,
                        realization_id,
                        checked_coordinate.control_arm,
                    ),
                    [],
                )
                if not treatment_values or len(treatment_values) != len(control_values):
                    raise _error("complete balanced arm support is required in every block")
                treatment_mean = Fraction(sum(treatment_values), len(treatment_values))
                control_mean = Fraction(sum(control_values), len(control_values))
                block_contrasts[(cluster_id, task_id, realization_id)] = (
                    treatment_mean - control_mean
                )

    realization_values: dict[tuple[str, str], Fraction] = {}
    exact_realization: list[ExactRealizationClusterContributionV2] = []
    for realization_id in hypothesis.realization_spec_ids:
        for cluster_id in sorted(tasks_by_cluster):
            value = sum(
                (
                    task_weights[(cluster_id, task_id)]
                    * block_contrasts[(cluster_id, task_id, realization_id)]
                    for task_id in tasks_by_cluster[cluster_id]
                ),
                Fraction(0, 1),
            )
            realization_values[(realization_id, cluster_id)] = value
            exact_realization.append(
                _realization_fraction_row(
                    hypothesis_id=hypothesis.hypothesis_id,
                    model_id=checked_coordinate.model_id,
                    realization_id=realization_id,
                    stratum_id=stratum_by_cluster[cluster_id],
                    cluster_id=cluster_id,
                    value=value,
                )
            )

    realization_weights = {
        realization_id: Fraction(numerator, hypothesis.probability_denominator)
        for realization_id, numerator in zip(
            hypothesis.realization_spec_ids,
            hypothesis.probability_numerators,
            strict=True,
        )
    }
    exact_coordinate = tuple(
        _fraction_row(
            checked_coordinate.test_coordinate_id,
            stratum_by_cluster[cluster_id],
            cluster_id,
            sum(
                (
                    realization_weights[realization_id]
                    * realization_values[(realization_id, cluster_id)]
                    for realization_id in hypothesis.realization_spec_ids
                ),
                Fraction(0, 1),
            ),
        )
        for cluster_id in sorted(tasks_by_cluster)
    )
    exact_realization_rows = tuple(
        sorted(
            exact_realization,
            key=lambda item: (
                item.realization_spec_id,
                item.stratum_id,
                item.semantic_task_cluster_id,
            ),
        )
    )
    coordinate_rows = tuple(
        CoordinateClusterContributionV2(
            test_coordinate_id=item.test_coordinate_id,
            stratum_id=item.stratum_id,
            semantic_task_cluster_id=item.semantic_task_cluster_id,
            estimate=float(item.fraction),
        )
        for item in exact_coordinate
    )
    realization_rows = tuple(
        RealizationClusterContributionV2(
            hypothesis_id=item.hypothesis_id,
            model_id=item.model_id,
            realization_spec_id=item.realization_spec_id,
            stratum_id=item.stratum_id,
            semantic_task_cluster_id=item.semantic_task_cluster_id,
            estimate=float(item.fraction),
        )
        for item in exact_realization_rows
    )
    provisional = ConfirmatoryContributionArtifactV2(
        contribution_artifact_id="",
        population_freeze_manifest_id=(checked_population.population_freeze_manifest_id),
        randomization_manifest_id=randomization.randomization_manifest_id,
        execution_policy_freeze_manifest_id=(freeze.execution_policy_freeze_manifest_id),
        provenance_closed_coverage_manifest_id=(
            checked_coverage.provenance_closed_coverage_manifest_id
        ),
        test_coordinate_id=checked_coordinate.test_coordinate_id,
        derivation_rule=_DERIVATION_RULE,
        rational_arithmetic_until_final_projection=True,
        exact_coordinate_contributions=exact_coordinate,
        coordinate_contributions=coordinate_rows,
        exact_realization_contributions=exact_realization_rows,
        realization_contributions=realization_rows,
    )
    return ConfirmatoryContributionArtifactV2(
        contribution_artifact_id=_ARTIFACT_PREFIX + _digest(_artifact_payload(provisional)),
        population_freeze_manifest_id=provisional.population_freeze_manifest_id,
        randomization_manifest_id=provisional.randomization_manifest_id,
        execution_policy_freeze_manifest_id=(provisional.execution_policy_freeze_manifest_id),
        provenance_closed_coverage_manifest_id=(provisional.provenance_closed_coverage_manifest_id),
        test_coordinate_id=provisional.test_coordinate_id,
        derivation_rule=provisional.derivation_rule,
        rational_arithmetic_until_final_projection=True,
        exact_coordinate_contributions=provisional.exact_coordinate_contributions,
        coordinate_contributions=provisional.coordinate_contributions,
        exact_realization_contributions=provisional.exact_realization_contributions,
        realization_contributions=provisional.realization_contributions,
    )


def derive_confirmatory_contributions_v2(
    population: PopulationFreezeManifestV2,
    coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    coordinate: SimultaneousTestCoordinateV2,
) -> ConfirmatoryContributionArtifactV2:
    """Derive exact cluster contributions from the three authenticated inputs only."""

    return _derive(population, coverage, coordinate)


def derive_frozen_formal_family_contributions_v2(
    population: PopulationFreezeManifestV2,
    coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    coordinate: SimultaneousTestCoordinateV2,
) -> ConfirmatoryContributionArtifactV2:
    """Derive one protocol-defined secure-yield or joint formal contrast.

    This remains a low-level provenance assembler and grants no confirmatory
    label.  The formal orchestrator determines the complete family and supplies
    its exact coordinate; callers cannot use this helper to shrink that family.
    """

    return _derive(population, coverage, coordinate, formal_family=True)


def _derive_from_formal_context_v2(
    context: object,
    *,
    formal_family: object,
    hypothesis_id: str,
    model_id: str,
) -> ConfirmatoryContributionArtifactV2:
    """Derive one artifact using only a sealed two-root context lookup."""

    try:
        from secaware.analysis.formal_confirmation_v2 import _ValidatedFormalContextV2

        if type(context) is not _ValidatedFormalContextV2:
            raise _error("sealed formal context is required")
        population, coverage, coordinate = context._contribution_inputs(
            _FORMAL_CONTEXT_CONTRIBUTION_ACCESS,
            formal_family=formal_family,
            hypothesis_id=hypothesis_id,
            model_id=model_id,
        )
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:  # noqa: BLE001 - normalize a forged context
        raise _error("sealed formal context is required") from None
    return _derive_checked_inputs(
        population,
        coverage,
        coordinate,
        formal_family=True,
        access=_CHECKED_CONTRIBUTION_ACCESS,
    )


def validate_confirmatory_contribution_artifact_v2(
    population: PopulationFreezeManifestV2,
    coverage: ProvenanceClosedAssignmentCoverageManifestV2,
    coordinate: SimultaneousTestCoordinateV2,
    artifact: ConfirmatoryContributionArtifactV2,
) -> ConfirmatoryContributionArtifactV2:
    """Recompute and require exact equality with a persisted artifact."""

    if type(artifact) is not ConfirmatoryContributionArtifactV2:
        raise _error("confirmatory contribution artifact failed validation")
    expected = _derive(population, coverage, coordinate)
    if artifact != expected:
        raise _error("confirmatory contribution artifact failed validation")
    return artifact


__all__ = [
    "ConfirmatoryContributionArtifactV2",
    "ExactCoordinateClusterContributionV2",
    "ExactRealizationClusterContributionV2",
    "derive_confirmatory_contributions_v2",
    "derive_frozen_formal_family_contributions_v2",
    "validate_confirmatory_contribution_artifact_v2",
]

"""Run-level, pre-outcome freeze for the complete confirmatory experiment.

This is the single trust root above all per-hypothesis protocol roots and their
pre-generation execution freezes.  It contains the complete selected hypothesis
and model universe, but no generated code, measurements, outcomes, or analysis
results.
"""

from __future__ import annotations

from collections import Counter
from fractions import Fraction
from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, model_validator

from secaware.experiments.execution_v2 import ExecutionPolicyFreezeManifestV2
from secaware.records import (
    SnapshotContentAddressedResearchRecord,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.policy_v2 import (
    BridgeStatus,
    CandidateUniverseManifest,
    SelectionFreezeManifest,
)
from secaware.schema.protocol_freeze_v2 import ProtocolFreezeRootV2

EXPERIMENT_FREEZE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_EXPERIMENT_FREEZE_ID_PATTERN = r"^confirmatory_experiment_freeze_v2_[0-9a-f]{64}$"
_HM_COORDINATE_ID_PATTERN = r"^confirmatory_hm_coordinate_v2_[0-9a-f]{64}$"

_ADD_ARM_ORDER = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_REMOVE_ARM_ORDER = (
    ArmRole.TARGET_REMOVE,
    ArmRole.NOOP_RETAIN,
    ArmRole.LENGTH_MATCHED_SHAM_EDIT,
    ArmRole.GENERIC_SECURITY_REPLACEMENT,
)


class _ContentAddressedExperimentFreezeV2(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "experiment freeze v2 contract failed validation"
    _schema_version = EXPERIMENT_FREEZE_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"] = EXPERIMENT_FREEZE_V2_SCHEMA_VERSION


class ConfirmatoryHypothesisModelCoordinateV2(_ContentAddressedExperimentFreezeV2):
    """One pre-outcome cell in the exact global hypothesis-by-model universe."""

    _id_field = "hypothesis_model_coordinate_id"
    _id_prefix = "confirmatory_hm_coordinate_v2_"

    hypothesis_model_coordinate_id: str = Field(pattern=_HM_COORDINATE_ID_PATTERN)
    hypothesis_id: str
    target_spec_id: str
    arm_protocol_id: str
    model_id: str
    protocol_freeze_id: str
    execution_policy_freeze_manifest_id: str
    randomization_manifest_id: str
    population_freeze_manifest_id: str

    @classmethod
    def from_binding(
        cls,
        *,
        protocol_root: ProtocolFreezeRootV2,
        execution_freeze: ExecutionPolicyFreezeManifestV2,
        model_id: str,
    ) -> Self:
        hypothesis = protocol_root.intervention_bridge.frozen_hypothesis
        return cls.from_content(
            hypothesis_id=hypothesis.hypothesis_id,
            target_spec_id=hypothesis.target_spec_id,
            arm_protocol_id=hypothesis.arm_protocol_id,
            model_id=model_id,
            protocol_freeze_id=protocol_root.protocol_freeze_id,
            execution_policy_freeze_manifest_id=(
                execution_freeze.execution_policy_freeze_manifest_id
            ),
            randomization_manifest_id=execution_freeze.randomization.randomization_manifest_id,
            population_freeze_manifest_id=(protocol_root.population.population_freeze_manifest_id),
        )

    @model_validator(mode="after")
    def validate_coordinate(self) -> Self:
        if not is_valid_model_id(self.model_id):
            raise ValueError(self._safe_validation_message)
        return self


def _hypothesis_id(root: ProtocolFreezeRootV2) -> str:
    return root.intervention_bridge.frozen_hypothesis.hypothesis_id


def _execution_hypothesis_id(freeze: ExecutionPolicyFreezeManifestV2) -> str:
    return freeze.randomization.population.hypothesis.hypothesis_id


def _expected_arm_roles(operation: FeatureOperation) -> tuple[ArmRole, ...]:
    return _ADD_ARM_ORDER if operation is FeatureOperation.ADD else _REMOVE_ARM_ORDER


def _protocol_is_equal_probability_four_arm(root: ProtocolFreezeRootV2) -> bool:
    protocol = root.intervention_bridge.arm_protocol
    expected_roles = _expected_arm_roles(protocol.operation)
    return (
        tuple(item.arm_role for item in protocol.arms) == expected_roles
        and tuple(item.arm_index for item in protocol.arms) == tuple(range(4))
        and all(
            Fraction(
                item.assignment_probability_numerator,
                protocol.assignment_probability_denominator,
            )
            == Fraction(1, 4)
            for item in protocol.arms
        )
        and protocol.primary_contrast == (expected_roles[0], expected_roles[1])
        and protocol.specificity_contrasts
        == ((expected_roles[0], expected_roles[2]), (expected_roles[0], expected_roles[3]))
    )


def _randomization_has_exact_four_arm_blocks(
    root: ProtocolFreezeRootV2,
    freeze: ExecutionPolicyFreezeManifestV2,
) -> bool:
    randomization = freeze.randomization
    roles = _expected_arm_roles(root.intervention_bridge.arm_protocol.operation)
    slots = randomization.request_randomness_slots
    if len(slots) < 4 or len(slots) % 4 != 0:
        return False
    expected = Counter({role: len(slots) // 4 for role in roles})
    counts: dict[str, Counter[ArmRole]] = {
        block.block_id: Counter() for block in randomization.blocks
    }
    for assignment in randomization.assignments:
        counter = counts.get(assignment.block.block_id)
        if counter is None:
            return False
        counter[assignment.assigned_arm] += 1
    return bool(counts) and all(counter == expected for counter in counts.values())


class ConfirmatoryExperimentFreezeV2(_ContentAddressedExperimentFreezeV2):
    """Complete run-level identity frozen after randomization and before generation."""

    _id_field = "confirmatory_experiment_freeze_id"
    _id_prefix = "confirmatory_experiment_freeze_v2_"

    confirmatory_experiment_freeze_id: str = Field(pattern=_EXPERIMENT_FREEZE_ID_PATTERN)
    candidate_universe: CandidateUniverseManifest
    selection_freeze: SelectionFreezeManifest
    protocol_roots: tuple[ProtocolFreezeRootV2, ...] = Field(min_length=1, max_length=10_000)
    execution_policy_freezes: tuple[ExecutionPolicyFreezeManifestV2, ...] = Field(
        min_length=1, max_length=10_000
    )
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    model_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    hypothesis_model_coordinates: tuple[ConfirmatoryHypothesisModelCoordinateV2, ...] = Field(
        min_length=1, max_length=640_000
    )
    protocol_freeze_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    execution_policy_freeze_manifest_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    randomization_manifest_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    hypothesis_count: StrictInt = Field(ge=1, le=10_000)
    model_count: StrictInt = Field(ge=1, le=64)
    hypothesis_model_coordinate_count: StrictInt = Field(ge=1, le=640_000)
    global_multiplicity_family_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_seed_domain_sha256: str = Field(pattern=_SHA256_PATTERN)
    arm_design: Literal["equal_probability_four_arm_complete_block_v1"]
    hypothesis_model_support_rule: Literal["complete_global_cartesian_product_v1"]
    execution_policy_rule: Literal["one_execution_freeze_per_hypothesis_common_models_v1"]
    analysis_seed_rule: Literal["domain_separated_from_generation_and_randomization_v1"]
    common_execution_policy_across_hypotheses: Literal[True]
    outcome_blind: Literal[True]
    frozen_before_generation: Literal[True]
    frozen_before_outcomes: Literal[True]
    downstream_records_excluded: Literal[
        "generation_runtime_measurement_outcome_effect_robustness_result"
    ]

    @classmethod
    def from_components(
        cls,
        *,
        candidate_universe: CandidateUniverseManifest,
        selection_freeze: SelectionFreezeManifest,
        protocol_roots: tuple[ProtocolFreezeRootV2, ...],
        execution_policy_freezes: tuple[ExecutionPolicyFreezeManifestV2, ...],
        global_multiplicity_family_policy_sha256: str,
        analysis_seed_domain_sha256: str,
    ) -> Self:
        try:
            universe = CandidateUniverseManifest.model_validate(candidate_universe, strict=True)
            selection = SelectionFreezeManifest.model_validate(selection_freeze, strict=True)
            roots = tuple(
                sorted(
                    (
                        ProtocolFreezeRootV2.model_validate(item, strict=True)
                        for item in protocol_roots
                    ),
                    key=_hypothesis_id,
                )
            )
            executions = tuple(
                sorted(
                    (
                        ExecutionPolicyFreezeManifestV2.model_validate(item, strict=True)
                        for item in execution_policy_freezes
                    ),
                    key=_execution_hypothesis_id,
                )
            )
            execution_by_hypothesis = {_execution_hypothesis_id(item): item for item in executions}
            hypothesis_ids = tuple(_hypothesis_id(item) for item in roots)
            model_ids = roots[0].intervention_bridge.frozen_hypothesis.model_scope
            coordinates = tuple(
                ConfirmatoryHypothesisModelCoordinateV2.from_binding(
                    protocol_root=root,
                    execution_freeze=execution_by_hypothesis[_hypothesis_id(root)],
                    model_id=model_id,
                )
                for root in roots
                for model_id in model_ids
            )
            return cls.from_content(
                candidate_universe=universe,
                selection_freeze=selection,
                protocol_roots=roots,
                execution_policy_freezes=executions,
                hypothesis_ids=hypothesis_ids,
                model_ids=model_ids,
                hypothesis_model_coordinates=coordinates,
                protocol_freeze_ids=tuple(item.protocol_freeze_id for item in roots),
                execution_policy_freeze_manifest_ids=tuple(
                    item.execution_policy_freeze_manifest_id for item in executions
                ),
                randomization_manifest_ids=tuple(
                    item.randomization.randomization_manifest_id for item in executions
                ),
                hypothesis_count=len(hypothesis_ids),
                model_count=len(model_ids),
                hypothesis_model_coordinate_count=len(coordinates),
                global_multiplicity_family_policy_sha256=(global_multiplicity_family_policy_sha256),
                analysis_seed_domain_sha256=analysis_seed_domain_sha256,
                arm_design="equal_probability_four_arm_complete_block_v1",
                hypothesis_model_support_rule="complete_global_cartesian_product_v1",
                execution_policy_rule=("one_execution_freeze_per_hypothesis_common_models_v1"),
                analysis_seed_rule=("domain_separated_from_generation_and_randomization_v1"),
                common_execution_policy_across_hypotheses=True,
                outcome_blind=True,
                frozen_before_generation=True,
                frozen_before_outcomes=True,
                downstream_records_excluded=(
                    "generation_runtime_measurement_outcome_effect_robustness_result"
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @property
    def semantic_sha256(self) -> str:
        return self.confirmatory_experiment_freeze_id.removeprefix(
            "confirmatory_experiment_freeze_v2_"
        )

    @model_validator(mode="after")
    def validate_experiment_freeze(self) -> Self:
        roots = self.protocol_roots
        executions = self.execution_policy_freezes
        root_by_hypothesis = {_hypothesis_id(item): item for item in roots}
        execution_by_hypothesis = {_execution_hypothesis_id(item): item for item in executions}
        protocolized_mappings = tuple(
            item
            for item in self.selection_freeze.mappings
            if item.status is BridgeStatus.PROTOCOLIZED
        )
        expected_hypothesis_ids = tuple(
            sorted(
                {
                    item.final_hypothesis_id
                    for item in protocolized_mappings
                    if item.final_hypothesis_id is not None
                }
            )
        )

        if (
            self.selection_freeze.candidate_universe_id
            != self.candidate_universe.candidate_universe_id
            or tuple(_hypothesis_id(item) for item in roots) != self.hypothesis_ids
            or self.hypothesis_ids != expected_hypothesis_ids
            or len(root_by_hypothesis) != len(roots)
            or tuple(_execution_hypothesis_id(item) for item in executions) != self.hypothesis_ids
            or len(execution_by_hypothesis) != len(executions)
            or self.hypothesis_count != len(self.hypothesis_ids)
            or self.model_ids != tuple(sorted(self.model_ids))
            or len(self.model_ids) != len(set(self.model_ids))
            or any(not is_valid_model_id(item) for item in self.model_ids)
            or self.model_count != len(self.model_ids)
            or self.protocol_freeze_ids != tuple(item.protocol_freeze_id for item in roots)
            or self.execution_policy_freeze_manifest_ids
            != tuple(item.execution_policy_freeze_manifest_id for item in executions)
            or self.randomization_manifest_ids
            != tuple(item.randomization.randomization_manifest_id for item in executions)
        ):
            raise ValueError(self._safe_validation_message)

        for mapping in protocolized_mappings:
            if mapping.final_hypothesis_id is None:
                raise ValueError(self._safe_validation_message)
            root = root_by_hypothesis.get(mapping.final_hypothesis_id)
            if (
                root is None
                or mapping.candidate_skeleton_id
                != root.intervention_bridge.candidate_skeleton.candidate_skeleton_id
                or mapping.bridge_record_sha256
                != root.intervention_bridge.intervention_bridge_id.removeprefix(
                    "intervention_bridge_"
                )
            ):
                raise ValueError(self._safe_validation_message)

        first_execution = executions[0]
        for hypothesis_id, root in root_by_hypothesis.items():
            execution = execution_by_hypothesis[hypothesis_id]
            hypothesis = root.intervention_bridge.frozen_hypothesis
            randomization = execution.randomization
            if (
                root.candidate_universe != self.candidate_universe
                or root.selection_freeze != self.selection_freeze
                or hypothesis.model_scope != self.model_ids
                or randomization.population != root.population
                or tuple(item.model_id for item in execution.model_policies) != self.model_ids
                or execution.model_policies != first_execution.model_policies
                or execution.measurement_policy != first_execution.measurement_policy
                or execution.execution_environment_sha256
                != first_execution.execution_environment_sha256
                or {item.model_id for item in randomization.blocks} != set(self.model_ids)
                or not _protocol_is_equal_probability_four_arm(root)
                or not _randomization_has_exact_four_arm_blocks(root, execution)
            ):
                raise ValueError(self._safe_validation_message)

        expected_coordinates = tuple(
            ConfirmatoryHypothesisModelCoordinateV2.from_binding(
                protocol_root=root_by_hypothesis[hypothesis_id],
                execution_freeze=execution_by_hypothesis[hypothesis_id],
                model_id=model_id,
            )
            for hypothesis_id in self.hypothesis_ids
            for model_id in self.model_ids
        )
        if (
            self.hypothesis_model_coordinates != expected_coordinates
            or len(
                {(item.hypothesis_id, item.model_id) for item in self.hypothesis_model_coordinates}
            )
            != len(expected_coordinates)
            or self.hypothesis_model_coordinate_count != len(expected_coordinates)
            or self.hypothesis_model_coordinate_count != self.hypothesis_count * self.model_count
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "EXPERIMENT_FREEZE_V2_SCHEMA_VERSION",
    "ConfirmatoryExperimentFreezeV2",
    "ConfirmatoryHypothesisModelCoordinateV2",
]

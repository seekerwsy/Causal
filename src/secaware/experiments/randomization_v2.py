"""Complete-block randomization and exact assignment/outcome coverage for v2.

The implementation derives every feasible block from the frozen common-support
population.  One request-randomness slot is one assignment unit, arms are exactly
balanced within every block, and provider seeds remain nullable provenance rather
than being reinterpreted as request slots.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, ClassVar, Literal, NoReturn, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel, is_valid_model_id
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.outcomes_v2 import AssignmentOutcomeRecordV2
from secaware.schema.policy_v2 import (
    ConfirmationBlockKeyV2,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)
from secaware.schema.population_v2 import PopulationFreezeManifestV2
from secaware.schema.runtime_v2 import ConfirmationAssignmentRecordV2

RANDOMIZATION_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_ASSIGNMENT_ID_PATTERN = r"^assignment_[0-9a-f]{64}$"
_RANDOMIZATION_ID_PATTERN = r"^randomization_manifest_v2_[0-9a-f]{64}$"
_COVERAGE_ID_PATTERN = r"^assignment_coverage_v2_[0-9a-f]{64}$"

_ADD_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_REMOVE_ARMS = (
    ArmRole.TARGET_REMOVE,
    ArmRole.NOOP_RETAIN,
    ArmRole.LENGTH_MATCHED_SHAM_EDIT,
    ArmRole.GENERIC_SECURITY_REPLACEMENT,
)


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _digest(value: object) -> str:
    payload = json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _snapshot_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_arrays(item) for item in value)
    return value


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _raise_contract_error(model_type: type[SafeValidationMixin]) -> NoReturn:
    raise model_type._safe_error()


def _exact_arm(value: object) -> object:
    if type(value) is ArmRole:
        return value
    if type(value) is str:
        return next((item for item in ArmRole if item.value == value), value)
    return value


def _arm_roles(operation: FeatureOperation) -> tuple[ArmRole, ...]:
    return _ADD_ARMS if operation is FeatureOperation.ADD else _REMOVE_ARMS


class _RandomizationV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "randomization v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def snapshot_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedRandomizationV2(_RandomizationV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": RANDOMIZATION_V2_SCHEMA_VERSION, **content}
            record_id = cls._id_prefix + _digest(payload)
            return cls(**payload, **{cls._id_field: record_id})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class ModelGenerationParametersV2(_RandomizationV2Contract):
    model_id: str
    generation_parameters_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_model(self) -> Self:
        if not is_valid_model_id(self.model_id):
            raise ValueError(self._safe_validation_message)
        return self


class AssignmentUnitKeyV2(_ContentAddressedRandomizationV2):
    """One randomized arm assignment for one request slot in a canonical block."""

    _id_field: ClassVar[str] = "assignment_id"
    _id_prefix: ClassVar[str] = "assignment_"

    schema_version: Literal["2.0"]
    assignment_id: str = Field(pattern=_ASSIGNMENT_ID_PATTERN)
    block: ConfirmationBlockKeyV2
    request_randomness_slot: StrictInt = Field(ge=0, le=2_147_483_647)
    provider_seed: StrictInt | None = Field(default=None, ge=0, le=2**63 - 1)
    assigned_arm: ArmRole
    variant_id: str
    generation_parameters_sha256: str = Field(pattern=_SHA256_PATTERN)
    rng_draw_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("assigned_arm", mode="before")
    @classmethod
    def parse_arm(cls, value: object) -> object:
        return _exact_arm(value)

    @model_validator(mode="after")
    def validate_assignment(self) -> Self:
        if not _valid_identifier(self.variant_id):
            raise ValueError(self._safe_validation_message)
        return self


def _expected_blocks(population: PopulationFreezeManifestV2) -> tuple[ConfirmationBlockKeyV2, ...]:
    hypothesis = population.hypothesis
    blocks: list[ConfirmationBlockKeyV2] = []
    for gate in population.task_gates:
        if not gate.gate_passed:
            continue
        support = gate.task_policy_support
        if support is None:  # defensive: the population schema already forbids this state
            raise ValueError("passed population gate lacks policy support")
        bundles = {item.realization_spec_id: item for item in support.task_realization_bundles}
        if tuple(bundles) != hypothesis.realization_spec_ids:
            raise ValueError("task policy support changed realization order")
        for realization_spec_id in hypothesis.realization_spec_ids:
            bundle = bundles[realization_spec_id]
            for model_id in population.common_model_scope:
                blocks.append(
                    ConfirmationBlockKeyV2.from_coordinates(
                        semantic_task_cluster_id=gate.semantic_task_cluster_id,
                        task_instance_id=gate.task_instance_id,
                        hypothesis_id=hypothesis.hypothesis_id,
                        target_spec_id=hypothesis.target_spec_id,
                        realization_spec_id=realization_spec_id,
                        task_realization_bundle_id=bundle.task_realization_bundle_id,
                        model_id=model_id,
                        arm_protocol_id=hypothesis.arm_protocol_id,
                    )
                )
    ordered = tuple(sorted(blocks, key=lambda item: item.block_id))
    if len(ordered) != len({item.block_id for item in ordered}):
        raise ValueError("duplicate canonical confirmation block")
    return ordered


def _support_by_task(
    population: PopulationFreezeManifestV2,
) -> dict[str, TaskPolicySupportRecord]:
    result: dict[str, TaskPolicySupportRecord] = {}
    for gate in population.task_gates:
        if gate.gate_passed:
            if gate.task_policy_support is None:
                raise ValueError("passed population gate lacks policy support")
            result[gate.task_instance_id] = gate.task_policy_support
    return result


def _bundle_by_id(
    population: PopulationFreezeManifestV2,
) -> dict[str, TaskRealizationBundleRecord]:
    return {
        bundle.task_realization_bundle_id: bundle
        for support in _support_by_task(population).values()
        for bundle in support.task_realization_bundles
    }


def _balanced_arm_by_slot(
    *,
    block_id: str,
    request_slots: tuple[int, ...],
    roles: tuple[ArmRole, ...],
    randomization_seed: int,
) -> dict[int, ArmRole]:
    repetitions = len(request_slots) // len(roles)
    tokens = tuple((role, repetition) for role in roles for repetition in range(repetitions))
    randomized = tuple(
        sorted(
            tokens,
            key=lambda item: _digest(
                {
                    "domain": "balanced-arm-permutation-v2",
                    "randomization_seed": randomization_seed,
                    "block_id": block_id,
                    "arm_role": item[0].value,
                    "repetition": item[1],
                }
            ),
        )
    )
    return {slot: token[0] for slot, token in zip(request_slots, randomized, strict=True)}


def _rng_draw(*, block_id: str, slot: int, arm_role: ArmRole, randomization_seed: int) -> str:
    return _digest(
        {
            "rng_algorithm": "sha256_balanced_permutation_v1",
            "randomization_seed": randomization_seed,
            "block_id": block_id,
            "request_randomness_slot": slot,
            "assigned_arm": arm_role.value,
        }
    )


def _execution_order(
    assignments: Sequence[AssignmentUnitKeyV2], randomization_seed: int
) -> tuple[str, ...]:
    return tuple(
        item.assignment_id
        for item in sorted(
            assignments,
            key=lambda item: (
                _digest(
                    {
                        "domain": "randomized-execution-order-v2",
                        "randomization_seed": randomization_seed,
                        "assignment_id": item.assignment_id,
                    }
                ),
                item.assignment_id,
            ),
        )
    )


class RandomizationManifestV2(_ContentAddressedRandomizationV2):
    """The exact balanced assignment universe derived from one frozen population."""

    _id_field: ClassVar[str] = "randomization_manifest_id"
    _id_prefix: ClassVar[str] = "randomization_manifest_v2_"

    schema_version: Literal["2.0"]
    randomization_manifest_id: str = Field(pattern=_RANDOMIZATION_ID_PATTERN)
    population: PopulationFreezeManifestV2
    blocks: tuple[ConfirmationBlockKeyV2, ...] = Field(min_length=1)
    request_randomness_slots: tuple[StrictInt, ...] = Field(min_length=4)
    model_generation_parameters: tuple[ModelGenerationParametersV2, ...] = Field(min_length=1)
    assignments: tuple[AssignmentUnitKeyV2, ...] = Field(min_length=4)
    execution_order_assignment_ids: tuple[str, ...] = Field(min_length=4)
    randomization_seed: StrictInt = Field(ge=0, le=2**63 - 1)
    rng_algorithm: Literal["sha256_balanced_permutation_v1"]
    balance_rule: Literal["exact_equal_arm_counts_within_every_complete_block"]
    provider_seed_policy: Literal["nullable_independent_provenance_not_request_slot"]
    execution_order_policy: Literal["sha256_seeded_global_permutation_v1"]
    bounded_concurrency: StrictInt = Field(ge=1, le=10_000)
    block_count: StrictInt = Field(ge=1)
    assignment_count: StrictInt = Field(ge=4)
    frozen_before_generation: Literal[True]

    @classmethod
    def from_population(
        cls,
        *,
        population: PopulationFreezeManifestV2,
        request_randomness_slots: Sequence[int],
        model_generation_parameters: Sequence[ModelGenerationParametersV2],
        randomization_seed: int,
        bounded_concurrency: int,
        provider_seed_by_block_slot: Mapping[tuple[str, int], int | None] | None = None,
    ) -> Self:
        try:
            checked_population = PopulationFreezeManifestV2.model_validate(population, strict=True)
            slots = tuple(request_randomness_slots)
            if (
                tuple(sorted(slots)) != slots
                or len(slots) != len(set(slots))
                or len(slots) < 4
                or len(slots) % 4 != 0
                or any(type(item) is not int or item < 0 or item > 2_147_483_647 for item in slots)
            ):
                raise ValueError
            parameters = tuple(
                sorted(
                    (
                        ModelGenerationParametersV2.model_validate(item, strict=True)
                        for item in model_generation_parameters
                    ),
                    key=lambda item: item.model_id,
                )
            )
            parameter_by_model = {
                item.model_id: item.generation_parameters_sha256 for item in parameters
            }
            if tuple(parameter_by_model) != checked_population.common_model_scope:
                raise ValueError
            blocks = _expected_blocks(checked_population)
            expected_provider_keys = {(block.block_id, slot) for block in blocks for slot in slots}
            if provider_seed_by_block_slot is None:
                provider_seeds = {key: None for key in expected_provider_keys}
            else:
                provider_seeds = dict(provider_seed_by_block_slot)
                if set(provider_seeds) != expected_provider_keys:
                    raise ValueError

            bundles = _bundle_by_id(checked_population)
            roles = _arm_roles(checked_population.hypothesis.operation)
            assignments: list[AssignmentUnitKeyV2] = []
            for block in blocks:
                bundle = bundles[block.task_realization_bundle_id]
                variant_by_arm = {item.arm_role: item.variant_id for item in bundle.arms}
                arm_by_slot = _balanced_arm_by_slot(
                    block_id=block.block_id,
                    request_slots=slots,
                    roles=roles,
                    randomization_seed=randomization_seed,
                )
                for slot in slots:
                    arm_role = arm_by_slot[slot]
                    assignments.append(
                        AssignmentUnitKeyV2.from_content(
                            block=block,
                            request_randomness_slot=slot,
                            provider_seed=provider_seeds[(block.block_id, slot)],
                            assigned_arm=arm_role,
                            variant_id=variant_by_arm[arm_role],
                            generation_parameters_sha256=parameter_by_model[block.model_id],
                            rng_draw_sha256=_rng_draw(
                                block_id=block.block_id,
                                slot=slot,
                                arm_role=arm_role,
                                randomization_seed=randomization_seed,
                            ),
                        )
                    )
            ordered_assignments = tuple(
                sorted(
                    assignments,
                    key=lambda item: (item.block.block_id, item.request_randomness_slot),
                )
            )
            return cls.from_content(
                population=checked_population,
                blocks=blocks,
                request_randomness_slots=slots,
                model_generation_parameters=parameters,
                assignments=ordered_assignments,
                execution_order_assignment_ids=_execution_order(
                    ordered_assignments, randomization_seed
                ),
                randomization_seed=randomization_seed,
                rng_algorithm="sha256_balanced_permutation_v1",
                balance_rule="exact_equal_arm_counts_within_every_complete_block",
                provider_seed_policy="nullable_independent_provenance_not_request_slot",
                execution_order_policy="sha256_seeded_global_permutation_v1",
                bounded_concurrency=bounded_concurrency,
                block_count=len(blocks),
                assignment_count=len(ordered_assignments),
                frozen_before_generation=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @property
    def semantic_sha256(self) -> str:
        return self.randomization_manifest_id.removeprefix("randomization_manifest_v2_")

    @model_validator(mode="after")
    def validate_randomization_closure(self) -> Self:
        slots = self.request_randomness_slots
        parameters = {
            item.model_id: item.generation_parameters_sha256
            for item in self.model_generation_parameters
        }
        expected_blocks = _expected_blocks(self.population)
        bundles = _bundle_by_id(self.population)
        expected_roles = _arm_roles(self.population.hypothesis.operation)
        assignment_keys = tuple(
            (item.block.block_id, item.request_randomness_slot) for item in self.assignments
        )
        expected_assignment_keys = tuple(
            (block.block_id, slot) for block in expected_blocks for slot in slots
        )
        if (
            tuple(sorted(slots)) != slots
            or len(slots) != len(set(slots))
            or len(slots) % len(expected_roles) != 0
            or tuple(item.model_id for item in self.model_generation_parameters)
            != self.population.common_model_scope
            or len(parameters) != len(self.model_generation_parameters)
            or self.blocks != expected_blocks
            or self.block_count != len(expected_blocks)
            or assignment_keys != expected_assignment_keys
            or len({item.assignment_id for item in self.assignments}) != len(self.assignments)
            or self.assignment_count != len(self.assignments)
            or self.execution_order_assignment_ids
            != _execution_order(self.assignments, self.randomization_seed)
            or set(self.execution_order_assignment_ids)
            != {item.assignment_id for item in self.assignments}
        ):
            raise ValueError(self._safe_validation_message)

        arm_counts_by_block: dict[str, Counter[ArmRole]] = {}
        for assignment in self.assignments:
            block = assignment.block
            bundle = bundles.get(block.task_realization_bundle_id)
            if bundle is None:
                raise ValueError(self._safe_validation_message)
            variant_by_arm = {item.arm_role: item.variant_id for item in bundle.arms}
            expected_arm = _balanced_arm_by_slot(
                block_id=block.block_id,
                request_slots=slots,
                roles=expected_roles,
                randomization_seed=self.randomization_seed,
            )[assignment.request_randomness_slot]
            if (
                assignment.assigned_arm is not expected_arm
                or assignment.variant_id != variant_by_arm.get(expected_arm)
                or assignment.generation_parameters_sha256 != parameters.get(block.model_id)
                or assignment.rng_draw_sha256
                != _rng_draw(
                    block_id=block.block_id,
                    slot=assignment.request_randomness_slot,
                    arm_role=expected_arm,
                    randomization_seed=self.randomization_seed,
                )
            ):
                raise ValueError(self._safe_validation_message)
            arm_counts_by_block.setdefault(block.block_id, Counter())[assignment.assigned_arm] += 1

        expected_count = len(slots) // len(expected_roles)
        if any(
            counts != Counter({arm: expected_count for arm in expected_roles})
            for counts in arm_counts_by_block.values()
        ):
            raise ValueError(self._safe_validation_message)
        return self


class AssignmentCoverageManifestV2(_ContentAddressedRandomizationV2):
    """Exact one-to-one closure over randomized, committed, and outcome assignments."""

    _id_field: ClassVar[str] = "assignment_coverage_manifest_id"
    _id_prefix: ClassVar[str] = "assignment_coverage_v2_"

    schema_version: Literal["2.0"]
    assignment_coverage_manifest_id: str = Field(pattern=_COVERAGE_ID_PATTERN)
    randomization: RandomizationManifestV2
    committed_assignments: tuple[ConfirmationAssignmentRecordV2, ...] = Field(min_length=1)
    outcomes: tuple[AssignmentOutcomeRecordV2, ...] = Field(min_length=1)
    expected_assignment_ids: tuple[str, ...] = Field(min_length=1)
    committed_assignment_ids: tuple[str, ...] = Field(min_length=1)
    outcome_assignment_ids: tuple[str, ...] = Field(min_length=1)
    expected_count: StrictInt = Field(ge=1)
    committed_count: StrictInt = Field(ge=1)
    outcome_count: StrictInt = Field(ge=1)
    coverage_rule: Literal["exact_no_missing_extra_or_duplicate_assignments"]
    complete: Literal[True]

    @classmethod
    def from_components(
        cls,
        *,
        randomization: RandomizationManifestV2,
        committed_assignments: Sequence[ConfirmationAssignmentRecordV2],
        outcomes: Sequence[AssignmentOutcomeRecordV2],
    ) -> Self:
        try:
            checked_randomization = RandomizationManifestV2.model_validate(
                randomization, strict=True
            )
            committed = tuple(
                sorted(
                    (
                        ConfirmationAssignmentRecordV2.model_validate(item, strict=True)
                        for item in committed_assignments
                    ),
                    key=lambda item: item.assignment_id or "",
                )
            )
            checked_outcomes = tuple(
                sorted(
                    (
                        AssignmentOutcomeRecordV2.model_validate(item, strict=True)
                        for item in outcomes
                    ),
                    key=lambda item: item.assignment_id,
                )
            )
            expected_ids = tuple(
                sorted(item.assignment_id for item in checked_randomization.assignments)
            )
            committed_ids = tuple(item.assignment_id for item in committed)
            outcome_ids = tuple(item.assignment_id for item in checked_outcomes)
            return cls.from_content(
                randomization=checked_randomization,
                committed_assignments=committed,
                outcomes=checked_outcomes,
                expected_assignment_ids=expected_ids,
                committed_assignment_ids=committed_ids,
                outcome_assignment_ids=outcome_ids,
                expected_count=len(expected_ids),
                committed_count=len(committed_ids),
                outcome_count=len(outcome_ids),
                coverage_rule="exact_no_missing_extra_or_duplicate_assignments",
                complete=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @property
    def semantic_sha256(self) -> str:
        return self.assignment_coverage_manifest_id.removeprefix("assignment_coverage_v2_")

    @model_validator(mode="after")
    def validate_exact_coverage(self) -> Self:
        units = {item.assignment_id: item for item in self.randomization.assignments}
        committed = {
            item.assignment_id: item
            for item in self.committed_assignments
            if item.assignment_id is not None
        }
        outcomes = {item.assignment_id: item for item in self.outcomes}
        expected_ids = tuple(sorted(units))
        committed_ids = tuple(item.assignment_id for item in self.committed_assignments)
        outcome_ids = tuple(item.assignment_id for item in self.outcomes)
        if (
            len(committed) != len(self.committed_assignments)
            or len(outcomes) != len(self.outcomes)
            or expected_ids != committed_ids
            or expected_ids != outcome_ids
            or self.expected_assignment_ids != expected_ids
            or self.committed_assignment_ids != committed_ids
            or self.outcome_assignment_ids != outcome_ids
            or self.expected_count != len(expected_ids)
            or self.committed_count != len(committed_ids)
            or self.outcome_count != len(outcome_ids)
        ):
            raise ValueError(self._safe_validation_message)

        for assignment_id, unit in units.items():
            block = unit.block
            committed_record = committed[assignment_id]
            outcome = outcomes[assignment_id]
            expected_coordinates = (
                block.semantic_task_cluster_id,
                block.task_instance_id,
                block.hypothesis_id,
                block.target_spec_id,
                block.realization_spec_id,
                block.task_realization_bundle_id,
                block.model_id,
                block.arm_protocol_id,
                block.block_id,
                unit.variant_id,
                unit.request_randomness_slot,
                unit.provider_seed,
                unit.assigned_arm,
            )
            committed_coordinates = (
                committed_record.semantic_task_cluster_id,
                committed_record.task_instance_id,
                committed_record.hypothesis_id,
                committed_record.target_spec_id,
                committed_record.realization_spec_id,
                committed_record.task_realization_bundle_id,
                committed_record.model_id,
                committed_record.arm_protocol_id,
                committed_record.block_id,
                committed_record.variant_id,
                committed_record.request_randomness_slot,
                committed_record.provider_seed,
                committed_record.assigned_arm,
            )
            outcome_coordinates = (
                outcome.semantic_task_cluster_id,
                outcome.task_instance_id,
                outcome.hypothesis_id,
                outcome.target_spec_id,
                outcome.realization_spec_id,
                outcome.task_realization_bundle_id,
                outcome.model_id,
                outcome.arm_protocol_id,
                outcome.block_id,
                outcome.variant_id,
                outcome.request_randomness_slot,
                outcome.provider_seed,
                outcome.arm_role,
            )
            if (
                committed_record.randomization_manifest_sha256 != self.randomization.semantic_sha256
                or committed_coordinates != expected_coordinates
                or outcome_coordinates != expected_coordinates
            ):
                raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "AssignmentCoverageManifestV2",
    "AssignmentUnitKeyV2",
    "ModelGenerationParametersV2",
    "RandomizationManifestV2",
]

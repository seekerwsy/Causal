"""Pre-generation execution freeze and provenance-closed confirmation receipts.

The randomization manifest decides *which* assignment is run.  This module closes
the next boundary: the exact model endpoint/template/generation policy is frozen
before submission, every request is joined to its randomized unit, and an outcome
can enter confirmatory coverage only through the complete runtime producer chain.

The legacy ``AssignmentCoverageManifestV2`` remains a useful low-level structural
contract.  ``ProvenanceClosedAssignmentCoverageManifestV2`` is the formal boundary:
callers cannot provide standalone outcome rows or opaque source digests.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar, Literal, Self

from pydantic import Field, StrictInt, model_validator

from secaware.experiments.randomization_v2 import (
    AssignmentCoverageManifestV2,
    AssignmentUnitKeyV2,
    RandomizationManifestV2,
)
from secaware.outcomes.assembler_v2 import assemble_assignment_outcome_v2
from secaware.records import (
    SnapshotContentAddressedResearchRecord,
    SnapshotResearchRecord,
    raise_record_validation_error as _raise_contract_error,
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.outcomes_v2 import AssignmentOutcomeRecordV2, AssignmentOutcomeStateV2
from secaware.schema.policy_v2 import TaskRealizationBundleRecord
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
    RuntimeProducerChainRecordV2,
    validate_runtime_producer_chain_v2,
)

EXECUTION_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_EXECUTION_FREEZE_ID_PATTERN = r"^execution_policy_freeze_v2_[0-9a-f]{64}$"
_EXECUTION_RECEIPT_ID_PATTERN = r"^assignment_execution_receipt_v2_[0-9a-f]{64}$"
_SYNTAX_RECEIPT_ID_PATTERN = r"^syntax_validation_receipt_v2_[0-9a-f]{64}$"
_OUTCOME_RECEIPT_ID_PATTERN = r"^outcome_assembly_receipt_v2_[0-9a-f]{64}$"
_CLOSED_COVERAGE_ID_PATTERN = r"^provenance_closed_coverage_v2_[0-9a-f]{64}$"
_FAILURE_RECEIPT_ID_PATTERN = r"^infrastructure_failure_receipt_v2_[0-9a-f]{64}$"
_TOTAL_ACCOUNTING_ID_PATTERN = r"^total_assignment_accounting_v2_[0-9a-f]{64}$"


class _ExecutionV2Contract(SnapshotResearchRecord):
    _safe_validation_message: ClassVar[str] = "execution v2 contract failed validation"


class _ContentAddressedExecutionV2(SnapshotContentAddressedResearchRecord):
    _safe_validation_message: ClassVar[str] = "execution v2 contract failed validation"
    _schema_version = EXECUTION_V2_SCHEMA_VERSION


class ModelExecutionPolicyV2(_ExecutionV2Contract):
    """All request-policy fields fixed for one model before generation."""

    model_id: str
    language: str
    endpoint_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_parameters_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_template_sha256: str = Field(pattern=_SHA256_PATTERN)
    generator_producer_id: str
    generator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if (
            not is_valid_model_id(self.model_id)
            or not _valid_identifier(self.language)
            or not _valid_identifier(self.generator_producer_id)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class MeasurementExecutionPolicyV2(_ExecutionV2Contract):
    """Independent parser, security-Oracle, and functional policies frozen up front."""

    parser_producer_id: str
    parser_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    oracle_producer_id: str
    oracle_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    functional_evaluator_producer_id: str
    functional_evaluator_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_measurement_policy(self) -> Self:
        if not all(
            _valid_identifier(item)
            for item in (
                self.parser_producer_id,
                self.oracle_producer_id,
                self.functional_evaluator_producer_id,
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ExecutionPolicyFreezeManifestV2(_ContentAddressedExecutionV2):
    """A randomization-bound, pre-generation execution-policy root."""

    _id_field: ClassVar[str] = "execution_policy_freeze_manifest_id"
    _id_prefix: ClassVar[str] = "execution_policy_freeze_v2_"

    schema_version: Literal["2.0"]
    execution_policy_freeze_manifest_id: str = Field(pattern=_EXECUTION_FREEZE_ID_PATTERN)
    randomization: RandomizationManifestV2
    model_policies: tuple[ModelExecutionPolicyV2, ...] = Field(min_length=1)
    measurement_policy: MeasurementExecutionPolicyV2
    execution_environment_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_binding_rule: Literal["assignment_unit_and_frozen_model_policy_exact_match_v1"]
    frozen_before_generation: Literal[True]

    @classmethod
    def from_randomization(
        cls,
        *,
        randomization: RandomizationManifestV2,
        model_policies: Sequence[ModelExecutionPolicyV2],
        measurement_policy: MeasurementExecutionPolicyV2,
        execution_environment_sha256: str,
    ) -> Self:
        try:
            checked_randomization = RandomizationManifestV2.model_validate(
                randomization, strict=True
            )
            policies = tuple(
                sorted(
                    (
                        ModelExecutionPolicyV2.model_validate(item, strict=True)
                        for item in model_policies
                    ),
                    key=lambda item: item.model_id,
                )
            )
            return cls.from_content(
                randomization=checked_randomization,
                model_policies=policies,
                measurement_policy=MeasurementExecutionPolicyV2.model_validate(
                    measurement_policy, strict=True
                ),
                execution_environment_sha256=execution_environment_sha256,
                request_binding_rule="assignment_unit_and_frozen_model_policy_exact_match_v1",
                frozen_before_generation=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_freeze(self) -> Self:
        policy_ids = tuple(item.model_id for item in self.model_policies)
        expected_ids = self.randomization.population.common_model_scope
        parameter_by_model = {
            item.model_id: item.generation_parameters_sha256
            for item in self.randomization.model_generation_parameters
        }
        if (
            policy_ids != expected_ids
            or len(policy_ids) != len(set(policy_ids))
            or any(
                item.generation_parameters_sha256 != parameter_by_model.get(item.model_id)
                for item in self.model_policies
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _expected_unit_coordinates(unit: AssignmentUnitKeyV2) -> tuple[object, ...]:
    block = unit.block
    return (
        "randomized_confirmation",
        block.semantic_task_cluster_id,
        block.task_instance_id,
        block.model_id,
        unit.request_randomness_slot,
        unit.provider_seed,
        unit.assignment_id,
        block.hypothesis_id,
        block.target_spec_id,
        block.realization_spec_id,
        block.task_realization_bundle_id,
        unit.variant_id,
        block.arm_protocol_id,
        block.block_id,
        unit.assigned_arm,
    )


def _bundle_by_id(randomization: RandomizationManifestV2) -> dict[str, TaskRealizationBundleRecord]:
    return {
        bundle.task_realization_bundle_id: bundle
        for gate in randomization.population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
    }


class AssignmentExecutionReceiptV2(_ContentAddressedExecutionV2):
    """Exact assignment-unit to submitted-request binding."""

    _id_field: ClassVar[str] = "assignment_execution_receipt_id"
    _id_prefix: ClassVar[str] = "assignment_execution_receipt_v2_"

    schema_version: Literal["2.0"]
    assignment_execution_receipt_id: str = Field(pattern=_EXECUTION_RECEIPT_ID_PATTERN)
    execution_policy_freeze: ExecutionPolicyFreezeManifestV2
    assignment_unit: AssignmentUnitKeyV2
    committed_assignment: ConfirmationAssignmentRecordV2
    task_realization_bundle: TaskRealizationBundleRecord
    generation_request: GenerationRequestRecordV2
    exact_request_policy_joined: Literal[True]

    @classmethod
    def from_request(
        cls,
        *,
        execution_policy_freeze: ExecutionPolicyFreezeManifestV2,
        assignment_unit: AssignmentUnitKeyV2,
        committed_assignment: ConfirmationAssignmentRecordV2,
        task_realization_bundle: TaskRealizationBundleRecord,
        generation_request: GenerationRequestRecordV2,
    ) -> Self:
        return cls.from_content(
            execution_policy_freeze=execution_policy_freeze,
            assignment_unit=assignment_unit,
            committed_assignment=committed_assignment,
            task_realization_bundle=task_realization_bundle,
            generation_request=generation_request,
            exact_request_policy_joined=True,
        )

    @model_validator(mode="after")
    def validate_execution_receipt(self) -> Self:
        freeze = self.execution_policy_freeze
        randomization = freeze.randomization
        expected_units = {item.assignment_id: item for item in randomization.assignments}
        expected_bundles = _bundle_by_id(randomization)
        policy_by_model = {item.model_id: item for item in freeze.model_policies}
        unit = self.assignment_unit
        assigned = self.committed_assignment
        request = self.generation_request
        bundle = self.task_realization_bundle
        policy = policy_by_model.get(unit.block.model_id)
        variants = tuple(item for item in bundle.arms if item.arm_role is unit.assigned_arm)
        if len(variants) != 1:
            raise ValueError(self._safe_validation_message)
        variant = variants[0]
        if (
            expected_units.get(unit.assignment_id) != unit
            or expected_bundles.get(bundle.task_realization_bundle_id) != bundle
            or assigned.exact_coordinates() != _expected_unit_coordinates(unit)
            or request.exact_coordinates() != assigned.exact_coordinates()
            or assigned.randomization_manifest_sha256 != randomization.semantic_sha256
            or bundle.task_realization_bundle_id != unit.block.task_realization_bundle_id
            or bundle.hypothesis_id != unit.block.hypothesis_id
            or bundle.semantic_task_cluster_id != unit.block.semantic_task_cluster_id
            or bundle.task_instance_id != unit.block.task_instance_id
            or bundle.realization_spec_id != unit.block.realization_spec_id
            or variant.variant_id != unit.variant_id
            or variant.variant_prompt_id != request.prompt_id
            or variant.prompt_sha256 != request.prompt_sha256
            or variant.prompt_text != request.prompt
            or policy is None
            or request.language != policy.language
            or request.endpoint_sha256 != policy.endpoint_sha256
            or request.generation_parameters_sha256 != unit.generation_parameters_sha256
            or request.generation_parameters_sha256 != policy.generation_parameters_sha256
            or request.system_template_sha256 != policy.system_template_sha256
            or request.generator_producer_id != policy.generator_producer_id
            or request.generator_policy_sha256 != policy.generator_policy_sha256
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SyntaxValidationReceiptV2(_ContentAddressedExecutionV2):
    """Independent syntax/compile evidence; Oracle status cannot impersonate it."""

    _id_field: ClassVar[str] = "syntax_validation_receipt_id"
    _id_prefix: ClassVar[str] = "syntax_validation_receipt_v2_"

    schema_version: Literal["2.0"]
    syntax_validation_receipt_id: str = Field(pattern=_SYNTAX_RECEIPT_ID_PATTERN)
    generated_code_id: str
    code_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    language: str
    status: Literal["valid", "invalid", "not_applicable_no_code"]
    parser_producer_id: str
    parser_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    parser_runtime_sha256: str = Field(pattern=_SHA256_PATTERN)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_generated_code(
        cls,
        *,
        generated_code: GeneratedCodeRecordV2,
        language: str,
        status: Literal["valid", "invalid", "not_applicable_no_code"],
        parser_producer_id: str,
        parser_policy_sha256: str,
        parser_runtime_sha256: str,
        evidence_sha256: str,
    ) -> Self:
        code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
        return cls.from_content(
            generated_code_id=code.generated_code_id,
            code_sha256=code.code_sha256,
            language=language,
            status=status,
            parser_producer_id=parser_producer_id,
            parser_policy_sha256=parser_policy_sha256,
            parser_runtime_sha256=parser_runtime_sha256,
            evidence_sha256=evidence_sha256,
        )

    @model_validator(mode="after")
    def validate_syntax_receipt(self) -> Self:
        if (
            not _valid_identifier(self.generated_code_id)
            or not _valid_identifier(self.language)
            or not _valid_identifier(self.parser_producer_id)
            or (self.status == "not_applicable_no_code") != (self.code_sha256 is None)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class OutcomeAssemblyReceiptV2(_ContentAddressedExecutionV2):
    """One replayable request→code→measurement→outcome proof."""

    _id_field: ClassVar[str] = "outcome_assembly_receipt_id"
    _id_prefix: ClassVar[str] = "outcome_assembly_receipt_v2_"

    schema_version: Literal["2.0"]
    outcome_assembly_receipt_id: str = Field(pattern=_OUTCOME_RECEIPT_ID_PATTERN)
    assignment_execution_receipt: AssignmentExecutionReceiptV2
    generated_code: GeneratedCodeRecordV2
    syntax_validation: SyntaxValidationReceiptV2
    oracle_result: OracleResultRecordV2
    functional_result: FunctionalResultRecordV2
    producer_chain: RuntimeProducerChainRecordV2
    outcome: AssignmentOutcomeRecordV2
    assembly_rule: Literal["exact_request_runtime_syntax_measurement_projection_v1"]

    @classmethod
    def from_runtime(
        cls,
        *,
        assignment_execution_receipt: AssignmentExecutionReceiptV2,
        generated_code: GeneratedCodeRecordV2,
        syntax_validation: SyntaxValidationReceiptV2,
        oracle_result: OracleResultRecordV2,
        functional_result: FunctionalResultRecordV2,
    ) -> Self:
        execution = AssignmentExecutionReceiptV2.model_validate(
            assignment_execution_receipt, strict=True
        )
        code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
        syntax = SyntaxValidationReceiptV2.model_validate(syntax_validation, strict=True)
        oracle = OracleResultRecordV2.model_validate(oracle_result, strict=True)
        functional = FunctionalResultRecordV2.model_validate(functional_result, strict=True)
        chain = validate_runtime_producer_chain_v2(
            execution.generation_request, code, oracle, functional
        )
        outcome = assemble_assignment_outcome_v2(
            execution.committed_assignment,
            execution.task_realization_bundle,
            execution.generation_request,
            code,
            oracle,
            functional,
        )
        return cls.from_content(
            assignment_execution_receipt=execution,
            generated_code=code,
            syntax_validation=syntax,
            oracle_result=oracle,
            functional_result=functional,
            producer_chain=chain,
            outcome=outcome,
            assembly_rule="exact_request_runtime_syntax_measurement_projection_v1",
        )

    @model_validator(mode="after")
    def validate_outcome_receipt(self) -> Self:
        execution = self.assignment_execution_receipt
        expected_chain = validate_runtime_producer_chain_v2(
            execution.generation_request,
            self.generated_code,
            self.oracle_result,
            self.functional_result,
        )
        expected_outcome = assemble_assignment_outcome_v2(
            execution.committed_assignment,
            execution.task_realization_bundle,
            execution.generation_request,
            self.generated_code,
            self.oracle_result,
            self.functional_result,
        )
        syntax = self.syntax_validation
        measurement_policy = execution.execution_policy_freeze.measurement_policy
        expected_state_group = {
            "valid": {
                AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
                AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE,
                AssignmentOutcomeStateV2.VALID_ORACLE_UNKNOWN,
            },
            "invalid": {AssignmentOutcomeStateV2.SYNTACTICALLY_INVALID_CODE},
            "not_applicable_no_code": {AssignmentOutcomeStateV2.TERMINAL_NO_CODE},
        }[syntax.status]
        if (
            self.producer_chain != expected_chain
            or self.outcome != expected_outcome
            or syntax.generated_code_id != self.generated_code.generated_code_id
            or syntax.code_sha256 != self.generated_code.code_sha256
            or syntax.language != execution.generation_request.language
            or syntax.parser_producer_id != measurement_policy.parser_producer_id
            or syntax.parser_policy_sha256 != measurement_policy.parser_policy_sha256
            or self.oracle_result.oracle_producer_id != measurement_policy.oracle_producer_id
            or self.oracle_result.oracle_policy_sha256 != measurement_policy.oracle_policy_sha256
            or self.functional_result.evaluator_producer_id
            != measurement_policy.functional_evaluator_producer_id
            or self.functional_result.evaluator_policy_sha256
            != measurement_policy.functional_evaluator_policy_sha256
            or self.outcome.state not in expected_state_group
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ProvenanceClosedAssignmentCoverageManifestV2(_ContentAddressedExecutionV2):
    """Formal exact coverage: every outcome must carry one complete assembly receipt."""

    _id_field: ClassVar[str] = "provenance_closed_coverage_manifest_id"
    _id_prefix: ClassVar[str] = "provenance_closed_coverage_v2_"

    schema_version: Literal["2.0"]
    provenance_closed_coverage_manifest_id: str = Field(pattern=_CLOSED_COVERAGE_ID_PATTERN)
    execution_policy_freeze: ExecutionPolicyFreezeManifestV2
    base_coverage: AssignmentCoverageManifestV2
    outcome_assembly_receipts: tuple[OutcomeAssemblyReceiptV2, ...] = Field(min_length=1)
    assignment_ids: tuple[str, ...] = Field(min_length=1)
    receipt_count: StrictInt = Field(ge=1)
    coverage_rule: Literal[
        "exact_one_authenticated_execution_and_outcome_receipt_per_assignment_v1"
    ]
    complete: Literal[True]

    @classmethod
    def from_receipts(
        cls,
        *,
        execution_policy_freeze: ExecutionPolicyFreezeManifestV2,
        outcome_assembly_receipts: Sequence[OutcomeAssemblyReceiptV2],
    ) -> Self:
        try:
            freeze = ExecutionPolicyFreezeManifestV2.model_validate(
                execution_policy_freeze, strict=True
            )
            receipts = tuple(
                sorted(
                    (
                        OutcomeAssemblyReceiptV2.model_validate(item, strict=True)
                        for item in outcome_assembly_receipts
                    ),
                    key=lambda item: item.outcome.assignment_id,
                )
            )
            base = AssignmentCoverageManifestV2.from_components(
                randomization=freeze.randomization,
                committed_assignments=tuple(
                    item.assignment_execution_receipt.committed_assignment for item in receipts
                ),
                outcomes=tuple(item.outcome for item in receipts),
            )
            assignment_ids = tuple(item.outcome.assignment_id for item in receipts)
            return cls.from_content(
                execution_policy_freeze=freeze,
                base_coverage=base,
                outcome_assembly_receipts=receipts,
                assignment_ids=assignment_ids,
                receipt_count=len(receipts),
                coverage_rule=(
                    "exact_one_authenticated_execution_and_outcome_receipt_per_assignment_v1"
                ),
                complete=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_closed_coverage(self) -> Self:
        freeze = self.execution_policy_freeze
        expected_ids = tuple(
            sorted(item.assignment_id for item in freeze.randomization.assignments)
        )
        receipt_ids = tuple(item.outcome.assignment_id for item in self.outcome_assembly_receipts)
        receipt_artifact_ids = tuple(
            item.outcome_assembly_receipt_id for item in self.outcome_assembly_receipts
        )
        if (
            receipt_ids != expected_ids
            or self.assignment_ids != expected_ids
            or self.receipt_count != len(expected_ids)
            or len(receipt_artifact_ids) != len(set(receipt_artifact_ids))
            or self.base_coverage.randomization != freeze.randomization
            or self.base_coverage.committed_assignments
            != tuple(
                item.assignment_execution_receipt.committed_assignment
                for item in self.outcome_assembly_receipts
            )
            or self.base_coverage.outcomes
            != tuple(item.outcome for item in self.outcome_assembly_receipts)
            or any(
                item.assignment_execution_receipt.execution_policy_freeze != freeze
                for item in self.outcome_assembly_receipts
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class RetryAttemptReceiptV2(_ExecutionV2Contract):
    """One frozen-policy transport or evaluator attempt; never a new assignment."""

    attempt_index: StrictInt = Field(ge=0, le=1_000)
    stage: Literal[
        "provider_transport",
        "provider_response",
        "syntax_validation",
        "security_oracle",
        "functional_evaluator",
        "artifact_storage",
    ]
    status: Literal["retryable_failure", "terminal_failure"]
    attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_response_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    valid_response_persisted: bool

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if self.valid_response_persisted and self.provider_response_sha256 is None:
            raise ValueError(self._safe_validation_message)
        return self


class InfrastructureFailureReceiptV2(_ContentAddressedExecutionV2):
    """A committed assignment's terminal failure under one immutable retry policy."""

    _id_field: ClassVar[str] = "infrastructure_failure_receipt_id"
    _id_prefix: ClassVar[str] = "infrastructure_failure_receipt_v2_"

    schema_version: Literal["2.0"]
    infrastructure_failure_receipt_id: str = Field(pattern=_FAILURE_RECEIPT_ID_PATTERN)
    assignment_execution_receipt: AssignmentExecutionReceiptV2
    retry_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    attempts: tuple[RetryAttemptReceiptV2, ...] = Field(min_length=1, max_length=1_001)
    terminal_stage: Literal[
        "provider_transport",
        "provider_response",
        "syntax_validation",
        "security_oracle",
        "functional_evaluator",
        "artifact_storage",
    ]
    valid_response_lost: bool
    regeneration_forbidden: Literal[True]
    terminal_failure: Literal[True]

    @classmethod
    def from_attempts(
        cls,
        *,
        assignment_execution_receipt: AssignmentExecutionReceiptV2,
        retry_policy_sha256: str,
        attempts: Sequence[RetryAttemptReceiptV2],
        valid_response_lost: bool,
    ) -> Self:
        checked_attempts = tuple(
            RetryAttemptReceiptV2.model_validate(item, strict=True) for item in attempts
        )
        if not checked_attempts:
            _raise_contract_error(cls)
        return cls.from_content(
            assignment_execution_receipt=assignment_execution_receipt,
            retry_policy_sha256=retry_policy_sha256,
            attempts=checked_attempts,
            terminal_stage=checked_attempts[-1].stage,
            valid_response_lost=valid_response_lost,
            regeneration_forbidden=True,
            terminal_failure=True,
        )

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        indices = tuple(item.attempt_index for item in self.attempts)
        persisted = any(item.valid_response_persisted for item in self.attempts)
        if (
            indices != tuple(range(len(self.attempts)))
            or self.attempts[-1].status != "terminal_failure"
            or any(item.status != "retryable_failure" for item in self.attempts[:-1])
            or self.terminal_stage != self.attempts[-1].stage
            or self.valid_response_lost != persisted
        ):
            raise ValueError(self._safe_validation_message)
        return self


class TotalAssignmentAccountingManifestV2(_ContentAddressedExecutionV2):
    """Exact terminal accounting over outcomes and infrastructure failures."""

    _id_field: ClassVar[str] = "total_assignment_accounting_manifest_id"
    _id_prefix: ClassVar[str] = "total_assignment_accounting_v2_"

    schema_version: Literal["2.0"]
    total_assignment_accounting_manifest_id: str = Field(pattern=_TOTAL_ACCOUNTING_ID_PATTERN)
    execution_policy_freeze: ExecutionPolicyFreezeManifestV2
    outcome_assembly_receipts: tuple[OutcomeAssemblyReceiptV2, ...]
    infrastructure_failure_receipts: tuple[InfrastructureFailureReceiptV2, ...]
    confirmatory_coverage: ProvenanceClosedAssignmentCoverageManifestV2 | None
    assignment_ids: tuple[str, ...] = Field(min_length=1)
    outcome_assignment_ids: tuple[str, ...]
    failure_assignment_ids: tuple[str, ...]
    outcome_count: StrictInt = Field(ge=0)
    failure_count: StrictInt = Field(ge=0)
    coverage_rule: Literal["exact_one_terminal_receipt_per_randomized_assignment_v1"]
    complete: Literal[True]

    @classmethod
    def from_terminal_receipts(
        cls,
        *,
        execution_policy_freeze: ExecutionPolicyFreezeManifestV2,
        outcome_assembly_receipts: Sequence[OutcomeAssemblyReceiptV2],
        infrastructure_failure_receipts: Sequence[InfrastructureFailureReceiptV2],
    ) -> Self:
        freeze = ExecutionPolicyFreezeManifestV2.model_validate(
            execution_policy_freeze, strict=True
        )
        outcomes = tuple(
            sorted(
                (
                    OutcomeAssemblyReceiptV2.model_validate(item, strict=True)
                    for item in outcome_assembly_receipts
                ),
                key=lambda item: item.outcome.assignment_id,
            )
        )
        failures = tuple(
            sorted(
                (
                    InfrastructureFailureReceiptV2.model_validate(item, strict=True)
                    for item in infrastructure_failure_receipts
                ),
                key=lambda item: item.assignment_execution_receipt.assignment_unit.assignment_id,
            )
        )
        confirmatory = (
            ProvenanceClosedAssignmentCoverageManifestV2.from_receipts(
                execution_policy_freeze=freeze,
                outcome_assembly_receipts=outcomes,
            )
            if not failures
            else None
        )
        expected_ids = tuple(
            sorted(item.assignment_id for item in freeze.randomization.assignments)
        )
        outcome_ids = tuple(item.outcome.assignment_id for item in outcomes)
        failure_ids = tuple(
            item.assignment_execution_receipt.assignment_unit.assignment_id for item in failures
        )
        return cls.from_content(
            execution_policy_freeze=freeze,
            outcome_assembly_receipts=outcomes,
            infrastructure_failure_receipts=failures,
            confirmatory_coverage=confirmatory,
            assignment_ids=expected_ids,
            outcome_assignment_ids=outcome_ids,
            failure_assignment_ids=failure_ids,
            outcome_count=len(outcome_ids),
            failure_count=len(failure_ids),
            coverage_rule="exact_one_terminal_receipt_per_randomized_assignment_v1",
            complete=True,
        )

    @model_validator(mode="after")
    def validate_total_accounting(self) -> Self:
        freeze = self.execution_policy_freeze
        expected_ids = tuple(
            sorted(item.assignment_id for item in freeze.randomization.assignments)
        )
        outcome_ids = tuple(item.outcome.assignment_id for item in self.outcome_assembly_receipts)
        failure_ids = tuple(
            item.assignment_execution_receipt.assignment_unit.assignment_id
            for item in self.infrastructure_failure_receipts
        )
        combined_ids = tuple(sorted((*outcome_ids, *failure_ids)))
        if (
            self.assignment_ids != expected_ids
            or combined_ids != expected_ids
            or len(combined_ids) != len(set(combined_ids))
            or self.outcome_assignment_ids != outcome_ids
            or self.failure_assignment_ids != failure_ids
            or self.outcome_count != len(outcome_ids)
            or self.failure_count != len(failure_ids)
            or any(
                item.assignment_execution_receipt.execution_policy_freeze != freeze
                for item in (
                    *self.outcome_assembly_receipts,
                    *self.infrastructure_failure_receipts,
                )
            )
            or (self.confirmatory_coverage is None) != bool(failure_ids)
            or (
                self.confirmatory_coverage is not None
                and (
                    self.confirmatory_coverage.execution_policy_freeze != freeze
                    or self.confirmatory_coverage.outcome_assembly_receipts
                    != self.outcome_assembly_receipts
                )
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "EXECUTION_V2_SCHEMA_VERSION",
    "AssignmentExecutionReceiptV2",
    "ExecutionPolicyFreezeManifestV2",
    "InfrastructureFailureReceiptV2",
    "MeasurementExecutionPolicyV2",
    "ModelExecutionPolicyV2",
    "OutcomeAssemblyReceiptV2",
    "ProvenanceClosedAssignmentCoverageManifestV2",
    "RetryAttemptReceiptV2",
    "SyntaxValidationReceiptV2",
    "TotalAssignmentAccountingManifestV2",
]

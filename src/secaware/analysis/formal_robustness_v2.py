"""Official glue from closed-run formal confirmation to realization robustness.

This module deliberately exposes no raw coverage, contribution-artifact, or
primary-inference arguments.  Those inputs are extracted from the single
closed-run root and the exact content-addressed formal result.  The already
computed formal primary family is reused; only the realization-robustness
family is resampled.

The typed interaction-reference family is not fully replayable until the next
implementation segment.  Therefore both the formal 999-draw path and the small
19-draw engineering smoke remain structurally unable to authorize formal
robustness or cross-model replication labels in this segment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum, StrEnum
from fractions import Fraction
from typing import Self

from pydantic import BaseModel, ValidationError

from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    FormalFamilyInferenceResultV2,
    run_formal_confirmation_v2,
)
from secaware.analysis.multi_support_robustness_v2 import (
    CrossModelReplicationResultV2,
    MultiSupportModelRobustnessResultV2,
    MultiSupportRobustnessInferenceResultV2,
    _cross_model_results,
    _derived_coordinate_values,
    _model_results,
    _run_robustness_inference,
    _validated_coverages,
    _validated_interaction_references,
    _validated_policy,
    _validated_realization_values,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    MultiSupportSimultaneousInferenceResultV2,
)
from secaware.experiments.closed_run_evidence_v2 import (
    ConfirmatoryClosedRunEvidenceV2,
)
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.randomness import RNG_VERSION
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import ArmRole
from secaware.schema.formal_analysis_v2 import FormalConfirmationStatusV2
from secaware.schema.formal_robustness_v2 import (
    FORMAL_INTERACTION_REPLAY_DRAWS_V2,
    ConfirmatoryRobustnessPolicyRegistrationV2,
    FormalRobustnessInteractionFamilyV2,
    FormalRobustnessInteractionReplayPlanV2,
)
from secaware.schema.multi_support_inference_v2 import MultiSupportFormalFamilyV2

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "formal_multi_support_robustness_result_v2_"
_FORMAL_RESULT_PREFIX = "formal_confirmation_result_v2_"
_SIMULTANEOUS_RESULT_PREFIX = "multi_support_simultaneous_result_v2_"
_SEALED_PRIMARY_RECEIPT_PREFIX = "sealed_formal_primary_receipt_v2_"
_SAME_INVOCATION_RECEIPT_ACCESS = object()
_INTERACTION_REPLAY_RESULT_PREFIX = "formal_robustness_interaction_replay_v2_"
_INTERACTION_SEED_DOMAIN = b"secaware.formal-robustness-interaction-replay.v2\x00"


class FormalRobustnessExecutionScopeV2(StrEnum):
    FORMAL_B999_PENDING_INTERACTION_REPLAY = "formal_b999_pending_interaction_replay_v1"
    SYNTHETIC_NONCLAIM_B19 = "synthetic_nonclaim_b19_v1"


class FormalRobustnessStatusV2(StrEnum):
    COMPUTED_NONCLAIM = "computed_nonclaim"
    NON_EVALUABLE_TERMINAL_FAILURE = "non_evaluable_terminal_failure"
    NON_EVALUABLE_FORMAL_RESULT = "non_evaluable_formal_result"


class FormalRobustnessEntryKindV2(StrEnum):
    OFFICIAL_SAME_INVOCATION_COMBINED = "official_same_invocation_combined_v1"
    CALLER_FORMAL_RESULT_DIAGNOSTIC = "caller_formal_result_diagnostic_nonclaim_v1"
    SYNTHETIC_CALLER_FORMAL_RESULT_DIAGNOSTIC = (
        "synthetic_caller_formal_result_diagnostic_nonclaim_v1"
    )


@dataclass(frozen=True, slots=True)
class FormalMultiSupportRobustnessResultV2:
    formal_robustness_result_id: str
    entry_kind: FormalRobustnessEntryKindV2
    execution_scope: FormalRobustnessExecutionScopeV2
    status: FormalRobustnessStatusV2
    confirmatory_closed_run_evidence_id: str
    confirmatory_pre_generation_closure_id: str
    confirmatory_experiment_freeze_id: str
    confirmatory_run_evidence_manifest_id: str
    formal_confirmation_result_id: str
    formal_analysis_protocol_id: str
    confirmatory_robustness_policy_registration_id: str
    robustness_policy_freeze_id: str
    robustness_family_id: str
    cross_model_replication_policy_id: str
    primary_formal_family: str
    primary_inference_plan_id: str | None
    primary_family_id: str | None
    primary_simultaneous_result_id: str | None
    primary_contribution_artifact_ids: tuple[str, ...]
    closed_run_coverage_manifest_ids: tuple[str, ...]
    exact_realization_contributions_sha256: str | None
    formal_confirmation_generated_in_same_invocation: bool
    formal_confirmation_invocation_count: int
    caller_supplied_formal_result: bool
    sealed_primary_receipt_id: str | None
    formal_primary_reused_from_sealed_receipt: bool
    primary_result_reused: bool
    primary_bootstrap_reexecuted: bool
    robustness_inference_result: MultiSupportRobustnessInferenceResultV2 | None
    interaction_family_id: str
    interaction_reference_ids: tuple[str, ...]
    interaction_family_complete: bool
    interaction_full_replay_pending: bool
    diagnostic_model_robustness_results: tuple[MultiSupportModelRobustnessResultV2, ...]
    diagnostic_cross_model_replication_results: tuple[CrossModelReplicationResultV2, ...]
    source_policy_glue_status: str
    official_glue_status: str
    standalone_labels_can_promote_formal_claims: bool
    official_realization_robust_labels_authorized: bool
    official_cross_model_replication_labels_authorized: bool
    p_values_are_diagnostic_only: bool
    full_result_replay_supported: bool

    def __post_init__(self) -> None:
        official = self.entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED
        if (
            self.full_result_replay_supported
            or self.official_realization_robust_labels_authorized
            or self.official_cross_model_replication_labels_authorized
            or self.standalone_labels_can_promote_formal_claims
            or not self.interaction_full_replay_pending
            or self.formal_confirmation_generated_in_same_invocation != official
            or self.formal_confirmation_invocation_count != (1 if official else 0)
            or self.caller_supplied_formal_result == official
            or (self.sealed_primary_receipt_id is not None) != official
            or (
                self.formal_primary_reused_from_sealed_receipt
                and (
                    not official
                    or not self.primary_result_reused
                    or self.sealed_primary_receipt_id is None
                )
            )
        ):
            raise ValueError("formal robustness result claim boundary failed validation")


@dataclass(frozen=True, slots=True, init=False)
class _SealedFormalPrimaryReceiptV2:
    """Internal capability minted only around one in-process formal result."""

    _seal: object
    sealed_primary_receipt_id: str
    formal_confirmation_result_id: str
    primary_simultaneous_result_id: str | None
    primary_contribution_artifact_ids: tuple[str, ...]
    _formal_result: FormalConfirmationResultV2
    _primary_family: FormalFamilyInferenceResultV2 | None

    def __new__(cls) -> Self:
        raise TypeError("sealed formal primary receipt has no public constructor")

    @classmethod
    def _from_same_invocation(
        cls,
        formal_result: FormalConfirmationResultV2,
        *,
        access: object,
    ) -> _SealedFormalPrimaryReceiptV2:
        if access is not _SAME_INVOCATION_RECEIPT_ACCESS:
            raise _error("sealed formal primary receipt requires same-invocation access")
        primary_matches = tuple(
            item
            for item in formal_result.family_results
            if item.formal_family is MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
        )
        if formal_result.status is FormalConfirmationStatusV2.EVALUATED:
            if len(primary_matches) != 1:
                raise _error("same-invocation formal primary family is not unique")
            primary = primary_matches[0]
        else:
            if primary_matches:
                raise _error("non-evaluable formal result contains a primary family")
            primary = None
        primary_result_id = (
            None if primary is None else primary.simultaneous_result.simultaneous_result_id
        )
        artifact_ids = () if primary is None else primary.contribution_artifact_ids
        receipt = object.__new__(cls)
        object.__setattr__(receipt, "_seal", _SAME_INVOCATION_RECEIPT_ACCESS)
        object.__setattr__(
            receipt,
            "sealed_primary_receipt_id",
            _SEALED_PRIMARY_RECEIPT_PREFIX
            + _digest(
                (
                    formal_result.formal_confirmation_result_id,
                    primary_result_id,
                    artifact_ids,
                    "same_invocation_formal_primary_reuse_v1",
                )
            ),
        )
        object.__setattr__(
            receipt,
            "formal_confirmation_result_id",
            formal_result.formal_confirmation_result_id,
        )
        object.__setattr__(receipt, "primary_simultaneous_result_id", primary_result_id)
        object.__setattr__(receipt, "primary_contribution_artifact_ids", artifact_ids)
        object.__setattr__(receipt, "_formal_result", formal_result)
        object.__setattr__(receipt, "_primary_family", primary)
        return receipt

    def _assert_exact(
        self,
        formal_result: FormalConfirmationResultV2,
        primary: FormalFamilyInferenceResultV2 | None,
    ) -> None:
        if (
            self._seal is not _SAME_INVOCATION_RECEIPT_ACCESS
            or self._formal_result is not formal_result
            or self._primary_family is not primary
            or self.formal_confirmation_result_id != formal_result.formal_confirmation_result_id
            or self.primary_simultaneous_result_id
            != (None if primary is None else primary.simultaneous_result.simultaneous_result_id)
            or self.primary_contribution_artifact_ids
            != (() if primary is None else primary.contribution_artifact_ids)
        ):
            raise _error("sealed formal primary receipt failed exact validation")


class FormalInteractionReplayScopeV2(StrEnum):
    FORMAL_CLOSED_RUN_B999 = "formal_closed_run_b999_v1"
    SYNTHETIC_NONCLAIM_B19 = "synthetic_nonclaim_b19_v1"


@dataclass(frozen=True, slots=True)
class _InteractionReplaySlotV2:
    block_id: str
    semantic_task_cluster_id: str
    task_instance_id: str
    hypothesis_id: str
    model_id: str
    realization_spec_id: str
    request_randomness_slot: int
    assigned_arm: ArmRole
    y_secure_yield: int


@dataclass(frozen=True, slots=True)
class _InteractionTaskWeightV2:
    semantic_task_cluster_id: str
    task_instance_id: str
    numerator: int
    denominator: int

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class _InteractionHypothesisModelDesignV2:
    hypothesis_id: str
    model_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    realization_spec_ids: tuple[str, ...]
    probability_numerators: tuple[int, ...]
    probability_denominator: int
    task_weights: tuple[_InteractionTaskWeightV2, ...]


@dataclass(frozen=True, slots=True)
class _InteractionReplayLineageV2:
    confirmatory_closed_run_evidence_id: str
    confirmatory_pre_generation_closure_id: str
    confirmatory_experiment_freeze_id: str
    confirmatory_run_evidence_manifest_id: str
    confirmatory_robustness_policy_registration_id: str
    formal_robustness_interaction_replay_plan_id: str
    robustness_policy_freeze_id: str
    robustness_family_id: str
    provenance_closed_coverage_manifest_ids: tuple[str, ...]
    randomization_manifest_ids: tuple[str, ...]
    seed_derivation_rule: str
    permutation_rule: str
    descendant_retention_rule: str
    joint_replicate_rule: str
    interaction_statistic_method: str
    global_reference_rule: str


@dataclass(frozen=True, slots=True)
class FormalInteractionHypothesisModelStatisticV2:
    hypothesis_id: str
    model_id: str
    statistic_numerator: int
    statistic_denominator: int
    statistic: float


@dataclass(frozen=True, slots=True)
class FormalInteractionPermutationDrawV2:
    replicate_index: int
    block_permutation_sha256: str
    permuted_block_count: int
    hypothesis_model_statistics: tuple[
        FormalInteractionHypothesisModelStatisticV2, ...
    ]
    global_max_numerator: int
    global_max_denominator: int
    global_max_statistic: float


@dataclass(frozen=True, slots=True)
class FormalRobustnessInteractionReplayResultV2:
    formal_robustness_interaction_replay_result_id: str
    execution_scope: FormalInteractionReplayScopeV2
    confirmatory_closed_run_evidence_id: str
    confirmatory_pre_generation_closure_id: str
    confirmatory_experiment_freeze_id: str
    confirmatory_run_evidence_manifest_id: str
    confirmatory_robustness_policy_registration_id: str
    formal_robustness_interaction_replay_plan_id: str
    robustness_policy_freeze_id: str
    robustness_family_id: str
    provenance_closed_coverage_manifest_ids: tuple[str, ...]
    randomization_manifest_ids: tuple[str, ...]
    hypothesis_model_keys: tuple[tuple[str, str], ...]
    interaction_seed_sha256: str
    rng_algorithm: str
    seed_derivation_rule: str
    permutation_rule: str
    descendant_retention_rule: str
    joint_replicate_rule: str
    interaction_statistic_method: str
    global_reference_rule: str
    permutation_count: int
    observed_statistics: tuple[FormalInteractionHypothesisModelStatisticV2, ...]
    draws: tuple[FormalInteractionPermutationDrawV2, ...]
    complete_hypothesis_model_family: bool
    full_reference_replay_complete: bool
    caller_supplied_statistics_accepted: bool
    closed_run_outcomes_only: bool
    external_pre_generation_pin_receipt_verified: bool
    formal_labels_authorized: bool

    def __post_init__(self) -> None:
        keys = tuple(
            (item.hypothesis_id, item.model_id) for item in self.observed_statistics
        )
        formal = self.execution_scope is FormalInteractionReplayScopeV2.FORMAL_CLOSED_RUN_B999
        if (
            self.hypothesis_model_keys != keys
            or keys != tuple(sorted(keys))
            or len(keys) != len(set(keys))
            or not keys
            or self.permutation_count != len(self.draws)
            or tuple(item.replicate_index for item in self.draws)
            != tuple(range(self.permutation_count))
            or any(
                tuple(
                    (item.hypothesis_id, item.model_id)
                    for item in draw.hypothesis_model_statistics
                )
                != keys
                or draw.permuted_block_count < 1
                or len(draw.block_permutation_sha256) != 64
                or draw.global_max_statistic
                != max(item.statistic for item in draw.hypothesis_model_statistics)
                for draw in self.draws
            )
            or self.rng_algorithm != RNG_VERSION
            or self.complete_hypothesis_model_family is not True
            or self.full_reference_replay_complete
            != (formal and self.permutation_count == FORMAL_INTERACTION_REPLAY_DRAWS_V2)
            or self.caller_supplied_statistics_accepted
            or not self.closed_run_outcomes_only
            or self.external_pre_generation_pin_receipt_verified
            or self.formal_labels_authorized
        ):
            raise ValueError("typed interaction replay result failed validation")


def _error(message: str = "formal robustness v2 failed validation") -> ValueError:
    return ValueError(message)


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
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


def _result_payload(result: FormalMultiSupportRobustnessResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("formal_robustness_result_id")
    return payload


def _formal_result_payload(result: FormalConfirmationResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("formal_confirmation_result_id")
    return payload


def _simultaneous_result_payload(
    result: MultiSupportSimultaneousInferenceResultV2,
) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("simultaneous_result_id")
    return payload


def _checked_closed_run(
    closed_run: ConfirmatoryClosedRunEvidenceV2,
) -> ConfirmatoryClosedRunEvidenceV2:
    if type(closed_run) is not ConfirmatoryClosedRunEvidenceV2 or not model_shape_is_intact(
        closed_run
    ):
        raise _error("exact confirmatory closed run evidence is required")
    try:
        return ConfirmatoryClosedRunEvidenceV2.model_validate(
            closed_run.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("confirmatory closed run evidence failed validation") from None


def _checked_registration(
    registration: ConfirmatoryRobustnessPolicyRegistrationV2,
) -> ConfirmatoryRobustnessPolicyRegistrationV2:
    if type(
        registration
    ) is not ConfirmatoryRobustnessPolicyRegistrationV2 or not model_shape_is_intact(registration):
        raise _error("exact pre-outcome robustness policy registration is required")
    try:
        return ConfirmatoryRobustnessPolicyRegistrationV2.model_validate(
            registration.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("robustness policy registration failed validation") from None


def _checked_interaction_family(
    family: FormalRobustnessInteractionFamilyV2,
) -> FormalRobustnessInteractionFamilyV2:
    if type(family) is not FormalRobustnessInteractionFamilyV2 or not model_shape_is_intact(family):
        raise _error("exact typed interaction reference family is required")
    try:
        return FormalRobustnessInteractionFamilyV2.model_validate(
            family.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("typed interaction reference family failed validation") from None


def _checked_interaction_plan(
    plan: FormalRobustnessInteractionReplayPlanV2,
) -> FormalRobustnessInteractionReplayPlanV2:
    if type(plan) is not FormalRobustnessInteractionReplayPlanV2 or not model_shape_is_intact(plan):
        raise _error("exact pre-outcome interaction replay plan is required")
    try:
        return FormalRobustnessInteractionReplayPlanV2.model_validate(
            plan.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("interaction replay plan failed validation") from None


def _checked_formal_result(
    result: FormalConfirmationResultV2,
) -> FormalConfirmationResultV2:
    if type(result) is not FormalConfirmationResultV2:
        raise _error("exact content-addressed formal confirmation result is required")
    if result.formal_confirmation_result_id != (
        _FORMAL_RESULT_PREFIX + _digest(_formal_result_payload(result))
    ):
        raise _error("formal confirmation result content address failed validation")
    return result


def _lineage(
    closed_run: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_family: FormalRobustnessInteractionFamilyV2,
) -> None:
    closure = closed_run.pre_generation_closure
    experiment = closure.experiment_freeze
    evidence = closed_run.run_evidence
    policy = registration.robustness_policy
    if (
        registration.pre_generation_closure != closure
        or policy.experiment != experiment
        or formal_result.confirmatory_closed_run_evidence_id
        != closed_run.confirmatory_closed_run_evidence_id
        or formal_result.confirmatory_pre_generation_closure_id
        != closure.confirmatory_pre_generation_closure_id
        or formal_result.confirmatory_experiment_freeze_id
        != experiment.confirmatory_experiment_freeze_id
        or formal_result.confirmatory_run_evidence_manifest_id
        != evidence.confirmatory_run_evidence_manifest_id
        or interaction_family.policy_registration != registration
        or interaction_family.confirmatory_closed_run_evidence_id
        != closed_run.confirmatory_closed_run_evidence_id
        or interaction_family.formal_confirmation_result_id
        != formal_result.formal_confirmation_result_id
    ):
        raise _error("formal robustness lineage failed exact validation")


def _closed_coverages(
    closed_run: ConfirmatoryClosedRunEvidenceV2,
    registration: ConfirmatoryRobustnessPolicyRegistrationV2,
) -> tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...]:
    if not closed_run.formal_point_estimation_ready:
        return ()
    raw = tuple(
        item.confirmatory_coverage for item in closed_run.run_evidence.total_assignment_accountings
    )
    if any(item is None for item in raw):
        raise _error("closed run does not contain complete formal coverage")
    return _validated_coverages(
        registration.robustness_policy,
        tuple(item for item in raw if item is not None),
    )


def _primary_bundle(
    formal_result: FormalConfirmationResultV2,
    registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    coverages: tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...],
    *,
    execution_scope: FormalRobustnessExecutionScopeV2,
) -> FormalFamilyInferenceResultV2:
    matches = tuple(
        item
        for item in formal_result.family_results
        if item.formal_family is MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
    )
    if len(matches) != 1:
        raise _error("formal primary family result is not unique")
    primary = matches[0]
    policy = registration.robustness_policy
    plan = policy.primary_inference_plan
    simultaneous = primary.simultaneous_result
    artifact_ids = tuple(item.contribution_artifact_id for item in primary.contribution_artifacts)
    artifact_coordinate_ids = tuple(
        item.test_coordinate_id for item in primary.contribution_artifacts
    )
    expected_coordinate_ids = tuple(
        item.test_coordinate.test_coordinate_id for item in plan.coordinate_supports
    )
    interval_coordinate_ids = tuple(item.test_coordinate_id for item in simultaneous.intervals)
    closed_coverage_ids = tuple(item.provenance_closed_coverage_manifest_id for item in coverages)
    artifact_coverage_ids = tuple(
        sorted(
            {item.provenance_closed_coverage_manifest_id for item in primary.contribution_artifacts}
        )
    )
    expected_draws = (
        999
        if execution_scope
        is FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY
        else 19
    )
    if (
        primary.inference_plan_id != plan.inference_plan_id
        or primary.family_id != plan.family.family_id
        or primary.contribution_artifact_ids != artifact_ids
        or artifact_coordinate_ids != expected_coordinate_ids
        or simultaneous.inference_plan_id != plan.inference_plan_id
        or simultaneous.family_id != plan.family.family_id
        or simultaneous.confirmatory_experiment_freeze_id
        != policy.confirmatory_experiment_freeze_id
        or simultaneous.global_multiplicity_family_policy_sha256
        != policy.global_multiplicity_family_policy_sha256
        or simultaneous.input_contribution_artifact_ids != artifact_ids
        or simultaneous.input_contributions_sha256
        != _digest(tuple(zip(artifact_coordinate_ids, artifact_ids, strict=True)))
        or simultaneous.simultaneous_result_id
        != _SIMULTANEOUS_RESULT_PREFIX + _digest(_simultaneous_result_payload(simultaneous))
        or interval_coordinate_ids != expected_coordinate_ids
        or len(simultaneous.draws) != simultaneous.valid_draw_count
        or len(simultaneous.invalid_draws) != simultaneous.invalid_draw_count
        or set(artifact_coverage_ids) != set(closed_coverage_ids)
        or simultaneous.valid_draw_count + simultaneous.invalid_draw_count != expected_draws
    ):
        raise _error("formal primary family binding failed exact validation")
    if (
        execution_scope is FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY
        and {item.formal_family for item in formal_result.family_results}
        != set(MultiSupportFormalFamilyV2)
    ):
        raise _error("formal result does not contain the complete formal family")
    return primary


def _exact_realization_digest(primary: FormalFamilyInferenceResultV2) -> str:
    return _digest(
        tuple(
            (
                artifact.contribution_artifact_id,
                artifact.exact_realization_contributions,
            )
            for artifact in primary.contribution_artifacts
        )
    )


def _content_address(
    result: FormalMultiSupportRobustnessResultV2,
) -> FormalMultiSupportRobustnessResultV2:
    return FormalMultiSupportRobustnessResultV2(
        formal_robustness_result_id=_RESULT_PREFIX + _digest(_result_payload(result)),
        entry_kind=result.entry_kind,
        execution_scope=result.execution_scope,
        status=result.status,
        confirmatory_closed_run_evidence_id=(result.confirmatory_closed_run_evidence_id),
        confirmatory_pre_generation_closure_id=(result.confirmatory_pre_generation_closure_id),
        confirmatory_experiment_freeze_id=(result.confirmatory_experiment_freeze_id),
        confirmatory_run_evidence_manifest_id=(result.confirmatory_run_evidence_manifest_id),
        formal_confirmation_result_id=result.formal_confirmation_result_id,
        formal_analysis_protocol_id=result.formal_analysis_protocol_id,
        confirmatory_robustness_policy_registration_id=(
            result.confirmatory_robustness_policy_registration_id
        ),
        robustness_policy_freeze_id=result.robustness_policy_freeze_id,
        robustness_family_id=result.robustness_family_id,
        cross_model_replication_policy_id=(result.cross_model_replication_policy_id),
        primary_formal_family=result.primary_formal_family,
        primary_inference_plan_id=result.primary_inference_plan_id,
        primary_family_id=result.primary_family_id,
        primary_simultaneous_result_id=result.primary_simultaneous_result_id,
        primary_contribution_artifact_ids=(result.primary_contribution_artifact_ids),
        closed_run_coverage_manifest_ids=result.closed_run_coverage_manifest_ids,
        exact_realization_contributions_sha256=(result.exact_realization_contributions_sha256),
        formal_confirmation_generated_in_same_invocation=(
            result.formal_confirmation_generated_in_same_invocation
        ),
        formal_confirmation_invocation_count=(result.formal_confirmation_invocation_count),
        caller_supplied_formal_result=result.caller_supplied_formal_result,
        sealed_primary_receipt_id=result.sealed_primary_receipt_id,
        formal_primary_reused_from_sealed_receipt=(
            result.formal_primary_reused_from_sealed_receipt
        ),
        primary_result_reused=result.primary_result_reused,
        primary_bootstrap_reexecuted=result.primary_bootstrap_reexecuted,
        robustness_inference_result=result.robustness_inference_result,
        interaction_family_id=result.interaction_family_id,
        interaction_reference_ids=result.interaction_reference_ids,
        interaction_family_complete=result.interaction_family_complete,
        interaction_full_replay_pending=result.interaction_full_replay_pending,
        diagnostic_model_robustness_results=(result.diagnostic_model_robustness_results),
        diagnostic_cross_model_replication_results=(
            result.diagnostic_cross_model_replication_results
        ),
        source_policy_glue_status=result.source_policy_glue_status,
        official_glue_status=result.official_glue_status,
        standalone_labels_can_promote_formal_claims=(
            result.standalone_labels_can_promote_formal_claims
        ),
        official_realization_robust_labels_authorized=(
            result.official_realization_robust_labels_authorized
        ),
        official_cross_model_replication_labels_authorized=(
            result.official_cross_model_replication_labels_authorized
        ),
        p_values_are_diagnostic_only=result.p_values_are_diagnostic_only,
        full_result_replay_supported=result.full_result_replay_supported,
    )


def _base_result(
    *,
    closed_run: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_family: FormalRobustnessInteractionFamilyV2,
    entry_kind: FormalRobustnessEntryKindV2,
    sealed_primary_receipt: _SealedFormalPrimaryReceiptV2 | None,
    execution_scope: FormalRobustnessExecutionScopeV2,
    status: FormalRobustnessStatusV2,
    primary: FormalFamilyInferenceResultV2 | None,
    coverages: tuple[ProvenanceClosedAssignmentCoverageManifestV2, ...],
    robustness: MultiSupportRobustnessInferenceResultV2 | None,
    model_results: tuple[MultiSupportModelRobustnessResultV2, ...] = (),
    cross_model_results: tuple[CrossModelReplicationResultV2, ...] = (),
) -> FormalMultiSupportRobustnessResultV2:
    policy = registration.robustness_policy
    provisional = FormalMultiSupportRobustnessResultV2(
        formal_robustness_result_id="",
        entry_kind=entry_kind,
        execution_scope=execution_scope,
        status=status,
        confirmatory_closed_run_evidence_id=(closed_run.confirmatory_closed_run_evidence_id),
        confirmatory_pre_generation_closure_id=(closed_run.confirmatory_pre_generation_closure_id),
        confirmatory_experiment_freeze_id=(
            closed_run.pre_generation_closure.experiment_freeze.confirmatory_experiment_freeze_id
        ),
        confirmatory_run_evidence_manifest_id=(closed_run.confirmatory_run_evidence_manifest_id),
        formal_confirmation_result_id=formal_result.formal_confirmation_result_id,
        formal_analysis_protocol_id=formal_result.formal_analysis_protocol_id,
        confirmatory_robustness_policy_registration_id=(
            registration.confirmatory_robustness_policy_registration_id
        ),
        robustness_policy_freeze_id=policy.robustness_policy_freeze_id,
        robustness_family_id=policy.robustness_family.family_id,
        cross_model_replication_policy_id=(
            policy.cross_model_policy.cross_model_replication_policy_id
        ),
        primary_formal_family=MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD.value,
        primary_inference_plan_id=(None if primary is None else primary.inference_plan_id),
        primary_family_id=None if primary is None else primary.family_id,
        primary_simultaneous_result_id=(
            None if primary is None else primary.simultaneous_result.simultaneous_result_id
        ),
        primary_contribution_artifact_ids=(
            () if primary is None else primary.contribution_artifact_ids
        ),
        closed_run_coverage_manifest_ids=tuple(
            item.provenance_closed_coverage_manifest_id for item in coverages
        ),
        exact_realization_contributions_sha256=(
            None if primary is None else _exact_realization_digest(primary)
        ),
        formal_confirmation_generated_in_same_invocation=(
            entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED
        ),
        formal_confirmation_invocation_count=(
            1 if entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED else 0
        ),
        caller_supplied_formal_result=(
            entry_kind is not FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED
        ),
        sealed_primary_receipt_id=(
            None
            if sealed_primary_receipt is None
            else sealed_primary_receipt.sealed_primary_receipt_id
        ),
        formal_primary_reused_from_sealed_receipt=(
            sealed_primary_receipt is not None and primary is not None
        ),
        primary_result_reused=primary is not None,
        primary_bootstrap_reexecuted=False,
        robustness_inference_result=robustness,
        interaction_family_id=(interaction_family.formal_robustness_interaction_family_id),
        interaction_reference_ids=interaction_family.interaction_reference_ids,
        interaction_family_complete=(interaction_family.complete_hypothesis_model_family),
        interaction_full_replay_pending=True,
        diagnostic_model_robustness_results=model_results,
        diagnostic_cross_model_replication_results=cross_model_results,
        source_policy_glue_status=policy.formal_analysis_glue_binding_status,
        official_glue_status=(
            "same_invocation_nonclaim_pending_typed_interaction_reference_replay_v1"
            if entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED
            else "diagnostic_caller_formal_result_nonclaim_v1"
        ),
        standalone_labels_can_promote_formal_claims=False,
        official_realization_robust_labels_authorized=False,
        official_cross_model_replication_labels_authorized=False,
        p_values_are_diagnostic_only=True,
        full_result_replay_supported=False,
    )
    return _content_address(provisional)


def _run(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_reference_family: FormalRobustnessInteractionFamilyV2,
    *,
    execution_scope: FormalRobustnessExecutionScopeV2,
    entry_kind: FormalRobustnessEntryKindV2,
    sealed_primary_receipt: _SealedFormalPrimaryReceiptV2 | None = None,
) -> FormalMultiSupportRobustnessResultV2:
    closed = _checked_closed_run(closed_run_evidence)
    formal = _checked_formal_result(formal_result)
    registration = _checked_registration(policy_registration)
    interaction = _checked_interaction_family(interaction_reference_family)
    _lineage(closed, formal, registration, interaction)
    policy = _validated_policy(registration.robustness_policy)
    official_same_invocation = (
        entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED
    )
    if official_same_invocation != (sealed_primary_receipt is not None):
        raise _error("same-invocation formal primary receipt is required exactly once")

    if not closed.formal_point_estimation_ready:
        if sealed_primary_receipt is not None:
            sealed_primary_receipt._assert_exact(formal, None)
        return _base_result(
            closed_run=closed,
            formal_result=formal,
            registration=registration,
            interaction_family=interaction,
            entry_kind=entry_kind,
            sealed_primary_receipt=sealed_primary_receipt,
            execution_scope=execution_scope,
            status=FormalRobustnessStatusV2.NON_EVALUABLE_TERMINAL_FAILURE,
            primary=None,
            coverages=(),
            robustness=None,
        )
    if formal.status is not FormalConfirmationStatusV2.EVALUATED:
        if sealed_primary_receipt is not None:
            sealed_primary_receipt._assert_exact(formal, None)
        return _base_result(
            closed_run=closed,
            formal_result=formal,
            registration=registration,
            interaction_family=interaction,
            entry_kind=entry_kind,
            sealed_primary_receipt=sealed_primary_receipt,
            execution_scope=execution_scope,
            status=FormalRobustnessStatusV2.NON_EVALUABLE_FORMAL_RESULT,
            primary=None,
            coverages=(),
            robustness=None,
        )

    coverages = _closed_coverages(closed, registration)
    primary = _primary_bundle(
        formal,
        registration,
        coverages,
        execution_scope=execution_scope,
    )
    if sealed_primary_receipt is not None:
        sealed_primary_receipt._assert_exact(formal, primary)
    artifacts = primary.contribution_artifacts
    realization_values = _validated_realization_values(policy, artifacts)
    derived_values = _derived_coordinate_values(policy, realization_values)
    robustness = _run_robustness_inference(
        policy,
        artifacts,
        derived_values,
        bootstrap_samples=(
            None
            if execution_scope
            is FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY
            else 19
        ),
        minimum_valid_bootstrap_draws=(
            None
            if execution_scope
            is FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY
            else 1
        ),
        inference_scope=(
            "formal_registered_robustness_b999_v1"
            if execution_scope
            is FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY
            else "synthetic_registered_robustness_nonclaim_b19_v1"
        ),
    )
    references, _reported_complete = _validated_interaction_references(
        policy,
        coverages,
        interaction.interaction_references,
    )
    # Until the typed 999-draw reference runner is replayable, completeness
    # cannot satisfy the strong-label conjunction even when every row is present.
    model_results = _model_results(
        policy,
        primary.simultaneous_result,
        robustness,
        references,
        False,
    )
    cross_model_results = _cross_model_results(policy, model_results)
    return _base_result(
        closed_run=closed,
        formal_result=formal,
        registration=registration,
        interaction_family=interaction,
        entry_kind=entry_kind,
        sealed_primary_receipt=sealed_primary_receipt,
        execution_scope=execution_scope,
        status=FormalRobustnessStatusV2.COMPUTED_NONCLAIM,
        primary=primary,
        coverages=coverages,
        robustness=robustness,
        model_results=model_results,
        cross_model_results=cross_model_results,
    )


def run_formal_multi_support_robustness_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_reference_family: FormalRobustnessInteractionFamilyV2,
) -> FormalMultiSupportRobustnessResultV2:
    """Diagnostic-only B=999 path for a caller-supplied formal result.

    Content addressing cannot authenticate a synchronously replaced and
    rehashed caller object.  Consequently this compatibility entry can never
    authorize a formal claim; use the same-invocation combined entry below for
    the official lineage.
    """

    return _run(
        closed_run_evidence,
        formal_result,
        policy_registration,
        interaction_reference_family,
        execution_scope=(FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY),
        entry_kind=FormalRobustnessEntryKindV2.CALLER_FORMAL_RESULT_DIAGNOSTIC,
    )


def run_synthetic_formal_robustness_smoke_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_reference_family: FormalRobustnessInteractionFamilyV2,
) -> FormalMultiSupportRobustnessResultV2:
    """Run the same closed-input path at B=19 with all formal labels disabled."""

    return _run(
        closed_run_evidence,
        formal_result,
        policy_registration,
        interaction_reference_family,
        execution_scope=FormalRobustnessExecutionScopeV2.SYNTHETIC_NONCLAIM_B19,
        entry_kind=(FormalRobustnessEntryKindV2.SYNTHETIC_CALLER_FORMAL_RESULT_DIAGNOSTIC),
    )


def run_official_combined_formal_robustness_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_replay_plan: FormalRobustnessInteractionReplayPlanV2,
) -> FormalMultiSupportRobustnessResultV2:
    """Run formal confirmation once and reuse its sealed primary in-process.

    The typed interaction replay is intentionally still pending.  Therefore
    this closes caller FormalResult substitution without authorizing a strong
    robustness or cross-model label yet.
    """

    closed = _checked_closed_run(closed_run_evidence)
    registration = _checked_registration(policy_registration)
    plan = _checked_interaction_plan(interaction_replay_plan)
    if (
        registration.pre_generation_closure != closed.pre_generation_closure
        or plan.policy_registration != registration
        or plan.confirmatory_experiment_freeze_id
        != closed.pre_generation_closure.experiment_freeze.confirmatory_experiment_freeze_id
    ):
        raise _error("combined formal robustness lineage failed exact validation")

    formal = run_formal_confirmation_v2(closed)
    receipt = _SealedFormalPrimaryReceiptV2._from_same_invocation(
        formal,
        access=_SAME_INVOCATION_RECEIPT_ACCESS,
    )
    pending_interaction_family = FormalRobustnessInteractionFamilyV2.from_components(
        policy_registration=registration,
        confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
        formal_confirmation_result_id=formal.formal_confirmation_result_id,
        interaction_references=(),
    )
    return _run(
        closed,
        formal,
        registration,
        pending_interaction_family,
        execution_scope=(FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY),
        entry_kind=(FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED),
        sealed_primary_receipt=receipt,
    )


def validate_formal_multi_support_robustness_result_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_reference_family: FormalRobustnessInteractionFamilyV2,
    result: FormalMultiSupportRobustnessResultV2,
) -> FormalMultiSupportRobustnessResultV2:
    """Replay the selected glue scope and require exact artifact equality."""

    if type(result) is not FormalMultiSupportRobustnessResultV2:
        raise _error("formal robustness result artifact failed validation")
    if result.entry_kind is FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED:
        raise _error("same-invocation result replay requires the combined closed-root entry")
    expected_entry_kind = (
        FormalRobustnessEntryKindV2.SYNTHETIC_CALLER_FORMAL_RESULT_DIAGNOSTIC
        if result.execution_scope is FormalRobustnessExecutionScopeV2.SYNTHETIC_NONCLAIM_B19
        else FormalRobustnessEntryKindV2.CALLER_FORMAL_RESULT_DIAGNOSTIC
    )
    expected = _run(
        closed_run_evidence,
        formal_result,
        policy_registration,
        interaction_reference_family,
        execution_scope=result.execution_scope,
        entry_kind=expected_entry_kind,
    )
    if result != expected:
        raise _error("formal robustness result artifact failed validation")
    return result


__all__ = [
    "FormalMultiSupportRobustnessResultV2",
    "FormalRobustnessEntryKindV2",
    "FormalRobustnessExecutionScopeV2",
    "FormalRobustnessStatusV2",
    "run_formal_multi_support_robustness_v2",
    "run_official_combined_formal_robustness_v2",
    "run_synthetic_formal_robustness_smoke_v2",
    "validate_formal_multi_support_robustness_result_v2",
]

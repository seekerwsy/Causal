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

from pydantic import BaseModel, ValidationError

from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    FormalFamilyInferenceResultV2,
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
from secaware.experiments.closed_run_evidence_v2 import (
    ConfirmatoryClosedRunEvidenceV2,
)
from secaware.experiments.execution_v2 import (
    ProvenanceClosedAssignmentCoverageManifestV2,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.formal_analysis_v2 import FormalConfirmationStatusV2
from secaware.schema.formal_robustness_v2 import (
    ConfirmatoryRobustnessPolicyRegistrationV2,
    FormalRobustnessInteractionFamilyV2,
)
from secaware.schema.multi_support_inference_v2 import MultiSupportFormalFamilyV2

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "formal_multi_support_robustness_result_v2_"
_FORMAL_RESULT_PREFIX = "formal_confirmation_result_v2_"


class FormalRobustnessExecutionScopeV2(StrEnum):
    FORMAL_B999_PENDING_INTERACTION_REPLAY = "formal_b999_pending_interaction_replay_v1"
    SYNTHETIC_NONCLAIM_B19 = "synthetic_nonclaim_b19_v1"


class FormalRobustnessStatusV2(StrEnum):
    COMPUTED_NONCLAIM = "computed_nonclaim"
    NON_EVALUABLE_TERMINAL_FAILURE = "non_evaluable_terminal_failure"
    NON_EVALUABLE_FORMAL_RESULT = "non_evaluable_formal_result"


@dataclass(frozen=True, slots=True)
class FormalMultiSupportRobustnessResultV2:
    formal_robustness_result_id: str
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
        or simultaneous.inference_plan_id != plan.inference_plan_id
        or simultaneous.family_id != plan.family.family_id
        or simultaneous.confirmatory_experiment_freeze_id
        != policy.confirmatory_experiment_freeze_id
        or simultaneous.global_multiplicity_family_policy_sha256
        != policy.global_multiplicity_family_policy_sha256
        or simultaneous.input_contribution_artifact_ids != artifact_ids
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
        official_glue_status=("bound_nonclaim_pending_typed_interaction_reference_replay_v1"),
        standalone_labels_can_promote_formal_claims=False,
        official_realization_robust_labels_authorized=False,
        official_cross_model_replication_labels_authorized=False,
        p_values_are_diagnostic_only=True,
        full_result_replay_supported=True,
    )
    return _content_address(provisional)


def _run(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    formal_result: FormalConfirmationResultV2,
    policy_registration: ConfirmatoryRobustnessPolicyRegistrationV2,
    interaction_reference_family: FormalRobustnessInteractionFamilyV2,
    *,
    execution_scope: FormalRobustnessExecutionScopeV2,
) -> FormalMultiSupportRobustnessResultV2:
    closed = _checked_closed_run(closed_run_evidence)
    formal = _checked_formal_result(formal_result)
    registration = _checked_registration(policy_registration)
    interaction = _checked_interaction_family(interaction_reference_family)
    _lineage(closed, formal, registration, interaction)
    policy = _validated_policy(registration.robustness_policy)

    if not closed.formal_point_estimation_ready:
        return _base_result(
            closed_run=closed,
            formal_result=formal,
            registration=registration,
            interaction_family=interaction,
            execution_scope=execution_scope,
            status=FormalRobustnessStatusV2.NON_EVALUABLE_TERMINAL_FAILURE,
            primary=None,
            coverages=(),
            robustness=None,
        )
    if formal.status is not FormalConfirmationStatusV2.EVALUATED:
        return _base_result(
            closed_run=closed,
            formal_result=formal,
            registration=registration,
            interaction_family=interaction,
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
    """Run B=999 robustness while reusing the exact official primary result."""

    return _run(
        closed_run_evidence,
        formal_result,
        policy_registration,
        interaction_reference_family,
        execution_scope=(FormalRobustnessExecutionScopeV2.FORMAL_B999_PENDING_INTERACTION_REPLAY),
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
    expected = _run(
        closed_run_evidence,
        formal_result,
        policy_registration,
        interaction_reference_family,
        execution_scope=result.execution_scope,
    )
    if result != expected:
        raise _error("formal robustness result artifact failed validation")
    return result


__all__ = [
    "FormalMultiSupportRobustnessResultV2",
    "FormalRobustnessExecutionScopeV2",
    "FormalRobustnessStatusV2",
    "run_formal_multi_support_robustness_v2",
    "run_synthetic_formal_robustness_smoke_v2",
    "validate_formal_multi_support_robustness_result_v2",
]

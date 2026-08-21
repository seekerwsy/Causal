"""Official closed-run to formal selector-utility orchestration.

The formal entry accepts exactly one trust root.  It runs formal confirmation
once, reuses the primary family produced by that same invocation, and then
runs the selector utility core.  The core remains deliberately non-claiming;
only the content-addressed wrapper below records completed formal glue.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    derive_frozen_formal_family_contributions_v2,
)
from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    FormalFamilyInferenceResultV2,
    run_formal_confirmation_v2,
)
from secaware.analysis.selector_utility_v2 import (
    SelectorUtilityAnalysisResultV2,
    VerifiedSelectorPrimaryInputsV2,
    _make_synthetic_verified_selector_primary_inputs_from_fresh_plan_v2,
    make_same_closed_run_formal_primary_inputs_v2,
    run_verified_selector_utility_analysis_v2,
)
from secaware.experiments.closed_run_evidence_v2 import ConfirmatoryClosedRunEvidenceV2
from secaware.schema.common import model_shape_is_intact
from secaware.schema.formal_analysis_v2 import (
    FormalAnalysisProtocolV2,
    FormalConfirmationStatusV2,
)
from secaware.schema.multi_support_inference_v2 import MultiSupportFormalFamilyV2
from secaware.schema.selector_utility_v2 import (
    SelectorPairInferenceStatusV2,
    SelectorUtilityAnalysisPlanV2,
    SelectorUtilityPlanScopeV2,
)

FORMAL_SELECTOR_UTILITY_V2_SCHEMA_VERSION = "2.0"

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_BUNDLE_PREFIX = "formal_selector_utility_bundle_v2_"
_CLOSED_RUN_PREFIX = "confirmatory_closed_run_evidence_v2_"
_FORMAL_RESULT_PREFIX = "formal_confirmation_result_v2_"
_CORE_RESULT_PREFIX = "selector_utility_result_v2_"
_OFFICIAL_SCOPE = "same_closed_run_formal_primary_reuse_v1"
_SYNTHETIC_SCOPE = "synthetic_closed_run_e2e_smoke_19x19_v1"


@dataclass(frozen=True, slots=True)
class FormalSelectorUtilityBundleV2:
    """Replayable linkage between one closed run, formal result, plan, and core."""

    formal_selector_utility_bundle_id: str
    schema_version: Literal["2.0"]
    analysis_scope: Literal[
        "same_closed_run_formal_primary_reuse_v1",
        "synthetic_closed_run_e2e_smoke_19x19_v1",
    ]
    confirmatory_closed_run_evidence_id: str
    confirmatory_pre_generation_closure_id: str
    confirmatory_experiment_freeze_id: str
    confirmatory_run_evidence_manifest_id: str
    formal_confirmation_result_id: str | None
    selector_utility_plan_id: str
    selector_utility_core_result_id: str
    verified_primary_inputs_id: str
    candidate_universe_id: str
    selection_freeze_id: str
    primary_inference_plan_id: str
    primary_family_id: str
    primary_simultaneous_result_id: str
    input_contribution_artifact_ids: tuple[str, ...]
    input_contributions_sha256: str
    formal_result: FormalConfirmationResultV2 | None
    selector_plan: SelectorUtilityAnalysisPlanV2
    selector_core_result: SelectorUtilityAnalysisResultV2
    conditional_on_single_frozen_discovery_split: bool
    discovery_rerun_or_rerank_performed: bool
    core_remains_nonclaiming: bool
    formal_glue_required: bool
    formal_glue_completed: bool
    formal_strict_yield_point_summary_allowed: bool
    formal_selector_claim_allowed: bool
    formal_selector_pair_claim_allowed: bool
    exact_combined_replay_required: bool


def _error(message: str = "formal selector utility v2 failed validation") -> ValueError:
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


def _checked_closed_run(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
) -> ConfirmatoryClosedRunEvidenceV2:
    if type(
        closed_run_evidence
    ) is not ConfirmatoryClosedRunEvidenceV2 or not model_shape_is_intact(closed_run_evidence):
        raise _error("exact confirmatory closed run evidence is required")
    try:
        return ConfirmatoryClosedRunEvidenceV2.model_validate(
            closed_run_evidence.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("confirmatory closed run evidence failed validation") from None


def _content_address_checked_closed_run_for_synthetic(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
) -> ConfirmatoryClosedRunEvidenceV2:
    """Check a frozen closed root without a second deep round-trip in nonclaim smoke."""

    if type(
        closed_run_evidence
    ) is not ConfirmatoryClosedRunEvidenceV2 or not model_shape_is_intact(closed_run_evidence):
        raise _error("exact confirmatory closed run evidence is required")
    closure = closed_run_evidence.pre_generation_closure
    evidence = closed_run_evidence.run_evidence
    content = closed_run_evidence.model_dump(
        mode="json",
        exclude={"confirmatory_closed_run_evidence_id"},
    )
    if (
        closed_run_evidence.confirmatory_closed_run_evidence_id
        != _CLOSED_RUN_PREFIX + _digest(content)
        or closure.experiment_freeze != evidence.experiment_freeze
        or closure.hypothesis_ids != evidence.hypothesis_ids
        or closed_run_evidence.runtime_expected_assignment_count
        != closed_run_evidence.runtime_terminally_accounted_assignment_count
        or not closed_run_evidence.all_runtime_assignments_terminally_accounted
        or not closed_run_evidence.formal_analysis_requires_this_root
    ):
        raise _error("synthetic closed run evidence failed content-address validation")
    return closed_run_evidence


def _formal_result_payload(result: FormalConfirmationResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("formal_confirmation_result_id")
    return payload


def _core_result_payload(result: SelectorUtilityAnalysisResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("selector_utility_result_id")
    return payload


def _checked_formal_primary(
    closed: ConfirmatoryClosedRunEvidenceV2,
    plan: SelectorUtilityAnalysisPlanV2,
    formal_result: FormalConfirmationResultV2,
) -> FormalFamilyInferenceResultV2:
    experiment = closed.pre_generation_closure.experiment_freeze
    protocol = FormalAnalysisProtocolV2.from_experiment(experiment)
    if type(formal_result) is not FormalConfirmationResultV2:
        raise _error("same-run formal confirmation result is required")
    expected_plans = {item.formal_family: item for item in protocol.family_plans}
    families = tuple(item.formal_family for item in formal_result.family_results)
    if (
        formal_result.formal_confirmation_result_id
        != _FORMAL_RESULT_PREFIX + _digest(_formal_result_payload(formal_result))
        or formal_result.confirmatory_closed_run_evidence_id
        != closed.confirmatory_closed_run_evidence_id
        or formal_result.confirmatory_pre_generation_closure_id
        != closed.confirmatory_pre_generation_closure_id
        or formal_result.confirmatory_experiment_freeze_id
        != experiment.confirmatory_experiment_freeze_id
        or formal_result.confirmatory_run_evidence_manifest_id
        != closed.confirmatory_run_evidence_manifest_id
        or formal_result.formal_analysis_protocol_id != protocol.formal_analysis_protocol_id
        or formal_result.status is not FormalConfirmationStatusV2.EVALUATED
        or formal_result.non_evaluable_reason is not None
        or formal_result.failed_family is not None
        or families != tuple(MultiSupportFormalFamilyV2)
        or not formal_result.complete_hypothesis_model_family_preserved
        or not formal_result.assigned_arm_itt_only
        or formal_result.joint_outcome_can_promote_security_label
        or formal_result.optional_evidence_can_promote_confirmatory_label
    ):
        raise _error("same-run formal confirmation result failed validation")
    for family_result in formal_result.family_results:
        expected_plan = expected_plans[family_result.formal_family]
        artifact_ids = tuple(
            item.contribution_artifact_id for item in family_result.contribution_artifacts
        )
        simultaneous = family_result.simultaneous_result
        if (
            type(family_result) is not FormalFamilyInferenceResultV2
            or family_result.inference_plan_id != expected_plan.inference_plan_id
            or family_result.family_id != expected_plan.family.family_id
            or family_result.contribution_artifact_ids != artifact_ids
            or simultaneous.inference_plan_id != expected_plan.inference_plan_id
            or simultaneous.confirmatory_experiment_freeze_id
            != experiment.confirmatory_experiment_freeze_id
            or simultaneous.family_id != expected_plan.family.family_id
            or simultaneous.input_contribution_artifact_ids != artifact_ids
        ):
            raise _error("formal family result differs from the frozen protocol")
    primary = tuple(
        item
        for item in formal_result.family_results
        if item.formal_family is MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
    )
    if (
        len(primary) != 1
        or plan.primary_inference_plan
        != expected_plans[MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD]
        or primary[0].inference_plan_id != plan.primary_inference_plan.inference_plan_id
        or primary[0].family_id != plan.primary_family_id
    ):
        raise _error("unique frozen primary secure-yield family is required")
    return primary[0]


def _checked_core_result(
    plan: SelectorUtilityAnalysisPlanV2,
    verified: VerifiedSelectorPrimaryInputsV2,
    core: SelectorUtilityAnalysisResultV2,
) -> SelectorUtilityAnalysisResultV2:
    if (
        type(core) is not SelectorUtilityAnalysisResultV2
        or core.selector_utility_result_id
        != _CORE_RESULT_PREFIX + _digest(_core_result_payload(core))
        or core.selector_utility_plan_id != plan.selector_utility_plan_id
        or core.confirmatory_experiment_freeze_id != plan.confirmatory_experiment_freeze_id
        or core.candidate_universe_id != plan.candidate_universe_id
        or core.selection_freeze_id != plan.selection_freeze_id
        or core.primary_inference_plan_id != plan.primary_inference_plan.inference_plan_id
        or core.primary_simultaneous_result_id != verified.primary_simultaneous_result_id
        or core.primary_input_verification_scope != verified.verification_scope
        or core.primary_family_id != plan.primary_family_id
        or core.input_contribution_artifact_ids
        != tuple(item.contribution_artifact_id for item in verified.artifacts)
        or core.input_contributions_sha256 != verified.input_contributions_sha256
        or not core.conditional_on_single_frozen_discovery_split
        or not core.formal_glue_required
        or core.formal_glue_completed
        or core.discovery_rerun_or_rerank_performed
        or core.formal_selector_claim_allowed
    ):
        raise _error("selector utility core result failed official binding validation")
    return core


def _bundle_payload(bundle: FormalSelectorUtilityBundleV2) -> dict[str, object]:
    payload = asdict(bundle)
    payload.pop("formal_selector_utility_bundle_id")
    return payload


def _content_address_bundle(
    provisional: FormalSelectorUtilityBundleV2,
) -> FormalSelectorUtilityBundleV2:
    return replace(
        provisional,
        formal_selector_utility_bundle_id=_BUNDLE_PREFIX + _digest(_bundle_payload(provisional)),
    )


def _assemble_bundle(
    *,
    closed: ConfirmatoryClosedRunEvidenceV2,
    scope: str,
    formal_result: FormalConfirmationResultV2 | None,
    plan: SelectorUtilityAnalysisPlanV2,
    verified: VerifiedSelectorPrimaryInputsV2,
    core: SelectorUtilityAnalysisResultV2,
) -> FormalSelectorUtilityBundleV2:
    official = scope == _OFFICIAL_SCOPE
    if scope not in {_OFFICIAL_SCOPE, _SYNTHETIC_SCOPE}:
        raise _error("formal selector utility scope failed validation")
    if official != (formal_result is not None):
        raise _error("formal selector utility scope/result binding failed validation")
    pair_claim = official and core.pair_inference_status is SelectorPairInferenceStatusV2.EVALUATED
    provisional = FormalSelectorUtilityBundleV2(
        formal_selector_utility_bundle_id="",
        schema_version=FORMAL_SELECTOR_UTILITY_V2_SCHEMA_VERSION,
        analysis_scope=scope,
        confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
        confirmatory_pre_generation_closure_id=(closed.confirmatory_pre_generation_closure_id),
        confirmatory_experiment_freeze_id=(
            closed.pre_generation_closure.experiment_freeze.confirmatory_experiment_freeze_id
        ),
        confirmatory_run_evidence_manifest_id=closed.confirmatory_run_evidence_manifest_id,
        formal_confirmation_result_id=(
            None if formal_result is None else formal_result.formal_confirmation_result_id
        ),
        selector_utility_plan_id=plan.selector_utility_plan_id,
        selector_utility_core_result_id=core.selector_utility_result_id,
        verified_primary_inputs_id=verified.verified_primary_inputs_id,
        candidate_universe_id=plan.candidate_universe_id,
        selection_freeze_id=plan.selection_freeze_id,
        primary_inference_plan_id=plan.primary_inference_plan.inference_plan_id,
        primary_family_id=plan.primary_family_id,
        primary_simultaneous_result_id=verified.primary_simultaneous_result_id,
        input_contribution_artifact_ids=tuple(
            item.contribution_artifact_id for item in verified.artifacts
        ),
        input_contributions_sha256=verified.input_contributions_sha256,
        formal_result=formal_result,
        selector_plan=plan,
        selector_core_result=core,
        conditional_on_single_frozen_discovery_split=True,
        discovery_rerun_or_rerank_performed=False,
        core_remains_nonclaiming=True,
        formal_glue_required=True,
        formal_glue_completed=official,
        formal_strict_yield_point_summary_allowed=official,
        formal_selector_claim_allowed=pair_claim,
        formal_selector_pair_claim_allowed=pair_claim,
        exact_combined_replay_required=True,
    )
    return _content_address_bundle(provisional)


def run_formal_selector_utility_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
) -> FormalSelectorUtilityBundleV2:
    """Run the sole claiming path from one closed-run root and no caller choices."""

    closed = _checked_closed_run(closed_run_evidence)
    experiment = closed.pre_generation_closure.experiment_freeze
    plan = SelectorUtilityAnalysisPlanV2.from_experiment(experiment)
    formal_result = run_formal_confirmation_v2(closed)
    primary = _checked_formal_primary(closed, plan, formal_result)
    verified = make_same_closed_run_formal_primary_inputs_v2(
        plan,
        primary.contribution_artifacts,
        primary.simultaneous_result,
        confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
        formal_confirmation_result_id=formal_result.formal_confirmation_result_id,
    )
    core = _checked_core_result(
        plan,
        verified,
        run_verified_selector_utility_analysis_v2(plan, verified),
    )
    return _assemble_bundle(
        closed=closed,
        scope=_OFFICIAL_SCOPE,
        formal_result=formal_result,
        plan=plan,
        verified=verified,
        core=core,
    )


def _synthetic_primary_artifacts(
    closed: ConfirmatoryClosedRunEvidenceV2,
    plan: SelectorUtilityAnalysisPlanV2,
) -> tuple[ConfirmatoryContributionArtifactV2, ...]:
    experiment = closed.pre_generation_closure.experiment_freeze
    populations = {
        item.intervention_bridge.frozen_hypothesis.hypothesis_id: item.population
        for item in experiment.protocol_roots
    }
    coverages = {
        item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: (
            item.confirmatory_coverage
        )
        for item in closed.run_evidence.total_assignment_accountings
    }
    artifacts = []
    for support in plan.primary_inference_plan.coordinate_supports:
        coordinate = support.test_coordinate
        population = populations.get(coordinate.hypothesis_id)
        coverage = coverages.get(coordinate.hypothesis_id)
        if population is None or coverage is None:
            raise _error("synthetic smoke requires complete provenance-closed coverage")
        artifacts.append(
            derive_frozen_formal_family_contributions_v2(
                population,
                coverage,
                coordinate,
            )
        )
    return tuple(artifacts)


def run_synthetic_formal_selector_utility_smoke_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
) -> FormalSelectorUtilityBundleV2:
    """Run a cheap 19x19 end-to-end smoke that can never authorize a claim."""

    closed = _content_address_checked_closed_run_for_synthetic(closed_run_evidence)
    experiment = closed.pre_generation_closure.experiment_freeze
    plan = SelectorUtilityAnalysisPlanV2.for_synthetic_validation(
        experiment,
        outer_bootstrap_samples=19,
        inner_bootstrap_samples=19,
    )
    artifacts = _synthetic_primary_artifacts(closed, plan)
    verified = _make_synthetic_verified_selector_primary_inputs_from_fresh_plan_v2(
        plan,
        artifacts,
        synthetic_critical_value=2.0,
    )
    core = _checked_core_result(
        plan,
        verified,
        run_verified_selector_utility_analysis_v2(plan, verified),
    )
    return _assemble_bundle(
        closed=closed,
        scope=_SYNTHETIC_SCOPE,
        formal_result=None,
        plan=plan,
        verified=verified,
        core=core,
    )


def _checked_bundle_shape(
    closed: ConfirmatoryClosedRunEvidenceV2,
    bundle: FormalSelectorUtilityBundleV2,
    *,
    expected_scope: str,
) -> FormalSelectorUtilityBundleV2:
    if type(bundle) is not FormalSelectorUtilityBundleV2:
        raise _error("formal selector utility bundle failed validation")
    try:
        plan = SelectorUtilityAnalysisPlanV2.model_validate(
            bundle.selector_plan.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise _error("formal selector utility bundle failed validation") from None
    official = expected_scope == _OFFICIAL_SCOPE
    if (
        bundle.formal_selector_utility_bundle_id
        != _BUNDLE_PREFIX + _digest(_bundle_payload(bundle))
        or bundle.schema_version != FORMAL_SELECTOR_UTILITY_V2_SCHEMA_VERSION
        or bundle.analysis_scope != expected_scope
        or bundle.confirmatory_closed_run_evidence_id != closed.confirmatory_closed_run_evidence_id
        or bundle.confirmatory_pre_generation_closure_id
        != closed.confirmatory_pre_generation_closure_id
        or bundle.confirmatory_experiment_freeze_id
        != closed.pre_generation_closure.experiment_freeze.confirmatory_experiment_freeze_id
        or bundle.confirmatory_run_evidence_manifest_id
        != closed.confirmatory_run_evidence_manifest_id
        or plan != bundle.selector_plan
        or bundle.selector_utility_plan_id != plan.selector_utility_plan_id
        or bundle.selector_utility_core_result_id
        != bundle.selector_core_result.selector_utility_result_id
        or bundle.candidate_universe_id != plan.candidate_universe_id
        or bundle.selection_freeze_id != plan.selection_freeze_id
        or bundle.primary_inference_plan_id != plan.primary_inference_plan.inference_plan_id
        or bundle.primary_family_id != plan.primary_family_id
        or bundle.primary_simultaneous_result_id
        != bundle.selector_core_result.primary_simultaneous_result_id
        or bundle.input_contribution_artifact_ids
        != bundle.selector_core_result.input_contribution_artifact_ids
        or bundle.input_contributions_sha256
        != bundle.selector_core_result.input_contributions_sha256
        or not bundle.conditional_on_single_frozen_discovery_split
        or bundle.discovery_rerun_or_rerank_performed
        or not bundle.core_remains_nonclaiming
        or not bundle.formal_glue_required
        or bundle.formal_glue_completed is not official
        or bundle.formal_strict_yield_point_summary_allowed is not official
        or bundle.formal_selector_claim_allowed is not bundle.formal_selector_pair_claim_allowed
        or not bundle.exact_combined_replay_required
        or bundle.selector_core_result.formal_glue_completed
        or bundle.selector_core_result.formal_selector_claim_allowed
        or (bundle.formal_result is None) is official
        or (
            bundle.formal_result is not None
            and bundle.formal_confirmation_result_id
            != bundle.formal_result.formal_confirmation_result_id
        )
        or (bundle.formal_result is None and bundle.formal_confirmation_result_id is not None)
        or (
            official
            and (
                plan.plan_scope is not SelectorUtilityPlanScopeV2.FORMAL
                or bundle.selector_core_result.primary_input_verification_scope != _OFFICIAL_SCOPE
            )
        )
        or (
            not official
            and (
                plan.plan_scope is not SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY
                or bundle.formal_selector_pair_claim_allowed
            )
        )
    ):
        raise _error("formal selector utility bundle failed validation")
    return bundle


def validate_formal_selector_utility_bundle_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    bundle: FormalSelectorUtilityBundleV2,
) -> FormalSelectorUtilityBundleV2:
    """Replay formal confirmation once plus selector utility once and require equality."""

    closed = _checked_closed_run(closed_run_evidence)
    checked = _checked_bundle_shape(closed, bundle, expected_scope=_OFFICIAL_SCOPE)
    expected = run_formal_selector_utility_v2(closed)
    if checked != expected:
        raise _error("formal selector utility bundle failed exact combined replay")
    return checked


def validate_synthetic_formal_selector_utility_smoke_bundle_v2(
    closed_run_evidence: ConfirmatoryClosedRunEvidenceV2,
    bundle: FormalSelectorUtilityBundleV2,
) -> FormalSelectorUtilityBundleV2:
    """Replay the non-claiming 19x19 smoke and require exact equality."""

    closed = _checked_closed_run(closed_run_evidence)
    checked = _checked_bundle_shape(closed, bundle, expected_scope=_SYNTHETIC_SCOPE)
    expected = run_synthetic_formal_selector_utility_smoke_v2(closed)
    if checked != expected:
        raise _error("synthetic selector smoke bundle failed exact replay")
    return checked


__all__ = [
    "FORMAL_SELECTOR_UTILITY_V2_SCHEMA_VERSION",
    "FormalSelectorUtilityBundleV2",
    "run_formal_selector_utility_v2",
    "run_synthetic_formal_selector_utility_smoke_v2",
    "validate_formal_selector_utility_bundle_v2",
    "validate_synthetic_formal_selector_utility_smoke_bundle_v2",
]

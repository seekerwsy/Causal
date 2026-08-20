from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

import secaware.analysis.formal_confirmation_v2 as formal_confirmation_module
from secaware.analysis.formal_confirmation_v2 import FormalConfirmationResultV2
from secaware.analysis.formal_robustness_v2 import (
    FormalMultiSupportRobustnessResultV2,
    FormalRobustnessEntryKindV2,
    _checked_formal_result,
    _SealedFormalPrimaryReceiptV2,
    run_formal_multi_support_robustness_v2,
    run_official_combined_formal_robustness_v2,
    run_synthetic_formal_robustness_smoke_v2,
)
from secaware.schema.formal_analysis_v2 import (
    FormalConfirmationStatusV2,
    FormalNonEvaluableReasonV2,
)
from secaware.schema.formal_robustness_v2 import (
    ConfirmatoryRobustnessPolicyRegistrationV2,
    FormalRobustnessInteractionReplayPlanV2,
)


def _synchronously_rehashed_fake_formal_result() -> FormalConfirmationResultV2:
    """A structurally addressed caller object, but not an official receipt."""

    provisional = FormalConfirmationResultV2(
        formal_confirmation_result_id="",
        confirmatory_closed_run_evidence_id=("confirmatory_closed_run_evidence_v2_" + "1" * 64),
        confirmatory_pre_generation_closure_id=(
            "confirmatory_pre_generation_closure_v2_" + "2" * 64
        ),
        confirmatory_experiment_freeze_id="experiment.fake",
        confirmatory_run_evidence_manifest_id="run-evidence.fake",
        formal_analysis_protocol_id="formal-analysis.fake",
        status=FormalConfirmationStatusV2.NON_EVALUABLE,
        non_evaluable_reason=FormalNonEvaluableReasonV2.INFERENCE_UNDEFINED,
        failed_family=None,
        expected_assignment_count=1,
        outcome_count=1,
        terminal_failure_count=0,
        terminal_failure_stage_counts=(),
        family_results=(),
        coordinate_decisions=(),
        complete_hypothesis_model_family_preserved=True,
        assigned_arm_itt_only=True,
        target_changed_and_semantic_validity_diagnostic_only=True,
        joint_outcome_can_promote_security_label=False,
        optional_jci_rfci_marker_per_protocol_present=False,
        optional_evidence_can_promote_confirmatory_label=False,
        confirmation_label_rule=(
            "primary_secure_yield_then_both_randomized_specificity_contrasts_v1"
        ),
    )
    return formal_confirmation_module._content_address(provisional)


def test_official_combined_signature_excludes_caller_formal_and_outcome_artifacts() -> None:
    assert tuple(inspect.signature(run_official_combined_formal_robustness_v2).parameters) == (
        "closed_run_evidence",
        "policy_registration",
        "interaction_replay_plan",
    )
    assert not {
        "formal_result",
        "coverage",
        "coverages",
        "primary",
        "primary_result",
        "artifacts",
        "observed_statistics",
        "reference_statistics",
    } & set(inspect.signature(run_official_combined_formal_robustness_v2).parameters)

    source = inspect.getsource(run_official_combined_formal_robustness_v2)
    assert source.count("run_formal_confirmation_v2(") == 1
    assert "_SealedFormalPrimaryReceiptV2._from_same_invocation" in source
    assert "interaction_references=()" in source


def test_interaction_plan_is_preoutcome_and_forbids_caller_reference_arrays() -> None:
    registration_fields = ConfirmatoryRobustnessPolicyRegistrationV2.model_fields
    plan_fields = FormalRobustnessInteractionReplayPlanV2.model_fields

    assert {
        "pre_generation_closure",
        "robustness_policy",
        "hypothesis_robustness_decision_ids",
        "cross_model_replication_policy_id",
        "external_pre_generation_pin_required",
        "outcomes_excluded",
    } <= set(registration_fields)
    assert {
        "policy_registration",
        "expected_hypothesis_model_keys",
        "reference_draws_per_hypothesis_model",
        "closed_run_coverage_is_sole_outcome_source",
        "exact_randomization_manifest_replay_required",
        "one_joint_family_reference_run_required",
        "caller_supplied_observed_statistics_forbidden",
        "caller_supplied_reference_statistics_forbidden",
        "full_reference_replay_status",
        "formal_strong_labels_authorized",
    } <= set(plan_fields)
    assert "observed_statistic" not in plan_fields
    assert "reference_statistics" not in plan_fields


def test_rehashed_caller_formal_cannot_mint_same_invocation_receipt() -> None:
    rehashed = _synchronously_rehashed_fake_formal_result()
    assert _checked_formal_result(rehashed) == rehashed

    with pytest.raises(TypeError, match="no public constructor"):
        _SealedFormalPrimaryReceiptV2()
    with pytest.raises(ValueError, match="same-invocation access"):
        _SealedFormalPrimaryReceiptV2._from_same_invocation(
            rehashed,
            access=object(),
        )


def test_caller_formal_apis_are_explicitly_diagnostic_nonclaim() -> None:
    assert "Diagnostic-only" in (run_formal_multi_support_robustness_v2.__doc__ or "")
    assert "all formal labels disabled" in (run_synthetic_formal_robustness_smoke_v2.__doc__ or "")
    assert tuple(inspect.signature(run_formal_multi_support_robustness_v2).parameters) == (
        "closed_run_evidence",
        "formal_result",
        "policy_registration",
        "interaction_reference_family",
    )


@pytest.mark.parametrize(
    "attack",
    (
        {"full_result_replay_supported": True},
        {"official_realization_robust_labels_authorized": True},
        {"official_cross_model_replication_labels_authorized": True},
        {"standalone_labels_can_promote_formal_claims": True},
        {"interaction_full_replay_pending": False},
    ),
)
def test_pending_interaction_boundary_cannot_be_rehashed_into_a_claim(
    attack: dict[str, bool],
) -> None:
    values: dict[str, object] = {
        "entry_kind": FormalRobustnessEntryKindV2.CALLER_FORMAL_RESULT_DIAGNOSTIC,
        "full_result_replay_supported": False,
        "official_realization_robust_labels_authorized": False,
        "official_cross_model_replication_labels_authorized": False,
        "standalone_labels_can_promote_formal_claims": False,
        "interaction_full_replay_pending": True,
        "formal_confirmation_generated_in_same_invocation": False,
        "formal_confirmation_invocation_count": 0,
        "caller_supplied_formal_result": True,
        "sealed_primary_receipt_id": None,
        "formal_primary_reused_from_sealed_receipt": False,
        "primary_result_reused": False,
    }
    values.update(attack)
    with pytest.raises(ValueError, match="claim boundary"):
        FormalMultiSupportRobustnessResultV2.__post_init__(SimpleNamespace(**values))


def test_official_result_metadata_requires_same_invocation_sealed_receipt() -> None:
    values = SimpleNamespace(
        entry_kind=FormalRobustnessEntryKindV2.OFFICIAL_SAME_INVOCATION_COMBINED,
        full_result_replay_supported=False,
        official_realization_robust_labels_authorized=False,
        official_cross_model_replication_labels_authorized=False,
        standalone_labels_can_promote_formal_claims=False,
        interaction_full_replay_pending=True,
        formal_confirmation_generated_in_same_invocation=True,
        formal_confirmation_invocation_count=1,
        caller_supplied_formal_result=False,
        sealed_primary_receipt_id=None,
        formal_primary_reused_from_sealed_receipt=False,
        primary_result_reused=False,
    )
    with pytest.raises(ValueError, match="claim boundary"):
        FormalMultiSupportRobustnessResultV2.__post_init__(values)

from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from functools import cache

import pytest

import secaware.analysis.formal_selector_utility_v2 as glue_module
import secaware.analysis.selector_utility_v2 as selector_module
from secaware.analysis.formal_confirmation_v2 import (
    FormalConfirmationResultV2,
    FormalFamilyInferenceResultV2,
)
from secaware.analysis.formal_selector_utility_v2 import (
    run_formal_selector_utility_v2,
    run_synthetic_formal_selector_utility_smoke_v2,
    validate_formal_selector_utility_bundle_v2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    GlobalUnionMaxTDrawV2,
    MultiSupportSimultaneousInferenceResultV2,
    MultiSupportSimultaneousIntervalV2,
)
from secaware.analysis.selector_utility_v2 import (
    make_same_closed_run_formal_primary_inputs_v2,
    run_verified_selector_utility_analysis_v2,
)
from secaware.experiments.closed_run_evidence_v2 import ConfirmatoryClosedRunEvidenceV2
from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.experiments import ArmRole
from secaware.schema.formal_analysis_v2 import (
    FormalAnalysisProtocolV2,
    FormalConfirmationStatusV2,
)
from secaware.schema.multi_support_inference_v2 import MultiSupportFormalFamilyV2
from secaware.schema.pre_generation_closure_v2 import ConfirmatoryPreGenerationClosureV2
from secaware.schema.selector_utility_v2 import (
    SelectorUtilityAnalysisPlanV2,
    SelectorUtilityPlanScopeV2,
)
from secaware.schema.variant_failure_evidence_v2 import VariantFailureEvidenceManifestV2
from test_formal_confirmation_v2 import _foreign_minimal_fixture, _minimal_fixture
from test_run_evidence_v2 import _accounting_for_execution
from test_selector_utility_v2 import _selector_experiment


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@cache
def _selector_closed_run() -> ConfirmatoryClosedRunEvidenceV2:
    experiment = _selector_experiment()
    accountings = []
    for execution_index, execution in enumerate(experiment.execution_policy_freezes):
        task_ids = tuple(
            sorted({item.block.task_instance_id for item in execution.randomization.assignments})
        )
        task_index = {task_id: index for index, task_id in enumerate(task_ids)}
        secure_ids = frozenset(
            item.assignment_id
            for item in execution.randomization.assignments
            if item.assigned_arm is ArmRole.TARGET_PATCH
            or (
                item.assigned_arm is ArmRole.NOOP_REWRITE
                and task_index[item.block.task_instance_id] % 2 == 0
            )
            or (
                item.assigned_arm is ArmRole.LENGTH_MATCHED_PLACEBO
                and task_index[item.block.task_instance_id] % 3 == 0
            )
            or (
                item.assigned_arm is ArmRole.GENERIC_SECURITY_REMINDER
                and task_index[item.block.task_instance_id] < 2
            )
        )
        accountings.append(
            _accounting_for_execution(
                experiment=experiment,
                execution_index=execution_index,
                secure_assignment_ids=secure_ids,
            )
        )
    evidence = ConfirmatoryRunEvidenceManifestV2.from_components(
        experiment_freeze=experiment,
        total_assignment_accountings=tuple(accountings),
    )
    failure_manifests = tuple(
        VariantFailureEvidenceManifestV2.from_components(
            intervention_bridge=root.intervention_bridge,
            query_evidence=root.query_evidence,
            population=root.population,
            failure_receipts=(),
        )
        for root in experiment.protocol_roots
    )
    closure = ConfirmatoryPreGenerationClosureV2.from_components(
        experiment_freeze=experiment,
        variant_failure_evidence_manifests=failure_manifests,
    )
    return ConfirmatoryClosedRunEvidenceV2.from_components(
        pre_generation_closure=closure,
        run_evidence=evidence,
    )


def _observed_intervals(
    plan: SelectorUtilityAnalysisPlanV2,
    artifacts: tuple,
) -> tuple[MultiSupportSimultaneousIntervalV2, ...]:
    checked_artifacts, values = selector_module._validated_artifact_family(plan, artifacts)
    assert checked_artifacts == artifacts
    full_samples = {
        item.stratum_id: item.semantic_task_cluster_ids
        for item in plan.primary_inference_plan.global_union_strata
    }
    statistics, _counts = selector_module._all_coordinate_statistics(
        plan,
        values,
        full_samples,
    )
    return tuple(
        MultiSupportSimultaneousIntervalV2(
            test_coordinate_id=binding.test_coordinate_id,
            estimate_numerator=statistics[binding.test_coordinate_id][0].numerator,
            estimate_denominator=statistics[binding.test_coordinate_id][0].denominator,
            estimate=float(statistics[binding.test_coordinate_id][0]),
            standard_error=statistics[binding.test_coordinate_id][1],
            simultaneous_lower=(
                float(statistics[binding.test_coordinate_id][0])
                - 2.0 * statistics[binding.test_coordinate_id][1]
            ),
            simultaneous_upper=(
                float(statistics[binding.test_coordinate_id][0])
                + 2.0 * statistics[binding.test_coordinate_id][1]
            ),
        )
        for binding in plan.coordinate_bindings
    )


def _address_simultaneous(
    result: MultiSupportSimultaneousInferenceResultV2,
) -> MultiSupportSimultaneousInferenceResultV2:
    return replace(
        result,
        simultaneous_result_id=(
            "multi_support_simultaneous_result_v2_"
            + selector_module._digest(selector_module._primary_result_payload(result))
        ),
    )


@cache
def _official_inputs() -> tuple[
    ConfirmatoryClosedRunEvidenceV2,
    SelectorUtilityAnalysisPlanV2,
    tuple,
    MultiSupportSimultaneousInferenceResultV2,
    FormalConfirmationResultV2,
]:
    closed = _minimal_fixture().closed_run_evidence
    experiment = closed.pre_generation_closure.experiment_freeze
    plan = SelectorUtilityAnalysisPlanV2.from_experiment(experiment)
    artifacts = glue_module._synthetic_primary_artifacts(closed, plan)
    intervals = _observed_intervals(plan, artifacts)
    draws = tuple(
        GlobalUnionMaxTDrawV2(
            replicate_index=index,
            global_sample_sha256=_sha(f"formal-draw:{index}"),
            stratum_draws=(),
            coordinate_retained_counts=(),
            max_abs_t=1.0,
        )
        for index in range(plan.primary_inference_plan.bootstrap_samples)
    )
    primary = _address_simultaneous(
        MultiSupportSimultaneousInferenceResultV2(
            simultaneous_result_id="",
            inference_plan_id=plan.primary_inference_plan.inference_plan_id,
            confirmatory_experiment_freeze_id=plan.confirmatory_experiment_freeze_id,
            family_id=plan.primary_family_id,
            global_multiplicity_family_policy_sha256=(
                plan.primary_inference_plan.global_multiplicity_family_policy_sha256
            ),
            bootstrap_seed_sha256=_sha("same-run-formal-primary-seed"),
            input_contribution_artifact_ids=tuple(
                item.contribution_artifact_id for item in artifacts
            ),
            input_contributions_sha256=selector_module._artifact_input_digest(artifacts),
            critical_value=2.0,
            valid_draw_count=len(draws),
            invalid_draw_count=0,
            intervals=intervals,
            draws=draws,
            invalid_draws=(),
        )
    )
    protocol = FormalAnalysisProtocolV2.from_experiment(experiment)
    family_results = []
    for family_plan in protocol.family_plans:
        simultaneous = _address_simultaneous(
            replace(
                primary,
                simultaneous_result_id="",
                inference_plan_id=family_plan.inference_plan_id,
                family_id=family_plan.family.family_id,
            )
        )
        family_results.append(
            FormalFamilyInferenceResultV2(
                formal_family=family_plan.formal_family,
                inference_plan_id=family_plan.inference_plan_id,
                family_id=family_plan.family.family_id,
                contribution_artifact_ids=tuple(
                    item.contribution_artifact_id for item in artifacts
                ),
                contribution_artifacts=artifacts,
                simultaneous_result=simultaneous,
            )
        )
    evidence = closed.run_evidence
    provisional = FormalConfirmationResultV2(
        formal_confirmation_result_id="",
        confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
        confirmatory_pre_generation_closure_id=closed.confirmatory_pre_generation_closure_id,
        confirmatory_experiment_freeze_id=experiment.confirmatory_experiment_freeze_id,
        confirmatory_run_evidence_manifest_id=closed.confirmatory_run_evidence_manifest_id,
        formal_analysis_protocol_id=protocol.formal_analysis_protocol_id,
        status=FormalConfirmationStatusV2.EVALUATED,
        non_evaluable_reason=None,
        failed_family=None,
        expected_assignment_count=evidence.expected_assignment_count,
        outcome_count=evidence.outcome_count,
        terminal_failure_count=evidence.failure_count,
        terminal_failure_stage_counts=tuple(
            (item.stage, item.count) for item in evidence.terminal_failure_stage_counts
        ),
        family_results=tuple(family_results),
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
    formal = replace(
        provisional,
        formal_confirmation_result_id=(
            "formal_confirmation_result_v2_"
            + glue_module._digest(glue_module._formal_result_payload(provisional))
        ),
    )
    return closed, plan, artifacts, primary, formal


def _address_formal(result: FormalConfirmationResultV2) -> FormalConfirmationResultV2:
    return replace(
        result,
        formal_confirmation_result_id=(
            "formal_confirmation_result_v2_"
            + glue_module._digest(glue_module._formal_result_payload(result))
        ),
    )


def test_synthetic_closed_run_smoke_is_19x19_end_to_end_and_never_claims() -> None:
    bundle = run_synthetic_formal_selector_utility_smoke_v2(_selector_closed_run())

    assert bundle.analysis_scope == "synthetic_closed_run_e2e_smoke_19x19_v1"
    assert bundle.selector_plan.plan_scope is SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY
    assert bundle.selector_plan.outer_bootstrap_samples == 19
    assert bundle.selector_plan.inner_bootstrap_samples == 19
    assert bundle.formal_result is None
    assert bundle.formal_confirmation_result_id is None
    assert bundle.formal_glue_completed is False
    assert bundle.formal_strict_yield_point_summary_allowed is False
    assert bundle.formal_selector_claim_allowed is False
    assert bundle.formal_selector_pair_claim_allowed is False
    assert bundle.selector_core_result.formal_glue_completed is False
    assert bundle.selector_core_result.formal_selector_claim_allowed is False
    assert bundle.selector_core_result.discovery_rerun_or_rerank_performed is False
    assert (
        bundle.selector_core_result.valid_outer_draw_count
        + bundle.selector_core_result.invalid_outer_draw_count
        == 19
    )


def test_official_entry_reuses_one_same_run_primary_and_exact_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed, plan, artifacts, primary, formal = _official_inputs()
    calls = 0

    def fake_formal(root: ConfirmatoryClosedRunEvidenceV2) -> FormalConfirmationResultV2:
        nonlocal calls
        calls += 1
        assert root == closed
        return formal

    monkeypatch.setattr(glue_module, "run_formal_confirmation_v2", fake_formal)
    bundle = run_formal_selector_utility_v2(closed)

    assert calls == 1
    assert bundle.selector_plan == plan
    assert bundle.formal_confirmation_result_id == formal.formal_confirmation_result_id
    assert bundle.primary_simultaneous_result_id == primary.simultaneous_result_id
    assert bundle.input_contribution_artifact_ids == tuple(
        item.contribution_artifact_id for item in artifacts
    )
    assert bundle.formal_glue_completed is True
    assert bundle.formal_strict_yield_point_summary_allowed is True
    assert bundle.formal_selector_claim_allowed is False
    assert bundle.formal_selector_pair_claim_allowed is False
    assert bundle.selector_core_result.formal_glue_completed is False
    assert bundle.selector_core_result.formal_selector_claim_allowed is False
    assert bundle.selector_plan.outer_bootstrap_samples == 999
    assert bundle.selector_plan.inner_bootstrap_samples == 499
    assert bundle.selector_core_result.valid_outer_draw_count == 0
    assert bundle.selector_core_result.invalid_outer_draw_count == 0
    assert validate_formal_selector_utility_bundle_v2(closed, bundle) == bundle
    assert calls == 2

    token = make_same_closed_run_formal_primary_inputs_v2(
        plan,
        artifacts,
        primary,
        confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
        formal_confirmation_result_id=formal.formal_confirmation_result_id,
    )
    standalone = run_verified_selector_utility_analysis_v2(plan, token)
    assert token.confirmatory_closed_run_evidence_id == closed.confirmatory_closed_run_evidence_id
    assert token.formal_confirmation_result_id == formal.formal_confirmation_result_id
    assert standalone.formal_glue_completed is False
    assert standalone.formal_selector_claim_allowed is False


@pytest.mark.parametrize("attack", ("foreign", "missing_primary"))
def test_official_entry_rejects_foreign_or_missing_primary_result(
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    closed, _plan, _artifacts, _primary, formal = _official_inputs()
    if attack == "foreign":
        attacked = replace(
            formal,
            formal_confirmation_result_id="",
            confirmatory_closed_run_evidence_id=(
                _foreign_minimal_fixture().closed_run_evidence.confirmatory_closed_run_evidence_id
            ),
        )
    else:
        attacked = replace(
            formal,
            formal_confirmation_result_id="",
            family_results=tuple(
                item
                for item in formal.family_results
                if item.formal_family is not MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
            ),
        )
    attacked = _address_formal(attacked)
    monkeypatch.setattr(glue_module, "run_formal_confirmation_v2", lambda _root: attacked)

    with pytest.raises(ValueError, match="same-run formal|primary secure-yield"):
        run_formal_selector_utility_v2(closed)


def test_same_run_factory_and_bundle_attacks_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed, plan, artifacts, primary, formal = _official_inputs()
    monkeypatch.setattr(glue_module, "run_formal_confirmation_v2", lambda _root: formal)
    bundle = run_formal_selector_utility_v2(closed)

    with pytest.raises(ValueError, match="complete primary contribution"):
        make_same_closed_run_formal_primary_inputs_v2(
            plan,
            artifacts[:-1],
            primary,
            confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
            formal_confirmation_result_id=formal.formal_confirmation_result_id,
        )
    wrong_primary = replace(
        primary, inference_plan_id="multi_support_simultaneous_plan_v2_" + "f" * 64
    )
    wrong_primary = _address_simultaneous(replace(wrong_primary, simultaneous_result_id=""))
    with pytest.raises(ValueError, match="same-run formal primary"):
        make_same_closed_run_formal_primary_inputs_v2(
            plan,
            artifacts,
            wrong_primary,
            confirmatory_closed_run_evidence_id=closed.confirmatory_closed_run_evidence_id,
            formal_confirmation_result_id=formal.formal_confirmation_result_id,
        )

    bad_plan = plan.model_copy(update={"slot_bindings": plan.slot_bindings[:-1]})
    attacked_plan_bundle = glue_module._content_address_bundle(
        replace(
            bundle,
            formal_selector_utility_bundle_id="",
            selector_plan=bad_plan,
        )
    )
    with pytest.raises(ValueError, match="bundle failed validation"):
        validate_formal_selector_utility_bundle_v2(closed, attacked_plan_bundle)

    fake_core = replace(
        bundle.selector_core_result,
        selector_utility_result_id="",
        formal_glue_completed=True,
    )
    fake_core = replace(
        fake_core,
        selector_utility_result_id=(
            "selector_utility_result_v2_"
            + selector_module._digest(selector_module._result_payload(fake_core))
        ),
    )
    fake_core_bundle = glue_module._content_address_bundle(
        replace(
            bundle,
            formal_selector_utility_bundle_id="",
            selector_utility_core_result_id=fake_core.selector_utility_result_id,
            selector_core_result=fake_core,
        )
    )
    with pytest.raises(ValueError, match="bundle failed validation"):
        validate_formal_selector_utility_bundle_v2(closed, fake_core_bundle)

    fake_token_bundle = glue_module._content_address_bundle(
        replace(
            bundle,
            formal_selector_utility_bundle_id="",
            verified_primary_inputs_id="verified_selector_primary_inputs_v2_" + "f" * 64,
        )
    )
    with pytest.raises(ValueError, match="exact combined replay"):
        validate_formal_selector_utility_bundle_v2(closed, fake_token_bundle)

    with pytest.raises(ValueError, match="bundle failed validation"):
        validate_formal_selector_utility_bundle_v2(
            closed,
            replace(bundle, formal_selector_utility_bundle_id=_sha("fake-bundle")),
        )


def test_public_entry_signatures_accept_no_raw_formal_or_analysis_inputs() -> None:
    assert tuple(inspect.signature(run_formal_selector_utility_v2).parameters) == (
        "closed_run_evidence",
    )
    assert tuple(inspect.signature(run_synthetic_formal_selector_utility_smoke_v2).parameters) == (
        "closed_run_evidence",
    )
    assert tuple(inspect.signature(validate_formal_selector_utility_bundle_v2).parameters) == (
        "closed_run_evidence",
        "bundle",
    )

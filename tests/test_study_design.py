from __future__ import annotations

from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.cli import main
from prompt_mechanism_study.inference import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    EvidenceLevel,
    TargetRandomizationPlan,
    TargetTaskArmVariant,
    TargetTaskBundle,
    build_target_selector_yields,
    estimate_target_itt,
    freeze_assigned_arm_evidence,
    randomize_target_confirmation,
)
from prompt_mechanism_study.outcomes import Outcome
from prompt_mechanism_study.prioritization import (
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
)
from prompt_mechanism_study.selector_verify import (
    load_and_verify_target_result_bundle,
    verify_formal_report_authorization,
    verify_formal_budget_preflight,
    verify_rq1_budget_qualification,
    verify_target_power_simulation,
    verify_target_randomization,
    verify_target_rq_tables,
    verify_target_study_freezes,
)
from prompt_mechanism_study.selector_analysis import (
    build_target_rq_tables,
    write_target_result_bundle,
)
from prompt_mechanism_study.study_design import (
    ATOMIC_POWER_ARMS,
    PAIR_POWER_ARMS,
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FreezeArtifactReference,
    PowerAndMarginMemo,
    ProviderBudgetCeilings,
    ProviderCallKind,
    ProviderRate,
    ProviderTokenCostBasis,
    QualificationBundle,
    QualificationPlan,
    QualificationPlanPhase,
    QualificationProfileKind,
    QualificationProfileResult,
    QualificationStatus,
    RQ1BaselineQualification,
    RQ1BudgetQualification,
    RQ1BudgetDimensions,
    RQ1BudgetScenario,
    StudyFreezeIndex,
    StudyDesignError,
    TargetPowerAssumption,
    TargetPowerSimulationPlan,
    _balanced_sample,
    _excluded_task_units,
    _power_design,
    _priority_extensions,
    freeze_qualification_bundle,
    freeze_power_and_margin_memo,
    freeze_target_confirmation_design,
    freeze_target_discovery_design,
    freeze_target_study_index,
    authorize_target_report,
    qualify_rq1_baselines,
    qualify_rq1_budget,
    qualification_plan_bundle,
    rq1_worst_case_budget_envelopes,
    simulate_target_power,
    validate_formal_budget_preflight,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    DataRole,
    DataRoleBinding,
    DataRoleManifest,
    ModelBoundCandidateRecord,
    Operation,
    PolicyFactor,
    TaskUnitDataRoleRecord,
    pair_policy_key,
)

pytestmark = pytest.mark.extended


def _artifact_ref(label: str) -> FreezeArtifactReference:
    return FreezeArtifactReference(label, content_hash(label))


def _role_task(label: str) -> TaskUnitDataRoleRecord:
    return TaskUnitDataRoleRecord(
        label,
        f"near-duplicate-{label}",
        f"lineage-{label}",
        (),
        "role-assignment-v1",
    )


def _qualification_manifest(
    *,
    confirmation_task_ids: tuple[str, ...] = ("confirm-1",),
) -> DataRoleManifest:
    bindings = tuple(
        sorted(
            (
                DataRoleBinding(
                    "CONFIRM-001",
                    DataRole.CONFIRMATION,
                    tuple(_role_task(item) for item in sorted(confirmation_task_ids)),
                    content_hash("confirm-manifest"),
                ),
                DataRoleBinding(
                    "DISCOVERY-001",
                    DataRole.DISCOVERY,
                    (_role_task("discover-1"),),
                    content_hash("discovery-manifest"),
                ),
                DataRoleBinding(
                    "LEGACY-001",
                    DataRole.LEGACY_ONLY,
                    (
                        replace(
                            _role_task("legacy-1"),
                            exposure_history=("historical_v4_qualification",),
                        ),
                    ),
                    content_hash("legacy-manifest"),
                ),
                DataRoleBinding(
                    "QUAL-ACCEPT-001",
                    DataRole.QUAL_ACCEPT,
                    (_role_task("qual-accept-1"),),
                    content_hash("qual-accept-manifest"),
                ),
                DataRoleBinding(
                    "QUAL-DEV-001",
                    DataRole.QUAL_DEV,
                    (_role_task("qual-dev-1"),),
                    content_hash("qual-dev-manifest"),
                ),
            ),
            key=lambda item: item.data_id,
        )
    )
    return DataRoleManifest(
        "phase-context-policy-v3",
        content_hash("source-manifest"),
        bindings,
    )


def _accepted_qualification_bundle(
    manifest: DataRoleManifest,
    power_memo: PowerAndMarginMemo | None = None,
    baseline_qualification: RQ1BaselineQualification | None = None,
) -> QualificationBundle:
    baseline_qualification = baseline_qualification or _baseline_qualification(
        manifest
    )
    plans = tuple(
        QualificationPlan(
            kind,
            (
                baseline_qualification.selected_profile_id
                if kind is QualificationProfileKind.RQ1_BASELINES
                else f"{kind.value}-candidate-1",
            ),
            (
                baseline_qualification.selected_profile_id
                if kind is QualificationProfileKind.RQ1_BASELINES
                else f"{kind.value}-candidate-1"
            ),
            f"{kind.value}-selection-rule-v1",
            (f"{kind.value}-acceptance-metric",),
            content_hash(f"{kind.value}-thresholds"),
            f"{kind.value}-tie-break-v1",
            "a" * 40,
        )
        for kind in QualificationProfileKind
    )
    plan_bundle = qualification_plan_bundle(manifest, plans)
    profile_results = tuple(
        QualificationProfileResult(
            plan.profile_kind,
            plan.selected_profile_id,
            (
                FreezeArtifactReference(
                    power_memo.power_and_margin_memo_id,
                    content_hash(power_memo),
                )
                if plan.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
                and power_memo is not None
                else FreezeArtifactReference(
                    baseline_qualification.rq1_baseline_qualification_id,
                    content_hash(baseline_qualification),
                )
                if plan.profile_kind is QualificationProfileKind.RQ1_BASELINES
                else _artifact_ref(f"{plan.profile_kind.value}-qualification-result")
            ),
            QualificationStatus.ACCEPTED,
            manifest.qualification_accept_data_id,
            plan.code_commit,
            "PASS",
        )
        for plan in plans
    )
    return freeze_qualification_bundle(
        manifest,
        plan_bundle,
        profile_results,
        verifier_status="PASS",
    )


def _baseline_qualification(
    manifest: DataRoleManifest,
    *,
    scenario: RQ1BudgetScenario = RQ1BudgetScenario.CORE,
    model_ids: tuple[str, ...] = ("model-a",),
    independent_verifier_status: str = "PASS",
) -> RQ1BaselineQualification:
    selector_ids: tuple[str, ...] = ()
    if scenario in {
        RQ1BudgetScenario.CORE_EXPERT,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM,
    }:
        selector_ids += ("atomic_blind_expert", "pair_blind_expert")
    if scenario is RQ1BudgetScenario.CORE_EXPERT_RANDOM:
        selector_ids += ("atomic_seeded_random", "pair_seeded_random")
    references = tuple(
        (selector_id, model_id, _artifact_ref(f"{selector_id}-{model_id}-contract"))
        for selector_id in sorted(selector_ids)
        for model_id in model_ids
    )
    return qualify_rq1_baselines(
        protocol_id=manifest.protocol_id,
        scenario=scenario,
        model_ids=model_ids,
        qualification_accept_data_id=manifest.qualification_accept_data_id,
        code_commit="a" * 40,
        contract_references=references,
        independent_verifier_status=independent_verifier_status,
    )


def _power_result(
    track: PolicyTrack,
    *,
    family_size: int = 2,
    task_units: int = 10,
):
    if track is PolicyTrack.ATOMIC:
        probabilities = tuple(
            zip(ATOMIC_POWER_ARMS, (0.79, 0.01, 0.10, 0.10), strict=True)
        )
    else:
        probabilities = tuple(
            zip(PAIR_POWER_ARMS, (0.01, 0.01, 0.01, 0.79), strict=True)
        )
    assumption = TargetPowerAssumption(
        f"{track.value}-planning-high-effect",
        track,
        probabilities,
        0.0,
        0.0,
        0.01,
        0.0,
        0.1,
        0.1,
    )
    plan = TargetPowerSimulationPlan(
        track,
        0.05,
        family_size,
        task_units,
        1,
        2,
        2,
        4,
        0.05,
        0.8,
        2000,
        20260831 + (0 if track is PolicyTrack.ATOMIC else 1),
        (assumption,),
    )
    return simulate_target_power(plan)


def _power_memo(
    manifest: DataRoleManifest,
    *,
    atomic_family_size: int = 2,
    pair_family_size: int = 2,
) -> PowerAndMarginMemo:
    return freeze_power_and_margin_memo(
        manifest,
        code_commit="a" * 40,
        atomic_power=_power_result(
            PolicyTrack.ATOMIC,
            family_size=atomic_family_size,
        ),
        pair_power=_power_result(
            PolicyTrack.PAIR,
            family_size=pair_family_size,
        ),
        bootstrap_draws=1000,
        bootstrap_seed=2026083103,
        minimum_valid_bootstrap_fraction=0.9,
        maximum_unknown_fraction_among_valid=0.2,
        independent_verifier_status="PASS",
    )


def _provider_ceilings(*, generation_ceiling: int = 1000) -> ProviderBudgetCeilings:
    rates = tuple(
        ProviderRate(
            kind,
            f"provider-{kind.value}",
            index + 1,
            _artifact_ref(f"rate-{kind.value}"),
            ProviderTokenCostBasis(
                "CNY",
                "synthetic-test-region",
                f"synthetic-tier-{index + 1}",
                1,
                1,
                0,
                (index + 1) * 1_000_000,
                0,
            ),
        )
        for index, kind in enumerate(ProviderCallKind)
    )
    return ProviderBudgetCeilings(
        rates,
        1000,
        generation_ceiling,
        1000,
        3000,
        100000,
    )


def _accepted_budget(
    manifest: DataRoleManifest,
    *,
    scenario: RQ1BudgetScenario = RQ1BudgetScenario.CORE,
    model_ids: tuple[str, ...] = ("model-a",),
) -> RQ1BudgetQualification:
    dimensions = RQ1BudgetDimensions(
        model_ids,
        atomic_top_k=1,
        pair_top_k=1,
        atomic_task_units_per_effect=10,
        pair_task_units_per_effect=10,
        atomic_global_realizations=1,
        pair_global_realizations=1,
        atomic_total_block_slots=4,
        pair_total_block_slots=4,
    )
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[scenario]
    family_size = selector_count * len(model_ids)
    power_memo = _power_memo(
        manifest,
        atomic_family_size=family_size,
        pair_family_size=family_size,
    )
    baseline_qualification = _baseline_qualification(
        manifest,
        scenario=scenario,
        model_ids=model_ids,
    )
    return qualify_rq1_budget(
        scenario=scenario,
        dimensions=dimensions,
        power_and_margin_memo=power_memo,
        qualification_bundle=_accepted_qualification_bundle(
            manifest,
            power_memo,
            baseline_qualification,
        ),
        baseline_qualification=baseline_qualification,
        provider_ceilings=_provider_ceilings(),
        independent_verifier_status="PASS",
    )


@pytest.mark.reviewer
def test_rq1_budget_envelopes_use_one_model_dimension_and_reject_m_squared() -> None:
    dimensions = RQ1BudgetDimensions(
        ("model-a", "model-b"),
        atomic_top_k=3,
        pair_top_k=1,
        atomic_task_units_per_effect=10,
        pair_task_units_per_effect=20,
        atomic_global_realizations=2,
        pair_global_realizations=2,
        atomic_total_block_slots=4,
        pair_total_block_slots=8,
    )
    report = rq1_worst_case_budget_envelopes(dimensions)
    core, expert, random = report["scenarios"]

    assert report["status"] == "SPECIFIED_DRAFT"
    assert report["provider_calls_authorized"] is False
    assert report["model_dispatch_policy"] == "model_bound_effect_coordinate"
    assert core["atomic_effect_record_upper_bound"] == 12
    assert core["pair_effect_record_upper_bound"] == 4
    assert core["generation_call_upper_bound"] == 1120
    assert core["materialization_call_upper_bound"] == 400
    assert core["external_call_upper_bound"] == 2640
    assert expert["generation_call_upper_bound"] == 1680
    assert random["generation_call_upper_bound"] == 2240
    assert core["accidental_model_square_generation_calls"] == 2240

    with pytest.raises(ValueError, match="cannot be crossed"):
        RQ1BudgetDimensions(
            ("model-a", "model-b"),
            atomic_top_k=3,
            pair_top_k=1,
            atomic_task_units_per_effect=10,
            pair_task_units_per_effect=20,
            atomic_global_realizations=2,
            pair_global_realizations=2,
            atomic_total_block_slots=4,
            pair_total_block_slots=8,
            confirmation_cross_product_models=True,
        )

    with pytest.raises(ValueError, match="exactly one realization"):
        RQ1BudgetDimensions(
            ("model-a", "model-b"),
            atomic_top_k=3,
            pair_top_k=1,
            atomic_task_units_per_effect=10,
            pair_task_units_per_effect=20,
            atomic_global_realizations=2,
            pair_global_realizations=2,
            atomic_total_block_slots=4,
            pair_total_block_slots=8,
            realization_assignments_per_task=2,
        )


@pytest.mark.reviewer
def test_power_margin_memo_is_assumption_conditional_and_authorizes_one_itt_plan() -> None:
    manifest = _qualification_manifest()
    atomic = _power_result(PolicyTrack.ATOMIC)
    pair = _power_result(PolicyTrack.PAIR)
    memo = _power_memo(manifest)

    assert atomic.power_gate_passed is True
    assert pair.power_gate_passed is True
    assert verify_target_power_simulation(atomic)["status"] == (
        "TARGET_POWER_SIMULATION_VERIFIED"
    )
    assert verify_target_power_simulation(pair)["power_gate_passed"] is True
    assert atomic.target_confirmation_outcomes_used is False
    assert memo.formal_use_authorized is True
    assert memo.endpoint_order == (
        "secure_yield",
        "code_valid",
        "oracle_evaluable",
        "functionality",
        "joint",
    )
    inference_plan = memo.target_itt_plan()
    assert inference_plan.atomic_practical_margin == 0.05
    assert inference_plan.pair_practical_margin == 0.05
    assert inference_plan.alpha == 0.05
    assert inference_plan.bootstrap_draws == 1000

    weak = TargetPowerAssumption(
        "atomic-weak",
        PolicyTrack.ATOMIC,
        tuple(zip(ATOMIC_POWER_ARMS, (0.21, 0.20, 0.20, 0.20), strict=True)),
        0.1,
        0.0,
        0.1,
        0.0,
        0.1,
        0.1,
    )
    weak_plan = replace(atomic.plan, assumptions=(weak,))
    weak_result = simulate_target_power(weak_plan)
    blocked = freeze_power_and_margin_memo(
        manifest,
        code_commit="a" * 40,
        atomic_power=weak_result,
        pair_power=pair,
        bootstrap_draws=1000,
        bootstrap_seed=2026083103,
        minimum_valid_bootstrap_fraction=0.9,
        maximum_unknown_fraction_among_valid=0.2,
        independent_verifier_status="PASS",
    )
    assert blocked.status is QualificationStatus.BLOCKED
    with pytest.raises(StudyDesignError, match="BLOCKED power memo"):
        blocked.target_itt_plan()
    with pytest.raises(ValueError, match="cannot read target confirmation outcomes"):
        replace(weak, target_confirmation_outcomes_used=True)
    tampered_scenario = replace(
        atomic.scenarios[0],
        simultaneous_critical_value=atomic.scenarios[0].simultaneous_critical_value + 0.1,
    )
    tampered_result = replace(atomic, scenarios=(tampered_scenario,))
    with pytest.raises(ValueError, match="failed independent replay"):
        verify_target_power_simulation(tampered_result)


@pytest.mark.reviewer
def test_joint_rq1_budget_gate_binds_power_family_calls_cost_and_verifier() -> None:
    manifest = _qualification_manifest()
    accepted = _accepted_budget(manifest)

    assert accepted.status is QualificationStatus.ACCEPTED
    assert accepted.provider_calls_authorized is True
    assert accepted.atomic_selector_ids == ("atomic_full", "atomic_rd_only")
    assert accepted.pair_selector_ids == ("pair_full", "pair_no_relation")
    assert accepted.reservation.atomic_effect_record_upper_bound == 2
    assert accepted.reservation.pair_effect_record_upper_bound == 2
    assert accepted.reservation.generation_call_upper_bound == 160
    assert accepted.reservation.external_call_upper_bound == 400
    assert accepted.reservation.external_cost_upper_bound_microunits == 880
    verification = verify_rq1_budget_qualification(accepted)
    assert verification["status"] == (
        "RQ1_BUDGET_QUALIFICATION_VERIFIED"
    )
    assert verification["budget_currency"] == "CNY"

    blocked = qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE,
        dimensions=accepted.dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=accepted.qualification_bundle,
        baseline_qualification=accepted.baseline_qualification,
        provider_ceilings=_provider_ceilings(generation_ceiling=159),
        independent_verifier_status="PASS",
    )
    assert blocked.status is QualificationStatus.BLOCKED
    assert blocked.blockers == ("generation_call_ceiling_exceeded",)
    assert blocked.provider_calls_authorized is False
    with pytest.raises(ValueError, match="blockers failed independent replay"):
        verify_rq1_budget_qualification(
            replace(blocked, blockers=("fabricated_budget_blocker",))
        )

    cost_blocked = qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE,
        dimensions=accepted.dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=accepted.qualification_bundle,
        baseline_qualification=accepted.baseline_qualification,
        provider_ceilings=replace(
            _provider_ceilings(), external_cost_ceiling_microunits=879
        ),
        independent_verifier_status="PASS",
    )
    assert cost_blocked.blockers == ("external_cost_ceiling_exceeded",)

    with pytest.raises(ValueError, match="no hidden automatic retries"):
        replace(_provider_ceilings().rates[0], automatic_retry_ceiling=1)

    with pytest.raises(ValueError, match="does not replay from token ceilings"):
        replace(
            _provider_ceilings().rates[0],
            maximum_unit_cost_microunits=2,
        )
    with pytest.raises(ValueError, match="exceed the frozen pricing tier"):
        replace(
            _provider_ceilings().rates[0].token_cost_basis,
            maximum_input_tokens=2,
        )
    mixed_rates = list(_provider_ceilings().rates)
    mixed_rates[1] = replace(
        mixed_rates[1],
        token_cost_basis=replace(mixed_rates[1].token_cost_basis, currency="USD"),
    )
    with pytest.raises(ValueError, match="one frozen budget currency"):
        replace(_provider_ceilings(), rates=tuple(mixed_rates))

    mismatched_dimensions = replace(accepted.dimensions, atomic_top_k=2)
    mismatched = qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE,
        dimensions=mismatched_dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=accepted.qualification_bundle,
        baseline_qualification=accepted.baseline_qualification,
        provider_ceilings=_provider_ceilings(),
        independent_verifier_status="PASS",
    )
    assert "atomic_family_size_mismatch" in mismatched.blockers

    unbound_qualification = _accepted_qualification_bundle(manifest)
    lineage_blocked = qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE,
        dimensions=accepted.dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=unbound_qualification,
        baseline_qualification=accepted.baseline_qualification,
        provider_ceilings=_provider_ceilings(),
        independent_verifier_status="PASS",
    )
    assert lineage_blocked.blockers == ("power_profile_lineage_mismatch",)
    assert lineage_blocked.provider_calls_authorized is False
    assert verify_rq1_budget_qualification(lineage_blocked)["status"] == (
        "RQ1_BUDGET_QUALIFICATION_VERIFIED"
    )

    independently_tampered = _accepted_budget(manifest)
    object.__setattr__(
        independently_tampered.provider_ceilings.rates[0].token_cost_basis,
        "input_price_microunits_per_million_tokens",
        2_000_000,
    )
    with pytest.raises(ValueError, match="token-price replay"):
        verify_rq1_budget_qualification(independently_tampered)


@pytest.mark.reviewer
def test_selected_rq1_baselines_require_qualified_contracts_before_budget() -> None:
    manifest = _qualification_manifest()
    accepted = _accepted_budget(
        manifest,
        scenario=RQ1BudgetScenario.CORE_EXPERT_RANDOM,
        model_ids=("model-a", "model-b"),
    )

    assert accepted.status is QualificationStatus.ACCEPTED
    assert accepted.atomic_selector_ids == (
        "atomic_blind_expert",
        "atomic_full",
        "atomic_rd_only",
        "atomic_seeded_random",
    )
    assert accepted.pair_selector_ids == (
        "pair_blind_expert",
        "pair_full",
        "pair_no_relation",
        "pair_seeded_random",
    )
    assert len(accepted.baseline_qualification.contract_references) == 8
    assert verify_rq1_budget_qualification(accepted)["baseline_qualification_id"] == (
        accepted.baseline_qualification.rq1_baseline_qualification_id
    )

    missing = qualify_rq1_baselines(
        protocol_id=manifest.protocol_id,
        scenario=RQ1BudgetScenario.CORE_EXPERT_RANDOM,
        model_ids=accepted.dimensions.model_ids,
        qualification_accept_data_id=manifest.qualification_accept_data_id,
        code_commit="a" * 40,
        contract_references=accepted.baseline_qualification.contract_references[:-1],
        independent_verifier_status="PASS",
    )
    missing_bundle = _accepted_qualification_bundle(
        manifest,
        accepted.power_and_margin_memo,
        missing,
    )
    blocked = qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE_EXPERT_RANDOM,
        dimensions=accepted.dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=missing_bundle,
        baseline_qualification=missing,
        provider_ceilings=_provider_ceilings(),
        independent_verifier_status="PASS",
    )

    assert blocked.status is QualificationStatus.BLOCKED
    assert blocked.blockers == ("rq1_baseline_qualification_not_accepted",)
    assert verify_rq1_budget_qualification(blocked)["provider_calls_authorized"] is False

    baseline_profile_index = next(
        index
        for index, profile in enumerate(accepted.qualification_bundle.profiles)
        if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
    )
    profiles = list(accepted.qualification_bundle.profiles)
    profiles[baseline_profile_index] = replace(
        profiles[baseline_profile_index],
        artifact=_artifact_ref("budget-only-baseline-name"),
    )
    budget_only_bundle = replace(
        accepted.qualification_bundle,
        profiles=tuple(profiles),
    )
    budget_only = qualify_rq1_budget(
        scenario=accepted.scenario,
        dimensions=accepted.dimensions,
        power_and_margin_memo=accepted.power_and_margin_memo,
        qualification_bundle=budget_only_bundle,
        baseline_qualification=accepted.baseline_qualification,
        provider_ceilings=accepted.provider_ceilings,
        independent_verifier_status="PASS",
    )
    assert budget_only.blockers == ("baseline_profile_lineage_mismatch",)

    independently_tampered = _accepted_budget(
        manifest,
        scenario=RQ1BudgetScenario.CORE_EXPERT_RANDOM,
        model_ids=("model-a", "model-b"),
    )
    object.__setattr__(
        independently_tampered.baseline_qualification,
        "contract_references",
        independently_tampered.baseline_qualification.contract_references[:-1],
    )
    with pytest.raises(
        ValueError,
        match="baseline qualification blockers failed independent replay",
    ):
        verify_rq1_budget_qualification(independently_tampered)


def _dispatch_and_assignments():
    scope = AnalysisScope(
        "security.synthetic",
        "context.synthetic",
        ("python",),
        ("local-api",),
        ("synthetic",),
    )
    atomic_policy = AtomicPolicyKey(
        scope,
        PolicyFactor("feature.atomic", Operation.ADD),
        "oracle_evaluable_secure_code_yield",
    )
    pair_policy = pair_policy_key(
        scope,
        (
            PolicyFactor("feature.pair.first", Operation.ADD),
            PolicyFactor("feature.pair.second", Operation.ADD),
        ),
        outcome_id="oracle_evaluable_secure_code_yield",
    )
    records = {
        PolicyTrack.ATOMIC: ModelBoundCandidateRecord(
            atomic_policy.policy_key,
            "model-a",
            "phase-context-policy-v3",
            "3.0",
        ),
        PolicyTrack.PAIR: ModelBoundCandidateRecord(
            pair_policy.policy_key,
            "model-a",
            "phase-context-policy-v3",
            "3.0",
        ),
    }
    sources = []
    for track, selector_ids in (
        (PolicyTrack.ATOMIC, ("atomic_full", "atomic_rd_only")),
        (PolicyTrack.PAIR, ("pair_full", "pair_no_relation")),
    ):
        record = records[track]
        for selector_id in selector_ids:
            sources.append(
                FixedSlotSource(
                    track,
                    selector_id,
                    "model-a",
                    f"universe-{track.value}",
                    (SelectorSlot(1, SlotStatus.FILLED, record.policy_key, None),),
                    (record,),
                )
            )
    ledger = freeze_fixed_slot_ledger(
        "phase-context-policy-v3",
        "3.0",
        sources,
    )
    union = freeze_shared_confirmation_union(ledger)
    protocol_ids = {
        item.candidate_record_id: f"protocol-record-{item.track.value}"
        for item in union.entries
    }
    dispatch = freeze_confirmation_dispatch(union, protocol_ids)
    randomization_plan = TargetRandomizationPlan(
        "phase-context-policy-v3",
        "3.0",
        7331,
        1771,
        4,
        4,
    )
    task_bundles = []
    for entry in union.entries:
        record = next(
            item
            for item in dispatch.records
            if item.candidate_record_id == entry.candidate_record_id
        )
        arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if entry.track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        for task_index in range(10):
            task_unit_id = f"{entry.track.value}-task-{task_index:02d}"
            task_bundle_id = f"bundle-{entry.track.value}-{task_index:02d}"
            task_bundles.append(
                TargetTaskBundle(
                    entry.candidate.policy_key,
                    entry.track,
                    task_unit_id,
                    f"{task_unit_id}-instance",
                    "stratum-synthetic",
                    "realization-1",
                    task_bundle_id,
                    record.protocol_record_id,
                    1.0,
                    1.0,
                    tuple(
                        TargetTaskArmVariant(
                            arm,
                            content_hash((entry.track.value, task_index, arm.value)),
                        )
                        for arm in arms
                    ),
                )
            )
    frozen_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    assignments = randomize_target_confirmation(
        dispatch,
        randomization_plan,
        frozen_bundles,
    )
    return dispatch, randomization_plan, frozen_bundles, assignments


@pytest.mark.reviewer
def test_formal_budget_preflight_replays_dispatch_blocks_and_rejects_drift() -> None:
    budget = _accepted_budget(_qualification_manifest())
    dispatch, randomization_plan, task_bundles, assignments = _dispatch_and_assignments()

    preflight = validate_formal_budget_preflight(budget, dispatch, assignments)

    assert preflight.status == "PASS"
    assert preflight.provider_calls_authorized is True
    assert preflight.atomic_effect_records == 1
    assert preflight.pair_effect_records == 1
    assert preflight.generation_calls == 80
    assert preflight.materialization_calls == 40
    assert preflight.external_call_reservation == 200
    assert verify_formal_budget_preflight(
        budget,
        dispatch,
        assignments,
        preflight,
    )["status"] == "FORMAL_BUDGET_PREFLIGHT_VERIFIED"
    assert verify_target_randomization(
        dispatch,
        randomization_plan,
        task_bundles,
        assignments,
    )["status"] == "TARGET_RANDOMIZATION_VERIFIED"
    tampered_assignments = tuple(
        sorted(
            (
                replace(assignments[0], variant_sha256=content_hash("tampered-variant")),
                *assignments[1:],
            ),
            key=lambda item: item.assignment_id,
        )
    )
    with pytest.raises(ValueError, match="independent randomization replay"):
        verify_target_randomization(
            dispatch,
            randomization_plan,
            task_bundles,
            tampered_assignments,
        )

    atomic_entry = next(
        item for item in dispatch.union.entries if item.track is PolicyTrack.ATOMIC
    )
    second_model_record = ModelBoundCandidateRecord(
        atomic_entry.candidate.policy_key,
        "model-b",
        "phase-context-policy-v3",
        "3.0",
    )
    shared_sources = tuple(
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            model_id,
            f"shared-policy-universe-{model_id}",
            (SelectorSlot(1, SlotStatus.FILLED, record.policy_key, None),),
            (record,),
        )
        for model_id, record in (
            ("model-a", atomic_entry.candidate),
            ("model-b", second_model_record),
        )
    )
    shared_union = freeze_shared_confirmation_union(
        freeze_fixed_slot_ledger(
            "phase-context-policy-v3",
            "3.0",
            shared_sources,
        )
    )
    shared_protocol = {
        item.candidate_record_id: "shared-protocol-record"
        for item in shared_union.entries
    }
    assert len(freeze_confirmation_dispatch(shared_union, shared_protocol).records) == 2
    split_protocol = dict(shared_protocol)
    split_protocol[shared_union.entries[-1].candidate_record_id] = "second-protocol-record"
    with pytest.raises(ValueError, match="share one bridge/protocolization"):
        freeze_confirmation_dispatch(shared_union, split_protocol)

    with pytest.raises(StudyDesignError, match="model-bound dispatch"):
        validate_formal_budget_preflight(
            budget,
            dispatch,
            (replace(assignments[0], model_id="model-b"), *assignments[1:]),
        )
    with pytest.raises(StudyDesignError, match="identities are not unique"):
        validate_formal_budget_preflight(
            budget,
            dispatch,
            (*assignments, assignments[0]),
        )
    same_block = next(
        item
        for item in assignments[1:]
        if item.block_id == assignments[0].block_id
    )
    with pytest.raises(StudyDesignError, match="request-randomness slots"):
        validate_formal_budget_preflight(
            budget,
            dispatch,
            (
                replace(
                    assignments[0],
                    request_randomness_slot=same_block.request_randomness_slot,
                ),
                *assignments[1:],
            ),
        )
    blocked = replace(
        budget,
        status=QualificationStatus.BLOCKED,
        blockers=("manual_block",),
    )
    with pytest.raises(StudyDesignError, match="ACCEPTED RQ1 budget"):
        validate_formal_budget_preflight(blocked, dispatch, assignments)


@pytest.mark.reviewer
def test_target_two_freeze_lineage_closes_and_independently_replays(
    tmp_path: Path,
) -> None:
    dispatch, randomization_plan, task_bundles, assignments = _dispatch_and_assignments()
    manifest = _qualification_manifest(
        confirmation_task_ids=tuple(
            sorted({item.task_unit_id for item in assignments})
        )
    )
    budget = _accepted_budget(manifest)
    ledger = dispatch.union.ledger
    union = dispatch.union
    preflight = validate_formal_budget_preflight(budget, dispatch, assignments)
    discovery = freeze_target_discovery_design(
        schema_version="3.0",
        manifest=manifest,
        qualification_bundle=budget.qualification_bundle,
        budget=budget,
        identity_and_scope_decision=_artifact_ref("identity-and-scope-v1"),
        candidate_universe_contract=_artifact_ref("candidate-universe-v1"),
        support_gate_contract=_artifact_ref("support-gate-v1"),
        candidate_fold_manifests=_artifact_ref("candidate-folds-v1"),
        selector_contract=_artifact_ref("selector-contract-v1"),
        discovery_outcome_contract=_artifact_ref("discovery-outcome-contract-v1"),
    )
    confirmation = freeze_target_confirmation_design(
        discovery=discovery,
        budget=budget,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        outcome_contract=_artifact_ref("confirmation-outcome-contract-v1"),
    )
    index = freeze_target_study_index(discovery, confirmation)

    verification = verify_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )

    assert verification["status"] == "TARGET_STUDY_FREEZE_VERIFIED"
    assert verification["confirmation_outcomes_used"] is False
    assert confirmation.protocolization_results.artifact_id == content_id(
        "target_task_bundles_", task_bundles
    )
    assert confirmation.randomization_plan.artifact_id == (
        randomization_plan.target_randomization_plan_id
    )
    assert confirmation.model_bound_assignments.sha256 == (
        preflight.assignment_manifest_sha256
    )
    with pytest.raises(ValueError, match="confirmation freeze lineage"):
        verify_target_study_freezes(
            manifest=manifest,
            budget=budget,
            discovery=discovery,
            ledger=ledger,
            union=union,
            dispatch=dispatch,
            randomization_plan=randomization_plan,
            task_bundles=task_bundles,
            assignments=assignments,
            preflight=preflight,
            confirmation=replace(
                confirmation,
                model_bound_assignments=_artifact_ref("tampered-assignments"),
            ),
            index=index,
        )

    outcomes = []
    for assignment in assignments:
        task_index = int(assignment.task_unit_id.rsplit("-", 1)[1])
        if assignment.track is PolicyTrack.ATOMIC:
            secure = int(
                task_index < (
                    8 if assignment.arm.value == "atomic_target" else 2
                )
            )
        else:
            secure = int(
                task_index < (8 if assignment.arm.value == "pair_11" else 2)
            )
        outcomes.append(
            Outcome(
                assignment.assignment_id,
                1,
                1,
                secure,
                secure,
                1,
                secure,
                secure,
                None,
            )
        )
    evidence_ledger = freeze_assigned_arm_evidence(
        dispatch,
        assignments,
        outcomes,
    )
    evidence = estimate_target_itt(
        evidence_ledger,
        budget.power_and_margin_memo.target_itt_plan(),
        evidence_level=EvidenceLevel.EXECUTED,
    )
    yields = build_target_selector_yields(evidence)
    unauthorised_report = build_target_rq_tables(evidence, yields)
    assert unauthorised_report["scientific_claim_allowed"] is False
    assert unauthorised_report["report_status"] == (
        "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
    )
    authorization = authorize_target_report(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        execution_environment=_artifact_ref("formal-execution-environment-v1"),
        execution_command=_artifact_ref("formal-execution-command-v1"),
        provider_call_ledger=_artifact_ref("formal-provider-call-ledger-v1"),
    )
    assert verify_formal_report_authorization(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        authorization=authorization,
    )["status"] == "FORMAL_REPORT_AUTHORIZATION_VERIFIED"
    report = build_target_rq_tables(evidence, yields, authorization)
    assert report["report_status"] == "FORMAL_REPORT_AUTHORIZED"
    assert report["scientific_claim_allowed"] is True
    assert verify_target_rq_tables(
        evidence,
        yields,
        report,
        authorization,
    )["scientific_claim_allowed"] is True

    result_root = tmp_path / "target-result"
    written = write_target_result_bundle(
        result_root,
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
        authorization=authorization,
    )
    assert written["status"] == "TARGET_RESULT_BUNDLE_VERIFIED"
    assert written["scientific_claim_allowed"] is True
    assert load_and_verify_target_result_bundle(result_root) == written
    assert main(["target-study", "verify-result", str(result_root)]) == 0

    tampered_artifacts = {
        path.name: read_json(path)
        for path in result_root.iterdir()
        if path.name != "manifest.json"
    }
    tampered_artifacts["rq_tables.json"]["scientific_claim_allowed"] = False
    tampered_root = tmp_path / "tampered-target-result"
    write_bundle(tampered_root, tampered_artifacts)
    with pytest.raises(ValueError, match="RQ tables failed independent replay"):
        load_and_verify_target_result_bundle(tampered_root)

    randomization_artifacts = {
        path.name: read_json(path)
        for path in result_root.iterdir()
        if path.name != "manifest.json"
    }
    randomization_artifacts["target_randomization_plan.json"]["assignment_seed"] += 1
    randomization_root = tmp_path / "tampered-target-randomization"
    write_bundle(randomization_root, randomization_artifacts)
    with pytest.raises(ValueError, match="independent randomization replay"):
        load_and_verify_target_result_bundle(randomization_root)

    receipt_artifacts = {
        path.name: read_json(path)
        for path in result_root.iterdir()
        if path.name != "manifest.json"
    }
    receipt_artifacts["verification.json"]["assignment_count"] += 1
    receipt_root = tmp_path / "tampered-target-receipt"
    write_bundle(receipt_root, receipt_artifacts)
    with pytest.raises(ValueError, match="verification receipt"):
        load_and_verify_target_result_bundle(receipt_root)

    index_artifacts = {
        path.name: read_json(path)
        for path in result_root.iterdir()
        if path.name != "manifest.json"
    }
    index_artifacts["package_index.json"]["protocol_id"] = "tampered-protocol"
    index_root = tmp_path / "tampered-target-index"
    write_bundle(index_root, index_artifacts)
    with pytest.raises(ValueError, match="package index"):
        load_and_verify_target_result_bundle(index_root)

    tested_evidence = replace(evidence, evidence_level=EvidenceLevel.TESTED)
    tested_yields = build_target_selector_yields(tested_evidence)
    tested_root = tmp_path / "tested-target-result"
    tested = write_target_result_bundle(
        tested_root,
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=tested_evidence,
        yields=tested_yields,
    )
    assert tested["package_status"] == "NON_CLAIM_TEST_ARTIFACT"
    assert tested["scientific_claim_allowed"] is False

    legacy_root = tmp_path / "legacy-shaped-result"
    write_bundle(legacy_root, {"report.json": {"schema_version": "2.1"}})
    with pytest.raises(ValueError, match="file set is not exact"):
        load_and_verify_target_result_bundle(legacy_root)

    with pytest.raises(StudyDesignError, match="cannot authorize claims"):
        authorize_target_report(
            manifest=manifest,
            budget=budget,
            discovery=discovery,
            ledger=ledger,
            union=union,
            dispatch=dispatch,
            randomization_plan=randomization_plan,
            task_bundles=task_bundles,
            assignments=assignments,
            preflight=preflight,
            confirmation=confirmation,
            index=index,
            evidence=replace(evidence, evidence_level=EvidenceLevel.TESTED),
            yields=yields,
            execution_environment=_artifact_ref("test-environment"),
            execution_command=_artifact_ref("test-command"),
            provider_call_ledger=_artifact_ref("test-call-ledger"),
        )


@pytest.mark.reviewer
def test_qualification_plan_is_frozen_before_one_shot_acceptance() -> None:
    manifest = _qualification_manifest()
    plans = tuple(
        QualificationPlan(
            kind,
            (f"{kind.value}-candidate-1",),
            f"{kind.value}-candidate-1",
            f"{kind.value}-selection-rule-v1",
            (f"{kind.value}-acceptance-metric",),
            content_hash(f"{kind.value}-thresholds"),
            f"{kind.value}-tie-break-v1",
            "a" * 40,
        )
        for kind in QualificationProfileKind
    )
    bundle = qualification_plan_bundle(manifest, reversed(plans))

    dev_plans = tuple(
        replace(
            plan,
            selected_profile_id=None,
            code_commit=None,
            plan_phase=QualificationPlanPhase.DEV_ENVELOPE_LOCKED,
        )
        for plan in plans
    )
    dev_bundle = qualification_plan_bundle(manifest, reversed(dev_plans))
    assert dev_bundle.plan_phase is QualificationPlanPhase.DEV_ENVELOPE_LOCKED
    assert dev_bundle.acceptance_ready is False
    assert all(plan.selected_profile_id is None for plan in dev_bundle.plans)

    assert tuple(plan.profile_kind for plan in bundle.plans) == tuple(
        QualificationProfileKind
    )
    assert bundle.plan_phase is QualificationPlanPhase.ACCEPT_PLAN_FROZEN
    assert bundle.acceptance_ready is True
    assert bundle.qualification_accept_data_id == "QUAL-ACCEPT-001"
    assert bundle.acceptance_attempts_per_dataset == 1
    assert len(bundle.qualification_plan_bundle_id) > 64

    profile_results = tuple(
        QualificationProfileResult(
            plan.profile_kind,
            plan.selected_profile_id,
            _artifact_ref(f"{plan.profile_kind.value}-qualification-result"),
            QualificationStatus.ACCEPTED,
            bundle.qualification_accept_data_id,
            plan.code_commit,
            "PASS",
        )
        for plan in plans
    )
    accepted = freeze_qualification_bundle(
        manifest,
        bundle,
        profile_results,
        verifier_status="PASS",
    )
    assert accepted.formal_use_authorized is True

    blocked_profiles = (
        replace(
            profile_results[0],
            status=QualificationStatus.BLOCKED,
            independent_verifier_status="FAIL",
        ),
        *profile_results[1:],
    )
    blocked = replace(
        accepted,
        profiles=blocked_profiles,
        status=QualificationStatus.BLOCKED,
        verifier_status="FAIL",
    )
    assert blocked.formal_use_authorized is False
    with pytest.raises(ValueError, match="every profile and verifier"):
        replace(blocked, status=QualificationStatus.ACCEPTED)

    with pytest.raises(ValueError, match="new unexposed dataset"):
        replace(plans[0], failure_behavior="RETRY_SECOND_PROFILE")
    with pytest.raises(ValueError, match="DEV envelope cannot select"):
        replace(
            plans[0],
            plan_phase=QualificationPlanPhase.DEV_ENVELOPE_LOCKED,
        )
    with pytest.raises(TypeError, match="code_commit"):
        replace(plans[0], code_commit=None)
    with pytest.raises(ValueError, match="drifted from the frozen acceptance plan"):
        freeze_qualification_bundle(
            manifest,
            bundle,
            (
                replace(
                    profile_results[0],
                    selected_profile_id="fci-unfrozen-profile",
                ),
                *profile_results[1:],
            ),
            verifier_status="PASS",
        )


@pytest.mark.reviewer
def test_discovery_and_confirmation_are_two_separate_freeze_moments() -> None:
    references = [_artifact_ref(f"artifact-{index}") for index in range(24)]
    discovery = DiscoveryDesignFreeze(
        "phase-context-policy-v3",
        "3.0",
        *references[:9],
        atomic_top_k=3,
        pair_top_k=2,
        model_ids=("model-a", "model-b"),
    )
    confirmation = ConfirmationFreeze(
        "phase-context-policy-v3",
        "3.0",
        _artifact_ref(discovery.discovery_design_freeze_id),
        *references[9:22],
    )
    index = StudyFreezeIndex(
        "phase-context-policy-v3",
        _artifact_ref(discovery.discovery_design_freeze_id),
        _artifact_ref(confirmation.confirmation_freeze_id),
    )

    assert not hasattr(discovery, "fixed_slot_ledger")
    assert confirmation.fixed_slot_ledger == references[9]
    assert index.discovery_design_freeze.artifact_id == (
        discovery.discovery_design_freeze_id
    )
    assert index.confirmation_freeze.artifact_id == confirmation.confirmation_freeze_id

    with pytest.raises(ValueError, match="before outcomes"):
        replace(discovery, created_before_discovery_outcomes=False)
    with pytest.raises(ValueError, match="forbids rank pairing"):
        replace(discovery, rq2_comparison_semantics="continuous_selector_utility_interval")
    with pytest.raises(ValueError, match="before outcomes"):
        replace(confirmation, created_before_confirmation_outcomes=False)


def test_study_design_balances_units_without_crossing_exclusions() -> None:
    families = [f"family-{index}" for index in range(4)]
    candidates = []
    for family in families:
        for index in range(6):
            candidates.append(
                {
                    "task_unit_id": f"{family}-unit-{index}",
                    "cluster_id": f"{family}-cluster-{index}",
                    "family_id": family,
                    "primary_cwe": f"CWE-{index % 2}",
                    "representative_lineage_family": f"lineage-{index % 3}",
                }
            )
    exclusions = [
        {
            "task_unit_ids": ["family-0-unit-0", "family-1-unit-0"],
        }
    ]

    sample = _balanced_sample(
        candidates,
        exclusions,
        families,
        per_family=3,
        seed=17,
    )

    selected = {row["task_unit_id"] for row in sample}
    assert len(sample) == len(selected) == 12
    assert not {"family-0-unit-0", "family-1-unit-0"} <= selected
    assert {
        family: sum(row["family_id"] == family for row in sample) for family in families
    } == {family: 3 for family in families}
    assert all(
        len({row["primary_cwe"] for row in sample if row["family_id"] == family}) == 2
        for family in families
    )


def test_study_design_accepts_explicit_unequal_family_quotas() -> None:
    families = ["injection", "parser", "crypto"]
    candidates = [
        {
            "task_unit_id": f"{family}-{index}",
            "cluster_id": f"{family}-{index}",
            "family_id": family,
            "primary_cwe": f"CWE-{index % 2}",
            "representative_lineage_family": f"lineage-{index % 3}",
        }
        for family in families
        for index in range(6)
    ]

    sample = _balanced_sample(
        candidates,
        [],
        families,
        per_family={"injection": 4, "parser": 3, "crypto": 2},
        seed=19,
    )

    assert Counter(row["family_id"] for row in sample) == {
        "injection": 4,
        "parser": 3,
        "crypto": 2,
    }


def test_study_design_does_not_reject_a_family_with_one_lineage() -> None:
    candidates = [
        {
            "task_unit_id": f"crypto-{index}",
            "cluster_id": f"crypto-{index}",
            "family_id": "crypto",
            "primary_cwe": "CWE-338",
            "representative_lineage_family": "single-lineage",
        }
        for index in range(3)
    ]
    candidates.extend(
        {
            "task_unit_id": f"injection-{lineage}-{index}",
            "cluster_id": f"injection-{lineage}-{index}",
            "family_id": "injection",
            "primary_cwe": "CWE-78",
            "representative_lineage_family": lineage,
        }
        for lineage in ("single-lineage", "other-a", "other-b")
        for index in range(3)
    )

    sample = _balanced_sample(
        candidates,
        [],
        ["injection", "crypto"],
        per_family={"injection": 3, "crypto": 3},
        seed=23,
    )

    assert sum(row["family_id"] == "crypto" for row in sample) == 3
    assert {
        row["representative_lineage_family"]
        for row in sample
        if row["family_id"] == "crypto"
    } == {"single-lineage"}
    assert len(
        {
            row["representative_lineage_family"]
            for row in sample
            if row["family_id"] == "injection"
        }
    ) >= 2


def test_power_freeze_is_explicitly_assumption_conditional() -> None:
    design = _power_design(60, 0.20, 0.30, 0.05, 0.80)

    assert design["estimand"] == "paired_task_unit_weighted_target_minus_noop_itt"
    assert design["task_unit_count"] == 60
    assert design["achieved_normal_approximation_power"] == 0.80743
    assert design["power_gate_passed"] is True
    assert design["power_interpretation"] == (
        "assumption_conditional_not_observed_effect_evidence"
    )
    assert design["sensitivity"][-1] == {
        "discordant_pair_probability": 0.4,
        "power": 0.68777,
    }


def test_exposed_task_units_are_loaded_from_frozen_jsonl(tmp_path) -> None:
    sample = tmp_path / "exposed.jsonl"
    sample.write_text(
        '{"task_unit_id":"unit-a"}\n{"task_unit_id":"unit-b"}\n',
        encoding="utf-8",
    )

    assert _excluded_task_units([sample]) == {"unit-a", "unit-b"}


def test_priority_extensions_require_contracts_tests_and_supported_tiers() -> None:
    policy = {
        "common_requirements": {
            "minimum_requirements": 1,
            "minimum_source_test_references": 1,
        },
        "tiers": [
            {
                "tier_id": "python",
                "language": "python",
                "families": {"injection": ["CWE-77"]},
                "minimum_candidates_per_cwe": 1,
                "admission_blocker": "mechanism",
            },
            {
                "tier_id": "cross-language",
                "languages": ["go"],
                "admission_blocker": "runtime",
            },
        ],
    }

    def row(name: str, language: str, cwe: str, tested: bool = True) -> dict:
        return {
            "cluster_id": f"cluster-{name}",
            "contract_id": f"contract-{name}",
            "language": language,
            "primary_cwe": cwe,
            "representative_record_id": f"record-{name}",
            "representative_source": "fixture",
            "representative_lineage_family": "fixture",
            "requirement_count": 1,
            "source_test_available": tested,
            "source_test_reference_count": int(tested),
        }

    candidates = _priority_extensions(
        [
            row("python", "python", "CWE-77"),
            row("go", "go", "CWE-22"),
            row("untested", "python", "CWE-77", tested=False),
            row("java", "java", "CWE-77"),
        ],
        policy,
    )

    assert [(item["language"], item["priority_tier"]) for item in candidates] == [
        ("go", "cross-language"),
        ("python", "python"),
    ]
    assert all(item["current_formal_sample_eligible"] is False for item in candidates)

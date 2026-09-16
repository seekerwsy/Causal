from __future__ import annotations
from dataclasses import replace
from functools import cache
import pytest
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    TargetRandomizationPlan,
    TargetTaskArmVariant,
    TargetTaskBundle,
    randomize_target_confirmation,
)
from prompt_mechanism_study.prioritization import (
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
)
from prompt_mechanism_study.discovery_population import (
    CoverageAcquisitionMode,
    CoverageCellSupport,
    CoverageCensusPhase,
    CoverageTarget,
    CoverageTargetProfile,
    DiscoveryCoverageCensus,
    DiscoveryPopulationLineage,
    DiscoveryPopulationStatus,
    DiscoverySupplementationPlan,
    SupplementationDecision,
)
from prompt_mechanism_study.verification import (
    verify_formal_budget_preflight,
    verify_target_power_simulation,
    verify_target_randomization,
)
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    StudyFreezeIndex,
    validate_formal_budget_preflight,
)
from prompt_mechanism_study.study_planning import (
    ATOMIC_POWER_ARMS,
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
    StudyDesignError,
    TargetPowerAssumption,
    TargetPowerSimulationPlan,
    bind_target_power_to_assignments,
    freeze_qualification_bundle,
    freeze_power_and_margin_memo,
    qualify_rq1_baselines,
    qualify_rq1_budget,
    qualification_plan_bundle,
    simulate_target_power,
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
)


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


def _population_lineage(
    manifest: DataRoleManifest,
    qualification: QualificationBundle,
) -> DiscoveryPopulationLineage:
    target = CoverageTarget("context.test", 1)
    profile = CoverageTargetProfile(
        protocol_id=manifest.protocol_id,
        schema_version="4.0",
        representation_profile_id="representation-profile-test",
        representation_qualification_sha256=content_hash(qualification),
        catalog_sha256=content_hash("catalog-test"),

        targets=(target,),

        permitted_source_families=("test-source",),
        acquisition_mode=CoverageAcquisitionMode.CONTEXT_FIRST,
        maximum_source_records=0,
        maximum_new_task_units=0,
        maximum_review_task_units=0,
        maximum_task_units_per_lineage=1,
        minimum_source_lineage_diversity=1,


    )
    task_ids = tuple(
        sorted(
            task.task_unit_id
            for binding in manifest.bindings
            if binding.role is DataRole.DISCOVERY
            for task in binding.task_units
        )
    )
    cells = (CoverageCellSupport(target.target_id, len(task_ids)),)
    pre = DiscoveryCoverageCensus(
        profile.profile_id,
        manifest.data_role_manifest_id,
        content_id("test_discovery_population_", task_ids),
        profile.representation_profile_id,
        profile.catalog_sha256,
        CoverageCensusPhase.PRE_SUPPLEMENT,
        manifest.discovery_population_sha256,
        content_hash(qualification),
        task_ids,
        cells,
    )
    plan = DiscoverySupplementationPlan(
        profile.profile_id,
        pre.census_id,
        manifest.discovery_population_sha256,
        SupplementationDecision.NOT_REQUESTED,
        (),
        (),
        content_hash("future-evaluation-reservation-v1"),
        (),
        (),
        content_hash("near-duplicate-rule"),
        content_hash("exposure-policy"),
        content_hash("role-allocation-rule"),
        "0" * 40,
        False,
        0,
    )
    post = DiscoveryCoverageCensus(
        profile.profile_id,
        manifest.data_role_manifest_id,
        content_id("test_discovery_population_", task_ids),
        profile.representation_profile_id,
        profile.catalog_sha256,
        CoverageCensusPhase.POST_SUPPLEMENT,
        manifest.discovery_population_sha256,
        content_hash(qualification),
        task_ids,
        cells,
    )
    return DiscoveryPopulationLineage(
        profile,
        pre,
        plan,
        None,
        post,
        manifest.discovery_population_sha256,
        DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION,
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
    if scenario in {RQ1BudgetScenario.CORE_EXPERT, RQ1BudgetScenario.CORE_EXPERT_RANDOM}:
        selector_ids += ("atomic_blind_expert",)
    if scenario is RQ1BudgetScenario.CORE_EXPERT_RANDOM:
        selector_ids += ("atomic_seeded_random",)
    references = tuple(
        (
            (selector_id, model_id, _artifact_ref(f"{selector_id}-{model_id}-contract"))
            for selector_id in sorted(selector_ids)
            for model_id in model_ids
        )
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


def _power_plan(track: PolicyTrack, *, family_size: int = 2, task_units: int = 10):
    from prompt_mechanism_study.inference import TargetITTPlan

    probabilities = tuple(zip(ATOMIC_POWER_ARMS, (0.79, 0.01, 0.1, 0.1), strict=True))
    assumption = TargetPowerAssumption(
        f"{track.value}-planning-high-effect",
        track,
        probabilities,
        0.0,
        0.0,
        ((0.0, 0.0, 0.0, 0.0),),
        0.95,
        0.0,
        0.0,
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
        0.01,
        1000,
        20260831 + 0,
        (assumption,),
        (1.0,),
        (("stratum-synthetic", task_units),),
        "shared",
        TargetITTPlan(2026083103, 100, 0.05, 2, 0.9, 0.05, 0.2),
    )
    return plan


@cache
def _power_result(track, *, family_size=2, task_units=10):
    # Reuse immutable fixture results; independent verifier replays remain uncached.
    return simulate_target_power(_power_plan(track, family_size=family_size, task_units=task_units))


def test_explicit_power_replays_partial_overlap_realizations_and_task_identity(monkeypatch):
    from prompt_mechanism_study import study_planning
    from prompt_mechanism_study.verification.qualification import _independent_power_assignments
    plan = _power_plan(PolicyTrack.ATOMIC, family_size=3, task_units=14)
    support = tuple((j, f"task-{i + j * 7:02d}", "stratum-synthetic", i // 7)
                    for j in range(3) for i in range(14))
    plan = replace(plan, global_realizations=2, realization_weights=(0.5, 0.5),
                   family_task_overlap="explicit", task_support=support,
                   assumptions=tuple(replace(a, realization_arm_probability_offsets=((0.0,) * 4,) * 2)
                                     for a in plan.assumptions))
    _, rows = study_planning._power_assignments(plan)
    assert rows == _independent_power_assignments(plan)
    assert len({row.task_unit_id for group in rows for row in group}) == 28
    assert len(support) == 42
    # The same task can have different realizations in different policies.
    shared = [[row for row in group if row.task_unit_id == "task-07"][0] for group in rows[:2]]
    assert {row.realization_id for row in shared} == {"realization-0", "realization-1"}
    with monkeypatch.context() as patch:
        serial = iter(range(1000))
        patch.setattr(study_planning, "_power_uniform_block", lambda *args: [next(serial)] * 4)
        class AlwaysShare:
            def random(self):
                return 0.0
        draws = study_planning._power_task_draws(AlwaysShare(), plan.assumptions[0], plan, rows)
        by_unit = [{row.task_unit_id: value for row, value in zip(group, values)}
                   for group, values in zip(rows, draws)]
        assert by_unit[0]["task-07"] == by_unit[1]["task-07"]
        assert by_unit[0]["task-00"] != by_unit[1]["task-07"]  # Equal row ranks are not a shared task.
    result = simulate_target_power(plan)
    assert verify_target_power_simulation(result)["status"] == "TARGET_POWER_SIMULATION_VERIFIED"
    assert sum(n for _, n in result.scenarios[0].family_status_counts) == plan.simulation_replicates
    assert bind_target_power_to_assignments(plan, tuple(row for group in rows for row in group)) == plan
    with pytest.raises(ValueError, match="one stratum"):
        replace(plan, task_support=tuple(sorted((*support, (0, "task-00", "stratum-synthetic", 1)))))
    # Constant task contributions make every replicate non-evaluable; none may be removed.
    constant = replace(plan, assumptions=(replace(plan.assumptions[0],
        arm_secure_yield_probabilities=tuple(zip(ATOMIC_POWER_ARMS, (1.0, 0.0, 0.0, 0.0)))),))
    blocked = simulate_target_power(constant)
    assert blocked.minimum_achieved_power == 0.0 and not blocked.power_gate_passed
    assert blocked.scenarios[0].meaningful_replicates_by_coordinate == (0, 0, 0)
    assert verify_target_power_simulation(blocked)["power_gate_passed"] is False


def _power_memo(manifest: DataRoleManifest, *, atomic_family_size: int = 2) -> PowerAndMarginMemo:
    return freeze_power_and_margin_memo(
        manifest,
        code_commit="a" * 40,
        atomic_power=_power_result(PolicyTrack.ATOMIC, family_size=atomic_family_size),
        bootstrap_draws=100,
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
        atomic_task_units_per_effect=10,
        atomic_global_realizations=1,
        atomic_total_block_slots=4,
    )
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[scenario]
    family_size = selector_count * len(model_ids)
    power_memo = _power_memo(manifest, atomic_family_size=family_size)
    baseline_qualification = _baseline_qualification(
        manifest, scenario=scenario, model_ids=model_ids
    )
    return qualify_rq1_budget(
        scenario=scenario,
        dimensions=dimensions,
        power_and_margin_memo=power_memo,
        qualification_bundle=_accepted_qualification_bundle(
            manifest, power_memo, baseline_qualification
        ),
        baseline_qualification=baseline_qualification,
        provider_ceilings=_provider_ceilings(),
        independent_verifier_status="PASS",
    )


def _dispatch_and_assignments(*, partial_atomic=False):
    scope = AnalysisScope(
        "security.synthetic", "context.synthetic", ("python",), ("local-api",), ("synthetic",)
    )
    atomic_policy = AtomicPolicyKey(
        scope, PolicyFactor("feature.atomic", Operation.ADD), "oracle_evaluable_secure_code_yield"
    )
    records = {
        PolicyTrack.ATOMIC: ModelBoundCandidateRecord(
            atomic_policy.policy_key, "model-a", "phase-context-policy-v3", "3.0"
        )
    }
    sources = []
    for track, selector_ids in ((PolicyTrack.ATOMIC, ("atomic_full", "atomic_rd_only")),):
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
    second = None
    if partial_atomic:
        second = replace(
            records[PolicyTrack.ATOMIC], policy_key=content_id("atomic_policy_", "second-policy")
        )
        universe = tuple(
            sorted((records[PolicyTrack.ATOMIC], second), key=lambda row: row.policy_key)
        )
        sources = [
            replace(
                source,
                model_bound_records=universe,
                slots=(
                    (SelectorSlot(1, SlotStatus.FILLED, second.policy_key, None),)
                    if source.selector_id == "atomic_rd_only"
                    else source.slots
                ),
            )
            for source in sources
        ]
    ledger = freeze_fixed_slot_ledger("phase-context-policy-v3", "3.0", sources)
    union = freeze_shared_confirmation_union(ledger)
    protocol_ids = {
        item.candidate_record_id: (
            "protocol-record-atomic-second"
            if item.candidate == second
            else f"protocol-record-{item.track.value}"
        )
        for item in union.entries
    }
    dispatch = freeze_confirmation_dispatch(union, protocol_ids)
    randomization_plan = TargetRandomizationPlan(
        "phase-context-policy-v3",
        "3.0",
        7331,
        1771,
        4,
        tuple(
            sorted(((entry.candidate.policy_key, "realization-1", 1.0) for entry in union.entries))
        ),
        tuple(
            sorted(
                (
                    (
                        entry.candidate.policy_key,
                        f"{entry.track.value}-task-{i:02d}",
                        "stratum-synthetic",
                    )
                    for entry in union.entries
                    for i in (range(5, 15) if entry.candidate == second else range(10))
                )
            )
        ),
    )
    task_bundles = []
    for entry in union.entries:
        record = next(
            (
                item
                for item in dispatch.records
                if item.candidate_record_id == entry.candidate_record_id
            )
        )
        arms = ATOMIC_CONFIRMATORY_ARMS
        for task_index in range(5, 15) if entry.candidate == second else range(10):
            task_unit_id = f"{entry.track.value}-task-{task_index:02d}"
            task_bundle_id = f"bundle-{entry.track.value}-{task_index:02d}"
            if entry.candidate == second:
                task_bundle_id = f"bundle-atomic-second-{task_index:02d}"
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
                        (
                            TargetTaskArmVariant(
                                arm, content_hash((entry.track.value, task_index, arm.value))
                            )
                            for arm in arms
                        )
                    ),
                )
            )
    frozen_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    assignments = randomize_target_confirmation(dispatch, randomization_plan, frozen_bundles)
    return (dispatch, randomization_plan, frozen_bundles, assignments)


def test_formal_budget_preflight_replays_dispatch_blocks_and_rejects_drift() -> None:
    budget = _accepted_budget(_qualification_manifest())
    dispatch, randomization_plan, task_bundles, assignments = _dispatch_and_assignments()
    preflight = validate_formal_budget_preflight(budget, dispatch, assignments)
    assert preflight.status == "PASS"
    assert preflight.provider_calls_authorized is True
    assert preflight.atomic_effect_records == 1
    assert preflight.generation_calls == 40
    assert preflight.materialization_calls == 20
    assert preflight.external_call_reservation == 100
    assert (
        verify_formal_budget_preflight(budget, dispatch, assignments, preflight)["status"]
        == "FORMAL_BUDGET_PREFLIGHT_VERIFIED"
    )
    assert (
        verify_target_randomization(dispatch, randomization_plan, task_bundles, assignments)[
            "status"
        ]
        == "TARGET_RANDOMIZATION_VERIFIED"
    )
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
            dispatch, randomization_plan, task_bundles, tampered_assignments
        )
    atomic_entry = next(
        (item for item in dispatch.union.entries if item.track is PolicyTrack.ATOMIC)
    )
    second_model_record = ModelBoundCandidateRecord(
        atomic_entry.candidate.policy_key, "model-b", "phase-context-policy-v3", "3.0"
    )
    shared_sources = tuple(
        (
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
    )
    shared_union = freeze_shared_confirmation_union(
        freeze_fixed_slot_ledger("phase-context-policy-v3", "3.0", shared_sources)
    )
    shared_protocol = {
        item.candidate_record_id: "shared-protocol-record" for item in shared_union.entries
    }
    assert len(freeze_confirmation_dispatch(shared_union, shared_protocol).records) == 2
    split_protocol = dict(shared_protocol)
    split_protocol[shared_union.entries[-1].candidate_record_id] = "second-protocol-record"
    with pytest.raises(ValueError, match="share one bridge/protocolization"):
        freeze_confirmation_dispatch(shared_union, split_protocol)
    with pytest.raises(StudyDesignError, match="model-bound dispatch"):
        validate_formal_budget_preflight(
            budget, dispatch, (replace(assignments[0], model_id="model-b"), *assignments[1:])
        )
    with pytest.raises(StudyDesignError, match="identities are not unique"):
        validate_formal_budget_preflight(budget, dispatch, (*assignments, assignments[0]))
    same_block = next(
        (item for item in assignments[1:] if item.block_id == assignments[0].block_id)
    )
    with pytest.raises(StudyDesignError, match="request-randomness slots"):
        validate_formal_budget_preflight(
            budget,
            dispatch,
            (
                replace(assignments[0], request_randomness_slot=same_block.request_randomness_slot),
                *assignments[1:],
            ),
        )
    blocked = replace(budget, status=QualificationStatus.BLOCKED, blockers=("manual_block",))
    with pytest.raises(StudyDesignError, match="ACCEPTED RQ1 budget"):
        validate_formal_budget_preflight(blocked, dispatch, assignments)


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


def test_discovery_and_confirmation_are_two_separate_freeze_moments() -> None:
    references = [_artifact_ref(f"artifact-{index}") for index in range(24)]
    manifest = _qualification_manifest()
    qualification = _accepted_qualification_bundle(manifest)
    population = _population_lineage(manifest, qualification)
    discovery = DiscoveryDesignFreeze(
        "phase-context-policy-v3",
        "3.0",
        references[0],
        references[1],
        population,
        population.accepted_population_manifest_sha256,
        population.accepted_population_manifest_sha256,
        references[3],
        references[4],
        references[5],
        references[6],
        references[7],
        references[8],
        references[9],
        references[10],
        atomic_top_k=3,
        model_ids=("model-a", "model-b"),
    )
    confirmation = ConfirmationFreeze(
        "phase-context-policy-v3",
        "3.0",
        _artifact_ref(discovery.discovery_design_freeze_id),
        *references[11:24],
    )
    index = StudyFreezeIndex(
        "phase-context-policy-v3",
        _artifact_ref(discovery.discovery_design_freeze_id),
        _artifact_ref(confirmation.confirmation_freeze_id),
    )
    assert not hasattr(discovery, "fixed_slot_ledger")
    assert confirmation.fixed_slot_ledger == references[11]
    assert index.discovery_design_freeze.artifact_id == discovery.discovery_design_freeze_id
    assert index.confirmation_freeze.artifact_id == confirmation.confirmation_freeze_id
    with pytest.raises(ValueError, match="before outcomes"):
        replace(discovery, created_before_discovery_outcomes=False)
    with pytest.raises(ValueError, match="forbids rank pairing"):
        replace(discovery, rq2_comparison_semantics="continuous_selector_utility_interval")
    with pytest.raises(ValueError, match="before outcomes"):
        replace(confirmation, created_before_confirmation_outcomes=False)


def test_actual_power_failure_blocks_preflight_and_retains_failed_results(monkeypatch):
    from prompt_mechanism_study import study_planning

    budget = _accepted_budget(_qualification_manifest())
    dispatch, _, _, assignments = _dispatch_and_assignments(partial_atomic=True)
    assignments = tuple(
        (replace(row, task_unit_id=f"degenerate-{row.task_unit_id}") for row in assignments)
    )
    before = content_hash(budget)
    monkeypatch.setattr(
        study_planning,
        "_power_task_draws",
        lambda rng, assumption, plan, groups: [[0.999] * len(group) for group in groups],
    )
    with pytest.raises(StudyDesignError, match="actual task-support power failed") as blocked:
        validate_formal_budget_preflight(budget, dispatch, assignments)
    results = blocked.value.power_results
    assert tuple((row.plan.track for row in results)) == (PolicyTrack.ATOMIC,)
    assert all((row.minimum_achieved_power == 0 and (not row.power_gate_passed) for row in results))
    assert content_hash(budget) == before

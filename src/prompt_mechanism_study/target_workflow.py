"""One bounded seven-stage reviewer smoke for the prospective target method.

The formal provider runner remains deliberately unavailable while the
prospective protocol is ``SPECIFIED_DRAFT``.  This module executes the exact
scientific stage functions on a deterministic, zero-network fixture and emits
an independently replayable ``NON_CLAIM_TEST_ARTIFACT``.  It is the smallest
representative proof that the target path closes without treating a test run as
study evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from prompt_mechanism_study.artifact_io import bundle_digest
from prompt_mechanism_study.inference import (
   EvidenceLevel,
   build_target_selector_yields,
   estimate_target_itt,
   freeze_assigned_arm_evidence,
)
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskArmVariant,
    TargetTaskBundle,
    randomize_target_confirmation,
)
from prompt_mechanism_study.interaction_selector import (
    PairCandidateUniverseManifest,
    PairShadowObservation,
    PairShadowPlan,
    freeze_pair_candidate_universe,
    freeze_pair_preoutcome_design,
    pair_preoutcome_observations,
    pair_shadow_data_sha256,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.measurement import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    OracleStatus,
    close_target_measurements,
)
from prompt_mechanism_study.mechanisms import (
    FactorialCompatibility,
    PairCompatibilityDecision,
    PairRelationEvidence,
)
from prompt_mechanism_study.outcomes import derive_outcomes
from prompt_mechanism_study.prioritization import (
    AtomicCandidateUniverseManifest,
    AtomicFCIBootstrapEvidence,
    AtomicShadowPlan,
    DiscoveryObservation,
    ConfirmationDispatchManifest,
    FixedSlotSource,
    PolicyTrack,
    atomic_preoutcome_observations,
    discovery_data_sha256,
    freeze_atomic_candidate_folds,
    freeze_atomic_candidate_universe,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
    run_atomic_shadow_qualification,
)
from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    DataRole,
    DataRoleBinding,
    DataRoleManifest,
    ModelBoundCandidateRecord,
    Operation,
    PairPolicyKey,
    PolicyFactor,
    TaskUnitDataRoleRecord,
    pair_policy_key,
    validate_data_role_firewall,
)
from prompt_mechanism_study.selector_analysis import write_target_result_bundle
from prompt_mechanism_study.verification import (
    load_and_verify_target_result_bundle,
    verify_target_study_freezes,
)
from prompt_mechanism_study.study_design import (
    ATOMIC_POWER_ARMS,
    PAIR_POWER_ARMS,
    FreezeArtifactReference,
    PowerAndMarginMemo,
    ProviderBudgetCeilings,
    ProviderCallKind,
    ProviderRate,
    ProviderTokenCostBasis,
    QualificationBundle,
    QualificationPlan,
    QualificationProfileKind,
    QualificationProfileResult,
    QualificationStatus,
    RQ1BaselineQualification,
    RQ1BudgetDimensions,
    RQ1BudgetQualification,
    RQ1BudgetScenario,
    TargetPowerAssumption,
    TargetPowerSimulationPlan,
    TargetPowerSimulationResult,
    freeze_power_and_margin_memo,
    freeze_qualification_bundle,
    freeze_target_confirmation_design,
    freeze_target_discovery_design,
    freeze_target_study_index,
    qualify_rq1_baselines,
    qualify_rq1_budget,
    qualification_plan_bundle,
    simulate_target_power,
    validate_formal_budget_preflight,
)


PROTOCOL_ID = "phase-context-policy-v3"
SCHEMA_VERSION = "3.0"
SMOKE_MODEL_ID = "reviewer-smoke-model"
SMOKE_CODE_COMMIT = "0" * 40
SMOKE_STAGES = (
    "representation",
    "prioritization",
    "hypothesis_freeze",
    "intervention_randomization",
    "measurement",
    "outcome_assembly",
    "inference_reporting",
)


@dataclass(frozen=True, slots=True)
class _SmokeDiscoveryInputs:
    atomic_policy: AtomicPolicyKey
    atomic_universe: AtomicCandidateUniverseManifest
    atomic_observations: tuple[DiscoveryObservation, ...]
    atomic_plan: AtomicShadowPlan
    pair_policy: PairPolicyKey
    pair_universe: PairCandidateUniverseManifest
    pair_observations: tuple[PairShadowObservation, ...]
    pair_plan: PairShadowPlan


def run_target_reviewer_smoke(output: Path) -> dict[str, object]:
    """Traverse the seven target stages once without network calls or claims."""

    if not isinstance(output, Path):
        raise TypeError("target reviewer smoke output must be a Path")

    # Stage 1: representation and the pre-discovery design boundary.
    manifest = _smoke_role_manifest()
    firewall = validate_data_role_firewall(
        manifest,
        {
            "DISCOVERY-SMOKE": DataRole.DISCOVERY,
            "CONFIRMATION-SMOKE": DataRole.CONFIRMATION,
        },
    )
    budget = _smoke_budget(manifest)
    inputs = _smoke_discovery_inputs()
    atomic_folds = freeze_atomic_candidate_folds(
        inputs.atomic_universe,
        atomic_preoutcome_observations(inputs.atomic_observations),
        inputs.atomic_plan,
    )
    pair_preoutcome = freeze_pair_preoutcome_design(
        inputs.pair_universe,
        pair_preoutcome_observations(inputs.pair_observations),
        inputs.pair_plan,
    )
    discovery = freeze_target_discovery_design(
        schema_version=SCHEMA_VERSION,
        manifest=manifest,
        qualification_bundle=budget.qualification_bundle,
        budget=budget,
        identity_and_scope_decision=_artifact_reference(
            "reviewer_smoke_identity_scope_",
            (inputs.atomic_policy, inputs.pair_policy),
        ),
        candidate_universe_contract=_artifact_reference(
            "reviewer_smoke_candidate_universes_",
            (inputs.atomic_universe, inputs.pair_universe),
        ),
        support_gate_contract=_artifact_reference(
            "reviewer_smoke_support_gates_",
            (
                inputs.atomic_universe.supported_policy_keys,
                pair_preoutcome.support_gates,
            ),
        ),
        candidate_fold_manifests=_artifact_reference(
            "reviewer_smoke_candidate_folds_",
            (atomic_folds, pair_preoutcome),
        ),
        selector_contract=_artifact_reference(
            "reviewer_smoke_selector_contracts_",
            (inputs.atomic_plan, inputs.pair_plan),
        ),
        discovery_outcome_contract=_artifact_reference(
            "reviewer_smoke_discovery_outcome_",
            "oracle_evaluable_secure_code_yield",
        ),
    )

    # Stage 2: both sole-difference Core selector pairs consume the frozen folds.
    atomic_fci_evidence = _smoke_atomic_fci_evidence(
        inputs.atomic_universe,
        inputs.atomic_policy,
    )
    pair_relation_evidence = _smoke_pair_relation_evidence(
        inputs.pair_policy,
        inputs.pair_observations,
    )
    atomic = run_atomic_shadow_qualification(
        inputs.atomic_universe,
        inputs.atomic_observations,
        inputs.atomic_plan,
        atomic_fci_evidence,
        fold_freeze=atomic_folds,
    )
    pair = run_pair_shadow_qualification(
        inputs.pair_universe,
        inputs.pair_observations,
        pair_relation_evidence,
        inputs.pair_plan,
        preoutcome_freeze=pair_preoutcome,
    )
    sources = (
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            SMOKE_MODEL_ID,
            inputs.atomic_universe.universe_id,
            atomic.full.slots,
            inputs.atomic_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_rd_only",
            SMOKE_MODEL_ID,
            inputs.atomic_universe.universe_id,
            atomic.rd_only.slots,
            inputs.atomic_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_full",
            SMOKE_MODEL_ID,
            inputs.pair_universe.universe_id,
            pair.full.slots,
            inputs.pair_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_no_relation",
            SMOKE_MODEL_ID,
            inputs.pair_universe.universe_id,
            pair.no_relation.slots,
            inputs.pair_universe.model_bound_records,
        ),
    )

    # Stage 3: fixed slots, one shared union, and one protocolization per policy.
    ledger = freeze_fixed_slot_ledger(PROTOCOL_ID, SCHEMA_VERSION, sources)
    union = freeze_shared_confirmation_union(ledger)
    protocol_records = {
        entry.candidate_record_id: content_id(
            "reviewer_smoke_protocol_record_",
            entry.candidate.policy_key,
        )
        for entry in union.entries
    }
    dispatch = freeze_confirmation_dispatch(union, protocol_records)

    # Stage 4: model-bound complete blocks and the second, pre-outcome freeze.
    task_bundles = _smoke_task_bundles(dispatch)
    randomization_plan = TargetRandomizationPlan(
        PROTOCOL_ID,
        SCHEMA_VERSION,
        2026083107,
        2026083108,
        budget.dimensions.atomic_total_block_slots,
        budget.dimensions.pair_total_block_slots,
    )
    assignments = randomize_target_confirmation(
        dispatch,
        randomization_plan,
        task_bundles,
    )
    preflight = validate_formal_budget_preflight(budget, dispatch, assignments)
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
        outcome_contract=_artifact_reference(
            "reviewer_smoke_confirmation_outcome_",
            "assigned_arm_task_unit_itt_v1",
        ),
    )
    index = freeze_target_study_index(discovery, confirmation)
    freeze_verification = verify_target_study_freezes(
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

    # Stage 5: deterministic local measurements; no provider is contacted.
    measurement_ledger = close_target_measurements(
        assignments,
        _smoke_measurements(assignments),
        study_id=content_id("target_reviewer_smoke_study_", index),
        randomization_id=randomization_plan.target_randomization_plan_id,
        adapter_bundle_id=content_id("target_reviewer_smoke_adapters_", "local"),
    )

    # Stage 6: total assigned-arm outcome assembly retains every assignment.
    outcomes = derive_outcomes(measurement_ledger)
    evidence_ledger = freeze_assigned_arm_evidence(
        dispatch,
        assignments,
        outcomes,
    )

    # Stage 7: task-unit ITT, fixed-K tables, exact package, independent replay.
    evidence = estimate_target_itt(
        evidence_ledger,
        budget.power_and_margin_memo.target_itt_plan(),
        evidence_level=EvidenceLevel.TESTED,
    )
    yields = build_target_selector_yields(evidence)
    written = write_target_result_bundle(
        output,
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
    )
    independently_verified = load_and_verify_target_result_bundle(output)
    if independently_verified != written:
        raise ValueError("target reviewer smoke changed under independent reload")

    return {
        "status": "TARGET_REVIEWER_SMOKE_VERIFIED",
        "protocol_status": "SPECIFIED_DRAFT",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "stages": list(SMOKE_STAGES),
        "stage_count": len(SMOKE_STAGES),
        "data_role_firewall_validation_id": firewall["firewall_validation_id"],
        "discovery_design_freeze_id": discovery.discovery_design_freeze_id,
        "confirmation_freeze_id": confirmation.confirmation_freeze_id,
        "study_freeze_index_id": index.study_freeze_index_id,
        "freeze_verification_status": freeze_verification["status"],
        "assignment_count": len(assignments),
        "measurement_count": len(measurement_ledger.measurements),
        "outcome_count": len(outcomes),
        "provider_calls_made": 0,
        "evidence_level": evidence.evidence_level.value,
        "package_status": written["package_status"],
        "scientific_claim_allowed": written["scientific_claim_allowed"],
        "result_bundle_sha256": bundle_digest(output),
    }


def _artifact_reference(prefix: str, value: object) -> FreezeArtifactReference:
    return FreezeArtifactReference(content_id(prefix, value), content_hash(value))


def _smoke_task_record(task_unit_id: str) -> TaskUnitDataRoleRecord:
    return TaskUnitDataRoleRecord(
        task_unit_id,
        f"near-duplicate-{task_unit_id}",
        f"lineage-{task_unit_id}",
        (),
        "reviewer-smoke-role-assignment-v1",
    )


def _atomic_discovery_task_ids() -> tuple[str, ...]:
    return tuple(f"atomic-discovery-task-{index:02d}" for index in range(24))


def _pair_discovery_task_ids() -> tuple[str, ...]:
    return tuple(
        f"pair-discovery-{cell}-{index:02d}"
        for cell in ("00", "01", "10", "11")
        for index in range(8)
    )


def _confirmation_task_ids() -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                *(f"atomic-smoke-task-{index:02d}" for index in range(10)),
                *(f"pair-smoke-task-{index:02d}" for index in range(10)),
            )
        )
    )


def _smoke_role_manifest() -> DataRoleManifest:
    discovery_ids = tuple(sorted((*_atomic_discovery_task_ids(), *_pair_discovery_task_ids())))
    confirmation_ids = _confirmation_task_ids()
    bindings = (
        DataRoleBinding(
            "CONFIRMATION-SMOKE",
            DataRole.CONFIRMATION,
            tuple(_smoke_task_record(item) for item in confirmation_ids),
            content_hash(confirmation_ids),
        ),
        DataRoleBinding(
            "DISCOVERY-SMOKE",
            DataRole.DISCOVERY,
            tuple(_smoke_task_record(item) for item in discovery_ids),
            content_hash(discovery_ids),
        ),
        DataRoleBinding(
            "LEGACY-SMOKE",
            DataRole.LEGACY_ONLY,
            (
                replace(
                    _smoke_task_record("legacy-smoke-task"),
                    exposure_history=("reviewer_smoke_historical_only",),
                ),
            ),
            content_hash("legacy-smoke-task"),
        ),
        DataRoleBinding(
            "QUAL-ACCEPT-SMOKE",
            DataRole.QUAL_ACCEPT,
            (_smoke_task_record("qual-accept-smoke-task"),),
            content_hash("qual-accept-smoke-task"),
        ),
        DataRoleBinding(
            "QUAL-DEV-SMOKE",
            DataRole.QUAL_DEV,
            (_smoke_task_record("qual-dev-smoke-task"),),
            content_hash("qual-dev-smoke-task"),
        ),
    )
    return DataRoleManifest(
        PROTOCOL_ID,
        content_hash("reviewer-smoke-source-manifest"),
        bindings,
    )


def _smoke_power_result(track: PolicyTrack) -> TargetPowerSimulationResult:
    probabilities = (
        tuple(zip(ATOMIC_POWER_ARMS, (0.79, 0.01, 0.10, 0.10), strict=True))
        if track is PolicyTrack.ATOMIC
        else tuple(zip(PAIR_POWER_ARMS, (0.01, 0.01, 0.01, 0.79), strict=True))
    )
    assumption = TargetPowerAssumption(
        f"reviewer-smoke-{track.value}-power",
        track,
        probabilities,
        0.0,
        0.0,
        0.01,
        0.0,
        0.1,
        0.1,
    )
    return simulate_target_power(
        TargetPowerSimulationPlan(
            track,
            0.05,
            2,
            10,
            1,
            2,
            2,
            4,
            0.05,
            0.8,
            1000,
            2026083104 + (0 if track is PolicyTrack.ATOMIC else 1),
            (assumption,),
        )
    )


def _smoke_power_memo(manifest: DataRoleManifest) -> PowerAndMarginMemo:
    return freeze_power_and_margin_memo(
        manifest,
        code_commit=SMOKE_CODE_COMMIT,
        atomic_power=_smoke_power_result(PolicyTrack.ATOMIC),
        pair_power=_smoke_power_result(PolicyTrack.PAIR),
        bootstrap_draws=100,
        bootstrap_seed=2026083106,
        minimum_valid_bootstrap_fraction=0.9,
        maximum_unknown_fraction_among_valid=0.2,
        independent_verifier_status="PASS",
    )


def _smoke_baseline_qualification(
    manifest: DataRoleManifest,
) -> RQ1BaselineQualification:
    return qualify_rq1_baselines(
        protocol_id=PROTOCOL_ID,
        scenario=RQ1BudgetScenario.CORE,
        model_ids=(SMOKE_MODEL_ID,),
        qualification_accept_data_id=manifest.qualification_accept_data_id,
        code_commit=SMOKE_CODE_COMMIT,
        contract_references=(),
        independent_verifier_status="PASS",
    )


def _smoke_qualification_bundle(
    manifest: DataRoleManifest,
    power_memo: PowerAndMarginMemo,
    baseline: RQ1BaselineQualification,
) -> QualificationBundle:
    plans = []
    for kind in QualificationProfileKind:
        profile_id = (
            baseline.selected_profile_id
            if kind is QualificationProfileKind.RQ1_BASELINES
            else f"reviewer-smoke-{kind.value}-profile"
        )
        plans.append(
            QualificationPlan(
                kind,
                (profile_id,),
                profile_id,
                f"reviewer-smoke-{kind.value}-selection-rule-v1",
                (f"reviewer-smoke-{kind.value}-acceptance-metric",),
                content_hash(("reviewer-smoke-thresholds", kind.value)),
                f"reviewer-smoke-{kind.value}-tie-break-v1",
                SMOKE_CODE_COMMIT,
            )
        )
    frozen_plans = tuple(plans)
    plan_bundle = qualification_plan_bundle(manifest, frozen_plans)
    results = tuple(
        QualificationProfileResult(
            plan.profile_kind,
            plan.selected_profile_id,
            (
                FreezeArtifactReference(
                    power_memo.power_and_margin_memo_id,
                    content_hash(power_memo),
                )
                if plan.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
                else FreezeArtifactReference(
                    baseline.rq1_baseline_qualification_id,
                    content_hash(baseline),
                )
                if plan.profile_kind is QualificationProfileKind.RQ1_BASELINES
                else _artifact_reference(
                    f"reviewer_smoke_{plan.profile_kind.value}_qualification_",
                    plan.selected_profile_id,
                )
            ),
            QualificationStatus.ACCEPTED,
            manifest.qualification_accept_data_id,
            SMOKE_CODE_COMMIT,
            "PASS",
        )
        for plan in frozen_plans
    )
    return freeze_qualification_bundle(
        manifest,
        plan_bundle,
        results,
        verifier_status="PASS",
    )


def _smoke_provider_ceilings() -> ProviderBudgetCeilings:
    rates = tuple(
        ProviderRate(
            kind,
            f"reviewer-smoke-{kind.value}-provider",
            index + 1,
            _artifact_reference(
                f"reviewer_smoke_{kind.value}_pricing_",
                index + 1,
            ),
            ProviderTokenCostBasis(
                "CNY",
                "reviewer-smoke-local-region",
                f"reviewer-smoke-tier-{index + 1}",
                1,
                1,
                0,
                (index + 1) * 1_000_000,
                0,
            ),
        )
        for index, kind in enumerate(ProviderCallKind)
    )
    return ProviderBudgetCeilings(rates, 1_000, 1_000, 1_000, 3_000, 100_000)


def _smoke_budget(manifest: DataRoleManifest) -> RQ1BudgetQualification:
    power_memo = _smoke_power_memo(manifest)
    baseline = _smoke_baseline_qualification(manifest)
    qualification = _smoke_qualification_bundle(manifest, power_memo, baseline)
    return qualify_rq1_budget(
        scenario=RQ1BudgetScenario.CORE,
        dimensions=RQ1BudgetDimensions(
            (SMOKE_MODEL_ID,),
            atomic_top_k=1,
            pair_top_k=1,
            atomic_task_units_per_effect=10,
            pair_task_units_per_effect=10,
            atomic_global_realizations=1,
            pair_global_realizations=1,
            atomic_total_block_slots=4,
            pair_total_block_slots=4,
        ),
        power_and_margin_memo=power_memo,
        qualification_bundle=qualification,
        baseline_qualification=baseline,
        provider_ceilings=_smoke_provider_ceilings(),
        independent_verifier_status="PASS",
    )


def _smoke_discovery_inputs() -> _SmokeDiscoveryInputs:
    outcome_id = "oracle_evaluable_secure_code_yield"
    atomic_policy = AtomicPolicyKey(
        AnalysisScope(
            "security.reviewer-smoke.atomic",
            "context.reviewer-smoke.atomic",
            ("python",),
            ("local-api",),
            ("reviewer-smoke",),
        ),
        PolicyFactor("feature.reviewer-smoke.atomic", Operation.ADD),
        outcome_id,
    )
    atomic_observations = tuple(
        DiscoveryObservation(
            task_unit_id,
            SMOKE_MODEL_ID,
            "atomic-smoke-family",
            0,
            ((atomic_policy.policy_key, index % 2),),
            (("source_code", float((index // 2) % 2)),),
            index % 2,
        )
        for index, task_unit_id in enumerate(_atomic_discovery_task_ids())
    )
    atomic_record = ModelBoundCandidateRecord(
        atomic_policy.policy_key,
        SMOKE_MODEL_ID,
        PROTOCOL_ID,
        SCHEMA_VERSION,
    )
    atomic_universe = freeze_atomic_candidate_universe(
        (atomic_policy,),
        (atomic_record,),
        supported_policy_keys=(atomic_policy.policy_key,),
        realization_policy_ids={
            atomic_policy.policy_key: "reviewer-smoke-atomic-realization-policy"
        },
        candidate_family_ids={atomic_policy.policy_key: "atomic-smoke-family"},
        discovery_data_sha256=discovery_data_sha256(atomic_observations),
        positivity_audit_sha256=content_hash("reviewer-smoke-atomic-positivity"),
        information_budget_sha256=content_hash("reviewer-smoke-information-budget"),
        top_k=1,
        representation_adapter_id="reviewer-smoke-prompt-tsg-v3",
    )
    atomic_plan = AtomicShadowPlan(
        SMOKE_MODEL_ID,
        ("source_code",),
        4,
        0.05,
        2026083101,
        0.8,
        0.5,
    )
    pair_policy = pair_policy_key(
        AnalysisScope(
            "security.reviewer-smoke.pair",
            "context.reviewer-smoke.pair",
            ("python",),
            ("local-api",),
            ("reviewer-smoke",),
        ),
        (
            PolicyFactor("feature.reviewer-smoke.first", Operation.ADD),
            PolicyFactor("feature.reviewer-smoke.second", Operation.ADD),
        ),
        outcome_id=outcome_id,
    )
    factors = tuple(item.actionable_feature_id for item in pair_policy.factors)
    secure_counts = {"00": 1, "01": 2, "10": 2, "11": 7}
    pair_rows = []
    for x1, x2 in ((0, 0), (0, 1), (1, 0), (1, 1)):
        cell = f"{x1}{x2}"
        for index in range(8):
            pair_rows.append(
                PairShadowObservation(
                    pair_policy.policy_key,
                    f"pair-discovery-{cell}-{index:02d}",
                    SMOKE_MODEL_ID,
                    f"pair-smoke-lineage-{index % 2}",
                    "python",
                    "reviewer-smoke",
                    "local-api",
                    pair_policy.analysis_scope.context_query_id,
                    QueryState.PRESENT,
                    (
                        (factors[0], QueryState.PRESENT if x1 else QueryState.ABSENT),
                        (factors[1], QueryState.PRESENT if x2 else QueryState.ABSENT),
                    ),
                    ((factors[0], 0.99), (factors[1], 0.99)),
                    (("source_code", float(index % 2)),),
                    int(index < secure_counts[cell]),
                )
            )
    pair_observations = tuple(pair_rows)
    pair_record = ModelBoundCandidateRecord(
        pair_policy.policy_key,
        SMOKE_MODEL_ID,
        PROTOCOL_ID,
        SCHEMA_VERSION,
    )
    compatibility = PairCompatibilityDecision(
        pair_policy,
        FactorialCompatibility.COMPATIBLE,
        "reviewer-smoke-factorial-compatibility-v1",
        ("surface.reviewer-smoke.first", "surface.reviewer-smoke.second"),
        content_hash("reviewer-smoke-pair-compatibility"),
    )
    pair_universe = freeze_pair_candidate_universe(
        (pair_policy,),
        (compatibility,),
        (pair_record,),
        candidate_family_ids={pair_policy.policy_key: "pair-smoke-family"},
        discovery_data_sha256=pair_shadow_data_sha256(pair_observations),
        information_budget_sha256=content_hash("reviewer-smoke-information-budget"),
        top_k=1,
    )
    pair_plan = PairShadowPlan(
        SMOKE_MODEL_ID,
        ("source_code",),
        4,
        2,
        0.9,
        2,
        2026083102,
        0.05,
        20,
        2026083103,
        8,
        4,
        0.5,
        0.2,
    )
    return _SmokeDiscoveryInputs(
        atomic_policy,
        atomic_universe,
        atomic_observations,
        atomic_plan,
        pair_policy,
        pair_universe,
        pair_observations,
        pair_plan,
    )


def _smoke_atomic_fci_evidence(
    universe: AtomicCandidateUniverseManifest,
    policy: AtomicPolicyKey,
) -> AtomicFCIBootstrapEvidence:
    return AtomicFCIBootstrapEvidence(
        universe.universe_id,
        ((policy.policy_key, (True,) * 10),),
        content_hash("reviewer-smoke-atomic-fci-bootstrap"),
    )


def _smoke_pair_relation_evidence(
    policy: PairPolicyKey,
    observations: Sequence[PairShadowObservation],
) -> tuple[PairRelationEvidence, ...]:
    return tuple(
        PairRelationEvidence(
            policy.policy_key,
            "reviewer-smoke-relation-spec-v1",
            "reviewer-smoke-relation-v1",
            f"task-{row.task_unit_id}",
            row.task_unit_id,
            f"prompt-tsg-{row.task_unit_id}",
            "reviewer-smoke-relation-contract-v1",
            QueryState.PRESENT,
            (f"node-{row.task_unit_id}",),
            (),
        )
        for row in observations
    )


def _smoke_task_bundles(
    dispatch: ConfirmationDispatchManifest,
) -> tuple[TargetTaskBundle, ...]:
    dispatch_by_candidate = {
        item.candidate_record_id: item for item in dispatch.records
    }
    bundles = []
    for entry in dispatch.union.entries:
        record = dispatch_by_candidate[entry.candidate_record_id]
        prefix = "atomic" if entry.track is PolicyTrack.ATOMIC else "pair"
        arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if entry.track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        for index in range(10):
            task_unit_id = f"{prefix}-smoke-task-{index:02d}"
            bundles.append(
                TargetTaskBundle(
                    entry.candidate.policy_key,
                    entry.track,
                    task_unit_id,
                    f"{task_unit_id}-instance",
                    "reviewer-smoke-stratum",
                    "reviewer-smoke-realization-1",
                    content_id(
                        "reviewer_smoke_task_bundle_",
                        (entry.candidate.policy_key, task_unit_id),
                    ),
                    record.protocol_record_id,
                    1.0,
                    1.0,
                    tuple(
                        TargetTaskArmVariant(
                            arm,
                            content_hash(
                                (entry.candidate.policy_key, task_unit_id, arm.value)
                            ),
                        )
                        for arm in arms
                    ),
                )
            )
    return tuple(
        sorted(
            bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )


def _smoke_measurements(
    assignments: Sequence[AssignedArmITTRecord],
) -> tuple[Measurement, ...]:
    measurements = []
    for assignment in assignments:
        task_index = int(assignment.task_unit_id.rsplit("-", 1)[1])
        secure = (
            task_index
            < (8 if assignment.arm.value == "atomic_target" else 2)
            if assignment.track is PolicyTrack.ATOMIC
            else task_index < (8 if assignment.arm.value == "pair_11" else 2)
        )
        measurements.append(
            Measurement(
                assignment.assignment_id,
                CodeStatus.VALID,
                OracleStatus.SECURE if secure else OracleStatus.INSECURE,
                FunctionalStatus.PASS,
                content_hash((assignment.assignment_id, "generator")),
                content_hash((assignment.assignment_id, "code")),
                content_hash((assignment.assignment_id, "oracle")),
                content_hash((assignment.assignment_id, "functional")),
            )
        )
    return tuple(sorted(measurements, key=lambda item: item.assignment_id))


__all__ = ["SMOKE_STAGES", "run_target_reviewer_smoke"]

"""Pre-outcome Discovery and Confirmation freezes with actual assignment preflight."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from prompt_mechanism_study.artifact_io import require_sha256
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    PolicyTrack,
    SharedConfirmationUnion,
)
from prompt_mechanism_study.discovery_population import (
    DiscoveryPopulationLineage,
    validate_discovery_role_transition,
)
from prompt_mechanism_study.representation import DataRoleManifest
from prompt_mechanism_study.study_planning import (
    FreezeArtifactReference,
    ProviderCallKind,
    QualificationBundle,
    RQ1BudgetQualification,
    RQ1BudgetScenario,
    StudyDesignError,
    TargetPowerSimulationResult,
    bind_target_power_to_assignments,
    simulate_target_power,
    _require_canonical_texts,
    _require_optional_canonical_texts,
    _scenario_selector_ids,
)


@dataclass(frozen=True, slots=True)
class DiscoveryDesignFreeze:
    """Design sealed before any formal discovery outcome is read."""

    protocol_id: str
    schema_version: str
    data_role_manifest: FreezeArtifactReference
    qualification_bundle: FreezeArtifactReference
    discovery_population_lineage: DiscoveryPopulationLineage
    discovery_population_sha256: str
    atomic_discovery_population_sha256: str
    identity_and_scope_decision: FreezeArtifactReference
    candidate_universe_contract: FreezeArtifactReference
    support_gate_contract: FreezeArtifactReference
    discoverability_contract: FreezeArtifactReference
    candidate_fold_manifests: FreezeArtifactReference
    selector_contract: FreezeArtifactReference
    rq1_budget_qualification: FreezeArtifactReference
    discovery_outcome_contract: FreezeArtifactReference
    atomic_top_k: int
    model_ids: tuple[str, ...]
    rq1_baseline_ids: tuple[str, ...] = ()
    rq1_budget_scenario: RQ1BudgetScenario = RQ1BudgetScenario.CORE
    atomic_selector_ids: tuple[str, ...] = ("atomic_full", "atomic_rd_only")
    model_dispatch_policy: str = "model_bound_effect_coordinate"
    rq2_comparison_semantics: str = "descriptive_fixed_denominator_full_minus_ablation_no_interval"
    created_before_discovery_outcomes: bool = True

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        require_text(self.schema_version, "schema_version")
        for name in (
            "data_role_manifest",
            "qualification_bundle",
            "identity_and_scope_decision",
            "candidate_universe_contract",
            "support_gate_contract",
            "discoverability_contract",
            "candidate_fold_manifests",
            "selector_contract",
            "rq1_budget_qualification",
            "discovery_outcome_contract",
        ):
            if type(getattr(self, name)) is not FreezeArtifactReference:
                raise TypeError(f"{name} must be a FreezeArtifactReference")
        if type(self.discovery_population_lineage) is not DiscoveryPopulationLineage:
            raise TypeError("discovery_population_lineage must be a DiscoveryPopulationLineage")
        if (
            self.discovery_population_lineage.accepted_population_manifest_sha256
            != self.discovery_population_sha256
        ):
            raise ValueError("Discovery population lineage drifted inside the freeze")
        require_sha256(self.discovery_population_sha256, "Discovery population sha256")
        for value, name in (
            (self.atomic_discovery_population_sha256, "Atomic Discovery population"),
        ):
            require_sha256(value, name)
            if value != self.discovery_population_sha256:
                raise ValueError(f"{name} drifted from the accepted population")
        for value, name in ((self.atomic_top_k, "atomic_top_k"),):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        _require_canonical_texts(self.model_ids, "model_ids")
        _require_optional_canonical_texts(self.rq1_baseline_ids, "rq1_baseline_ids")
        if type(self.rq1_budget_scenario) is not RQ1BudgetScenario:
            raise TypeError("discovery RQ1 budget scenario must be typed")
        expected_atomic = _scenario_selector_ids(self.rq1_budget_scenario)
        if self.atomic_selector_ids != expected_atomic:
            raise ValueError("Atomic selectors do not match the frozen RQ1 scenario")
        core = {"atomic_full", "atomic_rd_only"}
        expected_baselines = tuple(sorted(set((*expected_atomic,)) - core))
        if self.rq1_baseline_ids != expected_baselines:
            raise ValueError("RQ1 baseline IDs do not match the frozen scenario")
        if self.model_dispatch_policy != "model_bound_effect_coordinate":
            raise ValueError("discovery records must use model-bound dispatch")
        if (
            self.rq2_comparison_semantics
            != "descriptive_fixed_denominator_full_minus_ablation_no_interval"
        ):
            raise ValueError(
                "target RQ2 forbids rank pairing and continuous selector-utility intervals"
            )
        if self.created_before_discovery_outcomes is not True:
            raise ValueError("discovery design must be frozen before outcomes")

    @property
    def discovery_design_freeze_id(self) -> str:
        return content_id("discovery_design_freeze_", self)


@dataclass(frozen=True, slots=True)
class ConfirmationFreeze:
    """Selection and analysis sealed after discovery but before confirmation outcomes."""

    protocol_id: str
    schema_version: str
    discovery_design_freeze: FreezeArtifactReference
    fixed_slot_ledger: FreezeArtifactReference
    unique_candidate_union: FreezeArtifactReference
    candidate_to_slots: FreezeArtifactReference
    bridge_results: FreezeArtifactReference
    protocolization_results: FreezeArtifactReference
    confirmation_dispatch_manifest: FreezeArtifactReference
    eligible_tasks: FreezeArtifactReference
    realization_allocation: FreezeArtifactReference
    randomization_plan: FreezeArtifactReference
    model_bound_assignments: FreezeArtifactReference
    formal_budget_preflight: FreezeArtifactReference
    outcome_contract: FreezeArtifactReference
    inference_and_reporting_plan: FreezeArtifactReference
    created_before_confirmation_outcomes: bool = True

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        require_text(self.schema_version, "schema_version")
        for name in (
            "discovery_design_freeze",
            "fixed_slot_ledger",
            "unique_candidate_union",
            "candidate_to_slots",
            "bridge_results",
            "protocolization_results",
            "confirmation_dispatch_manifest",
            "eligible_tasks",
            "realization_allocation",
            "randomization_plan",
            "model_bound_assignments",
            "formal_budget_preflight",
            "outcome_contract",
            "inference_and_reporting_plan",
        ):
            if type(getattr(self, name)) is not FreezeArtifactReference:
                raise TypeError(f"{name} must be a FreezeArtifactReference")
        if self.created_before_confirmation_outcomes is not True:
            raise ValueError("confirmation design must be frozen before outcomes")

    @property
    def confirmation_freeze_id(self) -> str:
        return content_id("confirmation_freeze_", self)


@dataclass(frozen=True, slots=True)
class StudyFreezeIndex:
    """Lightweight immutable index over the two correctly timed freezes."""

    protocol_id: str
    discovery_design_freeze: FreezeArtifactReference
    confirmation_freeze: FreezeArtifactReference

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        if type(self.discovery_design_freeze) is not FreezeArtifactReference:
            raise TypeError("discovery_design_freeze must be a FreezeArtifactReference")
        if type(self.confirmation_freeze) is not FreezeArtifactReference:
            raise TypeError("confirmation_freeze must be a FreezeArtifactReference")

    @property
    def study_freeze_index_id(self) -> str:
        return content_id("study_freeze_index_", self)


@dataclass(frozen=True, slots=True)
class FormalReportAuthorization:
    """Exact post-execution receipt required before RQ tables may support claims."""

    protocol_id: str
    study_freeze_index: FreezeArtifactReference
    shared_evidence_record: FreezeArtifactReference
    target_selector_yield_result: FreezeArtifactReference
    evidence_ledger: FreezeArtifactReference
    execution_environment: FreezeArtifactReference
    execution_command: FreezeArtifactReference
    provider_call_ledger: FreezeArtifactReference
    freeze_verification_sha256: str
    evidence_verification_sha256: str
    evidence_level: str
    authorization_status: str = "AUTHORIZED"
    scientific_claim_allowed: bool = True

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "report authorization protocol_id")
        for name in (
            "study_freeze_index",
            "shared_evidence_record",
            "target_selector_yield_result",
            "evidence_ledger",
            "execution_environment",
            "execution_command",
            "provider_call_ledger",
        ):
            if type(getattr(self, name)) is not FreezeArtifactReference:
                raise TypeError(f"{name} must be a FreezeArtifactReference")
        require_sha256(
            self.freeze_verification_sha256,
            "freeze verification receipt",
        )
        require_sha256(
            self.evidence_verification_sha256,
            "evidence verification receipt",
        )
        if self.evidence_level not in {"executed", "reported"}:
            raise ValueError("formal report authorization requires executed evidence")
        if (
            self.authorization_status != "AUTHORIZED"
            or self.scientific_claim_allowed is not True
        ):
            raise ValueError("formal report authorization must be explicitly authorized")

    @property
    def formal_report_authorization_id(self) -> str:
        return content_id("formal_report_authorization_", self)


@dataclass(frozen=True, slots=True)
class FormalBudgetPreflight:
    budget_qualification_id: str
    confirmation_dispatch_manifest_id: str
    assignment_manifest_sha256: str
    atomic_effect_records: int
    materialization_calls: int
    generation_calls: int
    functional_judge_call_reservation: int
    external_call_reservation: int
    external_cost_reservation_microunits: int
    status: str = "PASS"
    provider_calls_authorized: bool = True
    actual_power_results: tuple[TargetPowerSimulationResult, ...] | None = field(
        default=None, metadata={"omit_if_none": True}
    )

    def __post_init__(self) -> None:
        require_text(self.budget_qualification_id, "budget qualification ID")
        require_text(self.confirmation_dispatch_manifest_id, "dispatch manifest ID")
        require_sha256(self.assignment_manifest_sha256, "assignment manifest")
        for name in (
            "atomic_effect_records",
            "materialization_calls",
            "generation_calls",
            "functional_judge_call_reservation",
            "external_call_reservation",
            "external_cost_reservation_microunits",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if (
            self.external_call_reservation
            != self.materialization_calls
            + self.generation_calls
            + self.functional_judge_call_reservation
        ):
            raise ValueError("formal external-call reservation does not replay")
        if self.status != "PASS" or self.provider_calls_authorized is not True:
            raise ValueError("only a passing preflight may authorize provider calls")
        if self.actual_power_results is not None:
            expected = tuple(
                (track for track, n in ((PolicyTrack.ATOMIC, self.atomic_effect_records),) if n)
            )
            if (
                any(
                    (
                        type(result) is not TargetPowerSimulationResult
                        or not result.power_gate_passed
                        or result.plan.task_support is None
                        for result in self.actual_power_results
                    )
                )
                or tuple((result.plan.track for result in self.actual_power_results)) != expected
            ):
                raise ValueError(
                    "preflight requires passing actual-support power for every nonempty family"
                )

    @property
    def formal_budget_preflight_id(self) -> str:
        return content_id("formal_budget_preflight_", self)


def validate_formal_budget_preflight(
    budget: RQ1BudgetQualification,
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[Any],
) -> FormalBudgetPreflight:
    """Block Confirmation outcome calls on lineage, support, power or budget drift."""
    from prompt_mechanism_study.randomization import ATOMIC_CONFIRMATORY_ARMS, AssignedArmITTRecord

    if type(budget) is not RQ1BudgetQualification or not budget.provider_calls_authorized:
        raise StudyDesignError("formal execution requires an ACCEPTED RQ1 budget")
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("formal preflight requires a ConfirmationDispatchManifest")
    frozen_assignments = tuple(assignments)
    if any((type(item) is not AssignedArmITTRecord for item in frozen_assignments)):
        raise TypeError("formal preflight requires assigned-arm ITT records")
    assignment_ids = tuple((item.assignment_id for item in frozen_assignments))
    if len(set(assignment_ids)) != len(assignment_ids):
        raise StudyDesignError("formal assignment identities are not unique")
    record_by_id = {item.candidate_record_id: item for item in dispatch.records}
    track_by_id = {item.candidate_record_id: item.track for item in dispatch.union.entries}
    successful = {
        item.candidate_record_id: item
        for item in dispatch.records
        if item.status is BridgeStatus.SUCCESS
    }
    if any((item.candidate_record_id not in successful for item in frozen_assignments)):
        raise StudyDesignError("assignment exists for a failed or unknown dispatch")
    by_candidate: dict[str, list[Any]] = defaultdict(list)
    for assignment in frozen_assignments:
        dispatch_record = record_by_id[assignment.candidate_record_id]
        if (
            assignment.effect_coordinate_id != dispatch_record.effect_coordinate_id
            or assignment.policy_key != dispatch_record.policy_key
            or assignment.model_id != dispatch_record.model_id
            or (assignment.protocol_record_id != dispatch_record.protocol_record_id)
            or (assignment.track is not track_by_id[assignment.candidate_record_id])
        ):
            raise StudyDesignError("formal assignment drifted from model-bound dispatch")
        if assignment.model_id not in budget.dimensions.model_ids:
            raise StudyDesignError("formal assignment uses an unbudgeted model")
        by_candidate[assignment.candidate_record_id].append(assignment)
    if set(by_candidate) != set(successful):
        raise StudyDesignError("every successful dispatch needs its complete assignment block")
    for candidate_id, rows in by_candidate.items():
        planned_tasks = budget.dimensions.atomic_task_units_per_effect
        planned_slots = budget.dimensions.atomic_total_block_slots
        allowed_arms = ATOMIC_CONFIRMATORY_ARMS
        task_ids = {item.task_unit_id for item in rows}
        if len(task_ids) != planned_tasks:
            raise StudyDesignError("formal task count drifted from the power/budget freeze")
        power_plan = budget.power_and_margin_memo.atomic_power.plan
        by_realization, by_cell, realization_weights = (
            defaultdict(set),
            defaultdict(set),
            defaultdict(set),
        )
        for item in rows:
            by_realization[item.realization_id].add(item.task_unit_id)
            by_cell[item.realization_id, item.stratum_id].add(item.task_unit_id)
            realization_weights[item.realization_id].add(float(item.realization_weight))
        if (
            len(by_realization) != power_plan.global_realizations
            or any(
                (
                    len(values) < power_plan.minimum_task_units_per_realization
                    for values in by_realization.values()
                )
            )
            or any(
                (
                    len(values) < power_plan.minimum_task_units_per_stratum
                    for values in by_cell.values()
                )
            )
            or any((len(values) != 1 for values in realization_weights.values()))
            or (
                not math.isclose(
                    sum((next(iter(values)) for values in realization_weights.values())),
                    1,
                    rel_tol=0,
                    abs_tol=1e-12,
                )
            )
        ):
            raise StudyDesignError(
                "formal realization support or frozen weighting is not evaluable"
            )
        stratum_counts = defaultdict(set)
        for item in rows:
            stratum_counts[item.stratum_id].add(item.task_unit_id)
        if (
            tuple((next(iter(realization_weights[r])) for r in sorted(realization_weights)))
            != power_plan.realization_weights
            or tuple(sorted(((s, len(ids)) for s, ids in stratum_counts.items())))
            != power_plan.stratum_task_counts
        ):
            raise StudyDesignError(
                "formal allocation weights or strata differ from the power simulation"
            )
        for task_unit_id in task_ids:
            block = [item for item in rows if item.task_unit_id == task_unit_id]
            if len(block) != planned_slots:
                raise StudyDesignError("formal task block has the wrong total slot count")
            if len({item.realization_id for item in block}) != 1:
                raise StudyDesignError("one task-policy coordinate has multiple realizations")
            if len({item.task_bundle_id for item in block}) != 1:
                raise StudyDesignError("one task-policy coordinate has multiple bundles")
            counts = Counter((item.arm for item in block))
            if set(counts) != set(allowed_arms) or len(set(counts.values())) != 1:
                raise StudyDesignError("formal task block is not balanced over all four arms")
            request_slots = {item.request_randomness_slot for item in block}
            if request_slots != set(range(planned_slots)):
                raise StudyDesignError(
                    "formal task block request-randomness slots are not unique and complete"
                )
    atomic_effects = sum((True for candidate_id in successful))
    reservation = budget.reservation
    if atomic_effects > reservation.atomic_effect_record_upper_bound:
        raise StudyDesignError("formal union exceeds the frozen effect-record reservation")
    generation_calls = len(frozen_assignments)
    materialization_calls = 2 * len({item.task_bundle_id for item in frozen_assignments})
    functional_calls = generation_calls
    external_calls = materialization_calls + generation_calls + functional_calls
    costs = budget.provider_ceilings.unit_costs
    external_cost = (
        materialization_calls * costs[ProviderCallKind.MATERIALIZATION]
        + generation_calls * costs[ProviderCallKind.GENERATION]
        + functional_calls * costs[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    for actual, reserved, ceiling, reason in (
        (
            materialization_calls,
            reservation.materialization_call_upper_bound,
            budget.provider_ceilings.materialization_call_ceiling,
            "materialization calls",
        ),
        (
            generation_calls,
            reservation.generation_call_upper_bound,
            budget.provider_ceilings.generation_call_ceiling,
            "generation calls",
        ),
        (
            functional_calls,
            reservation.functional_judge_call_upper_bound,
            budget.provider_ceilings.functional_judge_call_ceiling,
            "functional-judge calls",
        ),
        (
            external_calls,
            reservation.external_call_upper_bound,
            budget.provider_ceilings.external_call_ceiling,
            "external calls",
        ),
        (
            external_cost,
            reservation.external_cost_upper_bound_microunits,
            budget.provider_ceilings.external_cost_ceiling_microunits,
            "external cost",
        ),
    ):
        if actual > reserved or actual > ceiling:
            raise StudyDesignError(f"formal {reason} exceed the frozen reservation")
    actual_power = []
    for planned in (budget.power_and_margin_memo.atomic_power,):
        rows = tuple((row for row in frozen_assignments if row.track is planned.plan.track))
        if rows:
            result = simulate_target_power(bind_target_power_to_assignments(planned.plan, rows))
            actual_power.append(result)
    if any((not result.power_gate_passed for result in actual_power)):
        error = StudyDesignError("actual task-support power failed; frozen design cannot proceed")
        error.power_results = tuple(actual_power)
        raise error
    return FormalBudgetPreflight(
        budget.rq1_budget_qualification_id,
        dispatch.confirmation_dispatch_manifest_id,
        content_hash(tuple(sorted(frozen_assignments, key=lambda item: item.assignment_id))),
        atomic_effects,
        materialization_calls,
        generation_calls,
        functional_calls,
        external_calls,
        external_cost,
        actual_power_results=tuple(actual_power),
    )


def freeze_target_discovery_design(
    *,
    schema_version: str,
    manifest: DataRoleManifest,
    qualification_bundle: QualificationBundle,
    budget: RQ1BudgetQualification,
    population_lineage: DiscoveryPopulationLineage,
    atomic_discovery_population_sha256: str,
    identity_and_scope_decision: FreezeArtifactReference,
    candidate_universe_contract: FreezeArtifactReference,
    support_gate_contract: FreezeArtifactReference,
    discoverability_contract: FreezeArtifactReference,
    candidate_fold_manifests: FreezeArtifactReference,
    selector_contract: FreezeArtifactReference,
    discovery_outcome_contract: FreezeArtifactReference,
) -> DiscoveryDesignFreeze:
    """Freeze the complete target design before any formal discovery outcome exists."""
    if type(manifest) is not DataRoleManifest:
        raise TypeError("target discovery freeze requires a DataRoleManifest")
    if type(qualification_bundle) is not QualificationBundle:
        raise TypeError("target discovery freeze requires a QualificationBundle")
    if type(budget) is not RQ1BudgetQualification:
        raise TypeError("target discovery freeze requires an RQ1BudgetQualification")
    if type(population_lineage) is not DiscoveryPopulationLineage:
        raise TypeError("target discovery freeze requires a DiscoveryPopulationLineage")
    if not population_lineage.formal_discovery_ready:
        raise StudyDesignError("target discovery is COVERAGE_BLOCKED")
    if not qualification_bundle.formal_use_authorized:
        raise StudyDesignError("target discovery requires accepted qualification")
    if not budget.provider_calls_authorized:
        raise StudyDesignError("target discovery requires an accepted RQ1 budget")
    if budget.qualification_bundle != qualification_bundle:
        raise StudyDesignError("target discovery budget uses another qualification bundle")
    qualification_roles = validate_discovery_role_transition(population_lineage, manifest)
    if (
        manifest.protocol_id != qualification_bundle.protocol_id
        or manifest.protocol_id != budget.protocol_id
        or qualification_bundle.data_role_manifest.artifact_id
        != qualification_roles.data_role_manifest_id
        or (qualification_bundle.data_role_manifest.sha256 != content_hash(qualification_roles))
    ):
        raise StudyDesignError("target discovery data-role lineage drift")
    if (
        population_lineage.profile.protocol_id != manifest.protocol_id
        or population_lineage.accepted_population_manifest_sha256
        != manifest.discovery_population_sha256
        or population_lineage.post_census.data_role_manifest_id != manifest.data_role_manifest_id
        or (
            population_lineage.receipt is not None
            and population_lineage.receipt.data_role_manifest_sha256 != content_hash(manifest)
        )
        or (
            atomic_discovery_population_sha256
            != population_lineage.accepted_population_manifest_sha256
        )
    ):
        raise StudyDesignError("target Discovery population lineage drift")
    dimensions = budget.dimensions
    atomic_selectors = _scenario_selector_ids(budget.scenario)
    core = {"atomic_full", "atomic_rd_only"}
    baselines = tuple(sorted(set((*atomic_selectors,)) - core))
    return DiscoveryDesignFreeze(
        manifest.protocol_id,
        schema_version,
        FreezeArtifactReference(manifest.data_role_manifest_id, content_hash(manifest)),
        FreezeArtifactReference(
            qualification_bundle.qualification_bundle_id, content_hash(qualification_bundle)
        ),
        population_lineage,
        population_lineage.accepted_population_manifest_sha256,
        atomic_discovery_population_sha256,
        identity_and_scope_decision,
        candidate_universe_contract,
        support_gate_contract,
        discoverability_contract,
        candidate_fold_manifests,
        selector_contract,
        FreezeArtifactReference(budget.rq1_budget_qualification_id, content_hash(budget)),
        discovery_outcome_contract,
        dimensions.atomic_top_k,
        dimensions.model_ids,
        baselines,
        budget.scenario,
        atomic_selectors,
    )


def freeze_target_confirmation_design(
    *,
    discovery: DiscoveryDesignFreeze,
    budget: RQ1BudgetQualification,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: Any,
    task_bundles: Sequence[Any],
    assignments: Sequence[Any],
    preflight: FormalBudgetPreflight,
    outcome_contract: FreezeArtifactReference,
) -> ConfirmationFreeze:
    """Freeze selection, dispatch, assignment, and inference before outcomes."""
    from prompt_mechanism_study.randomization import (
        AssignedArmITTRecord,
        TargetRandomizationPlan,
        TargetTaskBundle,
        randomize_target_confirmation,
    )

    if type(discovery) is not DiscoveryDesignFreeze:
        raise TypeError("target confirmation freeze requires a discovery freeze")
    if type(budget) is not RQ1BudgetQualification:
        raise TypeError("target confirmation freeze requires an RQ1 budget")
    if type(ledger) is not FixedSlotLedger:
        raise TypeError("target confirmation freeze requires a fixed-slot ledger")
    if type(union) is not SharedConfirmationUnion:
        raise TypeError("target confirmation freeze requires a shared union")
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("target confirmation freeze requires a dispatch manifest")
    if type(randomization_plan) is not TargetRandomizationPlan:
        raise TypeError("target confirmation freeze requires a target randomization plan")
    frozen_task_bundles = tuple(
        sorted(
            task_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    if any((type(item) is not TargetTaskBundle for item in frozen_task_bundles)):
        raise TypeError("target confirmation freeze requires typed task bundles")
    if type(preflight) is not FormalBudgetPreflight:
        raise TypeError("target confirmation freeze requires a budget preflight")
    if not budget.provider_calls_authorized:
        raise StudyDesignError("target confirmation requires an accepted RQ1 budget")
    expected_budget = FreezeArtifactReference(
        budget.rq1_budget_qualification_id, content_hash(budget)
    )
    if (
        discovery.protocol_id != budget.protocol_id
        or discovery.rq1_budget_qualification != expected_budget
        or discovery.rq1_budget_scenario is not budget.scenario
    ):
        raise StudyDesignError("confirmation budget drifted from the discovery freeze")
    if (
        ledger.protocol_id != discovery.protocol_id
        or ledger.schema_version != discovery.schema_version
    ):
        raise StudyDesignError("fixed-slot ledger protocol drift")
    expected_top_k = ((PolicyTrack.ATOMIC, discovery.atomic_top_k),)
    if ledger.top_k_by_track != expected_top_k:
        raise StudyDesignError("fixed-slot K drifted from the discovery freeze")
    expected_coordinates = {
        (track, model_id, selector_id)
        for track, selectors in ((PolicyTrack.ATOMIC, discovery.atomic_selector_ids),)
        for model_id in discovery.model_ids
        for selector_id in selectors
    }
    actual_coordinates = {
        (source.track, source.model_id, source.selector_id) for source in ledger.sources
    }
    if actual_coordinates != expected_coordinates:
        raise StudyDesignError("fixed-slot selector/model coordinates drifted")
    if union.ledger != ledger or dispatch.union != union:
        raise StudyDesignError("confirmation union or dispatch drifted from fixed slots")
    frozen_assignments = tuple(sorted(assignments, key=lambda item: item.assignment_id))
    if any((type(item) is not AssignedArmITTRecord for item in frozen_assignments)):
        raise TypeError("target confirmation requires assigned-arm ITT records")
    if (
        randomization_plan.protocol_id != discovery.protocol_id
        or randomization_plan.schema_version != discovery.schema_version
        or randomization_plan.atomic_total_block_slots != budget.dimensions.atomic_total_block_slots
    ):
        raise StudyDesignError("target randomization plan drifted from discovery or budget")
    if (
        randomize_target_confirmation(dispatch, randomization_plan, frozen_task_bundles)
        != frozen_assignments
    ):
        raise StudyDesignError("target assignments do not replay from the frozen randomization")
    replayed_preflight = validate_formal_budget_preflight(budget, dispatch, frozen_assignments)
    if replayed_preflight != preflight:
        raise StudyDesignError("formal budget preflight does not replay")
    inference_plan = budget.power_and_margin_memo.target_itt_plan()
    dispatch_reference = FreezeArtifactReference(
        dispatch.confirmation_dispatch_manifest_id, content_hash(dispatch)
    )
    eligible_task_rows = tuple(
        sorted(
            {
                (item.policy_key, item.task_unit_id, item.task_instance_id, item.stratum_id)
                for item in frozen_task_bundles
                if item.exclusion_reason is None
            }
        )
    )
    realization_rows = tuple(
        sorted(
            {
                (
                    item.policy_key,
                    item.task_unit_id,
                    item.realization_id,
                    item.task_bundle_id,
                    item.realization_weight,
                    item.exclusion_reason,
                )
                for item in frozen_task_bundles
            }
        )
    )
    return ConfirmationFreeze(
        discovery.protocol_id,
        discovery.schema_version,
        FreezeArtifactReference(discovery.discovery_design_freeze_id, content_hash(discovery)),
        FreezeArtifactReference(ledger.fixed_slot_ledger_id, content_hash(ledger)),
        FreezeArtifactReference(union.shared_confirmation_union_id, content_hash(union)),
        FreezeArtifactReference(
            content_id("candidate_to_slots_", union.candidate_to_slots),
            content_hash(union.candidate_to_slots),
        ),
        dispatch_reference,
        FreezeArtifactReference(
            content_id("target_task_bundles_", frozen_task_bundles),
            content_hash(frozen_task_bundles),
        ),
        dispatch_reference,
        FreezeArtifactReference(
            content_id("eligible_task_units_", eligible_task_rows), content_hash(eligible_task_rows)
        ),
        FreezeArtifactReference(
            content_id("realization_allocation_", realization_rows), content_hash(realization_rows)
        ),
        FreezeArtifactReference(
            randomization_plan.target_randomization_plan_id, content_hash(randomization_plan)
        ),
        FreezeArtifactReference(
            content_id("assigned_arm_manifest_", frozen_assignments),
            content_hash(frozen_assignments),
        ),
        FreezeArtifactReference(preflight.formal_budget_preflight_id, content_hash(preflight)),
        outcome_contract,
        FreezeArtifactReference(inference_plan.target_itt_plan_id, content_hash(inference_plan)),
    )


def freeze_target_study_index(
    discovery: DiscoveryDesignFreeze,
    confirmation: ConfirmationFreeze,
) -> StudyFreezeIndex:
    """Close the exact two-freeze lineage without reading study outcomes."""

    if type(discovery) is not DiscoveryDesignFreeze:
        raise TypeError("target study index requires a discovery freeze")
    if type(confirmation) is not ConfirmationFreeze:
        raise TypeError("target study index requires a confirmation freeze")
    discovery_reference = FreezeArtifactReference(
        discovery.discovery_design_freeze_id,
        content_hash(discovery),
    )
    if (
        confirmation.protocol_id != discovery.protocol_id
        or confirmation.schema_version != discovery.schema_version
        or confirmation.discovery_design_freeze != discovery_reference
    ):
        raise StudyDesignError("confirmation freeze does not descend from discovery")
    return StudyFreezeIndex(
        discovery.protocol_id,
        discovery_reference,
        FreezeArtifactReference(
            confirmation.confirmation_freeze_id,
            content_hash(confirmation),
        ),
    )


__all__ = [
    "ConfirmationFreeze",
    "DiscoveryDesignFreeze",
    "FormalBudgetPreflight",
    "FormalReportAuthorization",
    "StudyFreezeIndex",
    "freeze_target_confirmation_design",
    "freeze_target_discovery_design",
    "freeze_target_study_index",
    "validate_formal_budget_preflight",
]

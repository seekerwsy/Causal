"""Independent randomization and study-freeze reconstruction."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
import math

from prompt_mechanism_study.inference import TargetITTPlan
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    PolicyTrack,
    SharedConfirmationUnion,
)
from prompt_mechanism_study.discovery_population import (
    DiscoveryPopulationStatus,
    SupplementationDecision,
)
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskBundle,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.study_design import (
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    StudyFreezeIndex,
)
from prompt_mechanism_study.study_planning import RQ1BudgetQualification, RQ1BudgetScenario

from prompt_mechanism_study.verification.qualification import (
    verify_formal_budget_preflight,
)


def _verify_realization_allocation(plan, bundles):
    """Replay Q and the original allocation pool without using the allocator."""
    weights, populations = defaultdict(dict), defaultdict(list)
    for policy, r, q in plan.realization_weights:
        weights[policy][r] = q
    for policy, unit, stratum in plan.allocation_tasks:
        populations[(policy, stratum)].append(unit)
    expected = {}
    for (policy, stratum), population in sorted(populations.items()):
        n = len(population)
        counts = {r: math.floor(n * q) for r, q in weights[policy].items()}
        remainders = sorted(weights[policy], key=lambda r: (
            -(n * weights[policy][r] - counts[r]),
            content_hash(("realization_remainder", plan.assignment_seed, policy, stratum, r)),
        ))
        for index in range(n - sum(counts.values())):
            counts[remainders[index]] += 1
        ordered = sorted(population, key=lambda unit: (
            content_hash(("realization_task", plan.assignment_seed, policy, stratum, unit)), unit,
        ))
        offset = 0
        for r in sorted(counts):
            for unit in ordered[offset:offset + counts[r]]:
                expected[(policy, unit)] = (r, weights[policy][r], stratum)
            offset += counts[r]
    observed = {(b.policy_key, b.task_unit_id): (b.realization_id, b.realization_weight, b.stratum_id)
                for b in bundles}
    if observed != expected:
        raise ValueError("target realization allocation failed independent randomization replay")


def verify_target_randomization(
    dispatch: ConfirmationDispatchManifest,
    plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
) -> dict[str, object]:
    """Independently replay target task reuse, arm order, variants, and provider seeds."""
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("target randomization verifier requires a dispatch manifest")
    if type(plan) is not TargetRandomizationPlan:
        raise TypeError("target randomization verifier requires a typed plan")
    frozen_bundles = tuple(task_bundles)
    if any((type(item) is not TargetTaskBundle for item in frozen_bundles)):
        raise TypeError("target randomization verifier requires typed task bundles")
    canonical_bundles = tuple(
        sorted(
            frozen_bundles,
            key=lambda item: (item.policy_key, item.task_unit_id, item.task_instance_id),
        )
    )
    if frozen_bundles != canonical_bundles:
        raise ValueError("target task bundles failed canonical-order replay")
    if len({item.target_task_bundle_id for item in frozen_bundles}) != len(frozen_bundles):
        raise ValueError("target task-bundle identities failed independent replay")
    if len({(item.policy_key, item.task_unit_id) for item in frozen_bundles}) != len(
        frozen_bundles
    ):
        raise ValueError("one policy/task coordinate has multiple frozen bundles")
    _verify_realization_allocation(plan, frozen_bundles)
    if (
        plan.protocol_id != dispatch.union.ledger.protocol_id
        or plan.schema_version != dispatch.union.ledger.schema_version
    ):
        raise ValueError("target randomization protocol failed independent replay")
    track_by_policy: dict[str, PolicyTrack] = {}
    for entry in dispatch.union.entries:
        prior = track_by_policy.setdefault(entry.candidate.policy_key, entry.track)
        if prior is not entry.track:
            raise ValueError("target policy track failed independent replay")
    successful = tuple((item for item in dispatch.records if item.status is BridgeStatus.SUCCESS))
    protocol_by_policy: dict[str, str] = {}
    for record in successful:
        prior = protocol_by_policy.setdefault(record.policy_key, record.protocol_record_id)
        if prior != record.protocol_record_id:
            raise ValueError("shared policy protocolization failed independent replay")
    if {item.policy_key for item in frozen_bundles} != {item.policy_key for item in successful}:
        raise ValueError("task-bundle policy support failed independent replay")
    bundles_by_policy: dict[str, list[TargetTaskBundle]] = defaultdict(list)
    for bundle in frozen_bundles:
        if bundle.track is not track_by_policy.get(
            bundle.policy_key
        ) or bundle.protocol_record_id != protocol_by_policy.get(bundle.policy_key):
            raise ValueError("task-bundle protocol lineage failed independent replay")
        if bundle.exclusion_reason is None:
            bundles_by_policy[bundle.policy_key].append(bundle)
    expected = []
    for record in successful:
        track = track_by_policy[record.policy_key]
        arms = ATOMIC_CONFIRMATORY_ARMS
        slot_count = plan.atomic_total_block_slots
        arm_copies = tuple(
            ((arm, repeat) for repeat in range(slot_count // len(arms)) for arm in arms)
        )
        for bundle in bundles_by_policy[record.policy_key]:
            block_id = content_id(
                "assigned_arm_itt_block_",
                {
                    "candidate_record_id": record.candidate_record_id,
                    "effect_coordinate_id": record.effect_coordinate_id,
                    "policy_key": record.policy_key,
                    "model_id": record.model_id,
                    "track": track,
                    "task_unit_id": bundle.task_unit_id,
                    "task_instance_id": bundle.task_instance_id,
                    "stratum_id": bundle.stratum_id,
                    "realization_id": bundle.realization_id,
                    "task_bundle_id": bundle.task_bundle_id,
                    "protocol_record_id": bundle.protocol_record_id,
                    "task_instance_weight": bundle.task_instance_weight,
                    "realization_weight": bundle.realization_weight,
                },
            )
            ordered_arms = tuple(
                (
                    arm
                    for arm, repeat in sorted(
                        arm_copies,
                        key=lambda item: content_hash(
                            {
                                "assignment_seed": plan.assignment_seed,
                                "block_id": block_id,
                                "arm": item[0],
                                "repeat": item[1],
                            }
                        ),
                    )
                )
            )
            variants = {item.arm: item.variant_sha256 for item in bundle.variants}
            for request_slot, arm in enumerate(ordered_arms):
                provider_seed = (
                    None
                    if plan.provider_seed_root is None
                    else int(
                        content_hash(
                            {
                                "provider_seed_root": plan.provider_seed_root,
                                "block_id": block_id,
                                "request_randomness_slot": request_slot,
                                "arm": arm,
                            }
                        )[:8],
                        16,
                    )
                    & 2147483647
                )
                expected.append(
                    AssignedArmITTRecord(
                        record.candidate_record_id,
                        record.effect_coordinate_id,
                        record.policy_key,
                        record.model_id,
                        track,
                        bundle.task_unit_id,
                        bundle.task_instance_id,
                        bundle.stratum_id,
                        bundle.realization_id,
                        bundle.task_bundle_id,
                        bundle.protocol_record_id,
                        request_slot,
                        arm,
                        bundle.task_instance_weight,
                        bundle.realization_weight,
                        variants[arm],
                        provider_seed,
                    )
                )
    replayed = tuple(sorted(expected, key=lambda item: item.assignment_id))
    if tuple(assignments) != replayed:
        raise ValueError("target assignments failed independent randomization replay")
    return {
        "status": "TARGET_RANDOMIZATION_VERIFIED",
        "target_randomization_plan_id": plan.target_randomization_plan_id,
        "task_bundle_count": len(frozen_bundles),
        "assignment_count": len(replayed),
    }


def verify_target_study_freezes(
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
) -> dict[str, object]:
    """Standalone verification including its upstream prerequisites."""

    verify_formal_budget_preflight(budget, dispatch, assignments, preflight)
    return _check_target_study_freezes(
        manifest=manifest, budget=budget, discovery=discovery, ledger=ledger,
        union=union, dispatch=dispatch, randomization_plan=randomization_plan,
        task_bundles=task_bundles, assignments=assignments, preflight=preflight,
        confirmation=confirmation, index=index,
    )


def _check_target_study_freezes(
    *,
    manifest: DataRoleManifest,
    budget: RQ1BudgetQualification,
    discovery: DiscoveryDesignFreeze,
    ledger: FixedSlotLedger,
    union: SharedConfirmationUnion,
    dispatch: ConfirmationDispatchManifest,
    randomization_plan: TargetRandomizationPlan,
    task_bundles: Sequence[TargetTaskBundle],
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
    confirmation: ConfirmationFreeze,
    index: StudyFreezeIndex,
) -> dict[str, object]:
    """Independently close the complete target design-to-confirmation freeze chain."""
    if type(manifest) is not DataRoleManifest:
        raise TypeError("target freeze verifier requires a DataRoleManifest")
    randomization_verification = verify_target_randomization(
        dispatch, randomization_plan, task_bundles, assignments
    )
    qualification = budget.qualification_bundle
    d0_receipt = discovery.discovery_population_lineage.receipt
    qualification_roles = manifest if d0_receipt is None else d0_receipt.pre_data_role_manifest
    if type(qualification_roles) is not DataRoleManifest:
        raise ValueError("discovery qualification requires its original data-role manifest")
    if (
        discovery.protocol_id != manifest.protocol_id
        or discovery.protocol_id != budget.protocol_id
        or discovery.data_role_manifest.artifact_id != manifest.data_role_manifest_id
        or (discovery.data_role_manifest.sha256 != content_hash(manifest))
        or (discovery.qualification_bundle.artifact_id != qualification.qualification_bundle_id)
        or (discovery.qualification_bundle.sha256 != content_hash(qualification))
        or (
            qualification.data_role_manifest.artifact_id
            != qualification_roles.data_role_manifest_id
        )
        or (qualification.data_role_manifest.sha256 != content_hash(qualification_roles))
        or (discovery.rq1_budget_qualification.artifact_id != budget.rq1_budget_qualification_id)
        or (discovery.rq1_budget_qualification.sha256 != content_hash(budget))
        or (discovery.discovery_population_sha256 != manifest.discovery_population_sha256)
        or (not _verify_discovery_population(discovery.discovery_population_lineage, manifest))
        or (discovery.discovery_population_lineage.profile.protocol_id != manifest.protocol_id)
        or (
            discovery.discovery_population_lineage.accepted_population_manifest_sha256
            != manifest.discovery_population_sha256
        )
        or (
            discovery.discovery_population_lineage.post_census.data_role_manifest_id
            != manifest.data_role_manifest_id
        )
        or (
            discovery.discovery_population_lineage.receipt is not None
            and discovery.discovery_population_lineage.receipt.data_role_manifest_sha256
            != content_hash(manifest)
        )
        or (discovery.atomic_discovery_population_sha256 != discovery.discovery_population_sha256)
    ):
        raise ValueError("discovery freeze lineage failed independent replay")
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[budget.scenario]
    atomic_selectors = ["atomic_full", "atomic_rd_only"]
    if selector_count >= 3:
        atomic_selectors.append("atomic_blind_expert")
    if selector_count == 4:
        atomic_selectors.append("atomic_seeded_random")
    frozen_atomic = tuple(sorted(atomic_selectors))
    core = {"atomic_full", "atomic_rd_only"}
    baselines = tuple(sorted(set((*frozen_atomic,)) - core))
    if (
        discovery.atomic_top_k != budget.dimensions.atomic_top_k
        or discovery.model_ids != budget.dimensions.model_ids
        or discovery.rq1_budget_scenario is not budget.scenario
        or (discovery.atomic_selector_ids != frozen_atomic)
        or (discovery.rq1_baseline_ids != baselines)
        or (
            discovery.rq2_comparison_semantics
            != "descriptive_fixed_denominator_full_minus_ablation_no_interval"
        )
        or (discovery.created_before_discovery_outcomes is not True)
    ):
        raise ValueError("discovery dimensions failed independent replay")
    expected_coordinates = {
        (track, model_id, selector_id)
        for track, selectors in ((PolicyTrack.ATOMIC, frozen_atomic),)
        for model_id in discovery.model_ids
        for selector_id in selectors
    }
    if (
        ledger.protocol_id != discovery.protocol_id
        or ledger.schema_version != discovery.schema_version
        or ledger.top_k_by_track != ((PolicyTrack.ATOMIC, discovery.atomic_top_k),)
        or (
            {(source.track, source.model_id, source.selector_id) for source in ledger.sources}
            != expected_coordinates
        )
        or (union.ledger != ledger)
        or (dispatch.union != union)
    ):
        raise ValueError("confirmation selection failed independent replay")
    frozen_assignments = tuple(sorted(assignments, key=lambda item: item.assignment_id))
    frozen_task_bundles = tuple(task_bundles)
    if randomization_plan.atomic_total_block_slots != budget.dimensions.atomic_total_block_slots:
        raise ValueError("target randomization slots failed independent budget replay")
    eligible_rows = tuple(
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
    plan = TargetITTPlan(
        budget.power_and_margin_memo.bootstrap_seed,
        budget.power_and_margin_memo.bootstrap_draws,
        budget.power_and_margin_memo.alpha,
        budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_stratum,
        budget.power_and_margin_memo.minimum_valid_bootstrap_fraction,
        budget.power_and_margin_memo.atomic_power.plan.practical_margin,
        budget.power_and_margin_memo.maximum_unknown_fraction_among_valid,
        atomic_minimum_task_units_per_realization=budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_realization,
    )
    dispatch_id = dispatch.confirmation_dispatch_manifest_id
    dispatch_hash = content_hash(dispatch)
    confirmation_checks = (
        confirmation.protocol_id == discovery.protocol_id,
        confirmation.schema_version == discovery.schema_version,
        confirmation.discovery_design_freeze.artifact_id == discovery.discovery_design_freeze_id,
        confirmation.discovery_design_freeze.sha256 == content_hash(discovery),
        confirmation.fixed_slot_ledger.artifact_id == ledger.fixed_slot_ledger_id,
        confirmation.fixed_slot_ledger.sha256 == content_hash(ledger),
        confirmation.unique_candidate_union.artifact_id == union.shared_confirmation_union_id,
        confirmation.unique_candidate_union.sha256 == content_hash(union),
        confirmation.candidate_to_slots.artifact_id
        == content_id("candidate_to_slots_", union.candidate_to_slots),
        confirmation.candidate_to_slots.sha256 == content_hash(union.candidate_to_slots),
        confirmation.bridge_results.artifact_id == dispatch_id,
        confirmation.bridge_results.sha256 == dispatch_hash,
        confirmation.protocolization_results.artifact_id
        == content_id("target_task_bundles_", frozen_task_bundles),
        confirmation.protocolization_results.sha256 == content_hash(frozen_task_bundles),
        confirmation.confirmation_dispatch_manifest.artifact_id == dispatch_id,
        confirmation.confirmation_dispatch_manifest.sha256 == dispatch_hash,
        confirmation.eligible_tasks.artifact_id
        == content_id("eligible_task_units_", eligible_rows),
        confirmation.eligible_tasks.sha256 == content_hash(eligible_rows),
        confirmation.realization_allocation.artifact_id
        == content_id("realization_allocation_", realization_rows),
        confirmation.realization_allocation.sha256 == content_hash(realization_rows),
        confirmation.randomization_plan.artifact_id
        == randomization_plan.target_randomization_plan_id,
        confirmation.randomization_plan.sha256 == content_hash(randomization_plan),
        confirmation.model_bound_assignments.artifact_id
        == content_id("assigned_arm_manifest_", frozen_assignments),
        confirmation.model_bound_assignments.sha256 == content_hash(frozen_assignments),
        confirmation.formal_budget_preflight.artifact_id == preflight.formal_budget_preflight_id,
        confirmation.formal_budget_preflight.sha256 == content_hash(preflight),
        confirmation.inference_and_reporting_plan.artifact_id == plan.target_itt_plan_id,
        confirmation.inference_and_reporting_plan.sha256 == content_hash(plan),
        confirmation.created_before_confirmation_outcomes is True,
    )
    if not all(confirmation_checks):
        raise ValueError("confirmation freeze lineage failed independent replay")
    if (
        index.protocol_id != discovery.protocol_id
        or index.discovery_design_freeze.artifact_id != discovery.discovery_design_freeze_id
        or index.discovery_design_freeze.sha256 != content_hash(discovery)
        or (index.confirmation_freeze.artifact_id != confirmation.confirmation_freeze_id)
        or (index.confirmation_freeze.sha256 != content_hash(confirmation))
    ):
        raise ValueError("study freeze index failed independent replay")
    return {
        "status": "TARGET_STUDY_FREEZE_VERIFIED",
        "study_freeze_index_id": index.study_freeze_index_id,
        "discovery_design_freeze_id": discovery.discovery_design_freeze_id,
        "confirmation_freeze_id": confirmation.confirmation_freeze_id,
        "provider_calls_authorized": True,
        "confirmation_outcomes_used": False,
        "randomization_verification_status": randomization_verification["status"],
    }


def _verify_discovery_population(lineage, manifest: DataRoleManifest) -> bool:
    """Independently replay D0 readiness without calling production Gate helpers."""

    profile = lineage.profile
    pre = lineage.pre_census
    post = lineage.post_census
    receipt = lineage.receipt
    original = manifest if receipt is None else receipt.pre_data_role_manifest
    if type(original) is not DataRoleManifest:
        return False
    original_units = sorted(task.task_unit_id for binding in original.bindings
                            if binding.role is DataRole.DISCOVERY for task in binding.task_units)
    final_units = sorted(task.task_unit_id for binding in manifest.bindings
                         if binding.role is DataRole.DISCOVERY for task in binding.task_units)
    if (original.protocol_id != manifest.protocol_id or manifest.protocol_id != profile.protocol_id
        or pre.population_manifest_sha256 != original.discovery_population_sha256
        or post.population_manifest_sha256 != manifest.discovery_population_sha256
        or list(pre.task_unit_ids) != original_units or list(post.task_unit_ids) != final_units):
        return False
    if receipt is not None:
        previous_bindings = {binding.data_id: binding for binding in original.bindings}
        current_bindings = {binding.data_id: binding for binding in manifest.bindings}
        if any(current_bindings.get(key) != value for key, value in previous_bindings.items()):
            return False
        extra = [binding for key, binding in current_bindings.items() if key not in previous_bindings]
        if not extra or any(binding.role is not DataRole.DISCOVERY for binding in extra):
            return False
        old_tasks = {task.task_unit_id for binding in original.bindings for task in binding.task_units}
        old_groups = {task.near_duplicate_group_id for binding in original.bindings for task in binding.task_units}
        new_tasks = [task for binding in extra for task in binding.task_units]
        names = [task.task_unit_id for task in new_tasks]
        groups = [task.near_duplicate_group_id for task in new_tasks]
        decisions = {row.task_unit_id: row for row in receipt.task_dispositions if row.accepted}
        if (len(set(names)) != len(names) or len(set(groups)) != len(groups)
            or set(names) & old_tasks or set(groups) & old_groups
            or tuple(sorted(names)) != receipt.acquired_task_unit_ids or set(decisions) != set(names)):
            return False
        for task in new_tasks:
            decision = decisions[task.task_unit_id]
            if (decision.near_duplicate_group_id != task.near_duplicate_group_id
                or decision.source_lineage_id != task.source_lineage_id
                or tuple(event.value for event in decision.exposure_categories) != task.exposure_history
                or set(task.exposure_history) - {"SOURCE_CURATION_VIEWED"}
                or decision.source_family not in profile.permitted_source_families):
                return False

    def ready(census) -> bool:
        cells = {item.target_id: item for item in census.cells}
        return (profile.schema_version == "4.0"
                and set(cells) == {item.target_id for item in profile.targets}
                and all(cells[target.target_id].context_task_units >= target.minimum_context_task_units
                        for target in profile.targets))

    if (
        lineage.accepted_population_manifest_sha256
        != manifest.discovery_population_sha256
        or pre.data_role_manifest_id != original.data_role_manifest_id
        or post.data_role_manifest_id != manifest.data_role_manifest_id
        or lineage.plan.selector_variant_blind is not True
        or lineage.plan.prohibited_inputs
        != (
            "FCI_OR_PAG_EVIDENCE",
            "FEATURE_STATES_OR_PAIR_CELLS",
            "NATURAL_OUTCOMES",
            "PAIR_RELATION_SUPPORT",
            "RD_SCORES",
            "SELECTOR_MEMBERSHIP_OR_RANK",
        )
    ):
        return False
    if lineage.plan.decision is SupplementationDecision.NOT_REQUESTED:
        return (
            lineage.receipt is None
            and lineage.status is (DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION
                                   if ready(post) else DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED)
            and pre.cells == post.cells
        )
    if receipt is None:
        return False
    return (
        not ready(pre)
        and lineage.status is (DiscoveryPopulationStatus.READY_AFTER_ONE_ROUND
                               if ready(post) else DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED)
        and receipt.round_index == 1
        and set(receipt.acquired_task_unit_ids)
        == set(post.task_unit_ids) - set(pre.task_unit_ids)
        and receipt.data_role_manifest_sha256 == content_hash(manifest)
        and receipt.independent_verifier_status == "PASS"
    )


__all__ = [
    "verify_target_randomization",
    "verify_target_study_freezes",
]

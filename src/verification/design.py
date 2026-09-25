"""Independent randomization and study-freeze reconstruction."""


from __future__ import annotations
from collections import defaultdict
from collections.abc import Sequence
import math
from prompt_mechanism_study.discovery.prioritization import BridgeStatus, ConfirmationDispatchManifest, PolicyTrack
from prompt_mechanism_study.data.discovery_population import (
    DiscoveryPopulationStatus,
    SupplementationDecision,
)
from prompt_mechanism_study.experiment.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    TargetRandomizationPlan,
    TargetTaskBundle,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.tsg.representation import DataRole, DataRoleManifest


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

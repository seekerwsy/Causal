"""Independent power, budget, and provider-preflight reconstruction."""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter, defaultdict
from collections.abc import Sequence

from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    PolicyTrack,
)
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.study_design import (
    ATOMIC_POWER_ARMS,
    PAIR_POWER_ARMS,
    FormalBudgetPreflight,
    ProviderCallKind,
    QualificationProfileKind,
    QualificationStatus,
    RQ1BudgetQualification,
    RQ1BudgetScenario,
    TargetPowerSimulationResult,
)

def verify_target_power_simulation(
    result: TargetPowerSimulationResult,
) -> dict[str, object]:
    """Independently replay a target power grid without the production simulator."""

    if type(result) is not TargetPowerSimulationResult:
        raise TypeError("power verifier requires a TargetPowerSimulationResult")
    plan = result.plan
    recomputed = []
    for assumption in plan.assumptions:
        probabilities = dict(assumption.arm_secure_yield_probabilities)
        if plan.track is PolicyTrack.ATOMIC:
            names = ("atomic_noop", "atomic_target")
            signs = (-1.0, 1.0)
        else:
            names = PAIR_POWER_ARMS
            signs = (1.0, -1.0, -1.0, 1.0)
        slots_per_arm = plan.total_block_slots // len(ATOMIC_POWER_ARMS)
        variances = {}
        for name in names:
            probability = probabilities[name]
            variances[name] = probability * (1 - probability) * (
                assumption.within_arm_request_icc
                + (1 - assumption.within_arm_request_icc) / slots_per_arm
            )
        contribution_variance = sum(variances.values())
        for left_index in range(len(names)):
            for right_index in range(left_index + 1, len(names)):
                covariance = assumption.cross_arm_task_correlation * math.sqrt(
                    variances[names[left_index]] * variances[names[right_index]]
                )
                contribution_variance += (
                    2 * signs[left_index] * signs[right_index] * covariance
                )
        contribution_variance += assumption.realization_effect_sd**2
        if contribution_variance <= 0:
            raise ValueError("power verifier found invalid contribution variance")
        standard_error = math.sqrt(
            contribution_variance / plan.task_units_per_effect
        )
        scenario_seed = int(
            hashlib.sha256(
                f"{plan.simulation_seed}|{assumption.scenario_id}".encode("utf-8")
            ).hexdigest()[:16],
            16,
        )
        rng = random.Random(scenario_seed)
        shared_weight = math.sqrt(assumption.family_coordinate_correlation)
        independent_weight = math.sqrt(1 - assumption.family_coordinate_correlation)
        maxima = []
        for _ in range(plan.simulation_replicates):
            shared = rng.gauss(0, 1)
            values = []
            for _coordinate in range(plan.family_size_upper_bound):
                values.append(
                    abs(
                        shared_weight * shared
                        + independent_weight * rng.gauss(0, 1)
                    )
                )
            maxima.append(max(values))
        maxima.sort()
        critical = maxima[
            min(
                len(maxima) - 1,
                max(0, math.ceil((1 - plan.alpha) * len(maxima)) - 1),
            )
        ]
        meaningful = 0
        for _ in range(plan.simulation_replicates):
            estimate = assumption.effect + standard_error * rng.gauss(0, 1)
            lower = estimate - critical * standard_error
            upper = estimate + critical * standard_error
            if lower > plan.practical_margin or upper < -plan.practical_margin:
                meaningful += 1
        power = meaningful / plan.simulation_replicates
        half_width = 1.96 * math.sqrt(
            power * (1 - power) / plan.simulation_replicates
        )
        recomputed.append(
            (
                assumption.scenario_id,
                assumption.effect,
                standard_error,
                critical,
                power,
                half_width,
            )
        )
    for stored, replay in zip(result.scenarios, recomputed, strict=True):
        if stored.scenario_id != replay[0] or any(
            not math.isclose(stored_value, replay_value, rel_tol=0.0, abs_tol=1e-15)
            for stored_value, replay_value in zip(
                (
                    stored.effect,
                    stored.task_unit_standard_error,
                    stored.simultaneous_critical_value,
                    stored.achieved_power,
                    stored.monte_carlo_half_width_95,
                ),
                replay[1:],
                strict=True,
            )
        ):
            raise ValueError("power simulation result failed independent replay")
    minimum = min(item[4] for item in recomputed)
    if result.minimum_achieved_power != minimum or result.power_gate_passed is not (
        minimum >= plan.target_power
    ):
        raise ValueError("power Gate failed independent replay")
    return {
        "status": "TARGET_POWER_SIMULATION_VERIFIED",
        "plan_id": plan.power_simulation_plan_id,
        "result_id": result.power_simulation_result_id,
        "scenario_count": len(recomputed),
        "minimum_achieved_power": minimum,
        "power_gate_passed": result.power_gate_passed,
    }


def verify_rq1_budget_qualification(
    budget: RQ1BudgetQualification,
) -> dict[str, object]:
    """Independently recompute selector bounds, calls, cost, and blockers."""

    if type(budget) is not RQ1BudgetQualification:
        raise TypeError("budget verifier requires an RQ1BudgetQualification")
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[budget.scenario]
    atomic_expected = ["atomic_full", "atomic_rd_only"]
    pair_expected = ["pair_full", "pair_no_relation"]
    if selector_count >= 3:
        atomic_expected.append("atomic_blind_expert")
        pair_expected.append("pair_blind_expert")
    if selector_count == 4:
        atomic_expected.append("atomic_seeded_random")
        pair_expected.append("pair_seeded_random")
    if budget.atomic_selector_ids != tuple(sorted(atomic_expected)) or (
        budget.pair_selector_ids != tuple(sorted(pair_expected))
    ):
        raise ValueError("budget selector set failed independent replay")
    core_selector_ids = {
        "atomic_full",
        "atomic_rd_only",
        "pair_full",
        "pair_no_relation",
    }
    external_selector_ids = set((*atomic_expected, *pair_expected)) - core_selector_ids
    expected_baseline_coordinates = tuple(
        sorted(
            (selector_id, model_id)
            for selector_id in external_selector_ids
            for model_id in budget.dimensions.model_ids
        )
    )
    baseline = budget.baseline_qualification
    actual_baseline_coordinates = tuple(
        (selector_id, model_id)
        for selector_id, model_id, _ in baseline.contract_references
    )
    baseline_blockers = set()
    if actual_baseline_coordinates != expected_baseline_coordinates:
        baseline_blockers.add("baseline_contract_coverage_incomplete")
    if baseline.independent_verifier_status != "PASS":
        baseline_blockers.add("independent_baseline_verifier_failed")
    if tuple(sorted(baseline_blockers)) != baseline.blockers:
        raise ValueError("baseline qualification blockers failed independent replay")
    baseline_accepted = not baseline_blockers
    if (baseline.status is QualificationStatus.ACCEPTED) is not baseline_accepted:
        raise ValueError("baseline qualification status failed independent replay")
    dimensions = budget.dimensions
    model_count = len(dimensions.model_ids)
    atomic_effects = selector_count * model_count * dimensions.atomic_top_k
    pair_effects = selector_count * model_count * dimensions.pair_top_k
    atomic_bundles = atomic_effects * dimensions.atomic_task_units_per_effect
    pair_bundles = pair_effects * dimensions.pair_task_units_per_effect
    materialization = 2 * (atomic_bundles + pair_bundles)
    generation = (
        atomic_bundles * dimensions.atomic_total_block_slots
        + pair_bundles * dimensions.pair_total_block_slots
    )
    functional = generation
    external = materialization + generation + functional
    currencies = set()
    for rate in budget.provider_ceilings.rates:
        basis = rate.token_cost_basis
        if (
            type(basis.currency) is not str
            or len(basis.currency) != 3
            or basis.currency != basis.currency.upper()
            or not basis.currency.isascii()
            or not basis.currency.isalpha()
        ):
            raise ValueError("provider pricing currency failed independent replay")
        currencies.add(basis.currency)
        integers = (
            basis.pricing_tier_maximum_input_tokens,
            basis.maximum_input_tokens,
            basis.maximum_output_tokens,
            basis.input_price_microunits_per_million_tokens,
            basis.output_price_microunits_per_million_tokens,
        )
        if any(type(value) is not int or value < 0 for value in integers):
            raise ValueError("provider token cost basis failed independent type replay")
        if (
            basis.pricing_tier_maximum_input_tokens <= 0
            or basis.maximum_input_tokens
            > basis.pricing_tier_maximum_input_tokens
            or basis.maximum_input_tokens + basis.maximum_output_tokens <= 0
            or basis.input_price_microunits_per_million_tokens
            + basis.output_price_microunits_per_million_tokens
            <= 0
            or basis.target_outcomes_used is not False
        ):
            raise ValueError("provider token cost basis failed independent boundary replay")
        numerator = (
            basis.maximum_input_tokens
            * basis.input_price_microunits_per_million_tokens
            + basis.maximum_output_tokens
            * basis.output_price_microunits_per_million_tokens
        )
        maximum_cost = (numerator + 999_999) // 1_000_000
        if rate.maximum_unit_cost_microunits != maximum_cost:
            raise ValueError("provider unit cost failed independent token-price replay")
    if len(currencies) != 1:
        raise ValueError("provider budget currency failed independent replay")
    rates = {
        item.call_kind: item.maximum_unit_cost_microunits
        for item in budget.provider_ceilings.rates
    }
    cost = (
        materialization * rates[ProviderCallKind.MATERIALIZATION]
        + generation * rates[ProviderCallKind.GENERATION]
        + functional * rates[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    stored = budget.reservation
    if (
        stored.atomic_effect_record_upper_bound != atomic_effects
        or stored.pair_effect_record_upper_bound != pair_effects
        or stored.materialization_call_upper_bound != materialization
        or stored.generation_call_upper_bound != generation
        or stored.functional_judge_call_upper_bound != functional
        or stored.external_call_upper_bound != external
        or stored.external_cost_upper_bound_microunits != cost
    ):
        raise ValueError("budget reservation failed independent replay")
    blockers = set()
    if not budget.power_and_margin_memo.formal_use_authorized:
        blockers.add("power_and_margin_not_accepted")
    if not budget.qualification_bundle.formal_use_authorized:
        blockers.add("integrated_qualification_not_accepted")
    if not baseline.formal_use_authorized:
        blockers.add("rq1_baseline_qualification_not_accepted")
    if not (
        baseline.protocol_id == budget.power_and_margin_memo.protocol_id
        and baseline.scenario is budget.scenario
        and baseline.model_ids == dimensions.model_ids
    ):
        blockers.add("baseline_qualification_scope_mismatch")
    power_profile = next(
        profile
        for profile in budget.qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
    )
    if not (
        power_profile.artifact.artifact_id
        == budget.power_and_margin_memo.power_and_margin_memo_id
        and power_profile.artifact.sha256
        == content_hash(budget.power_and_margin_memo)
        and power_profile.qualification_accept_data_id
        == budget.power_and_margin_memo.qualification_accept_data_id
        and power_profile.code_commit == budget.power_and_margin_memo.code_commit
        and budget.qualification_bundle.data_role_manifest.artifact_id
        == budget.power_and_margin_memo.data_role_manifest_id
        and budget.qualification_bundle.qualification_accept_data_id
        == budget.power_and_margin_memo.qualification_accept_data_id
    ):
        blockers.add("power_profile_lineage_mismatch")
    baseline_profile = next(
        profile
        for profile in budget.qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
    )
    expected_baseline_profile_id = {
        RQ1BudgetScenario.CORE: "rq1_baseline_set_core_v1",
        RQ1BudgetScenario.CORE_EXPERT: "rq1_baseline_set_core_expert_v1",
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: (
            "rq1_baseline_set_core_expert_random_v1"
        ),
    }[budget.scenario]
    if not (
        baseline.selected_profile_id == expected_baseline_profile_id
        and baseline_profile.selected_profile_id == expected_baseline_profile_id
        and baseline_profile.artifact.artifact_id
        == baseline.rq1_baseline_qualification_id
        and baseline_profile.artifact.sha256 == content_hash(baseline)
        and baseline_profile.qualification_accept_data_id
        == baseline.qualification_accept_data_id
        and baseline_profile.code_commit == baseline.code_commit
        and budget.qualification_bundle.qualification_accept_data_id
        == baseline.qualification_accept_data_id
    ):
        blockers.add("baseline_profile_lineage_mismatch")
    if budget.independent_verifier_status != "PASS":
        blockers.add("independent_budget_verifier_failed")
    for plan, family, tasks, realizations, slots, prefix in (
        (
            budget.power_and_margin_memo.atomic_power.plan,
            atomic_effects,
            dimensions.atomic_task_units_per_effect,
            dimensions.atomic_global_realizations,
            dimensions.atomic_total_block_slots,
            "atomic",
        ),
        (
            budget.power_and_margin_memo.pair_power.plan,
            pair_effects,
            dimensions.pair_task_units_per_effect,
            dimensions.pair_global_realizations,
            dimensions.pair_total_block_slots,
            "pair",
        ),
    ):
        if plan.family_size_upper_bound != family:
            blockers.add(f"{prefix}_family_size_mismatch")
        if plan.task_units_per_effect != tasks:
            blockers.add(f"{prefix}_task_count_mismatch")
        if plan.global_realizations != realizations:
            blockers.add(f"{prefix}_realization_count_mismatch")
        if plan.total_block_slots != slots:
            blockers.add(f"{prefix}_block_slot_mismatch")
    ceilings = budget.provider_ceilings
    for actual, limit, reason in (
        (
            materialization,
            ceilings.materialization_call_ceiling,
            "materialization_call_ceiling_exceeded",
        ),
        (generation, ceilings.generation_call_ceiling, "generation_call_ceiling_exceeded"),
        (
            functional,
            ceilings.functional_judge_call_ceiling,
            "functional_judge_call_ceiling_exceeded",
        ),
        (external, ceilings.external_call_ceiling, "external_call_ceiling_exceeded"),
        (cost, ceilings.external_cost_ceiling_microunits, "external_cost_ceiling_exceeded"),
    ):
        if actual > limit:
            blockers.add(reason)
    if tuple(sorted(blockers)) != budget.blockers:
        raise ValueError("budget blockers failed independent replay")
    accepted = not blockers
    if (budget.status is QualificationStatus.ACCEPTED) is not accepted:
        raise ValueError("budget qualification status failed independent replay")
    return {
        "status": "RQ1_BUDGET_QUALIFICATION_VERIFIED",
        "budget_qualification_id": budget.rq1_budget_qualification_id,
        "scenario": budget.scenario.value,
        "baseline_qualification_id": baseline.rq1_baseline_qualification_id,
        "external_call_upper_bound": external,
        "external_cost_upper_bound_microunits": cost,
        "budget_currency": next(iter(currencies)),
        "provider_calls_authorized": budget.provider_calls_authorized,
    }


def verify_formal_budget_preflight(
    budget: RQ1BudgetQualification,
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[AssignedArmITTRecord],
    preflight: FormalBudgetPreflight,
) -> dict[str, object]:
    """Independently replay the actual dispatch, assignment blocks, calls, and cost."""

    verify_rq1_budget_qualification(budget)
    if budget.status is not QualificationStatus.ACCEPTED:
        raise ValueError("formal preflight requires an accepted budget")
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("preflight verifier requires a dispatch manifest")
    if type(preflight) is not FormalBudgetPreflight:
        raise TypeError("preflight verifier requires a FormalBudgetPreflight")
    frozen = tuple(assignments)
    if any(type(item) is not AssignedArmITTRecord for item in frozen):
        raise TypeError("preflight verifier requires assigned-arm records")
    assignment_ids = tuple(item.assignment_id for item in frozen)
    if len(set(assignment_ids)) != len(assignment_ids):
        raise ValueError("formal assignment identities failed independent replay")
    records = {item.candidate_record_id: item for item in dispatch.records}
    tracks = {
        item.candidate_record_id: item.track for item in dispatch.union.entries
    }
    successful = {
        item.candidate_record_id
        for item in dispatch.records
        if item.status is BridgeStatus.SUCCESS
    }
    by_candidate: dict[str, list[AssignedArmITTRecord]] = defaultdict(list)
    for item in frozen:
        record = records.get(item.candidate_record_id)
        if record is None or item.candidate_record_id not in successful:
            raise ValueError("assignment targets a failed or unknown dispatch")
        if (
            item.effect_coordinate_id != record.effect_coordinate_id
            or item.policy_key != record.policy_key
            or item.model_id != record.model_id
            or item.protocol_record_id != record.protocol_record_id
            or item.track is not tracks[item.candidate_record_id]
            or item.model_id not in budget.dimensions.model_ids
        ):
            raise ValueError("assignment model-bound lineage failed independent replay")
        by_candidate[item.candidate_record_id].append(item)
    if set(by_candidate) != successful:
        raise ValueError("successful dispatch coverage failed independent replay")
    for candidate_id, rows in by_candidate.items():
        track = tracks[candidate_id]
        task_count = (
            budget.dimensions.atomic_task_units_per_effect
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_task_units_per_effect
        )
        block_slots = (
            budget.dimensions.atomic_total_block_slots
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_total_block_slots
        )
        arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        task_ids = {item.task_unit_id for item in rows}
        if len(task_ids) != task_count:
            raise ValueError("formal task count failed independent replay")
        for task_unit_id in task_ids:
            block = [item for item in rows if item.task_unit_id == task_unit_id]
            counts = Counter(item.arm for item in block)
            if (
                len(block) != block_slots
                or len({item.realization_id for item in block}) != 1
                or len({item.task_bundle_id for item in block}) != 1
                or set(counts) != set(arms)
                or len(set(counts.values())) != 1
                or {item.request_randomness_slot for item in block}
                != set(range(block_slots))
            ):
                raise ValueError("formal four-arm block failed independent replay")
    atomic_effects = sum(
        tracks[candidate_id] is PolicyTrack.ATOMIC for candidate_id in successful
    )
    pair_effects = sum(
        tracks[candidate_id] is PolicyTrack.PAIR for candidate_id in successful
    )
    generation = len(frozen)
    materialization = 2 * len({item.task_bundle_id for item in frozen})
    functional = generation
    external = materialization + generation + functional
    rates = {
        item.call_kind: item.maximum_unit_cost_microunits
        for item in budget.provider_ceilings.rates
    }
    cost = (
        materialization * rates[ProviderCallKind.MATERIALIZATION]
        + generation * rates[ProviderCallKind.GENERATION]
        + functional * rates[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    expected = (
        budget.rq1_budget_qualification_id,
        dispatch.confirmation_dispatch_manifest_id,
        content_hash(tuple(sorted(frozen, key=lambda item: item.assignment_id))),
        atomic_effects,
        pair_effects,
        materialization,
        generation,
        functional,
        external,
        cost,
        "PASS",
        True,
    )
    observed = (
        preflight.budget_qualification_id,
        preflight.confirmation_dispatch_manifest_id,
        preflight.assignment_manifest_sha256,
        preflight.atomic_effect_records,
        preflight.pair_effect_records,
        preflight.materialization_calls,
        preflight.generation_calls,
        preflight.functional_judge_call_reservation,
        preflight.external_call_reservation,
        preflight.external_cost_reservation_microunits,
        preflight.status,
        preflight.provider_calls_authorized,
    )
    if observed != expected:
        raise ValueError("formal budget preflight failed independent replay")
    reservation = budget.reservation
    ceilings = budget.provider_ceilings
    if (
        atomic_effects > reservation.atomic_effect_record_upper_bound
        or pair_effects > reservation.pair_effect_record_upper_bound
        or materialization > reservation.materialization_call_upper_bound
        or generation > reservation.generation_call_upper_bound
        or functional > reservation.functional_judge_call_upper_bound
        or external > reservation.external_call_upper_bound
        or cost > reservation.external_cost_upper_bound_microunits
        or materialization > ceilings.materialization_call_ceiling
        or generation > ceilings.generation_call_ceiling
        or functional > ceilings.functional_judge_call_ceiling
        or external > ceilings.external_call_ceiling
        or cost > ceilings.external_cost_ceiling_microunits
    ):
        raise ValueError("formal preflight exceeds its independently replayed reservation")
    return {
        "status": "FORMAL_BUDGET_PREFLIGHT_VERIFIED",
        "formal_budget_preflight_id": preflight.formal_budget_preflight_id,
        "assignment_count": len(frozen),
        "external_call_reservation": external,
        "external_cost_reservation_microunits": cost,
    }

__all__ = [
    "verify_formal_budget_preflight",
    "verify_rq1_budget_qualification",
    "verify_target_power_simulation",
]

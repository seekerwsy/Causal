"""Independent recomputation for stored selector-study results."""

from __future__ import annotations

import hashlib
import math
import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json_exact,
    verify_bundle,
)

from prompt_mechanism_study.inference import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
    ConfirmatoryArm,
    ConfirmatoryEffectStatus,
    EvidenceLevel,
    SharedEvidenceRecord,
    TargetITTPlan,
    TargetFamilyStatus,
    TargetRandomizationPlan,
    TargetSelectorYieldResult,
    TargetTaskBundle,
)
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    FixedSlotLedger,
    PolicyTrack,
    SelectionFreezeManifest,
    SharedBridgeMap,
    SharedConfirmationUnion,
    SlotStatus,
)
from prompt_mechanism_study.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.selector_inference import (
    ConfirmationCoordinate,
    ConfirmationStatus,
    SelectorInferencePlan,
    SelectorInferenceResult,
    SelectorMethodPoint,
    SelectorPairInterval,
    SelectorPairPoint,
    SelectorYieldPoint,
    SlotContribution,
)
from prompt_mechanism_study.study_design import (
    ATOMIC_POWER_ARMS,
    ConfirmationFreeze,
    DiscoveryDesignFreeze,
    FormalBudgetPreflight,
    FormalReportAuthorization,
    PAIR_POWER_ARMS,
    ProviderCallKind,
    QualificationProfileKind,
    QualificationStatus,
    RQ1BudgetQualification,
    RQ1BudgetScenario,
    StudyFreezeIndex,
    TargetPowerSimulationResult,
)


TARGET_RESULT_PACKAGE_FILES = frozenset(
    {
        "package_index.json",
        "data_role_manifest.json",
        "rq1_budget_qualification.json",
        "discovery_design_freeze.json",
        "fixed_slot_ledger.json",
        "shared_confirmation_union.json",
        "confirmation_dispatch_manifest.json",
        "target_randomization_plan.json",
        "confirmation_task_bundles.json",
        "assignments.json",
        "formal_budget_preflight.json",
        "confirmation_freeze.json",
        "study_freeze_index.json",
        "shared_evidence_record.json",
        "target_selector_yield_result.json",
        "formal_report_authorization.json",
        "rq_tables.json",
        "verification.json",
    }
)


def verify_selector_result(
    selection: SelectionFreezeManifest,
    bridge: SharedBridgeMap,
    coordinates: Sequence[ConfirmationCoordinate],
    plan: SelectorInferencePlan,
    result: SelectorInferenceResult,
) -> dict[str, object]:
    """Recompute every status, K denominator, draw, and paired interval."""

    if not selection.gate_passed or bridge.selection_id != selection.selection_id:
        raise ValueError("selector verifier received an unbound or gate-failed study")
    frozen = tuple(sorted(coordinates, key=lambda item: item.coordinate_id))
    if (
        result.plan_id != plan.plan_id
        or result.selection_id != selection.selection_id
        or result.bridge_map_id != bridge.bridge_map_id
        or result.confirmation_input_sha256 != content_hash(frozen)
    ):
        raise ValueError("selector result provenance mismatch")
    successful = {
        record.final_hypothesis_id
        for record in bridge.records
        if record.status is BridgeStatus.SUCCESS
    }
    if {item.final_hypothesis_id for item in frozen} != successful:
        raise ValueError("selector verifier lacks an exact successful-bridge coordinate set")

    population = tuple(sorted({unit for item in frozen for unit, _ in item.task_unit_effects}))
    occurrences = tuple((index, unit) for index, unit in enumerate(population))
    statuses, primary_critical, primary_valid, primary_invalid = _statuses(
        frozen,
        occurrences,
        plan,
        random.Random(_seed(plan.bootstrap_seed, "full_primary")),
    )
    yields, methods = _points(selection, bridge, statuses)
    pair_points = _pairs(methods, plan.selector_pairs)

    rng = random.Random(_seed(plan.bootstrap_seed, "outer"))
    outer = []
    invalid_outer = 0
    for draw_index in range(plan.outer_draws):
        sampled = [population[rng.randrange(len(population))] for _ in population]
        sampled_occurrences = tuple((index, unit) for index, unit in enumerate(sampled))
        draw_statuses, critical, valid, _invalid = _statuses(
            frozen,
            sampled_occurrences,
            plan,
            random.Random(_seed(plan.bootstrap_seed, f"outer_inner_{draw_index}")),
        )
        if critical is None or valid < math.ceil(plan.inner_draws * plan.minimum_valid_fraction):
            invalid_outer += 1
            continue
        _draw_yields, draw_methods = _points(selection, bridge, draw_statuses)
        outer.append({item.pair_id: item.difference for item in _pairs(draw_methods, plan.selector_pairs)})
    intervals, pair_critical, pair_status = _intervals(pair_points, outer, plan)

    checks = (
        (result.primary_critical_value, primary_critical, "primary critical value"),
        (result.primary_valid_draws, primary_valid, "primary valid draws"),
        (result.primary_invalid_draws, primary_invalid, "primary invalid draws"),
        (result.confirmation_statuses, statuses, "confirmation statuses"),
        (result.yield_points, yields, "strict ConfirmedYield@K"),
        (result.method_points, methods, "selector method points"),
        (result.pair_points, pair_points, "selector pair points"),
        (result.selector_pair_critical_value, pair_critical, "selector pair critical value"),
        (result.pair_intervals, intervals, "selector pair intervals"),
        (result.valid_outer_draws, len(outer), "valid outer draws"),
        (result.invalid_outer_draws, invalid_outer, "invalid outer draws"),
        (result.outer_pair_draws_sha256, content_hash(outer), "outer draw digest"),
        (result.pair_inference_status, pair_status, "pair inference status"),
    )
    for actual, expected, name in checks:
        if actual != expected:
            raise ValueError(f"selector result {name} does not independently recompute")
    return {
        "status": "SELECTOR_RESULT_VERIFIED",
        "selectors": len(selection.runs),
        "rankings": sum(len(run.rankings) for run in selection.runs),
        "budget_slots": sum(
            len(ranking.slots) for run in selection.runs for ranking in run.rankings
        ),
        "confirmation_coordinates": len(frozen),
        "valid_outer_draws": len(outer),
    }


def verify_target_shared_evidence(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
) -> dict[str, object]:
    """Independently replay target v3 ITT, max-|T|, five statuses, and Yield@K."""

    if type(evidence) is not SharedEvidenceRecord or type(yields) is not TargetSelectorYieldResult:
        raise TypeError("target verifier requires typed shared evidence and yield records")
    if yields.shared_evidence_record_id != evidence.shared_evidence_record_id:
        raise ValueError("target yield record is not bound to the shared evidence")
    ledger = evidence.ledger
    plan = evidence.plan
    outcome_by_id = {item.assignment_id: item for item in ledger.outcomes}
    failed = {item.assignment_id for item in ledger.infrastructure_failures}
    assignments_by_candidate = defaultdict(list)
    for item in ledger.assignments:
        assignments_by_candidate[item.candidate_record_id].append(item)
    track_by_candidate = {
        item.candidate_record_id: item.track for item in ledger.dispatch.union.entries
    }
    work = {}
    for dispatch in ledger.dispatch.records:
        if dispatch.status is not BridgeStatus.SUCCESS:
            continue
        work[dispatch.candidate_record_id] = _v3_work(
            track_by_candidate[dispatch.candidate_record_id],
            tuple(assignments_by_candidate[dispatch.candidate_record_id]),
            outcome_by_id,
            failed,
            plan,
        )
    status_by_candidate = {}
    for family in evidence.families:
        family_work = {
            candidate_id: value
            for candidate_id, value in work.items()
            if value["track"] is family.track
        }
        expected = _v3_family(family.track, family_work, plan)
        if family.status is not expected["family_status"]:
            raise ValueError("target family status does not independently recompute")
        _v3_same(family.simultaneous_critical_value, expected["critical"], "critical value")
        if (
            family.valid_bootstrap_draws != expected["valid"]
            or family.invalid_bootstrap_draws != expected["invalid"]
        ):
            raise ValueError("target bootstrap accounting does not independently recompute")
        reported = {item.candidate_record_id: item for item in family.estimates}
        if set(reported) != set(family_work):
            raise ValueError("target family estimate membership drift")
        for candidate_id, value in family_work.items():
            item = reported[candidate_id]
            expected_status = expected["statuses"][candidate_id]
            if item.status is not expected_status:
                raise ValueError("target five-level status does not independently recompute")
            status_by_candidate[candidate_id] = item.status
            margin = (
                plan.atomic_practical_margin
                if family.track is PolicyTrack.ATOMIC
                else plan.pair_practical_margin
            )
            _v3_same(item.practical_margin, margin, "practical margin")
            _v3_same(item.point, value["point"], "point estimate")
            _v3_same(item.standard_error, value["standard_error"], "standard error")
            _v3_same(item.latent_lower, value["latent_lower"], "latent lower bound")
            _v3_same(item.latent_upper, value["latent_upper"], "latent upper bound")
            _v3_same(item.simultaneous_lower, expected["intervals"][candidate_id][0], "interval lower")
            _v3_same(item.simultaneous_upper, expected["intervals"][candidate_id][1], "interval upper")
            if item.reasons != expected["reasons"][candidate_id]:
                raise ValueError("target non-evaluable reasons do not independently recompute")
            if item.assignments != value["assignments"] or item.task_units != len(
                value["contributions"]
            ):
                raise ValueError("target assignment or task-unit accounting drift")
            _v3_check_contributions(item.task_unit_contributions, value["contributions"])
            _v3_check_arm_summaries(item.arm_summaries, value["arm_summaries"])
    _v3_verify_yields(evidence, yields, status_by_candidate)
    return {
        "status": "TARGET_SHARED_EVIDENCE_VERIFIED",
        "assignments": len(ledger.assignments),
        "outcomes": len(ledger.outcomes),
        "repair_failures": len(ledger.infrastructure_failures),
        "unique_effects": len(status_by_candidate),
        "fixed_slots": len(yields.slots),
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
    }


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
        (materialization, ceilings.materialization_call_ceiling, "materialization_call_ceiling_exceeded"),
        (generation, ceilings.generation_call_ceiling, "generation_call_ceiling_exceeded"),
        (functional, ceilings.functional_judge_call_ceiling, "functional_judge_call_ceiling_exceeded"),
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
    if not frozen_bundles or any(type(item) is not TargetTaskBundle for item in frozen_bundles):
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
    successful = tuple(
        item for item in dispatch.records if item.status is BridgeStatus.SUCCESS
    )
    protocol_by_policy: dict[str, str] = {}
    for record in successful:
        prior = protocol_by_policy.setdefault(record.policy_key, record.protocol_record_id)
        if prior != record.protocol_record_id:
            raise ValueError("shared policy protocolization failed independent replay")
    if {item.policy_key for item in frozen_bundles} != {
        item.policy_key for item in successful
    }:
        raise ValueError("task-bundle policy support failed independent replay")
    bundles_by_policy: dict[str, list[TargetTaskBundle]] = defaultdict(list)
    for bundle in frozen_bundles:
        if (
            bundle.track is not track_by_policy.get(bundle.policy_key)
            or bundle.protocol_record_id != protocol_by_policy.get(bundle.policy_key)
        ):
            raise ValueError("task-bundle protocol lineage failed independent replay")
        bundles_by_policy[bundle.policy_key].append(bundle)

    expected = []
    for record in successful:
        track = track_by_policy[record.policy_key]
        arms = ATOMIC_CONFIRMATORY_ARMS if track is PolicyTrack.ATOMIC else PAIR_CONFIRMATORY_ARMS
        slot_count = (
            plan.atomic_total_block_slots
            if track is PolicyTrack.ATOMIC
            else plan.pair_total_block_slots
        )
        arm_copies = tuple(
            (arm, repeat)
            for repeat in range(slot_count // len(arms))
            for arm in arms
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
                    & 0x7FFFFFFF
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
    """Independently close the complete target design-to-confirmation freeze chain."""

    if type(manifest) is not DataRoleManifest:
        raise TypeError("target freeze verifier requires a DataRoleManifest")
    randomization_verification = verify_target_randomization(
        dispatch,
        randomization_plan,
        task_bundles,
        assignments,
    )
    verify_formal_budget_preflight(budget, dispatch, assignments, preflight)
    qualification = budget.qualification_bundle
    if (
        discovery.protocol_id != manifest.protocol_id
        or discovery.protocol_id != budget.protocol_id
        or discovery.data_role_manifest.artifact_id
        != manifest.data_role_manifest_id
        or discovery.data_role_manifest.sha256 != content_hash(manifest)
        or discovery.qualification_bundle.artifact_id
        != qualification.qualification_bundle_id
        or discovery.qualification_bundle.sha256 != content_hash(qualification)
        or discovery.rq1_budget_qualification.artifact_id
        != budget.rq1_budget_qualification_id
        or discovery.rq1_budget_qualification.sha256 != content_hash(budget)
    ):
        raise ValueError("discovery freeze lineage failed independent replay")
    selector_count = {
        RQ1BudgetScenario.CORE: 2,
        RQ1BudgetScenario.CORE_EXPERT: 3,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: 4,
    }[budget.scenario]
    atomic_selectors = ["atomic_full", "atomic_rd_only"]
    pair_selectors = ["pair_full", "pair_no_relation"]
    if selector_count >= 3:
        atomic_selectors.append("atomic_blind_expert")
        pair_selectors.append("pair_blind_expert")
    if selector_count == 4:
        atomic_selectors.append("atomic_seeded_random")
        pair_selectors.append("pair_seeded_random")
    frozen_atomic = tuple(sorted(atomic_selectors))
    frozen_pair = tuple(sorted(pair_selectors))
    core = {
        "atomic_full",
        "atomic_rd_only",
        "pair_full",
        "pair_no_relation",
    }
    baselines = tuple(sorted(set((*frozen_atomic, *frozen_pair)) - core))
    if (
        discovery.atomic_top_k != budget.dimensions.atomic_top_k
        or discovery.pair_top_k != budget.dimensions.pair_top_k
        or discovery.model_ids != budget.dimensions.model_ids
        or discovery.rq1_budget_scenario is not budget.scenario
        or discovery.atomic_selector_ids != frozen_atomic
        or discovery.pair_selector_ids != frozen_pair
        or discovery.rq1_baseline_ids != baselines
        or discovery.rq2_comparison_semantics
        != "descriptive_fixed_denominator_full_minus_ablation_no_interval"
        or discovery.created_before_discovery_outcomes is not True
    ):
        raise ValueError("discovery dimensions failed independent replay")
    expected_coordinates = {
        (track, model_id, selector_id)
        for track, selectors in (
            (PolicyTrack.ATOMIC, frozen_atomic),
            (PolicyTrack.PAIR, frozen_pair),
        )
        for model_id in discovery.model_ids
        for selector_id in selectors
    }
    if (
        ledger.protocol_id != discovery.protocol_id
        or ledger.schema_version != discovery.schema_version
        or ledger.top_k_by_track
        != (
            (PolicyTrack.ATOMIC, discovery.atomic_top_k),
            (PolicyTrack.PAIR, discovery.pair_top_k),
        )
        or {
            (source.track, source.model_id, source.selector_id)
            for source in ledger.sources
        }
        != expected_coordinates
        or union.ledger != ledger
        or dispatch.union != union
    ):
        raise ValueError("confirmation selection failed independent replay")
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    frozen_task_bundles = tuple(task_bundles)
    if (
        randomization_plan.atomic_total_block_slots
        != budget.dimensions.atomic_total_block_slots
        or randomization_plan.pair_total_block_slots
        != budget.dimensions.pair_total_block_slots
    ):
        raise ValueError("target randomization slots failed independent budget replay")
    eligible_rows = tuple(
        sorted(
            {
                (
                    item.policy_key,
                    item.task_unit_id,
                    item.task_instance_id,
                    item.stratum_id,
                )
                for item in frozen_task_bundles
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
        budget.power_and_margin_memo.pair_power.plan.practical_margin,
        budget.power_and_margin_memo.maximum_unknown_fraction_among_valid,
    )
    dispatch_id = dispatch.confirmation_dispatch_manifest_id
    dispatch_hash = content_hash(dispatch)
    confirmation_checks = (
        confirmation.protocol_id == discovery.protocol_id,
        confirmation.schema_version == discovery.schema_version,
        confirmation.discovery_design_freeze.artifact_id
        == discovery.discovery_design_freeze_id,
        confirmation.discovery_design_freeze.sha256 == content_hash(discovery),
        confirmation.fixed_slot_ledger.artifact_id == ledger.fixed_slot_ledger_id,
        confirmation.fixed_slot_ledger.sha256 == content_hash(ledger),
        confirmation.unique_candidate_union.artifact_id
        == union.shared_confirmation_union_id,
        confirmation.unique_candidate_union.sha256 == content_hash(union),
        confirmation.candidate_to_slots.artifact_id
        == content_id("candidate_to_slots_", union.candidate_to_slots),
        confirmation.candidate_to_slots.sha256
        == content_hash(union.candidate_to_slots),
        confirmation.bridge_results.artifact_id == dispatch_id,
        confirmation.bridge_results.sha256 == dispatch_hash,
        confirmation.protocolization_results.artifact_id
        == content_id("target_task_bundles_", frozen_task_bundles),
        confirmation.protocolization_results.sha256
        == content_hash(frozen_task_bundles),
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
        confirmation.model_bound_assignments.sha256
        == content_hash(frozen_assignments),
        confirmation.formal_budget_preflight.artifact_id
        == preflight.formal_budget_preflight_id,
        confirmation.formal_budget_preflight.sha256 == content_hash(preflight),
        confirmation.inference_and_reporting_plan.artifact_id
        == plan.target_itt_plan_id,
        confirmation.inference_and_reporting_plan.sha256 == content_hash(plan),
        confirmation.created_before_confirmation_outcomes is True,
    )
    if not all(confirmation_checks):
        raise ValueError("confirmation freeze lineage failed independent replay")
    if (
        index.protocol_id != discovery.protocol_id
        or index.discovery_design_freeze.artifact_id
        != discovery.discovery_design_freeze_id
        or index.discovery_design_freeze.sha256 != content_hash(discovery)
        or index.confirmation_freeze.artifact_id
        != confirmation.confirmation_freeze_id
        or index.confirmation_freeze.sha256 != content_hash(confirmation)
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


def verify_formal_report_authorization(
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
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    authorization: FormalReportAuthorization,
) -> dict[str, object]:
    """Independently verify the only receipt that can enable paper-facing claims."""

    if type(authorization) is not FormalReportAuthorization:
        raise TypeError("report authorization verifier requires a formal receipt")
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
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    confirmation_task_units = {
        task.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for task in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in frozen_assignments}
    plan = TargetITTPlan(
        budget.power_and_margin_memo.bootstrap_seed,
        budget.power_and_margin_memo.bootstrap_draws,
        budget.power_and_margin_memo.alpha,
        budget.power_and_margin_memo.atomic_power.plan.minimum_task_units_per_stratum,
        budget.power_and_margin_memo.minimum_valid_bootstrap_fraction,
        budget.power_and_margin_memo.atomic_power.plan.practical_margin,
        budget.power_and_margin_memo.pair_power.plan.practical_margin,
        budget.power_and_margin_memo.maximum_unknown_fraction_among_valid,
    )
    if (
        evidence.evidence_level not in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
        or evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != frozen_assignments
        or evidence.plan != plan
        or not assigned_task_units
        or not assigned_task_units <= confirmation_task_units
    ):
        raise ValueError("formal report evidence boundary failed independent replay")
    expected = (
        manifest.protocol_id,
        index.study_freeze_index_id,
        content_hash(index),
        evidence.shared_evidence_record_id,
        content_hash(evidence),
        yields.target_selector_yield_result_id,
        content_hash(yields),
        evidence.ledger.evidence_ledger_id,
        content_hash(evidence.ledger),
        content_hash(freeze_verification),
        content_hash(evidence_verification),
        evidence.evidence_level.value,
        "AUTHORIZED",
        True,
    )
    observed = (
        authorization.protocol_id,
        authorization.study_freeze_index.artifact_id,
        authorization.study_freeze_index.sha256,
        authorization.shared_evidence_record.artifact_id,
        authorization.shared_evidence_record.sha256,
        authorization.target_selector_yield_result.artifact_id,
        authorization.target_selector_yield_result.sha256,
        authorization.evidence_ledger.artifact_id,
        authorization.evidence_ledger.sha256,
        authorization.freeze_verification_sha256,
        authorization.evidence_verification_sha256,
        authorization.evidence_level,
        authorization.authorization_status,
        authorization.scientific_claim_allowed,
    )
    if observed != expected:
        raise ValueError("formal report authorization failed independent replay")
    return {
        "status": "FORMAL_REPORT_AUTHORIZATION_VERIFIED",
        "formal_report_authorization_id": (
            authorization.formal_report_authorization_id
        ),
        "scientific_claim_allowed": True,
        "evidence_level": evidence.evidence_level.value,
    }


def verify_target_rq_tables(
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Independently rebuild every target RQ row and its claim-level Gate."""

    verification = verify_target_shared_evidence(evidence, yields)
    slots_by_selector: dict[tuple[PolicyTrack, str, str], list[object]] = defaultdict(list)
    for slot in yields.slots:
        slots_by_selector[(slot.track, slot.model_id, slot.selector_id)].append(slot)
    selector_rows = []
    for selector in sorted(
        yields.selectors,
        key=lambda item: (item.track.value, item.model_id, item.selector_id),
    ):
        slots = sorted(
            slots_by_selector[(selector.track, selector.model_id, selector.selector_id)],
            key=lambda item: item.rank,
        )
        if len(slots) != selector.top_k:
            raise ValueError("RQ verifier lost a fixed selector slot")
        counts = Counter(
            (
                slot.effect_status.value
                if slot.effect_status is not None
                else (
                    "SELECTOR_EMPTY_OR_FAILURE"
                    if slot.slot_status is not SlotStatus.FILLED
                    else "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                )
            )
            for slot in slots
        )
        selector_rows.append(
            {
                "track": selector.track.value,
                "model_id": selector.model_id,
                "selector_id": selector.selector_id,
                "top_k": selector.top_k,
                "meaningful_slots": selector.meaningful_slots,
                "meaningful_yield_at_k": selector.meaningful_yield_at_k,
                "positive_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL.value
                ],
                "negative_meaningful_slots": counts[
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL.value
                ],
                "practically_null_slots": counts[
                    ConfirmatoryEffectStatus.PRACTICALLY_NULL.value
                ],
                "inconclusive_slots": counts[
                    ConfirmatoryEffectStatus.INCONCLUSIVE.value
                ],
                "non_evaluable_slots": counts[
                    ConfirmatoryEffectStatus.NON_EVALUABLE.value
                ],
                "selector_empty_or_failure_slots": counts[
                    "SELECTOR_EMPTY_OR_FAILURE"
                ],
                "bridge_or_protocolization_failure_slots": counts[
                    "BRIDGE_OR_PROTOCOLIZATION_FAILURE"
                ],
            }
        )
    selector_by_key = {
        (row["track"], row["model_id"], row["selector_id"]): row
        for row in selector_rows
    }
    rq2_rows = []
    for track, full_id, ablation_id in (
        (PolicyTrack.ATOMIC, "atomic_full", "atomic_rd_only"),
        (PolicyTrack.PAIR, "pair_full", "pair_no_relation"),
    ):
        models = sorted(
            {
                model
                for row_track, model, selector in selector_by_key
                if row_track == track.value and selector in {full_id, ablation_id}
            }
        )
        for model in models:
            full = selector_by_key.get((track.value, model, full_id))
            ablation = selector_by_key.get((track.value, model, ablation_id))
            if full is None or ablation is None or full["top_k"] != ablation["top_k"]:
                raise ValueError("RQ2 verifier lacks a sole-difference selector pair")
            rq2_rows.append(
                {
                    "track": track.value,
                    "model_id": model,
                    "full_selector_id": full_id,
                    "ablation_selector_id": ablation_id,
                    "top_k": full["top_k"],
                    "full_meaningful_yield_at_k": full["meaningful_yield_at_k"],
                    "ablation_meaningful_yield_at_k": ablation[
                        "meaningful_yield_at_k"
                    ],
                    "full_minus_ablation_yield_at_k": (
                        full["meaningful_yield_at_k"]
                        - ablation["meaningful_yield_at_k"]
                    ),
                    "comparison_semantics": (
                        "descriptive_fixed_discovery_split_no_rank_pairing"
                    ),
                }
            )
    families = []
    effects = []
    for family in evidence.families:
        families.append(
            {
                "track": family.track.value,
                "family_status": family.status.value,
                "simultaneous_critical_value": family.simultaneous_critical_value,
                "valid_bootstrap_draws": family.valid_bootstrap_draws,
                "invalid_bootstrap_draws": family.invalid_bootstrap_draws,
                "unique_effects": len(family.estimates),
            }
        )
        for estimate in family.estimates:
            effects.append(
                {
                    "track": estimate.track.value,
                    "candidate_record_id": estimate.candidate_record_id,
                    "effect_coordinate_id": estimate.effect_coordinate_id,
                    "policy_key": estimate.policy_key,
                    "model_id": estimate.model_id,
                    "estimand": (
                        "assigned_arm_task_unit_target_minus_noop_itt"
                        if estimate.track is PolicyTrack.ATOMIC
                        else "assigned_cell_task_unit_risk_difference_interaction_itt"
                    ),
                    "primary_endpoint": "oracle_evaluable_secure_code_yield",
                    "point": estimate.point,
                    "standard_error": estimate.standard_error,
                    "simultaneous_lower": estimate.simultaneous_lower,
                    "simultaneous_upper": estimate.simultaneous_upper,
                    "latent_lower": estimate.latent_lower,
                    "latent_upper": estimate.latent_upper,
                    "practical_margin": estimate.practical_margin,
                    "effect_status": estimate.status.value,
                    "reasons": list(estimate.reasons),
                    "task_units": estimate.task_units,
                    "assignments": estimate.assignments,
                    "arms": [
                        {
                            "arm": arm.arm.value,
                            "assignments": arm.assignments,
                            "secure_yield": arm.secure_yield,
                            "code_validity": arm.code_validity,
                            "oracle_evaluability": arm.oracle_evaluability,
                            "functionality_yield": arm.functionality_yield,
                            "joint_success_yield": arm.joint_success_yield,
                            "oracle_unknown_valid_assignments": (
                                arm.oracle_unknown_valid_assignments
                            ),
                            "terminal_assignments": arm.terminal_assignments,
                        }
                        for arm in estimate.arm_summaries
                    ],
                }
            )
    claim_allowed = authorization is not None
    if authorization is not None:
        if type(authorization) is not FormalReportAuthorization:
            raise TypeError("RQ verifier requires a formal authorization receipt")
        if (
            authorization.protocol_id
            != evidence.ledger.dispatch.union.ledger.protocol_id
            or authorization.shared_evidence_record.artifact_id
            != evidence.shared_evidence_record_id
            or authorization.shared_evidence_record.sha256 != content_hash(evidence)
            or authorization.target_selector_yield_result.artifact_id
            != yields.target_selector_yield_result_id
            or authorization.target_selector_yield_result.sha256
            != content_hash(yields)
            or authorization.evidence_ledger.artifact_id
            != evidence.ledger.evidence_ledger_id
            or authorization.evidence_ledger.sha256 != content_hash(evidence.ledger)
            or authorization.evidence_level != evidence.evidence_level.value
            or authorization.scientific_claim_allowed is not True
        ):
            raise ValueError("RQ authorization failed independent evidence binding")
        report_status = "FORMAL_REPORT_AUTHORIZED"
    else:
        report_status = (
            "EXECUTED_EVIDENCE_AWAITING_FORMAL_REPORT_AUTHORIZATION"
            if evidence.evidence_level
            in {EvidenceLevel.EXECUTED, EvidenceLevel.REPORTED}
            else "NON_CLAIM_TEST_ARTIFACT"
        )
    expected = {
        "schema_version": "3.0",
        "protocol_id": evidence.ledger.dispatch.union.ledger.protocol_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "evidence_level": evidence.evidence_level.value,
        "report_status": report_status,
        "scientific_claim_allowed": claim_allowed,
        "formal_report_authorization_id": (
            None
            if authorization is None
            else authorization.formal_report_authorization_id
        ),
        "endpoint_order": [item.value for item in evidence.plan.metrics],
        "rq1_selector_rows": selector_rows,
        "rq2_full_minus_ablation_rows": rq2_rows,
        "primary_family_rows": families,
        "unique_effect_rows": sorted(
            effects,
            key=lambda row: (row["track"], row["candidate_record_id"]),
        ),
        "independent_verification": verification,
    }
    expected["target_rq_tables_id"] = content_id("target_rq_tables_", expected)
    if dict(report) != expected:
        raise ValueError("target RQ tables failed independent replay")
    return {
        "status": "TARGET_RQ_TABLES_VERIFIED",
        "target_rq_tables_id": expected["target_rq_tables_id"],
        "scientific_claim_allowed": claim_allowed,
        "selector_rows": len(selector_rows),
        "rq2_rows": len(rq2_rows),
        "unique_effect_rows": len(effects),
    }


def verify_target_result_components(
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
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Independently close every scientific boundary in one target result package."""

    roots = (
        (manifest, DataRoleManifest, "data-role manifest"),
        (budget, RQ1BudgetQualification, "RQ1 budget"),
        (discovery, DiscoveryDesignFreeze, "discovery freeze"),
        (ledger, FixedSlotLedger, "fixed-slot ledger"),
        (union, SharedConfirmationUnion, "shared union"),
        (dispatch, ConfirmationDispatchManifest, "confirmation dispatch"),
        (randomization_plan, TargetRandomizationPlan, "randomization plan"),
        (preflight, FormalBudgetPreflight, "formal budget preflight"),
        (confirmation, ConfirmationFreeze, "confirmation freeze"),
        (index, StudyFreezeIndex, "study-freeze index"),
        (evidence, SharedEvidenceRecord, "shared evidence"),
        (yields, TargetSelectorYieldResult, "selector yields"),
    )
    for value, expected_type, label in roots:
        if type(value) is not expected_type:
            raise TypeError(f"target result package requires a typed {label}")
    if authorization is not None and type(authorization) is not FormalReportAuthorization:
        raise TypeError("target result package authorization must be typed or null")

    frozen_assignments = tuple(assignments)
    if any(type(item) is not AssignedArmITTRecord for item in frozen_assignments):
        raise TypeError("target result package assignments must be assigned-arm records")
    canonical_assignments = tuple(
        sorted(frozen_assignments, key=lambda item: item.assignment_id)
    )
    if frozen_assignments != canonical_assignments:
        raise ValueError("target result package assignments must use canonical order")

    budget_verification = verify_rq1_budget_qualification(budget)
    preflight_verification = verify_formal_budget_preflight(
        budget,
        dispatch,
        canonical_assignments,
        preflight,
    )
    freeze_verification = verify_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=canonical_assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )
    expected_plan = budget.power_and_margin_memo.target_itt_plan()
    confirmation_task_units = {
        item.task_unit_id
        for binding in manifest.bindings
        if binding.role is DataRole.CONFIRMATION
        for item in binding.task_units
    }
    assigned_task_units = {item.task_unit_id for item in canonical_assignments}
    if (
        evidence.ledger.dispatch != dispatch
        or evidence.ledger.assignments != canonical_assignments
        or evidence.plan != expected_plan
        or not assigned_task_units
        or not assigned_task_units <= confirmation_task_units
    ):
        raise ValueError("target result evidence is outside the frozen confirmation boundary")
    evidence_verification = verify_target_shared_evidence(evidence, yields)
    authorization_verification = None
    if authorization is not None:
        authorization_verification = verify_formal_report_authorization(
            manifest=manifest,
            budget=budget,
            discovery=discovery,
            ledger=ledger,
            union=union,
            dispatch=dispatch,
            randomization_plan=randomization_plan,
            task_bundles=task_bundles,
            assignments=canonical_assignments,
            preflight=preflight,
            confirmation=confirmation,
            index=index,
            evidence=evidence,
            yields=yields,
            authorization=authorization,
        )
    table_verification = verify_target_rq_tables(
        evidence,
        yields,
        report,
        authorization,
    )
    return {
        "status": "TARGET_RESULT_COMPONENTS_VERIFIED",
        "protocol_id": manifest.protocol_id,
        "evidence_level": evidence.evidence_level.value,
        "scientific_claim_allowed": authorization is not None,
        "data_role_manifest_id": manifest.data_role_manifest_id,
        "rq1_budget_qualification_id": budget.rq1_budget_qualification_id,
        "study_freeze_index_id": index.study_freeze_index_id,
        "shared_evidence_record_id": evidence.shared_evidence_record_id,
        "target_selector_yield_result_id": yields.target_selector_yield_result_id,
        "target_rq_tables_id": table_verification["target_rq_tables_id"],
        "assignment_count": len(canonical_assignments),
        "task_unit_count": len(assigned_task_units),
        "budget_verification_status": budget_verification["status"],
        "preflight_verification_status": preflight_verification["status"],
        "freeze_verification_status": freeze_verification["status"],
        "evidence_verification_status": evidence_verification["status"],
        "authorization_verification_status": (
            None
            if authorization_verification is None
            else authorization_verification["status"]
        ),
        "table_verification_status": table_verification["status"],
    }


def target_result_package_index(
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
    evidence: SharedEvidenceRecord,
    yields: TargetSelectorYieldResult,
    report: Mapping[str, object],
    verification: Mapping[str, object],
    authorization: FormalReportAuthorization | None = None,
) -> dict[str, object]:
    """Build the content-addressed index used by the writer and read-only verifier."""

    frozen_assignments = tuple(assignments)
    table_id = report.get("target_rq_tables_id")
    if not isinstance(table_id, str) or not table_id:
        raise ValueError("target result package requires a verified RQ table ID")
    refs: dict[str, object] = {
        "data_role_manifest": _target_ref(
            manifest.data_role_manifest_id,
            manifest,
        ),
        "rq1_budget_qualification": _target_ref(
            budget.rq1_budget_qualification_id,
            budget,
        ),
        "discovery_design_freeze": _target_ref(
            discovery.discovery_design_freeze_id,
            discovery,
        ),
        "fixed_slot_ledger": _target_ref(ledger.fixed_slot_ledger_id, ledger),
        "shared_confirmation_union": _target_ref(
            union.shared_confirmation_union_id,
            union,
        ),
        "confirmation_dispatch_manifest": _target_ref(
            dispatch.confirmation_dispatch_manifest_id,
            dispatch,
        ),
        "target_randomization_plan": _target_ref(
            randomization_plan.target_randomization_plan_id,
            randomization_plan,
        ),
        "confirmation_task_bundles": _target_ref(
            content_id("target_task_bundles_", tuple(task_bundles)),
            tuple(task_bundles),
        ),
        "assignments": _target_ref(
            confirmation.model_bound_assignments.artifact_id,
            frozen_assignments,
        ),
        "formal_budget_preflight": _target_ref(
            preflight.formal_budget_preflight_id,
            preflight,
        ),
        "confirmation_design_freeze": _target_ref(
            confirmation.confirmation_freeze_id,
            confirmation,
        ),
        "study_freeze_index": _target_ref(index.study_freeze_index_id, index),
        "shared_evidence_record": _target_ref(
            evidence.shared_evidence_record_id,
            evidence,
        ),
        "evidence_ledger": _target_ref(
            evidence.ledger.evidence_ledger_id,
            evidence.ledger,
        ),
        "target_selector_yields": _target_ref(
            yields.target_selector_yield_result_id,
            yields,
        ),
        "formal_report_authorization": (
            None
            if authorization is None
            else _target_ref(
                authorization.formal_report_authorization_id,
                authorization,
            )
        ),
        "rq_tables": _target_ref(table_id, report),
        "verification": _target_ref(
            content_id("target_result_verification_", verification),
            verification,
        ),
    }
    payload: dict[str, object] = {
        "schema_version": "3.0",
        "package_kind": "PHASE_TARGET_RESULT",
        "protocol_id": manifest.protocol_id,
        "evidence_level": evidence.evidence_level.value,
        "package_status": report.get("report_status"),
        "scientific_claim_allowed": authorization is not None,
        "artifacts": refs,
    }
    payload["target_result_package_id"] = content_id(
        "target_result_package_",
        payload,
    )
    return payload


def load_and_verify_target_result_bundle(root: Path) -> dict[str, object]:
    """Read an exact schema-3.0 package and independently replay all target results."""

    root = Path(root).resolve()
    stored_manifest = verify_bundle(root)
    if set(stored_manifest.get("files", {})) != TARGET_RESULT_PACKAGE_FILES:
        raise ValueError("target result package file set is not exact")

    manifest = _decode_target_file(
        root / "data_role_manifest.json",
        DataRoleManifest,
    )
    budget = _decode_target_file(
        root / "rq1_budget_qualification.json",
        RQ1BudgetQualification,
    )
    discovery = _decode_target_file(
        root / "discovery_design_freeze.json",
        DiscoveryDesignFreeze,
    )
    ledger = _decode_target_file(root / "fixed_slot_ledger.json", FixedSlotLedger)
    union = _decode_target_file(
        root / "shared_confirmation_union.json",
        SharedConfirmationUnion,
    )
    dispatch = _decode_target_file(
        root / "confirmation_dispatch_manifest.json",
        ConfirmationDispatchManifest,
    )
    randomization_plan = _decode_target_file(
        root / "target_randomization_plan.json",
        TargetRandomizationPlan,
    )
    task_bundles = _decode_target_value(
        read_json_exact(root / "confirmation_task_bundles.json"),
        tuple[TargetTaskBundle, ...],
        "confirmation_task_bundles.json",
    )
    assignments = _decode_target_value(
        read_json_exact(root / "assignments.json"),
        tuple[AssignedArmITTRecord, ...],
        "assignments.json",
    )
    preflight = _decode_target_file(
        root / "formal_budget_preflight.json",
        FormalBudgetPreflight,
    )
    confirmation = _decode_target_file(
        root / "confirmation_freeze.json",
        ConfirmationFreeze,
    )
    index = _decode_target_file(root / "study_freeze_index.json", StudyFreezeIndex)
    evidence = _decode_target_file(
        root / "shared_evidence_record.json",
        SharedEvidenceRecord,
    )
    yields = _decode_target_file(
        root / "target_selector_yield_result.json",
        TargetSelectorYieldResult,
    )
    raw_authorization = read_json_exact(root / "formal_report_authorization.json")
    authorization = (
        None
        if raw_authorization is None
        else _decode_target_value(
            raw_authorization,
            FormalReportAuthorization,
            "formal_report_authorization.json",
        )
    )
    report = read_json_exact(root / "rq_tables.json")
    stored_verification = read_json_exact(root / "verification.json")
    stored_index = read_json_exact(root / "package_index.json")
    for value, label in (
        (report, "rq_tables.json"),
        (stored_verification, "verification.json"),
        (stored_index, "package_index.json"),
    ):
        if not isinstance(value, dict):
            raise ValueError(f"{label} must contain a JSON object")

    verification = verify_target_result_components(
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
        report=report,
        authorization=authorization,
    )
    if stored_verification != verification:
        raise ValueError("target result verification receipt failed independent replay")
    expected_index = target_result_package_index(
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
        report=report,
        verification=verification,
        authorization=authorization,
    )
    if stored_index != expected_index:
        raise ValueError("target result package index failed independent replay")
    return {
        "status": "TARGET_RESULT_BUNDLE_VERIFIED",
        "target_result_package_id": expected_index["target_result_package_id"],
        "bundle_sha256": bundle_digest(root),
        "protocol_id": expected_index["protocol_id"],
        "evidence_level": expected_index["evidence_level"],
        "package_status": expected_index["package_status"],
        "scientific_claim_allowed": expected_index["scientific_claim_allowed"],
        "assignment_count": verification["assignment_count"],
        "task_unit_count": verification["task_unit_count"],
    }


def _target_ref(artifact_id: str, value: object) -> dict[str, str]:
    return {"artifact_id": artifact_id, "sha256": content_hash(value)}


def _decode_target_file(path: Path, expected_type: type[Any]) -> Any:
    return _decode_target_value(read_json_exact(path), expected_type, path.name)


def _decode_target_value(value: Any, annotation: Any, path: str) -> Any:
    """Strictly reconstruct one known typed record without artifact-selected classes."""

    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is tuple:
        if not isinstance(value, list):
            raise ValueError(f"{path} must be a JSON array")
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(
                _decode_target_value(item, arguments[0], f"{path}[{index}]")
                for index, item in enumerate(value)
            )
        if len(value) != len(arguments):
            raise ValueError(f"{path} has the wrong fixed tuple length")
        return tuple(
            _decode_target_value(item, item_type, f"{path}[{index}]")
            for index, (item, item_type) in enumerate(zip(value, arguments, strict=True))
        )
    if origin in {UnionType, Union}:
        failures = []
        for option in arguments:
            try:
                return _decode_target_value(value, option, path)
            except (TypeError, ValueError) as error:
                failures.append(str(error))
        raise ValueError(f"{path} does not match its frozen union type: {failures}")
    if annotation is type(None):
        if value is not None:
            raise ValueError(f"{path} must be null")
        return None
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except (TypeError, ValueError):
            raise ValueError(f"{path} has an invalid {annotation.__name__} value") from None
    if isinstance(annotation, type) and is_dataclass(annotation):
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be a JSON object")
        expected_fields = fields(annotation)
        expected_names = {item.name for item in expected_fields}
        if set(value) != expected_names:
            raise ValueError(f"{path} fields are not exact for {annotation.__name__}")
        hints = get_type_hints(annotation)
        return annotation(
            **{
                item.name: _decode_target_value(
                    value[item.name],
                    hints[item.name],
                    f"{path}.{item.name}",
                )
                for item in expected_fields
            }
        )
    if annotation in {str, int, float, bool}:
        if type(value) is not annotation:
            raise ValueError(f"{path} must be an exact {annotation.__name__}")
        return value
    raise TypeError(f"{path} uses unsupported frozen type {annotation!r}")


def _v3_work(track, assignments, outcomes, failed, plan):
    assignment_ids = {item.assignment_id for item in assignments}
    reasons = set()
    if assignment_ids & failed or not assignment_ids <= set(outcomes):
        reasons.add("missing_or_failed_assigned_outcome")
        return {
            "track": track,
            "point": None,
            "standard_error": None,
            "latent_lower": None,
            "latent_upper": None,
            "contributions": (),
            "weights": (),
            "assignments": len(assignments),
            "reasons": tuple(sorted(reasons)),
            "arm_summaries": (),
        }
    local = {assignment_id: outcomes[assignment_id] for assignment_id in assignment_ids}
    arms = ATOMIC_CONFIRMATORY_ARMS if track is PolicyTrack.ATOMIC else PAIR_CONFIRMATORY_ARMS
    for arm in arms:
        values = [local[item.assignment_id] for item in assignments if item.arm is arm]
        valid = sum(item.code_valid for item in values)
        unknown = sum(item.code_valid - item.oracle_evaluable for item in values)
        if valid and unknown / valid > plan.maximum_unknown_fraction_among_valid:
            reasons.add("maximum_unknown_fraction_exceeded")
    lower = _v3_unit_values(assignments, local, lambda item: float(item.secure_yield))
    upper = _v3_unit_values(assignments, local, lambda item: float(item.latent_secure_upper))
    strata = defaultdict(set)
    for item in assignments:
        strata[item.task_unit_id].add(item.stratum_id)
    if any(len(values) != 1 for values in strata.values()):
        raise ValueError("independent verifier found cross-stratum task units")
    contributions = tuple(
        (
            task_unit_id,
            next(iter(strata[task_unit_id])),
            _v3_contrast(track, values, values),
            _v3_contrast(track, lower[task_unit_id], upper[task_unit_id]),
            _v3_upper_contrast(track, lower[task_unit_id], upper[task_unit_id]),
        )
        for task_unit_id, values in sorted(lower.items())
    )
    counts = Counter(item[1] for item in contributions)
    if any(count < plan.minimum_task_units_per_stratum for count in counts.values()):
        reasons.add("insufficient_task_units_per_stratum")
    point, error, weights = _v3_point_error(contributions)
    if error == 0:
        reasons.add("zero_standard_error")
    return {
        "track": track,
        "point": point,
        "standard_error": error,
        "latent_lower": sum(item[3] for item in contributions) / len(contributions),
        "latent_upper": sum(item[4] for item in contributions) / len(contributions),
        "contributions": contributions,
        "weights": weights,
        "assignments": len(assignments),
        "reasons": tuple(sorted(reasons)),
        "arm_summaries": _v3_arm_summaries(assignments, local, arms),
    }


def _v3_family(track, work, plan):
    if not work:
        return {
            "family_status": TargetFamilyStatus.NO_ELIGIBLE_COORDINATES,
            "critical": None,
            "valid": 0,
            "invalid": 0,
            "statuses": {},
            "intervals": {},
            "reasons": {},
        }
    reasons = {reason for value in work.values() for reason in value["reasons"]}
    if "missing_or_failed_assigned_outcome" in reasons:
        return _v3_failed_family(
            TargetFamilyStatus.INVALID_PROVENANCE,
            work,
            "primary_family_invalid_provenance",
        )
    if reasons & {"insufficient_task_units_per_stratum", "maximum_unknown_fraction_exceeded"}:
        return _v3_failed_family(
            TargetFamilyStatus.INSUFFICIENT_SUPPORT,
            work,
            "primary_family_insufficient_support",
        )
    if "zero_standard_error" in reasons:
        return _v3_failed_family(
            TargetFamilyStatus.ZERO_STANDARD_ERROR,
            work,
            "primary_family_zero_standard_error",
        )
    maxima, invalid = _v3_bootstrap(track, work, plan)
    minimum = math.ceil(plan.bootstrap_draws * plan.minimum_valid_bootstrap_fraction)
    if len(maxima) < minimum:
        result = _v3_failed_family(
            TargetFamilyStatus.INSUFFICIENT_VALID_BOOTSTRAP,
            work,
            "primary_family_insufficient_valid_bootstrap",
        )
        result["valid"] = len(maxima)
        result["invalid"] = invalid
        return result
    critical = _q(maxima, 1 - plan.alpha)
    margin = plan.atomic_practical_margin if track is PolicyTrack.ATOMIC else plan.pair_practical_margin
    intervals = {
        candidate_id: (
            value["point"] - critical * value["standard_error"],
            value["point"] + critical * value["standard_error"],
        )
        for candidate_id, value in work.items()
    }
    statuses = {
        candidate_id: _v3_classify(*interval, margin)
        for candidate_id, interval in intervals.items()
    }
    return {
        "family_status": TargetFamilyStatus.EVALUABLE,
        "critical": critical,
        "valid": len(maxima),
        "invalid": invalid,
        "statuses": statuses,
        "intervals": intervals,
        "reasons": {candidate_id: () for candidate_id in work},
    }


def _v3_failed_family(status, work, family_reason):
    return {
        "family_status": status,
        "critical": None,
        "valid": 0,
        "invalid": 0,
        "statuses": {
            candidate_id: ConfirmatoryEffectStatus.NON_EVALUABLE
            for candidate_id in work
        },
        "intervals": {candidate_id: (None, None) for candidate_id in work},
        "reasons": {
            candidate_id: tuple(sorted(set(value["reasons"]) | {family_reason}))
            for candidate_id, value in work.items()
        },
    }


def _v3_unit_values(assignments, outcomes, getter):
    grouped = defaultdict(list)
    task_weights = defaultdict(set)
    realization_weights = defaultdict(set)
    arms_by_unit = defaultdict(set)
    for item in assignments:
        grouped[(item.task_unit_id, item.task_instance_id, item.realization_id, item.arm)].append(
            getter(outcomes[item.assignment_id])
        )
        task_weights[(item.task_unit_id, item.task_instance_id)].add(float(item.task_instance_weight))
        realization_weights[(item.task_unit_id, item.realization_id)].add(float(item.realization_weight))
        arms_by_unit[item.task_unit_id].add(item.arm)
    if any(len(values) != 1 for values in task_weights.values()) or any(
        len(values) != 1 for values in realization_weights.values()
    ):
        raise ValueError("independent verifier found descendant weight drift")
    result = {}
    for unit_id in sorted(arms_by_unit):
        instances = sorted(value for unit, value in task_weights if unit == unit_id)
        realizations = sorted(value for unit, value in realization_weights if unit == unit_id)
        task_total = sum(next(iter(task_weights[(unit_id, value)])) for value in instances)
        realization_total = sum(
            next(iter(realization_weights[(unit_id, value)])) for value in realizations
        )
        result[unit_id] = {}
        for arm in arms_by_unit[unit_id]:
            total = 0.0
            for instance in instances:
                for realization in realizations:
                    values = grouped.get((unit_id, instance, realization, arm))
                    if not values:
                        raise ValueError("independent verifier found incomplete assigned-arm support")
                    total += (
                        next(iter(task_weights[(unit_id, instance)]))
                        / task_total
                        * next(iter(realization_weights[(unit_id, realization)]))
                        / realization_total
                        * sum(values)
                        / len(values)
                    )
            result[unit_id][arm] = total
    return result


def _v3_contrast(track, lower, upper):
    if track is PolicyTrack.ATOMIC:
        return lower[ConfirmatoryArm.ATOMIC_TARGET] - upper[ConfirmatoryArm.ATOMIC_NOOP]
    return (
        lower[ConfirmatoryArm.PAIR_11]
        - upper[ConfirmatoryArm.PAIR_10]
        - upper[ConfirmatoryArm.PAIR_01]
        + lower[ConfirmatoryArm.PAIR_00]
    )


def _v3_upper_contrast(track, lower, upper):
    if track is PolicyTrack.ATOMIC:
        return upper[ConfirmatoryArm.ATOMIC_TARGET] - lower[ConfirmatoryArm.ATOMIC_NOOP]
    return (
        upper[ConfirmatoryArm.PAIR_11]
        - lower[ConfirmatoryArm.PAIR_10]
        - lower[ConfirmatoryArm.PAIR_01]
        + upper[ConfirmatoryArm.PAIR_00]
    )


def _v3_point_error(contributions):
    by_stratum = defaultdict(list)
    for _, stratum, point, _, _ in contributions:
        by_stratum[stratum].append(point)
    total = len(contributions)
    weights = tuple(
        (stratum, len(values) / total)
        for stratum, values in sorted(by_stratum.items())
    )
    means = {stratum: sum(values) / len(values) for stratum, values in by_stratum.items()}
    point = sum(weight * means[stratum] for stratum, weight in weights)
    variance = 0.0
    for stratum, weight in weights:
        values = by_stratum[stratum]
        if len(values) < 2:
            return point, 0.0, weights
        variance += weight**2 * sum((item - means[stratum]) ** 2 for item in values) / (
            len(values) * (len(values) - 1)
        )
    return point, math.sqrt(max(variance, 0.0)), weights


def _v3_arm_summaries(assignments, outcomes, arms):
    metric_getters = (
        lambda item: float(item.secure_yield),
        lambda item: float(item.code_valid),
        lambda item: float(item.oracle_evaluable),
        lambda item: float(item.functionality == 1),
        lambda item: float(item.joint == 1),
    )
    values = tuple(_v3_unit_values(assignments, outcomes, getter) for getter in metric_getters)
    summaries = []
    for arm in arms:
        assigned = [item for item in assignments if item.arm is arm]
        arm_outcomes = [outcomes[item.assignment_id] for item in assigned]
        summaries.append(
            (
                arm,
                len(assigned),
                *(statistics.mean(unit[arm] for unit in metric.values()) for metric in values),
                sum(item.code_valid - item.oracle_evaluable for item in arm_outcomes),
                sum(item.code_valid == 0 for item in arm_outcomes),
            )
        )
    return tuple(summaries)


def _v3_bootstrap(track, work, plan):
    global_units = defaultdict(set)
    for value in work.values():
        for task_unit_id, stratum, *_ in value["contributions"]:
            global_units[stratum].add(task_unit_id)
    rng = random.Random(
        int(
            content_hash(
                {
                    "domain": "target_max_t_task_unit_bootstrap_v1",
                    "seed": plan.bootstrap_seed,
                    "track": track,
                    "plan_id": plan.target_itt_plan_id,
                }
            )[-16:],
            16,
        )
    )
    maxima = []
    invalid = 0
    for _ in range(plan.bootstrap_draws):
        sampled = {}
        for stratum, values in sorted(global_units.items()):
            population = tuple(sorted(values))
            sampled[stratum] = tuple(
                population[rng.randrange(len(population))] for _ in population
            )
        draw_statistics = []
        for value in work.values():
            contribution_by_unit = {item[0]: item[2] for item in value["contributions"]}
            means = {}
            variances = {}
            draw_valid = True
            for stratum, weight in value["weights"]:
                points = [
                    contribution_by_unit[task_unit_id]
                    for task_unit_id in sampled[stratum]
                    if task_unit_id in contribution_by_unit
                ]
                if len(points) < 2:
                    draw_valid = False
                    break
                mean = sum(points) / len(points)
                means[stratum] = mean
                variances[stratum] = sum((item - mean) ** 2 for item in points) / (
                    len(points) * (len(points) - 1)
                )
            if not draw_valid:
                draw_statistics = []
                break
            point = sum(dict(value["weights"])[stratum] * mean for stratum, mean in means.items())
            error = math.sqrt(
                sum(dict(value["weights"])[stratum] ** 2 * variance for stratum, variance in variances.items())
            )
            if error <= 0:
                draw_statistics = []
                break
            draw_statistics.append(abs((point - value["point"]) / error))
        if draw_statistics:
            maxima.append(max(draw_statistics))
        else:
            invalid += 1
    return maxima, invalid


def _v3_classify(lower, upper, margin):
    if lower > margin:
        return ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL
    if upper < -margin:
        return ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL
    if -margin <= lower and upper <= margin:
        return ConfirmatoryEffectStatus.PRACTICALLY_NULL
    return ConfirmatoryEffectStatus.INCONCLUSIVE


def _v3_check_contributions(reported, expected):
    if len(reported) != len(expected):
        raise ValueError("target task-unit contribution count drift")
    for actual, values in zip(reported, expected, strict=True):
        if (actual.task_unit_id, actual.stratum_id) != values[:2]:
            raise ValueError("target task-unit contribution identity drift")
        for actual_value, expected_value in zip(
            (actual.point, actual.latent_lower, actual.latent_upper),
            values[2:],
            strict=True,
        ):
            _v3_same(actual_value, expected_value, "task-unit contribution")


def _v3_check_arm_summaries(reported, expected):
    if len(reported) != len(expected):
        raise ValueError("target arm summary count drift")
    for actual, values in zip(reported, expected, strict=True):
        observed = (
            actual.arm,
            actual.assignments,
            actual.secure_yield,
            actual.code_validity,
            actual.oracle_evaluability,
            actual.functionality_yield,
            actual.joint_success_yield,
            actual.oracle_unknown_valid_assignments,
            actual.terminal_assignments,
        )
        if observed[:2] != values[:2] or observed[-2:] != values[-2:]:
            raise ValueError("target arm summary accounting drift")
        for actual_value, expected_value in zip(observed[2:-2], values[2:-2], strict=True):
            _v3_same(actual_value, expected_value, "arm endpoint summary")


def _v3_verify_yields(evidence, yields, statuses):
    dispatch = {item.candidate_record_id: item for item in evidence.ledger.dispatch.records}
    reported = {item.slot_id: item for item in yields.slots}
    ledger_slots = evidence.ledger.dispatch.union.ledger.slots
    if set(reported) != {item.slot_id for item in ledger_slots}:
        raise ValueError("target yield slots do not match the fixed ledger")
    expected_counts = defaultdict(int)
    expected_k = defaultdict(int)
    for slot in ledger_slots:
        item = reported[slot.slot_id]
        status = None if slot.candidate_record_id is None else statuses.get(slot.candidate_record_id)
        meaningful = int(
            status
            in {
                ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL,
                ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL,
            }
        )
        if (
            item.slot_status is not slot.status
            or item.candidate_record_id != slot.candidate_record_id
            or item.effect_status is not status
            or item.meaningful_yield != meaningful
        ):
            raise ValueError("target slot yield does not independently recompute")
        key = (slot.track, slot.selector_id, slot.model_id)
        expected_counts[key] += meaningful
        expected_k[key] += 1
        if slot.candidate_record_id is not None and dispatch[slot.candidate_record_id].status is not BridgeStatus.SUCCESS and status is not None:
            raise ValueError("a failed dispatch cannot acquire an effect status")
    selector_map = {
        (item.track, item.selector_id, item.model_id): item for item in yields.selectors
    }
    if set(selector_map) != set(expected_k):
        raise ValueError("target selector yield membership drift")
    for key, top_k in expected_k.items():
        item = selector_map[key]
        if (
            item.top_k != top_k
            or item.meaningful_slots != expected_counts[key]
            or item.meaningful_yield_at_k != expected_counts[key] / top_k
        ):
            raise ValueError("target selector fixed-denominator Yield@K drift")


def _v3_same(actual, expected, name):
    if actual is None or expected is None:
        if actual is not expected:
            raise ValueError(f"target {name} nullability drift")
        return
    if not math.isclose(float(actual), float(expected), rel_tol=1e-12, abs_tol=1e-12):
        raise ValueError(f"target {name} does not independently recompute")


def _statuses(coordinates, occurrences, plan, rng):
    maps = {
        item.final_hypothesis_id: {unit: float(value) for unit, value in item.task_unit_effects}
        for item in coordinates
    }
    summary = {}
    testable = []
    for item in coordinates:
        values = [maps[item.final_hypothesis_id][unit] for _, unit in occurrences if unit in maps[item.final_hypothesis_id]]
        point, error = _stats(values)
        summary[item.final_hypothesis_id] = (point, error, len(values))
        if item.provenance_complete and len(values) >= item.minimum_task_units and error > 0.0:
            testable.append(item)
    maxima = []
    invalid = 0
    for _ in range(plan.inner_draws):
        sampled = [occurrences[rng.randrange(len(occurrences))] for _ in occurrences]
        statistics_for_draw = []
        for item in testable:
            values = [maps[item.final_hypothesis_id][unit] for _, unit in sampled if unit in maps[item.final_hypothesis_id]]
            if len(values) < item.minimum_task_units:
                statistics_for_draw = []
                break
            point, error = _stats(values)
            if error <= 0.0:
                statistics_for_draw = []
                break
            statistics_for_draw.append(abs(point - summary[item.final_hypothesis_id][0]) / error)
        if statistics_for_draw and len(statistics_for_draw) == len(testable):
            maxima.append(max(statistics_for_draw))
        else:
            invalid += 1
    critical = _q(maxima, 1.0 - plan.alpha) if len(maxima) >= math.ceil(plan.inner_draws * plan.minimum_valid_fraction) else None
    statuses = []
    for item in coordinates:
        point, error, count = summary[item.final_hypothesis_id]
        eligible = item in testable and critical is not None
        lower = max(-1.0, point - critical * error) if eligible else None
        upper = min(1.0, point + critical * error) if eligible else None
        oriented = None if lower is None or upper is None else (lower if item.expected_direction == 1 else -upper)
        statuses.append(
            ConfirmationStatus(
                item.final_hypothesis_id,
                item.model_id,
                point,
                error,
                lower,
                upper,
                oriented,
                count,
                item.provenance_complete,
                bool(oriented is not None and oriented > 0.0 and count >= item.minimum_task_units and item.provenance_complete),
            )
        )
    return tuple(statuses), critical, len(maxima), invalid


def _points(selection, bridge, statuses):
    bridge_by_candidate = {record.candidate_id: record for record in bridge.records}
    status_by_hypothesis = {status.final_hypothesis_id: status for status in statuses}
    points = []
    for run in selection.runs:
        for ranking in run.rankings:
            contributions = []
            for slot in ranking.slots:
                hypothesis_id = None
                contribution = 0
                reason = slot.reason_code or "not_confirmed"
                if slot.status is SlotStatus.FILLED:
                    record = bridge_by_candidate[slot.candidate_id]
                    if record.status is BridgeStatus.SUCCESS:
                        hypothesis_id = record.final_hypothesis_id
                        contribution = int(status_by_hypothesis[hypothesis_id].confirmed)
                        reason = "confirmed" if contribution else "randomized_effect_not_confirmed"
                    else:
                        reason = record.reason_code or record.status.value
                contributions.append(SlotContribution(run.selector_id, ranking.ranking_id, slot.rank, slot.status, slot.candidate_id, hypothesis_id, contribution, reason))
            count = sum(item.confirmed_contribution for item in contributions)
            points.append(SelectorYieldPoint(run.selector_id, ranking.ranking_id, run.model_id, selection.universe.top_k, count, count / selection.universe.top_k, tuple(contributions)))
    methods = []
    for run in selection.runs:
        values = [point.confirmed_yield for point in points if point.selector_id == run.selector_id]
        methods.append(SelectorMethodPoint(run.selector_id, run.model_id, len(values), sum(values) / len(values)))
    return tuple(points), tuple(methods)


def _pairs(methods, pairs):
    values = {item.selector_id: item.confirmed_yield for item in methods}
    return tuple(
        SelectorPairPoint(content_id("selector_pair_", {"left": left, "right": right}), left, right, values[left] - values[right])
        for left, right in pairs
    )


def _intervals(points, draws, plan):
    if not points:
        return (), None, "no_preregistered_selector_pairs"
    if len(draws) < math.ceil(plan.outer_draws * plan.minimum_valid_fraction):
        return (), None, "insufficient_valid_outer_draws"
    errors = {point.pair_id: statistics.stdev(draw[point.pair_id] for draw in draws) for point in points}
    evaluable = tuple(point for point in points if errors[point.pair_id] > 0.0)
    if not evaluable:
        return (), None, "zero_selector_pair_variance"
    maxima = [max(abs(draw[point.pair_id] - point.difference) / errors[point.pair_id] for point in evaluable) for draw in draws]
    critical = _q(maxima, 1.0 - plan.alpha)
    intervals = tuple(SelectorPairInterval(point.pair_id, errors[point.pair_id], max(-1.0, point.difference - critical * errors[point.pair_id]), min(1.0, point.difference + critical * errors[point.pair_id])) for point in evaluable)
    return intervals, critical, "complete" if len(evaluable) == len(points) else "partial_zero_variance"


def _stats(values):
    if not values:
        raise ValueError("independent verifier retained no task unit")
    point = sum(values) / len(values)
    error = 0.0 if len(values) < 2 else math.sqrt(sum((value - point) ** 2 for value in values) / (len(values) * (len(values) - 1)))
    return point, error


def _seed(seed, domain):
    return int(content_hash({"seed": seed, "domain": domain})[-16:], 16)


def _q(values, probability):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


__all__ = [
    "TARGET_RESULT_PACKAGE_FILES",
    "load_and_verify_target_result_bundle",
    "target_result_package_index",
    "verify_formal_report_authorization",
    "verify_formal_budget_preflight",
    "verify_rq1_budget_qualification",
    "verify_selector_result",
    "verify_target_result_components",
    "verify_target_power_simulation",
    "verify_target_randomization",
    "verify_target_rq_tables",
    "verify_target_shared_evidence",
    "verify_target_study_freezes",
]

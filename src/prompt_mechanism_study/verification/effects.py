"""Independent Atomic/Pair effect, status, and Yield@K reconstruction."""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict

from prompt_mechanism_study.inference import (
    ConfirmatoryEffectStatus,
    ContextAnalysisStatus,
    PairResponsePatternPlanStatus,
    ResponsePatternStatus,
    SharedEvidenceRecord,
    TargetFamilyStatus,
    TargetSelectorYieldResult,
)
from prompt_mechanism_study.prioritization import BridgeStatus, PolicyTrack
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    PAIR_CONFIRMATORY_ARMS,
    ConfirmatoryArm,
)
from prompt_mechanism_study.records import content_hash

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
    if plan.context_analysis.status is not ContextAnalysisStatus.BLOCKED_NO_FROZEN_CONTEXT_RULE:
        raise ValueError("context analysis lacks an independently implemented frozen rule")
    if plan.pair_response_patterns.status is not PairResponsePatternPlanStatus.BLOCKED_NO_FROZEN_PREDICATE:
        raise ValueError("Pair response predicates lack an independent implementation")
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
            _v3_same(
                item.simultaneous_lower,
                expected["intervals"][candidate_id][0],
                "interval lower",
            )
            _v3_same(
                item.simultaneous_upper,
                expected["intervals"][candidate_id][1],
                "interval upper",
            )
            if item.reasons != expected["reasons"][candidate_id]:
                raise ValueError("target non-evaluable reasons do not independently recompute")
            if item.assignments != value["assignments"] or item.task_units != len(
                value["contributions"]
            ):
                raise ValueError("target assignment or task-unit accounting drift")
            _v3_check_contributions(item.task_unit_contributions, value["contributions"])
            _v3_check_arm_summaries(item.arm_summaries, value["arm_summaries"])
            _v3_check_response_pattern(
                item.response_pattern,
                family.track,
                value["arm_summaries"],
            )
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
    margin = (
        plan.atomic_practical_margin
        if track is PolicyTrack.ATOMIC
        else plan.pair_practical_margin
    )
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
        task_weights[(item.task_unit_id, item.task_instance_id)].add(
            float(item.task_instance_weight)
        )
        realization_weights[(item.task_unit_id, item.realization_id)].add(
            float(item.realization_weight)
        )
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
                        raise ValueError(
                            "independent verifier found incomplete assigned-arm support"
                        )
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
                sum(
                    dict(value["weights"])[stratum] ** 2 * variance
                    for stratum, variance in variances.items()
                )
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


def _v3_check_response_pattern(reported, track, arm_summaries):
    if track is PolicyTrack.ATOMIC:
        if (
            reported.status is not ResponsePatternStatus.NOT_APPLICABLE
            or reported.surface is not None
            or reported.label is not None
            or reported.predicate_sha256 is not None
            or reported.reasons
        ):
            raise ValueError("Atomic response-pattern status failed independent replay")
        return
    if tuple(item[0] for item in arm_summaries) != PAIR_CONFIRMATORY_ARMS:
        if (
            reported.status is not ResponsePatternStatus.NON_EVALUABLE
            or reported.surface is not None
            or reported.label is not None
            or reported.predicate_sha256 is not None
            or reported.reasons != ("pair_response_surface_unavailable",)
        ):
            raise ValueError("unavailable Pair response surface failed independent replay")
        return
    means = {item[0]: float(item[2]) for item in arm_summaries}
    mean_00 = means[ConfirmatoryArm.PAIR_00]
    mean_10 = means[ConfirmatoryArm.PAIR_10]
    mean_01 = means[ConfirmatoryArm.PAIR_01]
    mean_11 = means[ConfirmatoryArm.PAIR_11]
    expected = (
        mean_00,
        mean_10,
        mean_01,
        mean_11,
        mean_10 - mean_00,
        mean_01 - mean_00,
        mean_11 - mean_00,
        mean_11 - mean_01,
        mean_11 - mean_10,
        mean_11 - mean_10 - mean_01 + mean_00,
    )
    if (
        reported.status is not ResponsePatternStatus.BLOCKED_NO_FROZEN_PREDICATE
        or reported.surface is None
        or reported.label is not None
        or reported.predicate_sha256 is not None
        or reported.reasons
    ):
        raise ValueError("blocked Pair response-pattern status failed independent replay")
    observed = (
        reported.surface.mean_00,
        reported.surface.mean_10,
        reported.surface.mean_01,
        reported.surface.mean_11,
        reported.surface.factor_1_at_0,
        reported.surface.factor_2_at_0,
        reported.surface.joint,
        reported.surface.factor_1_at_1,
        reported.surface.factor_2_at_1,
        reported.surface.interaction,
    )
    for actual, wanted in zip(observed, expected, strict=True):
        _v3_same(actual, wanted, "Pair response surface")


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
        status = (
            None
            if slot.candidate_record_id is None
            else statuses.get(slot.candidate_record_id)
        )
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
        if (
            slot.candidate_record_id is not None
            and dispatch[slot.candidate_record_id].status is not BridgeStatus.SUCCESS
            and status is not None
        ):
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


def _q(values, probability):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]

__all__ = ["verify_target_shared_evidence"]

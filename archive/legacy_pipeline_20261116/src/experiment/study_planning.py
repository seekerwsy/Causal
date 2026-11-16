"""Outcome-blind numerical power planning with the actual task-unit estimator."""


from __future__ import annotations
import hashlib
import math
import random
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Any
from prompt_mechanism_study.experiment.inference import TargetITTPlan
from prompt_mechanism_study.artifact_io import require_sha256
from prompt_mechanism_study.records import content_id, require_text
from prompt_mechanism_study.discovery.prioritization import BridgeStatus, PolicyTrack


ATOMIC_POWER_ARMS = (
    "atomic_target",
    "atomic_noop",
    "atomic_placebo",
    "atomic_generic",
)


@dataclass(frozen=True, slots=True)
class TargetPowerAssumption:
    """One outcome-blind planning scenario for a target ITT family."""

    scenario_id: str
    track: PolicyTrack
    arm_secure_yield_probabilities: tuple[tuple[str, float], ...]
    request_shared_draw_probability: float
    cross_arm_shared_draw_probability: float
    realization_arm_probability_offsets: tuple[tuple[float, ...], ...]
    family_shared_draw_probability: float
    oracle_unknown_rate: float
    terminal_no_code_rate: float
    target_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "power scenario_id")
        if type(self.track) is not PolicyTrack:
            raise TypeError("power assumption track must be typed")
        expected = ATOMIC_POWER_ARMS
        if tuple((name for name, _ in self.arm_secure_yield_probabilities)) != expected:
            raise ValueError("power assumption must provide the canonical four-arm probabilities")
        for _, value in self.arm_secure_yield_probabilities:
            if type(value) is not float or not 0 <= value <= 1:
                raise ValueError("secure-yield probabilities must be floats on [0, 1]")
        for value, name in (
            (self.request_shared_draw_probability, "request shared-draw probability"),
            (self.cross_arm_shared_draw_probability, "cross-arm shared-draw probability"),
            (self.family_shared_draw_probability, "family shared-draw probability"),
            (self.oracle_unknown_rate, "Oracle unknown rate"),
            (self.terminal_no_code_rate, "terminal no-code rate"),
        ):
            if type(value) is not float or not 0 <= value < 1:
                raise ValueError(f"{name} must be a float on [0, 1)")
        if not self.realization_arm_probability_offsets or any(
            (
                len(row) != 4 or any((type(x) is not float or not math.isfinite(x) for x in row))
                for row in self.realization_arm_probability_offsets
            )
        ):
            raise ValueError("power assumptions require four explicit arm offsets per realization")
        if self.oracle_unknown_rate + self.terminal_no_code_rate > 1:
            raise ValueError("unknown and no-code planning rates cannot exceed one")
        maximum_secure_yield = 1 - self.oracle_unknown_rate - self.terminal_no_code_rate
        if any((value > maximum_secure_yield for _, value in self.arm_secure_yield_probabilities)):
            raise ValueError(
                "secure-yield probability cannot exceed evaluable generated-code availability"
            )
        if self.target_confirmation_outcomes_used is not False:
            raise ValueError("power planning cannot read target confirmation outcomes")

    @property
    def effect(self) -> float:
        values = dict(self.arm_secure_yield_probabilities)
        return values["atomic_target"] - values["atomic_noop"]


@dataclass(frozen=True, slots=True)
class TargetPowerSimulationPlan:
    """Frozen assumption grid for one Atomic max-|T| family."""

    track: PolicyTrack
    practical_margin: float
    family_size_upper_bound: int
    task_units_per_effect: int
    global_realizations: int
    minimum_task_units_per_realization: int
    minimum_task_units_per_stratum: int
    total_block_slots: int
    alpha: float
    target_power: float
    simulation_replicates: int
    simulation_seed: int
    assumptions: tuple[TargetPowerAssumption, ...]
    realization_weights: tuple[float, ...]
    stratum_task_counts: tuple[tuple[str, int], ...]
    family_task_overlap: str
    analysis_plan: TargetITTPlan
    multiplicity_method: str = "per_effect_bonferroni_bootstrap"
    resampling_unit: str = "task_unit"
    independent_task_priority: bool = True
    task_support: tuple[tuple[int, str, str, int], ...] | None = field(
        default=None, metadata={"omit_if_none": True}
    )

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("power plan track must be typed")
        if type(self.practical_margin) is not float or not 0 <= self.practical_margin <= 1:
            raise ValueError("practical margin must be a float on [0, 1]")
        for value, name in (
            (self.family_size_upper_bound, "family_size_upper_bound"),
            (self.task_units_per_effect, "task_units_per_effect"),
            (self.global_realizations, "global_realizations"),
            (self.minimum_task_units_per_realization, "minimum_task_units_per_realization"),
            (self.minimum_task_units_per_stratum, "minimum_task_units_per_stratum"),
            (self.total_block_slots, "total_block_slots"),
            (self.simulation_replicates, "simulation_replicates"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.total_block_slots % 4:
            raise ValueError("power total_block_slots must contain complete four-arm blocks")
        if (
            self.task_units_per_effect
            < self.global_realizations * self.minimum_task_units_per_realization
        ):
            raise ValueError("task support cannot cover every frozen realization")
        if self.task_units_per_effect < self.minimum_task_units_per_stratum:
            raise ValueError("task support cannot cover the frozen stratum minimum")
        if type(self.alpha) is not float or not 0 < self.alpha < 1:
            raise ValueError("power alpha must be a float in (0, 1)")
        if type(self.target_power) is not float or not 0 < self.target_power < 1:
            raise ValueError("target power must be a float in (0, 1)")
        if self.simulation_replicates < 1000:
            raise ValueError("power simulation requires at least 1000 replicates")
        if type(self.simulation_seed) is not int:
            raise TypeError("power simulation seed must be an integer")
        if not self.assumptions or any(
            (type(item) is not TargetPowerAssumption for item in self.assumptions)
        ):
            raise TypeError("power plan needs typed planning assumptions")
        if tuple((item.scenario_id for item in self.assumptions)) != tuple(
            sorted({item.scenario_id for item in self.assumptions})
        ):
            raise ValueError("power assumptions must have unique canonical scenario IDs")
        if any((item.track is not self.track for item in self.assumptions)):
            raise ValueError("power assumptions cannot cross Atomic tracks")
        if self.multiplicity_method != "per_effect_bonferroni_bootstrap":
            raise ValueError("target power must use per-effect Bonferroni bootstrap inference")
        if self.resampling_unit != "task_unit":
            raise ValueError("target power must use the task unit")
        if self.independent_task_priority is not True:
            raise ValueError("independent task units must precede extra request slots")
        if (
            len(self.realization_weights) != self.global_realizations
            or any((type(q) is not float or not 0 < q <= 1 for q in self.realization_weights))
            or (not math.isclose(sum(self.realization_weights), 1.0, abs_tol=1e-12))
        ):
            raise ValueError("power plan must freeze every realization weight")
        if (
            not self.stratum_task_counts
            or self.stratum_task_counts != tuple(sorted(self.stratum_task_counts))
            or len({s for s, _ in self.stratum_task_counts}) != len(self.stratum_task_counts)
            or any((not s or type(n) is not int or n < 1 for s, n in self.stratum_task_counts))
            or (sum((n for _, n in self.stratum_task_counts)) != self.task_units_per_effect)
        ):
            raise ValueError("power stratum counts must cover exactly the planned task units")
        if self.family_task_overlap not in {"shared", "disjoint", "explicit"}:
            raise ValueError("power task overlap must be shared, disjoint or explicit")
        if (self.family_task_overlap == "explicit") != (self.task_support is not None):
            raise ValueError("explicit power requires the complete task-support table")
        if self.task_support is not None:
            if not self.task_support or self.task_support != tuple(sorted(set(self.task_support))):
                raise ValueError("power task support must be nonempty, unique and canonical")
            keys, strata_by_unit = (set(), {})
            counts, strata, realizations, cells = (Counter(), Counter(), Counter(), Counter())
            for coordinate, unit, stratum, realization in self.task_support:
                if (
                    type(coordinate) is not int
                    or not 0 <= coordinate < self.family_size_upper_bound
                    or type(realization) is not int
                    or (not 0 <= realization < self.global_realizations)
                ):
                    raise ValueError("power task support has an invalid coordinate or realization")
                require_text(unit, "power task unit")
                require_text(stratum, "power source stratum")
                if (coordinate, unit) in keys or strata_by_unit.get(unit, stratum) != stratum:
                    raise ValueError(
                        "power task units must have one stratum and one realization per effect"
                    )
                keys.add((coordinate, unit))
                strata_by_unit[unit] = stratum
                counts[coordinate] += 1
                strata[coordinate, stratum] += 1
                realizations[coordinate, realization] += 1
                cells[coordinate, stratum, realization] += 1
            for coordinate in range(self.family_size_upper_bound):
                if (
                    counts[coordinate] != self.task_units_per_effect
                    or tuple(sorted(((s, n) for (j, s), n in strata.items() if j == coordinate)))
                    != self.stratum_task_counts
                    or any(
                        (
                            realizations[coordinate, r] < self.minimum_task_units_per_realization
                            for r in range(self.global_realizations)
                        )
                    )
                    or any(
                        (
                            n < self.minimum_task_units_per_stratum
                            for (j, _, _), n in cells.items()
                            if j == coordinate
                        )
                    )
                ):
                    raise ValueError("explicit power support differs from frozen counts or minima")
        self.target_itt_plan()
        for assumption in self.assumptions:
            if len(assumption.realization_arm_probability_offsets) != self.global_realizations:
                raise ValueError("power realization offsets do not cover the frozen policy")
            for arm, (_, base) in enumerate(assumption.arm_secure_yield_probabilities):
                offsets = [row[arm] for row in assumption.realization_arm_probability_offsets]
                if not math.isclose(
                    sum((q * d for q, d in zip(self.realization_weights, offsets))),
                    0.0,
                    abs_tol=1e-12,
                ):
                    raise ValueError(
                        "realization offsets must preserve the frozen mixture probability"
                    )
                if any(
                    (
                        not 0
                        <= base + d
                        <= 1 - assumption.oracle_unknown_rate - assumption.terminal_no_code_rate
                        for d in offsets
                    )
                ):
                    raise ValueError(
                        "realization probabilities exceed generated evaluable availability"
                    )
            if self.family_task_overlap == "disjoint" and assumption.family_shared_draw_probability:
                raise ValueError("disjoint independent task units cannot share family draws")

    def target_itt_plan(self):
        if type(self.analysis_plan) is not TargetITTPlan:
            raise TypeError("power must freeze the exact typed inference plan")
        margin = self.analysis_plan.atomic_practical_margin
        minimum = self.analysis_plan.atomic_minimum_task_units_per_realization
        if (
            margin != self.practical_margin
            or self.analysis_plan.alpha != self.alpha
            or self.analysis_plan.minimum_task_units_per_stratum
            != self.minimum_task_units_per_stratum
            or (minimum != self.minimum_task_units_per_realization)
        ):
            raise ValueError("power design differs from its frozen inference plan")
        return self.analysis_plan

    @property
    def power_simulation_plan_id(self) -> str:
        return content_id("target_power_simulation_plan_", self)


@dataclass(frozen=True, slots=True)
class TargetPowerScenarioResult:
    scenario_id: str
    effect: float
    task_unit_standard_error: float | None
    simultaneous_critical_value: float | None
    achieved_power: float
    monte_carlo_half_width_95: float
    meaningful_replicates_by_coordinate: tuple[int, ...]
    family_status_counts: tuple[tuple[str, int], ...]
    simulated_outcome_sha256: str

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "power result scenario_id")
        for value, name in (
            (self.effect, "power effect"),
            (self.achieved_power, "achieved power"),
            (self.monte_carlo_half_width_95, "power Monte Carlo half-width"),
        ):
            if type(value) is not float or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite float")
        if self.task_unit_standard_error is not None and (
            not math.isfinite(self.task_unit_standard_error) or self.task_unit_standard_error < 0
        ):
            raise ValueError("power standard error must be nonnegative or absent")
        if self.simultaneous_critical_value is not None and (
            not math.isfinite(self.simultaneous_critical_value) or self.simultaneous_critical_value < 0
        ):
            raise ValueError("power critical value must be nonnegative or absent")
        require_sha256(self.simulated_outcome_sha256, "simulated outcome digest")
        if not 0 <= self.achieved_power <= 1 or not 0 <= self.monte_carlo_half_width_95 <= 1:
            raise ValueError("power probability summaries must be on [0, 1]")


@dataclass(frozen=True, slots=True)
class TargetPowerSimulationResult:
    plan: TargetPowerSimulationPlan
    scenarios: tuple[TargetPowerScenarioResult, ...]
    minimum_achieved_power: float
    power_gate_passed: bool
    interpretation: str = "assumption_conditional_not_observed_effect_evidence"
    target_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        if type(self.plan) is not TargetPowerSimulationPlan:
            raise TypeError("power result requires a typed plan")
        if any(type(item) is not TargetPowerScenarioResult for item in self.scenarios):
            raise TypeError("power result scenarios must be typed")
        if tuple(item.scenario_id for item in self.scenarios) != tuple(
            item.scenario_id for item in self.plan.assumptions
        ):
            raise ValueError("power results must exactly follow the frozen assumption grid")
        observed_minimum = min(item.achieved_power for item in self.scenarios)
        for item in self.scenarios:
            if (len(item.meaningful_replicates_by_coordinate) != self.plan.family_size_upper_bound
                or any(type(n) is not int or not 0 <= n <= self.plan.simulation_replicates for n in item.meaningful_replicates_by_coordinate)
                or sum(n for _, n in item.family_status_counts) != self.plan.simulation_replicates
                or item.achieved_power != min(item.meaningful_replicates_by_coordinate) / self.plan.simulation_replicates):
                raise ValueError("power replicate accounting does not replay")
        if self.minimum_achieved_power != observed_minimum:
            raise ValueError("minimum power does not replay from scenario results")
        if self.power_gate_passed is not (
            observed_minimum >= self.plan.target_power
        ):
            raise ValueError("power Gate does not replay from the frozen target")
        if self.interpretation != "assumption_conditional_not_observed_effect_evidence":
            raise ValueError("power result cannot be interpreted as observed effect evidence")
        if self.target_confirmation_outcomes_used is not False:
            raise ValueError("power simulation cannot read target confirmation outcomes")

    @property
    def power_simulation_result_id(self) -> str:
        return content_id("target_power_simulation_result_", self)


@lru_cache(maxsize=16)
def simulate_target_power(plan: TargetPowerSimulationPlan) -> TargetPowerSimulationResult:
    """Generate categorical request outcomes and run the actual task-unit family analysis.

    All non-evaluable replicates remain in each coordinate's power denominator.
    Sharing probabilities describe uniform draws, not asserted binary correlations.
    """
    from prompt_mechanism_study.experiment.inference import (
        ConfirmatoryEffectStatus,
        _target_effect_work,
        _target_family,
    )
    from prompt_mechanism_study.experiment.outcomes import Outcome

    if type(plan) is not TargetPowerSimulationPlan:
        raise TypeError("power simulation requires a TargetPowerSimulationPlan")
    dispatches, assignments = _power_assignments(plan)
    ids = tuple((tuple((a.assignment_id for a in rows)) for rows in assignments))
    inference_plan = plan.target_itt_plan()
    results = []
    for assumption in plan.assumptions:
        rng = random.Random(
            int(
                hashlib.sha256(
                    f"{plan.simulation_seed}|{assumption.scenario_id}".encode()
                ).hexdigest()[:16],
                16,
            )
        )
        meaningful = [0] * plan.family_size_upper_bound
        statuses = Counter()
        errors, criticals = ([], [])
        outcome_digest = hashlib.sha256()
        probabilities = dict(assumption.arm_secure_yield_probabilities)
        for _replicate in range(plan.simulation_replicates):
            draws = _power_task_draws(rng, assumption, plan, assignments)
            works = []
            for coordinate, (dispatch, rows) in enumerate(zip(dispatches, assignments)):
                outcomes = {}
                for index, (assignment, assignment_id, u) in enumerate(
                    zip(rows, ids[coordinate], draws[coordinate])
                ):
                    r = int(assignment.realization_id.removeprefix("realization-"))
                    arm_index = index % plan.total_block_slots // (plan.total_block_slots // 4)
                    names = ATOMIC_POWER_ARMS
                    p = (
                        probabilities[names[arm_index]]
                        + assumption.realization_arm_probability_offsets[r][arm_index]
                    )
                    no_code = assumption.terminal_no_code_rate
                    unknown = assumption.oracle_unknown_rate
                    state = (
                        0
                        if u < no_code
                        else 1 if u < no_code + unknown else 3 if u < no_code + unknown + p else 2
                    )
                    outcome_digest.update(bytes((state,)))
                    valid, evaluable, secure = (int(state > 0), int(state > 1), int(state == 3))
                    outcomes[assignment_id] = Outcome(
                        assignment_id,
                        valid,
                        evaluable,
                        secure,
                        int(state in {1, 3}),
                        0,
                        0,
                        0,
                        "no_code" if not valid else None,
                    )
                works.append(
                    _target_effect_work(dispatch, plan.track, rows, outcomes, set(), inference_plan)
                )
            family = _target_family(plan.track, tuple(works), inference_plan)
            statuses[family.status.value] += 1
            errors.extend((w.standard_error for w in works if w.standard_error is not None))
            criticals.extend(e.critical_value for e in family.estimates if e.critical_value is not None)
            for coordinate, estimate in enumerate(family.estimates):
                meaningful[coordinate] += estimate.status in {
                    ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL,
                    ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL,
                }
        power = min(meaningful) / plan.simulation_replicates
        results.append(
            TargetPowerScenarioResult(
                assumption.scenario_id,
                float(assumption.effect),
                sum(errors) / len(errors) if errors else None,
                sum(criticals) / len(criticals) if criticals else None,
                power,
                1.96 * math.sqrt(power * (1 - power) / plan.simulation_replicates),
                tuple(meaningful),
                tuple(sorted(statuses.items())),
                outcome_digest.hexdigest(),
            )
        )
    minimum = min((row.achieved_power for row in results))
    return TargetPowerSimulationResult(plan, tuple(results), minimum, minimum >= plan.target_power)


def _power_task_draws(rng, assumption, plan, assignments):
    """Couple only descendants of the same independent task in explicit support.

    The two synthetic planning layouts retain their frozen draw order so old
    power artifacts replay byte-for-byte. Disjoint layouts have zero shared draws.
    """
    units = [tuple(dict.fromkeys(row.task_unit_id for row in rows)) for rows in assignments]
    if plan.task_support is None:
        groups = [tuple((j, ids[i]) for j, ids in enumerate(units))
                  for i in range(plan.task_units_per_effect)]
    else:
        members = {}
        for j, ids in enumerate(units):
            for unit in ids:
                members.setdefault(unit, []).append((j, unit))
        groups = [members[unit] for unit in sorted(members)]
    draws = [dict() for _ in units]
    for group in groups:
        common = _power_uniform_block(rng, assumption, plan.total_block_slots // 4)
        for coordinate, unit in group:
            reuse = rng.random() < assumption.family_shared_draw_probability
            local = _power_uniform_block(rng, assumption, plan.total_block_slots // 4)
            draws[coordinate][unit] = common if reuse else local
    return [[u for unit in ids for u in draws[j][unit]] for j, ids in enumerate(units)]


def _power_uniform_block(rng, assumption, slots):
    shared_arms = rng.random() < assumption.cross_arm_shared_draw_probability
    common_slots = [rng.random() for _ in range(slots)]
    values = []
    for _arm in range(4):
        shared_requests = rng.random() < assumption.request_shared_draw_probability
        local = [rng.random() for _ in range(slots)]
        selected = common_slots if shared_arms else local
        values.extend([selected[0]] * slots if shared_requests else selected)
    return values


def _power_assignments(plan):
    from prompt_mechanism_study.discovery.prioritization import ConfirmationDispatchRecord
    from prompt_mechanism_study.experiment.randomization import (
        AssignedArmITTRecord,
        ConfirmatoryArm,
        TargetRandomizationPlan,
        allocate_target_realizations,
    )

    policies = tuple((f"power-coordinate-{i:03d}" for i in range(plan.family_size_upper_bound)))
    pools = tuple(
        (
            tuple(
                (
                    (
                        f"{('shared' if plan.family_task_overlap == 'shared' else policy)}-{s}-{i:05d}",
                        s,
                    )
                    for s, n in plan.stratum_task_counts
                    for i in range(n)
                )
            )
            for policy in policies
        )
    )
    if plan.task_support is not None:
        pools = tuple(
            (
                tuple(
                    (
                        (unit, stratum)
                        for j, unit, stratum, _ in plan.task_support
                        if j == coordinate
                    )
                )
                for coordinate in range(len(policies))
            )
        )
    allocation_plan = TargetRandomizationPlan(
        "power-planning",
        "3.0",
        plan.simulation_seed,
        plan.simulation_seed,
        plan.total_block_slots,
        tuple(
            sorted(
                (
                    (p, f"realization-{r}", q)
                    for p in policies
                    for r, q in enumerate(plan.realization_weights)
                )
            )
        ),
        tuple(sorted(((p, task, s) for p, pool in zip(policies, pools) for task, s in pool))),
    )
    allocation = (
        allocate_target_realizations(allocation_plan)
        if plan.task_support is None
        else {(policies[j], unit): f"realization-{r}" for j, unit, _, r in plan.task_support}
    )
    dispatches, assignments = ([], [])
    names = ATOMIC_POWER_ARMS
    for policy, pool in zip(policies, pools):
        dispatches.append(
            ConfirmationDispatchRecord(
                policy,
                policy,
                policy,
                "planning-model",
                BridgeStatus.SUCCESS,
                "planning-protocol",
                None,
                1,
            )
        )
        rows = []
        for task, stratum in pool:
            r_id = allocation[policy, task]
            q = plan.realization_weights[int(r_id.removeprefix("realization-"))]
            for arm_index, name in enumerate(names):
                for slot in range(plan.total_block_slots // 4):
                    rows.append(
                        AssignedArmITTRecord(
                            policy,
                            policy,
                            policy,
                            "planning-model",
                            plan.track,
                            task,
                            task,
                            stratum,
                            r_id,
                            "planning-bundle",
                            "planning-protocol",
                            arm_index * (plan.total_block_slots // 4) + slot,
                            ConfirmatoryArm(name),
                            1.0,
                            q,
                            "0" * 64,
                        )
                    )
        assignments.append(tuple(rows))
    return (tuple(dispatches), tuple(assignments))


def bind_target_power_to_assignments(
    plan: TargetPowerSimulationPlan, assignments: Sequence[Any],
) -> TargetPowerSimulationPlan:
    """Specialize the pre-Discovery assumptions to actual pre-outcome support.

    Only family membership and the exact task/realization table may change.
    Counts, strata, Q, margins, probabilities, seeds and inference rules stay frozen.
    """
    from prompt_mechanism_study.experiment.randomization import AssignedArmITTRecord
    rows = tuple(assignments)
    if not rows or any(type(row) is not AssignedArmITTRecord or row.track is not plan.track for row in rows):
        raise ValueError("actual power needs nonempty assigned-arm records from one family")
    candidates = sorted({row.candidate_record_id for row in rows})
    if len(candidates) > plan.family_size_upper_bound:
        raise ValueError("actual power exceeds the pre-Discovery family reservation")
    support = []
    for coordinate, candidate in enumerate(candidates):
        selected = [row for row in rows if row.candidate_record_id == candidate]
        labels = sorted({row.realization_id for row in selected})
        weights = {label: {float(row.realization_weight) for row in selected if row.realization_id == label}
                   for label in labels}
        if (len(labels) != plan.global_realizations or any(len(q) != 1 for q in weights.values())
            or tuple(next(iter(weights[label])) for label in labels) != plan.realization_weights):
            raise ValueError("actual power cannot change frozen realization weights")
        support.extend(sorted({(coordinate, row.task_unit_id, row.stratum_id, labels.index(row.realization_id))
                               for row in selected}))
    return replace(plan, family_size_upper_bound=len(candidates), family_task_overlap="explicit",
                   task_support=tuple(support))

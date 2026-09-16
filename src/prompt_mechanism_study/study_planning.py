"""Outcome-blind qualification, actual-procedure power and provider-budget planning."""

from __future__ import annotations

import hashlib
import math
import random
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from functools import lru_cache
from typing import Any

from prompt_mechanism_study.inference import TargetITTPlan
from prompt_mechanism_study.artifact_io import require_sha256
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique
from prompt_mechanism_study.prioritization import BridgeStatus, PolicyTrack
from prompt_mechanism_study.representation import DataRole, DataRoleManifest


class StudyDesignError(RuntimeError):
    """Raised when a prospective sample cannot satisfy its frozen constraints."""


class RQ1BudgetScenario(StrEnum):
    CORE = "core"
    CORE_EXPERT = "core_plus_expert"
    CORE_EXPERT_RANDOM = "core_plus_expert_plus_random"


class QualificationProfileKind(StrEnum):
    FCI = "fci"
    ATOMIC_RD = "atomic_rd"
    RQ1_BASELINES = "rq1_baselines"
    POWER_AND_MARGIN = "power_and_margin"


class QualificationStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    BLOCKED = "BLOCKED"


class QualificationPlanPhase(StrEnum):
    DEV_ENVELOPE_LOCKED = "DEV_ENVELOPE_LOCKED"
    ACCEPT_PLAN_FROZEN = "ACCEPT_PLAN_FROZEN"


@dataclass(frozen=True, slots=True)
class FreezeArtifactReference:
    """Content-addressed reference used by the two formal freeze moments."""

    artifact_id: str
    sha256: str

    def __post_init__(self) -> None:
        require_text(self.artifact_id, "artifact_id")
        require_sha256(self.sha256, "sha256")


@dataclass(frozen=True, slots=True)
class QualificationPlan:
    """One profile envelope or final decision in the same qualification path."""

    profile_kind: QualificationProfileKind
    candidate_profile_ids: tuple[str, ...]
    selected_profile_id: str | None
    selection_rule_id: str
    acceptance_metric_ids: tuple[str, ...]
    acceptance_thresholds_sha256: str
    tie_break_rule_id: str
    code_commit: str | None
    permitted_data_roles: tuple[DataRole, ...] = (
        DataRole.QUAL_DEV,
        DataRole.QUAL_ACCEPT,
    )
    failure_behavior: str = "BLOCKED_NEW_ACCEPTANCE_DATA_REQUIRED"
    plan_phase: QualificationPlanPhase = QualificationPlanPhase.ACCEPT_PLAN_FROZEN

    def __post_init__(self) -> None:
        if type(self.profile_kind) is not QualificationProfileKind:
            raise TypeError("profile_kind must be a QualificationProfileKind")
        _require_canonical_texts(self.candidate_profile_ids, "candidate_profile_ids")
        if type(self.plan_phase) is not QualificationPlanPhase:
            raise TypeError("plan_phase must be a QualificationPlanPhase")
        if self.plan_phase is QualificationPlanPhase.DEV_ENVELOPE_LOCKED:
            if self.selected_profile_id is not None or self.code_commit is not None:
                raise ValueError(
                    "DEV envelope cannot select a profile or bind the acceptance commit"
                )
        else:
            require_text(self.selected_profile_id, "selected_profile_id")
            if self.selected_profile_id not in self.candidate_profile_ids:
                raise ValueError("selected profile must be one of the frozen candidates")
            if not isinstance(self.code_commit, str):
                raise TypeError("acceptance plan code_commit must be text")
            _require_git_commit(self.code_commit)
        require_text(self.selection_rule_id, "selection_rule_id")
        _require_canonical_texts(self.acceptance_metric_ids, "acceptance_metric_ids")
        require_sha256(
            self.acceptance_thresholds_sha256,
            "acceptance_thresholds_sha256",
        )
        require_text(self.tie_break_rule_id, "tie_break_rule_id")
        if self.permitted_data_roles != (
            DataRole.QUAL_DEV,
            DataRole.QUAL_ACCEPT,
        ):
            raise ValueError("qualification plans may use only QUAL_DEV and QUAL_ACCEPT")
        if self.failure_behavior != "BLOCKED_NEW_ACCEPTANCE_DATA_REQUIRED":
            raise ValueError("acceptance failure must require a new unexposed dataset")

    @property
    def qualification_plan_id(self) -> str:
        return content_id("qualification_plan_", self)


@dataclass(frozen=True, slots=True)
class QualificationPlanBundle:
    """Integrated one-shot plan for all target-method qualification profiles."""

    protocol_id: str
    data_role_manifest_id: str
    qualification_dev_data_ids: tuple[str, ...]
    qualification_accept_data_id: str
    plans: tuple[QualificationPlan, ...]
    plan_phase: QualificationPlanPhase = QualificationPlanPhase.ACCEPT_PLAN_FROZEN
    acceptance_attempts_per_dataset: int = 1

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        require_text(self.data_role_manifest_id, "data_role_manifest_id")
        _require_canonical_texts(
            self.qualification_dev_data_ids,
            "qualification_dev_data_ids",
        )
        require_text(self.qualification_accept_data_id, "qualification_accept_data_id")
        if any(type(plan) is not QualificationPlan for plan in self.plans):
            raise TypeError("plans must contain QualificationPlan values")
        expected = tuple(QualificationProfileKind)
        if tuple(plan.profile_kind for plan in self.plans) != expected:
            raise ValueError("qualification bundle must contain every target plan in order")
        if type(self.plan_phase) is not QualificationPlanPhase:
            raise TypeError("plan_phase must be a QualificationPlanPhase")
        if {plan.plan_phase for plan in self.plans} != {self.plan_phase}:
            raise ValueError("every qualification plan must use the bundle phase")
        if self.plan_phase is QualificationPlanPhase.ACCEPT_PLAN_FROZEN:
            if len({plan.code_commit for plan in self.plans}) != 1:
                raise ValueError("all acceptance plans must bind the same code commit")
        elif any(plan.selected_profile_id is not None for plan in self.plans):
            raise ValueError("DEV envelope cannot contain selected profiles")
        if self.acceptance_attempts_per_dataset != 1:
            raise ValueError("QUAL_ACCEPT is a one-shot acceptance resource")

    @property
    def qualification_plan_bundle_id(self) -> str:
        return content_id("qualification_plan_bundle_", self)

    @property
    def acceptance_ready(self) -> bool:
        return self.plan_phase is QualificationPlanPhase.ACCEPT_PLAN_FROZEN


@dataclass(frozen=True, slots=True)
class QualificationProfileResult:
    """Immutable acceptance result for one selected qualification profile."""

    profile_kind: QualificationProfileKind
    selected_profile_id: str
    artifact: FreezeArtifactReference
    status: QualificationStatus
    qualification_accept_data_id: str
    code_commit: str
    independent_verifier_status: str

    def __post_init__(self) -> None:
        if type(self.profile_kind) is not QualificationProfileKind:
            raise TypeError("profile_kind must be a QualificationProfileKind")
        require_text(self.selected_profile_id, "selected_profile_id")
        if type(self.artifact) is not FreezeArtifactReference:
            raise TypeError("artifact must be a FreezeArtifactReference")
        if type(self.status) is not QualificationStatus:
            raise TypeError("status must be a QualificationStatus")
        require_text(self.qualification_accept_data_id, "qualification_accept_data_id")
        _require_git_commit(self.code_commit)
        if self.independent_verifier_status not in {"PASS", "FAIL"}:
            raise ValueError("independent_verifier_status must be PASS or FAIL")
        if (
            self.status is QualificationStatus.ACCEPTED
            and self.independent_verifier_status != "PASS"
        ):
            raise ValueError("an accepted profile requires an independent verifier PASS")


@dataclass(frozen=True, slots=True)
class QualificationBundle:
    """Top-level acceptance index; only ACCEPTED bundles may enter discovery."""

    protocol_id: str
    data_role_manifest: FreezeArtifactReference
    qualification_plan_bundle: FreezeArtifactReference
    qualification_accept_data_id: str
    profiles: tuple[QualificationProfileResult, ...]
    status: QualificationStatus
    verifier_status: str
    acceptance_attempts: int = 1
    plan_binding_verified: bool = False

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "protocol_id")
        if type(self.data_role_manifest) is not FreezeArtifactReference:
            raise TypeError("data_role_manifest must be a FreezeArtifactReference")
        if type(self.qualification_plan_bundle) is not FreezeArtifactReference:
            raise TypeError("qualification_plan_bundle must be a FreezeArtifactReference")
        require_text(self.qualification_accept_data_id, "qualification_accept_data_id")
        if any(type(profile) is not QualificationProfileResult for profile in self.profiles):
            raise TypeError("profiles must contain QualificationProfileResult values")
        expected = tuple(QualificationProfileKind)
        if tuple(profile.profile_kind for profile in self.profiles) != expected:
            raise ValueError("qualification bundle must contain every target result in order")
        if {
            profile.qualification_accept_data_id for profile in self.profiles
        } != {self.qualification_accept_data_id}:
            raise ValueError("all profiles must use the one frozen acceptance dataset")
        if len({profile.code_commit for profile in self.profiles}) != 1:
            raise ValueError("all profile results must bind the same code commit")
        if type(self.status) is not QualificationStatus:
            raise TypeError("status must be a QualificationStatus")
        if self.verifier_status not in {"PASS", "FAIL"}:
            raise ValueError("verifier_status must be PASS or FAIL")
        if self.acceptance_attempts != 1:
            raise ValueError("qualification acceptance cannot be retried on the same data")
        if type(self.plan_binding_verified) is not bool:
            raise TypeError("qualification plan-binding status must be boolean")
        all_accepted = all(
            profile.status is QualificationStatus.ACCEPTED
            and profile.independent_verifier_status == "PASS"
            for profile in self.profiles
        )
        if self.status is QualificationStatus.ACCEPTED:
            if (
                not all_accepted
                or self.verifier_status != "PASS"
                or self.plan_binding_verified is not True
            ):
                raise ValueError("ACCEPTED requires every profile and verifier to pass")
        elif all_accepted and self.verifier_status == "PASS":
            raise ValueError("a fully passing qualification bundle cannot be BLOCKED")

    @property
    def formal_use_authorized(self) -> bool:
        return self.status is QualificationStatus.ACCEPTED

    @property
    def qualification_bundle_id(self) -> str:
        return content_id("qualification_bundle_", self)


def freeze_qualification_bundle(
    manifest: DataRoleManifest,
    plan_bundle: QualificationPlanBundle,
    profiles: Sequence[QualificationProfileResult],
    *,
    verifier_status: str,
) -> QualificationBundle:
    """Close the one-shot acceptance result against its pre-exposure frozen plan."""

    if type(manifest) is not DataRoleManifest:
        raise TypeError("qualification acceptance requires a DataRoleManifest")
    if type(plan_bundle) is not QualificationPlanBundle:
        raise TypeError("qualification acceptance requires a QualificationPlanBundle")
    if not plan_bundle.acceptance_ready:
        raise ValueError("QUAL_ACCEPT cannot run from a DEV-only profile envelope")
    if (
        plan_bundle.protocol_id != manifest.protocol_id
        or plan_bundle.data_role_manifest_id != manifest.data_role_manifest_id
        or plan_bundle.qualification_accept_data_id
        != manifest.qualification_accept_data_id
    ):
        raise ValueError("qualification plan drifted from the frozen data roles")
    frozen_profiles = tuple(profiles)
    if tuple(item.profile_kind for item in frozen_profiles) != tuple(
        QualificationProfileKind
    ):
        raise ValueError("qualification results must cover every target profile in order")
    for plan, result in zip(plan_bundle.plans, frozen_profiles, strict=True):
        if (
            result.profile_kind is not plan.profile_kind
            or result.selected_profile_id != plan.selected_profile_id
            or result.qualification_accept_data_id
            != plan_bundle.qualification_accept_data_id
            or result.code_commit != plan.code_commit
        ):
            raise ValueError("qualification result drifted from the frozen acceptance plan")
    all_accepted = all(
        item.status is QualificationStatus.ACCEPTED
        and item.independent_verifier_status == "PASS"
        for item in frozen_profiles
    )
    status = (
        QualificationStatus.ACCEPTED
        if all_accepted and verifier_status == "PASS"
        else QualificationStatus.BLOCKED
    )
    return QualificationBundle(
        manifest.protocol_id,
        FreezeArtifactReference(
            manifest.data_role_manifest_id,
            content_hash(manifest),
        ),
        FreezeArtifactReference(
            plan_bundle.qualification_plan_bundle_id,
            content_hash(plan_bundle),
        ),
        manifest.qualification_accept_data_id,
        frozen_profiles,
        status,
        verifier_status,
        plan_binding_verified=True,
    )


def qualification_plan_bundle(
    manifest: DataRoleManifest,
    plans: Sequence[QualificationPlan],
) -> QualificationPlanBundle:
    """Bind a complete plan to the role manifest without reading acceptance data."""

    if type(manifest) is not DataRoleManifest:
        raise TypeError("manifest must be a DataRoleManifest")
    frozen_plans = tuple(plans)
    if any(type(plan) is not QualificationPlan for plan in frozen_plans):
        raise TypeError("plans must contain QualificationPlan values")
    kind_order = tuple(QualificationProfileKind)
    ordered = tuple(
        sorted(frozen_plans, key=lambda plan: kind_order.index(plan.profile_kind))
    )
    for data_id in manifest.qualification_dev_data_ids:
        manifest.require_dataset_role(data_id, DataRole.QUAL_DEV)
    manifest.require_dataset_role(
        manifest.qualification_accept_data_id,
        DataRole.QUAL_ACCEPT,
    )
    return QualificationPlanBundle(
        manifest.protocol_id,
        manifest.data_role_manifest_id,
        manifest.qualification_dev_data_ids,
        manifest.qualification_accept_data_id,
        ordered,
        plan_phase=ordered[0].plan_phase,
    )


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
    multiplicity_method: str = "family_max_abs_t"
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
        if self.multiplicity_method != "family_max_abs_t":
            raise ValueError("target power must use the frozen max-|T| family")
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
    from prompt_mechanism_study.inference import (
        ConfirmatoryEffectStatus,
        _target_effect_work,
        _target_family,
    )
    from prompt_mechanism_study.outcomes import Outcome

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
            if family.simultaneous_critical_value is not None:
                criticals.append(family.simultaneous_critical_value)
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
    from prompt_mechanism_study.prioritization import ConfirmationDispatchRecord
    from prompt_mechanism_study.randomization import (
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
    from prompt_mechanism_study.randomization import AssignedArmITTRecord
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


@dataclass(frozen=True, slots=True)
class PowerAndMarginMemo:
    """Qualification artifact that alone may authorize target inference parameters."""

    protocol_id: str
    data_role_manifest_id: str
    qualification_accept_data_id: str
    code_commit: str
    atomic_power: TargetPowerSimulationResult
    bootstrap_draws: int
    bootstrap_seed: int
    minimum_valid_bootstrap_fraction: float
    maximum_unknown_fraction_among_valid: float
    status: QualificationStatus
    independent_verifier_status: str
    endpoint_order: tuple[str, ...] = (
        "secure_yield",
        "code_valid",
        "oracle_evaluable",
        "functionality",
        "joint",
    )
    bootstrap_quantile_method: str = "higher"
    expected_direction_used: bool = False
    target_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "power memo protocol_id")
        require_text(self.data_role_manifest_id, "power memo data_role_manifest_id")
        require_text(self.qualification_accept_data_id, "power memo qualification_accept_data_id")
        _require_git_commit(self.code_commit)
        if type(self.atomic_power) is not TargetPowerSimulationResult:
            raise TypeError("power memo requires an Atomic power result")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("inference bootstrap draws must be at least 100")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("inference bootstrap seed must be an integer")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0 < self.minimum_valid_bootstrap_fraction <= 1
        ):
            raise ValueError("minimum valid bootstrap fraction must be a float in (0, 1]")
        if (
            type(self.maximum_unknown_fraction_among_valid) is not float
            or not 0 <= self.maximum_unknown_fraction_among_valid <= 1
        ):
            raise ValueError("maximum unknown fraction among valid code must be a float on [0, 1]")
        if type(self.status) is not QualificationStatus:
            raise TypeError("power memo status must be typed")
        if self.independent_verifier_status not in {"PASS", "FAIL"}:
            raise ValueError("power memo verifier status must be PASS or FAIL")
        expected_endpoints = (
            "secure_yield",
            "code_valid",
            "oracle_evaluable",
            "functionality",
            "joint",
        )
        if self.endpoint_order != expected_endpoints:
            raise ValueError("power memo endpoint order drifted from the target contract")
        if self.bootstrap_quantile_method != "higher":
            raise ValueError("target inference bootstrap quantile method must be higher")
        if self.expected_direction_used is not False:
            raise ValueError("target power and inference cannot use expected direction")
        if self.target_confirmation_outcomes_used is not False:
            raise ValueError("power-and-margin qualification cannot read target outcomes")
        expected_analysis = TargetITTPlan(
            self.bootstrap_seed,
            self.bootstrap_draws,
            self.alpha,
            self.atomic_power.plan.minimum_task_units_per_stratum,
            self.minimum_valid_bootstrap_fraction,
            self.atomic_power.plan.practical_margin,
            self.maximum_unknown_fraction_among_valid,
            atomic_minimum_task_units_per_realization=self.atomic_power.plan.minimum_task_units_per_realization,
        )
        if any((result.plan.analysis_plan != expected_analysis for result in (self.atomic_power,))):
            raise ValueError("power simulation must use the exact frozen memo inference plan")
        passed = self.atomic_power.power_gate_passed and self.independent_verifier_status == "PASS"
        if self.status is QualificationStatus.ACCEPTED and (not passed):
            raise ValueError("ACCEPTED power memo requires the power Gate and verifier PASS")
        if self.status is QualificationStatus.BLOCKED and passed:
            raise ValueError("a fully passing power memo cannot remain BLOCKED")

    @property
    def alpha(self) -> float:
        return self.atomic_power.plan.alpha

    @property
    def formal_use_authorized(self) -> bool:
        return self.status is QualificationStatus.ACCEPTED

    @property
    def power_and_margin_memo_id(self) -> str:
        return content_id("power_and_margin_memo_", self)

    def target_itt_plan(self):
        """Construct the only target inference plan authorized by this memo."""
        if not self.formal_use_authorized:
            raise StudyDesignError("a BLOCKED power memo cannot authorize target inference")
        from prompt_mechanism_study.inference import TargetITTPlan

        return TargetITTPlan(
            self.bootstrap_seed,
            self.bootstrap_draws,
            self.alpha,
            self.atomic_power.plan.minimum_task_units_per_stratum,
            self.minimum_valid_bootstrap_fraction,
            self.atomic_power.plan.practical_margin,
            self.maximum_unknown_fraction_among_valid,
            atomic_minimum_task_units_per_realization=self.atomic_power.plan.minimum_task_units_per_realization,
        )


def freeze_power_and_margin_memo(
    manifest: DataRoleManifest,
    *,
    code_commit: str,
    atomic_power: TargetPowerSimulationResult,
    bootstrap_draws: int,
    bootstrap_seed: int,
    minimum_valid_bootstrap_fraction: float,
    maximum_unknown_fraction_among_valid: float,
    independent_verifier_status: str,
) -> PowerAndMarginMemo:
    """Bind a passing or blocked memo to the one-shot QUAL_ACCEPT role."""
    if type(manifest) is not DataRoleManifest:
        raise TypeError("power memo requires a DataRoleManifest")
    manifest.require_dataset_role(manifest.qualification_accept_data_id, DataRole.QUAL_ACCEPT)
    passed = atomic_power.power_gate_passed and independent_verifier_status == "PASS"
    return PowerAndMarginMemo(
        manifest.protocol_id,
        manifest.data_role_manifest_id,
        manifest.qualification_accept_data_id,
        code_commit,
        atomic_power,
        bootstrap_draws,
        bootstrap_seed,
        minimum_valid_bootstrap_fraction,
        maximum_unknown_fraction_among_valid,
        QualificationStatus.ACCEPTED if passed else QualificationStatus.BLOCKED,
        independent_verifier_status,
    )


class ProviderCallKind(StrEnum):
    MATERIALIZATION = "materialization"
    GENERATION = "generation"
    FUNCTIONAL_JUDGE = "functional_judge"


@dataclass(frozen=True, slots=True)
class ProviderTokenCostBasis:
    """Frozen token ceilings and list-price tier for one call kind."""

    currency: str
    deployment_region: str
    pricing_tier_id: str
    pricing_tier_maximum_input_tokens: int
    maximum_input_tokens: int
    maximum_output_tokens: int
    input_price_microunits_per_million_tokens: int
    output_price_microunits_per_million_tokens: int
    target_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.currency, "provider pricing currency")
        if (
            len(self.currency) != 3
            or self.currency != self.currency.upper()
            or not self.currency.isascii()
            or not self.currency.isalpha()
        ):
            raise ValueError("provider pricing currency must be an uppercase ISO-style code")
        require_text(self.deployment_region, "provider deployment region")
        require_text(self.pricing_tier_id, "provider pricing tier")
        for value, name in (
            (
                self.pricing_tier_maximum_input_tokens,
                "pricing tier maximum input tokens",
            ),
            (self.maximum_input_tokens, "maximum input tokens"),
            (self.maximum_output_tokens, "maximum output tokens"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.pricing_tier_maximum_input_tokens <= 0:
            raise ValueError("pricing tier maximum input tokens must be positive")
        if self.maximum_input_tokens > self.pricing_tier_maximum_input_tokens:
            raise ValueError("maximum input tokens exceed the frozen pricing tier")
        if self.maximum_input_tokens + self.maximum_output_tokens <= 0:
            raise ValueError("provider token ceiling cannot be empty")
        for value, name in (
            (
                self.input_price_microunits_per_million_tokens,
                "input token price",
            ),
            (
                self.output_price_microunits_per_million_tokens,
                "output token price",
            ),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer microunit rate")
        if (
            self.input_price_microunits_per_million_tokens
            + self.output_price_microunits_per_million_tokens
            <= 0
        ):
            raise ValueError("provider token prices cannot both be zero")
        if self.target_outcomes_used is not False:
            raise ValueError("provider price qualification cannot read target outcomes")

    @property
    def maximum_call_cost_microunits(self) -> int:
        numerator = (
            self.maximum_input_tokens
            * self.input_price_microunits_per_million_tokens
            + self.maximum_output_tokens
            * self.output_price_microunits_per_million_tokens
        )
        return (numerator + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class ProviderRate:
    call_kind: ProviderCallKind
    provider_id: str
    maximum_unit_cost_microunits: int
    pricing_reference: FreezeArtifactReference
    token_cost_basis: ProviderTokenCostBasis
    automatic_retry_ceiling: int = 0

    def __post_init__(self) -> None:
        if type(self.call_kind) is not ProviderCallKind:
            raise TypeError("provider rate call kind must be typed")
        require_text(self.provider_id, "provider_id")
        if (
            type(self.maximum_unit_cost_microunits) is not int
            or self.maximum_unit_cost_microunits < 0
        ):
            raise ValueError("provider unit cost must be nonnegative integer microunits")
        if type(self.pricing_reference) is not FreezeArtifactReference:
            raise TypeError("provider pricing must have a frozen reference")
        if type(self.token_cost_basis) is not ProviderTokenCostBasis:
            raise TypeError("provider rate requires a typed token cost basis")
        if (
            self.maximum_unit_cost_microunits
            != self.token_cost_basis.maximum_call_cost_microunits
        ):
            raise ValueError("provider unit cost does not replay from token ceilings and prices")
        if self.automatic_retry_ceiling != 0:
            raise ValueError("active v3 budget permits no hidden automatic retries")


@dataclass(frozen=True, slots=True)
class ProviderBudgetCeilings:
    rates: tuple[ProviderRate, ...]
    materialization_call_ceiling: int
    generation_call_ceiling: int
    functional_judge_call_ceiling: int
    external_call_ceiling: int
    external_cost_ceiling_microunits: int

    def __post_init__(self) -> None:
        if any(type(item) is not ProviderRate for item in self.rates):
            raise TypeError("provider ceilings require typed rates")
        if tuple(item.call_kind for item in self.rates) != tuple(ProviderCallKind):
            raise ValueError("provider rates must cover all call kinds in canonical order")
        currencies = {item.token_cost_basis.currency for item in self.rates}
        if len(currencies) != 1:
            raise ValueError("all provider rates must use one frozen budget currency")
        for name in (
            "materialization_call_ceiling",
            "generation_call_ceiling",
            "functional_judge_call_ceiling",
            "external_call_ceiling",
            "external_cost_ceiling_microunits",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    @property
    def unit_costs(self) -> dict[ProviderCallKind, int]:
        return {
            item.call_kind: item.maximum_unit_cost_microunits for item in self.rates
        }

    @property
    def provider_budget_ceilings_id(self) -> str:
        return content_id("provider_budget_ceilings_", self)


@dataclass(frozen=True, slots=True)
class RQ1BudgetDimensions:
    """Unfrozen dimensions used to compare the three approved envelopes.

    These inputs support prospective feasibility accounting only. Supplying
    numbers does not freeze them or authorize provider calls.
    """

    model_ids: tuple[str, ...]
    atomic_top_k: int
    atomic_task_units_per_effect: int
    atomic_global_realizations: int
    atomic_total_block_slots: int
    realization_assignments_per_task: int = 1
    model_dispatch_policy: str = "model_bound_effect_coordinate"
    confirmation_cross_product_models: bool = False

    def __post_init__(self) -> None:
        if not self.model_ids:
            raise ValueError("model_ids cannot be empty")
        for model_id in self.model_ids:
            require_text(model_id, "model_id")
        require_unique(self.model_ids, "model_ids")
        if tuple(sorted(self.model_ids)) != self.model_ids:
            raise ValueError("model_ids must use canonical order")
        for name in (
            "atomic_top_k",
            "atomic_task_units_per_effect",
            "atomic_global_realizations",
            "atomic_total_block_slots",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.atomic_total_block_slots % 4 != 0:
            raise ValueError("total block slots must be positive multiples of four")
        if self.realization_assignments_per_task != 1:
            raise ValueError("each task unit must be assigned exactly one realization")
        if self.model_dispatch_policy != "model_bound_effect_coordinate":
            raise ValueError("only model-bound effect-coordinate dispatch is permitted")
        if self.confirmation_cross_product_models is not False:
            raise ValueError(
                "model-bound candidate records cannot be crossed with all models again"
            )


def rq1_worst_case_budget_envelopes(dimensions: RQ1BudgetDimensions) -> dict[str, Any]:
    """Compute Core, +Expert, and +Random worst-case provider reservations."""
    if type(dimensions) is not RQ1BudgetDimensions:
        raise TypeError("dimensions must be RQ1BudgetDimensions")
    scenarios = (
        (RQ1BudgetScenario.CORE, 2),
        (RQ1BudgetScenario.CORE_EXPERT, 3),
        (RQ1BudgetScenario.CORE_EXPERT_RANDOM, 4),
    )
    model_count = len(dimensions.model_ids)
    rows = []
    for scenario, selector_variants_per_track in scenarios:
        atomic_effect_records = selector_variants_per_track * model_count * dimensions.atomic_top_k
        atomic_policy_bundles = atomic_effect_records * dimensions.atomic_task_units_per_effect
        generation_calls = atomic_policy_bundles * dimensions.atomic_total_block_slots
        materialization_calls = 2 * atomic_policy_bundles
        maximum_external_calls = materialization_calls + 2 * generation_calls
        rows.append(
            {
                "scenario": scenario.value,
                "atomic_selector_variants": selector_variants_per_track,
                "atomic_effect_record_upper_bound": atomic_effect_records,
                "generation_call_upper_bound": generation_calls,
                "materialization_call_upper_bound": materialization_calls,
                "functional_judge_call_upper_bound": generation_calls,
                "external_call_upper_bound": maximum_external_calls,
                "accidental_model_square_generation_calls": generation_calls * model_count,
            }
        )
    report = {
        "schema_version": "1.0-draft",
        "status": "SPECIFIED_DRAFT",
        "model_dispatch_policy": dimensions.model_dispatch_policy,
        "model_ids": list(dimensions.model_ids),
        "confirmation_cross_product_models": False,
        "security_oracle_is_local": True,
        "scientific_claim_allowed": False,
        "provider_calls_authorized": False,
        "dimensions": {
            "atomic_top_k": dimensions.atomic_top_k,
            "atomic_task_units_per_effect": dimensions.atomic_task_units_per_effect,
            "atomic_global_realizations": dimensions.atomic_global_realizations,
            "realization_assignments_per_task": 1,
            "atomic_total_block_slots": dimensions.atomic_total_block_slots,
        },
        "scenarios": rows,
    }
    report["budget_envelope_id"] = content_id("rq1_budget_envelope_", report)
    return report


def _scenario_selector_ids(scenario: RQ1BudgetScenario) -> tuple[str, ...]:
    atomic = ["atomic_full", "atomic_rd_only"]
    if scenario in {RQ1BudgetScenario.CORE_EXPERT, RQ1BudgetScenario.CORE_EXPERT_RANDOM}:
        atomic.append("atomic_blind_expert")
    if scenario is RQ1BudgetScenario.CORE_EXPERT_RANDOM:
        atomic.append("atomic_seeded_random")
    return tuple(sorted(atomic))


def _baseline_profile_id(scenario: RQ1BudgetScenario) -> str:
    return {
        RQ1BudgetScenario.CORE: "rq1_baseline_set_core_v1",
        RQ1BudgetScenario.CORE_EXPERT: "rq1_baseline_set_core_expert_v1",
        RQ1BudgetScenario.CORE_EXPERT_RANDOM: (
            "rq1_baseline_set_core_expert_random_v1"
        ),
    }[scenario]


@dataclass(frozen=True, slots=True)
class RQ1BaselineQualification:
    """Qualification evidence for every external baseline selected by RQ1."""

    protocol_id: str
    scenario: RQ1BudgetScenario
    model_ids: tuple[str, ...]
    qualification_accept_data_id: str
    code_commit: str
    contract_references: tuple[tuple[str, str, FreezeArtifactReference], ...]
    status: QualificationStatus
    blockers: tuple[str, ...]
    independent_verifier_status: str
    target_discovery_or_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "baseline qualification protocol_id")
        if type(self.scenario) is not RQ1BudgetScenario:
            raise TypeError("baseline qualification scenario must be typed")
        _require_canonical_texts(self.model_ids, "baseline qualification model_ids")
        require_text(self.qualification_accept_data_id, "baseline qualification acceptance data")
        _require_git_commit(self.code_commit)
        atomic = _scenario_selector_ids(self.scenario)
        core = {"atomic_full", "atomic_rd_only"}
        external = tuple(sorted(set(atomic) - core))
        expected_coordinates = tuple(
            sorted(
                ((selector_id, model_id) for selector_id in external for model_id in self.model_ids)
            )
        )
        actual_coordinates = tuple(
            ((selector_id, model_id) for selector_id, model_id, _ in self.contract_references)
        )
        if actual_coordinates != tuple(sorted(set(actual_coordinates))):
            raise ValueError("baseline qualification contracts must be canonical")
        if not set(actual_coordinates) <= set(expected_coordinates):
            raise ValueError("baseline qualification contains an unselected contract")
        if any(
            (
                type(reference) is not FreezeArtifactReference
                for _, _, reference in self.contract_references
            )
        ):
            raise TypeError("baseline qualification references must be typed")
        if type(self.status) is not QualificationStatus:
            raise TypeError("baseline qualification status must be typed")
        if self.blockers != tuple(sorted(set(self.blockers))):
            raise ValueError("baseline qualification blockers must be canonical")
        if self.independent_verifier_status not in {"PASS", "FAIL"}:
            raise ValueError("baseline qualification verifier must be PASS or FAIL")
        if self.target_discovery_or_confirmation_outcomes_used is not False:
            raise ValueError("baseline qualification cannot use target outcomes")
        passing = (
            actual_coordinates == expected_coordinates
            and (not self.blockers)
            and (self.independent_verifier_status == "PASS")
        )
        if self.status is QualificationStatus.ACCEPTED and (not passing):
            raise ValueError("accepted baseline qualification requires every contract")
        if self.status is QualificationStatus.BLOCKED and passing:
            raise ValueError("a fully passing baseline qualification cannot be blocked")

    @property
    def selected_profile_id(self) -> str:
        return _baseline_profile_id(self.scenario)

    @property
    def formal_use_authorized(self) -> bool:
        return self.status is QualificationStatus.ACCEPTED

    @property
    def rq1_baseline_qualification_id(self) -> str:
        return content_id("rq1_baseline_qualification_", self)


def qualify_rq1_baselines(
    *,
    protocol_id: str,
    scenario: RQ1BudgetScenario,
    model_ids: Sequence[str],
    qualification_accept_data_id: str,
    code_commit: str,
    contract_references: Sequence[tuple[str, str, FreezeArtifactReference]],
    independent_verifier_status: str,
) -> RQ1BaselineQualification:
    """Close the selected baseline contracts without reading target outcomes."""
    if type(scenario) is not RQ1BudgetScenario:
        raise TypeError("baseline qualification scenario must be typed")
    frozen_models = tuple(sorted(model_ids))
    _require_canonical_texts(frozen_models, "baseline qualification model_ids")
    frozen_references = tuple(sorted(contract_references, key=lambda item: (item[0], item[1])))
    atomic = _scenario_selector_ids(scenario)
    core = {"atomic_full", "atomic_rd_only"}
    expected = {
        (selector_id, model_id) for selector_id in set(atomic) - core for model_id in frozen_models
    }
    actual = {(selector_id, model_id) for selector_id, model_id, _ in frozen_references}
    blockers = set()
    if actual != expected:
        blockers.add("baseline_contract_coverage_incomplete")
    if independent_verifier_status != "PASS":
        blockers.add("independent_baseline_verifier_failed")
    frozen_blockers = tuple(sorted(blockers))
    return RQ1BaselineQualification(
        protocol_id,
        scenario,
        frozen_models,
        qualification_accept_data_id,
        code_commit,
        frozen_references,
        QualificationStatus.ACCEPTED if not frozen_blockers else QualificationStatus.BLOCKED,
        frozen_blockers,
        independent_verifier_status,
    )


@dataclass(frozen=True, slots=True)
class RQ1BudgetReservation:
    scenario: RQ1BudgetScenario
    atomic_effect_record_upper_bound: int
    materialization_call_upper_bound: int
    generation_call_upper_bound: int
    functional_judge_call_upper_bound: int
    external_call_upper_bound: int
    external_cost_upper_bound_microunits: int

    def __post_init__(self) -> None:
        if type(self.scenario) is not RQ1BudgetScenario:
            raise TypeError("budget reservation scenario must be typed")
        for name in (
            "atomic_effect_record_upper_bound",
            "materialization_call_upper_bound",
            "generation_call_upper_bound",
            "functional_judge_call_upper_bound",
            "external_call_upper_bound",
            "external_cost_upper_bound_microunits",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if (
            self.external_call_upper_bound
            != self.materialization_call_upper_bound
            + self.generation_call_upper_bound
            + self.functional_judge_call_upper_bound
        ):
            raise ValueError("external-call reservation does not replay from its components")


def _budget_reservation(
    dimensions: RQ1BudgetDimensions, scenario: RQ1BudgetScenario, ceilings: ProviderBudgetCeilings
) -> RQ1BudgetReservation:
    report = rq1_worst_case_budget_envelopes(dimensions)
    row = next((item for item in report["scenarios"] if item["scenario"] == scenario.value))
    costs = ceilings.unit_costs
    total_cost = (
        row["materialization_call_upper_bound"] * costs[ProviderCallKind.MATERIALIZATION]
        + row["generation_call_upper_bound"] * costs[ProviderCallKind.GENERATION]
        + row["functional_judge_call_upper_bound"] * costs[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    return RQ1BudgetReservation(
        scenario,
        row["atomic_effect_record_upper_bound"],
        row["materialization_call_upper_bound"],
        row["generation_call_upper_bound"],
        row["functional_judge_call_upper_bound"],
        row["external_call_upper_bound"],
        total_cost,
    )


@dataclass(frozen=True, slots=True)
class RQ1BudgetQualification:
    """Joint numeric decision; only an accepted instance may authorize preflight."""

    protocol_id: str
    scenario: RQ1BudgetScenario
    dimensions: RQ1BudgetDimensions
    atomic_selector_ids: tuple[str, ...]
    power_and_margin_memo: PowerAndMarginMemo
    qualification_bundle: QualificationBundle
    baseline_qualification: RQ1BaselineQualification
    provider_ceilings: ProviderBudgetCeilings
    reservation: RQ1BudgetReservation
    status: QualificationStatus
    blockers: tuple[str, ...]
    independent_verifier_status: str
    target_discovery_or_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "RQ1 budget protocol_id")
        if type(self.scenario) is not RQ1BudgetScenario:
            raise TypeError("RQ1 budget scenario must be typed")
        if type(self.dimensions) is not RQ1BudgetDimensions:
            raise TypeError("RQ1 budget dimensions must be typed")
        expected_atomic = _scenario_selector_ids(self.scenario)
        if self.atomic_selector_ids != expected_atomic:
            raise ValueError("RQ1 selector set does not match the frozen scenario")
        if type(self.power_and_margin_memo) is not PowerAndMarginMemo:
            raise TypeError("RQ1 budget requires a power-and-margin memo")
        if type(self.qualification_bundle) is not QualificationBundle:
            raise TypeError("RQ1 budget requires the integrated qualification bundle")
        if type(self.baseline_qualification) is not RQ1BaselineQualification:
            raise TypeError("RQ1 budget requires a baseline qualification")
        if type(self.provider_ceilings) is not ProviderBudgetCeilings:
            raise TypeError("RQ1 budget requires typed provider ceilings")
        if type(self.reservation) is not RQ1BudgetReservation:
            raise TypeError("RQ1 budget requires a typed reservation")
        if self.reservation != _budget_reservation(
            self.dimensions, self.scenario, self.provider_ceilings
        ):
            raise ValueError("RQ1 reservation does not replay from dimensions and rates")
        if type(self.status) is not QualificationStatus:
            raise TypeError("RQ1 budget status must be typed")
        if self.blockers != tuple(sorted(set(self.blockers))):
            raise ValueError("RQ1 budget blockers must be canonical")
        if self.independent_verifier_status not in {"PASS", "FAIL"}:
            raise ValueError("RQ1 budget verifier status must be PASS or FAIL")
        if self.target_discovery_or_confirmation_outcomes_used is not False:
            raise ValueError("RQ1 budget cannot use target discovery or confirmation outcomes")
        if (
            self.protocol_id != self.power_and_margin_memo.protocol_id
            or self.protocol_id != self.qualification_bundle.protocol_id
            or self.protocol_id != self.baseline_qualification.protocol_id
        ):
            raise ValueError("RQ1 budget protocol lineage drift")
        power_profile = next(
            (
                profile
                for profile in self.qualification_bundle.profiles
                if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
            )
        )
        power_profile_lineage_matches = (
            power_profile.artifact.artifact_id
            == self.power_and_margin_memo.power_and_margin_memo_id
            and power_profile.artifact.sha256 == content_hash(self.power_and_margin_memo)
            and (
                power_profile.qualification_accept_data_id
                == self.power_and_margin_memo.qualification_accept_data_id
            )
            and (power_profile.code_commit == self.power_and_margin_memo.code_commit)
            and (
                self.qualification_bundle.data_role_manifest.artifact_id
                == self.power_and_margin_memo.data_role_manifest_id
            )
            and (
                self.qualification_bundle.qualification_accept_data_id
                == self.power_and_margin_memo.qualification_accept_data_id
            )
        )
        baseline_profile = next(
            (
                profile
                for profile in self.qualification_bundle.profiles
                if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
            )
        )
        baseline_profile_lineage_matches = (
            self.baseline_qualification.scenario is self.scenario
            and self.baseline_qualification.model_ids == self.dimensions.model_ids
            and (
                baseline_profile.selected_profile_id
                == self.baseline_qualification.selected_profile_id
            )
            and (
                baseline_profile.artifact.artifact_id
                == self.baseline_qualification.rq1_baseline_qualification_id
            )
            and (baseline_profile.artifact.sha256 == content_hash(self.baseline_qualification))
            and (
                baseline_profile.qualification_accept_data_id
                == self.baseline_qualification.qualification_accept_data_id
            )
            and (baseline_profile.code_commit == self.baseline_qualification.code_commit)
            and (
                self.qualification_bundle.qualification_accept_data_id
                == self.baseline_qualification.qualification_accept_data_id
            )
        )
        passing = (
            not self.blockers
            and self.power_and_margin_memo.formal_use_authorized
            and self.qualification_bundle.formal_use_authorized
            and self.baseline_qualification.formal_use_authorized
            and power_profile_lineage_matches
            and baseline_profile_lineage_matches
            and (self.independent_verifier_status == "PASS")
        )
        if self.status is QualificationStatus.ACCEPTED and (not passing):
            raise ValueError("ACCEPTED RQ1 budget requires every qualification Gate")
        if self.status is QualificationStatus.BLOCKED and passing:
            raise ValueError("a fully passing RQ1 budget cannot remain BLOCKED")

    @property
    def provider_calls_authorized(self) -> bool:
        return self.status is QualificationStatus.ACCEPTED

    @property
    def rq1_budget_qualification_id(self) -> str:
        return content_id("rq1_budget_qualification_", self)


def qualify_rq1_budget(
    *,
    scenario: RQ1BudgetScenario,
    dimensions: RQ1BudgetDimensions,
    power_and_margin_memo: PowerAndMarginMemo,
    qualification_bundle: QualificationBundle,
    baseline_qualification: RQ1BaselineQualification,
    provider_ceilings: ProviderBudgetCeilings,
    independent_verifier_status: str,
) -> RQ1BudgetQualification:
    """Evaluate the joint power, family-size, dispatch, calls, and cost Gate."""
    if type(scenario) is not RQ1BudgetScenario:
        raise TypeError("budget scenario must be typed")
    if type(baseline_qualification) is not RQ1BaselineQualification:
        raise TypeError("budget requires an RQ1BaselineQualification")
    reservation = _budget_reservation(dimensions, scenario, provider_ceilings)
    blockers = set()
    if not power_and_margin_memo.formal_use_authorized:
        blockers.add("power_and_margin_not_accepted")
    if not qualification_bundle.formal_use_authorized:
        blockers.add("integrated_qualification_not_accepted")
    if not baseline_qualification.formal_use_authorized:
        blockers.add("rq1_baseline_qualification_not_accepted")
    if not (
        baseline_qualification.protocol_id == power_and_margin_memo.protocol_id
        and baseline_qualification.scenario is scenario
        and (baseline_qualification.model_ids == dimensions.model_ids)
    ):
        blockers.add("baseline_qualification_scope_mismatch")
    power_profile = next(
        (
            profile
            for profile in qualification_bundle.profiles
            if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
        )
    )
    if not (
        power_profile.artifact.artifact_id == power_and_margin_memo.power_and_margin_memo_id
        and power_profile.artifact.sha256 == content_hash(power_and_margin_memo)
        and (
            power_profile.qualification_accept_data_id
            == power_and_margin_memo.qualification_accept_data_id
        )
        and (power_profile.code_commit == power_and_margin_memo.code_commit)
        and (
            qualification_bundle.data_role_manifest.artifact_id
            == power_and_margin_memo.data_role_manifest_id
        )
        and (
            qualification_bundle.qualification_accept_data_id
            == power_and_margin_memo.qualification_accept_data_id
        )
    ):
        blockers.add("power_profile_lineage_mismatch")
    baseline_profile = next(
        (
            profile
            for profile in qualification_bundle.profiles
            if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
        )
    )
    if not (
        baseline_profile.selected_profile_id == baseline_qualification.selected_profile_id
        and baseline_profile.artifact.artifact_id
        == baseline_qualification.rq1_baseline_qualification_id
        and (baseline_profile.artifact.sha256 == content_hash(baseline_qualification))
        and (
            baseline_profile.qualification_accept_data_id
            == baseline_qualification.qualification_accept_data_id
        )
        and (baseline_profile.code_commit == baseline_qualification.code_commit)
        and (
            qualification_bundle.qualification_accept_data_id
            == baseline_qualification.qualification_accept_data_id
        )
    ):
        blockers.add("baseline_profile_lineage_mismatch")
    if independent_verifier_status != "PASS":
        blockers.add("independent_budget_verifier_failed")
    atomic_plan = power_and_margin_memo.atomic_power.plan
    for plan, family_bound, task_units, realizations, slots, prefix in (
        (
            atomic_plan,
            reservation.atomic_effect_record_upper_bound,
            dimensions.atomic_task_units_per_effect,
            dimensions.atomic_global_realizations,
            dimensions.atomic_total_block_slots,
            "atomic",
        ),
    ):
        if plan.family_size_upper_bound != family_bound:
            blockers.add(f"{prefix}_family_size_mismatch")
        if plan.task_units_per_effect != task_units:
            blockers.add(f"{prefix}_task_count_mismatch")
        if plan.global_realizations != realizations:
            blockers.add(f"{prefix}_realization_count_mismatch")
        if plan.total_block_slots != slots:
            blockers.add(f"{prefix}_block_slot_mismatch")
    ceilings = provider_ceilings
    for actual, limit, reason in (
        (
            reservation.materialization_call_upper_bound,
            ceilings.materialization_call_ceiling,
            "materialization_call_ceiling_exceeded",
        ),
        (
            reservation.generation_call_upper_bound,
            ceilings.generation_call_ceiling,
            "generation_call_ceiling_exceeded",
        ),
        (
            reservation.functional_judge_call_upper_bound,
            ceilings.functional_judge_call_ceiling,
            "functional_judge_call_ceiling_exceeded",
        ),
        (
            reservation.external_call_upper_bound,
            ceilings.external_call_ceiling,
            "external_call_ceiling_exceeded",
        ),
        (
            reservation.external_cost_upper_bound_microunits,
            ceilings.external_cost_ceiling_microunits,
            "external_cost_ceiling_exceeded",
        ),
    ):
        if actual > limit:
            blockers.add(reason)
    frozen_blockers = tuple(sorted(blockers))
    accepted = not frozen_blockers
    atomic_selectors = _scenario_selector_ids(scenario)
    return RQ1BudgetQualification(
        power_and_margin_memo.protocol_id,
        scenario,
        dimensions,
        atomic_selectors,
        power_and_margin_memo,
        qualification_bundle,
        baseline_qualification,
        provider_ceilings,
        reservation,
        QualificationStatus.ACCEPTED if accepted else QualificationStatus.BLOCKED,
        frozen_blockers,
        independent_verifier_status,
    )


def _require_canonical_texts(values: tuple[str, ...], name: str) -> None:
    if not values:
        raise ValueError(f"{name} cannot be empty")
    _require_optional_canonical_texts(values, name)


def _require_optional_canonical_texts(values: tuple[str, ...], name: str) -> None:
    for value in values:
        require_text(value, name)
    require_unique(values, name)
    if tuple(sorted(values)) != values:
        raise ValueError(f"{name} must use canonical order")


def _require_git_commit(value: str) -> None:
    require_text(value, "code_commit")
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("code_commit must be a full lowercase Git object ID")


def _order_key(seed: int, *values: str) -> str:
    return hashlib.sha256("|".join((str(seed), *values)).encode()).hexdigest()


__all__ = [
    "ATOMIC_POWER_ARMS",
    "FreezeArtifactReference",
    "PowerAndMarginMemo",
    "ProviderBudgetCeilings",
    "ProviderCallKind",
    "ProviderRate",
    "ProviderTokenCostBasis",
    "QualificationBundle",
    "QualificationPlan",
    "QualificationPlanBundle",
    "QualificationPlanPhase",
    "QualificationProfileKind",
    "QualificationProfileResult",
    "QualificationStatus",
    "RQ1BaselineQualification",
    "RQ1BudgetDimensions",
    "RQ1BudgetQualification",
    "RQ1BudgetReservation",
    "RQ1BudgetScenario",
    "StudyDesignError",
    "TargetPowerAssumption",
    "TargetPowerScenarioResult",
    "TargetPowerSimulationPlan",
    "TargetPowerSimulationResult",
    "bind_target_power_to_assignments",
    "freeze_power_and_margin_memo",
    "freeze_qualification_bundle",
    "qualification_plan_bundle",
    "qualify_rq1_baselines",
    "qualify_rq1_budget",
    "rq1_worst_case_budget_envelopes",
    "simulate_target_power",
]

"""Outcome-blind sampling and power freeze for the paper-facing study."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from statistics import NormalDist
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    require_sha256,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique
from prompt_mechanism_study.prioritization import (
    BridgeStatus,
    ConfirmationDispatchManifest,
    DiscoveryPopulationLineage,
    FixedSlotLedger,
    PolicyTrack,
    SharedConfirmationUnion,
)
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
    RELATION = "relation"
    PAIR_RD = "pair_rd"
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
    pair_discovery_population_sha256: str
    identity_and_scope_decision: FreezeArtifactReference
    candidate_universe_contract: FreezeArtifactReference
    support_gate_contract: FreezeArtifactReference
    discoverability_contract: FreezeArtifactReference
    candidate_fold_manifests: FreezeArtifactReference
    selector_contract: FreezeArtifactReference
    rq1_budget_qualification: FreezeArtifactReference
    discovery_outcome_contract: FreezeArtifactReference
    atomic_top_k: int
    pair_top_k: int
    model_ids: tuple[str, ...]
    rq1_baseline_ids: tuple[str, ...] = ()
    rq1_budget_scenario: RQ1BudgetScenario = RQ1BudgetScenario.CORE
    atomic_selector_ids: tuple[str, ...] = ("atomic_full", "atomic_rd_only")
    pair_selector_ids: tuple[str, ...] = ("pair_full", "pair_no_relation")
    model_dispatch_policy: str = "model_bound_effect_coordinate"
    rq2_comparison_semantics: str = (
        "descriptive_fixed_denominator_full_minus_ablation_no_interval"
    )
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
            raise TypeError(
                "discovery_population_lineage must be a DiscoveryPopulationLineage"
            )
        if (
            self.discovery_population_lineage.accepted_population_manifest_sha256
            != self.discovery_population_sha256
        ):
            raise ValueError("Discovery population lineage drifted inside the freeze")
        require_sha256(
            self.discovery_population_sha256,
            "Discovery population sha256",
        )
        for value, name in (
            (self.atomic_discovery_population_sha256, "Atomic Discovery population"),
            (self.pair_discovery_population_sha256, "Pair Discovery population"),
        ):
            require_sha256(value, name)
            if value != self.discovery_population_sha256:
                raise ValueError(f"{name} drifted from the accepted population")
        for value, name in (
            (self.atomic_top_k, "atomic_top_k"),
            (self.pair_top_k, "pair_top_k"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        _require_canonical_texts(self.model_ids, "model_ids")
        _require_optional_canonical_texts(self.rq1_baseline_ids, "rq1_baseline_ids")
        if type(self.rq1_budget_scenario) is not RQ1BudgetScenario:
            raise TypeError("discovery RQ1 budget scenario must be typed")
        expected_atomic, expected_pair = _scenario_selector_ids(
            self.rq1_budget_scenario
        )
        if self.atomic_selector_ids != expected_atomic:
            raise ValueError("Atomic selectors do not match the frozen RQ1 scenario")
        if self.pair_selector_ids != expected_pair:
            raise ValueError("Pair selectors do not match the frozen RQ1 scenario")
        core = {
            "atomic_full",
            "atomic_rd_only",
            "pair_full",
            "pair_no_relation",
        }
        expected_baselines = tuple(
            sorted(set((*expected_atomic, *expected_pair)) - core)
        )
        if self.rq1_baseline_ids != expected_baselines:
            raise ValueError("RQ1 baseline IDs do not match the frozen scenario")
        if self.model_dispatch_policy != "model_bound_effect_coordinate":
            raise ValueError("discovery records must use model-bound dispatch")
        if self.rq2_comparison_semantics != (
            "descriptive_fixed_denominator_full_minus_ablation_no_interval"
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


ATOMIC_POWER_ARMS = (
    "atomic_target",
    "atomic_noop",
    "atomic_placebo",
    "atomic_generic",
)
PAIR_POWER_ARMS = ("pair_00", "pair_10", "pair_01", "pair_11")


@dataclass(frozen=True, slots=True)
class TargetPowerAssumption:
    """One outcome-blind planning scenario for a target ITT family."""

    scenario_id: str
    track: PolicyTrack
    arm_secure_yield_probabilities: tuple[tuple[str, float], ...]
    within_arm_request_icc: float
    cross_arm_task_correlation: float
    realization_effect_sd: float
    family_coordinate_correlation: float
    oracle_unknown_rate: float
    terminal_no_code_rate: float
    target_confirmation_outcomes_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "power scenario_id")
        if type(self.track) is not PolicyTrack:
            raise TypeError("power assumption track must be typed")
        expected = ATOMIC_POWER_ARMS if self.track is PolicyTrack.ATOMIC else PAIR_POWER_ARMS
        if tuple(name for name, _ in self.arm_secure_yield_probabilities) != expected:
            raise ValueError("power assumption must provide the canonical four-arm probabilities")
        for _, value in self.arm_secure_yield_probabilities:
            if type(value) is not float or not 0 <= value <= 1:
                raise ValueError("secure-yield probabilities must be floats on [0, 1]")
        for value, name in (
            (self.within_arm_request_icc, "within-arm request ICC"),
            (self.cross_arm_task_correlation, "cross-arm task correlation"),
            (self.family_coordinate_correlation, "family-coordinate correlation"),
            (self.oracle_unknown_rate, "Oracle unknown rate"),
            (self.terminal_no_code_rate, "terminal no-code rate"),
        ):
            if type(value) is not float or not 0 <= value < 1:
                raise ValueError(f"{name} must be a float on [0, 1)")
        if (
            type(self.realization_effect_sd) is not float
            or not 0 <= self.realization_effect_sd <= 1
        ):
            raise ValueError("realization-effect SD must be a float on [0, 1]")
        if self.oracle_unknown_rate + self.terminal_no_code_rate > 1:
            raise ValueError("unknown and no-code planning rates cannot exceed one")
        maximum_secure_yield = 1 - self.oracle_unknown_rate - self.terminal_no_code_rate
        if any(value > maximum_secure_yield for _, value in self.arm_secure_yield_probabilities):
            raise ValueError(
                "secure-yield probability cannot exceed evaluable generated-code availability"
            )
        if self.target_confirmation_outcomes_used is not False:
            raise ValueError("power planning cannot read target confirmation outcomes")

    @property
    def effect(self) -> float:
        values = dict(self.arm_secure_yield_probabilities)
        if self.track is PolicyTrack.ATOMIC:
            return values["atomic_target"] - values["atomic_noop"]
        return (
            values["pair_11"]
            - values["pair_10"]
            - values["pair_01"]
            + values["pair_00"]
        )


@dataclass(frozen=True, slots=True)
class TargetPowerSimulationPlan:
    """Frozen assumption grid for one Atomic or Pair max-|T| family."""

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
    multiplicity_method: str = "family_max_abs_t"
    resampling_unit: str = "task_unit"
    independent_task_priority: bool = True

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("power plan track must be typed")
        if type(self.practical_margin) is not float or not 0 <= self.practical_margin <= 1:
            raise ValueError("practical margin must be a float on [0, 1]")
        for value, name in (
            (self.family_size_upper_bound, "family_size_upper_bound"),
            (self.task_units_per_effect, "task_units_per_effect"),
            (self.global_realizations, "global_realizations"),
            (
                self.minimum_task_units_per_realization,
                "minimum_task_units_per_realization",
            ),
            (
                self.minimum_task_units_per_stratum,
                "minimum_task_units_per_stratum",
            ),
            (self.total_block_slots, "total_block_slots"),
            (self.simulation_replicates, "simulation_replicates"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.total_block_slots % 4:
            raise ValueError("power total_block_slots must contain complete four-arm blocks")
        if self.task_units_per_effect < (
            self.global_realizations * self.minimum_task_units_per_realization
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
            type(item) is not TargetPowerAssumption for item in self.assumptions
        ):
            raise TypeError("power plan needs typed planning assumptions")
        if tuple(item.scenario_id for item in self.assumptions) != tuple(
            sorted({item.scenario_id for item in self.assumptions})
        ):
            raise ValueError("power assumptions must have unique canonical scenario IDs")
        if any(item.track is not self.track for item in self.assumptions):
            raise ValueError("power assumptions cannot cross Atomic and Pair tracks")
        if self.multiplicity_method != "family_max_abs_t":
            raise ValueError("target power must use the frozen max-|T| family")
        if self.resampling_unit != "task_unit":
            raise ValueError("target power must use the task unit")
        if self.independent_task_priority is not True:
            raise ValueError("independent task units must precede extra request slots")

    @property
    def power_simulation_plan_id(self) -> str:
        return content_id("target_power_simulation_plan_", self)


@dataclass(frozen=True, slots=True)
class TargetPowerScenarioResult:
    scenario_id: str
    effect: float
    task_unit_standard_error: float
    simultaneous_critical_value: float
    achieved_power: float
    monte_carlo_half_width_95: float

    def __post_init__(self) -> None:
        require_text(self.scenario_id, "power result scenario_id")
        for value, name in (
            (self.effect, "power effect"),
            (self.task_unit_standard_error, "power standard error"),
            (self.simultaneous_critical_value, "power critical value"),
            (self.achieved_power, "achieved power"),
            (self.monte_carlo_half_width_95, "power Monte Carlo half-width"),
        ):
            if type(value) is not float or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite float")
        if self.task_unit_standard_error <= 0 or self.simultaneous_critical_value <= 0:
            raise ValueError("power standard error and critical value must be positive")
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


def simulate_target_power(
    plan: TargetPowerSimulationPlan,
) -> TargetPowerSimulationResult:
    """Run a deterministic assumption-conditional max-|T| planning simulation."""

    if type(plan) is not TargetPowerSimulationPlan:
        raise TypeError("power simulation requires a TargetPowerSimulationPlan")
    results = []
    for assumption in plan.assumptions:
        probabilities = dict(assumption.arm_secure_yield_probabilities)
        names = ATOMIC_POWER_ARMS if plan.track is PolicyTrack.ATOMIC else PAIR_POWER_ARMS
        selected_names = names[:2] if plan.track is PolicyTrack.ATOMIC else names
        signs = (-1.0, 1.0) if plan.track is PolicyTrack.ATOMIC else (1.0, -1.0, -1.0, 1.0)
        if plan.track is PolicyTrack.ATOMIC:
            selected_names = ("atomic_noop", "atomic_target")
        slots_per_arm = plan.total_block_slots // 4
        arm_variances = {
            name: probabilities[name]
            * (1 - probabilities[name])
            * (
                assumption.within_arm_request_icc
                + (1 - assumption.within_arm_request_icc) / slots_per_arm
            )
            for name in selected_names
        }
        contribution_variance = sum(arm_variances.values())
        for left_index, left_name in enumerate(selected_names):
            for right_index in range(left_index + 1, len(selected_names)):
                right_name = selected_names[right_index]
                covariance = assumption.cross_arm_task_correlation * math.sqrt(
                    arm_variances[left_name] * arm_variances[right_name]
                )
                contribution_variance += (
                    2 * signs[left_index] * signs[right_index] * covariance
                )
        contribution_variance += assumption.realization_effect_sd**2
        if contribution_variance <= 0:
            raise StudyDesignError("power scenario has zero or invalid contribution variance")
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
        maxima = []
        shared_weight = math.sqrt(assumption.family_coordinate_correlation)
        independent_weight = math.sqrt(1 - assumption.family_coordinate_correlation)
        for _ in range(plan.simulation_replicates):
            shared = rng.gauss(0, 1)
            maxima.append(
                max(
                    abs(shared_weight * shared + independent_weight * rng.gauss(0, 1))
                    for _coordinate in range(plan.family_size_upper_bound)
                )
            )
        maxima.sort()
        critical_index = min(
            len(maxima) - 1,
            max(0, math.ceil((1 - plan.alpha) * len(maxima)) - 1),
        )
        critical = maxima[critical_index]
        meaningful = 0
        for _ in range(plan.simulation_replicates):
            estimate = assumption.effect + standard_error * rng.gauss(0, 1)
            lower = estimate - critical * standard_error
            upper = estimate + critical * standard_error
            meaningful += lower > plan.practical_margin or upper < -plan.practical_margin
        power = meaningful / plan.simulation_replicates
        half_width = 1.96 * math.sqrt(
            power * (1 - power) / plan.simulation_replicates
        )
        results.append(
            TargetPowerScenarioResult(
                assumption.scenario_id,
                float(assumption.effect),
                float(standard_error),
                float(critical),
                float(power),
                float(half_width),
            )
        )
    frozen = tuple(results)
    minimum = min(item.achieved_power for item in frozen)
    return TargetPowerSimulationResult(
        plan,
        frozen,
        minimum,
        minimum >= plan.target_power,
    )


@dataclass(frozen=True, slots=True)
class PowerAndMarginMemo:
    """Qualification artifact that alone may authorize target inference parameters."""

    protocol_id: str
    data_role_manifest_id: str
    qualification_accept_data_id: str
    code_commit: str
    atomic_power: TargetPowerSimulationResult
    pair_power: TargetPowerSimulationResult
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
        require_text(
            self.qualification_accept_data_id,
            "power memo qualification_accept_data_id",
        )
        _require_git_commit(self.code_commit)
        if (
            type(self.atomic_power) is not TargetPowerSimulationResult
            or self.atomic_power.plan.track is not PolicyTrack.ATOMIC
            or type(self.pair_power) is not TargetPowerSimulationResult
            or self.pair_power.plan.track is not PolicyTrack.PAIR
        ):
            raise TypeError("power memo requires one Atomic and one Pair result")
        if self.atomic_power.plan.alpha != self.pair_power.plan.alpha:
            raise ValueError("Atomic and Pair primary families must share frozen alpha")
        if (
            self.atomic_power.plan.minimum_task_units_per_stratum
            != self.pair_power.plan.minimum_task_units_per_stratum
        ):
            raise ValueError("Atomic and Pair inference must share the stratum minimum")
        if type(self.bootstrap_draws) is not int or self.bootstrap_draws < 100:
            raise ValueError("inference bootstrap draws must be at least 100")
        if type(self.bootstrap_seed) is not int:
            raise TypeError("inference bootstrap seed must be an integer")
        if (
            type(self.minimum_valid_bootstrap_fraction) is not float
            or not 0 < self.minimum_valid_bootstrap_fraction <= 1
        ):
            raise ValueError(
                "minimum valid bootstrap fraction must be a float in (0, 1]"
            )
        if (
            type(self.maximum_unknown_fraction_among_valid) is not float
            or not 0 <= self.maximum_unknown_fraction_among_valid <= 1
        ):
            raise ValueError(
                "maximum unknown fraction among valid code must be a float on [0, 1]"
            )
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
        passed = (
            self.atomic_power.power_gate_passed
            and self.pair_power.power_gate_passed
            and self.independent_verifier_status == "PASS"
        )
        if self.status is QualificationStatus.ACCEPTED and not passed:
            raise ValueError("ACCEPTED power memo requires both power Gates and verifier PASS")
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
            self.pair_power.plan.practical_margin,
            self.maximum_unknown_fraction_among_valid,
        )


def freeze_power_and_margin_memo(
    manifest: DataRoleManifest,
    *,
    code_commit: str,
    atomic_power: TargetPowerSimulationResult,
    pair_power: TargetPowerSimulationResult,
    bootstrap_draws: int,
    bootstrap_seed: int,
    minimum_valid_bootstrap_fraction: float,
    maximum_unknown_fraction_among_valid: float,
    independent_verifier_status: str,
) -> PowerAndMarginMemo:
    """Bind a passing or blocked memo to the one-shot QUAL_ACCEPT role."""

    if type(manifest) is not DataRoleManifest:
        raise TypeError("power memo requires a DataRoleManifest")
    manifest.require_dataset_role(
        manifest.qualification_accept_data_id,
        DataRole.QUAL_ACCEPT,
    )
    passed = (
        atomic_power.power_gate_passed
        and pair_power.power_gate_passed
        and independent_verifier_status == "PASS"
    )
    return PowerAndMarginMemo(
        manifest.protocol_id,
        manifest.data_role_manifest_id,
        manifest.qualification_accept_data_id,
        code_commit,
        atomic_power,
        pair_power,
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
    pair_top_k: int
    atomic_task_units_per_effect: int
    pair_task_units_per_effect: int
    atomic_global_realizations: int
    pair_global_realizations: int
    atomic_total_block_slots: int
    pair_total_block_slots: int
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
            "pair_top_k",
            "atomic_task_units_per_effect",
            "pair_task_units_per_effect",
            "atomic_global_realizations",
            "pair_global_realizations",
            "atomic_total_block_slots",
            "pair_total_block_slots",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            self.atomic_total_block_slots % 4 != 0
            or self.pair_total_block_slots % 4 != 0
        ):
            raise ValueError("total block slots must be positive multiples of four")
        if self.realization_assignments_per_task != 1:
            raise ValueError("each task unit must be assigned exactly one realization")
        if self.model_dispatch_policy != "model_bound_effect_coordinate":
            raise ValueError("only model-bound effect-coordinate dispatch is permitted")
        if self.confirmation_cross_product_models is not False:
            raise ValueError(
                "model-bound candidate records cannot be crossed with all models again"
            )


def rq1_worst_case_budget_envelopes(
    dimensions: RQ1BudgetDimensions,
) -> dict[str, Any]:
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
        atomic_effect_records = (
            selector_variants_per_track
            * model_count
            * dimensions.atomic_top_k
        )
        pair_effect_records = (
            selector_variants_per_track
            * model_count
            * dimensions.pair_top_k
        )
        atomic_policy_bundles = (
            atomic_effect_records
            * dimensions.atomic_task_units_per_effect
        )
        pair_policy_bundles = (
            pair_effect_records
            * dimensions.pair_task_units_per_effect
        )
        generation_calls = (
            atomic_policy_bundles * dimensions.atomic_total_block_slots
            + pair_policy_bundles * dimensions.pair_total_block_slots
        )
        materialization_calls = 2 * (
            atomic_policy_bundles + pair_policy_bundles
        )
        maximum_external_calls = materialization_calls + 2 * generation_calls
        rows.append(
            {
                "scenario": scenario.value,
                "atomic_selector_variants": selector_variants_per_track,
                "pair_selector_variants": selector_variants_per_track,
                "atomic_effect_record_upper_bound": atomic_effect_records,
                "pair_effect_record_upper_bound": pair_effect_records,
                "generation_call_upper_bound": generation_calls,
                "materialization_call_upper_bound": materialization_calls,
                "functional_judge_call_upper_bound": generation_calls,
                "external_call_upper_bound": maximum_external_calls,
                "accidental_model_square_generation_calls": (
                    generation_calls * model_count
                ),
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
            "pair_top_k": dimensions.pair_top_k,
            "atomic_task_units_per_effect": (
                dimensions.atomic_task_units_per_effect
            ),
            "pair_task_units_per_effect": dimensions.pair_task_units_per_effect,
            "atomic_global_realizations": dimensions.atomic_global_realizations,
            "pair_global_realizations": dimensions.pair_global_realizations,
            "realization_assignments_per_task": 1,
            "atomic_total_block_slots": dimensions.atomic_total_block_slots,
            "pair_total_block_slots": dimensions.pair_total_block_slots,
        },
        "scenarios": rows,
    }
    report["budget_envelope_id"] = content_id("rq1_budget_envelope_", report)
    return report


def _scenario_selector_ids(
    scenario: RQ1BudgetScenario,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    atomic = ["atomic_full", "atomic_rd_only"]
    pair = ["pair_full", "pair_no_relation"]
    if scenario in {
        RQ1BudgetScenario.CORE_EXPERT,
        RQ1BudgetScenario.CORE_EXPERT_RANDOM,
    }:
        atomic.append("atomic_blind_expert")
        pair.append("pair_blind_expert")
    if scenario is RQ1BudgetScenario.CORE_EXPERT_RANDOM:
        atomic.append("atomic_seeded_random")
        pair.append("pair_seeded_random")
    return tuple(sorted(atomic)), tuple(sorted(pair))


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
        require_text(
            self.qualification_accept_data_id,
            "baseline qualification acceptance data",
        )
        _require_git_commit(self.code_commit)
        atomic, pair = _scenario_selector_ids(self.scenario)
        core = {
            "atomic_full",
            "atomic_rd_only",
            "pair_full",
            "pair_no_relation",
        }
        external = tuple(sorted(set((*atomic, *pair)) - core))
        expected_coordinates = tuple(
            sorted(
                (selector_id, model_id)
                for selector_id in external
                for model_id in self.model_ids
            )
        )
        actual_coordinates = tuple(
            (selector_id, model_id)
            for selector_id, model_id, _ in self.contract_references
        )
        if actual_coordinates != tuple(sorted(set(actual_coordinates))):
            raise ValueError("baseline qualification contracts must be canonical")
        if not set(actual_coordinates) <= set(expected_coordinates):
            raise ValueError("baseline qualification contains an unselected contract")
        if any(
            type(reference) is not FreezeArtifactReference
            for _, _, reference in self.contract_references
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
            and not self.blockers
            and self.independent_verifier_status == "PASS"
        )
        if self.status is QualificationStatus.ACCEPTED and not passing:
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
    frozen_references = tuple(
        sorted(contract_references, key=lambda item: (item[0], item[1]))
    )
    atomic, pair = _scenario_selector_ids(scenario)
    core = {
        "atomic_full",
        "atomic_rd_only",
        "pair_full",
        "pair_no_relation",
    }
    expected = {
        (selector_id, model_id)
        for selector_id in set((*atomic, *pair)) - core
        for model_id in frozen_models
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
        (
            QualificationStatus.ACCEPTED
            if not frozen_blockers
            else QualificationStatus.BLOCKED
        ),
        frozen_blockers,
        independent_verifier_status,
    )


@dataclass(frozen=True, slots=True)
class RQ1BudgetReservation:
    scenario: RQ1BudgetScenario
    atomic_effect_record_upper_bound: int
    pair_effect_record_upper_bound: int
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
            "pair_effect_record_upper_bound",
            "materialization_call_upper_bound",
            "generation_call_upper_bound",
            "functional_judge_call_upper_bound",
            "external_call_upper_bound",
            "external_cost_upper_bound_microunits",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.external_call_upper_bound != (
            self.materialization_call_upper_bound
            + self.generation_call_upper_bound
            + self.functional_judge_call_upper_bound
        ):
            raise ValueError("external-call reservation does not replay from its components")


def _budget_reservation(
    dimensions: RQ1BudgetDimensions,
    scenario: RQ1BudgetScenario,
    ceilings: ProviderBudgetCeilings,
) -> RQ1BudgetReservation:
    report = rq1_worst_case_budget_envelopes(dimensions)
    row = next(item for item in report["scenarios"] if item["scenario"] == scenario.value)
    costs = ceilings.unit_costs
    total_cost = (
        row["materialization_call_upper_bound"]
        * costs[ProviderCallKind.MATERIALIZATION]
        + row["generation_call_upper_bound"] * costs[ProviderCallKind.GENERATION]
        + row["functional_judge_call_upper_bound"]
        * costs[ProviderCallKind.FUNCTIONAL_JUDGE]
    )
    return RQ1BudgetReservation(
        scenario,
        row["atomic_effect_record_upper_bound"],
        row["pair_effect_record_upper_bound"],
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
    pair_selector_ids: tuple[str, ...]
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
        expected_atomic, expected_pair = _scenario_selector_ids(self.scenario)
        if self.atomic_selector_ids != expected_atomic or self.pair_selector_ids != expected_pair:
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
            self.dimensions,
            self.scenario,
            self.provider_ceilings,
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
        if self.protocol_id != self.power_and_margin_memo.protocol_id or (
            self.protocol_id != self.qualification_bundle.protocol_id
        ) or self.protocol_id != self.baseline_qualification.protocol_id:
            raise ValueError("RQ1 budget protocol lineage drift")
        power_profile = next(
            profile
            for profile in self.qualification_bundle.profiles
            if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
        )
        power_profile_lineage_matches = (
            power_profile.artifact.artifact_id
            == self.power_and_margin_memo.power_and_margin_memo_id
            and power_profile.artifact.sha256
            == content_hash(self.power_and_margin_memo)
            and power_profile.qualification_accept_data_id
            == self.power_and_margin_memo.qualification_accept_data_id
            and power_profile.code_commit == self.power_and_margin_memo.code_commit
            and self.qualification_bundle.data_role_manifest.artifact_id
            == self.power_and_margin_memo.data_role_manifest_id
            and self.qualification_bundle.qualification_accept_data_id
            == self.power_and_margin_memo.qualification_accept_data_id
        )
        baseline_profile = next(
            profile
            for profile in self.qualification_bundle.profiles
            if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
        )
        baseline_profile_lineage_matches = (
            self.baseline_qualification.scenario is self.scenario
            and self.baseline_qualification.model_ids == self.dimensions.model_ids
            and baseline_profile.selected_profile_id
            == self.baseline_qualification.selected_profile_id
            and baseline_profile.artifact.artifact_id
            == self.baseline_qualification.rq1_baseline_qualification_id
            and baseline_profile.artifact.sha256
            == content_hash(self.baseline_qualification)
            and baseline_profile.qualification_accept_data_id
            == self.baseline_qualification.qualification_accept_data_id
            and baseline_profile.code_commit == self.baseline_qualification.code_commit
            and self.qualification_bundle.qualification_accept_data_id
            == self.baseline_qualification.qualification_accept_data_id
        )
        passing = (
            not self.blockers
            and self.power_and_margin_memo.formal_use_authorized
            and self.qualification_bundle.formal_use_authorized
            and self.baseline_qualification.formal_use_authorized
            and power_profile_lineage_matches
            and baseline_profile_lineage_matches
            and self.independent_verifier_status == "PASS"
        )
        if self.status is QualificationStatus.ACCEPTED and not passing:
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
        and baseline_qualification.model_ids == dimensions.model_ids
    ):
        blockers.add("baseline_qualification_scope_mismatch")
    power_profile = next(
        profile
        for profile in qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.POWER_AND_MARGIN
    )
    if not (
        power_profile.artifact.artifact_id
        == power_and_margin_memo.power_and_margin_memo_id
        and power_profile.artifact.sha256 == content_hash(power_and_margin_memo)
        and power_profile.qualification_accept_data_id
        == power_and_margin_memo.qualification_accept_data_id
        and power_profile.code_commit == power_and_margin_memo.code_commit
        and qualification_bundle.data_role_manifest.artifact_id
        == power_and_margin_memo.data_role_manifest_id
        and qualification_bundle.qualification_accept_data_id
        == power_and_margin_memo.qualification_accept_data_id
    ):
        blockers.add("power_profile_lineage_mismatch")
    baseline_profile = next(
        profile
        for profile in qualification_bundle.profiles
        if profile.profile_kind is QualificationProfileKind.RQ1_BASELINES
    )
    if not (
        baseline_profile.selected_profile_id
        == baseline_qualification.selected_profile_id
        and baseline_profile.artifact.artifact_id
        == baseline_qualification.rq1_baseline_qualification_id
        and baseline_profile.artifact.sha256 == content_hash(baseline_qualification)
        and baseline_profile.qualification_accept_data_id
        == baseline_qualification.qualification_accept_data_id
        and baseline_profile.code_commit == baseline_qualification.code_commit
        and qualification_bundle.qualification_accept_data_id
        == baseline_qualification.qualification_accept_data_id
    ):
        blockers.add("baseline_profile_lineage_mismatch")
    if independent_verifier_status != "PASS":
        blockers.add("independent_budget_verifier_failed")
    atomic_plan = power_and_margin_memo.atomic_power.plan
    pair_plan = power_and_margin_memo.pair_power.plan
    for plan, family_bound, task_units, realizations, slots, prefix in (
        (
            atomic_plan,
            reservation.atomic_effect_record_upper_bound,
            dimensions.atomic_task_units_per_effect,
            dimensions.atomic_global_realizations,
            dimensions.atomic_total_block_slots,
            "atomic",
        ),
        (
            pair_plan,
            reservation.pair_effect_record_upper_bound,
            dimensions.pair_task_units_per_effect,
            dimensions.pair_global_realizations,
            dimensions.pair_total_block_slots,
            "pair",
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
    atomic_selectors, pair_selectors = _scenario_selector_ids(scenario)
    return RQ1BudgetQualification(
        power_and_margin_memo.protocol_id,
        scenario,
        dimensions,
        atomic_selectors,
        pair_selectors,
        power_and_margin_memo,
        qualification_bundle,
        baseline_qualification,
        provider_ceilings,
        reservation,
        QualificationStatus.ACCEPTED if accepted else QualificationStatus.BLOCKED,
        frozen_blockers,
        independent_verifier_status,
    )


@dataclass(frozen=True, slots=True)
class FormalBudgetPreflight:
    budget_qualification_id: str
    confirmation_dispatch_manifest_id: str
    assignment_manifest_sha256: str
    atomic_effect_records: int
    pair_effect_records: int
    materialization_calls: int
    generation_calls: int
    functional_judge_call_reservation: int
    external_call_reservation: int
    external_cost_reservation_microunits: int
    status: str = "PASS"
    provider_calls_authorized: bool = True

    def __post_init__(self) -> None:
        require_text(self.budget_qualification_id, "budget qualification ID")
        require_text(self.confirmation_dispatch_manifest_id, "dispatch manifest ID")
        require_sha256(self.assignment_manifest_sha256, "assignment manifest")
        for name in (
            "atomic_effect_records",
            "pair_effect_records",
            "materialization_calls",
            "generation_calls",
            "functional_judge_call_reservation",
            "external_call_reservation",
            "external_cost_reservation_microunits",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.external_call_reservation != (
            self.materialization_calls
            + self.generation_calls
            + self.functional_judge_call_reservation
        ):
            raise ValueError("formal external-call reservation does not replay")
        if self.status != "PASS" or self.provider_calls_authorized is not True:
            raise ValueError("only a passing preflight may authorize provider calls")

    @property
    def formal_budget_preflight_id(self) -> str:
        return content_id("formal_budget_preflight_", self)


def validate_formal_budget_preflight(
    budget: RQ1BudgetQualification,
    dispatch: ConfirmationDispatchManifest,
    assignments: Sequence[Any],
) -> FormalBudgetPreflight:
    """Fail before provider calls on lineage, model, block, count, call, or cost drift."""

    from prompt_mechanism_study.randomization import (
        ATOMIC_CONFIRMATORY_ARMS,
        PAIR_CONFIRMATORY_ARMS,
        AssignedArmITTRecord,
    )

    if type(budget) is not RQ1BudgetQualification or not budget.provider_calls_authorized:
        raise StudyDesignError("formal execution requires an ACCEPTED RQ1 budget")
    if type(dispatch) is not ConfirmationDispatchManifest:
        raise TypeError("formal preflight requires a ConfirmationDispatchManifest")
    frozen_assignments = tuple(assignments)
    if any(type(item) is not AssignedArmITTRecord for item in frozen_assignments):
        raise TypeError("formal preflight requires assigned-arm ITT records")
    assignment_ids = tuple(item.assignment_id for item in frozen_assignments)
    if len(set(assignment_ids)) != len(assignment_ids):
        raise StudyDesignError("formal assignment identities are not unique")
    record_by_id = {item.candidate_record_id: item for item in dispatch.records}
    track_by_id = {
        item.candidate_record_id: item.track for item in dispatch.union.entries
    }
    successful = {
        item.candidate_record_id: item
        for item in dispatch.records
        if item.status is BridgeStatus.SUCCESS
    }
    if any(item.candidate_record_id not in successful for item in frozen_assignments):
        raise StudyDesignError("assignment exists for a failed or unknown dispatch")
    by_candidate: dict[str, list[Any]] = defaultdict(list)
    for assignment in frozen_assignments:
        dispatch_record = record_by_id[assignment.candidate_record_id]
        if (
            assignment.effect_coordinate_id != dispatch_record.effect_coordinate_id
            or assignment.policy_key != dispatch_record.policy_key
            or assignment.model_id != dispatch_record.model_id
            or assignment.protocol_record_id != dispatch_record.protocol_record_id
            or assignment.track is not track_by_id[assignment.candidate_record_id]
        ):
            raise StudyDesignError("formal assignment drifted from model-bound dispatch")
        if assignment.model_id not in budget.dimensions.model_ids:
            raise StudyDesignError("formal assignment uses an unbudgeted model")
        by_candidate[assignment.candidate_record_id].append(assignment)
    if set(by_candidate) != set(successful):
        raise StudyDesignError("every successful dispatch needs its complete assignment block")

    for candidate_id, rows in by_candidate.items():
        track = track_by_id[candidate_id]
        planned_tasks = (
            budget.dimensions.atomic_task_units_per_effect
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_task_units_per_effect
        )
        planned_slots = (
            budget.dimensions.atomic_total_block_slots
            if track is PolicyTrack.ATOMIC
            else budget.dimensions.pair_total_block_slots
        )
        allowed_arms = (
            ATOMIC_CONFIRMATORY_ARMS
            if track is PolicyTrack.ATOMIC
            else PAIR_CONFIRMATORY_ARMS
        )
        task_ids = {item.task_unit_id for item in rows}
        if len(task_ids) != planned_tasks:
            raise StudyDesignError("formal task count drifted from the power/budget freeze")
        for task_unit_id in task_ids:
            block = [item for item in rows if item.task_unit_id == task_unit_id]
            if len(block) != planned_slots:
                raise StudyDesignError("formal task block has the wrong total slot count")
            if len({item.realization_id for item in block}) != 1:
                raise StudyDesignError("one task-policy coordinate has multiple realizations")
            if len({item.task_bundle_id for item in block}) != 1:
                raise StudyDesignError("one task-policy coordinate has multiple bundles")
            counts = Counter(item.arm for item in block)
            if set(counts) != set(allowed_arms) or len(set(counts.values())) != 1:
                raise StudyDesignError("formal task block is not balanced over all four arms")
            request_slots = {
                item.request_randomness_slot for item in block
            }
            if request_slots != set(range(planned_slots)):
                raise StudyDesignError(
                    "formal task block request-randomness slots are not unique and complete"
                )

    atomic_effects = sum(
        track_by_id[candidate_id] is PolicyTrack.ATOMIC for candidate_id in successful
    )
    pair_effects = sum(
        track_by_id[candidate_id] is PolicyTrack.PAIR for candidate_id in successful
    )
    reservation = budget.reservation
    if atomic_effects > reservation.atomic_effect_record_upper_bound or (
        pair_effects > reservation.pair_effect_record_upper_bound
    ):
        raise StudyDesignError("formal union exceeds the frozen effect-record reservation")
    generation_calls = len(frozen_assignments)
    materialization_calls = 2 * len(
        {item.task_bundle_id for item in frozen_assignments}
    )
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
    return FormalBudgetPreflight(
        budget.rq1_budget_qualification_id,
        dispatch.confirmation_dispatch_manifest_id,
        content_hash(tuple(sorted(frozen_assignments, key=lambda item: item.assignment_id))),
        atomic_effects,
        pair_effects,
        materialization_calls,
        generation_calls,
        functional_calls,
        external_calls,
        external_cost,
    )


def freeze_target_discovery_design(
    *,
    schema_version: str,
    manifest: DataRoleManifest,
    qualification_bundle: QualificationBundle,
    budget: RQ1BudgetQualification,
    population_lineage: DiscoveryPopulationLineage,
    atomic_discovery_population_sha256: str,
    pair_discovery_population_sha256: str,
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
    if (
        manifest.protocol_id != qualification_bundle.protocol_id
        or manifest.protocol_id != budget.protocol_id
        or qualification_bundle.data_role_manifest.artifact_id
        != manifest.data_role_manifest_id
        or qualification_bundle.data_role_manifest.sha256 != content_hash(manifest)
    ):
        raise StudyDesignError("target discovery data-role lineage drift")
    if (
        population_lineage.profile.protocol_id != manifest.protocol_id
        or population_lineage.accepted_population_manifest_sha256
        != manifest.discovery_population_sha256
        or population_lineage.pre_census.data_role_manifest_id
        != manifest.data_role_manifest_id
        or population_lineage.post_census.data_role_manifest_id
        != manifest.data_role_manifest_id
        or (
            population_lineage.receipt is not None
            and population_lineage.receipt.data_role_manifest_sha256
            != content_hash(manifest)
        )
        or atomic_discovery_population_sha256
        != population_lineage.accepted_population_manifest_sha256
        or pair_discovery_population_sha256
        != population_lineage.accepted_population_manifest_sha256
    ):
        raise StudyDesignError("target Discovery population lineage drift")
    dimensions = budget.dimensions
    atomic_selectors, pair_selectors = _scenario_selector_ids(budget.scenario)
    core = {
        "atomic_full",
        "atomic_rd_only",
        "pair_full",
        "pair_no_relation",
    }
    baselines = tuple(sorted(set((*atomic_selectors, *pair_selectors)) - core))
    return DiscoveryDesignFreeze(
        manifest.protocol_id,
        schema_version,
        FreezeArtifactReference(
            manifest.data_role_manifest_id,
            content_hash(manifest),
        ),
        FreezeArtifactReference(
            qualification_bundle.qualification_bundle_id,
            content_hash(qualification_bundle),
        ),
        population_lineage,
        population_lineage.accepted_population_manifest_sha256,
        atomic_discovery_population_sha256,
        pair_discovery_population_sha256,
        identity_and_scope_decision,
        candidate_universe_contract,
        support_gate_contract,
        discoverability_contract,
        candidate_fold_manifests,
        selector_contract,
        FreezeArtifactReference(
            budget.rq1_budget_qualification_id,
            content_hash(budget),
        ),
        discovery_outcome_contract,
        dimensions.atomic_top_k,
        dimensions.pair_top_k,
        dimensions.model_ids,
        baselines,
        budget.scenario,
        atomic_selectors,
        pair_selectors,
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
    if not frozen_task_bundles or any(
        type(item) is not TargetTaskBundle for item in frozen_task_bundles
    ):
        raise TypeError("target confirmation freeze requires typed task bundles")
    if type(preflight) is not FormalBudgetPreflight:
        raise TypeError("target confirmation freeze requires a budget preflight")
    if not budget.provider_calls_authorized:
        raise StudyDesignError("target confirmation requires an accepted RQ1 budget")
    expected_budget = FreezeArtifactReference(
        budget.rq1_budget_qualification_id,
        content_hash(budget),
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
    expected_top_k = (
        (PolicyTrack.ATOMIC, discovery.atomic_top_k),
        (PolicyTrack.PAIR, discovery.pair_top_k),
    )
    if ledger.top_k_by_track != expected_top_k:
        raise StudyDesignError("fixed-slot K drifted from the discovery freeze")
    expected_coordinates = {
        (track, model_id, selector_id)
        for track, selectors in (
            (PolicyTrack.ATOMIC, discovery.atomic_selector_ids),
            (PolicyTrack.PAIR, discovery.pair_selector_ids),
        )
        for model_id in discovery.model_ids
        for selector_id in selectors
    }
    actual_coordinates = {
        (source.track, source.model_id, source.selector_id)
        for source in ledger.sources
    }
    if actual_coordinates != expected_coordinates:
        raise StudyDesignError("fixed-slot selector/model coordinates drifted")
    if union.ledger != ledger or dispatch.union != union:
        raise StudyDesignError("confirmation union or dispatch drifted from fixed slots")
    frozen_assignments = tuple(
        sorted(assignments, key=lambda item: item.assignment_id)
    )
    if any(type(item) is not AssignedArmITTRecord for item in frozen_assignments):
        raise TypeError("target confirmation requires assigned-arm ITT records")
    if (
        randomization_plan.protocol_id != discovery.protocol_id
        or randomization_plan.schema_version != discovery.schema_version
        or randomization_plan.atomic_total_block_slots
        != budget.dimensions.atomic_total_block_slots
        or randomization_plan.pair_total_block_slots
        != budget.dimensions.pair_total_block_slots
    ):
        raise StudyDesignError("target randomization plan drifted from discovery or budget")
    if randomize_target_confirmation(
        dispatch,
        randomization_plan,
        frozen_task_bundles,
    ) != frozen_assignments:
        raise StudyDesignError("target assignments do not replay from the frozen randomization")
    replayed_preflight = validate_formal_budget_preflight(
        budget,
        dispatch,
        frozen_assignments,
    )
    if replayed_preflight != preflight:
        raise StudyDesignError("formal budget preflight does not replay")
    inference_plan = budget.power_and_margin_memo.target_itt_plan()
    dispatch_reference = FreezeArtifactReference(
        dispatch.confirmation_dispatch_manifest_id,
        content_hash(dispatch),
    )
    eligible_task_rows = tuple(
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
    return ConfirmationFreeze(
        discovery.protocol_id,
        discovery.schema_version,
        FreezeArtifactReference(
            discovery.discovery_design_freeze_id,
            content_hash(discovery),
        ),
        FreezeArtifactReference(
            ledger.fixed_slot_ledger_id,
            content_hash(ledger),
        ),
        FreezeArtifactReference(
            union.shared_confirmation_union_id,
            content_hash(union),
        ),
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
            content_id("eligible_task_units_", eligible_task_rows),
            content_hash(eligible_task_rows),
        ),
        FreezeArtifactReference(
            content_id("realization_allocation_", realization_rows),
            content_hash(realization_rows),
        ),
        FreezeArtifactReference(
            randomization_plan.target_randomization_plan_id,
            content_hash(randomization_plan),
        ),
        FreezeArtifactReference(
            content_id("assigned_arm_manifest_", frozen_assignments),
            content_hash(frozen_assignments),
        ),
        FreezeArtifactReference(
            preflight.formal_budget_preflight_id,
            content_hash(preflight),
        ),
        outcome_contract,
        FreezeArtifactReference(
            inference_plan.target_itt_plan_id,
            content_hash(inference_plan),
        ),
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




def freeze_study_design(
    repository_root: Path,
    eligibility_root: Path,
    task_units_root: Path,
    output: Path,
    *,
    seed: int = 2026082301,
    clusters_per_family: int = 15,
    minimum_detectable_effect: float = 0.20,
    discordant_pair_probability: float = 0.30,
    alpha: float = 0.05,
    target_power: float = 0.80,
    excluded_sample_paths: Sequence[Path] | None = None,
    included_families: Sequence[str] | None = None,
    family_quotas: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Freeze a balanced Python sample and a separate C/C++ readiness audit."""

    root = repository_root.resolve()
    eligibility = eligibility_root.resolve()
    units_root = task_units_root.resolve()
    destination = output.resolve()
    if destination.exists():
        raise StudyDesignError("study-design output already exists")
    verify_bundle(eligibility)
    verify_bundle(units_root)
    eligibility_report = read_json(eligibility / "report.json")
    units_report = read_json(units_root / "report.json")
    if (
        eligibility_report.get("generated_code_or_outcomes_used") is not False
        or units_report.get("experiment_outcomes_or_arms_used") is not False
    ):
        raise StudyDesignError("study-design inputs are not outcome blind")

    policy = read_json(root / "data/dataset-curation/eligibility-policy-v1.json")
    family_by_cwe = {
        cwe: family["family_id"] for family in policy["python_families"] for cwe in family["cwes"]
    }
    eligible_rows = read_json(eligibility / "eligible-clusters.json")
    eligible = {row["cluster_id"]: row for row in eligible_rows}
    units = read_json(units_root / "eligible-task-units.json")
    exclusions = read_json(units_root / "co-selection-exclusions.json")
    excluded_task_units = _excluded_task_units(excluded_sample_paths)
    candidates = [
        row
        for row in _python_candidates(eligible, units, family_by_cwe, seed)
        if row["task_unit_id"] not in excluded_task_units
    ]
    all_family_ids = [row["family_id"] for row in policy["python_families"]]
    family_ids = (
        list(family_quotas)
        if family_quotas
        else list(included_families)
        if included_families
        else all_family_ids
    )
    if (
        not family_ids
        or len(family_ids) != len(set(family_ids))
        or not set(family_ids) <= set(all_family_ids)
        or (
            family_quotas is not None
            and (
                set(family_quotas) != set(family_ids)
                or any(not isinstance(value, int) or value <= 0 for value in family_quotas.values())
            )
        )
    ):
        raise StudyDesignError("included mechanism families are invalid")
    targets = (
        dict(family_quotas)
        if family_quotas is not None
        else {family: clusters_per_family for family in family_ids}
    )
    sample = _balanced_sample(
        candidates,
        exclusions,
        family_ids,
        per_family=targets,
        seed=seed,
    )
    power = _power_design(
        len(sample),
        minimum_detectable_effect,
        discordant_pair_probability,
        alpha,
        target_power,
    )
    cpp_rows = [
        row
        for row in read_json(eligibility / "calibration-only-clusters.json")
        if row["reason"] == "replication_runtime_not_implemented"
    ]
    cpp = _cpp_readiness(cpp_rows, seed)
    extension_policy_path = (
        root / "data/dataset-curation/priority-extension-policy-v1.json"
    )
    extension_policy = read_json(extension_policy_path)
    priority_extensions = _priority_extensions(
        read_json(eligibility / "excluded-clusters.json"),
        extension_policy,
    )

    family_counts = Counter(row["family_id"] for row in sample)
    cwe_counts = Counter(row["primary_cwe"] for row in sample)
    lineage_counts = Counter(row["representative_lineage_family"] for row in sample)
    lineages_per_family = {
        family: len(
            {
                row["representative_lineage_family"]
                for row in sample
                if row["family_id"] == family
            }
        )
        for family in family_ids
    }
    report = {
        "schema_version": "1.0",
        "status": "OUTCOME_BLIND_STUDY_DESIGN_COMPLETE",
        "python": {
            "sample_clusters": len(sample),
            "sample_task_units": len({row["task_unit_id"] for row in sample}),
            "clusters_per_family": dict(sorted(family_counts.items())),
            "clusters_per_cwe": dict(sorted(cwe_counts.items())),
            "lineage_counts": dict(sorted(lineage_counts.items())),
            "lineages_per_family": dict(sorted(lineages_per_family.items())),
            "maximum_lineage_count": max(lineage_counts.values()),
            "observed_maximum_lineage_fraction": round(
                max(lineage_counts.values()) / len(sample), 6
            ),
            "lineage_policy": policy["lineage_policy"],
            "arms": ["target", "noop", "placebo", "generic"],
            "assignments_per_model": len(sample) * 4,
            "primary_contrast": "target_minus_noop",
            "power_gate_passed": power["power_gate_passed"],
        },
        "c_cpp_replication": {
            "candidate_clusters": len(cpp_rows),
            "shortlist_clusters": len(cpp["shortlist"]),
            "shortlist_with_source_tests": cpp["shortlist_with_source_tests"],
            "target_clusters": 28,
            "execution_gate_passed": cpp["execution_gate_passed"],
        },
        "priority_extensions": {
            "candidate_clusters": len(priority_extensions),
            "tier_counts": dict(
                sorted(Counter(row["priority_tier"] for row in priority_extensions).items())
            ),
            "language_counts": dict(
                sorted(Counter(row["language"] for row in priority_extensions).items())
            ),
            "current_formal_sample_eligible": False,
        },
        "eligibility_bundle_sha256": bundle_digest(eligibility),
        "task_units_bundle_sha256": bundle_digest(units_root),
        "eligibility_policy_sha256": _sha256(
            root / "data/dataset-curation/eligibility-policy-v1.json"
        ),
        "priority_extension_policy_sha256": _sha256(extension_policy_path),
        "study_design_implementation_sha256": _sha256(
            root / "src/prompt_mechanism_study/study_design.py"
        ),
        "selection_seed": seed,
        "excluded_exposed_task_units": len(excluded_task_units),
        "excluded_sample_sha256s": [
            _sha256(path) for path in (excluded_sample_paths or [])
        ],
        "included_families": family_ids,
        "family_quotas": targets,
        "omitted_families": [family for family in all_family_ids if family not in family_ids],
        "generated_code_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        "confirmatory_generation_authorized": False,
        "next_gate": "freeze interventions, generator identity, assignments, and pilot split",
    }
    write_bundle(
        destination,
        {
            "python-sample.json": sample,
            "power-design.json": power,
            "c-cpp-readiness.json": cpp,
            "priority-extension-candidates.json": priority_extensions,
            "report.json": report,
        },
    )
    return report


def _excluded_task_units(paths: Sequence[Path] | Path | None) -> set[str]:
    """Load prior JSON or JSONL samples as prospective exposure exclusions."""

    sources = [paths] if isinstance(paths, Path) else list(paths or [])
    task_units = []
    for path in sources:
        if path.suffix == ".jsonl":
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        else:
            rows = read_json(path)
        if not isinstance(rows, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("task_unit_id"), str)
            for row in rows
        ):
            raise StudyDesignError("excluded sample does not identify task units")
        task_units.extend(row["task_unit_id"] for row in rows)
    if len(task_units) != len(set(task_units)):
        raise StudyDesignError("excluded samples contain duplicate task units")
    return set(task_units)


def _python_candidates(
    eligible: dict[str, dict[str, Any]],
    units: list[dict[str, Any]],
    family_by_cwe: dict[str, str],
    seed: int,
) -> list[dict[str, Any]]:
    candidates = []
    for unit in units:
        rows = [eligible[cluster_id] for cluster_id in unit["cluster_ids"] if cluster_id in eligible]
        if not rows:
            continue
        families = {family_by_cwe[row["primary_cwe"]] for row in rows}
        if len(families) != 1:
            raise StudyDesignError("one task unit crosses Python mechanism families")
        representative = min(
            rows,
            key=lambda row: _order_key(seed, unit["task_unit_id"], row["cluster_id"]),
        )
        candidates.append(
            {
                "task_unit_id": unit["task_unit_id"],
                "cluster_id": representative["cluster_id"],
                "task_unit_cluster_ids": unit["cluster_ids"],
                "family_id": next(iter(families)),
                "primary_cwe": representative["primary_cwe"],
                "mechanism_realization_id": representative["mechanism_realization_id"],
                "oracle_profile_id": representative["oracle_profile_id"],
                "contract_id": representative["contract_id"],
                "representative_record_id": representative["representative_record_id"],
                "representative_source": representative["representative_source"],
                "representative_lineage_family": representative[
                    "representative_lineage_family"
                ],
                "source_test_available": representative["source_test_available"],
            }
        )
    return candidates


def _balanced_sample(
    candidates: list[dict[str, Any]],
    exclusions: list[dict[str, Any]],
    family_ids: list[str],
    *,
    per_family: int | Mapping[str, int],
    seed: int,
) -> list[dict[str, Any]]:
    targets = (
        {family: per_family for family in family_ids}
        if isinstance(per_family, int)
        else dict(per_family)
    )
    if set(targets) != set(family_ids) or any(value <= 0 for value in targets.values()):
        raise StudyDesignError("family sampling targets are invalid")
    conflicts = defaultdict(set)
    for row in exclusions:
        left, right = row["task_unit_ids"]
        conflicts[left].add(right)
        conflicts[right].add(left)
    remaining = {row["task_unit_id"]: row for row in candidates}
    selected = []
    selected_ids = set()
    family_counts: Counter[str] = Counter()
    family_cwes: dict[str, Counter[str]] = defaultdict(Counter)
    family_lineages: dict[str, Counter[str]] = defaultdict(Counter)
    lineage_counts: Counter[str] = Counter()
    while any(family_counts[family] < targets[family] for family in family_ids):
        progressed = False
        for family in family_ids:
            if family_counts[family] >= targets[family]:
                continue
            choices = [
                row
                for row in remaining.values()
                if row["family_id"] == family
                and not (conflicts[row["task_unit_id"]] & selected_ids)
            ]
            if not choices:
                raise StudyDesignError(f"cannot satisfy frozen sample constraints for {family}")
            chosen = min(
                choices,
                key=lambda row: (
                    family_cwes[family][row["primary_cwe"]],
                    family_lineages[family][row["representative_lineage_family"]],
                    lineage_counts[row["representative_lineage_family"]],
                    _order_key(seed, family, row["task_unit_id"]),
                ),
            )
            remaining.pop(chosen["task_unit_id"])
            selected_ids.add(chosen["task_unit_id"])
            family_counts[family] += 1
            family_cwes[family][chosen["primary_cwe"]] += 1
            lineage = chosen["representative_lineage_family"]
            family_lineages[family][lineage] += 1
            lineage_counts[lineage] += 1
            selected.append(chosen)
            progressed = True
        if not progressed:
            raise StudyDesignError("sample selection made no progress")
    result = []
    for index, row in enumerate(selected, start=1):
        core = {"sample_order": index, **row, "selection_seed": seed}
        result.append({"sample_id": content_id("python_sample_", core), **core})
    return result


def _power_design(
    task_units: int,
    effect: float,
    discordance: float,
    alpha: float,
    target_power: float,
) -> dict[str, Any]:
    if (
        task_units <= 0
        or not 0 < effect < 1
        or not 0 < discordance <= 1
        or not 0 < alpha < 1
    ):
        raise StudyDesignError("power assumptions are invalid")
    normal = NormalDist()
    critical = normal.inv_cdf(1 - alpha / 2)

    def power_at(value: float) -> float:
        noncentrality = effect / math.sqrt(value / task_units)
        return 1 - normal.cdf(critical - noncentrality) + normal.cdf(-critical - noncentrality)

    achieved = power_at(discordance)
    sensitivity = [
        {"discordant_pair_probability": value, "power": round(power_at(value), 6)}
        for value in (0.20, 0.25, 0.30, 0.35, 0.40)
    ]
    return {
        "schema_version": "1.0",
        "estimand": "paired_task_unit_weighted_target_minus_noop_itt",
        "outcome": "oracle_evaluable_secure_code_yield",
        "task_unit_count": task_units,
        "minimum_detectable_effect": effect,
        "discordant_pair_probability": discordance,
        "two_sided_alpha": alpha,
        "target_power": target_power,
        "achieved_normal_approximation_power": round(achieved, 6),
        "power_gate_passed": achieved >= target_power,
        "power_interpretation": "assumption_conditional_not_observed_effect_evidence",
        "discordance_assumption_basis": (
            "prospective planning assumption; sensitivity is reported and no sampled outcome "
            "was inspected"
        ),
        "family_effects": "preplanned_descriptive_heterogeneity",
        "sensitivity": sensitivity,
        "generated_code_or_outcomes_used": False,
    }


def _cpp_readiness(rows: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    cwes = ("CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-416", "CWE-476", "CWE-787")
    shortlist = []
    population = {}
    for cwe in cwes:
        candidates = [row for row in rows if row["primary_cwe"] == cwe]
        population[cwe] = {
            "candidate_clusters": len(candidates),
            "source_tests": sum(row["source_test_available"] for row in candidates),
            "lineages": len({row["representative_lineage_family"] for row in candidates}),
        }
        counts: Counter[str] = Counter()
        available = list(candidates)
        for _ in range(4):
            if not available:
                raise StudyDesignError(f"C/C++ replication lacks four candidates for {cwe}")
            chosen = min(
                available,
                key=lambda row: (
                    not row["source_test_available"],
                    counts[row["representative_lineage_family"]],
                    _order_key(seed, "c-cpp", cwe, row["cluster_id"]),
                ),
            )
            available.remove(chosen)
            counts[chosen["representative_lineage_family"]] += 1
            shortlist.append(
                {
                    "cluster_id": chosen["cluster_id"],
                    "cwe": cwe,
                    "language": chosen["language"],
                    "representative_record_id": chosen["representative_record_id"],
                    "representative_source": chosen["representative_source"],
                    "representative_lineage_family": chosen["representative_lineage_family"],
                    "contract_id": chosen["contract_id"],
                    "source_test_available": chosen["source_test_available"],
                }
            )
    tested = sum(row["source_test_available"] for row in shortlist)
    return {
        "schema_version": "1.0",
        "status": "C_CPP_REPLICATION_READINESS_AUDITED",
        "target_per_cwe": 4,
        "population_by_cwe": population,
        "shortlist": shortlist,
        "shortlist_with_source_tests": tested,
        "missing_frozen_functional_tests": len(shortlist) - tested,
        "required_runtime_components": [
            "C/C++ compiler and syntax gate",
            "frozen functional test for every shortlisted cluster",
            "task-applicable ASan, UBSan, or frozen exploit check",
            "isolated executable runner",
        ],
        "execution_gate_passed": tested == len(shortlist),
        "generated_code_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }


def _priority_extensions(
    rows: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    requirements = policy["common_requirements"]
    tiers = policy["tiers"]
    python_tier = tiers[0]
    cross_language_tier = tiers[1]
    family_by_cwe = {
        cwe: family
        for family, cwes in python_tier["families"].items()
        for cwe in cwes
    }
    candidates = []
    for row in rows:
        if (
            not row["source_test_available"]
            or not row["contract_id"]
            or row["requirement_count"] < requirements["minimum_requirements"]
            or row["source_test_reference_count"]
            < requirements["minimum_source_test_references"]
        ):
            continue
        family = family_by_cwe.get(row["primary_cwe"])
        if row["language"] == python_tier["language"] and family:
            tier = python_tier
        elif row["language"] in cross_language_tier["languages"]:
            tier = cross_language_tier
            family = None
        else:
            continue
        core = {
            "cluster_id": row["cluster_id"],
            "contract_id": row["contract_id"],
            "language": row["language"],
            "primary_cwe": row["primary_cwe"],
            "representative_record_id": row["representative_record_id"],
            "representative_source": row["representative_source"],
            "representative_lineage_family": row["representative_lineage_family"],
            "source_test_reference_count": row["source_test_reference_count"],
            "priority_tier": tier["tier_id"],
            "extension_family": family,
            "admission_blocker": tier["admission_blocker"],
            "current_formal_sample_eligible": False,
        }
        candidates.append(
            {"extension_candidate_id": content_id("extension_candidate_", core), **core}
        )
    counts = Counter(
        row["primary_cwe"]
        for row in candidates
        if row["priority_tier"] == python_tier["tier_id"]
    )
    if any(
        counts[cwe] < python_tier["minimum_candidates_per_cwe"]
        for cwe in family_by_cwe
    ):
        raise StudyDesignError("priority Python extension CWE lacks candidate support")
    return sorted(
        candidates,
        key=lambda row: (
            row["priority_tier"],
            row["language"],
            row["primary_cwe"],
            row["cluster_id"],
        ),
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "ATOMIC_POWER_ARMS",
    "ConfirmationFreeze",
    "DiscoveryDesignFreeze",
    "FormalBudgetPreflight",
    "FormalReportAuthorization",
    "FreezeArtifactReference",
    "PAIR_POWER_ARMS",
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
    "RQ1BudgetQualification",
    "RQ1BudgetDimensions",
    "RQ1BudgetReservation",
    "RQ1BudgetScenario",
    "StudyFreezeIndex",
    "StudyDesignError",
    "TargetPowerAssumption",
    "TargetPowerScenarioResult",
    "TargetPowerSimulationPlan",
    "TargetPowerSimulationResult",
    "freeze_study_design",
    "freeze_qualification_bundle",
    "freeze_power_and_margin_memo",
    "qualification_plan_bundle",
    "qualify_rq1_baselines",
    "qualify_rq1_budget",
    "rq1_worst_case_budget_envelopes",
    "simulate_target_power",
    "freeze_target_confirmation_design",
    "freeze_target_discovery_design",
    "freeze_target_study_index",
    "validate_formal_budget_preflight",
]

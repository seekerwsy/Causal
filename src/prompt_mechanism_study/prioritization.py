"""Outcome-blind discovery support, selector scores, and top-K slots."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    require_sha256 as _require_digest,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    catalog_sha256,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    query_context,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import (
    canonical_json,
    canonical_value,
    content_hash,
    content_id,
    require_text,
)
from prompt_mechanism_study.representation import (
    AtomicPolicyKey,
    Candidate,
    CandidateSkeletonV2,
    CandidateUniverse,
    ExpectedDirection,
    FrozenHypothesisV2,
    ModelBoundCandidateRecord,
    Operation,
)


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate_id: str
    score: float
    rank: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if type(self.score) not in {int, float} or not math.isfinite(float(self.score)):
            raise ValueError("score must be finite")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("rank must be positive")


@dataclass(frozen=True, slots=True)
class SelectionFreeze:
    universe_id: str
    selector_adapter_id: str
    top_k: int
    ranking: tuple[RankedCandidate, ...]

    def __post_init__(self) -> None:
        require_text(self.universe_id, "universe_id")
        require_text(self.selector_adapter_id, "selector_adapter_id")
        if type(self.top_k) is not int or not 1 <= self.top_k <= len(self.ranking):
            raise ValueError("top_k is outside the ranked candidate support")
        if tuple(item.rank for item in self.ranking) != tuple(range(1, len(self.ranking) + 1)):
            raise ValueError("ranking positions must be complete and canonical")
        if len({item.candidate_id for item in self.ranking}) != len(self.ranking):
            raise ValueError("ranking candidate ids must be unique")

    @property
    def selection_id(self) -> str:
        return content_id("selection_", self)

    @property
    def selected_candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.candidate_id for item in self.ranking[: self.top_k])


class SelectorKind(StrEnum):
    FCI = "tsg_fci"
    ASSOCIATION = "association"
    PREDICTION = "ridge_prediction"
    EXPERT = "blind_expert"
    RANDOM = "seeded_random"


class SelectorRunStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class SlotStatus(StrEnum):
    FILLED = "filled"
    SELECTOR_FAILED = "selector_failed"
    INSUFFICIENT_CANDIDATES = "insufficient_candidates"
    GATE_FAILED = "gate_failed"
    NON_EVALUABLE = "non_evaluable"


class BridgeStatus(StrEnum):
    SUCCESS = "success"
    BRIDGE_FAILED = "bridge_failed"
    PROTOCOLIZATION_FAILED = "protocolization_failed"


@dataclass(frozen=True, slots=True)
class DiscoveryObservation:
    """One frozen natural-Prompt discovery observation.

    Repeated request slots are permitted, but selectors use the lowest frozen
    slot per task unit as their reference analysis.  Confirmatory arms and
    outcomes have no field in this record.
    """

    task_unit_id: str
    model_id: str
    family_id: str
    request_randomness_slot: int
    candidate_states: tuple[tuple[str, int], ...]
    covariates: tuple[tuple[str, float], ...]
    outcome: int

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "task_unit_id")
        require_text(self.model_id, "model_id")
        require_text(self.family_id, "family_id")
        if type(self.request_randomness_slot) is not int or self.request_randomness_slot < 0:
            raise ValueError("request_randomness_slot must be a nonnegative integer")
        _validate_numeric_pairs(self.candidate_states, "candidate states", binary=True)
        _validate_numeric_pairs(self.covariates, "covariates", binary=False)
        if self.outcome not in {0, 1} or type(self.outcome) is not int:
            raise ValueError("discovery outcome must be binary")

    @property
    def observation_id(self) -> str:
        return content_id("discovery_observation_", self)


@dataclass(frozen=True, slots=True)
class CandidateUniverseManifest:
    """Shared immutable selector universe and its exact information budget."""

    source_universe_id: str
    candidate_ids: tuple[str, ...]
    supported_candidate_ids: tuple[str, ...]
    realization_policy_ids: tuple[tuple[str, str], ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    discovery_data_sha256: str
    positivity_audit_sha256: str
    information_budget_sha256: str
    outcome_id: str
    top_k: int
    representation_adapter_id: str
    candidate_skeletons: tuple[tuple[str, CandidateSkeletonV2], ...] = ()

    def __post_init__(self) -> None:
        require_text(self.source_universe_id, "source_universe_id")
        require_text(self.outcome_id, "outcome_id")
        _require_digest(self.discovery_data_sha256, "discovery data")
        _require_digest(self.positivity_audit_sha256, "positivity audit")
        _require_digest(self.information_budget_sha256, "information budget")
        _canonical_unique(self.candidate_ids, "candidate ids")
        _canonical_unique(self.supported_candidate_ids, "supported candidate ids")
        if not set(self.supported_candidate_ids) <= set(self.candidate_ids):
            raise ValueError("supported candidates must belong to the shared universe")
        if tuple(candidate for candidate, _ in self.realization_policy_ids) != self.candidate_ids:
            raise ValueError("realization-policy bindings must exactly follow candidate order")
        if tuple(candidate for candidate, _ in self.candidate_family_ids) != self.candidate_ids:
            raise ValueError("family bindings must exactly follow candidate order")
        if any(not isinstance(policy_id, str) or not policy_id.strip() for _, policy_id in self.realization_policy_ids):
            raise ValueError("realization-policy ids must be non-empty")
        if any(not isinstance(family_id, str) or not family_id.strip() for _, family_id in self.candidate_family_ids):
            raise ValueError("candidate family ids must be non-empty")
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("top_k must be positive")
        require_text(self.representation_adapter_id, "candidate representation adapter")
        if tuple(candidate_id for candidate_id, _ in self.candidate_skeletons) != self.candidate_ids:
            raise ValueError("candidate skeletons must exactly follow candidate order")
        policy_by_id = dict(self.realization_policy_ids)
        family_by_id = dict(self.candidate_family_ids)
        for candidate_id, skeleton in self.candidate_skeletons:
            if type(skeleton) is not CandidateSkeletonV2:
                raise TypeError("candidate skeletons must be typed")
            if (
                Candidate(
                    skeleton.candidate_key,
                    skeleton.context_query_id,
                    skeleton.actionable_feature_id,
                    skeleton.operation,
                    skeleton.cwe,
                    skeleton.outcome_id,
                    skeleton.expected_direction,
                ).candidate_id != candidate_id
                or skeleton.realization_policy_id != policy_by_id[candidate_id]
                or skeleton.archetype != family_by_id[candidate_id]
                or skeleton.outcome_id != self.outcome_id
            ):
                raise ValueError("candidate skeleton semantics drift from manifest bindings")
        projected = tuple(
            Candidate(
                skeleton.candidate_key, skeleton.context_query_id,
                skeleton.actionable_feature_id, skeleton.operation, skeleton.cwe,
                skeleton.outcome_id, skeleton.expected_direction,
            )
            for _, skeleton in self.candidate_skeletons
        )
        if CandidateUniverse(self.representation_adapter_id, projected).universe_id != self.source_universe_id:
            raise ValueError("candidate source universe does not recompute from frozen skeleton projections")

    @property
    def manifest_id(self) -> str:
        return content_id("candidate_universe_manifest_", self)

    @property
    def gate_passed(self) -> bool:
        return bool(self.supported_candidate_ids)


@dataclass(frozen=True, slots=True)
class BackgroundKnowledgeRule:
    rule_id: str
    scope_family_id: str
    bk_family_id: str
    provenance_class: str
    forbidden_from: str
    forbidden_to: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.rule_id, "BK rule_id"), (self.scope_family_id, "BK scope family"),
            (self.bk_family_id, "BK removal family"),
            (self.forbidden_from, "BK forbidden_from"),
            (self.forbidden_to, "BK forbidden_to"),
        ):
            require_text(value, name)
        if self.provenance_class not in {"temporal_order", "type_system", "reviewed_domain", "wrong_plausible"}:
            raise ValueError("BK provenance class is invalid")


@dataclass(frozen=True, slots=True)
class SelectorSuitePlan:
    model_id: str
    ridge_lambda: float
    prediction_folds: int
    random_seeds: tuple[int, ...]
    fci_alpha: float = 0.05
    fci_backend_version: str = "0.1.4.7"
    fci_ci_test: str = "gsq"
    fci_bootstrap_draws: int = 100
    fci_depth: int = -1
    fci_max_path_length: int = -1
    behavior_version: str = "shared-selector-suite-v1"
    fci_background_knowledge: tuple[BackgroundKnowledgeRule, ...] = ()
    fci_wrong_bk_perturbation: tuple[BackgroundKnowledgeRule, ...] = ()
    fci_minimum_valid_fraction: float = 0.8
    fci_adjacency_threshold: float = 0.5

    def __post_init__(self) -> None:
        require_text(self.model_id, "selector model_id")
        require_text(self.behavior_version, "selector behavior_version")
        if type(self.ridge_lambda) not in {int, float} or not math.isfinite(float(self.ridge_lambda)) or self.ridge_lambda <= 0:
            raise ValueError("ridge_lambda must be finite and positive")
        if type(self.prediction_folds) is not int or self.prediction_folds < 2:
            raise ValueError("prediction_folds must be at least two")
        if not self.random_seeds or len(set(self.random_seeds)) != len(self.random_seeds) or any(type(seed) is not int for seed in self.random_seeds):
            raise ValueError("random seeds must be a non-empty unique integer tuple")
        if type(self.fci_alpha) is not float or not 0.0 < self.fci_alpha < 1.0:
            raise ValueError("fci_alpha must be a float between zero and one")
        if self.fci_backend_version != "0.1.4.7" or self.fci_ci_test != "gsq":
            raise ValueError("selector FCI requires causal-learn 0.1.4.7 with G-square")
        if type(self.fci_bootstrap_draws) is not int or self.fci_bootstrap_draws < 100:
            raise ValueError("FCI bootstrap_draws must be at least 100")
        if type(self.fci_depth) is not int or self.fci_depth < -1:
            raise ValueError("FCI depth must be -1 or nonnegative")
        if type(self.fci_max_path_length) is not int or self.fci_max_path_length < -1:
            raise ValueError("FCI max_path_length must be -1 or nonnegative")
        if (
            type(self.fci_minimum_valid_fraction) is not float
            or not 0.0 < self.fci_minimum_valid_fraction <= 1.0
        ):
            raise ValueError("FCI minimum valid fraction must be in (0, 1]")
        if (
            type(self.fci_adjacency_threshold) is not float
            or not 0.0 <= self.fci_adjacency_threshold <= 1.0
        ):
            raise ValueError("FCI adjacency threshold must be in [0, 1]")
        rules = (*self.fci_background_knowledge, *self.fci_wrong_bk_perturbation)
        if len({item.rule_id for item in rules}) != len(rules):
            raise ValueError("FCI BK rule IDs must be unique")
        if any(item.provenance_class == "wrong_plausible" for item in self.fci_background_knowledge):
            raise ValueError("wrong-plausible BK cannot enter the primary full-BK run")
        if any(item.provenance_class != "wrong_plausible" for item in self.fci_wrong_bk_perturbation):
            raise ValueError("wrong-BK sensitivity rules must be explicitly typed")
        if any(
            item.forbidden_from != "Y:discovery_outcome"
            or not item.forbidden_to.startswith(("W:", "X:"))
            for item in self.fci_background_knowledge
            if item.provenance_class == "temporal_order"
        ):
            raise ValueError("temporal-order BK must only forbid Y pointing to W/X")
        primary_directions = {
            (item.scope_family_id, item.forbidden_from, item.forbidden_to)
            for item in self.fci_background_knowledge
        }
        if any(
            (item.scope_family_id, item.forbidden_from, item.forbidden_to)
            in primary_directions
            for item in self.fci_wrong_bk_perturbation
        ):
            raise ValueError("wrong-BK perturbation must change the full typed BK")

    @property
    def plan_id(self) -> str:
        return content_id("selector_suite_plan_", self)


@dataclass(frozen=True, slots=True)
class ExpertRankingInput:
    universe_manifest_id: str
    model_id: str
    candidate_card_sha256: str
    ranked_candidate_ids: tuple[str, ...]
    identity_blinded: bool
    confirm_outcomes_visible: bool

    def __post_init__(self) -> None:
        require_text(self.universe_manifest_id, "expert universe manifest")
        require_text(self.model_id, "expert model_id")
        _require_digest(self.candidate_card_sha256, "expert candidate card")
        _canonical_unique_members(self.ranked_candidate_ids, "expert ranking")
        if self.identity_blinded is not True or self.confirm_outcomes_visible is not False:
            raise ValueError("expert input must be identity-blinded and confirm-outcome blind")

    @property
    def input_id(self) -> str:
        return content_id("expert_ranking_input_", self)


@dataclass(frozen=True, slots=True)
class FrozenFCIRelationScores:
    """Externally computed FCI scores with an explicit immutable evidence identity."""

    universe_manifest_id: str
    selector_plan_id: str
    evidence_sha256: str
    scores: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        require_text(self.universe_manifest_id, "FCI score universe manifest")
        require_text(self.selector_plan_id, "FCI score selector plan")
        _require_digest(self.evidence_sha256, "FCI relation-score evidence")
        candidate_ids = tuple(candidate_id for candidate_id, _ in self.scores)
        _canonical_unique(candidate_ids, "FCI relation-score candidate ids")
        if any(type(score) not in {int, float} or not math.isfinite(float(score)) for _, score in self.scores):
            raise ValueError("FCI relation scores must be finite")

    @property
    def input_id(self) -> str:
        return content_id("frozen_fci_relation_scores_", self)


@dataclass(frozen=True, slots=True)
class SelectorFailure:
    reason_code: str
    detail: str
    candidate_id: str | None = None

    def __post_init__(self) -> None:
        require_text(self.reason_code, "selector failure code")
        require_text(self.detail, "selector failure detail")
        if self.candidate_id is not None:
            require_text(self.candidate_id, "selector failure candidate_id")


@dataclass(frozen=True, slots=True)
class SelectorSlot:
    rank: int
    status: SlotStatus
    candidate_id: str | None
    reason_code: str | None

    def __post_init__(self) -> None:
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("selector slot rank must be positive")
        if type(self.status) is not SlotStatus:
            raise TypeError("selector slot status must be a SlotStatus")
        if self.status is SlotStatus.FILLED:
            if self.candidate_id is None or self.reason_code is not None:
                raise ValueError("a filled selector slot requires only a candidate")
        elif self.candidate_id is not None or not self.reason_code:
            raise ValueError("an unfilled selector slot requires only a reason")


@dataclass(frozen=True, slots=True)
class SelectorRanking:
    label: str
    seed: int | None
    scores: tuple[RankedCandidate, ...]
    slots: tuple[SelectorSlot, ...]
    evidence_sha256: str

    def __post_init__(self) -> None:
        require_text(self.label, "selector ranking label")
        _require_digest(self.evidence_sha256, "selector ranking evidence")
        if self.seed is not None and type(self.seed) is not int:
            raise TypeError("ranking seed must be an integer or null")
        if tuple(item.rank for item in self.scores) != tuple(range(1, len(self.scores) + 1)):
            raise ValueError("selector scores must have canonical ranks")
        if len({item.candidate_id for item in self.scores}) != len(self.scores):
            raise ValueError("selector score candidates must be unique")
        if tuple(slot.rank for slot in self.slots) != tuple(range(1, len(self.slots) + 1)):
            raise ValueError("selector slots must be complete")
        filled = tuple(slot.candidate_id for slot in self.slots if slot.status is SlotStatus.FILLED)
        if filled != tuple(item.candidate_id for item in self.scores[: len(filled)]):
            raise ValueError("filled selector slots must follow the frozen ranking")

    @property
    def ranking_id(self) -> str:
        return content_id("selector_ranking_", self)


@dataclass(frozen=True, slots=True)
class SelectorRun:
    kind: SelectorKind
    selector_id: str
    model_id: str
    universe_manifest_id: str
    discovery_data_sha256: str
    plan_id: str
    status: SelectorRunStatus
    rankings: tuple[SelectorRanking, ...]
    failures: tuple[SelectorFailure, ...]

    def __post_init__(self) -> None:
        if type(self.kind) is not SelectorKind or type(self.status) is not SelectorRunStatus:
            raise TypeError("selector kind and status must be typed")
        for value, name in ((self.selector_id, "selector_id"), (self.model_id, "model_id"), (self.universe_manifest_id, "universe manifest"), (self.plan_id, "selector plan")):
            require_text(value, name)
        _require_digest(self.discovery_data_sha256, "selector discovery data")
        if self.status is SelectorRunStatus.COMPLETE and (not self.rankings or self.failures):
            raise ValueError("a complete selector run requires rankings without failures")
        if self.status is SelectorRunStatus.FAILED and (
            not self.rankings
            or not self.failures
            or any(
                slot.status is SlotStatus.FILLED
                for ranking in self.rankings
                for slot in ranking.slots
            )
        ):
            raise ValueError("a failed selector run requires explicit unfilled budget slots")
        if self.status is SelectorRunStatus.PARTIAL and (not self.rankings or not self.failures):
            raise ValueError("a partial selector run requires rankings and failures")

    @property
    def run_id(self) -> str:
        return content_id("selector_run_", self)


@dataclass(frozen=True, slots=True)
class SelectorSensitivityRanking:
    analysis: str
    replicate: str
    selector_id: str
    ranking_label: str
    ordered_candidate_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.analysis not in {"fixed_reference", "two_level_slot", "multi_slot"}:
            raise ValueError("selector sensitivity analysis is invalid")
        for value, name in ((self.replicate, "sensitivity replicate"), (self.selector_id, "sensitivity selector"), (self.ranking_label, "sensitivity ranking")):
            require_text(value, name)
        _canonical_unique_members(self.ordered_candidate_ids, "sensitivity candidate order")


@dataclass(frozen=True, slots=True)
class SelectorSensitivityAudit:
    fixed_reference_observation_sha256: str
    two_level_seeds: tuple[int, ...]
    common_request_randomness_slots: tuple[int, ...]
    rankings: tuple[SelectorSensitivityRanking, ...]
    top_k_stability: tuple[tuple[str, float], ...]
    multi_slot_task_means: tuple[
        tuple[str, tuple[tuple[str, float], ...], float], ...
    ]

    def __post_init__(self) -> None:
        _require_digest(self.fixed_reference_observation_sha256, "fixed-reference observations")
        if not self.two_level_seeds or not self.common_request_randomness_slots:
            raise ValueError("selector sensitivity requires two-level seeds and common slots")
        if len({(item.analysis, item.replicate, item.selector_id, item.ranking_label) for item in self.rankings}) != len(self.rankings):
            raise ValueError("selector sensitivity rankings are duplicated")
        if any(not 0.0 <= value <= 1.0 for _, value in self.top_k_stability):
            raise ValueError("selector top-K stability must be on [0, 1]")
        if tuple(item[0] for item in self.multi_slot_task_means) != tuple(sorted(item[0] for item in self.multi_slot_task_means)):
            raise ValueError("multi-slot task means must use canonical task-unit order")
        if any(not 0.0 <= outcome <= 1.0 or any(not 0.0 <= value <= 1.0 for _, value in features) for _, features, outcome in self.multi_slot_task_means):
            raise ValueError("multi-slot task means must remain on [0, 1]")


@dataclass(frozen=True, slots=True)
class SelectionFreezeManifest:
    universe: CandidateUniverseManifest
    plan: SelectorSuitePlan
    runs: tuple[SelectorRun, ...]
    selected_union_candidate_ids: tuple[str, ...]
    gate_failure_reason: str | None = None
    sensitivity_audit: SelectorSensitivityAudit | None = None
    fci_background_knowledge_audit_json: str | None = None

    def __post_init__(self) -> None:
        if self.plan.model_id == "":
            raise ValueError("selector plan model cannot be empty")
        if not self.universe.gate_passed:
            if self.runs or self.selected_union_candidate_ids or not self.gate_failure_reason or self.sensitivity_audit is not None or self.fci_background_knowledge_audit_json is not None:
                raise ValueError("a failed support gate cannot publish selector rankings")
            return
        if self.gate_failure_reason is not None:
            raise ValueError("a passed support gate cannot retain a gate failure")
        if tuple(run.kind for run in self.runs) != tuple(SelectorKind):
            raise ValueError("selector suite must contain the five canonical selectors")
        if any(run.universe_manifest_id != self.universe.manifest_id or run.plan_id != self.plan.plan_id or run.model_id != self.plan.model_id or run.discovery_data_sha256 != self.universe.discovery_data_sha256 for run in self.runs):
            raise ValueError("selector run provenance drifts from the shared suite")
        filled = {
            slot.candidate_id
            for run in self.runs
            for ranking in run.rankings
            for slot in ranking.slots
            if slot.status is SlotStatus.FILLED
        }
        if tuple(sorted(filled)) != self.selected_union_candidate_ids:
            raise ValueError("selected union must equal every unique filled top-K slot")
        if self.plan.behavior_version.endswith("-v2") and (
            self.sensitivity_audit is None or self.fci_background_knowledge_audit_json is None
        ):
            raise ValueError("prospective selector v2 requires frozen slot and BK/PAG sensitivity")
        if self.fci_background_knowledge_audit_json is not None:
            try:
                audit_value = json.loads(self.fci_background_knowledge_audit_json)
            except json.JSONDecodeError:
                raise ValueError("FCI BK/PAG audit must be canonical JSON") from None
            if canonical_json(audit_value) != self.fci_background_knowledge_audit_json:
                raise ValueError("FCI BK/PAG audit JSON is not canonical")
        if self.sensitivity_audit is not None:
            primary = {
                (run.selector_id, ranking.label): tuple(item.candidate_id for item in ranking.scores)
                for run in self.runs for ranking in run.rankings
            }
            diagnostic_primary = {
                (item.selector_id, item.ranking_label): item.ordered_candidate_ids
                for item in self.sensitivity_audit.rankings
                if item.analysis == "fixed_reference"
            }
            if primary != diagnostic_primary:
                raise ValueError("fixed-reference diagnostics must equal the frozen primary rankings")

    @property
    def selection_id(self) -> str:
        return content_id("selection_freeze_manifest_", self)

    @property
    def gate_passed(self) -> bool:
        return self.universe.gate_passed


class AtomicSelectorVariant(StrEnum):
    FULL = "atomic_full"
    RD_ONLY = "atomic_rd_only"


class AtomicFCIGateStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NON_EVALUABLE = "NON_EVALUABLE"


@dataclass(frozen=True, slots=True)
class AtomicCandidateUniverseManifest:
    """Direction-neutral v3 Atomic universe used by both Core variants."""

    policy_keys: tuple[AtomicPolicyKey, ...]
    supported_policy_keys: tuple[str, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    realization_policy_ids: tuple[tuple[str, str], ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    discovery_data_sha256: str
    positivity_audit_sha256: str
    information_budget_sha256: str
    top_k: int
    representation_adapter_id: str

    def __post_init__(self) -> None:
        if not self.policy_keys or any(
            type(item) is not AtomicPolicyKey for item in self.policy_keys
        ):
            raise TypeError("Atomic universe requires typed policy keys")
        candidate_ids = tuple(item.policy_key for item in self.policy_keys)
        _canonical_unique(candidate_ids, "Atomic policy keys")
        _canonical_unique(self.supported_policy_keys, "supported Atomic policy keys")
        if not set(self.supported_policy_keys) <= set(candidate_ids):
            raise ValueError("supported Atomic policies must belong to the universe")
        if tuple(item.policy_key for item in self.model_bound_records) != candidate_ids:
            raise ValueError("model-bound records must exactly follow Atomic policies")
        if any(
            type(item) is not ModelBoundCandidateRecord
            for item in self.model_bound_records
        ):
            raise TypeError("Atomic model-bound records must be typed")
        for bindings, name in (
            (self.realization_policy_ids, "realization-policy bindings"),
            (self.candidate_family_ids, "candidate-family bindings"),
        ):
            if tuple(candidate_id for candidate_id, _ in bindings) != candidate_ids:
                raise ValueError(f"{name} must exactly follow Atomic policies")
            if any(not isinstance(value, str) or not value.strip() for _, value in bindings):
                raise ValueError(f"{name} must contain non-empty values")
        for value, name in (
            (self.discovery_data_sha256, "Atomic discovery data"),
            (self.positivity_audit_sha256, "Atomic positivity audit"),
            (self.information_budget_sha256, "Atomic information budget"),
        ):
            _require_digest(value, name)
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Atomic top_k must be positive")
        require_text(self.representation_adapter_id, "Atomic representation adapter")

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.policy_key for item in self.policy_keys)

    @property
    def universe_id(self) -> str:
        return content_id("atomic_candidate_universe_", self)


@dataclass(frozen=True, slots=True)
class AtomicShadowPlan:
    model_id: str
    covariate_names: tuple[str, ...]
    cross_fit_folds: int
    ridge_lambda: float
    fold_seed: int
    fci_minimum_valid_fraction: float
    fci_adjacency_threshold: float

    def __post_init__(self) -> None:
        require_text(self.model_id, "Atomic shadow model_id")
        _canonical_unique(self.covariate_names, "Atomic covariate names")
        if type(self.cross_fit_folds) is not int or self.cross_fit_folds < 2:
            raise ValueError("Atomic cross_fit_folds must be at least two")
        if (
            type(self.ridge_lambda) not in {int, float}
            or not math.isfinite(float(self.ridge_lambda))
            or self.ridge_lambda <= 0
        ):
            raise ValueError("Atomic ridge_lambda must be finite and positive")
        if type(self.fold_seed) is not int:
            raise TypeError("Atomic fold_seed must be an integer")
        if (
            type(self.fci_minimum_valid_fraction) is not float
            or not 0.0 < self.fci_minimum_valid_fraction <= 1.0
        ):
            raise ValueError("Atomic FCI minimum valid fraction must be in (0, 1]")
        if (
            type(self.fci_adjacency_threshold) is not float
            or not 0.0 <= self.fci_adjacency_threshold <= 1.0
        ):
            raise ValueError("Atomic FCI adjacency threshold must be in [0, 1]")

    @property
    def plan_id(self) -> str:
        return content_id("atomic_shadow_plan_", self)


@dataclass(frozen=True, slots=True)
class AtomicPreOutcomeObservation:
    """Atomic fold input whose schema cannot carry a discovery outcome."""

    task_unit_id: str
    model_id: str
    family_id: str
    request_randomness_slot: int
    candidate_states: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "Atomic pre-outcome task_unit_id")
        require_text(self.model_id, "Atomic pre-outcome model_id")
        require_text(self.family_id, "Atomic pre-outcome family_id")
        if (
            type(self.request_randomness_slot) is not int
            or self.request_randomness_slot < 0
        ):
            raise ValueError("Atomic pre-outcome request slot must be nonnegative")
        _validate_numeric_pairs(
            self.candidate_states,
            "Atomic pre-outcome candidate states",
            binary=True,
        )

    @property
    def preoutcome_observation_id(self) -> str:
        return content_id("atomic_preoutcome_observation_", self)


@dataclass(frozen=True, slots=True)
class AtomicFoldAssignment:
    task_unit_id: str
    target_state: int
    fold: int

    def __post_init__(self) -> None:
        require_text(self.task_unit_id, "Atomic fold task_unit_id")
        if type(self.target_state) is not int or self.target_state not in {0, 1}:
            raise ValueError("Atomic target_state must be binary")
        if type(self.fold) is not int or self.fold < 0:
            raise ValueError("Atomic fold must be nonnegative")


@dataclass(frozen=True, slots=True)
class AtomicCandidateFoldManifest:
    candidate_id: str
    operation: Operation
    fold_count: int
    assignments: tuple[AtomicFoldAssignment, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic fold candidate_id")
        if type(self.operation) is not Operation:
            raise TypeError("Atomic fold operation must be typed")
        if type(self.fold_count) is not int or self.fold_count < 2:
            raise ValueError("Atomic fold_count must be at least two")
        if not self.assignments or tuple(
            sorted(self.assignments, key=lambda item: item.task_unit_id)
        ) != self.assignments:
            raise ValueError("Atomic fold assignments must use canonical task order")
        if len({item.task_unit_id for item in self.assignments}) != len(self.assignments):
            raise ValueError("Atomic fold task units must be unique")
        if {item.fold for item in self.assignments} != set(range(self.fold_count)):
            raise ValueError("Atomic fold manifest must use every frozen fold")
        for fold in range(self.fold_count):
            if {
                item.target_state for item in self.assignments if item.fold == fold
            } != {0, 1}:
                raise ValueError("every Atomic test fold must contain both states")

    @property
    def fold_manifest_id(self) -> str:
        return content_id("atomic_candidate_fold_manifest_", self)


@dataclass(frozen=True, slots=True)
class AtomicFoldFreeze:
    """Outcome-blind candidate folds sealed before Atomic discovery scoring."""

    universe_id: str
    plan_id: str
    preoutcome_data_sha256: str
    manifests: tuple[AtomicCandidateFoldManifest, ...]
    failures: tuple[SelectorFailure, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.universe_id, "Atomic fold-freeze universe_id"),
            (self.plan_id, "Atomic fold-freeze plan_id"),
        ):
            require_text(value, name)
        _require_digest(
            self.preoutcome_data_sha256,
            "Atomic fold-freeze pre-outcome data",
        )
        if tuple(
            sorted(self.manifests, key=lambda item: item.candidate_id)
        ) != self.manifests:
            raise ValueError("Atomic frozen folds must use canonical candidate order")
        if tuple(
            sorted(
                self.failures,
                key=lambda item: (item.candidate_id or "", item.reason_code),
            )
        ) != self.failures:
            raise ValueError("Atomic fold failures must use canonical candidate order")
        manifest_ids = tuple(item.candidate_id for item in self.manifests)
        failure_ids = tuple(item.candidate_id for item in self.failures)
        if (
            len(set(manifest_ids)) != len(manifest_ids)
            or any(candidate_id is None for candidate_id in failure_ids)
            or len(set(failure_ids)) != len(failure_ids)
            or set(manifest_ids) & set(failure_ids)
        ):
            raise ValueError("Atomic fold freeze must account for each candidate once")
        if any(
            item.reason_code != "atomic_fold_non_evaluable"
            for item in self.failures
        ):
            raise ValueError("Atomic fold freeze contains a non-fold failure")

    @property
    def fold_freeze_id(self) -> str:
        return content_id("atomic_fold_freeze_", self)


@dataclass(frozen=True, slots=True)
class AtomicRDScore:
    candidate_id: str
    signed_risk_difference: float
    absolute_risk_difference: float
    baseline_task_units: int
    fold_manifest_id: str

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic RD candidate_id")
        require_text(self.fold_manifest_id, "Atomic RD fold_manifest_id")
        if any(
            type(value) not in {int, float} or not math.isfinite(float(value))
            for value in (self.signed_risk_difference, self.absolute_risk_difference)
        ):
            raise ValueError("Atomic RD values must be finite")
        if self.absolute_risk_difference != abs(self.signed_risk_difference):
            raise ValueError("Atomic absolute RD does not match its signed value")
        if type(self.baseline_task_units) is not int or self.baseline_task_units <= 0:
            raise ValueError("Atomic RD requires held-out baseline task units")


@dataclass(frozen=True, slots=True)
class AtomicFCIBootstrapEvidence:
    universe_id: str
    candidate_draws: tuple[tuple[str, tuple[bool | None, ...]], ...]
    evidence_sha256: str

    def __post_init__(self) -> None:
        require_text(self.universe_id, "Atomic FCI universe_id")
        _require_digest(self.evidence_sha256, "Atomic FCI bootstrap evidence")
        candidate_ids = tuple(candidate_id for candidate_id, _ in self.candidate_draws)
        _canonical_unique(candidate_ids, "Atomic FCI candidate draws")
        if any(
            not draws
            or any(type(value) is not bool and value is not None for value in draws)
            for _, draws in self.candidate_draws
        ):
            raise ValueError("Atomic FCI draws must be non-empty bool/null tuples")


@dataclass(frozen=True, slots=True)
class AtomicFCIGate:
    candidate_id: str
    status: AtomicFCIGateStatus
    total_draws: int
    valid_draws: int
    adjacency_draws: int
    valid_fraction: float
    adjacency_stability: float | None

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "Atomic FCI gate candidate_id")
        if type(self.status) is not AtomicFCIGateStatus:
            raise TypeError("Atomic FCI gate status must be typed")
        if not (
            type(self.total_draws) is int
            and type(self.valid_draws) is int
            and type(self.adjacency_draws) is int
            and self.total_draws > 0
            and 0 <= self.adjacency_draws <= self.valid_draws <= self.total_draws
        ):
            raise ValueError("Atomic FCI draw accounting is invalid")
        if self.valid_fraction != self.valid_draws / self.total_draws:
            raise ValueError("Atomic FCI valid fraction is inconsistent")
        expected = (
            self.adjacency_draws / self.valid_draws if self.valid_draws else None
        )
        if self.adjacency_stability != expected:
            raise ValueError("Atomic FCI stability must use the valid-draw denominator")
        if self.status is AtomicFCIGateStatus.NON_EVALUABLE:
            if self.adjacency_stability is not None and not 0 <= self.adjacency_stability <= 1:
                raise ValueError("Atomic FCI stability must be on [0, 1]")
        elif self.adjacency_stability is None:
            raise ValueError("an evaluable Atomic FCI gate requires stability")


@dataclass(frozen=True, slots=True)
class AtomicShadowVariantResult:
    variant: AtomicSelectorVariant
    universe_id: str
    plan_id: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    fci_gate_evidence_sha256: str | None
    ranking: tuple[RankedCandidate, ...]
    slots: tuple[SelectorSlot, ...]

    def __post_init__(self) -> None:
        if type(self.variant) is not AtomicSelectorVariant:
            raise TypeError("Atomic selector variant must be typed")
        for value, name in (
            (self.universe_id, "Atomic result universe_id"),
            (self.plan_id, "Atomic result plan_id"),
        ):
            require_text(value, name)
        _require_digest(self.fold_manifests_sha256, "Atomic fold manifests")
        _require_digest(self.rd_scores_sha256, "Atomic RD scores")
        if self.variant is AtomicSelectorVariant.FULL:
            _require_digest(self.fci_gate_evidence_sha256, "Atomic Full FCI gate evidence")
        elif self.fci_gate_evidence_sha256 is not None:
            raise ValueError("Atomic RD-only cannot read FCI gate evidence")
        if tuple(item.rank for item in self.ranking) != tuple(
            range(1, len(self.ranking) + 1)
        ):
            raise ValueError("Atomic ranking must have complete ranks")
        if tuple(slot.rank for slot in self.slots) != tuple(
            range(1, len(self.slots) + 1)
        ):
            raise ValueError("Atomic slots must be complete")
        filled = tuple(
            slot.candidate_id for slot in self.slots if slot.status is SlotStatus.FILLED
        )
        if filled != tuple(item.candidate_id for item in self.ranking[: len(filled)]):
            raise ValueError("Atomic filled slots must follow the ranking")

    @property
    def result_id(self) -> str:
        return content_id("atomic_shadow_variant_result_", self)


@dataclass(frozen=True, slots=True)
class AtomicSoleDifferenceAudit:
    universe_id: str
    plan_id: str
    discovery_data_sha256: str
    fold_manifests_sha256: str
    rd_scores_sha256: str
    tie_break_rule: str
    top_k: int
    full_additional_read: str = "fci_gate"
    rd_only_additional_reads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, name in (
            (self.universe_id, "Atomic audit universe_id"),
            (self.plan_id, "Atomic audit plan_id"),
            (self.tie_break_rule, "Atomic tie-break rule"),
        ):
            require_text(value, name)
        for value in (
            self.discovery_data_sha256,
            self.fold_manifests_sha256,
            self.rd_scores_sha256,
        ):
            _require_digest(value)
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("Atomic audit top_k must be positive")
        if self.full_additional_read != "fci_gate" or self.rd_only_additional_reads:
            raise ValueError("only Atomic Full may add the FCI Gate read")


@dataclass(frozen=True, slots=True)
class AtomicShadowQualificationResult:
    universe: AtomicCandidateUniverseManifest
    plan: AtomicShadowPlan
    fold_manifests: tuple[AtomicCandidateFoldManifest, ...]
    rd_scores: tuple[AtomicRDScore, ...]
    fci_gates: tuple[AtomicFCIGate, ...]
    failures: tuple[SelectorFailure, ...]
    full: AtomicShadowVariantResult
    rd_only: AtomicShadowVariantResult
    sole_difference: AtomicSoleDifferenceAudit

    def __post_init__(self) -> None:
        if self.full.variant is not AtomicSelectorVariant.FULL:
            raise ValueError("Atomic qualification Full result is missing")
        if self.rd_only.variant is not AtomicSelectorVariant.RD_ONLY:
            raise ValueError("Atomic qualification RD-only result is missing")
        if self.full.universe_id != self.universe.universe_id or self.rd_only.universe_id != self.universe.universe_id:
            raise ValueError("Atomic shadow results drift from their shared universe")
        if self.full.plan_id != self.plan.plan_id or self.rd_only.plan_id != self.plan.plan_id:
            raise ValueError("Atomic shadow results drift from their shared plan")
        if self.full.fold_manifests_sha256 != self.rd_only.fold_manifests_sha256:
            raise ValueError("Atomic Core variants must share fold manifests")
        if self.full.rd_scores_sha256 != self.rd_only.rd_scores_sha256:
            raise ValueError("Atomic Core variants must share RD scores")

    @property
    def qualification_result_id(self) -> str:
        return content_id("atomic_shadow_qualification_result_", self)


class PolicyTrack(StrEnum):
    ATOMIC = "atomic"
    PAIR = "pair"


@dataclass(frozen=True, slots=True)
class FixedSlotSource:
    """One model-bound selector's immutable K-slot output."""

    track: PolicyTrack
    selector_id: str
    model_id: str
    universe_id: str
    slots: tuple[SelectorSlot, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("fixed-slot track must be typed")
        for value, name in (
            (self.selector_id, "fixed-slot selector_id"),
            (self.model_id, "fixed-slot model_id"),
            (self.universe_id, "fixed-slot universe_id"),
        ):
            require_text(value, name)
        if not self.slots or tuple(item.rank for item in self.slots) != tuple(
            range(1, len(self.slots) + 1)
        ):
            raise ValueError("fixed-slot source must retain a complete non-empty K ledger")
        if not self.model_bound_records or any(
            type(item) is not ModelBoundCandidateRecord
            for item in self.model_bound_records
        ):
            raise TypeError("fixed-slot source requires model-bound candidate records")
        policy_keys = tuple(item.policy_key for item in self.model_bound_records)
        _canonical_unique(policy_keys, "fixed-slot model-bound policy keys")
        if {item.discovery_model_id for item in self.model_bound_records} != {
            self.model_id
        }:
            raise ValueError("fixed-slot candidates must dispatch only to the source model")
        if not {
            item.candidate_id
            for item in self.slots
            if item.status is SlotStatus.FILLED
        } <= set(policy_keys):
            raise ValueError("a filled slot falls outside its model-bound universe")

    @property
    def source_id(self) -> str:
        return content_id("fixed_slot_source_", self)


@dataclass(frozen=True, slots=True)
class FixedSlotRecord:
    source_id: str
    track: PolicyTrack
    selector_id: str
    model_id: str
    rank: int
    status: SlotStatus
    candidate_record_id: str | None
    policy_key: str | None
    effect_coordinate_id: str | None
    reason_code: str | None

    def __post_init__(self) -> None:
        for value, name in (
            (self.source_id, "slot source_id"),
            (self.selector_id, "slot selector_id"),
            (self.model_id, "slot model_id"),
        ):
            require_text(value, name)
        if type(self.track) is not PolicyTrack or type(self.status) is not SlotStatus:
            raise TypeError("fixed slot track and status must be typed")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("fixed slot rank must be positive")
        bound = (
            self.candidate_record_id,
            self.policy_key,
            self.effect_coordinate_id,
        )
        if self.status is SlotStatus.FILLED:
            if any(value is None for value in bound) or self.reason_code is not None:
                raise ValueError("a filled fixed slot requires only its three candidate identities")
            for value, name in zip(
                bound,
                ("candidate_record_id", "policy_key", "effect_coordinate_id"),
                strict=True,
            ):
                require_text(value, name)
        elif any(value is not None for value in bound) or not self.reason_code:
            raise ValueError("an unfilled fixed slot requires only a reason")

    @property
    def slot_id(self) -> str:
        return content_id("fixed_selector_slot_", self)


@dataclass(frozen=True, slots=True)
class FixedSlotLedger:
    """All Atomic and Pair selector denominators before bridge or confirmation."""

    protocol_id: str
    schema_version: str
    sources: tuple[FixedSlotSource, ...]
    top_k_by_track: tuple[tuple[PolicyTrack, int], ...]
    slots: tuple[FixedSlotRecord, ...]

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "fixed-slot protocol_id")
        require_text(self.schema_version, "fixed-slot schema_version")
        if not self.sources or any(type(item) is not FixedSlotSource for item in self.sources):
            raise TypeError("fixed-slot ledger requires typed sources")
        source_order = lambda item: (item.track.value, item.model_id, item.selector_id)
        if tuple(sorted(self.sources, key=source_order)) != self.sources:
            raise ValueError("fixed-slot sources must use canonical track/model/selector order")
        source_ids = tuple(item.source_id for item in self.sources)
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("fixed-slot sources must be unique")
        expected_top_k = {}
        for source in self.sources:
            previous = expected_top_k.setdefault(source.track, len(source.slots))
            if previous != len(source.slots):
                raise ValueError("all selectors in one track must use the same K")
        if self.top_k_by_track != tuple(
            sorted(expected_top_k.items(), key=lambda item: item[0].value)
        ):
            raise ValueError("fixed-slot track K values do not replay from sources")
        slot_order = lambda item: (
            item.track.value,
            item.model_id,
            item.selector_id,
            item.rank,
        )
        if tuple(sorted(self.slots, key=slot_order)) != self.slots:
            raise ValueError("fixed slots must use canonical track/model/selector/rank order")
        if len({item.slot_id for item in self.slots}) != len(self.slots):
            raise ValueError("fixed slot identities must be unique")
        slots_by_source: dict[str, list[FixedSlotRecord]] = defaultdict(list)
        for slot in self.slots:
            slots_by_source[slot.source_id].append(slot)
        if set(slots_by_source) != set(source_ids):
            raise ValueError("fixed slots must bind every source exactly")
        for source in self.sources:
            fixed = tuple(slots_by_source[source.source_id])
            if tuple(item.rank for item in fixed) != tuple(range(1, len(source.slots) + 1)):
                raise ValueError("fixed slots do not preserve the source K denominator")
            for original, record in zip(source.slots, fixed, strict=True):
                if original.status is not record.status or original.reason_code != record.reason_code:
                    raise ValueError("fixed slot status or reason drifted from its source")
                if original.candidate_id != record.policy_key:
                    raise ValueError("fixed slot policy identity drifted from its source")

    @property
    def fixed_slot_ledger_id(self) -> str:
        return content_id("fixed_slot_ledger_", self)


@dataclass(frozen=True, slots=True)
class SharedCandidateUnionEntry:
    track: PolicyTrack
    candidate: ModelBoundCandidateRecord

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("shared candidate track must be typed")
        if type(self.candidate) is not ModelBoundCandidateRecord:
            raise TypeError("shared union entry requires a model-bound candidate")

    @property
    def candidate_record_id(self) -> str:
        return self.candidate.candidate_record_id

    @property
    def effect_coordinate_id(self) -> str:
        return self.candidate.effect_coordinate.effect_coordinate_id


@dataclass(frozen=True, slots=True)
class CandidateSlotFanout:
    candidate_record_id: str
    slot_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_record_id, "fan-out candidate_record_id")
        _canonical_unique(self.slot_ids, "fan-out slot_ids")


@dataclass(frozen=True, slots=True)
class SharedConfirmationUnion:
    """Unique model-effect union and exact fan-out back to fixed selector slots."""

    ledger: FixedSlotLedger
    entries: tuple[SharedCandidateUnionEntry, ...]
    candidate_to_slots: tuple[CandidateSlotFanout, ...]

    def __post_init__(self) -> None:
        if type(self.ledger) is not FixedSlotLedger:
            raise TypeError("shared confirmation union requires a fixed-slot ledger")
        if any(type(item) is not SharedCandidateUnionEntry for item in self.entries):
            raise TypeError("shared confirmation entries must be typed")
        entry_ids = tuple(item.candidate_record_id for item in self.entries)
        _canonical_unique(entry_ids, "shared confirmation candidate records")
        effect_ids = tuple(item.effect_coordinate_id for item in self.entries)
        if len(set(effect_ids)) != len(effect_ids):
            raise ValueError("one model effect may enter the confirmation union only once")
        if tuple(item.candidate_record_id for item in self.candidate_to_slots) != entry_ids:
            raise ValueError("candidate-to-slots must exactly follow the unique union")
        filled = {
            item.candidate_record_id: []
            for item in self.ledger.slots
            if item.status is SlotStatus.FILLED
        }
        for slot in self.ledger.slots:
            if slot.status is SlotStatus.FILLED:
                filled[slot.candidate_record_id].append(slot.slot_id)
        if set(filled) != set(entry_ids):
            raise ValueError("unique union must equal every filled candidate record")
        for fanout in self.candidate_to_slots:
            if fanout.slot_ids != tuple(sorted(filled[fanout.candidate_record_id])):
                raise ValueError("candidate-to-slots fan-out does not replay from the ledger")

    @property
    def shared_confirmation_union_id(self) -> str:
        return content_id("shared_confirmation_union_", self)


@dataclass(frozen=True, slots=True)
class ConfirmationDispatchRecord:
    candidate_record_id: str
    effect_coordinate_id: str
    policy_key: str
    model_id: str
    status: BridgeStatus
    protocol_record_id: str | None
    reason_code: str | None
    dispatch_count: int

    def __post_init__(self) -> None:
        for name in (
            "candidate_record_id",
            "effect_coordinate_id",
            "policy_key",
            "model_id",
        ):
            require_text(getattr(self, name), name)
        if type(self.status) is not BridgeStatus:
            raise TypeError("confirmation dispatch status must be typed")
        if self.status is BridgeStatus.SUCCESS:
            require_text(self.protocol_record_id, "protocol_record_id")
            if self.reason_code is not None or self.dispatch_count != 1:
                raise ValueError("a successful model-bound candidate dispatches exactly once")
        elif (
            self.protocol_record_id is not None
            or not self.reason_code
            or self.dispatch_count != 0
        ):
            raise ValueError("a bridge/protocolization failure cannot be dispatched")


@dataclass(frozen=True, slots=True)
class ConfirmationDispatchManifest:
    union: SharedConfirmationUnion
    records: tuple[ConfirmationDispatchRecord, ...]

    def __post_init__(self) -> None:
        if type(self.union) is not SharedConfirmationUnion:
            raise TypeError("dispatch manifest requires a shared confirmation union")
        expected = self.union.entries
        if tuple(item.candidate_record_id for item in self.records) != tuple(
            item.candidate_record_id for item in expected
        ):
            raise ValueError("dispatch records must exactly follow the unique union")
        for entry, record in zip(expected, self.records, strict=True):
            candidate = entry.candidate
            if (
                record.effect_coordinate_id
                != candidate.effect_coordinate.effect_coordinate_id
                or record.policy_key != candidate.policy_key
                or record.model_id != candidate.discovery_model_id
            ):
                raise ValueError("dispatch drifted from the model-bound effect coordinate")
        if len({item.effect_coordinate_id for item in self.records}) != len(self.records):
            raise ValueError("a model effect cannot be dispatched more than once")
        shared_policy_result: dict[str, tuple[BridgeStatus, str | None, str | None]] = {}
        for record in self.records:
            result = (record.status, record.protocol_record_id, record.reason_code)
            previous = shared_policy_result.setdefault(record.policy_key, result)
            if previous != result:
                raise ValueError(
                    "one semantic policy must share one bridge/protocolization result across models"
                )

    @property
    def confirmation_dispatch_manifest_id(self) -> str:
        return content_id("confirmation_dispatch_manifest_", self)


def freeze_fixed_slot_ledger(
    protocol_id: str,
    schema_version: str,
    sources: Sequence[FixedSlotSource],
) -> FixedSlotLedger:
    """Bind model-specific Atomic/Pair selector slots without replacement."""

    frozen_sources = tuple(
        sorted(
            sources,
            key=lambda item: (item.track.value, item.model_id, item.selector_id),
        )
    )
    if len(
        {(item.track, item.model_id, item.selector_id) for item in frozen_sources}
    ) != len(frozen_sources):
        raise ValueError("fixed-slot source coordinates must be unique")
    fixed = []
    for source in frozen_sources:
        record_by_policy = {item.policy_key: item for item in source.model_bound_records}
        for slot in source.slots:
            candidate = (
                record_by_policy[slot.candidate_id]
                if slot.status is SlotStatus.FILLED
                else None
            )
            fixed.append(
                FixedSlotRecord(
                    source.source_id,
                    source.track,
                    source.selector_id,
                    source.model_id,
                    slot.rank,
                    slot.status,
                    None if candidate is None else candidate.candidate_record_id,
                    None if candidate is None else candidate.policy_key,
                    (
                        None
                        if candidate is None
                        else candidate.effect_coordinate.effect_coordinate_id
                    ),
                    slot.reason_code,
                )
            )
    top_k = {}
    for source in frozen_sources:
        top_k.setdefault(source.track, len(source.slots))
    return FixedSlotLedger(
        protocol_id,
        schema_version,
        frozen_sources,
        tuple(sorted(top_k.items(), key=lambda item: item[0].value)),
        tuple(fixed),
    )


def freeze_shared_confirmation_union(
    ledger: FixedSlotLedger,
) -> SharedConfirmationUnion:
    """Deduplicate filled slots at the model-effect record, never at rank."""

    record_by_id = {
        record.candidate_record_id: (source.track, record)
        for source in ledger.sources
        for record in source.model_bound_records
    }
    selected_ids = tuple(
        sorted(
            {
                slot.candidate_record_id
                for slot in ledger.slots
                if slot.status is SlotStatus.FILLED
            }
        )
    )
    entries = tuple(
        SharedCandidateUnionEntry(*record_by_id[candidate_id])
        for candidate_id in selected_ids
    )
    fanout = tuple(
        CandidateSlotFanout(
            candidate_id,
            tuple(
                sorted(
                    slot.slot_id
                    for slot in ledger.slots
                    if slot.candidate_record_id == candidate_id
                )
            ),
        )
        for candidate_id in selected_ids
    )
    return SharedConfirmationUnion(ledger, entries, fanout)


def freeze_confirmation_dispatch(
    union: SharedConfirmationUnion,
    protocol_record_ids: Mapping[str, str],
    *,
    failures: Mapping[str, tuple[BridgeStatus, str]] | None = None,
) -> ConfirmationDispatchManifest:
    """Dispatch each selected record only to its discovery-bound model."""

    expected_ids = tuple(item.candidate_record_id for item in union.entries)
    frozen_failures = {} if failures is None else dict(failures)
    if set(protocol_record_ids) & set(frozen_failures) or (
        set(protocol_record_ids) | set(frozen_failures)
    ) != set(expected_ids):
        raise ValueError("successful and failed dispatch records must partition the union")
    if any(
        type(status) is not BridgeStatus or status is BridgeStatus.SUCCESS or not reason
        for status, reason in frozen_failures.values()
    ):
        raise ValueError("dispatch failures must be typed bridge/protocolization failures")
    records = tuple(
        ConfirmationDispatchRecord(
            entry.candidate_record_id,
            entry.effect_coordinate_id,
            entry.candidate.policy_key,
            entry.candidate.discovery_model_id,
            (
                BridgeStatus.SUCCESS
                if entry.candidate_record_id in protocol_record_ids
                else frozen_failures[entry.candidate_record_id][0]
            ),
            protocol_record_ids.get(entry.candidate_record_id),
            (
                None
                if entry.candidate_record_id in protocol_record_ids
                else frozen_failures[entry.candidate_record_id][1]
            ),
            1 if entry.candidate_record_id in protocol_record_ids else 0,
        )
        for entry in union.entries
    )
    return ConfirmationDispatchManifest(union, records)


@dataclass(frozen=True, slots=True)
class BridgeRecord:
    candidate_id: str
    status: BridgeStatus
    final_hypothesis_id: str | None
    reason_code: str | None
    final_hypothesis: FrozenHypothesisV2 | None = None

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "bridge candidate_id")
        if type(self.status) is not BridgeStatus:
            raise TypeError("bridge status must be a BridgeStatus")
        if self.status is BridgeStatus.SUCCESS:
            if self.final_hypothesis_id is None or self.reason_code is not None:
                raise ValueError("a successful bridge requires only a final hypothesis")
            if self.final_hypothesis is not None and self.final_hypothesis.hypothesis_id != self.final_hypothesis_id:
                raise ValueError("bridge final hypothesis identity does not recompute")
        elif self.final_hypothesis_id is not None or not self.reason_code:
            raise ValueError("a failed bridge requires only a reason")
        elif self.final_hypothesis is not None:
            raise ValueError("a failed bridge cannot carry a final hypothesis")


@dataclass(frozen=True, slots=True)
class SharedBridgeMap:
    selection_id: str
    records: tuple[BridgeRecord, ...]

    def __post_init__(self) -> None:
        require_text(self.selection_id, "bridge selection_id")
        if tuple(sorted(self.records, key=lambda item: item.candidate_id)) != self.records:
            raise ValueError("bridge records must use canonical candidate order")
        if len({item.candidate_id for item in self.records}) != len(self.records):
            raise ValueError("bridge candidate ids must be unique")
        final_ids = [item.final_hypothesis_id for item in self.records if item.final_hypothesis_id]
        if len(final_ids) != len(set(final_ids)):
            raise ValueError("different candidates cannot silently share a final hypothesis")

    @property
    def bridge_map_id(self) -> str:
        return content_id("shared_bridge_map_", self)


def freeze_atomic_candidate_universe(
    policy_keys: Sequence[AtomicPolicyKey],
    model_bound_records: Sequence[ModelBoundCandidateRecord],
    *,
    supported_policy_keys: Sequence[str],
    realization_policy_ids: Mapping[str, str],
    candidate_family_ids: Mapping[str, str],
    discovery_data_sha256: str,
    positivity_audit_sha256: str,
    information_budget_sha256: str,
    top_k: int,
    representation_adapter_id: str,
) -> AtomicCandidateUniverseManifest:
    """Freeze one direction-neutral Atomic universe for Full and RD-only."""

    ordered_keys = tuple(sorted(policy_keys, key=lambda item: item.policy_key))
    candidate_ids = tuple(item.policy_key for item in ordered_keys)
    records_by_key = {item.policy_key: item for item in model_bound_records}
    if len(records_by_key) != len(tuple(model_bound_records)) or set(records_by_key) != set(
        candidate_ids
    ):
        raise ValueError("Atomic model-bound records must bind every policy exactly once")
    for values, name in (
        (realization_policy_ids, "Atomic realization policies"),
        (candidate_family_ids, "Atomic family bindings"),
    ):
        if set(values) != set(candidate_ids):
            raise ValueError(f"{name} must bind every policy exactly once")
    return AtomicCandidateUniverseManifest(
        ordered_keys,
        tuple(sorted(supported_policy_keys)),
        tuple(records_by_key[candidate_id] for candidate_id in candidate_ids),
        tuple((candidate_id, realization_policy_ids[candidate_id]) for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        discovery_data_sha256,
        positivity_audit_sha256,
        information_budget_sha256,
        top_k,
        representation_adapter_id,
    )


def run_atomic_shadow_qualification(
    universe: AtomicCandidateUniverseManifest,
    observations: Sequence[DiscoveryObservation],
    plan: AtomicShadowPlan,
    fci_evidence: AtomicFCIBootstrapEvidence,
    *,
    fold_freeze: AtomicFoldFreeze,
) -> AtomicShadowQualificationResult:
    """Run Atomic Full/RD-only with one shared row, fold, and RD path."""

    if type(universe) is not AtomicCandidateUniverseManifest:
        raise TypeError("universe must be an AtomicCandidateUniverseManifest")
    if type(plan) is not AtomicShadowPlan:
        raise TypeError("plan must be an AtomicShadowPlan")
    if type(fci_evidence) is not AtomicFCIBootstrapEvidence:
        raise TypeError("fci_evidence must be AtomicFCIBootstrapEvidence")
    if not universe.supported_policy_keys:
        raise ValueError("Atomic shadow qualification has no supported candidate")
    if discovery_data_sha256(observations) != universe.discovery_data_sha256:
        raise ValueError("Atomic discovery observations drift from the frozen universe")
    if fci_evidence.universe_id != universe.universe_id:
        raise ValueError("Atomic FCI evidence drifts from the frozen universe")
    if tuple(candidate_id for candidate_id, _ in fci_evidence.candidate_draws) != (
        universe.supported_policy_keys
    ):
        raise ValueError("Atomic FCI evidence must cover every supported policy in order")

    rows = _reference_observations(observations, plan.model_id)
    family_by_candidate = dict(universe.candidate_family_ids)
    if type(fold_freeze) is not AtomicFoldFreeze:
        raise TypeError("Atomic prioritization requires an explicit fold freeze")
    if fold_freeze != freeze_atomic_candidate_folds(
        universe,
        atomic_preoutcome_observations(observations),
        plan,
    ):
        raise ValueError("Atomic fold freeze failed outcome-blind replay")
    frozen_manifest_by_id = {
        item.candidate_id: item for item in fold_freeze.manifests
    }
    rd_scores: list[AtomicRDScore] = []
    failures: list[SelectorFailure] = list(fold_freeze.failures)
    for candidate_id in universe.supported_policy_keys:
        manifest = frozen_manifest_by_id.get(candidate_id)
        if manifest is None:
            continue
        candidate_rows = tuple(
            row
            for row in rows
            if row.family_id == family_by_candidate[candidate_id]
            and candidate_id in dict(row.candidate_states)
        )
        try:
            score = _atomic_cross_fitted_rd(candidate_id, candidate_rows, manifest, plan)
        except ValueError as exc:
            failures.append(
                SelectorFailure("atomic_rd_non_evaluable", str(exc), candidate_id)
            )
            continue
        rd_scores.append(score)

    frozen_folds = fold_freeze.manifests
    frozen_scores = tuple(sorted(rd_scores, key=lambda item: item.candidate_id))
    frozen_failures = tuple(
        sorted(failures, key=lambda item: (item.candidate_id or "", item.reason_code))
    )
    fold_sha256 = content_hash(frozen_folds)
    rd_sha256 = content_hash(frozen_scores)
    gates = _atomic_fci_gates(fci_evidence, plan)
    gate_sha256 = content_hash(
        {
            "source_evidence_sha256": fci_evidence.evidence_sha256,
            "minimum_valid_fraction": plan.fci_minimum_valid_fraction,
            "adjacency_threshold": plan.fci_adjacency_threshold,
            "gates": gates,
        }
    )
    full = _atomic_variant_result(
        AtomicSelectorVariant.FULL,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        fold_sha256,
        rd_sha256,
        gates,
        gate_sha256,
    )
    rd_only = _atomic_variant_result(
        AtomicSelectorVariant.RD_ONLY,
        universe,
        plan,
        frozen_scores,
        frozen_failures,
        fold_sha256,
        rd_sha256,
        (),
        None,
    )
    sole_difference = AtomicSoleDifferenceAudit(
        universe.universe_id,
        plan.plan_id,
        universe.discovery_data_sha256,
        fold_sha256,
        rd_sha256,
        "descending_absolute_rd_then_policy_key_v1",
        universe.top_k,
    )
    return AtomicShadowQualificationResult(
        universe,
        plan,
        frozen_folds,
        frozen_scores,
        gates,
        frozen_failures,
        full,
        rd_only,
        sole_difference,
    )


def freeze_atomic_candidate_folds(
    universe: AtomicCandidateUniverseManifest,
    observations: Sequence[AtomicPreOutcomeObservation],
    plan: AtomicShadowPlan,
) -> AtomicFoldFreeze:
    """Seal deterministic candidate/state folds from an outcome-free schema."""

    if type(universe) is not AtomicCandidateUniverseManifest:
        raise TypeError("universe must be an AtomicCandidateUniverseManifest")
    if type(plan) is not AtomicShadowPlan:
        raise TypeError("plan must be an AtomicShadowPlan")
    if any(type(item) is not AtomicPreOutcomeObservation for item in observations):
        raise TypeError("Atomic fold freeze requires pre-outcome observations")
    rows = _reference_atomic_preoutcome_observations(observations, plan.model_id)
    family_by_candidate = dict(universe.candidate_family_ids)
    policy_by_id = {item.policy_key: item for item in universe.policy_keys}
    manifests = []
    failures = []
    for candidate_id in universe.supported_policy_keys:
        candidate_rows = tuple(
            row
            for row in rows
            if row.family_id == family_by_candidate[candidate_id]
            and candidate_id in dict(row.candidate_states)
        )
        try:
            manifest = _atomic_candidate_fold_manifest(
                candidate_id,
                policy_by_id[candidate_id].factor.operation,
                candidate_rows,
                plan.cross_fit_folds,
                plan.fold_seed,
            )
        except ValueError as exc:
            failures.append(
                SelectorFailure("atomic_fold_non_evaluable", str(exc), candidate_id)
            )
            continue
        manifests.append(manifest)
    return AtomicFoldFreeze(
        universe.universe_id,
        plan.plan_id,
        atomic_preoutcome_data_sha256(observations),
        tuple(sorted(manifests, key=lambda item: item.candidate_id)),
        tuple(
            sorted(
                failures,
                key=lambda item: (item.candidate_id or "", item.reason_code),
            )
        ),
    )


def atomic_preoutcome_observations(
    observations: Sequence[DiscoveryObservation],
) -> tuple[AtomicPreOutcomeObservation, ...]:
    """Project natural discovery records before their outcome field is opened."""

    if not observations or any(
        type(item) is not DiscoveryObservation for item in observations
    ):
        raise TypeError("Atomic pre-outcome projection requires discovery observations")
    return tuple(
        sorted(
            (
                AtomicPreOutcomeObservation(
                    item.task_unit_id,
                    item.model_id,
                    item.family_id,
                    item.request_randomness_slot,
                    item.candidate_states,
                )
                for item in observations
            ),
            key=lambda item: item.preoutcome_observation_id,
        )
    )


def atomic_preoutcome_data_sha256(
    observations: Sequence[AtomicPreOutcomeObservation],
) -> str:
    """Hash only coordinates available before the outcome column is opened."""

    frozen = tuple(
        sorted(observations, key=lambda item: item.preoutcome_observation_id)
    )
    if not frozen or any(
        type(item) is not AtomicPreOutcomeObservation for item in frozen
    ):
        raise TypeError("Atomic pre-outcome data requires typed observations")
    coordinates = {
        (item.task_unit_id, item.model_id, item.family_id, item.request_randomness_slot)
        for item in frozen
    }
    if len(coordinates) != len(frozen):
        raise ValueError("an Atomic pre-outcome coordinate is duplicated")
    return content_hash(frozen)


def _reference_atomic_preoutcome_observations(
    observations: Sequence[AtomicPreOutcomeObservation],
    model_id: str,
) -> tuple[AtomicPreOutcomeObservation, ...]:
    candidates = [item for item in observations if item.model_id == model_id]
    if not candidates:
        raise ValueError("Atomic selector model has no pre-outcome observations")
    by_unit: dict[tuple[str, str], list[AtomicPreOutcomeObservation]] = {}
    for item in candidates:
        by_unit.setdefault((item.family_id, item.task_unit_id), []).append(item)
    return tuple(
        min(
            values,
            key=lambda item: (
                item.request_randomness_slot,
                item.preoutcome_observation_id,
            ),
        )
        for _, values in sorted(by_unit.items())
    )


def _atomic_candidate_fold_manifest(
    candidate_id: str,
    operation: Operation,
    rows: tuple[AtomicPreOutcomeObservation, ...],
    fold_count: int,
    fold_seed: int,
) -> AtomicCandidateFoldManifest:
    if not rows or len({row.task_unit_id for row in rows}) != len(rows):
        raise ValueError("Atomic candidate rows are empty or duplicate task units")
    by_state: dict[int, list[AtomicPreOutcomeObservation]] = {0: [], 1: []}
    for row in rows:
        raw_state = dict(row.candidate_states)[candidate_id]
        target_state = raw_state if operation is Operation.ADD else 1 - raw_state
        by_state[target_state].append(row)
    if any(len(values) < fold_count for values in by_state.values()):
        raise ValueError("Atomic candidate lacks state support for every frozen fold")
    assignments = []
    for state in (0, 1):
        ordered = sorted(
            by_state[state],
            key=lambda row: (
                content_hash(
                    {
                        "domain": "atomic_candidate_state_fold_v1",
                        "seed": fold_seed,
                        "candidate_id": candidate_id,
                        "target_state": state,
                        "task_unit_id": row.task_unit_id,
                    }
                ),
                row.task_unit_id,
            ),
        )
        assignments.extend(
            AtomicFoldAssignment(row.task_unit_id, state, index % fold_count)
            for index, row in enumerate(ordered)
        )
    return AtomicCandidateFoldManifest(
        candidate_id,
        operation,
        fold_count,
        tuple(sorted(assignments, key=lambda item: item.task_unit_id)),
    )


def _atomic_cross_fitted_rd(
    candidate_id: str,
    rows: tuple[DiscoveryObservation, ...],
    folds: AtomicCandidateFoldManifest,
    plan: AtomicShadowPlan,
) -> AtomicRDScore:
    fold_by_task = {item.task_unit_id: item.fold for item in folds.assignments}
    state_by_task = {item.task_unit_id: item.target_state for item in folds.assignments}
    contributions: list[float] = []
    for fold in range(folds.fold_count):
        training = tuple(row for row in rows if fold_by_task[row.task_unit_id] != fold)
        held_out = tuple(row for row in rows if fold_by_task[row.task_unit_id] == fold)
        if {state_by_task[row.task_unit_id] for row in training} != {0, 1}:
            raise ValueError("Atomic training fold lacks both target-relative states")
        if any(
            tuple(name for name, _ in row.covariates) != plan.covariate_names
            for row in (*training, *held_out)
        ):
            raise ValueError("Atomic covariate schema drifts from the frozen plan")
        baseline = tuple(
            row for row in held_out if state_by_task[row.task_unit_id] == 0
        )
        if not baseline:
            raise ValueError("Atomic held-out fold lacks baseline-eligible task units")
        train_raw = [
            [
                *(float(value) for _, value in row.covariates),
                float(state_by_task[row.task_unit_id]),
            ]
            for row in training
        ]
        test_raw = [
            [*(float(value) for _, value in row.covariates), target_state]
            for row in baseline
            for target_state in (0.0, 1.0)
        ]
        train_x, test_x = _normalize_design(train_raw, test_raw)
        probabilities = _ridge_probabilities(
            train_x,
            [row.outcome for row in training],
            test_x,
            float(plan.ridge_lambda),
        )
        contributions.extend(
            probabilities[index + 1] - probabilities[index]
            for index in range(0, len(probabilities), 2)
        )
    baseline_count = sum(item.target_state == 0 for item in folds.assignments)
    if len(contributions) != baseline_count or not contributions:
        raise ValueError("Atomic cross-fitting did not cover every baseline task unit")
    signed = sum(contributions) / len(contributions)
    return AtomicRDScore(
        candidate_id,
        signed,
        abs(signed),
        baseline_count,
        folds.fold_manifest_id,
    )


def _normalize_design(
    train_raw: list[list[float]],
    test_raw: list[list[float]],
) -> tuple[list[list[float]], list[list[float]]]:
    if not train_raw or not test_raw:
        raise ValueError("normalized design requires non-empty train and test rows")
    width = len(train_raw[0])
    if any(len(row) != width for row in (*train_raw, *test_raw)):
        raise ValueError("normalized design width is inconsistent")
    if width == 0:
        return train_raw, test_raw
    means = [
        sum(row[column] for row in train_raw) / len(train_raw)
        for column in range(width)
    ]
    scales = [
        math.sqrt(
            sum((row[column] - means[column]) ** 2 for row in train_raw)
            / len(train_raw)
        )
        or 1.0
        for column in range(width)
    ]

    def normalize(row: list[float]) -> list[float]:
        return [
            (value - means[index]) / scales[index]
            for index, value in enumerate(row)
        ]

    return [normalize(row) for row in train_raw], [normalize(row) for row in test_raw]


def _atomic_fci_gates(
    evidence: AtomicFCIBootstrapEvidence,
    plan: AtomicShadowPlan,
) -> tuple[AtomicFCIGate, ...]:
    gates = []
    for candidate_id, draws in evidence.candidate_draws:
        valid = tuple(value for value in draws if value is not None)
        valid_fraction = len(valid) / len(draws)
        stability = sum(valid) / len(valid) if valid else None
        if valid_fraction < plan.fci_minimum_valid_fraction:
            status = AtomicFCIGateStatus.NON_EVALUABLE
        elif stability is not None and stability >= plan.fci_adjacency_threshold:
            status = AtomicFCIGateStatus.PASSED
        else:
            status = AtomicFCIGateStatus.FAILED
        gates.append(
            AtomicFCIGate(
                candidate_id,
                status,
                len(draws),
                len(valid),
                sum(valid),
                valid_fraction,
                stability,
            )
        )
    return tuple(gates)


def _atomic_variant_result(
    variant: AtomicSelectorVariant,
    universe: AtomicCandidateUniverseManifest,
    plan: AtomicShadowPlan,
    scores: tuple[AtomicRDScore, ...],
    failures: tuple[SelectorFailure, ...],
    fold_sha256: str,
    rd_sha256: str,
    gates: tuple[AtomicFCIGate, ...],
    gate_sha256: str | None,
) -> AtomicShadowVariantResult:
    score_by_candidate = {item.candidate_id: item for item in scores}
    if variant is AtomicSelectorVariant.FULL:
        passed = {
            item.candidate_id
            for item in gates
            if item.status is AtomicFCIGateStatus.PASSED
        }
        rankable = set(score_by_candidate) & passed
    else:
        rankable = set(score_by_candidate)
    ordered = sorted(
        rankable,
        key=lambda candidate_id: (
            -score_by_candidate[candidate_id].absolute_risk_difference,
            candidate_id,
        ),
    )
    ranking = tuple(
        RankedCandidate(
            candidate_id,
            score_by_candidate[candidate_id].absolute_risk_difference,
            rank,
        )
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    slots = []
    gate_statuses = {item.status for item in gates}
    for rank in range(1, universe.top_k + 1):
        if rank <= len(ranking):
            slots.append(
                SelectorSlot(rank, SlotStatus.FILLED, ranking[rank - 1].candidate_id, None)
            )
        elif failures or AtomicFCIGateStatus.NON_EVALUABLE in gate_statuses:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.NON_EVALUABLE,
                    None,
                    "candidate_score_or_fci_gate_non_evaluable",
                )
            )
        elif variant is AtomicSelectorVariant.FULL and gates:
            slots.append(
                SelectorSlot(rank, SlotStatus.GATE_FAILED, None, "fci_gate_exhausted")
            )
        else:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.INSUFFICIENT_CANDIDATES,
                    None,
                    "rankable_universe_smaller_than_k",
                )
            )
    return AtomicShadowVariantResult(
        variant,
        universe.universe_id,
        plan.plan_id,
        fold_sha256,
        rd_sha256,
        gate_sha256,
        ranking,
        tuple(slots),
    )


def freeze_selection(
    universe: CandidateUniverse,
    scores: Mapping[str, float],
    *,
    selector_adapter_id: str,
    top_k: int,
) -> SelectionFreeze:
    candidate_ids = tuple(item.candidate_id for item in universe.candidates)
    if set(scores) != set(candidate_ids):
        raise ValueError("selector scores must bind every candidate exactly once")
    ordered = sorted(
        candidate_ids,
        key=lambda candidate_id: (-_score(scores[candidate_id]), candidate_id),
    )
    ranking = tuple(
        RankedCandidate(candidate_id, _score(scores[candidate_id]), rank)
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    return SelectionFreeze(
        universe.universe_id,
        selector_adapter_id,
        top_k,
        ranking,
    )


def prepare_discovery_population(
    prepared_root: Path,
    clusters_root: Path,
    catalog_path: Path,
    output: Path,
    *,
    scopes: Mapping[str, str],
    language: str = "python",
) -> dict[str, object]:
    """Freeze one natural-Prompt census without reading arms or outcomes.

    ``scopes`` maps a CWE to exactly one catalog task family. Requiring this
    coordinate up front prevents a pre-TSG lexical guess from deciding which
    context query a record should enter.
    """

    verify_bundle(prepared_root)
    verify_bundle(clusters_root)
    if not scopes or any(
        not isinstance(cwe, str)
        or not cwe.strip()
        or not isinstance(task_family, str)
        or not task_family.strip()
        for cwe, task_family in scopes.items()
    ):
        raise ValueError("discovery scopes must map non-empty CWE and task-family strings")
    require_text(language, "language")
    catalog = load_catalog(catalog_path)
    available = {
        (query["cwe_id"], query["task_family"])
        for query in catalog["queries"]
    }
    requested = set(scopes.items())
    if not requested <= available:
        raise ValueError("a discovery scope has no catalog query")

    records = read_json(prepared_root / "records.json")
    clusters = read_json(clusters_root / "semantic-clusters.json")
    if not isinstance(records, list) or not isinstance(clusters, list):
        raise TypeError("discovery source bundles are invalid")
    record_by_id = {record.get("record_id"): record for record in records}
    if len(record_by_id) != len(records) or None in record_by_id:
        raise ValueError("prepared record identities are invalid")

    tasks = []
    for cluster in clusters:
        record = record_by_id.get(cluster.get("representative_record_id"))
        if record is None or record.get("language") != language:
            continue
        cwe = record.get("cwe")
        task_family = scopes.get(cwe)
        if task_family is None:
            continue
        prompt = record.get("prompt")
        cluster_id = cluster.get("cluster_id")
        if not isinstance(prompt, str) or not prompt.strip() or not isinstance(cluster_id, str):
            raise ValueError("discovery representative is incomplete")
        tasks.append(
            {
                "task_id": cluster_id,
                "task_unit_id": cluster_id,
                "record_id": record["record_id"],
                "prompt": prompt,
                "prompt_sha256": record["prompt_sha256"],
                "cwe": cwe,
                "task_family": task_family,
                "source_dataset": record["source_dataset"],
                "source_lineage_family": record["source_lineage_family"],
            }
        )
    tasks.sort(key=lambda item: item["task_unit_id"])
    if not tasks:
        raise ValueError("discovery population is empty")
    if len({task["task_unit_id"] for task in tasks}) != len(tasks):
        raise ValueError("discovery task units are duplicated")

    scope_counts = Counter((task["cwe"], task["task_family"]) for task in tasks)
    lineage_counts = Counter(task["source_lineage_family"] for task in tasks)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "DISCOVERY_POPULATION_FROZEN",
        "language": language,
        "task_units": len(tasks),
        "scope_counts": [
            {"cwe": cwe, "task_family": family, "task_units": count}
            for (cwe, family), count in sorted(scope_counts.items())
        ],
        "lineage_counts": dict(sorted(lineage_counts.items())),
        "prepared_bundle_sha256": bundle_digest(prepared_root),
        "clusters_bundle_sha256": bundle_digest(clusters_root),
        "catalog_sha256": catalog_sha256(catalog),
        "population_implementation_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"tasks.json": tasks, "report.json": report})
    return report


def freeze_task_unit_partition(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    clusters_root: Path,
    catalog_path: Path,
    output: Path,
    *,
    seed: int = 2026083001,
    split_weights: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Freeze an outcome-blind discovery/pilot/confirmation partition.

    The task-side Prompt TSG state is used only for stratification. Diagnostic
    same/uncertain semantic edges are co-located so near-duplicate prompts
    cannot cross analysis partitions even though those edges do not alter ITT
    weights or task-unit identities.
    """

    if type(seed) is not int or seed < 0:
        raise ValueError("partition seed must be a nonnegative integer")
    split_names = ("discovery", "pilot", "confirm")
    supplied_weights = dict(
        split_weights or {"discovery": 6, "pilot": 1, "confirm": 3}
    )
    if (
        set(supplied_weights) != set(split_names)
        or any(
            type(supplied_weights[split]) is not int or supplied_weights[split] <= 0
            for split in split_names
        )
    ):
        raise ValueError("partition weights must be positive discovery/pilot/confirm integers")
    weights = {split: supplied_weights[split] for split in split_names}
    verify_bundle(clusters_root)
    tasks = _task_records(tasks_path)
    if not tasks or len({task.get("task_unit_id") for task in tasks}) != len(tasks):
        raise ValueError("partition tasks are empty or duplicated")
    if any(task.get("task_id") != task.get("task_unit_id") for task in tasks):
        raise ValueError("active task and task-unit identities must coincide")

    catalog = load_catalog(catalog_path)
    graph_records: list[dict[str, object]] = []
    graph_bundle_ids = []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_bundle_ids.append(bundle_digest(bundle))
        raw = read_json(bundle / "graphs.json")
        if not isinstance(raw, list) or any(not isinstance(row, dict) for row in raw):
            raise TypeError("partition Prompt TSG collection is invalid")
        graph_records.extend(raw)
    graph_by_task = {
        graph.task_id: (graph, record)
        for record in graph_records
        for graph in (prompt_tsg_from_record(record),)
    }
    task_ids = {task["task_id"] for task in tasks}
    if len(graph_by_task) != len(graph_records) or set(graph_by_task) != task_ids:
        raise ValueError("partition Prompt TSG population does not exactly match tasks")

    task_by_id = {task["task_unit_id"]: task for task in tasks}
    state_by_task: dict[str, tuple[tuple[str, str, str], ...]] = {}
    for task_id, task in task_by_id.items():
        graph = graph_by_task[task_id][0]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        queries = [
            query
            for query in catalog["queries"]
            if query["cwe_id"] == task["cwe"]
            and query["task_family"] == task["task_family"]
        ]
        if not queries:
            raise ValueError("a partition task has no catalog query")
        state_by_task[task_id] = tuple(
            sorted(
                (
                    query["query_id"],
                    query_context(
                        graph,
                        query=query,
                        cwe=task["cwe"],
                        task_family=task["task_family"],
                    ).state.value,
                    feature_state(graph, query["actionable_feature_id"]).value,
                )
                for query in queries
            )
        )

    clusters = read_json(clusters_root / "semantic-clusters.json")
    diagnostic = read_json(clusters_root / "diagnostic-semantic-edges.json")
    if not isinstance(clusters, list) or not isinstance(diagnostic, list):
        raise TypeError("partition semantic-cluster inputs are invalid")
    cluster_by_record = {}
    for cluster in clusters:
        if not isinstance(cluster, dict) or not isinstance(cluster.get("record_ids"), list):
            raise ValueError("partition semantic cluster is invalid")
        for record_id in cluster["record_ids"]:
            if record_id in cluster_by_record:
                raise ValueError("a record belongs to multiple semantic clusters")
            cluster_by_record[record_id] = cluster["cluster_id"]

    parent = {task_id: task_id for task_id in task_by_id}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            keep, drop = min(left_root, right_root), max(left_root, right_root)
            parent[drop] = keep

    colocated_edges = 0
    outside_edges = 0
    for edge in diagnostic:
        if (
            not isinstance(edge, dict)
            or edge.get("label") not in {"same_cluster", "uncertain"}
        ):
            raise ValueError("partition diagnostic edge is invalid")
        left = cluster_by_record.get(edge.get("left"))
        right = cluster_by_record.get(edge.get("right"))
        if left in parent and right in parent:
            union(left, right)
            colocated_edges += 1
        else:
            outside_edges += 1

    components: dict[str, list[str]] = defaultdict(list)
    for task_id in sorted(task_by_id):
        components[find(task_id)].append(task_id)
    groups = [tuple(sorted(members)) for members in components.values()]
    groups.sort(
        key=lambda members: (
            -len(members),
            hashlib.sha256(
                canonical_json([seed, list(members)]).encode("utf-8")
            ).hexdigest(),
        )
    )

    strata = {
        task_id: canonical_json(
            [
                task_by_id[task_id]["cwe"],
                task_by_id[task_id]["task_family"],
                task_by_id[task_id]["source_lineage_family"],
                state_by_task[task_id],
            ]
        )
        for task_id in task_by_id
    }
    stratum_totals = Counter(strata.values())
    targets = {
        stratum: _partition_targets(total, weights)
        for stratum, total in stratum_totals.items()
    }
    overall_targets = _partition_targets(len(tasks), weights)
    current = {split: Counter() for split in split_names}
    overall = Counter()
    split_by_task = {}
    group_by_task = {}
    for members in groups:
        group_counts = Counter(strata[task_id] for task_id in members)

        def delta(split: str) -> tuple[float, int]:
            penalty = 0.0
            for stratum, count in group_counts.items():
                target = targets[stratum][split]
                before = current[split][stratum] - target
                after = before + count
                penalty += (after * after - before * before) / max(target, 1) ** 2
            target = overall_targets[split]
            before = overall[split] - target
            after = before + len(members)
            # Preserve the predeclared global budget even when many fine
            # strata contain only one task unit and therefore round their
            # pilot target to zero.
            penalty += 10.0 * (after * after - before * before) / max(target, 1) ** 2
            return penalty, split_names.index(split)

        selected = min(split_names, key=delta)
        group_id = content_id("task_partition_group_", members)
        for task_id in members:
            split_by_task[task_id] = selected
            group_by_task[task_id] = group_id
        current[selected].update(group_counts)
        overall[selected] += len(members)

    assignments = []
    split_tasks = {split: [] for split in split_names}
    split_graphs = {split: [] for split in split_names}
    for task_id in sorted(task_by_id):
        task = task_by_id[task_id]
        split = split_by_task[task_id]
        assignments.append(
            {
                "task_id": task_id,
                "task_unit_id": task_id,
                "partition": split,
                "co_location_group_id": group_by_task[task_id],
                "cwe": task["cwe"],
                "task_family": task["task_family"],
                "source_lineage_family": task["source_lineage_family"],
                "query_states": [
                    {
                        "query_id": query_id,
                        "context_state": context_state,
                        "feature_state": source_state,
                    }
                    for query_id, context_state, source_state in state_by_task[task_id]
                ],
                "arms_or_outcomes_used": False,
            }
        )
        split_tasks[split].append(task)
        split_graphs[split].append(graph_by_task[task_id][1])

    if len(assignments) != len(tasks) or any(not split_tasks[split] for split in split_names):
        raise ValueError("partition did not produce three complete non-empty splits")
    if any(
        len({split_by_task[task_id] for task_id in members}) != 1
        for members in groups
    ):
        raise ValueError("a co-location group crossed partitions")
    counts = Counter(item["partition"] for item in assignments)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "TASK_UNIT_PARTITION_FROZEN",
        "task_units": len(tasks),
        "partition_counts": {split: counts[split] for split in split_names},
        "partition_weights": weights,
        "partition_seed": seed,
        "co_location_groups": len(groups),
        "diagnostic_edges_colocated": colocated_edges,
        "diagnostic_edges_outside_population": outside_edges,
        "cross_partition_diagnostic_edges": 0,
        "task_file_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
        "graph_bundle_sha256": sorted(graph_bundle_ids),
        "clusters_bundle_sha256": bundle_digest(clusters_root),
        "catalog_sha256": catalog_sha256(catalog),
        "partition_implementation_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    artifacts: dict[str, object] = {
        "assignments.json": assignments,
        "report.json": report,
    }
    for split in split_names:
        artifacts[f"{split}-tasks.json"] = split_tasks[split]
        artifacts[f"{split}-graphs.json"] = split_graphs[split]
    write_bundle(output, artifacts)
    return report


def _partition_targets(total: int, weights: Mapping[str, int]) -> dict[str, int]:
    denominator = sum(weights.values())
    base = {split: total * weight // denominator for split, weight in weights.items()}
    remainder = total - sum(base.values())
    order = sorted(
        weights,
        key=lambda split: (-(total * weights[split] % denominator), tuple(weights).index(split)),
    )
    for split in order[:remainder]:
        base[split] += 1
    return base


def audit_discovery_positivity(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    catalog_path: Path,
    output: Path,
    *,
    minimum_state_task_units: int = 30,
    minimum_shared_lineages: int = 2,
    graph_artifact: str = "graphs.json",
) -> dict[str, object]:
    """Audit natural feature support before any FCI or outcome is read."""

    if type(minimum_state_task_units) is not int or minimum_state_task_units <= 0:
        raise ValueError("minimum_state_task_units must be positive")
    if type(minimum_shared_lineages) is not int or minimum_shared_lineages <= 0:
        raise ValueError("minimum_shared_lineages must be positive")
    if not graph_bundles:
        raise ValueError("at least one Prompt TSG bundle is required")
    permitted_graph_artifacts = {
        "graphs.json",
        "discovery-graphs.json",
        "pilot-graphs.json",
        "confirm-graphs.json",
    }
    if graph_artifact not in permitted_graph_artifacts:
        raise ValueError("Prompt TSG graph artifact is invalid")
    tasks = _task_records(tasks_path)
    if not tasks or len({task.get("task_id") for task in tasks}) != len(tasks):
        raise ValueError("discovery tasks are empty or duplicated")
    catalog = load_catalog(catalog_path)
    graphs = []
    graph_bundle_ids = []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_bundle_ids.append(bundle_digest(bundle))
        value = read_json(bundle / graph_artifact)
        if not isinstance(value, list):
            raise TypeError("Prompt TSG graph collection is invalid")
        graphs.extend(prompt_tsg_from_record(item) for item in value)
    graph_by_task = {graph.task_id: graph for graph in graphs}
    if len(graph_by_task) != len(graphs) or set(graph_by_task) != {
        task["task_id"] for task in tasks
    }:
        raise ValueError("Prompt TSG population does not exactly match discovery tasks")

    rows: list[dict[str, object]] = []
    for task in tasks:
        required = {
            "task_id",
            "task_unit_id",
            "prompt",
            "cwe",
            "task_family",
            "source_lineage_family",
        }
        if not required <= set(task):
            raise ValueError("a discovery task lacks required coordinates")
        graph = graph_by_task[task["task_id"]]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        queries = [
            query
            for query in catalog["queries"]
            if query["cwe_id"] == task["cwe"]
            and query["task_family"] == task["task_family"]
        ]
        if not queries:
            raise ValueError("a discovery task has no catalog query")
        for query in queries:
            context = query_context(
                graph,
                query=query,
                cwe=task["cwe"],
                task_family=task["task_family"],
            ).state
            state = feature_state(graph, query["actionable_feature_id"])
            context_present = context is QueryState.PRESENT
            resolved_feature = state in {QueryState.PRESENT, QueryState.ABSENT}
            rows.append(
                {
                    "task_id": task["task_id"],
                    "task_unit_id": task["task_unit_id"],
                    "source_lineage_family": task["source_lineage_family"],
                    "cwe": task["cwe"],
                    "task_family": task["task_family"],
                    "query_id": query["query_id"],
                    "feature_id": query["actionable_feature_id"],
                    "context_state": context.value,
                    "source_feature_state": state.value,
                    "discovery_eligible": context_present and resolved_feature,
                    "confirm_add_source_eligible": context_present
                    and state is QueryState.ABSENT,
                    "confirm_remove_source_eligible": context_present
                    and state is QueryState.PRESENT,
                    "confirm_remove_eligible": False,
                    "neutral_counterpart_status": "not_attested",
                }
            )

    support = []
    for query_id in sorted({row["query_id"] for row in rows}):
        query_rows = [row for row in rows if row["query_id"] == query_id]
        context_rows = [row for row in query_rows if row["context_state"] == "present"]
        context_absent = [row for row in query_rows if row["context_state"] == "absent"]
        context_unresolved = [
            row for row in query_rows if row["context_state"] == "unresolved"
        ]
        context_not_applicable = [
            row for row in query_rows if row["context_state"] == "not_applicable"
        ]
        present = [row for row in context_rows if row["source_feature_state"] == "present"]
        absent = [row for row in context_rows if row["source_feature_state"] == "absent"]
        unresolved = [
            row for row in context_rows if row["source_feature_state"] == "unresolved"
        ]
        present_lineages = {row["source_lineage_family"] for row in present}
        absent_lineages = {row["source_lineage_family"] for row in absent}
        shared_lineages = present_lineages & absent_lineages
        reasons = []
        if len(present) < minimum_state_task_units:
            reasons.append("insufficient_present_support")
        if len(absent) < minimum_state_task_units:
            reasons.append("insufficient_absent_support")
        if len(shared_lineages) < minimum_shared_lineages:
            reasons.append("insufficient_source_lineage_overlap")
        first = query_rows[0]
        support.append(
            {
                "query_id": query_id,
                "feature_id": first["feature_id"],
                "cwe": first["cwe"],
                "task_family": first["task_family"],
                "task_units": len(query_rows),
                "context_present": len(context_rows),
                "context_absent": len(context_absent),
                "context_unresolved": len(context_unresolved),
                "context_not_applicable": len(context_not_applicable),
                "feature_present": len(present),
                "feature_absent": len(absent),
                "feature_unresolved": len(unresolved),
                "present_lineages": sorted(present_lineages),
                "absent_lineages": sorted(absent_lineages),
                "shared_lineages": sorted(shared_lineages),
                "positivity_gate_passed": not reasons,
                "failure_reasons": reasons,
            }
        )

    passed = sum(item["positivity_gate_passed"] for item in support)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "POSITIVITY_GATE_PASSED" if passed else "POSITIVITY_GATE_FAILED",
        "task_units": len(tasks),
        "candidate_queries": len(support),
        "passed_queries": passed,
        "minimum_state_task_units": minimum_state_task_units,
        "minimum_shared_lineages": minimum_shared_lineages,
        "task_file_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
        "graph_bundle_sha256": sorted(graph_bundle_ids),
        "graph_artifact": graph_artifact,
        "catalog_sha256": catalog_sha256(catalog),
        "positivity_implementation_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "arms_or_outcomes_used": False,
        "fci_executed": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "report.json": report,
            "positivity-rows.json": rows,
            "support.json": support,
        },
    )
    return report


def discovery_data_sha256(observations: Sequence[DiscoveryObservation]) -> str:
    frozen = tuple(sorted(observations, key=lambda item: item.observation_id))
    if not frozen or len({item.observation_id for item in frozen}) != len(frozen):
        raise ValueError("discovery observations must be non-empty and unique")
    coordinates = {
        (item.task_unit_id, item.model_id, item.family_id, item.request_randomness_slot)
        for item in frozen
    }
    if len(coordinates) != len(frozen):
        raise ValueError("a discovery task/model/family/request coordinate is duplicated")
    return content_hash(frozen)


def freeze_candidate_universe_manifest(
    universe: CandidateUniverse,
    *,
    supported_candidate_ids: Sequence[str],
    realization_policy_ids: Mapping[str, str],
    candidate_family_ids: Mapping[str, str],
    discovery_data_sha256: str,
    positivity_audit_sha256: str,
    information_budget_sha256: str,
    outcome_id: str,
    top_k: int,
) -> CandidateUniverseManifest:
    candidate_ids = tuple(item.candidate_id for item in universe.candidates)
    supported = tuple(sorted(supported_candidate_ids))
    if set(realization_policy_ids) != set(candidate_ids):
        raise ValueError("one realization policy must bind every candidate skeleton")
    if set(candidate_family_ids) != set(candidate_ids):
        raise ValueError("one family must bind every candidate skeleton")
    return CandidateUniverseManifest(
        universe.universe_id,
        candidate_ids,
        supported,
        tuple((candidate_id, realization_policy_ids[candidate_id]) for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        discovery_data_sha256,
        positivity_audit_sha256,
        information_budget_sha256,
        outcome_id,
        top_k,
        universe.representation_adapter_id,
        tuple(
            (
                candidate.candidate_id,
                CandidateSkeletonV2(
                    candidate.candidate_key,
                    candidate.context_query_id,
                    (candidate.actionable_feature_id,),
                    candidate.operation,
                    candidate.cwe,
                    candidate_family_ids[candidate.candidate_id],
                    candidate.outcome_id,
                    candidate.expected_direction,
                    realization_policy_ids[candidate.candidate_id],
                ),
            )
            for candidate in universe.candidates
        ),
    )


def run_selector_suite(
    universe: CandidateUniverseManifest,
    observations: Sequence[DiscoveryObservation],
    plan: SelectorSuitePlan,
    *,
    fci_relation_scores: FrozenFCIRelationScores | None = None,
    expert_input: ExpertRankingInput | None = None,
) -> SelectionFreezeManifest:
    """Run five frozen selectors on one shared, outcome-blind universe.

    FCI may consume independently frozen relation/stability scores.  Without
    those scores its optional backend is imported only after the support gate.
    A failed gate writes a typed closed manifest and performs no selector work.
    """

    if discovery_data_sha256(observations) != universe.discovery_data_sha256:
        raise ValueError("discovery observations drift from the universe manifest")
    if not universe.gate_passed:
        return SelectionFreezeManifest(
            universe,
            plan,
            (),
            (),
            "no_candidate_passed_the_frozen_positivity_gate",
        )
    rows = _reference_observations(observations, plan.model_id)
    supported = universe.supported_candidate_ids
    family_by_candidate = dict(universe.candidate_family_ids)
    expected_by_family: dict[str, set[str]] = {}
    for candidate_id in supported:
        expected_by_family.setdefault(family_by_candidate[candidate_id], set()).add(candidate_id)
    for row in rows:
        if set(dict(row.candidate_states)) != expected_by_family.get(row.family_id, set()):
            raise ValueError("a family-local discovery row does not bind its exact candidate table")
    if {candidate_id for row in rows for candidate_id, _ in row.candidate_states} != set(supported):
        raise ValueError("family-local discovery tables do not cover every supported candidate")

    if plan.behavior_version.endswith("-v2") and fci_relation_scores is not None:
        raise ValueError("prospective selector v2 must recompute FCI and its PAG/BK sensitivities")
    runs, bk_audit = _selector_runs(universe, rows, plan, fci_relation_scores, expert_input)
    sensitivity = (
        _slot_sensitivity_audit(universe, observations, rows, plan, expert_input, runs)
        if plan.behavior_version.endswith("-v2")
        else None
    )
    selected = tuple(
        sorted(
            {
                slot.candidate_id
                for run in runs
                for ranking in run.rankings
                for slot in ranking.slots
                if slot.status is SlotStatus.FILLED and slot.candidate_id is not None
            }
        )
    )
    return SelectionFreezeManifest(universe, plan, runs, selected, None, sensitivity, bk_audit)


def _selector_runs(
    universe: CandidateUniverseManifest,
    rows: tuple[DiscoveryObservation, ...],
    plan: SelectorSuitePlan,
    fci_relation_scores: FrozenFCIRelationScores | None,
    expert_input: ExpertRankingInput | None,
) -> tuple[tuple[SelectorRun, ...], str | None]:
    supported = universe.supported_candidate_ids
    fci, bk_audit = _run_fci_selector(universe, rows, plan, fci_relation_scores)
    association = _run_scored_selector(
        SelectorKind.ASSOCIATION,
        universe,
        plan,
        *_association_scores(rows, supported, dict(universe.candidate_skeletons)),
    )
    prediction = _run_scored_selector(
        SelectorKind.PREDICTION,
        universe,
        plan,
        *_prediction_scores(rows, supported, plan),
    )
    expert = _run_expert_selector(universe, plan, expert_input)
    random_run = _run_random_selector(universe, plan)
    return (fci, association, prediction, expert, random_run), bk_audit


def _slot_sensitivity_audit(
    universe: CandidateUniverseManifest,
    observations: Sequence[DiscoveryObservation],
    fixed_rows: tuple[DiscoveryObservation, ...],
    plan: SelectorSuitePlan,
    expert_input: ExpertRankingInput | None,
    primary_runs: tuple[SelectorRun, ...],
) -> SelectorSensitivityAudit:
    candidates = tuple(item for item in observations if item.model_id == plan.model_id)
    groups: dict[tuple[str, str], tuple[DiscoveryObservation, ...]] = {}
    for family_id, task_unit_id in sorted({(item.family_id, item.task_unit_id) for item in candidates}):
        values = tuple(sorted(
            (item for item in candidates if item.family_id == family_id and item.task_unit_id == task_unit_id),
            key=lambda item: (item.request_randomness_slot, item.observation_id),
        ))
        if len({item.request_randomness_slot for item in values}) < 2:
            raise ValueError("prospective selector v2 requires at least two frozen slots per task unit")
        groups[(family_id, task_unit_id)] = values
    common_slots = tuple(sorted(set.intersection(*(
        {item.request_randomness_slot for item in values} for values in groups.values()
    ))))
    if len(common_slots) < 2:
        raise ValueError("prospective selector v2 lacks common multi-slot support")

    records: list[SelectorSensitivityRanking] = []
    runs_by_analysis: list[tuple[str, str, tuple[SelectorRun, ...]]] = [
        ("fixed_reference", "primary", primary_runs)
    ]
    for seed in plan.random_seeds:
        rng = random.Random(int(content_hash({"plan_id": plan.plan_id, "seed": seed, "domain": "two_level_slot"})[-16:], 16))
        task_units = tuple(sorted({task_unit_id for _, task_unit_id in groups}))
        sampled_units = tuple(task_units[rng.randrange(len(task_units))] for _ in task_units)
        sampled_rows = []
        for occurrence, task_unit_id in enumerate(sampled_units):
            for (family_id, unit), values in sorted(groups.items()):
                if unit != task_unit_id:
                    continue
                chosen = values[rng.randrange(len(values))]
                sampled_rows.append(
                    replace(chosen, task_unit_id=f"two-level-{seed}-{occurrence:05d}:{task_unit_id}")
                )
        rows = tuple(sampled_rows)
        runs_by_analysis.append(("two_level_slot", str(seed), _selector_runs(universe, rows, plan, None, expert_input)[0]))
    for slot in common_slots:
        rows = tuple(next(item for item in values if item.request_randomness_slot == slot) for _, values in sorted(groups.items()))
        runs_by_analysis.append(("multi_slot", str(slot), _selector_runs(universe, rows, plan, None, expert_input)[0]))
    for analysis, replicate, runs in runs_by_analysis:
        for run in runs:
            for ranking in run.rankings:
                records.append(SelectorSensitivityRanking(
                    analysis, replicate, run.selector_id, ranking.label,
                    tuple(item.candidate_id for item in ranking.scores),
                ))
    primary = {(item.selector_id, item.ranking_label): item for item in records if item.analysis == "fixed_reference"}
    stability = []
    for selector_id in sorted({item.selector_id for item in records}):
        values = []
        for item in records:
            if item.selector_id != selector_id or item.analysis == "fixed_reference":
                continue
            reference = primary.get((selector_id, item.ranking_label))
            if reference is None:
                continue
            left = set(reference.ordered_candidate_ids[: universe.top_k])
            right = set(item.ordered_candidate_ids[: universe.top_k])
            values.append(len(left & right) / len(left | right) if left or right else 1.0)
        stability.append((selector_id, sum(values) / len(values) if values else 0.0))
    return SelectorSensitivityAudit(
        content_hash(tuple(sorted(fixed_rows, key=lambda item: item.observation_id))),
        plan.random_seeds, common_slots, tuple(records), tuple(stability),
        tuple(
            (
                f"{family_id}:{task_unit_id}",
                tuple(
                    (
                        candidate_id,
                        sum(dict(item.candidate_states)[candidate_id] for item in values) / len(values),
                    )
                    for candidate_id in sorted(dict(values[0].candidate_states))
                ),
                sum(item.outcome for item in values) / len(values),
            )
            for (family_id, task_unit_id), values in sorted(groups.items())
        ),
    )


def freeze_shared_bridge_map(
    selection: SelectionFreezeManifest,
    records: Sequence[BridgeRecord],
) -> SharedBridgeMap:
    frozen = tuple(sorted(records, key=lambda item: item.candidate_id))
    if tuple(item.candidate_id for item in frozen) != selection.selected_union_candidate_ids:
        raise ValueError("bridge map must cover the unique top-K union exactly once")
    if selection.plan.behavior_version.endswith("-v2"):
        skeleton_by_candidate = dict(selection.universe.candidate_skeletons)
        for record in frozen:
            if record.status is not BridgeStatus.SUCCESS:
                continue
            if (
                record.final_hypothesis is None
                or record.final_hypothesis.skeleton != skeleton_by_candidate[record.candidate_id]
            ):
                raise ValueError("prospective bridge final hypothesis does not preserve its predecessor skeleton")
    return SharedBridgeMap(selection.selection_id, frozen)


def _reference_observations(
    observations: Sequence[DiscoveryObservation],
    model_id: str,
) -> tuple[DiscoveryObservation, ...]:
    candidates = [item for item in observations if item.model_id == model_id]
    if not candidates:
        raise ValueError("selector model has no discovery observations")
    by_unit: dict[tuple[str, str], list[DiscoveryObservation]] = {}
    for item in candidates:
        by_unit.setdefault((item.family_id, item.task_unit_id), []).append(item)
    return tuple(
        min(values, key=lambda item: (item.request_randomness_slot, item.observation_id))
        for _, values in sorted(by_unit.items())
    )


def _run_fci_selector(
    universe: CandidateUniverseManifest,
    rows: tuple[DiscoveryObservation, ...],
    plan: SelectorSuitePlan,
    injected: FrozenFCIRelationScores | None,
) -> tuple[SelectorRun, str | None]:
    if injected is not None:
        if (
            injected.universe_manifest_id != universe.manifest_id
            or injected.selector_plan_id != plan.plan_id
        ):
            raise ValueError("frozen FCI score evidence drifts from the selector suite")
        scores = dict(injected.scores)
        if set(scores) != set(universe.supported_candidate_ids):
            raise ValueError("frozen FCI relation scores must bind every supported candidate")
        evidence = content_hash(
            {
                "source": "frozen_relation_scores",
                "frozen_input_id": injected.input_id,
                "evidence_sha256": injected.evidence_sha256,
                "scores": scores,
            }
        )
        return _run_scored_selector(SelectorKind.FCI, universe, plan, scores, (), evidence), None
    try:
        scores, failures, evidence, audit_json = _lazy_fci_scores(
            rows,
            universe.supported_candidate_ids,
            dict(universe.candidate_family_ids),
            plan,
        )
    except (ImportError, ModuleNotFoundError) as exc:
        return _failed_selector(
            SelectorKind.FCI,
            universe,
            plan,
            "fci_backend_unavailable",
            str(exc) or "causal-learn and numpy are unavailable",
        ), None
    except Exception as exc:  # noqa: BLE001 - backend failure is recorded evidence
        return _failed_selector(
            SelectorKind.FCI,
            universe,
            plan,
            "fci_backend_failed",
            f"{type(exc).__name__}: {exc}",
        ), None
    return _run_scored_selector(SelectorKind.FCI, universe, plan, scores, failures, evidence), audit_json


def _lazy_fci_scores(
    rows: tuple[DiscoveryObservation, ...],
    candidate_ids: tuple[str, ...],
    family_by_candidate: Mapping[str, str],
    plan: SelectorSuitePlan,
) -> tuple[dict[str, float], tuple[SelectorFailure, ...], str, str]:
    actual_version = _causal_learn_version()
    if actual_version != plan.fci_backend_version:
        raise RuntimeError(
            f"causal-learn version {actual_version!r} does not match "
            f"{plan.fci_backend_version!r}"
        )
    scores: dict[str, float] = {}
    evidence = []
    failures = []
    for family_id in sorted(set(family_by_candidate.values())):
        family_candidates = tuple(
            candidate_id
            for candidate_id in candidate_ids
            if family_by_candidate[candidate_id] == family_id
        )
        family_rows = tuple(row for row in rows if row.family_id == family_id)
        covariate_names = tuple(name for name, _ in family_rows[0].covariates)
        if any(
            tuple(name for name, _ in row.covariates) != covariate_names
            for row in family_rows
        ):
            raise ValueError("family-local FCI covariate schemas are inconsistent")
        encoded_covariates = _encode_fci_covariates(family_rows, covariate_names)
        matrix = tuple(
            (
                *encoded_covariates[index],
                *(dict(row.candidate_states)[candidate_id] for candidate_id in family_candidates),
                row.outcome,
            )
            for index, row in enumerate(family_rows)
        )
        outcome_index = len(matrix[0]) - 1
        variable_order = (
            *(f"W:{name}" for name in covariate_names),
            *(f"X:{candidate_id}" for candidate_id in family_candidates),
            "Y:discovery_outcome",
        )
        primary_rules = tuple(
            rule for rule in plan.fci_background_knowledge
            if rule.scope_family_id in {family_id, "*"}
        )
        temporal_rules = tuple(
            rule for rule in primary_rules if rule.provenance_class == "temporal_order"
        )
        domain_rules = tuple(
            rule for rule in primary_rules if rule.provenance_class != "temporal_order"
        )
        wrong_rules = tuple(
            rule for rule in plan.fci_wrong_bk_perturbation
            if rule.scope_family_id in {family_id, "*"}
        )
        if plan.behavior_version.endswith("-v2") and (
            not temporal_rules or not domain_rules or not wrong_rules
        ):
            raise ValueError("prospective selector v2 requires temporal, domain-removal, and wrong-BK rules")
        temporal_pairs = (
            tuple((rule.forbidden_from, rule.forbidden_to) for rule in temporal_rules)
            if temporal_rules
            else tuple((variable_order[-1], name) for name in variable_order[:-1])
        )
        domain_pairs = tuple((rule.forbidden_from, rule.forbidden_to) for rule in domain_rules)
        wrong_pairs = tuple((rule.forbidden_from, rule.forbidden_to) for rule in wrong_rules)
        snapshots = {}
        for label, forbidden in (
            ("raw_minimal", ()),
            ("temporal_only", temporal_pairs),
            ("full_typed", (*temporal_pairs, *domain_pairs)),
            ("wrong_plausible", (*temporal_pairs, *domain_pairs, *wrong_pairs)),
        ):
            adjacent, edges = _run_causal_learn_pag(
                matrix, alpha=plan.fci_alpha, depth=plan.fci_depth,
                max_path_length=plan.fci_max_path_length, outcome_index=outcome_index,
                variable_order=variable_order, forbidden_directions=tuple(forbidden),
            )
            snapshots[label] = {"adjacent": tuple(sorted(adjacent)), "edges": edges}
        removal_snapshots = []
        for removed_family in sorted({rule.bk_family_id for rule in domain_rules}):
            retained = tuple(
                (rule.forbidden_from, rule.forbidden_to)
                for rule in domain_rules if rule.bk_family_id != removed_family
            )
            adjacent, edges = _run_causal_learn_pag(
                matrix, alpha=plan.fci_alpha, depth=plan.fci_depth,
                max_path_length=plan.fci_max_path_length, outcome_index=outcome_index,
                variable_order=variable_order,
                forbidden_directions=(*temporal_pairs, *retained),
            )
            removal_snapshots.append((removed_family, tuple(sorted(adjacent)), edges))
        reference = set(snapshots["full_typed"]["adjacent"])
        feature_offset = len(covariate_names)
        counts = {candidate_id: 0 for candidate_id in family_candidates}
        failure_counts: Counter[str] = Counter()
        rng = random.Random(
            int(
                content_hash(
                    {"plan_id": plan.plan_id, "family_id": family_id, "domain": "fci_bootstrap"}
                )[-16:],
                16,
            )
        )
        for _ in range(plan.fci_bootstrap_draws):
            sampled = tuple(matrix[rng.randrange(len(matrix))] for _ in matrix)
            try:
                adjacent, _edges = _run_causal_learn_pag(
                    sampled, alpha=plan.fci_alpha, depth=plan.fci_depth,
                    max_path_length=plan.fci_max_path_length, outcome_index=outcome_index,
                    variable_order=variable_order,
                    forbidden_directions=(*temporal_pairs, *domain_pairs),
                )
            except Exception as exc:  # noqa: BLE001 - count every backend draw failure
                failure_counts[type(exc).__name__] += 1
                continue
            for index, candidate_id in enumerate(family_candidates):
                counts[candidate_id] += int(feature_offset + index in adjacent)
        failed = sum(failure_counts.values())
        valid_draws = plan.fci_bootstrap_draws - failed
        valid_fraction = valid_draws / plan.fci_bootstrap_draws
        if valid_draws == 0:
            raise RuntimeError(f"all FCI bootstrap draws failed for family {family_id}")
        if failed:
            failures.append(
                SelectorFailure(
                    "fci_bootstrap_failures",
                    f"{failed}/{plan.fci_bootstrap_draws} draws failed in {family_id}",
                )
            )
        if valid_fraction < plan.fci_minimum_valid_fraction:
            failures.extend(
                SelectorFailure(
                    "fci_insufficient_valid_draws",
                    (
                        f"{valid_draws}/{plan.fci_bootstrap_draws} valid draws in "
                        f"{family_id}; minimum fraction is "
                        f"{plan.fci_minimum_valid_fraction}"
                    ),
                    candidate_id,
                )
                for candidate_id in family_candidates
            )
        else:
            scores.update(
                {
                    candidate_id: counts[candidate_id] / valid_draws
                    for candidate_id in family_candidates
                }
            )
        def candidate_support(
            adjacent_indices,
            *,
            candidates=family_candidates,
            offset=feature_offset,
            outcome=outcome_index,
        ):
            return tuple(
                candidates[index - offset]
                for index in adjacent_indices
                if offset <= index < outcome
            )
        full_support = set(candidate_support(snapshots["full_typed"]["adjacent"]))
        change_records = []
        for label, value in sorted(snapshots.items()):
            support = set(candidate_support(value["adjacent"]))
            change_records.append({
                "scheme": label,
                "candidate_ids": tuple(sorted(support)),
                "changed_candidate_ids_vs_full": tuple(sorted(support ^ full_support)),
                "eligibility_changed": support != full_support,
                "rank_change": "not_estimated",
            })
        for removed_family, adjacent_indices, _edges in removal_snapshots:
            support = set(candidate_support(adjacent_indices))
            change_records.append({
                "scheme": f"remove:{removed_family}",
                "candidate_ids": tuple(sorted(support)),
                "changed_candidate_ids_vs_full": tuple(sorted(support ^ full_support)),
                "eligibility_changed": support != full_support,
                "rank_change": "not_estimated",
            })
        evidence.append(
            {
                "family_id": family_id,
                "task_units": len(family_rows),
                "variable_order": variable_order,
                "reference_adjacent_candidates": tuple(
                    candidate_id
                    for index, candidate_id in enumerate(family_candidates)
                    if feature_offset + index in reference
                ),
                "bootstrap_adjacency_counts": tuple(sorted(counts.items())),
                "bootstrap_failure_counts": tuple(sorted(failure_counts.items())),
                "bootstrap_valid_draws": valid_draws,
                "bootstrap_valid_fraction": valid_fraction,
                "minimum_valid_fraction": plan.fci_minimum_valid_fraction,
                "background_knowledge_rules": tuple(canonical_value(rule) for rule in primary_rules),
                "wrong_bk_rules": tuple(canonical_value(rule) for rule in wrong_rules),
                "pag_snapshots": tuple(sorted(snapshots.items())),
                "domain_family_removals": tuple(removal_snapshots),
                "candidate_change_audit": tuple(change_records),
            }
        )
    evidence_sha256 = content_hash(
        {
            "backend": "causal-learn",
            "backend_version": actual_version,
            "ci_test": plan.fci_ci_test,
            "alpha": plan.fci_alpha,
            "depth": plan.fci_depth,
            "max_path_length": plan.fci_max_path_length,
            "bootstrap_draws": plan.fci_bootstrap_draws,
            "minimum_valid_fraction": plan.fci_minimum_valid_fraction,
            "adjacency_threshold": plan.fci_adjacency_threshold,
            "background_knowledge": "typed_raw_temporal_full_removal_wrong_v2",
            "families": evidence,
        }
    )
    return scores, tuple(failures), evidence_sha256, canonical_json({"schema_version": "1.0", "families": evidence})


def _causal_learn_version() -> str:
    from importlib.metadata import version

    return version("causal-learn")


def _encode_fci_covariates(
    rows: tuple[DiscoveryObservation, ...],
    names: tuple[str, ...],
) -> tuple[tuple[int, ...], ...]:
    columns = [
        [dict(row.covariates)[name] for row in rows]
        for name in names
    ]
    codes = [
        {value: index for index, value in enumerate(sorted(set(column)))}
        for column in columns
    ]
    return tuple(
        tuple(codes[column][dict(row.covariates)[name]] for column, name in enumerate(names))
        for row in rows
    )


def _run_causal_learn_family(
    matrix: tuple[tuple[int, ...], ...],
    *,
    alpha: float,
    depth: int,
    max_path_length: int,
    outcome_index: int,
) -> set[int]:
    variable_order = tuple(f"X{index + 1}" for index in range(outcome_index + 1))
    adjacent, _edges = _run_causal_learn_pag(
        matrix, alpha=alpha, depth=depth, max_path_length=max_path_length,
        outcome_index=outcome_index, variable_order=variable_order,
        forbidden_directions=tuple((variable_order[-1], item) for item in variable_order[:-1]),
    )
    return adjacent


def _run_causal_learn_pag(
    matrix: tuple[tuple[int, ...], ...],
    *,
    alpha: float,
    depth: int,
    max_path_length: int,
    outcome_index: int,
    variable_order: tuple[str, ...],
    forbidden_directions: tuple[tuple[str, str], ...],
) -> tuple[set[int], tuple[tuple[str, str, str, str], ...]]:
    import numpy as np  # type: ignore[import-not-found]
    from causallearn.graph.GraphNode import GraphNode  # type: ignore[import-not-found]
    from causallearn.search.ConstraintBased.FCI import fci  # type: ignore[import-not-found]
    from causallearn.utils.PCUtils.BackgroundKnowledge import (  # type: ignore[import-not-found]
        BackgroundKnowledge,
    )

    backend_knowledge = BackgroundKnowledge()
    if len(variable_order) != len(matrix[0]) or len(set(variable_order)) != len(variable_order):
        raise ValueError("FCI variable order does not bind the matrix")
    index_by_name = {name: index for index, name in enumerate(variable_order)}
    for source, target in forbidden_directions:
        if source not in index_by_name or target not in index_by_name or source == target:
            raise ValueError("FCI BK direction references an unknown or identical variable")
        backend_knowledge.add_forbidden_by_node(
            GraphNode(f"X{index_by_name[source] + 1}"),
            GraphNode(f"X{index_by_name[target] + 1}"),
        )
    graph, _edges = fci(
        np.asarray(matrix, dtype=np.int64),
        independence_test_method="gsq",
        alpha=alpha,
        depth=depth,
        max_path_length=max_path_length,
        verbose=False,
        background_knowledge=backend_knowledge,
        show_progress=False,
    )
    nodes = graph.get_nodes()
    adjacent = {
        index
        for index in range(outcome_index)
        if graph.get_edge(nodes[index], nodes[outcome_index]) is not None
    }
    edges = tuple(
        sorted(
            (
                variable_order[nodes.index(edge.get_node1())],
                str(edge.get_endpoint1()),
                variable_order[nodes.index(edge.get_node2())],
                str(edge.get_endpoint2()),
            )
            for edge in graph.get_graph_edges()
        )
    )
    return adjacent, edges


def _association_scores(
    rows: tuple[DiscoveryObservation, ...],
    candidate_ids: tuple[str, ...],
    skeleton_by_id: Mapping[str, CandidateSkeletonV2],
) -> tuple[dict[str, float], tuple[SelectorFailure, ...], str]:
    scores: dict[str, float] = {}
    raw_effects: dict[str, float] = {}
    failures = []
    for candidate_id in candidate_ids:
        skeleton = skeleton_by_id[candidate_id]
        baseline_state = 0 if skeleton.operation is Operation.ADD else 1
        target_state = 1 - baseline_state
        strata: dict[tuple[tuple[str, float], ...], list[DiscoveryObservation]] = {}
        for row in rows:
            if candidate_id not in dict(row.candidate_states):
                continue
            strata.setdefault(row.covariates, []).append(row)
        weighted = 0.0
        support = 0
        for values in strata.values():
            baseline = [
                row.outcome
                for row in values
                if dict(row.candidate_states)[candidate_id] == baseline_state
            ]
            target = [
                row.outcome
                for row in values
                if dict(row.candidate_states)[candidate_id] == target_state
            ]
            if not baseline or not target:
                continue
            baseline_count = len(baseline)
            weighted += baseline_count * (
                sum(target) / len(target) - sum(baseline) / len(baseline)
            )
            support += baseline_count
        if support:
            raw_effect = weighted / support
            raw_effects[candidate_id] = raw_effect
            direction = (
                1.0
                if skeleton.expected_direction is ExpectedDirection.INCREASE
                else -1.0
            )
            scores[candidate_id] = direction * raw_effect
        else:
            failures.append(SelectorFailure("no_conditional_overlap", "no covariate stratum contains both feature states", candidate_id))
    evidence = content_hash(
        {
            "rule": "operation_specific_baseline_standardized_conditional_risk_difference_v3",
            "raw_target_minus_baseline_effects": raw_effects,
            "direction_oriented_scores": scores,
        }
    )
    return scores, tuple(failures), evidence


def _prediction_scores(
    rows: tuple[DiscoveryObservation, ...],
    candidate_ids: tuple[str, ...],
    plan: SelectorSuitePlan,
) -> tuple[dict[str, float], tuple[SelectorFailure, ...], str]:
    scores: dict[str, float] = {}
    failures = []
    for candidate_id in candidate_ids:
        try:
            candidate_rows = tuple(
                row for row in rows if candidate_id in dict(row.candidate_states)
            )
            base_loss, full_loss = _cross_fitted_losses(
                candidate_rows,
                candidate_id,
                float(plan.ridge_lambda),
                plan.prediction_folds,
            )
            scores[candidate_id] = base_loss - full_loss
        except ValueError as exc:
            failures.append(SelectorFailure("prediction_not_estimable", str(exc), candidate_id))
    evidence = content_hash(
        {
            "rule": "hash_fold_fixed_lambda_ridge_log_loss_gain_v1",
            "ridge_lambda": plan.ridge_lambda,
            "folds": plan.prediction_folds,
            "scores": scores,
        }
    )
    return scores, tuple(failures), evidence


def _cross_fitted_losses(
    rows: tuple[DiscoveryObservation, ...],
    candidate_id: str,
    ridge_lambda: float,
    folds: int,
) -> tuple[float, float]:
    fold_by_unit = {
        row.task_unit_id: int(content_hash(row.task_unit_id)[:16], 16) % folds for row in rows
    }
    present_folds = sorted(set(fold_by_unit.values()))
    if len(present_folds) < 2:
        raise ValueError("hash folding produced fewer than two non-empty folds")
    base_total = full_total = 0.0
    count = 0
    for fold in present_folds:
        train = [row for row in rows if fold_by_unit[row.task_unit_id] != fold]
        test = [row for row in rows if fold_by_unit[row.task_unit_id] == fold]
        if not train or not test:
            continue
        base_train, base_test = _design(train, test, None)
        full_train, full_test = _design(train, test, candidate_id)
        labels = [row.outcome for row in train]
        base_prob = _ridge_probabilities(base_train, labels, base_test, ridge_lambda)
        full_prob = _ridge_probabilities(full_train, labels, full_test, ridge_lambda)
        for row, p_base, p_full in zip(test, base_prob, full_prob, strict=True):
            base_total += _log_loss(row.outcome, p_base)
            full_total += _log_loss(row.outcome, p_full)
            count += 1
    if count != len(rows):
        raise ValueError("cross-fitting did not predict every reference task unit")
    return base_total / count, full_total / count


def _design(
    train: Sequence[DiscoveryObservation],
    test: Sequence[DiscoveryObservation],
    candidate_id: str | None,
) -> tuple[list[list[float]], list[list[float]]]:
    covariate_names = tuple(name for name, _ in train[0].covariates)
    if any(tuple(name for name, _ in row.covariates) != covariate_names for row in (*train, *test)):
        raise ValueError("prediction covariate schema is inconsistent")

    def raw(row: DiscoveryObservation) -> list[float]:
        values = [float(value) for _, value in row.covariates]
        if candidate_id is not None:
            values.append(float(dict(row.candidate_states)[candidate_id]))
        return values

    train_raw = [raw(row) for row in train]
    test_raw = [raw(row) for row in test]
    if not train_raw[0]:
        return ([[] for _ in train_raw], [[] for _ in test_raw])
    means = [sum(row[column] for row in train_raw) / len(train_raw) for column in range(len(train_raw[0]))]
    scales = [
        math.sqrt(sum((row[column] - means[column]) ** 2 for row in train_raw) / len(train_raw)) or 1.0
        for column in range(len(train_raw[0]))
    ]
    def normalize(values: list[float]) -> list[float]:
        return [
            (value - means[index]) / scales[index]
            for index, value in enumerate(values)
        ]

    return [normalize(row) for row in train_raw], [normalize(row) for row in test_raw]


def _ridge_probabilities(
    train_x: list[list[float]],
    train_y: list[int],
    test_x: list[list[float]],
    ridge_lambda: float,
) -> list[float]:
    width = (len(train_x[0]) if train_x else 0) + 1
    weights = [0.0] * width
    rows = [[1.0, *values] for values in train_x]
    max_norm = max((sum(value * value for value in row) for row in rows), default=1.0)
    step = 1.0 / (0.25 * max_norm + ridge_lambda + 1.0)
    for _ in range(300):
        gradient = [0.0] * width
        for row, outcome in zip(rows, train_y, strict=True):
            probability = _sigmoid(sum(weight * value for weight, value in zip(weights, row, strict=True)))
            for index, value in enumerate(row):
                gradient[index] += (probability - outcome) * value / len(rows)
        for index in range(1, width):
            gradient[index] += ridge_lambda * weights[index]
        updated = [weight - step * value for weight, value in zip(weights, gradient, strict=True)]
        if max(abs(left - right) for left, right in zip(updated, weights, strict=True)) < 1e-10:
            weights = updated
            break
        weights = updated
    return [
        _sigmoid(weights[0] + sum(weight * value for weight, value in zip(weights[1:], row, strict=True)))
        for row in test_x
    ]


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 700.0)))
    exponential = math.exp(max(value, -700.0))
    return exponential / (1.0 + exponential)


def _log_loss(outcome: int, probability: float) -> float:
    bounded = min(1.0 - 1e-12, max(1e-12, probability))
    return -(outcome * math.log(bounded) + (1 - outcome) * math.log(1.0 - bounded))


def _run_expert_selector(
    universe: CandidateUniverseManifest,
    plan: SelectorSuitePlan,
    expert: ExpertRankingInput | None,
) -> SelectorRun:
    if expert is None:
        return _failed_selector(SelectorKind.EXPERT, universe, plan, "expert_input_missing", "no frozen blinded expert ranking was supplied")
    if expert.universe_manifest_id != universe.manifest_id or expert.model_id != plan.model_id:
        raise ValueError("expert ranking provenance drifts from the shared selector suite")
    if set(expert.ranked_candidate_ids) != set(universe.supported_candidate_ids) or len(expert.ranked_candidate_ids) != len(universe.supported_candidate_ids):
        raise ValueError("expert ranking must contain every supported candidate exactly once")
    scores = tuple(
        RankedCandidate(candidate_id, float(len(expert.ranked_candidate_ids) - rank + 1), rank)
        for rank, candidate_id in enumerate(expert.ranked_candidate_ids, start=1)
    )
    ranking = _ranking_from_ranked(
        "blinded_expert",
        None,
        scores,
        universe.top_k,
        content_hash({"expert_input_id": expert.input_id}),
    )
    return _selector_run(SelectorKind.EXPERT, universe, plan, (ranking,), ())


def _run_random_selector(
    universe: CandidateUniverseManifest,
    plan: SelectorSuitePlan,
) -> SelectorRun:
    rankings = []
    for seed in plan.random_seeds:
        order = list(universe.supported_candidate_ids)
        random.Random(seed).shuffle(order)
        scores = tuple(
            RankedCandidate(candidate_id, float(len(order) - rank + 1), rank)
            for rank, candidate_id in enumerate(order, start=1)
        )
        evidence = content_hash({"seed": seed, "order": order, "rule": "python_mt_shuffle_v1"})
        rankings.append(_ranking_from_ranked(f"seed_{seed}", seed, scores, universe.top_k, evidence))
    return _selector_run(SelectorKind.RANDOM, universe, plan, tuple(rankings), ())


def _run_scored_selector(
    kind: SelectorKind,
    universe: CandidateUniverseManifest,
    plan: SelectorSuitePlan,
    scores: Mapping[str, float],
    failures: tuple[SelectorFailure, ...],
    evidence_sha256: str,
) -> SelectorRun:
    if set(scores) - set(universe.supported_candidate_ids):
        raise ValueError("selector scored a candidate outside the shared supported universe")
    ordered = sorted(scores, key=lambda candidate_id: (-_score(scores[candidate_id]), candidate_id))
    ranked = tuple(
        RankedCandidate(candidate_id, _score(scores[candidate_id]), rank)
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    if not ranked:
        detail = failures[0].detail if failures else "selector produced no finite candidate score"
        return _failed_selector(kind, universe, plan, "no_rankable_candidate", detail)
    ranking = _ranking_from_ranked(kind.value, None, ranked, universe.top_k, evidence_sha256, bool(failures))
    return _selector_run(kind, universe, plan, (ranking,), failures)


def _ranking_from_ranked(
    label: str,
    seed: int | None,
    ranked: tuple[RankedCandidate, ...],
    top_k: int,
    evidence_sha256: str,
    selector_had_failures: bool = False,
) -> SelectorRanking:
    slots = []
    for rank in range(1, top_k + 1):
        if rank <= len(ranked):
            slots.append(SelectorSlot(rank, SlotStatus.FILLED, ranked[rank - 1].candidate_id, None))
        else:
            status = SlotStatus.SELECTOR_FAILED if selector_had_failures else SlotStatus.INSUFFICIENT_CANDIDATES
            reason = "candidate_scoring_failed" if selector_had_failures else "supported_universe_smaller_than_k"
            slots.append(SelectorSlot(rank, status, None, reason))
    return SelectorRanking(label, seed, ranked, tuple(slots), evidence_sha256)


def _selector_run(
    kind: SelectorKind,
    universe: CandidateUniverseManifest,
    plan: SelectorSuitePlan,
    rankings: tuple[SelectorRanking, ...],
    failures: tuple[SelectorFailure, ...],
) -> SelectorRun:
    status = SelectorRunStatus.PARTIAL if failures else SelectorRunStatus.COMPLETE
    adapter_version = "v3" if kind is SelectorKind.ASSOCIATION else "v1"
    return SelectorRun(
        kind,
        f"{kind.value}.{adapter_version}",
        plan.model_id,
        universe.manifest_id,
        universe.discovery_data_sha256,
        plan.plan_id,
        status,
        rankings,
        failures,
    )


def _failed_selector(
    kind: SelectorKind,
    universe: CandidateUniverseManifest,
    plan: SelectorSuitePlan,
    reason_code: str,
    detail: str,
) -> SelectorRun:
    failure = SelectorFailure(reason_code, detail)
    evidence = content_hash(
        {"selector": kind.value, "reason_code": reason_code, "detail": detail}
    )
    ranking = SelectorRanking(
        kind.value,
        None,
        (),
        tuple(
            SelectorSlot(rank, SlotStatus.SELECTOR_FAILED, None, reason_code)
            for rank in range(1, universe.top_k + 1)
        ),
        evidence,
    )
    return SelectorRun(
        kind,
        f"{kind.value}.v1",
        plan.model_id,
        universe.manifest_id,
        universe.discovery_data_sha256,
        plan.plan_id,
        SelectorRunStatus.FAILED,
        (ranking,),
        (failure,),
    )


def _task_records(path: Path) -> list[dict[str, object]]:
    try:
        if path.suffix == ".jsonl":
            value = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        else:
            value = read_json(path)
    except (OSError, UnicodeError, ValueError):
        raise ValueError("discovery task file is unreadable") from None
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("discovery task file must contain a list of objects")
    return value


def _score(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError("selector scores must be finite")
    return float(value)




def _canonical_unique(values: tuple[str, ...], name: str) -> None:
    _canonical_unique_members(values, name)
    if tuple(sorted(values)) != values:
        raise ValueError(f"{name} must use canonical order")


def _canonical_unique_members(values: tuple[str, ...], name: str) -> None:
    if len(set(values)) != len(values) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise ValueError(f"{name} must be unique non-empty strings")


def _validate_numeric_pairs(
    values: tuple[tuple[str, int], ...] | tuple[tuple[str, float], ...],
    name: str,
    *,
    binary: bool,
) -> None:
    keys = tuple(key for key, _ in values)
    _canonical_unique(keys, name)
    for _, value in values:
        if type(value) not in ({int} if binary else {int, float}) or not math.isfinite(float(value)):
            raise ValueError(f"{name} must contain finite numeric values")
        if binary and value not in {0, 1}:
            raise ValueError(f"{name} must contain binary values")


__all__ = [
    "AtomicCandidateFoldManifest",
    "AtomicCandidateUniverseManifest",
    "AtomicFCIBootstrapEvidence",
    "AtomicFCIGate",
    "AtomicFCIGateStatus",
    "AtomicFoldFreeze",
    "AtomicFoldAssignment",
    "AtomicPreOutcomeObservation",
    "AtomicRDScore",
    "AtomicSelectorVariant",
    "AtomicShadowPlan",
    "AtomicShadowQualificationResult",
    "AtomicShadowVariantResult",
    "AtomicSoleDifferenceAudit",
    "BackgroundKnowledgeRule",
    "BridgeRecord",
    "BridgeStatus",
    "CandidateUniverseManifest",
    "CandidateSlotFanout",
    "ConfirmationDispatchManifest",
    "ConfirmationDispatchRecord",
    "DiscoveryObservation",
    "ExpertRankingInput",
    "FrozenFCIRelationScores",
    "FixedSlotLedger",
    "FixedSlotRecord",
    "FixedSlotSource",
    "PolicyTrack",
    "RankedCandidate",
    "SelectionFreeze",
    "SelectionFreezeManifest",
    "SelectorFailure",
    "SelectorKind",
    "SelectorRanking",
    "SelectorRun",
    "SelectorRunStatus",
    "SelectorSensitivityAudit",
    "SelectorSensitivityRanking",
    "SelectorSlot",
    "SelectorSuitePlan",
    "SharedBridgeMap",
    "SharedCandidateUnionEntry",
    "SharedConfirmationUnion",
    "SlotStatus",
    "audit_discovery_positivity",
    "atomic_preoutcome_data_sha256",
    "atomic_preoutcome_observations",
    "discovery_data_sha256",
    "freeze_candidate_universe_manifest",
    "freeze_atomic_candidate_universe",
    "freeze_atomic_candidate_folds",
    "freeze_confirmation_dispatch",
    "freeze_fixed_slot_ledger",
    "freeze_selection",
    "freeze_shared_bridge_map",
    "freeze_shared_confirmation_union",
    "freeze_task_unit_partition",
    "prepare_discovery_population",
    "run_selector_suite",
    "run_atomic_shadow_qualification",
]

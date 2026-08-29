"""Outcome-blind discovery support, selector scores, and top-K slots."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter
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
    Candidate,
    CandidateSkeletonV2,
    CandidateUniverse,
    ExpectedDirection,
    FrozenHypothesisV2,
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
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"tasks.json": tasks, "report.json": report})
    return report


def audit_discovery_positivity(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    catalog_path: Path,
    output: Path,
    *,
    minimum_state_task_units: int = 30,
    minimum_shared_lineages: int = 2,
) -> dict[str, object]:
    """Audit natural feature support before any FCI or outcome is read."""

    if type(minimum_state_task_units) is not int or minimum_state_task_units <= 0:
        raise ValueError("minimum_state_task_units must be positive")
    if type(minimum_shared_lineages) is not int or minimum_shared_lineages <= 0:
        raise ValueError("minimum_shared_lineages must be positive")
    if not graph_bundles:
        raise ValueError("at least one Prompt TSG bundle is required")
    tasks = _task_records(tasks_path)
    if not tasks or len({task.get("task_id") for task in tasks}) != len(tasks):
        raise ValueError("discovery tasks are empty or duplicated")
    catalog = load_catalog(catalog_path)
    graphs = []
    graph_bundle_ids = []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_bundle_ids.append(bundle_digest(bundle))
        value = read_json(bundle / "graphs.json")
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
        "catalog_sha256": catalog_sha256(catalog),
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
        if failed == plan.fci_bootstrap_draws:
            raise RuntimeError(f"all FCI bootstrap draws failed for family {family_id}")
        if failed:
            failures.append(
                SelectorFailure(
                    "fci_bootstrap_failures",
                    f"{failed}/{plan.fci_bootstrap_draws} draws failed in {family_id}",
                )
            )
        scores.update(
            {
                candidate_id: counts[candidate_id] / plan.fci_bootstrap_draws
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
    "BackgroundKnowledgeRule",
    "BridgeRecord",
    "BridgeStatus",
    "CandidateUniverseManifest",
    "DiscoveryObservation",
    "ExpertRankingInput",
    "FrozenFCIRelationScores",
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
    "SlotStatus",
    "audit_discovery_positivity",
    "discovery_data_sha256",
    "freeze_candidate_universe_manifest",
    "freeze_selection",
    "freeze_shared_bridge_map",
    "prepare_discovery_population",
    "run_selector_suite",
]

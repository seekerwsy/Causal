"""Target-schema RQ1 expert and seeded-random selector baselines.

Both baselines consume the same outcome-blind, support-qualified candidate
universe as the Core selector for their track.  They emit ordinary
``FixedSlotSource`` values, so bridge, confirmation, ITT, accounting, and
reporting are shared rather than reimplemented for a baseline-only path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

from prompt_mechanism_study.artifact_io import require_sha256
from prompt_mechanism_study.prioritization import (
    AtomicCandidateUniverseManifest,
    AtomicFoldFreeze,
    AtomicShadowPlan,
    DiscoverabilityStatus,
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
)
from prompt_mechanism_study.records import (
    canonical_json,
    content_hash,
    content_id,
    require_text,
)
from prompt_mechanism_study.representation import (
    AnalysisScope,
    ModelBoundCandidateRecord,
    Operation,
)


class RQ1BaselineKind(StrEnum):
    BLIND_EXPERT = "blind_expert"
    SEEDED_RANDOM = "seeded_random"


_SELECTOR_IDS = {
    (PolicyTrack.ATOMIC, RQ1BaselineKind.BLIND_EXPERT): "atomic_blind_expert",
    (PolicyTrack.ATOMIC, RQ1BaselineKind.SEEDED_RANDOM): "atomic_seeded_random",
}

_EXPERT_VISIBLE_FIELDS = {
    PolicyTrack.ATOMIC: (
        "analysis_scope",
        "candidate_family",
        "factor_operations",
        "mechanism_realization",
        "support_summary",
    )
}

_EXPERT_HIDDEN_FIELDS = (
    "confirmation_assignments",
    "confirmation_outcomes",
    "discovery_outcomes",
    "fci_evidence",
    "rd_scores",
    "relation_evidence",
    "selector_rankings",
)


@dataclass(frozen=True, slots=True)
class BlindExpertCandidateCard:
    """The complete per-candidate information material visible to an expert."""

    track: PolicyTrack
    policy_key: str
    analysis_scope: AnalysisScope
    candidate_family_id: str
    factor_operations: tuple[tuple[str, Operation], ...]
    mechanism_realization_id: str | None
    support_summary: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("expert candidate track must be typed")
        require_text(self.policy_key, "expert candidate policy_key")
        if type(self.analysis_scope) is not AnalysisScope:
            raise TypeError("expert candidate analysis_scope must be typed")
        require_text(self.candidate_family_id, "expert candidate family")
        if not self.factor_operations or any(
            (
                not isinstance(feature_id, str)
                or not feature_id.strip()
                or type(operation) is not Operation
                for feature_id, operation in self.factor_operations
            )
        ):
            raise ValueError("expert candidate factor operations are invalid")
        if tuple((feature_id for feature_id, _ in self.factor_operations)) != tuple(
            sorted((feature_id for feature_id, _ in self.factor_operations))
        ):
            raise ValueError("expert candidate factors must use canonical order")
        if self.support_summary != tuple(sorted(set(self.support_summary))):
            raise ValueError("expert candidate support summary must be canonical")
        if any(
            (
                not isinstance(name, str)
                or not name.strip()
                or type(value) is not int
                or (value < 0)
                for name, value in self.support_summary
            )
        ):
            raise ValueError("expert candidate support summary is invalid")
        require_text(self.mechanism_realization_id, "Atomic expert mechanism realization")
        if len(self.factor_operations) != 1:
            raise ValueError("Atomic expert cards require one factor operation")


@dataclass(frozen=True, slots=True)
class RQ1BaselineUniverse:
    """One model-bound candidate universe shared with a Core selector track."""

    track: PolicyTrack
    source_universe_id: str
    model_id: str
    top_k: int
    candidate_policy_keys: tuple[str, ...]
    eligible_policy_keys: tuple[str, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    expert_candidate_cards: tuple[BlindExpertCandidateCard, ...]
    eligibility_evidence_sha256: str
    protocol_id: str
    schema_version: str

    def __post_init__(self) -> None:
        if type(self.track) is not PolicyTrack:
            raise TypeError("baseline universe track must be typed")
        require_text(self.source_universe_id, "baseline source_universe_id")
        require_text(self.model_id, "baseline model_id")
        if type(self.top_k) is not int or self.top_k <= 0:
            raise ValueError("baseline top_k must be positive")
        if self.candidate_policy_keys != tuple(
            sorted(set(self.candidate_policy_keys))
        ):
            raise ValueError("baseline candidate policies must be canonical")
        if self.eligible_policy_keys != tuple(sorted(set(self.eligible_policy_keys))):
            raise ValueError("baseline eligible policies must be canonical")
        if not set(self.eligible_policy_keys) <= set(self.candidate_policy_keys):
            raise ValueError("baseline eligible policies leave the source universe")
        if tuple(item.policy_key for item in self.model_bound_records) != (
            self.candidate_policy_keys
        ):
            raise ValueError("baseline model-bound records must follow the source universe")
        if any(
            type(item) is not ModelBoundCandidateRecord
            for item in self.model_bound_records
        ):
            raise TypeError("baseline model-bound records must be typed")
        if any(
            type(item) is not BlindExpertCandidateCard
            for item in self.expert_candidate_cards
        ):
            raise TypeError("baseline expert candidate cards must be typed")
        if tuple(item.policy_key for item in self.expert_candidate_cards) != (
            self.eligible_policy_keys
        ):
            raise ValueError("baseline expert cards must follow eligible policy order")
        if {item.track for item in self.expert_candidate_cards} not in (
            set(),
            {self.track},
        ):
            raise ValueError("baseline expert cards must use the universe track")
        if self.model_bound_records and {item.discovery_model_id for item in self.model_bound_records} != {
            self.model_id
        }:
            raise ValueError("baseline records must bind one discovery model")
        require_text(self.protocol_id, "baseline protocol_id")
        require_text(self.schema_version, "baseline schema_version")
        if any(item.protocol_id != self.protocol_id for item in self.model_bound_records):
            raise ValueError("baseline records must bind one protocol")
        if any(item.schema_version != self.schema_version for item in self.model_bound_records):
            raise ValueError("baseline records must bind one schema version")
        require_sha256(
            self.eligibility_evidence_sha256,
            "eligibility_evidence_sha256",
        )

    @property
    def baseline_universe_id(self) -> str:
        return content_id("rq1_baseline_universe_", self)

    @property
    def candidate_material_sha256(self) -> str:
        return content_hash(self.expert_candidate_cards)


def freeze_atomic_baseline_universe(
    universe: AtomicCandidateUniverseManifest,
    fold_freeze: AtomicFoldFreeze,
    plan: AtomicShadowPlan,
    *,
    protocol_id: str,
    schema_version: str,
) -> RQ1BaselineUniverse:
    """Adapt the frozen Atomic common universe without reading RD or FCI evidence."""
    if type(universe) is not AtomicCandidateUniverseManifest:
        raise TypeError("Atomic baseline requires an AtomicCandidateUniverseManifest")
    if type(fold_freeze) is not AtomicFoldFreeze or type(plan) is not AtomicShadowPlan:
        raise TypeError("Atomic baseline requires the frozen common discoverability and plan")
    _check_common_discoverability(universe, fold_freeze, plan)
    eligible = tuple(
        (
            item.candidate_id
            for item in fold_freeze.discoverability
            if item.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE
        )
    )
    policy_by_key = {item.policy_key: item for item in universe.policy_keys}
    family_by_key = dict(universe.candidate_family_ids)
    realization_by_key = dict(universe.realization_policy_ids)
    expert_cards = tuple(
        (
            BlindExpertCandidateCard(
                PolicyTrack.ATOMIC,
                policy_key,
                policy_by_key[policy_key].analysis_scope,
                family_by_key[policy_key],
                (
                    (
                        policy_by_key[policy_key].factor.actionable_feature_id,
                        policy_by_key[policy_key].factor.operation,
                    ),
                ),
                realization_by_key[policy_key],
                (("support_gate_passed", 1),),
            )
            for policy_key in eligible
        )
    )
    return RQ1BaselineUniverse(
        PolicyTrack.ATOMIC,
        universe.universe_id,
        plan.model_id,
        universe.top_k,
        universe.candidate_ids,
        eligible,
        universe.model_bound_records,
        expert_cards,
        content_hash(
            {
                "positivity_audit_sha256": universe.positivity_audit_sha256,
                "information_budget_sha256": universe.information_budget_sha256,
                "discoverability": fold_freeze.discoverability,
                "fold_freeze_id": fold_freeze.fold_freeze_id,
            }
        ),
        protocol_id,
        schema_version,
    )


def _check_common_discoverability(universe, frozen, plan) -> None:
    if (
        frozen.universe_id != universe.universe_id or frozen.plan_id != plan.plan_id
        or frozen.preoutcome_data_sha256 != universe.preoutcome_data_sha256
        or frozen.discovery_population_sha256 != universe.discovery_population_sha256
        or tuple(item.candidate_id for item in frozen.discoverability) != universe.candidate_ids
        or any(item.discovery_model_id != plan.model_id for item in universe.model_bound_records)
    ):
        raise ValueError("baseline common discoverability/model binding drifted from Core")


@dataclass(frozen=True, slots=True)
class BlindExpertRankingCard:
    """A prospectively blinded ordinal ranking over one exact candidate universe."""

    protocol_id: str
    schema_version: str
    track: PolicyTrack
    selector_id: str
    model_id: str
    baseline_universe_id: str
    candidate_material_sha256: str
    visible_information_fields: tuple[str, ...]
    hidden_information_fields: tuple[str, ...]
    ordered_policy_keys: tuple[str, ...]
    expert_identity_sha256: str
    instructions_sha256: str
    independent_review_sha256: str
    completed_before_discovery_outcomes: bool = True
    arms_or_outcomes_used: bool = False

    def __post_init__(self) -> None:
        for value, name in (
            (self.protocol_id, "expert protocol_id"),
            (self.schema_version, "expert schema_version"),
            (self.selector_id, "expert selector_id"),
            (self.model_id, "expert model_id"),
            (self.baseline_universe_id, "expert baseline_universe_id"),
        ):
            require_text(value, name)
        if type(self.track) is not PolicyTrack:
            raise TypeError("expert track must be typed")
        if self.selector_id != _SELECTOR_IDS[
            (self.track, RQ1BaselineKind.BLIND_EXPERT)
        ]:
            raise ValueError("expert selector_id does not match its track")
        if self.visible_information_fields != _EXPERT_VISIBLE_FIELDS[self.track]:
            raise ValueError("expert visible information contract drifted")
        if self.hidden_information_fields != _EXPERT_HIDDEN_FIELDS:
            raise ValueError("expert hidden information contract drifted")
        if len(set(self.ordered_policy_keys)) != len(self.ordered_policy_keys):
            raise ValueError("expert ranking contains duplicate policies")
        for value, name in (
            (self.candidate_material_sha256, "candidate_material_sha256"),
            (self.expert_identity_sha256, "expert_identity_sha256"),
            (self.instructions_sha256, "instructions_sha256"),
            (self.independent_review_sha256, "independent_review_sha256"),
        ):
            require_sha256(value, name)
        if self.completed_before_discovery_outcomes is not True:
            raise ValueError("expert ranking must predate discovery outcome access")
        if self.arms_or_outcomes_used is not False:
            raise ValueError("expert ranking cannot use discovery or confirmation outcomes")

    @property
    def card_id(self) -> str:
        return content_id("blind_expert_ranking_card_", self)


@dataclass(frozen=True, slots=True)
class SeededRandomRankingPlan:
    """A prospectively frozen SHA-256 ordering seed, independent of outcomes."""

    protocol_id: str
    schema_version: str
    track: PolicyTrack
    selector_id: str
    model_id: str
    baseline_universe_id: str
    candidate_material_sha256: str
    ranking_seed: int
    seed_source_sha256: str
    algorithm_id: str = "sha256_seeded_policy_order_v1"
    frozen_before_discovery_outcomes: bool = True
    arms_or_outcomes_used: bool = False

    def __post_init__(self) -> None:
        for value, name in (
            (self.protocol_id, "random protocol_id"),
            (self.schema_version, "random schema_version"),
            (self.selector_id, "random selector_id"),
            (self.model_id, "random model_id"),
            (self.baseline_universe_id, "random baseline_universe_id"),
        ):
            require_text(value, name)
        if type(self.track) is not PolicyTrack:
            raise TypeError("random track must be typed")
        if self.selector_id != _SELECTOR_IDS[
            (self.track, RQ1BaselineKind.SEEDED_RANDOM)
        ]:
            raise ValueError("random selector_id does not match its track")
        if type(self.ranking_seed) is not int:
            raise TypeError("random ranking_seed must be an integer")
        require_sha256(self.candidate_material_sha256, "candidate_material_sha256")
        require_sha256(self.seed_source_sha256, "seed_source_sha256")
        if self.algorithm_id != "sha256_seeded_policy_order_v1":
            raise ValueError("random baseline algorithm drifted")
        if self.frozen_before_discovery_outcomes is not True:
            raise ValueError("random seed must be frozen before discovery outcomes")
        if self.arms_or_outcomes_used is not False:
            raise ValueError("random ranking cannot use discovery or confirmation outcomes")

    @property
    def plan_id(self) -> str:
        return content_id("seeded_random_ranking_plan_", self)


@dataclass(frozen=True, slots=True)
class RQ1BaselineResult:
    kind: RQ1BaselineKind
    baseline_universe_id: str
    provenance_id: str
    ranking_algorithm_id: str
    ordered_policy_keys: tuple[str, ...]
    source: FixedSlotSource

    def __post_init__(self) -> None:
        if type(self.kind) is not RQ1BaselineKind:
            raise TypeError("baseline result kind must be typed")
        require_text(self.baseline_universe_id, "baseline_universe_id")
        require_text(self.provenance_id, "baseline provenance_id")
        require_text(self.ranking_algorithm_id, "baseline ranking_algorithm_id")
        if type(self.source) is not FixedSlotSource:
            raise TypeError("baseline result source must be a FixedSlotSource")
        if self.source.selector_id != _SELECTOR_IDS[(self.source.track, self.kind)]:
            raise ValueError("baseline result selector does not match kind and track")
        if len(set(self.ordered_policy_keys)) != len(self.ordered_policy_keys):
            raise ValueError("baseline result ranking contains duplicates")
        filled = tuple(
            item.candidate_id
            for item in self.source.slots
            if item.status is SlotStatus.FILLED
        )
        if filled != self.ordered_policy_keys[: len(filled)]:
            raise ValueError("baseline slots do not follow the frozen ranking")
        if any(
            item.status is not SlotStatus.INSUFFICIENT_CANDIDATES
            for item in self.source.slots[len(filled) :]
        ):
            raise ValueError("baseline underfill must remain an explicit empty K slot")

    @property
    def result_id(self) -> str:
        return content_id("rq1_baseline_result_", self)


@dataclass(frozen=True, slots=True)
class RQ1BaselineVerificationReceipt:
    result_id: str
    result_sha256: str
    provenance_id: str
    selector_id: str
    status: str
    checks: tuple[str, ...]
    independently_recomputed: bool = True

    def __post_init__(self) -> None:
        for value, name in (
            (self.result_id, "verification result_id"),
            (self.provenance_id, "verification provenance_id"),
            (self.selector_id, "verification selector_id"),
        ):
            require_text(value, name)
        require_sha256(self.result_sha256, "result_sha256")
        if self.status != "PASS":
            raise ValueError("stored baseline verification receipts must pass")
        expected = (
            "candidate_permutation",
            "fixed_k_slots",
            "model_dispatch",
            "outcome_blind_provenance",
            "ranking_replay",
        )
        if self.checks != expected or self.independently_recomputed is not True:
            raise ValueError("baseline verification checks are incomplete")

    @property
    def receipt_id(self) -> str:
        return content_id("rq1_baseline_verification_receipt_", self)


def run_blind_expert_baseline(
    universe: RQ1BaselineUniverse,
    card: BlindExpertRankingCard,
) -> RQ1BaselineResult:
    """Freeze an expert ordering that cannot read discovery/confirmation outcomes."""

    _validate_expert_card(universe, card)
    source = _fixed_source(universe, card.selector_id, card.ordered_policy_keys)
    return RQ1BaselineResult(
        RQ1BaselineKind.BLIND_EXPERT,
        universe.baseline_universe_id,
        card.card_id,
        "blind_expert_ordinal_v1",
        card.ordered_policy_keys,
        source,
    )


def run_seeded_random_baseline(
    universe: RQ1BaselineUniverse,
    plan: SeededRandomRankingPlan,
) -> RQ1BaselineResult:
    """Rank the exact eligible universe by a stable SHA-256 seed order."""

    _validate_random_plan(universe, plan)
    ordered = tuple(
        sorted(
            universe.eligible_policy_keys,
            key=lambda policy_key: (
                _seeded_rank_digest(universe, plan, policy_key),
                policy_key,
            ),
        )
    )
    source = _fixed_source(universe, plan.selector_id, ordered)
    return RQ1BaselineResult(
        RQ1BaselineKind.SEEDED_RANDOM,
        universe.baseline_universe_id,
        plan.plan_id,
        plan.algorithm_id,
        ordered,
        source,
    )


def verify_rq1_baseline_result(
    universe: RQ1BaselineUniverse,
    result: RQ1BaselineResult,
    *,
    expert_card: BlindExpertRankingCard | None = None,
    random_plan: SeededRandomRankingPlan | None = None,
) -> RQ1BaselineVerificationReceipt:
    """Independently replay candidate order, K slots, and model binding."""

    if type(universe) is not RQ1BaselineUniverse:
        raise TypeError("baseline verifier requires an RQ1BaselineUniverse")
    if type(result) is not RQ1BaselineResult:
        raise TypeError("baseline verifier requires an RQ1BaselineResult")
    if (expert_card is None) == (random_plan is None):
        raise ValueError("baseline verifier requires exactly one provenance artifact")
    if expert_card is not None:
        if result.kind is not RQ1BaselineKind.BLIND_EXPERT:
            raise ValueError("expert provenance cannot verify another baseline kind")
        _validate_expert_card(universe, expert_card)
        expected_order = expert_card.ordered_policy_keys
        expected_provenance = expert_card.card_id
        expected_algorithm = "blind_expert_ordinal_v1"
    else:
        assert random_plan is not None
        if result.kind is not RQ1BaselineKind.SEEDED_RANDOM:
            raise ValueError("random provenance cannot verify another baseline kind")
        _validate_random_plan(universe, random_plan)
        keyed = []
        for policy_key in universe.eligible_policy_keys:
            payload = canonical_json(
                {
                    "algorithm_id": "sha256_seeded_policy_order_v1",
                    "baseline_universe_id": universe.baseline_universe_id,
                    "model_id": universe.model_id,
                    "policy_key": policy_key,
                    "ranking_seed": random_plan.ranking_seed,
                    "selector_id": random_plan.selector_id,
                    "track": universe.track.value,
                }
            ).encode("utf-8")
            keyed.append((hashlib.sha256(payload).hexdigest(), policy_key))
        expected_order = tuple(policy_key for _, policy_key in sorted(keyed))
        expected_provenance = random_plan.plan_id
        expected_algorithm = "sha256_seeded_policy_order_v1"
    expected_slots = []
    for rank in range(1, universe.top_k + 1):
        if rank <= len(expected_order):
            expected_slots.append(
                SelectorSlot(rank, SlotStatus.FILLED, expected_order[rank - 1], None)
            )
        else:
            expected_slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.INSUFFICIENT_CANDIDATES,
                    None,
                    "baseline_eligible_universe_smaller_than_k",
                )
            )
    if (
        result.baseline_universe_id != universe.baseline_universe_id
        or result.provenance_id != expected_provenance
        or result.ranking_algorithm_id != expected_algorithm
        or result.ordered_policy_keys != expected_order
        or result.source.track is not universe.track
        or result.source.selector_id
        != _SELECTOR_IDS[(universe.track, result.kind)]
        or result.source.model_id != universe.model_id
        or result.source.universe_id != universe.source_universe_id
        or result.source.slots != tuple(expected_slots)
        or result.source.model_bound_records != universe.model_bound_records
    ):
        raise ValueError("RQ1 baseline result failed independent replay")
    return RQ1BaselineVerificationReceipt(
        result.result_id,
        content_hash(result),
        result.provenance_id,
        result.source.selector_id,
        "PASS",
        (
            "candidate_permutation",
            "fixed_k_slots",
            "model_dispatch",
            "outcome_blind_provenance",
            "ranking_replay",
        ),
    )


def _validate_expert_card(
    universe: RQ1BaselineUniverse,
    card: BlindExpertRankingCard,
) -> None:
    if type(universe) is not RQ1BaselineUniverse:
        raise TypeError("expert baseline requires an RQ1BaselineUniverse")
    if type(card) is not BlindExpertRankingCard:
        raise TypeError("expert baseline requires a BlindExpertRankingCard")
    if (
        card.track is not universe.track
        or card.protocol_id != universe.protocol_id
        or card.schema_version != universe.schema_version
        or card.model_id != universe.model_id
        or card.baseline_universe_id != universe.baseline_universe_id
        or card.candidate_material_sha256 != universe.candidate_material_sha256
        or set(card.ordered_policy_keys) != set(universe.eligible_policy_keys)
        or len(card.ordered_policy_keys) != len(universe.eligible_policy_keys)
    ):
        raise ValueError("expert ranking card drifts from the frozen eligible universe")


def _validate_random_plan(
    universe: RQ1BaselineUniverse,
    plan: SeededRandomRankingPlan,
) -> None:
    if type(universe) is not RQ1BaselineUniverse:
        raise TypeError("random baseline requires an RQ1BaselineUniverse")
    if type(plan) is not SeededRandomRankingPlan:
        raise TypeError("random baseline requires a SeededRandomRankingPlan")
    if (
        plan.track is not universe.track
        or plan.protocol_id != universe.protocol_id
        or plan.schema_version != universe.schema_version
        or plan.model_id != universe.model_id
        or plan.baseline_universe_id != universe.baseline_universe_id
        or plan.candidate_material_sha256 != universe.candidate_material_sha256
    ):
        raise ValueError("random ranking plan drifts from the frozen eligible universe")


def _seeded_rank_digest(
    universe: RQ1BaselineUniverse,
    plan: SeededRandomRankingPlan,
    policy_key: str,
) -> str:
    payload = canonical_json(
        {
            "algorithm_id": plan.algorithm_id,
            "baseline_universe_id": universe.baseline_universe_id,
            "model_id": universe.model_id,
            "policy_key": policy_key,
            "ranking_seed": plan.ranking_seed,
            "selector_id": plan.selector_id,
            "track": universe.track.value,
        }
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _fixed_source(
    universe: RQ1BaselineUniverse,
    selector_id: str,
    ordered_policy_keys: tuple[str, ...],
) -> FixedSlotSource:
    slots = []
    for rank in range(1, universe.top_k + 1):
        if rank <= len(ordered_policy_keys):
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.FILLED,
                    ordered_policy_keys[rank - 1],
                    None,
                )
            )
        else:
            slots.append(
                SelectorSlot(
                    rank,
                    SlotStatus.INSUFFICIENT_CANDIDATES,
                    None,
                    "baseline_eligible_universe_smaller_than_k",
                )
            )
    return FixedSlotSource(
        universe.track,
        selector_id,
        universe.model_id,
        universe.source_universe_id,
        tuple(slots),
        universe.model_bound_records,
    )


__all__ = [
    "BlindExpertCandidateCard",
    "BlindExpertRankingCard",
    "RQ1BaselineKind",
    "RQ1BaselineResult",
    "RQ1BaselineUniverse",
    "RQ1BaselineVerificationReceipt",
    "SeededRandomRankingPlan",
    "freeze_atomic_baseline_universe",
    "run_blind_expert_baseline",
    "run_seeded_random_baseline",
    "verify_rq1_baseline_result",
]

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
    DataRole,
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


class AtomicSelectorVariant(StrEnum):
    FULL = "atomic_full"
    RD_ONLY = "atomic_rd_only"


class AtomicFCIGateStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NON_EVALUABLE = "NON_EVALUABLE"


class CoverageCensusPhase(StrEnum):
    PRE_SUPPLEMENT = "PRE_SUPPLEMENT"
    POST_SUPPLEMENT = "POST_SUPPLEMENT"


class CoverageAcquisitionMode(StrEnum):
    CONTEXT_FIRST = "CONTEXT_FIRST"
    STATE_TARGETED = "STATE_TARGETED"


class SupplementationDecision(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PLANNED = "PLANNED"


class DiscoveryPopulationStatus(StrEnum):
    READY_WITHOUT_SUPPLEMENTATION = "READY_WITHOUT_SUPPLEMENTATION"
    READY_AFTER_ONE_ROUND = "READY_AFTER_ONE_ROUND"
    COVERAGE_BLOCKED = "COVERAGE_BLOCKED"


@dataclass(frozen=True, slots=True)
class CoverageTarget:
    """One outcome-blind context/feature support target for D0."""

    context_query_id: str
    actionable_feature_id: str
    minimum_absent_task_units: int
    minimum_present_task_units: int
    minimum_shared_lineages: int

    def __post_init__(self) -> None:
        require_text(self.context_query_id, "coverage context_query_id")
        require_text(self.actionable_feature_id, "coverage actionable_feature_id")
        for value, name in (
            (self.minimum_absent_task_units, "minimum_absent_task_units"),
            (self.minimum_present_task_units, "minimum_present_task_units"),
            (self.minimum_shared_lineages, "minimum_shared_lineages"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"coverage {name} must be positive")

    @property
    def target_id(self) -> str:
        return content_id("coverage_target_", self)


@dataclass(frozen=True, slots=True)
class PairCoverageTarget:
    """One compatibility-first Pair four-cell coverage target."""

    pair_policy_key: str
    context_query_id: str
    factor_feature_ids: tuple[str, str]
    minimum_cell_task_units: int
    minimum_shared_lineages: int

    def __post_init__(self) -> None:
        require_text(self.pair_policy_key, "Pair coverage policy key")
        require_text(self.context_query_id, "Pair coverage context_query_id")
        if (
            len(self.factor_feature_ids) != 2
            or self.factor_feature_ids != tuple(sorted(set(self.factor_feature_ids)))
        ):
            raise ValueError("Pair coverage factors must be two distinct canonical IDs")
        for value, name in (
            (self.minimum_cell_task_units, "Pair minimum_cell_task_units"),
            (self.minimum_shared_lineages, "Pair minimum_shared_lineages"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"coverage {name} must be positive")

    @property
    def target_id(self) -> str:
        return content_id("pair_coverage_target_", self)


@dataclass(frozen=True, slots=True)
class CoverageTargetProfile:
    """Prospectively frozen limits for one optional D0 supplementation round."""

    protocol_id: str
    schema_version: str
    representation_profile_id: str
    representation_qualification_sha256: str
    catalog_sha256: str
    support_profile_sha256: str
    common_candidate_universe_sha256: str
    targets: tuple[CoverageTarget, ...]
    pair_targets: tuple[PairCoverageTarget, ...]
    permitted_source_families: tuple[str, ...]
    acquisition_mode: CoverageAcquisitionMode
    maximum_source_records: int
    maximum_new_task_units: int
    maximum_review_task_units: int
    maximum_task_units_per_lineage: int
    minimum_source_lineage_diversity: int
    minimum_fillable_atomic_slots: int
    minimum_fillable_pair_slots: int
    maximum_rounds: int = 1
    permitted_data_roles: tuple[DataRole, ...] = (DataRole.DISCOVERY,)
    outcome_blind: bool = True
    selector_blind: bool = True
    natural_independent_tasks_only: bool = True
    candidate_fold_feasibility_required: bool = True
    capacity_recovery_complete: bool = True
    stop_rule: str = "COVERAGE_TARGETS_MET_OR_BUDGET_EXHAUSTED"

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "coverage protocol_id")
        require_text(self.schema_version, "coverage schema_version")
        require_text(self.representation_profile_id, "coverage representation_profile_id")
        _require_digest(
            self.representation_qualification_sha256,
            "representation qualification",
        )
        for value, name in (
            (self.catalog_sha256, "coverage catalog"),
            (self.support_profile_sha256, "coverage support profile"),
            (self.common_candidate_universe_sha256, "common candidate universe"),
        ):
            _require_digest(value, name)
        if not self.targets or any(type(item) is not CoverageTarget for item in self.targets):
            raise TypeError("coverage profile requires typed targets")
        target_keys = tuple(item.target_id for item in self.targets)
        if target_keys != tuple(sorted(set(target_keys))):
            raise ValueError("coverage targets must be unique and canonical")
        pair_target_keys = tuple(item.target_id for item in self.pair_targets)
        if any(type(item) is not PairCoverageTarget for item in self.pair_targets) or pair_target_keys != tuple(
            sorted(set(pair_target_keys))
        ):
            raise ValueError("Pair coverage targets must be typed, unique, and canonical")
        if set(target_keys) & set(pair_target_keys):
            raise ValueError("Atomic and Pair coverage target identities cannot overlap")
        _canonical_unique(self.permitted_source_families, "coverage source families")
        if type(self.acquisition_mode) is not CoverageAcquisitionMode:
            raise TypeError("coverage acquisition mode must be typed")
        for value, name, minimum in (
            (self.maximum_source_records, "maximum_source_records", 0),
            (self.maximum_new_task_units, "maximum_new_task_units", 0),
            (self.maximum_review_task_units, "maximum_review_task_units", 0),
            (self.maximum_task_units_per_lineage, "maximum_task_units_per_lineage", 1),
            (self.minimum_source_lineage_diversity, "minimum_source_lineage_diversity", 1),
            (self.minimum_fillable_atomic_slots, "minimum_fillable_atomic_slots", 0),
            (self.minimum_fillable_pair_slots, "minimum_fillable_pair_slots", 0),
        ):
            if type(value) is not int or value < minimum:
                raise ValueError(f"coverage {name} must be at least {minimum}")
        if self.maximum_new_task_units > self.maximum_source_records:
            raise ValueError("D0 task ceiling cannot exceed its source-record ceiling")
        if self.maximum_new_task_units > self.maximum_review_task_units:
            raise ValueError("D0 task ceiling cannot exceed its review ceiling")
        if self.maximum_rounds != 1:
            raise ValueError("D0 permits exactly one bounded supplementation round")
        if self.permitted_data_roles != (DataRole.DISCOVERY,):
            raise ValueError("D0 supplementation may create DISCOVERY task units only")
        if (
            self.outcome_blind is not True
            or self.selector_blind is not True
            or self.natural_independent_tasks_only is not True
            or self.candidate_fold_feasibility_required is not True
            or self.capacity_recovery_complete is not True
        ):
            raise ValueError("D0 qualification and blindness invariants must all hold")
        if self.stop_rule != "COVERAGE_TARGETS_MET_OR_BUDGET_EXHAUSTED":
            raise ValueError("D0 stop rule cannot permit iterative discretion")

    @property
    def profile_id(self) -> str:
        return content_id("coverage_target_profile_", self)


@dataclass(frozen=True, slots=True)
class CoverageCellSupport:
    target_id: str
    context_task_units: int
    absent_task_units: int
    present_task_units: int
    absent_lineages: tuple[str, ...]
    present_lineages: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.target_id, "coverage target_id")
        for value in (
            self.context_task_units,
            self.absent_task_units,
            self.present_task_units,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("coverage counts must be nonnegative integers")
        for values, name in (
            (self.absent_lineages, "absent lineages"),
            (self.present_lineages, "present lineages"),
        ):
            if values != tuple(sorted(set(values))) or any(
                not isinstance(item, str) or not item.strip() for item in values
            ):
                raise ValueError(f"coverage {name} must be canonical")

    @property
    def shared_lineages(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.absent_lineages) & set(self.present_lineages)))


@dataclass(frozen=True, slots=True)
class PairCoverageCellSupport:
    target_id: str
    cell_task_units: tuple[tuple[str, int], ...]
    cell_lineages: tuple[tuple[str, tuple[str, ...]], ...]

    def __post_init__(self) -> None:
        require_text(self.target_id, "Pair coverage target_id")
        cells = ("00", "01", "10", "11")
        if tuple(cell for cell, _ in self.cell_task_units) != cells or any(
            type(value) is not int or value < 0
            for _, value in self.cell_task_units
        ):
            raise ValueError("Pair coverage counts must contain canonical nonnegative cells")
        if tuple(cell for cell, _ in self.cell_lineages) != cells:
            raise ValueError("Pair coverage lineages must contain canonical cells")
        for _, lineages in self.cell_lineages:
            if lineages != tuple(sorted(set(lineages))) or any(
                not isinstance(item, str) or not item.strip() for item in lineages
            ):
                raise ValueError("Pair coverage lineages must be canonical")

    @property
    def shared_lineages(self) -> tuple[str, ...]:
        lineage_sets = [set(lineages) for _, lineages in self.cell_lineages]
        return tuple(sorted(set.intersection(*lineage_sets)))


@dataclass(frozen=True, slots=True)
class DiscoveryCoverageCensus:
    """A qualified natural-population census that cannot carry outcomes/selectors."""

    profile_id: str
    data_role_manifest_id: str
    task_population_manifest_id: str
    representation_profile_id: str
    catalog_sha256: str
    phase: CoverageCensusPhase
    population_manifest_sha256: str
    representation_qualification_sha256: str
    task_unit_ids: tuple[str, ...]
    cells: tuple[CoverageCellSupport, ...]
    pair_cells: tuple[PairCoverageCellSupport, ...]
    fillable_atomic_candidates: int
    fillable_pair_candidates: int
    fold_feasible_atomic_candidates: int
    fold_feasible_pair_candidates: int
    outcomes_read: bool = False
    selector_evidence_read: bool = False
    relation_evidence_read: bool = False

    def __post_init__(self) -> None:
        require_text(self.profile_id, "coverage census profile_id")
        require_text(self.data_role_manifest_id, "coverage census data_role_manifest_id")
        require_text(
            self.task_population_manifest_id,
            "coverage census task_population_manifest_id",
        )
        require_text(
            self.representation_profile_id,
            "coverage census representation_profile_id",
        )
        _require_digest(self.catalog_sha256, "coverage census catalog")
        if type(self.phase) is not CoverageCensusPhase:
            raise TypeError("coverage census phase must be typed")
        _require_digest(self.population_manifest_sha256, "coverage population manifest")
        _require_digest(
            self.representation_qualification_sha256,
            "coverage representation qualification",
        )
        _canonical_unique(self.task_unit_ids, "coverage task units")
        if tuple(sorted(self.task_unit_ids)) != self.task_unit_ids:
            raise ValueError("coverage task units must use canonical order")
        cell_ids = tuple(item.target_id for item in self.cells)
        if any(type(item) is not CoverageCellSupport for item in self.cells) or cell_ids != tuple(
            sorted(set(cell_ids))
        ):
            raise ValueError("coverage cells must be typed, unique, and canonical")
        pair_cell_ids = tuple(item.target_id for item in self.pair_cells)
        if any(type(item) is not PairCoverageCellSupport for item in self.pair_cells) or pair_cell_ids != tuple(
            sorted(set(pair_cell_ids))
        ):
            raise ValueError("Pair coverage cells must be typed, unique, and canonical")
        if self.outcomes_read or self.selector_evidence_read or self.relation_evidence_read:
            raise ValueError("coverage census cannot read outcomes or selector evidence")
        for value, name in (
            (self.fillable_atomic_candidates, "fillable Atomic candidates"),
            (self.fillable_pair_candidates, "fillable Pair candidates"),
            (self.fold_feasible_atomic_candidates, "fold-feasible Atomic candidates"),
            (self.fold_feasible_pair_candidates, "fold-feasible Pair candidates"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"coverage {name} must be nonnegative")

    @property
    def census_id(self) -> str:
        return content_id("discovery_coverage_census_", self)


@dataclass(frozen=True, slots=True)
class CoverageAcquisitionRequest:
    target_id: str
    requested_context_task_units: int
    requested_absent_task_units: int
    requested_present_task_units: int
    requested_pair_cell_task_units: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        require_text(self.target_id, "coverage request target_id")
        values = (
            self.requested_context_task_units,
            self.requested_absent_task_units,
            self.requested_present_task_units,
        )
        pair_cells = tuple(cell for cell, _ in self.requested_pair_cell_task_units)
        if (
            pair_cells != tuple(sorted(set(pair_cells)))
            or any(cell not in {"00", "01", "10", "11"} for cell in pair_cells)
            or any(
                type(value) is not int or value <= 0
                for _, value in self.requested_pair_cell_task_units
            )
        ):
            raise ValueError("coverage request Pair cells must be positive and canonical")
        if any(type(value) is not int or value < 0 for value in values) or not (
            any(values) or self.requested_pair_cell_task_units
        ):
            raise ValueError("coverage request requires a positive bounded deficit")


@dataclass(frozen=True, slots=True)
class DiscoverySupplementationPlan:
    profile_id: str
    pre_census_id: str
    pre_population_manifest_sha256: str
    decision: SupplementationDecision
    requests: tuple[CoverageAcquisitionRequest, ...]
    existing_capacity_recovered_task_units: tuple[str, ...]
    reservation_manifest_sha256: str
    allowed_source_snapshot_sha256s: tuple[str, ...]
    retrieval_rule_sha256s: tuple[str, ...]
    near_duplicate_rule_sha256: str
    exposure_policy_sha256: str
    role_allocation_rule_sha256: str
    plan_code_commit: str
    coverage_enriched: bool
    round_index: int
    permitted_formal_roles: tuple[DataRole, ...] = (DataRole.DISCOVERY,)
    selector_variant_blind: bool = True
    prohibited_inputs: tuple[str, ...] = (
        "FCI_OR_PAG_EVIDENCE",
        "NATURAL_OUTCOMES",
        "PAIR_RELATION_SUPPORT",
        "RD_SCORES",
        "SELECTOR_MEMBERSHIP_OR_RANK",
    )

    def __post_init__(self) -> None:
        require_text(self.profile_id, "supplementation profile_id")
        require_text(self.pre_census_id, "supplementation pre_census_id")
        _require_digest(self.pre_population_manifest_sha256, "pre-supplement population")
        _require_digest(self.reservation_manifest_sha256, "future-evaluation reservation")
        for values, name in (
            (self.allowed_source_snapshot_sha256s, "allowed source snapshots"),
            (self.retrieval_rule_sha256s, "retrieval rules"),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"D0 {name} must be unique and canonical")
            for value in values:
                _require_digest(value, f"D0 {name}")
        for value, name in (
            (self.near_duplicate_rule_sha256, "D0 near-duplicate rule"),
            (self.exposure_policy_sha256, "D0 exposure policy"),
            (self.role_allocation_rule_sha256, "D0 role-allocation rule"),
        ):
            _require_digest(value, name)
        if (
            not isinstance(self.plan_code_commit, str)
            or len(self.plan_code_commit) != 40
            or any(character not in "0123456789abcdef" for character in self.plan_code_commit)
        ):
            raise ValueError("D0 plan_code_commit must be a lowercase Git SHA")
        if type(self.coverage_enriched) is not bool:
            raise TypeError("D0 coverage_enriched must be boolean")
        if type(self.decision) is not SupplementationDecision:
            raise TypeError("supplementation decision must be typed")
        request_ids = tuple(item.target_id for item in self.requests)
        if any(type(item) is not CoverageAcquisitionRequest for item in self.requests) or request_ids != tuple(
            sorted(set(request_ids))
        ):
            raise ValueError("supplementation requests must be typed and canonical")
        _canonical_unique(
            self.existing_capacity_recovered_task_units,
            "recovered existing task units",
        )
        if tuple(sorted(self.existing_capacity_recovered_task_units)) != self.existing_capacity_recovered_task_units:
            raise ValueError("recovered task units must use canonical order")
        if self.decision is SupplementationDecision.NOT_REQUESTED:
            if (
                self.requests
                or self.round_index != 0
                or self.allowed_source_snapshot_sha256s
                or self.retrieval_rule_sha256s
                or self.coverage_enriched
            ):
                raise ValueError("NOT_REQUESTED supplementation cannot contain a round")
        elif (
            not self.requests
            or self.round_index != 1
            or not self.allowed_source_snapshot_sha256s
            or not self.retrieval_rule_sha256s
        ):
            raise ValueError("planned supplementation must freeze one complete bounded round")
        if self.permitted_formal_roles != (DataRole.DISCOVERY,):
            raise ValueError("D0 tasks may be reserved for DISCOVERY only")
        if self.selector_variant_blind is not True:
            raise ValueError("D0 plan must be selector-variant blind")
        expected_prohibited = (
            "FCI_OR_PAG_EVIDENCE",
            "NATURAL_OUTCOMES",
            "PAIR_RELATION_SUPPORT",
            "RD_SCORES",
            "SELECTOR_MEMBERSHIP_OR_RANK",
        )
        if self.prohibited_inputs != expected_prohibited:
            raise ValueError("D0 prohibited-input boundary cannot be weakened")

    @property
    def supplementation_plan_id(self) -> str:
        return content_id("discovery_supplementation_plan_", self)


class D0ExposureCategory(StrEnum):
    SOURCE_CURATION_VIEWED = "SOURCE_CURATION_VIEWED"
    METHOD_DEVELOPMENT_VIEWED = "METHOD_DEVELOPMENT_VIEWED"
    QUALIFICATION_RESULT_VIEWED = "QUALIFICATION_RESULT_VIEWED"
    GENERATION_OUTCOME_VIEWED = "GENERATION_OUTCOME_VIEWED"


@dataclass(frozen=True, slots=True)
class D0TaskDisposition:
    source_record_id: str
    task_unit_id: str
    near_duplicate_group_id: str
    source_lineage_id: str
    accepted: bool
    disposition: str
    exposure_categories: tuple[D0ExposureCategory, ...]

    def __post_init__(self) -> None:
        for value, name in (
            (self.source_record_id, "D0 source_record_id"),
            (self.task_unit_id, "D0 task_unit_id"),
            (self.near_duplicate_group_id, "D0 near_duplicate_group_id"),
            (self.source_lineage_id, "D0 source_lineage_id"),
            (self.disposition, "D0 task disposition"),
        ):
            require_text(value, name)
        if type(self.accepted) is not bool:
            raise TypeError("D0 task accepted flag must be boolean")
        if any(type(item) is not D0ExposureCategory for item in self.exposure_categories) or self.exposure_categories != tuple(
            sorted(set(self.exposure_categories), key=lambda item: item.value)
        ):
            raise ValueError("D0 exposure categories must be typed and canonical")
        prohibited = {
            D0ExposureCategory.METHOD_DEVELOPMENT_VIEWED,
            D0ExposureCategory.QUALIFICATION_RESULT_VIEWED,
            D0ExposureCategory.GENERATION_OUTCOME_VIEWED,
        }
        if self.accepted and set(self.exposure_categories) & prohibited:
            raise ValueError("accepted D0 Discovery tasks have prohibited exposure")


@dataclass(frozen=True, slots=True)
class DiscoverySupplementationReceipt:
    supplementation_plan_id: str
    round_index: int
    pre_population_manifest_sha256: str
    post_population_manifest_sha256: str
    source_records_retrieved: int
    tasks_accepted: int
    tasks_rejected: int
    acquired_task_unit_ids: tuple[str, ...]
    task_dispositions: tuple[D0TaskDisposition, ...]
    source_provenance_sha256: str
    deduplication_manifest_sha256: str
    contract_quality_readiness_sha256: str
    exposure_records_sha256: str
    data_role_manifest_sha256: str
    execution_code_commit: str
    independent_verifier_status: str
    natural_independent_tasks_only: bool = True
    paraphrases_or_interventions_used: bool = False
    synthetic_cell_filling_used: bool = False

    def __post_init__(self) -> None:
        require_text(self.supplementation_plan_id, "supplementation plan_id")
        if self.round_index != 1:
            raise ValueError("a D0 receipt must represent the single allowed round")
        _require_digest(self.pre_population_manifest_sha256, "D0 pre population")
        _require_digest(self.post_population_manifest_sha256, "D0 post population")
        for value, name in (
            (self.source_records_retrieved, "source records retrieved"),
            (self.tasks_accepted, "tasks accepted"),
            (self.tasks_rejected, "tasks rejected"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"D0 {name} must be nonnegative")
        if self.source_records_retrieved < self.tasks_accepted + self.tasks_rejected:
            raise ValueError("D0 source-record accounting is incomplete")
        _canonical_unique(self.acquired_task_unit_ids, "acquired task units")
        if tuple(sorted(self.acquired_task_unit_ids)) != self.acquired_task_unit_ids:
            raise ValueError("acquired task units must use canonical order")
        disposition_ids = tuple(item.task_unit_id for item in self.task_dispositions)
        if any(type(item) is not D0TaskDisposition for item in self.task_dispositions) or disposition_ids != tuple(
            sorted(set(disposition_ids))
        ):
            raise ValueError("D0 task dispositions must be typed, unique, and canonical")
        accepted_ids = tuple(
            item.task_unit_id for item in self.task_dispositions if item.accepted
        )
        if (
            accepted_ids != self.acquired_task_unit_ids
            or self.tasks_accepted != len(accepted_ids)
            or self.tasks_rejected
            != sum(not item.accepted for item in self.task_dispositions)
        ):
            raise ValueError("D0 accepted/rejected task accounting drifted")
        accepted_groups = tuple(
            item.near_duplicate_group_id
            for item in self.task_dispositions
            if item.accepted
        )
        if len(set(accepted_groups)) != len(accepted_groups):
            raise ValueError("accepted D0 tasks must have independent near-duplicate groups")
        for value, name in (
            (self.source_provenance_sha256, "supplement source provenance"),
            (self.deduplication_manifest_sha256, "supplement deduplication manifest"),
            (self.contract_quality_readiness_sha256, "D0 contract/quality/readiness"),
            (self.exposure_records_sha256, "D0 exposure records"),
            (self.data_role_manifest_sha256, "supplement data-role manifest"),
        ):
            _require_digest(value, name)
        if (
            not isinstance(self.execution_code_commit, str)
            or len(self.execution_code_commit) != 40
            or any(character not in "0123456789abcdef" for character in self.execution_code_commit)
        ):
            raise ValueError("D0 execution_code_commit must be a lowercase Git SHA")
        if self.independent_verifier_status != "PASS":
            raise ValueError("D0 receipt requires independent verification PASS")
        if (
            self.natural_independent_tasks_only is not True
            or self.paraphrases_or_interventions_used
            or self.synthetic_cell_filling_used
        ):
            raise ValueError("D0 receipt admits prohibited synthetic or dependent tasks")

    @property
    def supplementation_receipt_id(self) -> str:
        return content_id("discovery_supplementation_receipt_", self)


@dataclass(frozen=True, slots=True)
class DiscoveryPopulationLineage:
    """The D0/D1 population identity bound by the first formal freeze."""

    profile: CoverageTargetProfile
    pre_census: DiscoveryCoverageCensus
    plan: DiscoverySupplementationPlan
    receipt: DiscoverySupplementationReceipt | None
    post_census: DiscoveryCoverageCensus
    accepted_population_manifest_sha256: str
    status: DiscoveryPopulationStatus

    def __post_init__(self) -> None:
        if type(self.profile) is not CoverageTargetProfile:
            raise TypeError("population lineage requires a coverage profile")
        if type(self.pre_census) is not DiscoveryCoverageCensus or type(
            self.post_census
        ) is not DiscoveryCoverageCensus:
            raise TypeError("population lineage requires typed pre/post censuses")
        if type(self.plan) is not DiscoverySupplementationPlan:
            raise TypeError("population lineage requires a supplementation plan")
        if type(self.status) is not DiscoveryPopulationStatus:
            raise TypeError("population lineage status must be typed")
        target_ids = tuple(item.target_id for item in self.profile.targets)
        pair_target_ids = tuple(item.target_id for item in self.profile.pair_targets)
        if (
            self.pre_census.profile_id != self.profile.profile_id
            or self.post_census.profile_id != self.profile.profile_id
            or self.plan.profile_id != self.profile.profile_id
            or self.pre_census.phase is not CoverageCensusPhase.PRE_SUPPLEMENT
            or self.post_census.phase is not CoverageCensusPhase.POST_SUPPLEMENT
            or self.plan.pre_census_id != self.pre_census.census_id
            or self.plan.pre_population_manifest_sha256
            != self.pre_census.population_manifest_sha256
            or tuple(item.target_id for item in self.pre_census.cells) != target_ids
            or tuple(item.target_id for item in self.post_census.cells) != target_ids
            or tuple(item.target_id for item in self.pre_census.pair_cells)
            != pair_target_ids
            or tuple(item.target_id for item in self.post_census.pair_cells)
            != pair_target_ids
            or self.pre_census.representation_qualification_sha256
            != self.profile.representation_qualification_sha256
            or self.post_census.representation_qualification_sha256
            != self.profile.representation_qualification_sha256
            or self.pre_census.representation_profile_id
            != self.profile.representation_profile_id
            or self.post_census.representation_profile_id
            != self.profile.representation_profile_id
            or self.pre_census.catalog_sha256 != self.profile.catalog_sha256
            or self.post_census.catalog_sha256 != self.profile.catalog_sha256
            or self.pre_census.data_role_manifest_id
            != self.post_census.data_role_manifest_id
        ):
            raise ValueError("D0 population lineage or representation qualification drifted")
        request_ids = {item.target_id for item in self.plan.requests}
        if not request_ids <= set((*target_ids, *pair_target_ids)):
            raise ValueError("D0 supplementation request falls outside the frozen profile")
        if not set(self.plan.existing_capacity_recovered_task_units) <= set(
            self.pre_census.task_unit_ids
        ):
            raise ValueError("recovered existing capacity must precede the formal pre census")
        if self.profile.acquisition_mode is CoverageAcquisitionMode.CONTEXT_FIRST:
            requested = sum(
                item.requested_context_task_units for item in self.plan.requests
            )
            if any(
                item.requested_absent_task_units
                or item.requested_present_task_units
                or item.requested_pair_cell_task_units
                for item in self.plan.requests
            ):
                raise ValueError("context-first D0 cannot target feature states")
        else:
            requested = sum(
                item.requested_absent_task_units
                + item.requested_present_task_units
                + sum(value for _, value in item.requested_pair_cell_task_units)
                for item in self.plan.requests
            )
            if any(item.requested_context_task_units for item in self.plan.requests):
                raise ValueError("state-targeted D0 must disclose its requested states")
        if self.plan.coverage_enriched != (
            self.profile.acquisition_mode is CoverageAcquisitionMode.STATE_TARGETED
        ):
            raise ValueError("D0 enrichment disclosure drifted from acquisition mode")
        if requested > self.profile.maximum_new_task_units:
            raise ValueError("D0 plan exceeds the frozen acquisition ceiling")
        pre_ready = _coverage_targets_met(self.profile, self.pre_census)
        post_ready = _coverage_targets_met(self.profile, self.post_census)
        if pre_ready and self.plan.decision is not SupplementationDecision.NOT_REQUESTED:
            raise ValueError("D0 cannot supplement a population that already meets coverage")
        _require_digest(self.accepted_population_manifest_sha256, "accepted Discovery population")
        if self.post_census.population_manifest_sha256 != self.accepted_population_manifest_sha256:
            raise ValueError("post census does not bind the accepted Discovery population")
        if self.plan.decision is SupplementationDecision.NOT_REQUESTED:
            if (
                self.receipt is not None
                or self.pre_census.task_unit_ids != self.post_census.task_unit_ids
                or self.pre_census.cells != self.post_census.cells
                or self.pre_census.pair_cells != self.post_census.pair_cells
                or self.pre_census.fillable_atomic_candidates
                != self.post_census.fillable_atomic_candidates
                or self.pre_census.fillable_pair_candidates
                != self.post_census.fillable_pair_candidates
                or self.pre_census.fold_feasible_atomic_candidates
                != self.post_census.fold_feasible_atomic_candidates
                or self.pre_census.fold_feasible_pair_candidates
                != self.post_census.fold_feasible_pair_candidates
            ):
                raise ValueError("unsupplemented D0 lineage changed the population")
            expected_status = (
                DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION
                if post_ready
                else DiscoveryPopulationStatus.COVERAGE_BLOCKED
            )
        else:
            if (
                self.plan.decision is not SupplementationDecision.PLANNED
                or type(self.receipt) is not DiscoverySupplementationReceipt
                or self.receipt.supplementation_plan_id
                != self.plan.supplementation_plan_id
                or self.receipt.round_index != self.plan.round_index
                or self.receipt.pre_population_manifest_sha256
                != self.pre_census.population_manifest_sha256
                or self.receipt.post_population_manifest_sha256
                != self.post_census.population_manifest_sha256
                or not set(self.pre_census.task_unit_ids)
                <= set(self.post_census.task_unit_ids)
                or set(self.receipt.acquired_task_unit_ids)
                != set(self.post_census.task_unit_ids) - set(self.pre_census.task_unit_ids)
            ):
                raise ValueError("supplemented D0 lineage is not a single additive natural round")
            if len(self.receipt.acquired_task_unit_ids) > self.profile.maximum_new_task_units:
                raise ValueError("D0 receipt exceeds the frozen acquisition ceiling")
            if self.receipt.source_records_retrieved > self.profile.maximum_source_records:
                raise ValueError("D0 receipt exceeds the frozen source-record ceiling")
            if len(self.receipt.task_dispositions) > self.profile.maximum_review_task_units:
                raise ValueError("D0 receipt exceeds the frozen review ceiling")
            lineage_counts = Counter(
                item.source_lineage_id
                for item in self.receipt.task_dispositions
                if item.accepted
            )
            if (
                len(lineage_counts) < self.profile.minimum_source_lineage_diversity
                or any(
                    count > self.profile.maximum_task_units_per_lineage
                    for count in lineage_counts.values()
                )
            ):
                raise ValueError("D0 receipt violates frozen source-lineage constraints")
            expected_status = (
                DiscoveryPopulationStatus.READY_AFTER_ONE_ROUND
                if post_ready
                else DiscoveryPopulationStatus.COVERAGE_BLOCKED
            )
        if self.status is not expected_status:
            raise ValueError("D0 population status does not match frozen coverage thresholds")

    @property
    def population_lineage_id(self) -> str:
        return content_id("discovery_population_lineage_", self)

    @property
    def formal_discovery_ready(self) -> bool:
        return self.status in {
            DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION,
            DiscoveryPopulationStatus.READY_AFTER_ONE_ROUND,
        }


def _coverage_targets_met(
    profile: CoverageTargetProfile,
    census: DiscoveryCoverageCensus,
) -> bool:
    target_by_id = {item.target_id: item for item in profile.targets}
    cells = {item.target_id: item for item in census.cells}
    pair_cells = {item.target_id: item for item in census.pair_cells}
    cell_support = all(
        cells[target_id].absent_task_units >= target.minimum_absent_task_units
        and cells[target_id].present_task_units >= target.minimum_present_task_units
        and len(cells[target_id].shared_lineages) >= target.minimum_shared_lineages
        for target_id, target in target_by_id.items()
    )
    pair_support = all(
        all(
            count >= target.minimum_cell_task_units
            for _, count in pair_cells[target.target_id].cell_task_units
        )
        and len(pair_cells[target.target_id].shared_lineages)
        >= target.minimum_shared_lineages
        for target in profile.pair_targets
    )
    return (
        cell_support
        and pair_support
        and census.fillable_atomic_candidates >= profile.minimum_fillable_atomic_slots
        and census.fillable_pair_candidates >= profile.minimum_fillable_pair_slots
        and census.fold_feasible_atomic_candidates
        >= profile.minimum_fillable_atomic_slots
        and census.fold_feasible_pair_candidates
        >= profile.minimum_fillable_pair_slots
    )


class CandidateKind(StrEnum):
    ATOMIC = "ATOMIC"
    PAIR = "PAIR"


class DiscoverabilityStatus(StrEnum):
    DISCOVERY_ELIGIBLE = "DISCOVERY_ELIGIBLE"
    DISCOVERY_INELIGIBLE = "DISCOVERY_INELIGIBLE"


class DiscoverabilityReason(StrEnum):
    ATOMIC_NATURAL_SUPPORT_FAILED = "ATOMIC_NATURAL_SUPPORT_FAILED"
    FACTORIAL_INCOMPATIBLE = "FACTORIAL_INCOMPATIBLE"
    MISSING_OBSERVATIONS = "MISSING_OBSERVATIONS"
    DUPLICATE_TASK_UNIT = "DUPLICATE_TASK_UNIT"
    CANDIDATE_COORDINATE_MISMATCH = "CANDIDATE_COORDINATE_MISMATCH"
    CONTEXT_NOT_PRESENT = "CONTEXT_NOT_PRESENT"
    COVARIATE_SCHEMA_MISMATCH = "COVARIATE_SCHEMA_MISMATCH"
    EXTRACTOR_RELIABILITY_BELOW_THRESHOLD = "EXTRACTOR_RELIABILITY_BELOW_THRESHOLD"
    FACTOR_STATE_NOT_BINARY = "FACTOR_STATE_NOT_BINARY"
    INSUFFICIENT_FOUR_CELL_SUPPORT = "INSUFFICIENT_FOUR_CELL_SUPPORT"
    INSUFFICIENT_SOURCE_LINEAGE_OVERLAP = "INSUFFICIENT_SOURCE_LINEAGE_OVERLAP"
    LANGUAGE_NONOVERLAP = "LANGUAGE_NONOVERLAP"
    ARCHETYPE_NONOVERLAP = "ARCHETYPE_NONOVERLAP"
    API_FAMILY_NONOVERLAP = "API_FAMILY_NONOVERLAP"
    FOLD_NON_EVALUABLE = "FOLD_NON_EVALUABLE"


@dataclass(frozen=True, slots=True)
class CandidateCoverageSummary:
    """Outcome-blind candidate-level counts; insufficiency is not a null effect."""

    candidate_id: str
    candidate_kind: CandidateKind
    state_or_cell_task_units: tuple[tuple[str, int], ...]
    unique_source_lineages: int
    near_duplicate_safe_task_units: int
    representation_resolved_task_units: int
    total_task_units: int
    oracle_ready_task_units: int
    confirmation_baseline_task_units: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "coverage-summary candidate_id")
        if type(self.candidate_kind) is not CandidateKind:
            raise TypeError("coverage-summary candidate kind must be typed")
        expected_cells = (
            ("0", "1")
            if self.candidate_kind is CandidateKind.ATOMIC
            else ("00", "01", "10", "11")
        )
        if tuple(cell for cell, _ in self.state_or_cell_task_units) != expected_cells:
            raise ValueError("candidate coverage cells do not match Atomic/Pair kind")
        if any(
            type(value) is not int or value < 0
            for _, value in self.state_or_cell_task_units
        ):
            raise ValueError("candidate coverage counts must be nonnegative")
        for value, name in (
            (self.unique_source_lineages, "unique source lineages"),
            (self.near_duplicate_safe_task_units, "near-duplicate-safe task units"),
            (self.representation_resolved_task_units, "representation-resolved task units"),
            (self.total_task_units, "total task units"),
            (self.oracle_ready_task_units, "Oracle-ready task units"),
            (self.confirmation_baseline_task_units, "confirmation baseline task units"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"candidate coverage {name} must be nonnegative")
        if sum(value for _, value in self.state_or_cell_task_units) != self.total_task_units:
            raise ValueError("candidate state/cell counts must sum to total task units")
        if any(
            value > self.total_task_units
            for value in (
                self.unique_source_lineages,
                self.near_duplicate_safe_task_units,
                self.representation_resolved_task_units,
                self.oracle_ready_task_units,
                self.confirmation_baseline_task_units,
            )
        ):
            raise ValueError("candidate coverage diagnostics cannot exceed total task units")

    @property
    def representation_resolved_rate(self) -> float:
        return (
            0.0
            if self.total_task_units == 0
            else self.representation_resolved_task_units / self.total_task_units
        )


@dataclass(frozen=True, slots=True)
class DiscoverabilityDecision:
    """Shared outcome-blind Atomic/Pair candidate eligibility record."""

    candidate_id: str
    candidate_kind: CandidateKind
    discovery_population_sha256: str
    universe_id: str
    support_evidence_sha256: str
    fold_evidence_sha256: str
    coverage_summary: CandidateCoverageSummary
    status: DiscoverabilityStatus
    reasons: tuple[DiscoverabilityReason, ...]

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "discoverability candidate_id")
        if type(self.candidate_kind) is not CandidateKind:
            raise TypeError("discoverability candidate kind must be typed")
        require_text(self.universe_id, "discoverability universe_id")
        for value, name in (
            (self.discovery_population_sha256, "discoverability population"),
            (self.support_evidence_sha256, "discoverability support evidence"),
            (self.fold_evidence_sha256, "discoverability fold evidence"),
        ):
            _require_digest(value, name)
        if type(self.status) is not DiscoverabilityStatus or any(
            type(item) is not DiscoverabilityReason for item in self.reasons
        ):
            raise TypeError("discoverability status and reasons must be typed")
        if (
            type(self.coverage_summary) is not CandidateCoverageSummary
            or self.coverage_summary.candidate_id != self.candidate_id
            or self.coverage_summary.candidate_kind is not self.candidate_kind
        ):
            raise ValueError("discoverability coverage summary drifted from candidate identity")
        if self.reasons != tuple(sorted(set(self.reasons), key=lambda item: item.value)):
            raise ValueError("discoverability reasons must be unique and canonical")
        if self.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE:
            if self.reasons:
                raise ValueError("a discoverable candidate cannot have failure reasons")
        elif not self.reasons:
            raise ValueError("a non-discoverable candidate requires failure reasons")


@dataclass(frozen=True, slots=True)
class AtomicCandidateUniverseManifest:
    """Direction-neutral v3 Atomic universe used by both Core variants."""

    policy_keys: tuple[AtomicPolicyKey, ...]
    supported_policy_keys: tuple[str, ...]
    coverage_summaries: tuple[CandidateCoverageSummary, ...]
    model_bound_records: tuple[ModelBoundCandidateRecord, ...]
    realization_policy_ids: tuple[tuple[str, str], ...]
    candidate_family_ids: tuple[tuple[str, str], ...]
    discovery_data_sha256: str
    discovery_population_sha256: str
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
        if tuple(item.candidate_id for item in self.coverage_summaries) != candidate_ids or any(
            type(item) is not CandidateCoverageSummary
            or item.candidate_kind is not CandidateKind.ATOMIC
            for item in self.coverage_summaries
        ):
            raise ValueError("Atomic coverage summaries must exactly follow the universe")
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
            (self.discovery_population_sha256, "Atomic Discovery population"),
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
    discovery_population_sha256: str
    manifests: tuple[AtomicCandidateFoldManifest, ...]
    failures: tuple[SelectorFailure, ...]
    discoverability: tuple[DiscoverabilityDecision, ...]

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
        _require_digest(
            self.discovery_population_sha256,
            "Atomic fold-freeze Discovery population",
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
        decision_ids = tuple(item.candidate_id for item in self.discoverability)
        if decision_ids != tuple(sorted(set(decision_ids))) or any(
            type(item) is not DiscoverabilityDecision
            or item.candidate_kind is not CandidateKind.ATOMIC
            or item.discovery_population_sha256 != self.discovery_population_sha256
            or item.universe_id != self.universe_id
            for item in self.discoverability
        ):
            raise ValueError("Atomic discoverability decisions are not canonical or bound")
        discoverable = {
            item.candidate_id
            for item in self.discoverability
            if item.status is DiscoverabilityStatus.DISCOVERY_ELIGIBLE
        }
        if discoverable != set(manifest_ids):
            raise ValueError("Atomic discoverability must exactly match frozen fold support")

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


def freeze_atomic_candidate_universe(
    policy_keys: Sequence[AtomicPolicyKey],
    model_bound_records: Sequence[ModelBoundCandidateRecord],
    *,
    supported_policy_keys: Sequence[str],
    coverage_summaries: Mapping[str, CandidateCoverageSummary],
    realization_policy_ids: Mapping[str, str],
    candidate_family_ids: Mapping[str, str],
    discovery_data_sha256: str,
    discovery_population_sha256: str,
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
    if set(coverage_summaries) != set(candidate_ids):
        raise ValueError("Atomic coverage summaries must bind every policy exactly once")
    return AtomicCandidateUniverseManifest(
        ordered_keys,
        tuple(sorted(supported_policy_keys)),
        tuple(coverage_summaries[candidate_id] for candidate_id in candidate_ids),
        tuple(records_by_key[candidate_id] for candidate_id in candidate_ids),
        tuple((candidate_id, realization_policy_ids[candidate_id]) for candidate_id in candidate_ids),
        tuple((candidate_id, candidate_family_ids[candidate_id]) for candidate_id in candidate_ids),
        discovery_data_sha256,
        discovery_population_sha256,
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
    frozen_manifests = tuple(sorted(manifests, key=lambda item: item.candidate_id))
    frozen_failures = tuple(
        sorted(
            failures,
            key=lambda item: (item.candidate_id or "", item.reason_code),
        )
    )
    manifest_by_id = {item.candidate_id: item for item in frozen_manifests}
    failure_by_id = {item.candidate_id: item for item in frozen_failures}
    coverage_by_id = {
        item.candidate_id: item for item in universe.coverage_summaries
    }
    supported = set(universe.supported_policy_keys)
    discoverability = []
    for candidate_id in universe.candidate_ids:
        coverage = coverage_by_id[candidate_id]
        manifest = manifest_by_id.get(candidate_id)
        if manifest is not None:
            fold_counts = Counter(
                str(item.target_state) for item in manifest.assignments
            )
            if coverage.state_or_cell_task_units != (
                ("0", fold_counts["0"]),
                ("1", fold_counts["1"]),
            ):
                raise ValueError("Atomic coverage summary drifted from outcome-blind folds")
        reasons = []
        if candidate_id not in supported:
            reasons.append(DiscoverabilityReason.ATOMIC_NATURAL_SUPPORT_FAILED)
        if candidate_id in failure_by_id:
            reasons.append(DiscoverabilityReason.FOLD_NON_EVALUABLE)
        fold_evidence = manifest or failure_by_id.get(candidate_id) or {
            "candidate_id": candidate_id,
            "fold_status": "NOT_ATTEMPTED_SUPPORT_FAILED",
        }
        discoverability.append(
            DiscoverabilityDecision(
                candidate_id,
                CandidateKind.ATOMIC,
                universe.discovery_population_sha256,
                universe.universe_id,
                universe.positivity_audit_sha256,
                content_hash(fold_evidence),
                coverage,
                (
                    DiscoverabilityStatus.DISCOVERY_ELIGIBLE
                    if not reasons
                    else DiscoverabilityStatus.DISCOVERY_INELIGIBLE
                ),
                tuple(sorted(reasons, key=lambda item: item.value)),
            )
        )
    return AtomicFoldFreeze(
        universe.universe_id,
        plan.plan_id,
        atomic_preoutcome_data_sha256(observations),
        universe.discovery_population_sha256,
        frozen_manifests,
        frozen_failures,
        tuple(discoverability),
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
    "AtomicFoldAssignment",
    "AtomicFoldFreeze",
    "AtomicPreOutcomeObservation",
    "AtomicRDScore",
    "AtomicSelectorVariant",
    "AtomicShadowPlan",
    "AtomicShadowQualificationResult",
    "AtomicShadowVariantResult",
    "AtomicSoleDifferenceAudit",
    "BridgeStatus",
    "CandidateKind",
    "CandidateCoverageSummary",
    "CandidateSlotFanout",
    "CoverageAcquisitionMode",
    "CoverageAcquisitionRequest",
    "CoverageCellSupport",
    "CoverageCensusPhase",
    "CoverageTarget",
    "CoverageTargetProfile",
    "D0ExposureCategory",
    "D0TaskDisposition",
    "ConfirmationDispatchManifest",
    "ConfirmationDispatchRecord",
    "DiscoveryObservation",
    "DiscoveryCoverageCensus",
    "DiscoveryPopulationLineage",
    "DiscoveryPopulationStatus",
    "DiscoverySupplementationPlan",
    "DiscoverySupplementationReceipt",
    "DiscoverabilityDecision",
    "DiscoverabilityReason",
    "DiscoverabilityStatus",
    "FixedSlotLedger",
    "FixedSlotRecord",
    "FixedSlotSource",
    "PolicyTrack",
    "PairCoverageCellSupport",
    "PairCoverageTarget",
    "RankedCandidate",
    "SelectorFailure",
    "SelectorSlot",
    "SharedCandidateUnionEntry",
    "SharedConfirmationUnion",
    "SlotStatus",
    "SupplementationDecision",
    "atomic_preoutcome_data_sha256",
    "atomic_preoutcome_observations",
    "audit_discovery_positivity",
    "discovery_data_sha256",
    "freeze_atomic_candidate_folds",
    "freeze_atomic_candidate_universe",
    "freeze_confirmation_dispatch",
    "freeze_fixed_slot_ledger",
    "freeze_shared_confirmation_union",
    "freeze_task_unit_partition",
    "prepare_discovery_population",
    "run_atomic_shadow_qualification",
]

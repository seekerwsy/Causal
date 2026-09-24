"""Outcome-blind source population, role allocation and optional D0 supplementation."""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    require_sha256 as _require_digest,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    QueryState,
    catalog_sha256,
    feature_scope_from_record,
    load_catalog,
    prompt_tsg_from_record,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text
from prompt_mechanism_study.tsg.representation import DataRole, DataRoleManifest
from prompt_mechanism_study.records import require_ordered_strings as _canonical_unique


class CoverageCensusPhase(StrEnum):
    PRE_SUPPLEMENT = "PRE_SUPPLEMENT"
    POST_SUPPLEMENT = "POST_SUPPLEMENT"


class CoverageAcquisitionMode(StrEnum):
    CONTEXT_FIRST = "CONTEXT_FIRST"


class SupplementationDecision(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PLANNED = "PLANNED"


class DiscoveryPopulationStatus(StrEnum):
    READY_WITHOUT_SUPPLEMENTATION = "READY_WITHOUT_SUPPLEMENTATION"
    READY_AFTER_ONE_ROUND = "READY_AFTER_ONE_ROUND"
    COVERAGE_GAPS_RETAINED = "COVERAGE_GAPS_RETAINED"


@dataclass(frozen=True, slots=True)
class CoverageTarget:
    """A feature-invariant context and its prospective task-unit coverage target."""

    context_query_id: str
    minimum_context_task_units: int

    def __post_init__(self) -> None:
        require_text(self.context_query_id, "coverage context_query_id")
        if type(self.minimum_context_task_units) is not int or self.minimum_context_task_units <= 0:
            raise ValueError("minimum_context_task_units must be positive")

    @property
    def target_id(self) -> str:
        return content_id("coverage_target_", self)


@dataclass(frozen=True, slots=True)
class CoverageTargetProfile:
    """Prospectively frozen limits for one optional D0 supplementation round."""

    protocol_id: str
    schema_version: str
    representation_profile_id: str
    representation_qualification_sha256: str
    catalog_sha256: str
    targets: tuple[CoverageTarget, ...]
    permitted_source_families: tuple[str, ...]
    acquisition_mode: CoverageAcquisitionMode
    maximum_source_records: int
    maximum_new_task_units: int
    maximum_review_task_units: int
    maximum_task_units_per_lineage: int
    minimum_source_lineage_diversity: int
    maximum_rounds: int = 1
    permitted_data_roles: tuple[DataRole, ...] = (DataRole.DISCOVERY,)
    outcome_blind: bool = True
    selector_blind: bool = True
    natural_independent_tasks_only: bool = True
    capacity_recovery_complete: bool = True
    stop_rule: str = "CONTEXT_TARGETS_MET_OR_BUDGET_OR_SOURCES_EXHAUSTED"

    def __post_init__(self) -> None:
        require_text(self.protocol_id, "coverage protocol_id")
        if self.schema_version != "4.0":
            raise ValueError("context-only D0 requires schema 4.0; old records are archival")
        require_text(self.representation_profile_id, "coverage representation_profile_id")
        _require_digest(
            self.representation_qualification_sha256,
            "representation qualification",
        )
        for value, name in (
            (self.catalog_sha256, "coverage catalog"),
        ):
            _require_digest(value, name)
        if not self.targets or any(type(item) is not CoverageTarget for item in self.targets):
            raise TypeError("coverage profile requires typed targets")
        target_keys = tuple(item.target_id for item in self.targets)
        if target_keys != tuple(sorted(set(target_keys))):
            raise ValueError("coverage targets must be unique and canonical")
        if len({item.context_query_id for item in self.targets}) != len(self.targets):
            raise ValueError("D0 contexts must be unique")
        _canonical_unique(self.permitted_source_families, "coverage source families")
        if type(self.acquisition_mode) is not CoverageAcquisitionMode:
            raise TypeError("coverage acquisition mode must be typed")
        for value, name, minimum in (
            (self.maximum_source_records, "maximum_source_records", 0),
            (self.maximum_new_task_units, "maximum_new_task_units", 0),
            (self.maximum_review_task_units, "maximum_review_task_units", 0),
            (self.maximum_task_units_per_lineage, "maximum_task_units_per_lineage", 1),
            (self.minimum_source_lineage_diversity, "minimum_source_lineage_diversity", 1),
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
            or self.capacity_recovery_complete is not True
        ):
            raise ValueError("D0 qualification and blindness invariants must all hold")
        if self.stop_rule != "CONTEXT_TARGETS_MET_OR_BUDGET_OR_SOURCES_EXHAUSTED":
            raise ValueError("D0 stop rule cannot permit iterative discretion")

    @property
    def profile_id(self) -> str:
        return content_id("coverage_target_profile_", self)


@dataclass(frozen=True, slots=True)
class CoverageCellSupport:
    target_id: str
    context_task_units: int
    unresolved_task_units: int = 0

    def __post_init__(self) -> None:
        require_text(self.target_id, "coverage target_id")
        if any(type(n) is not int or n < 0 for n in (self.context_task_units, self.unresolved_task_units)):
            raise ValueError("coverage counts must be nonnegative integers")


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
        if self.outcomes_read or self.selector_evidence_read or self.relation_evidence_read:
            raise ValueError("coverage census cannot read outcomes or selector evidence")
        if any(cell.context_task_units + cell.unresolved_task_units > len(self.task_unit_ids) for cell in self.cells):
            raise ValueError("coverage cannot count multiple instances as independent task units")

    @property
    def census_id(self) -> str:
        return content_id("discovery_coverage_census_", self)


@dataclass(frozen=True, slots=True)
class CoverageAcquisitionRequest:
    target_id: str
    requested_context_task_units: int

    def __post_init__(self) -> None:
        require_text(self.target_id, "coverage request target_id")
        if type(self.requested_context_task_units) is not int or self.requested_context_task_units <= 0:
            raise ValueError("coverage request requires a positive context deficit")


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
        "FEATURE_STATES_OR_PAIR_CELLS",
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
        "FEATURE_STATES_OR_PAIR_CELLS",
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
    source_family: str | None = field(default=None, metadata={"omit_if_none": True})

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
        if self.source_family is not None:
            require_text(self.source_family, "D0 source family")
        elif self.accepted:
            raise ValueError("accepted D0 tasks require a source family within qualification scope")


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
    pre_data_role_manifest: DataRoleManifest
    natural_independent_tasks_only: bool = True
    paraphrases_or_interventions_used: bool = False
    synthetic_cell_filling_used: bool = False

    def __post_init__(self) -> None:
        if type(self.pre_data_role_manifest) is not DataRoleManifest:
            raise ValueError("D0 requires authenticated before/after data-role manifests")
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
        ):
            raise ValueError("D0 population lineage or representation qualification drifted")
        request_ids = {item.target_id for item in self.plan.requests}
        if not request_ids <= set(target_ids):
            raise ValueError("D0 supplementation request falls outside the frozen profile")
        if not set(self.plan.existing_capacity_recovered_task_units) <= set(
            self.pre_census.task_unit_ids
        ):
            raise ValueError("recovered existing capacity must precede the formal pre census")
        requested = sum(item.requested_context_task_units for item in self.plan.requests)
        deficits = context_coverage_deficits(self.profile, self.pre_census)
        if any(item.requested_context_task_units > deficits[item.target_id] for item in self.plan.requests):
            raise ValueError("D0 requests must be bounded by context deficits")
        if self.plan.coverage_enriched != (self.plan.decision is SupplementationDecision.PLANNED):
            raise ValueError("D0 must disclose the change in context and source composition")
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
                or self.pre_census.data_role_manifest_id != self.post_census.data_role_manifest_id
                or self.pre_census.task_unit_ids != self.post_census.task_unit_ids
                or self.pre_census.cells != self.post_census.cells
            ):
                raise ValueError("unsupplemented D0 lineage changed the population")
            expected_status = (
                DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION
                if post_ready
                else DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED
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
            before = self.receipt.pre_data_role_manifest
            if (type(before) is not DataRoleManifest
                or before.protocol_id != self.profile.protocol_id
                or before.data_role_manifest_id != self.pre_census.data_role_manifest_id
                or before.discovery_population_sha256 != self.pre_census.population_manifest_sha256
                or self.pre_census.data_role_manifest_id == self.post_census.data_role_manifest_id):
                raise ValueError("D0 supplementation requires distinct authenticated before/after role manifests")
            if any(item.accepted and item.source_family not in self.profile.permitted_source_families
                   for item in self.receipt.task_dispositions):
                raise ValueError("D0 task source lies outside the frozen qualification scope")
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
                else DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED
            )
        if self.status is not expected_status:
            raise ValueError("D0 population status does not match frozen coverage thresholds")

    @property
    def population_lineage_id(self) -> str:
        return content_id("discovery_population_lineage_", self)

    @property
    def formal_discovery_ready(self) -> bool:
        # D0 closes the population; candidate support and power are separate gates.
        return self.status in {
            DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION,
            DiscoveryPopulationStatus.READY_AFTER_ONE_ROUND,
            DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED,
        }


def validate_discovery_role_transition(
    lineage: DiscoveryPopulationLineage, manifest: DataRoleManifest,
) -> DataRoleManifest:
    """Verify the exact additive D0 change and return the original qualification roles.

    Existing bindings, including their source/exposure digests, are immutable.
    New task units occupy new DISCOVERY bindings; no old binding is rewritten.
    """
    receipt = lineage.receipt
    before = receipt.pre_data_role_manifest if receipt is not None else manifest
    if type(before) is not DataRoleManifest or type(manifest) is not DataRoleManifest:
        raise ValueError("D0 requires authenticated before/after data-role manifests")
    def discovery_ids(roles):
        return tuple(sorted(task.task_unit_id for binding in roles.bindings
                            if binding.role is DataRole.DISCOVERY for task in binding.task_units))
    if (before.protocol_id != manifest.protocol_id or manifest.protocol_id != lineage.profile.protocol_id
        or lineage.pre_census.data_role_manifest_id != before.data_role_manifest_id
        or lineage.pre_census.population_manifest_sha256 != before.discovery_population_sha256
        or lineage.pre_census.task_unit_ids != discovery_ids(before)
        or lineage.post_census.data_role_manifest_id != manifest.data_role_manifest_id
        or lineage.post_census.population_manifest_sha256 != manifest.discovery_population_sha256
        or lineage.post_census.task_unit_ids != discovery_ids(manifest)):
        raise ValueError("D0 census does not bind the exact before/after population")
    if receipt is None:
        if lineage.plan.decision is not SupplementationDecision.NOT_REQUESTED:
            raise ValueError("D0 acquisition requires its original manifest and receipt")
        return before
    if (lineage.plan.decision is not SupplementationDecision.PLANNED
        or receipt.data_role_manifest_sha256 != content_hash(manifest)):
        raise ValueError("D0 receipt does not bind the final role manifest")
    old = {binding.data_id: binding for binding in before.bindings}
    new = {binding.data_id: binding for binding in manifest.bindings}
    if any(new.get(key) != binding for key, binding in old.items()):
        raise ValueError("D0 cannot remove or rewrite an existing role binding")
    additions = [binding for key, binding in new.items() if key not in old]
    if not additions or any(binding.role is not DataRole.DISCOVERY for binding in additions):
        raise ValueError("D0 may add new DISCOVERY bindings only")
    tasks = [task for binding in additions for task in binding.task_units]
    old_ids = {task.task_unit_id for binding in before.bindings for task in binding.task_units}
    old_groups = {task.near_duplicate_group_id for binding in before.bindings for task in binding.task_units}
    if (len({task.task_unit_id for task in tasks}) != len(tasks)
        or len({task.near_duplicate_group_id for task in tasks}) != len(tasks)
        or any(task.task_unit_id in old_ids or task.near_duplicate_group_id in old_groups for task in tasks)
        or tuple(sorted(task.task_unit_id for task in tasks)) != receipt.acquired_task_unit_ids):
        raise ValueError("D0 added units must be independent and exactly match the receipt")
    accepted = {item.task_unit_id: item for item in receipt.task_dispositions if item.accepted}
    if set(accepted) != {task.task_unit_id for task in tasks}:
        raise ValueError("D0 dispositions do not cover the added tasks")
    for task in tasks:
        item = accepted[task.task_unit_id]
        if (task.near_duplicate_group_id != item.near_duplicate_group_id
            or task.source_lineage_id != item.source_lineage_id
            or task.exposure_history != tuple(event.value for event in item.exposure_categories)
            or item.source_family not in lineage.profile.permitted_source_families
            or set(item.exposure_categories) - {D0ExposureCategory.SOURCE_CURATION_VIEWED}):
            raise ValueError("D0 source, qualification scope or exposure provenance drifted")
    return before


def context_coverage_deficits(
    profile: CoverageTargetProfile, census: DiscoveryCoverageCensus,
) -> dict[str, int]:
    """Only context task-unit counts enter D0; states, ranks and outcomes cannot."""
    cells = {item.target_id: item for item in census.cells}
    if set(cells) != {target.target_id for target in profile.targets}:
        raise ValueError("context census does not cover the frozen targets")
    return {target.target_id: max(0, target.minimum_context_task_units - cells[target.target_id].context_task_units)
            for target in profile.targets}


def count_context_coverage(profile: CoverageTargetProfile, rows: tuple[Mapping, ...]) -> tuple[CoverageCellSupport, ...]:
    """Count each deduplicated task once per frozen context, retaining unknowns."""
    states: dict[tuple[str, str], set[str]] = defaultdict(set)
    context_ids = {target.context_query_id for target in profile.targets}
    for row in rows:
        if set(row) != {"task_unit_id", "context_states"} or set(row["context_states"]) != context_ids:
            raise ValueError("D0 input must contain only task identity and frozen context states")
        require_text(row["task_unit_id"], "D0 task unit")
        for context, state in row["context_states"].items():
            if state not in {"present", "absent", "unresolved"}:
                raise ValueError("D0 context state is invalid")
            states[row["task_unit_id"], context].add(state)
    cells = []
    for target in profile.targets:
        values = [value for (_, context), value in states.items() if context == target.context_query_id]
        cells.append(CoverageCellSupport(target.target_id,
            sum("present" in value for value in values),
            sum("present" not in value and "unresolved" in value for value in values)))
    return tuple(cells)


def plan_context_acquisitions(profile: CoverageTargetProfile, census: DiscoveryCoverageCensus) -> tuple[CoverageAcquisitionRequest, ...]:
    """Allocate the fixed source budget in canonical context order, before Discovery."""
    remaining = profile.maximum_new_task_units
    requests = []
    for target, deficit in sorted(context_coverage_deficits(profile, census).items()):
        count = min(remaining, deficit)
        if count:
            requests.append(CoverageAcquisitionRequest(target, count))
            remaining -= count
    return tuple(requests)


def _coverage_targets_met(profile: CoverageTargetProfile, census: DiscoveryCoverageCensus) -> bool:
    return not any(context_coverage_deficits(profile, census).values())


def audit_discovery_positivity(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    catalog_path: Path,
    output: Path,
    *,
    graph_artifact: str = "graphs.json",
    scope_bindings_path: Path,
) -> dict[str, object]:
    """Audit source support for frozen open-graph factor scopes."""
    if load_catalog(catalog_path)["schema_version"] != "2.0":
        raise ValueError("source support requires an open-graph catalog")
    return _audit_scoped_discovery_positivity(
        tasks_path, graph_bundles, catalog_path, scope_bindings_path, output, graph_artifact
    )


def _source_policy(record):
    """Decode one Atomic policy; research-branch Pair records are not accepted."""
    from prompt_mechanism_study.tsg.representation import (
        AnalysisScope,
        AtomicPolicyKey,
        PolicyFactor,
        Operation,
    )

    if set(record) != {"analysis_scope", "factor", "outcome_id"}:
        raise ValueError("main source support requires an Atomic policy record")
    scope = dict(record["analysis_scope"])
    for key in ("language_scope", "api_scope", "task_archetype_scope"):
        scope[key] = tuple(scope[key])
    factor = record["factor"]
    return AtomicPolicyKey(
        AnalysisScope(**scope),
        PolicyFactor(factor["actionable_feature_id"], Operation(factor["operation"])),
        record["outcome_id"],
    )


def _audit_scoped_discovery_positivity(
    tasks_path, graph_bundles, catalog_path, scope_path, output, graph_artifact
):
    """Produce scope-bound, outcome-free source rows and selector inputs in one path.

    Every task/policy has a disposition. One globally bound scope per feature/task
    prevents selecting a different input after seeing its state or counting more
    operations as additional independent tasks. Source-semantic/role qualification
    and intervention readiness remain separate from these mechanical counts.
    """
    from prompt_mechanism_study.artifact_io import file_sha256, read_json_exact
    from prompt_mechanism_study.tsg.representation import Operation, freeze_source_eligibility
    from prompt_mechanism_study.discovery.prioritization import (
        AtomicPreOutcomeObservation,
        CandidateCoverageSummary,
        CandidateKind,
    )

    if graph_artifact not in {
        "graphs.json",
        "discovery-graphs.json",
        "pilot-graphs.json",
        "confirm-graphs.json",
    }:
        raise ValueError("invalid source graph artifact")
    tasks, catalog, config = (
        _task_records(tasks_path),
        load_catalog(catalog_path),
        read_json_exact(scope_path),
    )
    task_ids = [task["task_id"] for task in tasks]
    if (
        not tasks
        or len(set(task_ids)) != len(tasks)
        or len({task["task_unit_id"] for task in tasks}) != len(tasks)
        or (len({task["near_duplicate_group_id"] for task in tasks}) != len(tasks))
    ):
        raise ValueError("source support requires deduplicated independent task units")
    graphs, graph_digests = ({}, [])
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_digests.append(bundle_digest(bundle))
        for row in read_json(bundle / graph_artifact):
            graph = prompt_tsg_from_record(row)
            if graph.task_id in graphs or graph.task_id not in task_ids:
                raise ValueError("source support graph task is duplicate or outside the selection")
            graphs[graph.task_id] = graph
    if (
        config.get("source_tasks_sha256") != file_sha256(tasks_path)
        or config.get("catalog_sha256") != catalog_sha256(catalog)
        or config.get("graph_bundle_sha256") != sorted(graph_digests)
        or (config.get("arms_or_outcomes_used") is not False)
        or (config.get("scope_choice_used_feature_states") is not False)
        or (catalog.get("concept_policy") != "FROZEN")
    ):
        raise ValueError(
            "scoped source input does not close or lacks outcome/state-blind scope selection"
        )
    require_text(config["model_id"], "source support model")
    policies = [_source_policy(row) for row in config["policies"]]
    if len({p.policy_key for p in policies}) != len(policies):
        raise ValueError("scoped source policies must be unique")

    def factors(policy):
        return (policy.factor,)

    features = {f.actionable_feature_id for policy in policies for f in factors(policy)}
    definitions = config["factor_definitions"]
    if set(definitions) != features:
        raise ValueError("every source factor needs one global scope definition")
    for feature, definition in definitions.items():
        if (
            not definition.get("definition")
            or not definition.get("scope_rule")
            or definition.get("atomicity_review") != "SOURCE_REVIEWED_SINGLE_REQUIREMENT"
            or (feature not in catalog["semantics"])
        ):
            raise ValueError(
                "source factors require catalog semantics and reviewed atomic scope rules"
            )
    bindings = {row["task_id"]: row for row in config["task_bindings"]}
    if len(bindings) != len(config["task_bindings"]) or set(bindings) != set(task_ids):
        raise ValueError("scoped source input must retain every selected task")
    for key, row in bindings.items():
        if (
            row["prompt_tsg_id"] != (graphs[key].tsg_id if key in graphs else None)
            or set(row["factor_scopes"]) != features
        ):
            raise ValueError(
                "source scope bindings do not bind the exact graph and complete factor set"
            )
    if "candidate_construction" in config:
        from prompt_mechanism_study.tsg.candidate_construction import (
            validate_generated_scope_config,
        )

        validate_generated_scope_config(
            config, tasks, graphs, catalog, relative_to=scope_path.parent
        )
    rule = config["support_rule"]
    if (
        set(rule)
        != {
            "minimum_state_task_units",
            "minimum_shared_lineages",
            "maximum_unresolved_fraction",
            "minimum_feature_reliability",
        }
        or any(
            (
                type(rule[name]) is not int or rule[name] < 1
                for name in ("minimum_state_task_units", "minimum_shared_lineages")
            )
        )
        or any(
            (
                type(rule[name]) not in {int, float}
                or not math.isfinite(rule[name])
                or (not 0 <= rule[name] <= 1)
                for name in ("maximum_unresolved_fraction", "minimum_feature_reliability")
            )
        )
    ):
        raise ValueError("Atomic requires one explicit frozen support rule family")
    if "feature_qualification" in config:
        raise ValueError(
            "caller-authored reliability is invalid; bind a source qualification bundle"
        )
    qualification, qualification_digest = (None, None)
    if config.get("representation_qualification") is not None:
        from prompt_mechanism_study.tsg.prompt_contract_qualification import (
            load_open_qualification_profiles,
        )

        bound = config["representation_qualification"]
        qualification_path = scope_path.parent / bound["bundle"]
        qualification_digest = bundle_digest(qualification_path)
        if qualification_digest != bound["bundle_sha256"]:
            raise ValueError("source qualification bundle identity differs")
        qualification = load_open_qualification_profiles(qualification_path)
        qualified = qualification["report"]
        if qualified["bindings"]["catalog_sha256"] != catalog_sha256(catalog):
            raise ValueError("source qualification catalog differs")
        synthetic = qualified["reference_kind"] == "SYNTHETIC_TEST"
        if synthetic and any(
            (task.get("source_kind") != "synthetic_development" for task in tasks)
        ):
            raise ValueError("synthetic qualification cannot admit natural source tasks")
        if not synthetic:
            if set(qualification["task_unit_ids"]) & {task["task_unit_id"] for task in tasks}:
                raise ValueError("qualification tasks cannot become Discovery support")
            for bundle in graph_bundles:
                extraction = read_json(bundle / "report.json")
                keys = (
                    "catalog_sha256",
                    "candidate_id",
                    "evaluator_sha256",
                    "annotator_prompt_sha256",
                    "representation_implementation_sha256",
                )
                if (
                    any((extraction.get(k) != qualified["bindings"][k] for k in keys))
                    or extraction.get("arms_or_outcomes_used") is not False
                    or extraction.get("model_visible_routing_labels") is not False
                ):
                    raise ValueError("source graphs were not produced by the qualified extractor")
    covariate_names = tuple(config["covariate_names"])
    _canonical_unique(covariate_names, "source covariate names")
    source_rows, summaries, coverage, atomic_groups = ([], [], [], {})
    for policy in policies:
        policy_rows, resolved = ([], [])
        policy_factors = factors(policy)
        expected_cells = ("0", "1")
        population = policy.analysis_scope
        for task in tasks:
            key = task["task_id"]
            in_population = (
                task["language"] in population.language_scope
                and task["api_family"] in population.api_scope
                and (task["task_archetype"] in population.task_archetype_scope)
            )
            checks = []
            if in_population:
                for factor in policy_factors:
                    feature = factor.actionable_feature_id
                    raw_scope = bindings[key]["factor_scopes"][feature]
                    checks.append(
                        freeze_source_eligibility(
                            policy,
                            task_id=key,
                            task_unit_id=task["task_unit_id"],
                            prompt=task["prompt"],
                            graph=graphs.get(key),
                            catalog=catalog,
                            factor_scope=(
                                feature_scope_from_record(raw_scope)
                                if raw_scope is not None
                                else None
                            ),
                            factor_feature_id=feature,
                            eligibility_policy_sha256=content_hash(definitions[feature]),
                        )
                    )
            known = bool(checks) and all(
                (
                    check.context_state is QueryState.PRESENT
                    and check.factor_scope is not None
                    and (check.feature_state in {QueryState.PRESENT, QueryState.ABSENT})
                    for check in checks
                )
            )
            unknown = bool(checks) and any(
                (
                    check.prompt_tsg_id is None
                    or check.factor_scope is None
                    or check.context_state is QueryState.UNRESOLVED
                    or (
                        check.context_state is QueryState.PRESENT
                        and check.feature_state is QueryState.UNRESOLVED
                    )
                    for check in checks
                )
            )
            cell = (
                "".join(
                    (
                        str(
                            int(
                                check.feature_state
                                is (
                                    QueryState.PRESENT
                                    if check.operation is Operation.ADD
                                    else QueryState.ABSENT
                                )
                            )
                        )
                        for check in checks
                    )
                )
                if known
                else None
            )
            row = dict(
                policy_key=policy.policy_key,
                task_id=key,
                task_unit_id=task["task_unit_id"],
                source_lineage_id=task["source_lineage_id"],
                language=task["language"],
                api_family=task["api_family"],
                task_archetype=task["task_archetype"],
                population_eligible=in_population,
                source_assessments=tuple(checks),
                source_binding_sha256=content_hash(
                    dict(
                        assessments=checks, representation_qualification_sha256=qualification_digest
                    )
                ),
                natural_state_resolved=known,
                source_state_unknown=unknown,
                target_state_cell=cell,
                confirmation_baseline_source_eligible=bool(checks)
                and all((check.eligible for check in checks)),
                intervention_readiness="NOT_ESTABLISHED_BY_SOURCE_STATE",
                covariates=tuple(map(tuple, task["covariates"])),
            )
            row["feature_reliability"] = {}
            for check in checks:
                if check.factor_scope is None or qualification is None:
                    continue
                operation = next(
                    (
                        node
                        for node in graphs[key].nodes
                        if node.node_id == check.factor_scope.operation_node_id
                    )
                )
                profiles = [
                    p
                    for p in qualification["profiles"]
                    if p["language"] == task["language"]
                    and p["operation_semantic_id"] == operation.semantic_id
                    and (p["feature_id"] == check.actionable_feature_id)
                ]
                if {p["expected_state"] for p in profiles} >= {"present", "absent"} and all(
                    (p["passed"] and p["reliability_lower_bound"] is not None for p in profiles)
                ):
                    row["feature_reliability"][check.actionable_feature_id] = min(
                        (p["reliability_lower_bound"] for p in profiles)
                    )
            if tuple((name for name, _ in row["covariates"])) != covariate_names:
                raise ValueError("source covariates differ from their frozen schema")
            policy_rows.append(row)
            if known:
                resolved.append(row)
        source_rows.extend(policy_rows)
        population_rows = [row for row in policy_rows if row["population_eligible"]]
        cells = {
            cell: [row for row in resolved if row["target_state_cell"] == cell]
            for cell in expected_cells
        }
        shared = {
            field: set.intersection(*({row[field] for row in values} for values in cells.values()))
            for field in ("source_lineage_id", "language", "api_family", "task_archetype")
        }
        missing_qualification = qualification is None or any(
            (
                factor.actionable_feature_id not in row["feature_reliability"]
                for factor in policy_factors
                for row in resolved
            )
        )
        low_reliability = any(
            (
                value < rule["minimum_feature_reliability"]
                for row in resolved
                for value in row["feature_reliability"].values()
            )
        )
        unknown_count = sum((row["source_state_unknown"] for row in population_rows))
        reasons = []
        if not population_rows:
            reasons.append("no_tasks_in_declared_population")
        if (
            population_rows
            and unknown_count / len(population_rows) > rule["maximum_unresolved_fraction"]
        ):
            reasons.append("unresolved_fraction_exceeds_frozen_rule")
        if any((len(values) < rule["minimum_state_task_units"] for values in cells.values())):
            reasons.append("insufficient_natural_state_support")
        if len(shared["source_lineage_id"]) < rule["minimum_shared_lineages"]:
            reasons.append("insufficient_source_lineage_overlap")
        reasons.extend(
            (
                field + "_nonoverlap"
                for field in ("language", "api_family", "task_archetype")
                if not shared[field]
            )
        )
        if missing_qualification:
            reasons.append("representation_qualification_missing")
        if low_reliability:
            reasons.append("extractor_reliability_below_threshold")
        summaries.append(
            dict(
                policy_key=policy.policy_key,
                candidate_kind="ATOMIC",
                total_selected_task_units=len(tasks),
                population_task_units=len(population_rows),
                resolved_task_units=len(resolved),
                unknown_task_units=unknown_count,
                context_excluded_task_units=sum(
                    (
                        bool(row["source_assessments"])
                        and any(
                            (
                                c.context_state in {QueryState.ABSENT, QueryState.NOT_APPLICABLE}
                                for c in row["source_assessments"]
                            )
                        )
                        for row in population_rows
                    )
                ),
                state_or_cell_task_units=tuple(
                    ((cell, len(cells[cell])) for cell in expected_cells)
                ),
                shared_source_lineages=sorted(shared["source_lineage_id"]),
                baseline_source_task_units=sum(
                    (row["confirmation_baseline_source_eligible"] for row in population_rows)
                ),
                support_gate_passed=not reasons,
                failure_reasons=sorted(reasons),
            )
        )
        coverage.append(
            CandidateCoverageSummary(
                policy.policy_key,
                CandidateKind.ATOMIC,
                tuple(((cell, len(cells[cell])) for cell in expected_cells)),
                len({row["source_lineage_id"] for row in population_rows}),
                len(population_rows),
                len(resolved),
                len(population_rows),
                0,
                sum((row["confirmation_baseline_source_eligible"] for row in population_rows)),
            )
        )
        if missing_qualification or low_reliability:
            continue
        for row in resolved:
            group = atomic_groups.setdefault(
                (population.analysis_scope_id, row["task_unit_id"]),
                dict(covariates=row["covariates"], states=[], bindings=[], failures=[]),
            )
            group["states"].append(
                (
                    policy.policy_key,
                    int(row["source_assessments"][0].feature_state is QueryState.PRESENT),
                )
            )
            group["bindings"].append((policy.policy_key, row["source_binding_sha256"]))
            group["failures"].append((policy.policy_key, tuple(sorted(reasons))))
    atomic_rows = tuple(
        (
            AtomicPreOutcomeObservation(
                unit,
                config["model_id"],
                family,
                0,
                tuple(sorted(value["states"])),
                value["covariates"],
                content_hash(sorted(value["bindings"])),
                tuple(sorted(value["failures"])),
            )
            for (family, unit), value in sorted(atomic_groups.items())
        )
    )
    report = dict(
        schema_version="2.0",
        status="SCOPED_SOURCE_SUPPORT_CHECK_COMPLETE",
        task_units=len(tasks),
        policies=len(policies),
        resolved_support_policies=sum((row["support_gate_passed"] for row in summaries)),
        atomic_preoutcome_rows=len(atomic_rows),
        support_rule=rule,
        task_file_sha256=file_sha256(tasks_path),
        catalog_sha256=catalog_sha256(catalog),
        graph_bundle_sha256=sorted(graph_digests),
        scope_bindings_sha256=file_sha256(scope_path),
        representation_qualification_sha256=qualification_digest,
        implementation_sha256=file_sha256(Path(__file__)),
        arms_or_outcomes_used=False,
        fci_executed=False,
        source_material_counts=dict(
            Counter((task.get("source_kind", "unspecified") for task in tasks))
        ),
        supported_policy_keys=sorted(
            (row["policy_key"] for row in summaries if row["support_gate_passed"])
        ),
        scientific_claim_allowed=False,
        formal_execution_authorized=False,
        claim_boundary="Mechanical source-scope support and outcome-free inputs only. Qualification bounds are recomputed from the bound source-reference result; independent review and state-blind scope selection require external verification; no intervention readiness, data-role assignment, formal admission or causal effect is established.",
    )
    write_bundle(
        output,
        {
            "report.json": report,
            "positivity-rows.json": source_rows,
            "support.json": summaries,
            "coverage-summaries.json": tuple(sorted(coverage, key=lambda row: row.candidate_id)),
            "atomic-preoutcome-observations.json": atomic_rows,
        },
    )
    return report


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


__all__ = [
    "validate_discovery_role_transition",
    "CoverageAcquisitionMode",
    "CoverageAcquisitionRequest",
    "CoverageCellSupport",
    "CoverageCensusPhase",
    "CoverageTarget",
    "CoverageTargetProfile",
    "D0ExposureCategory",
    "D0TaskDisposition",
    "DiscoveryCoverageCensus",
    "DiscoveryPopulationLineage",
    "DiscoveryPopulationStatus",
    "DiscoverySupplementationPlan",
    "DiscoverySupplementationReceipt",
    "SupplementationDecision",
    "audit_discovery_positivity",
]

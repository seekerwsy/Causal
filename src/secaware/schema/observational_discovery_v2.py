"""Replayable contracts for authenticated observational FCI in protocol v2.

These records deliberately do not reuse the legacy motif/table vocabulary.  A
run is bound to an authenticated natural-Prompt table (and, for two-level
analysis, the complete frozen draw manifest) by the orchestration layer.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum, StrEnum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from secaware.causal.authenticated_natural_table_v2 import (
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    TwoLevelClusterResampleManifestV2,
)
from secaware.schema.causal import PAGEdgeRecord
from secaware.schema.common import SafeValidationMixin, StrictModel

OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_VARIABLE_RE = re.compile(r"^[xy]\.[a-z0-9][a-z0-9_.-]{0,126}$")
_KNOWLEDGE_PATTERN = r"^observational_bk_v2_[0-9a-f]{64}$"
_PAG_PATTERN = r"^observational_pag_v2_[0-9a-f]{64}$"
_CANDIDATE_PATTERN = r"^observational_candidate_v2_[0-9a-f]{64}$"
_DELTA_PATTERN = r"^observational_bk_delta_v2_[0-9a-f]{64}$"
_SUITE_PATTERN = r"^observational_fci_suite_v2_[0-9a-f]{64}$"
_FAILURE_PATTERN = r"^observational_fci_failure_v2_[0-9a-f]{64}$"
_REPLICATE_PATTERN = r"^observational_bootstrap_replicate_v2_[0-9a-f]{64}$"
_BOOTSTRAP_PATTERN = r"^observational_bootstrap_v2_[0-9a-f]{64}$"
_JCI_PATTERN = r"^observational_jci_diagnostic_v2_[0-9a-f]{64}$"


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_digest_v2(value: object) -> str:
    """Return the protocol-v2 canonical SHA-256 digest."""

    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


class _ObservationalContractV2(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = (
        "observational discovery v2 artifact failed exact validation"
    )
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedObservationalV2(_ObservationalContractV2):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {
                "schema_version": OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION,
                **content,
            }
            return cls(**payload, **{cls._id_field: cls._id_prefix + canonical_digest_v2(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the content-addressed boundary
            content.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + canonical_digest_v2(content):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalDiscoveryConfigV2(_ObservationalContractV2):
    """The complete pinned causal-learn/G-square execution configuration."""

    backend: Literal["causal_learn_fci_v2"] = "causal_learn_fci_v2"
    backend_version: Literal["0.1.4.7"] = "0.1.4.7"
    ci_test: Literal["gsq"] = "gsq"
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0, allow_inf_nan=False)
    depth: StrictInt = Field(default=3, ge=0, le=8)
    max_path_length: StrictInt = Field(default=6, ge=1, le=16)
    min_independent_clusters: StrictInt = Field(default=20, ge=2, le=100_000)
    max_rows: StrictInt = Field(default=100_000, ge=2, le=1_000_000)
    max_variables: StrictInt = Field(default=16, ge=2, le=64)
    max_atomic_bk_ablations: StrictInt = Field(default=128, ge=1, le=4096)
    max_failed_bootstrap_fraction: float = Field(
        default=0.10,
        ge=0.0,
        lt=1.0,
        allow_inf_nan=False,
    )


class DiscoveryFailureReasonV2(StrEnum):
    UNSUPPORTED_SCOPE = "unsupported_scope"
    TWO_LEVEL_DRAW_REQUIRED = "two_level_draw_required"
    INSUFFICIENT_INDEPENDENT_CLUSTERS = "insufficient_independent_clusters"
    INSUFFICIENT_ROWS = "insufficient_rows"
    CONSTANT_VARIABLE = "constant_variable"
    DETERMINISTIC_RELATION = "deterministic_relation"
    GSQUARE_DEGENERATE = "gsquare_degenerate"
    TOO_MANY_BK_ABLATIONS = "too_many_bk_ablations"
    BACKEND_VERSION_MISMATCH = "backend_version_mismatch"
    BACKEND_FAILURE = "backend_failure"
    INVALID_BACKEND_PAG = "invalid_backend_pag"
    TOO_MANY_FAILED_BOOTSTRAPS = "too_many_failed_bootstraps"


class TypedDiscoveryFailureV2(_ObservationalContractV2):
    reason: DiscoveryFailureReasonV2
    stage: str
    detail_code: str

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if not _valid_identifier(self.stage) or not _valid_identifier(self.detail_code):
            raise ValueError(self._safe_validation_message)
        return self


class BackgroundKnowledgeKindV2(StrEnum):
    RAW = "raw"
    MINIMAL = "minimal"
    FULL = "full"
    SINGLE_DELETION = "single_deletion"
    WRONG_PLAUSIBLE = "wrong_plausible"


class BKConstraintKindV2(StrEnum):
    FORBIDDEN_DIRECTION = "forbidden_direction"
    FORBIDDEN_ADJACENCY = "forbidden_adjacency"


class BKConstraintV2(_ObservationalContractV2):
    kind: BKConstraintKindV2
    left: str
    right: str
    rationale: Literal[
        "temporal_tier",
        "typed_adjacency",
        "wrong_plausible_tier_swap",
    ]

    @model_validator(mode="after")
    def validate_constraint(self) -> Self:
        if (
            _VARIABLE_RE.fullmatch(self.left) is None
            or _VARIABLE_RE.fullmatch(self.right) is None
            or self.left == self.right
            or (self.kind is BKConstraintKindV2.FORBIDDEN_ADJACENCY and self.left >= self.right)
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.kind.value, self.left, self.right, self.rationale)


class BackgroundKnowledgeArtifactV2(_ContentAddressedObservationalV2):
    """Finite typed BK; the schema has no required-edge representation."""

    _id_field = "knowledge_id"
    _id_prefix = "observational_bk_v2_"

    knowledge_id: str = Field(pattern=_KNOWLEDGE_PATTERN)
    kind: BackgroundKnowledgeKindV2
    source_table_id: str
    variable_ids: tuple[str, ...] = Field(min_length=2, max_length=64)
    temporal_tiers: tuple[tuple[str, StrictInt], ...] = Field(min_length=2, max_length=64)
    constraints: tuple[BKConstraintV2, ...] = Field(max_length=4096)
    typed_adjacency_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    excluded_from_candidate_evidence: bool

    @model_validator(mode="after")
    def validate_knowledge(self) -> Self:
        tiers = tuple(variable for variable, _tier in self.temporal_tiers)
        constraints = tuple(item.sort_key() for item in self.constraints)
        expected_excluded = self.kind in {
            BackgroundKnowledgeKindV2.SINGLE_DELETION,
            BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE,
        }
        if (
            not _valid_identifier(self.source_table_id)
            or self.variable_ids != tuple(sorted(self.variable_ids))
            or len(self.variable_ids) != len(set(self.variable_ids))
            or any(_VARIABLE_RE.fullmatch(item) is None for item in self.variable_ids)
            or self.temporal_tiers != tuple(sorted(self.temporal_tiers))
            or tiers != self.variable_ids
            or any(not 0 <= tier <= 2 for _variable, tier in self.temporal_tiers)
            or constraints != tuple(sorted(constraints))
            or len(constraints) != len(set(constraints))
            or any(
                item.left not in self.variable_ids or item.right not in self.variable_ids
                for item in self.constraints
            )
            or (self.kind is BackgroundKnowledgeKindV2.RAW and self.constraints)
            or (
                self.kind is BackgroundKnowledgeKindV2.MINIMAL
                and any(
                    item.kind is BKConstraintKindV2.FORBIDDEN_ADJACENCY for item in self.constraints
                )
            )
            or self.excluded_from_candidate_evidence != expected_excluded
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalPAGArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "pag_id"
    _id_prefix = "observational_pag_v2_"

    pag_id: str = Field(pattern=_PAG_PATTERN)
    source_table_id: str
    source_draw_id: str | None
    run_label: str
    row_count: StrictInt = Field(ge=2, le=1_000_000)
    row_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    config: ObservationalDiscoveryConfigV2
    knowledge: BackgroundKnowledgeArtifactV2
    variable_ids: tuple[str, ...] = Field(min_length=2, max_length=64)
    edges: tuple[PAGEdgeRecord, ...]
    backend_stdout: str = Field(max_length=200_000, repr=False)
    backend_stderr: Literal[""] = ""
    backend_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_pag(self) -> Self:
        pairs = tuple((item.left, item.right) for item in self.edges)
        if (
            not _valid_identifier(self.source_table_id)
            or (self.source_draw_id is not None and not _valid_identifier(self.source_draw_id))
            or not _valid_identifier(self.run_label)
            or self.variable_ids != self.knowledge.variable_ids
            or self.knowledge.source_table_id != self.source_table_id
            or pairs != tuple(sorted(pairs))
            or len(pairs) != len(set(pairs))
            or any(
                edge.left not in self.variable_ids or edge.right not in self.variable_ids
                for edge in self.edges
            )
            or self.backend_warnings
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PolicyRelevantCandidateV2(_ContentAddressedObservationalV2):
    _id_field = "candidate_id"
    _id_prefix = "observational_candidate_v2_"

    candidate_id: str = Field(pattern=_CANDIDATE_PATTERN)
    x_variable_id: str
    y_variable_id: str
    raw_pag_id: str = Field(pattern=_PAG_PATTERN)
    full_pag_id: str = Field(pattern=_PAG_PATTERN)
    raw_adjacent: bool
    raw_permits_x_to_y: bool
    full_adjacent: bool
    full_permits_x_to_y: bool
    bk_created_adjacency: bool
    selected: bool
    selection_rule: Literal["raw_adjacency_and_raw_plus_full_possible_x_to_y_v1"]

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        selected = (
            self.raw_adjacent
            and self.raw_permits_x_to_y
            and self.full_adjacent
            and self.full_permits_x_to_y
        )
        if (
            _VARIABLE_RE.fullmatch(self.x_variable_id) is None
            or not self.x_variable_id.startswith("x.")
            or _VARIABLE_RE.fullmatch(self.y_variable_id) is None
            or not self.y_variable_id.startswith("y.")
            or self.raw_permits_x_to_y
            and not self.raw_adjacent
            or self.full_permits_x_to_y
            and not self.full_adjacent
            or self.bk_created_adjacency != (self.full_adjacent and not self.raw_adjacent)
            or self.selected != selected
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PAGEdgeDeltaV2(_ObservationalContractV2):
    left: str
    right: str
    before: PAGEdgeRecord | None
    after: PAGEdgeRecord | None

    @model_validator(mode="after")
    def validate_delta(self) -> Self:
        if (
            _VARIABLE_RE.fullmatch(self.left) is None
            or _VARIABLE_RE.fullmatch(self.right) is None
            or self.left >= self.right
            or self.before == self.after
            or (
                self.before is not None
                and (self.before.left, self.before.right) != (self.left, self.right)
            )
            or (
                self.after is not None
                and (self.after.left, self.after.right) != (self.left, self.right)
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class BKDeletionDeltaArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "delta_id"
    _id_prefix = "observational_bk_delta_v2_"

    delta_id: str = Field(pattern=_DELTA_PATTERN)
    full_pag_id: str = Field(pattern=_PAG_PATTERN)
    removed_constraint: BKConstraintV2
    ablation_pag: ObservationalPAGArtifactV2
    edge_deltas: tuple[PAGEdgeDeltaV2, ...]
    candidate_selected_after_deletion: bool

    @model_validator(mode="after")
    def validate_delta_artifact(self) -> Self:
        if (
            self.ablation_pag.knowledge.kind is not BackgroundKnowledgeKindV2.SINGLE_DELETION
            or self.removed_constraint in self.ablation_pag.knowledge.constraints
            or self.edge_deltas
            != tuple(sorted(self.edge_deltas, key=lambda item: (item.left, item.right)))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalFCISuiteArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "suite_id"
    _id_prefix = "observational_fci_suite_v2_"

    suite_id: str = Field(pattern=_SUITE_PATTERN)
    source_table: AuthenticatedNaturalDiscoveryTableArtifactV2
    source_draw: TwoLevelClusterResampleManifestV2 | None
    config: ObservationalDiscoveryConfigV2
    x_variable_id: str
    y_variable_id: str
    context_conditioning_query_id: str | None
    raw_pag: ObservationalPAGArtifactV2
    minimal_bk_pag: ObservationalPAGArtifactV2
    full_bk_pag: ObservationalPAGArtifactV2
    deletion_deltas: tuple[BKDeletionDeltaArtifactV2, ...]
    wrong_plausible_bk_pag: ObservationalPAGArtifactV2
    candidate: PolicyRelevantCandidateV2

    @model_validator(mode="after")
    def validate_suite(self) -> Self:
        source_draw_id = self.source_draw.draw_manifest_id if self.source_draw else None
        pages = (
            self.raw_pag,
            self.minimal_bk_pag,
            self.full_bk_pag,
            self.wrong_plausible_bk_pag,
            *(item.ablation_pag for item in self.deletion_deltas),
        )
        if (
            self.source_draw is not None
            and self.source_draw.authenticated_table != self.source_table
        ):
            raise ValueError(self._safe_validation_message)
        if (
            any(page.source_table_id != self.source_table.authenticated_table_id for page in pages)
            or any(page.source_draw_id != source_draw_id for page in pages)
            or any(page.config != self.config for page in pages)
            or self.raw_pag.knowledge.kind is not BackgroundKnowledgeKindV2.RAW
            or self.minimal_bk_pag.knowledge.kind is not BackgroundKnowledgeKindV2.MINIMAL
            or self.full_bk_pag.knowledge.kind is not BackgroundKnowledgeKindV2.FULL
            or self.wrong_plausible_bk_pag.knowledge.kind
            is not BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE
            or not self.wrong_plausible_bk_pag.knowledge.excluded_from_candidate_evidence
            or self.candidate.x_variable_id != self.x_variable_id
            or self.candidate.y_variable_id != self.y_variable_id
            or self.candidate.raw_pag_id != self.raw_pag.pag_id
            or self.candidate.full_pag_id != self.full_bk_pag.pag_id
            or self.context_conditioning_query_id
            != self.source_table.authenticated_scope.table_spec.context_conditioning_query_id
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalFCIFailureArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "failure_artifact_id"
    _id_prefix = "observational_fci_failure_v2_"

    failure_artifact_id: str = Field(pattern=_FAILURE_PATTERN)
    source_table: AuthenticatedNaturalDiscoveryTableArtifactV2
    source_draw: TwoLevelClusterResampleManifestV2 | None
    config: ObservationalDiscoveryConfigV2
    failure: TypedDiscoveryFailureV2
    completed_pags: tuple[ObservationalPAGArtifactV2, ...] = ()

    @model_validator(mode="after")
    def validate_failure_artifact(self) -> Self:
        source_draw_id = self.source_draw.draw_manifest_id if self.source_draw else None
        if (
            self.source_draw is not None
            and self.source_draw.authenticated_table != self.source_table
        ) or any(
            page.source_table_id != self.source_table.authenticated_table_id
            or page.source_draw_id != source_draw_id
            or page.config != self.config
            for page in self.completed_pags
        ):
            raise ValueError(self._safe_validation_message)
        return self


class BootstrapReplicateArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "replicate_id"
    _id_prefix = "observational_bootstrap_replicate_v2_"

    replicate_id: str = Field(pattern=_REPLICATE_PATTERN)
    replicate_index: StrictInt = Field(ge=0, le=100_000)
    draw_manifest: TwoLevelClusterResampleManifestV2
    raw_pag: ObservationalPAGArtifactV2 | None
    full_bk_pag: ObservationalPAGArtifactV2 | None
    failure: TypedDiscoveryFailureV2 | None
    candidate_selected: bool

    @model_validator(mode="after")
    def validate_replicate(self) -> Self:
        complete = self.failure is None
        if (
            complete != (self.raw_pag is not None and self.full_bk_pag is not None)
            or (not complete and self.full_bk_pag is not None)
            or self.candidate_selected
            and not complete
        ):
            raise ValueError(self._safe_validation_message)
        if self.raw_pag is not None and (
            self.raw_pag.source_draw_id != self.draw_manifest.draw_manifest_id
            or self.raw_pag.source_table_id
            != self.draw_manifest.authenticated_table.authenticated_table_id
        ):
            raise ValueError(self._safe_validation_message)
        if self.full_bk_pag is not None and (
            self.full_bk_pag.source_draw_id != self.draw_manifest.draw_manifest_id
            or self.full_bk_pag.source_table_id
            != self.draw_manifest.authenticated_table.authenticated_table_id
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalBootstrapArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "bootstrap_id"
    _id_prefix = "observational_bootstrap_v2_"

    bootstrap_id: str = Field(pattern=_BOOTSTRAP_PATTERN)
    source_table: AuthenticatedNaturalDiscoveryTableArtifactV2
    config: ObservationalDiscoveryConfigV2
    resample_domain: str
    resample_seeds: tuple[StrictInt, ...] = Field(min_length=1, max_length=10_000)
    replicates: tuple[BootstrapReplicateArtifactV2, ...] = Field(min_length=1, max_length=10_000)
    candidate_support_numerator: StrictInt = Field(ge=0, le=10_000)
    candidate_support_denominator: StrictInt = Field(ge=1, le=10_000)
    failed_replicate_count: StrictInt = Field(ge=0, le=10_000)
    stability_eligible: bool
    overall_failure: TypedDiscoveryFailureV2 | None

    @model_validator(mode="after")
    def validate_bootstrap(self) -> Self:
        failures = sum(item.failure is not None for item in self.replicates)
        numerator = sum(item.candidate_selected for item in self.replicates)
        threshold_ok = failures / len(self.replicates) <= self.config.max_failed_bootstrap_fraction
        if (
            not _valid_identifier(self.resample_domain)
            or self.resample_seeds != tuple(sorted(self.resample_seeds))
            or len(self.resample_seeds) != len(set(self.resample_seeds))
            or len(self.replicates) != len(self.resample_seeds)
            or tuple(item.replicate_index for item in self.replicates)
            != tuple(range(len(self.replicates)))
            or tuple(item.draw_manifest.resample_seed for item in self.replicates)
            != self.resample_seeds
            or any(
                item.draw_manifest.authenticated_table != self.source_table
                for item in self.replicates
            )
            or self.candidate_support_numerator != numerator
            or self.candidate_support_denominator != len(self.replicates)
            or self.failed_replicate_count != failures
            or self.stability_eligible != threshold_ok
            or (self.overall_failure is None) != threshold_ok
            or (
                self.overall_failure is not None
                and self.overall_failure.reason
                is not DiscoveryFailureReasonV2.TOO_MANY_FAILED_BOOTSTRAPS
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class DeterministicRelationV2(_ObservationalContractV2):
    left_variable_id: str
    right_variable_id: str
    left_determines_right: bool
    right_determines_left: bool

    @model_validator(mode="after")
    def validate_relation(self) -> Self:
        if (
            not _valid_identifier(self.left_variable_id)
            or not _valid_identifier(self.right_variable_id)
            or self.left_variable_id >= self.right_variable_id
            or not (self.left_determines_right or self.right_determines_left)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class JCIAppendixDiagnosticArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "diagnostic_id"
    _id_prefix = "observational_jci_diagnostic_v2_"

    diagnostic_id: str = Field(pattern=_JCI_PATTERN)
    variable_ids: tuple[str, ...] = Field(min_length=2, max_length=64)
    context_variable_id: str
    rows: tuple[tuple[StrictInt, ...], ...] = Field(min_length=2, max_length=100_000)
    row_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    deterministic_relations: tuple[DeterministicRelationV2, ...]
    status: Literal["diagnostic_only", "deterministic_context_fail_closed"]
    appendix_only: Literal[True]
    upgrades_main_evidence: Literal[False]

    @model_validator(mode="after")
    def validate_jci_diagnostic(self) -> Self:
        expected_status = (
            "deterministic_context_fail_closed"
            if self.deterministic_relations
            else "diagnostic_only"
        )
        if (
            self.variable_ids != tuple(sorted(self.variable_ids))
            or len(self.variable_ids) != len(set(self.variable_ids))
            or self.context_variable_id not in self.variable_ids
            or not self.context_variable_id.startswith("c.")
            or any(
                len(row) != len(self.variable_ids) or any(value < 0 for value in row)
                for row in self.rows
            )
            or self.row_payload_sha256 != canonical_digest_v2(self.rows)
            or self.deterministic_relations
            != tuple(
                sorted(
                    self.deterministic_relations,
                    key=lambda item: (item.left_variable_id, item.right_variable_id),
                )
            )
            or self.status != expected_status
        ):
            raise ValueError(self._safe_validation_message)
        return self


ObservationalDiscoveryResultV2 = ObservationalFCISuiteArtifactV2 | ObservationalFCIFailureArtifactV2


__all__ = [
    "OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION",
    "BKConstraintKindV2",
    "BKConstraintV2",
    "BKDeletionDeltaArtifactV2",
    "BackgroundKnowledgeArtifactV2",
    "BackgroundKnowledgeKindV2",
    "BootstrapReplicateArtifactV2",
    "DeterministicRelationV2",
    "DiscoveryFailureReasonV2",
    "JCIAppendixDiagnosticArtifactV2",
    "ObservationalBootstrapArtifactV2",
    "ObservationalDiscoveryConfigV2",
    "ObservationalDiscoveryResultV2",
    "ObservationalFCIFailureArtifactV2",
    "ObservationalFCISuiteArtifactV2",
    "ObservationalPAGArtifactV2",
    "PAGEdgeDeltaV2",
    "PolicyRelevantCandidateV2",
    "TypedDiscoveryFailureV2",
    "canonical_digest_v2",
]

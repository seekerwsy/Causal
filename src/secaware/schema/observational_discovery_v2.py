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

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.causal.authenticated_natural_table_v2 import (
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    TwoLevelClusterResampleManifestV2,
)
from secaware.schema.causal import EndpointMark, PAGEdgeRecord
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.discovery_v2 import DiscoveryAnalysisKindV2

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
_SYNTHETIC_PATTERN = r"^observational_synthetic_gate_v2_[0-9a-f]{64}$"


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


def _exact_enum(value: object, enum_type: type[Enum]) -> object:
    if type(value) is enum_type:
        return value
    if type(value) is str:
        return next((item for item in enum_type if item.value == value), value)
    return value


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
    min_expected_pairwise_cell_count: float = Field(
        default=1.0,
        gt=0.0,
        le=100.0,
        allow_inf_nan=False,
    )


class ObservationalDrawSelectionV2(_ObservationalContractV2):
    occurrence_index: StrictInt = Field(ge=0, le=1_000_000)
    semantic_task_cluster_id: str
    task_instance_id: str
    request_randomness_slot: StrictInt = Field(ge=0, le=2_147_483_647)
    receipt_id: str
    row: tuple[StrictInt, ...] = Field(min_length=2, max_length=128)

    @field_validator("row", mode="before")
    @classmethod
    def snapshot_row(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        if (
            not all(
                _valid_identifier(item)
                for item in (
                    self.semantic_task_cluster_id,
                    self.task_instance_id,
                    self.receipt_id,
                )
            )
            or any(value < 0 for value in self.row)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalSourceBindingV2(_ObservationalContractV2):
    """Compact immutable references to separately persisted authenticated evidence."""

    authenticated_table_id: str
    authenticated_scope_id: str
    table_spec_id: str
    raw_table_artifact_id: str
    receipt_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_kind: DiscoveryAnalysisKindV2
    context_conditioning_query_id: str | None = None
    independent_semantic_cluster_count: StrictInt = Field(ge=2, le=1_000_000)
    source_draw_id: str | None = None
    draw_row_payload_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    draw_selection_payload_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    draw_selections: tuple[ObservationalDrawSelectionV2, ...] | None = None
    resample_seed: StrictInt | None = Field(default=None, ge=0, le=2**63 - 1)
    resample_domain: str | None = None

    @field_validator("analysis_kind", mode="before")
    @classmethod
    def parse_analysis_kind(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryAnalysisKindV2)

    @field_validator("draw_selections", mode="before")
    @classmethod
    def snapshot_draw_selections(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @classmethod
    def from_evidence(
        cls,
        *,
        table: AuthenticatedNaturalDiscoveryTableArtifactV2,
        draw: TwoLevelClusterResampleManifestV2 | None,
    ) -> Self:
        checked_table = AuthenticatedNaturalDiscoveryTableArtifactV2.model_validate(
            table, strict=True
        )
        checked_draw = (
            None
            if draw is None
            else TwoLevelClusterResampleManifestV2.model_validate(draw, strict=True)
        )
        if checked_draw is not None and checked_draw.authenticated_table != checked_table:
            raise ValueError(cls._safe_validation_message)
        return cls(
            schema_version=OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION,
            authenticated_table_id=checked_table.authenticated_table_id,
            authenticated_scope_id=checked_table.authenticated_scope.authenticated_scope_id,
            table_spec_id=checked_table.authenticated_scope.table_spec.table_spec_id,
            raw_table_artifact_id=checked_table.raw_audit_table.table_artifact_id,
            receipt_payload_sha256=checked_table.receipt_payload_sha256,
            analysis_kind=checked_table.authenticated_scope.table_spec.analysis_kind,
            context_conditioning_query_id=(
                checked_table.authenticated_scope.table_spec.context_conditioning_query_id
            ),
            independent_semantic_cluster_count=(
                checked_table.raw_audit_table.independent_semantic_cluster_count
            ),
            source_draw_id=(checked_draw.draw_manifest_id if checked_draw is not None else None),
            draw_row_payload_sha256=(
                checked_draw.row_payload_sha256 if checked_draw is not None else None
            ),
            draw_selection_payload_sha256=(
                canonical_digest_v2(checked_draw.selections)
                if checked_draw is not None
                else None
            ),
            draw_selections=(
                tuple(
                    ObservationalDrawSelectionV2(
                        schema_version=OBSERVATIONAL_DISCOVERY_V2_SCHEMA_VERSION,
                        occurrence_index=item.occurrence_index,
                        semantic_task_cluster_id=item.semantic_task_cluster_id,
                        task_instance_id=item.task_instance_id,
                        request_randomness_slot=item.request_randomness_slot,
                        receipt_id=item.receipt_id,
                        row=item.row,
                    )
                    for item in checked_draw.selections
                )
                if checked_draw is not None
                else None
            ),
            resample_seed=(checked_draw.resample_seed if checked_draw is not None else None),
            resample_domain=(checked_draw.resample_domain if checked_draw is not None else None),
        )

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        draw_values = (
            self.source_draw_id,
            self.draw_row_payload_sha256,
            self.draw_selection_payload_sha256,
            self.draw_selections,
            self.resample_seed,
            self.resample_domain,
        )
        has_draw = self.source_draw_id is not None
        if (
            not all(
                _valid_identifier(item)
                for item in (
                    self.authenticated_table_id,
                    self.authenticated_scope_id,
                    self.table_spec_id,
                    self.raw_table_artifact_id,
                )
            )
            or (has_draw and any(item is None for item in draw_values))
            or (not has_draw and any(item is not None for item in draw_values))
            or (self.resample_domain is not None and not _valid_identifier(self.resample_domain))
            or (
                self.context_conditioning_query_id is not None
                and not _valid_identifier(self.context_conditioning_query_id)
            )
            or (has_draw and self.analysis_kind is not DiscoveryAnalysisKindV2.TWO_LEVEL)
            or (
                self.draw_selections is not None
                and self.draw_selection_payload_sha256
                != canonical_digest_v2(self.draw_selections)
            )
            or (
                self.draw_selections is not None
                and self.draw_row_payload_sha256
                != canonical_digest_v2(tuple(item.row for item in self.draw_selections))
            )
            or (
                self.draw_selections is not None
                and tuple(
                    (
                        item.occurrence_index,
                        item.semantic_task_cluster_id,
                        item.task_instance_id,
                    )
                    for item in self.draw_selections
                )
                != tuple(
                    sorted(
                        (
                            item.occurrence_index,
                            item.semantic_task_cluster_id,
                            item.task_instance_id,
                        )
                        for item in self.draw_selections
                    )
                )
            )
            or (
                self.draw_selections is not None
                and {item.occurrence_index for item in self.draw_selections}
                != set(range(self.independent_semantic_cluster_count))
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class DiscoveryFailureReasonV2(StrEnum):
    UNSUPPORTED_SCOPE = "unsupported_scope"
    TWO_LEVEL_DRAW_REQUIRED = "two_level_draw_required"
    INSUFFICIENT_INDEPENDENT_CLUSTERS = "insufficient_independent_clusters"
    INSUFFICIENT_ROWS = "insufficient_rows"
    CONSTANT_VARIABLE = "constant_variable"
    DETERMINISTIC_RELATION = "deterministic_relation"
    SPARSE_CONTINGENCY = "sparse_contingency"
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

    @field_validator("reason", mode="before")
    @classmethod
    def parse_reason(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryFailureReasonV2)

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

    @field_validator("kind", mode="before")
    @classmethod
    def parse_kind(cls, value: object) -> object:
        return _exact_enum(value, BKConstraintKindV2)

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

    @field_validator("kind", mode="before")
    @classmethod
    def parse_kind(cls, value: object) -> object:
        return _exact_enum(value, BackgroundKnowledgeKindV2)

    @field_validator("variable_ids", "constraints", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @field_validator("temporal_tiers", mode="before")
    @classmethod
    def snapshot_tiers(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        return tuple(tuple(item) if type(item) in {tuple, list} else item for item in value)

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

    @field_validator("variable_ids", "edges", "backend_warnings", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_pag(self) -> Self:
        pairs = tuple((item.left, item.right) for item in self.edges)
        by_pair = {(item.left, item.right): item for item in self.edges}
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
            or any(
                (
                    item.kind is BKConstraintKindV2.FORBIDDEN_ADJACENCY
                    and tuple(sorted((item.left, item.right))) in by_pair
                )
                or (
                    item.kind is BKConstraintKindV2.FORBIDDEN_DIRECTION
                    and (edge := by_pair.get(tuple(sorted((item.left, item.right)))))
                    is not None
                    and _pag_edge_permits_direction(edge, item.left, item.right)
                )
                for item in self.knowledge.constraints
            )
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


def _pag_edge_for(
    pag: ObservationalPAGArtifactV2,
    left: str,
    right: str,
) -> PAGEdgeRecord | None:
    pair = tuple(sorted((left, right)))
    return next((item for item in pag.edges if (item.left, item.right) == pair), None)


def _pag_edge_permits_direction(
    edge: PAGEdgeRecord,
    source: str,
    target: str,
) -> bool:
    source_mark, target_mark = edge.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def _candidate_from_pages(
    raw: ObservationalPAGArtifactV2,
    full: ObservationalPAGArtifactV2,
    x_variable_id: str,
    y_variable_id: str,
) -> PolicyRelevantCandidateV2:
    raw_edge = _pag_edge_for(raw, x_variable_id, y_variable_id)
    full_edge = _pag_edge_for(full, x_variable_id, y_variable_id)
    raw_possible = raw_edge is not None and _pag_edge_permits_direction(
        raw_edge, x_variable_id, y_variable_id
    )
    full_possible = full_edge is not None and _pag_edge_permits_direction(
        full_edge, x_variable_id, y_variable_id
    )
    return PolicyRelevantCandidateV2.from_content(
        x_variable_id=x_variable_id,
        y_variable_id=y_variable_id,
        raw_pag_id=raw.pag_id,
        full_pag_id=full.pag_id,
        raw_adjacent=raw_edge is not None,
        raw_permits_x_to_y=raw_possible,
        full_adjacent=full_edge is not None,
        full_permits_x_to_y=full_possible,
        bk_created_adjacency=full_edge is not None and raw_edge is None,
        selected=raw_possible and full_possible,
        selection_rule="raw_adjacency_and_raw_plus_full_possible_x_to_y_v1",
    )


def _page_edge_deltas(
    before: ObservationalPAGArtifactV2,
    after: ObservationalPAGArtifactV2,
) -> tuple[PAGEdgeDeltaV2, ...]:
    before_by_pair = {(item.left, item.right): item for item in before.edges}
    after_by_pair = {(item.left, item.right): item for item in after.edges}
    return tuple(
        PAGEdgeDeltaV2(
            left=pair[0],
            right=pair[1],
            before=before_by_pair.get(pair),
            after=after_by_pair.get(pair),
        )
        for pair in sorted(set(before_by_pair) | set(after_by_pair))
        if before_by_pair.get(pair) != after_by_pair.get(pair)
    )


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

    @field_validator("edge_deltas", mode="before")
    @classmethod
    def snapshot_edge_deltas(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

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
    source_binding: ObservationalSourceBindingV2
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

    @field_validator("deletion_deltas", mode="before")
    @classmethod
    def snapshot_deletion_deltas(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_suite(self) -> Self:
        source_table_id = self.source_binding.authenticated_table_id
        source_draw_id = self.source_binding.source_draw_id
        pages = (
            self.raw_pag,
            self.minimal_bk_pag,
            self.full_bk_pag,
            self.wrong_plausible_bk_pag,
            *(item.ablation_pag for item in self.deletion_deltas),
        )
        reference_pages = (
            self.raw_pag,
            self.minimal_bk_pag,
            self.full_bk_pag,
            self.wrong_plausible_bk_pag,
        )
        full_constraints = self.full_bk_pag.knowledge.constraints
        minimal_constraints = self.minimal_bk_pag.knowledge.constraints
        tier_map = dict(self.full_bk_pag.knowledge.temporal_tiers)
        expected_minimal = tuple(
            sorted(
                (
                    BKConstraintV2(
                        kind=BKConstraintKindV2.FORBIDDEN_DIRECTION,
                        left=later,
                        right=earlier,
                        rationale="temporal_tier",
                    )
                    for later, later_tier in tier_map.items()
                    for earlier, earlier_tier in tier_map.items()
                    if later_tier > earlier_tier
                ),
                key=lambda item: item.sort_key(),
            )
        )
        reverse_temporal = BKConstraintV2(
            kind=BKConstraintKindV2.FORBIDDEN_DIRECTION,
            left=self.x_variable_id,
            right=self.y_variable_id,
            rationale="wrong_plausible_tier_swap",
        )
        expected_wrong = tuple(
            sorted(
                {
                    *(
                        item
                        for item in full_constraints
                        if not (
                            item.kind is BKConstraintKindV2.FORBIDDEN_DIRECTION
                            and item.left == self.y_variable_id
                            and item.right == self.x_variable_id
                        )
                    ),
                    reverse_temporal,
                },
                key=lambda item: item.sort_key(),
            )
        )
        expected_candidate = _candidate_from_pages(
            self.raw_pag,
            self.full_bk_pag,
            self.x_variable_id,
            self.y_variable_id,
        )
        deletion_by_constraint = {
            item.removed_constraint: item for item in self.deletion_deltas
        }
        if (
            any(page.source_table_id != source_table_id for page in pages)
            or any(page.source_draw_id != source_draw_id for page in pages)
            or any(page.config != self.config for page in pages)
            or self.raw_pag.knowledge.kind is not BackgroundKnowledgeKindV2.RAW
            or self.minimal_bk_pag.knowledge.kind is not BackgroundKnowledgeKindV2.MINIMAL
            or self.full_bk_pag.knowledge.kind is not BackgroundKnowledgeKindV2.FULL
            or self.wrong_plausible_bk_pag.knowledge.kind
            is not BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE
            or not self.wrong_plausible_bk_pag.knowledge.excluded_from_candidate_evidence
            or self.raw_pag.run_label != "reference.raw"
            or self.minimal_bk_pag.run_label != "reference.minimal_bk"
            or self.full_bk_pag.run_label != "reference.full_bk"
            or self.wrong_plausible_bk_pag.run_label
            != "sensitivity.wrong_plausible_bk"
            or any(
                (page.row_count, page.row_payload_sha256, page.variable_ids)
                != (
                    self.raw_pag.row_count,
                    self.raw_pag.row_payload_sha256,
                    self.raw_pag.variable_ids,
                )
                for page in reference_pages
            )
            or any(
                page.knowledge.temporal_tiers
                != self.full_bk_pag.knowledge.temporal_tiers
                or page.knowledge.typed_adjacency_policy_sha256
                != self.full_bk_pag.knowledge.typed_adjacency_policy_sha256
                for page in pages
            )
            or minimal_constraints != expected_minimal
            or any(item not in full_constraints for item in minimal_constraints)
            or any(
                item not in minimal_constraints
                and not (
                    item.kind is BKConstraintKindV2.FORBIDDEN_ADJACENCY
                    and item.rationale == "typed_adjacency"
                )
                for item in full_constraints
            )
            or self.wrong_plausible_bk_pag.knowledge.constraints != expected_wrong
            or len(deletion_by_constraint) != len(self.deletion_deltas)
            or set(deletion_by_constraint) != set(full_constraints)
            or any(
                delta.full_pag_id != self.full_bk_pag.pag_id
                or delta.ablation_pag.run_label != f"reference.single_deletion.{index}"
                or delta.ablation_pag.knowledge.constraints
                != tuple(item for item in full_constraints if item != delta.removed_constraint)
                or delta.edge_deltas
                != _page_edge_deltas(self.full_bk_pag, delta.ablation_pag)
                or delta.candidate_selected_after_deletion
                != _candidate_from_pages(
                    self.raw_pag,
                    delta.ablation_pag,
                    self.x_variable_id,
                    self.y_variable_id,
                ).selected
                for index, delta in enumerate(self.deletion_deltas)
            )
            or (
                self.source_binding.analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL
            )
            != (source_draw_id is not None)
            or not self.x_variable_id.startswith("x.")
            or not self.y_variable_id.startswith("y.")
            or self.x_variable_id not in self.raw_pag.variable_ids
            or self.y_variable_id not in self.raw_pag.variable_ids
            or self.candidate.x_variable_id != self.x_variable_id
            or self.candidate.y_variable_id != self.y_variable_id
            or self.candidate.raw_pag_id != self.raw_pag.pag_id
            or self.candidate.full_pag_id != self.full_bk_pag.pag_id
            or self.candidate != expected_candidate
            or self.context_conditioning_query_id
            != self.source_binding.context_conditioning_query_id
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalFCIFailureArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "failure_artifact_id"
    _id_prefix = "observational_fci_failure_v2_"

    failure_artifact_id: str = Field(pattern=_FAILURE_PATTERN)
    source_binding: ObservationalSourceBindingV2
    config: ObservationalDiscoveryConfigV2
    failure: TypedDiscoveryFailureV2
    completed_pags: tuple[ObservationalPAGArtifactV2, ...] = ()

    @field_validator("completed_pags", mode="before")
    @classmethod
    def snapshot_completed_pags(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_failure_artifact(self) -> Self:
        if any(
            page.source_table_id != self.source_binding.authenticated_table_id
            or page.source_draw_id != self.source_binding.source_draw_id
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
    source_binding: ObservationalSourceBindingV2
    raw_pag: ObservationalPAGArtifactV2 | None
    full_bk_pag: ObservationalPAGArtifactV2 | None
    failure: TypedDiscoveryFailureV2 | None
    candidate_selected: bool

    @model_validator(mode="after")
    def validate_replicate(self) -> Self:
        complete = self.failure is None
        expected_selected = (
            False
            if not complete
            else _candidate_from_pages(
                self.raw_pag,  # type: ignore[arg-type]
                self.full_bk_pag,  # type: ignore[arg-type]
                next(
                    item
                    for item in self.raw_pag.variable_ids  # type: ignore[union-attr]
                    if item.startswith("x.")
                ),
                next(
                    item
                    for item in self.raw_pag.variable_ids  # type: ignore[union-attr]
                    if item.startswith("y.")
                ),
            ).selected
        )
        if (
            self.source_binding.source_draw_id is None
            or self.source_binding.analysis_kind is not DiscoveryAnalysisKindV2.TWO_LEVEL
            or
            complete != (self.raw_pag is not None and self.full_bk_pag is not None)
            or (not complete and self.full_bk_pag is not None)
            or self.candidate_selected
            and not complete
            or self.candidate_selected != expected_selected
        ):
            raise ValueError(self._safe_validation_message)
        if self.raw_pag is not None and (
            self.raw_pag.source_draw_id != self.source_binding.source_draw_id
            or self.raw_pag.source_table_id
            != self.source_binding.authenticated_table_id
            or self.raw_pag.knowledge.kind is not BackgroundKnowledgeKindV2.RAW
            or self.raw_pag.run_label != f"bootstrap.{self.replicate_index}.raw"
        ):
            raise ValueError(self._safe_validation_message)
        if self.full_bk_pag is not None and (
            self.full_bk_pag.source_draw_id != self.source_binding.source_draw_id
            or self.full_bk_pag.source_table_id
            != self.source_binding.authenticated_table_id
            or self.full_bk_pag.knowledge.kind is not BackgroundKnowledgeKindV2.FULL
            or self.full_bk_pag.run_label
            != f"bootstrap.{self.replicate_index}.full_bk"
            or self.raw_pag is None
            or (
                self.full_bk_pag.row_count,
                self.full_bk_pag.row_payload_sha256,
                self.full_bk_pag.variable_ids,
                self.full_bk_pag.config,
            )
            != (
                self.raw_pag.row_count,
                self.raw_pag.row_payload_sha256,
                self.raw_pag.variable_ids,
                self.raw_pag.config,
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ObservationalBootstrapArtifactV2(_ContentAddressedObservationalV2):
    _id_field = "bootstrap_id"
    _id_prefix = "observational_bootstrap_v2_"

    bootstrap_id: str = Field(pattern=_BOOTSTRAP_PATTERN)
    source_binding: ObservationalSourceBindingV2
    config: ObservationalDiscoveryConfigV2
    resample_domain: str
    resample_seeds: tuple[StrictInt, ...] = Field(min_length=1, max_length=10_000)
    replicates: tuple[BootstrapReplicateArtifactV2, ...] = Field(min_length=1, max_length=10_000)
    candidate_support_numerator: StrictInt = Field(ge=0, le=10_000)
    candidate_support_denominator: StrictInt = Field(ge=1, le=10_000)
    failed_replicate_count: StrictInt = Field(ge=0, le=10_000)
    stability_eligible: bool
    overall_failure: TypedDiscoveryFailureV2 | None

    @field_validator("resample_seeds", "replicates", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_bootstrap(self) -> Self:
        failures = sum(item.failure is not None for item in self.replicates)
        numerator = sum(item.candidate_selected for item in self.replicates)
        threshold_ok = failures / len(self.replicates) <= self.config.max_failed_bootstrap_fraction
        if (
            not _valid_identifier(self.resample_domain)
            or self.source_binding.source_draw_id is not None
            or self.source_binding.analysis_kind is not DiscoveryAnalysisKindV2.TWO_LEVEL
            or self.resample_seeds != tuple(sorted(self.resample_seeds))
            or len(self.resample_seeds) != len(set(self.resample_seeds))
            or len(self.replicates) != len(self.resample_seeds)
            or tuple(item.replicate_index for item in self.replicates)
            != tuple(range(len(self.replicates)))
            or tuple(item.source_binding.resample_seed for item in self.replicates)
            != self.resample_seeds
            or any(
                item.source_binding.authenticated_table_id
                != self.source_binding.authenticated_table_id
                or item.source_binding.authenticated_scope_id
                != self.source_binding.authenticated_scope_id
                or item.source_binding.table_spec_id != self.source_binding.table_spec_id
                or item.source_binding.raw_table_artifact_id
                != self.source_binding.raw_table_artifact_id
                or item.source_binding.receipt_payload_sha256
                != self.source_binding.receipt_payload_sha256
                or item.source_binding.context_conditioning_query_id
                != self.source_binding.context_conditioning_query_id
                or item.source_binding.independent_semantic_cluster_count
                != self.source_binding.independent_semantic_cluster_count
                or item.source_binding.resample_domain != self.resample_domain
                or (
                    item.raw_pag is not None and item.raw_pag.config != self.config
                )
                or (
                    item.full_bk_pag is not None
                    and item.full_bk_pag.config != self.config
                )
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

    @field_validator("variable_ids", "rows", "deterministic_relations", mode="before")
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        if cls is JCIAppendixDiagnosticArtifactV2 and value and type(value[0]) in {tuple, list}:
            return tuple(tuple(item) for item in value)
        return tuple(value)

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


def _path_edge_permits_direction(
    edge: PAGEdgeRecord,
    source: str,
    target: str,
) -> bool:
    source_mark, target_mark = edge.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


class SyntheticTrueChainDiagnosticV2(_ContentAddressedObservationalV2):
    """Backend-only Phase-0 gate; it can never promote main observational evidence."""

    _id_field = "diagnostic_id"
    _id_prefix = "observational_synthetic_gate_v2_"

    diagnostic_id: str = Field(pattern=_SYNTHETIC_PATTERN)
    scm_kind: Literal["true_prompt_variable_chain"]
    generator: Literal["numpy_default_rng_xor_chain_v1"]
    sample_size: StrictInt = Field(ge=4, le=100_000)
    seed: StrictInt = Field(ge=0, le=2**63 - 1)
    flip_probability: float = Field(gt=0.0, lt=0.5, allow_inf_nan=False)
    variable_ids: tuple[str, ...] = Field(min_length=3, max_length=3)
    rows: tuple[tuple[StrictInt, ...], ...] = Field(min_length=4, max_length=100_000)
    row_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    config: ObservationalDiscoveryConfigV2
    edges: tuple[PAGEdgeRecord, ...]
    recovered_possible_path: tuple[str, ...] = Field(min_length=3, max_length=3)
    backend_stdout: str = Field(max_length=200_000, repr=False)
    backend_stderr: Literal[""] = ""
    backend_warnings: tuple[str, ...] = ()
    source_kind: Literal["backend_only_synthetic"]
    phase0_gate_only: Literal[True]
    uses_authenticated_natural_table: Literal[False]
    upgrades_main_evidence: Literal[False]

    @field_validator(
        "variable_ids",
        "rows",
        "edges",
        "recovered_possible_path",
        "backend_warnings",
        mode="before",
    )
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        if type(value) not in {tuple, list}:
            return value
        if value and type(value[0]) in {tuple, list}:
            return tuple(tuple(item) for item in value)
        return tuple(value)

    @model_validator(mode="after")
    def validate_gate(self) -> Self:
        expected_variables = (
            "x.synthetic_source",
            "x.synthetic_bridge",
            "y.secure_yield",
        )
        by_pair = {(item.left, item.right): item for item in self.edges}
        path_pairs = tuple(
            tuple(sorted((left, right)))
            for left, right in zip(
                self.recovered_possible_path[:-1],
                self.recovered_possible_path[1:],
                strict=True,
            )
        )
        if (
            self.variable_ids != expected_variables
            or self.recovered_possible_path != expected_variables
            or len(self.rows) != self.sample_size
            or any(len(row) != 3 or any(value not in {0, 1} for value in row) for row in self.rows)
            or self.row_payload_sha256 != canonical_digest_v2(self.rows)
            or tuple((item.left, item.right) for item in self.edges)
            != tuple(sorted(by_pair))
            or len(by_pair) != len(self.edges)
            or set(by_pair) != set(path_pairs)
            or any(
                not _path_edge_permits_direction(
                    by_pair[pair],
                    source,
                    target,
                )
                for pair, source, target in zip(
                    path_pairs,
                    self.recovered_possible_path[:-1],
                    self.recovered_possible_path[1:],
                    strict=True,
                )
            )
            or self.backend_warnings
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
    "ObservationalDrawSelectionV2",
    "ObservationalFCIFailureArtifactV2",
    "ObservationalFCISuiteArtifactV2",
    "ObservationalPAGArtifactV2",
    "ObservationalSourceBindingV2",
    "PAGEdgeDeltaV2",
    "PolicyRelevantCandidateV2",
    "SyntheticTrueChainDiagnosticV2",
    "TypedDiscoveryFailureV2",
    "canonical_digest_v2",
]

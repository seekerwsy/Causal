"""Strict persisted contracts for prompt extraction backend proposals."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
import hashlib
import json
from typing import Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from secaware.schema.common import SafeValidationMixin, StrictModel, VersionedModel
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.tsg import MAX_TSG_STRING_BYTES, EdgeType, NodeType


MAX_RAW_RESPONSE_CHARS = 262_144
MAX_PROPOSAL_FACTS = 64
MAX_PROPOSAL_NODES = 512
MAX_PROPOSAL_EDGES = 2_048
MAX_FACT_EVIDENCE = 16
MAX_RELATION_FEATURES = 20

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PROPOSAL_ID_PATTERN = r"^proposal_[0-9a-f]{64}$"
_FEATURE_ID_PATTERN = r"^(task|safety|presentation)\.[a-z][a-z0-9_]*$"
_SEMANTIC_ROLE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_LOCAL_ID_PATTERN = r"^v[0-9]{1,4}$"
_INVALID_PROPOSAL_MESSAGE = "prompt extraction proposal validation failed"


class _ImmutableProposalModel(SafeValidationMixin, StrictModel):
    _safe_validation_message = _INVALID_PROPOSAL_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )


class EvidenceSpan(_ImmutableProposalModel):
    start: int = Field(ge=0, le=2**31 - 1)
    end: int = Field(gt=0, le=2**31 - 1)
    text: str = Field(min_length=1, max_length=4096, repr=False)
    text_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        value.encode("utf-8")
        return value

    @model_validator(mode="after")
    def validate_bounds_and_digest(self) -> "EvidenceSpan":
        if self.end <= self.start:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        if hashlib.sha256(self.text.encode("utf-8")).hexdigest() != self.text_sha256:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        return self


class SemanticFact(_ImmutableProposalModel):
    feature_id: str = Field(pattern=_FEATURE_ID_PATTERN, max_length=128)
    state: FeatureState
    semantic_role: str = Field(pattern=_SEMANTIC_ROLE_PATTERN)
    evidence: tuple[EvidenceSpan, ...] = Field(max_length=MAX_FACT_EVIDENCE)
    relation_feature_ids: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_RELATION_FEATURES,
    )

    @field_validator("state", mode="before")
    @classmethod
    def parse_state(cls, value: object) -> FeatureState:
        if type(value) is FeatureState:
            return cast(FeatureState, value)
        if type(value) is str:
            return FeatureState(value)
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)

    @field_validator("evidence", mode="before")
    @classmethod
    def canonicalize_evidence(cls, value: object) -> tuple[object, ...]:
        items = _bounded_tuple(value, MAX_FACT_EVIDENCE)
        return tuple(sorted(items, key=_evidence_sort_key))

    @field_validator("evidence")
    @classmethod
    def reject_duplicate_evidence(cls, value: tuple[EvidenceSpan, ...]) -> tuple[EvidenceSpan, ...]:
        return _unique_evidence(value)

    @field_validator("relation_feature_ids", mode="before")
    @classmethod
    def canonicalize_relations(cls, value: object) -> tuple[str, ...]:
        items = _bounded_tuple(value, MAX_RELATION_FEATURES)
        if any(type(item) is not str for item in items):
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        result = tuple(sorted(cast(tuple[str, ...], items)))
        if len(result) != len(set(result)):
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        return result


class DirectNodeProposal(_ImmutableProposalModel):
    local_id: str = Field(pattern=_LOCAL_ID_PATTERN)
    node_type: NodeType
    label: str = Field(min_length=1, max_length=1024)
    feature_id: str = Field(pattern=_FEATURE_ID_PATTERN, max_length=128)
    evidence: tuple[EvidenceSpan, ...] = Field(min_length=1, max_length=MAX_FACT_EVIDENCE)

    @field_validator("node_type", mode="before")
    @classmethod
    def parse_node_type(cls, value: object) -> NodeType:
        if type(value) is NodeType:
            return cast(NodeType, value)
        if type(value) is str:
            return NodeType(value)
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_TSG_STRING_BYTES:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        return value

    @field_validator("evidence", mode="before")
    @classmethod
    def canonicalize_evidence(cls, value: object) -> tuple[object, ...]:
        return tuple(sorted(_bounded_tuple(value, MAX_FACT_EVIDENCE), key=_evidence_sort_key))

    @field_validator("evidence")
    @classmethod
    def reject_duplicate_evidence(cls, value: tuple[EvidenceSpan, ...]) -> tuple[EvidenceSpan, ...]:
        return _unique_evidence(value)


class DirectEdgeProposal(_ImmutableProposalModel):
    src_local_id: str = Field(pattern=_LOCAL_ID_PATTERN)
    dst_local_id: str = Field(pattern=_LOCAL_ID_PATTERN)
    edge_type: EdgeType
    evidence: tuple[EvidenceSpan, ...] = Field(min_length=1, max_length=MAX_FACT_EVIDENCE)

    @field_validator("edge_type", mode="before")
    @classmethod
    def parse_edge_type(cls, value: object) -> EdgeType:
        if type(value) is EdgeType:
            return cast(EdgeType, value)
        if type(value) is str:
            return EdgeType(value)
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)

    @field_validator("evidence", mode="before")
    @classmethod
    def canonicalize_evidence(cls, value: object) -> tuple[object, ...]:
        return tuple(sorted(_bounded_tuple(value, MAX_FACT_EVIDENCE), key=_evidence_sort_key))

    @field_validator("evidence")
    @classmethod
    def reject_duplicate_evidence(cls, value: tuple[EvidenceSpan, ...]) -> tuple[EvidenceSpan, ...]:
        return _unique_evidence(value)


def _bounded_tuple(value: object, maximum: int) -> tuple[object, ...]:
    if type(value) not in {tuple, list}:
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)
    items = tuple(cast(list[object] | tuple[object, ...], value))
    if len(items) > maximum:
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)
    return items


def _unique_evidence(value: tuple[EvidenceSpan, ...]) -> tuple[EvidenceSpan, ...]:
    identities = tuple((span.start, span.end, span.text_sha256, span.text) for span in value)
    if len(identities) != len(set(identities)):
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)
    return value


def _mapping_value(value: object, name: str) -> object:
    if isinstance(value, BaseModel):
        return getattr(value, name)
    if isinstance(value, Mapping):
        return value.get(name)
    return None


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


def _evidence_sort_key(value: object) -> tuple[object, ...]:
    return (
        _mapping_value(value, "start"),
        _mapping_value(value, "end"),
        _mapping_value(value, "text_sha256"),
        _mapping_value(value, "text"),
    )


def _fact_sort_key(value: object) -> tuple[object, ...]:
    return (
        _mapping_value(value, "feature_id"),
        _mapping_value(value, "semantic_role"),
        _enum_value(_mapping_value(value, "state")),
        tuple(_mapping_value(value, "relation_feature_ids") or ()),
        tuple(_evidence_sort_key(item) for item in (_mapping_value(value, "evidence") or ())),
    )


def _node_sort_key(value: object) -> tuple[object, ...]:
    return (
        _mapping_value(value, "local_id"),
        _mapping_value(value, "feature_id"),
        _enum_value(_mapping_value(value, "node_type")),
        _mapping_value(value, "label"),
    )


def _edge_sort_key(value: object) -> tuple[object, ...]:
    return (
        _mapping_value(value, "src_local_id"),
        _mapping_value(value, "dst_local_id"),
        _enum_value(_mapping_value(value, "edge_type")),
        tuple(_evidence_sort_key(item) for item in (_mapping_value(value, "evidence") or ())),
    )


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return _jsonable(value.model_dump(mode="python", round_trip=True, warnings=False))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(nested) for key, nested in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _item_mapping(value: object) -> dict[str, object]:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="python", round_trip=True, warnings=False)
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError(_INVALID_PROPOSAL_MESSAGE)


def _canonicalize_fact_identity(value: object) -> dict[str, object]:
    result = _item_mapping(value)
    result["evidence"] = sorted(result.get("evidence", ()), key=_evidence_sort_key)
    result["relation_feature_ids"] = sorted(result.get("relation_feature_ids", ()))
    return result


def _canonicalize_node_identity(value: object) -> dict[str, object]:
    result = _item_mapping(value)
    result["evidence"] = sorted(result.get("evidence", ()), key=_evidence_sort_key)
    return result


def _canonicalize_edge_identity(value: object) -> dict[str, object]:
    result = _item_mapping(value)
    result["evidence"] = sorted(result.get("evidence", ()), key=_evidence_sort_key)
    return result


def _canonicalized_identity_payload(payload: Mapping[str, object]) -> dict[str, object]:
    allowed = {
        "schema_version",
        "prompt_id",
        "task_id",
        "prompt_sha256",
        "backend",
        "catalog_sha256",
        "policy_sha256",
        "response_sha256",
        "raw_response",
        "facts",
        "direct_nodes",
        "direct_edges",
    }
    normalized = {key: payload[key] for key in allowed if key in payload}
    normalized["facts"] = sorted(
        (_canonicalize_fact_identity(item) for item in normalized.get("facts", ())),
        key=_fact_sort_key,
    )
    normalized["direct_nodes"] = sorted(
        (_canonicalize_node_identity(item) for item in normalized.get("direct_nodes", ())),
        key=_node_sort_key,
    )
    normalized["direct_edges"] = sorted(
        (_canonicalize_edge_identity(item) for item in normalized.get("direct_edges", ())),
        key=_edge_sort_key,
    )
    return cast(dict[str, object], _jsonable(normalized))


def proposal_id_for_payload(payload: Mapping[str, object]) -> str:
    """Return the canonical proposal ID for a record-like payload."""
    canonical = json.dumps(
        _canonicalized_identity_payload(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "proposal_" + hashlib.sha256(canonical).hexdigest()


class PromptExtractionProposalRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_PROPOSAL_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    proposal_id: str = Field(pattern=_PROPOSAL_ID_PATTERN)
    prompt_id: str = Field(min_length=1, max_length=1024)
    task_id: str = Field(min_length=1, max_length=1024)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    backend: PromptExtractorBackend
    catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    raw_response: str | None = Field(default=None, max_length=MAX_RAW_RESPONSE_CHARS, repr=False)
    facts: tuple[SemanticFact, ...] = Field(default=(), max_length=MAX_PROPOSAL_FACTS)
    direct_nodes: tuple[DirectNodeProposal, ...] = Field(default=(), max_length=MAX_PROPOSAL_NODES)
    direct_edges: tuple[DirectEdgeProposal, ...] = Field(default=(), max_length=MAX_PROPOSAL_EDGES)

    @model_validator(mode="before")
    @classmethod
    def canonicalize_collections(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        result = dict(value)
        if "facts" in result:
            facts = tuple(
                SemanticFact.model_validate(item)
                for item in _bounded_tuple(result["facts"], MAX_PROPOSAL_FACTS)
            )
            result["facts"] = tuple(sorted(facts, key=_fact_sort_key))
        if "direct_nodes" in result:
            nodes = tuple(
                DirectNodeProposal.model_validate(item)
                for item in _bounded_tuple(result["direct_nodes"], MAX_PROPOSAL_NODES)
            )
            result["direct_nodes"] = tuple(sorted(nodes, key=_node_sort_key))
        if "direct_edges" in result:
            edges = tuple(
                DirectEdgeProposal.model_validate(item)
                for item in _bounded_tuple(result["direct_edges"], MAX_PROPOSAL_EDGES)
            )
            result["direct_edges"] = tuple(sorted(edges, key=_edge_sort_key))
        return result

    @field_validator("backend", mode="before")
    @classmethod
    def parse_backend(cls, value: object) -> PromptExtractorBackend:
        if type(value) is PromptExtractorBackend:
            return cast(PromptExtractorBackend, value)
        if type(value) is str:
            return PromptExtractorBackend(value)
        raise ValueError(_INVALID_PROPOSAL_MESSAGE)

    @field_validator("prompt_id", "task_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        value.encode("utf-8")
        return value

    @field_validator("raw_response")
    @classmethod
    def validate_response_size(cls, value: str | None) -> str | None:
        if value is not None:
            value.encode("utf-8")
        return value

    @model_validator(mode="after")
    def validate_closed_payload(self) -> "PromptExtractionProposalRecord":
        from secaware.tsg.feature_catalog import (
            PROMPT_FEATURE_CATALOG,
            PROMPT_FEATURE_CATALOG_SHA256,
            prompt_feature_edge_slot,
            prompt_feature_node_slot,
            prompt_feature_spec,
        )

        if self.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        response = "" if self.raw_response is None else self.raw_response
        if hashlib.sha256(response.encode("utf-8")).hexdigest() != self.response_sha256:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        if (
            proposal_id_for_payload(self.model_dump(mode="python", round_trip=True, warnings=False))
            != self.proposal_id
        ):
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)

        facts_backend = self.backend in {
            PromptExtractorBackend.LLM_FACTS_V1,
            PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        }
        if facts_backend:
            if self.direct_nodes or self.direct_edges:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            expected_ids = tuple(item.feature_id for item in PROMPT_FEATURE_CATALOG)
            actual_ids = tuple(fact.feature_id for fact in self.facts)
            if len(actual_ids) != len(expected_ids) or set(actual_ids) != set(expected_ids):
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            for fact in self.facts:
                spec = prompt_feature_spec(fact.feature_id)
                if fact.semantic_role != "feature_state":
                    raise ValueError(_INVALID_PROPOSAL_MESSAGE)
                if (fact.state is FeatureState.PRESENT) != bool(fact.evidence):
                    raise ValueError(_INVALID_PROPOSAL_MESSAGE)
                if fact.feature_id in fact.relation_feature_ids:
                    raise ValueError(_INVALID_PROPOSAL_MESSAGE)
                if any(
                    prompt_feature_spec(related).feature_family is not spec.feature_family
                    for related in fact.relation_feature_ids
                ):
                    raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            return self

        if self.facts or not self.direct_nodes:
            raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        aliases: dict[str, DirectNodeProposal] = {}
        semantic_identities: set[tuple[str, NodeType]] = set()
        for node in self.direct_nodes:
            prompt_feature_spec(node.feature_id)
            try:
                slot = prompt_feature_node_slot(node.feature_id, node.node_type)
            except KeyError:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE) from None
            if node.local_id in aliases or node.label != slot.canonical_label:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            identity = (node.feature_id, node.node_type)
            if identity in semantic_identities:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            aliases[node.local_id] = node
            semantic_identities.add(identity)

        node_types_by_feature: dict[str, set[NodeType]] = {}
        edge_types_by_feature: dict[str, set[EdgeType]] = {}
        edge_identities: set[tuple[str, str, EdgeType, tuple[tuple[int, int, str, str], ...]]] = (
            set()
        )
        for node in self.direct_nodes:
            node_types_by_feature.setdefault(node.feature_id, set()).add(node.node_type)
        for edge in self.direct_edges:
            src = aliases.get(edge.src_local_id)
            dst = aliases.get(edge.dst_local_id)
            if src is None or dst is None or src.feature_id != dst.feature_id:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            prompt_feature_spec(src.feature_id)
            try:
                edge_slot = prompt_feature_edge_slot(src.feature_id, edge.edge_type)
            except KeyError:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            if (src.node_type, dst.node_type) != (
                edge_slot.src_node_type,
                edge_slot.dst_node_type,
            ):
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            identity = (
                edge.src_local_id,
                edge.dst_local_id,
                edge.edge_type,
                tuple(
                    (span.start, span.end, span.text_sha256, span.text) for span in edge.evidence
                ),
            )
            if identity in edge_identities:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            edge_identities.add(identity)
            edge_types_by_feature.setdefault(src.feature_id, set()).add(edge.edge_type)
        for feature_id, actual_node_types in node_types_by_feature.items():
            spec = prompt_feature_spec(feature_id)
            if not set(spec.structural_node_types) <= actual_node_types:
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
            if not set(spec.structural_edge_types) <= edge_types_by_feature.get(feature_id, set()):
                raise ValueError(_INVALID_PROPOSAL_MESSAGE)
        return self


__all__ = [
    "DirectEdgeProposal",
    "DirectNodeProposal",
    "EvidenceSpan",
    "MAX_RAW_RESPONSE_CHARS",
    "PromptExtractionProposalRecord",
    "SemanticFact",
    "proposal_id_for_payload",
]

from collections.abc import Iterator, Mapping
from enum import Enum
from itertools import islice
import math
import re
from types import MappingProxyType
from typing import Literal, TypeAlias, cast

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from secaware.errors import ErrorCode
from secaware.schema.features import FeatureFamily, FeatureState, PromptExtractorBackend
from secaware.schema.common import (
    SafeValidationMixin,
    StrictModel,
    VersionedModel,
    model_shape_is_intact,
)


TSG_SCHEMA_VERSION = "2.1"
MAX_TSG_NODES = 512
MAX_TSG_EDGES = 2_048
MAX_TSG_ATTRIBUTES = 32
MAX_TSG_STRING_BYTES = 1_024
MAX_MOTIF_HOPS = 8
MAX_MOTIF_MATCHES = 256
MAX_TSG_EVIDENCE_OFFSET = 2**31 - 1

_NODE_ID_PATTERN = r"^n_[0-9a-f]{64}$"
_EDGE_ID_PATTERN = r"^e_[0-9a-f]{64}$"
_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PROPOSAL_ID_PATTERN = r"^proposal_[0-9a-f]{64}$"
_INVALID_TSG_MESSAGE = f"{ErrorCode.TSG_INVALID.name}: prompt TSG validation failed"
_MIN_SIGNED_64_BIT = -(2**63)
_MAX_SIGNED_64_BIT = 2**63 - 1


class NodeType(str, Enum):
    TASK_OPERATION = "task_operation"
    DATA_OBJECT = "data_object"
    SOURCE = "source"
    SINK = "sink"
    GUARD = "guard"
    PROMPT_REQUIREMENT = "prompt_requirement"
    TRUST_BOUNDARY = "trust_boundary"
    SECURITY_ASSUMPTION = "security_assumption"
    API = "api"
    CWE = "cwe"
    FEATURE = "feature"
    PRESENTATION_FEATURE = "presentation_feature"


class EdgeType(str, Enum):
    OPERATES_ON = "operates_on"
    SOURCE_OF = "source_of"
    FLOWS_TO = "flows_to"
    GUARDED_BY = "guarded_by"
    REQUIRES = "requires"
    OMITS = "omits"
    WEAKENS = "weakens"
    MAPS_TO = "maps_to"
    RELATED_TO = "related_to"


class MotifId(str, Enum):
    USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD = "user_path_to_file_open_without_guard"
    USER_STRING_TO_SQL_WITHOUT_PARAMETERIZATION = "user_string_to_sql_without_parameterization"
    USER_INPUT_TO_SHELL_WITHOUT_GUARD = "user_input_to_shell_without_guard"
    SENSITIVE_OPERATION_WITHOUT_AUTH_GUARD = "sensitive_operation_without_auth_guard"
    UNTRUSTED_DATA_TO_DESERIALIZATION_SINK = "untrusted_data_to_deserialization_sink"
    UNTRUSTED_SOURCE_TO_SENSITIVE_SINK_WITHOUT_GUARD = (
        "untrusted_source_to_sensitive_sink_without_guard"
    )


_EVIDENCE_ATTRIBUTE_KEYS = frozenset(
    {"evidence_start", "evidence_end", "evidence_sha256", "confidence"}
)
_FEATURE_ATTRIBUTE_KEYS = frozenset({"feature_id", "feature_family", "feature_state"})
_NODE_TYPE_ATTRIBUTE_KEYS: Mapping[NodeType, frozenset[str]] = MappingProxyType(
    {
        NodeType.TASK_OPERATION: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.DATA_OBJECT: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.SOURCE: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.SINK: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.GUARD: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.PROMPT_REQUIREMENT: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.TRUST_BOUNDARY: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.SECURITY_ASSUMPTION: _EVIDENCE_ATTRIBUTE_KEYS,
        NodeType.API: _EVIDENCE_ATTRIBUTE_KEYS | {"api_name"},
        NodeType.CWE: _EVIDENCE_ATTRIBUTE_KEYS | {"cwe_id"},
        NodeType.FEATURE: _FEATURE_ATTRIBUTE_KEYS,
        NodeType.PRESENTATION_FEATURE: _FEATURE_ATTRIBUTE_KEYS,
    }
)
_EDGE_TYPE_ATTRIBUTE_KEYS: Mapping[EdgeType, frozenset[str]] = MappingProxyType(
    {
        EdgeType.OPERATES_ON: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.SOURCE_OF: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.FLOWS_TO: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.GUARDED_BY: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.REQUIRES: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.OMITS: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.WEAKENS: _EVIDENCE_ATTRIBUTE_KEYS,
        EdgeType.MAPS_TO: _EVIDENCE_ATTRIBUTE_KEYS | {"mapping_kind"},
        EdgeType.RELATED_TO: _EVIDENCE_ATTRIBUTE_KEYS | {"relation_kind"},
    }
)
_EVIDENCE_LOCATION_KEYS = frozenset({"evidence_start", "evidence_end", "evidence_sha256"})


TSGScalar: TypeAlias = str | bool | int | float | None


class _FrozenTSGMapping(Mapping[str, TSGScalar]):
    __slots__ = ("__items",)

    def __init__(self, values: Mapping[str, TSGScalar]) -> None:
        object.__setattr__(self, "_FrozenTSGMapping__items", tuple(values.items()))

    def __getitem__(self, key: str) -> TSGScalar:
        for candidate, value in self.__items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self.__items)

    def __len__(self) -> int:
        return len(self.__items)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Mapping) and dict(self.items()) == dict(other.items())

    def __repr__(self) -> str:
        return f"_FrozenTSGMapping(<{len(self.__items)} items>)"

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("TSG attributes are read-only")

    def __deepcopy__(self, memo: dict[int, object]) -> "_FrozenTSGMapping":
        return self


FrozenTSGAttributes: TypeAlias = Mapping[str, TSGScalar]


def _require_canonical_text(value: str, *, max_bytes: int = MAX_TSG_STRING_BYTES) -> str:
    if not value or not value.strip() or value != value.strip():
        raise ValueError(_INVALID_TSG_MESSAGE)
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(_INVALID_TSG_MESSAGE)
    return value


def _snapshot_scalar(value: object) -> TSGScalar:
    if value is None or type(value) in {bool, str}:
        scalar = cast(TSGScalar, value)
    elif type(value) is int:
        if not _MIN_SIGNED_64_BIT <= value <= _MAX_SIGNED_64_BIT:
            raise ValueError(_INVALID_TSG_MESSAGE)
        scalar = value
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError(_INVALID_TSG_MESSAGE)
        scalar = value
    else:
        raise TypeError(_INVALID_TSG_MESSAGE)
    if type(scalar) is str and len(scalar.encode("utf-8")) > MAX_TSG_STRING_BYTES:
        raise ValueError(_INVALID_TSG_MESSAGE)
    return scalar


def _snapshot_attributes(
    value: object,
    *,
    allowed_keys: frozenset[str] | None = None,
) -> dict[str, TSGScalar]:
    if not isinstance(value, Mapping):
        raise TypeError(_INVALID_TSG_MESSAGE)
    snapshot: dict[str, TSGScalar] = {}
    for index, key in enumerate(islice(value, MAX_TSG_ATTRIBUTES + 1)):
        if index == MAX_TSG_ATTRIBUTES:
            raise ValueError(_INVALID_TSG_MESSAGE)
        if type(key) is not str or key in snapshot:
            raise ValueError(_INVALID_TSG_MESSAGE)
        _require_canonical_text(key)
        snapshot[key] = _snapshot_scalar(value[key])
    if allowed_keys is not None and not snapshot.keys() <= allowed_keys:
        raise ValueError(_INVALID_TSG_MESSAGE)
    _validate_attribute_values(snapshot)
    return snapshot


def _validate_attribute_values(attributes: Mapping[str, TSGScalar]) -> None:
    evidence_keys = attributes.keys() & _EVIDENCE_LOCATION_KEYS
    if evidence_keys and evidence_keys != _EVIDENCE_LOCATION_KEYS:
        raise ValueError(_INVALID_TSG_MESSAGE)
    if evidence_keys:
        start = attributes["evidence_start"]
        end = attributes["evidence_end"]
        digest = attributes["evidence_sha256"]
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= MAX_TSG_EVIDENCE_OFFSET
            or type(digest) is not str
            or re.fullmatch(_LOWERCASE_SHA256_PATTERN, digest) is None
        ):
            raise ValueError(_INVALID_TSG_MESSAGE)

    if "confidence" in attributes:
        confidence = attributes["confidence"]
        if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
            raise ValueError(_INVALID_TSG_MESSAGE)

    for key in ("api_name", "mapping_kind", "relation_kind"):
        if key in attributes:
            value = attributes[key]
            if type(value) is not str:
                raise ValueError(_INVALID_TSG_MESSAGE)
            _require_canonical_text(value)

    if "cwe_id" in attributes:
        cwe_id = attributes["cwe_id"]
        if type(cwe_id) is not str or re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe_id) is None:
            raise ValueError(_INVALID_TSG_MESSAGE)

    feature_keys = attributes.keys() & _FEATURE_ATTRIBUTE_KEYS
    if feature_keys:
        if feature_keys != _FEATURE_ATTRIBUTE_KEYS:
            raise ValueError(_INVALID_TSG_MESSAGE)
        feature_id = attributes["feature_id"]
        family = attributes["feature_family"]
        state = attributes["feature_state"]
        if not all(type(value) is str for value in (feature_id, family, state)):
            raise ValueError(_INVALID_TSG_MESSAGE)
        try:
            FeatureFamily(cast(str, family))
            FeatureState(cast(str, state))
        except ValueError:
            raise ValueError(_INVALID_TSG_MESSAGE) from None


def _parse_enum(value: object, enum_type: type[Enum]) -> Enum:
    if type(value) is enum_type:
        return cast(Enum, value)
    if type(value) is str:
        try:
            return enum_type(value)
        except ValueError:
            pass
    raise ValueError(_INVALID_TSG_MESSAGE)


def _snapshot_models(
    value: object,
    *,
    model_type: type["TSGNode"] | type["TSGEdge"],
    maximum: int,
) -> tuple["TSGNode", ...] | tuple["TSGEdge", ...]:
    if type(value) not in {list, tuple}:
        raise TypeError(_INVALID_TSG_MESSAGE)
    snapshots: list[TSGNode | TSGEdge] = []
    for index, item in enumerate(islice(value, maximum + 1)):
        if index == maximum:
            raise ValueError(_INVALID_TSG_MESSAGE)
        if isinstance(item, model_type):
            if type(item) is not model_type or not model_shape_is_intact(item):
                raise ValueError(_INVALID_TSG_MESSAGE)
            item = item.model_dump(mode="python", round_trip=True, warnings=False)
        snapshots.append(model_type.model_validate(item))
    return tuple(snapshots)


def _snapshot_id_path(
    value: object,
    *,
    maximum: int,
    pattern_prefix: Literal["n_", "e_"],
) -> tuple[str, ...]:
    if type(value) not in {list, tuple}:
        raise TypeError(_INVALID_TSG_MESSAGE)
    snapshot: list[str] = []
    for index, item in enumerate(islice(value, maximum + 1)):
        if index == maximum:
            raise ValueError(_INVALID_TSG_MESSAGE)
        if type(item) is not str:
            raise TypeError(_INVALID_TSG_MESSAGE)
        expected_length = 66
        if (
            len(item) != expected_length
            or not item.startswith(pattern_prefix)
            or any(character not in "0123456789abcdef" for character in item[2:])
        ):
            raise ValueError(_INVALID_TSG_MESSAGE)
        snapshot.append(item)
    return tuple(snapshot)


class _ImmutableTSGModel(SafeValidationMixin, StrictModel):
    _safe_validation_message = _INVALID_TSG_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class TSGNode(_ImmutableTSGModel):
    node_id: str = Field(pattern=_NODE_ID_PATTERN)
    semantic_key_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    node_type: NodeType
    label: str
    attributes: FrozenTSGAttributes = Field(default_factory=dict, repr=False)

    @field_validator("node_type", mode="before")
    @classmethod
    def parse_node_type(cls, value: object) -> NodeType:
        return cast(NodeType, _parse_enum(value, NodeType))

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        return _require_canonical_text(value)

    @field_validator("attributes", mode="before")
    @classmethod
    def snapshot_attributes(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> dict[str, TSGScalar]:
        node_type = info.data.get("node_type")
        if type(node_type) is not NodeType:
            raise ValueError(_INVALID_TSG_MESSAGE)
        return _snapshot_attributes(
            value,
            allowed_keys=_NODE_TYPE_ATTRIBUTE_KEYS[node_type],
        )

    @field_validator("attributes")
    @classmethod
    def freeze_attributes(cls, value: Mapping[str, TSGScalar]) -> FrozenTSGAttributes:
        return _FrozenTSGMapping(value)

    @field_serializer("attributes")
    def serialize_attributes(self, value: FrozenTSGAttributes) -> dict[str, TSGScalar]:
        return dict(value.items())

    @model_validator(mode="after")
    def validate_feature_identity(self) -> "TSGNode":
        if self.node_type not in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}:
            return self
        from secaware.tsg.feature_catalog import prompt_feature_spec

        feature_id = cast(str, self.attributes["feature_id"])
        try:
            spec = prompt_feature_spec(feature_id)
        except KeyError:
            raise ValueError(_INVALID_TSG_MESSAGE) from None
        family = FeatureFamily(cast(str, self.attributes["feature_family"]))
        expected_node_type = (
            NodeType.PRESENTATION_FEATURE
            if family is FeatureFamily.PRESENTATION_CONTROL
            else NodeType.FEATURE
        )
        if (
            self.label != feature_id
            or spec.feature_family is not family
            or self.node_type is not expected_node_type
        ):
            raise ValueError(_INVALID_TSG_MESSAGE)
        return self


class TSGEdge(_ImmutableTSGModel):
    edge_id: str = Field(pattern=_EDGE_ID_PATTERN)
    src: str = Field(pattern=_NODE_ID_PATTERN)
    dst: str = Field(pattern=_NODE_ID_PATTERN)
    edge_type: EdgeType
    attributes: FrozenTSGAttributes = Field(default_factory=dict, repr=False)

    @field_validator("edge_type", mode="before")
    @classmethod
    def parse_edge_type(cls, value: object) -> EdgeType:
        return cast(EdgeType, _parse_enum(value, EdgeType))

    @field_validator("attributes", mode="before")
    @classmethod
    def snapshot_attributes(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> dict[str, TSGScalar]:
        edge_type = info.data.get("edge_type")
        if type(edge_type) is not EdgeType:
            raise ValueError(_INVALID_TSG_MESSAGE)
        return _snapshot_attributes(
            value,
            allowed_keys=_EDGE_TYPE_ATTRIBUTE_KEYS[edge_type],
        )

    @field_validator("attributes")
    @classmethod
    def freeze_attributes(cls, value: Mapping[str, TSGScalar]) -> FrozenTSGAttributes:
        return _FrozenTSGMapping(value)

    @field_serializer("attributes")
    def serialize_attributes(self, value: FrozenTSGAttributes) -> dict[str, TSGScalar]:
        return dict(value.items())


class PromptTSGRecord(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_TSG_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.1"]
    graph_id: str
    source_type: Literal["prompt"]
    prompt_id: str
    task_id: str
    task_family: str
    cwe: str
    extractor_backend: PromptExtractorBackend
    extractor_policy_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    proposal_id: str = Field(pattern=_PROPOSAL_ID_PATTERN)
    ontology_version: str
    motif_version: str
    graph_sha256: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    nodes: tuple[TSGNode, ...]
    edges: tuple[TSGEdge, ...]
    shadow: FrozenTSGAttributes = Field(repr=False)

    @field_validator(
        "graph_id",
        "prompt_id",
        "task_id",
        "task_family",
        "cwe",
        "ontology_version",
        "motif_version",
    )
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _require_canonical_text(value)

    @field_validator("extractor_backend", mode="before")
    @classmethod
    def parse_extractor_backend(cls, value: object) -> PromptExtractorBackend:
        return cast(
            PromptExtractorBackend,
            _parse_enum(value, PromptExtractorBackend),
        )

    @field_validator("nodes", mode="before")
    @classmethod
    def snapshot_nodes(cls, value: object) -> tuple[TSGNode, ...]:
        return cast(
            tuple[TSGNode, ...],
            _snapshot_models(value, model_type=TSGNode, maximum=MAX_TSG_NODES),
        )

    @field_validator("edges", mode="before")
    @classmethod
    def snapshot_edges(cls, value: object) -> tuple[TSGEdge, ...]:
        return cast(
            tuple[TSGEdge, ...],
            _snapshot_models(value, model_type=TSGEdge, maximum=MAX_TSG_EDGES),
        )

    @field_validator("shadow", mode="before")
    @classmethod
    def snapshot_shadow(cls, value: object) -> dict[str, TSGScalar]:
        return _snapshot_attributes(value)

    @field_validator("shadow")
    @classmethod
    def freeze_shadow(cls, value: Mapping[str, TSGScalar]) -> FrozenTSGAttributes:
        return _FrozenTSGMapping(value)

    @field_serializer("shadow")
    def serialize_shadow(self, value: FrozenTSGAttributes) -> dict[str, TSGScalar]:
        return dict(value.items())

    @model_validator(mode="after")
    def validate_graph_shape(self) -> "PromptTSGRecord":
        node_ids = tuple(node.node_id for node in self.nodes)
        edge_ids = tuple(edge.edge_id for edge in self.edges)
        if len(set(node_ids)) != len(node_ids) or len(set(edge_ids)) != len(edge_ids):
            raise ValueError(_INVALID_TSG_MESSAGE)
        if node_ids != tuple(sorted(node_ids)) or edge_ids != tuple(sorted(edge_ids)):
            raise ValueError(_INVALID_TSG_MESSAGE)
        known_nodes = set(node_ids)
        if any(edge.src not in known_nodes or edge.dst not in known_nodes for edge in self.edges):
            raise ValueError(_INVALID_TSG_MESSAGE)
        feature_nodes = tuple(
            node
            for node in self.nodes
            if node.node_type in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}
        )
        feature_ids = tuple(cast(str, node.attributes["feature_id"]) for node in feature_nodes)
        if len(set(feature_ids)) != len(feature_ids):
            raise ValueError(_INVALID_TSG_MESSAGE)
        structural_node_types = {
            node.node_type
            for node in self.nodes
            if node.node_type not in {NodeType.FEATURE, NodeType.PRESENTATION_FEATURE}
        }
        structural_edge_types = {edge.edge_type for edge in self.edges}
        from secaware.tsg.feature_catalog import prompt_feature_spec

        for node in feature_nodes:
            if (
                FeatureState(cast(str, node.attributes["feature_state"]))
                is not FeatureState.PRESENT
            ):
                continue
            spec = prompt_feature_spec(cast(str, node.attributes["feature_id"]))
            if (
                not set(spec.structural_node_types) <= structural_node_types
                or not set(spec.structural_edge_types) <= structural_edge_types
            ):
                raise ValueError(_INVALID_TSG_MESSAGE)
        return self


class MotifMatch(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_TSG_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    motif_id: MotifId
    node_path: tuple[str, ...]
    edge_path: tuple[str, ...]
    guarded: StrictBool
    guard_nodes: tuple[str, ...]

    @field_validator("motif_id", mode="before")
    @classmethod
    def parse_motif_id(cls, value: object) -> MotifId:
        return cast(MotifId, _parse_enum(value, MotifId))

    @field_validator("node_path", mode="before")
    @classmethod
    def snapshot_node_path(cls, value: object) -> tuple[str, ...]:
        return _snapshot_id_path(value, maximum=MAX_MOTIF_HOPS + 1, pattern_prefix="n_")

    @field_validator("edge_path", mode="before")
    @classmethod
    def snapshot_edge_path(cls, value: object) -> tuple[str, ...]:
        return _snapshot_id_path(value, maximum=MAX_MOTIF_HOPS, pattern_prefix="e_")

    @field_validator("guard_nodes", mode="before")
    @classmethod
    def snapshot_guard_nodes(cls, value: object) -> tuple[str, ...]:
        return _snapshot_id_path(value, maximum=MAX_MOTIF_MATCHES, pattern_prefix="n_")

    @model_validator(mode="after")
    def validate_evidence(self) -> "MotifMatch":
        if not self.node_path or len(self.edge_path) + 1 != len(self.node_path):
            raise ValueError(_INVALID_TSG_MESSAGE)
        if len(set(self.edge_path)) != len(self.edge_path):
            raise ValueError(_INVALID_TSG_MESSAGE)
        if len(set(self.guard_nodes)) != len(self.guard_nodes):
            raise ValueError(_INVALID_TSG_MESSAGE)
        if self.guard_nodes != tuple(sorted(self.guard_nodes)):
            raise ValueError(_INVALID_TSG_MESSAGE)
        if self.guarded != bool(self.guard_nodes):
            raise ValueError(_INVALID_TSG_MESSAGE)
        return self


__all__ = [
    "EdgeType",
    "FrozenTSGAttributes",
    "MAX_MOTIF_HOPS",
    "MAX_MOTIF_MATCHES",
    "MAX_TSG_ATTRIBUTES",
    "MAX_TSG_EDGES",
    "MAX_TSG_EVIDENCE_OFFSET",
    "MAX_TSG_NODES",
    "MAX_TSG_STRING_BYTES",
    "MotifId",
    "MotifMatch",
    "NodeType",
    "PromptTSGRecord",
    "TSGEdge",
    "TSGNode",
    "TSGScalar",
    "TSG_SCHEMA_VERSION",
]

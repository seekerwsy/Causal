"""Immutable finite catalog for prompt task, safety, and presentation features."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import re

from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.schema.tsg import MAX_TSG_STRING_BYTES, EdgeType, NodeType


FEATURE_CATALOG_VERSION = "1.0"
_FEATURE_ID_RE = re.compile(r"^(task|safety|presentation)\.[a-z][a-z0-9_]*$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
_MAX_TEXT_BYTES = 128
_PREFIX_BY_FAMILY = {
    FeatureFamily.TASK_FUNCTION: "task.",
    FeatureFamily.SAFETY_CONTROL: "safety.",
    FeatureFamily.PRESENTATION_CONTROL: "presentation.",
}
_ALL_OPERATIONS = (FeatureOperation.ADD, FeatureOperation.REMOVE)
_EXPECTED_FEATURE_IDS = (
    "task.input_consumption",
    "task.file_read",
    "task.database_query",
    "task.process_launch",
    "task.privileged_action",
    "task.object_deserialization",
    "safety.input_validation",
    "safety.path_normalization",
    "safety.sql_parameterization",
    "safety.safe_subprocess",
    "safety.authorization_check",
    "safety.safe_deserialization",
    "safety.generic_security_reminder",
    "safety.prohibited_unsafe_request",
    "safety.vulnerability_disclosure",
    "safety.expected_outcome_leakage",
    "presentation.noop_rewrite",
    "presentation.length_matched_placebo",
    "presentation.sham_edit",
    "presentation.matched_control",
)


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    feature_id: str
    feature_family: FeatureFamily
    applicable_cwes: tuple[str, ...]
    applicable_task_families: tuple[str, ...]
    intervenable: bool
    operations: tuple[FeatureOperation, ...]
    structural_node_types: tuple[NodeType, ...]
    structural_edge_types: tuple[EdgeType, ...]
    deterministic_terms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FeatureNodeSlot:
    """One finite direct-graph semantic slot derived from a catalog feature."""

    node_type: NodeType
    canonical_label: str
    is_presence_marker: bool


def _feature(
    feature_id: str,
    family: FeatureFamily,
    *,
    cwes: tuple[str, ...] = (),
    task_families: tuple[str, ...] = (),
    intervenable: bool = True,
    nodes: tuple[NodeType, ...] = (),
    edges: tuple[EdgeType, ...] = (),
    terms: tuple[str, ...] = (),
) -> FeatureSpec:
    return FeatureSpec(
        feature_id=feature_id,
        feature_family=family,
        applicable_cwes=cwes,
        applicable_task_families=task_families,
        intervenable=intervenable,
        operations=_ALL_OPERATIONS if intervenable else (),
        structural_node_types=nodes,
        structural_edge_types=edges,
        deterministic_terms=terms,
    )


PROMPT_FEATURE_CATALOG = (
    _feature(
        "task.input_consumption",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-20",),
        task_families=("input_handling",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SOURCE),
        edges=(EdgeType.OPERATES_ON, EdgeType.SOURCE_OF),
        terms=("accept user input", "process form input", "parse request field"),
    ),
    _feature(
        "task.file_read",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-22",),
        task_families=("file_access", "path_handling"),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("user-provided file path", "user path", "filename from the user"),
    ),
    _feature(
        "task.database_query",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-89",),
        task_families=("sql_query",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("sql query", "database query", "sqlite database"),
    ),
    _feature(
        "task.process_launch",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-78",),
        task_families=("command_execution",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("run a command", "execute command", "launch a subprocess"),
    ),
    _feature(
        "task.privileged_action",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-862",),
        task_families=("authorization",),
        nodes=(NodeType.TASK_OPERATION, NodeType.SINK),
        terms=("delete an account", "admin action", "sensitive operation"),
    ),
    _feature(
        "task.object_deserialization",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-502",),
        task_families=("deserialization",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("deserialize data", "load a pickle", "parse serialized object"),
    ),
    _feature(
        "safety.input_validation",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-20",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("validate input schema", "enforce input length", "reject invalid input"),
    ),
    _feature(
        "safety.path_normalization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-22",),
        task_families=("file_access", "path_handling"),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("normalize it", "normalize the path", "restrict it to a base directory"),
    ),
    _feature(
        "safety.sql_parameterization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-89",),
        task_families=("sql_query",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("parameterized queries", "prepared statement", "bind parameters"),
    ),
    _feature(
        "safety.safe_subprocess",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-78",),
        task_families=("command_execution",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("shell=false", "list arguments", "without a shell"),
    ),
    _feature(
        "safety.authorization_check",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-862",),
        task_families=("authorization",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("authorization check", "verify permissions", "enforce role access"),
    ),
    _feature(
        "safety.safe_deserialization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-502",),
        task_families=("deserialization",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("safe object loading", "allowlisted types", "trusted serializer"),
    ),
    _feature(
        "safety.generic_security_reminder",
        FeatureFamily.SAFETY_CONTROL,
        nodes=(NodeType.PROMPT_REQUIREMENT,),
        terms=("follow security best practices", "write secure code"),
    ),
    _feature(
        "safety.prohibited_unsafe_request",
        FeatureFamily.SAFETY_CONTROL,
        intervenable=False,
        nodes=(NodeType.SECURITY_ASSUMPTION,),
        terms=("ignore security", "disable security checks"),
    ),
    _feature(
        "safety.vulnerability_disclosure",
        FeatureFamily.SAFETY_CONTROL,
        intervenable=False,
        nodes=(NodeType.SECURITY_ASSUMPTION,),
        terms=("contains a vulnerability", "known vulnerability"),
    ),
    _feature(
        "safety.expected_outcome_leakage",
        FeatureFamily.SAFETY_CONTROL,
        intervenable=False,
        nodes=(NodeType.SECURITY_ASSUMPTION,),
        terms=("expected to pass", "expected to fail"),
    ),
    _feature("presentation.noop_rewrite", FeatureFamily.PRESENTATION_CONTROL),
    _feature("presentation.length_matched_placebo", FeatureFamily.PRESENTATION_CONTROL),
    _feature("presentation.sham_edit", FeatureFamily.PRESENTATION_CONTROL),
    _feature("presentation.matched_control", FeatureFamily.PRESENTATION_CONTROL),
)


def _node_slots_for_spec(spec: FeatureSpec) -> tuple[FeatureNodeSlot, ...]:
    if spec.structural_node_types:
        return tuple(
            FeatureNodeSlot(
                node_type=node_type,
                canonical_label=f"{spec.feature_id}:{node_type.value}",
                is_presence_marker=False,
            )
            for node_type in spec.structural_node_types
        )
    marker_type = (
        NodeType.PRESENTATION_FEATURE
        if spec.feature_family is FeatureFamily.PRESENTATION_CONTROL
        else NodeType.FEATURE
    )
    return (
        FeatureNodeSlot(
            node_type=marker_type,
            canonical_label=spec.feature_id,
            is_presence_marker=True,
        ),
    )


_PROMPT_FEATURE_NODE_SLOTS = {
    spec.feature_id: _node_slots_for_spec(spec) for spec in PROMPT_FEATURE_CATALOG
}


def _validate_feature_catalog(catalog: tuple[FeatureSpec, ...]) -> None:
    if type(catalog) is not tuple or len(catalog) != 20:
        raise RuntimeError("invalid prompt feature catalog shape")
    if any(type(item) is not FeatureSpec for item in catalog):
        raise RuntimeError("invalid prompt feature catalog entry")
    feature_ids = tuple(item.feature_id for item in catalog)
    if len(feature_ids) != len(set(feature_ids)):
        raise RuntimeError("duplicate prompt feature id")
    if feature_ids != _EXPECTED_FEATURE_IDS:
        raise RuntimeError("unexpected prompt feature id")
    if {item.feature_family for item in catalog} != set(FeatureFamily):
        raise RuntimeError("incomplete prompt feature families")
    forbidden = {"secure", "insecure", "outcome", "oracle", "code"}
    if forbidden & {field.name.casefold() for field in fields(FeatureSpec)}:
        raise RuntimeError("forbidden prompt feature catalog field")

    for item in catalog:
        prefix = _PREFIX_BY_FAMILY[item.feature_family]
        if _FEATURE_ID_RE.fullmatch(item.feature_id) is None or not item.feature_id.startswith(
            prefix
        ):
            raise RuntimeError("invalid prompt feature family prefix")
        tuple_fields = (
            item.applicable_cwes,
            item.applicable_task_families,
            item.operations,
            item.structural_node_types,
            item.structural_edge_types,
            item.deterministic_terms,
        )
        if any(type(value) is not tuple for value in tuple_fields):
            raise RuntimeError("mutable prompt feature catalog field")
        expected_operations = _ALL_OPERATIONS if item.intervenable else ()
        if type(item.intervenable) is not bool or item.operations != expected_operations:
            raise RuntimeError("invalid prompt feature operations")
        if len(item.applicable_cwes) != len(set(item.applicable_cwes)) or any(
            _CWE_RE.fullmatch(cwe) is None for cwe in item.applicable_cwes
        ):
            raise RuntimeError("invalid prompt feature CWE scope")
        text = (*item.applicable_task_families, *item.deterministic_terms)
        if len(text) != len(set(text)) or any(
            type(value) is not str
            or not value
            or value != value.strip()
            or value != value.casefold()
            or not value.isascii()
            or len(value.encode("ascii")) > _MAX_TEXT_BYTES
            for value in text
        ):
            raise RuntimeError("invalid prompt feature catalog text")
        if len(item.structural_node_types) != len(set(item.structural_node_types)) or any(
            type(value) is not NodeType for value in item.structural_node_types
        ):
            raise RuntimeError("invalid prompt feature node contract")
        if len(item.structural_edge_types) != len(set(item.structural_edge_types)) or any(
            type(value) is not EdgeType for value in item.structural_edge_types
        ):
            raise RuntimeError("invalid prompt feature edge contract")
        slots = _PROMPT_FEATURE_NODE_SLOTS[item.feature_id]
        if (
            not slots
            or len({slot.node_type for slot in slots}) != len(slots)
            or any(
                type(slot) is not FeatureNodeSlot
                or type(slot.node_type) is not NodeType
                or type(slot.canonical_label) is not str
                or not slot.canonical_label
                or slot.canonical_label != slot.canonical_label.strip()
                or len(slot.canonical_label.encode("utf-8")) > MAX_TSG_STRING_BYTES
                or type(slot.is_presence_marker) is not bool
                for slot in slots
            )
        ):
            raise RuntimeError("invalid prompt feature node slots")
        if bool(item.structural_node_types) == any(slot.is_presence_marker for slot in slots):
            raise RuntimeError("invalid prompt feature presence marker")

    non_intervenable = {item.feature_id for item in catalog if not item.intervenable}
    if non_intervenable != {
        "safety.prohibited_unsafe_request",
        "safety.vulnerability_disclosure",
        "safety.expected_outcome_leakage",
    }:
        raise RuntimeError("invalid prompt feature protocol sentinels")


_validate_feature_catalog(PROMPT_FEATURE_CATALOG)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_entry(item: FeatureSpec) -> dict[str, object]:
    payload = asdict(item)
    payload["feature_family"] = item.feature_family.value
    payload["operations"] = [value.value for value in item.operations]
    payload["structural_node_types"] = [value.value for value in item.structural_node_types]
    payload["structural_edge_types"] = [value.value for value in item.structural_edge_types]
    return payload


_CATALOG_DIGEST_PAYLOAD = {
    "catalog_version": FEATURE_CATALOG_VERSION,
    "entries": [_digest_entry(item) for item in PROMPT_FEATURE_CATALOG],
}
PROMPT_FEATURE_CATALOG_SHA256 = hashlib.sha256(_canonical_json(_CATALOG_DIGEST_PAYLOAD)).hexdigest()


def prompt_feature_spec(feature_id: str) -> FeatureSpec:
    """Return one exact reviewed feature entry; unknown IDs fail closed."""
    if type(feature_id) is not str:
        raise KeyError("unknown prompt feature")
    for item in PROMPT_FEATURE_CATALOG:
        if item.feature_id == feature_id:
            return item
    raise KeyError("unknown prompt feature")


def prompt_feature_node_slots(feature_id: str) -> tuple[FeatureNodeSlot, ...]:
    """Return the exact finite direct-graph slots for one catalog feature."""
    prompt_feature_spec(feature_id)
    return _PROMPT_FEATURE_NODE_SLOTS[feature_id]


def prompt_feature_node_slot(feature_id: str, node_type: NodeType) -> FeatureNodeSlot:
    """Return one exact feature/type slot; unknown combinations fail closed."""
    if type(node_type) is not NodeType:
        raise KeyError("unknown prompt feature node slot")
    for slot in prompt_feature_node_slots(feature_id):
        if slot.node_type is node_type:
            return slot
    raise KeyError("unknown prompt feature node slot")


__all__ = [
    "FEATURE_CATALOG_VERSION",
    "FeatureNodeSlot",
    "FeatureSpec",
    "PROMPT_FEATURE_CATALOG",
    "PROMPT_FEATURE_CATALOG_SHA256",
    "prompt_feature_node_slot",
    "prompt_feature_node_slots",
    "prompt_feature_spec",
]

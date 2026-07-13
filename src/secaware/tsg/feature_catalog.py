"""Immutable finite catalog for prompt task, safety, and presentation features."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import re

from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.schema.tsg import MAX_TSG_STRING_BYTES, EdgeType, NodeType


FEATURE_CATALOG_VERSION = "1.2"
_FEATURE_ID_RE = re.compile(r"^(task|safety|presentation)\.[a-z][a-z0-9_]*$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
_MAX_TEXT_BYTES = 128
_PREFIX_BY_FAMILY = {
    FeatureFamily.TASK_FUNCTION: "task.",
    FeatureFamily.SAFETY_CONTROL: "safety.",
    FeatureFamily.PRESENTATION_CONTROL: "presentation.",
}
_EDGE_ENDPOINT_TYPES = {
    EdgeType.OPERATES_ON: (NodeType.TASK_OPERATION, NodeType.DATA_OBJECT),
    EdgeType.SOURCE_OF: (NodeType.SOURCE, NodeType.DATA_OBJECT),
    EdgeType.FLOWS_TO: (NodeType.DATA_OBJECT, NodeType.SINK),
    EdgeType.GUARDED_BY: (NodeType.DATA_OBJECT, NodeType.GUARD),
    EdgeType.REQUIRES: (NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
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
_EXPECTED_MATCHED_CONTROLS = {
    "presentation.noop_rewrite": "presentation.matched_control",
    "presentation.length_matched_placebo": "presentation.matched_control",
    "presentation.sham_edit": "presentation.matched_control",
}


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    feature_id: str
    feature_family: FeatureFamily
    applicable_cwes: tuple[str, ...]
    applicable_task_families: tuple[str, ...]
    intervenable: bool
    operations: tuple[FeatureOperation, ...]
    matched_control_feature_id: str | None
    structural_node_types: tuple[NodeType, ...]
    structural_edge_types: tuple[EdgeType, ...]
    deterministic_terms: tuple[str, ...]
    intervention_clauses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FeatureNodeSlot:
    """One finite direct-graph semantic slot derived from a catalog feature."""

    node_type: NodeType
    canonical_label: str
    is_presence_marker: bool


@dataclass(frozen=True, slots=True)
class FeatureEdgeSlot:
    """One finite direct-graph edge slot derived from a catalog feature."""

    edge_type: EdgeType
    src_node_type: NodeType
    dst_node_type: NodeType


def _feature(
    feature_id: str,
    family: FeatureFamily,
    *,
    cwes: tuple[str, ...] = (),
    task_families: tuple[str, ...] = (),
    intervenable: bool = True,
    matched_control: str | None = None,
    nodes: tuple[NodeType, ...] = (),
    edges: tuple[EdgeType, ...] = (),
    terms: tuple[str, ...] = (),
    clauses: tuple[str, ...] = (),
) -> FeatureSpec:
    return FeatureSpec(
        feature_id=feature_id,
        feature_family=family,
        applicable_cwes=cwes,
        applicable_task_families=task_families,
        intervenable=intervenable,
        operations=_ALL_OPERATIONS if intervenable else (),
        matched_control_feature_id=matched_control,
        structural_node_types=nodes,
        structural_edge_types=edges,
        deterministic_terms=terms,
        intervention_clauses=clauses,
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
        clauses=(" Accept user input.",),
    ),
    _feature(
        "task.file_read",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-22",),
        task_families=("file_access", "path_handling"),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("user-provided file path", "user path", "filename from the user"),
        clauses=(" Read a user-provided file path.",),
    ),
    _feature(
        "task.database_query",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-89",),
        task_families=("sql_query",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("sql query", "database query", "sqlite database"),
        clauses=(" Query a SQLite database.",),
    ),
    _feature(
        "task.process_launch",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-78",),
        task_families=("command_execution",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("run a command", "execute command", "launch a subprocess"),
        clauses=(" Launch a subprocess.",),
    ),
    _feature(
        "task.privileged_action",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-862",),
        task_families=("authorization",),
        nodes=(NodeType.TASK_OPERATION, NodeType.SINK),
        terms=("delete an account", "admin action", "sensitive operation"),
        clauses=(" Perform a sensitive operation.",),
    ),
    _feature(
        "task.object_deserialization",
        FeatureFamily.TASK_FUNCTION,
        cwes=("CWE-502",),
        task_families=("deserialization",),
        nodes=(NodeType.TASK_OPERATION, NodeType.DATA_OBJECT, NodeType.SINK),
        edges=(EdgeType.OPERATES_ON, EdgeType.FLOWS_TO),
        terms=("deserialize data", "load a pickle", "parse serialized object"),
        clauses=(" Deserialize the provided data.",),
    ),
    _feature(
        "safety.input_validation",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-20",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("validate input schema", "enforce input length", "reject invalid input"),
        clauses=(" Validate the input schema and reject invalid input.",),
    ),
    _feature(
        "safety.path_normalization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-22",),
        task_families=("file_access", "path_handling"),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("normalize it", "normalize the path", "restrict it to a base directory"),
        clauses=(
            " Normalize the path.",
            " Normalize the path and restrict it to a base directory.",
        ),
    ),
    _feature(
        "safety.sql_parameterization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-89",),
        task_families=("sql_query",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("parameterized queries", "prepared statement", "bind parameters"),
        clauses=(" Use parameterized queries for user-provided values.",),
    ),
    _feature(
        "safety.safe_subprocess",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-78",),
        task_families=("command_execution",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("shell=false", "list arguments", "without a shell"),
        clauses=(" Pass arguments as a list and run without a shell.",),
    ),
    _feature(
        "safety.authorization_check",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-862",),
        task_families=("authorization",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("authorization check", "verify permissions", "enforce role access"),
        clauses=(" Verify permissions before the sensitive operation.",),
    ),
    _feature(
        "safety.safe_deserialization",
        FeatureFamily.SAFETY_CONTROL,
        cwes=("CWE-502",),
        task_families=("deserialization",),
        nodes=(NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
        edges=(EdgeType.REQUIRES,),
        terms=("safe object loading", "allowlisted types", "trusted serializer"),
        clauses=(" Allow only approved types during deserialization.",),
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
    _feature(
        "presentation.noop_rewrite",
        FeatureFamily.PRESENTATION_CONTROL,
        matched_control="presentation.matched_control",
        terms=("no-op rewrite", "noop rewrite", "no op rewrite"),
        clauses=(" Apply a no-op rewrite.",),
    ),
    _feature(
        "presentation.length_matched_placebo",
        FeatureFamily.PRESENTATION_CONTROL,
        matched_control="presentation.matched_control",
        terms=("length-matched placebo", "length matched placebo"),
        clauses=(" Apply a length-matched placebo rewrite.",),
    ),
    _feature(
        "presentation.sham_edit",
        FeatureFamily.PRESENTATION_CONTROL,
        matched_control="presentation.matched_control",
        terms=("sham edit",),
        clauses=(" Apply a sham edit.",),
    ),
    _feature(
        "presentation.matched_control",
        FeatureFamily.PRESENTATION_CONTROL,
        terms=("matched control",),
        clauses=(" Apply a matched-control rewrite.",),
    ),
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


def _edge_slots_for_spec(spec: FeatureSpec) -> tuple[FeatureEdgeSlot, ...]:
    result: list[FeatureEdgeSlot] = []
    for edge_type in spec.structural_edge_types:
        endpoint_types = _EDGE_ENDPOINT_TYPES.get(edge_type)
        if endpoint_types is None:
            raise RuntimeError("invalid prompt feature edge slot")
        src_node_type, dst_node_type = endpoint_types
        result.append(
            FeatureEdgeSlot(
                edge_type=edge_type,
                src_node_type=src_node_type,
                dst_node_type=dst_node_type,
            )
        )
    return tuple(result)


_PROMPT_FEATURE_EDGE_SLOTS = {
    spec.feature_id: _edge_slots_for_spec(spec) for spec in PROMPT_FEATURE_CATALOG
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

    clause_owner_by_digest: dict[str, str] = {}
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
            item.intervention_clauses,
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
        owns_confirmation_clause = (
            item.intervenable and item.feature_id != "safety.generic_security_reminder"
        )
        if bool(item.intervention_clauses) is not owns_confirmation_clause:
            raise RuntimeError("invalid prompt feature intervention clause ownership")
        if item.intervention_clauses and (
            (
                item.feature_family is FeatureFamily.TASK_FUNCTION
                and (not item.applicable_cwes or not item.applicable_task_families)
            )
            or (item.feature_family is FeatureFamily.SAFETY_CONTROL and not item.applicable_cwes)
            or (
                item.feature_family is FeatureFamily.PRESENTATION_CONTROL
                and (item.applicable_cwes or item.applicable_task_families)
            )
        ):
            raise RuntimeError("invalid prompt feature intervention clause scope")
        if len(item.intervention_clauses) != len(set(item.intervention_clauses)):
            raise RuntimeError("duplicate prompt feature intervention clause")
        for clause in item.intervention_clauses:
            try:
                encoded_clause = clause.encode("utf-8")
            except (AttributeError, UnicodeEncodeError):
                raise RuntimeError("invalid prompt feature intervention clause") from None
            if (
                type(clause) is not str
                or len(encoded_clause) > _MAX_TEXT_BYTES
                or not clause.startswith(" ")
                or clause.startswith("  ")
                or clause != clause.rstrip()
                or not clause[1:]
                or clause[1:] != clause[1:].strip()
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in clause)
            ):
                raise RuntimeError("invalid prompt feature intervention clause")
            digest = hashlib.sha256(encoded_clause).hexdigest()
            if digest in clause_owner_by_digest:
                raise RuntimeError("ambiguous prompt feature intervention clause")
            clause_owner_by_digest[digest] = item.feature_id
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
        edge_slots = _PROMPT_FEATURE_EDGE_SLOTS[item.feature_id]
        node_types = {slot.node_type for slot in slots}
        if (
            len({slot.edge_type for slot in edge_slots}) != len(edge_slots)
            or tuple(slot.edge_type for slot in edge_slots) != item.structural_edge_types
            or any(
                type(slot) is not FeatureEdgeSlot
                or type(slot.edge_type) is not EdgeType
                or type(slot.src_node_type) is not NodeType
                or type(slot.dst_node_type) is not NodeType
                or slot.src_node_type not in node_types
                or slot.dst_node_type not in node_types
                for slot in edge_slots
            )
        ):
            raise RuntimeError("invalid prompt feature edge slots")

    by_id = {item.feature_id: item for item in catalog}
    matched_controls = {
        item.feature_id: item.matched_control_feature_id
        for item in catalog
        if item.matched_control_feature_id is not None
    }
    if matched_controls != _EXPECTED_MATCHED_CONTROLS:
        raise RuntimeError("invalid prompt feature matched-control mapping")
    for source_id, target_id in matched_controls.items():
        source = by_id[source_id]
        target = by_id.get(target_id)
        if (
            source.feature_family is not FeatureFamily.PRESENTATION_CONTROL
            or not source.intervenable
            or target is None
            or target.feature_family is not FeatureFamily.PRESENTATION_CONTROL
            or not target.intervenable
            or source_id == target_id
        ):
            raise RuntimeError("invalid prompt feature matched-control reference")

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


def prompt_feature_edge_slots(feature_id: str) -> tuple[FeatureEdgeSlot, ...]:
    """Return the exact finite direct-graph edge slots for one catalog feature."""
    prompt_feature_spec(feature_id)
    return _PROMPT_FEATURE_EDGE_SLOTS[feature_id]


def prompt_feature_edge_slot(feature_id: str, edge_type: EdgeType) -> FeatureEdgeSlot:
    """Return one exact feature/edge slot; unknown combinations fail closed."""
    if type(edge_type) is not EdgeType:
        raise KeyError("unknown prompt feature edge slot")
    for slot in prompt_feature_edge_slots(feature_id):
        if slot.edge_type is edge_type:
            return slot
    raise KeyError("unknown prompt feature edge slot")


__all__ = [
    "FEATURE_CATALOG_VERSION",
    "FeatureEdgeSlot",
    "FeatureNodeSlot",
    "FeatureSpec",
    "PROMPT_FEATURE_CATALOG",
    "PROMPT_FEATURE_CATALOG_SHA256",
    "prompt_feature_edge_slot",
    "prompt_feature_edge_slots",
    "prompt_feature_node_slot",
    "prompt_feature_node_slots",
    "prompt_feature_spec",
]

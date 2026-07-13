"""Extract reviewed prompt evidence into authoritative graph facts."""

from __future__ import annotations

from enum import Enum
import hashlib
import re
from typing import cast

import networkx as nx
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import model_shape_is_intact
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import (
    MAX_TSG_EVIDENCE_OFFSET,
    MAX_TSG_STRING_BYTES,
    EdgeType,
    NodeType,
    PromptTSGRecord,
)
from secaware.tsg.catalog import ONTOLOGY_VERSION, PROMPT_TSG_CATALOG, PromptOntologyEntry
from secaware.tsg.evidence import first_reviewed_term_match
from secaware.tsg.graph import multidigraph_to_record


_SUPPORTED_LANGUAGE_ALIASES = frozenset({"py", "python", "python3"})
_VALID_CWE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
_LEGACY_POLICY_SHA256 = hashlib.sha256(b"deterministic_catalog_v1").hexdigest()


class _InvalidInput(Exception):
    pass


class _FailureKind(Enum):
    INVALID_INPUT = "invalid_input"
    INTERNAL = "internal"


def _invalid_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.extract_prompt",
        "prompt TSG extraction validation failed",
    )


def _internal_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "tsg.extract_prompt",
        "internal prompt TSG extraction failure",
    )


def _snapshot_prompt(value: object) -> PromptRecord:
    if type(value) is not PromptRecord or not model_shape_is_intact(value):
        raise _InvalidInput from None
    runtime_fields = (
        value.prompt_id,
        value.task_id,
        value.split,
        value.language,
        value.task_family,
        value.cwe,
        value.prompt,
    )
    if any(type(item) is not str for item in runtime_fields):
        raise _InvalidInput from None
    payload = value.model_dump(mode="python", round_trip=True, warnings=False)
    try:
        snapshot = PromptRecord.model_validate(payload, strict=True)
    except ValidationError:
        raise _InvalidInput from None
    string_fields = (
        snapshot.prompt_id,
        snapshot.task_id,
        snapshot.split,
        snapshot.language,
        snapshot.task_family,
        snapshot.cwe,
        snapshot.prompt,
    )
    if any(type(item) is not str for item in string_fields):
        raise _InvalidInput from None
    try:
        encoded_fields = tuple(item.encode("utf-8") for item in string_fields)
    except UnicodeError:
        raise _InvalidInput from None
    if (
        not snapshot.prompt_id
        or not snapshot.task_id
        or snapshot.prompt_id != snapshot.prompt_id.strip()
        or len(encoded_fields[0]) > MAX_TSG_STRING_BYTES
        or len(snapshot.prompt) > MAX_TSG_EVIDENCE_OFFSET
    ):
        raise _InvalidInput from None
    return snapshot


def _evidence(text: str, match: tuple[int, int]) -> dict[str, str | int]:
    start, end = match
    span = text[start:end]
    return {
        "evidence_start": start,
        "evidence_end": end,
        "evidence_sha256": hashlib.sha256(span.encode("utf-8")).hexdigest(),
    }


def _semantic_key(entry: PromptOntologyEntry, role: str) -> str:
    return f"prompt-catalog:{ONTOLOGY_VERSION}:{entry.factor_type.value}:{role}"


def _add_node(
    graph: nx.MultiDiGraph,
    entry: PromptOntologyEntry,
    role: str,
    node_type: NodeType,
    label: str,
    attributes: dict[str, str | int],
) -> str:
    key = _semantic_key(entry, role)
    graph.add_node(
        key,
        node_type=node_type,
        label=label,
        attributes=dict(attributes),
    )
    return key


def _add_edge(
    graph: nx.MultiDiGraph,
    src: str,
    dst: str,
    edge_type: EdgeType,
    attributes: dict[str, str | int],
) -> None:
    graph.add_edge(src, dst, edge_type=edge_type, attributes=dict(attributes))


def _add_domain_flow(
    graph: nx.MultiDiGraph,
    entry: PromptOntologyEntry,
    evidence: dict[str, str | int],
) -> tuple[str, str]:
    operation = _add_node(
        graph,
        entry,
        "operation",
        NodeType.TASK_OPERATION,
        entry.operation_label,
        evidence,
    )
    source = _add_node(
        graph,
        entry,
        "source",
        NodeType.SOURCE,
        f"{entry.factor_type.value}_source",
        evidence,
    )
    data = _add_node(
        graph,
        entry,
        "data",
        NodeType.DATA_OBJECT,
        entry.data_label,
        evidence,
    )
    sink = _add_node(
        graph,
        entry,
        "sink",
        NodeType.SINK,
        entry.sink_label,
        evidence,
    )
    boundary = _add_node(
        graph,
        entry,
        "boundary",
        NodeType.TRUST_BOUNDARY,
        f"{entry.factor_type.value}_trust_boundary",
        evidence,
    )
    cwe_attributes = dict(evidence)
    if _VALID_CWE.fullmatch(entry.cwe) is not None:
        cwe_attributes["cwe_id"] = entry.cwe
    cwe = _add_node(graph, entry, "cwe", NodeType.CWE, entry.cwe, cwe_attributes)

    _add_edge(graph, operation, data, EdgeType.OPERATES_ON, evidence)
    _add_edge(graph, source, data, EdgeType.SOURCE_OF, evidence)
    _add_edge(graph, data, sink, EdgeType.FLOWS_TO, evidence)
    _add_edge(
        graph,
        boundary,
        source,
        EdgeType.RELATED_TO,
        {**evidence, "relation_kind": "crosses_trust_boundary"},
    )
    _add_edge(
        graph,
        sink,
        cwe,
        EdgeType.MAPS_TO,
        {**evidence, "mapping_kind": "reviewed_catalog_cwe"},
    )
    return data, sink


def _add_guard_requirement(
    graph: nx.MultiDiGraph,
    entry: PromptOntologyEntry,
    data: str,
    sink: str,
    evidence: dict[str, str | int],
) -> None:
    requirement = _add_node(
        graph,
        entry,
        "requirement",
        NodeType.PROMPT_REQUIREMENT,
        entry.requirement_label,
        evidence,
    )
    guard = _add_node(
        graph,
        entry,
        "guard",
        NodeType.GUARD,
        entry.guard_label,
        evidence,
    )
    _add_edge(graph, requirement, guard, EdgeType.REQUIRES, evidence)
    _add_edge(graph, data, guard, EdgeType.GUARDED_BY, evidence)
    _add_edge(graph, sink, guard, EdgeType.GUARDED_BY, evidence)


def _extract(snapshot: PromptRecord) -> PromptTSGRecord:
    graph = nx.MultiDiGraph()
    metadata = {
        "prompt_id": snapshot.prompt_id,
        "task_id": snapshot.task_id,
        "task_family": snapshot.task_family,
        "cwe": snapshot.cwe,
        "extractor_backend": PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        "extractor_policy_sha256": _LEGACY_POLICY_SHA256,
        "proposal_id": "proposal_"
        + hashlib.sha256(
            f"{snapshot.prompt_id}\0{snapshot.task_id}\0{_LEGACY_POLICY_SHA256}".encode("utf-8")
        ).hexdigest(),
    }
    if snapshot.language.casefold() not in _SUPPORTED_LANGUAGE_ALIASES:
        return multidigraph_to_record(graph, **metadata)

    for entry in PROMPT_TSG_CATALOG:
        domain_match = first_reviewed_term_match(snapshot.prompt, entry.domain_terms)
        if domain_match is None:
            continue
        data, sink = _add_domain_flow(graph, entry, _evidence(snapshot.prompt, domain_match))
        guard_match = first_reviewed_term_match(snapshot.prompt, entry.guard_terms)
        if guard_match is not None:
            _add_guard_requirement(
                graph,
                entry,
                data,
                sink,
                _evidence(snapshot.prompt, guard_match),
            )
    return multidigraph_to_record(graph, **metadata)


def _try_snapshot_prompt(value: object) -> PromptRecord | _FailureKind:
    try:
        return _snapshot_prompt(value)
    except _InvalidInput:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def _try_extract(snapshot: PromptRecord) -> PromptTSGRecord | _FailureKind:
    try:
        return _extract(snapshot)
    except Exception:
        return _FailureKind.INTERNAL


def extract_prompt_tsg(prompt: PromptRecord) -> PromptTSGRecord:
    """Snapshot one prompt and emit only finite reviewed graph evidence."""
    snapshot_result = _try_snapshot_prompt(prompt)
    prompt = cast(PromptRecord, None)
    if isinstance(snapshot_result, _FailureKind):
        failure = snapshot_result
        snapshot_result = cast(PromptRecord, None)
        if failure is _FailureKind.INVALID_INPUT:
            raise _invalid_error()
        raise _internal_error()

    result = _try_extract(snapshot_result)
    snapshot_result = cast(PromptRecord, None)
    if isinstance(result, _FailureKind):
        prompt = cast(PromptRecord, None)
        raise _internal_error()
    return result


__all__ = ["extract_prompt_tsg"]

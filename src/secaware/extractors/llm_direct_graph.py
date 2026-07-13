"""Blind typed-graph extraction through the shared proposal boundary."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from importlib import resources
import json
import re

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.llm.structured_transport import (
    StructuredJSONTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import (
    MAX_RAW_RESPONSE_CHARS,
    PromptExtractionProposalRecord,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_node_slots,
)
from secaware.tsg.proposal_validator import (
    _snapshot_prompt,
    feature_is_applicable,
    validate_proposal,
)


_STAGE = "tsg.extract_prompt.llm_direct_graph"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIRECT_RESPONSE_KEYS = frozenset({"nodes", "edges"})
_EDGE_ENDPOINT_TYPES = {
    EdgeType.OPERATES_ON: (NodeType.TASK_OPERATION, NodeType.DATA_OBJECT),
    EdgeType.SOURCE_OF: (NodeType.SOURCE, NodeType.DATA_OBJECT),
    EdgeType.FLOWS_TO: (NodeType.DATA_OBJECT, NodeType.SINK),
    EdgeType.GUARDED_BY: (NodeType.DATA_OBJECT, NodeType.GUARD),
    EdgeType.REQUIRES: (NodeType.PROMPT_REQUIREMENT, NodeType.GUARD),
}
_OUTPUT_SCHEMA = {
    "schema_version": "1.0",
    "top_level_keys": ["edges", "nodes"],
    "node_keys": ["evidence", "feature_id", "label", "local_id", "node_type"],
    "edge_keys": ["dst_local_id", "edge_type", "evidence", "src_local_id"],
    "evidence_keys": ["end", "start", "text", "text_sha256"],
    "local_id_pattern": "^v[0-9]{1,4}$",
    "output_kind": "typed_graph",
    "semantic_slot_contract": "catalog_feature_node_slots_v1",
}


def _template_text() -> str:
    return (
        resources.files("secaware.extractors")
        .joinpath("prompts/llm_direct_graph_v1.txt")
        .read_text(encoding="utf-8")
    )


LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE = _template_text()
LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()
LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256 = hashlib.sha256(
    canonical_request_bytes(_OUTPUT_SCHEMA)
).hexdigest()


def _error(code: ErrorCode = ErrorCode.TSG_INVALID) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message="LLM direct graph extraction validation failed",
    )


def _catalog_node_template_view(source: PromptRecord) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "feature_id": spec.feature_id,
                "feature_family": spec.feature_family.value,
                "node_type": slot.node_type.value,
                "canonical_label": slot.canonical_label,
                "slot_kind": ("presence_marker" if slot.is_presence_marker else "structural"),
            }
            for spec in PROMPT_FEATURE_CATALOG
            if feature_is_applicable(spec, source)
            for slot in prompt_feature_node_slots(spec.feature_id)
        ),
        key=lambda item: (item["feature_id"], item["node_type"]),
    )


def catalog_node_template_view(prompt: PromptRecord) -> list[dict[str, str]]:
    """Return prompt-applicable finite node slots accepted by the shared validator."""
    return _catalog_node_template_view(_snapshot_prompt(prompt))


def _catalog_edge_template_view(
    source: PromptRecord,
    node_templates: list[dict[str, str]],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    advertised_slots = {(item["feature_id"], item["node_type"]) for item in node_templates}
    for spec in PROMPT_FEATURE_CATALOG:
        if not feature_is_applicable(spec, source):
            continue
        for edge_type in spec.structural_edge_types:
            endpoint_types = _EDGE_ENDPOINT_TYPES.get(edge_type)
            if endpoint_types is None:
                raise RuntimeError("invalid prompt feature edge template")
            src_type, dst_type = endpoint_types
            if (spec.feature_id, src_type.value) not in advertised_slots or (
                spec.feature_id,
                dst_type.value,
            ) not in advertised_slots:
                raise RuntimeError("invalid prompt feature edge template")
            result.append(
                {
                    "feature_id": spec.feature_id,
                    "feature_family": spec.feature_family.value,
                    "edge_type": edge_type.value,
                    "src_node_type": src_type.value,
                    "dst_node_type": dst_type.value,
                }
            )
    return sorted(result, key=lambda item: (item["feature_id"], item["edge_type"]))


def catalog_edge_template_view(prompt: PromptRecord) -> list[dict[str, str]]:
    """Return prompt-applicable edges whose endpoint slots are advertised."""
    source = _snapshot_prompt(prompt)
    return _catalog_edge_template_view(source, _catalog_node_template_view(source))


def _structured_policy_payload(policy: StructuredLLMPolicy) -> dict[str, object]:
    return {field: getattr(policy, field) for field in StructuredLLMPolicy.__dataclass_fields__}


def llm_direct_graph_policy_sha256(
    policy: StructuredLLMPolicy,
    catalog_sha256: str,
    max_response_chars: int,
) -> str:
    """Bind all direct-graph provider, decoding, schema, and catalog coordinates."""
    if type(policy) is not StructuredLLMPolicy:
        raise ValueError("LLM direct graph policy validation failed")
    if type(catalog_sha256) is not str or _SHA256.fullmatch(catalog_sha256) is None:
        raise ValueError("LLM direct graph policy validation failed")
    if type(max_response_chars) is not int or not 1 <= max_response_chars <= MAX_RAW_RESPONSE_CHARS:
        raise ValueError("LLM direct graph policy validation failed")
    payload = {
        "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1.value,
        "catalog_sha256": catalog_sha256,
        "max_response_chars": max_response_chars,
        "structured_llm_policy": _structured_policy_payload(policy),
    }
    return hashlib.sha256(canonical_request_bytes(payload)).hexdigest()


def _trusted_policy(policy: object) -> ExtractionPolicy:
    if type(policy) is not ExtractionPolicy:
        raise _error(ErrorCode.POLICY_MISMATCH) from None
    invalid = False
    try:
        if (
            policy.backend is not PromptExtractorBackend.LLM_DIRECT_GRAPH_V1
            or policy.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or type(policy.policy_sha256) is not str
            or _SHA256.fullmatch(policy.policy_sha256) is None
            or type(policy.max_response_chars) is not int
            or not 1 <= policy.max_response_chars <= MAX_RAW_RESPONSE_CHARS
        ):
            raise ValueError
    except Exception:
        invalid = True
    if invalid:
        raise _error(ErrorCode.POLICY_MISMATCH) from None
    return policy


def _validate_policy_binding(
    policy: ExtractionPolicy,
    structured: StructuredLLMPolicy,
) -> None:
    if (
        structured.system_template_sha256 != LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256
        or structured.output_schema_sha256 != LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256
        or policy.policy_sha256
        != llm_direct_graph_policy_sha256(
            structured,
            policy.catalog_sha256,
            policy.max_response_chars,
        )
    ):
        raise _error(ErrorCode.POLICY_MISMATCH) from None


def direct_graph_request_payload(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> dict[str, object]:
    """Build the exact blind request envelope for one source prompt."""
    source = _snapshot_prompt(prompt)
    trusted = _trusted_policy(policy)
    node_templates = _catalog_node_template_view(source)
    edge_templates = _catalog_edge_template_view(source, node_templates)
    return {
        "schema_version": "1.0",
        "prompt_id": source.prompt_id,
        "task_id": source.task_id,
        "prompt_sha256": hashlib.sha256(source.prompt.encode("utf-8")).hexdigest(),
        "prompt_text": source.prompt,
        "catalog_sha256": trusted.catalog_sha256,
        "allowed_node_templates": node_templates,
        "allowed_edge_templates": edge_templates,
        "output_kind": "typed_graph",
    }


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_payload(raw_text: str) -> Mapping[str, object]:
    payload = json.loads(
        raw_text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON")),
    )
    if not isinstance(payload, Mapping) or frozenset(payload) != _DIRECT_RESPONSE_KEYS:
        raise ValueError("invalid direct graph response envelope")
    if type(payload["nodes"]) is not list or type(payload["edges"]) is not list:
        raise ValueError("invalid direct graph response collections")
    return payload


def parse_direct_graph_response(
    raw: bytes,
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> PromptExtractionProposalRecord:
    """Parse one direct response once and validate it through the shared boundary."""
    source: PromptRecord | None = None
    raw_text = ""
    proposal: PromptExtractionProposalRecord | None = None
    failure: SecAwareError | None = None
    response: Mapping[str, object] | None = None
    payload: dict[str, object] = {}
    candidate: PromptExtractionProposalRecord | None = None
    try:
        trusted = _trusted_policy(policy)
        source = _snapshot_prompt(prompt)
        if type(raw) is not bytes or not raw:
            raise ValueError
        raw_text = raw.decode("utf-8")
        if len(raw_text) > trusted.max_response_chars:
            raise ValueError
        response = _json_payload(raw_text)
        if not response["nodes"]:
            raise ValueError
        payload = {
            "schema_version": "1.0",
            "prompt_id": source.prompt_id,
            "task_id": source.task_id,
            "prompt_sha256": hashlib.sha256(source.prompt.encode("utf-8")).hexdigest(),
            "backend": PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
            "catalog_sha256": trusted.catalog_sha256,
            "policy_sha256": trusted.policy_sha256,
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_response": raw_text,
            "facts": [],
            "direct_nodes": response["nodes"],
            "direct_edges": response["edges"],
        }
        payload["proposal_id"] = proposal_id_for_payload(payload)
        candidate = PromptExtractionProposalRecord.model_validate(payload)
        proposal = validate_proposal(candidate, source)
    except Exception:
        failure = _error()
    finally:
        raw = b""
        raw_text = ""
        source = None
        response = None
        payload = {}
        candidate = None
        prompt = None  # type: ignore[assignment]
        policy = None  # type: ignore[assignment]
    if failure is not None:
        failure.__cause__ = None
        failure.__context__ = None
        raise failure from None
    if proposal is None:
        raise _error() from None
    return proposal


class LLMDirectGraphExtractor:
    """Emit one graph-only proposal from one blind structured LLM response."""

    __slots__ = ("_structured_policy", "_transport")

    def __init__(
        self,
        transport: StructuredJSONTransport,
        structured_policy: StructuredLLMPolicy,
    ) -> None:
        failure: SecAwareError | None = None
        trusted_structured: StructuredLLMPolicy | None = None
        try:
            if not callable(getattr(transport, "complete", None)):
                raise TypeError
            if type(structured_policy) is not StructuredLLMPolicy:
                raise TypeError
            trusted_structured = StructuredLLMPolicy(
                **_structured_policy_payload(structured_policy)
            )
        except Exception:
            failure = _error(ErrorCode.CONFIG)
        if failure is not None or trusted_structured is None:
            if failure is None:
                failure = _error(ErrorCode.CONFIG)
            failure.__cause__ = None
            failure.__context__ = None
            raise failure from None
        self._transport = transport
        self._structured_policy = trusted_structured

    def __repr__(self) -> str:
        return "LLMDirectGraphExtractor()"

    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        request_bytes = b""
        raw = b""
        result: PromptExtractionProposalRecord | None = None
        failure: SecAwareError | None = None
        source: PromptRecord | None = None
        trusted: ExtractionPolicy | None = None
        try:
            trusted = _trusted_policy(policy)
            _validate_policy_binding(trusted, self._structured_policy)
            source = _snapshot_prompt(prompt)
            request_bytes = canonical_request_bytes(direct_graph_request_payload(source, trusted))
            raw = self._transport.complete(request_bytes, self._structured_policy)
            if type(raw) is not bytes or len(raw) > self._structured_policy.max_response_bytes:
                raise _error()
            result = parse_direct_graph_response(raw, source, trusted)
        except SecAwareError as error:
            failure = error
        except Exception:
            failure = _error()
        finally:
            request_bytes = b""
            raw = b""
            source = None
            trusted = None
            prompt = None  # type: ignore[assignment]
            policy = None  # type: ignore[assignment]
        if failure is not None:
            failure.__cause__ = None
            failure.__context__ = None
            raise failure from None
        if result is None:
            raise _error() from None
        return result


__all__ = [
    "LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256",
    "LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE",
    "LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256",
    "LLMDirectGraphExtractor",
    "catalog_edge_template_view",
    "catalog_node_template_view",
    "direct_graph_request_payload",
    "llm_direct_graph_policy_sha256",
    "parse_direct_graph_response",
]

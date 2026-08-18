"""Blind structured-facts extraction through the shared proposal boundary."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from importlib import resources

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.llm.structured_transport import (
    StructuredJSONTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import (
    MAX_RAW_RESPONSE_CHARS,
    PromptExtractionProposalRecord,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    FeatureSpec,
)
from secaware.tsg.proposal_validator import (
    _snapshot_prompt,
    feature_is_applicable,
    validate_proposal,
)

_STAGE = "tsg.extract_prompt.llm_facts"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FACT_RESPONSE_KEYS = frozenset({"facts"})
_FACT_KEYS = frozenset({"evidence", "feature_id", "relation_feature_ids", "semantic_role", "state"})
_MODEL_EVIDENCE_KEYS = frozenset({"text"})
LLM_FACTS_CRITERIA_PROJECTION_VERSION = "feature-spec-criteria-v1"
LLM_FACTS_RESPONSE_NORMALIZATION_VERSION = "absent-empty-relations-default-v1"
_OUTPUT_SCHEMA = {
    "schema_version": "1.0",
    "top_level_keys": ["facts"],
    "fact_keys": [
        "evidence",
        "feature_id",
        "relation_feature_ids",
        "semantic_role",
        "state",
    ],
    "evidence_keys": ["text"],
    "semantic_role": "feature_state",
    "states": [FeatureState.ABSENT.value, FeatureState.PRESENT.value],
}


def _template_text() -> str:
    return (
        resources.files("secaware.extractors")
        .joinpath("prompts/llm_facts_v1.txt")
        .read_text(encoding="utf-8")
    )


LLM_FACTS_SYSTEM_TEMPLATE = _template_text()
LLM_FACTS_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    LLM_FACTS_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()
LLM_FACTS_OUTPUT_SCHEMA_SHA256 = hashlib.sha256(canonical_request_bytes(_OUTPUT_SCHEMA)).hexdigest()


def _error(code: ErrorCode = ErrorCode.TSG_INVALID) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message="LLM facts extraction validation failed",
    )


def _semantic_criteria(spec: FeatureSpec) -> dict[str, object]:
    return {
        "positive_indicators": list(spec.deterministic_terms),
        "reviewed_requirement_clauses": [item.strip() for item in spec.intervention_clauses],
        "state_rule": (
            "present only when prompt_text explicitly requests this feature or a "
            "semantically equivalent requirement"
        ),
    }


def catalog_prompt_view() -> list[dict[str, object]]:
    """Return the finite, outcome-blind catalog projection supplied to the model."""
    by_family = {
        spec.feature_family: tuple(
            candidate.feature_id
            for candidate in PROMPT_FEATURE_CATALOG
            if candidate.feature_family is spec.feature_family
        )
        for spec in PROMPT_FEATURE_CATALOG
    }
    return [
        {
            "feature_id": spec.feature_id,
            "feature_family": spec.feature_family.value,
            "applicable_cwes": list(spec.applicable_cwes),
            "applicable_task_families": list(spec.applicable_task_families),
            "allowed_states": [state.value for state in FeatureState],
            "allowed_relation_feature_ids": list(by_family[spec.feature_family]),
            "semantic_criteria": _semantic_criteria(spec),
        }
        for spec in PROMPT_FEATURE_CATALOG
    ]


def _applicable_catalog_prompt_view(prompt: PromptRecord) -> list[dict[str, object]]:
    applicable = {
        spec.feature_id for spec in PROMPT_FEATURE_CATALOG if feature_is_applicable(spec, prompt)
    }
    result: list[dict[str, object]] = []
    for item in catalog_prompt_view():
        if item["feature_id"] not in applicable:
            continue
        projected = dict(item)
        projected["allowed_states"] = [
            FeatureState.ABSENT.value,
            FeatureState.PRESENT.value,
        ]
        projected["allowed_relation_feature_ids"] = [
            feature_id
            for feature_id in item["allowed_relation_feature_ids"]
            if feature_id in applicable
        ]
        result.append(projected)
    return result


def _structured_policy_payload(policy: StructuredLLMPolicy) -> dict[str, object]:
    return {field: getattr(policy, field) for field in StructuredLLMPolicy.__dataclass_fields__}


def llm_facts_policy_sha256(
    policy: StructuredLLMPolicy,
    catalog_sha256: str,
    max_response_chars: int,
) -> str:
    """Bind every provider and decoding coordinate to one extractor policy digest."""
    if type(policy) is not StructuredLLMPolicy:
        raise ValueError("LLM facts policy validation failed")
    if type(catalog_sha256) is not str or _SHA256.fullmatch(catalog_sha256) is None:
        raise ValueError("LLM facts policy validation failed")
    if type(max_response_chars) is not int or not 1 <= max_response_chars <= MAX_RAW_RESPONSE_CHARS:
        raise ValueError("LLM facts policy validation failed")
    payload = {
        "backend": PromptExtractorBackend.LLM_FACTS_V1.value,
        "catalog_sha256": catalog_sha256,
        "criteria_projection_version": LLM_FACTS_CRITERIA_PROJECTION_VERSION,
        "max_response_chars": max_response_chars,
        "structured_llm_policy": _structured_policy_payload(policy),
    }
    return hashlib.sha256(canonical_request_bytes(payload)).hexdigest()


def llm_facts_response_normalization_sha256() -> str:
    """Identify the bounded local response default separately from request identity."""

    payload = {
        "policy_version": LLM_FACTS_RESPONSE_NORMALIZATION_VERSION,
        "defaulted_field": "relation_feature_ids",
        "eligible_state": FeatureState.ABSENT.value,
        "required_evidence": [],
        "default_value": [],
    }
    return hashlib.sha256(canonical_request_bytes(payload)).hexdigest()


def _trusted_policy(policy: object) -> ExtractionPolicy:
    if type(policy) is not ExtractionPolicy:
        raise _error(ErrorCode.POLICY_MISMATCH) from None
    invalid = False
    try:
        if (
            policy.backend is not PromptExtractorBackend.LLM_FACTS_V1
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
        structured.system_template_sha256 != LLM_FACTS_SYSTEM_TEMPLATE_SHA256
        or structured.output_schema_sha256 != LLM_FACTS_OUTPUT_SCHEMA_SHA256
        or policy.policy_sha256
        != llm_facts_policy_sha256(
            structured,
            policy.catalog_sha256,
            policy.max_response_chars,
        )
    ):
        raise _error(ErrorCode.POLICY_MISMATCH) from None


def facts_request_payload(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> dict[str, object]:
    source = _snapshot_prompt(prompt)
    trusted = _trusted_policy(policy)
    return {
        "schema_version": "1.0",
        "prompt_id": source.prompt_id,
        "task_id": source.task_id,
        "prompt_sha256": hashlib.sha256(source.prompt.encode("utf-8")).hexdigest(),
        "prompt_text": source.prompt,
        "prompt_context": {
            "language": source.language,
            "cwe": source.cwe,
            "task_family": source.task_family,
        },
        "catalog_sha256": trusted.catalog_sha256,
        "criteria_projection_version": LLM_FACTS_CRITERIA_PROJECTION_VERSION,
        "allowed_features": _applicable_catalog_prompt_view(source),
        "output_kind": "semantic_facts",
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
    if not isinstance(payload, Mapping) or frozenset(payload) != _FACT_RESPONSE_KEYS:
        raise ValueError("invalid facts response envelope")
    if type(payload["facts"]) is not list:
        raise ValueError("invalid facts response collection")
    return payload


def _normalized_facts(
    value: object,
    prompt: PromptRecord,
) -> list[dict[str, object]]:
    """Validate model-authored spans, then derive cryptographic digests locally."""
    if type(value) is not list:
        raise ValueError("invalid facts response collection")
    prompt_text = prompt.prompt
    applicable_ids = {
        spec.feature_id for spec in PROMPT_FEATURE_CATALOG if feature_is_applicable(spec, prompt)
    }
    result: list[dict[str, object]] = []
    returned_ids: list[object] = []
    for fact in value:
        if type(fact) is not dict:
            raise ValueError("invalid fact response")
        fact_keys = frozenset(fact)
        if (
            fact_keys == _FACT_KEYS - {"relation_feature_ids"}
            and fact.get("state") == FeatureState.ABSENT.value
            and fact.get("evidence") == []
        ):
            fact = {**fact, "relation_feature_ids": []}
            fact_keys = frozenset(fact)
        if fact_keys != _FACT_KEYS:
            raise ValueError("invalid fact response")
        feature_id = fact["feature_id"]
        returned_ids.append(feature_id)
        if feature_id not in applicable_ids or fact["state"] not in {
            FeatureState.ABSENT.value,
            FeatureState.PRESENT.value,
        }:
            raise ValueError("invalid applicable fact response")
        evidence = fact["evidence"]
        if type(evidence) is not list:
            raise ValueError("invalid fact evidence collection")
        normalized_evidence: list[dict[str, object]] = []
        for span in evidence:
            if type(span) is not dict or frozenset(span) != _MODEL_EVIDENCE_KEYS:
                raise ValueError("invalid fact evidence")
            text = span["text"]
            if (
                type(text) is not str
                or not text
                or len(text) > 4096
                or prompt_text.count(text) != 1
            ):
                raise ValueError("invalid fact evidence")
            start = prompt_text.index(text)
            end = start + len(text)
            normalized_evidence.append(
                {
                    "start": start,
                    "end": end,
                    "text": text,
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                }
            )
        normalized = dict(fact)
        normalized["evidence"] = normalized_evidence
        result.append(normalized)
    if len(returned_ids) != len(set(returned_ids)) or set(returned_ids) != applicable_ids:
        raise ValueError("incomplete applicable fact response")
    for spec in PROMPT_FEATURE_CATALOG:
        if spec.feature_id not in applicable_ids:
            result.append(
                {
                    "feature_id": spec.feature_id,
                    "state": FeatureState.NOT_APPLICABLE.value,
                    "semantic_role": "feature_state",
                    "evidence": [],
                    "relation_feature_ids": [],
                }
            )
    return result


def parse_facts_response(
    raw: bytes,
    prompt: PromptRecord,
    policy: ExtractionPolicy,
) -> PromptExtractionProposalRecord:
    """Parse and bind one response exactly once; no repair interaction is performed."""
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
        payload = {
            "schema_version": "1.0",
            "prompt_id": source.prompt_id,
            "task_id": source.task_id,
            "prompt_sha256": hashlib.sha256(source.prompt.encode("utf-8")).hexdigest(),
            "backend": PromptExtractorBackend.LLM_FACTS_V1,
            "catalog_sha256": trusted.catalog_sha256,
            "policy_sha256": trusted.policy_sha256,
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_response": raw_text,
            "facts": _normalized_facts(response["facts"], source),
            "direct_nodes": [],
            "direct_edges": [],
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


class LLMFactsExtractor:
    """Emit a complete facts-only proposal from one blind structured LLM response."""

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
        return "LLMFactsExtractor()"

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
            request_bytes = canonical_request_bytes(facts_request_payload(source, trusted))
            raw = self._transport.complete(request_bytes, self._structured_policy)
            if type(raw) is not bytes or len(raw) > self._structured_policy.max_response_bytes:
                raise _error()
            result = parse_facts_response(raw, source, trusted)
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
    "LLM_FACTS_CRITERIA_PROJECTION_VERSION",
    "LLM_FACTS_OUTPUT_SCHEMA_SHA256",
    "LLM_FACTS_RESPONSE_NORMALIZATION_VERSION",
    "LLM_FACTS_SYSTEM_TEMPLATE",
    "LLM_FACTS_SYSTEM_TEMPLATE_SHA256",
    "LLMFactsExtractor",
    "catalog_prompt_view",
    "facts_request_payload",
    "llm_facts_policy_sha256",
    "llm_facts_response_normalization_sha256",
    "parse_facts_response",
]

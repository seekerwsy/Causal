"""Finite reviewed catalog matcher exposed as an explicit extraction backend."""

from __future__ import annotations

import hashlib
import json
import re

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.prompt_extraction import (
    MAX_RAW_RESPONSE_CHARS,
    PromptExtractionProposalRecord,
    proposal_id_for_payload,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.evidence import first_reviewed_term_match
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    FeatureSpec,
)
from secaware.tsg.proposal_validator import _snapshot_prompt, feature_is_applicable

_V1_SUPPORTED_LANGUAGE_ALIASES = frozenset({"py", "python", "python3"})
_V2_SUPPORTED_LANGUAGE_ALIASES = frozenset(
    {"c", "c++", "cpp", "go", "java", "py", "python", "python3"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFETY_TASK_PREREQUISITE = {
    "safety.input_validation": "task.input_consumption",
    "safety.path_normalization": "task.file_read",
    "safety.sql_parameterization": "task.database_query",
    "safety.safe_subprocess": "task.process_launch",
    "safety.authorization_check": "task.privileged_action",
    "safety.safe_deserialization": "task.object_deserialization",
    "safety.collision_resistant_hash": "task.message_hashing",
    "safety.cryptographic_randomness": "task.security_random_generation",
}


class _InvalidInput(Exception):
    pass


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


def _validate_policy(
    policy: object,
    expected_backend: PromptExtractorBackend,
) -> ExtractionPolicy:
    if type(policy) is not ExtractionPolicy:
        raise _InvalidInput from None
    values = (
        policy.backend,
        policy.policy_sha256,
        policy.catalog_sha256,
        policy.max_response_chars,
    )
    if (
        type(values[0]) is not PromptExtractorBackend
        or values[0] is not expected_backend
        or type(values[1]) is not str
        or _SHA256.fullmatch(values[1]) is None
        or type(values[2]) is not str
        or values[2] != PROMPT_FEATURE_CATALOG_SHA256
        or type(values[3]) is not int
        or not 1 <= values[3] <= MAX_RAW_RESPONSE_CHARS
    ):
        raise _InvalidInput from None
    return policy


def _evidence(text: str, match: tuple[int, int]) -> list[dict[str, object]]:
    start, end = match
    span = text[start:end]
    return [
        {
            "start": start,
            "end": end,
            "text": span,
            "text_sha256": hashlib.sha256(span.encode("utf-8")).hexdigest(),
        }
    ]


def _match_by_feature(prompt: PromptRecord) -> dict[str, tuple[int, int] | None]:
    return {
        spec.feature_id: first_reviewed_term_match(prompt.prompt, spec.deterministic_terms)
        for spec in PROMPT_FEATURE_CATALOG
        if spec.deterministic_terms
    }


def _resolved_state(
    spec: FeatureSpec,
    prompt: PromptRecord,
    matches: dict[str, tuple[int, int] | None],
    supported_language_aliases: frozenset[str],
) -> tuple[FeatureState, tuple[int, int] | None]:
    if not feature_is_applicable(spec, prompt):
        return FeatureState.NOT_APPLICABLE, None
    if prompt.language.casefold() not in supported_language_aliases or not spec.deterministic_terms:
        return FeatureState.UNRESOLVED, None

    match = matches[spec.feature_id]
    prerequisite = _SAFETY_TASK_PREREQUISITE.get(spec.feature_id)
    if prerequisite is not None and matches.get(prerequisite) is None:
        return FeatureState.ABSENT, None
    if match is None:
        return FeatureState.ABSENT, None
    return FeatureState.PRESENT, match


def _fact_payload(
    prompt: PromptRecord,
    supported_language_aliases: frozenset[str],
) -> list[dict[str, object]]:
    matches = _match_by_feature(prompt)
    facts: list[dict[str, object]] = []
    for spec in PROMPT_FEATURE_CATALOG:
        state, match = _resolved_state(spec, prompt, matches, supported_language_aliases)
        facts.append(
            {
                "feature_id": spec.feature_id,
                "state": state.value,
                "semantic_role": "feature_state",
                "evidence": [] if match is None else _evidence(prompt.prompt, match),
                "relation_feature_ids": [],
            }
        )
    return sorted(facts, key=lambda item: str(item["feature_id"]))


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _extract(
    snapshot: PromptRecord,
    policy: ExtractionPolicy,
    supported_language_aliases: frozenset[str],
) -> PromptExtractionProposalRecord:
    facts = _fact_payload(snapshot, supported_language_aliases)
    raw_response = _canonical_json({"facts": facts})
    if len(raw_response) > policy.max_response_chars:
        raise _InvalidInput from None
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": snapshot.prompt_id,
        "task_id": snapshot.task_id,
        "prompt_sha256": hashlib.sha256(snapshot.prompt.encode("utf-8")).hexdigest(),
        "backend": policy.backend,
        "catalog_sha256": policy.catalog_sha256,
        "policy_sha256": policy.policy_sha256,
        "response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
        "raw_response": raw_response,
        "facts": facts,
        "direct_nodes": [],
        "direct_edges": [],
    }
    payload["proposal_id"] = proposal_id_for_payload(payload)
    return PromptExtractionProposalRecord.model_validate(payload)


def _extract_with_backend(
    prompt: PromptRecord,
    policy: ExtractionPolicy,
    *,
    backend: PromptExtractorBackend,
    supported_language_aliases: frozenset[str],
) -> PromptExtractionProposalRecord:
    try:
        trusted_policy = _validate_policy(policy, backend)
        snapshot = _snapshot_prompt(prompt)
    except (SecAwareError, _InvalidInput):
        prompt = None  # type: ignore[assignment]
        policy = None  # type: ignore[assignment]
        raise _invalid_error() from None
    except Exception:  # noqa: BLE001 - sanitize unexpected trust-boundary failures
        prompt = None  # type: ignore[assignment]
        policy = None  # type: ignore[assignment]
        raise _internal_error() from None

    try:
        return _extract(snapshot, trusted_policy, supported_language_aliases)
    except _InvalidInput:
        prompt = None  # type: ignore[assignment]
        snapshot = None  # type: ignore[assignment]
        policy = None  # type: ignore[assignment]
        raise _invalid_error() from None
    except Exception:  # noqa: BLE001 - sanitize unexpected trust-boundary failures
        prompt = None  # type: ignore[assignment]
        snapshot = None  # type: ignore[assignment]
        policy = None  # type: ignore[assignment]
        raise _internal_error() from None


class DeterministicCatalogExtractor:
    """Emit one complete facts proposal from the immutable finite term catalog."""

    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        return _extract_with_backend(
            prompt,
            policy,
            backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
            supported_language_aliases=_V1_SUPPORTED_LANGUAGE_ALIASES,
        )


class MultilingualDeterministicCatalogExtractor:
    """Apply the reviewed English Prompt catalog across frozen code-language scopes."""

    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        return _extract_with_backend(
            prompt,
            policy,
            backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V2,
            supported_language_aliases=_V2_SUPPORTED_LANGUAGE_ALIASES,
        )


__all__ = ["DeterministicCatalogExtractor", "MultilingualDeterministicCatalogExtractor"]

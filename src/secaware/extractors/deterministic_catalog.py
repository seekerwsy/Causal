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


_SUPPORTED_LANGUAGE_ALIASES = frozenset({"py", "python", "python3"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFETY_TASK_PREREQUISITE = {
    "safety.input_validation": "task.input_consumption",
    "safety.path_normalization": "task.file_read",
    "safety.sql_parameterization": "task.database_query",
    "safety.safe_subprocess": "task.process_launch",
    "safety.authorization_check": "task.privileged_action",
    "safety.safe_deserialization": "task.object_deserialization",
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


def _validate_policy(policy: object) -> ExtractionPolicy:
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
        or values[0] is not PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
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
) -> tuple[FeatureState, tuple[int, int] | None]:
    if not feature_is_applicable(spec, prompt):
        return FeatureState.NOT_APPLICABLE, None
    if (
        prompt.language.casefold() not in _SUPPORTED_LANGUAGE_ALIASES
        or not spec.deterministic_terms
    ):
        return FeatureState.UNRESOLVED, None

    match = matches[spec.feature_id]
    prerequisite = _SAFETY_TASK_PREREQUISITE.get(spec.feature_id)
    if prerequisite is not None and matches.get(prerequisite) is None:
        return FeatureState.ABSENT, None
    if match is None:
        return FeatureState.ABSENT, None
    return FeatureState.PRESENT, match


def _fact_payload(prompt: PromptRecord) -> list[dict[str, object]]:
    matches = _match_by_feature(prompt)
    facts: list[dict[str, object]] = []
    for spec in PROMPT_FEATURE_CATALOG:
        state, match = _resolved_state(spec, prompt, matches)
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


def _extract(snapshot: PromptRecord, policy: ExtractionPolicy) -> PromptExtractionProposalRecord:
    facts = _fact_payload(snapshot)
    raw_response = _canonical_json({"facts": facts})
    if len(raw_response) > policy.max_response_chars:
        raise _InvalidInput from None
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "prompt_id": snapshot.prompt_id,
        "task_id": snapshot.task_id,
        "prompt_sha256": hashlib.sha256(snapshot.prompt.encode("utf-8")).hexdigest(),
        "backend": PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
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


class DeterministicCatalogExtractor:
    """Emit one complete facts proposal from the immutable finite term catalog."""

    def extract(
        self,
        prompt: PromptRecord,
        policy: ExtractionPolicy,
    ) -> PromptExtractionProposalRecord:
        try:
            trusted_policy = _validate_policy(policy)
            snapshot = _snapshot_prompt(prompt)
        except (SecAwareError, _InvalidInput):
            prompt = None  # type: ignore[assignment]
            policy = None  # type: ignore[assignment]
            raise _invalid_error() from None
        except Exception:
            prompt = None  # type: ignore[assignment]
            policy = None  # type: ignore[assignment]
            raise _internal_error() from None

        try:
            return _extract(snapshot, trusted_policy)
        except _InvalidInput:
            prompt = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            policy = None  # type: ignore[assignment]
            raise _invalid_error() from None
        except Exception:
            prompt = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            policy = None  # type: ignore[assignment]
            raise _internal_error() from None


__all__ = ["DeterministicCatalogExtractor"]

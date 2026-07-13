"""Temporary compatibility wrapper for deterministic Prompt TSG extraction."""

from __future__ import annotations

from enum import Enum
import hashlib
from typing import cast

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
from secaware.tsg.proposal_validator import _snapshot_prompt as _snapshot_source_prompt


_LEGACY_POLICY_SHA256 = hashlib.sha256(b"deterministic_catalog_v1").hexdigest()
_LEGACY_POLICY = ExtractionPolicy(
    backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
    policy_sha256=_LEGACY_POLICY_SHA256,
    catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    max_response_chars=262_144,
)


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
    return _snapshot_source_prompt(value)


def _extract(snapshot: PromptRecord) -> PromptTSGRecord:
    proposal = DeterministicCatalogExtractor().extract(snapshot, _LEGACY_POLICY)
    return build_prompt_tsg(proposal, snapshot)


def _try_snapshot_prompt(value: object) -> PromptRecord | _FailureKind:
    try:
        return _snapshot_prompt(value)
    except SecAwareError:
        return _FailureKind.INVALID_INPUT
    except Exception:
        return _FailureKind.INTERNAL


def _try_extract(snapshot: PromptRecord) -> PromptTSGRecord | _FailureKind:
    try:
        return _extract(snapshot)
    except SecAwareError as error:
        if error.code is ErrorCode.TSG_INVALID:
            return _FailureKind.INVALID_INPUT
        return _FailureKind.INTERNAL
    except Exception:
        return _FailureKind.INTERNAL


def extract_prompt_tsg(prompt: PromptRecord) -> PromptTSGRecord:
    """Build a canonical Prompt TSG through the explicit deterministic backend."""
    snapshot_result = _try_snapshot_prompt(prompt)
    prompt = cast(PromptRecord, None)
    if isinstance(snapshot_result, _FailureKind):
        failure = snapshot_result
        snapshot_result = cast(PromptRecord, None)
        if failure is _FailureKind.INVALID_INPUT:
            raise _invalid_error() from None
        raise _internal_error() from None

    result = _try_extract(snapshot_result)
    snapshot_result = cast(PromptRecord, None)
    if isinstance(result, _FailureKind):
        if result is _FailureKind.INVALID_INPUT:
            raise _invalid_error() from None
        raise _internal_error() from None
    return result


__all__ = ["extract_prompt_tsg"]

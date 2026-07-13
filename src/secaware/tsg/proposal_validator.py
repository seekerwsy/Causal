"""Deterministic trust boundary for prompt extraction proposals."""

from __future__ import annotations

import hashlib

from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import model_shape_is_intact
from secaware.schema.features import FeatureState
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG_SHA256,
    FeatureSpec,
    prompt_feature_spec,
)


def _invalid_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "tsg.validate_proposal",
        "prompt extraction proposal validation failed",
    )


def _snapshot_prompt(prompt: object) -> PromptRecord:
    if type(prompt) is not PromptRecord or not model_shape_is_intact(prompt):
        raise _invalid_error() from None
    try:
        return PromptRecord.model_validate(
            prompt.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except (ValidationError, UnicodeError):
        raise _invalid_error() from None


def feature_is_applicable(spec: FeatureSpec, prompt: PromptRecord) -> bool:
    """Return whether all finite scope constraints admit this prompt."""
    return (not spec.applicable_cwes or prompt.cwe in spec.applicable_cwes) and (
        not spec.applicable_task_families or prompt.task_family in spec.applicable_task_families
    )


def _validate_evidence(proposal: PromptExtractionProposalRecord, text: str) -> None:
    spans = [span for fact in proposal.facts for span in fact.evidence]
    spans.extend(span for node in proposal.direct_nodes for span in node.evidence)
    spans.extend(span for edge in proposal.direct_edges for span in edge.evidence)
    for span in spans:
        if span.end > len(text) or text[span.start : span.end] != span.text:
            raise _invalid_error() from None
        if hashlib.sha256(span.text.encode("utf-8")).hexdigest() != span.text_sha256:
            raise _invalid_error() from None


def validate_proposal(
    proposal: PromptExtractionProposalRecord,
    prompt: PromptRecord,
) -> PromptExtractionProposalRecord:
    """Deep-revalidate and bind one proposal to the exact source prompt."""
    source = _snapshot_prompt(prompt)
    if type(proposal) is not PromptExtractionProposalRecord or not model_shape_is_intact(proposal):
        raise _invalid_error() from None
    try:
        snapshot = PromptExtractionProposalRecord.model_validate(
            proposal.model_dump(mode="python", round_trip=True, warnings=False)
        )
    except ValidationError:
        raise _invalid_error() from None
    if (
        snapshot.prompt_id != source.prompt_id
        or snapshot.task_id != source.task_id
        or snapshot.prompt_sha256 != hashlib.sha256(source.prompt.encode("utf-8")).hexdigest()
        or snapshot.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
    ):
        raise _invalid_error() from None
    _validate_evidence(snapshot, source.prompt)

    for fact in snapshot.facts:
        applicable = feature_is_applicable(prompt_feature_spec(fact.feature_id), source)
        if applicable and fact.state is FeatureState.NOT_APPLICABLE:
            raise _invalid_error() from None
        if not applicable and fact.state is not FeatureState.NOT_APPLICABLE:
            raise _invalid_error() from None
    for node in snapshot.direct_nodes:
        if not feature_is_applicable(prompt_feature_spec(node.feature_id), source):
            raise _invalid_error() from None
    return snapshot


__all__ = ["feature_is_applicable", "validate_proposal"]

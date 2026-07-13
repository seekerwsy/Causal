from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
import hashlib
import json
import traceback

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy, PromptExtractor
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.schema.features import FeatureState, PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
)


_POLICY_SHA256 = hashlib.sha256(b"deterministic_catalog_v1").hexdigest()


def _prompt(
    text: str = "Read a user-provided file path and normalize the path.",
    *,
    language: str = "python",
    task_family: str = "path_handling",
    cwe: str = "CWE-22",
) -> PromptRecord:
    return PromptRecord(
        prompt_id="p-deterministic",
        task_id="task-deterministic",
        split="discover",
        language=language,
        task_family=task_family,
        cwe=cwe,
        prompt=text,
    )


def _policy(
    *,
    backend: PromptExtractorBackend = PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
    catalog_sha256: str = PROMPT_FEATURE_CATALOG_SHA256,
    max_response_chars: int = 262_144,
) -> ExtractionPolicy:
    return ExtractionPolicy(
        backend=backend,
        policy_sha256=_POLICY_SHA256,
        catalog_sha256=catalog_sha256,
        max_response_chars=max_response_chars,
    )


def _states(proposal) -> dict[str, FeatureState]:
    return {fact.feature_id: fact.state for fact in proposal.facts}


def test_extraction_policy_is_the_exact_frozen_slots_contract() -> None:
    policy = _policy()

    assert tuple(field.name for field in fields(ExtractionPolicy)) == (
        "backend",
        "policy_sha256",
        "catalog_sha256",
        "max_response_chars",
    )
    assert not hasattr(policy, "__dict__")
    with pytest.raises(FrozenInstanceError):
        policy.policy_sha256 = "0" * 64  # type: ignore[misc]


def test_prompt_extractor_protocol_declares_the_backend_boundary() -> None:
    assert PromptExtractor.extract.__annotations__ == {
        "prompt": "PromptRecord",
        "policy": "ExtractionPolicy",
        "return": "PromptExtractionProposalRecord",
    }


def test_deterministic_backend_returns_facts_not_graph_or_outcome() -> None:
    proposal = DeterministicCatalogExtractor().extract(_prompt(), _policy())

    assert proposal.backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    assert len(proposal.facts) == len(PROMPT_FEATURE_CATALOG)
    assert proposal.direct_nodes == ()
    assert proposal.direct_edges == ()
    assert "secure" not in proposal.model_dump_json().casefold()
    assert "oracle" not in proposal.model_dump_json().casefold()


def test_deterministic_backend_emits_closed_catalog_states_and_exact_evidence() -> None:
    prompt = _prompt()
    proposal = DeterministicCatalogExtractor().extract(prompt, _policy())
    states = _states(proposal)

    assert tuple(fact.feature_id for fact in proposal.facts) == tuple(
        sorted(spec.feature_id for spec in PROMPT_FEATURE_CATALOG)
    )
    assert states["task.file_read"] is FeatureState.PRESENT
    assert states["safety.path_normalization"] is FeatureState.PRESENT
    assert states["task.database_query"] is FeatureState.NOT_APPLICABLE
    assert states["presentation.noop_rewrite"] is FeatureState.UNRESOLVED

    fact = next(item for item in proposal.facts if item.feature_id == "task.file_read")
    assert len(fact.evidence) == 1
    span = fact.evidence[0]
    assert prompt.prompt[span.start : span.end] == "user-provided file path"
    assert span.text == "user-provided file path"
    assert span.text_sha256 == hashlib.sha256(span.text.encode("utf-8")).hexdigest()


def test_detached_safety_term_does_not_become_a_present_control() -> None:
    proposal = DeterministicCatalogExtractor().extract(
        _prompt("Please normalize the path carefully."),
        _policy(),
    )

    assert _states(proposal)["task.file_read"] is FeatureState.ABSENT
    assert _states(proposal)["safety.path_normalization"] is FeatureState.ABSENT


def test_unknown_language_marks_resolvable_in_scope_features_unresolved() -> None:
    proposal = DeterministicCatalogExtractor().extract(
        _prompt(language="brainfuck"),
        _policy(),
    )
    states = _states(proposal)

    assert states["task.file_read"] is FeatureState.UNRESOLVED
    assert states["safety.path_normalization"] is FeatureState.UNRESOLVED
    assert states["task.database_query"] is FeatureState.NOT_APPLICABLE


def test_unicode_prefix_uses_character_offsets_not_encoded_byte_offsets() -> None:
    prompt = _prompt("界 Read a user-provided file path.")
    proposal = DeterministicCatalogExtractor().extract(prompt, _policy())
    fact = next(item for item in proposal.facts if item.feature_id == "task.file_read")

    assert fact.evidence[0].start == prompt.prompt.index("user-provided file path")
    assert prompt.prompt[fact.evidence[0].start : fact.evidence[0].end] == fact.evidence[0].text


def test_non_utf8_prompt_state_is_rejected_as_invalid_not_internal() -> None:
    prompt = _prompt("Read a user-provided file path.")
    object.__setattr__(prompt, "prompt", "\ud800")

    with pytest.raises(SecAwareError) as exc_info:
        DeterministicCatalogExtractor().extract(prompt, _policy())

    assert exc_info.value.code is ErrorCode.TSG_INVALID


def test_raw_response_is_canonical_facts_json_with_shared_hash_and_id_semantics() -> None:
    proposal = DeterministicCatalogExtractor().extract(_prompt(), _policy())
    expected = json.dumps(
        {
            "facts": [
                fact.model_dump(mode="json", round_trip=True, warnings=False)
                for fact in proposal.facts
            ]
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )

    assert proposal.raw_response == expected
    assert proposal.response_sha256 == hashlib.sha256(expected.encode("utf-8")).hexdigest()
    assert proposal.proposal_id.startswith("proposal_")


def test_deterministic_backend_is_order_and_locale_independent() -> None:
    prompt = _prompt(
        "Build a SQL QUERY using a PREPARED STATEMENT.",
        task_family="sql_query",
        cwe="CWE-89",
    )

    first = DeterministicCatalogExtractor().extract(prompt, _policy())
    second = DeterministicCatalogExtractor().extract(prompt, _policy())

    assert first.model_dump_json() == second.model_dump_json()


@pytest.mark.parametrize(
    "policy",
    (
        _policy(backend=PromptExtractorBackend.LLM_FACTS_V1),
        _policy(catalog_sha256="0" * 64),
        _policy(max_response_chars=1),
    ),
)
def test_policy_identity_and_response_bound_fail_closed_without_prompt_leakage(
    policy: ExtractionPolicy,
) -> None:
    sentinel = "RAW_PROMPT_SENTINEL_4fb581"

    with pytest.raises(SecAwareError) as exc_info:
        DeterministicCatalogExtractor().extract(_prompt(sentinel), policy)

    rendered = "\n".join(
        (
            str(exc_info.value),
            repr(exc_info.value),
            "".join(traceback.format_exception(exc_info.value)),
        )
    )
    assert exc_info.value.code in {ErrorCode.TSG_INVALID, ErrorCode.ANALYSIS_INVALID}
    assert sentinel not in rendered


def test_mutated_non_string_prompt_field_is_rejected_without_leakage() -> None:
    sentinel = "RAW_PROMPT_SENTINEL_b9f0f6"
    prompt = _prompt(sentinel)
    object.__setattr__(prompt, "task_family", ["path_handling", sentinel])

    with pytest.raises(SecAwareError) as exc_info:
        DeterministicCatalogExtractor().extract(prompt, _policy())

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert sentinel not in "".join(traceback.format_exception(exc_info.value))

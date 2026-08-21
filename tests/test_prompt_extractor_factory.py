from __future__ import annotations

import math
from dataclasses import fields, replace

import pytest
from pydantic import ValidationError

from secaware.config import AppConfig, PromptExtractorLLMConfig, TSGConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.deterministic_catalog import (
    DeterministicCatalogExtractor,
    MultilingualDeterministicCatalogExtractor,
)
from secaware.extractors.factory import (
    extraction_policy,
    extractor_for_config,
    structured_policy_for_config,
)
from secaware.extractors.llm_direct_graph import (
    LLMDirectGraphExtractor,
    llm_direct_graph_policy_sha256,
)
from secaware.extractors.llm_facts import LLMFactsExtractor, llm_facts_policy_sha256
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import MAX_RAW_RESPONSE_CHARS
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def _llm_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "provider": "openai_compatible",
        "model_id": "locked-model-v1",
        "base_url": "https://example.invalid/v1",
        "api_key_env": "SECAWARE_TEST_API_KEY",
        "timeout_seconds": 30.0,
        "max_attempts": 2,
        "max_response_bytes": 262_144,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 0,
    }
    payload.update(overrides)
    return payload


def _tsg(
    backend: PromptExtractorBackend,
    *,
    llm: dict[str, object] | None = None,
) -> TSGConfig:
    payload: dict[str, object] = {"prompt_extractor": backend}
    if llm is not None:
        payload["llm"] = llm
    return TSGConfig.model_validate(payload)


class CapturingTransport:
    def complete(self, request_bytes: bytes, policy: object) -> bytes:
        del request_bytes, policy
        raise RuntimeError("transport must not be called by factory construction")


def test_default_backend_is_llm_facts_but_demo_is_explicitly_offline() -> None:
    assert TSGConfig.model_fields["prompt_extractor"].default is PromptExtractorBackend.LLM_FACTS_V1
    demo = load_config("configs/demo.yaml")
    paper = load_config("configs/paper_v0.yaml")
    assert demo.tsg.prompt_extractor is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    assert demo.tsg.llm is None
    assert paper.tsg.prompt_extractor is PromptExtractorBackend.LLM_FACTS_V1
    assert paper.tsg.llm is not None


def test_prompt_extractor_llm_config_is_the_exact_strict_contract() -> None:
    assert set(PromptExtractorLLMConfig.model_fields) == {
        "provider",
        "model_id",
        "base_url",
        "api_key_env",
        "timeout_seconds",
        "max_attempts",
        "max_response_bytes",
        "temperature",
        "top_p",
        "seed",
        "enable_thinking",
    }
    config = PromptExtractorLLMConfig.model_validate(_llm_payload())
    assert config.provider == "openai_compatible"
    assert "example.invalid" not in repr(config)
    assert "SECAWARE_TEST_API_KEY" not in repr(config)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("model_id", ""),
        ("model_id", " model"),
        ("model_id", "model\x00"),
        ("base_url", " https://example.invalid/v1"),
        ("base_url", "https://user:secret@example.invalid/v1"),
        ("base_url", "https://example.invalid/v1?token=secret"),
        ("api_key_env", "BAD-NAME"),
        ("timeout_seconds", math.inf),
        ("timeout_seconds", 0.0),
        ("max_attempts", 0),
        ("max_response_bytes", 1023),
        ("temperature", math.nan),
        ("temperature", 2.1),
        ("top_p", 0.0),
        ("seed", 2**63),
    ],
)
def test_prompt_extractor_llm_config_rejects_unsafe_values(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        PromptExtractorLLMConfig.model_validate(_llm_payload(**{field: value}))


def test_app_config_requires_backend_specific_llm_coordinates() -> None:
    base = {
        "run": {"name": "strict"},
        "data": {
            "prompts_path": "prompts.jsonl",
            "prompt_attestations_path": "prompt-attestations.jsonl",
        },
        "intervention": {"executor": "deterministic"},
    }
    with pytest.raises(ValidationError):
        AppConfig.model_validate(base)
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {
                **base,
                "tsg": {"prompt_extractor": "llm_direct_graph_v1"},
            }
        )
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {
                **base,
                "tsg": {
                    "prompt_extractor": "deterministic_catalog_v1",
                    "llm": _llm_payload(),
                },
            }
        )


def test_factory_mapping_is_exhaustive_and_never_uses_transport_for_deterministic() -> None:
    deterministic = _tsg(PromptExtractorBackend.DETERMINISTIC_CATALOG_V1)
    multilingual = _tsg(PromptExtractorBackend.DETERMINISTIC_CATALOG_V2)
    facts = _tsg(PromptExtractorBackend.LLM_FACTS_V1, llm=_llm_payload())
    direct = _tsg(PromptExtractorBackend.LLM_DIRECT_GRAPH_V1, llm=_llm_payload())
    transport = CapturingTransport()

    assert type(extractor_for_config(deterministic)) is DeterministicCatalogExtractor
    assert type(extractor_for_config(multilingual)) is MultilingualDeterministicCatalogExtractor
    assert type(extractor_for_config(facts, transport=transport)) is LLMFactsExtractor
    assert type(extractor_for_config(direct, transport=transport)) is LLMDirectGraphExtractor
    with pytest.raises(SecAwareError) as exc_info:
        extractor_for_config(deterministic, transport=transport)
    assert exc_info.value.code is ErrorCode.CONFIG
    with pytest.raises(SecAwareError) as exc_info:
        extractor_for_config(multilingual, transport=transport)
    assert exc_info.value.code is ErrorCode.CONFIG


def test_factory_rejects_mutated_config_state_before_backend_construction() -> None:
    config = _tsg(PromptExtractorBackend.LLM_FACTS_V1, llm=_llm_payload())
    object.__setattr__(config, "undeclared_coordinate", "private-mutated-state")

    with pytest.raises(SecAwareError) as exc_info:
        extractor_for_config(config, transport=CapturingTransport())

    assert exc_info.value.code is ErrorCode.CONFIG
    assert "private-mutated-state" not in str(exc_info.value)


def test_factory_policies_bind_every_llm_coordinate_without_raw_endpoint() -> None:
    base = _tsg(PromptExtractorBackend.LLM_FACTS_V1, llm=_llm_payload())
    structured = structured_policy_for_config(base)
    policy = extraction_policy(base)
    assert policy.backend is PromptExtractorBackend.LLM_FACTS_V1
    assert policy.max_response_chars == MAX_RAW_RESPONSE_CHARS
    assert len(structured.endpoint_sha256) == 64
    assert "example.invalid" not in repr(structured)

    variants = (
        _llm_payload(model_id="other-model"),
        _llm_payload(base_url="https://other.invalid/v1"),
        _llm_payload(timeout_seconds=45.0),
        _llm_payload(max_attempts=3),
        _llm_payload(max_response_bytes=131_072),
        _llm_payload(temperature=0.25),
        _llm_payload(top_p=0.75),
        _llm_payload(seed=99),
    )
    digests = {policy.policy_sha256}
    for variant in variants:
        digests.add(
            extraction_policy(_tsg(PromptExtractorBackend.LLM_FACTS_V1, llm=variant)).policy_sha256
        )
    assert len(digests) == len(variants) + 1


def test_facts_and_direct_backends_select_distinct_template_and_schema_policies() -> None:
    facts = _tsg(PromptExtractorBackend.LLM_FACTS_V1, llm=_llm_payload())
    direct = _tsg(PromptExtractorBackend.LLM_DIRECT_GRAPH_V1, llm=_llm_payload())
    facts_structured = structured_policy_for_config(facts)
    direct_structured = structured_policy_for_config(direct)

    assert facts_structured.system_template_sha256 != direct_structured.system_template_sha256
    assert facts_structured.output_schema_sha256 != direct_structured.output_schema_sha256
    assert extraction_policy(facts).policy_sha256 != extraction_policy(direct).policy_sha256
    assert {field.name for field in fields(facts_structured)} == {
        "endpoint_sha256",
        "model_id",
        "system_template_sha256",
        "output_schema_sha256",
        "temperature",
        "top_p",
        "seed",
        "timeout_seconds",
        "max_attempts",
        "max_response_bytes",
        "enable_thinking",
    }


@pytest.mark.parametrize(
    ("backend", "structured_field", "replacement"),
    [
        (PromptExtractorBackend.LLM_FACTS_V1, "system_template_sha256", "0" * 64),
        (PromptExtractorBackend.LLM_FACTS_V1, "output_schema_sha256", "1" * 64),
        (
            PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
            "system_template_sha256",
            "2" * 64,
        ),
        (
            PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
            "output_schema_sha256",
            "3" * 64,
        ),
    ],
)
def test_backend_policy_digest_changes_for_each_actual_template_and_schema_digest(
    backend: PromptExtractorBackend,
    structured_field: str,
    replacement: str,
) -> None:
    config = _tsg(backend, llm=_llm_payload())
    baseline_structured = structured_policy_for_config(config)
    changed_structured = replace(
        baseline_structured,
        **{structured_field: replacement},
    )
    digest = (
        llm_facts_policy_sha256
        if backend is PromptExtractorBackend.LLM_FACTS_V1
        else llm_direct_graph_policy_sha256
    )

    assert digest(
        changed_structured,
        PROMPT_FEATURE_CATALOG_SHA256,
        MAX_RAW_RESPONSE_CHARS,
    ) != digest(
        baseline_structured,
        PROMPT_FEATURE_CATALOG_SHA256,
        MAX_RAW_RESPONSE_CHARS,
    )


@pytest.mark.parametrize(
    ("backend", "digest"),
    (
        (PromptExtractorBackend.LLM_FACTS_V1, llm_facts_policy_sha256),
        (PromptExtractorBackend.LLM_DIRECT_GRAPH_V1, llm_direct_graph_policy_sha256),
    ),
)
def test_m4a_policy_digest_changes_with_versioned_feature_catalog(
    backend: PromptExtractorBackend,
    digest: object,
) -> None:
    structured = structured_policy_for_config(_tsg(backend, llm=_llm_payload()))

    assert callable(digest)
    assert digest(
        structured,
        PROMPT_FEATURE_CATALOG_SHA256,
        MAX_RAW_RESPONSE_CHARS,
    ) != digest(structured, "0" * 64, MAX_RAW_RESPONSE_CHARS)

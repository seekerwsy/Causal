"""Run-locked Prompt extraction backend and policy selection."""

from __future__ import annotations

import hashlib

from secaware.config import TSGConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy, PromptExtractor
from secaware.extractors.deterministic_catalog import (
    DeterministicCatalogExtractor,
    MultilingualDeterministicCatalogExtractor,
)
from secaware.extractors.llm_direct_graph import (
    LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE,
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
    LLMDirectGraphExtractor,
    llm_direct_graph_policy_sha256,
)
from secaware.extractors.llm_facts import (
    LLM_FACTS_OUTPUT_SCHEMA_SHA256,
    LLM_FACTS_SYSTEM_TEMPLATE,
    LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
    LLMFactsExtractor,
    llm_facts_policy_sha256,
)
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredJSONTransport,
    StructuredLLMPolicy,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import model_shape_is_intact
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import MAX_RAW_RESPONSE_CHARS
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def _config_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONFIG,
        stage="tsg.extract_prompt",
        message="prompt extractor configuration failed validation",
    )


def _require_tsg_config(config: object) -> TSGConfig:
    trusted: TSGConfig | None = None
    try:
        if type(config) is not TSGConfig or not model_shape_is_intact(config):
            raise ValueError
        trusted = TSGConfig.model_validate(
            config.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
        if type(trusted) is not TSGConfig or not model_shape_is_intact(trusted):
            raise ValueError
    except Exception:  # noqa: BLE001 - collapse malformed config at the trust boundary
        raise _config_error() from None
    return trusted


def _llm_coordinates(config: TSGConfig) -> tuple[str, str, str]:
    backend = config.prompt_extractor
    if config.llm is None:
        raise _config_error() from None
    if backend is PromptExtractorBackend.LLM_FACTS_V1:
        return (
            LLM_FACTS_SYSTEM_TEMPLATE,
            LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
            LLM_FACTS_OUTPUT_SCHEMA_SHA256,
        )
    if backend is PromptExtractorBackend.LLM_DIRECT_GRAPH_V1:
        return (
            LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE,
            LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
            LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
        )
    raise _config_error() from None


def structured_policy_for_config(config: TSGConfig) -> StructuredLLMPolicy:
    """Build the exact non-secret structured policy for one LLM backend."""
    trusted = _require_tsg_config(config)
    _template, template_sha256, output_schema_sha256 = _llm_coordinates(trusted)
    llm = trusted.llm
    if llm is None:  # pragma: no cover - guarded by _llm_coordinates
        raise _config_error() from None
    try:
        return StructuredLLMPolicy(
            endpoint_sha256=hashlib.sha256(llm.base_url.encode("utf-8")).hexdigest(),
            model_id=llm.model_id,
            system_template_sha256=template_sha256,
            output_schema_sha256=output_schema_sha256,
            temperature=llm.temperature,
            top_p=llm.top_p,
            seed=llm.seed,
            timeout_seconds=llm.timeout_seconds,
            max_attempts=llm.max_attempts,
            max_response_bytes=llm.max_response_bytes,
            enable_thinking=llm.enable_thinking,
        )
    except Exception:  # noqa: BLE001 - collapse malformed config at the trust boundary
        raise _config_error() from None


def extraction_policy(config: TSGConfig) -> ExtractionPolicy:
    """Return the run policy digest for the selected finite backend."""
    trusted = _require_tsg_config(config)
    backend = trusted.prompt_extractor
    if backend in {
        PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
        PromptExtractorBackend.DETERMINISTIC_CATALOG_V2,
    }:
        if trusted.llm is not None:
            raise _config_error() from None
        digest = canonical_sha256(
            {
                "backend": backend.value,
                "catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
                "max_response_chars": MAX_RAW_RESPONSE_CHARS,
                "policy_version": (
                    "deterministic_catalog_policy_v1"
                    if backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
                    else "deterministic_catalog_policy_v2_multilingual"
                ),
            }
        )
    elif backend is PromptExtractorBackend.LLM_FACTS_V1:
        structured = structured_policy_for_config(trusted)
        digest = llm_facts_policy_sha256(
            structured,
            PROMPT_FEATURE_CATALOG_SHA256,
            MAX_RAW_RESPONSE_CHARS,
        )
    elif backend is PromptExtractorBackend.LLM_DIRECT_GRAPH_V1:
        structured = structured_policy_for_config(trusted)
        digest = llm_direct_graph_policy_sha256(
            structured,
            PROMPT_FEATURE_CATALOG_SHA256,
            MAX_RAW_RESPONSE_CHARS,
        )
    else:  # pragma: no cover - enum exhaustiveness guard
        raise _config_error() from None
    return ExtractionPolicy(
        backend=backend,
        policy_sha256=digest,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        max_response_chars=MAX_RAW_RESPONSE_CHARS,
    )


def extractor_for_config(
    config: TSGConfig,
    *,
    transport: StructuredJSONTransport | None = None,
) -> PromptExtractor:
    """Construct exactly the configured backend, without fallback behavior."""
    trusted = _require_tsg_config(config)
    backend = trusted.prompt_extractor
    if backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V1:
        if trusted.llm is not None or transport is not None:
            raise _config_error() from None
        return DeterministicCatalogExtractor()
    if backend is PromptExtractorBackend.DETERMINISTIC_CATALOG_V2:
        if trusted.llm is not None or transport is not None:
            raise _config_error() from None
        return MultilingualDeterministicCatalogExtractor()

    template, _template_sha256, _schema_sha256 = _llm_coordinates(trusted)
    llm = trusted.llm
    if llm is None:  # pragma: no cover - guarded by _llm_coordinates
        raise _config_error() from None
    structured = structured_policy_for_config(trusted)
    selected_transport = transport
    if selected_transport is None:
        selected_transport = OpenAICompatibleStructuredTransport(
            base_url=llm.base_url,
            api_key_env=llm.api_key_env,
            system_template=template,
        )
    if not callable(getattr(selected_transport, "complete", None)):
        raise _config_error() from None
    if backend is PromptExtractorBackend.LLM_FACTS_V1:
        return LLMFactsExtractor(selected_transport, structured)
    if backend is PromptExtractorBackend.LLM_DIRECT_GRAPH_V1:
        return LLMDirectGraphExtractor(selected_transport, structured)
    raise _config_error() from None  # pragma: no cover


__all__ = [
    "extraction_policy",
    "extractor_for_config",
    "structured_policy_for_config",
]

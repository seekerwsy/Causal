"""Finite version binding for the persisted Prompt TSG stage contract."""

import re

from secaware.extractors.llm_direct_graph import (
    LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
)
from secaware.extractors.llm_facts import (
    LLM_FACTS_OUTPUT_SCHEMA_SHA256,
    LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.tsg import TSG_SCHEMA_VERSION
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256


PROMPT_TSG_EXTRACTOR_VERSION = "2.0"


def build_prompt_tsg_stage_contract_sha256(
    *,
    extractor_version: str = PROMPT_TSG_EXTRACTOR_VERSION,
    schema_version: str = TSG_SCHEMA_VERSION,
    catalog_sha256: str = PROMPT_TSG_CATALOG_SHA256,
    facts_template_sha256: str = LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
    facts_output_schema_sha256: str = LLM_FACTS_OUTPUT_SCHEMA_SHA256,
    direct_template_sha256: str = LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
    direct_output_schema_sha256: str = LLM_DIRECT_GRAPH_OUTPUT_SCHEMA_SHA256,
) -> str:
    if (
        type(extractor_version) is not str
        or not extractor_version
        or extractor_version != extractor_version.strip()
        or type(schema_version) is not str
        or not schema_version
        or schema_version != schema_version.strip()
        or type(catalog_sha256) is not str
        or any(
            type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in (
                catalog_sha256,
                facts_template_sha256,
                facts_output_schema_sha256,
                direct_template_sha256,
                direct_output_schema_sha256,
            )
        )
    ):
        raise ValueError("prompt TSG stage contract version is invalid")
    return canonical_sha256(
        {
            "catalog_sha256": catalog_sha256,
            "extractor_version": extractor_version,
            "schema_version": schema_version,
            "backend_values": sorted(item.value for item in PromptExtractorBackend),
            "facts_template_sha256": facts_template_sha256,
            "facts_output_schema_sha256": facts_output_schema_sha256,
            "direct_template_sha256": direct_template_sha256,
            "direct_output_schema_sha256": direct_output_schema_sha256,
        }
    )


PROMPT_TSG_STAGE_CONTRACT_SHA256 = build_prompt_tsg_stage_contract_sha256()


__all__ = [
    "PROMPT_TSG_EXTRACTOR_VERSION",
    "PROMPT_TSG_STAGE_CONTRACT_SHA256",
    "TSG_SCHEMA_VERSION",
    "build_prompt_tsg_stage_contract_sha256",
]

"""Transactional Prompt extraction proposal and TSG publication."""

from __future__ import annotations

import hashlib

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.factory import extraction_policy, extractor_for_config
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.llm.structured_transport import StructuredJSONTransport
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "extract-prompt-tsg"


def _stage_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
    )


def read_source_prompts(store: RunStore) -> tuple[PromptRecord, ...]:
    """Read the immutable source artifact exactly once for one stage build."""
    records = read_jsonl(
        store.path("inputs", "prompts.jsonl"),
        PromptRecord,
        required=True,
        allow_empty=False,
        stage=_STAGE,
    )
    if any(type(record) is not PromptRecord for record in records):
        raise _stage_error("source prompt coverage failed validation") from None
    return tuple(records)  # type: ignore[arg-type,return-value]


def validate_exact_extraction_coverage(
    prompts: tuple[PromptRecord, ...],
    proposals: tuple[PromptExtractionProposalRecord, ...],
    graphs: tuple[PromptTSGRecord, ...],
    policy: ExtractionPolicy,
) -> None:
    """Require ordered one-to-one identity and provenance coverage."""
    failed = False
    try:
        if type(policy) is not ExtractionPolicy or not prompts:
            raise ValueError
        if len(prompts) != len(proposals) or len(prompts) != len(graphs):
            raise ValueError
        prompt_ids = tuple(prompt.prompt_id for prompt in prompts)
        proposal_ids = tuple(proposal.proposal_id for proposal in proposals)
        graph_proposal_ids = tuple(graph.proposal_id for graph in graphs)
        if len(set(prompt_ids)) != len(prompt_ids):
            raise ValueError
        if len(set(proposal_ids)) != len(proposal_ids):
            raise ValueError
        if proposal_ids != graph_proposal_ids:
            raise ValueError
        for prompt, proposal, graph in zip(prompts, proposals, graphs, strict=True):
            prompt_sha256 = hashlib.sha256(prompt.prompt.encode("utf-8")).hexdigest()
            if (
                type(prompt) is not PromptRecord
                or type(proposal) is not PromptExtractionProposalRecord
                or type(graph) is not PromptTSGRecord
                or proposal.prompt_id != prompt.prompt_id
                or proposal.task_id != prompt.task_id
                or proposal.prompt_sha256 != prompt_sha256
                or proposal.backend is not policy.backend
                or proposal.policy_sha256 != policy.policy_sha256
                or proposal.catalog_sha256 != policy.catalog_sha256
                or proposal.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or graph.prompt_id != prompt.prompt_id
                or graph.task_id != prompt.task_id
                or graph.task_family != prompt.task_family
                or graph.cwe != prompt.cwe
                or graph.extractor_backend is not policy.backend
                or graph.extractor_policy_sha256 != policy.policy_sha256
                or graph.proposal_id != proposal.proposal_id
            ):
                raise ValueError
    except Exception:
        failed = True
    if failed:
        raise _stage_error("prompt extraction coverage failed validation") from None


def run_prompt_extraction_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    transport: StructuredJSONTransport | None = None,
) -> None:
    """Publish exactly one locked proposal and graph for every source prompt."""
    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _stage_error("prompt extraction configuration failed validation") from None
    backend = extractor_for_config(config.tsg, transport=transport)
    policy = extraction_policy(config.tsg)
    prompt_input = store.path("inputs", "prompts.jsonl")
    proposal_output = store.path("tsg", "prompt_extraction_proposals.jsonl")
    graph_output = store.path("tsg", "prompt_tsg.jsonl")

    def build() -> tuple[
        tuple[PromptExtractionProposalRecord, ...],
        tuple[PromptTSGRecord, ...],
    ]:
        prompts = read_source_prompts(store)
        proposals = tuple(backend.extract(prompt, policy) for prompt in prompts)
        graphs = tuple(
            build_prompt_tsg(proposal, prompt)
            for proposal, prompt in zip(proposals, prompts, strict=True)
        )
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        return proposals, graphs

    execute_jsonl_stage_transaction(
        store,
        stage=_STAGE,
        inputs=(prompt_input,),
        outputs=(
            JsonlOutputSpec(
                proposal_output,
                PromptExtractionProposalRecord,
                require_nonempty=True,
            ),
            JsonlOutputSpec(graph_output, PromptTSGRecord, require_nonempty=True),
        ),
        force=force,
        build=build,
        policy_sha256=policy.policy_sha256,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )


__all__ = [
    "read_source_prompts",
    "run_prompt_extraction_stage",
    "validate_exact_extraction_coverage",
]

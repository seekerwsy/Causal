from __future__ import annotations

from m5_executor_fixtures import request
from secaware.config import TSGConfig
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors.factory import extraction_policy
from secaware.intervention.variant_validation import security_neutral_prompt_invariant
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.graph import record_to_multidigraph


def _graph_for(text: str):
    execution = request()
    prompt = PromptRecord.model_validate(
        {
            **execution.source_prompt.model_dump(mode="python"),
            "prompt_id": "blind-neutrality-candidate",
            "prompt": text,
        }
    )
    policy = extraction_policy(TSGConfig(prompt_extractor="deterministic_catalog_v1"))
    proposal = DeterministicCatalogExtractor().extract(prompt, policy)
    return record_to_multidigraph(build_prompt_tsg(proposal, prompt))


def _source_attestation():
    execution = request()
    return next(
        item
        for item in execution.attestations
        if item.prompt_id == execution.source_prompt.prompt_id
    )


def test_neutral_prompt_requires_all_three_sentinels_absent() -> None:
    graph = _graph_for("Create a Python helper that reads a user-provided file path.")
    assert security_neutral_prompt_invariant(graph, _source_attestation()) is True


def test_vulnerability_disclosure_sentinel_is_hard_invalid() -> None:
    graph = _graph_for(
        "Create a Python helper that reads a user-provided file path. It contains a vulnerability."
    )
    assert security_neutral_prompt_invariant(graph, _source_attestation()) is False


def test_stale_or_forged_attestation_is_not_current() -> None:
    graph = _graph_for("Create a Python helper that reads a user-provided file path.")
    forged = _source_attestation().model_copy(update={"catalog_sha256": "0" * 64})
    assert security_neutral_prompt_invariant(graph, forged) is False

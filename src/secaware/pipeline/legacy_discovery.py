"""Direct-only compatibility wrapper for pre-FCI heuristic regression tests.

This module is intentionally not imported or registered by ``secaware.cli``.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import ExitStack
from typing import Any

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.discovery.tsg_qcd import discover_hypotheses
from secaware.io.run_store import RunStore
from secaware.pipeline.jsonl_stage import JsonlOutputSpec
from secaware.schema.hypotheses import HypothesisRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256


def discover_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    """Run the retired heuristic only for direct legacy regression coverage."""
    from secaware import cli as legacy_helpers

    stage = "discover"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
    ]
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    oracle_output = store.path("oracle", "observed_oracle.jsonl")

    def build() -> Sequence[Sequence[BaseModel | dict[Any, Any]]]:
        all_prompts, prompt_tsg_by_id = legacy_helpers._validated_prompt_tsg_coordinates(
            store,
            stage=stage,
        )
        prompts = [prompt for prompt in all_prompts if prompt.split == "discover"]
        prompt_ids = {prompt.prompt_id for prompt in prompts}
        prompt_tsgs = [prompt_tsg_by_id[prompt.prompt_id] for prompt in prompts]
        oracles = [
            record
            for record in legacy_helpers._read_oracle_output(
                oracle_output,
                stage=stage,
                condition="observed",
            )
            if record.prompt_id in prompt_ids
        ]
        all_h, selected_h = discover_hypotheses(
            prompts,
            prompt_tsgs,
            oracles,
            min_support_total=4,
            min_support_each_side=1,
            top_k_per_scope=2,
            score_weights=None,
        )
        return [all_h, selected_h[: config.intervention.max_hypotheses]]

    producer_outputs = {
        "extract-prompt-tsg": [
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            store.path("tsg", "prompt_tsg.jsonl"),
        ],
        "run-oracle-observed": [oracle_output],
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            if producer_stage == "extract-prompt-tsg":
                producer_context = store.hold_committed_stage(
                    producer_stage,
                    [store.path("inputs", "prompts.jsonl")],
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
                )
            else:
                producer_context = store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                )
            stack.enter_context(producer_context)
        legacy_helpers.execute_jsonl_stage_transaction(
            store,
            stage=stage,
            inputs=inputs,
            outputs=(
                JsonlOutputSpec(outputs[0], HypothesisRecord),
                JsonlOutputSpec(outputs[1], HypothesisRecord),
            ),
            force=force,
            build=build,
        )


__all__ = ["discover_hypotheses", "discover_stage"]

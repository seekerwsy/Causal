"""Transactional publication of exact Prompt-only local causal tables."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from secaware.causal.table_builder import build_local_tables, validate_local_table_bundle
from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.factory import extraction_policy
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.stages.prompt_extraction import validate_exact_extraction_coverage
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.causal import (
    CausalExclusionRecord,
    CausalObservationRecord,
    CausalTableRecord,
)
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


CAUSAL_TABLE_OUTPUTS = (
    ("causal_tables.jsonl", CausalTableRecord),
    ("causal_observations.jsonl", CausalObservationRecord),
    ("causal_exclusions.jsonl", CausalExclusionRecord),
)

_STAGE = "assemble-causal-tables"


@dataclass(frozen=True, slots=True)
class _ProducerSnapshot:
    prompts: tuple[PromptRecord, ...]
    proposals: tuple[PromptExtractionProposalRecord, ...]
    graphs: tuple[PromptTSGRecord, ...]
    oracles: tuple[OracleRecord, ...]
    input_sha256: tuple[str, ...]


def _stage_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage=_STAGE,
        message=message,
    )


def _producer_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
    )


def _read_records(path: Path, model: type, *, allow_empty: bool = False) -> tuple:
    return tuple(
        read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            stage=_STAGE,
        )
    )


def _validate_exact_observed_coverage(
    prompts: tuple[PromptRecord, ...],
    oracles: tuple[OracleRecord, ...],
    config: AppConfig,
) -> None:
    try:
        models = tuple(config.generation.models)
        seeds = tuple(config.generation.seeds)
        if (
            not prompts
            or not models
            or not seeds
            or len(models) != len(set(models))
            or len(seeds) != len(set(seeds))
        ):
            raise ValueError
        expected = {
            (prompt.prompt_id, model_id, seed_id)
            for prompt in prompts
            for model_id in models
            for seed_id in seeds
        }
        coordinates: set[tuple[str, str, int]] = set()
        request_ids: set[str] = set()
        code_ids: set[str] = set()
        for record in oracles:
            coordinate = (record.prompt_id, record.model_id, record.seed_id)
            if (
                type(record) is not OracleRecord
                or record.condition != "observed"
                or record.hypothesis_id is not None
                or record.intervention_id is not None
                or coordinate in coordinates
                or record.request_id in request_ids
                or record.code_id in code_ids
            ):
                raise ValueError
            coordinates.add(coordinate)
            request_ids.add(record.request_id)
            code_ids.add(record.code_id)
        if coordinates != expected:
            raise ValueError
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _producer_error("observed Oracle coverage failed validation") from None


def _discover_source_coordinates(
    prompts: tuple[PromptRecord, ...],
    oracles: tuple[OracleRecord, ...],
) -> tuple[tuple[str, str, str, str, str, int], ...]:
    prompt_by_id = {prompt.prompt_id: prompt for prompt in prompts}
    return tuple(
        sorted(
            (
                f"scope.cwe_{prompt_by_id[item.prompt_id].cwe.removeprefix('CWE-')}",
                prompt_by_id[item.prompt_id].cwe,
                item.model_id,
                prompt_by_id[item.prompt_id].task_id,
                item.prompt_id,
                item.seed_id,
            )
            for item in oracles
        )
    )


def assemble_causal_tables_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
) -> None:
    """Join committed producers and atomically publish closed local table bundles."""
    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _stage_error("causal-table stage configuration failed validation")
    prompt_input = store.path("inputs", "prompts.jsonl")
    proposal_input = store.path("tsg", "prompt_extraction_proposals.jsonl")
    graph_input = store.path("tsg", "prompt_tsg.jsonl")
    oracle_input = store.path("oracle", "observed_oracle.jsonl")
    inputs = (prompt_input, proposal_input, graph_input, oracle_input)
    output_specs = tuple(
        JsonlOutputSpec(
            store.path("discovery", filename),
            model,
            require_nonempty=model is not CausalExclusionRecord,
        )
        for filename, model in CAUSAL_TABLE_OUTPUTS
    )
    output_paths = tuple(item.path for item in output_specs)
    policy = extraction_policy(config.tsg)
    snapshot: _ProducerSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _stage_error("causal-table producer snapshot failed validation")
        digests = tuple(sha256_path(path) for path in inputs)
        prompts = _read_records(prompt_input, PromptRecord)
        proposals = _read_records(proposal_input, PromptExtractionProposalRecord)
        graphs = _read_records(graph_input, PromptTSGRecord)
        oracles = _read_records(oracle_input, OracleRecord)
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        _validate_exact_observed_coverage(prompts, oracles, config)
        snapshot = _ProducerSnapshot(prompts, proposals, graphs, oracles, digests)
        return digests

    def verify_input_snapshot() -> None:
        if snapshot is None or tuple(sha256_path(path) for path in inputs) != snapshot.input_sha256:
            raise _stage_error("causal-table producers changed during execution")

    def build():
        if snapshot is None:
            raise _stage_error("causal-table producer snapshot failed validation")
        discover_prompts = tuple(item for item in snapshot.prompts if item.split == "discover")
        prompt_ids = {item.prompt_id for item in discover_prompts}
        discover_graphs = tuple(item for item in snapshot.graphs if item.prompt_id in prompt_ids)
        discover_oracles = tuple(item for item in snapshot.oracles if item.prompt_id in prompt_ids)
        return build_local_tables(
            discover_prompts,
            discover_graphs,
            discover_oracles,
            PROMPT_CAUSAL_VARIABLES,
            max_variables=config.discovery.max_variables,
            max_rows=config.discovery.max_rows,
            min_independent_tasks=config.discovery.min_independent_tasks,
        )

    producer_outputs = {
        "extract-prompt-tsg": (proposal_input, graph_input),
        "run-oracle-observed": (oracle_input,),
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            if producer_stage == "extract-prompt-tsg":
                context = store.hold_committed_stage(
                    producer_stage,
                    (prompt_input,),
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
                )
            else:
                context = store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                )
            stack.enter_context(context)
        execute_jsonl_stage_transaction(
            store,
            stage=_STAGE,
            inputs=inputs,
            outputs=output_specs,
            force=force,
            build=build,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
        )
        if snapshot is None:
            raise _stage_error("causal-table producer snapshot failed validation")
        tables = _read_records(output_paths[0], CausalTableRecord)
        rows = _read_records(output_paths[1], CausalObservationRecord)
        exclusions = _read_records(output_paths[2], CausalExclusionRecord, allow_empty=True)
        discover_prompts = tuple(item for item in snapshot.prompts if item.split == "discover")
        prompt_ids = {item.prompt_id for item in discover_prompts}
        discover_oracles = tuple(item for item in snapshot.oracles if item.prompt_id in prompt_ids)
        validate_local_table_bundle(
            tables,
            rows,
            exclusions,
            source_coordinates=_discover_source_coordinates(discover_prompts, discover_oracles),
        )


__all__ = ["CAUSAL_TABLE_OUTPUTS", "assemble_causal_tables_stage"]

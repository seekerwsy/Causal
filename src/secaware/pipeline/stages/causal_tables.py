"""Transactional publication of exact Prompt-only local causal tables."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from secaware.causal.table_builder import build_local_tables, validate_local_table_bundle
from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.factory import extraction_policy
from secaware.generation.request_planner import is_observed_prompt_eligible
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
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


CAUSAL_TABLE_OUTPUTS = (
    ("causal_tables.jsonl", CausalTableRecord),
    ("causal_observations.jsonl", CausalObservationRecord),
    ("causal_exclusions.jsonl", CausalExclusionRecord),
)

_STAGE = "assemble-causal-tables"
_OBSERVED_GENERATION_PRODUCERS = (
    "generate-observed",
    "generate-provider-observed",
    "import-generation-observed",
)


@dataclass(frozen=True, slots=True)
class _ProducerSnapshot:
    prompts: tuple[PromptRecord, ...]
    proposals: tuple[PromptExtractionProposalRecord, ...]
    graphs: tuple[PromptTSGRecord, ...]
    codes: tuple[CanonicalGeneratedCodeRecord, ...]
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


def _validate_exact_observed_chain(
    prompts: tuple[PromptRecord, ...],
    codes: tuple[CanonicalGeneratedCodeRecord, ...],
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
        observed_prompts = tuple(prompt for prompt in prompts if is_observed_prompt_eligible(prompt))
        if not observed_prompts:
            raise ValueError
        expected = {
            (prompt.prompt_id, model_id, seed_id)
            for prompt in observed_prompts
            for model_id in models
            for seed_id in seeds
        }
        prompt_by_id = {item.prompt_id: item for item in observed_prompts}
        code_by_coordinate: dict[tuple[str, str, int], CanonicalGeneratedCodeRecord] = {}
        code_request_ids: set[str] = set()
        code_ids: set[str] = set()
        for record in codes:
            coordinate = (record.prompt_id, record.model_id, record.seed_id)
            prompt = prompt_by_id.get(record.prompt_id)
            request = record.generation_request
            if (
                type(record) is not CanonicalGeneratedCodeRecord
                or prompt is None
                or record.condition != "observed"
                or record.hypothesis_id is not None
                or record.intervention_id is not None
                or coordinate in code_by_coordinate
                or record.request_id in code_request_ids
                or record.code_id in code_ids
                or request.prompt_id != prompt.prompt_id
                or request.prompt != prompt.prompt
                or request.prompt_sha256 != record.prompt_sha256
                or request.language != prompt.language
                or record.prompt_sha256 != hashlib.sha256(prompt.prompt.encode("utf-8")).hexdigest()
            ):
                raise ValueError
            code_by_coordinate[coordinate] = record
            code_request_ids.add(record.request_id)
            code_ids.add(record.code_id)
        oracle_by_coordinate: dict[tuple[str, str, int], OracleRecord] = {}
        oracle_request_ids: set[str] = set()
        oracle_code_ids: set[str] = set()
        for record in oracles:
            coordinate = (record.prompt_id, record.model_id, record.seed_id)
            code = code_by_coordinate.get(coordinate)
            if (
                type(record) is not OracleRecord
                or code is None
                or record.condition != "observed"
                or record.hypothesis_id is not None
                or any(
                    value is not None
                    for value in (
                        record.assignment_id,
                        record.target_spec_id,
                        record.target_instance_id,
                        record.arm_protocol_id,
                        record.protocol_instance_id,
                        record.variant_id,
                        record.arm_role,
                    )
                )
                or coordinate in oracle_by_coordinate
                or record.request_id in oracle_request_ids
                or record.code_id in oracle_code_ids
                or record.request_id != code.request_id
                or record.code_id != code.code_id
                or record.code_sha256 != code.code_sha256
            ):
                raise ValueError
            oracle_by_coordinate[coordinate] = record
            oracle_request_ids.add(record.request_id)
            oracle_code_ids.add(record.code_id)
        if set(code_by_coordinate) != expected or set(oracle_by_coordinate) != expected:
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _producer_error("observed generation/Oracle coverage failed validation") from None


def _generation_producer_outputs(
    store: RunStore,
    stage: str,
    code_path: Path,
) -> tuple[Path, ...]:
    if stage == "generate-provider-observed":
        return (code_path, store.path("generation", "observed_attempts.jsonl"))
    return (code_path,)


def _observed_generation_producer(
    store: RunStore,
    code_path: Path,
) -> tuple[str, tuple[Path, ...]]:
    committed: list[tuple[str, tuple[Path, ...]]] = []
    for stage in _OBSERVED_GENERATION_PRODUCERS:
        outputs = _generation_producer_outputs(store, stage, code_path)
        try:
            store.require_committed_output(stage, outputs)
        except SecAwareError:
            continue
        committed.append((stage, outputs))
    if len(committed) != 1:
        raise _producer_error("observed generation producer failed validation")
    return committed[0]


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
    code_input = store.path("generation", "observed_code.jsonl")
    oracle_input = store.path("oracle", "observed_oracle.jsonl")
    producer_stages = (
        "extract-prompt-tsg",
        *_OBSERVED_GENERATION_PRODUCERS,
        "run-oracle-observed",
    )
    with store.hold_dependency_stages(producer_stages):
        _assemble_causal_tables_under_leases(
            config,
            store,
            force=force,
            prompt_input=prompt_input,
            proposal_input=proposal_input,
            graph_input=graph_input,
            code_input=code_input,
            oracle_input=oracle_input,
        )


def _assemble_causal_tables_under_leases(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    prompt_input: Path,
    proposal_input: Path,
    graph_input: Path,
    code_input: Path,
    oracle_input: Path,
) -> None:
    generation_stage, generation_outputs = _observed_generation_producer(store, code_input)
    store.require_committed_stage(
        "extract-prompt-tsg",
        (prompt_input,),
        (proposal_input, graph_input),
        expected_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    store.require_committed_stage(
        "run-oracle-observed",
        (code_input, prompt_input),
        (oracle_input,),
    )
    generation_manifest = store.path(".stages", f"{generation_stage}.json")
    oracle_manifest = store.path(".stages", "run-oracle-observed.json")
    inputs = (
        prompt_input,
        proposal_input,
        graph_input,
        code_input,
        oracle_input,
        generation_manifest,
        oracle_manifest,
    )
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
        codes = _read_records(code_input, CanonicalGeneratedCodeRecord)
        oracles = _read_records(oracle_input, OracleRecord)
        validate_exact_extraction_coverage(prompts, proposals, graphs, policy)
        _validate_exact_observed_chain(prompts, codes, oracles, config)
        snapshot = _ProducerSnapshot(prompts, proposals, graphs, codes, oracles, digests)
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

"""Transactional publication of Prompt-only FCI discovery artifacts."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path
from collections.abc import Sequence

from pydantic import BaseModel

from secaware.causal.background import build_background_knowledge
from secaware.causal.bootstrap import (
    build_reference_draw,
    replay_bootstrap_draws,
    run_task_cluster_fci_bootstrap,
)
from secaware.causal.freeze import (
    build_no_stable_hypothesis_failure,
    freeze_hypotheses,
    guard_no_future_confirmation_or_analysis,
    revalidate_frozen_hypothesis_batch,
)
from secaware.causal.paths import compute_bootstrap_path_support
from secaware.causal.table_builder import validate_local_table_bundle
from secaware.config import AppConfig
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.factory import extraction_policy
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.manifest import StageManifest, read_stage_manifest
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapDrawRecord,
    BootstrapFailureRecord,
    BootstrapPAGRecord,
    CausalTableRecord,
    DiscoveryFailureRecord,
    FrozenHypothesisRecord,
    PAGRecord,
    PathSupportRecord,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


FCI_DISCOVERY_OUTPUTS = (
    ("background_knowledge.jsonl", BackgroundKnowledgeRecord),
    ("reference_pags.jsonl", PAGRecord),
    ("bootstrap_draws.jsonl", BootstrapDrawRecord),
    ("bootstrap_pags.jsonl", BootstrapPAGRecord),
    ("bootstrap_failures.jsonl", BootstrapFailureRecord),
    ("path_support.jsonl", PathSupportRecord),
    ("hypotheses_frozen.jsonl", FrozenHypothesisRecord),
    ("discovery_failures.jsonl", DiscoveryFailureRecord),
)

_STAGE = "fci-discovery"


class FCIDiscoveryTerminalStatus(str, Enum):
    READY = "ready"
    NO_STABLE_HYPOTHESIS = "no_stable_hypothesis"
    TOO_MANY_FAILED_BOOTSTRAPS = "too_many_failed_bootstraps"


@dataclass(frozen=True, slots=True)
class FCIDiscoveryStageResult:
    status: FCIDiscoveryTerminalStatus
    hypothesis_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _DiscoveryInputSnapshot:
    tables: tuple[CausalTableRecord, ...]
    rows: tuple
    exclusions: tuple
    extraction_manifest: StageManifest
    input_sha256: tuple[str, ...]


def _stage_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage=_STAGE,
        message=message,
    )


def _read_records(path: Path, model: type[BaseModel], *, allow_empty: bool) -> tuple:
    return tuple(
        read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            stage=_STAGE,
        )
    )


def _source_coordinates_from_bundle(
    tables: Sequence[CausalTableRecord],
    rows: Sequence,
    exclusions: Sequence,
) -> tuple[tuple[str, str, str, str, str, int], ...]:
    table_by_id = {item.table_id: item for item in tables}
    coordinates = {
        (
            table_by_id[item.table_id].scope_id,
            table_by_id[item.table_id].cwe,
            item.model_id,
            item.task_id,
            item.prompt_id,
            item.seed_id,
        )
        for item in rows
    }
    coordinates.update(
        (
            item.scope_id,
            item.cwe,
            item.model_id,
            item.task_id,
            item.prompt_id,
            item.seed_id,
        )
        for item in exclusions
    )
    return tuple(sorted(coordinates))


def _too_many_failures(
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config,
    failed_count: int,
) -> DiscoveryFailureRecord:
    config_sha256 = canonical_sha256(config.model_dump(mode="json"))
    return DiscoveryFailureRecord.from_content(
        table_id=table.table_id,
        scope_id=table.scope_id,
        model_id=table.model_id,
        reason_code="too_many_failed_bootstraps",
        table_sha256=table.table_sha256,
        fci_config_sha256=config_sha256,
        background_knowledge_sha256=knowledge.knowledge_sha256,
        detail_sha256=canonical_sha256(
            {
                "reason": "too_many_failed_bootstraps",
                "failed_count": failed_count,
                "bootstrap_samples": config.bootstrap_samples,
            }
        ),
    )


def _ordered_draw_key(item) -> tuple[str, int, int]:
    return (
        item.table_id,
        0 if item.run_kind.value == "observational_reference" else 1,
        -1 if item.replicate_index is None else item.replicate_index,
    )


def _terminal_result(
    hypotheses: Sequence[FrozenHypothesisRecord],
    failures: Sequence[DiscoveryFailureRecord],
) -> FCIDiscoveryStageResult:
    reasons = {item.reason_code.value for item in failures}
    if "too_many_failed_bootstraps" in reasons:
        status = FCIDiscoveryTerminalStatus.TOO_MANY_FAILED_BOOTSTRAPS
    elif not hypotheses:
        status = FCIDiscoveryTerminalStatus.NO_STABLE_HYPOTHESIS
    else:
        status = FCIDiscoveryTerminalStatus.READY
    return FCIDiscoveryStageResult(status, len(hypotheses), len(failures))


def _validate_discovery_bundle(
    *,
    snapshot: _DiscoveryInputSnapshot,
    config: AppConfig,
    knowledge_records: tuple[BackgroundKnowledgeRecord, ...],
    reference_pags: tuple[PAGRecord, ...],
    draws: tuple,
    bootstrap_pags: tuple,
    bootstrap_failures: tuple,
    supports: tuple[PathSupportRecord, ...],
    hypotheses: tuple[FrozenHypothesisRecord, ...],
    discovery_failures: tuple[DiscoveryFailureRecord, ...],
) -> FCIDiscoveryStageResult:
    try:
        table_by_id = {item.table_id: item for item in snapshot.tables}
        table_by_sha256 = {item.table_sha256: item for item in snapshot.tables}
        table_ids = set(table_by_id)
        rows_by_table = {
            table_id: tuple(item for item in snapshot.rows if item.table_id == table_id)
            for table_id in table_by_id
        }
        knowledge_by_table = {item.table_id: item for item in knowledge_records}
        reference_by_table = {item.table_id: item for item in reference_pags}
        if (
            len(table_by_id) != len(snapshot.tables)
            or len(table_by_sha256) != len(snapshot.tables)
            or len(knowledge_by_table) != len(knowledge_records)
            or len(reference_by_table) != len(reference_pags)
            or set(knowledge_by_table) != table_ids
            or set(reference_by_table) != table_ids
            or {item.table_id for item in draws} - table_ids
            or {item.table_id for item in bootstrap_pags} - table_ids
            or {item.table_id for item in bootstrap_failures} - table_ids
            or {item.table_id for item in supports} - table_ids
            or {item.table_id for item in discovery_failures} - table_ids
            or any(item.table_sha256 not in table_by_sha256 for item in hypotheses)
            or knowledge_records != tuple(sorted(knowledge_records, key=lambda item: item.table_id))
            or reference_pags != tuple(sorted(reference_pags, key=lambda item: item.table_id))
            or draws != tuple(sorted(draws, key=_ordered_draw_key))
            or bootstrap_pags
            != tuple(sorted(bootstrap_pags, key=lambda item: (item.table_id, item.replicate_index)))
            or bootstrap_failures
            != tuple(
                sorted(
                    bootstrap_failures,
                    key=lambda item: (item.table_id, item.replicate_index),
                )
            )
            or supports
            != tuple(sorted(supports, key=lambda item: (item.table_id, item.path.variable_ids)))
            or hypotheses
            != tuple(
                sorted(
                    hypotheses,
                    key=lambda item: (item.scope_id, item.model_id, item.path.variable_ids),
                )
            )
            or discovery_failures
            != tuple(
                sorted(
                    discovery_failures,
                    key=lambda item: (item.table_id, item.reason_code.value, item.failure_id),
                )
            )
        ):
            raise ValueError
        catalog_sha256 = snapshot.extraction_manifest.catalog_sha256 or ""
        extractor_policy_sha256 = snapshot.extraction_manifest.policy_sha256 or ""
        for table_id, table in table_by_id.items():
            knowledge = knowledge_by_table[table_id]
            if knowledge != build_background_knowledge(table):
                raise ValueError
            local_rows = rows_by_table[table_id]
            expected_reference = build_reference_draw(table, local_rows, config.run.random_seed)
            expected_bootstrap = tuple(
                item.draw
                for item in replay_bootstrap_draws(
                    table,
                    local_rows,
                    config.run.random_seed,
                    config.discovery.bootstrap_samples,
                )
            )
            local_draws = tuple(item for item in draws if item.table_id == table_id)
            if local_draws != (expected_reference, *expected_bootstrap):
                raise ValueError
            local_pags = tuple(item for item in bootstrap_pags if item.table_id == table_id)
            local_bootstrap_failures = tuple(
                item for item in bootstrap_failures if item.table_id == table_id
            )
            local_supports = tuple(item for item in supports if item.table_id == table_id)
            expected_supports = compute_bootstrap_path_support(
                table=table,
                observations=local_rows,
                global_seed=config.run.random_seed,
                knowledge=knowledge,
                config=config.discovery,
                reference_pag=reference_by_table[table_id],
                bootstrap_draws=expected_bootstrap,
                bootstrap_pags=local_pags,
                bootstrap_failures=local_bootstrap_failures,
            )
            if local_supports != expected_supports:
                raise ValueError
            local_hypotheses = tuple(
                item for item in hypotheses if item.table_sha256 == table.table_sha256
            )
            local_discovery_failures = tuple(
                item for item in discovery_failures if item.table_id == table_id
            )
            failed_count = len(local_bootstrap_failures)
            too_many_failed = (
                failed_count / config.discovery.bootstrap_samples
                > config.discovery.max_failed_bootstrap_fraction
            )
            stable_support_by_path_id = {
                item.path.path_id: item
                for item in local_supports
                if Decimal(item.support_numerator)
                >= Decimal(str(config.discovery.stability_threshold))
                * Decimal(item.support_denominator)
            }
            if too_many_failed:
                if (
                    local_hypotheses
                    or local_discovery_failures
                    != (
                        _too_many_failures(
                            table,
                            knowledge,
                            config.discovery,
                            failed_count,
                        ),
                    )
                ):
                    raise ValueError
                continue
            if local_hypotheses:
                revalidate_frozen_hypothesis_batch(
                    local_hypotheses,
                    table=table,
                    reference_pag=reference_by_table[table_id],
                    knowledge=knowledge,
                    config=config.discovery,
                    catalog_sha256=catalog_sha256,
                    extractor_policy_sha256=extractor_policy_sha256,
                )
            hypothesis_by_path_id = {item.path.path_id: item for item in local_hypotheses}
            if (
                len(hypothesis_by_path_id) != len(local_hypotheses)
                or set(hypothesis_by_path_id) != set(stable_support_by_path_id)
                or bool(local_discovery_failures) == bool(local_hypotheses)
            ):
                raise ValueError
            for path_id, hypothesis in hypothesis_by_path_id.items():
                support = stable_support_by_path_id[path_id]
                if (
                    hypothesis.path != support.path
                    or hypothesis.reference_pag_id != support.reference_pag_id
                    or hypothesis.support_numerator != support.support_numerator
                    or hypothesis.support_denominator != support.support_denominator
                ):
                    raise ValueError
            if local_discovery_failures:
                expected_failure = build_no_stable_hypothesis_failure(
                    table=table,
                    reference_pag=reference_by_table[table_id],
                    knowledge=knowledge,
                    config=config.discovery,
                    catalog_sha256=catalog_sha256,
                    extractor_policy_sha256=extractor_policy_sha256,
                )
                if local_discovery_failures != (expected_failure,):
                    raise ValueError
        if (
            len({item.knowledge_id for item in knowledge_records}) != len(knowledge_records)
            or len({item.pag_id for item in reference_pags}) != len(reference_pags)
            or len({item.draw_id for item in draws}) != len(draws)
            or len({item.bootstrap_pag_id for item in bootstrap_pags}) != len(bootstrap_pags)
            or len({item.failure_id for item in bootstrap_failures}) != len(bootstrap_failures)
            or len({item.support_id for item in supports}) != len(supports)
            or len({item.hypothesis_id for item in hypotheses}) != len(hypotheses)
            or len({item.failure_id for item in discovery_failures})
            != len(discovery_failures)
        ):
            raise ValueError
        return _terminal_result(hypotheses, discovery_failures)
    except (KeyboardInterrupt, SystemExit, SecAwareError):
        raise
    except Exception:
        raise _stage_error("FCI discovery bundle failed readback validation") from None


def fci_discovery_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    runner: FCIRunner | None = None,
) -> FCIDiscoveryStageResult:
    """Publish authenticated FCI/bootstrap/freeze artifacts in one transaction."""
    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _stage_error("FCI discovery stage configuration failed validation")
    if runner is not None and not callable(getattr(runner, "run", None)):
        raise _stage_error("FCI runner failed validation")
    guard_no_future_confirmation_or_analysis(store)
    causal_paths = tuple(
        store.path("discovery", filename) for filename, _model in (
            ("causal_tables.jsonl", CausalTableRecord),
            ("causal_observations.jsonl", None),
            ("causal_exclusions.jsonl", None),
        )
    )
    causal_manifest_path = store.path(".stages", "assemble-causal-tables.json")
    extraction_manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    inputs = (*causal_paths, causal_manifest_path, extraction_manifest_path)
    output_specs = tuple(
        JsonlOutputSpec(store.path("discovery", filename), model)
        for filename, model in FCI_DISCOVERY_OUTPUTS
    )
    snapshot: _DiscoveryInputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _stage_error("FCI discovery input snapshot failed validation")
        from secaware.schema.causal import CausalExclusionRecord, CausalObservationRecord

        digests = tuple(sha256_path(path) for path in inputs)
        tables = _read_records(causal_paths[0], CausalTableRecord, allow_empty=False)
        rows = _read_records(causal_paths[1], CausalObservationRecord, allow_empty=False)
        exclusions = _read_records(causal_paths[2], CausalExclusionRecord, allow_empty=True)
        validate_local_table_bundle(
            tables,
            rows,
            exclusions,
            source_coordinates=_source_coordinates_from_bundle(tables, rows, exclusions),
        )
        extraction_manifest = read_stage_manifest(extraction_manifest_path)
        current_policy = extraction_policy(config.tsg)
        if (
            extraction_manifest.stage != "extract-prompt-tsg"
            or extraction_manifest.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or extraction_manifest.policy_sha256 != current_policy.policy_sha256
        ):
            raise _stage_error("extractor provenance failed validation")
        snapshot = _DiscoveryInputSnapshot(
            tables=tables,
            rows=rows,
            exclusions=exclusions,
            extraction_manifest=extraction_manifest,
            input_sha256=digests,
        )
        return digests

    def verify_input_snapshot() -> None:
        if snapshot is None or tuple(sha256_path(path) for path in inputs) != snapshot.input_sha256:
            raise _stage_error("FCI discovery inputs changed during execution")

    effective_runner = runner or SpawnedFCIRunner()

    def build():
        if snapshot is None:
            raise _stage_error("FCI discovery input snapshot failed validation")
        guard_no_future_confirmation_or_analysis(store)
        knowledge_records: list[BackgroundKnowledgeRecord] = []
        reference_pags: list[PAGRecord] = []
        draws: list = []
        bootstrap_pags: list = []
        bootstrap_failures: list = []
        supports: list[PathSupportRecord] = []
        hypotheses: list[FrozenHypothesisRecord] = []
        discovery_failures: list[DiscoveryFailureRecord] = []
        for table in snapshot.tables:
            local_rows = tuple(item for item in snapshot.rows if item.table_id == table.table_id)
            knowledge = build_background_knowledge(table)
            result = run_task_cluster_fci_bootstrap(
                table,
                local_rows,
                knowledge,
                config.discovery,
                config.run.random_seed,
                effective_runner,
            )
            knowledge_records.append(knowledge)
            reference_pags.append(result.reference_pag)
            draws.extend((result.reference_draw, *result.bootstrap_draws))
            bootstrap_pags.extend(result.bootstrap_pags)
            bootstrap_failures.extend(result.bootstrap_failures)
            local_supports = compute_bootstrap_path_support(
                table=table,
                observations=local_rows,
                global_seed=config.run.random_seed,
                knowledge=knowledge,
                config=config.discovery,
                reference_pag=result.reference_pag,
                bootstrap_draws=result.bootstrap_draws,
                bootstrap_pags=result.bootstrap_pags,
                bootstrap_failures=result.bootstrap_failures,
            )
            supports.extend(local_supports)
            failed_count = len(result.bootstrap_failures)
            if (
                failed_count / config.discovery.bootstrap_samples
                > config.discovery.max_failed_bootstrap_fraction
            ):
                discovery_failures.append(
                    _too_many_failures(table, knowledge, config.discovery, failed_count)
                )
                continue
            frozen = freeze_hypotheses(
                reference_pag=result.reference_pag,
                path_supports=local_supports,
                table=table,
                knowledge=knowledge,
                config=config.discovery,
                catalog_sha256=snapshot.extraction_manifest.catalog_sha256 or "",
                extractor_policy_sha256=snapshot.extraction_manifest.policy_sha256 or "",
                store=store,
            )
            hypotheses.extend(frozen.hypotheses)
            discovery_failures.extend(frozen.failures)
        bundle = (
            tuple(sorted(knowledge_records, key=lambda item: item.table_id)),
            tuple(sorted(reference_pags, key=lambda item: item.table_id)),
            tuple(sorted(draws, key=_ordered_draw_key)),
            tuple(sorted(bootstrap_pags, key=lambda item: (item.table_id, item.replicate_index))),
            tuple(
                sorted(bootstrap_failures, key=lambda item: (item.table_id, item.replicate_index))
            ),
            tuple(sorted(supports, key=lambda item: (item.table_id, item.path.variable_ids))),
            tuple(
                sorted(
                    hypotheses,
                    key=lambda item: (item.scope_id, item.model_id, item.path.variable_ids),
                )
            ),
            tuple(
                sorted(
                    discovery_failures,
                    key=lambda item: (item.table_id, item.reason_code.value, item.failure_id),
                )
            ),
        )
        _validate_discovery_bundle(
            snapshot=snapshot,
            config=config,
            knowledge_records=bundle[0],
            reference_pags=bundle[1],
            draws=bundle[2],
            bootstrap_pags=bundle[3],
            bootstrap_failures=bundle[4],
            supports=bundle[5],
            hypotheses=bundle[6],
            discovery_failures=bundle[7],
        )
        return bundle

    producer_outputs = {
        "assemble-causal-tables": causal_paths,
        "extract-prompt-tsg": (
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            store.path("tsg", "prompt_tsg.jsonl"),
        ),
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            context = store.hold_committed_output(
                producer_stage,
                producer_outputs[producer_stage],
                expected_catalog_sha256=(
                    PROMPT_FEATURE_CATALOG_SHA256
                    if producer_stage == "extract-prompt-tsg"
                    else None
                ),
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
            raise _stage_error("FCI discovery input snapshot failed validation")
        groups = tuple(
            _read_records(spec.path, spec.model, allow_empty=True)  # type: ignore[arg-type]
            for spec in output_specs
        )
        return _validate_discovery_bundle(
            snapshot=snapshot,
            config=config,
            knowledge_records=groups[0],
            reference_pags=groups[1],
            draws=groups[2],
            bootstrap_pags=groups[3],
            bootstrap_failures=groups[4],
            supports=groups[5],
            hypotheses=groups[6],
            discovery_failures=groups[7],
        )


__all__ = [
    "FCI_DISCOVERY_OUTPUTS",
    "FCIDiscoveryStageResult",
    "FCIDiscoveryTerminalStatus",
    "fci_discovery_stage",
]

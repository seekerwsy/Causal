"""Transactional JCI analysis over committed randomized confirmation artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from secaware.causal.jci import (
    JCIAnalysisResult,
    analyze_jci_stratum,
    build_jci_background,
    build_jci_tables,
    validate_jci_analysis_result,
    validate_jci_background_bundle,
    validate_jci_relations,
    validate_jci_table_bundle,
)
from secaware.causal.jci_limits import (
    MAX_JCI_FCI_RUNS,
    MAX_JCI_MATRIX_CELLS,
    MAX_JCI_TABLES,
)
from secaware.config import AppConfig
from secaware.discovery.fci_supervisor import (
    FCIRunner,
    FCISupervisorFailureKind,
    SpawnedFCIRunner,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.causal import (
    CausalTableRecord,
    JCIBackgroundKnowledgeRecord,
    PAGRecord,
)
from secaware.schema.experiments import (
    AssignmentRecord,
    ConfirmationProtocolRecord,
    PromptVariantRecord,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentOutcomeRecord,
    JCIObservationRecord,
    JCIOrientationDeltaRecord,
)
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "jci-confirmation"
_PRODUCER_STAGES = (
    "build-confirmation-variants",
    "estimate-confirmation-effects",
    "fci-discovery",
    "randomize-confirmation",
)
_MAX_RECORDS = 100_000
_MAX_LINE_CHARS = 4_000_000
_MAX_TOTAL_CHARS = 256_000_000

JCI_STAGE_OUTPUTS = (
    (Path("analysis/jci_tables.jsonl"), CausalTableRecord),
    (Path("analysis/jci_observations.jsonl"), JCIObservationRecord),
    (Path("analysis/jci_raw_pags.jsonl"), PAGRecord),
    (Path("analysis/jci_background_knowledge.jsonl"), JCIBackgroundKnowledgeRecord),
    (Path("analysis/jci_constrained_pags.jsonl"), PAGRecord),
    (Path("analysis/jci_orientation_deltas.jsonl"), JCIOrientationDeltaRecord),
    (Path("analysis/jci_failures.jsonl"), AnalysisFailureRecord),
)

JCI_STAGE_INPUTS = (
    *(relative for relative, _model in EFFECT_STAGE_OUTPUTS),
    *(Path("interventions") / name for name, _model in PROMPT_VARIANT_OUTPUTS),
    *(Path("discovery") / name for name, _model in FCI_DISCOVERY_OUTPUTS),
    *(Path("interventions") / name for name, _model in RANDOMIZATION_OUTPUTS),
    *(Path(".stages") / f"{stage}.json" for stage in _PRODUCER_STAGES),
)


@dataclass(frozen=True, slots=True)
class JCIStageResult:
    table_count: int
    observation_count: int
    raw_pag_count: int
    background_knowledge_count: int
    constrained_pag_count: int
    orientation_delta_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    input_paths: tuple[Path, ...]
    input_sha256: tuple[str, ...]
    assignments: tuple[AssignmentRecord, ...]
    outcomes: tuple[AssignmentOutcomeRecord, ...]
    variant_graphs: tuple[PromptTSGRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    hypotheses: tuple[BaseModel, ...]
    protocols: tuple[ConfirmationProtocolRecord, ...]


class _ClassifyingRunner:
    def __init__(self, runner: FCIRunner) -> None:
        self._runner = runner
        self.failure_reason: AnalysisFailureReason | None = None

    def run(self, *args: Any, **kwargs: Any) -> PAGRecord:
        try:
            return self._runner.run(*args, **kwargs)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except TimeoutError:
            self.failure_reason = AnalysisFailureReason.BACKEND_TIMEOUT
            raise
        except SecAwareError as error:
            try:
                failure_kind = FCISupervisorFailureKind(error.details.get("failure_kind"))
            except (TypeError, ValueError):
                failure_kind = None
            if error.stage == "causal.discovery.supervisor":
                if failure_kind is FCISupervisorFailureKind.TIMEOUT:
                    self.failure_reason = AnalysisFailureReason.BACKEND_TIMEOUT
                elif failure_kind is FCISupervisorFailureKind.BACKEND_FAILURE:
                    self.failure_reason = AnalysisFailureReason.BACKEND_FAILURE
            raise
        except Exception:
            self.failure_reason = AnalysisFailureReason.BACKEND_FAILURE
            raise


def _error(message: str = "JCI stage artifact validation failed") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _read(path: Path, model: type[BaseModel], *, allow_empty: bool) -> tuple[BaseModel, ...]:
    return tuple(
        read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            max_records=_MAX_RECORDS,
            max_line_chars=_MAX_LINE_CHARS,
            max_total_chars=_MAX_TOTAL_CHARS,
            stage=_STAGE,
        )
    )


def _output_specs(store: RunStore) -> tuple[JsonlOutputSpec, ...]:
    return tuple(
        JsonlOutputSpec(
            store.root / relative,
            model,
            require_nonempty=index in {0, 1, 3},
            max_records=_MAX_RECORDS,
            max_line_chars=_MAX_LINE_CHARS,
            max_total_chars=_MAX_TOTAL_CHARS,
        )
        for index, (relative, model) in enumerate(JCI_STAGE_OUTPUTS)
    )


def _producer_paths(store: RunStore) -> dict[str, tuple[Path, ...]]:
    return {
        "estimate-confirmation-effects": tuple(
            store.root / relative for relative, _model in EFFECT_STAGE_OUTPUTS
        ),
        "build-confirmation-variants": tuple(
            store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
        ),
        "fci-discovery": tuple(
            store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
        ),
        "randomize-confirmation": tuple(
            store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
        ),
    }


def _failure(
    table_id: str,
    reason: AnalysisFailureReason,
    *,
    config_sha256: str,
    input_bundle_sha256: str,
) -> AnalysisFailureRecord:
    return AnalysisFailureRecord.from_content(
        stage=AnalysisStage.JCI,
        subject_id=table_id,
        reason_code=reason,
        config_sha256=config_sha256,
        input_bundle_sha256=input_bundle_sha256,
    )


def _has_degenerate_gsq_support(
    table: CausalTableRecord,
    rows: tuple[JCIObservationRecord, ...],
) -> bool:
    local = tuple(row for row in rows if row.table_id == table.table_id)
    return (
        sum(
            len({row.values[index] for row in local}) >= 2
            for index, _variable in enumerate(table.variables)
        )
        < 2
    )


def _index_rows_by_table(
    tables: tuple[CausalTableRecord, ...],
    rows: tuple[JCIObservationRecord, ...],
) -> dict[str, tuple[JCIObservationRecord, ...]]:
    indexed: dict[str, list[JCIObservationRecord]] = {table.table_id: [] for table in tables}
    if len(indexed) != len(tables):
        raise _error()
    for row in rows:
        local = indexed.get(row.table_id)
        if local is None:
            raise _error()
        local.append(row)
    rows_by_table = {table_id: tuple(local) for table_id, local in indexed.items()}
    if any(not local for local in rows_by_table.values()):
        raise _error()
    return rows_by_table


def _enforce_resource_budget(
    tables: tuple[CausalTableRecord, ...],
    rows_by_table: dict[str, tuple[JCIObservationRecord, ...]],
) -> None:
    matrix_cells = sum(
        len(rows_by_table[table.table_id]) * len(table.variables) for table in tables
    )
    if (
        len(tables) > MAX_JCI_TABLES
        or 2 * len(tables) > MAX_JCI_FCI_RUNS
        or matrix_cells > MAX_JCI_MATRIX_CELLS
    ):
        raise _error("JCI stage resource budget failed validation")


def _validate_bundle(
    groups: tuple[tuple[BaseModel, ...], ...],
    *,
    snapshot: _Snapshot,
    config: AppConfig,
    rows_by_table: dict[str, tuple[JCIObservationRecord, ...]],
) -> None:
    tables = tuple(groups[0])
    rows = tuple(groups[1])
    raw_pags = tuple(groups[2])
    backgrounds = tuple(groups[3])
    constrained_pags = tuple(groups[4])
    deltas = tuple(groups[5])
    failures = tuple(groups[6])
    if not tables or not rows or len(backgrounds) != len(tables):
        raise _error()
    try:
        validate_jci_table_bundle(tables, rows)  # type: ignore[arg-type]
        validate_jci_relations(
            snapshot.assignments,
            snapshot.outcomes,
            snapshot.variant_graphs,
            variants=snapshot.variants,
            hypotheses=snapshot.hypotheses,
            protocols=snapshot.protocols,
            min_independent_tasks=2,
            tables=tables,  # type: ignore[arg-type]
            rows=rows,  # type: ignore[arg-type]
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None
    table_by_id = {table.table_id: table for table in tables}
    if len(table_by_id) != len(tables):
        raise _error()
    background_by_table = {
        item.materialized_background_knowledge.table_id: item for item in backgrounds
    }
    raw_by_table = {item.table_id: item for item in raw_pags}
    raw_by_pag = {item.pag_id: item for item in raw_pags}
    constrained_by_table = {item.table_id: item for item in constrained_pags}
    delta_by_table = {
        raw_by_pag[item.raw_pag_id].table_id: item
        for item in deltas
        if item.raw_pag_id in raw_by_pag
    }
    failure_by_table = {item.subject_id: item for item in failures}
    table_ids = set(table_by_id)
    success_ids = set(raw_by_table)
    if (
        len(background_by_table) != len(backgrounds)
        or len(raw_by_table) != len(raw_pags)
        or len(constrained_by_table) != len(constrained_pags)
        or len(delta_by_table) != len(deltas)
        or len(failure_by_table) != len(failures)
        or success_ids != set(constrained_by_table)
        or success_ids != set(delta_by_table)
        or success_ids & set(failure_by_table)
        or success_ids | set(failure_by_table) != table_ids
        or set(background_by_table) != table_ids
        or any(
            item.stage is not AnalysisStage.JCI
            or item.reason_code
            not in {
                AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                AnalysisFailureReason.DEGENERATE_GSQ_SUPPORT,
                AnalysisFailureReason.BACKEND_TIMEOUT,
                AnalysisFailureReason.BACKEND_FAILURE,
            }
            for item in failures
        )
    ):
        raise _error()
    for table_id, table in table_by_id.items():
        base, expected_background = build_jci_background(table)
        background = background_by_table[table_id]
        if background != expected_background:
            raise _error()
        validate_jci_background_bundle(table, base, background)
        if table_id in success_ids:
            local_rows = rows_by_table[table_id]
            validate_jci_analysis_result(
                table,
                local_rows,  # type: ignore[arg-type]
                config.discovery,
                JCIAnalysisResult(
                    raw_pag=raw_by_table[table_id],
                    constrained_pag=constrained_by_table[table_id],
                    delta=delta_by_table[table_id],
                ),
            )


def jci_stage(
    config: AppConfig,
    store: RunStore,
    *,
    runner: FCIRunner | None = None,
    force: bool = False,
) -> JCIStageResult:
    """Publish one exact JCI bundle while holding every producer lease."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _error("JCI stage configuration failed validation")
    if runner is None:
        runner = SpawnedFCIRunner(timeout_seconds=config.discovery.timeout_seconds)
    if runner is None or not callable(getattr(runner, "run", None)):
        raise _error("JCI runner failed validation")
    producer_paths = _producer_paths(store)
    snapshot: _Snapshot | None = None
    built: tuple[tuple[BaseModel, ...], ...] | None = None
    built_rows_by_table: dict[str, tuple[JCIObservationRecord, ...]] | None = None

    with store.hold_dependency_stages(_PRODUCER_STAGES):
        try:
            commitments = {
                stage: store.require_committed_output(
                    stage,
                    producer_paths[stage],
                    expected_catalog_sha256=(
                        PROMPT_FEATURE_CATALOG_SHA256
                        if stage == "build-confirmation-variants"
                        else None
                    ),
                )
                for stage in _PRODUCER_STAGES
            }
            manifest_paths = tuple(
                store.path(".stages", f"{stage}.json") for stage in _PRODUCER_STAGES
            )
            input_paths = (
                *(path for stage in _PRODUCER_STAGES for path in producer_paths[stage]),
                *manifest_paths,
            )

            def capture_input_snapshot() -> tuple[str, ...]:
                nonlocal snapshot
                if snapshot is not None:
                    raise _error()
                input_sha256 = tuple(sha256_path(path) for path in input_paths)
                outcome_path = producer_paths["estimate-confirmation-effects"][0]
                outcome_model = EFFECT_STAGE_OUTPUTS[0][1]
                outcomes = _read(outcome_path, outcome_model, allow_empty=False)
                task4 = tuple(
                    _read(path, model, allow_empty=index >= 4)
                    for index, (path, (_name, model)) in enumerate(
                        zip(
                            producer_paths["build-confirmation-variants"],
                            PROMPT_VARIANT_OUTPUTS,
                            strict=True,
                        )
                    )
                )
                fci = tuple(
                    _read(path, model, allow_empty=index != 6)
                    for index, (path, (_name, model)) in enumerate(
                        zip(
                            producer_paths["fci-discovery"],
                            FCI_DISCOVERY_OUTPUTS,
                            strict=True,
                        )
                    )
                )
                randomization = tuple(
                    _read(path, model, allow_empty=False)
                    for path, (_name, model) in zip(
                        producer_paths["randomize-confirmation"],
                        RANDOMIZATION_OUTPUTS,
                        strict=True,
                    )
                )
                if (
                    not outcomes
                    or not task4[2]
                    or not task4[6]
                    or not task4[8]
                    or not fci[6]
                    or len(randomization[0]) != 1
                    or not randomization[1]
                ):
                    raise _error("JCI stage input universe is empty")
                snapshot = _Snapshot(
                    input_paths=input_paths,
                    input_sha256=input_sha256,
                    assignments=tuple(randomization[1]),  # type: ignore[arg-type]
                    outcomes=tuple(outcomes),  # type: ignore[arg-type]
                    variant_graphs=tuple(task4[6]),  # type: ignore[arg-type]
                    variants=tuple(task4[8]),  # type: ignore[arg-type]
                    hypotheses=tuple(fci[6]),
                    protocols=tuple(task4[2]),  # type: ignore[arg-type]
                )
                return input_sha256

            def verify_input_snapshot() -> None:
                if (
                    snapshot is None
                    or tuple(sha256_path(path) for path in snapshot.input_paths)
                    != snapshot.input_sha256
                ):
                    raise _error("JCI stage producers changed during execution")
                for stage, expected in commitments.items():
                    current = store.require_committed_output(
                        stage,
                        producer_paths[stage],
                        expected_catalog_sha256=(
                            PROMPT_FEATURE_CATALOG_SHA256
                            if stage == "build-confirmation-variants"
                            else None
                        ),
                    )
                    if current != expected:
                        raise _error("JCI stage producers changed during execution")

            def build() -> tuple[tuple[BaseModel, ...], ...]:
                nonlocal built, built_rows_by_table
                if snapshot is None:
                    raise _error()
                try:
                    tables, rows = build_jci_tables(
                        snapshot.assignments,
                        snapshot.outcomes,
                        snapshot.variant_graphs,
                        variants=snapshot.variants,
                        hypotheses=snapshot.hypotheses,
                        protocols=snapshot.protocols,
                        min_independent_tasks=2,
                    )
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise _error() from None
                if not tables:
                    raise _error("JCI stage table universe is empty")
                built_rows_by_table = _index_rows_by_table(tables, rows)
                _enforce_resource_budget(tables, built_rows_by_table)
                try:
                    validate_jci_table_bundle(tables, rows)
                    validate_jci_relations(
                        snapshot.assignments,
                        snapshot.outcomes,
                        snapshot.variant_graphs,
                        variants=snapshot.variants,
                        hypotheses=snapshot.hypotheses,
                        protocols=snapshot.protocols,
                        min_independent_tasks=2,
                        tables=tables,
                        rows=rows,
                    )
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise _error() from None
                config_sha256 = canonical_sha256(config.discovery.model_dump(mode="json"))
                input_bundle_sha256 = canonical_sha256(
                    {"schema_version": "1.0", "input_sha256": list(snapshot.input_sha256)}
                )
                raw: list[PAGRecord] = []
                backgrounds: list[JCIBackgroundKnowledgeRecord] = []
                constrained: list[PAGRecord] = []
                deltas: list[JCIOrientationDeltaRecord] = []
                failures: list[AnalysisFailureRecord] = []
                for table in tables:
                    local_rows = built_rows_by_table[table.table_id]
                    base, background = build_jci_background(table)
                    validate_jci_background_bundle(table, base, background)
                    backgrounds.append(background)
                    if table.independent_task_count < config.discovery.min_independent_tasks:
                        failures.append(
                            _failure(
                                table.table_id,
                                AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                                config_sha256=config_sha256,
                                input_bundle_sha256=input_bundle_sha256,
                            )
                        )
                        continue
                    if _has_degenerate_gsq_support(table, local_rows):
                        failures.append(
                            _failure(
                                table.table_id,
                                AnalysisFailureReason.DEGENERATE_GSQ_SUPPORT,
                                config_sha256=config_sha256,
                                input_bundle_sha256=input_bundle_sha256,
                            )
                        )
                        continue
                    classifying = _ClassifyingRunner(runner)
                    try:
                        result = analyze_jci_stratum(
                            table,
                            local_rows,
                            config.discovery,
                            classifying,
                        )
                        validate_jci_analysis_result(
                            table,
                            local_rows,
                            config.discovery,
                            result,
                        )
                    except (MemoryError, KeyboardInterrupt, SystemExit):
                        raise
                    except Exception:
                        if classifying.failure_reason is None:
                            raise _error() from None
                        failures.append(
                            _failure(
                                table.table_id,
                                classifying.failure_reason,
                                config_sha256=config_sha256,
                                input_bundle_sha256=input_bundle_sha256,
                            )
                        )
                        continue
                    raw.append(result.raw_pag)
                    constrained.append(result.constrained_pag)
                    deltas.append(result.delta)
                built = (
                    tuple(tables),
                    tuple(rows),
                    tuple(sorted(raw, key=lambda item: item.table_id)),
                    tuple(
                        sorted(
                            backgrounds,
                            key=lambda item: item.materialized_background_knowledge.table_id,
                        )
                    ),
                    tuple(sorted(constrained, key=lambda item: item.table_id)),
                    tuple(sorted(deltas, key=lambda item: item.delta_id)),
                    tuple(sorted(failures, key=lambda item: item.subject_id)),
                )
                _validate_bundle(
                    built,
                    snapshot=snapshot,
                    config=config,
                    rows_by_table=built_rows_by_table,
                )
                return built

            def validate_staged_outputs(groups: tuple[tuple[BaseModel, ...], ...]) -> None:
                if (
                    snapshot is None
                    or built is None
                    or built_rows_by_table is None
                    or groups != built
                ):
                    raise _error("JCI staged output failed validation")
                _validate_bundle(
                    groups,
                    snapshot=snapshot,
                    config=config,
                    rows_by_table=built_rows_by_table,
                )

            output_specs = _output_specs(store)
            execute_jsonl_stage_transaction(
                store,
                stage=_STAGE,
                inputs=input_paths,
                outputs=output_specs,
                force=force,
                build=build,
                capture_input_snapshot=capture_input_snapshot,
                verify_input_snapshot=verify_input_snapshot,
                validate_staged_outputs=validate_staged_outputs,
            )
            if snapshot is None:
                raise _error()
            groups = tuple(
                tuple(
                    read_jsonl(
                        spec.path,
                        spec.model,
                        required=True,
                        allow_empty=not spec.require_nonempty,
                        max_records=spec.max_records,
                        max_line_chars=spec.max_line_chars,
                        max_total_chars=spec.max_total_chars,
                        stage=_STAGE,
                    )
                )
                for spec in output_specs
            )
            final_rows_by_table = _index_rows_by_table(
                tuple(groups[0]),  # type: ignore[arg-type]
                tuple(groups[1]),  # type: ignore[arg-type]
            )
            _validate_bundle(
                groups,
                snapshot=snapshot,
                config=config,
                rows_by_table=final_rows_by_table,
            )
            return JCIStageResult(*(len(group) for group in groups))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None


__all__ = [
    "JCI_STAGE_INPUTS",
    "JCI_STAGE_OUTPUTS",
    "JCIStageResult",
    "jci_stage",
]

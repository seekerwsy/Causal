"""Transactional optional RFCI sensitivity publication over committed JCI tables."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel

from secaware.causal.jci import (
    JCIAnalysisResult,
    build_jci_background,
    validate_jci_analysis_result,
    validate_jci_background_bundle,
    validate_jci_table_bundle,
)
from secaware.config import AppConfig, RFCIConfig
from secaware.discovery.rfci_backend import (
    RFCIBackendFailureKind,
    _run_rfci_sensitivity_with_capability,
    detect_rfci_capability,
    validate_rfci_capability,
    validate_rfci_sensitivity_result,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.stages.jci import JCI_STAGE_OUTPUTS
from secaware.schema.causal import (
    CausalTableRecord,
    JCIBackgroundKnowledgeRecord,
    PAGRecord,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    JCIObservationRecord,
    RFCICapabilityRecord,
    RFCISensitivityResult,
)


_STAGE = "rfci-confirmation"
_PRODUCER_STAGE = "jci-confirmation"
_MAX_RECORDS = 100_000
_MAX_LINE_CHARS = 4_000_000
_MAX_TOTAL_CHARS = 256_000_000

RFCI_STAGE_OUTPUTS = (
    (Path("analysis/rfci_capability.jsonl"), RFCICapabilityRecord),
    (Path("analysis/rfci_pags.jsonl"), PAGRecord),
    (Path("analysis/rfci_failures.jsonl"), AnalysisFailureRecord),
)

RFCI_STAGE_INPUTS = (
    *(relative for relative, _model in JCI_STAGE_OUTPUTS),
    Path(".stages/jci-confirmation.json"),
)


@dataclass(frozen=True, slots=True)
class RFCIStageResult:
    capability_count: int
    pag_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    input_paths: tuple[Path, ...]
    input_sha256: tuple[str, ...]
    tables: tuple[CausalTableRecord, ...]
    rows: tuple[JCIObservationRecord, ...]
    rows_by_table: Mapping[str, tuple[JCIObservationRecord, ...]]
    backgrounds: tuple[JCIBackgroundKnowledgeRecord, ...]


CapabilityProbe = Callable[[RFCIConfig], RFCICapabilityRecord]
RFCIRunner = Callable[..., RFCISensitivityResult]


class _ClassifyingRunner:
    def __init__(self, runner: RFCIRunner) -> None:
        self._runner = runner
        self.failure_reason: AnalysisFailureReason | None = None

    def run(self, *args: Any, **kwargs: Any) -> RFCISensitivityResult:
        try:
            return self._runner(*args, **kwargs)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except TimeoutError:
            self.failure_reason = AnalysisFailureReason.BACKEND_TIMEOUT
            raise
        except SecAwareError as error:
            try:
                failure_kind = RFCIBackendFailureKind(error.details.get("failure_kind"))
            except (TypeError, ValueError):
                failure_kind = None
            if error.stage == "causal.discovery.rfci":
                if failure_kind is RFCIBackendFailureKind.TIMEOUT:
                    self.failure_reason = AnalysisFailureReason.BACKEND_TIMEOUT
                elif failure_kind is RFCIBackendFailureKind.BACKEND_FAILURE:
                    self.failure_reason = AnalysisFailureReason.BACKEND_FAILURE
            raise
        except Exception:
            self.failure_reason = AnalysisFailureReason.BACKEND_FAILURE
            raise


def _error(message: str = "RFCI stage artifact validation failed") -> SecAwareError:
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
            require_nonempty=index == 0,
            max_records=_MAX_RECORDS,
            max_line_chars=_MAX_LINE_CHARS,
            max_total_chars=_MAX_TOTAL_CHARS,
        )
        for index, (relative, model) in enumerate(RFCI_STAGE_OUTPUTS)
    )


def _index_rows_by_table(
    tables: tuple[CausalTableRecord, ...],
    rows: tuple[JCIObservationRecord, ...],
) -> Mapping[str, tuple[JCIObservationRecord, ...]]:
    indexed: dict[str, list[JCIObservationRecord]] = {table.table_id: [] for table in tables}
    if len(indexed) != len(tables):
        raise ValueError
    for row in rows:
        local = indexed.get(row.table_id)
        if local is None:
            raise ValueError
        local.append(row)
    rows_by_table = {table_id: tuple(local) for table_id, local in indexed.items()}
    if any(not local for local in rows_by_table.values()):
        raise ValueError
    return MappingProxyType(rows_by_table)


def _validate_jci_snapshot(
    config: AppConfig,
    groups: tuple[tuple[BaseModel, ...], ...],
) -> _Snapshot:
    tables = tuple(groups[0])
    rows = tuple(groups[1])
    raw_pags = tuple(groups[2])
    backgrounds = tuple(groups[3])
    constrained_pags = tuple(groups[4])
    deltas = tuple(groups[5])
    failures = tuple(groups[6])
    try:
        checked_config = AppConfig.model_validate(config, strict=True)
        validate_jci_table_bundle(tables, rows)  # type: ignore[arg-type]
        table_by_id = {item.table_id: item for item in tables}
        rows_by_table = _index_rows_by_table(tables, rows)  # type: ignore[arg-type]
        raw_by_table = {item.table_id: item for item in raw_pags}
        raw_by_pag = {item.pag_id: item for item in raw_pags}
        constrained_by_table = {item.table_id: item for item in constrained_pags}
        constrained_by_pag = {item.pag_id: item for item in constrained_pags}
        delta_by_table = {
            raw_by_pag[item.raw_pag_id].table_id: item
            for item in deltas
            if item.raw_pag_id in raw_by_pag
        }
        failure_by_table = {item.subject_id: item for item in failures}
        background_by_table = {
            item.materialized_background_knowledge.table_id: item for item in backgrounds
        }
        table_ids = set(table_by_id)
        success_ids = set(raw_by_table)
        if (
            not tables
            or not rows
            or len(table_by_id) != len(tables)
            or len(background_by_table) != len(backgrounds)
            or set(background_by_table) != table_ids
            or len(raw_by_table) != len(raw_pags)
            or len(raw_by_pag) != len(raw_pags)
            or len(constrained_by_table) != len(constrained_pags)
            or len(constrained_by_pag) != len(constrained_pags)
            or len(delta_by_table) != len(deltas)
            or len(failure_by_table) != len(failures)
            or set(constrained_by_table) != success_ids
            or set(delta_by_table) != success_ids
            or success_ids & set(failure_by_table)
            or success_ids | set(failure_by_table) != table_ids
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
            raise ValueError
        for table in tables:
            base, expected = build_jci_background(table)
            if background_by_table[table.table_id] != expected:
                raise ValueError
            validate_jci_background_bundle(table, base, expected)
            if table.table_id in success_ids:
                validate_jci_analysis_result(
                    table,
                    rows_by_table[table.table_id],
                    checked_config.discovery,
                    JCIAnalysisResult(
                        raw_pag=raw_by_table[table.table_id],
                        constrained_pag=constrained_by_table[table.table_id],
                        delta=delta_by_table[table.table_id],
                    ),
                )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None
    return _Snapshot(
        input_paths=(),
        input_sha256=(),
        tables=tables,  # type: ignore[arg-type]
        rows=rows,  # type: ignore[arg-type]
        rows_by_table=rows_by_table,
        backgrounds=backgrounds,  # type: ignore[arg-type]
    )


def _failure(
    table_id: str,
    reason: AnalysisFailureReason,
    *,
    config_sha256: str,
    input_bundle_sha256: str,
) -> AnalysisFailureRecord:
    return AnalysisFailureRecord.from_content(
        stage=AnalysisStage.RFCI,
        subject_id=table_id,
        reason_code=reason,
        config_sha256=config_sha256,
        input_bundle_sha256=input_bundle_sha256,
    )


def _validate_outputs(
    config: AppConfig,
    groups: tuple[tuple[BaseModel, ...], ...],
    snapshot: _Snapshot,
) -> None:
    try:
        checked_config = AppConfig.model_validate(config, strict=True)
        capabilities = tuple(groups[0])
        pags = tuple(groups[1])
        failures = tuple(groups[2])
        if len(capabilities) != 1:
            raise ValueError
        capability = validate_rfci_capability(
            RFCICapabilityRecord.model_validate(capabilities[0], strict=True),
            checked_config.rfci,
        )
        if not capability.available:
            if pags or failures:
                raise ValueError
            return
        table_by_id = {item.table_id: item for item in snapshot.tables}
        background_by_table = {
            item.materialized_background_knowledge.table_id: (
                item.materialized_background_knowledge
            )
            for item in snapshot.backgrounds
        }
        pag_by_table = {item.table_id: item for item in pags}
        failure_by_table = {item.subject_id: item for item in failures}
        table_ids = set(table_by_id)
        config_sha256 = canonical_sha256(checked_config.rfci.model_dump(mode="json"))
        input_bundle_sha256 = canonical_sha256(
            {"schema_version": "1.0", "input_sha256": list(snapshot.input_sha256)}
        )
        if (
            len(table_by_id) != len(snapshot.tables)
            or len(background_by_table) != len(snapshot.backgrounds)
            or set(background_by_table) != table_ids
            or len(pag_by_table) != len(pags)
            or len(failure_by_table) != len(failures)
            or set(pag_by_table) & set(failure_by_table)
            or set(pag_by_table) | set(failure_by_table) != table_ids
            or any(
                item.stage is not AnalysisStage.RFCI
                or item.reason_code
                not in {
                    AnalysisFailureReason.BACKEND_TIMEOUT,
                    AnalysisFailureReason.BACKEND_FAILURE,
                }
                or item.config_sha256 != config_sha256
                or item.input_bundle_sha256 != input_bundle_sha256
                for item in failures
            )
        ):
            raise ValueError
        for table_id, pag in pag_by_table.items():
            result = RFCISensitivityResult(capability=capability, pag=pag)
            checked = validate_rfci_sensitivity_result(
                result,
                table_by_id[table_id],
                background_by_table[table_id],
                checked_config.rfci,
            )
            if checked != result:
                raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error() from None


def rfci_stage(
    config: AppConfig,
    store: RunStore,
    *,
    capability_probe: CapabilityProbe | None = None,
    runner: RFCIRunner | None = None,
    force: bool = False,
) -> RFCIStageResult:
    """Publish one capability record and optional table-bound RFCI outcomes."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _error("RFCI stage configuration failed validation")
    probe = detect_rfci_capability if capability_probe is None else capability_probe
    run = _run_rfci_sensitivity_with_capability if runner is None else runner
    if not callable(probe) or not callable(run):
        raise _error("RFCI stage boundary failed validation")
    producer_paths = tuple(store.root / relative for relative, _model in JCI_STAGE_OUTPUTS)
    manifest_path = store.path(".stages", "jci-confirmation.json")
    input_paths = (*producer_paths, manifest_path)
    snapshot: _Snapshot | None = None
    capability: RFCICapabilityRecord | None = None
    built: tuple[tuple[BaseModel, ...], ...] | None = None

    with store.hold_dependency_stages((_PRODUCER_STAGE,)):
        try:
            commitment = store.require_committed_output(_PRODUCER_STAGE, producer_paths)

            def capture_input_snapshot() -> tuple[str, ...]:
                nonlocal snapshot
                if snapshot is not None:
                    raise _error()
                input_sha256 = tuple(sha256_path(path) for path in input_paths)
                groups = tuple(
                    _read(path, model, allow_empty=index in {2, 4, 5, 6})
                    for index, (path, (_relative, model)) in enumerate(
                        zip(producer_paths, JCI_STAGE_OUTPUTS, strict=True)
                    )
                )
                checked = _validate_jci_snapshot(config, groups)
                snapshot = _Snapshot(
                    input_paths=input_paths,
                    input_sha256=input_sha256,
                    tables=checked.tables,
                    rows=checked.rows,
                    rows_by_table=checked.rows_by_table,
                    backgrounds=checked.backgrounds,
                )
                return input_sha256

            def verify_input_snapshot() -> None:
                if (
                    snapshot is None
                    or tuple(sha256_path(path) for path in snapshot.input_paths)
                    != snapshot.input_sha256
                ):
                    raise _error("RFCI stage producer changed during execution")
                if store.require_committed_output(_PRODUCER_STAGE, producer_paths) != commitment:
                    raise _error("RFCI stage producer changed during execution")

            def build() -> tuple[tuple[BaseModel, ...], ...]:
                nonlocal built, capability
                if snapshot is None or capability is not None:
                    raise _error()
                try:
                    capability = RFCICapabilityRecord.model_validate(
                        probe(config.rfci), strict=True
                    )
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise _error("RFCI capability probe failed validation") from None
                try:
                    capability = validate_rfci_capability(capability, config.rfci)
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise _error("RFCI capability/configuration mismatch") from None
                pags: list[PAGRecord] = []
                failures: list[AnalysisFailureRecord] = []
                if capability.available:
                    config_sha256 = canonical_sha256(config.rfci.model_dump(mode="json"))
                    input_bundle_sha256 = canonical_sha256(
                        {"schema_version": "1.0", "input_sha256": list(snapshot.input_sha256)}
                    )
                    background_by_table = {
                        item.materialized_background_knowledge.table_id: item
                        for item in snapshot.backgrounds
                    }
                    for table in snapshot.tables:
                        local_rows = snapshot.rows_by_table[table.table_id]
                        classifying = _ClassifyingRunner(run)
                        try:
                            result = classifying.run(
                                table,
                                local_rows,
                                background_by_table[
                                    table.table_id
                                ].materialized_background_knowledge,
                                config.rfci,
                                capability=capability,
                            )
                        except (MemoryError, KeyboardInterrupt, SystemExit):
                            raise
                        except Exception:
                            if classifying.failure_reason is None:
                                raise _error("RFCI runner execution failed validation") from None
                            failures.append(
                                _failure(
                                    table.table_id,
                                    classifying.failure_reason,
                                    config_sha256=config_sha256,
                                    input_bundle_sha256=input_bundle_sha256,
                                )
                            )
                            continue
                        try:
                            checked = validate_rfci_sensitivity_result(
                                result,
                                table,
                                background_by_table[
                                    table.table_id
                                ].materialized_background_knowledge,
                                config.rfci,
                            )
                            if checked.capability != capability or checked.pag is None:
                                raise ValueError
                            pags.append(checked.pag)
                        except (MemoryError, KeyboardInterrupt, SystemExit):
                            raise
                        except Exception:
                            raise _error("RFCI runner output failed validation") from None
                built = (
                    (capability,),
                    tuple(sorted(pags, key=lambda item: item.table_id)),
                    tuple(sorted(failures, key=lambda item: item.subject_id)),
                )
                _validate_outputs(config, built, snapshot)
                return built

            def validate_staged_outputs(groups: tuple[tuple[BaseModel, ...], ...]) -> None:
                if snapshot is None or built is None or groups != built:
                    raise _error()
                _validate_outputs(config, groups, snapshot)

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
            _validate_outputs(config, groups, snapshot)
            return RFCIStageResult(*(len(group) for group in groups))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None


__all__ = [
    "RFCI_STAGE_INPUTS",
    "RFCI_STAGE_OUTPUTS",
    "RFCIStageResult",
    "rfci_stage",
]

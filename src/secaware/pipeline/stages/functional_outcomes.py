"""Transactional import of pre-registered independent functional outcomes."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.outcomes.functional import validate_functional_outcomes
from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.experiments import (
    AssignmentRecord,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    RandomizationManifestRecord,
)
from secaware.schema.outcomes import FunctionalOutcomeRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "import-functional-outcomes"
_OUTPUT_NAME = "functional_outcomes.jsonl"
_MAX_RECORDS = 100_000
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_COMBINED_BYTES = 768 * 1024 * 1024
_MAX_LINE_BYTES = 4 * 1024 * 1024
_MAX_TRAVERSAL_ENTRIES = 100_000
_MAX_TRAVERSAL_DEPTH = 32
_MAX_RELATIVE_PATH_CHARS = 4096
_MAX_NAME_CHARS = 255
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_FUTURE_DIRS = frozenset({"effects", "reports", "report", "jci", "rfci", "mechanisms"})
_FUTURE_STAGE_MANIFESTS = frozenset({"assemble-assignment-outcomes.json"})


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    path: Path
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _InputSnapshot:
    files: tuple[_FileSnapshot, ...]
    protocols: tuple[ConfirmationProtocolRecord, ...]
    contracts: tuple[FunctionalOutcomeContractRecord, ...]
    manifest: RandomizationManifestRecord
    assignments: tuple[AssignmentRecord, ...]
    outcomes: tuple[FunctionalOutcomeRecord, ...]


@dataclass(frozen=True, slots=True)
class FunctionalOutcomeImportStageResult:
    assignment_count: int
    outcome_count: int


def _error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_snapshot(path: Path, *, allow_empty: bool) -> tuple[bytes, _FileSnapshot]:
    descriptor = -1
    buffer = bytearray()
    failed = False
    result: tuple[bytes, _FileSnapshot] | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_FILE_BYTES
            or (not allow_empty and before.st_size < 1)
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError
            buffer.extend(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if _identity(after) != _identity(opened) or _identity(after_path) != _identity(opened):
            raise ValueError
        result = (bytes(buffer), _FileSnapshot(path, digest.hexdigest(), _identity(after_path)))
    except _FATAL:
        raise
    except Exception:
        failed = True
    finally:
        buffer.clear()
        chunk = b""
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if failed or result is None:
        raise _error("functional outcome input snapshot failed validation") from None
    return result


def _parse_jsonl(payload: bytes, model: type[BaseModel], *, allow_empty: bool) -> tuple:
    records: list[BaseModel] = []
    result: tuple = ()
    line = b""
    failed = False
    try:
        if len(payload) > _MAX_FILE_BYTES:
            raise ValueError
        for line in payload.splitlines():
            if not line.strip():
                continue
            if len(line) > _MAX_LINE_BYTES or len(records) >= _MAX_RECORDS:
                raise ValueError
            records.append(model.model_validate(load_strict_json_bytes(line)))
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        failed = True
    finally:
        payload = b""
        model = BaseModel
        line = b""
        records.clear()
    if failed:
        raise _error("functional outcome input artifact failed validation") from None
    return result


def _parse_stage_manifest(payload: bytes, expected_stage: str) -> StageManifest:
    result: StageManifest | None = None
    failed = False
    try:
        result = StageManifest.model_validate(load_strict_json_bytes(payload))
        if result.stage != expected_stage:
            raise ValueError
    except _FATAL:
        raise
    except Exception:
        failed = True
    finally:
        payload = b""
        expected_stage = ""
    if failed or result is None:
        raise _error("functional outcome producer manifest failed validation") from None
    return result


def _assignment_digest(assignments: tuple[AssignmentRecord, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in assignments],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _validate_randomization_index(
    manifest: RandomizationManifestRecord,
    assignments: tuple[AssignmentRecord, ...],
) -> None:
    assignment_ids = tuple(item.assignment_id for item in assignments)
    block_ids = tuple(sorted({item.block_id for item in assignments}))
    if (
        not assignments
        or len(assignment_ids) != len(set(assignment_ids))
        or manifest.assignment_ids != assignment_ids
        or manifest.block_ids != block_ids
        or manifest.assignments_sha256 != _assignment_digest(assignments)
        or any(
            item.randomization_plan_sha256 != manifest.randomization_plan_sha256
            or item.rng_version != manifest.rng_version
            for item in assignments
        )
    ):
        raise _error("functional outcome randomization index failed validation")


def _guard_no_future_artifacts(store: RunStore, *, traversal=iter_bounded_tree) -> None:
    failed = False
    try:
        for entry in traversal(
            store.root,
            max_entries=_MAX_TRAVERSAL_ENTRIES,
            max_depth=_MAX_TRAVERSAL_DEPTH,
            max_relative_path_chars=_MAX_RELATIVE_PATH_CHARS,
            max_name_chars=_MAX_NAME_CHARS,
        ):
            if not entry.is_file:
                continue
            parts = entry.relative_path.replace("\\", "/").split("/")
            if parts[0].casefold() in _FUTURE_DIRS:
                raise ValueError
            if (
                len(parts) == 2
                and parts[0].casefold() == ".stages"
                and parts[1].casefold() in _FUTURE_STAGE_MANIFESTS
            ):
                raise ValueError
            if (
                parts[0].casefold() == "analysis"
                and entry.relative_path.replace("\\", "/").casefold()
                != "analysis/functional_outcomes.jsonl"
            ):
                raise ValueError
    except _FATAL:
        raise
    except BoundedTraversalError:
        failed = True
    except Exception:
        failed = True
    if failed:
        raise _error("future analysis artifact exists before functional outcome import") from None


def import_functional_outcomes_stage(
    config: AppConfig,
    store: RunStore,
    results_path: str | Path,
    *,
    force: bool = False,
) -> FunctionalOutcomeImportStageResult:
    """Import one exact external result for every randomized task-functional assignment."""

    try:
        if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
            raise ValueError
        effective_config = AppConfig.model_validate(config.model_dump(mode="python"))
        effective_store = store
        external_results_path = Path(results_path)
        contract_value = effective_config.data.functional_outcome_contracts_path
        if contract_value is None:
            raise ValueError
        contract_path = Path(contract_value)
    except _FATAL:
        raise
    except Exception:
        raise _error("functional outcome stage arguments failed validation") from None

    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task5_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    task4_manifest = effective_store.path(".stages", "build-confirmation-variants.json")
    task5_manifest = effective_store.path(".stages", "randomize-confirmation.json")
    inputs = (
        contract_path,
        external_results_path,
        *task4_paths,
        task4_manifest,
        *task5_paths,
        task5_manifest,
    )
    output = effective_store.path("analysis", _OUTPUT_NAME)
    output_spec = JsonlOutputSpec(
        output,
        FunctionalOutcomeRecord,
        require_nonempty=True,
        max_records=_MAX_RECORDS,
        max_line_chars=_MAX_LINE_BYTES,
        max_total_chars=_MAX_FILE_BYTES,
    )
    snapshot: _InputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _error("functional outcome input snapshot failed validation")
        _guard_no_future_artifacts(effective_store)
        payloads: list[bytes] = []
        files: list[_FileSnapshot] = []
        payload_by_path: dict[Path, bytes] = {}
        try:
            combined = 0
            protocol_path = next(
                path
                for path, (name, _model) in zip(task4_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
                if name == "confirmation_protocols.jsonl"
            )
            empty_task4_paths = set(task4_paths) - {protocol_path}
            for path in inputs:
                payload, file = _read_snapshot(path, allow_empty=path in empty_task4_paths)
                combined += len(payload)
                if combined > _MAX_COMBINED_BYTES:
                    raise _error("functional outcome input resource limit exceeded")
                payloads.append(payload)
                files.append(file)
            payload_by_path = dict(zip(inputs, payloads, strict=True))
            _parse_stage_manifest(payload_by_path[task4_manifest], "build-confirmation-variants")
            _parse_stage_manifest(payload_by_path[task5_manifest], "randomize-confirmation")
            randomization_manifest_path = next(
                path
                for path, (name, _model) in zip(task5_paths, RANDOMIZATION_OUTPUTS, strict=True)
                if name == "randomization_manifest.jsonl"
            )
            assignment_path = next(
                path
                for path, (name, _model) in zip(task5_paths, RANDOMIZATION_OUTPUTS, strict=True)
                if name == "assignments.jsonl"
            )
            protocols = _parse_jsonl(
                payload_by_path[protocol_path], ConfirmationProtocolRecord, allow_empty=False
            )
            contracts = _parse_jsonl(
                payload_by_path[contract_path], FunctionalOutcomeContractRecord, allow_empty=False
            )
            manifests = _parse_jsonl(
                payload_by_path[randomization_manifest_path],
                RandomizationManifestRecord,
                allow_empty=False,
            )
            assignments = _parse_jsonl(
                payload_by_path[assignment_path], AssignmentRecord, allow_empty=False
            )
            outcomes = _parse_jsonl(
                payload_by_path[external_results_path], FunctionalOutcomeRecord, allow_empty=True
            )
            if len(manifests) != 1:
                raise _error("functional outcome randomization index failed validation")
            _validate_randomization_index(manifests[0], assignments)
            validated = validate_functional_outcomes(assignments, protocols, contracts, outcomes)
            snapshot = _InputSnapshot(
                files=tuple(files),
                protocols=protocols,
                contracts=contracts,
                manifest=manifests[0],
                assignments=assignments,
                outcomes=validated,
            )
            return tuple(item.sha256 for item in snapshot.files)
        finally:
            payloads.clear()
            files.clear()
            payload_by_path = {}
            payload = b""
            file = None
            protocols = ()
            contracts = ()
            manifests = ()
            assignments = ()
            outcomes = ()
            validated = ()

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _error("functional outcome input snapshot failed validation")
        _guard_no_future_artifacts(effective_store)
        for expected in snapshot.files:
            payload, current = _read_snapshot(
                expected.path,
                allow_empty=expected.identity[4] == 0,
            )
            del payload
            if current != expected:
                raise _error("functional outcome inputs changed during import")
        _validate_randomization_index(snapshot.manifest, snapshot.assignments)
        if (
            validate_functional_outcomes(
                snapshot.assignments,
                snapshot.protocols,
                snapshot.contracts,
                snapshot.outcomes,
            )
            != snapshot.outcomes
        ):
            raise _error("functional outcome relation changed during import")

    def build() -> tuple[tuple[FunctionalOutcomeRecord, ...]]:
        if snapshot is None:
            raise _error("functional outcome input snapshot failed validation")
        _validate_randomization_index(snapshot.manifest, snapshot.assignments)
        return (
            validate_functional_outcomes(
                snapshot.assignments,
                snapshot.protocols,
                snapshot.contracts,
                snapshot.outcomes,
            ),
        )

    def validate_staged_outputs(
        groups: tuple[tuple[BaseModel | dict[str, object], ...], ...],
    ) -> None:
        if snapshot is None or len(groups) != 1:
            raise _error("functional outcome output bundle failed validation")
        checked = validate_functional_outcomes(
            snapshot.assignments,
            snapshot.protocols,
            snapshot.contracts,
            groups[0],  # type: ignore[arg-type]
        )
        if checked != snapshot.outcomes:
            raise _error("functional outcome output bundle failed validation")

    producer_outputs = {
        "build-confirmation-variants": task4_paths,
        "randomize-confirmation": task5_paths,
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            stack.enter_context(
                effective_store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=(
                        PROMPT_FEATURE_CATALOG_SHA256
                        if producer_stage == "build-confirmation-variants"
                        else None
                    ),
                )
            )
        execute_jsonl_stage_transaction(
            effective_store,
            stage=_STAGE,
            inputs=inputs,
            outputs=(output_spec,),
            force=force,
            build=build,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
        if snapshot is None:
            raise _error("functional outcome input snapshot failed validation")
        imported_payload, _file = _read_snapshot(output, allow_empty=False)
        imported = _parse_jsonl(
            imported_payload,
            FunctionalOutcomeRecord,
            allow_empty=False,
        )
        checked = validate_functional_outcomes(
            snapshot.assignments,
            snapshot.protocols,
            snapshot.contracts,
            imported,
        )
        if checked != snapshot.outcomes:
            raise _error("functional outcome committed artifact failed validation")
        return FunctionalOutcomeImportStageResult(
            assignment_count=len(snapshot.assignments),
            outcome_count=len(checked),
        )


__all__ = [
    "FunctionalOutcomeImportStageResult",
    "import_functional_outcomes_stage",
]

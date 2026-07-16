"""Transactional import of pre-registered independent functional outcomes."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.outcomes.functional import validate_functional_outcomes
from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.stage_contracts import confirmation_stage_is_downstream
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
_TRANSACTION_TOKEN = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


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


def _is_reparse_point(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _read_snapshot(path: Path, *, allow_empty: bool) -> tuple[bytes, _FileSnapshot]:
    descriptor = -1
    buffer = bytearray()
    failed = False
    result: tuple[bytes, _FileSnapshot] | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_point(before)
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
        if (
            _identity(after) != _identity(opened)
            or _identity(after_path) != _identity(opened)
            or _is_reparse_point(after_path)
        ):
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


def _transaction_target_key(path: Path) -> str:
    return hashlib.sha256(
        ("secaware-transaction-v1\x00" + os.path.normcase(str(path))).encode(
            "utf-8",
            errors="strict",
        )
    ).hexdigest()


def _active_transaction_backup_paths(store: RunStore) -> frozenset[str]:
    journal_path = store.path(".stages", f".{_STAGE}.transaction.json")
    try:
        journal_path.lstat()
    except FileNotFoundError:
        return frozenset()
    payload, _snapshot = _read_snapshot(journal_path, allow_empty=False)
    try:
        if len(payload) > 64 * 1024:
            raise ValueError
        value = load_strict_json_bytes(payload)
        if type(value) is not dict or set(value) != {
            "schema_version",
            "token",
            "state",
            "artifacts",
        }:
            raise ValueError
        token = value["token"]
        artifacts = value["artifacts"]
        output = store.path("analysis", _OUTPUT_NAME)
        manifest = store.path(".stages", f"{_STAGE}.json")
        expected_targets = (_transaction_target_key(output), _transaction_target_key(manifest))
        if (
            value["schema_version"] != "1.0"
            or type(token) is not str
            or _TRANSACTION_TOKEN.fullmatch(token) is None
            or value["state"] != "recovery"
            or type(artifacts) is not list
            or len(artifacts) != 2
        ):
            raise ValueError
        backups = (
            (
                output.with_name(f".{output.name}.{token}.output0.recovery.backup"),
                f"analysis/.{_OUTPUT_NAME}.{token}.output0.recovery.backup",
            ),
            (
                manifest.with_name(f".{manifest.name}.{token}.manifest.recovery.backup"),
                f".stages/.{_STAGE}.json.{token}.manifest.recovery.backup",
            ),
        )
        owned: set[str] = set()
        for artifact, expected_target, (backup, relative_backup) in zip(
            artifacts,
            expected_targets,
            backups,
            strict=True,
        ):
            if type(artifact) is not dict or set(artifact) != {
                "target_key",
                "old_exists",
                "old_sha256",
                "committed_sha256",
            }:
                raise ValueError
            old_exists = artifact["old_exists"]
            old_sha256 = artifact["old_sha256"]
            committed_sha256 = artifact["committed_sha256"]
            if (
                artifact["target_key"] != expected_target
                or type(old_exists) is not bool
                or (
                    old_exists
                    and (type(old_sha256) is not str or _SHA256.fullmatch(old_sha256) is None)
                )
                or (not old_exists and old_sha256 is not None)
                or committed_sha256 is not None
            ):
                raise ValueError
            if old_exists:
                _backup_payload, backup_snapshot = _read_snapshot(backup, allow_empty=True)
                _backup_payload = b""
                if backup_snapshot.sha256 != old_sha256:
                    raise ValueError
                owned.add(relative_backup)
            else:
                try:
                    backup.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError
        return frozenset(owned)
    finally:
        payload = b""


def _validate_producer_commitments(
    store: RunStore,
    producer_outputs: Mapping[str, tuple[Path, ...]],
    producer_manifests: Mapping[str, StageManifest],
    files: Mapping[Path, _FileSnapshot],
    held_output_sha256: Mapping[str, Mapping[str, str]],
) -> None:
    if set(producer_outputs) != set(producer_manifests) or set(producer_outputs) != set(
        held_output_sha256
    ):
        raise _error("functional outcome producer commitment failed validation")
    for stage, paths in producer_outputs.items():
        relative_paths = tuple(path.relative_to(store.root).as_posix() for path in paths)
        captured = {relative: files[path].sha256 for relative, path in zip(relative_paths, paths)}
        manifest = producer_manifests[stage]
        if (
            tuple(manifest.outputs) != relative_paths
            or manifest.output_sha256 != captured
            or dict(held_output_sha256[stage]) != captured
        ):
            raise _error("functional outcome producer commitment failed validation")


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
        owned_transaction_backups = _active_transaction_backup_paths(store)
        for entry in traversal(
            store.root,
            max_entries=_MAX_TRAVERSAL_ENTRIES,
            max_depth=_MAX_TRAVERSAL_DEPTH,
            max_relative_path_chars=_MAX_RELATIVE_PATH_CHARS,
            max_name_chars=_MAX_NAME_CHARS,
        ):
            if not entry.is_file:
                continue
            relative_path = entry.relative_path.replace("\\", "/").casefold()
            if relative_path in owned_transaction_backups:
                continue
            parts = relative_path.split("/")
            if parts[0].casefold() in _FUTURE_DIRS:
                raise ValueError
            if (
                len(parts) == 2
                and parts[0].casefold() == ".stages"
                and parts[1].endswith(".json")
                and confirmation_stage_is_downstream(parts[1][:-5], after=_STAGE)
            ):
                raise ValueError
            if (
                parts[0].casefold() == "analysis"
                and relative_path != "analysis/functional_outcomes.jsonl"
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
        if not external_results_path.parts or any(
            part in {".", ".."} for part in external_results_path.parts
        ):
            raise ValueError
        contract_value = effective_config.data.functional_outcome_contracts_path
        if contract_value is None:
            raise ValueError
        contract_path = Path(contract_value)
    except _FATAL:
        raise
    except Exception:
        results_path = ""
        external_results_path = Path()
        raise _error("functional outcome stage arguments failed validation") from None

    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task5_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    task4_manifest = effective_store.path(".stages", "build-confirmation-variants.json")
    task5_manifest = effective_store.path(".stages", "randomize-confirmation.json")
    producer_outputs = {
        "build-confirmation-variants": task4_paths,
        "randomize-confirmation": task5_paths,
    }
    producer_manifest_paths = {
        "build-confirmation-variants": task4_manifest,
        "randomize-confirmation": task5_manifest,
    }
    held_output_sha256: dict[str, dict[str, str]] = {}
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
        require_nonempty=False,
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
        file_by_path: dict[Path, _FileSnapshot] = {}
        producer_manifests: dict[str, StageManifest] = {}
        try:
            combined = 0
            protocol_path = next(
                path
                for path, (name, _model) in zip(task4_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
                if name == "confirmation_protocols.jsonl"
            )
            empty_input_paths = (set(task4_paths) - {protocol_path}) | {
                contract_path,
                external_results_path,
            }
            for path in inputs:
                payload, file = _read_snapshot(path, allow_empty=path in empty_input_paths)
                combined += len(payload)
                if combined > _MAX_COMBINED_BYTES:
                    raise _error("functional outcome input resource limit exceeded")
                payloads.append(payload)
                files.append(file)
            payload_by_path = dict(zip(inputs, payloads, strict=True))
            file_by_path = {item.path: item for item in files}
            producer_manifests = {
                stage: _parse_stage_manifest(payload_by_path[path], stage)
                for stage, path in producer_manifest_paths.items()
            }
            _validate_producer_commitments(
                effective_store,
                producer_outputs,
                producer_manifests,
                file_by_path,
                held_output_sha256,
            )
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
                payload_by_path[contract_path], FunctionalOutcomeContractRecord, allow_empty=True
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
            file_by_path = {}
            producer_manifests = {}
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
        current_files: dict[Path, _FileSnapshot] = {}
        producer_manifests: dict[str, StageManifest] = {}
        manifest_stage_by_path = {path: stage for stage, path in producer_manifest_paths.items()}
        payload = b""
        try:
            for expected in snapshot.files:
                payload, current = _read_snapshot(
                    expected.path,
                    allow_empty=expected.identity[4] == 0,
                )
                if current != expected:
                    raise _error("functional outcome inputs changed during import")
                current_files[expected.path] = current
                producer_stage = manifest_stage_by_path.get(expected.path)
                if producer_stage is not None:
                    producer_manifests[producer_stage] = _parse_stage_manifest(
                        payload,
                        producer_stage,
                    )
                payload = b""
            _validate_producer_commitments(
                effective_store,
                producer_outputs,
                producer_manifests,
                current_files,
                held_output_sha256,
            )
        finally:
            payload = b""
            current_files = {}
            producer_manifests = {}
            manifest_stage_by_path = {}
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

    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            committed = stack.enter_context(
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
            held_output_sha256[producer_stage] = dict(committed)
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
        imported_payload, _file = _read_snapshot(output, allow_empty=True)
        imported = _parse_jsonl(
            imported_payload,
            FunctionalOutcomeRecord,
            allow_empty=True,
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

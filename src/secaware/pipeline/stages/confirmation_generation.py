"""Atomic assignment-bound generation for the held-out confirmation experiment."""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Sequence

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.confirmation import execute_confirmation_requests
from secaware.generation.openai_compatible_provider import create_openai_compatible_provider
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
)
from secaware.schema.generation import GenerationProvenance, GenerationRequestRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "generate-confirmation"
CONFIRMATION_PROVIDER_POLICY_VERSION = "assignment-bound-generation-provider-v1"
CONFIRMATION_PROVIDER_FACTORY_VERSION = "frozen-app-config-provider-factory-v1"
CONFIRMATION_PROVIDER_RESPONSE_VERSION = "model-bound-code-result-v1"
_MAX_INPUT_FILE_BYTES = 256_000_000
_MAX_COMBINED_INPUT_BYTES = 1_000_000_000
_MAX_JSONL_LINE_BYTES = 4_000_000
_MAX_RECORDS = 100_000
_MAX_REQUEST_PROMPT_BYTES = 256_000_000
_MAX_PROJECTED_CODE_BYTES = 1_000_000_000
_MAX_CODE_BYTES_PER_REQUEST = 1_048_576
_MAX_TRAVERSAL_ENTRIES = 100_000
_MAX_TRAVERSAL_DEPTH = 32
_MAX_RELATIVE_PATH_CHARS = 4096
_MAX_NAME_CHARS = 255
_FUTURE_STAGE_NAMES = frozenset(
    {
        "run-oracle-confirmation",
        "import-functional-outcomes",
        "analyze-jci",
        "analyze-rfci",
        "effects",
        "report",
        "jci",
        "rfci",
        "reporting",
    }
)
_FUTURE_STAGE_PREFIXES = tuple(value + "-" for value in sorted(_FUTURE_STAGE_NAMES))


CONFIRMATION_GENERATION_OUTPUTS = (
    ("confirmation_requests.jsonl", GenerationRequestRecord),
    ("confirmation_execution.jsonl", AssignmentExecutionRecord),
    ("confirmation_code.jsonl", CanonicalGeneratedCodeRecord),
)


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: Path
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _InputSnapshot:
    files: tuple[_FileSnapshot, ...]
    assignments: tuple[AssignmentRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    randomization_manifest: RandomizationManifestRecord


@dataclass(frozen=True, slots=True)
class ConfirmationGenerationStageResult:
    assignment_count: int
    generated_count: int
    terminal_no_code_count: int


@dataclass(frozen=True, slots=True)
class _MockResult:
    code: str
    provenance: GenerationProvenance
    finish_reason: str = "stop"


class _LockedMockProvider:
    def generate_many(self, requests: Sequence[GenerationRequestRecord]):
        return tuple(
            (
                request.request_id,
                _MockResult(
                    code=(
                        "# secaware locked mock generation\n"
                        f"# assignment={request.assignment_id}\n"
                    ),
                    provenance=GenerationProvenance(
                        producer="secaware-locked-mock",
                        producer_version="v1",
                    ),
                ),
            )
            for request in reversed(tuple(requests))
        )


class _SingleRequestProviderAdapter:
    def __init__(self, provider: object, system_template: str) -> None:
        self._provider = provider
        self._system_template = system_template

    def generate_many(self, requests: Sequence[GenerationRequestRecord]):
        generate = getattr(self._provider, "generate", None)
        if not callable(generate):
            raise TypeError
        return tuple(
            (request.request_id, generate(request, self._system_template)) for request in requests
        )


def _provider_from_frozen_config(config: AppConfig) -> object:
    """Construct the only production provider path from the validated frozen config."""

    generation = config.generation
    if generation.provider == "mock":
        return _LockedMockProvider()
    if generation.provider == "openai_compatible":
        provider_config = generation.openai_compatible
        if provider_config is None:
            raise _stage_error("confirmation provider is unavailable", code=ErrorCode.CONFIG)
        return _SingleRequestProviderAdapter(
            create_openai_compatible_provider(provider_config),
            provider_config.system_template,
        )
    raise _stage_error(
        "confirmation provider is unavailable",
        code=ErrorCode.EXTERNAL_INPUT_REQUIRED,
    )


def _stage_error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(code=code, stage=_STAGE, message=message, retryable=False)


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
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_INPUT_FILE_BYTES
            or (not allow_empty and before.st_size < 1)
        ):
            raise ValueError
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
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
        return bytes(buffer), _FileSnapshot(path, digest.hexdigest(), _identity(after_path))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation input snapshot failed validation") from None
    finally:
        buffer.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    failed = True
    try:
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        failed = False
        return result
    finally:
        pairs.clear()
        key = ""
        value = None
        if failed:
            result.clear()


def _json(payload: bytes) -> object:
    result: object = None
    decoded = ""
    try:
        decoded = payload.decode("utf-8", errors="strict")
        result = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        return result
    finally:
        payload = b""
        decoded = ""
        result = None


def _parse_jsonl(payload: bytes, model: type, *, allow_empty: bool) -> tuple:
    records = []
    raw = ""
    result: tuple = ()
    try:
        for raw in payload.decode("utf-8", errors="strict").splitlines():
            if not raw.strip():
                continue
            if len(raw.encode("utf-8")) > _MAX_JSONL_LINE_BYTES:
                raise ValueError
            records.append(model.model_validate(_json(raw.encode("utf-8"))))
            if len(records) > _MAX_RECORDS:
                raise ValueError
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation input artifact failed validation") from None
    finally:
        payload = b""
        model = type(None)
        raw = ""
        records.clear()
    return result


def _parse_manifest(payload: bytes) -> StageManifest:
    result: StageManifest | None = None
    try:
        result = StageManifest.model_validate(_json(payload))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation producer manifest failed validation") from None
    finally:
        payload = b""
    if result is None:  # pragma: no cover - all failures raise above
        raise _stage_error("confirmation generation producer manifest failed validation")
    return result


def _guard_no_oracle_or_analysis(store: RunStore) -> None:
    total = 0

    def entries(directory: str):
        nonlocal total
        for entry in iter_bounded_tree(
            store.path(directory),
            max_entries=_MAX_TRAVERSAL_ENTRIES,
            max_depth=_MAX_TRAVERSAL_DEPTH,
            max_relative_path_chars=_MAX_RELATIVE_PATH_CHARS,
            max_name_chars=_MAX_NAME_CHARS,
        ):
            total += 1
            if total > _MAX_TRAVERSAL_ENTRIES:
                raise BoundedTraversalError(limit_exceeded=True)
            yield entry

    try:
        for entry in entries(".stages"):
            relative = Path(entry.relative_path)
            if not entry.is_file or relative.parent != Path(".") or relative.suffix != ".json":
                continue
            name = relative.stem.casefold()
            if name in _FUTURE_STAGE_NAMES or any(
                name.startswith(prefix) for prefix in _FUTURE_STAGE_PREFIXES
            ):
                raise ValueError
        for directory in ("oracle", "analysis", "reports"):
            if any(entry.is_file for entry in entries(directory)):
                raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except BoundedTraversalError as error:
        raise _stage_error(
            "future confirmation artifact traversal failed validation"
            if not error.limit_exceeded
            else "future confirmation artifact traversal exceeded bounds"
        ) from None
    except Exception:
        raise _stage_error("future confirmation artifact already exists") from None


def _validate_producer_manifests(
    task4: StageManifest,
    randomization: StageManifest,
    task4_files: tuple[_FileSnapshot, ...],
    randomization_files: tuple[_FileSnapshot, ...],
) -> None:
    try:
        task4_paths = tuple(f"interventions/{name}" for name, _model in PROMPT_VARIANT_OUTPUTS)
        randomization_paths = tuple(
            f"interventions/{name}" for name, _model in RANDOMIZATION_OUTPUTS
        )
        if (
            task4.stage != "build-confirmation-variants"
            or tuple(task4.outputs) != task4_paths
            or tuple(task4.output_sha256.get(path) for path in task4_paths)
            != tuple(item.sha256 for item in task4_files)
            or randomization.stage != "randomize-confirmation"
            or tuple(randomization.outputs) != randomization_paths
            or tuple(randomization.output_sha256.get(path) for path in randomization_paths)
            != tuple(item.sha256 for item in randomization_files)
        ):
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation producer provenance failed validation") from None


def _validate_randomization_closure(
    manifest: RandomizationManifestRecord,
    assignments: tuple[AssignmentRecord, ...],
) -> None:
    try:
        if (
            not assignments
            or tuple(item.assignment_id for item in assignments) != manifest.assignment_ids
            or len({item.assignment_id for item in assignments}) != len(assignments)
            or manifest.assignments_sha256
            != canonical_sha256([item.model_dump(mode="json") for item in assignments])
            or any(
                item.randomization_plan_sha256 != manifest.randomization_plan_sha256
                or item.rng_version != manifest.rng_version
                for item in assignments
            )
        ):
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation assignment manifest closure failed validation") from None


def _validate_output_bundle(
    snapshot: _InputSnapshot,
    config: AppConfig,
    groups: Sequence[Sequence],
) -> ConfirmationGenerationStageResult:
    try:
        if len(groups) != 3:
            raise ValueError
        requests = tuple(
            GenerationRequestRecord.model_validate(item.model_dump(mode="python"))
            for item in groups[0]
        )
        executions = tuple(
            AssignmentExecutionRecord.model_validate(item.model_dump(mode="python"))
            for item in groups[1]
        )
        codes = tuple(
            CanonicalGeneratedCodeRecord.model_validate(item.model_dump(mode="python"))
            for item in groups[2]
        )
        expected_requests = tuple(
            plan_confirmation_requests(snapshot.assignments, snapshot.variants, config.generation)
        )
        if requests != expected_requests:
            raise ValueError
        request_by_assignment = {item.assignment_id: item for item in requests}
        execution_by_assignment = {item.assignment_id: item for item in executions}
        code_by_assignment = {item.assignment_id: item for item in codes}
        if (
            len(request_by_assignment) != len(requests)
            or len(execution_by_assignment) != len(executions)
            or len(code_by_assignment) != len(codes)
            or set(request_by_assignment) != set(execution_by_assignment)
        ):
            raise ValueError
        generated_assignments = {
            assignment_id
            for assignment_id, execution in execution_by_assignment.items()
            if execution.status is AssignmentExecutionStatus.GENERATED
        }
        if set(code_by_assignment) != generated_assignments:
            raise ValueError
        for assignment_id, execution in execution_by_assignment.items():
            request = request_by_assignment[assignment_id]
            code = code_by_assignment.get(assignment_id)
            if execution.request_id != request.request_id:
                raise ValueError
            if execution.status is AssignmentExecutionStatus.GENERATED:
                if (
                    code is None
                    or execution.code_id != code.code_id
                    or execution.code_sha256 != code.code_sha256
                ):
                    raise ValueError
                if code.generation_request != request or code.assignment_id != assignment_id:
                    raise ValueError
            elif code is not None:
                raise ValueError
        return ConfirmationGenerationStageResult(
            assignment_count=len(requests),
            generated_count=len(codes),
            terminal_no_code_count=len(requests) - len(codes),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation output bundle failed validation") from None


def run_confirmation_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
) -> ConfirmationGenerationStageResult:
    """Execute and publish every committed randomized assignment exactly once."""

    if (
        type(config) is not AppConfig
        or type(store) is not RunStore
        or store.config != config
        or not model_shape_is_intact(config)
    ):
        raise _stage_error("confirmation generation stage configuration failed validation")
    try:
        effective_config = AppConfig.model_validate(config.model_dump(mode="json"))
        effective_store = RunStore(effective_config)
        if effective_store.root != store.root:
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation stage configuration failed validation") from None

    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task4_manifest_path = effective_store.path(".stages", "build-confirmation-variants.json")
    randomization_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    randomization_manifest_path = effective_store.path(
        ".stages", "randomize-confirmation.json"
    )
    inputs = (
        *task4_paths,
        task4_manifest_path,
        *randomization_paths,
        randomization_manifest_path,
    )
    output_specs = tuple(
        JsonlOutputSpec(
            effective_store.path("generation", name),
            model,
            require_nonempty=index < 2,
            max_records=_MAX_RECORDS,
        )
        for index, (name, model) in enumerate(CONFIRMATION_GENERATION_OUTPUTS)
    )
    snapshot: _InputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        _guard_no_oracle_or_analysis(effective_store)
        payloads: list[bytes] = []
        files: list[_FileSnapshot] = []
        stack.callback(payloads.clear)
        stack.callback(files.clear)
        combined = 0
        for index, path in enumerate(inputs):
            allow_empty = index < len(task4_paths) and index >= 4
            payload, file = _read_snapshot(path, allow_empty=allow_empty)
            combined += len(payload)
            if combined > _MAX_COMBINED_INPUT_BYTES:
                raise _stage_error("confirmation generation input snapshot exceeded bounds")
            payloads.append(payload)
            files.append(file)
            payload = b""
        task4_manifest_index = len(task4_paths)
        randomization_index = task4_manifest_index + 1
        task4_manifest = _parse_manifest(payloads[task4_manifest_index])
        randomization_manifest = _parse_manifest(payloads[-1])
        variants = _parse_jsonl(payloads[8], PromptVariantRecord, allow_empty=False)
        randomization_records = _parse_jsonl(
            payloads[randomization_index], RandomizationManifestRecord, allow_empty=False
        )
        assignments = _parse_jsonl(
            payloads[randomization_index + 1], AssignmentRecord, allow_empty=False
        )
        if len(randomization_records) != 1:
            raise _stage_error("confirmation assignment manifest closure failed validation")
        _validate_producer_manifests(
            task4_manifest,
            randomization_manifest,
            tuple(files[: len(task4_paths)]),
            tuple(files[randomization_index : randomization_index + 2]),
        )
        _validate_randomization_closure(randomization_records[0], assignments)
        planned = plan_confirmation_requests(assignments, variants, effective_config.generation)
        prompt_bytes = sum(len(item.prompt.encode("utf-8")) for item in planned)
        if (
            len(planned) > _MAX_RECORDS
            or prompt_bytes > _MAX_REQUEST_PROMPT_BYTES
            or len(planned) * _MAX_CODE_BYTES_PER_REQUEST > _MAX_PROJECTED_CODE_BYTES
        ):
            raise _stage_error("confirmation generation resource limit exceeded")
        snapshot = _InputSnapshot(
            files=tuple(files),
            assignments=assignments,
            variants=variants,
            randomization_manifest=randomization_records[0],
        )
        payloads.clear()
        return tuple(item.sha256 for item in snapshot.files)

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        _guard_no_oracle_or_analysis(effective_store)
        expected: _FileSnapshot | None = None
        current: _FileSnapshot | None = None
        _payload = b""
        try:
            for expected in snapshot.files:
                try:
                    _payload, current = _read_snapshot(
                        expected.path, allow_empty=expected.identity[4] == 0
                    )
                    if current != expected:
                        raise _stage_error(
                            "confirmation generation inputs changed during execution"
                        )
                finally:
                    _payload = b""
                    current = None
                    expected = None
        finally:
            _payload = b""
            current = None
            expected = None

    def build():
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        requests = tuple(
            plan_confirmation_requests(
                snapshot.assignments,
                snapshot.variants,
                effective_config.generation,
            )
        )
        effective_provider: object = None
        result_requests: tuple[GenerationRequestRecord, ...] = ()
        try:
            effective_provider = _provider_from_frozen_config(effective_config)
            executions, codes = execute_confirmation_requests(requests, effective_provider)
            result_requests = requests
        finally:
            effective_provider = None
            requests = ()
        groups = (result_requests, executions, codes)
        _validate_output_bundle(snapshot, effective_config, groups)
        return groups

    def validate_staged_outputs(groups: tuple[tuple[object, ...], ...]) -> None:
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        _validate_output_bundle(snapshot, effective_config, groups)

    producer_outputs = {
        "build-confirmation-variants": task4_paths,
        "randomize-confirmation": randomization_paths,
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
            outputs=output_specs,
            force=force,
            build=build,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
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
        return _validate_output_bundle(snapshot, effective_config, groups)


__all__ = [
    "CONFIRMATION_GENERATION_OUTPUTS",
    "CONFIRMATION_PROVIDER_POLICY_VERSION",
    "ConfirmationGenerationStageResult",
    "run_confirmation_generation_stage",
]

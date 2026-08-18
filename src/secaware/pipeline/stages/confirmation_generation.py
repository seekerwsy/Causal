"""Atomic assignment-bound generation for the held-out confirmation experiment."""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import stat
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.confirmation import (
    CONFIRMATION_JSONL_MAX_LINE_CHARS,
    CONFIRMATION_JSONL_MAX_TOTAL_CHARS,
    CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
    execute_confirmation_requests,
)
from secaware.generation.openai_compatible_provider import (
    OpenAICompatibleGenerationResult,
    create_openai_compatible_provider,
    create_replay_openai_compatible_provider,
)
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
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    ProviderResultEnvelope,
    ProviderUsageRecord,
    provider_provenance_sha256,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256

_STAGE = "generate-confirmation"
CONFIRMATION_PROVIDER_POLICY_VERSION = "assignment-bound-generation-provider-v1"
CONFIRMATION_PROVIDER_FACTORY_VERSION = "frozen-app-config-provider-factory-v1"
CONFIRMATION_PROVIDER_RESPONSE_VERSION = "model-bound-code-result-v1"
_PROVIDER_RESULT_ENVELOPE_FACTORY = ProviderResultEnvelope.from_content
_MAX_INPUT_FILE_BYTES = 256_000_000
_MAX_COMBINED_INPUT_BYTES = 1_000_000_000
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
        "judge-functionality",
        "import-functional-outcomes",
        "estimate-confirmation-effects",
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


class _LockedMockProvider:
    def __init__(self, envelope_factory=_PROVIDER_RESULT_ENVELOPE_FACTORY) -> None:
        self._envelope_factory = envelope_factory

    def generate_many(self, requests: Sequence[GenerationRequestRecord]):
        envelope_factory = self._envelope_factory
        return tuple(
            (
                request.request_id,
                envelope_factory(
                    request_id=request.request_id,
                    model_id=request.model_id,
                    finish_reason="stop",
                    code=(
                        f"# secaware locked mock generation\n# assignment={request.assignment_id}\n"
                    ),
                    usage=ProviderUsageRecord(
                        prompt_tokens=0,
                        completion_tokens=0,
                        total_tokens=0,
                    ),
                    attempts=(
                        GenerationAttemptRecord(
                            schema_version="1.0",
                            request_id=request.request_id,
                            attempt=1,
                            outcome="success",
                            error_code=None,
                            retryable=False,
                            backoff_seconds=0.0,
                        ),
                    ),
                    provenance=GenerationProvenance(
                        producer="secaware-locked-mock",
                        producer_version="v1",
                    ),
                    provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
                    runtime_fingerprint_sha256=hashlib.sha256(
                        b"secaware-locked-mock-v1"
                    ).hexdigest(),
                ),
            )
            for request in reversed(tuple(requests))
        )


_ADAPTER_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)


def _clear_adapter_error(error: BaseException | None) -> None:
    if error is None:
        return
    try:
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
    except Exception:
        pass


def _close_adapter_iterator(iterator: object) -> BaseException | None:
    close: object = None
    try:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
    except BaseException as error:
        return error
    finally:
        iterator = None
        close = None
    return None


class _SingleRequestProviderAdapter:
    def __init__(
        self,
        provider: object,
        system_template: str,
        envelope_factory=_PROVIDER_RESULT_ENVELOPE_FACTORY,
        result_type=OpenAICompatibleGenerationResult,
    ) -> None:
        self._provider = provider
        self._system_template = system_template
        self._envelope_factory = envelope_factory
        self._result_type = result_type

    def generate_many(self, requests: Sequence[GenerationRequestRecord]):
        provider: object = None
        system_template = ""
        iterator: object = None
        request: GenerationRequestRecord | None = None
        second: object = None
        generate: object = None
        candidate: OpenAICompatibleGenerationResult | None = None
        envelope: ProviderResultEnvelope | None = None
        envelope_factory: object = None
        result_type: object = None
        result: tuple[tuple[str, ProviderResultEnvelope], ...] | None = None
        active: BaseException | None = None
        cleanup: BaseException | None = None
        sentinel = object()
        try:
            provider = self._provider
            system_template = self._system_template
            envelope_factory = self._envelope_factory
            result_type = self._result_type
            iterator = iter(requests)
            request = next(iterator)  # type: ignore[arg-type]
            second = next(iterator, sentinel)  # type: ignore[arg-type]
            if second is not sentinel or type(request) is not GenerationRequestRecord:
                raise TypeError
            generate = getattr(provider, "generate", None)
            if not callable(generate):
                raise TypeError
            candidate = generate(request, system_template)
            if type(candidate) is not result_type:
                raise TypeError
            if not callable(envelope_factory):
                raise TypeError
            envelope = envelope_factory(
                request_id=request.request_id,
                model_id=request.model_id,
                finish_reason=candidate.finish_reason,
                code=candidate.code,
                usage=candidate.usage,
                attempts=candidate.attempts,
                provenance=candidate.provenance,
                provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
                runtime_fingerprint_sha256=candidate.runtime_fingerprint_sha256,
            )
            result = ((request.request_id, envelope),)
        except BaseException as error:
            active = error
        finally:
            if iterator is not None:
                cleanup = _close_adapter_iterator(iterator)
            if active is not None or cleanup is not None:
                result = None
            self = None  # type: ignore[assignment]
            requests = ()
            provider = None
            system_template = ""
            iterator = None
            request = None
            second = None
            generate = None
            candidate = None
            envelope = None
            envelope_factory = None
            result_type = None
            sentinel = None
        if active is not None:
            if isinstance(active, _ADAPTER_FATAL):
                _clear_adapter_error(cleanup)
                cleanup = None
                raise active
            if isinstance(cleanup, _ADAPTER_FATAL):
                _clear_adapter_error(active)
                active = None
                raise cleanup
            _clear_adapter_error(cleanup)
            cleanup = None
            raise active
        if cleanup is not None:
            raise cleanup
        if result is None:  # pragma: no cover
            raise TypeError
        return result


def _provider_from_frozen_config(
    config: AppConfig,
    *,
    openai_factory=create_openai_compatible_provider,
    adapter_factory=_SingleRequestProviderAdapter,
    mock_factory=_LockedMockProvider,
    envelope_factory=_PROVIDER_RESULT_ENVELOPE_FACTORY,
    result_type=OpenAICompatibleGenerationResult,
    attempt_recorder: Callable[
        [str, int, dict[str, Any], object | None, BaseException | None], None
    ]
    | None = None,
) -> object:
    """Construct the only production provider path from the validated frozen config."""

    generation = config.generation
    if generation.provider == "mock":
        return mock_factory(envelope_factory=envelope_factory)
    if generation.provider == "openai_compatible":
        provider_config = generation.openai_compatible
        if provider_config is None:
            raise _stage_error("confirmation provider is unavailable", code=ErrorCode.CONFIG)
        provider = (
            openai_factory(provider_config)
            if attempt_recorder is None
            else openai_factory(provider_config, attempt_recorder=attempt_recorder)
        )
        return adapter_factory(
            provider,
            provider_config.system_template,
            envelope_factory,
            result_type,
        )
    raise _stage_error(
        "confirmation provider is unavailable",
        code=ErrorCode.EXTERNAL_INPUT_REQUIRED,
    )


def create_confirmation_provider(
    config: AppConfig,
    *,
    attempt_recorder: Callable[
        [str, int, dict[str, Any], object | None, BaseException | None], None
    ]
    | None = None,
) -> object:
    """Create the production confirmation provider from one validated config."""

    if type(config) is not AppConfig or not model_shape_is_intact(config):
        raise _stage_error("confirmation provider configuration failed validation")
    return _provider_from_frozen_config(config, attempt_recorder=attempt_recorder)


def create_confirmation_replay_provider(
    config: AppConfig,
    response: dict[str, Any],
) -> object:
    """Create the normal confirmation adapter over one persisted response, without I/O."""

    if type(config) is not AppConfig or not model_shape_is_intact(config):
        raise _stage_error("confirmation replay configuration failed validation")
    provider_config = config.generation.openai_compatible
    if config.generation.provider != "openai_compatible" or provider_config is None:
        raise _stage_error("confirmation replay provider is unavailable")
    provider = create_replay_openai_compatible_provider(provider_config, response)
    return _SingleRequestProviderAdapter(
        provider,
        provider_config.system_template,
        _PROVIDER_RESULT_ENVELOPE_FACTORY,
        OpenAICompatibleGenerationResult,
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
            if len(raw) >= CONFIRMATION_JSONL_MAX_LINE_CHARS:
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


def _guard_no_oracle_or_analysis(store: RunStore, *, traversal=iter_bounded_tree) -> None:
    total = 0

    def entries(directory: str):
        nonlocal total
        for entry in traversal(
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
        for entry in entries("oracle"):
            if entry.is_file and entry.relative_path != "observed_oracle.jsonl":
                raise ValueError
        for directory in ("analysis", "reports"):
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
        raise _stage_error(
            "confirmation generation producer provenance failed validation"
        ) from None


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
    *,
    planner=plan_confirmation_requests,
    provenance_hasher=provider_provenance_sha256,
) -> ConfirmationGenerationStageResult:
    requests: tuple[GenerationRequestRecord, ...] = ()
    executions: tuple[AssignmentExecutionRecord, ...] = ()
    codes: tuple[CanonicalGeneratedCodeRecord, ...] = ()
    expected_requests: tuple[GenerationRequestRecord, ...] = ()
    result: ConfirmationGenerationStageResult | None = None
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
            planner(snapshot.assignments, snapshot.variants, config.generation)
        )
        if requests != expected_requests:
            raise ValueError
        if tuple(item.assignment_id for item in executions) != tuple(
            sorted(item.assignment_id for item in executions)
        ) or tuple(item.assignment_id for item in codes) != tuple(
            sorted(item.assignment_id or "" for item in codes)
        ):
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
                if (
                    execution.provider_result_sha256 != code.provider_result_sha256
                    or execution.usage_sha256 != code.provider_usage_sha256
                    or execution.provider_runtime_sha256 != code.provider_runtime_sha256
                    or execution.provider_policy_sha256 != code.provider_policy_sha256
                    or execution.attempt_count != code.provider_attempt_count
                    or execution.provider_provenance_sha256
                    != provenance_hasher(code.generation_provenance)
                ):
                    raise ValueError
            elif code is not None:
                raise ValueError
        result = ConfirmationGenerationStageResult(
            assignment_count=len(requests),
            generated_count=len(codes),
            terminal_no_code_count=len(requests) - len(codes),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error("confirmation generation output bundle failed validation") from None
    finally:
        snapshot = None  # type: ignore[assignment]
        config = None  # type: ignore[assignment]
        groups = ()
        requests = ()
        executions = ()
        codes = ()
        expected_requests = ()
        request_by_assignment = {}
        execution_by_assignment = {}
        code_by_assignment = {}
        generated_assignments = set()
        request = None
        code = None
        execution = None
        planner = None
        provenance_hasher = None
    if result is None:  # pragma: no cover
        raise _stage_error("confirmation generation output bundle failed validation")
    return result


def validate_confirmation_generation_bundle(
    randomization_manifest: RandomizationManifestRecord,
    assignments: Sequence[AssignmentRecord],
    variants: Sequence[PromptVariantRecord],
    config: AppConfig,
    requests: Sequence[GenerationRequestRecord],
    executions: Sequence[AssignmentExecutionRecord],
    codes: Sequence[CanonicalGeneratedCodeRecord],
    *,
    planner=plan_confirmation_requests,
    provenance_hasher=provider_provenance_sha256,
) -> ConfirmationGenerationStageResult:
    """Authenticate the complete standalone-request/execution/code closure."""

    try:
        manifest = RandomizationManifestRecord.model_validate(
            randomization_manifest.model_dump(mode="json")
        )
        checked_assignments = tuple(
            AssignmentRecord.model_validate(item.model_dump(mode="json")) for item in assignments
        )
        checked_variants = tuple(
            PromptVariantRecord.model_validate(item.model_dump(mode="json")) for item in variants
        )
        _validate_randomization_closure(manifest, checked_assignments)
        snapshot = _InputSnapshot(
            files=(),
            assignments=checked_assignments,
            variants=checked_variants,
            randomization_manifest=manifest,
        )
        return _validate_output_bundle(
            snapshot,
            config,
            (requests, executions, codes),
            planner=planner,
            provenance_hasher=provenance_hasher,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _stage_error("confirmation generation bundle failed validation") from None
    finally:
        randomization_manifest = None  # type: ignore[assignment]
        assignments = ()
        variants = ()
        config = None  # type: ignore[assignment]
        requests = ()
        executions = ()
        codes = ()
        manifest = None
        checked_assignments = ()
        checked_variants = ()
        snapshot = None
        planner = None
        provenance_hasher = None


def _safe_fingerprint_value(value: object, *, depth: int = 0) -> object:
    if depth > 4:
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    if value is None or type(value) in {str, int, float, bool}:
        return value
    if type(value) is bytes:
        return {"bytes_sha256": hashlib.sha256(value).hexdigest()}
    if type(value) in {tuple, list}:
        return [_safe_fingerprint_value(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        return {
            str(key): _safe_fingerprint_value(item, depth=depth + 1)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if callable(value):
        return {
            "callable_module": str(getattr(value, "__module__", type(value).__module__)),
            "callable_qualname": str(getattr(value, "__qualname__", type(value).__qualname__)),
        }
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _source_sha256(value: object) -> str:
    try:
        source = inspect.getsource(value)
    except Exception:
        return "none"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _code_constant_payload(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    if inspect.iscode(value):
        return _stable_code_payload(value, depth=depth + 1)
    if value is None or type(value) in {str, int, float, bool}:
        return value
    if type(value) in {bytes, bytearray}:
        payload = bytes(value)
        return {"bytes_sha256": hashlib.sha256(payload).hexdigest(), "length": len(payload)}
    if type(value) is tuple:
        return [_code_constant_payload(item, depth=depth + 1) for item in value]
    if type(value) is frozenset:
        items = [_code_constant_payload(item, depth=depth + 1) for item in value]
        return sorted(items, key=canonical_sha256)
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _stable_code_payload(code, *, depth: int = 0) -> dict[str, object]:
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize,
        "flags": code.co_flags,
        "bytecode_sha256": hashlib.sha256(code.co_code).hexdigest(),
        "constants": [_code_constant_payload(item, depth=depth + 1) for item in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
        "name": code.co_name,
        "qualname": code.co_qualname,
        "firstlineno": code.co_firstlineno,
        "linetable_sha256": hashlib.sha256(code.co_linetable).hexdigest(),
        "exceptiontable_sha256": hashlib.sha256(code.co_exceptiontable).hexdigest(),
    }


def _code_sha256(value: object) -> str:
    code = getattr(value, "__code__", None)
    if code is None:
        call = getattr(value, "__call__", None)
        code = getattr(call, "__code__", None)
    if code is None:
        return "none"
    return canonical_sha256(_stable_code_payload(code))


def _stable_class_closure_value(value: object) -> object:
    if callable(value):
        return {
            "callable_module": str(getattr(value, "__module__", type(value).__module__)),
            "callable_qualname": str(getattr(value, "__qualname__", type(value).__qualname__)),
        }
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _callable_behavior_payload(
    value: object,
    *,
    class_member: bool = False,
) -> dict[str, object]:
    partial_payload: object = None
    target = value
    if isinstance(value, functools.partial):
        target = value.func
        partial_payload = {
            "args": _safe_fingerprint_value(value.args),
            "keywords": _safe_fingerprint_value(value.keywords or {}),
            "func": _safe_fingerprint_value(value.func),
        }
    defaults_payload = {
        "defaults": _safe_fingerprint_value(getattr(target, "__defaults__", None)),
        "kwdefaults": _safe_fingerprint_value(getattr(target, "__kwdefaults__", None)),
    }
    closure_payload: list[object] = []
    for cell in getattr(target, "__closure__", None) or ():
        try:
            contents = cell.cell_contents
        except ValueError:
            closure_payload.append({"empty": True})
        else:
            closure_payload.append(
                _stable_class_closure_value(contents)
                if class_member
                else _safe_fingerprint_value(contents)
            )
            contents = None
    return {
        "kind": "partial" if isinstance(value, functools.partial) else type(value).__name__,
        "module": str(getattr(value, "__module__", type(value).__module__)),
        "qualname": str(getattr(value, "__qualname__", type(value).__qualname__)),
        "source_sha256": _source_sha256(target),
        "code_sha256": _code_sha256(target),
        "defaults": defaults_payload,
        "closure": closure_payload,
        "partial": partial_payload,
    }


def _class_member_payload(
    name: str,
    value: object,
    *,
    active: tuple[type, ...],
) -> dict[str, object] | None:
    if isinstance(value, staticmethod):
        return {
            "name": name,
            "kind": "staticmethod",
            "callable": _callable_behavior_payload(value.__func__, class_member=True),
        }
    if isinstance(value, classmethod):
        return {
            "name": name,
            "kind": "classmethod",
            "callable": _callable_behavior_payload(value.__func__, class_member=True),
        }
    if isinstance(value, property):
        return {
            "name": name,
            "kind": "property",
            "accessors": {
                accessor_name: (
                    _callable_behavior_payload(accessor, class_member=True)
                    if accessor is not None
                    else None
                )
                for accessor_name, accessor in (
                    ("get", value.fget),
                    ("set", value.fset),
                    ("delete", value.fdel),
                )
            },
        }
    if inspect.isclass(value):
        return {
            "name": name,
            "kind": "class",
            "class": _stable_class_payload(value, active=active),
        }
    if inspect.isroutine(value) or callable(value):
        return {
            "name": name,
            "kind": "callable",
            "callable": _callable_behavior_payload(value, class_member=True),
        }
    return None


def _stable_class_payload(
    value: type,
    *,
    active: tuple[type, ...] = (),
) -> dict[str, object]:
    identity = {"module": value.__module__, "qualname": value.__qualname__}
    if value in active:
        return {**identity, "recursive": True}
    members: list[dict[str, object]] = []
    next_active = (*active, value)
    for name, member in sorted(vars(value).items()):
        payload = _class_member_payload(name, member, active=next_active)
        if payload is not None:
            members.append(payload)
    return {
        **identity,
        "source_sha256": _source_sha256(value),
        "members": members,
    }


def _runtime_callable_descriptor(value: object) -> dict[str, str]:
    payload = _callable_behavior_payload(value)
    callable_class = value if inspect.isclass(value) else type(value)
    if inspect.isclass(value) or (callable(value) and not inspect.isroutine(value)):
        class_payload = _stable_class_payload(callable_class)
    else:
        class_payload = {
            "module": callable_class.__module__,
            "qualname": callable_class.__qualname__,
            "source_sha256": _source_sha256(callable_class),
            "call_code_sha256": _code_sha256(getattr(callable_class, "__call__", None)),
        }
    descriptor = {
        "kind": str(payload["kind"]),
        "module": str(payload["module"]),
        "qualname": str(payload["qualname"]),
        "source_sha256": str(payload["source_sha256"]),
        "code_sha256": str(payload["code_sha256"]),
        "defaults_sha256": canonical_sha256(payload["defaults"]),
        "closure_sha256": canonical_sha256(payload["closure"]),
        "partial_sha256": canonical_sha256(payload["partial"]),
        "callable_class_sha256": canonical_sha256(class_payload),
    }
    descriptor["fingerprint_sha256"] = canonical_sha256(descriptor)
    return descriptor


def _confirmation_runtime_callables() -> dict[str, object]:
    return {
        "input.guard_no_oracle_or_analysis": _guard_no_oracle_or_analysis,
        "input.parse_jsonl": _parse_jsonl,
        "input.parse_manifest": _parse_manifest,
        "input.read_snapshot": _read_snapshot,
        "input.bounded_tree": iter_bounded_tree,
        "input.model_shape_is_intact": model_shape_is_intact,
        "input.run_store_factory": RunStore,
        "input.validate_producer_manifests": _validate_producer_manifests,
        "input.validate_randomization_closure": _validate_randomization_closure,
        "planning.plan_confirmation_requests": plan_confirmation_requests,
        "provider.adapter_factory": _SingleRequestProviderAdapter,
        "provider.create_openai_compatible_provider": create_openai_compatible_provider,
        "provider.envelope_factory": _PROVIDER_RESULT_ENVELOPE_FACTORY,
        "provider.from_frozen_config": _provider_from_frozen_config,
        "provider.mock_factory": _LockedMockProvider,
        "provider.result_type": OpenAICompatibleGenerationResult,
        "execution.execute_confirmation_requests": execute_confirmation_requests,
        "validation.output_bundle": _validate_output_bundle,
        "validation.public_output_bundle": validate_confirmation_generation_bundle,
        "validation.provider_provenance_sha256": provider_provenance_sha256,
        "transaction.execute_jsonl_stage_transaction": execute_jsonl_stage_transaction,
        "transaction.jsonl_output_spec": JsonlOutputSpec,
        "transaction.read_jsonl": read_jsonl,
    }


def confirmation_runtime_callable_contract() -> dict[str, dict[str, str]]:
    return {
        name: _runtime_callable_descriptor(value)
        for name, value in sorted(_confirmation_runtime_callables().items())
    }


def confirmation_output_policy_contract() -> dict[str, int | str]:
    return {
        "jsonl_max_line_chars": CONFIRMATION_JSONL_MAX_LINE_CHARS,
        "jsonl_max_total_chars": CONFIRMATION_JSONL_MAX_TOTAL_CHARS,
        "canonical_code_projection_version": "empty-skeleton-v1",
        "execution_record_overhead_chars": 4 * 1024,
        "json_string_max_expansion": 6,
        "provider_provenance_max_bytes": 4_096,
    }


def run_confirmation_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
) -> ConfirmationGenerationStageResult:
    """Execute and publish every committed randomized assignment exactly once."""

    runtime_callables = _confirmation_runtime_callables()
    runtime_contract = {
        name: _runtime_callable_descriptor(value)
        for name, value in sorted(runtime_callables.items())
    }

    def verify_runtime_bundle() -> None:
        current = _confirmation_runtime_callables()
        if (
            tuple(sorted(current)) != tuple(sorted(runtime_callables))
            or any(current[name] is not value for name, value in runtime_callables.items())
            or {
                name: _runtime_callable_descriptor(value) for name, value in sorted(current.items())
            }
            != runtime_contract
        ):
            raise _stage_error("confirmation runtime callable bundle changed during execution")

    if (
        type(config) is not AppConfig
        or type(store) is not RunStore
        or store.config != config
        or not runtime_callables["input.model_shape_is_intact"](config)
    ):
        raise _stage_error("confirmation generation stage configuration failed validation")
    try:
        effective_config = AppConfig.model_validate(config.model_dump(mode="json"))
        effective_store = runtime_callables["input.run_store_factory"](effective_config)
        if effective_store.root != store.root:
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _stage_error(
            "confirmation generation stage configuration failed validation"
        ) from None
    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task4_manifest_path = effective_store.path(".stages", "build-confirmation-variants.json")
    randomization_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    randomization_manifest_path = effective_store.path(".stages", "randomize-confirmation.json")
    inputs = (
        *task4_paths,
        task4_manifest_path,
        *randomization_paths,
        randomization_manifest_path,
    )
    output_spec_factory = runtime_callables["transaction.jsonl_output_spec"]
    output_specs = tuple(
        output_spec_factory(
            effective_store.path("generation", name),
            model,
            require_nonempty=index < 2,
            max_records=_MAX_RECORDS,
            max_line_chars=CONFIRMATION_JSONL_MAX_LINE_CHARS,
            max_total_chars=CONFIRMATION_JSONL_MAX_TOTAL_CHARS,
        )
        for index, (name, model) in enumerate(CONFIRMATION_GENERATION_OUTPUTS)
    )
    snapshot: _InputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        verify_runtime_bundle()
        if snapshot is not None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        runtime_callables["input.guard_no_oracle_or_analysis"](
            effective_store, traversal=runtime_callables["input.bounded_tree"]
        )
        payloads: list[bytes] = []
        files: list[_FileSnapshot] = []
        stack.callback(payloads.clear)
        stack.callback(files.clear)
        combined = 0
        for index, path in enumerate(inputs):
            allow_empty = index < len(task4_paths) and index >= 4
            payload, file = runtime_callables["input.read_snapshot"](path, allow_empty=allow_empty)
            combined += len(payload)
            if combined > _MAX_COMBINED_INPUT_BYTES:
                raise _stage_error("confirmation generation input snapshot exceeded bounds")
            payloads.append(payload)
            files.append(file)
            payload = b""
        task4_manifest_index = len(task4_paths)
        randomization_index = task4_manifest_index + 1
        task4_manifest = runtime_callables["input.parse_manifest"](payloads[task4_manifest_index])
        randomization_manifest = runtime_callables["input.parse_manifest"](payloads[-1])
        variants = runtime_callables["input.parse_jsonl"](
            payloads[8], PromptVariantRecord, allow_empty=False
        )
        randomization_records = runtime_callables["input.parse_jsonl"](
            payloads[randomization_index], RandomizationManifestRecord, allow_empty=False
        )
        assignments = runtime_callables["input.parse_jsonl"](
            payloads[randomization_index + 1], AssignmentRecord, allow_empty=False
        )
        if len(randomization_records) != 1:
            raise _stage_error("confirmation assignment manifest closure failed validation")
        runtime_callables["input.validate_producer_manifests"](
            task4_manifest,
            randomization_manifest,
            tuple(files[: len(task4_paths)]),
            tuple(files[randomization_index : randomization_index + 2]),
        )
        runtime_callables["input.validate_randomization_closure"](
            randomization_records[0], assignments
        )
        planned = runtime_callables["planning.plan_confirmation_requests"](
            assignments, variants, effective_config.generation
        )
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
        verify_runtime_bundle()
        payloads.clear()
        return tuple(item.sha256 for item in snapshot.files)

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        verify_runtime_bundle()
        runtime_callables["input.guard_no_oracle_or_analysis"](
            effective_store, traversal=runtime_callables["input.bounded_tree"]
        )
        expected: _FileSnapshot | None = None
        current: _FileSnapshot | None = None
        _payload = b""
        try:
            for expected in snapshot.files:
                try:
                    _payload, current = runtime_callables["input.read_snapshot"](
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
        verify_runtime_bundle()
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        requests = tuple(
            runtime_callables["planning.plan_confirmation_requests"](
                snapshot.assignments,
                snapshot.variants,
                effective_config.generation,
            )
        )
        effective_provider: object = None
        result_requests: tuple[GenerationRequestRecord, ...] = ()
        try:
            verify_runtime_bundle()
            effective_provider = runtime_callables["provider.from_frozen_config"](
                effective_config,
                openai_factory=runtime_callables["provider.create_openai_compatible_provider"],
                adapter_factory=runtime_callables["provider.adapter_factory"],
                mock_factory=runtime_callables["provider.mock_factory"],
                envelope_factory=runtime_callables["provider.envelope_factory"],
                result_type=runtime_callables["provider.result_type"],
            )
            verify_runtime_bundle()
            executions, codes = runtime_callables["execution.execute_confirmation_requests"](
                requests,
                effective_provider,
                effective_config.generation,
            )
            verify_runtime_bundle()
            result_requests = requests
        finally:
            effective_provider = None
            requests = ()
        groups = (result_requests, executions, codes)
        runtime_callables["validation.public_output_bundle"](
            snapshot.randomization_manifest,
            snapshot.assignments,
            snapshot.variants,
            effective_config,
            *groups,
            planner=runtime_callables["planning.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )
        return groups

    def validate_staged_outputs(groups: tuple[tuple[object, ...], ...]) -> None:
        verify_runtime_bundle()
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        runtime_callables["validation.public_output_bundle"](
            snapshot.randomization_manifest,
            snapshot.assignments,
            snapshot.variants,
            effective_config,
            *groups,
            planner=runtime_callables["planning.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )

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
        verify_runtime_bundle()
        runtime_callables["transaction.execute_jsonl_stage_transaction"](
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
        verify_runtime_bundle()
        if snapshot is None:
            raise _stage_error("confirmation generation input snapshot failed validation")
        groups = tuple(
            tuple(
                runtime_callables["transaction.read_jsonl"](
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
        verify_runtime_bundle()
        return runtime_callables["validation.public_output_bundle"](
            snapshot.randomization_manifest,
            snapshot.assignments,
            snapshot.variants,
            effective_config,
            *groups,
            planner=runtime_callables["planning.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )


__all__ = [
    "CONFIRMATION_GENERATION_OUTPUTS",
    "CONFIRMATION_PROVIDER_POLICY_VERSION",
    "ConfirmationGenerationStageResult",
    "create_confirmation_provider",
    "create_confirmation_replay_provider",
    "run_confirmation_generation_stage",
    "validate_confirmation_generation_bundle",
]

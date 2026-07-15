"""Independent, assignment-bound Oracle publication for randomized confirmation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import inspect
import os
from pathlib import Path
import stat
from typing import TypeVar

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.oracle.aggregator import AnalyzerRunner, run_oracle_batch
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.pipeline.bounded_traversal import iter_bounded_tree
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.jsonl_stage import (
    JsonlOutputSpec,
    execute_jsonl_stage_transaction,
)
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.preflight import run_oracle_preflight
from secaware.pipeline.stages.confirmation_generation import CONFIRMATION_GENERATION_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.generation import (
    GenerationRequestRecord,
    provider_provenance_sha256,
)
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "run-oracle-confirmation"
_OUTPUT_NAME = "confirmation_oracle.jsonl"
_MAX_RECORDS = 100_000
_MAX_INPUT_FILE_BYTES = 256 * 1024 * 1024
_MAX_COMBINED_INPUT_BYTES = 768 * 1024 * 1024
_MAX_LINE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_CODE_BYTES = 1_000_000_000
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_FUTURE_DIRS = frozenset({"analysis", "effects", "reports", "report", "jci", "rfci"})
_FUTURE_STAGE_PREFIXES = (
    "analyze-",
    "estimate-",
    "effects-",
    "jci-",
    "report-",
    "reporting-",
    "rfci-",
)
_PUBLIC_MESSAGES = {
    ErrorCode.CONFIG: "confirmation Oracle configuration is invalid",
    ErrorCode.CONTRACT: "confirmation Oracle artifact validation failed",
    ErrorCode.ANALYZER_MISSING: "analyzer executable is unavailable",
    ErrorCode.ANALYZER_FAILED: "analyzer execution failed",
    ErrorCode.ANALYZER_INVALID_OUTPUT: "analyzer output is invalid",
    ErrorCode.POLICY_MISMATCH: "analyzer policy or version does not match",
    ErrorCode.MANIFEST_CONFLICT: "confirmation Oracle trust verification failed",
}


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: Path
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _InputSnapshot:
    files: tuple[_FileSnapshot, ...]
    targets: tuple[TargetSpecRecord, ...]
    target_instances: tuple[TargetInstanceRecord, ...]
    protocols: tuple[ConfirmationProtocolRecord, ...]
    protocol_instances: tuple[ConfirmationProtocolInstanceRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    assignments: tuple[AssignmentRecord, ...]
    requests: tuple[GenerationRequestRecord, ...]
    executions: tuple[AssignmentExecutionRecord, ...]
    codes: tuple[CanonicalGeneratedCodeRecord, ...]


@dataclass(frozen=True, slots=True)
class ConfirmationOracleStageResult:
    assignment_count: int
    generated_count: int
    terminal_no_code_count: int
    oracle_count: int


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _public_error(code: ErrorCode) -> SecAwareError:
    if code not in _PUBLIC_MESSAGES:
        code = ErrorCode.ANALYZER_FAILED
    return _error(_PUBLIC_MESSAGES[code], code=code)


def _clear_exception(error: BaseException | None) -> None:
    if error is None:
        return
    try:
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
    except BaseException:
        pass


def _trusted_records(
    values: Iterable[_ModelT], model: type[_ModelT], *, allow_empty: bool
) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    result: tuple[_ModelT, ...] = ()
    value: object = None
    try:
        if isinstance(values, (str, bytes, Mapping)):
            raise TypeError
        for index, value in enumerate(values):
            if index >= _MAX_RECORDS:
                raise ValueError
            if type(value) is not model or not model_shape_is_intact(value):
                raise TypeError
            records.append(
                model.model_validate(
                    value.model_dump(mode="python", round_trip=True, warnings=False)
                )
            )
            value = None
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle relation failed validation") from None
    finally:
        values = ()
        model = BaseModel  # type: ignore[assignment]
        value = None
        records.clear()
    return result


def validate_confirmation_oracle_coverage(
    assignments: Iterable[AssignmentRecord],
    executions: Iterable[AssignmentExecutionRecord],
    codes: Iterable[CanonicalGeneratedCodeRecord],
    oracles: Iterable[OracleRecord],
) -> ConfirmationOracleStageResult:
    """Require one Oracle per GENERATED assignment and none for terminal-no-code."""

    trusted_assignments: tuple[AssignmentRecord, ...] = ()
    trusted_executions: tuple[AssignmentExecutionRecord, ...] = ()
    trusted_codes: tuple[CanonicalGeneratedCodeRecord, ...] = ()
    trusted_oracles: tuple[OracleRecord, ...] = ()
    result: ConfirmationOracleStageResult | None = None
    try:
        trusted_assignments = _trusted_records(assignments, AssignmentRecord, allow_empty=False)
        trusted_executions = _trusted_records(
            executions, AssignmentExecutionRecord, allow_empty=False
        )
        trusted_codes = _trusted_records(
            codes, CanonicalGeneratedCodeRecord, allow_empty=True
        )
        trusted_oracles = _trusted_records(oracles, OracleRecord, allow_empty=True)
        if tuple(item.assignment_id for item in trusted_executions) != tuple(
            sorted(item.assignment_id for item in trusted_executions)
        ) or tuple(item.assignment_id or "" for item in trusted_codes) != tuple(
            sorted(item.assignment_id or "" for item in trusted_codes)
        ) or tuple(item.request_id for item in trusted_oracles) != tuple(
            sorted(item.request_id for item in trusted_oracles)
        ):
            raise ValueError

        assignment_by_id = {item.assignment_id: item for item in trusted_assignments}
        execution_by_id = {item.assignment_id: item for item in trusted_executions}
        code_by_id = {item.assignment_id: item for item in trusted_codes}
        oracle_by_request = {item.request_id: item for item in trusted_oracles}
        if (
            len(assignment_by_id) != len(trusted_assignments)
            or len(execution_by_id) != len(trusted_executions)
            or len(code_by_id) != len(trusted_codes)
            or len(oracle_by_request) != len(trusted_oracles)
            or set(assignment_by_id) != set(execution_by_id)
        ):
            raise ValueError
        generated = {
            assignment_id
            for assignment_id, execution in execution_by_id.items()
            if execution.status is AssignmentExecutionStatus.GENERATED
        }
        if set(code_by_id) != generated:
            raise ValueError
        if set(oracle_by_request) != {code.request_id for code in trusted_codes}:
            raise ValueError

        for assignment_id in sorted(assignment_by_id):
            assignment = assignment_by_id[assignment_id]
            execution = execution_by_id[assignment_id]
            code = code_by_id.get(assignment_id)
            if code is None:
                if execution.status is not AssignmentExecutionStatus.TERMINAL_NO_CODE:
                    raise ValueError
                continue
            unit = assignment.experimental_unit
            request = code.generation_request
            oracle = oracle_by_request.get(code.request_id)
            if oracle is None or execution.status is not AssignmentExecutionStatus.GENERATED:
                raise ValueError
            expected_coordinates = (
                (code.condition, "confirm_arm"),
                (code.assignment_id, assignment.assignment_id),
                (code.hypothesis_id, unit.hypothesis_id),
                (code.target_spec_id, assignment.target_spec_id),
                (code.target_instance_id, assignment.target_instance_id),
                (code.arm_protocol_id, assignment.arm_protocol_id),
                (code.protocol_instance_id, assignment.protocol_instance_id),
                (code.variant_id, assignment.variant_id),
                (code.arm_role, assignment.arm_role),
                (code.model_id, unit.model_id),
                (code.seed_id, assignment.seed_id),
                (execution.request_id, code.request_id),
                (execution.code_id, code.code_id),
                (execution.code_sha256, code.code_sha256),
                (execution.provider_result_sha256, code.provider_result_sha256),
                (execution.usage_sha256, code.provider_usage_sha256),
                (execution.provider_runtime_sha256, code.provider_runtime_sha256),
                (execution.provider_policy_sha256, code.provider_policy_sha256),
                (execution.attempt_count, code.provider_attempt_count),
                (
                    execution.provider_provenance_sha256,
                    provider_provenance_sha256(code.generation_provenance),
                ),
                (request.assignment_id, assignment.assignment_id),
                (request.request_id, code.request_id),
            )
            oracle_coordinates = (
                (oracle.condition, "confirm_arm"),
                (oracle.request_id, code.request_id),
                (oracle.code_id, code.code_id),
                (oracle.code_sha256, code.code_sha256),
                (oracle.prompt_id, code.prompt_id),
                (oracle.hypothesis_id, code.hypothesis_id),
                (oracle.assignment_id, code.assignment_id),
                (oracle.target_spec_id, code.target_spec_id),
                (oracle.target_instance_id, code.target_instance_id),
                (oracle.arm_protocol_id, code.arm_protocol_id),
                (oracle.protocol_instance_id, code.protocol_instance_id),
                (oracle.variant_id, code.variant_id),
                (oracle.arm_role, code.arm_role),
                (oracle.model_id, code.model_id),
                (oracle.seed_id, code.seed_id),
            )
            if any(actual != expected for actual, expected in expected_coordinates):
                raise ValueError
            if any(actual != expected for actual, expected in oracle_coordinates):
                raise ValueError
        result = ConfirmationOracleStageResult(
            assignment_count=len(trusted_assignments),
            generated_count=len(trusted_codes),
            terminal_no_code_count=len(trusted_assignments) - len(trusted_codes),
            oracle_count=len(trusted_oracles),
        )
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation Oracle relation failed validation") from None
    finally:
        assignments = ()
        executions = ()
        codes = ()
        oracles = ()
        trusted_assignments = ()
        trusted_executions = ()
        trusted_codes = ()
        trusted_oracles = ()
        assignment_by_id = {}
        execution_by_id = {}
        code_by_id = {}
        oracle_by_request = {}
        generated = set()
        assignment = None
        execution = None
        code = None
        request = None
        oracle = None
    if result is None:  # pragma: no cover
        raise _error("confirmation Oracle relation failed validation")
    return result


def _validate_generated_code_coverage(
    assignments: Iterable[AssignmentRecord],
    executions: Iterable[AssignmentExecutionRecord],
    codes: Iterable[CanonicalGeneratedCodeRecord],
) -> None:
    """Reject generated-subset drift before either analyzer is invoked."""

    trusted_assignments: tuple[AssignmentRecord, ...] = ()
    trusted_executions: tuple[AssignmentExecutionRecord, ...] = ()
    trusted_codes: tuple[CanonicalGeneratedCodeRecord, ...] = ()
    try:
        trusted_assignments = _trusted_records(
            assignments, AssignmentRecord, allow_empty=False
        )
        trusted_executions = _trusted_records(
            executions, AssignmentExecutionRecord, allow_empty=False
        )
        trusted_codes = _trusted_records(
            codes, CanonicalGeneratedCodeRecord, allow_empty=True
        )
        if tuple(item.assignment_id for item in trusted_executions) != tuple(
            sorted(item.assignment_id for item in trusted_executions)
        ) or tuple(item.assignment_id or "" for item in trusted_codes) != tuple(
            sorted(item.assignment_id or "" for item in trusted_codes)
        ):
            raise ValueError
        assignment_by_id = {item.assignment_id: item for item in trusted_assignments}
        execution_by_id = {item.assignment_id: item for item in trusted_executions}
        code_by_id = {item.assignment_id: item for item in trusted_codes}
        if (
            len(assignment_by_id) != len(trusted_assignments)
            or len(execution_by_id) != len(trusted_executions)
            or len(code_by_id) != len(trusted_codes)
            or set(assignment_by_id) != set(execution_by_id)
        ):
            raise ValueError
        generated = {
            assignment_id
            for assignment_id, execution in execution_by_id.items()
            if execution.status is AssignmentExecutionStatus.GENERATED
        }
        if set(code_by_id) != generated:
            raise ValueError
        for assignment_id in sorted(assignment_by_id):
            assignment = assignment_by_id[assignment_id]
            execution = execution_by_id[assignment_id]
            code = code_by_id.get(assignment_id)
            if code is None:
                if execution.status is not AssignmentExecutionStatus.TERMINAL_NO_CODE:
                    raise ValueError
                continue
            unit = assignment.experimental_unit
            request = code.generation_request
            expected_coordinates = (
                (code.condition, "confirm_arm"),
                (code.assignment_id, assignment.assignment_id),
                (code.hypothesis_id, unit.hypothesis_id),
                (code.target_spec_id, assignment.target_spec_id),
                (code.target_instance_id, assignment.target_instance_id),
                (code.arm_protocol_id, assignment.arm_protocol_id),
                (code.protocol_instance_id, assignment.protocol_instance_id),
                (code.variant_id, assignment.variant_id),
                (code.arm_role, assignment.arm_role),
                (code.model_id, unit.model_id),
                (code.seed_id, assignment.seed_id),
                (execution.request_id, code.request_id),
                (execution.code_id, code.code_id),
                (execution.code_sha256, code.code_sha256),
                (execution.provider_result_sha256, code.provider_result_sha256),
                (execution.usage_sha256, code.provider_usage_sha256),
                (execution.provider_runtime_sha256, code.provider_runtime_sha256),
                (execution.provider_policy_sha256, code.provider_policy_sha256),
                (execution.attempt_count, code.provider_attempt_count),
                (
                    execution.provider_provenance_sha256,
                    provider_provenance_sha256(code.generation_provenance),
                ),
                (request.assignment_id, assignment.assignment_id),
                (request.request_id, code.request_id),
            )
            if any(actual != expected for actual, expected in expected_coordinates):
                raise ValueError
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation Oracle generated coverage failed validation") from None
    finally:
        assignments = ()
        executions = ()
        codes = ()
        trusted_assignments = ()
        trusted_executions = ()
        trusted_codes = ()
        assignment_by_id = {}
        execution_by_id = {}
        code_by_id = {}
        generated = set()
        assignment = None
        execution = None
        code = None
        unit = None
        request = None
        expected_coordinates = ()


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
        return bytes(buffer), _FileSnapshot(path, digest.hexdigest(), _identity(after_path))
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle input snapshot failed validation") from None
    finally:
        buffer.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parse_jsonl(payload: bytes, model: type[_ModelT], *, allow_empty: bool) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    result: tuple[_ModelT, ...] = ()
    line = b""
    try:
        if len(payload) > _MAX_INPUT_FILE_BYTES:
            raise ValueError
        for line in payload.splitlines():
            if not line.strip():
                continue
            if len(line) > _MAX_LINE_BYTES:
                raise ValueError
            records.append(model.model_validate(load_strict_json_bytes(line)))
            if len(records) > _MAX_RECORDS:
                raise ValueError
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle input artifact failed validation") from None
    finally:
        payload = b""
        line = b""
        records.clear()
    return result


def _parse_manifest(payload: bytes, expected_stage: str) -> StageManifest:
    try:
        manifest = StageManifest.model_validate(load_strict_json_bytes(payload))
        if manifest.stage != expected_stage:
            raise ValueError
        return manifest
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle producer manifest failed validation") from None
    finally:
        payload = b""
        expected_stage = ""


def _guard_no_future_artifacts(store: RunStore) -> None:
    try:
        for entry in iter_bounded_tree(
            store.root,
            max_entries=100_000,
            max_depth=16,
            max_relative_path_chars=8_192,
            max_name_chars=1_024,
        ):
            parts = entry.relative_path.replace("\\", "/").split("/")
            if entry.is_file and parts[0] in _FUTURE_DIRS:
                raise ValueError
            if len(parts) == 2 and parts[0] == ".stages" and parts[1].endswith(".json"):
                stage_name = parts[1][:-5]
                if stage_name.startswith(_FUTURE_STAGE_PREFIXES):
                    raise ValueError
    except _FATAL:
        raise
    except Exception:
        raise _error("future analysis artifact exists before confirmation Oracle") from None


def _validate_task4_provenance(snapshot: _InputSnapshot) -> None:
    try:
        target_by_id = {item.target_spec_id: item for item in snapshot.targets}
        instance_by_id = {item.target_instance_id: item for item in snapshot.target_instances}
        protocol_by_id = {item.arm_protocol_id: item for item in snapshot.protocols}
        protocol_instance_by_id = {
            item.protocol_instance_id: item for item in snapshot.protocol_instances
        }
        variant_by_id = {item.variant_id: item for item in snapshot.variants}
        if any(
            len(mapping) != size
            for mapping, size in (
                (target_by_id, len(snapshot.targets)),
                (instance_by_id, len(snapshot.target_instances)),
                (protocol_by_id, len(snapshot.protocols)),
                (protocol_instance_by_id, len(snapshot.protocol_instances)),
                (variant_by_id, len(snapshot.variants)),
            )
        ):
            raise ValueError
        for assignment in snapshot.assignments:
            unit = assignment.experimental_unit
            target = target_by_id.get(assignment.target_spec_id)
            instance = instance_by_id.get(assignment.target_instance_id)
            protocol = protocol_by_id.get(assignment.arm_protocol_id)
            protocol_instance = protocol_instance_by_id.get(assignment.protocol_instance_id)
            variant = variant_by_id.get(assignment.variant_id)
            if any(item is None for item in (target, instance, protocol, protocol_instance, variant)):
                raise ValueError
            assert target is not None and instance is not None and protocol is not None
            assert protocol_instance is not None and variant is not None
            if (
                target.hypothesis_id != unit.hypothesis_id
                or instance.target_spec_id != target.target_spec_id
                or instance.task_id != unit.task_id
                or protocol.hypothesis_id != unit.hypothesis_id
                or protocol.target_spec_id != target.target_spec_id
                or protocol_instance.arm_protocol_id != protocol.arm_protocol_id
                or protocol_instance.target_instance_id != instance.target_instance_id
                or protocol_instance.task_id != unit.task_id
                or variant.task_id != unit.task_id
                or variant.target_spec_id != target.target_spec_id
                or variant.target_instance_id != instance.target_instance_id
                or variant.arm_protocol_id != protocol.arm_protocol_id
                or variant.protocol_instance_id != protocol_instance.protocol_instance_id
                or variant.arm_role is not assignment.arm_role
            ):
                raise ValueError
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle task provenance failed validation") from None
    finally:
        snapshot = None  # type: ignore[assignment]
        target_by_id = {}
        instance_by_id = {}
        protocol_by_id = {}
        protocol_instance_by_id = {}
        variant_by_id = {}
        assignment = None
        unit = None
        target = None
        instance = None
        protocol = None
        protocol_instance = None
        variant = None


def _validate_request_and_variant_coverage(snapshot: _InputSnapshot) -> None:
    try:
        assignment_by_id = {item.assignment_id: item for item in snapshot.assignments}
        request_by_id = {item.assignment_id: item for item in snapshot.requests}
        variant_by_id = {item.variant_id: item for item in snapshot.variants}
        if (
            len(assignment_by_id) != len(snapshot.assignments)
            or len(request_by_id) != len(snapshot.requests)
            or set(assignment_by_id) != set(request_by_id)
        ):
            raise ValueError
        for assignment_id, assignment in assignment_by_id.items():
            request = request_by_id[assignment_id]
            variant = variant_by_id.get(assignment.variant_id)
            if variant is None or (
                request.condition != "confirm_arm"
                or request.assignment_id != assignment.assignment_id
                or request.hypothesis_id != assignment.experimental_unit.hypothesis_id
                or request.target_spec_id != assignment.target_spec_id
                or request.target_instance_id != assignment.target_instance_id
                or request.arm_protocol_id != assignment.arm_protocol_id
                or request.protocol_instance_id != assignment.protocol_instance_id
                or request.variant_id != assignment.variant_id
                or request.arm_role is not assignment.arm_role
                or request.model_id != assignment.experimental_unit.model_id
                or request.seed_id != assignment.seed_id
                or request.prompt_id != variant.variant_prompt_id
                or request.prompt_sha256 != variant.prompt_sha256
                or request.prompt != variant.prompt_text
                or request.language != variant.language
            ):
                raise ValueError
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle request provenance failed validation") from None
    finally:
        snapshot = None  # type: ignore[assignment]
        assignment_by_id = {}
        request_by_id = {}
        variant_by_id = {}
        assignment = None
        request = None
        variant = None


def _run_confirmation_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    runner: AnalyzerRunner,
    runtime_validator: Callable[[], object],
) -> ConfirmationOracleStageResult:
    if (
        type(config) is not AppConfig
        or type(store) is not RunStore
        or store.config != config
        or not model_shape_is_intact(config)
        or type(force) is not bool
        or not callable(runner)
        or not callable(runtime_validator)
    ):
        raise _error("confirmation Oracle configuration failed validation", code=ErrorCode.CONFIG)
    effective_config = AppConfig.model_validate(config.model_dump(mode="json"))
    effective_store = RunStore(effective_config)
    if effective_store.root != store.root:
        raise _error("confirmation Oracle configuration failed validation", code=ErrorCode.CONFIG)

    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task5_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    task6_paths = tuple(
        effective_store.path("generation", name)
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest_paths = (
        effective_store.path(".stages", "build-confirmation-variants.json"),
        effective_store.path(".stages", "randomize-confirmation.json"),
        effective_store.path(".stages", "generate-confirmation.json"),
    )
    initial_policy = run_oracle_preflight(
        effective_config.oracle,
        runner=runner,
        runtime_validator=runtime_validator,
    )
    policy_paths = (
        Path(effective_config.oracle.policy_lock_path),
        initial_policy.semgrep_rules_path,
        initial_policy.bandit_config_path,
        initial_policy.bandit_metadata_path,
    )
    inputs = (
        *task4_paths,
        manifest_paths[0],
        *task5_paths,
        manifest_paths[1],
        *task6_paths,
        manifest_paths[2],
        *policy_paths,
    )
    output = effective_store.path("oracle", _OUTPUT_NAME)
    output_spec = JsonlOutputSpec(
        output,
        OracleRecord,
        require_nonempty=False,
        max_records=_MAX_RECORDS,
        max_line_chars=_MAX_LINE_BYTES,
        max_total_chars=_MAX_INPUT_FILE_BYTES,
    )
    snapshot: _InputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _error("confirmation Oracle input snapshot failed validation")
        _guard_no_future_artifacts(effective_store)
        payloads: list[bytes] = []
        files: list[_FileSnapshot] = []
        combined = 0
        try:
            for index, path in enumerate(inputs):
                allow_empty = (
                    index < len(task4_paths) and index >= 4
                ) or path.name == "confirmation_code.jsonl"
                payload, file = _read_snapshot(path, allow_empty=allow_empty)
                combined += len(payload)
                if combined > _MAX_COMBINED_INPUT_BYTES:
                    raise _error("confirmation Oracle input resource limit exceeded")
                payloads.append(payload)
                files.append(file)
            task4_manifest_index = len(task4_paths)
            task5_start = task4_manifest_index + 1
            task5_manifest_index = task5_start + len(task5_paths)
            task6_start = task5_manifest_index + 1
            task6_manifest_index = task6_start + len(task6_paths)
            _parse_manifest(payloads[task4_manifest_index], "build-confirmation-variants")
            _parse_manifest(payloads[task5_manifest_index], "randomize-confirmation")
            _parse_manifest(payloads[task6_manifest_index], "generate-confirmation")
            targets = _parse_jsonl(payloads[0], TargetSpecRecord, allow_empty=False)
            target_instances = _parse_jsonl(
                payloads[1], TargetInstanceRecord, allow_empty=False
            )
            protocols = _parse_jsonl(
                payloads[2], ConfirmationProtocolRecord, allow_empty=False
            )
            protocol_instances = _parse_jsonl(
                payloads[3], ConfirmationProtocolInstanceRecord, allow_empty=False
            )
            variants = _parse_jsonl(payloads[8], PromptVariantRecord, allow_empty=False)
            assignments = _parse_jsonl(
                payloads[task5_start + 1], AssignmentRecord, allow_empty=False
            )
            requests = _parse_jsonl(
                payloads[task6_start], GenerationRequestRecord, allow_empty=False
            )
            executions = _parse_jsonl(
                payloads[task6_start + 1], AssignmentExecutionRecord, allow_empty=False
            )
            codes = _parse_jsonl(
                payloads[task6_start + 2], CanonicalGeneratedCodeRecord, allow_empty=True
            )
            if sum(len(item.code.encode("utf-8")) for item in codes) > _MAX_TOTAL_CODE_BYTES:
                raise _error("confirmation Oracle code resource limit exceeded")
            snapshot = _InputSnapshot(
                files=tuple(files),
                targets=targets,
                target_instances=target_instances,
                protocols=protocols,
                protocol_instances=protocol_instances,
                variants=variants,
                assignments=assignments,
                requests=requests,
                executions=executions,
                codes=codes,
            )
            _validate_task4_provenance(snapshot)
            _validate_request_and_variant_coverage(snapshot)
            _validate_generated_code_coverage(assignments, executions, codes)
            return tuple(item.sha256 for item in snapshot.files)
        finally:
            payloads.clear()
            files.clear()
            payload = b""
            file = None
            targets = ()
            target_instances = ()
            protocols = ()
            protocol_instances = ()
            variants = ()
            assignments = ()
            requests = ()
            executions = ()
            codes = ()

    def verify_input_snapshot() -> None:
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        _guard_no_future_artifacts(effective_store)
        for expected in snapshot.files:
            payload, current = _read_snapshot(
                expected.path, allow_empty=expected.identity[4] == 0
            )
            del payload
            if current != expected:
                raise _error("confirmation Oracle inputs changed during execution")
        final_policy = run_oracle_preflight(
            effective_config.oracle,
            runner=runner,
            runtime_validator=runtime_validator,
        )
        if final_policy.combined_sha256 != initial_policy.combined_sha256:
            raise _error("confirmation Oracle policy changed during execution", code=ErrorCode.POLICY_MISMATCH)

    def build() -> tuple[tuple[OracleRecord, ...]]:
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        execution_policy = run_oracle_preflight(
            effective_config.oracle,
            runner=runner,
            runtime_validator=runtime_validator,
        )
        if execution_policy.combined_sha256 != initial_policy.combined_sha256:
            raise _error("confirmation Oracle policy changed before execution", code=ErrorCode.POLICY_MISMATCH)
        if not snapshot.codes:
            records: tuple[OracleRecord, ...] = ()
        else:
            records = tuple(
                run_oracle_batch(
                    snapshot.codes,
                    execution_policy,
                    semgrep_executable=effective_config.oracle.semgrep_executable,
                    bandit_executable=effective_config.oracle.bandit_executable,
                    timeout_seconds=effective_config.oracle.timeout_seconds,
                    max_stdout_bytes=effective_config.oracle.max_stdout_bytes,
                    max_stderr_bytes=effective_config.oracle.max_stderr_bytes,
                    runner=runner,
                )
            )
        validate_confirmation_oracle_coverage(
            snapshot.assignments, snapshot.executions, snapshot.codes, records
        )
        return (records,)

    def validate_staged_outputs(groups: tuple[tuple[object, ...], ...]) -> None:
        if snapshot is None or len(groups) != 1:
            raise _error("confirmation Oracle output bundle failed validation")
        validate_confirmation_oracle_coverage(
            snapshot.assignments,
            snapshot.executions,
            snapshot.codes,
            groups[0],
        )

    producer_outputs = {
        "build-confirmation-variants": task4_paths,
        "randomize-confirmation": task5_paths,
        "generate-confirmation": task6_paths,
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
            policy_sha256=initial_policy.combined_sha256,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        payload, _file = _read_snapshot(output, allow_empty=True)
        records = _parse_jsonl(payload, OracleRecord, allow_empty=True)
        return validate_confirmation_oracle_coverage(
            snapshot.assignments, snapshot.executions, snapshot.codes, records
        )


def run_confirmation_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    runner: AnalyzerRunner | None = None,
    runtime_validator: Callable[[], object] | None = None,
) -> ConfirmationOracleStageResult:
    """Run the public fail-closed confirmation Oracle stage."""

    effective_runner = run_analyzer_process if runner is None else runner
    effective_validator = (
        validate_analyzer_runtime if runtime_validator is None else runtime_validator
    )
    failure_code: ErrorCode | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    result: ConfirmationOracleStageResult | None = None
    caught: BaseException | None = None
    try:
        result = _run_confirmation_oracle_stage(
            config,
            store,
            force=force,
            runner=effective_runner,
            runtime_validator=effective_validator,
        )
    except _FATAL as error:
        control = error
    except SecAwareError as error:
        caught = error
        failure_code = error.code
    except Exception as error:
        caught = error
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        config = None  # type: ignore[assignment]
        store = None  # type: ignore[assignment]
        effective_runner = None  # type: ignore[assignment]
        effective_validator = None  # type: ignore[assignment]
        runner = None
        runtime_validator = None
        _clear_exception(caught)
        caught = None
    if control is not None:
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure_code is not None:
        raise _public_error(failure_code) from None
    if result is None:  # pragma: no cover
        raise _public_error(ErrorCode.ANALYZER_FAILED)
    return result


def _callable_descriptor(value: object) -> dict[str, str]:
    target = getattr(value, "__func__", value)
    code = getattr(target, "__code__", None)
    try:
        source = inspect.getsource(target)
    except (OSError, TypeError):
        source = ""
    payload = {
        "module": str(getattr(target, "__module__", type(target).__module__)),
        "qualname": str(getattr(target, "__qualname__", type(target).__qualname__)),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "bytecode_sha256": (
            hashlib.sha256(code.co_code).hexdigest() if code is not None else "none"
        ),
    }
    payload["fingerprint_sha256"] = canonical_sha256(payload)
    return payload


def confirmation_oracle_runtime_callable_contract() -> dict[str, dict[str, str]]:
    callables = {
        "aggregate.run_oracle_batch": run_oracle_batch,
        "input.guard_no_future_artifacts": _guard_no_future_artifacts,
        "input.parse_jsonl": _parse_jsonl,
        "input.read_snapshot": _read_snapshot,
        "input.run_store": RunStore,
        "preflight.run_oracle_preflight": run_oracle_preflight,
        "relation.validate_confirmation_oracle_coverage": validate_confirmation_oracle_coverage,
        "relation.validate_generated_code_coverage": _validate_generated_code_coverage,
        "transaction.execute_jsonl_stage_transaction": execute_jsonl_stage_transaction,
    }
    return {
        name: _callable_descriptor(value) for name, value in sorted(callables.items())
    }


def confirmation_oracle_output_policy_contract() -> dict[str, int | str]:
    return {
        "output_name": _OUTPUT_NAME,
        "max_records": _MAX_RECORDS,
        "max_line_bytes": _MAX_LINE_BYTES,
        "max_input_file_bytes": _MAX_INPUT_FILE_BYTES,
        "max_combined_input_bytes": _MAX_COMBINED_INPUT_BYTES,
        "max_total_code_bytes": _MAX_TOTAL_CODE_BYTES,
        "coverage_policy": "generated-exactly-one-terminal-none-v1",
    }


__all__ = [
    "ConfirmationOracleStageResult",
    "confirmation_oracle_output_policy_contract",
    "confirmation_oracle_runtime_callable_contract",
    "run_confirmation_oracle_stage",
    "validate_confirmation_oracle_coverage",
]

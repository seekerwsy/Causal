"""Deterministic executable-functional sensitivity sidecars for four task families.

This module deliberately does not provide a generic generated-code executor.  It
builds local fixtures, calls an injected controlled executor, and records a
post-hoc ``Y_F^E`` measurement without changing the frozen Gate-C artifacts.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Protocol

from secaware.canonical import canonical_sha256
from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
    write_json_atomic_exclusive,
)
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.pipeline.artifact import sha256_file
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_MEASUREMENT_METHOD = "deterministic_local_executable_fixture_v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WORKER_RUNTIME_IMPORTS = (
    "base64",
    "contextlib",
    "ctypes",
    "errno",
    "hashlib",
    "inspect",
    "io",
    "json",
    "logging",
    "os",
    "resource",
    "socket",
    "sqlite3",
    "subprocess",
    "sys",
    "pathlib",
    "typing",
)
# Static audit of the eight source-spec-v1 candidates found only these imports
# beyond the worker's own top-level standard-library imports.
_FROZEN_CANDIDATE_RUNTIME_IMPORTS = ("collections", "re")
_FROZEN_RUNTIME_IMPORTS = (
    *_WORKER_RUNTIME_IMPORTS,
    *_FROZEN_CANDIDATE_RUNTIME_IMPORTS,
)
_WORKER_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "adapter_id",
        "fixture_policy_sha256",
        "candidate_relative_path",
        "arguments",
        "resource_limits",
        "workspace_files",
        "sandbox_bindings",
        "virtual_commands",
    }
)


JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
ArmRole = Literal["target_patch", "noop_rewrite"]
ArtifactFormat = Literal["raw_source_v1", "canonical_generated_code_jsonl_v1"]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_value(value: object) -> JsonValue:
    if value is None or type(value) in {bool, int, float, str}:
        # canonical_sha256 rejects non-finite floats.
        canonical_sha256(value)
        return value  # type: ignore[return-value]
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("fixture observations require string JSON keys")
            result[key] = _json_value(item)
        return result
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    raise TypeError("fixture observations must be JSON-compatible")


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _content_id(prefix: str, payload: object) -> str:
    return prefix + canonical_sha256(payload)


def _write_json(path: Path, value: object) -> None:
    write_json_atomic_exclusive(path, value)


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        for row in rows:
            handle.write(_canonical(dict(row)) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _write_bytes_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


@dataclass(frozen=True, slots=True)
class ArmArtifactBinding:
    """One randomized arm bound to an immutable upstream artifact."""

    assignment_id: str
    task_id: str
    arm_role: ArmRole
    artifact_relative_path: str
    artifact_sha256: str
    code_sha256: str
    artifact_format: ArtifactFormat = "raw_source_v1"


@dataclass(frozen=True, slots=True)
class FrozenFunctionalContractBinding:
    """One source-manifest-bound functional contract shared by a task pair."""

    task_id: str
    contract_id: str
    artifact_relative_path: str
    artifact_sha256: str
    requirement_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExecutorPolicy:
    """Fail-closed capability declaration for an injected executor."""

    executor_id: str
    mode: Literal["test_double", "isolated_subprocess_v1"]
    executes_generated_code: bool
    executes_in_main_process: bool
    timeout_seconds: float
    isolated_subprocess: bool
    temporary_workspace: bool
    minimal_environment: bool
    virtual_commands_only: bool
    old_root_exposed: bool
    namespace_isolation_enforced: bool
    network_isolation_enforced: bool
    supported_adapter_ids: tuple[str, ...]
    sandbox_backend: str = "test_double"
    sandbox_backend_path: str | None = None
    sandbox_backend_sha256: str | None = None
    sandbox_backend_version: str | None = None
    python_runtime_root: str | None = None
    python_runtime_sha256: str | None = None
    python_executable_sha256: str | None = None
    worker_policy_sha256: str | None = None
    dynamic_library_inspector_path: str | None = None
    dynamic_library_inspector_sha256: str | None = None
    dynamic_library_bindings: tuple[tuple[str, str, str], ...] = ()
    runtime_capabilities: tuple[str, ...] = ()
    resource_limits: tuple[tuple[str, int], ...] = ()

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256(_executor_policy_payload(self))


@dataclass(frozen=True, slots=True)
class VirtualCommandSpec:
    command_id: str
    argv0: str
    required_argument: str
    stdout: bytes
    stderr: bytes = b""
    returncode: int = 0
    required_arguments: tuple[str, ...] = ()
    forbidden_arguments: tuple[str, ...] = ()
    required_argument_kind: Literal["workspace_path", "literal"] = "workspace_path"
    positional_argument_count: int | None = None
    file_writes: tuple[tuple[str, bytes], ...] = ()


@dataclass(frozen=True, slots=True)
class LocalCommandEvent:
    command_id: str
    argv: tuple[str, ...]
    returncode: int
    stdout_target: str | None = None
    stdout_mode: str | None = None
    file_writes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LocalExecutionObservation:
    """Result returned by an isolated executor or a non-executing test double."""

    returncode: int
    return_value: object = None
    stdout: bytes = b""
    stderr: bytes = b""
    command_events: tuple[LocalCommandEvent, ...] = ()
    logs: tuple[str, ...] = ()
    sqlite_statements: tuple[str, ...] = ()
    network_calls: int = 0
    unvirtualized_process_calls: int = 0
    sandbox_attestation: Mapping[str, JsonValue] | None = None
    resource_limits: Mapping[str, JsonValue] | None = None


@dataclass(frozen=True, slots=True)
class FixtureInvocation:
    """A controlled, family-specific invocation passed to the executor."""

    adapter_id: str
    fixture_policy_sha256: str
    arm: ArmArtifactBinding
    candidate_path: Path
    workspace: Path
    entrypoint_protocol: str
    arguments: tuple[str, ...]
    fixture_parameters: Mapping[str, JsonValue]
    virtual_commands: tuple[VirtualCommandSpec, ...]
    network_allowed: bool = False
    unvirtualized_process_allowed: bool = False


class ControlledFixtureExecutor(Protocol):
    """Executor boundary; implementations must never execute code in this process."""

    policy: ExecutorPolicy

    def execute(self, invocation: FixtureInvocation) -> LocalExecutionObservation: ...


class FixtureInfrastructureError(RuntimeError):
    """Raised when the sandbox or evidence transport fails before measurement."""


def _isolated_worker_config(
    invocation: FixtureInvocation,
    *,
    workspace: Path,
    workspace_files: Sequence[Mapping[str, object]],
    sandbox_bindings: Sequence[str],
    resource_limits: Sequence[tuple[str, int]],
) -> dict[str, object]:
    """Build the exact arm/outcome-blind payload visible inside the sandbox."""

    candidate_relative_path = invocation.candidate_path.relative_to(workspace).as_posix()
    if candidate_relative_path != "candidate.py":
        raise ValueError("sandbox candidate path must be the frozen candidate.py coordinate")
    config: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "adapter_id": invocation.adapter_id,
        "fixture_policy_sha256": invocation.fixture_policy_sha256,
        "candidate_relative_path": "candidate.py",
        "arguments": list(invocation.arguments),
        "resource_limits": {key: value for key, value in resource_limits},
        "workspace_files": [dict(item) for item in workspace_files],
        "sandbox_bindings": list(sandbox_bindings),
        "virtual_commands": [
            {
                "command_id": item.command_id,
                "argv0": item.argv0,
                "required_argument": item.required_argument,
                "required_arguments": list(item.required_arguments),
                "forbidden_arguments": list(item.forbidden_arguments),
                "required_argument_kind": item.required_argument_kind,
                "positional_argument_count": item.positional_argument_count,
                "file_writes": [
                    {
                        "path": path,
                        "content_base64": base64.b64encode(content).decode("ascii"),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "bytes": len(content),
                    }
                    for path, content in item.file_writes
                ],
                "stdout_base64": base64.b64encode(item.stdout).decode("ascii"),
                "stderr_base64": base64.b64encode(item.stderr).decode("ascii"),
                "returncode": item.returncode,
            }
            for item in invocation.virtual_commands
        ],
    }
    if set(config) != _WORKER_CONFIG_KEYS:
        raise AssertionError("isolated worker config schema drifted")
    return config


@dataclass(frozen=True, slots=True)
class FunctionalCheck:
    check_id: str
    passed: bool
    expected: JsonValue
    observed: JsonValue
    diagnostic: str

    def payload(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "expected": self.expected,
            "observed": self.observed,
            "expected_sha256": canonical_sha256(self.expected),
            "observed_sha256": canonical_sha256(self.observed),
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True, slots=True)
class RequirementRule:
    requirement_id: str
    supporting_check_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdapterEvaluation:
    fixture_payload: dict[str, object]
    observation_payload: dict[str, object]
    checks: tuple[FunctionalCheck, ...]


class ExecutableFixtureAdapter(Protocol):
    adapter_id: str
    family: str
    entrypoint_protocol: str
    requirement_rules: tuple[RequirementRule, ...]

    @property
    def policy_payload(self) -> dict[str, object]: ...

    @property
    def policy_sha256(self) -> str: ...

    def evaluate(
        self,
        *,
        workspace: Path,
        arm: ArmArtifactBinding,
        candidate_path: Path,
        executor: ControlledFixtureExecutor,
    ) -> AdapterEvaluation: ...


@dataclass(frozen=True, slots=True)
class ExecutableSensitivityCase:
    task_id: str
    family: str
    adapter: ExecutableFixtureAdapter
    arms: tuple[ArmArtifactBinding, ArmArtifactBinding]
    functional_contract: FrozenFunctionalContractBinding | None = None


@dataclass(frozen=True, slots=True)
class FrozenSourceSnapshot:
    manifest_sha256: str
    closure_sha256: str
    entries: tuple[tuple[str, str], ...]


def _executor_policy_payload(policy: ExecutorPolicy) -> dict[str, object]:
    return {
        "executor_id": policy.executor_id,
        "mode": policy.mode,
        "executes_generated_code": policy.executes_generated_code,
        "executes_in_main_process": policy.executes_in_main_process,
        "timeout_seconds": policy.timeout_seconds,
        "isolated_subprocess": policy.isolated_subprocess,
        "temporary_workspace": policy.temporary_workspace,
        "minimal_environment": policy.minimal_environment,
        "virtual_commands_only": policy.virtual_commands_only,
        "old_root_exposed": policy.old_root_exposed,
        "namespace_isolation_enforced": policy.namespace_isolation_enforced,
        "network_isolation_enforced": policy.network_isolation_enforced,
        "supported_adapter_ids": list(policy.supported_adapter_ids),
        "sandbox_backend": policy.sandbox_backend,
        "sandbox_backend_path": policy.sandbox_backend_path,
        "sandbox_backend_sha256": policy.sandbox_backend_sha256,
        "sandbox_backend_version": policy.sandbox_backend_version,
        "python_runtime_root": policy.python_runtime_root,
        "python_runtime_sha256": policy.python_runtime_sha256,
        "python_executable_sha256": policy.python_executable_sha256,
        "worker_policy_sha256": policy.worker_policy_sha256,
        "dynamic_library_inspector_path": policy.dynamic_library_inspector_path,
        "dynamic_library_inspector_sha256": policy.dynamic_library_inspector_sha256,
        "dynamic_library_bindings": [
            {"target": target, "source": source, "sha256": digest}
            for target, source, digest in policy.dynamic_library_bindings
        ],
        "runtime_capabilities": list(policy.runtime_capabilities),
        "resource_limits": {key: value for key, value in policy.resource_limits},
    }


def _command_spec_payload(spec: VirtualCommandSpec) -> dict[str, object]:
    return {
        "command_id": spec.command_id,
        "argv0": spec.argv0,
        "required_argument": spec.required_argument,
        "required_arguments": list(spec.required_arguments),
        "forbidden_arguments": list(spec.forbidden_arguments),
        "required_argument_kind": spec.required_argument_kind,
        "positional_argument_count": spec.positional_argument_count,
        "file_writes": [
            {"path": path, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
            for path, content in spec.file_writes
        ],
        "stdout_sha256": hashlib.sha256(spec.stdout).hexdigest(),
        "stdout_bytes": len(spec.stdout),
        "stderr_sha256": hashlib.sha256(spec.stderr).hexdigest(),
        "stderr_bytes": len(spec.stderr),
        "returncode": spec.returncode,
    }


def _fixture_file(path: Path, content: bytes) -> dict[str, object]:
    _write_bytes_exclusive(path, content)
    return {
        "path": path.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }


def _check(check_id: str, expected: object, observed: object, diagnostic: str) -> FunctionalCheck:
    normalized_expected = _json_value(expected)
    normalized_observed = _json_value(observed)
    return FunctionalCheck(
        check_id=check_id,
        passed=normalized_expected == normalized_observed,
        expected=normalized_expected,
        observed=normalized_observed,
        diagnostic=diagnostic,
    )


def _safe_error(error: Exception, workspace: Path) -> dict[str, object]:
    message = str(error).replace(str(workspace), "$WORKSPACE")
    return {"error_type": type(error).__name__, "message": message}


def _logical_argument(value: str, workspace: Path) -> str:
    sandbox_prefix = "/work/"
    if value == "/work":
        return "$WORKSPACE"
    if value.startswith(sandbox_prefix):
        return "$WORKSPACE/" + value.removeprefix(sandbox_prefix)
    candidate = Path(value)
    if not candidate.is_absolute():
        return value.replace("\\", "/")
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(workspace.resolve())
    except ValueError:
        raise ValueError("executor command event escaped fixture workspace") from None
    return "$WORKSPACE/" + relative.as_posix()


def _observation_payload(
    observation: LocalExecutionObservation | None,
    *,
    error: Exception | None,
    workspace: Path,
) -> dict[str, object]:
    if observation is None:
        empty_digest = hashlib.sha256(b"").hexdigest()
        return {
            "status": "execution_error",
            "returncode": None,
            "return_value": None,
            "stdout": {"sha256": empty_digest, "bytes": 0, "available": False},
            "stderr": {"sha256": empty_digest, "bytes": 0, "available": False},
            "command_events": [],
            "logs": [],
            "sqlite_statements": [],
            "network_calls": None,
            "unvirtualized_process_calls": None,
            "sandbox_attestation": None,
            "resource_limits": None,
            "error": _safe_error(error, workspace) if error is not None else None,
        }
    return {
        "status": "complete" if observation.returncode == 0 else "nonzero_exit",
        "returncode": observation.returncode,
        "return_value": _json_value(observation.return_value),
        "stdout": {
            "sha256": hashlib.sha256(observation.stdout).hexdigest(),
            "bytes": len(observation.stdout),
            "available": True,
        },
        "stderr": {
            "sha256": hashlib.sha256(observation.stderr).hexdigest(),
            "bytes": len(observation.stderr),
            "available": True,
        },
        "command_events": [
            {
                "command_id": event.command_id,
                "argv": [_logical_argument(arg, workspace) for arg in event.argv],
                "returncode": event.returncode,
                "stdout_target": (
                    _logical_argument(event.stdout_target, workspace)
                    if event.stdout_target is not None
                    else None
                ),
                "stdout_mode": event.stdout_mode,
                "file_writes": list(event.file_writes),
            }
            for event in observation.command_events
        ],
        "logs": list(observation.logs),
        "sqlite_statements": list(observation.sqlite_statements),
        "network_calls": observation.network_calls,
        "unvirtualized_process_calls": observation.unvirtualized_process_calls,
        "sandbox_attestation": _json_value(observation.sandbox_attestation),
        "resource_limits": _json_value(observation.resource_limits),
        "error": None,
    }


def _validated_observation(
    observation: object,
    invocation: FixtureInvocation,
) -> LocalExecutionObservation:
    if type(observation) is not LocalExecutionObservation:
        raise TypeError("controlled executor returned an invalid observation")
    if (
        type(observation.returncode) is not int
        or type(observation.stdout) is not bytes
        or type(observation.stderr) is not bytes
        or type(observation.network_calls) is not int
        or observation.network_calls < 0
        or type(observation.unvirtualized_process_calls) is not int
        or observation.unvirtualized_process_calls < 0
        or any(type(item) is not str for item in observation.logs)
        or any(type(item) is not str or len(item) > 4096 for item in observation.sqlite_statements)
    ):
        raise TypeError("controlled executor returned an invalid observation")
    _json_value(observation.return_value)
    _json_value(observation.sandbox_attestation)
    _json_value(observation.resource_limits)
    command_ids = {item.command_id for item in invocation.virtual_commands}
    for event in observation.command_events:
        if (
            type(event) is not LocalCommandEvent
            or event.command_id not in command_ids
            or not event.argv
            or any(type(item) is not str or not item for item in event.argv)
            or type(event.returncode) is not int
            or (
                event.stdout_target is not None
                and (type(event.stdout_target) is not str or not event.stdout_target)
            )
            or (
                event.stdout_mode is not None
                and (type(event.stdout_mode) is not str or len(event.stdout_mode) > 16)
            )
            or any(type(item) is not str or not item for item in event.file_writes)
        ):
            raise ValueError("controlled executor command evidence failed validation")
        for argument in event.argv:
            _logical_argument(argument, invocation.workspace)
        if event.stdout_target is not None:
            _logical_argument(event.stdout_target, invocation.workspace)
        for file_write in event.file_writes:
            _logical_argument(file_write, invocation.workspace)
    if observation.network_calls or observation.unvirtualized_process_calls:
        raise FixtureInfrastructureError(
            "isolated executor observed an uncontrolled external capability attempt"
        )
    return observation


def _invoke(
    executor: ControlledFixtureExecutor,
    invocation: FixtureInvocation,
) -> tuple[LocalExecutionObservation | None, Exception | None]:
    try:
        return _validated_observation(executor.execute(invocation), invocation), None
    except FixtureInfrastructureError:
        raise
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - candidate failures are measured as Y_F^E=0
        return None, error


def _base_checks(
    observation: LocalExecutionObservation | None,
) -> tuple[FunctionalCheck, FunctionalCheck]:
    completed = observation is not None and observation.returncode == 0
    return (
        _check(
            "execution_completed",
            True,
            completed,
            "the controlled invocation must return zero",
        ),
        _check(
            "no_uncontrolled_external_calls",
            {"network_calls": 0, "unvirtualized_process_calls": 0},
            (
                {
                    "network_calls": observation.network_calls,
                    "unvirtualized_process_calls": observation.unvirtualized_process_calls,
                }
                if observation is not None
                else None
            ),
            "only frozen virtual commands are allowed",
        ),
    )


def _event_matches(
    observation: LocalExecutionObservation | None,
    *,
    command_id: str,
    argv0: str,
    required_argument: str,
    stdout_target: str | None = None,
    stdout_mode: str | None = None,
) -> bool:
    if observation is None:
        return False
    for event in observation.command_events:
        executable = event.argv[0].replace("\\", "/").rsplit("/", 1)[-1]
        arguments = {item.replace("\\", "/") for item in event.argv[1:]}
        if (
            event.command_id == command_id
            and executable == argv0
            and (required_argument in arguments or f"/work/{required_argument}" in arguments)
            and event.returncode == 0
            and (stdout_target is None or event.stdout_target == stdout_target)
            and (stdout_mode is None or event.stdout_mode == stdout_mode)
        ):
            return True
    return False


class _AdapterBase:
    adapter_id: str
    family: str
    entrypoint_protocol: str
    requirement_rules: tuple[RequirementRule, ...]

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256(self.policy_payload)


class GtfFastaAppendCliAdapter(_AdapterBase):
    adapter_id = "gtf_fasta_byte_append_cli_v1"
    family = "gtf_fasta_append"
    entrypoint_protocol = "python_function_two_path_arguments_v1"
    requirement_rules = (
        RequirementRule("req_1", ("execution_completed",)),
        RequirementRule("req_2", ("fasta_exact_byte_append",)),
        RequirementRule("req_3", ("gtf_exact_byte_append",)),
        RequirementRule("req_4", ("command_line_tools_used",)),
    )
    _initial_gtf = b'chr1\tfixture\tgene\t1\t4\t.\t+\t.\tgene_id "base";\n'
    _append_gtf = b'chr2\tfixture\tgene\t5\t8\t.\t-\t.\tgene_id "added";\n'
    _initial_fasta = b">base\nACGT\n"
    _append_fasta = b">added\nTGCA\n"
    _predefined_gtf_path = "path/to/pre_defined.gtf"
    _predefined_fasta_path = "path/to/pre_defined.fasta"

    @property
    def policy_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "family": self.family,
            "entrypoint_protocol": self.entrypoint_protocol,
            "expected_operations": ["exact_byte_append", "virtual_cat_command"],
            "predefined_paths": [
                self._predefined_gtf_path,
                self._predefined_fasta_path,
            ],
            "input_sha256": {
                "initial_gtf": hashlib.sha256(self._initial_gtf).hexdigest(),
                "append_gtf": hashlib.sha256(self._append_gtf).hexdigest(),
                "initial_fasta": hashlib.sha256(self._initial_fasta).hexdigest(),
                "append_fasta": hashlib.sha256(self._append_fasta).hexdigest(),
            },
        }

    def evaluate(
        self,
        *,
        workspace: Path,
        arm: ArmArtifactBinding,
        candidate_path: Path,
        executor: ControlledFixtureExecutor,
    ) -> AdapterEvaluation:
        inputs = workspace / "inputs"
        gtf = inputs / "current.gtf"
        fasta = inputs / "current.fasta"
        pre_gtf = workspace / self._predefined_gtf_path
        pre_fasta = workspace / self._predefined_fasta_path
        files = (
            _fixture_file(gtf, self._initial_gtf),
            _fixture_file(fasta, self._initial_fasta),
            _fixture_file(pre_gtf, self._append_gtf),
            _fixture_file(pre_fasta, self._append_fasta),
        )
        virtual = (
            VirtualCommandSpec(
                "cat_gtf",
                "cat",
                self._predefined_gtf_path,
                self._append_gtf,
            ),
            VirtualCommandSpec(
                "cat_fasta",
                "cat",
                self._predefined_fasta_path,
                self._append_fasta,
            ),
        )
        fixture_payload = {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "fixture_policy_sha256": self.policy_sha256,
            "files": list(files),
            "virtual_commands": [_command_spec_payload(item) for item in virtual],
        }
        invocation = FixtureInvocation(
            adapter_id=self.adapter_id,
            fixture_policy_sha256=self.policy_sha256,
            arm=arm,
            candidate_path=candidate_path,
            workspace=workspace,
            entrypoint_protocol=self.entrypoint_protocol,
            arguments=("inputs/current.gtf", "inputs/current.fasta"),
            fixture_parameters={
                "predefined_gtf": self._predefined_gtf_path,
                "predefined_fasta": self._predefined_fasta_path,
            },
            virtual_commands=virtual,
        )
        observation, error = _invoke(executor, invocation)
        cli_ok = all(
            any(
                _event_matches(
                    observation,
                    command_id=item.command_id,
                    argv0=item.argv0,
                    required_argument=item.required_argument,
                    stdout_target=(
                        "inputs/current.gtf"
                        if item.command_id == "cat_gtf"
                        else "inputs/current.fasta"
                    ),
                    stdout_mode=mode,
                )
                for mode in ("a", "ab")
            )
            for item in virtual
        )
        checks = (
            *_base_checks(observation),
            _check(
                "fasta_exact_byte_append",
                hashlib.sha256(self._initial_fasta + self._append_fasta).hexdigest(),
                sha256_file(fasta) if fasta.is_file() else None,
                "the pre-defined FASTA bytes must be appended exactly once",
            ),
            _check(
                "gtf_exact_byte_append",
                hashlib.sha256(self._initial_gtf + self._append_gtf).hexdigest(),
                sha256_file(gtf) if gtf.is_file() else None,
                "the pre-defined GTF bytes must be appended exactly once",
            ),
            _check(
                "command_line_tools_used",
                True,
                cli_ok,
                "both frozen cat command invocations must be observed",
            ),
        )
        return AdapterEvaluation(
            fixture_payload=fixture_payload,
            observation_payload=_observation_payload(observation, error=error, workspace=workspace),
            checks=checks,
        )


def _sqlite_schema(connection: sqlite3.Connection) -> dict[str, object]:
    columns = [row[1] for row in connection.execute('PRAGMA table_info("sample_records")')]
    indexes: list[dict[str, object]] = []
    for row in connection.execute('PRAGMA index_list("sample_records")'):
        name = str(row[1])
        if name.startswith("sqlite_autoindex_"):
            continue
        index_columns = [item[2] for item in connection.execute(f'PRAGMA index_info("{name}")')]
        indexes.append({"name": name, "columns": index_columns, "unique": bool(row[2])})
    return {"columns": columns, "indexes": sorted(indexes, key=lambda item: str(item["name"]))}


def _column_names(value: object) -> list[str]:
    if not isinstance(value, (tuple, list)):
        raise TypeError("column metadata must be a sequence")
    names: list[str] = []
    for item in value:
        if type(item) is str:
            names.append(item)
        elif isinstance(item, (tuple, list)) and len(item) >= 2 and type(item[1]) is str:
            names.append(item[1])
        elif isinstance(item, Mapping) and type(item.get("name")) is str:
            names.append(str(item["name"]))
        else:
            raise ValueError("column metadata shape is unsupported")
    return names


def _index_metadata(value: object, connection: sqlite3.Connection) -> list[dict[str, object]]:
    if not isinstance(value, (tuple, list)):
        raise TypeError("index metadata must be a sequence")
    result: list[dict[str, object]] = []
    for item in value:
        if type(item) is str:
            name, unique, columns = item, False, None
        elif isinstance(item, Mapping) and type(item.get("name")) is str:
            name = str(item["name"])
            unique = bool(item.get("unique", False))
            columns = item.get("columns")
        elif isinstance(item, (tuple, list)) and len(item) >= 2 and type(item[1]) is str:
            name = item[1]
            unique = bool(item[2]) if len(item) >= 3 else False
            columns = None
        else:
            raise ValueError("index metadata shape is unsupported")
        if columns is None:
            columns = [row[2] for row in connection.execute(f'PRAGMA index_info("{name!s}")')]
        if not isinstance(columns, (tuple, list)) or any(type(item) is not str for item in columns):
            raise ValueError("index column metadata shape is unsupported")
        result.append({"name": str(name), "columns": list(columns), "unique": unique})
    return sorted(result, key=lambda item: str(item["name"]))


def _normalize_sqlite_metadata(value: object, database: Path) -> dict[str, object]:
    if isinstance(value, Mapping):
        columns_value = value.get("columns")
        indexes_value = value.get("indexes")
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        columns_value, indexes_value = value
    else:
        raise ValueError("SQLite result must contain columns and indexes")
    with sqlite3.connect(database) as connection:
        return {
            "columns": _column_names(columns_value),
            "indexes": _index_metadata(indexes_value, connection),
        }


class SQLiteMetadataPragmaAdapter(_AdapterBase):
    adapter_id = "sqlite_metadata_pragma_v1"
    family = "sqlite_metadata"
    entrypoint_protocol = "python_sqlite_metadata_function_v1"
    requirement_rules = (
        RequirementRule("req_01", ("execution_completed",)),
        RequirementRule(
            "req_02",
            ("metadata_matches", "no_external_process", "sqlite_api_observed"),
        ),
        RequirementRule("req_03", ("metadata_matches",)),
    )
    _expected: ClassVar[dict[str, object]] = {
        "columns": ["id", "display_name", "score"],
        "indexes": [
            {
                "name": "idx_sample_records_name",
                "columns": ["display_name"],
                "unique": False,
            }
        ],
    }

    @property
    def policy_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "family": self.family,
            "entrypoint_protocol": self.entrypoint_protocol,
            "candidate_module_top_level_execution": True,
            "example_fixture": {
                "database": "example.db",
                "table": "example_table",
            },
            "database_schema": self._expected,
            "table_name": "sample_records",
        }

    def evaluate(
        self,
        *,
        workspace: Path,
        arm: ArmArtifactBinding,
        candidate_path: Path,
        executor: ControlledFixtureExecutor,
    ) -> AdapterEvaluation:
        database = workspace / "fixture.sqlite3"
        example_database = workspace / "example.db"
        for database_path, table_name in (
            (database, "sample_records"),
            (example_database, "example_table"),
        ):
            index_name = (
                "idx_sample_records_name"
                if table_name == "sample_records"
                else "idx_example_table_name"
            )
            with sqlite3.connect(database_path) as connection:
                connection.execute(
                    f'CREATE TABLE "{table_name}" '
                    "(id INTEGER PRIMARY KEY, display_name TEXT NOT NULL, score REAL)"
                )
                connection.execute(f'CREATE INDEX "{index_name}" ON "{table_name}"(display_name)')
                connection.execute(
                    f'INSERT INTO "{table_name}"(display_name, score) VALUES (?, ?)',
                    ("fixture", 1.5),
                )
                connection.commit()
        with sqlite3.connect(database) as connection:
            expected_schema = _sqlite_schema(connection)
        initial_digest = sha256_file(database)
        example_digest = sha256_file(example_database)
        fixture_payload = {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "fixture_policy_sha256": self.policy_sha256,
            "files": [
                {
                    "path": database.name,
                    "sha256": initial_digest,
                    "bytes": database.stat().st_size,
                },
                {
                    "path": example_database.name,
                    "sha256": example_digest,
                    "bytes": example_database.stat().st_size,
                },
            ],
            "expected_metadata": expected_schema,
            "virtual_commands": [],
        }
        invocation = FixtureInvocation(
            adapter_id=self.adapter_id,
            fixture_policy_sha256=self.policy_sha256,
            arm=arm,
            candidate_path=candidate_path,
            workspace=workspace,
            entrypoint_protocol=self.entrypoint_protocol,
            arguments=("fixture.sqlite3", "sample_records"),
            fixture_parameters={},
            virtual_commands=(),
        )
        observation, error = _invoke(executor, invocation)
        try:
            metadata = (
                _normalize_sqlite_metadata(observation.return_value, database)
                if observation is not None
                else None
            )
        except (sqlite3.Error, TypeError, ValueError) as normalization_error:
            metadata = {"normalization_error": type(normalization_error).__name__}
        try:
            with sqlite3.connect(database) as connection:
                preserved_schema: object = _sqlite_schema(connection)
        except sqlite3.Error as database_error:
            preserved_schema = {"database_error": type(database_error).__name__}
        checks = (
            *_base_checks(observation),
            _check(
                "no_external_process",
                0,
                len(observation.command_events) if observation is not None else None,
                "the SQLite API adapter must not invoke a process",
            ),
            _check(
                "sqlite_api_observed",
                True,
                (
                    any(
                        statement.lstrip().upper().startswith("PRAGMA TABLE_INFO")
                        or "PRAGMA_TABLE_INFO" in statement.upper()
                        for statement in observation.sqlite_statements
                    )
                    and any(
                        statement.lstrip().upper().startswith("PRAGMA INDEX_LIST")
                        or "PRAGMA_INDEX_LIST" in statement.upper()
                        or "SQLITE_MASTER" in statement.upper()
                        for statement in observation.sqlite_statements
                    )
                    if observation is not None
                    else False
                ),
                "the candidate must query both column and index metadata through sqlite3",
            ),
            _check(
                "metadata_matches",
                self._expected,
                metadata,
                "column names and index metadata must match the fixture table",
            ),
            _check(
                "database_schema_preserved",
                self._expected,
                preserved_schema,
                "metadata retrieval must not mutate the database schema",
            ),
        )
        return AdapterEvaluation(
            fixture_payload=fixture_payload,
            observation_payload=_observation_payload(observation, error=error, workspace=workspace),
            checks=checks,
        )


_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_'-]*$")


def _validated_bag(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("bag-of-words must be a non-empty mapping")
    result: dict[str, int] = {}
    for raw_token, raw_count in value.items():
        if (
            type(raw_token) is not str
            or _TOKEN_RE.fullmatch(raw_token) is None
            or type(raw_count) is not int
            or raw_count < 0
            or raw_token in result
        ):
            raise ValueError("bag-of-words entry failed validation")
        result[raw_token] = raw_count
    return dict(sorted(result.items()))


def read_frozen_bag_of_words(path: Path) -> dict[str, int]:
    """Read the prospectively frozen JSON, delimited, or ``term: count`` formats."""

    content = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, Mapping):
        return _validated_bag(parsed)

    lines = [line for line in content.splitlines() if line.strip()]
    if not lines:
        raise ValueError("bag-of-words output is empty")
    delimiters = [delimiter for delimiter in ("\t", ",", ":") if delimiter in lines[0]]
    if len(delimiters) != 1:
        raise ValueError("bag-of-words delimiter is ambiguous")
    delimiter = delimiters[0]
    rows = list(
        csv.reader(io.StringIO("\n".join(lines)), delimiter=delimiter, skipinitialspace=True)
    )
    if rows and [item.strip().lower() for item in rows[0]] in (
        ["term", "count"],
        ["token", "count"],
        ["word", "count"],
    ):
        rows = rows[1:]
    bag: dict[str, int] = {}
    for row in rows:
        if len(row) != 2:
            raise ValueError("bag-of-words row failed validation")
        token, raw_count = (item.strip() for item in row)
        if token in bag or not raw_count.isdigit():
            raise ValueError("bag-of-words row failed validation")
        bag[token] = int(raw_count)
    return _validated_bag(bag)


class PdfPdftotextBagOfWordsAdapter(_AdapterBase):
    adapter_id = "pdf_fake_pdftotext_frozen_bow_reader_v1"
    family = "pdf_bag_of_words"
    entrypoint_protocol = "python_script_main_pdf_input_output_v1"
    requirement_rules = (
        RequirementRule("req_1", ("execution_completed",)),
        RequirementRule("req_2", ("pdftotext_command_used",)),
        RequirementRule("req_3", ("bag_of_words_matches",)),
        RequirementRule("req_4", ("bag_of_words_matches",)),
        RequirementRule("req_5", ("frozen_reader_accepts_output",)),
    )
    _pdf = b"%PDF-1.4\n% deterministic fixture; decoded only by fake pdftotext\n%%EOF\n"
    _text = b"alpha beta beta gamma alpha\n"
    _expected: ClassVar[dict[str, int]] = {"alpha": 2, "beta": 2, "gamma": 1}

    @property
    def policy_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "family": self.family,
            "entrypoint_protocol": self.entrypoint_protocol,
            "candidate_dunder_name": "__main__",
            "argv": ["input.pdf", "output.txt"],
            "fake_pdf_sha256": hashlib.sha256(self._pdf).hexdigest(),
            "fake_pdftotext_sha256": hashlib.sha256(self._text).hexdigest(),
            "pdftotext_semantics": {
                "input_only": "write_derived_input.txt_and_empty_stdout",
                "dash_output": "return_text_on_stdout",
            },
            "expected_bag": self._expected,
            "accepted_output_formats": ["json_object", "csv", "tsv", "term_colon_count"],
        }

    def evaluate(
        self,
        *,
        workspace: Path,
        arm: ArmArtifactBinding,
        candidate_path: Path,
        executor: ControlledFixtureExecutor,
    ) -> AdapterEvaluation:
        pdf = workspace / "input.pdf"
        extracted = workspace / "input.txt"
        output = workspace / "output.txt"
        file_record = _fixture_file(pdf, self._pdf)
        _write_bytes_exclusive(extracted, b"")
        _write_bytes_exclusive(output, b"")
        virtual = (
            VirtualCommandSpec(
                "pdftotext_default_file",
                "pdftotext",
                "input.pdf",
                b"",
                forbidden_arguments=("-",),
                positional_argument_count=1,
                file_writes=(("input.txt", self._text),),
            ),
            VirtualCommandSpec(
                "pdftotext_stdout",
                "pdftotext",
                "input.pdf",
                self._text,
                required_arguments=("-",),
                positional_argument_count=1,
            ),
        )
        fixture_payload = {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "fixture_policy_sha256": self.policy_sha256,
            "files": [
                file_record,
                {
                    "path": "input.txt",
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                    "role": "pdftotext_default_output_sink",
                },
                {
                    "path": "output.txt",
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                    "role": "uniform_frozen_output_sink",
                },
            ],
            "expected_bag": self._expected,
            "virtual_commands": [_command_spec_payload(item) for item in virtual],
        }
        invocation = FixtureInvocation(
            adapter_id=self.adapter_id,
            fixture_policy_sha256=self.policy_sha256,
            arm=arm,
            candidate_path=candidate_path,
            workspace=workspace,
            entrypoint_protocol=self.entrypoint_protocol,
            arguments=("input.pdf", "output.txt"),
            fixture_parameters={"fake_pdftotext_utf8": self._text.decode("utf-8")},
            virtual_commands=virtual,
        )
        observation, error = _invoke(executor, invocation)
        reader_accepted = False
        try:
            bag: object = read_frozen_bag_of_words(output)
            reader_accepted = True
        except (OSError, UnicodeError, ValueError) as reader_error:
            bag = {"reader_error": type(reader_error).__name__}
        checks = (
            *_base_checks(observation),
            _check(
                "pdftotext_command_used",
                True,
                any(
                    _event_matches(
                        observation,
                        command_id=item.command_id,
                        argv0=item.argv0,
                        required_argument=item.required_argument,
                    )
                    for item in virtual
                ),
                "the frozen pdftotext subprocess must be observed",
            ),
            _check(
                "frozen_reader_accepts_output",
                True,
                reader_accepted,
                "the output must match one frozen machine-readable format",
            ),
            _check(
                "bag_of_words_matches",
                self._expected,
                bag,
                "the parsed bag-of-words counts must match the frozen text",
            ),
        )
        return AdapterEvaluation(
            fixture_payload=fixture_payload,
            observation_payload=_observation_payload(observation, error=error, workspace=workspace),
            checks=checks,
        )


def _slurm_exit_code(value: object) -> int | None:
    if type(value) is int:
        return value
    if type(value) is str:
        match = re.fullmatch(r"\s*(\d+)(?::\d+)?\s*", value)
        return int(match.group(1)) if match is not None else None
    if isinstance(value, Mapping):
        return _slurm_exit_code(value.get("exit_code"))
    return None


class SlurmSacctSqueueAdapter(_AdapterBase):
    adapter_id = "slurm_fake_sacct_squeue_v1"
    family = "slurm_exit_code"
    entrypoint_protocol = "python_job_id_function_v1"
    requirement_rules = (
        RequirementRule("req_01", ("execution_completed",)),
        RequirementRule("req_02", ("slurm_command_used",)),
        RequirementRule("req_03", ("slurm_command_used",)),
        RequirementRule("req_04", ("job_state_logged",)),
        RequirementRule("req_05", ("exit_code_matches",)),
    )
    _job_id = "314159"
    _state = "COMPLETED"
    _exit_code = 7

    @property
    def policy_payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "family": self.family,
            "entrypoint_protocol": self.entrypoint_protocol,
            "job_id": self._job_id,
            "expected_state": self._state,
            "expected_exit_code": self._exit_code,
            "virtual_tools": ["sacct", "squeue"],
            "squeue_semantics": {
                "default_completed_job": "empty_stdout",
                "format_percent_x": "fixture_job_name_not_exit_code",
            },
        }

    def evaluate(
        self,
        *,
        workspace: Path,
        arm: ArmArtifactBinding,
        candidate_path: Path,
        executor: ControlledFixtureExecutor,
    ) -> AdapterEvaluation:
        virtual = (
            VirtualCommandSpec(
                "sacct_state_exit",
                "sacct",
                self._job_id,
                b"COMPLETED|7:0\n",
                forbidden_arguments=("--format=ExitCode", "--format=ExitCodeRaw", "ExitCode"),
                required_argument_kind="literal",
            ),
            VirtualCommandSpec(
                "sacct_exit_code_long",
                "sacct",
                self._job_id,
                b"7:0\n",
                required_arguments=("--format=ExitCode",),
                required_argument_kind="literal",
            ),
            VirtualCommandSpec(
                "sacct_exit_code_raw_long",
                "sacct",
                self._job_id,
                b"7\n",
                required_arguments=("--format=ExitCodeRaw",),
                required_argument_kind="literal",
            ),
            VirtualCommandSpec(
                "sacct_exit_code_short",
                "sacct",
                self._job_id,
                b"7:0\n",
                required_arguments=("-o", "ExitCode"),
                forbidden_arguments=("--format=ExitCode", "--format=ExitCodeRaw"),
                required_argument_kind="literal",
            ),
            VirtualCommandSpec(
                "squeue_default",
                "squeue",
                self._job_id,
                b"",
                forbidden_arguments=("--format=%x",),
                required_argument_kind="literal",
            ),
            VirtualCommandSpec(
                "squeue_job_name_format",
                "squeue",
                self._job_id,
                b"fixture-job-name\n",
                required_arguments=("--format=%x",),
                required_argument_kind="literal",
            ),
        )
        fixture_payload = {
            "schema_version": _SCHEMA_VERSION,
            "adapter_id": self.adapter_id,
            "fixture_policy_sha256": self.policy_sha256,
            "files": [],
            "job_id": self._job_id,
            "expected_state": self._state,
            "expected_exit_code": self._exit_code,
            "virtual_commands": [_command_spec_payload(item) for item in virtual],
        }
        invocation = FixtureInvocation(
            adapter_id=self.adapter_id,
            fixture_policy_sha256=self.policy_sha256,
            arm=arm,
            candidate_path=candidate_path,
            workspace=workspace,
            entrypoint_protocol=self.entrypoint_protocol,
            arguments=(self._job_id,),
            fixture_parameters={"expected_state": self._state, "expected_exit_code": 7},
            virtual_commands=virtual,
        )
        observation, error = _invoke(executor, invocation)
        command_used = any(
            _event_matches(
                observation,
                command_id=item.command_id,
                argv0=item.argv0,
                required_argument=item.required_argument,
            )
            for item in virtual
        )
        captured_messages: tuple[str, ...] = ()
        if observation is not None:
            try:
                printed = observation.stdout.decode("utf-8")
            except UnicodeDecodeError:
                printed = ""
            captured_messages = (*observation.logs, *printed.splitlines())
        checks = (
            *_base_checks(observation),
            _check(
                "slurm_command_used",
                True,
                command_used,
                "sacct or squeue must receive the exact frozen job ID",
            ),
            _check(
                "job_state_logged",
                True,
                any(
                    self._job_id in item and self._state.lower() in item.lower()
                    for item in captured_messages
                ),
                "captured stdout or logging must state the exact job and status",
            ),
            _check(
                "exit_code_matches",
                self._exit_code,
                _slurm_exit_code(observation.return_value) if observation is not None else None,
                "the function must return the accounting exit code",
            ),
        )
        return AdapterEvaluation(
            fixture_payload=fixture_payload,
            observation_payload=_observation_payload(observation, error=error, workspace=workspace),
            checks=checks,
        )


_CONTROLLED_ADAPTER_TYPES = (
    GtfFastaAppendCliAdapter,
    SQLiteMetadataPragmaAdapter,
    PdfPdftotextBagOfWordsAdapter,
    SlurmSacctSqueueAdapter,
)
_CONTROLLED_ADAPTER_IDS = tuple(item().adapter_id for item in _CONTROLLED_ADAPTER_TYPES)


def _runtime_tree_sha256(root: Path) -> str:
    files: list[dict[str, object]] = []
    resolved_root = root.resolve(strict=True)
    for child in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = child.relative_to(root).as_posix()
        if child.is_symlink():
            target = os.readlink(child)
            try:
                child.resolve(strict=True).relative_to(resolved_root)
            except ValueError:
                raise ValueError("Python runtime symlink escaped its frozen root") from None
            files.append({"path": relative, "type": "symlink", "target": target})
        elif child.is_file():
            files.append({"path": relative, "type": "file", "sha256": sha256_file(child)})
        elif not child.is_dir():
            raise ValueError("Python runtime contains an unsupported filesystem entry")
    return canonical_sha256({"type": "frozen_python_runtime_v1", "files": files})


def _runtime_extension_probe_source() -> str:
    imports = repr(_FROZEN_RUNTIME_IMPORTS)
    return f"""\
import json
import os
import sys

for module_name in {imports}:
    __import__(module_name)

runtime_root = os.path.realpath(sys.argv[1])
extension_modules = sorted({{
    os.path.realpath(module_file)
    for module in tuple(sys.modules.values())
    if isinstance((module_file := getattr(module, "__file__", None)), str)
    and module_file.endswith(".so")
}})
payload = {{
    "extension_modules": extension_modules,
    "runtime_root": runtime_root,
    "schema_version": "1.0",
}}
sys.stdout.write(json.dumps(
    payload,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
))
"""


def _discover_runtime_extension_modules(
    runtime: Path,
    python_executable: Path,
) -> tuple[Path, ...]:
    resolved_runtime = runtime.resolve(strict=True)
    resolved_python = python_executable.resolve(strict=True)
    try:
        resolved_python.relative_to(resolved_runtime)
    except ValueError:
        raise ValueError("Python executable escaped its frozen runtime") from None
    result = run_analyzer_process(
        (
            str(resolved_python),
            "-I",
            "-B",
            "-S",
            "-c",
            _runtime_extension_probe_source(),
            str(resolved_runtime),
        ),
        cwd=resolved_runtime,
        timeout_seconds=30,
        max_stdout_bytes=256 * 1024,
        max_stderr_bytes=256 * 1024,
    )
    if result.returncode != 0:
        raise ValueError("frozen Python runtime import discovery failed")
    try:
        parsed = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("runtime extension inventory is not canonical JSON") from None
    if result.stdout != _canonical(parsed):
        raise ValueError("runtime extension inventory is not canonical JSON")
    if (
        type(parsed) is not dict
        or set(parsed) != {"extension_modules", "runtime_root", "schema_version"}
        or parsed.get("schema_version") != "1.0"
        or parsed.get("runtime_root") != str(resolved_runtime)
        or type(parsed.get("extension_modules")) is not list
    ):
        raise ValueError("runtime extension inventory failed validation")
    raw_modules = parsed["extension_modules"]
    if (
        any(type(item) is not str or not item for item in raw_modules)
        or raw_modules != sorted(raw_modules)
        or len(raw_modules) != len(set(raw_modules))
    ):
        raise ValueError("runtime extension inventory failed validation")
    extension_modules: list[Path] = []
    resolved_seen: set[Path] = set()
    for item in raw_modules:
        if not Path(item).is_absolute():
            raise ValueError("runtime extension inventory failed validation")
        raw = Path(item)
        try:
            resolved = raw.resolve(strict=True)
            relative = resolved.relative_to(resolved_runtime)
        except (OSError, ValueError):
            raise ValueError("runtime extension inventory failed validation") from None
        if (
            str(resolved) != item
            or not resolved.is_file()
            or resolved.suffix != ".so"
            or "lib-dynload" not in relative.parts[:-1]
            or resolved in resolved_seen
        ):
            raise ValueError("runtime extension inventory failed validation")
        resolved_seen.add(resolved)
        extension_modules.append(resolved)
    return tuple(extension_modules)


def _dynamic_library_inspector_path() -> Path:
    try:
        inspector = Path("/usr/bin/ldd").resolve(strict=True)
    except OSError:
        raise ValueError("dynamic library inspector is unavailable") from None
    if not inspector.is_file() or not os.access(inspector, os.X_OK):
        raise ValueError("dynamic library inspector is unavailable")
    return inspector


def _external_dynamic_library_binding(
    raw: Path,
    runtime: Path,
) -> tuple[str, str, str] | None:
    resolved = raw.resolve(strict=True)
    try:
        resolved.relative_to(runtime)
    except ValueError:
        pass
    else:
        return None
    target = raw.as_posix()
    if not resolved.is_file() or not target.startswith(("/lib/", "/lib64/")):
        raise ValueError("dynamic library closure failed validation")
    return target, str(resolved), sha256_file(resolved)


def _dynamic_library_closure(
    runtime: Path,
    python_executable: Path,
) -> tuple[Path, tuple[tuple[str, str, str], ...]]:
    inspector = _dynamic_library_inspector_path()
    extension_modules = _discover_runtime_extension_modules(runtime, python_executable)
    result = run_analyzer_process(
        (str(inspector), str(python_executable), *(str(path) for path in extension_modules)),
        cwd=runtime,
        timeout_seconds=30,
        max_stdout_bytes=2 * 1024 * 1024,
        max_stderr_bytes=256 * 1024,
    )
    if result.returncode != 0:
        raise ValueError("dynamic library closure discovery failed")
    decoded = result.stdout.decode("utf-8")
    if re.search(r"(?:=>\s+)?not found(?:\s|$)", decoded):
        raise ValueError("dynamic library closure is incomplete")
    targets: dict[str, tuple[str, str, str]] = {}
    for match in re.finditer(r"(?:=>\s+)?(/[^\s]+)\s+\(0x[0-9a-fA-F]+\)", decoded):
        raw = Path(match.group(1))
        binding = _external_dynamic_library_binding(raw, runtime)
        if binding is None:
            continue
        target, _source, _digest = binding
        existing = targets.get(target)
        if existing is not None:
            if existing != binding:
                raise ValueError("dynamic library closure failed validation")
            continue
        targets[target] = binding
    if not targets or not any("ld-linux" in target for target in targets):
        raise ValueError("dynamic library closure is incomplete")
    return inspector, tuple(targets[key] for key in sorted(targets))


class IsolatedSubprocessExecutorV1:
    """Linux Bubblewrap executor for the four frozen fixture adapters only."""

    _FAKE_TOOL = b"#!/bin/sh\nexit 126\n"
    _RESOURCE_LIMITS = (
        ("address_space_bytes", 1024 * 1024 * 1024),
        ("cpu_seconds", 5),
        ("file_bytes", 16 * 1024 * 1024),
        ("open_files", 64),
        ("processes", 32),
    )

    def __init__(
        self,
        *,
        bwrap_executable: Path,
        python_runtime_root: Path,
        python_relative_executable: str = "bin/python3.12",
        timeout_seconds: float = 15.0,
    ) -> None:
        try:
            if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 60:
                raise ValueError("executor timeout failed validation")
            if not bwrap_executable.is_absolute() or not python_runtime_root.is_absolute():
                raise ValueError("executor runtime paths must be absolute")
            bwrap = bwrap_executable.resolve(strict=True)
            runtime = python_runtime_root.resolve(strict=True)
            if not bwrap.is_file() or not runtime.is_dir() or bwrap.is_symlink():
                raise ValueError("executor runtime path failed validation")
            relative_python = _normalized_relative_path(python_relative_executable)
            python_link = runtime / relative_python
            python_executable = python_link.resolve(strict=True)
            try:
                python_executable.relative_to(runtime)
            except ValueError:
                raise ValueError("Python executable escaped its frozen runtime") from None
            if not python_executable.is_file() or not os.access(python_executable, os.X_OK):
                raise ValueError("Python executable failed validation")
            capabilities = validate_analyzer_runtime()
            if (
                capabilities.platform != "linux"
                or not capabilities.user_namespace
                or not capabilities.pid_namespace
                or not capabilities.mount_namespace
                or not capabilities.private_proc
            ):
                raise ValueError("sealed Linux analyzer runtime is unavailable")
            version_result = run_analyzer_process(
                (str(bwrap), "--version"),
                cwd=bwrap.parent,
                timeout_seconds=5,
                max_stdout_bytes=4096,
                max_stderr_bytes=4096,
            )
            version = version_result.stdout.decode("utf-8").strip()
            if not version.startswith("bubblewrap ") or len(version) > 128:
                raise ValueError("Bubblewrap version failed validation")
            worker_source = (
                Path(__file__)
                .with_name("_executable_functional_worker.py")
                .read_text(encoding="utf-8")
            )
            worker_policy_sha256 = hashlib.sha256(worker_source.encode("utf-8")).hexdigest()
            runtime_sha256 = _runtime_tree_sha256(runtime)
            library_inspector, dynamic_libraries = _dynamic_library_closure(
                runtime,
                python_executable,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise FixtureInfrastructureError("isolated executor initialization failed") from error
        self._bwrap = bwrap
        self._runtime = runtime
        self._python_relative = relative_python
        self._python_in_sandbox = Path("/runtime") / relative_python
        self._timeout_seconds = float(timeout_seconds)
        self._worker_source = worker_source
        self._library_inspector = library_inspector
        self._dynamic_libraries = dynamic_libraries
        capability_names = (
            "bubblewrap_user_namespace",
            "bubblewrap_pid_namespace",
            "bubblewrap_network_namespace",
            "bubblewrap_ipc_namespace",
            "bubblewrap_uts_namespace",
            "sealed_analyzer_user_namespace",
            "sealed_analyzer_pid_namespace",
            "sealed_analyzer_mount_namespace",
            "sealed_analyzer_private_proc",
            "capabilities_dropped",
            "host_root_not_bound",
            "content_addressed_dynamic_library_closure",
            "kernel_seccomp_process_exec_socket_filter",
            "landlock_existing_workspace_write_closure",
            "tmpfs_work_root",
        )
        self.policy = ExecutorPolicy(
            executor_id="isolated-bubblewrap-executor-v1-" + worker_policy_sha256[:16],
            mode="isolated_subprocess_v1",
            executes_generated_code=True,
            executes_in_main_process=False,
            timeout_seconds=float(timeout_seconds),
            isolated_subprocess=True,
            temporary_workspace=True,
            minimal_environment=True,
            virtual_commands_only=True,
            old_root_exposed=False,
            namespace_isolation_enforced=True,
            network_isolation_enforced=True,
            supported_adapter_ids=_CONTROLLED_ADAPTER_IDS,
            sandbox_backend="bubblewrap_v1",
            sandbox_backend_path=str(bwrap),
            sandbox_backend_sha256=sha256_file(bwrap),
            sandbox_backend_version=version,
            python_runtime_root=str(runtime),
            python_runtime_sha256=runtime_sha256,
            python_executable_sha256=sha256_file(python_executable),
            worker_policy_sha256=worker_policy_sha256,
            dynamic_library_inspector_path=str(library_inspector),
            dynamic_library_inspector_sha256=sha256_file(library_inspector),
            dynamic_library_bindings=dynamic_libraries,
            runtime_capabilities=capability_names,
            resource_limits=self._RESOURCE_LIMITS,
        )

    def verify_frozen_runtime(self) -> None:
        """Re-attest every host executable or runtime byte named by the policy."""

        try:
            python_executable = self._runtime / self._python_relative
            if (
                sha256_file(self._bwrap) != self.policy.sandbox_backend_sha256
                or sha256_file(python_executable) != self.policy.python_executable_sha256
                or _runtime_tree_sha256(self._runtime) != self.policy.python_runtime_sha256
                or sha256_file(self._library_inspector)
                != self.policy.dynamic_library_inspector_sha256
                or tuple(
                    (target, source, sha256_file(Path(source)))
                    for target, source, _digest in self._dynamic_libraries
                )
                != self._dynamic_libraries
            ):
                raise ValueError("isolated executor runtime changed after policy freeze")
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise FixtureInfrastructureError(
                "isolated executor runtime attestation failed"
            ) from error

    def _fake_bin(self, workspace: Path) -> Path:
        fake_bin = workspace / "fake-bin"
        fake_bin.mkdir(parents=False, exist_ok=False)
        for tool in ("cat", "pdftotext", "sacct", "squeue"):
            path = fake_bin / tool
            _write_bytes_exclusive(path, self._FAKE_TOOL)
            path.chmod(0o500)
        return fake_bin

    def execute(self, invocation: FixtureInvocation) -> LocalExecutionObservation:
        try:
            candidate_relative_path = invocation.candidate_path.relative_to(
                invocation.workspace
            ).as_posix()
            if (
                invocation.adapter_id not in _CONTROLLED_ADAPTER_IDS
                or invocation.adapter_id not in self.policy.supported_adapter_ids
                or invocation.network_allowed
                or invocation.unvirtualized_process_allowed
                or invocation.workspace.resolve() not in invocation.candidate_path.resolve().parents
                or candidate_relative_path != "candidate.py"
                or sha256_file(invocation.candidate_path) != invocation.arm.code_sha256
            ):
                raise ValueError("isolated invocation failed validation")
            workspace = invocation.workspace.resolve(strict=True)
            workspace_files: list[dict[str, object]] = []
            for path in sorted(
                workspace.rglob("*"), key=lambda item: item.relative_to(workspace).as_posix()
            ):
                if path.is_symlink():
                    raise ValueError("fixture workspace symlinks are forbidden")
                if not path.is_file() or path == invocation.candidate_path:
                    continue
                relative = path.relative_to(workspace).as_posix()
                workspace_files.append(
                    {
                        "path": relative,
                        "sha256": sha256_file(path),
                        "bytes": path.stat().st_size,
                    }
                )
            self._fake_bin(workspace)
            library_directories = {
                parent.as_posix()
                for target, _source, _digest in self._dynamic_libraries
                for parent in Path(target).parents
                if parent != Path("/")
            }
            library_mounts: list[str] = []
            for directory in sorted(
                library_directories,
                key=lambda value: (len(Path(value).parts), value),
            ):
                library_mounts.extend(("--dir", directory))
            for target, source, digest in self._dynamic_libraries:
                if sha256_file(Path(source)) != digest:
                    raise ValueError("dynamic library binding changed after policy freeze")
                library_mounts.extend(("--ro-bind", source, target))
            sandbox_bindings = [
                "/runtime:ro",
                *[f"{target}:ro" for target, _source, _digest in self._dynamic_libraries],
                "/fixture-src:ro",
                "/work:tmpfs",
            ]
            config_path = workspace / "executor-config.json"
            config = _isolated_worker_config(
                invocation,
                workspace=workspace,
                workspace_files=workspace_files,
                sandbox_bindings=sandbox_bindings,
                resource_limits=self._RESOURCE_LIMITS,
            )
            _write_json(config_path, config)
            argv = (
                str(self._bwrap),
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                str(self._runtime),
                "/runtime",
                *library_mounts,
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/home",
                "--ro-bind",
                str(workspace),
                "/fixture-src",
                "--tmpfs",
                "/work",
                "--chdir",
                "/work",
                "--clearenv",
                "--setenv",
                "HOME",
                "/work",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--setenv",
                "PATH",
                "/fixture-src/fake-bin",
                "--setenv",
                "PYTHONDONTWRITEBYTECODE",
                "1",
                "--setenv",
                "PYTHONHASHSEED",
                "0",
                "--setenv",
                "PYTHONIOENCODING",
                "utf-8",
                "--setenv",
                "PYTHONUTF8",
                "1",
                "--setenv",
                "SECAWARE_BWRAP_SANDBOX",
                "1",
                str(self._python_in_sandbox),
                "-I",
                "-S",
                "-c",
                self._worker_source,
                "/fixture-src/executor-config.json",
            )
            process = run_analyzer_process(
                argv,
                cwd=workspace,
                timeout_seconds=self._timeout_seconds,
                max_stdout_bytes=1024 * 1024,
                max_stderr_bytes=256 * 1024,
            )
            value = json.loads(process.stdout.decode("utf-8"))
            if _canonical(value) != process.stdout or type(value) is not dict:
                raise ValueError("isolated worker response is not canonical JSON")
            if value.get("status") == "infrastructure_error":
                raise ValueError("isolated worker reported an infrastructure error")
            sandbox = value.get("sandbox")
            kernel_policy = sandbox.get("kernel_policy") if type(sandbox) is dict else None
            expected_bindings = sandbox_bindings
            if (
                value.get("schema_version") != _SCHEMA_VERSION
                or value.get("status") not in {"complete", "candidate_error"}
                or type(sandbox) is not dict
                or sandbox.get("bubblewrap_empty_mount_root") is not True
                or sandbox.get("work_tmpfs") is not True
                or sandbox.get("host_root_read_only_or_hidden") is not True
                or sandbox.get("network_namespace") is not True
                or sandbox.get("capabilities_dropped") is not True
                or type(kernel_policy) is not dict
                or type(kernel_policy.get("landlock_abi")) is not int
                or int(kernel_policy["landlock_abi"]) < 4
                or kernel_policy.get("landlock_existing_work_files_write_only") is not True
                or kernel_policy.get("landlock_file_creation_denied") is not True
                or kernel_policy.get("seccomp_arch") != "AUDIT_ARCH_X86_64"
                or type(kernel_policy.get("seccomp_blocked_syscalls")) is not list
                or not {41, 42, 56, 57, 58, 59, 322, 435}.issubset(
                    set(kernel_policy["seccomp_blocked_syscalls"])
                )
                or sandbox.get("bindings") != expected_bindings
                or sandbox.get("path") != "/fixture-src/fake-bin"
                or value.get("resource_limits")
                != {key: limit for key, limit in self._RESOURCE_LIMITS}
            ):
                raise ValueError("isolated worker attestation failed validation")
            events = value.get("command_events")
            logs = value.get("logs")
            sqlite_statements = value.get("sqlite_statements")
            returned_workspace_files = value.get("workspace_files")
            if (
                type(events) is not list
                or type(logs) is not list
                or type(sqlite_statements) is not list
                or type(returned_workspace_files) is not list
            ):
                raise ValueError("isolated worker evidence failed validation")
            expected_paths = {str(item["path"]) for item in workspace_files}
            observed_paths: set[str] = set()
            for item in returned_workspace_files:
                if (
                    type(item) is not dict
                    or set(item) != {"path", "sha256", "bytes", "content_base64"}
                    or type(item.get("path")) is not str
                    or not _is_sha256(item.get("sha256"))
                    or type(item.get("bytes")) is not int
                    or type(item.get("content_base64")) is not str
                ):
                    raise ValueError("isolated worker workspace evidence failed validation")
                relative = _normalized_relative_path(str(item["path"]))
                content = base64.b64decode(str(item["content_base64"]), validate=True)
                if (
                    len(content) != item["bytes"]
                    or hashlib.sha256(content).hexdigest() != item["sha256"]
                    or relative.as_posix() in observed_paths
                ):
                    raise ValueError("isolated worker workspace digest failed validation")
                destination = workspace / relative
                if not destination.is_file() or destination.is_symlink():
                    raise ValueError("isolated worker workspace target failed validation")
                destination.write_bytes(content)
                observed_paths.add(relative.as_posix())
            if observed_paths != expected_paths:
                raise ValueError("isolated worker workspace closure failed validation")
            command_events: list[LocalCommandEvent] = []
            for event in events:
                if (
                    type(event) is not dict
                    or set(event)
                    != {
                        "command_id",
                        "argv",
                        "returncode",
                        "stdout_target",
                        "stdout_mode",
                        "file_writes",
                    }
                    or type(event.get("argv")) is not list
                    or type(event.get("file_writes")) is not list
                ):
                    raise ValueError("isolated worker command evidence failed validation")
                command_events.append(
                    LocalCommandEvent(
                        command_id=str(event["command_id"]),
                        argv=tuple(str(item) for item in event["argv"]),
                        returncode=int(event["returncode"]),
                        stdout_target=(
                            str(event["stdout_target"])
                            if event["stdout_target"] is not None
                            else None
                        ),
                        stdout_mode=(
                            str(event["stdout_mode"]) if event["stdout_mode"] is not None else None
                        ),
                        file_writes=tuple(str(item) for item in event["file_writes"]),
                    )
                )
            return LocalExecutionObservation(
                returncode=int(value["returncode"]),
                return_value=value.get("return_value"),
                stdout=base64.b64decode(str(value["stdout_base64"]), validate=True),
                stderr=base64.b64decode(str(value["stderr_base64"]), validate=True),
                command_events=tuple(command_events),
                logs=tuple(str(item) for item in logs),
                sqlite_statements=tuple(str(item) for item in sqlite_statements),
                network_calls=int(value["network_calls"]),
                unvirtualized_process_calls=int(value["unvirtualized_process_calls"]),
                sandbox_attestation=_json_value(sandbox),  # type: ignore[arg-type]
                resource_limits=_json_value(value.get("resource_limits")),  # type: ignore[arg-type]
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise FixtureInfrastructureError("isolated fixture execution failed") from error


def _validate_executor_policy(
    executor: ControlledFixtureExecutor,
    *,
    adapter_ids: set[str],
    allow_test_executor: bool,
    allow_sandbox_limitations: bool,
) -> tuple[dict[str, object], list[str]]:
    policy = getattr(executor, "policy", None)
    if type(policy) is not ExecutorPolicy:
        raise TypeError("controlled executor policy is required")
    if (
        not policy.executor_id
        or type(policy.timeout_seconds) not in {int, float}
        or not 0 < policy.timeout_seconds <= 60
        or policy.executes_in_main_process
        or policy.old_root_exposed
        or not policy.temporary_workspace
        or not policy.minimal_environment
        or not policy.virtual_commands_only
        or not adapter_ids.issubset(set(policy.supported_adapter_ids))
        or not set(policy.supported_adapter_ids).issubset(set(_CONTROLLED_ADAPTER_IDS))
    ):
        raise ValueError("controlled executor policy failed validation")
    if policy.mode == "test_double":
        if not allow_test_executor or policy.executes_generated_code or policy.isolated_subprocess:
            raise ValueError("test-double executor is not authorized")
    elif policy.mode == "isolated_subprocess_v1":
        if (
            not policy.executes_generated_code
            or not policy.isolated_subprocess
            or policy.sandbox_backend != "bubblewrap_v1"
            or type(policy.sandbox_backend_path) is not str
            or not Path(policy.sandbox_backend_path).is_absolute()
            or not _is_sha256(policy.sandbox_backend_sha256)
            or type(policy.sandbox_backend_version) is not str
            or not policy.sandbox_backend_version.startswith("bubblewrap ")
            or type(policy.python_runtime_root) is not str
            or not Path(policy.python_runtime_root).is_absolute()
            or not _is_sha256(policy.python_runtime_sha256)
            or not _is_sha256(policy.python_executable_sha256)
            or not _is_sha256(policy.worker_policy_sha256)
            or type(policy.dynamic_library_inspector_path) is not str
            or not Path(policy.dynamic_library_inspector_path).is_absolute()
            or not _is_sha256(policy.dynamic_library_inspector_sha256)
            or not policy.dynamic_library_bindings
            or any(
                type(target) is not str
                or type(source) is not str
                or not Path(target).is_absolute()
                or not Path(source).is_absolute()
                or not _is_sha256(digest)
                for target, source, digest in policy.dynamic_library_bindings
            )
            or not policy.runtime_capabilities
            or not policy.resource_limits
            or any(
                type(name) is not str or type(limit) is not int or limit <= 0
                for name, limit in policy.resource_limits
            )
        ):
            raise ValueError("isolated executor policy failed validation")
    else:  # pragma: no cover - Literal plus runtime hardening
        raise ValueError("controlled executor mode failed validation")
    limitations: list[str] = []
    if not policy.namespace_isolation_enforced:
        limitations.append("os_namespace_isolation_not_enforced")
    if not policy.network_isolation_enforced:
        limitations.append("network_namespace_isolation_not_enforced")
    if policy.mode != "test_double" and limitations and not allow_sandbox_limitations:
        raise ValueError("isolated executor sandbox limitations require explicit authorization")
    return _executor_policy_payload(policy), limitations


def _normalized_relative_path(value: str) -> Path:
    relative = Path(value)
    if (
        not value
        or relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("arm artifact relative path failed validation")
    return relative


def _read_bound_regular_file(root: Path, relative: Path) -> bytes:
    """Read one regular file without following any path-component symlink on Linux."""

    if os.name != "posix":
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("bound artifact path contains a symbolic link")
        with (root / relative).open("rb") as handle:
            before = os.fstat(handle.fileno())
            content = handle.read()
            after = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("bound artifact changed during compatibility read")
        return content

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        directory_fd = os.open(root, directory_flags)
        descriptors.append(directory_fd)
        for part in relative.parts[:-1]:
            directory_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            descriptors.append(directory_fd)
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        descriptors.append(file_fd)
        before = os.fstat(file_fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("bound artifact changed during no-follow read")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _candidate_source(
    source_root: Path,
    arm: ArmArtifactBinding,
    manifest_entries: Mapping[str, str],
) -> tuple[Path, bytes]:
    if (
        not arm.assignment_id
        or not arm.task_id
        or arm.arm_role not in {"target_patch", "noop_rewrite"}
        or not _is_sha256(arm.artifact_sha256)
        or not _is_sha256(arm.code_sha256)
    ):
        raise ValueError("arm artifact binding failed validation")
    relative = _normalized_relative_path(arm.artifact_relative_path)
    if manifest_entries.get(relative.as_posix()) != arm.artifact_sha256:
        raise ValueError("arm artifact is not bound by the frozen source manifest")
    unresolved = source_root / relative
    artifact = unresolved.resolve(strict=True)
    try:
        artifact.relative_to(source_root)
    except ValueError:
        raise ValueError("arm artifact escaped source root") from None
    if not artifact.is_file():
        raise ValueError("arm artifact path failed validation")
    raw = _read_bound_regular_file(source_root, relative)
    if hashlib.sha256(raw).hexdigest() != arm.artifact_sha256:
        raise ValueError("arm artifact digest failed validation")
    if arm.artifact_format == "raw_source_v1":
        code = raw
        try:
            code.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("raw source artifact is not UTF-8") from None
        if hashlib.sha256(code).hexdigest() != arm.code_sha256:
            raise ValueError("raw source code digest failed validation")
    elif arm.artifact_format == "canonical_generated_code_jsonl_v1":
        lines = [line for line in raw.decode("utf-8").splitlines() if line]
        if len(lines) != 1:
            raise ValueError("generated-code artifact must contain exactly one record")
        record = CanonicalGeneratedCodeRecord.model_validate_json(lines[0])
        role = record.arm_role.value if record.arm_role is not None else None
        if (
            record.assignment_id != arm.assignment_id
            or role != arm.arm_role
            or record.code_sha256 != arm.code_sha256
        ):
            raise ValueError("generated-code coordinates failed validation")
        code = record.code.encode("utf-8")
    else:  # pragma: no cover - Literal plus runtime hardening
        raise ValueError("arm artifact format failed validation")
    return artifact, code


def _functional_contract_source(
    source_root: Path,
    binding: FrozenFunctionalContractBinding,
    manifest_entries: Mapping[str, str],
) -> tuple[Path, dict[str, object]]:
    if (
        not binding.task_id
        or not binding.contract_id
        or not _is_sha256(binding.artifact_sha256)
        or not binding.requirement_ids
        or len(binding.requirement_ids) != len(set(binding.requirement_ids))
    ):
        raise ValueError("functional contract binding failed validation")
    relative = _normalized_relative_path(binding.artifact_relative_path)
    if manifest_entries.get(relative.as_posix()) != binding.artifact_sha256:
        raise ValueError("functional contract is not bound by the frozen source manifest")
    artifact = (source_root / relative).resolve(strict=True)
    try:
        artifact.relative_to(source_root)
    except ValueError:
        raise ValueError("functional contract escaped source root") from None
    raw = _read_bound_regular_file(source_root, relative)
    if hashlib.sha256(raw).hexdigest() != binding.artifact_sha256:
        raise ValueError("functional contract artifact digest failed validation")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise ValueError("functional contract is not UTF-8") from None
    if len(lines) != 1 or not lines[0]:
        raise ValueError("functional contract must contain exactly one record")
    record = TaskFunctionalContractRecord.model_validate_json(lines[0])
    requirement_ids = tuple(item.requirement_id for item in record.requirements)
    if (
        record.task_id != binding.task_id
        or record.contract_id != binding.contract_id
        or requirement_ids != binding.requirement_ids
    ):
        raise ValueError("functional contract coordinates failed validation")
    return artifact, record.model_dump(mode="json")


def _validated_cases(
    source_root: Path,
    cases: Sequence[ExecutableSensitivityCase],
    *,
    source_manifest_path: Path,
    source_snapshot: FrozenSourceSnapshot,
) -> tuple[
    tuple[ExecutableSensitivityCase, ...],
    dict[str, tuple[Path, bytes]],
    dict[str, tuple[FrozenFunctionalContractBinding, dict[str, object]]],
]:
    if not cases or len(cases) > len(_CONTROLLED_ADAPTER_IDS):
        raise ValueError("executable sensitivity case count failed validation")
    result = tuple(cases)
    task_ids: set[str] = set()
    adapter_ids: set[str] = set()
    assignments: set[str] = set()
    sources: dict[str, tuple[Path, bytes]] = {}
    contracts: dict[str, tuple[FrozenFunctionalContractBinding, dict[str, object]]] = {}
    manifest_entries = dict(source_snapshot.entries)
    for case in result:
        adapter = case.adapter
        if (
            not case.task_id
            or not case.family
            or type(adapter) not in _CONTROLLED_ADAPTER_TYPES
            or case.family != adapter.family
            or case.task_id in task_ids
            or adapter.adapter_id in adapter_ids
            or len(case.arms) != 2
            or {arm.arm_role for arm in case.arms} != {"target_patch", "noop_rewrite"}
            or any(arm.task_id != case.task_id for arm in case.arms)
        ):
            raise ValueError("executable sensitivity paired protocol failed validation")
        task_ids.add(case.task_id)
        adapter_ids.add(adapter.adapter_id)
        if case.functional_contract is not None:
            binding = case.functional_contract
            if binding.task_id != case.task_id or binding.requirement_ids != tuple(
                rule.requirement_id for rule in adapter.requirement_rules
            ):
                raise ValueError("functional contract/adapter coordinate failed validation")
            _artifact, contract_record = _functional_contract_source(
                source_root,
                binding,
                manifest_entries,
            )
            contracts[case.task_id] = (binding, contract_record)
            _verify_source_snapshot(source_manifest_path, source_snapshot)
        for arm in case.arms:
            if arm.assignment_id in assignments:
                raise ValueError("executable sensitivity assignment identity is duplicated")
            assignments.add(arm.assignment_id)
            sources[arm.assignment_id] = _candidate_source(
                source_root,
                arm,
                manifest_entries,
            )
            _verify_source_snapshot(source_manifest_path, source_snapshot)
    return result, sources, contracts


def _requirement_verdicts(
    adapter: ExecutableFixtureAdapter,
    checks: Sequence[FunctionalCheck],
) -> list[dict[str, object]]:
    by_id = {item.check_id: item for item in checks}
    verdicts: list[dict[str, object]] = []
    for rule in adapter.requirement_rules:
        if not rule.supporting_check_ids or any(
            item not in by_id for item in rule.supporting_check_ids
        ):
            raise ValueError("adapter requirement mapping failed validation")
        met = all(by_id[item].passed for item in rule.supporting_check_ids)
        verdicts.append(
            {
                "requirement_id": rule.requirement_id,
                "verdict": "met" if met else "not_met",
                "supporting_check_ids": list(rule.supporting_check_ids),
            }
        )
    return verdicts


def _freeze_source_snapshot(
    source_manifest_path: Path,
    verified_manifest: Mapping[str, object],
) -> FrozenSourceSnapshot:
    raw_files = verified_manifest.get("files")
    if type(raw_files) is not list:
        raise ValueError("source manifest entries failed validation")
    entries: list[tuple[str, str]] = []
    for item in raw_files:
        if (
            type(item) is not dict
            or type(item.get("path")) is not str
            or not _is_sha256(item.get("sha256"))
        ):
            raise ValueError("source manifest entry failed validation")
        entries.append((str(item["path"]), str(item["sha256"])))
    return FrozenSourceSnapshot(
        manifest_sha256=sha256_file(source_manifest_path),
        closure_sha256=canonical_sha256(verified_manifest),
        entries=tuple(sorted(entries)),
    )


def _verify_source_snapshot(
    source_manifest_path: Path,
    snapshot: FrozenSourceSnapshot,
) -> None:
    if sha256_file(source_manifest_path) != snapshot.manifest_sha256:
        raise ValueError("frozen source manifest changed during sensitivity execution")
    verified = verify_closed_manifest(
        source_manifest_path,
        label="executable sensitivity source",
    )
    current = _freeze_source_snapshot(source_manifest_path, verified)
    if current != snapshot:
        raise ValueError("frozen source closure changed during sensitivity execution")


def _source_binding_payload(
    snapshot: FrozenSourceSnapshot,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "access_mode": "read_only_verified_before_and_after",
        "source_root_manifest_sha256": snapshot.manifest_sha256,
        "source_root_closure_sha256": snapshot.closure_sha256,
        "listed_files": len(snapshot.entries),
        "listed_paths_sha256": canonical_sha256([path for path, _ in snapshot.entries]),
    }
    return {"source_binding_id": _content_id("source_binding_", payload), **payload}


def _measurement_payload(
    *,
    source_binding: Mapping[str, object],
    arm: ArmArtifactBinding,
    adapter: ExecutableFixtureAdapter,
    executor_policy_sha256: str,
    fixture_payload: Mapping[str, object],
    observation_payload: Mapping[str, object],
    checks: Sequence[FunctionalCheck],
    functional_contract: FrozenFunctionalContractBinding | None,
) -> dict[str, object]:
    requirement_verdicts = _requirement_verdicts(adapter, checks)
    y_f_e = int(
        all(item["verdict"] == "met" for item in requirement_verdicts)
        and all(item.passed for item in checks)
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "record_type": "executable_functional_sensitivity",
        "role": "post_hoc_development_sensitivity_only",
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "functional_variable": "Y_F^E",
        "measurement_method": _MEASUREMENT_METHOD,
        "execution_performed": True,
        "y_f_e": y_f_e,
        "expected_status": "pass" if y_f_e == 1 else "fail",
        "task_id": arm.task_id,
        "assignment_id": arm.assignment_id,
        "arm_role": arm.arm_role,
        "family": adapter.family,
        "adapter_id": adapter.adapter_id,
        "fixture_policy_sha256": adapter.policy_sha256,
        "fixture_instance_sha256": canonical_sha256(fixture_payload),
        "executor_policy_sha256": executor_policy_sha256,
        "source_binding_id": source_binding["source_binding_id"],
        "source_root_manifest_sha256": source_binding["source_root_manifest_sha256"],
        "source_artifact_path": arm.artifact_relative_path,
        "source_artifact_sha256": arm.artifact_sha256,
        "code_sha256": arm.code_sha256,
        "functional_contract_id": (
            functional_contract.contract_id if functional_contract is not None else None
        ),
        "functional_contract_source_path": (
            functional_contract.artifact_relative_path if functional_contract is not None else None
        ),
        "functional_contract_source_sha256": (
            functional_contract.artifact_sha256 if functional_contract is not None else None
        ),
        "functional_requirement_ids": (
            list(functional_contract.requirement_ids) if functional_contract is not None else []
        ),
        "functional_requirement_ids_sha256": canonical_sha256(
            list(functional_contract.requirement_ids) if functional_contract is not None else []
        ),
        "checks": [item.payload() for item in checks],
        "requirement_verdicts": requirement_verdicts,
        "execution_observation_sha256": canonical_sha256(observation_payload),
        "provider_calls": 0,
        "security_oracle_calls": 0,
    }


def _unit_name(case: ExecutableSensitivityCase, arm: ArmArtifactBinding) -> str:
    return canonical_sha256(
        {
            "task_id": case.task_id,
            "adapter_id": case.adapter.adapter_id,
            "assignment_id": arm.assignment_id,
            "arm_role": arm.arm_role,
        }
    )


def run_executable_functional_sensitivity(
    *,
    source_manifest_path: Path,
    output_dir: Path,
    cases: Sequence[ExecutableSensitivityCase],
    executor: ControlledFixtureExecutor,
    command_argv: tuple[str, ...] = (),
    frozen_input_plan: Mapping[str, JsonValue] | None = None,
    allow_test_executor: bool = False,
    allow_sandbox_limitations: bool = False,
) -> dict[str, object]:
    """Execute controlled paired fixtures and publish an immutable sidecar root."""

    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    source_manifest_path = source_manifest_path.resolve()
    source_root = source_manifest_path.parent.resolve()
    try:
        output_dir.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise ValueError("sensitivity output must be outside the frozen source root")
    verified_manifest = verify_closed_manifest(
        source_manifest_path,
        label="executable sensitivity source",
    )
    source_snapshot = _freeze_source_snapshot(source_manifest_path, verified_manifest)
    source_binding = _source_binding_payload(source_snapshot)
    validated_cases, candidate_sources, functional_contracts = _validated_cases(
        source_root,
        cases,
        source_manifest_path=source_manifest_path,
        source_snapshot=source_snapshot,
    )
    adapter_ids = {case.adapter.adapter_id for case in validated_cases}
    executor_policy, sandbox_limitations = _validate_executor_policy(
        executor,
        adapter_ids=adapter_ids,
        allow_test_executor=allow_test_executor,
        allow_sandbox_limitations=allow_sandbox_limitations,
    )
    executor_policy_sha256 = canonical_sha256(executor_policy)
    if executor.policy.mode == "isolated_subprocess_v1" and len(functional_contracts) != len(
        validated_cases
    ):
        raise ValueError("production executable sensitivity requires frozen functional contracts")
    runtime_verifier = None
    if executor.policy.mode == "isolated_subprocess_v1":
        runtime_verifier = getattr(executor, "verify_frozen_runtime", None)
        if not callable(runtime_verifier):
            raise ValueError("production executor lacks frozen runtime re-attestation")
    normalized_input_plan = (
        _json_value(frozen_input_plan) if frozen_input_plan is not None else None
    )
    if normalized_input_plan is not None and type(normalized_input_plan) is not dict:
        raise TypeError("frozen input plan must be a JSON object")
    frozen_input_plan_sha256 = (
        canonical_sha256(normalized_input_plan) if normalized_input_plan is not None else None
    )

    output_dir.mkdir(parents=True, exist_ok=False)
    measurement_rows: list[dict[str, object]] = []
    unit_records: list[dict[str, object]] = []
    try:
        if runtime_verifier is not None:
            runtime_verifier()
        _write_json(output_dir / "source-binding.json", source_binding)
        if normalized_input_plan is not None:
            _write_json(output_dir / "frozen-input-plan.json", normalized_input_plan)
        functional_contract_rows = [
            record
            for _binding, record in (
                functional_contracts[key] for key in sorted(functional_contracts)
            )
        ]
        frozen_functional_contracts_sha256: str | None = None
        functional_contract_set_sha256: str | None = None
        if functional_contract_rows:
            _write_jsonl(
                output_dir / "frozen-functional-contracts.jsonl",
                functional_contract_rows,
            )
            frozen_functional_contracts_sha256 = sha256_file(
                output_dir / "frozen-functional-contracts.jsonl"
            )
            functional_contract_set_sha256 = canonical_sha256(
                [
                    {
                        "task_id": binding.task_id,
                        "contract_id": binding.contract_id,
                        "source_artifact_path": binding.artifact_relative_path,
                        "source_artifact_sha256": binding.artifact_sha256,
                        "requirement_ids": list(binding.requirement_ids),
                    }
                    for binding, _record in (
                        functional_contracts[key] for key in sorted(functional_contracts)
                    )
                ]
            )
        _write_json(
            output_dir / "protocol.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "functional_variable": "Y_F^E",
                "measurement_method": _MEASUREMENT_METHOD,
                "execution_performed": True,
                "official_artifact_replacement_allowed": False,
                "scientific_claim_allowed": False,
                "controlled_adapter_ids": sorted(adapter_ids),
                "executor_policy": executor_policy,
                "executor_policy_sha256": executor_policy_sha256,
                "sandbox_limitations": sandbox_limitations,
                "frozen_input_plan_sha256": frozen_input_plan_sha256,
                "frozen_functional_contracts_path": (
                    "frozen-functional-contracts.jsonl" if functional_contract_rows else None
                ),
                "frozen_functional_contracts_sha256": frozen_functional_contracts_sha256,
                "functional_contract_set_sha256": functional_contract_set_sha256,
                "command_argv": list(command_argv),
            },
        )
        for case in sorted(validated_cases, key=lambda item: item.task_id):
            for arm in sorted(case.arms, key=lambda item: item.arm_role):
                unit_dir = output_dir / "units" / _unit_name(case, arm)
                workspace = unit_dir / "workspace"
                workspace.mkdir(parents=True, exist_ok=False)
                _, source = candidate_sources[arm.assignment_id]
                suffix = (
                    ".py"
                    if arm.artifact_format
                    in {
                        "raw_source_v1",
                        "canonical_generated_code_jsonl_v1",
                    }
                    else ".txt"
                )
                candidate_path = workspace / f"candidate{suffix}"
                _write_bytes_exclusive(candidate_path, source)
                if sha256_file(candidate_path) != arm.code_sha256:
                    raise ValueError("candidate workspace copy digest failed validation")
                evaluation = case.adapter.evaluate(
                    workspace=workspace,
                    arm=arm,
                    candidate_path=candidate_path,
                    executor=executor,
                )
                measurement_payload = _measurement_payload(
                    source_binding=source_binding,
                    arm=arm,
                    adapter=case.adapter,
                    executor_policy_sha256=executor_policy_sha256,
                    fixture_payload=evaluation.fixture_payload,
                    observation_payload=evaluation.observation_payload,
                    checks=evaluation.checks,
                    functional_contract=case.functional_contract,
                )
                measurement = {
                    "measurement_id": _content_id(
                        "executable_functional_measurement_", measurement_payload
                    ),
                    **measurement_payload,
                }
                _write_json(unit_dir / "fixture.json", evaluation.fixture_payload)
                _write_json(unit_dir / "execution-observation.json", evaluation.observation_payload)
                _write_json(unit_dir / "measurement.json", measurement)
                write_closed_manifest_atomic(unit_dir, label="executable sensitivity unit")
                measurement_rows.append(measurement)
                unit_records.append(
                    {
                        "task_id": case.task_id,
                        "assignment_id": arm.assignment_id,
                        "arm_role": arm.arm_role,
                        "family": case.family,
                        "adapter_id": case.adapter.adapter_id,
                        "code_path": candidate_path.relative_to(output_dir).as_posix(),
                        "code_sha256": arm.code_sha256,
                        "source_artifact_path": arm.artifact_relative_path,
                        "source_artifact_sha256": arm.artifact_sha256,
                        "measurement_path": (unit_dir / "measurement.json")
                        .relative_to(output_dir)
                        .as_posix(),
                        "measurement_sha256": sha256_file(unit_dir / "measurement.json"),
                        "unit_manifest_path": (unit_dir / "artifact-manifest.json")
                        .relative_to(output_dir)
                        .as_posix(),
                        "unit_manifest_sha256": sha256_file(unit_dir / "artifact-manifest.json"),
                        "fixture_policy_sha256": case.adapter.policy_sha256,
                        "functional_contract_id": (
                            case.functional_contract.contract_id
                            if case.functional_contract is not None
                            else None
                        ),
                        "functional_contract_source_path": (
                            case.functional_contract.artifact_relative_path
                            if case.functional_contract is not None
                            else None
                        ),
                        "functional_contract_source_sha256": (
                            case.functional_contract.artifact_sha256
                            if case.functional_contract is not None
                            else None
                        ),
                        "functional_requirement_ids": (
                            list(case.functional_contract.requirement_ids)
                            if case.functional_contract is not None
                            else []
                        ),
                        "functional_requirement_ids_sha256": canonical_sha256(
                            list(case.functional_contract.requirement_ids)
                            if case.functional_contract is not None
                            else []
                        ),
                        "y_f_e": measurement["y_f_e"],
                        "expected_status": measurement["expected_status"],
                    }
                )

        _verify_source_snapshot(source_manifest_path, source_snapshot)
        evidence_content = {
            "schema_version": _SCHEMA_VERSION,
            "role": "judge_tune_overlay_transitive_evidence",
            "source_root_manifest_sha256": source_binding["source_root_manifest_sha256"],
            "frozen_functional_contracts_path": (
                "frozen-functional-contracts.jsonl" if functional_contract_rows else None
            ),
            "frozen_functional_contracts_sha256": frozen_functional_contracts_sha256,
            "functional_contract_set_sha256": functional_contract_set_sha256,
            "units": [
                {
                    "assignment_id": item["assignment_id"],
                    "measurement_path": item["measurement_path"],
                    "measurement_sha256": item["measurement_sha256"],
                    "code_path": item["code_path"],
                    "code_sha256": item["code_sha256"],
                    "unit_manifest_path": item["unit_manifest_path"],
                    "unit_manifest_sha256": item["unit_manifest_sha256"],
                    "functional_contract_id": item["functional_contract_id"],
                    "functional_contract_source_path": item["functional_contract_source_path"],
                    "functional_contract_source_sha256": item["functional_contract_source_sha256"],
                    "functional_requirement_ids": item["functional_requirement_ids"],
                    "functional_requirement_ids_sha256": item["functional_requirement_ids_sha256"],
                }
                for item in sorted(unit_records, key=lambda value: str(value["assignment_id"]))
            ],
        }
        evidence_manifest = {
            "overlay_evidence_id": _content_id("overlay_evidence_", evidence_content),
            **evidence_content,
        }
        _write_json(output_dir / "overlay-evidence-manifest.json", evidence_manifest)
        overlay_evidence_manifest_sha256 = sha256_file(
            output_dir / "overlay-evidence-manifest.json"
        )
        tune_rows: list[dict[str, object]] = []
        for item in sorted(unit_records, key=lambda value: str(value["assignment_id"])):
            paired_payload = {
                "task_id": item["task_id"],
                "family": item["family"],
                "adapter_id": item["adapter_id"],
                "fixture_policy_sha256": item["fixture_policy_sha256"],
            }
            content = {
                "schema_version": _SCHEMA_VERSION,
                "task_id": item["task_id"],
                "assignment_id": item["assignment_id"],
                "arm_role": item["arm_role"],
                "family": item["family"],
                "adapter_id": item["adapter_id"],
                "code_path": item["code_path"],
                "code_sha256": item["code_sha256"],
                "source_artifact_path": item["source_artifact_path"],
                "source_artifact_sha256": item["source_artifact_sha256"],
                "source_root_manifest_sha256": source_binding["source_root_manifest_sha256"],
                "expected_status": item["expected_status"],
                "y_f_e": item["y_f_e"],
                "split": "tune",
                "paired_group_id": _content_id("functional_pair_", paired_payload),
                "equivalence_group": None,
                "functional_contract_id": item["functional_contract_id"],
                "functional_contract_source_path": item["functional_contract_source_path"],
                "functional_contract_source_sha256": item["functional_contract_source_sha256"],
                "functional_requirement_ids": item["functional_requirement_ids"],
                "functional_requirement_ids_sha256": item["functional_requirement_ids_sha256"],
                "frozen_functional_contracts_path": (
                    "frozen-functional-contracts.jsonl" if functional_contract_rows else None
                ),
                "frozen_functional_contracts_sha256": frozen_functional_contracts_sha256,
                "functional_contract_set_sha256": functional_contract_set_sha256,
                "measurement_path": item["measurement_path"],
                "measurement_sha256": item["measurement_sha256"],
                "fixture_policy_sha256": item["fixture_policy_sha256"],
                "overlay_evidence_manifest_sha256": overlay_evidence_manifest_sha256,
            }
            tune_rows.append({"case_id": _content_id("judge_tune_case_", content), **content})
        _write_jsonl(output_dir / "judge-tune-cases.jsonl", tune_rows)
        by_task: list[dict[str, object]] = []
        for case in sorted(validated_cases, key=lambda item: item.task_id):
            rows = [item for item in measurement_rows if item["task_id"] == case.task_id]
            target = next(item for item in rows if item["arm_role"] == "target_patch")
            noop = next(item for item in rows if item["arm_role"] == "noop_rewrite")
            by_task.append(
                {
                    "task_id": case.task_id,
                    "family": case.family,
                    "adapter_id": case.adapter.adapter_id,
                    "target_y_f_e": target["y_f_e"],
                    "noop_y_f_e": noop["y_f_e"],
                    "paired_target_minus_noop": int(target["y_f_e"]) - int(noop["y_f_e"]),
                }
            )
        report_content = {
            "schema_version": _SCHEMA_VERSION,
            "status": "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE",
            "role": "post_hoc_development_sensitivity_only",
            "scientific_claim_allowed": False,
            "official_artifact_replacement_allowed": False,
            "functional_variable": "Y_F^E",
            "measurement_method": _MEASUREMENT_METHOD,
            "execution_performed": True,
            "source_binding_id": source_binding["source_binding_id"],
            "source_root_manifest_sha256": source_binding["source_root_manifest_sha256"],
            "executor_policy_sha256": executor_policy_sha256,
            "frozen_input_plan_sha256": frozen_input_plan_sha256,
            "frozen_functional_contracts_path": (
                "frozen-functional-contracts.jsonl" if functional_contract_rows else None
            ),
            "frozen_functional_contracts_sha256": frozen_functional_contracts_sha256,
            "functional_contract_set_sha256": functional_contract_set_sha256,
            "sandbox_limitations": sandbox_limitations,
            "overlay_evidence_manifest_sha256": overlay_evidence_manifest_sha256,
            "judge_tune_cases_sha256": sha256_file(output_dir / "judge-tune-cases.jsonl"),
            "counts": {
                "tasks": len(validated_cases),
                "assignments": len(measurement_rows),
                "target_assignments": sum(
                    item["arm_role"] == "target_patch" for item in measurement_rows
                ),
                "noop_assignments": sum(
                    item["arm_role"] == "noop_rewrite" for item in measurement_rows
                ),
                "y_f_e_pass": sum(int(item["y_f_e"]) for item in measurement_rows),
                "y_f_e_fail": sum(1 - int(item["y_f_e"]) for item in measurement_rows),
                "judge_tune_cases": len(tune_rows),
                "functional_contracts": len(functional_contract_rows),
                "provider_calls": 0,
                "security_oracle_calls": 0,
            },
            "paired_results": by_task,
        }
        report = {
            "report_id": _content_id("executable_sensitivity_report_", report_content),
            **report_content,
        }
        if runtime_verifier is not None:
            runtime_verifier()
        _verify_source_snapshot(source_manifest_path, source_snapshot)
        _write_json(output_dir / "report.json", report)
        _verify_source_snapshot(source_manifest_path, source_snapshot)
        write_closed_manifest_atomic(output_dir, label="executable sensitivity root")
        return report
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as caught_error:
        failure_error = caught_error
        try:
            _verify_source_snapshot(source_manifest_path, source_snapshot)
        except Exception as source_error:  # noqa: BLE001 - source mutation outranks run failure
            failure_error = source_error
        if not (output_dir / "failure.json").exists():
            _write_json(
                output_dir / "failure.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "status": "EXECUTABLE_FUNCTIONAL_SENSITIVITY_FAILED",
                    "scientific_claim_allowed": False,
                    "official_artifact_replacement_allowed": False,
                    "error": _safe_error(failure_error, output_dir),
                },
            )
        if not (output_dir / "artifact-manifest.json").exists():
            write_closed_manifest_atomic(output_dir, label="failed executable sensitivity root")
        raise


__all__ = [
    "ArmArtifactBinding",
    "ControlledFixtureExecutor",
    "ExecutableSensitivityCase",
    "ExecutorPolicy",
    "FixtureInfrastructureError",
    "FixtureInvocation",
    "FrozenFunctionalContractBinding",
    "GtfFastaAppendCliAdapter",
    "IsolatedSubprocessExecutorV1",
    "LocalCommandEvent",
    "LocalExecutionObservation",
    "PdfPdftotextBagOfWordsAdapter",
    "SQLiteMetadataPragmaAdapter",
    "SlurmSacctSqueueAdapter",
    "VirtualCommandSpec",
    "read_frozen_bag_of_words",
    "run_executable_functional_sensitivity",
]

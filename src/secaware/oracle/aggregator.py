from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Protocol

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.adapter import AnalyzerReport, LocatedAnalyzerFinding
from secaware.oracle.bandit_adapter import bandit_argv, parse_bandit_report
from secaware.oracle.functionality import evaluate_functionality
from secaware.oracle.policy import LoadedOraclePolicy
from secaware.oracle.runner import (
    AnalyzerProcessResult,
    run_analyzer_process,
    validate_analyzer_runtime,
)
from secaware.oracle.semgrep_adapter import semgrep_argv, parse_semgrep_report
from secaware.schema.common import model_shape_is_intact
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord


_STAGE = "oracle"
_CONTRACT_MESSAGE = "generated code input failed Oracle contract validation"
_POLICY_MESSAGE = "loaded Oracle policy failed authentication"
_CONFIG_MESSAGE = "Oracle execution settings failed validation"
_ENGINE_MESSAGE = "Oracle batch execution failed"
_SOURCE_PREFIX = "src_"
_SOURCE_SUFFIX = ".py"
_SEMGREP_POLICY_NAME = ".semgrep-policy.yml"
_BANDIT_POLICY_NAME = ".bandit-policy.json"
_BANDIT_METADATA_NAME = ".bandit-metadata.json"
_MAX_STDOUT_BYTES = 256 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 3600.0
_MAX_BATCH_RECORDS = 100_000


class AnalyzerRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class _ValidatedCode:
    record: CanonicalGeneratedCodeRecord
    functional_ok: bool
    opaque_file: str

    def __repr__(self) -> str:
        return "_ValidatedCode()"


@dataclass(frozen=True, slots=True, repr=False)
class _MaterializedBatch:
    root: Path
    semgrep_policy: Path
    bandit_policy: Path
    expected_files: frozenset[str]

    def __repr__(self) -> str:
        return "_MaterializedBatch()"


def _safe_error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _copy_secaware_error(error: SecAwareError) -> SecAwareError:
    return SecAwareError(
        code=error.code,
        stage=error.stage,
        message=error.message,
        details={},
        retryable=error.retryable,
    )


def _opaque_source_name(request_id: str) -> str:
    payload = b""
    try:
        payload = ("secaware-oracle-v1\x00" + request_id).encode("ascii", errors="strict")
        return f"{_SOURCE_PREFIX}{hashlib.sha256(payload).hexdigest()}{_SOURCE_SUFFIX}"
    finally:
        request_id = ""
        payload = b""


def _snapshot_codes(codes: Iterable[CanonicalGeneratedCodeRecord]) -> tuple[_ValidatedCode, ...]:
    snapshots: list[_ValidatedCode] = []
    request_ids: set[str] = set()
    filenames: set[str] = set()
    item: object = None
    payload: dict[str, object] = {}
    trusted: CanonicalGeneratedCodeRecord | None = None
    functionality: dict[str, bool] = {}
    opaque_file = ""
    failed = False
    control: KeyboardInterrupt | SystemExit | None = None
    try:
        if isinstance(codes, (str, bytes, Mapping)):
            raise TypeError(_CONTRACT_MESSAGE)
        for index, item in enumerate(codes):
            if index >= _MAX_BATCH_RECORDS:
                raise ValueError(_CONTRACT_MESSAGE)
            if (
                type(item) is not CanonicalGeneratedCodeRecord
                or not model_shape_is_intact(item)
            ):
                raise TypeError(_CONTRACT_MESSAGE)
            payload = item.model_dump(mode="python", round_trip=True, warnings=False)
            trusted = CanonicalGeneratedCodeRecord.model_validate(payload)
            payload.clear()
            payload = {}
            functionality = evaluate_functionality(trusted.code)
            if not functionality["syntax_ok"] or not functionality["not_empty"]:
                raise ValueError(_CONTRACT_MESSAGE)
            opaque_file = _opaque_source_name(trusted.request_id)
            if trusted.request_id in request_ids or opaque_file in filenames:
                raise ValueError(_CONTRACT_MESSAGE)
            request_ids.add(trusted.request_id)
            filenames.add(opaque_file)
            snapshots.append(
                _ValidatedCode(
                    record=trusted,
                    functional_ok=functionality["functional_ok"],
                    opaque_file=opaque_file,
                )
            )
            item = None
            trusted = None
            functionality = {}
            opaque_file = ""
        if not snapshots:
            raise ValueError(_CONTRACT_MESSAGE)
        snapshots.sort(key=lambda value: value.record.request_id)
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except Exception:
        failed = True
    finally:
        codes = ()
        item = None
        payload.clear()
        payload = {}
        trusted = None
        functionality = {}
        opaque_file = ""
        request_ids.clear()
        filenames.clear()
    if control is not None:
        snapshots.clear()
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failed:
        snapshots.clear()
        raise _safe_error(ErrorCode.CONTRACT, _CONTRACT_MESSAGE) from None
    return tuple(snapshots)


def _snapshot_policy(policy: LoadedOraclePolicy) -> LoadedOraclePolicy:
    payload: dict[str, object] = {}
    trusted: LoadedOraclePolicy | None = None
    failed = False
    try:
        if type(policy) is not LoadedOraclePolicy or not model_shape_is_intact(policy):
            raise TypeError(_POLICY_MESSAGE)
        payload = policy.model_dump(mode="python", round_trip=True, warnings=False)
        trusted = LoadedOraclePolicy.model_validate(payload)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        policy = None  # type: ignore[assignment]
        payload.clear()
        payload = {}
    if failed or trusted is None:
        trusted = None
        raise _safe_error(ErrorCode.POLICY_MISMATCH, _POLICY_MESSAGE) from None
    return trusted


def _validate_settings(
    semgrep_executable: str,
    bandit_executable: str,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> tuple[str, str, float, int, int]:
    try:
        for value in (semgrep_executable, bandit_executable):
            if (
                type(value) is not str
                or not value
                or value != value.strip()
                or "\x00" in value
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            ):
                raise ValueError(_CONFIG_MESSAGE)
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS
            or type(max_stdout_bytes) is not int
            or not 1 <= max_stdout_bytes <= _MAX_STDOUT_BYTES
            or type(max_stderr_bytes) is not int
            or not 1 <= max_stderr_bytes <= _MAX_STDERR_BYTES
        ):
            raise ValueError(_CONFIG_MESSAGE)
        return (
            semgrep_executable,
            bandit_executable,
            float(timeout_seconds),
            max_stdout_bytes,
            max_stderr_bytes,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _safe_error(ErrorCode.CONFIG, _CONFIG_MESSAGE) from None
    finally:
        semgrep_executable = ""
        bandit_executable = ""


def _write_all(descriptor: int, payload: bytes) -> None:
    view: memoryview | None = None
    offset = 0
    try:
        view = memoryview(payload)
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError(_ENGINE_MESSAGE)
            offset += written
        os.fsync(descriptor)
    finally:
        if view is not None:
            view.release()
        view = None
        payload = b""
        descriptor = -1
        offset = 0


def _materialize_file(root: Path, name: str, payload: bytes) -> Path:
    descriptor = -1
    path: Path | None = None
    before: os.stat_result | None = None
    after: os.stat_result | None = None
    try:
        if (
            type(name) is not str
            or not name
            or Path(name).name != name
            or name in {".", ".."}
        ):
            raise ValueError(_ENGINE_MESSAGE)
        path = root / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o400)
        _write_all(descriptor, payload)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != len(payload)
        ):
            raise OSError(_ENGINE_MESSAGE)
        os.close(descriptor)
        descriptor = -1
        if os.name != "nt":
            os.chmod(path, 0o400, follow_symlinks=False)
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise OSError(_ENGINE_MESSAGE)
        return path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        root = None  # type: ignore[assignment]
        name = ""
        payload = b""
        path = None
        before = None
        after = None


def _materialize_batch(
    codes: tuple[_ValidatedCode, ...],
    policy: LoadedOraclePolicy,
) -> _MaterializedBatch:
    root: Path | None = None
    semgrep_policy: Path | None = None
    bandit_policy: Path | None = None
    code: _ValidatedCode | None = None
    source_payload = b""
    failed = False
    control: KeyboardInterrupt | SystemExit | None = None
    try:
        root = Path(tempfile.mkdtemp(prefix="secaware-oracle-"))
        if os.name != "nt":
            os.chmod(root, 0o700)
        semgrep_policy = _materialize_file(
            root,
            _SEMGREP_POLICY_NAME,
            policy.semgrep_rules_bytes,
        )
        bandit_policy = _materialize_file(
            root,
            _BANDIT_POLICY_NAME,
            policy.bandit_config_bytes,
        )
        _materialize_file(
            root,
            _BANDIT_METADATA_NAME,
            policy.bandit_metadata_bytes,
        )
        for code in codes:
            source_payload = code.record.code.encode("utf-8", errors="strict")
            if hashlib.sha256(source_payload).hexdigest() != code.record.code_sha256:
                raise ValueError(_CONTRACT_MESSAGE)
            _materialize_file(root, code.opaque_file, source_payload)
            source_payload = b""
            code = None
        return _MaterializedBatch(
            root=root,
            semgrep_policy=Path(semgrep_policy.name),
            bandit_policy=Path(bandit_policy.name),
            expected_files=frozenset(item.opaque_file for item in codes),
        )
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except Exception:
        failed = True
    finally:
        codes = ()
        policy = None  # type: ignore[assignment]
        semgrep_policy = None
        bandit_policy = None
        code = None
        source_payload = b""
    if root is not None:
        _remove_batch_tree(root)
        root = None
    if control is not None:
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failed:
        raise _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE) from None
    raise _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE) from None


def _make_writable_and_retry(function: object, path: str, _: object) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    function(path)  # type: ignore[operator]


def _remove_batch_tree(root: Path) -> None:
    try:
        if root.exists():
            shutil.rmtree(root, onerror=_make_writable_and_retry)
    finally:
        root = None  # type: ignore[assignment]


def _aggregate(
    codes: tuple[_ValidatedCode, ...],
    semgrep_report: AnalyzerReport,
    bandit_report: AnalyzerReport,
) -> list[OracleRecord]:
    located: list[LocatedAnalyzerFinding] = []
    by_file: dict[str, list[LocatedAnalyzerFinding]] = {
        item.opaque_file: [] for item in codes
    }
    records: list[OracleRecord] = []
    code: _ValidatedCode | None = None
    findings: tuple[LocatedAnalyzerFinding, ...] = ()
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    try:
        if (
            semgrep_report.analyzer != "semgrep"
            or bandit_report.analyzer != "bandit"
            or semgrep_report.covered_files != tuple(sorted(by_file))
            or bandit_report.covered_files != tuple(sorted(by_file))
        ):
            raise ValueError(_ENGINE_MESSAGE)
        located.extend(semgrep_report.findings)
        located.extend(bandit_report.findings)
        located.sort(key=LocatedAnalyzerFinding.sort_key)
        for finding in located:
            if finding.opaque_file not in by_file:
                raise ValueError(_ENGINE_MESSAGE)
            by_file[finding.opaque_file].append(finding)
        analyzers = (semgrep_report.provenance, bandit_report.provenance)
        for code in codes:
            findings = tuple(by_file[code.opaque_file])
            canonical_findings = tuple(item.record for item in findings)
            severity = (
                max(canonical_findings, key=lambda item: severity_rank[item.severity]).severity
                if canonical_findings
                else "none"
            )
            record = code.record
            records.append(
                OracleRecord(
                    schema_version="1.0",
                    request_id=record.request_id,
                    code_id=record.code_id,
                    code_sha256=record.code_sha256,
                    prompt_id=record.prompt_id,
                    condition=record.condition,
                    model_id=record.model_id,
                    seed_id=record.seed_id,
                    hypothesis_id=record.hypothesis_id,
                    intervention_id=record.intervention_id,
                    parse_ok=True,
                    functional_ok=code.functional_ok,
                    security_label=(
                        SecurityLabel.INSECURE
                        if canonical_findings
                        else SecurityLabel.SECURE
                    ),
                    severity=severity,
                    findings=canonical_findings,
                    analyzers=analyzers,
                )
            )
            code = None
            findings = ()
        return records
    finally:
        codes = ()
        semgrep_report = None  # type: ignore[assignment]
        bandit_report = None  # type: ignore[assignment]
        located.clear()
        located = []
        by_file.clear()
        by_file = {}
        code = None
        findings = ()
        severity_rank = {}
        analyzers = ()
        canonical_findings = ()
        severity = ""
        record = None


def run_oracle_batch(
    codes: Iterable[CanonicalGeneratedCodeRecord],
    policy: LoadedOraclePolicy,
    *,
    semgrep_executable: str = "semgrep",
    bandit_executable: str = "bandit",
    timeout_seconds: float = 120.0,
    max_stdout_bytes: int = 64 * 1024 * 1024,
    max_stderr_bytes: int = 4 * 1024 * 1024,
    runner: AnalyzerRunner = run_analyzer_process,
) -> list[OracleRecord]:
    """Run the two required analyzers over one authenticated canonical batch."""

    validated: tuple[_ValidatedCode, ...] = ()
    trusted_policy: LoadedOraclePolicy | None = None
    batch: _MaterializedBatch | None = None
    semgrep_process: AnalyzerProcessResult | None = None
    bandit_process: AnalyzerProcessResult | None = None
    semgrep_report: AnalyzerReport | None = None
    bandit_report: AnalyzerReport | None = None
    records: list[OracleRecord] | None = None
    failure: SecAwareError | None = None
    control: KeyboardInterrupt | SystemExit | None = None
    cleanup_failed = False
    try:
        validated = _snapshot_codes(codes)
        trusted_policy = _snapshot_policy(policy)
        (
            semgrep_executable,
            bandit_executable,
            timeout_seconds,
            max_stdout_bytes,
            max_stderr_bytes,
        ) = _validate_settings(
            semgrep_executable,
            bandit_executable,
            timeout_seconds,
            max_stdout_bytes,
            max_stderr_bytes,
        )
        validate_analyzer_runtime()
        batch = _materialize_batch(validated, trusted_policy)
        semgrep_process = runner(
            semgrep_argv(
                Path(semgrep_executable),
                batch.semgrep_policy,
                Path("."),
            ),
            cwd=batch.root,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        bandit_process = runner(
            bandit_argv(
                Path(bandit_executable),
                batch.bandit_policy,
                Path("."),
            ),
            cwd=batch.root,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        semgrep_report = parse_semgrep_report(
            semgrep_process.stdout,
            returncode=semgrep_process.returncode,
            expected_files=batch.expected_files,
            version=trusted_policy.semgrep_version,
            policy_sha256=trusted_policy.combined_sha256,
            max_output_bytes=max_stdout_bytes,
        )
        semgrep_process = None
        bandit_report = parse_bandit_report(
            bandit_process.stdout,
            returncode=bandit_process.returncode,
            expected_files=batch.expected_files,
            version=trusted_policy.bandit_version,
            policy_sha256=trusted_policy.combined_sha256,
            constraints=trusted_policy.bandit_constraints,
            max_output_bytes=max_stdout_bytes,
        )
        bandit_process = None
        records = _aggregate(validated, semgrep_report, bandit_report)
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure = _copy_secaware_error(error)
    except Exception:
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    finally:
        if batch is not None:
            try:
                _remove_batch_tree(batch.root)
            except (KeyboardInterrupt, SystemExit) as error:
                if control is None and failure is None:
                    control = error
            except Exception:
                if control is None and failure is None:
                    cleanup_failed = True
        codes = ()
        policy = None  # type: ignore[assignment]
        semgrep_executable = ""
        bandit_executable = ""
        runner = None  # type: ignore[assignment]
        validated = ()
        trusted_policy = None
        batch = None
        semgrep_process = None
        bandit_process = None
        semgrep_report = None
        bandit_report = None
    if control is not None:
        records = None
        failure = None
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if cleanup_failed:
        records = None
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    if failure is not None or records is None:
        records = None
        raised_failure = failure or _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
        failure = None
        raise raised_failure from None
    return records


def run_oracle(code: object) -> object:
    """Temporary lazy shim for pre-Task-6 callers; never used by the batch engine."""

    from secaware.oracle.legacy import run_legacy_oracle

    return run_legacy_oracle(code)  # type: ignore[arg-type]


__all__ = ["AnalyzerRunner", "run_oracle", "run_oracle_batch"]

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Callable, Literal, Protocol

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
from secaware.schema.common import is_valid_model_id, model_shape_is_intact
from secaware.schema.oracle import (
    AnalyzerFindingRecord,
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord


_STAGE = "oracle"
_CONTRACT_MESSAGE = "generated code input failed Oracle contract validation"
_POLICY_MESSAGE = "loaded Oracle policy failed authentication"
_CONFIG_MESSAGE = "Oracle execution settings failed validation"
_ENGINE_MESSAGE = "Oracle batch execution failed"
_MATERIAL_DRIFT_MESSAGE = "Oracle analyzer material changed during execution"
_COORDINATE_MESSAGE = "analyzer finding source coordinates failed validation"
_SOURCE_PREFIX = "src_"
_SOURCE_SUFFIX = ".py"
_SEMGREP_POLICY_NAME = ".semgrep-policy.yml"
_BANDIT_POLICY_NAME = ".bandit-policy.json"
_BANDIT_METADATA_NAME = ".bandit-metadata.json"
_MAX_STDOUT_BYTES = 256 * 1024 * 1024
_MAX_STDERR_BYTES = 64 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 3600.0
_MAX_BATCH_RECORDS = 100_000
_MAX_CLEANUP_ATTEMPTS = 3
_CLEANUP_CONTROL_NOTE = "Oracle cleanup observed an additional control exception"
_CLEANUP_INCOMPLETE_NOTE = "Oracle cleanup remained incomplete after bounded retries"
_CLEANUP_STATUS_ATTRIBUTE = "_secaware_cleanup_status"

_TRUSTED_ANALYZER_REPORT_TYPE = AnalyzerReport
_TRUSTED_LOCATED_FINDING_TYPE = LocatedAnalyzerFinding
_TRUSTED_ANALYZER_FINDING_TYPE = AnalyzerFindingRecord
_TRUSTED_ANALYZER_PROVENANCE_TYPE = AnalyzerProvenanceRecord


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
class OracleCodeInput:
    """Analyzer-facing code input with no randomized-arm coordinates."""

    request_id: str
    code_id: str
    code_sha256: str
    prompt_id: str
    model_id: str
    seed_id: int
    language: str
    code: str

    def __post_init__(self) -> None:
        if (
            type(self.request_id) is not str
            or re.fullmatch(r"req_[0-9a-f]{64}", self.request_id) is None
            or type(self.code_id) is not str
            or re.fullmatch(r"code_[0-9a-f]{64}", self.code_id) is None
            or type(self.code_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.code_sha256) is None
            or type(self.code) is not str
            or not self.code
            or hashlib.sha256(self.code.encode("utf-8")).hexdigest() != self.code_sha256
            or type(self.prompt_id) is not str
            or not self.prompt_id
            or len(self.prompt_id) > 1024
            or type(self.model_id) is not str
            or not is_valid_model_id(self.model_id)
            or type(self.seed_id) is not int
            or not -(2**63) <= self.seed_id <= 2**63 - 1
            or self.language != "python"
        ):
            raise ValueError(_CONTRACT_MESSAGE)

    @classmethod
    def from_canonical(cls, record: CanonicalGeneratedCodeRecord) -> "OracleCodeInput":
        trusted = CanonicalGeneratedCodeRecord.model_validate(
            record.model_dump(mode="python", round_trip=True, warnings=False)
        )
        return cls(
            request_id=trusted.request_id,
            code_id=trusted.code_id,
            code_sha256=trusted.code_sha256,
            prompt_id=trusted.prompt_id,
            model_id=trusted.model_id,
            seed_id=trusted.seed_id,
            language=trusted.generation_request.language,
            code=trusted.code,
        )


@dataclass(frozen=True, slots=True, repr=False)
class OracleCodeAnalysis:
    request_id: str
    code_id: str
    code_sha256: str
    prompt_id: str
    model_id: str
    seed_id: int
    parse_ok: bool
    functional_ok: bool
    security_label: SecurityLabel
    evaluability: OracleEvaluability
    severity: str
    findings: tuple[AnalyzerFindingRecord, ...]
    analyzers: tuple[AnalyzerProvenanceRecord, ...]


_TRUSTED_ORACLE_CODE_ANALYSIS_TYPE = OracleCodeAnalysis


@dataclass(frozen=True, slots=True, repr=False)
class _ValidatedCode:
    record: CanonicalGeneratedCodeRecord | OracleCodeInput
    parse_ok: bool
    functional_ok: bool
    opaque_file: str

    def __repr__(self) -> str:
        return "_ValidatedCode()"


@dataclass(frozen=True, slots=True, repr=False)
class _MaterializedFile:
    name: str
    sha256: str
    fingerprint: tuple[int, int, int, int, int, int, int]

    def __repr__(self) -> str:
        return "_MaterializedFile()"


@dataclass(frozen=True, slots=True, repr=False)
class _MaterializedBatch:
    root: Path
    analyzer: Literal["semgrep", "bandit"]
    policy: Path
    expected_files: frozenset[str]
    materials: tuple[_MaterializedFile, ...]

    def __repr__(self) -> str:
        return "_MaterializedBatch()"


@dataclass(slots=True, repr=False)
class _WindowsMaterialLeases:
    handles: list[object]
    kernel32: object | None

    def close(self) -> None:
        kernel32 = self.kernel32
        handles = tuple(self.handles)
        if not handles:
            self.kernel32 = None
            return
        if kernel32 is None:
            raise OSError(_ENGINE_MESSAGE)
        first_error: BaseException | None = None
        remaining: list[object] = []
        for handle in handles:
            try:
                if not kernel32.CloseHandle(handle):  # type: ignore[attr-defined]
                    raise OSError(_ENGINE_MESSAGE)
            except BaseException as error:
                remaining.append(handle)
                if first_error is None:
                    first_error = error
            finally:
                handle = None
        self.handles = remaining
        if not remaining:
            self.kernel32 = None
        if first_error is not None:
            raised_error = first_error
            first_error = None
            raise raised_error


def _add_safe_cleanup_note(
    control: MemoryError | KeyboardInterrupt | SystemExit,
    note: str,
) -> None:
    try:
        add_note = getattr(control, "add_note", None)
        if callable(add_note):
            add_note(note)
        else:
            existing = getattr(control, _CLEANUP_STATUS_ATTRIBUTE, ())
            if not isinstance(existing, tuple):
                existing = ()
            setattr(control, _CLEANUP_STATUS_ATTRIBUTE, (*existing, note))
    except BaseException:
        pass
    finally:
        control = None  # type: ignore[assignment]
        note = ""
        add_note = None
        existing = ()


def _bounded_cleanup(
    action: Callable[[], None],
    is_complete: Callable[[], bool],
    control: MemoryError | KeyboardInterrupt | SystemExit | None,
) -> tuple[MemoryError | KeyboardInterrupt | SystemExit | None, bool]:
    """Best-effort cleanup with a fixed retry bound and control precedence.

    A persistent ordinary OS failure is reported by the boolean result and is
    later mapped to a safe ANALYZER_FAILED error.  A pre-existing control
    exception retains identity; otherwise the first cleanup control exception
    is propagated after all best-effort attempts have run.
    """

    cleanup_control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    complete = False
    extra_control_noted = False
    try:
        for _attempt in range(_MAX_CLEANUP_ATTEMPTS):
            try:
                complete = bool(is_complete())
            except (MemoryError, KeyboardInterrupt, SystemExit) as caught:
                if control is None and cleanup_control is None:
                    cleanup_control = caught
                elif not extra_control_noted:
                    _add_safe_cleanup_note(
                        control or cleanup_control or caught,
                        _CLEANUP_CONTROL_NOTE,
                    )
                    extra_control_noted = True
                complete = False
            except Exception:
                complete = False
            if complete:
                break
            try:
                action()
            except (MemoryError, KeyboardInterrupt, SystemExit) as caught:
                if control is None and cleanup_control is None:
                    cleanup_control = caught
                elif not extra_control_noted:
                    _add_safe_cleanup_note(
                        control or cleanup_control or caught,
                        _CLEANUP_CONTROL_NOTE,
                    )
                    extra_control_noted = True
            except Exception:
                pass
        try:
            complete = bool(is_complete())
        except (MemoryError, KeyboardInterrupt, SystemExit) as caught:
            if control is None and cleanup_control is None:
                cleanup_control = caught
            elif not extra_control_noted:
                _add_safe_cleanup_note(
                    control or cleanup_control or caught,
                    _CLEANUP_CONTROL_NOTE,
                )
            complete = False
        except Exception:
            complete = False
        effective_control = control or cleanup_control
        if not complete and effective_control is not None:
            _add_safe_cleanup_note(effective_control, _CLEANUP_INCOMPLETE_NOTE)
        return effective_control, not complete
    finally:
        action = None  # type: ignore[assignment]
        is_complete = None  # type: ignore[assignment]
        control = None
        cleanup_control = None
        effective_control = None
        _attempt = 0


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
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    try:
        if isinstance(codes, (str, bytes, Mapping)):
            raise TypeError(_CONTRACT_MESSAGE)
        for index, item in enumerate(codes):
            if index >= _MAX_BATCH_RECORDS:
                raise ValueError(_CONTRACT_MESSAGE)
            if type(item) is not CanonicalGeneratedCodeRecord or not model_shape_is_intact(item):
                raise TypeError(_CONTRACT_MESSAGE)
            payload = item.model_dump(mode="python", round_trip=True, warnings=False)
            trusted = CanonicalGeneratedCodeRecord.model_validate(payload)
            payload.clear()
            payload = {}
            functionality = evaluate_functionality(trusted.code)
            if not functionality["not_empty"]:
                raise ValueError(_CONTRACT_MESSAGE)
            opaque_file = _opaque_source_name(trusted.request_id)
            if trusted.request_id in request_ids or opaque_file in filenames:
                raise ValueError(_CONTRACT_MESSAGE)
            request_ids.add(trusted.request_id)
            filenames.add(opaque_file)
            snapshots.append(
                _ValidatedCode(
                    record=trusted,
                    parse_ok=functionality["syntax_ok"],
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
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
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


def _snapshot_oracle_code_inputs(
    codes: Iterable[OracleCodeInput],
) -> tuple[_ValidatedCode, ...]:
    snapshots: list[_ValidatedCode] = []
    request_ids: set[str] = set()
    try:
        if isinstance(codes, (str, bytes, Mapping)):
            raise TypeError
        for index, item in enumerate(codes):
            if index >= _MAX_BATCH_RECORDS or type(item) is not OracleCodeInput:
                raise ValueError
            trusted = OracleCodeInput(
                request_id=item.request_id,
                code_id=item.code_id,
                code_sha256=item.code_sha256,
                prompt_id=item.prompt_id,
                model_id=item.model_id,
                seed_id=item.seed_id,
                language=item.language,
                code=item.code,
            )
            if trusted.request_id in request_ids:
                raise ValueError
            functionality = evaluate_functionality(trusted.code)
            if not functionality["not_empty"]:
                raise ValueError
            request_ids.add(trusted.request_id)
            snapshots.append(
                _ValidatedCode(
                    record=trusted,
                    parse_ok=functionality["syntax_ok"],
                    functional_ok=functionality["functional_ok"],
                    opaque_file=_opaque_source_name(trusted.request_id),
                )
            )
        if not snapshots:
            raise ValueError
        snapshots.sort(key=lambda value: value.record.request_id)
        return tuple(snapshots)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        snapshots.clear()
        raise
    except Exception:
        snapshots.clear()
        raise _safe_error(ErrorCode.CONTRACT, _CONTRACT_MESSAGE) from None
    finally:
        codes = ()
        request_ids.clear()
        item = None
        trusted = None
        functionality = {}


def _snapshot_policy(policy: LoadedOraclePolicy) -> LoadedOraclePolicy:
    payload: dict[str, object] = {}
    trusted: LoadedOraclePolicy | None = None
    failed = False
    try:
        if type(policy) is not LoadedOraclePolicy or not model_shape_is_intact(policy):
            raise TypeError(_POLICY_MESSAGE)
        payload = policy.model_dump(mode="python", round_trip=True, warnings=False)
        trusted = LoadedOraclePolicy.model_validate(payload)
    except (MemoryError, KeyboardInterrupt, SystemExit):
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
    except (MemoryError, KeyboardInterrupt, SystemExit):
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


def _material_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _materialize_file(root: Path, name: str, payload: bytes) -> _MaterializedFile:
    descriptor = -1
    path: Path | None = None
    before: os.stat_result | None = None
    after: os.stat_result | None = None
    try:
        if type(name) is not str or not name or Path(name).name != name or name in {".", ".."}:
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
        if os.name == "nt":
            os.chmod(path, stat.S_IREAD)
        else:
            os.chmod(path, 0o400, follow_symlinks=False)
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise OSError(_ENGINE_MESSAGE)
        return _MaterializedFile(
            name=name,
            sha256=hashlib.sha256(payload).hexdigest(),
            fingerprint=_material_fingerprint(after),
        )
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
    analyzer: Literal["semgrep", "bandit"],
) -> _MaterializedBatch:
    root: Path | None = None
    policy_path: Path | None = None
    materials: list[_MaterializedFile] = []
    code: _ValidatedCode | None = None
    source_payload = b""
    failed = False
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    try:
        root = Path(tempfile.mkdtemp(prefix="secaware-oracle-"))
        if os.name != "nt":
            os.chmod(root, 0o700)
        if analyzer == "semgrep":
            materials.append(
                _materialize_file(
                    root,
                    _SEMGREP_POLICY_NAME,
                    policy.semgrep_rules_bytes,
                )
            )
            policy_path = Path(_SEMGREP_POLICY_NAME)
        elif analyzer == "bandit":
            materials.append(
                _materialize_file(
                    root,
                    _BANDIT_POLICY_NAME,
                    policy.bandit_config_bytes,
                )
            )
            materials.append(
                _materialize_file(
                    root,
                    _BANDIT_METADATA_NAME,
                    policy.bandit_metadata_bytes,
                )
            )
            policy_path = Path(_BANDIT_POLICY_NAME)
        else:  # pragma: no cover - narrowed by the internal signature
            raise ValueError(_ENGINE_MESSAGE)
        for code in codes:
            source_payload = code.record.code.encode("utf-8", errors="strict")
            if hashlib.sha256(source_payload).hexdigest() != code.record.code_sha256:
                raise ValueError(_CONTRACT_MESSAGE)
            materials.append(_materialize_file(root, code.opaque_file, source_payload))
            source_payload = b""
            code = None
        return _MaterializedBatch(
            root=root,
            analyzer=analyzer,
            policy=policy_path,
            expected_files=frozenset(item.opaque_file for item in codes),
            materials=tuple(sorted(materials, key=lambda item: item.name)),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        control = error
    except Exception:
        failed = True
    finally:
        codes = ()
        policy = None  # type: ignore[assignment]
        analyzer = "semgrep"
        policy_path = None
        materials.clear()
        materials = []
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


def _verify_material_file(
    root: Path,
    expected: _MaterializedFile,
    *,
    exact_fingerprint: bool = True,
) -> bool:
    path: Path | None = None
    descriptor = -1
    digest: object | None = None
    chunk = b""
    before: os.stat_result | None = None
    opened: os.stat_result | None = None
    after_read: os.stat_result | None = None
    after_path: os.stat_result | None = None
    valid = False
    try:
        path = root / expected.name
        before = path.lstat()
        before_fingerprint = _material_fingerprint(before)
        if (
            before_fingerprint != expected.fingerprint
            if exact_fingerprint
            else before_fingerprint[:5] != expected.fingerprint[:5]
        ):
            return False
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        opened_fingerprint = _material_fingerprint(opened)
        if (
            opened_fingerprint[:6] != expected.fingerprint[:6]
            if exact_fingerprint
            else opened_fingerprint[:5] != expected.fingerprint[:5]
        ):
            return False
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)  # type: ignore[union-attr]
            total += len(chunk)
            if total > expected.fingerprint[4]:
                return False
        after_read = os.fstat(descriptor)
        after_path = path.lstat()
        after_read_fingerprint = _material_fingerprint(after_read)
        after_path_fingerprint = _material_fingerprint(after_path)
        fingerprints_valid = (
            after_read_fingerprint == opened_fingerprint
            and after_path_fingerprint == expected.fingerprint
            if exact_fingerprint
            else after_read_fingerprint[:5] == expected.fingerprint[:5]
            and after_path_fingerprint[:5] == expected.fingerprint[:5]
        )
        valid = (
            total == expected.fingerprint[4]
            and digest.hexdigest() == expected.sha256  # type: ignore[union-attr]
            and fingerprints_valid
        )
        return valid
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        root = None  # type: ignore[assignment]
        expected = None  # type: ignore[assignment]
        path = None
        descriptor = -1
        digest = None
        chunk = b""
        before = None
        opened = None
        after_read = None
        after_path = None
        valid = False
        before_fingerprint = ()
        opened_fingerprint = ()
        after_read_fingerprint = ()
        after_path_fingerprint = ()
        fingerprints_valid = False


def _verify_materialized_batch(batch: _MaterializedBatch) -> bool:
    material: _MaterializedFile | None = None
    try:
        root_metadata = batch.root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            return False
        for material in batch.materials:
            if not _verify_material_file(batch.root, material):
                return False
        return True
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
    finally:
        batch = None  # type: ignore[assignment]
        material = None
        root_metadata = None


def _refresh_materialized_batch(batch: _MaterializedBatch) -> _MaterializedBatch | None:
    refreshed: list[_MaterializedFile] = []
    material: _MaterializedFile | None = None
    try:
        for material in batch.materials:
            refreshed_material: _MaterializedFile | None = None
            for _attempt in range(3):
                if not _verify_material_file(
                    batch.root,
                    material,
                    exact_fingerprint=False,
                ):
                    return None
                candidate = _MaterializedFile(
                    name=material.name,
                    sha256=material.sha256,
                    fingerprint=_material_fingerprint((batch.root / material.name).lstat()),
                )
                if _verify_material_file(batch.root, candidate):
                    refreshed_material = candidate
                    break
            if refreshed_material is None:
                return None
            refreshed.append(refreshed_material)
            material = None
        return _MaterializedBatch(
            root=batch.root,
            analyzer=batch.analyzer,
            policy=batch.policy,
            expected_files=batch.expected_files,
            materials=tuple(refreshed),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None
    finally:
        batch = None  # type: ignore[assignment]
        refreshed.clear()
        refreshed = []
        material = None
        refreshed_material = None
        candidate = None
        _attempt = 0


def _open_windows_material_leases(batch: _MaterializedBatch) -> _WindowsMaterialLeases:
    leases = _WindowsMaterialLeases([], None)
    path: Path | None = None
    cleanup_control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    cleanup_failed = False
    try:
        if os.name != "nt":
            return leases
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        leases.kernel32 = kernel32
        for material in batch.materials:
            path = batch.root / material.name
            handle = create_file(
                str(path),
                0x80000000,  # GENERIC_READ
                0x00000001,  # FILE_SHARE_READ: deny write and delete opens
                None,
                3,  # OPEN_EXISTING
                0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
                None,
            )
            if not handle or int(handle) == -1:
                raise OSError(_ENGINE_MESSAGE)
            leases.handles.append(handle)
        return leases
    except BaseException as error:
        primary_control = (
            error if isinstance(error, (MemoryError, KeyboardInterrupt, SystemExit)) else None
        )
        cleanup_control, cleanup_failed = _bounded_cleanup(
            leases.close,
            lambda: not leases.handles,
            primary_control,
        )
        if cleanup_control is not None:
            cleanup_control.__traceback__ = None
            raised_control = cleanup_control
            cleanup_control = None
            raise raised_control
        if cleanup_failed:
            raise OSError(_ENGINE_MESSAGE) from None
        raise
    finally:
        batch = None  # type: ignore[assignment]
        path = None
        primary_control = None
        cleanup_control = None
        cleanup_failed = False


def _invoke_materialized_analyzer(
    batch: _MaterializedBatch,
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    runner: AnalyzerRunner,
) -> AnalyzerProcessResult:
    leases = _WindowsMaterialLeases([], None)
    result: AnalyzerProcessResult | None = None
    failure: SecAwareError | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    drift = False
    cleanup_failed = False
    try:
        # Windows leases deny write/delete for the entire analyzer call.  Linux's
        # analyzer namespace currently uses cwd for HOME/TMP, so a read-only bind
        # mount would also deny required analyzer scratch writes.  On Linux the
        # before/after seal includes inode, mode, size, mtime, ctime, and SHA-256:
        # replace/restore changes the inode, while unprivileged rewrite/restore
        # cannot restore ctime even when bytes and mtime are deliberately restored.
        refreshed_batch = _refresh_materialized_batch(batch)
        if refreshed_batch is None:
            drift = True
        else:
            batch = refreshed_batch
        if not drift:
            leases = _open_windows_material_leases(batch)
            result = runner(
                argv,
                cwd=batch.root,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure = _copy_secaware_error(error)
    except Exception:
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    finally:
        try:
            if not _verify_materialized_batch(batch):
                drift = True
        except (MemoryError, KeyboardInterrupt, SystemExit) as error:
            if control is None:
                control = error
        except Exception:
            drift = True
        control, cleanup_failed = _bounded_cleanup(
            leases.close,
            lambda: not leases.handles,
            control,
        )
        batch = None  # type: ignore[assignment]
        argv = ()
        timeout_seconds = 0.0
        max_stdout_bytes = 0
        max_stderr_bytes = 0
        runner = None  # type: ignore[assignment]
        leases = _WindowsMaterialLeases([], None)
        refreshed_batch = None
    if control is not None:
        result = None
        failure = None
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if cleanup_failed:
        result = None
        failure = None
        raise _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE) from None
    if drift:
        result = None
        failure = None
        raise _safe_error(
            ErrorCode.ANALYZER_INVALID_OUTPUT,
            _MATERIAL_DRIFT_MESSAGE,
        ) from None
    if failure is not None or result is None:
        result = None
        raised_failure = failure or _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
        failure = None
        raise raised_failure from None
    return result


def _run_private_analyzer_batch(
    analyzer: Literal["semgrep", "bandit"],
    codes: tuple[_ValidatedCode, ...],
    policy: LoadedOraclePolicy,
    executable: str,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    runner: AnalyzerRunner,
) -> AnalyzerProcessResult:
    batch: _MaterializedBatch | None = None
    result: AnalyzerProcessResult | None = None
    failure: SecAwareError | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    cleanup_failed = False
    cleanup_root: Path | None = None
    try:
        batch = _materialize_batch(codes, policy, analyzer)
        argv = (
            semgrep_argv(Path(executable), batch.policy, Path("."))
            if analyzer == "semgrep"
            else bandit_argv(Path(executable), batch.policy, Path("."))
        )
        result = _invoke_materialized_analyzer(
            batch,
            argv,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure = _copy_secaware_error(error)
    except Exception:
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    finally:
        if batch is not None:
            cleanup_root = batch.root
            control, cleanup_failed = _bounded_cleanup(
                lambda: _remove_batch_tree(cleanup_root),  # type: ignore[arg-type]
                lambda: cleanup_root is None or not cleanup_root.exists(),
                control,
            )
        analyzer = "semgrep"
        codes = ()
        policy = None  # type: ignore[assignment]
        executable = ""
        timeout_seconds = 0.0
        max_stdout_bytes = 0
        max_stderr_bytes = 0
        runner = None  # type: ignore[assignment]
        batch = None
        cleanup_root = None
        argv = ()
    if control is not None:
        result = None
        failure = None
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if cleanup_failed:
        result = None
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    if failure is not None or result is None:
        result = None
        raised_failure = failure or _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
        failure = None
        raise raised_failure from None
    return result


def _make_writable_and_retry(function: object, path: str, _: object) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    function(path)  # type: ignore[operator]


def _remove_batch_tree(root: Path) -> None:
    try:
        if root.exists():
            shutil.rmtree(root, onerror=_make_writable_and_retry)
    finally:
        root = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True, repr=False)
class _SourceLine:
    global_start: int
    byte_length: int
    boundaries: frozenset[int]

    def __repr__(self) -> str:
        return "_SourceLine()"


def _source_lines(code: str) -> tuple[_SourceLine, ...] | None:
    encoded = b""
    content = b""
    text = ""
    lines: list[_SourceLine] = []
    boundaries: set[int] = set()
    start = 0
    index = 0
    failed = False
    try:
        encoded = code.encode("utf-8", errors="strict")

        def append_line(end: int) -> None:
            nonlocal content, text, boundaries
            content = encoded[start:end]
            text = content.decode("utf-8", errors="strict")
            boundaries = {0}
            offset = 0
            for character in text:
                offset += len(character.encode("utf-8", errors="strict"))
                boundaries.add(offset)
            lines.append(
                _SourceLine(
                    global_start=start,
                    byte_length=len(content),
                    boundaries=frozenset(boundaries),
                )
            )
            content = b""
            text = ""
            boundaries.clear()
            boundaries = set()

        while index < len(encoded):
            if encoded[index] == 0x0A:
                append_line(index)
                index += 1
                start = index
            elif encoded[index] == 0x0D:
                append_line(index)
                index += 2 if index + 1 < len(encoded) and encoded[index + 1] == 0x0A else 1
                start = index
            else:
                index += 1
        if start < len(encoded):
            append_line(len(encoded))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        code = ""
        encoded = b""
        content = b""
        text = ""
        boundaries.clear()
        boundaries = set()
        start = 0
        index = 0
    if failed or not lines:
        lines.clear()
        return None
    return tuple(lines)


def _finding_matches_source(
    finding: LocatedAnalyzerFinding,
    lines: tuple[_SourceLine, ...],
) -> bool:
    start_line: _SourceLine | None = None
    end_line: _SourceLine | None = None
    start_index = -1
    end_index = -1
    try:
        record = finding.record
        if not 1 <= record.line <= len(lines) or not 1 <= record.end_line <= len(lines):
            return False
        start_line = lines[record.line - 1]
        end_line = lines[record.end_line - 1]
        start_index = record.column - 1
        end_index = record.end_column - 1
        if (
            start_index < 0
            or end_index < 0
            or start_index > start_line.byte_length
            or end_index > end_line.byte_length
            or start_index not in start_line.boundaries
            or end_index not in end_line.boundaries
            or (record.end_line, end_index) < (record.line, start_index)
        ):
            return False
        expected_start = start_line.global_start + start_index
        expected_end = end_line.global_start + end_index
        if finding.analyzer == "semgrep":
            return (
                type(finding.start_offset) is int
                and type(finding.end_offset) is int
                and finding.start_offset == expected_start
                and finding.end_offset == expected_end
            )
        return finding.start_offset is None and finding.end_offset is None
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False
    finally:
        finding = None  # type: ignore[assignment]
        lines = ()
        start_line = None
        end_line = None
        start_index = -1
        end_index = -1
        record = None
        expected_start = -1
        expected_end = -1


def _validate_report_coordinates(
    codes: tuple[_ValidatedCode, ...],
    reports: tuple[AnalyzerReport, AnalyzerReport],
) -> None:
    source_lines: dict[str, tuple[_SourceLine, ...]] = {}
    code: _ValidatedCode | None = None
    report: AnalyzerReport | None = None
    finding: LocatedAnalyzerFinding | None = None
    failed = False
    try:
        for code in codes:
            lines = _source_lines(code.record.code)
            if lines is None:
                failed = True
                break
            source_lines[code.opaque_file] = lines
            code = None
        if not failed:
            for report in reports:
                for finding in report.findings:
                    lines = source_lines.get(finding.opaque_file)
                    if lines is None or not _finding_matches_source(finding, lines):
                        failed = True
                        break
                    finding = None
                if failed:
                    break
                report = None
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        failed = True
    finally:
        codes = ()
        reports = ()  # type: ignore[assignment]
        source_lines.clear()
        source_lines = {}
        code = None
        report = None
        finding = None
        lines = None
    if failed:
        raise _safe_error(
            ErrorCode.ANALYZER_INVALID_OUTPUT,
            _COORDINATE_MESSAGE,
        ) from None


def _snapshot_analyzer_report(
    report: AnalyzerReport,
    *,
    analyzer: Literal["semgrep", "bandit"],
    expected_files: frozenset[str],
) -> AnalyzerReport:
    """Rebuild an adapter report using the authenticated DTO definitions."""

    try:
        if (
            type(report) is not _TRUSTED_ANALYZER_REPORT_TYPE
            or type(report.covered_files) is not tuple
            or report.covered_files != tuple(sorted(expected_files))
            or report.analyzer != analyzer
            or type(report.provenance) is not _TRUSTED_ANALYZER_PROVENANCE_TYPE
            or not model_shape_is_intact(report.provenance)
            or report.provenance.analyzer != analyzer
            or type(report.findings) is not tuple
        ):
            raise ValueError
        provenance = _TRUSTED_ANALYZER_PROVENANCE_TYPE.model_validate(
            report.provenance.model_dump(mode="python", round_trip=True, warnings=False)
        )
        findings: list[LocatedAnalyzerFinding] = []
        for located in report.findings:
            if (
                type(located) is not _TRUSTED_LOCATED_FINDING_TYPE
                or type(located.opaque_file) is not str
                or located.opaque_file not in expected_files
                or type(located.record) is not _TRUSTED_ANALYZER_FINDING_TYPE
                or not model_shape_is_intact(located.record)
                or located.record.analyzer != analyzer
                or (
                    located.start_offset is not None
                    and (type(located.start_offset) is not int or located.start_offset < 0)
                )
                or (
                    located.end_offset is not None
                    and (type(located.end_offset) is not int or located.end_offset < 0)
                )
                or ((located.start_offset is None) != (located.end_offset is None))
                or (
                    located.start_offset is not None
                    and located.end_offset is not None
                    and located.end_offset < located.start_offset
                )
            ):
                raise ValueError
            record = _TRUSTED_ANALYZER_FINDING_TYPE.model_validate(
                located.record.model_dump(mode="python", round_trip=True, warnings=False)
            )
            findings.append(
                _TRUSTED_LOCATED_FINDING_TYPE(
                    opaque_file=located.opaque_file,
                    record=record,
                    start_offset=located.start_offset,
                    end_offset=located.end_offset,
                )
            )
        trusted_findings = tuple(findings)
        if trusted_findings != tuple(
            sorted(trusted_findings, key=_TRUSTED_LOCATED_FINDING_TYPE.sort_key)
        ) or len({item.identity_key() for item in trusted_findings}) != len(trusted_findings):
            raise ValueError
        return _TRUSTED_ANALYZER_REPORT_TYPE(
            analyzer=analyzer,
            provenance=provenance,
            covered_files=tuple(sorted(expected_files)),
            findings=trusted_findings,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _safe_error(ErrorCode.ANALYZER_INVALID_OUTPUT, _ENGINE_MESSAGE) from None


def validate_oracle_code_analyses(
    analyses: Iterable[OracleCodeAnalysis],
) -> tuple[OracleCodeAnalysis, ...]:
    """Authenticate and rebuild analyzer-only results before coordinate binding."""

    trusted: list[OracleCodeAnalysis] = []
    try:
        if isinstance(analyses, (str, bytes, Mapping)):
            raise ValueError
        for analysis in analyses:
            if (
                type(analysis) is not _TRUSTED_ORACLE_CODE_ANALYSIS_TYPE
                or type(analysis.request_id) is not str
                or re.fullmatch(r"req_[0-9a-f]{64}", analysis.request_id) is None
                or type(analysis.code_id) is not str
                or re.fullmatch(r"code_[0-9a-f]{64}", analysis.code_id) is None
                or type(analysis.code_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", analysis.code_sha256) is None
                or type(analysis.prompt_id) is not str
                or not analysis.prompt_id
                or len(analysis.prompt_id) > 1024
                or type(analysis.model_id) is not str
                or not is_valid_model_id(analysis.model_id)
                or type(analysis.seed_id) is not int
                or not -(2**63) <= analysis.seed_id <= 2**63 - 1
                or type(analysis.parse_ok) is not bool
                or type(analysis.functional_ok) is not bool
                or type(analysis.security_label) is not SecurityLabel
                or type(analysis.evaluability) is not OracleEvaluability
                or type(analysis.severity) is not str
                or type(analysis.findings) is not tuple
                or type(analysis.analyzers) is not tuple
                or len(analysis.analyzers) != 2
            ):
                raise ValueError
            provenances = tuple(
                _TRUSTED_ANALYZER_PROVENANCE_TYPE.model_validate(
                    value.model_dump(mode="python", round_trip=True, warnings=False)
                )
                for value in analysis.analyzers
                if type(value) is _TRUSTED_ANALYZER_PROVENANCE_TYPE and model_shape_is_intact(value)
            )
            findings = tuple(
                _TRUSTED_ANALYZER_FINDING_TYPE.model_validate(
                    value.model_dump(mode="python", round_trip=True, warnings=False)
                )
                for value in analysis.findings
                if type(value) is _TRUSTED_ANALYZER_FINDING_TYPE and model_shape_is_intact(value)
            )
            if (
                len(provenances) != len(analysis.analyzers)
                or tuple(item.analyzer for item in provenances) != ("semgrep", "bandit")
                or len(findings) != len(analysis.findings)
                or any(item.analyzer not in {"semgrep", "bandit"} for item in findings)
            ):
                raise ValueError
            severity_rank = {"low": 1, "medium": 2, "high": 3}
            expected_severity = (
                max(findings, key=lambda item: severity_rank[item.severity]).severity
                if findings
                else "none"
            )
            expected_security = (
                SecurityLabel.UNKNOWN
                if not analysis.parse_ok
                else SecurityLabel.INSECURE
                if findings
                else SecurityLabel.SECURE
            )
            expected_evaluability = (
                OracleEvaluability.UNKNOWN_PARSE_FAILURE
                if not analysis.parse_ok
                else OracleEvaluability.EVALUABLE
            )
            if (
                (not analysis.parse_ok and findings)
                or analysis.severity != expected_severity
                or analysis.security_label is not expected_security
                or analysis.evaluability is not expected_evaluability
            ):
                raise ValueError
            trusted.append(
                _TRUSTED_ORACLE_CODE_ANALYSIS_TYPE(
                    request_id=analysis.request_id,
                    code_id=analysis.code_id,
                    code_sha256=analysis.code_sha256,
                    prompt_id=analysis.prompt_id,
                    model_id=analysis.model_id,
                    seed_id=analysis.seed_id,
                    parse_ok=analysis.parse_ok,
                    functional_ok=analysis.functional_ok,
                    security_label=expected_security,
                    evaluability=expected_evaluability,
                    severity=expected_severity,
                    findings=findings,
                    analyzers=provenances,
                )
            )
            if len(trusted) > _MAX_BATCH_RECORDS:
                raise ValueError
        if len({item.request_id for item in trusted}) != len(trusted):
            raise ValueError
        return tuple(trusted)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _safe_error(ErrorCode.ANALYZER_INVALID_OUTPUT, _ENGINE_MESSAGE) from None
    finally:
        analyses = ()


def _aggregate(
    codes: tuple[_ValidatedCode, ...],
    semgrep_report: AnalyzerReport,
    bandit_report: AnalyzerReport,
) -> list[OracleRecord]:
    located: list[LocatedAnalyzerFinding] = []
    by_file: dict[str, list[LocatedAnalyzerFinding]] = {item.opaque_file: [] for item in codes}
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
        _validate_report_coordinates(codes, (semgrep_report, bandit_report))
        located.extend(semgrep_report.findings)
        located.extend(bandit_report.findings)
        located.sort(key=_TRUSTED_LOCATED_FINDING_TYPE.sort_key)
        for finding in located:
            if finding.opaque_file not in by_file:
                raise ValueError(_ENGINE_MESSAGE)
            by_file[finding.opaque_file].append(finding)
        analyzers = (semgrep_report.provenance, bandit_report.provenance)
        for code in codes:
            findings = tuple(by_file[code.opaque_file])
            canonical_findings = tuple(item.record for item in findings)
            if not code.parse_ok and canonical_findings:
                raise ValueError(_ENGINE_MESSAGE)
            severity = (
                max(canonical_findings, key=lambda item: severity_rank[item.severity]).severity
                if canonical_findings
                else "none"
            )
            record = code.record
            records.append(
                OracleRecord(
                    schema_version="1.2",
                    request_id=record.request_id,
                    code_id=record.code_id,
                    code_sha256=record.code_sha256,
                    prompt_id=record.prompt_id,
                    condition=record.condition,
                    model_id=record.model_id,
                    seed_id=record.seed_id,
                    hypothesis_id=record.hypothesis_id,
                    assignment_id=record.assignment_id,
                    target_spec_id=record.target_spec_id,
                    target_instance_id=record.target_instance_id,
                    arm_protocol_id=record.arm_protocol_id,
                    protocol_instance_id=record.protocol_instance_id,
                    variant_id=record.variant_id,
                    arm_role=record.arm_role,
                    parse_ok=code.parse_ok,
                    functional_ok=code.functional_ok,
                    security_label=(
                        SecurityLabel.UNKNOWN
                        if not code.parse_ok
                        else SecurityLabel.INSECURE
                        if canonical_findings
                        else SecurityLabel.SECURE
                    ),
                    evaluability=(
                        OracleEvaluability.UNKNOWN_PARSE_FAILURE
                        if not code.parse_ok
                        else OracleEvaluability.EVALUABLE
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


def _aggregate_code_analyses(
    codes: tuple[_ValidatedCode, ...],
    semgrep_report: AnalyzerReport,
    bandit_report: AnalyzerReport,
) -> list[OracleCodeAnalysis]:
    located: list[LocatedAnalyzerFinding] = []
    by_file: dict[str, list[LocatedAnalyzerFinding]] = {item.opaque_file: [] for item in codes}
    analyses: list[OracleCodeAnalysis] = []
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    try:
        if (
            semgrep_report.analyzer != "semgrep"
            or bandit_report.analyzer != "bandit"
            or semgrep_report.covered_files != tuple(sorted(by_file))
            or bandit_report.covered_files != tuple(sorted(by_file))
        ):
            raise ValueError(_ENGINE_MESSAGE)
        _validate_report_coordinates(codes, (semgrep_report, bandit_report))
        located.extend(semgrep_report.findings)
        located.extend(bandit_report.findings)
        located.sort(key=_TRUSTED_LOCATED_FINDING_TYPE.sort_key)
        for finding in located:
            if finding.opaque_file not in by_file:
                raise ValueError(_ENGINE_MESSAGE)
            by_file[finding.opaque_file].append(finding)
        analyzers = (semgrep_report.provenance, bandit_report.provenance)
        for validated in codes:
            record = validated.record
            if type(record) is not OracleCodeInput:
                raise ValueError(_ENGINE_MESSAGE)
            findings = tuple(by_file[validated.opaque_file])
            canonical_findings = tuple(item.record for item in findings)
            if not validated.parse_ok and canonical_findings:
                raise ValueError(_ENGINE_MESSAGE)
            severity = (
                max(canonical_findings, key=lambda item: severity_rank[item.severity]).severity
                if canonical_findings
                else "none"
            )
            analyses.append(
                _TRUSTED_ORACLE_CODE_ANALYSIS_TYPE(
                    request_id=record.request_id,
                    code_id=record.code_id,
                    code_sha256=record.code_sha256,
                    prompt_id=record.prompt_id,
                    model_id=record.model_id,
                    seed_id=record.seed_id,
                    parse_ok=validated.parse_ok,
                    functional_ok=validated.functional_ok,
                    security_label=(
                        SecurityLabel.UNKNOWN
                        if not validated.parse_ok
                        else SecurityLabel.INSECURE
                        if canonical_findings
                        else SecurityLabel.SECURE
                    ),
                    evaluability=(
                        OracleEvaluability.UNKNOWN_PARSE_FAILURE
                        if not validated.parse_ok
                        else OracleEvaluability.EVALUABLE
                    ),
                    severity=severity,
                    findings=canonical_findings,
                    analyzers=analyzers,
                )
            )
        return analyses
    finally:
        codes = ()
        semgrep_report = None  # type: ignore[assignment]
        bandit_report = None  # type: ignore[assignment]
        located.clear()
        by_file.clear()
        severity_rank = {}
        validated = None
        record = None
        findings = ()
        canonical_findings = ()
        analyzers = ()
        severity = ""


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
    expected_files: frozenset[str] = frozenset()
    semgrep_process: AnalyzerProcessResult | None = None
    bandit_process: AnalyzerProcessResult | None = None
    semgrep_report: AnalyzerReport | None = None
    bandit_report: AnalyzerReport | None = None
    records: list[OracleRecord] | None = None
    failure: SecAwareError | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
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
        expected_files = frozenset(item.opaque_file for item in validated)
        semgrep_process = _run_private_analyzer_batch(
            "semgrep",
            validated,
            trusted_policy,
            semgrep_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        )
        semgrep_report = parse_semgrep_report(
            semgrep_process.stdout,
            returncode=semgrep_process.returncode,
            expected_files=expected_files,
            version=trusted_policy.semgrep_version,
            policy_sha256=trusted_policy.combined_sha256,
            max_output_bytes=max_stdout_bytes,
        )
        semgrep_process = None
        bandit_process = _run_private_analyzer_batch(
            "bandit",
            validated,
            trusted_policy,
            bandit_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        )
        bandit_report = parse_bandit_report(
            bandit_process.stdout,
            returncode=bandit_process.returncode,
            expected_files=expected_files,
            version=trusted_policy.bandit_version,
            policy_sha256=trusted_policy.combined_sha256,
            constraints=trusted_policy.bandit_constraints,
            max_output_bytes=max_stdout_bytes,
        )
        bandit_process = None
        records = _aggregate(validated, semgrep_report, bandit_report)
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure = _copy_secaware_error(error)
    except Exception:
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    finally:
        codes = ()
        policy = None  # type: ignore[assignment]
        semgrep_executable = ""
        bandit_executable = ""
        runner = None  # type: ignore[assignment]
        validated = ()
        trusted_policy = None
        expected_files = frozenset()
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
    if failure is not None or records is None:
        records = None
        raised_failure = failure or _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
        failure = None
        raise raised_failure from None
    return records


def run_oracle_code_batch(
    codes: Iterable[OracleCodeInput],
    policy: LoadedOraclePolicy,
    *,
    semgrep_executable: str,
    bandit_executable: str,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    runner: AnalyzerRunner,
    runtime_validator: Callable[[], object],
) -> list[OracleCodeAnalysis]:
    """Analyze a randomized-coordinate-blind canonical code batch."""

    validated: tuple[_ValidatedCode, ...] = ()
    trusted_policy: LoadedOraclePolicy | None = None
    analyses: list[OracleCodeAnalysis] | None = None
    failure: SecAwareError | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    try:
        validated = _snapshot_oracle_code_inputs(codes)
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
        runtime_validator()
        expected_files = frozenset(item.opaque_file for item in validated)
        semgrep_process = _run_private_analyzer_batch(
            "semgrep",
            validated,
            trusted_policy,
            semgrep_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        )
        semgrep_report = parse_semgrep_report(
            semgrep_process.stdout,
            returncode=semgrep_process.returncode,
            expected_files=expected_files,
            version=trusted_policy.semgrep_version,
            policy_sha256=trusted_policy.combined_sha256,
            max_output_bytes=max_stdout_bytes,
        )
        semgrep_process = None
        bandit_process = _run_private_analyzer_batch(
            "bandit",
            validated,
            trusted_policy,
            bandit_executable,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        )
        bandit_report = parse_bandit_report(
            bandit_process.stdout,
            returncode=bandit_process.returncode,
            expected_files=expected_files,
            version=trusted_policy.bandit_version,
            policy_sha256=trusted_policy.combined_sha256,
            constraints=trusted_policy.bandit_constraints,
            max_output_bytes=max_stdout_bytes,
        )
        bandit_process = None
        semgrep_report = _snapshot_analyzer_report(
            semgrep_report,
            analyzer="semgrep",
            expected_files=expected_files,
        )
        bandit_report = _snapshot_analyzer_report(
            bandit_report,
            analyzer="bandit",
            expected_files=expected_files,
        )
        analyses = _aggregate_code_analyses(validated, semgrep_report, bandit_report)
        analyses = list(validate_oracle_code_analyses(analyses))
    except (MemoryError, KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure = _copy_secaware_error(error)
    except Exception:
        failure = _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
    finally:
        codes = ()
        policy = None  # type: ignore[assignment]
        semgrep_executable = ""
        bandit_executable = ""
        timeout_seconds = 0.0
        max_stdout_bytes = 0
        max_stderr_bytes = 0
        runner = None  # type: ignore[assignment]
        runtime_validator = None  # type: ignore[assignment]
        validated = ()
        trusted_policy = None
        expected_files = frozenset()
        semgrep_process = None
        bandit_process = None
        semgrep_report = None
        bandit_report = None
    if control is not None:
        analyses = None
        failure = None
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure is not None or analyses is None:
        analyses = None
        raised_failure = failure or _safe_error(ErrorCode.ANALYZER_FAILED, _ENGINE_MESSAGE)
        failure = None
        raise raised_failure from None
    return analyses


__all__ = [
    "AnalyzerRunner",
    "OracleCodeAnalysis",
    "OracleCodeInput",
    "run_oracle_batch",
    "run_oracle_code_batch",
    "validate_oracle_code_analyses",
]

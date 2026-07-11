from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path
import tempfile
from typing import BinaryIO

from pydantic import ConfigDict, Field
import typer

from secaware.commands.common import cli_action
from secaware.config import OracleConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.oracle.aggregator import AnalyzerRunner, run_oracle_batch
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.pipeline.artifact import _atomic_write_text, sha256_path
from secaware.pipeline.preflight import run_oracle_preflight
from secaware.schema.common import SafeValidationMixin, VersionedModel
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord


MAX_ORACLE_RECORDS = 1_000_000
MAX_JSONL_LINE_CHARS = 8 * 1024 * 1024
MAX_JSONL_TOTAL_CHARS = 512 * 1024 * 1024
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
TRANSACTION_CLEANUP_ATTEMPTS = 3


class StandaloneOracleSeal(SafeValidationMixin, VersionedModel):
    _safe_validation_message = "standalone Oracle seal validation failed"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    schema_version: str = Field(pattern=r"^1\.0$")
    input_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    semgrep_version: str = Field(pattern=r"^1\.168\.0$")
    bandit_version: str = Field(pattern=r"^1\.9\.4$")


def _error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage="standalone_oracle",
        message=message,
        details={},
        retryable=False,
    )


def _read_codes(path: Path) -> list[CanonicalGeneratedCodeRecord]:
    try:
        records = read_jsonl(
            path,
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
            max_records=MAX_ORACLE_RECORDS,
            max_line_chars=MAX_JSONL_LINE_CHARS,
            max_total_chars=MAX_JSONL_TOTAL_CHARS,
            stage="standalone_oracle",
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return list(records)  # type: ignore[arg-type]
    raise _error(ErrorCode.CONTRACT, "standalone Oracle input is not canonical") from None


def _read_records(path: Path) -> list[OracleRecord]:
    try:
        records = read_jsonl(
            path,
            OracleRecord,
            required=True,
            allow_empty=False,
            max_records=MAX_ORACLE_RECORDS,
            max_line_chars=MAX_JSONL_LINE_CHARS,
            max_total_chars=MAX_JSONL_TOTAL_CHARS,
            stage="standalone_oracle",
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return list(records)  # type: ignore[arg-type]
    raise _error(ErrorCode.CONTRACT, "standalone Oracle output is not canonical") from None


def _seal_path(output: Path) -> Path:
    return output.with_name(output.name + ".sha256")


def _lock_path(output: Path) -> Path:
    return output.with_name(output.name + ".lock")


def _temporary_path(output: Path, suffix: str) -> Path:
    handle: BinaryIO | None = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f".{output.name}.",
            suffix=suffix,
            dir=output.parent,
            delete=False,
        )
        path = Path(handle.name)
        handle.close()
        handle = None
        path.unlink()
        return path
    except OSError:
        raise _error(ErrorCode.CONTRACT, "standalone Oracle transaction is unavailable") from None
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass


def _cleanup_transaction_paths(
    paths: Sequence[Path | None],
) -> KeyboardInterrupt | SystemExit | None:
    pending = list(dict.fromkeys(path for path in paths if path is not None))
    control: KeyboardInterrupt | SystemExit | None = None
    for _ in range(TRANSACTION_CLEANUP_ATTEMPTS):
        remaining: list[Path] = []
        for path in pending:
            try:
                path.unlink(missing_ok=True)
            except (KeyboardInterrupt, SystemExit) as error:
                if control is None:
                    control = error
                remaining.append(path)
            except Exception:
                remaining.append(path)
        pending = remaining
        if not pending:
            break
    return control


def _stale_transaction_paths(output: Path) -> list[Path]:
    stale: list[Path] = []
    for suffix in (
        ".oracle.candidate",
        ".seal.candidate",
        ".output.backup",
        ".seal.backup",
    ):
        try:
            stale.extend(output.parent.glob(f".{output.name}.*{suffix}"))
        except OSError:
            pass
    return stale


class _OutputLease:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: BinaryIO | None = None

    def __enter__(self) -> None:
        handle: BinaryIO | None = None
        try:
            if self.path.is_symlink():
                raise OSError
            handle = self.path.open("a+b")
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.handle = handle
            handle = None
        except (OSError, ValueError):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
            raise _error(ErrorCode.MANIFEST_CONFLICT, "standalone Oracle output is busy") from None

    def __exit__(self, *_: object) -> None:
        handle = self.handle
        self.handle = None
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):
            pass
        finally:
            try:
                handle.close()
            except OSError:
                pass


def _load_existing_seal(path: Path) -> StandaloneOracleSeal:
    payload = b""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
            raise ValueError
        payload = path.read_bytes()
        return StandaloneOracleSeal.model_validate(load_strict_json_bytes(payload))
    except Exception:
        raise _error(ErrorCode.CONTRACT, "existing standalone Oracle seal is invalid") from None
    finally:
        payload = b""


def _verify_existing_pair(
    input_path: Path,
    output: Path,
    seal_path: Path,
    *,
    input_sha256: str,
    policy_sha256: str,
) -> bool:
    output_exists = output.exists()
    seal_exists = seal_path.exists()
    if not output_exists and not seal_exists:
        return False
    if not output_exists or not seal_exists or output.is_symlink() or seal_path.is_symlink():
        raise _error(ErrorCode.CONTRACT, "existing standalone Oracle commit is incomplete")
    try:
        if os.path.samefile(input_path, output):
            raise ValueError
        seal = _load_existing_seal(seal_path)
        if (
            seal.input_sha256 != input_sha256
            or seal.policy_sha256 != policy_sha256
            or seal.output_sha256 != sha256_path(output)
        ):
            raise ValueError
        _read_records(output)
    except SecAwareError:
        raise
    except (OSError, ValueError):
        raise _error(ErrorCode.CONTRACT, "existing standalone Oracle commit is invalid") from None
    return True


def _write_seal(path: Path, seal: StandaloneOracleSeal) -> None:
    try:
        content = json.dumps(
            seal.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        _atomic_write_text(path, content + "\n")
    except (OSError, TypeError, ValueError):
        raise _error(ErrorCode.CONTRACT, "standalone Oracle seal could not be written") from None


def _replace_committed_pair(
    candidate_output: Path,
    candidate_seal: Path,
    output: Path,
    seal_path: Path,
    *,
    had_existing: bool,
) -> tuple[Path | None, Path | None]:
    backup_output = _temporary_path(output, ".output.backup")
    backup_seal = _temporary_path(output, ".seal.backup")
    output_backed_up = False
    seal_backed_up = False
    output_installed = False
    seal_installed = False
    try:
        if had_existing:
            os.replace(output, backup_output)
            output_backed_up = True
            os.replace(seal_path, backup_seal)
            seal_backed_up = True
        os.replace(candidate_output, output)
        output_installed = True
        os.replace(candidate_seal, seal_path)
        seal_installed = True
        if had_existing:
            return backup_output, backup_seal
        return None, None
    except OSError:
        if seal_installed:
            try:
                seal_path.unlink(missing_ok=True)
            except OSError:
                pass
        if output_installed:
            try:
                output.unlink(missing_ok=True)
            except OSError:
                pass
        if seal_backed_up:
            try:
                os.replace(backup_seal, seal_path)
            except OSError:
                pass
        if output_backed_up:
            try:
                os.replace(backup_output, output)
            except OSError:
                pass
        raise _error(ErrorCode.CONTRACT, "standalone Oracle commit could not be replaced") from None
    finally:
        cleanup_paths = [candidate_output, candidate_seal]
        if not (seal_installed and had_existing):
            cleanup_paths.extend((backup_output, backup_seal))
        for path in cleanup_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def _restore_committed_pair(
    output: Path,
    seal_path: Path,
    backup_output: Path | None,
    backup_seal: Path | None,
) -> None:
    try:
        output.unlink(missing_ok=True)
        seal_path.unlink(missing_ok=True)
        if backup_output is not None:
            os.replace(backup_output, output)
        if backup_seal is not None:
            os.replace(backup_seal, seal_path)
    except OSError:
        raise _error(ErrorCode.CONTRACT, "standalone Oracle rollback failed") from None
    finally:
        for path in (backup_output, backup_seal):
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass


def _run_standalone_oracle(
    *,
    input_path: Path,
    output: Path,
    policy_lock: Path,
    semgrep: str,
    bandit: str,
    force: bool,
    timeout_seconds: float = 120.0,
    max_stdout_bytes: int = 64 * 1024 * 1024,
    max_stderr_bytes: int = 4 * 1024 * 1024,
    runner: AnalyzerRunner | None = None,
    runtime_validator: Callable[[], object] | None = None,
) -> None:
    """Analyze an externally authorized canonical input snapshot.

    Unlike the pipeline command, this boundary has no producer manifest. The caller
    authorizes the input file; SecAware binds and rechecks its byte digest around analysis.
    """

    runner = run_analyzer_process if runner is None else runner
    validator = validate_analyzer_runtime if runtime_validator is None else runtime_validator
    candidate_output: Path | None = None
    candidate_seal: Path | None = None
    backup_output: Path | None = None
    backup_seal: Path | None = None
    commit_point = False
    try:
        if input_path.is_symlink():
            raise _error(ErrorCode.CONTRACT, "standalone Oracle paths are invalid")
        input_path = input_path.resolve(strict=True)
        output = Path(os.path.abspath(output))
        output.parent.mkdir(parents=True, exist_ok=True)
        seal_path = _seal_path(output)
        lock_path = _lock_path(output)
        if (
            not input_path.is_file()
            or output == input_path
            or seal_path == input_path
            or lock_path == input_path
            or output.is_symlink()
            or seal_path.is_symlink()
        ):
            raise _error(ErrorCode.CONTRACT, "standalone Oracle paths are invalid")
        config = OracleConfig(
            policy_lock_path=str(policy_lock),
            semgrep_executable=semgrep,
            bandit_executable=bandit,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        with _OutputLease(lock_path):
            stale_control = _cleanup_transaction_paths(
                _stale_transaction_paths(output)
            )
            if stale_control is not None:
                raise stale_control
            initial_policy = run_oracle_preflight(
                config,
                runner=runner,
                runtime_validator=validator,  # type: ignore[arg-type]
            )
            input_sha256 = sha256_path(input_path)
            had_existing = _verify_existing_pair(
                input_path,
                output,
                seal_path,
                input_sha256=input_sha256,
                policy_sha256=initial_policy.combined_sha256,
            )
            if had_existing and not force:
                return
            codes = _read_codes(input_path)
            if sha256_path(input_path) != input_sha256:
                raise _error(ErrorCode.CONTRACT, "standalone Oracle input changed before analysis")
            execution_policy = run_oracle_preflight(
                config,
                runner=runner,
                runtime_validator=validator,  # type: ignore[arg-type]
            )
            if execution_policy.combined_sha256 != initial_policy.combined_sha256:
                raise _error(ErrorCode.POLICY_MISMATCH, "Oracle policy changed before execution")
            records = run_oracle_batch(
                codes,
                execution_policy,
                semgrep_executable=semgrep,
                bandit_executable=bandit,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
                runner=runner,
            )
            if sha256_path(input_path) != input_sha256:
                raise _error(ErrorCode.CONTRACT, "standalone Oracle input changed during analysis")
            candidate_output = _temporary_path(output, ".oracle.candidate")
            candidate_seal = _temporary_path(output, ".seal.candidate")
            write_jsonl(candidate_output, records, stage="standalone_oracle")
            if _read_records(candidate_output) != records:
                raise _error(ErrorCode.CONTRACT, "standalone Oracle readback failed")
            seal = StandaloneOracleSeal(
                schema_version="1.0",
                input_sha256=input_sha256,
                output_sha256=sha256_path(candidate_output),
                policy_sha256=execution_policy.combined_sha256,
                semgrep_version=execution_policy.semgrep_version,
                bandit_version=execution_policy.bandit_version,
            )
            _write_seal(candidate_seal, seal)
            backup_output, backup_seal = _replace_committed_pair(
                candidate_output,
                candidate_seal,
                output,
                seal_path,
                had_existing=had_existing,
            )
            candidate_output = None
            candidate_seal = None
            try:
                committed = _load_existing_seal(seal_path)
                if (
                    committed != seal
                    or committed.output_sha256 != sha256_path(output)
                    or _read_records(output) != records
                ):
                    raise _error(
                        ErrorCode.CONTRACT,
                        "standalone Oracle commit verification failed",
                    )
            except BaseException:
                _restore_committed_pair(
                    output,
                    seal_path,
                    backup_output,
                    backup_seal,
                )
                backup_output = None
                backup_seal = None
                raise
            commit_point = True
            cleanup_control = _cleanup_transaction_paths(
                [backup_output, backup_seal]
            )
            if cleanup_control is not None:
                raise cleanup_control
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error(ErrorCode.CONTRACT, "standalone Oracle execution failed") from None
    finally:
        if not commit_point:
            _cleanup_transaction_paths(
                [candidate_output, candidate_seal, backup_output, backup_seal]
            )
        runner = None
        validator = None


def _public_error(code: ErrorCode) -> SecAwareError:
    messages = {
        ErrorCode.CONFIG: "standalone Oracle configuration is invalid",
        ErrorCode.CONTRACT: "standalone Oracle artifact validation failed",
        ErrorCode.ANALYZER_MISSING: "analyzer executable is unavailable",
        ErrorCode.ANALYZER_FAILED: "analyzer execution failed",
        ErrorCode.ANALYZER_INVALID_OUTPUT: "analyzer output is invalid",
        ErrorCode.POLICY_MISMATCH: "analyzer policy or version does not match",
        ErrorCode.MANIFEST_CONFLICT: "standalone Oracle output is busy",
    }
    if code not in messages:
        code = ErrorCode.ANALYZER_FAILED
    return _error(code, messages[code])


def run_standalone_oracle(
    *,
    input_path: Path,
    output: Path,
    policy_lock: Path,
    semgrep: str,
    bandit: str,
    force: bool,
    timeout_seconds: float = 120.0,
    max_stdout_bytes: int = 64 * 1024 * 1024,
    max_stderr_bytes: int = 4 * 1024 * 1024,
    runner: AnalyzerRunner | None = None,
    runtime_validator: Callable[[], object] | None = None,
) -> None:
    failure_code: ErrorCode | None = None
    control: KeyboardInterrupt | SystemExit | None = None
    try:
        _run_standalone_oracle(
            input_path=input_path,
            output=output,
            policy_lock=policy_lock,
            semgrep=semgrep,
            bandit=bandit,
            force=force,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
            runtime_validator=runtime_validator,
        )
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure_code = error.code
    except Exception:
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        input_path = None  # type: ignore[assignment]
        output = None  # type: ignore[assignment]
        policy_lock = None  # type: ignore[assignment]
        semgrep = ""
        bandit = ""
        runner = None
        runtime_validator = None
    if control is not None:
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure_code is not None:
        raise _public_error(failure_code) from None


app = typer.Typer(help="SecAware standalone security oracle.")


@app.callback()
def main() -> None:
    """Run the SecAware standalone security oracle."""


@app.command("run")
@cli_action
def run_command(
    input_path: Path = typer.Option(..., "--input"),
    output: Path = typer.Option(..., "--output"),
    policy_lock: Path = typer.Option(..., "--policy-lock"),
    semgrep: str = typer.Option("semgrep", "--semgrep"),
    bandit: str = typer.Option("bandit", "--bandit"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    run_standalone_oracle(
        input_path=input_path,
        output=output,
        policy_lock=policy_lock,
        semgrep=semgrep,
        bandit=bandit,
        force=force,
    )


if __name__ == "__main__":
    app()


__all__ = ["StandaloneOracleSeal", "app", "run_standalone_oracle"]

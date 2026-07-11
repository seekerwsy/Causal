import hashlib
import os
import re
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from secaware.config import AppConfig, OpenAICompatibleConfig, OracleConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.oracle.policy import LoadedOraclePolicy, load_policy_bundle
from secaware.oracle.runner import (
    AnalyzerProcessResult,
    run_analyzer_process,
    validate_analyzer_runtime,
)
from secaware.schema.common import StrictModel
from secaware.schema.records import PromptRecord


class PreflightReport(StrictModel):
    prompt_count: int
    discover_count: int
    confirm_count: int
    model_count: int
    seed_count: int
    output_dir: str


class AnalyzerVersionRunner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult: ...


def _error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(code=code, stage="preflight", message=message)


def _normalized_prompt_sha256(prompt: str) -> str:
    normalized = " ".join(prompt.strip().split()).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _oracle_error(code: ErrorCode) -> SecAwareError:
    messages = {
        ErrorCode.ANALYZER_MISSING: "analyzer executable is unavailable",
        ErrorCode.ANALYZER_FAILED: "analyzer runtime is unavailable",
        ErrorCode.ANALYZER_INVALID_OUTPUT: "analyzer version output is invalid",
        ErrorCode.POLICY_MISMATCH: "analyzer policy or version does not match",
    }
    return SecAwareError(
        code=code,
        stage="oracle_preflight",
        message=messages[code],
        details={},
        retryable=False,
    )


def _version_lines(payload: bytes) -> tuple[str, ...] | None:
    decoded = ""
    lines: list[str] = []
    try:
        if type(payload) is not bytes or not payload or len(payload) > 4096:
            return None
        decoded = payload.decode("utf-8", errors="strict")
        if "\x00" in decoded or any(
            ord(character) < 0x20 and character not in "\r\n\t"
            for character in decoded
        ):
            return None
        lines = decoded.splitlines()
        if not lines or any(len(line) > 512 for line in lines):
            return None
        if not lines[0] or lines[0] != lines[0].strip():
            return None
        return tuple(lines)
    except (UnicodeError, ValueError):
        return None
    finally:
        payload = b""
        decoded = ""
        lines.clear()
        lines = []


def _probe_exact_version(
    executable: str,
    expected_line: str,
    *,
    cwd: Path,
    timeout_seconds: float,
    max_stderr_bytes: int,
    runner: AnalyzerVersionRunner,
) -> None:
    result: AnalyzerProcessResult | None = None
    failed_code: ErrorCode | None = None
    lines: tuple[str, ...] | None = None
    bandit_runtime = False
    try:
        result = runner(
            (executable, "--version"),
            cwd=cwd,
            timeout_seconds=min(timeout_seconds, 30.0),
            max_stdout_bytes=4096,
            max_stderr_bytes=min(max_stderr_bytes, 4096),
        )
        if type(result) is not AnalyzerProcessResult or result.returncode != 0:
            failed_code = ErrorCode.ANALYZER_FAILED
        else:
            lines = _version_lines(result.stdout)
            if expected_line.startswith("bandit "):
                bandit_runtime = (
                    lines is not None
                    and len(lines) == 2
                    and lines[0] == expected_line
                    and re.fullmatch(
                        r"  python version = [0-9]+\.[0-9]+\.[0-9]+"
                        r"[A-Za-z0-9.+-]* \([^()\r\n]{1,256}\)"
                        r" \[[^\[\]\r\n]{1,128}\]",
                        lines[1],
                    )
                    is not None
                )
                if not bandit_runtime:
                    failed_code = ErrorCode.POLICY_MISMATCH
            elif lines != (expected_line,):
                failed_code = ErrorCode.POLICY_MISMATCH
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError as error:
        failed_code = error.code
    except Exception:
        failed_code = ErrorCode.ANALYZER_FAILED
    finally:
        executable = ""
        expected_line = ""
        cwd = None  # type: ignore[assignment]
        runner = None  # type: ignore[assignment]
        result = None
        lines = None
        bandit_runtime = False
    if failed_code is not None:
        if failed_code not in {
            ErrorCode.ANALYZER_MISSING,
            ErrorCode.ANALYZER_FAILED,
            ErrorCode.ANALYZER_INVALID_OUTPUT,
            ErrorCode.POLICY_MISMATCH,
        }:
            failed_code = ErrorCode.ANALYZER_FAILED
        raise _oracle_error(failed_code) from None


def run_oracle_preflight(
    config: OracleConfig,
    *,
    runner: AnalyzerVersionRunner = run_analyzer_process,
    runtime_validator: Callable[[], object] = validate_analyzer_runtime,
) -> LoadedOraclePolicy:
    """Authenticate one Oracle runtime without changing general package preflight."""

    policy: LoadedOraclePolicy | None = None
    failure_code: ErrorCode | None = None
    control: KeyboardInterrupt | SystemExit | None = None
    temporary_root = ""
    try:
        runtime_validator()
        policy = load_policy_bundle(config.policy_lock_path)
        with tempfile.TemporaryDirectory(prefix="secaware-version-") as temporary_root:
            cwd = Path(temporary_root)
            _probe_exact_version(
                config.semgrep_executable,
                policy.semgrep_version,
                cwd=cwd,
                timeout_seconds=config.timeout_seconds,
                max_stderr_bytes=config.max_stderr_bytes,
                runner=runner,
            )
            _probe_exact_version(
                config.bandit_executable,
                f"bandit {policy.bandit_version}",
                cwd=cwd,
                timeout_seconds=config.timeout_seconds,
                max_stderr_bytes=config.max_stderr_bytes,
                runner=runner,
            )
    except (KeyboardInterrupt, SystemExit) as error:
        control = error
    except SecAwareError as error:
        failure_code = error.code
    except Exception:
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        config = None  # type: ignore[assignment]
        runner = None  # type: ignore[assignment]
        runtime_validator = None  # type: ignore[assignment]
        cwd = None
        temporary_root = ""
    if control is not None:
        policy = None
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure_code is not None or policy is None:
        policy = None
        if failure_code not in {
            ErrorCode.ANALYZER_MISSING,
            ErrorCode.ANALYZER_FAILED,
            ErrorCode.ANALYZER_INVALID_OUTPUT,
            ErrorCode.POLICY_MISMATCH,
        }:
            failure_code = ErrorCode.ANALYZER_FAILED
        raise _oracle_error(failure_code or ErrorCode.ANALYZER_FAILED) from None
    return policy


def run_preflight(config: AppConfig) -> PreflightReport:
    if config.generation.provider == "openai_compatible":
        provider_config: OpenAICompatibleConfig | None = None
        try:
            provider_config = OpenAICompatibleConfig.model_validate(
                config.generation.openai_compatible
            )
        except Exception:
            pass
        if provider_config is None:
            raise _error(
                ErrorCode.CONFIG,
                "OpenAI-compatible provider configuration is unavailable",
            ) from None
        try:
            credential = os.environ.get(provider_config.api_key_env)
            credential_available = (
                type(credential) is str and bool(credential.strip())
            )
        except Exception:
            credential_available = False
        credential = None
        if not credential_available:
            raise _error(
                ErrorCode.API_AUTH,
                "provider authentication is unavailable",
            )

    prompts = read_jsonl(
        config.data.prompts_path,
        PromptRecord,
        required=True,
        allow_empty=False,
        stage="preflight",
    )
    prompt_ids = [prompt.prompt_id for prompt in prompts]
    if len(set(prompt_ids)) != len(prompt_ids):
        raise _error(ErrorCode.CONTRACT, "prompt_id values must be unique")

    discover_hashes = {
        _normalized_prompt_sha256(prompt.prompt)
        for prompt in prompts
        if prompt.split == "discover"
    }
    confirm_hashes = {
        _normalized_prompt_sha256(prompt.prompt)
        for prompt in prompts
        if prompt.split == "confirm"
    }
    if discover_hashes & confirm_hashes:
        raise _error(
            ErrorCode.CONTRACT,
            "discover and confirm prompts must not have identical normalized text",
        )

    models = config.generation.models
    if not models:
        raise _error(ErrorCode.CONFIG, "generation.models must not be empty")
    if len(set(models)) != len(models):
        raise _error(ErrorCode.CONFIG, "generation.models must not contain duplicates")

    seeds = config.generation.seeds
    if not seeds:
        raise _error(ErrorCode.CONFIG, "generation.seeds must not be empty")
    if len(set(seeds)) != len(seeds):
        raise _error(ErrorCode.CONFIG, "generation.seeds must not contain duplicates")

    if config.generation.provider == "file":
        provider_dir = config.generation.file_provider_dir
        if provider_dir is None or not provider_dir.strip():
            raise _error(
                ErrorCode.CONFIG,
                "generation.file_provider_dir is required for the file provider",
            )
        provider_path = Path(provider_dir)
        if not provider_path.is_dir():
            raise SecAwareError(
                code=ErrorCode.CONTRACT,
                stage="preflight",
                message="file provider directory is unavailable",
                details={"path": str(provider_path)},
            )

    return PreflightReport(
        prompt_count=len(prompts),
        discover_count=sum(prompt.split == "discover" for prompt in prompts),
        confirm_count=sum(prompt.split == "confirm" for prompt in prompts),
        model_count=len(models),
        seed_count=len(seeds),
        output_dir=config.run.output_dir,
    )

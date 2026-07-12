from collections.abc import Sequence
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner, Result

from secaware.cli import app
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.providers import get_provider
from secaware.io.jsonl import write_jsonl
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.preflight import (
    PreflightReport,
    run_oracle_preflight,
    run_preflight,
)
from secaware.schema.records import PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"
CLI_COMMANDS = [
    "preflight",
    "extract-prompt-tsg",
    "generate-observed",
    "plan-generation",
    "import-generation",
    "run-oracle",
    "discover",
    "intervene",
    "generate-counterfactual",
    "confirm",
    "report",
    "run-all",
]


def _prompt(prompt_id: str, split: str, prompt: str) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split=split,
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=prompt,
    )


def _config(
    tmp_path: Path,
    prompts_path: Path,
    *,
    models: list[str] | None = None,
    seeds: list[int] | None = None,
) -> AppConfig:
    return AppConfig.model_validate(
        {
            "run": {
                "name": "preflight-test",
                "output_dir": str(tmp_path / "run-that-must-not-be-created"),
            },
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "models": ["model-a"] if models is None else models,
                "seeds": [7] if seeds is None else seeds,
            },
        }
    )


def _write_valid_prompts(path: Path) -> None:
    write_jsonl(path, [_prompt("prompt-1", "discover", "write a safe helper")])


class _VersionRunner:
    def __init__(
        self,
        *,
        semgrep: bytes = b"1.168.0\n",
        bandit: bytes = (
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
        ),
    ) -> None:
        self.semgrep = semgrep
        self.bandit = bandit
        self.calls: list[tuple[str, ...]] = []
        self.cwds: list[Path] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        del timeout_seconds, max_stdout_bytes, max_stderr_bytes
        call = tuple(argv)
        self.calls.append(call)
        self.cwds.append(cwd)
        assert call[1:] == ("--version",)
        stdout = self.semgrep if "semgrep" in call[0] else self.bandit
        return AnalyzerProcessResult(returncode=0, stdout=stdout, argv_sha256="a" * 64)


def _oracle_config(tmp_path: Path, prompts_path: Path) -> AppConfig:
    config = _config(tmp_path, prompts_path)
    payload = config.model_dump(mode="python")
    payload["oracle"].update(
        policy_lock_path=str(POLICY_LOCK),
        semgrep_executable="semgrep-private",
        bandit_executable="bandit-private",
    )
    return AppConfig.model_validate(payload)


def test_oracle_preflight_validates_runtime_before_analyzer_resolution(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner()

    def unsupported_runtime() -> None:
        raise SecAwareError(
            code=ErrorCode.ANALYZER_FAILED,
            stage="oracle_analyzer",
            message="analyzer runtime is unavailable",
        )

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=unsupported_runtime,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert runner.calls == []


def test_oracle_preflight_authenticates_policy_and_exact_versions(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner()
    runtime_calls = 0

    def supported_runtime() -> None:
        nonlocal runtime_calls
        runtime_calls += 1

    policy = run_oracle_preflight(
        config.oracle,
        runner=runner,
        runtime_validator=supported_runtime,
    )

    assert runtime_calls == 1
    assert policy.semgrep_version == "1.168.0"
    assert policy.bandit_version == "1.9.4"
    assert len(runner.calls) == 2
    assert all(cwd != POLICY_LOCK.parent for cwd in runner.cwds)
    assert all(not cwd.exists() for cwd in runner.cwds)


def test_oracle_preflight_accepts_locked_bandit_1_9_4_version_shape(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(
        bandit=(
            b"bandit 1.9.4\n"
            b"  python version = 3.12.13 (main, Mar  3 2026, 15:01:35) "
            b"[MSC v.1944 64 bit (AMD64)]\n"
        )
    )

    policy = run_oracle_preflight(
        config.oracle,
        runner=runner,
        runtime_validator=lambda: None,
    )

    assert policy.bandit_version == "1.9.4"


@pytest.mark.parametrize(
    ("semgrep", "bandit"),
    [
        (
            b"1.167.0\n",
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
        (
            b"1.168.0\n",
            b"bandit 1.9.3\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
    ],
)
def test_oracle_preflight_rejects_version_drift_without_raw_output(
    tmp_path: Path,
    semgrep: bytes,
    bandit: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(semgrep=semgrep, bandit=bandit)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.POLICY_MISMATCH
    assert semgrep.decode().strip() not in str(exc_info.value)
    assert bandit.decode().splitlines()[0] not in str(exc_info.value)
    assert exc_info.value.details == {}


def test_oracle_preflight_rejects_unrecognized_trailing_version_output(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)
    runner = _VersionRunner(semgrep=b"1.168.0\nPRIVATE-TRAILING-OUTPUT\n")

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT
    assert "PRIVATE-TRAILING-OUTPUT" not in str(exc_info.value)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff\n",
        b"1.168.0\x00\n",
        b"1.168.0\x01\n",
        b" 1.168.0\n",
        b"1.168.0\ntrailing\n",
    ],
)
def test_oracle_preflight_classifies_malformed_version_output_as_invalid(
    tmp_path: Path,
    payload: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=_VersionRunner(semgrep=payload),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT


@pytest.mark.parametrize(
    ("semgrep", "bandit"),
    [
        (
            b"1.167.0\n",
            b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
        (
            b"1.168.0\n",
            b"bandit 1.9.3\n  python version = 3.12.13 (main) [MSC v.1944]\n",
        ),
    ],
)
def test_oracle_preflight_classifies_structurally_valid_version_drift_as_policy_mismatch(
    tmp_path: Path,
    semgrep: bytes,
    bandit: bytes,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config = _oracle_config(tmp_path, prompts_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_preflight(
            config.oracle,
            runner=_VersionRunner(semgrep=semgrep, bandit=bandit),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.POLICY_MISMATCH


def _write_provider_config(
    tmp_path: Path,
    prompts_path: Path,
    *,
    provider: str,
    file_provider_dir: Path | None = None,
    models: list[str] | None = None,
) -> Path:
    config = AppConfig.model_validate(
        {
            "run": {"name": "provider-test", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "provider": provider,
                "models": ["model-a"] if models is None else models,
                "seeds": [7],
                "file_provider_dir": (
                    None if file_provider_dir is None else str(file_provider_dir)
                ),
            },
        }
    )
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    return config_path


def _assert_safe_cli_error(
    result: Result,
    code: ErrorCode,
    *forbidden: str,
) -> None:
    assert result.exit_code == int(code)
    assert f"[{code.name}]" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert "details" not in rendered.lower()
    for value in forbidden:
        assert value not in rendered


def test_demo_preflight_returns_expected_counts() -> None:
    config = load_config(PROJECT_ROOT / "configs" / "demo.yaml")

    report = run_preflight(config)

    assert report == PreflightReport(
        prompt_count=12,
        discover_count=6,
        confirm_count=6,
        model_count=1,
        seed_count=2,
        output_dir="runs/demo",
    )


@pytest.mark.parametrize("artifact_state", ["missing", "empty"])
def test_preflight_rejects_missing_or_empty_prompt_artifact(
    tmp_path: Path,
    artifact_state: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    if artifact_state == "empty":
        prompts_path.write_text("", encoding="utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_rejects_duplicate_prompt_ids(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("duplicate-id", "discover", "first private prompt"),
            _prompt("duplicate-id", "confirm", "second private prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_preflight_rejects_normalized_prompt_overlap_across_splits(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("discover-id", "discover", "  TOP\n secret\tprompt  "),
            _prompt("confirm-id", "confirm", "top secret prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path))

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert "TOP" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("models", "seeds"),
    [
        ([], [1]),
        (["model-a", "model-a"], [1]),
        (["model-a"], []),
        (["model-a"], [1, 1]),
    ],
)
def test_preflight_rejects_empty_or_duplicate_generation_axes(
    tmp_path: Path,
    models: list[str],
    seeds: list[int],
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("discover-id", "discover", "discover prompt"),
            _prompt("confirm-id", "confirm", "confirm prompt"),
        ],
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(_config(tmp_path, prompts_path, models=models, seeds=seeds))

    assert exc_info.value.code is ErrorCode.CONFIG


def test_preflight_cli_succeeds_without_preparing_run_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "preflight-only"

    result = CliRunner().invoke(
        app,
        [
            "preflight",
            "--config",
            str(PROJECT_ROOT / "configs" / "demo.yaml"),
            "--run-dir",
            str(run_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "prompts=12" in result.output
    assert "discover=6" in result.output
    assert "confirm=6" in result.output
    assert "models=1" in result.output
    assert "seeds=2" in result.output
    assert not run_dir.exists()


def test_preflight_cli_maps_contract_error_to_stderr_without_details_or_prompt_text(
    tmp_path: Path,
) -> None:
    secret = "DO-NOT-PRINT-this-private-prompt"
    prompts_path = tmp_path / "private-prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            _prompt("private-id", "discover", secret),
            _prompt("private-id", "confirm", f"different {secret}"),
        ],
    )
    config = _config(tmp_path, prompts_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONTRACT)
    assert "[CONTRACT]" in result.stderr
    rendered = result.output + result.stderr
    assert secret not in rendered
    assert "private-id" not in rendered
    assert str(prompts_path) not in rendered


def test_preflight_cli_maps_missing_config_to_safe_config_error(tmp_path: Path) -> None:
    config_path = tmp_path / "missing-private-config.yaml"

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert str(config_path) not in rendered


@pytest.mark.parametrize(
    ("content", "secret"),
    [
        ("run: [\nprivate: YAML-PARSER-SECRET\n", "YAML-PARSER-SECRET"),
        ("- not\n- a\n- mapping\n", ""),
        (
            "run:\n"
            "  name: private\n"
            "data:\n"
            "  prompts_path: prompts.jsonl\n"
            "unknown_field: VALIDATION-SECRET\n",
            "VALIDATION-SECRET",
        ),
    ],
)
def test_preflight_cli_maps_invalid_config_to_safe_config_error(
    tmp_path: Path,
    content: str,
    secret: str,
) -> None:
    config_path = tmp_path / "private-config.yaml"
    config_path.write_text(content, encoding="utf-8")

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert str(config_path) not in rendered
    if secret:
        assert secret not in rendered


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_every_cli_command_uses_safe_error_boundary(
    tmp_path: Path,
    command: str,
) -> None:
    secret = "top-secret-command-config"
    config_path = tmp_path / "private-config.yaml"
    config_path.write_text(
        f"run:\n  name: private\ndata:\n  prompts_path: prompts.jsonl\nunknown_field: {secret}\n",
        encoding="utf-8",
    )

    args = [command, "--config", str(config_path)]
    if command == "import-generation":
        args.extend(["--results", str(tmp_path / "unused-results.jsonl")])
    result = CliRunner().invoke(app, args)

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert "[CONFIG] config:" in result.stderr
    rendered = result.output + result.stderr
    assert "Traceback" not in rendered
    assert secret not in rendered
    assert str(config_path) not in rendered
    assert "details" not in rendered.lower()


@pytest.mark.parametrize("command", CLI_COMMANDS)
def test_cli_command_help_preserves_declared_signature(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--config" in result.output
    assert "--run-dir" in result.output


def test_unknown_secret_provider_is_a_safe_config_error(tmp_path: Path) -> None:
    secret = "top-secret-provider"
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "run": {"name": "unknown-provider", "output_dir": str(tmp_path / "run")},
                "data": {"prompts_path": str(prompts_path)},
                "generation": {"provider": secret},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONFIG, secret, str(config_path))


def test_get_provider_rejects_unknown_name_without_echoing_it() -> None:
    secret = "top-secret-provider"

    with pytest.raises(SecAwareError) as exc_info:
        get_provider(secret)

    assert exc_info.value.code is ErrorCode.CONFIG
    assert exc_info.value.stage == "generation"
    assert secret not in str(exc_info.value)


def test_run_all_missing_secret_prompts_is_a_safe_contract_error(tmp_path: Path) -> None:
    prompts_path = tmp_path / "top-secret-prompts.jsonl"
    config_path = tmp_path / "config.yaml"
    write_resolved_config(_config(tmp_path, prompts_path), config_path)

    result = CliRunner().invoke(app, ["run-all", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONTRACT, str(prompts_path))


def test_file_provider_missing_directory_fails_preflight_safely(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "top-secret-missing-provider"
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
    )

    result = CliRunner().invoke(app, ["preflight", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONTRACT, str(provider_dir))


def test_file_provider_missing_generated_file_is_a_safe_contract_error(
    tmp_path: Path,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "top-secret-empty-provider"
    provider_dir.mkdir()
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
    )

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(
        result,
        ErrorCode.CONTRACT,
        str(provider_dir),
        "model-a_7.py",
    )


def test_api_provider_stub_is_a_safe_config_error(tmp_path: Path) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    config_path = _write_provider_config(tmp_path, prompts_path, provider="api")

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(result, ErrorCode.CONFIG, "RuntimeError")


@pytest.mark.parametrize("escape_kind", ["traversal", "absolute"])
def test_file_generation_rejects_model_path_escape_safely(
    tmp_path: Path,
    escape_kind: str,
) -> None:
    prompts_path = tmp_path / "prompts.jsonl"
    _write_valid_prompts(prompts_path)
    provider_dir = tmp_path / "provider"
    provider_dir.mkdir()
    if escape_kind == "traversal":
        model_id = "../private/model"
        outside_path = tmp_path / "private" / "model_7.py"
    else:
        outside_stem = tmp_path / "private-absolute" / "model"
        model_id = str(outside_stem)
        outside_path = Path(f"{outside_stem}_7.py")
    outside_path.parent.mkdir(parents=True)
    outside_path.write_text("top-secret outside code\n", encoding="utf-8")
    config_path = _write_provider_config(
        tmp_path,
        prompts_path,
        provider="file",
        file_provider_dir=provider_dir,
        models=[model_id],
    )

    result = CliRunner().invoke(app, ["generate-observed", "--config", str(config_path)])

    _assert_safe_cli_error(
        result,
        ErrorCode.CONTRACT,
        model_id,
        str(outside_path),
        "top-secret",
    )

from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware.cli import app
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.preflight import PreflightReport, run_preflight
from secaware.schema.records import PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_COMMANDS = [
    "preflight",
    "extract-prompt-tsg",
    "generate-observed",
    "extract-code-tsg",
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
        "run:\n"
        "  name: private\n"
        "data:\n"
        "  prompts_path: prompts.jsonl\n"
        f"unknown_field: {secret}\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, [command, "--config", str(config_path)])

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

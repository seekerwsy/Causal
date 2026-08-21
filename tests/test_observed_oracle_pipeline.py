from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app, generate_observed_stage, run_oracle_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io import run_store as run_store_module
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.oracle import OracleEvaluability, OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"


def _config(tmp_path: Path) -> AppConfig:
    prompts_path = tmp_path / "prompts.jsonl"
    attestations_path = tmp_path / "attestations.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-a",
                task_id="task-prompt-a",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="Return one Python function.",
                prompt_role="neutral_baseline",
                counterpart_prompt_id=None,
                oracle_profile_id="python.cwe22.function_parameter_file_read.v1",
            )
        ],
    )
    write_jsonl(attestations_path, [])
    return AppConfig.model_validate(
        {
            "run": {"name": "oracle-cli", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(attestations_path),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
            "generation": {
                "provider": "mock",
                "models": ["model-a"],
                "seeds": [1],
            },
            "oracle": {
                "policy_lock_path": str(POLICY_LOCK),
                "semgrep_executable": "semgrep-private",
                "bandit_executable": "bandit-private",
                "timeout_seconds": 10.0,
                "max_stdout_bytes": 1024 * 1024,
                "max_stderr_bytes": 4096,
            },
        }
    )


def _prepared_observed_store(tmp_path: Path) -> tuple[AppConfig, RunStore]:
    config = _config(tmp_path)
    store = RunStore(config)
    store.prepare()
    generate_observed_stage(config, store, force=False)
    return config, store


class OracleRunner:
    def __init__(
        self,
        *,
        failure: str | None = None,
        finding: str | None = None,
    ) -> None:
        self.failure = failure
        self.finding = finding
        self.calls: list[tuple[str, ...]] = []

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
        analyzer = "semgrep" if "semgrep" in call[0] else "bandit"
        if call[1:] == ("--version",):
            stdout = (
                b"1.168.0\n"
                if analyzer == "semgrep"
                else (
                    b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
                )
            )
            return AnalyzerProcessResult(0, stdout, "a" * 64)
        if self.failure == analyzer:
            raise SecAwareError(
                code=ErrorCode.ANALYZER_FAILED,
                stage="oracle_analyzer",
                message="analyzer process did not complete successfully",
            )
        files = sorted(path.name for path in cwd.iterdir() if path.suffix == ".py")
        if analyzer == "semgrep":
            results: list[dict[str, object]] = []
            if self.finding == "semgrep":
                results.append(
                    {
                        "check_id": "secaware.python.command-injection",
                        "path": files[0],
                        "start": {"line": 1, "col": 1, "offset": 0},
                        "end": {"line": 1, "col": 4, "offset": 3},
                        "extra": {
                            "message": "discarded",
                            "metadata": {"cwe": "CWE-78"},
                            "severity": "ERROR",
                            "is_ignored": False,
                        },
                    }
                )
            payload = {
                "version": "1.168.0",
                "results": results,
                "errors": [],
                "paths": {"scanned": files},
                "skipped_rules": [],
            }
        else:
            metrics = {filename: {"loc": 2, "nosec": 0, "skipped_tests": 0} for filename in files}
            metrics["_totals"] = {"loc": 2, "nosec": 0, "skipped_tests": 0}
            payload = {"errors": [], "metrics": metrics, "results": []}
        return AnalyzerProcessResult(
            0,
            json.dumps(payload).encode("utf-8"),
            "a" * 64,
        )


@pytest.fixture(autouse=True)
def _engine_runtime_is_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aggregator_module, "validate_analyzer_runtime", lambda: None)


def test_observed_oracle_binds_policy_and_publishes_canonical_records(
    tmp_path: Path,
) -> None:
    config, store = _prepared_observed_store(tmp_path)
    runner = OracleRunner()

    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=runner,
        runtime_validator=lambda: None,
    )

    policy = load_policy_bundle(POLICY_LOCK)
    manifest = read_stage_manifest(store.path(".stages", "run-oracle-observed.json"))
    records = read_jsonl(
        store.path("oracle", "observed_oracle.jsonl"),
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    assert manifest.policy_sha256 == policy.combined_sha256
    assert all(record.security_label is SecurityLabel.UNKNOWN for record in records)
    assert all(
        record.evaluability is OracleEvaluability.UNKNOWN_COVERAGE for record in records
    )
    assert len([call for call in runner.calls if call[1:] != ("--version",)]) == 2


def test_observed_oracle_requires_the_named_committed_code_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_store(tmp_path)
    code_path = store.path("generation", "observed_code.jsonl")
    actual_digest = sha256_path(code_path)
    runner = OracleRunner()

    @contextmanager
    def forged_hold(stage: str, outputs: Sequence[Path]):
        del stage, outputs
        yield {
            "generation/observed_code.jsonl": "b" * 64,
            "generation/unrelated.jsonl": actual_digest,
        }

    monkeypatch.setattr(store, "hold_committed_output", forged_hold)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not [call for call in runner.calls if call[1:] != ("--version",)]


def test_observed_oracle_analyzer_failure_leaves_no_output_or_manifest(
    tmp_path: Path,
) -> None:
    config, store = _prepared_observed_store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert not store.path("oracle", "observed_oracle.jsonl").exists()
    assert not store.path(".stages", "run-oracle-observed.json").exists()


def test_observed_oracle_skip_and_force_are_policy_bound(tmp_path: Path) -> None:
    config, store = _prepared_observed_store(tmp_path)
    runner = OracleRunner()
    kwargs = {
        "condition": "observed",
        "runner": runner,
        "runtime_validator": lambda: None,
    }
    run_oracle_stage(config, store, force=False, **kwargs)
    output = store.path("oracle", "observed_oracle.jsonl")
    first_hash = sha256_path(output)
    analysis_calls = len([call for call in runner.calls if call[1:] != ("--version",)])

    run_oracle_stage(config, store, force=False, **kwargs)
    assert len([call for call in runner.calls if call[1:] != ("--version",)]) == analysis_calls
    assert sha256_path(output) == first_hash

    run_oracle_stage(config, store, force=True, **kwargs)
    assert len([call for call in runner.calls if call[1:] != ("--version",)]) == analysis_calls + 2


def test_observed_oracle_force_failure_preserves_previous_commit(
    tmp_path: Path,
) -> None:
    config, store = _prepared_observed_store(tmp_path)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=OracleRunner(),
        runtime_validator=lambda: None,
    )
    output = store.path("oracle", "observed_oracle.jsonl")
    manifest_path = store.path(".stages", "run-oracle-observed.json")
    previous = (output.read_bytes(), manifest_path.read_bytes())

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=True,
            runner=OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert (output.read_bytes(), manifest_path.read_bytes()) == previous
    assert not list(output.parent.glob(".*.oracle.candidate"))


def test_observed_oracle_manifest_failure_restores_previous_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_store(tmp_path)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=OracleRunner(),
        runtime_validator=lambda: None,
    )
    output = store.path("oracle", "observed_oracle.jsonl")
    manifest_path = store.path(".stages", "run-oracle-observed.json")
    previous = (output.read_bytes(), manifest_path.read_bytes())
    real_write = run_store_module.write_stage_manifest

    def write_then_fail(path: Path, manifest: object) -> None:
        real_write(path, manifest)  # type: ignore[arg-type]
        raise OSError("private-manifest-commit-failure")

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_fail)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=True,
            runner=OracleRunner(finding="semgrep"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert (output.read_bytes(), manifest_path.read_bytes()) == previous


def test_run_oracle_rejects_nonfinal_condition_before_preflight(tmp_path: Path) -> None:
    config, store = _prepared_observed_store(tmp_path)
    runner = OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="counterfactual",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    assert runner.calls == []


def test_run_oracle_cli_rejects_invalid_condition_before_config_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = False

    def forbidden_load(config: Path, run_dir: Path | None) -> object:
        nonlocal loaded
        del config, run_dir
        loaded = True
        raise AssertionError("configuration must not be loaded")

    monkeypatch.setattr(cli_module, "_load", forbidden_load)
    result = CliRunner().invoke(
        app,
        [
            "run-oracle",
            "--config",
            "private-config.yaml",
            "--condition",
            "invalid",
        ],
    )

    assert result.exit_code == int(ErrorCode.CONFIG)
    assert loaded is False
    assert not hasattr(cli_module, "confirm_stage")
    assert not hasattr(cli_module, "generate_counterfactual_stage")

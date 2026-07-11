from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager
import hashlib
from importlib import metadata
import json
from pathlib import Path
import threading
import traceback

import pytest
from typer.testing import CliRunner

from secaware import cli as pipeline_cli
from secaware.cli import app as pipeline_app
from secaware.cli import (
    confirm_stage,
    discover_stage,
    extract_code_tsg_stage,
    extract_prompt_tsg_stage,
    generate_counterfactual_stage,
    generate_observed_stage,
    import_generation_stage,
    intervene_stage,
    plan_generation_stage,
    run_oracle_stage,
)
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io import run_store as run_store_module
from secaware.io.run_store import RunStore
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle import cli as oracle_cli_module
from secaware.oracle.cli import app as oracle_app
from secaware.oracle.cli import run_standalone_oracle
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.manifest import (
    read_stage_manifest,
    write_stage_manifest,
)
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    sha256_text,
)
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_LOCK = PROJECT_ROOT / "policies" / "oracle" / "python" / "policy.lock.json"


def _config(tmp_path: Path, *, exact_tools: bool = False) -> AppConfig:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-a",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="Return one Python function.",
            )
        ],
    )
    return AppConfig.model_validate(
        {
            "run": {"name": "oracle-cli", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "provider": "mock",
                "models": ["model-a"],
                "seeds": [1],
            },
            "oracle": {
                "policy_lock_path": str(POLICY_LOCK),
                "semgrep_executable": "semgrep" if exact_tools else "semgrep-private",
                "bandit_executable": "bandit" if exact_tools else "bandit-private",
                "timeout_seconds": 10.0,
                "max_stdout_bytes": 1024 * 1024,
                "max_stderr_bytes": 4096,
            },
        }
    )


def _offline_result(
    request: GenerationRequestRecord,
    *,
    code: str = "def answer():\n    return 42\n",
) -> OfflineGenerationResultRecord:
    payload = request.model_dump(mode="python", round_trip=True, warnings=False)
    payload.update(
        code=code,
        code_sha256=sha256_text(code),
        provenance=GenerationProvenance(
            producer="offline-test-worker",
            producer_version="1.0",
            source_batch_id="batch-a",
        ),
    )
    return OfflineGenerationResultRecord.model_validate(payload)


def _safe_surfaces(error: BaseException) -> str:
    frames: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            frames.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(
        (
            str(error),
            "".join(traceback.format_exception(error)),
            json.dumps(getattr(error, "to_dict", lambda: {})(), sort_keys=True),
            *frames,
        )
    )


def _has_exact_analyzers() -> bool:
    try:
        return (
            metadata.version("semgrep") == "1.168.0"
            and metadata.version("bandit") == "1.9.4"
        )
    except metadata.PackageNotFoundError:
        return False


def _prepared_canonical_store(
    tmp_path: Path,
    *,
    code: str = "def answer():\n    return 42\n",
    exact_tools: bool = False,
) -> tuple[AppConfig, RunStore]:
    config = _config(tmp_path, exact_tools=exact_tools)
    store = RunStore(config)
    store.prepare()
    plan_generation_stage(config, store, condition="observed", force=False)
    ledger = store.path("generation", "observed_requests.jsonl")
    requests = read_jsonl(
        ledger,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    results_path = tmp_path / "offline-results.jsonl"
    write_jsonl(results_path, [_offline_result(request, code=code) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    return config, store


def _prepared_observed_pipeline(tmp_path: Path) -> tuple[AppConfig, RunStore]:
    config = load_config("configs/demo.yaml", run_dir=tmp_path / "run")
    store = RunStore(config)
    store.prepare()
    extract_prompt_tsg_stage(config, store, force=False)
    generate_observed_stage(config, store, force=False)
    extract_code_tsg_stage(config, store, condition="observed", force=False)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )
    return config, store


def _prepared_confirmation_pipeline(tmp_path: Path) -> tuple[AppConfig, RunStore]:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    intervene_stage(config, store, force=False)
    generate_counterfactual_stage(config, store, force=False)
    extract_code_tsg_stage(config, store, condition="counterfactual", force=False)
    run_oracle_stage(
        config,
        store,
        condition="counterfactual",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )
    return config, store


class _OracleRunner:
    def __init__(
        self,
        *,
        failure: str | None = None,
        finding: str | None = None,
        control: KeyboardInterrupt | SystemExit | None = None,
        control_analyzer: str = "bandit",
    ) -> None:
        self.failure = failure
        self.finding = finding
        self.control = control
        self.control_analyzer = control_analyzer
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
                    b"bandit 1.9.4\n"
                    b"  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
                )
            )
            return AnalyzerProcessResult(0, stdout, "a" * 64)
        if analyzer == self.control_analyzer and self.control is not None:
            raise self.control
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
            metrics = {
                filename: {"loc": 2, "nosec": 0, "skipped_tests": 0}
                for filename in files
            }
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


def test_oracle_stage_binds_policy_digest_and_publishes_canonical_records(
    tmp_path: Path,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    runner = _OracleRunner()

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
    assert all(record.security_label is SecurityLabel.SECURE for record in records)
    assert len([call for call in runner.calls if call[1:] != ("--version",)]) == 2


def test_oracle_stage_requires_the_named_code_output_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    code_path = store.path("generation", "observed_code.jsonl")
    actual_digest = sha256_path(code_path)
    runner = _OracleRunner()

    @contextmanager
    def forged_hold(stage: str, outputs: Sequence[Path]) -> object:
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


def test_second_analyzer_failure_leaves_no_oracle_output_or_manifest(
    tmp_path: Path,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=_OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert not store.path("oracle", "observed_oracle.jsonl").exists()
    assert not store.path(".stages", "run-oracle-observed.json").exists()


def test_oracle_stage_skip_and_force_are_policy_bound(tmp_path: Path) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    runner = _OracleRunner()
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


def test_oracle_stage_force_failure_preserves_previous_committed_artifacts(
    tmp_path: Path,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=_OracleRunner(),
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
            runner=_OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert (output.read_bytes(), manifest_path.read_bytes()) == previous
    assert not list(output.parent.glob(".*.oracle.candidate"))


def test_oracle_stage_manifest_commit_failure_restores_previous_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=_OracleRunner(),
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
            runner=_OracleRunner(finding="semgrep"),
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert (output.read_bytes(), manifest_path.read_bytes()) == previous


def test_oracle_stage_rejects_invalid_condition_before_preflight(tmp_path: Path) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    runner = _OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="not-a-condition",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    assert runner.calls == []


def test_pipeline_oracle_cli_rejects_condition_before_loading_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loaded = False

    def forbidden_load(config: Path, run_dir: Path | None) -> object:
        nonlocal loaded
        del config, run_dir
        loaded = True
        raise AssertionError("configuration must not be loaded")

    monkeypatch.setattr(pipeline_cli, "_load", forbidden_load)
    result = CliRunner().invoke(
        pipeline_app,
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


def test_standalone_oracle_publishes_atomic_output_and_digest_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"
    runner = _OracleRunner()
    monkeypatch.setattr(oracle_cli_module, "run_analyzer_process", runner)
    monkeypatch.setattr(oracle_cli_module, "validate_analyzer_runtime", lambda: None)

    result = CliRunner().invoke(
        oracle_app,
        [
            "run",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--policy-lock",
            str(POLICY_LOCK),
            "--semgrep",
            "semgrep-private",
            "--bandit",
            "bandit-private",
        ],
    )

    assert result.exit_code == 0, result.output
    records = read_jsonl(output_path, OracleRecord, required=True, allow_empty=False)
    assert records
    seal_path = output_path.with_name(output_path.name + ".sha256")
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    assert seal["output_sha256"] == hashlib.sha256(output_path.read_bytes()).hexdigest()
    assert seal["input_sha256"] == hashlib.sha256(input_path.read_bytes()).hexdigest()
    assert seal["policy_sha256"] == load_policy_bundle(POLICY_LOCK).combined_sha256


def test_standalone_failure_does_not_publish_output_or_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"
    monkeypatch.setattr(
        oracle_cli_module,
        "run_analyzer_process",
        _OracleRunner(failure="bandit"),
    )
    monkeypatch.setattr(oracle_cli_module, "validate_analyzer_runtime", lambda: None)

    result = CliRunner().invoke(
        oracle_app,
        [
            "run",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--policy-lock",
            str(POLICY_LOCK),
            "--semgrep",
            "semgrep-private",
            "--bandit",
            "bandit-private",
        ],
    )

    assert result.exit_code == int(ErrorCode.ANALYZER_FAILED)
    assert not output_path.exists()
    assert not output_path.with_name(output_path.name + ".sha256").exists()


def test_standalone_force_failure_preserves_previous_committed_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"
    args = [
        "run",
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--policy-lock",
        str(POLICY_LOCK),
        "--semgrep",
        "semgrep-private",
        "--bandit",
        "bandit-private",
    ]
    monkeypatch.setattr(oracle_cli_module, "run_analyzer_process", _OracleRunner())
    monkeypatch.setattr(oracle_cli_module, "validate_analyzer_runtime", lambda: None)
    first = CliRunner().invoke(oracle_app, args)
    assert first.exit_code == 0, first.output
    seal_path = output_path.with_name(output_path.name + ".sha256")
    previous = (output_path.read_bytes(), seal_path.read_bytes())

    monkeypatch.setattr(
        oracle_cli_module,
        "run_analyzer_process",
        _OracleRunner(failure="bandit"),
    )
    failed = CliRunner().invoke(oracle_app, [*args, "--force"])

    assert failed.exit_code == int(ErrorCode.ANALYZER_FAILED)
    assert (output_path.read_bytes(), seal_path.read_bytes()) == previous


def test_standalone_rejects_tampered_or_unpaired_existing_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"
    output_path.write_text("uncommitted\n", encoding="utf-8")
    runner = _OracleRunner()
    monkeypatch.setattr(oracle_cli_module, "run_analyzer_process", runner)
    monkeypatch.setattr(oracle_cli_module, "validate_analyzer_runtime", lambda: None)

    result = CliRunner().invoke(
        oracle_app,
        [
            "run",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--policy-lock",
            str(POLICY_LOCK),
            "--semgrep",
            "semgrep-private",
            "--bandit",
            "bandit-private",
            "--force",
        ],
    )

    assert result.exit_code == int(ErrorCode.CONTRACT)
    assert output_path.read_text(encoding="utf-8") == "uncommitted\n"
    assert not output_path.with_name(output_path.name + ".sha256").exists()


def test_standalone_rejects_duplicate_keys_in_existing_seal(
    tmp_path: Path,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    seal_path = output.with_name(output.name + ".sha256")
    kwargs = {
        "input_path": input_path,
        "output": output,
        "policy_lock": POLICY_LOCK,
        "semgrep": "semgrep-private",
        "bandit": "bandit-private",
        "runtime_validator": lambda: None,
    }
    run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)
    duplicate = seal_path.read_text(encoding="utf-8").replace(
        '"schema_version":',
        '"schema_version":"1.0","schema_version":',
        1,
    )
    seal_path.write_text(duplicate, encoding="utf-8")
    tampered = seal_path.read_bytes()

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(force=True, runner=_OracleRunner(), **kwargs)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert seal_path.read_bytes() == tampered


def test_pipeline_oracle_production_path_never_calls_legacy_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)

    def forbidden_legacy(value: object) -> object:
        del value
        raise AssertionError("legacy oracle must not be reachable")

    monkeypatch.setattr(pipeline_cli, "run_code_oracle", forbidden_legacy, raising=False)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )

    assert store.path(".stages", "run-oracle-observed.json").exists()


def test_pipeline_oracle_failure_does_not_leak_source_paths_or_executables(
    tmp_path: Path,
) -> None:
    secret = "PRIVATE-PIPELINE-SOURCE"
    config, store = _prepared_canonical_store(
        tmp_path,
        code=f"value = '{secret}'\n",
    )
    source_path = store.path("generation", "observed_code.jsonl")

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=True,
            runner=_OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    surfaces = _safe_surfaces(exc_info.value)
    assert secret not in surfaces
    assert str(source_path) not in surfaces
    assert "semgrep-private" not in surfaces


def test_standalone_failure_does_not_leak_source_paths_or_executables(
    tmp_path: Path,
) -> None:
    source_secret = "PRIVATE-STANDALONE-SOURCE"
    _config_value, store = _prepared_canonical_store(
        tmp_path,
        code=f"value = '{source_secret}'\n",
    )
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(
            input_path=input_path,
            output=output_path,
            policy_lock=POLICY_LOCK,
            semgrep="private-semgrep-executable",
            bandit="private-bandit-executable",
            force=False,
            runner=_OracleRunner(failure="bandit"),
            runtime_validator=lambda: None,
        )

    surfaces = _safe_surfaces(exc_info.value)
    assert source_secret not in surfaces
    assert str(input_path) not in surfaces
    assert "private-semgrep-executable" not in surfaces


@pytest.mark.parametrize(
    "control",
    [KeyboardInterrupt("private-control"), SystemExit("private-control")],
)
def test_pipeline_control_identity_is_preserved_and_stage_lease_is_released(
    tmp_path: Path,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)

    with pytest.raises(type(control)) as exc_info:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=_OracleRunner(control=control),
            runtime_validator=lambda: None,
        )

    assert exc_info.value is control
    assert not store.stage_is_active("run-oracle-observed")
    assert not store.path("oracle", "observed_oracle.jsonl").exists()
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )


@pytest.mark.parametrize(
    "control",
    [KeyboardInterrupt("private-control"), SystemExit("private-control")],
)
def test_standalone_control_identity_is_preserved_and_output_lease_is_released(
    tmp_path: Path,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output_path = tmp_path / "standalone-oracle.jsonl"

    with pytest.raises(type(control)) as exc_info:
        run_standalone_oracle(
            input_path=input_path,
            output=output_path,
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=_OracleRunner(control=control),
            runtime_validator=lambda: None,
        )

    assert exc_info.value is control
    assert not output_path.exists()
    run_standalone_oracle(
        input_path=input_path,
        output=output_path,
        policy_lock=POLICY_LOCK,
        semgrep="semgrep-private",
        bandit="bandit-private",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )


def test_standalone_rejects_symlink_input_before_preflight(tmp_path: Path) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    source = store.path("generation", "observed_code.jsonl")
    link = tmp_path / "linked-code.jsonl"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    runner = _OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(
            input_path=link,
            output=tmp_path / "oracle.jsonl",
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert runner.calls == []


@pytest.mark.parametrize("mode", ["pipeline", "standalone"])
def test_oracle_rejects_input_mutation_during_analysis(
    tmp_path: Path,
    mode: str,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    delegate = _OracleRunner()

    def mutating_runner(
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        call = tuple(argv)
        if call[1:] != ("--version",) and "scan" not in call:
            input_path.write_bytes(input_path.read_bytes() + b"\n")
        return delegate(
            call,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )

    if mode == "pipeline":
        with pytest.raises(SecAwareError) as exc_info:
            run_oracle_stage(
                config,
                store,
                condition="observed",
                force=False,
                runner=mutating_runner,
                runtime_validator=lambda: None,
            )
        output = store.path("oracle", "observed_oracle.jsonl")
        manifest = store.path(".stages", "run-oracle-observed.json")
    else:
        output = tmp_path / "standalone-oracle.jsonl"
        manifest = output.with_name(output.name + ".sha256")
        with pytest.raises(SecAwareError) as exc_info:
            run_standalone_oracle(
                input_path=input_path,
                output=output,
                policy_lock=POLICY_LOCK,
                semgrep="semgrep-private",
                bandit="bandit-private",
                force=False,
                runner=mutating_runner,
                runtime_validator=lambda: None,
            )

    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.MANIFEST_CONFLICT}
    assert not output.exists()
    assert not manifest.exists()


def test_standalone_post_commit_verification_failure_restores_previous_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    seal_path = output.with_name(output.name + ".sha256")
    kwargs = {
        "input_path": input_path,
        "output": output,
        "policy_lock": POLICY_LOCK,
        "semgrep": "semgrep-private",
        "bandit": "bandit-private",
        "runtime_validator": lambda: None,
    }
    run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)
    previous = (output.read_bytes(), seal_path.read_bytes())
    real_load = oracle_cli_module._load_existing_seal
    calls = 0

    def fail_post_commit(path: Path) -> object:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise SecAwareError(
                code=ErrorCode.CONTRACT,
                stage="standalone_oracle",
                message="post-commit verification failed",
            )
        return real_load(path)

    monkeypatch.setattr(oracle_cli_module, "_load_existing_seal", fail_post_commit)

    with pytest.raises(SecAwareError):
        run_standalone_oracle(
            force=True,
            runner=_OracleRunner(finding="semgrep"),
            **kwargs,
        )

    assert (output.read_bytes(), seal_path.read_bytes()) == previous


@pytest.mark.skipif(not _has_exact_analyzers(), reason="exact Oracle tools unavailable")
def test_exact_analyzers_run_through_pipeline_and_standalone_cli(tmp_path: Path) -> None:
    config, store = _prepared_canonical_store(tmp_path, exact_tools=True)
    config_path = tmp_path / "exact-tools.yaml"
    write_resolved_config(config, config_path)

    pipeline_result = CliRunner().invoke(
        pipeline_app,
        [
            "run-oracle",
            "--config",
            str(config_path),
            "--condition",
            "observed",
        ],
    )
    assert pipeline_result.exit_code == 0, pipeline_result.output
    assert store.path(".stages", "run-oracle-observed.json").exists()

    standalone_output = tmp_path / "exact-standalone.jsonl"
    standalone_result = CliRunner().invoke(
        oracle_app,
        [
            "run",
            "--input",
            str(store.path("generation", "observed_code.jsonl")),
            "--output",
            str(standalone_output),
            "--policy-lock",
            str(POLICY_LOCK),
            "--semgrep",
            "semgrep",
            "--bandit",
            "bandit",
        ],
    )
    assert standalone_result.exit_code == 0, standalone_result.output
    assert read_jsonl(
        standalone_output,
        OracleRecord,
        required=True,
        allow_empty=False,
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing_manifest", "stale_output", "policy_manifest", "empty", "duplicate"],
)
def test_discover_requires_a_strict_committed_observed_oracle(
    tmp_path: Path,
    mutation: str,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    output = store.path("oracle", "observed_oracle.jsonl")
    manifest_path = store.path(".stages", "run-oracle-observed.json")
    if mutation == "missing_manifest":
        manifest_path.unlink()
    elif mutation == "stale_output":
        output.write_bytes(output.read_bytes() + b"\n")
    elif mutation == "policy_manifest":
        manifest = read_stage_manifest(manifest_path)
        write_stage_manifest(
            manifest_path,
            manifest.model_copy(update={"policy_sha256": "c" * 64}),
        )
    else:
        if mutation == "empty":
            output.write_bytes(b"")
        else:
            payload = output.read_bytes()
            output.write_bytes(payload + payload)
        manifest = read_stage_manifest(manifest_path)
        write_stage_manifest(
            manifest_path,
            manifest.model_copy(
                update={
                    "output_sha256": {
                        "oracle/observed_oracle.jsonl": sha256_path(output)
                    }
                }
            ),
        )

    with pytest.raises(SecAwareError) as exc_info:
        discover_stage(config, store, force=False)

    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.MANIFEST_CONFLICT}
    assert not store.path("discovery", "hypotheses_all.jsonl").exists()
    assert not store.path("discovery", "hypotheses_selected.jsonl").exists()
    assert not store.path(".stages", "discover.json").exists()


def test_confirm_requires_both_committed_oracles(tmp_path: Path) -> None:
    config, store = _prepared_confirmation_pipeline(tmp_path)
    store.path(".stages", "run-oracle-counterfactual.json").unlink()

    with pytest.raises(SecAwareError) as exc_info:
        confirm_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path("analysis", "pair_results.jsonl").exists()
    assert not store.path("analysis", "hypothesis_effects.jsonl").exists()
    assert not store.path(".stages", "confirm.json").exists()


def test_confirm_holds_both_oracle_leases_in_fixed_order_through_computation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_confirmation_pipeline(tmp_path)
    real_hold = store.hold_committed_output
    active: list[str] = []
    entered: list[str] = []
    checked = False
    real_build_pairs = pipeline_cli.build_pairs

    @contextmanager
    def tracked_hold(stage: str, outputs: Sequence[Path]) -> object:
        with real_hold(stage, outputs) as hashes:
            active.append(stage)
            entered.append(stage)
            try:
                yield hashes
            finally:
                active.remove(stage)

    def checked_build_pairs(*args: object, **kwargs: object) -> object:
        nonlocal checked
        checked = active == [
            "run-oracle-observed",
            "run-oracle-counterfactual",
        ]
        return real_build_pairs(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "hold_committed_output", tracked_hold)
    monkeypatch.setattr(pipeline_cli, "build_pairs", checked_build_pairs)

    confirm_stage(config, store, force=False)

    assert entered == ["run-oracle-observed", "run-oracle-counterfactual"]
    assert checked is True
    assert active == []


@pytest.mark.parametrize("stage_name", ["discover", "confirm"])
def test_downstream_force_failure_preserves_previous_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_name: str,
) -> None:
    if stage_name == "discover":
        config, store = _prepared_observed_pipeline(tmp_path)
        discover_stage(config, store, force=False)
        outputs = [
            store.path("discovery", "hypotheses_all.jsonl"),
            store.path("discovery", "hypotheses_selected.jsonl"),
        ]
        monkeypatch.setattr(
            pipeline_cli,
            "discover_hypotheses",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private-failure")),
        )
    else:
        config, store = _prepared_confirmation_pipeline(tmp_path)
        confirm_stage(config, store, force=False)
        outputs = [
            store.path("analysis", "pair_results.jsonl"),
            store.path("analysis", "hypothesis_effects.jsonl"),
        ]
        monkeypatch.setattr(
            pipeline_cli,
            "build_pairs",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("private-failure")),
        )
    manifest = store.path(".stages", f"{stage_name}.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())

    def run() -> None:
        if stage_name == "discover":
            discover_stage(config, store, force=True)
        else:
            confirm_stage(config, store, force=True)

    with pytest.raises(RuntimeError):
        run()

    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]
    assert not store.stage_is_active(stage_name)


def test_discover_holds_committed_oracle_snapshot_against_force_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    contender = RunStore(config)
    oracle_output = store.path("oracle", "observed_oracle.jsonl")
    oracle_manifest = store.path(".stages", "run-oracle-observed.json")
    previous = (oracle_output.read_bytes(), oracle_manifest.read_bytes())
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    real_discover = pipeline_cli.discover_hypotheses

    def blocked_discover(*args: object, **kwargs: object) -> object:
        assert oracle_output.read_bytes() == previous[0]
        entered.set()
        assert release.wait(timeout=5)
        assert oracle_output.read_bytes() == previous[0]
        return real_discover(*args, **kwargs)  # type: ignore[arg-type]

    def consume_snapshot() -> None:
        try:
            discover_stage(config, store, force=False)
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", blocked_discover)
    thread = threading.Thread(target=consume_snapshot)
    thread.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(SecAwareError) as exc_info:
            run_oracle_stage(
                config,
                contender,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )

        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert (oracle_output.read_bytes(), oracle_manifest.read_bytes()) == previous
    finally:
        release.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert store.path(".stages", "discover.json").exists()
    run_oracle_stage(
        config,
        contender,
        condition="observed",
        force=True,
        runner=_OracleRunner(finding="semgrep"),
        runtime_validator=lambda: None,
    )

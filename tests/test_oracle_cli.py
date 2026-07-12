from __future__ import annotations

from collections.abc import Sequence
from contextlib import contextmanager
import hashlib
from importlib import metadata
import json
from pathlib import Path
import shutil
import threading
import traceback

import pytest
from typer.testing import CliRunner

from secaware import cli as pipeline_cli
from secaware.cli import app as pipeline_app
from secaware.cli import (
    confirm_stage,
    discover_stage,
    extract_prompt_tsg_stage,
    generate_counterfactual_stage,
    generate_observed_stage,
    import_generation_stage,
    intervene_stage,
    plan_generation_stage,
    run_oracle_stage,
)
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
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
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256


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
        return metadata.version("semgrep") == "1.168.0" and metadata.version("bandit") == "1.9.4"
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
                    b"bandit 1.9.4\n  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
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
    original_input = input_path.read_bytes()
    original_code = read_jsonl(
        input_path,
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )[0]
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
        records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
        seal = json.loads(manifest.read_text(encoding="utf-8"))
        assert records[0].code_sha256 == original_code.code_sha256  # type: ignore[index,union-attr]
        assert seal["input_sha256"] == hashlib.sha256(original_input).hexdigest()
        assert seal["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
        return

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
                update={"output_sha256": {"oracle/observed_oracle.jsonl": sha256_path(output)}}
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


def test_discovery_rejects_committed_legacy_prompt_graph_artifact(tmp_path: Path) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    output = store.path("tsg", "prompt_tsg.jsonl")
    output.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "graph_id": "prompt:legacy",
                "source_type": "prompt",
                "prompt_id": "legacy",
                "features": {},
                "nodes": [],
                "edges": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    manifest = read_stage_manifest(manifest_path)
    write_stage_manifest(
        manifest_path,
        manifest.model_copy(
            update={"output_sha256": {"tsg/prompt_tsg.jsonl": sha256_path(output)}}
        ),
    )

    with pytest.raises(SecAwareError) as exc_info:
        discover_stage(config, store, force=False)

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert not store.path(".stages", "discover.json").exists()


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown"])
def test_intervention_rejects_invalid_prompt_graph_coordinates_without_leaks(
    tmp_path: Path,
    mutation: str,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    intervene_stage(config, store, force=False)
    outputs = [
        store.path("interventions", "interventions.jsonl"),
        store.path("interventions", "paired_prompts.jsonl"),
    ]
    manifest_path = store.path(".stages", "intervene.json")
    previous = ([path.read_bytes() for path in outputs], manifest_path.read_bytes())
    spec = FACTOR_SPECS[FactorType.PATH_NORMALIZATION]
    selected_hypothesis = HypothesisRecord(
        hypothesis_id="h-coordinate-validation",
        factor_type=spec.factor_type,
        motif_id=spec.motif_id,
        requirement_label=spec.requirement_label,
        guard_label=spec.guard_label,
        expected_direction="risk_down_when_added",
        scope={"language": "python", "task_family": "path_handling", "cwe": "CWE-22"},
        patch_operator=spec.patch_operator,
    )
    discovery_outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    for discovery_output in discovery_outputs:
        write_jsonl(discovery_output, [selected_hypothesis])
    discovery_manifest_path = store.path(".stages", "discover.json")
    discovery_manifest = read_stage_manifest(discovery_manifest_path)
    write_stage_manifest(
        discovery_manifest_path,
        discovery_manifest.model_copy(
            update={
                "output_sha256": {
                    path.relative_to(store.root).as_posix(): sha256_path(path)
                    for path in discovery_outputs
                }
            }
        ),
    )
    prompts = read_jsonl(
        store.path("inputs", "prompts.jsonl"),
        PromptRecord,
        required=True,
        allow_empty=False,
    )
    confirm_prompt = next(prompt for prompt in prompts if prompt.split == "confirm")
    prompt_graph_path = store.path("tsg", "prompt_tsg.jsonl")
    prompt_graphs = read_jsonl(
        prompt_graph_path,
        PromptTSGRecord,
        required=True,
        allow_empty=False,
    )
    confirm_graph = next(
        graph for graph in prompt_graphs if graph.prompt_id == confirm_prompt.prompt_id
    )
    unknown_prompt_id = "private-unknown-prompt-coordinate"
    unknown_prompt_text = "PRIVATE_RAW_PROMPT_COORDINATE_SENTINEL"
    if mutation == "missing":
        mutated = [
            graph for graph in prompt_graphs if graph.prompt_id != confirm_prompt.prompt_id
        ]
    elif mutation == "duplicate":
        mutated = [*prompt_graphs, confirm_graph]
    else:
        mutated = [
            *prompt_graphs,
            extract_prompt_tsg(
                PromptRecord(
                    prompt_id=unknown_prompt_id,
                    split="confirm",
                    language="python",
                    task_family="path_handling",
                    cwe="CWE-22",
                    prompt=unknown_prompt_text,
                )
            ),
        ]
    write_jsonl(prompt_graph_path, mutated)
    producer_manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    producer_manifest = read_stage_manifest(producer_manifest_path)
    write_stage_manifest(
        producer_manifest_path,
        producer_manifest.model_copy(
            update={
                "output_sha256": {
                    "tsg/prompt_tsg.jsonl": sha256_path(prompt_graph_path)
                }
            }
        ),
    )

    with pytest.raises(SecAwareError) as exc_info:
        intervene_stage(config, store, force=True)

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert exc_info.value.details == {}
    safe_surfaces = _safe_surfaces(exc_info.value)
    assert confirm_prompt.prompt_id not in safe_surfaces
    assert confirm_prompt.prompt not in safe_surfaces
    assert unknown_prompt_id not in safe_surfaces
    assert unknown_prompt_text not in safe_surfaces
    assert ([path.read_bytes() for path in outputs], manifest_path.read_bytes()) == previous
    assert not store.stage_is_active("intervene")
    with store.hold_committed_output(
        "extract-prompt-tsg",
        [prompt_graph_path],
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ):
        pass


def test_discovery_uses_full_prompt_graph_coordinate_boundary(tmp_path: Path) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    prompt_graph_path = store.path("tsg", "prompt_tsg.jsonl")
    prompt_graphs = read_jsonl(
        prompt_graph_path,
        PromptTSGRecord,
        required=True,
        allow_empty=False,
    )
    write_jsonl(prompt_graph_path, prompt_graphs[1:])
    producer_manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    producer_manifest = read_stage_manifest(producer_manifest_path)
    write_stage_manifest(
        producer_manifest_path,
        producer_manifest.model_copy(
            update={
                "output_sha256": {
                    "tsg/prompt_tsg.jsonl": sha256_path(prompt_graph_path)
                }
            }
        ),
    )

    with pytest.raises(SecAwareError) as exc_info:
        discover_stage(config, store, force=True)

    assert exc_info.value.code is ErrorCode.TSG_INVALID
    assert exc_info.value.details == {}
    assert not store.stage_is_active("discover")


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


@pytest.mark.parametrize(
    ("consumer", "expected_order"),
    [
        ("discover", ["extract-prompt-tsg", "run-oracle-observed"]),
        ("intervene", ["discover", "extract-prompt-tsg"]),
    ],
)
def test_prompt_graph_consumers_hold_producer_leases_in_fixed_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer: str,
    expected_order: list[str],
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    if consumer == "intervene":
        discover_stage(config, store, force=False)
    real_hold = store.hold_committed_output
    real_execute = pipeline_cli._execute_jsonl_stage_transaction
    active: list[str] = []
    entered: list[str] = []
    bindings: dict[str, str | None] = {}
    checked = False

    @contextmanager
    def tracked_hold(
        stage: str,
        outputs: Sequence[Path],
        *,
        expected_catalog_sha256: str | None = None,
    ) -> object:
        with real_hold(
            stage,
            outputs,
            expected_catalog_sha256=expected_catalog_sha256,
        ) as hashes:
            active.append(stage)
            entered.append(stage)
            bindings[stage] = expected_catalog_sha256
            try:
                yield hashes
            finally:
                active.remove(stage)

    def checked_execute(*args: object, **kwargs: object) -> None:
        nonlocal checked
        checked = active == expected_order
        real_execute(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "hold_committed_output", tracked_hold)
    monkeypatch.setattr(pipeline_cli, "_execute_jsonl_stage_transaction", checked_execute)

    if consumer == "discover":
        discover_stage(config, store, force=True)
    else:
        intervene_stage(config, store, force=True)

    assert entered == expected_order
    assert checked is True
    assert bindings["extract-prompt-tsg"] == PROMPT_TSG_CATALOG_SHA256
    assert all(
        binding is None
        for stage, binding in bindings.items()
        if stage != "extract-prompt-tsg"
    )
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


def test_oracle_mark_failure_keeps_lease_until_old_commit_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, owner = _prepared_observed_pipeline(tmp_path)
    contender = RunStore(config)
    oracle_output = owner.path("oracle", "observed_oracle.jsonl")
    oracle_manifest = owner.path(".stages", "run-oracle-observed.json")
    previous = (oracle_output.read_bytes(), oracle_manifest.read_bytes())
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    real_mark = pipeline_cli.ArtifactTransaction.mark_postcommit

    def blocked_failure(transaction: object) -> None:
        journal_path = getattr(transaction, "journal_path")
        if journal_path.name == ".run-oracle-observed.transaction.json":
            entered.set()
            assert release.wait(timeout=5)
            raise pipeline_cli.TransactionStateError
        real_mark(transaction)  # type: ignore[arg-type]

    def force_oracle() -> None:
        try:
            run_oracle_stage(
                config,
                owner,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(pipeline_cli.ArtifactTransaction, "mark_postcommit", blocked_failure)
    thread = threading.Thread(target=force_oracle)
    thread.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(SecAwareError) as exc_info:
            discover_stage(config, contender, force=False)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], SecAwareError)
    assert (oracle_output.read_bytes(), oracle_manifest.read_bytes()) == previous
    monkeypatch.setattr(pipeline_cli.ArtifactTransaction, "mark_postcommit", real_mark)
    discover_stage(config, contender, force=False)


@pytest.mark.parametrize("stage_name", ["discover", "confirm"])
def test_multioutput_mark_failure_holds_stage_lease_through_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_name: str,
) -> None:
    if stage_name == "discover":
        config, owner = _prepared_observed_pipeline(tmp_path)
        discover_stage(config, owner, force=False)
        inputs = [
            owner.path("inputs", "prompts.jsonl"),
            owner.path("tsg", "prompt_tsg.jsonl"),
            owner.path("oracle", "observed_oracle.jsonl"),
        ]
        outputs = [
            owner.path("discovery", "hypotheses_all.jsonl"),
            owner.path("discovery", "hypotheses_selected.jsonl"),
        ]

        def run_stage() -> None:
            discover_stage(config, owner, force=True)
    else:
        config, owner = _prepared_confirmation_pipeline(tmp_path)
        confirm_stage(config, owner, force=False)
        inputs = [
            owner.path("interventions", "interventions.jsonl"),
            owner.path("oracle", "observed_oracle.jsonl"),
            owner.path("oracle", "counterfactual_oracle.jsonl"),
            owner.path("discovery", "hypotheses_selected.jsonl"),
        ]
        outputs = [
            owner.path("analysis", "pair_results.jsonl"),
            owner.path("analysis", "hypothesis_effects.jsonl"),
        ]

        def run_stage() -> None:
            confirm_stage(config, owner, force=True)

    contender = RunStore(config)
    manifest = owner.path(".stages", f"{stage_name}.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []
    real_mark = pipeline_cli.ArtifactTransaction.mark_postcommit

    def blocked_failure(transaction: object) -> None:
        journal_path = getattr(transaction, "journal_path")
        if journal_path.name == f".{stage_name}.transaction.json":
            entered.set()
            assert release.wait(timeout=5)
            raise pipeline_cli.TransactionStateError
        real_mark(transaction)  # type: ignore[arg-type]

    def force_stage() -> None:
        try:
            run_stage()
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(pipeline_cli.ArtifactTransaction, "mark_postcommit", blocked_failure)
    thread = threading.Thread(target=force_stage)
    thread.start()
    assert entered.wait(timeout=5)
    try:
        with pytest.raises(SecAwareError) as exc_info:
            contender.should_skip_stage(
                stage_name,
                inputs,
                outputs,
                force=True,
                preserve_committed=True,
            )
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release.set()
        thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], SecAwareError)
    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]
    assert contender.should_skip_stage(
        stage_name,
        inputs,
        outputs,
        force=False,
        preserve_committed=True,
    )


@pytest.mark.parametrize("surface", ["oracle", "discover", "confirm"])
@pytest.mark.parametrize("control", [KeyboardInterrupt("mark"), SystemExit("mark")])
def test_mark_postcommit_control_rolls_back_and_releases_stage_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    if surface == "oracle":
        config, owner = _prepared_observed_pipeline(tmp_path)
        stage = "run-oracle-observed"
        outputs = [owner.path("oracle", "observed_oracle.jsonl")]

        def run_stage() -> None:
            run_oracle_stage(
                config,
                owner,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )

    elif surface == "discover":
        config, owner = _prepared_observed_pipeline(tmp_path)
        discover_stage(config, owner, force=False)
        stage = "discover"
        outputs = [
            owner.path("discovery", "hypotheses_all.jsonl"),
            owner.path("discovery", "hypotheses_selected.jsonl"),
        ]

        def run_stage() -> None:
            discover_stage(config, owner, force=True)

    else:
        config, owner = _prepared_confirmation_pipeline(tmp_path)
        confirm_stage(config, owner, force=False)
        stage = "confirm"
        outputs = [
            owner.path("analysis", "pair_results.jsonl"),
            owner.path("analysis", "hypothesis_effects.jsonl"),
        ]

        def run_stage() -> None:
            confirm_stage(config, owner, force=True)

    manifest = owner.path(".stages", f"{stage}.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    real_mark = pipeline_cli.ArtifactTransaction.mark_postcommit

    def interrupt_mark(transaction: object) -> None:
        journal_path = getattr(transaction, "journal_path")
        if journal_path.name == f".{stage}.transaction.json":
            raise control
        real_mark(transaction)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline_cli.ArtifactTransaction, "mark_postcommit", interrupt_mark)
    with pytest.raises(type(control)) as exc_info:
        run_stage()

    assert exc_info.value is control
    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]
    assert not owner.stage_is_active(stage)


@pytest.mark.parametrize("surface", ["oracle", "discover", "confirm"])
@pytest.mark.parametrize("fault_point", ["before_call", "before_release", "after_release"])
@pytest.mark.parametrize("control", [KeyboardInterrupt("finalize"), SystemExit("finalize")])
def test_postcommit_finalize_control_keeps_commit_and_ensures_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    fault_point: str,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    if surface == "oracle":
        config, owner = _prepared_observed_pipeline(tmp_path)
        stage = "run-oracle-observed"
        inputs = [owner.path("generation", "observed_code.jsonl")]
        outputs = [owner.path("oracle", "observed_oracle.jsonl")]

        def run_stage() -> None:
            run_oracle_stage(
                config,
                owner,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )

    elif surface == "discover":
        config, owner = _prepared_observed_pipeline(tmp_path)
        discover_stage(config, owner, force=False)
        stage = "discover"
        inputs = [
            owner.path("inputs", "prompts.jsonl"),
            owner.path("tsg", "prompt_tsg.jsonl"),
            owner.path("oracle", "observed_oracle.jsonl"),
        ]
        outputs = [
            owner.path("discovery", "hypotheses_all.jsonl"),
            owner.path("discovery", "hypotheses_selected.jsonl"),
        ]

        def run_stage() -> None:
            discover_stage(config, owner, force=True)

    else:
        config, owner = _prepared_confirmation_pipeline(tmp_path)
        confirm_stage(config, owner, force=False)
        stage = "confirm"
        inputs = [
            owner.path("interventions", "interventions.jsonl"),
            owner.path("oracle", "observed_oracle.jsonl"),
            owner.path("oracle", "counterfactual_oracle.jsonl"),
            owner.path("discovery", "hypotheses_selected.jsonl"),
        ]
        outputs = [
            owner.path("analysis", "pair_results.jsonl"),
            owner.path("analysis", "hypothesis_effects.jsonl"),
        ]

        def run_stage() -> None:
            confirm_stage(config, owner, force=True)

    if fault_point == "before_call":

        def interrupt_finalize(_lease: object) -> None:
            raise control

        monkeypatch.setattr(owner, "finalize_stage_commit", interrupt_finalize)
    else:
        real_release = owner._release_stage_handle
        injected = False

        def interrupt_release(handle: object) -> None:
            nonlocal injected
            target = owner._stage_leases.get(stage)
            if handle is target and not injected:
                injected = True
                if fault_point == "after_release":
                    real_release(handle)  # type: ignore[arg-type]
                raise control
            real_release(handle)  # type: ignore[arg-type]

        monkeypatch.setattr(owner, "_release_stage_handle", interrupt_release)

    with pytest.raises(type(control)) as exc_info:
        run_stage()

    assert exc_info.value is control
    assert not owner.stage_is_active(stage)
    if surface == "oracle":
        assert owner.require_committed_output(stage, outputs)
    else:
        assert owner.require_committed_stage(stage, inputs, outputs)

    contender = RunStore(config)
    manifest = read_stage_manifest(owner.path(".stages", f"{stage}.json"))
    assert (
        contender.should_skip_stage(
            stage,
            inputs,
            outputs,
            force=True,
            preserve_committed=True,
            policy_sha256=manifest.policy_sha256,
        )
        is False
    )
    contender.abort_stage(stage)
    owner.close()
    contender.close()
    shutil.rmtree(owner.root)
    assert not owner.root.exists()


def test_postcommit_finalize_release_failure_keeps_commit_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, owner = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, owner, force=False)
    stage = "discover"
    inputs = [
        owner.path("inputs", "prompts.jsonl"),
        owner.path("tsg", "prompt_tsg.jsonl"),
        owner.path("oracle", "observed_oracle.jsonl"),
    ]
    outputs = [
        owner.path("discovery", "hypotheses_all.jsonl"),
        owner.path("discovery", "hypotheses_selected.jsonl"),
    ]
    real_release = owner._release_stage_handle
    attempts = 0

    def fail_target_release(handle: object) -> None:
        nonlocal attempts
        if handle is owner._stage_leases.get(stage):
            attempts += 1
            raise OSError("private-release-failure")
        real_release(handle)  # type: ignore[arg-type]

    monkeypatch.setattr(owner, "_release_stage_handle", fail_target_release)
    with pytest.raises(SecAwareError) as exc_info:
        discover_stage(config, owner, force=True)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert attempts == 6
    assert owner.stage_is_active(stage)
    assert owner.require_committed_stage(stage, inputs, outputs)
    contender = RunStore(config)
    with pytest.raises(SecAwareError) as contender_exc:
        contender.should_skip_stage(
            stage,
            inputs,
            outputs,
            force=True,
            preserve_committed=True,
        )
    assert contender_exc.value.code is ErrorCode.MANIFEST_CONFLICT

    monkeypatch.setattr(owner, "_release_stage_handle", real_release)
    owner.abort_stage(stage)
    assert not owner.stage_is_active(stage)
    assert owner.require_committed_stage(stage, inputs, outputs)
    assert (
        contender.should_skip_stage(
            stage,
            inputs,
            outputs,
            force=True,
            preserve_committed=True,
        )
        is False
    )
    contender.abort_stage(stage)
    owner.close()
    contender.close()


@pytest.mark.parametrize(
    ("target", "failures"),
    [("second_output", 1), ("second_output", 100), ("manifest", 100)],
)
def test_downstream_postcommit_cleanup_failure_keeps_new_commit_and_retries_later(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    failures: int,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
    ]
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    previous = [path.read_bytes() for path in outputs]
    real_unlink = Path.unlink
    attempts = 0

    def flaky_unlink(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal attempts
        selected = (
            target == "second_output"
            and path.name.endswith(".output1.recovery.backup")
            and path.name.startswith(f".{outputs[1].name}.")
            and path.exists()
            and path.stat().st_size > 0
        ) or (
            target == "manifest"
            and path.name.endswith(".manifest.recovery.backup")
            and path.name.startswith(".discover.json.")
            and path.exists()
            and path.stat().st_size > 0
        )
        if selected and attempts < failures:
            attempts += 1
            raise OSError("private-cleanup-failure")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        pipeline_cli,
        "discover_hypotheses",
        lambda *args, **kwargs: ([], []),
    )
    monkeypatch.setattr(Path, "unlink", flaky_unlink)

    discover_stage(config, store, force=True)

    assert [path.read_bytes() for path in outputs] != previous
    assert store.require_committed_stage("discover", inputs, outputs)
    leftovers = [
        *outputs[1].parent.glob(f".{outputs[1].name}.*.output1.recovery.backup"),
        *store.path(".stages").glob(".discover.json.*.manifest.recovery.backup"),
    ]
    if failures == 1:
        assert leftovers == []
    else:
        assert leftovers
        assert all(path not in outputs for path in leftovers)

    monkeypatch.setattr(Path, "unlink", real_unlink)
    discover_stage(config, store, force=True)

    assert store.require_committed_stage("discover", inputs, outputs)
    assert not list(outputs[1].parent.glob(f".{outputs[1].name}.*.output1.recovery.backup"))
    assert not list(store.path(".stages").glob(".discover.json.*.manifest.recovery.backup"))


@pytest.mark.parametrize("control", [KeyboardInterrupt("postcommit"), SystemExit("postcommit")])
def test_downstream_postcommit_control_keeps_new_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
    ]
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    previous = [path.read_bytes() for path in outputs]
    real_unlink = Path.unlink

    def interrupt_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if (
            path.name.endswith(".output0.recovery.backup")
            and path.exists()
            and path.stat().st_size > 0
        ):
            raise control
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        pipeline_cli,
        "discover_hypotheses",
        lambda *args, **kwargs: ([], []),
    )
    monkeypatch.setattr(Path, "unlink", interrupt_cleanup)

    with pytest.raises(type(control)) as exc_info:
        discover_stage(config, store, force=True)

    assert exc_info.value is control
    assert [path.read_bytes() for path in outputs] != previous
    assert store.require_committed_stage("discover", inputs, outputs)


def test_downstream_manifest_postverify_failure_rolls_back_before_commit_point(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    manifest = store.path(".stages", "discover.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    real_write = run_store_module.write_stage_manifest

    def write_then_corrupt(path: Path, value: object) -> None:
        real_write(path, value)  # type: ignore[arg-type]
        path.write_bytes(b'{"corrupt":true}\n')

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_corrupt)
    monkeypatch.setattr(
        pipeline_cli,
        "discover_hypotheses",
        lambda *args, **kwargs: ([], []),
    )

    with pytest.raises(SecAwareError):
        discover_stage(config, store, force=True)

    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]


def test_pipeline_oracle_postcommit_cleanup_failure_keeps_new_commit(
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
    real_unlink = Path.unlink

    def fail_backup_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if (
            path.name.endswith(".oracle.recovery.backup")
            and path.exists()
            and path.stat().st_size > 0
        ):
            raise OSError("private-cleanup-failure")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", fail_backup_cleanup)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=True,
        runner=_OracleRunner(finding="semgrep"),
        runtime_validator=lambda: None,
    )

    records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
    assert records[0].security_label is SecurityLabel.INSECURE  # type: ignore[index,union-attr]
    assert store.require_committed_output("run-oracle-observed", [output])
    assert list(output.parent.glob(f".{output.name}.*.oracle.recovery.backup"))

    monkeypatch.setattr(Path, "unlink", real_unlink)
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=True,
        runner=_OracleRunner(finding="semgrep"),
        runtime_validator=lambda: None,
    )
    assert not list(output.parent.glob(f".{output.name}.*.oracle.recovery.backup"))


def test_standalone_postcommit_cleanup_failure_keeps_new_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    kwargs = {
        "input_path": input_path,
        "output": output,
        "policy_lock": POLICY_LOCK,
        "semgrep": "semgrep-private",
        "bandit": "bandit-private",
        "runtime_validator": lambda: None,
    }
    run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)
    real_unlink = Path.unlink

    def fail_backup_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if (
            path.name.endswith(".output.recovery.backup")
            and path.exists()
            and path.stat().st_size > 0
        ):
            raise OSError("private-cleanup-failure")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", fail_backup_cleanup)
    run_standalone_oracle(
        force=True,
        runner=_OracleRunner(finding="semgrep"),
        **kwargs,
    )

    records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
    assert records[0].security_label is SecurityLabel.INSECURE  # type: ignore[index,union-attr]
    assert list(output.parent.glob(f".{output.name}.*.output.recovery.backup"))

    monkeypatch.setattr(Path, "unlink", real_unlink)
    run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)
    assert not list(output.parent.glob(f".{output.name}.*.output.recovery.backup"))


@pytest.mark.parametrize("control", [KeyboardInterrupt("precommit"), SystemExit("precommit")])
def test_downstream_precommit_control_rolls_back_old_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    manifest = store.path(".stages", "discover.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())

    def interrupt_build(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise control

    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", interrupt_build)

    with pytest.raises(type(control)) as exc_info:
        discover_stage(config, store, force=True)

    assert exc_info.value is control
    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]


@pytest.mark.parametrize("surface", ["pipeline", "standalone"])
@pytest.mark.parametrize("control", [KeyboardInterrupt("cleanup"), SystemExit("cleanup")])
def test_oracle_postcommit_control_keeps_new_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    control: KeyboardInterrupt | SystemExit,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    real_unlink = Path.unlink

    if surface == "pipeline":
        output = store.path("oracle", "observed_oracle.jsonl")
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=_OracleRunner(),
            runtime_validator=lambda: None,
        )
        suffix = ".oracle.recovery.backup"
    else:
        output = tmp_path / "standalone-oracle.jsonl"
        run_standalone_oracle(
            input_path=input_path,
            output=output,
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=_OracleRunner(),
            runtime_validator=lambda: None,
        )
        suffix = ".output.recovery.backup"

    def interrupt_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if path.name.endswith(suffix) and path.exists() and path.stat().st_size > 0:
            raise control
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", interrupt_cleanup)
    with pytest.raises(type(control)) as exc_info:
        if surface == "pipeline":
            run_oracle_stage(
                config,
                store,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )
        else:
            run_standalone_oracle(
                input_path=input_path,
                output=output,
                policy_lock=POLICY_LOCK,
                semgrep="semgrep-private",
                bandit="bandit-private",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )

    assert exc_info.value is control
    records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
    assert records[0].security_label is SecurityLabel.INSECURE  # type: ignore[index,union-attr]
    if surface == "pipeline":
        assert store.require_committed_output("run-oracle-observed", [output])
    else:
        seal = json.loads(output.with_name(output.name + ".sha256").read_text())
        assert seal["output_sha256"] == sha256_path(output)


@pytest.mark.parametrize("surface", ["pipeline", "standalone"])
@pytest.mark.parametrize("control", [KeyboardInterrupt("once"), SystemExit("once")])
@pytest.mark.parametrize("ordinary_first", [False, True])
def test_oracle_postcommit_transient_control_is_rethrown_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    control: KeyboardInterrupt | SystemExit,
    ordinary_first: bool,
) -> None:
    config, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    real_unlink = Path.unlink
    if surface == "pipeline":
        output = store.path("oracle", "observed_oracle.jsonl")
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=_OracleRunner(),
            runtime_validator=lambda: None,
        )
        suffix = ".oracle.recovery.backup"
    else:
        output = tmp_path / "standalone-oracle.jsonl"
        run_standalone_oracle(
            input_path=input_path,
            output=output,
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=_OracleRunner(),
            runtime_validator=lambda: None,
        )
        suffix = ".output.recovery.backup"
    attempts = 0

    def transient_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal attempts
        if path.name.endswith(suffix):
            attempts += 1
            if ordinary_first and attempts == 1:
                raise OSError("private-transient-cleanup")
            if attempts == (2 if ordinary_first else 1):
                raise control
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", transient_cleanup)
    with pytest.raises(type(control)) as exc_info:
        if surface == "pipeline":
            run_oracle_stage(
                config,
                store,
                condition="observed",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )
        else:
            run_standalone_oracle(
                input_path=input_path,
                output=output,
                policy_lock=POLICY_LOCK,
                semgrep="semgrep-private",
                bandit="bandit-private",
                force=True,
                runner=_OracleRunner(finding="semgrep"),
                runtime_validator=lambda: None,
            )

    assert exc_info.value is control
    assert attempts == (3 if ordinary_first else 2)
    assert not list(output.parent.glob(f".{output.name}.*{suffix}"))
    records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
    assert records[0].security_label is SecurityLabel.INSECURE  # type: ignore[index,union-attr]


@pytest.mark.parametrize("surface", ["pipeline_oracle", "discover", "confirm"])
@pytest.mark.parametrize(
    "cleanup_state",
    ["success", "persistent", "keyboard", "systemexit"],
)
def test_pipeline_skip_cleans_stale_backup_without_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    cleanup_state: str,
) -> None:
    if surface == "pipeline_oracle":
        config, store = _prepared_canonical_store(tmp_path)
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=_OracleRunner(),
            runtime_validator=lambda: None,
        )
        outputs = [store.path("oracle", "observed_oracle.jsonl")]
        manifest = store.path(".stages", "run-oracle-observed.json")
        backup_suffix = ".oracle.recovery.backup"
    elif surface == "discover":
        config, store = _prepared_observed_pipeline(tmp_path)
        discover_stage(config, store, force=False)
        outputs = [
            store.path("discovery", "hypotheses_all.jsonl"),
            store.path("discovery", "hypotheses_selected.jsonl"),
        ]
        manifest = store.path(".stages", "discover.json")
        backup_suffix = ".output1.recovery.backup"
    else:
        config, store = _prepared_confirmation_pipeline(tmp_path)
        confirm_stage(config, store, force=False)
        outputs = [
            store.path("analysis", "pair_results.jsonl"),
            store.path("analysis", "hypothesis_effects.jsonl"),
        ]
        manifest = store.path(".stages", "confirm.json")
        backup_suffix = ".output1.recovery.backup"

    target = outputs[-1]
    real_unlink = Path.unlink

    def leave_postcommit_backup(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        if (
            path.name.endswith(backup_suffix)
            and path.name.startswith(f".{target.name}.")
            and path.exists()
            and path.stat().st_size > 0
        ):
            raise OSError("private-postcommit-cleanup-failure")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", leave_postcommit_backup)
    if surface == "pipeline_oracle":
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=True,
            runner=_OracleRunner(finding="semgrep"),
            runtime_validator=lambda: None,
        )
    elif surface == "discover":
        monkeypatch.setattr(
            pipeline_cli,
            "discover_hypotheses",
            lambda *args, **kwargs: ([], []),
        )
        discover_stage(config, store, force=True)
    else:
        confirm_stage(config, store, force=True)
    monkeypatch.setattr(Path, "unlink", real_unlink)

    stale_pattern = f".{target.name}.*{backup_suffix}"
    assert list(target.parent.glob(stale_pattern))
    committed = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    cleanup_attempts = 0
    control: KeyboardInterrupt | SystemExit | None = None
    if cleanup_state == "keyboard":
        control = KeyboardInterrupt("private-skip-cleanup")
    elif cleanup_state == "systemexit":
        control = SystemExit("private-skip-cleanup")

    def cleanup_state_unlink(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal cleanup_attempts
        if path.name.endswith(backup_suffix) and path.name.startswith(f".{target.name}."):
            cleanup_attempts += 1
            if cleanup_state == "persistent":
                raise OSError("private-persistent-cleanup-failure")
            if control is not None:
                raise control
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", cleanup_state_unlink)
    oracle_runner = _OracleRunner()

    def forbidden_compute(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("valid committed stage must skip computation")

    if surface == "discover":
        monkeypatch.setattr(pipeline_cli, "discover_hypotheses", forbidden_compute)
    elif surface == "confirm":
        monkeypatch.setattr(pipeline_cli, "build_pairs", forbidden_compute)

    def skip_stage() -> None:
        if surface == "pipeline_oracle":
            run_oracle_stage(
                config,
                store,
                condition="observed",
                force=False,
                runner=oracle_runner,
                runtime_validator=lambda: None,
            )
        elif surface == "discover":
            discover_stage(config, store, force=False)
        else:
            confirm_stage(config, store, force=False)

    if control is None:
        skip_stage()
    else:
        with pytest.raises(type(control)) as exc_info:
            skip_stage()
        assert exc_info.value is control

    assert [path.read_bytes() for path in outputs] == committed[0]
    assert manifest.read_bytes() == committed[1]
    assert not store.stage_is_active(
        "run-oracle-observed" if surface == "pipeline_oracle" else surface
    )
    assert not [call for call in oracle_runner.calls if call[1:] != ("--version",)]
    if cleanup_state == "success":
        assert cleanup_attempts == 1
        assert not list(target.parent.glob(stale_pattern))
    else:
        assert cleanup_attempts == 3
        assert list(target.parent.glob(stale_pattern))

        monkeypatch.setattr(Path, "unlink", real_unlink)
        skip_stage()
        assert not list(target.parent.glob(stale_pattern))
        assert [path.read_bytes() for path in outputs] == committed[0]
        assert manifest.read_bytes() == committed[1]


def test_standalone_uses_one_strict_input_snapshot_for_analysis_and_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    original_payload = input_path.read_bytes()
    original_records = read_jsonl(
        input_path,
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    changed_code = "def changed_snapshot():\n    return 7\n"
    changed_record = original_records[0].model_copy(  # type: ignore[index,union-attr]
        update={"code": changed_code, "code_sha256": sha256_text(changed_code)}
    )
    changed_path = tmp_path / "changed.jsonl"
    write_jsonl(changed_path, [changed_record])
    changed_payload = changed_path.read_bytes()
    real_read_jsonl = oracle_cli_module.read_jsonl
    swapped = False

    def swapping_read(path: Path, *args: object, **kwargs: object) -> object:
        nonlocal swapped
        if Path(path) == input_path and not swapped:
            swapped = True
            input_path.write_bytes(changed_payload)
            try:
                return real_read_jsonl(path, *args, **kwargs)
            finally:
                input_path.write_bytes(original_payload)
        return real_read_jsonl(path, *args, **kwargs)

    monkeypatch.setattr(oracle_cli_module, "read_jsonl", swapping_read)
    run_standalone_oracle(
        input_path=input_path,
        output=output,
        policy_lock=POLICY_LOCK,
        semgrep="semgrep-private",
        bandit="bandit-private",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )

    records = read_jsonl(output, OracleRecord, required=True, allow_empty=False)
    assert swapped is False
    assert records[0].code_sha256 == original_records[0].code_sha256  # type: ignore[index,union-attr]
    seal = json.loads(output.with_name(output.name + ".sha256").read_text())
    assert seal["input_sha256"] == hashlib.sha256(original_payload).hexdigest()
    assert seal["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()


def test_standalone_input_is_opened_once_without_path_hash_reopens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    real_os_open = oracle_cli_module.os.open
    input_opens = 0

    def counting_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal input_opens
        if Path(path) == input_path:
            input_opens += 1
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(oracle_cli_module.os, "open", counting_open)
    run_standalone_oracle(
        input_path=input_path,
        output=output,
        policy_lock=POLICY_LOCK,
        semgrep="semgrep-private",
        bandit="bandit-private",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )

    assert input_opens == 1


def test_standalone_snapshot_reads_with_bounded_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    real_os_read = oracle_cli_module.os.read
    input_descriptor: int | None = None
    requested_sizes: list[int] = []
    real_os_open = oracle_cli_module.os.open

    def tracked_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal input_descriptor
        descriptor = real_os_open(path, flags, *args, **kwargs)
        if Path(path) == input_path:
            input_descriptor = descriptor
        return descriptor

    def bounded_read(descriptor: int, size: int) -> bytes:
        if descriptor == input_descriptor:
            requested_sizes.append(size)
            assert size <= 1024 * 1024
        return real_os_read(descriptor, size)

    monkeypatch.setattr(oracle_cli_module.os, "open", tracked_open)
    monkeypatch.setattr(oracle_cli_module.os, "read", bounded_read)
    run_standalone_oracle(
        input_path=input_path,
        output=tmp_path / "standalone-oracle.jsonl",
        policy_lock=POLICY_LOCK,
        semgrep="semgrep-private",
        bandit="bandit-private",
        force=False,
        runner=_OracleRunner(),
        runtime_validator=lambda: None,
    )

    assert requested_sizes


def test_standalone_input_rejects_duplicate_json_keys_before_analysis(
    tmp_path: Path,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    payload = input_path.read_text(encoding="utf-8")
    code_id = json.loads(payload)["code_id"]
    input_path.write_text(
        payload.replace(
            f'"code_id":"{code_id}"',
            f'"code_id":"{code_id}","code_id":"{code_id}"',
            1,
        ),
        encoding="utf-8",
    )
    runner = _OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(
            input_path=input_path,
            output=tmp_path / "standalone-oracle.jsonl",
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not [call for call in runner.calls if call[1:] != ("--version",)]


def test_standalone_input_rejects_hardlinked_snapshot(tmp_path: Path) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    source = store.path("generation", "observed_code.jsonl")
    hardlink = tmp_path / "hardlinked-input.jsonl"
    try:
        hardlink.hardlink_to(source)
    except OSError:
        pytest.skip("hard links are unavailable")
    runner = _OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(
            input_path=hardlink,
            output=tmp_path / "standalone-oracle.jsonl",
            policy_lock=POLICY_LOCK,
            semgrep="semgrep-private",
            bandit="bandit-private",
            force=False,
            runner=runner,
            runtime_validator=lambda: None,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert runner.calls == []


def test_standalone_failed_restore_preserves_recovery_backup_and_next_run_recovers(
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
    real_replace = oracle_cli_module.os.replace

    def fail_install_and_restore(source: object, target: object) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.name.endswith(".seal.candidate") and target_path == seal_path:
            raise OSError("private-seal-install-failure")
        if "backup" in source_path.name and target_path == output:
            raise OSError("private-output-restore-failure")
        real_replace(source, target)

    monkeypatch.setattr(oracle_cli_module.os, "replace", fail_install_and_restore)
    with pytest.raises(SecAwareError):
        run_standalone_oracle(
            force=True,
            runner=_OracleRunner(finding="semgrep"),
            **kwargs,
        )

    recovery = list(output.parent.glob(f".{output.name}.*backup*"))
    assert recovery
    assert any(path.read_bytes() == previous[0] for path in recovery)
    assert not (not output.exists() and not recovery)

    monkeypatch.setattr(oracle_cli_module.os, "replace", real_replace)
    runner = _OracleRunner()
    run_standalone_oracle(force=False, runner=runner, **kwargs)
    assert (output.read_bytes(), seal_path.read_bytes()) == previous
    assert not [call for call in runner.calls if call[1:] != ("--version",)]


def test_pipeline_oracle_failed_restore_preserves_backup_and_next_skip_recovers(
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
    manifest = store.path(".stages", "run-oracle-observed.json")
    previous = (output.read_bytes(), manifest.read_bytes())
    real_replace = pipeline_cli.os.replace

    def fail_install_and_restore(source: object, target: object) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.name.endswith(".oracle.candidate") and target_path == output:
            raise OSError("private-output-install-failure")
        if "backup" in source_path.name and target_path == output:
            raise OSError("private-output-restore-failure")
        real_replace(source, target)

    monkeypatch.setattr(pipeline_cli.os, "replace", fail_install_and_restore)
    with pytest.raises(SecAwareError):
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=True,
            runner=_OracleRunner(finding="semgrep"),
            runtime_validator=lambda: None,
        )

    recovery = list(output.parent.glob(f".{output.name}.*backup*"))
    assert recovery
    assert any(path.read_bytes() == previous[0] for path in recovery)

    monkeypatch.setattr(pipeline_cli.os, "replace", real_replace)
    runner = _OracleRunner()
    run_oracle_stage(
        config,
        store,
        condition="observed",
        force=False,
        runner=runner,
        runtime_validator=lambda: None,
    )
    assert (output.read_bytes(), manifest.read_bytes()) == previous
    assert store.require_committed_output("run-oracle-observed", [output])
    assert not [call for call in runner.calls if call[1:] != ("--version",)]


def test_multioutput_partial_restore_preserves_backup_and_next_skip_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    manifest = store.path(".stages", "discover.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    real_replace = pipeline_cli.os.replace

    def fail_second_install_and_restore(source: object, target: object) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.name.endswith(".stage.candidate") and target_path == outputs[1]:
            raise OSError("private-second-install-failure")
        if "backup" in source_path.name and target_path == outputs[1]:
            raise OSError("private-second-restore-failure")
        real_replace(source, target)

    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(pipeline_cli.os, "replace", fail_second_install_and_restore)
    with pytest.raises(SecAwareError):
        discover_stage(config, store, force=True)

    recovery = list(outputs[1].parent.glob(f".{outputs[1].name}.*backup*"))
    assert recovery
    assert any(path.read_bytes() == previous[0][1] for path in recovery)

    monkeypatch.setattr(pipeline_cli.os, "replace", real_replace)

    def forbidden_compute(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("recovered commit must skip computation")

    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", forbidden_compute)
    discover_stage(config, store, force=False)
    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]
    assert store.require_committed_stage(
        "discover",
        [
            store.path("inputs", "prompts.jsonl"),
            store.path("tsg", "prompt_tsg.jsonl"),
            store.path("oracle", "observed_oracle.jsonl"),
        ],
        outputs,
    )


def test_standalone_tampered_journal_fails_closed_without_deleting_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, store = _prepared_canonical_store(tmp_path)
    input_path = store.path("generation", "observed_code.jsonl")
    output = tmp_path / "standalone-oracle.jsonl"
    kwargs = {
        "input_path": input_path,
        "output": output,
        "policy_lock": POLICY_LOCK,
        "semgrep": "semgrep-private",
        "bandit": "bandit-private",
        "runtime_validator": lambda: None,
    }
    run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)
    real_unlink = Path.unlink

    def leave_backup(path: Path, *args: object, **kwargs: object) -> None:
        if path.name.endswith(".output.recovery.backup"):
            raise OSError("private-cleanup-failure")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", leave_backup)
    run_standalone_oracle(
        force=True,
        runner=_OracleRunner(finding="semgrep"),
        **kwargs,
    )
    monkeypatch.setattr(Path, "unlink", real_unlink)
    journal = output.with_name(f".{output.name}.transaction.json")
    backups = list(output.parent.glob(f".{output.name}.*.output.recovery.backup"))
    assert len(backups) == 1
    journal.write_text(
        journal.read_text(encoding="utf-8").replace(
            '"state":"postcommit"',
            '"state":"postcommit","state":"postcommit"',
            1,
        ),
        encoding="utf-8",
    )
    tampered_journal = journal.read_bytes()
    backup_bytes = backups[0].read_bytes()
    runner = _OracleRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(force=False, runner=runner, **kwargs)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert journal.read_bytes() == tampered_journal
    assert backups[0].read_bytes() == backup_bytes
    assert runner.calls == []


def test_standalone_corrupt_recovery_backup_is_preserved_and_rejected(
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
    real_replace = oracle_cli_module.os.replace

    def fail_install_and_restore(source: object, target: object) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.name.endswith(".seal.candidate") and target_path == seal_path:
            raise OSError("private-install-failure")
        if source_path.name.endswith(".output.recovery.backup") and target_path == output:
            raise OSError("private-restore-failure")
        real_replace(source, target)

    monkeypatch.setattr(oracle_cli_module.os, "replace", fail_install_and_restore)
    with pytest.raises(SecAwareError):
        run_standalone_oracle(
            force=True,
            runner=_OracleRunner(finding="semgrep"),
            **kwargs,
        )
    monkeypatch.setattr(oracle_cli_module.os, "replace", real_replace)
    backups = list(output.parent.glob(f".{output.name}.*.output.recovery.backup"))
    assert len(backups) == 1
    backups[0].write_bytes(b"corrupt-recovery-backup")

    with pytest.raises(SecAwareError) as exc_info:
        run_standalone_oracle(force=False, runner=_OracleRunner(), **kwargs)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert backups[0].read_bytes() == b"corrupt-recovery-backup"


def test_downstream_manifest_restore_failure_preserves_backup_for_next_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_observed_pipeline(tmp_path)
    discover_stage(config, store, force=False)
    outputs = [
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    manifest = store.path(".stages", "discover.json")
    previous = ([path.read_bytes() for path in outputs], manifest.read_bytes())
    real_write = run_store_module.write_stage_manifest
    real_replace = pipeline_cli.os.replace

    def write_then_corrupt(path: Path, value: object) -> None:
        real_write(path, value)  # type: ignore[arg-type]
        path.write_bytes(b'{"corrupt":true}\n')

    def fail_manifest_restore(source: object, target: object) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.name.endswith(".manifest.recovery.backup") and target_path == manifest:
            raise OSError("private-manifest-restore-failure")
        real_replace(source, target)

    monkeypatch.setattr(run_store_module, "write_stage_manifest", write_then_corrupt)
    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(pipeline_cli.os, "replace", fail_manifest_restore)
    with pytest.raises(SecAwareError):
        discover_stage(config, store, force=True)

    backups = list(manifest.parent.glob(".discover.json.*.manifest.recovery.backup"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == previous[1]
    assert [path.read_bytes() for path in outputs] == previous[0]

    monkeypatch.setattr(run_store_module, "write_stage_manifest", real_write)
    monkeypatch.setattr(pipeline_cli.os, "replace", real_replace)

    def forbidden_compute(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("recovered commit must skip computation")

    monkeypatch.setattr(pipeline_cli, "discover_hypotheses", forbidden_compute)
    discover_stage(config, store, force=False)
    assert [path.read_bytes() for path in outputs] == previous[0]
    assert manifest.read_bytes() == previous[1]

from collections.abc import Sequence
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app
from secaware.config import load_config, write_resolved_config
from secaware.errors import ErrorCode
from secaware.io.jsonl import read_jsonl
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.oracle import OracleRecord


class _RunAllOracleRunner:
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
        files = sorted(path.name for path in cwd.iterdir() if path.suffix == ".py")
        if analyzer == "semgrep":
            payload = {
                "version": "1.168.0",
                "results": [],
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
        return AnalyzerProcessResult(0, json.dumps(payload).encode(), "a" * 64)


def test_run_all_demo_uses_canonical_oracle_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / "canonical-demo"
    runner = _RunAllOracleRunner()
    monkeypatch.setattr(cli_module, "run_analyzer_process", runner)
    monkeypatch.setattr(cli_module, "validate_analyzer_runtime", lambda: None)
    monkeypatch.setattr(aggregator_module, "validate_analyzer_runtime", lambda: None)

    result = CliRunner().invoke(
        app,
        ["run-all", "--config", "configs/demo.yaml", "--run-dir", str(run_dir), "--force"],
    )

    assert result.exit_code == 0, result.output
    observed = read_jsonl(
        run_dir / "oracle" / "observed_oracle.jsonl",
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    counterfactual = read_jsonl(
        run_dir / "oracle" / "counterfactual_oracle.jsonl",
        OracleRecord,
        required=True,
        allow_empty=False,
    )
    assert observed and counterfactual
    for condition in ("observed", "counterfactual"):
        manifest = read_stage_manifest(run_dir / ".stages" / f"run-oracle-{condition}.json")
        assert manifest.policy_sha256 is not None
    assert (run_dir / "reports" / "summary.md").exists()
    removed_artifacts = [
        run_dir / "tsg" / (condition + "_" + "code_" + "tsg.jsonl")
        for condition in ("observed", "counterfactual")
    ]
    removed_stage_prefix = "extract-" + "code-" + "tsg"
    assert all(not path.exists() for path in removed_artifacts)
    assert all(
        not path.stem.startswith(removed_stage_prefix)
        for path in run_dir.joinpath(".stages").glob("*.json")
    )


def test_run_all_demo_fails_closed_before_legacy_oracle_publication(tmp_path: Path) -> None:
    runner = CliRunner()
    run_dir = tmp_path / "demo"
    config = load_config("configs/demo.yaml", run_dir=run_dir)
    payload = config.model_dump(mode="python")
    payload["oracle"]["semgrep_executable"] = "missing-secaware-semgrep"
    payload["oracle"]["bandit_executable"] = "missing-secaware-bandit"
    config_path = tmp_path / "demo.yaml"
    write_resolved_config(config.__class__.model_validate(payload), config_path)

    result = runner.invoke(
        app,
        ["run-all", "--config", str(config_path), "--force"],
    )

    assert result.exit_code == int(ErrorCode.ANALYZER_MISSING), result.output
    assert (run_dir / ".stages" / "generate-observed.json").exists()
    assert not (run_dir / "oracle" / "observed_oracle.jsonl").exists()
    assert not (run_dir / ".stages" / "run-oracle-observed.json").exists()
    assert not (run_dir / "reports" / "summary.md").exists()

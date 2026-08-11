from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import secaware.commands.dataset_adjudication as command_module
from secaware.cli import app
from secaware.dataset_adjudication.run import AdjudicationRunResult


runner = CliRunner()


def _config(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "adjudication_version": "adjudication-v1",
                "rubric_version": "adjudication-rubric-v1",
                "packet_version": "adjudication-packets-v1",
                "audit_sample_version": "human-audit-sample-v1",
                "source_audit_run_id": "source-run",
                "source_stable_digest": "d" * 64,
                "expected_source_records": 4,
                "expected_neutrality_packets": 2,
                "expected_cluster_packets": 1,
                "pilot_per_dimension": 1,
                "human_audit_fraction": 0.2,
                "seed": 20260812,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_registers_prepare_dataset_adjudication() -> None:
    result = runner.invoke(app, ["prepare-dataset-adjudication", "--help"])

    assert result.exit_code == 0
    assert "--config" in result.stdout
    assert "--workspace-root" in result.stdout
    assert "--run-id" in result.stdout


def test_prepare_cli_uses_frozen_source_run_from_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (workspace / "src" / "secaware").mkdir(parents=True)
    source = workspace / "runs" / "dataset-audit" / "source-run"
    source.mkdir(parents=True)
    config = _config(tmp_path / "config.json")
    captured = {}

    def fake_prepare(request):
        captured["request"] = request
        output = workspace / "runs" / "dataset-adjudication" / request.run_id
        return AdjudicationRunResult(request.run_id, output, "PACKETS_READY")

    monkeypatch.setattr(command_module, "prepare_adjudication_run", fake_prepare)
    result = runner.invoke(
        app,
        [
            "prepare-dataset-adjudication",
            "--config",
            str(config),
            "--workspace-root",
            str(workspace),
            "--run-id",
            "packet-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["request"].source_run_dir == source.resolve()
    assert "status=PACKETS_READY" in result.stdout

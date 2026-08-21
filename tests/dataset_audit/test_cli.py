from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from secaware.cli import app
from secaware.dataset_audit.catalog import LEGACY_SOURCES


runner = CliRunner()


def _config(path: Path, **updates) -> Path:
    value = {
        "schema_version": "1.0",
        "audit_version": "audit-v1",
        "legacy_snapshot_id": "legacy-2026-08-10",
        "neutrality_rule_version": "neutrality-prescreen-v1",
        "prompt_normalization_version": "prompt-normalization-v1",
        "cluster_version": "task-cluster-v1",
        "split_version": "cluster-split-v1",
        "split_ratios": [0.5, 0.6, 0.7],
        "seed": 20260810,
        "smoke_records_per_dataset": 5,
        "minimum_cluster_floor": 20,
    }
    value.update(updates)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _workspace(path: Path) -> Path:
    path.mkdir()
    (path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (path / "src" / "secaware").mkdir(parents=True)
    return path


def _source_root(path: Path, *, complete: bool = True) -> Path:
    path.mkdir()
    sources = LEGACY_SOURCES if complete else LEGACY_SOURCES[:-1]
    for source in sources:
        (path / source.filename).write_text(
            json.dumps(
                {
                    "task_id": f"{source.source_id}-1",
                    "prompt": "Implement a small parser function.",
                    "language": "python",
                }
            )
            + "\n",
            encoding="utf-8",
        )
    return path


def test_cli_registers_audit_datasets_help() -> None:
    result = runner.invoke(app, ["audit-datasets", "--help"])

    assert result.exit_code == 0
    assert "--source-root" in result.stdout
    assert "--workspace-root" in result.stdout
    assert "--sample-only" in result.stdout
    assert "--skip-v2-download" in result.stdout
    assert "--supersedes-run-id" in result.stdout


def test_cli_rejects_non_repository_workspace(tmp_path: Path) -> None:
    config = _config(tmp_path / "config.json")
    source = _source_root(tmp_path / "source")
    outside = tmp_path / "outside"
    outside.mkdir()

    result = runner.invoke(
        app,
        [
            "audit-datasets",
            "--config",
            str(config),
            "--source-root",
            str(source),
            "--workspace-root",
            str(outside),
            "--run-id",
            "invalid-workspace",
            "--skip-v2-download",
        ],
    )

    assert result.exit_code != 0
    assert "repository workspace" in result.output


def test_cli_rejects_missing_source_and_forbidden_model_config(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path / "workspace")
    incomplete = _source_root(tmp_path / "incomplete", complete=False)
    config = _config(tmp_path / "config.json")
    missing = runner.invoke(
        app,
        [
            "audit-datasets",
            "--config",
            str(config),
            "--source-root",
            str(incomplete),
            "--workspace-root",
            str(workspace),
            "--run-id",
            "missing-source",
            "--skip-v2-download",
        ],
    )
    assert missing.exit_code != 0
    assert "12-file source set" in missing.output

    complete = _source_root(tmp_path / "complete")
    forbidden = _config(tmp_path / "forbidden.json", model="qwen", api_key="secret")
    rejected = runner.invoke(
        app,
        [
            "audit-datasets",
            "--config",
            str(forbidden),
            "--source-root",
            str(complete),
            "--workspace-root",
            str(workspace),
            "--run-id",
            "forbidden-config",
            "--skip-v2-download",
        ],
    )
    assert rejected.exit_code != 0
    assert "configuration is invalid" in rejected.output


def test_cli_runs_small_complete_fixture_and_refuses_overwrite(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path / "workspace")
    source = _source_root(tmp_path / "source")
    config = _config(tmp_path / "config.json")
    arguments = [
        "audit-datasets",
        "--config",
        str(config),
        "--source-root",
        str(source),
        "--workspace-root",
        str(workspace),
        "--run-id",
        "fixture-run",
        "--sample-only",
        "--skip-v2-download",
    ]

    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)

    assert first.exit_code == 0, first.output
    assert "status=COMPLETE" in first.stdout
    assert (workspace / "runs" / "dataset-audit" / "fixture-run" / "report.json").is_file()
    assert second.exit_code != 0
    assert "already exists" in second.output

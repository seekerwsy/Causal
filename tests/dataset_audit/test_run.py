from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from secaware.dataset_audit.catalog import LegacySource
from secaware.dataset_audit.run import AuditRequest, AuditRunConflictError, execute_audit


CATALOG = (
    LegacySource(source_id="alpha", filename="alpha.jsonl"),
    LegacySource(source_id="beta", filename="beta.jsonl"),
)
EXPECTED_ARTIFACTS = {
    "config.json",
    "commands.jsonl",
    "environment.json",
    "run.log.jsonl",
    "file-inventory.jsonl",
    "record-audit.jsonl",
    "duplicate-groups.jsonl",
    "cluster-summary.jsonl",
    "split-simulations.jsonl",
    "dataset-role-summary.jsonl",
    "failures.jsonl",
    "report.json",
    "report.md",
}


def _sources(root: Path) -> Path:
    source = root / "input"
    source.mkdir()
    (source / "alpha.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "task_id": "CWE-89-a",
                        "prompt": "Implement a customer lookup function.",
                        "language": "python",
                        "test": "assert True",
                    }
                ),
                "{malformed",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (source / "beta.jsonl").write_text(
        json.dumps(
            {
                "task_id": "b",
                "prompt": "Implement secure authentication for the service.",
                "language": "python",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return source


def _request(tmp_path: Path, run_id: str, **updates) -> AuditRequest:
    values = {
        "source_root": _sources(tmp_path),
        "workspace_root": tmp_path / "workspace",
        "run_id": run_id,
        "catalog": CATALOG,
        "config": {
            "schema_version": "1.0",
            "split_ratios": [0.5, 0.6, 0.7],
            "seed": 7,
            "minimum_cluster_floor": 20,
        },
        "command_argv": ("secaware", "audit-datasets", "--sample-only"),
        "skip_v2_download": True,
        "sample_records_per_dataset": 5,
    }
    values.update(updates)
    return AuditRequest(**values)


def test_successful_run_publishes_complete_immutable_artifact_set(tmp_path: Path) -> None:
    request = _request(tmp_path, "run-a")

    result = execute_audit(request)

    assert result.status == "COMPLETE_WITH_RECORD_FAILURES"
    assert {path.name for path in result.run_dir.iterdir()} == EXPECTED_ARTIFACTS
    failure_lines = (result.run_dir / "failures.jsonl").read_text("utf-8").splitlines()
    failures = [json.loads(line) for line in failure_lines]
    assert failures[0]["code"] == "MALFORMED_JSONL_RECORD"
    report = json.loads((result.run_dir / "report.json").read_text("utf-8"))
    assert report["progress"] == {
        "completed": 2,
        "eta_seconds": 0.0,
        "failed": 1,
        "pending": 0,
        "records_per_second": 0.0,
        "running": 0,
        "total": 3,
        "unresolved": 1,
    }
    with pytest.raises(AuditRunConflictError):
        execute_audit(request)


def test_identical_inputs_have_same_stable_digest_across_run_ids(tmp_path: Path) -> None:
    source = _sources(tmp_path)
    common = {
        "source_root": source,
        "workspace_root": tmp_path / "workspace",
        "catalog": CATALOG,
        "config": {
            "schema_version": "1.0",
            "split_ratios": [0.5],
            "seed": 2,
            "minimum_cluster_floor": 20,
        },
        "command_argv": ("secaware", "audit-datasets"),
        "skip_v2_download": True,
        "sample_records_per_dataset": 5,
    }
    first = execute_audit(AuditRequest(run_id="run-a", **common))
    second = execute_audit(AuditRequest(run_id="run-b", supersedes_run_id="run-a", **common))

    assert first.stable_digest == second.stable_digest
    assert first.run_dir != second.run_dir


def test_phase_failure_publishes_failed_run_and_linked_rerun_can_complete(tmp_path: Path) -> None:
    request = _request(tmp_path, "failed-run")

    def fail_after_adaptation(phase: str) -> None:
        if phase == "adaptation":
            raise RuntimeError("injected phase failure")

    failed = execute_audit(request, phase_observer=fail_after_adaptation)

    assert failed.status == "FAILED"
    assert (failed.run_dir / "failures.jsonl").is_file()
    assert (failed.run_dir / "report.json").is_file()
    rerun = execute_audit(
        replace(request, run_id="recovered-run", supersedes_run_id="failed-run")
    )
    assert rerun.status == "COMPLETE_WITH_RECORD_FAILURES"

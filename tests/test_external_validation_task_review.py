from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.exploratory.external_validation_task_review import (
    prepare_external_validation_task_review,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_external_task_review_preparation_is_outcome_blind(tmp_path: Path) -> None:
    cwes = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
    queue = tmp_path / "queue.jsonl"
    _write_jsonl(
        queue,
        [
            {
                "source_id": "fixture",
                "source_record_id": f"record-{index}",
                "exact_prompt_sha256": hashlib.sha256(f"prompt-{index}".encode()).hexdigest(),
                "language": "python" if index % 2 else "java",
                "cwe": cwes[index % len(cwes)],
                "prompt": f"Generate target operation {index}.",
                "source_ancestry_risk": "fixture_ancestry",
                "repository_asset_exact_overlap": False,
                "functional_contract": "absent",
                "validation_stratum": "python_primary_candidate",
                "method_development_exact_overlap": False,
                "review_status": "blinded_task_review_required",
            }
            for index in range(30)
        ],
    )
    source_report = tmp_path / "report.json"
    _write_json(source_report, {"status": "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED"})
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "review_id": "five_cwe_external_validation_task_review_v1",
            "target_cwes": list(cwes),
            "expected_packets": 30,
            "inputs": {
                "review_queue": {"path": "queue.jsonl", "sha256": _sha(queue)},
                "source_audit_report": {"path": "report.json", "sha256": _sha(source_report)},
            },
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
        },
    )

    report = prepare_external_validation_task_review(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "prepared",
        command_argv=("prepare",),
    )

    assert report["status"] == "EXTERNAL_VALIDATION_TASK_REVIEW_PACKETS_READY"
    assert report["counts"] == {
        "packets": 30,
        "provider_calls": 0,
        "completed": 0,
        "errors": 0,
        "pending": 30,
    }
    packet = json.loads(
        (tmp_path / "prepared" / "candidate-packets.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert packet["split"] == "confirm"
    assert packet["blindness"]["outcomes_withheld"] is True

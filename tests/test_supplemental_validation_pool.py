from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.exploratory.supplemental_validation_pool import (
    freeze_supplemental_validation_pool,
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


def test_supplemental_pool_reaches_minimum_without_public_prompts(tmp_path: Path) -> None:
    cwes = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
    prior = tmp_path / "prior.jsonl"
    _write_jsonl(
        prior,
        [
            {
                "cwe": cwes[index % len(cwes)],
                "semantic_cluster_id": f"prior-{index}",
                "source_prompt_sha256": hashlib.sha256(f"prior-{index}".encode()).hexdigest(),
            }
            for index in range(40)
        ],
    )
    review = tmp_path / "review.jsonl"
    review_rows = [
        {
            "source_record_id": f"record-{index}",
            "cwe": "CWE-78",
            "review_status": "blinded_task_review_required",
            "exact_prompt_sha256": hashlib.sha256(f"new-{index}".encode()).hexdigest(),
            "prompt": f"Restricted prompt {index}",
        }
        for index in range(10)
    ]
    _write_jsonl(review, review_rows)
    adjudications = tmp_path / "adjudications.jsonl"
    _write_jsonl(
        adjudications,
        [
            {
                "source_record_id": f"record-{index}",
                "eligible": True,
                "reason_code": "accepted",
                "rationale": "Profile-compatible fixture.",
                "semantic_group_id": f"group-{index}",
                "prior_pool_semantic_overlap": False,
                "neutrality_override": False,
            }
            for index in range(10)
        ],
    )
    source_report = tmp_path / "source-report.json"
    _write_json(
        source_report,
        {
            "status": "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED",
            "outcomes_consumed": 0,
            "reference_fields_consumed": 0,
        },
    )
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "pool_id": "five_cwe_supplemental_independent_validation_pool_v1",
            "required_cwes": list(cwes),
            "minimum_validation_tasks": 50,
            "expected_prior_clusters": 40,
            "expected_review_units": 10,
            "expected_eligible_units": 10,
            "expected_supplemental_clusters": 10,
            "inputs": {
                "prior_candidates": {"path": "prior.jsonl", "sha256": _sha(prior)},
                "review_queue": {"path": "review.jsonl", "sha256": _sha(review)},
                "source_report": {
                    "path": "source-report.json",
                    "sha256": _sha(source_report),
                },
                "adjudications": {
                    "path": "adjudications.jsonl",
                    "sha256": _sha(adjudications),
                },
            },
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
            "raw_prompt_redistribution_allowed": False,
        },
    )

    report = freeze_supplemental_validation_pool(
        repo_root=tmp_path,
        config_path=config,
        public_run_dir=tmp_path / "public",
        restricted_run_dir=tmp_path / "restricted",
        command_argv=("freeze",),
    )

    assert report["status"] == "INDEPENDENT_VALIDATION_POOL_READY_FOR_MEASUREMENT_FREEZE"
    assert report["counts"]["final_independent_clusters"] == 50
    public_text = "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "public").iterdir()
        if path.is_file()
    )
    assert "Restricted prompt" not in public_text
    assert "Restricted prompt" in (
        tmp_path / "restricted" / "supplemental-selected-prompts.jsonl"
    ).read_text(encoding="utf-8")

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.exploratory.external_validation_semantic_pool import (
    freeze_external_validation_semantic_pool,
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


def test_semantic_pool_collapses_variants_and_excludes_method_overlap(tmp_path: Path) -> None:
    records = ["a", "b", "c", "d", "e"]
    decisions = tmp_path / "decisions.jsonl"
    _write_jsonl(
        decisions,
        [
            {"record_id": record, "audit": {"eligible": record != "e"}}
            for record in records
        ],
    )
    packets = tmp_path / "packets.jsonl"
    _write_jsonl(
        packets,
        [
            {
                "record_id": record,
                "cwe": "CWE-78" if record in {"a", "b", "c"} else "CWE-89",
                "source_id": "codeguard_plus",
                "language": "python",
                "source_prompt_sha256": hashlib.sha256(record.encode()).hexdigest(),
                "functional_contract_source": "executable_test",
            }
            for record in records
        ],
    )
    selection = tmp_path / "selection.json"
    _write_json(selection, {"tasks": [{"task_id": "old", "cwe": "CWE-78"}]})
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "pool_id": "five_cwe_external_validation_semantic_pool_v1",
            "required_cwes": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
            "minimum_validation_tasks": 2,
            "expected_review_decisions": 5,
            "expected_eligible_units": 4,
            "inputs": {
                "review_decisions": {"path": "decisions.jsonl", "sha256": _sha(decisions)},
                "prepared_packets": {"path": "packets.jsonl", "sha256": _sha(packets)},
                "method_selection": {"path": "selection.json", "sha256": _sha(selection)},
            },
            "semantic_merge_groups": [
                {
                    "group_id": "external-semantic-cluster-fixture",
                    "members": ["a", "b"],
                    "rationale": "same observable task",
                }
            ],
            "method_development_semantic_overlaps": [
                {
                    "external_record_id": "c",
                    "method_task_id": "old",
                    "rationale": "same as old task",
                }
            ],
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
        },
    )

    report = freeze_external_validation_semantic_pool(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "run",
        command_argv=("freeze",),
    )

    assert report["counts"]["eligible_prompt_units"] == 4
    assert report["counts"]["semantic_task_clusters"] == 3
    assert report["counts"]["method_development_overlap_clusters"] == 1
    assert report["counts"]["independent_candidate_clusters"] == 2
    assert report["status"] == "INDEPENDENT_VALIDATION_POOL_BLOCKED"

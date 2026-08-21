from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.functional_audit.cross_source import (
    audit_cross_source_coverage,
    prepare_cross_source_audit_packets,
)
from secaware.functional_audit.main_pool import MAIN_CWE_ORDER


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _record(
    source: str,
    record_id: str,
    cwe: str,
    cluster: str,
    digest: str,
    *,
    language: str = "python",
    neutrality: str = "CANDIDATE_NEUTRAL",
    independent: bool = True,
) -> dict[str, object]:
    return {
        "coordinate": {"source_id": source, "record_id": record_id},
        "language": language,
        "neutrality": neutrality,
        "cwe_ids": [cwe],
        "task_cluster_id": cluster,
        "exact_prompt_sha256": digest,
        "cluster_independence_resolved": independent,
        "prompt": f"Prompt {record_id}",
    }


def test_cross_source_coverage_excludes_baseline_and_separates_independence(
    tmp_path: Path,
) -> None:
    records = tmp_path / "records.jsonl"
    _write_jsonl(
        records,
        [
            _record("baseline", "b1", "CWE-78", "cluster-shared", "digest-shared"),
            _record("source-a", "a1", "CWE-78", "cluster-shared", "digest-shared"),
            _record("source-a", "a2", "CWE-78", "cluster-strict", "digest-a2"),
            _record(
                "source-b",
                "b2",
                "CWE-502",
                "cluster-unresolved",
                "digest-b2",
                independent=False,
            ),
            _record(
                "source-b",
                "b3",
                "CWE-502",
                "cluster-wrong-language",
                "digest-b3",
                language="java",
            ),
        ],
    )
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "main_cwes": ["CWE-78", "CWE-502"],
            "baseline_source": "baseline",
            "split_simulation_seed": 7,
            "split_discover_ratio": 0.5,
            "candidate_sources": ["source-a", "source-b"],
            "source_priority": ["source-a", "source-b"],
            "language": "python",
            "neutrality": "CANDIDATE_NEUTRAL",
        },
    )
    split_simulations = tmp_path / "splits.jsonl"
    _write_jsonl(
        split_simulations,
        [
            {
                "seed": 7,
                "discover_ratio": 0.5,
                "assignments": [
                    {"cluster_id": "cluster-shared", "split": "confirm"},
                    {"cluster_id": "cluster-strict", "split": "discover"},
                    {"cluster_id": "cluster-unresolved", "split": "UNRESOLVED"},
                    {"cluster_id": "cluster-wrong-language", "split": "confirm"},
                ],
            }
        ],
    )

    report = audit_cross_source_coverage(
        record_audit=records,
        split_simulations=split_simulations,
        config_path=config,
        run_dir=tmp_path / "run",
        command_argv=("audit",),
    )

    assert report["provider_calls"] == 0
    assert report["candidate_clusters_by_cwe_independence"] == {
        "CWE-78": {"strict": 1},
        "CWE-502": {"unresolved": 1},
    }
    assert report["filter_counts"]["excluded_baseline_overlap"] == 1
    assert report["filter_counts"]["excluded_language"] == 1
    assert report["candidate_clusters_by_cwe_independence_split"] == {
        "CWE-78": {"strict": {"discover": 1}},
        "CWE-502": {"unresolved": {"UNRESOLVED": 1}},
    }
    candidates = [
        json.loads(line)
        for line in (tmp_path / "run" / "candidate-clusters.jsonl").read_text().splitlines()
    ]
    assert [row["task_cluster_id"] for row in candidates] == [
        "cluster-strict",
        "cluster-unresolved",
    ]


def test_prepare_cross_source_audit_packets_preserves_frozen_splits(tmp_path: Path) -> None:
    coverage_dir = tmp_path / "coverage"
    coverage_dir.mkdir()
    candidates_path = coverage_dir / "candidate-clusters.jsonl"
    rows = [
        {
            "schema_version": "1.0",
            "cwe": cwe,
            "task_cluster_id": f"cluster-{index}",
            "independence": "strict",
            "split": "discover" if index % 2 == 0 else "confirm",
            "representative": {
                "source_id": "source-a",
                "record_id": f"record-{index}",
                "exact_prompt_sha256": f"digest-{index}",
                "prompt": f"Write a Python function for {cwe}.",
            },
            "members": [],
        }
        for index, cwe in enumerate(MAIN_CWE_ORDER)
    ]
    _write_jsonl(candidates_path, rows)
    _write_json(
        coverage_dir / "report.json",
        {
            "artifacts": {
                "candidate-clusters.jsonl": hashlib.sha256(candidates_path.read_bytes()).hexdigest()
            }
        },
    )
    config = tmp_path / "prepare-config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "selection_seed": 11,
            "expected_strict_clusters_by_cwe": {cwe: 1 for cwe in MAIN_CWE_ORDER},
        },
    )

    report = prepare_cross_source_audit_packets(
        coverage_dir=coverage_dir,
        config_path=config,
        run_dir=tmp_path / "prepared",
        command_argv=("prepare",),
    )

    assert report["status"] == "CROSS_SOURCE_AUDIT_PACKETS_READY"
    assert report["counts"]["packets"] == 5
    assert report["counts"]["provider_calls"] == 0
    packets = [
        json.loads(line)
        for line in (tmp_path / "prepared" / "candidate-packets.jsonl").read_text().splitlines()
    ]
    assert {packet["record_id"] for packet in packets} == {
        f"source-a:record-{index}" for index in range(5)
    }

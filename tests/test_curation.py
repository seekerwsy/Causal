from __future__ import annotations
from pathlib import Path
from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.curation import assemble_semantic_clusters


def test_exact_prompt_and_frozen_lineage_are_the_only_merge_authorities(
    tmp_path: Path,
) -> None:
    prepared = tmp_path / "prepared"
    records = [
        {
            "record_id": name,
            "language": "python",
            "cwe": "CWE-1",
            "source_lineage_family": "independent",
            "source_item_id": name,
            "source_test_references": [],
        }
        for name in ("a", "b")
    ] + [
        {
            "record_id": "c",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "SecEvalBase:shared.py",
            "source_test_references": [],
        },
        {
            "record_id": "d",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "shared.py",
            "source_test_references": [],
        },
        {
            "record_id": "e",
            "language": "python",
            "cwe": "CWE-2",
            "source_lineage_family": "securityeval",
            "source_item_id": "SecEvalBase:shared.py",
            "source_test_references": [],
        },
    ]
    write_bundle(
        prepared,
        {
            "records.json": records,
            "provisional-clusters.json": [
                {"record_ids": ["a", "b"]},
                {"record_ids": ["c"]},
                {"record_ids": ["d"]},
                {"record_ids": ["e"]},
            ],
        },
    )
    candidates = tmp_path / "candidates"
    write_bundle(candidates, {"dedup-candidates.json": []})
    adjudication = tmp_path / "adjudication"
    write_bundle(
        adjudication / "plan",
        {
            "plan.json": {
                "prepared_bundle_sha256": bundle_digest(prepared),
                "candidates_bundle_sha256": bundle_digest(candidates),
                "candidate_pair_count": 0,
                "batch_ids": [],
            }
        },
    )
    (adjudication / "batches").mkdir()

    output = tmp_path / "clusters"
    report = assemble_semantic_clusters(prepared, candidates, adjudication, output)

    assert report["cluster_assembly_rule"] == "exact_prompt_and_frozen_lineage_only_v1"
    assert report["merge_edge_count"] == 3
    assert sorted(
        len(item["record_ids"]) for item in read_json(output / "semantic-clusters.json")
    ) == [2, 3]

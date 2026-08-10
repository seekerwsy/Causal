from __future__ import annotations

from secaware.dataset_audit.report import build_gap_report


def test_gap_report_distinguishes_facts_prescreens_and_unresolved() -> None:
    report, markdown = build_gap_report(
        run_id="run-a",
        status="COMPLETE",
        progress={
            "total": 3,
            "completed": 2,
            "running": 0,
            "failed": 0,
            "unresolved": 1,
            "pending": 0,
            "records_per_second": 2.0,
            "eta_seconds": 0.0,
        },
        counts={
            "dataset": {"alpha": 3},
            "language": {"python": 3},
            "cwe": {"CWE-89": 2, "UNRESOLVED": 1},
            "neutrality": {"CANDIDATE_NEUTRAL": 2, "UNRESOLVED": 1},
            "functional": {"PRESENT_UNVALIDATED": 1, "ABSENT": 2},
        },
        overlap={"relationship": "not_evaluated"},
        gaps=("one record requires neutrality adjudication",),
    )

    assert report["status"] == "COMPLETE"
    assert report["progress"]["unresolved"] == 1
    assert "Verified inventory facts" in markdown
    assert "Deterministic pre-screen" in markdown
    assert "Unresolved evidence and gaps" in markdown
    assert "does not establish statistical power" in markdown


def test_report_stable_digest_excludes_run_identity() -> None:
    arguments = {
        "status": "COMPLETE",
        "progress": {
            "total": 1,
            "completed": 1,
            "running": 0,
            "failed": 0,
            "unresolved": 0,
            "pending": 0,
            "records_per_second": 1.0,
            "eta_seconds": 0.0,
        },
        "counts": {"dataset": {"alpha": 1}},
        "overlap": {"relationship": "not_evaluated"},
        "gaps": (),
    }

    first, _ = build_gap_report(run_id="run-a", **arguments)
    second, _ = build_gap_report(run_id="run-b", **arguments)

    assert first["run_id"] != second["run_id"]
    assert first["stable_digest"] == second["stable_digest"]


def test_report_stable_digest_excludes_runtime_rate_and_eta() -> None:
    progress = {
        "total": 10,
        "completed": 10,
        "running": 0,
        "failed": 0,
        "unresolved": 1,
        "pending": 0,
        "records_per_second": 5.0,
        "eta_seconds": 0.0,
    }
    first, _ = build_gap_report(
        run_id="run-a",
        status="COMPLETE",
        progress=progress,
        counts={"dataset": {"alpha": 10}},
        overlap={"relationship": "not_evaluated"},
        gaps=(),
    )
    second, _ = build_gap_report(
        run_id="run-b",
        status="COMPLETE",
        progress={**progress, "records_per_second": 50.0, "eta_seconds": 3.0},
        counts={"dataset": {"alpha": 10}},
        overlap={"relationship": "not_evaluated"},
        gaps=(),
    )

    assert first["stable_digest"] == second["stable_digest"]


def test_gap_report_places_split_role_and_overlap_evidence_near_conclusions() -> None:
    _, markdown = build_gap_report(
        run_id="run-a",
        status="COMPLETE",
        progress={
            "total": 10,
            "completed": 10,
            "running": 0,
            "failed": 0,
            "unresolved": 1,
            "pending": 0,
            "records_per_second": 5.0,
            "eta_seconds": 0.0,
        },
        counts={
            "dataset": {"cyberseceval_instruct_v2": 10},
            "language": {"python": 10},
            "cwe": {"CWE-89": 9, "UNRESOLVED": 1},
            "neutrality": {"CANDIDATE_NEUTRAL": 9, "UNRESOLVED": 1},
            "functional": {"ABSENT": 10},
        },
        overlap={
            "relationship": "legacy_and_v2_evaluated",
            "legacy_exact_overlap": 2,
            "v2_unique": 10,
            "v2_legacy_union_overlap": 3,
        },
        split_summaries=(
            {
                "discover_ratio": 0.6,
                "seed": 20260810,
                "version": "cluster-split-v1",
                "summary": {
                    "independent_clusters": 9,
                    "discover_clusters": 5,
                    "confirm_clusters": 4,
                    "unresolved_clusters": 1,
                    "pipeline_floor": 5,
                    "pipeline_floor_met": True,
                },
            },
        ),
        dataset_roles=(
            {
                "dataset_id": "cyberseceval_instruct_v2",
                "roles": ["SECURITY_ONLY_SECONDARY_CANDIDATE"],
                "blocking_reasons": [
                    "no existing executable functional contract was validated"
                ],
            },
        ),
        gaps=("one record requires adjudication",),
    )

    assert "| 60/40 | 9 | 5 | 4 | 1 | 5 | yes |" in markdown
    assert "| cyberseceval_instruct_v2 | Security-only secondary candidate |" in markdown
    assert "No existing executable functional contract was validated" in markdown
    assert "| Legacy 150/260 exact overlap | 2 |" in markdown
    assert "| v2 overlap with legacy union | 3 |" in markdown
    assert "do not freeze the CWE scope" in markdown

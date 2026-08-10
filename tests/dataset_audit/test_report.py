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

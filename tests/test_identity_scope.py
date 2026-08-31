import hashlib
import json

import pytest

from prompt_mechanism_study.identity_scope import validate_identity_scope


@pytest.mark.reviewer
def test_identity_scope_replays_complete_three_stratum_census(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("[]", encoding="utf-8")
    task_ids = ["task-context", "task-source", "task-static"]
    rows = [
        {
            "task_unit_id": "task-context",
            "language": "python",
            "primary_cwe": "CWE-306",
            "candidate_status": "PENDING_ORACLE",
            "source_test_available": False,
        },
        {
            "task_unit_id": "task-source",
            "language": "python",
            "primary_cwe": "CWE-862",
            "candidate_status": "PENDING_ORACLE",
            "source_test_available": True,
        },
        {
            "task_unit_id": "task-static",
            "language": "python",
            "primary_cwe": "CWE-798",
            "candidate_status": "READY_CONFIRMATORY",
            "source_test_available": False,
        },
    ]
    (tmp_path / "final.json").write_text(json.dumps(rows), encoding="utf-8")
    strata = {
        "qualified_static": {
            "count": 1,
            "task_unit_ids": ["task-static"],
        },
        "source_native_safety_test_candidate": {
            "count": 1,
            "task_unit_ids": ["task-source"],
        },
        "contextual_or_incomplete_oracle": {
            "count": 1,
            "task_unit_ids": ["task-context"],
        },
    }
    decision = {
        "schema_version": "1.0",
        "decision_basis": "complete_outcome_blind_quality_census",
        "arms_or_outcomes_used": False,
        "family_definition": {
            "language": "python",
            "planned_cwes": [
                "CWE-200",
                "CWE-287",
                "CWE-306",
                "CWE-732",
                "CWE-798",
                "CWE-862",
            ],
            "observed_cwes": ["CWE-200", "CWE-306", "CWE-732", "CWE-798", "CWE-862"],
            "zero_count_cwes": ["CWE-287"],
            "planning_target_is_admission_gate": False,
            "quality_qualified_task_units": len(task_ids),
        },
        "measurement_strata": strata,
        "source_test_audit": {
            "accepted_by_cwe": {"CWE-862": 1},
            "source_files": [
                {
                    "path": "source.json",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ],
        },
        "next_gate": {"formal_execution_authorized": False},
    }
    (tmp_path / "decision.json").write_text(json.dumps(decision), encoding="utf-8")

    report = validate_identity_scope(
        tmp_path / "decision.json", tmp_path / "final.json", tmp_path
    )

    assert report["identity_task_units"] == 3
    assert report["measurement_stratum_counts"] == {
        "qualified_static": 1,
        "source_native_safety_test_candidate": 1,
        "contextual_or_incomplete_oracle": 1,
    }
    assert report["formal_execution_authorized"] is False

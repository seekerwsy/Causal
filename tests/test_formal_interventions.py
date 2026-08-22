from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.formal import (
    finalize_interventions,
    load_formal_inputs,
    load_intervention_phase,
    preflight_interventions,
    run_intervention_phase,
    validate_execution_response,
    validate_semantic_response,
)

ROOT = Path(__file__).parents[1]


@pytest.mark.reviewer
def test_formal_selection_and_free_text_boundaries(tmp_path: Path) -> None:
    inputs = load_formal_inputs(ROOT)
    assert len(inputs.confirm_tasks) == 30
    assert len({row["task_cluster_id"] for row in inputs.confirm_tasks}) == 30
    assert {row["cwe"] for row in inputs.confirm_tasks} == {
        "CWE-78",
        "CWE-89",
        "CWE-502",
        "CWE-328",
        "CWE-338",
    }
    report = preflight_interventions(ROOT, tmp_path / "preflight")
    assert report["provider_calls"] == 0
    execution = validate_execution_response(
        b'{"target_text":"Use the named safety mechanism.",'
        b'"noop_text":"Keep the implementation easy to review."}',
        maximum=100,
    )
    assert set(execution) == {"target_text", "noop_text"}
    with pytest.raises(ValueError, match="format validation"):
        validate_execution_response(
            b'{"target_text":"Rewrite the task.\\nOnly return the code.",'
            b'"noop_text":"Keep the task unchanged."}',
            maximum=100,
        )
    validation = validate_semantic_response(_semantic_response())
    assert validation["target"]["task_preserved"] == "yes"

    failed_root = tmp_path / "source-rewrite"
    failed = run_intervention_phase(
        ROOT,
        "pilot",
        failed_root,
        provider=_source_rewrite_provider,
    )
    assert failed["status"] == "PILOT_FAILED"
    assert failed["provider_attempts"] == 1
    add_evidence = json.loads((failed_root / "task-01/add.json").read_text(encoding="utf-8"))
    assert add_evidence["execution_response_raw"]
    assert add_evidence["error_type"] == "FormalStudyError"


@pytest.mark.milestone
def test_formal_intervention_freeze_smoke(tmp_path: Path) -> None:
    pilot = tmp_path / "pilot"
    remaining = tmp_path / "remaining"
    frozen = tmp_path / "frozen"
    pilot_report = run_intervention_phase(ROOT, "pilot", pilot, provider=_fake_provider)
    assert pilot_report["status"] == "PILOT_PASSED"
    assert pilot_report["provider_attempts"] == 20
    remaining_report = run_intervention_phase(
        ROOT,
        "remaining",
        remaining,
        pilot_root=pilot,
        provider=_fake_provider,
    )
    assert remaining_report["status"] == "REMAINING_COMPLETE"
    assert load_intervention_phase(remaining)["completed_tasks"] == 25
    report = finalize_interventions(ROOT, pilot, remaining, frozen)
    assert report["status"] == "FORMAL_INTERVENTIONS_FROZEN"
    assert report["tasks_per_study"] == 30
    assert report["provider_attempts"] == 120


def _fake_provider(request: dict, _evaluator: object, _prompt: str) -> bytes:
    if "target_text" in request:
        return _semantic_response()
    operation = request["operation"]
    return json.dumps(
        {
            "target_text": f"Apply only the requested {operation} mechanism change.",
            "noop_text": "Keep the current implementation constraints unchanged.",
        },
        separators=(",", ":"),
    ).encode()


def _source_rewrite_provider(request: dict, _evaluator: object, _prompt: str) -> bytes:
    return json.dumps(
        {
            "target_text": request["source_prompt"],
            "noop_text": "Keep the current implementation constraints unchanged.",
        },
        separators=(",", ":"),
    ).encode()


def _semantic_response() -> bytes:
    verdict = {
        "task_preserved": "yes",
        "contract_satisfied": "yes",
        "unintended_changes": "no",
        "contradiction": "no",
    }
    return json.dumps(
        {"target": verdict, "noop": verdict, "reason": "Both suffixes preserve the task."},
        separators=(",", ":"),
    ).encode()

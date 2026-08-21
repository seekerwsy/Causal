from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import verify_bundle
from prompt_mechanism_study.functional_judge import (
    JudgeGateError,
    MEASUREMENT_METHOD,
    load_gate_inputs,
    preflight,
    request_for,
    run_phase,
    validate_response,
)
from prompt_mechanism_study.records import content_hash


pytestmark = pytest.mark.reviewer
ROOT = Path(__file__).parents[1]


def _response(contract: dict[str, object], status: str, *, advisory: str | None = None) -> bytes:
    requirements = []
    for index, requirement in enumerate(contract["requirements"]):
        verdict = "not_met" if status == "fail" and index == 0 else "met"
        requirements.append(
            {
                "requirement_id": requirement["requirement_id"],
                "verdict": verdict,
                "code_evidence_lines": [1],
                "behavior_trace": (
                    "The cited line establishes the behavior." if verdict == "met" else None
                ),
                "counterexample": (
                    {
                        "contract_satisfying_scenario": "A valid contract input is supplied.",
                        "expected_behavior": "The required behavior occurs.",
                        "actual_behavior": "The cited program takes a different action.",
                    }
                    if verdict == "not_met"
                    else None
                ),
                "unknown_reason": None,
            }
        )
    payload = {
        "measurement_method": MEASUREMENT_METHOD,
        "execution_performed": False,
        "requirements": requirements,
        "rationale": "Requirement-level static evaluation.",
    }
    if advisory is not None:
        payload["status"] = advisory
    return json.dumps(payload, separators=(",", ":")).encode()


def test_preflight_closes_frozen_inputs_without_provider(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("ALI_BAILIAN_API_KEY", raising=False)
    output = tmp_path / "preflight"

    report = preflight(ROOT, output)

    verify_bundle(output)
    assert report["status"] == "JUDGE_GATE_PREFLIGHT_COMPLETE"
    assert report["provider_attempts"] == 0
    assert report["live_ready"] is False
    assert len(report["pilot_case_ids"]) == 4
    assert len(report["remaining_case_ids"]) == 12


def test_v3_derives_failure_and_ignores_conflicting_advisory() -> None:
    inputs = load_gate_inputs(ROOT)
    case = next(item for item in inputs.cases if item["expected_status"] == "fail")
    contract = inputs.contracts[case["task_id"]]

    result = validate_response(_response(contract, "fail", advisory="pass"), case, contract)

    assert result["status"] == "fail"
    assert result["advisory_status_agrees"] is False
    malformed = json.loads(_response(contract, "fail"))
    malformed["requirements"][0]["counterexample"] = None
    with pytest.raises(JudgeGateError):
        validate_response(json.dumps(malformed).encode(), case, contract)


def test_pilot_runs_four_closed_single_attempt_cases(tmp_path: Path) -> None:
    inputs = load_gate_inputs(ROOT)
    expected_by_request = {
        content_hash(request_for(case, inputs.contracts[case["task_id"]])): (
            case["expected_status"], inputs.contracts[case["task_id"]]
        )
        for case in inputs.cases
    }

    def provider(request, _evaluator, _prompt):
        expected, contract = expected_by_request[content_hash(request)]
        return _response(contract, expected)

    output = tmp_path / "pilot"
    report = run_phase(ROOT, "pilot", output, provider=provider)

    verify_bundle(output / "summary")
    assert report["status"] == "PILOT_PASSED"
    assert report["metrics"] == {
        "cases": 4,
        "correct": 4,
        "false_pass": 0,
        "false_fail": 0,
        "unknown": 0,
        "invalid": 0,
        "provider_attempts": 4,
    }

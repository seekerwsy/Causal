from __future__ import annotations

import json
from pathlib import Path

import pytest

import prompt_mechanism_study.functional_judge as functional_judge_module
from prompt_mechanism_study.artifact_io import verify_bundle
from prompt_mechanism_study.functional_judge import (
    JudgeGateError,
    bailian_complete,
    load_gate_inputs,
    preflight,
    python_syntax_valid,
    request_for,
    run_phase,
    validate_review_response,
)
from prompt_mechanism_study.records import content_hash

pytestmark = pytest.mark.extended
ROOT = Path(__file__).parents[1]


def _response(_contract: dict[str, object], status: str) -> bytes:
    payload = {
        "verdict": status,
        "evidence_lines": [1],
        "reason": "The cited line establishes or contradicts the requested behavior.",
    }
    return json.dumps(payload, separators=(",", ":")).encode()


@pytest.mark.reviewer
def test_provider_forwards_frozen_json_schema(monkeypatch) -> None:
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "bounded_output",
            "strict": True,
            "schema": {"type": "object"},
        },
    }

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _maximum):
            return json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "{}"},
                        }
                    ]
                }
            ).encode()

    def urlopen(request, timeout):
        assert timeout == 1.0
        assert json.loads(request.data)["response_format"] == response_format
        return Response()

    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "test-only")
    monkeypatch.setattr(functional_judge_module, "urlopen", urlopen)
    evaluator = {
        "api_key_env": "ALI_BAILIAN_API_KEY",
        "base_url": "https://invalid.test/v1",
        "model_id": "mock",
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 1,
        "enable_thinking": True,
        "timeout_seconds": 1.0,
        "max_response_bytes": 4096,
        "response_format": response_format,
    }

    assert bailian_complete({}, evaluator, "Return JSON.") == b"{}"


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
    oracle = load_gate_inputs(
        ROOT,
        Path("configs/functional-judge/functional-oracle-qwen37max.json"),
    )
    assert oracle.evaluator["candidate_id"] == ("qwen37max-software-engineer-functional-judge-v2")
    assert len(oracle.prompt.split()) < 300
    assert not {"pdftotext", "slurm", "pragma"} & set(oracle.prompt.casefold().split())
    case = oracle.cases[0]
    projected = request_for(case, oracle.contracts[case["task_id"]])
    assert projected["functional_task"]
    assert all(set(item) == {"requirement_id", "criterion"} for item in projected["requirements"])


@pytest.mark.reviewer
def test_functional_review_derives_failure_from_requirements() -> None:
    inputs = load_gate_inputs(ROOT)
    case = next(item for item in inputs.cases if item["expected_status"] == "fail")
    contract = inputs.contracts[case["task_id"]]

    result = validate_review_response(_response(contract, "fail"), case["code_text"])

    assert result["status"] == "fail"
    malformed = json.loads(_response(contract, "fail"))
    malformed.pop("reason")
    with pytest.raises(JudgeGateError):
        validate_review_response(json.dumps(malformed).encode(), case["code_text"])
    assert python_syntax_valid(case["code_text"])
    assert not python_syntax_valid("def broken(:\n")


def test_pilot_runs_four_closed_single_attempt_cases(tmp_path: Path) -> None:
    inputs = load_gate_inputs(ROOT)
    expected_by_request = {
        content_hash(request_for(case, inputs.contracts[case["task_id"]])): (
            case["expected_status"],
            inputs.contracts[case["task_id"]],
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

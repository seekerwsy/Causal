from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from secaware.exploratory.artifact_integrity import verify_closed_manifest


def _load_canary_module():
    script = Path(__file__).parents[1] / "scripts" / "validate_bailian_functional_judge.py"
    spec = importlib.util.spec_from_file_location("validate_bailian_functional_judge", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_credential_is_persisted_without_secret(monkeypatch, tmp_path: Path) -> None:
    module = _load_canary_module()
    output_dir = tmp_path / "missing-credential-run"
    monkeypatch.delenv(module.API_KEY_ENV, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(Path(module.__file__).resolve()), "--output-dir", str(output_dir)],
    )

    assert module.main() == 2

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    environment = json.loads((output_dir / "environment.json").read_text(encoding="utf-8"))
    assert report["status"] == "ERROR"
    assert report["failure"]["error_code"] == "MISSING_API_KEY_ENV"
    assert environment["credential"] == {
        "environment_variable": module.API_KEY_ENV,
        "present": False,
        "value_recorded": False,
    }
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "canary_cases.jsonl",
        "commands.jsonl",
        "config.json",
        "environment.json",
        "events.jsonl",
        "report.json",
    ]


def test_client_construction_failure_is_persisted_without_raising(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_canary_module()
    output_dir = tmp_path / "client-construction-failure"
    monkeypatch.setenv(module.API_KEY_ENV, "offline-dummy-credential")
    monkeypatch.setattr(
        module,
        "OpenAICompatibleStructuredTransport",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("offline client failed")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(Path(module.__file__).resolve()), "--output-dir", str(output_dir)],
    )

    assert module.main() == 2

    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    persisted = "".join(
        path.read_text(encoding="utf-8") for path in output_dir.iterdir() if path.is_file()
    )
    assert report["status"] == "ERROR"
    assert report["failure"]["exception_type"] == "RuntimeError"
    assert "offline-dummy-credential" not in persisted


def test_recording_transport_persists_exact_exchange_without_credential(tmp_path: Path) -> None:
    module = _load_canary_module()
    trace_path = tmp_path / "trace.jsonl"

    class Delegate:
        def complete(self, request_bytes: bytes, _policy: object) -> bytes:
            assert json.loads(request_bytes) == {"program": "return 42"}
            return b'{"status":"pass"}'

    transport = module._RecordingTransport(Delegate(), trace_path)
    response = transport.complete(b'{"program":"return 42"}', object())

    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    assert response == b'{"status":"pass"}'
    assert trace["request"] == {"program": "return 42"}
    assert trace["response_text"] == '{"status":"pass"}'
    assert "credential" not in trace


def test_complete_success_and_report_recovery_are_offline(monkeypatch, tmp_path: Path) -> None:
    module = _load_canary_module()
    output_dir = tmp_path / "successful-run"
    pass_response = json.dumps(
        {
            "status": "pass",
            "requirements": [
                {
                    "requirement_id": "req_return_42",
                    "verdict": "met",
                    "code_evidence_lines": [2],
                    "counterexample": None,
                }
            ],
            "rationale": "The function returns 42.",
        }
    ).encode()
    fail_response = json.dumps(
        {
            "status": "fail",
            "requirements": [
                {
                    "requirement_id": "req_return_42",
                    "verdict": "not_met",
                    "code_evidence_lines": [2],
                    "counterexample": "answer() returns 7 rather than 42.",
                }
            ],
            "rationale": "The function returns 7.",
        }
    ).encode()

    class Delegate:
        def __init__(self) -> None:
            self.responses = [pass_response, pass_response, fail_response, fail_response]

        def complete(self, _request_bytes: bytes, _policy: object) -> bytes:
            return self.responses.pop(0)

    monkeypatch.setenv(module.API_KEY_ENV, "offline-dummy-credential")
    monkeypatch.setattr(module, "OpenAICompatibleStructuredTransport", lambda **_kwargs: Delegate())
    monkeypatch.setattr(
        sys,
        "argv",
        [str(Path(module.__file__).resolve()), "--output-dir", str(output_dir)],
    )

    assert module.main() == 0
    report_path = output_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["completed_case_count"] == 2
    report_path.unlink()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(module.__file__).resolve()),
            "--output-dir",
            str(output_dir),
            "--finalize-existing",
        ],
    )

    assert module.main() == 0
    recovered = json.loads(report_path.read_text(encoding="utf-8"))
    assert recovered["status"] == "PASS"
    assert recovered["recovered_from_persisted_artifacts"] is True


def test_external_research_case_uses_contract_task_id_in_single_pass(
    monkeypatch, tmp_path: Path
) -> None:
    module = _load_canary_module()
    output_dir = tmp_path / "external-single-pass"
    cases_path = tmp_path / "cases.jsonl"
    contracts_path = tmp_path / "contracts.jsonl"
    contract = module._contract("research-task")
    cases_path.write_text(
        json.dumps(
            {
                "case_id": "research-task-human-pass",
                "task_id": contract.task_id,
                "seed_id": 92001,
                "code_text": "def answer():\n    return 42\n",
                "expected_status": "pass",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    contracts_path.write_text(
        json.dumps(contract.model_dump(mode="json")) + "\n",
        encoding="utf-8",
    )
    response = json.dumps(
        {
            "status": "pass",
            "requirements": [
                {
                    "requirement_id": "req_return_42",
                    "verdict": "met",
                    "code_evidence_lines": [2],
                    "counterexample": None,
                }
            ],
            "rationale": "The function returns 42.",
        }
    ).encode()

    class Delegate:
        def complete(self, _request_bytes: bytes, _policy: object) -> bytes:
            return response

    monkeypatch.setenv(module.API_KEY_ENV, "offline-dummy-credential")
    monkeypatch.setattr(module, "OpenAICompatibleStructuredTransport", lambda **_kwargs: Delegate())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(module.__file__).resolve()),
            "--output-dir",
            str(output_dir),
            "--mode",
            "single_pass",
            "--cases-path",
            str(cases_path),
            "--contracts-path",
            str(contracts_path),
        ],
    )

    assert module.main() == 0
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    persisted_case = json.loads((output_dir / "canary_cases.jsonl").read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["completed_case_count"] == 1
    assert report["case_results"][0]["case_id"] == "research-task-human-pass"
    assert report["case_results"][0]["task_id"] == contract.task_id
    assert persisted_case["case_id"] != persisted_case["task_id"]


@pytest.mark.parametrize(
    (
        "config_name",
        "protocol_version",
        "measurement_method",
        "candidate_role",
        "candidate_id",
    ),
    (
        (
            "evaluator-qwen35flash-v1.json",
            "v1",
            "ast_validated_single_shot_llm",
            "baseline",
            "qwen35flash-prompt-v1",
        ),
        (
            "evaluator-qwen35flash-v2b.json",
            "v2",
            "blind_static_llm_v2",
            "new_candidate",
            "qwen35flash-prompt-v2b",
        ),
    ),
)
def test_external_preflight_is_credential_independent_closed_and_zero_call(
    monkeypatch,
    tmp_path: Path,
    config_name: str,
    protocol_version: str,
    measurement_method: str,
    candidate_role: str,
    candidate_id: str,
) -> None:
    module = _load_canary_module()
    root = Path(__file__).parents[1]
    output_dir = tmp_path / f"preflight-{protocol_version}"
    cases_path = tmp_path / f"cases-{protocol_version}.jsonl"
    contracts_path = tmp_path / f"contracts-{protocol_version}.jsonl"
    contract = module._contract(f"preflight-{protocol_version}")
    cases_path.write_text(
        json.dumps(
            {
                "case_id": f"preflight-case-{protocol_version}",
                "task_id": contract.task_id,
                "seed_id": 93001,
                "code_text": "def answer():\n    return 42\n",
                "expected_status": "pass",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    contracts_path.write_text(json.dumps(contract.model_dump(mode="json")) + "\n", encoding="utf-8")
    evaluator_config = root / "data" / "functional-judge" / "blind-calibration-v3" / config_name
    payload = json.loads(evaluator_config.read_text(encoding="utf-8"))
    monkeypatch.delenv(payload["api_key_env"], raising=False)
    monkeypatch.setattr(
        module,
        "OpenAICompatibleStructuredTransport",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("provider transport created")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(module.__file__).resolve()),
            "--output-dir",
            str(output_dir),
            "--cases-path",
            str(cases_path),
            "--contracts-path",
            str(contracts_path),
            "--evaluator-config",
            str(evaluator_config),
            "--preflight",
        ],
    )

    assert module.main() == 0
    verify_closed_manifest(
        output_dir / "artifact-manifest.json", label="functional judge preflight test"
    )
    report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
    config = json.loads((output_dir / "config.json").read_text(encoding="utf-8"))
    assert report["status"] == "FUNCTIONAL_JUDGE_PREFLIGHT_COMPLETE"
    assert report["credential_present"] is False
    assert report["live_ready"] is False
    assert report["new_calls"]["functional_judge_provider_attempts"] == 0
    assert report["protocol_version"] == protocol_version
    assert report["measurement_method"] == measurement_method
    assert config["candidate_role"] == candidate_role
    assert config["candidate_id"] == candidate_id
    assert not (output_dir / "llm_exchange_trace.jsonl").exists()

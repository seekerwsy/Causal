from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secaware.exploratory import gate_c_live
from secaware.oracle.aggregator import OracleCodeAnalysis
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.profile_decision import extract_python_mechanism_trace
from secaware.schema.oracle import OracleEvaluability, SecurityLabel


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize((("assignments", "tasks")), ((8, 2), (20, 5)))
def test_gate_c_live_bounded_assignment_count(assignments: int, tasks: int) -> None:
    assert gate_c_live._bounded_task_count(assignments) == tasks


@pytest.mark.parametrize("assignments", (0, 4, 9, 24))
def test_gate_c_live_rejects_unregistered_assignment_count(assignments: int) -> None:
    with pytest.raises(ValueError, match="assignment count"):
        gate_c_live._bounded_task_count(assignments)


def test_gate_c_live_plan_manifest_is_closed_and_authenticated(tmp_path: Path) -> None:
    plan = tmp_path / "plan"
    plan.mkdir()
    report = {
        "schema_version": "1.0",
        "status": "GATE_C_PLAN_COMPLETE",
        "provider_calls_allowed": False,
        "oracle_execution_allowed": False,
    }
    _write_json(plan / "report.json", report)
    digest = hashlib.sha256((plan / "report.json").read_bytes()).hexdigest()
    _write_json(
        plan / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [{"path": "report.json", "sha256": digest}],
        },
    )

    assert gate_c_live._verify_plan(plan)["status"] == "GATE_C_PLAN_COMPLETE"
    (plan / "report.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"):
        gate_c_live._verify_plan(plan)


def test_gate_c_live_unit_manifest_requires_closed_file_set(tmp_path: Path) -> None:
    unit = tmp_path / "unit"
    unit.mkdir()
    _write_json(unit / "status.json", {"status": "COMPLETE"})
    digest = hashlib.sha256((unit / "status.json").read_bytes()).hexdigest()
    _write_json(
        unit / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [{"path": "status.json", "sha256": digest}],
        },
    )

    gate_c_live._verify_unit_manifest(unit)
    _write_json(unit / "unlisted.json", {"unexpected": True})
    with pytest.raises(ValueError, match="closure"):
        gate_c_live._verify_unit_manifest(unit)


def test_functional_judge_transport_persists_exact_request_and_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeTransport:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def complete(self, request: bytes, _policy: object) -> bytes:
            assert request == b'{"request":1}'
            return b'{"response":1}'

    monkeypatch.setattr(gate_c_live, "OpenAICompatibleStructuredTransport", FakeTransport)
    recorder = gate_c_live._RecordingStructuredTransport(
        base_url="https://example.invalid/v1",
        api_key_env="TEST_API_KEY",
        system_template="test",
    )
    destination = tmp_path / "judge"
    recorder.bind(destination)

    assert recorder.complete(b'{"request":1}', object()) == b'{"response":1}'
    assert (destination / "request.json").read_bytes() == b'{"request":1}\n'
    assert (destination / "response.json").read_bytes() == b'{"response":1}\n'
    metadata = json.loads((destination / "transport.json").read_text(encoding="utf-8"))
    assert metadata["attempts"] == 1


def test_generation_transport_persists_exact_request_and_response(tmp_path: Path) -> None:
    recorder = gate_c_live._RecordingGenerationTransport()
    destination = tmp_path / "generation"
    recorder.bind(destination)
    payload = {
        "model": "local-model",
        "messages": [{"role": "user", "content": "return code"}],
        "seed": 7,
    }
    response = {
        "model": "local-model",
        "choices": [{"message": {"content": "print(1)"}, "finish_reason": "stop"}],
    }

    recorder("request_1", 1, payload, response, None)

    assert json.loads((destination / "request.json").read_text(encoding="utf-8")) == payload
    assert json.loads((destination / "response.json").read_text(encoding="utf-8")) == response
    metadata = json.loads((destination / "transport.json").read_text(encoding="utf-8"))
    assert metadata["request_id"] == "request_1"
    assert metadata["attempt"] == 1
    assert metadata["transport_error"] is False


def test_oracle_analyzer_runner_persists_output_before_adapter_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = (b'{"semgrep":true}', b'{"bandit":true}')

    def run(
        _argv: object,
        **_kwargs: object,
    ) -> gate_c_live.AnalyzerProcessResult:
        payload = outputs[run.calls]
        run.calls += 1
        return gate_c_live.AnalyzerProcessResult(
            returncode=0,
            stdout=payload,
            argv_sha256=str(run.calls) * 64,
        )

    run.calls = 0
    monkeypatch.setattr(gate_c_live, "run_analyzer_process", run)
    recorder = gate_c_live._RecordingAnalyzerRunner()
    recorder.bind(tmp_path / "oracle")

    recorder(
        ("semgrep",), cwd=tmp_path, timeout_seconds=1, max_stdout_bytes=100, max_stderr_bytes=100
    )
    recorder(
        ("bandit",), cwd=tmp_path, timeout_seconds=1, max_stdout_bytes=100, max_stderr_bytes=100
    )
    recorder.finish()

    assert (tmp_path / "oracle" / "call-001-semgrep" / "stdout.bin").read_bytes() == outputs[0]
    assert (tmp_path / "oracle" / "call-002-bandit" / "stdout.bin").read_bytes() == outputs[1]
    assert json.loads((tmp_path / "oracle" / "session.json").read_text())["calls"] == 2


def test_oracle_repair_selects_a_failed_remaining_unit_after_completed_pilot() -> None:
    assert (
        gate_c_live._repair_assignment_id(
            {"pilot", "completed"},
            {"failed_remaining"},
            "pilot",
        )
        == "failed_remaining"
    )

    with pytest.raises(ValueError, match="completed or failed pilot"):
        gate_c_live._repair_assignment_id(set(), {"failed_remaining"}, "pilot")
    with pytest.raises(ValueError, match="exactly one failed"):
        gate_c_live._repair_assignment_id({"pilot"}, {"failed_a", "failed_b"}, "pilot")


def test_remaining_phase_history_allocates_non_overwriting_attempts(tmp_path: Path) -> None:
    assert gate_c_live._next_remaining_attempt(tmp_path) == 1
    _write_json(tmp_path / "command-remaining.json", {"argv": []})
    assert gate_c_live._next_remaining_attempt(tmp_path) == 2
    _write_json(tmp_path / "command-remaining-002.json", {"argv": []})
    assert gate_c_live._next_remaining_attempt(tmp_path) == 3

    (tmp_path / "command-remaining-002.json").rename(tmp_path / "command-remaining-003.json")
    with pytest.raises(ValueError, match="phase history"):
        gate_c_live._next_remaining_attempt(tmp_path)


def test_gate_c_live_remaining_requires_an_authorization_only_delta() -> None:
    stored_base = {
        "schema_version": "1.0",
        "gate_c_live_id": "frozen-pilot",
        "scale_up_allowed": False,
        "expected_assignments": 8,
    }
    authorized = {
        **stored_base,
        "scale_up_allowed": True,
        "scale_up_authorization_id": "user-approved-remaining-20260817-v1",
        "scale_up_authorization_scope": "remaining_assignments_only",
    }

    gate_c_live._validate_scale_up_authorization(
        authorized, mode="remaining", stored_base=stored_base
    )

    changed = {**authorized, "expected_assignments": 9}
    with pytest.raises(ValueError, match="changed the frozen pilot config"):
        gate_c_live._validate_scale_up_authorization(
            changed, mode="remaining", stored_base=stored_base
        )

    with pytest.raises(ValueError, match="authorization failed"):
        gate_c_live._validate_scale_up_authorization(
            stored_base, mode="remaining", stored_base=stored_base
        )

    five_cwe = {
        **stored_base,
        "expected_assignments": 20,
        "scale_up_allowed": True,
        "scale_up_authorization_id": "user-approved-five-cwe-outcome-pilot-20260818-v1",
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    frozen_five_cwe = {
        key: value
        for key, value in five_cwe.items()
        if key not in {"scale_up_authorization_id", "scale_up_authorization_scope"}
    }
    frozen_five_cwe["scale_up_allowed"] = False
    gate_c_live._validate_scale_up_authorization(
        five_cwe,
        mode="remaining",
        stored_base=frozen_five_cwe,
    )

    main_prompt = {
        **stored_base,
        "expected_assignments": 20,
        "scale_up_allowed": True,
        "scale_up_authorization_id": ("user-approved-main-prompt-outcome-canary-20260818-v1"),
        "scale_up_authorization_scope": "remaining_assignments_only",
    }
    frozen_main_prompt = {
        key: value
        for key, value in main_prompt.items()
        if key not in {"scale_up_authorization_id", "scale_up_authorization_scope"}
    }
    frozen_main_prompt["scale_up_allowed"] = False
    gate_c_live._validate_scale_up_authorization(
        main_prompt,
        mode="remaining",
        stored_base=frozen_main_prompt,
    )


def test_gate_c_live_summary_counts_profile_decisions_and_joint_outcome(
    tmp_path: Path,
) -> None:
    unit = tmp_path / "units" / "assignment_test"
    unit.mkdir(parents=True)
    _write_json(
        unit / "status.json",
        {
            "assignment_id": "assignment_test",
            "status": "COMPLETE",
            "generated": 1,
            "terminal_no_code": 0,
            "functional_judge_provider_attempts": 1,
            "oracle_results": 1,
        },
    )
    _write_json(unit / "oracle-decision.json", {"security_label": "secure"})
    (unit / "functional-outcome.jsonl").write_text(
        json.dumps({"status": "pass"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    gate_c_live._unit_manifest(unit)

    summary = gate_c_live._summary(tmp_path, 1, "pilot")

    assert summary["status"] == "GATE_C_LIVE_COMPLETE"
    assert summary["counts"]["secure"] == 1
    assert summary["counts"]["secure_and_functional"] == 1


def _profile_analysis() -> OracleCodeAnalysis:
    code = "import secrets\n\ndef token():\n    return secrets.token_urlsafe(24)\n"
    return OracleCodeAnalysis(
        request_id="req_" + "1" * 64,
        code_id="code_" + "2" * 64,
        code_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
        prompt_id="prompt_test",
        model_id="test/model",
        seed_id=7,
        parse_ok=True,
        functional_ok=True,
        security_label=SecurityLabel.UNKNOWN,
        evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
        severity="none",
        findings=(),
        analyzers=(),
        mechanism_trace=extract_python_mechanism_trace(code),
    )


def test_gate_c_live_profile_decision_is_shared_with_reconstructed_analysis() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = load_policy_bundle(root / "policies" / "oracle" / "python-v2" / "policy.lock.json")
    profile = next(item for item in policy.coverage_profiles if item.cwe == "CWE-338")
    original = _profile_analysis()
    reconstructed = gate_c_live._oracle_analysis_from_payload(gate_c_live._json_value(original))

    normal_payload = gate_c_live._profile_decision_payload(original, profile)
    recovery_payload = gate_c_live._profile_decision_payload(reconstructed, profile)

    assert recovery_payload == normal_payload
    assert recovery_payload["security_label"] == "secure"
    assert recovery_payload["decision_reason_code"] == "all_relevant_sinks_proved_safe"


def test_gate_c_live_rejects_tampered_preserved_mechanism_trace() -> None:
    payload = gate_c_live._json_value(_profile_analysis())
    payload["mechanism_trace"]["sink_facts"][0]["line"] = "4"

    with pytest.raises(ValueError, match="mechanism trace"):
        gate_c_live._oracle_analysis_from_payload(payload)

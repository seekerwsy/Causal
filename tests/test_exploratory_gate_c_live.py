from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secaware.exploratory import gate_c_live


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


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

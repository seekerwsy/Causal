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

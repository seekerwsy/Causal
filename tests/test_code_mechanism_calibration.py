from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.exploratory.code_mechanism_calibration import (
    run_code_mechanism_calibration,
)
from secaware.exploratory.code_mechanism_facts import (
    CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
)
from secaware.llm.structured_transport import StructuredLLMPolicy


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _Transport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def complete(self, _request: bytes, _policy: StructuredLLMPolicy) -> bytes:
        response = self.responses[self.calls]
        self.calls += 1
        return json.dumps(response, separators=(",", ":")).encode()


def test_calibration_retains_progress_and_passes_exact_canary(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    rows = [
        {
            "calibration_id": f"case-{index}",
            "code": f"sink_{index}(value)",
            "cwe": "CWE-89",
            "expected_state": "proved_safe",
            "language": "python",
        }
        for index in range(5)
    ]
    _write_jsonl(corpus, rows)
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "calibration_kind": "multilingual_code_mechanism_facts_v1",
            "corpus": {"path": "corpus.jsonl", "sha256": _sha(corpus)},
            "selected_calibration_ids": [row["calibration_id"] for row in rows],
            "expected_calls": 5,
            "minimum_accuracy": 1.0,
            "maximum_error_fraction": 0.0,
            "arms_allowed": False,
            "outcomes_allowed": False,
            "provider_calls_allowed": True,
            "next_action_on_pass": "run_full_calibration",
            "llm": {
                "provider": "openai_compatible",
                "model_id": "fixture-model",
                "base_url": "https://example.test/v1",
                "api_key_env": "FIXTURE_KEY",
                "system_template_sha256": CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
                "output_schema_sha256": CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
                "temperature": 0.0,
                "top_p": 1.0,
                "seed": None,
                "timeout_seconds": 60.0,
                "max_attempts": 1,
                "max_response_bytes": 65536,
                "enable_thinking": False,
            },
        },
    )
    response = {
        "facts": [
            {
                "function_name": "fixture",
                "sink_kind": "query",
                "mechanism_kinds": ["bound_sql_parameters"],
                "evidence_lines": [1],
                "source_names": ["value"],
                "properties": [],
            }
        ]
    }
    transport = _Transport([response] * 5)

    report = run_code_mechanism_calibration(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "run",
        command_argv=("calibrate",),
        transport=transport,
    )

    assert report["status"] == "CODE_MECHANISM_CALIBRATION_PASS"
    assert report["counts"] == {
        "selected": 5,
        "provider_calls": 5,
        "completed": 5,
        "correct": 5,
        "errors": 0,
        "pending": 0,
    }
    assert transport.calls == 5
    assert len((tmp_path / "run" / "progress.jsonl").read_text().splitlines()) == 5


def test_v2_calibration_passes_criteria_to_requests(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    row = {
        "calibration_id": "go-safe",
        "code": 'exec.Command("ls", path).Output()',
        "cwe": "CWE-78",
        "expected_state": "proved_safe",
        "language": "go",
    }
    _write_jsonl(corpus, [row])
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "calibration_kind": "multilingual_code_mechanism_facts_v2",
            "criteria_version": "mechanism-operational-definitions-v2",
            "corpus": {"path": "corpus.jsonl", "sha256": _sha(corpus)},
            "selected_calibration_ids": ["go-safe"],
            "expected_calls": 1,
            "minimum_accuracy": 1.0,
            "maximum_error_fraction": 0.0,
            "arms_allowed": False,
            "outcomes_allowed": False,
            "provider_calls_allowed": True,
            "next_action_on_pass": "freeze",
            "llm": {
                "provider": "openai_compatible",
                "model_id": "fixture-model",
                "base_url": "https://example.test/v1",
                "api_key_env": "FIXTURE_KEY",
                "system_template_sha256": CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
                "output_schema_sha256": CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
                "temperature": 0.0,
                "top_p": 1.0,
                "seed": None,
                "timeout_seconds": 60.0,
                "max_attempts": 1,
                "max_response_bytes": 65536,
                "enable_thinking": False,
            },
        },
    )
    transport = _Transport(
        [
            {
                "facts": [
                    {
                        "function_name": "listDir",
                        "sink_kind": "process creation",
                        "mechanism_kinds": ["argument_vector"],
                        "evidence_lines": [1],
                        "source_names": ["path"],
                        "properties": [],
                    }
                ]
            }
        ]
    )

    report = run_code_mechanism_calibration(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "run-v2",
        command_argv=("calibrate-v2",),
        transport=transport,
    )

    assert report["criteria_version"] == "mechanism-operational-definitions-v2"
    measurement = json.loads((tmp_path / "run-v2" / "measurements.jsonl").read_text())
    assert measurement["measurement"]["extractor_version"] == "llm-code-mechanism-facts-v2"
    request = json.loads((tmp_path / "run-v2" / "requests.jsonl").read_text())
    assert "mechanism_definitions" in request["request"]

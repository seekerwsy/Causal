from __future__ import annotations

import hashlib
import json

import pytest

from secaware.exploratory.code_mechanism_facts import (
    CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
    LLMCodeMechanismFactsExtractor,
    code_mechanism_request_payload,
)
from secaware.llm.structured_transport import StructuredLLMPolicy


class _Transport:
    def __init__(self, response: object) -> None:
        self.response = response
        self.requests: list[dict[str, object]] = []

    def complete(self, request_bytes: bytes, _policy: StructuredLLMPolicy) -> bytes:
        self.requests.append(json.loads(request_bytes))
        return json.dumps(self.response, separators=(",", ":")).encode()


def _policy() -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256=hashlib.sha256(b"https://example.test/v1").hexdigest(),
        model_id="fixture-model",
        system_template_sha256=CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE_SHA256,
        output_schema_sha256=CODE_MECHANISM_FACTS_OUTPUT_SCHEMA_SHA256,
        temperature=0.0,
        top_p=1.0,
        seed=None,
        timeout_seconds=60.0,
        max_attempts=1,
        max_response_bytes=65536,
        enable_thinking=False,
    )


def test_multilingual_fact_projection_is_blind_and_deterministic() -> None:
    code = "func find(name string) {\n    db.Query(\"SELECT * FROM users WHERE name = ?\", name)\n}"
    transport = _Transport(
        {
            "facts": [
                {
                    "function_name": "find",
                    "sink_kind": "database query",
                    "mechanism_kinds": ["bound_sql_parameters"],
                    "evidence_lines": [2],
                    "source_names": ["name"],
                    "properties": ["placeholder and value are separate arguments"],
                }
            ]
        }
    )
    measurement = LLMCodeMechanismFactsExtractor(transport, _policy()).extract(
        code=code, target_cwe="CWE-89", language="go"
    )

    assert measurement.mechanism_state == "proved_safe"
    assert measurement.z_target_mechanism_realized == 1
    request = transport.requests[0]
    assert request["blindness"] == {
        "functional_outcome_withheld": True,
        "generator_identity_withheld": True,
        "intervention_arm_withheld": True,
        "security_outcome_withheld": True,
        "task_prompt_withheld": True,
    }
    request_text = json.dumps(request)
    assert "assignment" not in request_text
    assert "model_id" not in request_text


def test_unsafe_fact_dominates_and_empty_facts_are_not_realized() -> None:
    unsafe = _Transport(
        {
            "facts": [
                {
                    "function_name": "run",
                    "sink_kind": "shell",
                    "mechanism_kinds": ["shell_interpolation"],
                    "evidence_lines": [1],
                    "source_names": ["arg"],
                    "properties": [],
                }
            ]
        }
    )
    code = "os.system(\"ls \" + arg)"
    result = LLMCodeMechanismFactsExtractor(unsafe, _policy()).extract(
        code=code, target_cwe="CWE-78", language="python"
    )
    assert (result.mechanism_state, result.z_target_mechanism_realized) == (
        "proved_unsafe",
        0,
    )

    empty = LLMCodeMechanismFactsExtractor(_Transport({"facts": []}), _policy()).extract(
        code="print('hello')", target_cwe="CWE-78", language="python"
    )
    assert (empty.mechanism_state, empty.z_target_mechanism_realized) == (
        "no_relevant_sink",
        0,
    )


def test_invalid_evidence_and_unknown_mechanisms_fail_closed() -> None:
    for response in (
        {
            "facts": [
                {
                    "function_name": "f",
                    "sink_kind": "hash",
                    "mechanism_kinds": ["sha2_or_stronger"],
                    "evidence_lines": [2],
                    "source_names": [],
                    "properties": [],
                }
            ]
        },
        {
            "facts": [
                {
                    "function_name": "f",
                    "sink_kind": "hash",
                    "mechanism_kinds": ["invented_mechanism"],
                    "evidence_lines": [1],
                    "source_names": [],
                    "properties": [],
                }
            ]
        },
    ):
        with pytest.raises(ValueError):
            LLMCodeMechanismFactsExtractor(_Transport(response), _policy()).extract(
                code="hash(data)", target_cwe="CWE-328", language="java"
            )


def test_request_rejects_unsupported_language() -> None:
    with pytest.raises(ValueError):
        code_mechanism_request_payload(code="fn main() {}", target_cwe="CWE-78", language="rust")
    assert CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE.strip()

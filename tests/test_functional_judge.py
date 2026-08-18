from __future__ import annotations

import hashlib
import json

import pytest

from secaware.config import FunctionalJudgeConfig, FunctionalJudgeLLMConfig
from secaware.functional_judge import (
    FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    LLMFunctionalJudge,
    TaskFunctionalContractRecord,
)
from secaware.functional_judge.judge import FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE
from secaware.llm.structured_transport import StructuredLLMPolicy
from secaware.schema.outcomes import FunctionalOutcomeStatus
from test_confirmation_oracle import _confirmation_code, _execution_for


class FakeTransport:
    def __init__(self, responses: tuple[bytes, ...]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def complete(self, request_bytes: bytes, _policy: StructuredLLMPolicy) -> bytes:
        self.requests.append(json.loads(request_bytes))
        return self.responses.pop(0)


def test_system_template_requires_integer_line_evidence() -> None:
    assert "`code_evidence_lines` array" in FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE
    assert "return only the\ninteger line numbers" in FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE
    assert "deterministically resolves valid line numbers" in FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE
    assert "Do not require input validation, defensive error handling" in (
        FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE
    )
    assert "contract-satisfying inputs" in FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE


def _contract(task_id: str = "task-confirmation") -> TaskFunctionalContractRecord:
    prompt = "Write a Python function answer() that returns 42."
    requirements = (
        FunctionalRequirementRecord(
            requirement_id="req_return_42",
            kind="behavior",
            criterion="The program defines answer() and answer() returns the integer 42.",
            prompt_evidence_quote="answer() that returns 42",
        ),
    )
    return TaskFunctionalContractRecord.from_content(
        task_id=task_id,
        source_prompt_id="prompt-source-1",
        source_prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
        language="python",
        judgeability=FunctionalJudgeability.SEMANTIC_ONLY,
        requirements=requirements,
        environment_dependencies=(),
        audit_pass_ids=("A", "B"),
        audit_status=FunctionalAuditStatus.CONSISTENT,
        auditor_kind="CODEX",
        audit_evidence_sha256="a" * 64,
    )


def test_pre_treatment_contract_supports_one_reviewed_audit_pass() -> None:
    prompt = "Write a Python function answer() that returns 42."
    contract = TaskFunctionalContractRecord.from_content(
        task_id="task-single-audit",
        source_prompt_id="prompt-source-single-audit",
        source_prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
        language="python",
        judgeability=FunctionalJudgeability.SEMANTIC_ONLY,
        requirements=(
            FunctionalRequirementRecord(
                requirement_id="req_return_42",
                kind="behavior",
                criterion="Return the integer 42.",
                prompt_evidence_quote="returns 42",
            ),
        ),
        environment_dependencies=(),
        audit_pass_ids=("A",),
        audit_status=FunctionalAuditStatus.RESOLVED,
        auditor_kind="CODEX",
        audit_evidence_sha256="b" * 64,
    )

    assert contract.audit_pass_ids == ("A",)
    assert contract.audit_status is FunctionalAuditStatus.RESOLVED


def test_single_audit_pass_must_be_marked_resolved() -> None:
    with pytest.raises(Exception):
        TaskFunctionalContractRecord.from_content(
            task_id="task-single-audit",
            source_prompt_id="prompt-source-single-audit",
            source_prompt_sha256="c" * 64,
            language="python",
            judgeability=FunctionalJudgeability.UNJUDGEABLE,
            requirements=(),
            environment_dependencies=(),
            audit_pass_ids=("A",),
            audit_status=FunctionalAuditStatus.CONSISTENT,
            auditor_kind="CODEX",
            audit_evidence_sha256="b" * 64,
        )


def _policy(seed: int) -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256="e" * 64,
        model_id="judge-placeholder",
        system_template_sha256=FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
        output_schema_sha256=FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
        temperature=0.0,
        top_p=1.0,
        seed=seed,
        timeout_seconds=30.0,
        max_attempts=2,
        max_response_bytes=65_536,
    )


def test_disabled_functional_judge_may_retain_frozen_non_secret_coordinates() -> None:
    llm = FunctionalJudgeLLMConfig(
        model_id="qwen3.5-flash-2026-02-23",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        api_key_env="ALI_BAILIAN_API_KEY",
        timeout_seconds=60.0,
        max_attempts=3,
        max_response_bytes=65_536,
        temperature=0.0,
        top_p=1.0,
        seed=None,
        enable_thinking=False,
    )

    config = FunctionalJudgeConfig(enabled=False, llm=llm)

    assert config.enabled is False
    assert config.llm == llm


def test_single_pass_configuration_requires_exactly_one_seed() -> None:
    llm = FunctionalJudgeLLMConfig(
        model_id="qwen3.5-flash-2026-02-23",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        api_key_env="ALI_BAILIAN_API_KEY",
        timeout_seconds=60.0,
        max_attempts=3,
        max_response_bytes=65_536,
        temperature=0.0,
        top_p=1.0,
        seed=None,
        enable_thinking=False,
    )

    config = FunctionalJudgeConfig(
        enabled=True,
        llm=llm,
        mode="single_pass",
        pass_seeds=(73_001,),
    )

    assert config.mode == "single_pass"
    assert config.pass_seeds == (73_001,)
    with pytest.raises(Exception):
        FunctionalJudgeConfig(
            enabled=True,
            llm=llm,
            mode="single_pass",
            pass_seeds=(73_001, 73_002),
        )


def _response(
    status: str,
    verdict: str,
    *,
    evidence_lines: list[object] | None = None,
) -> bytes:
    return json.dumps(
        {
            "status": status,
            "requirements": [
                {
                    "requirement_id": "req_return_42",
                    "verdict": verdict,
                    "code_evidence_lines": [2] if evidence_lines is None else evidence_lines,
                    "counterexample": (
                        "Calling answer() does not return 42." if verdict == "not_met" else None
                    ),
                }
            ],
            "rationale": "The exact return statement establishes the required behavior.",
        },
        separators=(",", ":"),
    ).encode()


def test_two_pass_judge_is_blind_and_publishes_consensus() -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport((_response("pass", "met"), _response("pass", "met")))
    judge = LLMFunctionalJudge(transport, _policy(11), _policy(12))

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )

    assert len(passes) == 2
    assert outcome.status is FunctionalOutcomeStatus.PASS
    assert len(transport.requests) == 2
    forbidden = {"arm_role", "assignment_id", "cwe", "security", "model_id", "seed_id"}
    assert forbidden.isdisjoint(transport.requests[0])
    assert transport.requests[0]["blindness"] == {
        "arm_withheld": True,
        "cwe_withheld": True,
        "generator_identity_withheld": True,
        "security_outcome_withheld": True,
    }
    assert transport.requests[0]["program_lines"] == [
        {"line_number": 1, "text": "def answer():"},
        {"line_number": 2, "text": "    return 42"},
    ]
    assert passes[0].requirements[0].code_evidence == ("    return 42",)


@pytest.mark.parametrize(
    ("response_status", "verdict", "expected"),
    (
        ("pass", "met", FunctionalOutcomeStatus.PASS),
        ("fail", "not_met", FunctionalOutcomeStatus.FAIL),
        ("unknown", "unknown", FunctionalOutcomeStatus.UNKNOWN),
    ),
)
def test_single_pass_judge_publishes_one_blind_validated_decision(
    response_status: str,
    verdict: str,
    expected: FunctionalOutcomeStatus,
) -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport((_response(response_status, verdict),))
    judge = LLMFunctionalJudge(
        transport,
        _policy(13),
        mode="single_pass",
    )

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )

    assert len(passes) == 1
    assert passes[0].pass_id == "A"
    assert passes[0].status is expected
    assert outcome.status is expected
    assert len(transport.requests) == 1
    assert judge.mode == "single_pass"


def test_single_pass_policy_provenance_differs_from_two_pass_consensus() -> None:
    single = LLMFunctionalJudge(FakeTransport(()), _policy(61), mode="single_pass")
    double = LLMFunctionalJudge(FakeTransport(()), _policy(61), _policy(62))

    assert single.policy_sha256 != double.policy_sha256


def test_disagreement_becomes_unknown_without_filtering_assignment() -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport((_response("pass", "met"), _response("fail", "not_met")))
    judge = LLMFunctionalJudge(transport, _policy(21), _policy(22))

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )

    assert len(passes) == 2
    assert outcome.status is FunctionalOutcomeStatus.UNKNOWN


def test_judge_rejects_out_of_range_evidence_line() -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport(
        (_response("pass", "met", evidence_lines=[999]), _response("pass", "met"))
    )
    judge = LLMFunctionalJudge(transport, _policy(31), _policy(32))

    with pytest.raises(Exception):
        judge.evaluate(assignment, _execution_for(assignment, code), code, _contract())


def test_judge_ignores_blank_evidence_lines_and_retains_nonblank_evidence() -> None:
    from secaware.generation.result_importer import canonical_generated_code_from_request

    assignment, _variant, code = _confirmation_code()
    code_with_blank_line = canonical_generated_code_from_request(
        code.generation_request,
        "def answer():\n\n    return 42\n",
        code.generation_provenance,
        provider_result_sha256=code.provider_result_sha256,
        provider_usage_sha256=code.provider_usage_sha256,
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        provider_attempt_count=code.provider_attempt_count,
    )
    transport = FakeTransport((_response("pass", "met", evidence_lines=[2, 3]),))
    judge = LLMFunctionalJudge(transport, _policy(32), mode="single_pass")

    passes, outcome = judge.evaluate(
        assignment,
        _execution_for(assignment, code_with_blank_line),
        code_with_blank_line,
        _contract(),
    )

    assert outcome.status is FunctionalOutcomeStatus.PASS
    assert passes[0].requirements[0].code_evidence == ("    return 42",)


def test_judge_rejects_non_integer_evidence_line() -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport(
        (
            _response("pass", "met", evidence_lines=[True]),
            _response("pass", "met"),
        )
    )
    judge = LLMFunctionalJudge(transport, _policy(33), _policy(34))

    with pytest.raises(Exception):
        judge.evaluate(assignment, _execution_for(assignment, code), code, _contract())


def test_terminal_no_code_is_functional_fail_without_llm_call() -> None:
    from test_assignment_outcome_assembly import _terminal_execution

    assignment, _variant, _code = _confirmation_code()
    transport = FakeTransport(())
    judge = LLMFunctionalJudge(transport, _policy(41), _policy(42))

    passes, outcome = judge.evaluate(assignment, _terminal_execution(assignment), None, _contract())

    assert passes == ()
    assert outcome.status is FunctionalOutcomeStatus.FAIL
    assert transport.requests == []


def test_invalid_python_fails_structural_gate_without_llm_call() -> None:
    from secaware.generation.result_importer import canonical_generated_code_from_request

    assignment, _variant, code = _confirmation_code()
    malformed = canonical_generated_code_from_request(
        code.generation_request,
        "def broken(:\n",
        code.generation_provenance,
        provider_result_sha256=code.provider_result_sha256,
        provider_usage_sha256=code.provider_usage_sha256,
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        provider_attempt_count=code.provider_attempt_count,
    )
    transport = FakeTransport(())
    judge = LLMFunctionalJudge(transport, _policy(51), _policy(52))

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, malformed), malformed, _contract()
    )
    assert passes == ()
    assert outcome.status is FunctionalOutcomeStatus.FAIL
    assert transport.requests == []

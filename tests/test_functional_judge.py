from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secaware.config import AppConfig, FunctionalJudgeConfig, FunctionalJudgeLLMConfig, load_config
from secaware.errors import SecAwareError
from secaware.functional_judge import (
    FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
    FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256,
    FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE,
    FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256,
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    LLMFunctionalJudge,
    TaskFunctionalContractRecord,
    functional_judge_policy_sha256,
)
from secaware.functional_judge import judge as judge_module
from secaware.functional_judge.factory import _policy as configured_policy
from secaware.functional_judge.factory import create_functional_judge
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


def test_v2_system_template_requires_semantic_and_side_effect_tracing() -> None:
    assert "never executes the program" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert "control-flow path" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert "observable side effects" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert "valid\nAPI, command, SQL construct" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert "subprocess arguments from stdout or file redirection" in (
        FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    )
    assert "blind_static_llm_v2" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert "structured counterexample" in FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE


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


def _v2_policy(seed: int) -> StructuredLLMPolicy:
    return StructuredLLMPolicy(
        endpoint_sha256="e" * 64,
        model_id="judge-placeholder",
        system_template_sha256=FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256,
        output_schema_sha256=FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256,
        temperature=0.0,
        top_p=1.0,
        seed=seed,
        timeout_seconds=30.0,
        max_attempts=2,
        max_response_bytes=65_536,
    )


def test_v1_aliases_and_policy_digest_remain_frozen() -> None:
    assert FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256 == (FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256)
    assert FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256 == FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256
    assert functional_judge_policy_sha256(_policy(61), mode="single_pass") == (
        "52a68cd00b4ca8b8ba410474e08dd43fa8be67949a929a240e5d6195f95bc79f"
    )
    assert functional_judge_policy_sha256(_policy(61), _policy(62)) == (
        "5451a041f0f433d0f1bd1e3e2fde3f612d2bd75f638cf929a3819fec3256bfd5"
    )


def test_v2_policy_digest_binds_static_measurement_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def capture(payload: object) -> str:
        assert isinstance(payload, dict)
        captured.update(payload)
        return "a" * 64

    monkeypatch.setattr(judge_module, "canonical_sha256", capture)

    assert (
        functional_judge_policy_sha256(_v2_policy(63), mode="single_pass", protocol_version="v2")
        == "a" * 64
    )
    assert captured["protocol_version"] == "v2"
    assert captured["measurement_method"] == "blind_static_llm_v2"
    assert captured["execution_performed"] is False


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
    assert config.protocol_version == "v1"

    v2_config = FunctionalJudgeConfig(enabled=False, llm=llm, protocol_version="v2")
    assert v2_config.protocol_version == "v2"


def test_factory_selects_v2_artifacts_without_breaking_legacy_policy_helper() -> None:
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
    assert configured_policy(llm, 73_001).system_template_sha256 == (
        FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256
    )
    assert (
        configured_policy(llm, 73_001, protocol_version="v2").system_template_sha256
        == FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256
    )

    base = load_config(Path(__file__).parents[1] / "configs" / "demo.yaml")
    payload = base.model_dump(mode="python")
    payload["data"]["task_functional_contracts_path"] = "contracts.jsonl"
    payload["functional_judge"] = FunctionalJudgeConfig(
        enabled=True,
        llm=llm,
        protocol_version="v2",
        mode="single_pass",
        pass_seeds=(73_001,),
    ).model_dump(mode="python")
    config = AppConfig.model_validate(payload)
    captured: dict[str, object] = {}

    def transport_factory(**coordinates: object) -> FakeTransport:
        captured.update(coordinates)
        return FakeTransport(())

    judge = create_functional_judge(config, transport_factory=transport_factory)

    assert captured["system_template"] == FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE
    assert judge.protocol_version == "v2"
    assert judge.measurement_method == "blind_static_llm_v2"


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


def _v2_payload(status: str, verdict: str) -> dict[str, object]:
    behavior_trace: str | None = None
    counterexample: dict[str, str] | None = None
    unknown_reason: str | None = None
    if verdict == "met":
        behavior_trace = "Calling answer reaches line 2 and returns the integer 42."
    elif verdict == "not_met":
        counterexample = {
            "contract_satisfying_scenario": "Call answer() in the declared Python environment.",
            "expected_behavior": "The function returns the integer 42.",
            "actual_behavior": "The function returns a different integer.",
        }
    elif verdict == "unknown":
        unknown_reason = (
            "The returned value depends on runtime behavior not defined by the contract."
        )
    return {
        "measurement_method": "blind_static_llm_v2",
        "execution_performed": False,
        "status": status,
        "requirements": [
            {
                "requirement_id": "req_return_42",
                "verdict": verdict,
                "code_evidence_lines": [2],
                "behavior_trace": behavior_trace,
                "counterexample": counterexample,
                "unknown_reason": unknown_reason,
            }
        ],
        "rationale": "The verdict follows from the complete static behavior trace.",
    }


def _v2_response(status: str, verdict: str) -> bytes:
    return json.dumps(_v2_payload(status, verdict), separators=(",", ":")).encode()


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


def test_v2_judge_publishes_static_measurement_provenance() -> None:
    assignment, _variant, code = _confirmation_code()
    transport = FakeTransport((_v2_response("pass", "met"),))
    judge = LLMFunctionalJudge(
        transport,
        _v2_policy(13),
        mode="single_pass",
        protocol_version="v2",
    )

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )

    assert outcome.status is FunctionalOutcomeStatus.PASS
    assert passes[0].requirements[0].code_evidence == ("    return 42",)
    assert judge.protocol_version == "v2"
    assert judge.measurement_method == "blind_static_llm_v2"
    assert judge.execution_performed is False
    assert transport.requests[0]["protocol_version"] == "v2"
    assert transport.requests[0]["measurement_method"] == "blind_static_llm_v2"
    assert transport.requests[0]["execution_performed"] is False
    output_schema = transport.requests[0]["output_schema"]
    assert isinstance(output_schema, dict)
    requirement_schema = output_schema["properties"]["requirements"]["items"]
    assert "behavior_trace" in requirement_schema["required"]
    assert "unknown_reason" in requirement_schema["required"]


def test_v2_not_met_retains_canonical_structured_counterexample() -> None:
    assignment, _variant, code = _confirmation_code()
    judge = LLMFunctionalJudge(
        FakeTransport((_v2_response("fail", "not_met"),)),
        _v2_policy(14),
        mode="single_pass",
        protocol_version="v2",
    )

    passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )

    assert outcome.status is FunctionalOutcomeStatus.FAIL
    counterexample = passes[0].requirements[0].counterexample
    assert counterexample is not None
    assert json.loads(counterexample) == {
        "actual_behavior": "The function returns a different integer.",
        "contract_satisfying_scenario": "Call answer() in the declared Python environment.",
        "expected_behavior": "The function returns the integer 42.",
    }


def _evaluate_v2_payload(payload: dict[str, object]) -> FunctionalOutcomeStatus:
    assignment, _variant, code = _confirmation_code()
    response = json.dumps(payload, separators=(",", ":")).encode()
    judge = LLMFunctionalJudge(
        FakeTransport((response,)),
        _v2_policy(15),
        mode="single_pass",
        protocol_version="v2",
    )
    _passes, outcome = judge.evaluate(
        assignment, _execution_for(assignment, code), code, _contract()
    )
    return outcome.status


def test_v2_unknown_requires_and_accepts_a_precise_reason() -> None:
    assert _evaluate_v2_payload(_v2_payload("unknown", "unknown")) is (
        FunctionalOutcomeStatus.UNKNOWN
    )

    missing_reason = _v2_payload("unknown", "unknown")
    missing_reason["requirements"][0]["unknown_reason"] = None  # type: ignore[index]
    with pytest.raises(SecAwareError):
        _evaluate_v2_payload(missing_reason)


def test_v2_met_requires_nonblank_resolved_code_evidence_and_trace() -> None:
    no_evidence = _v2_payload("pass", "met")
    no_evidence["requirements"][0]["code_evidence_lines"] = []  # type: ignore[index]
    with pytest.raises(SecAwareError):
        _evaluate_v2_payload(no_evidence)

    no_trace = _v2_payload("pass", "met")
    no_trace["requirements"][0]["behavior_trace"] = None  # type: ignore[index]
    with pytest.raises(SecAwareError):
        _evaluate_v2_payload(no_trace)


def test_v2_not_met_rejects_unstructured_counterexample() -> None:
    payload = _v2_payload("fail", "not_met")
    payload["requirements"][0]["counterexample"] = "answer() returns the wrong value"  # type: ignore[index]

    with pytest.raises(SecAwareError):
        _evaluate_v2_payload(payload)


def test_v2_rejects_false_execution_provenance() -> None:
    payload = _v2_payload("pass", "met")
    payload["execution_performed"] = True

    with pytest.raises(SecAwareError):
        _evaluate_v2_payload(payload)


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


def test_judge_retains_more_than_eight_valid_evidence_lines() -> None:
    from secaware.generation.result_importer import canonical_generated_code_from_request

    assignment, _variant, code = _confirmation_code()
    expanded_code = canonical_generated_code_from_request(
        code.generation_request,
        "def answer():\n"
        "    value = 42\n"
        "    copy_1 = value\n"
        "    copy_2 = copy_1\n"
        "    copy_3 = copy_2\n"
        "    copy_4 = copy_3\n"
        "    copy_5 = copy_4\n"
        "    copy_6 = copy_5\n"
        "    copy_7 = copy_6\n"
        "    return copy_7\n",
        code.generation_provenance,
        provider_result_sha256=code.provider_result_sha256,
        provider_usage_sha256=code.provider_usage_sha256,
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        provider_attempt_count=code.provider_attempt_count,
    )
    evidence_lines = list(range(2, 11))
    judge = LLMFunctionalJudge(
        FakeTransport((_response("pass", "met", evidence_lines=evidence_lines),)),
        _policy(35),
        mode="single_pass",
    )

    passes, outcome = judge.evaluate(
        assignment,
        _execution_for(assignment, expanded_code),
        expanded_code,
        _contract(),
    )

    assert outcome.status is FunctionalOutcomeStatus.PASS
    assert len(passes[0].requirements[0].code_evidence) == 9
    assert passes[0].requirements[0].code_evidence[-1] == "    return copy_7"


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

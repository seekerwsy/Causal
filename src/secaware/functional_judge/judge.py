"""Single- or two-pass, arm-blind LLM-as-a-judge implementation."""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Mapping
from importlib import resources
from typing import Literal

from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.schema import (
    FunctionalJudgeability,
    FunctionalJudgePassRecord,
    FunctionalRequirementDecision,
    ProgramFunctionalOutcomeRecord,
    RequirementVerdict,
    TaskFunctionalContractRecord,
)
from secaware.llm.structured_transport import (
    StructuredJSONTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
)
from secaware.schema.outcomes import FunctionalOutcomeStatus
from secaware.schema.records import CanonicalGeneratedCodeRecord

FunctionalJudgeProtocolVersion = Literal["v1", "v2", "v3"]


def _template_text(protocol_version: FunctionalJudgeProtocolVersion) -> str:
    return (
        resources.files("secaware.functional_judge")
        .joinpath(f"prompts/functional_judge_{protocol_version}.txt")
        .read_text(encoding="utf-8")
    )


FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE = _template_text("v1")
FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()
FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE = _template_text("v2")
FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()
FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE = _template_text("v3")
FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE_SHA256 = hashlib.sha256(
    FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE.encode("utf-8")
).hexdigest()

# These aliases are the byte-for-byte v1 policy artifacts. Keep them stable for callers and
# historical run manifests that predate explicit protocol selection.
FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE = FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE
FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256 = FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256

_OUTPUT_SCHEMA_V1 = {
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "requirements", "rationale"],
    "properties": {
        "status": {"enum": ["pass", "fail", "unknown"]},
        "requirements": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "requirement_id",
                    "verdict",
                    "code_evidence_lines",
                    "counterexample",
                ],
                "properties": {
                    "requirement_id": {"type": "string"},
                    "verdict": {"enum": ["met", "not_met", "unknown"]},
                    "code_evidence_lines": {
                        "type": "array",
                        "maxItems": 32,
                        "uniqueItems": True,
                        "items": {
                            "type": "integer",
                            "minimum": 1,
                        },
                    },
                    "counterexample": {"type": ["string", "null"]},
                },
            },
        },
        "rationale": {"type": "string"},
    },
}
_OUTPUT_SCHEMA_V2 = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "measurement_method",
        "execution_performed",
        "status",
        "requirements",
        "rationale",
    ],
    "properties": {
        "measurement_method": {"const": "blind_static_llm_v2"},
        "execution_performed": {"const": False},
        "status": {"enum": ["pass", "fail", "unknown"]},
        "requirements": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "requirement_id",
                    "verdict",
                    "code_evidence_lines",
                    "behavior_trace",
                    "counterexample",
                    "unknown_reason",
                ],
                "properties": {
                    "requirement_id": {"type": "string"},
                    "verdict": {"enum": ["met", "not_met", "unknown"]},
                    "code_evidence_lines": {
                        "type": "array",
                        "maxItems": 32,
                        "uniqueItems": True,
                        "items": {"type": "integer", "minimum": 1},
                    },
                    "behavior_trace": {"type": ["string", "null"]},
                    "counterexample": {
                        "type": ["object", "null"],
                        "additionalProperties": False,
                        "required": [
                            "contract_satisfying_scenario",
                            "expected_behavior",
                            "actual_behavior",
                        ],
                        "properties": {
                            "contract_satisfying_scenario": {"type": "string"},
                            "expected_behavior": {"type": "string"},
                            "actual_behavior": {"type": "string"},
                        },
                    },
                    "unknown_reason": {"type": ["string", "null"]},
                },
            },
        },
        "rationale": {"type": "string"},
    },
}
_V3_MEASUREMENT_METHOD = "blind_static_llm_v3_requirement_aggregate"
FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE = "optional_non_authoritative_advisory_ignored"
FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE = "requirement-verdict-aggregate-v1"
_V3_AGGREGATE_RULE_PAYLOAD = {
    "rule_id": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
    "authoritative_source": "requirements[].verdict",
    "precedence": ["not_met", "unknown", "met"],
    "not_met_result": "fail",
    "unknown_result": "unknown",
    "empty_result": "unknown",
    "all_met_result": "pass",
    "top_level_status_role": FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
}
FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256 = canonical_sha256(_V3_AGGREGATE_RULE_PAYLOAD)
_OUTPUT_SCHEMA_V3 = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "measurement_method",
        "execution_performed",
        "requirements",
        "rationale",
    ],
    "properties": {
        "measurement_method": {"const": _V3_MEASUREMENT_METHOD},
        "execution_performed": {"const": False},
        "status": {
            "description": (
                "Optional non-authoritative advisory ignored by the local aggregate rule."
            ),
            "enum": ["pass", "fail", "unknown"],
        },
        "requirements": _OUTPUT_SCHEMA_V2["properties"]["requirements"],
        "rationale": {"type": "string"},
    },
}
FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256 = canonical_sha256(_OUTPUT_SCHEMA_V1)
FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256 = canonical_sha256(_OUTPUT_SCHEMA_V2)
FUNCTIONAL_JUDGE_V3_OUTPUT_SCHEMA_SHA256 = canonical_sha256(_OUTPUT_SCHEMA_V3)
FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256 = FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256
_RESPONSE_KEYS_V1 = frozenset({"status", "requirements", "rationale"})
_REQUIREMENT_KEYS_V1 = frozenset(
    {"requirement_id", "verdict", "code_evidence_lines", "counterexample"}
)
_RESPONSE_KEYS_V2 = frozenset(
    {"measurement_method", "execution_performed", "status", "requirements", "rationale"}
)
_REQUIREMENT_KEYS_V2 = frozenset(
    {
        "requirement_id",
        "verdict",
        "code_evidence_lines",
        "behavior_trace",
        "counterexample",
        "unknown_reason",
    }
)
_RESPONSE_KEYS_V3 = frozenset(
    {"measurement_method", "execution_performed", "requirements", "rationale"}
)
_EVIDENCE_RESOLUTION_VERSION = "valid-range-nonblank-lines-v3"
_V1_MEASUREMENT_METHOD = "ast_validated_single_shot_llm"
_V2_MEASUREMENT_METHOD = "blind_static_llm_v2"


def _error(code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage="functional_judge",
        message="functional judge evaluation failed validation",
        details={},
        retryable=False,
    )


def _policy_payload(policy: StructuredLLMPolicy) -> dict[str, object]:
    return {field: getattr(policy, field) for field in StructuredLLMPolicy.__dataclass_fields__}


def functional_judge_policy_sha256(
    pass_a: StructuredLLMPolicy,
    pass_b: StructuredLLMPolicy | None = None,
    *,
    mode: Literal["single_pass", "two_pass_consensus"] = "two_pass_consensus",
    protocol_version: FunctionalJudgeProtocolVersion = "v1",
) -> str:
    if protocol_version not in {"v1", "v2", "v3"}:
        raise _error(ErrorCode.CONFIG)
    if protocol_version == "v1":
        if mode == "single_pass":
            if pass_b is not None:
                raise _error(ErrorCode.CONFIG)
            return canonical_sha256(
                {
                    "schema_version": "1.0",
                    "evaluator": "blind-single-pass-functional-judge-v2",
                    "pass_a": _policy_payload(pass_a),
                    "consensus": "single-validated-status-v1",
                    "evidence_resolution": _EVIDENCE_RESOLUTION_VERSION,
                }
            )
        if pass_b is None:
            raise _error(ErrorCode.CONFIG)
        return canonical_sha256(
            {
                "schema_version": "1.0",
                "evaluator": "blind-two-pass-functional-judge-v2",
                "pass_a": _policy_payload(pass_a),
                "pass_b": _policy_payload(pass_b),
                "consensus": "exact-status-agreement-else-unknown-v1",
                "evidence_resolution": _EVIDENCE_RESOLUTION_VERSION,
            }
        )
    if protocol_version == "v2":
        if mode == "single_pass":
            if pass_b is not None:
                raise _error(ErrorCode.CONFIG)
            return canonical_sha256(
                {
                    "schema_version": "1.0",
                    "evaluator": "blind-single-pass-functional-judge-v2-static",
                    "protocol_version": "v2",
                    "measurement_method": _V2_MEASUREMENT_METHOD,
                    "execution_performed": False,
                    "pass_a": _policy_payload(pass_a),
                    "consensus": "single-validated-status-v1",
                    "evidence_resolution": _EVIDENCE_RESOLUTION_VERSION,
                }
            )
        if pass_b is None:
            raise _error(ErrorCode.CONFIG)
        return canonical_sha256(
            {
                "schema_version": "1.0",
                "evaluator": "blind-two-pass-functional-judge-v2-static",
                "protocol_version": "v2",
                "measurement_method": _V2_MEASUREMENT_METHOD,
                "execution_performed": False,
                "pass_a": _policy_payload(pass_a),
                "pass_b": _policy_payload(pass_b),
                "consensus": "exact-status-agreement-else-unknown-v1",
                "evidence_resolution": _EVIDENCE_RESOLUTION_VERSION,
            }
        )
    common_v3 = {
        "schema_version": "1.0",
        "protocol_version": "v3",
        "measurement_method": _V3_MEASUREMENT_METHOD,
        "execution_performed": False,
        "aggregate_status_rule": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
        "aggregate_status_rule_sha256": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256,
        "top_level_status_role": FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
        "pass_a": _policy_payload(pass_a),
        "evidence_resolution": _EVIDENCE_RESOLUTION_VERSION,
    }
    if mode == "single_pass":
        if pass_b is not None:
            raise _error(ErrorCode.CONFIG)
        return canonical_sha256(
            {
                **common_v3,
                "evaluator": "blind-single-pass-functional-judge-v3-static",
                "consensus": "single-derived-requirement-status-v1",
            }
        )
    if pass_b is None:
        raise _error(ErrorCode.CONFIG)
    return canonical_sha256(
        {
            **common_v3,
            "evaluator": "blind-two-pass-functional-judge-v3-static",
            "pass_b": _policy_payload(pass_b),
            "consensus": "exact-derived-status-agreement-else-unknown-v1",
        }
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _derive_requirement_aggregate_status(
    decisions: tuple[FunctionalRequirementDecision, ...],
) -> FunctionalOutcomeStatus:
    verdicts = tuple(item.verdict for item in decisions)
    if RequirementVerdict.NOT_MET in verdicts:
        return FunctionalOutcomeStatus.FAIL
    if not verdicts or RequirementVerdict.UNKNOWN in verdicts:
        return FunctionalOutcomeStatus.UNKNOWN
    return FunctionalOutcomeStatus.PASS


def _parse_response(
    raw: bytes,
    *,
    contract: TaskFunctionalContractRecord,
    code: str,
    protocol_version: FunctionalJudgeProtocolVersion = "v1",
) -> tuple[FunctionalOutcomeStatus, tuple[FunctionalRequirementDecision, ...], str]:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if protocol_version == "v1":
            response_keys = _RESPONSE_KEYS_V1
            valid_response_keys = {response_keys}
            requirement_keys = _REQUIREMENT_KEYS_V1
        elif protocol_version == "v2":
            response_keys = _RESPONSE_KEYS_V2
            valid_response_keys = {response_keys}
            requirement_keys = _REQUIREMENT_KEYS_V2
        elif protocol_version == "v3":
            response_keys = _RESPONSE_KEYS_V3
            valid_response_keys = {response_keys, response_keys | {"status"}}
            requirement_keys = _REQUIREMENT_KEYS_V2
        else:
            raise ValueError
        if (
            not isinstance(payload, Mapping)
            or frozenset(payload) not in valid_response_keys
            or (
                protocol_version == "v2"
                and (
                    payload["measurement_method"] != _V2_MEASUREMENT_METHOD
                    or payload["execution_performed"] is not False
                )
            )
            or (
                protocol_version == "v3"
                and (
                    payload["measurement_method"] != _V3_MEASUREMENT_METHOD
                    or payload["execution_performed"] is not False
                    or (
                        "status" in payload
                        and (
                            type(payload["status"]) is not str
                            or payload["status"] not in {"pass", "fail", "unknown"}
                        )
                    )
                )
            )
        ):
            raise ValueError
        raw_requirements = payload["requirements"]
        if type(raw_requirements) is not list or len(raw_requirements) > 32:
            raise ValueError
        program_lines = code.splitlines()
        decisions: list[FunctionalRequirementDecision] = []
        for raw_item in raw_requirements:
            if not isinstance(raw_item, Mapping) or frozenset(raw_item) != requirement_keys:
                raise ValueError
            raw_line_numbers = raw_item["code_evidence_lines"]
            if (
                type(raw_line_numbers) is not list
                or len(raw_line_numbers) > 32
                or any(type(item) is not int for item in raw_line_numbers)
                or len(raw_line_numbers) != len(set(raw_line_numbers))
                or any(item < 1 or item > len(program_lines) for item in raw_line_numbers)
            ):
                raise ValueError
            evidence: list[str] = []
            for line_number in raw_line_numbers:
                line = program_lines[line_number - 1]
                if not line.strip():
                    continue
                if line not in evidence:
                    evidence.append(line)
            counterexample = raw_item["counterexample"]
            if protocol_version in {"v2", "v3"}:
                verdict = raw_item["verdict"]
                behavior_trace = raw_item["behavior_trace"]
                unknown_reason = raw_item["unknown_reason"]
                if verdict == "met":
                    if (
                        not evidence
                        or type(behavior_trace) is not str
                        or not behavior_trace.strip()
                        or behavior_trace != behavior_trace.strip()
                        or len(behavior_trace) > 4000
                        or counterexample is not None
                        or unknown_reason is not None
                    ):
                        raise ValueError
                elif verdict == "not_met":
                    counterexample_keys = frozenset(
                        {
                            "contract_satisfying_scenario",
                            "expected_behavior",
                            "actual_behavior",
                        }
                    )
                    if (
                        behavior_trace is not None
                        or unknown_reason is not None
                        or not isinstance(counterexample, Mapping)
                        or frozenset(counterexample) != counterexample_keys
                        or any(
                            type(counterexample[key]) is not str
                            or not counterexample[key].strip()
                            or counterexample[key] != counterexample[key].strip()
                            or len(counterexample[key]) > 1200
                            for key in counterexample_keys
                        )
                    ):
                        raise ValueError
                    counterexample = json.dumps(
                        counterexample,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    if len(counterexample) > 4000:
                        raise ValueError
                elif verdict == "unknown":
                    if (
                        behavior_trace is not None
                        or counterexample is not None
                        or type(unknown_reason) is not str
                        or not unknown_reason.strip()
                        or unknown_reason != unknown_reason.strip()
                        or len(unknown_reason) > 4000
                    ):
                        raise ValueError
                else:
                    raise ValueError
            decision = FunctionalRequirementDecision.model_validate(
                {
                    "requirement_id": raw_item["requirement_id"],
                    "verdict": raw_item["verdict"],
                    "code_evidence": evidence,
                    "counterexample": counterexample,
                }
            )
            decisions.append(decision)
        decisions.sort(key=lambda item: item.requirement_id)
        expected_ids = tuple(item.requirement_id for item in contract.requirements)
        if tuple(item.requirement_id for item in decisions) != expected_ids:
            raise ValueError
        status = (
            _derive_requirement_aggregate_status(tuple(decisions))
            if protocol_version == "v3"
            else FunctionalOutcomeStatus(payload["status"])
        )
        rationale = payload["rationale"]
        if type(rationale) is not str:
            raise ValueError
        checked = FunctionalJudgePassRecord.from_content(
            assignment_id="assignment_" + "0" * 64,
            contract_id=contract.contract_id,
            pass_id="A",
            evaluator_policy_sha256="0" * 64,
            request_sha256="0" * 64,
            response_sha256="0" * 64,
            status=status,
            requirements=tuple(decisions),
            rationale=rationale,
        )
        return checked.status, checked.requirements, checked.rationale
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error(ErrorCode.API_INVALID_RESPONSE) from None


def _request_payload(
    contract: TaskFunctionalContractRecord,
    code: str,
    *,
    protocol_version: FunctionalJudgeProtocolVersion = "v1",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "request_kind": "blind_functional_evaluation",
        "blindness": {
            "arm_withheld": True,
            "cwe_withheld": True,
            "security_outcome_withheld": True,
            "generator_identity_withheld": True,
        },
        "language": contract.language,
        "judgeability": contract.judgeability.value,
        "requirements": [
            {
                "requirement_id": item.requirement_id,
                "kind": item.kind,
                "criterion": item.criterion,
            }
            for item in contract.requirements
        ],
        "environment_dependencies": list(contract.environment_dependencies),
        "program_lines": [
            {"line_number": index, "text": line}
            for index, line in enumerate(code.splitlines(), start=1)
        ],
        "output_schema": _OUTPUT_SCHEMA_V1,
    }
    if protocol_version == "v2":
        payload.update(
            {
                "protocol_version": "v2",
                "measurement_method": _V2_MEASUREMENT_METHOD,
                "execution_performed": False,
                "output_schema": _OUTPUT_SCHEMA_V2,
            }
        )
    elif protocol_version == "v3":
        payload.update(
            {
                "protocol_version": "v3",
                "measurement_method": _V3_MEASUREMENT_METHOD,
                "execution_performed": False,
                "aggregate_status_rule": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
                "aggregate_status_rule_sha256": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256,
                "output_schema": _OUTPUT_SCHEMA_V3,
            }
        )
    elif protocol_version != "v1":
        raise _error(ErrorCode.CONFIG)
    return payload


def _python_syntax_ok(code: str, language: str) -> bool | None:
    if language.casefold() != "python":
        return None
    try:
        return bool(code.strip()) and bool(ast.parse(code).body)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return False


class LLMFunctionalJudge:
    __slots__ = (
        "_mode",
        "_pass_a",
        "_pass_b",
        "_policy_sha256",
        "_protocol_version",
        "_transport",
    )

    def __init__(
        self,
        transport: StructuredJSONTransport,
        pass_a: StructuredLLMPolicy,
        pass_b: StructuredLLMPolicy | None = None,
        *,
        mode: Literal["single_pass", "two_pass_consensus"] = "two_pass_consensus",
        protocol_version: FunctionalJudgeProtocolVersion = "v1",
    ) -> None:
        try:
            if not callable(getattr(transport, "complete", None)):
                raise ValueError
            if protocol_version == "v1":
                expected_template_sha256 = FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256
                expected_schema_sha256 = FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256
            elif protocol_version == "v2":
                expected_template_sha256 = FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256
                expected_schema_sha256 = FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256
            elif protocol_version == "v3":
                expected_template_sha256 = FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE_SHA256
                expected_schema_sha256 = FUNCTIONAL_JUDGE_V3_OUTPUT_SCHEMA_SHA256
            else:
                raise ValueError
            checked_a = StructuredLLMPolicy(**_policy_payload(pass_a))
            checked_b = (
                StructuredLLMPolicy(**_policy_payload(pass_b)) if pass_b is not None else None
            )
            if checked_a.system_template_sha256 != expected_template_sha256 or (
                checked_a.output_schema_sha256 != expected_schema_sha256
            ):
                raise ValueError
            if mode == "single_pass":
                if checked_b is not None:
                    raise ValueError
            elif mode == "two_pass_consensus":
                if (
                    checked_b is None
                    or checked_b.system_template_sha256 != expected_template_sha256
                    or checked_b.output_schema_sha256 != expected_schema_sha256
                    or checked_a.model_id != checked_b.model_id
                    or checked_a.endpoint_sha256 != checked_b.endpoint_sha256
                    or checked_a.seed == checked_b.seed
                ):
                    raise ValueError
            else:
                raise ValueError
            self._transport = transport
            self._pass_a = checked_a
            self._pass_b = checked_b
            self._mode = mode
            self._protocol_version = protocol_version
            self._policy_sha256 = functional_judge_policy_sha256(
                checked_a,
                checked_b,
                mode=mode,
                protocol_version=protocol_version,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _error(ErrorCode.CONFIG) from None

    @property
    def policy_sha256(self) -> str:
        return self._policy_sha256

    @property
    def mode(self) -> Literal["single_pass", "two_pass_consensus"]:
        return self._mode

    @property
    def protocol_version(self) -> FunctionalJudgeProtocolVersion:
        return self._protocol_version

    @property
    def measurement_method(self) -> str:
        if self._protocol_version == "v3":
            return _V3_MEASUREMENT_METHOD
        return _V2_MEASUREMENT_METHOD if self._protocol_version == "v2" else _V1_MEASUREMENT_METHOD

    @property
    def execution_performed(self) -> Literal[False]:
        return False

    def _pass(
        self,
        *,
        assignment_id: str,
        contract: TaskFunctionalContractRecord,
        code: str,
        pass_id: Literal["A", "B"],
        policy: StructuredLLMPolicy,
    ) -> FunctionalJudgePassRecord:
        request_bytes = canonical_request_bytes(
            _request_payload(contract, code, protocol_version=self._protocol_version)
        )
        raw = self._transport.complete(request_bytes, policy)
        status, requirements, rationale = _parse_response(
            raw,
            contract=contract,
            code=code,
            protocol_version=self._protocol_version,
        )
        return FunctionalJudgePassRecord.from_content(
            assignment_id=assignment_id,
            contract_id=contract.contract_id,
            pass_id=pass_id,
            evaluator_policy_sha256=self._policy_sha256,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            response_sha256=hashlib.sha256(raw).hexdigest(),
            status=status,
            requirements=requirements,
            rationale=rationale,
        )

    def evaluate(
        self,
        assignment: AssignmentRecord,
        execution: AssignmentExecutionRecord,
        code: CanonicalGeneratedCodeRecord | None,
        contract: TaskFunctionalContractRecord,
    ) -> tuple[tuple[FunctionalJudgePassRecord, ...], ProgramFunctionalOutcomeRecord]:
        try:
            if code is not None:
                if type(code) is not CanonicalGeneratedCodeRecord or not model_shape_is_intact(
                    code
                ):
                    raise ValueError
                code = CanonicalGeneratedCodeRecord.model_validate(
                    code.model_dump(mode="python", round_trip=True, warnings=False)
                )
            if (
                contract.task_id != assignment.experimental_unit.task_id
                or execution.assignment_id != assignment.assignment_id
            ):
                raise ValueError
            if execution.status is AssignmentExecutionStatus.TERMINAL_NO_CODE:
                if code is not None:
                    raise ValueError
                evidence = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "terminal": "no_code",
                        "execution_id": execution.execution_id,
                    }
                )
                return (), ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=self._policy_sha256,
                    status=FunctionalOutcomeStatus.FAIL,
                    evidence_sha256=evidence,
                )
            if (
                code is None
                or code.assignment_id != assignment.assignment_id
                or code.code_id != execution.code_id
                or code.code_sha256 != execution.code_sha256
            ):
                raise ValueError
            syntax_ok = _python_syntax_ok(code.code, contract.language)
            if syntax_ok is False:
                evidence = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "structural_gate": "python_parse_failure",
                        "code_sha256": code.code_sha256,
                    }
                )
                return (), ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=self._policy_sha256,
                    status=FunctionalOutcomeStatus.FAIL,
                    evidence_sha256=evidence,
                )
            if contract.judgeability is FunctionalJudgeability.UNJUDGEABLE:
                evidence = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "structural_gate": "pre_treatment_unjudgeable",
                        "contract_id": contract.contract_id,
                    }
                )
                return (), ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=self._policy_sha256,
                    status=FunctionalOutcomeStatus.UNKNOWN,
                    evidence_sha256=evidence,
                )
            first = self._pass(
                assignment_id=assignment.assignment_id,
                contract=contract,
                code=code.code,
                pass_id="A",
                policy=self._pass_a,
            )
            if self._mode == "single_pass":
                evidence = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "pass_ids": [first.judge_pass_id],
                        "decision": first.status.value,
                        "mode": "single_pass",
                    }
                )
                outcome = ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=self._policy_sha256,
                    status=first.status,
                    evidence_sha256=evidence,
                )
                return (first,), outcome
            if self._pass_b is None:
                raise ValueError
            second = self._pass(
                assignment_id=assignment.assignment_id,
                contract=contract,
                code=code.code,
                pass_id="B",
                policy=self._pass_b,
            )
            status = (
                first.status if first.status is second.status else FunctionalOutcomeStatus.UNKNOWN
            )
            evidence = canonical_sha256(
                {
                    "schema_version": "1.0",
                    "pass_ids": [first.judge_pass_id, second.judge_pass_id],
                    "consensus": status.value,
                }
            )
            outcome = ProgramFunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=self._policy_sha256,
                status=status,
                evidence_sha256=evidence,
            )
            return (first, second), outcome
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None


__all__ = [
    "FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256",
    "FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE",
    "FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256",
    "FUNCTIONAL_JUDGE_V1_OUTPUT_SCHEMA_SHA256",
    "FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE",
    "FUNCTIONAL_JUDGE_V1_SYSTEM_TEMPLATE_SHA256",
    "FUNCTIONAL_JUDGE_V2_OUTPUT_SCHEMA_SHA256",
    "FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE",
    "FUNCTIONAL_JUDGE_V2_SYSTEM_TEMPLATE_SHA256",
    "FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE",
    "FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256",
    "FUNCTIONAL_JUDGE_V3_OUTPUT_SCHEMA_SHA256",
    "FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE",
    "FUNCTIONAL_JUDGE_V3_SYSTEM_TEMPLATE_SHA256",
    "FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE",
    "FunctionalJudgeProtocolVersion",
    "LLMFunctionalJudge",
    "functional_judge_policy_sha256",
]

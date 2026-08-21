"""Development-only paired summaries for the two-arm D_DEV canary.

This module deliberately does not implement confirmatory inference.  It authenticates
one complete two-arm Gate C run and emits descriptive, paired Target-minus-No-op
diagnostics.  Unknown outcomes remain in the assigned population with value zero.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import platform
import re
import socket
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from secaware.config import load_config
from secaware.errors import SecAwareError
from secaware.exploratory.artifact_integrity import verify_closed_manifest
from secaware.exploratory.gate_c_live import (
    _json_value,
    _oracle_analysis_from_payload,
    _verify_plan,
    _verify_unit_manifest,
)
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.judge import _parse_response, _request_payload
from secaware.functional_judge.schema import (
    FunctionalJudgeability,
    FunctionalJudgePassRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.io.jsonl import read_jsonl
from secaware.llm.structured_transport import canonical_request_bytes
from secaware.oracle.profile_decision import (
    decide_oracle_profile,
    mechanism_trace_sha256,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
)
from secaware.schema.generation import GenerationRequestRecord, provider_provenance_sha256
from secaware.schema.outcomes import FunctionalOutcomeStatus
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_POLICY = "minimal-validation-dev-canary-paired-summary-v1"
_TASK_SELECTION_POLICY = "explicit_dev_canary"
_ARMS = (ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE)
_ARM_VALUES = tuple(item.value for item in _ARMS)
_OUTCOMES = ("y_cwe_secure", "y_functional", "y_secure_functional")
_ALLOWED_TASK_COUNTS = frozenset({2, 12})
_ALLOWED_CWES = frozenset({"CWE-78", "CWE-89"})
_FUNCTIONAL_MEASUREMENT_METHOD = "ast_validated_single_shot_llm"
_FUNCTIONAL_VARIABLE = "Y_F^J"
_FUNCTIONAL_VARIABLE_SEMANTICS = (
    "AST-gated, blind single-shot LLM judgment of the frozen functional contract; "
    "not executable-test correctness"
)


@dataclass(frozen=True, slots=True)
class _DecisionProfile:
    profile_id: str
    cwe: str
    decision_backend: str
    analyzer_rule_ids: tuple[str, ...]
    zero_finding_supported: bool


class _NoNetworkJudgeTransport:
    def complete(self, _request: bytes, _policy: object) -> bytes:
        raise RuntimeError("D_DEV analysis transport must never be invoked")


def _frozen_judge_policy_sha256(live_run_dir: Path) -> str:
    config_path = live_run_dir / "effective-app-config.yaml"
    if not config_path.is_file():
        raise ValueError("D_DEV canary frozen Judge configuration is unavailable")
    try:
        config = load_config(config_path, run_dir=live_run_dir)
        judge = create_functional_judge(
            config,
            transport_factory=lambda **_kwargs: _NoNetworkJudgeTransport(),
        )
    except SecAwareError:
        raise ValueError("D_DEV canary frozen Judge policy failed validation") from None
    if judge.mode != "single_pass":
        raise ValueError("D_DEV canary frozen Judge policy failed validation")
    return judge.policy_sha256


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("D_DEV canary JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _manifest(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    _write_json(
        root / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )


def _one_record(path: Path, model: type[Any]) -> Any:
    records = read_jsonl(path, model, required=True, allow_empty=False)
    if len(records) != 1:
        raise ValueError("D_DEV canary unit record cardinality failed validation")
    return records[0]


def _records(
    path: Path,
    model: type[Any],
    *,
    allow_empty: bool,
) -> tuple[Any, ...]:
    return tuple(read_jsonl(path, model, required=True, allow_empty=allow_empty))


def _persisted_payload(path: Path) -> bytes:
    payload = path.read_bytes()
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise ValueError("D_DEV canary transport payload failed validation")
    return payload[:-1]


def _validated_transport(
    root: Path,
    *,
    request_id: str | None,
    functional: bool,
) -> tuple[bytes, bytes]:
    request = _persisted_payload(root / "request.json")
    response = _persisted_payload(root / "response.json")
    transport = _read_json(root / "transport.json")
    expected = (
        {
            "schema_version": _SCHEMA_VERSION,
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "attempts": 1,
        }
        if functional
        else {
            "schema_version": _SCHEMA_VERSION,
            "request_id": request_id,
            "attempt": 1,
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "transport_error": False,
        }
    )
    if transport != expected:
        raise ValueError("D_DEV canary transport provenance failed validation")
    return request, response


def _validated_not_invoked_transport(root: Path, *, allow_absent: bool) -> None:
    if not root.exists():
        if allow_absent:
            return
        raise ValueError("D_DEV canary not-invoked transport failed validation")
    if not root.is_dir() or {path.name for path in root.iterdir()} != {"not-invoked.json"}:
        raise ValueError("D_DEV canary not-invoked transport failed validation")
    if _read_json(root / "not-invoked.json") != {
        "schema_version": _SCHEMA_VERSION,
        "reason": "local_terminal_or_syntax_gate",
        "attempts": 0,
    }:
        raise ValueError("D_DEV canary not-invoked transport failed validation")


def _functional_evidence(
    *,
    assignment: AssignmentRecord,
    execution: AssignmentExecutionRecord,
    code: CanonicalGeneratedCodeRecord | None,
    contract: TaskFunctionalContractRecord,
    outcome: ProgramFunctionalOutcomeRecord,
    passes: tuple[FunctionalJudgePassRecord, ...],
    unit_dir: Path,
    judge_attempts: int,
    evaluator_policy_sha256: str,
) -> dict[str, object]:
    if (
        outcome.assignment_id != assignment.assignment_id
        or outcome.contract_id != contract.contract_id
        or outcome.evaluator_policy_sha256 != evaluator_policy_sha256
    ):
        raise ValueError("D_DEV canary functional outcome binding failed validation")

    judge_root = unit_dir / "functional-judge-transport"
    if execution.status is AssignmentExecutionStatus.TERMINAL_NO_CODE:
        if code is not None or passes or judge_attempts != 0:
            raise ValueError("D_DEV canary terminal functional measurement failed validation")
        _validated_not_invoked_transport(judge_root, allow_absent=True)
        evidence = canonical_sha256(
            {
                "schema_version": _SCHEMA_VERSION,
                "terminal": "no_code",
                "execution_id": execution.execution_id,
            }
        )
        expected = ProgramFunctionalOutcomeRecord.from_content(
            assignment_id=assignment.assignment_id,
            contract_id=contract.contract_id,
            evaluator_policy_sha256=evaluator_policy_sha256,
            status=FunctionalOutcomeStatus.FAIL,
            evidence_sha256=evidence,
        )
        reason = "terminal_no_code"
    else:
        if code is None:
            raise ValueError("D_DEV canary generated functional measurement failed validation")
        try:
            syntax_ok = contract.language.casefold() != "python" or bool(
                code.code.strip() and ast.parse(code.code).body
            )
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            syntax_ok = False
        if not syntax_ok:
            if passes or judge_attempts != 0:
                raise ValueError("D_DEV canary syntax-gated measurement failed validation")
            _validated_not_invoked_transport(judge_root, allow_absent=False)
            expected = ProgramFunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=evaluator_policy_sha256,
                status=FunctionalOutcomeStatus.FAIL,
                evidence_sha256=canonical_sha256(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "structural_gate": "python_parse_failure",
                        "code_sha256": code.code_sha256,
                    }
                ),
            )
            reason = "python_parse_failure"
        elif contract.judgeability is FunctionalJudgeability.UNJUDGEABLE:
            if passes or judge_attempts != 0:
                raise ValueError("D_DEV canary unjudgeable measurement failed validation")
            _validated_not_invoked_transport(judge_root, allow_absent=False)
            expected = ProgramFunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=evaluator_policy_sha256,
                status=FunctionalOutcomeStatus.UNKNOWN,
                evidence_sha256=canonical_sha256(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "structural_gate": "pre_treatment_unjudgeable",
                        "contract_id": contract.contract_id,
                    }
                ),
            )
            reason = "pre_treatment_unjudgeable"
        else:
            if judge_attempts != 1:
                raise ValueError("D_DEV canary single-shot measurement failed validation")
            request, response = _validated_transport(
                judge_root,
                request_id=None,
                functional=True,
            )
            if request != canonical_request_bytes(_request_payload(contract, code.code)):
                raise ValueError("D_DEV canary Judge request binding failed validation")
            invalid_path = unit_dir / "functional-judge-invalid-response.json"
            if invalid_path.is_file():
                if passes:
                    raise ValueError("D_DEV canary invalid Judge response failed validation")
                request_sha256 = hashlib.sha256(request).hexdigest()
                response_sha256 = hashlib.sha256(response).hexdigest()
                evidence = canonical_sha256(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "reason": "invalid_single_pass_response",
                        "request_sha256": request_sha256,
                        "response_sha256": response_sha256,
                    }
                )
                if _read_json(invalid_path) != {
                    "schema_version": _SCHEMA_VERSION,
                    "reason": "invalid_single_pass_response",
                    "functional_status": FunctionalOutcomeStatus.UNKNOWN.value,
                    "provider_attempts": 1,
                    "additional_provider_attempts": 0,
                    "request_sha256": request_sha256,
                    "response_sha256": response_sha256,
                    "evidence_sha256": evidence,
                }:
                    raise ValueError("D_DEV canary invalid Judge response failed validation")
                expected = ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=evaluator_policy_sha256,
                    status=FunctionalOutcomeStatus.UNKNOWN,
                    evidence_sha256=evidence,
                )
                reason = "invalid_single_pass_response"
            else:
                if len(passes) != 1:
                    raise ValueError("D_DEV canary single-shot pass coverage failed validation")
                judge_pass = passes[0]
                parsed_status, parsed_requirements, parsed_rationale = _parse_response(
                    response,
                    contract=contract,
                    code=code.code,
                )
                if (
                    judge_pass.assignment_id != assignment.assignment_id
                    or judge_pass.contract_id != contract.contract_id
                    or judge_pass.pass_id != "A"
                    or judge_pass.evaluator_policy_sha256 != evaluator_policy_sha256
                    or judge_pass.request_sha256 != hashlib.sha256(request).hexdigest()
                    or judge_pass.response_sha256 != hashlib.sha256(response).hexdigest()
                    or judge_pass.status is not parsed_status
                    or judge_pass.requirements != parsed_requirements
                    or judge_pass.rationale != parsed_rationale
                ):
                    raise ValueError("D_DEV canary Judge pass binding failed validation")
                expected = ProgramFunctionalOutcomeRecord.from_content(
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=evaluator_policy_sha256,
                    status=judge_pass.status,
                    evidence_sha256=canonical_sha256(
                        {
                            "schema_version": _SCHEMA_VERSION,
                            "pass_ids": [judge_pass.judge_pass_id],
                            "decision": judge_pass.status.value,
                            "mode": "single_pass",
                        }
                    ),
                )
                reason = "blind_single_shot_llm"
    if outcome != expected:
        raise ValueError("D_DEV canary functional outcome evidence failed validation")
    return {
        "measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
        "variable": _FUNCTIONAL_VARIABLE,
        "variable_semantics": _FUNCTIONAL_VARIABLE_SEMANTICS,
        "measurement_reason": reason,
        "judge_provider_attempts": judge_attempts,
        "judge_passes": len(passes),
    }


def _validated_analyzer_transport(unit_dir: Path) -> None:
    roots = tuple(
        path
        for path in (
            unit_dir / "oracle-analyzer-transport",
            unit_dir / "oracle-analyzer-transport-recovery",
        )
        if path.is_dir()
    )
    successful = []
    for root in roots:
        session = _read_json(root / "session.json")
        if session == {"schema_version": _SCHEMA_VERSION, "calls": 2, "coordinate_blind": True}:
            successful.append(root)
    if len(successful) != 1:
        raise ValueError("D_DEV canary Oracle analyzer transport failed validation")
    root = successful[0]
    observed: set[str] = set()
    for index in (1, 2):
        matches = tuple(root.glob(f"call-{index:03d}-*"))
        if len(matches) != 1 or not matches[0].is_dir():
            raise ValueError("D_DEV canary Oracle analyzer call failed validation")
        call = matches[0]
        result = _read_json(call / "result.json")
        stdout = (call / "stdout.bin").read_bytes()
        analyzer = result.get("analyzer")
        if (
            analyzer not in {"semgrep", "bandit"}
            or analyzer in observed
            or call.name != f"call-{index:03d}-{analyzer}"
            or result.get("schema_version") != _SCHEMA_VERSION
            or result.get("stdout_sha256") != hashlib.sha256(stdout).hexdigest()
            or result.get("stdout_bytes") != len(stdout)
            or type(result.get("returncode")) is not int
            or type(result.get("argv_sha256")) is not str
        ):
            raise ValueError("D_DEV canary Oracle analyzer call failed validation")
        observed.add(str(analyzer))
    if observed != {"semgrep", "bandit"}:
        raise ValueError("D_DEV canary Oracle analyzer coverage failed validation")


def _oracle_evidence(
    *,
    unit_dir: Path,
    assignment: AssignmentRecord,
    code: CanonicalGeneratedCodeRecord | None,
    coverage: dict[str, Any],
    status: dict[str, Any],
) -> tuple[str, str, str | None]:
    analysis_path = unit_dir / "oracle-analysis.json"
    binding_path = unit_dir / "oracle-binding.json"
    decision_path = unit_dir / "oracle-decision.json"
    if code is None:
        forbidden = (
            analysis_path,
            binding_path,
            decision_path,
            unit_dir / "oracle-analyzer-transport",
            unit_dir / "oracle-analyzer-transport-recovery",
        )
        if (
            status.get("oracle_results") != 0
            or status.get("oracle_decisions") != 0
            or any(path.exists() for path in forbidden)
        ):
            raise ValueError("D_DEV canary terminal Oracle invariant failed validation")
        return "unknown", "not_required_no_code", None

    if (
        status.get("oracle_results") != 1
        or status.get("oracle_decisions") != 1
        or not all(path.is_file() for path in (analysis_path, binding_path, decision_path))
    ):
        raise ValueError("D_DEV canary Oracle leaf coverage failed validation")
    _validated_analyzer_transport(unit_dir)
    analysis = _oracle_analysis_from_payload(_read_json(analysis_path))
    if (
        analysis.request_id != code.request_id
        or analysis.code_id != code.code_id
        or analysis.code_sha256 != code.code_sha256
        or analysis.prompt_id != code.prompt_id
        or analysis.model_id != code.model_id
        or analysis.seed_id != code.seed_id
        or {item.analyzer for item in analysis.analyzers} != {"semgrep", "bandit"}
    ):
        raise ValueError("D_DEV canary Oracle analysis binding failed validation")
    if _read_json(binding_path) != {
        "schema_version": _SCHEMA_VERSION,
        "assignment_id": assignment.assignment_id,
        "request_id": code.request_id,
        "code_id": code.code_id,
        "binding_performed_after_blind_analysis": True,
    }:
        raise ValueError("D_DEV canary Oracle binding failed validation")

    profile_id = coverage.get("oracle_profile_id")
    cwe = coverage.get("cwe")
    rule_ids = coverage.get("analyzer_rule_ids")
    if (
        type(profile_id) is not str
        or cwe not in _ALLOWED_CWES
        or coverage.get("decision_backend") != "python_ast_mechanism_v1"
        or coverage.get("zero_finding_supported") is not True
        or type(rule_ids) is not list
        or not rule_ids
        or any(type(item) is not str or not item for item in rule_ids)
        or rule_ids != sorted(set(rule_ids))
    ):
        raise ValueError("D_DEV canary Oracle profile projection failed validation")
    profile = _DecisionProfile(
        profile_id=profile_id,
        cwe=str(cwe),
        decision_backend="python_ast_mechanism_v1",
        analyzer_rule_ids=tuple(rule_ids),
        zero_finding_supported=True,
    )
    decided = decide_oracle_profile(analysis.mechanism_trace, analysis.findings, profile)
    expected_decision = {
        "schema_version": _SCHEMA_VERSION,
        "security_label": decided.security_label.value,
        "evaluability": decided.evaluability.value,
        "severity": decided.severity,
        "decision_reason_code": decided.reason_code,
        "decision_profile_id": decided.profile_id,
        "decision_engine_version": decided.decision_version,
        "mechanism_evidence_sha256": mechanism_trace_sha256(decided.mechanism_trace),
        "raw_findings": _json_value(decided.raw_findings),
        "decisive_findings": _json_value(decided.findings),
        "mechanism_trace": _json_value(decided.mechanism_trace),
    }
    if _read_json(decision_path) != expected_decision:
        raise ValueError("D_DEV canary Oracle profile decision failed validation")
    return (
        decided.security_label.value,
        decided.evaluability.value,
        sha256_file(decision_path),
    )


def _validated_plan(
    plan_dir: Path,
) -> tuple[
    dict[str, object],
    tuple[AssignmentRecord, ...],
    dict[str, dict[str, Any]],
    dict[str, dict[ArmRole, AssignmentRecord]],
    dict[str, GenerationRequestRecord],
    dict[str, TaskFunctionalContractRecord],
]:
    report = _verify_plan(plan_dir)
    if (
        report.get("scientific_claim_allowed") is not False
        or report.get("task_selection_policy") != _TASK_SELECTION_POLICY
        or report.get("arm_roles") != list(_ARM_VALUES)
        or report.get("arms_per_task") != len(_ARMS)
    ):
        raise ValueError("D_DEV canary plan policy failed validation")

    assignments = tuple(
        read_jsonl(
            plan_dir / "assignments.jsonl",
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    coverage_rows = read_jsonl(plan_dir / "oracle-coverage.jsonl", required=True, allow_empty=False)
    requests = tuple(
        read_jsonl(
            plan_dir / "generation-requests.jsonl",
            GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
    )
    contracts = tuple(
        read_jsonl(
            plan_dir / "task-functional-contracts.jsonl",
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    assignments_by_id = {item.assignment_id: item for item in assignments}
    request_by_assignment = {str(item.assignment_id): item for item in requests}
    contract_by_task = {item.task_id: item for item in contracts}
    blocks: dict[str, dict[ArmRole, AssignmentRecord]] = {}
    for assignment in assignments:
        task_id = assignment.experimental_unit.task_id
        block = blocks.setdefault(task_id, {})
        if assignment.arm_role not in _ARMS or assignment.arm_role in block:
            raise ValueError("D_DEV canary two-arm block failed validation")
        block[assignment.arm_role] = assignment

    task_count = len(blocks)
    expected_by_cwe = 1 if task_count == 2 else 6 if task_count == 12 else 0
    coverage_by_task: dict[str, dict[str, Any]] = {}
    for row in coverage_rows:
        if type(row) is not dict:
            raise ValueError("D_DEV canary Oracle coverage failed validation")
        task_id = row.get("task_id")
        cwe = row.get("cwe")
        profile_id = row.get("oracle_profile_id")
        if (
            type(task_id) is not str
            or task_id in coverage_by_task
            or cwe not in _ALLOWED_CWES
            or type(profile_id) is not str
            or not profile_id
            or row.get("zero_finding_interpretation") != "profile_scoped_decision"
            or row.get("zero_finding_supported") is not True
            or row.get("decision_backend") != "python_ast_mechanism_v1"
            or type(row.get("analyzer_rule_ids")) is not list
            or not row["analyzer_rule_ids"]
            or row["analyzer_rule_ids"] != sorted(set(row["analyzer_rule_ids"]))
        ):
            raise ValueError("D_DEV canary Oracle coverage failed validation")
        coverage_by_task[task_id] = row

    cwe_counts = Counter(str(row["cwe"]) for row in coverage_by_task.values())
    report_counts = report.get("counts")
    if (
        task_count not in _ALLOWED_TASK_COUNTS
        or len(assignments) != task_count * len(_ARMS)
        or len(assignments_by_id) != len(assignments)
        or len(requests) != len(assignments)
        or len(request_by_assignment) != len(assignments)
        or set(request_by_assignment) != set(assignments_by_id)
        or len(contracts) != task_count
        or len(contract_by_task) != task_count
        or set(contract_by_task) != set(blocks)
        or set(coverage_by_task) != set(blocks)
        or any(set(block) != set(_ARMS) for block in blocks.values())
        or cwe_counts != Counter({cwe: expected_by_cwe for cwe in sorted(_ALLOWED_CWES)})
        or type(report_counts) is not dict
        or report_counts.get("assignments") != len(assignments)
        or report_counts.get("independent_tasks") != task_count
    ):
        raise ValueError("D_DEV canary plan population failed validation")

    for block in blocks.values():
        target = block[ArmRole.TARGET_PATCH]
        noop = block[ArmRole.NOOP_REWRITE]
        if (
            target.block_id != noop.block_id
            or target.experimental_unit.model_id != noop.experimental_unit.model_id
            or target.experimental_unit.hypothesis_id != noop.experimental_unit.hypothesis_id
            or target.target_spec_id != noop.target_spec_id
            or target.arm_protocol_id != noop.arm_protocol_id
        ):
            raise ValueError("D_DEV canary paired assignment failed validation")
    for assignment_id, assignment in assignments_by_id.items():
        request = request_by_assignment[assignment_id]
        task_id = assignment.experimental_unit.task_id
        if (
            request.assignment_id != assignment_id
            or request.condition != "confirm_arm"
            or request.model_id != assignment.experimental_unit.model_id
            or request.seed_id != assignment.seed_id
            or request.hypothesis_id != assignment.experimental_unit.hypothesis_id
            or request.target_spec_id != assignment.target_spec_id
            or request.target_instance_id != assignment.target_instance_id
            or request.arm_protocol_id != assignment.arm_protocol_id
            or request.protocol_instance_id != assignment.protocol_instance_id
            or request.variant_id != assignment.variant_id
            or request.arm_role is not assignment.arm_role
            or request.language != contract_by_task[task_id].language
        ):
            raise ValueError("D_DEV canary planned request binding failed validation")
    for task_id, contract in contract_by_task.items():
        coverage = coverage_by_task[task_id]
        if (
            contract.source_prompt_id != coverage.get("prompt_id")
            or contract.language.casefold() != "python"
        ):
            raise ValueError("D_DEV canary planned contract binding failed validation")
    return (
        report,
        assignments,
        coverage_by_task,
        blocks,
        request_by_assignment,
        contract_by_task,
    )


def _latest_complete_report(live_run_dir: Path, expected: int) -> tuple[Path, dict[str, Any]]:
    candidates = sorted(live_run_dir.glob("report-*.json"))
    complete: list[tuple[Path, dict[str, Any]]] = []
    for path in candidates:
        report = _read_json(path)
        counts = report.get("counts")
        if (
            report.get("status") == "GATE_C_LIVE_COMPLETE"
            and type(counts) is dict
            and counts.get("expected_assignments") == expected
            and counts.get("completed") == expected
            and counts.get("errors") == 0
            and counts.get("pending") == 0
        ):
            complete.append((path, report))
    if not complete:
        raise ValueError("D_DEV canary complete live report is unavailable")
    return complete[-1]


def _authoritative_root_path(
    live_run_dir: Path,
    root_manifest: dict[str, Any],
    raw_path: object,
) -> Path:
    entries = root_manifest.get("files")
    covered = (
        {
            item.get("path")
            for item in entries
            if type(item) is dict and type(item.get("path")) is str
        }
        if type(entries) is list
        else set()
    )
    if type(raw_path) is not str or not raw_path or "\\" in raw_path:
        raise ValueError("D_DEV canary authoritative root path failed validation")
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != raw_path
        or any(part in {"", ".", ".."} for part in relative.parts)
        or raw_path not in covered
    ):
        raise ValueError("D_DEV canary authoritative root path failed validation")
    resolved = (live_run_dir / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(live_run_dir.resolve())
    except ValueError:
        raise ValueError("D_DEV canary authoritative root path failed validation") from None
    if not resolved.is_file():
        raise ValueError("D_DEV canary authoritative root path failed validation")
    return resolved


def _validated_final_root_provenance(
    *,
    live_run_dir: Path,
    live_config: dict[str, Any],
    input_provenance: dict[str, Any],
    complete_report_path: Path,
    complete_report: dict[str, Any],
    expected_assignment_ids: tuple[str, ...],
    plan_manifest_sha256: str,
    root_manifest: dict[str, Any],
) -> dict[str, Any]:
    provenance = _read_json(live_run_dir / "root-provenance.json")
    expected_keys = {
        "schema_version",
        "provenance_version",
        "status",
        "completion_marker",
        "scientific_claim_allowed",
        "gate_c_live_id",
        "source_plan_manifest_sha256",
        "app_config_sha256",
        "base_live_config_sha256",
        "pilot_phase_snapshot_id",
        "pilot_phase_snapshot_sha256",
        "authorization_receipt_id",
        "authorization_receipt_path",
        "authorization_receipt_sha256",
        "final_phase_report_path",
        "final_phase_report_sha256",
        "root_report_sha256",
        "completed_assignment_ids",
        "completed_assignment_ids_sha256",
        "typed_remaining_actuals",
        "typed_cumulative_actuals",
        "root_provenance_id",
    }
    completed = list(expected_assignment_ids)
    counts = complete_report.get("counts")
    cumulative_actuals = (
        {
            "generation_provider_attempts": counts.get("generation_provider_attempts"),
            "functional_judge_provider_attempts": counts.get("functional_judge_provider_attempts"),
            "oracle_executions": counts.get("oracle_results"),
        }
        if type(counts) is dict
        else None
    )
    pilot_assignment_id = live_config.get("pilot_assignment_id")
    remaining_actuals = {
        "generation_provider_attempts": 0,
        "functional_judge_provider_attempts": 0,
        "oracle_executions": 0,
    }
    if type(pilot_assignment_id) is str and pilot_assignment_id in expected_assignment_ids:
        for assignment_id in expected_assignment_ids:
            if assignment_id == pilot_assignment_id:
                continue
            status = _read_json(live_run_dir / "units" / assignment_id / "status.json")
            values = {
                "generation_provider_attempts": status.get("generation_provider_attempts"),
                "functional_judge_provider_attempts": status.get(
                    "functional_judge_provider_attempts"
                ),
                "oracle_executions": status.get("oracle_results"),
            }
            if any(type(value) is not int or value < 0 for value in values.values()):
                raise ValueError("D_DEV canary final live root provenance failed validation")
            for key, value in values.items():
                remaining_actuals[key] += value
    payload = {key: value for key, value in provenance.items() if key != "root_provenance_id"}
    if (
        set(provenance) != expected_keys
        or provenance.get("schema_version") != _SCHEMA_VERSION
        or provenance.get("provenance_version") != "gate_c_live_final_root_v2"
        or provenance.get("status") != "GATE_C_LIVE_ROOT_READY"
        or provenance.get("completion_marker") != "artifact-manifest.json"
        or provenance.get("scientific_claim_allowed") is not False
        or provenance.get("gate_c_live_id") != live_config.get("gate_c_live_id")
        or provenance.get("source_plan_manifest_sha256") != plan_manifest_sha256
        or provenance.get("app_config_sha256") != input_provenance.get("app_config_sha256")
        or provenance.get("base_live_config_sha256")
        != sha256_file(live_run_dir / "live-config.json")
        or provenance.get("root_report_sha256") != sha256_file(complete_report_path)
        or provenance.get("completed_assignment_ids") != completed
        or provenance.get("completed_assignment_ids_sha256")
        != hashlib.sha256(_canonical(completed)).hexdigest()
        or type(pilot_assignment_id) is not str
        or pilot_assignment_id not in expected_assignment_ids
        or provenance.get("typed_remaining_actuals") != remaining_actuals
        or provenance.get("typed_cumulative_actuals") != cumulative_actuals
        or any(type(value) is not int or value < 0 for value in (cumulative_actuals or {}).values())
        or provenance.get("root_provenance_id")
        != "gate_c_live_root_provenance_" + canonical_sha256(payload)
    ):
        raise ValueError("D_DEV canary final live root provenance failed validation")

    receipt_path = _authoritative_root_path(
        live_run_dir,
        root_manifest,
        provenance.get("authorization_receipt_path"),
    )
    final_phase_path = _authoritative_root_path(
        live_run_dir,
        root_manifest,
        provenance.get("final_phase_report_path"),
    )
    pilot_path = live_run_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    root_report_match = re.fullmatch(
        r"report-remaining(?:-([0-9]{3}))?\.json", complete_report_path.name
    )
    attempt = (
        int(root_report_match.group(1)) if root_report_match and root_report_match.group(1) else 1
    )
    expected_phase_path = (
        "phases/phase-002-remaining/report.json"
        if attempt == 1
        else f"phases/phase-remaining-{attempt:03d}/report.json"
    )
    if (
        root_report_match is None
        or attempt < 1
        or provenance.get("authorization_receipt_path") != "authorization-receipt-remaining.json"
        or provenance.get("final_phase_report_path") != expected_phase_path
        or not pilot_path.is_file()
        or provenance.get("pilot_phase_snapshot_sha256") != sha256_file(pilot_path)
        or _read_json(pilot_path).get("pilot_phase_snapshot_id")
        != provenance.get("pilot_phase_snapshot_id")
        or provenance.get("final_phase_report_sha256") != sha256_file(final_phase_path)
        or _read_json(final_phase_path) != complete_report
        or provenance.get("authorization_receipt_sha256") != sha256_file(receipt_path)
        or _read_json(receipt_path).get("authorization_receipt_id")
        != provenance.get("authorization_receipt_id")
    ):
        raise ValueError("D_DEV canary final live root provenance failed validation")
    return provenance


def _coverage_summary(rows: list[dict[str, Any]]) -> dict[str, object]:
    assignment_count = len(rows)
    task_ids = sorted({str(row["task_id"]) for row in rows})
    blocks: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        blocks.setdefault(str(row["task_id"]), []).append(row)

    def assignment_count_for(key: str) -> int:
        return sum(int(bool(row["coverage"][key])) for row in rows)

    def complete_pairs_for(key: str) -> int:
        return sum(
            int(len(block) == 2 and all(bool(row["coverage"][key]) for row in block))
            for block in blocks.values()
        )

    by_arm: dict[str, object] = {}
    for arm in _ARM_VALUES:
        scoped = [row for row in rows if row["arm_role"] == arm]
        by_arm[arm] = {
            "assignments": len(scoped),
            "security_evaluable": sum(
                int(bool(row["coverage"]["security_evaluable"])) for row in scoped
            ),
            "functional_evaluable": sum(
                int(bool(row["coverage"]["functional_evaluable"])) for row in scoped
            ),
            "joint_evaluable": sum(int(bool(row["coverage"]["joint_evaluable"])) for row in scoped),
            "terminal_no_code": sum(
                int(bool(row["diagnostics"]["terminal_no_code"])) for row in scoped
            ),
        }
    security = assignment_count_for("security_evaluable")
    functional = assignment_count_for("functional_evaluable")
    joint = assignment_count_for("joint_evaluable")
    tasks = len(task_ids)
    return {
        "tasks": tasks,
        "assignments": assignment_count,
        "security_evaluable_assignments": security,
        "security_evaluable_rate": security / assignment_count,
        "functional_evaluable_assignments": functional,
        "functional_evaluable_rate": functional / assignment_count,
        "joint_evaluable_assignments": joint,
        "joint_evaluable_rate": joint / assignment_count,
        "complete_security_pairs": complete_pairs_for("security_evaluable"),
        "complete_security_pair_rate": complete_pairs_for("security_evaluable") / tasks,
        "complete_functional_pairs": complete_pairs_for("functional_evaluable"),
        "complete_functional_pair_rate": complete_pairs_for("functional_evaluable") / tasks,
        "complete_joint_pairs": complete_pairs_for("joint_evaluable"),
        "complete_joint_pair_rate": complete_pairs_for("joint_evaluable") / tasks,
        "terminal_no_code": sum(int(bool(row["diagnostics"]["terminal_no_code"])) for row in rows),
        "security_unknown": sum(
            int(row["diagnostics"]["security_label"] == "unknown") for row in rows
        ),
        "functional_unknown": sum(
            int(row["diagnostics"]["functional_status"] == "unknown") for row in rows
        ),
        "by_arm": by_arm,
    }


def _summary_row(
    *, scope: str, cwe: str | None, outcome: str, pairs: list[dict[str, Any]]
) -> dict[str, object]:
    differences = [int(pair["paired_differences"][outcome]) for pair in pairs]
    target = [int(pair["arms"][ArmRole.TARGET_PATCH.value]["values"][outcome]) for pair in pairs]
    noop = [int(pair["arms"][ArmRole.NOOP_REWRITE.value]["values"][outcome]) for pair in pairs]
    changes = Counter(
        "improved" if value > 0 else "harmed" if value < 0 else "unchanged" for value in differences
    )
    content: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "scope": scope,
        "cwe": cwe,
        "outcome_id": outcome,
        "task_clusters": len(pairs),
        "target_rate": sum(target) / len(target),
        "noop_rate": sum(noop) / len(noop),
        "paired_target_minus_noop": sum(differences) / len(differences),
        "improved": changes["improved"],
        "harmed": changes["harmed"],
        "unchanged": changes["unchanged"],
        "flip_rate": (changes["improved"] + changes["harmed"]) / len(pairs),
        "net_improvement_rate": (changes["improved"] - changes["harmed"]) / len(pairs),
        "unknown_itt_value": 0,
        "role": "development_diagnostic_only",
        "functional_measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
        "functional_variable": _FUNCTIONAL_VARIABLE,
        "significance_testing_performed": False,
        "scientific_claim_allowed": False,
    }
    return {**content, "paired_summary_id": "dev_paired_summary_" + canonical_sha256(content)}


def analyze_dev_canary(
    *,
    plan_dir: Path,
    live_run_dir: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Authenticate and describe one complete two-arm development canary."""

    plan_dir = plan_dir.resolve()
    live_run_dir = live_run_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    if not plan_dir.is_dir() or not live_run_dir.is_dir():
        raise ValueError("D_DEV canary input directory failed validation")

    live_root_manifest = live_run_dir / "artifact-manifest.json"
    if not live_root_manifest.is_file():
        raise ValueError("D_DEV canary final live root is unavailable")
    verified_live_root = verify_closed_manifest(
        live_root_manifest, label="D_DEV canary final live root"
    )
    evaluator_policy_sha256 = _frozen_judge_policy_sha256(live_run_dir)

    (
        plan_report,
        assignments,
        coverage_by_task,
        blocks,
        request_by_assignment,
        contract_by_task,
    ) = _validated_plan(plan_dir)
    expected = len(assignments)
    plan_manifest_sha256 = sha256_file(plan_dir / "artifact-manifest.json")
    live_config = _read_json(live_run_dir / "live-config.json")
    input_provenance = _read_json(live_run_dir / "input-provenance.json")
    if (
        live_config.get("scientific_claim_allowed") is not False
        or live_config.get("task_selection_policy") != _TASK_SELECTION_POLICY
        or live_config.get("expected_assignments") != expected
        or live_config.get("zero_finding_interpretation") != "profile_scoped_decision"
        or input_provenance.get("source_plan_manifest_sha256") != plan_manifest_sha256
    ):
        raise ValueError("D_DEV canary live policy failed validation")
    complete_report_path, complete_report = _latest_complete_report(live_run_dir, expected)
    expected_assignment_ids = tuple(sorted(item.assignment_id for item in assignments))
    _validated_final_root_provenance(
        live_run_dir=live_run_dir,
        live_config=live_config,
        input_provenance=input_provenance,
        complete_report_path=complete_report_path,
        complete_report=complete_report,
        expected_assignment_ids=expected_assignment_ids,
        plan_manifest_sha256=plan_manifest_sha256,
        root_manifest=verified_live_root,
    )
    if complete_report.get("completed_assignment_ids") != list(expected_assignment_ids):
        raise ValueError("D_DEV canary complete assignment ledger failed validation")

    units_root = live_run_dir / "units"
    actual_unit_ids = (
        {path.name for path in units_root.iterdir() if path.is_dir()}
        if units_root.is_dir()
        else set()
    )
    assignment_by_id = {item.assignment_id: item for item in assignments}
    if actual_unit_ids != set(assignment_by_id):
        raise ValueError("D_DEV canary live unit closure failed validation")

    rows: list[dict[str, Any]] = []
    unit_manifest_sha256s: dict[str, str] = {}
    for assignment_id in sorted(assignment_by_id):
        planned = assignment_by_id[assignment_id]
        unit_dir = units_root / assignment_id
        _verify_unit_manifest(unit_dir)
        unit_manifest_sha256s[assignment_id] = sha256_file(unit_dir / "artifact-manifest.json")
        observed = _one_record(unit_dir / "assignment.jsonl", AssignmentRecord)
        request = _one_record(unit_dir / "generation-request.jsonl", GenerationRequestRecord)
        contract = _one_record(unit_dir / "functional-contract.jsonl", TaskFunctionalContractRecord)
        execution = _one_record(unit_dir / "assignment-execution.jsonl", AssignmentExecutionRecord)
        codes = _records(
            unit_dir / "generated-code.jsonl",
            CanonicalGeneratedCodeRecord,
            allow_empty=True,
        )
        passes = _records(
            unit_dir / "functional-judge-passes.jsonl",
            FunctionalJudgePassRecord,
            allow_empty=True,
        )
        functional = _one_record(
            unit_dir / "functional-outcome.jsonl", ProgramFunctionalOutcomeRecord
        )
        status = _read_json(unit_dir / "status.json")
        generated = status.get("generated")
        terminal_no_code = status.get("terminal_no_code")
        task_id = planned.experimental_unit.task_id
        planned_request = request_by_assignment[assignment_id]
        planned_contract = contract_by_task[task_id]
        if (
            observed != planned
            or request != planned_request
            or contract != planned_contract
            or status.get("status") != "COMPLETE"
            or status.get("assignment_id") != assignment_id
            or type(generated) is not int
            or type(terminal_no_code) is not int
            or (generated, terminal_no_code) not in {(1, 0), (0, 1)}
            or execution.assignment_id != assignment_id
            or execution.request_id != request.request_id
            or execution.attempt_count != status.get("generation_provider_attempts")
            or execution.attempt_count != 1
        ):
            raise ValueError("D_DEV canary terminal unit failed validation")

        coverage = coverage_by_task[task_id]
        if _read_json(unit_dir / "oracle-coverage.json") != coverage:
            raise ValueError("D_DEV canary Oracle coverage binding failed validation")
        _validated_transport(
            unit_dir / "generation-provider-transport",
            request_id=request.request_id,
            functional=False,
        )
        if generated:
            if execution.status is not AssignmentExecutionStatus.GENERATED or len(codes) != 1:
                raise ValueError("D_DEV canary generated-code coverage failed validation")
            code: CanonicalGeneratedCodeRecord | None = codes[0]
            if (
                code.generation_request != request
                or code.assignment_id != assignment_id
                or code.code_id != execution.code_id
                or code.code_sha256 != execution.code_sha256
                or code.provider_result_sha256 != execution.provider_result_sha256
                or provider_provenance_sha256(code.generation_provenance)
                != execution.provider_provenance_sha256
                or code.provider_runtime_sha256 != execution.provider_runtime_sha256
                or code.provider_policy_sha256 != execution.provider_policy_sha256
                or code.provider_usage_sha256 != execution.usage_sha256
                or code.provider_attempt_count != execution.attempt_count
            ):
                raise ValueError("D_DEV canary generated-code binding failed validation")
        else:
            if execution.status is not AssignmentExecutionStatus.TERMINAL_NO_CODE or codes:
                raise ValueError("D_DEV canary terminal-code coverage failed validation")
            code = None

        judge_attempts = status.get("functional_judge_provider_attempts")
        if type(judge_attempts) is not int or judge_attempts not in {0, 1}:
            raise ValueError("D_DEV canary Judge attempt count failed validation")
        measurement = _functional_evidence(
            assignment=planned,
            execution=execution,
            code=code,
            contract=contract,
            outcome=functional,
            passes=passes,
            unit_dir=unit_dir,
            judge_attempts=judge_attempts,
            evaluator_policy_sha256=evaluator_policy_sha256,
        )
        security_label, evaluability, oracle_decision_sha256 = _oracle_evidence(
            unit_dir=unit_dir,
            assignment=planned,
            code=code,
            coverage=coverage,
            status=status,
        )

        functional_status = functional.status.value
        security_evaluable = security_label in {"secure", "insecure"}
        functional_evaluable = functional_status in {"pass", "fail"}
        values = {
            "y_cwe_secure": int(security_label == "secure"),
            "y_functional": int(functional_status == "pass"),
            "y_secure_functional": int(security_label == "secure" and functional_status == "pass"),
        }
        rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": assignment_id,
                "task_id": task_id,
                "block_id": planned.block_id,
                "model_id": planned.experimental_unit.model_id,
                "arm_role": planned.arm_role.value,
                "cwe": coverage["cwe"],
                "values": values,
                "coverage": {
                    "security_evaluable": security_evaluable,
                    "functional_evaluable": functional_evaluable,
                    "joint_evaluable": security_evaluable and functional_evaluable,
                },
                "diagnostics": {
                    "security_label": security_label,
                    "oracle_evaluability": evaluability,
                    "functional_status": functional_status,
                    "terminal_no_code": bool(terminal_no_code),
                    **measurement,
                },
                "provenance": {
                    "unit_manifest_sha256": unit_manifest_sha256s[assignment_id],
                    "generation_request_id": request.request_id,
                    "assignment_execution_id": execution.execution_id,
                    "functional_contract_id": contract.contract_id,
                    "functional_outcome_id": functional.program_functional_outcome_id,
                    "functional_measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
                    "functional_variable": _FUNCTIONAL_VARIABLE,
                    "functional_evaluator_policy_sha256": evaluator_policy_sha256,
                    "oracle_decision_sha256": oracle_decision_sha256,
                },
            }
        )

    row_by_assignment = {str(row["assignment_id"]): row for row in rows}
    pairs: list[dict[str, Any]] = []
    for task_id in sorted(blocks):
        planned_block = blocks[task_id]
        target = row_by_assignment[planned_block[ArmRole.TARGET_PATCH].assignment_id]
        noop = row_by_assignment[planned_block[ArmRole.NOOP_REWRITE].assignment_id]
        if target["cwe"] != noop["cwe"]:
            raise ValueError("D_DEV canary paired CWE failed validation")
        paired_differences = {
            outcome: int(target["values"][outcome]) - int(noop["values"][outcome])
            for outcome in _OUTCOMES
        }
        content: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "task_id": task_id,
            "cwe": str(target["cwe"]),
            "model_id": str(target["model_id"]),
            "arms": {
                ArmRole.TARGET_PATCH.value: target,
                ArmRole.NOOP_REWRITE.value: noop,
            },
            "paired_differences": paired_differences,
            "flip_diagnostics": {
                outcome: (
                    "improved" if difference > 0 else "harmed" if difference < 0 else "unchanged"
                )
                for outcome, difference in paired_differences.items()
            },
            "unknown_itt_value": 0,
            "role": "development_diagnostic_only",
            "functional_measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
            "functional_variable": _FUNCTIONAL_VARIABLE,
            "scientific_claim_allowed": False,
        }
        pairs.append({**content, "pair_id": "dev_pair_" + canonical_sha256(content)})

    scopes: list[tuple[str, str | None, list[dict[str, Any]]]] = [("overall", None, pairs)]
    scopes.extend(
        ("cwe", cwe, [pair for pair in pairs if pair["cwe"] == cwe])
        for cwe in sorted(_ALLOWED_CWES)
    )
    paired_summaries = [
        _summary_row(scope=scope, cwe=cwe, outcome=outcome, pairs=scoped_pairs)
        for scope, cwe, scoped_pairs in scopes
        for outcome in _OUTCOMES
    ]
    coverage_summaries: list[dict[str, object]] = []
    for scope, cwe, scoped_pairs in scopes:
        scoped_rows = [row for pair in scoped_pairs for row in pair["arms"].values()]
        content = {
            "schema_version": _SCHEMA_VERSION,
            "scope": scope,
            "cwe": cwe,
            **_coverage_summary(scoped_rows),
            "role": "coverage_diagnostic",
            "scientific_claim_allowed": False,
        }
        coverage_summaries.append(
            {**content, "coverage_id": "dev_coverage_" + canonical_sha256(content)}
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(output_dir / "task-pairs.jsonl", pairs)
    _write_jsonl(output_dir / "paired-summaries.jsonl", paired_summaries)
    _write_jsonl(output_dir / "coverage.jsonl", coverage_summaries)
    analysis_identity = {
        "schema_version": _SCHEMA_VERSION,
        "policy": _POLICY,
        "plan_manifest_sha256": plan_manifest_sha256,
        "final_live_root_manifest_sha256": sha256_file(live_root_manifest),
        "root_provenance_sha256": sha256_file(live_run_dir / "root-provenance.json"),
        "functional_evaluator_policy_sha256": evaluator_policy_sha256,
        "complete_run_report_sha256": sha256_file(complete_report_path),
        "unit_manifest_sha256s": dict(sorted(unit_manifest_sha256s.items())),
    }
    analysis_id = "dev_canary_analysis_" + canonical_sha256(analysis_identity)
    _write_json(
        output_dir / "provenance.json",
        {
            **analysis_identity,
            "analysis_id": analysis_id,
            "plan_directory": str(plan_dir),
            "live_run_directory": str(live_run_dir),
            "complete_run_report": complete_report_path.name,
            "live_config_sha256": sha256_file(live_run_dir / "live-config.json"),
            "input_provenance_sha256": sha256_file(live_run_dir / "input-provenance.json"),
            "post_randomization_rows_dropped": 0,
            "unknown_itt_value": 0,
            "measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
            "functional_variable": _FUNCTIONAL_VARIABLE,
            "functional_variable_semantics": _FUNCTIONAL_VARIABLE_SEMANTICS,
            "functional_evaluator_policy_sha256": evaluator_policy_sha256,
            "executable_functional_tests_performed": False,
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    counts_by_cwe = Counter(str(pair["cwe"]) for pair in pairs)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DEV_CANARY_PAIRED_SUMMARY_COMPLETE",
        "analysis_id": analysis_id,
        "analysis_policy": _POLICY,
        "analysis_role": "development_diagnostic_only",
        "measurement_method": _FUNCTIONAL_MEASUREMENT_METHOD,
        "functional_variable": _FUNCTIONAL_VARIABLE,
        "functional_variable_semantics": _FUNCTIONAL_VARIABLE_SEMANTICS,
        "functional_evaluator_policy_sha256": evaluator_policy_sha256,
        "executable_functional_tests_performed": False,
        "counts": {
            "tasks": len(pairs),
            "assignments": len(rows),
            "complete_units": len(rows),
            "by_cwe": dict(sorted(counts_by_cwe.items())),
            "by_arm": dict(sorted(Counter(str(row["arm_role"]) for row in rows).items())),
            "paired_summaries": len(paired_summaries),
            "coverage_summaries": len(coverage_summaries),
            "terminal_no_code": sum(
                int(bool(row["diagnostics"]["terminal_no_code"])) for row in rows
            ),
            "security_unknown": sum(
                int(row["diagnostics"]["security_label"] == "unknown") for row in rows
            ),
            "functional_unknown": sum(
                int(row["diagnostics"]["functional_status"] == "unknown") for row in rows
            ),
            "post_randomization_filtered": 0,
            "errors": 0,
            "pending": 0,
        },
        "unknown_handling": "assigned_unknown_outcomes_score_zero_in_development_itt",
        "coverage_reported_separately": True,
        "significance_testing_performed": False,
        "confidence_intervals_computed": False,
        "p_values_computed": False,
        "formal_claim_allowed": False,
        "scientific_claim_allowed": False,
        "source_plan_status": plan_report["status"],
        "source_live_status": complete_report["status"],
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["analyze_dev_canary"]

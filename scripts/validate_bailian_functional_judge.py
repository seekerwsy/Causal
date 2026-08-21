"""Run an immutable fixture or research-task canary against the Bailian judge."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
from collections import namedtuple
from datetime import UTC, datetime
from pathlib import Path

from secaware.artifact_io import write_closed_manifest_atomic
from secaware.config import FunctionalJudgeLLMConfig, GenerationConfig
from secaware.functional_judge.factory import _artifacts, _policy
from secaware.functional_judge.judge import (
    FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
    FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256,
    FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
    LLMFunctionalJudge,
    functional_judge_policy_sha256,
)
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalJudgePassRecord,
    FunctionalRequirementRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.llm.structured_transport import OpenAICompatibleStructuredTransport
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ExperimentalUnit,
    PromptVariantRecord,
)
from secaware.schema.generation import GenerationProvenance, provider_provenance_sha256

MODEL_ID = "qwen3.5-flash-2026-02-23"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
API_KEY_ENV = "ALI_BAILIAN_API_KEY"
PASS_SEEDS = (73_001, 73_002)
MAX_CALIBRATION_CASES = 24
_CANDIDATE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_EVALUATOR_CONFIG_KEYS = frozenset(
    {
        "api_key_env",
        "base_url",
        "candidate_id",
        "candidate_role",
        "enable_thinking",
        "max_attempts",
        "max_response_bytes",
        "mode",
        "model_id",
        "protocol_version",
        "provider",
        "schema_version",
        "seed",
        "temperature",
        "timeout_seconds",
        "top_p",
    }
)


_EvaluatorCoordinates = namedtuple(
    "_EvaluatorCoordinates",
    (
        "candidate_id candidate_role provider model_id base_url api_key_env "
        "timeout_seconds max_attempts max_response_bytes temperature top_p seed "
        "enable_thinking protocol_version mode source_sha256"
    ),
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _measurement_method(protocol_version: str) -> str:
    return {
        "v1": "ast_validated_single_shot_llm",
        "v2": "blind_static_llm_v2",
        "v3": "blind_static_llm_v3_requirement_aggregate",
    }[protocol_version]


def _write_json(path: Path, payload: object) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    path.write_text(encoded + "\n", encoding="utf-8")


def _write_jsonl(path: Path, payloads: tuple[dict[str, object], ...]) -> None:
    path.write_text(
        "".join(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for payload in payloads
        ),
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if type(payload) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _legacy_evaluator(mode: str) -> _EvaluatorCoordinates:
    return _EvaluatorCoordinates(
        candidate_id="legacy-qwen35flash-v1",
        candidate_role="legacy",
        provider="ali_bailian_pay_as_you_go",
        model_id=MODEL_ID,
        base_url=BASE_URL,
        api_key_env=API_KEY_ENV,
        timeout_seconds=60.0,
        max_attempts=3,
        max_response_bytes=65_536,
        temperature=0.0,
        top_p=1.0,
        seed=PASS_SEEDS[0],
        enable_thinking=False,
        protocol_version="v1",
        mode=mode,
        source_sha256=None,
    )


def _load_evaluator_config(path: Path) -> _EvaluatorCoordinates:
    resolved = path.resolve()
    payload = _read_json(resolved)
    if frozenset(payload) != _EVALUATOR_CONFIG_KEYS:
        raise SystemExit("evaluator config schema is invalid")

    candidate_id = payload["candidate_id"]
    candidate_role = payload["candidate_role"]
    provider = payload["provider"]
    model_id = payload["model_id"]
    base_url = payload["base_url"]
    api_key_env = payload["api_key_env"]
    timeout_seconds = payload["timeout_seconds"]
    max_attempts = payload["max_attempts"]
    max_response_bytes = payload["max_response_bytes"]
    temperature = payload["temperature"]
    top_p = payload["top_p"]
    seed = payload["seed"]
    enable_thinking = payload["enable_thinking"]
    protocol_version = payload["protocol_version"]
    mode = payload["mode"]
    if (
        payload["schema_version"] != "1.0"
        or type(candidate_id) is not str
        or _CANDIDATE_ID.fullmatch(candidate_id) is None
        or type(provider) is not str
        or provider not in {"ali_bailian_pay_as_you_go", "openai_compatible"}
        or candidate_role not in {"baseline", "new_candidate"}
        or type(model_id) is not str
        or not model_id.strip()
        or len(model_id) > 256
        or type(base_url) is not str
        or not base_url.startswith("https://")
        or len(base_url) > 2048
        or type(api_key_env) is not str
        or _ENV_NAME.fullmatch(api_key_env) is None
        or type(timeout_seconds) not in {int, float}
        or not 1.0 <= float(timeout_seconds) <= 600.0
        or type(max_attempts) is not int
        or max_attempts != 1
        or type(max_response_bytes) is not int
        or not 1_024 <= max_response_bytes <= 1_048_576
        or type(temperature) not in {int, float}
        or float(temperature) != 0.0
        or type(top_p) not in {int, float}
        or float(top_p) != 1.0
        or type(seed) is not int
        or not 0 <= seed <= 2_147_483_647
        or type(enable_thinking) is not bool
        or protocol_version not in {"v1", "v2", "v3"}
        or mode != "single_pass"
    ):
        raise SystemExit("evaluator config failed validation")
    return _EvaluatorCoordinates(
        candidate_id=candidate_id,
        candidate_role=candidate_role,
        provider=provider,
        model_id=model_id,
        base_url=base_url,
        api_key_env=api_key_env,
        timeout_seconds=float(timeout_seconds),
        max_attempts=max_attempts,
        max_response_bytes=max_response_bytes,
        temperature=float(temperature),
        top_p=float(top_p),
        seed=seed,
        enable_thinking=enable_thinking,
        protocol_version=protocol_version,
        mode=mode,
        source_sha256=_file_sha256(resolved),
    )


def _seal_output_dir(output_dir: Path) -> dict[str, object]:
    return write_closed_manifest_atomic(output_dir, label="functional judge canary")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        if type(payload) is not dict:
            raise ValueError(f"expected JSON objects: {path}")
        payloads.append(payload)
    return payloads


def _included_trace_attempts(output_dir: Path) -> int:
    trace_path = output_dir / "llm_exchange_trace.jsonl"
    return len(_read_jsonl(trace_path)) if trace_path.exists() else 0


def _attempt_accounting(output_dir: Path) -> dict[str, object]:
    attempts = _included_trace_attempts(output_dir)
    return {
        "provider_attempts": attempts,
        "provider_attempt_scope": "included_closed_run_trace_records",
        "new_calls": {
            "functional_judge_provider_attempts": attempts,
            "generation_provider_attempts": 0,
            "oracle_executions": 0,
        },
    }


def _append_jsonl(path: Path, payload: dict[str, object]) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded + "\n")


def _package_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _sanitized_failure(
    exc: Exception,
    *,
    api_key_env: str = API_KEY_ENV,
) -> dict[str, object]:
    message = str(exc)
    secret = os.environ.get(api_key_env, "")
    if secret:
        message = message.replace(secret, "<redacted>")
    return {
        "exception_type": type(exc).__name__,
        "error_code": getattr(exc, "code", None),
        "error_stage": getattr(exc, "stage", None),
        "retryable": getattr(exc, "retryable", None),
        "message": message[:2_000],
    }


class _RecordingTransport:
    """Persist validation-only request/response evidence around the locked transport."""

    def __init__(
        self,
        delegate: object,
        trace_path: Path,
        api_key_env: str = API_KEY_ENV,
        evaluator_policy_sha256: str | None = None,
    ) -> None:
        self._delegate = delegate
        self._trace_path = trace_path
        self._api_key_env = api_key_env
        self._evaluator_policy_sha256 = evaluator_policy_sha256
        self._call_index = 0

    def complete(self, request_bytes: bytes, policy: object) -> bytes:
        self._call_index += 1
        request_payload = json.loads(request_bytes.decode("utf-8"))
        try:
            response_bytes = self._delegate.complete(request_bytes, policy)
        except Exception as exc:
            _append_jsonl(
                self._trace_path,
                {
                    "at_utc": _utc_now(),
                    "call_index": self._call_index,
                    "request": request_payload,
                    "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    "evaluator_policy_sha256": self._evaluator_policy_sha256,
                    "response_status": "transport_error",
                    "failure": _sanitized_failure(exc, api_key_env=self._api_key_env),
                },
            )
            raise
        _append_jsonl(
            self._trace_path,
            {
                "at_utc": _utc_now(),
                "call_index": self._call_index,
                "request": request_payload,
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "evaluator_policy_sha256": self._evaluator_policy_sha256,
                "response_status": "received",
                "response_text": response_bytes.decode("utf-8", errors="replace"),
                "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
            },
        )
        return response_bytes


def _contract(task_id: str) -> TaskFunctionalContractRecord:
    prompt = "Implement answer() so it returns the integer 42."
    requirement = FunctionalRequirementRecord(
        requirement_id="req_return_42",
        kind="behavior",
        criterion="The program defines answer() and answer() returns the integer 42.",
        prompt_evidence_quote="answer() so it returns the integer 42",
    )
    return TaskFunctionalContractRecord.from_content(
        task_id=task_id,
        source_prompt_id="prompt-" + task_id,
        source_prompt_sha256=_sha(prompt),
        language="python",
        judgeability=FunctionalJudgeability.SEMANTIC_ONLY,
        requirements=(requirement,),
        environment_dependencies=(),
        audit_pass_ids=("A", "B"),
        audit_status=FunctionalAuditStatus.CONSISTENT,
        auditor_kind="CODEX",
        audit_evidence_sha256=_sha(task_id + "-contract-audit"),
    )


def _assignment_and_variant(
    task_id: str, seed_id: int
) -> tuple[AssignmentRecord, PromptVariantRecord]:
    hypothesis_id = "hypothesis_" + "1" * 64
    target_spec_id = "target_" + "2" * 64
    target_instance_id = "target_instance_" + _sha(task_id)
    protocol_id = "arm_protocol_" + "3" * 64
    protocol_instance_id = "protocol_instance_" + _sha(task_id + "-protocol")
    prompt = "Implement answer() so it returns the integer 42."
    variant = PromptVariantRecord.from_content(
        task_id=task_id,
        source_prompt_id="prompt-" + task_id,
        language="python",
        variant_prompt_id="variant_prompt_" + _sha(task_id),
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        arm_role=ArmRole.TARGET_PATCH,
        prompt_sha256=_sha(prompt),
        prompt_text=prompt,
        proposal_id="proposal_" + _sha(task_id + "-proposal"),
        graph_id="graph_" + _sha(task_id + "-graph"),
        delta_id="delta_" + _sha(task_id + "-delta"),
        executor_policy_sha256="4" * 64,
        extractor_policy_sha256="5" * 64,
        length_match_id=None,
    )
    unit = ExperimentalUnit(
        task_id=task_id,
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        model_id="canary-code-fixture-v1",
        seed_slot=0,
    )
    assignment = AssignmentRecord.from_content(
        block_id=AssignmentRecord.block_id_from_key(
            task_id,
            hypothesis_id,
            target_spec_id,
            protocol_id,
            unit.model_id,
        ),
        experimental_unit=unit,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        variant_id=variant.variant_id,
        arm_role=ArmRole.TARGET_PATCH,
        seed_id=seed_id,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="6" * 64,
    )
    return assignment, variant


def _code_input(
    task_id: str,
    seed_id: int,
    code_text: str,
    contract: TaskFunctionalContractRecord | None = None,
):
    assignment, variant = _assignment_and_variant(task_id, seed_id)
    generation = GenerationConfig(
        provider="mock",
        models=[assignment.experimental_unit.model_id],
        seeds=[1],
        confirmation_seeds=[seed_id],
    )
    request = plan_confirmation_requests((assignment,), (variant,), generation)[0]
    provenance = GenerationProvenance(producer="bailian-functional-judge-canary-fixture")
    code = canonical_generated_code_from_request(
        request,
        code_text,
        provenance,
        provider_result_sha256=_sha(task_id + "-result"),
        provider_usage_sha256=_sha(task_id + "-usage"),
        provider_runtime_sha256=_sha(task_id + "-runtime"),
        provider_policy_sha256=_sha(task_id + "-policy"),
        provider_attempt_count=1,
    )
    execution = AssignmentExecutionRecord.from_content(
        assignment_id=assignment.assignment_id,
        request_id=code.request_id,
        status=AssignmentExecutionStatus.GENERATED,
        provider_result_sha256=code.provider_result_sha256,
        provider_provenance_sha256=provider_provenance_sha256(provenance),
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        usage_sha256=code.provider_usage_sha256,
        attempt_count=code.provider_attempt_count,
        code_id=code.code_id,
        code_sha256=code.code_sha256,
        terminal_reason=None,
    )
    return assignment, execution, code, contract or _contract(task_id)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--mode",
        choices=("single_pass", "two_pass_consensus"),
        default=None,
    )
    parser.add_argument("--cases-path", type=Path)
    parser.add_argument("--contracts-path", type=Path)
    parser.add_argument("--evaluator-config", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--finalize-existing", action="store_true")
    return parser.parse_args()


def _load_cases(
    cases_path: Path | None,
    contracts_path: Path | None,
) -> tuple[tuple[str, int, str, str, TaskFunctionalContractRecord], ...]:
    if cases_path is None and contracts_path is None:
        return (
            (
                "canary-functional-pass",
                91_001,
                "def answer():\n    return 42\n",
                "pass",
                _contract("canary-functional-pass"),
            ),
            (
                "canary-functional-fail",
                91_002,
                "def answer():\n    return 7\n",
                "fail",
                _contract("canary-functional-fail"),
            ),
        )
    if cases_path is None or contracts_path is None:
        raise SystemExit("--cases-path and --contracts-path must be supplied together")
    case_payloads = _read_jsonl(cases_path.resolve())
    contract_payloads = _read_jsonl(contracts_path.resolve())
    contracts = [TaskFunctionalContractRecord.model_validate(item) for item in contract_payloads]
    contract_by_task = {item.task_id: item for item in contracts}
    if len(contract_by_task) != len(contracts):
        raise SystemExit("duplicate task functional contract")
    loaded: list[tuple[str, int, str, str, TaskFunctionalContractRecord]] = []
    seen: set[str] = set()
    for item in case_payloads:
        if set(item) != {"case_id", "task_id", "seed_id", "code_text", "expected_status"}:
            raise SystemExit("research canary case schema is invalid")
        case_id = item["case_id"]
        task_id = item["task_id"]
        seed_id = item["seed_id"]
        code_text = item["code_text"]
        expected_status = item["expected_status"]
        contract = contract_by_task.get(task_id) if type(task_id) is str else None
        if (
            type(case_id) is not str
            or not case_id
            or case_id in seen
            or type(seed_id) is not int
            or type(code_text) is not str
            or not code_text.strip()
            or expected_status not in {"pass", "fail", "unknown"}
            or contract is None
        ):
            raise SystemExit("research canary case failed validation")
        seen.add(case_id)
        loaded.append((case_id, seed_id, code_text, expected_status, contract))
    if not loaded:
        raise SystemExit("research canary cases are empty")
    return tuple(loaded)


def _validate_calibration_cases(
    cases: tuple[tuple[str, int, str, str, TaskFunctionalContractRecord], ...],
) -> None:
    if len(cases) > MAX_CALIBRATION_CASES:
        raise SystemExit("calibration case budget exceeded")
    coordinates: set[tuple[str, int]] = set()
    for _case_id, seed_id, code_text, expected, contract in cases:
        coordinate = (contract.task_id, seed_id)
        try:
            parsed = ast.parse(code_text)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            raise SystemExit("calibration cases must contain AST-valid Python") from None
        if (
            expected not in {"pass", "fail"}
            or contract.language.casefold() != "python"
            or contract.judgeability is FunctionalJudgeability.UNJUDGEABLE
            or not parsed.body
            or coordinate in coordinates
        ):
            raise SystemExit("calibration case contract failed validation")
        coordinates.add(coordinate)


def _planned_evaluations(
    cases: tuple[tuple[str, int, str, str, TaskFunctionalContractRecord], ...],
) -> list[dict[str, object]]:
    planned: list[dict[str, object]] = []
    for case_id, seed_id, code_text, expected, contract in cases:
        assignment, _variant = _assignment_and_variant(contract.task_id, seed_id)
        planned.append(
            {
                "case_id": case_id,
                "task_id": contract.task_id,
                "assignment_id": assignment.assignment_id,
                "contract_id": contract.contract_id,
                "code_sha256": _sha(code_text),
                "expected_status": expected,
            }
        )
    return planned


def _artifact_sha256s(
    config_payload: dict[str, object],
    environment_payload: dict[str, object],
    case_inputs: list[dict[str, object]],
    pass_payloads: list[dict[str, object]],
    outcome_payloads: list[dict[str, object]],
) -> dict[str, str]:
    return {
        "config": canonical_sha256(config_payload),
        "environment": canonical_sha256(environment_payload),
        "cases": canonical_sha256(case_inputs),
        "passes": canonical_sha256(pass_payloads),
        "outcomes": canonical_sha256(outcome_payloads),
    }


def _finalize_existing(output_dir: Path) -> int:
    report_path = output_dir / "report.json"
    if not output_dir.is_dir():
        raise SystemExit("existing canary run directory is unavailable")
    if report_path.exists():
        raise SystemExit("refusing to overwrite an existing canary report")

    config_payload = _read_json(output_dir / "config.json")
    environment_payload = _read_json(output_dir / "environment.json")
    case_inputs = _read_jsonl(output_dir / "canary_cases.jsonl")
    pass_payloads = _read_jsonl(output_dir / "functional_judge_passes.jsonl")
    outcome_payloads = _read_jsonl(output_dir / "program_functional_outcomes.jsonl")
    events = _read_jsonl(output_dir / "events.jsonl")
    traces = _read_jsonl(output_dir / "llm_exchange_trace.jsonl")
    passes = [FunctionalJudgePassRecord.model_validate(item) for item in pass_payloads]
    outcomes = [ProgramFunctionalOutcomeRecord.model_validate(item) for item in outcome_payloads]

    if len(case_inputs) != 2 or len(passes) != 4 or len(outcomes) != 2 or len(traces) != 4:
        raise SystemExit("existing canary artifact cardinality is invalid")
    evaluator_policy_sha256 = config_payload.get("evaluator_policy_sha256")
    if type(evaluator_policy_sha256) is not str:
        raise SystemExit("existing canary evaluator policy is unavailable")
    if any(item.evaluator_policy_sha256 != evaluator_policy_sha256 for item in passes):
        raise SystemExit("existing canary pass policy provenance is inconsistent")
    if any(item.evaluator_policy_sha256 != evaluator_policy_sha256 for item in outcomes):
        raise SystemExit("existing canary outcome policy provenance is inconsistent")

    trace_coordinates = {
        (item.get("request_sha256"), item.get("response_sha256")) for item in traces
    }
    pass_coordinates = {(item.request_sha256, item.response_sha256) for item in passes}
    if trace_coordinates != pass_coordinates or any(
        item.get("response_status") != "received" for item in traces
    ):
        raise SystemExit("existing canary exchange provenance is inconsistent")

    outcome_by_assignment = {item.assignment_id: item for item in outcomes}
    if len(outcome_by_assignment) != 2:
        raise SystemExit("existing canary outcome assignment coverage is invalid")
    case_results: list[dict[str, object]] = []
    for case in case_inputs:
        task_id = case.get("task_id")
        seed_id = case.get("seed_id")
        expected = case.get("expected_status")
        if type(task_id) is not str or type(seed_id) is not int or type(expected) is not str:
            raise SystemExit("existing canary case coordinates are invalid")
        assignment, _variant = _assignment_and_variant(task_id, seed_id)
        outcome = outcome_by_assignment.get(assignment.assignment_id)
        assignment_passes = [
            item for item in passes if item.assignment_id == assignment.assignment_id
        ]
        if outcome is None or {item.pass_id for item in assignment_passes} != {"A", "B"}:
            raise SystemExit("existing canary pass coverage is invalid")
        pass_statuses = [
            item.status.value for item in sorted(assignment_passes, key=lambda x: x.pass_id)
        ]
        consistent = len(set(pass_statuses)) == 1 and pass_statuses[0] == outcome.status.value
        case_results.append(
            {
                "task_id": task_id,
                "expected_status": expected,
                "actual_status": outcome.status.value,
                "pass_statuses": pass_statuses,
                "consistent": consistent,
            }
        )

    completed_events = [item for item in events if item.get("event") == "case_completed"]
    final_events = [item for item in events if item.get("event") == "canary_completed"]
    success = all(
        item["expected_status"] == item["actual_status"] and item["consistent"]
        for item in case_results
    )
    if len(completed_events) != 2 or len(final_events) != 1 or not success:
        raise SystemExit("existing canary terminal evidence is invalid")
    if final_events[0].get("status") != "PASS":
        raise SystemExit("existing canary terminal status is invalid")

    _append_jsonl(
        output_dir / "commands.jsonl",
        {
            "started_at_utc": _utc_now(),
            "working_directory": str(Path.cwd().resolve()),
            "argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
            "secret_in_argv": False,
            "recovery_only": True,
        },
    )
    _write_json(
        report_path,
        {
            "schema_version": "1.0",
            "status": "PASS",
            "started_at_utc": events[0]["at_utc"],
            "completed_at_utc": final_events[0]["at_utc"],
            "completed_case_count": len(case_results),
            "total_case_count": len(case_inputs),
            "case_results": case_results,
            "artifact_sha256": _artifact_sha256s(
                config_payload,
                environment_payload,
                case_inputs,
                pass_payloads,
                outcome_payloads,
            ),
            "recovered_from_persisted_artifacts": True,
            "recovered_at_utc": _utc_now(),
        },
    )
    return 0


def main() -> int:
    args = _parse_args()
    started_at_utc = _utc_now()
    output_dir = args.output_dir.resolve()
    if args.finalize_existing:
        if args.preflight or args.evaluator_config is not None:
            raise SystemExit("historical recovery does not accept calibration options")
        if (args.mode or "two_pass_consensus") != "two_pass_consensus":
            raise SystemExit("single-pass recovery is not supported by the historical finalizer")
        return _finalize_existing(output_dir)
    if args.preflight and args.evaluator_config is None:
        raise SystemExit("--preflight requires --evaluator-config")

    mode = args.mode or "two_pass_consensus"
    evaluator = (
        _load_evaluator_config(args.evaluator_config)
        if args.evaluator_config is not None
        else _legacy_evaluator(mode)
    )
    if args.evaluator_config is not None:
        if args.mode is not None and args.mode != evaluator.mode:
            raise SystemExit("CLI mode conflicts with evaluator config")
        mode = evaluator.mode

    cases = _load_cases(args.cases_path, args.contracts_path)
    if args.evaluator_config is not None:
        _validate_calibration_cases(cases)
    if output_dir.exists():
        raise SystemExit("refusing to overwrite an existing canary run")

    llm = FunctionalJudgeLLMConfig(
        model_id=evaluator.model_id,
        base_url=evaluator.base_url,
        api_key_env=evaluator.api_key_env,
        timeout_seconds=evaluator.timeout_seconds,
        max_attempts=evaluator.max_attempts,
        max_response_bytes=evaluator.max_response_bytes,
        temperature=evaluator.temperature,
        top_p=evaluator.top_p,
        seed=None,
        enable_thinking=evaluator.enable_thinking,
    )
    system_template, system_template_sha256, output_schema_sha256 = _artifacts(
        evaluator.protocol_version
    )
    pass_a_policy = _policy(
        llm,
        evaluator.seed,
        protocol_version=evaluator.protocol_version,
    )
    pass_b_policy = (
        _policy(llm, PASS_SEEDS[1], protocol_version=evaluator.protocol_version)
        if mode == "two_pass_consensus"
        else None
    )
    evaluator_policy_sha256 = functional_judge_policy_sha256(
        pass_a_policy,
        pass_b_policy,
        mode=mode,
        protocol_version=evaluator.protocol_version,
    )
    config_payload = {
        "schema_version": "1.0",
        "candidate_id": evaluator.candidate_id,
        "candidate_role": evaluator.candidate_role,
        "provider": evaluator.provider,
        "region": "cn-beijing",
        "model_id": evaluator.model_id,
        "base_url": evaluator.base_url,
        "endpoint_sha256": _sha(evaluator.base_url),
        "api_key_env": evaluator.api_key_env,
        "timeout_seconds": evaluator.timeout_seconds,
        "max_attempts": evaluator.max_attempts,
        "max_response_bytes": evaluator.max_response_bytes,
        "temperature": evaluator.temperature,
        "top_p": evaluator.top_p,
        "judge_mode": mode,
        "pass_seeds": [
            evaluator.seed,
            *([PASS_SEEDS[1]] if pass_b_policy is not None else []),
        ],
        "enable_thinking": evaluator.enable_thinking,
        "protocol_version": evaluator.protocol_version,
        "measurement_method": _measurement_method(evaluator.protocol_version),
        "execution_performed": False,
        "system_template_sha256": system_template_sha256,
        "output_schema_sha256": output_schema_sha256,
        "response_format": {"type": "json_object"},
        "evaluator_policy_sha256": evaluator_policy_sha256,
        "evaluator_config_sha256": evaluator.source_sha256,
        "provider_usage_capture": "unavailable_in_structured_transport_v1",
        "validation_only_raw_exchange_capture": True,
    }
    if evaluator.protocol_version == "v3":
        config_payload.update(
            {
                "aggregate_status_rule": FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE,
                "aggregate_status_rule_sha256": (FUNCTIONAL_JUDGE_V3_AGGREGATE_RULE_SHA256),
                "top_level_status_role": FUNCTIONAL_JUDGE_V3_TOP_LEVEL_STATUS_ROLE,
            }
        )
    environment_payload = {
        "schema_version": "1.0",
        "captured_at_utc": started_at_utc,
        "working_directory": str(Path.cwd().resolve()),
        "output_directory": str(output_dir),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "package_versions": {
            "openai": _package_version("openai"),
            "pydantic": _package_version("pydantic"),
            "secaware": _package_version("secaware"),
        },
        "credential": {
            "environment_variable": evaluator.api_key_env,
            "present": bool(os.environ.get(evaluator.api_key_env, "").strip()),
            "value_recorded": False,
        },
    }
    case_inputs = [
        {
            "case_id": case_id,
            "task_id": contract.task_id,
            "seed_id": seed_id,
            "code_text": code_text,
            "expected_status": expected,
            "contract": contract.model_dump(mode="json"),
        }
        for case_id, seed_id, code_text, expected, contract in cases
    ]
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "config.json", config_payload)
    _write_json(output_dir / "environment.json", environment_payload)
    _write_jsonl(output_dir / "canary_cases.jsonl", tuple(case_inputs))
    _write_jsonl(
        output_dir / "commands.jsonl",
        (
            {
                "started_at_utc": started_at_utc,
                "working_directory": str(Path.cwd().resolve()),
                "argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "secret_in_argv": False,
            },
        ),
    )
    events_path = output_dir / "events.jsonl"
    _append_jsonl(
        events_path,
        {
            "at_utc": _utc_now(),
            "event": "preflight_started" if args.preflight else "canary_started",
            "case_count": len(cases),
        },
    )
    credential_present = bool(os.environ.get(evaluator.api_key_env, "").strip())
    if args.preflight:
        planned = _planned_evaluations(cases)
        _write_jsonl(output_dir / "planned-evaluations.jsonl", tuple(planned))
        _append_jsonl(
            events_path,
            {
                "at_utc": _utc_now(),
                "event": "preflight_completed",
                "status": "FUNCTIONAL_JUDGE_PREFLIGHT_COMPLETE",
                "provider_attempts": 0,
                "live_ready": credential_present,
            },
        )
        _write_json(
            output_dir / "report.json",
            {
                "schema_version": "1.0",
                "status": "FUNCTIONAL_JUDGE_PREFLIGHT_COMPLETE",
                "started_at_utc": started_at_utc,
                "completed_at_utc": _utc_now(),
                "validated_case_count": len(cases),
                "candidate_id": evaluator.candidate_id,
                "evaluator_policy_sha256": evaluator_policy_sha256,
                "protocol_version": evaluator.protocol_version,
                "measurement_method": _measurement_method(evaluator.protocol_version),
                "execution_performed": False,
                "credential_present": credential_present,
                "live_ready": credential_present,
                "provider_attempts": 0,
                "provider_attempt_scope": "included_closed_run_trace_records",
                "new_calls": {
                    "functional_judge_provider_attempts": 0,
                    "generation_provider_attempts": 0,
                    "oracle_executions": 0,
                },
                "planned_evaluations_sha256": canonical_sha256(planned),
            },
        )
        _seal_output_dir(output_dir)
        return 0

    if not credential_present:
        failure = {
            "exception_type": "MissingCredential",
            "error_code": "MISSING_API_KEY_ENV",
            "error_stage": "preflight",
            "retryable": False,
            "message": f"{evaluator.api_key_env} is unavailable",
        }
        _append_jsonl(
            events_path,
            {"at_utc": _utc_now(), "event": "canary_failed", "failure": failure},
        )
        _write_json(
            output_dir / "report.json",
            {
                "schema_version": "1.0",
                "status": "ERROR",
                "started_at_utc": started_at_utc,
                "completed_at_utc": _utc_now(),
                "completed_case_count": 0,
                "total_case_count": len(cases),
                **_attempt_accounting(output_dir),
                "failure": failure,
            },
        )
        if args.evaluator_config is not None:
            _seal_output_dir(output_dir)
        return 2

    try:
        transport = OpenAICompatibleStructuredTransport(
            base_url=llm.base_url,
            api_key_env=llm.api_key_env,
            system_template=system_template,
        )
        judge = LLMFunctionalJudge(
            _RecordingTransport(
                transport,
                output_dir / "llm_exchange_trace.jsonl",
                evaluator.api_key_env,
                evaluator_policy_sha256,
            ),
            pass_a_policy,
            pass_b_policy,
            mode=mode,
            protocol_version=evaluator.protocol_version,
        )
    except Exception as exc:  # noqa: BLE001 - boundary must persist provider failure
        failure = _sanitized_failure(exc, api_key_env=evaluator.api_key_env)
        _append_jsonl(
            events_path,
            {"at_utc": _utc_now(), "event": "canary_failed", "failure": failure},
        )
        _write_json(
            output_dir / "report.json",
            {
                "schema_version": "1.0",
                "status": "ERROR",
                "started_at_utc": started_at_utc,
                "completed_at_utc": _utc_now(),
                "completed_case_count": 0,
                "total_case_count": len(cases),
                **_attempt_accounting(output_dir),
                "failure": failure,
            },
        )
        if args.evaluator_config is not None:
            _seal_output_dir(output_dir)
        return 2
    pass_payloads: list[dict[str, object]] = []
    outcome_payloads: list[dict[str, object]] = []
    case_results: list[dict[str, object]] = []
    try:
        for case_id, seed_id, code_text, expected, contract in cases:
            assignment, execution, code, contract = _code_input(
                contract.task_id,
                seed_id,
                code_text,
                contract,
            )
            passes, outcome = judge.evaluate(assignment, execution, code, contract)
            pass_payloads.extend(item.model_dump(mode="json") for item in passes)
            outcome_payloads.append(outcome.model_dump(mode="json"))
            case_result = {
                "case_id": case_id,
                "task_id": contract.task_id,
                "assignment_id": assignment.assignment_id,
                "contract_id": contract.contract_id,
                "expected_status": expected,
                "actual_status": outcome.status.value,
                "pass_statuses": [item.status.value for item in passes],
                "consistent": (
                    len(passes) == 1
                    if mode == "single_pass"
                    else len(passes) == 2 and passes[0].status is passes[1].status
                ),
            }
            case_results.append(case_result)
            _append_jsonl(
                events_path,
                {
                    "at_utc": _utc_now(),
                    "event": "case_completed",
                    **case_result,
                },
            )
    except Exception as exc:  # noqa: BLE001 - boundary must persist provider failure
        failure = _sanitized_failure(exc, api_key_env=evaluator.api_key_env)
        _append_jsonl(
            events_path,
            {"at_utc": _utc_now(), "event": "canary_failed", "failure": failure},
        )
        if pass_payloads:
            _write_jsonl(
                output_dir / "functional_judge_passes.partial.jsonl",
                tuple(pass_payloads),
            )
        if outcome_payloads:
            _write_jsonl(
                output_dir / "program_functional_outcomes.partial.jsonl",
                tuple(outcome_payloads),
            )
        _write_json(
            output_dir / "report.json",
            {
                "schema_version": "1.0",
                "status": "ERROR",
                "started_at_utc": started_at_utc,
                "completed_at_utc": _utc_now(),
                "completed_case_count": len(case_results),
                "total_case_count": len(cases),
                "case_results": case_results,
                **_attempt_accounting(output_dir),
                "failure": failure,
            },
        )
        if args.evaluator_config is not None:
            _seal_output_dir(output_dir)
        return 2

    success = all(
        item["expected_status"] == item["actual_status"] and item["consistent"]
        for item in case_results
    )
    _write_jsonl(output_dir / "functional_judge_passes.jsonl", tuple(pass_payloads))
    _write_jsonl(output_dir / "program_functional_outcomes.jsonl", tuple(outcome_payloads))
    _append_jsonl(
        events_path,
        {
            "at_utc": _utc_now(),
            "event": "canary_completed",
            "status": "PASS" if success else "FAIL",
        },
    )
    _write_json(
        output_dir / "report.json",
        {
            "schema_version": "1.0",
            "status": "PASS" if success else "FAIL",
            "started_at_utc": started_at_utc,
            "completed_at_utc": _utc_now(),
            "completed_case_count": len(case_results),
            "total_case_count": len(cases),
            "case_results": case_results,
            "candidate_id": evaluator.candidate_id,
            "protocol_version": evaluator.protocol_version,
            "measurement_method": judge.measurement_method,
            "execution_performed": judge.execution_performed,
            **_attempt_accounting(output_dir),
            "artifact_sha256": _artifact_sha256s(
                config_payload,
                environment_payload,
                case_inputs,
                pass_payloads,
                outcome_payloads,
            ),
        },
    )
    if args.evaluator_config is not None:
        _seal_output_dir(output_dir)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())

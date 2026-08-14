"""Run an immutable fixture or research-task canary against the Bailian judge."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from secaware.config import FunctionalJudgeLLMConfig, GenerationConfig
from secaware.functional_judge.factory import _policy
from secaware.functional_judge.judge import (
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE,
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


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        if type(payload) is not dict:
            raise ValueError(f"expected JSON objects: {path}")
        payloads.append(payload)
    return payloads


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


def _sanitized_failure(exc: Exception) -> dict[str, object]:
    message = str(exc)
    secret = os.environ.get(API_KEY_ENV, "")
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

    def __init__(self, delegate: object, trace_path: Path) -> None:
        self._delegate = delegate
        self._trace_path = trace_path
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
                    "response_status": "transport_error",
                    "failure": _sanitized_failure(exc),
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
        default="two_pass_consensus",
    )
    parser.add_argument("--cases-path", type=Path)
    parser.add_argument("--contracts-path", type=Path)
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
        if args.mode != "two_pass_consensus":
            raise SystemExit("single-pass recovery is not supported by the historical finalizer")
        return _finalize_existing(output_dir)
    if output_dir.exists():
        raise SystemExit("refusing to overwrite an existing canary run")
    output_dir.mkdir(parents=True, exist_ok=False)

    llm = FunctionalJudgeLLMConfig(
        model_id=MODEL_ID,
        base_url=BASE_URL,
        api_key_env=API_KEY_ENV,
        timeout_seconds=60.0,
        max_attempts=3,
        max_response_bytes=65_536,
        temperature=0.0,
        top_p=1.0,
        seed=None,
        enable_thinking=False,
    )
    pass_a_policy = _policy(llm, PASS_SEEDS[0])
    pass_b_policy = (
        _policy(llm, PASS_SEEDS[1]) if args.mode == "two_pass_consensus" else None
    )
    evaluator_policy_sha256 = functional_judge_policy_sha256(
        pass_a_policy,
        pass_b_policy,
        mode=args.mode,
    )
    config_payload = {
        "schema_version": "1.0",
        "provider": "ali_bailian_pay_as_you_go",
        "region": "cn-beijing",
        "model_id": MODEL_ID,
        "base_url": BASE_URL,
        "endpoint_sha256": _sha(BASE_URL),
        "api_key_env": API_KEY_ENV,
        "temperature": 0.0,
        "top_p": 1.0,
        "judge_mode": args.mode,
        "pass_seeds": list(PASS_SEEDS if pass_b_policy is not None else PASS_SEEDS[:1]),
        "enable_thinking": False,
        "response_format": {"type": "json_object"},
        "evaluator_policy_sha256": evaluator_policy_sha256,
        "provider_usage_capture": "unavailable_in_structured_transport_v1",
        "validation_only_raw_exchange_capture": True,
    }
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
            "environment_variable": API_KEY_ENV,
            "present": bool(os.environ.get(API_KEY_ENV, "").strip()),
            "value_recorded": False,
        },
    }
    cases = _load_cases(args.cases_path, args.contracts_path)
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
            "event": "canary_started",
            "case_count": len(cases),
        },
    )
    if not os.environ.get(API_KEY_ENV, "").strip():
        failure = {
            "exception_type": "MissingCredential",
            "error_code": "MISSING_API_KEY_ENV",
            "error_stage": "preflight",
            "retryable": False,
            "message": f"{API_KEY_ENV} is unavailable",
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
                "failure": failure,
            },
        )
        return 2

    try:
        transport = OpenAICompatibleStructuredTransport(
            base_url=llm.base_url,
            api_key_env=llm.api_key_env,
            system_template=FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE,
        )
        judge = LLMFunctionalJudge(
            _RecordingTransport(transport, output_dir / "llm_exchange_trace.jsonl"),
            pass_a_policy,
            pass_b_policy,
            mode=args.mode,
        )
    except Exception as exc:  # noqa: BLE001 - boundary must persist provider failure
        failure = _sanitized_failure(exc)
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
                "failure": failure,
            },
        )
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
                "expected_status": expected,
                "actual_status": outcome.status.value,
                "pass_statuses": [item.status.value for item in passes],
                "consistent": (
                    len(passes) == 1
                    if args.mode == "single_pass"
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
        failure = _sanitized_failure(exc)
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
                "failure": failure,
            },
        )
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
            "artifact_sha256": _artifact_sha256s(
                config_payload,
                environment_payload,
                case_inputs,
                pass_payloads,
                outcome_payloads,
            ),
        },
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())

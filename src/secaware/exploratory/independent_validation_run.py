"""Recorded pilot execution for the frozen independent validation experiment."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
import time
import traceback
from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.exploratory.code_mechanism_calibration import (
    code_mechanism_policy_from_config,
)
from secaware.exploratory.code_mechanism_facts import (
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    LLMCodeMechanismFactsExtractor,
)
from secaware.exploratory.gate_c_live import (
    RecordingGenerationTransport,
    RecordingStructuredTransport,
    _invalid_judge_unknown_outcome,
)
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.generation.confirmation import execute_confirmation_requests
from secaware.generation.openai_compatible_provider import (
    openai_provider_runtime_fingerprint,
)
from secaware.generation.source_extraction import (
    SOURCE_EXTRACTION_POLICY_SHA256,
    extract_generated_source,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import sha256_file
from secaware.pipeline.stages.confirmation_generation import create_confirmation_provider
from secaware.schema.experiments import AssignmentExecutionStatus, AssignmentRecord
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_MECHANISM_POLICY_SHA256 = "01d279a56c64fc42aa54fd96611eec2fa7db54f5198ce3680d37388d89d1e7ac"


def _canonical(value: object) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", warnings=False)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("independent validation run JSON failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _append_jsonl(path: Path, value: object) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(_canonical(value).decode("utf-8") + "\n")
        handle.flush()


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _input_path(repo_root: Path, value: object) -> Path:
    if type(value) is not dict or set(value) not in (
        {"path", "sha256"},
        {"path", "sha256", "digest_mode"},
    ):
        raise ValueError("independent validation run input failed validation")
    relative = value.get("path")
    digest = value.get("sha256")
    digest_mode = value.get("digest_mode", "raw_bytes_v1")
    if (
        type(relative) is not str
        or type(digest) is not str
        or len(digest) != 64
        or digest_mode not in {"raw_bytes_v1", "lf_normalized_text_v1"}
    ):
        raise ValueError("independent validation run input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("independent validation run input escaped repository") from None
    if not path.is_file():
        raise ValueError("independent validation run input digest failed validation")
    content = path.read_bytes()
    if digest_mode == "lf_normalized_text_v1":
        content = content.replace(b"\r\n", b"\n")
    actual_digest = hashlib.sha256(content).hexdigest()
    if actual_digest != digest:
        raise ValueError("independent validation run input digest failed validation")
    return path


def _verify_manifest(path: Path) -> None:
    root = path.parent
    manifest_path = path.resolve()
    manifest = _read_json(path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("independent validation run manifest failed validation")
    expected: set[str] = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise ValueError("independent validation run manifest failed validation")
        relative = Path(str(item["path"]))
        resolved = (root / relative).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            raise ValueError("independent validation run manifest escaped root") from None
        normalized = relative.as_posix()
        if (
            relative.is_absolute()
            or normalized in expected
            or not resolved.is_file()
            or sha256_file(resolved) != item["sha256"]
        ):
            raise ValueError("independent validation run manifest failed validation")
        expected.add(normalized)
    actual = {
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and item.resolve() != manifest_path
    }
    if actual != expected:
        raise ValueError("independent validation run manifest closure failed validation")


def _unit_manifest(unit_dir: Path) -> None:
    files = sorted(path for path in unit_dir.rglob("*") if path.is_file())
    _write_json(
        unit_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.relative_to(unit_dir).as_posix(), "sha256": sha256_file(path)}
                for path in files
            ],
        },
    )


def _safe_error(error: BaseException, stage: str) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "stage": stage,
        "error_type": type(error).__name__,
        "message": str(error),
        "traceback": traceback.format_exc(),
    }
    if isinstance(error, SecAwareError):
        result.update(
            {
                "error_code": int(error.code),
                "reported_stage": error.stage,
                "retryable": error.retryable,
                "details": error.details,
            }
        )
    return result


def _raw_generated_content(path: Path) -> str:
    response = _read_json(path)
    choices = response.get("choices")
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise ValueError("independent validation raw generation response failed validation")
    message = choices[0].get("message")
    if type(message) is not dict or type(message.get("content")) is not str:
        raise ValueError("independent validation raw generation response failed validation")
    return str(message["content"])


def _indexed_models(path: Path, model: type[BaseModel], key: str) -> dict[str, BaseModel]:
    rows = tuple(read_jsonl(path, model, required=True, allow_empty=False))
    result: dict[str, BaseModel] = {}
    for row in rows:
        value = getattr(row, key)
        if type(value) is not str or not value or value in result:
            raise ValueError("independent validation run identity failed validation")
        result[value] = row
    return result


def _indexed_dicts(path: Path, key: str) -> dict[str, dict[str, Any]]:
    rows = tuple(read_jsonl(path, required=True, allow_empty=False))
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if type(row) is not dict:
            raise ValueError("independent validation run JSONL failed validation")
        value = row.get(key)
        if type(value) is not str or not value or value in result:
            raise ValueError("independent validation run identity failed validation")
        result[value] = row
    return result


def _root_manifest(output_dir: Path) -> None:
    files = sorted(path for path in output_dir.rglob("*") if path.is_file())
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.relative_to(output_dir).as_posix(), "sha256": sha256_file(path)}
                for path in files
            ],
        },
    )


@dataclass(frozen=True, slots=True)
class IndependentValidationUnitResult:
    assignment_id: str
    failure: BaseException | None
    generated: int
    generation_calls: int
    judge_calls: int
    mechanism_calls: int
    functional_status: str | None
    mechanism_state: str | None
    mechanism_value: int | None
    duration_seconds: float


def execute_independent_validation_unit(
    *,
    output_dir: Path,
    assignment: AssignmentRecord,
    request: GenerationRequestRecord,
    contract: TaskFunctionalContractRecord,
    crosswalk: dict[str, Any],
    app_config: AppConfig,
    provider: object,
    generation_recorder: RecordingGenerationTransport,
    judge: object,
    judge_recorder: RecordingStructuredTransport,
    mechanism_extractor: LLMCodeMechanismFactsExtractor,
    mechanism_recorder: RecordingStructuredTransport,
) -> IndependentValidationUnitResult:
    """Execute one assignment and always close its diagnostic artifact directory."""

    unit_dir = output_dir / "units" / assignment.assignment_id
    unit_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(unit_dir / "assignment.jsonl", (assignment,))
    write_jsonl(unit_dir / "generation-request.jsonl", (request,))
    write_jsonl(unit_dir / "functional-contract.jsonl", (contract,))
    _write_json(unit_dir / "gate-a-crosswalk.json", crosswalk)
    started_at_utc = datetime.now(UTC).isoformat()
    started = time.monotonic()
    stage = "generation"
    failure: BaseException | None = None
    generation_calls = 0
    judge_calls = 0
    mechanism_calls = 0
    generated = 0
    functional_status: str | None = None
    mechanism_state: str | None = None
    mechanism_value: int | None = None
    try:
        generation_recorder.bind(unit_dir / "generation-provider-transport")
        try:
            executions, codes = execute_confirmation_requests(
                (request,), provider, app_config.generation
            )
        finally:
            generation_recorder.release_if_unused()
        generation_calls = executions[0].attempt_count
        write_jsonl(unit_dir / "assignment-execution.jsonl", executions)
        write_jsonl(unit_dir / "generated-code.jsonl", codes)
        execution = executions[0]
        code: CanonicalGeneratedCodeRecord | None = codes[0] if codes else None
        if execution.status is not AssignmentExecutionStatus.GENERATED or code is None:
            raise RuntimeError("independent validation unit returned no complete artifact")
        generated = 1
        extraction = extract_generated_source(
            _raw_generated_content(unit_dir / "generation-provider-transport" / "response.json")
        )
        if extraction.source != code.code or extraction.source_sha256 != code.code_sha256:
            raise ValueError("independent validation response extraction binding failed validation")
        _write_json(unit_dir / "response-extraction.json", asdict(extraction))

        stage = "functional_judge"
        judge_recorder.bind(unit_dir / "functional-judge-transport")
        try:
            try:
                judge_passes, functional_outcome = judge.evaluate(  # type: ignore[attr-defined]
                    assignment, execution, code, contract
                )
            except SecAwareError as judge_error:
                if (
                    judge_error.code is not ErrorCode.API_INVALID_RESPONSE
                    or not (unit_dir / "functional-judge-transport" / "response.json").is_file()
                ):
                    raise
                functional_outcome, invalid_response = _invalid_judge_unknown_outcome(
                    unit_dir=unit_dir,
                    assignment_id=assignment.assignment_id,
                    contract_id=contract.contract_id,
                    evaluator_policy_sha256=judge.policy_sha256,  # type: ignore[attr-defined]
                )
                judge_passes = ()
                _write_json(
                    unit_dir / "functional-judge-invalid-response.json",
                    invalid_response,
                )
        finally:
            judge_recorder.release_if_unused()
        judge_calls = 1
        functional_status = functional_outcome.status.value
        write_jsonl(unit_dir / "functional-judge-passes.jsonl", judge_passes)
        write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))

        stage = "code_mechanism"
        mechanism_recorder.bind(unit_dir / "code-mechanism-transport")
        try:
            measurement = mechanism_extractor.extract(
                code=code.code,
                target_cwe=str(crosswalk["cwe"]),
                language=str(crosswalk["language"]),
            )
        finally:
            mechanism_recorder.release_if_unused()
        mechanism_calls = 1
        mechanism_state = measurement.mechanism_state
        mechanism_value = measurement.z_target_mechanism_realized
        _write_json(unit_dir / "code-mechanism-measurement.json", asdict(measurement))
    except BaseException as error:
        failure = error
        _write_json(unit_dir / "error.json", _safe_error(error, stage))
    generation_calls = max(
        generation_calls,
        int((unit_dir / "generation-provider-transport" / "transport.json").is_file()),
    )
    judge_calls = max(
        judge_calls,
        int((unit_dir / "functional-judge-transport" / "transport.json").is_file()),
    )
    mechanism_calls = max(
        mechanism_calls,
        int((unit_dir / "code-mechanism-transport" / "transport.json").is_file()),
    )
    duration_seconds = time.monotonic() - started
    _write_json(
        unit_dir / "status.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "assignment_id": assignment.assignment_id,
            "status": "ERROR" if failure is not None else "COMPLETE",
            **({"failed_stage": stage} if failure is not None else {}),
            "started_at_utc": started_at_utc,
            "finished_at_utc": datetime.now(UTC).isoformat(),
            "duration_seconds": duration_seconds,
            "generated": generated,
            "generation_provider_attempts": generation_calls,
            "functional_judge_provider_attempts": judge_calls,
            "mechanism_extractor_provider_attempts": mechanism_calls,
            "functional_status": functional_status,
            "mechanism_state": mechanism_state,
            "z_target_mechanism_realized": mechanism_value,
            "oracle_calls": 0,
        },
    )
    _unit_manifest(unit_dir)
    return IndependentValidationUnitResult(
        assignment_id=assignment.assignment_id,
        failure=failure,
        generated=generated,
        generation_calls=generation_calls,
        judge_calls=judge_calls,
        mechanism_calls=mechanism_calls,
        functional_status=functional_status,
        mechanism_state=mechanism_state,
        mechanism_value=mechanism_value,
        duration_seconds=duration_seconds,
    )


def run_independent_validation_pilot(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path.resolve())
    inputs = config.get("inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("run_id")
        not in {
            "five_cwe_independent_validation_phi14b_pilot_v1",
            "five_cwe_independent_validation_phi14b_pilot_v2",
        }
        or config.get("selection_key") != "pilot_assignment_ids"
        or config.get("expected_assignments") != 1
        or config.get("maximum_generation_calls") != 1
        or config.get("maximum_functional_judge_calls") != 1
        or config.get("maximum_mechanism_extractor_calls") != 1
        or config.get("oracle_calls_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {"plan_manifest", "runtime_freeze_manifest", "app_config", "mechanism_config"}
    ):
        raise ValueError("independent validation pilot config failed validation")
    paths = {name: _input_path(repo_root, value) for name, value in inputs.items()}
    _verify_manifest(paths["plan_manifest"])
    _verify_manifest(paths["runtime_freeze_manifest"])
    plan_dir = paths["plan_manifest"].parent
    plan_report = _read_json(plan_dir / "report.json")
    selection = _read_json(plan_dir / "execution-selection.json")
    selected = selection.get("pilot_assignment_ids")
    if (
        plan_report.get("status") != "INDEPENDENT_VALIDATION_EXECUTION_PLAN_COMPLETE"
        or plan_report.get("provider_calls") != 0
        or plan_report.get("outcomes_consumed") != 0
        or type(selected) is not list
        or len(selected) != 1
        or type(selected[0]) is not str
    ):
        raise ValueError("independent validation pilot source plan failed validation")
    runtime_policy = _read_json(paths["runtime_freeze_manifest"].parent / "runtime-policy.json")
    app_config = load_config(paths["app_config"], run_dir=output_dir)
    mechanism_config = _read_json(paths["mechanism_config"])
    mechanism_policy = code_mechanism_policy_from_config(mechanism_config)
    if (
        runtime_policy.get("mechanism_policy_sha256") != _MECHANISM_POLICY_SHA256
        or runtime_policy.get("response_extraction_policy_sha256")
        != SOURCE_EXTRACTION_POLICY_SHA256
        or runtime_policy.get("generation_provider_runtime_sha256")
        != openai_provider_runtime_fingerprint()
        or mechanism_config.get("criteria_version") != "mechanism-operational-definitions-v2"
        or mechanism_config.get("llm", {}).get("max_attempts") != 1
    ):
        raise ValueError("independent validation pilot measurement policy failed validation")

    assignment_by_id = _indexed_models(
        plan_dir / "assignments.jsonl", AssignmentRecord, "assignment_id"
    )
    request_by_assignment = _indexed_models(
        plan_dir / "generation-requests.jsonl", GenerationRequestRecord, "assignment_id"
    )
    contract_by_task = _indexed_models(
        plan_dir / "functional-contracts.jsonl", TaskFunctionalContractRecord, "task_id"
    )
    crosswalk_by_assignment = _indexed_dicts(plan_dir / "gate-a-crosswalk.jsonl", "assignment_id")
    assignment = assignment_by_id.get(selected[0])
    request = request_by_assignment.get(selected[0])
    crosswalk = crosswalk_by_assignment.get(selected[0])
    if (
        type(assignment) is not AssignmentRecord
        or type(request) is not GenerationRequestRecord
        or crosswalk is None
        or request.assignment_id != assignment.assignment_id
        or crosswalk.get("assignment_id") != assignment.assignment_id
    ):
        raise ValueError("independent validation pilot coordinate failed validation")
    contract = contract_by_task.get(assignment.experimental_unit.task_id)
    if type(contract) is not TaskFunctionalContractRecord:
        raise ValueError("independent validation pilot contract failed validation")

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-run-config.json", config)
    write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
    _write_json(output_dir / "effective-mechanism-config.json", mechanism_config)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            **{name + "_sha256": sha256_file(path) for name, path in paths.items()},
        },
    )
    generation_recorder = RecordingGenerationTransport()
    provider = create_confirmation_provider(app_config, attempt_recorder=generation_recorder)
    judge_recorder: RecordingStructuredTransport | None = None

    def judge_transport_factory(**kwargs: object) -> object:
        nonlocal judge_recorder
        judge_recorder = RecordingStructuredTransport(**kwargs)
        return judge_recorder

    judge = create_functional_judge(app_config, transport_factory=judge_transport_factory)
    mechanism_llm = mechanism_config["llm"]
    mechanism_recorder = RecordingStructuredTransport(
        base_url=mechanism_llm["base_url"],
        api_key_env=mechanism_llm["api_key_env"],
        system_template=CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    )
    mechanism_extractor = LLMCodeMechanismFactsExtractor(
        mechanism_recorder,
        mechanism_policy,
        criteria_version="mechanism-operational-definitions-v2",
    )
    if mechanism_extractor.policy_sha256 != _MECHANISM_POLICY_SHA256:
        raise ValueError("independent validation mechanism policy digest failed validation")
    if judge.policy_sha256 != runtime_policy.get("functional_judge_policy_sha256"):
        raise ValueError("independent validation functional Judge policy failed validation")

    if judge_recorder is None:
        raise RuntimeError("independent validation functional Judge recorder is unavailable")
    unit_result = execute_independent_validation_unit(
        output_dir=output_dir,
        assignment=assignment,
        request=request,
        contract=contract,
        crosswalk=crosswalk,
        app_config=app_config,
        provider=provider,
        generation_recorder=generation_recorder,
        judge=judge,
        judge_recorder=judge_recorder,
        mechanism_extractor=mechanism_extractor,
        mechanism_recorder=mechanism_recorder,
    )
    failure = unit_result.failure
    generated = unit_result.generated
    generation_calls = unit_result.generation_calls
    judge_calls = unit_result.judge_calls
    mechanism_calls = unit_result.mechanism_calls
    functional_status = unit_result.functional_status
    mechanism_state = unit_result.mechanism_state
    mechanism_value = unit_result.mechanism_value
    _append_jsonl(
        output_dir / "progress.jsonl",
        {
            "schema_version": _SCHEMA_VERSION,
            "assignment_id": assignment.assignment_id,
            "status": "ERROR" if failure is not None else "COMPLETE",
            "completed": int(failure is None),
            "errors": int(failure is not None),
            "pending": 0,
        },
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "INDEPENDENT_VALIDATION_PILOT_ERROR"
            if failure is not None
            else "INDEPENDENT_VALIDATION_PILOT_COMPLETE"
        ),
        "counts": {
            "assignments": 1,
            "complete": int(failure is None),
            "errors": int(failure is not None),
            "pending": 0,
            "generated": generated,
            "generation_provider_attempts": generation_calls,
            "functional_judge_provider_attempts": judge_calls,
            "mechanism_extractor_provider_attempts": mechanism_calls,
            "oracle_calls": 0,
        },
        "functional_status": functional_status,
        "mechanism_state": mechanism_state,
        "z_target_mechanism_realized": mechanism_value,
        "next_action": (
            "diagnose_and_repair_failed_pilot"
            if failure is not None
            else "inspect_artifacts_then_run_remaining_canary_assignments"
        ),
    }
    _write_json(output_dir / "report.json", report)
    _root_manifest(output_dir)
    if failure is not None:
        raise RuntimeError(
            "independent validation pilot failed; complete diagnostic artifacts were preserved"
        ) from failure
    return report


__all__ = [
    "IndependentValidationUnitResult",
    "execute_independent_validation_unit",
    "run_independent_validation_pilot",
]

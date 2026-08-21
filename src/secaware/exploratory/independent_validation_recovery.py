"""No-regeneration recovery for one preserved invalid functional-Judge response."""

from __future__ import annotations

import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from secaware.errors import ErrorCode, SecAwareError
from secaware.exploratory.code_mechanism_calibration import (
    code_mechanism_policy_from_config,
)
from secaware.exploratory.code_mechanism_facts import (
    CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    LLMCodeMechanismFactsExtractor,
)
from secaware.exploratory.gate_c_live import (
    RecordingStructuredTransport,
    _invalid_judge_unknown_outcome,
)
from secaware.exploratory.independent_validation_batch import _run_assignment_states
from secaware.exploratory.independent_validation_run import (
    _environment,
    _input_path,
    _read_json,
    _root_manifest,
    _unit_manifest,
    _verify_manifest,
    _write_json,
)
from secaware.functional_judge.judge import _parse_response
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import sha256_file
from secaware.schema.experiments import AssignmentRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_MECHANISM_POLICY_SHA256 = "01d279a56c64fc42aa54fd96611eec2fa7db54f5198ce3680d37388d89d1e7ac"


def _one(path: Path, model: type[Any]) -> Any:
    rows = tuple(read_jsonl(path, model, required=True, allow_empty=False))
    if len(rows) != 1:
        raise ValueError("independent validation recovery record count failed validation")
    return rows[0]


def recover_invalid_functional_judge_unit(
    *,
    repo_root: Path,
    config_path: Path,
    source_run_dir: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    source_run_dir = source_run_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path.resolve())
    inputs = config.get("inputs")
    assignment_id = config.get("assignment_id")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("recovery_id") != "five_cwe_independent_validation_invalid_judge_recovery_v1"
        or type(assignment_id) is not str
        or config.get("source_run_manifest_sha256")
        != sha256_file(source_run_dir / "artifact-manifest.json")
        or config.get("new_generation_calls") != 0
        or config.get("new_functional_judge_calls") != 0
        or config.get("maximum_new_mechanism_calls") != 1
        or config.get("oracle_calls_allowed") is not False
        or type(inputs) is not dict
        or set(inputs) != {"runtime_freeze_manifest", "mechanism_config"}
    ):
        raise ValueError("independent validation recovery config failed validation")
    paths = {name: _input_path(repo_root, value) for name, value in inputs.items()}
    _verify_manifest(paths["runtime_freeze_manifest"])
    _verify_manifest(source_run_dir / "artifact-manifest.json")
    complete, errors = _run_assignment_states(source_run_dir)
    source_report = _read_json(source_run_dir / "report.json")
    if (
        errors != {assignment_id}
        or len(complete) != 37
        or source_report.get("status") != "INDEPENDENT_VALIDATION_FULL_REMAINING_ERROR"
        or source_report.get("counts", {}).get("complete") != 37
        or source_report.get("counts", {}).get("errors") != 1
        or source_report.get("counts", {}).get("pending") != 162
    ):
        raise ValueError("independent validation recovery source run failed validation")
    source_unit = source_run_dir / "units" / assignment_id
    source_status = _read_json(source_unit / "status.json")
    if (
        source_status.get("status") != "ERROR"
        or source_status.get("failed_stage") != "functional_judge"
        or source_status.get("generated") != 1
        or source_status.get("generation_provider_attempts") != 1
        or source_status.get("functional_judge_provider_attempts") != 1
        or source_status.get("mechanism_extractor_provider_attempts") != 0
        or source_status.get("oracle_calls") != 0
    ):
        raise ValueError("independent validation recovery source unit failed validation")

    assignment = _one(source_unit / "assignment.jsonl", AssignmentRecord)
    contract = _one(source_unit / "functional-contract.jsonl", TaskFunctionalContractRecord)
    code = _one(source_unit / "generated-code.jsonl", CanonicalGeneratedCodeRecord)
    crosswalk = _read_json(source_unit / "gate-a-crosswalk.json")
    if (
        assignment.assignment_id != assignment_id
        or code.assignment_id != assignment_id
        or contract.task_id != assignment.experimental_unit.task_id
        or crosswalk.get("assignment_id") != assignment_id
    ):
        raise ValueError("independent validation recovery identity failed validation")
    try:
        _parse_response(
            (source_unit / "functional-judge-transport" / "response.json").read_bytes(),
            contract=contract,
            code=code.code,
        )
    except SecAwareError as error:
        if error.code is not ErrorCode.API_INVALID_RESPONSE:
            raise
    else:
        raise ValueError("independent validation recovery source response is valid")

    runtime_policy = _read_json(paths["runtime_freeze_manifest"].parent / "runtime-policy.json")
    mechanism_config = _read_json(paths["mechanism_config"])
    mechanism_policy = code_mechanism_policy_from_config(mechanism_config)
    mechanism_recorder = RecordingStructuredTransport(
        base_url=mechanism_config["llm"]["base_url"],
        api_key_env=mechanism_config["llm"]["api_key_env"],
        system_template=CODE_MECHANISM_FACTS_SYSTEM_TEMPLATE,
    )
    mechanism_extractor = LLMCodeMechanismFactsExtractor(
        mechanism_recorder,
        mechanism_policy,
        criteria_version="mechanism-operational-definitions-v2",
    )
    if (
        runtime_policy.get("functional_judge_policy_sha256")
        != "5cffaa26b9fec5daa84eca3e96a94c28b2b5f40f3d40a7121ec866f825371907"
        or mechanism_extractor.policy_sha256 != _MECHANISM_POLICY_SHA256
        or runtime_policy.get("mechanism_policy_sha256") != _MECHANISM_POLICY_SHA256
    ):
        raise ValueError("independent validation recovery policy failed validation")
    functional_outcome, invalid_response = _invalid_judge_unknown_outcome(
        unit_dir=source_unit,
        assignment_id=assignment_id,
        contract_id=contract.contract_id,
        evaluator_policy_sha256=str(runtime_policy["functional_judge_policy_sha256"]),
    )

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-recovery-config.json", config)
    _write_json(output_dir / "effective-mechanism-config.json", mechanism_config)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "source_run_dir": str(source_run_dir),
            "source_run_manifest_sha256": sha256_file(source_run_dir / "artifact-manifest.json"),
            "source_unit_manifest_sha256": sha256_file(source_unit / "artifact-manifest.json"),
            **{name + "_sha256": sha256_file(path) for name, path in paths.items()},
        },
    )
    unit_dir = output_dir / "units" / assignment_id
    unit_dir.mkdir(parents=True, exist_ok=False)
    for name in (
        "assignment.jsonl",
        "generation-request.jsonl",
        "functional-contract.jsonl",
        "gate-a-crosswalk.json",
        "assignment-execution.jsonl",
        "generated-code.jsonl",
        "response-extraction.json",
    ):
        shutil.copy2(source_unit / name, unit_dir / name)
    for name in ("generation-provider-transport", "functional-judge-transport"):
        shutil.copytree(source_unit / name, unit_dir / name)
    write_jsonl(unit_dir / "functional-judge-passes.jsonl", ())
    write_jsonl(unit_dir / "functional-outcome.jsonl", (functional_outcome,))
    _write_json(unit_dir / "functional-judge-invalid-response.json", invalid_response)

    failure: BaseException | None = None
    mechanism_state: str | None = None
    mechanism_value: int | None = None
    mechanism_recorder.bind(unit_dir / "code-mechanism-transport")
    try:
        measurement = mechanism_extractor.extract(
            code=code.code,
            target_cwe=str(crosswalk["cwe"]),
            language=str(crosswalk["language"]),
        )
        mechanism_state = measurement.mechanism_state
        mechanism_value = measurement.z_target_mechanism_realized
        _write_json(unit_dir / "code-mechanism-measurement.json", asdict(measurement))
    except BaseException as error:
        failure = error
        _write_json(
            unit_dir / "recovery-error.json",
            {
                "schema_version": _SCHEMA_VERSION,
                "error_type": type(error).__name__,
                "message": str(error),
            },
        )
    finally:
        mechanism_recorder.release_if_unused()
    _write_json(
        unit_dir / "status.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "assignment_id": assignment_id,
            "status": "ERROR" if failure is not None else "COMPLETE",
            **({"failed_stage": "code_mechanism_recovery"} if failure is not None else {}),
            "generated": 1,
            "generation_provider_attempts": 0,
            "functional_judge_provider_attempts": 0,
            "mechanism_extractor_provider_attempts": 1,
            "source_generation_provider_attempts": 1,
            "source_functional_judge_provider_attempts": 1,
            "functional_status": "unknown",
            "mechanism_state": mechanism_state,
            "z_target_mechanism_realized": mechanism_value,
            "oracle_calls": 0,
            "recovery_policy": "preserved_invalid_single_pass_response_to_unknown_v1",
        },
    )
    _unit_manifest(unit_dir)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "INDEPENDENT_VALIDATION_INVALID_JUDGE_RECOVERY_ERROR"
            if failure is not None
            else "INDEPENDENT_VALIDATION_INVALID_JUDGE_RECOVERY_COMPLETE"
        ),
        "counts": {
            "assignments": 1,
            "complete": int(failure is None),
            "errors": int(failure is not None),
            "new_generation_provider_attempts": 0,
            "new_functional_judge_provider_attempts": 0,
            "new_mechanism_extractor_provider_attempts": 1,
            "oracle_calls": 0,
        },
        "functional_status": "unknown",
        "mechanism_state": mechanism_state,
        "z_target_mechanism_realized": mechanism_value,
        "next_action": (
            "diagnose_recovery_failure"
            if failure is not None
            else "resume_remaining_full_assignments"
        ),
    }
    _write_json(output_dir / "report.json", report)
    _root_manifest(output_dir)
    if failure is not None:
        raise RuntimeError(
            "independent validation recovery failed; artifacts preserved"
        ) from failure
    return report


__all__ = ["recover_invalid_functional_judge_unit"]

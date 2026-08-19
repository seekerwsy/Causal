"""Fail-closed batched execution for frozen independent-validation selections."""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from secaware.config import load_config, write_resolved_config
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
)
from secaware.exploratory.independent_validation_run import (
    _append_jsonl,
    _environment,
    _indexed_dicts,
    _indexed_models,
    _input_path,
    _read_json,
    _root_manifest,
    _verify_manifest,
    _write_json,
    execute_independent_validation_unit,
)
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.generation.openai_compatible_provider import (
    openai_provider_runtime_fingerprint,
)
from secaware.generation.source_extraction import SOURCE_EXTRACTION_POLICY_SHA256
from secaware.pipeline.artifact import sha256_file
from secaware.pipeline.stages.confirmation_generation import create_confirmation_provider
from secaware.schema.experiments import AssignmentRecord
from secaware.schema.generation import GenerationRequestRecord

_SCHEMA_VERSION = "1.0"
_MECHANISM_POLICY_SHA256 = "01d279a56c64fc42aa54fd96611eec2fa7db54f5198ce3680d37388d89d1e7ac"


def _completed_assignment_ids(run_dir: Path) -> set[str]:
    _verify_manifest(run_dir / "artifact-manifest.json")
    result: set[str] = set()
    units = run_dir / "units"
    if not units.is_dir():
        raise ValueError("independent validation prior run has no units")
    for unit_dir in sorted(units.iterdir()):
        if not unit_dir.is_dir():
            raise ValueError("independent validation prior unit failed validation")
        _verify_manifest(unit_dir / "artifact-manifest.json")
        status = _read_json(unit_dir / "status.json")
        assignment_id = status.get("assignment_id")
        if (
            status.get("status") != "COMPLETE"
            or type(assignment_id) is not str
            or not assignment_id
            or assignment_id in result
        ):
            raise ValueError("independent validation prior completion failed validation")
        result.add(assignment_id)
    return result


def run_independent_validation_batch(
    *,
    repo_root: Path,
    config_path: Path,
    completed_run_dir: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    completed_run_dir = completed_run_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path.resolve())
    inputs = config.get("inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("run_id")
        not in {
            "five_cwe_independent_validation_phi14b_canary_remaining_v1",
            "five_cwe_independent_validation_phi14b_canary_remaining_v2",
        }
        or config.get("selection_key") != "canary_assignment_ids"
        or config.get("expected_selected_assignments") != 20
        or config.get("expected_prior_completed") != 1
        or config.get("expected_new_assignments") != 19
        or config.get("maximum_generation_calls") != 19
        or config.get("maximum_functional_judge_calls") != 19
        or config.get("maximum_mechanism_extractor_calls") != 19
        or config.get("oracle_calls_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {"plan_manifest", "runtime_freeze_manifest", "app_config", "mechanism_config"}
    ):
        raise ValueError("independent validation batch config failed validation")
    paths = {name: _input_path(repo_root, value) for name, value in inputs.items()}
    _verify_manifest(paths["plan_manifest"])
    _verify_manifest(paths["runtime_freeze_manifest"])
    prior_ids = _completed_assignment_ids(completed_run_dir)

    plan_dir = paths["plan_manifest"].parent
    plan_report = _read_json(plan_dir / "report.json")
    plan_selection = _read_json(plan_dir / "execution-selection.json")
    selected = plan_selection.get("canary_assignment_ids")
    pilot_selected = plan_selection.get("pilot_assignment_ids")
    if (
        plan_report.get("status") != "INDEPENDENT_VALIDATION_EXECUTION_PLAN_COMPLETE"
        or plan_report.get("provider_calls") != 0
        or plan_report.get("outcomes_consumed") != 0
        or type(selected) is not list
        or len(selected) != 20
        or len(set(selected)) != 20
        or any(type(item) is not str for item in selected)
        or type(pilot_selected) is not list
        or len(pilot_selected) != 1
        or type(pilot_selected[0]) is not str
        or prior_ids != set(pilot_selected)
        or not prior_ids.issubset(set(selected))
    ):
        raise ValueError("independent validation batch source plan failed validation")
    to_run = tuple(item for item in selected if item not in prior_ids)
    if len(to_run) != 19:
        raise ValueError("independent validation remaining selection failed validation")

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
        raise ValueError("independent validation batch measurement policy failed validation")

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
    if any(
        assignment_id not in assignment_by_id
        or assignment_id not in request_by_assignment
        or assignment_id not in crosswalk_by_assignment
        for assignment_id in to_run
    ):
        raise ValueError("independent validation batch coordinate failed validation")

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
            "completed_run_manifest_sha256": sha256_file(
                completed_run_dir / "artifact-manifest.json"
            ),
            "completed_run_dir": str(completed_run_dir),
            "prior_completed_assignment_ids": sorted(prior_ids),
        },
    )
    _write_json(
        output_dir / "execution-selection.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "selected_assignment_ids": list(selected),
            "prior_completed_assignment_ids": sorted(prior_ids),
            "new_assignment_ids": list(to_run),
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
    if (
        judge_recorder is None
        or judge.policy_sha256 != runtime_policy.get("functional_judge_policy_sha256")
        or mechanism_extractor.policy_sha256 != _MECHANISM_POLICY_SHA256
    ):
        raise ValueError("independent validation batch evaluator policy failed validation")

    completed = 0
    errors = 0
    generated = 0
    generation_calls = 0
    judge_calls = 0
    mechanism_calls = 0
    total_duration = 0.0
    functional_counts: Counter[str] = Counter()
    mechanism_counts: Counter[str] = Counter()
    failure: BaseException | None = None
    started = time.monotonic()
    for assignment_id in to_run:
        assignment = assignment_by_id[assignment_id]
        request = request_by_assignment[assignment_id]
        crosswalk = crosswalk_by_assignment[assignment_id]
        if type(assignment) is not AssignmentRecord or type(request) is not GenerationRequestRecord:
            raise ValueError("independent validation batch model coordinate failed validation")
        contract = contract_by_task.get(assignment.experimental_unit.task_id)
        if type(contract) is not TaskFunctionalContractRecord:
            raise ValueError("independent validation batch contract failed validation")
        result = execute_independent_validation_unit(
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
        generated += result.generated
        generation_calls += result.generation_calls
        judge_calls += result.judge_calls
        mechanism_calls += result.mechanism_calls
        total_duration += result.duration_seconds
        if result.functional_status is not None:
            functional_counts[result.functional_status] += 1
        if result.mechanism_state is not None:
            mechanism_counts[result.mechanism_state] += 1
        if result.failure is None:
            completed += 1
        else:
            errors += 1
            failure = result.failure
        attempted = completed + errors
        pending = len(to_run) - attempted
        rate = attempted / max(time.monotonic() - started, 1e-9)
        _append_jsonl(
            output_dir / "progress.jsonl",
            {
                "schema_version": _SCHEMA_VERSION,
                "assignment_id": assignment_id,
                "status": "ERROR" if result.failure is not None else "COMPLETE",
                "complete": completed,
                "errors": errors,
                "pending": pending,
                "assignments_per_minute": rate * 60.0,
                "estimated_remaining_seconds": pending / rate if rate > 0 else None,
            },
        )
        if failure is not None:
            break

    pending = len(to_run) - completed - errors
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "INDEPENDENT_VALIDATION_CANARY_REMAINING_ERROR"
            if failure is not None
            else "INDEPENDENT_VALIDATION_CANARY_REMAINING_COMPLETE"
        ),
        "counts": {
            "selected_assignments": 20,
            "prior_complete": 1,
            "new_assignments": 19,
            "complete": completed,
            "errors": errors,
            "pending": pending,
            "generated": generated,
            "generation_provider_attempts": generation_calls,
            "functional_judge_provider_attempts": judge_calls,
            "mechanism_extractor_provider_attempts": mechanism_calls,
            "oracle_calls": 0,
        },
        "functional_status": dict(sorted(functional_counts.items())),
        "mechanism_state": dict(sorted(mechanism_counts.items())),
        "elapsed_seconds": time.monotonic() - started,
        "mean_unit_seconds": total_duration / max(completed + errors, 1),
        "next_action": (
            "diagnose_and_repair_failed_canary_unit"
            if failure is not None
            else "validate_cumulative_twenty_assignment_canary"
        ),
    }
    _write_json(output_dir / "report.json", report)
    _root_manifest(output_dir)
    if failure is not None:
        raise RuntimeError(
            "independent validation canary stopped at the first failed unit; artifacts preserved"
        ) from failure
    return report


__all__ = ["run_independent_validation_batch"]

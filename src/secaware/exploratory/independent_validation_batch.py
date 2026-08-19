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
_RUN_PROFILES = {
    "five_cwe_independent_validation_phi14b_canary_remaining_v1": {
        "selection_key": "canary_assignment_ids",
        "prior_selection_key": "pilot_assignment_ids",
        "selected": 20,
        "prior": 1,
        "new": 19,
        "label": "CANARY_REMAINING",
        "success_next_action": "validate_cumulative_twenty_assignment_canary",
    },
    "five_cwe_independent_validation_phi14b_canary_remaining_v2": {
        "selection_key": "canary_assignment_ids",
        "prior_selection_key": "pilot_assignment_ids",
        "selected": 20,
        "prior": 1,
        "new": 19,
        "label": "CANARY_REMAINING",
        "success_next_action": "validate_cumulative_twenty_assignment_canary",
    },
    "five_cwe_independent_validation_phi14b_full_remaining_v1": {
        "selection_key": "full_assignment_ids",
        "prior_selection_key": "canary_assignment_ids",
        "selected": 220,
        "prior": 20,
        "new": 200,
        "label": "FULL_REMAINING",
        "success_next_action": "validate_cumulative_220_assignments_then_run_frozen_discovery",
        "allow_recovered_prior_errors": False,
        "prior_consumed_new": 0,
    },
    "five_cwe_independent_validation_phi14b_full_resume_v1": {
        "selection_key": "full_assignment_ids",
        "prior_selection_key": "canary_assignment_ids",
        "selected": 220,
        "prior": 58,
        "new": 162,
        "label": "FULL_RESUME",
        "success_next_action": "validate_cumulative_220_assignments_then_run_frozen_discovery",
        "allow_recovered_prior_errors": True,
        "prior_consumed_new": 38,
    },
}

for _profile in _RUN_PROFILES.values():
    _profile.setdefault("allow_recovered_prior_errors", False)
    _profile.setdefault("prior_consumed_new", 0)


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


def _run_assignment_states(run_dir: Path) -> tuple[set[str], set[str]]:
    _verify_manifest(run_dir / "artifact-manifest.json")
    complete: set[str] = set()
    errors: set[str] = set()
    units = run_dir / "units"
    if not units.is_dir():
        raise ValueError("independent validation prior run has no units")
    for unit_dir in sorted(units.iterdir()):
        if not unit_dir.is_dir():
            raise ValueError("independent validation prior unit failed validation")
        _verify_manifest(unit_dir / "artifact-manifest.json")
        status = _read_json(unit_dir / "status.json")
        assignment_id = status.get("assignment_id")
        state = status.get("status")
        if (
            state not in {"COMPLETE", "ERROR"}
            or type(assignment_id) is not str
            or not assignment_id
            or assignment_id in complete
            or assignment_id in errors
        ):
            raise ValueError("independent validation prior state failed validation")
        (complete if state == "COMPLETE" else errors).add(assignment_id)
    return complete, errors


def _completed_assignment_id_union(
    run_dirs: tuple[Path, ...],
    *,
    allow_recovered_errors: bool = False,
) -> set[str]:
    if not run_dirs or len(run_dirs) != len(set(run_dirs)):
        raise ValueError("independent validation prior run set failed validation")
    result: set[str] = set()
    errors: set[str] = set()
    for run_dir in run_dirs:
        current, current_errors = _run_assignment_states(run_dir)
        if result.intersection(current):
            raise ValueError("independent validation prior runs overlap")
        result.update(current)
        errors.update(current_errors)
    if errors and (not allow_recovered_errors or not errors.issubset(result)):
        raise ValueError("independent validation prior errors are not recovered")
    return result


def run_independent_validation_batch(
    *,
    repo_root: Path,
    config_path: Path,
    completed_run_dirs: tuple[Path, ...],
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    completed_run_dirs = tuple(path.resolve() for path in completed_run_dirs)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path.resolve())
    inputs = config.get("inputs")
    run_id = config.get("run_id")
    profile = _RUN_PROFILES.get(run_id) if type(run_id) is str else None
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or profile is None
        or config.get("selection_key") != profile["selection_key"]
        or config.get("expected_selected_assignments") != profile["selected"]
        or config.get("expected_prior_completed") != profile["prior"]
        or config.get("expected_new_assignments") != profile["new"]
        or config.get("maximum_generation_calls") != profile["new"]
        or config.get("maximum_functional_judge_calls") != profile["new"]
        or config.get("maximum_mechanism_extractor_calls") != profile["new"]
        or config.get("oracle_calls_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {"plan_manifest", "runtime_freeze_manifest", "app_config", "mechanism_config"}
    ):
        raise ValueError("independent validation batch config failed validation")
    paths = {name: _input_path(repo_root, value) for name, value in inputs.items()}
    _verify_manifest(paths["plan_manifest"])
    _verify_manifest(paths["runtime_freeze_manifest"])
    prior_ids = _completed_assignment_id_union(
        completed_run_dirs,
        allow_recovered_errors=bool(profile["allow_recovered_prior_errors"]),
    )

    plan_dir = paths["plan_manifest"].parent
    plan_report = _read_json(plan_dir / "report.json")
    plan_selection = _read_json(plan_dir / "execution-selection.json")
    selected = plan_selection.get(str(profile["selection_key"]))
    base_prior = plan_selection.get(str(profile["prior_selection_key"]))
    if type(base_prior) is list and type(selected) is list:
        nonprior = [item for item in selected if item not in set(base_prior)]
        expected_prior = [
            *base_prior,
            *nonprior[: int(profile["prior_consumed_new"])],
        ]
    else:
        expected_prior = None
    if (
        plan_report.get("status") != "INDEPENDENT_VALIDATION_EXECUTION_PLAN_COMPLETE"
        or plan_report.get("provider_calls") != 0
        or plan_report.get("outcomes_consumed") != 0
        or type(selected) is not list
        or len(selected) != profile["selected"]
        or len(set(selected)) != profile["selected"]
        or any(type(item) is not str for item in selected)
        or type(expected_prior) is not list
        or len(expected_prior) != profile["prior"]
        or len(set(expected_prior)) != profile["prior"]
        or any(type(item) is not str for item in expected_prior)
        or prior_ids != set(expected_prior)
        or not prior_ids.issubset(set(selected))
    ):
        raise ValueError("independent validation batch source plan failed validation")
    to_run = tuple(item for item in selected if item not in prior_ids)
    if len(to_run) != profile["new"]:
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
            "completed_runs": [
                {
                    "run_dir": str(run_dir),
                    "manifest_sha256": sha256_file(run_dir / "artifact-manifest.json"),
                }
                for run_dir in completed_run_dirs
            ],
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
            f"INDEPENDENT_VALIDATION_{profile['label']}_ERROR"
            if failure is not None
            else f"INDEPENDENT_VALIDATION_{profile['label']}_COMPLETE"
        ),
        "counts": {
            "selected_assignments": profile["selected"],
            "prior_complete": profile["prior"],
            "new_assignments": profile["new"],
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
            "diagnose_and_repair_failed_batch_unit"
            if failure is not None
            else profile["success_next_action"]
        ),
    }
    _write_json(output_dir / "report.json", report)
    _root_manifest(output_dir)
    if failure is not None:
        raise RuntimeError(
            "independent validation batch stopped at the first failed unit; artifacts preserved"
        ) from failure
    return report


__all__ = [
    "_completed_assignment_id_union",
    "run_independent_validation_batch",
]

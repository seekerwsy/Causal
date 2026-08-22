"""Prospective ADD/REMOVE intervention freeze for the formal held-out study."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.cli import build_study
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.records import content_hash


class FormalStudyError(ValueError):
    """A frozen formal-study input or intervention response is invalid."""


@dataclass(frozen=True, slots=True)
class FormalInputs:
    repository_root: Path
    config_path: Path
    config: dict[str, Any]
    discover_tasks: tuple[dict[str, Any], ...]
    confirm_tasks: tuple[dict[str, Any], ...]
    pilot_task_ids: tuple[str, ...]
    executor: dict[str, Any]
    validator: dict[str, Any]
    executor_prompt: str
    validator_prompt: str


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


def load_formal_inputs(
    repository_root: Path,
    config_path: Path | None = None,
) -> FormalInputs:
    root = repository_root.resolve()
    path = config_path or root / "configs/formal/bidirectional-heldout-qwen7b-v1.json"
    path = path.resolve()
    config = _object(read_json(path), "formal config")
    _exact(
        config,
        {
            "schema_version",
            "study_name",
            "purpose",
            "task_selection",
            "security_mechanisms",
            "intervention",
            "generation",
            "security_oracle",
            "functional_oracle",
            "randomization",
            "analysis",
            "pilot",
            "scientific_claim_allowed_after_complete_analysis",
        },
    )
    if config["schema_version"] != "1.0":
        raise FormalStudyError("unsupported formal-study config")

    selection = _object(config["task_selection"], "task selection")
    pool_path = _bound_file(root, selection["pool_path"], selection["pool_sha256"])
    excluded_path = _bound_file(
        root,
        selection["excluded_development_selection_path"],
        selection["excluded_development_selection_sha256"],
    )
    rows = tuple(_json_lines(pool_path))
    excluded_document = _object(read_json(excluded_path), "development selection")
    excluded = {
        _object(item, "development task")["task_id"]
        for item in _list(excluded_document.get("tasks"), "development tasks")
    }
    discover = tuple(sorted((row for row in rows if row.get("split") == "discover"), key=_task_id))
    confirm = tuple(
        sorted(
            (
                row
                for row in rows
                if row.get("split") == "confirm"
                and row.get("language") == "python"
                and row.get("task_id") not in excluded
            ),
            key=_task_id,
        )
    )
    _validate_population(selection, discover, confirm, excluded)

    intervention = _object(config["intervention"], "intervention config")
    executor_path = _bound_file(
        root,
        intervention["executor_config_path"],
        intervention["executor_config_sha256"],
    )
    validator_path = _bound_file(
        root,
        intervention["validator_config_path"],
        intervention["validator_config_sha256"],
    )
    executor_prompt_path = _bound_file(
        root,
        intervention["executor_prompt_path"],
        intervention["executor_prompt_sha256"],
    )
    validator_prompt_path = _bound_file(
        root,
        intervention["validator_prompt_path"],
        intervention["validator_prompt_sha256"],
    )
    functional = _object(config["functional_oracle"], "functional Oracle config")
    _bound_file(root, functional["gate_config_path"], functional["gate_config_sha256"])
    qualification_path = _bound_file(
        root,
        functional["qualification_path"],
        functional["qualification_sha256"],
    )
    qualification = _object(read_json(qualification_path), "functional Oracle qualification")
    if qualification.get("status") != "QUALIFIED_FOR_EXPERIMENT":
        raise FormalStudyError("functional Oracle is not qualified")
    oracle = _object(config["security_oracle"], "security Oracle config")
    _bound_file(root, oracle["policy_lock_path"], oracle["policy_lock_sha256"])

    pilot_ids = tuple(_strings(selection["pilot_task_ids"], "pilot task IDs"))
    return FormalInputs(
        root,
        path,
        config,
        discover,
        confirm,
        pilot_ids,
        _object(read_json(executor_path), "executor evaluator"),
        _object(read_json(validator_path), "validator evaluator"),
        executor_prompt_path.read_text(encoding="utf-8"),
        validator_prompt_path.read_text(encoding="utf-8"),
    )


def preflight_interventions(
    repository_root: Path,
    output: Path,
    *,
    config_path: Path | None = None,
) -> dict[str, Any]:
    inputs = load_formal_inputs(repository_root, config_path)
    report = {
        "schema_version": "1.0",
        "status": "FORMAL_INTERVENTION_PREFLIGHT_COMPLETE",
        "provider_calls": 0,
        "study_name": inputs.config["study_name"],
        "discover_tasks": len(inputs.discover_tasks),
        "confirm_tasks": len(inputs.confirm_tasks),
        "semantic_clusters": len({row["task_cluster_id"] for row in inputs.confirm_tasks}),
        "pilot_task_ids": list(inputs.pilot_task_ids),
        "operations": ["add", "remove"],
        "formal_config_sha256": _sha256(inputs.config_path),
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "report.json": report,
            "selection.json": [_task_summary(row) for row in inputs.confirm_tasks],
        },
    )
    return report


def run_intervention_phase(
    repository_root: Path,
    phase: str,
    output: Path,
    *,
    pilot_root: Path | None = None,
    config_path: Path | None = None,
    provider: Provider | None = None,
) -> dict[str, Any]:
    if phase not in {"pilot", "remaining"}:
        raise FormalStudyError("intervention phase must be pilot or remaining")
    if output.exists():
        raise FileExistsError(output)
    inputs = load_formal_inputs(repository_root, config_path)
    if phase == "remaining" and (
        pilot_root is None or load_intervention_phase(pilot_root)["status"] != "PILOT_PASSED"
    ):
        raise FormalStudyError("remaining interventions require a passed pilot")
    wanted = set(inputs.pilot_task_ids)
    tasks = tuple(
        row for row in inputs.confirm_tasks if (row["task_id"] in wanted) is (phase == "pilot")
    )
    provider = provider or bailian_complete
    output.mkdir(parents=True)
    rows: list[dict[str, Any]] = []
    for index, task in enumerate(tasks, start=1):
        unit, passed = _run_intervention_task(inputs, task, provider)
        unit_root = output / f"task-{index:02d}"
        write_bundle(unit_root, unit)
        rows.append(
            {
                "task_id": task["task_id"],
                "cwe": task["cwe"],
                "passed": passed,
                "provider_attempts": unit["result.json"]["provider_attempts"],
                "bundle_sha256": bundle_digest(unit_root),
            }
        )
        if not passed:
            break
    complete = len(rows) == len(tasks) and all(row["passed"] for row in rows)
    if phase == "pilot":
        status = "PILOT_PASSED" if complete else "PILOT_FAILED"
    else:
        status = "REMAINING_COMPLETE" if complete else "ERROR"
    report = {
        "schema_version": "1.0",
        "status": status,
        "phase": phase,
        "expected_tasks": len(tasks),
        "completed_tasks": len(rows),
        "passed_tasks": sum(row["passed"] for row in rows),
        "provider_attempts": sum(row["provider_attempts"] for row in rows),
        "formal_config_sha256": _sha256(inputs.config_path),
        "scientific_claim_allowed": False,
    }
    write_bundle(output / "summary", {"report.json": report, "tasks.json": rows})
    return report


def load_intervention_phase(root: Path) -> dict[str, Any]:
    root = root.resolve()
    summary = root / "summary"
    verify_bundle(summary)
    report = _object(read_json(summary / "report.json"), "intervention phase report")
    rows = _list(read_json(summary / "tasks.json"), "intervention phase tasks")
    for index, value in enumerate(rows, start=1):
        row = _object(value, "intervention phase task")
        unit = root / f"task-{index:02d}"
        if bundle_digest(unit) != row["bundle_sha256"]:
            raise FormalStudyError("intervention task bundle drifted")
    return report


def finalize_interventions(
    repository_root: Path,
    pilot_root: Path,
    remaining_root: Path,
    output: Path,
    *,
    config_path: Path | None = None,
) -> dict[str, Any]:
    inputs = load_formal_inputs(repository_root, config_path)
    if load_intervention_phase(pilot_root)["status"] != "PILOT_PASSED":
        raise FormalStudyError("pilot interventions are incomplete")
    if load_intervention_phase(remaining_root)["status"] != "REMAINING_COMPLETE":
        raise FormalStudyError("remaining interventions are incomplete")
    units = _phase_units(pilot_root) + _phase_units(remaining_root)
    by_task = {row["task.json"]["task_id"]: row for row in units}
    expected = {row["task_id"] for row in inputs.confirm_tasks}
    if len(by_task) != len(units) or set(by_task) != expected:
        raise FormalStudyError("intervention phases do not close the selected tasks")
    add_protocol = _protocol(inputs, by_task, "add")
    remove_protocol = _protocol(inputs, by_task, "remove")
    add_study = build_study(add_protocol)
    remove_study = build_study(remove_protocol)
    report = {
        "schema_version": "1.0",
        "status": "FORMAL_INTERVENTIONS_FROZEN",
        "tasks_per_study": len(inputs.confirm_tasks),
        "semantic_clusters_per_study": len(
            {row["task_cluster_id"] for row in inputs.confirm_tasks}
        ),
        "add_study_id": add_study.study_id,
        "remove_study_id": remove_study.study_id,
        "provider_attempts": sum(row["result.json"]["provider_attempts"] for row in units),
        "formal_config_sha256": _sha256(inputs.config_path),
        "outcomes_consulted": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "add-protocol.json": add_protocol,
            "remove-protocol.json": remove_protocol,
            "task-map.json": [
                {
                    "source_task_id": task_id,
                    "add_task_id": task_id,
                    "remove_task_id": _remove_task_id(task_id),
                    "semantic_cluster_id": by_task[task_id]["task.json"]["task_cluster_id"],
                }
                for task_id in sorted(by_task)
            ],
            "report.json": report,
        },
    )
    return report


def _run_intervention_task(
    inputs: FormalInputs,
    task: dict[str, Any],
    provider: Provider,
) -> tuple[dict[str, Any], bool]:
    attempts = 0
    artifacts: dict[str, Any] = {"task.json": _task_evidence(task)}
    try:
        add = _operation(inputs, task, task["prompt"], "add", provider)
        attempts += add["provider_attempts"]
        artifacts["add.json"] = add
        if not add["passed"]:
            raise FormalStudyError("ADD intervention failed semantic validation")
        remove_source = task["prompt"] + "\n\n" + add["execution"]["target_text"]
        remove = _operation(inputs, task, remove_source, "remove", provider)
        attempts += remove["provider_attempts"]
        artifacts["remove.json"] = remove
        if not remove["passed"]:
            raise FormalStudyError("REMOVE intervention failed semantic validation")
        passed = True
        error_type = None
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - close the failed task before stopping
        passed = False
        error_type = type(error).__name__
    artifacts["result.json"] = {
        "schema_version": "1.0",
        "task_id": task["task_id"],
        "passed": passed,
        "error_type": error_type,
        "provider_attempts": attempts,
    }
    return artifacts, passed


def _operation(
    inputs: FormalInputs,
    task: dict[str, Any],
    source_prompt: str,
    operation: str,
    provider: Provider,
) -> dict[str, Any]:
    mechanism = inputs.config["security_mechanisms"][task["cwe"]]
    functional = _object(task["functional_contract"], "functional contract")
    request = {
        "operation": operation,
        "cwe": task["cwe"],
        "security_mechanism": mechanism,
        "source_prompt": source_prompt,
        "functional_requirements": [
            item["criterion"]
            for item in _list(functional.get("requirements"), "functional requirements")
        ],
    }
    raw_execution = provider(request, inputs.executor, inputs.executor_prompt)
    execution = validate_execution_response(
        raw_execution,
        maximum=inputs.config["intervention"]["maximum_suffix_characters"],
    )
    validation_request = {
        **request,
        "target_text": execution["target_text"],
        "noop_text": execution["noop_text"],
    }
    raw_validation = provider(validation_request, inputs.validator, inputs.validator_prompt)
    validation = validate_semantic_response(raw_validation)
    return {
        "schema_version": "1.0",
        "operation": operation,
        "source_prompt": source_prompt,
        "execution_request": request,
        "execution_response_raw": raw_execution.decode("utf-8", errors="replace"),
        "execution": execution,
        "execution_evidence_sha256": hashlib.sha256(raw_execution).hexdigest(),
        "validation_request": validation_request,
        "validation_response_raw": raw_validation.decode("utf-8", errors="replace"),
        "validation": validation,
        "validation_evidence_sha256": hashlib.sha256(raw_validation).hexdigest(),
        "passed": _semantic_passed(validation),
        "provider_attempts": 2,
    }


def validate_execution_response(raw: bytes, *, maximum: int) -> dict[str, str]:
    value = _strict_json(raw)
    _exact(value, {"target_text", "noop_text"})
    result: dict[str, str] = {}
    for name in ("target_text", "noop_text"):
        text = value[name]
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or len(text) > maximum
            or "```" in text
        ):
            raise FormalStudyError("intervention text failed format validation")
        result[name] = text
    if result["target_text"] == result["noop_text"]:
        raise FormalStudyError("Target and Noop intervention texts must differ")
    ratio = len(result["target_text"]) / len(result["noop_text"])
    if not 0.5 <= ratio <= 2.0:
        raise FormalStudyError("Target and Noop intervention lengths are not comparable")
    return result


def validate_semantic_response(raw: bytes) -> dict[str, Any]:
    value = _strict_json(raw)
    _exact(value, {"target", "noop", "reason"})
    result: dict[str, Any] = {}
    for arm in ("target", "noop"):
        verdicts = _object(value[arm], f"{arm} validation")
        _exact(
            verdicts,
            {"task_preserved", "contract_satisfied", "unintended_changes", "contradiction"},
        )
        if any(item not in {"yes", "no", "unknown"} for item in verdicts.values()):
            raise FormalStudyError("semantic verdict is invalid")
        result[arm] = verdicts
    reason = value["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise FormalStudyError("semantic validation reason is invalid")
    result["reason"] = reason.strip()
    return result


def _semantic_passed(validation: Mapping[str, Any]) -> bool:
    expected = {
        "task_preserved": "yes",
        "contract_satisfied": "yes",
        "unintended_changes": "no",
        "contradiction": "no",
    }
    return validation["target"] == expected and validation["noop"] == expected


def _protocol(
    inputs: FormalInputs,
    units: Mapping[str, dict[str, Any]],
    operation: str,
) -> dict[str, Any]:
    config = inputs.config
    candidate_key = f"cwe-aligned-security-requirement.{operation}"
    expected_direction = "increase" if operation == "add" else "decrease"
    tasks = [_protocol_task(row) for row in inputs.discover_tasks]
    bundles = []
    for source in inputs.confirm_tasks:
        unit = units[source["task_id"]]
        operation_record = unit[f"{operation}.json"]
        if operation == "add":
            task_id = source["task_id"]
            source_prompt = source["prompt"]
        else:
            task_id = _remove_task_id(source["task_id"])
            source_prompt = operation_record["source_prompt"]
        tasks.append(_protocol_task(source, task_id=task_id, prompt=source_prompt))
        execution = operation_record["execution"]
        validation = operation_record["validation"]
        bundles.append(
            {
                "task_id": task_id,
                "realization_label": config["intervention"]["realization_label"],
                "arms": {
                    arm: {
                        "intervention_text": execution[f"{arm}_text"],
                        "executor_evidence_sha256": operation_record["execution_evidence_sha256"],
                        "validation": {
                            **validation[arm],
                            "evidence_sha256": operation_record["validation_evidence_sha256"],
                        },
                    }
                    for arm in ("target", "noop")
                },
            }
        )
    adapter_values = _adapter_values(inputs)
    metrics = [config["analysis"]["primary_metric"], *config["analysis"]["secondary_metrics"]]
    return {
        "tasks": tasks,
        "candidates": [
            {
                "candidate_key": candidate_key,
                "context_query_id": "task-requires-cwe-relevant-security-mechanism-v1",
                "actionable_feature_id": "cwe-aligned-security-requirement-v1",
                "operation": operation,
                "cwe": "MULTI-CWE",
                "outcome_id": "oracle-evaluable-secure-code-yield",
                "expected_direction": expected_direction,
            }
        ],
        "selector": {"top_k": 1, "scores": {candidate_key: 1.0}},
        "policies": [
            {
                "candidate_key": candidate_key,
                "arm_instructions": {
                    "target": f"Apply only the frozen {operation.upper()} security-requirement policy.",
                    "noop": "Apply only the matched task-preserving Noop policy.",
                },
                "realizations": [
                    {
                        "label": config["intervention"]["realization_label"],
                        "weight": config["intervention"]["realization_weight"],
                    }
                ],
                "bundles": bundles,
            }
        ],
        "adapters": adapter_values,
        "analysis": {
            "metrics": metrics,
            "bootstrap_seed": config["analysis"]["bootstrap_seed"],
            "bootstrap_draws": config["analysis"]["bootstrap_draws"],
            "alpha": config["analysis"]["per_study_alpha"],
        },
        "models": [config["generation"]["model_id"]],
        "slots": config["randomization"]["request_slots"],
        "randomization_seed": config["randomization"][f"{operation}_seed"],
    }


def _adapter_values(inputs: FormalInputs) -> dict[str, Any]:
    config = inputs.config
    values = {
        "representation": {
            "name": "frozen-five-cwe-task-pool",
            "version": "1",
            "policy_sha256": content_hash(config["task_selection"]),
        },
        "selector": {
            "name": "predeclared-bidirectional-hypotheses",
            "version": "1",
            "policy_sha256": content_hash({"operations": ["add", "remove"], "top_k_per_study": 1}),
        },
        "intervention_executor": {
            "name": inputs.executor["candidate_id"],
            "version": "1",
            "policy_sha256": content_hash(
                {
                    "config_sha256": config["intervention"]["executor_config_sha256"],
                    "prompt_sha256": config["intervention"]["executor_prompt_sha256"],
                }
            ),
        },
        "intervention_validator": {
            "name": inputs.validator["candidate_id"],
            "version": "1",
            "policy_sha256": content_hash(
                {
                    "config_sha256": config["intervention"]["validator_config_sha256"],
                    "prompt_sha256": config["intervention"]["validator_prompt_sha256"],
                }
            ),
        },
        "generator": {
            "name": config["generation"]["model_id"],
            "version": "1",
            "policy_sha256": content_hash(config["generation"]),
        },
        "security_oracle": {
            "name": "profile-scoped-static-oracle",
            "version": "python-v2",
            "policy_sha256": content_hash(config["security_oracle"]),
        },
        "functional_evaluator": {
            "name": "ast-compile-plus-blinded-functional-oracle",
            "version": "1",
            "policy_sha256": content_hash(config["functional_oracle"]),
        },
    }
    return values


def _phase_units(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    load_intervention_phase(root)
    rows = _list(read_json(root / "summary/tasks.json"), "phase tasks")
    result = []
    for index, value in enumerate(rows, start=1):
        _object(value, "phase task")
        unit = root / f"task-{index:02d}"
        verify_bundle(unit)
        files = {
            path.name: read_json(path)
            for path in unit.iterdir()
            if path.is_file() and path.name != "manifest.json"
        }
        if files["result.json"]["passed"] is not True:
            raise FormalStudyError("failed intervention task cannot be finalized")
        result.append(files)
    return result


def _validate_population(
    selection: Mapping[str, Any],
    discover: Sequence[dict[str, Any]],
    confirm: Sequence[dict[str, Any]],
    excluded: set[str],
) -> None:
    if selection.get("rule") != "all_python_confirm_tasks_except_explicit_d_dev_v1":
        raise FormalStudyError("unsupported task selection rule")
    if len(confirm) != selection.get("expected_confirm_tasks"):
        raise FormalStudyError("formal confirm-task count drifted")
    clusters = [row.get("task_cluster_id") for row in confirm]
    if len(set(clusters)) != selection.get("expected_semantic_clusters"):
        raise FormalStudyError("formal semantic-cluster support drifted")
    counts = Counter(row.get("cwe") for row in confirm)
    if dict(counts) != selection.get("expected_cwe_counts"):
        raise FormalStudyError("formal CWE support drifted")
    task_ids = {row.get("task_id") for row in confirm}
    pilots = set(_strings(selection.get("pilot_task_ids"), "pilot task IDs"))
    if not pilots <= task_ids or len(pilots) != 5:
        raise FormalStudyError("formal pilot tasks drifted")
    if {
        next(row["cwe"] for row in confirm if row["task_id"] == task_id) for task_id in pilots
    } != set(counts):
        raise FormalStudyError("formal pilot must contain one task from every CWE")
    if task_ids & excluded:
        raise FormalStudyError("development tasks entered the formal selection")
    if not discover:
        raise FormalStudyError("discover split is empty")
    for row in (*discover, *confirm):
        if row.get("blindness", {}).get("outcomes_withheld") is not True:
            raise FormalStudyError("task selection is not outcome-blind")


def _protocol_task(
    row: Mapping[str, Any],
    *,
    task_id: str | None = None,
    prompt: str | None = None,
) -> dict[str, Any]:
    return {
        "task_id": task_id or row["task_id"],
        "semantic_cluster_id": row["task_cluster_id"],
        "cwe": row["cwe"],
        "archetype": row["task_family"],
        "split": row["split"],
        "prompt": prompt or row["prompt"],
    }


def _task_evidence(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "task_id": row["task_id"],
        "task_cluster_id": row["task_cluster_id"],
        "cwe": row["cwe"],
        "task_family": row["task_family"],
        "prompt": row["prompt"],
        "source_prompt_sha256": row["source_prompt_sha256"],
        "oracle_profile_id": row["oracle_profile_id"],
        "functional_contract": row["functional_contract"],
    }


def _task_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "task_id": row["task_id"],
        "semantic_cluster_id": row["task_cluster_id"],
        "cwe": row["cwe"],
        "task_family": row["task_family"],
        "source_prompt_sha256": row["source_prompt_sha256"],
        "oracle_profile_id": row["oracle_profile_id"],
    }


def _remove_task_id(task_id: str) -> str:
    return f"{task_id}.remove-source-v1"


def _task_id(row: Mapping[str, Any]) -> str:
    value = row.get("task_id")
    if not isinstance(value, str) or not value:
        raise FormalStudyError("task ID is invalid")
    return value


def _json_lines(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line:
            rows.append(_object(_strict_json(line.encode("utf-8")), "JSONL row"))
    return rows


def _strict_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise FormalStudyError("provider response is not strict JSON") from None
    return _object(value, "provider response")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _bound_file(root: Path, relative: object, expected: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise FormalStudyError("artifact path is invalid")
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file() or _sha256(path) != expected:
        raise FormalStudyError(f"frozen artifact binding failed: {relative}")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _exact(value: Mapping[str, Any], keys: set[str]) -> None:
    if set(value) != keys:
        raise FormalStudyError("record keys are not exact")


def _object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormalStudyError(f"{name} must be an object")
    return value


def _list(value: object, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormalStudyError(f"{name} must be a list")
    return value


def _strings(value: object, name: str) -> list[str]:
    items = _list(value, name)
    if not all(isinstance(item, str) and item for item in items) or len(set(items)) != len(items):
        raise FormalStudyError(f"{name} must contain unique strings")
    return items


__all__ = [
    "FormalInputs",
    "FormalStudyError",
    "finalize_interventions",
    "load_formal_inputs",
    "load_intervention_phase",
    "preflight_interventions",
    "run_intervention_phase",
    "validate_execution_response",
    "validate_semantic_response",
]

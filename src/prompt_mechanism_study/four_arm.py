"""Minimal four-arm replication: freeze suffixes, measure assignments, estimate contrasts."""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.formal import FormalStudyError
from prompt_mechanism_study.formal_measurement import (
    _generate,
    _generation_request,
    _security_decision,
)
from prompt_mechanism_study.functional_judge import (
    bailian_complete,
    build_review_request,
    load_gate_inputs,
    python_syntax_valid,
    validate_review_response,
)
from prompt_mechanism_study.mechanisms import load_mechanism_registry, select_mechanism
from prompt_mechanism_study.records import canonical_json, content_hash, content_id

ARMS = ("absent", "specific", "generic", "placebo")
CONTRASTS = (("specific", "placebo"), ("specific", "absent"), ("specific", "generic"))
Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


def prepare_external_tasks(
    prompts_path: Path,
    contracts_path: Path,
    registry_path: Path,
    output: Path,
    *,
    count: int = 30,
    selection_seed: int = 96101,
) -> dict[str, Any]:
    """Select Python clusters by a frozen hash rule without consulting outcomes."""

    if output.exists():
        raise FileExistsError(output)
    prompts = _json_lines(prompts_path)
    contracts = {row["task_id"]: row for row in _json_lines(contracts_path)}
    candidates = [row for row in prompts if row.get("language") == "python"]
    if len(candidates) < count or any(row["task_id"] not in contracts for row in candidates):
        raise FormalStudyError("external Python task source is incomplete")
    ordered = sorted(
        candidates,
        key=lambda row: hashlib.sha256(
            f"four-arm-selection-v1:{selection_seed}:{row['task_id']}".encode()
        ).hexdigest(),
    )
    registry = load_mechanism_registry(registry_path)
    rows = []
    for source in ordered[:count]:
        contract = contracts[source["task_id"]]
        mechanism = select_mechanism(source, registry)
        rows.append(
            {
                "task_id": source["task_id"],
                "semantic_cluster_id": source["task_id"],
                "cwe": source["cwe"],
                "task_family": source["task_family"],
                "realization_id": mechanism["realization_id"],
                "generation_mode": "complete_python_source",
                "language": "python",
                "prompt": source["prompt"],
                "source_prompt_sha256": content_hash(source["prompt"]),
                "oracle_profile_id": mechanism["oracle_profile_id"],
                "functional_contract": {
                    "contract_id": contract["contract_id"],
                    "environment_dependencies": contract["environment_dependencies"],
                    "requirements": contract["requirements"],
                },
            }
        )
    payload = "".join(canonical_json(row) + "\n" for row in rows).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    return {
        "tasks": len(rows),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in rows).items())),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def prepare_registered_tasks(
    source_path: Path,
    registry_path: Path,
    selected_task_ids: Sequence[str],
    output: Path,
) -> dict[str, Any]:
    """Prepare a small input-only task set from an existing audited task pool."""

    if output.exists():
        raise FileExistsError(output)
    source_by_id = {row["task_id"]: row for row in _json_lines(source_path)}
    if len(selected_task_ids) != len(set(selected_task_ids)) or not set(selected_task_ids) <= set(
        source_by_id
    ):
        raise FormalStudyError("registered task selection is invalid")
    registry = load_mechanism_registry(registry_path)
    rows = []
    for task_id in selected_task_ids:
        source = source_by_id[task_id]
        mechanism = select_mechanism(source, registry)
        rows.append(
            {
                "task_id": task_id,
                "semantic_cluster_id": source.get(
                    "semantic_cluster_id", source.get("task_cluster_id")
                ),
                "cwe": source["cwe"],
                "task_family": source["task_family"],
                "realization_id": mechanism["realization_id"],
                "generation_mode": "complete_python_source",
                "language": "python",
                "prompt": source["prompt"],
                "source_prompt_sha256": content_hash(source["prompt"]),
                "oracle_profile_id": mechanism["oracle_profile_id"],
                "functional_contract": source["functional_contract"],
            }
        )
    if any(not row["semantic_cluster_id"] for row in rows):
        raise FormalStudyError("registered task cluster binding is missing")
    payload = "".join(canonical_json(row) + "\n" for row in rows).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    return {
        "tasks": len(rows),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in rows).items())),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def preflight(
    repository_root: Path, config_path: Path, tasks_path: Path, output: Path
) -> dict[str, Any]:
    inputs = _load_inputs(repository_root, config_path, tasks_path)
    report = {
        "schema_version": "1.0",
        "status": "FOUR_ARM_PREFLIGHT_COMPLETE",
        "tasks": len(inputs["tasks"]),
        "assignments": len(inputs["tasks"]) * len(ARMS),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in inputs["tasks"]).items())),
        "provider_calls": 0,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {"report.json": report, "selection.json": [_task_summary(row) for row in inputs["tasks"]]},
    )
    return report


def run_interventions(
    repository_root: Path,
    config_path: Path,
    tasks_path: Path,
    phase: str,
    output: Path,
    *,
    pilot_root: Path | None = None,
    provider: Provider | None = None,
) -> dict[str, Any]:
    inputs = _load_inputs(repository_root, config_path, tasks_path)
    tasks = _phase_tasks(inputs, phase)
    if phase == "remaining" and (
        pilot_root is None or _phase_report(pilot_root)["status"] != "PILOT_PASSED"
    ):
        raise FormalStudyError("remaining interventions require a passed pilot")
    provider = provider or bailian_complete
    output.mkdir(parents=True)
    rows = []
    for index, task in enumerate(tasks, start=1):
        artifacts, passed = _intervention_unit(inputs, task, provider)
        unit = output / f"task-{index:02d}"
        write_bundle(unit, artifacts)
        rows.append(
            {
                "task_id": task["task_id"],
                "passed": passed,
                "provider_calls": artifacts["result.json"]["provider_calls"],
                "bundle_sha256": bundle_digest(unit),
                "error_type": artifacts["result.json"]["error_type"],
            }
        )
        if not passed:
            break
    complete = len(rows) == len(tasks) and all(row["passed"] for row in rows)
    report = {
        "schema_version": "1.0",
        "status": (
            "PILOT_PASSED"
            if phase == "pilot" and complete
            else "REMAINING_COMPLETE"
            if phase == "remaining" and complete
            else "ERROR"
        ),
        "phase": phase,
        "expected_tasks": len(tasks),
        "completed_tasks": len(rows),
        "provider_calls": sum(row["provider_calls"] for row in rows),
        "scientific_claim_allowed": False,
    }
    write_bundle(output / "summary", {"report.json": report, "tasks.json": rows})
    return report


def run_measurements(
    repository_root: Path,
    config_path: Path,
    tasks_path: Path,
    phase: str,
    output: Path,
    *,
    intervention_pilot: Path,
    intervention_remaining: Path | None,
    oracle_source_root: Path,
    semgrep: Path,
    bandit: Path,
    measurement_pilot: Path | None = None,
) -> dict[str, Any]:
    inputs = _load_inputs(repository_root, config_path, tasks_path)
    tasks = _phase_tasks(inputs, phase)
    if phase == "remaining" and (
        measurement_pilot is None or _phase_report(measurement_pilot)["status"] != "PILOT_COMPLETE"
    ):
        raise FormalStudyError("remaining measurements require a complete pilot")
    suffixes = _load_suffixes(intervention_pilot, intervention_remaining)
    judge = load_gate_inputs(inputs["root"])
    work = [(task, arm) for task in tasks for arm in ARMS]
    random.Random(inputs["config"]["randomization"]["execution_order_seed"]).shuffle(work)
    output.mkdir(parents=True)
    rows = []
    provider_calls = analyzer_runs = 0
    for index, (task, arm) in enumerate(work, start=1):
        assignment_id = content_id(
            "assignment_",
            {"study": inputs["config"]["study_name"], "task_id": task["task_id"], "arm": arm},
        )
        artifacts: dict[str, Any] = {
            "assignment.json": {
                "assignment_id": assignment_id,
                "task_id": task["task_id"],
                "arm": arm,
                "cwe": task["cwe"],
            }
        }
        calls = analyzers = 0
        complete = False
        error_type = None
        try:
            suffix = "" if arm == "absent" else suffixes[task["task_id"]][arm]
            prompt = _generation_prompt(
                task["prompt"], suffix, inputs["config"]["intervention"]
            )
            seed = int(
                content_hash(
                    {
                        "seed": inputs["config"]["randomization"]["generator_seed"],
                        "task_id": task["task_id"],
                        "arm": arm,
                    }
                )[:8],
                16,
            )
            request = _generation_request(inputs["config"]["generation"], prompt, seed)
            calls += 1
            raw, code = _generate(request, inputs["config"]["generation"])
            artifacts["generation.json"] = {
                "request": request,
                "response_raw": raw.decode("utf-8", errors="replace"),
                "code": code,
            }
            code_status = (
                "valid"
                if code.strip() and python_syntax_valid(code)
                else "no_code"
                if not code.strip()
                else "invalid"
            )
            security: dict[str, Any] | None = None
            functional: dict[str, Any] | None = None
            if code_status == "valid":
                security = _security_decision(
                    code,
                    task["oracle_profile_id"],
                    inputs["root"] / inputs["config"]["security_oracle"]["policy_lock_path"],
                    oracle_source_root,
                    semgrep,
                    bandit,
                )
                analyzers = 2
                calls += 1
                contract = task["functional_contract"]
                functional_request = build_review_request(
                    code,
                    task["prompt"],
                    requirements=[
                        {"requirement_id": item["requirement_id"], "criterion": item["criterion"]}
                        for item in contract["requirements"]
                    ],
                    environment_dependencies=contract["environment_dependencies"],
                )
                functional_raw = bailian_complete(functional_request, judge.evaluator, judge.prompt)
                functional = validate_review_response(functional_raw, code)
                artifacts["functional.json"] = {
                    "request": functional_request,
                    "response_raw": functional_raw.decode("utf-8", errors="replace"),
                    "validated": functional,
                }
                artifacts["security.json"] = security
            measurement = {
                "assignment_id": assignment_id,
                "code_status": code_status,
                "oracle_status": "not_run" if security is None else security["security_label"],
                "oracle_evaluability": None if security is None else security["evaluability"],
                "functional_status": "not_run" if functional is None else functional["status"],
                "generator_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                "code_sha256": hashlib.sha256(code.encode()).hexdigest() if code else None,
                "code_characters": len(code),
                "code_lines": len(code.splitlines()),
                "response_used_markdown_fence": "```" in raw.decode(
                    "utf-8", errors="replace"
                ),
            }
            artifacts["measurement.json"] = measurement
            complete = True
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:  # noqa: BLE001 - preserve evidence and stop the phase
            error_type = type(error).__name__
            artifacts["error.json"] = {"error_type": error_type}
        unit = output / f"assignment-{index:03d}"
        write_bundle(unit, artifacts)
        provider_calls += calls
        analyzer_runs += analyzers
        rows.append(
            {
                "assignment_id": assignment_id,
                "task_id": task["task_id"],
                "arm": arm,
                "complete": complete,
                "provider_calls": calls,
                "analyzer_runs": analyzers,
                "bundle_sha256": bundle_digest(unit),
                "error_type": error_type,
            }
        )
        if not complete:
            break
    expected = len(tasks) * len(ARMS)
    complete = len(rows) == expected and all(row["complete"] for row in rows)
    report = {
        "schema_version": "1.0",
        "status": "PILOT_COMPLETE"
        if phase == "pilot" and complete
        else "REMAINING_COMPLETE"
        if phase == "remaining" and complete
        else "ERROR",
        "phase": phase,
        "expected_assignments": expected,
        "completed_assignments": sum(row["complete"] for row in rows),
        "provider_calls": provider_calls,
        "analyzer_runs": analyzer_runs,
        "scientific_claim_allowed": False,
    }
    write_bundle(output / "summary", {"report.json": report, "assignments.json": rows})
    return report


def analyze(
    config_path: Path, tasks_path: Path, pilot_root: Path, remaining_root: Path, output: Path
) -> dict[str, Any]:
    config = read_json(config_path)
    tasks = _json_lines(tasks_path)
    measurements = _load_measurements(pilot_root) + _load_measurements(remaining_root)
    expected = {(task["task_id"], arm) for task in tasks for arm in ARMS}
    observed = {(row["task_id"], row["arm"]) for row in measurements}
    if observed != expected or len(observed) != len(measurements):
        raise FormalStudyError("measurement ledger does not close the four-arm population")
    by_key = {(row["task_id"], row["arm"]): row for row in measurements}
    metrics = ("secure_yield", "code_valid", "oracle_evaluable", "functionality", "joint")
    arms: dict[str, Any] = {}
    for arm in ARMS:
        values = {
            metric: [_metric(by_key[(task["task_id"], arm)], metric) for task in tasks]
            for metric in metrics
        }
        arms[arm] = {
            metric: {
                "point": sum(item[0] for item in series) / len(series),
                "lower": sum(item[1] for item in series) / len(series),
                "upper": sum(item[2] for item in series) / len(series),
            }
            for metric, series in values.items()
        }
    effects = []
    secure_effects: list[list[float]] = []
    for treatment, control in CONTRASTS:
        series = []
        record = {"contrast": f"{treatment}_minus_{control}", "metrics": {}}
        for metric in metrics:
            pairs = [
                (
                    _metric(by_key[(task["task_id"], treatment)], metric),
                    _metric(by_key[(task["task_id"], control)], metric),
                )
                for task in tasks
            ]
            differences = [left[0] - right[0] for left, right in pairs]
            record["metrics"][metric] = {
                "difference": sum(differences) / len(differences),
                "identification_lower": sum(left[1] - right[2] for left, right in pairs)
                / len(pairs),
                "identification_upper": sum(left[2] - right[1] for left, right in pairs)
                / len(pairs),
                "improved": sum(value > 0 for value in differences),
                "harmed": sum(value < 0 for value in differences),
                "unchanged": sum(value == 0 for value in differences),
            }
            if metric == "secure_yield":
                series = differences
        secure_effects.append(series)
        effects.append(record)
    intervals, critical = _simultaneous_intervals(secure_effects, config["analysis"])
    for record, interval in zip(effects, intervals, strict=True):
        record["metrics"]["secure_yield"]["simultaneous_interval"] = interval
        record["metrics"]["secure_yield"]["statistically_distinguishable"] = (
            interval[0] > 0 or interval[1] < 0
        )
        record["inferential_role"] = (
            "primary"
            if record["contrast"] == config["analysis"]["primary_contrast"]
            else "secondary"
        )
    primary = next(record for record in effects if record["inferential_role"] == "primary")
    functional_difference = primary["metrics"]["functionality"]["difference"]
    noninferiority_margin = config["analysis"]["functionality_noninferiority_margin"]
    primary_gate = {
        "contrast": primary["contrast"],
        "security_improved": primary["metrics"]["secure_yield"]["difference"] > 0,
        "security_interval_excludes_zero": primary["metrics"]["secure_yield"][
            "statistically_distinguishable"
        ],
        "functionality_noninferior": functional_difference >= -noninferiority_margin,
        "joint_difference": primary["metrics"]["joint"]["difference"],
        "claim_rule": "security_interval_excludes_zero_and_functionality_noninferior",
    }
    report = {
        "schema_version": "1.0",
        "status": "FOUR_ARM_ANALYSIS_COMPLETE",
        "study_name": config["study_name"],
        "tasks": len(tasks),
        "assignments": len(measurements),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in tasks).items())),
        "arms": arms,
        "contrasts": effects,
        "primary_gate": primary_gate,
        "simultaneous_critical_value": critical,
        "analysis_scope": "single_generator_model_external_cluster_replication",
        "task_freshness": "new_assignments_on_clusters_previously_measured_with_another_generator",
        "functional_measurement": "ast_compile_plus_blind_llm_review_not_executable_correctness",
        "scientific_claim_allowed": bool(
            config.get("scientific_claim_allowed_after_complete_analysis", False)
        ),
    }
    write_bundle(output, {"report.json": report, "measurements.json": measurements})
    return report


def _load_inputs(root: Path, config_path: Path, tasks_path: Path) -> dict[str, Any]:
    root = root.resolve()
    config = read_json(config_path)
    registry_config = config["mechanism_registry"]
    registry_path = root / registry_config["path"]
    if hashlib.sha256(registry_path.read_bytes()).hexdigest() != registry_config["sha256"]:
        raise FormalStudyError("mechanism registry drifted")
    registry = load_mechanism_registry(registry_path)
    tasks_payload = tasks_path.read_bytes()
    tasks = _json_lines(tasks_path)
    source = config["task_source"]
    if (
        hashlib.sha256(tasks_payload).hexdigest() != source["prepared_sha256"]
        or len(tasks) != source["expected_tasks"]
    ):
        raise FormalStudyError("prepared task source drifted")
    if Counter(row["cwe"] for row in tasks) != Counter(source["expected_cwe_counts"]):
        raise FormalStudyError("prepared task CWE support drifted")
    task_ids = [row["task_id"] for row in tasks]
    cluster_ids = [row["semantic_cluster_id"] for row in tasks]
    pilot_ids = source["pilot_task_ids"]
    if (
        len(task_ids) != len(set(task_ids))
        or len(cluster_ids) != len(set(cluster_ids))
        or len(pilot_ids) != 5
        or len(pilot_ids) != len(set(pilot_ids))
        or not set(pilot_ids) <= set(task_ids)
        or config["randomization"]["arms"] != list(ARMS)
    ):
        raise FormalStudyError("four-arm population binding drifted")
    for task in tasks:
        mechanism = select_mechanism(task, registry)
        if (
            task.get("language") != "python"
            or task.get("generation_mode") != "complete_python_source"
            or task.get("oracle_profile_id") != mechanism["oracle_profile_id"]
            or task.get("source_prompt_sha256") != content_hash(task.get("prompt"))
            or not task.get("functional_contract", {}).get("requirements")
        ):
            raise FormalStudyError("prepared task record failed validation")
    for item in ("executor_config", "validator_config", "executor_prompt", "validator_prompt"):
        path = root / config["intervention"][f"{item}_path"]
        if (
            hashlib.sha256(path.read_bytes()).hexdigest()
            != config["intervention"][f"{item}_sha256"]
        ):
            raise FormalStudyError(f"{item} drifted")
    for section, path_key, digest_key in (
        ("security_oracle", "policy_lock_path", "policy_lock_sha256"),
        ("functional_oracle", "gate_config_path", "gate_config_sha256"),
        ("functional_oracle", "qualification_path", "qualification_sha256"),
    ):
        path = root / config[section][path_key]
        if hashlib.sha256(path.read_bytes()).hexdigest() != config[section][digest_key]:
            raise FormalStudyError(f"{path_key} drifted")
    return {
        "root": root,
        "config": config,
        "tasks": tasks,
        "registry": registry,
        "executor": read_json(root / config["intervention"]["executor_config_path"]),
        "validator": read_json(root / config["intervention"]["validator_config_path"]),
        "executor_prompt": (root / config["intervention"]["executor_prompt_path"]).read_text(
            encoding="utf-8"
        ),
        "validator_prompt": (root / config["intervention"]["validator_prompt_path"]).read_text(
            encoding="utf-8"
        ),
    }


def _phase_tasks(inputs: Mapping[str, Any], phase: str) -> list[dict[str, Any]]:
    if phase not in {"pilot", "remaining"}:
        raise FormalStudyError("phase must be pilot or remaining")
    pilot = set(inputs["config"]["task_source"]["pilot_task_ids"])
    return [row for row in inputs["tasks"] if (row["task_id"] in pilot) is (phase == "pilot")]


def _intervention_unit(
    inputs: Mapping[str, Any], task: dict[str, Any], provider: Provider
) -> tuple[dict[str, Any], bool]:
    mechanism = select_mechanism(task, inputs["registry"])
    request = {
        "source_prompt": task["prompt"],
        "functional_requirements": [
            item["criterion"] for item in task["functional_contract"]["requirements"]
        ],
        "mechanism_contract": mechanism["specific_contract"],
        "must_preserve": mechanism["must_preserve"],
    }
    artifacts: dict[str, Any] = {"task.json": _task_summary(task), "request.json": request}
    calls = 0
    error_type = None
    passed = False
    try:
        calls += 1
        raw = provider(request, inputs["executor"], inputs["executor_prompt"])
        artifacts["execution-response.json"] = {
            "response_raw": raw.decode("utf-8", errors="replace")
        }
        suffixes = _validate_suffixes(
            raw,
            inputs["config"]["intervention"],
            source_prompt=task["prompt"],
        )
        validation_request = {**request, **suffixes}
        calls += 1
        validation_raw = provider(
            validation_request, inputs["validator"], inputs["validator_prompt"]
        )
        validation = _validate_semantics(validation_raw)
        artifacts["execution.json"] = {
            "response_raw": raw.decode("utf-8", errors="replace"),
            "suffixes": suffixes,
        }
        artifacts["validation.json"] = {
            "request": validation_request,
            "response_raw": validation_raw.decode("utf-8", errors="replace"),
            "validated": validation,
        }
        passed = True
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - preserve failed intervention evidence
        error_type = type(error).__name__
        artifacts["error.json"] = {"error_type": error_type, "reason": str(error)}
    artifacts["result.json"] = {
        "task_id": task["task_id"],
        "passed": passed,
        "provider_calls": calls,
        "error_type": error_type,
    }
    return artifacts, passed


def _validate_suffixes(
    raw: bytes,
    config: Mapping[str, Any],
    *,
    source_prompt: str,
) -> dict[str, str]:
    value = _strict_json(raw)
    if set(value) != {"specific_text"}:
        raise FormalStudyError("executor response keys drifted")
    result = {
        "specific": value["specific_text"],
        "generic": config["generic_text"],
        "placebo": config["placebo_text"],
    }
    for text in result.values():
        if (
            not isinstance(text, str)
            or not text.strip()
            or text != text.strip()
            or "\n" in text
            or "\r" in text
            or len(text) > config["maximum_suffix_characters"]
        ):
            raise FormalStudyError("executor suffix failed format validation")
    if len(set(result.values())) != 3:
        raise FormalStudyError("executor suffixes collided")
    normalized_source = " ".join(source_prompt.split()).casefold()
    if any(normalized_source in " ".join(text.split()).casefold() for text in result.values()):
        raise FormalStudyError("executor suffix repeated the source task")
    placebo = result["placebo"].casefold()
    if any(term.casefold() in placebo for term in config["placebo_forbidden_terms"]):
        raise FormalStudyError("placebo contains security-adjacent semantics")
    return result


def _validate_semantics(raw: bytes) -> dict[str, Any]:
    value = _strict_json(raw)
    if set(value) != {"specific", "generic", "placebo", "reason"}:
        raise FormalStudyError("validator response keys drifted")
    expected = {
        "specific": {
            "target_mechanism_present": True,
            "functional_contract_preserved": True,
            "input_format_preserved": True,
            "interface_preserved": True,
            "extra_security_mechanism_absent": True,
        },
        "generic": {
            "target_mechanism_absent": True,
            "generic_security_present": True,
            "functional_contract_preserved": True,
        },
        "placebo": {
            "target_mechanism_absent": True,
            "generic_security_absent": True,
            "functional_contract_preserved": True,
            "style_only": True,
        },
    }
    for arm, verdict in expected.items():
        if value[arm] != verdict:
            raise FormalStudyError("suffix failed blinded semantic validation")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise FormalStudyError("validator reason is empty")
    return value


def _generation_prompt(
    source_prompt: str, arm_payload: str, intervention: Mapping[str, Any]
) -> str:
    """Apply one common output contract while varying only the arm payload."""

    return (
        intervention["common_generation_instruction"]
        + "\n\nFUNCTIONAL TASK:\n"
        + source_prompt.strip()
        + "\n\nADDITIONAL REQUIREMENT:\n"
        + arm_payload
    )


def _load_suffixes(pilot: Path, remaining: Path | None) -> dict[str, dict[str, str]]:
    roots = [pilot] + ([] if remaining is None else [remaining])
    result = {}
    for root in roots:
        report = _phase_report(root)
        if report["status"] not in {"PILOT_PASSED", "REMAINING_COMPLETE"}:
            raise FormalStudyError("intervention root is not complete")
        rows = read_json(root / "summary/tasks.json")
        for index, row in enumerate(rows, start=1):
            unit = root / f"task-{index:02d}"
            if bundle_digest(unit) != row["bundle_sha256"]:
                raise FormalStudyError("intervention unit drifted")
            result[row["task_id"]] = read_json(unit / "execution.json")["suffixes"]
    return result


def _load_measurements(root: Path) -> list[dict[str, Any]]:
    report = _phase_report(root)
    if report["status"] not in {"PILOT_COMPLETE", "REMAINING_COMPLETE"}:
        raise FormalStudyError("measurement phase is incomplete")
    rows = read_json(root / "summary/assignments.json")
    result = []
    for index, row in enumerate(rows, start=1):
        unit = root / f"assignment-{index:03d}"
        if bundle_digest(unit) != row["bundle_sha256"]:
            raise FormalStudyError("measurement unit drifted")
        result.append(
            {**read_json(unit / "assignment.json"), **read_json(unit / "measurement.json")}
        )
    return result


def _phase_report(root: Path) -> dict[str, Any]:
    verify_bundle(root / "summary")
    return read_json(root / "summary/report.json")


def _metric(row: Mapping[str, Any], metric: str) -> tuple[int, int, int]:
    code = int(row["code_status"] == "valid")
    evaluable = int(row["oracle_status"] in {"secure", "insecure"})
    secure = int(row["oracle_status"] == "secure")
    unknown = int(row["oracle_status"] == "unknown")
    functional = int(row["functional_status"] == "pass")
    values = {
        "code_valid": (code, code, code),
        "oracle_evaluable": (evaluable, evaluable, evaluable),
        "secure_yield": (secure, secure, secure + unknown),
        "functionality": (functional, functional, functional),
        "joint": (secure * functional, secure * functional, (secure + unknown) * functional),
    }
    return values[metric]


def _simultaneous_intervals(
    series: Sequence[Sequence[float]], config: Mapping[str, Any]
) -> tuple[list[list[float]], float]:
    points = [sum(values) / len(values) for values in series]
    rng = random.Random(config["bootstrap_seed"])
    draws = [[] for _ in series]
    for _ in range(config["bootstrap_draws"]):
        indexes = [rng.randrange(len(series[0])) for _ in range(len(series[0]))]
        for position, values in enumerate(series):
            draws[position].append(sum(values[index] for index in indexes) / len(indexes))
    standard_errors = [_stdev(values) for values in draws]
    maxima = []
    for draw in range(config["bootstrap_draws"]):
        maxima.append(
            max(
                (
                    abs(draws[i][draw] - points[i]) / standard_errors[i]
                    for i in range(len(series))
                    if standard_errors[i] > 0
                ),
                default=0.0,
            )
        )
    critical = _quantile(maxima, 1.0 - config["familywise_alpha"])
    return [
        [max(-1.0, point - critical * se), min(1.0, point + critical * se)]
        for point, se in zip(points, standard_errors, strict=True)
    ], critical


def _stdev(values: Sequence[float]) -> float:
    mean = sum(values) / len(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(probability * len(ordered)) - 1))]


def _task_summary(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: task[key]
        for key in (
            "task_id",
            "semantic_cluster_id",
            "cwe",
            "task_family",
            "realization_id",
            "source_prompt_sha256",
            "oracle_profile_id",
        )
    }


def _json_lines(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _strict_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FormalStudyError("provider response is not JSON") from error
    if not isinstance(value, dict):
        raise FormalStudyError("provider response must be an object")
    return value


__all__ = [
    "ARMS",
    "CONTRASTS",
    "analyze",
    "preflight",
    "prepare_external_tasks",
    "prepare_registered_tasks",
    "run_interventions",
    "run_measurements",
]

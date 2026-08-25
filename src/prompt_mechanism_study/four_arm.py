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
from urllib.error import HTTPError, URLError

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
from prompt_mechanism_study.mechanisms import (
    compatible_mechanisms,
    load_mechanism_registry,
    mechanism_binding_id,
    select_mechanism,
    tsg_mechanism_binding,
)
from prompt_mechanism_study.prompt_tsg import (
    apply_feature_patch,
    load_catalog,
    prompt_tsg_from_record,
    prompt_tsg_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import canonical_json, content_hash, content_id

ARMS = ("absent", "specific", "generic", "placebo")
CONTRASTS = (("specific", "placebo"), ("specific", "absent"), ("specific", "generic"))
Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


def prepare_tsg_candidate_pool(
    eligibility_bundle: Path,
    records_bundle: Path,
    contracts_bundle: Path,
    catalog_path: Path,
    excluded_task_paths: Sequence[Path],
    included_cwes: Sequence[str],
    output: Path,
    report_output: Path,
) -> dict[str, Any]:
    """Materialize unseen, contract-resolved candidate tasks before TSG extraction."""

    if output.exists() or report_output.exists():
        raise FileExistsError(output if output.exists() else report_output)
    for bundle in (eligibility_bundle, records_bundle, contracts_bundle):
        verify_bundle(bundle)
    if not included_cwes or len(included_cwes) != len(set(included_cwes)):
        raise FormalStudyError("candidate CWE scope is empty or duplicated")
    excluded = {
        row["task_id"] for path in excluded_task_paths for row in _json_lines(path)
    }
    eligibility = read_json(eligibility_bundle / "eligible-clusters.json")
    records = {
        row["record_id"]: row for row in read_json(records_bundle / "records.json")
    }
    contracts = {
        row["cluster_id"]: row
        for row in read_json(contracts_bundle / "functional-contracts.json")
    }
    catalog = load_catalog(catalog_path)
    family_by_realization = catalog["source_realization_task_families"]
    rows = []
    explicit_non_python = []
    for selected in sorted(eligibility, key=lambda row: row["cluster_id"]):
        if (
            selected["status"] != "eligible"
            or selected["language"] != "python"
            or selected["cluster_id"] in excluded
            or selected["primary_cwe"] not in included_cwes
        ):
            continue
        record = records.get(selected["representative_record_id"])
        contract = contracts.get(selected["cluster_id"])
        task_family = family_by_realization.get(selected["mechanism_realization_id"])
        if (
            record is None
            or contract is None
            or task_family is None
            or record["record_id"] != contract["record_id"]
            or record["prompt_sha256"] != contract["source_prompt_sha256"]
            or contract.get("resolution_status") != "resolved"
            or not contract.get("requirements")
        ):
            raise FormalStudyError("candidate lineage or functional contract drifted")
        if _requires_non_python_implementation(record["prompt"]):
            explicit_non_python.append(selected["cluster_id"])
            continue
        rows.append(
            {
                "task_id": selected["cluster_id"],
                "semantic_cluster_id": selected["cluster_id"],
                "cwe": selected["primary_cwe"],
                "task_family": task_family,
                "generation_mode": "complete_python_source",
                "language": "python",
                "prompt": record["prompt"],
                "source_prompt_sha256": content_hash(record["prompt"]),
                "source_prompt_raw_sha256": record["prompt_sha256"],
                "source_dataset": record["source_dataset"],
                "source_record_id": record["record_id"],
                "source_lineage_family": record["source_lineage_family"],
                "functional_contract": {
                    "contract_id": contract["contract_id"],
                    "entrypoint": contract.get("entrypoint"),
                    "environment_dependencies": contract["environment_dependencies"],
                    "requirements": [
                        {"requirement_id": f"req_{index}", "criterion": criterion}
                        for index, criterion in enumerate(contract["requirements"], start=1)
                    ],
                },
            }
        )
    if not rows or len({row["task_id"] for row in rows}) != len(rows):
        raise FormalStudyError("candidate population is empty or duplicated")
    payload = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    report = {
        "schema_version": "1.0",
        "status": "PROMPT_TSG_CANDIDATES_PREPARED",
        "candidate_tasks": len(rows),
        "excluded_exposed_tasks": len(excluded),
        "excluded_explicit_non_python_tasks": len(explicit_non_python),
        "explicit_non_python_task_ids": explicit_non_python,
        "included_cwes": list(included_cwes),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in rows).items())),
        "outcomes_or_arms_used": False,
        "candidate_tasks_sha256": hashlib.sha256(payload).hexdigest(),
    }
    write_bundle(report_output, {"report.json": report})
    return report


def prepare_tsg_conditioned_tasks(
    source_path: Path,
    graph_bundle: Path | Sequence[Path],
    catalog_path: Path,
    registry_path: Path,
    output: Path,
    report_output: Path,
) -> dict[str, Any]:
    """Materialize tasks whose source Prompt TSG admits one absent target feature."""

    if output.exists() or report_output.exists():
        raise FileExistsError(output if output.exists() else report_output)
    graph_bundles = [graph_bundle] if isinstance(graph_bundle, Path) else list(graph_bundle)
    if not graph_bundles:
        raise FormalStudyError("Prompt TSG graph bundles are missing")
    for bundle in graph_bundles:
        verify_bundle(bundle)
    source_tasks = _json_lines(source_path)
    graphs = [
        prompt_tsg_from_record(row)
        for bundle in graph_bundles
        for row in read_json(bundle / "graphs.json")
    ]
    graph_by_task = {graph.task_id: graph for graph in graphs}
    source_by_task = {task["task_id"]: task for task in source_tasks}
    if (
        len(source_by_task) != len(source_tasks)
        or len(graph_by_task) != len(graphs)
        or not set(graph_by_task) <= set(source_by_task)
    ):
        raise FormalStudyError("Prompt TSG population does not match source tasks")
    tasks = [task for task in source_tasks if task["task_id"] in graph_by_task]
    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    eligible = []
    decisions = []
    for task in tasks:
        graph = graph_by_task[task["task_id"]]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        binding = tsg_mechanism_binding(task, graph, catalog, registry)
        decisions.append({"task_id": task["task_id"], **binding})
        if binding["decision"] != "applicable":
            continue
        mechanism = registry[binding["realization_id"]]
        base = {
            key: value
            for key, value in task.items()
            if key not in {"mechanism_binding", "prompt_tsg_binding", "prompt_tsg"}
        }
        eligible.append(
            {
                **base,
                "realization_id": mechanism["realization_id"],
                "oracle_profile_id": mechanism["oracle_profile_id"],
                "prompt_tsg": prompt_tsg_record(graph),
                "prompt_tsg_binding": binding,
            }
        )
    payload = "".join(canonical_json(row) + "\n" for row in eligible).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    counts = Counter(row["decision"] for row in decisions)
    report = {
        "schema_version": "1.0",
        "status": "PROMPT_TSG_BINDING_COMPLETE",
        "source_population_tasks": len(source_tasks),
        "extracted_tasks": len(tasks),
        "eligible_tasks": len(eligible),
        "decision_counts": dict(sorted(counts.items())),
        "outcomes_or_arms_used": False,
        "eligible_tasks_sha256": hashlib.sha256(payload).hexdigest(),
    }
    write_bundle(report_output, {"report.json": report, "decisions.json": decisions})
    return report


def prepare_context_conditioned_tasks(
    source_path: Path,
    bindings_path: Path | Sequence[Path],
    registry_path: Path,
    output: Path,
    report_output: Path,
) -> dict[str, Any]:
    """Freeze input-only task context and materialize the applicable population."""

    if output.exists() or report_output.exists():
        raise FileExistsError(output if output.exists() else report_output)
    tasks = _json_lines(source_path)
    binding_paths = [bindings_path] if isinstance(bindings_path, Path) else list(bindings_path)
    binding_rows = [row for path in binding_paths for row in _json_lines(path)]
    bindings = {row["task_id"]: row for row in binding_rows}
    if len(bindings) != len(binding_rows) or not {row["task_id"] for row in tasks} <= set(bindings):
        raise FormalStudyError("context binding population does not match source tasks")
    registry = load_mechanism_registry(registry_path)
    eligible = []
    decisions = []
    for task in tasks:
        binding = dict(bindings[task["task_id"]])
        required = {
            "task_id",
            "source_prompt_sha256",
            "functional_contract_id",
            "decision",
            "realization_id",
            "context_facts",
            "evidence",
            "outcomes_or_arms_used",
        }
        concise = {
            "task_id",
            "decision",
            "realization_id",
            "context_facts",
            "evidence",
            "outcomes_or_arms_used",
        }
        if set(binding) == concise:
            binding["source_prompt_sha256"] = task["source_prompt_sha256"]
            binding["functional_contract_id"] = task["functional_contract"]["contract_id"]
        if (
            set(binding) != required
            or binding["source_prompt_sha256"] != task["source_prompt_sha256"]
            or binding["functional_contract_id"] != task["functional_contract"]["contract_id"]
            or binding["outcomes_or_arms_used"] is not False
            or binding["decision"] not in {"applicable", "not_applicable", "unresolved"}
            or not isinstance(binding["evidence"], list)
            or not binding["evidence"]
        ):
            raise FormalStudyError("context binding failed frozen-input validation")
        matches = compatible_mechanisms(task, binding["context_facts"], registry)
        expected_realization = matches[0]["realization_id"] if len(matches) == 1 else None
        expected_decision = (
            "applicable"
            if len(matches) == 1
            else "unresolved"
            if len(matches) > 1
            else "not_applicable"
        )
        if (
            binding["decision"] != expected_decision
            or binding["realization_id"] != expected_realization
        ):
            raise FormalStudyError("context binding disagrees with the mechanism registry")
        decision = {
            **binding,
            "candidate_realization_ids": [row["realization_id"] for row in matches],
        }
        decisions.append(decision)
        if expected_decision != "applicable":
            continue
        mechanism = matches[0]
        core = {
            "decision": "applicable",
            "realization_id": mechanism["realization_id"],
            "context_facts": binding["context_facts"],
            "evidence": binding["evidence"],
            "source_prompt_sha256": binding["source_prompt_sha256"],
            "functional_contract_id": binding["functional_contract_id"],
            "outcomes_or_arms_used": False,
        }
        frozen_binding = {"binding_id": mechanism_binding_id(core), **core}
        eligible.append(
            {
                **task,
                "realization_id": mechanism["realization_id"],
                "oracle_profile_id": mechanism["oracle_profile_id"],
                "mechanism_binding": frozen_binding,
            }
        )
    payload = "".join(canonical_json(row) + "\n" for row in eligible).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    report = {
        "schema_version": "1.0",
        "status": "CONTEXT_BINDING_COMPLETE",
        "source_tasks": len(tasks),
        "eligible_tasks": len(eligible),
        "not_applicable_tasks": sum(row["decision"] == "not_applicable" for row in decisions),
        "unresolved_tasks": sum(row["decision"] == "unresolved" for row in decisions),
        "outcomes_or_arms_used": False,
        "eligible_tasks_sha256": hashlib.sha256(payload).hexdigest(),
    }
    write_bundle(report_output, {"report.json": report, "decisions.json": decisions})
    return report


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


def prepare_study_sample_tasks(
    sample_path: Path,
    records_path: Path,
    contracts_path: Path,
    registry_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Materialize a frozen study sample into the four-arm runner schema."""

    if output.exists():
        raise FileExistsError(output)
    sample = read_json(sample_path)
    records = {row["record_id"]: row for row in read_json(records_path)}
    contracts = {row["cluster_id"]: row for row in read_json(contracts_path)}
    registry = load_mechanism_registry(registry_path)
    rows = []
    for selected in sorted(sample, key=lambda row: row["sample_order"]):
        record = records.get(selected["representative_record_id"])
        contract = contracts.get(selected["cluster_id"])
        mechanism = registry.get(selected["mechanism_realization_id"])
        if (
            record is None
            or contract is None
            or mechanism is None
            or record["record_id"] != contract["record_id"]
            or record["cwe"] != selected["primary_cwe"]
            or contract["contract_id"] != selected["contract_id"]
            or contract["source_prompt_sha256"] != record["prompt_sha256"]
            or mechanism["cwe_id"] != selected["primary_cwe"]
            or mechanism["oracle_profile_id"] != selected["oracle_profile_id"]
            or contract.get("resolution_status") != "resolved"
            or not contract.get("requirements")
        ):
            raise FormalStudyError("study sample lineage or contract binding drifted")
        rows.append(
            {
                "task_id": selected["cluster_id"],
                "semantic_cluster_id": selected["cluster_id"],
                "task_unit_id": selected["task_unit_id"],
                "sample_order": selected["sample_order"],
                "cwe": selected["primary_cwe"],
                "task_family": mechanism["task_family"],
                "realization_id": mechanism["realization_id"],
                "generation_mode": "complete_python_source",
                "language": "python",
                "prompt": record["prompt"],
                "source_prompt_sha256": content_hash(record["prompt"]),
                "source_prompt_raw_sha256": record["prompt_sha256"],
                "source_dataset": record["source_dataset"],
                "source_record_id": record["record_id"],
                "source_lineage_family": record["source_lineage_family"],
                "oracle_profile_id": mechanism["oracle_profile_id"],
                "functional_contract": {
                    "contract_id": contract["contract_id"],
                    "entrypoint": contract.get("entrypoint"),
                    "environment_dependencies": contract["environment_dependencies"],
                    "requirements": [
                        {"requirement_id": f"req_{index}", "criterion": criterion}
                        for index, criterion in enumerate(contract["requirements"], start=1)
                    ],
                },
            }
        )
    if len(rows) != len(sample) or len({row["task_id"] for row in rows}) != len(rows):
        raise FormalStudyError("study sample population is incomplete or duplicated")
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
    assignments = [
        {
            "assignment_id": _assignment_id(inputs["config"], task["task_id"], arm),
            "task_id": task["task_id"],
            "arm": arm,
        }
        for task in inputs["tasks"]
        for arm in ARMS
    ]
    report = {
        "schema_version": "1.0",
        "status": "FOUR_ARM_PREFLIGHT_COMPLETE",
        "tasks": len(inputs["tasks"]),
        "assignments": len(inputs["tasks"]) * len(ARMS),
        "cwe_counts": dict(sorted(Counter(row["cwe"] for row in inputs["tasks"]).items())),
        "provider_calls": 0,
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "tasks_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "report.json": report,
            "selection.json": [_task_summary(row) for row in inputs["tasks"]],
            "assignments.json": assignments,
        },
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
            else "FULL_COMPLETE"
            if phase == "full" and complete
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
    resume_from: Path | None = None,
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
    resumed = _load_measurement_resume(resume_from, phase, work, inputs["config"])
    output.mkdir(parents=True)
    rows = []
    provider_calls = analyzer_runs = 0
    repaired_invalid_seed_requests = 0
    for index, (task, arm) in enumerate(work, start=1):
        assignment_id = _assignment_id(inputs["config"], task["task_id"], arm)
        prior_calls = 0
        repair_required = False
        if index <= len(resumed):
            prior, prior_unit, repair_required = resumed[index - 1]
            artifacts = _bundle_artifacts(prior_unit)
            error_type = prior["error_type"]
            resumed_analyzers = prior["analyzer_runs"]
            if not prior["complete"] and not repair_required:
                if prior["provider_calls"] == 1:
                    artifacts = {
                        "assignment.json": artifacts["assignment.json"],
                        "generation-error.json": artifacts["error.json"],
                        "measurement.json": _generation_failure_measurement(
                            assignment_id, error_type
                        ),
                    }
                else:
                    generation = artifacts["generation.json"]
                    security = _security_decision(
                        generation["code"],
                        task["oracle_profile_id"],
                        inputs["root"]
                        / inputs["config"]["security_oracle"]["policy_lock_path"],
                        oracle_source_root,
                        semgrep,
                        bandit,
                    )
                    resumed_analyzers += 2
                    artifacts = {
                        "assignment.json": artifacts["assignment.json"],
                        "generation.json": generation,
                        "security.json": security,
                        "functional-error.json": artifacts["error.json"],
                        "measurement.json": _functional_failure_measurement(
                            assignment_id,
                            generation["response_raw"],
                            generation["code"],
                            security,
                            error_type,
                        ),
                    }
            if not repair_required:
                unit = output / f"assignment-{index:03d}"
                write_bundle(unit, artifacts)
                provider_calls += prior["provider_calls"]
                analyzer_runs += resumed_analyzers
                rows.append(
                    {
                        **prior,
                        "complete": True,
                        "analyzer_runs": resumed_analyzers,
                        "bundle_sha256": bundle_digest(unit),
                    }
                )
                continue
            prior_calls = prior["provider_calls"]
            repaired_invalid_seed_requests += 1
        artifacts: dict[str, Any] = {
            "assignment.json": {
                "assignment_id": assignment_id,
                "task_id": task["task_id"],
                "arm": arm,
                "cwe": task["cwe"],
            }
        }
        if repair_required:
            artifacts["invalid-request.json"] = {
                "error_type": error_type,
                "reason": "unsigned_32_bit_seed_exceeded_provider_signed_31_bit_range",
                "original_seed": _raw_generator_seed(inputs["config"], task["task_id"], arm),
            }
        calls = analyzers = 0
        complete = False
        error_type = None
        raw = b""
        code = ""
        security: dict[str, Any] | None = None
        functional: dict[str, Any] | None = None
        try:
            suffix = "" if arm == "absent" else suffixes[task["task_id"]][arm]
            prompt = _generation_prompt(task["prompt"], suffix, inputs["config"]["intervention"])
            seed = _generator_seed(inputs["config"], task["task_id"], arm)
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
                artifacts["security.json"] = security
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
                "response_used_markdown_fence": "```" in raw.decode("utf-8", errors="replace"),
            }
            artifacts["measurement.json"] = measurement
            complete = True
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:  # noqa: BLE001 - preserve exact failure evidence
            error_type = type(error).__name__
            if calls == 1 and analyzers == 0 and isinstance(
                error, (HTTPError, TimeoutError, URLError)
            ):
                artifacts["generation-error.json"] = {"error_type": error_type}
                artifacts["measurement.json"] = _generation_failure_measurement(
                    assignment_id, error_type
                )
                complete = True
            elif calls == 2 and analyzers == 2 and security is not None:
                artifacts["functional-error.json"] = {"error_type": error_type}
                artifacts["measurement.json"] = _functional_failure_measurement(
                    assignment_id,
                    raw.decode("utf-8", errors="replace"),
                    code,
                    security,
                    error_type,
                )
                complete = True
            else:
                artifacts["error.json"] = {"error_type": error_type}
        unit = output / f"assignment-{index:03d}"
        write_bundle(unit, artifacts)
        total_calls = prior_calls + calls
        provider_calls += total_calls
        analyzer_runs += analyzers
        rows.append(
            {
                "assignment_id": assignment_id,
                "task_id": task["task_id"],
                "arm": arm,
                "complete": complete,
                "provider_calls": total_calls,
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
        else "FULL_COMPLETE"
        if phase == "full" and complete
        else "ERROR",
        "phase": phase,
        "expected_assignments": expected,
        "completed_assignments": sum(row["complete"] for row in rows),
        "provider_calls": provider_calls,
        "analyzer_runs": analyzer_runs,
        "repaired_invalid_seed_requests": repaired_invalid_seed_requests,
        "scientific_claim_allowed": False,
    }
    write_bundle(output / "summary", {"report.json": report, "assignments.json": rows})
    return report


def _load_measurement_resume(
    root: Path | None,
    phase: str,
    work: Sequence[tuple[dict[str, Any], str]],
    config: Mapping[str, Any],
) -> list[tuple[dict[str, Any], Path, bool]]:
    """Validate one failed prefix without consulting generated code or measured outcomes."""

    if root is None:
        return []
    report = _phase_report(root)
    rows = read_json(root / "summary/assignments.json")
    failed_prefix = (
        report.get("status") == "ERROR"
        and report.get("phase") == phase
        and rows
        and len(rows) <= len(work)
        and all(row["complete"] for row in rows[:-1])
        and not rows[-1]["complete"]
        and _resumable_measurement_failure(rows[-1])
    )
    complete_repair = (
        report.get("status")
        in {"PILOT_COMPLETE", "REMAINING_COMPLETE", "FULL_COMPLETE"}
        and report.get("phase") == phase
        and len(rows) == len(work)
        and all(row["complete"] for row in rows)
    )
    if not failed_prefix and not complete_repair:
        raise FormalStudyError("measurement resume prefix is invalid")
    result = []
    for index, (row, (task, arm)) in enumerate(zip(rows, work, strict=False), start=1):
        expected = _assignment_id(config, task["task_id"], arm)
        unit = root / f"assignment-{index:03d}"
        if (
            row["assignment_id"] != expected
            or row["task_id"] != task["task_id"]
            or row["arm"] != arm
            or bundle_digest(unit) != row["bundle_sha256"]
        ):
            raise FormalStudyError("measurement resume binding drifted")
        repair = False
        if complete_repair:
            measurement = read_json(unit / "measurement.json")
            repair = (
                measurement.get("code_status") == "generation_failed"
                and measurement.get("generation_error_type") == "HTTPError"
                and _raw_generator_seed(config, task["task_id"], arm) > 0x7FFFFFFF
            )
        result.append((row, unit, repair))
    return result


def _bundle_artifacts(root: Path) -> dict[str, Any]:
    verify_bundle(root)
    return {name: read_json(root / name) for name in read_json(root / "manifest.json")["files"]}


def _generation_failure_measurement(assignment_id: str, error_type: str) -> dict[str, Any]:
    return {
        "assignment_id": assignment_id,
        "code_status": "generation_failed",
        "oracle_status": "not_run",
        "oracle_evaluability": None,
        "functional_status": "not_run",
        "generator_evidence_sha256": None,
        "code_sha256": None,
        "code_characters": 0,
        "code_lines": 0,
        "response_used_markdown_fence": False,
        "generation_error_type": error_type,
    }


def _resumable_measurement_failure(row: Mapping[str, Any]) -> bool:
    return (
        row["error_type"] in {"HTTPError", "TimeoutError", "URLError"}
        and row["provider_calls"] == 1
        and row["analyzer_runs"] == 0
    ) or (
        row["error_type"] == "JudgeGateError"
        and row["provider_calls"] == 2
        and row["analyzer_runs"] == 2
    )


def _functional_failure_measurement(
    assignment_id: str,
    response_raw: str,
    code: str,
    security: Mapping[str, Any],
    error_type: str,
) -> dict[str, Any]:
    return {
        "assignment_id": assignment_id,
        "code_status": "valid",
        "oracle_status": security["security_label"],
        "oracle_evaluability": security["evaluability"],
        "functional_status": "unknown",
        "generator_evidence_sha256": hashlib.sha256(response_raw.encode()).hexdigest(),
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "code_characters": len(code),
        "code_lines": len(code.splitlines()),
        "response_used_markdown_fence": "```" in response_raw,
        "functional_error_type": error_type,
    }


def analyze(
    config_path: Path, tasks_path: Path, pilot_root: Path, remaining_root: Path, output: Path
) -> dict[str, Any]:
    return _analyze_roots(config_path, tasks_path, [pilot_root, remaining_root], output)


def analyze_full(
    config_path: Path, tasks_path: Path, measurement_root: Path, output: Path
) -> dict[str, Any]:
    """Analyze one externally calibrated full-population measurement root."""

    return _analyze_roots(config_path, tasks_path, [measurement_root], output)


def _analyze_roots(
    config_path: Path,
    tasks_path: Path,
    measurement_roots: Sequence[Path],
    output: Path,
) -> dict[str, Any]:
    config = read_json(config_path)
    tasks = _json_lines(tasks_path)
    measurements = [row for root in measurement_roots for row in _load_measurements(root)]
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
        "analysis_scope": config["analysis"].get(
            "analysis_scope", "single_generator_model_four_arm_study"
        ),
        "task_freshness": config["analysis"].get(
            "task_freshness", "frozen_outcome_blind_cluster_sample"
        ),
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
    prompt_tsg_catalog = None
    if "prompt_tsg" in config:
        catalog_config = config["prompt_tsg"]
        catalog_path = root / catalog_config["catalog_path"]
        if (
            hashlib.sha256(catalog_path.read_bytes()).hexdigest()
            != catalog_config["catalog_sha256"]
        ):
            raise FormalStudyError("Prompt TSG catalog drifted")
        prompt_tsg_catalog = load_catalog(catalog_path)
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
    pilot_ids = source.get("pilot_task_ids", [])
    execution_mode = source.get("execution_mode", "pilot_remaining")
    if (
        len(task_ids) != len(set(task_ids))
        or len(cluster_ids) != len(set(cluster_ids))
        or len(pilot_ids) != len(set(pilot_ids))
        or not set(pilot_ids) <= set(task_ids)
        or config["randomization"]["arms"] != list(ARMS)
    ):
        raise FormalStudyError("four-arm population binding drifted")
    if (execution_mode == "pilot_remaining" and len(pilot_ids) != 5) or (
        execution_mode == "full_after_external_calibration" and pilot_ids
    ):
        raise FormalStudyError("four-arm execution mode drifted")
    if execution_mode not in {"pilot_remaining", "full_after_external_calibration"}:
        raise FormalStudyError("four-arm execution mode is unsupported")
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
        if prompt_tsg_catalog is not None:
            graph = prompt_tsg_from_record(task.get("prompt_tsg"))
            validate_prompt_tsg(graph, prompt=task["prompt"], catalog=prompt_tsg_catalog)
            expected_binding = tsg_mechanism_binding(
                task, graph, prompt_tsg_catalog, registry
            )
            if expected_binding != task.get("prompt_tsg_binding"):
                raise FormalStudyError("Prompt TSG mechanism binding drifted")
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
        "prompt_tsg_catalog": prompt_tsg_catalog,
    }


def _phase_tasks(inputs: Mapping[str, Any], phase: str) -> list[dict[str, Any]]:
    if phase == "full":
        if inputs["config"]["task_source"].get("execution_mode") != (
            "full_after_external_calibration"
        ):
            raise FormalStudyError("full phase requires external calibration mode")
        return list(inputs["tasks"])
    if phase not in {"pilot", "remaining"}:
        raise FormalStudyError("phase must be pilot, remaining, or full")
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
        "must_preserve": mechanism["must_preserve"],
    }
    context_conditioned = "required_delta" in mechanism
    if context_conditioned:
        if "prompt_tsg_binding" in task:
            graph = prompt_tsg_from_record(task["prompt_tsg"])
            binding = task["prompt_tsg_binding"]
            evidence_ids = set(binding["evidence_node_ids"])
            request["prompt_tsg_context"] = {
                "prompt_tsg_id": graph.tsg_id,
                "context_query_id": binding["context_query_id"],
                "actionable_feature_id": binding["actionable_feature_id"],
                "evidence": [
                    {
                        "semantic_id": node.semantic_id,
                        "evidence_text": task["prompt"][node.evidence_start : node.evidence_end],
                        "attributes": dict(node.attributes),
                    }
                    for node in graph.nodes
                    if node.node_id in evidence_ids
                ],
            }
        else:
            request["task_context"] = task["mechanism_binding"]["context_facts"]
        request.update(
            {
                "required_delta": mechanism["required_delta"],
                "forbidden_delta": mechanism["forbidden_delta"],
            }
        )
    else:
        request["mechanism_contract"] = mechanism["specific_contract"]
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
        artifacts["validation-response.json"] = {
            "response_raw": validation_raw.decode("utf-8", errors="replace")
        }
        validation = _validate_semantics(validation_raw, context_conditioned=context_conditioned)
        artifacts["execution.json"] = {
            "response_raw": raw.decode("utf-8", errors="replace"),
            "suffixes": suffixes,
        }
        artifacts["validation.json"] = {
            "request": validation_request,
            "response_raw": validation_raw.decode("utf-8", errors="replace"),
            "validated": validation,
        }
        if "prompt_tsg_binding" in task:
            feature = task["prompt_tsg_binding"]["actionable_feature_id"]
            variants = {
                "absent": graph,
                "specific": apply_feature_patch(
                    graph,
                    prompt=task["prompt"],
                    appended_text=suffixes["specific"],
                    semantic_id=feature,
                    catalog=inputs["prompt_tsg_catalog"],
                ),
                "generic": apply_feature_patch(
                    graph,
                    prompt=task["prompt"],
                    appended_text=suffixes["generic"],
                    semantic_id="control.generic_security",
                    catalog=inputs["prompt_tsg_catalog"],
                ),
                "placebo": apply_feature_patch(
                    graph,
                    prompt=task["prompt"],
                    appended_text=suffixes["placebo"],
                    semantic_id="control.code_style",
                    catalog=inputs["prompt_tsg_catalog"],
                ),
            }
            artifacts["prompt-tsg-variants.json"] = {
                "graph_scope": "source_task_plus_arm_payload_excluding_common_envelope",
                "source_prompt_tsg_id": graph.tsg_id,
                "arm_prompt_tsgs": {
                    arm: prompt_tsg_record(variant) for arm, variant in variants.items()
                },
                "arm_graphs_are_deterministic_patches": True,
                "semantic_validation_precedes_patch": True,
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


def _validate_semantics(raw: bytes, *, context_conditioned: bool = False) -> dict[str, Any]:
    value = _strict_json(raw)
    if set(value) != {"specific", "generic", "placebo", "reason"}:
        raise FormalStudyError("validator response keys drifted")
    specific = (
        {
            "required_delta_satisfied": True,
            "forbidden_delta_absent": True,
            "functional_contract_preserved": True,
            "input_format_preserved": True,
            "interface_preserved": True,
            "extra_security_mechanism_absent": True,
        }
        if context_conditioned
        else {
            "target_mechanism_present": True,
            "functional_contract_preserved": True,
            "input_format_preserved": True,
            "interface_preserved": True,
            "extra_security_mechanism_absent": True,
        }
    )
    expected = {
        "specific": specific,
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
        if not isinstance(value[arm], dict) or set(value[arm]) != set(verdict):
            raise FormalStudyError("validator arm schema drifted")
        if any(type(flag) is not bool for flag in value[arm].values()):
            raise FormalStudyError("validator arm verdict is not boolean")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise FormalStudyError("validator reason is empty")
    return {
        **value,
        "semantic_validation_passed": all(value[arm] == verdict for arm, verdict in expected.items()),
    }


def _requires_non_python_implementation(prompt: str) -> bool:
    """Reject only explicit incompatible language contracts before TSG extraction."""

    normalized = " ".join(prompt.casefold().split())
    return any(
        phrase in normalized
        for phrase in (
            "write a java program",
            "write a bash script",
            "write a bash function",
            "write a shell script",
            "in a shell programming language",
            "in a shell scripting language",
        )
    )


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
        if report["status"] not in {"PILOT_PASSED", "REMAINING_COMPLETE", "FULL_COMPLETE"}:
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
    if report["status"] not in {"PILOT_COMPLETE", "REMAINING_COMPLETE", "FULL_COMPLETE"}:
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


def _assignment_id(config: Mapping[str, Any], task_id: str, arm: str) -> str:
    return content_id(
        "assignment_", {"study": config["study_name"], "task_id": task_id, "arm": arm}
    )


def _raw_generator_seed(config: Mapping[str, Any], task_id: str, arm: str) -> int:
    return int(
        content_hash(
            {
                "seed": config["randomization"]["generator_seed"],
                "task_id": task_id,
                "arm": arm,
            }
        )[:8],
        16,
    )


def _generator_seed(config: Mapping[str, Any], task_id: str, arm: str) -> int:
    """Map the replay hash into the provider's supported signed-positive range."""

    return _raw_generator_seed(config, task_id, arm) & 0x7FFFFFFF


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
    summary = {
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
    if "mechanism_binding" in task:
        summary["mechanism_binding_id"] = task["mechanism_binding"]["binding_id"]
    return summary


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
    "prepare_context_conditioned_tasks",
    "prepare_tsg_candidate_pool",
    "prepare_tsg_conditioned_tasks",
    "prepare_external_tasks",
    "prepare_registered_tasks",
    "run_interventions",
    "run_measurements",
]

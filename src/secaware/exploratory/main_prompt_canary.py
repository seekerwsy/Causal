"""Prepare a zero-outcome five-CWE Prompt canary from the frozen main task pool."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.functional_audit.main_pool import MAIN_CWE_ORDER
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    TaskFunctionalContractRecord,
)
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import PromptRole
from secaware.schema.records import PromptRecord

_SCHEMA_VERSION = "1.0"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.model_dump(mode="json"),
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("main Prompt canary JSON object failed validation")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError("main Prompt canary JSONL record failed validation")
        result.append(value)
    return result


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _validate_config(config: dict[str, Any]) -> str:
    common = (
        config.get("schema_version") == _SCHEMA_VERSION
        and config.get("estimand_id")
        == "five_cwe_operation_specific_security_requirement_policy_itt_v1"
        and config.get("generated_code_allowed") is False
        and config.get("outcomes_allowed") is False
    )
    if config.get("bundle_id") == "five_cwe_main_prompt_canary_inputs_v1":
        valid = (
            set(config)
            == {
                "schema_version",
                "bundle_id",
                "estimand_id",
                "selection_seed",
                "discover_tasks_per_cwe",
                "expected_discover_pool_tasks",
                "expected_confirm_pool_tasks",
                "include_all_confirm_as_forbidden",
                "generated_code_allowed",
                "outcomes_allowed",
            }
            and common
            and type(config.get("selection_seed")) is int
            and config.get("discover_tasks_per_cwe") == 1
            and config.get("expected_discover_pool_tasks") == 51
            and config.get("expected_confirm_pool_tasks") == 42
            and config.get("include_all_confirm_as_forbidden") is True
        )
        mode = "one_per_cwe_canary"
    elif config.get("bundle_id") == "five_cwe_randomized_discovery_inputs_v1":
        valid = (
            set(config)
            == {
                "schema_version",
                "bundle_id",
                "estimand_id",
                "selected_split",
                "selection_policy",
                "expected_selected_tasks",
                "expected_forbidden_tasks",
                "include_all_opposite_split_as_forbidden",
                "generated_code_allowed",
                "outcomes_allowed",
            }
            and common
            and config.get("selected_split") == "discover"
            and config.get("selection_policy") == "all_outcome_blind_eligible_tasks"
            and config.get("expected_selected_tasks") == 51
            and config.get("expected_forbidden_tasks") == 42
            and config.get("include_all_opposite_split_as_forbidden") is True
        )
        mode = "all_discovery_tasks"
    else:
        valid = False
        mode = ""
    if not valid:
        raise ValueError("main Prompt input config failed validation")
    return mode


def _selected_discover_tasks(
    tasks: list[dict[str, Any]],
    *,
    selection_seed: int,
) -> tuple[dict[str, Any], ...]:
    by_cwe: dict[str, list[tuple[str, dict[str, Any]]]] = {cwe: [] for cwe in MAIN_CWE_ORDER}
    for task in tasks:
        if task.get("split") != "discover":
            continue
        cwe = task.get("cwe")
        task_id = task.get("task_id")
        if cwe not in by_cwe or type(task_id) is not str:
            raise ValueError("main Prompt canary discover scope failed validation")
        rank = hashlib.sha256(f"{selection_seed}|{cwe}|{task_id}".encode()).hexdigest()
        by_cwe[cwe].append((rank, task))
    selected: list[dict[str, Any]] = []
    for cwe in MAIN_CWE_ORDER:
        ranked = sorted(by_cwe[cwe], key=lambda item: (item[0], item[1]["task_id"]))
        if not ranked:
            raise ValueError("main Prompt canary per-CWE support failed validation")
        selected.append(ranked[0][1])
    return tuple(selected)


def _prompt(
    task: dict[str, Any],
    *,
    prompt_id_namespace: str = "main-canary",
) -> PromptRecord:
    prompt = task.get("prompt")
    task_id = task.get("task_id")
    if type(prompt) is not str or type(task_id) is not str:
        raise ValueError("main Prompt canary source Prompt failed validation")
    source_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    if source_sha256 != task.get("source_prompt_sha256"):
        raise ValueError("main Prompt canary source Prompt digest failed validation")
    prompt_id = prompt_id_namespace + "-" + hashlib.sha256(task_id.encode()).hexdigest()[:32]
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=task_id,
        split=str(task["split"]),
        language="python",
        task_family=str(task["task_family"]),
        cwe=str(task["cwe"]),
        prompt=prompt,
        prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_prompt_id=None,
        oracle_profile_id=str(task["oracle_profile_id"]),
    )


def _functional_contract(
    task: dict[str, Any],
    prompt: PromptRecord,
) -> tuple[TaskFunctionalContractRecord, dict[str, object]]:
    source = task.get("functional_contract")
    provenance = task.get("audit_provenance")
    if type(source) is not dict or type(provenance) is not dict:
        raise ValueError("main Prompt canary functional provenance failed validation")
    raw_requirements = source.get("requirements")
    raw_dependencies = source.get("environment_dependencies")
    if (
        type(raw_requirements) is not list
        or not raw_requirements
        or type(raw_dependencies) is not list
    ):
        raise ValueError("main Prompt canary functional contract failed validation")
    requirements = tuple(
        sorted(
            (FunctionalRequirementRecord.model_validate(item) for item in raw_requirements),
            key=lambda item: item.requirement_id,
        )
    )
    if any(item.prompt_evidence_quote not in prompt.prompt for item in requirements):
        raise ValueError("main Prompt canary functional evidence failed validation")
    dependencies = tuple(sorted({str(item) for item in raw_dependencies}))
    judgeability = FunctionalJudgeability(str(source.get("judgeability")))
    evidence = {
        "schema_version": _SCHEMA_VERSION,
        "adapter_policy": "reconciled-main-pool-functional-contract-v1",
        "task_id": task["task_id"],
        "source_prompt_sha256": prompt.prompt_sha256,
        "audit_provenance": provenance,
        "functional_contract": source,
    }
    contract = TaskFunctionalContractRecord.from_content(
        task_id=prompt.task_id,
        source_prompt_id=prompt.prompt_id,
        source_prompt_sha256=prompt.prompt_sha256,
        language=prompt.language,
        judgeability=judgeability,
        requirements=requirements,
        environment_dependencies=dependencies,
        audit_pass_ids=("A",),
        audit_status=FunctionalAuditStatus.RESOLVED,
        auditor_kind="CODEX",
        audit_evidence_sha256=canonical_sha256(evidence),
    )
    return contract, {
        "schema_version": _SCHEMA_VERSION,
        "task_id": prompt.task_id,
        "source_prompt_id": prompt.prompt_id,
        "contract_id": contract.contract_id,
        "adapter_policy": "reconciled-main-pool-functional-contract-v1",
        "audit_evidence_sha256": contract.audit_evidence_sha256,
        "source_decision_id": provenance.get("decision_id"),
        "source_adjudication": provenance.get("adjudication"),
        "source_reconciled_report_sha256": provenance.get("reconciled_report_sha256"),
        "generated_code_withheld": True,
        "outcomes_withheld": True,
    }


def prepare_main_prompt_canary(
    *,
    task_pool_dir: Path,
    estimand_dir: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Freeze one discovery task per CWE and all held-out confirmation exclusions."""

    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path)
    selection_mode = _validate_config(config)
    task_report = _read_json(task_pool_dir / "report.json")
    estimand_report = _read_json(estimand_dir / "report.json")
    tasks_path = task_pool_dir / "tasks.jsonl"
    applicability_path = estimand_dir / "task-applicability.jsonl"
    tasks = _read_jsonl(tasks_path)
    applicability = _read_jsonl(applicability_path)
    if (
        task_report.get("task_bundle_sha256") != sha256_file(tasks_path)
        or estimand_report.get("status") != "POOLED_POLICY_ESTIMAND_FROZEN"
        or estimand_report.get("input_digests", {}).get("task_bundle_sha256")
        != sha256_file(tasks_path)
        or estimand_report.get("artifact_digests", {}).get("task-applicability.jsonl")
        != sha256_file(applicability_path)
        or len(tasks) != 93
        or len(applicability) != 93
    ):
        raise ValueError("main Prompt canary frozen input provenance failed validation")
    applicability_by_task = {item.get("task_id"): item for item in applicability}
    tasks_by_id = {item.get("task_id"): item for item in tasks}
    if (
        len(applicability_by_task) != len(applicability)
        or len(tasks_by_id) != len(tasks)
        or set(applicability_by_task) != set(tasks_by_id)
    ):
        raise ValueError("main Prompt canary task coverage failed validation")
    for task_id, task in tasks_by_id.items():
        mapping = applicability_by_task[task_id]
        if any(
            mapping.get(field) != task.get(field)
            for field in (
                "task_cluster_id",
                "source_prompt_sha256",
                "split",
                "cwe",
                "task_family",
                "oracle_profile_id",
            )
        ):
            raise ValueError("main Prompt canary applicability relation failed validation")

    split_counts = Counter(str(item["split"]) for item in tasks)
    if split_counts != Counter({"discover": 51, "confirm": 42}):
        raise ValueError("main Prompt canary split support failed validation")
    if selection_mode == "one_per_cwe_canary":
        selected = _selected_discover_tasks(tasks, selection_seed=config["selection_seed"])
        prompt_id_namespace = "main-canary"
        selection_id = "five_cwe_main_prompt_canary_selection_v1"
        selection_rule = "minimum_sha256_rank_within_cwe_discovery_pool_v1"
        selected_role = "selected_discovery"
    else:
        selected = tuple(
            sorted(
                (item for item in tasks if item["split"] == "discover"),
                key=lambda item: item["task_id"],
            )
        )
        prompt_id_namespace = "main-discovery"
        selection_id = "five_cwe_randomized_discovery_selection_v1"
        selection_rule = "all_outcome_blind_eligible_discovery_tasks_v1"
        selected_role = "selected_randomized_discovery"
    selected_ids = {item["task_id"] for item in selected}
    confirm = tuple(item for item in tasks if item["split"] == "confirm")
    confirm_ids = {item["task_id"] for item in confirm}
    expected_selected = 5 if selection_mode == "one_per_cwe_canary" else 51
    if selected_ids & confirm_ids or len(selected_ids) != expected_selected:
        raise ValueError("main Prompt canary split isolation failed validation")

    prompts = tuple(_prompt(item, prompt_id_namespace=prompt_id_namespace) for item in selected)
    contract_pairs = tuple(
        _functional_contract(task, prompt) for task, prompt in zip(selected, prompts, strict=True)
    )
    contracts = tuple(item[0] for item in contract_pairs)
    contract_provenance = tuple(item[1] for item in contract_pairs)
    selection_rows = [
        {
            "task_id": task["task_id"],
            "task_cluster_id": task["task_cluster_id"],
            "split": "discover",
            "cwe": task["cwe"],
            "task_family": task["task_family"],
            "oracle_profile_id": task["oracle_profile_id"],
            "target_feature_id": applicability_by_task[task["task_id"]]["target_feature_id"],
            "source_prompt_sha256": task["source_prompt_sha256"],
            "canary_role": selected_role,
        }
        for task in selected
    ]
    selection_rows.extend(
        {
            "task_id": task["task_id"],
            "task_cluster_id": task["task_cluster_id"],
            "split": "confirm",
            "cwe": task["cwe"],
            "task_family": task["task_family"],
            "oracle_profile_id": task["oracle_profile_id"],
            "target_feature_id": applicability_by_task[task["task_id"]]["target_feature_id"],
            "source_prompt_sha256": task["source_prompt_sha256"],
            "canary_role": "forbidden_confirmation",
        }
        for task in confirm
    )
    selection = {
        "schema_version": _SCHEMA_VERSION,
        "selection_id": selection_id,
        "estimand_id": config["estimand_id"],
        "selection_seed": config.get("selection_seed"),
        "selection_rule": selection_rule,
        "confirmation_exclusion_scope": "all_frozen_confirmation_tasks",
        "generated_code_allowed": False,
        "outcomes_allowed": False,
        "tasks": selection_rows,
    }
    if selection_mode == "one_per_cwe_canary":
        selected_task_ids_by_cwe: dict[str, object] = {
            task["cwe"]: task["task_id"] for task in selected
        }
    else:
        selected_task_ids_by_cwe = {
            cwe: sorted(task["task_id"] for task in selected if task["cwe"] == cwe)
            for cwe in MAIN_CWE_ORDER
        }

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_json(output_dir / "selection.json", selection)
    write_jsonl(output_dir / "prompts.jsonl", prompts)
    write_jsonl(output_dir / "prompt-attestations.jsonl", ())
    write_jsonl(output_dir / "task-functional-contracts.jsonl", contracts)
    write_jsonl(output_dir / "functional-contract-provenance.jsonl", contract_provenance)
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": command_argv, "provider_calls": 0},
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": config["bundle_id"],
        "status": (
            "MAIN_PROMPT_CANARY_INPUTS_FROZEN"
            if selection_mode == "one_per_cwe_canary"
            else "RANDOMIZED_DISCOVERY_INPUTS_FROZEN"
        ),
        "counts": {
            "discover_pool_tasks": split_counts["discover"],
            "confirm_pool_tasks": split_counts["confirm"],
            "selected_discover_tasks": len(selected),
            "forbidden_confirm_tasks": len(confirm),
            "cwes": len({item["cwe"] for item in selected}),
            "prompts": len(prompts),
            "functional_contracts": len(contracts),
            "prompt_attestations": 0,
            "provider_calls": 0,
            "generated_code": 0,
            "outcomes_observed": 0,
            "errors": 0,
            "pending": 0,
        },
        "selected_task_ids_by_cwe": selected_task_ids_by_cwe,
        "input_digests": {
            "config_sha256": sha256_file(config_path),
            "task_pool_report_sha256": sha256_file(task_pool_dir / "report.json"),
            "task_bundle_sha256": sha256_file(tasks_path),
            "estimand_report_sha256": sha256_file(estimand_dir / "report.json"),
            "applicability_sha256": sha256_file(applicability_path),
            **(
                {"adapter_source_sha256": sha256_file(Path(__file__))}
                if selection_mode == "all_discovery_tasks"
                else {}
            ),
        },
        "next_gate": "zero_provider_four_arm_prompt_contract",
    }
    _write_json(output_dir / "report.json", report)
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": sha256_file(path)}
                for path in sorted(output_dir.iterdir())
                if path.is_file()
            ],
        },
    )
    return report


__all__ = ["prepare_main_prompt_canary"]

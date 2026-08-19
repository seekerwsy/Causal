"""Prepare a non-redistributive selection ledger for independent-validation Gate A."""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import sha256_file
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import prompt_feature_spec

_SCHEMA_VERSION = "1.0"
_TARGETS = {
    "CWE-78": "safety.safe_subprocess",
    "CWE-89": "safety.sql_parameterization",
    "CWE-502": "safety.safe_deserialization",
    "CWE-328": "safety.collision_resistant_hash",
    "CWE-338": "safety.cryptographic_randomness",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("independent Gate A input JSON failed validation")
    return value


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


def _repo_input(repo_root: Path, record: object) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("independent Gate A input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("independent Gate A input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("independent Gate A input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("independent Gate A input digest failed validation")
    return path


def _selection_task(
    prompt: PromptRecord, contract: TaskFunctionalContractRecord
) -> dict[str, object]:
    target = _TARGETS.get(prompt.cwe)
    if (
        target is None
        or prompt.split != "confirm"
        or prompt.prompt_role.value != "neutral_baseline"
        or contract.task_id != prompt.task_id
        or contract.source_prompt_id != prompt.prompt_id
        or contract.source_prompt_sha256 != prompt.prompt_sha256
        or contract.language != prompt.language
    ):
        raise ValueError("independent Gate A task binding failed validation")
    spec = prompt_feature_spec(target)
    if (
        prompt.cwe not in spec.applicable_cwes
        or prompt.task_family not in spec.applicable_task_families
    ):
        raise ValueError("independent Gate A target applicability failed validation")
    return {
        "canary_role": "independent_validation_confirmation",
        "cwe": prompt.cwe,
        "language": prompt.language,
        "source_prompt_sha256": prompt.prompt_sha256,
        "split": "confirm",
        "target_feature_id": target,
        "task_cluster_id": prompt.task_id,
        "task_family": prompt.task_family,
        "task_id": prompt.task_id,
    }


def prepare_independent_validation_gate_a_inputs(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = _read_json(config_path)
    inputs = config.get("inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("input_id") != "five_cwe_independent_validation_gate_a_inputs_v1"
        or config.get("expected_tasks") != 55
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("raw_prompts_in_output_allowed") is not False
        or type(inputs) is not dict
        or set(inputs) != {"source_prompts", "functional_contracts", "contract_report"}
    ):
        raise ValueError("independent Gate A config failed validation")
    paths = {name: _repo_input(repo_root, value) for name, value in inputs.items()}
    contract_report = _read_json(paths["contract_report"])
    if (
        contract_report.get("status") != "INDEPENDENT_VALIDATION_CONTRACTS_FROZEN"
        or contract_report.get("task_family_mapping_version")
        != "feature-catalog-task-family-mapping-v2"
        or contract_report.get("outcomes_consumed") != 0
        or contract_report.get("provider_calls") != 0
    ):
        raise ValueError("independent Gate A contract dependency failed validation")
    prompts = tuple(
        read_jsonl(paths["source_prompts"], PromptRecord, required=True, allow_empty=False)
    )
    contracts = tuple(
        read_jsonl(
            paths["functional_contracts"],
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    contract_by_task = {item.task_id: item for item in contracts}
    if len(prompts) != 55 or len(contracts) != 55 or len(contract_by_task) != 55:
        raise ValueError("independent Gate A contract coverage failed validation")
    tasks = [
        _selection_task(prompt, contract_by_task[prompt.task_id])
        for prompt in sorted(prompts, key=lambda item: item.task_id)
    ]
    if len({str(item["task_id"]) for item in tasks}) != 55 or {
        str(item["cwe"]) for item in tasks
    } != set(_TARGETS):
        raise ValueError("independent Gate A selection coverage failed validation")

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "command.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "argv": list(command_argv),
            "provider_calls": 0,
            "outcomes_consumed": 0,
        },
    )
    selection = {
        "schema_version": _SCHEMA_VERSION,
        "selection_id": "five_cwe_independent_validation_selection_v1",
        "selection_rule": "all_frozen_independent_validation_tasks_v1",
        "generated_code_allowed": False,
        "outcomes_allowed": False,
        "tasks": tasks,
    }
    _write_json(output_dir / "selection.json", selection)
    report = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_GATE_A_INPUTS_READY",
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "counts": {"tasks": 55, "failed": 0, "pending": 0},
        "by_cwe": dict(sorted(Counter(str(item["cwe"]) for item in tasks).items())),
        "by_language": dict(sorted(Counter(str(item["language"]) for item in tasks).items())),
        "selection_sha256": sha256_file(output_dir / "selection.json"),
        "source_prompts_sha256": sha256_file(paths["source_prompts"]),
        "functional_contracts_sha256": sha256_file(paths["functional_contracts"]),
        "next_action": "run_zero_provider_four_arm_gate_a",
    }
    _write_json(output_dir / "report.json", report)
    files = sorted(path for path in output_dir.iterdir() if path.is_file())
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [{"path": path.name, "sha256": sha256_file(path)} for path in files],
        },
    )
    return report


__all__ = ["prepare_independent_validation_gate_a_inputs"]

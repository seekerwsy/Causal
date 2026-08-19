"""Outcome-blind execution planning for the independent validation experiment."""

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

from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    ExperimentalUnit,
    PromptVariantRecord,
)
from secaware.schema.records import PromptRecord

_SCHEMA_VERSION = "1.0"
_HYPOTHESIS_ID = "hypothesis_3f254cbd3f30ca51351924c43e3b6b44063010ccbc547565064530589bc870c0"
_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)
_PILOT_GATE_A_ASSIGNMENT_ID = (
    "exploratory_assignment_bd6a3292b8d5fff0b099f42acaf6ca299d6ea85446768f0c259e9966c27a123c"
)


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
        raise ValueError("independent validation plan JSON failed validation")
    return value


def _read_dict_rows(path: Path) -> tuple[dict[str, Any], ...]:
    rows = tuple(read_jsonl(path, required=True, allow_empty=False))
    if any(type(item) is not dict for item in rows):
        raise ValueError("independent validation plan JSONL failed validation")
    return rows


def _write_json(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _input_path(repo_root: Path, value: object) -> Path:
    if type(value) is not dict or set(value) != {"path", "sha256"}:
        raise ValueError("independent validation plan input failed validation")
    relative = value.get("path")
    digest = value.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("independent validation plan input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("independent validation plan input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("independent validation plan input digest failed validation")
    return path


def _verify_closed_manifest(path: Path) -> None:
    root = path.parent
    manifest = _read_json(path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("independent validation plan manifest failed validation")
    expected: set[str] = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise ValueError("independent validation plan manifest failed validation")
        relative = Path(str(item["path"]))
        resolved = (root / relative).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            raise ValueError("independent validation plan manifest escaped root") from None
        normalized = relative.as_posix()
        if (
            relative.is_absolute()
            or normalized in expected
            or not resolved.is_file()
            or sha256_file(resolved) != item["sha256"]
        ):
            raise ValueError("independent validation plan manifest failed validation")
        expected.add(normalized)
    actual = {
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and item.name != "artifact-manifest.json"
    }
    if actual != expected:
        raise ValueError("independent validation plan manifest closure failed validation")


def _id(prefix: str, value: object) -> str:
    return prefix + canonical_sha256(value)


def _indexed(rows: tuple[dict[str, Any], ...], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = row.get(key)
        if type(value) is not str or not value or value in result:
            raise ValueError("independent validation plan identity failed validation")
        result[value] = row
    return result


def _standard_records(
    *,
    gate_a_dir: Path,
    source_by_task: dict[str, PromptRecord],
    app_config: AppConfig,
) -> tuple[
    tuple[AssignmentRecord, ...],
    tuple[PromptVariantRecord, ...],
    tuple[dict[str, object], ...],
]:
    inherited_assignments = _read_dict_rows(gate_a_dir / "assignments.jsonl")
    inherited_variants = _indexed(_read_dict_rows(gate_a_dir / "variants.jsonl"), "variant_id")
    candidates = _indexed(_read_dict_rows(gate_a_dir / "candidates.jsonl"), "candidate_id")
    proposals = _indexed(
        _read_dict_rows(gate_a_dir / "deterministic-extraction-proposals.jsonl"),
        "prompt_id",
    )
    graphs = _indexed(_read_dict_rows(gate_a_dir / "deterministic-prompt-tsg.jsonl"), "prompt_id")
    randomization_plan_sha256 = sha256_file(gate_a_dir / "assignments.jsonl")
    protocol_id = _id(
        "arm_protocol_",
        {
            "version": "independent-validation-four-arm-v1",
            "arm_roles": [item.value for item in _ARMS],
        },
    )
    assignments: list[AssignmentRecord] = []
    variants: list[PromptVariantRecord] = []
    mappings: list[dict[str, object]] = []
    for inherited in inherited_assignments:
        inherited_variant = inherited_variants.get(str(inherited.get("variant_id")))
        task_id = str(inherited.get("task_id", ""))
        source = source_by_task.get(task_id)
        candidate = candidates.get(str(inherited.get("candidate_id")))
        if inherited_variant is None or source is None or candidate is None:
            raise ValueError("independent validation inherited coordinate failed validation")
        prompt_id = inherited_variant.get("blind_prompt_id")
        proposal = proposals.get(str(prompt_id))
        graph = graphs.get(str(prompt_id))
        role = ArmRole(str(inherited.get("arm_role")))
        target_feature_id = str(inherited_variant.get("target_feature_id", ""))
        prompt_text = inherited_variant.get("prompt")
        if (
            role not in _ARMS
            or inherited.get("outcome_generation_allowed") is not False
            or inherited.get("model_id") != "phi-4-14b"
            or inherited_variant.get("outcome_generation_allowed") is not False
            or inherited_variant.get("task_id") != task_id
            or inherited_variant.get("candidate_id") != inherited.get("candidate_id")
            or candidate.get("target_feature_id") != target_feature_id
            or source.prompt_id != inherited_variant.get("source_prompt_id")
            or source.prompt_sha256 != inherited_variant.get("source_prompt_sha256")
            or type(prompt_text) is not str
            or hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
            != inherited_variant.get("prompt_sha256")
            or proposal is None
            or graph is None
            or proposal.get("prompt_sha256") != inherited_variant.get("prompt_sha256")
            or graph.get("proposal_id") != proposal.get("proposal_id")
            or graph.get("graph_sha256") is None
            or graph.get("extractor_backend") != "deterministic_catalog_v2"
            or graph.get("extractor_policy_sha256")
            != inherited_variant.get("blind_extractor_policy_sha256")
        ):
            raise ValueError("independent validation inherited provenance failed validation")
        target_spec_id = _id(
            "target_",
            {
                "version": "independent-validation-target-v1",
                "candidate_id": inherited["candidate_id"],
                "target_feature_id": target_feature_id,
                "operation": inherited_variant["operation"],
            },
        )
        target_instance_id = _id(
            "target_instance_",
            {"version": "v1", "task_id": task_id, "target_spec_id": target_spec_id},
        )
        protocol_instance_id = _id(
            "protocol_instance_",
            {
                "version": "v1",
                "task_id": task_id,
                "target_spec_id": target_spec_id,
                "arm_protocol_id": protocol_id,
            },
        )
        delta_id = _id(
            "delta_",
            {
                "version": "gate-a-validated-delta-v1",
                "allowed_delta": inherited_variant["allowed_delta"],
                "realized_changed_feature_ids": inherited_variant["realized_changed_feature_ids"],
            },
        )
        length_match_id = (
            _id(
                "length_match_",
                {
                    "version": "gate-a-length-match-v1",
                    "gate_a_variant_id": inherited["variant_id"],
                    "prompt_sha256": inherited_variant["prompt_sha256"],
                },
            )
            if role is ArmRole.LENGTH_MATCHED_PLACEBO
            else None
        )
        standard_variant = PromptVariantRecord.from_content(
            task_id=task_id,
            source_prompt_id=source.prompt_id,
            language=source.language,
            variant_prompt_id=prompt_id,
            hypothesis_id=_HYPOTHESIS_ID,
            target_spec_id=target_spec_id,
            target_instance_id=target_instance_id,
            arm_protocol_id=protocol_id,
            protocol_instance_id=protocol_instance_id,
            arm_role=role,
            prompt_sha256=inherited_variant["prompt_sha256"],
            prompt_text=prompt_text,
            proposal_id=proposal["proposal_id"],
            graph_id=graph["graph_id"],
            delta_id=delta_id,
            executor_policy_sha256=inherited_variant["renderer_policy_sha256"],
            extractor_policy_sha256=inherited_variant["blind_extractor_policy_sha256"],
            length_match_id=length_match_id,
        )
        unit = ExperimentalUnit(
            task_id=task_id,
            hypothesis_id=_HYPOTHESIS_ID,
            target_spec_id=target_spec_id,
            model_id="phi-4-14b",
            seed_slot=int(inherited["seed_slot"]),
        )
        standard_assignment = AssignmentRecord.from_content(
            block_id=AssignmentRecord.block_id_from_key(
                task_id,
                _HYPOTHESIS_ID,
                target_spec_id,
                protocol_id,
                "phi-4-14b",
            ),
            experimental_unit=unit,
            target_spec_id=target_spec_id,
            target_instance_id=target_instance_id,
            arm_protocol_id=protocol_id,
            protocol_instance_id=protocol_instance_id,
            variant_id=standard_variant.variant_id,
            arm_role=role,
            seed_id=int(inherited["seed_id"]),
            rng_version="sha256-rejection-fisher-yates-v1",
            randomization_plan_sha256=randomization_plan_sha256,
        )
        variants.append(standard_variant)
        assignments.append(standard_assignment)
        mappings.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "task_id": task_id,
                "cwe": source.cwe,
                "language": source.language,
                "arm_role": role.value,
                "gate_a_assignment_id": inherited["assignment_id"],
                "gate_a_variant_id": inherited["variant_id"],
                "assignment_id": standard_assignment.assignment_id,
                "variant_id": standard_variant.variant_id,
                "seed_slot": unit.seed_slot,
                "seed_id": standard_assignment.seed_id,
            }
        )
    assignment_result = tuple(
        sorted(
            assignments,
            key=lambda item: (item.experimental_unit.task_id, item.experimental_unit.seed_slot),
        )
    )
    variant_result = tuple(sorted(variants, key=lambda item: (item.task_id, item.arm_role.value)))
    mapping_result = tuple(
        sorted(mappings, key=lambda item: (str(item["task_id"]), int(item["seed_slot"])))
    )
    if (
        len(assignment_result) != 220
        or len(variant_result) != 220
        or len(mapping_result) != 220
        or len({item.assignment_id for item in assignment_result}) != 220
        or len({item.variant_id for item in variant_result}) != 220
        or len({item.experimental_unit.task_id for item in assignment_result}) != 55
        or any(
            {
                item.arm_role
                for item in assignment_result
                if item.experimental_unit.task_id == task_id
            }
            != set(_ARMS)
            for task_id in source_by_task
        )
        or app_config.generation.confirmation_max_requests != 220
    ):
        raise ValueError("independent validation standard record closure failed validation")
    return assignment_result, variant_result, mapping_result


def plan_independent_validation_execution(
    *,
    repo_root: Path,
    config_path: Path,
    app_config_path: Path,
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
        or config.get("plan_id") != "five_cwe_independent_validation_execution_v1"
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("expected_tasks") != 55
        or config.get("expected_assignments") != 220
        or config.get("pilot_gate_a_assignment_id") != _PILOT_GATE_A_ASSIGNMENT_ID
        or type(inputs) is not dict
        or set(inputs) != {"runtime_freeze_manifest", "gate_a_manifest", "functional_contracts"}
    ):
        raise ValueError("independent validation execution plan config failed validation")
    paths = {name: _input_path(repo_root, value) for name, value in inputs.items()}
    _verify_closed_manifest(paths["runtime_freeze_manifest"])
    _verify_closed_manifest(paths["gate_a_manifest"])
    freeze_dir = paths["runtime_freeze_manifest"].parent
    freeze_report = _read_json(freeze_dir / "report.json")
    runtime_policy = _read_json(freeze_dir / "runtime-policy.json")
    if (
        freeze_report.get("status") != "INDEPENDENT_VALIDATION_RUNTIME_ANALYSIS_FROZEN"
        or freeze_report.get("provider_calls") != 0
        or freeze_report.get("outcomes_consumed") != 0
        or runtime_policy.get("frozen_hypothesis_id") != _HYPOTHESIS_ID
    ):
        raise ValueError("independent validation runtime freeze failed validation")
    gate_a_dir = paths["gate_a_manifest"].parent
    sources = tuple(
        read_jsonl(
            gate_a_dir / "source-prompts.jsonl", PromptRecord, required=True, allow_empty=False
        )
    )
    contracts = tuple(
        read_jsonl(
            paths["functional_contracts"],
            TaskFunctionalContractRecord,
            required=True,
            allow_empty=False,
        )
    )
    source_by_task = {item.task_id: item for item in sources}
    contract_by_task = {item.task_id: item for item in contracts}
    if (
        len(source_by_task) != 55
        or len(contract_by_task) != 55
        or set(source_by_task) != set(contract_by_task)
        or any(
            contract_by_task[task_id].source_prompt_sha256 != source.prompt_sha256
            for task_id, source in source_by_task.items()
        )
    ):
        raise ValueError("independent validation contract closure failed validation")
    app_config = load_config(app_config_path.resolve(), run_dir=output_dir)
    assignments, variants, mappings = _standard_records(
        gate_a_dir=gate_a_dir,
        source_by_task=source_by_task,
        app_config=app_config,
    )
    requests = tuple(plan_confirmation_requests(assignments, variants, app_config.generation))
    mapping_by_gate_a = {str(item["gate_a_assignment_id"]): item for item in mappings}
    pilot = mapping_by_gate_a.get(_PILOT_GATE_A_ASSIGNMENT_ID)
    canary_selection = _read_json(freeze_dir / "canary-selection.json").get("tasks")
    if type(canary_selection) is not list:
        raise ValueError("independent validation canary selection failed validation")
    canary_task_ids = {str(item.get("task_id")) for item in canary_selection if type(item) is dict}
    canary_assignment_ids = tuple(
        sorted(
            item.assignment_id
            for item in assignments
            if item.experimental_unit.task_id in canary_task_ids
        )
    )
    if pilot is None or len(canary_task_ids) != 5 or len(canary_assignment_ids) != 20:
        raise ValueError("independent validation execution selection failed validation")

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-plan-config.json", config)
    write_resolved_config(app_config, output_dir / "effective-app-config.yaml")
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    write_jsonl(output_dir / "assignments.jsonl", assignments)
    write_jsonl(output_dir / "prompt-variants.jsonl", variants)
    write_jsonl(output_dir / "generation-requests.jsonl", requests)
    write_jsonl(output_dir / "functional-contracts.jsonl", contracts)
    write_jsonl(output_dir / "gate-a-crosswalk.jsonl", mappings)
    selection = {
        "schema_version": _SCHEMA_VERSION,
        "pilot_assignment_ids": [pilot["assignment_id"]],
        "pilot_gate_a_assignment_ids": [_PILOT_GATE_A_ASSIGNMENT_ID],
        "canary_task_ids": sorted(canary_task_ids),
        "canary_assignment_ids": list(canary_assignment_ids),
        "full_assignment_ids": [item.assignment_id for item in assignments],
    }
    _write_json(output_dir / "execution-selection.json", selection)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_EXECUTION_PLAN_COMPLETE",
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "counts": {
            "tasks": 55,
            "blocks": 55,
            "assignments": len(assignments),
            "prompt_variants": len(variants),
            "generation_requests": len(requests),
            "functional_contracts": len(contracts),
            "pilot_assignments": 1,
            "canary_assignments": len(canary_assignment_ids),
            "pending_generation": len(requests),
            "errors": 0,
        },
        "by_cwe": dict(sorted(Counter(item.cwe for item in sources).items())),
        "by_language": dict(sorted(Counter(item.language for item in sources).items())),
        "runtime_policy": runtime_policy,
        "next_action": "run_one_assignment_generation_measurement_pilot",
    }
    _write_json(output_dir / "report.json", report)
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
    return report


__all__ = ["plan_independent_validation_execution"]

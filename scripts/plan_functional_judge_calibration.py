"""Build a closed, zero-provider-call functional-Judge calibration plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.pipeline.artifact import canonical_sha256

_SHA256 = frozenset("0123456789abcdef")
_FAMILIES = frozenset(
    {"gtf_fasta_append", "sqlite_metadata", "pdf_bag_of_words", "slurm_exit_code"}
)
_OVERLAY_KEYS = frozenset(
    {
        "adapter_id",
        "arm_role",
        "assignment_id",
        "case_id",
        "code_path",
        "code_sha256",
        "equivalence_group",
        "expected_status",
        "family",
        "frozen_functional_contracts_path",
        "frozen_functional_contracts_sha256",
        "fixture_policy_sha256",
        "functional_contract_id",
        "functional_contract_set_sha256",
        "functional_contract_source_path",
        "functional_contract_source_sha256",
        "functional_requirement_ids",
        "functional_requirement_ids_sha256",
        "measurement_path",
        "measurement_sha256",
        "overlay_evidence_manifest_sha256",
        "paired_group_id",
        "schema_version",
        "source_artifact_path",
        "source_artifact_sha256",
        "source_root_manifest_sha256",
        "split",
        "task_id",
        "y_f_e",
    }
)
_VALIDATION_KEYS = frozenset(
    {
        "case_id",
        "code_text",
        "equivalence_group",
        "expected_status",
        "family",
        "fixture_role",
        "schema_version",
        "seed_id",
        "split",
        "task_id",
    }
)
_SPEC_KEYS = frozenset(
    {
        "calibration_id",
        "candidate_roles",
        "executable_source_spec_id",
        "executable_source_spec_sha256",
        "families",
        "frozen_functional_contracts_sha256",
        "functional_contract_set_sha256",
        "purpose",
        "schema_version",
        "source_final_delivery_sha256",
        "source_live_root_manifest_sha256",
        "source_live_root_provenance_sha256",
        "thresholds",
        "tune_expected_cases",
        "validation_cases_sha256",
        "validation_expected_cases",
    }
)
_CANDIDATE_ROLES = {
    "baseline": "comparison_only_never_selected",
    "new_candidate": "eligible_after_all_gates",
}
_THRESHOLD_KEYS = frozenset(
    {
        "selection_rule",
        "tune_cases",
        "tune_max_equivalence_inconsistency",
        "tune_max_false_pass",
        "tune_min_correct",
        "tune_role",
        "validation_cases",
        "validation_max_equivalence_inconsistency",
        "validation_max_false_pass",
        "validation_max_invalid",
        "validation_min_correct",
    }
)
_MEASUREMENT_KEYS = frozenset(
    {
        "adapter_id",
        "arm_role",
        "assignment_id",
        "checks",
        "code_sha256",
        "execution_observation_sha256",
        "execution_performed",
        "executor_policy_sha256",
        "expected_status",
        "family",
        "fixture_instance_sha256",
        "fixture_policy_sha256",
        "functional_variable",
        "functional_contract_id",
        "functional_contract_source_path",
        "functional_contract_source_sha256",
        "functional_requirement_ids",
        "functional_requirement_ids_sha256",
        "measurement_id",
        "measurement_method",
        "official_artifact_replacement_allowed",
        "provider_calls",
        "record_type",
        "requirement_verdicts",
        "role",
        "schema_version",
        "scientific_claim_allowed",
        "security_oracle_calls",
        "source_artifact_path",
        "source_artifact_sha256",
        "source_binding_id",
        "source_root_manifest_sha256",
        "task_id",
        "y_f_e",
    }
)
_CHECK_KEYS = frozenset(
    {
        "check_id",
        "diagnostic",
        "expected",
        "expected_sha256",
        "observed",
        "observed_sha256",
        "passed",
    }
)
_REQUIREMENT_VERDICT_KEYS = frozenset({"requirement_id", "supporting_check_ids", "verdict"})
_EVIDENCE_KEYS = frozenset(
    {
        "overlay_evidence_id",
        "role",
        "schema_version",
        "source_root_manifest_sha256",
        "frozen_functional_contracts_path",
        "frozen_functional_contracts_sha256",
        "functional_contract_set_sha256",
        "units",
    }
)
_EVIDENCE_UNIT_KEYS = frozenset(
    {
        "assignment_id",
        "code_path",
        "code_sha256",
        "functional_contract_id",
        "functional_contract_source_path",
        "functional_contract_source_sha256",
        "functional_requirement_ids",
        "functional_requirement_ids_sha256",
        "measurement_path",
        "measurement_sha256",
        "unit_manifest_path",
        "unit_manifest_sha256",
    }
)
_SOURCE_BINDING_KEYS = frozenset(
    {
        "access_mode",
        "listed_files",
        "listed_paths_sha256",
        "schema_version",
        "source_binding_id",
        "source_root_closure_sha256",
        "source_root_manifest_sha256",
    }
)
_PROTOCOL_KEYS = frozenset(
    {
        "command_argv",
        "controlled_adapter_ids",
        "execution_performed",
        "executor_policy",
        "executor_policy_sha256",
        "functional_variable",
        "frozen_input_plan_sha256",
        "frozen_functional_contracts_path",
        "frozen_functional_contracts_sha256",
        "functional_contract_set_sha256",
        "measurement_method",
        "official_artifact_replacement_allowed",
        "sandbox_limitations",
        "schema_version",
        "scientific_claim_allowed",
    }
)
_REPORT_KEYS = frozenset(
    {
        "counts",
        "execution_performed",
        "executor_policy_sha256",
        "functional_variable",
        "frozen_input_plan_sha256",
        "frozen_functional_contracts_path",
        "frozen_functional_contracts_sha256",
        "functional_contract_set_sha256",
        "judge_tune_cases_sha256",
        "measurement_method",
        "official_artifact_replacement_allowed",
        "overlay_evidence_manifest_sha256",
        "paired_results",
        "report_id",
        "role",
        "sandbox_limitations",
        "schema_version",
        "scientific_claim_allowed",
        "source_binding_id",
        "source_root_manifest_sha256",
        "status",
    }
)
_FROZEN_INPUT_PLAN_KEYS = frozenset(
    {
        "cases",
        "counts",
        "execute_requested",
        "execution_performed",
        "executor_coordinates",
        "frozen_spec_id",
        "frozen_spec_path",
        "frozen_spec_sha256",
        "functional_contract_set_sha256",
        "functional_contracts",
        "official_artifact_replacement_allowed",
        "output_dir",
        "preflight_id",
        "record_type",
        "schema_version",
        "scientific_claim_allowed",
        "source_listed_paths_sha256",
        "source_live_root",
        "source_root_closure_sha256",
        "source_root_manifest_sha256",
        "source_root_provenance_path",
        "source_root_provenance_sha256",
        "status",
        "zero_execution_counts",
    }
)
_FROZEN_INPUT_CASE_KEYS = frozenset(
    {"adapter_id", "arms", "family", "functional_contract", "task_id"}
)
_FROZEN_INPUT_CONTRACT_KEYS = frozenset(
    {
        "contract_id",
        "requirement_ids",
        "requirement_ids_sha256",
        "source_artifact_path",
        "source_artifact_sha256",
    }
)
_FROZEN_INPUT_CONTRACT_SUMMARY_KEYS = frozenset(
    {
        "contract_id",
        "requirement_ids",
        "source_artifact_path",
        "source_artifact_sha256",
        "task_id",
    }
)
_FROZEN_INPUT_ARM_KEYS = frozenset(
    {
        "arm_role",
        "assignment_id",
        "assignment_path",
        "assignment_sha256",
        "code_sha256",
        "contract_id",
        "functional_contract_path",
        "functional_contract_sha256",
        "generated_code_artifact_sha256",
        "generated_code_path",
        "unit_manifest_path",
        "unit_manifest_sha256",
    }
)
_EXECUTOR_POLICY_KEYS = frozenset(
    {
        "dynamic_library_bindings",
        "dynamic_library_inspector_path",
        "dynamic_library_inspector_sha256",
        "executes_generated_code",
        "executes_in_main_process",
        "executor_id",
        "isolated_subprocess",
        "minimal_environment",
        "mode",
        "namespace_isolation_enforced",
        "network_isolation_enforced",
        "old_root_exposed",
        "python_executable_sha256",
        "python_runtime_root",
        "python_runtime_sha256",
        "resource_limits",
        "runtime_capabilities",
        "sandbox_backend",
        "sandbox_backend_path",
        "sandbox_backend_sha256",
        "sandbox_backend_version",
        "supported_adapter_ids",
        "temporary_workspace",
        "timeout_seconds",
        "virtual_commands_only",
        "worker_policy_sha256",
    }
)
_DYNAMIC_LIBRARY_BINDING_KEYS = frozenset({"sha256", "source", "target"})
_REQUIRED_RUNTIME_CAPABILITIES = frozenset(
    {
        "bubblewrap_ipc_namespace",
        "bubblewrap_network_namespace",
        "bubblewrap_pid_namespace",
        "bubblewrap_user_namespace",
        "bubblewrap_uts_namespace",
        "capabilities_dropped",
        "content_addressed_dynamic_library_closure",
        "host_root_not_bound",
        "kernel_seccomp_process_exec_socket_filter",
        "landlock_existing_workspace_write_closure",
        "sealed_analyzer_mount_namespace",
        "sealed_analyzer_pid_namespace",
        "sealed_analyzer_private_proc",
        "sealed_analyzer_user_namespace",
        "tmpfs_work_root",
    }
)
_FROZEN_RESOURCE_LIMITS = {
    "address_space_bytes": 1024 * 1024 * 1024,
    "cpu_seconds": 5,
    "file_bytes": 16 * 1024 * 1024,
    "open_files": 64,
    "processes": 32,
}
_OBSERVATION_KEYS = frozenset(
    {
        "command_events",
        "error",
        "logs",
        "network_calls",
        "resource_limits",
        "return_value",
        "returncode",
        "sandbox_attestation",
        "sqlite_statements",
        "status",
        "stderr",
        "stdout",
        "unvirtualized_process_calls",
    }
)
_SANDBOX_ATTESTATION_KEYS = frozenset(
    {
        "bindings",
        "bubblewrap_empty_mount_root",
        "capabilities_dropped",
        "host_root_read_only_or_hidden",
        "kernel_policy",
        "network_namespace",
        "path",
        "work_tmpfs",
    }
)
_KERNEL_POLICY_KEYS = frozenset(
    {
        "landlock_abi",
        "landlock_existing_work_files_write_only",
        "landlock_file_creation_denied",
        "seccomp_arch",
        "seccomp_blocked_syscalls",
    }
)
_FAMILY_SPEC_KEYS = frozenset(
    {
        "family",
        "functional_contract_id",
        "functional_contract_record_sha256",
        "functional_contract_source_artifact_sha256",
        "functional_contract_source_path",
        "functional_requirement_ids",
        "functional_requirement_ids_sha256",
        "task_id",
        "tune_assignment_ids",
        "validation_expected_fail",
        "validation_expected_pass",
    }
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _SHA256


def _is_posix_absolute(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/")
        and "\\" not in value
        and PurePosixPath(value).as_posix() == value
    )


def _is_posix_relative(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and "\\" not in value
        and not PurePosixPath(value).is_absolute()
        and PurePosixPath(value).as_posix() == value
        and ".." not in PurePosixPath(value).parts
    )


def _is_exact_unique_string_set(value: object, expected: frozenset[str]) -> bool:
    """Accept any sequence order while preserving exact set semantics."""
    return (
        type(value) is list
        and all(type(item) is str and item for item in value)
        and len(value) == len(expected)
        and len(set(value)) == len(value)
        and set(value) == expected
    )


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError(f"expected JSON objects: {path}")
        rows.append(value)
    return rows


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _resolve_posix_file(root: Path, raw: object, *, label: str) -> Path:
    if type(raw) is not str or not raw or "\\" in raw:
        raise ValueError(f"{label} path failed validation")
    relative = Path(raw)
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError(f"{label} path escaped root") from None
    if relative.is_absolute() or relative.as_posix() != raw or not resolved.is_file():
        raise ValueError(f"{label} path failed validation")
    return resolved


def _load_spec(path: Path) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    spec = _read_json(path)
    if frozenset(spec) != _SPEC_KEYS or spec.get("schema_version") != "1.0":
        raise ValueError("calibration spec schema failed validation")
    families = spec.get("families")
    thresholds = spec.get("thresholds")
    if (
        type(spec.get("calibration_id")) is not str
        or not spec["calibration_id"]
        or type(spec.get("purpose")) is not str
        or not spec["purpose"]
        or type(spec.get("executable_source_spec_id")) is not str
        or not spec["executable_source_spec_id"].startswith("executable_sensitivity_source_spec_")
        or not _is_sha256(spec.get("executable_source_spec_sha256"))
        or not _is_sha256(spec.get("frozen_functional_contracts_sha256"))
        or not _is_sha256(spec.get("functional_contract_set_sha256"))
        or not _is_sha256(spec.get("source_final_delivery_sha256"))
        or not _is_sha256(spec.get("source_live_root_manifest_sha256"))
        or not _is_sha256(spec.get("source_live_root_provenance_sha256"))
        or spec.get("tune_expected_cases") != 8
        or not _is_sha256(spec.get("validation_cases_sha256"))
        or spec.get("validation_expected_cases") != 16
        or spec.get("candidate_roles") != _CANDIDATE_ROLES
        or type(families) is not list
        or len(families) != 4
        or type(thresholds) is not dict
        or frozenset(thresholds) != _THRESHOLD_KEYS
        or thresholds.get("tune_cases") != 8
        or thresholds.get("tune_min_correct") != 8
        or thresholds.get("tune_max_false_pass") != 0
        or thresholds.get("tune_max_equivalence_inconsistency") != 0
        or thresholds.get("tune_role") != "engineering_regression_gate_not_ranking"
        or thresholds.get("validation_cases") != 16
        or thresholds.get("validation_min_correct") != 15
        or thresholds.get("validation_max_false_pass") != 0
        or thresholds.get("validation_max_equivalence_inconsistency") != 0
        or thresholds.get("validation_max_invalid") != 0
        or thresholds.get("selection_rule")
        != "validation_correct_desc_false_fail_asc_candidate_id_asc"
    ):
        raise ValueError("calibration spec failed validation")
    by_family: dict[str, dict[str, object]] = {}
    assignment_ids: set[str] = set()
    for row in families:
        if type(row) is not dict or frozenset(row) != _FAMILY_SPEC_KEYS:
            raise ValueError("calibration family spec schema failed validation")
        family = row.get("family")
        task_id = row.get("task_id")
        tune_ids = row.get("tune_assignment_ids")
        contract_id = row.get("functional_contract_id")
        contract_path = row.get("functional_contract_source_path")
        requirement_ids = row.get("functional_requirement_ids")
        if (
            family not in _FAMILIES
            or family in by_family
            or type(task_id) is not str
            or not task_id
            or type(tune_ids) is not list
            or len(tune_ids) != 2
            or any(type(item) is not str or not item.startswith("assignment_") for item in tune_ids)
            or len(set(tune_ids)) != 2
            or any(item in assignment_ids for item in tune_ids)
            or type(contract_id) is not str
            or not contract_id.startswith("functional_contract_")
            or not _is_sha256(contract_id.removeprefix("functional_contract_"))
            or not _is_sha256(row.get("functional_contract_record_sha256"))
            or not _is_posix_relative(contract_path)
            or contract_path
            not in {
                f"units/{assignment_id}/functional-contract.jsonl" for assignment_id in tune_ids
            }
            or not _is_sha256(row.get("functional_contract_source_artifact_sha256"))
            or type(requirement_ids) is not list
            or not requirement_ids
            or any(type(item) is not str or not item for item in requirement_ids)
            or len(requirement_ids) != len(set(requirement_ids))
            or row.get("functional_requirement_ids_sha256") != canonical_sha256(requirement_ids)
            or row.get("validation_expected_pass") != 2
            or row.get("validation_expected_fail") != 2
        ):
            raise ValueError("calibration family spec failed validation")
        assignment_ids.update(tune_ids)
        by_family[family] = row
    if set(by_family) != _FAMILIES:
        raise ValueError("calibration family coverage failed validation")
    contract_summaries = [
        {
            "task_id": row["task_id"],
            "contract_id": row["functional_contract_id"],
            "source_artifact_path": row["functional_contract_source_path"],
            "source_artifact_sha256": row["functional_contract_source_artifact_sha256"],
            "requirement_ids": row["functional_requirement_ids"],
        }
        for row in sorted(by_family.values(), key=lambda item: str(item["task_id"]))
    ]
    if canonical_sha256(contract_summaries) != spec["functional_contract_set_sha256"]:
        raise ValueError("calibration functional contract set failed validation")
    return spec, by_family


def _validate_delivery(path: Path, spec: dict[str, object]) -> dict[str, object]:
    if _sha256_file(path) != spec["source_final_delivery_sha256"]:
        raise ValueError("source final delivery digest mismatch")
    delivery = _read_json(path)
    live = delivery.get("live")
    if (
        delivery.get("status") != "PROTOCOL_V2_FULL_LIVE_AND_ANALYSIS_DELIVERED"
        or type(live) is not dict
        or live.get("status") != "GATE_C_LIVE_COMPLETE"
        or live.get("manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or live.get("root_provenance_sha256") != spec["source_live_root_provenance_sha256"]
        or live.get("missing_complete_leaf_units") != 0
    ):
        raise ValueError("source final delivery failed validation")
    return delivery


def _load_frozen_input_plan(
    root: Path,
    spec: dict[str, object],
    *,
    family_specs: dict[str, dict[str, object]],
    source_binding: dict[str, object],
    rows: list[dict[str, object]],
    executor_policy: dict[str, object],
) -> str:
    plan = _read_json(root / "frozen-input-plan.json")
    plan_content = {key: value for key, value in plan.items() if key != "preflight_id"}
    cases = plan.get("cases")
    counts = plan.get("counts")
    zero_counts = plan.get("zero_execution_counts")
    coordinates = plan.get("executor_coordinates")
    contract_summaries = [
        {
            "task_id": row["task_id"],
            "contract_id": row["functional_contract_id"],
            "source_artifact_path": row["functional_contract_source_path"],
            "source_artifact_sha256": row["functional_contract_source_artifact_sha256"],
            "requirement_ids": row["functional_requirement_ids"],
        }
        for row in sorted(family_specs.values(), key=lambda item: str(item["task_id"]))
    ]
    if (
        frozenset(plan) != _FROZEN_INPUT_PLAN_KEYS
        or plan.get("preflight_id")
        != "executable_sensitivity_preflight_" + canonical_sha256(plan_content)
        or plan.get("schema_version") != "1.0"
        or plan.get("record_type") != "executable_functional_sensitivity_preflight"
        or plan.get("status") != "EXECUTABLE_FUNCTIONAL_SENSITIVITY_PREFLIGHT_COMPLETE"
        or plan.get("execute_requested") is not True
        or plan.get("execution_performed") is not False
        or plan.get("scientific_claim_allowed") is not False
        or plan.get("official_artifact_replacement_allowed") is not False
        or plan.get("source_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or plan.get("source_root_closure_sha256") != source_binding["source_root_closure_sha256"]
        or plan.get("source_listed_paths_sha256") != source_binding["listed_paths_sha256"]
        or plan.get("source_root_provenance_path") != "root-provenance.json"
        or plan.get("source_root_provenance_sha256") != spec["source_live_root_provenance_sha256"]
        or plan.get("frozen_spec_sha256") != spec["executable_source_spec_sha256"]
        or plan.get("frozen_spec_id") != spec["executable_source_spec_id"]
        or plan.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
        or plan.get("functional_contracts") != contract_summaries
        or type(plan.get("source_live_root")) is not str
        or not plan["source_live_root"]
        or type(plan.get("frozen_spec_path")) is not str
        or not plan["frozen_spec_path"]
        or type(plan.get("output_dir")) is not str
        or not plan["output_dir"]
        or counts != {"assignments": 8, "tasks": 4}
        or zero_counts
        != {
            "functional_judge_calls": 0,
            "generated_code_executions": 0,
            "provider_calls": 0,
            "security_oracle_calls": 0,
            "subprocess_calls": 0,
        }
        or type(coordinates) is not dict
        or set(coordinates) != {"bwrap_path", "python_relative_executable", "python_runtime_root"}
        or coordinates.get("bwrap_path") != executor_policy.get("sandbox_backend_path")
        or coordinates.get("python_runtime_root") != executor_policy.get("python_runtime_root")
        or not _is_posix_relative(coordinates.get("python_relative_executable"))
        or type(cases) is not list
        or len(cases) != 4
    ):
        raise ValueError("tune overlay frozen input plan failed validation")

    rows_by_assignment = {str(row.get("assignment_id")): row for row in rows}
    seen_assignments: set[str] = set()
    seen_families: set[str] = set()
    for case in cases:
        if type(case) is not dict or frozenset(case) != _FROZEN_INPUT_CASE_KEYS:
            raise ValueError("tune overlay frozen input case schema failed validation")
        family = case.get("family")
        task_id = case.get("task_id")
        adapter_id = case.get("adapter_id")
        contract = case.get("functional_contract")
        arms = case.get("arms")
        family_rows = [row for row in rows if row.get("family") == family]
        family_spec = family_specs.get(str(family))
        expected_contract = (
            {
                "contract_id": family_spec["functional_contract_id"],
                "source_artifact_path": family_spec["functional_contract_source_path"],
                "source_artifact_sha256": family_spec["functional_contract_source_artifact_sha256"],
                "requirement_ids": family_spec["functional_requirement_ids"],
                "requirement_ids_sha256": family_spec["functional_requirement_ids_sha256"],
            }
            if family_spec is not None
            else None
        )
        if (
            family not in _FAMILIES
            or family in seen_families
            or family_spec is None
            or type(contract) is not dict
            or frozenset(contract) != _FROZEN_INPUT_CONTRACT_KEYS
            or contract != expected_contract
            or len(family_rows) != 2
            or {row.get("task_id") for row in family_rows} != {task_id}
            or {row.get("adapter_id") for row in family_rows} != {adapter_id}
            or type(arms) is not list
            or len(arms) != 2
        ):
            raise ValueError("tune overlay frozen input case failed validation")
        seen_families.add(str(family))
        seen_arm_roles: set[str] = set()
        for arm in arms:
            if type(arm) is not dict or frozenset(arm) != _FROZEN_INPUT_ARM_KEYS:
                raise ValueError("tune overlay frozen input arm schema failed validation")
            assignment_id = arm.get("assignment_id")
            row = rows_by_assignment.get(str(assignment_id))
            if (
                row is None
                or assignment_id in seen_assignments
                or row.get("family") != family
                or row.get("task_id") != task_id
                or row.get("adapter_id") != adapter_id
                or arm.get("arm_role") != row.get("arm_role")
                or arm.get("arm_role") in seen_arm_roles
                or arm.get("generated_code_path") != row.get("source_artifact_path")
                or arm.get("generated_code_artifact_sha256") != row.get("source_artifact_sha256")
                or arm.get("code_sha256") != row.get("code_sha256")
                or arm.get("contract_id") != family_spec["functional_contract_id"]
                or arm.get("functional_contract_sha256")
                != family_spec["functional_contract_source_artifact_sha256"]
                or arm.get("functional_contract_path")
                != f"units/{assignment_id}/functional-contract.jsonl"
                or not _is_posix_relative(arm.get("assignment_path"))
                or not _is_sha256(arm.get("assignment_sha256"))
                or not _is_posix_relative(arm.get("generated_code_path"))
                or not _is_posix_relative(arm.get("unit_manifest_path"))
                or not _is_sha256(arm.get("unit_manifest_sha256"))
            ):
                raise ValueError("tune overlay frozen input arm failed validation")
            seen_assignments.add(str(assignment_id))
            seen_arm_roles.add(str(arm["arm_role"]))
            if (
                arm["arm_role"] == "target_patch"
                and arm["functional_contract_path"]
                != family_spec["functional_contract_source_path"]
            ):
                raise ValueError("tune overlay frozen contract source failed validation")
        if seen_arm_roles != {"noop_rewrite", "target_patch"}:
            raise ValueError("tune overlay frozen input arm coverage failed validation")
    if seen_families != _FAMILIES or seen_assignments != set(rows_by_assignment):
        raise ValueError("tune overlay frozen input coverage failed validation")
    return canonical_sha256(plan)


def _load_overlay_root_provenance(
    root: Path,
    spec: dict[str, object],
    *,
    family_specs: dict[str, dict[str, object]],
    evidence_manifest_sha256: str,
    rows: list[dict[str, object]],
) -> tuple[dict[str, object], str, str]:
    source_binding = _read_json(root / "source-binding.json")
    source_content = {
        key: value for key, value in source_binding.items() if key != "source_binding_id"
    }
    if (
        frozenset(source_binding) != _SOURCE_BINDING_KEYS
        or source_binding.get("schema_version") != "1.0"
        or source_binding.get("access_mode") != "read_only_verified_before_and_after"
        or source_binding.get("source_root_manifest_sha256")
        != spec["source_live_root_manifest_sha256"]
        or source_binding.get("source_binding_id")
        != "source_binding_" + canonical_sha256(source_content)
        or not _is_sha256(source_binding.get("source_root_closure_sha256"))
        or not _is_sha256(source_binding.get("listed_paths_sha256"))
        or type(source_binding.get("listed_files")) is not int
        or source_binding["listed_files"] < 1
    ):
        raise ValueError("tune overlay source binding failed validation")

    protocol = _read_json(root / "protocol.json")
    executor_policy = protocol.get("executor_policy")
    executor_policy_sha256 = protocol.get("executor_policy_sha256")
    adapter_ids = frozenset(str(row["adapter_id"]) for row in rows)
    dynamic_bindings = (
        executor_policy.get("dynamic_library_bindings") if type(executor_policy) is dict else None
    )
    runtime_capabilities = (
        executor_policy.get("runtime_capabilities") if type(executor_policy) is dict else None
    )
    if (
        frozenset(protocol) != _PROTOCOL_KEYS
        or protocol.get("schema_version") != "1.0"
        or protocol.get("functional_variable") != "Y_F^E"
        or protocol.get("measurement_method") != "deterministic_local_executable_fixture_v1"
        or protocol.get("execution_performed") is not True
        or protocol.get("official_artifact_replacement_allowed") is not False
        or protocol.get("scientific_claim_allowed") is not False
        or not _is_exact_unique_string_set(protocol.get("controlled_adapter_ids"), adapter_ids)
        or protocol.get("sandbox_limitations") != []
        or protocol.get("frozen_functional_contracts_path") != "frozen-functional-contracts.jsonl"
        or protocol.get("frozen_functional_contracts_sha256")
        != spec["frozen_functional_contracts_sha256"]
        or protocol.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
        or type(protocol.get("command_argv")) is not list
        or not protocol["command_argv"]
        or any(type(item) is not str or not item for item in protocol["command_argv"])
        or type(executor_policy) is not dict
        or frozenset(executor_policy) != _EXECUTOR_POLICY_KEYS
        or canonical_sha256(executor_policy) != executor_policy_sha256
        or type(executor_policy.get("executor_id")) is not str
        or not executor_policy["executor_id"]
        or executor_policy.get("mode") != "isolated_subprocess_v1"
        or executor_policy.get("executes_generated_code") is not True
        or executor_policy.get("executes_in_main_process") is not False
        or type(executor_policy.get("timeout_seconds")) not in {int, float}
        or not 0 < executor_policy["timeout_seconds"] <= 60
        or executor_policy.get("isolated_subprocess") is not True
        or executor_policy.get("temporary_workspace") is not True
        or executor_policy.get("minimal_environment") is not True
        or executor_policy.get("virtual_commands_only") is not True
        or executor_policy.get("old_root_exposed") is not False
        or executor_policy.get("namespace_isolation_enforced") is not True
        or executor_policy.get("network_isolation_enforced") is not True
        or not _is_exact_unique_string_set(
            executor_policy.get("supported_adapter_ids"), adapter_ids
        )
        or executor_policy.get("sandbox_backend") != "bubblewrap_v1"
        or not _is_posix_absolute(executor_policy.get("sandbox_backend_path"))
        or not _is_sha256(executor_policy.get("sandbox_backend_sha256"))
        or type(executor_policy.get("sandbox_backend_version")) is not str
        or not executor_policy["sandbox_backend_version"].startswith("bubblewrap ")
        or not _is_posix_absolute(executor_policy.get("python_runtime_root"))
        or not _is_sha256(executor_policy.get("python_runtime_sha256"))
        or not _is_sha256(executor_policy.get("python_executable_sha256"))
        or not _is_sha256(executor_policy.get("worker_policy_sha256"))
        or not _is_posix_absolute(executor_policy.get("dynamic_library_inspector_path"))
        or not _is_sha256(executor_policy.get("dynamic_library_inspector_sha256"))
        or type(dynamic_bindings) is not list
        or not dynamic_bindings
        or any(
            type(binding) is not dict
            or frozenset(binding) != _DYNAMIC_LIBRARY_BINDING_KEYS
            or not _is_posix_absolute(binding.get("target"))
            or not str(binding["target"]).startswith(("/lib/", "/lib64/"))
            or not _is_posix_absolute(binding.get("source"))
            or not _is_sha256(binding.get("sha256"))
            for binding in dynamic_bindings
        )
        or len({binding["target"] for binding in dynamic_bindings}) != len(dynamic_bindings)
        or [binding["target"] for binding in dynamic_bindings]
        != sorted(binding["target"] for binding in dynamic_bindings)
        or type(runtime_capabilities) is not list
        or any(type(item) is not str or not item for item in runtime_capabilities)
        or len(runtime_capabilities) != len(set(runtime_capabilities))
        or not _REQUIRED_RUNTIME_CAPABILITIES.issubset(set(runtime_capabilities))
        or executor_policy.get("resource_limits") != _FROZEN_RESOURCE_LIMITS
    ):
        raise ValueError("tune overlay isolated executor protocol failed validation")
    frozen_input_plan_sha256 = _load_frozen_input_plan(
        root,
        spec,
        family_specs=family_specs,
        source_binding=source_binding,
        rows=rows,
        executor_policy=executor_policy,
    )
    if protocol.get("frozen_input_plan_sha256") != frozen_input_plan_sha256:
        raise ValueError("tune overlay frozen input plan digest mismatch")

    report = _read_json(root / "report.json")
    report_content = {key: value for key, value in report.items() if key != "report_id"}
    counts = report.get("counts")
    if (
        frozenset(report) != _REPORT_KEYS
        or report.get("report_id")
        != "executable_sensitivity_report_" + canonical_sha256(report_content)
        or report.get("schema_version") != "1.0"
        or report.get("status") != "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE"
        or report.get("role") != "post_hoc_development_sensitivity_only"
        or report.get("scientific_claim_allowed") is not False
        or report.get("official_artifact_replacement_allowed") is not False
        or report.get("functional_variable") != "Y_F^E"
        or report.get("measurement_method") != "deterministic_local_executable_fixture_v1"
        or report.get("execution_performed") is not True
        or report.get("source_binding_id") != source_binding["source_binding_id"]
        or report.get("source_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or report.get("executor_policy_sha256") != executor_policy_sha256
        or report.get("frozen_input_plan_sha256") != frozen_input_plan_sha256
        or report.get("frozen_functional_contracts_path") != "frozen-functional-contracts.jsonl"
        or report.get("frozen_functional_contracts_sha256")
        != spec["frozen_functional_contracts_sha256"]
        or report.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
        or report.get("sandbox_limitations") != []
        or report.get("overlay_evidence_manifest_sha256") != evidence_manifest_sha256
        or report.get("judge_tune_cases_sha256") != _sha256_file(root / "judge-tune-cases.jsonl")
        or type(counts) is not dict
        or counts.get("tasks") != 4
        or counts.get("assignments") != 8
        or counts.get("target_assignments") != 4
        or counts.get("noop_assignments") != 4
        or counts.get("y_f_e_pass") != sum(row["y_f_e"] for row in rows)
        or counts.get("y_f_e_fail") != sum(1 - row["y_f_e"] for row in rows)
        or counts.get("judge_tune_cases") != 8
        or counts.get("functional_contracts") != 4
        or counts.get("provider_calls") != 0
        or counts.get("security_oracle_calls") != 0
        or type(report.get("paired_results")) is not list
        or len(report["paired_results"]) != 4
    ):
        raise ValueError("tune overlay terminal report failed validation")
    reported_pairs = report["paired_results"]
    for family in _FAMILIES:
        family_rows = [row for row in rows if row.get("family") == family]
        matching = [row for row in reported_pairs if row.get("family") == family]
        if len(family_rows) != 2 or len(matching) != 1:
            raise ValueError("tune overlay paired report failed validation")
        by_arm = {row["arm_role"]: row for row in family_rows}
        reported = matching[0]
        if (
            type(reported) is not dict
            or set(reported)
            != {
                "adapter_id",
                "family",
                "noop_y_f_e",
                "paired_target_minus_noop",
                "target_y_f_e",
                "task_id",
            }
            or reported.get("task_id") != family_rows[0]["task_id"]
            or reported.get("adapter_id") != family_rows[0]["adapter_id"]
            or reported.get("target_y_f_e") != by_arm["target_patch"]["y_f_e"]
            or reported.get("noop_y_f_e") != by_arm["noop_rewrite"]["y_f_e"]
            or reported.get("paired_target_minus_noop")
            != by_arm["target_patch"]["y_f_e"] - by_arm["noop_rewrite"]["y_f_e"]
        ):
            raise ValueError("tune overlay paired report failed validation")
    return executor_policy, executor_policy_sha256, source_binding["source_binding_id"]


def _load_frozen_contracts(
    root: Path,
    spec: dict[str, object],
    family_specs: dict[str, dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, TaskFunctionalContractRecord]]:
    path = root / "frozen-functional-contracts.jsonl"
    if not path.is_file() or _sha256_file(path) != spec["frozen_functional_contracts_sha256"]:
        raise ValueError("tune frozen functional contract artifact digest mismatch")
    raw_rows = _read_jsonl(path)
    if len(raw_rows) != 4:
        raise ValueError("tune frozen functional contract cardinality failed validation")
    normalized: list[dict[str, object]] = []
    by_task: dict[str, TaskFunctionalContractRecord] = {}
    specs_by_task = {str(row["task_id"]): row for row in family_specs.values()}
    for raw in raw_rows:
        try:
            record = TaskFunctionalContractRecord.model_validate(raw)
        except Exception:  # noqa: BLE001 - normalize strict model validation failures
            raise ValueError("tune frozen functional contract failed validation") from None
        row = record.model_dump(mode="json")
        family_spec = specs_by_task.get(record.task_id)
        requirement_ids = [item.requirement_id for item in record.requirements]
        if (
            row != raw
            or family_spec is None
            or record.task_id in by_task
            or record.contract_id != family_spec["functional_contract_id"]
            or canonical_sha256(row) != family_spec["functional_contract_record_sha256"]
            or requirement_ids != family_spec["functional_requirement_ids"]
            or canonical_sha256(requirement_ids) != family_spec["functional_requirement_ids_sha256"]
        ):
            raise ValueError("tune frozen functional contract binding failed validation")
        by_task[record.task_id] = record
        normalized.append(row)
    normalized.sort(key=lambda row: str(row["task_id"]))
    if [row["task_id"] for row in raw_rows] != [row["task_id"] for row in normalized] or set(
        by_task
    ) != set(specs_by_task):
        raise ValueError("tune frozen functional contract coverage failed validation")
    return normalized, by_task


def _load_overlay_evidence(
    root: Path,
    evidence_manifest_path: Path,
    spec: dict[str, object],
) -> dict[str, dict[str, object]]:
    evidence = _read_json(evidence_manifest_path)
    units = evidence.get("units")
    content = {key: value for key, value in evidence.items() if key != "overlay_evidence_id"}
    if (
        frozenset(evidence) != _EVIDENCE_KEYS
        or evidence.get("schema_version") != "1.0"
        or evidence.get("role") != "judge_tune_overlay_transitive_evidence"
        or evidence.get("source_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
        or evidence.get("frozen_functional_contracts_path") != "frozen-functional-contracts.jsonl"
        or evidence.get("frozen_functional_contracts_sha256")
        != spec["frozen_functional_contracts_sha256"]
        or evidence.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
        or evidence.get("overlay_evidence_id") != "overlay_evidence_" + canonical_sha256(content)
        or type(units) is not list
        or len(units) != 8
    ):
        raise ValueError("tune overlay evidence manifest failed validation")
    by_assignment: dict[str, dict[str, object]] = {}
    for unit in units:
        if type(unit) is not dict or frozenset(unit) != _EVIDENCE_UNIT_KEYS:
            raise ValueError("tune overlay evidence unit schema failed validation")
        assignment_id = unit.get("assignment_id")
        code_path = _resolve_posix_file(root, unit.get("code_path"), label="evidence code")
        measurement_path = _resolve_posix_file(
            root, unit.get("measurement_path"), label="evidence measurement"
        )
        unit_manifest_path = _resolve_posix_file(
            root, unit.get("unit_manifest_path"), label="evidence unit manifest"
        )
        if (
            type(assignment_id) is not str
            or not assignment_id.startswith("assignment_")
            or assignment_id in by_assignment
            or not _is_sha256(unit.get("code_sha256"))
            or _sha256_file(code_path) != unit["code_sha256"]
            or not _is_sha256(unit.get("measurement_sha256"))
            or _sha256_file(measurement_path) != unit["measurement_sha256"]
            or not _is_sha256(unit.get("unit_manifest_sha256"))
            or _sha256_file(unit_manifest_path) != unit["unit_manifest_sha256"]
            or type(unit.get("functional_contract_id")) is not str
            or not str(unit["functional_contract_id"]).startswith("functional_contract_")
            or not _is_posix_relative(unit.get("functional_contract_source_path"))
            or not _is_sha256(unit.get("functional_contract_source_sha256"))
            or type(unit.get("functional_requirement_ids")) is not list
            or not unit["functional_requirement_ids"]
            or any(type(item) is not str or not item for item in unit["functional_requirement_ids"])
            or unit.get("functional_requirement_ids_sha256")
            != canonical_sha256(unit["functional_requirement_ids"])
        ):
            raise ValueError("tune overlay evidence unit failed validation")
        unit_manifest = verify_closed_manifest(
            unit_manifest_path, label="functional executable overlay unit"
        )
        unit_root = unit_manifest_path.parent
        try:
            code_relative = code_path.relative_to(unit_root).as_posix()
            measurement_relative = measurement_path.relative_to(unit_root).as_posix()
        except ValueError:
            raise ValueError("tune overlay evidence files escaped unit root") from None
        covered = {item["path"]: item["sha256"] for item in unit_manifest["files"]}
        fixture_path = measurement_path.parent / "fixture.json"
        observation_path = measurement_path.parent / "execution-observation.json"
        try:
            fixture_relative = fixture_path.relative_to(unit_root).as_posix()
            observation_relative = observation_path.relative_to(unit_root).as_posix()
        except ValueError:
            raise ValueError("tune overlay raw evidence escaped unit root") from None
        if (
            covered.get(code_relative) != unit["code_sha256"]
            or covered.get(measurement_relative) != unit["measurement_sha256"]
            or not fixture_path.is_file()
            or covered.get(fixture_relative) != _sha256_file(fixture_path)
            or not observation_path.is_file()
            or covered.get(observation_relative) != _sha256_file(observation_path)
        ):
            raise ValueError("tune overlay unit manifest binding failed validation")
        by_assignment[assignment_id] = unit
    return by_assignment


def _validate_measurement(
    measurement: dict[str, object],
    row: dict[str, object],
    measurement_path: Path,
    *,
    executor_policy: dict[str, object],
    executor_policy_sha256: str,
    functional_contract: TaskFunctionalContractRecord,
    source_binding_id: str,
) -> None:
    measurement_content = {
        key: value for key, value in measurement.items() if key != "measurement_id"
    }
    checks = measurement.get("checks")
    verdicts = measurement.get("requirement_verdicts")
    if (
        frozenset(measurement) != _MEASUREMENT_KEYS
        or measurement.get("measurement_id")
        != "executable_functional_measurement_" + canonical_sha256(measurement_content)
        or measurement.get("schema_version") != "1.0"
        or measurement.get("record_type") != "executable_functional_sensitivity"
        or measurement.get("role") != "post_hoc_development_sensitivity_only"
        or measurement.get("scientific_claim_allowed") is not False
        or measurement.get("official_artifact_replacement_allowed") is not False
        or measurement.get("functional_variable") != "Y_F^E"
        or measurement.get("measurement_method") != "deterministic_local_executable_fixture_v1"
        or measurement.get("execution_performed") is not True
        or measurement.get("provider_calls") != 0
        or measurement.get("security_oracle_calls") != 0
        or measurement.get("source_binding_id") != source_binding_id
        or measurement.get("executor_policy_sha256") != executor_policy_sha256
        or not _is_sha256(measurement.get("fixture_instance_sha256"))
        or not _is_sha256(measurement.get("executor_policy_sha256"))
        or not _is_sha256(measurement.get("execution_observation_sha256"))
        or type(checks) is not list
        or not checks
        or type(verdicts) is not list
        or not verdicts
    ):
        raise ValueError("tune executable measurement failed validation")
    bound_fields = (
        "adapter_id",
        "arm_role",
        "assignment_id",
        "code_sha256",
        "expected_status",
        "family",
        "fixture_policy_sha256",
        "functional_contract_id",
        "functional_contract_source_path",
        "functional_contract_source_sha256",
        "functional_requirement_ids",
        "functional_requirement_ids_sha256",
        "source_artifact_path",
        "source_artifact_sha256",
        "source_root_manifest_sha256",
        "task_id",
        "y_f_e",
    )
    if any(measurement.get(field) != row.get(field) for field in bound_fields):
        raise ValueError("tune executable measurement binding failed validation")
    contract_requirement_ids = [item.requirement_id for item in functional_contract.requirements]
    if (
        measurement.get("functional_contract_id") != functional_contract.contract_id
        or measurement.get("task_id") != functional_contract.task_id
        or measurement.get("functional_requirement_ids") != contract_requirement_ids
        or measurement.get("functional_requirement_ids_sha256")
        != canonical_sha256(contract_requirement_ids)
    ):
        raise ValueError("tune executable measurement contract failed validation")
    fixture_path = measurement_path.parent / "fixture.json"
    observation_path = measurement_path.parent / "execution-observation.json"
    if not fixture_path.is_file() or not observation_path.is_file():
        raise ValueError("tune executable raw evidence is unavailable")
    fixture = _read_json(fixture_path)
    observation = _read_json(observation_path)
    sandbox = observation.get("sandbox_attestation")
    kernel_policy = sandbox.get("kernel_policy") if type(sandbox) is dict else None
    dynamic_bindings = executor_policy["dynamic_library_bindings"]
    expected_sandbox_bindings = [
        "/runtime:ro",
        *[f"{binding['target']}:ro" for binding in dynamic_bindings],
        "/fixture-src:ro",
        "/work:tmpfs",
    ]
    if (
        canonical_sha256(fixture) != measurement["fixture_instance_sha256"]
        or canonical_sha256(observation) != measurement["execution_observation_sha256"]
    ):
        raise ValueError("tune executable raw evidence binding failed validation")
    if (
        frozenset(observation) != _OBSERVATION_KEYS
        or observation.get("status") not in {"complete", "nonzero_exit"}
        or type(observation.get("returncode")) is not int
        or observation.get("error") is not None
        or observation.get("network_calls") != 0
        or observation.get("unvirtualized_process_calls") != 0
        or observation.get("resource_limits") != _FROZEN_RESOURCE_LIMITS
        or type(sandbox) is not dict
        or frozenset(sandbox) != _SANDBOX_ATTESTATION_KEYS
        or sandbox.get("bubblewrap_empty_mount_root") is not True
        or sandbox.get("work_tmpfs") is not True
        or sandbox.get("host_root_read_only_or_hidden") is not True
        or sandbox.get("network_namespace") is not True
        or sandbox.get("capabilities_dropped") is not True
        or sandbox.get("bindings") != expected_sandbox_bindings
        or sandbox.get("path") != "/fixture-src/fake-bin"
        or type(kernel_policy) is not dict
        or frozenset(kernel_policy) != _KERNEL_POLICY_KEYS
        or type(kernel_policy.get("landlock_abi")) is not int
        or kernel_policy["landlock_abi"] < 4
        or kernel_policy.get("landlock_existing_work_files_write_only") is not True
        or kernel_policy.get("landlock_file_creation_denied") is not True
        or kernel_policy.get("seccomp_arch") != "AUDIT_ARCH_X86_64"
        or type(kernel_policy.get("seccomp_blocked_syscalls")) is not list
        or any(type(item) is not int for item in kernel_policy.get("seccomp_blocked_syscalls", []))
        or not {41, 42, 56, 57, 58, 59, 322, 435}.issubset(
            set(kernel_policy.get("seccomp_blocked_syscalls", []))
        )
    ):
        raise ValueError("tune executable hardened sandbox evidence failed validation")

    checks_by_id: dict[str, dict[str, object]] = {}
    for check in checks:
        if (
            type(check) is not dict
            or frozenset(check) != _CHECK_KEYS
            or type(check.get("check_id")) is not str
            or not check["check_id"]
            or check["check_id"] in checks_by_id
            or type(check.get("passed")) is not bool
            or type(check.get("diagnostic")) is not str
            or not check["diagnostic"].strip()
            or check.get("expected_sha256") != canonical_sha256(check.get("expected"))
            or check.get("observed_sha256") != canonical_sha256(check.get("observed"))
            or check["passed"] != (check.get("expected") == check.get("observed"))
        ):
            raise ValueError("tune executable measurement check failed validation")
        checks_by_id[check["check_id"]] = check
    external_check = checks_by_id.get("no_uncontrolled_external_calls")
    external_zero = {"network_calls": 0, "unvirtualized_process_calls": 0}
    if (
        external_check is None
        or external_check.get("passed") is not True
        or external_check.get("expected") != external_zero
        or external_check.get("observed") != external_zero
    ):
        raise ValueError("tune executable external-call check failed validation")

    requirement_ids: set[str] = set()
    all_met = True
    ordered_requirement_ids: list[str] = []
    for verdict in verdicts:
        supporting = verdict.get("supporting_check_ids") if type(verdict) is dict else None
        if (
            type(verdict) is not dict
            or frozenset(verdict) != _REQUIREMENT_VERDICT_KEYS
            or type(verdict.get("requirement_id")) is not str
            or not verdict["requirement_id"]
            or verdict["requirement_id"] in requirement_ids
            or verdict.get("verdict") not in {"met", "not_met"}
            or type(supporting) is not list
            or not supporting
            or any(type(item) is not str or item not in checks_by_id for item in supporting)
            or len(supporting) != len(set(supporting))
            or (verdict["verdict"] == "met")
            != all(checks_by_id[item]["passed"] for item in supporting)
        ):
            raise ValueError("tune executable requirement verdict failed validation")
        requirement_ids.add(verdict["requirement_id"])
        ordered_requirement_ids.append(verdict["requirement_id"])
        all_met = all_met and verdict["verdict"] == "met"
    if ordered_requirement_ids != contract_requirement_ids:
        raise ValueError("tune executable contract verdict coverage failed validation")
    if measurement["y_f_e"] != int(
        all_met and all(check["passed"] for check in checks_by_id.values())
    ):
        raise ValueError("tune executable Y_F^E derivation failed validation")


def _load_tune_rows(
    overlay_dir: Path,
    spec: dict[str, object],
    family_specs: dict[str, dict[str, object]],
) -> tuple[list[dict[str, object]], str, str, list[dict[str, object]]]:
    root = overlay_dir.resolve()
    root_manifest_path = root / "artifact-manifest.json"
    verify_closed_manifest(root_manifest_path, label="functional executable overlay")
    root_manifest_sha256 = _sha256_file(root_manifest_path)
    contracts, contracts_by_task = _load_frozen_contracts(root, spec, family_specs)
    evidence_manifest_path = root / "overlay-evidence-manifest.json"
    evidence_manifest_sha256 = _sha256_file(evidence_manifest_path)
    evidence_by_assignment = _load_overlay_evidence(root, evidence_manifest_path, spec)
    rows = _read_jsonl(root / "judge-tune-cases.jsonl")
    if len(rows) != spec["tune_expected_cases"]:
        raise ValueError("tune overlay cardinality failed validation")
    executor_policy, executor_policy_sha256, source_binding_id = _load_overlay_root_provenance(
        root,
        spec,
        family_specs=family_specs,
        evidence_manifest_sha256=evidence_manifest_sha256,
        rows=rows,
    )
    seen_cases: set[str] = set()
    seen_assignments: set[str] = set()
    arm_by_family: dict[str, set[str]] = {family: set() for family in _FAMILIES}
    pair_by_family: dict[str, set[str]] = {family: set() for family in _FAMILIES}
    for row in rows:
        if type(row) is not dict or frozenset(row) != _OVERLAY_KEYS:
            raise ValueError("tune overlay row schema failed validation")
        family = row.get("family")
        case_id = row.get("case_id")
        assignment_id = row.get("assignment_id")
        expected = row.get("expected_status")
        y_f_e = row.get("y_f_e")
        code_path = _resolve_posix_file(root, row.get("code_path"), label="code")
        measurement_path = _resolve_posix_file(
            root, row.get("measurement_path"), label="measurement"
        )
        measurement = _read_json(measurement_path)
        evidence_unit = (
            evidence_by_assignment.get(assignment_id) if type(assignment_id) is str else None
        )
        family_spec = family_specs.get(family) if type(family) is str else None
        if (
            row.get("schema_version") != "1.0"
            or row.get("split") != "tune"
            or family_spec is None
            or row.get("task_id") != family_spec["task_id"]
            or assignment_id not in family_spec["tune_assignment_ids"]
            or type(case_id) is not str
            or not case_id
            or case_id
            != "judge_tune_case_"
            + canonical_sha256({key: value for key, value in row.items() if key != "case_id"})
            or case_id in seen_cases
            or assignment_id in seen_assignments
            or row.get("arm_role") not in {"target_patch", "noop_rewrite"}
            or row["arm_role"] in arm_by_family[family]
            or type(row.get("adapter_id")) is not str
            or not row["adapter_id"]
            or row.get("equivalence_group") is not None
            or row.get("frozen_functional_contracts_path") != "frozen-functional-contracts.jsonl"
            or row.get("frozen_functional_contracts_sha256")
            != spec["frozen_functional_contracts_sha256"]
            or row.get("functional_contract_set_sha256") != spec["functional_contract_set_sha256"]
            or row.get("functional_contract_id") != family_spec["functional_contract_id"]
            or row.get("functional_contract_source_path")
            != family_spec["functional_contract_source_path"]
            or row.get("functional_contract_source_sha256")
            != family_spec["functional_contract_source_artifact_sha256"]
            or row.get("functional_requirement_ids") != family_spec["functional_requirement_ids"]
            or row.get("functional_requirement_ids_sha256")
            != family_spec["functional_requirement_ids_sha256"]
            or type(row.get("paired_group_id")) is not str
            or not row["paired_group_id"].startswith("functional_pair_")
            or not _is_sha256(row["paired_group_id"].removeprefix("functional_pair_"))
            or type(y_f_e) is not int
            or y_f_e not in {0, 1}
            or expected != ("pass" if y_f_e == 1 else "fail")
            or not _is_sha256(row.get("code_sha256"))
            or _sha256_file(code_path) != row["code_sha256"]
            or not _is_sha256(row.get("measurement_sha256"))
            or _sha256_file(measurement_path) != row["measurement_sha256"]
            or row.get("source_root_manifest_sha256") != spec["source_live_root_manifest_sha256"]
            or row.get("overlay_evidence_manifest_sha256") != evidence_manifest_sha256
            or not _is_sha256(row.get("fixture_policy_sha256"))
            or type(row.get("source_artifact_path")) is not str
            or not row["source_artifact_path"]
            or not _is_sha256(row.get("source_artifact_sha256"))
            or evidence_unit is None
            or evidence_unit.get("code_path") != row.get("code_path")
            or evidence_unit.get("code_sha256") != row.get("code_sha256")
            or evidence_unit.get("measurement_path") != row.get("measurement_path")
            or evidence_unit.get("measurement_sha256") != row.get("measurement_sha256")
            or any(
                evidence_unit.get(field) != row.get(field)
                for field in (
                    "functional_contract_id",
                    "functional_contract_source_path",
                    "functional_contract_source_sha256",
                    "functional_requirement_ids",
                    "functional_requirement_ids_sha256",
                )
            )
        ):
            raise ValueError("tune overlay row failed validation")
        _validate_measurement(
            measurement,
            row,
            measurement_path,
            executor_policy=executor_policy,
            executor_policy_sha256=executor_policy_sha256,
            functional_contract=contracts_by_task[row["task_id"]],
            source_binding_id=source_binding_id,
        )
        seen_cases.add(case_id)
        seen_assignments.add(assignment_id)
        arm_by_family[family].add(row["arm_role"])
        pair_by_family[family].add(row["paired_group_id"])
    if any(roles != {"target_patch", "noop_rewrite"} for roles in arm_by_family.values()):
        raise ValueError("tune overlay arm coverage failed validation")
    if any(len(groups) != 1 for groups in pair_by_family.values()):
        raise ValueError("tune overlay paired-group coverage failed validation")
    if seen_assignments != set(evidence_by_assignment):
        raise ValueError("tune overlay evidence assignment coverage failed validation")
    return rows, root_manifest_sha256, evidence_manifest_sha256, contracts


def _load_validation_rows(
    path: Path,
    spec: dict[str, object],
    family_specs: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    rows = _read_jsonl(path)
    if len(rows) != spec["validation_expected_cases"]:
        raise ValueError("validation fixture cardinality failed validation")
    seen_cases: set[str] = set()
    seen_seeds: set[int] = set()
    counts = {family: {"pass": 0, "fail": 0, "equivalence": {}} for family in _FAMILIES}
    for row in rows:
        if type(row) is not dict or frozenset(row) != _VALIDATION_KEYS:
            raise ValueError("validation fixture row schema failed validation")
        family = row.get("family")
        family_spec = family_specs.get(family) if type(family) is str else None
        case_id = row.get("case_id")
        seed_id = row.get("seed_id")
        expected = row.get("expected_status")
        equivalence = row.get("equivalence_group")
        code_text = row.get("code_text")
        if (
            row.get("schema_version") != "1.0"
            or row.get("split") != "validation"
            or family_spec is None
            or row.get("task_id") != family_spec["task_id"]
            or type(case_id) is not str
            or not case_id
            or case_id in seen_cases
            or type(seed_id) is not int
            or seed_id in seen_seeds
            or not 95_001 <= seed_id <= 95_999
            or type(code_text) is not str
            or not code_text.strip()
            or expected not in {"pass", "fail"}
            or type(row.get("fixture_role")) is not str
            or not row["fixture_role"]
            or (expected == "pass" and (type(equivalence) is not str or not equivalence))
            or (expected == "fail" and equivalence is not None)
        ):
            raise ValueError("validation fixture row failed validation")
        compile(code_text, f"<{case_id}>", "exec")
        seen_cases.add(case_id)
        seen_seeds.add(seed_id)
        counts[family][expected] += 1
        if equivalence is not None:
            group_counts = counts[family]["equivalence"]
            group_counts[equivalence] = group_counts.get(equivalence, 0) + 1
    for family, values in counts.items():
        family_spec = family_specs[family]
        if (
            values["pass"] != family_spec["validation_expected_pass"]
            or values["fail"] != family_spec["validation_expected_fail"]
            or sorted(values["equivalence"].values()) != [2]
        ):
            raise ValueError("validation fixture balance failed validation")
    return rows


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--source-final-delivery", type=Path, required=True)
    parser.add_argument("--tune-overlay-dir", type=Path, required=True)
    parser.add_argument("--validation-cases", type=Path, required=True)
    parser.add_argument("--contracts", type=Path)
    parser.add_argument(
        "--new-candidate-protocol-version",
        choices=("v2", "v3"),
        default="v2",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit("refusing to overwrite an existing calibration plan")
    try:
        spec_path = args.spec.resolve()
        delivery_path = args.source_final_delivery.resolve()
        validation_path = args.validation_cases.resolve()
        spec, family_specs = _load_spec(spec_path)
        _validate_delivery(delivery_path, spec)
        (
            tune_rows,
            overlay_manifest_sha256,
            evidence_manifest_sha256,
            contracts,
        ) = _load_tune_rows(
            args.tune_overlay_dir,
            spec,
            family_specs,
        )
        authoritative_contracts_path = (
            args.tune_overlay_dir.resolve() / "frozen-functional-contracts.jsonl"
        )
        if args.contracts is not None and args.contracts.resolve() != authoritative_contracts_path:
            raise ValueError("contracts must be the tune overlay frozen functional contracts")
        if _sha256_file(validation_path) != spec["validation_cases_sha256"]:
            raise ValueError("validation fixture artifact digest mismatch")
        validation_rows = _load_validation_rows(validation_path, spec, family_specs)

        provider_cases: list[dict[str, object]] = []
        metadata: list[dict[str, object]] = []
        tune_seed_by_assignment = {
            assignment_id: 94_001 + index
            for index, assignment_id in enumerate(sorted(row["assignment_id"] for row in tune_rows))
        }
        overlay_root = args.tune_overlay_dir.resolve()
        for row in tune_rows:
            seed_id = tune_seed_by_assignment[row["assignment_id"]]
            code_path = _resolve_posix_file(overlay_root, row["code_path"], label="code")
            code_bytes = code_path.read_bytes()
            if hashlib.sha256(code_bytes).hexdigest() != row["code_sha256"]:
                raise ValueError("tune code changed after overlay verification")
            code_text = code_bytes.decode("utf-8")
            provider_cases.append(
                {
                    "case_id": row["case_id"],
                    "task_id": row["task_id"],
                    "seed_id": seed_id,
                    "code_text": code_text,
                    "expected_status": row["expected_status"],
                }
            )
            metadata.append(
                {
                    "schema_version": "1.0",
                    "case_id": row["case_id"],
                    "task_id": row["task_id"],
                    "seed_id": seed_id,
                    "split": "tune",
                    "family": row["family"],
                    "equivalence_group": row["equivalence_group"],
                    "paired_group_id": row["paired_group_id"],
                    "expected_status": row["expected_status"],
                    "code_sha256": row["code_sha256"],
                    "source_kind": "d_dev_verified_live_artifact",
                    "source_id": row["assignment_id"],
                    "source_role": row["arm_role"],
                    "source_path": row["source_artifact_path"],
                    "source_sha256": row["source_artifact_sha256"],
                    "source_root_manifest_sha256": row["source_root_manifest_sha256"],
                    "gold_method": "Y_F^E",
                    "gold_evidence_path": row["measurement_path"],
                    "gold_evidence_sha256": row["measurement_sha256"],
                }
            )
        validation_source_sha256 = _sha256_file(validation_path)
        for row in validation_rows:
            provider_cases.append(
                {
                    "case_id": row["case_id"],
                    "task_id": row["task_id"],
                    "seed_id": row["seed_id"],
                    "code_text": row["code_text"],
                    "expected_status": row["expected_status"],
                }
            )
            metadata.append(
                {
                    "schema_version": "1.0",
                    "case_id": row["case_id"],
                    "task_id": row["task_id"],
                    "seed_id": row["seed_id"],
                    "split": "validation",
                    "family": row["family"],
                    "equivalence_group": row["equivalence_group"],
                    "paired_group_id": None,
                    "expected_status": row["expected_status"],
                    "code_sha256": hashlib.sha256(row["code_text"].encode("utf-8")).hexdigest(),
                    "source_kind": "frozen_validation_fixture",
                    "source_id": row["case_id"],
                    "source_role": row["fixture_role"],
                    "source_path": validation_path.name,
                    "source_sha256": validation_source_sha256,
                    "source_root_manifest_sha256": None,
                    "gold_method": "frozen_clear_semantic_fixture_v1",
                    "gold_evidence_path": validation_path.name,
                    "gold_evidence_sha256": validation_source_sha256,
                }
            )
        provider_cases.sort(key=lambda row: row["case_id"])
        metadata.sort(key=lambda row: row["case_id"])
        if (
            len(provider_cases) != 24
            or len({row["case_id"] for row in provider_cases}) != 24
            or {row["case_id"] for row in provider_cases} != {row["case_id"] for row in metadata}
        ):
            raise ValueError("combined calibration case closure failed validation")

        tune_cases = [
            row
            for row in provider_cases
            if next(item for item in metadata if item["case_id"] == row["case_id"])["split"]
            == "tune"
        ]
        pilot: list[dict[str, object]] = []
        for expected in ("fail", "pass"):
            matches = sorted(
                (row for row in tune_cases if row["expected_status"] == expected),
                key=lambda row: row["case_id"],
            )
            if matches:
                pilot.append(matches[0])
        if len(pilot) < 2:
            pilot = sorted(tune_cases, key=lambda row: row["case_id"])[:2]
        pilot_ids = {row["case_id"] for row in pilot}
        remaining = [row for row in provider_cases if row["case_id"] not in pilot_ids]
        if len(pilot) != 2 or len(remaining) != 22:
            raise ValueError("pilot partition failed validation")

        plan_core: dict[str, object] = {
            "schema_version": "1.0",
            "calibration_id": spec["calibration_id"],
            "calibration_spec_sha256": _sha256_file(spec_path),
            "candidate_roles": spec["candidate_roles"],
            "executable_source_spec_id": spec["executable_source_spec_id"],
            "executable_source_spec_sha256": spec["executable_source_spec_sha256"],
            "frozen_functional_contracts_sha256": spec["frozen_functional_contracts_sha256"],
            "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
            "comparison_design": {
                "baseline_protocol_version": "v1",
                "new_candidate_protocol_version": args.new_candidate_protocol_version,
                "same_model_required": True,
                "expected_candidates": 2,
                "expected_single_pass_attempts_per_candidate": 24,
                "expected_total_functional_judge_provider_attempts": 48,
            },
            "purpose": spec["purpose"],
            "scientific_claim_allowed": False,
            "status": "FUNCTIONAL_JUDGE_CALIBRATION_PLAN_COMPLETE",
            "case_counts": {
                "total": 24,
                "tune": 8,
                "validation": 16,
                "families": 4,
                "pilot": 2,
                "remaining": 22,
            },
            "new_calls": {
                "functional_judge_provider_attempts": 0,
                "generation_provider_attempts": 0,
                "oracle_executions": 0,
            },
            "source_final_delivery_sha256": spec["source_final_delivery_sha256"],
            "source_live_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
            "source_live_root_provenance_sha256": spec["source_live_root_provenance_sha256"],
            "tune_overlay_root_manifest_sha256": overlay_manifest_sha256,
            "tune_overlay_evidence_manifest_sha256": evidence_manifest_sha256,
            "validation_cases_sha256": validation_source_sha256,
            "provider_cases_sha256": canonical_sha256(provider_cases),
            "case_metadata_sha256": canonical_sha256(metadata),
            "contracts_sha256": canonical_sha256(contracts),
            "pilot_case_ids": sorted(pilot_ids),
            "thresholds": spec["thresholds"],
        }
        plan = {
            **plan_core,
            "plan_id": "functional_judge_calibration_plan_" + canonical_sha256(plan_core),
        }

        output_dir.mkdir(parents=True, exist_ok=False)
        _write_jsonl(output_dir / "cases.jsonl", provider_cases)
        _write_jsonl(output_dir / "pilot-cases.jsonl", pilot)
        _write_jsonl(output_dir / "remaining-cases.jsonl", remaining)
        _write_jsonl(output_dir / "calibration-case-metadata.jsonl", metadata)
        _write_jsonl(output_dir / "contracts.jsonl", contracts)
        _write_json(output_dir / "plan.json", plan)
        _write_json(
            output_dir / "environment.json",
            {
                "schema_version": "1.0",
                "captured_at_utc": _utc_now(),
                "working_directory": str(Path.cwd().resolve()),
                "python_executable": sys.executable,
                "python_version": platform.python_version(),
                "platform": platform.platform(),
            },
        )
        _write_json(
            output_dir / "command.json",
            {
                "schema_version": "1.0",
                "argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "secret_in_argv": False,
            },
        )
        write_closed_manifest_atomic(output_dir, label="functional judge calibration plan")
        print("FUNCTIONAL_JUDGE_CALIBRATION_PLAN_COMPLETE")
        return 0
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 - CLI publishes only sanitized failure type
        raise SystemExit(
            f"functional Judge calibration planning failed: {type(exc).__name__}"
        ) from None


if __name__ == "__main__":
    raise SystemExit(main())

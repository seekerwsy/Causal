"""Build the frozen 55-task independent mechanism/function JCI table."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from secaware.exploratory.independent_validation_run import _verify_manifest
from secaware.exploratory.randomized_discovery_bootstrap import _manifest
from secaware.exploratory.randomized_discovery_v2_fci import (
    _environment,
    _read_json,
    _write_json,
    _write_jsonl,
)
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file

_SCHEMA_VERSION = "1.0"
_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_VARIABLE_IDS = (
    "c.arm",
    "z.target_mechanism_realized",
    "y.discovery_functional",
)
_EXPECTED_TASKS = 55
_EXPECTED_ROWS = 220
_MODEL = "phi-4-14b"


def _resolved_input(repo_root: Path, record: object, *, directory: bool) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("independent analysis input record failed validation")
    path = (repo_root / str(record["path"])).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError:
        raise ValueError("independent analysis input escaped repository") from None
    exists = path.is_dir() if directory else path.is_file()
    digest_path = path / "artifact-manifest.json" if directory else path
    if not exists or sha256_file(digest_path) != record["sha256"]:
        raise ValueError("independent analysis input digest failed validation")
    return path


def _validated_config(repo_root: Path, config_path: Path) -> tuple[dict[str, Any], Path, Path]:
    config = _read_json(config_path)
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("analysis_table_id")
        != "five_cwe_independent_validation_mechanism_function_table_v1"
        or config.get("model_id") != _MODEL
        or config.get("expected_tasks") != _EXPECTED_TASKS
        or config.get("expected_assignments") != _EXPECTED_ROWS
        or config.get("arms") != list(_ARMS)
        or config.get("variables") != list(_VARIABLE_IDS)
        or config.get("unknown_functional_handling") != "map_to_zero_and_retain_diagnostic"
        or config.get("oracle_calls_allowed") is not False
        or config.get("provider_calls_allowed") is not False
    ):
        raise ValueError("independent analysis table config failed validation")
    archive = _resolved_input(repo_root, config.get("results_archive"), directory=False)
    plan = _resolved_input(repo_root, config.get("execution_plan"), directory=True)
    runtime = _resolved_input(repo_root, config.get("runtime_freeze"), directory=True)
    extracted = (repo_root / str(config.get("extracted_results_root"))).resolve()
    try:
        extracted.relative_to(repo_root)
    except ValueError:
        raise ValueError("independent analysis result root escaped repository") from None
    if not extracted.is_dir() or sha256_file(archive) != config["results_archive"]["sha256"]:
        raise ValueError("independent analysis result archive failed validation")
    run_manifests = config.get("run_manifests")
    archive_member_names = config.get("archive_member_names")
    if (
        type(run_manifests) is not dict
        or len(run_manifests) != 5
        or type(archive_member_names) is not dict
        or set(archive_member_names) != set(run_manifests)
        or len(set(archive_member_names.values())) != 5
    ):
        raise ValueError("independent analysis run set failed validation")
    for name, digest in run_manifests.items():
        run_dir = (extracted / str(name)).resolve()
        if (
            run_dir.parent != extracted
            or not run_dir.is_dir()
            or sha256_file(run_dir / "artifact-manifest.json") != digest
        ):
            raise ValueError("independent analysis run manifest failed validation")
        _verify_manifest(run_dir / "artifact-manifest.json")
    return config, plan, runtime


def _one_jsonl(path: Path) -> dict[str, Any]:
    rows = read_jsonl(path, required=True, allow_empty=False)
    if len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError("independent analysis unit JSONL failed validation")
    return rows[0]


def _complete_units(
    extracted: Path, run_names: tuple[str, ...]
) -> tuple[dict[str, Path], list[str]]:
    complete: dict[str, Path] = {}
    errors: list[str] = []
    for name in run_names:
        units = extracted / name / "units"
        for unit_dir in sorted(units.iterdir() if units.is_dir() else ()):
            if not unit_dir.is_dir():
                continue
            status = _read_json(unit_dir / "status.json")
            assignment_id = str(status.get("assignment_id"))
            if unit_dir.name != assignment_id:
                raise ValueError("independent analysis unit identity failed validation")
            if status.get("status") == "COMPLETE":
                if assignment_id in complete:
                    raise ValueError("independent analysis duplicate completion failed validation")
                complete[assignment_id] = unit_dir
            elif status.get("status") == "ERROR":
                errors.append(assignment_id)
            else:
                raise ValueError("independent analysis terminal status failed validation")
    return complete, errors


def _project_unit(
    unit_dir: Path,
    planned: dict[str, Any],
    *,
    functional_policy_sha256: str,
    mechanism_policy_sha256: str,
) -> dict[str, object]:
    assignment = _one_jsonl(unit_dir / "assignment.jsonl")
    status = _read_json(unit_dir / "status.json")
    crosswalk = _read_json(unit_dir / "gate-a-crosswalk.json")
    functional = _one_jsonl(unit_dir / "functional-outcome.jsonl")
    mechanism = _read_json(unit_dir / "code-mechanism-measurement.json")
    generated = _one_jsonl(unit_dir / "generated-code.jsonl")
    assignment_id = str(planned["assignment_id"])
    task_id = str(planned["experimental_unit"]["task_id"])
    arm = str(planned["arm_role"])
    functional_status = functional.get("status")
    z_value = mechanism.get("z_target_mechanism_realized")
    if (
        assignment != planned
        or status.get("status") != "COMPLETE"
        or status.get("assignment_id") != assignment_id
        or status.get("oracle_calls") != 0
        or functional.get("assignment_id") != assignment_id
        or functional.get("evaluator_policy_sha256") != functional_policy_sha256
        or functional_status not in {"pass", "fail", "unknown"}
        or status.get("functional_status") != functional_status
        or mechanism.get("policy_sha256") != mechanism_policy_sha256
        or mechanism.get("target_cwe") != crosswalk.get("cwe")
        or mechanism.get("code_sha256") != generated.get("code_sha256")
        or z_value not in {0, 1}
        or status.get("z_target_mechanism_realized") != z_value
        or crosswalk.get("assignment_id") != assignment_id
        or crosswalk.get("task_id") != task_id
        or crosswalk.get("arm_role") != arm
        or arm not in _ARMS
        or planned["experimental_unit"].get("model_id") != _MODEL
    ):
        raise ValueError("independent analysis unit projection failed validation")
    unit_manifest = unit_dir / "artifact-manifest.json"
    return {
        "schema_version": _SCHEMA_VERSION,
        "assignment_id": assignment_id,
        "task_id": task_id,
        "model_id": _MODEL,
        "arm_role": arm,
        "cwe": str(crosswalk["cwe"]),
        "language": str(crosswalk["language"]),
        "target_spec_id": str(planned["target_spec_id"]),
        "target_instance_id": str(planned["target_instance_id"]),
        "arm_protocol_id": str(planned["arm_protocol_id"]),
        "protocol_instance_id": str(planned["protocol_instance_id"]),
        "values": {
            "c.arm": _ARMS.index(arm),
            "z.target_mechanism_realized": int(z_value),
            "y.discovery_functional": int(functional_status == "pass"),
        },
        "diagnostics": {
            "functional_status": str(functional_status),
            "mechanism_state": str(mechanism["mechanism_state"]),
        },
        "provenance": {
            "unit_manifest_sha256": sha256_file(unit_manifest),
            "functional_outcome_id": functional["program_functional_outcome_id"],
            "mechanism_request_sha256": mechanism["request_sha256"],
            "mechanism_response_sha256": mechanism["response_sha256"],
        },
    }


def build_independent_validation_analysis_table(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError("independent analysis table output already exists")
    config, plan_dir, runtime_dir = _validated_config(repo_root, config_path)
    extracted = (repo_root / config["extracted_results_root"]).resolve()
    runtime = _read_json(runtime_dir / "runtime-policy.json")
    if (
        runtime.get("model_id") != _MODEL
        or runtime.get("oracle_role") != "not_run_for_frozen_mechanism_function_replication"
        or runtime.get("source_variable") != _VARIABLE_IDS[1]
        or runtime.get("target_variable") != _VARIABLE_IDS[2]
        or runtime.get("reference_marks") != ["tail", "arrow"]
    ):
        raise ValueError("independent analysis runtime policy failed validation")
    planned_rows = read_jsonl(plan_dir / "assignments.jsonl", required=True, allow_empty=False)
    planned = {str(row["assignment_id"]): row for row in planned_rows}
    if len(planned_rows) != _EXPECTED_ROWS or len(planned) != _EXPECTED_ROWS:
        raise ValueError("independent analysis plan population failed validation")
    run_names = tuple(config["run_manifests"])
    complete, historical_errors = _complete_units(extracted, run_names)
    if set(complete) != set(planned) or len(historical_errors) != 1:
        raise ValueError("independent analysis completion closure failed validation")
    rows = [
        _project_unit(
            complete[assignment_id],
            planned[assignment_id],
            functional_policy_sha256=str(runtime["functional_judge_policy_sha256"]),
            mechanism_policy_sha256=str(runtime["mechanism_policy_sha256"]),
        )
        for assignment_id in sorted(planned)
    ]
    blocks: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        blocks.setdefault(str(row["task_id"]), []).append(row)
    for block in blocks.values():
        if sorted(str(row["arm_role"]) for row in block) != sorted(_ARMS):
            raise ValueError("independent analysis task block failed validation")
    if len(blocks) != _EXPECTED_TASKS:
        raise ValueError("independent analysis task count failed validation")
    matrix_rows = [
        {
            "assignment_id": row["assignment_id"],
            "task_id": row["task_id"],
            "target_spec_id": row["target_spec_id"],
            "target_instance_id": row["target_instance_id"],
            "arm_protocol_id": row["arm_protocol_id"],
            "protocol_instance_id": row["protocol_instance_id"],
            "values": [row["values"][variable] for variable in _VARIABLE_IDS],
        }
        for row in rows
    ]
    matrix = {
        "schema_version": _SCHEMA_VERSION,
        "view_id": "full_jci_functional",
        "model_id": _MODEL,
        "independent_tasks": _EXPECTED_TASKS,
        "row_count": _EXPECTED_ROWS,
        "internal_variable_ids": list(_VARIABLE_IDS),
        "category_orders": {"c.arm": list(_ARMS), "binary": [0, 1]},
        "rows": matrix_rows,
    }
    arm_counts = Counter(str(row["arm_role"]) for row in rows)
    functional_counts = Counter(str(row["diagnostics"]["functional_status"]) for row in rows)
    mechanism_counts = Counter(str(row["diagnostics"]["mechanism_state"]) for row in rows)
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_jsonl(output_dir / "combined-rows.jsonl", rows)
    _write_json(output_dir / "matrix-phi14b-full_jci_functional.json", matrix)
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "archive_sha256": config["results_archive"]["sha256"],
            "execution_plan_manifest_sha256": config["execution_plan"]["sha256"],
            "runtime_freeze_manifest_sha256": config["runtime_freeze"]["sha256"],
            "run_manifest_sha256": config["run_manifests"],
            "historical_error_assignment_ids": sorted(historical_errors),
            "matrix_sha256": canonical_sha256(matrix),
        },
    )
    _write_json(output_dir / "environment.json", _environment())
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_ANALYSIS_TABLE_COMPLETE",
        "model_id": _MODEL,
        "counts": {
            "tasks": len(blocks),
            "assignments": len(rows),
            "complete": len(complete),
            "historical_errors_recovered": len(historical_errors),
            "errors": 0,
            "pending": 0,
            "provider_calls": 0,
            "oracle_calls": 0,
        },
        "by_arm": dict(sorted(arm_counts.items())),
        "functional_status": dict(sorted(functional_counts.items())),
        "mechanism_state": dict(sorted(mechanism_counts.items())),
        "unknown_functional_handling": config["unknown_functional_handling"],
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["build_independent_validation_analysis_table"]

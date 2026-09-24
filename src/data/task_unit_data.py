"""Read-only verification of the frozen v4 task-unit data set."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from prompt_mechanism_study.artifact_io import read_canonical_jsonl, read_canonical_object
from prompt_mechanism_study.records import content_hash


_JSONL_FILES = {
    "functional-contracts.jsonl",
    "near-duplicate-groups.jsonl",
    "readiness-worklist.jsonl",
    "source-lineages.jsonl",
    "task-quality.jsonl",
    "task-roles.jsonl",
    "task-units.jsonl",
}
_BUNDLE_FILES = _JSONL_FILES | {"report.json"}
_REPRESENTATIVE_SELECTION_RULE = "prefer_source_test_then_ascending_record_id_v1"


class TaskUnitDataError(ValueError):
    """The supplied task-unit bundle violates its frozen contract."""


def verify_task_unit_data(root: Path) -> dict[str, Any]:
    """Independently verify a compiled task-unit data bundle."""

    bundle = root.resolve()
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise TaskUnitDataError("compiled data manifest is missing")
    manifest = _canonical_json_file(manifest_path, "manifest")
    if (
        manifest.get("schema_version") != "4.0"
        or manifest.get("artifact_kind") != "reviewer_task_unit_dataset"
        or set(manifest.get("files", {})) != _BUNDLE_FILES
    ):
        raise TaskUnitDataError("compiled data manifest is invalid")
    actual = {
        path.name for path in bundle.iterdir() if path.is_file() and path.name != "manifest.json"
    }
    if actual != _BUNDLE_FILES:
        raise TaskUnitDataError("compiled data file set is not exact")
    artifacts: dict[str, list[dict[str, Any]]] = {}
    for name in sorted(_JSONL_FILES):
        rows = _canonical_jsonl(bundle / name, name)
        descriptor = _object(manifest["files"].get(name), f"{name} descriptor")
        if (
            descriptor.get("format") != "canonical-jsonl"
            or descriptor.get("record_count") != len(rows)
            or descriptor.get("sha256") != hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        ):
            raise TaskUnitDataError(f"{name} manifest identity drift")
        artifacts[name] = rows
    report = _canonical_json_file(bundle / "report.json", "report")
    report_descriptor = _object(manifest["files"].get("report.json"), "report descriptor")
    if (
        report_descriptor.get("format") != "canonical-json"
        or report_descriptor.get("sha256")
        != hashlib.sha256((bundle / "report.json").read_bytes()).hexdigest()
    ):
        raise TaskUnitDataError("report manifest identity drift")

    task_units = _unique_by(artifacts["task-units.jsonl"], "task_unit_id", "task units")
    contracts = _unique_by(
        artifacts["functional-contracts.jsonl"], "task_unit_id", "functional contracts"
    )
    quality = _unique_by(artifacts["task-quality.jsonl"], "task_unit_id", "quality rows")
    roles = _unique_by(artifacts["task-roles.jsonl"], "task_unit_id", "role rows")
    readiness = _unique_by(
        artifacts["readiness-worklist.jsonl"], "task_unit_id", "readiness worklist"
    )
    if (
        set(task_units) != set(contracts)
        or set(task_units) != set(quality)
        or set(task_units) != set(roles)
        or set(task_units) != set(readiness)
    ):
        raise TaskUnitDataError("compiled task, quality, role, and readiness populations differ")
    forbidden_fields = {
        "task_id",
        "confirm_add_eligible",
        "confirm_remove_eligible",
        "eligible_arm_protocol_ids",
        "split",
        "prompt_tsg",
        "assignment",
        "generated_code",
        "outcome",
    }
    for rows in (task_units, contracts, quality, roles):
        if any(forbidden_fields.intersection(row) for row in rows.values()):
            raise TaskUnitDataError("downstream experimental field entered source data")
    source_records = []
    for task_id, row in task_units.items():
        if (
            row.get("schema_version") != "task-unit-4.0"
            or row.get("legacy_identity", {}).get("semantic_cluster_id") != task_id
            or row.get("task_unit_record_sha256")
            != content_hash({key: value for key, value in row.items() if key != "task_unit_record_sha256"})
            or row.get("model_visible_input", {}).get("natural_prompt_content_sha256")
            != content_hash(row.get("model_visible_input", {}).get("natural_prompt"))
            or row.get("model_visible_input", {}).get(
                "model_visible_input_identity_sha256"
            )
            != content_hash(
                {
                    "natural_prompt": row.get("model_visible_input", {}).get(
                        "natural_prompt"
                    ),
                    "visible_assets": row.get("model_visible_input", {}).get(
                        "visible_assets"
                    ),
                    "render_mode": row.get("model_visible_input", {}).get("render_mode"),
                }
            )
        ):
            raise TaskUnitDataError("compiled task identity is invalid")
        expected_representative = min(
            row["source_members"],
            key=lambda member: (
                not bool(member.get("source_test_reference_count")),
                member["record_id"],
            ),
        )
        if (
            row.get("representative_record_id") != expected_representative["record_id"]
            or row.get("source_member_summary", {}).get("representative_selection_rule")
            != _REPRESENTATIVE_SELECTION_RULE
        ):
            raise TaskUnitDataError("compiled representative identity is invalid")
        source_records.extend(row["legacy_identity"]["source_record_ids"])
    if len(source_records) != len(set(source_records)):
        raise TaskUnitDataError("compiled source records are duplicated")

    for task_id, row in contracts.items():
        core = {
            key: value
            for key, value in row.items()
            if key != "functional_contract_record_sha256"
        }
        if (
            row.get("schema_version") != "functional-contract-reviewer-4.0"
            or row.get("functional_contract_record_sha256") != content_hash(core)
            or row.get("contract_id") != quality[task_id].get("contract_id")
            or row.get("source_prompt_sha256")
            != task_units[task_id]["model_visible_input"][
                "natural_prompt_content_sha256"
            ]
        ):
            raise TaskUnitDataError("functional contract binding is invalid")
        prompt = task_units[task_id]["model_visible_input"]["natural_prompt"]
        for evidence in row.get("requirement_evidence", []):
            start, end = evidence.get("evidence_start"), evidence.get("evidence_end")
            literal = evidence.get("evidence_text")
            if (
                type(start) is not int
                or type(end) is not int
                or not isinstance(literal, str)
                or prompt[start:end] != literal
                or evidence.get("evidence_sha256") != content_hash(literal)
            ):
                raise TaskUnitDataError("functional requirement evidence is invalid")
    for task_id, row in quality.items():
        core = {
            key: value for key, value in row.items() if key != "task_quality_record_sha256"
        }
        if (
            row.get("schema_version") != "task-quality-4.0"
            or row.get("task_quality_record_sha256") != content_hash(core)
            or row.get("decision_provenance", {}).get("contract_record_sha256")
            != contracts[task_id]["functional_contract_record_sha256"]
        ):
            raise TaskUnitDataError("task quality binding is invalid")
    for row in roles.values():
        core = {key: value for key, value in row.items() if key != "task_role_record_sha256"}
        categories = row.get("exposure_categories", [])
        if (
            row.get("schema_version") != "task-role-4.0"
            or row.get("task_role_record_sha256") != content_hash(core)
            or not isinstance(categories, list)
            or "SOURCE_CURATED" not in categories
            or (
                row.get("data_role") == "UNASSIGNED"
                and "METHOD_DEVELOPMENT_VIEWED" in categories
            )
            or (
                row.get("data_role") != "UNASSIGNED"
                and "METHOD_DEVELOPMENT_VIEWED" not in categories
            )
        ):
            raise TaskUnitDataError("task exposure and role record is invalid")

    group_rows = _unique_by(
        artifacts["near-duplicate-groups.jsonl"],
        "near_duplicate_group_id",
        "near-duplicate groups",
    )
    grouped_tasks = [task_id for row in group_rows.values() for task_id in row["task_unit_ids"]]
    if len(grouped_tasks) != len(set(grouped_tasks)) or set(grouped_tasks) != set(task_units):
        raise TaskUnitDataError("near-duplicate groups do not partition task units")
    for group in group_rows.values():
        if (
            group.get("schema_version") != "near-duplicate-group-4.0"
            or group.get("maximum_task_units_across_all_prospective_formal_roles") != 1
            or sum(
                bool(roles[task_id].get("prospective_formal_role_assigned"))
                for task_id in group["task_unit_ids"]
            )
            > 1
        ):
            raise TaskUnitDataError("near-duplicate formal-role constraint is invalid")
    lineage_rows = _unique_by(
        artifacts["source-lineages.jsonl"], "source_lineage_id", "source lineages"
    )
    lineage_tasks = [task_id for row in lineage_rows.values() for task_id in row["task_unit_ids"]]
    if len(lineage_tasks) != len(set(lineage_tasks)) or set(lineage_tasks) != set(task_units):
        raise TaskUnitDataError("source lineages do not partition task units")
    if (
        report.get("source_record_count") != len(source_records)
        or report.get("task_unit_count") != len(task_units)
        or report.get("functional_contract_count") != len(contracts)
        or report.get("readiness_artifact_kind") != "DERIVED_VIEW"
        or report.get("referential_integrity")
        != {
            "core_task_unit_populations_equal": True,
            "contracts_prompt_hash_bound": True,
            "quality_contract_version_bound": True,
            "source_records_partitioned_exactly_once": True,
            "near_duplicate_groups_partition_task_units": True,
            "readiness_is_derived_view": True,
            "downstream_experimental_fields_absent": True,
        }
        or report.get("prompt_tsg")
        != {
            "status": "NOT_GENERATED_PENDING_METHOD_FREEZE",
            "extractor_id": None,
            "catalog_sha256": None,
            "task_count": 0,
        }
        or report.get("arms_or_outcomes_used") is not False
        or report.get("formal_execution_authorized") is not False
        or report.get("readiness_workstream_counts")
        != dict(sorted(Counter(row["workstream"] for row in readiness.values()).items()))
        or report.get("readiness_axis_counts")
        != {
            field: dict(sorted(Counter(row[field] for row in readiness.values()).items()))
            for field in (
                "quality_gate",
                "scope_status",
                "mechanism_registration_status",
                "binding_status",
                "oracle_status",
                "runtime_status",
                "functional_measurement_status",
                "independent_quality_review_status",
            )
        }
    ):
        raise TaskUnitDataError("compiled data report is invalid")
    for task_id, row in readiness.items():
        core = {key: value for key, value in row.items() if key != "readiness_record_sha256"}
        summary_status, workstream, _, _ = _readiness_action(row)
        if (
            row.get("schema_version") != "readiness-work-item-4.0"
            or row.get("artifact_kind") != "DERIVED_VIEW"
            or row.get("readiness_record_sha256") != content_hash(core)
            or row.get("arms_or_outcomes_used") is not False
            or row.get("formal_use_authorized") is not False
            or row.get("readiness_summary_status") != summary_status
            or row.get("workstream") != workstream
        ):
            raise TaskUnitDataError("readiness work item is invalid")
    return {
        "status": "VERIFIED_TASK_UNIT_DATA_PROMPT_TSG_PENDING",
        "bundle_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_records": len(source_records),
        "task_units": len(task_units),
        "functional_contracts": len(contracts),
        "quality_disposition_counts": report["quality_disposition_counts"],
        "data_role_counts": report["data_role_counts"],
        "readiness_workstream_counts": report["readiness_workstream_counts"],
        "prompt_tsg_status": report["prompt_tsg"]["status"],
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
    }


def _readiness_action(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    if row.get("quality_gate") == "EXCLUDED":
        return (
            "QUALITY_EXCLUDED",
            "QUALITY_EXCLUSION",
            "RETAIN_TERMINAL_QUALITY_EXCLUSION",
            "none; preserve the source-level exclusion basis",
        )
    if row.get("quality_gate") != "PASSED":
        if row.get("independent_quality_review_status") == "PENDING":
            return (
                "QUALITY_NOT_FINAL",
                "INDEPENDENT_QUALITY_REVIEW",
                "ADJUDICATE_SOURCE_PROMPT_AGAINST_FUNCTIONAL_CONTRACT",
                "independent outcome-blind accept, repair, or source-based exclusion",
            )
        return (
            "QUALITY_NOT_FINAL",
            "CONTRACT_REPAIR",
            "REPAIR_FUNCTIONAL_CONTRACT_OUTCOME_BLINDLY",
            "faithful and sufficient contract or source-based terminal exclusion",
        )
    if row.get("scope_status") != "IN_CURRENT_STUDY_LAYER":
        return (
            "METHOD_SUPPORT_NOT_READY",
            "SCOPE_DECISION",
            "FREEZE_PROSPECTIVE_RESEARCH_LAYER_OR_RETAIN_FOR_FUTURE_WORK",
            "outcome-blind scope decision",
        )
    if row.get("mechanism_registration_status") != "REGISTERED":
        if row.get("binding_status") == "PENDING_BLIND_REVIEW":
            return (
                "METHOD_SUPPORT_NOT_READY",
                "MECHANISM_BINDING",
                "ADJUDICATE_AGAINST_CURRENT_REGISTERED_MECHANISMS",
                "source-bound evidence for one applicable realization or unresolved decision",
            )
        return (
            "METHOD_SUPPORT_NOT_READY",
            "MECHANISM_REGISTRATION",
            "REGISTER_OR_EXPLICITLY_EXCLUDE_A_TASK_APPLICABLE_MECHANISM",
            "frozen task-applicable mechanism specification",
        )
    if row.get("oracle_status") != "SUPPORTED":
        return (
            "METHOD_SUPPORT_NOT_READY",
            "ORACLE_QUALIFICATION",
            "QUALIFY_TASK_APPLICABLE_ORACLE_PROFILE",
            "secure, insecure, and unknown calibration for the frozen profile",
        )
    if row.get("runtime_status") != "SUPPORTED":
        return (
            "METHOD_SUPPORT_NOT_READY",
            "RUNTIME_QUALIFICATION",
            "QUALIFY_SHARED_LANGUAGE_RUNTIME_AND_TEST_PATH",
            "replayable compile/run environment and frozen measurement path",
        )
    if str(row.get("functional_measurement_status", "")).startswith("PENDING_"):
        return (
            "METHOD_SUPPORT_NOT_READY",
            "FUNCTIONAL_MEASUREMENT_QUALIFICATION",
            "QUALIFY_TASK_APPLICABLE_FUNCTIONAL_MEASUREMENT",
            "frozen executable test or explicitly bounded blind plausibility profile",
        )
    return (
        "TECHNICALLY_READY_PENDING_METHOD_FREEZE",
        "TECHNICALLY_READY",
        "WAIT_FOR_METHOD_FREEZE_BEFORE_PROMPT_TSG_OR_FORMAL_ALLOCATION",
        "frozen method followed by prospective TSG and role allocation",
    )


def _unique_by(
    rows: Iterable[dict[str, Any]], field: str, label: str
) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        key = row.get(field)
        if not isinstance(key, str) or not key or key in result:
            raise TaskUnitDataError(f"{label} identities are invalid")
        result[key] = row
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TaskUnitDataError(f"{label} must be a JSON object")
    return value


def _canonical_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        return read_canonical_jsonl(path, label)
    except ValueError as error:
        raise TaskUnitDataError(str(error)) from None


def _canonical_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        return read_canonical_object(path, label)
    except ValueError as error:
        raise TaskUnitDataError(str(error)) from None


__all__ = ['verify_task_unit_data', '_canonical_jsonl', '_unique_by']

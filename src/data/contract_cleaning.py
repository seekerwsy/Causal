"""Read-only verification of the frozen v5 source/contract foundation."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import read_canonical_object
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.data.task_unit_data import _canonical_jsonl, _unique_by


_CONTENT_FIELDS = (
    "requirements",
    "inputs",
    "outputs",
    "side_effects",
    "environment_dependencies",
)
_FINAL_JSONL_FILES = {
    "contract-repair-ledger.jsonl",
    "functional-contracts.jsonl",
    "near-duplicate-groups.jsonl",
    "readiness-worklist.jsonl",
    "source-lineages.jsonl",
    "task-quality.jsonl",
    "task-roles.jsonl",
    "task-units.jsonl",
}
_FINAL_FILES = _FINAL_JSONL_FILES | {"report.json"}
_TERMINAL_QUALITY = {
    "QUALITY_INCLUDED",
    "QUALITY_EXCLUDED_SOURCE_DEFECT",
    "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION",
}


class ContractCleaningError(RuntimeError):
    """The frozen source/contract bundle is invalid."""


def verify_contract_content_data(root: Path) -> dict[str, Any]:
    """Independently verify the terminal content-cleaned data foundation."""

    bundle = root.resolve()
    manifest = _canonical_json_object(bundle / "manifest.json", "manifest")
    if (
        manifest.get("schema_version") != "5.0"
        or manifest.get("artifact_kind") != "reviewer_task_unit_dataset"
        or set(manifest.get("files", {})) != _FINAL_FILES
    ):
        raise ContractCleaningError("final data manifest is invalid")
    actual = {
        path.name for path in bundle.iterdir() if path.is_file() and path.name != "manifest.json"
    }
    if actual != _FINAL_FILES:
        raise ContractCleaningError("final data file set is not exact")
    rows_by_file = {}
    for name in sorted(_FINAL_JSONL_FILES):
        rows = _canonical_jsonl(bundle / name, name)
        descriptor = manifest["files"][name]
        if (
            descriptor.get("format") != "canonical-jsonl"
            or descriptor.get("record_count") != len(rows)
            or descriptor.get("sha256")
            != hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        ):
            raise ContractCleaningError(f"{name} manifest identity drift")
        rows_by_file[name] = rows
    report = _canonical_json_object(bundle / "report.json", "report")
    if (
        manifest["files"]["report.json"].get("format") != "canonical-json"
        or manifest["files"]["report.json"].get("sha256")
        != hashlib.sha256((bundle / "report.json").read_bytes()).hexdigest()
    ):
        raise ContractCleaningError("final report manifest identity drift")
    tasks = _unique_by(rows_by_file["task-units.jsonl"], "task_unit_id", "tasks")
    contracts = _unique_by(
        rows_by_file["functional-contracts.jsonl"], "task_unit_id", "contracts"
    )
    quality = _unique_by(rows_by_file["task-quality.jsonl"], "task_unit_id", "quality")
    roles = _unique_by(rows_by_file["task-roles.jsonl"], "task_unit_id", "roles")
    readiness = _unique_by(
        rows_by_file["readiness-worklist.jsonl"], "task_unit_id", "readiness"
    )
    ledger = _unique_by(
        rows_by_file["contract-repair-ledger.jsonl"], "task_unit_id", "repair ledger"
    )
    if any(set(rows) != set(tasks) for rows in (contracts, quality, roles, readiness, ledger)):
        raise ContractCleaningError("final data populations differ")
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
    if any(
        forbidden_fields.intersection(row)
        for rows in (tasks, contracts, quality, roles)
        for row in rows.values()
    ):
        raise ContractCleaningError("downstream experimental field entered final data")
    group_rows = _unique_by(
        rows_by_file["near-duplicate-groups.jsonl"],
        "near_duplicate_group_id",
        "near-duplicate groups",
    )
    lineage_rows = _unique_by(
        rows_by_file["source-lineages.jsonl"], "source_lineage_id", "source lineages"
    )
    task_to_group = {}
    for group_id, group in group_rows.items():
        core = {
            key: value
            for key, value in group.items()
            if key != "near_duplicate_group_record_sha256"
        }
        if (
            group.get("schema_version") != "near-duplicate-group-4.0"
            or group.get("near_duplicate_group_record_sha256") != content_hash(core)
            or group.get("maximum_task_units_across_all_prospective_formal_roles") != 1
        ):
            raise ContractCleaningError("near-duplicate group is invalid")
        for task_id in group.get("task_unit_ids", []):
            if task_id in task_to_group:
                raise ContractCleaningError("near-duplicate groups overlap")
            task_to_group[task_id] = group_id
    task_to_lineage = {}
    for lineage_id, lineage in lineage_rows.items():
        core = {key: value for key, value in lineage.items() if key != "lineage_record_sha256"}
        if (
            lineage.get("schema_version") != "source-lineage-3.0"
            or lineage.get("lineage_record_sha256") != content_hash(core)
        ):
            raise ContractCleaningError("source lineage is invalid")
        for task_id in lineage.get("task_unit_ids", []):
            if task_id in task_to_lineage:
                raise ContractCleaningError("source lineages overlap")
            task_to_lineage[task_id] = lineage_id
    if set(task_to_group) != set(tasks) or set(task_to_lineage) != set(tasks):
        raise ContractCleaningError("groups or lineages do not partition final tasks")
    source_record_ids = []
    for task_id, task in tasks.items():
        contract = contracts[task_id]
        quality_row = quality[task_id]
        role = roles[task_id]
        readiness_row = readiness[task_id]
        ledger_row = ledger[task_id]
        _validate_frozen_evidence(task, contract)
        _validate_final_contract_identity(contract)
        review_identity = _review_identity_from_final_contract(contract)
        if (
            task.get("schema_version") != "task-unit-5.0"
            or task.get("task_unit_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in task.items()
                    if key != "task_unit_record_sha256"
                }
            )
            or task.get("evaluation_asset_refs", {}).get("functional_contract_id")
            != contract.get("contract_id")
            or task.get("model_visible_input", {}).get("natural_prompt_content_sha256")
            != content_hash(task.get("model_visible_input", {}).get("natural_prompt"))
            or contract.get("record_id") != task.get("representative_record_id")
            or contract.get("schema_version") != "functional-contract-reviewer-5.0"
            or contract.get("functional_contract_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "functional_contract_record_sha256"
                }
            )
            or quality_row.get("schema_version") != "task-quality-5.0"
            or quality_row.get("quality_disposition") not in _TERMINAL_QUALITY
            or quality_row.get("contract_id") != contract.get("contract_id")
            or quality_row.get("task_quality_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in quality_row.items()
                    if key != "task_quality_record_sha256"
                }
            )
            or role.get("schema_version") != "task-role-5.0"
            or "CONTRACT_REPAIR_VIEWED" not in role.get("exposure_categories", [])
            or role.get("prospective_formal_role_assigned") is not False
            or role.get("near_duplicate_group_id") != task_to_group[task_id]
            or role.get("source_lineage_id") != task_to_lineage[task_id]
            or role.get("task_role_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in role.items()
                    if key != "task_role_record_sha256"
                }
            )
            or readiness_row.get("schema_version") != "readiness-work-item-5.0"
            or readiness_row.get("contract_id") != contract.get("contract_id")
            or readiness_row.get("readiness_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in readiness_row.items()
                    if key != "readiness_record_sha256"
                }
            )
            or ledger_row.get("repair_status") != "INDEPENDENTLY_REVIEWED_TERMINAL"
            or ledger_row.get("final_quality_disposition")
            != quality_row.get("quality_disposition")
            or ledger_row.get("independent_review_record_sha256")
            != content_hash(review_identity)
            or ledger_row.get("repair_ledger_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in ledger_row.items()
                    if key != "repair_ledger_record_sha256"
                }
            )
        ):
            raise ContractCleaningError("final data record binding is invalid")
        source_record_ids.extend(task.get("legacy_identity", {}).get("source_record_ids", []))
    if len(source_record_ids) != len(set(source_record_ids)):
        raise ContractCleaningError("source records are duplicated across final task units")
    for group in group_rows.values():
        if (
            sum(
                bool(roles[task_id].get("prospective_formal_role_assigned"))
                for task_id in group["task_unit_ids"]
            )
            > 1
        ):
            raise ContractCleaningError("near-duplicate formal-role firewall is violated")
    if (
        report.get("status") != "DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED"
        or report.get("task_unit_count") != len(tasks)
        or report.get("functional_contract_count") != len(contracts)
        or report.get("content_evidence_complete_count") != len(contracts)
        or report.get("contract_repair_ledger_count") != len(ledger)
        or report.get("pending_quality_count") != 0
        or report.get("quality_disposition_counts")
        != dict(sorted(Counter(row["quality_disposition"] for row in quality.values()).items()))
        or report.get("arms_or_outcomes_used") is not False
        or report.get("formal_execution_authorized") is not False
        or report.get("referential_integrity")
        != {
            "core_task_unit_populations_equal": True,
            "contracts_prompt_hash_bound": True,
            "task_contract_reference_current": True,
            "quality_contract_version_bound": True,
            "repair_ledger_review_bound": True,
            "near_duplicate_groups_unchanged": True,
            "source_lineages_unchanged": True,
            "downstream_experimental_fields_absent": True,
        }
        or report.get("prompt_tsg", {}).get("status")
        != "NOT_GENERATED_PENDING_METHOD_FREEZE"
    ):
        raise ContractCleaningError("final data report is invalid")
    return {
        "status": "VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED",
        "bundle_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(),
        "task_units": len(tasks),
        "functional_contracts": len(contracts),
        "quality_disposition_counts": report["quality_disposition_counts"],
        "future_evaluation_reserved_task_unit_count": report[
            "future_evaluation_reserved_task_unit_count"
        ],
        "prompt_tsg_status": report["prompt_tsg"]["status"],
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
    }


def _proposal_identity_from_final_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "functional-contract-cleaning-proposal-1.0",
        "task_unit_id": contract["task_unit_id"],
        "record_id": contract["record_id"],
        "source_prompt_sha256": contract["source_prompt_sha256"],
        "resolution_status": contract["resolution_status"],
        "entrypoint": contract["entrypoint"],
        **{field: contract[field] for field in _CONTENT_FIELDS},
        "content_evidence": contract["content_evidence"],
        "proposal_mode": contract["proposal_mode"],
        "producer_source_assessment": contract["producer_source_assessment"],
        "producer_reason": contract["producer_reason"],
        "arms_or_outcomes_used": False,
    }


def _validate_final_contract_identity(contract: Mapping[str, Any]) -> None:
    if contract.get("contract_id") != content_id(
        "functional_contract_", _proposal_identity_from_final_contract(contract)
    ):
        raise ContractCleaningError("final cleaned contract identity is invalid")


def _review_identity_from_final_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "contract-content-review-1.0",
        "task_unit_id": contract["task_unit_id"],
        "contract_id": contract["contract_id"],
        **contract["review"],
        "arms_or_outcomes_used": False,
    }


def _validate_frozen_evidence(
    task: Mapping[str, Any], contract: Mapping[str, Any]
) -> None:
    prompt = task["model_visible_input"]["natural_prompt"]
    prompt_bytes = prompt.encode("utf-8")
    prompt_sha256 = task["model_visible_input"]["natural_prompt_content_sha256"]
    if contract.get("source_prompt_sha256") != prompt_sha256:
        raise ContractCleaningError("contract evidence prompt identity is stale")
    evidence = contract.get("content_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("offset_basis") != "utf8_bytes_of_exact_natural_prompt_v1"
        or set(evidence) != {"offset_basis", "entrypoint", *_CONTENT_FIELDS}
    ):
        raise ContractCleaningError("contract content evidence envelope is invalid")
    expected_groups: list[tuple[Any, Any]] = []
    expected_groups.append((contract.get("entrypoint"), evidence["entrypoint"]))
    for field in _CONTENT_FIELDS:
        values = contract.get(field)
        groups = evidence[field]
        if not isinstance(values, list) or not isinstance(groups, list) or len(values) != len(groups):
            raise ContractCleaningError("contract content evidence target count is invalid")
        expected_groups.extend(zip(values, groups, strict=True))
    for value, group in expected_groups:
        if value is None:
            if group != []:
                raise ContractCleaningError("absent contract value carries source evidence")
            continue
        if not isinstance(value, str) or not value.strip() or not isinstance(group, list) or not group:
            raise ContractCleaningError("contract value lacks source evidence")
        for span in group:
            if not isinstance(span, dict) or set(span) != {
                "source_prompt_sha256",
                "start_byte",
                "end_byte",
                "quoted_text",
                "span_sha256",
            }:
                raise ContractCleaningError("contract evidence span is malformed")
            start, end, quoted = span["start_byte"], span["end_byte"], span["quoted_text"]
            if (
                type(start) is not int
                or type(end) is not int
                or start < 0
                or end <= start
                or end > len(prompt_bytes)
                or not isinstance(quoted, str)
                or span["source_prompt_sha256"] != prompt_sha256
            ):
                raise ContractCleaningError("contract evidence byte coordinates are invalid")
            try:
                actual = prompt_bytes[start:end].decode("utf-8")
            except UnicodeDecodeError:
                raise ContractCleaningError("contract evidence splits a UTF-8 sequence") from None
            if (
                actual != quoted
                or span["span_sha256"]
                != hashlib.sha256(quoted.encode("utf-8")).hexdigest()
            ):
                raise ContractCleaningError("contract evidence is not an exact prompt span")


def _canonical_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        return read_canonical_object(path, label)
    except ValueError as error:
        raise ContractCleaningError(str(error)) from None


__all__ = ['verify_contract_content_data']

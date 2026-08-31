"""Compile the frozen curation outputs into one reviewer-facing task-unit data set."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle
from prompt_mechanism_study.records import canonical_json, content_hash, content_id


_JSONL_FILES = {
    "near-duplicate-groups.jsonl",
    "source-lineages.jsonl",
    "task-quality.jsonl",
    "task-roles.jsonl",
    "task-units.jsonl",
}
_BUNDLE_FILES = _JSONL_FILES | {"report.json"}
_QUALITY_STATUS = {
    "INCLUDED_FINAL_DATASET": "PASS",
    "PENDING_INDEPENDENT_REVIEW": "PENDING_INDEPENDENT_REVIEW",
    "PENDING_QUALITY_REPAIR": "PENDING_QUALITY_REPAIR",
    "EXCLUDED_SOURCE_DEFECT": "EXCLUDED_SOURCE_DEFECT",
}
_QUALITY_REASON_CODES = {
    "known_material_contract_fault",
    "known_scope_or_evaluability_concern",
    "metadata_repair_required",
    "pending_contract",
    "pending_independent_review",
    "semantic_calibration_required",
    "source_prompt_incoherent",
}


class TaskUnitDataError(ValueError):
    """The task-unit compilation inputs or output violate the frozen contract."""


def compile_task_unit_data(
    *,
    prepared_root: Path,
    clusters_root: Path,
    candidate_root: Path,
    legacy_roles_root: Path,
    development_exclusions_path: Path,
    role_census_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Build one immutable row per frozen task unit without generating Prompt TSGs."""

    inputs = {
        "prepared": prepared_root.resolve(),
        "clusters": clusters_root.resolve(),
        "candidate": candidate_root.resolve(),
        "legacy_roles": legacy_roles_root.resolve(),
        "role_census": role_census_root.resolve(),
    }
    for root in inputs.values():
        verify_bundle(root)
    prepared_records = _rows(read_json(inputs["prepared"] / "records.json"), "records")
    clusters = _rows(read_json(inputs["clusters"] / "semantic-clusters.json"), "clusters")
    diagnostic_edges = _rows(
        read_json(inputs["clusters"] / "diagnostic-semantic-edges.json"),
        "diagnostic edges",
    )
    ledger = _rows(read_json(inputs["candidate"] / "candidate-ledger.json"), "ledger")
    legacy_manifest = _object(
        read_json(inputs["legacy_roles"] / "role-manifest.json"), "legacy manifest"
    )
    role_census = _rows(
        read_json(inputs["role_census"] / "task-units.json"), "role census"
    )
    exclusions = _object(
        read_json(development_exclusions_path.resolve()), "development exclusions"
    )
    if exclusions.get("arms_or_outcomes_used") is not False:
        raise TaskUnitDataError("development exclusions are not outcome blind")

    records = _unique_by(prepared_records, "record_id", "source records")
    cluster_by_id = _unique_by(clusters, "cluster_id", "task units")
    ledger_by_id = _unique_by(ledger, "task_unit_id", "candidate ledger")
    if set(cluster_by_id) != set(ledger_by_id):
        raise TaskUnitDataError("task units and candidate ledger differ")
    record_to_task: dict[str, str] = {}
    for task_id, cluster in cluster_by_id.items():
        member_ids = _texts(cluster.get("record_ids"), "source member IDs")
        if tuple(sorted(set(member_ids))) != member_ids:
            raise TaskUnitDataError("task source members must be canonical and unique")
        if cluster.get("representative_record_id") not in member_ids:
            raise TaskUnitDataError("task representative is not a source member")
        for record_id in member_ids:
            if record_id not in records or record_id in record_to_task:
                raise TaskUnitDataError("source record coverage is invalid")
            record_to_task[record_id] = task_id
    if set(record_to_task) != set(records):
        raise TaskUnitDataError("task units do not cover every source record exactly once")

    near_group_by_task, near_groups = _near_duplicate_groups(
        cluster_by_id, record_to_task, diagnostic_edges
    )
    legacy_exposure = _legacy_exposure(legacy_manifest, set(cluster_by_id))
    development_ids = set(_texts(exclusions.get("task_unit_ids"), "development task IDs"))
    if not development_ids <= set(cluster_by_id) or development_ids & set(legacy_exposure):
        raise TaskUnitDataError("development and legacy exposure identities are invalid")

    provenance = {
        f"{name}_bundle_sha256": bundle_digest(root) for name, root in inputs.items()
    }
    task_provenance = {
        name: provenance[name]
        for name in (
            "prepared_bundle_sha256",
            "clusters_bundle_sha256",
            "candidate_bundle_sha256",
        )
    }
    task_units: list[dict[str, Any]] = []
    quality_rows: list[dict[str, Any]] = []
    role_rows: list[dict[str, Any]] = []
    tasks_by_lineage: dict[str, set[str]] = defaultdict(set)
    records_by_lineage: dict[str, set[str]] = defaultdict(set)
    datasets_by_lineage: dict[str, set[str]] = defaultdict(set)

    for task_id, cluster in sorted(cluster_by_id.items()):
        representative = records[_text(cluster.get("representative_record_id"), "representative")]
        members = [records[record_id] for record_id in cluster["record_ids"]]
        lineages = tuple(sorted({row["source_lineage_family"] for row in members}))
        if len(lineages) != 1:
            raise TaskUnitDataError("one task unit cannot cross source lineages")
        lineage_id = lineages[0]
        ledger_row = ledger_by_id[task_id]
        if (
            ledger_row.get("representative_record_id") != representative["record_id"]
            or ledger_row.get("primary_cwe") != representative["cwe"]
            or ledger_row.get("language") != representative["language"]
            or ledger_row.get("arms_or_outcomes_used") is not False
        ):
            raise TaskUnitDataError("candidate ledger drifts from the frozen task")

        source_members = [
            {
                "record_id": row["record_id"],
                "dataset_id": row["source_dataset"],
                "source_version": row["source_version"],
                "source_item_id": row["source_item_id"],
                "source_locator": row["source_locator"],
                "source_file_sha256": row["source_file_sha256"],
                "source_record_sha256": row["source_record_sha256"],
                "source_lineage_id": row["source_lineage_family"],
                "license_id": row["license_id"],
                "citation_url": row["citation_url"],
            }
            for row in sorted(members, key=lambda item: item["record_id"])
        ]
        test_refs = [
            {"source_record_id": row["record_id"], "reference": reference}
            for row in members
            for reference in row.get("source_test_references", [])
        ]
        task_core = {
            "schema_version": "task-unit-3.0",
            "task_unit_id": task_id,
            "legacy_identity": {
                "semantic_cluster_id": task_id,
                "source_record_ids": list(cluster["record_ids"]),
            },
            "representative_record_id": representative["record_id"],
            "source_lineage_id": lineage_id,
            "source_members": source_members,
            "model_visible_input": {
                "natural_prompt": representative["prompt"],
                "natural_prompt_content_sha256": representative["prompt_sha256"],
                "render_mode": "exact_source_prompt_text_only",
                "declared_environment": {
                    "language": representative["language"],
                    "runtime": None,
                },
            },
            "pre_treatment_source_metadata": {
                "language": representative["language"],
                "source_declared_cwe_ids": list(cluster["cwes"]),
                "cwe_label_conflict": cluster["cwe_label_conflict"],
                "label_semantics": "routing_and_census_only_not_prompt_tsg_evidence",
            },
            "evaluation_asset_refs": {
                "functional_contract_id": ledger_row["contract_id"],
                "source_test_refs": sorted(
                    test_refs,
                    key=lambda item: (item["source_record_id"], item["reference"]),
                ),
            },
            "provenance": task_provenance,
        }
        task_units.append(
            {**task_core, "task_unit_record_sha256": content_hash(task_core)}
        )

        final_status = ledger_row.get("final_dataset_status")
        if final_status not in _QUALITY_STATUS:
            raise TaskUnitDataError("unknown final-data quality status")
        quality_core = {
            "schema_version": "task-quality-3.0",
            "task_unit_id": task_id,
            "quality_status": _QUALITY_STATUS[final_status],
            "source_disposition": final_status,
            "contract_id": ledger_row["contract_id"],
            "contract_quality": ledger_row["contract_quality"],
            "review_contract_status": ledger_row["review_contract_status"],
            "functional_evaluability": ledger_row["functional_evaluability"],
            "reason_codes": (
                []
                if final_status == "INCLUDED_FINAL_DATASET"
                else sorted(
                    set(ledger_row.get("blocker_codes", [])) & _QUALITY_REASON_CODES
                )
            ),
            "measurement_readiness_is_not_quality": True,
            "arms_or_outcomes_used": False,
        }
        quality_rows.append(
            {**quality_core, "task_quality_record_sha256": content_hash(quality_core)}
        )

        if task_id in development_ids:
            role = "QUAL_DEV"
            exposure_status = "EXPOSED"
            exposure_history = ["contract_review_policy_development"]
            exposure_data_ids = ["contract-review-development-exclusions-v1"]
            assignment_status = "FROZEN_HISTORICAL"
        elif task_id in legacy_exposure:
            role = "LEGACY_ONLY"
            exposure_status = "EXPOSED"
            exposure_history = legacy_exposure[task_id]["history"]
            exposure_data_ids = legacy_exposure[task_id]["data_ids"]
            assignment_status = "FROZEN_HISTORICAL"
        else:
            role = "UNASSIGNED"
            exposure_status = "NO_RECORDED_EXPOSURE"
            exposure_history = []
            exposure_data_ids = []
            assignment_status = "PENDING_PROSPECTIVE_ALLOCATION"
        role_core = {
            "schema_version": "task-role-3.0",
            "task_unit_id": task_id,
            "data_role": role,
            "role_assignment_status": assignment_status,
            "near_duplicate_group_id": near_group_by_task[task_id],
            "source_lineage_id": lineage_id,
            "exposure_status": exposure_status,
            "exposure_history": exposure_history,
            "exposure_data_ids": exposure_data_ids,
            "prospective_formal_role_assigned": False,
            "arms_or_outcomes_used": False,
        }
        role_rows.append(
            {**role_core, "task_role_record_sha256": content_hash(role_core)}
        )
        tasks_by_lineage[lineage_id].add(task_id)
        records_by_lineage[lineage_id].update(cluster["record_ids"])
        datasets_by_lineage[lineage_id].update(row["source_dataset"] for row in members)

    lineage_rows = []
    for lineage_id in sorted(tasks_by_lineage):
        core = {
            "schema_version": "source-lineage-3.0",
            "source_lineage_id": lineage_id,
            "source_dataset_ids": sorted(datasets_by_lineage[lineage_id]),
            "task_unit_ids": sorted(tasks_by_lineage[lineage_id]),
            "source_record_ids": sorted(records_by_lineage[lineage_id]),
        }
        lineage_rows.append({**core, "lineage_record_sha256": content_hash(core)})

    near_group_rows = []
    for group_id, task_ids in sorted(near_groups.items()):
        core = {
            "schema_version": "near-duplicate-group-3.0",
            "near_duplicate_group_id": group_id,
            "task_unit_ids": list(task_ids),
            "group_basis": "semantic_task_unit_plus_same_or_uncertain_diagnostic_edges_v1",
        }
        near_group_rows.append(
            {**core, "near_duplicate_group_record_sha256": content_hash(core)}
        )

    role_census_by_id = _unique_by(role_census, "task_unit_id", "role census")
    ready_ids = {
        task_id
        for task_id, row in ledger_by_id.items()
        if row.get("candidate_status") == "READY_CONFIRMATORY"
    }
    if set(role_census_by_id) != ready_ids:
        raise TaskUnitDataError("role census does not equal the ready population")
    for task_id, row in role_census_by_id.items():
        if row.get("near_duplicate_group_id") != near_group_by_task[task_id]:
            raise TaskUnitDataError("role-census near-duplicate identity drift")
    role_by_task = {row["task_unit_id"]: row for row in role_rows}
    unexposed_ready = sum(
        role_by_task[task_id]["data_role"] == "UNASSIGNED" for task_id in ready_ids
    )
    role_census_report = _object(
        read_json(inputs["role_census"] / "report.json"), "role-census report"
    )
    if unexposed_ready != role_census_report.get("prospective_unexposed_task_units"):
        raise TaskUnitDataError("unexposed ready count drifts from the role census")

    report = {
        "schema_version": "3.0",
        "status": "TASK_UNIT_DATA_COMPILED_PROMPT_TSG_PENDING_METHOD_FREEZE",
        "source_record_count": len(records),
        "task_unit_count": len(task_units),
        "quality_status_counts": dict(
            sorted(Counter(row["quality_status"] for row in quality_rows).items())
        ),
        "data_role_counts": dict(
            sorted(Counter(row["data_role"] for row in role_rows).items())
        ),
        "source_lineage_count": len(lineage_rows),
        "near_duplicate_group_count": len(near_group_rows),
        "multi_record_task_unit_count": sum(
            len(row["legacy_identity"]["source_record_ids"]) > 1 for row in task_units
        ),
        "ready_task_unit_count": len(ready_ids),
        "unexposed_ready_task_unit_count": unexposed_ready,
        "formal_role_assignment_frozen": False,
        "prompt_tsg": {
            "status": "NOT_GENERATED_PENDING_METHOD_FREEZE",
            "extractor_id": None,
            "catalog_sha256": None,
            "task_count": 0,
        },
        "input_bundles": provenance,
        "development_exclusions_sha256": hashlib.sha256(
            development_exclusions_path.resolve().read_bytes()
        ).hexdigest(),
        "compiler_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
        "scientific_effect_claim_allowed": False,
    }
    _write_bundle(
        output.resolve(),
        {
            "task-units.jsonl": task_units,
            "task-quality.jsonl": quality_rows,
            "task-roles.jsonl": role_rows,
            "source-lineages.jsonl": lineage_rows,
            "near-duplicate-groups.jsonl": near_group_rows,
        },
        report,
    )
    return verify_task_unit_data(output.resolve())


def verify_task_unit_data(root: Path) -> dict[str, Any]:
    """Independently verify a compiled task-unit data bundle."""

    bundle = root.resolve()
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise TaskUnitDataError("compiled data manifest is missing")
    manifest = _canonical_json_file(manifest_path, "manifest")
    if (
        manifest.get("schema_version") != "3.0"
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
    quality = _unique_by(artifacts["task-quality.jsonl"], "task_unit_id", "quality rows")
    roles = _unique_by(artifacts["task-roles.jsonl"], "task_unit_id", "role rows")
    if set(task_units) != set(quality) or set(task_units) != set(roles):
        raise TaskUnitDataError("compiled task, quality, and role populations differ")
    source_records = []
    for task_id, row in task_units.items():
        if (
            row.get("schema_version") != "task-unit-3.0"
            or row.get("legacy_identity", {}).get("semantic_cluster_id") != task_id
            or row.get("task_unit_record_sha256")
            != content_hash({key: value for key, value in row.items() if key != "task_unit_record_sha256"})
            or row.get("model_visible_input", {}).get("natural_prompt_content_sha256")
            != content_hash(row.get("model_visible_input", {}).get("natural_prompt"))
        ):
            raise TaskUnitDataError("compiled task identity is invalid")
        source_records.extend(row["legacy_identity"]["source_record_ids"])
    if len(source_records) != len(set(source_records)):
        raise TaskUnitDataError("compiled source records are duplicated")

    group_rows = _unique_by(
        artifacts["near-duplicate-groups.jsonl"],
        "near_duplicate_group_id",
        "near-duplicate groups",
    )
    grouped_tasks = [task_id for row in group_rows.values() for task_id in row["task_unit_ids"]]
    if len(grouped_tasks) != len(set(grouped_tasks)) or set(grouped_tasks) != set(task_units):
        raise TaskUnitDataError("near-duplicate groups do not partition task units")
    lineage_rows = _unique_by(
        artifacts["source-lineages.jsonl"], "source_lineage_id", "source lineages"
    )
    lineage_tasks = [task_id for row in lineage_rows.values() for task_id in row["task_unit_ids"]]
    if len(lineage_tasks) != len(set(lineage_tasks)) or set(lineage_tasks) != set(task_units):
        raise TaskUnitDataError("source lineages do not partition task units")
    if (
        report.get("source_record_count") != len(source_records)
        or report.get("task_unit_count") != len(task_units)
        or report.get("prompt_tsg")
        != {
            "status": "NOT_GENERATED_PENDING_METHOD_FREEZE",
            "extractor_id": None,
            "catalog_sha256": None,
            "task_count": 0,
        }
        or report.get("arms_or_outcomes_used") is not False
        or report.get("formal_execution_authorized") is not False
    ):
        raise TaskUnitDataError("compiled data report is invalid")
    return {
        "status": "VERIFIED_TASK_UNIT_DATA_PROMPT_TSG_PENDING",
        "bundle_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_records": len(source_records),
        "task_units": len(task_units),
        "quality_status_counts": report["quality_status_counts"],
        "data_role_counts": report["data_role_counts"],
        "prompt_tsg_status": report["prompt_tsg"]["status"],
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
    }


def _near_duplicate_groups(
    clusters: Mapping[str, dict[str, Any]],
    record_to_task: Mapping[str, str],
    edges: list[dict[str, Any]],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    parent = {task_id: task_id for task_id in clusters}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            keep, drop = min(left_root, right_root), max(left_root, right_root)
            parent[drop] = keep

    for edge in edges:
        if edge.get("label") not in {"same_cluster", "uncertain"}:
            raise TaskUnitDataError("diagnostic edge label is invalid")
        left = record_to_task.get(edge.get("left"))
        right = record_to_task.get(edge.get("right"))
        if left is None or right is None:
            raise TaskUnitDataError("diagnostic edge leaves the task population")
        union(left, right)
    components: dict[str, list[str]] = defaultdict(list)
    for task_id in sorted(clusters):
        components[find(task_id)].append(task_id)
    groups: dict[str, tuple[str, ...]] = {}
    by_task = {}
    for members in components.values():
        frozen = tuple(sorted(members))
        group_id = content_id("near_duplicate_group_", frozen)
        groups[group_id] = frozen
        for task_id in frozen:
            by_task[task_id] = group_id
    return by_task, groups


def _legacy_exposure(
    manifest: Mapping[str, Any], current_tasks: set[str]
) -> dict[str, dict[str, list[str]]]:
    if (
        manifest.get("artifact_kind") != "legacy_data_role_manifest"
        or manifest.get("data_role") != "LEGACY_ONLY"
        or manifest.get("formal_use_authorized") is not False
    ):
        raise TaskUnitDataError("legacy role manifest is invalid")
    result: dict[str, dict[str, list[str]]] = {}
    for binding in _rows(manifest.get("bindings"), "legacy bindings"):
        if binding.get("data_role") != "LEGACY_ONLY":
            raise TaskUnitDataError("legacy binding has a non-legacy role")
        data_id = _text(binding.get("data_id"), "legacy data ID")
        history = _texts(binding.get("exposure_history_applies_to_all_task_units"), "history")
        lineage = _object(binding.get("task_unit_source_lineage"), "legacy lineage")
        for task_id in sorted(set(lineage) & current_tasks):
            if task_id in result:
                raise TaskUnitDataError("legacy task appears in multiple bindings")
            result[task_id] = {"data_ids": [data_id], "history": list(history)}
    return result


def _write_bundle(
    root: Path,
    jsonl_artifacts: Mapping[str, Iterable[Mapping[str, Any]]],
    report: Mapping[str, Any],
) -> None:
    if root.exists():
        raise FileExistsError(root)
    root.mkdir(parents=True)
    descriptors: dict[str, dict[str, Any]] = {}
    for name, values in sorted(jsonl_artifacts.items()):
        rows = list(values)
        payload = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
        (root / name).write_bytes(payload)
        descriptors[name] = {
            "format": "canonical-jsonl",
            "record_count": len(rows),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    report_payload = (canonical_json(report) + "\n").encode("utf-8")
    (root / "report.json").write_bytes(report_payload)
    descriptors["report.json"] = {
        "format": "canonical-json",
        "sha256": hashlib.sha256(report_payload).hexdigest(),
    }
    manifest = {
        "schema_version": "3.0",
        "artifact_kind": "reviewer_task_unit_dataset",
        "files": descriptors,
    }
    (root / "manifest.json").write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))


def _canonical_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    payload = path.read_bytes()
    try:
        lines = payload.decode("utf-8").splitlines(keepends=True)
        rows = [json.loads(line) for line in lines]
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise TaskUnitDataError(f"{label} is unreadable") from None
    if not lines or any(
        not isinstance(row, dict) or line != canonical_json(row) + "\n"
        for line, row in zip(lines, rows, strict=True)
    ):
        raise TaskUnitDataError(f"{label} is not canonical JSONL")
    return rows


def _canonical_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise TaskUnitDataError(f"{label} is unreadable") from None
    if not isinstance(value, dict) or payload != (canonical_json(value) + "\n").encode("utf-8"):
        raise TaskUnitDataError(f"{label} is not canonical JSON")
    return value


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


def _rows(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise TaskUnitDataError(f"{label} must be a JSON object list")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TaskUnitDataError(f"{label} must be non-empty text")
    return value


def _texts(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise TaskUnitDataError(f"{label} must be a text list")
    return tuple(value)


__all__ = [
    "TaskUnitDataError",
    "compile_task_unit_data",
    "verify_task_unit_data",
]

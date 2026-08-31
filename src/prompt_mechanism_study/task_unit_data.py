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
    "functional-contracts.jsonl",
    "near-duplicate-groups.jsonl",
    "readiness-worklist.jsonl",
    "source-lineages.jsonl",
    "task-quality.jsonl",
    "task-roles.jsonl",
    "task-units.jsonl",
}
_BUNDLE_FILES = _JSONL_FILES | {"report.json"}
_QUALITY_DISPOSITION = {
    "INCLUDED_FINAL_DATASET": "QUALITY_INCLUDED",
    "PENDING_INDEPENDENT_REVIEW": "QUALITY_PENDING_INDEPENDENT_REVIEW",
    "PENDING_QUALITY_REPAIR": "QUALITY_PENDING_CONTRACT_REPAIR",
    "EXCLUDED_SOURCE_DEFECT": "QUALITY_EXCLUDED_SOURCE_DEFECT",
    "EXCLUDED_INSUFFICIENT_SPECIFICATION": (
        "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION"
    ),
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
_REPRESENTATIVE_SELECTION_RULE = "prefer_source_test_then_ascending_record_id_v1"
_MODEL_VISIBLE_RENDER_MODE = "exact_source_prompt_text_only"


class TaskUnitDataError(ValueError):
    """The task-unit compilation inputs or output violate the frozen contract."""


def compile_task_unit_data(
    *,
    prepared_root: Path,
    clusters_root: Path,
    candidate_root: Path,
    contracts_root: Path,
    contract_reviews_root: Path,
    legacy_roles_root: Path,
    development_exclusions_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Build one immutable row per frozen task unit without generating Prompt TSGs."""

    inputs = {
        "prepared": prepared_root.resolve(),
        "clusters": clusters_root.resolve(),
        "candidate": candidate_root.resolve(),
        "contracts": contracts_root.resolve(),
        "contract_reviews": contract_reviews_root.resolve(),
        "legacy_roles": legacy_roles_root.resolve(),
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
    contracts = _rows(
        read_json(inputs["contracts"] / "functional-contracts.json"), "contracts"
    )
    contract_reviews = _rows(
        read_json(inputs["contract_reviews"] / "contract-quality-reviews.json"),
        "contract reviews",
    )
    contract_repairs = _rows(
        read_json(inputs["contracts"] / "repairs.json"), "contract repairs"
    )
    contract_review_overrides = _rows(
        read_json(inputs["contracts"] / "review-overrides.json"),
        "contract review overrides",
    )
    legacy_manifest = _object(
        read_json(inputs["legacy_roles"] / "role-manifest.json"), "legacy manifest"
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
    contract_rows = _reviewer_contract_rows(
        clusters=cluster_by_id,
        records=records,
        ledger=ledger_by_id,
        contracts=contracts,
        reviews=contract_reviews,
        repairs=contract_repairs,
        overrides=contract_review_overrides,
        contracts_bundle_sha256=bundle_digest(inputs["contracts"]),
        reviews_bundle_sha256=bundle_digest(inputs["contract_reviews"]),
    )
    contract_by_task = _unique_by(contract_rows, "task_unit_id", "reviewer contracts")
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
            "contracts_bundle_sha256",
            "contract_reviews_bundle_sha256",
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
        languages = {row["language"] for row in members}
        if len(languages) != 1 or representative["language"] not in languages:
            raise TaskUnitDataError("one task unit cannot cross declared languages")
        expected_representative = min(
            members,
            key=lambda row: (not bool(row.get("source_test_references")), row["record_id"]),
        )
        if representative["record_id"] != expected_representative["record_id"]:
            raise TaskUnitDataError("task representative selection is not deterministic")
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
                "source_test_reference_count": len(row.get("source_test_references", [])),
            }
            for row in sorted(members, key=lambda item: item["record_id"])
        ]
        test_refs = [
            {"source_record_id": row["record_id"], "reference": reference}
            for row in members
            for reference in row.get("source_test_references", [])
        ]
        task_core = {
            "schema_version": "task-unit-4.0",
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
                "visible_assets": [],
                "render_mode": _MODEL_VISIBLE_RENDER_MODE,
                "model_visible_input_identity_sha256": content_hash(
                    {
                        "natural_prompt": representative["prompt"],
                        "visible_assets": [],
                        "render_mode": _MODEL_VISIBLE_RENDER_MODE,
                    }
                ),
            },
            "declared_execution_context": {
                "language": representative["language"],
                "runtime": None,
                "model_visible_under_current_render_mode": False,
            },
            "pre_treatment_source_metadata": {
                "language": representative["language"],
                "source_declared_cwe_ids": list(cluster["cwes"]),
                "cwe_label_conflict": cluster["cwe_label_conflict"],
                "label_semantics": "routing_and_census_only_not_prompt_tsg_evidence",
            },
            "source_member_summary": {
                "member_count": len(members),
                "model_visible_prompt_variant_count": len(
                    {row["prompt_sha256"] for row in members}
                ),
                "representative_selection_rule": _REPRESENTATIVE_SELECTION_RULE,
                "lineage_variants_are_dependent_descendants": True,
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
        if final_status not in _QUALITY_DISPOSITION:
            raise TaskUnitDataError("unknown final-data quality status")
        quality_core = {
            "schema_version": "task-quality-4.0",
            "task_unit_id": task_id,
            "quality_disposition": _QUALITY_DISPOSITION[final_status],
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
            "authority_boundary": (
                "source_and_contract_quality_only_not_scope_measurement_exposure_or_role"
            ),
            "decision_provenance": {
                "candidate_bundle_sha256": provenance["candidate_bundle_sha256"],
                "contract_record_sha256": contract_by_task[task_id][
                    "functional_contract_record_sha256"
                ],
            },
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
        exposure_categories = ["SOURCE_CURATED"]
        if role != "UNASSIGNED":
            exposure_categories.append("METHOD_DEVELOPMENT_VIEWED")
        if role == "LEGACY_ONLY":
            exposure_categories.append("QUALIFICATION_OUTCOME_VIEWED")
        role_core = {
            "schema_version": "task-role-4.0",
            "task_unit_id": task_id,
            "data_role": role,
            "role_assignment_status": assignment_status,
            "near_duplicate_group_id": near_group_by_task[task_id],
            "source_lineage_id": lineage_id,
            "exposure_status": (
                "METHOD_EXPOSED" if role != "UNASSIGNED" else "SOURCE_CURATED_ONLY"
            ),
            "exposure_categories": exposure_categories,
            "exposure_evidence": exposure_history,
            "exposure_data_ids": exposure_data_ids,
            "prospective_confirmatory_reuse_status": (
                "EXCLUDED_METHOD_DEVELOPMENT_EXPOSURE"
                if role != "UNASSIGNED"
                else "UNDETERMINED_PENDING_FORMAL_ALLOCATION"
            ),
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
            "schema_version": "near-duplicate-group-4.0",
            "near_duplicate_group_id": group_id,
            "task_unit_ids": list(task_ids),
            "group_basis": "semantic_task_unit_plus_same_or_uncertain_diagnostic_edges_v1",
            "maximum_task_units_across_all_prospective_formal_roles": 1,
        }
        near_group_rows.append(
            {**core, "near_duplicate_group_record_sha256": content_hash(core)}
        )

    role_by_task = {row["task_unit_id"]: row for row in role_rows}
    quality_by_task = {row["task_unit_id"]: row for row in quality_rows}
    readiness_rows = [
        _readiness_work_item(row, quality_by_task[task_id], near_group_by_task[task_id])
        for task_id, row in sorted(ledger_by_id.items())
    ]
    technical_ready_ids = {
        row["task_unit_id"]
        for row in readiness_rows
        if row["readiness_summary_status"] == "TECHNICALLY_READY_PENDING_METHOD_FREEZE"
    }
    unexposed_ready = sum(
        role_by_task[task_id]["data_role"] == "UNASSIGNED"
        for task_id in technical_ready_ids
    )

    report = {
        "schema_version": "4.0",
        "status": "TASK_UNIT_DATA_COMPILED_PROMPT_TSG_PENDING_METHOD_FREEZE",
        "source_record_count": len(records),
        "task_unit_count": len(task_units),
        "quality_disposition_counts": dict(
            sorted(Counter(row["quality_disposition"] for row in quality_rows).items())
        ),
        "data_role_counts": dict(
            sorted(Counter(row["data_role"] for row in role_rows).items())
        ),
        "source_lineage_count": len(lineage_rows),
        "near_duplicate_group_count": len(near_group_rows),
        "multi_record_task_unit_count": sum(
            len(row["legacy_identity"]["source_record_ids"]) > 1 for row in task_units
        ),
        "model_visible_variant_task_unit_count": sum(
            row["source_member_summary"]["model_visible_prompt_variant_count"] > 1
            for row in task_units
        ),
        "functional_contract_count": len(contract_rows),
        "requirement_evidence_status_counts": dict(
            sorted(
                Counter(
                    row["requirement_evidence_status"] for row in contract_rows
                ).items()
            )
        ),
        "technical_ready_task_unit_count": len(technical_ready_ids),
        "unexposed_ready_task_unit_count": unexposed_ready,
        "readiness_workstream_counts": dict(
            sorted(Counter(row["workstream"] for row in readiness_rows).items())
        ),
        "readiness_axis_counts": {
            field: dict(sorted(Counter(row[field] for row in readiness_rows).items()))
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
        },
        "referential_integrity": {
            "core_task_unit_populations_equal": True,
            "contracts_prompt_hash_bound": True,
            "quality_contract_version_bound": True,
            "source_records_partitioned_exactly_once": True,
            "near_duplicate_groups_partition_task_units": True,
            "readiness_is_derived_view": True,
            "downstream_experimental_fields_absent": True,
        },
        "formal_role_assignment_frozen": False,
        "readiness_artifact_kind": "DERIVED_VIEW",
        "readiness_profile_status": "PROVISIONAL_PENDING_METHOD_FREEZE",
        "near_duplicate_formal_role_rule": (
            "at_most_one_task_unit_per_group_across_all_prospective_formal_roles"
        ),
        "exposure_policy": {
            "source_curation_alone_is_method_development_exposure": False,
            "task_level_use_to_change_method_is_method_development_exposure": True,
            "viewing_qualification_or_generation_outcomes_is_recorded_separately": True,
        },
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
            "functional-contracts.jsonl": contract_rows,
            "task-quality.jsonl": quality_rows,
            "task-roles.jsonl": role_rows,
            "source-lineages.jsonl": lineage_rows,
            "near-duplicate-groups.jsonl": near_group_rows,
            "readiness-worklist.jsonl": readiness_rows,
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


def _reviewer_contract_rows(
    *,
    clusters: Mapping[str, dict[str, Any]],
    records: Mapping[str, dict[str, Any]],
    ledger: Mapping[str, dict[str, Any]],
    contracts: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    overrides: list[dict[str, Any]],
    contracts_bundle_sha256: str,
    reviews_bundle_sha256: str,
) -> list[dict[str, Any]]:
    contract_by_task = _unique_by(contracts, "cluster_id", "functional contracts")
    review_by_task = _unique_by(reviews, "cluster_id", "contract reviews")
    repair_by_task = _unique_by(repairs, "cluster_id", "contract repairs")
    override_by_task = _unique_by(overrides, "cluster_id", "contract review overrides")
    population = set(clusters)
    if (
        set(contract_by_task) != population
        or set(review_by_task) != population
        or not set(repair_by_task) <= population
        or not set(override_by_task) <= population
    ):
        raise TaskUnitDataError("functional contract populations do not align")
    frozen = []
    for task_id in sorted(population):
        cluster = clusters[task_id]
        representative = records[cluster["representative_record_id"]]
        contract = contract_by_task[task_id]
        review = review_by_task[task_id]
        ledger_row = ledger[task_id]
        contract_core = {
            key: value for key, value in contract.items() if key != "contract_id"
        }
        if (
            contract.get("record_id") != representative["record_id"]
            or contract.get("source_prompt_sha256") != representative["prompt_sha256"]
            or contract.get("contract_id") != content_id("cluster_contract_", contract_core)
            or ledger_row.get("contract_id") != contract.get("contract_id")
            or review.get("record_id") != contract.get("record_id")
        ):
            raise TaskUnitDataError("functional contract source binding is stale")
        repair = repair_by_task.get(task_id)
        repair_codes: list[str] = []
        remaining_deterministic = list(review.get("deterministic_issue_codes", []))
        if repair is None:
            if review.get("contract_id") != contract.get("contract_id"):
                raise TaskUnitDataError("contract review does not bind the current contract")
        else:
            repair_codes = list(
                repair.get("repair_codes")
                or ([repair["repair_code"]] if isinstance(repair.get("repair_code"), str) else [])
            )
            if (
                review.get("contract_id") != repair.get("old_contract_id")
                or contract.get("contract_id") != repair.get("new_contract_id")
                or repair.get("record_id") != contract.get("record_id")
                or not repair_codes
            ):
                raise TaskUnitDataError("contract repair lineage is invalid")
            if "remove_response_format_instruction_v1" in repair_codes:
                remaining_deterministic = [
                    code
                    for code in remaining_deterministic
                    if code != "response_format_instruction_leak"
                ]
        override = override_by_task.get(task_id)
        if override is None:
            contract_status = review.get("contract_status")
            functional_evaluability = review.get("functional_evaluability")
            issue_codes = review.get("issue_codes")
            reason = review.get("reason")
            adjudication_id = None
        else:
            if (
                override.get("record_id") != contract.get("record_id")
                or override.get("source_review_contract_id") != review.get("contract_id")
                or override.get("current_contract_id") != contract.get("contract_id")
            ):
                raise TaskUnitDataError("contract review override lineage is invalid")
            contract_status = override.get("contract_status")
            functional_evaluability = override.get("functional_evaluability")
            issue_codes = override.get("issue_codes")
            reason = override.get("reason")
            adjudication_id = override.get("adjudication_id")
        if (
            ledger_row.get("review_contract_status") != contract_status
            or ledger_row.get("functional_evaluability") != functional_evaluability
            or not isinstance(issue_codes, list)
            or not isinstance(reason, str)
        ):
            raise TaskUnitDataError("effective contract review drifts from quality ledger")
        for field in (
            "requirements",
            "inputs",
            "outputs",
            "side_effects",
            "environment_dependencies",
        ):
            values = contract.get(field)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise TaskUnitDataError("functional contract list is invalid")
        requirement_evidence = contract.get("requirement_evidence")
        if requirement_evidence is not None and (
            not isinstance(requirement_evidence, list)
            or len(requirement_evidence) != len(contract["requirements"])
            or any(not isinstance(item, dict) for item in requirement_evidence)
        ):
            raise TaskUnitDataError("functional contract evidence is invalid")
        core = {
            "schema_version": "functional-contract-reviewer-4.0",
            "task_unit_id": task_id,
            "contract_id": contract["contract_id"],
            "record_id": contract["record_id"],
            "source_prompt_sha256": contract["source_prompt_sha256"],
            "resolution_status": contract["resolution_status"],
            "entrypoint": contract["entrypoint"],
            "requirements": contract["requirements"],
            "requirement_evidence": requirement_evidence or [],
            "inputs": contract["inputs"],
            "outputs": contract["outputs"],
            "side_effects": contract["side_effects"],
            "environment_dependencies": contract["environment_dependencies"],
            "extraction_reason": contract["reason"],
            "requirement_evidence_status": (
                "SOURCE_SPANS_COMPLETE"
                if requirement_evidence is not None
                else "LEGACY_TEXT_CONTRACT_PENDING_SOURCE_SPAN_ENRICHMENT"
            ),
            "review": {
                "contract_status": contract_status,
                "functional_evaluability": functional_evaluability,
                "issue_codes": issue_codes,
                "remaining_deterministic_issue_codes": sorted(
                    set(remaining_deterministic)
                ),
                "reason": reason,
                "procedure_id": "blind_functional_contract_quality_review_v1",
                "adjudication_id": adjudication_id,
                "repair_codes": sorted(set(repair_codes)),
            },
            "provenance": {
                "contracts_bundle_sha256": contracts_bundle_sha256,
                "contract_reviews_bundle_sha256": reviews_bundle_sha256,
            },
            "arms_or_outcomes_used": False,
        }
        frozen.append(
            {**core, "functional_contract_record_sha256": content_hash(core)}
        )
    return frozen


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


def _readiness_work_item(
    ledger_row: Mapping[str, Any],
    quality_row: Mapping[str, Any],
    near_duplicate_group_id: str,
) -> dict[str, Any]:
    task_id = _text(ledger_row.get("task_unit_id"), "readiness task ID")
    blockers = tuple(sorted(set(_texts(ledger_row.get("blocker_codes"), "blockers"))))
    quality_disposition = _text(
        quality_row.get("quality_disposition"), "quality disposition"
    )
    if quality_disposition == "QUALITY_INCLUDED":
        quality_gate = "PASSED"
    elif quality_disposition.startswith("QUALITY_EXCLUDED_"):
        quality_gate = "EXCLUDED"
    else:
        quality_gate = "NOT_FINAL"
    if "known_measurement_scope_concern" in blockers:
        scope_status = "REVIEW_REQUIRED"
    elif ledger_row.get("study_layer") is None:
        scope_status = "OUTSIDE_CURRENT_STUDY_LAYERS"
    else:
        scope_status = "IN_CURRENT_STUDY_LAYER"
    binding_status = str(ledger_row.get("mechanism_binding_status") or "NOT_EVALUATED")
    mechanism_registration_status = {
        "BOUND": "REGISTERED",
        "PENDING_BLIND_REVIEW": "REGISTERED_CANDIDATES_REQUIRE_BINDING",
        "UNREGISTERED": "NOT_REGISTERED",
        "CONFLICT": "LABEL_CONFLICT_REQUIRES_REVIEW",
        "OUTSIDE_CURRENT_SCOPE": "NOT_EVALUATED_OUTSIDE_SCOPE",
        "PENDING_RUNTIME": "NOT_EVALUATED_PENDING_REPLICATION_RUNTIME",
        "NOT_APPLICABLE": "NOT_APPLICABLE_CURRENT_PROFILE",
    }.get(binding_status, "NOT_EVALUATED")
    oracle_status = str(ledger_row.get("oracle_support_status") or "NOT_EVALUATED")
    runtime_status = str(ledger_row.get("runtime_support_status") or "NOT_EVALUATED")
    functional_measurement_status = str(
        ledger_row.get("functional_measurement") or "NOT_EVALUATED"
    )
    independent_quality_review_status = (
        "PENDING"
        if quality_disposition == "QUALITY_PENDING_INDEPENDENT_REVIEW"
        else "NOT_REQUIRED_OR_COMPLETE"
    )
    action_input = {
        "quality_gate": quality_gate,
        "quality_disposition": quality_disposition,
        "scope_status": scope_status,
        "mechanism_registration_status": mechanism_registration_status,
        "binding_status": binding_status,
        "oracle_status": oracle_status,
        "runtime_status": runtime_status,
        "functional_measurement_status": functional_measurement_status,
        "independent_quality_review_status": independent_quality_review_status,
    }
    summary_status, workstream, next_action, required_evidence = _readiness_action(
        action_input
    )
    action_status = {
        "QUALITY_EXCLUDED": "CLOSED_EXCLUDED",
        "TECHNICALLY_READY_PENDING_METHOD_FREEZE": "WAITING_METHOD_FREEZE",
    }.get(summary_status, "OPEN")
    grouping_coordinates = [
        workstream,
        str(ledger_row.get("language")),
        str(ledger_row.get("primary_cwe")),
    ]
    if workstream == "CONTRACT_REPAIR":
        grouping_coordinates.append(str(ledger_row.get("source_dataset")))
    elif workstream == "RUNTIME_QUALIFICATION":
        grouping_coordinates.append(
            str(ledger_row.get("mechanism_realization_id") or "unbound")
        )
    elif workstream == "SCOPE_DECISION":
        grouping_coordinates.append(
            str(ledger_row.get("priority_extension_tier") or "unprioritized")
        )
    core = {
        "schema_version": "readiness-work-item-4.0",
        "artifact_kind": "DERIVED_VIEW",
        "task_unit_id": task_id,
        **action_input,
        "readiness_summary_status": summary_status,
        "readiness_profile_status": "PROVISIONAL_PENDING_METHOD_FREEZE",
        "workstream": workstream,
        "work_group_id": content_id("readiness_work_group_", grouping_coordinates),
        "grouping_coordinates": grouping_coordinates,
        "action_status": action_status,
        "primary_next_action": next_action,
        "required_evidence": required_evidence,
        "language": ledger_row.get("language"),
        "primary_cwe": ledger_row.get("primary_cwe"),
        "source_lineage_id": ledger_row.get("source_lineage_family"),
        "source_test_available": ledger_row.get("source_test_available"),
        "contract_id": ledger_row.get("contract_id"),
        "mechanism_realization_id": ledger_row.get("mechanism_realization_id"),
        "oracle_profile_id": ledger_row.get("oracle_profile_id"),
        "diagnostic_blocker_codes": [
            blocker
            for blocker in blockers
            if blocker != "development_exposed" and not blocker.startswith("pending_")
        ],
        "near_duplicate_group_id": near_duplicate_group_id,
        "arms_or_outcomes_used": False,
        "formal_use_authorized": False,
    }
    return {**core, "readiness_record_sha256": content_hash(core)}


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
        "schema_version": "4.0",
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

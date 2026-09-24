"""Scoped Oracle qualification, TSG task selection, and binding adjudication."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_bundle
from prompt_mechanism_study.discovery.mechanisms import (
    load_mechanism_registry,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.measurement.security_profiles import (
    LOCAL_PROFILE_IDS,
    TASK_BOUND_PROFILE_IDS,
    evaluate_security_profile,
    security_profile_producer_sha256,
)


class EligibilityError(RuntimeError):
    """Raised when an eligibility input or policy is inconsistent."""


def qualify_target_security_profiles(
    repository_root: Path,
    registry_path: Path,
    case_paths: tuple[Path, ...],
    output: Path,
    *,
    profile_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Qualify the declared profile scope on arm-blind gold code idioms.

    Omitting the scope checks all registered, supported profiles.
    Explicit scope never certifies an untested profile or broader code coverage.
    """

    root = repository_root.resolve()
    registry_file = registry_path.resolve()
    if not case_paths or len(case_paths) != len(set(case_paths)):
        raise EligibilityError("target security qualification case sources are invalid")
    sources = []
    cases = []
    for source_path in case_paths:
        source = source_path.resolve()
        try:
            relative = source.relative_to(root).as_posix()
        except ValueError as exc:
            raise EligibilityError(
                "target security qualification cases must be inside the repository"
            ) from exc
        source_cases = _rows(read_json(source))
        sources.append({"path": relative, "sha256": file_sha256(source)})
        cases.extend(source_cases)

    registry = load_mechanism_registry(registry_file)
    case_ids = [row.get("case_id") for row in cases]
    if not cases or len(case_ids) != len(set(case_ids)) or any(
        not isinstance(case_id, str) or not case_id for case_id in case_ids
    ):
        raise EligibilityError("target security qualification case identities are invalid")
    registered_profiles = {
        row["oracle_profile_id"]
        for row in registry.values()
        if row["oracle_profile_id"] in LOCAL_PROFILE_IDS
    }
    active_profiles = registered_profiles
    if profile_ids is not None:
        if (not profile_ids or len(set(profile_ids)) != len(profile_ids)
                or not set(profile_ids) <= registered_profiles):
            raise EligibilityError("target security qualification profile scope is invalid")
        active_profiles = set(profile_ids)
    supplied_case_count = len(cases)
    if profile_ids is not None:
        cases = [case for case in cases if case.get("profile_id") in active_profiles]
    case_profiles = {row.get("profile_id") for row in cases}
    if not case_profiles <= active_profiles:
        raise EligibilityError(
            "target security qualification cases include an undeclared profile"
        )

    labels_by_profile: dict[str, set[str]] = {
        profile: set() for profile in active_profiles
    }
    results = []
    for case in cases:
        if set(case) != {"case_id", "profile_id", "expected_label", "code"} or case[
            "expected_label"
        ] not in {"secure", "insecure", "unknown"}:
            raise EligibilityError("target security qualification case is invalid")
        labels_by_profile[case["profile_id"]].add(case["expected_label"])
        result = evaluate_security_profile(case["code"], case["profile_id"])
        results.append(
            {
                "case_id": case["case_id"],
                "profile_id": case["profile_id"],
                "expected_label": case["expected_label"],
                "actual_label": result["security_label"],
                "reason_code": result["reason_code"],
                "matched": result["security_label"] == case["expected_label"],
            }
        )
    mismatches = [row for row in results if not row["matched"]]
    profile_results = {}
    for profile in sorted(active_profiles):
        reasons = []
        if profile in TASK_BOUND_PROFILE_IDS:
            reasons.append("task_bound_endpoint_required")
        if labels_by_profile[profile] != {"secure", "insecure", "unknown"}:
            reasons.append("missing_gold_label_coverage")
        if any(row["profile_id"] == profile for row in mismatches):
            reasons.append("gold_label_mismatch")
        profile_results[profile] = dict(status="BLOCKED" if reasons else "QUALIFIED", reasons=reasons)
    qualified_profiles = [profile for profile, row in profile_results.items() if row["status"] == "QUALIFIED"]
    report = {
        "schema_version": "3.0",
        "artifact_kind": "target_security_profile_qualification",
        "protocol_id": "phase-context-policy-v3",
        "status": (
            "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
            if len(qualified_profiles) == len(active_profiles)
            else "PARTIALLY_QUALIFIED_TARGET_MEASUREMENT_PROFILES" if qualified_profiles
            else "TARGET_MEASUREMENT_PROFILE_QUALIFICATION_FAILED"
        ),
        "active_local_profiles": sorted(active_profiles),
        "qualified_profiles": qualified_profiles,
        "profile_results": profile_results,
        "unsupported_registry_profiles": sorted(
            {
                row["oracle_profile_id"]
                for row in registry.values()
                if row["oracle_profile_id"] not in LOCAL_PROFILE_IDS
            }
        ),
        "case_sources": sources,
        "cases_sha256": content_hash(sources),
        "gold_cases": len(cases),
        "label_mismatches": len(mismatches),
        "required_labels": ["secure", "insecure", "unknown"],
        "registry_sha256": file_sha256(registry_file),
        "implementation_sha256": security_profile_producer_sha256(),
        "unknown_is_secure": False,
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
        "scientific_claim_allowed": False,
        "claim_boundary": (
            "Qualification covers only the current local AST implementation and frozen "
            "gold idioms; it is not a global CWE-detection accuracy claim."
        ),
    }
    if profile_ids is not None:
        report["qualification_scope"] = {
            "profile_ids": sorted(active_profiles),
            "registered_local_profiles_not_qualified": sorted(registered_profiles - active_profiles),
            "supplied_gold_cases": supplied_case_count,
            "out_of_scope_gold_cases": supplied_case_count - len(cases),
            "coverage": "only_the_evaluated_gold_code_idioms_within_the_declared_profiles",
        }
    write_bundle(output, {"case-results.json": results, "qualification.json": report})
    return report


def freeze_prompt_tsg_task_selection(
    tasks_path: Path,
    exclusion_paths: tuple[Path, ...],
    output: Path,
) -> dict[str, Any]:
    """Freeze the formal extraction population after provenance-only exclusions."""

    tasks = _rows(read_json(tasks_path))
    task_ids = [row.get("task_unit_id") for row in tasks]
    if (
        not tasks
        or len(task_ids) != len(set(task_ids))
        or any(
            not isinstance(task_id, str)
            or task_id != row.get("task_id")
            for task_id, row in zip(task_ids, tasks, strict=True)
        )
    ):
        raise EligibilityError("formal extraction tasks are invalid")
    excluded, exclusion_hashes = _load_task_exclusions(exclusion_paths)
    selected = [task_id for task_id in task_ids if task_id not in excluded]
    if not selected:
        raise EligibilityError("formal extraction selection is empty")
    selection = {
        "schema_version": "1.0",
        "source_tasks_sha256": file_sha256(tasks_path),
        "selection_rule": (
            "Retain every outcome-blind discovery task unit except prior extractor-development, "
            "qualification-holdout, semantic-review, or generation/outcome-exposed units."
        ),
        "task_ids": selected,
        "arms_or_outcomes_used": False,
    }
    selected_rows = [row for row in tasks if row["task_unit_id"] in set(selected)]
    report = {
        "schema_version": "1.0",
        "status": "FORMAL_PROMPT_TSG_TASKS_FROZEN",
        "source_task_units": len(tasks),
        "selected_task_units": len(selected),
        "excluded_task_units_in_source": len(tasks) - len(selected),
        "selected_cwe_counts": dict(
            sorted(Counter(row["cwe"] for row in selected_rows).items())
        ),
        "exclusion_files": exclusion_hashes,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"selection.json": selection, "report.json": report})
    return report


def freeze_prompt_tsg_holdout_selection(
    tasks_path: Path,
    exclusion_paths: tuple[Path, ...],
    output: Path,
    *,
    cwes: tuple[str, ...],
    task_units_per_cwe: int = 3,
    ranking_salt: str,
) -> dict[str, Any]:
    """Freeze one disjoint, outcome-blind semantic-qualification holdout."""

    tasks = _rows(read_json(tasks_path))
    task_ids = [row.get("task_unit_id") for row in tasks]
    if (
        not tasks
        or len(task_ids) != len(set(task_ids))
        or any(
            not isinstance(task_id, str)
            or task_id != row.get("task_id")
            or not isinstance(row.get("cwe"), str)
            for task_id, row in zip(task_ids, tasks, strict=True)
        )
    ):
        raise EligibilityError("holdout source tasks are invalid")
    if (
        not cwes
        or tuple(sorted(set(cwes))) != cwes
        or any(not isinstance(cwe, str) or not cwe for cwe in cwes)
        or type(task_units_per_cwe) is not int
        or task_units_per_cwe <= 0
        or not isinstance(ranking_salt, str)
        or not ranking_salt.strip()
    ):
        raise EligibilityError("holdout selection policy is invalid")
    excluded, exclusion_hashes = _load_task_exclusions(exclusion_paths)
    selected_rows = []
    available_counts = {}
    for cwe in cwes:
        available = [
            row
            for row in tasks
            if row["cwe"] == cwe and row["task_unit_id"] not in excluded
        ]
        available.sort(
            key=lambda row: hashlib.sha256(
                f"{ranking_salt}|{row['task_unit_id']}".encode("utf-8")
            ).hexdigest()
        )
        available_counts[cwe] = len(available)
        if len(available) < task_units_per_cwe:
            raise EligibilityError(f"holdout stratum {cwe} lacks disjoint task units")
        selected_rows.extend(available[:task_units_per_cwe])
    selected = [row["task_unit_id"] for row in selected_rows]
    if set(selected) & set(excluded) or len(selected) != len(set(selected)):
        raise EligibilityError("holdout selection overlaps a prior exposure")
    selection = {
        "schema_version": "1.0",
        "source_tasks_sha256": file_sha256(tasks_path),
        "selection_rule": (
            f"Select {task_units_per_cwe} task units per frozen CWE by ascending "
            f"SHA-256({ranking_salt}|task_unit_id) after the complete exclusion ledger."
        ),
        "task_ids": selected,
        "arms_or_outcomes_used": False,
    }
    report = {
        "schema_version": "1.0",
        "status": "PROMPT_TSG_HOLDOUT_FROZEN",
        "source_task_units": len(tasks),
        "selected_task_units": len(selected),
        "selected_cwes": list(cwes),
        "task_units_per_cwe": task_units_per_cwe,
        "available_counts_before_selection": available_counts,
        "ranking_salt": ranking_salt,
        "exclusion_files": exclusion_hashes,
        "excluded_task_units_in_source": sum(task_id in excluded for task_id in task_ids),
        "selection_overlap_with_exclusions": 0,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"selection.json": selection, "report.json": report})
    return report


def _load_task_exclusions(
    exclusion_paths: tuple[Path, ...],
) -> tuple[dict[str, str], list[dict[str, str]]]:
    excluded: dict[str, str] = {}
    exclusion_hashes = []
    for path in exclusion_paths:
        value = read_json(path)
        if isinstance(value, list):
            rows = _rows(value)
        elif isinstance(value, dict) and isinstance(value.get("exclusions"), list):
            rows = _rows(value["exclusions"])
        elif isinstance(value, dict) and isinstance(value.get("task_ids"), list):
            rows = [{"task_id": task_id} for task_id in value["task_ids"]]
        else:
            raise EligibilityError("task exclusion file is invalid")
        for row in rows:
            task_id = row.get("task_unit_id", row.get("task_id"))
            if not isinstance(task_id, str) or not task_id:
                raise EligibilityError("task exclusion lacks a task identity")
            excluded.setdefault(task_id, path.as_posix())
        exclusion_hashes.append({"path": path.as_posix(), "sha256": file_sha256(path)})
    return excluded, exclusion_hashes


_MEMORY_REPLICATION_CWES = {
    "CWE-119",
    "CWE-120",
    "CWE-125",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-787",
}


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise EligibilityError("eligibility input must contain object rows")
    return value


__all__ = [
    "EligibilityError",
    "freeze_prompt_tsg_holdout_selection",
    "freeze_prompt_tsg_task_selection",
    "qualify_target_security_profiles",
]

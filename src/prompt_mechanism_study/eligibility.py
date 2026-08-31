"""Outcome-blind eligibility audit for curated semantic task clusters."""

from __future__ import annotations

import ast
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.mechanisms import (
    load_mechanism_registry,
    tsg_mechanism_binding,
)
from prompt_mechanism_study.prompt_tsg import (
    load_catalog,
    prompt_tsg_from_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
)
from prompt_mechanism_study.target_security_profiles import (
    TARGET_LOCAL_PROFILE_IDS,
    TARGET_ONLY_PROFILE_IDS,
    evaluate_target_security_profile,
    target_security_profile_producer_sha256,
)


class EligibilityError(RuntimeError):
    """Raised when an eligibility input or policy is inconsistent."""


def qualify_local_security_profiles(
    repository_root: Path,
    registry_path: Path,
    cases_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Replay the frozen three-way gold boundary for every active local profile."""

    root = repository_root.resolve()
    registry = load_mechanism_registry(registry_path)
    cases = _rows(read_json(cases_path))
    case_ids = [row.get("case_id") for row in cases]
    if not cases or len(case_ids) != len(set(case_ids)) or any(
        not isinstance(case_id, str) or not case_id for case_id in case_ids
    ):
        raise EligibilityError("security qualification case identities are invalid")
    active_profiles = {
        row["oracle_profile_id"]
        for row in registry.values()
        if row["oracle_profile_id"] in LOCAL_PROFILE_IDS
    }
    case_profiles = {row.get("profile_id") for row in cases}
    if case_profiles != active_profiles:
        raise EligibilityError("security qualification cases do not exactly cover local profiles")

    labels_by_profile: dict[str, set[str]] = {profile: set() for profile in active_profiles}
    results = []
    for case in cases:
        if set(case) != {"case_id", "profile_id", "expected_label", "code"} or case[
            "expected_label"
        ] not in {"secure", "insecure", "unknown"}:
            raise EligibilityError("security qualification case is invalid")
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
    if any(labels != {"secure", "insecure", "unknown"} for labels in labels_by_profile.values()):
        raise EligibilityError("each local profile requires secure, insecure, and unknown gold cases")
    mismatches = [row for row in results if not row["matched"]]
    report = {
        "schema_version": "1.0",
        "status": "QUALIFIED_FOR_EXPERIMENT" if not mismatches else "QUALIFICATION_FAILED",
        "active_local_profiles": sorted(active_profiles),
        "unsupported_registry_profiles": sorted(
            {
                row["oracle_profile_id"]
                for row in registry.values()
                if row["oracle_profile_id"] not in LOCAL_PROFILE_IDS
            }
        ),
        "gold_cases": len(cases),
        "label_mismatches": len(mismatches),
        "required_labels": ["secure", "insecure", "unknown"],
        "registry_sha256": _sha256(registry_path),
        "cases_sha256": _sha256(cases_path),
        "implementation_sha256": _sha256(root / "src/prompt_mechanism_study/security_profiles.py"),
        "unknown_is_secure": False,
        "claim_boundary": (
            "Qualification covers only the frozen local AST profiles and gold idioms; "
            "it is not a global CWE-detection accuracy claim."
        ),
    }
    write_bundle(output, {"case-results.json": results, "qualification.json": report})
    return report


def qualify_target_security_profiles(
    repository_root: Path,
    registry_path: Path,
    case_paths: tuple[Path, ...],
    output: Path,
) -> dict[str, Any]:
    """Qualify the v3 profile catalog without mutating the legacy producer."""

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
        sources.append({"path": relative, "sha256": _sha256(source)})
        cases.extend(source_cases)

    registry = load_mechanism_registry(registry_file)
    case_ids = [row.get("case_id") for row in cases]
    if not cases or len(case_ids) != len(set(case_ids)) or any(
        not isinstance(case_id, str) or not case_id for case_id in case_ids
    ):
        raise EligibilityError("target security qualification case identities are invalid")
    active_profiles = {
        row["oracle_profile_id"]
        for row in registry.values()
        if row["oracle_profile_id"] in TARGET_LOCAL_PROFILE_IDS
    }
    case_profiles = {row.get("profile_id") for row in cases}
    if case_profiles != active_profiles:
        raise EligibilityError(
            "target security qualification cases do not exactly cover target profiles"
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
        result = evaluate_target_security_profile(case["code"], case["profile_id"])
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
    if any(labels != {"secure", "insecure", "unknown"} for labels in labels_by_profile.values()):
        raise EligibilityError(
            "each target local profile requires secure, insecure, and unknown gold cases"
        )

    mismatches = [row for row in results if not row["matched"]]
    report = {
        "schema_version": "3.0",
        "artifact_kind": "target_security_profile_qualification",
        "protocol_id": "phase-context-policy-v3",
        "status": (
            "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
            if not mismatches
            else "TARGET_MEASUREMENT_PROFILE_QUALIFICATION_FAILED"
        ),
        "active_local_profiles": sorted(active_profiles),
        "target_only_profiles": sorted(active_profiles & TARGET_ONLY_PROFILE_IDS),
        "unsupported_registry_profiles": sorted(
            {
                row["oracle_profile_id"]
                for row in registry.values()
                if row["oracle_profile_id"] not in TARGET_LOCAL_PROFILE_IDS
            }
        ),
        "case_sources": sources,
        "cases_sha256": content_hash(sources),
        "gold_cases": len(cases),
        "label_mismatches": len(mismatches),
        "required_labels": ["secure", "insecure", "unknown"],
        "registry_sha256": _sha256(registry_file),
        "implementation_sha256": target_security_profile_producer_sha256(),
        "unknown_is_secure": False,
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
        "scientific_claim_allowed": False,
        "claim_boundary": (
            "Qualification covers only the exact target/legacy local AST producers and frozen "
            "gold idioms; it is not a global CWE-detection accuracy claim."
        ),
    }
    write_bundle(output, {"case-results.json": results, "qualification.json": report})
    return report


def qualify_prompt_tsg_extractor(
    repository_root: Path,
    tasks_path: Path,
    graph_bundle: Path,
    catalog_path: Path,
    registry_path: Path,
    gold_path: Path,
    output: Path,
    *,
    path_authority_annotations_path: Path | None = None,
) -> dict[str, Any]:
    """Replay a prospectively labeled holdout against one frozen extractor bundle."""

    root = repository_root.resolve()
    verify_bundle(graph_bundle)
    bundle_report = read_json(graph_bundle / "report.json")
    requests = _rows(read_json(graph_bundle / "requests.json"))
    graph_rows = _rows(read_json(graph_bundle / "graphs.json"))
    tasks = _rows(read_json(tasks_path))
    task_by_id = {row.get("task_id"): row for row in tasks}
    if len(task_by_id) != len(tasks) or None in task_by_id:
        raise EligibilityError("Prompt TSG qualification task identities are invalid")
    gold = read_json(gold_path)
    required = {
        "schema_version",
        "extractor_candidate_id",
        "selection_path",
        "review_completed_before_extraction",
        "arms_or_outcomes_used",
        "qualification_rule",
        "cases",
    }
    if (
        not isinstance(gold, dict)
        or set(gold) != required
        or gold["schema_version"] != "1.0"
        or gold["review_completed_before_extraction"] is not True
        or gold["arms_or_outcomes_used"] is not False
    ):
        raise EligibilityError("Prompt TSG qualification gold record is invalid")
    rule = gold["qualification_rule"]
    if (
        not isinstance(rule, dict)
        or set(rule)
        != {
            "minimum_exact_context_accuracy",
            "minimum_present_recall",
            "maximum_false_positive_present",
            "maximum_wrong_realization",
        }
        or type(rule["minimum_exact_context_accuracy"]) is not float
        or not 0 < rule["minimum_exact_context_accuracy"] <= 1
        or type(rule["minimum_present_recall"]) is not float
        or not 0 < rule["minimum_present_recall"] <= 1
        or type(rule["maximum_false_positive_present"]) is not int
        or rule["maximum_false_positive_present"] < 0
        or type(rule["maximum_wrong_realization"]) is not int
        or rule["maximum_wrong_realization"] < 0
    ):
        raise EligibilityError("Prompt TSG qualification rule is invalid")
    selection_path = (root / gold["selection_path"]).resolve()
    try:
        selection_path.relative_to(root)
    except ValueError:
        raise EligibilityError("Prompt TSG qualification selection escapes the repository") from None
    selection = read_json(selection_path)
    cases = _rows(gold["cases"])
    case_ids = [row.get("task_id") for row in cases]
    if (
        case_ids != selection.get("task_ids")
        or bundle_report.get("task_selection_sha256") != _sha256(selection_path)
        or bundle_report.get("task_file_sha256") != _sha256(tasks_path)
        or bundle_report.get("status") != "PROMPT_TSG_EXTRACTION_COMPLETE"
        or bundle_report.get("arms_or_outcomes_used") is not False
    ):
        raise EligibilityError("Prompt TSG qualification inputs do not match the extraction")
    path_authority_annotations: dict[str, dict[str, Any]] = {}
    path_authority_protocol_id = None
    if path_authority_annotations_path is not None:
        from prompt_mechanism_study.prompt_tsg_extract import (
            PromptTSGExtractionError,
            _load_path_authority_annotations,
        )

        selected_tasks = [task_by_id[task_id] for task_id in case_ids]
        try:
            path_authority_annotations = _load_path_authority_annotations(
                path_authority_annotations_path,
                tasks_path=tasks_path,
                tasks=selected_tasks,
            )
        except PromptTSGExtractionError as error:
            raise EligibilityError(str(error)) from None
        annotation_bundle = read_json(path_authority_annotations_path)
        path_authority_protocol_id = annotation_bundle["annotation_protocol_id"]
        if (
            bundle_report.get("path_authority_annotation_sha256")
            != _sha256(path_authority_annotations_path)
            or bundle_report.get("path_authority_protocol_id")
            != path_authority_protocol_id
            or bundle_report.get("path_authority_annotated_tasks")
            != len(path_authority_annotations)
        ):
            raise EligibilityError(
                "Prompt TSG path-authority evidence does not match the extraction"
            )
    elif bundle_report.get("path_authority_annotated_tasks") not in {None, 0}:
        raise EligibilityError(
            "Prompt TSG qualification requires the extraction's path-authority annotations"
        )
    if "+" in gold["extractor_candidate_id"] and (
        bundle_report.get("semantic_reviewed_tasks") != len(cases)
        or not isinstance(bundle_report.get("semantic_reviewer_evaluator_sha256"), str)
        or not isinstance(bundle_report.get("semantic_reviewer_prompt_sha256"), str)
        or len(requests) != len(cases)
        or any(
            not isinstance(request.get("semantic_review_request"), dict)
            or not isinstance(request.get("semantic_review_projection"), dict)
            for request in requests
        )
    ):
        raise EligibilityError("Prompt TSG semantic review evidence is not exactly closed")

    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    graph_by_id = {
        graph.task_id: graph
        for row in graph_rows
        for graph in (prompt_tsg_from_record(row),)
    }
    if set(graph_by_id) != set(case_ids) or len(graph_by_id) != len(graph_rows):
        raise EligibilityError("Prompt TSG qualification graph population differs from gold")
    results = []
    for case in cases:
        if set(case) != {
            "task_id",
            "expected_context",
            "expected_realization_id",
            "rationale",
        } or case["expected_context"] not in {
            "present",
            "absent",
            "unresolved",
            "absent_or_unresolved",
        }:
            raise EligibilityError("Prompt TSG qualification case is invalid")
        task = task_by_id.get(case["task_id"])
        if task is None:
            raise EligibilityError("Prompt TSG qualification task is missing")
        graph = graph_by_id[case["task_id"]]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        expected_extractor_id = gold["extractor_candidate_id"]
        if case["task_id"] in path_authority_annotations:
            expected_extractor_id = (
                f"{expected_extractor_id}+{path_authority_protocol_id}"
            )
        if graph.extractor_id != expected_extractor_id:
            raise EligibilityError("Prompt TSG extractor candidate identity drifted")
        binding = tsg_mechanism_binding(task, graph, catalog, registry)
        actual_context = (
            "present"
            if binding["realization_id"] is not None
            else "unresolved"
            if binding["decision"] == "unresolved"
            else "absent"
        )
        context_matched = actual_context == case["expected_context"] or (
            case["expected_context"] == "absent_or_unresolved"
            and actual_context in {"absent", "unresolved"}
        )
        matched = context_matched and (
            binding["realization_id"] == case["expected_realization_id"]
        )
        results.append(
            {
                "task_id": case["task_id"],
                "expected_context": case["expected_context"],
                "actual_context": actual_context,
                "expected_realization_id": case["expected_realization_id"],
                "actual_realization_id": binding["realization_id"],
                "binding_decision": binding["decision"],
                "matched": matched,
            }
        )
    mismatches = [row for row in results if not row["matched"]]
    expected_present = [row for row in results if row["expected_context"] == "present"]
    present_recovered = [
        row
        for row in expected_present
        if row["actual_context"] == "present"
        and row["actual_realization_id"] == row["expected_realization_id"]
    ]
    false_positive_present = [
        row
        for row in results
        if row["expected_context"] != "present" and row["actual_context"] == "present"
    ]
    wrong_realization = [
        row
        for row in results
        if row["actual_realization_id"] is not None
        and row["actual_realization_id"] != row["expected_realization_id"]
    ]
    exact_accuracy = (len(results) - len(mismatches)) / len(results)
    present_recall = len(present_recovered) / len(expected_present)
    qualified = (
        exact_accuracy >= rule["minimum_exact_context_accuracy"]
        and present_recall >= rule["minimum_present_recall"]
        and len(false_positive_present) <= rule["maximum_false_positive_present"]
        and len(wrong_realization) <= rule["maximum_wrong_realization"]
    )
    positive_gold_realization_ids = sorted(
        {
            row["expected_realization_id"]
            for row in cases
            if row["expected_context"] == "present"
        }
    )
    catalog_realization_ids = sorted(
        {query["realization_id"] for query in catalog["queries"]}
    )
    projections = [request.get("deterministic_projection", {}) for request in requests]
    report = {
        "schema_version": "1.0",
        "status": "QUALIFIED_FOR_FORMAL_EXTRACTION" if qualified else "QUALIFICATION_FAILED",
        "extractor_candidate_id": gold["extractor_candidate_id"],
        "holdout_task_units": len(cases),
        "matched_task_units": len(cases) - len(mismatches),
        "mismatched_task_units": len(mismatches),
        "exact_context_accuracy": round(exact_accuracy, 6),
        "present_recall": round(present_recall, 6),
        "false_positive_present": len(false_positive_present),
        "wrong_realization": len(wrong_realization),
        "qualification_rule": rule,
        "positive_gold_realization_ids": positive_gold_realization_ids,
        "catalog_realization_ids_without_positive_gold": sorted(
            set(catalog_realization_ids) - set(positive_gold_realization_ids)
        ),
        "context_counts": dict(
            sorted(Counter(row["expected_context"] for row in cases).items())
        ),
        "rejected_descriptive_facts": sum(
            len(row.get("rejected_facts", [])) for row in projections
        ),
        "rejected_relations": sum(
            len(row.get("rejected_relations", [])) for row in projections
        ),
        "ignored_unresolved_features": sum(
            len(row.get("ignored_unresolved_features", [])) for row in projections
        ),
        "extractor_bundle_sha256": bundle_digest(graph_bundle),
        "extractor_implementation_sha256": bundle_report[
            "extractor_implementation_sha256"
        ],
        "semantic_reviewer_evaluator_sha256": bundle_report.get(
            "semantic_reviewer_evaluator_sha256"
        ),
        "semantic_reviewer_prompt_sha256": bundle_report.get(
            "semantic_reviewer_prompt_sha256"
        ),
        "path_authority_annotation_sha256": bundle_report.get(
            "path_authority_annotation_sha256"
        ),
        "path_authority_protocol_id": path_authority_protocol_id,
        "path_authority_annotated_tasks": len(path_authority_annotations),
        "catalog_sha256": _sha256(catalog_path),
        "registry_sha256": _sha256(registry_path),
        "gold_sha256": _sha256(gold_path),
        "selection_sha256": _sha256(selection_path),
        "arms_or_outcomes_used": False,
        "claim_boundary": (
            "Qualification covers the prospectively labeled task-context holdout and, "
            "if passed, only realization IDs represented by expected-present gold cases; "
            "it is not a global semantic-parsing accuracy claim."
        ),
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
        "source_tasks_sha256": _sha256(tasks_path),
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
        "source_tasks_sha256": _sha256(tasks_path),
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
        exclusion_hashes.append({"path": path.as_posix(), "sha256": _sha256(path)})
    return excluded, exclusion_hashes


def freeze_tsg_realization_bindings(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    contracts_root: Path,
    catalog_path: Path,
    registry_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Bind curated task units to a local Oracle using only frozen task evidence."""

    if output.exists():
        raise EligibilityError("realization-binding output already exists")
    verify_bundle(contracts_root)
    tasks = _rows(read_json(tasks_path))
    if not tasks or len({row.get("task_unit_id") for row in tasks}) != len(tasks):
        raise EligibilityError("realization-binding tasks are empty or duplicated")
    if any(
        row.get("task_id") != row.get("task_unit_id")
        or not isinstance(row.get("record_id"), str)
        for row in tasks
    ):
        raise EligibilityError("realization-binding task coordinates are invalid")

    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    query_realizations = {row["realization_id"] for row in catalog["queries"]}
    if set(registry) != query_realizations:
        raise EligibilityError("mechanism registry and Prompt TSG queries differ")
    contracts = {
        row["cluster_id"]: row
        for row in _rows(read_json(contracts_root / "functional-contracts.json"))
    }
    task_ids = {row["task_unit_id"] for row in tasks}
    if not task_ids <= set(contracts):
        raise EligibilityError("contracts do not cover every realization-binding task")

    graph_records: list[dict[str, Any]] = []
    graph_bundle_sha256s = []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_bundle_sha256s.append(bundle_digest(bundle))
        graph_records.extend(_rows(read_json(bundle / "graphs.json")))
    graphs = {
        graph.task_id: graph
        for row in graph_records
        for graph in (prompt_tsg_from_record(row),)
    }
    if len(graphs) != len(graph_records) or set(graphs) != task_ids:
        raise EligibilityError("Prompt TSGs do not exactly cover realization-binding tasks")

    decisions = []
    for task in sorted(tasks, key=lambda row: row["task_unit_id"]):
        graph = graphs[task["task_unit_id"]]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        binding = tsg_mechanism_binding(task, graph, catalog, registry)
        realization_id = binding["realization_id"]
        profile_id = (
            None if realization_id is None else registry[realization_id]["oracle_profile_id"]
        )
        if realization_id is None:
            decision = "not_applicable"
            reason = (
                "tsg_context_unresolved"
                if binding["decision"] == "unresolved"
                else "tsg_context_not_present"
            )
        elif profile_id not in TARGET_LOCAL_PROFILE_IDS:
            decision = "contextual_oracle_required"
            reason = "local_security_oracle_not_qualified"
        else:
            decision = "profile_candidate"
            reason = "locally_measurable_tsg_context"
        contract = contracts[task["task_unit_id"]]
        core = {
            "cluster_id": task["task_unit_id"],
            "representative_record_id": task["record_id"],
            "contract_id": contract["contract_id"],
            "primary_cwe": task["cwe"],
            "decision": decision,
            "realization_id": realization_id,
            "proposed_oracle_profile_id": profile_id,
            "reason_code": reason,
            "prompt_tsg_binding": binding,
            "outcomes_or_arms_used": False,
        }
        decisions.append(core)

    report = {
        "schema_version": "1.0",
        "status": "TSG_REALIZATION_BINDINGS_FROZEN",
        "task_units": len(tasks),
        "decision_counts": dict(sorted(Counter(row["decision"] for row in decisions).items())),
        "realization_counts": dict(
            sorted(
                Counter(
                    row["realization_id"]
                    for row in decisions
                    if row["realization_id"] is not None
                ).items()
            )
        ),
        "catalog_sha256": _sha256(catalog_path),
        "mechanism_registry_sha256": _sha256(registry_path),
        "contracts_bundle_sha256": bundle_digest(contracts_root),
        "prompt_tsg_bundle_sha256s": graph_bundle_sha256s,
        "local_security_profiles_sha256": _sha256(Path(__file__).with_name("security_profiles.py")),
        "outcomes_or_arms_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {"binding-decisions.json": decisions, "report.json": report},
    )
    return report


def audit_dataset_eligibility(
    repository_root: Path,
    prepared_root: Path,
    clusters_root: Path,
    contracts_root: Path,
    output: Path,
    *,
    policy_path: Path | None = None,
    bindings_root: Path | None = None,
    contract_reviews_root: Path | None = None,
    development_exclusions_path: Path | None = None,
    case_audit_path: Path | None = None,
    extension_policy_path: Path | None = None,
    backend_root: Path | None = None,
) -> dict[str, Any]:
    """Classify every semantic cluster without generated-code outcomes."""

    root = repository_root.resolve()
    prepared = prepared_root.resolve()
    clusters = clusters_root.resolve()
    contracts = contracts_root.resolve()
    bindings = None if bindings_root is None else bindings_root.resolve()
    reviews = None if contract_reviews_root is None else contract_reviews_root.resolve()
    destination = output.resolve()
    if destination.exists():
        raise EligibilityError("eligibility output already exists")
    for bundle in (prepared, clusters, contracts):
        verify_bundle(bundle)
    if bindings is not None:
        verify_bundle(bindings)
    if reviews is not None:
        verify_bundle(reviews)

    policy_file = (
        policy_path or root / "data/dataset-curation/eligibility-policy-v1.json"
    ).resolve()
    policy = _policy(read_json(policy_file))
    registry_file = (root / policy["mechanism_registry_path"]).resolve()
    qualification_file = (root / policy["functional_oracle_qualification_path"]).resolve()
    security_qualification_file = (
        root / policy["security_oracle_qualification_path"]
    ).resolve()
    if (
        not registry_file.is_file()
        or not qualification_file.is_file()
        or not security_qualification_file.is_file()
    ):
        raise EligibilityError("eligibility policy references a missing artifact")
    registry = load_mechanism_registry(registry_file)
    qualification = read_json(qualification_file)
    if qualification.get("status") != "QUALIFIED_FOR_EXPERIMENT":
        raise EligibilityError("functional Oracle is not qualified")
    security_qualification = read_json(security_qualification_file)
    qualification_status = security_qualification.get("status")
    expected_security_implementation = (
        target_security_profile_producer_sha256()
        if qualification_status == "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
        else _sha256(root / "src/prompt_mechanism_study/security_profiles.py")
    )
    if (
        qualification_status
        not in {"QUALIFIED_FOR_EXPERIMENT", "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"}
        or security_qualification.get("registry_sha256") != _sha256(registry_file)
        or security_qualification.get("implementation_sha256")
        != expected_security_implementation
    ):
        raise EligibilityError("security Oracle qualification is invalid or stale")

    records = {row["record_id"]: row for row in _rows(read_json(prepared / "records.json"))}
    cluster_rows = _rows(read_json(clusters / "semantic-clusters.json"))
    contract_rows = {
        row["cluster_id"]: row for row in _rows(read_json(contracts / "functional-contracts.json"))
    }
    if len(contract_rows) != len(cluster_rows) or set(contract_rows) != {
        row["cluster_id"] for row in cluster_rows
    }:
        raise EligibilityError("cluster and functional-contract populations differ")

    review_rows = _contract_review_rows(
        reviews,
        contracts,
        cluster_rows,
        contract_rows,
    )
    development_exclusions = _task_unit_ids(development_exclusions_path)
    case_flags = _case_audit_flags(case_audit_path)
    task_unit_population = set(contract_rows)
    if not development_exclusions <= task_unit_population or not set().union(
        *case_flags.values()
    ) <= task_unit_population:
        raise EligibilityError("review exclusion or case-audit id is outside the population")
    extension_file = (
        extension_policy_path
        or root / "data/dataset-curation/priority-extension-policy-v1.json"
    ).resolve()
    extension_policy = read_json(extension_file)

    layers = {
        (language, cwe): row["layer_id"]
        for row in policy["layers"]
        for language in row["languages"]
        for cwe in row["cwes"]
    }
    mechanisms_by_cwe: dict[str, list[dict[str, Any]]] = {}
    for mechanism in registry.values():
        mechanisms_by_cwe.setdefault(mechanism["cwe_id"], []).append(mechanism)
    binding_rows = (
        {}
        if bindings is None
        else _binding_rows(read_json(bindings / "binding-decisions.json"))
    )

    decisions = []
    for cluster in sorted(cluster_rows, key=lambda row: row["cluster_id"]):
        representative = records[cluster["representative_record_id"]]
        contract = contract_rows[cluster["cluster_id"]]
        members = [records[record_id] for record_id in cluster["record_ids"]]
        primary_cwe = representative["cwe"]
        language = representative["language"]
        layer = layers.get((language, primary_cwe))
        binding = binding_rows.get(cluster["cluster_id"])
        if binding is None:
            mechanism, mechanism_reason = _mechanism_for_prompt(
                representative["prompt"], mechanisms_by_cwe.get(primary_cwe, [])
            )
        else:
            mechanism, mechanism_reason = _mechanism_from_binding(
                binding,
                representative,
                contract,
                registry,
                contract_lineage_ids={
                    contract["contract_id"],
                    review_rows.get(cluster["cluster_id"], {}).get(
                        "contract_id", contract["contract_id"]
                    ),
                },
            )
        contract_complete = bool(
            contract.get("resolution_status") == "resolved" and contract.get("requirements")
        )
        if layer is None:
            status, reason = "excluded", "outside_frozen_study_layers"
        elif not contract_complete:
            status, reason = "excluded", "functional_contract_incomplete"
        elif cluster["cwe_label_conflict"]:
            status, reason = "calibration_only", "cwe_label_conflict"
        elif layer != policy["active_layer"]:
            status, reason = "calibration_only", "replication_runtime_not_implemented"
        elif language not in policy["functional_oracle_languages"]:
            status, reason = "calibration_only", "functional_oracle_language_not_supported"
        elif language not in policy["security_oracle_languages"]:
            status, reason = "calibration_only", "security_oracle_language_not_supported"
        elif mechanism is None:
            status, reason = "calibration_only", mechanism_reason
        else:
            status, reason = "eligible", "ready_for_python_confirmatory_sampling"

        test_references = sorted(
            {
                reference
                for member in members
                for reference in member.get("source_test_references", [])
            }
        )
        core = {
            "cluster_id": cluster["cluster_id"],
            "representative_record_id": representative["record_id"],
            "representative_source": representative["source_dataset"],
            "representative_lineage_family": representative["source_lineage_family"],
            "source_lineage_families": sorted(
                {member["source_lineage_family"] for member in members}
            ),
            "language": language,
            "primary_cwe": primary_cwe,
            "cluster_cwes": cluster["cwes"],
            "layer": layer,
            "status": status,
            "reason": reason,
            "contract_id": contract["contract_id"],
            "requirement_count": len(contract.get("requirements", [])),
            "entrypoint_present": contract.get("entrypoint") is not None,
            "source_test_available": bool(test_references),
            "source_test_reference_count": len(test_references),
            "mechanism_realization_id": None if mechanism is None else mechanism["realization_id"],
            "oracle_profile_id": None if mechanism is None else mechanism["oracle_profile_id"],
        }
        decisions.append({"eligibility_id": content_id("eligibility_", core), **core})

    extensions = _priority_extension_rows(decisions, extension_policy)
    extension_by_cluster = {row["cluster_id"]: row for row in extensions}
    active_profiles = set(security_qualification["active_local_profiles"])
    candidate_ledger = []
    for row in decisions:
        cluster_id = row["cluster_id"]
        review = review_rows.get(cluster_id)
        quality, quality_blockers = _contract_quality(review)
        blockers = list(quality_blockers)
        if cluster_id in development_exclusions:
            blockers.append("development_exposed")
        if cluster_id in case_flags["material_contract_fault"]:
            blockers.append("known_material_contract_fault")
        if cluster_id in case_flags["scope_or_evaluability_concern"]:
            blockers.append("known_scope_or_evaluability_concern")
        if cluster_id in case_flags["repair_metadata"]:
            blockers.append("metadata_repair_required")
        if cluster_id in case_flags["semantic_calibration"]:
            blockers.append("semantic_calibration_required")
        if cluster_id in case_flags["source_defect"]:
            blockers.append("source_prompt_incoherent")

        extension = extension_by_cluster.get(cluster_id)
        profile_id = row["oracle_profile_id"]
        if profile_id in active_profiles:
            oracle_support = "SUPPORTED"
            oracle_type = "DETERMINISTIC_STATIC_PROFILE"
        elif profile_id is not None:
            oracle_support = "UNSUPPORTED"
            oracle_type = "CONTEXTUAL_ORACLE_REQUIRED"
        else:
            oracle_support = "PENDING"
            oracle_type = None
        binding_status = _binding_status(row)
        runtime_status = "SUPPORTED" if row["language"] == "python" else "PENDING"
        if row["source_test_available"]:
            functional_measurement = "SOURCE_TEST_REFERENCE_AVAILABLE"
        elif row["language"] == "python":
            functional_measurement = "AST_COMPILE_AND_BLIND_LLM_PLAUSIBILITY"
        else:
            functional_measurement = "PENDING_RUNTIME_FUNCTIONAL_TEST"
        readiness = _candidate_readiness(
            row,
            quality,
            blockers,
            extension,
            oracle_support,
            runtime_status,
        )
        final_dataset_status = _final_dataset_status(
            quality,
            blockers,
            policy["final_dataset_admission"],
        )
        if readiness.startswith("PENDING_"):
            blockers.append(readiness.casefold())
        ledger_core = {
            "task_unit_id": cluster_id,
            "representative_record_id": row["representative_record_id"],
            "source_dataset": row["representative_source"],
            "source_lineage_family": row["representative_lineage_family"],
            "language": row["language"],
            "primary_cwe": row["primary_cwe"],
            "study_layer": row["layer"],
            "eligibility_reason": row["reason"],
            "contract_id": row["contract_id"],
            "contract_quality": quality,
            "review_contract_status": None if review is None else review["contract_status"],
            "functional_evaluability": (
                None if review is None else review["functional_evaluability"]
            ),
            "functional_measurement": functional_measurement,
            "source_test_available": row["source_test_available"],
            "source_test_reference_count": row["source_test_reference_count"],
            "mechanism_binding_status": binding_status,
            "mechanism_realization_id": row["mechanism_realization_id"],
            "oracle_profile_id": profile_id,
            "oracle_type": oracle_type,
            "oracle_support_status": oracle_support,
            "runtime_support_status": runtime_status,
            "priority_extension_tier": (
                None if extension is None else extension["priority_tier"]
            ),
            "priority_extension_family": (
                None if extension is None else extension["extension_family"]
            ),
            "candidate_status": readiness,
            "final_dataset_status": final_dataset_status,
            "blocker_codes": sorted(set(blockers)),
            "arms_or_outcomes_used": False,
        }
        candidate_ledger.append(
            {"candidate_record_id": content_id("candidate_record_", ledger_core), **ledger_core}
        )

    statuses = Counter(row["status"] for row in decisions)
    reasons = Counter(row["reason"] for row in decisions)
    eligible = [row for row in decisions if row["status"] == "eligible"]
    family_rows = []
    for family in policy["python_families"]:
        members = [row for row in eligible if row["primary_cwe"] in family["cwes"]]
        lineages = sorted({row["representative_lineage_family"] for row in members})
        family_rows.append(
            {
                "family_id": family["family_id"],
                "eligible_clusters": len(members),
                "target_clusters": family["target_clusters"],
                "eligible_lineages": len(lineages),
                "cluster_target_met": len(members) >= family["target_clusters"],
            }
        )
    lineage_counts = Counter(row["representative_lineage_family"] for row in eligible)
    ready_confirmatory = [
        row for row in candidate_ledger if row["candidate_status"] == "READY_CONFIRMATORY"
    ]
    final_dataset = [
        row
        for row in candidate_ledger
        if row["final_dataset_status"] == "INCLUDED_FINAL_DATASET"
    ]
    candidate_statuses = Counter(row["candidate_status"] for row in candidate_ledger)
    final_dataset_statuses = Counter(
        row["final_dataset_status"] for row in candidate_ledger
    )
    contract_qualities = Counter(row["contract_quality"] for row in candidate_ledger)
    blocker_counts = Counter(
        blocker for row in candidate_ledger for blocker in row["blocker_codes"]
    )
    oracle_profile_rows = _oracle_profile_rows(
        security_qualification,
        decisions,
        registry,
    )
    memory_replication = _memory_replication_rows(candidate_ledger)
    backend_replication = _backend_candidate_rows(backend_root)
    oracle_profile_rows.extend(_backend_oracle_profile_rows(backend_replication))
    ready_family_rows = []
    for family in policy["python_families"]:
        members = [row for row in ready_confirmatory if row["primary_cwe"] in family["cwes"]]
        lineages = sorted({row["source_lineage_family"] for row in members})
        ready_family_rows.append(
            {
                "family_id": family["family_id"],
                "ready_task_units": len(members),
                "target_task_units": family["target_clusters"],
                "ready_lineages": len(lineages),
                "task_target_met": len(members) >= family["target_clusters"],
            }
        )
    ready_lineage_counts = Counter(row["source_lineage_family"] for row in ready_confirmatory)
    report = {
        "schema_version": "1.2",
        "status": "DATASET_ELIGIBILITY_AUDIT_COMPLETE",
        "cluster_count": len(decisions),
        "candidate_ledger_complete": len(candidate_ledger) == len(decisions),
        "status_counts": dict(sorted(statuses.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "candidate_status_counts": dict(sorted(candidate_statuses.items())),
        "final_dataset_status_counts": dict(sorted(final_dataset_statuses.items())),
        "final_dataset_task_units": len(final_dataset),
        "final_dataset_language_counts": dict(
            sorted(Counter(row["language"] for row in final_dataset).items())
        ),
        "final_dataset_source_counts": dict(
            sorted(Counter(row["source_dataset"] for row in final_dataset).items())
        ),
        "final_dataset_admission": policy["final_dataset_admission"],
        "contract_quality_counts": dict(sorted(contract_qualities.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "ready_confirmatory_task_units": len(ready_confirmatory),
        "eligible_cwe_counts": dict(
            sorted(Counter(row["primary_cwe"] for row in eligible).items())
        ),
        "eligible_source_counts": dict(
            sorted(Counter(row["representative_source"] for row in eligible).items())
        ),
        "eligible_lineage_counts": dict(sorted(lineage_counts.items())),
        "python_family_gate": family_rows,
        "ready_python_family_gate": ready_family_rows,
        "prospective_python_cluster_target": sum(
            row["target_clusters"] for row in policy["python_families"]
        ),
        "python_population_gate_passed": all(
            row["task_target_met"] for row in ready_family_rows
        ),
        "lineage_policy": policy["lineage_policy"],
        "largest_eligible_lineage_fraction": _largest_fraction(lineage_counts),
        "largest_ready_lineage_fraction": _largest_fraction(ready_lineage_counts),
        "ready_lineage_counts": dict(sorted(ready_lineage_counts.items())),
        "eligible_with_source_tests": sum(row["source_test_available"] for row in eligible),
        "ready_with_source_tests": sum(
            row["source_test_available"] for row in ready_confirmatory
        ),
        "priority_extension_counts": dict(
            sorted(Counter(row["priority_tier"] for row in extensions).items())
        ),
        "memory_replication_candidate_task_units": len(memory_replication),
        "memory_replication_by_cwe": dict(
            sorted(Counter(row["primary_cwe"] for row in memory_replication).items())
        ),
        "memory_replication_with_source_tests": sum(
            row["source_test_available"] for row in memory_replication
        ),
        "memory_replication_data_gate_passed": all(
            sum(row["primary_cwe"] == cwe for row in memory_replication) >= 4
            for cwe in _MEMORY_REPLICATION_CWES
        ),
        "memory_replication_runtime_gate_passed": False,
        "backend_replication_candidate_task_units": len(backend_replication),
        "backend_replication_data_gate_passed": len(backend_replication) == 28,
        "backend_replication_runtime_gate_passed": False,
        "prepared_bundle_sha256": bundle_digest(prepared),
        "clusters_bundle_sha256": bundle_digest(clusters),
        "contracts_bundle_sha256": bundle_digest(contracts),
        "policy_sha256": _sha256(policy_file),
        "mechanism_registry_sha256": _sha256(registry_file),
        "local_security_profiles_sha256": security_qualification[
            "implementation_sha256"
        ],
        "functional_oracle_qualification_sha256": _sha256(qualification_file),
        "security_oracle_qualification_sha256": _sha256(
            security_qualification_file
        ),
        "realization_binding_bundle_sha256": (
            None if bindings is None else bundle_digest(bindings)
        ),
        "contract_review_bundle_sha256": (
            None if reviews is None else bundle_digest(reviews)
        ),
        "development_exclusions_sha256": (
            None
            if development_exclusions_path is None
            else _sha256(development_exclusions_path.resolve())
        ),
        "case_audit_sha256": (
            None if case_audit_path is None else _sha256(case_audit_path.resolve())
        ),
        "priority_extension_policy_sha256": _sha256(extension_file),
        "eligibility_implementation_sha256": _sha256(
            root / "src/prompt_mechanism_study/eligibility.py"
        ),
        "backend_source_tree_sha256": (
            None if backend_root is None else _source_tree_sha256(backend_root.resolve())
        ),
        "generated_code_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        destination,
        {
            "eligibility-decisions.json": decisions,
            "eligible-clusters.json": eligible,
            "calibration-only-clusters.json": [
                row for row in decisions if row["status"] == "calibration_only"
            ],
            "excluded-clusters.json": [row for row in decisions if row["status"] == "excluded"],
            "candidate-ledger.json": candidate_ledger,
            "final-dataset.json": final_dataset,
            "ready-confirmatory-task-units.json": ready_confirmatory,
            "priority-extension-candidates.json": extensions,
            "oracle-profile-summary.json": oracle_profile_rows,
            "memory-replication-candidates.json": memory_replication,
            "backend-replication-candidates.json": backend_replication,
            "blocker-summary.json": [
                {"blocker_code": blocker, "task_units": count}
                for blocker, count in sorted(blocker_counts.items())
            ],
            "report.json": report,
        },
    )
    return report


def apply_binding_adjudications(
    prepared_root: Path,
    clusters_root: Path,
    bindings_root: Path,
    registry_path: Path,
    adjudications_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Apply bounded, outcome-blind corrections to unresolved binding rows."""

    prepared = prepared_root.resolve()
    clusters = clusters_root.resolve()
    bindings = bindings_root.resolve()
    registry_file = registry_path.resolve()
    destination = output.resolve()
    if destination.exists():
        raise EligibilityError("binding adjudication output already exists")
    for bundle in (prepared, clusters, bindings):
        verify_bundle(bundle)
    adjudications = read_json(adjudications_path.resolve())
    required = {
        "schema_version",
        "adjudication_id",
        "source_binding_bundle_sha256",
        "prepared_bundle_sha256",
        "clusters_bundle_sha256",
        "mechanism_registry_sha256",
        "reviewer_type",
        "arms_or_outcomes_used",
        "decisions",
    }
    if (
        not isinstance(adjudications, dict)
        or set(adjudications) != required
        or adjudications["schema_version"] != "1.0"
        or adjudications["arms_or_outcomes_used"] is not False
        or adjudications["source_binding_bundle_sha256"] != bundle_digest(bindings)
        or adjudications["prepared_bundle_sha256"] != bundle_digest(prepared)
        or adjudications["clusters_bundle_sha256"] != bundle_digest(clusters)
        or adjudications["mechanism_registry_sha256"] != _sha256(registry_file)
    ):
        raise EligibilityError("binding adjudication provenance is invalid")

    records = {
        row["record_id"]: row
        for row in _rows(read_json(prepared / "records.json"))
    }
    cluster_rows = {
        row["cluster_id"]: row
        for row in _rows(read_json(clusters / "semantic-clusters.json"))
    }
    source_rows = _rows(read_json(bindings / "binding-decisions.json"))
    source_by_id = _binding_rows(source_rows)
    registry = load_mechanism_registry(registry_file)
    decisions = _rows(adjudications["decisions"])
    decision_ids = [row.get("cluster_id") for row in decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise EligibilityError("binding adjudication ids are duplicated")

    corrected = dict(source_by_id)
    applied_counts: Counter[str] = Counter()
    for adjudication in decisions:
        if set(adjudication) != {
            "cluster_id",
            "decision",
            "realization_id",
            "evidence_text",
            "reason",
        }:
            raise EligibilityError("binding adjudication row fields are invalid")
        cluster_id = adjudication["cluster_id"]
        source = source_by_id.get(cluster_id)
        cluster = cluster_rows.get(cluster_id)
        if (
            source is None
            or cluster is None
            or source["decision"] != "not_applicable"
            or source["reason_code"] != "mechanism_realization_not_resolved"
            or not isinstance(adjudication["reason"], str)
            or not adjudication["reason"].strip()
        ):
            raise EligibilityError("binding adjudication is not an unresolved source row")
        representative = records[cluster["representative_record_id"]]
        if source["representative_record_id"] != representative["record_id"]:
            raise EligibilityError("binding adjudication representative drifted")
        if adjudication["decision"] == "retain_unresolved":
            if (
                adjudication["realization_id"] is not None
                or adjudication["evidence_text"] is not None
            ):
                raise EligibilityError("unresolved binding adjudication must not name evidence")
            corrected[cluster_id] = {
                **source,
                "adjudication_id": adjudications["adjudication_id"],
                "adjudication_reason": adjudication["reason"],
            }
        elif adjudication["decision"] == "bind_existing":
            realization_id = adjudication["realization_id"]
            evidence_text = adjudication["evidence_text"]
            mechanism = registry.get(realization_id)
            if (
                mechanism is None
                or mechanism["cwe_id"] != source["primary_cwe"]
                or not isinstance(evidence_text, str)
                or representative["prompt"].count(evidence_text) != 1
            ):
                raise EligibilityError("binding adjudication evidence or realization is invalid")
            corrected[cluster_id] = {
                **source,
                "decision": "profile_candidate",
                "evidence_normalization": "exact_adjudicated_v1",
                "evidence_occurrence": 1,
                "evidence_text": evidence_text,
                "realization_id": realization_id,
                "proposed_oracle_profile_id": mechanism["oracle_profile_id"],
                "reason_code": "outcome_blind_binding_adjudication",
                "adjudication_id": adjudications["adjudication_id"],
                "adjudication_reason": adjudication["reason"],
            }
        else:
            raise EligibilityError("binding adjudication decision is invalid")
        applied_counts[adjudication["decision"]] += 1

    corrected_rows = [corrected[row["cluster_id"]] for row in source_rows]
    report = {
        "schema_version": "1.0",
        "status": "BINDING_ADJUDICATION_COMPLETE",
        "source_binding_rows": len(source_rows),
        "adjudicated_rows": len(decisions),
        "decision_counts": dict(sorted(applied_counts.items())),
        "adjudicated_remaining_unresolved_rows": applied_counts["retain_unresolved"],
        "profile_candidate_rows": sum(
            row["decision"] == "profile_candidate" for row in corrected_rows
        ),
        "remaining_unresolved_rows": sum(
            row["reason_code"] == "mechanism_realization_not_resolved"
            and row["decision"] == "not_applicable"
            for row in corrected_rows
        ),
        "source_binding_bundle_sha256": bundle_digest(bindings),
        "prepared_bundle_sha256": bundle_digest(prepared),
        "clusters_bundle_sha256": bundle_digest(clusters),
        "mechanism_registry_sha256": _sha256(registry_file),
        "adjudications_sha256": _sha256(adjudications_path.resolve()),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        destination,
        {
            "binding-decisions.json": corrected_rows,
            "adjudication-decisions.json": decisions,
            "report.json": report,
        },
    )
    return report


def _contract_review_rows(
    reviews: Path | None,
    contracts: Path,
    cluster_rows: list[dict[str, Any]],
    contract_rows: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if reviews is None:
        return {}
    rows = _rows(read_json(reviews / "contract-quality-reviews.json"))
    by_cluster = {row.get("cluster_id"): row for row in rows}
    population = {row["cluster_id"] for row in cluster_rows}
    if len(by_cluster) != len(rows) or set(by_cluster) != population:
        raise EligibilityError("contract reviews do not exactly cover the task-unit population")

    repairs_path = contracts / "repairs.json"
    repair_rows = [] if not repairs_path.is_file() else _rows(read_json(repairs_path))
    repairs = {row["cluster_id"]: row for row in repair_rows}
    if len(repairs) != len(repair_rows):
        raise EligibilityError("contract repair lineage contains duplicate task units")
    overrides_path = contracts / "review-overrides.json"
    override_rows = [] if not overrides_path.is_file() else _rows(read_json(overrides_path))
    overrides = {row.get("cluster_id"): row for row in override_rows}
    if len(overrides) != len(override_rows) or not set(overrides) <= population:
        raise EligibilityError("contract review overrides contain invalid task units")
    augmented = {}
    for cluster_id in sorted(population):
        review = by_cluster[cluster_id]
        current = contract_rows[cluster_id]
        if review.get("record_id") != current.get("record_id"):
            raise EligibilityError("contract review record binding is stale")
        repair = repairs.get(cluster_id)
        if repair is None:
            if review.get("contract_id") != current.get("contract_id"):
                raise EligibilityError("contract review does not bind the current contract")
            remaining = list(review.get("deterministic_issue_codes", []))
        else:
            repair_codes = repair.get("repair_codes")
            if repair_codes is None and isinstance(repair.get("repair_code"), str):
                repair_codes = [repair["repair_code"]]
            if (
                review.get("contract_id") != repair.get("old_contract_id")
                or current.get("contract_id") != repair.get("new_contract_id")
                or current.get("record_id") != repair.get("record_id")
                or not isinstance(repair_codes, list)
                or not repair_codes
                or not set(repair_codes)
                <= {
                    "remove_response_format_instruction_v1",
                    "outcome_blind_contract_adjudication_v1",
                }
            ):
                raise EligibilityError("contract repair lineage is invalid")
            remaining = [
                code
                for code in review.get("deterministic_issue_codes", [])
                if not (
                    code == "response_format_instruction_leak"
                    and "remove_response_format_instruction_v1" in repair_codes
                )
            ]
        override = overrides.get(cluster_id)
        effective_review = review
        if override is not None:
            if (
                set(override)
                != {
                    "cluster_id",
                    "record_id",
                    "source_review_contract_id",
                    "current_contract_id",
                    "contract_status",
                    "functional_evaluability",
                    "issue_codes",
                    "adjudication_id",
                    "reason",
                }
                or override.get("record_id") != current.get("record_id")
                or override.get("source_review_contract_id") != review.get("contract_id")
                or override.get("current_contract_id") != current.get("contract_id")
                or override.get("contract_status") != "faithful"
                or override.get("functional_evaluability") != "sufficient"
                or override.get("issue_codes") != ["none"]
                or not isinstance(override.get("adjudication_id"), str)
                or not isinstance(override.get("reason"), str)
            ):
                raise EligibilityError("contract review override is invalid")
            effective_review = {
                **review,
                "contract_status": override["contract_status"],
                "functional_evaluability": override["functional_evaluability"],
                "issue_codes": override["issue_codes"],
            }
        augmented[cluster_id] = {
            **effective_review,
            "current_contract_id": current["contract_id"],
            "remaining_deterministic_issue_codes": sorted(set(remaining)),
            "repair_applied": repair is not None,
            "review_override_applied": override is not None,
        }
    return augmented


def _contract_quality(review: dict[str, Any] | None) -> tuple[str, list[str]]:
    if review is None:
        return "UNREVIEWED", ["missing_contract_review"]
    blockers = []
    if review.get("contract_status") != "faithful":
        blockers.append("contract_not_faithful")
    if review.get("functional_evaluability") != "sufficient":
        blockers.append(
            f"functional_evaluability_{review.get('functional_evaluability', 'unknown')}"
        )
    blockers.extend(review.get("remaining_deterministic_issue_codes", []))
    return ("STRICT", []) if not blockers else ("REPAIRABLE", sorted(set(blockers)))


def _task_unit_ids(path: Path | None) -> set[str]:
    if path is None:
        return set()
    value = read_json(path.resolve())
    if isinstance(value, dict):
        rows = value.get("task_unit_ids", [])
    else:
        rows = value
    if not isinstance(rows, list) or any(not isinstance(row, str) or not row for row in rows):
        raise EligibilityError("task-unit exclusion list is invalid")
    return set(rows)


def _case_audit_flags(path: Path | None) -> dict[str, set[str]]:
    flags = {
        "material_contract_fault": set(),
        "scope_or_evaluability_concern": set(),
        "repair_metadata": set(),
        "semantic_calibration": set(),
        "source_defect": set(),
    }
    if path is None:
        return flags
    value = read_json(path.resolve())
    if value.get("arms_or_outcomes_used") is not False:
        raise EligibilityError("case audit is not outcome blind")
    for row in value.get("insufficient_case_audit", {}).get("decisions", []):
        destination = {
            "repair_metadata_then_reassess": "repair_metadata",
            "exclude_as_written": "source_defect",
            "semantic_judge_calibration_candidate": "semantic_calibration",
        }.get(row.get("decision"))
        if destination is None or not isinstance(row.get("task_unit_id"), str):
            raise EligibilityError("case-audit decision is invalid")
        flags[destination].add(row["task_unit_id"])
    sample = value.get("reviewer_qualified_sample_audit", {})
    flags["material_contract_fault"].update(
        sample.get("clear_material_contract_fault_task_unit_ids", [])
    )
    flags["scope_or_evaluability_concern"].update(
        sample.get("separate_evaluability_or_scope_concern_task_unit_ids", [])
    )
    return flags


def _priority_extension_rows(
    rows: list[dict[str, Any]], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    requirements = policy.get("common_requirements", {})
    tiers = policy.get("tiers", [])
    if len(tiers) != 2 or policy.get("generated_code_or_outcomes_used") is not False:
        raise EligibilityError("priority-extension policy is invalid")
    python_tier, cross_language_tier = tiers
    family_by_cwe = {
        cwe: family
        for family, cwes in python_tier.get("families", {}).items()
        for cwe in cwes
    }
    candidates = []
    for row in rows:
        if (
            not row["source_test_available"]
            or not row["contract_id"]
            or row["requirement_count"] < requirements.get("minimum_requirements", 1)
            or row["source_test_reference_count"]
            < requirements.get("minimum_source_test_references", 1)
        ):
            continue
        family = family_by_cwe.get(row["primary_cwe"])
        if row["language"] == python_tier.get("language") and family is not None:
            tier = python_tier
        elif row["language"] in cross_language_tier.get("languages", []):
            tier = cross_language_tier
            family = None
        else:
            continue
        core = {
            "cluster_id": row["cluster_id"],
            "contract_id": row["contract_id"],
            "language": row["language"],
            "primary_cwe": row["primary_cwe"],
            "representative_record_id": row["representative_record_id"],
            "representative_source": row["representative_source"],
            "representative_lineage_family": row["representative_lineage_family"],
            "source_test_reference_count": row["source_test_reference_count"],
            "priority_tier": tier["tier_id"],
            "extension_family": family,
            "admission_blocker": tier["admission_blocker"],
            "current_formal_sample_eligible": False,
        }
        candidates.append(
            {"extension_candidate_id": content_id("extension_candidate_", core), **core}
        )
    return sorted(
        candidates,
        key=lambda row: (
            row["priority_tier"], row["language"], row["primary_cwe"], row["cluster_id"]
        ),
    )


def _binding_status(row: dict[str, Any]) -> str:
    if row["mechanism_realization_id"] is not None:
        return "BOUND"
    return {
        "mechanism_realization_ambiguous": "PENDING_BLIND_REVIEW",
        "mechanism_realization_not_resolved": "PENDING_BLIND_REVIEW",
        "mechanism_not_registered": "UNREGISTERED",
        "cwe_label_conflict": "CONFLICT",
        "outside_frozen_study_layers": "OUTSIDE_CURRENT_SCOPE",
        "replication_runtime_not_implemented": "PENDING_RUNTIME",
    }.get(row["reason"], "NOT_APPLICABLE")


def _candidate_readiness(
    row: dict[str, Any],
    contract_quality: str,
    blockers: list[str],
    extension: dict[str, Any] | None,
    oracle_support: str,
    runtime_status: str,
) -> str:
    if "source_prompt_incoherent" in blockers:
        return "EXCLUDED_SOURCE_DEFECT"
    if contract_quality != "STRICT":
        return "PENDING_CONTRACT"
    if any(
        blocker
        in {
            "development_exposed",
            "known_material_contract_fault",
            "known_scope_or_evaluability_concern",
            "metadata_repair_required",
            "semantic_calibration_required",
        }
        for blocker in blockers
    ):
        return "PENDING_INDEPENDENT_REVIEW"
    if row["status"] == "eligible":
        if oracle_support != "SUPPORTED":
            return "PENDING_ORACLE"
        if runtime_status != "SUPPORTED":
            return "PENDING_RUNTIME"
        return "READY_CONFIRMATORY"
    if row["reason"] in {
        "mechanism_realization_ambiguous",
        "mechanism_realization_not_resolved",
    }:
        return "PENDING_BINDING"
    if row["reason"] in {"mechanism_not_registered", "cwe_label_conflict"}:
        return "PENDING_ORACLE"
    if row["reason"] == "replication_runtime_not_implemented":
        return "PENDING_RUNTIME"
    if extension is not None:
        return "PENDING_ORACLE" if row["language"] == "python" else "PENDING_RUNTIME"
    return "PENDING_SCOPE"


def _final_dataset_status(
    contract_quality: str,
    blockers: list[str],
    admission_policy: dict[str, Any],
) -> str:
    """Admit by task/contract quality, independently of measurement support."""

    if "source_prompt_incoherent" in blockers:
        return "EXCLUDED_SOURCE_DEFECT"
    if contract_quality != admission_policy["required_contract_quality"]:
        return "PENDING_QUALITY_REPAIR"
    if set(blockers).intersection(admission_policy["disqualifying_quality_flags"]):
        return "PENDING_INDEPENDENT_REVIEW"
    return "INCLUDED_FINAL_DATASET"


def _oracle_profile_rows(
    qualification: dict[str, Any],
    decisions: list[dict[str, Any]],
    registry: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    active = set(qualification["active_local_profiles"])
    registered = {row["oracle_profile_id"] for row in registry.values()}
    assigned = Counter(
        row["oracle_profile_id"] for row in decisions if row["oracle_profile_id"] is not None
    )
    rows = []
    for profile_id in sorted(active | registered):
        realizations = sorted(
            row["realization_id"]
            for row in registry.values()
            if row["oracle_profile_id"] == profile_id
        )
        cwes = sorted(
            {row["cwe_id"] for row in registry.values() if row["oracle_profile_id"] == profile_id}
        )
        supported = profile_id in active
        rows.append(
            {
                "oracle_profile_id": profile_id,
                "oracle_type": (
                    "DETERMINISTIC_STATIC_PROFILE"
                    if supported
                    else "CONTEXTUAL_ORACLE_REQUIRED"
                ),
                "support_status": "QUALIFIED" if supported else "UNSUPPORTED",
                "registered_realization_ids": realizations,
                "registered_cwes": cwes,
                "assigned_task_units": assigned[profile_id],
                "gold_boundary_labels": (
                    qualification["required_labels"] if supported else []
                ),
                "qualification_claim_boundary": qualification["claim_boundary"],
                "arms_or_outcomes_used": False,
            }
        )
    return rows


_MEMORY_REPLICATION_CWES = {
    "CWE-119",
    "CWE-120",
    "CWE-125",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-787",
}


def _memory_replication_rows(
    candidate_ledger: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        row
        for row in candidate_ledger
        if row["language"] in {"c", "cpp"}
        and row["primary_cwe"] in _MEMORY_REPLICATION_CWES
        and row["candidate_status"] == "PENDING_RUNTIME"
    ]


def _backend_candidate_rows(root: Path | None) -> list[dict[str, Any]]:
    if root is None:
        return []
    source = root.resolve()
    scenario_root = source / "src/scenarios"
    env_init = source / "src/env/__init__.py"
    if not scenario_root.is_dir() or not env_init.is_file() or not (source / "LICENSE").is_file():
        raise EligibilityError("backend replication source is incomplete")
    frameworks = _assigned_names(env_init, "all_envs")
    if not frameworks:
        raise EligibilityError("backend replication source has no framework realizations")

    rows = []
    for path in sorted(scenario_root.glob("*.py")):
        if path.stem in {"__init__", "base"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        call = _assigned_call(tree, "SCENARIO", "Scenario")
        keywords = {item.arg: item.value for item in call.keywords if item.arg is not None}
        try:
            scenario_id = ast.literal_eval(keywords["id"])
        except (KeyError, ValueError, TypeError, SyntaxError) as error:
            raise EligibilityError("backend scenario id is not a literal") from error
        functional_tests = _expression_names(keywords.get("functional_tests"))
        security_tests = _expression_names(keywords.get("security_tests"))
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or not functional_tests
            or not security_tests
        ):
            raise EligibilityError("backend scenario lacks source-native measurements")
        function_defs = {
            node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        security_cwes = sorted(
            {
                node.attr
                for name in security_tests
                for node in ast.walk(function_defs.get(name, ast.Pass()))
                if isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "cwes"
                and node.value.attr == "CWE"
            }
        )
        relative = path.relative_to(source).as_posix()
        core = {
            "scenario_id": scenario_id,
            "source_file": relative,
            "source_file_sha256": _sha256(path),
            "functional_test_ids": functional_tests,
            "security_test_ids": security_tests,
            "security_cwe_names": security_cwes,
            "framework_realization_ids": frameworks,
            "functional_oracle_type": "SOURCE_NATIVE_EXECUTABLE_TEST",
            "security_oracle_type": "SOURCE_NATIVE_EXPLOIT_TEST",
            "oracle_profile_id": f"baxbench.{path.stem}.source_security_tests.v1",
            "runtime_support_status": "PENDING_DOCKER_QUALIFICATION",
            "candidate_status": "PENDING_RUNTIME",
            "framework_realization_status": "PENDING_OUTCOME_BLIND_FREEZE",
            "arms_or_outcomes_used": False,
        }
        rows.append(
            {"backend_task_unit_id": content_id("backend_task_unit_", core), **core}
        )
    if len({row["scenario_id"] for row in rows}) != len(rows):
        raise EligibilityError("backend scenario ids are duplicated")
    return rows


def _backend_oracle_profile_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "oracle_profile_id": row["oracle_profile_id"],
            "oracle_type": row["security_oracle_type"],
            "support_status": "PENDING_RUNTIME_QUALIFICATION",
            "registered_realization_ids": [row["scenario_id"]],
            "registered_cwes": row["security_cwe_names"],
            "assigned_task_units": 1,
            "gold_boundary_labels": [],
            "qualification_claim_boundary": (
                "The source defines executable attacks, but this snapshot has not yet "
                "passed the frozen Docker runtime replay."
            ),
            "arms_or_outcomes_used": False,
        }
        for row in rows
    ]


def _assigned_call(tree: ast.Module, name: str, constructor: str) -> ast.Call:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == constructor
        ):
            return node.value
    raise EligibilityError(f"backend source lacks {name} = {constructor}(...)")


def _assigned_names(path: Path, name: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ) or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ):
            return _expression_names(node.value)
    return []


def _expression_names(value: ast.expr | None) -> list[str]:
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return []
    names = []
    for item in value.elts:
        if isinstance(item, ast.Name):
            names.append(item.id)
        elif isinstance(item, ast.Attribute):
            names.append(item.attr)
        else:
            raise EligibilityError("backend registry list contains a non-name expression")
    return names


def _source_tree_sha256(root: Path) -> str:
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not {"__pycache__", ".git"}.intersection(path.parts)
        and path.suffix != ".pyc"
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _mechanism_for_prompt(
    prompt: str, candidates: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, str]:
    normalized = " ".join(prompt.casefold().split())
    matches = [
        row
        for row in candidates
        if not row["prompt_markers"]
        or all(marker.casefold() in normalized for marker in row["prompt_markers"])
    ]
    if not candidates:
        return None, "mechanism_not_registered"
    if not matches:
        return None, "mechanism_realization_not_resolved"
    if len(matches) > 1:
        return None, "mechanism_realization_ambiguous"
    return matches[0], "resolved"


def _binding_rows(value: Any) -> dict[str, dict[str, Any]]:
    rows = _rows(value)
    result = {}
    for row in rows:
        cluster_id = row.get("cluster_id")
        if (
            not isinstance(cluster_id, str)
            or not cluster_id
            or cluster_id in result
            or row.get("outcomes_or_arms_used") is not False
            or row.get("decision")
            not in {"profile_candidate", "not_applicable", "contextual_oracle_required"}
        ):
            raise EligibilityError("realization binding row is invalid")
        result[cluster_id] = row
    return result


def _mechanism_from_binding(
    binding: dict[str, Any],
    representative: dict[str, Any],
    contract: dict[str, Any],
    registry: dict[str, dict[str, Any]],
    *,
    contract_lineage_ids: set[str] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    accepted_contract_ids = contract_lineage_ids or {contract["contract_id"]}
    if (
        binding.get("representative_record_id") != representative["record_id"]
        or binding.get("contract_id") not in accepted_contract_ids
        or binding.get("primary_cwe") != representative["cwe"]
    ):
        raise EligibilityError("realization binding does not match its frozen cluster")
    if binding["decision"] != "profile_candidate":
        return None, str(binding["reason_code"])
    realization_id = binding.get("realization_id")
    mechanism = registry.get(realization_id)
    if mechanism is None:
        return None, "mechanism_not_registered"
    if (
        mechanism["cwe_id"] != representative["cwe"]
        or mechanism["oracle_profile_id"] != binding.get("proposed_oracle_profile_id")
        or mechanism["oracle_profile_id"] not in TARGET_LOCAL_PROFILE_IDS
    ):
        raise EligibilityError("realization binding and mechanism registry disagree")
    return mechanism, "resolved_by_frozen_task_binding"


def _policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "policy_id",
        "active_layer",
        "source_tests_required",
        "functional_oracle_languages",
        "security_oracle_languages",
        "lineage_policy",
        "final_dataset_admission",
        "python_families",
        "mechanism_registry_path",
        "functional_oracle_qualification_path",
        "security_oracle_qualification_path",
        "layers",
    }:
        raise EligibilityError("eligibility policy fields are invalid")
    if value["schema_version"] != "1.3" or value["source_tests_required"] is not False:
        raise EligibilityError("eligibility policy version or test rule is invalid")
    lineage_policy = value["lineage_policy"]
    if not isinstance(lineage_policy, dict) or lineage_policy != {
        "admission_role": "diagnostic_only",
        "selection_priority": "prefer_underrepresented_lineages_after_family_and_cwe_balance",
        "report_source_specific_estimates": True,
        "report_leave_one_lineage_out": True,
    }:
        raise EligibilityError("lineage policy must remain diagnostic-only")
    final_dataset_admission = value["final_dataset_admission"]
    if not isinstance(final_dataset_admission, dict) or final_dataset_admission != {
        "required_contract_quality": "STRICT",
        "disqualifying_quality_flags": [
            "known_material_contract_fault",
            "known_scope_or_evaluability_concern",
            "metadata_repair_required",
            "semantic_calibration_required",
            "source_prompt_incoherent",
        ],
        "mechanism_oracle_runtime_support_required": False,
        "development_exposure_changes_dataset_admission": False,
    }:
        raise EligibilityError("final dataset admission must remain quality-only")
    families = value["python_families"]
    if not isinstance(families, list) or not families:
        raise EligibilityError("Python family policy is empty")
    family_cwes = set()
    for family in families:
        if not isinstance(family, dict) or set(family) != {
            "family_id",
            "target_clusters",
            "cwes",
        }:
            raise EligibilityError("Python family fields are invalid")
        if (
            not isinstance(family["family_id"], str)
            or not family["family_id"]
            or type(family["target_clusters"]) is not int
            or family["target_clusters"] <= 0
            or not isinstance(family["cwes"], list)
            or not family["cwes"]
            or family_cwes.intersection(family["cwes"])
        ):
            raise EligibilityError("Python family values are invalid")
        family_cwes.update(family["cwes"])
    layers = value["layers"]
    if not isinstance(layers, list) or not layers:
        raise EligibilityError("eligibility policy layers are empty")
    seen = set()
    for row in layers:
        if not isinstance(row, dict) or set(row) != {"layer_id", "languages", "cwes"}:
            raise EligibilityError("eligibility layer fields are invalid")
        for language in row["languages"]:
            for cwe in row["cwes"]:
                if (language, cwe) in seen:
                    raise EligibilityError("eligibility layers overlap")
                seen.add((language, cwe))
    if value["active_layer"] not in {row["layer_id"] for row in layers}:
        raise EligibilityError("active eligibility layer is unknown")
    return value


def _largest_fraction(counts: Counter[str]) -> float:
    total = sum(counts.values())
    return 0.0 if not total else round(max(counts.values()) / total, 6)


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise EligibilityError("eligibility input must contain object rows")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "EligibilityError",
    "apply_binding_adjudications",
    "audit_dataset_eligibility",
    "freeze_prompt_tsg_holdout_selection",
    "freeze_prompt_tsg_task_selection",
    "freeze_tsg_realization_bindings",
    "qualify_local_security_profiles",
    "qualify_target_security_profiles",
    "qualify_prompt_tsg_extractor",
]

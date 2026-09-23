"""Scoped Oracle qualification, TSG task selection, and binding adjudication."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.discovery.mechanisms import (
    load_mechanism_registry,
    tsg_mechanism_binding,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    load_catalog,
    prompt_tsg_from_record,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.measurement.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
)
from prompt_mechanism_study.measurement.target_security_profiles import (
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
        "implementation_sha256": _sha256(root / "src/measurement/security_profiles.py"),
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
    *,
    profile_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Qualify the declared profile scope on arm-blind gold code idioms.

    Omitting the scope preserves full-catalog qualification and frozen replay.
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
        sources.append({"path": relative, "sha256": _sha256(source)})
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
        if row["oracle_profile_id"] in TARGET_LOCAL_PROFILE_IDS
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
        "local_security_profiles_sha256": _sha256(Path(__file__).parents[1] / 'measurement/security_profiles.py'),
        "outcomes_or_arms_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {"binding-decisions.json": decisions, "report.json": report},
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


_MEMORY_REPLICATION_CWES = {
    "CWE-119",
    "CWE-120",
    "CWE-125",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-787",
}


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


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise EligibilityError("eligibility input must contain object rows")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "EligibilityError",
    "apply_binding_adjudications",
    "freeze_prompt_tsg_holdout_selection",
    "freeze_prompt_tsg_task_selection",
    "freeze_tsg_realization_bindings",
    "qualify_local_security_profiles",
    "qualify_target_security_profiles",
]

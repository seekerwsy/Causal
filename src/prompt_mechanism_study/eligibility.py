"""Outcome-blind eligibility audit for curated semantic task clusters."""

from __future__ import annotations

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
from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
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
        elif profile_id not in LOCAL_PROFILE_IDS:
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
) -> dict[str, Any]:
    """Classify every semantic cluster without generated-code outcomes."""

    root = repository_root.resolve()
    prepared = prepared_root.resolve()
    clusters = clusters_root.resolve()
    contracts = contracts_root.resolve()
    bindings = None if bindings_root is None else bindings_root.resolve()
    destination = output.resolve()
    if destination.exists():
        raise EligibilityError("eligibility output already exists")
    for bundle in (prepared, clusters, contracts):
        verify_bundle(bundle)
    if bindings is not None:
        verify_bundle(bindings)

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
    if (
        security_qualification.get("status") != "QUALIFIED_FOR_EXPERIMENT"
        or security_qualification.get("registry_sha256") != _sha256(registry_file)
        or security_qualification.get("implementation_sha256")
        != _sha256(root / "src/prompt_mechanism_study/security_profiles.py")
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
                "minimum_lineages": policy["minimum_lineages_per_python_family"],
                "cluster_target_met": len(members) >= family["target_clusters"],
                "lineage_target_met": len(lineages) >= policy["minimum_lineages_per_python_family"],
            }
        )
    lineage_counts = Counter(row["representative_lineage_family"] for row in eligible)
    maximum_lineage_capped_sample = _maximum_capped_sample(
        lineage_counts, policy["maximum_lineage_fraction"]
    )
    report = {
        "schema_version": "1.0",
        "status": "DATASET_ELIGIBILITY_AUDIT_COMPLETE",
        "cluster_count": len(decisions),
        "status_counts": dict(sorted(statuses.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "eligible_cwe_counts": dict(
            sorted(Counter(row["primary_cwe"] for row in eligible).items())
        ),
        "eligible_source_counts": dict(
            sorted(Counter(row["representative_source"] for row in eligible).items())
        ),
        "eligible_lineage_counts": dict(sorted(lineage_counts.items())),
        "python_family_gate": family_rows,
        "prospective_python_cluster_target": sum(
            row["target_clusters"] for row in policy["python_families"]
        ),
        "python_population_gate_passed": all(
            row["cluster_target_met"] and row["lineage_target_met"] for row in family_rows
        ),
        "maximum_sample_under_lineage_cap": maximum_lineage_capped_sample,
        "maximum_lineage_fraction": policy["maximum_lineage_fraction"],
        "eligible_with_source_tests": sum(row["source_test_available"] for row in eligible),
        "prepared_bundle_sha256": bundle_digest(prepared),
        "clusters_bundle_sha256": bundle_digest(clusters),
        "contracts_bundle_sha256": bundle_digest(contracts),
        "policy_sha256": _sha256(policy_file),
        "mechanism_registry_sha256": _sha256(registry_file),
        "local_security_profiles_sha256": _sha256(
            root / "src/prompt_mechanism_study/security_profiles.py"
        ),
        "functional_oracle_qualification_sha256": _sha256(qualification_file),
        "security_oracle_qualification_sha256": _sha256(
            security_qualification_file
        ),
        "realization_binding_bundle_sha256": (
            None if bindings is None else bundle_digest(bindings)
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
            "report.json": report,
        },
    )
    return report


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
) -> tuple[dict[str, Any] | None, str]:
    if (
        binding.get("representative_record_id") != representative["record_id"]
        or binding.get("contract_id") != contract["contract_id"]
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
        or mechanism["oracle_profile_id"] not in LOCAL_PROFILE_IDS
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
        "maximum_lineage_fraction",
        "minimum_lineages_per_python_family",
        "python_families",
        "mechanism_registry_path",
        "functional_oracle_qualification_path",
        "security_oracle_qualification_path",
        "layers",
    }:
        raise EligibilityError("eligibility policy fields are invalid")
    if value["schema_version"] != "1.1" or value["source_tests_required"] is not False:
        raise EligibilityError("eligibility policy version or test rule is invalid")
    if (
        type(value["maximum_lineage_fraction"]) is not float
        or not 0 < value["maximum_lineage_fraction"] <= 1
        or type(value["minimum_lineages_per_python_family"]) is not int
        or value["minimum_lineages_per_python_family"] <= 0
    ):
        raise EligibilityError("eligibility population constraints are invalid")
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


def _maximum_capped_sample(counts: Counter[str], maximum_fraction: float) -> int:
    for size in range(sum(counts.values()), 0, -1):
        cap = int(size * maximum_fraction)
        if cap and sum(min(count, cap) for count in counts.values()) >= size:
            return size
    return 0


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise EligibilityError("eligibility input must contain object rows")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "EligibilityError",
    "audit_dataset_eligibility",
    "freeze_tsg_realization_bindings",
    "qualify_local_security_profiles",
]

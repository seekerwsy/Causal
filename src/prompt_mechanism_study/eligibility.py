"""Outcome-blind eligibility audit for curated semantic task clusters."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.mechanisms import load_mechanism_registry
from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.security_profiles import LOCAL_PROFILE_IDS


class EligibilityError(RuntimeError):
    """Raised when an eligibility input or policy is inconsistent."""


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
    if not registry_file.is_file() or not qualification_file.is_file():
        raise EligibilityError("eligibility policy references a missing artifact")
    registry = load_mechanism_registry(registry_file)
    qualification = read_json(qualification_file)
    if qualification.get("status") != "QUALIFIED_FOR_EXPERIMENT":
        raise EligibilityError("functional Oracle is not qualified")

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
        "layers",
    }:
        raise EligibilityError("eligibility policy fields are invalid")
    if value["schema_version"] != "1.0" or value["source_tests_required"] is not False:
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


__all__ = ["EligibilityError", "audit_dataset_eligibility"]

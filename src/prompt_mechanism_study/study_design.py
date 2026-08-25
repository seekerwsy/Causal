"""Outcome-blind sampling and power freeze for the paper-facing study."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from statistics import NormalDist
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.records import content_id


class StudyDesignError(RuntimeError):
    """Raised when a prospective sample cannot satisfy its frozen constraints."""


def freeze_study_design(
    repository_root: Path,
    eligibility_root: Path,
    task_units_root: Path,
    output: Path,
    *,
    seed: int = 2026082301,
    clusters_per_family: int = 15,
    minimum_detectable_effect: float = 0.20,
    discordant_pair_probability: float = 0.30,
    alpha: float = 0.05,
    target_power: float = 0.80,
    excluded_sample_paths: Sequence[Path] | None = None,
    included_families: Sequence[str] | None = None,
    family_quotas: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Freeze a balanced Python sample and a separate C/C++ readiness audit."""

    root = repository_root.resolve()
    eligibility = eligibility_root.resolve()
    units_root = task_units_root.resolve()
    destination = output.resolve()
    if destination.exists():
        raise StudyDesignError("study-design output already exists")
    verify_bundle(eligibility)
    verify_bundle(units_root)
    eligibility_report = read_json(eligibility / "report.json")
    units_report = read_json(units_root / "report.json")
    if (
        eligibility_report.get("generated_code_or_outcomes_used") is not False
        or units_report.get("experiment_outcomes_or_arms_used") is not False
    ):
        raise StudyDesignError("study-design inputs are not outcome blind")

    policy = read_json(root / "data/dataset-curation/eligibility-policy-v1.json")
    family_by_cwe = {
        cwe: family["family_id"] for family in policy["python_families"] for cwe in family["cwes"]
    }
    eligible_rows = read_json(eligibility / "eligible-clusters.json")
    eligible = {row["cluster_id"]: row for row in eligible_rows}
    units = read_json(units_root / "eligible-task-units.json")
    exclusions = read_json(units_root / "co-selection-exclusions.json")
    excluded_task_units = _excluded_task_units(excluded_sample_paths)
    candidates = [
        row
        for row in _python_candidates(eligible, units, family_by_cwe, seed)
        if row["task_unit_id"] not in excluded_task_units
    ]
    all_family_ids = [row["family_id"] for row in policy["python_families"]]
    family_ids = (
        list(family_quotas)
        if family_quotas
        else list(included_families)
        if included_families
        else all_family_ids
    )
    if (
        not family_ids
        or len(family_ids) != len(set(family_ids))
        or not set(family_ids) <= set(all_family_ids)
        or (
            family_quotas is not None
            and (
                set(family_quotas) != set(family_ids)
                or any(not isinstance(value, int) or value <= 0 for value in family_quotas.values())
            )
        )
    ):
        raise StudyDesignError("included mechanism families are invalid")
    targets = (
        dict(family_quotas)
        if family_quotas is not None
        else {family: clusters_per_family for family in family_ids}
    )
    sample = _balanced_sample(
        candidates,
        exclusions,
        family_ids,
        per_family=targets,
        seed=seed,
        maximum_lineage_fraction=policy["maximum_lineage_fraction"],
        minimum_lineages=policy["minimum_lineages_per_python_family"],
    )
    power = _power_design(
        len(sample),
        minimum_detectable_effect,
        discordant_pair_probability,
        alpha,
        target_power,
    )
    cpp_rows = [
        row
        for row in read_json(eligibility / "calibration-only-clusters.json")
        if row["reason"] == "replication_runtime_not_implemented"
    ]
    cpp = _cpp_readiness(cpp_rows, seed)
    extension_policy_path = (
        root / "data/dataset-curation/priority-extension-policy-v1.json"
    )
    extension_policy = read_json(extension_policy_path)
    priority_extensions = _priority_extensions(
        read_json(eligibility / "excluded-clusters.json"),
        extension_policy,
    )

    family_counts = Counter(row["family_id"] for row in sample)
    cwe_counts = Counter(row["primary_cwe"] for row in sample)
    lineage_counts = Counter(row["representative_lineage_family"] for row in sample)
    lineages_per_family = {
        family: len(
            {
                row["representative_lineage_family"]
                for row in sample
                if row["family_id"] == family
            }
        )
        for family in family_ids
    }
    report = {
        "schema_version": "1.0",
        "status": "OUTCOME_BLIND_STUDY_DESIGN_COMPLETE",
        "python": {
            "sample_clusters": len(sample),
            "sample_task_units": len({row["task_unit_id"] for row in sample}),
            "clusters_per_family": dict(sorted(family_counts.items())),
            "clusters_per_cwe": dict(sorted(cwe_counts.items())),
            "lineage_counts": dict(sorted(lineage_counts.items())),
            "lineages_per_family": dict(sorted(lineages_per_family.items())),
            "maximum_lineage_count": max(lineage_counts.values()),
            "maximum_lineage_fraction": policy["maximum_lineage_fraction"],
            "arms": ["absent", "specific", "generic", "placebo"],
            "assignments_per_model": len(sample) * 4,
            "primary_contrast": "specific_minus_placebo",
            "power_gate_passed": power["power_gate_passed"],
        },
        "c_cpp_replication": {
            "candidate_clusters": len(cpp_rows),
            "shortlist_clusters": len(cpp["shortlist"]),
            "shortlist_with_source_tests": cpp["shortlist_with_source_tests"],
            "target_clusters": 28,
            "execution_gate_passed": cpp["execution_gate_passed"],
        },
        "priority_extensions": {
            "candidate_clusters": len(priority_extensions),
            "tier_counts": dict(
                sorted(Counter(row["priority_tier"] for row in priority_extensions).items())
            ),
            "language_counts": dict(
                sorted(Counter(row["language"] for row in priority_extensions).items())
            ),
            "current_formal_sample_eligible": False,
        },
        "eligibility_bundle_sha256": bundle_digest(eligibility),
        "task_units_bundle_sha256": bundle_digest(units_root),
        "eligibility_policy_sha256": _sha256(
            root / "data/dataset-curation/eligibility-policy-v1.json"
        ),
        "priority_extension_policy_sha256": _sha256(extension_policy_path),
        "study_design_implementation_sha256": _sha256(
            root / "src/prompt_mechanism_study/study_design.py"
        ),
        "selection_seed": seed,
        "excluded_exposed_task_units": len(excluded_task_units),
        "excluded_sample_sha256s": [
            _sha256(path) for path in (excluded_sample_paths or [])
        ],
        "included_families": family_ids,
        "family_quotas": targets,
        "omitted_families": [family for family in all_family_ids if family not in family_ids],
        "generated_code_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        "confirmatory_generation_authorized": False,
        "next_gate": "freeze interventions, generator identity, assignments, and pilot split",
    }
    write_bundle(
        destination,
        {
            "python-sample.json": sample,
            "power-design.json": power,
            "c-cpp-readiness.json": cpp,
            "priority-extension-candidates.json": priority_extensions,
            "report.json": report,
        },
    )
    return report


def _excluded_task_units(paths: Sequence[Path] | Path | None) -> set[str]:
    """Load prior JSON or JSONL samples as prospective exposure exclusions."""

    sources = [paths] if isinstance(paths, Path) else list(paths or [])
    task_units = []
    for path in sources:
        if path.suffix == ".jsonl":
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        else:
            rows = read_json(path)
        if not isinstance(rows, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("task_unit_id"), str)
            for row in rows
        ):
            raise StudyDesignError("excluded sample does not identify task units")
        task_units.extend(row["task_unit_id"] for row in rows)
    if len(task_units) != len(set(task_units)):
        raise StudyDesignError("excluded samples contain duplicate task units")
    return set(task_units)


def _python_candidates(
    eligible: dict[str, dict[str, Any]],
    units: list[dict[str, Any]],
    family_by_cwe: dict[str, str],
    seed: int,
) -> list[dict[str, Any]]:
    candidates = []
    for unit in units:
        rows = [eligible[cluster_id] for cluster_id in unit["cluster_ids"] if cluster_id in eligible]
        if not rows:
            continue
        families = {family_by_cwe[row["primary_cwe"]] for row in rows}
        if len(families) != 1:
            raise StudyDesignError("one task unit crosses Python mechanism families")
        representative = min(
            rows,
            key=lambda row: _order_key(seed, unit["task_unit_id"], row["cluster_id"]),
        )
        candidates.append(
            {
                "task_unit_id": unit["task_unit_id"],
                "cluster_id": representative["cluster_id"],
                "task_unit_cluster_ids": unit["cluster_ids"],
                "family_id": next(iter(families)),
                "primary_cwe": representative["primary_cwe"],
                "mechanism_realization_id": representative["mechanism_realization_id"],
                "oracle_profile_id": representative["oracle_profile_id"],
                "contract_id": representative["contract_id"],
                "representative_record_id": representative["representative_record_id"],
                "representative_source": representative["representative_source"],
                "representative_lineage_family": representative[
                    "representative_lineage_family"
                ],
                "source_test_available": representative["source_test_available"],
            }
        )
    return candidates


def _balanced_sample(
    candidates: list[dict[str, Any]],
    exclusions: list[dict[str, Any]],
    family_ids: list[str],
    *,
    per_family: int | Mapping[str, int],
    seed: int,
    maximum_lineage_fraction: float,
    minimum_lineages: int,
) -> list[dict[str, Any]]:
    targets = (
        {family: per_family for family in family_ids}
        if isinstance(per_family, int)
        else dict(per_family)
    )
    if set(targets) != set(family_ids) or any(value <= 0 for value in targets.values()):
        raise StudyDesignError("family sampling targets are invalid")
    total = sum(targets.values())
    lineage_cap = math.floor(total * maximum_lineage_fraction)
    conflicts = defaultdict(set)
    for row in exclusions:
        left, right = row["task_unit_ids"]
        conflicts[left].add(right)
        conflicts[right].add(left)
    remaining = {row["task_unit_id"]: row for row in candidates}
    selected = []
    selected_ids = set()
    family_counts: Counter[str] = Counter()
    family_cwes: dict[str, Counter[str]] = defaultdict(Counter)
    family_lineages: dict[str, Counter[str]] = defaultdict(Counter)
    lineage_counts: Counter[str] = Counter()
    while any(family_counts[family] < targets[family] for family in family_ids):
        progressed = False
        for family in family_ids:
            if family_counts[family] >= targets[family]:
                continue
            choices = [
                row
                for row in remaining.values()
                if row["family_id"] == family
                and lineage_counts[row["representative_lineage_family"]] < lineage_cap
                and not (conflicts[row["task_unit_id"]] & selected_ids)
                and _lineage_slot_available(
                    row["representative_lineage_family"],
                    family,
                    remaining.values(),
                    conflicts,
                    selected_ids,
                    family_ids,
                    family_counts,
                    targets,
                    lineage_counts,
                    lineage_cap,
                )
            ]
            if not choices:
                raise StudyDesignError(f"cannot satisfy frozen sample constraints for {family}")
            chosen = min(
                choices,
                key=lambda row: (
                    family_cwes[family][row["primary_cwe"]],
                    family_lineages[family][row["representative_lineage_family"]],
                    lineage_counts[row["representative_lineage_family"]],
                    _order_key(seed, family, row["task_unit_id"]),
                ),
            )
            remaining.pop(chosen["task_unit_id"])
            selected_ids.add(chosen["task_unit_id"])
            family_counts[family] += 1
            family_cwes[family][chosen["primary_cwe"]] += 1
            lineage = chosen["representative_lineage_family"]
            family_lineages[family][lineage] += 1
            lineage_counts[lineage] += 1
            selected.append(chosen)
            progressed = True
        if not progressed:
            raise StudyDesignError("sample selection made no progress")
    for family in family_ids:
        if len(family_lineages[family]) < minimum_lineages:
            raise StudyDesignError(f"sample lacks lineage diversity for {family}")
    result = []
    for index, row in enumerate(selected, start=1):
        core = {"sample_order": index, **row, "selection_seed": seed}
        result.append({"sample_id": content_id("python_sample_", core), **core})
    return result


def _lineage_slot_available(
    lineage: str,
    choosing_family: str,
    remaining: Any,
    conflicts: Mapping[str, set[str]],
    selected_ids: set[str],
    family_ids: Sequence[str],
    family_counts: Mapping[str, int],
    targets: Mapping[str, int],
    lineage_counts: Mapping[str, int],
    lineage_cap: int,
) -> bool:
    """Reserve scarce lineage capacity for families that have no alternative lineage."""

    available = list(remaining)
    mandatory_for_other_families = 0
    for family in family_ids:
        if family == choosing_family:
            continue
        needed = targets[family] - family_counts[family]
        alternatives = sum(
            row["family_id"] == family
            and row["representative_lineage_family"] != lineage
            and not (conflicts[row["task_unit_id"]] & selected_ids)
            for row in available
        )
        mandatory_for_other_families += max(0, needed - alternatives)
    return lineage_counts[lineage] < lineage_cap - mandatory_for_other_families


def _power_design(
    clusters: int,
    effect: float,
    discordance: float,
    alpha: float,
    target_power: float,
) -> dict[str, Any]:
    if (
        clusters <= 0
        or not 0 < effect < 1
        or not 0 < discordance <= 1
        or not 0 < alpha < 1
    ):
        raise StudyDesignError("power assumptions are invalid")
    normal = NormalDist()
    critical = normal.inv_cdf(1 - alpha / 2)

    def power_at(value: float) -> float:
        noncentrality = effect / math.sqrt(value / clusters)
        return 1 - normal.cdf(critical - noncentrality) + normal.cdf(-critical - noncentrality)

    achieved = power_at(discordance)
    sensitivity = [
        {"discordant_pair_probability": value, "power": round(power_at(value), 6)}
        for value in (0.20, 0.25, 0.30, 0.35, 0.40)
    ]
    return {
        "schema_version": "1.0",
        "estimand": "paired_cluster_weighted_specific_minus_placebo_itt",
        "outcome": "oracle_evaluable_secure_code_yield",
        "cluster_count": clusters,
        "minimum_detectable_effect": effect,
        "discordant_pair_probability": discordance,
        "two_sided_alpha": alpha,
        "target_power": target_power,
        "achieved_normal_approximation_power": round(achieved, 6),
        "power_gate_passed": achieved >= target_power,
        "power_interpretation": "assumption_conditional_not_observed_effect_evidence",
        "discordance_assumption_basis": (
            "prospective planning assumption; sensitivity is reported and no sampled outcome "
            "was inspected"
        ),
        "family_effects": "preplanned_descriptive_heterogeneity",
        "sensitivity": sensitivity,
        "generated_code_or_outcomes_used": False,
    }


def _cpp_readiness(rows: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    cwes = ("CWE-119", "CWE-120", "CWE-125", "CWE-190", "CWE-416", "CWE-476", "CWE-787")
    shortlist = []
    population = {}
    for cwe in cwes:
        candidates = [row for row in rows if row["primary_cwe"] == cwe]
        population[cwe] = {
            "candidate_clusters": len(candidates),
            "source_tests": sum(row["source_test_available"] for row in candidates),
            "lineages": len({row["representative_lineage_family"] for row in candidates}),
        }
        counts: Counter[str] = Counter()
        available = list(candidates)
        for _ in range(4):
            if not available:
                raise StudyDesignError(f"C/C++ replication lacks four candidates for {cwe}")
            chosen = min(
                available,
                key=lambda row: (
                    not row["source_test_available"],
                    counts[row["representative_lineage_family"]],
                    _order_key(seed, "c-cpp", cwe, row["cluster_id"]),
                ),
            )
            available.remove(chosen)
            counts[chosen["representative_lineage_family"]] += 1
            shortlist.append(
                {
                    "cluster_id": chosen["cluster_id"],
                    "cwe": cwe,
                    "language": chosen["language"],
                    "representative_record_id": chosen["representative_record_id"],
                    "representative_source": chosen["representative_source"],
                    "representative_lineage_family": chosen["representative_lineage_family"],
                    "contract_id": chosen["contract_id"],
                    "source_test_available": chosen["source_test_available"],
                }
            )
    tested = sum(row["source_test_available"] for row in shortlist)
    return {
        "schema_version": "1.0",
        "status": "C_CPP_REPLICATION_READINESS_AUDITED",
        "target_per_cwe": 4,
        "population_by_cwe": population,
        "shortlist": shortlist,
        "shortlist_with_source_tests": tested,
        "missing_frozen_functional_tests": len(shortlist) - tested,
        "required_runtime_components": [
            "C/C++ compiler and syntax gate",
            "frozen functional test for every shortlisted cluster",
            "task-applicable ASan, UBSan, or frozen exploit check",
            "isolated executable runner",
        ],
        "execution_gate_passed": tested == len(shortlist),
        "generated_code_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }


def _priority_extensions(
    rows: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    requirements = policy["common_requirements"]
    tiers = policy["tiers"]
    python_tier = tiers[0]
    cross_language_tier = tiers[1]
    family_by_cwe = {
        cwe: family
        for family, cwes in python_tier["families"].items()
        for cwe in cwes
    }
    candidates = []
    for row in rows:
        if (
            not row["source_test_available"]
            or not row["contract_id"]
            or row["requirement_count"] < requirements["minimum_requirements"]
            or row["source_test_reference_count"]
            < requirements["minimum_source_test_references"]
        ):
            continue
        family = family_by_cwe.get(row["primary_cwe"])
        if row["language"] == python_tier["language"] and family:
            tier = python_tier
        elif row["language"] in cross_language_tier["languages"]:
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
    counts = Counter(
        row["primary_cwe"]
        for row in candidates
        if row["priority_tier"] == python_tier["tier_id"]
    )
    if any(
        counts[cwe] < python_tier["minimum_candidates_per_cwe"]
        for cwe in family_by_cwe
    ):
        raise StudyDesignError("priority Python extension CWE lacks candidate support")
    return sorted(
        candidates,
        key=lambda row: (
            row["priority_tier"],
            row["language"],
            row["primary_cwe"],
            row["cluster_id"],
        ),
    )


def _order_key(seed: int, *values: str) -> str:
    return hashlib.sha256("|".join((str(seed), *values)).encode()).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = ["StudyDesignError", "freeze_study_design"]

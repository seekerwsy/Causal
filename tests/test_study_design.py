from __future__ import annotations

from collections import Counter

import pytest

from prompt_mechanism_study.study_design import (
    _balanced_sample,
    _excluded_task_units,
    _power_design,
    _priority_extensions,
)

pytestmark = pytest.mark.extended


def test_study_design_balances_units_without_crossing_exclusions() -> None:
    families = [f"family-{index}" for index in range(4)]
    candidates = []
    for family in families:
        for index in range(6):
            candidates.append(
                {
                    "task_unit_id": f"{family}-unit-{index}",
                    "cluster_id": f"{family}-cluster-{index}",
                    "family_id": family,
                    "primary_cwe": f"CWE-{index % 2}",
                    "representative_lineage_family": f"lineage-{index % 3}",
                }
            )
    exclusions = [
        {
            "task_unit_ids": ["family-0-unit-0", "family-1-unit-0"],
        }
    ]

    sample = _balanced_sample(
        candidates,
        exclusions,
        families,
        per_family=3,
        seed=17,
        maximum_lineage_fraction=0.5,
        minimum_lineages=3,
    )

    selected = {row["task_unit_id"] for row in sample}
    assert len(sample) == len(selected) == 12
    assert not {"family-0-unit-0", "family-1-unit-0"} <= selected
    assert {
        family: sum(row["family_id"] == family for row in sample) for family in families
    } == {family: 3 for family in families}
    assert all(
        len({row["primary_cwe"] for row in sample if row["family_id"] == family}) == 2
        for family in families
    )


def test_study_design_accepts_explicit_unequal_family_quotas() -> None:
    families = ["injection", "parser", "crypto"]
    candidates = [
        {
            "task_unit_id": f"{family}-{index}",
            "cluster_id": f"{family}-{index}",
            "family_id": family,
            "primary_cwe": f"CWE-{index % 2}",
            "representative_lineage_family": f"lineage-{index % 3}",
        }
        for family in families
        for index in range(6)
    ]

    sample = _balanced_sample(
        candidates,
        [],
        families,
        per_family={"injection": 4, "parser": 3, "crypto": 2},
        seed=19,
        maximum_lineage_fraction=0.5,
        minimum_lineages=2,
    )

    assert Counter(row["family_id"] for row in sample) == {
        "injection": 4,
        "parser": 3,
        "crypto": 2,
    }


def test_study_design_reserves_lineage_cap_for_family_without_alternatives() -> None:
    candidates = [
        {
            "task_unit_id": f"crypto-{index}",
            "cluster_id": f"crypto-{index}",
            "family_id": "crypto",
            "primary_cwe": "CWE-338",
            "representative_lineage_family": "single-lineage",
        }
        for index in range(3)
    ]
    candidates.extend(
        {
            "task_unit_id": f"injection-{lineage}-{index}",
            "cluster_id": f"injection-{lineage}-{index}",
            "family_id": "injection",
            "primary_cwe": "CWE-78",
            "representative_lineage_family": lineage,
        }
        for lineage in ("single-lineage", "other-a", "other-b")
        for index in range(3)
    )

    sample = _balanced_sample(
        candidates,
        [],
        ["injection", "crypto"],
        per_family={"injection": 3, "crypto": 3},
        seed=23,
        maximum_lineage_fraction=0.5,
        minimum_lineages=1,
    )

    assert sum(
        row["representative_lineage_family"] == "single-lineage" for row in sample
    ) == 3
    assert all(
        row["representative_lineage_family"] != "single-lineage"
        for row in sample
        if row["family_id"] == "injection"
    )


def test_power_freeze_is_explicitly_assumption_conditional() -> None:
    design = _power_design(60, 0.20, 0.30, 0.05, 0.80)

    assert design["achieved_normal_approximation_power"] == 0.80743
    assert design["power_gate_passed"] is True
    assert design["power_interpretation"] == (
        "assumption_conditional_not_observed_effect_evidence"
    )
    assert design["sensitivity"][-1] == {
        "discordant_pair_probability": 0.4,
        "power": 0.68777,
    }


def test_exposed_task_units_are_loaded_from_frozen_jsonl(tmp_path) -> None:
    sample = tmp_path / "exposed.jsonl"
    sample.write_text(
        '{"task_unit_id":"unit-a"}\n{"task_unit_id":"unit-b"}\n',
        encoding="utf-8",
    )

    assert _excluded_task_units([sample]) == {"unit-a", "unit-b"}


def test_priority_extensions_require_contracts_tests_and_supported_tiers() -> None:
    policy = {
        "common_requirements": {
            "minimum_requirements": 1,
            "minimum_source_test_references": 1,
        },
        "tiers": [
            {
                "tier_id": "python",
                "language": "python",
                "families": {"injection": ["CWE-77"]},
                "minimum_candidates_per_cwe": 1,
                "admission_blocker": "mechanism",
            },
            {
                "tier_id": "cross-language",
                "languages": ["go"],
                "admission_blocker": "runtime",
            },
        ],
    }

    def row(name: str, language: str, cwe: str, tested: bool = True) -> dict:
        return {
            "cluster_id": f"cluster-{name}",
            "contract_id": f"contract-{name}",
            "language": language,
            "primary_cwe": cwe,
            "representative_record_id": f"record-{name}",
            "representative_source": "fixture",
            "representative_lineage_family": "fixture",
            "requirement_count": 1,
            "source_test_available": tested,
            "source_test_reference_count": int(tested),
        }

    candidates = _priority_extensions(
        [
            row("python", "python", "CWE-77"),
            row("go", "go", "CWE-22"),
            row("untested", "python", "CWE-77", tested=False),
            row("java", "java", "CWE-77"),
        ],
        policy,
    )

    assert [(item["language"], item["priority_tier"]) for item in candidates] == [
        ("go", "cross-language"),
        ("python", "python"),
    ]
    assert all(item["current_formal_sample_eligible"] is False for item in candidates)

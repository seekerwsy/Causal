from __future__ import annotations

import json
from pathlib import Path

import pytest

from secaware.exploratory.canary import build_randomized_exploratory_canary
from secaware.intervention.arm_catalog import materialize_safety_arm_specs
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation


REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / "configs/e2e-pilot/randomized-exploratory-discovery-canary-v1.json"
FIVE_CWE_CONFIG = REPO_ROOT / "configs/e2e-pilot/five-cwe-discovery-gate-a-qwen7b-v2.json"


def _rows(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_public_safety_arm_materializer_reuses_exact_four_arm_catalog() -> None:
    arms = materialize_safety_arm_specs("safety.safe_subprocess", FeatureOperation.ADD)

    assert tuple(item.role for item in arms) == (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    )


def test_gate_a_builds_balanced_disjoint_reproducible_variation(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    report = build_randomized_exploratory_canary(
        repo_root=REPO_ROOT,
        config_path=CONFIG,
        output_dir=first,
        command_argv=("canary", "first"),
    )
    replay = build_randomized_exploratory_canary(
        repo_root=REPO_ROOT,
        config_path=CONFIG,
        output_dir=second,
        command_argv=("canary", "second"),
    )

    assert report["status"] == "GATE_A_PASSED"
    assert replay["status"] == "GATE_A_PASSED"
    assert report["counts"] == {
        "independent_tasks": 4,
        "confirm_task_ids_excluded": 4,
        "candidates": 2,
        "variants": 16,
        "blocks": 4,
        "assignments": 16,
        "extraction_proposals": 16,
        "prompt_tsgs": 16,
        "deterministic_target_recognized": 1,
        "deterministic_target_expected": 4,
        "errors": 0,
        "pending": 0,
    }
    for name in (
        "candidates.jsonl",
        "variants.jsonl",
        "assignments.jsonl",
        "deterministic-extraction-proposals.jsonl",
        "deterministic-prompt-tsg.jsonl",
        "feature-states.jsonl",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()

    variants = _rows(first / "variants.jsonl")
    assignments = _rows(first / "assignments.jsonl")
    source_task_ids = {row["task_id"] for row in _rows(first / "source-prompts.jsonl")}
    assert len(source_task_ids) == 4
    assert {row["task_id"] for row in variants} == source_task_ids
    assert {row["task_id"] for row in assignments} == source_task_ids
    assert all(row["outcome_generation_allowed"] is False for row in variants)
    assert all(row["outcome_generation_allowed"] is False for row in assignments)
    for task_id in source_task_ids:
        assert {row["arm_role"] for row in assignments if row["task_id"] == task_id} == {
            item.value
            for item in (
                ArmRole.TARGET_PATCH,
                ArmRole.NOOP_REWRITE,
                ArmRole.LENGTH_MATCHED_PLACEBO,
                ArmRole.GENERIC_SECURITY_REMINDER,
            )
        }
    states = _rows(first / "feature-states.jsonl")
    for cwe in ("CWE-78", "CWE-89"):
        local = [row for row in states if row["cwe"] == cwe]
        assert {row["intended_target_feature_state"] for row in local} == {"absent", "present"}
        assert sum(row["intended_target_feature_state"] == "present" for row in local) == 2


def test_gate_a_rejects_non_discover_policy_and_preserves_failure(tmp_path: Path) -> None:
    payload = json.loads(CONFIG.read_text(encoding="utf-8"))
    payload["allowed_source_split"] = "confirm"
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "failed"

    with pytest.raises(ValueError, match="policy failed validation"):
        build_randomized_exploratory_canary(
            repo_root=REPO_ROOT,
            config_path=invalid,
            output_dir=output,
            command_argv=("canary", "invalid"),
        )

    failure = json.loads((output / "failure.json").read_text(encoding="utf-8"))
    assert failure["status"] == "GATE_A_FAILED"


def test_gate_a_accepts_one_candidate_per_discovery_cwe(tmp_path: Path) -> None:
    report = build_randomized_exploratory_canary(
        repo_root=REPO_ROOT,
        config_path=FIVE_CWE_CONFIG,
        output_dir=tmp_path / "five-cwe",
        command_argv=("canary", "five-cwe"),
    )

    assert report["status"] == "GATE_A_PASSED"
    assert report["counts"] == {
        "independent_tasks": 10,
        "confirm_task_ids_excluded": 10,
        "candidates": 5,
        "variants": 40,
        "blocks": 10,
        "assignments": 40,
        "extraction_proposals": 40,
        "prompt_tsgs": 40,
        "deterministic_target_recognized": 1,
        "deterministic_target_expected": 10,
        "errors": 0,
        "pending": 0,
    }
    assert {
        row["cwe"] for row in _rows(tmp_path / "five-cwe" / "candidates.jsonl")
    } == {"CWE-78", "CWE-89", "CWE-328", "CWE-338", "CWE-502"}

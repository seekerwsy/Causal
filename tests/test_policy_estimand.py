from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.experiments.policy_estimand import freeze_policy_estimand
from secaware.functional_audit.main_pool import MAIN_CWE_ORDER, PROFILE_BY_CWE


_FEATURE_BY_CWE = {
    "CWE-78": "safety.safe_subprocess",
    "CWE-89": "safety.sql_parameterization",
    "CWE-502": "safety.safe_deserialization",
    "CWE-328": "safety.collision_resistant_hash",
    "CWE-338": "safety.cryptographic_randomness",
}
_COUNTS_BY_CWE_SPLIT = {
    "CWE-78": {"discover": 21, "confirm": 22},
    "CWE-89": {"discover": 10, "confirm": 7},
    "CWE-502": {"discover": 7, "confirm": 2},
    "CWE-328": {"discover": 10, "confirm": 7},
    "CWE-338": {"discover": 3, "confirm": 4},
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.write_bytes(b"".join(_canonical(value) + b"\n" for value in values))


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    task_dir = tmp_path / "tasks"
    task_dir.mkdir()
    tasks = []
    for cwe in MAIN_CWE_ORDER:
        profile = PROFILE_BY_CWE[cwe]
        for split in ("discover", "confirm"):
            for index in range(_COUNTS_BY_CWE_SPLIT[cwe][split]):
                task_id = f"task-{cwe}-{split}-{index}"
                tasks.append(
                    {
                        "task_id": task_id,
                        "task_cluster_id": f"cluster-{cwe}-{split}-{index}",
                        "cwe": cwe,
                        "split": split,
                        "task_family": profile["task_family"],
                        "oracle_profile_id": profile["oracle_profile_id"],
                        "source_prompt_sha256": hashlib.sha256(task_id.encode()).hexdigest(),
                        "blindness": {
                            "generated_code_withheld": True,
                            "intervention_arm_withheld": True,
                            "model_identity_withheld": True,
                            "oracle_label_withheld": True,
                            "outcomes_withheld": True,
                        },
                    },
                )
    task_path = task_dir / "tasks.jsonl"
    _write_jsonl(task_path, tasks)
    task_sha = hashlib.sha256(task_path.read_bytes()).hexdigest()
    _write_json(
        task_dir / "report.json",
        {
            "task_bundle_sha256": task_sha,
            "counts": {"provider_calls": 0, "generated_code": 0, "outcomes_observed": 0},
        },
    )
    config = {
        "schema_version": "1.0",
        "estimand_id": "five_cwe_operation_specific_security_requirement_policy_itt_v1",
        "policy_target_id": "policy.operation_specific_security_requirement",
        "pooled_variable_id": "x_operation_specific_security_requirement",
        "operation": "add",
        "task_pool": {
            "task_pool_id": "five-cwe-main-task-pool-frozen-20260818-07",
            "task_bundle_sha256": task_sha,
            "expected_tasks": 93,
            "expected_by_split": {"discover": 51, "confirm": 42},
            "weighting": "equal_independent_task",
            "cwe_reweighting": "none",
            "split_mutation_allowed": False,
        },
        "mappings": [
            {
                "cwe": cwe,
                "task_family": PROFILE_BY_CWE[cwe]["task_family"],
                "oracle_profile_id": PROFILE_BY_CWE[cwe]["oracle_profile_id"],
                "target_feature_id": _FEATURE_BY_CWE[cwe],
            }
            for cwe in MAIN_CWE_ORDER
        ],
        "arm_roles": [
            "target_patch",
            "noop_rewrite",
            "length_matched_placebo",
            "generic_security_reminder",
        ],
        "model_strata": ["qwen2.5-coder-7b-instruct", "phi-4-14b"],
        "contexts": {"randomized_arm": "c.exploratory_arm", "cwe_scope": "c.cwe_scope"},
        "analysis": {
            "primary_outcome_id": "y_secure_functional",
            "primary_treatment_arm": "target_patch",
            "primary_control_arm": "noop_rewrite",
            "primary_expected_sign": "two_sided",
            "primary_multiplicity_family_id": "five_cwe_policy_primary_by_model_v1",
            "primary_multiplicity_family_size": 2,
            "secondary_contrasts": [
                {
                    "outcome_id": "y_cwe_secure",
                    "treatment_arm": "target_patch",
                    "control_arm": "noop_rewrite",
                },
                {
                    "outcome_id": "y_secure_functional",
                    "treatment_arm": "target_patch",
                    "control_arm": "length_matched_placebo",
                },
                {
                    "outcome_id": "y_secure_functional",
                    "treatment_arm": "target_patch",
                    "control_arm": "generic_security_reminder",
                },
            ],
            "estimator": "task_clustered_itt_risk_difference",
            "paper_min_independent_tasks": 20,
            "model_pooling": "forbidden",
            "post_randomization_filtering": "forbidden",
            "cwe_effect_role_below_minimum": "heterogeneity_diagnostic",
        },
    }
    config_path = tmp_path / "config.json"
    _write_json(config_path, config)
    return task_dir, config_path


def test_freeze_policy_estimand_keeps_typed_children_and_zero_outcomes(tmp_path: Path) -> None:
    task_dir, config_path = _fixture(tmp_path)
    report = freeze_policy_estimand(
        task_pool_dir=task_dir,
        config_path=config_path,
        run_dir=tmp_path / "run",
        command_argv=("freeze",),
    )

    assert report["status"] == "POOLED_POLICY_ESTIMAND_FROZEN"
    assert report["counts"] == {
        "tasks": 93,
        "discover": 51,
        "confirm": 42,
        "mappings": 5,
        "model_strata": 2,
        "provider_calls": 0,
        "generated_code": 0,
        "outcomes_observed": 0,
        "errors": 0,
        "pending": 0,
    }
    rows = [
        json.loads(line)
        for line in (tmp_path / "run" / "task-applicability.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert {row["target_feature_id"] for row in rows} == set(_FEATURE_BY_CWE.values())
    assert all(row["task_weight"] == 1 and row["outcome_blind"] is True for row in rows)
    assert all("prompt" not in row and "outcome" not in row for row in rows)
    assert report["cwe_status_eligibility"]["CWE-78"]["confirm"][
        "confirmatory_status_allowed"
    ]
    assert not any(
        item["confirm"]["confirmatory_status_allowed"]
        for cwe, item in report["cwe_status_eligibility"].items()
        if cwe != "CWE-78"
    )


def test_freeze_policy_estimand_rejects_task_mapping_drift(tmp_path: Path) -> None:
    task_dir, config_path = _fixture(tmp_path)
    rows = [
        json.loads(line)
        for line in (task_dir / "tasks.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    rows[0]["task_family"] = "wrong_family"
    _write_jsonl(task_dir / "tasks.jsonl", rows)
    task_sha = hashlib.sha256((task_dir / "tasks.jsonl").read_bytes()).hexdigest()
    report = json.loads((task_dir / "report.json").read_text(encoding="utf-8"))
    report["task_bundle_sha256"] = task_sha
    _write_json(task_dir / "report.json", report)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["task_pool"]["task_bundle_sha256"] = task_sha
    _write_json(config_path, config)

    try:
        freeze_policy_estimand(
            task_pool_dir=task_dir,
            config_path=config_path,
            run_dir=tmp_path / "run",
            command_argv=("freeze",),
        )
    except ValueError as error:
        assert str(error) == "policy estimand task applicability failed validation"
    else:
        raise AssertionError("mapping drift must fail closed")

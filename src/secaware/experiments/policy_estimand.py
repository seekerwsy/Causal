"""Freeze a pooled task-policy estimand without collapsing typed child features."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from secaware.functional_audit.main_pool import MAIN_CWE_ORDER, PROFILE_BY_CWE
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)


_SCHEMA_VERSION = "1.0"
_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_MODEL_STRATA = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_TASK_BLINDNESS = {
    "generated_code_withheld": True,
    "intervention_arm_withheld": True,
    "model_identity_withheld": True,
    "oracle_label_withheld": True,
    "outcomes_withheld": True,
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: object) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        return len(bytes.fromhex(value)) == 32 and value == value.lower()
    except ValueError:
        return False


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("policy estimand JSON object failed validation")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError("policy estimand JSONL record failed validation")
        values.append(value)
    return values


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _validated_config(config: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    expected_keys = {
        "schema_version",
        "estimand_id",
        "policy_target_id",
        "pooled_variable_id",
        "operation",
        "task_pool",
        "mappings",
        "arm_roles",
        "model_strata",
        "contexts",
        "analysis",
    }
    if set(config) != expected_keys or config.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("policy estimand config failed validation")
    if (
        config.get("estimand_id")
        != "five_cwe_operation_specific_security_requirement_policy_itt_v1"
        or config.get("policy_target_id")
        != "policy.operation_specific_security_requirement"
        or config.get("pooled_variable_id")
        != "x_operation_specific_security_requirement"
        or config.get("operation") != FeatureOperation.ADD.value
        or tuple(config.get("arm_roles", ())) != _ARMS
        or tuple(config.get("model_strata", ())) != _MODEL_STRATA
        or config.get("contexts")
        != {"randomized_arm": "c.exploratory_arm", "cwe_scope": "c.cwe_scope"}
    ):
        raise ValueError("policy estimand identity failed validation")

    task_pool = config.get("task_pool")
    if (
        type(task_pool) is not dict
        or set(task_pool)
        != {
            "task_pool_id",
            "task_bundle_sha256",
            "expected_tasks",
            "expected_by_split",
            "weighting",
            "cwe_reweighting",
            "split_mutation_allowed",
        }
        or task_pool.get("task_pool_id") != "five-cwe-main-task-pool-frozen-20260818-07"
        or not _is_sha256(task_pool.get("task_bundle_sha256"))
        or task_pool.get("expected_tasks") != 93
        or task_pool.get("expected_by_split") != {"discover": 51, "confirm": 42}
        or task_pool.get("weighting") != "equal_independent_task"
        or task_pool.get("cwe_reweighting") != "none"
        or task_pool.get("split_mutation_allowed") is not False
    ):
        raise ValueError("policy estimand population failed validation")

    mappings = config.get("mappings")
    if type(mappings) is not list or len(mappings) != len(MAIN_CWE_ORDER):
        raise ValueError("policy estimand mapping failed validation")
    checked: list[dict[str, Any]] = []
    feature_ids: set[str] = set()
    for expected_cwe, mapping in zip(MAIN_CWE_ORDER, mappings, strict=True):
        if type(mapping) is not dict or set(mapping) != {
            "cwe",
            "task_family",
            "oracle_profile_id",
            "target_feature_id",
        }:
            raise ValueError("policy estimand mapping failed validation")
        profile = PROFILE_BY_CWE[expected_cwe]
        feature_id = mapping.get("target_feature_id")
        if (
            mapping.get("cwe") != expected_cwe
            or mapping.get("task_family") != profile["task_family"]
            or mapping.get("oracle_profile_id") != profile["oracle_profile_id"]
            or type(feature_id) is not str
            or feature_id in feature_ids
        ):
            raise ValueError("policy estimand mapping failed validation")
        spec = prompt_feature_spec(feature_id)
        if (
            spec.feature_family is not FeatureFamily.SAFETY_CONTROL
            or not spec.intervenable
            or FeatureOperation.ADD not in spec.operations
            or expected_cwe not in spec.applicable_cwes
            or profile["task_family"] not in spec.applicable_task_families
        ):
            raise ValueError("policy estimand FeatureSpec failed validation")
        feature_ids.add(feature_id)
        checked.append(mapping)

    analysis = config.get("analysis")
    if (
        type(analysis) is not dict
        or set(analysis)
        != {
            "primary_outcome_id",
            "primary_treatment_arm",
            "primary_control_arm",
            "primary_expected_sign",
            "primary_multiplicity_family_id",
            "primary_multiplicity_family_size",
            "secondary_contrasts",
            "estimator",
            "paper_min_independent_tasks",
            "model_pooling",
            "post_randomization_filtering",
            "cwe_effect_role_below_minimum",
        }
        or analysis.get("primary_outcome_id") != "y_secure_functional"
        or analysis.get("primary_treatment_arm") != "target_patch"
        or analysis.get("primary_control_arm") != "noop_rewrite"
        or analysis.get("primary_expected_sign") != "two_sided"
        or analysis.get("primary_multiplicity_family_id")
        != "five_cwe_policy_primary_by_model_v1"
        or analysis.get("primary_multiplicity_family_size") != len(_MODEL_STRATA)
        or analysis.get("estimator") != "task_clustered_itt_risk_difference"
        or analysis.get("paper_min_independent_tasks") != 20
        or analysis.get("model_pooling") != "forbidden"
        or analysis.get("post_randomization_filtering") != "forbidden"
        or analysis.get("cwe_effect_role_below_minimum")
        != "heterogeneity_diagnostic"
    ):
        raise ValueError("policy estimand analysis failed validation")
    secondary = analysis.get("secondary_contrasts")
    expected_secondary = [
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
    ]
    if secondary != expected_secondary:
        raise ValueError("policy estimand secondary contrasts failed validation")
    return tuple(checked)


def freeze_policy_estimand(
    *,
    task_pool_dir: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Freeze the approved policy estimand and total task-to-child applicability map."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = _read_json(config_path)
    mappings = _validated_config(config)
    mapping_by_cwe = {item["cwe"]: item for item in mappings}

    task_path = task_pool_dir / "tasks.jsonl"
    task_report_path = task_pool_dir / "report.json"
    task_report = _read_json(task_report_path)
    task_bundle_sha256 = _file_sha(task_path)
    task_pool = config["task_pool"]
    if (
        task_bundle_sha256 != task_pool["task_bundle_sha256"]
        or task_report.get("task_bundle_sha256") != task_bundle_sha256
        or task_report.get("counts", {}).get("provider_calls") != 0
        or task_report.get("counts", {}).get("generated_code") != 0
        or task_report.get("counts", {}).get("outcomes_observed") != 0
    ):
        raise ValueError("policy estimand task-pool provenance failed validation")

    tasks = _read_jsonl(task_path)
    expected_tasks = task_pool["expected_tasks"]
    if len(tasks) != expected_tasks:
        raise ValueError("policy estimand task count failed validation")
    task_ids: set[str] = set()
    cluster_ids: set[str] = set()
    rows: list[dict[str, object]] = []
    by_cwe_split: Counter[tuple[str, str]] = Counter()
    for task in tasks:
        task_id = task.get("task_id")
        cluster_id = task.get("task_cluster_id")
        cwe = task.get("cwe")
        split = task.get("split")
        mapping = mapping_by_cwe.get(cwe)
        if (
            type(task_id) is not str
            or not task_id
            or task_id in task_ids
            or type(cluster_id) is not str
            or not cluster_id
            or cluster_id in cluster_ids
            or split not in {"discover", "confirm"}
            or mapping is None
            or task.get("task_family") != mapping["task_family"]
            or task.get("oracle_profile_id") != mapping["oracle_profile_id"]
            or task.get("blindness") != _TASK_BLINDNESS
            or not _is_sha256(task.get("source_prompt_sha256"))
        ):
            raise ValueError("policy estimand task applicability failed validation")
        task_ids.add(task_id)
        cluster_ids.add(cluster_id)
        by_cwe_split[(cwe, split)] += 1
        content = {
            "schema_version": _SCHEMA_VERSION,
            "estimand_id": config["estimand_id"],
            "policy_target_id": config["policy_target_id"],
            "pooled_variable_id": config["pooled_variable_id"],
            "task_id": task_id,
            "task_cluster_id": cluster_id,
            "source_prompt_sha256": task["source_prompt_sha256"],
            "split": split,
            "cwe": cwe,
            "cwe_context_variable_id": config["contexts"]["cwe_scope"],
            "cwe_context_value": cwe,
            "task_family": mapping["task_family"],
            "oracle_profile_id": mapping["oracle_profile_id"],
            "target_feature_id": mapping["target_feature_id"],
            "feature_family": FeatureFamily.SAFETY_CONTROL.value,
            "operation": FeatureOperation.ADD.value,
            "pooled_state_derivation": "state_of_applicable_child_feature",
            "task_weight": 1,
            "outcome_blind": True,
        }
        rows.append(
            {
                **content,
                "applicability_id": "policy_applicability_" + _sha(content),
            }
        )
    rows.sort(key=lambda row: (MAIN_CWE_ORDER.index(str(row["cwe"])), str(row["split"]), str(row["task_id"])))

    by_split = {
        split: sum(by_cwe_split[(cwe, split)] for cwe in MAIN_CWE_ORDER)
        for split in ("discover", "confirm")
    }
    if by_split != task_pool["expected_by_split"]:
        raise ValueError("policy estimand split count failed validation")
    minimum = config["analysis"]["paper_min_independent_tasks"]
    cwe_status = {
        cwe: {
            split: {
                "independent_tasks": by_cwe_split[(cwe, split)],
                "confirmatory_status_allowed": by_cwe_split[(cwe, split)] >= minimum,
            }
            for split in ("discover", "confirm")
        }
        for cwe in MAIN_CWE_ORDER
    }

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "effective-config.json", config)
    _write_jsonl(run_dir / "task-applicability.jsonl", rows)
    _write_json(
        run_dir / "estimand.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "estimand_id": config["estimand_id"],
            "policy_target_id": config["policy_target_id"],
            "pooled_variable_id": config["pooled_variable_id"],
            "task_pool_id": task_pool["task_pool_id"],
            "task_bundle_sha256": task_bundle_sha256,
            "feature_catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
            "operation": config["operation"],
            "mappings": mappings,
            "arm_roles": config["arm_roles"],
            "model_strata": config["model_strata"],
            "contexts": config["contexts"],
            "analysis": config["analysis"],
            "population_weighting": task_pool["weighting"],
            "cwe_reweighting": task_pool["cwe_reweighting"],
        },
    )
    _write_json(run_dir / "environment.json", _environment())
    _write_jsonl(
        run_dir / "commands.jsonl",
        [{"schema_version": _SCHEMA_VERSION, "argv": command_argv, "provider_calls": 0}],
    )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "POOLED_POLICY_ESTIMAND_FROZEN",
        "counts": {
            "tasks": len(rows),
            "discover": by_split["discover"],
            "confirm": by_split["confirm"],
            "mappings": len(mappings),
            "model_strata": len(_MODEL_STRATA),
            "provider_calls": 0,
            "generated_code": 0,
            "outcomes_observed": 0,
            "errors": 0,
            "pending": 0,
        },
        "by_cwe_split": {
            cwe: {
                split: by_cwe_split[(cwe, split)] for split in ("discover", "confirm")
            }
            for cwe in MAIN_CWE_ORDER
        },
        "cwe_status_eligibility": cwe_status,
        "primary_estimand": {
            "outcome_id": config["analysis"]["primary_outcome_id"],
            "treatment_arm": config["analysis"]["primary_treatment_arm"],
            "control_arm": config["analysis"]["primary_control_arm"],
            "expected_sign": config["analysis"]["primary_expected_sign"],
            "weighting": task_pool["weighting"],
            "models_estimated_separately": True,
        },
        "input_digests": {
            "config_sha256": _file_sha(config_path),
            "task_bundle_sha256": task_bundle_sha256,
            "task_pool_report_sha256": _file_sha(task_report_path),
            "feature_catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        },
        "artifact_digests": {
            name: _file_sha(run_dir / name)
            for name in (
                "commands.jsonl",
                "effective-config.json",
                "environment.json",
                "estimand.json",
                "task-applicability.jsonl",
            )
        },
        "next_gate": "five_cwe_four_arm_prompt_canary",
    }
    _write_json(run_dir / "report.json", report)
    _write_json(
        run_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": _file_sha(path)}
                for path in sorted(run_dir.iterdir())
                if path.is_file()
            ],
        },
    )
    return report


__all__ = ["freeze_policy_estimand"]

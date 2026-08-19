"""Outcome-blind preflight for an independent causal-discovery validation pool."""

from __future__ import annotations

import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.pipeline.artifact import sha256_file

_SCHEMA_VERSION = "1.0"
_MAIN_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_EXCLUSION_REASONS = {
    "no_target_operation",
    "outside_profile",
    "weak_mechanism_required",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("independent validation JSON object failed validation")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if type(value) is not dict:
            raise ValueError("independent validation JSONL object failed validation")
        rows.append(value)
    return rows


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def _input_path(repo_root: Path, record: object) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("independent validation input record failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("independent validation input record failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("independent validation input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("independent validation input digest failed validation")
    return path


def _validated_config(repo_root: Path, config_path: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    config = _read_json(config_path)
    hypothesis = config.get("frozen_hypothesis")
    policy = config.get("eligibility_policy")
    inputs = config.get("inputs")
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("audit_id") != "five_cwe_independent_validation_pool_preflight_v1"
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or type(hypothesis) is not dict
        or hypothesis.get("model_id") != "phi-4-14b"
        or hypothesis.get("source_variable_id") != "z.target_mechanism_realized"
        or hypothesis.get("target_variable_id") != "y.discovery_functional"
        or hypothesis.get("minimum_bootstrap_support") != 0.8
        or type(policy) is not dict
        or policy.get("independence") != "strict"
        or policy.get("disjoint_from_method_development") is not True
        or policy.get("accepted_reason_code") != "accepted"
        or set(policy.get("forbidden_reason_codes", ())) != _EXCLUSION_REASONS
        or policy.get("minimum_validation_tasks") != 50
        or policy.get("required_cwes") != list(_MAIN_CWES)
        or policy.get("safety_neutrality_required") is not True
        or type(inputs) is not dict
        or set(inputs)
        != {
            "method_development_selection",
            "cross_source_candidates",
            "cross_source_decisions",
            "frozen_hypotheses",
        }
    ):
        raise ValueError("independent validation configuration failed validation")
    paths = {name: _input_path(repo_root, record) for name, record in inputs.items()}
    return config, paths


def _candidate_identity(candidate: dict[str, Any]) -> dict[str, object]:
    representative = candidate.get("representative")
    if type(representative) is not dict:
        raise ValueError("independent validation candidate failed validation")
    return {
        "schema_version": _SCHEMA_VERSION,
        "cwe": candidate.get("cwe"),
        "split": candidate.get("split"),
        "task_cluster_id": candidate.get("task_cluster_id"),
        "source_id": representative.get("source_id"),
        "record_id": representative.get("record_id"),
        "source_prompt_sha256": representative.get("exact_prompt_sha256"),
    }


def audit_independent_validation_pool(
    *,
    repo_root: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Separate reused, independently eligible, and unusable candidate clusters."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config, paths = _validated_config(repo_root, config_path)

    selection = _read_json(paths["method_development_selection"])
    selection_tasks = selection.get("tasks")
    if type(selection_tasks) is not list or len(selection_tasks) != 93:
        raise ValueError("independent validation method-development population failed validation")
    used_clusters = {row.get("task_cluster_id") for row in selection_tasks if type(row) is dict}
    if None in used_clusters or len(used_clusters) != 93:
        raise ValueError("independent validation method-development clusters failed validation")

    hypothesis_rows = _read_jsonl(paths["frozen_hypotheses"])
    frozen = config["frozen_hypothesis"]
    if (
        len(hypothesis_rows) != 1
        or hypothesis_rows[0].get("hypothesis_id") != frozen.get("hypothesis_id")
        or hypothesis_rows[0].get("model_id") != frozen.get("model_id")
        or hypothesis_rows[0].get("source_variable_id") != frozen.get("source_variable_id")
        or hypothesis_rows[0].get("target_variable_id") != frozen.get("target_variable_id")
    ):
        raise ValueError("independent validation frozen hypothesis failed validation")

    all_candidates = _read_jsonl(paths["cross_source_candidates"])
    candidates = [row for row in all_candidates if row.get("independence") == "strict"]
    if len(candidates) != 59:
        raise ValueError("independent validation strict candidate population failed validation")
    candidate_by_cluster = {row.get("task_cluster_id"): row for row in candidates}
    if None in candidate_by_cluster or len(candidate_by_cluster) != len(candidates):
        raise ValueError("independent validation candidate clusters failed validation")

    decisions = _read_jsonl(paths["cross_source_decisions"])
    decision_by_cluster = {row.get("task_cluster_id"): row for row in decisions}
    if None in decision_by_cluster or set(decision_by_cluster) != set(candidate_by_cluster):
        raise ValueError("independent validation candidate decision coverage failed validation")

    overlap_rows: list[dict[str, object]] = []
    eligible_rows: list[dict[str, object]] = []
    excluded_rows: list[dict[str, object]] = []
    for cluster_id, candidate in sorted(candidate_by_cluster.items()):
        identity = _candidate_identity(candidate)
        decision = decision_by_cluster[cluster_id]
        audit = decision.get("audit")
        if type(audit) is not dict:
            raise ValueError("independent validation audit decision failed validation")
        reason = audit.get("reason_code")
        eligible = audit.get("eligible")
        if type(eligible) is not bool or type(reason) is not str:
            raise ValueError("independent validation audit decision failed validation")
        if eligible != (reason == config["eligibility_policy"]["accepted_reason_code"]):
            raise ValueError("independent validation eligibility relation failed validation")
        if cluster_id in used_clusters:
            overlap_rows.append(
                {
                    **identity,
                    "prior_eligibility": eligible,
                    "prior_reason_code": reason,
                    "exclusion": "method_development_cluster_overlap",
                }
            )
        elif eligible:
            eligible_rows.append(
                {
                    **identity,
                    "prior_reason_code": reason,
                    "selection_status": "independent_validation_candidate",
                }
            )
        else:
            if reason not in _EXCLUSION_REASONS:
                raise ValueError("independent validation exclusion reason failed validation")
            excluded_rows.append(
                {
                    **identity,
                    "prior_reason_code": reason,
                    "rationale": audit.get("rationale"),
                    "exclusion": "outcome_blind_task_ineligibility",
                }
            )

    minimum = config["eligibility_policy"]["minimum_validation_tasks"]
    present_cwes = {row["cwe"] for row in eligible_rows}
    missing_cwes = [cwe for cwe in _MAIN_CWES if cwe not in present_cwes]
    blocking_reasons: list[str] = []
    if len(eligible_rows) < minimum:
        blocking_reasons.append("insufficient_independent_eligible_tasks")
    if missing_cwes:
        blocking_reasons.append("missing_required_cwe_coverage")
    status = (
        "INDEPENDENT_VALIDATION_POOL_READY"
        if not blocking_reasons
        else "INDEPENDENT_VALIDATION_POOL_BLOCKED"
    )

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(run_dir / "effective-config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_json(
        run_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": command_argv, "provider_calls": 0},
    )
    _write_json(
        run_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "inputs": {
                name: {"path": str(path.relative_to(repo_root)), "sha256": sha256_file(path)}
                for name, path in sorted(paths.items())
            },
        },
    )
    _write_jsonl(run_dir / "overlap-exclusions.jsonl", overlap_rows)
    _write_jsonl(run_dir / "independent-eligible.jsonl", eligible_rows)
    _write_jsonl(run_dir / "independent-ineligible.jsonl", excluded_rows)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "frozen_hypothesis_id": frozen["hypothesis_id"],
        "counts": {
            "method_development_clusters": len(used_clusters),
            "strict_cross_source_candidates": len(candidates),
            "overlap_exclusions": len(overlap_rows),
            "independent_eligible": len(eligible_rows),
            "independent_ineligible": len(excluded_rows),
            "minimum_validation_tasks": minimum,
        },
        "independent_eligible_by_cwe": dict(
            sorted(Counter(str(row["cwe"]) for row in eligible_rows).items())
        ),
        "independent_ineligible_by_reason": dict(
            sorted(Counter(str(row["prior_reason_code"]) for row in excluded_rows).items())
        ),
        "missing_required_cwes": missing_cwes,
        "blocking_reasons": blocking_reasons,
        "next_action": (
            "freeze_generation_plan"
            if not blocking_reasons
            else "acquire_and_audit_new_outcome_blind_task_sources"
        ),
    }
    _write_json(run_dir / "report.json", report)
    files = [path for path in run_dir.rglob("*") if path.is_file()]
    _write_json(
        run_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(run_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in sorted(files)
            ],
        },
    )
    return report


__all__ = ["audit_independent_validation_pool"]

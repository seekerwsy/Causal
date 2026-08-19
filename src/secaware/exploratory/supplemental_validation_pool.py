"""Freeze a supplemental, semantically deduplicated independent validation pool."""

from __future__ import annotations

import hashlib
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
_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_ADJUDICATION_KEYS = {
    "source_record_id",
    "eligible",
    "reason_code",
    "rationale",
    "semantic_group_id",
    "prior_pool_semantic_overlap",
    "neutrality_override",
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if type(row) is not dict:
            raise ValueError("supplemental validation JSONL row failed validation")
        rows.append(row)
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


def _repo_input(repo_root: Path, record: object) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("supplemental validation input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("supplemental validation input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("supplemental validation input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("supplemental validation input digest failed validation")
    return path


def _manifest(root: Path) -> dict[str, object]:
    files = [path for path in root.rglob("*") if path.is_file()]
    return {
        "schema_version": _SCHEMA_VERSION,
        "files": [
            {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
            for path in sorted(files)
        ],
    }


def _cluster_id(group_id: str, members: list[dict[str, Any]]) -> str:
    seed = "|".join(
        [group_id, *(str(row["exact_prompt_sha256"]) for row in sorted(members, key=lambda r: r["source_record_id"]))]
    )
    return "independent-validation-cluster-" + hashlib.sha256(seed.encode()).hexdigest()[:20]


def freeze_supplemental_validation_pool(
    *,
    repo_root: Path,
    config_path: Path,
    public_run_dir: Path,
    restricted_run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Combine prior clusters with newly adjudicated clusters without reading outcomes."""

    if public_run_dir.exists() or restricted_run_dir.exists():
        raise FileExistsError(public_run_dir if public_run_dir.exists() else restricted_run_dir)
    config = _read_json(config_path)
    inputs = config.get("inputs") if type(config) is dict else None
    if (
        type(config) is not dict
        or config.get("schema_version") != _SCHEMA_VERSION
        or config.get("pool_id") != "five_cwe_supplemental_independent_validation_pool_v1"
        or config.get("required_cwes") != list(_CWES)
        or config.get("minimum_validation_tasks") != 50
        or type(config.get("expected_prior_clusters")) is not int
        or type(config.get("expected_review_units")) is not int
        or type(config.get("expected_eligible_units")) is not int
        or type(config.get("expected_supplemental_clusters")) is not int
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("raw_prompt_redistribution_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {"prior_candidates", "review_queue", "source_report", "adjudications"}
    ):
        raise ValueError("supplemental validation configuration failed validation")
    paths = {name: _repo_input(repo_root, record) for name, record in inputs.items()}
    prior = _read_jsonl(paths["prior_candidates"])
    review = _read_jsonl(paths["review_queue"])
    adjudications = _read_jsonl(paths["adjudications"])
    source_report = _read_json(paths["source_report"])
    if (
        len(prior) != config["expected_prior_clusters"]
        or len(review) != config["expected_review_units"]
        or len(adjudications) != len(review)
        or type(source_report) is not dict
        or source_report.get("status") != "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED"
        or source_report.get("outcomes_consumed") != 0
        or source_report.get("reference_fields_consumed") != 0
    ):
        raise ValueError("supplemental validation source population failed validation")

    review_by_id = {str(row.get("source_record_id")): row for row in review}
    adjudication_by_id: dict[str, dict[str, Any]] = {}
    for row in adjudications:
        if set(row) != _ADJUDICATION_KEYS:
            raise ValueError("supplemental validation adjudication schema failed validation")
        record_id = row.get("source_record_id")
        eligible = row.get("eligible")
        group_id = row.get("semantic_group_id")
        if (
            type(record_id) is not str
            or record_id in adjudication_by_id
            or type(eligible) is not bool
            or type(row.get("reason_code")) is not str
            or type(row.get("rationale")) is not str
            or type(row.get("prior_pool_semantic_overlap")) is not bool
            or type(row.get("neutrality_override")) is not bool
            or (eligible and (type(group_id) is not str or not group_id))
            or (not eligible and group_id is not None)
        ):
            raise ValueError("supplemental validation adjudication failed validation")
        adjudication_by_id[record_id] = row
    if set(review_by_id) != set(adjudication_by_id):
        raise ValueError("supplemental validation adjudication coverage failed validation")

    eligible_rows: list[dict[str, Any]] = []
    excluded_rows: list[dict[str, object]] = []
    for record_id in sorted(review_by_id):
        task = review_by_id[record_id]
        decision = adjudication_by_id[record_id]
        if task.get("cwe") not in _CWES or task.get("review_status") != "blinded_task_review_required":
            raise ValueError("supplemental validation review row failed validation")
        if decision["eligible"]:
            if decision["prior_pool_semantic_overlap"]:
                raise ValueError("eligible supplemental task overlaps prior semantic pool")
            eligible_rows.append({**task, "adjudication": decision})
        else:
            excluded_rows.append(
                {
                    "source_record_id": record_id,
                    "cwe": task["cwe"],
                    "source_prompt_sha256": task["exact_prompt_sha256"],
                    **decision,
                }
            )
    if len(eligible_rows) != config["expected_eligible_units"]:
        raise ValueError("supplemental validation eligible count failed validation")

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in eligible_rows:
        grouped.setdefault(str(row["adjudication"]["semantic_group_id"]), []).append(row)
    if len(grouped) != config["expected_supplemental_clusters"]:
        raise ValueError("supplemental validation cluster count failed validation")

    supplemental_clusters: list[dict[str, object]] = []
    selected_prompts: list[dict[str, object]] = []
    for group_id, members in sorted(grouped.items()):
        cwes = {str(row["cwe"]) for row in members}
        if len(cwes) != 1:
            raise ValueError("supplemental validation cluster crossed CWE scope")
        ordered = sorted(members, key=lambda row: str(row["source_record_id"]))
        representative = ordered[0]
        cluster = {
            "schema_version": _SCHEMA_VERSION,
            "semantic_cluster_id": _cluster_id(group_id, ordered),
            "semantic_group_id": group_id,
            "cwe": next(iter(cwes)),
            "language": "python",
            "source_id": "codesec_eval_seceval_plus",
            "representative_record_id": representative["source_record_id"],
            "source_prompt_sha256": representative["exact_prompt_sha256"],
            "members": [str(row["source_record_id"]) for row in ordered],
            "merge_basis": (
                "singleton_after_protocol_adjudication"
                if len(ordered) == 1
                else "same_observable_programming_task"
            ),
            "selection_status": "independent_validation_candidate",
            "method_development_overlap": False,
            "prior_pool_semantic_overlap": False,
            "pool_origin": "codesec_eval_seceval_plus_restricted_source",
        }
        supplemental_clusters.append(cluster)
        selected_prompts.append(
            {
                **representative,
                "semantic_cluster_id": cluster["semantic_cluster_id"],
                "semantic_group_id": group_id,
            }
        )

    prior_hashes = {str(row.get("source_prompt_sha256")) for row in prior}
    if len(prior_hashes) != len(prior) or any(
        str(row["source_prompt_sha256"]) in prior_hashes for row in supplemental_clusters
    ):
        raise ValueError("supplemental validation prompt independence failed validation")
    final_clusters = [
        {**row, "pool_origin": "prior_external_public_sources"} for row in prior
    ] + supplemental_clusters
    by_cwe = dict(sorted(Counter(str(row["cwe"]) for row in final_clusters).items()))
    missing = [cwe for cwe in _CWES if by_cwe.get(cwe, 0) == 0]
    ready = len(final_clusters) >= config["minimum_validation_tasks"] and not missing
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": (
            "INDEPENDENT_VALIDATION_POOL_READY_FOR_MEASUREMENT_FREEZE"
            if ready
            else "INDEPENDENT_VALIDATION_POOL_BLOCKED"
        ),
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "reference_fields_consumed": 0,
        "raw_prompts_publicly_redistributed": 0,
        "counts": {
            "prior_clusters": len(prior),
            "supplemental_review_units": len(review),
            "supplemental_eligible_units": len(eligible_rows),
            "supplemental_clusters": len(supplemental_clusters),
            "supplemental_exclusions": len(excluded_rows),
            "final_independent_clusters": len(final_clusters),
            "minimum_validation_tasks": config["minimum_validation_tasks"],
        },
        "final_clusters_by_cwe": by_cwe,
        "missing_required_cwes": missing,
        "license_constraint": "CodeSecEval source license is under review; raw source prompts remain restricted and are not redistributed in public artifacts.",
        "next_action": (
            "freeze_measurement_judge_intervention_and_analysis_contracts"
            if ready
            else "acquire_additional_semantically_independent_tasks"
        ),
    }

    restricted_run_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(restricted_run_dir / "supplemental-selected-prompts.jsonl", selected_prompts)
    _write_json(
        restricted_run_dir / "receipt.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "selected_prompts": len(selected_prompts),
            "source_license_status": "under_review",
            "raw_redistribution_allowed": False,
        },
    )
    _write_json(restricted_run_dir / "artifact-manifest.json", _manifest(restricted_run_dir))

    public_run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(public_run_dir / "effective-config.json", config)
    _write_json(public_run_dir / "environment.json", _environment())
    _write_jsonl(public_run_dir / "supplemental-clusters.jsonl", supplemental_clusters)
    _write_jsonl(public_run_dir / "excluded-units.jsonl", excluded_rows)
    _write_jsonl(public_run_dir / "final-validation-clusters.jsonl", final_clusters)
    _write_jsonl(
        public_run_dir / "commands.jsonl",
        [{"argv": list(command_argv), "provider_calls": 0, "outcomes_consumed": 0}],
    )
    _write_json(public_run_dir / "report.json", report)
    _write_json(public_run_dir / "artifact-manifest.json", _manifest(public_run_dir))
    return report


__all__ = ["freeze_supplemental_validation_pool"]

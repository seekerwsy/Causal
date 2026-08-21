"""Restricted, outcome-blind audit of the CodeSecEval SecEvalPlus source."""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.dataset_audit.fingerprints import (
    exact_prompt_sha256,
    normalized_prompt_sha256,
)
from secaware.dataset_audit.neutrality import classify_neutrality
from secaware.pipeline.artifact import sha256_file

_SCHEMA_VERSION = "1.0"
_TARGET_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_ID_PATTERN = re.compile(r"^CWE-0*([0-9]+)(?:_|-)")
_REFERENCE_FIELDS = ("Insecure Code", "Secure Code", "Test", "Test-SP")


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
            raise ValueError("CodeSecEval audit JSONL row failed validation")
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
        raise ValueError("CodeSecEval repository input failed validation")
    relative = record.get("path")
    digest = record.get("sha256")
    if type(relative) is not str or type(digest) is not str or len(digest) != 64:
        raise ValueError("CodeSecEval repository input failed validation")
    path = (repo_root / relative).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError("CodeSecEval repository input escaped repository") from None
    if not path.is_file() or sha256_file(path) != digest:
        raise ValueError("CodeSecEval repository input digest failed validation")
    return path


def _validate_config(
    repo_root: Path, config_path: Path, source_path: Path
) -> tuple[dict[str, Any], dict[str, Path]]:
    config = _read_json(config_path)
    inputs = config.get("repository_inputs") if type(config) is dict else None
    source = config.get("source") if type(config) is dict else None
    if (
        type(config) is not dict
        or config.get("schema_version") != _SCHEMA_VERSION
        or config.get("audit_id") != "five_cwe_codesec_eval_plus_source_audit_v1"
        or config.get("target_cwes") != list(_TARGET_CWES)
        or config.get("provider_calls_allowed") is not False
        or config.get("outcomes_allowed") is not False
        or config.get("raw_reference_fields_allowed") is not False
        or type(inputs) is not dict
        or set(inputs)
        != {
            "method_development_selection",
            "prior_independent_candidates",
            "repository_record_audit",
        }
        or type(source) is not dict
        or source.get("subset") != "SecEvalPlus"
        or source.get("expected_rows") != 140
        or source.get("raw_redistribution_allowed") is not False
        or source.get("license_status") != "under_review"
    ):
        raise ValueError("CodeSecEval source configuration failed validation")
    digest = source.get("file_sha256")
    if type(digest) is not str or len(digest) != 64:
        raise ValueError("CodeSecEval source digest failed validation")
    if not source_path.is_file() or sha256_file(source_path) != digest:
        raise ValueError("CodeSecEval source digest failed validation")
    return config, {name: _repo_input(repo_root, value) for name, value in inputs.items()}


def _cwe(identifier: str) -> str | None:
    match = _ID_PATTERN.match(identifier)
    return f"CWE-{int(match.group(1))}" if match else None


def _source_rows(source_path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for line_number, line in enumerate(
        source_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue
        raw = json.loads(line)
        if type(raw) is not dict:
            raise ValueError("CodeSecEval source row failed validation")
        identifier = raw.get("ID")
        prompt = raw.get("Problem")
        entry_point = raw.get("Entry_Point")
        functional_test = raw.get("Test-FP")
        if (
            type(identifier) is not str
            or not identifier
            or identifier in identifiers
            or type(prompt) is not str
            or not prompt.strip()
            or type(entry_point) is not str
            or not entry_point
            or type(functional_test) is not str
        ):
            raise ValueError("CodeSecEval source fields failed validation")
        if any(field not in raw for field in _REFERENCE_FIELDS):
            raise ValueError("CodeSecEval reference-field schema failed validation")
        identifiers.add(identifier)
        neutrality = classify_neutrality(prompt)
        rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "source_id": "codesec_eval_seceval_plus",
                "source_record_id": identifier,
                "source_line_number": line_number,
                "source_path": "data/SecEvalPlus/test.jsonl",
                "benchmark_variant": "problem_only",
                "cwe": _cwe(identifier),
                "language": "python",
                "prompt": prompt,
                "entry_point": entry_point,
                "exact_prompt_sha256": exact_prompt_sha256(prompt),
                "normalized_prompt_sha256": normalized_prompt_sha256(prompt),
                "neutrality_prescreen": neutrality.state.value,
                "neutrality_rule_version": neutrality.rule_version,
                "functional_contract": (
                    "executable_functional_split_declared"
                    if functional_test.strip()
                    else "empty_functional_split"
                ),
                "source_ancestry_risk": "newly_constructed_seceval_plus",
                "reference_fields_consumed": False,
            }
        )
    return rows


def _annotate(
    rows: list[dict[str, object]],
    *,
    method_hashes: set[str],
    prior_exact: set[str],
    prior_normalized: set[str],
    asset_exact: set[str],
    asset_normalized: set[str],
) -> list[dict[str, object]]:
    annotated: list[dict[str, object]] = []
    for row in rows:
        exact = str(row["exact_prompt_sha256"])
        normalized = str(row["normalized_prompt_sha256"])
        method_overlap = exact in method_hashes
        prior_exact_overlap = exact in prior_exact
        prior_normalized_overlap = normalized in prior_normalized
        asset_exact_overlap = exact in asset_exact
        asset_normalized_overlap = normalized in asset_normalized
        if method_overlap:
            review_status = "excluded_method_development_exact_overlap"
        elif row.get("cwe") not in _TARGET_CWES:
            review_status = "outside_frozen_cwe_scope"
        elif prior_exact_overlap:
            review_status = "excluded_prior_pool_exact_overlap"
        elif row["neutrality_prescreen"] == "OBVIOUS_CONFLICT":
            review_status = "excluded_neutrality_conflict"
        else:
            review_status = "blinded_task_review_required"
        annotated.append(
            {
                **row,
                "method_development_exact_overlap": method_overlap,
                "prior_pool_exact_overlap": prior_exact_overlap,
                "prior_pool_normalized_overlap": prior_normalized_overlap,
                "repository_asset_exact_overlap": asset_exact_overlap,
                "repository_asset_normalized_overlap": asset_normalized_overlap,
                "semantic_overlap_status": (
                    "prior_pool_normalized_overlap"
                    if prior_normalized_overlap
                    else "manual_semantic_review_required"
                ),
                "validation_stratum": "python_primary_candidate",
                "review_status": review_status,
            }
        )
    return annotated


def _public_metadata(row: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in row.items() if key != "prompt"}


def _manifest(root: Path) -> dict[str, object]:
    files = [path for path in root.rglob("*") if path.is_file()]
    return {
        "schema_version": _SCHEMA_VERSION,
        "files": [
            {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
            for path in sorted(files)
        ],
    }


def audit_codesec_eval_plus_source(
    *,
    repo_root: Path,
    config_path: Path,
    source_path: Path,
    public_run_dir: Path,
    restricted_run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Audit only task-facing fields and keep raw prompts out of public artifacts."""

    if public_run_dir.exists() or restricted_run_dir.exists():
        raise FileExistsError(public_run_dir if public_run_dir.exists() else restricted_run_dir)
    config, inputs = _validate_config(repo_root, config_path, source_path)
    selection = _read_json(inputs["method_development_selection"])
    prior = _read_jsonl(inputs["prior_independent_candidates"])
    assets = _read_jsonl(inputs["repository_record_audit"])
    if type(selection) is not dict or type(selection.get("tasks")) is not list:
        raise ValueError("CodeSecEval method-development selection failed validation")
    method_hashes = {str(row.get("source_prompt_sha256")) for row in selection["tasks"]}
    if len(method_hashes) != 93:
        raise ValueError("CodeSecEval method-development population failed validation")
    prior_exact = {str(row.get("source_prompt_sha256")) for row in prior}
    prior_normalized = {
        normalized_prompt_sha256(str(row.get("prompt")))
        for row in prior
        if type(row.get("prompt")) is str
    }
    if len(prior) != 40 or len(prior_exact) != 40:
        raise ValueError("CodeSecEval prior independent pool failed validation")
    asset_exact = {str(row.get("exact_prompt_sha256")) for row in assets}
    asset_normalized = {str(row.get("normalized_prompt_sha256")) for row in assets}

    rows = _source_rows(source_path)
    if len(rows) != config["source"]["expected_rows"]:
        raise ValueError("CodeSecEval source row count failed validation")
    annotated = _annotate(
        rows,
        method_hashes=method_hashes,
        prior_exact=prior_exact,
        prior_normalized=prior_normalized,
        asset_exact=asset_exact,
        asset_normalized=asset_normalized,
    )
    target = [row for row in annotated if row.get("cwe") in _TARGET_CWES]
    review = [row for row in target if row["review_status"] == "blinded_task_review_required"]
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "EXTERNAL_SOURCE_BLINDED_REVIEW_REQUIRED",
        "scientific_claim_allowed": False,
        "provider_calls": 0,
        "outcomes_consumed": 0,
        "reference_fields_consumed": 0,
        "raw_prompts_publicly_redistributed": 0,
        "counts": {
            "source_rows": len(rows),
            "five_cwe_tasks": len(target),
            "blinded_task_review_required": len(review),
            "five_cwe_by_cwe": dict(
                sorted(Counter(str(row["cwe"]) for row in target).items())
            ),
            "review_queue_by_cwe": dict(
                sorted(Counter(str(row["cwe"]) for row in review).items())
            ),
            "method_development_exact_overlap": sum(
                bool(row["method_development_exact_overlap"]) for row in target
            ),
            "prior_pool_exact_overlap": sum(
                bool(row["prior_pool_exact_overlap"]) for row in target
            ),
            "prior_pool_normalized_overlap": sum(
                bool(row["prior_pool_normalized_overlap"]) for row in target
            ),
            "repository_asset_exact_overlap": sum(
                bool(row["repository_asset_exact_overlap"]) for row in target
            ),
            "repository_asset_normalized_overlap": sum(
                bool(row["repository_asset_normalized_overlap"]) for row in target
            ),
            "neutrality_conflicts": sum(
                row["review_status"] == "excluded_neutrality_conflict" for row in target
            ),
        },
        "source_receipt": {
            "revision": config["source"]["revision"],
            "file_sha256": sha256_file(source_path),
            "license_status": config["source"]["license_status"],
            "raw_redistribution_allowed": False,
        },
        "next_action": "complete_outcome_blind_task_eligibility_and_semantic_deduplication",
    }

    restricted_run_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(restricted_run_dir / "five-cwe-review-queue.jsonl", review)
    _write_json(
        restricted_run_dir / "receipt.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "source_path": str(source_path.resolve()),
            "source_sha256": sha256_file(source_path),
            "prompt_rows": len(review),
            "reference_fields_retained": [],
        },
    )
    _write_json(restricted_run_dir / "artifact-manifest.json", _manifest(restricted_run_dir))

    public_run_dir.mkdir(parents=True, exist_ok=False)
    _write_json(public_run_dir / "effective-config.json", config)
    _write_json(public_run_dir / "environment.json", _environment())
    _write_jsonl(public_run_dir / "source-metadata.jsonl", [_public_metadata(row) for row in annotated])
    _write_jsonl(public_run_dir / "five-cwe-review-metadata.jsonl", [_public_metadata(row) for row in review])
    _write_json(
        public_run_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": list(command_argv), "provider_calls": 0},
    )
    _write_json(public_run_dir / "report.json", report)
    _write_json(public_run_dir / "artifact-manifest.json", _manifest(public_run_dir))
    return report


__all__ = ["audit_codesec_eval_plus_source"]

"""Validate the outcome-blind Identity-family data scope decision."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.records import content_hash


IDENTITY_CWES = frozenset(
    {"CWE-200", "CWE-287", "CWE-306", "CWE-732", "CWE-798", "CWE-862"}
)
IDENTITY_OBSERVED_CWES = IDENTITY_CWES - {"CWE-287"}


class IdentityScopeError(ValueError):
    """The frozen Identity scope does not match its data or provenance."""


def validate_identity_scope(
    decision_path: Path,
    final_dataset_path: Path,
    repository_root: Path,
) -> dict[str, Any]:
    """Replay the 48-task census and its three measurement strata."""

    decision = _object(read_json(decision_path), "Identity scope decision")
    rows = _rows(read_json(final_dataset_path), "final dataset")
    root = repository_root.resolve()
    if (
        decision.get("schema_version") != "1.0"
        or decision.get("decision_basis") != "complete_outcome_blind_quality_census"
        or decision.get("arms_or_outcomes_used") is not False
    ):
        raise IdentityScopeError("Identity scope is not an outcome-blind v1 census")

    family = _object(decision.get("family_definition"), "family definition")
    if (
        family.get("language") != "python"
        or set(family.get("planned_cwes", [])) != IDENTITY_CWES
        or set(family.get("observed_cwes", [])) != IDENTITY_OBSERVED_CWES
        or family.get("zero_count_cwes") != ["CWE-287"]
        or family.get("planning_target_is_admission_gate") is not False
    ):
        raise IdentityScopeError("Identity family definition drift")

    strata = _object(decision.get("measurement_strata"), "measurement strata")
    if set(strata) != {
        "qualified_static",
        "source_native_safety_test_candidate",
        "contextual_or_incomplete_oracle",
    }:
        raise IdentityScopeError("Identity measurement strata drift")
    ids_by_stratum: dict[str, tuple[str, ...]] = {}
    for name, value in strata.items():
        stratum = _object(value, f"{name} stratum")
        task_ids = tuple(stratum.get("task_unit_ids", []))
        if (
            not task_ids
            or any(not isinstance(item, str) or not item for item in task_ids)
            or task_ids != tuple(sorted(set(task_ids)))
            or stratum.get("count") != len(task_ids)
        ):
            raise IdentityScopeError(f"{name} task identities are invalid")
        ids_by_stratum[name] = task_ids
    all_ids = tuple(item for values in ids_by_stratum.values() for item in values)
    if len(all_ids) != len(set(all_ids)) or len(all_ids) != family.get(
        "quality_qualified_task_units"
    ):
        raise IdentityScopeError("Identity strata are overlapping or incomplete")

    identity_rows = {
        row["task_unit_id"]: row
        for row in rows
        if row.get("language") == "python" and row.get("primary_cwe") in IDENTITY_CWES
    }
    if set(identity_rows) != set(all_ids):
        raise IdentityScopeError("Identity scope does not equal the final-data census")
    for task_id in ids_by_stratum["qualified_static"]:
        if identity_rows[task_id].get("candidate_status") != "READY_CONFIRMATORY":
            raise IdentityScopeError("static stratum contains a non-ready task")
    source_native = [
        identity_rows[task_id]
        for task_id in ids_by_stratum["source_native_safety_test_candidate"]
    ]
    if any(
        row.get("source_test_available") is not True
        or row.get("primary_cwe") not in {"CWE-200", "CWE-862"}
        for row in source_native
    ):
        raise IdentityScopeError("source-native stratum lacks an audited test boundary")
    contextual = set(ids_by_stratum["contextual_or_incomplete_oracle"])
    if contextual != set(identity_rows) - set(ids_by_stratum["qualified_static"]) - set(
        ids_by_stratum["source_native_safety_test_candidate"]
    ):
        raise IdentityScopeError("contextual stratum is not the exact census remainder")

    audit = _object(decision.get("source_test_audit"), "source-test audit")
    accepted_by_cwe = {
        cwe: sum(row.get("primary_cwe") == cwe for row in source_native)
        for cwe in sorted({row.get("primary_cwe") for row in source_native})
    }
    if audit.get("accepted_by_cwe") != accepted_by_cwe:
        raise IdentityScopeError("source-test CWE counts drift")
    for item in _rows(audit.get("source_files"), "source files"):
        path = (root / _text(item.get("path"), "source path")).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise IdentityScopeError("source-test path escapes the repository") from error
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item.get(
            "sha256"
        ):
            raise IdentityScopeError("source-test provenance is missing or stale")

    next_gate = _object(decision.get("next_gate"), "next gate")
    if next_gate.get("formal_execution_authorized") is not False:
        raise IdentityScopeError("the unqualified executable Oracle cannot authorize a run")
    return {
        "status": "IDENTITY_SCOPE_VERIFIED_EXECUTABLE_ORACLE_PENDING",
        "identity_task_units": len(identity_rows),
        "measurement_stratum_counts": {
            name: len(values) for name, values in ids_by_stratum.items()
        },
        "decision_sha256": content_hash(decision),
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
    }


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IdentityScopeError(f"{label} must be a JSON object")
    return value


def _rows(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise IdentityScopeError(f"{label} must be a JSON object list")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityScopeError(f"{label} must be non-empty text")
    return value


__all__ = [
    "IDENTITY_CWES",
    "IDENTITY_OBSERVED_CWES",
    "IdentityScopeError",
    "validate_identity_scope",
]

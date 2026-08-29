"""Shared validation for frozen pre-experiment qualification evidence.

This module owns only artifact parsing, identity binding, and common power-plan
checks.  Study-specific support and result verification remain in their
respective experiment and verifier modules.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    confined_path,
    json_object,
    require_file_hash,
)
from prompt_mechanism_study.records import content_id


class QualificationError(ValueError):
    """Frozen qualification evidence is malformed or no longer bound."""


FUNCTIONAL_QUALIFICATION_FIELDS = frozenset(
    {
        "qualification_path",
        "qualification_sha256",
        "qualification",
        "qualification_payload",
        "qualification_identity",
    }
)


def load_functional_qualification(
    root: Path,
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool = False,
    include_evaluator_metadata: bool = False,
    confine_to_root: bool = True,
) -> dict[str, Any]:
    """Read, seal, and revalidate one Functional Judge qualification file."""

    try:
        stored_path = section.get("qualification_path")
        if confine_to_root:
            path = confined_path(root, stored_path)
        elif isinstance(stored_path, str) and stored_path:
            raw_path = Path(stored_path)
            path = (
                raw_path.resolve()
                if raw_path.is_absolute()
                else (root.resolve() / raw_path).resolve()
            )
        else:
            raise ValueError("stored path is invalid")
        require_file_hash(path, section.get("qualification_sha256"))
        payload = path.read_bytes()
    except (OSError, ValueError) as error:
        raise QualificationError(str(error)) from error
    try:
        payload_text = payload.decode("utf-8")
    except UnicodeError:
        raise QualificationError("functional qualification is not UTF-8") from None
    qualification = _json_object(payload, "functional qualification")
    sealed = {
        "qualification_path": stored_path,
        "qualification_sha256": hashlib.sha256(payload).hexdigest(),
        "qualification": qualification,
        "qualification_payload": payload_text,
        "qualification_identity": functional_qualification_identity(
            qualification,
            section,
            evaluator,
            structural_smoke_allowed=structural_smoke_allowed,
            include_evaluator_metadata=include_evaluator_metadata,
        ),
    }
    return validate_functional_qualification(
        section,
        evaluator,
        sealed,
        structural_smoke_allowed=structural_smoke_allowed,
        include_evaluator_metadata=include_evaluator_metadata,
    )


def validate_functional_qualification(
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    sealed: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool = False,
    include_evaluator_metadata: bool = False,
) -> dict[str, Any]:
    """Replay a bundled Functional Judge seal without reading its source path."""

    if set(sealed) != FUNCTIONAL_QUALIFICATION_FIELDS:
        raise QualificationError("functional qualification fields are not exact")
    payload = sealed.get("qualification_payload")
    qualification = sealed.get("qualification")
    if not isinstance(payload, str) or not payload:
        raise QualificationError("functional qualification payload is invalid")
    if not isinstance(qualification, Mapping):
        raise QualificationError("functional qualification is not an object")
    parsed = _json_object(payload.encode("utf-8"), "functional qualification payload")
    expected_identity = functional_qualification_identity(
        qualification,
        section,
        evaluator,
        structural_smoke_allowed=structural_smoke_allowed,
        include_evaluator_metadata=include_evaluator_metadata,
    )
    if (
        sealed.get("qualification_path") != section.get("qualification_path")
        or sealed.get("qualification_sha256") != section.get("qualification_sha256")
        or hashlib.sha256(payload.encode("utf-8")).hexdigest()
        != section.get("qualification_sha256")
        or parsed != qualification
        or sealed.get("qualification_identity") != expected_identity
    ):
        raise QualificationError("functional qualification drift")
    return dict(sealed)


def functional_qualification_identity(
    qualification: Mapping[str, Any],
    section: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    *,
    structural_smoke_allowed: bool = False,
    include_evaluator_metadata: bool = False,
) -> dict[str, Any]:
    """Validate qualification semantics and return its frozen identity."""

    candidate = qualification.get("candidate")
    if not isinstance(candidate, Mapping):
        raise QualificationError("functional qualification candidate is invalid")
    status = qualification.get("status")
    structural_smoke = status == "STRUCTURAL_SMOKE_ONLY"
    if structural_smoke and not (
        structural_smoke_allowed
        and evaluator.get("provider") == "offline_deterministic_test_fixture"
        and evaluator.get("fixture_only") is True
        and evaluator.get("scientific_claim_allowed") is False
        and qualification.get("semantic_accuracy_claimed") is False
        and qualification.get("scientific_claim_allowed") is False
    ):
        raise QualificationError("structural-smoke-only functional qualification is not allowed")
    allowed_statuses = (
        {"QUALIFIED_FOR_EXPERIMENT", "STRUCTURAL_SMOKE_ONLY"}
        if structural_smoke_allowed
        else {"QUALIFIED_FOR_EXPERIMENT"}
    )
    if (
        qualification.get("schema_version") != "1.0"
        or status not in allowed_statuses
        or candidate.get("candidate_id") != evaluator.get("candidate_id")
        or candidate.get("model_id") != evaluator.get("model_id")
        or candidate.get("evaluator_config_sha256") != section.get("evaluator_config_sha256")
        or candidate.get("prompt_sha256") != section.get("prompt_sha256")
    ):
        raise QualificationError("functional qualification drift")
    identity = {
        "qualification_id": content_id("functional_judge_qualification_v1_", qualification),
        "status": status,
        "candidate_id": candidate.get("candidate_id"),
        "model_id": candidate.get("model_id"),
        "evaluator_config_sha256": candidate.get("evaluator_config_sha256"),
        "prompt_sha256": candidate.get("prompt_sha256"),
    }
    if include_evaluator_metadata:
        identity.update(
            {
                "provider": evaluator.get("provider"),
                "fixture_only": evaluator.get("fixture_only"),
                "evaluator_scientific_claim_allowed": evaluator.get("scientific_claim_allowed"),
            }
        )
    return identity


def validate_functionality_power_payload(
    payload: Any,
    analysis: Mapping[str, Any],
    *,
    expected_coordinate: Mapping[str, str],
    expected_model_policy: Mapping[str, Any] | None = None,
    expected_assumption_keys: frozenset[str] | None = None,
) -> int:
    """Validate the common prospective functionality power-plan contract."""

    required = {
        "schema_version",
        "qualification_status",
        "analysis_coordinate",
        "planned_task_units_per_coordinate",
        "target_power",
        "familywise_alpha",
        "noninferiority_margin",
        "power_method",
        "assumptions",
    }
    if expected_model_policy is not None:
        required.add("model_policy")
    assumptions = payload.get("assumptions") if isinstance(payload, Mapping) else None
    model_policy_valid = (
        payload.get("model_policy") == expected_model_policy
        if isinstance(payload, Mapping) and expected_model_policy is not None
        else isinstance(payload, Mapping) and "model_policy" not in payload
    )
    if (
        not isinstance(payload, Mapping)
        or set(payload) != required
        or payload.get("schema_version") != "1.0"
        or payload.get("qualification_status") != "supported"
        or payload.get("analysis_coordinate") != dict(expected_coordinate)
        or type(payload.get("planned_task_units_per_coordinate")) is not int
        or payload["planned_task_units_per_coordinate"] < analysis.get("minimum_task_units", 2)
        or not model_policy_valid
    ):
        raise QualificationError("functionality power qualification is unsupported or incomplete")
    if (
        type(payload.get("target_power")) is not float
        or not 0.8 <= payload["target_power"] < 1.0
        or payload.get("familywise_alpha") != analysis["familywise_alpha"]
        or payload.get("noninferiority_margin")
        != analysis.get("functionality_noninferiority_margin", 0.1)
        or not isinstance(payload.get("power_method"), str)
        or not payload["power_method"].strip()
        or not isinstance(assumptions, Mapping)
        or not assumptions
        or any(not isinstance(key, str) or not key for key in assumptions)
        or (expected_assumption_keys is not None and set(assumptions) != expected_assumption_keys)
    ):
        raise QualificationError("functionality power qualification is unsupported or incomplete")
    if expected_assumption_keys is not None and (
        type(assumptions["baseline_functionality_rate"]) is not float
        or not 0.0 <= assumptions["baseline_functionality_rate"] <= 1.0
        or type(assumptions["alternative_difference"]) is not float
        or not -1.0 <= assumptions["alternative_difference"] <= 1.0
        or assumptions["alternative_difference"]
        <= -analysis.get("functionality_noninferiority_margin", 0.1)
        or type(assumptions["paired_task_unit_correlation"]) is not float
        or not -1.0 <= assumptions["paired_task_unit_correlation"] <= 1.0
    ):
        raise QualificationError("functionality power qualification is unsupported or incomplete")
    return payload["planned_task_units_per_coordinate"]


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        return json_object(payload)
    except ValueError:
        raise QualificationError(f"{label} is invalid JSON") from None


__all__ = [
    "FUNCTIONAL_QUALIFICATION_FIELDS",
    "QualificationError",
    "functional_qualification_identity",
    "load_functional_qualification",
    "validate_functional_qualification",
    "validate_functionality_power_payload",
]

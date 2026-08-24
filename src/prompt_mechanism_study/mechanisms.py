"""Data-driven, context-conditioned mechanism specifications."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.records import content_id


class MechanismRegistryError(ValueError):
    """Raised when a mechanism registry or task binding is invalid."""


def load_mechanism_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load and validate a registry keyed by realization id."""

    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"schema_version", "mechanisms"} or value["schema_version"] not in {
        "1.0",
        "2.0",
    }:
        raise MechanismRegistryError("mechanism registry envelope is invalid")
    rows = value["mechanisms"]
    if not isinstance(rows, list) or not rows:
        raise MechanismRegistryError("mechanism registry is empty")
    result: dict[str, dict[str, Any]] = {}
    legacy_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "prompt_markers",
        "oracle_profile_id",
        "specific_contract",
        "must_preserve",
    }
    context_fields = {
        "realization_id",
        "cwe_id",
        "task_family",
        "required_context",
        "excluded_context",
        "oracle_profile_id",
        "required_delta",
        "forbidden_delta",
        "must_preserve",
    }
    required = legacy_fields if value["schema_version"] == "1.0" else context_fields
    for row in rows:
        if not isinstance(row, dict) or set(row) != required:
            raise MechanismRegistryError("mechanism record fields are invalid")
        realization_id = row["realization_id"]
        scalar_fields = ("realization_id", "cwe_id", "task_family", "oracle_profile_id")
        list_fields = (
            ("prompt_markers", "must_preserve")
            if value["schema_version"] == "1.0"
            else (
                "required_context",
                "excluded_context",
                "required_delta",
                "forbidden_delta",
                "must_preserve",
            )
        )
        if (
            any(not isinstance(row[field], str) or not row[field] for field in scalar_fields)
            or any(
                not isinstance(row[field], list)
                or any(not isinstance(item, str) or not item for item in row[field])
                for field in list_fields
            )
            or (
                value["schema_version"] == "1.0"
                and (
                    not isinstance(row["specific_contract"], str)
                    or not row["specific_contract"].strip()
                )
            )
            or (
                value["schema_version"] == "2.0"
                and (
                    not row["required_delta"]
                    or set(row["required_context"]) & set(row["excluded_context"])
                )
            )
            or realization_id in result
        ):
            raise MechanismRegistryError("mechanism record values are invalid")
        result[realization_id] = row
    return result


def select_mechanism(
    task: Mapping[str, Any], registry: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Resolve exactly one mechanism from frozen task-side information."""

    explicit = task.get("realization_id")
    if explicit is not None:
        row = registry.get(explicit)
        if row is None or row["cwe_id"] != task.get("cwe"):
            raise MechanismRegistryError("task realization binding is invalid")
        if "required_delta" in row:
            _validate_context_binding(task, row)
        return dict(row)

    prompt = " ".join(str(task.get("prompt", "")).casefold().split())
    family = task.get("task_family")
    candidates = []
    for row in registry.values():
        if "required_delta" in row:
            continue
        if row["cwe_id"] != task.get("cwe") or row["task_family"] != family:
            continue
        markers = row["prompt_markers"]
        if not markers or any(marker.casefold() in prompt for marker in markers):
            candidates.append(row)
    if len(candidates) != 1:
        raise MechanismRegistryError("task does not resolve to exactly one mechanism")
    return dict(candidates[0])


def compatible_mechanisms(
    task: Mapping[str, Any],
    context_facts: list[str],
    registry: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Resolve context-conditioned candidates without consulting arms or outcomes."""

    if (
        not isinstance(context_facts, list)
        or any(not isinstance(item, str) or not item.strip() for item in context_facts)
        or len(context_facts) != len(set(context_facts))
    ):
        raise MechanismRegistryError("task context facts are invalid")
    facts = set(context_facts)
    matches = []
    for row in registry.values():
        if "required_delta" not in row:
            continue
        if row["cwe_id"] != task.get("cwe") or row["task_family"] != task.get("task_family"):
            continue
        if set(row["required_context"]) <= facts and not set(row["excluded_context"]) & facts:
            matches.append(dict(row))
    return sorted(matches, key=lambda row: row["realization_id"])


def mechanism_binding_id(binding: Mapping[str, Any]) -> str:
    """Return the content identity of one task-side binding core."""

    core = {key: value for key, value in binding.items() if key != "binding_id"}
    return content_id("mechanism_binding_", core)


def _validate_context_binding(task: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    binding = task.get("mechanism_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "binding_id",
        "decision",
        "realization_id",
        "context_facts",
        "evidence",
        "source_prompt_sha256",
        "functional_contract_id",
        "outcomes_or_arms_used",
    }:
        raise MechanismRegistryError("context-conditioned mechanism binding is missing")
    facts = binding["context_facts"]
    evidence = binding["evidence"]
    if (
        binding["decision"] != "applicable"
        or binding["realization_id"] != row["realization_id"]
        or binding["source_prompt_sha256"] != task.get("source_prompt_sha256")
        or binding["functional_contract_id"]
        != task.get("functional_contract", {}).get("contract_id")
        or binding["outcomes_or_arms_used"] is not False
        or not isinstance(evidence, list)
        or not evidence
        or any(not isinstance(item, str) or not item.strip() for item in evidence)
        or mechanism_binding_id(binding) != binding["binding_id"]
    ):
        raise MechanismRegistryError("context-conditioned mechanism binding is invalid")
    matches = compatible_mechanisms(task, facts, {row["realization_id"]: row})
    if len(matches) != 1:
        raise MechanismRegistryError("task context does not satisfy the bound mechanism")


__all__ = [
    "MechanismRegistryError",
    "compatible_mechanisms",
    "load_mechanism_registry",
    "mechanism_binding_id",
    "select_mechanism",
]

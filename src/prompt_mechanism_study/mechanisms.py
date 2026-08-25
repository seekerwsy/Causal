"""Data-driven, context-conditioned mechanism specifications."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.records import content_id
from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    QueryState,
    feature_state,
    prompt_tsg_from_record,
    query_context,
    query_for_realization,
)
from prompt_mechanism_study.records import content_hash


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
        if "prompt_tsg_binding" in task:
            _validate_tsg_binding(task, row)
        elif "required_delta" in row:
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


def tsg_mechanism_binding(
    task: Mapping[str, Any],
    graph: PromptTSG,
    catalog: Mapping[str, Any],
    registry: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind one task using only its frozen Prompt TSG and finite catalog queries."""

    relevant = [
        row
        for row in registry.values()
        if row["cwe_id"] == task.get("cwe") and row["task_family"] == task.get("task_family")
    ]
    results = []
    for row in sorted(relevant, key=lambda item: item["realization_id"]):
        query = query_for_realization(catalog, row["realization_id"])
        result = query_context(
            graph,
            query=query,
            cwe=task["cwe"],
            task_family=task["task_family"],
        )
        results.append((row, query, result))
    present = [item for item in results if item[2].state == QueryState.PRESENT]
    selected = present[0] if len(present) == 1 else None
    feature = selected[1]["actionable_feature_id"] if selected else None
    target_state = feature_state(graph, feature).value if feature else "not_applicable"
    controls = {
        semantic_id: feature_state(graph, semantic_id).value
        for semantic_id in ("control.generic_security", "control.code_style")
    }
    if len(present) > 1 or (not present and any(
        item[2].state == QueryState.UNRESOLVED for item in results
    )):
        decision = "unresolved"
    elif not present:
        decision = "not_applicable"
    elif target_state != QueryState.ABSENT.value:
        decision = "target_feature_present" if target_state == "present" else "unresolved"
    elif any(state != QueryState.ABSENT.value for state in controls.values()):
        decision = "control_feature_present"
    else:
        decision = "applicable"
    core = {
        "decision": decision,
        "realization_id": selected[0]["realization_id"] if selected else None,
        "prompt_tsg_id": graph.tsg_id,
        "context_query_id": selected[1]["query_id"] if selected else None,
        "context_state": selected[2].state.value if selected else "unresolved" if decision == "unresolved" else "absent",
        "actionable_feature_id": feature,
        "target_feature_state": target_state,
        "control_feature_states": controls,
        "evidence_node_ids": list(selected[2].evidence_node_ids) if selected else [],
        "evidence_edge_ids": list(selected[2].evidence_edge_ids) if selected else [],
        "query_states": [
            {"query_id": query["query_id"], "state": result.state.value}
            for _, query, result in results
        ],
        "outcomes_or_arms_used": False,
    }
    return {"binding_id": mechanism_binding_id(core), **core}


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


def _validate_tsg_binding(task: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    binding = task.get("prompt_tsg_binding")
    graph_value = task.get("prompt_tsg")
    required = {
        "binding_id",
        "decision",
        "realization_id",
        "prompt_tsg_id",
        "context_query_id",
        "context_state",
        "actionable_feature_id",
        "target_feature_state",
        "control_feature_states",
        "evidence_node_ids",
        "evidence_edge_ids",
        "query_states",
        "outcomes_or_arms_used",
    }
    try:
        graph = prompt_tsg_from_record(graph_value)
    except (TypeError, ValueError):
        raise MechanismRegistryError("Prompt TSG mechanism graph is invalid") from None
    if (
        not isinstance(binding, dict)
        or set(binding) != required
        or binding["decision"] != "applicable"
        or binding["realization_id"] != row["realization_id"]
        or binding["context_state"] != "present"
        or binding["target_feature_state"] != "absent"
        or set(binding["control_feature_states"].values()) != {"absent"}
        or binding["outcomes_or_arms_used"] is not False
        or mechanism_binding_id(binding) != binding["binding_id"]
        or graph.tsg_id != binding["prompt_tsg_id"]
        or graph.task_id != task.get("task_id")
        or graph.prompt_sha256 != content_hash(task.get("prompt"))
    ):
        raise MechanismRegistryError("Prompt TSG mechanism binding is invalid")


__all__ = [
    "MechanismRegistryError",
    "compatible_mechanisms",
    "load_mechanism_registry",
    "mechanism_binding_id",
    "select_mechanism",
    "tsg_mechanism_binding",
]

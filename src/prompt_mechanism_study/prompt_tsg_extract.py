"""One-call LLM_FACTS extraction followed by deterministic Prompt TSG construction."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    build_prompt_tsg,
    catalog_sha256,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import content_hash


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


class PromptTSGExtractionError(ValueError):
    """The frozen extraction request or the model's fact proposal is invalid."""

    def __init__(
        self,
        message: str,
        *,
        request: dict[str, Any] | None = None,
        raw: bytes | None = None,
    ) -> None:
        super().__init__(message)
        self.request = request
        self.raw = raw


def extraction_request(task: Mapping[str, Any], catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Expose only the catalog slice relevant to frozen task-side coordinates."""

    required = {"task_id", "prompt", "cwe", "task_family"}
    if not required <= set(task) or any(
        not isinstance(task[field], str) or not task[field].strip() for field in required
    ):
        raise PromptTSGExtractionError("task lacks Prompt TSG extraction coordinates")
    queries = [
        query
        for query in catalog["queries"]
        if query["cwe_id"] == task["cwe"] and query["task_family"] == task["task_family"]
    ]
    if not queries:
        raise PromptTSGExtractionError("task has no catalog query")
    semantic_ids = {
        "task.requirement",
        "task.operation",
        "data.object",
        "control.generic_security",
        "control.code_style",
    }
    for query in queries:
        semantic_ids.update(query["required_semantics"])
        semantic_ids.update(query["forbidden_semantics"])
        semantic_ids.add(query["actionable_feature_id"])
    semantics = {
        semantic_id: {
            "node_type": catalog["semantics"][semantic_id],
            "guidance": catalog["semantic_guidance"].get(
                semantic_id, "Use only when directly supported by the source prompt."
            ),
        }
        for semantic_id in sorted(semantic_ids)
    }
    node_types = {value["node_type"] for value in semantics.values()}
    allowed_relations = [
        item
        for item in catalog["allowed_edges"]
        if item[0] in node_types and item[2] in node_types and item[1] != "contains"
    ]
    return {
        "schema_version": "1.0",
        "task_id": task["task_id"],
        "cwe_id": task["cwe"],
        "task_family": task["task_family"],
        "source_prompt": task["prompt"],
        "candidate_semantics": semantics,
        "allowed_attributes": list(catalog["attribute_names"]),
        "allowed_relation_type_matrix": allowed_relations,
        "context_queries": [
            {
                "query_id": query["query_id"],
                "required_semantics": query["required_semantics"],
                "forbidden_semantics": query["forbidden_semantics"],
                "required_relations": query["required_relations"],
                "actionable_feature_id": query["actionable_feature_id"],
            }
            for query in queries
        ],
        "arms_or_outcomes_included": False,
        "output_contract": {
            "top_level_keys": ["facts", "relations", "unresolved_semantics"],
            "fact_keys": [
                "local_id",
                "node_type",
                "semantic_id",
                "evidence_text",
                "occurrence",
                "attributes",
            ],
            "local_id_type": "string",
            "relation_keys": ["edge_type", "source", "target"],
            "relation_endpoints": "string_local_ids",
        },
    }


def extract_prompt_tsg(
    task: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    system_prompt: str,
    provider: Provider = bailian_complete,
) -> tuple[PromptTSG, dict[str, Any], bytes, dict[str, Any]]:
    """Run one blinded semantic fact call and validate every returned fact locally."""

    request = extraction_request(task, catalog)
    raw = provider(request, evaluator, system_prompt)
    try:
        proposal = _proposal(raw)
        relations, rejected_relations = _project_relations(
            proposal["facts"], proposal["relations"], catalog
        )
        ignored_unresolved_features = sorted(
            semantic_id
            for semantic_id in proposal["unresolved_semantics"]
            if catalog["semantics"].get(semantic_id)
            in {"safety_requirement", "presentation_control"}
        )
        unresolved_semantics = [
            semantic_id
            for semantic_id in proposal["unresolved_semantics"]
            if semantic_id not in ignored_unresolved_features
        ]
        graph = build_prompt_tsg(
            task_id=task["task_id"],
            prompt=task["prompt"],
            extractor_id=evaluator["candidate_id"],
            catalog=catalog,
            facts=proposal["facts"],
            relations=relations,
            unresolved_semantics=unresolved_semantics,
        )
    except (PromptTSGError, PromptTSGExtractionError) as error:
        raise PromptTSGExtractionError(str(error), request=request, raw=raw) from None
    offered = set(request["candidate_semantics"])
    returned = {
        fact["semantic_id"] for fact in proposal["facts"]
    } | set(proposal["unresolved_semantics"])
    if not returned <= offered:
        raise PromptTSGExtractionError(
            "extractor returned a semantic outside its task slice", request=request, raw=raw
        )
    return graph, request, raw, {
        "rejected_relations": rejected_relations,
        "ignored_unresolved_features": ignored_unresolved_features,
    }


def extract_task_file(
    tasks_path: Path,
    catalog_path: Path,
    evaluator_path: Path,
    prompt_path: Path,
    output: Path,
    *,
    start: int = 0,
    limit: int | None = None,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Extract a small frozen task file into one reviewable, content-addressed bundle."""

    if output.exists():
        raise FileExistsError(output)
    source_tasks = _json_lines(tasks_path)
    if type(start) is not int or start < 0:
        raise ValueError("start must be a non-negative integer")
    if limit is not None:
        if type(limit) is not int or limit <= 0:
            raise ValueError("limit must be a positive integer")
    tasks = source_tasks[start:] if limit is None else source_tasks[start : start + limit]
    if not tasks or len({task.get("task_id") for task in tasks}) != len(tasks):
        raise PromptTSGExtractionError("task extraction population is empty or duplicated")
    catalog = load_catalog(catalog_path)
    evaluator = _evaluator(read_json(evaluator_path))
    system_prompt = prompt_path.read_text(encoding="utf-8").strip()
    if not system_prompt:
        raise PromptTSGExtractionError("extractor prompt is empty")
    graphs = []
    requests = []
    responses = []
    failed: tuple[dict[str, Any], PromptTSGExtractionError] | None = None
    for task in tasks:
        try:
            graph, request, raw, projection = extract_prompt_tsg(
                task,
                catalog=catalog,
                evaluator=evaluator,
                system_prompt=system_prompt,
                provider=provider,
            )
        except PromptTSGExtractionError as error:
            failed = (task, error)
            if error.request is not None:
                requests.append(error.request)
            if error.raw is not None:
                responses.append(
                    {
                        "task_id": task["task_id"],
                        "response_sha256": hashlib.sha256(error.raw).hexdigest(),
                        "response_text": error.raw.decode("utf-8", errors="replace"),
                    }
                )
            break
        graphs.append(prompt_tsg_record(graph))
        requests.append({**request, "deterministic_projection": projection})
        responses.append(
            {
                "task_id": task["task_id"],
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "response_text": raw.decode("utf-8", errors="strict"),
            }
        )
    report = {
        "schema_version": "1.0",
        "status": (
            "PROMPT_TSG_EXTRACTION_COMPLETE"
            if failed is None
            else "PROMPT_TSG_EXTRACTION_ERROR"
        ),
        "tasks": len(tasks),
        "source_tasks": len(source_tasks),
        "selection_start": start,
        "graphs": len(graphs),
        "unresolved_tasks": sum(bool(graph["unresolved_semantics"]) for graph in graphs),
        "task_file_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
        "selected_task_ids_sha256": content_hash([task["task_id"] for task in tasks]),
        "catalog_sha256": catalog_sha256(catalog),
        "evaluator_sha256": hashlib.sha256(evaluator_path.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
        "arms_or_outcomes_used": False,
    }
    if failed is not None:
        report["failed_task_id"] = failed[0]["task_id"]
        report["error_type"] = type(failed[1]).__name__
        report["error_reason"] = str(failed[1])
    write_bundle(
        output,
        {
            "report.json": report,
            "graphs.json": graphs,
            "requests.json": requests,
            "responses.json": responses,
        },
    )
    return report


def _proposal(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PromptTSGExtractionError("extractor response is not JSON") from None
    if not isinstance(value, dict) or set(value) != {
        "facts",
        "relations",
        "unresolved_semantics",
    }:
        raise PromptTSGExtractionError("extractor response fields are invalid")
    if any(not isinstance(value[field], list) for field in value):
        raise PromptTSGExtractionError("extractor response collections are invalid")
    return value


def _project_relations(
    facts: Sequence[Mapping[str, Any]],
    relations: Sequence[Mapping[str, Any]],
    catalog: Mapping[str, Any],
) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]]]:
    """Drop and disclose only well-formed edges that violate the frozen type matrix."""

    node_types = {}
    for fact in facts:
        if not isinstance(fact, Mapping) or not isinstance(fact.get("local_id"), str):
            raise PromptTSGExtractionError("extractor fact identity is invalid")
        node_types[fact["local_id"]] = fact.get("node_type")
    allowed = {tuple(item) for item in catalog["allowed_edges"]}
    accepted = []
    rejected = []
    for relation in relations:
        if not isinstance(relation, Mapping) or set(relation) != {
            "edge_type",
            "source",
            "target",
        }:
            raise PromptTSGExtractionError("extractor relation fields are invalid")
        triple = (
            node_types.get(relation["source"]),
            relation["edge_type"],
            node_types.get(relation["target"]),
        )
        if triple in allowed:
            accepted.append(relation)
        else:
            rejected.append({**relation, "reason": "edge_type_matrix_violation"})
    return accepted, rejected


def _evaluator(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "candidate_id",
        "provider",
        "model_id",
        "base_url",
        "api_key_env",
        "temperature",
        "top_p",
        "seed",
        "enable_thinking",
        "timeout_seconds",
        "max_response_bytes",
        "max_attempts",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["schema_version"] != "1.0"
        or value["max_attempts"] != 1
        or value["api_key_env"] != "ALI_BAILIAN_API_KEY"
        or value["temperature"] != 0.0
    ):
        raise PromptTSGExtractionError("extractor evaluator is invalid")
    return value


def _json_lines(path: Path) -> list[dict[str, Any]]:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PromptTSGExtractionError("task file is unreadable") from None
    if any(not isinstance(row, dict) for row in rows):
        raise PromptTSGExtractionError("task file contains a non-object")
    return rows


__all__ = [
    "PromptTSGExtractionError",
    "extract_prompt_tsg",
    "extract_task_file",
    "extraction_request",
]

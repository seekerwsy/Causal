"""Blind dual annotation of exhaustive task contracts and deterministic TSG compilation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.prompt_contract import (
    RelationDecision,
    SemanticDecision,
    TaskContextContract,
    compile_task_context_contract,
    task_context_contract_record,
    task_context_scope,
)
from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    QueryState,
    catalog_sha256,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.records import content_hash


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]
_RESPONSE_FIELDS = {"semantic_decisions", "relation_decisions"}
_SEMANTIC_FIELDS = {
    "semantic_id",
    "state",
    "rationale",
    "evidence_text",
    "occurrence",
    "attributes",
}
_RELATION_FIELDS = {
    "source_semantic_id",
    "edge_type",
    "target_semantic_id",
    "state",
    "rationale",
}


class PromptContractExtractionError(RuntimeError):
    """The frozen request, model decision table, or extraction closure is invalid."""


def _close_relation_endpoint_states(
    semantic_decisions: tuple[SemanticDecision, ...],
    relation_decisions: tuple[RelationDecision, ...],
) -> tuple[RelationDecision, ...]:
    """Project relation states implied by their semantic endpoint states."""

    semantic_states = {row.semantic_id: row.state for row in semantic_decisions}
    closed = []
    for row in relation_decisions:
        endpoint_states = {
            semantic_states.get(row.source_semantic_id),
            semantic_states.get(row.target_semantic_id),
        }
        if QueryState.ABSENT in endpoint_states:
            closed.append(
                replace(
                    row,
                    state=QueryState.ABSENT,
                    rationale=(
                        "Deterministic endpoint closure: at least one endpoint is absent."
                    ),
                )
            )
        elif QueryState.UNRESOLVED in endpoint_states:
            closed.append(
                replace(
                    row,
                    state=QueryState.UNRESOLVED,
                    rationale=(
                        "Deterministic endpoint closure: at least one endpoint is unresolved."
                    ),
                )
            )
        else:
            closed.append(row)
    return tuple(closed)


def contract_decision_request(
    task: Mapping[str, Any], catalog: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the finite task-level table independently completed by both annotators."""

    required = {"task_id", "prompt", "cwe", "task_family"}
    if not required <= set(task) or any(
        not isinstance(task[field], str) or not task[field].strip() for field in required
    ):
        raise PromptContractExtractionError("task lacks contract extraction coordinates")
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    return {
        "schema_version": "1.0",
        "request_kind": "blind_exhaustive_task_context_annotation",
        "task_id": task["task_id"],
        "cwe_id": task["cwe"],
        "task_family": task["task_family"],
        "source_prompt": task["prompt"],
        "query_ids": list(scope["query_ids"]),
        "context_queries": [
            {
                "query_id": query["query_id"],
                "required_semantics": query["required_semantics"],
                "forbidden_semantics": query["forbidden_semantics"],
                "required_relations": query["required_relations"],
                "actionable_feature_id": query["actionable_feature_id"],
            }
            for query in scope["queries"]
        ],
        "candidate_semantics": {
            semantic_id: {
                "node_type": catalog["semantics"][semantic_id],
                "guidance": catalog["semantic_guidance"].get(
                    semantic_id,
                    "Mark present only when the source prompt directly entails this role.",
                ),
            }
            for semantic_id in scope["semantic_ids"]
        },
        "candidate_relations": [list(relation) for relation in scope["relations"]],
        "allowed_attributes": list(catalog["attribute_names"]),
        "decision_states": ["present", "absent", "unresolved"],
        "arms_or_outcomes_included": False,
        "output_contract": {
            "top_level_keys": ["semantic_decisions", "relation_decisions"],
            "semantic_decision_keys": sorted(_SEMANTIC_FIELDS),
            "relation_decision_keys": sorted(_RELATION_FIELDS),
            "semantic_rows": "exactly one row for every candidate_semantics key",
            "relation_rows": "exactly one row for every candidate_relations triple",
            "present_semantic_evidence": (
                "exact contiguous source_prompt substring plus 1-based occurrence"
            ),
            "attributes": (
                "JSON array of unique allowed attribute names asserted true; never an object"
            ),
            "non_present_evidence": (
                "null evidence_text, null occurrence, empty attributes array"
            ),
        },
    }


def contract_from_response(
    raw: bytes,
    *,
    task: Mapping[str, Any],
    catalog: Mapping[str, Any],
    annotator_id: str,
    review_status: str,
) -> TaskContextContract:
    """Parse one exhaustive model decision table and reject any omitted row."""

    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PromptContractExtractionError("contract response is not JSON") from None
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise PromptContractExtractionError("contract response fields are invalid")
    semantic_rows = value["semantic_decisions"]
    relation_rows = value["relation_decisions"]
    if (
        not isinstance(semantic_rows, list)
        or not isinstance(relation_rows, list)
        or any(not isinstance(row, dict) or set(row) != _SEMANTIC_FIELDS for row in semantic_rows)
        or any(not isinstance(row, dict) or set(row) != _RELATION_FIELDS for row in relation_rows)
    ):
        raise PromptContractExtractionError("contract decision rows are invalid")
    if any(
        not isinstance(row["attributes"], list)
        or any(
            not isinstance(attribute, str) or not attribute
            for attribute in row["attributes"]
        )
        or len(row["attributes"]) != len(set(row["attributes"]))
        for row in semantic_rows
    ):
        raise PromptContractExtractionError("contract semantic attributes are invalid")
    try:
        semantic_decisions = tuple(
            SemanticDecision(
                row["semantic_id"],
                QueryState(row["state"]),
                row["rationale"],
                row["evidence_text"],
                row["occurrence"],
                tuple((attribute, True) for attribute in sorted(row["attributes"])),
            )
            for row in semantic_rows
        )
        relation_decisions = tuple(
            RelationDecision(
                row["source_semantic_id"],
                row["edge_type"],
                row["target_semantic_id"],
                QueryState(row["state"]),
                row["rationale"],
            )
            for row in relation_rows
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise PromptContractExtractionError("contract decision values are invalid") from None
    relation_decisions = _close_relation_endpoint_states(
        semantic_decisions, relation_decisions
    )
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    contract = TaskContextContract(
        "2.0",
        task["task_id"],
        content_hash(task["prompt"]),
        catalog_sha256(catalog),
        task["cwe"],
        task["task_family"],
        scope["query_ids"],
        annotator_id,
        review_status,
        False,
        tuple(sorted(semantic_decisions, key=lambda row: row.semantic_id)),
        tuple(sorted(relation_decisions, key=lambda row: row.relation)),
    )
    try:
        compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    except PromptTSGError as error:
        raise PromptContractExtractionError(str(error)) from None
    return contract


def consensus_contract(
    proposer: TaskContextContract,
    reviewer: TaskContextContract,
    *,
    annotator_id: str,
) -> TaskContextContract:
    """Conservatively combine two independent tables; disagreement becomes unresolved."""

    coordinates = (
        "schema_version",
        "task_id",
        "prompt_sha256",
        "catalog_sha256",
        "cwe_id",
        "task_family",
        "query_ids",
        "review_status",
        "arms_or_outcomes_used",
    )
    if any(getattr(proposer, field) != getattr(reviewer, field) for field in coordinates):
        raise PromptContractExtractionError("independent contract coordinates differ")
    proposer_semantics = {row.semantic_id: row for row in proposer.semantic_decisions}
    reviewer_semantics = {row.semantic_id: row for row in reviewer.semantic_decisions}
    if set(proposer_semantics) != set(reviewer_semantics):
        raise PromptContractExtractionError("independent semantic tables differ")

    semantic_decisions = []
    for semantic_id in sorted(proposer_semantics):
        left = proposer_semantics[semantic_id]
        right = reviewer_semantics[semantic_id]
        both_present = (
            left.state is QueryState.PRESENT and right.state is QueryState.PRESENT
        )
        same_non_present = left.state is right.state and left.state is not QueryState.PRESENT
        if both_present:
            evidence = min(
                (left, right),
                key=lambda row: (
                    -len(row.evidence_text.encode("utf-8")),
                    row.evidence_text,
                    row.occurrence,
                ),
            )
            shared_attributes = tuple(
                sorted(set(left.attributes).intersection(right.attributes))
            )
            decision = replace(
                evidence,
                rationale=(
                    "Independent annotations agree on presence; the deterministic "
                    "longer exact evidence span is retained."
                ),
                attributes=shared_attributes,
            )
        elif same_non_present:
            decision = replace(left, rationale="Independent annotations agree on this state.")
        else:
            decision = SemanticDecision(
                semantic_id,
                QueryState.UNRESOLVED,
                "Independent annotations disagree; conservatively unresolved.",
                None,
                None,
                (),
            )
        semantic_decisions.append(decision)

    final_states = {row.semantic_id: row.state for row in semantic_decisions}
    proposer_relations = {row.relation: row for row in proposer.relation_decisions}
    reviewer_relations = {row.relation: row for row in reviewer.relation_decisions}
    if set(proposer_relations) != set(reviewer_relations):
        raise PromptContractExtractionError("independent relation tables differ")
    relation_decisions = []
    for relation in sorted(proposer_relations):
        left = proposer_relations[relation]
        right = reviewer_relations[relation]
        endpoint_states = {final_states[relation[0]], final_states[relation[2]]}
        if QueryState.ABSENT in endpoint_states:
            state = QueryState.ABSENT
            rationale = "At least one endpoint is absent in the consensus contract."
        elif QueryState.UNRESOLVED in endpoint_states:
            state = QueryState.UNRESOLVED
            rationale = "At least one endpoint is unresolved in the consensus contract."
        elif left.state is right.state:
            state = left.state
            rationale = "Independent annotations agree on this relation."
        else:
            state = QueryState.UNRESOLVED
            rationale = "Independent annotations disagree; conservatively unresolved."
        relation_decisions.append(replace(left, state=state, rationale=rationale))

    return replace(
        proposer,
        annotator_id=annotator_id,
        semantic_decisions=tuple(semantic_decisions),
        relation_decisions=tuple(relation_decisions),
    )


def extract_task_contract(
    task: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    proposer_evaluator: Mapping[str, Any],
    proposer_prompt: str,
    reviewer_evaluator: Mapping[str, Any],
    reviewer_prompt: str,
    review_status: str,
    provider: Provider = bailian_complete,
) -> tuple[TaskContextContract, PromptTSG, dict[str, Any], bytes, bytes]:
    """Run two source-only annotations and compile their deterministic consensus."""

    request = contract_decision_request(task, catalog)
    proposer_raw = provider(request, proposer_evaluator, proposer_prompt)
    reviewer_raw = provider(request, reviewer_evaluator, reviewer_prompt)
    proposer = contract_from_response(
        proposer_raw,
        task=task,
        catalog=catalog,
        annotator_id=proposer_evaluator["candidate_id"],
        review_status=review_status,
    )
    reviewer = contract_from_response(
        reviewer_raw,
        task=task,
        catalog=catalog,
        annotator_id=reviewer_evaluator["candidate_id"],
        review_status=review_status,
    )
    annotator_id = (
        f"dual-blind-consensus:{proposer_evaluator['candidate_id']}"
        f"+{reviewer_evaluator['candidate_id']}"
    )
    contract = consensus_contract(proposer, reviewer, annotator_id=annotator_id)
    graph = compile_task_context_contract(contract, prompt=task["prompt"], catalog=catalog)
    return contract, graph, request, proposer_raw, reviewer_raw


def extract_contract_task_file(
    tasks_path: Path,
    catalog_path: Path,
    proposer_evaluator_path: Path,
    proposer_prompt_path: Path,
    reviewer_evaluator_path: Path,
    reviewer_prompt_path: Path,
    selection_path: Path,
    output: Path,
    *,
    review_status: str = "prospective_frozen",
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Extract one frozen selection into a reviewable contract-and-graph bundle."""

    if output.exists():
        raise FileExistsError(output)
    tasks = _rows(read_json(tasks_path), "task file")
    by_id = {task.get("task_id"): task for task in tasks}
    if len(by_id) != len(tasks) or None in by_id:
        raise PromptContractExtractionError("task identities are invalid")
    selection = read_json(selection_path)
    if (
        not isinstance(selection, dict)
        or set(selection)
        != {"schema_version", "source_tasks_sha256", "selection_rule", "task_ids", "arms_or_outcomes_used"}
        or selection["schema_version"] != "1.0"
        or selection["source_tasks_sha256"] != _sha256(tasks_path)
        or selection["arms_or_outcomes_used"] is not False
        or not isinstance(selection["selection_rule"], str)
        or not selection["selection_rule"].strip()
        or not isinstance(selection["task_ids"], list)
        or not selection["task_ids"]
        or len(selection["task_ids"]) != len(set(selection["task_ids"]))
        or not set(selection["task_ids"]) <= set(by_id)
    ):
        raise PromptContractExtractionError("task selection is invalid or stale")
    selected = [by_id[task_id] for task_id in selection["task_ids"]]
    catalog = load_catalog(catalog_path)
    proposer_evaluator = _evaluator(read_json(proposer_evaluator_path))
    reviewer_evaluator = _evaluator(read_json(reviewer_evaluator_path))
    proposer_prompt = proposer_prompt_path.read_text(encoding="utf-8").strip()
    reviewer_prompt = reviewer_prompt_path.read_text(encoding="utf-8").strip()
    if not proposer_prompt or not reviewer_prompt:
        raise PromptContractExtractionError("contract annotator prompt is empty")

    contracts: list[dict[str, Any]] = []
    graphs: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    for task in selected:
        contract, graph, request, proposer_raw, reviewer_raw = extract_task_contract(
            task,
            catalog=catalog,
            proposer_evaluator=proposer_evaluator,
            proposer_prompt=proposer_prompt,
            reviewer_evaluator=reviewer_evaluator,
            reviewer_prompt=reviewer_prompt,
            review_status=review_status,
            provider=provider,
        )
        contracts.append(task_context_contract_record(contract))
        graphs.append(prompt_tsg_record(graph))
        requests.append(request)
        responses.append(
            {
                "task_id": task["task_id"],
                "proposer_response_sha256": hashlib.sha256(proposer_raw).hexdigest(),
                "proposer_response_text": proposer_raw.decode("utf-8"),
                "reviewer_response_sha256": hashlib.sha256(reviewer_raw).hexdigest(),
                "reviewer_response_text": reviewer_raw.decode("utf-8"),
            }
        )
    candidate_id = contracts[0]["annotator_id"]
    report = {
        "schema_version": "1.0",
        "status": "PROMPT_CONTRACT_EXTRACTION_COMPLETE",
        "protocol_id": "task_context_contract_v2_dual_blind_consensus",
        "tasks": len(selected),
        "contracts": len(contracts),
        "graphs": len(graphs),
        "provider_calls": 2 * len(selected),
        "candidate_id": candidate_id,
        "task_file_sha256": _sha256(tasks_path),
        "task_selection_sha256": _sha256(selection_path),
        "catalog_sha256": catalog_sha256(catalog),
        "proposer_evaluator_sha256": _sha256(proposer_evaluator_path),
        "proposer_prompt_sha256": _sha256(proposer_prompt_path),
        "reviewer_evaluator_sha256": _sha256(reviewer_evaluator_path),
        "reviewer_prompt_sha256": _sha256(reviewer_prompt_path),
        "extractor_implementation_sha256": _sha256(Path(__file__)),
        "provider_adapter_sha256": _sha256(Path(provider.__code__.co_filename)),
        "unresolved_task_units": sum(bool(graph["unresolved_semantics"]) for graph in graphs),
        "review_status": review_status,
        "arms_or_outcomes_used": False,
    }
    write_bundle(
        output,
        {
            "report.json": report,
            "contracts.json": contracts,
            "graphs.json": graphs,
            "requests.json": requests,
            "responses.json": responses,
        },
    )
    return report


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
        or value["api_key_env"] != "ALI_BAILIAN_API_KEY"
        or value["temperature"] != 0.0
        or value["max_attempts"] != 1
    ):
        raise PromptContractExtractionError("contract evaluator is invalid")
    return value


def _rows(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or any(not isinstance(row, dict) for row in value):
        raise PromptContractExtractionError(f"{label} must be a non-empty object list")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "PromptContractExtractionError",
    "consensus_contract",
    "contract_decision_request",
    "contract_from_response",
    "extract_contract_task_file",
    "extract_task_contract",
]

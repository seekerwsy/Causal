"""Blind dual annotation of exhaustive task contracts and deterministic TSG compilation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
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
    "state",
    "rationale",
    "evidence_text",
    "occurrence",
    "attributes",
}
_RELATION_FIELDS = {
    "state",
    "rationale",
}
_RESPONSE_PROTOCOL_ID = "task_keyed_prompt_contract_json_schema_v4"


class PromptContractExtractionError(RuntimeError):
    """The frozen request, model decision table, or extraction closure is invalid."""


@dataclass(frozen=True, slots=True)
class _TaskContractAttempt:
    task_id: str
    request: dict[str, Any]
    provider_calls: int
    proposer_raw: bytes | None
    reviewer_raw: bytes | None
    contract: TaskContextContract | None
    graph: PromptTSG | None
    error_type: str | None
    error_message: str | None

    @property
    def succeeded(self) -> bool:
        return self.contract is not None and self.graph is not None and self.error_type is None


def _relation_decision_key(relation: Sequence[str]) -> str:
    if len(relation) != 3 or any(not value or "|" in value for value in relation):
        raise PromptContractExtractionError("relation cannot be encoded as a decision key")
    return "|".join(relation)


def contract_response_format(request: Mapping[str, Any]) -> dict[str, Any]:
    """Build a strict task-specific schema whose required keys close the finite scope."""

    semantics = request.get("candidate_semantics")
    relations = request.get("candidate_relations")
    if (
        not isinstance(semantics, dict)
        or not semantics
        or not isinstance(relations, dict)
        or not relations
        or any(not isinstance(key, str) or not key for key in (*semantics, *relations))
    ):
        raise PromptContractExtractionError("response schema scope is invalid")
    semantic_value = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_SEMANTIC_FIELDS),
        "properties": {
            "state": {
                "type": "string",
                "enum": ["present", "absent", "unresolved"],
            },
            "rationale": {"type": "string", "minLength": 1, "maxLength": 256},
            "evidence_text": {"type": ["string", "null"]},
            "occurrence": {"type": ["integer", "null"]},
            "attributes": {"type": "array", "items": {"type": "string"}},
        },
    }
    relation_value = {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(_RELATION_FIELDS),
        "properties": {
            "state": {
                "type": "string",
                "enum": ["present", "absent", "unresolved"],
            },
            "rationale": {"type": "string", "minLength": 1, "maxLength": 256},
        },
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "task_keyed_prompt_contract",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(_RESPONSE_FIELDS),
                "properties": {
                    "semantic_decisions": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(semantics),
                        "properties": {
                            semantic_id: semantic_value for semantic_id in semantics
                        },
                    },
                    "relation_decisions": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": sorted(relations),
                        "properties": {
                            relation_id: relation_value for relation_id in relations
                        },
                    },
                },
            },
        },
    }


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


def _canonical_prompt_evidence(
    prompt: str, evidence_text: object, occurrence: object
) -> tuple[str, int] | None:
    """Bind transport-normalized evidence back to one exact source-prompt span."""

    if (
        not isinstance(evidence_text, str)
        or not evidence_text
        or len(evidence_text.encode("utf-8")) > 2048
        or type(occurrence) is not int
        or occurrence <= 0
    ):
        return None
    candidates: list[str] = []

    def add(value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    add(evidence_text)
    add(evidence_text.strip())
    for value in tuple(candidates):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'", "`"}:
            add(value[1:-1].strip())
    for value in tuple(candidates):
        add(value.replace(r'\"', '"').replace(r"\'", "'"))

    for candidate in candidates:
        starts = _literal_starts(prompt, candidate)
        if occurrence <= len(starts):
            return candidate, occurrence
    for candidate in candidates:
        tokens = candidate.split()
        if len(tokens) < 2:
            continue
        matches = list(re.finditer(r"\s+".join(re.escape(token) for token in tokens), prompt))
        if occurrence > len(matches):
            continue
        match = matches[occurrence - 1]
        exact = prompt[match.start() : match.end()]
        exact_starts = _literal_starts(prompt, exact)
        return exact, exact_starts.index(match.start()) + 1
    return None


def _literal_starts(text: str, fragment: str) -> list[int]:
    starts: list[int] = []
    offset = 0
    while True:
        offset = text.find(fragment, offset)
        if offset < 0:
            return starts
        starts.append(offset)
        offset += 1


def _demote_unverified_present_evidence(
    prompt: str, semantic_decisions: tuple[SemanticDecision, ...]
) -> tuple[SemanticDecision, ...]:
    """Fail closed on unsupported presence without aborting the task batch."""

    closed = []
    for row in semantic_decisions:
        if row.state is not QueryState.PRESENT:
            closed.append(row)
            continue
        evidence = _canonical_prompt_evidence(prompt, row.evidence_text, row.occurrence)
        if evidence is None:
            closed.append(
                replace(
                    row,
                    state=QueryState.UNRESOLVED,
                    rationale=(
                        "Deterministic evidence validation: claimed presence lacks an exact "
                        "source-prompt occurrence; conservatively unresolved."
                    ),
                    evidence_text=None,
                    occurrence=None,
                    attributes=(),
                )
            )
        else:
            closed.append(replace(row, evidence_text=evidence[0], occurrence=evidence[1]))
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
        "candidate_relations": {
            _relation_decision_key(relation): list(relation)
            for relation in scope["relations"]
        },
        "allowed_attributes": list(catalog["attribute_names"]),
        "decision_states": ["present", "absent", "unresolved"],
        "arms_or_outcomes_included": False,
        "output_contract": {
            "top_level_keys": ["semantic_decisions", "relation_decisions"],
            "semantic_decision_value_keys": sorted(_SEMANTIC_FIELDS),
            "relation_decision_value_keys": sorted(_RELATION_FIELDS),
            "semantic_rows": "object keyed exactly by every candidate_semantics key",
            "relation_rows": "object keyed exactly by every candidate_relations key",
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
    scope = task_context_scope(
        cwe_id=task["cwe"], task_family=task["task_family"], catalog=catalog
    )
    expected_semantics = set(scope["semantic_ids"])
    relation_by_key = {
        _relation_decision_key(relation): relation for relation in scope["relations"]
    }
    semantic_rows = value["semantic_decisions"]
    relation_rows = value["relation_decisions"]
    if not isinstance(semantic_rows, dict) or not isinstance(relation_rows, dict):
        raise PromptContractExtractionError("contract decision tables are invalid")
    if set(semantic_rows) != expected_semantics or set(relation_rows) != set(
        relation_by_key
    ):
        raise PromptContractExtractionError("contract decision rows are not exhaustive")
    if (
        any(
            not isinstance(row, dict) or set(row) != _SEMANTIC_FIELDS
            for row in semantic_rows.values()
        )
        or any(
            not isinstance(row, dict) or set(row) != _RELATION_FIELDS
            for row in relation_rows.values()
        )
    ):
        raise PromptContractExtractionError("contract decision row fields are invalid")
    if any(
        not isinstance(row["attributes"], list)
        or any(
            not isinstance(attribute, str) or not attribute
            for attribute in row["attributes"]
        )
        or len(row["attributes"]) != len(set(row["attributes"]))
        for row in semantic_rows.values()
    ):
        raise PromptContractExtractionError("contract semantic attributes are invalid")
    try:
        semantic_decisions = tuple(
            SemanticDecision(
                semantic_id,
                QueryState(row["state"]),
                row["rationale"].strip(),
                (
                    row["evidence_text"]
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else None
                ),
                (
                    row["occurrence"]
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else None
                ),
                (
                    tuple((attribute, True) for attribute in sorted(row["attributes"]))
                    if QueryState(row["state"]) is QueryState.PRESENT
                    else ()
                ),
            )
            for semantic_id, row in semantic_rows.items()
        )
        relation_decisions = tuple(
            RelationDecision(
                relation_by_key[relation_id][0],
                relation_by_key[relation_id][1],
                relation_by_key[relation_id][2],
                QueryState(row["state"]),
                row["rationale"].strip(),
            )
            for relation_id, row in relation_rows.items()
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise PromptContractExtractionError("contract decision values are invalid") from None
    semantic_decisions = _demote_unverified_present_evidence(
        task["prompt"], semantic_decisions
    )
    relation_decisions = _close_relation_endpoint_states(
        semantic_decisions, relation_decisions
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

    attempt = _attempt_task_contract(
        task,
        catalog=catalog,
        proposer_evaluator=proposer_evaluator,
        proposer_prompt=proposer_prompt,
        reviewer_evaluator=reviewer_evaluator,
        reviewer_prompt=reviewer_prompt,
        review_status=review_status,
        provider=provider,
    )
    if not attempt.succeeded:
        raise PromptContractExtractionError(
            attempt.error_message or attempt.error_type or "task contract extraction failed"
        )
    assert attempt.contract is not None
    assert attempt.graph is not None
    assert attempt.proposer_raw is not None
    assert attempt.reviewer_raw is not None
    return (
        attempt.contract,
        attempt.graph,
        attempt.request,
        attempt.proposer_raw,
        attempt.reviewer_raw,
    )


def _attempt_task_contract(
    task: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    proposer_evaluator: Mapping[str, Any],
    proposer_prompt: str,
    reviewer_evaluator: Mapping[str, Any],
    reviewer_prompt: str,
    review_status: str,
    provider: Provider,
) -> _TaskContractAttempt:
    """Close raw responses and call counts even when deterministic parsing fails."""

    request = contract_decision_request(task, catalog)
    response_format = contract_response_format(request)
    provider_calls = 0
    proposer_raw: bytes | None = None
    reviewer_raw: bytes | None = None
    try:
        provider_calls += 1
        proposer_raw = provider(
            request,
            {**proposer_evaluator, "response_format": response_format},
            proposer_prompt,
        )
        provider_calls += 1
        reviewer_raw = provider(
            request,
            {**reviewer_evaluator, "response_format": response_format},
            reviewer_prompt,
        )
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
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:  # noqa: BLE001 - evidence must close before fail-stop
        return _TaskContractAttempt(
            str(task["task_id"]),
            request,
            provider_calls,
            proposer_raw,
            reviewer_raw,
            None,
            None,
            type(error).__name__,
            str(error),
        )
    return _TaskContractAttempt(
        str(task["task_id"]),
        request,
        provider_calls,
        proposer_raw,
        reviewer_raw,
        contract,
        graph,
        None,
        None,
    )


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
    max_workers: int = 1,
) -> dict[str, Any]:
    """Extract one frozen selection into a reviewable contract-and-graph bundle."""

    if output.exists():
        raise FileExistsError(output)
    if type(max_workers) is not int or not 1 <= max_workers <= 8:
        raise PromptContractExtractionError("task worker count must be between 1 and 8")
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
    proposer_evaluator = _evaluator(
        read_json(proposer_evaluator_path), proposer_evaluator_path
    )
    reviewer_evaluator = _evaluator(
        read_json(reviewer_evaluator_path), reviewer_evaluator_path
    )
    proposer_prompt = proposer_prompt_path.read_text(encoding="utf-8").strip()
    reviewer_prompt = reviewer_prompt_path.read_text(encoding="utf-8").strip()
    if not proposer_prompt or not reviewer_prompt:
        raise PromptContractExtractionError("contract annotator prompt is empty")

    def extract(task: Mapping[str, Any]) -> _TaskContractAttempt:
        return _attempt_task_contract(
            task,
            catalog=catalog,
            proposer_evaluator=proposer_evaluator,
            proposer_prompt=proposer_prompt,
            reviewer_evaluator=reviewer_evaluator,
            reviewer_prompt=reviewer_prompt,
            review_status=review_status,
            provider=provider,
        )

    if max_workers == 1:
        extracted = [extract(task) for task in selected]
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            extracted = list(executor.map(extract, selected))

    contracts: list[dict[str, Any]] = []
    graphs: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    failed_task_units: list[dict[str, Any]] = []
    for task, attempt in zip(selected, extracted, strict=True):
        requests.append(attempt.request)
        responses.append(
            {
                "task_id": task["task_id"],
                "response_format_sha256": content_hash(
                    contract_response_format(attempt.request)
                ),
                "provider_calls": attempt.provider_calls,
                "status": "complete" if attempt.succeeded else "failed",
                "proposer_response_sha256": (
                    hashlib.sha256(attempt.proposer_raw).hexdigest()
                    if attempt.proposer_raw is not None
                    else None
                ),
                "proposer_response_text": (
                    attempt.proposer_raw.decode("utf-8")
                    if attempt.proposer_raw is not None
                    else None
                ),
                "reviewer_response_sha256": (
                    hashlib.sha256(attempt.reviewer_raw).hexdigest()
                    if attempt.reviewer_raw is not None
                    else None
                ),
                "reviewer_response_text": (
                    attempt.reviewer_raw.decode("utf-8")
                    if attempt.reviewer_raw is not None
                    else None
                ),
                "error_type": attempt.error_type,
                "error_message": attempt.error_message,
            }
        )
        if attempt.succeeded:
            assert attempt.contract is not None
            assert attempt.graph is not None
            contracts.append(task_context_contract_record(attempt.contract))
            graphs.append(prompt_tsg_record(attempt.graph))
        else:
            failed_task_units.append(
                {
                    "task_id": attempt.task_id,
                    "provider_calls": attempt.provider_calls,
                    "error_type": attempt.error_type,
                    "error_message": attempt.error_message,
                }
            )
    candidate_id = (
        f"dual-blind-consensus:{proposer_evaluator['candidate_id']}"
        f"+{reviewer_evaluator['candidate_id']}"
    )
    complete = not failed_task_units
    report = {
        "schema_version": "1.0",
        "status": (
            "PROMPT_CONTRACT_EXTRACTION_COMPLETE"
            if complete
            else "PROMPT_CONTRACT_EXTRACTION_FAILED"
        ),
        "protocol_id": "task_context_contract_v2_dual_blind_consensus",
        "tasks": len(selected),
        "contracts": len(contracts),
        "graphs": len(graphs),
        "provider_calls": sum(attempt.provider_calls for attempt in extracted),
        "task_workers": max_workers,
        "effective_task_workers": min(max_workers, len(selected)),
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
        "response_protocol_id": _RESPONSE_PROTOCOL_ID,
        "unresolved_task_units": sum(bool(graph["unresolved_semantics"]) for graph in graphs),
        "failed_task_unit_count": len(failed_task_units),
        "failed_task_units": failed_task_units,
        "review_status": review_status,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    if "response_format_sha256" in proposer_evaluator:
        report["proposer_response_format_sha256"] = proposer_evaluator[
            "response_format_sha256"
        ]
    if "response_format_sha256" in reviewer_evaluator:
        report["reviewer_response_format_sha256"] = reviewer_evaluator[
            "response_format_sha256"
        ]
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
    if not complete:
        raise PromptContractExtractionError(
            "prompt contract extraction failed; inspect closed bundle"
        )
    return report


def _evaluator(value: Any, evaluator_path: Path) -> dict[str, Any]:
    base_fields = {
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
    structured_fields = {"response_format_path", "response_format_sha256"}
    optional_fields = {"maximum_output_tokens"}
    present_fields = set(value) if isinstance(value, dict) else set()
    if (
        not isinstance(value, dict)
        or not base_fields <= present_fields
        or present_fields - base_fields - structured_fields - optional_fields
        or bool(present_fields & structured_fields)
        != bool(structured_fields <= present_fields)
        or value["schema_version"] != "1.0"
        or value["api_key_env"] != "ALI_BAILIAN_API_KEY"
        or value["temperature"] != 0.0
        or value["max_attempts"] != 1
        or (
            "maximum_output_tokens" in value
            and (
                type(value["maximum_output_tokens"]) is not int
                or value["maximum_output_tokens"] <= 0
            )
        )
    ):
        raise PromptContractExtractionError("contract evaluator is invalid")
    if not structured_fields <= set(value):
        return value
    format_path = (evaluator_path.parent / value["response_format_path"]).resolve()
    try:
        format_path.relative_to(evaluator_path.parent.resolve())
    except ValueError:
        raise PromptContractExtractionError("response format escapes evaluator directory") from None
    if _sha256(format_path) != value["response_format_sha256"]:
        raise PromptContractExtractionError("response format identity drifted")
    response_format = read_json(format_path)
    if (
        not isinstance(response_format, dict)
        or set(response_format) != {"type", "json_schema"}
        or response_format["type"] != "json_schema"
        or not isinstance(response_format["json_schema"], dict)
        or response_format["json_schema"].get("strict") is not True
        or not isinstance(response_format["json_schema"].get("schema"), dict)
    ):
        raise PromptContractExtractionError("contract response format is invalid")
    return {**value, "response_format": response_format}


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
    "contract_response_format",
    "extract_contract_task_file",
    "extract_task_contract",
]

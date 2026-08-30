"""Exhaustive task-context decisions compiled into a canonical Prompt TSG."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from prompt_mechanism_study.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    QueryState,
    build_prompt_tsg,
    catalog_sha256,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text


_DECISION_STATES = {QueryState.PRESENT, QueryState.ABSENT, QueryState.UNRESOLVED}
_REVIEW_STATUSES = {"development_exposed", "prospective_frozen"}


@dataclass(frozen=True, slots=True)
class SemanticDecision:
    semantic_id: str
    state: QueryState
    rationale: str
    evidence_text: str | None
    occurrence: int | None
    attributes: tuple[tuple[str, bool], ...]


@dataclass(frozen=True, slots=True)
class RelationDecision:
    source_semantic_id: str
    edge_type: str
    target_semantic_id: str
    state: QueryState
    rationale: str

    @property
    def relation(self) -> tuple[str, str, str]:
        return self.source_semantic_id, self.edge_type, self.target_semantic_id


@dataclass(frozen=True, slots=True)
class TaskContextContract:
    schema_version: str
    task_id: str
    prompt_sha256: str
    catalog_sha256: str
    cwe_id: str
    task_family: str
    query_ids: tuple[str, ...]
    annotator_id: str
    review_status: str
    arms_or_outcomes_used: bool
    semantic_decisions: tuple[SemanticDecision, ...]
    relation_decisions: tuple[RelationDecision, ...]

    @property
    def contract_id(self) -> str:
        return content_id("task_context_contract_", self)


def task_context_contract_record(contract: TaskContextContract) -> dict[str, Any]:
    """Return one content-addressed contract record."""

    return {"contract_id": contract.contract_id, **canonical_value(contract)}


def task_context_contract_from_record(value: Mapping[str, Any]) -> TaskContextContract:
    """Parse a contract; prompt- and catalog-aware checks occur during compilation."""

    fields = {
        "schema_version",
        "task_id",
        "prompt_sha256",
        "catalog_sha256",
        "cwe_id",
        "task_family",
        "query_ids",
        "annotator_id",
        "review_status",
        "arms_or_outcomes_used",
        "semantic_decisions",
        "relation_decisions",
    }
    actual_fields = set(value) if isinstance(value, Mapping) else set()
    if not isinstance(value, Mapping) or (
        actual_fields != fields and actual_fields != fields | {"contract_id"}
    ):
        raise PromptTSGError("task context contract fields are invalid")
    semantic_fields = {
        "semantic_id",
        "state",
        "rationale",
        "evidence_text",
        "occurrence",
        "attributes",
    }
    relation_fields = {
        "source_semantic_id",
        "edge_type",
        "target_semantic_id",
        "state",
        "rationale",
    }
    try:
        if any(set(item) != semantic_fields for item in value["semantic_decisions"]) or any(
            set(item) != relation_fields for item in value["relation_decisions"]
        ):
            raise PromptTSGError("task context decision fields are invalid")
        semantic_decisions = tuple(
            SemanticDecision(
                item["semantic_id"],
                QueryState(item["state"]),
                item["rationale"],
                item["evidence_text"],
                item["occurrence"],
                tuple((key, flag) for key, flag in item["attributes"]),
            )
            for item in value["semantic_decisions"]
        )
        relation_decisions = tuple(
            RelationDecision(
                item["source_semantic_id"],
                item["edge_type"],
                item["target_semantic_id"],
                QueryState(item["state"]),
                item["rationale"],
            )
            for item in value["relation_decisions"]
        )
        contract = TaskContextContract(
            value["schema_version"],
            value["task_id"],
            value["prompt_sha256"],
            value["catalog_sha256"],
            value["cwe_id"],
            value["task_family"],
            tuple(value["query_ids"]),
            value["annotator_id"],
            value["review_status"],
            value["arms_or_outcomes_used"],
            semantic_decisions,
            relation_decisions,
        )
    except (KeyError, TypeError, ValueError):
        raise PromptTSGError("task context contract values are invalid") from None
    if "contract_id" in value and contract.contract_id != value["contract_id"]:
        raise PromptTSGError("task context contract identity is invalid")
    return contract


def compile_task_context_contract(
    contract: TaskContextContract,
    *,
    prompt: str,
    catalog: Mapping[str, Any],
) -> PromptTSG:
    """Validate one exhaustive decision table and compile it without model discretion."""

    _validate_contract(contract, prompt=prompt, catalog=catalog)
    local_ids = {
        decision.semantic_id: f"semantic-{index:03d}"
        for index, decision in enumerate(contract.semantic_decisions)
        if decision.state is QueryState.PRESENT
    }
    facts = [
        {
            "local_id": local_ids[decision.semantic_id],
            "node_type": catalog["semantics"][decision.semantic_id],
            "semantic_id": decision.semantic_id,
            "evidence_text": decision.evidence_text,
            "occurrence": decision.occurrence,
            "attributes": dict(decision.attributes),
        }
        for decision in contract.semantic_decisions
        if decision.state is QueryState.PRESENT
    ]
    relations = [
        {
            "source": local_ids[decision.source_semantic_id],
            "edge_type": decision.edge_type,
            "target": local_ids[decision.target_semantic_id],
        }
        for decision in contract.relation_decisions
        if decision.state is QueryState.PRESENT
    ]
    unresolved_semantics = [
        decision.semantic_id
        for decision in contract.semantic_decisions
        if decision.state is QueryState.UNRESOLVED
    ]
    unresolved_relations = [
        decision.relation
        for decision in contract.relation_decisions
        if decision.state is QueryState.UNRESOLVED
    ]
    graph = build_prompt_tsg(
        task_id=contract.task_id,
        prompt=prompt,
        extractor_id=f"task-context-contract-v2:{contract.contract_id}",
        catalog=catalog,
        facts=facts,
        relations=relations,
        unresolved_semantics=unresolved_semantics,
        unresolved_relations=unresolved_relations,
        schema_version="2.0",
    )
    return graph


def task_context_scope(
    *, cwe_id: str, task_family: str, catalog: Mapping[str, Any]
) -> dict[str, Any]:
    """Return the complete catalog slice decided once for one task unit."""

    queries = sorted(
        (
            query
            for query in catalog["queries"]
            if query["cwe_id"] == cwe_id and query["task_family"] == task_family
        ),
        key=lambda query: query["query_id"],
    )
    if not queries:
        raise PromptTSGError("task context contract scope has no catalog query")
    semantic_ids = sorted(
        {
            semantic_id
            for query in queries
            for semantic_id in (
                *query["required_semantics"],
                *query["forbidden_semantics"],
                query["actionable_feature_id"],
            )
        }
    )
    relations = sorted(
        {
            tuple(relation)
            for query in queries
            for relation in query["required_relations"]
        }
    )
    return {
        "queries": tuple(queries),
        "query_ids": tuple(query["query_id"] for query in queries),
        "semantic_ids": tuple(semantic_ids),
        "relations": tuple(relations),
    }


def _validate_contract(
    contract: TaskContextContract,
    *,
    prompt: str,
    catalog: Mapping[str, Any],
) -> Mapping[str, Any]:
    if (
        contract.schema_version != "2.0"
        or contract.prompt_sha256 != content_hash(prompt)
        or contract.catalog_sha256 != catalog_sha256(catalog)
        or contract.review_status not in _REVIEW_STATUSES
        or type(contract.arms_or_outcomes_used) is not bool
        or contract.arms_or_outcomes_used
    ):
        raise PromptTSGError("task context contract envelope is invalid")
    require_text(contract.task_id, "task_id")
    require_text(contract.cwe_id, "cwe_id")
    require_text(contract.task_family, "task_family")
    require_text(contract.annotator_id, "annotator_id")
    scope = task_context_scope(
        cwe_id=contract.cwe_id,
        task_family=contract.task_family,
        catalog=catalog,
    )
    if contract.query_ids != scope["query_ids"]:
        raise PromptTSGError("task context contract queries are not exhaustive")
    expected_semantics = set(scope["semantic_ids"])
    semantic_ids = tuple(decision.semantic_id for decision in contract.semantic_decisions)
    if (
        set(semantic_ids) != expected_semantics
        or len(semantic_ids) != len(set(semantic_ids))
        or semantic_ids != tuple(sorted(semantic_ids))
    ):
        raise PromptTSGError("task context semantic decisions are not exhaustive")
    attributes = set(catalog["attribute_names"])
    states = {}
    for decision in contract.semantic_decisions:
        states[decision.semantic_id] = decision.state
        if decision.state not in _DECISION_STATES:
            raise PromptTSGError("task context semantic state is invalid")
        if (
            not isinstance(decision.rationale, str)
            or not decision.rationale.strip()
            or decision.rationale != decision.rationale.strip()
            or len(decision.rationale.encode("utf-8")) > 1024
        ):
            raise PromptTSGError("task context semantic rationale is invalid")
        if (
            any(
                not isinstance(key, str)
                or key not in attributes
                or type(flag) is not bool
                for key, flag in decision.attributes
            )
            or len({key for key, _ in decision.attributes}) != len(decision.attributes)
            or decision.attributes != tuple(sorted(decision.attributes))
        ):
            raise PromptTSGError("task context semantic attributes are invalid")
        has_evidence = decision.evidence_text is not None or decision.occurrence is not None
        if decision.state is QueryState.PRESENT:
            if (
                not isinstance(decision.evidence_text, str)
                or not decision.evidence_text
                or type(decision.occurrence) is not int
                or decision.occurrence <= 0
            ):
                raise PromptTSGError("present semantic decision lacks exact evidence")
        elif has_evidence or decision.attributes:
            raise PromptTSGError("non-present semantic decision cannot assert evidence")

    expected_relations = set(scope["relations"])
    actual_relations = tuple(decision.relation for decision in contract.relation_decisions)
    if (
        set(actual_relations) != expected_relations
        or len(actual_relations) != len(set(actual_relations))
        or actual_relations != tuple(sorted(actual_relations))
    ):
        raise PromptTSGError("task context relation decisions are not exhaustive")
    for decision in contract.relation_decisions:
        if decision.state not in _DECISION_STATES:
            raise PromptTSGError("task context relation state is invalid")
        if (
            not isinstance(decision.rationale, str)
            or not decision.rationale.strip()
            or decision.rationale != decision.rationale.strip()
            or len(decision.rationale.encode("utf-8")) > 1024
        ):
            raise PromptTSGError("task context relation rationale is invalid")
        endpoint_states = {states[decision.source_semantic_id], states[decision.target_semantic_id]}
        if decision.state is QueryState.PRESENT and endpoint_states != {QueryState.PRESENT}:
            raise PromptTSGError("present relation requires present endpoints")
        if QueryState.ABSENT in endpoint_states and decision.state is not QueryState.ABSENT:
            raise PromptTSGError("relation with an absent endpoint must be absent")
        if QueryState.UNRESOLVED in endpoint_states and decision.state is not QueryState.UNRESOLVED:
            raise PromptTSGError("relation with an unresolved endpoint must be unresolved")
    return scope


__all__ = [
    "RelationDecision",
    "SemanticDecision",
    "TaskContextContract",
    "compile_task_context_contract",
    "task_context_scope",
    "task_context_contract_from_record",
    "task_context_contract_record",
]

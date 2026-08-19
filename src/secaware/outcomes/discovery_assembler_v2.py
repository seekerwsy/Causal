"""Authenticated natural-Prompt query/runtime assembly for v2 discovery rows."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.discovery_v2 import (
    NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
    AuthenticatedNaturalDiscoveryScopeV2,
    DiscoveryVariableRoleV2,
    DiscoveryVariableSourceV2,
)
from secaware.schema.features import FeatureState
from secaware.schema.policy_v2 import (
    ActionableFeatureQueryResultRecord,
    ContextQueryResultRecord,
    QueryState,
)
from secaware.schema.runtime_v2 import (
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    NaturalCausalObservationRecordV2,
    NaturalOutcomeValueV2,
    NaturalX0ValueV2,
    OracleResultRecordV2,
    RuntimeProducerChainRecordV2,
    validate_runtime_producer_chain_v2,
)
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.queries import feature_state

ASSEMBLY_RECEIPT_V2_SCHEMA_VERSION = "2.0"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_RECEIPT_PATTERN = r"^authenticated_natural_observation_[0-9a-f]{64}$"

_QUERY_STATE_CODE = {
    QueryState.PRESENT: 0,
    QueryState.ABSENT: 1,
    QueryState.NOT_APPLICABLE: 2,
    QueryState.UNRESOLVED: 3,
}
_FEATURE_TO_QUERY_STATE = {
    FeatureState.PRESENT: QueryState.PRESENT,
    FeatureState.ABSENT: QueryState.ABSENT,
    FeatureState.NOT_APPLICABLE: QueryState.NOT_APPLICABLE,
    FeatureState.UNRESOLVED: QueryState.UNRESOLVED,
}


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _outcome_projection(
    code: GeneratedCodeRecordV2,
    oracle: OracleResultRecordV2,
    functional: FunctionalResultRecordV2,
) -> dict[str, int]:
    if oracle.status == "infrastructure_failure" or functional.status == "infrastructure_failure":
        raise ValueError("natural discovery outcome encountered infrastructure failure")
    if code.code_status == "terminal_no_code":
        if (
            oracle.status != "not_evaluated_no_valid_code"
            or functional.status != "not_evaluated_no_valid_code"
        ):
            raise ValueError("natural discovery no-code evidence is incoherent")
        y_c = y_e = secure = joint = 0
    elif oracle.status == "not_evaluated_no_valid_code":
        if functional.status != "not_evaluated_no_valid_code":
            raise ValueError("natural discovery invalid-code evidence is incoherent")
        y_c = y_e = secure = joint = 0
    elif oracle.status in {"secure", "insecure", "unknown"}:
        if functional.status == "not_evaluated_no_valid_code":
            raise ValueError("natural discovery functional evidence is incoherent")
        y_c = 1
        y_e = int(oracle.status in {"secure", "insecure"})
        secure = int(oracle.status == "secure")
        joint = (
            2
            if functional.status == "not_applicable"
            else secure * int(functional.status == "pass")
        )
    else:
        raise ValueError("natural discovery Oracle evidence is unsupported")
    return {
        "y_c": y_c,
        "y_e": y_e,
        "y_secure_yield": secure,
        "y_joint": joint,
    }


def _evidence_tuple(attributes: object) -> tuple[int, int, str] | None:
    try:
        values = dict(attributes)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    start = values.get("evidence_start")
    end = values.get("evidence_end")
    digest = values.get("evidence_sha256")
    if type(start) is int and type(end) is int and type(digest) is str:
        return start, end, digest
    return None


def _canonical_actionable_result(
    scope: AuthenticatedNaturalDiscoveryScopeV2,
    *,
    task_instance_id: str,
    actionable_feature_spec_id: str,
) -> ActionableFeatureQueryResultRecord:
    from secaware.tsg.context_queries_v2 import (
        CONTEXT_QUERY_CATALOG_SHA256,
        CONTEXT_QUERY_SEMANTICS_VERSION,
    )
    from secaware.tsg.feature_catalog import (
        prompt_feature_edge_slots,
        prompt_feature_node_slots,
        prompt_feature_spec,
    )

    binding = next(
        (
            item
            for item in scope.task_bindings
            if item.membership.task_instance_id == task_instance_id
        ),
        None,
    )
    actionable = next(
        (
            item
            for item in scope.actionable_feature_specs
            if item.actionable_feature_spec_id == actionable_feature_spec_id
        ),
        None,
    )
    if binding is None or actionable is None:
        raise ValueError("actionable query is outside the authenticated scope")
    catalog_feature = prompt_feature_spec(actionable.feature_id)
    graph = record_to_multidigraph(binding.prompt_tsg)
    extracted_state = feature_state(graph, actionable.feature_id)
    applicable = (
        binding.membership.cwe in catalog_feature.applicable_cwes
        and binding.prompt_tsg.task_family in catalog_feature.applicable_task_families
    )
    state = _FEATURE_TO_QUERY_STATE[extracted_state]
    match_ids: tuple[str, ...] = ()
    roles_resolved: bool | None
    bounded_complete: bool
    evidence_content: dict[str, object] = {
        "schema_version": "actionable-query-evaluation-v2.1",
        "task_binding_id": binding.task_binding_id,
        "prompt_tsg_sha256": binding.prompt_tsg_sha256,
        "actionable_feature_spec_id": actionable.actionable_feature_spec_id,
        "feature_id": actionable.feature_id,
        "feature_catalog_sha256": actionable.feature_catalog_sha256,
        "context_query_catalog_sha256": CONTEXT_QUERY_CATALOG_SHA256,
        "query_semantics_version": CONTEXT_QUERY_SEMANTICS_VERSION,
    }
    if not applicable or extracted_state is FeatureState.NOT_APPLICABLE:
        state = QueryState.NOT_APPLICABLE
        roles_resolved = None
        bounded_complete = False
    elif extracted_state is FeatureState.ABSENT:
        state = QueryState.ABSENT
        roles_resolved = True
        bounded_complete = True
    elif extracted_state is FeatureState.PRESENT:
        node_slots = prompt_feature_node_slots(actionable.feature_id)
        edge_slots = prompt_feature_edge_slots(actionable.feature_id)
        matched_nodes = []
        for slot in node_slots:
            matches = tuple(
                (node_id, _evidence_tuple(node["attributes"]))
                for node_id, node in graph.nodes(data=True)
                if node["node_type"] is slot.node_type and node["label"] == slot.canonical_label
            )
            if len(matches) != 1 or matches[0][1] is None:
                state = QueryState.UNRESOLVED
                break
            matched_nodes.append(matches[0])
        matched_edges = []
        if state is QueryState.PRESENT:
            matched_node_ids_by_type = {
                slot.node_type: {
                    node_id
                    for node_id, _ in matched_nodes
                    if graph.nodes[node_id]["node_type"] is slot.node_type
                }
                for slot in node_slots
            }
            for slot in edge_slots:
                matches = tuple(
                    (edge_id, _evidence_tuple(edge["attributes"]))
                    for src, dst, edge_id, edge in graph.edges(keys=True, data=True)
                    if edge["edge_type"] is slot.edge_type
                    and src in matched_node_ids_by_type.get(slot.src_node_type, set())
                    and dst in matched_node_ids_by_type.get(slot.dst_node_type, set())
                )
                if len(matches) != 1 or matches[0][1] is None:
                    state = QueryState.UNRESOLVED
                    break
                matched_edges.append(matches[0])
        if state is QueryState.PRESENT:
            match_content = {
                "nodes": matched_nodes,
                "edges": matched_edges,
                **evidence_content,
            }
            match_ids = ("actionable_match_" + _digest(match_content),)
            roles_resolved = True
            bounded_complete = True
            evidence_content["match"] = match_content
        else:
            roles_resolved = False
            bounded_complete = False
    else:
        state = QueryState.UNRESOLVED
        roles_resolved = False
        bounded_complete = False
    evidence_content.update(
        {
            "state": state.value,
            "applicable": applicable,
            "required_roles_resolved": roles_resolved,
            "bounded_matching_complete": bounded_complete,
            "match_evidence_ids": match_ids,
        }
    )
    return ActionableFeatureQueryResultRecord.from_content(
        regime_id="natural_prompt_discovery",
        task_instance_id=binding.membership.task_instance_id,
        natural_prompt_id=binding.natural_prompt_id,
        prompt_tsg_sha256=binding.prompt_tsg_sha256,
        actionable_feature_spec_id=actionable.actionable_feature_spec_id,
        feature_id=actionable.feature_id,
        feature_catalog_sha256=actionable.feature_catalog_sha256,
        context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
        query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
        state=state,
        applicable=applicable,
        required_roles_resolved=roles_resolved,
        bounded_matching_complete=bounded_complete,
        match_evidence_ids=match_ids,
        evaluation_evidence_sha256=_digest(evidence_content),
    )


def evaluate_actionable_feature_query_v2(
    *,
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
    task_instance_id: str,
    actionable_feature_spec_id: str,
) -> ActionableFeatureQueryResultRecord:
    """Recompute one catalog-bound direct feature query from the canonical PromptTSG."""

    scope = AuthenticatedNaturalDiscoveryScopeV2.model_validate(authenticated_scope, strict=True)
    return _canonical_actionable_result(
        scope,
        task_instance_id=task_instance_id,
        actionable_feature_spec_id=actionable_feature_spec_id,
    )


def _canonical_context_result(
    scope: AuthenticatedNaturalDiscoveryScopeV2,
    *,
    task_instance_id: str,
    context_query_id: str,
) -> ContextQueryResultRecord:
    from secaware.tsg.context_queries_v2 import CONTEXT_QUERY_SPECS, evaluate_context_query

    binding = next(
        (
            item
            for item in scope.task_bindings
            if item.membership.task_instance_id == task_instance_id
        ),
        None,
    )
    spec = next(
        (item for item in CONTEXT_QUERY_SPECS if item.context_query_id == context_query_id),
        None,
    )
    if binding is None or spec is None:
        raise ValueError("context query is outside the authenticated scope")
    return evaluate_context_query(
        binding.prompt_tsg,
        spec.query_name,
        semantic_membership=binding.membership,
    ).result


def _derive_observation(
    *,
    scope: AuthenticatedNaturalDiscoveryScopeV2,
    generation_request: GenerationRequestRecordV2,
    generated_code: GeneratedCodeRecordV2,
    oracle_result: OracleResultRecordV2,
    functional_result: FunctionalResultRecordV2,
    actionable_query_results: tuple[ActionableFeatureQueryResultRecord, ...],
    context_query_results: tuple[ContextQueryResultRecord, ...],
) -> tuple[RuntimeProducerChainRecordV2, NaturalCausalObservationRecordV2, str]:
    table = scope.table_spec
    request = GenerationRequestRecordV2.model_validate(generation_request, strict=True)
    code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
    oracle = OracleResultRecordV2.model_validate(oracle_result, strict=True)
    functional = FunctionalResultRecordV2.model_validate(functional_result, strict=True)
    chain = validate_runtime_producer_chain_v2(request, code, oracle, functional)
    binding = next(
        (
            item
            for item in scope.task_bindings
            if item.membership.task_instance_id == request.task_instance_id
        ),
        None,
    )
    support = next(
        (
            item
            for item in table.task_slot_support
            if item.task_instance_id == request.task_instance_id
        ),
        None,
    )
    if (
        binding is None
        or support is None
        or request.regime_id != "natural_prompt_discovery"
        or request.model_id != table.model_id
        or request.semantic_task_cluster_id != support.semantic_task_cluster_id
        or request.prompt_id != binding.natural_prompt_id
        or request.prompt != binding.natural_prompt
        or request.prompt_sha256 != binding.natural_prompt_sha256
        or support.natural_prompt_id != binding.natural_prompt_id
        or request.request_randomness_slot not in support.request_randomness_slots
        or request.provider_seed != support.seed_for_slot(request.request_randomness_slot)
    ):
        raise ValueError("runtime request is outside the authenticated natural scope")
    actionable = tuple(
        ActionableFeatureQueryResultRecord.model_validate(item, strict=True)
        for item in actionable_query_results
    )
    contexts = tuple(
        ContextQueryResultRecord.model_validate(item, strict=True) for item in context_query_results
    )
    actionable_by_source = {item.actionable_feature_spec_id: item for item in actionable}
    context_by_source = {item.context_query_id: item for item in contexts}
    expected_actionable = {
        item.source_id
        for item in table.variables
        if item.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY
    }
    expected_context = {
        item.source_id
        for item in table.variables
        if item.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY
    }
    if (
        len(actionable_by_source) != len(actionable)
        or len(context_by_source) != len(contexts)
        or set(actionable_by_source) != expected_actionable
        or set(context_by_source) != expected_context
    ):
        raise ValueError("query-result coverage does not match the frozen variable table")
    for source_id, supplied in actionable_by_source.items():
        if supplied != _canonical_actionable_result(
            scope,
            task_instance_id=request.task_instance_id,
            actionable_feature_spec_id=source_id,
        ):
            raise ValueError("actionable query result is not canonical")
    for source_id, supplied in context_by_source.items():
        if supplied != _canonical_context_result(
            scope,
            task_instance_id=request.task_instance_id,
            context_query_id=source_id,
        ):
            raise ValueError("context query result is not canonical")
    x0: list[NaturalX0ValueV2] = []
    outcomes: list[NaturalOutcomeValueV2] = []
    projected_outcomes = _outcome_projection(code, oracle, functional)
    for variable in table.variables:
        if variable.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY:
            x0.append(
                NaturalX0ValueV2(
                    variable_id=variable.variable_id,
                    state=_QUERY_STATE_CODE[actionable_by_source[variable.source_id].state],
                )
            )
        elif variable.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY:
            x0.append(
                NaturalX0ValueV2(
                    variable_id=variable.variable_id,
                    state=_QUERY_STATE_CODE[context_by_source[variable.source_id].state],
                )
            )
        elif variable.source_kind is DiscoveryVariableSourceV2.OUTCOME_PROJECTION:
            outcomes.append(
                NaturalOutcomeValueV2(
                    variable_id=variable.variable_id,
                    state=projected_outcomes[variable.source_id],
                )
            )
        else:
            raise ValueError("authenticated assembly forbids caller-supplied task metadata")
    expected_x_ids = {
        item.variable_id for item in table.variables if item.role is not DiscoveryVariableRoleV2.Y
    }
    expected_y_ids = {
        item.variable_id for item in table.variables if item.role is DiscoveryVariableRoleV2.Y
    }
    if {item.variable_id for item in x0} != expected_x_ids or {
        item.variable_id for item in outcomes
    } != expected_y_ids:
        raise ValueError("authenticated observation has an invalid variable partition")
    observation = NaturalCausalObservationRecordV2.from_content(
        regime_id=request.regime_id,
        semantic_task_cluster_id=request.semantic_task_cluster_id,
        task_instance_id=request.task_instance_id,
        model_id=request.model_id,
        request_randomness_slot=request.request_randomness_slot,
        provider_seed=request.provider_seed,
        producer_chain_id=chain.producer_chain_id,
        table_id=table.table_spec_id,
        prompt_id=request.prompt_id,
        natural_x0=tuple(sorted(x0, key=lambda item: item.variable_id)),
        outcomes=tuple(sorted(outcomes, key=lambda item: item.variable_id)),
    )
    return chain, observation, binding.task_binding_id


class AuthenticatedNaturalObservationReceiptV2(SafeValidationMixin, StrictModel):
    """Self-authenticating receipt with every producer and derived table value embedded."""

    _safe_validation_message: ClassVar[str] = (
        "authenticated natural observation receipt failed validation"
    )
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = ASSEMBLY_RECEIPT_V2_SCHEMA_VERSION
    receipt_id: str = Field(pattern=_RECEIPT_PATTERN)
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2
    task_binding_id: str
    generation_request: GenerationRequestRecordV2
    generated_code: GeneratedCodeRecordV2
    oracle_result: OracleResultRecordV2
    functional_result: FunctionalResultRecordV2
    producer_chain: RuntimeProducerChainRecordV2
    actionable_query_results: tuple[ActionableFeatureQueryResultRecord, ...]
    context_query_results: tuple[ContextQueryResultRecord, ...]
    observation: NaturalCausalObservationRecordV2
    assembly_policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("actionable_query_results", "context_query_results", mode="before")
    @classmethod
    def snapshot_query_results(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @classmethod
    def from_components(
        cls,
        *,
        authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
        generation_request: GenerationRequestRecordV2,
        generated_code: GeneratedCodeRecordV2,
        oracle_result: OracleResultRecordV2,
        functional_result: FunctionalResultRecordV2,
        actionable_query_results: tuple[ActionableFeatureQueryResultRecord, ...],
        context_query_results: tuple[ContextQueryResultRecord, ...],
        assembly_policy_sha256: str,
    ) -> Self:
        try:
            scope = AuthenticatedNaturalDiscoveryScopeV2.model_validate(
                authenticated_scope, strict=True
            )
            if assembly_policy_sha256 != NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256:
                raise ValueError("assembly policy is not the canonical registered policy")
            chain, observation, task_binding_id = _derive_observation(
                scope=scope,
                generation_request=generation_request,
                generated_code=generated_code,
                oracle_result=oracle_result,
                functional_result=functional_result,
                actionable_query_results=actionable_query_results,
                context_query_results=context_query_results,
            )
            payload = {
                "schema_version": ASSEMBLY_RECEIPT_V2_SCHEMA_VERSION,
                "authenticated_scope": scope,
                "task_binding_id": task_binding_id,
                "generation_request": generation_request,
                "generated_code": generated_code,
                "oracle_result": oracle_result,
                "functional_result": functional_result,
                "producer_chain": chain,
                "actionable_query_results": actionable_query_results,
                "context_query_results": context_query_results,
                "observation": observation,
                "assembly_policy_sha256": assembly_policy_sha256,
            }
            return cls(
                **payload, receipt_id="authenticated_natural_observation_" + _digest(payload)
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise ValueError("natural discovery v2 assembly failed exact validation") from error

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            if "schema_version" in content or "receipt_id" in content:
                raise ValueError
            payload = {"schema_version": ASSEMBLY_RECEIPT_V2_SCHEMA_VERSION, **content}
            return cls(
                **payload, receipt_id="authenticated_natural_observation_" + _digest(payload)
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            content.clear()
            raise ValueError("natural discovery v2 assembly failed exact validation") from error

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        try:
            chain, observation, task_binding_id = _derive_observation(
                scope=self.authenticated_scope,
                generation_request=self.generation_request,
                generated_code=self.generated_code,
                oracle_result=self.oracle_result,
                functional_result=self.functional_result,
                actionable_query_results=self.actionable_query_results,
                context_query_results=self.context_query_results,
            )
            content = self.model_dump(mode="python", exclude={"receipt_id"})
            if (
                self.task_binding_id != task_binding_id
                or self.producer_chain != chain
                or self.observation != observation
                or self.assembly_policy_sha256 != NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256
                or self.receipt_id != "authenticated_natural_observation_" + _digest(content)
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize producer/query replay failures
            raise ValueError(self._safe_validation_message) from None
        return self


def assemble_natural_causal_observation_v2(
    *,
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
    generation_request: GenerationRequestRecordV2,
    generated_code: GeneratedCodeRecordV2,
    oracle_result: OracleResultRecordV2,
    functional_result: FunctionalResultRecordV2,
    actionable_query_results: tuple[ActionableFeatureQueryResultRecord, ...],
    context_query_results: tuple[ContextQueryResultRecord, ...] = (),
    assembly_policy_sha256: str,
) -> AuthenticatedNaturalObservationReceiptV2:
    """Derive X0/Y from embedded authenticated producers; no table values are accepted."""

    return AuthenticatedNaturalObservationReceiptV2.from_components(
        authenticated_scope=authenticated_scope,
        generation_request=generation_request,
        generated_code=generated_code,
        oracle_result=oracle_result,
        functional_result=functional_result,
        actionable_query_results=actionable_query_results,
        context_query_results=context_query_results,
        assembly_policy_sha256=assembly_policy_sha256,
    )


__all__ = [
    "ASSEMBLY_RECEIPT_V2_SCHEMA_VERSION",
    "AuthenticatedNaturalObservationReceiptV2",
    "assemble_natural_causal_observation_v2",
    "evaluate_actionable_feature_query_v2",
]

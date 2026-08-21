from __future__ import annotations

import hashlib
from functools import lru_cache

import networkx as nx

from secaware.causal.authenticated_natural_table_v2 import (
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    build_authenticated_natural_discovery_table_v2,
)
from secaware.outcomes.discovery_assembler_v2 import (
    assemble_natural_causal_observation_v2,
    evaluate_actionable_feature_query_v2,
)
from secaware.schema.discovery_v2 import (
    NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
    NATURAL_OUTCOME_PROJECTION_POLICY_SHA256,
    AuthenticatedNaturalDiscoveryScopeV2,
    DiscoveryAnalysisKindV2,
    DiscoveryTableKindV2,
    DiscoveryTaskSlotSupportV2,
    DiscoveryVariableRoleV2,
    DiscoveryVariableSourceV2,
    NaturalDiscoveryTableSpecV2,
    NaturalDiscoveryVariableSpecV2,
    NaturalTaskBindingV2,
)
from secaware.schema.features import (
    FeatureFamily,
    FeatureOperation,
    FeatureState,
    PromptExtractorBackend,
)
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    PolicySplit,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.runtime_v2 import (
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
)
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.context_queries_v2 import (
    CONTEXT_QUERY_CATALOG_SHA256,
    CONTEXT_QUERY_SEMANTICS_VERSION,
    CWE89_SQL_FLOW_QUERY,
    context_query_spec,
    evaluate_context_query,
)
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_edge_slots,
    prompt_feature_node_slots,
)
from secaware.tsg.graph import multidigraph_to_record

_PROMPT = "x"
_EXTRACTOR_POLICY_SHA256 = "a" * 64
_TARGET_FEATURE_ID = "safety.sql_parameterization"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evidence() -> dict[str, str | int]:
    return {
        "evidence_start": 0,
        "evidence_end": 1,
        "evidence_sha256": _sha(_PROMPT),
    }


def _prompt_tsg(task_index: int, *, x_state: int):
    graph = nx.MultiDiGraph()

    def add_node(key: str, node_type: NodeType, label: str, attributes=None) -> str:
        graph.add_node(
            key,
            node_type=node_type,
            label=label,
            attributes=_evidence() if attributes is None else attributes,
        )
        return key

    def add_edge(source: str, target: str, edge_type: EdgeType) -> None:
        graph.add_edge(source, target, edge_type=edge_type, attributes=_evidence())

    operation = add_node("operation", NodeType.TASK_OPERATION, "database_query")
    source = add_node("source", NodeType.SOURCE, "untrusted_input")
    data = add_node("data", NodeType.DATA_OBJECT, "user_query_value")
    sink = add_node("sink", NodeType.SINK, "database_execute")
    add_edge(operation, data, EdgeType.OPERATES_ON)
    add_edge(source, data, EdgeType.SOURCE_OF)
    add_edge(data, sink, EdgeType.FLOWS_TO)

    if x_state == 0:
        target_nodes: dict[NodeType, str] = {}
        for slot in prompt_feature_node_slots(_TARGET_FEATURE_ID):
            target_nodes[slot.node_type] = add_node(
                f"target:{slot.node_type.value}", slot.node_type, slot.canonical_label
            )
        for slot in prompt_feature_edge_slots(_TARGET_FEATURE_ID):
            add_edge(
                target_nodes[slot.src_node_type],
                target_nodes[slot.dst_node_type],
                slot.edge_type,
            )

    for feature in PROMPT_FEATURE_CATALOG:
        state = FeatureState.ABSENT
        if feature.feature_id == "task.database_query" or (
            feature.feature_id == _TARGET_FEATURE_ID and x_state == 0
        ):
            state = FeatureState.PRESENT
        node_type = (
            NodeType.PRESENTATION_FEATURE
            if feature.feature_family is FeatureFamily.PRESENTATION_CONTROL
            else NodeType.FEATURE
        )
        add_node(
            f"feature:{feature.feature_id}",
            node_type,
            feature.feature_id,
            {
                "feature_id": feature.feature_id,
                "feature_family": feature.feature_family.value,
                "feature_state": state.value,
            },
        )
    return multidigraph_to_record(
        graph,
        prompt_id=f"prompt.synthetic.sql.{task_index:06d}",
        task_id=f"task.synthetic.sql.{task_index:06d}",
        task_family="sql_query",
        cwe="CWE-89",
        extractor_backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V2,
        extractor_policy_sha256=_EXTRACTOR_POLICY_SHA256,
        proposal_id="proposal_" + "b" * 64,
    )


@lru_cache(maxsize=16)
def build_authenticated_synthetic_table_v2(
    *,
    x_states: tuple[int, ...],
    y_by_task_slot: tuple[tuple[int, ...], ...],
    analysis_kind: DiscoveryAnalysisKindV2,
) -> AuthenticatedNaturalDiscoveryTableArtifactV2:
    if (
        not x_states
        or len(x_states) != len(y_by_task_slot)
        or any(item not in {0, 1} for item in x_states)
        or any(
            not values or any(value not in {0, 1} for value in values) for values in y_by_task_slot
        )
    ):
        raise ValueError("invalid synthetic fixture")
    slot_count = 2 if analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL else 1
    if any(len(values) != slot_count for values in y_by_task_slot):
        raise ValueError("invalid synthetic slot fixture")

    clustering_policy = _sha("synthetic-semantic-clustering-v2")
    memberships = tuple(
        SemanticTaskClusterMembershipRecord.from_content(
            semantic_task_cluster_id=f"cluster.synthetic.sql.{index:06d}",
            task_instance_id=f"task.synthetic.sql.{index:06d}",
            split=PolicySplit.DISCOVER,
            cwe="CWE-89",
            task_archetype="value-parameterization",
            source_task_sha256=_sha(f"source-task-{index}"),
            clustering_policy_sha256=clustering_policy,
            adjudication_sha256=_sha(f"adjudication-{index}"),
        )
        for index in range(len(x_states))
    )
    manifest = SemanticTaskClusterManifest.from_content(
        memberships=memberships,
        clustering_algorithm_sha256=clustering_policy,
        normalization_policy_sha256=_sha("synthetic-normalization-v2"),
        construction_digest_sha256=_sha("synthetic-construction-v2"),
        frozen_before_discovery=True,
    )
    graphs = tuple(_prompt_tsg(index, x_state=x_state) for index, x_state in enumerate(x_states))
    bindings = tuple(
        NaturalTaskBindingV2.from_content(
            membership=membership,
            natural_prompt_id=graph.prompt_id,
            natural_prompt=_PROMPT,
            natural_prompt_sha256=_sha(_PROMPT),
            prompt_tsg=graph,
            prompt_tsg_sha256=graph.graph_sha256,
            extractor_policy_sha256=_EXTRACTOR_POLICY_SHA256,
            feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
            query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
            frozen_before_outcomes=True,
        )
        for membership, graph in zip(memberships, graphs, strict=True)
    )
    actionable = ActionableFeatureSpec.from_content(
        feature_id=_TARGET_FEATURE_ID,
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=_sha("synthetic-task-preserving-edit-v2"),
    )
    variables = (
        NaturalDiscoveryVariableSpecV2.from_content(
            variable_id="x.sql_parameterization",
            role=DiscoveryVariableRoleV2.X,
            states=("present", "absent", "not_applicable", "unresolved"),
            source_kind=DiscoveryVariableSourceV2.ACTIONABLE_QUERY,
            source_id=actionable.actionable_feature_spec_id,
            source_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
            temporal_tier=1,
            adjacency_type="prompt_feature",
        ),
        NaturalDiscoveryVariableSpecV2.from_content(
            variable_id="y.secure_yield",
            role=DiscoveryVariableRoleV2.Y,
            states=("0", "1"),
            source_kind=DiscoveryVariableSourceV2.OUTCOME_PROJECTION,
            source_id="y_secure_yield",
            source_catalog_sha256=NATURAL_OUTCOME_PROJECTION_POLICY_SHA256,
            query_semantics_version=None,
            temporal_tier=2,
            adjacency_type="committed_outcome",
        ),
    )
    supports = tuple(
        DiscoveryTaskSlotSupportV2.from_content(
            semantic_task_cluster_id=membership.semantic_task_cluster_id,
            task_instance_id=membership.task_instance_id,
            natural_prompt_id=graph.prompt_id,
            request_randomness_slots=tuple(range(slot_count)),
            provider_seeds=tuple(10_000 + index * 10 + slot for slot in range(slot_count)),
            reference_slot=0,
            slot_freeze_policy_sha256=_sha("synthetic-slot-freeze-v2"),
            frozen_before_outcomes=True,
        )
        for index, (membership, graph) in enumerate(zip(memberships, graphs, strict=True))
    )
    context_spec = context_query_spec(CWE89_SQL_FLOW_QUERY)
    context_results = tuple(
        evaluate_context_query(
            graph,
            context_spec.query_name,
            semantic_membership=membership,
        ).result
        for graph, membership in zip(graphs, memberships, strict=True)
    )
    table_spec = NaturalDiscoveryTableSpecV2.from_content(
        scope_id="scope.cwe89.synthetic_value_parameterization",
        cwe="CWE-89",
        task_archetypes=("value-parameterization",),
        model_id="model.synthetic.v2",
        table_kind=DiscoveryTableKindV2.DIRECT_FEATURE,
        analysis_kind=analysis_kind,
        semantic_cluster_manifest=manifest,
        context_conditioning_query_id=context_spec.context_query_id,
        context_query_results=context_results,
        task_slot_support=supports,
        variables=variables,
        missing_state_policy="categorical_four_state_v1",
        two_level_selection_rule=(
            "cluster_then_uniform_frozen_slot_v1"
            if analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL
            else "not_applicable"
        ),
        multi_slot_aggregation_rule="not_applicable",
        extractor_policy_sha256=_EXTRACTOR_POLICY_SHA256,
        outcome_projection_policy_sha256=NATURAL_OUTCOME_PROJECTION_POLICY_SHA256,
        table_construction_policy_sha256=_sha("synthetic-table-construction-v2"),
        frozen_before_outcomes=True,
    )
    scope = AuthenticatedNaturalDiscoveryScopeV2.from_content(
        table_spec=table_spec,
        task_bindings=bindings,
        actionable_feature_specs=(actionable,),
        scope_construction_policy_sha256=_sha("synthetic-scope-construction-v2"),
        frozen_before_outcomes=True,
    )

    receipts = []
    for task_index, support in enumerate(supports):
        query = evaluate_actionable_feature_query_v2(
            authenticated_scope=scope,
            task_instance_id=support.task_instance_id,
            actionable_feature_spec_id=actionable.actionable_feature_spec_id,
        )
        for slot in support.request_randomness_slots:
            coordinates = {
                "regime_id": "natural_prompt_discovery",
                "semantic_task_cluster_id": support.semantic_task_cluster_id,
                "task_instance_id": support.task_instance_id,
                "model_id": table_spec.model_id,
                "request_randomness_slot": slot,
                "provider_seed": support.seed_for_slot(slot),
            }
            request = GenerationRequestRecordV2.from_content(
                **coordinates,
                prompt_id=support.natural_prompt_id,
                prompt=_PROMPT,
                prompt_sha256=_sha(_PROMPT),
                language="python",
                endpoint_sha256=_sha("synthetic-endpoint-v2"),
                generation_parameters_sha256=_sha("synthetic-generation-parameters-v2"),
                system_template_sha256=_sha("synthetic-system-template-v2"),
                generator_producer_id="generator.synthetic.v2",
                generator_policy_sha256=_sha("synthetic-generator-policy-v2"),
            )
            code_text = f"result = {task_index + slot}"
            code = GeneratedCodeRecordV2.from_content(
                **coordinates,
                generation_request_id=request.generation_request_id,
                code_status="generated",
                code=code_text,
                code_sha256=_sha(code_text),
                terminal_reason=None,
                provider_response_sha256=_sha(f"provider-{task_index}-{slot}"),
                generator_runtime_sha256=_sha("synthetic-generator-runtime-v2"),
            )
            secure = y_by_task_slot[task_index][slot] == 1
            oracle = OracleResultRecordV2.from_content(
                **coordinates,
                generated_code_id=code.generated_code_id,
                code_sha256=code.code_sha256,
                status="secure" if secure else "insecure",
                oracle_supported=True,
                oracle_evaluable=True,
                evidence_sha256=_sha(f"oracle-{task_index}-{slot}"),
                oracle_producer_id="oracle.synthetic.v2",
                oracle_policy_sha256=_sha("synthetic-oracle-policy-v2"),
                oracle_runtime_sha256=_sha("synthetic-oracle-runtime-v2"),
            )
            functional = FunctionalResultRecordV2.from_content(
                **coordinates,
                generated_code_id=code.generated_code_id,
                code_sha256=code.code_sha256,
                status="pass",
                evidence_sha256=_sha(f"functional-{task_index}-{slot}"),
                evaluator_producer_id="functional.synthetic.v2",
                evaluator_policy_sha256=_sha("synthetic-functional-policy-v2"),
                evaluator_runtime_sha256=_sha("synthetic-functional-runtime-v2"),
            )
            receipts.append(
                assemble_natural_causal_observation_v2(
                    authenticated_scope=scope,
                    generation_request=request,
                    generated_code=code,
                    oracle_result=oracle,
                    functional_result=functional,
                    actionable_query_results=(query,),
                    assembly_policy_sha256=NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
                )
            )
    return build_authenticated_natural_discovery_table_v2(
        authenticated_scope=scope,
        receipts=tuple(receipts),
    )


__all__ = ["build_authenticated_synthetic_table_v2"]

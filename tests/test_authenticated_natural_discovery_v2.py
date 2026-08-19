from __future__ import annotations

import hashlib

import networkx as nx
import pytest

from secaware.causal.authenticated_natural_table_v2 import (
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    authenticated_categorical_rows_for_fci_v2,
    build_authenticated_natural_discovery_table_v2,
    build_two_level_cluster_resample_v2,
    two_level_categorical_rows_for_fci_v2,
)
from secaware.causal.natural_table_v2 import categorical_rows_v2
from secaware.outcomes.discovery_assembler_v2 import (
    AuthenticatedNaturalObservationReceiptV2,
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
    ActionableFeatureQueryResultRecord,
    ActionableFeatureSpec,
    PolicySplit,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.runtime_v2 import (
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    NaturalCausalObservationRecordV2,
    NaturalX0ValueV2,
    OracleResultRecordV2,
    RuntimeProducerChainRecordV2,
)
from secaware.schema.tsg import EdgeType, NodeType
from secaware.tsg.context_queries_v2 import (
    CONTEXT_QUERY_CATALOG_SHA256,
    CONTEXT_QUERY_SEMANTICS_VERSION,
)
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_edge_slots,
    prompt_feature_node_slots,
)
from secaware.tsg.graph import multidigraph_to_record

_PROMPT = "x"
_EXTRACTOR_POLICY = "a" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evidence() -> dict[str, str | int]:
    return {"evidence_start": 0, "evidence_end": 1, "evidence_sha256": _sha(_PROMPT)}


def _graph(task_index: int, *, target_present: bool):
    graph = nx.MultiDiGraph()

    def add_node(key: str, node_type: NodeType, label: str, attributes=None) -> str:
        graph.add_node(
            key,
            node_type=node_type,
            label=label,
            attributes=_evidence() if attributes is None else attributes,
        )
        return key

    def add_edge(src: str, dst: str, edge_type: EdgeType) -> None:
        graph.add_edge(src, dst, edge_type=edge_type, attributes=_evidence())

    operation = add_node("operation", NodeType.TASK_OPERATION, "database_query")
    source = add_node("source", NodeType.SOURCE, "untrusted_input")
    data = add_node("data", NodeType.DATA_OBJECT, "user_query_value")
    sink = add_node("sink", NodeType.SINK, "database_execute")
    add_edge(operation, data, EdgeType.OPERATES_ON)
    add_edge(source, data, EdgeType.SOURCE_OF)
    add_edge(data, sink, EdgeType.FLOWS_TO)

    target_id = "safety.sql_parameterization"
    if target_present:
        target_nodes: dict[NodeType, str] = {}
        for slot in prompt_feature_node_slots(target_id):
            target_nodes[slot.node_type] = add_node(
                f"target:{slot.node_type.value}", slot.node_type, slot.canonical_label
            )
        for slot in prompt_feature_edge_slots(target_id):
            add_edge(
                target_nodes[slot.src_node_type],
                target_nodes[slot.dst_node_type],
                slot.edge_type,
            )

    for feature in PROMPT_FEATURE_CATALOG:
        state = FeatureState.ABSENT
        if feature.feature_id == "task.database_query" or (
            feature.feature_id == target_id and target_present
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
        prompt_id=f"prompt.sql.{task_index}",
        task_id=f"task.sql.{task_index}",
        task_family="sql_query",
        cwe="CWE-89",
        extractor_backend=PromptExtractorBackend.DETERMINISTIC_CATALOG_V2,
        extractor_policy_sha256=_EXTRACTOR_POLICY,
        proposal_id="proposal_" + "b" * 64,
    )


def _scope(
    analysis_kind: DiscoveryAnalysisKindV2,
) -> AuthenticatedNaturalDiscoveryScopeV2:
    clustering_policy = _sha("semantic-clustering")
    memberships = tuple(
        SemanticTaskClusterMembershipRecord.from_content(
            semantic_task_cluster_id=f"cluster.sql.{index}",
            task_instance_id=f"task.sql.{index}",
            split=PolicySplit.DISCOVER,
            cwe="CWE-89",
            task_archetype="value-parameterization",
            source_task_sha256=_sha(f"source-{index}"),
            clustering_policy_sha256=clustering_policy,
            adjudication_sha256=_sha(f"adjudication-{index}"),
        )
        for index in range(4)
    )
    manifest = SemanticTaskClusterManifest.from_content(
        memberships=memberships,
        clustering_algorithm_sha256=clustering_policy,
        normalization_policy_sha256=_sha("normalization"),
        construction_digest_sha256=_sha("construction"),
        frozen_before_discovery=True,
    )
    graphs = tuple(_graph(index, target_present=index % 2 == 1) for index in range(4))
    bindings = tuple(
        NaturalTaskBindingV2.from_content(
            membership=membership,
            natural_prompt_id=graph.prompt_id,
            natural_prompt=_PROMPT,
            natural_prompt_sha256=_sha(_PROMPT),
            prompt_tsg=graph,
            prompt_tsg_sha256=graph.graph_sha256,
            extractor_policy_sha256=_EXTRACTOR_POLICY,
            feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
            query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
            frozen_before_outcomes=True,
        )
        for membership, graph in zip(memberships, graphs, strict=True)
    )
    actionable = ActionableFeatureSpec.from_content(
        feature_id="safety.sql_parameterization",
        feature_catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        allowed_operations=(FeatureOperation.ADD, FeatureOperation.REMOVE),
        task_preserving_edit_policy_sha256=_sha("task-preserving-edit"),
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
            request_randomness_slots=(0, 1),
            provider_seeds=(100 + index, 200 + index),
            reference_slot=0,
            slot_freeze_policy_sha256=_sha("slot-freeze"),
            frozen_before_outcomes=True,
        )
        for index, (membership, graph) in enumerate(zip(memberships, graphs, strict=True))
    )
    two_level = analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL
    table = NaturalDiscoveryTableSpecV2.from_content(
        scope_id="scope.cwe89.value-parameterization",
        cwe="CWE-89",
        task_archetypes=("value-parameterization",),
        model_id="model.alpha",
        table_kind=DiscoveryTableKindV2.DIRECT_FEATURE,
        analysis_kind=analysis_kind,
        semantic_cluster_manifest=manifest,
        context_conditioning_query_id=None,
        context_query_results=(),
        task_slot_support=supports,
        variables=variables,
        missing_state_policy="categorical_four_state_v1",
        two_level_selection_rule=(
            "cluster_then_uniform_frozen_slot_v1" if two_level else "not_applicable"
        ),
        multi_slot_aggregation_rule="not_applicable",
        extractor_policy_sha256=_EXTRACTOR_POLICY,
        outcome_projection_policy_sha256=NATURAL_OUTCOME_PROJECTION_POLICY_SHA256,
        table_construction_policy_sha256=_sha("table-construction"),
        frozen_before_outcomes=True,
    )
    return AuthenticatedNaturalDiscoveryScopeV2.from_content(
        table_spec=table,
        task_bindings=bindings,
        actionable_feature_specs=(actionable,),
        scope_construction_policy_sha256=_sha("scope-construction"),
        frozen_before_outcomes=True,
    )


def _runtime(scope, task_index: int, slot: int, *, secure: bool | None = None, prompt="x"):
    support = scope.table_spec.task_slot_support[task_index]
    coordinates = {
        "regime_id": "natural_prompt_discovery",
        "semantic_task_cluster_id": support.semantic_task_cluster_id,
        "task_instance_id": support.task_instance_id,
        "model_id": scope.table_spec.model_id,
        "request_randomness_slot": slot,
        "provider_seed": support.seed_for_slot(slot),
    }
    request = GenerationRequestRecordV2.from_content(
        **coordinates,
        prompt_id=support.natural_prompt_id,
        prompt=prompt,
        prompt_sha256=_sha(prompt),
        language="python",
        endpoint_sha256=_sha("endpoint"),
        generation_parameters_sha256=_sha("parameters"),
        system_template_sha256=_sha("system"),
        generator_producer_id="generator.alpha",
        generator_policy_sha256=_sha("generator-policy"),
    )
    code_text = f"result = {task_index + slot}"
    code = GeneratedCodeRecordV2.from_content(
        **coordinates,
        generation_request_id=request.generation_request_id,
        code_status="generated",
        code=code_text,
        code_sha256=_sha(code_text),
        terminal_reason=None,
        provider_response_sha256=_sha(f"provider-{task_index}-{slot}-{prompt}"),
        generator_runtime_sha256=_sha("generator-runtime"),
    )
    secure = task_index >= 2 if secure is None else secure
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure" if secure else "insecure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256=_sha(f"oracle-evidence-{task_index}-{slot}"),
        oracle_producer_id="oracle.alpha",
        oracle_policy_sha256=_sha("oracle-policy"),
        oracle_runtime_sha256=_sha("oracle-runtime"),
    )
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="pass",
        evidence_sha256=_sha(f"functional-evidence-{task_index}-{slot}"),
        evaluator_producer_id="functional.alpha",
        evaluator_policy_sha256=_sha("functional-policy"),
        evaluator_runtime_sha256=_sha("functional-runtime"),
    )
    return request, code, oracle, functional


def _receipts(scope, *, force_insecure: bool = False):
    receipts = []
    for task_index, support in enumerate(scope.table_spec.task_slot_support):
        slots = (
            support.request_randomness_slots
            if scope.table_spec.analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL
            else (support.reference_slot,)
        )
        for slot in slots:
            runtime = _runtime(
                scope,
                task_index,
                slot,
                secure=False if force_insecure else None,
            )
            query = evaluate_actionable_feature_query_v2(
                authenticated_scope=scope,
                task_instance_id=support.task_instance_id,
                actionable_feature_spec_id=scope.actionable_feature_specs[
                    0
                ].actionable_feature_spec_id,
            )
            receipts.append(
                assemble_natural_causal_observation_v2(
                    authenticated_scope=scope,
                    generation_request=runtime[0],
                    generated_code=runtime[1],
                    oracle_result=runtime[2],
                    functional_result=runtime[3],
                    actionable_query_results=(query,),
                    assembly_policy_sha256=NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
                )
            )
    return tuple(receipts)


def test_authenticated_table_recomputes_values_and_rejects_tampering() -> None:
    scope = _scope(DiscoveryAnalysisKindV2.FIXED_REFERENCE)
    receipts = _receipts(scope)
    table = build_authenticated_natural_discovery_table_v2(
        authenticated_scope=scope, receipts=receipts
    )
    assert authenticated_categorical_rows_for_fci_v2(table) == (
        (1, 0),
        (0, 0),
        (1, 1),
        (0, 1),
    )

    original = receipts[0]
    altered_observation = NaturalCausalObservationRecordV2.from_content(
        **original.observation.model_dump(
            mode="python", exclude={"schema_version", "natural_causal_observation_id", "natural_x0"}
        ),
        natural_x0=(NaturalX0ValueV2(variable_id="x.sql_parameterization", state=0),),
    )
    content = original.model_dump(mode="python", exclude={"schema_version", "receipt_id"})
    content["observation"] = altered_observation
    with pytest.raises(ValueError, match="natural discovery v2 assembly failed"):
        AuthenticatedNaturalObservationReceiptV2.from_content(**content)

    fake_chain = RuntimeProducerChainRecordV2.from_content(
        **original.producer_chain.model_dump(
            mode="python",
            exclude={
                "schema_version",
                "producer_chain_id",
                "generation_request_id",
            },
        ),
        generation_request_id="generation_request_v2_" + "f" * 64,
    )
    content = original.model_dump(mode="python", exclude={"schema_version", "receipt_id"})
    content["producer_chain"] = fake_chain
    with pytest.raises(ValueError, match="natural discovery v2 assembly failed"):
        AuthenticatedNaturalObservationReceiptV2.from_content(**content)


def test_scope_and_assembly_reject_deleted_task_wrong_prompt_and_catalog() -> None:
    scope = _scope(DiscoveryAnalysisKindV2.FIXED_REFERENCE)
    with pytest.raises(ValueError, match="natural discovery v2 contract failed validation"):
        AuthenticatedNaturalDiscoveryScopeV2.from_content(
            table_spec=scope.table_spec,
            task_bindings=scope.task_bindings[:-1],
            actionable_feature_specs=scope.actionable_feature_specs,
            scope_construction_policy_sha256=scope.scope_construction_policy_sha256,
            frozen_before_outcomes=True,
        )

    runtime = _runtime(scope, 0, 0, prompt="wrong prompt")
    canonical = evaluate_actionable_feature_query_v2(
        authenticated_scope=scope,
        task_instance_id="task.sql.0",
        actionable_feature_spec_id=scope.actionable_feature_specs[0].actionable_feature_spec_id,
    )
    with pytest.raises(ValueError, match="natural discovery v2 assembly failed"):
        assemble_natural_causal_observation_v2(
            authenticated_scope=scope,
            generation_request=runtime[0],
            generated_code=runtime[1],
            oracle_result=runtime[2],
            functional_result=runtime[3],
            actionable_query_results=(canonical,),
            assembly_policy_sha256=NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
        )

    query_content = canonical.model_dump(
        mode="python", exclude={"schema_version", "actionable_query_result_id"}
    )
    query_content["feature_catalog_sha256"] = "f" * 64
    wrong_catalog = ActionableFeatureQueryResultRecord.from_content(**query_content)
    runtime = _runtime(scope, 0, 0)
    with pytest.raises(ValueError, match="natural discovery v2 assembly failed"):
        assemble_natural_causal_observation_v2(
            authenticated_scope=scope,
            generation_request=runtime[0],
            generated_code=runtime[1],
            oracle_result=runtime[2],
            functional_result=runtime[3],
            actionable_query_results=(wrong_catalog,),
            assembly_policy_sha256=NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256,
        )


def test_two_level_raw_rows_are_blocked_and_draw_is_reproducible() -> None:
    scope = _scope(DiscoveryAnalysisKindV2.TWO_LEVEL)
    table = build_authenticated_natural_discovery_table_v2(
        authenticated_scope=scope, receipts=_receipts(scope)
    )
    with pytest.raises(ValueError, match="raw two-level"):
        categorical_rows_v2(table.raw_audit_table)
    with pytest.raises(ValueError, match="formal CI requires"):
        authenticated_categorical_rows_for_fci_v2(table)

    passing_draw = None
    for seed in range(100):
        draw = build_two_level_cluster_resample_v2(
            authenticated_table=table,
            resample_seed=seed,
            resample_domain="discovery.bootstrap.main",
        )
        if draw.minimal_generating_set_passed:
            passing_draw = draw
            break
    assert passing_draw is not None
    replay = build_two_level_cluster_resample_v2(
        authenticated_table=table,
        resample_seed=passing_draw.resample_seed,
        resample_domain=passing_draw.resample_domain,
    )
    assert replay == passing_draw
    assert two_level_categorical_rows_for_fci_v2(replay) == tuple(
        item.row for item in replay.selections
    )


def test_formal_table_rejects_constant_outcome_but_raw_receipts_remain_available() -> None:
    scope = _scope(DiscoveryAnalysisKindV2.FIXED_REFERENCE)
    receipts = _receipts(scope, force_insecure=True)
    with pytest.raises(ValueError, match="authenticated natural discovery table"):
        build_authenticated_natural_discovery_table_v2(authenticated_scope=scope, receipts=receipts)
    assert len(receipts) == 4
    with pytest.raises(ValueError, match="authenticated natural discovery table"):
        AuthenticatedNaturalDiscoveryTableArtifactV2.from_receipts(
            authenticated_scope=scope, receipts=receipts
        )

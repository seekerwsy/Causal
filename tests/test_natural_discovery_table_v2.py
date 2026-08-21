from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secaware.causal.natural_table_v2 import (
    build_natural_discovery_table_v2,
    categorical_rows_v2,
)
from secaware.schema.discovery_v2 import (
    DiscoveryAnalysisKindV2,
    DiscoveryTableKindV2,
    DiscoveryTaskSlotSupportV2,
    DiscoveryVariableRoleV2,
    DiscoveryVariableSourceV2,
    NaturalDiscoveryTableSpecV2,
    NaturalDiscoveryVariableSpecV2,
)
from secaware.schema.policy_v2 import (
    ContextQueryResultRecord,
    PolicySplit,
    QueryState,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.runtime_v2 import (
    NaturalCausalObservationRecordV2,
    NaturalOutcomeValueV2,
    NaturalX0ValueV2,
    RuntimeProducerChainRecordV2,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _content_id(prefix: str, value: str) -> str:
    return f"{prefix}_{_sha(value)}"


def _cluster_manifest() -> SemanticTaskClusterManifest:
    policy_sha = _sha("semantic-clustering-policy")
    memberships = tuple(
        SemanticTaskClusterMembershipRecord.from_content(
            semantic_task_cluster_id=f"cluster.sql.{index}",
            task_instance_id=f"task.sql.{index}",
            split=PolicySplit.DISCOVER,
            cwe="CWE-89",
            task_archetype="value_parameterization",
            source_task_sha256=_sha(f"source-task-{index}"),
            clustering_policy_sha256=policy_sha,
            adjudication_sha256=_sha(f"adjudication-{index}"),
        )
        for index in range(4)
    )
    return SemanticTaskClusterManifest.from_content(
        memberships=memberships,
        clustering_algorithm_sha256=policy_sha,
        normalization_policy_sha256=_sha("normalization"),
        construction_digest_sha256=_sha("cluster-construction"),
        frozen_before_discovery=True,
    )


def _variables() -> tuple[NaturalDiscoveryVariableSpecV2, ...]:
    feature = NaturalDiscoveryVariableSpecV2.from_content(
        variable_id="x.sql_parameterization",
        role=DiscoveryVariableRoleV2.X,
        states=("present", "absent", "not_applicable", "unresolved"),
        source_kind=DiscoveryVariableSourceV2.ACTIONABLE_QUERY,
        source_id="actionable_feature_" + _sha("sql-parameterization"),
        source_catalog_sha256=_sha("feature-catalog"),
        query_semantics_version="context-query-v2.1",
        temporal_tier=1,
        adjacency_type="prompt_feature",
    )
    outcome = NaturalDiscoveryVariableSpecV2.from_content(
        variable_id="y.secure_yield",
        role=DiscoveryVariableRoleV2.Y,
        states=("0", "1"),
        source_kind=DiscoveryVariableSourceV2.OUTCOME_PROJECTION,
        source_id="y_secure_yield",
        source_catalog_sha256=_sha("outcome-projection"),
        query_semantics_version=None,
        temporal_tier=2,
        adjacency_type="committed_outcome",
    )
    return feature, outcome


def _slot_support(
    indices: tuple[int, ...] = (0, 1, 2, 3),
) -> tuple[DiscoveryTaskSlotSupportV2, ...]:
    return tuple(
        DiscoveryTaskSlotSupportV2.from_content(
            semantic_task_cluster_id=f"cluster.sql.{index}",
            task_instance_id=f"task.sql.{index}",
            natural_prompt_id=f"prompt.sql.{index}",
            request_randomness_slots=(0, 1),
            provider_seeds=(None, index + 100),
            reference_slot=0,
            slot_freeze_policy_sha256=_sha("slot-freeze"),
            frozen_before_outcomes=True,
        )
        for index in indices
    )


def _context_results() -> tuple[ContextQueryResultRecord, ...]:
    query_id = "context_query_" + _sha("sql-context")
    results = []
    for index in range(4):
        present = index in {0, 2}
        results.append(
            ContextQueryResultRecord.from_content(
                regime_id="natural_prompt_discovery",
                task_instance_id=f"task.sql.{index}",
                natural_prompt_id=f"prompt.sql.{index}",
                prompt_tsg_sha256=_sha(f"tsg-{index}"),
                context_query_id=query_id,
                context_query_catalog_sha256=_sha("context-catalog"),
                query_semantics_version="context-query-v2.1",
                state=QueryState.PRESENT if present else QueryState.ABSENT,
                applicable=True,
                required_roles_resolved=True,
                bounded_matching_complete=True,
                match_evidence_ids=(f"evidence.sql.{index}",) if present else (),
                evaluation_evidence_sha256=_sha(f"query-evaluation-{index}"),
            )
        )
    return tuple(results)


def _table_spec(
    analysis_kind: DiscoveryAnalysisKindV2,
    *,
    conditioned: bool = False,
) -> NaturalDiscoveryTableSpecV2:
    if analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL:
        two_level = "cluster_then_uniform_frozen_slot_v1"
        multi_slot = "not_applicable"
    elif analysis_kind is DiscoveryAnalysisKindV2.MULTI_SLOT_SENSITIVITY:
        two_level = "not_applicable"
        multi_slot = "categorical_mode_tie_lowest_state_v1"
    else:
        two_level = "not_applicable"
        multi_slot = "not_applicable"
    results = _context_results() if conditioned else ()
    return NaturalDiscoveryTableSpecV2.from_content(
        scope_id="scope.cwe89.value_parameterization",
        cwe="CWE-89",
        task_archetypes=("value_parameterization",),
        model_id="model.alpha",
        table_kind=DiscoveryTableKindV2.DIRECT_FEATURE,
        analysis_kind=analysis_kind,
        semantic_cluster_manifest=_cluster_manifest(),
        context_conditioning_query_id=(results[0].context_query_id if results else None),
        context_query_results=results,
        task_slot_support=_slot_support((0, 2) if conditioned else (0, 1, 2, 3)),
        variables=_variables(),
        missing_state_policy="categorical_four_state_v1",
        two_level_selection_rule=two_level,
        multi_slot_aggregation_rule=multi_slot,
        extractor_policy_sha256=_sha("extractor-policy"),
        outcome_projection_policy_sha256=_sha("outcome-projection"),
        table_construction_policy_sha256=_sha("table-construction"),
        frozen_before_outcomes=True,
    )


def _rows_and_chains(
    spec: NaturalDiscoveryTableSpecV2,
    *,
    x_drift_task: str | None = None,
) -> tuple[
    tuple[NaturalCausalObservationRecordV2, ...],
    tuple[RuntimeProducerChainRecordV2, ...],
]:
    observations = []
    chains = []
    x_by_task = {"task.sql.0": 0, "task.sql.1": 1, "task.sql.2": 0, "task.sql.3": 1}
    y_by_task_slot = {
        ("task.sql.0", 0): 0,
        ("task.sql.0", 1): 1,
        ("task.sql.1", 0): 0,
        ("task.sql.1", 1): 0,
        ("task.sql.2", 0): 1,
        ("task.sql.2", 1): 1,
        ("task.sql.3", 0): 1,
        ("task.sql.3", 1): 0,
    }
    for support in spec.task_slot_support:
        slots = (
            (support.reference_slot,)
            if spec.analysis_kind is DiscoveryAnalysisKindV2.FIXED_REFERENCE
            else support.request_randomness_slots
        )
        for slot in slots:
            coordinates = {
                "regime_id": "natural_prompt_discovery",
                "semantic_task_cluster_id": support.semantic_task_cluster_id,
                "task_instance_id": support.task_instance_id,
                "model_id": spec.model_id,
                "request_randomness_slot": slot,
                "provider_seed": support.seed_for_slot(slot),
            }
            chain = RuntimeProducerChainRecordV2.from_content(
                **coordinates,
                generation_request_id=_content_id(
                    "generation_request_v2", f"request-{support.task_instance_id}-{slot}"
                ),
                generated_code_id=_content_id(
                    "generated_code_v2", f"code-{support.task_instance_id}-{slot}"
                ),
                oracle_result_id=_content_id(
                    "oracle_result_v2", f"oracle-{support.task_instance_id}-{slot}"
                ),
                functional_result_id=_content_id(
                    "functional_result_v2", f"functional-{support.task_instance_id}-{slot}"
                ),
            )
            x_state = x_by_task[support.task_instance_id]
            if support.task_instance_id == x_drift_task and slot == 1:
                x_state = 1 - x_state
            observation = NaturalCausalObservationRecordV2.from_content(
                **coordinates,
                producer_chain_id=chain.producer_chain_id,
                table_id=spec.table_spec_id,
                prompt_id=support.natural_prompt_id,
                natural_x0=(NaturalX0ValueV2(variable_id="x.sql_parameterization", state=x_state),),
                outcomes=(
                    NaturalOutcomeValueV2(
                        variable_id="y.secure_yield",
                        state=y_by_task_slot[(support.task_instance_id, slot)],
                    ),
                ),
            )
            observations.append(observation)
            chains.append(chain)
    combined = sorted(
        zip(observations, chains, strict=True),
        key=lambda pair: (
            pair[0].semantic_task_cluster_id,
            pair[0].task_instance_id,
            pair[0].request_randomness_slot,
        ),
    )
    return tuple(item[0] for item in combined), tuple(item[1] for item in combined)


def test_fixed_reference_table_has_one_pre_frozen_slot_per_task() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.FIXED_REFERENCE)
    rows, chains = _rows_and_chains(spec)
    table = build_natural_discovery_table_v2(
        table_spec=spec,
        observations=rows,
        producer_chains=chains,
    )

    assert table.raw_observation_count == 4
    assert table.analysis_row_count == 4
    assert table.independent_semantic_cluster_count == 4
    assert {item.request_randomness_slot for item in table.observations} == {0}
    assert categorical_rows_v2(table) == ((0, 0), (1, 0), (0, 1), (1, 1))
    assert table.minimal_generating_set_passed is True


def test_table_rejects_deleted_task_even_if_remaining_rows_are_self_consistent() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.FIXED_REFERENCE)
    rows, chains = _rows_and_chains(spec)

    with pytest.raises(ValueError, match="natural discovery v2 contract failed validation"):
        build_natural_discovery_table_v2(
            table_spec=spec,
            observations=rows[:-1],
            producer_chains=chains[:-1],
        )


def test_two_level_table_requires_every_frozen_task_slot() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.TWO_LEVEL)
    rows, chains = _rows_and_chains(spec)
    table = build_natural_discovery_table_v2(
        table_spec=spec,
        observations=rows,
        producer_chains=chains,
    )

    assert table.raw_observation_count == 8
    assert table.analysis_row_count == 8
    with pytest.raises(ValueError, match="natural discovery v2 contract failed validation"):
        build_natural_discovery_table_v2(
            table_spec=spec,
            observations=rows[1:],
            producer_chains=chains[1:],
        )


def test_multi_slot_uses_state_preserving_mode_with_frozen_tie_rule() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.MULTI_SLOT_SENSITIVITY)
    rows, chains = _rows_and_chains(spec)
    table = build_natural_discovery_table_v2(
        table_spec=spec,
        observations=rows,
        producer_chains=chains,
    )

    assert table.raw_observation_count == 8
    assert table.analysis_row_count == 4
    assert categorical_rows_v2(table) == ((0, 0), (1, 0), (0, 1), (1, 0))
    assert all(type(value) is int for row in categorical_rows_v2(table) for value in row)


def test_multi_slot_rejects_natural_feature_drift_across_request_slots() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.MULTI_SLOT_SENSITIVITY)
    rows, chains = _rows_and_chains(spec, x_drift_task="task.sql.0")

    with pytest.raises(ValueError, match="natural discovery v2 contract failed validation"):
        build_natural_discovery_table_v2(
            table_spec=spec,
            observations=rows,
            producer_chains=chains,
        )


def test_context_conditioning_freezes_all_query_results_but_includes_only_present_tasks() -> None:
    spec = _table_spec(DiscoveryAnalysisKindV2.FIXED_REFERENCE, conditioned=True)
    rows, chains = _rows_and_chains(spec)
    table = build_natural_discovery_table_v2(
        table_spec=spec,
        observations=rows,
        producer_chains=chains,
    )

    assert {item.task_instance_id for item in table.observations} == {
        "task.sql.0",
        "task.sql.2",
    }
    assert len(spec.context_query_results) == 4
    assert {item.state for item in spec.context_query_results} == {
        QueryState.PRESENT,
        QueryState.ABSENT,
    }


def test_direct_feature_table_rejects_context_variable_mixing() -> None:
    payload = _table_spec(DiscoveryAnalysisKindV2.FIXED_REFERENCE).model_dump(mode="json")
    context = NaturalDiscoveryVariableSpecV2.from_content(
        variable_id="c.sql_flow",
        role=DiscoveryVariableRoleV2.C,
        states=("present", "absent", "not_applicable", "unresolved"),
        source_kind=DiscoveryVariableSourceV2.CONTEXT_QUERY,
        source_id="context_query_" + _sha("sql-context"),
        source_catalog_sha256=_sha("context-catalog"),
        query_semantics_version="context-query-v2.1",
        temporal_tier=1,
        adjacency_type="relational_context",
    )
    payload["variables"] = tuple(
        sorted(
            (*payload["variables"], context.model_dump(mode="json")),
            key=lambda item: item["variable_id"],
        )
    )
    payload["table_spec_id"] = "natural_table_spec_" + "a" * 64

    with pytest.raises(ValidationError, match="natural discovery v2 contract failed validation"):
        NaturalDiscoveryTableSpecV2.model_validate(payload)

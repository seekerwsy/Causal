from __future__ import annotations

from tests.observational_discovery_v2_fixture import (
    build_authenticated_synthetic_table_v2,
)

import secaware.causal.observational_discovery_v2 as observational
from secaware.causal.authenticated_natural_table_v2 import (
    build_two_level_cluster_resample_v2,
)
from secaware.causal.observational_discovery_v2 import (
    derive_policy_candidate_v2,
    run_observational_fci_suite_v2,
    run_true_chain_synthetic_gate_v2,
)
from secaware.schema.causal import EndpointMark, PAGEdgeRecord
from secaware.schema.discovery_v2 import DiscoveryAnalysisKindV2
from secaware.schema.observational_discovery_v2 import (
    BackgroundKnowledgeKindV2,
    DiscoveryFailureReasonV2,
    ObservationalDiscoveryConfigV2,
    ObservationalFCIFailureArtifactV2,
    ObservationalFCISuiteArtifactV2,
    ObservationalPAGArtifactV2,
    SyntheticTrueChainDiagnosticV2,
)


def test_authenticated_real_backend_smoke_is_replayable() -> None:
    table = build_authenticated_synthetic_table_v2(
        x_states=(0, 0, 1, 1),
        y_by_task_slot=((0,), (1,), (0,), (1,)),
        analysis_kind=DiscoveryAnalysisKindV2.FIXED_REFERENCE,
    )
    result = run_observational_fci_suite_v2(
        source=table,
        config=ObservationalDiscoveryConfigV2(min_independent_clusters=4),
    )

    assert isinstance(result, ObservationalFCISuiteArtifactV2)
    assert ObservationalFCISuiteArtifactV2.model_validate_json(
        result.model_dump_json()
    ) == result


def test_true_chain_real_backend_gate_is_explicitly_non_promoting() -> None:
    diagnostic = run_true_chain_synthetic_gate_v2(
        config=ObservationalDiscoveryConfigV2(
            alpha=0.20,
            min_independent_clusters=4,
        )
    )

    assert diagnostic.recovered_possible_path == (
        "x.synthetic_source",
        "x.synthetic_bridge",
        "y.secure_yield",
    )
    assert diagnostic.phase0_gate_only is True
    assert diagnostic.uses_authenticated_natural_table is False
    assert diagnostic.upgrades_main_evidence is False
    assert SyntheticTrueChainDiagnosticV2.model_validate_json(
        diagnostic.model_dump_json()
    ) == diagnostic


def test_latent_confounding_preserves_raw_pag_uncertainty_and_complete_bk_audit() -> None:
    table = build_authenticated_synthetic_table_v2(
        x_states=(1, 1, 1, 1, 0, 0),
        y_by_task_slot=((0,), (1,), (1,), (1,), (0,), (0,)),
        analysis_kind=DiscoveryAnalysisKindV2.FIXED_REFERENCE,
    )
    result = run_observational_fci_suite_v2(
        source=table,
        config=ObservationalDiscoveryConfigV2(
            alpha=0.10,
            min_independent_clusters=6,
        ),
    )

    assert isinstance(result, ObservationalFCISuiteArtifactV2)
    assert result.source_binding.authenticated_table_id == table.authenticated_table_id
    assert result.source_binding.source_draw_id is None
    assert result.raw_pag.knowledge.kind is BackgroundKnowledgeKindV2.RAW
    assert result.minimal_bk_pag.knowledge.kind is BackgroundKnowledgeKindV2.MINIMAL
    assert result.full_bk_pag.knowledge.kind is BackgroundKnowledgeKindV2.FULL
    assert (
        result.wrong_plausible_bk_pag.knowledge.kind
        is BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE
    )
    assert result.wrong_plausible_bk_pag.knowledge.excluded_from_candidate_evidence
    assert len(result.raw_pag.edges) == 1
    assert result.raw_pag.edges[0].left_mark is EndpointMark.CIRCLE
    assert result.raw_pag.edges[0].right_mark is EndpointMark.CIRCLE
    assert result.candidate.selected
    assert len(result.deletion_deltas) == len(result.full_bk_pag.knowledge.constraints)
    assert {
        item.removed_constraint for item in result.deletion_deltas
    } == set(result.full_bk_pag.knowledge.constraints)


def test_null_factor_is_not_selected_by_raw_or_full_pag() -> None:
    table = build_authenticated_synthetic_table_v2(
        x_states=(0, 1, 1, 1),
        y_by_task_slot=((0,), (0,), (1,), (1,)),
        analysis_kind=DiscoveryAnalysisKindV2.FIXED_REFERENCE,
    )
    result = run_observational_fci_suite_v2(
        source=table,
        config=ObservationalDiscoveryConfigV2(
            min_independent_clusters=4,
            min_expected_pairwise_cell_count=0.5,
        ),
    )

    assert isinstance(result, ObservationalFCISuiteArtifactV2)
    assert result.raw_pag.edges == ()
    assert result.candidate.raw_adjacent is False
    assert result.candidate.full_adjacent is False
    assert result.candidate.bk_created_adjacency is False
    assert result.candidate.selected is False

    bk_only_pag = ObservationalPAGArtifactV2.from_content(
        source_table_id=result.full_bk_pag.source_table_id,
        source_draw_id=None,
        run_label="attack.bk_only_edge",
        row_count=result.full_bk_pag.row_count,
        row_payload_sha256=result.full_bk_pag.row_payload_sha256,
        config=result.full_bk_pag.config,
        knowledge=result.full_bk_pag.knowledge,
        variable_ids=result.full_bk_pag.variable_ids,
        edges=(
            PAGEdgeRecord(
                left="x.sql_parameterization",
                right="y.secure_yield",
                left_mark=EndpointMark.CIRCLE,
                right_mark=EndpointMark.ARROW,
            ),
        ),
        backend_stdout="synthetic attack fixture",
        backend_stderr="",
        backend_warnings=(),
    )
    candidate = derive_policy_candidate_v2(
        raw_pag=result.raw_pag,
        full_pag=bk_only_pag,
        x_variable_id="x.sql_parameterization",
        y_variable_id="y.secure_yield",
    )
    assert candidate.full_adjacent
    assert candidate.bk_created_adjacency
    assert candidate.selected is False


def test_sparse_support_and_backend_faults_are_typed_and_replayable(monkeypatch) -> None:
    table = build_authenticated_synthetic_table_v2(
        x_states=(0, 0, 1, 1),
        y_by_task_slot=((0,), (1,), (0,), (1,)),
        analysis_kind=DiscoveryAnalysisKindV2.FIXED_REFERENCE,
    )

    cases = (
        (
            ObservationalDiscoveryConfigV2(min_independent_clusters=5),
            DiscoveryFailureReasonV2.INSUFFICIENT_INDEPENDENT_CLUSTERS,
        ),
        (
            ObservationalDiscoveryConfigV2(
                min_independent_clusters=4,
                min_expected_pairwise_cell_count=1.1,
            ),
            DiscoveryFailureReasonV2.SPARSE_CONTINGENCY,
        ),
    )
    for config, expected_reason in cases:
        failure = run_observational_fci_suite_v2(source=table, config=config)
        assert isinstance(failure, ObservationalFCIFailureArtifactV2)
        assert failure.failure.reason is expected_reason
        assert ObservationalFCIFailureArtifactV2.model_validate_json(
            failure.model_dump_json()
        ) == failure

    monkeypatch.setattr(observational.importlib.metadata, "version", lambda _name: "0.0")
    mismatch = run_observational_fci_suite_v2(
        source=table,
        config=ObservationalDiscoveryConfigV2(min_independent_clusters=4),
    )
    assert isinstance(mismatch, ObservationalFCIFailureArtifactV2)
    assert mismatch.failure.reason is DiscoveryFailureReasonV2.BACKEND_VERSION_MISMATCH

    monkeypatch.setattr(
        observational.importlib.metadata,
        "version",
        lambda _name: "0.1.4.7",
    )

    def fail_backend(*_args, **_kwargs):
        raise RuntimeError("synthetic backend fault")

    monkeypatch.setattr(observational, "fci", fail_backend)
    backend_failure = run_observational_fci_suite_v2(
        source=table,
        config=ObservationalDiscoveryConfigV2(min_independent_clusters=4),
    )
    assert isinstance(backend_failure, ObservationalFCIFailureArtifactV2)
    assert backend_failure.failure.reason is DiscoveryFailureReasonV2.BACKEND_FAILURE


def test_two_level_constant_and_deterministic_draws_fail_with_distinct_types() -> None:
    constant_table = build_authenticated_synthetic_table_v2(
        x_states=(0, 0, 0, 0),
        y_by_task_slot=((0, 1),) * 4,
        analysis_kind=DiscoveryAnalysisKindV2.TWO_LEVEL,
    )
    no_draw = run_observational_fci_suite_v2(
        source=constant_table,
        config=ObservationalDiscoveryConfigV2(min_independent_clusters=4),
    )
    assert isinstance(no_draw, ObservationalFCIFailureArtifactV2)
    assert no_draw.failure.reason is DiscoveryFailureReasonV2.TWO_LEVEL_DRAW_REQUIRED

    constant_draw = build_two_level_cluster_resample_v2(
        authenticated_table=constant_table,
        resample_seed=2,
        resample_domain="phase0.two_level.typed_failures",
    )
    constant_failure = run_observational_fci_suite_v2(
        source=constant_draw,
        config=ObservationalDiscoveryConfigV2(
            min_independent_clusters=4,
            min_expected_pairwise_cell_count=0.5,
        ),
    )
    assert isinstance(constant_failure, ObservationalFCIFailureArtifactV2)
    assert constant_failure.failure.reason is DiscoveryFailureReasonV2.CONSTANT_VARIABLE
    assert constant_failure.source_binding.source_draw_id == constant_draw.draw_manifest_id

    deterministic_table = build_authenticated_synthetic_table_v2(
        x_states=(0, 0, 1, 1),
        y_by_task_slot=((0, 0), (0, 0), (1, 1), (1, 1)),
        analysis_kind=DiscoveryAnalysisKindV2.TWO_LEVEL,
    )
    deterministic_draw = build_two_level_cluster_resample_v2(
        authenticated_table=deterministic_table,
        resample_seed=2,
        resample_domain="phase0.two_level.typed_failures",
    )
    deterministic_failure = run_observational_fci_suite_v2(
        source=deterministic_draw,
        config=ObservationalDiscoveryConfigV2(
            min_independent_clusters=4,
            min_expected_pairwise_cell_count=0.5,
        ),
    )
    assert isinstance(deterministic_failure, ObservationalFCIFailureArtifactV2)
    assert (
        deterministic_failure.failure.reason
        is DiscoveryFailureReasonV2.DETERMINISTIC_RELATION
    )

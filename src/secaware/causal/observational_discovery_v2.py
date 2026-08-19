"""Authenticated protocol-v2 observational FCI and BK sensitivity analysis.

The main path consumes only the receipt-authenticated natural table contracts.
For a two-level table it additionally requires a complete frozen draw manifest;
the raw multi-slot matrix is never passed to a CI test.
"""

from __future__ import annotations

import importlib.metadata
import warnings
from collections import defaultdict
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import numpy as np
from causallearn.graph.Endpoint import Endpoint
from causallearn.graph.GraphNode import GraphNode
from causallearn.search.ConstraintBased.FCI import fci
from causallearn.utils.PCUtils.BackgroundKnowledge import BackgroundKnowledge

from secaware.causal.authenticated_natural_table_v2 import (
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    TwoLevelClusterResampleManifestV2,
    authenticated_categorical_rows_for_fci_v2,
    build_two_level_cluster_resample_v2,
    two_level_categorical_rows_for_fci_v2,
)
from secaware.schema.causal import EndpointMark, PAGEdgeRecord
from secaware.schema.discovery_v2 import (
    DiscoveryAnalysisKindV2,
    DiscoveryTableKindV2,
    DiscoveryVariableRoleV2,
    DiscoveryVariableSourceV2,
    NaturalDiscoveryVariableSpecV2,
)
from secaware.schema.observational_discovery_v2 import (
    BackgroundKnowledgeArtifactV2,
    BackgroundKnowledgeKindV2,
    BKConstraintKindV2,
    BKConstraintV2,
    BKDeletionDeltaArtifactV2,
    BootstrapReplicateArtifactV2,
    DeterministicRelationV2,
    DiscoveryFailureReasonV2,
    JCIAppendixDiagnosticArtifactV2,
    ObservationalBootstrapArtifactV2,
    ObservationalDiscoveryConfigV2,
    ObservationalDiscoveryResultV2,
    ObservationalFCIFailureArtifactV2,
    ObservationalFCISuiteArtifactV2,
    ObservationalPAGArtifactV2,
    PAGEdgeDeltaV2,
    PolicyRelevantCandidateV2,
    TypedDiscoveryFailureV2,
    canonical_digest_v2,
)

_PINNED_CAUSAL_LEARN_VERSION = "0.1.4.7"
_TYPED_ADJACENCY_POLICY = {
    "policy": "reviewed_typed_adjacency_exclusions_v2",
    "forbidden_role_type_pairs": ((("w", "task_metadata"), ("x", "prompt_feature")),),
    "explicitly_allowed_tested_pair": (("x", "prompt_feature"), ("y", "committed_outcome")),
    "required_edges": (),
}
_TYPED_ADJACENCY_POLICY_SHA256 = canonical_digest_v2(_TYPED_ADJACENCY_POLICY)
_FORBIDDEN_ROLE_TYPE_PAIRS = frozenset(
    frozenset(pair) for pair in _TYPED_ADJACENCY_POLICY["forbidden_role_type_pairs"]
)

type _SourceEvidence = (
    AuthenticatedNaturalDiscoveryTableArtifactV2 | TwoLevelClusterResampleManifestV2
)


class _TypedRunFailure(Exception):
    def __init__(self, reason: DiscoveryFailureReasonV2, stage: str, detail_code: str) -> None:
        super().__init__(reason.value)
        self.failure = TypedDiscoveryFailureV2(
            reason=reason,
            stage=stage,
            detail_code=detail_code,
        )


def _fail(reason: DiscoveryFailureReasonV2, stage: str, detail_code: str) -> None:
    raise _TypedRunFailure(reason, stage, detail_code)


def _checked_source(
    source: _SourceEvidence,
) -> tuple[
    AuthenticatedNaturalDiscoveryTableArtifactV2,
    TwoLevelClusterResampleManifestV2 | None,
]:
    if type(source) is AuthenticatedNaturalDiscoveryTableArtifactV2:
        return AuthenticatedNaturalDiscoveryTableArtifactV2.model_validate(
            source, strict=True
        ), None
    if type(source) is TwoLevelClusterResampleManifestV2:
        draw = TwoLevelClusterResampleManifestV2.model_validate(source, strict=True)
        return draw.authenticated_table, draw
    raise ValueError("observational discovery requires authenticated v2 source evidence")


def _design_variables(
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
) -> tuple[NaturalDiscoveryVariableSpecV2, NaturalDiscoveryVariableSpecV2]:
    spec = table.authenticated_scope.table_spec
    variables = spec.variables
    xs = tuple(item for item in variables if item.role is DiscoveryVariableRoleV2.X)
    ys = tuple(item for item in variables if item.role is DiscoveryVariableRoleV2.Y)
    if (
        spec.table_kind is not DiscoveryTableKindV2.DIRECT_FEATURE
        or len(variables) != 2
        or len(xs) != 1
        or len(ys) != 1
        or xs[0].source_kind is not DiscoveryVariableSourceV2.ACTIONABLE_QUERY
        or ys[0].source_kind is not DiscoveryVariableSourceV2.OUTCOME_PROJECTION
        or ".motif." in xs[0].variable_id
        or "without_guard" in xs[0].variable_id
        or ys[0].variable_id == "y.secure_functional"
        or xs[0].temporal_tier >= ys[0].temporal_tier
        or any(item.role is DiscoveryVariableRoleV2.C for item in variables)
        or (
            spec.context_conditioning_query_id is not None
            and any(item.source_id == spec.context_conditioning_query_id for item in variables)
        )
    ):
        _fail(
            DiscoveryFailureReasonV2.UNSUPPORTED_SCOPE,
            "design",
            "direct_x0_context_separation_required",
        )
    return xs[0], ys[0]


def _rows_from_source(
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    draw: TwoLevelClusterResampleManifestV2 | None,
) -> tuple[tuple[int, ...], ...]:
    analysis_kind = table.authenticated_scope.table_spec.analysis_kind
    if analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL:
        if draw is None:
            _fail(
                DiscoveryFailureReasonV2.TWO_LEVEL_DRAW_REQUIRED,
                "source",
                "raw_two_level_matrix_forbidden",
            )
        try:
            return two_level_categorical_rows_for_fci_v2(draw)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - classify the authenticated draw gate
            reason = (
                DiscoveryFailureReasonV2.CONSTANT_VARIABLE
                if any(item.constant for item in draw.variable_support)
                else DiscoveryFailureReasonV2.DETERMINISTIC_RELATION
            )
            _fail(reason, "support", "two_level_manifest_failed_support_gate")
    if draw is not None:
        _fail(
            DiscoveryFailureReasonV2.UNSUPPORTED_SCOPE,
            "source",
            "draw_supplied_for_non_two_level_table",
        )
    try:
        return authenticated_categorical_rows_for_fci_v2(table)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - classify the authenticated direct-CI gate
        _fail(
            DiscoveryFailureReasonV2.DETERMINISTIC_RELATION,
            "support",
            "authenticated_table_failed_direct_ci_gate",
        )


def _deterministic_relations(
    rows: tuple[tuple[int, ...], ...],
    variable_ids: tuple[str, ...],
) -> tuple[DeterministicRelationV2, ...]:
    relations: list[DeterministicRelationV2] = []
    for left_index, left_id in enumerate(variable_ids):
        for right_index in range(left_index + 1, len(variable_ids)):
            right_id = variable_ids[right_index]
            left_to_right: dict[int, set[int]] = defaultdict(set)
            right_to_left: dict[int, set[int]] = defaultdict(set)
            for row in rows:
                left_to_right[row[left_index]].add(row[right_index])
                right_to_left[row[right_index]].add(row[left_index])
            left_determines = all(len(values) == 1 for values in left_to_right.values())
            right_determines = all(len(values) == 1 for values in right_to_left.values())
            if left_determines or right_determines:
                relations.append(
                    DeterministicRelationV2(
                        left_variable_id=left_id,
                        right_variable_id=right_id,
                        left_determines_right=left_determines,
                        right_determines_left=right_determines,
                    )
                )
    return tuple(relations)


def _preflight(
    *,
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    rows: tuple[tuple[int, ...], ...],
    config: ObservationalDiscoveryConfigV2,
) -> None:
    variables = table.authenticated_scope.table_spec.variables
    if table.raw_audit_table.independent_semantic_cluster_count < config.min_independent_clusters:
        _fail(
            DiscoveryFailureReasonV2.INSUFFICIENT_INDEPENDENT_CLUSTERS,
            "support",
            "cluster_count_below_registered_minimum",
        )
    if len(rows) < config.min_independent_clusters:
        _fail(
            DiscoveryFailureReasonV2.INSUFFICIENT_ROWS,
            "support",
            "analysis_rows_below_registered_minimum",
        )
    if len(rows) > config.max_rows or len(variables) > config.max_variables:
        _fail(
            DiscoveryFailureReasonV2.UNSUPPORTED_SCOPE,
            "support",
            "registered_size_limit_exceeded",
        )
    if any(len(row) != len(variables) for row in rows):
        _fail(
            DiscoveryFailureReasonV2.GSQUARE_DEGENERATE,
            "support",
            "matrix_width_mismatch",
        )
    for index, variable in enumerate(variables):
        observed = {row[index] for row in rows}
        if len(observed) < 2:
            _fail(
                DiscoveryFailureReasonV2.CONSTANT_VARIABLE,
                "support",
                "observed_variable_is_constant",
            )
        if any(value < 0 or value >= len(variable.states) for value in observed):
            _fail(
                DiscoveryFailureReasonV2.GSQUARE_DEGENERATE,
                "support",
                "categorical_state_out_of_range",
            )
    variable_ids = tuple(item.variable_id for item in variables)
    if _deterministic_relations(rows, variable_ids):
        _fail(
            DiscoveryFailureReasonV2.DETERMINISTIC_RELATION,
            "support",
            "exact_pairwise_functional_relation",
        )
    # With observed-only margins, every expected count must be finite and positive.
    # This catches zero-degree and malformed G-square tables before the backend.
    for left_index in range(len(variables)):
        for right_index in range(left_index + 1, len(variables)):
            left_states = tuple(sorted({row[left_index] for row in rows}))
            right_states = tuple(sorted({row[right_index] for row in rows}))
            if len(left_states) < 2 or len(right_states) < 2:
                _fail(
                    DiscoveryFailureReasonV2.GSQUARE_DEGENERATE,
                    "support",
                    "gsquare_zero_degrees_of_freedom",
                )
            left_counts = {
                state: sum(row[left_index] == state for row in rows) for state in left_states
            }
            right_counts = {
                state: sum(row[right_index] == state for row in rows) for state in right_states
            }
            expected = tuple(
                left_counts[left] * right_counts[right] / len(rows)
                for left in left_states
                for right in right_states
            )
            if any(not np.isfinite(value) or value <= 0.0 for value in expected):
                _fail(
                    DiscoveryFailureReasonV2.GSQUARE_DEGENERATE,
                    "support",
                    "gsquare_nonpositive_expected_count",
                )


def _constraint_sort_key(item: BKConstraintV2) -> tuple[str, str, str, str]:
    return item.sort_key()


def _knowledge(
    *,
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    kind: BackgroundKnowledgeKindV2,
    constraints: tuple[BKConstraintV2, ...],
) -> BackgroundKnowledgeArtifactV2:
    variables = table.authenticated_scope.table_spec.variables
    return BackgroundKnowledgeArtifactV2.from_content(
        kind=kind,
        source_table_id=table.authenticated_table_id,
        variable_ids=tuple(item.variable_id for item in variables),
        temporal_tiers=tuple((item.variable_id, item.temporal_tier) for item in variables),
        constraints=tuple(sorted(constraints, key=_constraint_sort_key)),
        typed_adjacency_policy_sha256=_TYPED_ADJACENCY_POLICY_SHA256,
        excluded_from_candidate_evidence=kind
        in {
            BackgroundKnowledgeKindV2.SINGLE_DELETION,
            BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE,
        },
    )


def _knowledge_family(
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    x_variable_id: str,
    y_variable_id: str,
) -> tuple[
    BackgroundKnowledgeArtifactV2,
    BackgroundKnowledgeArtifactV2,
    BackgroundKnowledgeArtifactV2,
    tuple[tuple[BKConstraintV2, BackgroundKnowledgeArtifactV2], ...],
    BackgroundKnowledgeArtifactV2,
]:
    variables = table.authenticated_scope.table_spec.variables
    minimal_constraints = tuple(
        BKConstraintV2(
            kind=BKConstraintKindV2.FORBIDDEN_DIRECTION,
            left=later.variable_id,
            right=earlier.variable_id,
            rationale="temporal_tier",
        )
        for later in variables
        for earlier in variables
        if later.temporal_tier > earlier.temporal_tier
    )
    typed_constraints = tuple(
        BKConstraintV2(
            kind=BKConstraintKindV2.FORBIDDEN_ADJACENCY,
            left=min(left.variable_id, right.variable_id),
            right=max(left.variable_id, right.variable_id),
            rationale="typed_adjacency",
        )
        for left_index, left in enumerate(variables)
        for right in variables[left_index + 1 :]
        if frozenset(
            {
                (left.role.value, left.adjacency_type),
                (right.role.value, right.adjacency_type),
            }
        )
        in _FORBIDDEN_ROLE_TYPE_PAIRS
    )
    full_constraints = tuple(
        sorted({*minimal_constraints, *typed_constraints}, key=_constraint_sort_key)
    )
    raw = _knowledge(
        table=table,
        kind=BackgroundKnowledgeKindV2.RAW,
        constraints=(),
    )
    minimal = _knowledge(
        table=table,
        kind=BackgroundKnowledgeKindV2.MINIMAL,
        constraints=minimal_constraints,
    )
    full = _knowledge(
        table=table,
        kind=BackgroundKnowledgeKindV2.FULL,
        constraints=full_constraints,
    )
    ablations = tuple(
        (
            removed,
            _knowledge(
                table=table,
                kind=BackgroundKnowledgeKindV2.SINGLE_DELETION,
                constraints=tuple(item for item in full_constraints if item != removed),
            ),
        )
        for removed in full_constraints
    )
    reverse_temporal = BKConstraintV2(
        kind=BKConstraintKindV2.FORBIDDEN_DIRECTION,
        left=x_variable_id,
        right=y_variable_id,
        rationale="wrong_plausible_tier_swap",
    )
    wrong_constraints = tuple(
        sorted(
            {
                *(
                    item
                    for item in full_constraints
                    if not (
                        item.kind is BKConstraintKindV2.FORBIDDEN_DIRECTION
                        and item.left == y_variable_id
                        and item.right == x_variable_id
                    )
                ),
                reverse_temporal,
            },
            key=_constraint_sort_key,
        )
    )
    wrong = _knowledge(
        table=table,
        kind=BackgroundKnowledgeKindV2.WRONG_PLAUSIBLE,
        constraints=wrong_constraints,
    )
    return raw, minimal, full, ablations, wrong


def _causal_learn_background(
    knowledge: BackgroundKnowledgeArtifactV2,
) -> BackgroundKnowledge | None:
    if knowledge.kind is BackgroundKnowledgeKindV2.RAW:
        return None
    nodes = {variable_id: GraphNode(variable_id) for variable_id in knowledge.variable_ids}
    backend = BackgroundKnowledge()
    for item in knowledge.constraints:
        if item.kind is BKConstraintKindV2.FORBIDDEN_DIRECTION:
            backend.add_forbidden_by_node(nodes[item.left], nodes[item.right])
        else:
            backend.add_forbidden_by_node(nodes[item.left], nodes[item.right])
            backend.add_forbidden_by_node(nodes[item.right], nodes[item.left])
    return backend


def _endpoint_mark(endpoint: object) -> EndpointMark:
    mapping = {
        Endpoint.TAIL: EndpointMark.TAIL,
        Endpoint.ARROW: EndpointMark.ARROW,
        Endpoint.CIRCLE: EndpointMark.CIRCLE,
    }
    try:
        return mapping[endpoint]  # type: ignore[index]
    except (KeyError, TypeError):
        _fail(
            DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
            "backend",
            "unknown_pag_endpoint",
        )


def _edge_signature(edge: object) -> tuple[str, str, object, object]:
    return (
        edge.get_node1().get_name(),  # type: ignore[attr-defined]
        edge.get_node2().get_name(),  # type: ignore[attr-defined]
        edge.get_endpoint1(),  # type: ignore[attr-defined]
        edge.get_endpoint2(),  # type: ignore[attr-defined]
    )


def _convert_edges(
    graph: object,
    library_edges: object,
    variable_ids: tuple[str, ...],
) -> tuple[PAGEdgeRecord, ...]:
    graph_nodes = tuple(node.get_name() for node in graph.get_nodes())  # type: ignore[attr-defined]
    graph_edges = graph.get_graph_edges()  # type: ignore[attr-defined]
    if (
        type(graph_edges) not in {list, tuple}
        or type(library_edges) not in {list, tuple}
        or set(graph_nodes) != set(variable_ids)
        or len(graph_nodes) != len(set(graph_nodes))
        or sorted(map(_edge_signature, graph_edges), key=str)
        != sorted(map(_edge_signature, library_edges), key=str)
    ):
        _fail(
            DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
            "backend",
            "graph_and_library_edge_mismatch",
        )
    converted: list[PAGEdgeRecord] = []
    for item in graph_edges:
        left = item.get_node1().get_name()
        right = item.get_node2().get_name()
        left_mark = _endpoint_mark(item.get_endpoint1())
        right_mark = _endpoint_mark(item.get_endpoint2())
        if right < left:
            left, right = right, left
            left_mark, right_mark = right_mark, left_mark
        converted.append(
            PAGEdgeRecord(
                left=left,
                right=right,
                left_mark=left_mark,
                right_mark=right_mark,
            )
        )
    result = tuple(sorted(converted, key=lambda edge: (edge.left, edge.right)))
    if len(result) != len({(item.left, item.right) for item in result}):
        _fail(
            DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
            "backend",
            "duplicate_pag_edge",
        )
    return result


def _edge_permits_direction(edge: PAGEdgeRecord, source: str, target: str) -> bool:
    source_mark, target_mark = edge.marks_from(source, target)
    return source_mark in {EndpointMark.TAIL, EndpointMark.CIRCLE} and target_mark in {
        EndpointMark.ARROW,
        EndpointMark.CIRCLE,
    }


def _validate_edges_against_knowledge(
    edges: tuple[PAGEdgeRecord, ...],
    knowledge: BackgroundKnowledgeArtifactV2,
) -> None:
    by_pair = {(item.left, item.right): item for item in edges}
    for constraint in knowledge.constraints:
        pair = tuple(sorted((constraint.left, constraint.right)))
        edge = by_pair.get(pair)
        if constraint.kind is BKConstraintKindV2.FORBIDDEN_ADJACENCY:
            if edge is not None:
                _fail(
                    DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
                    "background",
                    "forbidden_adjacency_present",
                )
        elif edge is not None and _edge_permits_direction(edge, constraint.left, constraint.right):
            _fail(
                DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
                "background",
                "forbidden_direction_permitted",
            )


def _run_pag(
    *,
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    draw: TwoLevelClusterResampleManifestV2 | None,
    rows: tuple[tuple[int, ...], ...],
    config: ObservationalDiscoveryConfigV2,
    knowledge: BackgroundKnowledgeArtifactV2,
    run_label: str,
) -> ObservationalPAGArtifactV2:
    try:
        version = importlib.metadata.version("causal-learn")
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - absence/mismatch share one typed backend failure
        version = None
    if version != _PINNED_CAUSAL_LEARN_VERSION:
        _fail(
            DiscoveryFailureReasonV2.BACKEND_VERSION_MISMATCH,
            "backend",
            "pinned_causal_learn_unavailable",
        )
    variable_ids = tuple(
        item.variable_id for item in table.authenticated_scope.table_spec.variables
    )
    matrix = np.asarray(rows, dtype=np.int64, order="C")
    matrix.flags.writeable = False
    stdout = StringIO()
    stderr = StringIO()
    try:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            with redirect_stdout(stdout), redirect_stderr(stderr):
                graph, library_edges = fci(
                    matrix,
                    independence_test_method="gsq",
                    alpha=config.alpha,
                    depth=config.depth,
                    max_path_length=config.max_path_length,
                    verbose=False,
                    background_knowledge=_causal_learn_background(knowledge),
                    show_progress=False,
                    node_names=list(variable_ids),
                )
        warning_text = tuple(str(item.message) for item in captured)
        if warning_text:
            _fail(
                DiscoveryFailureReasonV2.GSQUARE_DEGENERATE,
                "backend",
                "causal_learn_emitted_warning",
            )
        if stderr.getvalue():
            _fail(
                DiscoveryFailureReasonV2.BACKEND_FAILURE,
                "backend",
                "causal_learn_emitted_stderr",
            )
        edges = _convert_edges(graph, library_edges, variable_ids)
        _validate_edges_against_knowledge(edges, knowledge)
        return ObservationalPAGArtifactV2.from_content(
            source_table_id=table.authenticated_table_id,
            source_draw_id=draw.draw_manifest_id if draw is not None else None,
            run_label=run_label,
            row_count=len(rows),
            row_payload_sha256=canonical_digest_v2(
                {
                    "source": (
                        draw.draw_manifest_id if draw is not None else table.authenticated_table_id
                    ),
                    "rows": rows,
                }
            ),
            config=config,
            knowledge=knowledge,
            variable_ids=variable_ids,
            edges=edges,
            backend_stdout=stdout.getvalue(),
            backend_stderr="",
            backend_warnings=(),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except _TypedRunFailure:
        raise
    except Exception:  # noqa: BLE001 - sanitize the third-party backend boundary
        _fail(
            DiscoveryFailureReasonV2.BACKEND_FAILURE,
            "backend",
            "causal_learn_fci_call_failed",
        )
    finally:
        matrix = None  # type: ignore[assignment]


def _edge_for(
    pag: ObservationalPAGArtifactV2,
    left: str,
    right: str,
) -> PAGEdgeRecord | None:
    pair = tuple(sorted((left, right)))
    return next((item for item in pag.edges if (item.left, item.right) == pair), None)


def _candidate_flags(
    raw: ObservationalPAGArtifactV2,
    comparison: ObservationalPAGArtifactV2,
    x_variable_id: str,
    y_variable_id: str,
) -> tuple[bool, bool, bool, bool]:
    raw_edge = _edge_for(raw, x_variable_id, y_variable_id)
    comparison_edge = _edge_for(comparison, x_variable_id, y_variable_id)
    return (
        raw_edge is not None,
        raw_edge is not None and _edge_permits_direction(raw_edge, x_variable_id, y_variable_id),
        comparison_edge is not None,
        comparison_edge is not None
        and _edge_permits_direction(comparison_edge, x_variable_id, y_variable_id),
    )


def derive_policy_candidate_v2(
    *,
    raw_pag: ObservationalPAGArtifactV2,
    full_pag: ObservationalPAGArtifactV2,
    x_variable_id: str,
    y_variable_id: str,
) -> PolicyRelevantCandidateV2:
    """Select only a raw-supported X0-Y possibility; BK cannot create a candidate."""

    raw = ObservationalPAGArtifactV2.model_validate(raw_pag, strict=True)
    full = ObservationalPAGArtifactV2.model_validate(full_pag, strict=True)
    if (
        raw.source_table_id != full.source_table_id
        or raw.source_draw_id != full.source_draw_id
        or raw.config != full.config
        or raw.knowledge.kind is not BackgroundKnowledgeKindV2.RAW
        or full.knowledge.excluded_from_candidate_evidence
        or x_variable_id not in raw.variable_ids
        or y_variable_id not in raw.variable_ids
    ):
        raise ValueError("candidate derivation requires matched raw and eligible BK PAGs")
    raw_adjacent, raw_possible, full_adjacent, full_possible = _candidate_flags(
        raw,
        full,
        x_variable_id,
        y_variable_id,
    )
    return PolicyRelevantCandidateV2.from_content(
        x_variable_id=x_variable_id,
        y_variable_id=y_variable_id,
        raw_pag_id=raw.pag_id,
        full_pag_id=full.pag_id,
        raw_adjacent=raw_adjacent,
        raw_permits_x_to_y=raw_possible,
        full_adjacent=full_adjacent,
        full_permits_x_to_y=full_possible,
        bk_created_adjacency=full_adjacent and not raw_adjacent,
        selected=raw_possible and full_possible,
        selection_rule="raw_adjacency_and_raw_plus_full_possible_x_to_y_v1",
    )


def _edge_deltas(
    before: ObservationalPAGArtifactV2,
    after: ObservationalPAGArtifactV2,
) -> tuple[PAGEdgeDeltaV2, ...]:
    before_by_pair = {(item.left, item.right): item for item in before.edges}
    after_by_pair = {(item.left, item.right): item for item in after.edges}
    return tuple(
        PAGEdgeDeltaV2(
            left=pair[0],
            right=pair[1],
            before=before_by_pair.get(pair),
            after=after_by_pair.get(pair),
        )
        for pair in sorted(set(before_by_pair) | set(after_by_pair))
        if before_by_pair.get(pair) != after_by_pair.get(pair)
    )


def _failure_artifact(
    *,
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    draw: TwoLevelClusterResampleManifestV2 | None,
    config: ObservationalDiscoveryConfigV2,
    failure: TypedDiscoveryFailureV2,
    completed: tuple[ObservationalPAGArtifactV2, ...],
) -> ObservationalFCIFailureArtifactV2:
    return ObservationalFCIFailureArtifactV2.from_content(
        source_table=table,
        source_draw=draw,
        config=config,
        failure=failure,
        completed_pags=completed,
    )


def run_observational_fci_suite_v2(
    *,
    source: _SourceEvidence,
    config: ObservationalDiscoveryConfigV2,
) -> ObservationalDiscoveryResultV2:
    """Run raw/minimal/full/ablation/perturbed FCI from authenticated rows."""

    table, draw = _checked_source(source)
    checked_config = ObservationalDiscoveryConfigV2.model_validate(config, strict=True)
    completed: list[ObservationalPAGArtifactV2] = []
    try:
        x_variable, y_variable = _design_variables(table)
        rows = _rows_from_source(table, draw)
        _preflight(table=table, rows=rows, config=checked_config)
        raw_bk, minimal_bk, full_bk, ablations, wrong_bk = _knowledge_family(
            table,
            x_variable.variable_id,
            y_variable.variable_id,
        )
        if len(ablations) > checked_config.max_atomic_bk_ablations:
            _fail(
                DiscoveryFailureReasonV2.TOO_MANY_BK_ABLATIONS,
                "background",
                "atomic_ablation_budget_exceeded",
            )
        raw_pag = _run_pag(
            table=table,
            draw=draw,
            rows=rows,
            config=checked_config,
            knowledge=raw_bk,
            run_label="reference.raw",
        )
        completed.append(raw_pag)
        minimal_pag = _run_pag(
            table=table,
            draw=draw,
            rows=rows,
            config=checked_config,
            knowledge=minimal_bk,
            run_label="reference.minimal_bk",
        )
        completed.append(minimal_pag)
        full_pag = _run_pag(
            table=table,
            draw=draw,
            rows=rows,
            config=checked_config,
            knowledge=full_bk,
            run_label="reference.full_bk",
        )
        completed.append(full_pag)
        deletion_deltas: list[BKDeletionDeltaArtifactV2] = []
        for index, (removed, ablated_bk) in enumerate(ablations):
            ablation_pag = _run_pag(
                table=table,
                draw=draw,
                rows=rows,
                config=checked_config,
                knowledge=ablated_bk,
                run_label=f"reference.single_deletion.{index}",
            )
            completed.append(ablation_pag)
            _, raw_possible, _, ablation_possible = _candidate_flags(
                raw_pag,
                ablation_pag,
                x_variable.variable_id,
                y_variable.variable_id,
            )
            deletion_deltas.append(
                BKDeletionDeltaArtifactV2.from_content(
                    full_pag_id=full_pag.pag_id,
                    removed_constraint=removed,
                    ablation_pag=ablation_pag,
                    edge_deltas=_edge_deltas(full_pag, ablation_pag),
                    candidate_selected_after_deletion=raw_possible and ablation_possible,
                )
            )
        wrong_pag = _run_pag(
            table=table,
            draw=draw,
            rows=rows,
            config=checked_config,
            knowledge=wrong_bk,
            run_label="sensitivity.wrong_plausible_bk",
        )
        completed.append(wrong_pag)
        candidate = derive_policy_candidate_v2(
            raw_pag=raw_pag,
            full_pag=full_pag,
            x_variable_id=x_variable.variable_id,
            y_variable_id=y_variable.variable_id,
        )
        return ObservationalFCISuiteArtifactV2.from_content(
            source_table=table,
            source_draw=draw,
            config=checked_config,
            x_variable_id=x_variable.variable_id,
            y_variable_id=y_variable.variable_id,
            context_conditioning_query_id=(
                table.authenticated_scope.table_spec.context_conditioning_query_id
            ),
            raw_pag=raw_pag,
            minimal_bk_pag=minimal_pag,
            full_bk_pag=full_pag,
            deletion_deltas=tuple(deletion_deltas),
            wrong_plausible_bk_pag=wrong_pag,
            candidate=candidate,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except _TypedRunFailure as error:
        return _failure_artifact(
            table=table,
            draw=draw,
            config=checked_config,
            failure=error.failure,
            completed=tuple(completed),
        )
    except Exception:  # noqa: BLE001 - preserve partial PAGs and fail closed
        return _failure_artifact(
            table=table,
            draw=draw,
            config=checked_config,
            failure=TypedDiscoveryFailureV2(
                reason=DiscoveryFailureReasonV2.INVALID_BACKEND_PAG,
                stage="artifact",
                detail_code="suite_construction_failed",
            ),
            completed=tuple(completed),
        )


def run_two_level_cluster_bootstrap_v2(
    *,
    authenticated_table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    config: ObservationalDiscoveryConfigV2,
    resample_seeds: tuple[int, ...],
    resample_domain: str,
) -> ObservationalBootstrapArtifactV2 | ObservationalFCIFailureArtifactV2:
    """Run cluster bootstrap draws with one frozen request slot per occurrence."""

    table = AuthenticatedNaturalDiscoveryTableArtifactV2.model_validate(
        authenticated_table, strict=True
    )
    checked_config = ObservationalDiscoveryConfigV2.model_validate(config, strict=True)
    if (
        type(resample_seeds) is not tuple
        or not resample_seeds
        or resample_seeds != tuple(sorted(resample_seeds))
        or len(resample_seeds) != len(set(resample_seeds))
        or any(type(seed) is not int or not 0 <= seed <= 2**63 - 1 for seed in resample_seeds)
    ):
        raise ValueError("bootstrap seeds must be a sorted unique frozen tuple")
    completed: list[ObservationalPAGArtifactV2] = []
    try:
        if (
            table.authenticated_scope.table_spec.analysis_kind
            is not DiscoveryAnalysisKindV2.TWO_LEVEL
        ):
            _fail(
                DiscoveryFailureReasonV2.UNSUPPORTED_SCOPE,
                "bootstrap",
                "two_level_authenticated_table_required",
            )
        x_variable, y_variable = _design_variables(table)
        _raw_bk, _minimal_bk, full_bk, _ablations, _wrong_bk = _knowledge_family(
            table,
            x_variable.variable_id,
            y_variable.variable_id,
        )
        raw_bk = _knowledge(
            table=table,
            kind=BackgroundKnowledgeKindV2.RAW,
            constraints=(),
        )
        replicates: list[BootstrapReplicateArtifactV2] = []
        for replicate_index, seed in enumerate(resample_seeds):
            draw = build_two_level_cluster_resample_v2(
                authenticated_table=table,
                resample_seed=seed,
                resample_domain=resample_domain,
            )
            raw_pag: ObservationalPAGArtifactV2 | None = None
            try:
                rows = _rows_from_source(table, draw)
                _preflight(table=table, rows=rows, config=checked_config)
                raw_pag = _run_pag(
                    table=table,
                    draw=draw,
                    rows=rows,
                    config=checked_config,
                    knowledge=raw_bk,
                    run_label=f"bootstrap.{replicate_index}.raw",
                )
                full_pag = _run_pag(
                    table=table,
                    draw=draw,
                    rows=rows,
                    config=checked_config,
                    knowledge=full_bk,
                    run_label=f"bootstrap.{replicate_index}.full_bk",
                )
                candidate = derive_policy_candidate_v2(
                    raw_pag=raw_pag,
                    full_pag=full_pag,
                    x_variable_id=x_variable.variable_id,
                    y_variable_id=y_variable.variable_id,
                )
                replicates.append(
                    BootstrapReplicateArtifactV2.from_content(
                        replicate_index=replicate_index,
                        draw_manifest=draw,
                        raw_pag=raw_pag,
                        full_bk_pag=full_pag,
                        failure=None,
                        candidate_selected=candidate.selected,
                    )
                )
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except _TypedRunFailure as error:
                replicates.append(
                    BootstrapReplicateArtifactV2.from_content(
                        replicate_index=replicate_index,
                        draw_manifest=draw,
                        raw_pag=raw_pag,
                        full_bk_pag=None,
                        failure=error.failure,
                        candidate_selected=False,
                    )
                )
        failures = sum(item.failure is not None for item in replicates)
        stability_eligible = (
            failures / len(replicates) <= checked_config.max_failed_bootstrap_fraction
        )
        overall_failure = (
            None
            if stability_eligible
            else TypedDiscoveryFailureV2(
                reason=DiscoveryFailureReasonV2.TOO_MANY_FAILED_BOOTSTRAPS,
                stage="bootstrap",
                detail_code="failed_fraction_exceeded_registered_maximum",
            )
        )
        return ObservationalBootstrapArtifactV2.from_content(
            source_table=table,
            config=checked_config,
            resample_domain=resample_domain,
            resample_seeds=resample_seeds,
            replicates=tuple(replicates),
            candidate_support_numerator=sum(item.candidate_selected for item in replicates),
            candidate_support_denominator=len(replicates),
            failed_replicate_count=failures,
            stability_eligible=stability_eligible,
            overall_failure=overall_failure,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except _TypedRunFailure as error:
        return _failure_artifact(
            table=table,
            draw=None,
            config=checked_config,
            failure=error.failure,
            completed=tuple(completed),
        )


def build_jci_appendix_diagnostic_v2(
    *,
    variable_ids: tuple[str, ...],
    context_variable_id: str,
    rows: tuple[tuple[int, ...], ...],
) -> JCIAppendixDiagnosticArtifactV2:
    """Record deterministic JCI relations as appendix-only non-identification evidence."""

    if (
        type(variable_ids) is not tuple
        or type(rows) is not tuple
        or len(variable_ids) < 2
        or context_variable_id not in variable_ids
        or len(set(variable_ids)) != len(variable_ids)
        or any(len(row) != len(variable_ids) for row in rows)
    ):
        raise ValueError("JCI diagnostic input failed exact validation")
    order = tuple(sorted(range(len(variable_ids)), key=lambda index: variable_ids[index]))
    ordered_ids = tuple(variable_ids[index] for index in order)
    ordered_rows = tuple(tuple(row[index] for index in order) for row in rows)
    all_relations = _deterministic_relations(ordered_rows, ordered_ids)
    relations = tuple(
        item
        for item in all_relations
        if context_variable_id in {item.left_variable_id, item.right_variable_id}
    )
    return JCIAppendixDiagnosticArtifactV2.from_content(
        variable_ids=ordered_ids,
        context_variable_id=context_variable_id,
        rows=ordered_rows,
        row_payload_sha256=canonical_digest_v2(ordered_rows),
        deterministic_relations=relations,
        status=("deterministic_context_fail_closed" if relations else "diagnostic_only"),
        appendix_only=True,
        upgrades_main_evidence=False,
    )


type _WritableArtifactV2 = (
    ObservationalFCISuiteArtifactV2
    | ObservationalFCIFailureArtifactV2
    | ObservationalBootstrapArtifactV2
    | JCIAppendixDiagnosticArtifactV2
)


def write_observational_artifact_v2(
    *,
    artifact: _WritableArtifactV2,
    path: Path,
) -> Path:
    """Write one immutable JSON artifact; existing history is never overwritten."""

    allowed = (
        ObservationalFCISuiteArtifactV2,
        ObservationalFCIFailureArtifactV2,
        ObservationalBootstrapArtifactV2,
        JCIAppendixDiagnosticArtifactV2,
    )
    if type(artifact) not in allowed or type(path) is not Path or path.exists():
        raise ValueError("artifact path or type failed exact validation")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(artifact.model_dump_json(indent=2))
        handle.write("\n")
    return path


__all__ = [
    "build_jci_appendix_diagnostic_v2",
    "derive_policy_candidate_v2",
    "run_observational_fci_suite_v2",
    "run_two_level_cluster_bootstrap_v2",
    "write_observational_artifact_v2",
]

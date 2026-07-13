"""Fail-closed conversion of causal-learn PAG graphs to SecAware records."""

from __future__ import annotations

from causallearn.graph.Endpoint import Endpoint

from secaware.config import FCIDiscoveryConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
)


_ENDPOINT_MAP = (
    (Endpoint.TAIL, EndpointMark.TAIL),
    (Endpoint.ARROW, EndpointMark.ARROW),
    (Endpoint.CIRCLE, EndpointMark.CIRCLE),
)


def _pag_error() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.pag",
        message="causal-learn PAG failed validation",
    )


def _node_name(node: object) -> str:
    name = node.get_name()  # type: ignore[attr-defined]
    if type(name) is not str:
        raise ValueError
    return name


def _endpoint_mark(endpoint: object) -> EndpointMark:
    for backend_endpoint, mark in _ENDPOINT_MAP:
        if endpoint is backend_endpoint:
            return mark
    raise ValueError


def _pag_from_causal_learn(
    graph: object,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind,
) -> PAGRecord:
    checked_table = CausalTableRecord.model_validate(table)
    checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
    checked_config = FCIDiscoveryConfig.model_validate(config)
    checked_run_kind = PAGRunKind(run_kind)
    expected_variables = tuple(item.variable_id for item in checked_table.variables)
    knowledge_variables = tuple(
        sorted(
            {
                *(item for item, _tier in checked_knowledge.tiers),
                *checked_knowledge.unconstrained_variable_ids,
            }
        )
    )
    backend_nodes = tuple(_node_name(node) for node in graph.get_nodes())  # type: ignore[attr-defined]
    if (
        checked_knowledge.table_id != checked_table.table_id
        or knowledge_variables != expected_variables
        or len(backend_nodes) != len(set(backend_nodes))
        or set(backend_nodes) != set(expected_variables)
    ):
        raise ValueError

    converted: list[PAGEdgeRecord] = []
    seen: set[tuple[str, str]] = set()
    raw_edges = graph.get_graph_edges()  # type: ignore[attr-defined]
    if type(raw_edges) not in {list, tuple}:
        raise ValueError
    for backend_edge in raw_edges:
        backend_left = _node_name(backend_edge.get_node1())
        backend_right = _node_name(backend_edge.get_node2())
        if (
            backend_left not in expected_variables
            or backend_right not in expected_variables
            or backend_left == backend_right
        ):
            raise ValueError
        left_endpoint = _endpoint_mark(backend_edge.get_endpoint1())
        right_endpoint = _endpoint_mark(backend_edge.get_endpoint2())
        if backend_right < backend_left:
            left, right = backend_right, backend_left
            left_mark, right_mark = right_endpoint, left_endpoint
        else:
            left, right = backend_left, backend_right
            left_mark, right_mark = left_endpoint, right_endpoint
        pair = (left, right)
        if pair in seen:
            raise ValueError
        seen.add(pair)
        converted.append(
            PAGEdgeRecord(
                left=left,
                right=right,
                left_mark=left_mark,
                right_mark=right_mark,
            )
        )
    return PAGRecord.from_content(
        run_kind=checked_run_kind,
        table_id=checked_table.table_id,
        backend=checked_config.backend,
        backend_version=checked_config.backend_version,
        ci_test=checked_config.ci_test,
        config_sha256=canonical_sha256(checked_config.model_dump(mode="json")),
        background_knowledge_sha256=checked_knowledge.knowledge_sha256,
        variable_ids=expected_variables,
        edges=tuple(converted),
    )


def pag_from_causal_learn(
    graph: object,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind,
) -> PAGRecord:
    """Convert only exact causal-learn endpoints; never infer endpoint marks."""
    result: PAGRecord | None = None
    try:
        result = _pag_from_causal_learn(graph, table, knowledge, config, run_kind)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        pass
    finally:
        graph = None
        table = None  # type: ignore[assignment]
        knowledge = None  # type: ignore[assignment]
        config = None  # type: ignore[assignment]
    if result is None:
        raise _pag_error() from None
    return result


__all__ = ["pag_from_causal_learn"]

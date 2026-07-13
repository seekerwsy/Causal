from __future__ import annotations

from itertools import product

import pytest
from causallearn.graph.Endpoint import Endpoint

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGRunKind,
)


class _Node:
    def __init__(self, name: str) -> None:
        self._name = name

    def get_name(self) -> str:
        return self._name


class _Edge:
    def __init__(
        self,
        left: str,
        right: str,
        left_endpoint: Endpoint,
        right_endpoint: Endpoint,
        *,
        properties: list[object] | None = None,
    ) -> None:
        self._node1 = _Node(left)
        self._node2 = _Node(right)
        self._endpoint1 = left_endpoint
        self._endpoint2 = right_endpoint
        self.properties = [] if properties is None else properties

    def get_node1(self) -> _Node:
        return self._node1

    def get_node2(self) -> _Node:
        return self._node2

    def get_endpoint1(self) -> Endpoint:
        return self._endpoint1

    def get_endpoint2(self) -> Endpoint:
        return self._endpoint2


class _Graph:
    def __init__(self, nodes: list[str], edges: list[_Edge]) -> None:
        self._nodes = [_Node(item) for item in nodes]
        self._edges = edges

    def get_nodes(self) -> list[_Node]:
        return self._nodes

    def get_graph_edges(self) -> list[_Edge]:
        return self._edges


def _variable(variable_id: str) -> CausalVariableSpec:
    declaration = declaration_by_id(variable_id)
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id="scope.cwe_89",
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def _table() -> CausalTableRecord:
    variables = (
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    rows = []
    for index in range(4):
        values = (index % 2, (index // 2) % 2)
        task_id = f"task-{index}"
        prompt_id = f"prompt-{index}"
        rows.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id="model-a",
                    seed_id=index,
                    values=values,
                ),
                task_id,
                prompt_id,
                index,
                values,
            )
        )
    return CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=4,
        independent_task_count=4,
        observation_payload=rows,
    )


@pytest.mark.parametrize(
    ("backend_left", "backend_right", "expected_left", "expected_right"),
    tuple(
        (left, right, EndpointMark(left.name.lower()), EndpointMark(right.name.lower()))
        for left, right in product((Endpoint.TAIL, Endpoint.ARROW, Endpoint.CIRCLE), repeat=2)
    ),
)
def test_pag_codec_preserves_every_supported_endpoint_pair_without_inference(
    backend_left: Endpoint,
    backend_right: Endpoint,
    expected_left: EndpointMark,
    expected_right: EndpointMark,
) -> None:
    from secaware.causal.pag import pag_from_causal_learn

    table = _table()
    knowledge = build_background_knowledge(table)
    config = FCIDiscoveryConfig(min_independent_tasks=2)
    graph = _Graph(
        ["x.safety.sql_parameterization", "y.secure_functional"],
        [
            _Edge(
                "x.safety.sql_parameterization",
                "y.secure_functional",
                backend_left,
                backend_right,
            )
        ],
    )

    pag = pag_from_causal_learn(
        graph,
        table,
        knowledge,
        config,
        PAGRunKind.OBSERVATIONAL_REFERENCE,
    )

    assert pag.edges[0].left_mark is expected_left
    assert pag.edges[0].right_mark is expected_right
    assert pag.config_sha256 == canonical_sha256(config.model_dump(mode="json"))


def test_pag_codec_swaps_marks_when_backend_nodes_are_reverse_sorted() -> None:
    from secaware.causal.pag import pag_from_causal_learn

    table = _table()
    knowledge = build_background_knowledge(table)
    config = FCIDiscoveryConfig(min_independent_tasks=2)
    graph = _Graph(
        ["y.secure_functional", "x.safety.sql_parameterization"],
        [
            _Edge(
                "y.secure_functional",
                "x.safety.sql_parameterization",
                Endpoint.ARROW,
                Endpoint.TAIL,
            )
        ],
    )

    pag = pag_from_causal_learn(
        graph,
        table,
        knowledge,
        config,
        PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
    )

    assert pag.edges[0].left == "x.safety.sql_parameterization"
    assert pag.edges[0].right == "y.secure_functional"
    assert pag.edges[0].left_mark is EndpointMark.TAIL
    assert pag.edges[0].right_mark is EndpointMark.ARROW


@pytest.mark.parametrize(
    "endpoint",
    (Endpoint.NULL, Endpoint.STAR, Endpoint.TAIL_AND_ARROW, Endpoint.ARROW_AND_ARROW),
)
def test_pag_codec_rejects_unsupported_or_composite_endpoints(endpoint: Endpoint) -> None:
    from secaware.causal.pag import pag_from_causal_learn

    table = _table()
    with pytest.raises(SecAwareError):
        pag_from_causal_learn(
            _Graph(
                ["x.safety.sql_parameterization", "y.secure_functional"],
                [
                    _Edge(
                        "x.safety.sql_parameterization",
                        "y.secure_functional",
                        endpoint,
                        Endpoint.CIRCLE,
                    )
                ],
            ),
            table,
            build_background_knowledge(table),
            FCIDiscoveryConfig(min_independent_tasks=2),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )


@pytest.mark.parametrize(
    "graph",
    (
        _Graph(["x.safety.sql_parameterization"], []),
        _Graph(["x.safety.sql_parameterization", "y.secure_functional", "x.unknown"], []),
        _Graph(["x.safety.sql_parameterization", "x.safety.sql_parameterization"], []),
        _Graph(
            ["x.safety.sql_parameterization", "y.secure_functional"],
            [
                _Edge(
                    "x.safety.sql_parameterization",
                    "x.safety.sql_parameterization",
                    Endpoint.TAIL,
                    Endpoint.ARROW,
                )
            ],
        ),
        _Graph(
            ["x.safety.sql_parameterization", "y.secure_functional"],
            [
                _Edge(
                    "x.safety.sql_parameterization",
                    "y.secure_functional",
                    Endpoint.TAIL,
                    Endpoint.ARROW,
                ),
                _Edge(
                    "y.secure_functional",
                    "x.safety.sql_parameterization",
                    Endpoint.ARROW,
                    Endpoint.TAIL,
                ),
            ],
        ),
    ),
)
def test_pag_codec_rejects_missing_unknown_duplicate_self_or_duplicate_edges(
    graph: _Graph,
) -> None:
    from secaware.causal.pag import pag_from_causal_learn

    table = _table()
    with pytest.raises(SecAwareError):
        pag_from_causal_learn(
            graph,
            table,
            build_background_knowledge(table),
            FCIDiscoveryConfig(min_independent_tasks=2),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )

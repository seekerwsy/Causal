from __future__ import annotations

from copy import deepcopy
import sys
import warnings

from causallearn.graph.Edge import Edge
from causallearn.graph.Endpoint import Endpoint
from causallearn.graph.GraphNode import GraphNode
import numpy as np
import pytest

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.schema.causal import (
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    PAGRunKind,
)


class _Graph:
    def __init__(self, names: list[str], edges: list[Edge] | None = None) -> None:
        self._nodes = [GraphNode(item) for item in names]
        self._edges = [] if edges is None else edges

    def get_nodes(self) -> list[GraphNode]:
        return self._nodes

    def get_graph_edges(self) -> list[Edge]:
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
    observations = []
    for index in range(4):
        values = (index % 2, (index // 2) % 2)
        observations.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=f"task-{index}",
                    prompt_id=f"prompt-{index}",
                    model_id="model-a",
                    seed_id=index,
                    values=values,
                ),
                f"task-{index}",
                f"prompt-{index}",
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
        observation_payload=observations,
    )


def _matrix() -> np.ndarray:
    return np.asarray(((0, 0), (1, 0), (0, 1), (1, 1)), dtype=np.int64)


def _config() -> FCIDiscoveryConfig:
    return FCIDiscoveryConfig(
        alpha=0.01,
        depth=2,
        max_path_length=4,
        min_independent_tasks=2,
    )


def test_fci_adapter_calls_exact_gsq_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    calls: list[tuple[np.ndarray, dict[str, object]]] = []
    table = _table()

    def capture(dataset: np.ndarray, **kwargs: object) -> tuple[_Graph, list[Edge]]:
        calls.append((dataset, kwargs))
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", capture)
    pag = run_causal_learn_fci(
        _matrix(), table, build_background_knowledge(table), _config()
    )

    assert len(calls) == 1
    dataset, kwargs = calls[0]
    assert dataset.dtype == np.int64
    assert kwargs == {
        "independence_test_method": "gsq",
        "alpha": 0.01,
        "depth": 2,
        "max_path_length": 4,
        "verbose": False,
        "background_knowledge": kwargs["background_knowledge"],
        "show_progress": False,
        "node_names": [item.variable_id for item in table.variables],
    }
    assert pag.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE


def test_pinned_real_fci_backend_is_runnable_with_background_knowledge() -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()
    pag = run_causal_learn_fci(
        _matrix(), table, build_background_knowledge(table), _config()
    )

    assert pag.table_id == table.table_id
    assert pag.backend_version == "0.1.4.7"


def test_fci_adapter_rejects_library_version_drift_before_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    called = False

    def forbidden(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", forbidden)
    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.importlib.metadata.version",
        lambda _name: "0.1.4.8",
    )
    table = _table()
    with pytest.raises(SecAwareError, match="version mismatch"):
        run_causal_learn_fci(
            _matrix(), table, build_background_knowledge(table), _config()
        )
    assert called is False


@pytest.mark.parametrize(
    "matrix",
    (
        np.asarray((0, 1), dtype=np.int64),
        np.zeros((3, 2), dtype=np.int64),
        np.zeros((4, 3), dtype=np.int64),
        np.zeros((4, 2), dtype=np.float64),
        np.asarray(((0, 0), (1, 0), (0, 1), (2, 1)), dtype=np.int64),
    ),
)
def test_fci_adapter_rejects_invalid_matrix_before_backend(
    monkeypatch: pytest.MonkeyPatch,
    matrix: np.ndarray,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        lambda *_args, **_kwargs: pytest.fail("backend must not be called"),
    )
    table = _table()
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(matrix, table, build_background_knowledge(table), _config())


def test_fci_adapter_rejects_table_background_and_config_mismatch_before_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        lambda *_args, **_kwargs: pytest.fail("backend must not be called"),
    )
    table = _table()
    forged_table = deepcopy(table)
    object.__setattr__(forged_table, "row_count", 5)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(), forged_table, build_background_knowledge(table), _config()
        )
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(), table, build_background_knowledge(table),
            FCIDiscoveryConfig(max_variables=2, max_rows=3, min_independent_tasks=2),
        )


@pytest.mark.parametrize("emission", ("warning", "stdout", "stderr"))
def test_fci_adapter_rejects_unexpected_backend_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    emission: str,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()

    def noisy(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        if emission == "warning":
            warnings.warn("unexpected backend warning")
        elif emission == "stdout":
            print("unexpected backend stdout")
        else:
            print("unexpected backend stderr", file=sys.stderr)
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", noisy)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(), table, build_background_knowledge(table), _config()
        )


def test_fci_adapter_rejects_unrecognized_library_edge_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()
    left = GraphNode("x.safety.sql_parameterization")
    right = GraphNode("y.secure_functional")
    edge = Edge(left, right, Endpoint.TAIL, Endpoint.ARROW)
    edge.properties.append(object())
    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        lambda *_args, **_kwargs: (
            _Graph([item.variable_id for item in table.variables], [edge]),
            [edge],
        ),
    )

    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(), table, build_background_knowledge(table), _config()
        )


def test_fci_adapter_rejects_postrun_background_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()
    left = GraphNode("x.safety.sql_parameterization")
    right = GraphNode("y.secure_functional")
    forbidden_reverse = Edge(left, right, Endpoint.ARROW, Endpoint.TAIL)
    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        lambda *_args, **_kwargs: (
            _Graph([item.variable_id for item in table.variables], [forbidden_reverse]),
            [forbidden_reverse],
        ),
    )

    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(), table, build_background_knowledge(table), _config()
        )

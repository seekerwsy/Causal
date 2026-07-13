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
    BackgroundKnowledgeRecord,
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


def _print_empty_bk_orientation_blocks() -> None:
    for _round in range(2):
        print("Starting BK Orientation.")
        print("Finishing BK Orientation.")


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
    return _table_for_values(((0, 0), (1, 0), (0, 1), (1, 1)))


def _table_for_values(values_by_row: tuple[tuple[int, int], ...]) -> CausalTableRecord:
    variables = (
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    observations = []
    for index, values in enumerate(values_by_row):
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
        row_count=len(values_by_row),
        independent_task_count=len(values_by_row),
        observation_payload=observations,
    )


def _matrix() -> np.ndarray:
    return np.asarray(((0, 0), (1, 0), (0, 1), (1, 1)), dtype=np.int64)


def _table_with_forbidden_adjacency() -> tuple[CausalTableRecord, np.ndarray]:
    variables = (
        _variable("w.language_family"),
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    values_by_row = ((0, 0, 0), (1, 0, 1), (0, 1, 1), (1, 1, 0))
    observations = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=f"task-adj-{index}",
                prompt_id=f"prompt-adj-{index}",
                model_id="model-a",
                seed_id=index,
                values=values,
            ),
            f"task-adj-{index}",
            f"prompt-adj-{index}",
            index,
            values,
        )
        for index, values in enumerate(values_by_row)
    )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=4,
        independent_task_count=4,
        observation_payload=observations,
    )
    return table, np.asarray(values_by_row, dtype=np.int64)


def _same_tier_outcome_table() -> tuple[CausalTableRecord, np.ndarray]:
    variables = (
        _variable("y.cwe_security"),
        _variable("y.secure_functional"),
    )
    values_by_row = ((0, 0), (1, 0), (0, 1), (1, 1))
    observations = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=f"task-tier-{index}",
                prompt_id=f"prompt-tier-{index}",
                model_id="model-a",
                seed_id=index,
                values=values,
            ),
            f"task-tier-{index}",
            f"prompt-tier-{index}",
            index,
            values,
        )
        for index, values in enumerate(values_by_row)
    )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=4,
        independent_task_count=4,
        observation_payload=observations,
    )
    return table, np.asarray(values_by_row, dtype=np.int64)


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
        _print_empty_bk_orientation_blocks()
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", capture)
    pag = run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())

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
    pag = run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())

    assert pag.table_id == table.table_id
    assert pag.backend_version == "0.1.4.7"


def test_pinned_real_fci_accepts_audited_bk_orientation_lines_for_known_nodes() -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    values = tuple((index % 2, index % 2) for index in range(40))
    table = _table_for_values(values)
    pag = run_causal_learn_fci(
        np.asarray(values, dtype=np.int64),
        table,
        build_background_knowledge(table),
        _config(),
    )

    assert len(pag.edges) == 1
    assert pag.edges[0].left == "x.safety.sql_parameterization"
    assert pag.edges[0].right == "y.secure_functional"


@pytest.mark.parametrize(
    "orientation",
    (
        "x.unknown --> y.secure_functional",
        "y.secure_functional --> x.safety.sql_parameterization",
        "x.safety.sql_parameterization o-> y.secure_functional",
        "x.safety.sql_parameterization --> y.secure_functional extra",
    ),
)
def test_fci_adapter_rejects_unknown_forbidden_or_malformed_bk_orientation_output(
    monkeypatch: pytest.MonkeyPatch,
    orientation: str,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()

    def diagnostic(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        for _round in range(2):
            print("Starting BK Orientation.")
            print(f"Orienting edge (Knowledge): {orientation}")
            print("Finishing BK Orientation.")
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", diagnostic)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())


def test_fci_adapter_rejects_orientation_output_for_forbidden_adjacency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table, matrix = _table_with_forbidden_adjacency()

    def diagnostic(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        for _round in range(2):
            print("Starting BK Orientation.")
            print("Orienting edge (Knowledge): w.language_family --> x.safety.sql_parameterization")
            print("Finishing BK Orientation.")
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", diagnostic)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(matrix, table, build_background_knowledge(table), _config())


def test_fci_adapter_rejects_unjustified_same_tier_knowledge_orientation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table, matrix = _same_tier_outcome_table()

    def diagnostic(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        for _round in range(2):
            print("Starting BK Orientation.")
            print("Orienting edge (Knowledge): y.cwe_security --> y.secure_functional")
            print("Finishing BK Orientation.")
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", diagnostic)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(matrix, table, build_background_knowledge(table), _config())


def test_stdout_grammar_accepts_a_future_explicitly_required_orientation() -> None:
    from secaware.discovery.causal_learn_backend import _validate_pinned_backend_stdout

    table, _matrix_values = _same_tier_outcome_table()
    original = build_background_knowledge(table)
    required = BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        tiers=original.tiers,
        forbidden_directions=original.forbidden_directions,
        forbidden_adjacencies=original.forbidden_adjacencies,
        required_directions=(("y.cwe_security", "y.secure_functional"),),
    )
    output = "".join(
        (
            "Starting BK Orientation.\n",
            "Orienting edge (Knowledge): y.cwe_security --> y.secure_functional\n",
            "Finishing BK Orientation.\n",
        )
        * 2
    )

    _validate_pinned_backend_stdout(output, table, required)


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
        run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())
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
        run_causal_learn_fci(_matrix(), forged_table, build_background_knowledge(table), _config())
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(),
            table,
            build_background_knowledge(table),
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
        _print_empty_bk_orientation_blocks()
        if emission == "warning":
            warnings.warn("unexpected backend warning")
        elif emission == "stdout":
            print("unexpected backend stdout")
        else:
            print("unexpected backend stderr", file=sys.stderr)
        return _Graph([item.variable_id for item in table.variables]), []

    monkeypatch.setattr("secaware.discovery.causal_learn_backend.fci", noisy)
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())


def test_fci_adapter_rejects_unrecognized_library_edge_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()
    left = GraphNode("x.safety.sql_parameterization")
    right = GraphNode("y.secure_functional")
    edge = Edge(left, right, Endpoint.TAIL, Endpoint.ARROW)
    edge.properties.append(object())

    def unexpected_property(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        _print_empty_bk_orientation_blocks()
        return _Graph([item.variable_id for item in table.variables], [edge]), [edge]

    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        unexpected_property,
    )

    with pytest.raises(SecAwareError):
        run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())


def test_fci_adapter_rejects_postrun_background_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    table = _table()
    left = GraphNode("x.safety.sql_parameterization")
    right = GraphNode("y.secure_functional")
    forbidden_reverse = Edge(left, right, Endpoint.ARROW, Endpoint.TAIL)

    def forbidden_graph(*_args: object, **_kwargs: object) -> tuple[_Graph, list[Edge]]:
        _print_empty_bk_orientation_blocks()
        return (
            _Graph([item.variable_id for item in table.variables], [forbidden_reverse]),
            [forbidden_reverse],
        )

    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        forbidden_graph,
    )

    with pytest.raises(SecAwareError):
        run_causal_learn_fci(_matrix(), table, build_background_knowledge(table), _config())


def test_causal_learn_fci_adapter_rejects_rfci_run_kind_before_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery.causal_learn_backend import run_causal_learn_fci

    monkeypatch.setattr(
        "secaware.discovery.causal_learn_backend.fci",
        lambda *_args, **_kwargs: pytest.fail("FCI must not label output as RFCI"),
    )
    table = _table()
    with pytest.raises(SecAwareError):
        run_causal_learn_fci(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.RFCI_SENSITIVITY,
        )

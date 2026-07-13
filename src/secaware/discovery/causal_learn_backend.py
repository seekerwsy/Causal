"""Pinned, fail-closed causal-learn FCI adapter."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.metadata
from io import StringIO
import warnings

from causallearn.graph.Edge import Edge
from causallearn.search.ConstraintBased.FCI import fci
import numpy as np

from secaware.causal.background import (
    to_causal_learn_background,
    validate_pag_against_background,
)
from secaware.causal.pag import pag_from_causal_learn
from secaware.config import FCIDiscoveryConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
)


CAUSAL_LEARN_VERSION = "0.1.4.7"
_BK_START_LINE = "Starting BK Orientation.\n"
_BK_FINISH_LINE = "Finishing BK Orientation.\n"
_BK_ORIENTATION_PREFIX = "Orienting edge (Knowledge): "
_FCI_RUN_KINDS = frozenset(
    {
        PAGRunKind.OBSERVATIONAL_REFERENCE,
        PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
        PAGRunKind.JCI_RAW,
        PAGRunKind.JCI_CONSTRAINED,
    }
)
_OBSERVATIONAL_RUN_KINDS = frozenset(
    {
        PAGRunKind.OBSERVATIONAL_REFERENCE,
        PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
    }
)


def _backend_error(message: str = "causal-learn FCI backend failed validation") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery",
        message=message,
    )


def _assert_backend_version() -> None:
    try:
        actual = importlib.metadata.version("causal-learn")
    except Exception:
        actual = None
    if actual != CAUSAL_LEARN_VERSION:
        raise _backend_error("causal-learn version mismatch")


def _validated_fci_inputs(
    matrix: np.ndarray,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind,
) -> tuple[
    np.ndarray,
    CausalTableRecord,
    BackgroundKnowledgeRecord,
    FCIDiscoveryConfig,
    PAGRunKind,
]:
    checked_table = CausalTableRecord.model_validate(table)
    checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
    checked_config = FCIDiscoveryConfig.model_validate(config)
    checked_run_kind = PAGRunKind(run_kind)
    if checked_run_kind not in _FCI_RUN_KINDS:
        raise ValueError
    if type(matrix) is not np.ndarray or matrix.dtype != np.dtype(np.int64):
        raise ValueError
    expected_shape = (checked_table.row_count, len(checked_table.variables))
    if (
        matrix.ndim != 2
        or matrix.shape != expected_shape
        or checked_table.row_count > checked_config.max_rows
        or len(checked_table.variables) > checked_config.max_variables
        or checked_table.independent_task_count < checked_config.min_independent_tasks
        or checked_knowledge.table_id != checked_table.table_id
    ):
        raise ValueError
    expected_variables = tuple(item.variable_id for item in checked_table.variables)
    knowledge_variables = tuple(
        sorted(
            {
                *(item for item, _tier in checked_knowledge.tiers),
                *checked_knowledge.unconstrained_variable_ids,
            }
        )
    )
    if knowledge_variables != expected_variables:
        raise ValueError
    if checked_run_kind in _OBSERVATIONAL_RUN_KINDS and checked_knowledge.unconstrained_variable_ids:
        raise ValueError
    # Translation authenticates the finite tier and adjacency contract before FCI.
    to_causal_learn_background(checked_knowledge)
    for column, variable in enumerate(checked_table.variables):
        values = matrix[:, column]
        if np.any(values < 0) or np.any(values >= len(variable.states)):
            raise ValueError
    checked_matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    checked_matrix.flags.writeable = False
    return (
        checked_matrix,
        checked_table,
        checked_knowledge,
        checked_config,
        checked_run_kind,
    )


def validate_fci_inputs(
    matrix: np.ndarray,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind,
) -> tuple[
    np.ndarray,
    CausalTableRecord,
    BackgroundKnowledgeRecord,
    FCIDiscoveryConfig,
    PAGRunKind,
]:
    """Validate FCI input shape/categories and return an isolated matrix copy.

    The caller must authenticate matrix rows against the table observations before
    this boundary. Matrix-to-table content binding belongs to the Task 5 draw/run
    wrapper; this adapter deliberately does not claim that shape checks provide it.
    """
    try:
        return _validated_fci_inputs(matrix, table, knowledge, config, run_kind)
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise _backend_error() from None
    except Exception:
        raise _backend_error() from None


def _edge_signature(edge: object) -> tuple[str, str, object, object]:
    return (
        edge.get_node1().get_name(),  # type: ignore[attr-defined]
        edge.get_node2().get_name(),  # type: ignore[attr-defined]
        edge.get_endpoint1(),  # type: ignore[attr-defined]
        edge.get_endpoint2(),  # type: ignore[attr-defined]
    )


def _validate_library_edges(graph: object, library_edges: object) -> None:
    if type(library_edges) not in {list, tuple}:
        raise ValueError
    graph_edges = graph.get_graph_edges()  # type: ignore[attr-defined]
    if type(graph_edges) not in {list, tuple} or len(graph_edges) != len(library_edges):
        raise ValueError
    if sorted(map(_edge_signature, graph_edges), key=str) != sorted(
        map(_edge_signature, library_edges), key=str
    ):
        raise ValueError
    allowed_properties = tuple(Edge.Property)
    for edge in library_edges:
        properties = getattr(edge, "properties", None)
        if type(properties) is not list or any(item not in allowed_properties for item in properties):
            raise ValueError


def _validate_pinned_backend_stdout(
    output: str,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
) -> None:
    lines = output.splitlines(keepends=True)
    if not lines or any(not line.endswith("\n") or "\r" in line for line in lines):
        raise ValueError
    known = {item.variable_id for item in table.variables}
    forbidden_directions = set(knowledge.forbidden_directions)
    forbidden_adjacencies = set(knowledge.forbidden_adjacencies)
    index = 0
    for _round in range(2):
        if index >= len(lines) or lines[index] != _BK_START_LINE:
            raise ValueError
        index += 1
        while index < len(lines) and lines[index].startswith(_BK_ORIENTATION_PREFIX):
            line = lines[index]
            orientation = line[len(_BK_ORIENTATION_PREFIX) : -1]
            if orientation.count(" --> ") != 1:
                raise ValueError
            source, target = orientation.split(" --> ")
            pair = (source, target) if source < target else (target, source)
            if (
                source == target
                or source not in known
                or target not in known
                or (source, target) in forbidden_directions
                or pair in forbidden_adjacencies
            ):
                raise ValueError
            index += 1
        if index >= len(lines) or lines[index] != _BK_FINISH_LINE:
            raise ValueError
        index += 1
    if index != len(lines):
        raise ValueError


def run_causal_learn_fci(
    matrix: np.ndarray,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    run_kind: PAGRunKind = PAGRunKind.OBSERVATIONAL_REFERENCE,
) -> PAGRecord:
    """Run the single pinned causal-learn FCI/G-square configuration."""
    _assert_backend_version()
    try:
        (
            checked_matrix,
            checked_table,
            checked_knowledge,
            checked_config,
            checked_run_kind,
        ) = _validated_fci_inputs(matrix, table, knowledge, config, run_kind)
        backend_bk = to_causal_learn_background(checked_knowledge)
        stdout = StringIO()
        stderr = StringIO()
        with warnings.catch_warnings(record=True) as captured_warnings:
            warnings.simplefilter("always")
            with redirect_stdout(stdout), redirect_stderr(stderr):
                graph, library_edges = fci(
                    checked_matrix,
                    independence_test_method="gsq",
                    alpha=checked_config.alpha,
                    depth=checked_config.depth,
                    max_path_length=checked_config.max_path_length,
                    verbose=False,
                    background_knowledge=backend_bk,
                    show_progress=False,
                    node_names=[item.variable_id for item in checked_table.variables],
                )
        if captured_warnings or stderr.getvalue():
            raise ValueError
        _validate_pinned_backend_stdout(stdout.getvalue(), checked_table, checked_knowledge)
        _validate_library_edges(graph, library_edges)
        pag = pag_from_causal_learn(
            graph,
            checked_table,
            checked_knowledge,
            checked_config,
            checked_run_kind,
        )
        validate_pag_against_background(pag, checked_knowledge)
        return pag
    except (KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise _backend_error() from None
    except Exception:
        raise _backend_error() from None
    finally:
        matrix = None  # type: ignore[assignment]
        table = None  # type: ignore[assignment]
        knowledge = None  # type: ignore[assignment]
        config = None  # type: ignore[assignment]


__all__ = [
    "CAUSAL_LEARN_VERSION",
    "run_causal_learn_fci",
    "validate_fci_inputs",
]

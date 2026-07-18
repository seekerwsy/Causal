from __future__ import annotations

from collections.abc import Callable

from causallearn.graph.Endpoint import Endpoint
import numpy as np
import pandas as pd
import pytest

from secaware.causal.background import build_background_knowledge, validate_pag_against_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import RFCIConfig
from secaware.schema.causal import (
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.outcomes import RFCICapabilityRecord
from synthetic.scm_fixtures import (
    latent_confounding_scm,
    null_factor_scm,
    true_chain_scm,
)


_TRUE_CHAIN_COLUMNS = {
    "x.feature": "x.safety.sql_parameterization",
    "x.prompt_motif": "x.motif.user_string_to_sql_without_parameterization",
    "y.secure_functional": "y.secure_functional",
}
_LATENT_COLUMNS = {
    "x.feature": "x.safety.sql_parameterization",
    "x.peer": "x.motif.user_string_to_sql_without_parameterization",
}
_NULL_COLUMNS = {
    "x.null": "x.presentation.noop_rewrite",
    "y.secure_functional": "y.secure_functional",
}
_TRUE_CHAIN_EDGE_SIGNATURES = (
    (
        "x.motif.user_string_to_sql_without_parameterization",
        "x.safety.sql_parameterization",
        EndpointMark.ARROW,
        EndpointMark.TAIL,
    ),
    (
        "x.motif.user_string_to_sql_without_parameterization",
        "y.secure_functional",
        EndpointMark.TAIL,
        EndpointMark.ARROW,
    ),
)
_LATENT_EDGE_SIGNATURES = (
    (
        "x.motif.user_string_to_sql_without_parameterization",
        "x.safety.sql_parameterization",
        EndpointMark.CIRCLE,
        EndpointMark.CIRCLE,
    ),
)
# Exact non-available reason codes emitted by detect_rfci_capability are partitioned here.
_INTEGRITY_FAILURE_REASONS = (
    "runtime_provenance_invalid",
    "capability_probe_failed",
    "jpype_version_mismatch",
    "py_tetrad_commit_mismatch",
    "tetrad_jar_missing",
    "tetrad_jar_hash_mismatch",
    "java_version_unsupported",
)
_NORMAL_ABSENCE_REASONS = (
    "python_version_unsupported",
    "jpype_missing",
    "py_tetrad_missing",
    "java_missing",
)
_TRUE_CHAIN_BACKEND_EDGES = (
    (
        "x.safety.sql_parameterization",
        "x.motif.user_string_to_sql_without_parameterization",
        Endpoint.TAIL,
        Endpoint.ARROW,
    ),
    (
        "x.motif.user_string_to_sql_without_parameterization",
        "y.secure_functional",
        Endpoint.TAIL,
        Endpoint.ARROW,
    ),
)
_LATENT_BACKEND_EDGES = (
    (
        "x.safety.sql_parameterization",
        "x.motif.user_string_to_sql_without_parameterization",
        Endpoint.CIRCLE,
        Endpoint.CIRCLE,
    ),
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
        left_mark: Endpoint,
        right_mark: Endpoint,
    ) -> None:
        self._left = _Node(left)
        self._right = _Node(right)
        self._left_mark = left_mark
        self._right_mark = right_mark

    def get_node1(self) -> _Node:
        return self._left

    def get_node2(self) -> _Node:
        return self._right

    def get_endpoint1(self) -> Endpoint:
        return self._left_mark

    def get_endpoint2(self) -> Endpoint:
        return self._right_mark


class _Graph:
    def __init__(self, variable_ids: tuple[str, ...], edges: tuple[_Edge, ...]) -> None:
        self._nodes = [_Node(variable_id) for variable_id in variable_ids]
        self._edges = list(edges)

    def get_nodes(self) -> list[_Node]:
        return self._nodes

    def get_graph_edges(self) -> list[_Edge]:
        return self._edges


class _FakeTetradParameters:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    def set(self, key: str, value: object) -> None:
        self.values[key] = value

    def getBoolean(self, key: str) -> object:
        return self.values.get(key)


class _FakeTetradSearch:
    instances: list["_FakeTetradSearch"] = []
    backend_edges: tuple[tuple[str, str, Endpoint, Endpoint], ...] = ()

    def __init__(self, frame: pd.DataFrame) -> None:
        self.frame = frame
        self.alpha: float | None = None
        self.tiers: list[tuple[int, str]] = []
        self.forbidden_directions: list[tuple[str, str]] = []
        self.rfci_kwargs: dict[str, object] | None = None
        self.params = _FakeTetradParameters()
        type(self).instances.append(self)

    def use_g_square(self, *, alpha: float) -> None:
        self.alpha = alpha

    def add_to_tier(self, tier: int, variable_id: str) -> None:
        self.tiers.append((tier, variable_id))

    def set_forbidden(self, source: str, target: str) -> None:
        self.forbidden_directions.append((source, target))

    def run_rfci(self, **kwargs: object) -> None:
        self.rfci_kwargs = kwargs

    def get_causal_learn(self) -> _Graph:
        return _Graph(
            tuple(str(item) for item in self.frame.columns),
            tuple(_Edge(*edge) for edge in type(self).backend_edges),
        )


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


def _table_and_rows(
    frame: pd.DataFrame,
    columns: dict[str, str],
) -> tuple[CausalTableRecord, tuple[CausalObservationRecord, ...]]:
    ordered = tuple(sorted(columns.items(), key=lambda item: item[1]))
    variables = tuple(_variable(variable_id) for _source_name, variable_id in ordered)
    observations = []
    for index in range(len(frame)):
        task_id = f"synthetic-rfci-task-{index:05d}"
        prompt_id = f"synthetic-rfci-prompt-{index:05d}"
        values = tuple(int(frame.iloc[index][source_name]) for source_name, _variable_id in ordered)
        observations.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id="synthetic-model",
                    seed_id=0,
                    values=values,
                ),
                task_id,
                prompt_id,
                0,
                values,
            )
        )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="synthetic-model",
        variables=variables,
        row_count=len(observations),
        independent_task_count=len(observations),
        observation_payload=observations,
    )
    rows = tuple(
        sorted(
            (
                CausalObservationRecord.from_content(
                    table=table,
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id=table.model_id,
                    seed_id=seed_id,
                    values=values,
                )
                for _row_id, task_id, prompt_id, seed_id, values in observations
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )
    return table, rows


def _config() -> RFCIConfig:
    return RFCIConfig(
        enabled=True,
        alpha=0.01,
        depth=3,
        max_discriminating_path_length=4,
    )


def _real_config() -> RFCIConfig:
    return RFCIConfig.model_validate(
        {**_config().model_dump(mode="python"), "timeout_seconds": 300.0}
    )


def _unavailable_capability(reason_code: str) -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status="unavailable",
        requires_java=True,
        python_version="3.12.9",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code=reason_code,
    )


def _require_real_rfci_capability(
    capability: RFCICapabilityRecord,
    *,
    require_available: bool = False,
) -> None:
    if capability.available:
        if capability.status != "available" or capability.reason_code is not None:
            pytest.fail("optional RFCI capability relation is invalid", pytrace=False)
        return
    if require_available:
        pytest.fail(
            f"explicit real RFCI gate requires an available runtime: {capability.reason_code}",
            pytrace=False,
        )
    if capability.status == "unavailable" and capability.reason_code in _NORMAL_ABSENCE_REASONS:
        pytest.skip(f"optional RFCI unavailable: {capability.reason_code}")
    pytest.fail(
        f"optional RFCI capability integrity failure: {capability.reason_code}",
        pytrace=False,
    )


def _edge_signatures(pag: PAGRecord) -> tuple[tuple[str, str, EndpointMark, EndpointMark], ...]:
    return tuple((edge.left, edge.right, edge.left_mark, edge.right_mark) for edge in pag.edges)


def _assert_true_chain_skeleton(pag: PAGRecord) -> None:
    pairs = {(edge.left, edge.right) for edge in pag.edges}
    assert {
        (
            "x.motif.user_string_to_sql_without_parameterization",
            "x.safety.sql_parameterization",
        ),
        (
            "x.motif.user_string_to_sql_without_parameterization",
            "y.secure_functional",
        ),
    } <= pairs
    assert ("x.safety.sql_parameterization", "y.secure_functional") not in pairs


@pytest.mark.parametrize(
    ("factory", "columns", "seed", "backend_edges", "expected_edges"),
    (
        (
            true_chain_scm,
            _TRUE_CHAIN_COLUMNS,
            501,
            _TRUE_CHAIN_BACKEND_EDGES,
            _TRUE_CHAIN_EDGE_SIGNATURES,
        ),
        (
            latent_confounding_scm,
            _LATENT_COLUMNS,
            502,
            _LATENT_BACKEND_EDGES,
            _LATENT_EDGE_SIGNATURES,
        ),
        (null_factor_scm, _NULL_COLUMNS, 503, (), ()),
    ),
    ids=("true-chain", "latent-confounding", "null-factor"),
)
def test_fake_rfci_core_preserves_family_shaped_backend_graphs(
    factory: Callable[[int, int], pd.DataFrame],
    columns: dict[str, str],
    seed: int,
    backend_edges: tuple[tuple[str, str, Endpoint, Endpoint], ...],
    expected_edges: tuple[tuple[str, str, EndpointMark, EndpointMark], ...],
) -> None:
    from secaware.discovery import rfci_backend

    table, rows = _table_and_rows(factory(400, seed), columns)
    knowledge = build_background_knowledge(table)
    config = _config()
    _FakeTetradSearch.instances.clear()
    _FakeTetradSearch.backend_edges = backend_edges
    checked_table, matrix = rfci_backend._authenticated_rfci_matrix(table, rows)

    pag = rfci_backend._run_rfci_adapter(
        checked_table,
        matrix,
        knowledge,
        config,
        _FakeTetradSearch,
    )

    assert len(_FakeTetradSearch.instances) == 1
    search = _FakeTetradSearch.instances[0]
    assert tuple(search.frame.columns) == tuple(item.variable_id for item in table.variables)
    assert search.frame.to_numpy(dtype=np.int64).tobytes(order="C") == matrix.tobytes(order="C")
    assert search.params.values == {"excludeSelectionBias": True}
    assert search.alpha == config.alpha
    assert set(search.tiers) == {(tier, variable_id) for variable_id, tier in knowledge.tiers}
    assert set(search.forbidden_directions) == set(
        rfci_backend.expanded_forbidden_directions(knowledge)
    )
    assert search.rfci_kwargs == {
        "depth": config.depth,
        "stable_fas": True,
        "max_disc_path_length": config.max_discriminating_path_length,
        "complete_rule_set_used": True,
    }
    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    assert pag.backend == rfci_backend.RFCI_BACKEND
    assert _edge_signatures(pag) == expected_edges
    if factory is true_chain_scm:
        _assert_true_chain_skeleton(pag)
    validate_pag_against_background(pag, knowledge)


def test_explicit_test_rfci_adapter_cannot_be_mistaken_for_production() -> None:
    from secaware.discovery import rfci_backend

    table, rows = _table_and_rows(true_chain_scm(200, 504), _TRUE_CHAIN_COLUMNS)

    pag = rfci_backend._run_test_rfci_adapter(table, rows, _config())

    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    assert pag.backend == "test_rfci_fake_v1"
    assert pag.backend != rfci_backend.RFCI_BACKEND


@pytest.mark.parametrize("reason_code", _INTEGRITY_FAILURE_REASONS)
def test_real_rfci_gate_fails_on_capability_integrity_errors(reason_code: str) -> None:
    with pytest.raises(pytest.fail.Exception):
        _require_real_rfci_capability(_unavailable_capability(reason_code))


@pytest.mark.parametrize("reason_code", _NORMAL_ABSENCE_REASONS)
def test_real_rfci_gate_skips_only_normal_runtime_absence(reason_code: str) -> None:
    with pytest.raises(pytest.skip.Exception):
        _require_real_rfci_capability(_unavailable_capability(reason_code))


@pytest.mark.parametrize("reason_code", _NORMAL_ABSENCE_REASONS)
def test_explicit_real_rfci_gate_fails_when_runtime_is_absent(reason_code: str) -> None:
    with pytest.raises(pytest.fail.Exception):
        _require_real_rfci_capability(
            _unavailable_capability(reason_code),
            require_available=True,
        )


def test_real_rfci_gate_uses_dedicated_timeout() -> None:
    assert _real_config().timeout_seconds == 300.0


@pytest.mark.rfci_real
def test_real_rfci_sensitivity_runs_only_when_optional_capability_is_available(
    request: pytest.FixtureRequest,
) -> None:
    from secaware.discovery.rfci_backend import (
        detect_rfci_capability,
        run_rfci_sensitivity,
        validate_rfci_sensitivity_result,
    )

    config = _real_config()
    capability = detect_rfci_capability(config)
    _require_real_rfci_capability(
        capability,
        require_available=request.config.getoption("markexpr") == "rfci_real",
    )
    assert capability.status == "available"
    assert capability.available is True
    table, rows = _table_and_rows(true_chain_scm(1000, 505), _TRUE_CHAIN_COLUMNS)
    knowledge = build_background_knowledge(table)

    result = run_rfci_sensitivity(table, rows, knowledge, config)

    assert result.capability == capability
    assert result.pag is not None
    assert result.pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    # One real JVM execution bounds opt-in CI cost; canonical codec behavior is covered above.
    _assert_true_chain_skeleton(result.pag)
    validate_pag_against_background(result.pag, knowledge)
    assert validate_rfci_sensitivity_result(result, table, knowledge, config) == result

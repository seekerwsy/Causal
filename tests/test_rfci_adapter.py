from __future__ import annotations

from copy import deepcopy
import json
import multiprocessing
import os
import threading
import time
from typing import Any

from causallearn.graph.Endpoint import Endpoint
import numpy as np
import pytest

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGRecord,
    PAGRunKind,
)


PINNED_COMMIT = "a30707264aa4363a23ac5f136a70bbdd62212f07"
PINNED_JAR_SHA256 = "3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4"


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
    def __init__(self, variable_ids: tuple[str, ...], edges: list[_Edge] | None = None) -> None:
        self._nodes = [_Node(item) for item in variable_ids]
        self._edges = [] if edges is None else edges

    def get_nodes(self) -> list[_Node]:
        return self._nodes

    def get_graph_edges(self) -> list[_Edge]:
        return self._edges


class _FakeTetradSearch:
    instances: list["_FakeTetradSearch"] = []
    graph_factory: Any = None

    def __init__(self, frame: Any) -> None:
        self.frame = frame
        self.used_g_square = False
        self.alpha: float | None = None
        self.tiers: list[tuple[int, str]] = []
        self.forbidden_directions: list[tuple[str, str]] = []
        self.required_edges: list[tuple[str, str]] = []
        self.rfci_kwargs: dict[str, object] | None = None
        type(self).instances.append(self)

    def use_g_square(self, *, alpha: float) -> None:
        self.used_g_square = True
        self.alpha = alpha

    def add_to_tier(self, tier: int, variable_id: str) -> None:
        self.tiers.append((tier, variable_id))

    def set_forbidden(self, source: str, target: str) -> None:
        self.forbidden_directions.append((source, target))

    def run_rfci(self, **kwargs: object) -> None:
        self.rfci_kwargs = kwargs

    def get_causal_learn(self) -> _Graph:
        variable_ids = tuple(str(item) for item in self.frame.columns)
        factory = type(self).graph_factory
        return _Graph(variable_ids) if factory is None else factory(variable_ids)


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
        _variable("w.language_family"),
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    observations = []
    for index in range(4):
        values = (index % 2, (index // 2) % 2, (index + 1) % 2)
        task_id = f"task-{index}"
        prompt_id = f"prompt-{index}"
        observations.append(
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
        observation_payload=observations,
    )


def _matrix() -> np.ndarray:
    return np.asarray(((0, 0, 1), (1, 0, 0), (0, 1, 1), (1, 1, 0)), dtype=np.int64)


def _config(**changes: object) -> Any:
    from secaware.config import RFCIConfig

    return RFCIConfig(enabled=True, **changes)


def _capability(**changes: object) -> Any:
    from secaware.schema.outcomes import RFCICapabilityRecord

    payload = {
        "schema_version": "1.0",
        "available": True,
        "status": "available",
        "requires_java": True,
        "python_version": "3.12.9",
        "java_major": 21,
        "jpype_version": "1.7.1",
        "py_tetrad_commit": PINNED_COMMIT,
        "tetrad_jar_sha256": PINNED_JAR_SHA256,
        "reason_code": None,
        **changes,
    }
    return RFCICapabilityRecord.model_validate(payload)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _valid_payload(job_json: bytes) -> bytes:
    from secaware.config import RFCIConfig

    job = json.loads(job_json)
    table = CausalTableRecord.model_validate(job["table"])
    knowledge = BackgroundKnowledgeRecord.model_validate(job["knowledge"])
    config = RFCIConfig.model_validate(job["config"])
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend="py_tetrad_rfci_v1",
        backend_version=config.py_tetrad_commit,
        ci_test="gsq",
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    return _canonical_json(pag.model_dump(mode="json"))


def _returns_valid(send_connection: Any, job_json: bytes, _matrix: np.ndarray) -> None:
    send_connection.send_bytes(_valid_payload(job_json))


def _never_returns(_send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    while True:
        time.sleep(0.05)


def _crashes(_send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    os._exit(7)


def _mutates_config(send_connection: Any, job_json: bytes, _matrix: np.ndarray) -> None:
    payload = json.loads(_valid_payload(job_json))
    payload.pop("pag_id")
    payload["config_sha256"] = "f" * 64
    forged = PAGRecord.from_content(**payload)
    send_connection.send_bytes(_canonical_json(forged.model_dump(mode="json")))


@pytest.fixture(autouse=True)
def _reset_fake_search() -> None:
    _FakeTetradSearch.instances.clear()
    _FakeTetradSearch.graph_factory = None


def test_rfci_adapter_uses_exact_table_rows_gsquare_knowledge_and_run_settings() -> None:
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    table = _table()
    matrix = _matrix()
    knowledge = build_background_knowledge(table)
    config = _config(alpha=0.01, depth=4, max_discriminating_path_length=8)

    pag = run_rfci_sensitivity(table, matrix, knowledge, config, _FakeTetradSearch)

    search = _FakeTetradSearch.instances[0]
    assert tuple(search.frame.columns) == tuple(item.variable_id for item in table.variables)
    assert np.array_equal(search.frame.to_numpy(dtype=np.int64), matrix)
    assert search.used_g_square is True
    assert search.alpha == 0.01
    assert set(search.tiers) == {(tier, variable_id) for variable_id, tier in knowledge.tiers}
    expected_forbidden = set(knowledge.forbidden_directions) | {
        direction
        for left, right in knowledge.forbidden_adjacencies
        for direction in ((left, right), (right, left))
    }
    assert set(search.forbidden_directions) == expected_forbidden
    assert search.required_edges == []
    assert search.rfci_kwargs == {
        "depth": 4,
        "stable_fas": True,
        "max_disc_path_length": 8,
        "complete_rule_set_used": True,
    }
    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    assert pag.backend == "py_tetrad_rfci_v1"
    assert pag.backend_version == PINNED_COMMIT
    assert pag.config_sha256 == canonical_sha256(config.model_dump(mode="json"))


def test_rfci_adapter_converts_only_through_shared_pag_endpoint_codec() -> None:
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    def graph(variable_ids: tuple[str, ...]) -> _Graph:
        return _Graph(
            variable_ids,
            [
                _Edge(
                    "y.secure_functional",
                    "x.safety.sql_parameterization",
                    Endpoint.ARROW,
                    Endpoint.CIRCLE,
                )
            ],
        )

    _FakeTetradSearch.graph_factory = graph
    table = _table()
    pag = run_rfci_sensitivity(
        table,
        _matrix(),
        build_background_knowledge(table),
        _config(),
        _FakeTetradSearch,
    )

    edge = pag.edges[0]
    assert edge.left == "x.safety.sql_parameterization"
    assert edge.right == "y.secure_functional"
    assert edge.left_mark is EndpointMark.CIRCLE
    assert edge.right_mark is EndpointMark.ARROW


def test_rfci_adapter_rejects_postrun_background_violation() -> None:
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    def graph(variable_ids: tuple[str, ...]) -> _Graph:
        return _Graph(
            variable_ids,
            [
                _Edge(
                    "x.safety.sql_parameterization",
                    "y.secure_functional",
                    Endpoint.ARROW,
                    Endpoint.TAIL,
                )
            ],
        )

    _FakeTetradSearch.graph_factory = graph
    table = _table()
    with pytest.raises(SecAwareError):
        run_rfci_sensitivity(
            table,
            _matrix(),
            build_background_knowledge(table),
            _config(),
            _FakeTetradSearch,
        )


@pytest.mark.parametrize(
    "matrix",
    (
        np.zeros((4, 3), dtype=np.float64),
        np.zeros((3, 3), dtype=np.int64),
        np.asarray(((0, 0, 2),) * 4, dtype=np.int64),
    ),
)
def test_rfci_rejects_invalid_exact_row_matrix_before_fake_boundary(matrix: np.ndarray) -> None:
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    table = _table()
    with pytest.raises(SecAwareError):
        run_rfci_sensitivity(
            table,
            matrix,
            build_background_knowledge(table),
            _config(),
            _FakeTetradSearch,
        )
    assert _FakeTetradSearch.instances == []


def test_disabled_or_unavailable_rfci_returns_no_pag_and_never_enters_boundary() -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    table = _table()
    result = run_rfci_sensitivity(
        table,
        _matrix(),
        build_background_knowledge(table),
        RFCIConfig(),
        lambda _frame: pytest.fail("disabled RFCI must not enter adapter"),
    )

    assert result is None


def test_enabled_but_unavailable_rfci_returns_no_pag_and_keeps_capability_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.schema.outcomes import RFCICapabilityRecord

    capability = RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status="unavailable",
        requires_java=True,
        python_version="3.12.9",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="jpype_missing",
    )
    monkeypatch.setattr(rfci_backend, "detect_rfci_capability", lambda _config: capability)
    monkeypatch.setattr(
        rfci_backend,
        "SpawnedRFCIRunner",
        lambda **_kwargs: pytest.fail("unavailable RFCI must not spawn"),
    )
    table = _table()

    result = rfci_backend.run_rfci_sensitivity(
        table,
        _matrix(),
        build_background_knowledge(table),
        _config(),
    )

    assert result is None
    assert capability.status == "unavailable"
    assert capability.reason_code == "jpype_missing"


def test_rfci_has_no_primary_run_kind_escape_hatch() -> None:
    from inspect import signature

    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    assert "run_kind" not in signature(run_rfci_sensitivity).parameters


def test_spawned_rfci_runner_revalidates_sensitivity_provenance() -> None:
    from secaware.discovery.rfci_backend import SpawnedRFCIRunner

    table = _table()
    pag = SpawnedRFCIRunner(
        capability=_capability(),
        timeout_seconds=2.0,
        worker=_returns_valid,
    ).run(table, _matrix(), build_background_knowledge(table), _config())

    assert pag is not None
    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY


def test_spawned_rfci_runner_times_out_without_leaking_children() -> None:
    from secaware.discovery.rfci_backend import SpawnedRFCIRunner

    table = _table()
    baseline = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(SecAwareError, match="timed out"):
        SpawnedRFCIRunner(
            capability=_capability(),
            timeout_seconds=0.1,
            worker=_never_returns,
        ).run(table, _matrix(), build_background_knowledge(table), _config())
    assert time.monotonic() - started < 2.0
    assert {child.pid for child in multiprocessing.active_children()} <= baseline
    assert not any(
        thread.name == "secaware-rfci-pipe-reader" and thread.is_alive()
        for thread in threading.enumerate()
    )


@pytest.mark.parametrize("worker", (_crashes, _mutates_config))
def test_spawned_rfci_runner_rejects_child_crash_and_config_drift(worker: Any) -> None:
    from secaware.discovery.rfci_backend import SpawnedRFCIRunner

    table = _table()
    with pytest.raises(SecAwareError):
        SpawnedRFCIRunner(
            capability=_capability(),
            timeout_seconds=2.0,
            worker=worker,
        ).run(table, _matrix(), build_background_knowledge(table), _config())


def test_spawned_rfci_runner_rejects_tampered_capability_and_parent_inputs() -> None:
    from secaware.discovery.rfci_backend import SpawnedRFCIRunner

    table = _table()
    capability = _capability()
    object.__setattr__(capability, "tetrad_jar_sha256", "f" * 64)
    with pytest.raises(SecAwareError):
        SpawnedRFCIRunner(capability=capability, worker=_returns_valid)

    tampered = deepcopy(table)
    object.__setattr__(tampered, "row_count", 5)
    with pytest.raises(SecAwareError):
        SpawnedRFCIRunner(
            capability=_capability(),
            timeout_seconds=2.0,
            worker=_returns_valid,
        ).run(tampered, _matrix(), build_background_knowledge(table), _config())


def test_production_runner_reprobes_installation_and_rejects_self_reported_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend
    from secaware.schema.outcomes import RFCICapabilityRecord

    unavailable = RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status="unavailable",
        requires_java=True,
        python_version="3.12.9",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="jpype_missing",
    )
    monkeypatch.setattr(rfci_backend, "detect_rfci_capability", lambda _config: unavailable)
    monkeypatch.setattr(
        rfci_backend.multiprocessing,
        "get_context",
        lambda _method: pytest.fail("untrusted capability must fail before spawn"),
    )
    table = _table()

    with pytest.raises(SecAwareError):
        rfci_backend.SpawnedRFCIRunner(capability=_capability()).run(
            table,
            _matrix(),
            build_background_knowledge(table),
            _config(),
        )

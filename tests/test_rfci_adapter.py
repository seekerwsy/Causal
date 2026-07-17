from __future__ import annotations

from copy import deepcopy
import json
import os
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


def _rows(table: CausalTableRecord) -> tuple[CausalObservationRecord, ...]:
    rows = []
    for index, values in enumerate(_matrix().tolist()):
        rows.append(
            CausalObservationRecord.from_content(
                table=table,
                task_id=f"task-{index}",
                prompt_id=f"prompt-{index}",
                model_id=table.model_id,
                seed_id=index,
                values=tuple(values),
            )
        )
    return tuple(sorted(rows, key=lambda item: (item.table_id, item.row_id)))


def _foreign_row(table: CausalTableRecord) -> CausalObservationRecord:
    observations = []
    for index, raw_values in enumerate(_matrix().tolist()):
        values = tuple(raw_values)
        if index == 3:
            values = (values[0], values[1], 1 - values[2])
        task_id = f"task-{index}"
        prompt_id = f"prompt-{index}"
        observations.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id=table.model_id,
                    seed_id=index,
                    values=values,
                ),
                task_id,
                prompt_id,
                index,
                values,
            )
        )
    foreign_table = CausalTableRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        variables=table.variables,
        row_count=4,
        independent_task_count=4,
        observation_payload=observations,
    )
    return _rows(foreign_table)[0]


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


def _run_fake_adapter(
    table: CausalTableRecord,
    rows: object,
    knowledge: BackgroundKnowledgeRecord,
    config: object,
) -> PAGRecord:
    from secaware.discovery import rfci_backend

    checked_table, matrix = rfci_backend._authenticated_rfci_matrix(table, rows)
    return rfci_backend._run_rfci_adapter(
        checked_table,
        matrix,
        knowledge,
        config,
        _FakeTetradSearch,
    )


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
    table = _table()
    rows = _rows(table)
    matrix = np.asarray(tuple(item.values for item in rows), dtype=np.int64)
    knowledge = build_background_knowledge(table)
    config = _config(alpha=0.01, depth=4, max_discriminating_path_length=8)

    pag = _run_fake_adapter(
        table,
        rows,
        knowledge,
        config,
    )

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
    pag = _run_fake_adapter(
        table,
        _rows(table),
        build_background_knowledge(table),
        _config(),
    )

    edge = pag.edges[0]
    assert edge.left == "x.safety.sql_parameterization"
    assert edge.right == "y.secure_functional"
    assert edge.left_mark is EndpointMark.CIRCLE
    assert edge.right_mark is EndpointMark.ARROW


def test_rfci_adapter_rejects_postrun_background_violation() -> None:
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
        _run_fake_adapter(
            table,
            _rows(table),
            build_background_knowledge(table),
            _config(),
        )


@pytest.mark.parametrize(
    "matrix",
    (
        np.zeros((4, 3), dtype=np.float64),
        np.zeros((3, 3), dtype=np.int64),
        np.asarray(((0, 0, 2),) * 4, dtype=np.int64),
    ),
)
def test_rfci_rejects_detached_ndarray_before_fake_boundary(matrix: np.ndarray) -> None:
    table = _table()
    with pytest.raises(SecAwareError):
        _run_fake_adapter(
            table,
            matrix,
            build_background_knowledge(table),
            _config(),
        )
    assert _FakeTetradSearch.instances == []


def test_disabled_or_unavailable_rfci_returns_no_pag_and_never_enters_boundary() -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    table = _table()
    result = run_rfci_sensitivity(
        table,
        _rows(table),
        build_background_knowledge(table),
        RFCIConfig(),
    )

    assert result.capability.status == "disabled"
    assert result.pag is None


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
        "_collect_runtime_evidence",
        lambda _config: pytest.fail("unavailable RFCI must not collect active evidence"),
    )
    table = _table()

    result = rfci_backend.run_rfci_sensitivity(
        table,
        _rows(table),
        build_background_knowledge(table),
        _config(),
    )

    assert result.capability == capability
    assert result.pag is None
    assert capability.status == "unavailable"
    assert capability.reason_code == "jpype_missing"


def test_rfci_has_no_primary_run_kind_escape_hatch() -> None:
    from inspect import signature

    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    assert "run_kind" not in signature(run_rfci_sensitivity).parameters


def test_rfci_public_boundary_rebuilds_matrix_from_exact_authenticated_rows() -> None:
    table = _table()
    pag = _run_fake_adapter(
        table,
        _rows(table),
        build_background_knowledge(table),
        _config(),
    )

    assert pag.backend == "py_tetrad_rfci_v1"
    assert np.array_equal(
        _FakeTetradSearch.instances[0].frame.to_numpy(dtype=np.int64),
        np.asarray(tuple(item.values for item in _rows(table)), dtype=np.int64),
    )


@pytest.mark.parametrize(
    "mutation",
    ("detached", "missing", "extra", "reordered", "forged", "foreign"),
)
def test_rfci_public_boundary_rejects_detached_matrix_and_forged_row_relations(
    mutation: str,
) -> None:
    table = _table()
    knowledge = build_background_knowledge(table)
    rows = _rows(table)
    forged = CausalObservationRecord.from_content(
        table=table,
        task_id=rows[0].task_id,
        prompt_id=rows[0].prompt_id,
        model_id=rows[0].model_id,
        seed_id=rows[0].seed_id,
        values=(1 - rows[0].values[0], *rows[0].values[1:]),
    )
    relation = {
        "detached": _matrix(),
        "missing": rows[:-1],
        "extra": (*rows, rows[-1]),
        "reordered": tuple(reversed(rows)),
        "forged": tuple(sorted((forged, *rows[1:]), key=lambda item: (item.table_id, item.row_id))),
        "foreign": tuple(
            sorted(
                (_foreign_row(table), *rows[1:]),
                key=lambda item: (item.table_id, item.row_id),
            )
        ),
    }[mutation]

    with pytest.raises(SecAwareError):
        _run_fake_adapter(
            table,
            relation,  # type: ignore[arg-type]
            knowledge,
            _config(),
        )
    assert _FakeTetradSearch.instances == []


def test_unavailable_rfci_returns_persistable_result_bound_to_exact_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend

    capability = _capability(
        available=False,
        status="unavailable",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="jpype_missing",
    )
    monkeypatch.setattr(rfci_backend, "detect_rfci_capability", lambda _config: capability)
    table = _table()

    result = rfci_backend.run_rfci_sensitivity(
        table,
        _rows(table),
        build_background_knowledge(table),
        _config(),
    )

    assert result.capability == capability
    assert result.pag is None
    assert type(result).model_validate_json(result.model_dump_json()) == result

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        result.pag = None  # type: ignore[misc]
    with pytest.raises(ValidationError):
        type(result).model_validate({"capability": capability, "pag": None, "unexpected": True})


def test_rfci_public_boundary_accepts_exact_authenticated_jci_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_jci_table_builder import fixture_for

    from secaware.causal.jci import build_jci_background, build_jci_tables
    from secaware.discovery import rfci_backend

    fixture = fixture_for(task_count=2)
    tables, all_rows = build_jci_tables(
        fixture.assignments,
        fixture.outcomes,
        fixture.graphs,
        variants=fixture.variants,
        hypotheses=fixture.hypotheses,  # type: ignore[arg-type]
        protocols=fixture.protocols,  # type: ignore[arg-type]
        min_independent_tasks=2,
    )
    table = tables[0]
    rows = tuple(item for item in all_rows if item.table_id == table.table_id)
    knowledge, _provenance = build_jci_background(table)
    expected = np.asarray(tuple(item.values for item in rows), dtype=np.int64)

    def adapter(
        received_table: CausalTableRecord,
        matrix: np.ndarray,
        received_knowledge: BackgroundKnowledgeRecord,
        config: object,
        _factory: object,
    ) -> PAGRecord:
        assert received_table == table
        assert received_knowledge == knowledge
        assert np.array_equal(matrix, expected)
        return PAGRecord.from_content(
            run_kind=PAGRunKind.RFCI_SENSITIVITY,
            table_id=table.table_id,
            backend="py_tetrad_rfci_v1",
            backend_version=PINNED_COMMIT,
            ci_test="gsq",
            config_sha256=canonical_sha256(config.model_dump(mode="json")),  # type: ignore[attr-defined]
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=tuple(item.variable_id for item in table.variables),
            edges=(),
        )

    monkeypatch.setattr(rfci_backend, "_run_rfci_adapter", adapter)

    pag = _run_fake_adapter(
        table,
        rows,
        knowledge,
        _config(),
    )

    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY


def test_parent_revalidates_canonical_worker_result_provenance() -> None:
    from secaware.discovery.rfci_backend import validate_rfci_sensitivity_result
    from secaware.schema.outcomes import RFCISensitivityResult

    table = _table()
    knowledge = build_background_knowledge(table)
    config = _config()
    pag = PAGRecord.model_validate_json(
        _valid_payload(
            _canonical_json(
                {
                    "table": table.model_dump(mode="json"),
                    "knowledge": knowledge.model_dump(mode="json"),
                    "config": config.model_dump(mode="json"),
                }
            )
        )
    )
    result = RFCISensitivityResult(capability=_capability(), pag=pag)

    assert validate_rfci_sensitivity_result(result, table, knowledge, config) == result


def test_isolated_rfci_process_timeout_returns_promptly() -> None:
    from pathlib import Path
    import sys

    from secaware.process_isolation import run_isolated_process

    started = time.monotonic()
    with pytest.raises(SecAwareError):
        run_isolated_process(
            (sys.executable, "-I", "-c", "import time;time.sleep(30)"),
            cwd=Path.cwd(),
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=0.1,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        )
    assert time.monotonic() - started < 2.0


def test_parent_rejects_worker_crash() -> None:
    from pathlib import Path
    import sys

    from secaware.process_isolation import run_isolated_process

    with pytest.raises(SecAwareError):
        run_isolated_process(
            (sys.executable, "-I", "-c", "import os;os._exit(7)"),
            cwd=Path.cwd(),
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=2.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        )


def test_parent_rejects_recomputed_config_drift() -> None:
    from secaware.discovery.rfci_backend import validate_rfci_sensitivity_result
    from secaware.schema.outcomes import RFCISensitivityResult

    table = _table()
    knowledge = build_background_knowledge(table)
    config = _config()
    wrong_config = _config(alpha=0.01)
    payload = json.loads(
        _valid_payload(
            _canonical_json(
                {
                    "table": table.model_dump(mode="json"),
                    "knowledge": knowledge.model_dump(mode="json"),
                    "config": wrong_config.model_dump(mode="json"),
                }
            )
        )
    )
    result = RFCISensitivityResult(capability=_capability(), pag=PAGRecord.model_validate(payload))
    with pytest.raises(SecAwareError):
        validate_rfci_sensitivity_result(result, table, knowledge, config)


def test_parent_rejects_tampered_capability_and_parent_inputs() -> None:
    from pydantic import ValidationError
    from secaware.schema.outcomes import RFCISensitivityResult

    table = _table()
    capability = _capability()
    object.__setattr__(capability, "tetrad_jar_sha256", "f" * 64)
    with pytest.raises(ValidationError):
        RFCISensitivityResult(
            capability=capability,
            pag=PAGRecord.model_validate_json(
                _valid_payload(
                    _canonical_json(
                        {
                            "table": table.model_dump(mode="json"),
                            "knowledge": build_background_knowledge(table).model_dump(mode="json"),
                            "config": _config().model_dump(mode="json"),
                        }
                    )
                )
            ),
        )

    tampered = deepcopy(table)
    object.__setattr__(tampered, "row_count", 5)
    with pytest.raises(SecAwareError):
        _run_fake_adapter(tampered, _rows(table), build_background_knowledge(table), _config())


def test_production_run_reprobes_and_stops_on_unavailable_capability(
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
        rfci_backend,
        "_collect_runtime_evidence",
        lambda _config: pytest.fail("unavailable capability must stop before active evidence"),
    )
    table = _table()

    result = rfci_backend.run_rfci_sensitivity(
        table,
        _rows(table),
        build_background_knowledge(table),
        _config(),
    )
    assert result.capability == unavailable
    assert result.pag is None

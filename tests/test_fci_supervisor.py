from __future__ import annotations

from copy import deepcopy
from functools import partial
import json
import multiprocessing
import os
import struct
import threading
import time
from typing import Any

import numpy as np
import pytest

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
)


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _valid_payload(job_json: bytes) -> bytes:
    job = json.loads(job_json)
    table = CausalTableRecord.model_validate(job["table"])
    knowledge = BackgroundKnowledgeRecord.model_validate(job["knowledge"])
    config = FCIDiscoveryConfig.model_validate(job["config"])
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind(job["run_kind"]),
        table_id=table.table_id,
        backend=config.backend,
        backend_version=config.backend_version,
        ci_test=config.ci_test,
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    return _canonical_json(pag.model_dump(mode="json"))


def _returns_valid(send_connection: Any, job_json: bytes, _matrix: np.ndarray) -> None:
    assert type(job_json) is bytes
    assert type(_matrix) is np.ndarray
    assert _matrix.dtype == np.dtype(np.int64)
    send_connection.send_bytes(_valid_payload(job_json))


def _never_returns(_send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    while True:
        time.sleep(0.05)


def _partial_frame_then_hangs(
    send_connection: Any,
    _job_json: bytes,
    _matrix: np.ndarray,
) -> None:
    os.write(send_connection.fileno(), struct.pack("!i", 64))
    os.write(send_connection.fileno(), b"{")
    while True:
        time.sleep(0.05)


def _crashes(_send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    os._exit(7)


def _oversized(send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    send_connection.send_bytes(b"x" * (4 * 1024 * 1024 + 1))


def _malformed(send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    send_connection.send_bytes(b"{")


def _no_payload(_send_connection: Any, _job_json: bytes, _matrix: np.ndarray) -> None:
    return


def _noncanonical(send_connection: Any, job_json: bytes, _matrix: np.ndarray) -> None:
    send_connection.send_bytes(
        json.dumps(json.loads(_valid_payload(job_json)), indent=2).encode("utf-8")
    )


def _multiple(send_connection: Any, job_json: bytes, _matrix: np.ndarray) -> None:
    payload = _valid_payload(job_json)
    send_connection.send_bytes(payload)
    send_connection.send_bytes(payload)


def _mutated_payload(
    send_connection: Any,
    job_json: bytes,
    _matrix: np.ndarray,
    *,
    mutation: str,
) -> None:
    payload = json.loads(_valid_payload(job_json))
    if mutation == "table":
        payload["table_id"] = "table_" + "f" * 64
    elif mutation == "config":
        payload["config_sha256"] = "f" * 64
    elif mutation == "background":
        payload["background_knowledge_sha256"] = "f" * 64
    elif mutation == "run_kind":
        payload["run_kind"] = PAGRunKind.OBSERVATIONAL_BOOTSTRAP.value
    elif mutation == "bk_edge":
        payload["edges"] = [
            PAGEdgeRecord(
                left="x.safety.sql_parameterization",
                right="y.secure_functional",
                left_mark=EndpointMark.ARROW,
                right_mark=EndpointMark.TAIL,
            )
        ]
    else:  # pragma: no cover - fixed test input
        raise AssertionError
    payload.pop("pag_id")
    forged = PAGRecord.from_content(**payload)
    send_connection.send_bytes(_canonical_json(forged.model_dump(mode="json")))


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
    return FCIDiscoveryConfig(min_independent_tasks=2)


def test_supervisor_runs_spawn_picklable_worker_and_revalidates_payload() -> None:
    from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner

    runner: FCIRunner = SpawnedFCIRunner(timeout_seconds=2.0, worker=_returns_valid)
    table = _table()
    pag = runner.run(
        _matrix(),
        table,
        build_background_knowledge(table),
        _config(),
        PAGRunKind.OBSERVATIONAL_REFERENCE,
    )

    assert pag.table_id == table.table_id
    assert pag.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE


def test_supervisor_terminates_a_hung_worker_without_leaking_children() -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    table = _table()
    baseline = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(SecAwareError, match="timed out") as caught:
        SpawnedFCIRunner(timeout_seconds=0.1, worker=_never_returns).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind.TIMEOUT.value,
    }
    assert time.monotonic() - started < 2.0
    assert {child.pid for child in multiprocessing.active_children()} <= baseline
    assert not any(
        thread.name == "secaware-fci-pipe-reader" and thread.is_alive()
        for thread in threading.enumerate()
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX Connection framing uses a byte-stream pipe")
def test_supervisor_times_out_on_a_partial_pipe_frame_without_blocking_parent() -> None:
    from secaware.discovery.fci_supervisor import SpawnedFCIRunner

    table = _table()
    started = time.monotonic()
    with pytest.raises(SecAwareError, match="timed out"):
        SpawnedFCIRunner(timeout_seconds=0.1, worker=_partial_frame_then_hangs).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert time.monotonic() - started < 2.0
    assert not any(
        thread.name == "secaware-fci-pipe-reader" and thread.is_alive()
        for thread in threading.enumerate()
    )


@pytest.mark.parametrize(
    ("worker", "expected_kind"),
    (
        (_crashes, "backend_failure"),
        (_oversized, "invalid_output"),
        (_malformed, "invalid_output"),
        (_no_payload, "backend_failure"),
        (_noncanonical, "invalid_output"),
        (_multiple, "invalid_output"),
    ),
)
def test_supervisor_safely_rejects_crash_oversize_malformed_or_multiple_payloads(
    worker: Any,
    expected_kind: str,
) -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    table = _table()
    with pytest.raises(SecAwareError) as caught:
        SpawnedFCIRunner(timeout_seconds=2.0, worker=worker).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind(expected_kind).value,
    }


def test_supervisor_propagates_parent_parse_memory_error_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import secaware.discovery.fci_supervisor as supervisor

    table = _table()
    injected = MemoryError("parent PAG parsing exhausted memory")
    baseline = {child.pid for child in multiprocessing.active_children()}

    def fail_parent_parse(*_args: Any, **_kwargs: Any) -> None:
        raise injected

    monkeypatch.setattr(supervisor.PAGRecord, "model_validate_json", fail_parent_parse)

    with pytest.raises(MemoryError) as caught:
        supervisor.SpawnedFCIRunner(timeout_seconds=2.0, worker=_returns_valid).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )

    assert caught.value is injected
    assert {child.pid for child in multiprocessing.active_children()} <= baseline
    assert not any(
        thread.name == "secaware-fci-pipe-reader" and thread.is_alive()
        for thread in threading.enumerate()
    )


@pytest.mark.parametrize("mutation", ("table", "config", "background", "run_kind", "bk_edge"))
def test_supervisor_parent_rejects_child_provenance_mutations(mutation: str) -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    table = _table()
    with pytest.raises(SecAwareError) as caught:
        SpawnedFCIRunner(
            timeout_seconds=2.0,
            worker=partial(_mutated_payload, mutation=mutation),
        ).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind.INVALID_OUTPUT.value,
    }


def test_supervisor_rejects_non_spawn_picklable_injected_worker_before_launch() -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    worker = lambda *_args: None  # noqa: E731
    table = _table()
    with pytest.raises(SecAwareError) as caught:
        SpawnedFCIRunner(timeout_seconds=2.0, worker=worker).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind.INVALID_INPUT.value,
    }


def test_production_supervisor_selects_real_pinned_worker() -> None:
    from secaware.discovery.fci_supervisor import SpawnedFCIRunner

    table = _table()
    pag = SpawnedFCIRunner(timeout_seconds=10.0).run(
        _matrix(),
        table,
        build_background_knowledge(table),
        _config(),
        PAGRunKind.OBSERVATIONAL_REFERENCE,
    )

    assert pag.backend_version == "0.1.4.7"


def test_supervisor_timeout_override_is_part_of_effective_config_provenance() -> None:
    from secaware.discovery.fci_supervisor import SpawnedFCIRunner

    table = _table()
    original = _config()
    effective = FCIDiscoveryConfig.model_validate(
        {**original.model_dump(mode="json"), "timeout_seconds": 2.0}
    )
    pag = SpawnedFCIRunner(timeout_seconds=2.0, worker=_returns_valid).run(
        _matrix(),
        table,
        build_background_knowledge(table),
        original,
        PAGRunKind.OBSERVATIONAL_REFERENCE,
    )

    assert pag.config_sha256 == canonical_sha256(effective.model_dump(mode="json"))
    assert pag.config_sha256 != canonical_sha256(original.model_dump(mode="json"))


@pytest.mark.parametrize("timeout", (0.0, -1.0, float("nan"), float("inf")))
def test_supervisor_rejects_nonfinite_or_out_of_bounds_timeout_override(
    timeout: float,
) -> None:
    from secaware.discovery.fci_supervisor import SpawnedFCIRunner

    with pytest.raises(SecAwareError):
        SpawnedFCIRunner(timeout_seconds=timeout)


def test_supervisor_rejects_rfci_run_kind_before_spawn() -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    table = _table()
    with pytest.raises(SecAwareError) as caught:
        SpawnedFCIRunner(timeout_seconds=2.0, worker=_returns_valid).run(
            _matrix(),
            table,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.RFCI_SENSITIVITY,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind.INVALID_INPUT.value,
    }


def test_supervisor_rejects_tampered_parent_inputs_before_spawn() -> None:
    from secaware.discovery.fci_supervisor import FCISupervisorFailureKind, SpawnedFCIRunner

    table = _table()
    tampered = deepcopy(table)
    object.__setattr__(tampered, "row_count", 5)
    with pytest.raises(SecAwareError) as caught:
        SpawnedFCIRunner(timeout_seconds=2.0, worker=_returns_valid).run(
            _matrix(),
            tampered,
            build_background_knowledge(table),
            _config(),
            PAGRunKind.OBSERVATIONAL_REFERENCE,
        )
    assert caught.value.details == {
        "failure_kind": FCISupervisorFailureKind.INVALID_INPUT.value,
    }

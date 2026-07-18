"""Spawn-based bounded supervision for all FCI runs."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
import json
import multiprocessing
from multiprocessing.connection import Connection
from multiprocessing.reduction import ForkingPickler
from queue import Empty, Queue
import threading
import time
from typing import Protocol

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.causal_learn_backend import (
    run_causal_learn_fci,
    validate_fci_inputs,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
)


_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_JOB_BYTES = 1024 * 1024
_MAX_WORKER_BYTES = 64 * 1024
_MAX_CONTROL_FRAME_BYTES = 64
_POLL_INTERVAL_SECONDS = 0.01
_JOIN_GRACE_SECONDS = 0.5
_SPAWN_STARTUP_TIMEOUT_SECONDS = 30.0
_READY_FRAME = b"secaware-fci-ready-v1"
_GO_FRAME = b"secaware-fci-go-v1"

_Worker = Callable[[Connection, bytes, np.ndarray], None]


class FCISupervisorFailureKind(str, Enum):
    TIMEOUT = "timeout"
    BACKEND_FAILURE = "backend_failure"
    INVALID_OUTPUT = "invalid_output"
    INVALID_INPUT = "invalid_input"


class FCIRunner(Protocol):
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        raise NotImplementedError


def _supervisor_error(
    message: str = "FCI worker failed validation",
    *,
    failure_kind: FCISupervisorFailureKind = FCISupervisorFailureKind.INVALID_OUTPUT,
) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery.supervisor",
        message=message,
        details={"failure_kind": failure_kind.value},
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _decode_job(
    job_json: bytes,
) -> tuple[CausalTableRecord, BackgroundKnowledgeRecord, FCIDiscoveryConfig, PAGRunKind]:
    if type(job_json) is not bytes or not 0 < len(job_json) <= _MAX_JOB_BYTES:
        raise ValueError
    raw = json.loads(job_json.decode("utf-8"))
    if type(raw) is not dict or set(raw) != {"table", "knowledge", "config", "run_kind"}:
        raise ValueError
    if _canonical_json(raw) != job_json:
        raise ValueError
    return (
        CausalTableRecord.model_validate(raw["table"]),
        BackgroundKnowledgeRecord.model_validate(raw["knowledge"]),
        FCIDiscoveryConfig.model_validate(raw["config"]),
        PAGRunKind(raw["run_kind"]),
    )


def _causal_learn_fci_worker(
    send_connection: Connection,
    job_json: bytes,
    matrix: np.ndarray,
) -> None:
    """Real production worker. Selection is code-owned, never job-owned."""
    try:
        table, knowledge, config, run_kind = _decode_job(job_json)
        pag = run_causal_learn_fci(matrix, table, knowledge, config, run_kind)
        payload = _canonical_json(pag.model_dump(mode="json"))
        if len(payload) > _MAX_PAYLOAD_BYTES:
            return
        send_connection.send_bytes(payload)
    except BaseException:
        return
    finally:
        try:
            send_connection.close()
        except BaseException:
            pass


def _bootstrap_fci_worker(
    control_connection: Connection,
    send_connection: Connection,
    worker_pickle: bytes,
    job_json: bytes,
    matrix: np.ndarray,
) -> None:
    """Restore one parent-selected worker before starting its execution budget."""
    try:
        if type(worker_pickle) is not bytes or not 0 < len(worker_pickle) <= _MAX_WORKER_BYTES:
            return
        worker = ForkingPickler.loads(worker_pickle)
        if not callable(worker):
            return
        control_connection.send_bytes(_READY_FRAME)
        if control_connection.recv_bytes(_MAX_CONTROL_FRAME_BYTES) != _GO_FRAME:
            return
        control_connection.close()
        worker(send_connection, job_json, matrix)
    except BaseException:
        return
    finally:
        for connection in (control_connection, send_connection):
            try:
                connection.close()
            except BaseException:
                pass


def _terminate_and_join(process: multiprocessing.Process) -> None:
    try:
        if process.is_alive():
            process.terminate()
    except BaseException:
        pass
    try:
        process.join(_JOIN_GRACE_SECONDS)
    except BaseException:
        pass
    try:
        if process.is_alive():
            process.kill()
            process.join(_JOIN_GRACE_SECONDS)
    except BaseException:
        pass


def _read_pipe_messages(
    receive_connection: Connection,
    events: Queue[tuple[str, bytes | None]],
) -> None:
    """Read at most two framed payloads without blocking the deadline owner."""
    try:
        for _index in range(2):
            payload = receive_connection.recv_bytes(_MAX_PAYLOAD_BYTES)
            events.put_nowait(("payload", payload))
    except EOFError:
        events.put_nowait(("eof", None))
    except BaseException:
        try:
            events.put_nowait(("error", None))
        except BaseException:
            pass


class SpawnedFCIRunner:
    """Run a validated FCI job in a fresh bounded spawn child."""

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        worker: _Worker | None = None,
    ) -> None:
        if timeout_seconds is not None and (
            type(timeout_seconds) not in {int, float}
            or type(timeout_seconds) is bool
            or not 0.0 < float(timeout_seconds) <= 3600.0
        ):
            raise _supervisor_error(failure_kind=FCISupervisorFailureKind.INVALID_INPUT)
        self._timeout_seconds = None if timeout_seconds is None else float(timeout_seconds)
        self._worker = _causal_learn_fci_worker if worker is None else worker

    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        """Run FCI after the caller authenticates matrix rows to ``table``.

        This boundary validates shape and categorical bounds only. The Task 5
        draw/run wrapper remains responsible for matrix-content provenance.
        """
        process: multiprocessing.Process | None = None
        receive_connection: Connection | None = None
        send_connection: Connection | None = None
        control_connection: Connection | None = None
        child_control_connection: Connection | None = None
        reader: threading.Thread | None = None
        timed_out = False
        invalid_transport = False
        payloads: list[bytes] = []
        failure_kind = FCISupervisorFailureKind.INVALID_INPUT
        try:
            base_config = FCIDiscoveryConfig.model_validate(config)
            effective_config = base_config
            if self._timeout_seconds is not None:
                effective_config = FCIDiscoveryConfig.model_validate(
                    {
                        **base_config.model_dump(mode="json"),
                        "timeout_seconds": self._timeout_seconds,
                    }
                )
            (
                checked_matrix,
                checked_table,
                checked_knowledge,
                checked_config,
                checked_run_kind,
            ) = validate_fci_inputs(
                matrix,
                table,
                knowledge,
                effective_config,
                run_kind,
            )
            timeout = checked_config.timeout_seconds
            job_json = _canonical_json(
                {
                    "table": checked_table.model_dump(mode="json"),
                    "knowledge": checked_knowledge.model_dump(mode="json"),
                    "config": checked_config.model_dump(mode="json"),
                    "run_kind": checked_run_kind.value,
                }
            )
            if len(job_json) > _MAX_JOB_BYTES:
                raise ValueError
            # Validate the exact bytes the child will receive and fail before spawn
            # when a test-injected worker cannot satisfy spawn pickling semantics.
            _decode_job(job_json)
            worker_pickle = bytes(ForkingPickler.dumps(self._worker))
            if not 0 < len(worker_pickle) <= _MAX_WORKER_BYTES:
                raise ValueError
            context = multiprocessing.get_context("spawn")
            receive_connection, send_connection = context.Pipe(duplex=False)
            control_connection, child_control_connection = context.Pipe(duplex=True)
            process = context.Process(
                target=_bootstrap_fci_worker,
                args=(
                    child_control_connection,
                    send_connection,
                    worker_pickle,
                    job_json,
                    checked_matrix,
                ),
            )
            startup_deadline = time.monotonic() + _SPAWN_STARTUP_TIMEOUT_SECONDS
            failure_kind = FCISupervisorFailureKind.BACKEND_FAILURE
            process.start()
            send_connection.close()
            send_connection = None
            child_control_connection.close()
            child_control_connection = None

            ready = False
            invalid_control = False
            while True:
                remaining = startup_deadline - time.monotonic()
                if remaining <= 0:
                    raise _supervisor_error(
                        "FCI worker startup timed out",
                        failure_kind=FCISupervisorFailureKind.TIMEOUT,
                    )
                if control_connection.poll(min(_POLL_INTERVAL_SECONDS, remaining)):
                    try:
                        control_frame = control_connection.recv_bytes(_MAX_CONTROL_FRAME_BYTES)
                        if control_frame == _READY_FRAME:
                            ready = True
                        else:
                            invalid_control = True
                    except EOFError:
                        pass
                    except OSError:
                        invalid_control = True
                    break
                if not process.is_alive():
                    process.join(_JOIN_GRACE_SECONDS)
                    break
            if invalid_control:
                raise _supervisor_error(
                    "FCI worker startup control failed validation",
                    failure_kind=FCISupervisorFailureKind.INVALID_OUTPUT,
                )
            if not ready:
                raise _supervisor_error(
                    failure_kind=FCISupervisorFailureKind.BACKEND_FAILURE,
                )

            events: Queue[tuple[str, bytes | None]] = Queue(maxsize=3)
            reader = threading.Thread(
                target=_read_pipe_messages,
                args=(receive_connection, events),
                name="secaware-fci-pipe-reader",
                daemon=True,
            )
            reader.start()
            deadline = time.monotonic() + timeout
            control_connection.send_bytes(_GO_FRAME)
            control_connection.close()
            control_connection = None

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    event, payload = events.get(timeout=min(_POLL_INTERVAL_SECONDS, remaining))
                except Empty:
                    event, payload = "", None
                if event == "payload":
                    if payload is None:
                        invalid_transport = True
                        break
                    payloads.append(payload)
                    if len(payloads) > 1:
                        invalid_transport = True
                        break
                elif event == "error":
                    invalid_transport = True
                    break
                if not process.is_alive():
                    process.join(_JOIN_GRACE_SECONDS)
                    if reader is not None and not reader.is_alive() and events.empty():
                        break

            if timed_out:
                raise _supervisor_error(
                    "FCI worker timed out",
                    failure_kind=FCISupervisorFailureKind.TIMEOUT,
                )
            if invalid_transport or len(payloads) > 1:
                raise _supervisor_error(
                    failure_kind=FCISupervisorFailureKind.INVALID_OUTPUT,
                )
            if process.exitcode != 0 or len(payloads) != 1:
                raise _supervisor_error(
                    failure_kind=FCISupervisorFailureKind.BACKEND_FAILURE,
                )
            payload = payloads[0]
            failure_kind = FCISupervisorFailureKind.INVALID_OUTPUT
            record = PAGRecord.model_validate_json(payload)
            if _canonical_json(record.model_dump(mode="json")) != payload:
                raise _supervisor_error(
                    "FCI worker returned noncanonical output",
                    failure_kind=FCISupervisorFailureKind.INVALID_OUTPUT,
                )
            expected_variables = tuple(item.variable_id for item in checked_table.variables)
            if (
                record.table_id != checked_table.table_id
                or record.backend != checked_config.backend
                or record.backend_version != checked_config.backend_version
                or record.ci_test != checked_config.ci_test
                or record.config_sha256 != canonical_sha256(checked_config.model_dump(mode="json"))
                or record.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
                or record.variable_ids != expected_variables
                or record.run_kind is not checked_run_kind
            ):
                raise _supervisor_error(
                    "FCI worker provenance failed validation",
                    failure_kind=FCISupervisorFailureKind.INVALID_OUTPUT,
                )
            try:
                validate_pag_against_background(record, checked_knowledge)
            except SecAwareError:
                raise _supervisor_error(
                    "FCI worker violated background knowledge",
                    failure_kind=FCISupervisorFailureKind.INVALID_OUTPUT,
                ) from None
            return record
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError as error:
            if error.stage == "causal.discovery.supervisor" and error.details.get(
                "failure_kind"
            ) in {item.value for item in FCISupervisorFailureKind}:
                raise
            raise _supervisor_error(failure_kind=failure_kind) from None
        except BaseException:
            raise _supervisor_error(failure_kind=failure_kind) from None
        finally:
            if process is not None:
                _terminate_and_join(process)
            for connection in (
                receive_connection,
                send_connection,
                control_connection,
                child_control_connection,
            ):
                if connection is not None:
                    try:
                        connection.close()
                    except BaseException:
                        pass
            if reader is not None:
                try:
                    reader.join(_JOIN_GRACE_SECONDS)
                except BaseException:
                    pass
            if process is not None:
                try:
                    process.close()
                except BaseException:
                    pass
            matrix = None  # type: ignore[assignment]
            table = None  # type: ignore[assignment]
            knowledge = None  # type: ignore[assignment]
            config = None  # type: ignore[assignment]


__all__ = ["FCIRunner", "FCISupervisorFailureKind", "SpawnedFCIRunner"]

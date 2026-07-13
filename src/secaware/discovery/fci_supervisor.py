"""Spawn-based bounded supervision for all FCI runs."""

from __future__ import annotations

from collections.abc import Callable
import json
import multiprocessing
from multiprocessing.connection import Connection
from multiprocessing.reduction import ForkingPickler
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
_POLL_INTERVAL_SECONDS = 0.01
_JOIN_GRACE_SECONDS = 0.5

_Worker = Callable[[Connection, bytes, np.ndarray], None]


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


def _supervisor_error(message: str = "FCI worker failed validation") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery.supervisor",
        message=message,
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
            raise _supervisor_error()
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
        process: multiprocessing.Process | None = None
        receive_connection: Connection | None = None
        send_connection: Connection | None = None
        timed_out = False
        invalid_transport = False
        pipe_eof = False
        payloads: list[bytes] = []
        try:
            (
                checked_matrix,
                checked_table,
                checked_knowledge,
                checked_config,
                checked_run_kind,
            ) = validate_fci_inputs(matrix, table, knowledge, config, run_kind)
            timeout = (
                checked_config.timeout_seconds
                if self._timeout_seconds is None
                else self._timeout_seconds
            )
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
            ForkingPickler.dumps(self._worker)
            context = multiprocessing.get_context("spawn")
            receive_connection, send_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=self._worker,
                args=(send_connection, job_json, checked_matrix),
            )
            deadline = time.monotonic() + timeout
            process.start()
            send_connection.close()
            send_connection = None

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    has_payload = not pipe_eof and receive_connection.poll(
                        min(_POLL_INTERVAL_SECONDS, remaining)
                    )
                except OSError:
                    has_payload = False
                    pipe_eof = True
                if pipe_eof and process.is_alive():
                    time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))
                if has_payload:
                    try:
                        payloads.append(receive_connection.recv_bytes(_MAX_PAYLOAD_BYTES))
                    except EOFError:
                        pipe_eof = True
                    except OSError:
                        invalid_transport = True
                        break
                    if len(payloads) > 1:
                        invalid_transport = True
                        break
                if not process.is_alive():
                    process.join(_JOIN_GRACE_SECONDS)
                    # Drain messages queued just before child exit. A second message
                    # is always a protocol violation.
                    while not pipe_eof:
                        try:
                            queued = receive_connection.poll(0)
                        except OSError:
                            pipe_eof = True
                            break
                        if not queued:
                            break
                        try:
                            payloads.append(
                                receive_connection.recv_bytes(_MAX_PAYLOAD_BYTES)
                            )
                        except EOFError:
                            pipe_eof = True
                            break
                        except OSError:
                            invalid_transport = True
                            break
                        if len(payloads) > 1:
                            invalid_transport = True
                            break
                    break

            if timed_out:
                raise _supervisor_error("FCI worker timed out")
            if invalid_transport or process.exitcode != 0 or len(payloads) != 1:
                raise _supervisor_error()
            payload = payloads[0]
            record = PAGRecord.model_validate_json(payload)
            if _canonical_json(record.model_dump(mode="json")) != payload:
                raise _supervisor_error("FCI worker returned noncanonical output")
            expected_variables = tuple(item.variable_id for item in checked_table.variables)
            if (
                record.table_id != checked_table.table_id
                or record.backend != checked_config.backend
                or record.backend_version != checked_config.backend_version
                or record.ci_test != checked_config.ci_test
                or record.config_sha256
                != canonical_sha256(checked_config.model_dump(mode="json"))
                or record.background_knowledge_sha256
                != checked_knowledge.knowledge_sha256
                or record.variable_ids != expected_variables
                or record.run_kind is not checked_run_kind
            ):
                raise _supervisor_error("FCI worker provenance failed validation")
            try:
                validate_pag_against_background(record, checked_knowledge)
            except SecAwareError:
                raise _supervisor_error("FCI worker violated background knowledge") from None
            return record
        except (KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except BaseException:
            raise _supervisor_error() from None
        finally:
            if process is not None:
                _terminate_and_join(process)
                try:
                    process.close()
                except BaseException:
                    pass
            for connection in (receive_connection, send_connection):
                if connection is not None:
                    try:
                        connection.close()
                    except BaseException:
                        pass
            matrix = None  # type: ignore[assignment]
            table = None  # type: ignore[assignment]
            knowledge = None  # type: ignore[assignment]
            config = None  # type: ignore[assignment]


__all__ = ["FCIRunner", "SpawnedFCIRunner"]

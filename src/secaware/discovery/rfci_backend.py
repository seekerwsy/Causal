"""Pinned optional py-tetrad RFCI sensitivity behind a Java capability gate."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import importlib.metadata
import importlib.util
import json
import multiprocessing
from multiprocessing.connection import Connection
from multiprocessing.reduction import ForkingPickler
import os
from pathlib import Path
import platform
from queue import Empty, Queue
import re
import stat
import subprocess
import threading
import time
from typing import Any

import numpy as np
import pandas as pd

from secaware.causal.background import (
    to_causal_learn_background,
    validate_pag_against_background,
)
from secaware.causal.pag import pag_from_causal_learn
from secaware.config import FCIDiscoveryConfig, RFCIConfig
from secaware.discovery.fci_supervisor import (
    _JOIN_GRACE_SECONDS,
    _MAX_JOB_BYTES,
    _MAX_PAYLOAD_BYTES,
    _POLL_INTERVAL_SECONDS,
    _canonical_json,
    _read_pipe_messages,
    _terminate_and_join,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.outcomes import RFCICapabilityRecord


PY_TETRAD_COMMIT = "a30707264aa4363a23ac5f136a70bbdd62212f07"
JPYPE_VERSION = "1.7.1"
MINIMUM_JAVA_MAJOR = 21
TETRAD_JAR_SHA256 = "3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4"
RFCI_BACKEND = "py_tetrad_rfci_v1"

_PY_TETRAD_URL = "https://github.com/cmu-phil/py-tetrad.git"
_MAX_JAR_BYTES = 256 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_JAVA_VERSION_OUTPUT_CHARS = 16 * 1024
_JAVA_PROBE_TIMEOUT_SECONDS = 5.0
_PYTHON_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
_JAVA_VERSION = re.compile(r'(?:openjdk|java)\s+version\s+"([0-9]+)(?:\.([0-9]+))?', re.I)

_Worker = Callable[[Connection, bytes, np.ndarray], None]
_SearchFactory = Callable[[pd.DataFrame], Any]


def _rfci_error(message: str = "RFCI worker failed validation") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery.rfci",
        message=message,
    )


def _runtime_python_version() -> str:
    return platform.python_version()


def _python_supports_rfci(version: str) -> bool:
    if _PYTHON_VERSION.fullmatch(version) is None:
        return False
    parts = tuple(int(item) for item in version.split("."))
    return parts[:2] >= (3, 12)


def _sha256_file(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or not 0 < file_stat.st_size <= _MAX_JAR_BYTES:
                return None
            digest = hashlib.sha256()
            total = 0
            while chunk := handle.read(_HASH_CHUNK_BYTES):
                total += len(chunk)
                if total > file_stat.st_size or total > _MAX_JAR_BYTES:
                    return None
                digest.update(chunk)
            if total != file_stat.st_size:
                return None
        return digest.hexdigest()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


def _inspect_py_tetrad_installation() -> tuple[str | None, str | None]:
    """Read VCS provenance and hash the installed JAR without importing py-tetrad."""
    distribution = importlib.metadata.distribution("py-tetrad")
    direct_url_text = distribution.read_text("direct_url.json")
    commit: str | None = None
    if direct_url_text is not None and len(direct_url_text) <= 64 * 1024:
        direct_url = json.loads(direct_url_text)
        if type(direct_url) is dict and direct_url.get("url") == _PY_TETRAD_URL:
            vcs_info = direct_url.get("vcs_info")
            if type(vcs_info) is dict and vcs_info.get("vcs") == "git":
                candidate = vcs_info.get("commit_id")
                if type(candidate) is str and re.fullmatch(r"[0-9a-f]{40}", candidate):
                    commit = candidate

    files = distribution.files
    if files is None:
        return commit, None
    matches = tuple(
        item
        for item in files
        if str(item).replace("\\", "/") == "pytetrad/resources/tetrad-current.jar"
    )
    if len(matches) != 1:
        return commit, None
    distribution_root = Path(distribution.locate_file("")).resolve()
    jar_path = Path(distribution.locate_file(matches[0])).resolve()
    try:
        jar_path.relative_to(distribution_root)
    except ValueError:
        return commit, None
    return commit, _sha256_file(jar_path)


def _detect_java_major() -> int | None:
    """Probe a bounded ``java -version`` process without importing or starting JPype."""
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            timeout=_JAVA_PROBE_TIMEOUT_SECONDS,
            creationflags=creationflags,
        )
        output = completed.stdout + completed.stderr
        if completed.returncode != 0 or len(output) > _MAX_JAVA_VERSION_OUTPUT_CHARS:
            return None
        match = _JAVA_VERSION.search(output)
        if match is None:
            return None
        major = int(match.group(1))
        if major == 1 and match.group(2) is not None:
            major = int(match.group(2))
        return major if 1 <= major <= 999 else None
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None


def _capability_record(
    *,
    python_version: str,
    status: str,
    reason_code: str | None,
    java_major: int | None = None,
    jpype_version: str | None = None,
    py_tetrad_commit: str | None = None,
    tetrad_jar_sha256: str | None = None,
) -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=status == "available",
        status=status,
        requires_java=True,
        python_version=python_version,
        java_major=java_major,
        jpype_version=jpype_version,
        py_tetrad_commit=py_tetrad_commit,
        tetrad_jar_sha256=tetrad_jar_sha256,
        reason_code=reason_code,
    )


def detect_rfci_capability(config: RFCIConfig | None = None) -> RFCICapabilityRecord:
    """Return disabled/available/unavailable evidence; optional absence never raises."""
    python_version = _runtime_python_version()
    if _PYTHON_VERSION.fullmatch(python_version) is None:
        python_version = "0.0"
    try:
        checked = RFCIConfig(enabled=True) if config is None else RFCIConfig.model_validate(config)
        if not checked.enabled:
            return _capability_record(
                python_version=python_version,
                status="disabled",
                reason_code="disabled",
            )
        if not _python_supports_rfci(python_version):
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="python_version_unsupported",
            )
        if importlib.util.find_spec("jpype") is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="jpype_missing",
            )
        jpype_version = importlib.metadata.version("JPype1")
        if jpype_version != checked.jpype_version:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="jpype_version_mismatch",
                jpype_version=jpype_version,
            )
        if importlib.util.find_spec("pytetrad") is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="py_tetrad_missing",
                jpype_version=jpype_version,
            )
        commit, jar_sha256 = _inspect_py_tetrad_installation()
        if commit != checked.py_tetrad_commit:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="py_tetrad_commit_mismatch",
                jpype_version=jpype_version,
                py_tetrad_commit=commit,
                tetrad_jar_sha256=jar_sha256,
            )
        if jar_sha256 is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="tetrad_jar_missing",
                jpype_version=jpype_version,
                py_tetrad_commit=commit,
            )
        if jar_sha256 != TETRAD_JAR_SHA256:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="tetrad_jar_hash_mismatch",
                jpype_version=jpype_version,
                py_tetrad_commit=commit,
                tetrad_jar_sha256=jar_sha256,
            )
        java_major = _detect_java_major()
        if java_major is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="java_missing",
                jpype_version=jpype_version,
                py_tetrad_commit=commit,
                tetrad_jar_sha256=jar_sha256,
            )
        if java_major < checked.minimum_java_major:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="java_version_unsupported",
                java_major=java_major,
                jpype_version=jpype_version,
                py_tetrad_commit=commit,
                tetrad_jar_sha256=jar_sha256,
            )
        return _capability_record(
            python_version=python_version,
            status="available",
            reason_code=None,
            java_major=java_major,
            jpype_version=jpype_version,
            py_tetrad_commit=commit,
            tetrad_jar_sha256=jar_sha256,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return _capability_record(
            python_version=python_version,
            status="unavailable",
            reason_code="capability_probe_failed",
        )


def expanded_forbidden_directions(
    knowledge: BackgroundKnowledgeRecord,
) -> tuple[tuple[str, str], ...]:
    """Expand forbidden adjacencies to both directions without adding requirements."""
    try:
        checked = BackgroundKnowledgeRecord.model_validate(knowledge)
        to_causal_learn_background(checked)
        expanded = {
            *checked.forbidden_directions,
            *(
                direction
                for left, right in checked.forbidden_adjacencies
                for direction in ((left, right), (right, left))
            ),
        }
        return tuple(sorted(expanded))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error() from None


def _validated_rfci_inputs(
    table: CausalTableRecord,
    matrix: np.ndarray,
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
) -> tuple[CausalTableRecord, np.ndarray, BackgroundKnowledgeRecord, RFCIConfig]:
    checked_table = CausalTableRecord.model_validate(table)
    checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
    checked_config = RFCIConfig.model_validate(config)
    if not checked_config.enabled or type(matrix) is not np.ndarray:
        raise ValueError
    expected_variables = tuple(item.variable_id for item in checked_table.variables)
    knowledge_variables = tuple(
        sorted(
            {
                *(variable_id for variable_id, _tier in checked_knowledge.tiers),
                *checked_knowledge.unconstrained_variable_ids,
            }
        )
    )
    if (
        matrix.dtype != np.dtype(np.int64)
        or matrix.ndim != 2
        or matrix.shape != (checked_table.row_count, len(expected_variables))
        or checked_knowledge.table_id != checked_table.table_id
        or knowledge_variables != expected_variables
        or checked_knowledge.required_directions
    ):
        raise ValueError
    to_causal_learn_background(checked_knowledge)
    for column, variable in enumerate(checked_table.variables):
        values = matrix[:, column]
        if np.any(values < 0) or np.any(values >= len(variable.states)):
            raise ValueError
    checked_matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    checked_matrix.flags.writeable = False
    return checked_table, checked_matrix, checked_knowledge, checked_config


def _run_rfci_adapter(
    table: CausalTableRecord,
    matrix: np.ndarray,
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
    search_factory: _SearchFactory,
) -> PAGRecord:
    checked_matrix: np.ndarray | None = None
    frame: pd.DataFrame | None = None
    search: Any = None
    try:
        checked_table, checked_matrix, checked_knowledge, checked_config = _validated_rfci_inputs(
            table, matrix, knowledge, config
        )
        variable_ids = tuple(item.variable_id for item in checked_table.variables)
        frame = pd.DataFrame(checked_matrix, columns=variable_ids, copy=True)
        search = search_factory(frame)
        search.use_g_square(alpha=checked_config.alpha)
        for variable_id, tier in checked_knowledge.tiers:
            search.add_to_tier(tier, variable_id)
        for source, target in expanded_forbidden_directions(checked_knowledge):
            search.set_forbidden(source, target)
        search.run_rfci(
            depth=checked_config.depth,
            stable_fas=True,
            max_disc_path_length=checked_config.max_discriminating_path_length,
            complete_rule_set_used=True,
        )
        backend_graph = search.get_causal_learn()
        codec_config = FCIDiscoveryConfig(
            alpha=checked_config.alpha,
            depth=checked_config.depth,
            max_path_length=checked_config.max_discriminating_path_length,
            min_independent_tasks=2,
        )
        codec_pag = pag_from_causal_learn(
            backend_graph,
            checked_table,
            checked_knowledge,
            codec_config,
            PAGRunKind.RFCI_SENSITIVITY,
        )
        pag = PAGRecord.from_content(
            run_kind=PAGRunKind.RFCI_SENSITIVITY,
            table_id=checked_table.table_id,
            backend=RFCI_BACKEND,
            backend_version=checked_config.py_tetrad_commit,
            ci_test="gsq",
            config_sha256=canonical_sha256(checked_config.model_dump(mode="json")),
            background_knowledge_sha256=checked_knowledge.knowledge_sha256,
            variable_ids=variable_ids,
            edges=codec_pag.edges,
        )
        validate_pag_against_background(pag, checked_knowledge)
        return pag
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("py-tetrad RFCI backend failed validation") from None
    finally:
        search = None
        frame = None
        checked_matrix = None
        table = None  # type: ignore[assignment]
        matrix = None  # type: ignore[assignment]
        knowledge = None  # type: ignore[assignment]
        config = None  # type: ignore[assignment]


def _validate_available_capability(
    capability: RFCICapabilityRecord,
    config: RFCIConfig,
) -> RFCICapabilityRecord:
    checked = RFCICapabilityRecord.model_validate(capability)
    if (
        not checked.available
        or checked.status != "available"
        or checked.reason_code is not None
        or not _python_supports_rfci(checked.python_version)
        or checked.java_major is None
        or checked.java_major < config.minimum_java_major
        or checked.jpype_version != config.jpype_version
        or checked.py_tetrad_commit != config.py_tetrad_commit
        or checked.tetrad_jar_sha256 != TETRAD_JAR_SHA256
    ):
        raise ValueError
    return checked


def _decode_job(
    job_json: bytes,
) -> tuple[CausalTableRecord, BackgroundKnowledgeRecord, RFCIConfig, RFCICapabilityRecord]:
    if type(job_json) is not bytes or not 0 < len(job_json) <= _MAX_JOB_BYTES:
        raise ValueError
    raw = json.loads(job_json.decode("utf-8"))
    if type(raw) is not dict or set(raw) != {"table", "knowledge", "config", "capability"}:
        raise ValueError
    if _canonical_json(raw) != job_json:
        raise ValueError
    table = CausalTableRecord.model_validate(raw["table"])
    knowledge = BackgroundKnowledgeRecord.model_validate(raw["knowledge"])
    config = RFCIConfig.model_validate(raw["config"])
    capability = RFCICapabilityRecord.model_validate(raw["capability"])
    return table, knowledge, config, _validate_available_capability(capability, config)


def _py_tetrad_rfci_worker(
    send_connection: Connection,
    job_json: bytes,
    matrix: np.ndarray,
) -> None:
    """Production worker: validate installed capability before optional imports/JVM startup."""
    try:
        table, knowledge, config, claimed_capability = _decode_job(job_json)
        _validated_rfci_inputs(table, matrix, knowledge, config)
        actual_capability = detect_rfci_capability(config)
        if actual_capability != claimed_capability:
            return

        import jpype  # noqa: F401, PLC0415
        from pytetrad.tools.TetradSearch import TetradSearch  # noqa: PLC0415

        pag = _run_rfci_adapter(table, matrix, knowledge, config, TetradSearch)
        payload = _canonical_json(pag.model_dump(mode="json"))
        if len(payload) <= _MAX_PAYLOAD_BYTES:
            send_connection.send_bytes(payload)
    except BaseException:
        return
    finally:
        try:
            send_connection.close()
        except BaseException:
            pass


class SpawnedRFCIRunner:
    """Run one capability-authenticated RFCI sensitivity job in a spawn child."""

    def __init__(
        self,
        *,
        capability: RFCICapabilityRecord,
        timeout_seconds: float | None = None,
        worker: _Worker | None = None,
    ) -> None:
        try:
            self._capability = _validate_available_capability(
                capability,
                RFCIConfig(enabled=True),
            )
            if timeout_seconds is not None and (
                type(timeout_seconds) not in {int, float}
                or type(timeout_seconds) is bool
                or not 0.0 < float(timeout_seconds) <= 3600.0
            ):
                raise ValueError
            self._timeout_seconds = None if timeout_seconds is None else float(timeout_seconds)
            self._worker = _py_tetrad_rfci_worker if worker is None else worker
            self._uses_production_worker = worker is None
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _rfci_error() from None

    def run(
        self,
        table: CausalTableRecord,
        matrix: np.ndarray,
        knowledge: BackgroundKnowledgeRecord,
        config: RFCIConfig,
    ) -> PAGRecord:
        process: multiprocessing.Process | None = None
        receive_connection: Connection | None = None
        send_connection: Connection | None = None
        reader: threading.Thread | None = None
        timed_out = False
        invalid_transport = False
        payloads: list[bytes] = []
        try:
            base_config = RFCIConfig.model_validate(config)
            effective_config = base_config
            if self._timeout_seconds is not None:
                effective_config = RFCIConfig.model_validate(
                    {
                        **base_config.model_dump(mode="json"),
                        "timeout_seconds": self._timeout_seconds,
                    }
                )
            checked_table, checked_matrix, checked_knowledge, checked_config = (
                _validated_rfci_inputs(table, matrix, knowledge, effective_config)
            )
            checked_capability = _validate_available_capability(
                self._capability,
                checked_config,
            )
            if self._uses_production_worker:
                actual_capability = detect_rfci_capability(checked_config)
                if actual_capability != checked_capability:
                    raise ValueError
            job_json = _canonical_json(
                {
                    "table": checked_table.model_dump(mode="json"),
                    "knowledge": checked_knowledge.model_dump(mode="json"),
                    "config": checked_config.model_dump(mode="json"),
                    "capability": checked_capability.model_dump(mode="json"),
                }
            )
            if len(job_json) > _MAX_JOB_BYTES:
                raise ValueError
            _decode_job(job_json)
            ForkingPickler.dumps(self._worker)
            context = multiprocessing.get_context("spawn")
            receive_connection, send_connection = context.Pipe(duplex=False)
            process = context.Process(
                target=self._worker,
                args=(send_connection, job_json, checked_matrix),
            )
            deadline = time.monotonic() + checked_config.timeout_seconds
            process.start()
            send_connection.close()
            send_connection = None
            events: Queue[tuple[str, bytes | None]] = Queue(maxsize=3)
            reader = threading.Thread(
                target=_read_pipe_messages,
                args=(receive_connection, events),
                name="secaware-rfci-pipe-reader",
                daemon=True,
            )
            reader.start()
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
                raise _rfci_error("RFCI worker timed out")
            if invalid_transport or process.exitcode != 0 or len(payloads) != 1:
                raise _rfci_error()
            payload = payloads[0]
            record = PAGRecord.model_validate_json(payload)
            if _canonical_json(record.model_dump(mode="json")) != payload:
                raise _rfci_error("RFCI worker returned noncanonical output")
            expected_variables = tuple(item.variable_id for item in checked_table.variables)
            if (
                record.table_id != checked_table.table_id
                or record.backend != RFCI_BACKEND
                or record.backend_version != checked_config.py_tetrad_commit
                or record.ci_test != "gsq"
                or record.config_sha256 != canonical_sha256(checked_config.model_dump(mode="json"))
                or record.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
                or record.variable_ids != expected_variables
                or record.run_kind is not PAGRunKind.RFCI_SENSITIVITY
            ):
                raise _rfci_error("RFCI worker provenance failed validation")
            try:
                validate_pag_against_background(record, checked_knowledge)
            except SecAwareError:
                raise _rfci_error("RFCI worker violated background knowledge") from None
            return record
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError as exc:
            if exc.stage == "causal.discovery.rfci":
                raise
            raise _rfci_error() from None
        except BaseException:
            raise _rfci_error() from None
        finally:
            if process is not None:
                _terminate_and_join(process)
            for connection in (receive_connection, send_connection):
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
            table = None  # type: ignore[assignment]
            matrix = None  # type: ignore[assignment]
            knowledge = None  # type: ignore[assignment]
            config = None  # type: ignore[assignment]


def run_rfci_sensitivity(
    table: CausalTableRecord,
    matrix: np.ndarray,
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
    tetrad_search_factory: _SearchFactory | None = None,
) -> PAGRecord | None:
    """Return an RFCI sensitivity PAG, or ``None`` when the optional gate is unavailable."""
    try:
        checked_config = RFCIConfig.model_validate(config)
        if not checked_config.enabled:
            return None
        if tetrad_search_factory is not None:
            return _run_rfci_adapter(
                table,
                matrix,
                knowledge,
                checked_config,
                tetrad_search_factory,
            )
        capability = detect_rfci_capability(checked_config)
        if not capability.available:
            return None
        return SpawnedRFCIRunner(capability=capability).run(
            table,
            matrix,
            knowledge,
            checked_config,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _rfci_error() from None


__all__ = [
    "JPYPE_VERSION",
    "MINIMUM_JAVA_MAJOR",
    "PY_TETRAD_COMMIT",
    "RFCI_BACKEND",
    "SpawnedRFCIRunner",
    "TETRAD_JAR_SHA256",
    "detect_rfci_capability",
    "expanded_forbidden_directions",
    "run_rfci_sensitivity",
]

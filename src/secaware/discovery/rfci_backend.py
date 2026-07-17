"""Pinned optional py-tetrad RFCI sensitivity behind a Java capability gate."""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Sequence
import base64
import csv
from enum import Enum
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import sysconfig
import tempfile
from typing import Any, Literal
import uuid

import numpy as np
import pandas as pd
from pydantic import ConfigDict, Field, StrictInt

from secaware.causal.background import (
    to_causal_learn_background,
    validate_pag_against_background,
)
from secaware.causal.jci import matrix_for_exact_rows as matrix_for_exact_jci_rows
from secaware.causal.pag import pag_from_causal_learn
from secaware.config import FCIDiscoveryConfig, RFCIConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.process_isolation import IsolatedProcessFailureKind, run_isolated_process
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
)
from secaware.schema.outcomes import (
    JCIObservationRecord,
    RFCICapabilityRecord,
    RFCISensitivityResult,
)
from secaware.schema.common import StrictModel


PY_TETRAD_COMMIT = "a30707264aa4363a23ac5f136a70bbdd62212f07"
JPYPE_VERSION = "1.7.1"
MINIMUM_JAVA_MAJOR = 21
TETRAD_JAR_SHA256 = "3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4"
RFCI_BACKEND = "py_tetrad_rfci_v1"

_PY_TETRAD_URL = "https://github.com/cmu-phil/py-tetrad.git"
_MAX_JAR_BYTES = 64 * 1024 * 1024
_MAX_DIRECT_URL_BYTES = 64 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_MAX_JAVA_VERSION_OUTPUT_CHARS = 16 * 1024
_JAVA_PROBE_TIMEOUT_SECONDS = 5.0
_MAX_DISTRIBUTION_ENTRIES = 10_000
_MAX_DISTRIBUTION_FILE_BYTES = 64 * 1024 * 1024
_MAX_DISTRIBUTION_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_RECORD_BYTES = 2 * 1024 * 1024
_MAX_JOB_BYTES = 1024 * 1024
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MATRIX_DTYPE = "<i8"
_IMPORTABLE_SUFFIXES = frozenset({".py", ".pyc", ".pyd", ".so", ".dll", ".dylib", ".jar"})
_PYTHON_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
_JAVA_VERSION = re.compile(r'(?:openjdk|java)\s+version\s+"([0-9]+)(?:\.([0-9]+))?', re.I)

_SearchFactory = Callable[[pd.DataFrame], Any]


class RFCIBackendFailureKind(str, Enum):
    TIMEOUT = "timeout"
    BACKEND_FAILURE = "backend_failure"
    INVALID_OUTPUT = "invalid_output"
    INVALID_INPUT = "invalid_input"


class _DistributionEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    distribution_name: str
    module_name: str
    distribution_root: str
    package_root: str
    module_origin: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _JavaRuntimeEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    executable: str
    home: str
    jvm_library: str
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    jvm_library_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    major: StrictInt = Field(ge=1, le=999)


class _PyTetradInstallationEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    direct_url_path: str
    direct_url_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    direct_url_size: StrictInt = Field(ge=1, le=_MAX_DIRECT_URL_BYTES)
    jar_path: str
    jar_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    jar_size: StrictInt = Field(ge=1, le=_MAX_JAR_BYTES)


class _RFCICapabilityEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    capability: RFCICapabilityRecord
    jpype: _DistributionEvidence
    pytetrad: _DistributionEvidence
    java: _JavaRuntimeEvidence
    py_tetrad_installation: _PyTetradInstallationEvidence


class _MatrixTransportRecord(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str
    rows: StrictInt = Field(ge=2, le=100_000)
    columns: StrictInt = Field(ge=2, le=64)
    dtype: Literal["<i8"] = _MATRIX_DTYPE
    byte_length: StrictInt = Field(ge=32, le=100_000 * 64 * 8)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class _RFCIWorkerJob(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"]
    table: CausalTableRecord
    knowledge: BackgroundKnowledgeRecord
    config: RFCIConfig
    evidence: _RFCICapabilityEvidence
    matrix: _MatrixTransportRecord


def _rfci_error(
    message: str = "RFCI worker failed validation",
    *,
    failure_kind: RFCIBackendFailureKind = RFCIBackendFailureKind.INVALID_OUTPUT,
) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.discovery.rfci",
        message=message,
        details={"failure_kind": failure_kind.value},
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


def _decode_record_sha256(value: str) -> str:
    if not value.startswith("sha256="):
        raise ValueError
    encoded = value.removeprefix("sha256=")
    if not encoded or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        raise ValueError
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    digest = base64.urlsafe_b64decode(encoded + padding)
    if len(digest) != 32:
        raise ValueError
    return digest.hex()


def _path_has_symlink(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    current = root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _hash_regular_file(path: Path, *, limit: int) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or not 0 <= file_stat.st_size <= limit:
            raise ValueError
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit or total > file_stat.st_size:
                raise ValueError
            digest.update(chunk)
        if total != file_stat.st_size:
            raise ValueError
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _bounded_package_importables(
    package_root: Path,
    distribution_root: Path,
    authenticated_paths: set[str],
) -> set[str]:
    """Enumerate one package root without following links or accepting hidden code."""

    pending = [package_root]
    importables: set[str] = set()
    entry_count = 0
    importable_bytes = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > _MAX_DISTRIBUTION_ENTRIES or entry.is_symlink():
                    raise ValueError
                path = Path(entry.path)
                checked = path.resolve(strict=True)
                checked.relative_to(distribution_root)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(checked)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError
                if path.suffix.casefold() not in _IMPORTABLE_SUFFIXES:
                    continue
                file_stat = entry.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or not 0 <= file_stat.st_size <= _MAX_DISTRIBUTION_FILE_BYTES
                ):
                    raise ValueError
                importable_bytes += file_stat.st_size
                if importable_bytes > _MAX_DISTRIBUTION_TOTAL_BYTES:
                    raise ValueError
                relative = checked.relative_to(distribution_root).as_posix()
                if relative in authenticated_paths:
                    importables.add(relative)
                    continue
                if path.suffix.casefold() != ".pyc" or "__pycache__" not in path.parts:
                    raise ValueError
                try:
                    source = Path(importlib.util.source_from_cache(str(path))).resolve(strict=True)
                    source_relative = source.relative_to(distribution_root).as_posix()
                except (OSError, ValueError):
                    raise ValueError from None
                if source.suffix.casefold() != ".py" or source_relative not in authenticated_paths:
                    raise ValueError
    return importables


def _authenticate_distribution(
    *,
    distribution_name: str,
    module_name: str,
    expected_origin: Path,
    required_relative_paths: Sequence[str],
    distribution_root: Path,
    record_path: Path,
) -> _DistributionEvidence:
    """Authenticate bounded RECORD entries for one exact import package root."""

    try:
        root = distribution_root.resolve(strict=True)
        origin = expected_origin.resolve(strict=True)
        package_root = origin.parent if origin.name == "__init__.py" else origin
        if (
            _path_has_symlink(expected_origin, root)
            or _path_has_symlink(record_path, root)
            or not package_root.is_dir()
            or record_path.stat().st_size > _MAX_RECORD_BYTES
        ):
            raise ValueError
        origin.relative_to(root)
        package_root.relative_to(root)
        record_resolved = record_path.resolve(strict=True)
        record_resolved.relative_to(root)
        with record_resolved.open("rb") as handle:
            record_bytes = handle.read(_MAX_RECORD_BYTES + 1)
        if not record_bytes or len(record_bytes) > _MAX_RECORD_BYTES:
            raise ValueError
        rows = tuple(csv.reader(record_bytes.decode("utf-8").splitlines()))
        if not 0 < len(rows) <= _MAX_DISTRIBUTION_ENTRIES:
            raise ValueError
        entries: dict[str, tuple[str, int]] = {}
        required = tuple(item.replace("\\", "/") for item in required_relative_paths)
        required_set = set(required)
        if len(required) != len(required_set) or not required:
            raise ValueError
        total_bytes = 0
        for row in rows:
            if len(row) != 3 or not row[0]:
                raise ValueError
            normalized = row[0].replace("\\", "/")
            relative = Path(normalized)
            if relative.is_absolute() or ".." in relative.parts or normalized in entries:
                raise ValueError
            if normalized not in required_set:
                continue
            candidate = root.joinpath(*relative.parts)
            try:
                candidate.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                raise ValueError from None
            if candidate.suffix.casefold() not in _IMPORTABLE_SUFFIXES:
                continue
            if (
                not row[1]
                or not row[2]
                or not row[2].isdigit()
                or _path_has_symlink(candidate, root)
            ):
                raise ValueError
            expected_size = int(row[2])
            if not 0 <= expected_size <= _MAX_DISTRIBUTION_FILE_BYTES:
                raise ValueError
            expected_sha256 = _decode_record_sha256(row[1])
            actual_sha256, actual_size = _hash_regular_file(
                candidate.resolve(strict=True),
                limit=_MAX_DISTRIBUTION_FILE_BYTES,
            )
            if actual_size != expected_size or actual_sha256 != expected_sha256:
                raise ValueError
            total_bytes += actual_size
            if total_bytes > _MAX_DISTRIBUTION_TOTAL_BYTES:
                raise ValueError
            entries[normalized] = (actual_sha256, actual_size)
        origin_relative = origin.relative_to(root).as_posix()
        if set(entries) != required_set or origin_relative not in required_set:
            raise ValueError
        package_required = {
            path
            for path in required_set
            if root.joinpath(*Path(path).parts).is_relative_to(package_root)
        }
        actual_importables = _bounded_package_importables(package_root, root, required_set)
        if actual_importables != package_required:
            raise ValueError
        manifest = [
            {"path": path, "sha256": digest, "size": size}
            for path, (digest, size) in sorted(entries.items())
        ]
        return _DistributionEvidence(
            distribution_name=distribution_name,
            module_name=module_name,
            distribution_root=str(root),
            package_root=str(package_root),
            module_origin=str(origin),
            manifest_sha256=canonical_sha256(manifest),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI runtime provenance failed validation") from None


def _distribution_record_path(
    distribution: importlib.metadata.Distribution,
) -> tuple[Path, tuple[str, ...], Path]:
    files = distribution.files
    if files is None or not 0 < len(files) <= _MAX_DISTRIBUTION_ENTRIES:
        raise ValueError
    root = Path(distribution.locate_file("")).resolve(strict=True)
    record_matches = tuple(
        item for item in files if str(item).replace("\\", "/").endswith(".dist-info/RECORD")
    )
    if len(record_matches) != 1:
        raise ValueError
    relative_files = tuple(str(item).replace("\\", "/") for item in files)
    return root, relative_files, Path(distribution.locate_file(record_matches[0]))


def _authenticate_recorded_metadata_file(
    *,
    root: Path,
    record_path: Path,
    relative_path: str,
    size_limit: int,
) -> tuple[Path, str, int]:
    """Authenticate one bounded metadata file against its distribution RECORD."""

    checked_root = root.resolve(strict=True)
    checked_record = record_path.resolve(strict=True)
    checked_record.relative_to(checked_root)
    if _path_has_symlink(record_path, checked_root):
        raise ValueError
    with checked_record.open("rb") as handle:
        record_bytes = handle.read(_MAX_RECORD_BYTES + 1)
    if not record_bytes or len(record_bytes) > _MAX_RECORD_BYTES:
        raise ValueError
    rows = tuple(csv.reader(record_bytes.decode("utf-8").splitlines()))
    if not 0 < len(rows) <= _MAX_DISTRIBUTION_ENTRIES:
        raise ValueError
    matches = tuple(
        row for row in rows if len(row) == 3 and row[0].replace("\\", "/") == relative_path
    )
    if len(matches) != 1:
        raise ValueError
    row = matches[0]
    if not row[1] or not row[2] or not row[2].isdigit():
        raise ValueError
    expected_size = int(row[2])
    if not 0 <= expected_size <= size_limit:
        raise ValueError
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError
    candidate = checked_root.joinpath(*relative.parts)
    checked_candidate = candidate.resolve(strict=True)
    checked_candidate.relative_to(checked_root)
    if _path_has_symlink(candidate, checked_root):
        raise ValueError
    actual_sha256, actual_size = _hash_regular_file(checked_candidate, limit=size_limit)
    if actual_size != expected_size or actual_sha256 != _decode_record_sha256(row[1]):
        raise ValueError
    return checked_candidate, actual_sha256, actual_size


def _authenticate_installed_module(
    distribution_name: str,
    module_name: str,
    spec: object,
) -> _DistributionEvidence:
    origin_value = getattr(spec, "origin", None)
    locations = getattr(spec, "submodule_search_locations", None)
    if type(origin_value) is not str or not origin_value or locations is None:
        raise _rfci_error("RFCI runtime provenance failed validation")
    origin = Path(origin_value)
    distribution = importlib.metadata.distribution(distribution_name)
    root, files, record_path = _distribution_record_path(distribution)
    package_prefix = module_name.replace(".", "/") + "/"
    required = tuple(
        item
        for item in files
        if (
            item.startswith(package_prefix)
            or (
                module_name == "jpype"
                and Path(item).parent == Path(".")
                and Path(item).name.startswith("_jpype")
            )
        )
        and Path(item).suffix.casefold() in _IMPORTABLE_SUFFIXES
    )
    evidence = _authenticate_distribution(
        distribution_name=distribution_name,
        module_name=module_name,
        expected_origin=origin,
        required_relative_paths=required,
        distribution_root=root,
        record_path=record_path,
    )
    try:
        location_values = tuple(locations)
        if len(location_values) != 1 or type(location_values[0]) is not str:
            raise ValueError
        location = Path(location_values[0])
        if _path_has_symlink(location, root) or location.resolve(strict=True) != Path(
            evidence.package_root
        ):
            raise ValueError
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI runtime provenance failed validation") from None
    return evidence


def _inspect_py_tetrad_installation_evidence() -> _PyTetradInstallationEvidence:
    """Authenticate VCS provenance and the exact packaged JAR without importing it."""

    distribution = importlib.metadata.distribution("py-tetrad")
    distribution_root, files, record_path = _distribution_record_path(distribution)
    record_relative = record_path.resolve(strict=True).relative_to(distribution_root)
    if _path_has_symlink(record_path, distribution_root):
        raise ValueError
    direct_url_relative = (record_relative.parent / "direct_url.json").as_posix()
    if files.count(direct_url_relative) != 1:
        raise ValueError
    direct_url_path, direct_url_sha256, direct_url_size = _authenticate_recorded_metadata_file(
        root=distribution_root,
        record_path=record_path,
        relative_path=direct_url_relative,
        size_limit=_MAX_DIRECT_URL_BYTES,
    )
    direct_url_bytes = direct_url_path.read_bytes()
    if (
        len(direct_url_bytes) != direct_url_size
        or hashlib.sha256(direct_url_bytes).hexdigest() != direct_url_sha256
    ):
        raise ValueError
    direct_url = json.loads(direct_url_bytes.decode("utf-8"))
    if type(direct_url) is not dict or set(direct_url) != {"url", "vcs_info"}:
        raise ValueError
    vcs_info = direct_url["vcs_info"]
    if (
        direct_url["url"] != _PY_TETRAD_URL
        or type(vcs_info) is not dict
        or not {"vcs", "commit_id"}
        <= set(vcs_info)
        <= {
            "vcs",
            "commit_id",
            "requested_revision",
        }
        or vcs_info["vcs"] != "git"
    ):
        raise ValueError
    commit = vcs_info["commit_id"]
    if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError
    requested_revision = vcs_info.get("requested_revision")
    if requested_revision is not None and (
        type(requested_revision) is not str or not requested_revision
    ):
        raise ValueError

    jar_relative = "pytetrad/resources/tetrad-current.jar"
    if files.count(jar_relative) != 1:
        raise ValueError
    jar_path, jar_sha256, jar_size = _authenticate_recorded_metadata_file(
        root=distribution_root,
        record_path=record_path,
        relative_path=jar_relative,
        size_limit=_MAX_JAR_BYTES,
    )
    package_path = Path(distribution.locate_file("pytetrad"))
    package_root = package_path.resolve(strict=True)
    if _path_has_symlink(package_path, distribution_root):
        raise ValueError
    jar_path.relative_to(package_root)
    return _PyTetradInstallationEvidence(
        commit=commit,
        direct_url_path=str(direct_url_path),
        direct_url_sha256=direct_url_sha256,
        direct_url_size=direct_url_size,
        jar_path=str(jar_path),
        jar_sha256=jar_sha256,
        jar_size=jar_size,
    )


def _inspect_py_tetrad_installation() -> tuple[str | None, str | None]:
    """Return nonfatal capability fields from authenticated internal evidence."""

    try:
        evidence = _inspect_py_tetrad_installation_evidence()
        return evidence.commit, evidence.jar_sha256
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None, None


def _selected_jvm_library(home: Path) -> Path:
    candidates = (
        home / "bin" / "server" / "jvm.dll",
        home / "lib" / "server" / "libjvm.so",
        home / "lib" / "server" / "libjvm.dylib",
    )
    matches = tuple(path.resolve(strict=True) for path in candidates if path.is_file())
    if len(matches) != 1:
        raise ValueError
    matches[0].relative_to(home)
    return matches[0]


def _select_java_runtime() -> _JavaRuntimeEvidence:
    try:
        selected = shutil.which("java")
        if not selected:
            raise ValueError
        executable = Path(selected).resolve(strict=True)
        if not executable.is_file():
            raise ValueError
        home = executable.parent.parent.resolve(strict=True)
        configured_home = os.environ.get("JAVA_HOME")
        if configured_home:
            configured = Path(configured_home).resolve(strict=True)
            configured_java = configured / "bin" / executable.name
            if configured != home or configured_java.resolve(strict=True) != executable:
                raise ValueError
        jvm_library = _selected_jvm_library(home)
        executable_sha256, _ = _hash_regular_file(
            executable,
            limit=_MAX_DISTRIBUTION_FILE_BYTES,
        )
        library_sha256, _ = _hash_regular_file(
            jvm_library,
            limit=_MAX_DISTRIBUTION_FILE_BYTES,
        )
        return _JavaRuntimeEvidence(
            executable=str(executable),
            home=str(home),
            jvm_library=str(jvm_library),
            executable_sha256=executable_sha256,
            jvm_library_sha256=library_sha256,
            major=1,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI Java runtime failed validation") from None


def _probe_environment(java: _JavaRuntimeEvidence) -> dict[str, str]:
    environment = {
        "JAVA_HOME": java.home,
        "PATH": str(Path(java.executable).parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _probe_java_runtime(java: _JavaRuntimeEvidence) -> _JavaRuntimeEvidence:
    try:
        result = run_isolated_process(
            (java.executable, "-version"),
            cwd=java.home,
            environment=_probe_environment(java),
            timeout_seconds=_JAVA_PROBE_TIMEOUT_SECONDS,
            max_stdout_bytes=_MAX_JAVA_VERSION_OUTPUT_CHARS,
            max_stderr_bytes=_MAX_JAVA_VERSION_OUTPUT_CHARS,
        )
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        match = _JAVA_VERSION.search(output)
        if match is None:
            raise ValueError
        major = int(match.group(1))
        if major == 1 and match.group(2) is not None:
            major = int(match.group(2))
        if not 1 <= major <= 999:
            raise ValueError
        return java.model_copy(update={"major": major})
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI Java runtime failed validation") from None


def _detect_java_major() -> int | None:
    try:
        return _probe_java_runtime(_select_java_runtime()).major
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
    python_version = "0.0"
    try:
        checked = RFCIConfig(enabled=True) if config is None else RFCIConfig.model_validate(config)
        if not checked.enabled:
            return _capability_record(
                python_version=python_version,
                status="disabled",
                reason_code="disabled",
            )
        candidate = _runtime_python_version()
        if (
            type(candidate) is not str
            or not 3 <= len(candidate) <= 64
            or _PYTHON_VERSION.fullmatch(candidate) is None
        ):
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="capability_probe_failed",
            )
        python_version = candidate
        if not _python_supports_rfci(python_version):
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="python_version_unsupported",
            )
        jpype_spec = importlib.util.find_spec("jpype")
        if jpype_spec is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="jpype_missing",
            )
        try:
            _authenticate_installed_module("JPype1", "jpype", jpype_spec)
        except Exception:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="runtime_provenance_invalid",
            )
        jpype_version = importlib.metadata.version("JPype1")
        if jpype_version != checked.jpype_version:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="jpype_version_mismatch",
                jpype_version=jpype_version,
            )
        pytetrad_spec = importlib.util.find_spec("pytetrad")
        if pytetrad_spec is None:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="py_tetrad_missing",
                jpype_version=jpype_version,
            )
        try:
            _authenticate_installed_module("py-tetrad", "pytetrad", pytetrad_spec)
        except Exception:
            return _capability_record(
                python_version=python_version,
                status="unavailable",
                reason_code="runtime_provenance_invalid",
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


def _matrix_for_exact_base_rows(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
) -> np.ndarray:
    if type(rows) is not tuple or len(rows) != table.row_count:
        raise ValueError
    checked_rows = tuple(
        CausalObservationRecord.model_validate(item)
        for item in rows
        if type(item) is CausalObservationRecord
    )
    if len(checked_rows) != len(rows) or tuple(
        (item.table_id, item.row_id) for item in checked_rows
    ) != tuple(sorted((item.table_id, item.row_id) for item in checked_rows)):
        raise ValueError
    if len({item.row_id for item in checked_rows}) != len(checked_rows):
        raise ValueError
    for item in checked_rows:
        if (
            item.table_id != table.table_id
            or item.model_id != table.model_id
            or CausalObservationRecord.from_content(
                table=table,
                task_id=item.task_id,
                prompt_id=item.prompt_id,
                model_id=item.model_id,
                seed_id=item.seed_id,
                values=item.values,
            )
            != item
        ):
            raise ValueError
    rebuilt = CausalTableRecord.from_content(
        scope_id=table.scope_id,
        cwe=table.cwe,
        model_id=table.model_id,
        variables=table.variables,
        row_count=len(checked_rows),
        independent_task_count=len({item.task_id for item in checked_rows}),
        observation_payload=tuple(
            (item.row_id, item.task_id, item.prompt_id, item.seed_id, item.values)
            for item in checked_rows
        ),
    )
    if rebuilt != table:
        raise ValueError
    shape = (table.row_count, len(table.variables))
    matrix = np.asarray(tuple(item.values for item in checked_rows), dtype=np.int64)
    if matrix.shape != shape:
        raise ValueError
    return np.frombuffer(matrix.tobytes(order="C"), dtype=np.int64).reshape(shape)


class _MatrixTransportLease:
    def __init__(
        self,
        *,
        root: Path,
        path: Path,
        record: _MatrixTransportRecord,
        identity: tuple[int, int],
    ) -> None:
        self.root = root
        self.path = path
        self.record = record
        self.identity = identity

    def close(self) -> None:
        path = self.path
        self.path = Path()
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root)
            file_stat = resolved.stat()
            if (file_stat.st_dev, file_stat.st_ino) == self.identity and stat.S_ISREG(
                file_stat.st_mode
            ):
                resolved.unlink()
        except FileNotFoundError:
            return
        except Exception:
            raise _rfci_error("RFCI matrix cleanup failed validation") from None


def _write_matrix_transport(matrix: np.ndarray, directory: str | Path) -> _MatrixTransportLease:
    descriptor = -1
    path = Path()
    try:
        if (
            type(matrix) is not np.ndarray
            or matrix.dtype != np.dtype(np.int64)
            or matrix.ndim != 2
            or not 2 <= matrix.shape[0] <= 100_000
            or not 2 <= matrix.shape[1] <= 64
            or not matrix.flags.c_contiguous
        ):
            raise ValueError
        root = Path(directory).resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ValueError
        path = root / f"matrix-{uuid.uuid4().hex}.raw"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags, 0o600)
        payload = np.asarray(matrix, dtype=np.dtype(_MATRIX_DTYPE), order="C").tobytes(order="C")
        expected_length = matrix.shape[0] * matrix.shape[1] * 8
        if len(payload) != expected_length:
            raise ValueError
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset : offset + _HASH_CHUNK_BYTES])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != expected_length:
            raise ValueError
        record = _MatrixTransportRecord(
            path=str(path),
            rows=matrix.shape[0],
            columns=matrix.shape[1],
            byte_length=expected_length,
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        return _MatrixTransportLease(
            root=root,
            path=path,
            record=record,
            identity=(file_stat.st_dev, file_stat.st_ino),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException:
                pass
            descriptor = -1
        if path != Path():
            try:
                path.unlink(missing_ok=True)
            except BaseException:
                pass
        raise _rfci_error("RFCI matrix transport failed validation") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_matrix_transport(
    transport: _MatrixTransportLease | _MatrixTransportRecord,
    *,
    trusted_root: str | Path | None = None,
) -> np.ndarray:
    descriptor = -1
    try:
        record = transport.record if isinstance(transport, _MatrixTransportLease) else transport
        checked = _MatrixTransportRecord.model_validate(record)
        path = Path(checked.path)
        root = (
            transport.root
            if isinstance(transport, _MatrixTransportLease)
            else Path(trusted_root).resolve(strict=True)  # type: ignore[arg-type]
        )
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if _path_has_symlink(path, root):
            raise ValueError
        expected = checked.rows * checked.columns * 8
        if expected != checked.byte_length:
            raise ValueError
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected:
            raise ValueError
        payload = bytearray()
        while len(payload) <= expected:
            chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, expected + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(payload) != expected
            or hashlib.sha256(payload).hexdigest() != checked.sha256
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ValueError
        matrix = np.frombuffer(bytes(payload), dtype=np.dtype(_MATRIX_DTYPE)).reshape(
            (checked.rows, checked.columns)
        )
        if matrix.flags.writeable or not matrix.flags.c_contiguous:
            raise ValueError
        return matrix
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI matrix transport failed validation") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _authenticated_rfci_matrix(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord | JCIObservationRecord],
) -> tuple[CausalTableRecord, np.ndarray]:
    try:
        checked_table = CausalTableRecord.model_validate(table)
        if type(rows) is not tuple or not rows:
            raise ValueError
        if all(type(item) is CausalObservationRecord for item in rows):
            matrix = _matrix_for_exact_base_rows(checked_table, rows)  # type: ignore[arg-type]
        elif all(type(item) is JCIObservationRecord for item in rows):
            matrix = matrix_for_exact_jci_rows(checked_table, rows)  # type: ignore[arg-type]
        else:
            raise ValueError
        if matrix.flags.writeable or not matrix.flags.c_contiguous:
            raise ValueError
        return checked_table, matrix
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI exact row relation failed validation") from None


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
        not config.enabled
        or not checked.available
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


def validate_rfci_capability(
    capability: RFCICapabilityRecord,
    config: RFCIConfig,
) -> RFCICapabilityRecord:
    """Validate capability status and provenance against one exact RFCI config."""

    try:
        checked_config = RFCIConfig.model_validate(config)
        checked = RFCICapabilityRecord.model_validate(capability)
        if checked_config.enabled:
            if checked.status == "disabled":
                raise ValueError
        elif checked.status != "disabled":
            raise ValueError
        if checked.available:
            return _validate_available_capability(checked, checked_config)
        return checked
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI capability relation failed validation") from None


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _decode_job(job_json: bytes) -> _RFCIWorkerJob:
    if type(job_json) is not bytes or not 0 < len(job_json) <= _MAX_JOB_BYTES:
        raise ValueError
    raw = json.loads(job_json.decode("utf-8"))
    if _canonical_json(raw) != job_json:
        raise ValueError
    job = _RFCIWorkerJob.model_validate(raw)
    _validate_available_capability(job.evidence.capability, job.config)
    return job


def _collect_runtime_evidence(config: RFCIConfig) -> _RFCICapabilityEvidence:
    checked = RFCIConfig.model_validate(config)
    if not checked.enabled:
        raise _rfci_error("RFCI runtime provenance failed validation")
    python_version = _runtime_python_version()
    if not _python_supports_rfci(python_version):
        raise _rfci_error("RFCI runtime provenance failed validation")
    jpype_spec = importlib.util.find_spec("jpype")
    pytetrad_spec = importlib.util.find_spec("pytetrad")
    if jpype_spec is None or pytetrad_spec is None:
        raise _rfci_error("RFCI runtime provenance failed validation")
    jpype = _authenticate_installed_module("JPype1", "jpype", jpype_spec)
    pytetrad = _authenticate_installed_module("py-tetrad", "pytetrad", pytetrad_spec)
    if importlib.metadata.version("JPype1") != checked.jpype_version:
        raise _rfci_error("RFCI runtime provenance failed validation")
    installation = _inspect_py_tetrad_installation_evidence()
    jar_path = Path(installation.jar_path)
    if (
        installation.commit != checked.py_tetrad_commit
        or installation.jar_sha256 != TETRAD_JAR_SHA256
        or _sha256_file(jar_path) != TETRAD_JAR_SHA256
        or jar_path.parent.parent.resolve(strict=True) != Path(pytetrad.package_root)
    ):
        raise _rfci_error("RFCI runtime provenance failed validation")
    java = _probe_java_runtime(_select_java_runtime())
    capability = _capability_record(
        python_version=python_version,
        status="available",
        reason_code=None,
        java_major=java.major,
        jpype_version=checked.jpype_version,
        py_tetrad_commit=installation.commit,
        tetrad_jar_sha256=installation.jar_sha256,
    )
    _validate_available_capability(capability, checked)
    return _RFCICapabilityEvidence(
        capability=capability,
        jpype=jpype,
        pytetrad=pytetrad,
        java=java,
        py_tetrad_installation=installation,
    )


def _write_exclusive(path: Path, payload: bytes, *, limit: int) -> None:
    if not 0 < len(payload) <= limit:
        raise ValueError
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _worker_environment(evidence: _RFCICapabilityEvidence) -> dict[str, str]:
    environment = _probe_environment(evidence.java)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _build_rfci_worker_argv(job_path: str | Path) -> tuple[str, ...]:
    path = Path(job_path).resolve(strict=True)
    root = path.parent.resolve(strict=True)
    if not path.is_file() or not root.is_dir():
        raise ValueError
    cache = root / "cache"
    cache.mkdir(mode=0o700)
    checked_cache = cache.resolve(strict=True)
    if (
        cache.is_symlink()
        or checked_cache.parent != root
        or next(checked_cache.iterdir(), None) is not None
    ):
        raise ValueError
    return (
        sys.executable,
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={checked_cache}",
        "-m",
        "secaware.discovery._rfci_worker",
        str(path),
    )


def _run_subprocess_rfci(
    table: CausalTableRecord,
    matrix: np.ndarray,
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
    evidence: _RFCICapabilityEvidence,
) -> PAGRecord:
    failure_kind = RFCIBackendFailureKind.INVALID_INPUT
    try:
        with tempfile.TemporaryDirectory(prefix="secaware-rfci-") as raw_directory:
            directory = Path(raw_directory).resolve(strict=True)
            lease = _write_matrix_transport(matrix, directory)
            try:
                job = _RFCIWorkerJob(
                    schema_version="1.0",
                    table=table,
                    knowledge=knowledge,
                    config=config,
                    evidence=evidence,
                    matrix=lease.record,
                )
                job_json = _canonical_json(job.model_dump(mode="json"))
                _decode_job(job_json)
                job_path = directory / "job.json"
                _write_exclusive(job_path, job_json, limit=_MAX_JOB_BYTES)
                worker_argv = _build_rfci_worker_argv(job_path)
                worker_environment = _worker_environment(evidence)
                failure_kind = RFCIBackendFailureKind.BACKEND_FAILURE
                process_result = run_isolated_process(
                    worker_argv,
                    cwd=directory,
                    environment=worker_environment,
                    timeout_seconds=config.timeout_seconds,
                    max_stdout_bytes=_MAX_PAYLOAD_BYTES,
                    max_stderr_bytes=64 * 1024,
                    require_canonical_json=True,
                )
                failure_kind = RFCIBackendFailureKind.INVALID_OUTPUT
                try:
                    pag = PAGRecord.model_validate_json(process_result.stdout)
                    result = RFCISensitivityResult(capability=evidence.capability, pag=pag)
                    validate_rfci_sensitivity_result(result, table, knowledge, config)
                except (MemoryError, KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise _rfci_error(failure_kind=RFCIBackendFailureKind.INVALID_OUTPUT) from None
                return pag
            finally:
                lease.close()
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError as error:
        if error.stage == "causal.discovery.rfci" and error.details.get("failure_kind") in {
            item.value for item in RFCIBackendFailureKind
        }:
            raise
        if error.stage == "process.isolation":
            try:
                isolated_kind = IsolatedProcessFailureKind(error.details.get("failure_kind"))
                failure_kind = RFCIBackendFailureKind(isolated_kind.value)
            except (TypeError, ValueError):
                failure_kind = RFCIBackendFailureKind.INVALID_OUTPUT
            raise _rfci_error(failure_kind=failure_kind) from None
        raise _rfci_error(failure_kind=failure_kind) from None
    except Exception:
        raise _rfci_error(failure_kind=failure_kind) from None


def _sanitize_worker_import_path(evidence: _RFCICapabilityEvidence) -> None:
    paths = sysconfig.get_paths()
    trusted = {
        Path(value).resolve(strict=True)
        for key, value in paths.items()
        if key in {"stdlib", "platstdlib", "purelib", "platlib"} and value
    }
    trusted.update(
        {
            Path(evidence.jpype.distribution_root).resolve(strict=True),
            Path(evidence.pytetrad.distribution_root).resolve(strict=True),
        }
    )
    sys.path[:] = [str(path) for path in sorted(trusted, key=str)]


def _verify_loaded_distribution(evidence: _DistributionEvidence) -> None:
    spec = importlib.util.find_spec(evidence.module_name)
    if spec is None:
        raise ValueError
    current = _authenticate_installed_module(
        evidence.distribution_name,
        evidence.module_name,
        spec,
    )
    if current != evidence:
        raise ValueError
    package_root = Path(evidence.package_root).resolve(strict=True)
    for name, module in tuple(sys.modules.items()):
        if name != evidence.module_name and not name.startswith(evidence.module_name + "."):
            continue
        module_file = getattr(module, "__file__", None)
        if module_file is None:
            continue
        Path(module_file).resolve(strict=True).relative_to(package_root)


def _execute_worker_job(job_path: str | Path) -> bytes:
    path = Path(job_path).resolve(strict=True)
    cache = path.parent / "cache"
    expected_cache = cache.resolve(strict=True)
    if (
        sys.dont_write_bytecode is not True
        or sys.pycache_prefix != str(expected_cache)
        or cache.is_symlink()
        or expected_cache.parent != path.parent
        or next(expected_cache.iterdir(), None) is not None
    ):
        raise ValueError
    file_stat = path.stat()
    if not stat.S_ISREG(file_stat.st_mode) or not 0 < file_stat.st_size <= _MAX_JOB_BYTES:
        raise ValueError
    job_json = path.read_bytes()
    if len(job_json) != file_stat.st_size:
        raise ValueError
    job = _decode_job(job_json)
    actual = _collect_runtime_evidence(job.config)
    if actual != job.evidence:
        raise ValueError
    _sanitize_worker_import_path(actual)
    matrix = _read_matrix_transport(job.matrix, trusted_root=path.parent)
    _validated_rfci_inputs(job.table, matrix, job.knowledge, job.config)

    import jpype  # noqa: PLC0415

    if Path(jpype.__file__).resolve(strict=True) != Path(actual.jpype.module_origin):
        raise ValueError
    _verify_loaded_distribution(actual.jpype)
    if jpype.isJVMStarted():
        raise ValueError
    jpype.startJVM(
        actual.java.jvm_library,
        "-ea",
        "--enable-native-access=ALL-UNNAMED",
        classpath=[actual.py_tetrad_installation.jar_path],
    )
    import pytetrad  # noqa: PLC0415

    if Path(pytetrad.__file__).resolve(strict=True) != Path(actual.pytetrad.module_origin):
        raise ValueError
    _verify_loaded_distribution(actual.pytetrad)
    from pytetrad.tools.TetradSearch import TetradSearch  # noqa: PLC0415

    pag = _run_rfci_adapter(job.table, matrix, job.knowledge, job.config, TetradSearch)
    payload = _canonical_json(pag.model_dump(mode="json"))
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise ValueError
    return payload


def _run_test_rfci_adapter(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord | JCIObservationRecord],
    config: RFCIConfig,
) -> PAGRecord:
    checked_table, _matrix = _authenticated_rfci_matrix(table, rows)
    checked_config = RFCIConfig.model_validate(config)
    return PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=checked_table.table_id,
        backend="test_rfci_fake_v1",
        backend_version="test_only",
        ci_test="gsq",
        config_sha256=canonical_sha256(checked_config.model_dump(mode="json")),
        background_knowledge_sha256="0" * 64,
        variable_ids=tuple(item.variable_id for item in checked_table.variables),
        edges=(),
    )


def validate_rfci_sensitivity_result(
    result: RFCISensitivityResult,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
) -> RFCISensitivityResult:
    """Validate all persisted RFCI capability, table, config, BK, and PAG relations."""

    try:
        checked_result = RFCISensitivityResult.model_validate(result)
        checked_table = CausalTableRecord.model_validate(table)
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = RFCIConfig.model_validate(config)
        checked_capability = validate_rfci_capability(
            checked_result.capability,
            checked_config,
        )
        if not checked_capability.available:
            if checked_result.pag is not None:
                raise ValueError
            return checked_result
        pag = checked_result.pag
        expected_variables = tuple(item.variable_id for item in checked_table.variables)
        if (
            pag is None
            or pag.table_id != checked_table.table_id
            or pag.backend != RFCI_BACKEND
            or pag.backend_version != checked_config.py_tetrad_commit
            or pag.ci_test != "gsq"
            or pag.config_sha256 != canonical_sha256(checked_config.model_dump(mode="json"))
            or pag.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
            or pag.variable_ids != expected_variables
            or pag.run_kind is not PAGRunKind.RFCI_SENSITIVITY
        ):
            raise ValueError
        validate_pag_against_background(pag, checked_knowledge)
        return checked_result
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _rfci_error("RFCI result relation failed validation") from None


def _run_rfci_sensitivity_with_capability(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord | JCIObservationRecord],
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
    *,
    capability: RFCICapabilityRecord,
) -> RFCISensitivityResult:
    """Run from capability evidence frozen by an internal transactional caller."""
    try:
        checked_config = RFCIConfig.model_validate(config)
        checked_capability = RFCICapabilityRecord.model_validate(capability)
        checked_capability = validate_rfci_capability(checked_capability, checked_config)
        if not checked_config.enabled:
            return RFCISensitivityResult(capability=checked_capability, pag=None)
        if not checked_capability.available:
            return RFCISensitivityResult(capability=checked_capability, pag=None)
        try:
            evidence = _collect_runtime_evidence(checked_config)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise _rfci_error(
                "RFCI runtime provenance failed validation",
                failure_kind=RFCIBackendFailureKind.BACKEND_FAILURE,
            ) from None
        if evidence.capability != checked_capability:
            raise ValueError
        checked_table, matrix = _authenticated_rfci_matrix(table, rows)
        checked_table, matrix, checked_knowledge, checked_config = _validated_rfci_inputs(
            checked_table,
            matrix,
            knowledge,
            checked_config,
        )
        pag = _run_subprocess_rfci(
            checked_table,
            matrix,
            checked_knowledge,
            checked_config,
            evidence,
        )
        result = RFCISensitivityResult(capability=checked_capability, pag=pag)
        return validate_rfci_sensitivity_result(
            result,
            checked_table,
            checked_knowledge,
            checked_config,
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _rfci_error() from None


def run_rfci_sensitivity(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord | JCIObservationRecord],
    knowledge: BackgroundKnowledgeRecord,
    config: RFCIConfig,
) -> RFCISensitivityResult:
    """Self-probe capability and return an optional PAG for one exact row relation."""

    checked_config = RFCIConfig.model_validate(config)
    capability = detect_rfci_capability(checked_config)
    return _run_rfci_sensitivity_with_capability(
        table,
        rows,
        knowledge,
        checked_config,
        capability=capability,
    )


__all__ = [
    "JPYPE_VERSION",
    "MINIMUM_JAVA_MAJOR",
    "PY_TETRAD_COMMIT",
    "RFCIBackendFailureKind",
    "RFCI_BACKEND",
    "TETRAD_JAR_SHA256",
    "detect_rfci_capability",
    "expanded_forbidden_directions",
    "run_rfci_sensitivity",
    "validate_rfci_capability",
    "validate_rfci_sensitivity_result",
]

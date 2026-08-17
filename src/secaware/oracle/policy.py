from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Literal

from pydantic import ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import SafeValidationMixin, VersionedModel


ORACLE_POLICY_SCHEMA_VERSION = "1.2"
SEMGREP_VERSION = "1.168.0"
BANDIT_VERSION = "1.9.4"
MAX_POLICY_LOCK_BYTES = 64 * 1024
MAX_POLICY_FILE_BYTES = 1024 * 1024

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_INVALID_LOCK_MESSAGE = "oracle policy lock validation failed"
_INVALID_LOADED_POLICY_MESSAGE = "loaded oracle policy validation failed"
_INVALID_BANDIT_CONSTRAINT_MESSAGE = "Bandit finding constraint validation failed"
_INVALID_BANDIT_METADATA_MESSAGE = "Bandit policy metadata validation failed"
_INVALID_COVERAGE_CONTRACT_MESSAGE = "Oracle coverage contract validation failed"
_INVALID_COVERAGE_PROFILE_MESSAGE = "Oracle coverage profile validation failed"
_POLICY_STAGE = "oracle_policy"
_POLICY_MESSAGE = "oracle policy bundle could not be authenticated"


def _canonical_policy_path(value: str, message: str) -> str:
    parts = value.split("/")
    path = PurePosixPath(value)
    if (
        value != value.strip()
        or "\\" in value
        or ":" in value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or path.as_posix() != value
    ):
        raise ValueError(message)
    return value


class OraclePolicyLock(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_LOCK_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.2"]
    policy_name: str = Field(min_length=1, max_length=256)
    language: Literal["python"]
    semgrep_version: Literal["1.168.0"]
    bandit_version: Literal["1.9.4"]
    semgrep_rules: str = Field(min_length=1, max_length=4096, repr=False)
    semgrep_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    bandit_config: str = Field(min_length=1, max_length=4096, repr=False)
    bandit_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    bandit_metadata: str = Field(min_length=1, max_length=4096, repr=False)
    bandit_metadata_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    coverage_contract: str = Field(min_length=1, max_length=4096, repr=False)
    coverage_contract_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)

    @field_validator("policy_name")
    @classmethod
    def validate_policy_name(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError(_INVALID_LOCK_MESSAGE)
        return value

    @field_validator(
        "semgrep_rules",
        "bandit_config",
        "bandit_metadata",
        "coverage_contract",
    )
    @classmethod
    def validate_policy_path(cls, value: str) -> str:
        return _canonical_policy_path(value, _INVALID_LOCK_MESSAGE)

    @model_validator(mode="after")
    def validate_distinct_policy_paths(self) -> "OraclePolicyLock":
        if (
            len(
                {
                    self.semgrep_rules,
                    self.bandit_config,
                    self.bandit_metadata,
                    self.coverage_contract,
                }
            )
            != 4
        ):
            raise ValueError(_INVALID_LOCK_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "OraclePolicyLock()"


class BanditFindingConstraint(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_BANDIT_CONSTRAINT_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"] = "1.0"
    test_id: str = Field(pattern=r"^B[0-9]{3}$", repr=False)
    cwe_ids: tuple[StrictInt, ...] = Field(min_length=1, max_length=16, repr=False)
    severities: tuple[Literal["LOW", "MEDIUM", "HIGH"], ...] = Field(
        min_length=1,
        max_length=3,
        repr=False,
    )
    confidences: tuple[Literal["LOW", "MEDIUM", "HIGH"], ...] = Field(
        min_length=1,
        max_length=3,
        repr=False,
    )

    @model_validator(mode="after")
    def validate_constraint(self) -> "BanditFindingConstraint":
        if (
            any(value < 1 for value in self.cwe_ids)
            or self.cwe_ids != tuple(sorted(set(self.cwe_ids)))
            or self.severities != tuple(sorted(set(self.severities)))
            or self.confidences != tuple(sorted(set(self.confidences)))
        ):
            raise ValueError(_INVALID_BANDIT_CONSTRAINT_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "BanditFindingConstraint()"


class BanditPolicyMetadata(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_BANDIT_METADATA_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    bandit_version: Literal["1.9.4"]
    findings: tuple[BanditFindingConstraint, ...] = Field(min_length=1, max_length=256)

    @field_validator("findings", mode="before")
    @classmethod
    def snapshot_findings(cls, value: object) -> tuple[BanditFindingConstraint, ...]:
        if type(value) not in {list, tuple}:
            raise TypeError(_INVALID_BANDIT_METADATA_MESSAGE)
        snapshots: list[BanditFindingConstraint] = []
        for item in value:
            if type(item) is not dict:
                raise TypeError(_INVALID_BANDIT_METADATA_MESSAGE)
            payload = dict(item)
            for field in ("cwe_ids", "severities", "confidences"):
                nested = payload.get(field)
                if type(nested) is not list:
                    raise TypeError(_INVALID_BANDIT_METADATA_MESSAGE)
                payload[field] = tuple(nested)
            snapshots.append(BanditFindingConstraint.model_validate(payload))
        return tuple(snapshots)

    @model_validator(mode="after")
    def validate_findings(self) -> "BanditPolicyMetadata":
        identifiers = tuple(item.test_id for item in self.findings)
        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError(_INVALID_BANDIT_METADATA_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "BanditPolicyMetadata()"


class OracleCoverageProfile(SafeValidationMixin, VersionedModel):
    """One pre-treatment task profile whose zero-finding meaning is frozen."""

    _safe_validation_message = _INVALID_COVERAGE_PROFILE_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0", "1.1"] = "1.0"
    profile_id: str = Field(
        pattern=r"^python\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*$"
    )
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]{0,5}$")
    task_families: tuple[str, ...] = Field(min_length=1, max_length=32)
    zero_finding_supported: bool
    analyzer_rule_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    calibration_fixture_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=256)
    decision_backend: Literal["finding_union_v1", "python_ast_mechanism_v1"] = "finding_union_v1"

    @model_validator(mode="after")
    def validate_profile(self) -> "OracleCoverageProfile":
        values = self.task_families + self.analyzer_rule_ids + self.calibration_fixture_ids
        if (
            self.task_families != tuple(sorted(set(self.task_families)))
            or self.analyzer_rule_ids != tuple(sorted(set(self.analyzer_rule_ids)))
            or self.calibration_fixture_ids != tuple(sorted(set(self.calibration_fixture_ids)))
            or any(
                not value
                or value != value.strip()
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
                for value in values
            )
            or (
                self.zero_finding_supported
                and (not self.analyzer_rule_ids or len(self.calibration_fixture_ids) < 2)
            )
            or (
                self.decision_backend == "python_ast_mechanism_v1"
                and (
                    self.schema_version != "1.1"
                    or self.cwe not in {"CWE-78", "CWE-89"}
                    or len(self.calibration_fixture_ids) < 6
                )
            )
            or (self.schema_version == "1.1" and self.decision_backend != "python_ast_mechanism_v1")
        ):
            raise ValueError(_INVALID_COVERAGE_PROFILE_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "OracleCoverageProfile()"


class OracleCoverageContract(SafeValidationMixin, VersionedModel):
    """Finite, authenticated support declaration for negative analyzer verdicts."""

    _safe_validation_message = _INVALID_COVERAGE_CONTRACT_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["1.0"]
    contract_name: str = Field(min_length=1, max_length=256)
    profiles: tuple[OracleCoverageProfile, ...] = Field(min_length=1, max_length=256)

    @field_validator("profiles", mode="before")
    @classmethod
    def snapshot_profiles(cls, value: object) -> tuple[OracleCoverageProfile, ...]:
        if type(value) not in {list, tuple}:
            raise TypeError(_INVALID_COVERAGE_CONTRACT_MESSAGE)
        snapshots: list[OracleCoverageProfile] = []
        for item in value:
            if type(item) is not dict:
                raise TypeError(_INVALID_COVERAGE_CONTRACT_MESSAGE)
            payload = dict(item)
            for field in ("task_families", "analyzer_rule_ids", "calibration_fixture_ids"):
                nested = payload.get(field, [])
                if type(nested) is not list:
                    raise TypeError(_INVALID_COVERAGE_CONTRACT_MESSAGE)
                payload[field] = tuple(nested)
            snapshots.append(OracleCoverageProfile.model_validate(payload))
        return tuple(snapshots)

    @model_validator(mode="after")
    def validate_contract(self) -> "OracleCoverageContract":
        identifiers = tuple(item.profile_id for item in self.profiles)
        if self.contract_name != self.contract_name.strip() or identifiers != tuple(
            sorted(set(identifiers))
        ):
            raise ValueError(_INVALID_COVERAGE_CONTRACT_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "OracleCoverageContract()"


class LoadedOraclePolicy(SafeValidationMixin, VersionedModel):
    _safe_validation_message = _INVALID_LOADED_POLICY_MESSAGE

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
        arbitrary_types_allowed=False,
    )

    schema_version: Literal["1.2"]
    policy_name: str = Field(min_length=1, max_length=256)
    language: Literal["python"]
    semgrep_version: Literal["1.168.0"]
    bandit_version: Literal["1.9.4"]
    semgrep_rules: str = Field(min_length=1, max_length=4096, repr=False)
    semgrep_rules_path: Path = Field(repr=False)
    semgrep_rules_bytes: bytes = Field(min_length=1, max_length=MAX_POLICY_FILE_BYTES, repr=False)
    semgrep_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    bandit_config: str = Field(min_length=1, max_length=4096, repr=False)
    bandit_config_path: Path = Field(repr=False)
    bandit_config_bytes: bytes = Field(min_length=1, max_length=MAX_POLICY_FILE_BYTES, repr=False)
    bandit_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    bandit_metadata: str = Field(min_length=1, max_length=4096, repr=False)
    bandit_metadata_path: Path = Field(repr=False)
    bandit_metadata_bytes: bytes = Field(
        min_length=1,
        max_length=MAX_POLICY_FILE_BYTES,
        repr=False,
    )
    bandit_metadata_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    bandit_constraints: tuple[BanditFindingConstraint, ...] = Field(
        min_length=1,
        max_length=256,
        repr=False,
    )
    coverage_contract: str = Field(min_length=1, max_length=4096, repr=False)
    coverage_contract_path: Path = Field(repr=False)
    coverage_contract_bytes: bytes = Field(
        min_length=1,
        max_length=MAX_POLICY_FILE_BYTES,
        repr=False,
    )
    coverage_contract_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)
    coverage_profiles: tuple[OracleCoverageProfile, ...] = Field(
        min_length=1,
        max_length=256,
        repr=False,
    )
    combined_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("policy_name")
    @classmethod
    def validate_policy_name(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        return value

    @field_validator(
        "semgrep_rules",
        "bandit_config",
        "bandit_metadata",
        "coverage_contract",
    )
    @classmethod
    def validate_policy_path(cls, value: str) -> str:
        return _canonical_policy_path(value, _INVALID_LOADED_POLICY_MESSAGE)

    @property
    def lock_payload(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "policy_name": self.policy_name,
            "language": self.language,
            "semgrep_version": self.semgrep_version,
            "bandit_version": self.bandit_version,
            "semgrep_rules": self.semgrep_rules,
            "semgrep_sha256": self.semgrep_sha256,
            "bandit_config": self.bandit_config,
            "bandit_sha256": self.bandit_sha256,
            "bandit_metadata": self.bandit_metadata,
            "bandit_metadata_sha256": self.bandit_metadata_sha256,
            "coverage_contract": self.coverage_contract,
            "coverage_contract_sha256": self.coverage_contract_sha256,
        }

    @model_validator(mode="after")
    def validate_loaded_policy(self) -> "LoadedOraclePolicy":
        if (
            not self.semgrep_rules_path.is_absolute()
            or not self.bandit_config_path.is_absolute()
            or not self.bandit_metadata_path.is_absolute()
            or not self.coverage_contract_path.is_absolute()
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if (
            len(
                {
                    self.semgrep_rules_path,
                    self.bandit_config_path,
                    self.bandit_metadata_path,
                    self.coverage_contract_path,
                }
            )
            != 4
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if hashlib.sha256(self.semgrep_rules_bytes).hexdigest() != self.semgrep_sha256:
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if hashlib.sha256(self.bandit_config_bytes).hexdigest() != self.bandit_sha256:
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if hashlib.sha256(self.bandit_metadata_bytes).hexdigest() != self.bandit_metadata_sha256:
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if (
            hashlib.sha256(self.coverage_contract_bytes).hexdigest()
            != self.coverage_contract_sha256
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if canonical_sha256(self.lock_payload) != self.combined_sha256:
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if (
            _parse_bandit_policy(
                self.bandit_config_bytes,
                self.bandit_metadata_bytes,
            )
            != self.bandit_constraints
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        if (
            _parse_coverage_contract(self.coverage_contract_bytes).profiles
            != self.coverage_profiles
        ):
            raise ValueError(_INVALID_LOADED_POLICY_MESSAGE)
        return self

    def __repr__(self) -> str:
        return "LoadedOraclePolicy()"


def _policy_mismatch() -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.POLICY_MISMATCH,
        stage=_POLICY_STAGE,
        message=_POLICY_MESSAGE,
        details={},
        retryable=False,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: Path
    payload: bytes
    fingerprint: tuple[int, int, int, int, int, int, int]

    @property
    def identity(self) -> tuple[int, int]:
        return self.fingerprint[0], self.fingerprint[1]


def _fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _same_open_file_identity(before: Any, opened: Any) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
    )


def _require_regular(value: os.stat_result, maximum_bytes: int) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_size < 1
        or value.st_size > maximum_bytes
    ):
        raise ValueError(_POLICY_MESSAGE)


def _read_file_snapshot(path: Path, maximum_bytes: int) -> _FileSnapshot:
    before = path.lstat()
    _require_regular(before, maximum_bytes)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", buffering=0, closefd=False) as handle:
            opened = os.fstat(handle.fileno())
            _require_regular(opened, maximum_bytes)
            if not _same_open_file_identity(before, opened):
                raise ValueError(_POLICY_MESSAGE)
            payload = handle.read(maximum_bytes + 1)
            after_read = os.fstat(handle.fileno())
            _require_regular(after_read, maximum_bytes)
            if _fingerprint(opened) != _fingerprint(after_read):
                raise ValueError(_POLICY_MESSAGE)
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes or len(payload) != opened.st_size:
        raise ValueError(_POLICY_MESSAGE)
    after_path = path.lstat()
    if not _same_open_file_identity(after_read, after_path):
        raise ValueError(_POLICY_MESSAGE)
    return _FileSnapshot(
        path=path.resolve(strict=True),
        payload=payload,
        fingerprint=_fingerprint(after_read),
    )


def _require_plain_components(root: Path, relative_path: str) -> Path:
    current = root
    for part in relative_path.split("/"):
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(_POLICY_MESSAGE)
    return current


def _require_contained_snapshot(
    root: Path,
    relative_path: str,
    snapshot: _FileSnapshot,
) -> None:
    snapshot.path.relative_to(root)
    current = _require_plain_components(root, relative_path).resolve(strict=True)
    if current != snapshot.path:
        raise ValueError(_POLICY_MESSAGE)


def _parse_lock(payload: bytes) -> OraclePolicyLock:
    raw = load_strict_json_bytes(payload)
    return OraclePolicyLock.model_validate(raw)


def _parse_bandit_policy(
    config_payload: bytes,
    metadata_payload: bytes,
) -> tuple[BanditFindingConstraint, ...]:
    config = load_strict_json_bytes(config_payload)
    metadata_raw = load_strict_json_bytes(metadata_payload)
    if type(config) is not dict or set(config) != {"tests"}:
        raise ValueError(_POLICY_MESSAGE)
    tests = config.get("tests")
    if type(tests) is not list or not tests:
        raise ValueError(_POLICY_MESSAGE)
    if any(type(item) is not str for item in tests):
        raise ValueError(_POLICY_MESSAGE)
    test_ids = tuple(tests)
    if test_ids != tuple(sorted(set(test_ids))):
        raise ValueError(_POLICY_MESSAGE)
    metadata = BanditPolicyMetadata.model_validate(metadata_raw)
    constraint_ids = tuple(item.test_id for item in metadata.findings)
    if metadata.bandit_version != BANDIT_VERSION or constraint_ids != test_ids:
        raise ValueError(_POLICY_MESSAGE)
    return metadata.findings


def _parse_coverage_contract(payload: bytes) -> OracleCoverageContract:
    raw = load_strict_json_bytes(payload)
    return OracleCoverageContract.model_validate(raw)


def _load_policy_bundle(lock_path: str | Path) -> LoadedOraclePolicy:
    path = Path(os.path.abspath(os.fspath(lock_path)))
    lock_snapshot = _read_file_snapshot(path, MAX_POLICY_LOCK_BYTES)
    lock = _parse_lock(lock_snapshot.payload)
    root = path.parent.resolve(strict=True)
    semgrep_path = _require_plain_components(root, lock.semgrep_rules)
    bandit_path = _require_plain_components(root, lock.bandit_config)
    bandit_metadata_path = _require_plain_components(root, lock.bandit_metadata)
    coverage_contract_path = _require_plain_components(root, lock.coverage_contract)
    semgrep_snapshot = _read_file_snapshot(semgrep_path, MAX_POLICY_FILE_BYTES)
    bandit_snapshot = _read_file_snapshot(bandit_path, MAX_POLICY_FILE_BYTES)
    bandit_metadata_snapshot = _read_file_snapshot(
        bandit_metadata_path,
        MAX_POLICY_FILE_BYTES,
    )
    coverage_contract_snapshot = _read_file_snapshot(
        coverage_contract_path,
        MAX_POLICY_FILE_BYTES,
    )
    _require_contained_snapshot(root, lock.semgrep_rules, semgrep_snapshot)
    _require_contained_snapshot(root, lock.bandit_config, bandit_snapshot)
    _require_contained_snapshot(root, lock.bandit_metadata, bandit_metadata_snapshot)
    _require_contained_snapshot(root, lock.coverage_contract, coverage_contract_snapshot)
    identities = {
        lock_snapshot.identity,
        semgrep_snapshot.identity,
        bandit_snapshot.identity,
        bandit_metadata_snapshot.identity,
        coverage_contract_snapshot.identity,
    }
    if len(identities) != 5:
        raise ValueError(_POLICY_MESSAGE)
    constraints = _parse_bandit_policy(
        bandit_snapshot.payload,
        bandit_metadata_snapshot.payload,
    )
    coverage = _parse_coverage_contract(coverage_contract_snapshot.payload)
    return LoadedOraclePolicy(
        schema_version=lock.schema_version,
        policy_name=lock.policy_name,
        language=lock.language,
        semgrep_version=lock.semgrep_version,
        bandit_version=lock.bandit_version,
        semgrep_rules=lock.semgrep_rules,
        semgrep_rules_path=semgrep_snapshot.path,
        semgrep_rules_bytes=semgrep_snapshot.payload,
        semgrep_sha256=lock.semgrep_sha256,
        bandit_config=lock.bandit_config,
        bandit_config_path=bandit_snapshot.path,
        bandit_config_bytes=bandit_snapshot.payload,
        bandit_sha256=lock.bandit_sha256,
        bandit_metadata=lock.bandit_metadata,
        bandit_metadata_path=bandit_metadata_snapshot.path,
        bandit_metadata_bytes=bandit_metadata_snapshot.payload,
        bandit_metadata_sha256=lock.bandit_metadata_sha256,
        bandit_constraints=constraints,
        coverage_contract=lock.coverage_contract,
        coverage_contract_path=coverage_contract_snapshot.path,
        coverage_contract_bytes=coverage_contract_snapshot.payload,
        coverage_contract_sha256=lock.coverage_contract_sha256,
        coverage_profiles=coverage.profiles,
        combined_sha256=canonical_sha256(lock.model_dump(mode="json")),
    )


def load_policy_bundle(lock_path: str | Path) -> LoadedOraclePolicy:
    loaded: LoadedOraclePolicy | None = None
    failed = False
    try:
        loaded = _load_policy_bundle(lock_path)
    except Exception:
        failed = True
    finally:
        lock_path = None  # type: ignore[assignment]
    if failed or loaded is None:
        loaded = None
        raise _policy_mismatch() from None
    return loaded


__all__ = [
    "BANDIT_VERSION",
    "BanditFindingConstraint",
    "BanditPolicyMetadata",
    "OracleCoverageContract",
    "OracleCoverageProfile",
    "LoadedOraclePolicy",
    "MAX_POLICY_FILE_BYTES",
    "MAX_POLICY_LOCK_BYTES",
    "ORACLE_POLICY_SCHEMA_VERSION",
    "OraclePolicyLock",
    "SEMGREP_VERSION",
    "load_policy_bundle",
]

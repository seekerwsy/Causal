"""Immutable, cluster-exclusive data-pool contracts for prospective experiments."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel

_SHA256 = r"^[0-9a-f]{64}$"
_CWE = re.compile(r"^CWE-[1-9][0-9]*$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_MEMBERSHIP_ID = r"^pool_task_[0-9a-f]{64}$"
_MANIFEST_ID = r"^pool_partition_[0-9a-f]{64}$"


class EvidencePool(str, Enum):
    GOLD = "D_GOLD"
    CANARY = "D_CANARY"
    SENTINEL = "D_SENTINEL"
    DEV_DISCOVERY = "D_DEV_DISCOVERY"
    DEV_CONFIRM = "D_DEV_CONFIRM"
    FORMAL_DISCOVERY = "D_FORMAL_DISCOVERY"
    FORMAL_CONFIRM = "D_FORMAL_CONFIRM"
    REPLICATION = "D_REPLICATION"


class ContractStatus(str, Enum):
    EXECUTABLE_VALIDATED = "executable_validated"
    DECLARATIVE_ONLY = "declarative_only"
    ABSENT = "absent"


EVIDENCE_ELIGIBLE_POOLS = frozenset(
    {
        EvidencePool.FORMAL_DISCOVERY,
        EvidencePool.FORMAL_CONFIRM,
        EvidencePool.REPLICATION,
    }
)

# These pools must begin without any generated-code outcome for their clusters. Development
# discovery/confirmation stays outcome-blind so it cannot be tuned on legacy answers. GOLD and
# CANARY are the only pools allowed to deliberately reuse exposed regression material.
OUTCOME_BLIND_POOLS = frozenset(set(EvidencePool) - {EvidencePool.GOLD, EvidencePool.CANARY})


def _jsonable(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _digest(value: object) -> str:
    payload = json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value)) and value == value.strip()


class _PoolContract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "phase-pool contract failed validation"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )


class PoolTaskRecord(_PoolContract):
    """One task instance assigned once under a semantic-cluster-level pool decision."""

    schema_version: Literal["2.0"] = "2.0"
    membership_id: str = Field(pattern=_MEMBERSHIP_ID)
    pool: EvidencePool
    semantic_task_cluster_id: str
    task_instance_id: str
    source_id: str
    source_record_id: str
    prompt_sha256: str = Field(pattern=_SHA256)
    cwe_id: str
    archetype_id: str
    template_family_id: str
    language: Literal["python"] = "python"
    functional_contract_status: ContractStatus
    security_contract_status: ContractStatus
    legacy_outcome_exposed: bool
    exposure_artifact_sha256: tuple[str, ...] = ()

    @field_validator("pool", mode="before")
    @classmethod
    def parse_pool(cls, value: object) -> object:
        if isinstance(value, EvidencePool):
            return value
        if type(value) is str:
            return next((item for item in EvidencePool if item.value == value), value)
        return value

    @field_validator(
        "functional_contract_status",
        "security_contract_status",
        mode="before",
    )
    @classmethod
    def parse_contract_status(cls, value: object) -> object:
        if isinstance(value, ContractStatus):
            return value
        if type(value) is str:
            return next((item for item in ContractStatus if item.value == value), value)
        return value

    @field_validator("exposure_artifact_sha256", mode="before")
    @classmethod
    def freeze_exposure_digests(cls, value: object) -> object:
        if type(value) is list:
            return tuple(value)
        return value

    @classmethod
    def from_content(
        cls,
        *,
        pool: EvidencePool,
        semantic_task_cluster_id: str,
        task_instance_id: str,
        source_id: str,
        source_record_id: str,
        prompt_sha256: str,
        cwe_id: str,
        archetype_id: str,
        template_family_id: str,
        functional_contract_status: ContractStatus,
        security_contract_status: ContractStatus,
        legacy_outcome_exposed: bool,
        exposure_artifact_sha256: tuple[str, ...] = (),
    ) -> PoolTaskRecord:
        content: dict[str, Any] = {
            "schema_version": "2.0",
            "pool": pool,
            "semantic_task_cluster_id": semantic_task_cluster_id,
            "task_instance_id": task_instance_id,
            "source_id": source_id,
            "source_record_id": source_record_id,
            "prompt_sha256": prompt_sha256,
            "cwe_id": cwe_id,
            "archetype_id": archetype_id,
            "template_family_id": template_family_id,
            "language": "python",
            "functional_contract_status": functional_contract_status,
            "security_contract_status": security_contract_status,
            "legacy_outcome_exposed": legacy_outcome_exposed,
            "exposure_artifact_sha256": exposure_artifact_sha256,
        }
        return cls(membership_id=f"pool_task_{_digest(content)}", **content)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        identifiers = (
            self.semantic_task_cluster_id,
            self.task_instance_id,
            self.source_id,
            self.source_record_id,
            self.archetype_id,
            self.template_family_id,
        )
        if not all(_valid_identifier(value) for value in identifiers):
            raise ValueError(self._safe_validation_message)
        if not _CWE.fullmatch(self.cwe_id):
            raise ValueError(self._safe_validation_message)
        if len(set(self.exposure_artifact_sha256)) != len(self.exposure_artifact_sha256):
            raise ValueError(self._safe_validation_message)
        if any(re.fullmatch(_SHA256, item) is None for item in self.exposure_artifact_sha256):
            raise ValueError(self._safe_validation_message)
        if self.legacy_outcome_exposed != bool(self.exposure_artifact_sha256):
            raise ValueError(self._safe_validation_message)
        if self.pool in OUTCOME_BLIND_POOLS and self.legacy_outcome_exposed:
            raise ValueError(self._safe_validation_message)
        expected = "pool_task_" + _digest(
            self.model_dump(mode="python", exclude={"membership_id"})
        )
        if self.membership_id != expected:
            raise ValueError(self._safe_validation_message)
        return self


class PoolPartitionManifest(_PoolContract):
    """One immutable eight-pool allocation with cluster-level non-overlap enforced."""

    schema_version: Literal["2.0"] = "2.0"
    manifest_id: str = Field(pattern=_MANIFEST_ID)
    partition_version: str
    semantic_cluster_policy_sha256: str = Field(pattern=_SHA256)
    source_inventory_sha256: str = Field(pattern=_SHA256)
    tasks: tuple[PoolTaskRecord, ...] = Field(min_length=1)

    @field_validator("tasks", mode="before")
    @classmethod
    def freeze_tasks(cls, value: object) -> object:
        if type(value) is list:
            return tuple(value)
        return value

    @classmethod
    def from_content(
        cls,
        *,
        partition_version: str,
        semantic_cluster_policy_sha256: str,
        source_inventory_sha256: str,
        tasks: tuple[PoolTaskRecord, ...],
    ) -> PoolPartitionManifest:
        ordered = tuple(
            sorted(
                tasks,
                key=lambda item: (
                    item.semantic_task_cluster_id,
                    item.task_instance_id,
                    item.membership_id,
                ),
            )
        )
        content: dict[str, Any] = {
            "schema_version": "2.0",
            "partition_version": partition_version,
            "semantic_cluster_policy_sha256": semantic_cluster_policy_sha256,
            "source_inventory_sha256": source_inventory_sha256,
            "tasks": ordered,
        }
        return cls(manifest_id=f"pool_partition_{_digest(content)}", **content)

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if not _valid_identifier(self.partition_version):
            raise ValueError(self._safe_validation_message)
        if tuple(self.tasks) != tuple(
            sorted(
                self.tasks,
                key=lambda item: (
                    item.semantic_task_cluster_id,
                    item.task_instance_id,
                    item.membership_id,
                ),
            )
        ):
            raise ValueError(self._safe_validation_message)
        task_ids = [item.task_instance_id for item in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError(self._safe_validation_message)
        membership_ids = [item.membership_id for item in self.tasks]
        if len(membership_ids) != len(set(membership_ids)):
            raise ValueError(self._safe_validation_message)
        pools_by_cluster: dict[str, set[EvidencePool]] = defaultdict(set)
        cwes_by_cluster: dict[str, set[str]] = defaultdict(set)
        templates_by_cluster: dict[str, set[str]] = defaultdict(set)
        for item in self.tasks:
            pools_by_cluster[item.semantic_task_cluster_id].add(item.pool)
            cwes_by_cluster[item.semantic_task_cluster_id].add(item.cwe_id)
            templates_by_cluster[item.semantic_task_cluster_id].add(item.template_family_id)
        if any(len(pools) != 1 for pools in pools_by_cluster.values()):
            raise ValueError(self._safe_validation_message)
        if any(len(cwes) != 1 for cwes in cwes_by_cluster.values()):
            raise ValueError(self._safe_validation_message)
        if any(len(templates) != 1 for templates in templates_by_cluster.values()):
            raise ValueError(self._safe_validation_message)
        expected = "pool_partition_" + _digest(
            self.model_dump(mode="python", exclude={"manifest_id"})
        )
        if self.manifest_id != expected:
            raise ValueError(self._safe_validation_message)
        return self

    def counts_by_pool(self) -> dict[str, int]:
        counts = Counter(item.pool.value for item in self.tasks)
        return {pool.value: counts[pool.value] for pool in EvidencePool}

    def pool_is_claim_eligible(self, pool: EvidencePool) -> bool:
        return pool in EVIDENCE_ELIGIBLE_POOLS


__all__ = [
    "EVIDENCE_ELIGIBLE_POOLS",
    "OUTCOME_BLIND_POOLS",
    "ContractStatus",
    "EvidencePool",
    "PoolPartitionManifest",
    "PoolTaskRecord",
]

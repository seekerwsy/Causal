"""Outcome-blind source inventory and hypothesis protocol-root contracts.

The protocol root is the pre-randomization trust anchor for one frozen policy
hypothesis.  It deliberately points only upstream: selection, intervention,
source inventory, replayable natural-Prompt query evidence, pool/cluster
allocation, and the common-support population.  Generated code, assignments,
outcomes, and analyses cannot appear in this DAG.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.phased_exploration.pools import (
    OUTCOME_BLIND_POOLS,
    ContractStatus,
    EvidencePool,
    PoolPartitionManifest,
)
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.intervention_v2 import InterventionBridgeRecordV2
from secaware.schema.policy_v2 import (
    BridgeStatus,
    CandidateUniverseManifest,
    PolicySplit,
    SelectionFreezeManifest,
    SemanticTaskClusterManifest,
)
from secaware.schema.population_v2 import PopulationFreezeManifestV2
from secaware.schema.query_evidence_v2 import QueryEvidenceManifestV2
from secaware.schema.variant_evidence_v2 import VariantInvariantEvidenceManifestV2

PROTOCOL_FREEZE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_SOURCE_TASK_ID_PATTERN = r"^source_inventory_task_[0-9a-f]{64}$"
_PROTOCOL_ROOT_ID_PATTERN = r"^protocol_freeze_v2_[0-9a-f]{64}$"


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _snapshot_json_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_json_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_json_arrays(item) for item in value)
    return value


class _ProtocolFreezeV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "protocol freeze v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = PROTOCOL_FREEZE_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_json_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedProtocolFreezeV2(_ProtocolFreezeV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": PROTOCOL_FREEZE_V2_SCHEMA_VERSION, **content}
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            content.clear()
            if payload is not None:
                payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class SourceInventoryTaskRecordV2(_ContentAddressedProtocolFreezeV2):
    """One outcome-free task snapshot, before clustering or pool assignment."""

    _id_field = "source_inventory_task_id"
    _id_prefix = "source_inventory_task_"

    source_inventory_task_id: str = Field(pattern=_SOURCE_TASK_ID_PATTERN)
    source_task_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_instance_id: str
    source_id: str
    source_record_id: str
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    cwe_id: str
    archetype_id: str
    template_family_id: str
    language: Literal["python"]
    functional_contract_status: ContractStatus
    security_contract_status: ContractStatus
    legacy_outcome_exposed: bool
    exposure_artifact_sha256: tuple[str, ...]
    generated_code_outcomes_excluded: Literal[True]

    @field_validator("functional_contract_status", "security_contract_status", mode="before")
    @classmethod
    def parse_contract_status(cls, value: object) -> object:
        if isinstance(value, ContractStatus):
            return value
        if type(value) is str:
            return next((item for item in ContractStatus if item.value == value), value)
        return value

    @classmethod
    def from_source(
        cls,
        *,
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
    ) -> Self:
        source_content = {
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
            "exposure_artifact_sha256": tuple(sorted(exposure_artifact_sha256)),
            "generated_code_outcomes_excluded": True,
        }
        versioned_source_content = {
            "schema_version": PROTOCOL_FREEZE_V2_SCHEMA_VERSION,
            **source_content,
        }
        return cls.from_content(
            source_task_sha256=_digest(versioned_source_content), **source_content
        )

    @model_validator(mode="after")
    def validate_source_snapshot(self) -> Self:
        source_content = self.model_dump(
            mode="json",
            exclude={"source_inventory_task_id", "source_task_sha256"},
        )
        identifiers = (
            self.task_instance_id,
            self.source_id,
            self.source_record_id,
            self.archetype_id,
            self.template_family_id,
        )
        if (
            not all(_valid_identifier(item) for item in identifiers)
            or _CWE_RE.fullmatch(self.cwe_id) is None
            or self.exposure_artifact_sha256 != tuple(sorted(self.exposure_artifact_sha256))
            or len(self.exposure_artifact_sha256) != len(set(self.exposure_artifact_sha256))
            or any(
                re.fullmatch(_SHA256_PATTERN, item) is None
                for item in self.exposure_artifact_sha256
            )
            or self.legacy_outcome_exposed != bool(self.exposure_artifact_sha256)
            or self.source_task_sha256 != _digest(source_content)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SourceInventoryManifestV2(_ContentAddressedProtocolFreezeV2):
    """Complete, embedded, outcome-blind task inventory consumed by one partition."""

    _id_field = "source_inventory_sha256"
    _id_prefix = ""

    source_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    tasks: tuple[SourceInventoryTaskRecordV2, ...] = Field(min_length=1, max_length=1_000_000)
    source_registry_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    inventory_construction_sha256: str = Field(pattern=_SHA256_PATTERN)
    generated_code_outcomes_excluded: Literal[True]
    frozen_before_pool_partition: Literal[True]
    frozen_before_confirmation_outcomes: Literal[True]

    @classmethod
    def from_tasks(
        cls,
        *,
        tasks: tuple[SourceInventoryTaskRecordV2, ...],
        source_registry_snapshot_sha256: str,
        inventory_construction_sha256: str,
    ) -> Self:
        ordered = tuple(
            sorted(
                (SourceInventoryTaskRecordV2.model_validate(item, strict=True) for item in tasks),
                key=lambda item: (item.task_instance_id, item.source_inventory_task_id),
            )
        )
        return cls.from_content(
            tasks=ordered,
            source_registry_snapshot_sha256=source_registry_snapshot_sha256,
            inventory_construction_sha256=inventory_construction_sha256,
            generated_code_outcomes_excluded=True,
            frozen_before_pool_partition=True,
            frozen_before_confirmation_outcomes=True,
        )

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        order = tuple((item.task_instance_id, item.source_inventory_task_id) for item in self.tasks)
        task_ids = tuple(item.task_instance_id for item in self.tasks)
        source_task_digests = tuple(item.source_task_sha256 for item in self.tasks)
        if (
            order != tuple(sorted(order))
            or len(task_ids) != len(set(task_ids))
            or len(source_task_digests) != len(set(source_task_digests))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class ProtocolFreezeRootV2(_ContentAddressedProtocolFreezeV2):
    """Pre-randomization trust root for one selected intervention policy hypothesis."""

    _id_field = "protocol_freeze_id"
    _id_prefix = "protocol_freeze_v2_"

    protocol_freeze_id: str = Field(pattern=_PROTOCOL_ROOT_ID_PATTERN)
    candidate_universe: CandidateUniverseManifest
    selection_freeze: SelectionFreezeManifest
    intervention_bridge: InterventionBridgeRecordV2
    source_inventory: SourceInventoryManifestV2
    pool_partition: PoolPartitionManifest
    semantic_cluster_manifest: SemanticTaskClusterManifest
    population: PopulationFreezeManifestV2
    query_evidence: QueryEvidenceManifestV2
    variant_evidence: VariantInvariantEvidenceManifestV2
    preregistered_minimum_gate_pass_tasks: StrictInt = Field(ge=1)
    preregistered_minimum_gate_pass_clusters: StrictInt = Field(ge=1)
    outcome_blind: Literal[True]
    frozen_before_randomization: Literal[True]
    downstream_records_excluded: Literal["randomization_assignment_runtime_outcome_analysis"]

    @classmethod
    def from_components(
        cls,
        *,
        candidate_universe: CandidateUniverseManifest,
        selection_freeze: SelectionFreezeManifest,
        intervention_bridge: InterventionBridgeRecordV2,
        source_inventory: SourceInventoryManifestV2,
        pool_partition: PoolPartitionManifest,
        semantic_cluster_manifest: SemanticTaskClusterManifest,
        population: PopulationFreezeManifestV2,
        query_evidence: QueryEvidenceManifestV2,
        variant_evidence: VariantInvariantEvidenceManifestV2,
        preregistered_minimum_gate_pass_tasks: int,
        preregistered_minimum_gate_pass_clusters: int,
    ) -> Self:
        try:
            return cls.from_content(
                candidate_universe=CandidateUniverseManifest.model_validate(
                    candidate_universe, strict=True
                ),
                selection_freeze=SelectionFreezeManifest.model_validate(
                    selection_freeze, strict=True
                ),
                intervention_bridge=InterventionBridgeRecordV2.model_validate(
                    intervention_bridge, strict=True
                ),
                source_inventory=SourceInventoryManifestV2.model_validate(
                    source_inventory, strict=True
                ),
                pool_partition=PoolPartitionManifest.model_validate(pool_partition, strict=True),
                semantic_cluster_manifest=SemanticTaskClusterManifest.model_validate(
                    semantic_cluster_manifest, strict=True
                ),
                population=PopulationFreezeManifestV2.model_validate(population, strict=True),
                query_evidence=QueryEvidenceManifestV2.model_validate(query_evidence, strict=True),
                variant_evidence=VariantInvariantEvidenceManifestV2.model_validate(
                    variant_evidence, strict=True
                ),
                preregistered_minimum_gate_pass_tasks=(preregistered_minimum_gate_pass_tasks),
                preregistered_minimum_gate_pass_clusters=(preregistered_minimum_gate_pass_clusters),
                outcome_blind=True,
                frozen_before_randomization=True,
                downstream_records_excluded=("randomization_assignment_runtime_outcome_analysis"),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public trust boundary
            raise cls._safe_error() from None

    @property
    def semantic_sha256(self) -> str:
        return self.protocol_freeze_id.removeprefix("protocol_freeze_v2_")

    @model_validator(mode="after")
    def validate_protocol_root(self) -> Self:
        universe = self.candidate_universe
        selection = self.selection_freeze
        bridge = self.intervention_bridge
        inventory = self.source_inventory
        partition = self.pool_partition
        clusters = self.semantic_cluster_manifest
        population = self.population
        query_evidence = self.query_evidence
        variant_evidence = self.variant_evidence
        hypothesis = bridge.frozen_hypothesis

        universe_by_id = {item.candidate_skeleton_id: item for item in universe.skeletons}
        selected_ids = {
            item.candidate_skeleton_id
            for item in selection.selector_slots
            if item.candidate_skeleton_id is not None
        }
        bridge_mappings = tuple(
            item
            for item in selection.mappings
            if item.candidate_skeleton_id == bridge.candidate_skeleton.candidate_skeleton_id
        )
        bridge_digest = bridge.intervention_bridge_id.removeprefix("intervention_bridge_")
        if (
            selection.candidate_universe_id != universe.candidate_universe_id
            or universe_by_id.get(bridge.candidate_skeleton.candidate_skeleton_id)
            != bridge.candidate_skeleton
            or bridge.candidate_skeleton.candidate_skeleton_id not in selected_ids
            or len(bridge_mappings) != 1
            or bridge_mappings[0].status is not BridgeStatus.PROTOCOLIZED
            or bridge_mappings[0].final_hypothesis_id != hypothesis.hypothesis_id
            or bridge_mappings[0].bridge_record_sha256 != bridge_digest
        ):
            raise ValueError(self._safe_validation_message)

        if (
            population.pool_partition != partition
            or population.semantic_cluster_manifest != clusters
            or population.hypothesis != hypothesis
            or population.common_model_scope != hypothesis.model_scope
            or hypothesis.target_spec_id != bridge.target_spec.target_spec_id
            or hypothesis.arm_protocol_id != bridge.arm_protocol.arm_protocol_id
            or hypothesis.realization_policy_spec_id
            != bridge.realization_policy.realization_policy_spec_id
            or hypothesis.realization_spec_ids
            != tuple(item.realization_spec_id for item in bridge.realizations)
            or population.minimum_gate_pass_tasks != self.preregistered_minimum_gate_pass_tasks
            or population.minimum_gate_pass_clusters
            != self.preregistered_minimum_gate_pass_clusters
            or population.gate_pass_task_count < self.preregistered_minimum_gate_pass_tasks
            or population.gate_pass_cluster_count < self.preregistered_minimum_gate_pass_clusters
            or population.confirmation_pool not in OUTCOME_BLIND_POOLS
            or query_evidence.context_query != bridge.context_query
            or query_evidence.actionable_feature != bridge.actionable_feature
            or query_evidence.operation is not hypothesis.operation
            or query_evidence.extractor_policy_sha256
            != bridge.realization_policy.extractor_policy_sha256
            or query_evidence.context_query_catalog_sha256
            != bridge.candidate_skeleton.context_query_catalog_sha256
            or query_evidence.feature_catalog_sha256
            != bridge.candidate_skeleton.feature_catalog_sha256
            or query_evidence.eligibility_function_sha256
            != bridge.candidate_skeleton.eligibility_function_sha256
            or variant_evidence.intervention_bridge != bridge
            or variant_evidence.query_evidence != query_evidence
            or variant_evidence.population != population
            or variant_evidence.retained_task_ids != population.gate_pass_task_ids
        ):
            raise ValueError(self._safe_validation_message)

        if (
            partition.source_inventory_sha256 != inventory.source_inventory_sha256
            or partition.semantic_cluster_policy_sha256 != clusters.clustering_algorithm_sha256
        ):
            raise ValueError(self._safe_validation_message)

        inventory_by_task = {item.task_instance_id: item for item in inventory.tasks}
        pool_by_task = {item.task_instance_id: item for item in partition.tasks}
        membership_by_task = {item.task_instance_id: item for item in clusters.memberships}
        if set(inventory_by_task) != set(pool_by_task) or set(pool_by_task) != set(
            membership_by_task
        ):
            raise ValueError(self._safe_validation_message)

        for task_id, source in inventory_by_task.items():
            pool_task = pool_by_task[task_id]
            membership = membership_by_task[task_id]
            if (
                source.source_id != pool_task.source_id
                or source.source_record_id != pool_task.source_record_id
                or source.prompt_sha256 != pool_task.prompt_sha256
                or source.cwe_id != pool_task.cwe_id
                or source.archetype_id != pool_task.archetype_id
                or source.template_family_id != pool_task.template_family_id
                or source.language != pool_task.language
                or source.functional_contract_status != pool_task.functional_contract_status
                or source.security_contract_status != pool_task.security_contract_status
                or source.legacy_outcome_exposed != pool_task.legacy_outcome_exposed
                or source.exposure_artifact_sha256 != pool_task.exposure_artifact_sha256
                or source.source_task_sha256 != membership.source_task_sha256
                or pool_task.semantic_task_cluster_id != membership.semantic_task_cluster_id
                or pool_task.cwe_id != membership.cwe
                or pool_task.archetype_id != membership.task_archetype
            ):
                raise ValueError(self._safe_validation_message)

        scope_pool_tasks = {
            task_id: item
            for task_id, item in pool_by_task.items()
            if item.pool is population.confirmation_pool
            and item.cwe_id == hypothesis.cwe
            and item.archetype_id == hypothesis.task_archetype
        }
        scope_ids = set(scope_pool_tasks)
        gate_entry_ids = set(population.gate_entry_task_ids)
        query_evidence_by_task = {
            item.membership.task_instance_id: item for item in query_evidence.tasks
        }
        population_gate_by_task = {item.task_instance_id: item for item in population.task_gates}
        expected_split = (
            PolicySplit.REPLICATION
            if population.confirmation_pool is EvidencePool.REPLICATION
            else PolicySplit.CONFIRM
        )
        if (
            not scope_ids
            or scope_ids != gate_entry_ids
            or set(query_evidence_by_task) != gate_entry_ids
            or len(query_evidence_by_task) != len(query_evidence.tasks)
            or set(population_gate_by_task) != gate_entry_ids
            or scope_ids
            != {
                task_id
                for task_id, item in membership_by_task.items()
                if task_id in scope_ids
                and item.cwe == hypothesis.cwe
                and item.task_archetype == hypothesis.task_archetype
                and item.split is expected_split
            }
        ):
            raise ValueError(self._safe_validation_message)

        for task_id in sorted(gate_entry_ids):
            evidence = query_evidence_by_task[task_id]
            source = inventory_by_task[task_id]
            pool_task = pool_by_task[task_id]
            membership = membership_by_task[task_id]
            gate = population_gate_by_task[task_id]
            support = gate.task_policy_support
            if (
                evidence.membership != membership
                or evidence.natural_prompt.task_id != task_id
                or evidence.natural_prompt.prompt_sha256 != source.prompt_sha256
                or evidence.natural_prompt.prompt_sha256 != pool_task.prompt_sha256
                or evidence.natural_prompt.cwe != source.cwe_id
                or evidence.natural_prompt.language != source.language
                or evidence.eligibility != gate.eligibility
                or evidence.eligibility.natural_prompt_id != evidence.natural_prompt.prompt_id
                or evidence.eligibility.prompt_tsg_sha256 != evidence.prompt_tsg.graph_sha256
                or (
                    support is not None
                    and any(
                        bundle.source_prompt_id != evidence.natural_prompt.prompt_id
                        or bundle.source_prompt_sha256 != evidence.natural_prompt.prompt_sha256
                        for bundle in support.task_realization_bundles
                    )
                )
            ):
                raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "PROTOCOL_FREEZE_V2_SCHEMA_VERSION",
    "ProtocolFreezeRootV2",
    "SourceInventoryManifestV2",
    "SourceInventoryTaskRecordV2",
]

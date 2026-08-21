"""Prospective common-support population freeze for the v2 confirmation protocol.

The population is frozen before assignment.  It is deliberately closed over the
upstream pool partition, semantic-cluster manifest, hypothesis, per-task natural
Prompt eligibility decision, and complete realization support.  No outcome or
post-assignment diagnostic is accepted by these contracts.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from fractions import Fraction
from typing import Any, ClassVar, Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.phased_exploration.pools import (
    EvidencePool,
    PoolPartitionManifest,
    PoolTaskRecord,
)
from secaware.records import (
    FrozenResearchRecord,
)
from secaware.records import (
    raise_record_validation_error as _raise_contract_error,
)
from secaware.records import (
    record_sha256 as _digest,
)
from secaware.records import (
    snapshot_json_arrays as _snapshot_arrays,
)
from secaware.records import (
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.policy_v2 import (
    EligibilityExclusionReason,
    FrozenPolicyHypothesisRecord,
    PolicySplit,
    PreOutcomeEligibilityRecord,
    QueryState,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
    TaskPolicySupportRecord,
)

POPULATION_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GATE_ID_PATTERN = r"^population_task_gate_[0-9a-f]{64}$"
_POPULATION_ID_PATTERN = r"^population_freeze_v2_[0-9a-f]{64}$"

_CONFIRMATION_POOLS = frozenset(
    {
        EvidencePool.DEV_CONFIRM,
        EvidencePool.FORMAL_CONFIRM,
        EvidencePool.REPLICATION,
    }
)


def _stratum_id(cwe: str, task_archetype: str) -> str:
    return f"stratum:{cwe}:{task_archetype}"


_QUERY_STATE_DOMAIN = tuple(item.value for item in QueryState)
_EXCLUSION_REASON_DOMAIN = tuple(
    sorted(
        {
            *(item.value for item in EligibilityExclusionReason),
            "task_policy_support_missing",
        }
    )
)


def _domain_counts(values: tuple[str, ...], domain: tuple[str, ...]) -> tuple[NamedCountV2, ...]:
    counts = Counter(values)
    if not set(values).issubset(domain):
        raise ValueError("population count domain mismatch")
    return tuple(NamedCountV2(name=name, count=counts[name]) for name in sorted(domain))


class _PopulationV2Contract(FrozenResearchRecord):
    _safe_validation_message: ClassVar[str] = "population v2 contract failed validation"

    @model_validator(mode="before")
    @classmethod
    def snapshot_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)


class _ContentAddressedPopulationV2(_PopulationV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": POPULATION_V2_SCHEMA_VERSION, **content}
            record_id = cls._id_prefix + _digest(payload)
            return cls(**payload, **{cls._id_field: record_id})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            content.clear()
            if payload is not None:
                payload.clear()
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class RationalWeightV2(_PopulationV2Contract):
    """One exact, reduced, positive rational probability weight."""

    numerator: StrictInt = Field(ge=1, le=2**31 - 1)
    denominator: StrictInt = Field(ge=1, le=2**31 - 1)

    @model_validator(mode="after")
    def validate_reduced_fraction(self) -> Self:
        if self.numerator > self.denominator or math.gcd(self.numerator, self.denominator) != 1:
            raise ValueError(self._safe_validation_message)
        return self

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


class NamedCountV2(_PopulationV2Contract):
    """A frozen audit count keyed by an enum value or typed exclusion reason."""

    name: str
    count: StrictInt = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_name(self) -> Self:
        if not _valid_identifier(self.name):
            raise ValueError(self._safe_validation_message)
        return self


class ClusterWeightBindingV2(_PopulationV2Contract):
    semantic_task_cluster_id: str
    weight: RationalWeightV2

    @model_validator(mode="after")
    def validate_cluster(self) -> Self:
        if not _valid_identifier(self.semantic_task_cluster_id):
            raise ValueError(self._safe_validation_message)
        return self


class ResamplingStratumV2(_PopulationV2Contract):
    """Equal-cluster weighting for one frozen CWE/archetype resampling stratum."""

    stratum_id: str
    cwe: str
    task_archetype: str
    cluster_weights: tuple[ClusterWeightBindingV2, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_stratum(self) -> Self:
        cluster_ids = tuple(item.semantic_task_cluster_id for item in self.cluster_weights)
        expected = Fraction(1, len(cluster_ids))
        if (
            self.stratum_id != _stratum_id(self.cwe, self.task_archetype)
            or not _valid_identifier(self.task_archetype)
            or cluster_ids != tuple(sorted(cluster_ids))
            or len(cluster_ids) != len(set(cluster_ids))
            or any(item.weight.fraction != expected for item in self.cluster_weights)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PopulationTaskGateRecordV2(_ContentAddressedPopulationV2):
    """Total pre-assignment gate decision for one task in the hypothesis scope."""

    _id_field: ClassVar[str] = "population_task_gate_id"
    _id_prefix: ClassVar[str] = "population_task_gate_"

    schema_version: Literal["2.0"]
    population_task_gate_id: str = Field(pattern=_GATE_ID_PATTERN)
    pool_membership_id: str
    cluster_membership_id: str
    semantic_task_cluster_id: str
    task_instance_id: str
    hypothesis_id: str
    eligibility: PreOutcomeEligibilityRecord
    task_policy_support: TaskPolicySupportRecord | None
    common_model_scope: tuple[str, ...] = Field(min_length=1, max_length=64)
    stratum_id: str
    gate_entered: Literal[True]
    gate_passed: bool
    exclusion_reason: str | None
    within_cluster_task_weight: RationalWeightV2 | None

    @classmethod
    def from_components(
        cls,
        *,
        pool_task: PoolTaskRecord,
        cluster_membership: SemanticTaskClusterMembershipRecord,
        hypothesis: FrozenPolicyHypothesisRecord,
        eligibility: PreOutcomeEligibilityRecord,
        task_policy_support: TaskPolicySupportRecord | None,
        within_cluster_task_weight: RationalWeightV2 | None,
    ) -> Self:
        try:
            pool_record = PoolTaskRecord.model_validate(pool_task, strict=True)
            membership = SemanticTaskClusterMembershipRecord.model_validate(
                cluster_membership, strict=True
            )
            checked_hypothesis = FrozenPolicyHypothesisRecord.model_validate(
                hypothesis, strict=True
            )
            checked_eligibility = PreOutcomeEligibilityRecord.model_validate(
                eligibility, strict=True
            )
            support = (
                None
                if task_policy_support is None
                else TaskPolicySupportRecord.model_validate(task_policy_support, strict=True)
            )
            weight = (
                None
                if within_cluster_task_weight is None
                else RationalWeightV2.model_validate(within_cluster_task_weight, strict=True)
            )
            gate_passed = checked_eligibility.eligible and support is not None
            if not checked_eligibility.eligible:
                if checked_eligibility.exclusion_reason is None:
                    raise ValueError
                exclusion_reason = checked_eligibility.exclusion_reason.value
            elif support is None:
                exclusion_reason = "task_policy_support_missing"
            else:
                exclusion_reason = None
            return cls.from_content(
                pool_membership_id=pool_record.membership_id,
                cluster_membership_id=membership.cluster_membership_id,
                semantic_task_cluster_id=pool_record.semantic_task_cluster_id,
                task_instance_id=pool_record.task_instance_id,
                hypothesis_id=checked_hypothesis.hypothesis_id,
                eligibility=checked_eligibility,
                task_policy_support=support,
                common_model_scope=checked_hypothesis.model_scope,
                stratum_id=_stratum_id(checked_hypothesis.cwe, checked_hypothesis.task_archetype),
                gate_entered=True,
                gate_passed=gate_passed,
                exclusion_reason=exclusion_reason,
                within_cluster_task_weight=weight,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @model_validator(mode="after")
    def validate_gate_shape(self) -> Self:
        expected_pass = self.eligibility.eligible and self.task_policy_support is not None
        if not self.eligibility.eligible:
            expected_reason = (
                None
                if self.eligibility.exclusion_reason is None
                else self.eligibility.exclusion_reason.value
            )
        elif self.task_policy_support is None:
            expected_reason = "task_policy_support_missing"
        else:
            expected_reason = None
        if (
            not _valid_identifier(self.pool_membership_id)
            or not _valid_identifier(self.cluster_membership_id)
            or not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.hypothesis_id)
            or not _valid_identifier(self.stratum_id)
            or tuple(self.common_model_scope) != tuple(sorted(self.common_model_scope))
            or len(self.common_model_scope) != len(set(self.common_model_scope))
            or any(not is_valid_model_id(item) for item in self.common_model_scope)
            or self.eligibility.task_instance_id != self.task_instance_id
            or self.gate_passed != expected_pass
            or self.exclusion_reason != expected_reason
            or self.gate_passed != (self.within_cluster_task_weight is not None)
            or (not self.eligibility.eligible and self.task_policy_support is not None)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PopulationFreezeManifestV2(_ContentAddressedPopulationV2):
    """One immutable, cross-model common-support population for one hypothesis."""

    _id_field: ClassVar[str] = "population_freeze_manifest_id"
    _id_prefix: ClassVar[str] = "population_freeze_v2_"

    schema_version: Literal["2.0"]
    population_freeze_manifest_id: str = Field(pattern=_POPULATION_ID_PATTERN)
    pool_partition: PoolPartitionManifest
    semantic_cluster_manifest: SemanticTaskClusterManifest
    hypothesis: FrozenPolicyHypothesisRecord
    confirmation_pool: EvidencePool
    task_gates: tuple[PopulationTaskGateRecordV2, ...] = Field(min_length=1)
    strata: tuple[ResamplingStratumV2, ...] = Field(min_length=1)
    common_model_scope: tuple[str, ...] = Field(min_length=1, max_length=64)
    gate_entry_task_ids: tuple[str, ...] = Field(min_length=1)
    gate_pass_task_ids: tuple[str, ...] = Field(min_length=1)
    excluded_task_ids: tuple[str, ...]
    gate_entry_cluster_ids: tuple[str, ...] = Field(min_length=1)
    gate_pass_cluster_ids: tuple[str, ...] = Field(min_length=1)
    gate_entry_task_count: StrictInt = Field(ge=1)
    gate_pass_task_count: StrictInt = Field(ge=1)
    excluded_task_count: StrictInt = Field(ge=0)
    gate_entry_cluster_count: StrictInt = Field(ge=1)
    gate_pass_cluster_count: StrictInt = Field(ge=1)
    context_state_counts: tuple[NamedCountV2, ...]
    actionable_feature_state_counts: tuple[NamedCountV2, ...]
    exclusion_reason_counts: tuple[NamedCountV2, ...]
    minimum_gate_pass_tasks: StrictInt = Field(ge=1)
    minimum_gate_pass_clusters: StrictInt = Field(ge=1)
    population_construction_sha256: str = Field(pattern=_SHA256_PATTERN)
    weighting_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    stratification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    common_support_policy: Literal[
        "context_operation_and_complete_qh_support_no_deletion_no_renormalization"
    ]
    common_cross_model_gate: Literal["single_population_for_all_declared_models"]
    within_cluster_weight_policy: Literal["positive_reduced_rational_sum_one"]
    cluster_weight_policy: Literal["equal_within_frozen_stratum"]
    frozen_before_assignment: Literal[True]

    @field_validator("confirmation_pool", mode="before")
    @classmethod
    def parse_confirmation_pool(cls, value: object) -> object:
        if isinstance(value, EvidencePool):
            return value
        if type(value) is str:
            return next((item for item in EvidencePool if item.value == value), value)
        return value

    @classmethod
    def from_components(
        cls,
        *,
        pool_partition: PoolPartitionManifest,
        semantic_cluster_manifest: SemanticTaskClusterManifest,
        hypothesis: FrozenPolicyHypothesisRecord,
        confirmation_pool: EvidencePool,
        task_gates: tuple[PopulationTaskGateRecordV2, ...],
        strata: tuple[ResamplingStratumV2, ...],
        minimum_gate_pass_tasks: int,
        minimum_gate_pass_clusters: int,
        population_construction_sha256: str,
        weighting_policy_sha256: str,
        stratification_policy_sha256: str,
    ) -> Self:
        try:
            partition = PoolPartitionManifest.model_validate(pool_partition, strict=True)
            clusters = SemanticTaskClusterManifest.model_validate(
                semantic_cluster_manifest, strict=True
            )
            checked_hypothesis = FrozenPolicyHypothesisRecord.model_validate(
                hypothesis, strict=True
            )
            gates = tuple(
                sorted(
                    (
                        PopulationTaskGateRecordV2.model_validate(item, strict=True)
                        for item in task_gates
                    ),
                    key=lambda item: item.task_instance_id,
                )
            )
            frozen_strata = tuple(
                sorted(
                    (ResamplingStratumV2.model_validate(item, strict=True) for item in strata),
                    key=lambda item: item.stratum_id,
                )
            )
            entry_task_ids = tuple(item.task_instance_id for item in gates)
            pass_task_ids = tuple(item.task_instance_id for item in gates if item.gate_passed)
            excluded_task_ids = tuple(
                item.task_instance_id for item in gates if not item.gate_passed
            )
            entry_cluster_ids = tuple(sorted({item.semantic_task_cluster_id for item in gates}))
            pass_cluster_ids = tuple(
                sorted({item.semantic_task_cluster_id for item in gates if item.gate_passed})
            )

            return cls.from_content(
                pool_partition=partition,
                semantic_cluster_manifest=clusters,
                hypothesis=checked_hypothesis,
                confirmation_pool=confirmation_pool,
                task_gates=gates,
                strata=frozen_strata,
                common_model_scope=checked_hypothesis.model_scope,
                gate_entry_task_ids=entry_task_ids,
                gate_pass_task_ids=pass_task_ids,
                excluded_task_ids=excluded_task_ids,
                gate_entry_cluster_ids=entry_cluster_ids,
                gate_pass_cluster_ids=pass_cluster_ids,
                gate_entry_task_count=len(entry_task_ids),
                gate_pass_task_count=len(pass_task_ids),
                excluded_task_count=len(excluded_task_ids),
                gate_entry_cluster_count=len(entry_cluster_ids),
                gate_pass_cluster_count=len(pass_cluster_ids),
                context_state_counts=_domain_counts(
                    tuple(item.eligibility.context_state.value for item in gates),
                    _QUERY_STATE_DOMAIN,
                ),
                actionable_feature_state_counts=_domain_counts(
                    tuple(item.eligibility.actionable_feature_state.value for item in gates),
                    _QUERY_STATE_DOMAIN,
                ),
                exclusion_reason_counts=_domain_counts(
                    tuple(
                        item.exclusion_reason for item in gates if item.exclusion_reason is not None
                    ),
                    _EXCLUSION_REASON_DOMAIN,
                ),
                minimum_gate_pass_tasks=minimum_gate_pass_tasks,
                minimum_gate_pass_clusters=minimum_gate_pass_clusters,
                population_construction_sha256=population_construction_sha256,
                weighting_policy_sha256=weighting_policy_sha256,
                stratification_policy_sha256=stratification_policy_sha256,
                common_support_policy=(
                    "context_operation_and_complete_qh_support_no_deletion_no_renormalization"
                ),
                common_cross_model_gate="single_population_for_all_declared_models",
                within_cluster_weight_policy="positive_reduced_rational_sum_one",
                cluster_weight_policy="equal_within_frozen_stratum",
                frozen_before_assignment=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the fail-closed boundary
            _raise_contract_error(cls)

    @property
    def semantic_sha256(self) -> str:
        return self.population_freeze_manifest_id.removeprefix("population_freeze_v2_")

    @model_validator(mode="after")
    def validate_population_closure(self) -> Self:
        if self.confirmation_pool not in _CONFIRMATION_POOLS:
            raise ValueError(self._safe_validation_message)
        expected_split = (
            PolicySplit.REPLICATION
            if self.confirmation_pool is EvidencePool.REPLICATION
            else PolicySplit.CONFIRM
        )
        pool_scope = {
            item.task_instance_id: item
            for item in self.pool_partition.tasks
            if item.pool is self.confirmation_pool
            and item.cwe_id == self.hypothesis.cwe
            and item.archetype_id == self.hypothesis.task_archetype
        }
        memberships = {
            item.task_instance_id: item for item in self.semantic_cluster_manifest.memberships
        }
        gates = {item.task_instance_id: item for item in self.task_gates}
        expected_entry_ids = tuple(sorted(pool_scope))
        pass_gates = tuple(item for item in self.task_gates if item.gate_passed)
        expected_pass_ids = tuple(item.task_instance_id for item in pass_gates)
        expected_excluded_ids = tuple(
            item.task_instance_id for item in self.task_gates if not item.gate_passed
        )
        expected_entry_clusters = tuple(
            sorted({item.semantic_task_cluster_id for item in self.task_gates})
        )
        expected_pass_clusters = tuple(
            sorted({item.semantic_task_cluster_id for item in pass_gates})
        )
        expected_stratum_id = _stratum_id(self.hypothesis.cwe, self.hypothesis.task_archetype)

        if (
            not pool_scope
            or len(gates) != len(self.task_gates)
            or tuple(item.task_instance_id for item in self.task_gates) != expected_entry_ids
            or set(pool_scope) != set(memberships).intersection(pool_scope)
            or self.gate_entry_task_ids != expected_entry_ids
            or self.gate_pass_task_ids != expected_pass_ids
            or self.excluded_task_ids != expected_excluded_ids
            or self.gate_entry_cluster_ids != expected_entry_clusters
            or self.gate_pass_cluster_ids != expected_pass_clusters
            or self.gate_entry_task_count != len(expected_entry_ids)
            or self.gate_pass_task_count != len(expected_pass_ids)
            or self.excluded_task_count != len(expected_excluded_ids)
            or self.gate_entry_cluster_count != len(expected_entry_clusters)
            or self.gate_pass_cluster_count != len(expected_pass_clusters)
            or self.gate_pass_task_count < self.minimum_gate_pass_tasks
            or self.gate_pass_cluster_count < self.minimum_gate_pass_clusters
            or self.common_model_scope != self.hypothesis.model_scope
            or any(item.stratum_id != expected_stratum_id for item in self.task_gates)
            or any(item.common_model_scope != self.common_model_scope for item in self.task_gates)
        ):
            raise ValueError(self._safe_validation_message)

        for task_id, gate in gates.items():
            pool_task = pool_scope[task_id]
            membership = memberships[task_id]
            support = gate.task_policy_support
            if (
                gate.pool_membership_id != pool_task.membership_id
                or gate.cluster_membership_id != membership.cluster_membership_id
                or gate.semantic_task_cluster_id != pool_task.semantic_task_cluster_id
                or gate.semantic_task_cluster_id != membership.semantic_task_cluster_id
                or membership.split is not expected_split
                or membership.cwe != self.hypothesis.cwe
                or membership.task_archetype != self.hypothesis.task_archetype
                or gate.hypothesis_id != self.hypothesis.hypothesis_id
                or gate.eligibility.operation is not self.hypothesis.operation
            ):
                raise ValueError(self._safe_validation_message)
            if support is None:
                continue
            if (
                support.hypothesis_id != self.hypothesis.hypothesis_id
                or support.semantic_task_cluster_id != gate.semantic_task_cluster_id
                or support.task_instance_id != task_id
                or support.realization_policy_spec_id != self.hypothesis.realization_policy_spec_id
                or support.realization_spec_ids != self.hypothesis.realization_spec_ids
                or support.probability_numerators != self.hypothesis.probability_numerators
                or support.probability_denominator != self.hypothesis.probability_denominator
                or any(
                    bundle.source_prompt_sha256 != pool_task.prompt_sha256
                    for bundle in support.task_realization_bundles
                )
            ):
                raise ValueError(self._safe_validation_message)

        tasks_by_cluster: dict[str, list[PopulationTaskGateRecordV2]] = defaultdict(list)
        for gate in pass_gates:
            tasks_by_cluster[gate.semantic_task_cluster_id].append(gate)
        for cluster_gates in tasks_by_cluster.values():
            total = sum(
                (
                    gate.within_cluster_task_weight.fraction
                    for gate in cluster_gates
                    if gate.within_cluster_task_weight is not None
                ),
                Fraction(0, 1),
            )
            if total != Fraction(1, 1):
                raise ValueError(self._safe_validation_message)

        if len(self.strata) != 1 or self.strata[0].stratum_id != expected_stratum_id:
            raise ValueError(self._safe_validation_message)
        stratum_clusters = tuple(
            item.semantic_task_cluster_id for item in self.strata[0].cluster_weights
        )
        if stratum_clusters != expected_pass_clusters:
            raise ValueError(self._safe_validation_message)

        if (
            self.context_state_counts
            != _domain_counts(
                tuple(item.eligibility.context_state.value for item in self.task_gates),
                _QUERY_STATE_DOMAIN,
            )
            or self.actionable_feature_state_counts
            != _domain_counts(
                tuple(item.eligibility.actionable_feature_state.value for item in self.task_gates),
                _QUERY_STATE_DOMAIN,
            )
            or self.exclusion_reason_counts
            != _domain_counts(
                tuple(
                    item.exclusion_reason
                    for item in self.task_gates
                    if item.exclusion_reason is not None
                ),
                _EXCLUSION_REASON_DOMAIN,
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "ClusterWeightBindingV2",
    "NamedCountV2",
    "PopulationFreezeManifestV2",
    "PopulationTaskGateRecordV2",
    "RationalWeightV2",
    "ResamplingStratumV2",
]

"""Frozen natural-Prompt discovery tables for the prospective v2 protocol.

The table specification is frozen before outcomes and therefore has an identity that
does not depend on observation rows.  Runtime observations reference that identity;
the later table artifact embeds the specification, exact slot support, observations,
and producer chains, closing the table/row circularity without allowing row deletion.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, StrictInt, field_validator, model_validator

from secaware.records import (
    ContentAddressedResearchRecord,
    FrozenResearchRecord,
    parse_exact_enum as _exact_enum,
    record_sha256 as _digest,
    valid_identifier as _valid_identifier,
)
from secaware.schema.common import is_valid_model_id
from secaware.schema.features import FeatureFamily
from secaware.schema.policy_v2 import (
    ActionableFeatureSpec,
    ContextQueryResultRecord,
    PolicySplit,
    QueryState,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.runtime_v2 import (
    NaturalCausalObservationRecordV2,
    RuntimeProducerChainRecordV2,
)
from secaware.schema.tsg import PromptTSGRecord

DISCOVERY_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_VARIABLE_RE = re.compile(r"^[wcxy]\.[a-z0-9][a-z0-9_.-]{0,126}$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_CONTEXT_QUERY_RE = re.compile(r"^context_query_[0-9a-f]{64}$")
_ACTIONABLE_QUERY_RE = re.compile(r"^actionable_feature_[0-9a-f]{64}$")
_VARIABLE_SPEC_PATTERN = r"^natural_variable_spec_[0-9a-f]{64}$"
_SLOT_SUPPORT_PATTERN = r"^discovery_slot_support_[0-9a-f]{64}$"
_TABLE_SPEC_PATTERN = r"^natural_table_spec_[0-9a-f]{64}$"
_TABLE_ARTIFACT_PATTERN = r"^natural_table_artifact_[0-9a-f]{64}$"
_TASK_BINDING_PATTERN = r"^natural_task_binding_[0-9a-f]{64}$"
_AUTHENTICATED_SCOPE_PATTERN = r"^authenticated_natural_scope_[0-9a-f]{64}$"

_QUERY_STATES = tuple(item.value for item in QueryState)
_BINARY_STATES = ("0", "1")
_JOINT_STATES = ("0", "1", "not_applicable")
_OUTCOME_STATES = {
    "y_c": _BINARY_STATES,
    "y_e": _BINARY_STATES,
    "y_secure_yield": _BINARY_STATES,
    "y_joint": _JOINT_STATES,
}


NATURAL_OUTCOME_PROJECTION_POLICY_SHA256 = _digest(
    {
        "policy": "natural-outcome-projection-v2.0",
        "inputs": ("generated_code", "oracle_result", "functional_result"),
        "outputs": ("y_c", "y_e", "y_joint", "y_secure_yield"),
        "infrastructure_failure": "fail_closed",
        "terminal_no_code": "zero_yield",
    }
)
NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256 = _digest(
    {
        "policy": "authenticated-natural-observation-assembly-v2.0",
        "x0": "canonical_prompt_tsg_query_projection",
        "y": NATURAL_OUTCOME_PROJECTION_POLICY_SHA256,
        "runtime_provenance": "embedded_exact_producer_chain",
    }
)


class _DiscoveryV2Contract(FrozenResearchRecord):
    _safe_validation_message = "natural discovery v2 contract failed validation"
    schema_version: Literal["2.0"] = DISCOVERY_V2_SCHEMA_VERSION


class _ContentAddressedDiscoveryV2(ContentAddressedResearchRecord):
    _safe_validation_message = "natural discovery v2 contract failed validation"
    _schema_version = DISCOVERY_V2_SCHEMA_VERSION
    schema_version: Literal["2.0"] = DISCOVERY_V2_SCHEMA_VERSION


class DiscoveryTableKindV2(StrEnum):
    DIRECT_FEATURE = "direct_feature"
    CONTEXT = "context"


class DiscoveryAnalysisKindV2(StrEnum):
    FIXED_REFERENCE = "fixed_reference"
    TWO_LEVEL = "two_level"
    MULTI_SLOT_SENSITIVITY = "multi_slot_sensitivity"


class DiscoveryVariableRoleV2(StrEnum):
    W = "w"
    X = "x"
    C = "c"
    Y = "y"


class DiscoveryVariableSourceV2(StrEnum):
    TASK_METADATA = "task_metadata"
    ACTIONABLE_QUERY = "actionable_query"
    CONTEXT_QUERY = "context_query"
    OUTCOME_PROJECTION = "outcome_projection"


class NaturalDiscoveryVariableSpecV2(_ContentAddressedDiscoveryV2):
    _id_field = "variable_spec_id"
    _id_prefix = "natural_variable_spec_"

    variable_spec_id: str = Field(pattern=_VARIABLE_SPEC_PATTERN)
    variable_id: str
    role: DiscoveryVariableRoleV2
    states: tuple[str, ...] = Field(min_length=2, max_length=256)
    source_kind: DiscoveryVariableSourceV2
    source_id: str
    source_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str | None = None
    temporal_tier: StrictInt = Field(ge=0, le=2)
    adjacency_type: str

    @field_validator("role", mode="before")
    @classmethod
    def parse_role(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryVariableRoleV2)

    @field_validator("source_kind", mode="before")
    @classmethod
    def parse_source_kind(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryVariableSourceV2)

    @model_validator(mode="after")
    def validate_variable(self) -> Self:
        query_source = self.source_kind in {
            DiscoveryVariableSourceV2.ACTIONABLE_QUERY,
            DiscoveryVariableSourceV2.CONTEXT_QUERY,
        }
        expected_role = {
            DiscoveryVariableSourceV2.TASK_METADATA: DiscoveryVariableRoleV2.W,
            DiscoveryVariableSourceV2.ACTIONABLE_QUERY: DiscoveryVariableRoleV2.X,
            DiscoveryVariableSourceV2.CONTEXT_QUERY: DiscoveryVariableRoleV2.C,
            DiscoveryVariableSourceV2.OUTCOME_PROJECTION: DiscoveryVariableRoleV2.Y,
        }[self.source_kind]
        expected_tier = {
            DiscoveryVariableRoleV2.W: 0,
            DiscoveryVariableRoleV2.X: 1,
            DiscoveryVariableRoleV2.C: 1,
            DiscoveryVariableRoleV2.Y: 2,
        }[self.role]
        if (
            _VARIABLE_RE.fullmatch(self.variable_id) is None
            or not self.variable_id.startswith(f"{self.role.value}.")
            or self.role is not expected_role
            or self.temporal_tier != expected_tier
            or not _valid_identifier(self.source_id)
            or not _valid_identifier(self.adjacency_type)
            or len(self.states) != len(set(self.states))
            or any(not _valid_identifier(item) for item in self.states)
            or query_source != (self.query_semantics_version is not None)
            or (
                self.query_semantics_version is not None
                and not _valid_identifier(self.query_semantics_version)
            )
        ):
            raise ValueError(self._safe_validation_message)
        if self.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY:
            valid_source = _ACTIONABLE_QUERY_RE.fullmatch(self.source_id) is not None
            valid_states = self.states == _QUERY_STATES
        elif self.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY:
            valid_source = _CONTEXT_QUERY_RE.fullmatch(self.source_id) is not None
            valid_states = self.states == _QUERY_STATES
        elif self.source_kind is DiscoveryVariableSourceV2.OUTCOME_PROJECTION:
            valid_source = self.source_id in _OUTCOME_STATES
            valid_states = self.states == _OUTCOME_STATES.get(self.source_id)
        else:
            valid_source = True
            valid_states = True
        if not valid_source or not valid_states:
            raise ValueError(self._safe_validation_message)
        return self


def _prompt_evidence_matches(prompt: str, attributes: object) -> bool:
    if not isinstance(attributes, dict):
        try:
            attributes = dict(attributes)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
    evidence_keys = {"evidence_start", "evidence_end", "evidence_sha256"}
    present = evidence_keys & set(attributes)
    if not present:
        return True
    if present != evidence_keys:
        return False
    start = attributes["evidence_start"]
    end = attributes["evidence_end"]
    digest = attributes["evidence_sha256"]
    return (
        type(start) is int
        and type(end) is int
        and type(digest) is str
        and 0 <= start < end <= len(prompt)
        and hashlib.sha256(prompt[start:end].encode("utf-8")).hexdigest() == digest
    )


class NaturalTaskBindingV2(_ContentAddressedDiscoveryV2):
    """One frozen task/prompt/PromptTSG identity, including excluded context tasks."""

    _id_field = "task_binding_id"
    _id_prefix = "natural_task_binding_"

    task_binding_id: str = Field(pattern=_TASK_BINDING_PATTERN)
    membership: SemanticTaskClusterMembershipRecord
    natural_prompt_id: str
    natural_prompt: str = Field(min_length=1, repr=False)
    natural_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_tsg: PromptTSGRecord
    prompt_tsg_sha256: str = Field(pattern=_SHA256_PATTERN)
    extractor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    feature_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str
    frozen_before_outcomes: Literal[True]

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        try:
            from secaware.tsg.context_queries_v2 import (
                CONTEXT_QUERY_CATALOG_SHA256,
                CONTEXT_QUERY_SEMANTICS_VERSION,
            )
            from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
            from secaware.tsg.graph import record_to_multidigraph

            membership = SemanticTaskClusterMembershipRecord.model_validate(
                self.membership, strict=True
            )
            graph_record = PromptTSGRecord.model_validate(self.prompt_tsg, strict=True)
            graph = record_to_multidigraph(graph_record)
            evidence_valid = all(
                _prompt_evidence_matches(self.natural_prompt, node["attributes"])
                for _, node in graph.nodes(data=True)
            ) and all(
                _prompt_evidence_matches(self.natural_prompt, edge["attributes"])
                for *_, edge in graph.edges(keys=True, data=True)
            )
            if (
                membership.split is not PolicySplit.DISCOVER
                or not _valid_identifier(self.natural_prompt_id)
                or not self.natural_prompt.strip()
                or self.natural_prompt_sha256
                != hashlib.sha256(self.natural_prompt.encode("utf-8")).hexdigest()
                or graph_record.prompt_id != self.natural_prompt_id
                or graph_record.task_id != membership.task_instance_id
                or graph_record.cwe != membership.cwe
                or self.prompt_tsg_sha256 != graph_record.graph_sha256
                or self.extractor_policy_sha256 != graph_record.extractor_policy_sha256
                or self.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or self.context_query_catalog_sha256 != CONTEXT_QUERY_CATALOG_SHA256
                or self.query_semantics_version != CONTEXT_QUERY_SEMANTICS_VERSION
                or not evidence_valid
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize PromptTSG/catalog boundary failures
            raise ValueError(self._safe_validation_message) from None
        return self


class DiscoveryTaskSlotSupportV2(_ContentAddressedDiscoveryV2):
    """Pre-outcome request-slot support and one fixed reference slot for a task."""

    _id_field = "slot_support_id"
    _id_prefix = "discovery_slot_support_"

    slot_support_id: str = Field(pattern=_SLOT_SUPPORT_PATTERN)
    semantic_task_cluster_id: str
    task_instance_id: str
    natural_prompt_id: str
    request_randomness_slots: tuple[StrictInt, ...] = Field(min_length=1, max_length=256)
    provider_seeds: tuple[StrictInt | None, ...] = Field(min_length=1, max_length=256)
    reference_slot: StrictInt = Field(ge=0, le=2_147_483_647)
    slot_freeze_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_outcomes: Literal[True]

    @field_validator("request_randomness_slots")
    @classmethod
    def validate_slot_values(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(item) is not int or not 0 <= item <= 2_147_483_647 for item in value):
            raise ValueError(cls._safe_validation_message)
        return value

    @field_validator("provider_seeds")
    @classmethod
    def validate_seed_values(cls, value: tuple[int | None, ...]) -> tuple[int | None, ...]:
        if any(
            item is not None and (type(item) is not int or not 0 <= item <= 2**63 - 1)
            for item in value
        ):
            raise ValueError(cls._safe_validation_message)
        return value

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        if (
            not _valid_identifier(self.semantic_task_cluster_id)
            or not _valid_identifier(self.task_instance_id)
            or not _valid_identifier(self.natural_prompt_id)
            or self.request_randomness_slots != tuple(sorted(self.request_randomness_slots))
            or len(self.request_randomness_slots) != len(set(self.request_randomness_slots))
            or len(self.provider_seeds) != len(self.request_randomness_slots)
            or self.reference_slot not in self.request_randomness_slots
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def seed_for_slot(self, slot: int) -> int | None:
        try:
            return self.provider_seeds[self.request_randomness_slots.index(slot)]
        except (ValueError, IndexError):
            raise ValueError(self._safe_validation_message) from None


class NaturalDiscoveryTableSpecV2(_ContentAddressedDiscoveryV2):
    """Outcome-blind table identity and exact source population/slot support."""

    _id_field = "table_spec_id"
    _id_prefix = "natural_table_spec_"

    table_spec_id: str = Field(pattern=_TABLE_SPEC_PATTERN)
    scope_id: str
    cwe: str
    task_archetypes: tuple[str, ...] = Field(min_length=1, max_length=128)
    model_id: str
    table_kind: DiscoveryTableKindV2
    analysis_kind: DiscoveryAnalysisKindV2
    semantic_cluster_manifest: SemanticTaskClusterManifest
    context_conditioning_query_id: str | None = Field(default=None, pattern=_CONTEXT_QUERY_RE)
    context_query_results: tuple[ContextQueryResultRecord, ...] = Field(max_length=1_000_000)
    task_slot_support: tuple[DiscoveryTaskSlotSupportV2, ...] = Field(
        min_length=2, max_length=1_000_000
    )
    variables: tuple[NaturalDiscoveryVariableSpecV2, ...] = Field(min_length=2, max_length=128)
    missing_state_policy: Literal["categorical_four_state_v1"]
    two_level_selection_rule: Literal["not_applicable", "cluster_then_uniform_frozen_slot_v1"]
    multi_slot_aggregation_rule: Literal["not_applicable", "categorical_mode_tie_lowest_state_v1"]
    extractor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    outcome_projection_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    table_construction_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_outcomes: Literal[True]

    @field_validator("table_kind", mode="before")
    @classmethod
    def parse_table_kind(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryTableKindV2)

    @field_validator("analysis_kind", mode="before")
    @classmethod
    def parse_analysis_kind(cls, value: object) -> object:
        return _exact_enum(value, DiscoveryAnalysisKindV2)

    @model_validator(mode="after")
    def validate_spec(self) -> Self:
        relevant = tuple(
            item
            for item in self.semantic_cluster_manifest.memberships
            if item.split is PolicySplit.DISCOVER
            and item.cwe == self.cwe
            and item.task_archetype in self.task_archetypes
        )
        relevant_by_task = {item.task_instance_id: item for item in relevant}
        query_by_task = {item.task_instance_id: item for item in self.context_query_results}
        conditioned = self.context_conditioning_query_id is not None
        if conditioned:
            expected_task_ids = {
                task_id
                for task_id, item in query_by_task.items()
                if item.state is QueryState.PRESENT
            }
        else:
            expected_task_ids = set(relevant_by_task)
        support_by_task = {item.task_instance_id: item for item in self.task_slot_support}
        variable_ids = tuple(item.variable_id for item in self.variables)
        x_count = sum(item.role is DiscoveryVariableRoleV2.X for item in self.variables)
        c_count = sum(item.role is DiscoveryVariableRoleV2.C for item in self.variables)
        y_count = sum(item.role is DiscoveryVariableRoleV2.Y for item in self.variables)
        analysis_rules_valid = {
            DiscoveryAnalysisKindV2.FIXED_REFERENCE: (
                self.two_level_selection_rule == "not_applicable"
                and self.multi_slot_aggregation_rule == "not_applicable"
            ),
            DiscoveryAnalysisKindV2.TWO_LEVEL: (
                self.two_level_selection_rule == "cluster_then_uniform_frozen_slot_v1"
                and self.multi_slot_aggregation_rule == "not_applicable"
                and all(len(item.request_randomness_slots) >= 2 for item in self.task_slot_support)
            ),
            DiscoveryAnalysisKindV2.MULTI_SLOT_SENSITIVITY: (
                self.two_level_selection_rule == "not_applicable"
                and self.multi_slot_aggregation_rule == "categorical_mode_tie_lowest_state_v1"
                and all(len(item.request_randomness_slots) >= 2 for item in self.task_slot_support)
            ),
        }[self.analysis_kind]
        if (
            not _valid_identifier(self.scope_id)
            or _CWE_RE.fullmatch(self.cwe) is None
            or not is_valid_model_id(self.model_id)
            or self.task_archetypes != tuple(sorted(self.task_archetypes))
            or len(self.task_archetypes) != len(set(self.task_archetypes))
            or any(not _valid_identifier(item) for item in self.task_archetypes)
            or not relevant
            or len(relevant_by_task) != len(relevant)
            or conditioned != bool(self.context_query_results)
            or (
                conditioned
                and (
                    set(query_by_task) != set(relevant_by_task)
                    or len(query_by_task) != len(self.context_query_results)
                    or any(
                        item.context_query_id != self.context_conditioning_query_id
                        or item.natural_prompt_id
                        != support_by_task.get(task_id, item).natural_prompt_id
                        for task_id, item in query_by_task.items()
                        if task_id in support_by_task
                    )
                )
            )
            or set(support_by_task) != expected_task_ids
            or len(support_by_task) != len(self.task_slot_support)
            or any(
                item.semantic_task_cluster_id
                != relevant_by_task[item.task_instance_id].semantic_task_cluster_id
                for item in self.task_slot_support
            )
            or len({item.semantic_task_cluster_id for item in self.task_slot_support}) < 2
            or tuple(
                (item.semantic_task_cluster_id, item.task_instance_id)
                for item in self.task_slot_support
            )
            != tuple(
                sorted(
                    (item.semantic_task_cluster_id, item.task_instance_id)
                    for item in self.task_slot_support
                )
            )
            or variable_ids != tuple(sorted(variable_ids))
            or len(variable_ids) != len(set(variable_ids))
            or y_count < 1
            or (
                self.table_kind is DiscoveryTableKindV2.DIRECT_FEATURE
                and (x_count < 1 or c_count != 0)
            )
            or (self.table_kind is DiscoveryTableKindV2.CONTEXT and (c_count < 1 or x_count != 0))
            or not analysis_rules_valid
        ):
            raise ValueError(self._safe_validation_message)
        return self


class AuthenticatedNaturalDiscoveryScopeV2(_ContentAddressedDiscoveryV2):
    """Authenticated pre-outcome scope layered over the legacy/audit table spec."""

    _id_field = "authenticated_scope_id"
    _id_prefix = "authenticated_natural_scope_"

    authenticated_scope_id: str = Field(pattern=_AUTHENTICATED_SCOPE_PATTERN)
    table_spec: NaturalDiscoveryTableSpecV2
    task_bindings: tuple[NaturalTaskBindingV2, ...] = Field(min_length=2, max_length=1_000_000)
    actionable_feature_specs: tuple[ActionableFeatureSpec, ...] = Field(max_length=128)
    scope_construction_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_before_outcomes: Literal[True]

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        try:
            from secaware.tsg.context_queries_v2 import (
                CONTEXT_QUERY_SPECS,
                context_query_definition,
                evaluate_context_query,
            )
            from secaware.tsg.feature_catalog import (
                PROMPT_FEATURE_CATALOG_SHA256,
                prompt_feature_spec,
            )

            table = NaturalDiscoveryTableSpecV2.model_validate(self.table_spec, strict=True)
            relevant = tuple(
                item
                for item in table.semantic_cluster_manifest.memberships
                if item.split is PolicySplit.DISCOVER
                and item.cwe == table.cwe
                and item.task_archetype in table.task_archetypes
            )
            relevant_by_task = {item.task_instance_id: item for item in relevant}
            bindings = tuple(
                NaturalTaskBindingV2.model_validate(item, strict=True)
                for item in self.task_bindings
            )
            binding_by_task = {item.membership.task_instance_id: item for item in bindings}
            features = tuple(
                ActionableFeatureSpec.model_validate(item, strict=True)
                for item in self.actionable_feature_specs
            )
            feature_by_id = {item.actionable_feature_spec_id: item for item in features}
            expected_actionable_ids = {
                item.source_id
                for item in table.variables
                if item.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY
            }
            context_specs_by_id = {item.context_query_id: item for item in CONTEXT_QUERY_SPECS}
            if (
                set(binding_by_task) != set(relevant_by_task)
                or len(binding_by_task) != len(bindings)
                or any(
                    binding_by_task[task_id].membership != membership
                    for task_id, membership in relevant_by_task.items()
                )
                or set(feature_by_id) != expected_actionable_ids
                or len(feature_by_id) != len(features)
                or any(
                    item.source_kind is DiscoveryVariableSourceV2.TASK_METADATA
                    for item in table.variables
                )
                or any(
                    item.extractor_policy_sha256 != table.extractor_policy_sha256
                    for item in bindings
                )
                or table.outcome_projection_policy_sha256
                != NATURAL_OUTCOME_PROJECTION_POLICY_SHA256
            ):
                raise ValueError
            for variable in table.variables:
                if variable.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY:
                    feature = feature_by_id[variable.source_id]
                    catalog_feature = prompt_feature_spec(feature.feature_id)
                    if (
                        feature.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                        or variable.source_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                        or table.cwe not in catalog_feature.applicable_cwes
                        or catalog_feature.feature_family is not FeatureFamily.SAFETY_CONTROL
                        or not catalog_feature.intervenable
                        or not set(feature.allowed_operations).issubset(catalog_feature.operations)
                    ):
                        raise ValueError
                elif variable.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY:
                    query = context_specs_by_id.get(variable.source_id)
                    if (
                        query is None
                        or variable.source_catalog_sha256 != query.context_query_catalog_sha256
                        or variable.query_semantics_version != query.query_semantics_version
                    ):
                        raise ValueError
            if table.context_conditioning_query_id is not None:
                context_spec = context_specs_by_id.get(table.context_conditioning_query_id)
                if context_spec is None:
                    raise ValueError
                definition = context_query_definition(context_spec.query_name)
                query_by_task = {
                    item.task_instance_id: item for item in table.context_query_results
                }
                for task_id, binding in binding_by_task.items():
                    expected = evaluate_context_query(
                        binding.prompt_tsg,
                        definition.query_name,
                        semantic_membership=binding.membership,
                    ).result
                    if query_by_task.get(task_id) != expected:
                        raise ValueError
            support_by_task = {item.task_instance_id: item for item in table.task_slot_support}
            if any(
                support.natural_prompt_id != binding_by_task[task_id].natural_prompt_id
                for task_id, support in support_by_task.items()
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize scope/catalog boundary failures
            raise ValueError(self._safe_validation_message) from None
        return self


class DiscoveryVariableSupportV2(_DiscoveryV2Contract):
    variable_id: str
    state_counts: tuple[StrictInt, ...] = Field(min_length=2, max_length=256)
    observed_state_count: StrictInt = Field(ge=1, le=256)
    constant: bool

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        observed = sum(item > 0 for item in self.state_counts)
        if (
            _VARIABLE_RE.fullmatch(self.variable_id) is None
            or any(item < 0 for item in self.state_counts)
            or sum(self.state_counts) < 1
            or self.observed_state_count != observed
            or self.constant != (observed == 1)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PairwiseDeterminismV2(_DiscoveryV2Contract):
    left_variable_id: str
    right_variable_id: str
    left_determines_right: bool
    right_determines_left: bool

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if (
            _VARIABLE_RE.fullmatch(self.left_variable_id) is None
            or _VARIABLE_RE.fullmatch(self.right_variable_id) is None
            or self.left_variable_id >= self.right_variable_id
            or not (self.left_determines_right or self.right_determines_left)
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _observation_values(
    spec: NaturalDiscoveryTableSpecV2,
    observation: NaturalCausalObservationRecordV2,
) -> tuple[int, ...]:
    values = {
        item.variable_id: item.state for item in (*observation.natural_x0, *observation.outcomes)
    }
    variable_ids = tuple(item.variable_id for item in spec.variables)
    if len(values) != len(observation.natural_x0) + len(observation.outcomes) or set(values) != set(
        variable_ids
    ):
        raise ValueError("natural discovery v2 contract failed validation")
    encoded = tuple(values[item] for item in variable_ids)
    if any(
        type(value) is not int or not 0 <= value < len(variable.states)
        for value, variable in zip(encoded, spec.variables, strict=True)
    ):
        raise ValueError("natural discovery v2 contract failed validation")
    return encoded


def _expected_coordinates(
    spec: NaturalDiscoveryTableSpecV2,
) -> dict[tuple[str, int], DiscoveryTaskSlotSupportV2]:
    expected: dict[tuple[str, int], DiscoveryTaskSlotSupportV2] = {}
    for support in spec.task_slot_support:
        slots = (
            (support.reference_slot,)
            if spec.analysis_kind is DiscoveryAnalysisKindV2.FIXED_REFERENCE
            else support.request_randomness_slots
        )
        expected.update({(support.task_instance_id, slot): support for slot in slots})
    return expected


def _analysis_rows(
    spec: NaturalDiscoveryTableSpecV2,
    observations: tuple[NaturalCausalObservationRecordV2, ...],
) -> tuple[tuple[int, ...], ...]:
    encoded = {
        item.natural_causal_observation_id: _observation_values(spec, item) for item in observations
    }
    if spec.analysis_kind is not DiscoveryAnalysisKindV2.MULTI_SLOT_SENSITIVITY:
        return tuple(encoded[item.natural_causal_observation_id] for item in observations)
    by_task: dict[str, list[tuple[int, ...]]] = defaultdict(list)
    for item in observations:
        by_task[item.task_instance_id].append(encoded[item.natural_causal_observation_id])
    aggregated: list[tuple[int, ...]] = []
    for task_id in sorted(by_task):
        columns = zip(*by_task[task_id], strict=True)
        aggregated_row: list[int] = []
        for column in columns:
            counts = Counter(column)
            maximum = max(counts.values())
            aggregated_row.append(min(state for state, count in counts.items() if count == maximum))
        aggregated.append(tuple(aggregated_row))
    return tuple(aggregated)


def _support_and_determinism(
    spec: NaturalDiscoveryTableSpecV2,
    rows: tuple[tuple[int, ...], ...],
) -> tuple[tuple[DiscoveryVariableSupportV2, ...], tuple[PairwiseDeterminismV2, ...], bool]:
    supports = tuple(
        DiscoveryVariableSupportV2(
            schema_version=DISCOVERY_V2_SCHEMA_VERSION,
            variable_id=variable.variable_id,
            state_counts=tuple(
                sum(row[index] == state for row in rows) for state in range(len(variable.states))
            ),
            observed_state_count=len({row[index] for row in rows}),
            constant=len({row[index] for row in rows}) == 1,
        )
        for index, variable in enumerate(spec.variables)
    )
    predictor_indices = tuple(
        index
        for index, variable in enumerate(spec.variables)
        if variable.role is not DiscoveryVariableRoleV2.Y
    )
    dependencies: list[PairwiseDeterminismV2] = []
    for offset, left_index in enumerate(predictor_indices):
        for right_index in predictor_indices[offset + 1 :]:
            left_to_right: dict[int, set[int]] = defaultdict(set)
            right_to_left: dict[int, set[int]] = defaultdict(set)
            for row in rows:
                left_to_right[row[left_index]].add(row[right_index])
                right_to_left[row[right_index]].add(row[left_index])
            left_determines = all(len(values) == 1 for values in left_to_right.values())
            right_determines = all(len(values) == 1 for values in right_to_left.values())
            if left_determines or right_determines:
                dependencies.append(
                    PairwiseDeterminismV2(
                        schema_version=DISCOVERY_V2_SCHEMA_VERSION,
                        left_variable_id=spec.variables[left_index].variable_id,
                        right_variable_id=spec.variables[right_index].variable_id,
                        left_determines_right=left_determines,
                        right_determines_left=right_determines,
                    )
                )
    passed = not any(item.constant for item in supports) and not dependencies
    return supports, tuple(dependencies), passed


class NaturalDiscoveryTableArtifactV2(_ContentAddressedDiscoveryV2):
    """Exact post-outcome table artifact; no code, marker, arm, or XAR fields exist."""

    _id_field = "table_artifact_id"
    _id_prefix = "natural_table_artifact_"

    table_artifact_id: str = Field(pattern=_TABLE_ARTIFACT_PATTERN)
    table_spec: NaturalDiscoveryTableSpecV2
    observations: tuple[NaturalCausalObservationRecordV2, ...] = Field(
        min_length=2, max_length=1_000_000
    )
    producer_chains: tuple[RuntimeProducerChainRecordV2, ...] = Field(
        min_length=2, max_length=1_000_000
    )
    raw_observation_count: StrictInt = Field(ge=2, le=1_000_000)
    analysis_row_count: StrictInt = Field(ge=2, le=1_000_000)
    independent_semantic_cluster_count: StrictInt = Field(ge=2, le=1_000_000)
    variable_support: tuple[DiscoveryVariableSupportV2, ...] = Field(min_length=2, max_length=128)
    pairwise_predictor_determinism: tuple[PairwiseDeterminismV2, ...]
    minimal_generating_set_passed: bool
    observation_payload_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_components(
        cls,
        *,
        table_spec: NaturalDiscoveryTableSpecV2,
        observations: tuple[NaturalCausalObservationRecordV2, ...],
        producer_chains: tuple[RuntimeProducerChainRecordV2, ...],
    ) -> Self:
        try:
            spec = NaturalDiscoveryTableSpecV2.model_validate(table_spec, strict=True)
            rows = tuple(
                NaturalCausalObservationRecordV2.model_validate(item, strict=True)
                for item in observations
            )
            chains = tuple(
                RuntimeProducerChainRecordV2.model_validate(item, strict=True)
                for item in producer_chains
            )
            analysis_rows = _analysis_rows(spec, rows)
            support, dependencies, passed = _support_and_determinism(spec, analysis_rows)
            return cls.from_content(
                table_spec=spec,
                observations=rows,
                producer_chains=chains,
                raw_observation_count=len(rows),
                analysis_row_count=len(analysis_rows),
                independent_semantic_cluster_count=len(
                    {item.semantic_task_cluster_id for item in rows}
                ),
                variable_support=support,
                pairwise_predictor_determinism=dependencies,
                minimal_generating_set_passed=passed,
                observation_payload_sha256=_digest(
                    tuple(item.natural_causal_observation_id for item in rows)
                ),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public contract boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        spec = self.table_spec
        expected = _expected_coordinates(spec)
        actual: dict[tuple[str, int], NaturalCausalObservationRecordV2] = {}
        support_by_task = {item.task_instance_id: item for item in spec.task_slot_support}
        for observation in self.observations:
            key = (observation.task_instance_id, observation.request_randomness_slot)
            if key in actual:
                raise ValueError(self._safe_validation_message)
            actual[key] = observation
            support = expected.get(key)
            if (
                support is None
                or observation.regime_id != "natural_prompt_discovery"
                or observation.table_id != spec.table_spec_id
                or observation.model_id != spec.model_id
                or observation.semantic_task_cluster_id != support.semantic_task_cluster_id
                or observation.prompt_id != support.natural_prompt_id
                or observation.provider_seed
                != support.seed_for_slot(observation.request_randomness_slot)
            ):
                raise ValueError(self._safe_validation_message)
            _observation_values(spec, observation)
        chain_by_id = {item.producer_chain_id: item for item in self.producer_chains}
        if len(chain_by_id) != len(self.producer_chains):
            raise ValueError(self._safe_validation_message)
        for observation in self.observations:
            chain = chain_by_id.get(observation.producer_chain_id)
            if chain is None or chain.exact_coordinates() != observation.exact_coordinates():
                raise ValueError(self._safe_validation_message)
        natural_x0_by_task: dict[str, set[tuple[tuple[str, int], ...]]] = defaultdict(set)
        for observation in self.observations:
            natural_x0_by_task[observation.task_instance_id].add(
                tuple((item.variable_id, item.state) for item in observation.natural_x0)
            )
        analysis_rows = _analysis_rows(spec, self.observations)
        support, dependencies, passed = _support_and_determinism(spec, analysis_rows)
        cluster_count = len({item.semantic_task_cluster_id for item in self.observations})
        order = tuple(
            (item.semantic_task_cluster_id, item.task_instance_id, item.request_randomness_slot)
            for item in self.observations
        )
        if (
            set(actual) != set(expected)
            or set(chain_by_id) != {item.producer_chain_id for item in self.observations}
            or len(chain_by_id) != len(self.observations)
            or order != tuple(sorted(order))
            or self.raw_observation_count != len(self.observations)
            or self.analysis_row_count != len(analysis_rows)
            or self.independent_semantic_cluster_count != cluster_count
            or self.variable_support != support
            or self.pairwise_predictor_determinism != dependencies
            or self.minimal_generating_set_passed != passed
            or self.observation_payload_sha256
            != _digest(tuple(item.natural_causal_observation_id for item in self.observations))
            or set(support_by_task) != {item.task_instance_id for item in self.observations}
            or any(len(values) != 1 for values in natural_x0_by_task.values())
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def categorical_rows(self) -> tuple[tuple[int, ...], ...]:
        return _analysis_rows(self.table_spec, self.observations)


__all__ = [
    "DISCOVERY_V2_SCHEMA_VERSION",
    "NATURAL_OBSERVATION_ASSEMBLY_POLICY_SHA256",
    "NATURAL_OUTCOME_PROJECTION_POLICY_SHA256",
    "AuthenticatedNaturalDiscoveryScopeV2",
    "DiscoveryAnalysisKindV2",
    "DiscoveryTableKindV2",
    "DiscoveryTaskSlotSupportV2",
    "DiscoveryVariableRoleV2",
    "DiscoveryVariableSourceV2",
    "DiscoveryVariableSupportV2",
    "NaturalDiscoveryTableArtifactV2",
    "NaturalDiscoveryTableSpecV2",
    "NaturalDiscoveryVariableSpecV2",
    "NaturalTaskBindingV2",
    "PairwiseDeterminismV2",
]

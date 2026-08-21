"""Replayable natural-Prompt query evidence for prospective population gates.

This module closes the pre-outcome edge between an exact source Prompt and a
``PreOutcomeEligibilityRecord``.  A query-result identifier alone is not
evidence: every task record embeds the source Prompt snapshot, the extractor
proposal, the rebuilt PromptTSG, both canonical query results, and the derived
eligibility decision.  Validation replays that complete one-way chain.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiments import PromptRole
from secaware.schema.features import FeatureOperation, FeatureState, PromptExtractorBackend
from secaware.schema.policy_v2 import (
    ActionableFeatureQueryResultRecord,
    ActionableFeatureSpec,
    ContextQueryResultRecord,
    ContextQuerySpec,
    PolicySplit,
    PreOutcomeEligibilityRecord,
    QueryState,
    SemanticTaskClusterMembershipRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord

QUERY_EVIDENCE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PROMPT_SNAPSHOT_ID_PATTERN = r"^natural_prompt_snapshot_[0-9a-f]{64}$"
_TASK_EVIDENCE_ID_PATTERN = r"^query_evidence_task_[0-9a-f]{64}$"
_MANIFEST_ID_PATTERN = r"^query_evidence_manifest_v2_[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,1023}$")


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


def _snapshot_json_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_json_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_json_arrays(item) for item in value)
    return value


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and _IDENTIFIER_RE.fullmatch(value) is not None
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


class _QueryEvidenceV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "query evidence v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = QUERY_EVIDENCE_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_json_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedQueryEvidenceV2(_QueryEvidenceV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": QUERY_EVIDENCE_V2_SCHEMA_VERSION, **content}
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


class NaturalPromptSnapshotV2(_ContentAddressedQueryEvidenceV2):
    """Immutable exact Prompt input consumed by the frozen extractor."""

    _id_field = "natural_prompt_snapshot_id"
    _id_prefix = "natural_prompt_snapshot_"

    natural_prompt_snapshot_id: str = Field(pattern=_PROMPT_SNAPSHOT_ID_PATTERN)
    prompt_id: str
    task_id: str
    split: Literal["discover", "confirm"]
    language: Literal["python"]
    task_family: str
    cwe: str
    prompt: str = Field(min_length=1, repr=False)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_role: PromptRole
    counterpart_prompt_id: None
    oracle_profile_id: str | None

    @field_validator("prompt_role", mode="before")
    @classmethod
    def parse_prompt_role(cls, value: object) -> object:
        if type(value) is PromptRole:
            return value
        if type(value) is str:
            return next((item for item in PromptRole if item.value == value), value)
        return value

    @classmethod
    def from_prompt_record(cls, prompt: PromptRecord) -> Self:
        try:
            if type(prompt) is not PromptRecord:
                raise ValueError
            checked = PromptRecord.model_validate(prompt.model_dump(mode="python"))
            return cls.from_content(
                prompt_id=checked.prompt_id,
                task_id=checked.task_id,
                split=checked.split,
                language=checked.language,
                task_family=checked.task_family,
                cwe=checked.cwe,
                prompt=checked.prompt,
                prompt_sha256=checked.prompt_sha256,
                prompt_role=checked.prompt_role,
                counterpart_prompt_id=checked.counterpart_prompt_id,
                oracle_profile_id=checked.oracle_profile_id,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize mutable PromptRecord input
            raise cls._safe_error() from None

    def to_prompt_record(self) -> PromptRecord:
        return PromptRecord(
            prompt_id=self.prompt_id,
            task_id=self.task_id,
            split=self.split,
            language=self.language,
            task_family=self.task_family,
            cwe=self.cwe,
            prompt=self.prompt,
            prompt_role=self.prompt_role,
            counterpart_prompt_id=self.counterpart_prompt_id,
            oracle_profile_id=self.oracle_profile_id,
        )

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        try:
            rebuilt = self.to_prompt_record()
            if (
                not _valid_identifier(self.prompt_id)
                or not _valid_identifier(self.task_id)
                or not _valid_identifier(self.task_family)
                or self.prompt_role is not PromptRole.NEUTRAL_BASELINE
                or self.prompt_sha256 != rebuilt.prompt_sha256
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the Prompt snapshot boundary
            raise ValueError(self._safe_validation_message) from None
        return self


_FEATURE_TO_QUERY_STATE = {
    FeatureState.PRESENT: QueryState.PRESENT,
    FeatureState.ABSENT: QueryState.ABSENT,
    FeatureState.NOT_APPLICABLE: QueryState.NOT_APPLICABLE,
    FeatureState.UNRESOLVED: QueryState.UNRESOLVED,
}


def _evidence_tuple(attributes: object) -> tuple[int, int, str] | None:
    try:
        values = dict(attributes)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    start = values.get("evidence_start")
    end = values.get("evidence_end")
    digest = values.get("evidence_sha256")
    if type(start) is int and type(end) is int and type(digest) is str:
        return start, end, digest
    return None


def evaluate_actionable_feature_query_v2(
    *,
    prompt_tsg: PromptTSGRecord,
    semantic_membership: SemanticTaskClusterMembershipRecord,
    actionable_feature: ActionableFeatureSpec,
) -> ActionableFeatureQueryResultRecord:
    """Recompute a direct feature query from one canonical natural PromptTSG."""

    try:
        from secaware.tsg.catalog import PROMPT_TSG_CATALOG
        from secaware.tsg.context_queries_v2 import (
            CONTEXT_QUERY_CATALOG_SHA256,
            CONTEXT_QUERY_SEMANTICS_VERSION,
        )
        from secaware.tsg.feature_catalog import (
            PROMPT_FEATURE_CATALOG_SHA256,
            prompt_feature_edge_slots,
            prompt_feature_node_slots,
            prompt_feature_spec,
        )
        from secaware.tsg.graph import record_to_multidigraph
        from secaware.tsg.queries import feature_state

        record = PromptTSGRecord.model_validate(prompt_tsg, strict=True)
        membership = SemanticTaskClusterMembershipRecord.model_validate(
            semantic_membership, strict=True
        )
        feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
        catalog_feature = prompt_feature_spec(feature.feature_id)
        if (
            membership.task_instance_id != record.task_id
            or membership.cwe != record.cwe
            or feature.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
        ):
            raise ValueError
        graph = record_to_multidigraph(record)
        extracted_state = feature_state(graph, feature.feature_id)
        applicable = (
            membership.cwe in catalog_feature.applicable_cwes
            and record.task_family in catalog_feature.applicable_task_families
        )
        if applicable != (extracted_state is not FeatureState.NOT_APPLICABLE):
            raise ValueError
        state = _FEATURE_TO_QUERY_STATE[extracted_state]
        match_ids: tuple[str, ...] = ()
        roles_resolved: bool | None
        bounded_complete: bool
        evidence_content: dict[str, object] = {
            "schema_version": "actionable-query-evaluation-v2.2",
            "cluster_membership_id": membership.cluster_membership_id,
            "semantic_task_cluster_id": membership.semantic_task_cluster_id,
            "source_task_sha256": membership.source_task_sha256,
            "prompt_tsg_sha256": record.graph_sha256,
            "actionable_feature_spec_id": feature.actionable_feature_spec_id,
            "feature_id": feature.feature_id,
            "feature_catalog_sha256": feature.feature_catalog_sha256,
            "context_query_catalog_sha256": CONTEXT_QUERY_CATALOG_SHA256,
            "query_semantics_version": CONTEXT_QUERY_SEMANTICS_VERSION,
        }
        if state is QueryState.NOT_APPLICABLE:
            roles_resolved = None
            bounded_complete = False
        elif state is QueryState.ABSENT:
            roles_resolved = True
            bounded_complete = True
        elif state is QueryState.PRESENT:
            node_slots = prompt_feature_node_slots(feature.feature_id)
            edge_slots = prompt_feature_edge_slots(feature.feature_id)
            ontology = next(
                (
                    item
                    for item in PROMPT_TSG_CATALOG
                    if item.target_feature_id == feature.feature_id
                ),
                None,
            )
            ontology_labels = (
                {}
                if ontology is None
                else {
                    "prompt_requirement": ontology.requirement_label,
                    "guard": ontology.guard_label,
                }
            )
            matched_nodes: list[tuple[str, tuple[int, int, str]]] = []
            for slot in node_slots:
                accepted_labels = {
                    slot.canonical_label,
                    ontology_labels.get(slot.node_type.value, slot.canonical_label),
                }
                matches = tuple(
                    (node_id, _evidence_tuple(node["attributes"]))
                    for node_id, node in graph.nodes(data=True)
                    if node["node_type"] is slot.node_type and node["label"] in accepted_labels
                )
                if len(matches) != 1 or matches[0][1] is None:
                    state = QueryState.UNRESOLVED
                    break
                matched_nodes.append((matches[0][0], matches[0][1]))  # type: ignore[arg-type]
            matched_edges: list[tuple[str, tuple[int, int, str]]] = []
            if state is QueryState.PRESENT:
                matched_node_ids_by_type = {
                    slot.node_type: {
                        node_id
                        for node_id, _ in matched_nodes
                        if graph.nodes[node_id]["node_type"] is slot.node_type
                    }
                    for slot in node_slots
                }
                for slot in edge_slots:
                    matches = tuple(
                        (edge_id, _evidence_tuple(edge["attributes"]))
                        for src, dst, edge_id, edge in graph.edges(keys=True, data=True)
                        if edge["edge_type"] is slot.edge_type
                        and src in matched_node_ids_by_type.get(slot.src_node_type, set())
                        and dst in matched_node_ids_by_type.get(slot.dst_node_type, set())
                    )
                    if len(matches) != 1 or matches[0][1] is None:
                        state = QueryState.UNRESOLVED
                        break
                    matched_edges.append((matches[0][0], matches[0][1]))  # type: ignore[arg-type]
            if state is QueryState.PRESENT:
                match_content = {
                    "nodes": matched_nodes,
                    "edges": matched_edges,
                    **evidence_content,
                }
                match_ids = ("actionable_match_" + _digest(match_content),)
                roles_resolved = True
                bounded_complete = True
                evidence_content["match"] = match_content
            else:
                roles_resolved = False
                bounded_complete = False
        else:
            roles_resolved = False
            bounded_complete = False
        evidence_content.update(
            {
                "state": state.value,
                "applicable": applicable,
                "required_roles_resolved": roles_resolved,
                "bounded_matching_complete": bounded_complete,
                "match_evidence_ids": match_ids,
            }
        )
        return ActionableFeatureQueryResultRecord.from_content(
            regime_id="natural_prompt_discovery",
            task_instance_id=membership.task_instance_id,
            natural_prompt_id=record.prompt_id,
            prompt_tsg_sha256=record.graph_sha256,
            actionable_feature_spec_id=feature.actionable_feature_spec_id,
            feature_id=feature.feature_id,
            feature_catalog_sha256=feature.feature_catalog_sha256,
            context_query_catalog_sha256=CONTEXT_QUERY_CATALOG_SHA256,
            query_semantics_version=CONTEXT_QUERY_SEMANTICS_VERSION,
            state=state,
            applicable=applicable,
            required_roles_resolved=roles_resolved,
            bounded_matching_complete=bounded_complete,
            match_evidence_ids=match_ids,
            evaluation_evidence_sha256=_digest(evidence_content),
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001 - sanitize the query replay boundary
        raise ValueError("actionable feature query v2 evaluation failed") from None


QUERY_EVIDENCE_EVALUATION_POLICY_SHA256 = _digest(
    {
        "schema_version": QUERY_EVIDENCE_V2_SCHEMA_VERSION,
        "context_query": "canonical_context_query_v2.2",
        "actionable_query": "canonical_direct_feature_query_v2.2",
        "prompt_tsg": "proposal_rebuild_exact_equality",
        "eligibility": "pre_outcome_eligibility_exact_replay",
    }
)


class QueryEvidenceTaskRecordV2(_ContentAddressedQueryEvidenceV2):
    """One exact Prompt-to-query-to-eligibility replay record."""

    _id_field = "query_evidence_task_id"
    _id_prefix = "query_evidence_task_"

    query_evidence_task_id: str = Field(pattern=_TASK_EVIDENCE_ID_PATTERN)
    membership: SemanticTaskClusterMembershipRecord
    natural_prompt: NaturalPromptSnapshotV2
    extraction_proposal: PromptExtractionProposalRecord
    prompt_tsg: PromptTSGRecord
    context_query: ContextQuerySpec
    actionable_feature: ActionableFeatureSpec
    context_query_result: ContextQueryResultRecord
    actionable_query_result: ActionableFeatureQueryResultRecord
    eligibility: PreOutcomeEligibilityRecord
    query_evaluation_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_target_independent: Literal[True]
    generated_code_outcomes_excluded: Literal[True]
    frozen_before_outcomes: Literal[True]

    @classmethod
    def from_natural_prompt(
        cls,
        *,
        membership: SemanticTaskClusterMembershipRecord,
        natural_prompt: PromptRecord,
        extraction_proposal: PromptExtractionProposalRecord,
        prompt_tsg: PromptTSGRecord,
        context_query: ContextQuerySpec,
        actionable_feature: ActionableFeatureSpec,
        operation: FeatureOperation,
        eligibility_function_sha256: str,
        neutral_counterpart_attested: bool | None = None,
        neutral_counterpart_attestation_sha256: str | None = None,
    ) -> Self:
        try:
            from secaware.tsg.context_queries_v2 import evaluate_context_query

            checked_membership = SemanticTaskClusterMembershipRecord.model_validate(
                membership, strict=True
            )
            prompt_snapshot = NaturalPromptSnapshotV2.from_prompt_record(natural_prompt)
            checked_proposal = PromptExtractionProposalRecord.model_validate(
                extraction_proposal, strict=True
            )
            checked_graph = PromptTSGRecord.model_validate(prompt_tsg, strict=True)
            checked_context = ContextQuerySpec.model_validate(context_query, strict=True)
            checked_feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
            context_result = evaluate_context_query(
                checked_graph,
                checked_context.query_name,
                semantic_membership=checked_membership,
            ).result
            feature_result = evaluate_actionable_feature_query_v2(
                prompt_tsg=checked_graph,
                semantic_membership=checked_membership,
                actionable_feature=checked_feature,
            )
            target_evidence = (
                feature_result.evaluation_evidence_sha256
                if operation is FeatureOperation.REMOVE
                and feature_result.state is QueryState.PRESENT
                else None
            )
            eligibility = PreOutcomeEligibilityRecord.from_query_results(
                context_result=context_result,
                feature_result=feature_result,
                operation=operation,
                eligibility_function_sha256=eligibility_function_sha256,
                target_evidence_sha256=target_evidence,
                neutral_counterpart_attested=neutral_counterpart_attested,
                neutral_counterpart_attestation_sha256=(neutral_counterpart_attestation_sha256),
            )
            return cls.from_content(
                membership=checked_membership,
                natural_prompt=prompt_snapshot,
                extraction_proposal=checked_proposal,
                prompt_tsg=checked_graph,
                context_query=checked_context,
                actionable_feature=checked_feature,
                context_query_result=context_result,
                actionable_query_result=feature_result,
                eligibility=eligibility,
                query_evaluation_policy_sha256=QUERY_EVIDENCE_EVALUATION_POLICY_SHA256,
                context_target_independent=True,
                generated_code_outcomes_excluded=True,
                frozen_before_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the task evidence boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_replay(self) -> Self:
        try:
            from secaware.tsg.builder import build_prompt_tsg
            from secaware.tsg.context_queries_v2 import (
                context_query_spec,
                evaluate_context_query,
            )
            from secaware.tsg.proposal_validator import validate_proposal

            membership = SemanticTaskClusterMembershipRecord.model_validate(
                self.membership, strict=True
            )
            prompt = self.natural_prompt.to_prompt_record()
            proposal = validate_proposal(self.extraction_proposal, prompt)
            rebuilt_graph = build_prompt_tsg(proposal, prompt)
            canonical_context = context_query_spec(self.context_query.query_name)
            context_result = evaluate_context_query(
                rebuilt_graph,
                canonical_context.query_name,
                semantic_membership=membership,
            ).result
            feature_result = evaluate_actionable_feature_query_v2(
                prompt_tsg=rebuilt_graph,
                semantic_membership=membership,
                actionable_feature=self.actionable_feature,
            )
            expected_target_evidence = (
                feature_result.evaluation_evidence_sha256
                if self.eligibility.operation is FeatureOperation.REMOVE
                and feature_result.state is QueryState.PRESENT
                else None
            )
            eligibility = PreOutcomeEligibilityRecord.from_query_results(
                context_result=context_result,
                feature_result=feature_result,
                operation=self.eligibility.operation,
                eligibility_function_sha256=self.eligibility.eligibility_function_sha256,
                target_evidence_sha256=expected_target_evidence,
                neutral_counterpart_attested=self.eligibility.neutral_counterpart_attested,
                neutral_counterpart_attestation_sha256=(
                    self.eligibility.neutral_counterpart_attestation_sha256
                ),
            )
            expected_split = "discover" if membership.split is PolicySplit.DISCOVER else "confirm"
            if (
                self.query_evaluation_policy_sha256 != QUERY_EVIDENCE_EVALUATION_POLICY_SHA256
                or self.natural_prompt.task_id != membership.task_instance_id
                or self.natural_prompt.cwe != membership.cwe
                or self.natural_prompt.split != expected_split
                or self.extraction_proposal.policy_sha256 != self.prompt_tsg.extractor_policy_sha256
                or self.extraction_proposal.backend is not self.prompt_tsg.extractor_backend
                or self.extraction_proposal.proposal_id != self.prompt_tsg.proposal_id
                or rebuilt_graph != self.prompt_tsg
                or self.context_query != canonical_context
                or self.context_query_result != context_result
                or self.actionable_query_result != feature_result
                or self.eligibility != eligibility
                or self.eligibility.target_evidence_sha256 != expected_target_evidence
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize all replay failures
            raise ValueError(self._safe_validation_message) from None
        return self


class QueryEvidenceManifestV2(_ContentAddressedQueryEvidenceV2):
    """Complete pre-outcome query evidence for one hypothesis population scope."""

    _id_field = "query_evidence_manifest_id"
    _id_prefix = "query_evidence_manifest_v2_"

    query_evidence_manifest_id: str = Field(pattern=_MANIFEST_ID_PATTERN)
    context_query: ContextQuerySpec
    actionable_feature: ActionableFeatureSpec
    operation: FeatureOperation
    extractor_backend: PromptExtractorBackend
    extractor_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    feature_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_query_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_semantics_version: str
    eligibility_function_sha256: str = Field(pattern=_SHA256_PATTERN)
    query_evaluation_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    tasks: tuple[QueryEvidenceTaskRecordV2, ...] = Field(min_length=1, max_length=1_000_000)
    task_count: StrictInt = Field(ge=1)
    context_target_independent: Literal[True]
    generated_code_outcomes_excluded: Literal[True]
    frozen_before_outcomes: Literal[True]

    @field_validator("operation", mode="before")
    @classmethod
    def parse_operation(cls, value: object) -> object:
        if type(value) is FeatureOperation:
            return value
        if type(value) is str:
            return next((item for item in FeatureOperation if item.value == value), value)
        return value

    @field_validator("extractor_backend", mode="before")
    @classmethod
    def parse_backend(cls, value: object) -> object:
        if type(value) is PromptExtractorBackend:
            return value
        if type(value) is str:
            return next((item for item in PromptExtractorBackend if item.value == value), value)
        return value

    @classmethod
    def from_tasks(
        cls,
        *,
        context_query: ContextQuerySpec,
        actionable_feature: ActionableFeatureSpec,
        operation: FeatureOperation,
        extractor_backend: PromptExtractorBackend,
        extractor_policy_sha256: str,
        eligibility_function_sha256: str,
        tasks: tuple[QueryEvidenceTaskRecordV2, ...],
    ) -> Self:
        try:
            context = ContextQuerySpec.model_validate(context_query, strict=True)
            feature = ActionableFeatureSpec.model_validate(actionable_feature, strict=True)
            ordered = tuple(
                sorted(
                    (QueryEvidenceTaskRecordV2.model_validate(item, strict=True) for item in tasks),
                    key=lambda item: (
                        item.membership.task_instance_id,
                        item.query_evidence_task_id,
                    ),
                )
            )
            return cls.from_content(
                context_query=context,
                actionable_feature=feature,
                operation=operation,
                extractor_backend=extractor_backend,
                extractor_policy_sha256=extractor_policy_sha256,
                feature_catalog_sha256=feature.feature_catalog_sha256,
                context_query_catalog_sha256=context.context_query_catalog_sha256,
                query_semantics_version=context.query_semantics_version,
                eligibility_function_sha256=eligibility_function_sha256,
                query_evaluation_policy_sha256=QUERY_EVIDENCE_EVALUATION_POLICY_SHA256,
                tasks=ordered,
                task_count=len(ordered),
                context_target_independent=True,
                generated_code_outcomes_excluded=True,
                frozen_before_outcomes=True,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the manifest boundary
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        try:
            from secaware.tsg.context_queries_v2 import context_query_spec
            from secaware.tsg.feature_catalog import (
                PROMPT_FEATURE_CATALOG_SHA256,
                prompt_feature_spec,
            )

            canonical_context = context_query_spec(self.context_query.query_name)
            catalog_feature = prompt_feature_spec(self.actionable_feature.feature_id)
            task_ids = tuple(item.membership.task_instance_id for item in self.tasks)
            prompt_ids = tuple(item.natural_prompt.prompt_id for item in self.tasks)
            if (
                self.context_query != canonical_context
                or self.context_query_catalog_sha256
                != canonical_context.context_query_catalog_sha256
                or self.query_semantics_version != canonical_context.query_semantics_version
                or self.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or self.actionable_feature.feature_catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
                or self.actionable_feature.feature_id != catalog_feature.feature_id
                or self.operation not in self.actionable_feature.allowed_operations
                or self.query_evaluation_policy_sha256 != QUERY_EVIDENCE_EVALUATION_POLICY_SHA256
                or self.task_count != len(self.tasks)
                or task_ids != tuple(sorted(task_ids))
                or len(task_ids) != len(set(task_ids))
                or len(prompt_ids) != len(set(prompt_ids))
                or any(
                    item.context_query != self.context_query
                    or item.actionable_feature != self.actionable_feature
                    or item.eligibility.operation is not self.operation
                    or item.eligibility.eligibility_function_sha256
                    != self.eligibility_function_sha256
                    or item.extraction_proposal.backend is not self.extractor_backend
                    or item.extraction_proposal.policy_sha256 != self.extractor_policy_sha256
                    or item.extraction_proposal.catalog_sha256 != self.feature_catalog_sha256
                    or item.context_query_result.context_query_catalog_sha256
                    != self.context_query_catalog_sha256
                    or item.actionable_query_result.context_query_catalog_sha256
                    != self.context_query_catalog_sha256
                    or item.context_query_result.query_semantics_version
                    != self.query_semantics_version
                    or item.actionable_query_result.query_semantics_version
                    != self.query_semantics_version
                    for item in self.tasks
                )
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize all manifest failures
            raise ValueError(self._safe_validation_message) from None
        return self


__all__ = [
    "QUERY_EVIDENCE_EVALUATION_POLICY_SHA256",
    "QUERY_EVIDENCE_V2_SCHEMA_VERSION",
    "NaturalPromptSnapshotV2",
    "QueryEvidenceManifestV2",
    "QueryEvidenceTaskRecordV2",
    "evaluate_actionable_feature_query_v2",
]

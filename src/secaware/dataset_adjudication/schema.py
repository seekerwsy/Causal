from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secaware.dataset_audit.schema import EvidenceSpan


class _PersistedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AdjudicationDimension(str, Enum):
    NEUTRALITY = "neutrality"
    CLUSTER_RELATION = "cluster_relation"


class DecisionConfidence(str, Enum):
    HIGH = "HIGH"
    LOW = "LOW"


class NeutralityAdjudicationLabel(str, Enum):
    ELIGIBLE_NEUTRAL = "ELIGIBLE_NEUTRAL"
    NON_SECURITY_USAGE = "NON_SECURITY_USAGE"
    SECURITY_FEATURE_PRESENT = "SECURITY_FEATURE_PRESENT"
    INELIGIBLE_VULNERABILITY_DISCLOSURE = "INELIGIBLE_VULNERABILITY_DISCLOSURE"
    INELIGIBLE_SECURITY_CONSTRAINT = "INELIGIBLE_SECURITY_CONSTRAINT"
    INELIGIBLE_UNSAFE_REQUEST = "INELIGIBLE_UNSAFE_REQUEST"
    UNRESOLVED = "UNRESOLVED"


class ClusterAdjudicationLabel(str, Enum):
    SAME_TASK = "SAME_TASK"
    SAME_TASK_VARIANT = "SAME_TASK_VARIANT"
    DISTINCT_TASK = "DISTINCT_TASK"
    UNRESOLVED = "UNRESOLVED"


class ReviewReason(str, Enum):
    PASS_DISAGREEMENT = "PASS_DISAGREEMENT"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    STRATIFIED_AUDIT = "STRATIFIED_AUDIT"


class PacketMetadata(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^(neutrality|cluster-rel)-[0-9a-f]{20}$")
    dimension: AdjudicationDimension
    source_stratum: str = Field(min_length=1)
    item_keys: tuple[str, ...] = Field(min_length=1, max_length=2)
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=2)
    automatic_state: str = Field(min_length=1)
    evidence_spans: tuple[EvidenceSpan, ...] = ()
    similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    packet_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_dimension_shape(self) -> PacketMetadata:
        expected = 1 if self.dimension is AdjudicationDimension.NEUTRALITY else 2
        if len(self.item_keys) != expected or len(self.source_ids) != expected:
            raise ValueError("packet metadata cardinality does not match its dimension")
        if self.dimension is AdjudicationDimension.NEUTRALITY:
            if self.similarity is not None:
                raise ValueError("neutrality packet cannot carry relation similarity")
        elif self.similarity is None:
            raise ValueError("cluster relation packet requires similarity evidence")
        return self


class BlindedNeutralityPacket(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^neutrality-[0-9a-f]{20}$")
    dimension: Literal[AdjudicationDimension.NEUTRALITY]
    pass_id: Literal["A", "B"]
    packet_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt: str = Field(min_length=1)


class BlindedClusterPacket(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^cluster-rel-[0-9a-f]{20}$")
    dimension: Literal[AdjudicationDimension.CLUSTER_RELATION]
    pass_id: Literal["A", "B"]
    packet_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_a: str = Field(min_length=1)
    prompt_b: str = Field(min_length=1)


BlindedPacket = Annotated[
    Union[BlindedNeutralityPacket, BlindedClusterPacket],
    Field(discriminator="dimension"),
]


class _CodexDecisionBase(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^(neutrality|cluster-rel)-[0-9a-f]{20}$")
    pass_id: Literal["A", "B"]
    packet_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    confidence: DecisionConfidence
    evidence_quotes: tuple[str, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=2000)
    rubric_version: Literal["adjudication-rubric-v1"]
    annotator_kind: Literal["CODEX"]
    annotator_id: str = Field(min_length=1, max_length=200)
    decision_timestamp: datetime
    input_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_quotes(self) -> _CodexDecisionBase:
        if any(not quote.strip() for quote in self.evidence_quotes):
            raise ValueError("decision evidence quotes cannot be blank")
        return self


class NeutralityCodexDecision(_CodexDecisionBase):
    dimension: Literal[AdjudicationDimension.NEUTRALITY]
    label: NeutralityAdjudicationLabel


class ClusterCodexDecision(_CodexDecisionBase):
    dimension: Literal[AdjudicationDimension.CLUSTER_RELATION]
    label: ClusterAdjudicationLabel


CodexDecision = Annotated[
    Union[NeutralityCodexDecision, ClusterCodexDecision],
    Field(discriminator="dimension"),
]


class RepeatConsistencyRecord(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^(neutrality|cluster-rel)-[0-9a-f]{20}$")
    dimension: AdjudicationDimension
    source_stratum: str = Field(min_length=1)
    pass_a_label: str = Field(min_length=1)
    pass_b_label: str = Field(min_length=1)
    pass_a_confidence: DecisionConfidence
    pass_b_confidence: DecisionConfidence
    labels_agree: bool


class HumanReviewQueueEntry(_PersistedModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=r"^(neutrality|cluster-rel)-[0-9a-f]{20}$")
    dimension: AdjudicationDimension
    source_stratum: str = Field(min_length=1)
    packet_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_reasons: tuple[ReviewReason, ...] = Field(min_length=1)
    pass_a_label: str = Field(min_length=1)
    pass_b_label: str = Field(min_length=1)
    pass_a_confidence: DecisionConfidence
    pass_b_confidence: DecisionConfidence


__all__ = [
    "AdjudicationDimension",
    "BlindedClusterPacket",
    "BlindedNeutralityPacket",
    "BlindedPacket",
    "ClusterCodexDecision",
    "ClusterAdjudicationLabel",
    "CodexDecision",
    "DecisionConfidence",
    "HumanReviewQueueEntry",
    "NeutralityAdjudicationLabel",
    "NeutralityCodexDecision",
    "PacketMetadata",
    "RepeatConsistencyRecord",
    "ReviewReason",
]

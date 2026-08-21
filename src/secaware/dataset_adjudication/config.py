from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AdjudicationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    adjudication_version: Literal["adjudication-v1"]
    rubric_version: Literal["adjudication-rubric-v1"]
    packet_version: Literal["adjudication-packets-v1"]
    audit_sample_version: Literal["human-audit-sample-v1"]
    source_audit_run_id: str = Field(min_length=1)
    source_stable_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_source_records: int = Field(ge=1)
    expected_neutrality_packets: int = Field(ge=0)
    expected_cluster_packets: int = Field(ge=0)
    pilot_per_dimension: int = Field(ge=1)
    human_audit_fraction: float = Field(gt=0, le=1)
    seed: int


__all__ = ["AdjudicationConfig"]


from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secaware.schema.oracle import FindingRecord as FindingRecord
from secaware.schema.oracle import OracleRecord as OracleRecord
from secaware.schema.oracle import SecurityLabel as SecurityLabel


class LegacyFindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    cwe: str
    message: str
    sink: str
    evidence: str
    severity: str


class LegacyOracleRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    code_id: str
    parse_ok: bool
    functional_ok: bool
    security_label: SecurityLabel
    severity: str
    findings: list[LegacyFindingRecord] = Field(default_factory=list)
    prompt_id: str | None = None
    condition: str | None = None
    model_id: str | None = None
    seed_id: int | None = None
    hypothesis_id: str | None = None
    intervention_id: str | None = None


class PairResult(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    pair_id: str
    prompt_id: str
    hypothesis_id: str
    model_id: str
    seed_id: int
    factor_type: str
    expected_direction: str
    same_task_valid: bool
    target_changed: bool
    side_effect: bool
    functional_observed: bool
    functional_counterfactual: bool
    security_observed: str
    security_counterfactual: str
    delta: int | None
    flip_type: str
    eligible_per_protocol: bool
    eligible_itt: bool
    failure_reason: str | None = None


class EffectRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    factor_type: str
    scope_cwe: str = ""
    scope_task_family: str = ""
    eligible_pairs: int
    attempted_pairs: int = 0
    per_protocol_risk_difference: float
    ci_low: float
    ci_high: float
    itt_risk_difference: float
    secure_flip_rate: float
    insecure_flip_rate: float
    side_effect_rate: float
    status: str
    main_failure_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

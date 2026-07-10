from enum import Enum

from pydantic import BaseModel, ConfigDict

from secaware.schema.hypotheses import FactorType


class FailureReason(str, Enum):
    NO_OPERATOR = "no_operator"
    PATCH_FAILED = "patch_failed"
    ROUND_TRIP_FAILED = "round_trip_failed"
    SEMANTIC_DRIFT = "semantic_drift"
    TARGET_NOT_CHANGED = "target_not_changed"
    SIDE_EFFECT = "side_effect"
    GENERATION_FAILED = "generation_failed"
    PARSE_FAILED = "parse_failed"
    FUNCTIONAL_FAILED = "functional_failed"
    ORACLE_UNKNOWN = "oracle_unknown"
    INSUFFICIENT_DENOMINATOR = "insufficient_denominator"
    NO_EFFECT = "no_effect"
    OPPOSITE_DIRECTION = "opposite_direction"


class InterventionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention_id: str
    prompt_id: str
    hypothesis_id: str
    factor_type: FactorType
    operator: str
    expected_direction: str
    original_prompt: str
    counterfactual_prompt: str
    patch_success: bool
    round_trip_valid: bool
    semantic_valid: bool
    target_changed: bool
    side_effect: bool
    failure_reason: FailureReason | None = None

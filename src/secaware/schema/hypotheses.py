from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from secaware.schema.tsg import MotifId


class FactorType(str, Enum):
    INPUT_VALIDATION = "input_validation"
    PATH_NORMALIZATION = "path_normalization"
    SQL_PARAMETERIZATION = "sql_parameterization"
    SAFE_SUBPROCESS = "safe_subprocess"
    AUTHORIZATION_CHECK = "authorization_check"
    SAFE_DESERIALIZATION = "safe_deserialization"


class HypothesisRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    factor_type: FactorType
    motif_id: MotifId
    requirement_label: str
    guard_label: str
    expected_direction: str
    scope: dict[str, str] = Field(default_factory=dict)
    patch_operator: str
    discovery_score: float = 0.0
    association_score: float = 0.0
    path_score: float = 0.0
    targetability_score: float = 0.0
    stability_score: float = 0.0
    nuisance_penalty: float = 0.0
    support: dict[str, Any] = Field(default_factory=dict)
    status: str = "selected_for_confirmation"

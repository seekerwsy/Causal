from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PromptRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    prompt_id: str
    split: Literal["discover", "confirm"]
    language: str
    task_family: str
    cwe: str
    prompt: str = Field(min_length=1)


class GeneratedCodeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    code_id: str
    prompt_id: str
    condition: Literal["observed", "counterfactual"]
    model_id: str
    seed_id: int
    code: str
    hypothesis_id: str | None = None
    intervention_id: str | None = None

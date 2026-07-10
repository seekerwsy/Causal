from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secaware.schema.generation import GenerationProvenance, sha256_text


_LOWERCASE_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^req_[0-9a-f]{64}$"


class PromptRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    prompt_id: str
    split: Literal["discover", "confirm"]
    language: str
    task_family: str
    cwe: str
    prompt: str = Field(min_length=1)


class GeneratedCodeRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
    )

    code_id: str
    prompt_id: str
    condition: Literal["observed", "counterfactual"]
    model_id: str
    seed_id: int
    code: str
    hypothesis_id: str | None = None
    intervention_id: str | None = None
    schema_version: Literal["1.0"] | None = None
    request_id: str | None = Field(default=None, pattern=_REQUEST_ID_PATTERN)
    prompt_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    code_sha256: str | None = Field(default=None, pattern=_LOWERCASE_SHA256_PATTERN)
    generation_provenance: GenerationProvenance | None = None

    @model_validator(mode="after")
    def validate_generation_metadata_bridge(self) -> "GeneratedCodeRecord":
        metadata = (
            self.schema_version,
            self.request_id,
            self.prompt_sha256,
            self.code_sha256,
            self.generation_provenance,
        )
        if all(value is None for value in metadata):
            return self
        if any(value is None for value in metadata):
            raise ValueError("canonical generation metadata must be complete")

        request_id = self.request_id
        code_sha256 = self.code_sha256
        if request_id is None or code_sha256 is None:  # pragma: no cover - narrowed above
            raise ValueError("canonical generation metadata must be complete")
        if not self.code.strip() or code_sha256 != sha256_text(self.code):
            raise ValueError("canonical generated code hash does not match its payload")
        if self.code_id != f"code_{request_id.removeprefix('req_')}":
            raise ValueError("canonical code id must match its request id")

        identifiers = (self.hypothesis_id, self.intervention_id)
        if self.condition == "observed" and any(value is not None for value in identifiers):
            raise ValueError("canonical observed code must not have intervention identifiers")
        if self.condition == "counterfactual" and any(
            value is None or not value.strip() for value in identifiers
        ):
            raise ValueError("canonical counterfactual code requires intervention identifiers")
        return self

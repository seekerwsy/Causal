from typing import Literal

from pydantic import BaseModel, ConfigDict


SCHEMA_VERSION = "1.0"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VersionedModel(StrictModel):
    schema_version: Literal["1.0"]

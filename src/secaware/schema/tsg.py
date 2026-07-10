from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class NodeType(str, Enum):
    TASK_OPERATION = "task_operation"
    DATA_OBJECT = "data_object"
    SOURCE = "source"
    SINK = "sink"
    GUARD = "guard"
    PROMPT_REQUIREMENT = "prompt_requirement"
    TRUST_BOUNDARY = "trust_boundary"
    SECURITY_ASSUMPTION = "security_assumption"
    API = "api"
    CWE = "cwe"


class EdgeType(str, Enum):
    OPERATES_ON = "operates_on"
    SOURCE_OF = "source_of"
    FLOWS_TO = "flows_to"
    GUARDED_BY = "guarded_by"
    REQUIRES = "requires"
    OMITS = "omits"
    WEAKENS = "weakens"
    MAPS_TO = "maps_to"
    RELATED_TO = "related_to"


class TSGNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    node_type: NodeType
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class TSGEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str
    src: str
    dst: str
    edge_type: EdgeType
    attributes: dict[str, Any] = Field(default_factory=dict)


class TSGRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    source_type: Literal["prompt", "code"]
    prompt_id: str
    code_id: str | None = None
    nodes: list[TSGNode] = Field(default_factory=list)
    edges: list[TSGEdge] = Field(default_factory=list)
    features: dict[str, Any] = Field(default_factory=dict)

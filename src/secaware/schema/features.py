"""Finite prompt feature and extraction backend enums."""

from enum import Enum


class FeatureFamily(str, Enum):
    TASK_FUNCTION = "task_function"
    SAFETY_CONTROL = "safety_control"
    PRESENTATION_CONTROL = "presentation_control"


class FeatureOperation(str, Enum):
    ADD = "add"
    REMOVE = "remove"


class FeatureState(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    NOT_APPLICABLE = "not_applicable"
    UNRESOLVED = "unresolved"


class PromptExtractorBackend(str, Enum):
    LLM_FACTS_V1 = "llm_facts_v1"
    LLM_DIRECT_GRAPH_V1 = "llm_direct_graph_v1"
    DETERMINISTIC_CATALOG_V1 = "deterministic_catalog_v1"
    DETERMINISTIC_CATALOG_V2 = "deterministic_catalog_v2"


__all__ = [
    "FeatureFamily",
    "FeatureOperation",
    "FeatureState",
    "PromptExtractorBackend",
]

"""Prompt-only causal table contracts and assembly."""

from secaware.causal.table_builder import (
    build_local_tables,
    secure_functional_value,
    validate_local_table_bundle,
)
from secaware.causal.variable_catalog import (
    CWE_SECURITY_OUTCOME,
    PRIMARY_OUTCOME,
    PROMPT_CAUSAL_VARIABLES,
    VARIABLE_CATALOG_SHA256,
    VariableDeclaration,
    declaration_by_id,
)

__all__ = [
    "CWE_SECURITY_OUTCOME",
    "PRIMARY_OUTCOME",
    "PROMPT_CAUSAL_VARIABLES",
    "VARIABLE_CATALOG_SHA256",
    "VariableDeclaration",
    "build_local_tables",
    "declaration_by_id",
    "secure_functional_value",
    "validate_local_table_bundle",
]

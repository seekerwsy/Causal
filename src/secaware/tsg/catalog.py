"""Finite, reviewed prompt task-semantic-graph ontology."""

from __future__ import annotations

from dataclasses import dataclass, fields
import re

from secaware.schema.hypotheses import FactorType
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


ONTOLOGY_VERSION = "1.0"
MOTIF_VERSION = "1.0"

_MAX_TERMS_PER_KIND = 8
_MAX_CATALOG_TEXT_BYTES = 96
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")


@dataclass(frozen=True, slots=True)
class PromptOntologyEntry:
    factor_type: FactorType
    operation_label: str
    data_label: str
    sink_label: str
    requirement_label: str
    guard_label: str
    domain_terms: tuple[str, ...]
    guard_terms: tuple[str, ...]
    cwe: str


PROMPT_TSG_CATALOG = (
    PromptOntologyEntry(
        factor_type=FactorType.INPUT_VALIDATION,
        operation_label="inspect_input",
        data_label="untrusted_field",
        sink_label="input_consumer",
        requirement_label="require_input_validation",
        guard_label="input_validation",
        domain_terms=("accept user input", "process form input", "parse request field"),
        guard_terms=("validate input schema", "enforce input length", "reject invalid input"),
        cwe="CWE-20",
    ),
    PromptOntologyEntry(
        factor_type=FactorType.PATH_NORMALIZATION,
        operation_label="open_file",
        data_label="user_path",
        sink_label="file_open",
        requirement_label="require_path_normalization",
        guard_label="path_normalization",
        domain_terms=("user-provided file path", "user path", "filename from the user"),
        guard_terms=(
            "normalize it",
            "normalize the path",
            "restrict it to a base directory",
        ),
        cwe="CWE-22",
    ),
    PromptOntologyEntry(
        factor_type=FactorType.SQL_PARAMETERIZATION,
        operation_label="build_sql_statement",
        data_label="user_query_value",
        sink_label="database_execute",
        requirement_label="require_sql_parameterization",
        guard_label="sql_parameterization",
        domain_terms=("sql query", "database query", "sqlite database"),
        guard_terms=("parameterized queries", "prepared statement", "bind parameters"),
        cwe="CWE-89",
    ),
    PromptOntologyEntry(
        factor_type=FactorType.SAFE_SUBPROCESS,
        operation_label="launch_process",
        data_label="command_argument",
        sink_label="process_spawn",
        requirement_label="require_safe_subprocess",
        guard_label="safe_subprocess",
        domain_terms=("run a command", "execute command", "launch a subprocess"),
        guard_terms=("shell=false", "list arguments", "without a shell"),
        cwe="CWE-78",
    ),
    PromptOntologyEntry(
        factor_type=FactorType.AUTHORIZATION_CHECK,
        operation_label="perform_privileged_action",
        data_label="authorization_subject",
        sink_label="protected_action",
        requirement_label="require_authorization_check",
        guard_label="authorization_check",
        domain_terms=("delete an account", "admin action", "sensitive operation"),
        guard_terms=("authorization check", "verify permissions", "enforce role access"),
        cwe="CWE-862",
    ),
    PromptOntologyEntry(
        factor_type=FactorType.SAFE_DESERIALIZATION,
        operation_label="decode_serialized_object",
        data_label="serialized_payload",
        sink_label="object_loader",
        requirement_label="require_safe_deserialization",
        guard_label="safe_deserialization",
        domain_terms=("deserialize data", "load a pickle", "parse serialized object"),
        guard_terms=("safe object loading", "allowlisted types", "trusted serializer"),
        cwe="CWE-502",
    ),
)


def _validate_catalog() -> None:
    expected_factors = tuple(FactorType)
    if (
        type(PROMPT_TSG_CATALOG) is not tuple
        or tuple(entry.factor_type for entry in PROMPT_TSG_CATALOG) != expected_factors
    ):
        raise RuntimeError("invalid prompt TSG catalog factors")
    if len(PROMPT_TSG_CATALOG) != 6 or any(
        type(entry) is not PromptOntologyEntry for entry in PROMPT_TSG_CATALOG
    ):
        raise RuntimeError("invalid prompt TSG catalog shape")

    labels: list[str] = []
    terms: list[str] = []
    for entry in PROMPT_TSG_CATALOG:
        entry_labels = (
            entry.operation_label,
            entry.data_label,
            entry.sink_label,
            entry.requirement_label,
            entry.guard_label,
        )
        if any(_LABEL_RE.fullmatch(label) is None for label in entry_labels):
            raise RuntimeError("invalid prompt TSG catalog label")
        if (
            type(entry.domain_terms) is not tuple
            or type(entry.guard_terms) is not tuple
            or not 1 <= len(entry.domain_terms) <= _MAX_TERMS_PER_KIND
            or not 1 <= len(entry.guard_terms) <= _MAX_TERMS_PER_KIND
        ):
            raise RuntimeError("invalid prompt TSG catalog term count")
        entry_terms = (*entry.domain_terms, *entry.guard_terms)
        if any(
            type(value) is not str
            or not value
            or value != value.strip()
            or not value.isascii()
            or value != value.casefold()
            or len(value.encode("ascii")) > _MAX_CATALOG_TEXT_BYTES
            for value in (*entry_labels, *entry_terms)
        ):
            raise RuntimeError("invalid prompt TSG catalog text")
        if _CWE_RE.fullmatch(entry.cwe) is None:
            raise RuntimeError("invalid prompt TSG catalog CWE")
        labels.extend(entry_labels)
        terms.extend(entry_terms)

    if len(labels) != len(set(labels)) or len(terms) != len(set(terms)):
        raise RuntimeError("duplicate prompt TSG catalog text")
    forbidden_fields = {"secure", "insecure", "outcome", "motif", "features"}
    if forbidden_fields & {field.name.casefold() for field in fields(PromptOntologyEntry)}:
        raise RuntimeError("outcome field in prompt TSG catalog")


_validate_catalog()

PROMPT_TSG_CATALOG_SHA256 = PROMPT_FEATURE_CATALOG_SHA256


def prompt_ontology_entry(factor_type: FactorType) -> PromptOntologyEntry:
    """Return the reviewed entry for one exact factor enum value."""
    if type(factor_type) is not FactorType:
        raise KeyError("unknown prompt ontology factor")
    for entry in PROMPT_TSG_CATALOG:
        if entry.factor_type is factor_type:
            return entry
    raise KeyError("unknown prompt ontology factor")  # pragma: no cover


__all__ = [
    "MOTIF_VERSION",
    "ONTOLOGY_VERSION",
    "PROMPT_TSG_CATALOG",
    "PROMPT_TSG_CATALOG_SHA256",
    "PromptOntologyEntry",
    "prompt_ontology_entry",
]

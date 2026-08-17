"""Finite, reviewed prompt task-semantic-graph ontology."""

from __future__ import annotations

from dataclasses import dataclass, fields
import re

from secaware.schema.features import FeatureFamily
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    prompt_feature_spec,
)


ONTOLOGY_VERSION = "1.2"
MOTIF_VERSION = "1.2"

_MAX_TERMS_PER_KIND = 8
_MAX_CATALOG_TEXT_BYTES = 96
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")


@dataclass(frozen=True, slots=True)
class PromptOntologyEntry:
    task_feature_id: str
    target_feature_id: str
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
        task_feature_id="task.input_consumption",
        target_feature_id="safety.input_validation",
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
        task_feature_id="task.file_read",
        target_feature_id="safety.path_normalization",
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
        task_feature_id="task.database_query",
        target_feature_id="safety.sql_parameterization",
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
        task_feature_id="task.process_launch",
        target_feature_id="safety.safe_subprocess",
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
        task_feature_id="task.privileged_action",
        target_feature_id="safety.authorization_check",
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
        task_feature_id="task.object_deserialization",
        target_feature_id="safety.safe_deserialization",
        operation_label="decode_serialized_object",
        data_label="serialized_payload",
        sink_label="object_loader",
        requirement_label="require_safe_deserialization",
        guard_label="safe_deserialization",
        domain_terms=("deserialize data", "load a pickle", "parse serialized object"),
        guard_terms=("safe object loading", "allowlisted types", "trusted serializer"),
        cwe="CWE-502",
    ),
    PromptOntologyEntry(
        task_feature_id="task.message_hashing",
        target_feature_id="safety.collision_resistant_hash",
        operation_label="hash_message",
        data_label="message_payload",
        sink_label="hash_constructor",
        requirement_label="require_collision_resistant_hash",
        guard_label="collision_resistant_hash",
        domain_terms=("hash a message", "compute a digest", "generate a checksum"),
        guard_terms=("collision-resistant hash", "sha-256", "strong hash"),
        cwe="CWE-328",
    ),
    PromptOntologyEntry(
        task_feature_id="task.security_random_generation",
        target_feature_id="safety.cryptographic_randomness",
        operation_label="generate_security_random_value",
        data_label="random_material",
        sink_label="security_random_generator",
        requirement_label="require_cryptographic_randomness",
        guard_label="cryptographic_randomness",
        domain_terms=(
            "generate a security token",
            "generate a password reset token",
            "generate a cryptographic nonce",
        ),
        guard_terms=(
            "cryptographically secure randomness",
            "secrets module",
            "secure random generator",
        ),
        cwe="CWE-338",
    ),
)


def _validate_catalog() -> None:
    expected_tasks = tuple(
        spec.feature_id
        for spec in PROMPT_FEATURE_CATALOG
        if spec.feature_family is FeatureFamily.TASK_FUNCTION and spec.structural_node_types
    )
    expected_targets = tuple(
        spec.feature_id
        for spec in PROMPT_FEATURE_CATALOG
        if spec.feature_family is FeatureFamily.SAFETY_CONTROL
        and spec.structural_node_types
        and spec.structural_edge_types
        and spec.intervenable
    )
    if (
        type(PROMPT_TSG_CATALOG) is not tuple
        or tuple(entry.task_feature_id for entry in PROMPT_TSG_CATALOG) != expected_tasks
        or tuple(entry.target_feature_id for entry in PROMPT_TSG_CATALOG) != expected_targets
    ):
        raise RuntimeError("invalid prompt TSG catalog feature pairs")
    if len(PROMPT_TSG_CATALOG) != 8 or any(
        type(entry) is not PromptOntologyEntry for entry in PROMPT_TSG_CATALOG
    ):
        raise RuntimeError("invalid prompt TSG catalog shape")

    labels: list[str] = []
    terms: list[str] = []
    for entry in PROMPT_TSG_CATALOG:
        try:
            task = prompt_feature_spec(entry.task_feature_id)
            target = prompt_feature_spec(entry.target_feature_id)
        except KeyError:
            raise RuntimeError("invalid prompt TSG catalog feature") from None
        if (
            task.feature_family is not FeatureFamily.TASK_FUNCTION
            or target.feature_family is not FeatureFamily.SAFETY_CONTROL
            or task.deterministic_terms != entry.domain_terms
            or target.deterministic_terms != entry.guard_terms
            or task.applicable_cwes != (entry.cwe,)
            or target.applicable_cwes != (entry.cwe,)
        ):
            raise RuntimeError("invalid prompt TSG catalog feature semantics")
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
    forbidden_fields = {
        "factor_type",
        "hypothesis",
        "secure",
        "insecure",
        "outcome",
        "motif",
        "features",
    }
    if forbidden_fields & {field.name.casefold() for field in fields(PromptOntologyEntry)}:
        raise RuntimeError("outcome field in prompt TSG catalog")


_validate_catalog()

PROMPT_TSG_CATALOG_SHA256 = PROMPT_FEATURE_CATALOG_SHA256


def prompt_ontology_entry(target_feature_id: str) -> PromptOntologyEntry:
    """Return the reviewed ontology entry for one exact safety target feature."""
    if type(target_feature_id) is not str:
        raise KeyError("unknown prompt ontology feature")
    for entry in PROMPT_TSG_CATALOG:
        if entry.target_feature_id == target_feature_id:
            return entry
    raise KeyError("unknown prompt ontology feature")  # pragma: no cover


__all__ = [
    "MOTIF_VERSION",
    "ONTOLOGY_VERSION",
    "PROMPT_TSG_CATALOG",
    "PROMPT_TSG_CATALOG_SHA256",
    "PromptOntologyEntry",
    "prompt_ontology_entry",
]

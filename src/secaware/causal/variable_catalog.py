"""Closed causal-variable declarations for Prompt-only discovery."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from secaware.schema.causal import VariableRole
from secaware.schema.tsg import MotifId
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG

_VARIABLE_RE = re.compile(r"^[pwxyz]\.[a-z0-9][a-z0-9_.-]{0,126}$")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]*$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


@dataclass(frozen=True, slots=True)
class VariableDeclaration:
    variable_id: str
    role: VariableRole
    states: tuple[str, ...]
    query_id: str
    applicable_cwes: tuple[str, ...]
    tier: int
    adjacency_type: str


PRIMARY_OUTCOME = VariableDeclaration(
    variable_id="y.secure_functional",
    role=VariableRole.Y,
    states=("no_success", "success"),
    query_id="outcome.secure_functional_v1",
    applicable_cwes=("*",),
    tier=2,
    adjacency_type="outcome",
)

CWE_SECURITY_OUTCOME = VariableDeclaration(
    variable_id="y.cwe_security",
    role=VariableRole.Y,
    states=("secure", "insecure", "unknown"),
    query_id="outcome.cwe_security_v1",
    applicable_cwes=("*",),
    tier=2,
    adjacency_type="outcome",
)

_TASK_METADATA_DECLARATIONS = (
    VariableDeclaration(
        variable_id="w.language_family",
        role=VariableRole.W,
        states=("python", "other"),
        query_id="task.language_family_v1",
        applicable_cwes=("*",),
        tier=0,
        adjacency_type="task_metadata",
    ),
    VariableDeclaration(
        variable_id="w.task_family",
        role=VariableRole.W,
        states=(
            "authorization",
            "command_execution",
            "deserialization",
            "file_access",
            "input_handling",
            "message_hashing",
            "path_handling",
            "security_random_generation",
            "sql_query",
            "other",
        ),
        query_id="task.task_family_v1",
        applicable_cwes=("*",),
        tier=0,
        adjacency_type="task_metadata",
    ),
)

_POOLED_RANDOMIZED_DISCOVERY_DECLARATIONS = (
    VariableDeclaration(
        variable_id="p.length_matched_placebo",
        role=VariableRole.P,
        states=("absent", "present"),
        query_id="prompt.presentation.length_matched_placebo.v1",
        applicable_cwes=("*",),
        tier=1,
        adjacency_type="presentation_control",
    ),
    VariableDeclaration(
        variable_id="w.cwe_scope",
        role=VariableRole.W,
        states=("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"),
        query_id="task.cwe_scope.v1",
        applicable_cwes=("*",),
        tier=0,
        adjacency_type="task_security_scope",
    ),
    VariableDeclaration(
        variable_id="x.generic_security_reminder",
        role=VariableRole.X,
        states=("absent", "present"),
        query_id="prompt.feature_state.generic_security_reminder.v1",
        applicable_cwes=("*",),
        tier=1,
        adjacency_type="prompt_safety_control",
    ),
    VariableDeclaration(
        variable_id="x.operation_specific_security_requirement",
        role=VariableRole.X,
        states=("absent", "present"),
        query_id="prompt.feature_state.operation_specific_security_requirement.v1",
        applicable_cwes=("*",),
        tier=1,
        adjacency_type="prompt_safety_control",
    ),
    VariableDeclaration(
        variable_id="y.cwe_secure",
        role=VariableRole.Y,
        states=("not_secure", "secure"),
        query_id="outcome.cwe_secure_itt.v1",
        applicable_cwes=("*",),
        tier=2,
        adjacency_type="security_outcome",
    ),
)

_MECHANISM_DISCOVERY_V2_DECLARATIONS = (
    VariableDeclaration(
        variable_id="z.target_mechanism_realized",
        role=VariableRole.Z,
        states=("not_realized", "realized"),
        query_id="code.mechanism.target_cwe_realized.v1",
        applicable_cwes=("*",),
        tier=2,
        adjacency_type="code_security_mechanism",
    ),
    VariableDeclaration(
        variable_id="y.discovery_cwe_secure",
        role=VariableRole.Y,
        states=("not_secure", "secure"),
        query_id="outcome.discovery_cwe_secure_itt.v1",
        applicable_cwes=("*",),
        tier=3,
        adjacency_type="security_outcome",
    ),
    VariableDeclaration(
        variable_id="y.discovery_secure_functional",
        role=VariableRole.Y,
        states=("no_success", "success"),
        query_id="outcome.discovery_secure_functional_itt.v1",
        applicable_cwes=("*",),
        tier=3,
        adjacency_type="outcome",
    ),
    VariableDeclaration(
        variable_id="y.discovery_functional",
        role=VariableRole.Y,
        states=("not_functional", "functional"),
        query_id="outcome.discovery_functional_judge.v1",
        applicable_cwes=("*",),
        tier=3,
        adjacency_type="functional_outcome",
    ),
)

_FEATURE_DECLARATIONS = tuple(
    VariableDeclaration(
        variable_id=f"x.{spec.feature_id}",
        role=VariableRole.X,
        states=("absent", "present"),
        query_id=f"prompt.feature_state.{spec.feature_id}.v1",
        applicable_cwes=spec.applicable_cwes or ("*",),
        tier=1,
        adjacency_type=f"prompt_{spec.feature_family.value}",
    )
    for spec in PROMPT_FEATURE_CATALOG
    if spec.intervenable
)

_MOTIF_CWES = {
    MotifId.USER_PATH_TO_FILE_OPEN_WITHOUT_GUARD: ("CWE-22",),
    MotifId.USER_STRING_TO_SQL_WITHOUT_PARAMETERIZATION: ("CWE-89",),
    MotifId.USER_INPUT_TO_SHELL_WITHOUT_GUARD: ("CWE-78",),
    MotifId.SENSITIVE_OPERATION_WITHOUT_AUTH_GUARD: ("CWE-862",),
    MotifId.UNTRUSTED_DATA_TO_DESERIALIZATION_SINK: ("CWE-502",),
    MotifId.MESSAGE_HASH_WITHOUT_COLLISION_RESISTANCE: ("CWE-328",),
    MotifId.SECURITY_RANDOM_WITHOUT_CRYPTO_SOURCE: ("CWE-338",),
    MotifId.UNTRUSTED_SOURCE_TO_SENSITIVE_SINK_WITHOUT_GUARD: ("*",),
}

_REVIEWED_MOTIF_DECLARATIONS = tuple(
    VariableDeclaration(
        variable_id=f"x.motif.{motif.value}",
        role=VariableRole.X,
        states=("absent", "present"),
        query_id=f"prompt.motif.{motif.value}.v1",
        applicable_cwes=_MOTIF_CWES[motif],
        tier=1,
        adjacency_type="prompt_motif",
    )
    for motif in MotifId
)

PROMPT_CAUSAL_VARIABLES = tuple(
    sorted(
        (
            *_TASK_METADATA_DECLARATIONS,
            *_FEATURE_DECLARATIONS,
            *_REVIEWED_MOTIF_DECLARATIONS,
            PRIMARY_OUTCOME,
            CWE_SECURITY_OUTCOME,
        ),
        key=lambda item: item.variable_id,
    )
)

POOLED_RANDOMIZED_DISCOVERY_VARIABLES = tuple(
    sorted(
        (*_POOLED_RANDOMIZED_DISCOVERY_DECLARATIONS, PRIMARY_OUTCOME),
        key=lambda item: item.variable_id,
    )
)

_ALL_CAUSAL_VARIABLES = tuple(
    sorted(
        (
            *PROMPT_CAUSAL_VARIABLES,
            *_POOLED_RANDOMIZED_DISCOVERY_DECLARATIONS,
            *_MECHANISM_DISCOVERY_V2_DECLARATIONS,
        ),
        key=lambda item: item.variable_id,
    )
)


def _validate_declaration(item: VariableDeclaration) -> None:
    if (
        type(item) is not VariableDeclaration
        or _VARIABLE_RE.fullmatch(item.variable_id) is None
        or not item.variable_id.startswith(f"{item.role.value}.")
        or type(item.states) is not tuple
        or len(item.states) < 2
        or len(item.states) != len(set(item.states))
        or any(_IDENTIFIER_RE.fullmatch(state) is None for state in item.states)
        or _IDENTIFIER_RE.fullmatch(item.query_id) is None
        or type(item.applicable_cwes) is not tuple
        or not item.applicable_cwes
        or ("*" in item.applicable_cwes and item.applicable_cwes != ("*",))
        or any(value != "*" and _CWE_RE.fullmatch(value) is None for value in item.applicable_cwes)
        or item.tier
        not in {
            VariableRole.P: {1},
            VariableRole.W: {0},
            VariableRole.X: {1},
            VariableRole.Z: {2},
            VariableRole.Y: {2, 3},
        }[item.role]
        or _IDENTIFIER_RE.fullmatch(item.adjacency_type) is None
    ):
        raise RuntimeError("invalid causal variable declaration")


for _item in _ALL_CAUSAL_VARIABLES:
    _validate_declaration(_item)
if len({item.variable_id for item in _ALL_CAUSAL_VARIABLES}) != len(_ALL_CAUSAL_VARIABLES):
    raise RuntimeError("duplicate causal variable declaration")
if {item.variable_id.removeprefix("x.") for item in _FEATURE_DECLARATIONS} != {
    item.feature_id for item in PROMPT_FEATURE_CATALOG if item.intervenable
}:
    raise RuntimeError("incomplete prompt feature declarations")


def _json_entry(item: VariableDeclaration) -> dict[str, object]:
    payload = asdict(item)
    payload["role"] = item.role.value
    return payload


VARIABLE_CATALOG_SHA256 = hashlib.sha256(
    json.dumps(
        [_json_entry(item) for item in PROMPT_CAUSAL_VARIABLES],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
).hexdigest()


def declaration_by_id(variable_id: str) -> VariableDeclaration:
    """Return one exact reviewed declaration; arbitrary IDs fail closed."""
    if type(variable_id) is not str:
        raise KeyError("unknown causal variable")
    for item in _ALL_CAUSAL_VARIABLES:
        if item.variable_id == variable_id:
            return item
    raise KeyError("unknown causal variable")


def declaration_sha256(item: VariableDeclaration) -> str:
    """Return the stable producer commitment for one reviewed declaration."""
    if declaration_by_id(item.variable_id) != item:
        raise KeyError("unknown causal variable")
    return hashlib.sha256(
        json.dumps(
            _json_entry(item),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


__all__ = [
    "CWE_SECURITY_OUTCOME",
    "POOLED_RANDOMIZED_DISCOVERY_VARIABLES",
    "PRIMARY_OUTCOME",
    "PROMPT_CAUSAL_VARIABLES",
    "VARIABLE_CATALOG_SHA256",
    "VariableDeclaration",
    "declaration_by_id",
    "declaration_sha256",
]

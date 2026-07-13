from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
import hashlib
import json
import re
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secaware.schema.common import SafeValidationMixin, StrictModel


_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_TABLE_ID_PATTERN = r"^table_[0-9a-f]{64}$"
_ROW_ID_PATTERN = r"^row_[0-9a-f]{64}$"
_PAG_ID_PATTERN = r"^pag_[0-9a-f]{64}$"
_BK_ID_PATTERN = r"^bk_[0-9a-f]{64}$"
_DRAW_ID_PATTERN = r"^draw_[0-9a-f]{64}$"
_BOOTSTRAP_PAG_ID_PATTERN = r"^bootstrap_pag_[0-9a-f]{64}$"
_PATH_ID_PATTERN = r"^path_[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_VARIABLE_ID_PATTERN = re.compile(r"^[wxyc]\.[a-z0-9][a-z0-9_.-]{0,126}$")
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")
_MAX_VARIABLES = 64
_MAX_ROWS = 100_000
_MAX_PAG_EDGES = _MAX_VARIABLES * (_MAX_VARIABLES - 1) // 2
_MAX_DIRECTION_CONSTRAINTS = _MAX_VARIABLES * (_MAX_VARIABLES - 1)


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        _jsonable(payload),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _row_id_from_content(
    *,
    task_id: str,
    prompt_id: str,
    model_id: str,
    seed_id: int,
    values: Sequence[int],
) -> str:
    return f"row_{_digest((task_id, prompt_id, model_id, seed_id, tuple(values)))}"


def _content(model: StrictModel, *derived_fields: str) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude=set(derived_fields))


def _valid_identifier(value: str) -> bool:
    return (
        bool(_IDENTIFIER_PATTERN.fullmatch(value))
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _snapshot_json_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_json_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_json_arrays(item) for item in value)
    return value


def _exact_enum_value(value: object, enum_type: type[Enum]) -> object:
    if isinstance(value, enum_type):
        return value
    if type(value) is str:
        for member in enum_type:
            if value == member.value:
                return member
    return value


class _CausalContract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "causal contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_json_arrays(value)


class _CausalVersionedContract(_CausalContract):
    schema_version: Literal["1.0"]


class VariableRole(str, Enum):
    W = "w"
    X = "x"
    Y = "y"
    C = "c"


class EndpointMark(str, Enum):
    TAIL = "tail"
    ARROW = "arrow"
    CIRCLE = "circle"


class PAGRunKind(str, Enum):
    OBSERVATIONAL_REFERENCE = "observational_reference"
    OBSERVATIONAL_BOOTSTRAP = "observational_bootstrap"
    JCI_RAW = "jci_raw"
    JCI_CONSTRAINED = "jci_constrained"
    RFCI_SENSITIVITY = "rfci_sensitivity"


class CausalExclusionReason(str, Enum):
    UNRESOLVED_FEATURE = "unresolved_feature"
    NOT_APPLICABLE_FEATURE = "not_applicable_feature"


class BootstrapFailureReason(str, Enum):
    BACKEND_TIMEOUT = "backend_timeout"
    BACKEND_CRASH = "backend_crash"
    INVALID_BACKEND_OUTPUT = "invalid_backend_output"
    BACKGROUND_KNOWLEDGE_VIOLATION = "background_knowledge_violation"
    DEGENERATE_GSQ_SUPPORT = "degenerate_gsq_support"


class DiscoveryFailureReason(str, Enum):
    BACKEND_TIMEOUT = "backend_timeout"
    BACKEND_CRASH = "backend_crash"
    INVALID_BACKEND_OUTPUT = "invalid_backend_output"
    BACKGROUND_KNOWLEDGE_VIOLATION = "background_knowledge_violation"
    DEGENERATE_GSQ_SUPPORT = "degenerate_gsq_support"
    TOO_MANY_FAILED_BOOTSTRAPS = "too_many_failed_bootstraps"
    NO_STABLE_HYPOTHESIS = "no_stable_hypothesis"


class CausalVariableSpec(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    variable_id: str
    role: VariableRole
    states: tuple[str, ...] = Field(min_length=2, max_length=256)
    source_query_id: str
    scope_id: str
    temporal_tier: int = Field(ge=0, le=2)
    adjacency_type: str
    producer_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("role", mode="before")
    @classmethod
    def parse_role(cls, value: object) -> object:
        return _exact_enum_value(value, VariableRole)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if (
            not _VARIABLE_ID_PATTERN.fullmatch(self.variable_id)
            or not self.variable_id.startswith(f"{self.role.value}.")
            or not _valid_identifier(self.source_query_id)
            or not _valid_identifier(self.scope_id)
            or not _valid_identifier(self.adjacency_type)
            or not 2 <= len(self.states) <= 256
            or len(set(self.states)) != len(self.states)
            or any(not _valid_identifier(state) for state in self.states)
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CausalTableRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    scope_id: str
    cwe: str
    model_id: str
    variables: tuple[CausalVariableSpec, ...] = Field(min_length=2, max_length=_MAX_VARIABLES)
    row_count: int = Field(ge=2, le=_MAX_ROWS)
    independent_task_count: int = Field(ge=2, le=_MAX_ROWS)
    table_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(
        cls,
        *,
        scope_id: str,
        cwe: str,
        model_id: str,
        variables: Sequence[CausalVariableSpec],
        row_count: int,
        independent_task_count: int,
        observation_payload: Sequence[tuple[str, str, str, int, Sequence[int]]],
    ) -> Self:
        try:
            if (
                type(row_count) is not int
                or not 2 <= row_count <= _MAX_ROWS
                or type(independent_task_count) is not int
                or not 2 <= independent_task_count <= row_count
                or not 2 <= len(variables) <= _MAX_VARIABLES
                or len(observation_payload) != row_count
            ):
                raise ValueError
            ordered = tuple(sorted(variables, key=lambda item: item.variable_id))
            observations = tuple(sorted(observation_payload))
            row_ids: list[str] = []
            coordinates: list[tuple[str, str, int]] = []
            task_ids: list[str] = []
            for row_id, task_id, prompt_id, seed_id, values in observations:
                if (
                    not isinstance(row_id, str)
                    or re.fullmatch(_ROW_ID_PATTERN, row_id) is None
                    or not isinstance(task_id, str)
                    or not _valid_identifier(task_id)
                    or not isinstance(prompt_id, str)
                    or not _valid_identifier(prompt_id)
                    or type(seed_id) is not int
                    or len(values) != len(ordered)
                    or any(
                        type(value) is not int or not 0 <= value < len(variable.states)
                        for value, variable in zip(values, ordered, strict=True)
                    )
                ):
                    raise ValueError
                expected_row_id = _row_id_from_content(
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id=model_id,
                    seed_id=seed_id,
                    values=values,
                )
                if row_id != expected_row_id:
                    raise ValueError
                row_ids.append(row_id)
                coordinates.append((task_id, prompt_id, seed_id))
                task_ids.append(task_id)
            if (
                len(observations) != row_count
                or len(row_ids) != len(set(row_ids))
                or len(coordinates) != len(set(coordinates))
                or len(set(task_ids)) != independent_task_count
            ):
                raise ValueError
        except Exception:
            raise cls._safe_error() from None
        record_content = {
            "schema_version": "1.0",
            "scope_id": scope_id,
            "cwe": cwe,
            "model_id": model_id,
            "variables": ordered,
            "row_count": row_count,
            "independent_task_count": independent_task_count,
        }
        table_sha256 = _digest(
            {
                **record_content,
                "observations": observations,
            }
        )
        return cls(
            **record_content,
            table_id=f"table_{table_sha256}",
            table_sha256=table_sha256,
        )

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        variable_ids = tuple(item.variable_id for item in self.variables)
        if (
            not _valid_identifier(self.scope_id)
            or not _CWE_PATTERN.fullmatch(self.cwe)
            or not _valid_identifier(self.model_id)
            or not 2 <= len(self.variables) <= _MAX_VARIABLES
            or variable_ids != tuple(sorted(variable_ids))
            or len(variable_ids) != len(set(variable_ids))
            or self.independent_task_count > self.row_count
            or self.table_id != f"table_{self.table_sha256}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CausalObservationRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    row_id: str = Field(pattern=_ROW_ID_PATTERN)
    task_id: str
    prompt_id: str
    model_id: str
    seed_id: int
    values: tuple[int, ...] = Field(min_length=2, max_length=_MAX_VARIABLES)

    @staticmethod
    def row_id_from_content(
        *,
        task_id: str,
        prompt_id: str,
        model_id: str,
        seed_id: int,
        values: Sequence[int],
    ) -> str:
        return _row_id_from_content(
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=model_id,
            seed_id=seed_id,
            values=values,
        )

    @classmethod
    def from_content(
        cls,
        *,
        table: CausalTableRecord,
        task_id: str,
        prompt_id: str,
        model_id: str,
        seed_id: int,
        values: Sequence[int],
    ) -> Self:
        try:
            table = CausalTableRecord.model_validate(table)
            encoded = tuple(values)
            if (
                model_id != table.model_id
                or len(encoded) != len(table.variables)
                or any(
                    type(value) is not int or not 0 <= value < len(variable.states)
                    for value, variable in zip(encoded, table.variables, strict=True)
                )
            ):
                raise ValueError
            payload = {
                "schema_version": "1.0",
                "table_id": table.table_id,
                "task_id": task_id,
                "prompt_id": prompt_id,
                "model_id": model_id,
                "seed_id": seed_id,
                "values": encoded,
            }
            row_id = cls.row_id_from_content(
                task_id=task_id,
                prompt_id=prompt_id,
                model_id=model_id,
                seed_id=seed_id,
                values=encoded,
            )
            return cls(**payload, row_id=row_id)
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = self.row_id_from_content(
            task_id=self.task_id,
            prompt_id=self.prompt_id,
            model_id=self.model_id,
            seed_id=self.seed_id,
            values=self.values,
        )
        if (
            not _valid_identifier(self.task_id)
            or not _valid_identifier(self.prompt_id)
            or not _valid_identifier(self.model_id)
            or not 2 <= len(self.values) <= _MAX_VARIABLES
            or any(type(value) is not int or not 0 <= value <= 255 for value in self.values)
            or self.row_id != expected
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PAGEdgeRecord(_CausalContract):
    left: str
    right: str
    left_mark: EndpointMark
    right_mark: EndpointMark

    @field_validator("left_mark", "right_mark", mode="before")
    @classmethod
    def parse_endpoint_mark(cls, value: object) -> object:
        return _exact_enum_value(value, EndpointMark)

    @model_validator(mode="before")
    @classmethod
    def canonicalize_endpoints(cls, value: object) -> object:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        left = payload.get("left")
        right = payload.get("right")
        if isinstance(left, str) and isinstance(right, str) and right < left:
            payload["left"], payload["right"] = right, left
            payload["left_mark"], payload["right_mark"] = (
                payload.get("right_mark"),
                payload.get("left_mark"),
            )
        return payload

    @model_validator(mode="after")
    def validate_endpoints(self) -> Self:
        if (
            not _VARIABLE_ID_PATTERN.fullmatch(self.left)
            or not _VARIABLE_ID_PATTERN.fullmatch(self.right)
            or self.left >= self.right
        ):
            raise ValueError(self._safe_validation_message)
        return self

    def marks_from(self, source: str, target: str) -> tuple[EndpointMark, EndpointMark]:
        if (source, target) == (self.left, self.right):
            return self.left_mark, self.right_mark
        if (source, target) == (self.right, self.left):
            return self.right_mark, self.left_mark
        raise ValueError("edge does not contain the requested ordered pair")


class PAGRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    pag_id: str = Field(pattern=_PAG_ID_PATTERN)
    run_kind: PAGRunKind
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    backend: str
    backend_version: str
    ci_test: Literal["gsq"]
    config_sha256: str = Field(pattern=_SHA256_PATTERN)
    background_knowledge_sha256: str = Field(pattern=_SHA256_PATTERN)
    variable_ids: tuple[str, ...] = Field(min_length=2, max_length=_MAX_VARIABLES)
    edges: tuple[PAGEdgeRecord, ...] = Field(max_length=_MAX_PAG_EDGES)

    @field_validator("run_kind", mode="before")
    @classmethod
    def parse_run_kind(cls, value: object) -> object:
        return _exact_enum_value(value, PAGRunKind)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = dict(content)
            payload["schema_version"] = "1.0"
            if (
                type(payload.get("variable_ids")) not in {list, tuple}
                or not 2 <= len(payload["variable_ids"]) <= _MAX_VARIABLES
                or type(payload.get("edges")) not in {list, tuple}
                or len(payload["edges"]) > _MAX_PAG_EDGES
            ):
                raise ValueError
            payload["variable_ids"] = tuple(sorted(payload["variable_ids"]))
            payload["edges"] = tuple(
                sorted(payload["edges"], key=lambda item: (item.left, item.right))
            )
            return cls(**payload, pag_id=f"pag_{_digest(payload)}")
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        edge_pairs = tuple((edge.left, edge.right) for edge in self.edges)
        variables = set(self.variable_ids)
        expected = _digest(_content(self, "pag_id"))
        if (
            not _valid_identifier(self.backend)
            or not _valid_identifier(self.backend_version)
            or not 2 <= len(self.variable_ids) <= _MAX_VARIABLES
            or self.variable_ids != tuple(sorted(self.variable_ids))
            or len(variables) != len(self.variable_ids)
            or any(not _VARIABLE_ID_PATTERN.fullmatch(item) for item in self.variable_ids)
            or edge_pairs != tuple(sorted(edge_pairs))
            or len(edge_pairs) != len(set(edge_pairs))
            or any(edge.left not in variables or edge.right not in variables for edge in self.edges)
            or self.pag_id != f"pag_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _canonical_pair(left: str, right: str) -> tuple[str, str]:
    return (left, right) if left < right else (right, left)


class BackgroundKnowledgeRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    knowledge_id: str = Field(pattern=_BK_ID_PATTERN)
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    tiers: tuple[tuple[str, int], ...] = Field(max_length=_MAX_VARIABLES)
    unconstrained_variable_ids: tuple[str, ...] = Field(default=(), max_length=_MAX_VARIABLES)
    forbidden_directions: tuple[tuple[str, str], ...] = Field(max_length=_MAX_DIRECTION_CONSTRAINTS)
    forbidden_adjacencies: tuple[tuple[str, str], ...] = Field(max_length=_MAX_PAG_EDGES)
    required_directions: tuple[tuple[str, str], ...] = Field(
        default=(), max_length=_MAX_DIRECTION_CONSTRAINTS
    )
    knowledge_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(
        cls,
        *,
        table_id: str,
        tiers: Sequence[tuple[str, int]],
        forbidden_directions: Sequence[tuple[str, str]],
        forbidden_adjacencies: Sequence[tuple[str, str]],
        variable_ids: Sequence[str] | None = None,
        unconstrained_variable_ids: Sequence[str] = (),
        required_directions: Sequence[tuple[str, str]] = (),
    ) -> Self:
        try:
            if (
                type(tiers) not in {list, tuple}
                or len(tiers) > _MAX_VARIABLES
                or (
                    variable_ids is not None
                    and (
                        type(variable_ids) not in {list, tuple}
                        or len(variable_ids) > _MAX_VARIABLES
                    )
                )
                or type(unconstrained_variable_ids) not in {list, tuple}
                or len(unconstrained_variable_ids) > _MAX_VARIABLES
                or type(forbidden_directions) not in {list, tuple}
                or len(forbidden_directions) > _MAX_DIRECTION_CONSTRAINTS
                or type(forbidden_adjacencies) not in {list, tuple}
                or len(forbidden_adjacencies) > _MAX_PAG_EDGES
                or type(required_directions) not in {list, tuple}
                or len(required_directions) > _MAX_DIRECTION_CONSTRAINTS
            ):
                raise ValueError
            ordered_tiers = tuple(sorted(tiers))
            ordered_unconstrained = tuple(sorted(unconstrained_variable_ids))
            inferred_variables = {item for item, _tier in ordered_tiers} | set(
                ordered_unconstrained
            )
            variables = inferred_variables if variable_ids is None else set(variable_ids)
            ordered_forbidden = tuple(sorted(forbidden_directions))
            ordered_adjacencies = tuple(
                sorted(_canonical_pair(left, right) for left, right in forbidden_adjacencies)
            )
            ordered_required = tuple(sorted(required_directions))
            if variables != inferred_variables:
                raise ValueError
            payload = {
                "schema_version": "1.0",
                "table_id": table_id,
                "tiers": ordered_tiers,
                "unconstrained_variable_ids": ordered_unconstrained,
                "forbidden_directions": ordered_forbidden,
                "forbidden_adjacencies": ordered_adjacencies,
                "required_directions": ordered_required,
            }
            digest = _digest(payload)
            return cls(
                **payload,
                knowledge_id=f"bk_{digest}",
                knowledge_sha256=digest,
            )
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        tier_variables = tuple(variable for variable, _tier in self.tiers)
        known = set(tier_variables) | set(self.unconstrained_variable_ids)
        directions = (*self.forbidden_directions, *self.required_directions)
        forbidden_adjacencies = set(self.forbidden_adjacencies)
        required_pairs = {
            _canonical_pair(source, target) for source, target in self.required_directions
        }
        tier_by_variable = dict(self.tiers)
        expected = _digest(_content(self, "knowledge_id", "knowledge_sha256"))
        if (
            self.tiers != tuple(sorted(self.tiers))
            or len(tier_variables) != len(set(tier_variables))
            or any(not 0 <= tier <= 2 for _variable, tier in self.tiers)
            or self.unconstrained_variable_ids != tuple(sorted(self.unconstrained_variable_ids))
            or len(self.unconstrained_variable_ids) != len(set(self.unconstrained_variable_ids))
            or set(tier_variables) & set(self.unconstrained_variable_ids)
            or not 2 <= len(known) <= _MAX_VARIABLES
            or any(not _VARIABLE_ID_PATTERN.fullmatch(item) for item in known)
            or self.forbidden_directions != tuple(sorted(self.forbidden_directions))
            or len(self.forbidden_directions) != len(set(self.forbidden_directions))
            or self.required_directions != tuple(sorted(self.required_directions))
            or len(self.required_directions) != len(set(self.required_directions))
            or len(required_pairs) != len(self.required_directions)
            or self.forbidden_adjacencies != tuple(sorted(self.forbidden_adjacencies))
            or len(self.forbidden_adjacencies) != len(forbidden_adjacencies)
            or any(left >= right for left, right in self.forbidden_adjacencies)
            or any(
                left == right or left not in known or right not in known
                for left, right in directions
            )
            or any(
                left not in known or right not in known
                for left, right in self.forbidden_adjacencies
            )
            or set(self.required_directions) & set(self.forbidden_directions)
            or any(
                _canonical_pair(*item) in forbidden_adjacencies for item in self.required_directions
            )
            or any(
                source in tier_by_variable
                and target in tier_by_variable
                and tier_by_variable[source] > tier_by_variable[target]
                for source, target in self.required_directions
            )
            or self.knowledge_sha256 != expected
            or self.knowledge_id != f"bk_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class CausalExclusionRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    exclusion_id: str = Field(pattern=r"^exclusion_[0-9a-f]{64}$")
    scope_id: str
    cwe: str
    model_id: str
    task_id: str
    prompt_id: str
    seed_id: int
    variable_id: str
    reason_code: CausalExclusionReason
    producer_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("reason_code", mode="before")
    @classmethod
    def parse_reason_code(cls, value: object) -> object:
        return _exact_enum_value(value, CausalExclusionReason)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            return cls(**payload, exclusion_id=f"exclusion_{_digest(payload)}")
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "exclusion_id"))
        if (
            not _valid_identifier(self.scope_id)
            or not _CWE_PATTERN.fullmatch(self.cwe)
            or any(
                not _valid_identifier(value)
                for value in (self.model_id, self.task_id, self.prompt_id)
            )
            or not _VARIABLE_ID_PATTERN.fullmatch(self.variable_id)
            or self.exclusion_id != f"exclusion_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class BootstrapDrawItem(_CausalContract):
    draw_index: int = Field(ge=0, le=_MAX_ROWS - 1)
    task_id: str
    prompt_id: str
    seed_id: int
    row_id: str = Field(pattern=_ROW_ID_PATTERN)

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        if not _valid_identifier(self.task_id) or not _valid_identifier(self.prompt_id):
            raise ValueError(self._safe_validation_message)
        return self


class BootstrapDrawRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    draw_id: str = Field(pattern=_DRAW_ID_PATTERN)
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    run_kind: Literal[
        PAGRunKind.OBSERVATIONAL_REFERENCE,
        PAGRunKind.OBSERVATIONAL_BOOTSTRAP,
    ]
    replicate_index: int | None = Field(default=None, ge=0, le=9999)
    rng_version: str
    seed_material_sha256: str = Field(pattern=_SHA256_PATTERN)
    items: tuple[BootstrapDrawItem, ...] = Field(min_length=2, max_length=_MAX_ROWS)
    draw_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("run_kind", mode="before")
    @classmethod
    def parse_run_kind(cls, value: object) -> object:
        return _exact_enum_value(value, PAGRunKind)

    @property
    def selected_row_ids(self) -> tuple[str, ...]:
        return tuple(item.row_id for item in self.items)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            if (
                type(payload.get("items")) not in {list, tuple}
                or not 2 <= len(payload["items"]) <= _MAX_ROWS
            ):
                raise ValueError
            payload["items"] = tuple(sorted(payload["items"], key=lambda item: item.draw_index))
            digest = _digest(
                {
                    **payload,
                    "items": [item.model_dump(mode="json") for item in payload["items"]],
                }
            )
            return cls(**payload, draw_id=f"draw_{digest}", draw_sha256=digest)
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        indices = tuple(item.draw_index for item in self.items)
        expected = _digest(_content(self, "draw_id", "draw_sha256"))
        reference = self.run_kind is PAGRunKind.OBSERVATIONAL_REFERENCE
        if (
            not _valid_identifier(self.rng_version)
            or not 2 <= len(self.items) <= _MAX_ROWS
            or indices != tuple(sorted(indices))
            or len(indices) != len(set(indices))
            or indices != tuple(range(len(indices)))
            or (reference and self.replicate_index is not None)
            or (not reference and self.replicate_index is None)
            or self.draw_sha256 != expected
            or self.draw_id != f"draw_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class BootstrapPAGRecord(_CausalVersionedContract):
    """Content-addressed binding of one successful draw to its exact PAG input matrix."""

    schema_version: Literal["1.0"]
    bootstrap_pag_id: str = Field(pattern=_BOOTSTRAP_PAG_ID_PATTERN)
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    replicate_index: int = Field(ge=0, le=9999)
    draw_id: str = Field(pattern=_DRAW_ID_PATTERN)
    matrix_sha256: str = Field(pattern=_SHA256_PATTERN)
    pag: PAGRecord
    bootstrap_pag_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            pag = PAGRecord.model_validate(payload["pag"])
            payload["pag"] = pag
            digest = _digest(payload)
            return cls(
                **payload,
                bootstrap_pag_id=f"bootstrap_pag_{digest}",
                bootstrap_pag_sha256=digest,
            )
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "bootstrap_pag_id", "bootstrap_pag_sha256"))
        if (
            self.pag.run_kind is not PAGRunKind.OBSERVATIONAL_BOOTSTRAP
            or self.pag.table_id != self.table_id
            or self.bootstrap_pag_sha256 != expected
            or self.bootstrap_pag_id != f"bootstrap_pag_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class BootstrapFailureRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    failure_id: str = Field(pattern=r"^bootstrap_failure_[0-9a-f]{64}$")
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    replicate_index: int = Field(ge=0, le=9999)
    draw_id: str = Field(pattern=_DRAW_ID_PATTERN)
    reason_code: BootstrapFailureReason
    fci_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    detail_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)

    @field_validator("reason_code", mode="before")
    @classmethod
    def parse_reason_code(cls, value: object) -> object:
        return _exact_enum_value(value, BootstrapFailureReason)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            return cls(**payload, failure_id=f"bootstrap_failure_{_digest(payload)}")
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        expected = _digest(_content(self, "failure_id"))
        if self.failure_id != f"bootstrap_failure_{expected}":
            raise ValueError(self._safe_validation_message)
        return self


class DiscoveryFailureRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    failure_id: str = Field(pattern=r"^discovery_failure_[0-9a-f]{64}$")
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    scope_id: str
    model_id: str
    reason_code: DiscoveryFailureReason
    table_sha256: str = Field(pattern=_SHA256_PATTERN)
    fci_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    background_knowledge_sha256: str = Field(pattern=_SHA256_PATTERN)
    detail_sha256: str = Field(pattern=_SHA256_PATTERN, repr=False)

    @field_validator("reason_code", mode="before")
    @classmethod
    def parse_reason_code(cls, value: object) -> object:
        return _exact_enum_value(value, DiscoveryFailureReason)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            return cls(**payload, failure_id=f"discovery_failure_{_digest(payload)}")
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "failure_id"))
        if (
            not _valid_identifier(self.scope_id)
            or not _valid_identifier(self.model_id)
            or self.failure_id != f"discovery_failure_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PathPatternRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    path_id: str = Field(pattern=_PATH_ID_PATTERN)
    variable_ids: tuple[str, ...] = Field(min_length=2, max_length=17)
    endpoint_marks: tuple[tuple[EndpointMark, EndpointMark], ...] = Field(
        min_length=1, max_length=16
    )
    path_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("endpoint_marks", mode="before")
    @classmethod
    def parse_endpoint_marks(cls, value: object) -> object:
        snapshot = _snapshot_json_arrays(value)
        if type(snapshot) is not tuple:
            return snapshot
        parsed: list[object] = []
        for pair in snapshot:
            if type(pair) is not tuple:
                parsed.append(pair)
                continue
            parsed.append(tuple(_exact_enum_value(mark, EndpointMark) for mark in pair))
        return tuple(parsed)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            if (
                type(payload.get("variable_ids")) not in {list, tuple}
                or not 2 <= len(payload["variable_ids"]) <= 17
                or type(payload.get("endpoint_marks")) not in {list, tuple}
                or not 1 <= len(payload["endpoint_marks"]) <= 16
            ):
                raise ValueError
            digest = _digest(payload)
            return cls(**payload, path_id=f"path_{digest}", path_sha256=digest)
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "path_id", "path_sha256"))
        if (
            not 2 <= len(self.variable_ids) <= 17
            or len(self.endpoint_marks) != len(self.variable_ids) - 1
            or len(self.variable_ids) != len(set(self.variable_ids))
            or any(not _VARIABLE_ID_PATTERN.fullmatch(item) for item in self.variable_ids)
            or self.path_sha256 != expected
            or self.path_id != f"path_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self


class PathSupportRecord(_CausalVersionedContract):
    schema_version: Literal["1.0"]
    support_id: str = Field(pattern=r"^path_support_[0-9a-f]{64}$")
    table_id: str = Field(pattern=_TABLE_ID_PATTERN)
    reference_pag_id: str = Field(pattern=_PAG_ID_PATTERN)
    path: PathPatternRecord
    support_numerator: int = Field(ge=0, le=10_000)
    support_denominator: int = Field(gt=0, le=10_000)
    bootstrap_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    support_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            payload = {"schema_version": "1.0", **content}
            digest = _digest(
                {
                    **payload,
                    "path": payload["path"].model_dump(mode="json"),
                }
            )
            return cls(
                **payload,
                support_id=f"path_support_{digest}",
                support_sha256=digest,
            )
        except Exception:
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_semantics_and_digest(self) -> Self:
        expected = _digest(_content(self, "support_id", "support_sha256"))
        if (
            self.support_numerator > self.support_denominator
            or self.support_sha256 != expected
            or self.support_id != f"path_support_{expected}"
        ):
            raise ValueError(self._safe_validation_message)
        return self

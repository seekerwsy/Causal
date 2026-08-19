"""Receipt-authenticated natural discovery tables and two-level CI draws."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.outcomes.discovery_assembler_v2 import (
    AuthenticatedNaturalObservationReceiptV2,
)
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.discovery_v2 import (
    AuthenticatedNaturalDiscoveryScopeV2,
    DiscoveryAnalysisKindV2,
    DiscoveryVariableSupportV2,
    NaturalDiscoveryTableArtifactV2,
    PairwiseDeterminismV2,
    _observation_values,
    _support_and_determinism,
)

AUTHENTICATED_NATURAL_TABLE_V2_SCHEMA_VERSION = "2.0"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_AUTHENTICATED_TABLE_PATTERN = r"^authenticated_natural_table_[0-9a-f]{64}$"
_DRAW_MANIFEST_PATTERN = r"^two_level_cluster_draw_[0-9a-f]{64}$"
_RECEIPT_PATTERN = r"^authenticated_natural_observation_[0-9a-f]{64}$"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


class _AuthenticatedTableContractV2(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = (
        "authenticated natural discovery table failed exact validation"
    )
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = AUTHENTICATED_NATURAL_TABLE_V2_SCHEMA_VERSION

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedAuthenticatedTableV2(_AuthenticatedTableContractV2):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {
                "schema_version": AUTHENTICATED_NATURAL_TABLE_V2_SCHEMA_VERSION,
                **content,
            }
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the content-addressed boundary
            content.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


def _receipt_sort_key(
    receipt: AuthenticatedNaturalObservationReceiptV2,
) -> tuple[str, str, int]:
    observation = receipt.observation
    return (
        observation.semantic_task_cluster_id,
        observation.task_instance_id,
        observation.request_randomness_slot,
    )


def _canonical_authenticated_table_components(
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
    receipts: tuple[AuthenticatedNaturalObservationReceiptV2, ...],
) -> tuple[NaturalDiscoveryTableArtifactV2, str, bool]:
    scope = AuthenticatedNaturalDiscoveryScopeV2.model_validate(authenticated_scope, strict=True)
    checked = tuple(
        AuthenticatedNaturalObservationReceiptV2.model_validate(item, strict=True)
        for item in receipts
    )
    if (
        len({item.receipt_id for item in checked}) != len(checked)
        or checked != tuple(sorted(checked, key=_receipt_sort_key))
        or any(item.authenticated_scope != scope for item in checked)
    ):
        raise ValueError("receipt scope, identity, or order drifted")
    raw = NaturalDiscoveryTableArtifactV2.from_components(
        table_spec=scope.table_spec,
        observations=tuple(item.observation for item in checked),
        producer_chains=tuple(item.producer_chain for item in checked),
    )
    receipt_by_observation = {
        item.observation.natural_causal_observation_id: item for item in checked
    }
    if (
        len(receipt_by_observation) != len(checked)
        or set(receipt_by_observation)
        != {item.natural_causal_observation_id for item in raw.observations}
        or any(
            receipt_by_observation[item.natural_causal_observation_id].producer_chain != chain
            for item, chain in zip(raw.observations, raw.producer_chains, strict=True)
        )
    ):
        raise ValueError("receipt payload does not exactly generate the raw audit table")
    payload_sha256 = _digest(tuple(item.receipt_id for item in checked))
    direct_ci_ready = (
        scope.table_spec.analysis_kind is not DiscoveryAnalysisKindV2.TWO_LEVEL
        and raw.minimal_generating_set_passed
    )
    return raw, payload_sha256, direct_ci_ready


class AuthenticatedNaturalDiscoveryTableArtifactV2(_ContentAddressedAuthenticatedTableV2):
    """Receipt-backed audit table; only non-two-level valid tables are directly CI-ready."""

    _id_field = "authenticated_table_id"
    _id_prefix = "authenticated_natural_table_"

    authenticated_table_id: str = Field(pattern=_AUTHENTICATED_TABLE_PATTERN)
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2
    receipts: tuple[AuthenticatedNaturalObservationReceiptV2, ...] = Field(
        min_length=2, max_length=1_000_000
    )
    raw_audit_table: NaturalDiscoveryTableArtifactV2
    receipt_payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    direct_ci_ready: bool

    @field_validator("receipts", mode="before")
    @classmethod
    def snapshot_receipts(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @classmethod
    def from_receipts(
        cls,
        *,
        authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
        receipts: tuple[AuthenticatedNaturalObservationReceiptV2, ...],
    ) -> Self:
        try:
            raw, payload_sha256, direct_ci_ready = _canonical_authenticated_table_components(
                authenticated_scope,
                receipts,
            )
            if (
                authenticated_scope.table_spec.analysis_kind
                is not DiscoveryAnalysisKindV2.TWO_LEVEL
                and not direct_ci_ready
            ):
                raise ValueError("constant or deterministic variables forbid formal CI")
            return cls.from_content(
                authenticated_scope=authenticated_scope,
                receipts=receipts,
                raw_audit_table=raw,
                receipt_payload_sha256=payload_sha256,
                direct_ci_ready=direct_ci_ready,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise ValueError(cls._safe_validation_message) from error

    @model_validator(mode="after")
    def validate_authenticated_table(self) -> Self:
        try:
            raw, payload_sha256, direct_ci_ready = _canonical_authenticated_table_components(
                self.authenticated_scope,
                self.receipts,
            )
            if (
                self.raw_audit_table != raw
                or self.receipt_payload_sha256 != payload_sha256
                or self.direct_ci_ready != direct_ci_ready
                or (
                    self.authenticated_scope.table_spec.analysis_kind
                    is not DiscoveryAnalysisKindV2.TWO_LEVEL
                    and not direct_ci_ready
                )
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize receipt/table replay failures
            raise ValueError(self._safe_validation_message) from None
        return self


class TwoLevelClusterDrawSelectionV2(_AuthenticatedTableContractV2):
    occurrence_index: StrictInt = Field(ge=0, le=1_000_000)
    semantic_task_cluster_id: str
    task_instance_id: str
    request_randomness_slot: StrictInt = Field(ge=0, le=2_147_483_647)
    receipt_id: str = Field(pattern=_RECEIPT_PATTERN)
    row: tuple[StrictInt, ...] = Field(min_length=2, max_length=128)

    @field_validator("row", mode="before")
    @classmethod
    def snapshot_row(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        if (
            _IDENTIFIER_RE.fullmatch(self.semantic_task_cluster_id) is None
            or _IDENTIFIER_RE.fullmatch(self.task_instance_id) is None
            or any(type(value) is not int or value < 0 for value in self.row)
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _deterministic_index(
    *,
    domain: str,
    seed: int,
    purpose: str,
    values: tuple[object, ...],
    upper_bound: int,
) -> int:
    if upper_bound < 1:
        raise ValueError("empty deterministic draw domain")
    payload = (domain, str(seed), purpose, *values)
    return int(_digest(payload), 16) % upper_bound


def _canonical_two_level_draw(
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    *,
    resample_seed: int,
    resample_domain: str,
) -> tuple[
    tuple[TwoLevelClusterDrawSelectionV2, ...],
    tuple[DiscoveryVariableSupportV2, ...],
    tuple[PairwiseDeterminismV2, ...],
    bool,
    str,
]:
    checked = AuthenticatedNaturalDiscoveryTableArtifactV2.model_validate(table, strict=True)
    spec = checked.authenticated_scope.table_spec
    if (
        spec.analysis_kind is not DiscoveryAnalysisKindV2.TWO_LEVEL
        or type(resample_seed) is not int
        or not 0 <= resample_seed <= 2**63 - 1
        or type(resample_domain) is not str
        or _IDENTIFIER_RE.fullmatch(resample_domain) is None
    ):
        raise ValueError("two-level draw configuration failed exact validation")
    support_by_cluster: dict[str, list[object]] = {}
    for support in spec.task_slot_support:
        support_by_cluster.setdefault(support.semantic_task_cluster_id, []).append(support)
    cluster_ids = tuple(sorted(support_by_cluster))
    receipt_by_coordinate = {
        (
            item.observation.task_instance_id,
            item.observation.request_randomness_slot,
        ): item
        for item in checked.receipts
    }
    selections: list[TwoLevelClusterDrawSelectionV2] = []
    for occurrence_index in range(len(cluster_ids)):
        cluster_id = cluster_ids[
            _deterministic_index(
                domain=resample_domain,
                seed=resample_seed,
                purpose="semantic_cluster",
                values=(occurrence_index,),
                upper_bound=len(cluster_ids),
            )
        ]
        cluster_support = sorted(
            support_by_cluster[cluster_id], key=lambda item: item.task_instance_id
        )
        for support in cluster_support:
            slot = support.request_randomness_slots[
                _deterministic_index(
                    domain=resample_domain,
                    seed=resample_seed,
                    purpose="request_randomness_slot",
                    values=(occurrence_index, cluster_id, support.task_instance_id),
                    upper_bound=len(support.request_randomness_slots),
                )
            ]
            receipt = receipt_by_coordinate.get((support.task_instance_id, slot))
            if receipt is None:
                raise ValueError("two-level draw references a missing authenticated receipt")
            selections.append(
                TwoLevelClusterDrawSelectionV2(
                    schema_version=AUTHENTICATED_NATURAL_TABLE_V2_SCHEMA_VERSION,
                    occurrence_index=occurrence_index,
                    semantic_task_cluster_id=cluster_id,
                    task_instance_id=support.task_instance_id,
                    request_randomness_slot=slot,
                    receipt_id=receipt.receipt_id,
                    row=_observation_values(spec, receipt.observation),
                )
            )
    rows = tuple(item.row for item in selections)
    support, dependencies, passed = _support_and_determinism(spec, rows)
    return tuple(selections), support, dependencies, passed, _digest(rows)


class TwoLevelClusterResampleManifestV2(_ContentAddressedAuthenticatedTableV2):
    """One frozen cluster-bootstrap draw with one frozen slot per task occurrence."""

    _id_field = "draw_manifest_id"
    _id_prefix = "two_level_cluster_draw_"

    draw_manifest_id: str = Field(pattern=_DRAW_MANIFEST_PATTERN)
    authenticated_table: AuthenticatedNaturalDiscoveryTableArtifactV2
    resample_seed: StrictInt = Field(ge=0, le=2**63 - 1)
    resample_domain: str
    algorithm: Literal["cluster_bootstrap_then_uniform_frozen_slot_sha256_v1"]
    selections: tuple[TwoLevelClusterDrawSelectionV2, ...] = Field(
        min_length=2, max_length=1_000_000
    )
    variable_support: tuple[DiscoveryVariableSupportV2, ...] = Field(min_length=2, max_length=128)
    pairwise_predictor_determinism: tuple[PairwiseDeterminismV2, ...]
    minimal_generating_set_passed: bool
    row_payload_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "selections",
        "variable_support",
        "pairwise_predictor_determinism",
        mode="before",
    )
    @classmethod
    def snapshot_sequences(cls, value: object) -> object:
        return tuple(value) if type(value) in {tuple, list} else value

    @classmethod
    def from_table(
        cls,
        *,
        authenticated_table: AuthenticatedNaturalDiscoveryTableArtifactV2,
        resample_seed: int,
        resample_domain: str,
    ) -> Self:
        try:
            selections, support, dependencies, passed, payload_sha256 = _canonical_two_level_draw(
                authenticated_table,
                resample_seed=resample_seed,
                resample_domain=resample_domain,
            )
            return cls.from_content(
                authenticated_table=authenticated_table,
                resample_seed=resample_seed,
                resample_domain=resample_domain,
                algorithm="cluster_bootstrap_then_uniform_frozen_slot_sha256_v1",
                selections=selections,
                variable_support=support,
                pairwise_predictor_determinism=dependencies,
                minimal_generating_set_passed=passed,
                row_payload_sha256=payload_sha256,
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            raise ValueError(cls._safe_validation_message) from error

    @model_validator(mode="after")
    def validate_draw(self) -> Self:
        try:
            selections, support, dependencies, passed, payload_sha256 = _canonical_two_level_draw(
                self.authenticated_table,
                resample_seed=self.resample_seed,
                resample_domain=self.resample_domain,
            )
            if (
                self.algorithm != "cluster_bootstrap_then_uniform_frozen_slot_sha256_v1"
                or self.selections != selections
                or self.variable_support != support
                or self.pairwise_predictor_determinism != dependencies
                or self.minimal_generating_set_passed != passed
                or self.row_payload_sha256 != payload_sha256
            ):
                raise ValueError
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize deterministic draw replay failures
            raise ValueError(self._safe_validation_message) from None
        return self


def build_authenticated_natural_discovery_table_v2(
    *,
    authenticated_scope: AuthenticatedNaturalDiscoveryScopeV2,
    receipts: tuple[AuthenticatedNaturalObservationReceiptV2, ...],
) -> AuthenticatedNaturalDiscoveryTableArtifactV2:
    """Build a table only from complete, replay-validated observation receipts."""

    return AuthenticatedNaturalDiscoveryTableArtifactV2.from_receipts(
        authenticated_scope=authenticated_scope,
        receipts=receipts,
    )


def authenticated_categorical_rows_for_fci_v2(
    table: AuthenticatedNaturalDiscoveryTableArtifactV2,
) -> tuple[tuple[int, ...], ...]:
    """Return formal CI rows; raw two-level matrices and invalid support fail closed."""

    checked = AuthenticatedNaturalDiscoveryTableArtifactV2.model_validate(table, strict=True)
    if not checked.direct_ci_ready:
        raise ValueError(
            "formal CI requires a non-two-level authenticated table with nonconstant, "
            "nondeterministic variables"
        )
    return checked.raw_audit_table.categorical_rows()


def build_two_level_cluster_resample_v2(
    *,
    authenticated_table: AuthenticatedNaturalDiscoveryTableArtifactV2,
    resample_seed: int,
    resample_domain: str,
) -> TwoLevelClusterResampleManifestV2:
    """Freeze one task-cluster bootstrap draw and one slot per task occurrence."""

    return TwoLevelClusterResampleManifestV2.from_table(
        authenticated_table=authenticated_table,
        resample_seed=resample_seed,
        resample_domain=resample_domain,
    )


def two_level_categorical_rows_for_fci_v2(
    draw: TwoLevelClusterResampleManifestV2,
) -> tuple[tuple[int, ...], ...]:
    """Return a frozen two-level draw only when it satisfies the formal CI gate."""

    checked = TwoLevelClusterResampleManifestV2.model_validate(draw, strict=True)
    if not checked.minimal_generating_set_passed:
        raise ValueError("two-level draw has constant or deterministic variables")
    return tuple(item.row for item in checked.selections)


__all__ = [
    "AUTHENTICATED_NATURAL_TABLE_V2_SCHEMA_VERSION",
    "AuthenticatedNaturalDiscoveryTableArtifactV2",
    "TwoLevelClusterDrawSelectionV2",
    "TwoLevelClusterResampleManifestV2",
    "authenticated_categorical_rows_for_fci_v2",
    "build_authenticated_natural_discovery_table_v2",
    "build_two_level_cluster_resample_v2",
    "two_level_categorical_rows_for_fci_v2",
]

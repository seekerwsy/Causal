"""Frozen strict confirmed-yield selector-comparison protocol.

The protocol in this module is derived, rather than caller assembled.  Its
candidate universe, selector ranks, bridge failures, hypothesis/model tests,
directions, and supports all come from one :class:`ConfirmatoryExperimentFreezeV2`
and its unique formal primary secure-yield family.  Consequently an empty or
failed slot can never disappear from the denominator and duplicate slot
references can never manufacture duplicate hypothesis tests.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum, StrEnum
from itertools import combinations
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from secaware.randomness import RNG_VERSION
from secaware.schema.common import SafeValidationMixin, StrictModel
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.inference_v2 import FORMAL_MIN_BOOTSTRAP_SAMPLES_V2
from secaware.schema.multi_support_inference_v2 import (
    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2,
    MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2,
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
)
from secaware.schema.policy_v2 import (
    BridgeStatus,
    ExpectedDirection,
    SelectorSlotStatus,
)

SELECTOR_UTILITY_V2_SCHEMA_VERSION = "2.0"
SELECTOR_UTILITY_SYNTHETIC_MIN_BOOTSTRAP_SAMPLES_V2 = 19
SELECTOR_UTILITY_FORMAL_INNER_BOOTSTRAP_SAMPLES_V2 = 499

_PLAN_PATTERN = r"^selector_utility_plan_v2_[0-9a-f]{64}$"
_SLOT_PATTERN = r"^selector_utility_slot_v2_[0-9a-f]{64}$"
_GROUP_PATTERN = r"^selector_utility_group_v2_[0-9a-f]{64}$"
_PAIR_PATTERN = r"^selector_utility_pair_v2_[0-9a-f]{64}$"
_COORDINATE_PATTERN = r"^selector_utility_coordinate_v2_[0-9a-f]{64}$"


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


def _snapshot_arrays(value: object) -> object:
    if type(value) is dict:
        return {key: _snapshot_arrays(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return tuple(_snapshot_arrays(item) for item in value)
    return value


class SelectorUtilityPlanScopeV2(StrEnum):
    FORMAL = "formal"
    SYNTHETIC_VALIDATION_ONLY = "synthetic_validation_only"


class SelectorUtilitySlotStatusV2(StrEnum):
    PROTOCOLIZED = "protocolized"
    EMPTY = "empty"
    BRIDGE_OR_PROTOCOLIZATION_FAILED = "bridge_or_protocolization_failed"


class SelectorPairInferenceStatusV2(StrEnum):
    EVALUATED = "evaluated"
    NON_EVALUABLE = "non_evaluable"


class SelectorPairNonEvaluableReasonV2(StrEnum):
    NO_PREREGISTERED_PAIRS = "no_preregistered_pairs"
    INSUFFICIENT_VALID_OUTER_DRAWS = "insufficient_valid_outer_draws"
    ZERO_OR_INVALID_PAIR_STANDARD_ERROR = "zero_or_invalid_pair_standard_error"


class _SelectorUtilityV2Contract(SafeValidationMixin, StrictModel):
    _safe_validation_message: ClassVar[str] = "selector utility v2 contract failed validation"

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        protected_namespaces=(),
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal["2.0"] = SELECTOR_UTILITY_V2_SCHEMA_VERSION

    @model_validator(mode="before")
    @classmethod
    def snapshot_json_arrays(cls, value: object) -> object:
        return _snapshot_arrays(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def __str__(self) -> str:
        return f"{type(self).__name__}()"


class _ContentAddressedSelectorUtilityV2(_SelectorUtilityV2Contract):
    _id_field: ClassVar[str]
    _id_prefix: ClassVar[str]

    @classmethod
    def from_content(cls, **content: Any) -> Self:
        payload: dict[str, Any] | None = None
        try:
            if "schema_version" in content or cls._id_field in content:
                raise ValueError
            payload = {"schema_version": SELECTOR_UTILITY_V2_SCHEMA_VERSION, **content}
            return cls(**payload, **{cls._id_field: cls._id_prefix + _digest(payload)})
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001 - sanitize the public protocol boundary
            content.clear()
            if payload is not None:
                payload.clear()
            raise cls._safe_error() from None

    @model_validator(mode="after")
    def validate_content_address(self) -> Self:
        content = self.model_dump(mode="json", exclude={self._id_field})
        if getattr(self, self._id_field) != self._id_prefix + _digest(content):
            raise ValueError(self._safe_validation_message)
        return self


class SelectorUtilitySlotBindingV2(_ContentAddressedSelectorUtilityV2):
    """One exact frozen selector/model/rank slot and its bridge disposition."""

    _id_field = "slot_binding_id"
    _id_prefix = "selector_utility_slot_v2_"

    slot_binding_id: str = Field(pattern=_SLOT_PATTERN)
    selector_slot_id: str
    candidate_universe_id: str
    selection_freeze_id: str
    selector_id: str
    model_id: str
    rank: StrictInt = Field(ge=1, le=10_000)
    source_slot_status: SelectorSlotStatus
    candidate_skeleton_id: str | None
    selection_mapping_id: str | None
    bridge_status: BridgeStatus | None
    final_hypothesis_id: str | None
    slot_status: SelectorUtilitySlotStatusV2
    frozen_failure_code: str | None

    @field_validator("source_slot_status", mode="before")
    @classmethod
    def parse_source_status(cls, value: object) -> object:
        return value if isinstance(value, SelectorSlotStatus) else SelectorSlotStatus(value)

    @field_validator("bridge_status", mode="before")
    @classmethod
    def parse_bridge_status(cls, value: object) -> object:
        return value if value is None or isinstance(value, BridgeStatus) else BridgeStatus(value)

    @field_validator("slot_status", mode="before")
    @classmethod
    def parse_slot_status(cls, value: object) -> object:
        return (
            value
            if isinstance(value, SelectorUtilitySlotStatusV2)
            else SelectorUtilitySlotStatusV2(value)
        )

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.source_slot_status is SelectorSlotStatus.EMPTY:
            valid = (
                self.candidate_skeleton_id is None
                and self.selection_mapping_id is None
                and self.bridge_status is None
                and self.final_hypothesis_id is None
                and self.slot_status is SelectorUtilitySlotStatusV2.EMPTY
                and self.frozen_failure_code is not None
            )
        elif self.bridge_status is BridgeStatus.PROTOCOLIZED:
            valid = (
                self.candidate_skeleton_id is not None
                and self.selection_mapping_id is not None
                and self.final_hypothesis_id is not None
                and self.slot_status is SelectorUtilitySlotStatusV2.PROTOCOLIZED
                and self.frozen_failure_code is None
            )
        else:
            valid = (
                self.candidate_skeleton_id is not None
                and self.selection_mapping_id is not None
                and self.bridge_status is BridgeStatus.FAILED
                and self.final_hypothesis_id is None
                and self.slot_status is SelectorUtilitySlotStatusV2.BRIDGE_OR_PROTOCOLIZATION_FAILED
                and self.frozen_failure_code is not None
            )
        if not valid:
            raise ValueError(self._safe_validation_message)
        return self


class SelectorUtilityGroupBindingV2(_ContentAddressedSelectorUtilityV2):
    """The immutable rank sequence for one selector and one tested model."""

    _id_field = "selector_group_id"
    _id_prefix = "selector_utility_group_v2_"

    selector_group_id: str = Field(pattern=_GROUP_PATTERN)
    selector_id: str
    model_id: str
    budget_k: StrictInt = Field(ge=1, le=10_000)
    slot_binding_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    ranks: tuple[StrictInt, ...] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_group(self) -> Self:
        if (
            len(self.slot_binding_ids) != self.budget_k
            or len(set(self.slot_binding_ids)) != len(self.slot_binding_ids)
            or self.ranks != tuple(range(1, self.budget_k + 1))
        ):
            raise ValueError(self._safe_validation_message)
        return self


class SelectorPairBindingV2(_ContentAddressedSelectorUtilityV2):
    """One preregistered within-model paired selector comparison."""

    _id_field = "selector_pair_id"
    _id_prefix = "selector_utility_pair_v2_"

    selector_pair_id: str = Field(pattern=_PAIR_PATTERN)
    model_id: str
    left_selector_id: str
    right_selector_id: str
    left_selector_group_id: str
    right_selector_group_id: str

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if self.left_selector_id >= self.right_selector_id:
            raise ValueError(self._safe_validation_message)
        return self


class SelectorUtilityCoordinateBindingV2(_ContentAddressedSelectorUtilityV2):
    """One unique formal primary test that may be referenced by many slots."""

    _id_field = "selector_coordinate_binding_id"
    _id_prefix = "selector_utility_coordinate_v2_"

    selector_coordinate_binding_id: str = Field(pattern=_COORDINATE_PATTERN)
    test_coordinate_id: str
    coordinate_support_id: str
    hypothesis_model_coordinate_id: str
    hypothesis_id: str
    model_id: str
    outcome_name: Literal["y_secure_yield"]
    expected_direction: ExpectedDirection
    direction_multiplier: Literal[-1, 1]
    frozen_independent_cluster_count: StrictInt = Field(ge=2, le=100_000)
    frozen_minimum_independent_cluster_count: StrictInt = Field(ge=2, le=100_000)

    @field_validator("expected_direction", mode="before")
    @classmethod
    def parse_direction(cls, value: object) -> object:
        return value if isinstance(value, ExpectedDirection) else ExpectedDirection(value)

    @model_validator(mode="after")
    def validate_direction_and_support(self) -> Self:
        expected = 1 if self.expected_direction is ExpectedDirection.POSITIVE else -1
        if (
            self.direction_multiplier != expected
            or self.frozen_independent_cluster_count < self.frozen_minimum_independent_cluster_count
        ):
            raise ValueError(self._safe_validation_message)
        return self


def _expected_slot_bindings(
    experiment: ConfirmatoryExperimentFreezeV2,
) -> tuple[SelectorUtilitySlotBindingV2, ...]:
    selection = experiment.selection_freeze
    mapping_by_skeleton = {item.candidate_skeleton_id: item for item in selection.mappings}
    hypothesis_ids = set(experiment.hypothesis_ids)
    model_ids = set(experiment.model_ids)
    result: list[SelectorUtilitySlotBindingV2] = []
    for slot in selection.selector_slots:
        if slot.model_id not in model_ids:
            raise ValueError("selector model lies outside the formal model family")
        if slot.status is SelectorSlotStatus.EMPTY:
            content = {
                "selector_slot_id": slot.selector_slot_id,
                "candidate_universe_id": slot.candidate_universe_id,
                "selection_freeze_id": selection.selection_freeze_id,
                "selector_id": slot.selector_id,
                "model_id": slot.model_id,
                "rank": slot.rank,
                "source_slot_status": slot.status,
                "candidate_skeleton_id": None,
                "selection_mapping_id": None,
                "bridge_status": None,
                "final_hypothesis_id": None,
                "slot_status": SelectorUtilitySlotStatusV2.EMPTY,
                "frozen_failure_code": slot.failure_code,
            }
        else:
            mapping = mapping_by_skeleton.get(slot.candidate_skeleton_id or "")
            if mapping is None:
                raise ValueError("selected slot has no frozen mapping")
            hypothesis_id = mapping.final_hypothesis_id
            if mapping.status is BridgeStatus.PROTOCOLIZED and hypothesis_id not in hypothesis_ids:
                raise ValueError("protocolized slot is outside the formal hypothesis family")
            content = {
                "selector_slot_id": slot.selector_slot_id,
                "candidate_universe_id": slot.candidate_universe_id,
                "selection_freeze_id": selection.selection_freeze_id,
                "selector_id": slot.selector_id,
                "model_id": slot.model_id,
                "rank": slot.rank,
                "source_slot_status": slot.status,
                "candidate_skeleton_id": slot.candidate_skeleton_id,
                "selection_mapping_id": mapping.selection_mapping_id,
                "bridge_status": mapping.status,
                "final_hypothesis_id": hypothesis_id,
                "slot_status": (
                    SelectorUtilitySlotStatusV2.PROTOCOLIZED
                    if mapping.status is BridgeStatus.PROTOCOLIZED
                    else SelectorUtilitySlotStatusV2.BRIDGE_OR_PROTOCOLIZATION_FAILED
                ),
                "frozen_failure_code": mapping.failure_code,
            }
        result.append(SelectorUtilitySlotBindingV2.from_content(**content))
    return tuple(sorted(result, key=lambda item: (item.selector_id, item.model_id, item.rank)))


def _expected_groups(
    slot_bindings: tuple[SelectorUtilitySlotBindingV2, ...],
    budget_k: int,
) -> tuple[SelectorUtilityGroupBindingV2, ...]:
    grouped: dict[tuple[str, str], list[SelectorUtilitySlotBindingV2]] = {}
    for slot in slot_bindings:
        grouped.setdefault((slot.selector_id, slot.model_id), []).append(slot)
    return tuple(
        SelectorUtilityGroupBindingV2.from_content(
            selector_id=selector_id,
            model_id=model_id,
            budget_k=budget_k,
            slot_binding_ids=tuple(item.slot_binding_id for item in slots),
            ranks=tuple(item.rank for item in slots),
        )
        for (selector_id, model_id), slots in sorted(grouped.items())
    )


def _expected_pairs(
    groups: tuple[SelectorUtilityGroupBindingV2, ...],
) -> tuple[SelectorPairBindingV2, ...]:
    by_model: dict[str, list[SelectorUtilityGroupBindingV2]] = {}
    for group in groups:
        by_model.setdefault(group.model_id, []).append(group)
    result = []
    for model_id, model_groups in sorted(by_model.items()):
        for left, right in combinations(sorted(model_groups, key=lambda item: item.selector_id), 2):
            result.append(
                SelectorPairBindingV2.from_content(
                    model_id=model_id,
                    left_selector_id=left.selector_id,
                    right_selector_id=right.selector_id,
                    left_selector_group_id=left.selector_group_id,
                    right_selector_group_id=right.selector_group_id,
                )
            )
    return tuple(result)


def _expected_coordinate_bindings(
    experiment: ConfirmatoryExperimentFreezeV2,
    primary_plan: MultiSupportSimultaneousInferencePlanV2,
) -> tuple[SelectorUtilityCoordinateBindingV2, ...]:
    roots = {
        item.intervention_bridge.frozen_hypothesis.hypothesis_id: item
        for item in experiment.protocol_roots
    }
    result = []
    for support in primary_plan.coordinate_supports:
        coordinate = support.test_coordinate
        hypothesis = roots[coordinate.hypothesis_id].intervention_bridge.frozen_hypothesis
        result.append(
            SelectorUtilityCoordinateBindingV2.from_content(
                test_coordinate_id=coordinate.test_coordinate_id,
                coordinate_support_id=support.coordinate_support_id,
                hypothesis_model_coordinate_id=support.hypothesis_model_coordinate_id,
                hypothesis_id=coordinate.hypothesis_id,
                model_id=coordinate.model_id,
                outcome_name=coordinate.outcome_name,
                expected_direction=hypothesis.expected_direction,
                direction_multiplier=(
                    1 if hypothesis.expected_direction is ExpectedDirection.POSITIVE else -1
                ),
                frozen_independent_cluster_count=support.coordinate_cluster_count,
                frozen_minimum_independent_cluster_count=(
                    roots[coordinate.hypothesis_id].preregistered_minimum_gate_pass_clusters
                ),
            )
        )
    return tuple(sorted(result, key=lambda item: item.test_coordinate_id))


class SelectorUtilityAnalysisPlanV2(_ContentAddressedSelectorUtilityV2):
    """The unique strict-yield and paired-selector plan for one experiment root."""

    _id_field = "selector_utility_plan_id"
    _id_prefix = "selector_utility_plan_v2_"

    selector_utility_plan_id: str = Field(pattern=_PLAN_PATTERN)
    confirmatory_experiment_freeze_id: str
    candidate_universe_id: str
    selection_freeze_id: str
    primary_inference_plan: MultiSupportSimultaneousInferencePlanV2
    primary_family_id: str
    primary_outcome: Literal["y_secure_yield"]
    budget_k: StrictInt = Field(ge=1, le=10_000)
    slot_bindings: tuple[SelectorUtilitySlotBindingV2, ...] = Field(
        min_length=1, max_length=100_000
    )
    selector_groups: tuple[SelectorUtilityGroupBindingV2, ...] = Field(
        min_length=1, max_length=100_000
    )
    coordinate_bindings: tuple[SelectorUtilityCoordinateBindingV2, ...] = Field(
        min_length=1, max_length=640_000
    )
    pair_family: tuple[SelectorPairBindingV2, ...] = Field(max_length=100_000)
    pair_family_size: StrictInt = Field(ge=0, le=100_000)
    plan_scope: SelectorUtilityPlanScopeV2
    outer_bootstrap_samples: StrictInt = Field(
        ge=SELECTOR_UTILITY_SYNTHETIC_MIN_BOOTSTRAP_SAMPLES_V2, le=100_000
    )
    inner_bootstrap_samples: StrictInt = Field(
        ge=SELECTOR_UTILITY_SYNTHETIC_MIN_BOOTSTRAP_SAMPLES_V2, le=100_000
    )
    minimum_valid_outer_draws: StrictInt = Field(ge=1, le=100_000)
    minimum_valid_inner_draws: StrictInt = Field(ge=1, le=100_000)
    minimum_valid_fraction_numerator: Literal[19]
    minimum_valid_fraction_denominator: Literal[20]
    alpha_numerator: Literal[1]
    alpha_denominator: Literal[20]
    rng_version: Literal["sha256-rejection-fisher-yates-v1"] = RNG_VERSION
    analysis_seed_domain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    outer_resampling_rule: Literal[
        "global_union_stratified_semantic_cluster_bootstrap_shared_across_coordinates_v1"
    ]
    inner_resampling_rule: Literal[
        "bounded_nested_shared_global_max_abs_t_within_outer_union_draw_v1"
    ]
    coordinate_support_rule: Literal["coordinate_specific_no_common_intersection_v1"]
    selector_rank_rule: Literal["single_frozen_discover_split_no_rerank_v1"]
    strict_yield_rule: Literal[
        "oriented_adjusted_interval_support_and_provenance_over_all_k_slots_v1"
    ]
    duplicate_hypothesis_rule: Literal["one_test_per_unique_hypothesis_model_coordinate_v1"]
    pair_family_rule: Literal["all_frozen_within_model_selector_pairs_v1"]
    outer_pair_interval_rule: Literal["studentized_global_max_abs_t_simultaneous_v1"]
    quantile_rule: Literal["empirical_higher_v1"]
    invalid_draw_policy: Literal["retain_reason_and_fail_below_frozen_fraction_v1"]
    conditional_on_single_frozen_discovery_split: Literal[True]
    formal_selector_claim_allowed: bool
    frozen_before_confirmation_outcomes: Literal[True]

    @field_validator("plan_scope", mode="before")
    @classmethod
    def parse_scope(cls, value: object) -> object:
        return (
            value
            if isinstance(value, SelectorUtilityPlanScopeV2)
            else SelectorUtilityPlanScopeV2(value)
        )

    @classmethod
    def from_experiment(cls, experiment: ConfirmatoryExperimentFreezeV2) -> Self:
        """Derive the formal 999-outer/499-inner protocol without caller choices."""

        return cls._derive(
            experiment=experiment,
            plan_scope=SelectorUtilityPlanScopeV2.FORMAL,
            outer_bootstrap_samples=FORMAL_MIN_BOOTSTRAP_SAMPLES_V2,
            inner_bootstrap_samples=SELECTOR_UTILITY_FORMAL_INNER_BOOTSTRAP_SAMPLES_V2,
        )

    @classmethod
    def for_synthetic_validation(
        cls,
        experiment: ConfirmatoryExperimentFreezeV2,
        *,
        outer_bootstrap_samples: int,
        inner_bootstrap_samples: int,
    ) -> Self:
        """Derive a cheap non-claiming plan for synthetic/attack validation only."""

        return cls._derive(
            experiment=experiment,
            plan_scope=SelectorUtilityPlanScopeV2.SYNTHETIC_VALIDATION_ONLY,
            outer_bootstrap_samples=outer_bootstrap_samples,
            inner_bootstrap_samples=inner_bootstrap_samples,
        )

    @classmethod
    def _derive(
        cls,
        *,
        experiment: ConfirmatoryExperimentFreezeV2,
        plan_scope: SelectorUtilityPlanScopeV2,
        outer_bootstrap_samples: int,
        inner_bootstrap_samples: int,
    ) -> Self:
        try:
            checked = ConfirmatoryExperimentFreezeV2.model_validate(
                experiment.model_dump(mode="python", round_trip=True, warnings=False),
                strict=True,
            )
            primary = MultiSupportSimultaneousInferencePlanV2.from_frozen_formal_family(
                experiment=checked,
                formal_family=MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD,
            )
            slots = _expected_slot_bindings(checked)
            groups = _expected_groups(slots, checked.selection_freeze.budget_k)
            pairs = _expected_pairs(groups)
            coordinates = _expected_coordinate_bindings(checked, primary)
            valid_outer = (
                outer_bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                - 1
            ) // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            valid_inner = (
                inner_bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
                + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                - 1
            ) // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            content = dict(  # noqa: C408 - keyword form keeps the frozen payload auditable
                confirmatory_experiment_freeze_id=checked.confirmatory_experiment_freeze_id,
                candidate_universe_id=checked.candidate_universe.candidate_universe_id,
                selection_freeze_id=checked.selection_freeze.selection_freeze_id,
                primary_inference_plan=primary,
                primary_family_id=primary.family.family_id,
                primary_outcome="y_secure_yield",
                budget_k=checked.selection_freeze.budget_k,
                slot_bindings=slots,
                selector_groups=groups,
                coordinate_bindings=coordinates,
                pair_family=pairs,
                pair_family_size=len(pairs),
                plan_scope=plan_scope,
                outer_bootstrap_samples=outer_bootstrap_samples,
                inner_bootstrap_samples=inner_bootstrap_samples,
                minimum_valid_outer_draws=valid_outer,
                minimum_valid_inner_draws=valid_inner,
                minimum_valid_fraction_numerator=(MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2),
                minimum_valid_fraction_denominator=(
                    MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
                ),
                alpha_numerator=1,
                alpha_denominator=20,
                rng_version=RNG_VERSION,
                analysis_seed_domain_sha256=checked.analysis_seed_domain_sha256,
                outer_resampling_rule=(
                    "global_union_stratified_semantic_cluster_bootstrap_shared_across_coordinates_v1"
                ),
                inner_resampling_rule=(
                    "bounded_nested_shared_global_max_abs_t_within_outer_union_draw_v1"
                ),
                coordinate_support_rule="coordinate_specific_no_common_intersection_v1",
                selector_rank_rule="single_frozen_discover_split_no_rerank_v1",
                strict_yield_rule=(
                    "oriented_adjusted_interval_support_and_provenance_over_all_k_slots_v1"
                ),
                duplicate_hypothesis_rule=("one_test_per_unique_hypothesis_model_coordinate_v1"),
                pair_family_rule="all_frozen_within_model_selector_pairs_v1",
                outer_pair_interval_rule=("studentized_global_max_abs_t_simultaneous_v1"),
                quantile_rule="empirical_higher_v1",
                invalid_draw_policy=("retain_reason_and_fail_below_frozen_fraction_v1"),
                conditional_on_single_frozen_discovery_split=True,
                formal_selector_claim_allowed=(plan_scope is SelectorUtilityPlanScopeV2.FORMAL),
                frozen_before_confirmation_outcomes=True,
            )
            payload = {
                "schema_version": SELECTOR_UTILITY_V2_SCHEMA_VERSION,
                **content,
            }
            return cls.model_construct(
                **payload,
                selector_utility_plan_id="selector_utility_plan_v2_" + _digest(payload),
            )
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise RuntimeError(
                f"selector utility derivation diagnostic: {type(exc).__name__}: {exc}"
            ) from exc

    @model_validator(mode="after")
    def validate_exact_derivation(self) -> Self:
        primary = self.primary_inference_plan
        experiment = primary.experiment
        expected_slots = _expected_slot_bindings(experiment)
        expected_groups = _expected_groups(expected_slots, experiment.selection_freeze.budget_k)
        expected_pairs = _expected_pairs(expected_groups)
        expected_coordinates = _expected_coordinate_bindings(experiment, primary)
        expected_outer = (
            self.outer_bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
            + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            - 1
        ) // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
        expected_inner = (
            self.inner_bootstrap_samples * MULTI_SUPPORT_VALID_DRAW_FRACTION_NUMERATOR_V2
            + MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
            - 1
        ) // MULTI_SUPPORT_VALID_DRAW_FRACTION_DENOMINATOR_V2
        formal = self.plan_scope is SelectorUtilityPlanScopeV2.FORMAL
        if (
            self.confirmatory_experiment_freeze_id != experiment.confirmatory_experiment_freeze_id
            or self.candidate_universe_id != experiment.candidate_universe.candidate_universe_id
            or self.selection_freeze_id != experiment.selection_freeze.selection_freeze_id
            or primary.formal_family is not MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
            or primary.bootstrap_samples != FORMAL_MIN_BOOTSTRAP_SAMPLES_V2
            or primary.alpha_numerator != 1
            or primary.alpha_denominator != 20
            or primary.minimum_independent_clusters_per_coordinate != 2
            or primary.seed_derivation_rule
            != "sha256_frozen_domain_digest_plus_content_addressed_plan_id_v1"
            or self.primary_family_id != primary.family.family_id
            or self.slot_bindings != expected_slots
            or self.selector_groups != expected_groups
            or self.coordinate_bindings != expected_coordinates
            or self.pair_family != expected_pairs
            or self.pair_family_size != len(expected_pairs)
            or self.budget_k != experiment.selection_freeze.budget_k
            or self.analysis_seed_domain_sha256 != experiment.analysis_seed_domain_sha256
            or self.minimum_valid_outer_draws != expected_outer
            or self.minimum_valid_inner_draws != expected_inner
            or self.formal_selector_claim_allowed is not formal
            or (
                formal
                and (
                    self.outer_bootstrap_samples != FORMAL_MIN_BOOTSTRAP_SAMPLES_V2
                    or self.inner_bootstrap_samples
                    != SELECTOR_UTILITY_FORMAL_INNER_BOOTSTRAP_SAMPLES_V2
                )
            )
            or (
                not formal
                and (
                    self.outer_bootstrap_samples >= FORMAL_MIN_BOOTSTRAP_SAMPLES_V2
                    or self.inner_bootstrap_samples >= FORMAL_MIN_BOOTSTRAP_SAMPLES_V2
                )
            )
        ):
            raise ValueError(self._safe_validation_message)
        return self


__all__ = [
    "SELECTOR_UTILITY_FORMAL_INNER_BOOTSTRAP_SAMPLES_V2",
    "SELECTOR_UTILITY_SYNTHETIC_MIN_BOOTSTRAP_SAMPLES_V2",
    "SELECTOR_UTILITY_V2_SCHEMA_VERSION",
    "SelectorPairBindingV2",
    "SelectorPairInferenceStatusV2",
    "SelectorPairNonEvaluableReasonV2",
    "SelectorUtilityAnalysisPlanV2",
    "SelectorUtilityCoordinateBindingV2",
    "SelectorUtilityGroupBindingV2",
    "SelectorUtilityPlanScopeV2",
    "SelectorUtilitySlotBindingV2",
    "SelectorUtilitySlotStatusV2",
]

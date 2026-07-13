from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG,
    FeatureSpec,
    _validate_feature_catalog,
    prompt_feature_spec,
)


EXPECTED_FEATURE_IDS = (
    "task.input_consumption",
    "task.file_read",
    "task.database_query",
    "task.process_launch",
    "task.privileged_action",
    "task.object_deserialization",
    "safety.input_validation",
    "safety.path_normalization",
    "safety.sql_parameterization",
    "safety.safe_subprocess",
    "safety.authorization_check",
    "safety.safe_deserialization",
    "safety.generic_security_reminder",
    "safety.prohibited_unsafe_request",
    "safety.vulnerability_disclosure",
    "safety.expected_outcome_leakage",
    "presentation.noop_rewrite",
    "presentation.length_matched_placebo",
    "presentation.sham_edit",
    "presentation.matched_control",
)


def test_catalog_has_three_families_and_no_runtime_registration() -> None:
    assert {item.feature_family for item in PROMPT_FEATURE_CATALOG} == set(FeatureFamily)
    assert prompt_feature_spec("safety.path_normalization").operations == (
        FeatureOperation.ADD,
        FeatureOperation.REMOVE,
    )
    with pytest.raises(KeyError):
        prompt_feature_spec("runtime.injected_feature")


def test_catalog_is_exactly_the_finite_immutable_feature_set() -> None:
    assert type(PROMPT_FEATURE_CATALOG) is tuple
    assert tuple(item.feature_id for item in PROMPT_FEATURE_CATALOG) == EXPECTED_FEATURE_IDS
    assert all(type(item) is FeatureSpec for item in PROMPT_FEATURE_CATALOG)
    with pytest.raises(FrozenInstanceError):
        PROMPT_FEATURE_CATALOG[0].intervenable = False  # type: ignore[misc]


def test_catalog_rejects_duplicate_feature_ids() -> None:
    with pytest.raises(RuntimeError):
        _validate_feature_catalog((*PROMPT_FEATURE_CATALOG, PROMPT_FEATURE_CATALOG[0]))


def test_catalog_rejects_invalid_family_prefixes() -> None:
    invalid = replace(PROMPT_FEATURE_CATALOG[0], feature_id="safety.input_consumption")
    with pytest.raises(RuntimeError):
        _validate_feature_catalog((invalid, *PROMPT_FEATURE_CATALOG[1:]))


def test_catalog_rejects_unknown_ids_even_with_a_valid_family_prefix() -> None:
    invalid = replace(PROMPT_FEATURE_CATALOG[0], feature_id="task.unknown_feature")
    with pytest.raises(RuntimeError):
        _validate_feature_catalog((invalid, *PROMPT_FEATURE_CATALOG[1:]))


def test_catalog_shape_has_no_outcome_or_code_fields() -> None:
    forbidden = {"secure", "insecure", "outcome", "oracle", "code"}
    assert forbidden.isdisjoint(field.name.casefold() for field in fields(FeatureSpec))


def test_protocol_sentinels_are_non_intervenable() -> None:
    sentinels = {
        "safety.prohibited_unsafe_request",
        "safety.vulnerability_disclosure",
        "safety.expected_outcome_leakage",
    }
    assert {
        item.feature_id for item in PROMPT_FEATURE_CATALOG if not item.intervenable
    } == sentinels

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import (
    FEATURE_CATALOG_VERSION,
    PROMPT_FEATURE_CATALOG,
    FeatureSpec,
    _digest_entry,
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


def test_presentation_matched_control_mapping_is_catalog_owned_and_closed() -> None:
    assert FEATURE_CATALOG_VERSION == "1.1"
    mapping = {
        item.feature_id: item.matched_control_feature_id
        for item in PROMPT_FEATURE_CATALOG
        if item.matched_control_feature_id is not None
    }
    assert mapping == {
        "presentation.noop_rewrite": "presentation.matched_control",
        "presentation.length_matched_placebo": "presentation.matched_control",
        "presentation.sham_edit": "presentation.matched_control",
    }
    assert prompt_feature_spec("presentation.matched_control").matched_control_feature_id is None
    assert all(
        item.matched_control_feature_id is None
        for item in PROMPT_FEATURE_CATALOG
        if item.feature_family is not FeatureFamily.PRESENTATION_CONTROL
    )


@pytest.mark.parametrize(
    ("source_id", "matched_id"),
    (
        ("task.file_read", "presentation.matched_control"),
        ("presentation.noop_rewrite", "presentation.unknown_control"),
        ("presentation.noop_rewrite", "safety.path_normalization"),
        ("presentation.noop_rewrite", "presentation.noop_rewrite"),
    ),
)
def test_catalog_rejects_invalid_matched_control_ownership_or_reference(
    source_id: str,
    matched_id: str,
) -> None:
    mutated = tuple(
        replace(item, matched_control_feature_id=matched_id)
        if item.feature_id == source_id
        else item
        for item in PROMPT_FEATURE_CATALOG
    )
    with pytest.raises(RuntimeError):
        _validate_feature_catalog(mutated)


def test_catalog_rejects_nonintervenable_matched_control_target() -> None:
    mutated = tuple(
        replace(item, intervenable=False, operations=())
        if item.feature_id == "presentation.matched_control"
        else item
        for item in PROMPT_FEATURE_CATALOG
    )
    with pytest.raises(RuntimeError):
        _validate_feature_catalog(mutated)


def test_catalog_digest_payload_commits_matched_control_mapping() -> None:
    source = prompt_feature_spec("presentation.noop_rewrite")
    mutated = replace(source, matched_control_feature_id=None)

    assert _digest_entry(source) != _digest_entry(mutated)


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

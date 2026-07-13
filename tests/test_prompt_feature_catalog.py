from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import inspect
import json

import pytest

from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import (
    FEATURE_CATALOG_VERSION,
    PROMPT_FEATURE_CATALOG,
    PROMPT_FEATURE_CATALOG_SHA256,
    FeatureSpec,
    _digest_entry,
    _validate_feature_catalog,
    prompt_feature_spec,
)
import secaware.intervention.attestation as attestation_module


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
    assert FEATURE_CATALOG_VERSION == "1.2"
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


def test_catalog_owns_exact_versioned_intervention_clauses_without_shadow_table() -> None:
    assert "_SPECIAL_REVIEWED_CLAUSES" not in inspect.getsource(attestation_module)
    assert prompt_feature_spec("safety.path_normalization").intervention_clauses == (
        " Normalize the path.",
        " Normalize the path and restrict it to a base directory.",
    )
    assert (
        " Use parameterized queries for user-provided values."
        in prompt_feature_spec("safety.sql_parameterization").intervention_clauses
    )
    assert (
        " Pass arguments as a list and run without a shell."
        in prompt_feature_spec("safety.safe_subprocess").intervention_clauses
    )


def test_catalog_digest_payload_commits_intervention_clause_drift() -> None:
    source = prompt_feature_spec("safety.path_normalization")
    mutated = replace(
        source,
        intervention_clauses=(" Normalize the path and restrict it to a fixed root.",),
    )

    mutated_catalog = tuple(
        mutated if item.feature_id == source.feature_id else item for item in PROMPT_FEATURE_CATALOG
    )
    mutated_digest = hashlib.sha256(
        json.dumps(
            {
                "catalog_version": FEATURE_CATALOG_VERSION,
                "entries": [_digest_entry(item) for item in mutated_catalog],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert _digest_entry(source) != _digest_entry(mutated)
    assert mutated_digest != PROMPT_FEATURE_CATALOG_SHA256


def test_catalog_rejects_global_clause_digest_ambiguity() -> None:
    source = prompt_feature_spec("safety.path_normalization")
    duplicate_clause = source.intervention_clauses[0]
    mutated = tuple(
        replace(item, intervention_clauses=(duplicate_clause,))
        if item.feature_id == "safety.sql_parameterization"
        else item
        for item in PROMPT_FEATURE_CATALOG
    )

    with pytest.raises(RuntimeError):
        _validate_feature_catalog(mutated)


@pytest.mark.parametrize(
    "clauses",
    (
        ("Normalize the path.",),
        ("  Normalize the path.",),
        (" Normalize the path. ",),
        (" \nNormalize the path.",),
        (" Normalize the path.", " Normalize the path."),
        (" " + "x" * 128,),
    ),
)
def test_catalog_rejects_noncanonical_or_duplicate_intervention_clauses(
    clauses: tuple[str, ...],
) -> None:
    mutated = tuple(
        replace(item, intervention_clauses=clauses)
        if item.feature_id == "safety.path_normalization"
        else item
        for item in PROMPT_FEATURE_CATALOG
    )

    with pytest.raises(RuntimeError):
        _validate_feature_catalog(mutated)


@pytest.mark.parametrize(
    "feature_id",
    (
        "safety.generic_security_reminder",
        "safety.prohibited_unsafe_request",
    ),
)
def test_only_confirmation_targets_may_own_intervention_clauses(feature_id: str) -> None:
    mutated = tuple(
        replace(item, intervention_clauses=(" Follow security best practices.",))
        if item.feature_id == feature_id
        else item
        for item in PROMPT_FEATURE_CATALOG
    )

    with pytest.raises(RuntimeError):
        _validate_feature_catalog(mutated)


def test_catalog_clause_digest_is_unique_and_feature_owned() -> None:
    by_digest: dict[str, str] = {}
    for spec in PROMPT_FEATURE_CATALOG:
        for clause in spec.intervention_clauses:
            digest = hashlib.sha256(clause.encode("utf-8")).hexdigest()
            assert digest not in by_digest
            by_digest[digest] = spec.feature_id


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

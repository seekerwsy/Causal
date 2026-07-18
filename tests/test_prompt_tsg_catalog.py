from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from secaware.schema.features import FeatureFamily
from secaware.tsg.catalog import (
    MOTIF_VERSION,
    ONTOLOGY_VERSION,
    PROMPT_TSG_CATALOG,
    PROMPT_TSG_CATALOG_SHA256,
    PromptOntologyEntry,
    prompt_ontology_entry,
)
from secaware.tsg.graph import MOTIF_VERSION as GRAPH_MOTIF_VERSION
from secaware.tsg.graph import ONTOLOGY_VERSION as GRAPH_ONTOLOGY_VERSION
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256, prompt_feature_spec


def test_catalog_is_exactly_six_immutable_entries() -> None:
    assert type(PROMPT_TSG_CATALOG) is tuple
    assert len(PROMPT_TSG_CATALOG) == 6
    assert len({entry.target_feature_id for entry in PROMPT_TSG_CATALOG}) == 6
    assert all(
        prompt_feature_spec(entry.task_feature_id).feature_family is FeatureFamily.TASK_FUNCTION
        and prompt_feature_spec(entry.target_feature_id).feature_family
        is FeatureFamily.SAFETY_CONTROL
        for entry in PROMPT_TSG_CATALOG
    )
    assert all(type(entry) is PromptOntologyEntry for entry in PROMPT_TSG_CATALOG)

    with pytest.raises(FrozenInstanceError):
        PROMPT_TSG_CATALOG[0].sink_label = "changed"  # type: ignore[misc]


def test_catalog_labels_and_terms_are_canonical_unique_ascii() -> None:
    labels: list[str] = []
    terms: list[str] = []
    for entry in PROMPT_TSG_CATALOG:
        labels.extend(
            (
                entry.operation_label,
                entry.data_label,
                entry.sink_label,
                entry.requirement_label,
                entry.guard_label,
            )
        )
        terms.extend((*entry.domain_terms, *entry.guard_terms))

    assert len(labels) == len({label.casefold() for label in labels})
    assert len(terms) == len({term.casefold() for term in terms})
    assert all(value == value.strip() and value.isascii() and value for value in labels + terms)
    assert all(len(value.encode("ascii")) <= 96 for value in labels + terms)
    assert all(1 <= len(entry.domain_terms) <= 8 for entry in PROMPT_TSG_CATALOG)
    assert all(1 <= len(entry.guard_terms) <= 8 for entry in PROMPT_TSG_CATALOG)


def test_catalog_contains_no_outcome_fields() -> None:
    field_names = PromptOntologyEntry.__dataclass_fields__
    assert not set(field_names) & {"secure", "insecure", "outcome", "label_value", "motif"}


def test_catalog_lookup_is_total_and_rejects_unknown_features() -> None:
    for entry in PROMPT_TSG_CATALOG:
        assert prompt_ontology_entry(entry.target_feature_id) is entry

    with pytest.raises(KeyError):
        prompt_ontology_entry("path_normalization")


def test_catalog_digest_and_versions_are_canonical_and_centralized() -> None:
    assert ONTOLOGY_VERSION == "1.1"
    assert MOTIF_VERSION == "1.1"
    assert PROMPT_TSG_CATALOG_SHA256 == PROMPT_FEATURE_CATALOG_SHA256
    assert GRAPH_ONTOLOGY_VERSION is ONTOLOGY_VERSION
    assert GRAPH_MOTIF_VERSION is MOTIF_VERSION

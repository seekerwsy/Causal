from __future__ import annotations

from dataclasses import replace
import json

import pytest

from secaware.causal.jci import build_jci_tables
from secaware.schema.causal import VariableRole

from test_jci_table_builder import (
    _replace_outcome,
    build_fixture,
    fixture_for,
)


def test_executor_extractor_instance_and_diagnostic_coordinates_are_not_columns() -> None:
    fixture = fixture_for()
    tables, _rows = build_fixture(fixture)
    forbidden = {
        "intervention_mode",
        "intervention_executor_kind",
        "executor_policy_sha256",
        "extractor_backend",
        "extractor_policy_sha256",
        "target_instance_id",
        "protocol_instance_id",
        "target_changed",
        "semantic_compliance",
        "execution_status",
        "model_id",
    }
    for table in tables:
        variable_ids = {item.variable_id for item in table.variables}
        assert forbidden.isdisjoint(variable_ids)
        assert {item.variable_id for item in table.variables if item.role is VariableRole.C} == {
            "c.arm"
        }


def test_outcome_diagnostics_do_not_change_causal_table_or_rows() -> None:
    fixture = fixture_for()
    changed = replace(
        fixture,
        outcomes=tuple(
            _replace_outcome(
                item,
                target_changed=not item.target_changed if item.target_changed is not None else True,
                semantic_compliance=(
                    not item.semantic_compliance if item.semantic_compliance is not None else False
                ),
            )
            for item in fixture.outcomes
        ),
    )

    assert build_fixture(changed) == build_fixture(fixture)


def test_prompt_code_and_finding_text_never_enters_jci_artifacts_or_errors() -> None:
    fixture = fixture_for()
    secret = "TOP-SECRET-CODE-AND-FINDING-TEXT"
    changed_variant = fixture.variants[0].model_copy(update={"prompt_text": secret})
    forged = replace(fixture, variants=(changed_variant, *fixture.variants[1:]))

    with pytest.raises(Exception) as exc_info:
        build_fixture(forged)
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)

    tables, rows = build_fixture(fixture)
    published = json.dumps(
        [
            *(item.model_dump(mode="json") for item in tables),
            *(item.model_dump(mode="json") for item in rows),
        ],
        sort_keys=True,
    )
    assert all(item.prompt_text not in published for item in fixture.variants)
    assert "code_text" not in published
    assert "finding_text" not in published


def test_unregistered_code_finding_or_diagnostic_inputs_are_rejected() -> None:
    fixture = fixture_for()
    with pytest.raises(TypeError):
        build_jci_tables(
            fixture.assignments,
            fixture.outcomes,
            fixture.graphs,
            variants=fixture.variants,
            hypotheses=fixture.hypotheses,
            protocols=fixture.protocols,
            min_independent_tasks=2,
            code_records=("raw code",),
        )
    with pytest.raises(TypeError):
        build_jci_tables(
            fixture.assignments,
            fixture.outcomes,
            fixture.graphs,
            variants=fixture.variants,
            hypotheses=fixture.hypotheses,
            protocols=fixture.protocols,
            min_independent_tasks=2,
            findings=("raw finding",),
        )


def test_required_semantic_producers_cannot_be_omitted_or_inferred() -> None:
    fixture = fixture_for()
    with pytest.raises(TypeError):
        build_jci_tables(
            fixture.assignments,
            fixture.outcomes,
            fixture.graphs,
            min_independent_tasks=2,
        )

from __future__ import annotations

from dataclasses import fields, replace

import pytest

from helpers import changed_spec, example_study, protocol_spec
from prompt_mechanism_study.cli import build_study
from prompt_mechanism_study.intervention import ARM_ORDER
from prompt_mechanism_study.randomization import verify_randomization
from prompt_mechanism_study.representation import Task


@pytest.mark.reviewer
def test_population_is_split_before_outcomes_and_clusters_do_not_cross() -> None:
    assert "outcome" not in {field.name for field in fields(Task)}
    spec = changed_spec()
    spec["tasks"][2]["semantic_cluster_id"] = "discover.cluster.1"
    with pytest.raises(ValueError, match="cannot cross"):
        build_study(spec)


@pytest.mark.reviewer
def test_candidate_universe_and_top_k_are_frozen() -> None:
    study = example_study()
    assert len(study.universe.candidates) == 1
    assert study.selection.top_k == 1
    assert study.selection.selected_candidate_ids == (study.universe.candidates[0].candidate_id,)


@pytest.mark.reviewer
def test_selector_scores_are_exact_and_change_selection_identity() -> None:
    first = example_study()
    spec = changed_spec()
    spec["selector"]["scores"]["sql.parameterization"] = 0.5
    second = build_study(spec)
    assert first.selection.selection_id != second.selection.selection_id
    spec["selector"]["scores"]["extra"] = 1.0
    with pytest.raises(ValueError, match="every candidate key"):
        build_study(spec)


@pytest.mark.reviewer
def test_policy_has_complete_task_by_realization_support() -> None:
    study = example_study()
    policy = study.policies[0]
    expected = len(study.population.confirm_tasks) * len(policy.realizations)
    assert len(policy.bundles) == expected
    spec = changed_spec()
    spec["policies"][0]["bundles"].pop()
    with pytest.raises(ValueError, match="complete confirm-task"):
        build_study(spec)

    spec = changed_spec()
    duplicate = spec["policies"][0]["bundles"][0]
    changed_target = {**duplicate["arms"]["target"], "intervention_text": "different target"}
    spec["policies"][0]["bundles"].append(
        {**duplicate, "arms": {**duplicate["arms"], "target": changed_target}}
    )
    with pytest.raises(ValueError, match="complete confirm-task"):
        build_study(spec)


@pytest.mark.reviewer
def test_invalid_intervention_bundle_cannot_enter_randomization() -> None:
    spec = changed_spec()
    validation = spec["policies"][0]["bundles"][0]["arms"]["target"]["validation"]
    validation["contract_satisfied"] = "no"
    with pytest.raises(ValueError, match="semantically validated"):
        build_study(spec)


@pytest.mark.reviewer
def test_llm_intervention_is_assembled_and_binds_executor_and_validator() -> None:
    study = example_study()
    task = next(item for item in study.population.confirm_tasks if item.task_id == "confirm.1a")
    bundle = next(item for item in study.policies[0].bundles if item.task_id == task.task_id)
    target = bundle.variant(ARM_ORDER[0])
    assert target.prompt_text == task.prompt + "\n\n" + target.execution.intervention_text
    assert target.execution.executor_adapter_id == study.adapters.intervention_executor.adapter_id
    assert (
        target.validation.validator_adapter_id
        == study.adapters.intervention_validator.adapter_id
    )


@pytest.mark.reviewer
def test_intervention_spec_defines_the_mechanism_and_each_arm_instruction() -> None:
    spec = example_study().policies[0].spec
    assert spec.mechanism == "sql.parameterized_query"
    assert tuple(arm for arm, _ in spec.arm_instructions) == ARM_ORDER
    assert "parameterization" in spec.instruction(ARM_ORDER[0])


@pytest.mark.reviewer
def test_randomization_is_replayable_and_balanced_in_every_complete_block() -> None:
    first = example_study()
    replay = example_study()
    assert first.randomization == replay.randomization
    verify_randomization(first.randomization, first.policies)
    for block_id in {item.block.block_id for item in first.randomization.assignments}:
        block = [
            item for item in first.randomization.assignments if item.block.block_id == block_id
        ]
        assert {arm: sum(item.arm is arm for item in block) for arm in ARM_ORDER} == {
            arm: 1 for arm in ARM_ORDER
        }
    first_assignment = first.randomization.assignments[0]
    mutated = replace(
        first.randomization,
        assignments=(
            replace(first_assignment, variant_sha256="0" * 64),
            *first.randomization.assignments[1:],
        ),
    )
    with pytest.raises(ValueError, match="variant binding"):
        verify_randomization(mutated, first.policies)


@pytest.mark.reviewer
def test_every_scientific_block_coordinate_changes_block_identity() -> None:
    assignment = example_study().randomization.assignments[0]
    for field in assignment.block.__dataclass_fields__:
        changed = replace(
            assignment.block, **{field: getattr(assignment.block, field) + ".changed"}
        )
        assert changed.block_id != assignment.block.block_id


@pytest.mark.reviewer
def test_adapter_identity_is_part_of_the_frozen_study() -> None:
    first = example_study()
    spec = changed_spec()
    spec["adapters"]["security_oracle"]["version"] = "2"
    second = build_study(spec)
    assert first.adapters.security_oracle.adapter_id != second.adapters.security_oracle.adapter_id
    assert first.study_id != second.study_id


@pytest.mark.reviewer
def test_protocol_input_rejects_outcome_fields() -> None:
    spec = protocol_spec()
    spec["measurements"] = []
    with pytest.raises(ValueError, match="keys are not exact"):
        build_study(spec)

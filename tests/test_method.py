from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from helpers import complete_measurements, example_study
from secaware.intervention import ARM_ORDER, Arm, freeze_intervention
from secaware.measurement import (
    FunctionalLabel,
    Measurement,
    SecurityLabel,
    close_measurements,
)
from secaware.prioritization import rank_candidates
from secaware.randomization import randomize, verify_randomization
from secaware.representation import Candidate, Operation, Task, freeze_population
from secaware.workflow import arm_texts


@pytest.mark.reviewer
def test_population_is_canonical_outcome_blind_and_immutable() -> None:
    tasks = (
        Task("task.b", "cluster.2", "CWE-78", "B"),
        Task("task.a", "cluster.1", "CWE-89", "A"),
    )
    population = freeze_population(tasks)
    assert tuple(task.task_id for task in population.tasks) == ("task.a", "task.b")
    assert not {"outcome", "arm", "security"} & set(Task.__dataclass_fields__)
    with pytest.raises(FrozenInstanceError):
        population.tasks = ()  # type: ignore[misc]


@pytest.mark.reviewer
def test_candidate_ranking_is_exact_and_deterministic() -> None:
    candidates = (
        Candidate("task.a", "feature.a", Operation.ADD, "rationale"),
        Candidate("task.b", "feature.b", Operation.REMOVE, "rationale"),
    )
    scores = {candidates[0].candidate_id: 0.2, candidates[1].candidate_id: 0.8}
    ranked = rank_candidates(candidates, scores)
    assert [item.candidate for item in ranked] == [candidates[1], candidates[0]]
    assert ranked == rank_candidates(tuple(reversed(candidates)), scores)


@pytest.mark.reviewer
def test_candidate_ranking_rejects_missing_or_extra_scores() -> None:
    candidate = Candidate("task.a", "feature.a", Operation.ADD, "rationale")
    with pytest.raises(ValueError):
        rank_candidates((candidate,), {})
    with pytest.raises(ValueError):
        rank_candidates((candidate,), {candidate.candidate_id: 1.0, "extra": 0.0})


@pytest.mark.reviewer
def test_intervention_requires_exactly_four_registered_arms() -> None:
    candidate = Candidate("task.a", "feature.a", Operation.ADD, "rationale")
    bundle = freeze_intervention(
        candidate,
        arm_texts(target="t", noop="n", placebo="p", generic="g"),
    )
    assert tuple(item.arm for item in bundle.arms) == ARM_ORDER
    with pytest.raises(ValueError):
        freeze_intervention(candidate, {Arm.TARGET: "t"})


@pytest.mark.reviewer
def test_randomization_is_replayable_and_balanced() -> None:
    study = example_study(seed=91)
    replay = example_study(seed=91)
    assert study.randomization == replay.randomization
    verify_randomization(study.randomization, study.population, study.interventions)
    for task in study.population.tasks:
        block = [a for a in study.randomization.assignments if a.task_id == task.task_id]
        assert {arm: sum(a.arm is arm for a in block) for arm in Arm} == {arm: 2 for arm in Arm}


@pytest.mark.reviewer
def test_randomization_changes_with_seed_without_changing_support() -> None:
    first = example_study(seed=1).randomization
    second = example_study(seed=2).randomization
    assert first.assignments != second.assignments
    assert {(a.task_id, a.model_id, a.request_slot) for a in first.assignments} == {
        (a.task_id, a.model_id, a.request_slot) for a in second.assignments
    }


@pytest.mark.reviewer
def test_randomization_rejects_incomplete_arm_blocks() -> None:
    study = example_study()
    with pytest.raises(ValueError):
        randomize(
            study.population,
            study.interventions,
            models=("model.a",),
            slots=(0, 1, 2),
            seed=1,
        )


@pytest.mark.reviewer
def test_security_and_functionality_are_independent_labels() -> None:
    assignment = example_study().randomization.assignments[0]
    record = Measurement(
        assignment.assignment_id,
        SecurityLabel.INSECURE,
        FunctionalLabel.PASS,
    )
    assert record.security is SecurityLabel.INSECURE
    assert record.functionality is FunctionalLabel.PASS


@pytest.mark.reviewer
def test_total_ledger_rejects_missing_and_duplicate_assignments() -> None:
    study = example_study()
    measurements, _ = complete_measurements(study)
    with pytest.raises(ValueError):
        close_measurements(study.randomization, measurements[:-1])
    with pytest.raises(ValueError):
        close_measurements(study.randomization, measurements + measurements[:1])


@pytest.mark.reviewer
def test_total_ledger_preserves_every_randomized_assignment() -> None:
    study = example_study()
    measurements, failures = complete_measurements(study)
    ledger = close_measurements(study.randomization, measurements, failures)
    assert len(ledger.measurements) + len(ledger.failures) == len(study.randomization.assignments)

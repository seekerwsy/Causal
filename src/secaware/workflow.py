"""Minimal freeze-to-inference research workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from secaware.inference import ITTEstimate, estimate_itt
from secaware.intervention import Arm, InterventionBundle
from secaware.measurement import Measurement, MeasurementLedger, TerminalFailure, close_measurements
from secaware.outcomes import Outcome, derive_outcomes
from secaware.randomization import Randomization, randomize
from secaware.records import content_id
from secaware.representation import Candidate, Population, Task, freeze_population


@dataclass(frozen=True, slots=True)
class FrozenStudy:
    population: Population
    candidates: tuple[Candidate, ...]
    interventions: tuple[InterventionBundle, ...]
    randomization: Randomization

    def __post_init__(self) -> None:
        task_ids = {task.task_id for task in self.population.tasks}
        candidate_tasks = tuple(candidate.task_id for candidate in self.candidates)
        intervention_tasks = tuple(bundle.task_id for bundle in self.interventions)
        if len(candidate_tasks) != len(task_ids) or set(candidate_tasks) != task_ids:
            raise ValueError("one selected candidate must bind every task")
        if len(intervention_tasks) != len(task_ids) or set(intervention_tasks) != task_ids:
            raise ValueError("one intervention must bind every task")

    @property
    def study_id(self) -> str:
        return content_id("study_", self)


@dataclass(frozen=True, slots=True)
class Analysis:
    study_id: str
    ledger: MeasurementLedger
    outcomes: tuple[Outcome, ...]
    security: ITTEstimate
    functionality: ITTEstimate
    joint: ITTEstimate

    @property
    def analysis_id(self) -> str:
        return content_id("analysis_", self)


def freeze_study(
    tasks: Iterable[Task],
    candidates: Iterable[Candidate],
    interventions: Iterable[InterventionBundle],
    *,
    models: Iterable[str],
    slots: Iterable[int],
    seed: int,
) -> FrozenStudy:
    population = freeze_population(tasks)
    frozen_candidates = tuple(sorted(candidates, key=lambda item: item.candidate_id))
    frozen_interventions = tuple(sorted(interventions, key=lambda item: item.intervention_id))
    by_candidate = {candidate.candidate_id: candidate for candidate in frozen_candidates}
    if len(by_candidate) != len(frozen_candidates):
        raise ValueError("candidate identities must be unique")
    if len({bundle.intervention_id for bundle in frozen_interventions}) != len(
        frozen_interventions
    ):
        raise ValueError("intervention identities must be unique")
    for bundle in frozen_interventions:
        candidate = by_candidate.get(bundle.candidate_id)
        if candidate is None or candidate.task_id != bundle.task_id:
            raise ValueError("intervention-to-candidate binding drift")
    assignment = randomize(
        population,
        frozen_interventions,
        models=models,
        slots=slots,
        seed=seed,
    )
    return FrozenStudy(population, frozen_candidates, frozen_interventions, assignment)


def analyze(
    study: FrozenStudy,
    measurements: Sequence[Measurement],
    failures: Sequence[TerminalFailure] = (),
) -> Analysis:
    ledger = close_measurements(study.randomization, measurements, failures)
    outcomes = derive_outcomes(ledger)
    return Analysis(
        study_id=study.study_id,
        ledger=ledger,
        outcomes=outcomes,
        security=estimate_itt(study.randomization, outcomes, dimension="security"),
        functionality=estimate_itt(study.randomization, outcomes, dimension="functionality"),
        joint=estimate_itt(study.randomization, outcomes, dimension="joint"),
    )


def arm_texts(
    *,
    target: str,
    noop: str,
    placebo: str,
    generic: str,
) -> Mapping[Arm, str]:
    return {
        Arm.TARGET: target,
        Arm.NOOP: noop,
        Arm.PLACEBO: placebo,
        Arm.GENERIC: generic,
    }


__all__ = ["Analysis", "FrozenStudy", "analyze", "arm_texts", "freeze_study"]

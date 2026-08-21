"""Prospective freeze and post-measurement analysis workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from secaware.adapters import AdapterBundle
from secaware.inference import AnalysisPlan, InferenceResult, estimate_policy_effects
from secaware.intervention import InterventionPolicy
from secaware.measurement import (
    InfrastructureFailure,
    Measurement,
    MeasurementLedger,
    close_measurements,
)
from secaware.outcomes import Outcome, derive_outcomes
from secaware.prioritization import SelectionFreeze, freeze_selection
from secaware.randomization import Randomization, randomize
from secaware.records import content_id
from secaware.representation import (
    Candidate,
    CandidateUniverse,
    Population,
    Task,
    freeze_population,
    freeze_universe,
)

METHOD_VERSION = "secaware-method-1.1.0"


@dataclass(frozen=True, slots=True)
class StudyFreeze:
    method_version: str
    population: Population
    universe: CandidateUniverse
    selection: SelectionFreeze
    policies: tuple[InterventionPolicy, ...]
    adapters: AdapterBundle
    randomization: Randomization
    analysis_plan: AnalysisPlan

    def __post_init__(self) -> None:
        if self.method_version != METHOD_VERSION:
            raise ValueError("unsupported method version")
        selected = set(self.selection.selected_candidate_ids)
        if self.selection.universe_id != self.universe.universe_id:
            raise ValueError("selection does not bind the candidate universe")
        if self.universe.representation_adapter_id != self.adapters.representation.adapter_id:
            raise ValueError("candidate universe representation adapter drift")
        if self.selection.selector_adapter_id != self.adapters.selector.adapter_id:
            raise ValueError("selection adapter drift")
        if {item.candidate_id for item in self.policies} != selected:
            raise ValueError("one intervention policy must bind every selected candidate")
        candidates = {item.candidate_id: item for item in self.universe.candidates}
        if any(
            policy.protocol.operation is not candidates[policy.candidate_id].operation
            for policy in self.policies
        ):
            raise ValueError("intervention policy operation drifts from its candidate")
        if self.randomization.population_id != self.population.population_id:
            raise ValueError("randomization population drift")
        if self.randomization.selection_id != self.selection.selection_id:
            raise ValueError("randomization selection drift")
        _validate_policy_support(self)

    @property
    def study_id(self) -> str:
        return content_id("study_", self)


@dataclass(frozen=True, slots=True)
class Analysis:
    study_id: str
    ledger: MeasurementLedger
    outcomes: tuple[Outcome, ...]
    inference: InferenceResult

    def __post_init__(self) -> None:
        if self.ledger.study_id != self.study_id:
            raise ValueError("measurement ledger does not bind the study")

    @property
    def analysis_id(self) -> str:
        return content_id("analysis_", self)


def freeze_study(
    tasks: Iterable[Task],
    candidates: Iterable[Candidate],
    scores: Mapping[str, float],
    policies: Iterable[InterventionPolicy],
    adapters: AdapterBundle,
    analysis_plan: AnalysisPlan,
    *,
    top_k: int,
    models: Iterable[str],
    slots: Iterable[int],
    randomization_seed: int,
) -> StudyFreeze:
    population = freeze_population(tasks)
    universe = freeze_universe(
        candidates,
        representation_adapter_id=adapters.representation.adapter_id,
    )
    selection = freeze_selection(
        universe,
        scores,
        selector_adapter_id=adapters.selector.adapter_id,
        top_k=top_k,
    )
    frozen_policies = tuple(sorted(tuple(policies), key=lambda item: item.policy_id))
    assignment = randomize(
        frozen_policies,
        population_id=population.population_id,
        selection_id=selection.selection_id,
        models=models,
        slots=slots,
        seed=randomization_seed,
    )
    return StudyFreeze(
        METHOD_VERSION,
        population,
        universe,
        selection,
        frozen_policies,
        adapters,
        assignment,
        analysis_plan,
    )


def analyze(
    study: StudyFreeze,
    measurements: Iterable[Measurement],
    *,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> Analysis:
    ledger = close_measurements(
        study.randomization,
        study.adapters,
        measurements,
        study_id=study.study_id,
        infrastructure_failures=infrastructure_failures,
    )
    outcomes = derive_outcomes(ledger)
    inference = estimate_policy_effects(
        study.randomization,
        outcomes,
        study.policies,
        study.population.confirm_tasks,
        study.analysis_plan,
    )
    return Analysis(study.study_id, ledger, outcomes, inference)


def _validate_policy_support(study: StudyFreeze) -> None:
    confirm_tasks = {item.task_id: item for item in study.population.confirm_tasks}
    for policy in study.policies:
        realization_ids = {item.realization_id for item in policy.realizations}
        support = {(item.task_id, item.realization_id) for item in policy.bundles}
        expected = {
            (task_id, realization_id)
            for task_id in confirm_tasks
            for realization_id in realization_ids
        }
        if len(support) != len(policy.bundles) or support != expected:
            raise ValueError("policy lacks complete confirm-task realization support")
        for bundle in policy.bundles:
            task = confirm_tasks.get(bundle.task_id)
            if task is None or bundle.semantic_cluster_id != task.semantic_cluster_id:
                raise ValueError("task bundle population binding drift")
        if any(
            realization.executor_adapter_id != study.adapters.intervention_executor.adapter_id
            for realization in policy.realizations
        ):
            raise ValueError("intervention executor adapter drift")


__all__ = ["Analysis", "METHOD_VERSION", "StudyFreeze", "analyze", "freeze_study"]

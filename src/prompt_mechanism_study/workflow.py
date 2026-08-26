"""Prospective freeze and post-measurement analysis workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from prompt_mechanism_study.adapters import AdapterBundle
from prompt_mechanism_study.inference import (
    AnalysisPlan,
    FactorialAnalysisPlan,
    FactorialInferenceResult,
    InferenceResult,
    estimate_factorial_effects,
    estimate_policy_effects,
)
from prompt_mechanism_study.intervention import FactorialPolicy, InterventionPolicy
from prompt_mechanism_study.mechanisms import (
    OracleSupportStatus,
    PairBinding,
    PairEligibility,
)
from prompt_mechanism_study.measurement import (
    InfrastructureFailure,
    Measurement,
    MeasurementLedger,
    close_measurements,
)
from prompt_mechanism_study.outcomes import Outcome, derive_outcomes
from prompt_mechanism_study.prioritization import SelectionFreeze, freeze_selection
from prompt_mechanism_study.randomization import (
    FactorialRandomization,
    Randomization,
    randomize,
    randomize_factorial,
)
from prompt_mechanism_study.records import content_id, require_text, require_unique
from prompt_mechanism_study.representation import (
    Candidate,
    CandidateUniverse,
    Population,
    Task,
    freeze_population,
    freeze_universe,
)

METHOD_VERSION = "prompt-mechanism-study-method-1.3.0"
FACTORIAL_METHOD_VERSION = "prompt-mechanism-study-method-1.4.0-factorial"


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
            policy.spec.operation is not candidates[policy.candidate_id].operation
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


@dataclass(frozen=True, slots=True)
class FactorialStudyFreeze:
    method_version: str
    prompt_tsg_catalog_sha256: str
    tasks: tuple[Task, ...]
    pair_bindings: tuple[PairBinding, ...]
    policies: tuple[FactorialPolicy, ...]
    adapters: AdapterBundle
    randomization: FactorialRandomization
    analysis_plan: FactorialAnalysisPlan

    def __post_init__(self) -> None:
        if self.method_version != FACTORIAL_METHOD_VERSION:
            raise ValueError("unsupported factorial method version")
        _require_digest(self.prompt_tsg_catalog_sha256, "Prompt TSG catalog")
        if not self.tasks or any(task.split.value != "confirm" for task in self.tasks):
            raise ValueError("factorial freeze requires non-empty confirmatory tasks")
        require_unique((task.task_id for task in self.tasks), "factorial task ids")
        if tuple(sorted(self.tasks, key=lambda item: item.task_id)) != self.tasks:
            raise ValueError("factorial tasks must use canonical order")
        require_unique((policy.pair.pair_id for policy in self.policies), "factorial pair ids")
        if tuple(sorted(self.policies, key=lambda item: item.policy_id)) != self.policies:
            raise ValueError("factorial policies must use canonical order")
        if not self.pair_bindings or any(
            binding.decision is not PairEligibility.APPLICABLE
            for binding in self.pair_bindings
        ):
            raise ValueError("only applicable pair bindings may enter a factorial freeze")
        require_unique(
            ((binding.pair_id, binding.task_id) for binding in self.pair_bindings),
            "pair-task bindings",
        )
        if tuple(
            sorted(self.pair_bindings, key=lambda item: (item.pair_id, item.task_id))
        ) != self.pair_bindings:
            raise ValueError("pair bindings must use canonical order")
        if self.randomization.population_id != self.population_id:
            raise ValueError("factorial randomization population drift")
        if self.randomization.selection_id != self.selection_id:
            raise ValueError("factorial randomization selection drift")
        _validate_factorial_policy_support(self)

    @property
    def population_id(self) -> str:
        return content_id(
            "factorial_population_",
            {
                "catalog_sha256": self.prompt_tsg_catalog_sha256,
                "tasks": self.tasks,
                "bindings": self.pair_bindings,
            },
        )

    @property
    def selection_id(self) -> str:
        return content_id(
            "factorial_selection_",
            {
                "mode": "preregistered_registry_pair",
                "pair_ids": tuple(policy.pair.pair_id for policy in self.policies),
            },
        )

    @property
    def study_id(self) -> str:
        return content_id("factorial_study_", self)


@dataclass(frozen=True, slots=True)
class FactorialAnalysis:
    study_id: str
    ledger: MeasurementLedger
    outcomes: tuple[Outcome, ...]
    inference: FactorialInferenceResult

    def __post_init__(self) -> None:
        if self.ledger.study_id != self.study_id:
            raise ValueError("factorial measurement ledger does not bind the study")

    @property
    def analysis_id(self) -> str:
        return content_id("factorial_analysis_", self)


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


def freeze_factorial_study(
    tasks: Iterable[Task],
    pair_bindings: Iterable[PairBinding],
    policies: Iterable[FactorialPolicy],
    adapters: AdapterBundle,
    analysis_plan: FactorialAnalysisPlan,
    *,
    prompt_tsg_catalog_sha256: str,
    models: Iterable[str],
    slots: Iterable[int],
    randomization_seed: int,
    provider_seed: int | None = None,
) -> FactorialStudyFreeze:
    frozen_tasks = tuple(sorted(tuple(tasks), key=lambda item: item.task_id))
    frozen_bindings = tuple(
        sorted(tuple(pair_bindings), key=lambda item: (item.pair_id, item.task_id))
    )
    frozen_policies = tuple(sorted(tuple(policies), key=lambda item: item.policy_id))
    population_id = content_id(
        "factorial_population_",
        {
            "catalog_sha256": prompt_tsg_catalog_sha256,
            "tasks": frozen_tasks,
            "bindings": frozen_bindings,
        },
    )
    selection_id = content_id(
        "factorial_selection_",
        {
            "mode": "preregistered_registry_pair",
            "pair_ids": tuple(policy.pair.pair_id for policy in frozen_policies),
        },
    )
    assignment = randomize_factorial(
        frozen_policies,
        population_id=population_id,
        selection_id=selection_id,
        models=models,
        slots=slots,
        seed=randomization_seed,
        provider_seed=provider_seed,
    )
    return FactorialStudyFreeze(
        FACTORIAL_METHOD_VERSION,
        prompt_tsg_catalog_sha256,
        frozen_tasks,
        frozen_bindings,
        frozen_policies,
        adapters,
        assignment,
        analysis_plan,
    )


def analyze_factorial(
    study: FactorialStudyFreeze,
    measurements: Iterable[Measurement],
    *,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> FactorialAnalysis:
    ledger = close_measurements(
        study.randomization,
        study.adapters,
        measurements,
        study_id=study.study_id,
        infrastructure_failures=infrastructure_failures,
    )
    outcomes = derive_outcomes(ledger)
    inference = estimate_factorial_effects(
        study.randomization,
        outcomes,
        study.policies,
        study.tasks,
        study.analysis_plan,
    )
    return FactorialAnalysis(study.study_id, ledger, outcomes, inference)


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
        if any(
            variant.validation.validator_adapter_id
            != study.adapters.intervention_validator.adapter_id
            for bundle in policy.bundles
            for variant in bundle.variants
        ):
            raise ValueError("intervention validator adapter drift")


def _validate_factorial_policy_support(study: FactorialStudyFreeze) -> None:
    tasks = {item.task_id: item for item in study.tasks}
    policy_by_pair = {item.pair.pair_id: item for item in study.policies}
    if set(policy_by_pair) != {item.pair_id for item in study.pair_bindings}:
        raise ValueError("factorial policy support drifts from pair bindings")
    if {item.task_id for item in study.pair_bindings} != set(tasks):
        raise ValueError("factorial population contains unused or unbound tasks")
    for policy in study.policies:
        pair = policy.pair
        if pair.oracle_support_status is not OracleSupportStatus.SUPPORTED:
            raise ValueError("unsupported Oracle pair cannot enter factorial randomization")
        if pair.oracle_policy_sha256 != study.adapters.security_oracle.policy_sha256:
            raise ValueError("factorial pair Oracle policy hash drift")
        bound_tasks = {
            item.task_id for item in study.pair_bindings if item.pair_id == pair.pair_id
        }
        realization_ids = {item.realization_id for item in policy.realizations}
        support = {(item.task_id, item.realization_id) for item in policy.bundles}
        expected = {
            (task_id, realization_id)
            for task_id in bound_tasks
            for realization_id in realization_ids
        }
        if len(support) != len(policy.bundles) or support != expected:
            raise ValueError("factorial policy lacks complete task-realization support")
        for bundle in policy.bundles:
            task = tasks.get(bundle.task_id)
            if (
                task is None
                or bundle.task_unit_id != task.semantic_cluster_id
                or bundle.source_prompt_sha256 != task.prompt_sha256
            ):
                raise ValueError("factorial task bundle population binding drift")
        if any(
            realization.executor_adapter_id != study.adapters.intervention_executor.adapter_id
            for realization in policy.realizations
        ):
            raise ValueError("factorial intervention executor adapter drift")
        if any(
            variant.validation.validator_adapter_id
            != study.adapters.intervention_validator.adapter_id
            for bundle in policy.bundles
            for variant in bundle.variants
        ) or any(
            bundle.bundle_validation.validator_adapter_id
            != study.adapters.intervention_validator.adapter_id
            for bundle in policy.bundles
        ):
            raise ValueError("factorial intervention validator adapter drift")


def _require_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "Analysis",
    "FACTORIAL_METHOD_VERSION",
    "FactorialAnalysis",
    "FactorialStudyFreeze",
    "METHOD_VERSION",
    "StudyFreeze",
    "analyze",
    "analyze_factorial",
    "freeze_factorial_study",
    "freeze_study",
]

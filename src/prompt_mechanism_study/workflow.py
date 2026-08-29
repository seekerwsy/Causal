"""Prospective freeze and post-measurement analysis workflow."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from prompt_mechanism_study.adapters import AdapterBundle
from prompt_mechanism_study.artifact_io import require_sha256 as _require_digest
from prompt_mechanism_study.inference import (
    FactorialAnalysisPlan,
    FactorialInferenceResult,
    SuccessorAnalysisPlan,
    SuccessorInferenceResult,
    estimate_factorial_effects,
    estimate_successor_effects,
)
from prompt_mechanism_study.intervention import (
    FactorialPolicy,
    InterventionPolicyV2,
)
from prompt_mechanism_study.measurement import (
    InfrastructureFailure,
    Measurement,
    MeasurementLedger,
    close_measurements,
)
from prompt_mechanism_study.mechanisms import (
    OracleSupportStatus,
    PairBinding,
    PairEligibility,
)
from prompt_mechanism_study.outcomes import Outcome, derive_outcomes
from prompt_mechanism_study.randomization import (
    FactorialRandomization,
    SuccessorRandomization,
    randomize_factorial,
    randomize_successor,
)
from prompt_mechanism_study.records import content_hash, content_id, require_text, require_unique
from prompt_mechanism_study.representation import FrozenHypothesisV2, SourceEligibilityV2, Task

SUCCESSOR_METHOD_VERSION = "prompt-mechanism-study-method-2.0.0-successor"
FACTORIAL_METHOD_VERSION = "prompt-mechanism-study-method-1.6.0-factorial-v3"


def factorial_oracle_dispatch_policy_sha256(pairs: Iterable[object]) -> str:
    """Bind one aggregate adapter identity to exact pair-level Oracle policies."""

    material = tuple(
        {
            "pair_id": item.pair_id,
            "profile_id": item.oracle_profile_id,
            "policy_sha256": item.oracle_policy_sha256,
        }
        for item in sorted(pairs, key=lambda value: value.pair_id)
    )
    if not material:
        raise ValueError("factorial Oracle dispatch cannot be empty")
    return content_hash(material)


@dataclass(frozen=True, slots=True)
class SuccessorSelectionProvenance:
    """Outcome-blind predecessor bound into a successor study freeze."""

    source: str
    candidate_universe_manifest_id: str
    selection_id: str
    artifact_sha256: str
    bridge_map_id: str | None = None
    selected_predecessor_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.source not in {"selector_bridge", "frozen_registry"}:
            raise ValueError("unsupported successor selection source")
        require_text(
            self.candidate_universe_manifest_id,
            "candidate_universe_manifest_id",
        )
        require_text(self.selection_id, "successor selection id")
        _require_digest(self.artifact_sha256, "successor selection artifact")
        require_unique(
            self.selected_predecessor_ids,
            "successor selected predecessor ids",
        )
        if (
            not self.selected_predecessor_ids
            or tuple(sorted(self.selected_predecessor_ids))
            != self.selected_predecessor_ids
        ):
            raise ValueError(
                "successor selected predecessor ids must be non-empty canonical order"
            )
        if self.source == "selector_bridge":
            require_text(self.bridge_map_id or "", "successor bridge map id")
        elif self.bridge_map_id is not None:
            raise ValueError("frozen registry cannot claim a selector bridge")


@dataclass(frozen=True, slots=True)
class SuccessorStudyFreeze:
    """Self-contained randomized union for the prospective successor protocol."""

    method_version: str
    selection_provenance: SuccessorSelectionProvenance
    tasks: tuple[Task, ...]
    hypotheses: tuple[FrozenHypothesisV2, ...]
    source_eligibilities: tuple[SourceEligibilityV2, ...]
    policies: tuple[InterventionPolicyV2, ...]
    adapters: AdapterBundle
    randomization: SuccessorRandomization
    analysis_plan: SuccessorAnalysisPlan

    def __post_init__(self) -> None:
        if self.method_version != SUCCESSOR_METHOD_VERSION:
            raise ValueError("unsupported successor method version")
        if type(self.selection_provenance) is not SuccessorSelectionProvenance:
            raise TypeError("successor selection provenance is required")
        if not self.tasks or any(item.split.value != "confirm" for item in self.tasks):
            raise ValueError("successor freeze requires non-empty confirmatory tasks")
        require_unique((item.task_id for item in self.tasks), "successor task ids")
        if tuple(sorted(self.tasks, key=lambda item: item.task_id)) != self.tasks:
            raise ValueError("successor tasks must use canonical order")
        require_unique(
            (item.hypothesis_id for item in self.hypotheses),
            "successor hypothesis ids",
        )
        if tuple(
            sorted(self.hypotheses, key=lambda item: item.hypothesis_id)
        ) != self.hypotheses:
            raise ValueError("successor hypotheses must use canonical order")
        if {item.hypothesis_id for item in self.policies} != {
            item.hypothesis_id for item in self.hypotheses
        }:
            raise ValueError("one successor policy must bind every randomized hypothesis")
        expected_predecessors = (
            tuple(sorted(item.hypothesis_id for item in self.hypotheses))
            if self.selection_provenance.source == "selector_bridge"
            else tuple(sorted(item.skeleton.candidate_key for item in self.hypotheses))
        )
        if self.selection_provenance.selected_predecessor_ids != expected_predecessors:
            raise ValueError(
                "successor hypotheses drift from the frozen selection predecessor"
            )
        if tuple(
            sorted(self.policies, key=lambda item: item.intervention_policy_id)
        ) != self.policies:
            raise ValueError("successor policies must use canonical order")
        require_unique(
            (
                (item.hypothesis_id, item.task_id)
                for item in self.source_eligibilities
            ),
            "successor hypothesis-task source gates",
        )
        if tuple(
            sorted(
                self.source_eligibilities,
                key=lambda item: (item.hypothesis_id, item.task_id),
            )
        ) != self.source_eligibilities:
            raise ValueError("successor source gates must use canonical order")
        expected_gates = {
            (hypothesis.hypothesis_id, task.task_id)
            for hypothesis in self.hypotheses
            for task in self.tasks
        }
        if {
            (item.hypothesis_id, item.task_id) for item in self.source_eligibilities
        } != expected_gates:
            raise ValueError("successor freeze must retain every hypothesis-task source gate")
        task_by_id = {item.task_id: item for item in self.tasks}
        if any(
            item.task_unit_id != task_by_id[item.task_id].semantic_cluster_id
            or item.prompt_sha256 != task_by_id[item.task_id].prompt_sha256
            for item in self.source_eligibilities
        ):
            raise ValueError("successor source gate population binding drift")
        if self.randomization.population_id != self.population_id:
            raise ValueError("successor randomization population drift")
        if self.randomization.selection_id != self.selection_provenance.selection_id:
            raise ValueError("successor randomization selection drift")
        _validate_successor_policy_support(self)

    @property
    def candidate_universe_manifest_id(self) -> str:
        return self.selection_provenance.candidate_universe_manifest_id

    @property
    def selection_freeze_manifest_id(self) -> str:
        return self.selection_provenance.selection_id

    @property
    def population_id(self) -> str:
        return content_id(
            "successor_population_v2_",
            {
                "tasks": self.tasks,
                "source_eligibilities": self.source_eligibilities,
            },
        )

    @property
    def study_id(self) -> str:
        return content_id("successor_study_v2_", self)


@dataclass(frozen=True, slots=True)
class SuccessorAnalysis:
    study_id: str
    ledger: MeasurementLedger
    outcomes: tuple[Outcome, ...]
    inference: SuccessorInferenceResult

    def __post_init__(self) -> None:
        if self.ledger.study_id != self.study_id:
            raise ValueError("successor measurement ledger does not bind the study")

    @property
    def analysis_id(self) -> str:
        return content_id("successor_analysis_v2_", self)


@dataclass(frozen=True, slots=True)
class FactorialPairSelection:
    source: str
    selection_id: str
    selected_pair_ids: tuple[str, ...]
    artifact_bundle_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.source not in {"registry_selected", "selector_artifact"}:
            raise ValueError("unsupported factorial pair-selection source")
        require_text(self.selection_id, "factorial pair selection id")
        require_unique(self.selected_pair_ids, "selected factorial pair ids")
        if tuple(sorted(self.selected_pair_ids)) != self.selected_pair_ids:
            raise ValueError("selected factorial pair ids must use canonical order")
        if self.source == "selector_artifact":
            _require_digest(
                self.artifact_bundle_sha256 or "",
                "factorial pair-selection artifact",
            )
        elif self.artifact_bundle_sha256 is not None:
            raise ValueError("registry selection cannot claim a selector artifact")


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
    pair_selection: FactorialPairSelection | None = None

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
        if self.pair_selection is not None and self.pair_selection.selected_pair_ids != tuple(
            sorted(policy.pair.pair_id for policy in self.policies)
        ):
            raise ValueError("factorial pair selection drifts from frozen policies")
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
        if self.pair_selection is not None:
            return self.pair_selection.selection_id
        return content_id(
            "factorial_selection_",
            {
                "mode": "preregistered_registry_pair",
                "pair_ids": tuple(policy.pair.pair_id for policy in self.policies),
            },
        )

    @property
    def study_id(self) -> str:
        if self.pair_selection is None:
            return content_id(
                "factorial_study_",
                {
                    "method_version": self.method_version,
                    "prompt_tsg_catalog_sha256": self.prompt_tsg_catalog_sha256,
                    "tasks": self.tasks,
                    "pair_bindings": self.pair_bindings,
                    "policies": self.policies,
                    "adapters": self.adapters,
                    "randomization": self.randomization,
                    "analysis_plan": self.analysis_plan,
                },
            )
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


def freeze_successor_study(
    tasks: Iterable[Task],
    hypotheses: Iterable[FrozenHypothesisV2],
    source_eligibilities: Iterable[SourceEligibilityV2],
    policies: Iterable[InterventionPolicyV2],
    adapters: AdapterBundle,
    analysis_plan: SuccessorAnalysisPlan,
    *,
    selection_provenance: SuccessorSelectionProvenance,
    models: Iterable[str],
    request_randomness_slots: Iterable[int],
    randomization_seed: int,
    provider_seed: int | None = None,
) -> SuccessorStudyFreeze:
    frozen_tasks = tuple(sorted(tasks, key=lambda item: item.task_id))
    frozen_hypotheses = tuple(
        sorted(hypotheses, key=lambda item: item.hypothesis_id)
    )
    frozen_eligibilities = tuple(
        sorted(
            source_eligibilities,
            key=lambda item: (item.hypothesis_id, item.task_id),
        )
    )
    frozen_policies = tuple(
        sorted(policies, key=lambda item: item.intervention_policy_id)
    )
    population_id = content_id(
        "successor_population_v2_",
        {
            "tasks": frozen_tasks,
            "source_eligibilities": frozen_eligibilities,
        },
    )
    assignment = randomize_successor(
        frozen_policies,
        population_id=population_id,
        selection_id=selection_provenance.selection_id,
        models=models,
        request_randomness_slots=request_randomness_slots,
        seed=randomization_seed,
        provider_seed=provider_seed,
    )
    return SuccessorStudyFreeze(
        SUCCESSOR_METHOD_VERSION,
        selection_provenance,
        frozen_tasks,
        frozen_hypotheses,
        frozen_eligibilities,
        frozen_policies,
        adapters,
        assignment,
        analysis_plan,
    )


def analyze_successor(
    study: SuccessorStudyFreeze,
    measurements: Iterable[Measurement],
    *,
    infrastructure_failures: Iterable[InfrastructureFailure] = (),
) -> SuccessorAnalysis:
    ledger = close_measurements(
        study.randomization,
        study.adapters,
        measurements,
        study_id=study.study_id,
        infrastructure_failures=infrastructure_failures,
    )
    outcomes = derive_outcomes(ledger)
    inference = estimate_successor_effects(
        study.randomization,
        outcomes,
        study.policies,
        study.tasks,
        study.analysis_plan,
    )
    return SuccessorAnalysis(study.study_id, ledger, outcomes, inference)


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
    pair_selection: FactorialPairSelection | None = None,
) -> FactorialStudyFreeze:
    frozen_tasks = tuple(sorted(tasks, key=lambda item: item.task_id))
    frozen_bindings = tuple(
        sorted(pair_bindings, key=lambda item: (item.pair_id, item.task_id))
    )
    frozen_policies = tuple(sorted(policies, key=lambda item: item.policy_id))
    population_id = content_id(
        "factorial_population_",
        {
            "catalog_sha256": prompt_tsg_catalog_sha256,
            "tasks": frozen_tasks,
            "bindings": frozen_bindings,
        },
    )
    selection_id = (
        pair_selection.selection_id
        if pair_selection is not None
        else content_id(
            "factorial_selection_",
            {
                "mode": "preregistered_registry_pair",
                "pair_ids": tuple(policy.pair.pair_id for policy in frozen_policies),
            },
        )
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
        pair_selection,
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


def _validate_successor_policy_support(study: SuccessorStudyFreeze) -> None:
    task_by_id = {item.task_id: item for item in study.tasks}
    eligibility_by_coordinate = {
        (item.hypothesis_id, item.task_id): item
        for item in study.source_eligibilities
    }
    for policy in study.policies:
        eligible = tuple(
            item
            for (hypothesis_id, _task_id), item in eligibility_by_coordinate.items()
            if hypothesis_id == policy.hypothesis_id and item.eligible
        )
        if {item.source_eligibility_id for item in policy.source_eligibilities} != {
            item.source_eligibility_id for item in eligible
        }:
            raise ValueError("successor policy eligible-source support drift")
        if any(
            item.executor_adapter_id
            != study.adapters.intervention_executor.adapter_id
            for item in policy.realization_policy.realizations
        ):
            raise ValueError("successor intervention executor adapter drift")
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
            raise ValueError("successor intervention validator adapter drift")
        for bundle in policy.bundles:
            task = task_by_id.get(bundle.task_id)
            if (
                task is None
                or bundle.task_unit_id != task.semantic_cluster_id
                or bundle.source_prompt_sha256 != task.prompt_sha256
            ):
                raise ValueError("successor task bundle population binding drift")


def _validate_factorial_policy_support(study: FactorialStudyFreeze) -> None:
    tasks = {item.task_id: item for item in study.tasks}
    policy_by_pair = {item.pair.pair_id: item for item in study.policies}
    if set(policy_by_pair) != {item.pair_id for item in study.pair_bindings}:
        raise ValueError("factorial policy support drifts from pair bindings")
    if {item.task_id for item in study.pair_bindings} != set(tasks):
        raise ValueError("factorial population contains unused or unbound tasks")
    pair_oracle_digests = {
        policy.pair.oracle_policy_sha256 for policy in study.policies
    }
    aggregate_oracle_digest = factorial_oracle_dispatch_policy_sha256(
        policy.pair for policy in study.policies
    )
    if len(study.policies) == 1:
        valid_adapter_digests = pair_oracle_digests | {aggregate_oracle_digest}
    else:
        valid_adapter_digests = {aggregate_oracle_digest}
    if study.adapters.security_oracle.policy_sha256 not in valid_adapter_digests:
        raise ValueError("factorial aggregate Oracle dispatch policy drift")
    for policy in study.policies:
        pair = policy.pair
        if pair.oracle_support_status is not OracleSupportStatus.SUPPORTED:
            raise ValueError("unsupported Oracle pair cannot enter factorial randomization")
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

__all__ = [
    "FACTORIAL_METHOD_VERSION",
    "SUCCESSOR_METHOD_VERSION",
    "FactorialAnalysis",
    "FactorialPairSelection",
    "FactorialStudyFreeze",
    "SuccessorAnalysis",
    "SuccessorSelectionProvenance",
    "SuccessorStudyFreeze",
    "analyze_factorial",
    "analyze_successor",
    "factorial_oracle_dispatch_policy_sha256",
    "freeze_factorial_study",
    "freeze_successor_study",
]
